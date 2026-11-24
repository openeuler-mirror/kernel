// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu IMP command queue (CMDQ) management.
 */

#define pr_fmt(fmt) "[ub dtu]: " fmt

#include <asm/barrier.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "dtu.h"
#include "dtu_cmd.h"
#include "../ummu.h"


void ub_dtu_write_reg(void __iomem *base, u32 reg, u32 value)
{
	writel(value, base + reg);
}

u32 ub_dtu_read_reg(void __iomem *base, u32 reg)
{
	return readl(base + reg);
}

static inline struct dtu_cmdq_ring *csq_of(struct ub_dtu_device *dtu)
{
	return &dtu->cmdq.csq;
}


static int ub_dtu_alloc_cmd_queue(struct ub_dtu_device *dtu,
				    struct dtu_cmdq_ring *csq)
{
	struct page *page;
	unsigned int order;
	size_t size;

	size = csq->desc_num * sizeof(struct dtu_cmdq_desc);
	order = get_order(size);

	page = alloc_pages_node(dev_to_node(dtu->dev), UMMU_GFP(GFP_KERNEL) | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	csq->desc = page_address(page);
	csq->desc_pa = page_to_phys(page);
	return 0;
}

static void ub_dtu_free_cmd_queue(struct ub_dtu_device *dtu,
				    struct dtu_cmdq_ring *csq)
{
	unsigned int order;
	size_t size;

	if (!csq->desc)
		return;

	size = csq->desc_num * sizeof(struct dtu_cmdq_desc);
	order = get_order(size);
	free_pages((unsigned long)csq->desc, order);

	csq->desc = NULL;
	csq->desc_pa = 0;
}


static int csq_init(struct ub_dtu_device *dtu, struct dtu_cmdq_ring *csq)
{
	u32 depth;
	int ret;

	csq->tx_timeout = UB_DTU_CMDQ_TX_TIMEOUT_US;
	csq->desc_num = UMMU_CMDQ_DESC_NUM;

	ret = ub_dtu_alloc_cmd_queue(dtu, csq);
	if (ret) {
		dtu_err(dtu, "failed to alloc csq, ret = %d.\n", ret);
		return ret;
	}

	csq->head = 0;
	csq->tail = 0;

	depth = csq->desc_num >> UMMU_CMDQ_DESC_NUM_S; /* 128 >> 3 = 16 */

	ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_HEAD_REG, 0);
	ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_TAIL_REG, 0);
	ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_DEPTH_REG, depth);
	ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_BASEADDR_L_REG,
			lower_32_bits(csq->desc_pa));
	ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_BASEADDR_H_REG,
			upper_32_bits(csq->desc_pa));

	return 0;
}

int ub_dtu_cmdq_init(struct ub_dtu_device *dtu)
{
	struct dtu_cmdq_ring *csq = csq_of(dtu);

	mutex_init(&csq->lock);
	clear_bit(DTU_STATE_CMD_DISABLE, &dtu->cmdq.state_bitmap);

	return csq_init(dtu, csq);
}

void ub_dtu_cmdq_uninit(struct ub_dtu_device *dtu)
{
	struct dtu_cmdq_ring *csq = csq_of(dtu);

	if (dtu->cmdq_base && !IS_ERR_OR_NULL(dtu->cmdq_base)) {
		ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_HEAD_REG, 0);
		ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_TAIL_REG, 0);
		ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_DEPTH_REG, 0);
		ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_BASEADDR_L_REG, 0);
		ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_BASEADDR_H_REG, 0);
	}

	ub_dtu_free_cmd_queue(dtu, csq);
}


static int ub_dtu_remain_cmdq_space(struct dtu_cmdq_ring *csq)
{
	u32 used;

	if (!csq || csq->desc_num == 0)
		return 0;

	used = (csq->tail - csq->head + csq->desc_num) % csq->desc_num;
	return csq->desc_num - used - 1;
}

static void ub_dtu_write_desc_to_cmdq(struct ub_dtu_device *dtu,
				      struct dtu_cmdq_desc *desc, int num)
{
	struct dtu_cmdq_ring *csq = csq_of(dtu);
	int cnt = 0;

	while (cnt < num) {
		csq->desc[csq->tail] = desc[cnt];
		csq->tail++;
		if (csq->tail >= csq->desc_num)
			csq->tail = 0;
		cnt++;
	}

	ub_dtu_write_reg(dtu->cmdq_base, UMMU_CSQ_TAIL_REG, csq->tail);
}

static bool ub_dtu_wait_for_resp(struct ub_dtu_device *dtu)
{
	struct dtu_cmdq_ring *csq = csq_of(dtu);
	u32 head;
	int err;

	err = readl_poll_timeout(dtu->cmdq_base + UMMU_CSQ_HEAD_REG, head,
	head == csq->tail,
	UB_DTU_CMDQ_TX_DELAY_US,
	csq->tx_timeout);

	return err == 0;
}

static int ub_dtu_get_cmd_result(struct ub_dtu_device *dtu,
				   struct dtu_cmdq_desc *desc, u32 sw_pi)
{
	struct dtu_cmdq_ring *csq = csq_of(dtu);

	*desc = csq->desc[sw_pi];
	if (desc->flag & DTU_CMD_FLAG_OUT)
		return le16_to_cpu(desc->ret);

	return -ETIMEDOUT;
}

static int ub_dtu_csq_data_is_valid(struct ub_dtu_device *dtu, u32 head)
{
	struct dtu_cmdq_ring *csq = csq_of(dtu);
	u32 sw_ci = csq->head;
	u32 sw_pi = csq->tail;

	if (sw_pi > sw_ci)
		return head >= sw_ci && head <= sw_pi;

	return head >= sw_ci || head <= sw_pi;
}

static int ub_dtu_csq_clean(struct ub_dtu_device *dtu)
{
	struct dtu_cmdq_ring *csq = csq_of(dtu);
	u32 head;
	int clean;

	head = ub_dtu_read_reg(dtu->cmdq_base, UMMU_CSQ_HEAD_REG);

	if (head >= csq->desc_num) {
		dtu_err(dtu, "csq head out of range (%u, desc_num=%u).\n",
			head, csq->desc_num);
		set_bit(DTU_STATE_CMD_DISABLE, &dtu->cmdq.state_bitmap);
		return -EIO;
	}

	if (!ub_dtu_csq_data_is_valid(dtu, head)) {
		dtu_err(dtu, "csq head incorrect (%u, %u-%u).\n",
			head, csq->tail, csq->head);
		set_bit(DTU_STATE_CMD_DISABLE, &dtu->cmdq.state_bitmap);
		return -EIO;
	}

	clean = (int)((head - csq->head + csq->desc_num) % csq->desc_num);
	csq->head = head;
	return clean;
}

/*
 * Core command submission: lock, enqueue descriptors, notify IMP via
 * TAIL register, poll HEAD for completion, translate IMP return code
 * to errno, then sync software head via csq_clean.
 */
static int ub_dtu_send_cmd(struct ub_dtu_device *dtu,
			     struct dtu_cmdq_desc *desc, int num)
{
	struct dtu_cmdq_ring *csq = csq_of(dtu);
	bool is_completed = false;
	int cleaned, free_num, ret;
	u32 sw_pi;

	guard(mutex)(&csq->lock);

	if (test_bit(DTU_STATE_CMD_DISABLE, &dtu->cmdq.state_bitmap))
		return -EBUSY;

	free_num = ub_dtu_remain_cmdq_space(csq);
	if (num > free_num) {
		csq->head = ub_dtu_read_reg(dtu->cmdq_base, UMMU_CSQ_HEAD_REG);
		dtu_err(dtu, "csq requested space(%d) exceeds remaining(%d).\n",
			num, free_num);
		return -EBUSY;
	}

	sw_pi = csq->tail;

	ub_dtu_write_desc_to_cmdq(dtu, desc, num);

	is_completed = ub_dtu_wait_for_resp(dtu);
	if (!is_completed) {
		ret = -EBADE;
		goto err_clr_cmdq;
	}

	ret = ub_dtu_get_cmd_result(dtu, desc, sw_pi);

	switch (ret) {
	case 0x0:
		break;
	case 0x1:
		dtu_err(dtu, "csq command has no authority to execute.\n");
		ret = -EPERM;
		break;
	case 0x2:
		dtu_err(dtu, "csq other link without execute the command.\n");
		ret = -EIO;
		break;
	case -ETIMEDOUT:
		dtu_err(dtu, "csq command timeout.\n");
		break;
	default:
		dtu_err(dtu, "csq command executed failed, ret=%d.\n", ret);
		ret = -EIO;
		break;
	}

	cleaned = ub_dtu_csq_clean(dtu);
	if (cleaned < 0) {
		dtu_err(dtu, "csq clean failed, cleaned=%d.\n", cleaned);
	if (ret >= 0)
		ret = cleaned;
	}

	return ret;

err_clr_cmdq:
	cleaned = ub_dtu_csq_clean(dtu);
	if (cleaned < 0)
		ret = cleaned;
	return ret;
}


static u16 ub_dtu_calc_bd_num(struct dtu_cmd_buf *buf)
{
	u32 left_size = buf->data_size > DTU_CMD_DATA_LENGTH
			? buf->data_size - DTU_CMD_DATA_LENGTH : 0;

	return DIV_ROUND_UP(left_size, sizeof(struct dtu_cmdq_desc)) + 1;
}

static int ub_dtu_cmd_buf_check(struct dtu_cmd_buf *in, u16 *num)
{
	u16 in_bd = ub_dtu_calc_bd_num(in);

	*num = in_bd;
	if (in_bd > UMMU_CMDQ_DESC_NUM - 1) {
		pr_err("requested space(%u) exceeds the maximum(%lu).\n",
		       in->data_size, DTU_CMD_MAX_DESC_SIZE - 1);
		return -EINVAL;
	}
	return 0;
}

static void ub_dtu_setup_basic_desc(struct dtu_cmdq_desc *desc, u16 opcode,
				      bool is_read, u8 num)
{
	memset(desc, 0, sizeof(*desc));
	desc->opcode = cpu_to_le16(opcode);
	desc->flag = DTU_CMD_FLAG_NO_INTR | DTU_CMD_FLAG_IN;
	desc->bd_num = num;

	if (is_read)
		desc->flag |= DTU_CMD_FLAG_WR;
}

static void ub_dtu_setup_desc_by_inbuf(struct dtu_cmd_buf *in,
					 struct dtu_cmdq_desc *desc, u16 num)
{
	u32 remaining, copy_len, offset;
	int i;

	ub_dtu_setup_basic_desc(&desc[0], in->opcode, in->is_read, num);

	if (!in->data)
		return;

	remaining = in->data_size;
	offset = 0;

	copy_len = min_t(u32, remaining, DTU_CMD_DATA_LENGTH);
	memcpy(desc[0].data, in->data, copy_len);
	remaining -= copy_len;
	offset += copy_len;

	for (i = 1; i < num && remaining > 0; i++) {
		copy_len = min_t(u32, remaining, sizeof(struct dtu_cmdq_desc));
		memcpy(&desc[i], (u8 *)in->data + offset, copy_len);
		remaining -= copy_len;
		offset += copy_len;
	}
}

int ub_dtu_cmd_send_inout(struct ub_dtu_device *dtu_dev,
			  struct dtu_cmd_buf *in,
			  struct dtu_cmdq_desc *out_desc)
{
	struct dtu_cmdq_desc *desc;
	u16 num;
	int ret;

	ret = ub_dtu_cmd_buf_check(in, &num);
	if (ret)
		return ret;

	desc = kcalloc(num, sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ub_dtu_setup_desc_by_inbuf(in, desc, num);

	ret = ub_dtu_send_cmd(dtu_dev, desc, num);

	if (out_desc)
		*out_desc = desc[0];

	kfree(desc);
	return ret;
}
