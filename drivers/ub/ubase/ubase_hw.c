// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/delay.h>
#include <linux/ummu_core.h>

#include "ubase_cmd.h"
#include "ubase_dtumem.h"
#include "ubase_ctrlq.h"
#include "ubase_dev.h"
#include "ubase_mailbox.h"
#include "ubase_tp.h"
#include "ubase_usc.h"
#include "ubase_hw.h"

static DEFINE_MUTEX(ubase_perf_mutex);

struct ubase_dma_buf_desc {
	struct ubase_dma_buf	*buf;
	u16			opc;
	bool (*is_supported)(struct ubase_dev *dev);
};

#define UBASE_DEFINE_TA_DMA_BUFS(udev) \
	struct ubase_dma_buf_desc bufs[] = { \
		{ &(udev)->ta_ctx.extdb_buf, UBASE_OPC_TA_EXTDB_VA_CONFIG, \
		  &ubase_dev_ta_extdb_buf_supported }, \
		{ &(udev)->ta_ctx.timer_buf, UBASE_OPC_TA_TIMER_VA_CONFIG, \
		  &ubase_dev_ta_timer_buf_supported } \
	}

static void ubase_assign_addr_val(void *addr, u32 val, u8 size)
{
#define VAL_SIZE_1	1
#define VAL_SIZE_2	2
#define VAL_SIZE_4	4

	switch (size) {
	case VAL_SIZE_1:
		*(u8 *)addr = (u8)val;
		break;
	case VAL_SIZE_2:
		*(u16 *)addr = (u16)val;
		break;
	case VAL_SIZE_4:
		*(u32 *)addr = (u32)val;
		break;
	default:
		break;
	}
}

static void ubase_check_dev_caps_comm(struct ubase_dev *udev)
{
	struct ubase_caps *caps = &udev->caps.dev_caps;
	struct ubase_caps_item items[] = {
		{
			&caps->num_ceq_vectors, UBASE_DEF_CEQ_VECTOR_NUM,
			sizeof(caps->num_ceq_vectors), "ceq vector num"
		},
		{
			&caps->num_aeq_vectors, UBASE_DEF_AEQ_VECTOR_NUM,
			sizeof(caps->num_aeq_vectors), "aeq vector num"
		},
		{
			&caps->num_misc_vectors, UBASE_DEF_MISC_VERCTOR_NUM,
			sizeof(caps->num_misc_vectors), "misc vector num"
		},
		{
			&caps->public_jetty_cnt, UBASE_DEF_PUBLIC_JETTY_CNT,
			sizeof(caps->public_jetty_cnt), "public jetty count"
		},
		{
			&caps->aeqe_size, UBASE_DEF_EQE_SIZE,
			sizeof(caps->aeqe_size), "aeqe size"
		},
		{
			&caps->ceqe_size, UBASE_DEF_EQE_SIZE,
			sizeof(caps->ceqe_size), "ceqe size"
		},
		{
			&caps->aeqe_depth, UBASE_DEF_AEQ_DEPTH,
			sizeof(caps->aeqe_depth), "aeqe depth"
		},
		{
			&caps->ceqe_depth, UBASE_DEF_CEQ_DEPTH,
			sizeof(caps->ceqe_depth), "ceqe depth"
		},
	};
	u32 i, items_size = ARRAY_SIZE(items);
	u32 val;

	for (i = 0; i < items_size; i++) {
		val = 0;
		memcpy(&val, items[i].p, items[i].size);
		if (!val) {
			ubase_assign_addr_val(items[i].p, items[i].default_val,
					      items[i].size);
			ubase_warn(udev, "using default %s(%u).\n",
				   items[i].name, items[i].default_val);
		}
	}
}

static int ubase_check_dev_caps_rct(struct ubase_dev *udev)
{
	if (!ubase_dev_udma_supported(udev))
		return 0;

	if (!udev->caps.udma_caps.rc_que_depth) {
		ubase_err(udev, "failed to check rct caps: depth = 0.\n");
		return -EINVAL;
	}

	return 0;
}

static int ubase_check_dev_caps_extdb(struct ubase_dev *udev)
{
	UBASE_DEFINE_TA_DMA_BUFS(udev);
	int i;

	for (i = 0; i < ARRAY_SIZE(bufs); i++) {
		if (bufs[i].is_supported(udev) && !bufs[i].buf->size) {
			ubase_err(udev,
				  "failed to check caps: buf[%d] size=0.\n", i);
			return -EINVAL;
		}
	}

	return 0;
}

static int ubase_check_dev_caps_compat(struct ubase_dev *udev)
{
	if (ubase_dev_usc_supported(udev)) {
		if (ubase_dev_dtu_supported(udev)) {
			ubase_err(udev,
			  "failed to check caps, usc and dtu are both enabled.\n");
			return -EINVAL;
		}

		if (ubase_dev_prealloc_supported(udev)) {
			ubase_err(udev,
				  "failed to check caps, usc and prealloc are both enabled.\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int ubase_check_dev_caps(struct ubase_dev *udev)
{
	int ret;

	ret = ubase_check_dev_caps_compat(udev);
	if (ret)
		return ret;

	ubase_check_dev_caps_comm(udev);

	ret = ubase_check_dev_caps_rct(udev);
	if (ret)
		return ret;

	return ubase_check_dev_caps_extdb(udev);
}

static void ubase_parse_dev_caps_comm(struct ubase_dev *udev,
				      const struct ubase_res_cmd_resp *resp)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;

	udev->node_type = resp->node_type;
	dev_caps->num_ceq_vectors = le16_to_cpu(resp->ceq_vector_num);
	dev_caps->num_aeq_vectors = le16_to_cpu(resp->aeq_vector_num);
	dev_caps->num_misc_vectors = le16_to_cpu(resp->misc_vector_num);
	dev_caps->aeqe_size = le16_to_cpu(resp->aeqe_size);
	dev_caps->ceqe_size = le16_to_cpu(resp->ceqe_size);
	dev_caps->aeqe_depth = le32_to_cpu(resp->aeqe_depth);
	dev_caps->ceqe_depth = le32_to_cpu(resp->ceqe_depth);
	dev_caps->total_ue_num = le32_to_cpu(resp->total_ue_num);
	dev_caps->public_jetty_cnt = le32_to_cpu(resp->public_jetty_cnt);
	dev_caps->rsvd_jetty_cnt = le16_to_cpu(resp->rsvd_jetty_cnt);
	dev_caps->ue_num = resp->ue_num;
	dev_caps->mac_stats_num = le16_to_cpu(resp->mac_stats_num);

	udev->ta_ctx.extdb_buf.size = le32_to_cpu(resp->ta_extdb_buf_size);
	udev->ta_ctx.timer_buf.size = le32_to_cpu(resp->ta_timer_buf_size);
}

static void ubase_parse_dev_caps_unic(struct ubase_dev *udev,
				      const struct ubase_res_cmd_resp *resp)
{
	struct ubase_adev_caps *unic_caps = &udev->caps.unic_caps;

	unic_caps->jfs.max_cnt = le32_to_cpu(resp->nic_jfs_max_cnt);
	unic_caps->jfs.depth = le32_to_cpu(resp->nic_jfs_depth);
	unic_caps->jfr.max_cnt = le32_to_cpu(resp->nic_jfr_max_cnt);
	unic_caps->jfr.depth = le32_to_cpu(resp->nic_jfr_depth);
	unic_caps->jfc.max_cnt = le32_to_cpu(resp->nic_jfc_max_cnt);
	unic_caps->jfc.depth = le32_to_cpu(resp->nic_jfc_depth);
	unic_caps->cqe_size = le16_to_cpu(resp->nic_cqe_size);
}

static void ubase_parse_dev_caps_udma(struct ubase_dev *udev,
				      const struct ubase_res_cmd_resp *resp)
{
	struct ubase_adev_caps *udma_caps = &udev->caps.udma_caps;

	udma_caps->jfs.max_cnt = le32_to_cpu(resp->udma_jfs_max_cnt);
	udma_caps->jfs.depth = le32_to_cpu(resp->udma_jfs_depth);
	udma_caps->jfr.max_cnt = le32_to_cpu(resp->udma_jfr_max_cnt);
	udma_caps->jfr.depth = le32_to_cpu(resp->udma_jfr_depth);
	udma_caps->jfc.max_cnt = le32_to_cpu(resp->udma_jfc_max_cnt);
	udma_caps->jfc.depth = le32_to_cpu(resp->udma_jfc_depth);
	udma_caps->cqe_size = le16_to_cpu(resp->udma_cqe_size);
	udma_caps->jtg_max_cnt = le32_to_cpu(resp->jtg_max_cnt);
	udma_caps->rc_max_cnt = le32_to_cpu(resp->rc_max_cnt_per_vl);
	udma_caps->rc_que_depth = le32_to_cpu(resp->udma_rc_depth);
}

static void ubase_parse_dev_caps(struct ubase_dev *udev,
				 const struct ubase_res_cmd_resp *resp)
{
	int i;

	for (i = 0; i < UBASE_CAP_LEN; i++) {
		udev->cap_bits[i] = le32_to_cpu(resp->cap_bits[i]);
		ubase_info(udev, "udev cap_bits[%d] = 0x%x\n", i,
			   udev->cap_bits[i]);
	}

	ubase_parse_dev_caps_comm(udev, resp);
	ubase_parse_dev_caps_unic(udev, resp);
	ubase_parse_dev_caps_udma(udev, resp);
}

static int ubase_parse_dev_res(struct ubase_dev *udev,
			       struct ubase_res_cmd_resp *resp)
{
	ubase_parse_dev_caps(udev, resp);

	return ubase_check_dev_caps(udev);
}

int ubase_query_dev_res(struct ubase_dev *udev)
{
	struct ubase_res_cmd_resp resp = {0};
	struct ubase_cmd_buf out;
	struct ubase_cmd_buf in;
	int ret;

	__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_COMM_RSRC_PARAM, true, 0,
			       NULL);

	__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_COMM_RSRC_PARAM, false,
			       sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev, "failed to query ubase res, ret = %d.\n", ret);
		return ret;
	}

	return ubase_parse_dev_res(udev, &resp);
}

static void ubase_init_start_idx(struct ubase_dev *udev)
{
	struct ubase_adev_caps *udma_caps = &udev->caps.udma_caps;
	struct ubase_adev_caps *unic_caps = &udev->caps.unic_caps;

	unic_caps->jfs.start_idx = udev->caps.dev_caps.public_jetty_cnt +
				   udev->caps.dev_caps.rsvd_jetty_cnt;

	udma_caps->jfs.start_idx = unic_caps->jfs.max_cnt +
				   udev->caps.dev_caps.public_jetty_cnt +
				   udev->caps.dev_caps.rsvd_jetty_cnt;
	udma_caps->jfr.start_idx = unic_caps->jfr.max_cnt;
	udma_caps->jfc.start_idx = unic_caps->jfc.max_cnt;
}

int ubase_config_ctx_buf_to_hw(struct ubase_dev *udev,
			       struct ubase_ctx_buf_cap *ctx_buf,
			       struct ubase_mbx_attr *attr)
{
	struct ubase_cmd_mailbox mailbox;
	int ret;

	mailbox.dma = ctx_buf->dma_ctx_buf_ba;
	ret = __ubase_hw_upgrade_ctx(udev, attr, &mailbox);
	if (ret)
		ubase_err(udev,
			  "failed to config ctx_buf to hw, cmd = 0x%x, ret = %d.\n",
			  attr->op, ret);
	return ret;
}

static void ubase_ctx_free(struct ubase_dev *udev,
			   struct ubase_ctx_buf *ctx_buf, int idx)
{
	struct ubase_ctx_buf_map map[] = {
		{ &ctx_buf->jfs, UBASE_MB_WRITE_JFS_CONTEXT_VA },
		{ &ctx_buf->jfr, UBASE_MB_WRITE_JFR_CONTEXT_VA },
		{ &ctx_buf->jfc, UBASE_MB_WRITE_JFC_CONTEXT_VA },
		{ &ctx_buf->jtg, UBASE_MB_WRITE_JETTY_GROUP_CONTEXT_VA },
		{ &ctx_buf->rc, UBASE_MB_WRITE_RC_CONTEXT_VA },
	};
	int i, end_idx = ARRAY_SIZE(map) - 1;

	i = (idx == UBASE_CTX_REMOVE_ALL) ? end_idx : idx;
	for (; i >= 0; i--) {
		if (ubase_dev_usc_supported(udev) && ubase_ctx_in_usc(map[i].mb_cmd)) {
			ubase_cmd_ctx_buf_free_usc(udev, map[i].ctx, map[i].mb_cmd);
			continue;
		}

		__ubase_cmd_ctx_buf_free(udev, map[i].ctx);
	}
}

static int ubase_fill_common_ctx_buf(struct ubase_dev *udev,
				     struct ubase_ctx_buf_cap *ctx_buf,
				     u32 start_pos, u32 size)
{
	struct ubase_ctx_page *ctx_page;
	size_t npage;
	int ret;
	u32 i;

	mutex_lock(&ctx_buf->ctx_mutex);

	for (i = start_pos; i < start_pos + size; i++) {
		ctx_page = (struct ubase_ctx_page *)xa_load(&ctx_buf->ctx_xa, i);
		if (ctx_page)
			continue;

		ret = ubase_create_ctx_page(udev, ctx_buf, &ctx_page, i);
		if (ret) {
			ubase_err(udev, "failed to create context page, ret = %d.\n",
				  ret);
			goto err_fill_ctx_page;
		}

		ret = xa_err(xa_store(&ctx_buf->ctx_xa, i, ctx_page,
				      GFP_KERNEL));
		if (ret) {
			ubase_err(udev, "failed to store page, ret = %d.\n",
				  ret);
			goto err_fill_ctx_page;
		}
	}

	mutex_unlock(&ctx_buf->ctx_mutex);

	return 0;

err_fill_ctx_page:
	xa_for_each(&ctx_buf->ctx_xa, npage, ctx_page)
		ubase_destroy_ctx_page(udev, ctx_page, ctx_buf);
	mutex_unlock(&ctx_buf->ctx_mutex);

	return ret;
}

static int ubase_fill_ctx_inherent_buf(struct ubase_dev *udev,
				       struct ubase_ctx_buf_cap *ctx_buf,
				       struct ubase_mbx_attr *attr)
{
	struct ubase_adev_caps *unic_caps = &udev->caps.unic_caps;
	u32 buf_size, page_cnt;
	u32 start_pos = 0;

	switch (attr->op) {
	case UBASE_MB_WRITE_JFS_CONTEXT_VA:
		start_pos = udev->caps.unic_caps.jfs.start_idx >>
			    ctx_buf->cnt_per_page_shift;
		buf_size = unic_caps->jfs.max_cnt * ctx_buf->entry_size;
		break;
	case UBASE_MB_WRITE_JFR_CONTEXT_VA:
		buf_size = unic_caps->jfr.max_cnt * ctx_buf->entry_size;
		break;
	case UBASE_MB_WRITE_JFC_CONTEXT_VA:
		buf_size = unic_caps->jfc.max_cnt * ctx_buf->entry_size;
		break;
	default:
		return 0;
	}

	page_cnt = DIV_ROUND_UP(buf_size, PAGE_SIZE);
	return ubase_fill_common_ctx_buf(udev, ctx_buf, start_pos, page_cnt);
}

static int ubase_alloc_and_fill_ctx_buf(struct ubase_dev *udev,
					struct ubase_ctx_buf_cap *ctx_buf,
					struct ubase_mbx_attr *attr,
					size_t size)
{
	size_t sizep;
	int ret;

	ctx_buf->cnt_per_page_shift =
		ilog2(roundup_pow_of_two(PAGE_SIZE / ctx_buf->entry_size));
	ctx_buf->slot = dma_alloc_iova(udev->dev, size, 0,
				       &ctx_buf->dma_ctx_buf_ba, &sizep);
	if (IS_ERR(ctx_buf->slot)) {
		ubase_err(udev,
			  "failed to alloc iova slot, cmd = 0x%x, size = %lu.\n",
			  attr->op, size);
		return -ENOMEM;
	}

	ret = ubase_fill_ctx_inherent_buf(udev, ctx_buf, attr);
	if (ret) {
		ubase_err(udev,
			  "failed to fill inherent ctx buf, cmd = 0x%x, ret = %d.\n",
			  attr->op, ret);
		dma_free_iova(ctx_buf->slot);
	}

	return ret;
}

static void ubase_free_and_clear_ctx_buf(struct ubase_dev *udev,
					 struct ubase_ctx_buf_cap *ctx_buf)
{
	struct ubase_ctx_page *ctx_page;
	size_t npage;

	if (!xa_empty(&ctx_buf->ctx_xa)) {
		xa_for_each(&ctx_buf->ctx_xa, npage, ctx_page)
			ubase_destroy_ctx_page(udev, ctx_page, ctx_buf);
	}
	dma_free_iova(ctx_buf->slot);

	ctx_buf->slot = NULL;
	ctx_buf->dma_ctx_buf_ba = 0;
}

static int ubase_config_ctx_buf_by_dtu(struct ubase_dev *udev,
				       struct ubase_ctx_buf_cap *ctx_buf,
				       struct ubase_mbx_attr *attr,
				       size_t size)
{
	struct ubase_cmd_mailbox mailbox;
	void *va;
	int ret;

	va = ubase_dtu_alloc(udev, &ctx_buf->page, size,
			     &ctx_buf->dma_ctx_buf_ba);
	if (!va) {
		ubase_err(udev, "failed to alloc dtu memory.\n");
		return -ENOMEM;
	}

	mailbox.dma = ctx_buf->dma_ctx_buf_ba;
	ret = __ubase_hw_upgrade_ctx(udev, attr, &mailbox);
	if (ret) {
		ubase_err(udev,
			  "failed to config ctx buf, ret = %d.\n", ret);
		ubase_dtu_free(udev, ctx_buf->page, size, ctx_buf->dma_ctx_buf_ba);
	}

	return ret;
}

static int ubase_config_jfs_ctx_buf_by_pmem(struct ubase_dev *udev,
					    struct ubase_mbx_attr *attr)
{
	struct ubase_cmd_mailbox mailbox;
	int ret;

	mailbox.dma = udev->pmem_info.comm.dma_addr;
	ret = __ubase_hw_upgrade_ctx(udev, attr, &mailbox);
	if (ret)
		ubase_err(udev,
			  "failed to config jfs ctx buf, ret = %d.\n", ret);

	return ret;
}

void __ubase_cmd_ctx_buf_free(struct ubase_dev *udev,
			      struct ubase_ctx_buf_cap *ctx_buf)
{
	size_t size;

	if (!ctx_buf || !ctx_buf->slot)
		return;

	size = ctx_buf->entry_cnt * ctx_buf->entry_size;
	if (!size)
		return;

	if (ubase_dev_dtu_supported(udev)) {
		ubase_dtu_free(udev, ctx_buf->page, size,
			       ctx_buf->dma_ctx_buf_ba);
		return;
	}

	ubase_free_and_clear_ctx_buf(udev, ctx_buf);
	xa_destroy(&ctx_buf->ctx_xa);
}

int __ubase_cmd_ctx_buf_alloc(struct ubase_dev *udev,
			      struct ubase_ctx_buf_cap *ctx_buf,
			      struct ubase_mbx_attr *attr)
{
	size_t size = ctx_buf->entry_cnt * ctx_buf->entry_size;
	int ret;

	if (!size)
		return 0;

	if (ubase_dev_dtu_supported(udev))
		return ubase_config_ctx_buf_by_dtu(udev, ctx_buf, attr, size);

	if (attr->op == UBASE_MB_WRITE_JFS_CONTEXT_VA &&
	    test_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits))
		return ubase_config_jfs_ctx_buf_by_pmem(udev, attr);

	xa_init(&ctx_buf->ctx_xa);
	ret = ubase_alloc_and_fill_ctx_buf(udev, ctx_buf, attr, size);
	if (ret)
		goto err_ctx_alloc;

	ret = ubase_config_ctx_buf_to_hw(udev, ctx_buf, attr);
	if (ret)
		goto err_ctx_to_hw;

	return 0;

err_ctx_to_hw:
	ubase_free_and_clear_ctx_buf(udev, ctx_buf);

err_ctx_alloc:
	xa_destroy(&ctx_buf->ctx_xa);

	return ret;
}

static int ubase_ctx_alloc(struct ubase_dev *udev,
			   struct ubase_ctx_buf *ctx_buf)
{
	struct ubase_ctx_buf_map map[] = {
		{ &ctx_buf->jfs, UBASE_MB_WRITE_JFS_CONTEXT_VA },
		{ &ctx_buf->jfr, UBASE_MB_WRITE_JFR_CONTEXT_VA },
		{ &ctx_buf->jfc, UBASE_MB_WRITE_JFC_CONTEXT_VA },
		{ &ctx_buf->jtg, UBASE_MB_WRITE_JETTY_GROUP_CONTEXT_VA },
		{ &ctx_buf->rc, UBASE_MB_WRITE_RC_CONTEXT_VA },
	};
	struct ubase_mbx_attr attr = {0};
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(map); i++) {
		memset(&attr, 0, sizeof(attr));
		attr.op = map[i].mb_cmd;

		if (ubase_dev_usc_supported(udev) && ubase_ctx_in_usc(attr.op)) {
			ret = ubase_cmd_ctx_buf_alloc_usc(udev, map[i].ctx, &attr);
			if (ret)
				goto err_alloc_ctx_buf;
			continue;
		}

		ret = __ubase_cmd_ctx_buf_alloc(udev, map[i].ctx, &attr);
		if (ret) {
			ubase_err(udev,
				  "failed to alloc ctx buf, mb_cmd = 0x%x, ret = %d.\n",
				  map[i].mb_cmd, ret);
			goto err_alloc_ctx_buf;
		}
	}

	return 0;

err_alloc_ctx_buf:
	ubase_ctx_free(udev, ctx_buf, --i);
	return ret;
}

static void ubase_get_ctx_entry_cnt(struct ubase_dev *udev)
{
	struct ubase_adev_caps *unic_caps = &udev->caps.unic_caps;
	struct ubase_adev_caps *udma_caps = &udev->caps.udma_caps;
	struct ubase_ctx_buf *ubase_ctx_buf = &udev->ctx_buf;

	ubase_ctx_buf->jfs.entry_cnt = ubase_jfs_num(udev);
	ubase_ctx_buf->jfr.entry_cnt = unic_caps->jfr.max_cnt;
	ubase_ctx_buf->jfc.entry_cnt = unic_caps->jfc.max_cnt;
	ubase_ctx_buf->jtg.entry_cnt = udma_caps->jtg_max_cnt;
	ubase_ctx_buf->rc.entry_cnt = udma_caps->rc_max_cnt;

	ubase_ctx_buf->jfr.entry_cnt += udma_caps->jfr.max_cnt;
	ubase_ctx_buf->jfc.entry_cnt += udma_caps->jfc.max_cnt;
}

static void ubase_get_ctx_entry_size(struct ubase_dev *udev)
{
	struct ubase_ctx_buf *ubase_ctx_buf = &udev->ctx_buf;

	ubase_ctx_buf->jfs.entry_size = UBASE_JFS_CTX_SIZE;
	ubase_ctx_buf->jfr.entry_size = UBASE_JFR_CTX_SIZE;
	ubase_ctx_buf->jfc.entry_size = UBASE_JFC_CTX_SIZE;
	ubase_ctx_buf->jtg.entry_size = UBASE_JTG_CTX_SIZE;
	ubase_ctx_buf->rc.entry_size = UBASE_RC_CTX_SIZE;
}

static int ubase_ctx_buf_alloc(struct ubase_dev *udev)
{
	struct ubase_ctx_buf *ctx_buf = &udev->ctx_buf;

	ubase_get_ctx_entry_cnt(udev);
	ubase_get_ctx_entry_size(udev);

	return ubase_ctx_alloc(udev, ctx_buf);
}

static int ubase_config_dma_buf(struct ubase_dev *udev, u16 opc, u64 dma_addr)
{
	struct ubase_cfg_dma_buf_req req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.addr_l = cpu_to_le32(lower_32_bits(dma_addr));
	req.addr_h = cpu_to_le32(upper_32_bits(dma_addr));

	__ubase_fill_inout_buf(&in, opc, false, sizeof(req), &req);

	ret = __ubase_cmd_send_in(udev, &in);
	if (ret)
		ubase_err(udev,
			  "failed to send cmd in cfg dma buf, ret = %d.\n", ret);

	return ret;
}

static int ubase_config_ta_timer_buf_by_pmem(struct ubase_dev *udev, u16 opc)
{
	u64 dma_addr, offset;

	offset = ubase_jfs_ctx_align_size(udev);
	dma_addr = udev->pmem_info.comm.dma_addr + offset;

	return ubase_config_dma_buf(udev, opc, dma_addr);
}

static int ubase_alloc_ta_buf(struct ubase_dev *udev, struct ubase_dma_buf *buf)
{
	buf->addr = ubase_alloc_buf(udev, buf->size, &buf->dma_addr, &buf->page);
	if (!buf->addr)
		return -ENOMEM;

	return 0;
}

static void ubase_free_ta_buf(struct ubase_dev *udev, struct ubase_dma_buf *buf)
{
	ubase_free_buf(udev, buf->size, buf->addr, buf->dma_addr, buf->page);

	buf->addr = NULL;
}

static int ubase_init_dma_buf(struct ubase_dev *udev, struct ubase_dma_buf *buf,
			      u16 opc)
{
	int ret;

	if (opc == UBASE_OPC_TA_TIMER_VA_CONFIG &&
	    test_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits)
	    && !ubase_dev_dtu_supported(udev))
		return ubase_config_ta_timer_buf_by_pmem(udev, opc);

	ret = ubase_alloc_ta_buf(udev, buf);
	if (ret) {
		ubase_err(udev, "failed to alloc ta buf, ret = %d.\n", ret);
		return ret;
	}

	ret = ubase_config_dma_buf(udev, opc, buf->dma_addr);
	if (ret)
		ubase_free_ta_buf(udev, buf);

	return ret;
}

static void ubase_uninit_dma_buf(struct ubase_dev *udev,
				 struct ubase_dma_buf *buf)
{
	if (!buf->addr)
		return;

	ubase_free_ta_buf(udev, buf);
}

static int ubase_init_ta_ext_buf(struct ubase_dev *udev)
{
	UBASE_DEFINE_TA_DMA_BUFS(udev);
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(bufs); i++) {
		ret = bufs[i].is_supported(udev) ?
		      ubase_init_dma_buf(udev, bufs[i].buf, bufs[i].opc) : 0;
		if (ret) {
			ubase_err(udev,
				  "failed to init buf[%d], ret = %d.\n", i, ret);
			goto err_out;
		}
	}

	return 0;
err_out:
	for (i -= 1; i >= 0; i--) {
		if (bufs[i].is_supported(udev))
			ubase_uninit_dma_buf(udev, bufs[i].buf);
	}
	return ret;
}

static void ubase_uninit_ta_ext_buf(struct ubase_dev *udev)
{
	UBASE_DEFINE_TA_DMA_BUFS(udev);
	int i;

	for (i = 0; i < ARRAY_SIZE(bufs); i++) {
		if (bufs[i].is_supported(udev))
			ubase_uninit_dma_buf(udev, bufs[i].buf);
	}
}

int ubase_query_hw_oor_caps(struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_query_oor_resp resp = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_OOR_CAPS, true, 0, NULL);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_OOR_CAPS, true,
			     sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev,
			  "failed to query hw oor caps, ret = %d.\n", ret);
		return ret;
	}

	dev_caps->oor_en = resp.oor_en;
	dev_caps->reorder_queue_en = resp.reorder_cq_buffer_en;
	dev_caps->reorder_cap = resp.reorder_cap;
	dev_caps->reorder_queue_shift = resp.reorder_cq_shift;
	dev_caps->on_flight_size = le32_to_cpu(resp.on_flight_size);
	dev_caps->at_times = resp.dynamic_ack_timeout;

	return 0;
}

int ubase_query_port_bitmap(struct ubase_dev *udev)
{
#define OPCODE_CNT 2

	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_query_port_bitmap_resp resp = {0};
	enum ubase_opcode_type opcode[OPCODE_CNT];
	struct ubase_cmd_buf in, out;
	int ret, i;

	opcode[0] = UBASE_OPC_QUERY_UB_PORT_BITMAP;
	opcode[1] = UBASE_OPC_QUERY_PORT_BITMAP;

	for (i = 0; i < OPCODE_CNT; i++) {
		ubase_fill_inout_buf(&in, opcode[i], true, 0, NULL);
		ubase_fill_inout_buf(&out, opcode[i], true, sizeof(resp), &resp);
		ret = __ubase_cmd_send_inout(udev, &in, &out);
		if (ret != -EOPNOTSUPP)
			break;

		dev_warn(udev->dev,
			 "The function of querying real-time traffic in UBOE mode is not supported.\n");
	}

	if (ret && ret != -EPERM) {
		dev_err(udev->dev,
			"failed to query port bitmap, ret = %d.\n", ret);
		return ret;
	}

	dev_caps->logic_port_bitmap = le32_to_cpu(resp.logic_port_bitmap);

	return 0;
}

int ubase_query_controller_info(struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_query_controller_info_resp resp = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_CTL_INFO, true, 0, NULL);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_CTL_INFO, true,
			     sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev,
			  "failed to query controller info, ret = %d.\n", ret);
		return ret;
	}

	dev_caps->packet_pattern_mode = resp.packet_pattern_mode;
	dev_caps->ack_queue_num = resp.ack_queue_num;

	return 0;
}

int ubase_query_chip_info(struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_query_chip_die_cmd resp = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_CHIP_INFO, true, 0, NULL);
	__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_CHIP_INFO, true,
			       sizeof(resp), &resp);
	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev,
			  "failed to query ub chip info, ret = %d.\n", ret);
		return ret;
	}

	dev_caps->nl_port_id = le16_to_cpu(resp.nl_port_id);
	dev_caps->chip_id = le16_to_cpu(resp.chip_id);
	dev_caps->die_id = le16_to_cpu(resp.die_id);
	dev_caps->io_port_id = le16_to_cpu(resp.io_port_id);
	dev_caps->ue_id = le16_to_cpu(resp.ue_id);
	dev_caps->ub_port_logic_id = le16_to_cpu(resp.ub_port_logic_id);
	dev_caps->io_port_logic_id = le16_to_cpu(resp.io_port_logic_id);
	dev_caps->nl_id = le16_to_cpu(resp.nl_id);

	return 0;
}

static void ubase_destroy_ctx_res(struct ubase_dev *udev)
{
#define DESTROY_RETRY_MIN_TIME	50000
#define DESTROY_RETRY_MAX_TIME	150000
#define DESTROY_RETRY_COUNT	5
#define QUERY_WAIT_TIME		20
#define QUERY_RETRY_COUNT	10

	struct ubase_destroy_res_cmd resp;
	struct ubase_cmd_buf in, out;
	int try_cnt = 0;
	int ret;

	__ubase_fill_inout_buf(&in, UBASE_OPC_DESTROY_CTX_RESOURCE, false, 0, NULL);

	do {
		ret = __ubase_cmd_send_in(udev, &in);
		if (ret) {
			ubase_err(udev, "failed to send destroy resource, ret = %d.\n",
				  ret);
			usleep_range(DESTROY_RETRY_MIN_TIME,
				     DESTROY_RETRY_MAX_TIME);
		}
		try_cnt++;
	} while (ret && try_cnt < DESTROY_RETRY_COUNT);

	if (ret) {
		ubase_warn(udev, "retry destroy resource failed, ret = %d.\n",
			   ret);
		return;
	}

	try_cnt = 0;
	__ubase_fill_inout_buf(&in, UBASE_OPC_DESTROY_CTX_RESOURCE, true, 0, NULL);
	__ubase_fill_inout_buf(&out, UBASE_OPC_DESTROY_CTX_RESOURCE, false,
			       sizeof(resp), &resp);
	do {
		memset(&resp, 0, sizeof(resp));
		msleep(QUERY_WAIT_TIME);
		ret = __ubase_cmd_send_inout(udev, &in, &out);
		if (ret)
			ubase_err(udev,
				  "failed to query destroy resource, ret = %d.\n",
				  ret);

		try_cnt++;
	} while (!resp.destroy_done && try_cnt < QUERY_RETRY_COUNT);

	if (!resp.destroy_done)
		ubase_warn(udev, "wait ue destroy res timeout!\n");
}

static inline void ubase_uninit_ctx_buf(struct ubase_dev *udev)
{
	ubase_ctx_free(udev, &udev->ctx_buf, UBASE_CTX_REMOVE_ALL);
}

static void ubase_init_ctx_buf_lock(struct ubase_ctx_buf *ctx_buf)
{
	struct mutex *ctx_mutex[] = { &ctx_buf->jfs.ctx_mutex,
				      &ctx_buf->jfr.ctx_mutex,
				      &ctx_buf->jfc.ctx_mutex,
				      &ctx_buf->jtg.ctx_mutex,
				      &ctx_buf->rc.ctx_mutex };
	int i;

	for (i = 0; i < ARRAY_SIZE(ctx_mutex); i++)
		mutex_init(ctx_mutex[i]);
}

static void ubase_uninit_ctx_buf_lock(struct ubase_ctx_buf *ctx_buf)
{
	struct mutex *ctx_mutex[] = { &ctx_buf->jfs.ctx_mutex,
				      &ctx_buf->jfr.ctx_mutex,
				      &ctx_buf->jfc.ctx_mutex,
				      &ctx_buf->jtg.ctx_mutex,
				      &ctx_buf->rc.ctx_mutex };
	int i;

	for (i = 0; i < ARRAY_SIZE(ctx_mutex); i++)
		mutex_destroy(ctx_mutex[i]);
}

int ubase_ue_init(struct ubase_dev *udev)
{
	ubase_init_start_idx(udev);
	INIT_LIST_HEAD(&udev->ue_list);
	mutex_init(&udev->ue_list_lock);
	mutex_init(&udev->stats.stats_lock);
	mutex_init(&udev->stats.activate_record.lock);
	spin_lock_init(&udev->tp_ctx.tpg_lock);
	mutex_init(&udev->act_ctx.lock);
	init_completion(&udev->act_ctx.self.activate_done);
	init_completion(&udev->act_ctx.other.activate_done);
	ubase_init_ctx_buf_lock(&udev->ctx_buf);

	return 0;
}

void ubase_ue_uninit(struct ubase_dev *udev)
{
	mutex_destroy(&udev->act_ctx.lock);
	mutex_destroy(&udev->stats.activate_record.lock);
	mutex_destroy(&udev->stats.stats_lock);
	mutex_destroy(&udev->ue_list_lock);
	ubase_uninit_ctx_buf_lock(&udev->ctx_buf);
}

static int ubase_notify_ctrl_plane_init_res(struct ubase_dev *udev)
{
	struct ubase_ctrlq_reset_ctrl_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	u32 resp;
	int ret;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER;
	msg.opcode = UBASE_CTRLQ_OPC_UE_RESET_CTRL;
	msg.need_resp = 1;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(resp);
	msg.out = &resp;

	req.flag = UBASE_CTRL_PLANE_INIT_RES;

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret)
		dev_err(udev->dev,
			"failed to notify ctrl plane init res, ret = %d.\n",
			ret);

	return ret;
}

int ubase_hw_init(struct ubase_dev *udev)
{
	int ret;

	ret = ubase_notify_ctrl_plane_init_res(udev);
	if (ret)
		return ret;

	ret = ubase_ctx_buf_alloc(udev);
	if (ret) {
		ubase_err(udev, "failed to init ctx buf, ret = %d.\n", ret);
		return ret;
	}

	ret = ubase_init_ta_ext_buf(udev);
	if (ret)
		goto err_init_ta_ext_buf;

	ret = ubase_dev_init_tp_tpg(udev);
	if (ret) {
		ubase_err(udev, "failed to init tp & tpg, ret = %d.\n", ret);
		goto err_init_tp_tpg;
	}

	set_bit(UBASE_STATE_CTX_READY_B, &udev->state_bits);

	return 0;

err_init_tp_tpg:
	ubase_uninit_ta_ext_buf(udev);
err_init_ta_ext_buf:
	ubase_uninit_ctx_buf(udev);

	return ret;
}

static int ubase_start_perf_stats(struct ubase_dev *udev, u32 period,
				  u64 port_bitmap)
{
	struct ubase_start_perf_stats_cmd req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.period = cpu_to_le32(period);
	req.logic_port_bitmap[0] = cpu_to_le32(lower_32_bits(port_bitmap));
	req.logic_port_bitmap[1] = cpu_to_le32(upper_32_bits(port_bitmap));

	__ubase_fill_inout_buf(&in, UBASE_OPC_START_PERF_STATS, false,
			       sizeof(req), &req);
	ret = __ubase_cmd_send_in(udev, &in);
	if (ret && ret != -EPERM)
		ubase_err(udev, "failed to cfg perf stats period, ret = %d.\n",
			  ret);

	return ret == -EPERM ? -EOPNOTSUPP : ret;
}

static int ubase_stop_perf_stats(struct ubase_dev *udev,
				 struct ubase_stop_perf_stats_cmd *resp,
				 u32 period, u16 port_id)
{
	struct ubase_stop_perf_stats_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.period = cpu_to_le32(period);
	req.port_id = cpu_to_le16(port_id);

	__ubase_fill_inout_buf(&in, UBASE_OPC_STOP_PERF_STATS, true,
			       sizeof(req), &req);
	__ubase_fill_inout_buf(&out, UBASE_OPC_STOP_PERF_STATS, false,
			       sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret && ret != -EPERM)
		ubase_err(udev, "failed to query perf stats, ret = %d.\n", ret);

	return ret == -EPERM ? -EOPNOTSUPP : ret;
}

int __ubase_perf_stats(struct ubase_dev *udev, u64 port_bitmap, u32 period,
		       struct ubase_perf_stats_result *data, u32 data_size)
{
#define UBASE_MS_TO_US(ms)	(1000 * (ms))

	unsigned long logic_port_bitmap = udev->caps.dev_caps.logic_port_bitmap;
	struct ubase_stop_perf_stats_cmd resp;
	u32 j, k, port_num;
	int ret;
	u8 i;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	if (port_bitmap) {
		if (data_size < bitmap_weight((unsigned long *)&port_bitmap,
					      UBASE_MAX_PORT_NUM) ||
		    !bitmap_subset((unsigned long *)&port_bitmap,
				   &logic_port_bitmap, UBASE_MAX_PORT_NUM))
			return -EINVAL;
	} else {
		if (data_size != UBASE_MAX_PORT_NUM ||
		    data_size < bitmap_weight((unsigned long *)&logic_port_bitmap,
					      UBASE_MAX_PORT_NUM))
			return -EINVAL;

		port_bitmap = logic_port_bitmap;
	}

	mutex_lock(&ubase_perf_mutex);
	ret = ubase_start_perf_stats(udev, period, port_bitmap);
	if (ret)
		goto unlock;

	usleep_range(UBASE_MS_TO_US(period), UBASE_MS_TO_US(period + 1));

	port_num = bitmap_weight((unsigned long *)&port_bitmap,
				 UBASE_MAX_PORT_NUM);
	for (i = 0, k = 0; i < UBASE_MAX_PORT_NUM && k < port_num; i++) {
		if (!test_bit(i, (unsigned long *)&port_bitmap))
			continue;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_stop_perf_stats(udev, &resp, period, i);
		if (ret)
			goto unlock;

		data[k].tx_port_bw = le32_to_cpu(resp.tx_port_bw);
		data[k].rx_port_bw = le32_to_cpu(resp.rx_port_bw);
		data[k].tx_max_port_bw = le32_to_cpu(resp.tx_max_port_bw);
		data[k].rx_max_port_bw = le32_to_cpu(resp.rx_max_port_bw);
		data[k].port_id = i;
		data[k].valid = 1;

		for (j = 0; j < UBASE_STATS_MAX_VL_NUM; j++) {
			data[k].tx_vl_bw[j] = le32_to_cpu(resp.tx_vl_bw[j]);
			data[k].rx_vl_bw[j] = le32_to_cpu(resp.rx_vl_bw[j]);
		}

		k++;
	}

unlock:
	mutex_unlock(&ubase_perf_mutex);

	return ret;
}

/**
 * ubase_perf_stats() - get ub port stats
 * @adev: auxiliary device
 * @port_bitmap: port bitmap
 * @period: period, unit: ms
 * @data: stats data
 * @data_size: data size
 *
 * The function is used to query the port bandwidth and the bandwidth of each vl
 * under the port. The bandwidth statistics collection duration is 'period'.
 * The larger the 'period', the longer the time required, and the more accurate
 * the bandwidth measurement.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_perf_stats(struct auxiliary_device *adev, u64 port_bitmap, u32 period,
		     struct ubase_perf_stats_result *data, u32 data_size)
{
	struct ubase_dev *udev;

	if (!adev || !data || !period || !data_size)
		return -EINVAL;

	udev = ubase_get_udev_by_adev(adev);
	if (!(ubase_dev_ubl_supported(udev) || ubase_dev_fwctl_supported(udev)))
		return -EOPNOTSUPP;

	return __ubase_perf_stats(udev, port_bitmap, period, data, data_size);
}
EXPORT_SYMBOL(ubase_perf_stats);

void ubase_hw_uninit(struct ubase_dev *udev)
{
	clear_bit(UBASE_STATE_CTX_READY_B, &udev->state_bits);

	ubase_dev_uninit_tp_tpg(udev);
	ubase_uninit_ta_ext_buf(udev);

	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		ubase_ctrlq_disable_remote(udev);
		__ubase_deactivate_dev(udev);
		ubase_destroy_ctx_res(udev);
	}

	ubase_uninit_ctx_buf(udev);
}
