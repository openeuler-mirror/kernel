// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "ubus hisi memory: " fmt

#include <ub/ubus/ubus.h>
#include <ub/ubus/ub-mem-decoder.h>

#include "../../ubus.h"
#include "../../msg.h"
#include "../../memory.h"
#include "hisi-msg.h"
#include "hisi-ubus.h"
#define CREATE_TRACE_POINTS
#include "memory_trace.h"

#define DRAIN_ENABLE_REG_OFFSET		0x24
#define DRAIN_STATE_REG_OFFSET		0x28

#define HI_GET_UBMEM_EVENT_REQ_SIZE 4
#define HI_GET_UBMEM_EVENT_RSP_SIZE 772
#define MEM_EVENT_MAX_NUM 16
#define MAR_ERR_ADDR_COUNT 10
#define MAR_ERR_ADDR_SIZE 2
#define MEM_DECODER_NUMBER_V1 5
#define MEM_DECODER_NUMBER_V2 2

#define hpa_gen(addr_h, addr_l) (((u64)(addr_h) << 32) | (addr_l))

static u8 ub_mem_num;

struct ub_mem_decoder {
	struct device *dev;
	struct ub_entity *uent;
	void *base_reg;
};

struct hi_ubmem_event {
	u32 device_ras_status3;
	u32 device_ras_status4;
	u32 err_addr[MAR_ERR_ADDR_COUNT];
};

struct hi_get_ubmem_event_rsp {
	u32 event_num;
	struct hi_ubmem_event event_info[MEM_EVENT_MAX_NUM];
};

struct hi_get_ubmem_event_req {
	u32 rsv0;
};

struct hi_get_ubmem_event_pld {
	union {
		struct hi_get_ubmem_event_req req;
		struct hi_get_ubmem_event_rsp rsp;
	};
};

static bool hi_mem_validate_pa(struct ub_bus_controller *ubc,
			       u64 pa_start, u64 pa_end, bool cacheable);

static void hi_mem_drain_start(struct ub_bus_controller *ubc)
{
	struct ub_mem_decoder *decoder, *data = ubc->mem_device->priv_data;

	if (!data) {
		dev_err(&ubc->dev, "ubc mem_decoder is null.\n");
		return;
	}

	for (int i = 0; i < ub_mem_num; i++) {
		decoder = &data[i];
		writel(0, decoder->base_reg + DRAIN_ENABLE_REG_OFFSET);
		writel(1, decoder->base_reg + DRAIN_ENABLE_REG_OFFSET);
	}
}

static int hi_mem_drain_state(struct ub_bus_controller *ubc)
{
	struct ub_mem_decoder *decoder, *data = ubc->mem_device->priv_data;
	struct ub_mem_device *mem_device = ubc->mem_device;
	int val = 0;

	if (!data) {
		dev_err(mem_device->dev, "ubc mem_decoder is null.\n");
		return 0;
	}

	for (int i = 0; i < ub_mem_num; i++) {
		decoder = &data[i];
		val = readb(decoder->base_reg + DRAIN_STATE_REG_OFFSET) & 0x1;
		dev_info_ratelimited(decoder->dev, "ub memory decoder[%d] drain state, val=%d\n",
					i, val);
		if (!val)
			return val;
	}

	return val;
}

static const struct ub_mem_device_ops device_ops = {
	.mem_drain_start = hi_mem_drain_start,
	.mem_drain_state = hi_mem_drain_state,
	.mem_validate_pa = hi_mem_validate_pa,
};

static int save_ras_err_info(struct ub_mem_device *mem_device,
			     enum ras_err_type type, u64 val0, u64 val1)
{
	struct ub_mem_ras_err_info err_info = {
		.type = type,
		.val0 = val0,
		.val1 = val1,
	};

	if (!kfifo_put(&mem_device->ras_ctx.ras_fifo, err_info)) {
		dev_err(mem_device->dev, "kfifo put failed!\n");
		return -ENOMEM;
	}

	return 0;
}

static irqreturn_t hi_mem_ras_isr(int irq, void *context)
{
	struct ub_bus_controller *ubc = (struct ub_bus_controller *)context;
	struct ub_mem_ras_ctx *ras_ctx = &ubc->mem_device->ras_ctx;
	struct ub_mem_ras_err_info err_info;
	ubmem_ras_handler handler;
	u64 ctl_no = ubc->ctl_no;
	u64 vals[3];
	int ret;

	handler = ub_mem_ras_handler_get();
	while (kfifo_get(&ras_ctx->ras_fifo, &err_info)) {
		trace_mem_ras_event(ubc->mem_device, &err_info);
		pr_info("ras: type=%u\n", err_info.type);
		if (err_info.type == UB_MEM_PORT_WARNING ||
		    err_info.type == UB_MEM_PORT_RECOVERY) {
			vals[0] = err_info.val0;
			vals[1] = err_info.val1;
			vals[2] = ctl_no;
			if (handler) {
				ret = handler((u64)vals, err_info.type);
				WARN_ON(ret);
			}
		} else {
			if (handler) {
				ret = handler(err_info.val0, err_info.type);
				WARN_ON(ret);
			}
		}
	}

	return IRQ_HANDLED;
}

static int err_type_bitmap[] = {
	/* DEVICE_RAS_STATUS_3 */
	[UB_MEM_ATOMIC_DATA_ERR] = 31,
	[UB_MEM_READ_DATA_ERR] = 28,
	[UB_MEM_FLOW_POISON] = 27,
	[UB_MEM_FLOW_READ_AUTH_POISON] = 23,
	[UB_MEM_FLOW_READ_AUTH_RESPERR] = 22,
	[UB_MEM_TIMEOUT_POISON] = 21,
	[UB_MEM_TIMEOUT_RESPERR] = 20,
	[UB_MEM_READ_DATA_POISON] = 19,
	[UB_MEM_READ_DATA_RESPERR] = 18,
	/* DEVICE_RAS_STATUS_4 */
	[MAR_NOPORT_VLD_INT_ERR] = 26,
	[MAR_FLUX_INT_ERR] = 25,
	[MAR_WITHOUT_CXT_ERR] = 24,
	[RSP_BKPRE_OVER_TIMEOUT_ERR] = 10,
	/* DEVICE_RAS_STATUS_4 need save addr */
	[MAR_NEAR_AUTH_FAIL_ERR] = 21,
	[MAR_FAR_AUTH_FAIL_ERR] = 22,
	[MAR_TIMEOUT_ERR] = 23,
	[MAR_ILLEGAL_ACCESS_ERR] = 9,
	[REMOTE_READ_DATA_ERR_OR_WRITE_RESPONSE_ERR] = 11,
	/* DEVICE_RAS_STATUS_4 need save transaction id and port bitmap */
	[UB_MEM_PORT_WARNING] = 31,
	/* DEVICE_RAS_STATUS_4 need save transaction id */
	[UB_MEM_PORT_RECOVERY] = 30,
};

static int save_injected_route_info(struct ub_bus_controller *ubc,
				    struct hi_ubmem_event *info,
				    unsigned long status4_bitmap)
{
	u32 addr_h, addr_l;
	u64 val0, val1;
	int ret, i;

	if (test_bit(err_type_bitmap[UB_MEM_PORT_WARNING], &status4_bitmap)) {
		i = UB_MEM_PORT_WARNING;
		addr_h = info->err_addr[1];
		addr_l = info->err_addr[0];
		val0 = hpa_gen(addr_h, addr_l);
		addr_h = info->err_addr[3];
		addr_l = info->err_addr[2];
		val1 = hpa_gen(addr_h, addr_l);
		ret = save_ras_err_info(ubc->mem_device, (enum ras_err_type)i, val0, val1);
		if (ret)
			return ret;
	}

	if (test_bit(err_type_bitmap[UB_MEM_PORT_RECOVERY], &status4_bitmap)) {
		i = UB_MEM_PORT_RECOVERY;
		addr_h = info->err_addr[5];
		addr_l = info->err_addr[4];
		val0 = hpa_gen(addr_h, addr_l);
		ret = save_ras_err_info(ubc->mem_device, (enum ras_err_type)i, val0, 0);
		if (ret)
			return ret;
	}

	return 0;
}

static int save_ras_err_info_all(struct ub_bus_controller *ubc, struct hi_ubmem_event *info)
{
	unsigned long status3_bitmap = (unsigned long)info->device_ras_status3;
	unsigned long status4_bitmap = (unsigned long)info->device_ras_status4;
	u32 addr_h, addr_l;
	int ret = -EINVAL;
	int index, i;
	u64 val0 = 0;

	/* receives and processes one injected route event at a time */
	if (test_bit(err_type_bitmap[UB_MEM_PORT_WARNING], &status4_bitmap) ||
	    test_bit(err_type_bitmap[UB_MEM_PORT_RECOVERY], &status4_bitmap))
		return save_injected_route_info(ubc, info, status4_bitmap);

	for (i = UB_MEM_ATOMIC_DATA_ERR; i <= UB_MEM_READ_DATA_RESPERR; i++) {
		if (test_bit(err_type_bitmap[i], &status3_bitmap)) {
			ret = save_ras_err_info(ubc->mem_device, (enum ras_err_type)i, val0, 0);
			if (ret)
				return ret;
		}
	}

	for (i = MAR_FLUX_INT_ERR; i <= RSP_BKPRE_OVER_TIMEOUT_ERR; i++) {
		if (test_bit(err_type_bitmap[i], &status4_bitmap)) {
			ret = save_ras_err_info(ubc->mem_device, (enum ras_err_type)i, val0, 0);
			if (ret)
				return ret;
		}
	}

	for (i = MAR_NEAR_AUTH_FAIL_ERR; i <= REMOTE_READ_DATA_ERR_OR_WRITE_RESPONSE_ERR; i++) {
		if (test_bit(err_type_bitmap[i], &status4_bitmap)) {
			index = MAR_ERR_ADDR_SIZE * (i - MAR_NEAR_AUTH_FAIL_ERR);
			addr_h = info->err_addr[index + 1];
			addr_l = info->err_addr[index];
			val0 = hpa_gen(addr_h, addr_l);
			ret = save_ras_err_info(ubc->mem_device, (enum ras_err_type)i, val0, 0);
			if (ret)
				return ret;
		}
	}

	/* if no_port_vld and near_auth_fail report at the same time, ignore no_port_vld */
	if (test_bit(err_type_bitmap[MAR_NOPORT_VLD_INT_ERR], &status4_bitmap) &&
	    !test_bit(err_type_bitmap[MAR_NEAR_AUTH_FAIL_ERR], &status4_bitmap)) {
		i = MAR_NOPORT_VLD_INT_ERR;
		ret = save_ras_err_info(ubc->mem_device, (enum ras_err_type)i, val0, 0);
	}

	return ret;
}

static irqreturn_t hi_mem_ras_irq(int irq, void *context)
{
	struct ub_bus_controller *ubc = (struct ub_bus_controller *)context;
	struct hi_get_ubmem_event_pld pld = {};
	struct msg_info info = {};
	u32 event_cnt;
	int ret;

	message_info_init(&info, ubc->uent, &pld, &pld,
			  (HI_GET_UBMEM_EVENT_REQ_SIZE << MSG_REQ_SIZE_OFFSET) |
			  HI_GET_UBMEM_EVENT_RSP_SIZE);
	ret = hi_message_private(ubc->mdev, &info, GET_UBMEM_EVENT_CMD);
	if (ret) {
		dev_err(&ubc->dev, "get ubmem event failed, ret=%d\n",
			ret);
		return IRQ_HANDLED;
	}

	event_cnt = pld.rsp.event_num;
	if (event_cnt == 0 || event_cnt > MEM_EVENT_MAX_NUM) {
		dev_warn(&ubc->dev, "event_cnt [%u] is invalid\n", event_cnt);
		return IRQ_HANDLED;
	}

	for (u32 i = 0; i < event_cnt; i++) {
		ret = save_ras_err_info_all(ubc, &pld.rsp.event_info[i]);
		if (ret == -EINVAL) {
			dev_err(&ubc->dev, "save_ras_err_info failed, ret=%d\n", ret);
			return IRQ_HANDLED;
		}
	}

	return IRQ_WAKE_THREAD;
}

static bool is_ub_mem_version_valid(struct ub_bus_controller *ubc)
{
	struct hi_ubc_private_data *data = ubc->data;

	if (!data || data->ub_mem_version == UB_MEM_VERSION_INVALID)
		return false;
	return true;
}

static int hi_mem_decoder_create_one(struct ub_bus_controller *ubc, int index)
{
	struct ub_mem_decoder *decoder, *priv_data = ubc->mem_device->priv_data;
	struct hi_ubc_private_data *data = ubc->data;

	decoder = &priv_data[index];
	decoder->dev = &ubc->dev;
	decoder->uent = ubc->uent;

	decoder->base_reg = ioremap(data->mem_pa_info[index].decode_addr,
				    SZ_64);
	if (!decoder->base_reg) {
		dev_err(decoder->dev, "ub mem decoder base reg ioremap failed.\n");
		return -ENOMEM;
	}

	return 0;
}

static void hi_mem_decoder_remove_one(struct ub_bus_controller *ubc, int index)
{
	struct ub_mem_decoder *priv_data = ubc->mem_device->priv_data;

	iounmap(priv_data[index].base_reg);
}

static u8 get_mem_decoder_number(struct hi_ubc_private_data *data)
{
	switch (data->ub_mem_version) {
	case UB_MEM_VERSION_0:
	case UB_MEM_VERSION_1:
		return MEM_DECODER_NUMBER_V1;
	case UB_MEM_VERSION_2:
		return MEM_DECODER_NUMBER_V2;
	default:
		return 0;
	}
}

int hi_mem_decoder_create(struct ub_bus_controller *ubc)
{
	struct hi_ubc_private_data *data = ubc->data;
	struct ub_mem_device *mem_device;
	void *priv_data;
	int ret;

	if (!is_ub_mem_version_valid(ubc)) {
		dev_info(&ubc->dev, "Don't need to create mem decoder\n");
		return 0;
	}

	ub_mem_num = get_mem_decoder_number(data);
	if (!ub_mem_num)
		return -EINVAL;

	mem_device = kzalloc(sizeof(*mem_device), GFP_KERNEL);
	if (!mem_device)
		return -ENOMEM;

	priv_data = kcalloc(ub_mem_num, sizeof(struct ub_mem_decoder),
			    GFP_KERNEL);
	if (!priv_data) {
		kfree(mem_device);
		return -ENOMEM;
	}

	mem_device->dev = &ubc->dev;
	mem_device->uent = ubc->uent;
	mem_device->ubmem_irq_num = -1;
	mem_device->ops = &device_ops;
	mem_device->priv_data = priv_data;
	ubc->mem_device = mem_device;

	for (int i = 0; i < ub_mem_num; i++) {
		ret = hi_mem_decoder_create_one(ubc, i);
		if (ret) {
			dev_err(&ubc->dev, "hi mem create decoder %d failed\n", i);
			for (int j = i - 1; j >= 0; j--)
				hi_mem_decoder_remove_one(ubc, j);

			kfree(mem_device->priv_data);
			kfree(mem_device);
			ubc->mem_device = NULL;
			return ret;
		}
	}

	return ret;
}

void hi_mem_decoder_remove(struct ub_bus_controller *ubc)
{
	if (!ubc->mem_device)
		return;

	if (!is_ub_mem_version_valid(ubc)) {
		dev_info(&ubc->dev, "Don't need to remove mem decoder\n");
		return;
	}

	for (int i = 0; i < ub_mem_num; i++)
		hi_mem_decoder_remove_one(ubc, i);

	kfree(ubc->mem_device->priv_data);
	kfree(ubc->mem_device);
	ubc->mem_device = NULL;
}

void hi_register_ubmem_irq(struct ub_bus_controller *ubc)
{
	struct ub_entity *uent = ubc->uent;
	int irq_num, ret;
	u32 usi_idx;

	if (!ubc->mem_device) {
		pr_err("register ubmem irq failed, mem device is NULL!\n");
		return;
	}

	if (!is_ub_mem_version_valid(ubc)) {
		dev_info(&ubc->dev, "Don't need to register_ubmem_irq\n");
		return;
	}

	ret = ub_cfg_read_dword(uent, UB_MEM_USI_IDX, &usi_idx);
	if (ret) {
		ub_err(uent, "get ubmem usi idx failed, ret=%d\n", ret);
		return;
	}

	irq_num = ub_irq_vector(uent, usi_idx);
	if (irq_num < 0) {
		ub_err(uent, "ub get irq vector failed, irq num=%d\n", irq_num);
		return;
	}

	INIT_KFIFO(ubc->mem_device->ras_ctx.ras_fifo);

	ret = request_threaded_irq(irq_num, hi_mem_ras_irq,
					   hi_mem_ras_isr, IRQF_SHARED,
					   "ub_mem_event", ubc);
	if (ret) {
		ub_err(uent, "ubmem request_irq failed, ret=%d\n", ret);
		return;
	}

	ubc->mem_device->ubmem_irq_num = irq_num;
}

void hi_unregister_ubmem_irq(struct ub_bus_controller *ubc)
{
	int irq_num;

	if (!ubc->mem_device) {
		dev_err(&ubc->dev, "mem device is NULL!\n");
		return;
	}

	if (!is_ub_mem_version_valid(ubc)) {
		dev_info(&ubc->dev, "Don't need to unregister_ubmem_irq\n");
		return;
	}

	irq_num = ubc->mem_device->ubmem_irq_num;
	if (irq_num < 0)
		return;

	free_irq((unsigned int)irq_num, (void *)ubc);
}

#define MB_SIZE_OFFSET 20

static bool ub_hpa_valid(u64 pa_start, u64 pa_end, u32 base_addr, u32 size)
{
	if (pa_start >= ((u64)base_addr << MB_SIZE_OFFSET) &&
	    pa_end < (((u64)base_addr + (u64)size) << MB_SIZE_OFFSET))
		return true;

	return false;
}

static bool hi_mem_validate_pa(struct ub_bus_controller *ubc,
			       u64 pa_start, u64 pa_end, bool cacheable)
{
	struct hi_ubc_private_data *data;

	if (!ubc->data) {
		dev_err(&ubc->dev, "Ubc data is null.\n");
		return false;
	}

	if (pa_end < pa_start) {
		dev_err(&ubc->dev, "pa_start is over pa_end.\n");
		return false;
	}

	data = ubc->data;
	for (u16 i = 0; i < ub_mem_num; i++) {
		if (ub_hpa_valid(pa_start, pa_end,
				 data->mem_pa_info[i].cc_base_addr,
				 data->mem_pa_info[i].cc_base_size) &&
		    cacheable)
			return true;

		if (ub_hpa_valid(pa_start, pa_end,
				 data->mem_pa_info[i].nc_base_addr,
				 data->mem_pa_info[i].nc_base_size) &&
		    !cacheable)
			return true;
	}

	return false;
}
