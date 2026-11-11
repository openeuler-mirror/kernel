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

#define DRAIN_ENABLE_REG_OFFSET 0x24
#define DRAIN_STATE_REG_OFFSET 0x28
#define UPA_DRAIN_OFFSET 0x1A888

#define HI_GET_UBMEM_EVENT_REQ_SIZE 4
#define HI_GET_UBMEM_EVENT_RSP_SIZE 772
#define HI_GET_UBMEM_EVENT_V2_RSP_SIZE 1156
#define MEM_EVENT_MAX_NUM 16
#define MAR_ERR_ADDR_COUNT 10
#define MAR_ERR_ADDR_SIZE 2
#define MEM_DECODER_NUMBER_V1 5
#define MEM_DECODER_NUMBER_V2 2
#define UBMEM_ERR_MISC_OFFSET 8

#define hpa_gen(addr_h, addr_l) (((u64)(addr_h) << 32) | (addr_l))
#define gen_ubmevt(module_id, module_event_id) \
		(((u32)module_id << 16) | (u16)module_event_id)
#define vendor_gen(vendor, device) \
		(((u32)vendor << 16) | device)

enum ubmem_event_module {
	UBMEVT_LOCAL_BUS = 0x0001U,
	UBMEVT_LOCAL_BUFFER = 0x0002U,
	UBMEVT_LOCAL_OUTBOUND_ROUTE = 0x0003U,
	UBMEVT_LOCAL_OUTBOUND_TRANSLATION = 0x0004U,
	UBMEVT_LOCAL_INBOUND_TRANSLATION = 0x0005U,
	UBMEVT_REMOTE = 0x8000U,
	UBMEVT_UNDEFINE = 0xffffU,
};

enum ubmem_event_id {
	UBMEVT_LOCAL_BUS_UNSUPPORTED_OP =
		gen_ubmevt(UBMEVT_LOCAL_BUS, 0x0U),
	UBMEVT_LOCAL_BUS_UNSUPPORTED_LOAD =
		gen_ubmevt(UBMEVT_LOCAL_BUS, 0x1U),
	UBMEVT_LOCAL_BUS_UNSUPPORTED_STORE =
		gen_ubmevt(UBMEVT_LOCAL_BUS, 0x2U),
	UBMEVT_LOCAL_BUS_DATA_POISONED =
		gen_ubmevt(UBMEVT_LOCAL_BUS, 0x4U),
	UBMEVT_LOCAL_INBOUND_NO_MAPPING_IN_ADDRESS_SPACE =
		gen_ubmevt(UBMEVT_LOCAL_INBOUND_TRANSLATION, 0x0U),
	UBMEVT_LOCAL_INBOUND_TOKENID_OUT_OF_RANGE =
		gen_ubmevt(UBMEVT_LOCAL_INBOUND_TRANSLATION, 0x1U),
	UBMEVT_LOCAL_INBOUND_INVALID_BUS_CONFIG =
		gen_ubmevt(UBMEVT_LOCAL_INBOUND_TRANSLATION, 0x2U),
	UBMEVT_LOCAL_OUTBOUND_NO_AVAILABLE_PORT =
		gen_ubmevt(UBMEVT_LOCAL_OUTBOUND_ROUTE, 0x0U),
	UBMEVT_LOCAL_OUTBOUND_DECODER_TAMPERED_ON_THE_FLY =
		gen_ubmevt(UBMEVT_LOCAL_OUTBOUND_TRANSLATION, 0x2U),
	UBMEVT_LOCAL_OUTBOUND_NO_MAPPING =
		gen_ubmevt(UBMEVT_LOCAL_OUTBOUND_TRANSLATION, 0x3U),
	UBMEVT_REMOTE_WRITE_RESPONSE_ERROR =
		gen_ubmevt(UBMEVT_REMOTE, 0x0U),
	UBMEVT_REMOTE_READ_RESPONSE_ERROR =
		gen_ubmevt(UBMEVT_REMOTE, 0x1U),
	UBMEVT_REMOTE_DATA_POISONED =
		gen_ubmevt(UBMEVT_REMOTE, 0x2U),
	UBMEVT_REMOTE_TIMEOUT =
		gen_ubmevt(UBMEVT_REMOTE, 0x3U),
	UBMEVT_UNDEFINE_NULL =
		gen_ubmevt(UBMEVT_UNDEFINE, 0x0U),
};

struct upa_err_misc {
	union {
		struct {
			u32 err_frl;
			u32 err_frh;
			u32 err_ctrll;
			u32 err_ctrlh;
			struct {
				u32 ras_status_serr : 8;
				u32 ras_status_ierr : 8;
				u32 rsvd : 15;
				u32 ras_status_av : 1;
			} err_statusl;
			u32 err_statush;
			u32 err_addrl;
			struct {
				u32 ras_asddr_msb : 24;
				u32 rsvd : 5;
				u32 ras_address_ai : 1;
				u32 rsvd1 : 2;
			} err_addrh;
			u32 err_misc0l;
			u32 err_misc0h;
			struct {
				u32 upa_ras_timeout_int : 12;
				u32 upa_ras_rps_int : 12;
				u32 upa_rxsch_exceed_int : 8;
			} err_misc1l;
			struct {
				u32 upa_ras_mem_ecc_int : 9;
				u32 upa_ras_fifo_of_uf_int : 23;
			} err_misc1h;
			u32 err_misc2l;
			struct {
				u32 upa_ras_sys_decode_err_int : 5;
				u32 upa_ras_so_outstanding_int : 1;
				u32 rsvd : 2;
				u32 upa_ras_sys_err_int : 16;
				u32 upa_ras_rxsch_opcode_int : 8;
			} err_misc2h;
			u32 err_misc3l;
			u32 err_misc3h;
		};
		u32 err_data[16];
	};
};

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
	union {
		struct hi_ubmem_event event_info[MEM_EVENT_MAX_NUM];
		struct ub_mem_event_info event_info_v2[MEM_EVENT_MAX_NUM];
	};
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

struct ubmem_event_match {
	enum ubmem_event_id event_id;
	u8 serr;
	u8 ierr;
	u8 misc_num;
	u32 valid_bit;
};

static const struct ubmem_event_match ubmem_event_table[] = {
	{ UBMEVT_LOCAL_BUS_UNSUPPORTED_OP, 0x1, 0x1, 5, BIT(8)},
	{ UBMEVT_LOCAL_BUS_UNSUPPORTED_LOAD, 0x1, 0x1, 5, BIT(9)},
	{ UBMEVT_LOCAL_BUS_UNSUPPORTED_STORE, 0x1, 0x1, 5, BIT(10)},
	{ UBMEVT_LOCAL_BUS_DATA_POISONED, 0x12, 0xC, 5, BIT(14)},
	{ UBMEVT_LOCAL_INBOUND_NO_MAPPING_IN_ADDRESS_SPACE, 0xD, 0x3, 5, GENMASK(21, 20)},
	{ UBMEVT_LOCAL_INBOUND_TOKENID_OUT_OF_RANGE, 0xD, 0x3, 5, BIT(19)},
	{ UBMEVT_LOCAL_INBOUND_INVALID_BUS_CONFIG, 0xD, 0x4, 5, BIT(0)},
	{ UBMEVT_LOCAL_OUTBOUND_NO_AVAILABLE_PORT, 0xD, 0xD, 5, BIT(15)},
	{ UBMEVT_LOCAL_OUTBOUND_DECODER_TAMPERED_ON_THE_FLY, 0xD, 0xD, 5, BIT(17)},
	{ UBMEVT_LOCAL_OUTBOUND_NO_MAPPING, 0xD, 0xD, 5, BIT(18)},
	{ UBMEVT_REMOTE_WRITE_RESPONSE_ERROR, 0x12, 0xE, 5, BIT(22)},
	{ UBMEVT_REMOTE_READ_RESPONSE_ERROR, 0x12, 0xE, 5, BIT(23)},
	{ UBMEVT_REMOTE_DATA_POISONED, 0x12, 0xC, 5, BIT(13)},
	{ UBMEVT_REMOTE_TIMEOUT, 0x13, 0x5, 2, GENMASK(15, 12)},
};

static enum ubmem_event_id find_match_event_id(const struct upa_err_misc *err_misc)
{
	const struct ubmem_event_match *match;
	int i;

	for (i = 0; i < ARRAY_SIZE(ubmem_event_table); i++) {
		match = &ubmem_event_table[i];
		if (match->serr == err_misc->err_statusl.ras_status_serr &&
			match->ierr == err_misc->err_statusl.ras_status_ierr &&
			(err_misc->err_data[UBMEM_ERR_MISC_OFFSET + match->misc_num]
			& match->valid_bit))
			return match->event_id;
	}

	return UBMEVT_UNDEFINE_NULL;
}

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

static void hi_mem_ras_process_v1(struct ub_bus_controller *ubc)
{
	struct ub_mem_ras_ctx *ras_ctx = &ubc->mem_device->ras_ctx;
	struct ub_mem_ras_err_info err_info;
	ubmem_ras_handler handler;
	u64 ctl_no = ubc->ctl_no;
	u64 vals[3];
	int ret;

	mutex_lock(&mem_ras_mutex);
	handler = ub_mem_ras_handler_get();
	while (kfifo_get(&ras_ctx->ras_fifo, &err_info)) {
		trace_mem_ras_event(ubc->mem_device, &err_info);
		pr_info("UB memory ras event: type=%u\n", err_info.type);
		if (err_info.type == UB_MEM_PORT_WARNING ||
		    err_info.type == UB_MEM_PORT_RECOVERY) {
			vals[0] = err_info.val0;
			vals[1] = err_info.val1;
			vals[2] = ctl_no;
			if (handler) {
				ret = handler((u64)vals, err_info.type);
				if (ret)
					pr_err("UB memory ras handler failed, ret=%d\n",
					       ret);
			}
		} else {
			if (handler) {
				ret = handler(err_info.val0, err_info.type);
				if (ret)
					pr_err("UB memory ras handler failed, ret=%d\n",
					       ret);
			}
		}
	}
	mutex_unlock(&mem_ras_mutex);
}

static void hi_mem_ras_process_v2(struct ub_bus_controller *ubc)
{
	struct ub_mem_event_ctx *event_ctx = ubc->mem_device->event_ctx;
	struct ub_mem_event_info event_data;
	ubmem_event_handler event_handler;
	struct upa_err_misc err_misc;
	int ret;

	mutex_lock(&mem_ras_mutex);
	event_handler = ub_mem_event_handler_get();

	while (kfifo_get(&event_ctx->event_fifo, &event_data)) {
		struct ubmem_event event_info = {0};

		if (!event_handler)
			continue;

		if (event_data.status0) {
			memcpy(&err_misc, event_data.info, sizeof(err_misc));
			event_info.event_id = find_match_event_id(&err_misc);
			event_info.pa_valid = err_misc.err_statusl.ras_status_av &&
				!err_misc.err_addrh.ras_address_ai;
			if (event_info.pa_valid)
				event_info.pa = hpa_gen(err_misc.err_addrh.ras_asddr_msb,
							err_misc.err_addrl);
		} else {
			event_info.event_id = UBMEVT_UNDEFINE_NULL;
		}
		event_info.vendor_info = vendor_gen(ubc->uent->guid.bits.vendor,
							    ubc->uent->guid.bits.device);
		event_info.vendor_data_len = sizeof(event_data);
		event_info.vendor_data = &event_data;

		ret = event_handler(&event_info);
		if (ret)
			pr_err("UB memory event handler failed, ret=%d\n", ret);
	}
	mutex_unlock(&mem_ras_mutex);
}

static irqreturn_t hi_mem_ras_isr(int irq, void *context)
{
	struct ub_bus_controller *ubc = (struct ub_bus_controller *)context;
	struct hi_ubc_private_data *data = (struct hi_ubc_private_data *)ubc->data;

	if (data->ub_mem_version == UB_MEM_VERSION_2)
		hi_mem_ras_process_v2(ubc);
	else
		hi_mem_ras_process_v1(ubc);

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

static int save_ras_err_info_v2(struct ub_bus_controller *ubc, struct ub_mem_event_info *info)
{
	if (!info->status0 && !info->status1) {
		dev_err(&ubc->dev, "upa_status: %#08x, umau_status: %#08x\n",
		 info->status0, info->status1);
		return -EINVAL;
	}

	if (!kfifo_put(&ubc->mem_device->event_ctx->event_fifo, *info)) {
		dev_err(&ubc->dev, "kfifo put failed!\n");
		return -ENOMEM;
	}

	return 0;
}

static irqreturn_t hi_mem_ras_irq(int irq, void *context)
{
	struct ub_bus_controller *ubc = (struct ub_bus_controller *)context;
	struct hi_ubc_private_data *data = (struct hi_ubc_private_data *)ubc->data;
	struct hi_get_ubmem_event_pld pld = {};
	struct msg_info info = {};
	u32 event_cnt;
	u32 rsp_size;
	int ret;

	if (data->ub_mem_version == UB_MEM_VERSION_2)
		rsp_size = HI_GET_UBMEM_EVENT_V2_RSP_SIZE;
	else
		rsp_size = HI_GET_UBMEM_EVENT_RSP_SIZE;

	message_info_init(&info, ubc->uent, &pld, &pld,
			  (HI_GET_UBMEM_EVENT_REQ_SIZE << MSG_REQ_SIZE_OFFSET) |
			  rsp_size);
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
		if (data->ub_mem_version == UB_MEM_VERSION_2)
			ret = save_ras_err_info_v2(ubc, &pld.rsp.event_info_v2[i]);
		else
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
	u64 base_addr;

	decoder = &priv_data[index];
	decoder->dev = &ubc->dev;
	decoder->uent = ubc->uent;

	if (data->ub_mem_version == UB_MEM_VERSION_2)
		base_addr = data->mem_pa_info[index].decode_addr + UPA_DRAIN_OFFSET;
	else
		base_addr = data->mem_pa_info[index].decode_addr;

	decoder->base_reg = ioremap(base_addr, SZ_64);
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

	if (data->ub_mem_version == UB_MEM_VERSION_2) {
		mem_device->event_ctx = kzalloc(sizeof(*mem_device->event_ctx),
						GFP_KERNEL);
		if (!mem_device->event_ctx) {
			kfree(priv_data);
			kfree(mem_device);
			return -ENOMEM;
		}
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

			kfree(mem_device->event_ctx);
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

	kfree(ubc->mem_device->event_ctx);
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
	if (ubc->mem_device->event_ctx)
		INIT_KFIFO(ubc->mem_device->event_ctx->event_fifo);

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
