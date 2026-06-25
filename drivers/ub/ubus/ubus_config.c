// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus config: " fmt

#include "ubus.h"
#include "msg.h"
#include "ubus_config.h"
#include "ubus_inner.h"

struct cfg_msg_pld_req {
	/* DW0 */
	u32 rsvd0 : 4;
	u32 byte_enable : 4;
	u32 rsvd1 : 8;
	u32 entity_idx : 16;
	/* DW1 */
	u32 req_addr;
	/* DW2 */
	u32 rsvd2;
	/* DW3 */
	u32 write_data;
};

struct cfg_msg_pld_rsp {
	/* DW0 */
	u32 read_data;
	/* DW1 */
	u32 rsvd1;
	/* DW2 */
	u32 rsvd2;
	/* DW3 */
	u32 rsvd3;
};

struct cfg_msg_req_pkt {
	struct msg_pkt_header header;
	struct cfg_msg_pld_req req_payload;
};

struct cfg_msg_rsp_pkt {
	struct msg_pkt_header header;
	struct cfg_msg_pld_rsp rsp_payload;
};

enum ub_cfg_sub_msg_code {
	UB_CFG0_READ = 0,
	UB_CFG0_WRITE = 1,
	UB_CFG1_READ = 2,
	UB_CFG1_WRITE = 3
};

#define CFG_MSG_PLD_SIZE 16

struct ub_cfg {
	u8 size;
	u8 pos_mask;
	u8 byte_mask;
};

static struct ub_cfg ub_cfg_param[] = { { 0x1, 0x0, 0x1 },
					{ 0x2, 0x1, 0x3 },
					{ 0x4, 0x3, 0xf } };
#define UB_CFG_PARAM_CNT ARRAY_SIZE(ub_cfg_param)

static bool pos_size_valid(u64 pos, u8 size)
{
	struct ub_cfg *cfg;
	u8 i;

	if (pos >= UB_CFG_SAPCE_SLICE_END)
		return false;

	for (i = 0; i < UB_CFG_PARAM_CNT; i++) {
		cfg = &ub_cfg_param[i];
		if (cfg->size == size)
			return !(pos & cfg->pos_mask);
	}
	return false; /* size invalid */
}

static void ub_msg_extended_header_init(struct msg_extended_header *msgetah,
					u16 plen, u8 code)
{
	msgetah->plen = plen;
	msgetah->msg_code = msg_code(code);
	msgetah->type = msg_type(code);
	msgetah->sub_msg_code = sub_msg_code(code);
}

void ub_msg_pkt_header_init(struct msg_pkt_header *header, struct ub_entity *uent,
			    u16 plen, u8 code, bool flag)
{
	struct compact_network_header *cnth = &header->nth;
	struct ub_link_header *ulh = &header->ulh;
	struct ub_entity *ubc_uent = uent->ubc->uent;
	u32 seid = ubc_uent->eid;
	u16 scna = (u16)ubc_uent->cna;
	u32 deid = uent->eid;
	u16 dcna = (u16)uent->cna;

	if (flag) {
		dcna = scna;
		deid = seid;
	}

	ulh->cfg = UB_COMPACT_LINK_CFG;

	cnth->nth_nlp = NTH_NLP_WITH_TPH;
	cnth->scna = scna;
	cnth->dcna = dcna;
	cnth->mgmt = (is_p_device(uent) ||
		      (uent->pool && uent_type(uent) == UB_TYPE_CONTROLLER))
		      ? 0 : 1;

	header->ctph_nlp = CTPH_NLP_UPI_40BITS_UEID;
	header->tp_opcode = CTPH_OPCODE_NOT_CNP;
	header->pad = 0;
	header->upi = uent->ubc->cluster ? uent->upi : UB_CP_UPI;
	header->seid_h = seid_high(seid);
	header->seid_l = seid_low(seid);
	header->deid = deid;
	header->ta_opcode = TAH_OPCODE_MSG;

	ub_msg_extended_header_init(&header->msgetah, plen, code);
}
EXPORT_SYMBOL_GPL(ub_msg_pkt_header_init);

int ub_check_cfg_msg_code(struct device *dev, u8 req_code, u8 rsp_code)
{
	u8 req_sub = sub_msg_code(req_code);
	u8 rsp_sub = sub_msg_code(rsp_code);
	u8 req = msg_code(req_code);
	u8 rsp = msg_code(rsp_code);

	if (req != UB_MSG_CODE_CFG || rsp != UB_MSG_CODE_CFG) {
		dev_err(dev, "The message code is incorrect, req message code=%#x, rsp message code=%#x\n",
			req, rsp);
		return -EIO;
	}

	if (msg_type(req_code) == MSG_REQ &&
	    msg_type(rsp_code) == MSG_RSP && req_sub == rsp_sub)
		return 0;

	dev_err(dev, "The response code is incorrect, req code=%#x, rsp code=%#x\n",
			req_code, rsp_code);
	return -EIO;
}
EXPORT_SYMBOL_GPL(ub_check_cfg_msg_code);

static int ub_sync_cfg_rsp_check(struct ub_entity *uent,
				 struct cfg_msg_req_pkt *req_pkt,
				 struct cfg_msg_rsp_pkt *rsp_pkt)
{
	struct msg_pkt_header *req_header = &req_pkt->header;
	struct msg_pkt_header *rsp_header = &rsp_pkt->header;
	u32 rsp_seid = eid_gen(rsp_header->seid_h, rsp_header->seid_l);
	u32 req_seid = eid_gen(req_header->seid_h, req_header->seid_l);
	u8 rsp_status = rsp_header->msgetah.rsp_status;

	if (rsp_status != UB_MSG_RSP_SUCCESS) {
		ub_err(uent, "Message response error, rsp_status=%#x\n",
		       rsp_status);
		return -EIO;
	}

	if (rsp_header->nth.scna != req_header->nth.dcna ||
		rsp_header->nth.dcna != req_header->nth.scna) {
		ub_err(uent, "CNA mismatch, req_scna=%#x req_dcna=%#x, rsp_scna=%#x rsp_dcna=%#x\n",
			   req_header->nth.scna, req_header->nth.dcna,
			   rsp_header->nth.scna, rsp_header->nth.dcna);
		return -EIO;
	}

	if (rsp_seid != req_header->deid || rsp_header->deid != req_seid) {
		ub_err(uent, "EID mismatch, req_seid=%#x req_deid=%#x, rsp_seid=%#x rsp_deid=%#x\n",
			   req_seid, req_header->deid, rsp_seid, rsp_header->deid);
		return -EIO;
	}

	if (rsp_header->msgetah.plen != CFG_MSG_PLD_SIZE) {
		ub_err(uent, "The packet length is incorrect, len=%#x\n",
		       rsp_header->msgetah.plen);
		return -EIO;
	}

	return ub_check_cfg_msg_code(&uent->dev, req_header->msgetah.code,
				     rsp_header->msgetah.code);
}

static void ub_sync_cfg_rsp_handle(struct cfg_msg_pld_rsp *rsp, u8 size,
				   u64 pos, bool write, u32 *val)
{
#define UB_CFG_REG_SIZE 4
	u8 pos_in_reg = pos % UB_CFG_REG_SIZE;
	u32 read_data;

	if (!write) {
		read_data = rsp->read_data >> (pos_in_reg * BITS_PER_BYTE);
		if (size == sizeof(u8))
			*(u8 *)val = read_data;
		else if (size == sizeof(u16))
			*(u16 *)val = read_data;
		else
			*val = read_data;
	}
}

static u8 gen_cfg_sub_msg_code(bool is_write, u64 pos)
{
	if (pos >= UB_CFG1_BASIC_SLICE && pos < UB_PORT_SLICE_START)
		return is_write ? UB_CFG1_WRITE : UB_CFG1_READ;
	else
		return is_write ? UB_CFG0_WRITE : UB_CFG0_READ;
}

static void ub_msg_pkt_req_init(struct ub_entity *uent, u8 size, u64 pos, u32 *val,
				struct cfg_msg_pld_req *req)
{
	u8 bt_mask = ub_cfg_param[size >> 1].byte_mask;

	if (val) {
		if (size == sizeof(u8))
			req->write_data = *(u8 *)val;
		else if (size == sizeof(u16))
			req->write_data = *(u16 *)val;
		else
			req->write_data = *val;
		req->write_data <<= ((pos % sizeof(u32)) * BITS_PER_BYTE);
	}

	req->byte_enable = bt_mask << (u8)(pos % sizeof(u32));
	req->entity_idx = uent->entity_idx;
	/* The address is in four bytes. */
	req->req_addr = pos / sizeof(u32);
}

static bool ub_entity_is_disconnected(struct ub_entity *uent)
{
	struct ub_entity *pri = uent;

	if (uent->pool && uent_type(uent) == UB_TYPE_CONTROLLER)
		return false; /* Pool entity not consider here. */

	while (pri->entity_idx != 0)
		pri = pri->pue;

	return ub_entity_test_priv_flag(pri, UB_ENTITY_DISCONNECTED);
}

static int ub_sync_cfg(struct ub_entity *uent, u8 size, u64 pos, bool iswrite,
		       u32 *val)
{
	struct cfg_msg_req_pkt req_pkt = {};
	struct cfg_msg_rsp_pkt rsp_pkt = {};
	struct msg_info info = {};
	u8 sub_msg_code;
	int ret;

	if (ub_entity_is_disconnected(uent))
		return 0; /* Just silence */

	if (!pos_size_valid(pos, size)) {
		ub_err(uent, "pos or size invalid, pos=%#llx, size=%#x\n", pos,
		       size);
		return -EINVAL;
	}

	if (!iswrite)
		memset(val, 0xFF, size);

	sub_msg_code = gen_cfg_sub_msg_code(iswrite, pos);
	ub_msg_pkt_header_init(&req_pkt.header, uent, CFG_MSG_PLD_SIZE,
			       code_gen(UB_MSG_CODE_CFG, sub_msg_code,
					MSG_REQ), false);

	ub_msg_pkt_req_init(uent, size, pos, (iswrite ? val : NULL),
			    &req_pkt.req_payload);

	message_info_init(&info, uent, &req_pkt, &rsp_pkt,
			  (MSG_CFG_PKT_SIZE << MSG_REQ_SIZE_OFFSET) |
				  MSG_CFG_PKT_SIZE);
	ret = message_sync_request(uent->message->mdev, &info,
				   req_pkt.header.msgetah.code);
	if (ret)
		return ret;

	ret = ub_sync_cfg_rsp_check(uent, &req_pkt, &rsp_pkt);
	if (!ret)
		ub_sync_cfg_rsp_handle(&rsp_pkt.rsp_payload, size, pos, iswrite, val);

	return ret;
}

int ub_send_cfg(struct ub_entity *uent, u8 size, u64 pos, u32 *val)
{
	struct cfg_msg_req_pkt req_pkt = {};
	struct msg_info info = {};
	u8 sub_msg_code;

	if (!uent || !uent->message || !uent->message->mdev) {
		pr_err("uent or message or mdev is null\n");
		return -EINVAL;
	}

	if (!pos_size_valid(pos, size)) {
		pr_err("pos or size invalid, pos=%#llx, size=%u\n", pos, size);
		return -EINVAL;
	}

	sub_msg_code = gen_cfg_sub_msg_code(true, pos);
	ub_msg_pkt_header_init(&req_pkt.header, uent, CFG_MSG_PLD_SIZE,
			       code_gen(UB_MSG_CODE_CFG, sub_msg_code,
							MSG_REQ), false);

	ub_msg_pkt_req_init(uent, size, pos, val,
			    &req_pkt.req_payload);

	message_info_init(&info, uent, &req_pkt, NULL,
			  (MSG_CFG_PKT_SIZE << MSG_REQ_SIZE_OFFSET) |
			   MSG_CFG_PKT_SIZE);
	return message_send(uent->message->mdev, &info,
			    req_pkt.header.msgetah.code);
}

static int __ub_cfg_read_byte(struct ub_entity *uent, u64 pos, u8 *val)
{
	if (!uent || !uent->message || !uent->message->mdev || !val) {
		pr_err("uent or message or mdev is null\n");
		return -EINVAL;
	}

	return ub_sync_cfg(uent, (u8)sizeof(u8), pos, false, (u32 *)val);
}

static int __ub_cfg_read_word(struct ub_entity *uent, u64 pos, u16 *val)
{
	if (!uent || !uent->message || !uent->message->mdev || !val) {
		pr_err("uent or message or mdev is null\n");
		return -EINVAL;
	}

	return ub_sync_cfg(uent, (u8)sizeof(u16), pos, false, (u32 *)val);
}

static int __ub_cfg_read_dword(struct ub_entity *uent, u64 pos, u32 *val)
{
	if (!uent || !uent->message || !uent->message->mdev || !val) {
		pr_err("uent or message or mdev is null\n");
		return -EINVAL;
	}

	return ub_sync_cfg(uent, (u8)sizeof(u32), pos, false, val);
}

static int __ub_cfg_write_byte(struct ub_entity *uent, u64 pos, u8 val)
{
	if (!uent || !uent->message || !uent->message->mdev) {
		pr_err("uent or message or mdev is null\n");
		return -EINVAL;
	}

	return ub_sync_cfg(uent, (u8)sizeof(u8), pos, true, (u32 *)&val);
}

static int __ub_cfg_write_word(struct ub_entity *uent, u64 pos, u16 val)
{
	if (!uent || !uent->message || !uent->message->mdev) {
		pr_err("uent or message or mdev is null\n");
		return -EINVAL;
	}

	return ub_sync_cfg(uent, (u8)sizeof(u16), pos, true, (u32 *)&val);
}

static int __ub_cfg_write_dword(struct ub_entity *uent, u64 pos, u32 val)
{
	if (!uent || !uent->message || !uent->message->mdev) {
		pr_err("uent or message or mdev is null\n");
		return -EINVAL;
	}

	return ub_sync_cfg(uent, (u8)sizeof(u32), pos, true, (u32 *)&val);
}

int ub_cfg_ops_init(void)
{
	int ret;

	ret = register_ub_cfg_read_ops(__ub_cfg_read_byte, __ub_cfg_read_word,
				       __ub_cfg_read_dword);
	if (ret)
		return ret;

	ret = register_ub_cfg_write_ops(__ub_cfg_write_byte,
					__ub_cfg_write_word,
					__ub_cfg_write_dword);
	if (ret)
		unregister_ub_cfg_ops();

	return ret;
}
