// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus enum: " fmt

#include <linux/kfifo.h>

#include "ubus.h"
#include "ubus_inner.h"
#include "ubus_entity.h"
#include "msg.h"
#include "port.h"
#include "cna.h"
#include "route.h"
#include "task.h"
#include "enum.h"

#define ENUM_MAX_HOPS 255

enum enum_topo_query_opcode {
	ENUM_TOPO_QUERY_RESPONSE = 0,
	ENUM_TOPO_QUERY_REQUEST
};

enum enum_na_cfg_opcode {
	ENUM_NA_CFG_RESPONSE = 0,
	ENUM_NA_CFG_PRIMARY = 2,
	ENUM_NA_CFG_PORT = 3
};

enum enum_hop_type {
	ENUM_HOP_TYPE_4BIT = 0,
	ENUM_HOP_TYPE_BYTE,
	ENUM_HOP_TYPE_WORD
};

enum enum_na_query_opcode {
	ENUM_NA_QUERY_RESPONSE = 0,
	ENUM_NA_QUERY_SWITCH,
	ENUM_NA_QUERY_DEVICE,
	ENUM_NA_QUERY_PORT,
};

struct enum_na_cfg_req {
	/* DW0~DW5 */
	struct enum_pld_scan_pdu_common common;
	/* DW6 */
	u16 rsvd;
	u16 port_idx;
	/* DW7 */
	u32 cna : 24;
	u32 rsvd1 : 8;
};
#define ENUM_NA_CFG_REQ_SIZE 32

struct enum_na_cfg_rsp {
	/* DW0~DW5 */
	struct enum_pld_scan_pdu_common common;
};
#define ENUM_NA_CFG_RSP_SIZE 24

struct enum_na_query_req {
	/* DW0~DW5 */
	struct enum_pld_scan_pdu_common common;
	/* DW6 */
	u32 port_idx : 16;
	u32 rsv : 16;
};
#define ENUM_NA_QUERY_REQ_SIZE 28

struct enum_na_query_rsp {
	/* DW0~DW5 */
	struct enum_pld_scan_pdu_common common;
	/* DW6 */
	u32 cna : 24;
	u32 rsvd : 8;
};
#define ENUM_NA_QUERY_RSP_SIZE 28

static void ub_enum_pkt_header_init(void *buf)
{
	struct enum_pkt_header *header = (struct enum_pkt_header *)buf;
	struct compact_network_header *cnth = &header->cnth;
	struct ub_link_header *ulh = &header->ulh;

	ulh->cfg = UB_COMPACT_LINK_CFG;
	cnth->nth_nlp = NTH_NLP_WITHOUT_TPH;
	cnth->mgmt = 1;
	header->upi = UB_CP_UPI;
}

/* Attention: The caller must ensure that hop_type is valid */
static size_t calc_forward_path_size(struct enum_pld_scan_header *header)
{
#define FOUR_BITS_PER_DWORD 8
	u8 hop_bits[] = { SZ_4, SZ_8, SZ_16 };

	/* Path size is hops * hop_bits[], then align it to 4byte */
	return ALIGN(hop_bits[header->bits.hop_type] * header->bits.hops /
		     hop_bits[0], FOUR_BITS_PER_DWORD) / SZ_2;
}

static void set_hop_path(u8 *path, int type, u32 index, u32 val)
{
	u32 offset, mask;
	u16 *p;

	switch (type) {
	case ENUM_HOP_TYPE_4BIT:
		offset = index / SZ_2;
		mask = 0x0F << ((index % SZ_2) * SZ_4);
		val = val << ((index % SZ_2) * SZ_4);
		break;
	case ENUM_HOP_TYPE_BYTE:
		offset = index;
		mask = GENMASK(7, 0);
		break;
	case ENUM_HOP_TYPE_WORD:
		offset = index * SZ_2;
		mask = GENMASK(15, 0);
		break;
	default:
		return;
	}

	p = (u16 *)(path + offset);
	*p = (*p & ~mask) | (val & mask);
}

static void ub_enum_pld_header_init(struct ub_entity *uent, void *buf)
{
	struct enum_pld_scan_header *header;
	struct ub_entity *parent, *target;
	struct ub_port *port;
	u8 *path, *r_path;
	size_t size;
	int i, j;

	header = (struct enum_pld_scan_header *)(buf + ENUM_PKT_HEADER_SIZE);
	header->bits.hop_type = ENUM_HOP_TYPE_BYTE;
	header->bits.hops = (u32)uent->topo_rank;
	header->bits.step = 0;

	if (header->bits.hops == 0) /* First hop doesn't need path */
		return;

	header->bits.r = 1; /* Use return path */

	size = calc_forward_path_size(header);

	path = header->path;
	r_path = path + size;
	target = uent;
	for (i = uent->topo_rank - 1; i >= 0; i--) {
		parent = to_ub_entity(target->dev.parent);
		for_each_uent_port(port, parent) {
			if (port->r_uent == target) {
				set_hop_path(path, header->bits.hop_type,
					     (u32)i, (u32)port->index);
				j = uent->topo_rank - 1 - i;
				set_hop_path(r_path, header->bits.hop_type,
					     (u32)j, (u32)port->r_index);
				break;
			}
		}
		target = parent;
	}
}

/* rsp should check return value, req is inside caller, don't need */
size_t calc_enum_pld_header_size(struct enum_pld_scan_header *header, bool req)
{
	size_t bytes;

	if (!req && header->bits.hop_type > ENUM_HOP_TYPE_WORD) {
		pr_err("rsp header hop_type error, type=%u\n", header->bits.hop_type);
		return 0;
	}

	bytes = calc_forward_path_size(header);

	if (req && header->bits.r)
		bytes <<= 1;

	bytes += ENUM_PLD_SCAN_HEADER_BASE_SIZE;

	return bytes;
}
EXPORT_SYMBOL_GPL(calc_enum_pld_header_size);

/* pkt header + scan header */
static size_t ub_enum_calc_header_sz(void *buf, bool req)
{
	size_t bytes;

	bytes = calc_enum_pld_header_size((struct enum_pld_scan_header *)(buf +
					  ENUM_PKT_HEADER_SIZE), req);
	if (bytes == 0)
		return 0;

	return bytes + ENUM_PKT_HEADER_SIZE;
}

static struct topo_scan_info {
#define UB_TOPO_BUF_SZ SZ_4K
	void *buf;
	struct list_head dev_list;
} topo_scan;

static int ub_enum_topo_scan_init(void)
{
	topo_scan.buf = kzalloc(UB_TOPO_BUF_SZ, GFP_KERNEL);
	if (!topo_scan.buf)
		return -ENOMEM;

	INIT_LIST_HEAD(&topo_scan.dev_list);

	return 0;
}

static void ub_enum_topo_scan_uninit(void)
{
	kfree(topo_scan.buf);
}

static inline void ub_enum_refresh_and_init_buffer_header(struct ub_entity *uent,
							  void *buf)
{
	memset(buf, 0, UB_TOPO_BUF_SZ);
	ub_enum_pkt_header_init(buf);
	ub_enum_pld_header_init(uent, buf);
}

static void ub_enum_pld_common_setup(struct enum_pld_scan_pdu_common *common,
				     u8 cmd, u8 opcode, guid_t *guid,
				     int plen)
{
	common->bits.version = UB_ENUM_MNG_VERSION;
	common->bits.cmd = cmd;
	common->bits.opcode = opcode;
	common->msn = 0;
	common->guid = *guid;
	common->pdu_len = (u8)(plen / SZ_4);
}

static int ub_enum_topo_query(struct ub_entity *uent, void *buf, u16 start_idx,
			      u16 *actual_rsp_size)
{
	struct message_device *mdev = uent->message->mdev;
	struct enum_topo_query_req *req;
	struct msg_info info = {};
	size_t header_sz;
	int ret;

	ub_enum_refresh_and_init_buffer_header(uent, buf);

	header_sz = ub_enum_calc_header_sz(buf, true);
	req = (struct enum_topo_query_req *)(buf + header_sz);
	ub_enum_pld_common_setup(&req->common, ENUM_CMD_TOPO_QUERY,
				 ENUM_TOPO_QUERY_REQUEST, &uent->guid.id,
				 ENUM_TOPO_QUERY_REQ_SIZE);

	req->common.bits.slice_id = start_idx;

	message_info_init(&info, uent, buf, buf,
			  ((header_sz + ENUM_TOPO_QUERY_REQ_SIZE) <<
			  MSG_REQ_SIZE_OFFSET) | UB_TOPO_BUF_SZ);

	ret = message_sync_enum(mdev, &info, ENUM_CMD_TOPO_QUERY);
	if (!ret)
		*actual_rsp_size = info.actual_rsp_size;

	return ret;
}

static struct enum_topo_query_rsp *
ub_enum_topo_query_and_check(struct ub_entity *uent, void *buf, u16 start_idx)
{
	struct device *dev = &uent->ubc->dev;
	struct enum_topo_query_rsp *rsp;
	u16 actual_rsp_size;
	size_t header_sz;
	int ret;

	ret = ub_enum_topo_query(uent, buf, start_idx, &actual_rsp_size);
	if (ret) {
		dev_err(dev, "enum topo query failed, ret=%d\n", ret);
		return NULL;
	}

	header_sz = ub_enum_calc_header_sz(buf, false);
	if (header_sz == 0) {
		dev_err(dev, "enum topo query rsp header sz 0\n");
		return NULL;
	}

	if (header_sz + ENUM_TOPO_QUERY_RSP_BASE_SIZE > actual_rsp_size) {
		dev_err(dev, "enum topo query rsp pkt size invalid\n");
		return NULL;
	}

	rsp = (struct enum_topo_query_rsp *)(buf + header_sz);
	ret = rsp->common.bits.status;
	if (ret) {
		dev_err(dev, "enum rsp has error, status=%d\n", ret);
		return NULL;
	}

	if (header_sz + rsp->common.pdu_len * SZ_4 != actual_rsp_size) {
		dev_err(dev, "enum topo query rsp pdu_len invalid\n");
		return NULL;
	}

	return rsp;
}

static void ub_enum_parse_port(struct ub_entity *uent,
			       struct enum_tlv_port_info *pi, u16 num)
{
	struct enum_tlv_port_info *port_info;
	struct device *dev = &uent->ubc->dev;
	struct ub_port *port;

	for (u16 i = 0; i < num; i++) {
		port_info = pi + i;
		if (port_info->local_port_idx >= uent->port_nums) {
			dev_err(dev, "local port idx %u exceeds uent port num %u\n",
				port_info->local_port_idx, uent->port_nums);
			continue;
		}

		port = uent->ports + port_info->local_port_idx;

		port->domain_boundary = port_info->bits0.b;
		port->type = port_info->bits0.t ? VIRTUAL : PHYSICAL;
		port->shareable = (bool)port_info->bits0.w;

		/* skip link down port */
		if (!port_info->bits0.s)
			continue;

		if (!is_device(uent) && !is_idev(uent) && port->domain_boundary)
			continue;

		/* neighbor info of a boundary port shouldn't be stored */
		port->r_index = port_info->remote_port_idx;
		guid_copy(&port->r_guid, &port_info->remote_guid);
	}
}

struct enum_tlv_info {
	struct enum_tlv_slice_info *si;
	struct enum_tlv_port_info *pi;
	struct enum_tlv_port_num *pn;
	struct enum_tlv_cap_info *ci;
	u16 port_nums;
};

static int ub_enum_tlv_parse(void *tlv, int tlv_len, struct enum_tlv_info *info)
{
	struct enum_tlv_common *common;
	u16 port_nums = 0;
	int left_len = tlv_len;

	while ((left_len > 0) && (left_len % SZ_4 == 0)) {
		common = (struct enum_tlv_common *)tlv;

		switch (common->type) {
		case TLV_SLICE_INFO:
			info->si = (struct enum_tlv_slice_info *)tlv;
			break;
		case TLV_PORT_NUM:
			info->pn = (struct enum_tlv_port_num *)tlv;
			break;
		case TLV_PORT_INFO:
			if (port_nums == 0)
				info->pi = (struct enum_tlv_port_info *)tlv;
			port_nums++;
			break;
		case TLV_CAP_INFO:
			info->ci = (struct enum_tlv_cap_info *)tlv;
			break;
		default:
			pr_warn("not support tlv type[%u]\n", common->type);
		}

		if (common->len == 0) {
			pr_err("enum tlv len is invalid\n");
			return -EINVAL;
		}

		left_len -= (int)common->len;
		tlv += common->len;
	}

	info->port_nums = port_nums;

	return 0;
}

/* only check guid itself here, repetition problem is not considered */
bool ub_type_valid(struct ub_entity *uent, bool is_ctl)
{
	struct device *dev = &uent->ubc->dev;
	u16 code = uent_class(uent);
	u8 type = uent_type(uent);

	if (uent->ent_type == UB_ENT_UNKNOWN) {
		dev_err(dev, "ent type unknown, type=%#x, class=%#x\n",
			type, code);
		return false;
	}

	if (is_ctl && !is_ibus_controller(uent)) {
		dev_err(dev, "ubc bad type, type=%#x, class=%#x\n",
			type, code);
		return false;
	}

	if (!is_ctl && (is_ibus_controller(uent) || is_bus_controller(uent))) {
		dev_err(dev, "peripheral bad type, type=%#x, class=%#x\n",
			type, code);
		return false;
	}

	if (uent->pool && !(is_p_device(uent) || is_p_idevice(uent))) {
		dev_err(dev, "pool bad type, type=%#x, class=%#x\n",
			type, code);
		return false;
	}

	return true;
}

void ub_entity_type_init(struct ub_entity *uent)
{
	u8 base = uent_base_code(uent);

	switch (uent_type(uent)) {
	case UB_TYPE_CONTROLLER:
		if (base == UB_BASE_CODE_BUS_CONTROLLER) {
			if (uent->class_code == UB_CLASS_BUS_CONTROLLER)
				uent->ent_type = UB_ENT_BUS_CONTROLLER;
			else
				uent->ent_type = UB_ENT_UNKNOWN;
		} else {
			if (!uent->pool)
				uent->ent_type = UB_ENT_DEVICE;
			else
				uent->ent_type = UB_ENT_P_DEVICE;
		}
		break;
	case UB_TYPE_ICONTROLLER:
		if (base == UB_BASE_CODE_BUS_CONTROLLER) {
			uent->ent_type = UB_ENT_IBUS_CONTROLLER;
		} else {
			if (!uent->pool)
				uent->ent_type = UB_ENT_IDEVICE;
			else
				uent->ent_type = UB_ENT_P_IDEVICE;
		}
		break;
	case UB_TYPE_SWITCH:
	case UB_TYPE_ISWITCH:
		uent->ent_type = UB_ENT_SWITCH;
		break;
	default:
		uent->ent_type = UB_ENT_UNKNOWN;
	}
}

#define PORT_TOTAL_NUM_MAX 256

static int ub_enum_ent(struct ub_entity *uent, void *buf)
{
	struct device *dev = &uent->ubc->dev;
	struct enum_pld_scan_pdu_common *pc;
	int tlv_len, ret, total_num_ports;
	struct enum_tlv_info info = {};
	u8 total_slice, slice_id = 0;
	void *rsp, *tlv;

	do {
		rsp = (void *)ub_enum_topo_query_and_check(uent, buf, slice_id);
		if (!rsp) {
			ret = -EBUSY;
			goto err;
		}

		pc = (struct enum_pld_scan_pdu_common *)rsp;
		tlv_len = (int)pc->pdu_len * SZ_4 - ENUM_PLD_SCAN_PDU_COMMON_SIZE;
		tlv = rsp + ENUM_PLD_SCAN_PDU_COMMON_SIZE;

		ret = ub_enum_tlv_parse(tlv, tlv_len, &info);
		if (ret)
			goto err;

		if (slice_id == 0) {
			if (!info.si || !info.pi || !info.pn || !info.ci) {
				dev_err(dev, "tlv si/pi/pn/ci NULL\n");
				ret = -EFAULT;
				goto err;
			}

			uent->class_code = info.ci->class_code;
			ub_entity_type_init(uent);
			if (!ub_type_valid(uent, !uent->topo_rank)) {
				ret = -EINVAL;
				goto err;
			}

			total_slice = info.si->total_slice;
			total_num_ports = (int)info.pn->total_num_ports;
		}

		if (!uent->ports) {
			uent->port_nums = total_num_ports;
			if (uent->port_nums > PORT_TOTAL_NUM_MAX) {
				dev_err(dev, "Total num ports is over total num max(%d).\n",
					PORT_TOTAL_NUM_MAX);
				return -EINVAL;
			}

			ret = ub_ports_setup(uent);
			if (ret) {
				dev_err(dev, "enum port setup fail, ret=%d\n",
					ret);
				return ret;
			}
		}

		ub_enum_parse_port(uent, info.pi, info.port_nums);
		slice_id++;
	} while (slice_id < total_slice);

	return 0;
err:
	if (uent->ports)
		ub_ports_unset(uent);
	return ret;
}

static int ub_enum_na_query_rsp(void *buf, u32 *cna, u16 actual_rsp_size)
{
	struct enum_na_query_rsp *rsp;
	size_t header_sz;

	header_sz = ub_enum_calc_header_sz(buf, false);
	if (header_sz == 0) {
		pr_err("na query rsp header sz 0\n");
		return -EINVAL;
	}

	if (header_sz + ENUM_NA_QUERY_RSP_SIZE != actual_rsp_size) {
		pr_err("na query rsp pld sz invalid\n");
		return -EINVAL;
	}

	rsp = (struct enum_na_query_rsp *)(buf + header_sz);

	if (!rsp->common.bits.status)
		*cna = rsp->cna;

	return rsp->common.bits.status;
}

static size_t ub_enum_na_query_init(struct ub_entity *uent, void *buf, u8 opcode,
				    u16 port_idx)
{
	struct enum_na_query_req *req;
	size_t header_sz;

	memset(buf, 0, UB_TOPO_BUF_SZ);
	ub_enum_pkt_header_init(buf);
	ub_enum_pld_header_init(uent, buf);

	header_sz = ub_enum_calc_header_sz(buf, true);
	req = (struct enum_na_query_req *)(buf + header_sz);

	ub_enum_pld_common_setup(&req->common, ENUM_CMD_NA_QUERY,
				 opcode, &uent->guid.id,
				 ENUM_NA_QUERY_REQ_SIZE);

	if (opcode == ENUM_NA_QUERY_PORT)
		req->port_idx = port_idx;

	return header_sz + ENUM_NA_QUERY_REQ_SIZE;
}

int ub_query_port_na(struct ub_entity *uent, void *buf)
{
	struct device *dev = &uent->ubc->dev;
	struct msg_info info = {0};
	size_t req_pkt_sz;
	struct ub_port *p;
	int ret;
	u32 cna;

	for_each_uent_port(p, uent) {
		if (!p->domain_boundary)
			continue;

		req_pkt_sz = ub_enum_na_query_init(uent, buf,
						   ENUM_NA_QUERY_PORT,
						   p->index);

		message_info_init(&info, uent, buf, buf,
				  (req_pkt_sz << MSG_REQ_SIZE_OFFSET) |
				  UB_TOPO_BUF_SZ);

		ret = message_sync_enum(uent->ubc->mdev, &info,
					ENUM_CMD_NA_QUERY);
		if (ret)
			goto out;

		ret = ub_enum_na_query_rsp(buf, &cna, info.actual_rsp_size);
		if (ret) {
			dev_err(dev, "port na query rsp, status=%d\n", ret);
			ret = -EBUSY;
			goto out;
		}

		p->cna = cna;
		if (p->cna)
			dev_info(dev, "update boundary port%u cna to %#x\n",
				 p->index, p->cna);
	}

	return 0;
out:
	for_each_uent_port(p, uent)
		if (p->domain_boundary)
			p->cna = 0;

	dev_err(dev, "query fail and reset boundary port cna to 0.\n");

	return ret;
}

int ub_query_ent_na(struct ub_entity *uent, void *buf)
{
	struct device *dev = &uent->ubc->dev;
	struct msg_info info = {};
	size_t req_pkt_sz;
	int ret;
	u32 cna;

	req_pkt_sz = ub_enum_na_query_init(uent, buf, ENUM_NA_QUERY_DEVICE, 0);
	message_info_init(&info, uent, buf, buf,
			  (req_pkt_sz << MSG_REQ_SIZE_OFFSET) |
			  UB_TOPO_BUF_SZ);

	ret = message_sync_enum(uent->ubc->mdev, &info,
				ENUM_CMD_NA_QUERY);
	if (ret)
		return ret;

	ret = ub_enum_na_query_rsp(buf, &cna, info.actual_rsp_size);
	if (ret) {
		dev_err(dev, "dev na query rsp, status=%d\n", ret);
		return -EBUSY;
	}

	uent->cna = cna;
	if (uent->cna)
		dev_info(dev, "update cluster ubc cna to %#x\n", uent->cna);

	return 0;
}

static int ub_enum_cluster_query(struct ub_entity *uent, void *buf)
{
	int ret;

	ret = ub_query_ent_na(uent, buf);
	if (ret) {
		dev_err(&uent->ubc->dev, "query cluster ubc dev cna err\n");
		return ret;
	}

	ret = ub_query_port_na(uent, buf);
	if (ret)
		dev_err(&uent->ubc->dev, "query cluster ubc port cna err\n");

	return ret;
}

static int ub_enum_na_cfg_rsp(void *buf, u16 actual_rsp_size)
{
	struct enum_na_cfg_rsp *rsp;
	size_t header_sz;

	header_sz = ub_enum_calc_header_sz(buf, false);
	if (header_sz == 0) {
		pr_err("na cfg rsp header sz 0\n");
		return -EINVAL;
	}

	if (header_sz + ENUM_NA_CFG_RSP_SIZE != actual_rsp_size) {
		pr_err("na cfg rsp pld sz invalid\n");
		return -EINVAL;
	}

	rsp = (struct enum_na_cfg_rsp *)(buf + header_sz);

	return rsp->common.bits.status;
}

static size_t ub_enum_na_cfg_init(struct ub_entity *uent, void *buf, u32 cna,
				  u8 opcode, u16 port_idx)
{
	struct enum_na_cfg_req *req;
	size_t header_sz;

	ub_enum_refresh_and_init_buffer_header(uent, buf);

	header_sz = ub_enum_calc_header_sz(buf, true);
	req = (struct enum_na_cfg_req *)(buf + header_sz);

	ub_enum_pld_common_setup(&req->common, ENUM_CMD_NA_CFG, opcode,
				 &uent->guid.id, ENUM_NA_CFG_REQ_SIZE);

	req->cna = cna;
	if (opcode == ENUM_NA_CFG_PORT)
		req->port_idx = port_idx;

	return header_sz + ENUM_NA_CFG_REQ_SIZE;
}

/* Configuring the CNA of the ub entity Port */
static int ub_enum_port_na_cfg(struct ub_entity *uent, void *buf)
{
	struct message_device *mdev = uent->message->mdev;
	struct msg_info info = {};
	size_t req_pkt_sz;
	struct ub_port *p;
	int ret;

	for_each_uent_port(p, uent) {
		if (is_ibus_controller(uent) && p->domain_boundary)
			continue;

		req_pkt_sz = ub_enum_na_cfg_init(uent, buf, p->cna,
						 ENUM_NA_CFG_PORT, p->index);

		message_info_init(&info, uent, buf, buf,
				  (req_pkt_sz << MSG_REQ_SIZE_OFFSET) |
				  UB_TOPO_BUF_SZ);

		ret = message_sync_enum(mdev, &info, ENUM_CMD_NA_CFG);
		if (ret)
			return ret;

		ret = ub_enum_na_cfg_rsp(buf, info.actual_rsp_size);
		if (ret) {
			dev_err(&uent->ubc->dev, "port na cfg rsp, status=%d\n",
				ret);
			return -EBUSY;
		}
	}

	return 0;
}

static int ub_enum_na_cfg(struct ub_entity *uent, void *buf)
{
	struct message_device *mdev = uent->message->mdev;
	struct device *dev = &uent->ubc->dev;
	enum enum_na_cfg_opcode opcode;
	struct msg_info info = {};
	size_t req_pkt_sz;
	int ret;

	ret = ub_cna_alloc(uent);
	if (ret) {
		dev_err(dev, "cna alloc fail, ret=%d\n", ret);
		goto na_failed;
	}

	if (is_switch(uent)) /* Switch hasn't port cna register */
		goto cfg_dev;

	ret = ub_enum_port_na_cfg(uent, buf);
	if (ret) {
		dev_err(dev, "port na cfg fail, ret=%d\n", ret);
		goto na_failed;
	}

	if (is_ibus_controller(uent) && uent->ubc->cluster) {
		ret = ub_enum_cluster_query(uent, buf);
		if (ret)
			goto na_failed;
		return 0;
	}

cfg_dev:
	opcode = ENUM_NA_CFG_PRIMARY;
	req_pkt_sz = ub_enum_na_cfg_init(uent, buf, uent->cna, opcode, 0);

	message_info_init(&info, uent, buf, buf,
			  (req_pkt_sz << MSG_REQ_SIZE_OFFSET) | UB_TOPO_BUF_SZ);

	ret = message_sync_enum(mdev, &info, ENUM_CMD_NA_CFG);
	if (ret)
		goto na_failed;

	return 0;

na_failed:
	ub_cna_free(uent);
	return ret;
}


/*
 * Routing Algorithm: The BFS (Breadth First Search) algorithm
 * calculates the shortest forwarding path. The steps are as follows:
 * 1.	Obtain the "nodes" and forwarding device information in the host
 *	scenario, and construct an interconnected network in the single host
 *	scenario.
 * 2.	Starting from each node in the interconnected network, sequentially
 *	visit the adjacent nodes that are directly connected with one hop,
 *	without considering weight/cost.
 * 3.	Visit the adjacent nodes of the adjacent nodes, traversing layer by
 *	layer.
 * 4.	Continue until reaching the destination or there are no unvisited nodes
 *	left, constructing the forwarding path with the minimum number of hops.
 * 5.	When the weights/costs of the links are not the same, the BFS algorithm
 *	may calculate non-shortest paths.
 * 6.	Based on the above mechanism, the BFS algorithm does not allow cycles.
 */

struct bfs_port_path {
	struct ub_port *s_port; /* source port for set cna_map */
	struct ub_entity *uent; /* BFS current ub entity */
};

static struct bfs_route_info {
	DECLARE_KFIFO_PTR(kfifo, struct bfs_port_path);
	int *visited; /* 0: unvisited, 1: visited, 2: visiting */
	u32 cna_used;
	u32 *cna_map;
} bfs_route;

enum { BFS_UNVISITED, BFS_VISITED, BFS_VISITING };

/* Return: Whether to join the kfifo */
static int bfs_route_test_and_put(struct ub_port *p, struct ub_entity *uent)
{
	struct bfs_port_path path;

	if (!is_switch(uent) && !is_ibus_controller(uent))
		return 0;

	if (uent->port_nums == 1)
		return 0;

	path.s_port = p;
	path.uent = uent;

	if (!kfifo_put(&bfs_route.kfifo, path)) {
		pr_info("multiple paths join the kfifo, kfifo put failed\n");
		return 0;
	}

	return 1;
}

static int cna2index(int cna)
{
	int i;

	for (i = 0; i < bfs_route.cna_used; ++i) {
		if (bfs_route.cna_map[i] == cna)
			return i;
	}

	return 0;
}

static void ub_enum_bfs_layer_update(struct ub_entity *uent, int *curr, int *next,
				     int *layer)
{
	int i;

	*curr = *next;
	*next = 0;
	*layer += 1;

	for (i = 0; i < bfs_route.cna_used; ++i)
		if (bfs_route.visited[i] == BFS_VISITING)
			bfs_route.visited[i] = BFS_VISITED;
}

static void ub_enum_bfs_route_dev(struct ub_entity *ldev)
{
	struct ub_entity *uent, *rdev;
	struct ub_port *p, *rport, *s_port;
	struct bfs_port_path path = { NULL, ldev };
	int curr_layer_devs = 1, next_layer_devs = 0, layer = 0;

	bfs_route.visited[cna2index(ldev->cna)] = BFS_VISITED;
	kfifo_put(&bfs_route.kfifo, path);
	while (kfifo_get(&bfs_route.kfifo, &path)) {
		curr_layer_devs--;
		uent = path.uent;
		for_each_uent_port(p, uent) {
			if (!p->cna || !p->r_uent ||
			    bfs_route.visited[cna2index(p->r_uent->cna)] ==
				    BFS_VISITED ||
			    !ub_entity_test_priv_flag(p->r_uent, UB_ENTITY_DETACHED))
				continue;

			rdev = p->r_uent;
			rport = rdev->ports + p->r_index;
			s_port = path.s_port ? path.s_port : p;

			bfs_route.visited[cna2index(rdev->cna)] = BFS_VISITING;
			ub_route_add_entry(s_port, rdev->cna, layer + 1);
			if (!ONE_CNA(rdev))
				ub_route_add_entry(s_port, rport->cna, layer + 1);
			ub_entity_assign_priv_flag(ldev, UB_ENTITY_ROUTE_UPDATED, true);
			next_layer_devs += bfs_route_test_and_put(s_port, rdev);
		}

		if (curr_layer_devs == 0)
			ub_enum_bfs_layer_update(uent, &curr_layer_devs,
						 &next_layer_devs, &layer);
	}
}

static void ub_enum_bfs_route_core(struct list_head *dev_list)
{
	struct ub_entity *uent;

	list_for_each_entry(uent, dev_list, node) {
		if (uent->port_nums == 1)
			continue;

		memset(bfs_route.visited, 0, sizeof(int) * bfs_route.cna_used);

		ub_enum_bfs_route_dev(uent);
	}
}

static void ub_bfs_set_cna_map(struct list_head *dev_list)
{
	struct ub_port *port;
	struct ub_entity *uent;
	int i = 0;

	list_for_each_entry(uent, dev_list, node) {
		bfs_route.cna_map[i++] = uent->cna;
		if (ONE_CNA(uent))
			continue;
		for_each_uent_port(port, uent)
			bfs_route.cna_map[i++] = port->cna;
	}
}

int ub_enum_bfs_route_cal(struct list_head *dev_list)
{
	u16 max_port_num = 0;
	struct ub_entity *uent;
	int ret = -ENOMEM;

	if (kfifo_alloc(&bfs_route.kfifo, SZ_4K, GFP_KERNEL))
		goto kfifo_fail;

	bfs_route.cna_used = 0;
	list_for_each_entry(uent, dev_list, node) {
		if (max_port_num < uent->port_nums)
			max_port_num = uent->port_nums;
		bfs_route.cna_used += ONE_CNA(uent) ? 1 : uent->port_nums + 1;
	}

	bfs_route.cna_map = kcalloc(bfs_route.cna_used, sizeof(u32), GFP_KERNEL);
	if (!bfs_route.cna_map)
		goto map_fail;
	ub_bfs_set_cna_map(dev_list);

	bfs_route.visited = kcalloc(bfs_route.cna_used, sizeof(int), GFP_KERNEL);
	if (!bfs_route.visited)
		goto visited_fail;

	ub_enum_bfs_route_core(dev_list);
	ret = 0;

	kfree(bfs_route.visited);
visited_fail:
	kfree(bfs_route.cna_map);
map_fail:
	kfifo_free(&bfs_route.kfifo);
kfifo_fail:
	return ret;
}

int ub_cfg_read_guid(struct ub_entity *uent, u32 *dw)
{
	u32 val[UB_GUID_DW_NUM];
	int i, ret;

	for (i = 0; i < UB_GUID_DW_NUM; i++) {
		ret = ub_cfg_read_dword(uent, UB_GUID + i * sizeof(u32), &val[i]);
		if (ret)
			return ret;
	}

	for (i = 0; i < UB_GUID_DW_NUM; i++)
		*(dw + i) = val[i];

	return 0;
}

static void ub_enum_destroy_entity(struct ub_entity *uent)
{
	message_remove_device(uent);

	if (is_primary(uent))
		ub_ubc_put(uent->ubc);

	kfree(uent);
}

static struct ub_entity *ub_enum_create_uent(struct ub_bus_controller *ubc)
{
	struct ub_entity *uent;
	int ret;

	uent = ub_alloc_ent();
	if (!uent)
		return NULL;

	uent->pue = uent;
	uent->entity_idx = 0;
	uent->is_mue = 1;
	uent->ubc = ub_ubc_get(ubc);
	uent->upi = UB_CP_UPI;
	ret = message_probe_device(uent);
	if (ret) {
		dev_err(&ubc->dev, "enum msg probe dev failed, ret=%d\n", ret);
		goto err_out;
	}

	return uent;
err_out:
	ub_ubc_put(ubc);
	kfree(uent);
	return NULL;
}

static struct ub_entity *ub_enum_create_bus_controller(struct ub_bus_controller *ubc)
{
	struct ub_entity *uent;
	int ret;

	uent = ub_enum_create_uent(ubc);
	if (!uent)
		return (struct ub_entity *)ERR_PTR(-ENOMEM);

	ubc->uent = uent;
	ret = ub_cfg_read_guid(uent, uent->guid.dw);
	if (ret) {
		dev_err(&ubc->dev, "read guid failed, ret=%d\n", ret);
		goto err_out;
	}

	uent->topo_rank = 0;
	uent->dev.parent = &ubc->dev;

	return uent;
err_out:
	ub_enum_destroy_entity(uent);
	return (struct ub_entity *)ERR_PTR(ret);
}

static void ub_enum_topo_ent_uninit(struct ub_entity *uent)
{
	if (is_primary(uent)) {
		ub_route_clear(uent); /* alloc in route_config */
		ub_cna_free(uent); /* alloc in na_cfg */
		ub_ports_unset(uent); /* alloc in scan_device */
	}
}

static int ub_enum_ports(struct ub_entity *uent, u16 start_port, u16 num,
			 void *buf)
{
	u16 left = num, start = start_port, count;
	struct enum_pld_scan_pdu_common *pc;
	struct enum_tlv_info info = {};
	u8 total_slice, slice_id = 0;
	int tlv_len, ret, nums = 0;
	void *rsp, *tlv;

	do {
		rsp = (void *)ub_enum_topo_query_and_check(uent, buf, slice_id);
		if (!rsp)
			return -EBUSY;

		pc = rsp;
		tlv_len = (int)pc->pdu_len * SZ_4 - ENUM_PLD_SCAN_PDU_COMMON_SIZE;
		tlv = rsp + ENUM_PLD_SCAN_PDU_COMMON_SIZE;

		ret = ub_enum_tlv_parse(tlv, tlv_len, &info);
		if (ret)
			return ret;

		if (slice_id == 0) {
			if (!info.si || !info.pi || !info.pn || !info.ci) {
				dev_err(&uent->ubc->dev, "port tlv si/pi/pn/ci null\n");
				return -EINVAL;
			}

			total_slice = info.si->total_slice;
		}

		if (start >= nums + info.port_nums)
			goto next;

		info.pi += start - nums;
		count = min(left, nums + info.port_nums - start);
		ub_enum_parse_port(uent, info.pi, count);
		start += count;
		left -= count;

		if (left == 0)
			break;
next:
		nums += info.port_nums;
		slice_id++;
	} while (slice_id < total_slice);

	return 0;
}

static int ub_enum_and_configure_ent(struct ub_entity *uent, void *buf)
{
	int ret;

	ret = ub_enum_ent(uent, buf);
	if (ret)
		return ret;

	ret = ub_enum_na_cfg(uent, buf);
	if (ret)
		ub_ports_unset(uent);

	return ret;
}

void ub_enum_clear_ent_list(struct list_head *dev_list)
{
	struct ub_entity *uent, *tmp;
	struct ub_port *port;

	list_for_each_entry_safe_reverse(uent, tmp, dev_list, node) {
		list_del(&uent->node);
		for_each_uent_port(port, uent)
			ub_port_disconnect(port);

		ub_cna_free(uent);
		ub_ports_unset(uent);
		ub_enum_destroy_entity(uent);
	}
}

static int ub_enum_bus_controllers(struct list_head *dev_list)
{
	struct ub_bus_controller *ubc;
	struct ub_entity *uent;
	int ret;

	list_for_each_entry(ubc, &ubc_list, node) {
		uent = ub_enum_create_bus_controller(ubc);
		if (IS_ERR(uent)) {
			ret = PTR_ERR(uent);
			dev_err(&ubc->dev, "create controller failed, ret=%d\n",
				ret);
			goto clear_list;
		}

		ret = ub_enum_and_configure_ent(uent, topo_scan.buf);
		if (ret) {
			dev_err(&ubc->dev, "enum controller failed, ret=%d\n",
				ret);
			ub_enum_destroy_entity(uent);
			goto clear_list;
		}

		list_add_tail(&uent->node, dev_list);
	}

	return 0;
clear_list:
	ub_enum_clear_ent_list(dev_list);
	return ret;
}

static struct ub_entity *ub_enum_get_ent(guid_t *guid, struct list_head *dev_list)
{
	struct ub_entity *uent;

	list_for_each_entry(uent, dev_list, node)
		if (guid_equal(guid, &uent->guid.id))
			return uent;

	return NULL;
}

static bool ub_enum_port_recognise_check(struct ub_entity *root,
					 struct ub_port *port)
{
	struct ub_port *tmp;

	if (guid_equal(&port->r_guid, &root->guid.id)) {
		tmp = root->ports + port->r_index;
		if (guid_is_null(&tmp->r_guid)) {
			port->r_index = 0;
			guid_copy(&port->r_guid, &guid_null);
			return true;
		}
	}

	return false;
}

static bool port_need_scan(struct ub_entity *root, struct ub_port *port)
{
	if (port->r_uent)
		return false;

	if (guid_is_null(&port->r_guid))
		return false;

	if (root && ub_enum_port_recognise_check(root, port))
		return false;

	return true;
}

static struct ub_entity *ub_enum_create_entity(guid_t *guid, struct ub_entity *parent)
{
	struct ub_entity *uent;

	if (parent->topo_rank + 1 > ENUM_MAX_HOPS) {
		dev_err(&parent->ubc->dev, "ub support max hops: %d\n",
			ENUM_MAX_HOPS);
		return (struct ub_entity *)ERR_PTR(-EINVAL);
	}

	uent = ub_enum_create_uent(parent->ubc);
	if (!uent)
		return (struct ub_entity *)ERR_PTR(-ENOMEM);

	guid_copy(&uent->guid.id, guid);

	uent->topo_rank = parent->topo_rank + 1;
	uent->dev.parent = &parent->dev;

	return uent;
}

static int ub_enum_do_topo_scan(struct ub_entity *root, struct list_head *dev_list,
				void *buf)
{
#define UB_TOPO_KFIFO_DEPTH SZ_128
	DECLARE_KFIFO(kfifo, struct ub_entity *, UB_TOPO_KFIFO_DEPTH);
	struct ub_entity *uent, *r_uent;
	struct ub_port *port;
	struct device *dev;
	int ret = 0;

	INIT_KFIFO(kfifo);

	if (root)
		kfifo_put(&kfifo, root);

	list_for_each_entry(uent, dev_list, node)
		kfifo_put(&kfifo, uent);

	while (kfifo_get(&kfifo, &uent)) {
		dev = &uent->ubc->dev;

		for_each_uent_port(port, uent) {
			if (!port_need_scan(root, port))
				continue;

			r_uent = ub_enum_get_ent(&port->r_guid, dev_list);
			if (r_uent)
				goto connect_port;

			if (is_device(uent)) {
				ret = -EINVAL;
				dev_err(dev, "device connect to multi peer\n");
				goto clear_list;
			}

			r_uent = ub_enum_create_entity(&port->r_guid, uent);
			if (IS_ERR(r_uent)) {
				ret = PTR_ERR(r_uent);
				dev_err(dev, "enum create device failed, ret=%d\n",
					ret);
				goto clear_list;
			}

			/* set here to help enum find path */
			port->r_uent = r_uent;
			ret = ub_enum_and_configure_ent(r_uent, buf);
			if (ret) {
				dev_err(dev, "enum device failed, ret=%d\n",
					ret);
				ub_enum_destroy_entity(r_uent);
				goto clear_port;
			}

			list_add_tail(&r_uent->node, dev_list);
			if (!kfifo_put(&kfifo, r_uent))
				dev_err(dev, "do topo scan kfifo put full\n");

connect_port:
			if (!ub_check_and_connect(port, r_uent)) {
				dev_err(dev, "port%u wrong topo\n", port->index);
				ret = -EINVAL;
				goto clear_port;
			}
		}
	}

	return 0;
clear_port:
	port->r_uent = NULL;
clear_list:
	ub_enum_clear_ent_list(dev_list);
	return ret;
}

int ub_enum_topo_scan_ports(struct ub_entity *uent, u16 start_port, u16 num,
			    struct list_head *dev_list, void *buf)
{
	int ret;

	if (!uent || !dev_list || !buf)
		return -EINVAL;

	ret = ub_enum_ports(uent, start_port, num, buf);
	if (ret)
		return ret;

	return ub_enum_do_topo_scan(uent, dev_list, buf);
}

struct ub_entity *ub_enum_get_port_r_uent(struct ub_port *port, void *buf)
{
	struct ub_bus_controller *ubc;
	int ret;

	if (!port || !buf)
		return NULL;

	ret = ub_enum_ports(port->uent, port->index, 1, buf);
	if (ret)
		return NULL;

	ubc = port->uent->ubc;
	return ub_enum_get_ent(&port->r_guid, &ubc->devs);
}

/*
 * During topo scan, just alloc ub_entity, alloc ub_port, alloc cna,
 * so, when topo scan failed, just go to free devs in topo_scan.uents
 */
static int ub_enum_topo_scan(struct list_head *dev_list)
{
	int ret;

	ret = ub_enum_topo_scan_init();
	if (ret) {
		pr_err("enum topo scan init failed, ret=%d\n", ret);
		return ret;
	}

	ret = ub_enum_bus_controllers(dev_list);
	if (ret) {
		pr_err("enum create controllers failed, ret=%d\n", ret);
		goto out;
	}

	if (list_empty(dev_list)) {
		pr_warn("No ub bus controller exists in the current environment.\n");
		ret = -ENODEV;
		goto out;
	}

	ret = ub_enum_do_topo_scan(NULL, dev_list, topo_scan.buf);
	if (ret)
		pr_err("enum scan devices failed, ret=%d\n", ret);

out:
	ub_enum_topo_scan_uninit();
	return ret;
}

static void ub_enum_free_all(void)
{
	struct ub_entity *uent, *tmp;

	list_for_each_entry_safe_reverse(uent, tmp, &topo_scan.dev_list, node) {
		list_del(&uent->node);
		ub_enum_topo_ent_uninit(uent);
		ub_enum_destroy_entity(uent);
	}

	ub_stop_entities();
	ub_remove_entities();
}

int ub_enum_entities_active(struct list_head *dev_list, int src)
{
	struct ub_entity *uent, *tmp;
	int ret;

	list_for_each_entry_safe(uent, tmp, dev_list, node) {
		if (uent->entity_idx != 0)
			continue;

		ub_route_sync_dev(uent);
		ret = ub_setup_ent(uent);
		if (ret) {
			pr_err("setup dev err, ret=%d\n", ret);
			return ret;
		}

		list_del(&uent->node);
		ub_entity_add(uent, uent->ubc);
		ub_entity_assign_task_src(uent, src, true);

		if (is_ibus_controller(uent) && uent->ubc->cluster)
			continue;

		if (ub_entity_test_task_src(uent, TASK_SRC_SELF)) {
			ub_start_ent(uent);
		} else {
			ret = ub_add_delay_task(uent, NULL, TASK_TYPE_START);
			if (ret) {
				ub_err(uent, "active add start task failed\n");
				return ret; /* Just one entity */
			}
		}
	}

	return 0;
}

int ub_enum_probe(void)
{
	int ret;

	ret = ub_enum_topo_scan(&topo_scan.dev_list);
	if (ret == -ENODEV) {
		return 0;
	} else if (ret) {
		pr_err("topo_scan failed, ret=%d\n", ret);
		return ret;
	}

	ret = ub_enum_bfs_route_cal(&topo_scan.dev_list);
	if (ret) {
		pr_err("route cal failed, ret=%d\n", ret);
		goto err_out;
	}

	ret = ub_enum_entities_active(&topo_scan.dev_list, TASK_SRC_SELF);
	if (ret) {
		pr_err("devices start failed, ret=%d\n", ret);
		goto err_out;
	}

	return 0;
err_out:
	ub_enum_free_all();
	return ret;
}

void ub_enum_remove(void)
{
	ub_stop_entities();
	ub_remove_entities();
}
