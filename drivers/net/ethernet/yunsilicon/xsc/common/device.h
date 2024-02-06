/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_DEVICE_H
#define XSC_DEVICE_H

#include <linux/types.h>
#include <rdma/ib_verbs.h>

enum {
	XSC_MAX_COMMANDS		= 32,
	XSC_CMD_DATA_BLOCK_SIZE	= 512,
	XSC_PCI_CMD_XPORT		= 7,
};

enum {
	XSC_PERM_LOCAL_READ	= 1 << 0,
	XSC_PERM_LOCAL_WRITE	= 1 << 1,
	XSC_PERM_REMOTE_READ	= 1 << 2,
	XSC_PERM_REMOTE_WRITE	= 1 << 3,
	XSC_PERM_ATOMIC	= 1 << 6,
	XSC_PERM_UMR_EN	= 1 << 7,
};

enum {
	XSC_ACCESS_MODE_PA	= 0,
	XSC_ACCESS_MODE_MTT	= 1,
	XSC_ACCESS_MODE_KLM	= 2
};

enum {
	XSC_MKEY_REMOTE_INVAL	= 1 << 24,
	XSC_MKEY_FLAG_SYNC_UMR = 1 << 29,
	XSC_MKEY_BSF_EN	= 1 << 30,
	XSC_MKEY_LEN64		= 1 << 31,
};

enum {
	XSC_BF_REGS_PER_PAGE	= 4,
	XSC_MAX_UAR_PAGES	= 1 << 8,
	XSC_MAX_UUARS		= XSC_MAX_UAR_PAGES * XSC_BF_REGS_PER_PAGE,
};

enum {
	XSC_DEV_CAP_FLAG_RC		= 1LL <<  0,
	XSC_DEV_CAP_FLAG_UC		= 1LL <<  1,
	XSC_DEV_CAP_FLAG_UD		= 1LL <<  2,
	XSC_DEV_CAP_FLAG_XRC		= 1LL <<  3,
	XSC_DEV_CAP_FLAG_SRQ		= 1LL <<  6,
	XSC_DEV_CAP_FLAG_BAD_PKEY_CNTR	= 1LL <<  8,
	XSC_DEV_CAP_FLAG_BAD_QKEY_CNTR	= 1LL <<  9,
	XSC_DEV_CAP_FLAG_APM		= 1LL << 17,
	XSC_DEV_CAP_FLAG_ATOMIC	= 1LL << 18,
	XSC_DEV_CAP_FLAG_ON_DMND_PG	= 1LL << 24,
	XSC_DEV_CAP_FLAG_RESIZE_SRQ	= 1LL << 32,
	XSC_DEV_CAP_FLAG_REMOTE_FENCE	= 1LL << 38,
	XSC_DEV_CAP_FLAG_TLP_HINTS	= 1LL << 39,
	XSC_DEV_CAP_FLAG_SIG_HAND_OVER	= 1LL << 40,
	XSC_DEV_CAP_FLAG_DCT		= 1LL << 41,
	XSC_DEV_CAP_FLAG_CMDIF_CSUM	= 1LL << 46,
};

enum xsc_event {
	XSC_EVENT_TYPE_COMP               = 0x0,
	XSC_EVENT_TYPE_COMM_EST           = 0x02,//mad
	XSC_EVENT_TYPE_CQ_ERROR           = 0x04,
	XSC_EVENT_TYPE_WQ_CATAS_ERROR     = 0x05,
	XSC_EVENT_TYPE_INTERNAL_ERROR     = 0x08,//tpe私有err，无IB event对应
	XSC_EVENT_TYPE_WQ_INVAL_REQ_ERROR = 0x10,//IBV_EVENT_QP_REQ_ERR
	XSC_EVENT_TYPE_WQ_ACCESS_ERROR    = 0x11,//IBV_EVENT_QP_ACCESS_ERR
};

struct xsc_cmd_prot_block {
	u8		data[XSC_CMD_DATA_BLOCK_SIZE];
	u8		rsvd0[48];
	__be64		next;
	__be32		block_num;
	u8		owner_status; //init to 0, dma user should change this val to 1
	u8		token;
	u8		ctrl_sig;
	u8		sig;
};

#define XSC_ATTR_EXTENDED_PORT_INFO	cpu_to_be16(0xff90)

enum xsc_traffic_types {
	XSC_TT_IPV4,
	XSC_TT_IPV4_TCP,
	XSC_TT_IPV4_UDP,
	XSC_TT_IPV6,
	XSC_TT_IPV6_TCP,
	XSC_TT_IPV6_UDP,
	XSC_TT_IPV4_IPSEC_AH,
	XSC_TT_IPV6_IPSEC_AH,
	XSC_TT_IPV4_IPSEC_ESP,
	XSC_TT_IPV6_IPSEC_ESP,
	XSC_TT_ANY,
	XSC_NUM_TT,
};

#define XSC_NUM_INDIR_TIRS XSC_NUM_TT

enum {
	XSC_HASH_FUNC_XOR		= 0,
	XSC_HASH_FUNC_TOP		= 1,
	XSC_HASH_FUNC_TOP_SYM	= 2,
	XSC_HASH_FUNC_RSV		= 3,
};

enum {
	XSC_L3_PROT_TYPE_IPV4	= 1 << 0,
	XSC_L3_PROT_TYPE_IPV6	= 1 << 1,
};

enum {
	XSC_L4_PROT_TYPE_TCP	= 1 << 0,
	XSC_L4_PROT_TYPE_UDP	= 1 << 1,
};

struct xsc_tirc_config {
	u8 l3_prot_type;
	u8 l4_prot_type;
	u32 rx_hash_fields;
};

static inline u8 hash_func_type(u8 hash_func)
{
	switch (hash_func) {
	case ETH_RSS_HASH_TOP:
		return XSC_HASH_FUNC_TOP;
	case ETH_RSS_HASH_XOR:
		return XSC_HASH_FUNC_XOR;
	default:
		return XSC_HASH_FUNC_TOP;
	}
}

#endif /* XSC_DEVICE_H */
