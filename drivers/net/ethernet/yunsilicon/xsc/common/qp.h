/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_QP_H
#define XSC_QP_H

#include "common/xsc_hsi.h"
#include "common/device.h"
#include "common/driver.h"

enum {
	XSC_QP_PM_MIGRATED		= 0x3,
	XSC_QP_PM_ARMED			= 0x0,
	XSC_QP_PM_REARM			= 0x1
};

enum {
	XSC_WQE_CTRL_CQ_UPDATE		= 2 << 2,
	XSC_WQE_CTRL_SOLICITED		= 1 << 1,
};

struct xsc_send_wqe_ctrl_seg {
	__le32		msg_opcode:8;
	__le32		with_immdt:1;
	__le32		csum_en:2;
	__le32		ds_data_num:5;
	__le32		wqe_id:16;
	__le32		msg_len;
	union {
		__le32		opcode_data;
		struct {
			u8		has_pph:1;
			u8		so_type:1;
			__le16		so_data_size:14;
			u8:8;
			u8		so_hdr_len:8;
		};
		struct {
			__le16		desc_id;
			__le16		is_last_wqe:1;
			__le16		dst_qp_id:15;
		};
	};
	__le32		se:1;
	__le32		ce:1;
	__le32:30;
};

struct xsc_wqe_data_seg {
	union {
		__le32		in_line:1;
		struct {
			__le32:1;
			__le32		seg_len:31;
			__le32		mkey;
			__le64		va;
		};
		struct {
			__le32:1;
			__le32		len:7;
			u8		in_line_data[15];
		};
	};
};

struct xsc_wqe_ctrl_seg_2 {
	__be32			opmod_idx_opcode;
	__be32			qpn_ds;
	u8			signature;
	u8			rsvd[2];
	u8			fm_ce_se;
	__be32			imm;
};

struct xsc_av {
	union {
		struct {
			__be32	qkey;
			__be32	reserved;
		} qkey;
		__be64	dc_key;
	} key;
	__be32	dqp_dct;
	u8	stat_rate_sl;
	u8	fl_mlid;
	union {
		__be16	rlid;
		__be16  udp_sport;
	};
	u8	reserved0[4];
	u8	rmac[6];
	u8	tclass;
	u8	hop_limit;
	__be32	grh_gid_fl;
	u8	rgid[16];
};

struct xsc_wqe_data_seg_2 {
	__be32			byte_count;
	__be32			lkey;
	__be64			addr;
};

struct xsc_core_qp {
	void (*event)(struct xsc_core_qp *qp, int type);
	int			qpn;
	atomic_t		refcount;
	struct completion	free;
	struct xsc_rsc_debug	*dbg;
	int			pid;
	u16		qp_type;
	u16		eth_queue_type;
	struct dentry           *trace;
	struct xsc_qp_trace	*trace_info;
	u16	qp_type_internal;
	u16	grp_id;
};

struct xsc_qp_rsc {
	struct list_head	node;
	u32 qpn;
	struct completion	delayed_release;
	struct xsc_core_device	*xdev;
};

struct xsc_qp_path {
	u8			fl;
	u8			rsvd3;
	u8			free_ar;
	u8			pkey_index;
	u8			rsvd0;
	u8			grh_mlid;
	__be16			rlid;
	u8			ackto_lt;
	u8			mgid_index;
	u8			static_rate;
	u8			hop_limit;
	__be32			tclass_flowlabel;
	u8			rgid[16];
	u8			rsvd1[4];
	u8			sl;
	u8			port;
	u8			rsvd2[6];
	u8			dmac[6];
	u8			smac[6];
	__be16		af_type;
	__be32		sip[4];
	__be32		dip[4];
	__be16			sport;
	u8			ecn_dscp;
	u8			vlan_valid;
	__be16			vlan_id;
	u8			dci_cfi_prio_sl; //not left moved yet.
};

static inline struct xsc_core_qp *__xsc_qp_lookup(struct xsc_core_device *xdev, u32 qpn)
{
	return radix_tree_lookup(&xdev->dev_res->qp_table.tree, qpn);
}

int create_resource_common(struct xsc_core_device *xdev,
			   struct xsc_core_qp *qp);
void destroy_resource_common(struct xsc_core_device *xdev,
			     struct xsc_core_qp *qp);

int xsc_core_create_qp(struct xsc_core_device *xdev,
		       struct xsc_core_qp *qp,
		       struct xsc_create_qp_mbox_in *in,
		       int inlen);
int xsc_core_qp_modify(struct xsc_core_device *xdev, enum xsc_qp_state cur_state,
		       enum xsc_qp_state new_state,
		       struct xsc_modify_qp_mbox_in *in, int sqd_event,
		       struct xsc_core_qp *qp);
int xsc_core_destroy_qp(struct xsc_core_device *xdev,
			struct xsc_core_qp *qp);
int xsc_core_qp_query(struct xsc_core_device *xdev, struct xsc_core_qp *qp,
		      struct xsc_query_qp_mbox_out *out, int outlen);

void xsc_init_qp_table(struct xsc_core_device *xdev);
void xsc_cleanup_qp_table(struct xsc_core_device *xdev);
int xsc_debug_qp_add(struct xsc_core_device *xdev, struct xsc_core_qp *qp);
void xsc_debug_qp_remove(struct xsc_core_device *xdev, struct xsc_core_qp *qp);

int xsc_create_qptrace(struct xsc_core_device *xdev, struct xsc_core_qp *qp);
void xsc_remove_qptrace(struct xsc_core_device *xdev, struct xsc_core_qp *qp);

void xsc_init_delayed_release(void);
void xsc_stop_delayed_release(void);

int xsc_modify_qp(struct xsc_core_device *xdev,
		  struct xsc_modify_qp_mbox_in *in,
		  struct xsc_modify_qp_mbox_out *out,
		  u32 qpn, u16 status);


#endif /* XSC_QP_H */
