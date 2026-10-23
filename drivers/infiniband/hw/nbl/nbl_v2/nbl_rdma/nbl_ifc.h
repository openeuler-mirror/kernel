/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef NBL_IFC_H
#define NBL_IFC_H

enum nbldv_cmd_op {
	NBL_CMD_OP_CREATE_CQ,
	NBL_CMD_OP_DESTROY_CQ,
	NBL_CMD_OP_CREATE_QP,
	NBL_CMD_OP_DESTROY_QP,
	NBL_CMD_OP_RST2INIT_QP,
	NBL_CMD_OP_INIT2RTR_QP,
	NBL_CMD_OP_RTR2RTS_QP,
};

struct nbl_ifc_general_obj_in_cmd_hdr_bits {
	u8 opcode[0x10];
	u8 reserved_at_8[0x10];

	u8 reserved[0x20];
};

struct nbl_ifc_general_obj_out_cmd_hdr_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];

	u8 reserved[0x20];
};

struct nbl_ifc_create_cq_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_8[0x10];

	u8 reserved_at_20[0x1];
	u8 cc[0x1];
	u8 cq_umem_valid[0x1];
	u8 log_cq_size[0x5];
	u8 umem_id[0x18];

	u8 umem_offset[0x20];

	u8 reserved_at_60[0x14];
	u8 eqn[0xc];
};

struct nbl_ifc_create_cq_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];

	u8 reserved_at_20[0x8];
	u8 cqn[0x18];

	u8 cqc_size[0x10]; /* 512bits(64bytes)*/
	u8 shadow_size[0x10]; /* size of shadow area, 8bytes */

	u8 shadow_offset[0x20]; /* offset from page start */

	u8 shadow_base_addr_h[0x20]; /* use as mmap para */
	u8 shadow_base_addr_l[0x20]; /* use as mmap para */

	u8 page_size[0x20]; /* 4096(4K) or 2097152(2M), from HMC */

	u8 reserved_at_100[0x20];
	u8 shad_cba[0x40];
};

struct nbl_ifc_create_qp_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];

	u8 reserved_at_20[0x5];
	u8 sq_umem_valid[0x1];
	u8 rq_umem_valid[0x1];
	u8 use_srq[0x1];
	u8 srqn[0x18];

	u8 reserved_at_40[0x8];
	u8 pdn[0x18];

	u8 reserved_at_60[0x8];
	u8 cqn_snd[0x18];

	u8 reserved_at_80[0x3];
	u8 max_recv_sge[0x5];
	u8 cqn_rcv[0x18];

	u8 reserved_at_a0[0x3];
	u8 log_sq_size[0x5];
	u8 sq_umem_id[0x18];

	u8 sq_umem_offset[0x20];

	u8 reserved_at_e0[0x3];
	u8 log_rq_size[0x5];
	u8 rq_umem_id[0x18];

	u8 rq_umem_offset[0x20];
};

struct nbl_ifc_create_qp_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];

	u8 reserved_at_20[0x8];
	u8 qpn[0x18];

	u8 qpc_size[0x10]; /* 512bytes */
	u8 shadow_size[0x10]; /* size of shadow area, 8bytes */

	u8 shadow_offset[0x20]; /* offset from page start */

	u8 shadow_base_addr_h[0x20]; /* use as mmap para */
	u8 shadow_base_addr_l[0x20]; /* use as mmap para */

	u8 page_size[0x20]; /* 4096(4K) or 2097152(2M), from HMC */

	u8 qp_caps[0x20]; /* use post_send pre-check */

	u8 seq_num[0x20]; /*use post_send db check*/

	u8 reserved_at_120[0xf];
	u8 dport_id[0xa];
	u8 dport[0x3];
	u8 fwd[0x2];
	u8 rss_lag_en[0x1];
	u8 tunnel_en[0x1];

	u8 reserved_at_140[0x18];
	u8 rqe_mult[0x8];

	u8 max_recv_wr[0x20];

	u8 max_send_wr[0x20];

	u8 reserved_at_1a0[0x20];
	u8 shad_cba[0x40];
};

struct nbl_ifc_rst2init_qp_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];

	u8 reserved_at_20[0x5];
	u8 qpn[0x18];
	u8 rwe[0x1];
	u8 rre[0x1];
	u8 rae[0x1];
};

struct nbl_ifc_rst2init_qp_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];

	u8 reserved_at_20[0x20];
};

struct nbl_ifc_init2rtr_qp_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];

	u8 reserved_at_20[0x8];
	u8 qpn[0x18];

	u8 patch_mtu[0x8]; /* ib mtu */
	u8 dst_qp_num[0x18];

	u8 rq_psn[0x20];

	u8 reserved_at_80[0xb];
	u8 min_rnr_timer[0x5];
	u8 max_dest_rd_atomic[0x10];

	/* ah related info */
	u8 dst_ip[16][0x8];

	u8 udp_sport[0x10];
	u8 dst_mac_47_32[0x10];

	u8 dst_mac_31_0[0x20];

	u8 sgid_index[0x10];
	u8 hop_limit[0x8];
	u8 tclass[0x8];
};

struct nbl_ifc_init2rtr_qp_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];

	u8 reserved_at_20[0x20];
};

struct nbl_ifc_rtr2rts_qp_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];

	u8 reserved_at_20[0x8];
	u8 qpn[0x18];

	u8 reserved_at_40[0x18];
	u8 timeout[0x8];

	u8 sq_psn[0x20];

	u8 max_rd_atomic[0x10];
	u8 rnr_retry[0x8];
	u8 retry_cnt[0x8];
};

struct nbl_ifc_rtr2rts_qp_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];

	u8 reserved_at_20[0x20];
};

#endif /* NBL_IFC_H */
