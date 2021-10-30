/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_PARENT_CONTEXT_H
#define SPFC_PARENT_CONTEXT_H

enum fc_parent_status {
	FC_PARENT_STATUS_INVALID = 0,
	FC_PARENT_STATUS_NORMAL,
	FC_PARENT_STATUS_CLOSING
};

#define SPFC_PARENT_CONTEXT_KEY_ALIGN_SIZE (48)

#define SPFC_PARENT_CONTEXT_TIMER_SIZE (32) /* 24+2*N,N=timer count */

#define FC_CALC_CID(_xid)                                                   \
	(((((_xid) >> 5) & 0x1ff) << 11) | ((((_xid) >> 5) & 0x1ff) << 2) | \
	 (((_xid) >> 3) & 0x3))

#define MAX_PKT_SIZE_PER_DISPATCH (fc_child_ctx_ex->per_xmit_data_size)

/* immediate data DIF info definition in parent context */
struct immi_dif_info {
	union {
		u32 value;
		struct {
			u32 app_tag_ctrl : 3; /* DIF/DIX APP TAG Control */
			u32 ref_tag_mode : 2; /* Bit 0: scenario of the reference tag verify mode */
			/* Bit 1: scenario of the reference tag insert/replace
			 * mode  0: fixed; 1: increasement;
			 */
			u32 ref_tag_ctrl : 3; /* The DIF/DIX Reference tag control */
			u32 grd_agm_ini_ctrl : 3;
			u32 grd_agm_ctrl : 2; /* Bit 0: DIF/DIX guard verify algorithm control */
			/* Bit 1: DIF/DIX guard replace or insert algorithm control */
			u32 grd_ctrl : 3;	 /* The DIF/DIX Guard control */
			u32 dif_verify_type : 2; /* verify type */
			/* Check blocks whose reference tag contains 0xFFFF flag */
			u32 difx_ref_esc : 1;
			/* Check blocks whose application tag contains 0xFFFF flag */
			u32 difx_app_esc : 1;
			u32 rsvd : 8;
			u32 sct_size : 1; /* Sector size, 1: 4K; 0: 512 */
			u32 smd_tp : 2;
			u32 difx_en : 1;
		} info;
	} dif_dw3;

	u32 cmp_app_tag : 16;
	u32 rep_app_tag : 16;
	/* The ref tag value for verify compare, do not support replace or insert ref tag */
	u32 cmp_ref_tag;
	u32 rep_ref_tag;

	u32 rsv1 : 16;
	u32 cmp_app_tag_msk : 16;
};

/* parent context SW section definition: SW(80B) */
struct spfc_sw_section {
	u16 scq_num_rcv_cmd;
	u16 scq_num_max_scqn;

	struct {
		u32 xid : 13;
		u32 vport : 7;
		u32 csctrl : 8;
		u32 rsvd0 : 4;
	} sw_ctxt_vport_xid;

	u32 scq_num_scqn_mask : 12;
	u32 cid : 20; /* ucode init */

	u16 conn_id;
	u16 immi_rq_page_size;

	u16 immi_taskid_min;
	u16 immi_taskid_max;

	union {
		u32 pctxt_val0;
		struct {
			u32 srv_type : 5;    /* driver init */
			u32 srr_support : 2; /* sequence retransmition support flag */
			u32 rsvd1 : 5;
			u32 port_id : 4;  /* driver init */
			u32 vlan_id : 16; /* driver init */
		} dw;
	} sw_ctxt_misc;

	u32 rsvd2;
	u32 per_xmit_data_size;

	/* RW fields */
	u32 cmd_scq_gpa_h;
	u32 cmd_scq_gpa_l;
	u32 e_d_tov_timer_val; /* E_D_TOV timer value: value should be set on ms by driver */
	u16 mfs_unaligned_bytes; /* mfs unalined bytes of per 64KB dispatch*/
	u16 tx_mfs;		 /* remote port max receive fc payload length */
	u32 xfer_rdy_dis_max_len_remote; /* max data len allowed in xfer_rdy dis scenario */
	u32 xfer_rdy_dis_max_len_local;

	union {
		struct {
			u32 priority : 3; /* vlan priority */
			u32 rsvd4 : 2;
			u32 status : 8;	      /* status of flow */
			u32 cos : 3;	      /* doorbell cos value */
			u32 oq_cos_data : 3;  /* esch oq cos for data */
			u32 oq_cos_cmd : 3;   /* esch oq cos for cmd/xferrdy/rsp */
			/* used for parent context cache Consistency judgment,1: done */
			u32 flush_done : 1;
			u32 work_mode : 2;    /* 0:Target, 1:Initiator, 2:Target&Initiator */
			u32 seq_cnt : 1;      /* seq_cnt */
			u32 e_d_tov : 1;      /* E_D_TOV resolution */
			u32 vlan_enable : 1;  /* Vlan enable flag */
			u32 conf_support : 1; /* Response confirm support flag */
			u32 rec_support : 1;  /* REC support flag */
			u32 write_xfer_rdy : 1; /* WRITE Xfer_Rdy disable or enable */
			u32 sgl_num : 1; /* Double or single SGL, 1: double; 0: single */
		} dw;
		u32 pctxt_val1;
	} sw_ctxt_config;
	struct immi_dif_info immi_dif_info; /* immediate data dif control info(20B) */
};

struct spfc_hw_rsvd_queue {
	/* bitmap[0]:255-192 */
	/* bitmap[1]:191-128 */
	/* bitmap[2]:127-64 */
	/* bitmap[3]:63-0 */
	u64 seq_id_bitmap[4];
	struct {
		u64 last_req_seq_id : 8;
		u64 xid : 20;
		u64 rsvd0 : 36;
	} wd0;
};

struct spfc_sq_qinfo {
	u64 rsvd_0 : 10;
	u64 pmsn_type : 1; /* 0: get pmsn from queue header; 1: get pmsn from ucode */
	u64 rsvd_1 : 4;
	u64 cur_wqe_o : 1; /* should be opposite from loop_o */
	u64 rsvd_2 : 48;

	u64 cur_sqe_gpa;
	u64 pmsn_gpa; /* sq's queue header gpa */

	u64 sqe_dmaattr_idx : 6;
	u64 sq_so_ro : 2;
	u64 rsvd_3 : 2;
	u64 ring : 1;	/* 0: link; 1: ring */
	u64 loop_o : 1; /* init to be the first round o-bit */
	u64 rsvd_4 : 4;
	u64 zerocopy_dmaattr_idx : 6;
	u64 zerocopy_so_ro : 2;
	u64 parity : 8;
	u64 r : 1;
	u64 s : 1;
	u64 enable_256 : 1;
	u64 rsvd_5 : 23;
	u64 pcie_template : 6;
};

struct spfc_cq_qinfo {
	u64 pcie_template_hi : 3;
	u64 parity_2 : 1;
	u64 cur_cqe_gpa : 60;

	u64 pi : 15;
	u64 pi_o : 1;
	u64 ci : 15;
	u64 ci_o : 1;
	u64 c_eqn_msi_x : 10; /* if init_mode = 2, is msi/msi-x; other the low-5-bit means c_eqn */
	u64 parity_1 : 1;
	u64 ci_type : 1; /* 0: get ci from queue header; 1: get ci from ucode */
	u64 cq_depth : 3; /* valid when ring = 1 */
	u64 armq : 1;	  /* 0: IDLE state; 1: NEXT state */
	u64 cur_cqe_cnt : 8;
	u64 cqe_max_cnt : 8;

	u64 cqe_dmaattr_idx : 6;
	u64 cq_so_ro : 2;
	u64 init_mode : 2; /* 1: armQ; 2: msi/msi-x; others: rsvd */
	u64 next_o : 1;	   /* next pate valid o-bit */
	u64 loop_o : 1;	   /* init to be the first round o-bit */
	u64 next_cq_wqe_page_gpa : 52;

	u64 pcie_template_lo : 3;
	u64 parity_0 : 1;
	u64 ci_gpa : 60; /* cq's queue header gpa */
};

struct spfc_scq_qinfo {
	union {
		struct {
			u64 scq_n : 20; /* scq number */
			u64 sq_min_preld_cache_num : 4;
			u64 sq_th0_preld_cache_num : 5;
			u64 sq_th1_preld_cache_num : 5;
			u64 sq_th2_preld_cache_num : 5;
			u64 rq_min_preld_cache_num : 4;
			u64 rq_th0_preld_cache_num : 5;
			u64 rq_th1_preld_cache_num : 5;
			u64 rq_th2_preld_cache_num : 5;
			u64 parity : 6;
		} info;

		u64 pctxt_val1;
	} hw_scqc_config;
};

struct spfc_srq_qinfo {
	u64 parity : 4;
	u64 srqc_gpa : 60;
};

/* here is the layout of service type 12/13 */
struct spfc_parent_context {
	u8 key[SPFC_PARENT_CONTEXT_KEY_ALIGN_SIZE];
	struct spfc_scq_qinfo resp_scq_qinfo;
	struct spfc_srq_qinfo imm_srq_info;
	struct spfc_sq_qinfo sq_qinfo;
	u8 timer_section[SPFC_PARENT_CONTEXT_TIMER_SIZE];
	struct spfc_hw_rsvd_queue hw_rsvdq;
	struct spfc_srq_qinfo els_srq_info;
	struct spfc_sw_section sw_section;
};

/* here is the layout of service type 13 */
struct spfc_ssq_parent_context {
	u8 rsvd0[64];
	struct spfc_sq_qinfo sq1_qinfo;
	u8 rsvd1[32];
	struct spfc_sq_qinfo sq2_qinfo;
	u8 rsvd2[32];
	struct spfc_sq_qinfo sq3_qinfo;
	struct spfc_scq_qinfo sq_pretchinfo;
	u8 rsvd3[24];
};

/* FC Key Section */
struct spfc_fc_key_section {
	u32 xid_h : 4;
	u32 key_size : 2;
	u32 rsvd1 : 1;
	u32 srv_type : 5;
	u32 csize : 2;
	u32 rsvd0 : 17;
	u32 v : 1;

	u32 tag_fp_h : 4;
	u32 rsvd2 : 12;
	u32 xid_l : 16;

	u16 tag_fp_l;
	u8 smac[6];  /* Source MAC */
	u8 dmac[6];  /* Dest MAC */
	u8 sid[3];   /* Source FC ID */
	u8 did[3];   /* Dest FC ID */
	u8 svlan[4]; /* Svlan */
	u8 cvlan[4]; /* Cvlan */

	u32 next_ptr_h;
};

#endif
