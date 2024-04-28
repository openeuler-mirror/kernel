/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_USER_H
#define ROCE_USER_H

#include <linux/types.h>

struct roce3_alloc_ucontext_resp {
	u32 num_qps;
	u32 num_xsrqs;
	u32 cqe_size;
	u32 wqebb_size;   /* 64B or 128B */
	u32 dwqe_size;	/* 256B */
	u32 max_msg_size; /* (2G -1)B */
	u32 max_comp_vector;
	u32 max_inline_size;
	u32 dev_caps;
	u8 phy_port;
	u8 storage_aa_en;
	u16 rsvd;
	u16 db_offset;
	u16 dwqe_offset;
	u8 srq_container_en;
	u8 srq_container_mode;
	u8 xrc_srq_container_mode;
	u8 warn_th;
};

struct roce3_create_cq_cmd {
	u64 buf_addr;
	u64 db_addr;
};

struct roce3_resize_cq_cmd {
	u64 buf_addr; /* resize cq's 'buf vaַ */
	u64 stage;	/* describe the resize stage,0 or 1; */
};

struct roce3_create_srq_cmd {
	u64 buf_addr;
	u64 db_addr;
	u32 rsvd;
};

struct create_qp_cmd {
	u64 buf_addr;	   /* describe the qp buf address that used to store cqe; */
	u64 db_addr;		/* describe the qp sw db address */
	u32 comp_mask;	  /* kernel can judge whether handle receive inline through comp_mask */
	u8 log_sq_bb_count; /* wqebb number = 2 << log_sq_bb_count */
	u8 log_sq_stride;   /* wqebb size = 2 << log_sq_stride */
	u16 reserved;	   /* reserved is used to aligned cmd */
};

struct roce3_modify_srq_cmd {
	u8 container_flag;
	u8 container_warn_th;
	u16 rsvd;
};

struct roce3_reg_frmr_cmd {
	u64 pbl_vaddr;
};

#endif // ROCE_USER_H
