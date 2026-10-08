/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) or Linux-OpenIB) */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_V2_ABI_H
#define NBL_V2_ABI_H

#include <linux/types.h>
#include <linux/if_ether.h>

#define SRQ_SUBQ_NUM 8

enum nbl_memreg_type {
	NBL_MEMREG_TYPE_MEM = 0,
	NBL_MEMREG_TYPE_MR_BRANCH = 1,
};

struct nbl_mem_reg_req {
	__u16 reg_type; /* enum nbl_memreg_type */
	__u16 bdf_num;
	__u32 rsv;
};

struct nbl_ib_alloc_pd_resp {
	__u32 pd_id;
	__u8 reserved[4];
};

struct nbl_ib_create_qp_resp {
	__u64 shadow_base_addr; /* use as mmap para */
	__u32 qp_id;
	__u32 sq_size;
	__u32 rq_size;
	__u32 qpc_size; /* 512 or other, now 512 */
	__u32 shadow_offset; /* offset from page 4k OR 2M */
	__u32 shadow_size; /* size of shadow area, now 32 */
	__u32 page_size; /* 4096(4K) or 2097152(2M), from HMC */
	__u32 qp_caps; /* use post_send pre-check */
	__u32 seq_num; /*use post_send db check*/
	__u32 dport_id : 10;
	__u32 dport : 3;
	__u32 fwd : 2;
	__u32 rss_lag_en : 1;
	__u32 tunnel_en : 1;
	__u32 dwqe_en : 1; /*use for DF200/ASIC V1R1/V2R1*/
	__u32 rsv0 : 14;
	__u32 vsi_id;
	__u32 dpage_offset; /*use for DF200/ASIC V2R1*/
	__u64 dpage_mmap_key; /*use for DF200/ASIC V2R1*/
	__u64 tc2pri; /* used for RNIC400 only */
};

struct nbl_create_qp_req {
	__u64 sq_bufer; /* __aligned_u64 */
	__u64 rq_bufer;
	__u32 sq_size;
	__u32 rq_size;
	__u64 qp;
};

struct nbl_create_cq_req {
	__u64 user_cq_buf;
	__u32 cq_buf_size; /* size of Queue, 4k align*/
	__u32 rsv;
};

struct nbl_ib_create_cq_resp {
	__u32 cq_id;
	__u32 cq_size;
	__u32 cqc_size; /* 512bits(64bytes)*/
	__u32 shadow_offset; /* offset from page start */
	__u64 shadow_base_addr; /* use as mmap para */
	__u32 shadow_size; /* size of shadow area, 8bytes */
	__u32 page_size; /* 4096(4K) or 2097152(2M), from HMC */
};

struct nbl_resize_cq_req {
	__u64 user_cq_buffer;
	__u32 cq_buf_size; /* size of Queue, 4k align*/
	__u32 rsz_free_num; /* queue ready to free */
};

struct nbl_ib_create_ah_resp {
	__u32 response_length;
	__u32 ah_id;
	__u8 dest_mac[ETH_ALEN];
	__u8 vlan_tag_ipv4_valid;
	__u8 is_local;
	__u16 src_addr_index;
	__u16 vlan_id;
	__u8 rsv[4];
};

struct nbl_ib_alloc_ucontext_resp {
	__u64 dwqe_mmap_key;
	__u64 db_mmap_key;
	__u64 feature_flags;
	__u32 notify_offset; /* use after mmap db */
	__u32 notify_dwqe_offset; /* use after mmap dwqe db */
	__u32 max_hw_wq_sges; /* 1.0 version is 6 */
	__u32 max_hw_read_sges; /* 1.0 version is 7 */
	__u32 max_hw_inline; /* 1.0 version is 92 */
	__u32 max_hw_ud_inline;
	__u32 max_hw_rq_quanta; /* 1.0 version is 128 */
	__u32 max_hw_wq_quanta; /* 1.0 version is 128 */
	__u32 min_hw_cq_size;
	__u32 max_hw_cq_size;
	__u32 max_hw_srq_wr;
	__u32 qp_table_size;
	__u16 max_hw_sq_chunk; /* 1.0 version is 128 */
	__u8 hw_rev;
	__u8 rsvd[5];
};

struct nbl_ib_modify_qp_req {
	__u8 sq_flush;
	__u8 rq_flush;
	__u8 rsvd[6];
};

struct nbl_ib_modify_qp_resp {
	__u8 dst_is_local;
	__u8 local_rd_no_pkt;
	__u8 real_tclass; /* QP really used tclass */
	__u8 rsv;
	__u16 pmtu;
	__u16 seq_num;
};

struct nbl_create_srq_req {
	__u64 buf_base[SRQ_SUBQ_NUM];
	__u32 buf_size;
	__u32 rsv;
};

struct nbl_ib_create_srq_resp {
	__u32 srqn;
	__u32 page_0_num; /* how many subq is page 0 */
	__u32 srqc_size; /* 64B or 16B */
	__u32 shadow_offset; /* offset from page start */
	__u64 shadow_base_addr; /* use as mmap para */
	__u32 shadow_size; /* size of shadow area, 8bytes */
	__u32 page_size; /* 4096(4K) or 2097152(2M), from HMC */
	__u8 sorted_indices[SRQ_SUBQ_NUM];
	__u64 sorted_ba[SRQ_SUBQ_NUM];
	__u8 seq_num;
	__u8 rsvd[7];
};

struct nbl_ib_create_flow {
	__u32 ncounters_data;
	__u32 reserved;
};

#endif /* NBL_V2_ABI_H */
