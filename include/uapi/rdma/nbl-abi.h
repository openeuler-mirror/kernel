/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) or Linux-OpenIB) */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_ABI_H
#define NBL_ABI_H

#include <linux/types.h>
#include <linux/if_ether.h>

enum nbl_memreg_type {
	NBL_MEMREG_TYPE_MEM = 0,
};

struct nbl_mem_reg_req {
	__u16 reg_type; /* enum nbl_memreg_type */
	__u16 cq_pages;
	__u16 rq_pages;
	__u16 sq_pages;
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
	__u32 shadow_offset; /* where shadow begin from qpc head, now 480 */
	__u32 shadow_size; /* size of shadow area, now 32 */
	__u32 page_size; /* 4096(4K) or 2097152(2M), from HMC */
	__u32 qp_caps; /* use post_send pre-check */
	__u32 seq_num; /*use post_send db check*/
	__u32 dport_id : 10;
	__u32 dport : 3;
	__u32 fwd : 2;
	__u32 rss_lag_en : 1;
	__u32 tunnel_en : 1;
	__u32 dwqe_en : 1;
	__u32 batch_wqe_th : 8; /* kick db when post send wqe reach batch_wqe_th */
	__u32 qp_dump_flag : 1;
	__u32 rsv0 : 5;
	__u64 tc2pri;
	__u64 sys_page_offset;
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
	__u32 shadow_offset; /* where shadow begin from cqc head, now 384bits(48bytes) */
	__u64 shadow_base_addr; /* use as mmap para */
	__u32 shadow_size; /* size of shadow area, 16bytes */
	__u32 page_size; /* 4096(4K) or 2097152(2M), from HMC */
	__u64 sys_page_offset;
};

struct nbl_ib_create_ah_resp {
	__u32 response_length;
	__u32 ah_id;
	__u8 dest_mac[ETH_ALEN];
	__u8 vlan_tag_ipv4_valid;
	__u8 src_addr_index;
	__u16 vlan_id;
	__u8 rsv[6];
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
	__u32 max_hw_rq_quanta; /* 1.0 version is 128 */
	__u32 max_hw_wq_quanta; /* 1.0 version is 128 */
	__u32 min_hw_cq_size;
	__u32 max_hw_cq_size;
	__u16 max_hw_sq_chunk; /* 1.0 version is 128 */
	__u8 hw_rev;
	__u8 reserved;
};

struct nbl_modify_qp_req {
	__u8 sq_flush;
	__u8 rq_flush;
	__u8 rsvd[6];
};

#endif /* NBL_ABI_H */
