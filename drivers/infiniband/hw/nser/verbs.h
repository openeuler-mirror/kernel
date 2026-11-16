/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd.*/
#ifndef NSER_VERBS_H
#define NSER_VERBS_H

#define NSER_MAX_SAVED_PHY_PGADDR	4
#define NSER_FLUSH_DELAY_MS		20

#define NSER_PKEY_TBL_SZ		1
#define NSER_DEFAULT_PKEY		0xFFFF

#define NSER_SHADOW_PGCNT		1

#define iwdev_to_idev(iwdev)	(&(iwdev)->rf->sc_dev)

struct nser_ucontext {
	struct ib_ucontext ibucontext;
	struct nser_device *iwdev;
	struct rdma_user_mmap_entry *db_mmap_entry;
	struct list_head cq_reg_mem_list;
	spinlock_t cq_reg_mem_list_lock; /* protect CQ memory list */
	struct list_head qp_reg_mem_list;
	spinlock_t qp_reg_mem_list_lock; /* protect QP memory list */
#ifdef CONFIG_DEBUG_FS
	struct list_head uctx_list;
#endif
	/* FIXME: Move to kcompat ideally. Used < 4.20.0 for old diassasscoaite flow */
	struct list_head vma_list;
	struct mutex vma_list_mutex; /* protect the vma_list */
	int abi_ver;
};

struct nser_pd {
	struct ib_pd ibpd;
	struct nser_sc_pd sc_pd;
};

struct nser_av {
	u8 macaddr[16];
	struct rdma_ah_attr attrs;
	union {
		struct sockaddr saddr;
		struct sockaddr_in saddr_in;
		struct sockaddr_in6 saddr_in6;
	} sgid_addr, dgid_addr;
	u8 net_type;
};

struct nser_ah {
	struct ib_ah ibah;
	struct nser_sc_ah sc_ah;
	struct nser_pd *pd;
	struct nser_av av;
	u8 sgid_index;
	union ib_gid dgid;
	struct hlist_node list;
	refcount_t refcnt;
	struct nser_ah *parent_ah;	/* AH from cached list */
};

struct nser_hmc_pble {
	union {
		u32 idx;
		dma_addr_t addr;
	};
};

struct nser_cq_mr {
	struct nser_hmc_pble cq_pbl;
	dma_addr_t shadow;
	bool split;
};

struct nser_qp_mr {
	struct nser_hmc_pble sq_pbl;
	struct nser_hmc_pble rq_pbl;
	dma_addr_t shadow;
	struct page *sq_page;
};

struct nser_cq_buf {
	struct nser_dma_mem kmem_buf;
	struct nser_cq_uk cq_uk;
	struct nser_hw *hw;
	struct list_head list;
	struct work_struct work;
};

struct nser_pbl {
	struct list_head list;
	union {
		struct nser_qp_mr qp_mr;
		struct nser_cq_mr cq_mr;
	};

	bool pbl_allocated:1;
	bool on_list:1;
	u64 user_base;
	struct nser_pble_alloc pble_alloc;
	struct nser_mr *iwmr;
};

struct nser_mr {
	union {
		struct ib_mr ibmr;
		struct ib_mw ibmw;
	};
	struct ib_umem *region;
	int access;
	u8 is_hwreg;
	u16 type;
	u32 page_cnt;
	u64 ib_umem_page_size;
	u64 page_size;
	u64 page_msk;
	u32 npages;
	u32 stag;
	u64 len;
	u64 pgaddrmem[NSER_MAX_SAVED_PHY_PGADDR];
#ifdef CONFIG_DEBUG_FS
	u64 level0_pa;
#endif
	struct nser_pbl iwpbl;
};

struct nser_cq {
	struct ib_cq ibcq;
	struct nser_sc_cq sc_cq;
	u16 cq_head;
	u16 cq_size;
	u16 cq_num;
	bool user_mode;
	atomic_t armed;
	enum nser_cmpl_notify last_notify;
	u32 polled_cmpls;
	u32 cq_mem_size;
	struct nser_dma_mem kmem;
	struct nser_dma_mem kmem_shadow;
	struct completion free_cq;
	refcount_t refcnt;
	spinlock_t lock; /* for poll cq */
	struct nser_pbl *iwpbl;
	struct nser_pbl *iwpbl_shadow;
	struct list_head resize_list;
	struct nser_cq_poll_info cur_cqe;
	struct list_head cmpl_generated;
	bool ceq_id_valid_flag;
};

struct nser_cmpl_gen {
	struct list_head list;
	struct nser_cq_poll_info cpi;
};

struct disconn_work {
	struct work_struct work;
	struct nser_qp *iwqp;
};

struct iw_cm_id;

struct nser_qp_kmode {
	struct nser_dma_mem dma_mem;
	struct nser_sq_uk_wr_trk_info *sq_wrid_mem;
	u64 *rq_wrid_mem;
};

struct nser_qp {
	struct ib_qp ibqp;
	struct nser_sc_qp sc_qp;
	struct nser_device *iwdev;
	struct nser_cq *iwscq;
	struct nser_cq *iwrcq;
	struct nser_pd *iwpd;
	struct nser_qp_host_ctx_info ctx_info;
	struct nser_roce_offload_info roce_info;
	struct nser_udp_offload_info udp_info;

	struct nser_ah roce_ah;
	struct list_head teardown_entry;
	refcount_t refcnt;
	struct delayed_work dwork_flush;
	atomic_t hw_mod_qp_pend;
	enum ib_qp_state ibqp_state;
	u32 qp_mem_size;
	u32 last_aeq;
	int max_send_wr;
	int max_recv_wr;
	spinlock_t lock; /* serialize posting WRs to SQ/RQ */
	struct nser_qp_context *iwqp_context;
	void *pbl_vbase;
	dma_addr_t pbl_pbase;
	struct page *page;
	u8 user_mode : 1;
	u8 flush_issued : 1;
	u8 sig_all : 1;
	u8 pau_mode : 1;
	u8 rsvd : 1;
	u8 rdma_state;
	u8 hw_rdma_state;
	struct nser_qp_kmode kqp;
	struct nser_dma_mem host_ctx;
	struct nser_pbl *iwpbl;
	struct nser_sge *sg_list;
	struct nser_dma_mem qp_ctx_mem;
	struct completion free_qp;
	wait_queue_head_t waitq;
	wait_queue_head_t mod_qp_waitq;
	u8 rts_ae_rcvd;
};

enum nser_mmap_flag {
	NSER_MMAP_IO_NC,
	NSER_MMAP_IO_WC,
};

struct nser_user_mmap_entry {
	struct rdma_user_mmap_entry rdma_entry;
	u64 bar_offset;
	u8 mmap_flag;
};

static inline u32 nser_fw_ver(struct nser_sc_dev *dev)
{
	return (u32)FIELD_GET(NSER_FW_VER, dev->feature_info[NSER_FEATURE_FW_INFO]);
}

/**
 * nser_mcast_mac_v4 - Get the multicast MAC for an IP address
 * @ip_addr: IPv4 address
 * @mac: pointer to result MAC address
 *
 */
static inline void nser_mcast_mac_v4(u32 *ip_addr, u8 *mac)
{
	u8 *ip = (u8 *)ip_addr;
	unsigned char mac4[ETH_ALEN] = {0x01, 0x00, 0x5E, ip[2] & 0x7F, ip[1],
					ip[0]};

	ether_addr_copy(mac, mac4);
}

/**
 * nser_mcast_mac_v6 - Get the multicast MAC for an IP address
 * @ip_addr: IPv6 address
 * @mac: pointer to result MAC address
 *
 */
static inline void nser_mcast_mac_v6(u32 *ip_addr, u8 *mac)
{
	u8 *ip = (u8 *)ip_addr;
	unsigned char mac6[ETH_ALEN] = {0x33, 0x33, ip[3], ip[2], ip[1], ip[0]};

	ether_addr_copy(mac, mac6);
}

struct rdma_user_mmap_entry*
nser_user_mmap_entry_insert(struct nser_ucontext *ucontext, u64 bar_offset,
			     enum nser_mmap_flag mmap_flag, u64 *mmap_offset);
struct nser_mr *nser_alloc_iwmr(struct ib_umem *region,
				  struct ib_pd *pd, u64 virt,
				  enum nser_memreg_type reg_type);
void nser_free_iwmr(struct nser_mr *iwmr);
int nser_reg_user_mr_type_mem(struct nser_mr *iwmr, int access,
				  bool create_stag);
int nser_ib_register_device(struct nser_device *iwdev);
void nser_ib_unregister_device(struct nser_device *iwdev);
int nser_register_notifiers(struct nser_device *iwdev);
void nser_ib_dealloc_device(struct ib_device *ibdev);
void nser_ib_qp_event(struct nser_qp *iwqp, enum nser_qp_event_type event);
void nser_generate_flush_completions(struct nser_qp *iwqp);
void nser_remove_cmpls_list(struct nser_cq *iwcq);
int nser_generated_cmpls(struct nser_cq *iwcq, struct nser_cq_poll_info *cq_poll_info);
void nser_sched_qp_flush_work(struct nser_qp *iwqp);
void nser_flush_worker(struct work_struct *work);
#endif /* NSER_VERBS_H */
