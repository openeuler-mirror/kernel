/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_QUEUE_H
#define XSC_QUEUE_H

#include <net/page_pool.h>

#include "../pci/wq.h"

enum {
	XSC_SEND_WQE_DS	= 16,
	XSC_SEND_WQE_BB	= 64,
};

enum {
	XSC_RECV_WQE_DS	= 16,
	XSC_RECV_WQE_BB	= 16,
};

#define XSC_SEND_WQEBB_NUM_DS	        (XSC_SEND_WQE_BB / XSC_SEND_WQE_DS)
#define XSC_LOG_SEND_WQEBB_NUM_DS	ilog2(XSC_SEND_WQEBB_NUM_DS)

#define XSC_RECV_WQEBB_NUM_DS	        (XSC_RECV_WQE_BB / XSC_RECV_WQE_DS)
#define XSC_LOG_RECV_WQEBB_NUM_DS	ilog2(XSC_RECV_WQEBB_NUM_DS)

#define XSC_SEND_WQEBB_CTRL_NUM_DS	1

enum {
	XSC_ETH_RQ_STATE_ENABLED,
};

enum {
	XSC_ETH_SQ_STATE_ENABLED,
	XSC_ETH_RQ_STATE_CACHE_REDUCE_PENDING,
};

struct xsc_dma_info {
	struct page	*page;
	dma_addr_t	addr;
};

struct xsc_wqe_frag_info {
	struct xsc_dma_info *di;
	u32 offset;
	u8 last_in_page;
};

struct xsc_rq_frag_info {
	int frag_size;
	int frag_stride;
};

struct xsc_rq_frags_info {
	struct xsc_rq_frag_info arr[XSC_MAX_RX_FRAGS];
	u8 num_frags;
	u8 log_num_frags;
	u8 wqe_bulk;
	u8 wqe_bulk_min;
	u8 frags_max_num;
};

struct xsc_cq {
	/* data path - accessed per cqe */
	struct xsc_cqwq	wq;

	/* data path - accessed per napi poll */
	u16			event_ctr;
	struct napi_struct	*napi;
	struct xsc_core_cq	xcq;
	struct xsc_channel	*channel;

	/* control */
	struct xsc_core_device	*xdev;
	struct xsc_wq_ctrl	wq_ctrl;
	u8			rx;
} ____cacheline_aligned_in_smp;

struct xsc_pcie_lat_work {
	struct xsc_core_device *xdev;
	struct xsc_adapter *adapter;
	struct delayed_work work;
	u16 enable;
	u32 period;
};

#define XSC_PAGE_CACHE_LOG_MAX_RQ_MULT		6
#define XSC_PAGE_CACHE_REDUCE_WORK_INTERVAL	200  /* msecs */
#define XSC_PAGE_CACHE_REDUCE_GRACE_PERIOD	1000 /* msecs */
#define XSC_PAGE_CACHE_REDUCE_SUCCESS_CNT	4

struct xsc_page_cache_reduce {
	struct delayed_work	reduce_work;
	u32		success;
	unsigned long	next_ts;
	unsigned long	grace_period;
	unsigned long	delay;
	struct xsc_dma_info	*pending;
	u32		npages;
};

struct xsc_page_cache {
	struct xsc_dma_info	*page_cache;
	u32	head;
	u32	tail;
	u32	sz;
	u32	resv;
};

struct xsc_rq;
struct xsc_cqe;
typedef void (*xsc_fp_handle_rx_cqe)(struct xsc_cqwq *cqwq, struct xsc_rq *rq,
				     struct xsc_cqe *cqe);
typedef bool (*xsc_fp_post_rx_wqes)(struct xsc_rq *rq);
typedef void (*xsc_fp_dealloc_wqe)(struct xsc_rq *rq, u16 ix);
typedef struct sk_buff * (*xsc_fp_skb_from_cqe)(struct xsc_rq *rq,
			  struct xsc_wqe_frag_info *wi, u32 cqe_bcnt, u8 has_pph);

struct xsc_rq {
	struct xsc_core_qp		cqp;
	struct {
		struct xsc_wq_cyc	wq;
		struct xsc_wqe_frag_info	*frags;
		struct xsc_dma_info	*di;
		struct xsc_rq_frags_info	info;
		xsc_fp_skb_from_cqe	skb_from_cqe;
	} wqe;

	struct {
		u16	headroom;
		u8	map_dir;	/* dma map direction */
	} buff;

	struct page_pool	*page_pool;
	struct xsc_wq_ctrl	wq_ctrl;
	struct xsc_cq		cq;
	u32	rqn;
	int	ix;

	unsigned long	state;
	struct work_struct  recover_work;
	struct xsc_rq_stats *stats;

	u32 hw_mtu;
	u32 frags_sz;

	xsc_fp_handle_rx_cqe	handle_rx_cqe;
	xsc_fp_post_rx_wqes	post_wqes;
	xsc_fp_dealloc_wqe	dealloc_wqe;
	struct xsc_page_cache	page_cache;
} ____cacheline_aligned_in_smp;

struct xsc_tx_wqe_info {
	struct sk_buff *skb;
	u32 num_bytes;
	u8  num_wqebbs;
	u8  num_dma;
};

enum xsc_dma_map_type {
	XSC_DMA_MAP_SINGLE,
	XSC_DMA_MAP_PAGE
};

struct xsc_sq_dma {
	dma_addr_t	addr;
	u32		size;
	enum xsc_dma_map_type	type;
};

struct xsc_sq {
	struct xsc_core_qp		cqp;
	/* dirtied @completion */
	u16                        cc;
	u32                        dma_fifo_cc;
	/* dirtied @xmit */
	u16                        pc ____cacheline_aligned_in_smp;
	u32                        dma_fifo_pc;

	struct xsc_cq            cq;

	/* read only */
	struct xsc_wq_cyc         wq;
	u32                        dma_fifo_mask;
	struct xsc_sq_stats     *stats;
	struct {
		struct xsc_sq_dma         *dma_fifo;
		struct xsc_tx_wqe_info    *wqe_info;
	} db;
	void __iomem              *uar_map;
	struct netdev_queue       *txq;
	u32                        sqn;
	u16                        stop_room;

	__be32                     mkey_be;
	unsigned long              state;
	unsigned int               hw_mtu;

	/* control path */
	struct xsc_wq_ctrl        wq_ctrl;
	struct xsc_channel         *channel;
	int                        ch_ix;
	int                        txq_ix;
	struct work_struct         recover_work;
} ____cacheline_aligned_in_smp;

struct rdma_opcode_data {
	u32      immdt_value;
} __packed __aligned(4);

struct raw_opcode_data {
	u16      has_pph : 1;
	u16      so_type : 1;
	u16      so_data_size : 14;
	u8       rsv;
	u8       so_hdr_len;
} __packed __aligned(4);

struct rawtype_opcode_data {
	u16     desc_id;
	u16     is_last_wqe : 1;
	u16     dst_qp_id : 15;
} __packed __aligned(4);

struct xsc_wqe_ctrl_seg {
	u8			msg_opcode;
	u8			with_immdt : 1;
	u8			csum_en : 2;
	u8			ds_data_num : 5;
	u16			wqe_id;
	u32                     msg_len;
	union {
		struct rdma_opcode_data   _rdma_opcode_data;
		struct raw_opcode_data   _raw_opcode_data;
		struct rawtype_opcode_data   _rawtype_opcode_data;
	} opcode_data;
	u32                      se : 1;
	u32                      ce : 1;
	u32                      rsv : 30;
};

static inline u8 get_cqe_opcode(struct xsc_cqe *cqe)
{
	return cqe->msg_opcode;
}

static inline void xsc_dump_err_cqe(struct xsc_core_device *dev,
				    struct xsc_cqe *cqe)
{
	print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_OFFSET, 16, 1, cqe,
		       sizeof(*cqe), false);
}

#endif /* XSC_QUEUE_H */
