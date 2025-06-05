/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_SMC_H__
#define __XSC_SMC_H__

#include <rdma/ib_verbs.h>

enum smc_wr_reg_state {
	POSTED,         /* ib_wr_reg_mr request posted */
	CONFIRMED,      /* ib_wr_reg_mr response: successful */
	FAILED          /* ib_wr_reg_mr response: failure */
};

enum smc_link_state {       /* possible states of a link */
	SMC_LNK_UNUSED,         /* link is unused */
	SMC_LNK_INACTIVE,       /* link is inactive */
	SMC_LNK_ACTIVATING,     /* link is being activated */
	SMC_LNK_ACTIVE,         /* link is active */
};

#define SMC_GID_SIZE            sizeof(union ib_gid)
#define SMC_LGR_ID_SIZE         4
#define SMC_WR_BUF_CNT		64	/* # of ctrl buffers per link, SMC_WR_BUF_CNT
					 * should not be less than 2 * SMC_RMBS_PER_LGR_MAX,
					 * since every connection at least has two rq/sq
					 * credits in average, otherwise may result in
					 * waiting for credits in sending process.
					 */
#define SMC_WR_BUF_SIZE		48	/* size of work request buffer */
#define SMC_WR_BUF_V2_SIZE	8192	/* size of v2 work request buffer */

struct smc_ib_cq {				/* ib_cq wrapper for smc */
	struct smc_ib_device	*smcibdev;	/* parent ib device */
	struct ib_cq		*ib_cq;		/* real ib_cq for link */
	struct tasklet_struct	tasklet;	/* tasklet for wr */
	int			load;		/* load of current cq */
};

struct smc_wr_buf {
	u8	raw[SMC_WR_BUF_SIZE];
};

struct smc_wr_v2_buf {
	u8	raw[SMC_WR_BUF_V2_SIZE];
};

struct smc_link {
	struct iw_ext_conn_param	iw_conn_param;
	struct smc_ib_device	*smcibdev;	/* ib-device */
	u8			ibport;		/* port - values 1 | 2 */
	struct ib_pd		*roce_pd;	/* IB protection domain,
						 * unique for every RoCE QP
						 */
	struct smc_ib_cq	*smcibcq;	/* cq for recv & send */
	struct ib_qp		*roce_qp;	/* IB queue pair */
	struct ib_qp_attr	qp_attr;	/* IB queue pair attributes */

	struct smc_wr_buf	*wr_tx_bufs;	/* WR send payload buffers */
	struct ib_send_wr	*wr_tx_ibs;	/* WR send meta data */
	struct ib_sge		*wr_tx_sges;	/* WR send gather meta data */
	struct smc_rdma_sges	*wr_tx_rdma_sges;/*RDMA WRITE gather meta data*/
	struct smc_rdma_wr	*wr_tx_rdmas;	/* WR RDMA WRITE */
	struct smc_wr_tx_pend	*wr_tx_pends;	/* WR send waiting for CQE */
	struct completion	*wr_tx_compl;	/* WR send CQE completion */
	/* above four vectors have wr_tx_cnt elements and use the same index */
	struct ib_send_wr	*wr_tx_v2_ib;	/* WR send v2 meta data */
	struct ib_sge		*wr_tx_v2_sge;	/* WR send v2 gather meta data*/
	struct smc_wr_tx_pend	*wr_tx_v2_pend;	/* WR send v2 waiting for CQE */
	dma_addr_t		wr_tx_dma_addr;	/* DMA address of wr_tx_bufs */
	dma_addr_t		wr_tx_v2_dma_addr; /* DMA address of v2 tx buf*/
	atomic_long_t		wr_tx_id;	/* seq # of last sent WR */
	unsigned long		*wr_tx_mask;	/* bit mask of used indexes */
	u32			wr_tx_cnt;	/* number of WR send buffers */
	wait_queue_head_t	wr_tx_wait;	/* wait for free WR send buf */
	struct {
		struct percpu_ref	wr_tx_refs;
	} ____cacheline_aligned_in_smp;
	struct completion	tx_ref_comp;
	atomic_t		tx_inflight_credit;

	struct smc_wr_buf	*wr_rx_bufs[SMC_WR_BUF_CNT];
						/* WR recv payload buffers */
	struct ib_recv_wr	*wr_rx_ibs;	/* WR recv meta data */
	struct ib_sge		*wr_rx_sges;	/* WR recv scatter meta data */
	/* above three vectors have wr_rx_cnt elements and use the same index */
	dma_addr_t		wr_rx_dma_addr[SMC_WR_BUF_CNT];
						/* DMA address of wr_rx_bufs */
	u64			wr_rx_id;	/* seq # of last recv WR */
	u32			wr_rx_cnt;	/* number of WR recv buffers */
	unsigned long		wr_rx_tstamp;	/* jiffies when last buf rx */

	struct ib_reg_wr	wr_reg;		/* WR register memory region */
	wait_queue_head_t	wr_reg_wait;	/* wait for wr_reg result */
	struct {
		struct percpu_ref	wr_reg_refs;
	} ____cacheline_aligned_in_smp;
	struct completion	reg_ref_comp;
	enum smc_wr_reg_state	wr_reg_state;	/* state of wr_reg request */

	atomic_t	peer_rq_credits;	/* credits for peer rq flowctrl */
	atomic_t	local_rq_credits;	/* credits for local rq flowctrl */
	u8		credits_enable;		/* credits enable flag, set when negotiation */
	u8		local_cr_watermark_high;	/* local rq credits watermark */
	u8		peer_cr_watermark_low;	/* peer rq credits watermark */
	u8		credits_update_limit;	/* credits update limit for cdc msg */
	struct work_struct	credits_announce_work;	/* work for credits announcement */
	unsigned long	flags;	/* link flags, SMC_LINKFLAG_ANNOUNCE_PENDING .etc */

	u8			gid[SMC_GID_SIZE];/* gid matching used vlan id*/
	u8			eiwarp_gid[SMC_GID_SIZE];
						/* gid of eRDMA iWARP device */
	u8			sgid_index;	/* gid index for vlan id      */
	u32			peer_qpn;	/* QP number of peer */
	enum ib_mtu		path_mtu;	/* used mtu */
	enum ib_mtu		peer_mtu;	/* mtu size of peer */
	u32			psn_initial;	/* QP tx initial packet seqno */
	u32			peer_psn;	/* QP rx initial packet seqno */
	u8			peer_mac[ETH_ALEN];	/* = gid[8:10||13:15] */
	u8			peer_gid[SMC_GID_SIZE];	/* gid of peer*/
	u8			link_id;	/* unique # within link group */
	u8			link_uid[SMC_LGR_ID_SIZE]; /* unique lnk id */
	u8			peer_link_uid[SMC_LGR_ID_SIZE]; /* peer uid */
	u8			link_idx;	/* index in lgr link array */
	u8			link_is_asym;	/* is link asymmetric? */
	u8			clearing : 1;	/* link is being cleared */
	refcount_t		refcnt;		/* link reference count */
	struct smc_link_group	*lgr;		/* parent link group */
	struct work_struct	link_down_wrk;	/* wrk to bring link down */
	char			ibname[IB_DEVICE_NAME_MAX]; /* ib device name */
	int			ndev_ifidx; /* network device ifindex */

	enum smc_link_state	state;		/* state of link */
	struct delayed_work	llc_testlink_wrk; /* testlink worker */
	struct completion	llc_testlink_resp; /* wait for rx of testlink */
	int			llc_testlink_time; /* testlink interval */
	atomic_t		conn_cnt; /* connections on this link */
};

#endif
