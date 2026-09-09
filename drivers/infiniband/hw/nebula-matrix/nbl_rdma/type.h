/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef NBL_IB_TYPE_H
#define NBL_IB_TYPE_H

#include "hw.h"
#include "user.h"

#define NBL_INVALID_CQ_IDX 0xffffffff
#define NBL_PARAM_LEN 400

enum nbl_mmap_flag {
	NBL_MMAP_IO_NC,
	NBL_MMAP_IO_WC,
};

enum nbl_registers {
	NBL_CQP_PI,
	NBL_SQ_DB,
	NBL_ARM_CQ,
	NBL_CEQ0_CI,
	NBL_CEQ1_CI,
	NBL_AEQ_CI,
	NBL_RQ_DB,
	NBL_NOTIFY_OFFSET,
	NBL_DWQE_OFFSET,
	NBL_MAX_REGS,
};

/* common define*/
enum nbl_ib_dbg_cc_param_types {
	/* golbal */
	NBL_CFG_CC_MODE,
	NBL_CFG_CC_EN,
	/* nbl-cc */
	NBL_CFG_CC_SAVE,
	NBL_CFG_CC_OAMREQ_TC_EN,
	NBL_CFG_CC_OAMREQ_NET_TC,
	NBL_CFG_CC_OAMACK_TC_EN,
	NBL_CFG_CC_OAMACK_NET_TC,

	NBL_CFG_CC_OAMACK_BLK_TH,
	NBL_CFG_CC_TARGETWIN_MIN,
	NBL_CFG_CC_PKT_NUM_EN,

	NBL_CFG_CC_HIGH_RTT_FRACTION,
	NBL_CFG_CC_LOW_RTT_FRACTION,
	NBL_CFG_CC_INC_TARWINTH,
	NBL_CFG_CC_DEC_TARWINTH,
	NBL_CFG_CC_TARGETWIN,
	NBL_CFG_CC_RTT_OFFSET,
	NBL_CFG_CC_RTT_PROBE_INVL,
	NBL_CFG_CC_HIGH_PRI_RTT_INVL,
	NBL_CFG_CC_HIGH_PRI_RTT_EN,
	NBL_CFG_CC_RST_WIN_HIGH,
	NBL_CFG_CC_RST_WIN_EN,
	NBL_CFG_CC_RST_WIN_LOW,
	NBL_CFG_CC_RST_WIN_RTT_INT,
	NBL_CFG_CC_RST_WIN_RTT_FRACTION,
	NBL_CFG_CC_DYN_RTT_OFFSET_EN,
	NBL_CFG_CC_REMOVE_REMOTE_TIME,
	NBL_CFG_CC_HIGH_RTT_INT,
	NBL_CFG_CC_LOW_RTT_INT,
	NBL_CFG_CC_RDMA_TIME_SEL,
	NBL_CFG_CC_CMP_RTT_QP_MULT,
	NBL_CFG_CC_LOW_RTT_OFFSET,
	NBL_CFG_CC_HIGH_RTT_OFFSET,
	NBL_CFG_CC_RST_WIN_RTT_OFFSET,

	/* NBLCC add before NBL_CFG_CC_TXP_SENDREQ_DB_CFG*/
	NBL_CFG_CC_TXP_SENDREQ_DB_CFG,

	/* nbl-qcn */
	NBL_CFG_CC_QCN_SAVE,
	NBL_CFG_QCN_RR_MODE,
	NBL_CFG_QCN_MID_SENDBLK_TH_HIGH,
	NBL_CFG_QCN_MID_SENDBLK_TH_LOW,
	NBL_CFG_QCN_MID_SENDTIME_TH_HIGH,
	NBL_CFG_QCN_MID_SENDTIME_TH_LOW,
	NBL_CFG_QCN_RR_TH,
	NBL_CFG_QCN_AI_RP,
	NBL_CFG_QCN_HAI_RP,
	NBL_CFG_QCN_MIN_RATE_RP,
	NBL_CFG_QCN_MAX_RATE_RP,
	NBL_CFG_QCN_QUICK_START_FLAG,
	NBL_CFG_QCN_SENDCNP_FLAG,
	NBL_CFG_QCN_SENDCNP_TIME_TH,
	NBL_CFG_QCN_START_RATE,
	NBL_CFG_QCN_EXTRA_QUANTA,
	NBL_CFG_QCN_FAST_REDUCE_MODE,
	NBL_CFG_QCN_REDUCE_COE,

	NBL_CFG_CC_TYPE_MAX,
};

enum nbl_ib_qos_param_types {
	/* golbal */
	NBL_CFG_QOS_SAVE,
	NBL_CFG_TC_PRI,
	NBL_CFG_SQ_PRI_MAP,
	NBL_CFG_RAQ_PRI_MAP,
	NBL_CFG_PRI_IMAP,
	NBL_CFG_PFC_IMAP,
	NBL_CFG_DB_TO_CSCH_EN,
	NBL_CFG_SW_DB_CSCH_TH,
	NBL_CFG_CSCH_QLEN_TH,
	NBL_CFG_POLL_WGT,

	/* function  base */
	NBL_CFG_SPWRR,
	NBL_CFG_TC_WGT,
	NBL_CFG_SET_PFC,
	NBL_CFG_TRUST_DSCP_EN,
	NBL_CFG_SET_PFC_BUF,
	NBL_CFG_SET_DSCP_TO_PRI,
	NBL_CFG_SET_8021P_TO_PRI,
	NBL_CFG_QOS_TYPE_MAX,
};

struct nbl_aeqe_info {
	u32 qp_cq_ceq_id;
	u32 wqe_idx;
	u8  cmd_idx;
	u16 ae_id;
	u8 ae_src;
	bool aeqe_overflow : 1;
};

struct nbl_ceq_init_info {
	u64 ceqe_pa;
	struct nbl_sc_dev *dev;
	u64 *ceqe_base;
	u32 elem_cnt;
	u32 msix_idx;
	u32 ceq_id;
	u32 ceq_pg_num;
	bool pa_continuous : 1;
};

struct nbl_ceqe {
	__be64 buf[NBL_CEQE_SIZE];
};

struct nbl_sc_ceq {
	u64 ceq_elem_pa; /* physical addr*/
	struct nbl_sc_dev *dev;
	struct nbl_ceqe *ceqe_base; /* virtual addr*/
	u32 ceq_id;
	u32 msix_idx;
	u32 elem_cnt;
	struct nbl_ring ceq_ring;
	u8 polarity;
	u32 ceq_pg_num;
	bool pa_continuous : 1;
};

struct nbl_sc_dev {
	struct nbl_hw *hw;
	struct nbl_hmc_info *hmc_info;
	struct nbl_hw_attrs hw_attrs;
	const struct nbl_irq_ops *irq_ops;
	bool ceq_valid : 1;
	void __iomem *hw_regs[NBL_MAX_REGS];
	struct nbl_sc_ceq *ceq[NBL_CEQ_MAX_COUNT];
	struct nbl_sc_aeq *aeq;
	int cc_dbgfs_params[NBL_CFG_CC_TYPE_MAX];
	char qos_dbgfs_params[NBL_CFG_QOS_TYPE_MAX][NBL_PARAM_LEN];
	u16 function_id;
	u16 pcie_func_id;
	u16 dport_id;
	u8 dport;
	u8 fwd;
	u8 stat_id;
	u8 ackreq_th;
	u8 cc_mode;
	bool rss_lag_en;
	bool tunnel_en;
	bool fmr_nofence;
	bool dwqe_en;
	u32 debug_errcdoe;
	union rdma_tc_wgt_cfg_tbl tc_wgt;
	u64 tc2pri;
	u8 batch_wqe_th;
	bool has_high_temp_alarm;
	u64 qpn_interval;
	bool is_ctrl_dev;
	bool dev_dump_flag;
};

struct nbl_device_init_info {
	struct nbl_hw *hw;
	void __iomem *bar0;
	u8 ost_rd_atom; /* from nbl_actual_rd_atom */
};

struct nbl_cq_uk_init_info {
	struct nbl_cqe *cq_base;
	u32 cq_id; /* rsrc cq_num*/
	u32 cq_size; /* cqe num*/
	__be64 *shadow_area; /* shadow area address, VA */
	void *cqc_base_va; /* page addr where cqc locate, VA */
	u64 cqc_base_pa;
};

struct nbl_cq_init_info {
	struct nbl_sc_dev *dev;
	u64 cq_base_pa;
	u64 cqc_begin_pa; /* CQC base PA */
	u64 shadow_area_pa; /* shadow area address, PA */
	u32 ceq_id;
	u32 shadow_read_threshold;
	u32 cq_pg_num;
	bool pa_continuous : 1;
	struct nbl_cq_uk_init_info cq_uk_init_info;
};

struct nbl_sc_cq {
	struct nbl_cq_uk cq_uk;
	u64 cqc_begin_pa; /* CQC base PA */
	u64 shadow_area_pa; /* physical address*/
	u64 cq_pa; /* pa*/
	u32 cq_pg_num;
	struct nbl_sc_dev *dev;
	u32 ceq_id;
	void *bak_nbl_cq; /* point to struct nbl_cq */
	u32 shadow_read_threshold;

	bool pa_continuous : 1;
};

#endif /* NBL_IB_TYPE_H */
