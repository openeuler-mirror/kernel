/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef NBL_IB_TYPE_H
#define NBL_IB_TYPE_H

#include "hw.h"
#include "user.h"

#define NBL_INVALID_CQ_IDX 0xffffffff
#define TC_MAX_NUM 8

enum nbl_registers {
	NBL_CQP_PI,
	NBL_SQ_DB,
	NBL_ARM_CQ,
	NBL_CEQ0_CI,
	NBL_AEQ_CI,
	NBL_RQ_DB,
	NBL_SRQ_DB0,
	NBL_SRQ_DB1,
	NBL_NOTIFY_OFFSET,
	NBL_DWQE_OFFSET,
	NBL_MAX_REGS,
};

/* common define*/

enum nbl_ib_dbg_fun_param_types {
	NBL_FUN_DBG_QUERY_VOA,
	NBL_FUN_DBG_CACHE_QPC,
	NBL_FUN_DBG_CACHE_CQC,
	NBL_FUN_DBG_CACHE_MRTE,
	NBL_FUN_DBG_CACHE_PBLE,
	NBL_FUN_DBG_CACHE_SQRQE,
	NBL_FUN_DBG_CACHE_IRQE,
	NBL_FUN_DBG_CACHE_RAQE,
	NBL_FUN_DBG_CACHE_SRQC,
	NBL_FUN_DBG_CACHE_PDC,
	NBL_FUN_DBG_HMC_QPC,
	NBL_FUN_DBG_HMC_CQC,
	NBL_FUN_DBG_HMC_SD,
	NBL_FUN_DBG_HMC_PBLE,
	NBL_FUN_DBG_HMC_MRT,
	NBL_FUN_DBG_HMC_SRQC,
	NBL_FUN_DBG_QUERY_AEQ,
	NBL_FUN_DBG_QUERY_CEQ,
	NBL_FUN_DBG_CREATE_QP,
	NBL_FUN_DBG_DESTROY_QP,
	NBL_FUN_DBG_CREATE_CQ,
	NBL_FUN_DBG_DESTROY_CQ,
	NBL_FUN_DBG_QUERY_AEQE,
	NBL_FUN_DBG_QUERY_CEQE,
	NBL_FUN_DBG_QUERY_VSI,
	NBL_FUN_DBG_SET_FWD,
	NBL_FUN_DBG_SET_DPORT,
	NBL_FUN_DBG_SET_DPORT_ID,
	NBL_FUN_DBG_SET_STAT_ID,
	NBL_FUN_DBG_LAG_EN,
	NBL_FUN_DBG_TUNNEL_EN,
	NBL_FUN_DBG_ACKREQ_TH,
	NBL_FUN_DBG_QUERY_PBLE_CNT,
	NBL_FUN_DBG_FMR_NOFENCE_DBG,
	NBL_FUN_DBG_GET_ARM_QUTR,
	NBL_FUN_DBG_GET_ARM_LIMT,
	NBL_FUN_DBG_GET_ARM_FIFONZ,
	NBL_FUN_DBG_GET_ARM_FIFORD,
	NBL_FUN_DBG_DUMP_SQE,
	NBL_FUN_DBG_SET_DWQE_EN,
	NBL_FUN_DBG_SET_DEBUG_ERRCODE,
	NBL_FUN_DBG_CACHE_ORQE,
	NBL_FUN_DBG_CACHE_UNAQE,
	NBL_FUN_DBG_LLC,
	NBL_FUN_DBG_UMR_REVOKE,
	NBL_FUN_DBG_UMR_FLDPBL,
	NBL_FUN_DBG_LOCAL_RD_NO_PKT,
	NBL_FUN_DBG_QUERY_GLO_SD,
	NBL_FUN_DBG_MEM_READ,
	NBL_FUN_DBG_RESET_RDMA,
	NBL_FUN_DBG_SRP_EN,
	NBL_FUN_DBG_SRP_SPRAY_EN,
	NBL_FUN_DBG_SRP_SRACK_TIMER,
	NBL_FUN_DBG_RDMA_DPORT,
	NBL_FUN_DBG_PSN_OST,
	NBL_FUN_DBG_SRP_RETRY_TIMER,
	NBL_FUN_DBG_SRP_RETRY_TH,
	NBL_FUN_DBG_SRP_EXT_BITMAP_EN,
	NBL_FUN_DBG_SRP_OOO_TH,
	NBL_FUN_DBG_SRP_RETRY_PKT_TH,
	NBL_FUN_DBG_QPN_ALLOC_INTERVAL,
	NBL_FUN_DBG_CHECK_CC_PARAM,
	NBL_FUN_DBG_SRP_NIC_SPRAY_MODE,
	NBL_FUN_DBG_CEM_EN,
	NBL_FUN_DBG_WRITE_ATOMIC_FENCE,
	NBL_FUN_DBG_CLEAR_CACHE_QPC,
	NBL_FUN_DBG_CLEAR_CACHE_CQC,
	NBL_FUN_DBG_CLEAR_CACHE_MRTE,
	NBL_FUN_DBG_CLEAR_CACHE_SRQC,
	NBL_FUN_DBG_CLEAR_CACHE_SQRQE,
	NBL_FUN_DBG_SLOW_PATH_EN,
	NBL_FUN_DBG_PRINT_GRC_SRC_ADDR_TBL,
	NBL_FUN_DBG_MP_EN,
	NBL_FUN_DBG_TYPE_MAX,
};

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
	NBL_CFG_CC_TARGET_RTTMIN,

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
	NBL_CFG_QCN_TIME_ACCUM,
	NBL_CFG_QCN_USE_HAI_EN,
	NBL_CFG_QCN_QUANTA_CC2TXP,
	/* rnic 400 */
	NBL_CFG_QCN_CLAMP_RT,
	NBL_CFG_QCN_ALPHA_G,
	NBL_CFG_QCN_ALPHA_T,
	NBL_CFG_QCN_ALPHA_RPG_RD,
	NBL_CFG_QCN_ECN_MODE,
	NBL_CFG_QCN_SMOOTH_PERIOD,
	NBL_CFG_QCN_SMOOTH_WEIGHT,
	NBL_CFG_QCN_ECN_KMIN,
	NBL_CFG_QCN_ECN_KMAX,
	NBL_CFG_QCN_ECN_PMAX,
	NBL_CFG_QCN_ECN_K,
	NBL_CFG_QCN_TXP_R_CNP_INVL,
	NBL_CFG_QCN_CNP_ACCOMPANIED,
	NBL_CFG_QCN_BTH_REDUCE_FLAG,
	NBL_CFG_CC_TYPE_MAX,
};

/*
 * ATTENTION: DON'T CHANGE ENUM ORDER!
 */
enum nbl_ib_qos_param_types {
	/* global */
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

	/* global */
	NBL_CFG_DWRR_EN,

	NBL_CFG_QOS_TYPE_MAX,
};

/* Packet Trim (PT) parameter types (independent of qos enum) */
enum nbl_ib_pt_param_types {
	NBL_CFG_PT_EN = 0,
	NBL_CFG_PT_CODE_TRIMMED,
	NBL_CFG_PT_CODE_TRIMMED_LAST,
	NBL_CFG_PT_CODE_TRIMMABLE,
	NBL_CFG_PT_CODE_CONTROL,
	NBL_CFG_PT_NAK_PRI_SAME_AS_CNP_EN,
	NBL_CFG_PT_TYPE_MAX,
};

struct nbl_pt_params {
	union nbl_pt_en_reg en;
	union nbl_pt_code_val_reg code;
};

#define NBL_PARAM_LEN 400

#define NBL_GET_PRI_FROM_T2P(_t2p, _pri)  (((_t2p) >> (3 * (_pri))) & 0x7)
#define NBL_SET_PRI_TO_T2P(_t2p, _tc, _pri) \
	do {	\
		u64 __mask = ~(0x7 << ((_tc) * 3));	\
		(_t2p) = ((_t2p) & __mask) | (((_pri) & 0x7) << ((_tc) * 3));	\
	} while (0)

struct nbl_dump_work {
	struct nbl_pci_f *rf;
	struct work_struct work;
	u32 qp_cq_ceq_id;
	u32 wqe_idx;
	u8  cmd_idx;
	u16 ae_id;
	u8 ae_src;
};

struct nbl_aeqe_info {
	u32 qp_cq_ceq_id;
	u32 wqe_idx;
	u8  cmd_idx;
	u16 ae_id;
	u8 ae_src;
	bool dump; /* whether dump */
	u8 seq_num;
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
	const struct nbl_lag_ops *lag_ops;
	void __iomem *hw_regs[NBL_MAX_REGS];
	struct nbl_sc_ceq **ceq;
	struct nbl_sc_aeq *aeq;
	int cc_dbgfs_params[NBL_CFG_CC_TYPE_MAX];
	int fundbg_params[NBL_FUN_DBG_TYPE_MAX];
	char qos_dbgfs_params[NBL_CFG_QOS_TYPE_MAX][NBL_PARAM_LEN];
	struct nbl_pt_params pt_params;
	u16 function_id;
	u16 pcie_fn_id;
	u8 pf_count;
	u16 dport_id;
	u8 dport;
	u8 fwd;
	u8 stat_id;
	u8 ackreq_th;
	u8 cc_mode;
	bool rss_lag_en;
	bool tunnel_en;
	bool nvme_fmr_en;
	bool local_rd_no_pkt;
	bool ddr_mode_en;
	bool dwqe_en; /* global en for direct wqe DF200/ASIC V2R1*/
	bool check_cc_param;
	__u32 debug_errcdoe;
	union rdma_tc_wgt_cfg_tbl tc_wgt;
	u64 tc2pri;
	u64 fw_ver;
	u64 mtu;
	u8 pmtu; /* 0- 256B, 1- 512B, 2- 1024B, 3- 2048B, 4- 4096B, 5- 8192B*/
	bool srp_en;
	bool srp_spray_en;
	bool mp_en; /* multi plane en for 4pf bond */
	bool muti_active_port; /* only for lag */
	u32 srp_nic_spray_val;
	u8 srp_srack_timer;
	u8 tlp_timer;
	u8 tlp_retry_th;
	u8 srp_epsn_rth;
	u32 srp_ext_bmp_qpn_max;
	u64 qpn_interval;
	bool cem_enable; /* completion event moderation */
	bool write_atomic_fence; /* rxm write + atomic nofence en */
};

struct nbl_device_init_info {
	struct nbl_hw *hw;
	void __iomem *bar0;
};

struct nbl_modify_cq_info {
	struct nbl_buf_desc bdes;
	struct nbl_cqe *cq_base; /* 0 level: queue va or NULL, 1 level: PD VA */
	u64 cq_base_pa; /* 0 level: queue pa, 1 level: PD PA */
	u32 cq_size;
	u32 shadow_rd_thd;
};

struct nbl_sc_cq {
	struct nbl_cq_uk cq_uk;
	u64 cqc_begin_pa; /* CQC base PA */
	u64 shadow_area_pa; /* shadow area, PA */
	struct nbl_sc_dev *dev;
	u32 ceq_id;
	void *bak_nbl_cq; /* point to struct nbl_cq */
	bool cq_cc; /* if set, CQE is writted to first CQ entry */
};

#endif /* NBL_IB_TYPE_H */
