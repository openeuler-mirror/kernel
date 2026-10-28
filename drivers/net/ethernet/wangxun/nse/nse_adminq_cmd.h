/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_ADMINQ_CMD_H
#define _NSE_ADMINQ_CMD_H

/* This header file defines the Admin Queue commands, error codes and
 * descriptor format. It is shared between Firmware and Software.
 */

#if !defined(NSE_AQ_MAX_FV_WORDS)
#define NSE_AQ_MAX_FV_WORDS 64 /*max field vector config regs in adminq cmd*/
#endif

#if !defined(ETH_ALEN)
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#endif

#define NSE_MAX_TRAFFIC_CLASS	8

/* this is static max-max value, sometimes should use nse_hw_conf->max_vsi_space */
#define NSE_MAX_VSI		256

#define NSE_AQ_SET_MAC_FRAME_SIZE_MAX	9018

#define NSE_AQ_LINK_UP			BIT(0)	/* Link Status */

#define NSE_AQ_LINK_SPEED_UNKNOWN	0
#define NSE_AQ_LINK_SPEED_10MB		BIT(0)
#define NSE_AQ_LINK_SPEED_100MB		BIT(1)
#define NSE_AQ_LINK_SPEED_1000MB	BIT(2)
#define NSE_AQ_LINK_SPEED_2500MB	BIT(3)
#define NSE_AQ_LINK_SPEED_5GB		BIT(4)
#define NSE_AQ_LINK_SPEED_10GB		BIT(5)
#define NSE_AQ_LINK_SPEED_20GB		BIT(6)
#define NSE_AQ_LINK_SPEED_25GB		BIT(7)
#define NSE_AQ_LINK_SPEED_40GB		BIT(8)
#define NSE_AQ_LINK_SPEED_50GB		BIT(9)
#define NSE_AQ_LINK_SPEED_100GB		BIT(10)
#define NSE_AQ_LINK_SPEED_200GB		BIT(11)
#define NSE_AQ_LINK_SPEED_400GB		BIT(12)
#define NSE_AQ_LINK_SPEED_800GB		BIT(13)

struct nse_aq_desc {
	__le16 flags;
/* command flags and offsets */
#define NSE_AQ_FLAG_DD_S	0
#define NSE_AQ_FLAG_DD		BIT(0)

#define NSE_AQ_FLAG_RETVAL_S	1
#define NSE_AQ_FLAG_RETVAL_M	NSE_M(0x7F, 1)

#define NSE_AQ_FLAG_WB_S	8
#define NSE_AQ_FLAG_WB		BIT(8)

#define NSE_AQ_FLAG_LB_S	9
#define NSE_AQ_FLAG_LB		BIT(9)

#define NSE_AQ_FLAG_RD_S	10
#define NSE_AQ_FLAG_RD		BIT(10)

#define NSE_AQ_FLAG_BUF_S	12
#define NSE_AQ_FLAG_BUF		BIT(12)

#define NSE_AQ_FLAG_SI_S	13
#define NSE_AQ_FLAG_SI		BIT(13)

#define NSE_AQ_FLAG_EI_S	14
#define NSE_AQ_FLAG_EI		BIT(14)

#define NSE_AQ_FLAG_FE_S	15
#define NSE_AQ_FLAG_FE		BIT(15)

	union {
		__le16 opcode;
		struct {
			u8 opc_subcode;
			u8 opc_category;
		};
	};
#define MAKE_AQC_OPCODE(category, subcode) (((category) << 8) | (subcode))

	__le16 datalen;

	__le16 mailbox_id;	/* bits: 6.0-7.0 + 7.1~7.7(reserved) */
#define NSE_AQ_MAILBOX_ID_S		0
#define NSE_AQ_MAILBOX_ID_M		NSE_M(0x1FF, 0)

#define NSE_AQ_MAILBOX_ID_VSI_MAX	0x100	/* MUST < 256 */

#define NSE_AQ_MAILBOX_ID_PF	0x100		/* special ID, indicates: VF to parent PF */
#define NSE_AQ_MAILBOX_ID_UTILQ	0x1FE	/* special ID, indicates: to AQM utilQ, then to RPP RCF */
#define NSE_AQ_MAILBOX_ID_FW	0x1FF		/* special ID, indicates, PF to FW */

	union {
		__le32 addr_high;
		__le32 param0;
	};
	union {
		__le32 addr_low;
		__le32 param1;
	};
} __packed;

/* FW defined boundary for a large buffer, 4k >= Large buffer > 512 bytes */
#define NSE_AQ_LG_BUF	512

/* error codes */
enum nse_aq_err {
	NSE_AQ_RC_OK		= 0,	/* Success */

	NSE_AQ_RC_EIO,				/* I/O error */
	NSE_AQ_RC_EINVAL,			/* Invalid argument */
	NSE_AQ_RC_ERANGE,			/* Parameter out of range */
	NSE_AQ_RC_EPERM,			/* Operation not permitted */
	NSE_AQ_RC_EFAULT,			/* Bad address */
	NSE_AQ_RC_ENOENT,			/* No such element */
	NSE_AQ_RC_EEXIST,			/* Object already exists */

	NSE_AQ_RC_EAGAIN,			/* Try again */
	NSE_AQ_RC_EBUSY,			/* Device or resource busy */
	NSE_AQ_RC_ETIMEOUT = NSE_AQ_RC_EBUSY,

	NSE_AQ_RC_EINPROGRESS,

	NSE_AQ_RC_ENOMEM,			/* Out of memory */
	NSE_AQ_RC_ENOSPC,			/* No space left or allocation failure */

	NSE_AQ_RC_ENOTSUPP,
	NSE_AQ_RC_EBADOP = NSE_AQ_RC_ENOTSUPP,

	/*************************************
	 *
	 * the range [96 - 127] starting from here.
	 *
	 ***************************************/

	NSE_AQ_RC_EACCES_FW_IN_UPDATE		= 127, /* FW live Update in progress */
};

struct nse_aqc_generic_common_hdr {
	u8 magic;
	u8 pad_0[3];

	u8 pcore_id;
	u8 pcore_pf_id;

	u8 dma_id;
	u8 dma_pf_id;

	u8 chan_id;
	u8 chan_pf_id;

	u8 lan_id;
	u8 pad_1[1];

	__le16 vsi_abs_id;
	__le16 vsp_abs_id;

} __packed;
struct nse_aqc_xchg_ver_sw_ver {
	u8 major_ver;
	u8 minor_ver;
	u8 mini_ver;
	u8 patch_ver;
	__le32 build_ver;
	__le32 sw_drv_type;
} __packed;

/* Definitions for sw_type (but FW may not care):
 */
#define NSE_SW_DRV_TYPE_LINUX	0x0		/* nse-linux */
#define NSE_SW_DRV_TYPE_DPDK	0x1		/* nse-dpdk */

struct nse_aqc_xchg_ver_fw_ver {
	u8 major_ver;
	u8 minor_ver;
	u8 mini_ver;
	u8 build_ver;

	u8 private_major_ver;
	u8 private_minor_ver;
	u8 private_mini_ver;
	u8 private_build_ver;
} __packed;

struct nse_aqc_xchg_sw_fw_ver {
	union {
		struct nse_aqc_xchg_ver_sw_ver sw_ver;		/* set by SW, read by FW */
		struct nse_aqc_xchg_ver_fw_ver fw_ver;		/* writeback by FW, read by SW */
	};

	/* if FW think can not support this SW by version, then set it to true to tell SW */
	__le32 refused_by_fw;

} __packed;

struct nse_aqc_discover_cap_elem {
	__le16 cap_id;		/* capability ID */

	u8 major_ver;	/* currently, not used at all. */
	u8 minor_ver;

	union {
		struct {
			__le32 val0;	/* depending on specific capability */
			__le32 val1;
			__le32 val2;
		} __packed;

		struct {
			__le32 val32;
			__le32 val64;
		} __packed;
	};

} __packed;

enum nse_pf_type {
	NSE_PF_TYPE_NORMAL				= 0,

	NSE_PF_TYPE_MH_DPU_PRIMARY	= 1,

	NSE_PF_TYPE_MH_DPU_SECONDARY = 2,

	NSE_PF_TYPE_MAX,
};

enum nse_aqc_discover_cap_elem_id {
	NSE_AQC_CAP_ID_BASIC			= 0,

	NSE_AQC_CAP_ID_VSI_SPACE,

	NSE_AQC_CAP_ID_LANRXQ_SPACE,

	NSE_AQC_CAP_ID_LANTXQ_SPACE,

	NSE_AQC_CAP_ID_IRQ_SPACE,

	NSE_AQC_CAP_ID_VF_SPACE,

	NSE_AQC_CAP_ID_LAN_TX_CQ_SPACE,

	NSE_AQC_CAP_ID_RDMA_QSET_SPACE,

	NSE_AQC_CAP_ID_HW_PLATFORM,

	NSE_AQC_CAP_ID_LINK_TYPES_SPEEDS,

	NSE_AQC_CAP_ID_MAX,
};

struct nse_aqc_discover_func_caps {
	__le32 count;
	struct nse_aqc_discover_cap_elem caps[];

} __packed;

struct nse_aqc_set_unset_sriov_res {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 vf_vsialloc_firstvsi;
	u8 pad_0[2];

	__le16 vf_rx_qbase_firstq;
	__le16 vf_rx_qbase_numq;

	__le16 vf_tx_qbase_firstq;
	__le16 vf_tx_qbase_numq;

	__le16 vfint_alloc_first;
	__le16 vfint_alloc_vecnum;

} __packed;

struct nse_aqc_vflr_event {
	u8 pcore_id;
	u8 pad[3];

	__le32 vf_flr[8];

} __packed;

struct nse_aqc_vflr_event_mini {
	u8 pcore_id;
	u8 pcore_pf_id;
	u8 vf_abs_id;
	u8 pad;
} __packed;

struct nse_aqc_conf_irqll {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 flags;
#define NSE_AQC_CONF_IRQLL_FLAG_RESET_MANY	BIT(0)

	__le16 qid;

	u8 qtype;
#define NSE_AQC_CONF_IRQLL_QTYPE_LAN_TXQ	0x0
#define NSE_AQC_CONF_IRQLL_QTYPE_LAN_RXQ	0x1
#define NSE_AQC_CONF_IRQLL_QTYPE_LAN_CQ		0x2
#define NSE_AQC_CONF_IRQLL_QTYPE_AQM		0x3

	u8 op;
#define NSE_AQC_CONF_IRQLL_OP_ADD			0x0
#define NSE_AQC_CONF_IRQLL_OP_DEL			0x1
#define NSE_AQC_CONF_IRQLL_OP_RESET			0x2
#define NSE_AQC_CONF_IRQLL_OP_FLUSH			0x3

	__le16 msix;
#define NSE_AQC_CONF_IRQLL_INVALID_MSIX		0xFFFF

	u8 conf_result;

	u8 pad0;

	__le16 msix_first;
	__le16 msix_last;
};

struct nse_aqc_ddp {
	__le32 flags;

	__le32 data_len;

	u8 data[];

} __packed;

enum nse_aqc_man_mac_addr_type {
	NSE_AQC_MAN_MAC_ADDR_TYPE_FACTORY	= 0,

	NSE_AQC_MAN_MAC_ADDR_TYPE_LMAC,

	NSE_AQC_MAN_MAC_ADDR_TYPE_WOL,

	NSE_AQC_MAN_MAC_ADDR_TYPE_MAX,
};

struct nse_aqc_manage_mac_item {
	u8 mac_addr[ETH_ALEN];
} __packed;

struct nse_aqc_manage_mac {
	u8 lan_id;
	u8 wol_mpe;
	__le16 wflags;
#define NSE_AQC_MAN_MAC_WFLAG_UPDATE_LMAC_ADDR		BIT(0)
#define NSE_AQC_MAN_MAC_WFLAG_UPDATE_WOL_ADDR		BIT(1)
#define NSE_AQC_MAN_MAC_WFLAG_UPDATE_WOL_MPE		BIT(2)

	struct nse_aqc_manage_mac_item addrs[NSE_AQC_MAN_MAC_ADDR_TYPE_MAX];
} __packed;

struct nse_aqc_ptp_get_set_adj_sys_time_amber {
	u8 lan_id;
	u8 pad[3];
	__le32 sec;
	__le32 nsec;
} __packed;

struct nse_aqc_ptp_get_set_adj_sys_time_ms {
	u8 lan_id;
	u8 pad[3];
	__le32 val_h;
	__le32 val_l;
} __packed;

struct nse_aqc_ptp_get_set_adj_sys_time {
	union {
		u8 lan_id;
		struct nse_aqc_ptp_get_set_adj_sys_time_amber amber;
		struct nse_aqc_ptp_get_set_adj_sys_time_ms ms;
	};
} __packed;

struct nse_aqc_ptp_get_set_corr {
	u8 lan_id;
	u8 pad[3];
	__le32 ingress_corr_nsec;
	__le32 ingress_corr_subsec;
	__le32 egress_corr_nsec;
	__le32 egress_corr_subsec;
} __packed;

struct nse_aqc_ptp_init_amber {
	u8 lan_id;
	u8 pad;
	__le16 flags;
#define AMBER_AQC_PTP_INIT_UPDATE_CORR	0x1
	__le32 sec;
	__le32 nsec;

	__le32 control;
#define AMBER_AQC_PTP_CONTROL_TXTSSTSM	BIT(24)
#define AMBER_AQC_PTP_CONTROL_TSCTRLSSR	BIT(9)
#define AMBER_AQC_PTP_CONTROL_TSENALL		BIT(8)
#define AMBER_AQC_PTP_CONTROL_TSUPDT		BIT(3)
#define AMBER_AQC_PTP_CONTROL_TSINIT		BIT(2)
#define AMBER_AQC_PTP_CONTROL_TSCFUPDT	BIT(1)
#define AMBER_AQC_PTP_CONTROL_TSENA		BIT(0)

	__le32 incval;
	__le32 addend;
	__le32 ingress_corr_nsec;
	__le32 ingress_corr_subsec;
	__le32 egress_corr_nsec;
	__le32 egress_corr_subsec;

	__le32 rdm_rx_ts_en;
	__le32 rpp_rx_ts_en;
#define RDM_RX_TS_EN_BIT	BIT(9)
#define RPP_RX_TS_EN_BIT	BIT(0)

} __packed;

struct nse_aqc_ptp_init_ms {
	u8 lan_id;
	u8 pad[3];

	__le32 systime_l;
	__le32 systime_h;

	__le32 inc;
#define MS_AQC_PTP_INC_PERIOD_S	24
#define MS_AQC_PTP_INC_PERIOD_M	NSE_M(0xFF, 24)

#define MS_AQC_PTP_INC_VAL_S		0
#define MS_AQC_PTP_INC_VAL_M		NSE_M(0xFFFFFF, 0)

	__le32 rdm_rx_ts_en;
	__le32 rpp_rx_ts_en;

} __packed;

struct nse_aqc_ptp_init {
	union {
		u8 lan_id;
		struct nse_aqc_ptp_init_amber amber;
		struct nse_aqc_ptp_init_ms ms;
	};
} __packed;

struct nse_aqc_ptp_tx_ts {
	__le32 tx_ts_low;
	__le32 tx_ts_high;
} __packed;

struct nse_aqc_ptp_rd_clr_tx_ts {
	u8 lan_id;
	u8 reg_idx;
#define NSE_AQC_PTP_TX_TS_ALL_REG	0xFF
	u8 pad[2];

	struct nse_aqc_ptp_tx_ts tx_ts;
} __packed;

struct nse_aqc_ptp_tx_ts_event {
	u8 lan_id;	/* reg_eth_mac[0,1,2,3 ] */
	u8 pad[3];

	__le32 tx_ts_vld_l;
	__le32 tx_ts_vld_h;

	struct nse_aqc_ptp_tx_ts tx_ts[];
} __packed;

struct nse_aqc_ptp_rw_tx_ts_report_method {
	u8 lan_id;	/* reg_eth_mac[0,1,2,3 ] */
	u8 pad[3];

	u8 rw;	/* 0 for read, 1 for write */
	u8 report_method;
#define NSE_AQC_PTP_TX_TS_REPORT_METHOD_AQ		0x0
#define NSE_AQC_PTP_TX_TS_REPORT_METHOD_FWMNG	0x1

	u8 pad_2[2];
} __packed;

#define NSE_AQC_SCHED_LAYER_MAX_NUM		16

#define NSE_SCHED_DUMMY_TNID 0x0
#define NSE_SCHED_INVAL_TNID 0xFFFFFFFF

enum nse_aqc_psr_ctrl_type {
	NSE_AQC_PSR_CTRL_TYPE_TS_ET,			/* ts_et_ctrl */
	NSE_AQC_PSR_CTRL_TYPE_MPLS_ALT,		/* mpls_alt */
	NSE_AQC_PSR_CTRL_TYPE_GRE,				/* gre_ctrl */
	NSE_AQC_PSR_CTRL_TYPE_VXLAN_UDP,		/* vxlan_udp_ctrl */
	NSE_AQC_PSR_CTRL_TYPE_ALIVXLAN_UDP,	/* alivxlan_udp_ctrl */
	NSE_AQC_PSR_CTRL_TYPE_VXLAN_GPE_UDP,	/* gpe_udp_ctrl */
	NSE_AQC_PSR_CTRL_TYPE_GENEVE_UDP,		/* geneve_udp_ctrl */
	NSE_AQC_PSR_CTRL_TYPE_MPLS_UDP,		/* mpls_udp_ctrl */
	/* Note, roce_udp is not here, should be handle by RoCE-specific aq-cmd, but not this one */
	NSE_AQC_PSR_CTRL_TYPE_TS_UDP,			/* ts_udp_ctrl */
	NSE_AQC_PSR_CTRL_TYPE_NSH,				/* nsh_ctrl */
	NSE_AQC_PSR_CTRL_TYPE_RFC1071,			/* rfc1071_ctrl, only in RPSR*/

	NSE_AQC_PSR_CTRL_TYPE_MAX,
};

struct nse_aqc_psr_set_ctrl {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 flags;
#define NSE_AQC_PSR_SET_CTRL_FLAG_RPSR	BIT(0)
#define NSE_AQC_PSR_SET_CTRL_FLAG_TPSR	BIT(1)

	u8 ctrl_type;
	u8 dis_or_en;
	__le16 port_or_etype;
} __packed;

struct nse_aqc_hw_lag_remap {
	u8 remap_port[2];
} __packed;

struct nse_aqc_hw_lag_hash_entry {
	u8 entry_idx;
	u8 dst_port;
} __packed;

struct nse_aqc_hw_lag_hash_tbl {
	u8 hash_type;
#define NSE_AQC_HW_LAG_HASH_L2_TYPE	BIT(0)
#define NSE_AQC_HW_LAG_HASH_L23_TYPE	BIT(1)
#define NSE_AQC_HW_LAG_HASH_L34_TYPE	BIT(2)
#define NSE_AQC_HW_LAG_HASH_E23_TYPE	BIT(3)
#define NSE_AQC_HW_LAG_HASH_E34_TYPE	BIT(4)
	u8 rsvd;
	__le16 vld_entries;
	struct nse_aqc_hw_lag_hash_entry entry[256];
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_HW_LAG
 *  struct for cmd: NSE_AQ_OPC_UPDATE_HW_LAG
 *  struct for cmd: NSE_AQ_OPC_REMOVE_HW_LAG
 *  struct for cmd: NSE_AQ_OPC_GET_HW_LAG
 */
struct nse_aqc_hw_lag_cfg {
	u8 lag_id;
	u8 lan_port_num;
	u8 lan_id[4];
	u8 tx_type; /*active_backup:0; hash: 1*/
#define NSE_AQC_LAG_TX_TYPE_ACT_BKUP 0
#define NSE_AQC_LAG_TX_TYPE_HASH	 1
	union {
		struct nse_aqc_hw_lag_remap remap;
		struct nse_aqc_hw_lag_hash_tbl hash_tbl;
	} tbl;
} __packed;

/*  struct for cmd: NSE_AQ_OPC_HW_LAG_CFG_DROP
 */
struct nse_aqc_hw_lag_cfg_drop {
	__le16 lan_id;
	__le16 drop_en; /*1: enable rx drop; 0: disable rx drop*/
} __packed;

/* CEE or IEEE 802.1Qaz ETS Configuration data */
struct nse_dcb_ets_cfg {
	u8 willing;
	u8 cbs;
	u8 maxtcs;
	u8 prio_table[NSE_MAX_TRAFFIC_CLASS];
	u8 tcbwtable[NSE_MAX_TRAFFIC_CLASS];
	u8 tsatable[NSE_MAX_TRAFFIC_CLASS];
} __packed;

/* CEE or IEEE 802.1Qaz PFC Configuration data */
struct nse_dcb_pfc_cfg {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcena;
} __packed;

struct nse_dcbx_cfg {
	struct nse_dcb_ets_cfg etscfg;
	struct nse_dcb_ets_cfg etsrec;
	struct nse_dcb_pfc_cfg pfc;
} __packed;

struct nse_aqc_qos_db_rpb_stat_cnt_amber {
	/* reg_rpb_rana[0, 1, 2, 3] /stat */
	__le32 rpb_stat;
	__le32 rpb_pb_sz_used[8];
	__le32 rpb_tc_share_sz_used[8];
	__le32 rpb_share_sz_used;
	__le32 rpb_global_sz_used;
	__le32 rpb_exist_pkt_cnt[8];
	__le32 rpb_pb_linklist_ptr[8];
	__le32 rpb_fbcb_linklist_ptr;
	__le32 rpb_tc_tail_stat1[8];
	__le32 rpb_tc_tail_stat2[8];

	/* reg_rpb_rana[0, 1, 2, 3] /cnt */
	__le32 rpb_rx_pkt[8];
	__le32 rpb_miss_pkt[8];
} __packed;

struct nse_aqc_qos_db_rdb_stat_cnt_amber {
	/* reg_rdb[0, 1] /stat */
	__le32 rdb_stat;
	__le32 rdb_pb_sz_used;
	__le32 rdb_exist_pkt_cnt;
	__le32 rdb_exist_mpo_cnt;
	__le32 rdb_pb_linklist_ptr;
	__le32 rdb_fbcb_linklist_ptr;
	__le32 rdb_inter_buf_stat;

	/* reg_rdb[0, 1] /cnt */
	__le32 rdb_rx_pkt;
	__le32 rdb_drp_pkt;
	__le32 rdb_miss_pkt;
} __packed;

struct nse_aqc_qos_db_tdb_stat_cnt_amber {
	/* reg_tdb[0, 1] /stat */
	__le32 tdb_stat;
	__le32 tdb_pb_sz_used[32];
	__le32 tdb_tc_share_sz_used[32];
	__le32 tdb_share_sz_used;
	__le32 tdb_exist_pkt_cnt[32];
	__le32 tdb_exist_mpo_cnt[32];
	__le32 tdb_pb_linklist_ptr[32];
	__le32 tdb_fbcb_linklist_ptr;

	/* reg_tdb[0, 1] /cnt */
	__le32 tdb_rx_pkt[32];
} __packed;

struct nse_aqc_qos_db_trt_stat_cnt_amber {
	/* reg_trt[0, 1] /stat */
	__le32 trt_stat;
	__le32 trt_pb_sz_used[17];
	__le32 trt_tc_share_sz_used[17];
	__le32 trt_share_sz_used;
	__le32 trt_exist_pkt_cnt[17];
	__le32 trt_pb_linklist_ptr[17];
	__le32 trt_fbcb_linklist_ptr;
	__le32 trt_rfcs;
	__le32 trt_frsz_ctl_stat;
	__le32 trt_frsz_ctl_stat1;
	__le32 trt_tx_ctl_stat;
	__le32 trt_pkt_rel_stat;

	/* reg_trt[0, 1] /cnt */
	__le32 out_pkt[2];
	__le32 lpbk_pkt;
	__le32 mng_pkt;
	__le32 lpbk_drp_pkt;
	__le32 mng_drp_pkt;
	__le32 mng_oversz_drp_pkt;
	__le32 nodst_drp_pkt;
	__le32 mpos_drp_pkt;
	__le32 flush_drp_pkt[16];

} __packed;

struct nse_aqc_qos_db_stat_cnt_amber {
	struct nse_aqc_generic_common_hdr hdr;

	struct nse_aqc_qos_db_rpb_stat_cnt_amber rpb[4];
	struct nse_aqc_qos_db_rdb_stat_cnt_amber rdb[2];
	struct nse_aqc_qos_db_tdb_stat_cnt_amber tdb[2];
	struct nse_aqc_qos_db_trt_stat_cnt_amber trt[2];

} __packed;

struct nse_aqc_qos_db_rpb_stat_cnt_ms {
	/* reg_rpb0 /buffer_stat, stat, cnt */

	__le32 port_global_used;
	__le32 port_share_used;
	__le32 tc_share_used[8];
	__le32 tc_dedicate_used[8];

	__le32 rpb_stat;
	__le32 tc_pfc_stat;
	__le32 rpb_fifo_stat1;
	__le32 tc_linklist_ptr[8];
	__le32 free_linklist_ptr;

	__le32 rpb_exist_cnt[9];
	__le32 rpb_rx_cnt[9];
	__le32 rpb_mcast_cnt[9];
	__le32 rpb_miss_cnt[9];

} __packed;

struct nse_aqc_qos_db_rdb_stat_cnt_ms {
	/* reg_rdb0 / stat, cnt */

	__le32 rdb_stat;
	__le32 rdb_pb_sz_used;
	__le32 rdb_exist_pkt_cnt;
	__le32 rdb_exist_mpo_cnt;
	__le32 rdb_pb_linklist_ptr;
	__le32 rdb_fbcb_linklist_ptr;

	__le32 rdb_rx_pkt;
	__le32 rdb_drp_pkt;
	__le32 rdb_miss_pkt;

} __packed;

struct nse_aqc_qos_db_tdb_stat_cnt_ms {
	/* reg_tdb0 / stat, cnt */

	__le32 tdb_stat;
	__le32 tdb_pb_sz_used[8];
	__le32 tdb_tc_share_sz_used[8];
	__le32 tdb_share_sz_used;
	__le32 tdb_exist_pkt_cnt[8];
	__le32 tdb_exist_mpo_cnt[8];
	__le32 tdb_pb_linklist_ptr[8];
	__le32 tdb_fbcb_linklist_ptr;

	__le32 tdb_rx_pkt[8];
} __packed;

struct nse_aqc_qos_db_stat_cnt_ms {
	struct nse_aqc_generic_common_hdr hdr;

	struct nse_aqc_qos_db_rpb_stat_cnt_ms rpb;
	struct nse_aqc_qos_db_rdb_stat_cnt_ms rdb;
	struct nse_aqc_qos_db_tdb_stat_cnt_ms tdb;

} __packed;

struct nse_aqc_qos_db_stat_cnt {
	union {
		struct nse_aqc_generic_common_hdr hdr;	/* common header to amber and ms */
		struct nse_aqc_qos_db_stat_cnt_amber amber;
		struct nse_aqc_qos_db_stat_cnt_ms ms;
	};

} __packed;

struct nse_aqc_qos_db_cfg_amber {
	struct nse_aqc_generic_common_hdr hdr;

	u8 eth_grp_id;	/* currently not used, unless we do HW-bond */
	u8 pad[3];

	__le32	rpb_pb_ctl_vld;
	__le32	rpb_pb_ctl_value;
#define RPB_PB_CTL_EN_S				0
#define RPB_PB_CTL_EN_M				BIT(0)

#define RPB_PB_CTL_RST_S			8
#define RPB_PB_CTL_RST_M			BIT(8)

#define RPB_PB_CTL_OVFL_EN_S		24
#define RPB_PB_CTL_OVFL_EN_M		NSE_M(0xFF, 24)

	__le32	rpb_pb_sz_vld;
	__le32	rpb_pb_sz_value[8];
#define RPB_PB_SZ_SIZE_S			10
#define RPB_PB_SZ_SIZE_M			NSE_M(0x3FF, 10)

	__le32	rpb_share_sz_vld;
	__le32	rpb_share_sz_value;
#define RPB_SHARE_SZ_SIZE_S			10
#define RPB_SHARE_SZ_SIZE_M			NSE_M(0x3FF, 10)

	__le32	rpb_pbrarb_ctl_vld;
	__le32	rpb_pbrarb_ctl_value;
#define RPB_PBRARB_CTL_RPPAC_S		4
#define RPB_PBRARB_CTL_RPPAC_M		BIT(4)

	#define RPB_PBRARB_CTL_RPPAC_WRR	0
	#define RPB_PBRARB_CTL_RPPAC_WSP	1

	__le32	rpb_pbrarb_credit_vld;
	__le32	rpb_pbrarb_credit_value[8];
#define RPB_PBRARB_CREDIT_VAL_S		0
#define RPB_PBRARB_CREDIT_VAL_M		NSE_M(0xFFF, 0)

	#define RPB_PBRARB_CREDIT_VAL_SP_MAX	0xFFF
	#define RPB_PBRARB_CREDIT_VAL_SP_MIN	0x3FF
	#define RPB_PBRARB_CREDIT_VAL_ETS_TOTAL	0x7FF

	__le32	rpb_ovfl_time_vld;
	__le32	rpb_ovfl_time_value;
#define RPB_OVFL_TIME_INIT_S		0
#define RPB_OVFL_TIME_INIT_M		NSE_M(0xFFFFFFF, 0)

	__le32	rpb_dhw_vld;
	__le32	rpb_dhw_value[8];
#define RPB_WM_THRES_VAL_S			4
#define RPB_WM_THRES_VAL_M			NSE_M(0xFFFF, 4)

	__le32	rpb_dlw_vld;
	__le32	rpb_dlw_value[8];

	__le32	rpb_sht_vld;
	__le32	rpb_sht_value[8];

	__le32	rpb_slt_vld;
	__le32	rpb_slt_value[8];

	__le32	rpb_shw_vld;
	__le32	rpb_shw_value;

	__le32	rpb_slw_vld;
	__le32	rpb_slw_value;

	__le32	rpb_ghw_vld;
	__le32	rpb_ghw_value;

	__le32	rpb_glw_vld;
	__le32	rpb_glw_value;

	__le32	rpb_up2tc_vld;
	__le32	rpb_up2tc_value;
#define RPB_UP2TC_PER_TC_SHIFT		4

	__le32	rpb_tc2pfc_vld;
	__le32	rpb_tc2pfc_value;

	__le32	rpb_lltc_vld;
	__le32	rpb_lltc_value;
#define RPB_LLTC_MAP_S				0
#define RPB_LLTC_MAP_M				NSE_M(0xFF, 0)

	__le32	rdb_pb_ctl_vld;
	__le32	rdb_pb_ctl_value;
#define RDB_PB_CTL_EN_S				0
#define RDB_PB_CTL_EN_M				BIT(0)

#define RDB_PB_CTL_RST_S			8
#define RDB_PB_CTL_RST_M			BIT(8)

	__le32	rdb_pbwarb_ctl_vld;
	__le32	rdb_pbwarb_ctl_value;
#define RDB_PBWARB_CTL_RPPAC_S			4
#define RDB_PBWARB_CTL_RPPAC_M			BIT(4)

	#define RDB_PBWARB_CTL_RPPAC_WRR	0
	#define RDB_PBWARB_CTL_RPPAC_WSP	1

	__le32	rdb_pbwarb_credit_vld;
	__le32	rdb_pbwarb_credit_value[2];
#define RDB_PBWARB_CREDIT_VAL_S		0
#define RDB_PBWARB_CREDIT_VAL_M		NSE_M(0x7FF, 0)

	#define RDB_PBWARB_CREDIT_VAL_MAX		0x7FF
	#define RDB_PBWARB_CREDIT_VAL_INIT		0x200
	#define RDB_PBWARB_CREDIT_VAL_DFLT		0x7FF

	__le32	rdb_pbrarb_ctl_vld;
	__le32	rdb_pbrarb_ctl_value;
#define RDB_PBRARB_CTL_RPPAC_S			4
#define RDB_PBRARB_CTL_RPPAC_M			BIT(4)

	#define RDB_PBRARB_CTL_RPPAC_WRR		0
	#define RDB_PBRARB_CTL_RPPAC_WSP		1

#define RDB_PBRARB_CTL_WSP_PRI_S		5
#define RDB_PBRARB_CTL_WSP_PRI_M		BIT(5)

	#define RDB_PBRARB_CTL_WSP_PRI_PACKET		0
	#define RDB_PBRARB_CTL_WSP_PRI_MINIPO		1

	__le32	rdb_pbrarb_credit_vld;
	__le32	rdb_pbrarb_credit_value[7];
#define RDB_PBRARB_CREDIT_VAL_S		0
#define RDB_PBRARB_CREDIT_VAL_M		NSE_M(0x7FF, 0)

	#define RDB_PBRARB_CREDIT_VAL_MAX		0x7FF
	#define RDB_PBRARB_CREDIT_VAL_INIT		0x200
	#define RDB_PBRARB_CREDIT_VAL_DFLT		0x7FF

	__le32	tdb_pb_ctl_vld;
	__le32	tdb_pb_ctl_value;

#define TDB_PB_CTL_RST_S			8
#define TDB_PB_CTL_RST_M			BIT(8)

#define TDB_PB_CTL_EN_S				0
#define TDB_PB_CTL_EN_M				BIT(0)

	__le32	tdb_pb_sz_vld;
	__le32	tdb_pb_sz_egrps_bitmap;
	__le32	tdb_pb_sz_egrps_values[4][8];

#define TDB_PB_SZ_SIZE_S			10
#define TDB_PB_SZ_SIZE_M			NSE_M(0x3FF, 10)

	__le32	tdb_share_sz_vld;
	__le32	tdb_share_sz_value;

	__le32	tdb_sht_vld;
	__le32	tdb_sht_egrps_bitmap;
	__le32	tdb_sht_egrps_values[4][8];
#define TDB_SHT_SIZE_S				5
#define TDB_SHT_SIZE_M				NSE_M(0x7FFF, 5)

	__le32	tdb_pbwarb_credit_vld;
	__le32	tdb_pbwarb_credit_value[2];
#define TDB_PBWARB_CREDIT_VAL_S			0
#define TDB_PBWARB_CREDIT_VAL_M			NSE_M(0x7FF, 0)

	#define TDB_PBWARB_CREDIT_VAL_MAX		0x7FF
	#define TDB_PBWARB_CREDIT_VAL_INIT		0x200
	#define TDB_PBWARB_CREDIT_VAL_DFLT		0x7FF

	__le32	tdb_pbrarb_ctl_vld;
	__le32	tdb_pbrarb_ctl_value;
#define TDB_PBRARB_CTL_WSP_PRI_S	5
#define TDB_PBRARB_CTL_WSP_PRI_M	BIT(5)

	#define TDB_PBRARB_CTL_WSP_PRI_PACKET	0
	#define TDB_PBRARB_CTL_WSP_PRI_MINIPO	1

#define TDB_PBRARB_CTL_RPPAC4_S		4
#define TDB_PBRARB_CTL_RPPAC4_M		BIT(4)

#define TDB_PBRARB_CTL_RPPAC3_S		3
#define TDB_PBRARB_CTL_RPPAC3_M		BIT(3)

#define TDB_PBRARB_CTL_RPPAC2_S		2
#define TDB_PBRARB_CTL_RPPAC2_M		BIT(2)

#define TDB_PBRARB_CTL_RPPAC1_S		1
#define TDB_PBRARB_CTL_RPPAC1_M		BIT(1)

#define TDB_PBRARB_CTL_RPPAC0_S		0
#define TDB_PBRARB_CTL_RPPAC0_M		BIT(0)

	#define TDB_PBRARB_CTL_RPPAC_WRR		0
	#define TDB_PBRARB_CTL_RPPAC_WSP		1

	__le32	tdb_pbrarb_credit_vld;
	__le32	tdb_pbrarb_credit_value[4];

#define TDB_PBRARB_CREDIT_VAL_S		0
#define TDB_PBRARB_CREDIT_VAL_M		NSE_M(0x7FF, 0)

	#define TDB_PBRARB_CREDIT_VAL_MAX		0x7FF
	#define TDB_PBRARB_CREDIT_VAL_INIT		0x200
	#define TDB_PBRARB_CREDIT_VAL_DFLT		0x7FF

	__le32	tdb_tcpbrarb_credit_vld;
	__le32	tdb_tcpbrarb_credit_egrps_bitmap;
	__le32	tdb_tcpbrarb_credit_egrps_values[4][8];

#define TDB_TCPBRARB_CREDIT_VAL_S	0
#define TDB_TCPBRARB_CREDIT_VAL_M	NSE_M(0x7FF, 0)

	#define TDB_TCPBRARB_CREDIT_VAL_MAX			0x7FF
	#define TDB_TCPBRARB_CREDIT_VAL_INIT		0x200
	#define TDB_TCPBRARB_CREDIT_VAL_DFLT		0x7FF

	__le32	trt_ctl_vld;
	__le32	trt_ctl_value;
#define TRT_CTL_TDB_PLD_REQ_CROSS_CHK_EN_S			25
#define TRT_CTL_TDB_PLD_REQ_CROSS_CHK_EN_M			BIT(25)

#define TRT_CTL_LINKSEC_EN_S			24
#define TRT_CTL_LINKSEC_EN_M			BIT(24)

#define TRT_CTL_MNG_DRP_EN_S			17
#define TRT_CTL_MNG_DRP_EN_M			BIT(17)

#define TRT_CTL_LPBK_DRP_EN_S			16
#define TRT_CTL_LPBK_DRP_EN_M			BIT(16)

/* these rst bits should never be used in set_cfg */
#define TRT_CTL_MNG_FREE_SZ_RST_S		12
#define TRT_CTL_MNG_FREE_SZ_RST_M		BIT(12)

#define TRT_CTL_RDB_FREE_SZ_RST_S		11
#define TRT_CTL_RDB_FREE_SZ_RST_M		BIT(11)

#define TRT_CTL_LAN1_FREE_SZ_RST_S		10
#define TRT_CTL_LAN1_FREE_SZ_RST_M		BIT(10)

#define TRT_CTL_LAN0_FREE_SZ_RST_S		9
#define TRT_CTL_LAN0_FREE_SZ_RST_M		BIT(9)

#define TRT_CTL_PB_RST_S				8
#define TRT_CTL_PB_RST_M				BIT(8)

#define TRT_CTL_ETH_LD_TX_HALT_EN_S		4
#define TRT_CTL_ETH_LD_TX_HALT_EN_M		NSE_M(0x3, 4)

#define TRT_CTL_PB_LAN1_DIS_S			2
#define TRT_CTL_PB_LAN1_DIS_M			BIT(2)

#define TRT_CTL_PB_LAN0_DIS_S			1
#define TRT_CTL_PB_LAN0_DIS_M			BIT(1)

#define TRT_CTL_PB_EN_S					0
#define TRT_CTL_PB_EN_M					BIT(0)

	__le32	trt_pb_sz_lan_dedicate_vld;
	/* bit 0 for lan-0: values[0][], bit 1 for lan-1: values[1][] */
	__le32	trt_pb_sz_lan_dedicate_bitmap;
	__le32	trt_pb_sz_lan_dedicate_values[2][8];

#define TRT_PB_SZ_SIZE_S				10
#define TRT_PB_SZ_SIZE_M				NSE_M(0xFF, 10)

	__le32	trt_pb_sz_tmp_buf_vld;		/* pb_sz[16] */
	__le32	trt_pb_sz_tmp_buf_value;

	__le32	trt_share_sz_vld;
	__le32	trt_share_sz_value;

	__le32	trt_sht_lan_dedicate_vld;
	/* bit 0 for lan-0: values[0][], bit 1 for lan-1: values[1][] */
	__le32	trt_sht_lan_dedicate_bitmap;
	__le32	trt_sht_lan_dedicate_values[2][8];

#define TRT_SHT_VAL_S					5
#define TRT_SHT_VAL_M					NSE_M(0x1FFF, 5)

	__le32	trt_sht_tmp_buf_vld;
	__le32	trt_sht_tmp_buf_value;

	__le32	trt_pbrarb_ctl_vld;
	__le32	trt_pbrarb_ctl_value;
#define TRT_PBRARB_CTL_TPPAC1_S			1
#define TRT_PBRARB_CTL_TPPAC1_M			BIT(1)

#define TRT_PBRARB_CTL_TPPAC0_S			0
#define TRT_PBRARB_CTL_TPPAC0_M			BIT(0)

	#define TRT_PBRARB_CTL_TPPAC_WRR	0
	#define TRT_PBRARB_CTL_TPPAC_WSP	1

	__le32	trt_pbrarb_credit_vld;
	__le32	trt_pbrarb_credit_lan_bitmap;
	__le32	trt_pbrarb_credit_lan_values[2][8];

#define TRT_PBRARB_CREDIT_VAL_S			0
#define TRT_PBRARB_CREDIT_VAL_M			NSE_M(0x7FF, 0)

	#define TRT_PBRARB_CREDIT_VAL_SP_MAX	0x7FF
	#define TRT_PBRARB_CREDIT_VAL_SP_MIN	0x3FF
	#define TRT_PBRARB_CREDIT_VAL_ETS_TOTAL	0x3FF

	__le32	trt_mng_tc_vld;
	__le32	trt_mng_tc_value;
#define TRT_MNG_TC_EN1_S				12
#define TRT_MNG_TC_EN1_M				BIT(12)

#define TRT_MNG_TC_MAP1_S				8
#define TRT_MNG_TC_MAP1_M				NSE_M(0x7, 8)

#define TRT_MNG_TC_EN0_S				4
#define TRT_MNG_TC_EN0_M				BIT(4)

#define TRT_MNG_TC_MAP0_S				0
#define TRT_MNG_TC_MAP0_M				NSE_M(0x7, 0)

	__le32	trt_sni_ctl_vld;
	__le32	trt_sni_ctl_value;

	__le32	trt_up2tc_lan0_vld;
	__le32	trt_up2tc_lan0_value;
	__le32	trt_up2tc_lan1_vld;
	__le32	trt_up2tc_lan1_value;

#define TRT_UP2TC_PFCE_S		31
#define TRT_UP2TC_PFCE_M		BIT(31)

#define TRT_UP2TC_PER_TC_SHIFT	4

	__le32	trt_sch_cfg_lan0_vld;
	__le32	trt_sch_cfg_lan0_value;
	__le32	trt_sch_cfg_lan1_vld;
	__le32	trt_sch_cfg_lan1_value;
#define TRT_SCH_CFG_DRP_PKT_LEN_UPD_DIS_S		18
#define TRT_SCH_CFG_DRP_PKT_LEN_UPD_DIS_M		BIT(18)

#define TRT_SCH_CFG_DUP_PKT_LEN_UPD_DIS_S		17
#define TRT_SCH_CFG_DUP_PKT_LEN_UPD_DIS_M		BIT(17)

#define TRT_SCH_CFG_LEN_UPD_DIS_S				16
#define TRT_SCH_CFG_LEN_UPD_DIS_M				BIT(16)

#define TRT_SCH_CFG_MAC_SCH_UP_LEN_S			0
#define TRT_SCH_CFG_MAC_SCH_UP_LEN_M			NSE_M(0xFFF, 0)

	__le32	trt_exoff_thres_vld;
	__le32	trt_exoff_thres_value;
#define TRT_EXOFF_THRES_VAL_S			0
#define TRT_EXOFF_THRES_VAL_M			NSE_M(0x3FFF, 0)

	__le32	trt_1us_tick_cnt_vld;
	__le32	trt_1us_tick_cnt_value;

	__le32	trt_lksts_fltr_vld;
	__le32	trt_lksts_fltr_value;

	__le32	lmac_rx_flow_ctl_vld;
	__le32	lmac_rx_flow_ctl_value;
#define LMAC_TYPE_1_RX_FLOW_CTL_PFCE_S					8
#define LMAC_TYPE_1_RX_FLOW_CTL_PFCE_M					BIT(8)

#define LMAC_TYPE_1_RX_FLOW_CTL_UP_S					1
#define LMAC_TYPE_1_RX_FLOW_CTL_UP_M					BIT(1)

#define LMAC_TYPE_1_RX_FLOW_CTL_RFE_S					0
#define LMAC_TYPE_1_RX_FLOW_CTL_RFE_M					BIT(0)

	__le32	lmac_tx_flow_ctl_vld;
	__le32	lmac_tx_flow_ctl_value[8];
#define LMAC_TYPE_1_TX_FLOW_CTL_PT_S					16
#define LMAC_TYPE_1_TX_FLOW_CTL_PT_M					NSE_M(0xFFFF, 16)

#define LMAC_TYPE_1_TX_FLOW_CTL_DZPQ_S					7
#define LMAC_TYPE_1_TX_FLOW_CTL_DZPQ_M					BIT(7)

#define LMAC_TYPE_1_TX_FLOW_CTL_PLT_S					4
#define LMAC_TYPE_1_TX_FLOW_CTL_PLT_M					NSE_M(0x7, 4)

#define LMAC_TYPE_1_TX_FLOW_CTL_TFE_S					1
#define LMAC_TYPE_1_TX_FLOW_CTL_TFE_M					BIT(1)

#define LMAC_TYPE_1_TX_FLOW_CTL_FCB_S					0
#define LMAC_TYPE_1_TX_FLOW_CTL_FCB_M					BIT(0)

	__le32 lmac_rxq_prio_mapping_ctrl_vld;
	__le32 lmac_rxq_prio_mapping_ctrl_value[2];

	struct nse_dcbx_cfg		local_dcbx_cfg;
	struct nse_dcbx_cfg		remote_dcbx_cfg;

	__le32 dcbx_cfg_flags;
#define QOS_DCBX_CFG_FLAG_LOCAL		BIT(0)
#define QOS_DCBX_CFG_FLAG_REMOTE	BIT(1)

	__le32 sch_tree_flags;
#define QOS_DB_SCH_TREE_FLAG_UPDATE_TC_LAYER	0x1

} __packed;

struct nse_aqc_qos_db_cfg_ms {
	struct nse_aqc_generic_common_hdr hdr;

	__le32	rpb_pb_ctl_vld;
	__le32	rpb_pb_ctl_value;
#define MS_RPB_PB_CTL_WARB_MODE_S	24
#define MS_RPB_PB_CTL_WARB_MODE_M	BIT(24)

#define MS_RPB_PB_CTL_WARB_MODE_WRR		0
#define MS_RPB_PB_CTL_WARB_MODE_WSP		1

#define MS_RPB_PB_CTL_SAVE_MAC_ERR_S	20
#define MS_RPB_PB_CTL_SAVE_MAC_ERR_M	BIT(20)

#define MS_RPB_PB_CTL_RST_S			16
#define MS_RPB_PB_CTL_RST_M			BIT(16)

#define MS_RPB_PB_CTL_TC_TX_EN_S	8
#define MS_RPB_PB_CTL_TC_TX_EN_M	NSE_M(0xFF, 8)

#define MS_RPB_PB_CTL_TC_RX_EN_S	0
#define MS_RPB_PB_CTL_TC_RX_EN_M	NSE_M(0xFF, 0)

/* used for all size, watermark setting */
#define MS_RPB_SZ_WM_VAL_S			9
#define MS_RPB_SZ_WM_VAL_M			NSE_M(0x3FFF, 9)	/* width: 14 */

#define MS_RPB_SZ_WM_VAL_SHIFT		9	/* 512 byte unit */

	__le32	rpb_tc_dedicate_sz_vld;
	__le32	rpb_tc_dedicate_sz_value[8];

	__le32	rpb_tc_share_sz_vld;
	__le32	rpb_tc_share_sz_value[8];

	__le32 rpb_tc_dhw_vld;
	__le32 rpb_tc_dhw_value[8];

	__le32 rpb_tc_dlw_vld;
	__le32 rpb_tc_dlw_value[8];

	__le32 rpb_tc_slw_vld;
	__le32 rpb_tc_slw_value[8];

	__le32	rpb_tc2pfc_vld;
	__le32	rpb_tc2pfc_value;	/* tc bitmap */

	__le32	rpb_lltc_vld;
	__le32	rpb_lltc_value;		/* tc bitmap */

	__le32	rpb_arb_credit_vld;
	__le32	rpb_arb_credit_value[8];
#define MS_RPB_PBRARB_CREDIT_VAL_S		0
#define MS_RPB_PBRARB_CREDIT_VAL_M		NSE_M(0x3FF, 0)

	#define MS_RPB_PBRARB_CREDIT_VAL_SP_MAX		0x3FF
	#define MS_RPB_PBRARB_CREDIT_VAL_SP_MIN		0x1FF
	#define MS_RPB_PBRARB_CREDIT_VAL_ETS_TOTAL	0x3FF

	__le32	rpb_ovfl_en_vld;
	__le32	rpb_ovfl_en_value;	/* tc bitmap */

	__le32	rpb_ovfl_time_vld;
	__le32	rpb_ovfl_time_value;
#define MS_RPB_OVFL_TIME_INIT_S		0
#define MS_RPB_OVFL_TIME_INIT_M		NSE_M(0xFFFFFFF, 0)

	__le32 rpb_port_ctl_vld;
	__le32 rpb_port_ctl_value;
#define MS_RPB_PORT_CTL_CRCP_S		30
#define MS_RPB_PORT_CTL_CRCP_M		BIT(30)

	__le32 rpb_port_share_sz_vld;
	__le32 rpb_port_share_sz_value;

	__le32 rpb_port_ghw_vld;
	__le32 rpb_port_ghw_value;

	__le32 rpb_port_glw_vld;
	__le32 rpb_port_glw_value;

	__le32 rpb_port_shw_vld;
	__le32 rpb_port_shw_value;

	__le32 rpb_port_slw_vld;
	__le32 rpb_port_slw_value;

	__le32	rpb_port_up2tc_vld;
	__le32	rpb_port_up2tc_value;
#define MS_RPB_PORT_UP2TC_PER_TC_SHIFT		4

	__le32	rpb_port_vlan2up_ctrl_vld;
	__le32	rpb_port_vlan2up_ctrl_value;
#define MS_RPB_PORT_VLAN2UP_CTRL_DFT_UP_S	4
#define MS_RPB_PORT_VLAN2UP_CTRL_DFT_UP_M	NSE_M(0x7, 4)

	__le32	rdb_pb_ctl_vld;
	__le32	rdb_pb_ctl_value;
#define MS_RDB_PB_CTL_RST_S			8
#define MS_RDB_PB_CTL_RST_M			BIT(8)

#define MS_RDB_PB_PSR_BP_S			4
#define MS_RDB_PB_PSR_BP_M			BIT(4)

#define MS_RDB_PB_CTL_EN_S				0
#define MS_RDB_PB_CTL_EN_M				BIT(0)

	__le32	rdb_pbrarb_ctl_vld;
	__le32	rdb_pbrarb_ctl_value;
#define MS_RDB_PBRARB_CTL_WSP_PRI_S		5
#define MS_RDB_PBRARB_CTL_WSP_PRI_M		BIT(5)

	#define MS_RDB_PBRARB_CTL_WSP_PRI_PACKET		0
	#define MS_RDB_PBRARB_CTL_WSP_PRI_MINIPO		1

#define MS_RDB_PBRARB_CTL_RPPAC_S			4
#define MS_RDB_PBRARB_CTL_RPPAC_M			BIT(4)

	#define MS_RDB_PBRARB_CTL_RPPAC_WRR		0
	#define MS_RDB_PBRARB_CTL_RPPAC_WSP		1

	__le32	rdb_pbrarb_credit_vld;
	__le32	rdb_pbrarb_credit_value[7];
#define MS_RDB_PBRARB_CREDIT_VAL_S		0
#define MS_RDB_PBRARB_CREDIT_VAL_M		NSE_M(0x7FF, 0)

	#define MS_RDB_PBRARB_CREDIT_VAL_MAX		0x7FF
	#define MS_RDB_PBRARB_CREDIT_VAL_INIT		0x200
	#define MS_RDB_PBRARB_CREDIT_VAL_DFLT		0x7FF

	__le32	rdb_stall_time_vld;
	__le32	rdb_stall_time_value;
#define MS_RDB_STALL_TIME_EN_S			31
#define MS_RDB_STALL_TIME_EN_M			BIT(31)

#define MS_RDB_STALL_TIME_INIT_S		0
#define MS_RDB_STALL_TIME_INIT_M		NSE_M(0x7FFFFFFF, 0)

	__le32	tdb_pb_ctl_vld;
	__le32	tdb_pb_ctl_value;

#define MS_TDB_PB_CTL_RST_S			8
#define MS_TDB_PB_CTL_RST_M			BIT(8)

#define MS_TDB_PB_CTL_EN_S				0
#define MS_TDB_PB_CTL_EN_M				BIT(0)

	__le32	tdb_pb_sz_vld;
	__le32	tdb_pb_sz_value[8];

#define MS_TDB_PB_SZ_SIZE_S			10
#define MS_TDB_PB_SZ_SIZE_M			NSE_M(0x3FF, 10)

	__le32	tdb_share_sz_vld;
	__le32	tdb_share_sz_value;

	__le32	tdb_sht_vld;
	__le32	tdb_sht_value[8];
#define MS_TDB_SHT_SIZE_S				5
#define MS_TDB_SHT_SIZE_M				NSE_M(0x7FFF, 5)

	__le32	tdb_pbwarb_credit_vld;
	__le32	tdb_pbwarb_credit_value[2];
#define MS_TDB_PBWARB_CREDIT_VAL_S			0
#define MS_TDB_PBWARB_CREDIT_VAL_M			NSE_M(0x7FF, 0)

	#define MS_TDB_PBWARB_CREDIT_VAL_MAX		0x7FF
	#define MS_TDB_PBWARB_CREDIT_VAL_INIT		0x200
	#define MS_TDB_PBWARB_CREDIT_VAL_DFLT		0x7FF

	__le32	tdb_pbrarb_ctl_vld;
	__le32	tdb_pbrarb_ctl_value;
#define MS_TDB_PBRARB_CTL_POH_STORE_CNT_S	8
#define MS_TDB_PBRARB_CTL_POH_STORE_CNT_M	NSE_M(0x7, 8)

	#define MS_TDB_PBRARB_CTL_POH_STORE_CNT_DFLT	0x2

#define MS_TDB_PBRARB_CTL_RPPAC0_S		0
#define MS_TDB_PBRARB_CTL_RPPAC0_M		BIT(0)

	#define MS_TDB_PBRARB_CTL_RPPAC_WRR		0
	#define MS_TDB_PBRARB_CTL_RPPAC_WSP		1

	__le32	tdb_tcpbrarb_credit_vld;
	__le32	tdb_tcpbrarb_credit_value[8];

#define MS_TDB_TCPBRARB_CREDIT_VAL_S	0
#define MS_TDB_TCPBRARB_CREDIT_VAL_M	NSE_M(0x7FF, 0)

	#define MS_TDB_TCPBRARB_CREDIT_VAL_MAX			0x7FF
	#define MS_TDB_TCPBRARB_CREDIT_VAL_INIT		0x200
	#define MS_TDB_TCPBRARB_CREDIT_VAL_DFLT		0x7FF

	struct nse_dcbx_cfg		local_dcbx_cfg;
	struct nse_dcbx_cfg		remote_dcbx_cfg;

	__le32 dcbx_cfg_flags;

	__le32 lmac_tx_pause_en_vld;
	__le32 lmac_tx_pause_en_value;

	__le32 lmac_retransmit_xoff_holdoff_en_vld;
	__le32 lmac_retransmit_xoff_holdoff_en_value;

	__le32 lmac_retransmit_xoff_holdoff_quanta_vld;
	__le32 lmac_retransmit_xoff_holdoff_quanta_value;

	__le32 lmac_tx_pause_quanta_vld;
	__le32 lmac_tx_pause_quanta_value;

	__le32 lmac_tx_xof_en_tx_pause_qnumber_vld;
	__le32 lmac_tx_xof_en_tx_pause_qnumber_value;

	/* badly named, should be "Uniform Holdoff" */
	__le32 lmac_cfg_retransmit_holdoff_en_vld;
	__le32 lmac_cfg_retransmit_holdoff_en_value;

	/* badly named, should be "Uniform Holdoff" */
	__le32 lmac_cfg_retransmit_holdoff_quanta_vld;
	__le32 lmac_cfg_retransmit_holdoff_quanta_value;

	__le32 lmac_txsfc_ehip_cfg_vld;
	__le32 lmac_txsfc_ehip_cfg_value;
#define LMAC_TYPE_2_TXSFC_CHIP_CFG_EN_SFC_S		0
#define LMAC_TYPE_2_TXSFC_CHIP_CFG_EN_SFC_M		BIT(0)

#define LMAC_TYPE_2_TXSFC_CHIP_CFG_EN_PFC_S		1
#define LMAC_TYPE_2_TXSFC_CHIP_CFG_EN_PFC_M		BIT(1)

	__le32 lmac_rx_pause_enable_vld;
	__le32 lmac_rx_pause_enable_value;

	__le32 lmac_rx_pause_fwd_vld;
	__le32 lmac_rx_pause_fwd_value;

	__le32 lmac_rxsfc_ehip_cfg_vld;
	__le32 lmac_rxsfc_ehip_cfg_value;
#define LMAC_TYPE_2_RXSFC_CHIP_CFG_EN_SFC_S		0
#define LMAC_TYPE_2_RXSFC_CHIP_CFG_EN_SFC_M		BIT(0)

#define LMAC_TYPE_2_RXSFC_CHIP_CFG_EN_PFC_S		1
#define LMAC_TYPE_2_RXSFC_CHIP_CFG_EN_PFC_M		BIT(1)

	__le32 lmac_pfc_pause_quanta_vld;
	__le32 lmac_pfc_pause_quanta_value[8];

	__le32 lmac_pfc_holdoff_quanta_vld;
	__le32 lmac_pfc_holdoff_quanta_value[8];

} __packed;

struct nse_aqc_qos_db_cfg {
	union {
		struct nse_aqc_generic_common_hdr hdr;	/* common header to amber and ms */
		struct nse_aqc_qos_db_cfg_amber amber;
		struct nse_aqc_qos_db_cfg_ms ms;
	};

} __packed;

struct nse_aqc_qos_db_flush_disable {
	struct nse_aqc_generic_common_hdr hdr;

	u8 eth_grp_id;	/* currently not used, unless we do HW-bond */
	u8 pad[3];

	__le32 flags;
#define NSE_AQC_QOS_DB_FLUSH_DISABLE_RPB			0x1
#define NSE_AQC_QOS_DB_FLUSH_DISABLE_RDB			0x2
#define NSE_AQC_QOS_DB_FLUSH_DISABLE_TDB			0x4
#define NSE_AQC_QOS_DB_FLUSH_DISABLE_TRT_THIS_LAN	0x8
#define NSE_AQC_QOS_DB_FLUSH_DISABLE_TRT_ALL_LAN	0x10

} __packed;

struct nse_aqc_qos_db_conf_up_enforcement {
	struct nse_aqc_generic_common_hdr hdr;

	u8 eth_grp_id;	/* currently not used, unless we do HW-bond */
	u8 rw;			/* 0 for read, 1 for write */
	u8 pad[2];

	__le32 dscp2tc_block_ipv4_vld;
	__le32 dscp2tc_block_ipv4_values[64];

	__le32 dscp2tc_block_ipv6_vld;
	__le32 dscp2tc_block_ipv6_values[64];

	__le32 tctupr_vld;
	__le32 tctupr_bitmap;
	__le32 tctupr_values[4][8];

#define TCTUPR_PER_UP_SHIFT		4

	__le32 up_ctl_vld;
	__le32 up_ctl_value;

#define UP_CTL_ENFORCE_EN_S		0
#define UP_CTL_ENFORCE_EN_M		BIT(0)

	__le32 dscp_ctl_vld;
	__le32 dscp_ctl_value;

#define DSCP_CTL_DRP_EN_S		2
#define DSCP_CTL_DRP_EN_M		BIT(2)

#define DSCP_CTL_RPT_EN_S		1
#define DSCP_CTL_RPT_EN_M		BIT(1)

#define DSCP_CTL_CHK_EN_S		0
#define DSCP_CTL_CHK_EN_M		BIT(0)

} __packed;

struct nse_aqc_fw_lldp_agent_get_status {
	struct nse_aqc_generic_common_hdr hdr;

#define FW_LLDP_AGENT_NVM_DEFAULT_RUN	0x100
#define FW_LLDP_AGENT_CUR_RUNNING		0x1
	__le32 status;

} __packed;

struct nse_aqc_fw_lldp_agent_start_stop {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 start_or_stop;	/* 1 for start, 0 for stop. */

} __packed;

struct nse_aqc_qos_fw_lldp_dcbx_subagent_get_status {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 status;

} __packed;

struct nse_aqc_qos_fw_dcbx_subagent_start_stop {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 start_or_stop;	/* 1 for start, 0 for stop. */

} __packed;

struct nse_aqc_qos_dcbx_conf_chg_event {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 chg_flags;

//BIT(0)		/* local_dcbx_cfg is changed. */
#define QOS_DCBX_CONF_CHG_FLAG_LOCAL	QOS_DCBX_CFG_FLAG_LOCAL
//BIT(1)		/* remote_dcbx_cfg is changed. */
#define QOS_DCBX_CONF_CHG_FLAG_REMOTE	QOS_DCBX_CFG_FLAG_REMOTE

} __packed;

struct nse_aqc_qos_sch_rw_ctl {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 rw_flag;

	__le32 sch_ctl;
#define SCH_CTL_MAX_BURST_SIZE_S	8
#define SCH_CTL_MAX_BURST_SIZE_M	NSE_M(0x7F, 8)

#define SCH_CTL_CRL_CAL_EN_S		5
#define SCH_CTL_CRL_CAL_EN_M		BIT(5)

#define SCH_CTL_PRL_CAL_EN_S		4
#define SCH_CTL_PRL_CAL_EN_M		BIT(4)

#define SCH_CTL_SCH_EN_S			0
#define SCH_CTL_SCH_EN_M			NSE_M(0x3, 0)

	#define SCH_CTL_SCH_EN_DISABLE		0x0
	#define SCH_CTL_SCH_EN_ENABLE		0x1
	#define SCH_CTL_SCH_EN_BYPASS		0x2

} __packed;

struct nse_aqc_qos_sch_per_pf_init {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 lan_txq_space_start;
	__le32 lan_txq_space_size;

	__le32 rdma_qset_space_start;
	__le32 rdma_qset_space_size;

	__le32 sch_node_space_start;
	__le32 sch_node_space_size;

	__le32 sch_tc_node_tnid_start;
	__le32 sch_tc_node_tnid_end;

	__le32 sch_qid2lnid_tdm_space_start;
	__le32 sch_qid2lnid_tdm_space_size;

	__le32 sch_qid2lnid_tpe_space_start;
	__le32 sch_qid2lnid_tpe_space_size;
} __packed;

struct nse_sch_node_param {
	__le16 valid_section; /* Bit 0: sch_mode
			       * Bit 1: sp_val (only available in sp mode)
			       * Bit 2: node_type
			       * Bit 3: pir
			       * Bit 4: cir
			       * Bit 5: tc value
			       * Bit 6: port id
			       * Bits 7-15: Reserved
			       */
#define NSE_SCH_NODE_PARAM_SECTION_ARB_MODE_VALID		1
#define NSE_SCH_NODE_PARAM_SECTION_SP_VAL_VALID			2
#define NSE_SCH_NODE_PARAM_SECTION_NODE_TYPE_VALID		4
#define NSE_SCH_NODE_PARAM_SECTION_PIR_VALID			8
#define NSE_SCH_NODE_PARAM_SECTION_CIR_VALID			16
#define NSE_SCH_NODE_PARAM_SECTION_TC_VAL_VALID			32
#define NSE_SCH_NODE_PARAM_SECTION_PORT_ID_VALID		64

	__le16 arb_mode;      /*0: WFQ 1: SP  2:WSP*/
#define NSE_SCH_NODE_PARAM_ARB_MODE_WFQ   0
#define NSE_SCH_NODE_PARAM_ARB_MODE_SP    1
#define NSE_SCH_NODE_PARAM_ARB_MODE_WSP   2

	__le16 sp_val;        /*only available in SP mode, range 0~7*/
#define NSE_SCH_NODE_PARAM_MAX_SP_VAL   7

	__le16 node_type;      /*node type*/
#define NSE_SCH_NODE_PARAM_NODE_TYPE_LEAF    0
#define NSE_SCH_NODE_PARAM_NODE_TYPE_PARENT  1
#define NSE_SCH_NODE_PARAM_NODE_TYPE_LEAF_TC 2
#define NSE_SCH_NODE_PARAM_NODE_TYPE_ROOT    3

	__le16 pir;     /*in 1/4000 multiplied by port rate */
	__le16 cir;     /*in 1/4000 multiplied by port rate */
#define NSE_SCH_NODE_PARAM_PIR_CIR_MIN_VAL	1
#define NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL	4000
/* NSE_SCHED_FACTOR_TBL_LEN == NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL, **MUST** sync change */

	__le16 tc_val;  /*TC value, range 0~7, only available in TC node type*/
#define NSE_SCH_NODE_PARAM_MAX_TC_VAL   7

	__le16 port_id;  /*port id  range 0~3*/
#define NSE_SCH_NODE_PARAM_MAX_PORT_ID  3

	__le16 pir_factor_int;
	__le16 pir_factor_df_int;
	__le16 pir_factor_df_df;
	u8 pad_0[2];

	__le16 cir_factor_int;
	__le16 cir_factor_df_int;
	__le16 cir_factor_df_df;
	u8 pad_1[2];

} __packed;

struct nse_aqc_qos_sch_add_node_one {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 parent_tnid;
	__le32 parent_suid;
	__le32 parent_logic_idx_in_su;

	__le32 flags;
#define ADD_NODE_ONE_FLAG_SUGGEST_CHILD_TNID			0x1
#define ADD_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID		0x2
#define ADD_NODE_ONE_FLAG_SUGGEST_NEXT_SIBLING_TNID		0x4
#define ADD_NODE_ONE_FLAG_LEAF	0x8	/* add a leaf node, otherwise, a non-leaf node */

	__le32 new_child_tnid;			/* FW write back allocate node TNID to here */

	__le32 prev_sibling_tnid;
	__le32 next_sibling_tnid;

	__le32 leaf_node_qid;

	struct nse_sch_node_param sch_param;

} __packed;

struct nse_aqc_qos_sch_del_node_one {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 parent_tnid;
	__le32 parent_suid;
	__le32 parent_logic_idx_in_su;

	__le32 flags;
/* the whole child SE is gonna deleted, child_seid = (child_tnid >> 1) */
#define DEL_NODE_ONE_FLAG_DEL_CHILD_SE					BIT(0)
#define DEL_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID		BIT(1)
#define DEL_NODE_ONE_FLAG_SUGGEST_NEXT_SIBLING_TNID		BIT(2)
#define DEL_NODE_ONE_FLAG_LEAF	BIT(3)	/* add a leaf node, otherwise, a non-leaf node */
#define DEL_NODE_ONE_FLAG_PREV_SE						BIT(4)
#define DEL_NODE_ONE_FLAG_NEXT_SE						BIT(5)
#define DEL_NODE_ONE_FLAG_NEED_LOCK_PARENT_SE			BIT(6)
#define DEL_NODE_ONE_FLAG_NEED_LOCK_PREV_SE				BIT(7)

	/* if (flags & DEL_CHILD_SE), then these position 3 flags tells SE's position in SU
	 *
	 *  just for convenience for debug, FW deleting logic may not actually use these 3 position
	 * flags.
	 *
	 *		Actually FW itself can determine the position various situation
	 *
	 *  note, a deleting SE can be both HEAD and TAIL, if it is the only SE in SU --- and in
	 * that case, FLAG_SU_BECOME_EMPTY is also set.
	 */
#define DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_HEAD			BIT(8)
#define DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_MIDDLE		BIT(9)
#define DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_TAIL			BIT(10)

/* if yes, then can reset parent node CN_SU_PTR to 0 */
#define DEL_NODE_ONE_FLAG_SU_BECOME_EMPTY				BIT(11)

	__le32 child_tnid;

	__le32 prev_sibling_tnid;
	__le32 next_sibling_tnid;

	__le32 prev_se;
	__le32 next_se;

#define DEL_NODE_ONE_EXISTING_SIB_TAIL_CHILD_SE_CNT_MAX 14
	__le32 remain_sib_tail_child_se_cnt;
	__le32 remain_sib_tail_child_se[14];
	__le32 remain_sib_tail_child_se_new_ptr[14];
	__le32 remain_sib_tail_child_se_new_idx[14];

#define DEL_NODE_ONE_EXISTING_LEAF_SIB_QID2LNID_CNT_MAX	14
	__le32 remain_leaf_sib_qid2lnid_cnt;
	__le32 remain_leaf_sib_qid2lnid[14];
	__le32 remain_leaf_sib_qid2lnid_new_ptr[14];
	__le32 remain_leaf_sib_qid2lnid_new_idx[14];

	__le32 leaf_qid2lnid;
	__le16 qid;
	__le16 qid_type;	/* QID_TYPE_LAN_TXQ (0x1) or QID_TYPE_RDMA_QSET (0x2) */

} __packed;

struct nse_aqc_qos_sch_suspend_resume_node_one {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 suspend;	/* 1 for suspend, 0 for resume */
	__le16 resume_state;
#define RESUME_STATE_EIR	0x2
#define RESUME_STATE_CIR	0x3

	__le32 tnid;
} __packed;

struct nse_aqc_qos_sch_update_child_se_nxt_ptr_idx {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 parent_tnid;
	__le32 parent_suid;
	__le32 parent_logic_idx_in_su;

	__le32 child_tnid;

} __packed;

struct nse_aqc_qos_sch_set_unset_qid2lnid {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 flags;
#define SET_UNSET_QID2LNID_FLAG_SET		0x1

	__le32 leaf_tnid;
	__le32 leaf_suid;
	__le32 leaf_logic_idx_in_su;

	__le16 qid;					/* LAN-TXQ ID or RDMA-QSET ID */
	__le16 qid_type;
#define QID_TYPE_LAN_TXQ		0x1
#define QID_TYPE_RDMA_QSET		0x2

	__le32 leaf_qid2lnid;

} __packed;

struct nse_aqc_qos_sch_get_set_node_param_one {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 tnid;

	__le32 rw;

	struct nse_sch_node_param sch_param;

} __packed;

struct nse_aqc_qos_sch_rw_port_ctl {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 rw;	/* 1 for read request, 0 for write request */

	__le32 reg_bitmap;

	__le32 port_ctl[4];

#define SCH_PORT_CTL_SCAL_DIR_S			4
#define SCH_PORT_CTL_SCAL_DIR_M			BIT(4)

	#define SCH_PORT_CTL_SCAL_DIR_LARGEN	0
	#define SCH_PORT_CTL_SCAL_DIR_LESSON	1

#define SCH_PORT_CTL_SCAL_VAL_S			0
#define SCH_PORT_CTL_SCAL_VAL_M			NSE_M(0x3, 0)

	#define SCH_PORT_CTL_SCAL_VAL_NO_SCAL	0
	#define SCH_PORT_CTL_SCAL_VAL_BY_2		1
	#define SCH_PORT_CTL_SCAL_VAL_BY_4		2
	#define SCH_PORT_CTL_SCAL_VAL_BY_8		3

	__le32 rsv[32];

} __packed;

struct nse_aqc_qos_sch_conf_cir {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 tnid;

	__le16 op;
#define NSE_AQC_QOS_SCH_CONF_CIR_OP_SET		0x0
#define NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET	0x1

	u8 pad_0[2];

	__le16 cir;				/* only for debug print */
	u8 pad_1[6];

	__le16 factor_int;
	__le16 factor_df_int;
	__le16 factor_df_df;

	u8 conf_status;
	u8 pad_2;

} __packed;

struct nse_aqc_qos_sch_conf_pir {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 tnid;

	__le16 op;
#define NSE_AQC_QOS_SCH_CONF_PIR_OP_SET		0x0
#define NSE_AQC_QOS_SCH_CONF_PIR_OP_RESET	0x1

	__le16 pir;				/* not used */

	u8 conf_status;
	u8 pad_0;

	__le16 available_pir;	/* not used */

	__le16 factor_int;
	__le16 factor_df_int;
	__le16 factor_df_df;
	u8 pad_1[2];

} __packed;

/* should be less than 4K bytes of one aq-cmd */
#define NSE_AQC_QOS_SCH_DBG_DUMP_FREE_SE_LIST_MAX_SE_CNT_ONCE 800

struct nse_aqc_qos_sch_dbg_dump_free_se_list {
	struct nse_aqc_generic_common_hdr hdr;
	__le32 free_se_offset;
	__le32 free_se_dump_cnt;
	__le32 free_se_total_cnt;
	__le32 free_se_ids[NSE_AQC_QOS_SCH_DBG_DUMP_FREE_SE_LIST_MAX_SE_CNT_ONCE];
} __packed;

struct nse_aqc_qos_sch_dbg_dump_se {
	struct nse_aqc_generic_common_hdr hdr;
	__le32 seid;
	u8 se_data[256];
} __packed;

struct nse_aqc_qos_sch_dbg_dump_qid2lnid {
	struct nse_aqc_generic_common_hdr hdr;
	__le16 qid;
	__le16 qid_type;
	u8 qid2lnid_data[32];
} __packed;

#define NSE_MAX_NUM_LUTS 256
#define NSE_MAX_NUM_RCPS 256

struct nse_aqc_get_sw_cfg_resp_elem {
	/* VSI/Port Number */
	__le16 vsi_port_num;
#define NSE_AQC_GET_SW_CONF_RESP_VSI_PORT_NUM_S	0
#define NSE_AQC_GET_SW_CONF_RESP_VSI_PORT_NUM_M	0x3FF
#define NSE_AQC_GET_SW_CONF_RESP_TYPE_S	14
#define NSE_AQC_GET_SW_CONF_RESP_TYPE_M	0x3
#define NSE_AQC_GET_SW_CONF_RESP_PHYS_PORT	0
#define NSE_AQC_GET_SW_CONF_RESP_VIRT_PORT	1
#define NSE_AQC_GET_SW_CONF_RESP_VSI		2

	/* SWID VSI/Port belongs to */
	__le16 swid;

	/* Bit 14..0 : PF/VF number VSI belongs to
	 * Bit 15 : VF indication bit
	 */
	__le16 pf_vf_num;
#define NSE_AQC_GET_SW_CONF_RESP_FUNC_NUM_S	0
#define NSE_AQC_GET_SW_CONF_RESP_FUNC_NUM_M	0x7FFF
#define NSE_AQC_GET_SW_CONF_RESP_IS_VF		BIT(15)
} __packed;

struct nse_aqc_get_sw_cfg {
	/*element number in buf, 0 means get all */
	__le16 count;
	/* request: it is the start element id to get
	 *  response: if there are element left, it is the next element id
	 *			if there is no element left, it is set to zero by FW
	 */
	__le16 start_id;
	struct nse_aqc_get_sw_cfg_resp_elem elems[];
} __packed;

struct nse_aqc_recipe_content {
#define	NSE_AQ_SW_ID_LKUP_IDX		0
#define NSE_AQ_SW_ID_LKUP_MASK		0x00FF
#define	NSE_AQ_IN_PORT_LKUP_IDX		1
#define NSE_AQ_IN_PORT_LKUP_MASK	0xFFFF

	/* pointer to lut tree root node */
	__le16 lut_id;
	__le16 mask[5];
	u8 lkup_indx[5];
	__le16 dflt_action;
	u8 result_indx;
#define NSE_AQ_RECIPE_DFLT_ACT_LG	BIT(0) /*Bit 0:0 - Default action MSB 17 bit*/
#define NSE_AQ_RECIPE_RSLT_INDX_S	  1 /* Bit 7:1 - result_indx */
#define NSE_AQ_RECIPE_RSLT_INDX_M	  (0x7F << NSE_AQ_RECIPE_RSLT_INDX_S)
#define NSE_AQ_RECIPE_RSLT_INDX_G_M	  (0x7F)

	/* Current recipe can be executed after the
	 * specified recipe has been finished.
	 *  it is relative recipe id per profile.
	 */
	u8 depend_recipe_id;
	u8 priority;
	u8 ctrl_flg;
#define NSE_AQ_RECIPE_LPM_EN		BIT(2)
#define NSE_AQ_RECIPE_IS_ROOT		BIT(3)
#define NSE_AQ_RECIPE_DFLT_ACT_EN	BIT(4)
#define NSE_AQ_RECIPE_RESULT_EN		BIT(6)
#define NSE_AQ_RECIPE_ALTER_RESULT_EN		BIT(7)

	/* bit 0:4 - Key Ignore valid bitmap flags, not used in adv recipe now
	 * 1 means if key is extracted invalidly, value is treated as 0,
	 * and while key is extracted validly, value is from packet.
	 *
	 * bit 5:7 - rsvd
	 */
	u8 ignore_vld;
#define NSE_AQ_RECIPE_IGNORE_VLD_S	  0 /* Bit 4:0 - ignore_vld */
#define NSE_AQ_RECIPE_IGNORE_VLD_M	  (0x1F << NSE_AQ_RECIPE_IGNORE_VLD_S)
#define NSE_AQ_RECIPE_INVERSE_INDX	BIT(5)
#define NSE_AQ_RECIPE_RESULT_SEL	BIT(6)
#define NSE_AQ_RECIPE_INVERSE_EN	BIT(7)
} __packed;

struct nse_aqc_recipe_data_elem {
	__le16 profile_id;
	u8 recipe_id; /* it is relative recipe id per profile*/
	u8 rsvd;
	struct nse_aqc_recipe_content content;
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_RECIPE
 *  struct for cmd: NSE_AQ_OPC_UPDATE_RECIPE
 *  struct for cmd: NSE_AQ_OPC_REMOVE_RECIPE
 *  struct for cmd: NSE_AQ_OPC_GET_RECIPE
 */
struct nse_aqc_recipe_cfg {
	__le16 count; /*element number in one buf */
	__le16 rsvd;
	struct nse_aqc_recipe_data_elem elem[];
} __packed;

struct nse_aqc_field_vector_cfg_elem {
	__le32 fec;
#define NSE_AQ_PROFILE_FEC_EN_S			31 /*bit 31 is enable flag*/
#define NSE_AQ_PROFILE_FEC_EN_M			1
#define NSE_AQ_PROFILE_FEC_OFF_S		16 /*bit 24:16 is offset*/
#define NSE_AQ_PROFILE_FEC_OFF_M		0x1ff
#define NSE_AQ_PROFILE_FEC_PROT_ID_S	0  /*bit 7:0 is protocol id*/
#define NSE_AQ_PROFILE_FEC_PROT_ID_M	0xff
} __packed;

#define NSE_AQ_GET_PRFL_MAX_LOOP		20
struct nse_aqc_profile_cfg_elem {
	__le16 profile_id;
	u8 chain_id;
	u8 rsvd1;
	__le32 base_recipe_id;
	u8 total_recipe_num;
	u8 used_recipe_num;
	__le16 fe_num; /*bit 0-6 fe_num, bit 7 -12 rcpe num, bit 13-15 grp num*/
#define NSE_AQC_PROFILE_FENUM_M 0x7F
#define NSE_AQC_PROFILE_LOCAL_RCP_S 0x7
#define NSE_AQC_PROFILE_LOCAL_RCP_M 0x3F

	struct nse_aqc_field_vector_cfg_elem fvw[NSE_AQ_MAX_FV_WORDS];
	u8 end_recipe_id[7];
	u8 rsvd2;
} __packed;

/*  struct for cmd: NSE_AQ_OPC_GET_PROFILE_CFG
 *  struct for cmd: NSE_AQ_OPC_UPDATE_PROFILE_CFG
 */
struct nse_aqc_profile_cfg {
	/*element number in one buf, 0 means read all */
	__le16 count;
	/* request: it is the start profile id to read
	 *  response: if there are profiles left, it is the next profile id
	 *			if there is no profile left, it is set to zero by FW
	 */
	__le16 start_id;
	struct nse_aqc_profile_cfg_elem elems[];
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ALLOC_RESOURCE
 *  struct for cmd: NSE_AQ_OPC_FREE_RESOURCE
 */
struct nse_aqc_alloc_free_res_elem {
	__le16 res_type;
#define NSE_AQC_RES_TYPE_VSI_LIST_ID			0x00
#define NSE_AQC_RES_TYPE_LUT_ID					0x01
#define NSE_AQC_RES_TYPE_NODE_STATE_ID			0x02
#define NSE_AQC_RES_TYPE_TASK_LIST_ID			0x03
#define NSE_AQC_RES_TYPE_DU_DATA_ID				0x04
#define NSE_AQC_RES_TYPE_COUNTER_ID				0x05
#define NSE_AQC_RES_TYPE_METER_ID				0x06
#define NSE_AQC_RES_TYPE_LITE_NODE_STATE		0x07

	__le16 num_elems;
	__le16 res_id[]; /*resource id or CBUF addr*/
#define NSE_AQC_RES_TYPE_BLUT_BIT	BIT(13) /* cbuf bst lut*/
#define NSE_AQC_RES_TYPE_PLUT_BIT	BIT(14) /* cbuf lpm lut*/
#define NSE_AQC_RES_TYPE_TLUT_BIT	BIT(15) /* tcam lut*/

} __packed;

/*  struct for cmd: NSE_AQ_OPC_REMOVE_VSI_LIST
 *  struct for cmd: NSE_AQ_OPC_GET_VSI_LIST
 */
struct nse_aqc_get_remove_vsi_lists_elem {
	__le16 vsi_list_id; /*it is alloced first by ALLOC RESOURCE cmd*/
	__le16 rsvd;
#define NSE_AQC_MAX_VSI_BM_BYTE_SIZE	8

	__le32 vsi_bm[NSE_AQC_MAX_VSI_BM_BYTE_SIZE]; /* 256 VSI's bitmap*/
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_VSI_LIST
 *  struct for cmd: NSE_AQ_OPC_UPDATE_VSI_LIST
 */
struct nse_aqc_vsi_lists_elem {
	__le16 vsi_list_id; /*it is alloced first by ALLOC RESOURCE cmd*/
	u8   op_type; /* set or clear*/
	u8   rsvd;
#define NSE_AQC_SW_RULES_T_VSI_LIST_CLEAR 0
#define NSE_AQC_SW_RULES_T_VSI_LIST_SET	  1
	__le16 num_vsi;
	__le16 rsvd1;
	__le16 vsi[];
} __packed;

struct nse_aqc_lut_node_elem {
	__le16 lut_id;
	/*when add, firmware return node id if successfully*/
	/*when update/remove/get, software fill node id*/
	__le16 node_id;

	/*below is the content of hw node element*/
	__le16 action;
/*definition for fwd action*/
#define NSE_SINGLE_ACT_TYPE_FWD_S	14 /* Bit 15:14 - Action type for fwd */
#define NSE_SINGLE_ACT_TYPE_FWD_M	(0x3 << NSE_SINGLE_ACT_TYPE_FWD_S)
#define NSE_SINGLE_ACT_TYPE_FWD		0x0 /*value for fwd*/
#define NSE_SINGLE_FWD_TYPE_S	11 /* Bit 13:11 - fwd type */
#define NSE_SINGLE_FWD_TYPE_M	(0x7 << NSE_SINGLE_FWD_TYPE_S)
#define NSE_SINGLE_FWD_VSI_DIS_LB		0x0 /*0b000*/
#define NSE_SINGLE_FWD_VSI_LIST_DIS_LB	0x1 /*0b001*/
#define NSE_SINGLE_FWD_QUEUE_DIS_LB		0x2 /*0b010*/
#define NSE_SINGLE_FWD_BMC				0x3 /*0b011*/
#define NSE_SINGLE_FWD_VSI_EN_LB		0x4 /*0b100*/
#define NSE_SINGLE_FWD_VSI_LIST_EN_LB	0x5 /*0b101*/
#define NSE_SINGLE_FWD_QUEUE_EN_LB		0x6 /*0b110*/
#define NSE_SINGLE_FWD_DROP				0x7 /*0b111*/

#define NSE_SINGLE_FWD_VSI_ID_S		0
#define NSE_SINGLE_FWD_VSI_ID_M		(0xFF << NSE_SINGLE_FWD_VSI_ID_S)
#define NSE_SINGLE_FWD_VSI_LIST_ID_S	0
#define NSE_SINGLE_FWD_VSI_LIST_ID_M	(0x3FF << NSE_SINGLE_FWD_VSI_LIST_ID_S)
#define NSE_SINGLE_FWD_LAN_DISABLE	BIT(10)

/*definition for prune action*/
#define NSE_SINGLE_ACT_TYPE_PRUNE_S	13 /* Bit 15:13 - Action type for prune*/
#define NSE_SINGLE_ACT_TYPE_PRUNE_M	(0x7 << NSE_SINGLE_ACT_TYPE_PRUNE_S)
#define NSE_SINGLE_ACT_TYPE_PRUNE	0x2 /* 0b010, value for prune*/
#define NSE_SINGLE_PRUNE_AND_NOT	BIT(12)
#define NSE_SINGLE_PRUNE_VSI_LIST	BIT(11)

/*definition for count action*/
#define NSE_SINGLE_ACT_TYPE_COUNT_S	14 /* Bit 15:14 - Action type for count*/
#define NSE_SINGLE_ACT_TYPE_COUNT_M	(0x3 << NSE_SINGLE_ACT_TYPE_COUNT_S)
#define NSE_SINGLE_ACT_TYPE_COUNT	0x3 /* 0b11, value for count */
#define NSE_SINGLE_COUNT_BYTE		BIT(13) /*1: byte count, 0: pkt count*/
#define NSE_SINGLE_COUNT_ID_S		0
#define NSE_SINGLE_COUNT_ID_M		(0x1FFF << NSE_SINGLE_COUNT_ID_S)

/*definition for large action*/
#define NSE_SINGLE_LARGE_ACT_ID_S	0 /* Bit 14:0 - large act id */
#define NSE_SINGLE_LARGE_ACT_ID_M	(0x7FFF << NSE_SINGLE_LARGE_ACT_ID_S)
#define NSE_SINGLE_LARGE_ACT_FULL	BIT(15) /*set 1: full, 0: lite*/

/*definition for decap action*/
#define NSE_SINGLE_ACT_TYPE_DECAP_S	7 /* Bit 15:7 - Action type for decap act */
#define NSE_SINGLE_ACT_TYPE_DECAP_M	(0x1FF << NSE_SINGLE_ACT_TYPE_DECAP_S)
#define NSE_SINGLE_ACT_TYPE_DECAP	0x101 /*value for decap act*/

#define NSE_SINGLE_ACT_TYPE_DECAP_ECN	BIT(0) /*ecn inherit enable bit*/
#define NSE_SINGLE_ACT_TYPE_DECAP_DSCP	BIT(1) /*dscp inherit enable bit*/

/*definition for dup action*/
#define NSE_SINGLE_ACT_TYPE_DUP_S	7 /* Bit 15:7 - Action type for dup act */
#define NSE_SINGLE_ACT_TYPE_DUP_M	(0x1FF << NSE_SINGLE_ACT_TYPE_DUP_S)
#define NSE_SINGLE_ACT_TYPE_DUP		0x106 /*value for dup act*/
#define NSE_SINGLE_ACT_TYPE_DUP_CP_NUM_S	0 /* Bit 3:0 - copy num for dup act */
#define NSE_SINGLE_ACT_TYPE_DUP_CP_NUM_M	(0xF << NSE_SINGLE_ACT_TYPE_DUP_CP_NUM_S)

/*definition for goto action*/
#define NSE_SINGLE_ACT_TYPE_GOTO_S	7 /* Bit 15:7 - Action type for goto act */
#define NSE_SINGLE_ACT_TYPE_GOTO_M	(0x1FF << NSE_SINGLE_ACT_TYPE_GOTO_S)
#define NSE_SINGLE_ACT_TYPE_GOTO	0x107 /*value for goto act*/
#define NSE_SINGLE_ACT_TYPE_GOTO_CHAIN_ID_S	 0 /*  Bit 2:0 - dest chain id for goto act */
#define NSE_SINGLE_ACT_TYPE_GOTO_CHAIN_ID_M	(0x7 << NSE_SINGLE_ACT_TYPE_GOTO_CHAIN_ID_S)

/*definition for sflow action*/
#define NSE_SINGLE_ACT_TYPE_SFLOW_S	10 /* Bit 15:10 - Action type for sflow act */
#define NSE_SINGLE_ACT_TYPE_SFLOW_M	(0x3F << NSE_SINGLE_ACT_TYPE_SFLOW_S)
#define NSE_SINGLE_ACT_TYPE_SFLOW	0x23 /*value for sflow act*/
#define NSE_SINGLE_ACT_TYPE_SFLOW_VSI_ID_S	 0 /* Bit 7:0 - dest vsi id for sflow act */
#define NSE_SINGLE_ACT_TYPE_SFLOW_VSI_ID_M	(0xFF << NSE_SINGLE_ACT_TYPE_SFLOW_VSI_ID_S)

/*definition for set metadata action*/
#define NSE_SINGLE_ACT_TYPE_SET_MD_S	12 /* Bit 15:12 - Action type for set md act */
#define NSE_SINGLE_ACT_TYPE_SET_MD_M	(0xF << NSE_SINGLE_ACT_TYPE_SET_MD_S)
#define NSE_SINGLE_ACT_TYPE_SET_MD	0x9 /*value for set metadata act*/
#define NSE_SINGLE_ACT_TYPE_SET_MD_DST_ID_S	 8 /* Bit 10:8 - dest md id */
#define NSE_SINGLE_ACT_TYPE_SET_MD_DST_ID_M	(0x7 << NSE_SINGLE_ACT_TYPE_SET_MD_DST_ID_S)
#define NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_S	 0 /* Bit 7:0 - usr data offset */
#define NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_M	(0xFF << NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_S)

/*definition for policy/meter action*/
#define NSE_SINGLE_ACT_TYPE_METER_S	12 /* Bit 15:12 - Action type for meter*/
#define NSE_SINGLE_ACT_TYPE_METER_M	(0xF << NSE_SINGLE_ACT_TYPE_METER_S)
#define NSE_SINGLE_ACT_TYPE_METER	0xa /* 0b1010, value for meter */
#define NSE_SINGLE_METER_ID_S		0
#define NSE_SINGLE_METER_ID_M		(0x3FF << NSE_SINGLE_METER_ID_S)

	__le16 left_ptr;
#define NSE_LUT_NODE_LARGE_ACTION_EN	BIT(15)

	__le16 right_ptr;
#define NSE_LUT_NODE_IS_DELETED			BIT(15)

	/*if key is used for packet content, its type should be __be16*/
	__le16 key[5];
#define NSE_LUT_KEY_ROCE_FLAG_VLD_BIT	BIT(8)
#define NSE_LPM_PREFIX_M		0x7F

} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_LUT_NODE
 *  struct for cmd: NSE_AQ_OPC_UPDATE_LUT_NODE
 *  struct for cmd: NSE_AQ_OPC_REMOVE_LUT_NODE
 *  struct for cmd: NSE_AQ_OPC_GET_LUT_NODE
 */
struct nse_aqc_lut_nodes {
	__le16 count; /*element number in one buf */
	__le16 rsvd;
	struct nse_aqc_lut_node_elem elem[];
} __packed;

struct nse_aqc_bmc_mac_elem {
	__le16 op; /*1: add, 0: remove*/
	u8 mac[6];
} __packed;

struct nse_aqc_bmc_mac_event {
	__le16 count; /*element number in one buf */
	__le16 rsvd;
#define NSE_AQC_BMC_MAC_MAX_CNT 16
	struct nse_aqc_bmc_mac_elem elem[NSE_AQC_BMC_MAC_MAX_CNT];
} __packed;

struct nse_aqc_fast_act_info {
	__le16 action;
	__le16 res_type; /* resource type which action need */
#define NSE_FAST_ACT_INV_RES_TYPE	0xFFFF

} __packed;

struct nse_aqc_fast_lut_info {
	__le16 lut_id;
	__le16 node_id;

	/* if it is intermedia Lut, the result key index in Root Lut;
	 * if it is root lut, this field is unmeaningful.
	 */
	__le16 key_idx;

	/*if key is used for packet content, its type should be __be16*/
	__le16 key[5];
} __packed;

struct nse_aqc_lut_fast_node_action {
	__le16 node_state_id;
	__le16 act_ctrl;
#define NSE_FAST_ACT_DU_CNT_S	4 /* Bit 7:4 - du action count */
#define NSE_FAST_ACT_DU_CNT_M	(0xF << NSE_FAST_ACT_DU_CNT_S)

	struct nse_aqc_fast_act_info act[];
} __packed;

struct nse_aqc_lut_fast_node_match {
	u8 lut_num;
	u8 rt_idx;
	__le16 rsvd;
	struct nse_aqc_fast_lut_info lut[];
} __packed;

struct nse_aqc_lut_fast_node_elem {
	/* action field */
	struct nse_aqc_lut_fast_node_action action;
	/* match field */
	struct nse_aqc_lut_fast_node_match match;
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_LUT_FAST_NODE
 *  struct for cmd: NSE_AQ_OPC_UPDATE_LUT_FAST_NODE
 *  struct for cmd: NSE_AQ_OPC_REMOVE_LUT_FAST_NODE
 *  struct for cmd: NSE_AQ_OPC_GET_LUT_FAST_NODE
 */
struct nse_aqc_lut_fast_nodes {
	__le16 count; /*element number in one buf */
	struct nse_aqc_lut_fast_node_elem elem[];
} __packed;

struct nse_aqc_node_state_elem {
	__le16 node_state_id;
	__le16 rsvd;
	__le16 ctrl_info;
#define NSE_AQC_DU_DESC_CNT_S		0 /*bit 3:0*/
#define NSE_AQC_DU_DESC_CNT_M		(0xF << NSE_AQC_DU_DESC_CNT_S)
#define NSE_AQC_DU_ACTION_CNT_S		4 /*bit 7:4*/
#define NSE_AQC_DU_ACTION_CNT_M		(0xF << NSE_AQC_DU_ACTION_CNT_S)
#define NSE_AQC_AU_TASK_CNT_S		8 /*bit 12:8*/
#define NSE_AQC_AU_TASK_CNT_M		(0x1F << NSE_AQC_AU_TASK_CNT_S)
#define NSE_AQC_DU_STAT_MSB_S		13 /*bit 15:13*/
#define NSE_AQC_DU_STAT_MSB_M		(0x7 << NSE_AQC_DU_STAT_MSB_S)

	__le16 task_list_id;
#define NSE_AQC_TSK_LST_ID_S		0
#define NSE_AQC_TSK_LST_ID_M		(0x1FFF << NSE_AQC_TSK_LST_ID_S)

#define NSE_AQC_SLOWPATH_ORIGINAL	BIT(13)
#define NSE_AQC_SLOWPATH			BIT(14)
#define NSE_AQC_TASK_REFORMAT		BIT(15)

	__le16 act_or_desc[14];

/*definition of du desc*/
#define NSE_AQC_DU_DESC_SIZE_S		14 /*15:14 is du data size*/
#define NSE_AQC_DU_DESC_SIZE_M		(0x3 << NSE_AQC_DU_DESC_SIZE_S)
#define NSE_AQC_DU_DESC_SIZE_32B	1
#define NSE_AQC_DU_DESC_SIZE_64B	2
#define NSE_AQC_DU_DESC_SIZE_96B	3
#define NSE_AQC_DU_DESC_SIZE_128B	0
#define NSE_AQC_DU_DESC_DATA_ID_S	0 /*13:0 is du data id*/
#define NSE_AQC_DU_DESC_DATA_ID_M	(0x3FFF << NSE_AQC_DU_DESC_DATA_ID_S)

	/* how to align_to 32B, du_action and du_desc are both variable? */
#define NSE_AQC_NODE_STATE_SIZE		32
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_NODE_STATE
 *  struct for cmd: NSE_AQ_OPC_UPDATE_NODE_STATE
 *  struct for cmd: NSE_AQ_OPC_REMOVE_NODE_STATE
 *  struct for cmd: NSE_AQ_OPC_GET_NODE_STATE
 */
struct nse_aqc_node_states {
	__le16 count; /*element number in one buf */
	__le16 rsvd;
	struct nse_aqc_node_state_elem elem[];
} __packed;

struct nse_aqc_lite_node_state_elem {
	__le16 node_state_id;
	__le16 rsvd;
	__le16 ctrl_info;
#define NSE_AQC_LITE_SLOWPATH				BIT(0)
#define NSE_AQC_LITE_SLOWPATH_ORIGINAL		BIT(1)
	__le16 act[3];
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_LITE_NODE_STATE
 *  struct for cmd: NSE_AQ_OPC_UPDATE_LITE_NODE_STATE
 *  struct for cmd: NSE_AQ_OPC_REMOVE_LITE_NODE_STATE
 *  struct for cmd: NSE_AQ_OPC_GET_LITE_NODE_STATE
 */
struct nse_aqc_lite_node_states {
	__le16 count; /*element number in one buf */
	__le16 rsvd;
	struct nse_aqc_lite_node_state_elem elem[];
} __packed;

struct nse_aqc_task_cfg {
	u8 task_id;
#define NSE_AQC_TASK_TYPE_BIT			BIT(7)
#define NSE_AQC_TASK_TYPE_STANDARD		0
#define NSE_AQC_TASK_TYPE_PRIVATE		1

#define NSE_AQC_TASK_ID_S				0
#define NSE_AQC_TASK_ID_M				(0x7F << NSE_AQC_TASK_ID_S)

	u8 task_param;
} __packed;

struct nse_aqc_task_list_elem {
	__le16 task_list_id;
	__le16 rsvd;
	struct nse_aqc_task_cfg task[16];
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_TASK_LIST
 *  struct for cmd: NSE_AQ_OPC_UPDATE_TASK_LIST
 *  struct for cmd: NSE_AQ_OPC_REMOVE_TASK_LIST
 *  struct for cmd: NSE_AQ_OPC_GET_TASK_LIST
 */
struct nse_aqc_task_lists {
	__le16 count; /*element number in one buf */
	__le16 rsvd;
	struct nse_aqc_task_list_elem elem[];
} __packed;

struct nse_aqc_meter_cfg {
	__le32 policy_type;
#define NSE_AQC_METER_MODE_PPS			BIT(2) /*0-BPS; 1-PPS*/
#define NSE_AQC_METER_ALGORITHM_S		0
#define NSE_AQC_METER_ALGORITHM_M		(0x3 << NSE_AQC_METER_ALGORITHM_S)
#define NSE_AQC_METER_ALG_CBSR			0x0
#define NSE_AQC_METER_ALG_CASR			0x1
#define NSE_AQC_METER_ALG_CBTR			0x2
#define NSE_AQC_METER_ALG_CATR			0x3

	__le32 cir;
#define NSE_AQC_METER_CIR_S				0
#define NSE_AQC_METER_CIR_M				(0x7FFF << NSE_AQC_METER_CIR_S)
#define POLICY_HW_SPEED_LIMIT 0x2000

	__le32 cbs;
#define NSE_AQC_METER_CBS_S				0
#define NSE_AQC_METER_CBS_M				(0x1FFFFFFF << NSE_AQC_METER_CBS_S)
	__le32 pir;
#define NSE_AQC_METER_PIR_S				0
#define NSE_AQC_METER_PIR_M				(0x7FFF << NSE_AQC_METER_PIR_S)
	__le32 pbs;
#define NSE_AQC_METER_PBS_S				0
#define NSE_AQC_METER_PBS_M				(0x1FFFFFFF << NSE_AQC_METER_PBS_S)
} __packed;

/*  struct for cmd: NSE_AQ_OPC_SET_SFLOW
 *  struct for cmd: NSE_AQ_OPC_GET_SFLOW
 */
struct nse_aqc_sflow {
	__le16 rate;
} __packed;

struct nse_aqc_meter_elem {
	__le16 meter_id;
	__le16 rsvd;
	struct nse_aqc_meter_cfg cfg;
} __packed;

/*  struct for cmd: NSE_AQ_OPC_ADD_METER
 *  struct for cmd: NSE_AQ_OPC_UPDATE_METER
 *  struct for cmd: NSE_AQ_OPC_REMOVE_METER
 *  struct for cmd: NSE_AQ_OPC_GET_METER
 */
struct nse_aqc_meters {
	__le16 count; /*element number in one buf */
	__le16 rsvd;
	struct nse_aqc_meter_elem elem[];
} __packed;

struct nse_aqc_du_data_elem {
	__le16 du_data_id;
	__le16 data_len; /* value should be 1 or 2 or 3 or 4, 32B unit */
#define NSE_AQC_DU_DATA_SHIFT	5
	u8 usr_data[];
} __packed;

struct nse_aqc_sw_feature_elem {
	__le16 feature; /*feature type*/
#define NSE_AQC_FEATURE_TYPE_SW_MODE   0
#define NSE_AQC_FEATURE_TYPE_GOTO   1
#define NSE_AQC_FEATURE_TYPE_AU_DUP   2

	__le16 param;  /*feature parameter, per feature type*/
#define NSE_AQC_SW_MODE_LEGACY		0
#define NSE_AQC_SW_MODE_SWITCHDEV	1
#define NSE_AQC_GOTO_DISABLE	    0
#define NSE_AQC_GOTO_ENABLE		1
} __packed;

/*  struct for cmd: NSE_AQ_OPC_SET_FEATURE
 *  struct for cmd: NSE_AQ_OPC_GET_FEATURE
 */
struct nse_aqc_sw_feature {
	__le16 count; /*element number in one buf */
	__le16 rsvd;
	struct nse_aqc_sw_feature_elem elem[];
} __packed;

/*  struct for cmd: NSE_AQ_OPC_GET_CAPBILITY
 *  struct for cmd: NSE_AQ_OPC_SET_CAPBILITY
 */
struct nse_aqc_sw_cap {
	__le16 max_lut;
	__le16 max_tnode;
	__le16 max_recipe;
	__le16 max_profile;
	__le16 max_node;
	__le16 max_au_data;
	__le16 max_vsi_list;
	__le16 max_node_state;
	__le16 max_task_list;
	__le16 max_counter;
	__le16 max_meter;

	__le16 share_ratio;
} __packed;

/*  struct for cmd: NSE_AQ_OPC_GET_RESOURCE
 *  struct for cmd: NSE_AQ_OPC_GET_ALLOCED_RES_DESC
 */
struct nse_aqc_sw_usage {
#define NSE_AQC_MAX_PORT 4
	__le16 total;
	__le16 priv_total[NSE_AQC_MAX_PORT];
	__le16 priv_vld[NSE_AQC_MAX_PORT];

	__le16 share_used[NSE_AQC_MAX_PORT];
	__le16 share_vld;
	__le16 share_total;
} __packed;

/*	struct for cmd: NSE_AQ_OPC_ADD_DU_DATA
 *	struct for cmd: NSE_AQ_OPC_UPDATE_DU_DATA
 *	struct for cmd: NSE_AQ_OPC_REMOVE_DU_DATA
 *	struct for cmd: NSE_AQ_OPC_GET_DU_DATA
 */
struct nse_aqc_du_datas {
	__le16 count; /* element number in one buf */
	__le16 rsvd;
	struct nse_aqc_du_data_elem elem[];
} __packed;

struct nse_aqc_legacy_fltr_elem {
	__le16 fltr_type;
#define NSE_AQC_LEGACY_MAC_FLTR		0
#define NSE_AQC_LEGACY_VLAN_FLTR	1
#define NSE_AQC_LEGACY_ETHTYPE_FLTR 2

	__le16 index;
	__le32 content0;
/*definition for mac fltr*/
#define NSE_LEGACY_MAC_FLTR_EN	BIT(31) /* Bit 31 - enable bit */
#define NSE_LEGACY_MAC_FLTR_VSI_LIST_S	16/* Bit 23:16 - vsi list */
#define NSE_LEGACY_MAC_FLTR_VSI_LIST_M	(0xFF << NSE_LEGACY_MAC_FLTR_VSI_LIST_S)
#define NSE_LEGACY_MAC_FLTR_ADDR_HIGH_16_S	0/* Bit 15:0 - mac address high 16 bits */
#define NSE_LEGACY_MAC_FLTR_ADDR_HIGH_16_M	(0xFFFF << NSE_LEGACY_MAC_FLTR_ADDR_HIGH_16_S)

/*definition for vlan fltr*/
#define NSE_LEGACY_VLAN_FLTR_EN	BIT(31) /* Bit 31 - enable bit */
#define NSE_LEGACY_VLAN_FLTR_VSI_LIST_S	16/* Bit 23:16 - vsi list */
#define NSE_LEGACY_VLAN_FLTR_VSI_LIST_M	(0xFF << NSE_LEGACY_VLAN_FLTR_VSI_LIST_S)
#define NSE_LEGACY_VLAN_FLTR_VID_S	0/* Bit 11:0 - vlan id */
#define NSE_LEGACY_VLAN_FLTR_VID_M	(0xFFF << NSE_LEGACY_VLAN_FLTR_VID_S)

/*definition for ethtype fltr*/
#define NSE_LEGACY_ETHTYPE_FLTR_EN	BIT(16) /* Bit 16 - enable bit */
#define NSE_LEGACY_ETHTYPE_FLTR_ETYPE_S	0/* Bit 15:0 - ethernet type value*/
#define NSE_LEGACY_ETHTYPE_FLTR_ETYPE_M	(0xFFFF << NSE_LEGACY_ETHTYPE_FLTR_ETYPE_S)

	__le32 content1;
/*definition for mac fltr*/
#define NSE_LEGACY_MAC_FLTR_ADDR_LOW_32_S	0/* Bit 31:0 - mac address low 32 bits */
#define NSE_LEGACY_MAC_FLTR_ADDR_LOW_32_M	(0xFFFFFFFF << NSE_LEGACY_MAC_FLTR_ADDR_LOW_32_S)

/*definition for ethtype fltr*/
#define NSE_LEGACY_ETHTYPE_FLTR_VSI_LIST_S	0/* Bit 7:0 - vsi list*/
#define NSE_LEGACY_ETHTYPE_FLTR_VSI_LIST_M	(0xFF << NSE_LEGACY_ETHTYPE_FLTR_VSI_LIST_S)

} __packed;

/*	struct for cmd: NSE_AQ_OPC_SET_LEGACY_FILTER
 *	struct for cmd: NSE_AQ_OPC_GET_LEGACY_FILTER
 */
struct nse_aqc_legacy_fltrs {
	__le16 count; /* element number in one buf */
	__le16 rsvd;
	struct nse_aqc_legacy_fltr_elem elem[];
} __packed;

struct nse_aqc_policy_counter_elem {
	__le16 policy_id;
	__le16 rsvd0;
	__le32 rsvd1;
	__le64 p_counter_val; /*packet*/
	__le64 b_counter_val; /*byte*/
} __packed;

/*	struct for cmd: NSE_AQ_OPC_GET_POLICY_COUNTER
 *	struct for cmd: NSE_AQ_OPC_SET_POLICY_COUNTER
 */
struct nse_aqc_policy_counters {
	__le16 count;
	__le16 rsvd0;
	__le32 rsvd1;
	struct nse_aqc_policy_counter_elem elem[];
} __packed;

struct nse_aqc_sw_counter_elem {
	__le64 counter_val;
} __packed;

/*	struct for cmd: NSE_AQ_OPC_GET_COUNTER
 *	struct for cmd: NSE_AQ_OPC_SET_COUNTER
 */
struct nse_aqc_sw_counters {
	__le16 count;
	__le16 start_id;
	__le32 rsvd;
	struct nse_aqc_sw_counter_elem elem[];
} __packed;

/*	struct for cmd: NSE_AQ_OPC_GET_COUNTER
 *	struct for cmd: NSE_AQ_OPC_SET_COUNTER
 */
struct nse_aqc_sw_dma_counters {
	__le16 count;
	__le16 start_id;
	__le32 rsvd;
	__le32 addr_low;
	__le32 addr_high;
} __packed;

struct nse_aqc_set_port_params {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 cmd_flags;
#define NSE_AQC_SET_P_PARAMS_SAVE_BAD_PACKETS	BIT(0)
#define NSE_AQC_SET_P_PARAMS_PAD_SHORT_PACKETS	BIT(1)

	__le16 bad_frame_vsi;
#define NSE_AQC_SET_P_PARAMS_VSI_S	0
#define NSE_AQC_SET_P_PARAMS_VSI_M	(0xFF << NSE_AQC_SET_P_PARAMS_VSI_S)

	__le16 swid;
#define NSE_AQC_SET_P_PARAMS_SWID_S	0
#define NSE_AQC_SET_P_PARAMS_SWID_M	(0xFF << NSE_AQC_SET_P_PARAMS_SWID_S)

#define NSE_AQC_SET_P_PARAMS_SWID_VALID		BIT(15)

	u8 pad[2];
} __packed;

struct nse_aqc_vsi_props {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 vsi_abs_num;	/* absolute ID in LAN VSI space [0, 256) */

	__le16 valid_sections;
#define NSE_AQ_VSI_PROP_SECTION_SW_VALID			BIT(0)
#define NSE_AQ_VSI_PROP_SECTION_RXMAX_VALID			BIT(2)
#define NSE_AQ_VSI_PROP_SECTION_CTAG_VALID			BIT(3)
#define NSE_AQ_VSI_PROP_SECTION_STAG_VALID			BIT(4)
#define NSE_AQ_VSI_PROP_SECTION_PASID_VALID			BIT(5)
#define NSE_AQ_VSI_PROP_SECTION_PE_VALID			BIT(6)

#define NSE_AQ_VSI_PROP_SECTION_VALID_ALL (NSE_AQ_VSI_PROP_SECTION_SW_VALID | \
	NSE_AQ_VSI_PROP_SECTION_RXMAX_VALID | \
	NSE_AQ_VSI_PROP_SECTION_CTAG_VALID | \
	NSE_AQ_VSI_PROP_SECTION_STAG_VALID | \
	NSE_AQ_VSI_PROP_SECTION_PASID_VALID | \
	NSE_AQ_VSI_PROP_SECTION_PE_VALID)

	/* section: Switching
	 */

	union {
		struct {	/* for amber */

			__le32 rpp_per_vsi_ctxt;
#define NSE_AQ_VSI_SW_FLAG_RPP_RX_PRUNE			BIT(1) /* vlan rx filter en bit*/
#define NSE_AQ_VSI_SW_FLAG_RPP_SRC_PRUNE		BIT(3)
#define NSE_AQ_VSI_SW_FLAG_RPP_VSI_EN			BIT(4)
#define NSE_AQ_VSI_SW_FLAG_RPP_OVS_MISS			BIT(8)
#define NSE_AQ_VSI_SW_FLAG_RPP_DFLT_VSI			BIT(9)
#define NSE_AQ_VSI_SW_FLAG_RPP_MAC_SRC_PRUNE	BIT(10) /* rpp mac src prune used by VEPA Bridge*/
#define NSE_AQ_VSI_SW_FLAG_RPP_MIRR_EN			BIT(15)
#define NSE_AQ_VSI_SW_FLAG_RPP_MIRR_VSI_S		16
#define NSE_AQ_VSI_SW_FLAG_RPP_MIRR_VSI_M		(0xFF << NSE_AQ_VSI_SW_FLAG_RPP_MIRR_VSI_S)
#define NSE_AQ_VSI_SW_FLAG_RPP_SW_ID_S			24
#define NSE_AQ_VSI_SW_FLAG_RPP_SW_ID_M			(0xFF << NSE_AQ_VSI_SW_FLAG_RPP_SW_ID_S)

			__le32 tpp_per_vsi_ctxt;
		/* NSE_AQ_VSI_SW_FLAG_TPP_TX_PRUNE is hard-code to 0 in driver,
		 *  tx prune always do, tx prune en flag influence lan_dis only
		 */
#define NSE_AQ_VSI_SW_FLAG_TPP_TX_PRUNE			BIT(0)
#define NSE_AQ_VSI_SW_FLAG_TPP_RX_PRUNE			BIT(1) /* vlan rx filter en bit*/
#define NSE_AQ_VSI_SW_FLAG_TPP_ALLOW_DEST_OVRD	BIT(2)
#define NSE_AQ_VSI_SW_FLAG_TPP_SRC_PRUNE		BIT(3)
#define NSE_AQ_VSI_SW_FLAG_TPP_VSI_EN			BIT(4)
#define NSE_AQ_VSI_SW_FLAG_TPP_LAN_ENA			BIT(5)
#define NSE_AQ_VSI_SW_FLAG_TPP_TX_ALLOW_LB		BIT(6)
#define NSE_AQ_VSI_SW_FLAG_TPP_RX_ALLOW_LB		BIT(7)
#define NSE_AQ_VSI_SW_FLAG_TPP_OVS_MISS			BIT(8)
#define NSE_AQ_VSI_SW_FLAG_TPP_MAC_ANTI_SPOOF	BIT(10)
#define NSE_AQ_VSI_SW_FLAG_TPP_VLAN_ANTI_SPOOF	BIT(11)
#define NSE_AQ_VSI_SW_FLAG_TPP_MIRR_EN			BIT(15)
#define NSE_AQ_VSI_SW_FLAG_TPP_MIRR_VSI_S		16
#define NSE_AQ_VSI_SW_FLAG_TPP_MIRR_VSI_M		(0xFF << NSE_AQ_VSI_SW_FLAG_TPP_MIRR_VSI_S)
#define NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_S			24
#define NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_M			(0xFF << NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_S)

		} __packed;

		struct {	/* for moonstone */
			__le32 rsw_per_vsi_l2ctxt;
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_UPE	BIT(0)	/*Unicast promiscuous enable*/
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_MPE	BIT(1)	/*Multicast promiscuous enable*/
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_BAM	BIT(2)	/*Broadcast accept mode enable*/
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_VPE	BIT(3)	/*VLAN promiscuous enable*/
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_VACCEPT			BIT(4)
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_AUPE				BIT(5)
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_RX_DEF				BIT(6)
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_MAC_SRC_PRUNE		BIT(7)
#define NSE_AQ_VSI_L2_CTRL_FLAG_RSW_EG_MIRROR			BIT(8)

		} __packed;

		__le32 sw_section_dummy;

	} __packed;

	/* section: PE (RDMA)	-	owner: @renjunlin
	 */
	u8 pe_flags;
#define NSE_AQ_VSI_PE_FLAG_FLTR_EN		BIT(0)
	u8 pad_2[3];

	/* section: "RXMAX"
	 */
	__le32	rxmax;

	/* section: "CTag Handling"
	 */
	__le16 ctag_port_based_tci;

	__le16 ctag_host_insertion_mode;
#define NSE_AQ_VSI_CTAG_HOST_INSERTION_MODE_RSVD			0x00
#define NSE_AQ_VSI_CTAG_HOST_INSERTION_MODE_ACCEPT_UNTAGGED	0x01
#define NSE_AQ_VSI_CTAG_HOST_INSERTION_MODE_ACCEPT_TAGGED	0x02
#define NSE_AQ_VSI_CTAG_HOST_INSERTION_MODE_ACCEPT_ALL		0x03

	__le16 ctag_port_based;	/* true or false */

	__le16 ctag_host_expose_mode;
#define NSE_AQ_VSI_CTAG_HOST_EXPOSE_MODE_SHOW_ALL_IN_DESC	0x00
#define NSE_AQ_VSI_CTAG_HOST_EXPOSE_MODE_SHOW_UP_IN_DESC	0x01
#define NSE_AQ_VSI_CTAG_HOST_EXPOSE_MODE_SHOW_NONE			0x02
#define NSE_AQ_VSI_CTAG_HOST_EXPOSE_MODE_DO_NOTHING			0x03

	/* section: "STag Handling"
	 */
	__le16 stag_port_based_tci;

	__le16 stag_host_insertion_mode;
#define NSE_AQ_VSI_STAG_HOST_INSERTION_MODE_RSVD			0x00
#define NSE_AQ_VSI_STAG_HOST_INSERTION_MODE_ACCEPT_UNTAGGED	0x01
#define NSE_AQ_VSI_STAG_HOST_INSERTION_MODE_ACCEPT_TAGGED	0x02
#define NSE_AQ_VSI_STAG_HOST_INSERTION_MODE_ACCEPT_ALL		0x03

	__le16 stag_port_based;	/* true or false */

	__le16 stag_host_expose_mode;
#define NSE_AQ_VSI_STAG_HOST_EXPOSE_MODE_SHOW_ALL_IN_DESC	0x00
#define NSE_AQ_VSI_STAG_HOST_EXPOSE_MODE_SHOW_UP_IN_DESC	0x01
#define NSE_AQ_VSI_STAG_HOST_EXPOSE_MODE_SHOW_NONE			0x02
#define NSE_AQ_VSI_STAG_HOST_EXPOSE_MODE_DO_NOTHING			0x03

	__le16 stag_etype;	/* 0x88A8, 0x8100, 0x9100(maybe not use) */
	u8 pad_3[2];

	/* section: "PASID"
	 */
	union {
		struct {	/* for amber */
			__le32 pasid_flags;
#define NSE_AQ_VSI_PASID_FLAG_EN		BIT(0)	/* enable or not */

			__le32 pasid_id;
#define NSE_AQ_VSI_PASID_ID_S			0
#define NSE_AQ_VSI_PASID_ID_M			(0xFFFFF << NSE_AQ_VSI_PASID_ID_S)
#define NSE_AQ_VSI_PASID_ID_VALID		BIT(31)

		} __packed;

		__le32 pasid_section_dummy;

	} __packed;

} __packed;

struct nse_aqc_switch_rpp_set_bypass {
	struct nse_aqc_generic_common_hdr hdr;

	/* boolean: bypass RPP or not, true for bypass, false for not bypass */
	__le32 rpp_bypass;

	__le32 ll_ctrl_val;

} __packed;

struct nse_aqc_lmac_get_set_basic_cfg_type1 {
	struct nse_aqc_generic_common_hdr hdr;

	u8 rw;
	u8 pad[3];

	__le32 flags;
#define LMAC_TYPE1_BASIC_CFG_FLAG_TX_CFG		BIT(0)
#define LMAC_TYPE1_BASIC_CFG_FLAG_RX_CFG		BIT(1)
#define LMAC_TYPE1_BASIC_CFG_FLAG_PKT_FILTER	BIT(2)
#define LMAC_TYPE1_BASIC_CFG_FLAG_WD_TIMEOUT	BIT(3)

#define LMAC_TYPE1_BASIC_CFG_FLAGS_ALL		(LMAC_TYPE1_BASIC_CFG_FLAG_TX_CFG | \
	LMAC_TYPE1_BASIC_CFG_FLAG_RX_CFG | \
	LMAC_TYPE1_BASIC_CFG_FLAG_PKT_FILTER | \
	LMAC_TYPE1_BASIC_CFG_FLAG_WD_TIMEOUT)

	__le32 lmac_tx_cfg;

#define LMAC_TYPE1_TX_CFG_CS_S				31
#define LMAC_TYPE1_TX_CFG_CS_M				BIT(31)

	/* this 3 bits include SS_reserved and SS */
	/* here, SS = SS_2 + SS */
#define LMAC_TYPE1_TX_CFG_SS_S				28
#define LMAC_TYPE1_TX_CFG_SS_M				NSE_M(0x7, 28)

	#define LMAC_TYPE1_TX_CFG_SS_40G			0x0
	#define LMAC_TYPE1_TX_CFG_SS_25G			0x1
	#define LMAC_TYPE1_TX_CFG_SS_50G			0x2
	#define LMAC_TYPE1_TX_CFG_SS_100G			0x3
	#define LMAC_TYPE1_TX_CFG_SS_10G			0x4
	#define LMAC_TYPE1_TX_CFG_SS_5G				0x5
	#define LMAC_TYPE1_TX_CFG_SS_2_5_G			0x6
	#define LMAC_TYPE1_TX_CFG_SS_1_G			0x7

#define LMAC_TYPE1_TX_CFG_SS_3_S				27
#define LMAC_TYPE1_TX_CFG_SS_3_M				BIT(27)

#define LMAC_TYPE1_TX_CFG_SARC_S				20
#define LMAC_TYPE1_TX_CFG_SARC_M				NSE_M(0x7, 20)

#define LMAC_TYPE1_TX_CFG_JD_S				16
#define LMAC_TYPE1_TX_CFG_JD_M				BIT(16)

#define LMAC_TYPE1_TX_CFG_IFP_S				11
#define LMAC_TYPE1_TX_CFG_IFP_M				BIT(11)

#define LMAC_TYPE1_TX_CFG_IPG_S				8
#define LMAC_TYPE1_TX_CFG_IPG_M				NSE_M(0x7, 8)

#define LMAC_TYPE1_TX_CFG_ISR_S				4
#define LMAC_TYPE1_TX_CFG_ISR_M				NSE_M(0xF, 4)

#define LMAC_TYPE1_TX_CFG_ISM_S				3
#define LMAC_TYPE1_TX_CFG_ISM_M				BIT(3)

#define LMAC_TYPE1_TX_CFG_DDIC_S				1
#define LMAC_TYPE1_TX_CFG_DDIC_M				BIT(1)

#define LMAC_TYPE1_TX_CFG_TE_S				0
#define LMAC_TYPE1_TX_CFG_TE_M				BIT(0)

	__le32 lmac_rx_cfg;

#define LMAC_TYPE1_RX_CFG_GPSL_S				16
#define LMAC_TYPE1_RX_CFG_GPSL_M				NSE_M(0x3FFF, 16)

#define LMAC_TYPE1_RX_CFG_HDSMS_S				12
#define LMAC_TYPE1_RX_CFG_HDSMS_M				NSE_M(0x7, 12)

#define LMAC_TYPE1_RX_CFG_S2KP_S				11
#define LMAC_TYPE1_RX_CFG_S2KP_M				BIT(11)

#define LMAC_TYPE1_RX_CFG_LM_S				10
#define LMAC_TYPE1_RX_CFG_LM_M				BIT(10)

#define LMAC_TYPE1_RX_CFG_IPC_S				9
#define LMAC_TYPE1_RX_CFG_IPC_M				BIT(9)

#define LMAC_TYPE1_RX_CFG_JE_S				8
#define LMAC_TYPE1_RX_CFG_JE_M				BIT(8)

#define LMAC_TYPE1_RX_CFG_WD_S				7
#define LMAC_TYPE1_RX_CFG_WD_M				BIT(7)

#define LMAC_TYPE1_RX_CFG_GPSLCE_S			6
#define LMAC_TYPE1_RX_CFG_GPSLCE_M			BIT(6)

#define LMAC_TYPE1_RX_CFG_USP_S				5
#define LMAC_TYPE1_RX_CFG_USP_M				BIT(5)

#define LMAC_TYPE1_RX_CFG_SPEN_S				4
#define LMAC_TYPE1_RX_CFG_SPEN_M				BIT(4)

#define LMAC_TYPE1_RX_CFG_DCRCC_S				3
#define LMAC_TYPE1_RX_CFG_DCRCC_M				BIT(3)

#define LMAC_TYPE1_RX_CFG_CST_S				2
#define LMAC_TYPE1_RX_CFG_CST_M				BIT(2)

#define LMAC_TYPE1_RX_CFG_ACS_S				1
#define LMAC_TYPE1_RX_CFG_ACS_M				BIT(1)

#define LMAC_TYPE1_RX_CFG_RE_S				0
#define LMAC_TYPE1_RX_CFG_RE_M				BIT(0)

	__le32 lmac_pkt_filter;

#define LMAC_TYPE1_PKT_FILTER_RA_S			31
#define LMAC_TYPE1_PKT_FILTER_RA_M			BIT(31)

/* DNTU, IPFE, VTFE, HPF, SAF, SAIF - should be set to 0 */

#define LMAC_TYPE1_PKT_FILTER_PCF_S			6
#define LMAC_TYPE1_PKT_FILTER_PCF_M			NSE_M(0x3, 6)

	#define LMAC_TYPE1_PKT_FILTER_PCF_FORWARD_NONE		0x0
	#define LMAC_TYPE1_PKT_FILTER_PCF_FORWARD_ALL_BUT_FC	0x1
	#define LMAC_TYPE1_PKT_FILTER_PCF_FORWARD_ALL			0x2
	#define LMAC_TYPE1_PKT_FILTER_PCF_FORWARD_PASS_AF		0x3

/* DBF - should be set to 0 */

#define LMAC_TYPE1_PKT_FILTER_PM_S			4
#define LMAC_TYPE1_PKT_FILTER_PM_M			BIT(4)

/* DAIF, HMC, HUC - should be set to 0 */

#define LMAC_TYPE1_PKT_FILTER_PR_S			0
#define LMAC_TYPE1_PKT_FILTER_PR_M			BIT(0)

	__le32 lmac_wd_timeout;

#define LMAC_TYPE1_WD_TIMEOUT_PWE_S			8
#define LMAC_TYPE1_WD_TIMEOUT_PWE_M			BIT(8)

#define LMAC_TYPE1_WD_TIMEOUT_WTO_S			0
#define LMAC_TYPE1_WD_TIMEOUT_WTO_M			NSE_M(0xF, 0)

} __packed;

struct nse_aqc_lmac_get_set_basic_cfg {
	union {
		struct {
			struct nse_aqc_generic_common_hdr hdr;
			u8 rw;
			u8 pad[3];
		} __packed;

		struct nse_aqc_lmac_get_set_basic_cfg_type1 cfg_type1;
	};
} __packed;

enum lmac_type1_tx_stats_id {
	LMAC_TYPE1_Tx_Octet_Count_Good_Bad_Low,
	LMAC_TYPE1_Tx_Octet_Count_Good_Bad_High,
	LMAC_TYPE1_Tx_Frame_Count_Good_Bad_Low,
	LMAC_TYPE1_Tx_Frame_Count_Good_Bad_High,
	LMAC_TYPE1_Tx_Broadcast_Frames_Good_Low,
	LMAC_TYPE1_Tx_Broadcast_Frames_Good_High,
	LMAC_TYPE1_Tx_Multicast_Frames_Good_Low,
	LMAC_TYPE1_Tx_Multicast_Frames_Good_High,
	LMAC_TYPE1_Tx_64Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_64Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_65To127Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_65To127Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_128To255Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_128To255Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_256To511Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_256To511Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_512To1023Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_512To1023Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_1024ToMaxOctets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_1024ToMaxOctets_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_Unicast_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_Unicast_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_Multicast_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_Multicast_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_Broadcast_Frames_Good_Bad_Low,
	LMAC_TYPE1_Tx_Broadcast_Frames_Good_Bad_High,
	LMAC_TYPE1_Tx_Underflow_Error_Frames_Low,
	LMAC_TYPE1_Tx_Underflow_Error_Frames_High,
	LMAC_TYPE1_Tx_Octet_Count_Good_Low,
	LMAC_TYPE1_Tx_Octet_Count_Good_High,
	LMAC_TYPE1_Tx_Frame_Count_Good_Low,
	LMAC_TYPE1_Tx_Frame_Count_Good_High,
	LMAC_TYPE1_Tx_Pause_Frames_Low,
	LMAC_TYPE1_Tx_Pause_Frames_High,
	LMAC_TYPE1_Tx_VLAN_Frames_Good_Low,
	LMAC_TYPE1_Tx_VLAN_Frames_Good_High,

	LMAC_TYPE1_TX_STATS_ID_MAX,
};

enum lmac_type1_rx_stats_id {
	LMAC_TYPE1_Rx_Frame_Count_Good_Bad_Low,
	LMAC_TYPE1_Rx_Frame_Count_Good_Bad_High,
	LMAC_TYPE1_Rx_Octet_Count_Good_Bad_Low,
	LMAC_TYPE1_Rx_Octet_Count_Good_Bad_High,
	LMAC_TYPE1_Rx_Octet_Count_Good_Low,
	LMAC_TYPE1_Rx_Octet_Count_Good_High,
	LMAC_TYPE1_Rx_Broadcast_Frames_Good_Low,
	LMAC_TYPE1_Rx_Broadcast_Frames_Good_High,
	LMAC_TYPE1_Rx_Multicast_Frames_Good_Low,
	LMAC_TYPE1_Rx_Multicast_Frames_Good_High,
	LMAC_TYPE1_Rx_CRC_Error_Frames_Low,
	LMAC_TYPE1_Rx_CRC_Error_Frames_High,
	LMAC_TYPE1_Rx_Runt_Error_Frames,
	LMAC_TYPE1_Rx_Jabber_Error_Frames,
	LMAC_TYPE1_Rx_Undersize_Frames_Good,
	LMAC_TYPE1_Rx_Oversize_Frames_Good,
	LMAC_TYPE1_Rx_64Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Rx_64Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Rx_65To127Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Rx_65To127Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Rx_128To255Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Rx_128To255Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Rx_256To511Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Rx_256To511Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Rx_512To1023Octets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Rx_512To1023Octets_Frames_Good_Bad_High,
	LMAC_TYPE1_Rx_1024ToMaxOctets_Frames_Good_Bad_Low,
	LMAC_TYPE1_Rx_1024ToMaxOctets_Frames_Good_Bad_High,
	LMAC_TYPE1_Rx_Unicast_Frames_Good_Low,
	LMAC_TYPE1_Rx_Unicast_Frames_Good_High,
	LMAC_TYPE1_Rx_Length_Error_Frames_Low,
	LMAC_TYPE1_Rx_Length_Error_Frames_High,
	LMAC_TYPE1_Rx_OutofRange_Frames_Low,
	LMAC_TYPE1_Rx_OutofRange_Frames_High,
	LMAC_TYPE1_Rx_Pause_Frames_Low,
	LMAC_TYPE1_Rx_Pause_Frames_High,
	LMAC_TYPE1_Rx_VLAN_Frames_Good_Bad_Low,
	LMAC_TYPE1_Rx_VLAN_Frames_Good_Bad_High,
	LMAC_TYPE1_Rx_Watchdog_Error_Frames,

	LMAC_TYPE1_RX_STATS_ID_MAX,
};

struct nse_aqc_lmac_stats_type1 {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 tx_stats[LMAC_TYPE1_TX_STATS_ID_MAX];
	__le32 rx_stats[LMAC_TYPE1_RX_STATS_ID_MAX];

	__le32 fc_lxofftxc;
	__le32 fc_lxontxc;
	__le32 fc_pxon2xoffc[8];
	__le32 fc_pxofftxc[8];
	__le32 fc_pxontxc[8];
	__le32 fc_lxoffrxc;
	__le32 fc_lxonrxc;
	__le32 fc_pxoffrxc[8];
	__le32 fc_pxonrxc[8];

} __packed;

enum lmac_type2_rx_stats_id {
	LMAC_TYPE2_cntr_rx_fragments_lo,
	LMAC_TYPE2_cntr_rx_fragments_hi,

	LMAC_TYPE2_cntr_rx_jabbers_lo,
	LMAC_TYPE2_cntr_rx_jabbers_hi,

	LMAC_TYPE2_cntr_rx_dummy_0_lo,
	LMAC_TYPE2_cntr_rx_dummy_0_hi,

	LMAC_TYPE2_cntr_rx_fcs_err_okpkt_lo,
	LMAC_TYPE2_cntr_rx_fcs_err_okpkt_hi,

	LMAC_TYPE2_cntr_rx_mcast_data_err_lo,
	LMAC_TYPE2_cntr_rx_mcast_data_err_hi,

	LMAC_TYPE2_cntr_rx_bcast_data_err_lo,
	LMAC_TYPE2_cntr_rx_bcast_data_err_hi,

	LMAC_TYPE2_cntr_rx_ucast_data_err_lo,
	LMAC_TYPE2_cntr_rx_ucast_data_err_hi,

	LMAC_TYPE2_cntr_rx_mcast_ctrl_err_lo,
	LMAC_TYPE2_cntr_rx_mcast_ctrl_err_hi,

	LMAC_TYPE2_cntr_rx_bcast_ctrl_err_lo,
	LMAC_TYPE2_cntr_rx_bcast_ctrl_err_hi,

	LMAC_TYPE2_cntr_rx_ucast_ctrl_err_lo,
	LMAC_TYPE2_cntr_rx_ucast_ctrl_err_hi,

	LMAC_TYPE2_cntr_rx_pause_err_lo,
	LMAC_TYPE2_cntr_rx_pause_err_hi,

	LMAC_TYPE2_cntr_rx_64b_lo,
	LMAC_TYPE2_cntr_rx_64b_hi,

	LMAC_TYPE2_cntr_rx_65to127b_lo,
	LMAC_TYPE2_cntr_rx_65to127b_hi,

	LMAC_TYPE2_cntr_rx_128to255b_lo,
	LMAC_TYPE2_cntr_rx_128to255b_hi,

	LMAC_TYPE2_cntr_rx_256to511b_lo,
	LMAC_TYPE2_cntr_rx_256to511b_hi,

	LMAC_TYPE2_cntr_rx_512to1023b_lo,
	LMAC_TYPE2_cntr_rx_512to1023b_hi,

	LMAC_TYPE2_cntr_rx_1024to1518b_lo,
	LMAC_TYPE2_cntr_rx_1024to1518b_hi,

	LMAC_TYPE2_cntr_rx_1519tomaxb_lo,
	LMAC_TYPE2_cntr_rx_1519tomaxb_hi,

	LMAC_TYPE2_cntr_rx_oversize_lo,
	LMAC_TYPE2_cntr_rx_oversize_hi,

	LMAC_TYPE2_cntr_rx_mcast_data_ok_lo,
	LMAC_TYPE2_cntr_rx_mcast_data_ok_hi,

	LMAC_TYPE2_cntr_rx_bcast_data_ok_lo,
	LMAC_TYPE2_cntr_rx_bcast_data_ok_hi,

	LMAC_TYPE2_cntr_rx_ucast_data_ok_lo,
	LMAC_TYPE2_cntr_rx_ucast_data_ok_hi,

	LMAC_TYPE2_cntr_rx_mcast_ctrl_lo,
	LMAC_TYPE2_cntr_rx_mcast_ctrl_hi,

	LMAC_TYPE2_cntr_rx_bcast_ctrl_lo,
	LMAC_TYPE2_cntr_rx_bcast_ctrl_hi,

	LMAC_TYPE2_cntr_rx_ucast_ctrl_lo,
	LMAC_TYPE2_cntr_rx_ucast_ctrl_hi,

	LMAC_TYPE2_cntr_rx_pause_lo,
	LMAC_TYPE2_cntr_rx_pause_hi,

	LMAC_TYPE2_cntr_rx_runt_lo,
	LMAC_TYPE2_cntr_rx_runt_hi,

	LMAC_TYPE2_cntr_rx_st_lo,
	LMAC_TYPE2_cntr_rx_st_hi,

	LMAC_TYPE2_cntr_rx_lenerr_lo,
	LMAC_TYPE2_cntr_rx_lenerr_hi,

	LMAC_TYPE2_cntr_rx_pfc_err_lo,
	LMAC_TYPE2_cntr_rx_pfc_err_hi,

	LMAC_TYPE2_cntr_rx_pfc_lo,
	LMAC_TYPE2_cntr_rx_pfc_hi,

	LMAC_TYPE2_cntr_rx_payloadoctetsok_lo,
	LMAC_TYPE2_cntr_rx_payloadoctetsok_hi,

	LMAC_TYPE2_cntr_rx_octetsok_lo,
	LMAC_TYPE2_cntr_rx_octetsok_hi,

	LMAC_TYPE2_cntr_rx_malformed_lo,
	LMAC_TYPE2_cntr_rx_malformed_hi,

	LMAC_TYPE2_cntr_rx_dropped_lo,
	LMAC_TYPE2_cntr_rx_dropped_hi,

	LMAC_TYPE2_cntr_rx_badlt_lo,
	LMAC_TYPE2_cntr_rx_badlt_hi,

	LMAC_TYPE2_cntr_rx_total_ptp_ts,

	LMAC_TYPE2_RX_STATS_ID_MAX,
};

enum lmac_type2_tx_stats_id {
	LMAC_TYPE2_cntr_tx_fragments_lo,
	LMAC_TYPE2_cntr_tx_fragments_hi,

	LMAC_TYPE2_cntr_tx_jabbers_lo,
	LMAC_TYPE2_cntr_tx_jabbers_hi,

	LMAC_TYPE2_cntr_tx_dummy_0_lo,
	LMAC_TYPE2_cntr_tx_dummy_0_hi,

	LMAC_TYPE2_cntr_tx_fcs_err_okpkt_lo,
	LMAC_TYPE2_cntr_tx_fcs_err_okpkt_hi,

	LMAC_TYPE2_cntr_tx_mcast_data_err_lo,
	LMAC_TYPE2_cntr_tx_mcast_data_err_hi,

	LMAC_TYPE2_cntr_tx_bcast_data_err_lo,
	LMAC_TYPE2_cntr_tx_bcast_data_err_hi,

	LMAC_TYPE2_cntr_tx_ucast_data_err_lo,
	LMAC_TYPE2_cntr_tx_ucast_data_err_hi,

	LMAC_TYPE2_cntr_tx_mcast_ctrl_err_lo,
	LMAC_TYPE2_cntr_tx_mcast_ctrl_err_hi,

	LMAC_TYPE2_cntr_tx_bcast_ctrl_err_lo,
	LMAC_TYPE2_cntr_tx_bcast_ctrl_err_hi,

	LMAC_TYPE2_cntr_tx_ucast_ctrl_err_lo,
	LMAC_TYPE2_cntr_tx_ucast_ctrl_err_hi,

	LMAC_TYPE2_cntr_tx_pause_err_lo,
	LMAC_TYPE2_cntr_tx_pause_err_hi,

	LMAC_TYPE2_cntr_tx_64b_lo,
	LMAC_TYPE2_cntr_tx_64b_hi,

	LMAC_TYPE2_cntr_tx_65to127b_lo,
	LMAC_TYPE2_cntr_tx_65to127b_hi,

	LMAC_TYPE2_cntr_tx_128to255b_lo,
	LMAC_TYPE2_cntr_tx_128to255b_hi,

	LMAC_TYPE2_cntr_tx_256to511b_lo,
	LMAC_TYPE2_cntr_tx_256to511b_hi,

	LMAC_TYPE2_cntr_tx_512to1023b_lo,
	LMAC_TYPE2_cntr_tx_512to1023b_hi,

	LMAC_TYPE2_cntr_tx_1024to1518b_lo,
	LMAC_TYPE2_cntr_tx_1024to1518b_hi,

	LMAC_TYPE2_cntr_tx_1519tomaxb_lo,
	LMAC_TYPE2_cntr_tx_1519tomaxb_hi,

	LMAC_TYPE2_cntr_tx_oversize_lo,
	LMAC_TYPE2_cntr_tx_oversize_hi,

	LMAC_TYPE2_cntr_tx_mcast_data_ok_lo,
	LMAC_TYPE2_cntr_tx_mcast_data_ok_hi,

	LMAC_TYPE2_cntr_tx_bcast_data_ok_lo,
	LMAC_TYPE2_cntr_tx_bcast_data_ok_hi,

	LMAC_TYPE2_cntr_tx_ucast_data_ok_lo,
	LMAC_TYPE2_cntr_tx_ucast_data_ok_hi,

	LMAC_TYPE2_cntr_tx_mcast_ctrl_lo,
	LMAC_TYPE2_cntr_tx_mcast_ctrl_hi,

	LMAC_TYPE2_cntr_tx_bcast_ctrl_lo,
	LMAC_TYPE2_cntr_tx_bcast_ctrl_hi,

	LMAC_TYPE2_cntr_tx_ucast_ctrl_lo,
	LMAC_TYPE2_cntr_tx_ucast_ctrl_hi,

	LMAC_TYPE2_cntr_tx_pause_lo,
	LMAC_TYPE2_cntr_tx_pause_hi,

	LMAC_TYPE2_cntr_tx_runt_lo,
	LMAC_TYPE2_cntr_tx_runt_hi,

	LMAC_TYPE2_cntr_tx_st_lo,
	LMAC_TYPE2_cntr_tx_st_hi,

	LMAC_TYPE2_cntr_tx_lenerr_lo,
	LMAC_TYPE2_cntr_tx_lenerr_hi,

	LMAC_TYPE2_cntr_tx_pfc_err_lo,
	LMAC_TYPE2_cntr_tx_pfc_err_hi,

	LMAC_TYPE2_cntr_tx_pfc_lo,
	LMAC_TYPE2_cntr_tx_pfc_hi,

	LMAC_TYPE2_cntr_tx_payloadoctetsok_lo,
	LMAC_TYPE2_cntr_tx_payloadoctetsok_hi,

	LMAC_TYPE2_cntr_tx_octetsok_lo,
	LMAC_TYPE2_cntr_tx_octetsok_hi,

	LMAC_TYPE2_cntr_tx_malformed_lo,
	LMAC_TYPE2_cntr_tx_malformed_hi,

	LMAC_TYPE2_cntr_tx_dropped_lo,
	LMAC_TYPE2_cntr_tx_dropped_hi,

	LMAC_TYPE2_cntr_tx_badlt_lo,
	LMAC_TYPE2_cntr_tx_badlt_hi,

	LMAC_TYPE2_cntr_tx_total_ptp_pkts,

	LMAC_TYPE2_cntr_tx_total_1step_ptp_pkts,

	LMAC_TYPE2_cntr_tx_total_2step_ptp_pkts,

	LMAC_TYPE2_cntr_tx_total_v1_ptp_pkts,

	LMAC_TYPE2_cntr_tx_total_v2_ptp_pkts,

	LMAC_TYPE2_TX_STATS_ID_MAX,
};

struct nse_aqc_lmac_stats_type2 {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 tx_stats[LMAC_TYPE2_TX_STATS_ID_MAX];
	__le32 rx_stats[LMAC_TYPE2_RX_STATS_ID_MAX];

} __packed;

struct nse_aqc_lmac_stats {
	union {
		struct nse_aqc_generic_common_hdr hdr;
		struct nse_aqc_lmac_stats_type1 stats_type1;
		struct nse_aqc_lmac_stats_type2 stats_type2;
	};
} __packed;

enum nse_nic_type {
	NSE_NIC_TYPE_UNKNOWN = 0,
	NSE_NIC_TYPE_1000BASE_T,	/* only for fpga test */
	NSE_NIC_TYPE_SFP,
	NSE_NIC_TYPE_QSFP,
	NSE_NIC_TYPE_BACKPLANE,

	NSE_NIC_TYPE_MAX,
};

enum nse_ephy_type {
	EPHY_TYPE_NONE,	/* backplane is none */

	EPHY_TYPE_SFP,

	EPHY_TYPE_QSFP,

	EPHY_TYPE_MII,

	EPHY_TYPE_GEN_1G,	/* used by Amber FPGA or any future FPGA */
};

enum xsfp_mng_if_type {	/* sfp, qsfp */
	XSFP_MNG_IF_TYPE_UNKNOWN,

	XSFP_MNG_IF_TYPE_SFF8472,	/* for SFP */
	XSFP_MNG_IF_TYPE_SFF8636,	/* for QSFP */
	XSFP_MNG_IF_TYPE_CMIS,
};

enum nse_media_type_bits {
	MEDIA_BASET_BIT = 0,
	MEDIA_FIBER_BIT = 1,
	MEDIA_DAC_BIT = 2,
	MEDIA_BACKPLANE_BIT = 3,
	MEDIA_AUI_BIT = 4,
};

#define MEDIA_UNKNOWN		0
#define MEDIA_BASET			BIT(MEDIA_BASET_BIT)
#define MEDIA_FIBER			BIT(MEDIA_FIBER_BIT)
#define MEDIA_DAC			BIT(MEDIA_DAC_BIT)
#define MEDIA_BACKPLANE		BIT(MEDIA_BACKPLANE_BIT)
#define MEDIA_AUI			BIT(MEDIA_AUI_BIT)

/* AN logic specify
 *
 *		_NONE
 *			means we don't advertise any FEC
 *
 *
 *		_AUTO
 *
 *			we advertise FEC ( RS in preference, according to link_types)
 *			but actual FEC setting depends on an_outcome() ( & lp_advertisement)
 *
 *
 *  If AN logic not enabled, but set fixed link, then should only _NONE or _BASER/_RS (according to
 * fixed link_type)
 *
 *
 * When used as "supported" bitmap field, only _BASER and _RS are specified in the bitmap
 */
enum nse_eth_fec_bits {
	FEC_RS_BIT		= 0,
	FEC_BASER_BIT	= 1,
	FEC_OFF_BIT		= 2,

	FEC_AUTO_BIT	= 16,	/* FEC switch logic for both set_link and start_an */
};

#define FEC_NONE	0	/* consider as FEC_OFF most case */
#define FEC_RS		BIT(FEC_RS_BIT)
#define FEC_BASER	BIT(FEC_BASER_BIT)
#define FEC_OFF		BIT(FEC_OFF_BIT)
/* FEC auto switch logic for both set_link and start_an */
#define FEC_AUTO	BIT(FEC_AUTO_BIT)

struct nse_aqc_lmac_phy_event_ephy_sfp {
	__le32 mod_abs;
	__le32 tx_fault;
	__le32 rx_los;

} __packed;

struct nse_aqc_lmac_phy_event_ephy_qsfp {
	__le32 modprsl;

	__le32 mng_if_type;	/* enum xsfp_mng_if_type */

	union {
		struct {
			u8 status_indicators;
			u8 interrupt_flags[19];
		} __packed sff8636;

		struct {
			__le32 dummy;
		} __packed cmis;
	};

} __packed;

struct nse_aqc_lmac_phy_event_ephy {
	__le32 ephy_type;

	union {
		struct nse_aqc_lmac_phy_event_ephy_sfp sfp;
		struct nse_aqc_lmac_phy_event_ephy_qsfp qsfp;
	};

} __packed;

struct nse_aqc_lmac_phy_event_eth {
	__le32 evt_id;
#define NSE_AQC_LMAC_PHY_EVT_ETH_LSC	0x0			/* link status change */

	union {
		struct {
			__le32 link_status;
			__le32 link_speed;		/* NSE_AQ_LINK_SPEED_XXX */
		} __packed lsc;
	};
} __packed;

struct nse_aqc_lmac_phy_event {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 evt_src;
#define NSE_AQC_LMAC_PHY_EVT_SRC_UNKNOWN		0x0
#define NSE_AQC_LMAC_PHY_EVT_SRC_LMAC			0x1
#define NSE_AQC_LMAC_PHY_EVT_SRC_LPCS			0x2
#define NSE_AQC_LMAC_PHY_EVT_SRC_IPHY			0x3
#define NSE_AQC_LMAC_PHY_EVT_SRC_EPHY			0x4
#define NSE_AQC_LMAC_PHY_EVT_SRC_ETH			0x5		/* overall */

	__le32 flags;
#define NSE_AQC_LMAC_PHY_EVT_FLAG_NO_DETAIL_DATA	BIT(0)

	union {
		struct nse_aqc_lmac_phy_event_ephy evt_ephy;
		struct nse_aqc_lmac_phy_event_eth evt_eth;
	};

} __packed;

struct nse_aqc_ephy_cmd_sfp {
	__le32 cmd;
#define EPHY_CMD_SFP_TX_DISABLE			0x0
#define EPHY_CMD_SFP_RATE_SELECT		0x1
#define EPHY_CMD_SFP_READ_BYTES			0x2
#define EPHY_CMD_SFP_WRITE_BYTES		0x3
#define EPHY_CMD_SFP_GET_PIN_STATUS		0x4
/* similar to READ_BYTES, but read cached bytes in buffer */
#define EPHY_CMD_SFP_READ_BYTES_IN_CBUF	0x5
#define EPHY_CMD_SFP_ADDR_CHANGE		0x6	/* <<SFF-8472>> / 8.9 Addressing Modes */

	__le32 mng_if_type;	/* enum xsfp_mng_if_type */

	union {
		/* cmd: TX_DISABLE  */
		__le32 tx_disable;	/* 1 or 0 */

		/* cmd: RATE_SELECT */
		struct {
			__le32 rs0;
			__le32 rs1;
		} __packed rs;

		/* cmd: READ_BYTES, WRITE_BYTES, READ_BYTES_IN_CBUF */
		struct {
			u8 address;	/* 0xA0 or 0xA2 */
			u8 bank;		/* CMIS only */
			u8 page;
			u8 bytes_offset;
			u8 bytes_len;
			u8 pad_0[3];

			u8 bytes[256];
		} __packed rw_bytes;

		/* cmd: GET_PIN_STATUS */
		struct {
			__le32 mod_abs;
			__le32 tx_fault;
			__le32 rx_los;
		} __packed pin_status;

		/* cmd: ADDR_CHANGE */
		struct {
			u8 address;	/* 0xA0 or 0xA2 */
		} __packed addr_change;
	};

} __packed;

struct nse_aqc_ephy_cmd_qsfp {
	__le32 cmd;
#define EPHY_CMD_QSFP_RESET			0x0
#define EPHY_CMD_QSFP_SET_LPMODE	0x1
#define EPHY_CMD_QSFP_READ_BYTES	0x2
#define EPHY_CMD_QSFP_WRITE_BYTES	0x3
#define EPHY_CMD_QSFP_GET_PIN_STATUS			0x4
/* similar to READ_BYTES, but read cached bytes in buffer */
#define EPHY_CMD_QSFP_READ_BYTES_IN_CBUF		0x5

	__le32 mng_if_type;	/* enum xsfp_mng_if_type */

	union {
		/* cmd: SET_LPMODE  */
		__le32 lpmode;	/* 1 or 0 */

		/* cmd: READ_BYTES, WRITE_BYTES, READ_BYTES_IN_CBUF */
		struct {
			u8 address;	/* 0xA0 or 0xA2 */
			u8 bank;		/* CMIS only */
			u8 page;
			u8 bytes_offset;
			u8 bytes_len;
			u8 pad_0[3];

			u8 bytes[256];
		} __packed rw_bytes;

		/* cmd: GET_PIN_STATUS */
		struct {
			__le32 modprsl;
			__le32 intl;
		} __packed pin_status;
	};

} __packed;

struct nse_aqc_ephy_cmd {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 ephy_type;

	__le32 result;

	union {
		struct nse_aqc_ephy_cmd_sfp sfp;
		struct nse_aqc_ephy_cmd_qsfp qsfp;
	};

} __packed;

enum nse_eth_link_types {
	NSE_ETH_LINK_TYPE_1GBaseT_BIT = 0,	/* for pldm and fpga test */

	NSE_ETH_LINK_TYPE_10GbaseR_BIT,		/* including -LR, -SR, -ER, -LRM */

#define NSE_ETH_LINK_TYPE_10GbaseSR_BIT		NSE_ETH_LINK_TYPE_10GbaseR_BIT
#define NSE_ETH_LINK_TYPE_10GbaseCR_BIT		NSE_ETH_LINK_TYPE_10GbaseR_BIT
#define NSE_ETH_LINK_TYPE_10GbaseKR_BIT		NSE_ETH_LINK_TYPE_10GbaseR_BIT

	NSE_EHT_LINK_TYPE_10GbaseX_BIT,		/* 10GBASE-X, 10GbaseKX4, XAUI */

#define NSE_EHT_LINK_TYPE_10GbaseKX4_BIT	NSE_EHT_LINK_TYPE_10GbaseX_BIT
#define NSE_EHT_LINK_TYPE_10GbaseXAUI_BIT	NSE_EHT_LINK_TYPE_10GbaseX_BIT

	NSE_ETH_LINK_TYPE_25GbaseR_BIT,			/* SR, CR, KR */
	NSE_ETH_LINK_TYPE_25GbaseRS_BIT,

#define NSE_ETH_LINK_TYPE_25GbaseSR_BIT		NSE_ETH_LINK_TYPE_25GbaseR_BIT
#define NSE_ETH_LINK_TYPE_25GbaseCR_BIT		NSE_ETH_LINK_TYPE_25GbaseR_BIT
#define NSE_ETH_LINK_TYPE_25GbaseKR_BIT		NSE_ETH_LINK_TYPE_25GbaseR_BIT

#define NSE_ETH_LINK_TYPE_25GbaseCRS_BIT	NSE_ETH_LINK_TYPE_25GbaseRS_BIT
#define NSE_ETH_LINK_TYPE_25GbaseKRS_BIT	NSE_ETH_LINK_TYPE_25GbaseRS_BIT

	NSE_ETH_LINK_TYPE_40GbaseR4_BIT,

#define	NSE_ETH_LINK_TYPE_40GbaseSR4_BIT	NSE_ETH_LINK_TYPE_40GbaseR4_BIT
#define	NSE_ETH_LINK_TYPE_40GbaseCR4_BIT	NSE_ETH_LINK_TYPE_40GbaseR4_BIT
#define	NSE_ETH_LINK_TYPE_40GbaseKR4_BIT	NSE_ETH_LINK_TYPE_40GbaseR4_BIT

	NSE_ETH_LINK_TYPE_50GbaseR2_BIT,
	NSE_ETH_LINK_TYPE_50GbaseR1_BIT,

#define NSE_ETH_LINK_TYPE_50GbaseSR2_BIT	NSE_ETH_LINK_TYPE_50GbaseR2_BIT
#define NSE_ETH_LINK_TYPE_50GbaseCR2_BIT	NSE_ETH_LINK_TYPE_50GbaseR2_BIT
#define NSE_ETH_LINK_TYPE_50GbaseKR2_BIT	NSE_ETH_LINK_TYPE_50GbaseR2_BIT

#define NSE_ETH_LINK_TYPE_50GbaseSR1_BIT	NSE_ETH_LINK_TYPE_50GbaseR1_BIT
#define NSE_ETH_LINK_TYPE_50GbaseCR1_BIT	NSE_ETH_LINK_TYPE_50GbaseR1_BIT
#define NSE_ETH_LINK_TYPE_50GbaseKR1_BIT	NSE_ETH_LINK_TYPE_50GbaseR1_BIT

	NSE_ETH_LINK_TYPE_50GAUI2_BIT,
	NSE_ETH_LINK_TYPE_50GAUI1_BIT,

	NSE_ETH_LINK_TYPE_100GbaseR4_BIT,	/* SR4, CR4, KR4 */
	NSE_ETH_LINK_TYPE_100GbaseR2_BIT,	/* SR2, CR2, KR2 */
	NSE_ETH_LINK_TYPE_100GbaseR1_BIT,	/* SR1, CR1, KR1 */

#define NSE_ETH_LINK_TYPE_100GbaseSR4_BIT	NSE_ETH_LINK_TYPE_100GbaseR4_BIT
#define NSE_ETH_LINK_TYPE_100GbaseCR4_BIT	NSE_ETH_LINK_TYPE_100GbaseR4_BIT
#define NSE_ETH_LINK_TYPE_100GbaseKR4_BIT	NSE_ETH_LINK_TYPE_100GbaseR4_BIT

#define NSE_ETH_LINK_TYPE_100GbaseSR2_BIT	NSE_ETH_LINK_TYPE_100GbaseR2_BIT
#define NSE_ETH_LINK_TYPE_100GbaseCR2_BIT	NSE_ETH_LINK_TYPE_100GbaseR2_BIT
#define NSE_ETH_LINK_TYPE_100GbaseKR2_BIT	NSE_ETH_LINK_TYPE_100GbaseR2_BIT

#define NSE_ETH_LINK_TYPE_100GbaseSR1_BIT	NSE_ETH_LINK_TYPE_100GbaseR1_BIT
#define NSE_ETH_LINK_TYPE_100GbaseCR1_BIT	NSE_ETH_LINK_TYPE_100GbaseR1_BIT
#define NSE_ETH_LINK_TYPE_100GbaseKR1_BIT	NSE_ETH_LINK_TYPE_100GbaseR1_BIT

	NSE_ETH_LINK_TYPE_100GAUI4_BIT,
	NSE_ETH_LINK_TYPE_100GAUI2_BIT,
	NSE_ETH_LINK_TYPE_100GAUI1_BIT,

	NSE_ETH_LINK_TYPE_200GbaseR4_BIT,
	NSE_ETH_LINK_TYPE_200GbaseR2_BIT,
	NSE_ETH_LINK_TYPE_200GbaseR1_BIT,	/* this is in future, according to AI */

#define NSE_ETH_LINK_TYPE_200GbaseSR4_BIT	NSE_ETH_LINK_TYPE_200GbaseR4_BIT
#define NSE_ETH_LINK_TYPE_200GbaseCR4_BIT	NSE_ETH_LINK_TYPE_200GbaseR4_BIT
#define NSE_ETH_LINK_TYPE_200GbaseKR4_BIT	NSE_ETH_LINK_TYPE_200GbaseR4_BIT

#define NSE_ETH_LINK_TYPE_200GbaseSR2_BIT	NSE_ETH_LINK_TYPE_200GbaseR2_BIT
#define NSE_ETH_LINK_TYPE_200GbaseCR2_BIT	NSE_ETH_LINK_TYPE_200GbaseR2_BIT
#define NSE_ETH_LINK_TYPE_200GbaseKR2_BIT	NSE_ETH_LINK_TYPE_200GbaseR2_BIT

#define NSE_ETH_LINK_TYPE_200GbaseSR1_BIT	NSE_ETH_LINK_TYPE_200GbaseR1_BIT
#define NSE_ETH_LINK_TYPE_200GbaseCR1_BIT	NSE_ETH_LINK_TYPE_200GbaseR1_BIT
#define NSE_ETH_LINK_TYPE_200GbaseKR1_BIT	NSE_ETH_LINK_TYPE_200GbaseR1_BIT

	NSE_ETH_LINK_TYPE_200GAUI2_BIT,
	NSE_ETH_LINK_TYPE_200GAUI4_BIT,
	NSE_ETH_LINK_TYPE_200GAUI8_BIT,

	NSE_ETH_LINK_TYPE_400GbaseR4_BIT,
	NSE_ETH_LINK_TYPE_400GbaseR8_BIT,

#define NSE_ETH_LINK_TYPE_400GbaseSR4_BIT	NSE_ETH_LINK_TYPE_400GbaseR4_BIT
#define NSE_ETH_LINK_TYPE_400GbaseCR4_BIT	NSE_ETH_LINK_TYPE_400GbaseR4_BIT
#define NSE_ETH_LINK_TYPE_400GbaseKR4_BIT	NSE_ETH_LINK_TYPE_400GbaseR4_BIT

#define NSE_ETH_LINK_TYPE_400GbaseSR4_BIT	NSE_ETH_LINK_TYPE_400GbaseR4_BIT
#define NSE_ETH_LINK_TYPE_400GbaseCR4_BIT	NSE_ETH_LINK_TYPE_400GbaseR4_BIT
#define NSE_ETH_LINK_TYPE_400GbaseKR4_BIT	NSE_ETH_LINK_TYPE_400GbaseR4_BIT

	NSE_ETH_LINK_TYPE_400GAUI4_BIT,
	NSE_ETH_LINK_TYPE_400GAUI8_BIT,

	NSE_ETH_LINK_TYPE_MAX,	/* should <= 64*/
};

#define NSE_ETH_LINK_TYPE_UNKNOWN		0

#define NSE_ETH_LINK_TYPE_1GBaseT		(1ULL << NSE_ETH_LINK_TYPE_1GBaseT_BIT)

#define NSE_ETH_LINK_TYPE_10GbaseR		(1ULL << NSE_ETH_LINK_TYPE_10GbaseR_BIT)
#define NSE_ETH_LINK_TYPE_10GbaseX		(1ULL << NSE_EHT_LINK_TYPE_10GbaseX_BIT)

#define NSE_ETH_LINK_TYPE_25GbaseR		(1ULL << NSE_ETH_LINK_TYPE_25GbaseR_BIT)
#define NSE_ETH_LINK_TYPE_25GbaseRS		(1ULL << NSE_ETH_LINK_TYPE_25GbaseRS_BIT)

#define NSE_ETH_LINK_TYPE_40GbaseR4		(1ULL << NSE_ETH_LINK_TYPE_40GbaseR4_BIT)

#define NSE_ETH_LINK_TYPE_50GbaseR2		(1ULL << NSE_ETH_LINK_TYPE_50GbaseR2_BIT)
#define NSE_ETH_LINK_TYPE_50GbaseR1		(1ULL << NSE_ETH_LINK_TYPE_50GbaseR1_BIT)

#define NSE_ETH_LINK_TYPE_50GAUI2		(1ULL << NSE_ETH_LINK_TYPE_50GAUI2_BIT)
#define NSE_ETH_LINK_TYPE_50GAUI1		(1ULL << NSE_ETH_LINK_TYPE_50GAUI1_BIT)

#define NSE_ETH_LINK_TYPE_100GbaseR4	(1ULL << NSE_ETH_LINK_TYPE_100GbaseR4_BIT)
#define NSE_ETH_LINK_TYPE_100GbaseR2	(1ULL << NSE_ETH_LINK_TYPE_100GbaseR2_BIT)
#define NSE_ETH_LINK_TYPE_100GbaseR1	(1ULL << NSE_ETH_LINK_TYPE_100GbaseR1_BIT)

#define NSE_ETH_LINK_TYPE_100GAUI4		(1ULL << NSE_ETH_LINK_TYPE_100GAUI4_BIT)
#define NSE_ETH_LINK_TYPE_100GAUI2		(1ULL << NSE_ETH_LINK_TYPE_100GAUI2_BIT)
#define NSE_ETH_LINK_TYPE_100GAUI1		(1ULL << NSE_ETH_LINK_TYPE_100GAUI1_BIT)

#define NSE_ETH_LINK_TYPE_200GbaseR4	(1ULL << NSE_ETH_LINK_TYPE_200GbaseR4_BIT)
#define NSE_ETH_LINK_TYPE_200GbaseR2	(1ULL << NSE_ETH_LINK_TYPE_200GbaseR2_BIT)
#define NSE_ETH_LINK_TYPE_200GbaseR1	(1ULL << NSE_ETH_LINK_TYPE_200GbaseR1_BIT)

#define NSE_ETH_LINK_TYPE_200GAUI2		(1ULL << NSE_ETH_LINK_TYPE_200GAUI2_BIT)
#define NSE_ETH_LINK_TYPE_200GAUI4		(1ULL << NSE_ETH_LINK_TYPE_200GAUI4_BIT)
#define NSE_ETH_LINK_TYPE_200GAUI8		(1ULL << NSE_ETH_LINK_TYPE_200GAUI8_BIT)

#define NSE_ETH_LINK_TYPE_400GbaseR4	(1ULL << NSE_ETH_LINK_TYPE_400GbaseR4_BIT)
#define NSE_ETH_LINK_TYPE_400GbaseR8	(1ULL << NSE_ETH_LINK_TYPE_400GbaseR8_BIT)

#define NSE_ETH_LINK_TYPE_400GAUI4		(1ULL << NSE_ETH_LINK_TYPE_400GAUI4_BIT)
#define NSE_ETH_LINK_TYPE_400GAUI8		(1ULL << NSE_ETH_LINK_TYPE_400GAUI8_BIT)

struct amber_txeq_info {
	__le32 flags;
#define AMBER_TXEQ_FLAG_NEED		BIT(0)

	__le32 main;
	__le32 pre;
	__le32 post;

} __packed;

struct amber_rxeq_info {
	__le32 flags;
#define AMBER_RXEQ_FLAG_DfeBypass			BIT(0)
#define AMBER_RXEQ_FLAG_AttLvl				BIT(1)
#define AMBER_RXEQ_FLAG_CtleBoost			BIT(2)
#define AMBER_RXEQ_FLAG_CtlePole			BIT(3)
#define AMBER_RXEQ_FLAG_BufGain			BIT(4)
#define AMBER_RXEQ_FLAG_VgaGain			BIT(5)
#define AMBER_RXEQ_FLAG_DfeTap1			BIT(6)
#define AMBER_RXEQ_FLAG_DfeTap2			BIT(7)

	__le32 dfe_bypass;
	__le32 att_lvl;
	__le32 ctle_boost;
	__le32 ctle_pole;
	__le32 buf_gain;
	__le32 vga_gain;
	__le32 dfe_tap1;
	__le32 dfe_tap2;

} __packed;

struct nse_aqc_eth_set_link_amber {
	__le32 flags;
#define AMBER_ETH_SET_LINK_FLAG_PRE_TURN_OFF_LMAC	BIT(0)
#define AMBER_ETH_SET_LINK_FLAG_POST_TURN_ON_LMAC	BIT(1)
#define AMBER_ETH_SET_LINK_FLAG_POST_TUNE_LMAC_SS	BIT(2)
#define AMBER_ETH_SET_LINK_FLAG_PRE_RESET_LPHY_INTERNAL		BIT(3)

	__le32 speed;	/* a single NSE_AQ_LINK_SPEED_XXX */

	__le64 link_type;	/* a single NSE_ETH_LINK_TYPE_XXX */

	__le32 fec;			/* enum nse_eth_fec */

	struct amber_txeq_info txeq;

	struct amber_rxeq_info rxeq;

} __packed;

struct nse_aqc_eth_set_link_ms {
	__le32 speed;

	__le64 link_type;

	__le32 fec;		/* enum nse_eth_fec */

} __packed;

struct nse_aqc_eth_set_link {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 result;

	union {
		struct nse_aqc_eth_set_link_amber amber;
		struct nse_aqc_eth_set_link_ms ms;
	};

} __packed;

struct nse_aqc_eth_start_an_amber {
	__le32 flags;	/* borrow set_link_amber -> flags */

	__le32 speeds_set;

	__le64 link_types_set;

	__le32 fec_adv;

} __packed;

struct nse_aqc_eth_start_an {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 result;

	union {
		struct nse_aqc_eth_start_an_amber amber;

		u8 rsv[256];
	};
} __packed;

struct nse_aqc_eth_get_link_status {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 link_status;
	__le32 link_speed;		/* a NSE_AQ_LINK_SPEED_XXX */

	__le32 fec;		/* if link UP: current FEC: FEC_NONE, FEC_BASER, FEC_RS */

} __packed;

struct nse_aqc_fpga_phy_lse {
	u8 lan_id;
	u8 pad[3];

	__le32 link_status;	/* 0 for DOWN, 1 for UP */
	__le32 link_speed;
} __packed;
struct nse_aqc_fpga_phy_get_lfc_adv {
	struct nse_aqc_generic_common_hdr hdr;

	u8 local_pause;
	u8 local_asym_pause;

	u8 remote_pause;
	u8 remote_asym_pause;
} __packed;
struct nse_aqc_fpga_phy_set_lfc_adv {
	struct nse_aqc_generic_common_hdr hdr;

	u8 local_pause;
	u8 local_asym_pause;

	u8 pad[2];

	__le32 flags;
#define NSE_AQC_PHY_SET_LFC_ADV_RESTART_AN	0x1
} __packed;
struct nse_aqc_mbx_cmd_buff_hdr {
	__le32 cookie_high;	/* used as vch: u32 v_opcode */
	__le32 cookie_low;	/* used as vch: u32 v_retval */
} __packed;

struct nse_aqc_lan_rxq_txq_ctx {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 q_abs_id;
	__le16 flags;
#define NSE_AQC_LAN_SET_RXQ_TXQ_CXT_FLAG_NEED_PAUSE_DISABLE		0x1
#define NSE_AQC_LAN_SET_RXQ_TXQ_CXT_FLAG_NEED_ENABLE			0x2

	__le32 ctx_data[32];
} __packed;

enum nse_lanq_stat_bit_idx {
	NSE_LANQ_STAT_BIT_IDX_Q_EN		= 0,		/* bit index 0: Q_en */
	/* bit index 1: Q_pause_n: value 0 for 'pause', value 1 for 'active' */
	NSE_LANQ_STAT_BIX_IDX_Q_PAUSE_N	= 1,
};

enum nse_ctlq_stat_bit_idx {
	NSE_CTLQ_STAT_BIT_IDX_Q_EN		= 0,
	NSE_CTLQ_STAT_BIT_IDX_Q_PAUSE_N	= 1,
};

struct nse_aqc_lan_ena_dis_rxq_txq {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 q_abs_id;
	__le16 irqll_msix;

	u8 irqll_conf_result;	/* writeback irqll ADD/DEL 'err' here */
	u8 pad[3];
} __packed;

struct nse_aqc_lan_ena_dis_rxq_txq_many {
	struct nse_aqc_generic_common_hdr hdr;

	u8 ena_or_dis;
	u8 qtype;	/* 0 for LAN-RXQ, 1 for LAN-TXQ */
	u8 pad_0[2];

	__le16 firstq_abs_id;
	__le16 lastq_abs_id;

	__le16 irqll_conf_fail_idx;
	u8 irqll_conf_result;
	u8 pad_1[1];

	/* array length = (lastq_abs_id - firstq_abs_id + 1) */
	__le16 irqll_msix[];
} __packed;

struct nse_aqc_lan_rxq_txq_status {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 q_abs_id;
	__le16 q_status;
} __packed;

struct nse_aqc_set_tso_hsb {
	struct nse_aqc_generic_common_hdr hdr;

	u8 reg_id;
	u8 pad[3];

	__le32 hsb_lsb;
	__le32 hsb_msb;
} __packed;

struct nse_aqc_rc_dma_chan_total_stats {
	struct nse_aqc_generic_common_hdr hdr;

	u8 read_or_clear;
	u8 pad[3];

	__le32 rdm_total_gpkt_cnt_lo;	/* total / gpkt_cnt[0] */
	__le32 rdm_total_gpkt_cnt_hi;	/* total / gpkt_cnt[1] */
	__le32 rdm_total_goct_cnt_lo;
	__le32 rdm_total_goct_cnt_hi;
	__le32 rdm_total_dpkt_cnt_lo;
	__le32 rdm_total_dpkt_cnt_high;
	__le32 rdm_total_b2os_cnt_lo;
	__le32 rdm_total_b2os_cnt_hi;
	__le32 rdm_total_vlen_256_cnt;
	__le32 rdm_total_vlen_1024_cnt;
	__le32 rdm_total_vlen_1534_cnt;
	__le32 rdm_total_vlen_over1534_cnt;
	__le32 rdm_total_rel_cnt_lo;
	__le32 rdm_total_rel_cnt_hi;
	__le32 rdm_total_fetch_cnt_lo;
	__le32 rdm_total_fetch_cnt_hi;

	__le32 tdm_total_gptc_lo;
	__le32 tdm_total_gptc_hi;
	__le32 tdm_total_gotc_lo;
	__le32 tdm_total_gotc_hi;
	__le32 tdm_total_dptc_lo;
	__le32 tdm_total_dptc_hi;

	__le32 fdir_match_cnt;
	__le32 fdir_miss_cnt;

} __packed;

struct nse_aqc_rc_dma_chan_per_vsi_stats {
	struct nse_aqc_generic_common_hdr hdr;

	u8 read_or_clear;
	u8 pad[3];

	__le32 rdm_vsi_drop_err;		/* drop_err[vsi_abs_id] */
#define RDM_VSI_DROP_ERR_NO_DESC_CNT_S	16
#define RDM_VSI_DROP_ERR_NO_DESC_CNT_M	NSE_M(0xFFFF, 16)

#define RDM_VSI_DROP_ERR_CNT_S			0
#define RDM_VSI_DROP_ERR_CNT_M			NSE_M(0xFFFF, 0)

	__le32 rdm_vsi_dpkt_lo;			/* dpkt[2 * vsi_abs_id]*/
	__le32 rdm_vsi_dpkt_hi;			/* dpkt[2 * vsi_abs_id] + 1*/
	__le32 rdm_vsi_goct_lo;			/* goct[2 * vsi_abs_id]*/
	__le32 rdm_vsi_goct_hi;			/* goct[2 * vsi_abs_id + 1]*/
	__le32 rdm_vsi_gpkt_lo;			/* gpkt[2 * vsi_abs_id]*/
	__le32 rdm_vsi_gpkt_hi;			/* gpkt[2 * vsi_abs_id + 1]*/
	__le32 rdm_vsi_mpkt_lo;			/* mpkt[2 * vsi_abs_id]*/
	__le32 rdm_vsi_mpkt_hi;			/* mpkt[2 * vsi_abs_id + 1]*/
	__le32 rdm_vsi_bpkt_lo;			/* bpkt[2 * vsi_abs_id]*/
	__le32 rdm_vsi_bpkt_hi;			/* bpkt[2 * vsi_abs_id + 1]*/

	__le32 tdm_vsi_gptc_lo;
	__le32 tdm_vsi_gptc_hi;
	__le32 tdm_vsi_dptc_lo;
	__le32 tdm_vsi_dptc_hi;
	__le32 tdm_vsi_gotc_lo;
	__le32 tdm_vsi_gotc_hi;
	__le32 tdm_vsi_mptc_lo;
	__le32 tdm_vsi_mptc_hi;
	__le32 tdm_vsi_bptc_lo;
	__le32 tdm_vsi_bptc_hi;

} __packed;

struct nse_aqc_read_write_lan_cq_ctx {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 cq_abs_id;
	__le16 cq_type;

	__le32 flags;
#define NSE_AQC_LAN_WRITE_CQ_CXT_FLAG_NEED_DISABLE		0x1
#define NSE_AQC_LAN_WRITE_CQ_CXT_FLAG_NEED_ENABLE		0x2

	__le32 ctx_data[32];
} __packed;

struct nse_aqc_disable_enable_lan_cq {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 cq_abs_id;
	__le16 irqll_msix;

	u8 irqll_conf_result;
	u8 pad[3];
} __packed;

struct nse_aqc_read_lan_cq_status {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 cq_abs_id;
	__le16 status;
} __packed;

struct nse_aqc_set_rsc_ctrl {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 rsc_ctrl;
#define RSC_CTRL_DIS_S		0
#define RSC_CTRL_DIS_M		BIT(0)

#define RSC_CTRL_DISALLOW_PSH_S		1
#define RSC_CTRL_DISALLOW_PSH_M		BIT(1)

#define RSC_CTRL_DISALLOW_PURE_ACK_S		2
#define RSC_CTRL_DISALLOW_PURE_ACK_M		BIT(2)

} __packed;

struct nse_aqc_logall_entry {
	u64 bitmap_addr;
	u32 bitmap_len;
	u16 vsi_id;
	u8 vsi_vld;
	u8 hm_vld;
};

#define NSE_AQC_LOGALL_CTL_PAGE_SIZE_4KB 0
/* ADDR_RX_DATA | ADDR_TX_DATA */
#define NSE_AQC_LOGALL_CTL_REQ_TYPE 0x40

struct nse_aqc_set_logall {
	struct nse_aqc_generic_common_hdr hdr;

//	u8 flags;

	u32 page_size;
	u32 req_type;

	struct nse_aqc_logall_entry lga_info[8];

} __packed;

struct nse_aqc_conf_tdm_legacy_wb_mode {
	struct nse_aqc_generic_common_hdr hdr;

	u32 rw;	/* 1 for read, 0 for write */

	u32 val;
};

struct nse_aqc_rss_get_set_ctl {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 ctl;
} __packed;

struct nse_aqc_rss_get_set_key {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 key[10];
} __packed;

struct nse_aqc_rss_get_set_lut {
	struct nse_aqc_generic_common_hdr hdr;

	__le16 lut_start;
	__le16 lut_size;

	__le16 lut_data[];		/* actual size is determined by lut_size */
} __packed;

struct nse_aqc_fdir_reinit {
	struct nse_aqc_generic_common_hdr hdr;
} __packed;

struct nse_aqc_fdir_reinit_event {
	struct nse_aqc_generic_common_hdr hdr;
} __packed;

struct nse_aqc_fdir_query_setting {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 fdir_act_root_base;
	__le32 fdir_8act_root_base;

	__le32 fdir_ctl;
#define FDIR_CTL_PBALLOC_S			0
#define FDIR_CTL_PBALLOC_M			NSE_M(0x3, 0)

	#define FDIR_CTL_PBALLOC_NONE		0x0
	#define FDIR_CTL_PBALLOC_64KB		0x1
	#define FDIR_CTL_PBALLOC_128KB		0x2
	#define FDIR_CTL_PBALLOC_256KB		0x3

#define FDIR_CTL_INIT_DN_S			3
#define FDIR_CTL_INIT_DN_M			BIT(3)

#define FDIR_CTL_FILTER_MODE_S		4
#define FDIR_CTL_FILTER_MODE_M		BIT(4)

	#define FDIR_CTL_FILTER_MODE_SIGNATURE	0x0
	#define FDIR_CTL_FILTER_MODE_PERFECT	0x1

#define FDIR_CTL_HASH_BITS_S		20
#define FDIR_CTL_HASH_BITS_M		NSE_M(0xF, 20)

#define FDIR_CTL_MAX_LEN_S			24
#define FDIR_CTL_MAX_LEN_M			NSE_M(0xF, 24)

#define FDIR_CTL_FULL_THRES_S		28
#define FDIR_CTL_FULL_THRES_M		NSE_M(0xF, 28)

	__le32 fdir_pf_vsi_num;
#define FDIR_PF_VSI_PF0_S			0
#define FDIR_PF_VSI_PF0_M			NSE_M(0xFF, 0)

#define FDIR_PF_VSI_PF1_S			8
#define FDIR_PF_VSI_PF1_M			NSE_M(0xFF, 8)

#define FDIR_PF_VSI_PF2_S			16
#define FDIR_PF_VSI_PF2_M			NSE_M(0xFF, 16)

	__le32 fdir_drp_pf[4];
#define FDIR_DRP_QUEUE_S		0
#define FDIR_DRP_QUEUE_M		NSE_M(0x3FF, 0)

#define FDIR_DRP_VSI_S			16
#define FDIR_DRP_VSI_M			NSE_M(0xFF, 16)

	__le32 fdir_hkey;
	__le32 fdir_skey;

	__le32 fdir_bst_effort_space;

	__le32 hw_md_update;
#define HW_MD_UPDATE_RSS_EN_S		0
#define HW_MD_UPDATE_RSS_EN_M		BIT(0)

#define HW_MD_UPDATE_FDIR_EN_S		1
#define HW_MD_UPDATE_FDIR_EN_M		BIT(1)

} __packed;

struct nse_aqc_fdir_query_stats {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 fdir_bst_effort_free;
	__le32 fdir_free;

	/* tip: these registers are RCLR(read clear)
	 */
	__le32 fdir_len;
#define FDIR_LEN_MAX_LEN_S		0
#define FDIR_LEN_MAX_LEN_M		NSE_M(0xFFFF, 0)

#define FDIR_LEN_BUCKET_LEN_S	16
#define FDIR_LEN_BUCKET_LEN_M	NSE_M(0xFFFF, 16)

	__le32 fdir_use_st;
#define FDIR_USE_ST_ADD_S		0
#define FDIR_USE_ST_ADD_M		NSE_M(0xFFFF, 0)

#define FDIR_USE_ST_REM_S		16
#define FDIR_USE_ST_REM_M		NSE_M(0xFFFF, 16)

	__le32 fdir_fail_st;
#define FDIR_FAIL_ST_ADD_S		0
#define FDIR_FAIL_ST_ADD_M		NSE_M(0xFF, 0)

#define FDIR_FAIL_ST_REM_S		8
#define FDIR_FAIL_ST_REM_M		NSE_M(0xFF, 8)

	__le32 fdir_match;
	__le32 fdir_miss;

} __packed;

struct nse_aqc_fdir_get_set_vsi_space {
	struct nse_aqc_generic_common_hdr hdr;

	u8 get_or_set;	/* 1 for get, 0 for set */
	u8 pad[3];

	__le32 vsi_space;

} __packed;

struct nse_aqc_fdir_get_set_drop_q {
	struct nse_aqc_generic_common_hdr hdr;

	u8 get_or_set;	/* 1 for get, 0 for set */
	u8 pad[3];

	__le32 drp_vsi_q;

} __packed;

struct nse_aqc_fdir_get_set_vsi_input_mask {
	struct nse_aqc_generic_common_hdr hdr;

	u8 get_or_set;	/* 1 for read registers, 0 for write registers */
	u8 pad[3];

	__le32 flex_cfg;
#define FDIR_FLEX_CFG_BASE_S		0
#define FDIR_FLEX_CFG_BASE_M		NSE_M(0x3, 0)

	#define FDIR_FLEX_CFG_BASE_L2_HDR		0x0
	#define FDIR_FLEX_CFG_BASE_L3_HDR		0x1
	#define FDIR_FLEX_CFG_BASE_L4_HDR		0x2
	#define FDIR_FLEX_CFG_BASE_L4_PAYLOAD	0x3

#define FDIR_FLEX_CFG_MASK_S		2
#define FDIR_FLEX_CFG_MASK_M		BIT(2)

#define FDIR_FLEX_CFG_OFFSET_S		3
#define FDIR_FLEX_CFG_OFFSET_M		NSE_M(0x1F, 3)

	__le32 mask[7];

#define FDIR_MASK_IDX_DA4		0
#define FDIR_MASK_IDX_SA4		1

#define FDIR_MASK_IDX_TCP		2

	#define FDIR_MASK_TCP_DPORT_S	16
	#define FDIR_MASK_TCP_DPORT_M	NSE_M(0xFFFF, 16)

	#define FDIR_MASK_TCP_SPORT_S	0
	#define FDIR_MASK_TCP_SPORT_M	NSE_M(0xFFFF, 0)

#define FDIR_MASK_IDX_UDP		3

	#define FDIR_MASK_UDP_DPORT_S	16
	#define FDIR_MASK_UDP_DPORT_M	NSE_M(0xFFFF, 16)

	#define FDIR_MASK_UDP_SPORT_S	0
	#define FDIR_MASK_UDP_SPORT_M	NSE_M(0xFFFF, 0)

#define FDIR_MASK_IDX_SCTP		4

	#define FDIR_MASK_SCTP_DPORT_S	16
	#define FDIR_MASK_SCTP_DPORT_M	NSE_M(0xFFFF, 16)

	#define FDIR_MASK_SCTP_SPORT_S	0
	#define FDIR_MASK_SCTP_SPORT_M	NSE_M(0xFFFF, 0)

#define FDIR_MASK_IDX_IP6		5

	#define FDIR_MASK_IP6_DIP_S		16
	#define FDIR_MASK_IP6_DIP_M		NSE_M(0xFFFF, 16)

	#define FDIR_MASK_IP6_SIP_S		0
	#define FDIR_MASK_IP6_SIP_M		NSE_M(0xFFFF, 0)

#define FDIR_MASK_IDX_OTHER		6

	#define FDIR_MASK_OTHER_TUN_S		5
	#define FDIR_MASK_OTHER_TUN_M		BIT(5)

	#define FDIR_MASK_OTHER_L3P_S		4
	#define FDIR_MASK_OTHER_L3P_M		BIT(4)

	#define FDIR_MASK_OTHER_L4P_S		3
	#define FDIR_MASK_OTHER_L4P_M		BIT(3)

	#define FDIR_MASK_OTHER_L4PORT_S	1
	#define FDIR_MASK_OTHER_L4PORT_M	BIT(1)

} __packed;

struct nse_aqc_fdir_conf_perfect_filter {
	struct nse_aqc_generic_common_hdr hdr;

	u8 optype;
#define FDIR_CONF_PERFECT_FILTER_OPTYPE_ADD		0x1
#define FDIR_CONF_PERFECT_FILTER_OPTYPE_DEL		0x2
#define FDIR_CONF_PERFECT_FILTER_OPTYPE_QUERY	0x3

	u8 pad[3];

	__le32 ip6_sa1;
	__le32 ip6_sa2;
	__le32 ip6_sa3;
	__le32 sa0;
	__le32 da;

	__le32 port;
#define FDIR_PORT_DPORT_S			16
#define FDIR_PORT_DPORT_M			NSE_M(0xFFFF, 16)

#define FDIR_PORT_SPORT_S			0
#define FDIR_PORT_SPORT_M			NSE_M(0xFFFF, 0)

	__le32 flex;
#define FDIR_FLEX_FLEX_DATA_S		16
#define FDIR_FLEX_FLEX_DATA_M		NSE_M(0xFFFF, 16)

#define FDIR_FLEX_VSI_S				8
#define FDIR_FLEX_VSI_M				NSE_M(0xFF, 8)

#define FDIR_FLEX_PTYPE_S			0
#define FDIR_FLEX_PTYPE_M			NSE_M(0xFF, 0)

	__le32 hash;
#define FDIR_HASH_SW_IDX_S			16
#define FDIR_HASH_SW_IDX_M			NSE_M(0xFFFF, 16)

#define FDIR_HASH_SIG_HASH_S		16
#define FDIR_HASH_SIG_HASH_M		NSE_M(0x1FFF, 16)

#define FDIR_HASH_SIG_PF_S			29
#define FDIR_HASH_SIG_PF_M			NSE_M(0x3, 29)

#define FDIR_HASH_VLD_S				15
#define FDIR_HASH_VLD_M				BIT(15)

#define FDIR_HASH_BUCKET_HASH_S		0
#define FDIR_HASH_BUCKET_HASH_M		NSE_M(0x7FFF, 0)

	__le32 cmd;
#define FDIR_CMD_FLAG_S				31
#define FDIR_CMD_FLAG_M				BIT(31)

	#define FDIR_CMD_FLAG_QUEUE			0x0
	#define FDIR_CMD_FLAG_ACTION		0x1

#define FDIR_CMD_QUEUE_ACTION_S		16
#define FDIR_CMD_QUEUE_ACTION_M		NSE_M(0x7FFF, 16)

#define FDIR_CMD_QUEUE_EN_S			15
#define FDIR_CMD_QUEUE_EN_M			BIT(15)

#define FDIR_CMD_COLLISION_S		12
#define FDIR_CMD_COLLISION_M		BIT(12)

#define FDIR_CMD_LAST_S				11
#define FDIR_CMD_LAST_M				BIT(11)

#define FDIR_CMD_INT_S				10
#define FDIR_CMD_INT_M				BIT(10)

#define FDIR_CMD_DROP_S				9
#define FDIR_CMD_DROP_M				BIT(9)

#define FDIR_CMD_CLEARHT_S			8
#define FDIR_CMD_CLEARHT_M			BIT(8)

#define FDIR_CMD_RM_VSI_ALL_S		4
#define FDIR_CMD_RM_VSI_ALL_M		BIT(4)

#define FDIR_CMD_UPDATE_S			3
#define FDIR_CMD_UPDATE_M			BIT(3)

#define FDIR_CMD_VLD_S				2
#define FDIR_CMD_VLD_M				BIT(2)

#define FDIR_CMD_OP_S				0
#define FDIR_CMD_OP_M				NSE_M(0x3, 0)

	#define FDIR_CMD_OP_NONE			0x0
	#define FDIR_CMD_OP_ADD				0x1
	#define FDIR_CMD_OP_REMOVE			0x2
	#define FDIR_CMD_OP_QUERY			0x3

} __packed;

struct nse_aqc_fdir_conf_sig_filter {
	struct nse_aqc_generic_common_hdr hdr;

	u8 optype;
#define FDIR_CONF_SIG_FILTER_OPTYPE_ADD			0x1
#define FDIR_CONF_SIG_FILTER_OPTYPE_DEL			0x2

	u8 pad[3];

	__le32 hash;

	__le32 cmd;

} __packed;

struct nse_aqc_fdir_get_set_vsi_qtbl {
	struct nse_aqc_generic_common_hdr hdr;

	u8 get_or_set;	/* 1 for get, 0 for set */
	u8 pad[3];

	__le32 entry_val;
#define FDIR_VSI_QTBL_ENTRY_MIN_Q_S		0
#define FDIR_VSI_QTBL_ENTRY_MIN_Q_M		NSE_M(0x3FF, 0)

#define FDIR_VSI_QTBL_ENTRY_MAX_Q_S		10
#define FDIR_VSI_QTBL_ENTRY_MAX_Q_M		NSE_M(0x3FF, 10)

} __packed;

struct nse_aqc_dbg_rw_regs {
	__le32 reg_base_addr;
	__le16 reg_cnt;
	__le16 rw_flag;	/* 0 for read, non-0 for write */

	__le32 reg_values[];
} __packed;

enum mdio_mode_type {
	MDIO_MODE_NONE,

	MDIO_MODE_CL22,
	MDIO_MODE_CL45,
};

struct nse_aqc_mdio_set_mode {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 mdio_mode;	/* mdio_mode_type */

	__le32 mdio_port;	/* maybe not used */
#define MDIO_PORT_ALL	0xFFFFFFFF
} __packed;

struct nse_aqc_mdio_rw_reg {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 rw;

	__le32 mdio_addr;

	__le32 mmd;	/* devad */

	__le32 reg_addr;

	__le16 reg_val;
	u8 pad[2];

	__le32 result;

} __packed;

struct nse_aqc_i2c_reinit {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 flags;
#define NSE_AQC_I2C_FLAG_USE_SEL_I2C_BUS_ID	0x1

	__le32 sel_i2c_bus_id;

} __packed;

struct nse_aqc_i2c_rw_bytes {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 flags;
	__le32 sel_i2c_bus_id;

	__le32 rw;

	__le32 target_addr;

	__le32 bytes_offset;
	__le32 bytes_len_in;
	__le32 bytes_len_out;

	__le32 result;

#define NSE_AQ_I2C_RW_MAX_DATA_LEN		256
	u8 bytes_data[NSE_AQ_I2C_RW_MAX_DATA_LEN];

} __packed;

struct nse_aqc_led_cfg_amber {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 rw;

	__le32 w_bitmap;

	__le32 cfg0[8];
	__le32 cfg1[8];

} __packed;

struct nse_aqc_led_cfg {
	union {
		struct nse_aqc_generic_common_hdr hdr;
		struct nse_aqc_led_cfg_amber amber;
	};
} __packed;

/* currently we only have 96, so 256 should be enough for long future */
#define NSE_GPIO_ID_MAX			256
#define NSE_GPIO_ID_MAX_GROUP	8		/* 256 / 32 */

struct nse_aqc_gpio_cfg {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 gpio_id;

	__le32 direction;	/* 0: input, 1: output */

	__le32 init_value;

	__le32 int_type;	/* 0: level-sensitive, 1: edge-sensitive */

	__le32 int_polarity;

	__le32 int_en;		/* interrupt enable */

	__le32 result;

} __packed;

struct nse_aqc_gpio_rw {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 gpio_id;

	__le32 rw;

	__le32 value;

	__le32 result;

} __packed;

struct nse_aqc_gpio_evt {
	struct nse_aqc_generic_common_hdr hdr;

	__le32 gpio_id_bitmap[NSE_GPIO_ID_MAX_GROUP];

	__le32 gpio_value[NSE_GPIO_ID_MAX_GROUP];

} __packed;

enum nse_adminq_opc_category {
	NSE_AQ_OPC_CATEGORY_BASIC	= 0x0,

	NSE_AQ_OPC_CATEGORY_MISC	= 0x1,

	NSE_AQ_OPC_CATEGORY_SWITCH	= 0x2,

	NSE_AQ_OPC_CATEGORY_QOS		= 0x3,

	NSE_AQ_OPC_CATEGORY_LMAC_PHY	= 0x4,

	NSE_AQ_OPC_CATEGORY_LAN		= 0x5,

	NSE_AQ_OPC_CATEGORY_COMM	= 0x6,

	NSE_AQ_OPC_CATEGORY_RCF	= 0x7,

	NSE_AQ_OPC_CATEGORY_DBG = 0x8,

	NSE_AQ_OPC_CATEGORY_ACL		= 0x9,

	NSE_AQ_OPC_CATEGORY_MAX,
};

enum nse_adminq_opc_category_basic_subcodes {
	NSE_AQ_OPC_DUMMY		= 0x0,

	NSE_AQ_OPC_XCHG_SW_FW_VER		= 0x1,

	NSE_AQ_OPC_PING_FW				= 0x2,

	NSE_AQ_OPC_Q_SHUTDOWN			= 0x3,

	NSE_AQ_OPC_DISCOVER_FUNC_CAPS	= 0x4,

	NSE_AQ_OPC_SET_SRIOV_RES		= 0x5,
	NSE_AQ_OPC_UNSET_SRIOV_RES		= 0x6,

	NSE_AQ_OPC_QUERY_STAG_TYPE		= 0x7,

	NSE_AQ_OPC_FW_LLDP_AGENT_GET_STATUS		= 0x10,
	NSE_AQ_OPC_FW_LLDP_AGENT_START_STOP		= 0x11,

	NSE_AQ_OPC_VFLR_EVENT				= 0x20,

	NSE_AQ_OPC_CONF_IRQLL				= 0x21,

	NSE_AQ_OPC_RESET_RDMA				= 0x22,

	NSE_AQ_OPC_DDP					= 0x23,

	NSE_AQ_OPC_VFLR_EVENT_MINI		= 0x24,

	/* @internal-comment: aq-cmd: (basic, read_chip_temperature)
	 *
	 * brief
	 *
	 *		Query FW about current chip temperature
	 *
	 *		Driver might send this cmd at 2 cases:
	 *
	 *				#1. On receiving OICR -> overheat interrupt to driver
	 *
	 *				#2. Periodically, monitor temperature from driver's aspect
	 *
	 *
	 * cmd_data:
	 *
	 *		Note cmd buffer
	 *
	 *		desc->param0 (u32) as OUTPUT write back by FW.
	 */
	NSE_AQ_OPC_READ_CHIP_TEMPERATURE = 0x25,

	NSE_AQ_OPC_CATEGORY_BASIC_MAX,
};

enum nse_adminq_opc_category_misc_subcodes {
	NSE_AQ_OPC_CLEAR_PXE_MODE		= 0x0,

	NSE_AQ_OPC_SET_ITR_INTERVAL		= 0x1,

	NSE_AQ_OPC_MANAGE_MAC_READ		= 0x2,
	NSE_AQ_OPC_MANAGE_MAC_WRITE		= 0x3,

	NSE_AQ_OPC_SET_INTRL_INTERVAL		= 0x4,

	NSE_AQ_OPC_PTP_GET_SYS_TIME		= 0x5,
	NSE_AQ_OPC_PTP_SET_SYS_TIME		= 0x6,
	NSE_AQ_OPC_PTP_ADJ_SYS_TIME		= 0x7,

	NSE_AQ_OPC_PTP_GET_CONTROL		= 0x8,
	NSE_AQ_OPC_PTP_SET_CONTROL		= 0x9,

	NSE_AQ_OPC_PTP_GET_INCVAL		= 0xA,
	NSE_AQ_OPC_PTP_SET_INCVAL		= 0xB,

	NSE_AQ_OPC_PTP_GET_CORR			= 0xC,
	NSE_AQ_OPC_PTP_SET_CORR			= 0xD,

	NSE_AQ_OPC_PTP_INIT				= 0xE,

	NSE_AQ_OPC_PTP_RD_TX_TS			= 0xF,
	NSE_AQ_OPC_PTP_CLR_TX_TS		= 0x10,

	NSE_AQ_OPC_PTP_TX_TS_EVENT		= 0x11,

	NSE_AQ_OPC_PTP_GET_ADDEND		= 0x12,
	NSE_AQ_OPC_PTP_SET_ADDEND		= 0x13,

	NSE_AQ_OPC_PTP_RW_TX_TS_REPORT_METHOD	= 0x14,

	/* reserve some misc cmds IDs for PTP, new cmds start with 0x20 */

	NSE_AQ_OPC_PSR_SET_CTRL	=	0x20,

	NSE_AQ_OPC_ADD_HW_LAG			= 0x21,
	NSE_AQ_OPC_UPDATE_HW_LAG		= 0x22,
	NSE_AQ_OPC_GET_HW_LAG			= 0x23,
	NSE_AQ_OPC_REMOVE_HW_LAG		= 0x24,
	NSE_AQ_OPC_HW_LAG_CFG_DROP		= 0x25,

	NSE_AQ_OPC_MDIO_SET_MODE = 0x30,
	NSE_AQ_OPC_MDIO_RW_REG = 0x31,

	NSE_AQ_OPC_I2C_REINIT = 0x32,
	NSE_AQ_OPC_I2C_RW_BYTES = 0x33,

	NSE_AQ_OPC_LED_CFG = 0x34,

	NSE_AQ_OPC_GPIO_CFG = 0x35,
	NSE_AQ_OPC_GPIO_RW = 0x36,
	NSE_AQ_OPC_GPIO_EVT = 0x37,

	NSE_AQ_OPC_CATEGORY_MISC_MAX,
};

enum nse_adminq_opc_category_switch_subcodes {
	NSE_AQ_OPC_GET_SW_CFG			= 0x0,

	NSE_AQ_OPC_SET_PORT_PARAMS		= 0x1,

	NSE_AQ_OPC_CFG_VSI				= 0x2,
	NSE_AQ_OPC_GET_VSI_PARAMS		= 0x3,
	NSE_AQ_OPC_FREE_VSI				= 0x4,

	NSE_AQ_OPC_CLEAR_PF_CFG			= 0x5,

	/* switch rules population commands */

	NSE_AQ_OPC_ALLOC_RESOURCE		= 0x6,
	NSE_AQ_OPC_FREE_RESOURCE		= 0x7,

	NSE_AQ_OPC_GET_RESOURCE			= 0x8,
	NSE_AQ_OPC_GET_ALLOCED_RES_DESC	= 0x9,

	NSE_AQ_OPC_ADD_LUT_NODE			= 0xa,
	NSE_AQ_OPC_UPDATE_LUT_NODE		= 0xb,
	NSE_AQ_OPC_REMOVE_LUT_NODE		= 0xc,
	NSE_AQ_OPC_GET_LUT_NODE			= 0xd,

	NSE_AQ_OPC_ADD_VSI_LIST			= 0xe,
	NSE_AQ_OPC_UPDATE_VSI_LIST		= 0xf,

	NSE_AQ_OPC_REMOVE_VSI_LIST		= 0x10,
	NSE_AQ_OPC_GET_VSI_LIST			= 0x11,

	NSE_AQ_OPC_GET_PROFILE_CFG		= 0x12,
	NSE_AQ_OPC_UPDATE_PROFILE_CFG	= 0x13,

	NSE_AQ_OPC_ADD_RECIPE			= 0x14,
	NSE_AQ_OPC_UPDATE_RECIPE		= 0x15,
	NSE_AQ_OPC_REMOVE_RECIPE		= 0x16,
	NSE_AQ_OPC_GET_RECIPE			= 0x17,

	NSE_AQ_OPC_ADD_NODE_STATE		= 0x18,
	NSE_AQ_OPC_UPDATE_NODE_STATE	= 0x19,
	NSE_AQ_OPC_REMOVE_NODE_STATE	= 0x1a,
	NSE_AQ_OPC_GET_NODE_STATE		= 0x1b,

	NSE_AQ_OPC_ADD_TASK_LIST		= 0x1c,
	NSE_AQ_OPC_UPDATE_TASK_LIST		= 0x1d,
	NSE_AQ_OPC_REMOVE_TASK_LIST		= 0x1e,
	NSE_AQ_OPC_GET_TASK_LIST		= 0x1f,

	NSE_AQ_OPC_ADD_DU_DATA			= 0x20,
	NSE_AQ_OPC_UPDATE_DU_DATA		= 0x21,
	NSE_AQ_OPC_REMOVE_DU_DATA		= 0x22,
	NSE_AQ_OPC_GET_DU_DATA			= 0x23,

	NSE_AQ_OPC_GET_COUNTER			= 0x24,
	NSE_AQ_OPC_SET_COUNTER			= 0x25,

	NSE_AQ_OPC_ADD_METER			= 0x26,
	NSE_AQ_OPC_UPDATE_METER			= 0x27,
	NSE_AQ_OPC_REMOVE_METER			= 0x28,
	NSE_AQ_OPC_GET_METER			= 0x29,

	NSE_AQ_OPC_SET_SFLOW			= 0x2a,
	NSE_AQ_OPC_GET_SFLOW			= 0x2b,

	NSE_AQ_OPC_ADD_LITE_NODE_STATE		= 0x2c,
	NSE_AQ_OPC_UPDATE_LITE_NODE_STATE	= 0x2d,
	NSE_AQ_OPC_REMOVE_LITE_NODE_STATE	= 0x2e,
	NSE_AQ_OPC_GET_LITE_NODE_STATE		= 0x2f,

	NSE_AQ_OPC_SWITCH_RPP_SET_BYPASS	=	0x30,

	NSE_AQ_OPC_SET_FEATURE				=	0x31,
	NSE_AQ_OPC_GET_FEATURE				=	0x32,

	NSE_AQ_OPC_GET_CAPBILITY			=	0x33,
	NSE_AQ_OPC_SET_CAPBILITY			=	0x34,

	NSE_AQ_OPC_ADD_LUT_FAST_NODE		=	0x35,
	NSE_AQ_OPC_UPDATE_LUT_FAST_NODE		=	0x36,
	NSE_AQ_OPC_REMOVE_LUT_FAST_NODE		=	0x37,
	NSE_AQ_OPC_GET_LUT_FAST_NODE		=	0x38,

	NSE_AQ_OPC_GET_POLICY_COUNTER			= 0x39,
	NSE_AQ_OPC_SET_POLICY_COUNTER			= 0x3a,

	NSE_AQ_OPC_SET_LEGACY_FILTER			= 0x3b,
	NSE_AQ_OPC_GET_LEGACY_FILTER			= 0x3c,

	NSE_AQ_OPC_CATEGORY_SWITCH_MAX,
};

enum nse_adminq_opc_category_qos_subcodes {
	NSE_AQ_OPC_QOS_DB_SET_CFG		= 0x0,
	NSE_AQ_OPC_QOS_DB_GET_CFG			= 0x1,

	NSE_AQ_OPC_QOS_DB_FLUSH_DISABLE			= 0x2,

	NSE_AQ_OPC_QOS_DB_GET_STAT_CNT				=	0x3,

	NSE_AQ_OPC_QOS_DB_CONF_UP_ENFORCEMENT		=	0x4,

	NSE_AQ_OPC_QOS_FW_LLDP_DCBX_SUBAGENT_GET_STATUS		=	0xC,
	NSE_AQ_OPC_QOS_FW_LLDP_DCBX_SUBAGENT_START_STOP		=	0xD,
	NSE_AQ_OPC_QOS_DCBX_CFG_CHG_EVENT					=	0xE,

	NSE_AQ_OPC_QOS_SCH_RW_CTL				=	0x10,

	NSE_AQ_OPC_QOS_SCH_PER_PF_INIT					=	0x11,

	NSE_AQ_OPC_QOS_SCH_ADD_NODE_ONE			=	0x12,

	NSE_AQ_OPC_QOS_SCH_DEL_NODE_ONE			=	0x13,

	NSE_AQ_OPC_QOS_SCH_SUSPEND_RESUME_NODE_ONE		=	0x14,

	NSE_AQ_OPC_QOS_SCH_SET_UNSET_QID2LNID			=	0x16,

	NSE_AQ_OPC_QOS_SCH_GET_SET_NODE_PARAM_ONE			=	0x18,

	NSE_AQ_OPC_QOS_SCH_RW_PORT_CTL					=	0x19,

	NSE_AQ_OPC_QOS_SCH_CONF_CIR						=	0x1B,
	NSE_AQ_OPC_QOS_SCH_CONF_PIR						=	0x1C,

	NSE_AQ_OPC_QOS_SCH_DBG_DUMP_FREE_SE_LIST		=	0x20,
	NSE_AQ_OPC_QOS_SCH_DBG_DUMP_SE					=	0x21,
	NSE_AQ_OPC_QOS_SCH_DBG_DUMP_QID2LNID			=	0x22,

	NSE_AQ_OPC_CATEGORY_QOS_MAX,
};

enum nse_adminq_opc_category_lmac_phy_subcodes {
	NSE_AQ_OPC_LMAC_GET_SET_BASIC_CFG		= 0x0,

	NSE_AQ_OPC_LMAC_READ_STATS			= 0x1,

	NSE_AQ_OPC_LMAC_PHY_EVENT			= 0x2,

	NSE_AQ_OPC_EPHY_CMD = 0x3,

	NSE_AQ_OPC_ETH_SET_LINK = 0x4,

	NSE_AQ_OPC_ETH_GET_LINK_STATUS = 0x5,

	NSE_AQ_OPC_ETH_START_AN = 0x6,

	NSE_AQ_OPC_FPGA_PHY_STARTUP				= 0x10,
#define NSE_AQ_OPC_TEST_PHY_STARTUP	NSE_AQ_OPC_FPGA_PHY_STARTUP

	NSE_AQ_OPC_FPGA_PHY_GET_LINK_STATUS		= 0x11,
#define NSE_AQ_OPC_TEST_PHY_GET_LINK_STATUS	NSE_AQ_OPC_FPGA_PHY_GET_LINK_STATUS

	NSE_AQ_OPC_FPGA_PHY_SET_LOOPBACK		= 0x12,
#define NSE_AQ_OPC_TEST_PHY_SET_LOOPBACK	NSE_AQ_OPC_FPGA_PHY_SET_LOOPBACK

	NSE_AQ_OPC_FPGA_PHY_LSE = 0x13,
#define NSE_AQ_OPC_TEST_PHY_LSE	NSE_AQ_OPC_FPGA_PHY_LSE

	NSE_AQ_OPC_FPGA_PHY_GET_LFC_ADV = 0x14,
	NSE_AQ_OPC_FPGA_PHY_SET_LFC_ADV = 0x15,
#define NSE_AQ_OPC_TEST_PHY_GET_LFC_ADV	NSE_AQ_OPC_FPGA_PHY_GET_LFC_ADV
#define NSE_AQ_OPC_TEST_PHY_SET_LFC_ADV	NSE_AQ_OPC_FPGA_PHY_SET_LFC_ADV

	NSE_AQ_OPC_CATEGORY_LMAC_PHY_MAX,
};

enum nse_adminq_opc_category_lan_subcodes {
	NSE_AQ_OPC_WRITE_LAN_RXQ_CTX			= 0x0,
	NSE_AQ_OPC_WRITE_LAN_TXQ_CTX			= 0x1,

	NSE_AQ_OPC_DISABLE_LAN_RXQ				= 0x2,
	NSE_AQ_OPC_DISABLE_LAN_TXQ				= 0x3,

	NSE_AQ_OPC_ENABLE_LAN_RXQ				= 0x4,
	NSE_AQ_OPC_ENABLE_LAN_TXQ				= 0x5,

	NSE_AQ_OPC_READ_LAN_RXQ_STATUS			= 0x6,
	NSE_AQ_OPC_READ_LAN_TXQ_STATUS			= 0x7,

	NSE_AQ_OPC_READ_LAN_RXQ_CTX			= 0x8,
	NSE_AQ_OPC_READ_LAN_TXQ_CTX			= 0x9,

	NSE_AQ_OPC_EVENT_LAN_OVERFLOW		= 0xA,

	NSE_AQ_OPC_SET_TSO_HSB				= 0xB,

	NSE_AQ_OPC_RC_DMA_CHAN_TOTAL_STATS		= 0xC,
	NSE_AQ_OPC_RC_DMA_CHAN_PER_VSI_STATS		= 0xD,

	NSE_AQ_OPC_READ_LAN_CQ_CTX					= 0xE,
	NSE_AQ_OPC_WRITE_LAN_CQ_CTX					= 0xF,

	NSE_AQ_OPC_DISABLE_LAN_CQ					= 0x10,
	NSE_AQ_OPC_ENABLE_LAN_CQ					= 0x11,

	NSE_AQ_OPC_READ_LAN_CQ_STATUS				= 0x12,

	NSE_AQ_OPC_SET_RSC_CTRL						= 0x13,

	NSE_AQ_OPC_ENA_DIS_LAN_RXQ_TXQ_MANY				= 0x14,

	NSE_AQ_OPC_ENA_DIS_LOGALL			= 0x15,

	NSE_AQ_OPC_CONF_TDM_LEGACY_WB_MODE	=	0x16,

	NSE_AQ_OPC_CATEGORY_LAN_MAX,
};

enum nse_adminq_opc_category_comm_subcodes {
	NSE_AQ_OPC_SEND_MSG_TO_PF			= 0x0,
	NSE_AQ_OPC_SEND_MSG_TO_VF			= 0x1,

	NSE_AQ_OPC_SEND_MSG_TO_MH_PEER_PF	= 0x2,

	NSE_AQ_OPC_CATEGORY_COMM_MAX,
};

enum nse_adminq_opc_category_rcf_subcodes {
	NSE_AQ_OPC_RSS_GET_CTL		= 0x0,
	NSE_AQ_OPC_RSS_SET_CTL		= 0x1,

	NSE_AQ_OPC_RSS_GET_KEY		= 0x2,
	NSE_AQ_OPC_RSS_SET_KEY		= 0x3,

	NSE_AQ_OPC_RSS_GET_LUT		= 0x4,
	NSE_AQ_OPC_RSS_SET_LUT		= 0x5,

	NSE_AQ_OPC_FDIR_REINIT = 0x10,
	NSE_AQ_OPC_FDIR_REINIT_EVENT = 0x11,

	NSE_AQ_OPC_FDIR_QUERY_SETTING	= 0x12,

	NSE_AQ_OPC_FDIR_QUERY_STATS		= 0x13,

	NSE_AQ_OPC_FDIR_GET_SET_VSI_SPACE = 0x14,

	NSE_AQ_OPC_FDIR_GET_SET_DROP_Q = 0x15,

	NSE_AQ_OPC_FDIR_GET_SET_VSI_INPUT_MASK = 0x16,

	NSE_AQ_OPC_FDIR_CONF_PERFECT_FILTER = 0x17,

	NSE_AQ_OPC_FDIR_CONF_SIG_FILTER		= 0x18,

	NSE_AQ_OPC_FDIR_GET_SET_VSI_QTBL	= 0x19,

	NSE_AQ_OPC_FDIR_CONF_FILTER_BY_UTILQ = 0x1A,

	NSE_AQ_OPC_CATEGORY_RCF_MAX,
};

enum nse_adminq_opc_category_dbg_subcodes {
	NSE_AQ_OPC_DBG_PING_FW_WITH_BUF	= 0x0,

	NSE_AQ_OPC_DBG_PING_FW_RQ_REQ		= 0x1,
	NSE_AQ_OPC_DBG_PING_FW_RQ_RSP		= 0x2,

	NSE_AQ_OPC_DBG_REQ_DUMMY_EVENT	= 0x3,
	NSE_AQ_OPC_DBG_DUMMY_EVENT		= 0x4,

	NSE_AQ_OPC_DBG_RW_REGS		= 0x5,

	NSE_AQ_OPC_CATEGORY_DBG_MAX,
};

enum nse_adminq_opc_category_acl_subcodes {
	NSE_AQ_ACL_OPC_ALLOC_RESOURCE = NSE_AQ_OPC_ALLOC_RESOURCE,
	NSE_AQ_ACL_OPC_FREE_RESOURCE = NSE_AQ_OPC_FREE_RESOURCE,
	NSE_AQ_ACL_OPC_GET_RESOURCE = NSE_AQ_OPC_GET_RESOURCE,
	NSE_AQ_ACL_OPC_GET_ALLOCED_RES_DESC = NSE_AQ_OPC_GET_ALLOCED_RES_DESC,

	NSE_AQ_ACL_OPC_ADD_LUT_NODE = NSE_AQ_OPC_ADD_LUT_NODE,
	NSE_AQ_ACL_OPC_UPDATE_LUT_NODE = NSE_AQ_OPC_UPDATE_LUT_NODE,
	NSE_AQ_ACL_OPC_REMOVE_LUT_NODE = NSE_AQ_OPC_REMOVE_LUT_NODE,
	NSE_AQ_ACL_OPC_GET_LUT_NODE	 = NSE_AQ_OPC_GET_LUT_NODE,

	NSE_AQ_ACL_OPC_ADD_METER  = NSE_AQ_OPC_ADD_METER,
	NSE_AQ_ACL_OPC_UPDATE_METER = NSE_AQ_OPC_UPDATE_METER,
	NSE_AQ_ACL_OPC_REMOVE_METER = NSE_AQ_OPC_REMOVE_METER,
	NSE_AQ_ACL_OPC_GET_METER	= NSE_AQ_OPC_GET_METER,

	NSE_AQ_ACL_OPC_GET_POLICY_COUNTER	= NSE_AQ_OPC_GET_POLICY_COUNTER,
	NSE_AQ_ACL_OPC_SET_POLICY_COUNTER	= NSE_AQ_OPC_SET_POLICY_COUNTER,

	NSE_AQ_OPC_CATEGORY_ACL_MAX,
};

static inline bool nse_sq_cmd_is_no_wait(u8 opc_category, u8 opc_subcode)
{
	if (opc_category == NSE_AQ_OPC_CATEGORY_BASIC &&
		opc_subcode == NSE_AQ_OPC_Q_SHUTDOWN)
		return true;

	if (opc_category == NSE_AQ_OPC_CATEGORY_RCF &&
		opc_subcode == NSE_AQ_OPC_FDIR_CONF_FILTER_BY_UTILQ)
		return true;

	return false;
}

static inline bool nse_sq_cmd_is_need_retry(u8 opc_category, u8 opc_subcode, u32 *retry_times)
{
	if (opc_category == NSE_AQ_OPC_CATEGORY_SWITCH) {
		switch (opc_subcode) {
		case NSE_AQ_OPC_ADD_LUT_NODE:
		case NSE_AQ_OPC_UPDATE_LUT_NODE:
		case NSE_AQ_OPC_REMOVE_LUT_NODE:
		case NSE_AQ_OPC_GET_LUT_NODE:
		case NSE_AQ_OPC_ADD_LUT_FAST_NODE:
		case NSE_AQ_OPC_UPDATE_LUT_FAST_NODE:
		case NSE_AQ_OPC_REMOVE_LUT_FAST_NODE:
		case NSE_AQ_OPC_GET_LUT_FAST_NODE:
			return true;
		}
	}
	return false;
}

#define NSE_SCH_TREE_MAX_LAYERS_NUM		16

#define NSE_SCH_TREE_SCHEME_6_LAYERS	6	/* Moonstone use 6 layer */
#define NSE_SCH_TREE_SCHEME_7_LAYERS	7	/* used on Amber-FPGA only */
#define NSE_SCH_TREE_SCHEME_8_LAYERS	8
#define NSE_SCH_TREE_SCHEME_10_LAYERS	10

#endif

