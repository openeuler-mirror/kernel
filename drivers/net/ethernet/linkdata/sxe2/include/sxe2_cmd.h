/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_cmd.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_CMD_H__
#define __SXE2_CMD_H__

#ifdef SXE2_FW
#include "sxe2_drv_type.h"
#endif

#if defined(SXE2_SUPPORT_UEFI) || defined(SXE2_SUPPORT_IPXE)
#include "sxe2_uefi_type.h"
#include "sxe2_uefi_def.h"
#endif

#ifdef SXE2_LINUX_DRIVER
#include <linux/types.h>
#endif

#ifdef SXE2_DPDK_DRIVER
#include "rte_os.h"
#include "sxe2_type.h"
#include "sxe2_common.h"
#include "sxe2_osal.h"
#endif

#ifndef SXE2_DRIVER_SIM
#include "sxe2_spec.h"
#endif

#pragma pack(4)

#define SXE2_VSI_MAX_CNT (768)

#define SXE2_INVAL_U8  (0xFF)
#define SXE2_INVAL_U16 (0xFFFF)
#define SXE2_INVAL_U32 (0xFFFFFFFF)
#define SXE2_VF_ID_INVAL	(0xFFFF)

#define SXE2_CMD_MAGIC (0xFEFEEFEF)

#define SXE2_FW_COMP_MAJOR_VER (1)
#define SXE2_FW_COMP_MINOR_VER (1)
#define SXE2_FW_COMP_VER           \
	(SXE2_FW_COMP_MAJOR_VER << 16 | \
	 SXE2_FW_COMP_MINOR_VER)

#define SXE2_CMD_LARGE_BUF_SIZE (512)
#define SXE2_CMD_MAX_BUF \
		(2 * 4096)
#define SXE2_CMD_MAX_TRANSMIT_DATA_SIZE \
		(SXE2_CMD_MAX_BUF - SXE2_CMD_HDR_SIZE)
#define SXE2_DRV_CMD_MAX_MSG_SIZE      \
		(SXE2_CMD_MAX_TRANSMIT_DATA_SIZE - \
		SXE2_DRV_MSG_HDR_SIZE)

#define SXE2_CMD_MAX_BUF_MBX \
			(4096)
#define SXE2_CMD_MAX_TRANSMIT_DATA_SIZE_MBX \
			(SXE2_CMD_MAX_BUF_MBX - SXE2_CMD_HDR_SIZE)
#define SXE2_DRV_CMD_MAX_MSG_SIZE_MBX      \
			(SXE2_CMD_MAX_TRANSMIT_DATA_SIZE_MBX - \
			SXE2_DRV_MSG_HDR_SIZE)

#define SXE2_CMD_DD        BIT(0)
#define SXE2_CMD_COMPLETE  BIT(1)
#define SXE2_CMD_ERROR     BIT(2)
#define SXE2_CMD_LARGE_BUF BIT(9)
#define SXE2_CMD_READ      BIT(10)
#define SXE2_CMD_BUF       BIT(12)
#define SXE2_CMD_NO_INTR   BIT(13)

#define SXE2_CMD_DONE   (SXE2_CMD_DD | SXE2_CMD_COMPLETE | SXE2_CMD_ERROR)

#define SXE2_VSI_SCATTER_TXRX_Q_MAX_CNT \
	(16)
#define SXE2_TC_MAX_CNT   (8)
#define SXE2_TXQ_CTXT_LEN (24)

#define SXE2_CMD_HDR_SIZE sizeof(struct sxe2_cmd_hdr)
#define SXE2_DRV_MSG_HDR_SIZE \
	sizeof(struct sxe2_drv_msg_hdr)

#define SXE2_DRV_MSG_HDR_PTR(cmd_hdr_ptr) \
	({ \
		typeof(cmd_hdr_ptr) ptr = (cmd_hdr_ptr); \
		((struct sxe2_drv_msg_hdr *)((u8 *)(ptr) + (ptr)->hdr_len)); \
	})

#define SXE2_CMD_MODULE_S        (8)
#define SXE2_MK_CMD(module, cmd) ((module) << SXE2_CMD_MODULE_S | (cmd))

#define SXE2_TCAM_KEY_VALUE_LEN    (5)
#define SXE2_TCAM_KEY_LEN         (2 * SXE2_TCAM_KEY_VALUE_LEN)

#define SXE2_FULLKEY_DWORD_CNT		(3)
#define SXE2_PACKET_INFO_DWORD_CNT	(20)
#define SXE2_SWITCH_FV_CNT		(48)
#define SXE2_PACKET_MAX_RECIPES	(32)

#define SXE2_MAX_NUM_RECIPES			(64)
#define SXE2_MAX_NUM_RECIPES_PER_PROFILE			(32)
#define SXE2_MAX_NUM_ROOT_RECIPES_PER_PROFILE		(24)

#if defined(SXE2_TEST)
#define SXE2_MAX_NUM_RECIPES_VER_I_O	(64)
#else
#define SXE2_MAX_NUM_RECIPES_VER_I_O	(24)
#endif

#define SXE2_MAX_NUM_PROFILES		(256)
#define SXE2_NUM_WORDS_RECIPE		(4)
#define SXE2_MAX_REPLY_RECIPE		(4)
#define SXE2_MAX_CHAIN_RECIPE		(SXE2_MAX_REPLY_RECIPE + 1)
#define SXE2_MAX_CHAIN_WORDS		(SXE2_NUM_WORDS_RECIPE * \
	SXE2_MAX_REPLY_RECIPE)
#define SXE2_VSI_LIST_DAT_LEN		DIV_ROUND_UP(SXE2_VSI_MAX_CNT, \
	(BITS_PER_BYTE * sizeof(u32)))

#define SXE2_ACTION_PRIORITY_HIGH	(7)

#define SXE2_CMD_SWITCH_RULE_FLAG_COMPLEX	BIT(0)
#define SXE2_CMD_SWITCH_VSI_FLAG_LIST_PRUNE	BIT(1)
#define SXE2_CMD_SWITCH_VSI_FLAG_LIST_INC	BIT(2)

#define SXE2_SINGLE_ACT_LB_ENABLE		BIT(16)
#define SXE2_SINGLE_ACT_LAN_ENABLE		BIT(15)

#define SXE2_SINGLE_ACT_VSI_TYPE_S		(17)
#define SXE2_SINGLE_ACT_VSI_FORWARD		(0x0 << SXE2_SINGLE_ACT_VSI_TYPE_S)
#define SXE2_SINGLE_ACT_VSI_ID_S		(5)
#define SXE2_SINGLE_ACT_VSI_ID_M		(0x3FF << SXE2_SINGLE_ACT_VSI_ID_S)
#define SXE2_SINGLE_ACT_VSI_LIST_ID_S		(5)
#define SXE2_SINGLE_ACT_VSI_LIST_ID_M		(0x3FF << SXE2_SINGLE_ACT_VSI_LIST_ID_S)
#define SXE2_SINGLE_ACT_VSI_LIST		BIT(4)
#define SXE2_SINGLE_ACT_VALID_BIT		BIT(1)
#define SXE2_SINGLE_ACT_DROP			BIT(0)

#define SXE2_SINGLE_ACT_TO_Q			(0x1 << SXE2_SINGLE_ACT_VSI_TYPE_S)
#define SXE2_SINGLE_ACT_Q_INDEX_S		(4)
#define SXE2_SINGLE_ACT_Q_INDEX_M		(0x7FF << SXE2_SINGLE_ACT_Q_INDEX_S)
#define SXE2_SINGLE_ACT_Q_REGION_S		(1)
#define SXE2_SINGLE_ACT_Q_REGION_M		(0x7 << SXE2_SINGLE_ACT_Q_REGION_S)
#define SXE2_SINGLE_ACT_Q_PRIORITY		BIT(0)

#define SXE2_SINGLE_ACT_PRUNE			(0x2 << SXE2_SINGLE_ACT_VSI_TYPE_S)
#define SXE2_SINGLE_ACT_EGRESS			BIT(3)
#define SXE2_SINGLE_ACT_INGRESS		BIT(2)
#define SXE2_SINGLE_ACT_PRUNET			BIT(1)

#define SXE2_SINGLE_ACT_MIRROR			(0x3 << SXE2_SINGLE_ACT_VSI_TYPE_S)

#define SXE2_SINGLE_ACT_POINTER		(0x2 << SXE2_SINGLE_ACT_VSI_TYPE_S)
#define SXE2_SINGLE_ACT_TO_LARGE		BIT(0)
#define SXE2_SINGLE_ACT_HASFWD			BIT(1)

#define SXE2_MAC_NUM					(4)

#define SXE2_RSS_FV_CNT				(24)

#define SXE2_RSS_FV_TRACE_CNT			(12)

#define SXE2_OG_BUF_SIZE      (4096)
#define SXE2_FV_CNT_MAX       SXE2_SWITCH_FV_CNT
#define SXE2_FNAV_INPUT_CNT   (30)

#define SXE2_BFD_FV_CNT_MAX   (32)

#define SXE2_RXFT_PPE_INFO_REG_CNT (20)

#define SXE2_FV_DIRECTION_OFFSET	(10)
#define SXE2_FV_DIRECTION_MASK		BIT(SXE2_FV_DIRECTION_OFFSET)
#define SXE2_FV_DIRECTION_TX		(0)
#define SXE2_FV_DIRECTION_RX		(1)

#define SXE2_FV_CAST_OFFSET		(0)
#define SXE2_FV_CAST_UNI		(0)
#define SXE2_FV_CAST_MULTI		(1)
#define SXE2_FV_CAST_BROAD		(2)

#define SXE2_FV_PKT_SRC_OFFSET		(10)
#define SXE2_FV_PKT_SRC_MASK		(0x3 << SXE2_FV_PKT_SRC_OFFSET)
#define SXE2_FV_PKT_SRC_TX			(0x3)
#define SXE2_FV_PKT_SRC_RX			(0x0)

#define SXE2_FV_VSI_NUM_OFFSET		(0)
#define SXE2_FV_VSI_NUM_MASK		(0x3ff << SXE2_FV_VSI_NUM_OFFSET)

#define SXE2_FV_PKT_TO_RDMA_OFFSET		(8)
#define SXE2_FV_PKT_TO_RDMA_MASK		(0x1 << SXE2_FV_PKT_TO_RDMA_OFFSET)
#define SXE2_FV_PKT_TO_RDMA			(1)
#define SXE2_FV_PKT_TO_RDMA_NO			(0)

#define SXE2_SWITCH_RECIPE_PRIO_7	(7)
#define SXE2_SWITCH_RECIPE_PRIO_6	(6)

#define SXE2_LLDP_FRAME_MAX_SIZE	(1500)
#define SXE2_MAX_TRAFFIC_CLASS		(8)
#define SXE2_MAX_USER_PRIORITY         (8)
#define SXE2_DCBX_MAX_APPS		    (64)
#define SXE2_DSCP_MAX_NUM          (64)

#define SXE2_DSCP_OUI				(0xFFFFFFU)
#define SXE2_DSCP_SUBTYPE_DSCP2UP	(0x41U)
#define SXE2_DSCP_SUBTYPE_ENFORCE	(0x42U)
#define SXE2_DSCP_SUBTYPE_TCBW		(0x43U)
#define SXE2_DSCP_SUBTYPE_PFC		(0x44U)
#define SXE2_DSCP_IPV6_OFFSET		(80)
#define SXE2_DSCP_IPV4_UNTAG_OFFSET    (64)
#define SXE2_DSCP_IPV6_UNTAG_OFFSET    (144)

#define SXE2_CMD_VSI_STATS_MAX_CNT     (16)

#define SXE2_SERIAL_NUM_LEN (20)

#define SXE2_MDD_TYPE_TX (1)
#define SXE2_MDD_TYPE_RX (2)

#define SXE2_FNAV_DEFAULT_MASK_CNT (6)

#define SXE2_RSS_CORE_LUT_SIZE (32)

#define SXE2_LARGE_ACTION_COUNT_IN_GROUP (4)
#define SXE2_FLM_VENDOR_LEN 16
#define SXE2_FLM_VENDOR_PN_LEN 16
#define SXE2_HOST_FLM_VENDOR_LEN 32
#define SXE2_HOST_FLM_VENDOR_PN_LEN 32

#define SXE2_LLDP_FW_AGENT_DISABLE 0
#define SXE2_LLDP_FW_AGENT_ENABLE 1

enum sxe2_txq_quanta_prof_cfg {
	SXE2_TXQ_QUANTA_PROF_DEFAULT = 0,
	SXE2_TXQ_QUANTA_PROF_SIMPLE,
	SXE2_TXQ_QUANTA_PROF_COMPLEX,
};

enum sxe2_cmd_type {
	SXE2_CMD_TYPE_CLI = 0,
	SXE2_CMD_TYPE_DRV_TO_FW,
	SXE2_CMD_TYPE_FW_NOTIFY,
	SXE2_CMD_TYPE_PF_TO_VF,
	SXE2_CMD_TYPE_VF_TO_PF,
	SXE2_CMD_TYPE_DRV_TO_HW,
	SXE2_CMD_TYPE_PF_REPLY_VF,
};

enum sxe2_cmd_module {
	SXE2_CMD_MODULE_HANDSHAKE = 0,
	SXE2_CMD_MODULE_CAPS = 1,
	SXE2_CMD_MODULE_VSI = 2,
	SXE2_CMD_MODULE_QUEUE = 3,
	SXE2_CMD_MODULE_CFG = 4,
	SXE2_CMD_MODULE_SWITCH = 5,
	SXE2_CMD_MODULE_RULE = 6,
	SXE2_CMD_MODULE_EVENT = 7,
	SXE2_CMD_MODULE_MBX = 8,
	SXE2_CMD_MODULE_TXSCHED = 9,
	SXE2_CMD_MODULE_STATS = 11,
	SXE2_CMD_MODULE_OPT = 12,
	SXE2_CMD_MODULE_RSS = 13,
	SXE2_CMD_MODULE_LED = 14,
	SXE2_CMD_MODULE_OG = 15,
	SXE2_CMD_MODULE_RDMA = 16,
	SXE2_CMD_MODULE_IPSEC = 17,
	SXE2_CMD_MODULE_FNAV = 18,
	SXE2_CMD_MODULE_PXE = 19,
	SXE2_CMD_MODULE_DCB = 20,
	SXE2_CMD_MODULE_LLDP = 21,
	SXE2_CMD_MODULE_PTP = 22,
	SXE2_CMD_MODULE_MACADDR = 23,
	SXE2_CMD_MODULE_MACSEC = 24,
	SXE2_CMD_MODULE_UPGRADE = 25,
	SXE2_CMD_MODULE_ETHTOOL = 26,
	SXE2_CMD_MODULE_FLM = 27,
	SXE2_CMD_MODULE_SFP = 28,
	SXE2_CMD_MODULE_RWREG = 29,
	SXE2_CMD_MODULE_UDPTUNEEL = 30,
	SXE2_CMD_MODULE_NCD = 31,
	SXE2_CMD_MODULE_BFD = 32,
	SXE2_CMD_MODULE_NCD_UDF = 33,
	SXE2_CMD_MODULE_QUEUE_STATS_MAP = 34,
	SXE2_CMD_MODULE_ACL = 35,
};

enum sxe2_drv_cmd_opcode {
	SXE2_CMD_Q_HANDSHAKE = SXE2_MK_CMD(SXE2_CMD_MODULE_HANDSHAKE, 1),
	SXE2_CMD_Q_DISABLE   = SXE2_MK_CMD(SXE2_CMD_MODULE_HANDSHAKE, 3),

	SXE2_CMD_DEV_CAPS = SXE2_MK_CMD(SXE2_CMD_MODULE_CAPS, 1),
	SXE2_CMD_FUNC_CAPS,
	SXE2_CMD_PF_CFG_CLEAR,
	SXE2_CMD_PF_SRIOV_SET,
	SXE2_CMD_PF_DDP_REF_CLR,
	SXE2_CMD_PHY_PORT_INFO_GET,
	SXE2_CMD_PF_SERIAL_GET,
	SXE2_CMD_DRV_MODE_GET,
	SXE2_CMD_DRV_MODE_SET,

	SXE2_CMD_VSI_CFG = SXE2_MK_CMD(SXE2_CMD_MODULE_VSI, 1),
	SXE2_CMD_UPDATE_VSI,
	SXE2_CMD_FREE_VSI,
	SXE2_CMD_VSI_VLAN_FILTER,
	SXE2_CMD_VSI_LOOPBACK,
	SXE2_CMD_VSI_SPOOFCHK,
	SXE2_CMD_VSI_SRC_PRUNE,
	SXE2_CMD_VSI_MDD_CHECK,
	SXE2_CMD_VSI_VF_QUEUE_SET,
	SXE2_CMD_VSI_VF_QUEUE_CLEAR,

	SXE2_CMD_TXQ_CFG_AND_ENABLE  = SXE2_MK_CMD(SXE2_CMD_MODULE_QUEUE, 1),
	SXE2_CMD_RXQ_CFG    = SXE2_MK_CMD(SXE2_CMD_MODULE_QUEUE, 2),
	SXE2_CMD_RX_FB    = SXE2_MK_CMD(SXE2_CMD_MODULE_QUEUE, 3),
	SXE2_CMD_TXQ_DISABLE = SXE2_MK_CMD(SXE2_CMD_MODULE_QUEUE, 4),
	SXE2_CMD_TXQ_STATE = SXE2_MK_CMD(SXE2_CMD_MODULE_QUEUE, 5),

	SXE2_CMD_CFG_DOWNLOAD = SXE2_MK_CMD(SXE2_CMD_MODULE_CFG, 1),
	SXE2_CMD_CFG_UPDATE,
	SXE2_CMD_DP_DLD_PRE,
	SXE2_CMD_DP_DLD_PROC,
	SXE2_CMD_DP_DLD_DONE,
	SXE2_CMD_DP_DLD_STATE,

	SXE2_CMD_SWITCH_RULE_ADD = SXE2_MK_CMD(SXE2_CMD_MODULE_SWITCH, 1),
	SXE2_CMD_SWITCH_RULE_DEL,
	SXE2_CMD_SWITCH_RULE_UPDATE,
	SXE2_CMD_SWITCH_RULE_GET,
	SXE2_CMD_SWITCH_VSI_LIST_ADD,
	SXE2_CMD_SWITCH_VSI_LIST_DEL,
	SXE2_CMD_SWITCH_VSI_LIST_GET,
	SXE2_CMD_SWITCH_VSI_LIST_UPDATE,
	SXE2_CMD_SWITCH_LARGE_ACTION_CFG,
	SXE2_CMD_SWITCH_RULE_CPX_ADD,
	SXE2_CMD_SWITCH_RULE_CPX_DEL,
	SXE2_CMD_SWITCH_RULE_CPX_UPDATE,
	SXE2_CMD_SWITCH_RULE_CPX_GET,
	SXE2_CMD_SWITCH_TRACE_TRIGGER,
	SXE2_CMD_SWITCH_TRACE_RECORDER,
	SXE2_CMD_HW_DFX_SHOW,
	SXE2_CMD_SWITCH_RECIPE_GET,
	SXE2_CMD_SWITCH_PROFILE_RECIPE_MAP_GET,
	SXE2_CMD_SWITCH_SHARE_ID_GET,
	SXE2_CMD_SWITCH_DFX_IRQ,

	SXE2_CMD_PARSE_RULE = SXE2_MK_CMD(SXE2_CMD_MODULE_RULE, 1),
	SXE2_CMD_UDP_TUNNEL_PORT,

	SXE2_CMD_EVENT_SUBSCRIBE = SXE2_MK_CMD(SXE2_CMD_MODULE_EVENT, 1),
	SXE2_CMD_EVENT_UNSUBSCRIBE,
	SXE2_CMD_EVENT_FW_LOG_ACK,

	SXE2_CMD_MBX_TO_PF =
		SXE2_MK_CMD(SXE2_CMD_MODULE_MBX, 1),
	SXE2_CMD_MBX_TO_VF =
		SXE2_MK_CMD(SXE2_CMD_MODULE_MBX, 2),

	SXE2_CMD_TXSCHED_CAP_QUERY =  SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 1),
	SXE2_CMD_TXSCHED_DFLT_TOPO_QUERY = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 2),
	SXE2_CMD_TX_SCHED_NODE_INFO_QUERY = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 3),
	SXE2_CMD_TX_SCHED_NODE_DEL  = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 4),
	SXE2_CMD_TX_SCHED_NODE_ADD  = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 5),
	SXE2_CMD_TX_SCHED_NODE_SUSPEND = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 6),
	SXE2_CMD_TX_SCHED_NODE_RESUME = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 7),
	SXE2_CMD_TX_SCHED_LEAF_NODE_ADD = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 10),
	SXE2_CMD_TX_SCHED_LEAF_NODE_DEL = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 11),
	SXE2_CMD_TX_SCHED_NODE_RL_CFG  = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 12),
	SXE2_CMD_TX_SCHED_Q_CFG     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 13),
	SXE2_CMD_TX_SCHED_Q_STOP     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 14),
	SXE2_CMD_TX_SCHED_ETS_QUERY     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 15),
	SXE2_CMD_TX_SCHED_LEAF_NODE_MOVE     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 16),
	SXE2_CMD_TX_SCHED_QSET_LEAF_ADD     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 17),
	SXE2_CMD_TX_SCHED_QSET_LEAF_DEL     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 18),
	SXE2_CMD_TX_SCHED_PRIO_CFG     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 19),
	SXE2_CMD_TX_SCHED_WEIGHT_CFG	= SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 20),
	SXE2_CMD_TX_SCHED_QUEUE_LEAF_ADD     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 21),
	SXE2_CMD_TX_SCHED_QUEUE_LEAF_DEL     = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 22),
	SXE2_CMD_TX_SCHED_NODE_SRL_CFG  = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 23),
	SXE2_CMD_TX_SCHED_PROFILE_RL_PRE_QUERY = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 24),
	SXE2_CMD_TX_SCHED_PROFILE_SRL_ADD  = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 25),
	SXE2_CMD_TX_SCHED_PROFILE_SRL_DEL  = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 26),
	SXE2_CMD_TX_SCHED_PROFILE_SRL_UPD  = SXE2_MK_CMD(SXE2_CMD_MODULE_TXSCHED, 27),

	SXE2_CMD_GET_PF_STATS = SXE2_MK_CMD(SXE2_CMD_MODULE_STATS, 1),
	SXE2_CMD_GET_VSI_STATS = SXE2_MK_CMD(SXE2_CMD_MODULE_STATS, 2),
	SXE2_CMD_GET_PPE_DFX,

	SXE2_CMD_OPT_EEP = SXE2_MK_CMD(SXE2_CMD_MODULE_OPT, 1),

	SXE2_CMD_RSS_VSI_HCTRL_SET = SXE2_MK_CMD(SXE2_CMD_MODULE_RSS, 1),
	SXE2_CMD_RSS_LUT_SET,
	SXE2_CMD_RSS_LUT_GET,
	SXE2_CMD_RSS_HKEY_SET,
	SXE2_CMD_RSS_HKEY_GET,
	SXE2_CMD_RSS_SYMM_FV_SET,
	SXE2_CMD_RSS_TRACE_TRIGGER,
	SXE2_CMD_RSS_TRACE_RECORDER,

	SXE2_CMD_LED_CTRL = SXE2_MK_CMD(SXE2_CMD_MODULE_LED, 1),

	SXE2_CMD_OG_CFG_UPDATE = SXE2_MK_CMD(SXE2_CMD_MODULE_OG, 1),
	SXE2_CMD_OG_TCAM_ENTRY_ALLOC,
	SXE2_CMD_OG_TCAM_ENTRY_FREE,
	SXE2_CMD_OG_TCAM_ENTRY_BATCH,
	SXE2_CMD_OG_PROF_ID_ALLOC,
	SXE2_CMD_OG_PROF_ID_FREE,
	SXE2_CMD_OG_MASK_SEL_UPDATE,

	SXE2_CMD_RDMA_QP_ATTACH_MC = SXE2_MK_CMD(SXE2_CMD_MODULE_RDMA, 1),
	SXE2_CMD_RDMA_QP_DETACH_MC,
	SXE2_CMD_RDMA_QET_BIND_TC,
	SXE2_CMD_RDMA_PF_FUNC_TABLE_INIT,
	SXE2_CMD_RDMA_DESTROY_CC_QP,
	SXE2_CMD_RDMA_GET_CC_QP_DFX,
	SXE2_CMD_RDMA_NOTIFY_STATUS,

	SXE2_CMD_IPSEC_GET_CAPA = SXE2_MK_CMD(SXE2_CMD_MODULE_IPSEC, 1),
	SXE2_CMD_IPSEC_TXSA_ADD,
	SXE2_CMD_IPSEC_TXSA_DEL,
	SXE2_CMD_IPSEC_TXSA_SET,
	SXE2_CMD_IPSEC_RXSA_ADD,
	SXE2_CMD_IPSEC_RXSA_DEL,
	SXE2_CMD_IPSEC_RXSA_SET,
	SXE2_CMD_IPSEC_STATS_SHOW,
	SXE2_CMD_IPSEC_TXRX_SWITCH,
	SXE2_CMD_IPSEC_DRV_CLEAR,

	SXE2_CMD_FNAV_FILTER_UPDATE = SXE2_MK_CMD(SXE2_CMD_MODULE_FNAV, 1),
	SXE2_CMD_FNAV_TRACE_TRIGGER,
	SXE2_CMD_FNAV_TRACE_RECORDER,
	SXE2_CMD_FNAV_HW_STS,
	SXE2_CMD_FNAV_HW_CLEAR,
	SXE2_CMD_RXFT_PPE_INFO,
	SXE2_CMD_VF_FNAV_FILTER_CLEAR,
	SXE2_CMD_FNAV_STATS_GET,
	SXE2_CMD_FNAV_DFLT_COMP_QIDX_SET,
	SXE2_CMD_FNAV_SPACE_CNT_GET,
	SXE2_CMD_FNAV_MATCH_GET_BATCH,

	SXE2_PXE_CTRL = SXE2_MK_CMD(SXE2_CMD_MODULE_PXE, 1),
	SXE2_UEFI_PRIV_DATA_SET,
	SXE2_UEFI_PRIV_DATA_GET,
	SXE2_UEFI_SOCINFO_GET,

	SXE2_CMD_QOS_MODE_SET = SXE2_MK_CMD(SXE2_CMD_MODULE_DCB, 1),
	SXE2_CMD_QOS_MODE_GET,
	SXE2_CMD_LINK_FLOW_CONTROL_GET,
	SXE2_CMD_LINK_FLOW_CONTROL_SET,

	SXE2_CMD_LLDP_MIB_SET = SXE2_MK_CMD(SXE2_CMD_MODULE_LLDP, 1),
	SXE2_CMD_LLDP_MIB_GET,
	SXE2_CMD_LLDP_MIB_NOTIFY,
	SXE2_CMD_LLDP_DCBX_FW_AGENT_SET,
	SXE2_CMD_LLDP_DCBX_FW_AGENT_GET,
	SXE2_CMD_LLDP_FW_STATS,
	SXE2_CMD_LLDP_REMOTE_MIBS_INFO,
	SXE2_CMD_LLDP_REMOTE_MIBS_DUMP,
	SXE2_CMD_LLDP_FW_AGENT_SET,
	SXE2_CMD_LLDP_FW_AGENT_GET,

	SXE2_CMD_PTP_INIT = SXE2_MK_CMD(SXE2_CMD_MODULE_PTP, 1),
	SXE2_CMD_PTP_RX_MODE_SET,
	SXE2_CMD_PTP_SEM_CLEAN,

	SXE2_CMD_MAC_ADDR_GET = SXE2_MK_CMD(SXE2_CMD_MODULE_MACADDR, 1),
	SXE2_CMD_MAC_ADDR_SET,
	SXE2_CMD_MAC_MTU_SET,

	SXE2_CMD_MACSEC_TXSC_CFG = SXE2_MK_CMD(SXE2_CMD_MODULE_MACSEC, 1),
	SXE2_CMD_MACSEC_TXSA_CFG,
	SXE2_CMD_MACSEC_RXSC_CFG,
	SXE2_CMD_MACSEC_RXSA_CFG,
	SXE2_CMD_MACSEC_FIX_CFG,

	SXE2_CMD_FW_DOWNLOAD = SXE2_MK_CMD(SXE2_CMD_MODULE_UPGRADE, 1),
	SXE2_CMD_FW_DOWNLOAD_PRE,
	SXE2_CMD_FW_DOWNLOAD_OPEN,
	SXE2_CMD_FW_DOWNLOAD_FLASH,
	SXE2_CMD_FW_DOWNLOAD_CLOSE,
	SXE2_CMD_FW_DOWNLOAD_END,

	SXE2_CMD_TXQUEUE_STATS_MAP_POOL_GET = SXE2_MK_CMD(SXE2_CMD_MODULE_QUEUE_STATS_MAP, 1),
	SXE2_CMD_RXQUEUE_STATS_MAP_POOL_GET,
	SXE2_CMD_TXQUEUE_STATS_MAP_POOL_SET,
	SXE2_CMD_RXQUEUE_STATS_MAP_POOL_SET,
	SXE2_CMD_RXQUEUE_STATS_MAP_INFO_GET,
	SXE2_CMD_RXLAN_QUEUE_STATS_MAP_INFO_GET,
	SXE2_CMD_TXQUEUE_STATS_MAP_INFO_GET,
	SXE2_CMD_TXQUEUE_STATS_MAP_INFO_CLEAR,
	SXE2_CMD_RXQUEUE_STATS_MAP_INFO_CLEAR,
	SXE2_CMD_RXLAN_QUEUE_STATS_MAP_INFO_CLEAR,
	SXE2_CMD_RXQUEUE_STATS_MAP_RES_REL,
	SXE2_CMD_TXQUEUE_STATS_MAP_RES_REL,

	SXE2_CMD_ETHTOOL_LOOPBACK_SET = SXE2_MK_CMD(SXE2_CMD_MODULE_ETHTOOL, 1),

	SXE2_CMD_FLM_INIT = SXE2_MK_CMD(SXE2_CMD_MODULE_FLM, 1),
	SXE2_CMD_FLM_LINK_UP,
	SXE2_CMD_FLM_LINK_DOWN,
	SXE2_CMD_FLM_FEC_GET,
	SXE2_CMD_FLM_FEC_SET,
	SXE2_CMD_FLM_AN_SET,
	SXE2_CMD_FLM_LINK_INFO_SET,
	SXE2_CMD_FLM_LINK_INFO_GET,
	SXE2_CMD_FLM_LINK_STATUS_SET,
	SXE2_CMD_FLM_LINK_STATUS_SYNC,
	SXE2_CMD_TEST_LINK_STATUS,
	SXE2_CMD_FLM_LINK_UP_DOWN_SET,

	SXE2_CMD_SFP_WHITE_CFG = SXE2_MK_CMD(SXE2_CMD_MODULE_SFP, 1),
	SXE2_CMD_SFP_TX_FAULT_CFG,
	SXE2_CMD_SFP_SET_FEC_CFG,
	SXE2_CMD_SFP_GET_FEC_CFG,
	SXE2_CMD_SFP_GET_LINKINFO_CFG,
	SXE2_CMD_ETHTOOL_GET_LINKINFO_CFG,
	SXE2_CMD_ETHTOOL_SET_LINKINFO_CFG,
	SXE2_CMD_PERSIST_GET_LINK_CFG,
	SXE2_CMD_SUPPORT_SPEED_GET_CFG,
	SXE2_CMD_CURRENT_SPEED_STATUS_GET_CFG,
	SXE2_CMD_CURRENT_SPEED_GET_CFG,
	SXE2_CMD_SFP_SET_LINK_CFG,
	SXE2_CMD_GET_LINKST_CFG,
	SXE2_CMD_GET_VENDOR_INFO_CHECK_WARNING,
	SXE2_CMD_GET_OPT_DATA_INFO,

	SXE2_CMD_CLI_READ_REG = SXE2_MK_CMD(SXE2_CMD_MODULE_RWREG, 1),
	SXE2_CMD_CLI_WRITE_REG,

	SXE2_CMD_UDPTUNNEL_ADD = SXE2_MK_CMD(SXE2_CMD_MODULE_UDPTUNEEL, 1),
	SXE2_CMD_UDPTUNNEL_DEL,
	SXE2_CMD_UDPTUNNEL_GET,

	SXE2_CMD_BFD_INTRQ_GET = SXE2_MK_CMD(SXE2_CMD_MODULE_BFD, 1),
	SXE2_CMD_BFD_CAPA_GET,
	SXE2_CMD_BFD_CFG_SET,
	SXE2_CMD_BFD_SESS_CFG_SET,
	SXE2_CMD_BFD_SESS_STATE_GET,
	SXE2_CMD_BFD_PACK_PROF_SET,
	SXE2_CMD_BFD_FLOW_RULE_SET,
	SXE2_CMD_BFD_KEYLEN_SET,

	SXE2_CMD_NCD_CORE_NUM = SXE2_MK_CMD(SXE2_CMD_MODULE_NCD, 1),
	SXE2_CMD_NCD_CORE_FS_QUEUE_SET,
	SXE2_CMD_NCD_CORE_FS_QUEUE_GET,

	SXE2_CMD_NCD_UDF_CAPA_GET = SXE2_MK_CMD(SXE2_CMD_MODULE_NCD_UDF, 1),

	SXE2_CMD_NCD_SWITCH_TAG_EN,
	SXE2_CMD_NCD_SWITCH_TAG_SET,
	SXE2_CMD_NCD_SWITCH_TAG_GET,
	SXE2_CMD_NCD_TXLEN_ADJ_SET,
	SXE2_CMD_NCD_TXLEN_ADJ_GET,

	SXE2_CMD_NCD_SDF_EN,
	SXE2_CMD_NCD_SDF_SET,
	SXE2_CMD_NCD_SDF_GET,

	SXE2_CMD_NCD_SDN_UDP_ADD,
	SXE2_CMD_NCD_SDN_UDP_DEL,
	SXE2_CMD_NCD_SDN_UDP_QUERY,
	SXE2_CMD_NCD_SDN_ADD,
	SXE2_CMD_NCD_SDN_DEL,
	SXE2_CMD_NCD_SDN_QUERY,
	SXE2_CMD_NCD_SDN_IPSEC_QUERY,
	SXE2_CMD_NCD_SDN_IPSEC_UDP_ADD,
	SXE2_CMD_NCD_SDN_IPSEC_UDP_DEL,

	SXE2_CMD_NCD_APP_PORT_SET,

	SXE2_CMD_NCD_PKT_PRI_SET,

	SXE2_CMD_ACL_LUT_ALLOC = SXE2_MK_CMD(SXE2_CMD_MODULE_ACL, 1),
	SXE2_CMD_ACL_LUT_DEALLOC,
	SXE2_CMD_ACL_PROF_SEL_BASE_SET,
	SXE2_CMD_ACL_SCEN_ALLOC,
	SXE2_CMD_ACL_SCEN_DEALLOC,
	SXE2_CMD_ACL_LUT_ENTRY_SET,
	SXE2_CMD_ACL_ACT_ENTRY_SET,
	SXE2_CMD_ACL_TRACE_TRIGGER,
	SXE2_CMD_ACL_TRACE_RECORDER,
	SXE2_CMD_ACL_DFX_INFO_GET,

	SXE2_CMD_MAX = 0xFFFF,
};

enum sxe2_drv_event_code {
	SXE2_EVENT_CODE_INVAL = 0,
	SXE2_EVENT_CODE_AUTO_LOG,
	SXE2_EVENT_CODE_MIB_NOTIFY,
	SXE2_EVENT_CODE_SFP_WHITE_LIST,
	SXE2_EVENT_CODE_SFP_TX_FAULT,
	SXE2_EVENT_CODE_QSFP_TX_FAULT_COUNT,
	SXE2_EVENT_CODE_LLDP_AGENT_NOTIFY,

	SXE2_EVENT_CODE_MAX,
	SXE2_EVENT_CODE_ALL = 255,
};

enum sxe2_desc_err_code {
	SXE2_CMD_DESC_ERR_NONE = 0,
	SXE2_CMD_DESC_ERR_DES_ERR,
	SXE2_CMD_DESC_ERR_BUF_ERR,
	SXE2_CMD_DESC_ERR_BUF_NUM_ERR,
	SXE2_CMD_DESC_ERR_SRC_BUSY,
	SXE2_CMD_DESC_ERR_DATA_LEN_LACK,
	SXE2_CMD_DESC_ERR_DATA_LEN_LACK2,
	SXE2_CMD_DESC_ERR_SESSION_BUFFER_OV,
	SXE2_CMD_DESC_ERR_CMD_BUFFER_OV,
	SXE2_CMD_DESC_ERR_IN_OUT_LEN_LACK,
	SXE2_CMD_DESC_ERR_UNKNOWN_OPCODE,
	SXE2_CMD_DESC_ERR_UNKNOWN_CMD_TYPE,
	SXE2_CMD_DESC_ERR_ADMINQ_STATE,
	SXE2_CMD_DESC_ERR_FIND_JOB,
	SXE2_CMD_DESC_ERR_NONE_START,
	SXE2_CMD_DESC_ERR_JOB_DELIVERY,
	SXE2_CMD_DESC_ERR_PF_FLR,
	SXE2_CMD_DESC_ERR_OVER_FLOW,
	SXE2_CMD_DESC_ERR_SEQ_ERR,
	SXE2_CMD_DESC_ERR_NR,
};

enum sxe2_cmd_drv_err_code {
	SXE2_CMD_DRV_SUCCESS = 0,
	SXE2_CMD_DRV_HW_OP_ERR = 1024,

	SXE2_CMD_DRV_NO_FREE_VSI,
	SXE2_CMD_DUMP_LOG_FAILED,

	SXE2_CMD_DRV_RXQ_CFG_FAIL,
	SXE2_CMD_DRV_TXQ_EN_FAIL,
	SXE2_CMD_DRV_TXQ_DISA_FAIL,

	SXE2_CMD_DRV_PFR_FAILED,
	SXE2_CMD_DRV_VFR_FAILED,
	SXE2_CMD_DRV_PARAM_INVALID,
	SXE2_CMD_DRV_HW_RETURN,
	SXE2_CMD_DRV_HW_TIMEOUT,
	SXE2_CMD_DRV_HW_MISMATCH,
	SXE2_CMD_DRV_HW_NOSPC,
	SXE2_CMD_DRV_HW_EXIST,
	SXE2_CMD_DRV_HW_HID_EXIST,
	SXE2_CMD_DRV_HW_NOENT,
	SXE2_CMD_DRV_FW_NOMEM,
	SXE2_CMD_DRV_HW_NO_RES,
	SXE2_CMD_DRV_TLV_ERROR,
	SXE2_CMD_DRV_DCB_ERROR,
	SXE2_CMD_DRV_LINK_REBUILD_FAILED,

	SXE2_CMD_DRV_UNSUPPORT,
	SXE2_CMD_DRV_TXSCHED_CFG_FAILED,
	SXE2_CMD_DRV_TXSCHED_TIMEOUT,
	SXE2_CMD_DRV_TXSCHED_TEID_ALLOC_FAILED,
	SXE2_CMD_DRV_TXSCHED_CHILDIDX_ALLOC_FAILED,
	SXE2_CMD_DRV_TXSCHED_ALLOC_FAILED,

	SXE2_CMD_DRV_UDP_TUNNEL_WRONG_PORT,

	SXE2_CMD_DRV_NCD_UNSUPPORT,
	SXE2_CMD_DRV_BFD_INTQ_NOP,
	SXE2_CMD_DRV_BFD_FLOW_NOSPC,
	SXE2_CMD_DRV_BFD_FLOW_HT_COLLISION,

	SXE2_CMD_DRV_LINK_UPDATE_FAILED,
	SXE2_OPT_DEV_BUSY,

};

enum sxe2_fwc_mapping_mode {
	SXE2_MAPPING_CONTIG = 0,
	SXE2_MAPPING_SCATTER,
};

enum sxe2_fwc_vsi_type_hw {
	SXE2_VSI_HW_T_VF    = 0,
	SXE2_VSI_HW_T_VMDQ2 = 1,
	SXE2_VSI_HW_T_PF    = 2,
	SXE2_VSI_HW_T_MNG   = 3,
};

enum sxe2_cmd_buffer_st {
	SXE2_CMD_BUFFER_ST_NORMAL = (s16)0,
	SXE2_CMD_BUFFER_ST_OVERFLOW,
	SXE2_CMD_BUFFER_ST_SEQ_ERR,
	SXE2_CMD_BUFFER_ST_NR,
};

enum sxe2_cmd_queue_stats_map_add {
	SXE2_CMD_QUEUE_STATS_MAP_ADD_SUCCEED = 0,
	SXE2_CMD_QUEUE_STATS_MAP_ADD_FAIL = 1,
};

enum sxe2_weight_type {
	SXE2_UNKNOWN_TYPE = 0,
	SXE2_CIR_WEIGHT,
	SXE2_PIR_WEIGHT,
};

struct sxe2_cmd_desc {
	__le16 flags;
	__le16 opcode;
	__le16 data_len;
	__le16 ret;
	u8  checksum;
	u8  rsvd[3];
	__le32 custom1;
	__le32 custom2;
	__le32 custom3;
	__le32 buf_addr_h;
	__le32 buf_addr_l;
};

#define SXE2_CMD_HDR_MULTI_END BIT(6)
#define SXE2_CMD_HDR_MULTI_START BIT(7)
#define SXE2_CMD_HDR_MULTI_CMD_ID_MASK 0x3F
struct sxe2_cmd_hdr {
	__le32 magic_code;
	__le16 tran_in_len;
	__le16 tran_out_len;
	__le16 hdr_len;
	u8     cmd_type;
	u8     multi_packet;

	__le64 trace_id;
	__le64 session_id;
	__le32 ret;
	__le32 timeout;
	u8     no_resp;
	u8     resv1;
	__le16 cur_in_len;
	u8     resv[24];
	u8     body[];
};

struct sxe2_drv_msg_hdr {
	__le32 op_code;
	__le32 err_code;
	__le32 data_offset;
	__le32 data_len;
	__le16 vf_id;
	u8     mac_id;
	u8     mac_id_valid;
	u8     resv[12];
	u8     body[];
};

struct sxe2_channel_handshake_req {
	__le32 drv_ver;
	u8     drv_mode;
	u8     resv[3];
	__le64 timestamp;
};

struct sxe2_channel_handshake_resp {
	__le32 fw_ver;
};

struct sxe2_fwc_serial_num_resp {
	u8 serial_num[SXE2_SERIAL_NUM_LEN];
};

struct sxe2_fwc_drv_mode_resp {
	u8 drv_mode;
	u8 reserve[3];
};

struct sxe2_fwc_drv_mode_req {
	u8 drv_mode;
	u8 reserve[3];
};

struct sxe2_fwc_vf_caps {
	__le16 cnt;
	__le16 base_idx;
	u8     sriov_cap;
	u8     resv[27];
};

struct sxe2_fwc_queue_caps {
	__le16 cnt;
	__le16 base_idx;
	u8     resv[28];
};

struct sxe2_fwc_msix_caps {
	__le16 cnt;
	__le16 base_idx;
	u8     resv[28];
};

struct sxe2_fwc_vsi_caps {
	__le16 cnt;
	__le16 base_idx;
	u8     resv[28];
};

struct sxe2_fwc_ppe_caps {
	__le16 rss_lut_size;
	__le16 fnav_space_bsize;
	__le16 fnav_space_gsize;
	__le16 fnav_counter_base;
	__le16 fnav_counter_num;
	__le16 bfd_sess_size;
	__le16 rss_global_lut_base;
	__le16 rss_global_lut_num;
	u8     resv[16];
};

struct sxe2_dev_common_caps {
	u8 rdma_support;
	u8 ipsec_support;
	u8 macsec_support;
	u8 rss_support;
	u8 fnav_support;
	u8 acl_support;
	u8 switch_support;
	u8 bfd_support;
	u8 sdn_support;
	u8 sdf_support;
	u8 core_fs_support;
	u8 switch_tag_support;
	u8 mac_ts_support;
	u8 resv[19];
};

struct sxe2_fwc_dev_caps {
	u8 pf_cnt;
	u8 port_cnt;
	__le16 vf_cnt;
	struct sxe2_dev_common_caps  dev_common_caps;
	u8 pad[92];
};

struct sxe2_common_caps {
	u8 vmdq_support;
	u8 ptp_owner;
	u8 resv[30];
};

struct sxe2_fwc_func_caps {
	struct sxe2_fwc_vf_caps    vf_caps;
	struct sxe2_fwc_queue_caps tx_caps;
	struct sxe2_fwc_queue_caps rx_caps;
	struct sxe2_fwc_msix_caps  msix_caps;
	struct sxe2_fwc_vsi_caps   vsi_caps;
	struct sxe2_fwc_ppe_caps   ppe_caps;
	struct sxe2_common_caps    common_caps;
	u8 pf_idx;
	u8 port_idx;
	u8 mode;
	u8 resv;
};

struct sxe2_fwc_sw_cfg_entry {
	__le16 type;
	__le16 idx;
	__le16 sw_id;
	__le16 pf_vf_id;
	u8     resv[8];
};

struct sxe2_fwc_phy_port_info {
	u8 mac_to_phy_port[SXE2_MAC_NUM];
};

struct sxe2_fwc_sw_cfg {
	__le16                    count;
	__le16                    remain;
	struct sxe2_fwc_sw_cfg_entry caps_entry[];
};

struct sxe2_fwc_tc_rxq_info {
	__le16 pow;
	__le16 offset;
};

struct sxe2_fwc_vsi_q_info {
	u8 mapping_mode;
	u8 resv[7];
	__le16 cnt;
	u8 resv1[6];
	union {
		__le16 base_idx;
		__le16 q_id[SXE2_VSI_SCATTER_TXRX_Q_MAX_CNT];
	};

	struct sxe2_fwc_tc_rxq_info tc_q_map[SXE2_TC_MAX_CNT];
};

struct sxe2_fwc_vsi_fnav_info {
	u8 fnav_enable;
	u8 auto_evict;
	u8 prog_enable;
	u8 rsv0[1];
	__le16 gsize;
	__le16 bsize;
};

struct sxe2_fwc_vsi_props {
	u8                      rxq_valid;
	u8                      rsv[31];
	struct sxe2_fwc_vsi_q_info rxq_info;
	struct sxe2_fwc_vsi_q_info txq_info;
	struct sxe2_fwc_vsi_fnav_info fnav_info;

};

struct sxe2_fwc_vsi_crud_info {
	__le16 vsi_id;
	__le16 vf_id;
	u8 type;
	u8 is_clear;
	u8 resv[10];
	struct sxe2_fwc_vsi_props props;
};

struct sxe2_fwc_vsi_crud_resp {
	__le16 vsi_id;
	u8     resv[14];
};

struct sxe2_fwc_ena_txq_entry {
	__le16 q_id;
	u8     resv[2];
	u8     txq_ctxt[SXE2_TXQ_CTXT_LEN];
};

struct sxe2_fwc_ena_txqs {
	__le16                     cnt;
	u8                         resv[14];
	struct sxe2_fwc_ena_txq_entry txq[];
};

struct sxe2_fwc_dis_txqs {
	__le16 cnt;
	u8     resv[2];
	__le16 q_id[];
};

#define SXE2_TXSCHED_PROFIDX_INVALID   U16_MAX
#define SXE2_TXSCHED_TEID_INVALID      0x7FFF
#define SXE2_TXSHCED_HW_DEFT_LAYER     2
#define SXE2_TXSCHED_NODE_CHILD_MAX    8

#define SXE2_TXSCHED_MIN_BW            500
#define SXE2_TXSCHED_MAX_BW            100000000
#define SXE2_TXSCHED_BW_50G            50000000
#define SXE2_TXSCHED_BW_25G            25000000
#define SXE2_TXSCHED_BW_10G            10000000

#define SXE2_TXSCHED_DFLT_BW           0xFFFFFFFF
#define SXE2_TXSCHED_CLK_FREQ          500000000
#define SXE2_TXSCHED_ARB_CREDIT_TOTAL  32768
#define SXE2_TXSCHED_ARB_CREDIT_UNIT   328
#define SXE2_TXSCHED_ARB_CREDIT_DFLT   SXE2_TXSCHED_ARB_CREDIT_TOTAL

#define SXE2_NODE_RL_TYPE_CIR     BIT(0)
#define SXE2_NODE_RL_TYPE_EIR     BIT(1)
#define SXE2_NODE_RL_TYPE_SRL     BIT(2)

#define SXE2_NODE_ARB_MODE_BPS   0
#define SXE2_NODE_ARB_MODE_PPS   1

#define SXE2_NODE_STATUS_ENABLE   0x0
#define SXE2_NODE_STATUS_SUSPEND  0x1

#define SXE2_TXSCHED_DFLT_RL_PROF_ID 0

enum sxe2_txsched_node_owner {
	SXE2_TXSCHED_NODE_OWNER_LAN = 0,
	SXE2_TXSCHED_NODE_OWNER_RDMA,
	SXE2_TXSCHED_NODE_OWNER_USER,
	SXE2_TXSCHED_NODE_OWNER_UNKNOWN,
};

enum sxe2_txsched_hw_layer {
	SXE2_TXSCHED_HW_LAYER_UNDEFINED = 0,
	SXE2_TXSCHED_HW_LAYER_PORT,
	SXE2_TXSCHED_HW_LAYER_TC,
	SXE2_TXSCHED_HW_LAYER_SW_ENTRY,
	SXE2_TXSCHED_HW_LAYER_4,
	SXE2_TXSCHED_HW_LAYER_5,
	SXE2_TXSCHED_HW_LAYER_6,
	SXE2_TXSCHED_HW_LAYER_7,
};

struct sxe2_txsched_generic_props {
	u8  layer_max;

	__le32 clk_freq;
};

struct sxe2_txsched_layer_props {
	u8  hw_layer;
	__le16 max_rl_cir_prof;
	__le16 max_rl_pir_prof;
	__le16 max_rl_srl_prof;
};

struct sxe2_fwc_txsched_cap_resp {
	struct sxe2_txsched_generic_props generic;

	struct sxe2_txsched_layer_props layer[SXE2_TXSCHED_HW_LAYER_7];
};

struct scbge_txsched_node_bw {
	__le32 bw;
	__le32 prof_id;
	__le16 weight;
	__le16 rsv;
};

struct sxe2_txsched_node_props {
	u8 prio;
	u8 status;
	u8 arb_mode;
	u8 rl_type;
	enum sxe2_txsched_hw_layer  hw_layer;
	struct scbge_txsched_node_bw cir;
	struct scbge_txsched_node_bw srlPir;
	u8 adj_lvl;
	u8 rsv[3];
};

struct sxe2_txsched_node_info {
	__le16 parent_teid;
	__le16 node_teid;
	__le32 sibling_idx;
	struct sxe2_txsched_node_props data;
};

struct sxe2_fwc_txsched_dflt_topo_resp {
	struct sxe2_txsched_node_info node_info[SXE2_TXSHCED_HW_DEFT_LAYER];
};

struct sxe2_txsched_topo_upd_hdr {
	__le16 parent_teid;
	__le16 node_num;
	__le16 start_child_idx;
	__le16 rsv;
};

struct sxe2_fwc_txsched_del_nodes_req {
	struct sxe2_txsched_topo_upd_hdr hdr;
	__le16 teid[];
};

struct sxe2_fwc_txsched_move_nodes_req {
	struct sxe2_txsched_topo_upd_hdr hdr;
	__le16 teid[];
};

struct sxe2_fwc_txsched_query_node_req {
	__le16 parent_teid;
	__le16 node_teid;
	u8  sibling_idx;
};

struct sxe2_fwc_txsched_query_node_resp {
	struct sxe2_txsched_node_info node;
};

struct sxe2_fwc_txsched_pri_node_cfg_req {
	__le16 parent_teid;
	__le16 node_teid;
	u8  sibling_idx;
	u8  prio;
};

struct sxe2_fwc_txsched_weight_node_cfg_req {
	__le16 parent_teid;
	__le16 node_teid;
	u8  sibling_idx;
	__le16  weight;
	enum sxe2_weight_type type;
};

struct sxe2_fwc_txsched_add_nodes_req {
	struct sxe2_txsched_topo_upd_hdr hdr;
	struct sxe2_txsched_node_info node[];
};

struct sxe2_fwc_txsched_add_nodes_resp {
	__le32 add_node_num;
	__le16 node_teid[SXE2_TXSCHED_NODE_CHILD_MAX];
	__le16 sibling_idx[SXE2_TXSCHED_NODE_CHILD_MAX];
};

struct sxe2_fwc_txq_stats_map_pool_get_resp {
	u8 hw_index;
};

struct sxe2_fwc_rxq_stats_map_pool_get_resp {
	u8 hw_pool_idx;
};

struct sxe2_fwc_txq_stats_map_pool_set_req {
	u8 hw_index;
	u32 cfg_info;
};

struct sxe2_fwc_rxq_stats_map_pool_set_req {
	u8 hw_pool_idx;
	u32 cfg_info;
};

struct sxe2_fwc_txq_stats_map_get_info_req {
	u8 hw_index;
};

struct sxe2_fwc_rxq_stats_map_get_info_req {
	u8 hw_pool_idx;
};

struct sxe2_fwc_txq_stats_map_info_clear_req {
	u8 hw_index;
};

struct sxe2_fwc_rxq_stats_map_info_clear_req {
	u8 hw_pool_idx;
};

struct sxe2_fwc_txq_stats_map_get_info_resp {
	u32 txq_lan_pkt_cnt;
	u32 txq_lan_byte_cnt;
};

struct sxe2_fwc_rxq_stats_map_get_info_resp {
	u64 rxq_lan_in_pkt_cnt;
	u64 rxq_lan_in_byte_cnt;

	u64 rxq_fd_in_pkt_cnt;

	u64 rxq_mng_in_pkt_cnt;
	u64 rxq_mng_in_byte_cnt;
	u64 rxq_mng_out_pkt_cnt;
};

struct sxe2_fwc_rxlan_rxq_stats_map_get_info_resp {
	u64 rxq_lan_out_pkt_cnt;
	u64 rxq_lan_out_byte_cnt;
};

struct sxe2_txq_ctxt {
	__le16 q_idx_in_nic;
	u8  rsv[2];

	__le64 base_addr;

	__le16 cgd_idx;
	__le16 vmvf_idx;
	u8 port_idx;
	u8 pf_idx;
	u8 vmvf_type;
	u8 tsyn_enable;
	u8 alt_vlan;
	u8 wb_mode;
	u8 itr_notify_mode;
	u8 legacy_enable;
	u8 adv_sso;
	u8 rsv1[3];

	__le16 src_vsi;
	__le16 cpuid;
	u8 tphrd_desc;
	u8 tphrd;
	u8 tphwr_desc;
	u8 rsv2;

	__le16 q_idx_in_func;
	u8  rd_desc_ro;
	u8  wb_desc_ro;
	__le32 qlen;
	u8  ptp_en;
	u8  rsv3[3];

	u8 quanta_prof_idx;

	u8 is_tm;
	u8  rsv4[2];
};

struct sxe2_txsched_add_leaf_req {
	u8 port;
	u8 tc;
	__le16 txq_idx_in_dev;
	struct sxe2_txsched_node_info node;
};

struct sxe2_fwc_cfg_txq_req {
	struct sxe2_txq_ctxt ctxt;
	struct sxe2_txsched_add_leaf_req leaf;
};

struct sxe2_fwc_st_txq_req {
	__le16 txq_idx_in_func;
	__le16 txq_idx_in_nic;
};

struct sxe2_fwc_st_txq_resp {
	u8 state;
};

struct sxe2_fwc_add_qset_req {
	struct sxe2_txsched_add_leaf_req leaf;
};

struct sxe2_fwc_add_qset_resp {
	__le16 node_teid;
	u8 sibling_idx;
};

struct sxe2_fwc_cfg_txq_resp {
	__le16 node_teid;
	u8 sibling_idx;
};

struct sxe2_txsched_del_leaf_req {
	u8 port;
	u8 tc;
	__le16 txq_idx_in_dev;
	__le16 parent_teid;
	__le16 sibling_idx;
	__le16 node_teid;
	__le16 rsv;
};

struct sxe2_txsched_rl_profile_pre_query_req {
	u8 hw_layer;
	u8 prof_type;
	__le16 rsv;
	u32 bw;
};

struct sxe2_txsched_rl_profile_pre_query_resp {
	__le16 prof_id;
	__le16 rsv;
};

struct sxe2_txsched_cfg_node_rl_req {
	u8 hw_layer;
	u8 prof_type;
	__le16 orig_prof_id;

	u32 bw;
	__le16 teid;
	__le16 rsv;
};

struct sxe2_txsched_cfg_node_rl_resp {
	u8 hw_layer;
	u8 prof_type;
	__le16 prof_id;
	u32 bw;
};

struct sxe2_txsched_cfg_profile_srl_req {
	u8 hw_layer;
	u8 rsv;
	__le16 prof_id;
	u32 bw;
};

struct sxe2_txsched_cfg_profile_srl_resp {
	__le16 prof_id;
	__le16 rsv;
};

struct sxe2_txsched_cfg_node_srl_req {
	u8 hw_layer;
	u8 attach;
	__le16 prof_id;
	__le16 teid;
	__le16 rsv;
};

struct sxe2_txsched_tc_node {
	__le16 teid;
	__le16 parent_teid;
	__le16 silbing_idx;
	__le16 rsv;
};

struct sxe2_txsched_ets_query_rep {
	u8 tc_cnt;
	u8 rsv[3];
};

struct sxe2_txsched_ets_query_resp {
	u8 tc_cnt;
	struct sxe2_txsched_tc_node tc_node[SXE2_TC_MAX_CNT];
};

struct sxe2_fwc_del_qset_req {
	struct sxe2_txsched_del_leaf_req leaf;
};

struct sxe2_fwc_disable_txq_req {
	__le16 txq_idx_in_func;
	__le16 txq_idx_in_nic;
	struct sxe2_txsched_del_leaf_req leaf;
};

struct sxe2_fwc_txsched_suspend_node_req {
	u8 port;
	u8 tc;
	__le16 node_teid;
	__le16 parent_teid;
	u8 child_idx;
};

struct sxe2_fwc_txsched_resume_node_req {
	u8 port;
	u8 tc;
	struct sxe2_txsched_node_info node;
};

enum sxe2QosMode {
	SXE2_QOS_MODE_VLAN = 0,
	SXE2_QOS_MODE_DSCP,
};

enum sxe2_block_id {
	SXE2_HW_BLOCK_ID_SWITCH = 0x1,
	SXE2_HW_BLOCK_ID_ACL,
	SXE2_HW_BLOCK_ID_RSS,
	SXE2_HW_BLOCK_ID_FNAV,
	SXE2_HW_BLOCK_ID_BFD = SXE2_HW_BLOCK_ID_FNAV,
	SXE2_HW_BLOCK_ID_PE,
	SXE2_HW_BLOCK_ID_MAX
};

enum sxe2_class_id {
	SXE2_XLT0_CLASS_ID = 0x1,
	SXE2_XLT2_CLASS_ID,
	SXE2_EXTRACTOR_CLASS_ID,
	SXE2_MAP_CLASS_ID,
	SXE2_TCAM_CLASS_ID,
	SXE2_RECIPE_CLASS_ID,
};

#define SXE2_CFG_ID(block_id, class_id)   ((block_id) << 16 | (class_id))
#define SXE2_CFG_CLASS_ID_MASK            (0xFFFF)

#define SXE2_CFG_GROUP_SIZE             SXE2_DRV_CMD_MAX_MSG_SIZE

enum {
	SXE2_SWITCH_XLT0_CLASS_ID = SXE2_CFG_ID(SXE2_HW_BLOCK_ID_SWITCH, SXE2_XLT0_CLASS_ID),
	SXE2_SWITCH_XLT2_CLASS_ID,
	SXE2_SWITCH_EXTRACTOR_CLASS_ID,
	SXE2_SWITCH_MAP_CLASS_ID,
	SXE2_SWITCH_TCAM_CLASS_ID,

	SXE2_ACL_XLT0_CLASS_ID = SXE2_CFG_ID(SXE2_HW_BLOCK_ID_ACL, SXE2_XLT0_CLASS_ID),
};

enum sxe2_udp_tunnel_protocol {
	SXE2_UDP_TUNNEL_PROTOCOL_VXLAN = 0,
	SXE2_UDP_TUNNEL_PROTOCOL_VXLAN_GPE,
	SXE2_UDP_TUNNEL_PROTOCOL_GENEVE,
	SXE2_UDP_TUNNEL_PROTOCOL_GTP_C = 4,
	SXE2_UDP_TUNNEL_PROTOCOL_GTP_U,
	SXE2_UDP_TUNNEL_PROTOCOL_PFCP,
	SXE2_UDP_TUNNEL_PROTOCOL_ECPRI,
	SXE2_UDP_TUNNEL_PROTOCOL_MPLS,
	SXE2_UDP_TUNNEL_PROTOCOL_NVGRE = 10,
	SXE2_UDP_TUNNEL_PROTOCOL_L2TP,
	SXE2_UDP_TUNNEL_PROTOCOL_TEREDO,
	SXE2_UDP_TUNNEL_MAX,
};

struct sxe2_cfg_group_hdr {
	__le16 class_cnt;
	__le16 size;
};

struct sxe2_cfg_class {
	__le32 class_id;
	__le16 offset;
	__le16 size;
};

struct sxe2_pipeline_group {
	struct sxe2_cfg_group_hdr hdr;
	struct sxe2_cfg_class class[];
};

struct sxe2_es_fv {
	u8 prot_id;
	u8 rsv;
	__le16 off;
};

struct sxe2_vsi_hw_stats {
	__le64 rx_vsi_unicast_packets;
	__le64 rx_vsi_bytes;
	__le64 tx_vsi_unicast_packets;
	__le64 tx_vsi_bytes;
	__le64 rx_vsi_multicast_packets;
	__le64 tx_vsi_multicast_packets;
	__le64 rx_vsi_broadcast_packets;
	__le64 tx_vsi_broadcast_packets;
	__le64 rx_lan_engine_packets;
};

struct sxe2_pf_hw_stats {
	__le64 tx_frame_good;
	__le64 rx_frame_good;
	__le64 rx_crc_errors;
	__le64 tx_bytes_good;
	__le64 rx_bytes_good;
	__le64 tx_multicast_good;
	__le64 tx_broadcast_good;
	__le64 rx_multicast_good;
	__le64 rx_broadcast_good;
	__le64 rx_len_errors;
	__le64 rx_out_of_range_errors;
	__le64 rx_symbol_err;
	__le64 rx_pause_frame;
	__le64 tx_pause_frame;

	__le64 rx_discards_phy;
	__le64 tx_dropped_link_down;
	__le64 tx_bytes_good_bad;
	__le64 tx_frame_good_bad;
	__le64 rx_size_64;
	__le64 rx_size_65_127;
	__le64 rx_size_128_255;
	__le64 rx_size_256_511;
	__le64 rx_size_512_1023;
	__le64 rx_size_1024_1522;
	__le64 rx_size_1523_max;
	__le64 rx_illegal_bytes;
	__le64 tx_unicast;
	__le64 tx_broadcast;
	__le64 tx_multicast;
	__le64 tx_vlan_packet_good;
	__le64 tx_size_64;
	__le64 tx_size_65_127;
	__le64 tx_size_128_255;
	__le64 tx_size_256_511;
	__le64 tx_size_512_1023;
	__le64 tx_size_1024_1522;
	__le64 tx_size_1523_max;
	__le64 tx_underflow_error;
	__le64 rx_byte_good_bad;
	__le64 rx_frame_good_bad;
	__le64 rx_unicast_good;
	__le64 rx_vlan_packets;
	__le64 prio_xoff_rx[SXE2_MAX_USER_PRIORITY];
	__le64 prio_xon_rx[SXE2_MAX_USER_PRIORITY];
	__le64 prio_xon_tx[SXE2_MAX_USER_PRIORITY];
	__le64 prio_xoff_tx[SXE2_MAX_USER_PRIORITY];
	__le64 prio_xon_2_xoff[SXE2_MAX_USER_PRIORITY];
	__le64 rx_pause;
	__le64 tx_pause;
	__le64 rx_undersize_good;
	__le64 rx_runt_error;
	__le64 rx_oversize_good;
	__le64 rx_jabbers;
	__le64 rx_oversize_pkts_phy;

	__le64 rx_out_of_buffer;
	__le64 rx_qblock_drop;
	__le64 rx_discards_ips_phy;

	__le64 rx_pcs_symbol_err_phy;
	__le64 rx_corrected_bits_phy;

	__le64 rx_err_lane_0_phy;
	__le64 rx_err_lane_1_phy;
	__le64 rx_err_lane_2_phy;
	__le64 rx_err_lane_3_phy;
	__le64 rx_prio_buf_discard[8];
	__le64 fnav_match;
	__le64 spoof_mac_packets;
	__le64 spoof_vlan_packets;
};

#define SXE2_FNAV_INVALID_STATS_IDX   (0xFFFF)

struct sxe2_fwc_pf_stats_req {
	__le16 fnav_stats_idx;
};

struct sxe2_fwc_pf_stats_resp {
	struct sxe2_pf_hw_stats stats;
};

struct sxe2_fwc_vsi_stats {
	struct sxe2_vsi_hw_stats stats;
	__le16 vsi_id;
};

struct sxe2_fwc_vsi_stats_req {
	__le16 vsi_cnt;
	__le16 vsi_ids[SXE2_CMD_VSI_STATS_MAX_CNT];
};

struct sxe2_fwc_vsi_stats_resp {
	__le16 vsi_cnt;
	struct sxe2_fwc_vsi_stats vsi_stats[SXE2_CMD_VSI_STATS_MAX_CNT];
};

struct sxe2_fwc_pxe_req {
	u8 ena;
};

#define SXE2_EVENT_SUBSCRIBE_MAX_COUNT 32

struct sxe2_fwc_event {
	u8     count;
	u8     rsv[3];
	__le16 code[SXE2_EVENT_SUBSCRIBE_MAX_COUNT];
};

struct sxe2_fwc_fw_log_ack {
	__le32     result;
};

enum sxe2_default_recipe_id {
	SXE2_DEFAULT_RECIPE_MAC = 0,
	SXE2_DEFAULT_RECIPE_VLAN,
	SXE2_DEFAULT_RECIPE_TX_ETYPE,
	SXE2_DEFAULT_RECIPE_RX_ETYPE,
	SXE2_DEFAULT_RECIPE_ALLMULTI,
	SXE2_DEFAULT_RECIPE_PROMISC,
	SXE2_DEFAULT_RECIPE_SRCVSI,
	SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK,
	SXE2_DEFAULT_RECIPE_MAC_SPOOFCHK_EXT,
	SXE2_DEFAULT_RECIPE_SRCVSI_EXT,
	SXE2_DEFAULT_RECIPE_MAX
};

union sxe2_switch_full_key_dw0 {
	u32 val;
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		u32 fv0		: 16;
		u32 rid		: 6;
		u32 rsvd0	: 9;
		u32 is_root	: 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
		u32 is_root	: 1;
		u32 rsvd0	: 9;
		u32 rid		: 6;
		u32 fv0		: 16;
#endif
	} field;
};

union sxe2_switch_full_key_dw1 {
	u32 val;
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		u32 fv2		: 16;
		u32 fv1		: 16;
#elif defined(__BIG_ENDIAN_BITFIELD)
		u32 fv1		: 16;
		u32 fv2		: 16;
#endif
	} field;
};

union sxe2_switch_full_key_dw2 {
	u32 val;
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		u32 fv4		: 16;
		u32 fv3		: 16;
#elif defined(__BIG_ENDIAN_BITFIELD)
		u32 fv3: 16;
		u32 fv4: 16;
#endif
	} field;
};

struct sxe2_fwc_switch_rule {
	__le16 flag;
	__le16 recipe_id;
	__le32 act;
	__le16 rule_id;
	u8 recv[2];
	__le32 full_key[SXE2_FULLKEY_DWORD_CNT];
	u8 add_fkot;
	u8 resv2[3];
};

struct sxe2_fwc_switch_vsi_list {
	__le16 flag;
	__le16 vsi_list_id;
	__le16 vsi_cnt;
	__le16 vsi[];
};

union sxe2_switch_large_action {
	u32 val;
	struct {
		u32 rsv0          : 8;
		u32 valid         : 1;
		u32 rsv1          : 2;
		u32 list          : 1;
		u32 vsi_list      : 10;
		u32 fwd_vsi000    : 3;
		u32 rsv2          : 8;
	} reg;
};

struct sxe2_fwc_switch_large_action {
	union sxe2_switch_large_action action[SXE2_LARGE_ACTION_COUNT_IN_GROUP];
	__le32 idx;
};

struct sxe2_fwc_switch_recipe {
	u8        rid                 :6;
	u8        rcp_rsv0            :1;
	u8        is_root             :1;
	u8        lookup_index0       :7;
	u8        lookup_index0_valid :1;
	u8        lookup_index1       :7;
	u8        lookup_index1_valid :1;
	u8        lookup_index2       :7;
	u8        lookup_index2_valid :1;
	u8        lookup_index3       :7;
	u8        lookup_index3_valid :1;
	u8        lookup_index4       :7;
	u8        lookup_index4_valid :1;
	u8        join_priority;
	u8        priority            :3;
	u8        need_pass_l2        :1;
	u8        allow_pass_l2       :1;
	u8        inverse_action      :1;
	u8        prune_idx           :2;
	__le32    default_action      :19;
	__le32    rcp_rsv1            :4;
	__le32    default_action_valid:1;
	__le32    rcp_rsv2            :8;
	__le32    fv4_bitmask         :16;
	__le32    fv3_bitmask         :16;
	__le32    fv2_bitmask         :16;
	__le32    fv1_bitmask         :16;
	__le32    fv0_bitmask         :16;
	__le32    rcp_rsv3            :16;
	__le16    ref_cnt;
};

struct sxe2_fwc_switch_profile_recipe_map {
	__le16 profile_id;
	__le32  map[2];
};

struct sxe2_fwc_switch_share_id {
	__le32 usage;
	__le32 share_id[SXE2_MAX_NUM_RECIPES];
	__le32 bitmap[SXE2_MAX_NUM_RECIPES];
};

struct sxe2_fwc_switch_rule_resp {
	__le16 index;
	u8 resv1[2];
	__le32 act;
	__le32 full_key[SXE2_FULLKEY_DWORD_CNT];
	__le16 ref_cnt;
	u8 resv2[2];
};

struct sxe2_fwc_switch_vsi_list_resp {
	__le16 index;
	u8 resv1[2];
	__le32 vsi[SXE2_VSI_LIST_DAT_LEN];
	u8 resv2[4];
};

struct sxe2_fwc_switch_mac_info {
	u8 mac_addr[ETH_ALEN];
};

struct sxe2_fwc_switch_mac_info_resp {
	u8 mac_addr[ETH_ALEN];
};

struct sxe2_fw_mtu_info {
	__le32 mtu;
	u8 is_set_hw;
	u8 resv0;
	__le16 resv1;
};

struct sxe2_fwc_switch_complex_rule {
	__le16 flag;
	__le32 act;
	u8 priority;
	u8 resv;
	u8 add_fkot;

	__le16 word_cnt;
	__le16 lkup_index[SXE2_MAX_CHAIN_WORDS];
	__le16 lkup_mask[SXE2_MAX_CHAIN_WORDS];
	__le16 lkup_value[SXE2_MAX_CHAIN_WORDS];

	__le16 recipe_root;
	__le16 recipe_cnt;
	__le16 recipe_id[SXE2_MAX_CHAIN_RECIPE];

	__le16 profile_cnt;
	__le16 profile_id[SXE2_MAX_NUM_PROFILES];

	__le16 rule_root;
	__le16 rule_id[SXE2_MAX_CHAIN_RECIPE];
};

struct sxe2_fwc_switch_complex_rule_resp {
	__le32 act;

	__le16 lkup_index[SXE2_MAX_CHAIN_WORDS];
	__le16 lkup_mask[SXE2_MAX_CHAIN_WORDS];
	__le16 lkup_value[SXE2_MAX_CHAIN_WORDS];

	__le16 recipe_root;
	__le16 recipe_cnt;
	__le16 recipe_id[SXE2_MAX_CHAIN_RECIPE];

	__le16 rule_root;
	__le16 rule_id[SXE2_MAX_CHAIN_RECIPE];
};

struct sxe2_og_trace_rcd {
	u8 done;
	u8 status;
	u8 profile_id;
	u8 resv;
	__le16 fv[SXE2_SWITCH_FV_CNT];
};

struct sxe2_recp_trace_rcd {
	__le16 recipe_id;
	u8 ht1_hit;
	u8 ht2_hit;
	u8 fkot_hit;
	u8 kt_hit;
	__le16 index;
};

struct sxe2_swe_trace_rcd {
	u8 done;
	u8 status;
	u8 resv[2];
	struct sxe2_recp_trace_rcd recp[SXE2_PACKET_MAX_RECIPES];
};

struct sxe2_rg_trace_rcd {
	u8 done;
	u8 status;
	u8 resv[2];
	__le32 ppe_info[SXE2_PACKET_INFO_DWORD_CNT];
};

struct sxe2_fwc_switch_trace_req {
	u8 is_rx;
	u8 resv[3];
};

struct sxe2_fwc_switch_trace_resp {
	struct sxe2_og_trace_rcd og;
	struct sxe2_swe_trace_rcd swe;
	struct sxe2_rg_trace_rcd rg;
};

struct sxe2_fwc_recipe_get_req {
	__le16 recipe_id;
	u8 resv[2];
};

struct sxe2_fwc_recipe_get_resp {
	u8 is_root;
	u8 priority;
	u8 is_inverse;
	u8 resv;
	__le16 recipe_cnt;
	__le16 profile_cnt;
	__le16 recipe_id[SXE2_MAX_CHAIN_RECIPE];
	__le16 lkup_index[SXE2_MAX_CHAIN_WORDS];
	__le16 lkup_mask[SXE2_MAX_CHAIN_WORDS];
	__le16 profile_id[SXE2_MAX_NUM_PROFILES];
};

struct sxe2_fwc_recipe_add_req {
	u8 is_root;
	u8 priority;
	__le16 profile_cnt;
	__le16 recipe_cnt;
	__le16 lkup_index[SXE2_MAX_CHAIN_WORDS];
	__le16 lkup_mask[SXE2_MAX_CHAIN_WORDS];
	__le16 profile_id[SXE2_MAX_NUM_PROFILES];
};

struct sxe2_fwc_recipe_add_resp {
	__le16 recipe_cnt;
	__le16 recipe_root;
	__le16 recipe_id[SXE2_MAX_CHAIN_RECIPE];
};

struct sxe2_fwc_recipe_del_req {
	__le16 recipe_cnt;
	__le16 profile_cnt;
	__le16 recipe_id[SXE2_MAX_CHAIN_RECIPE];
	__le16 profile_id[SXE2_MAX_NUM_PROFILES];
};

enum sxe2_switch_dfx_stats_index {
	SXE2_SW_DFX_PROFILE_ID_BYPASS = 0,
	SXE2_SW_DFX_PROFILE_TCAM_HIT,
	SXE2_SW_DFX_PROFILE_TCAM_MISS,
	SXE2_SW_DFX_RX_FB_INPUT,
	SXE2_SW_DFX_TX_PA_INPUT,
	SXE2_SW_DFX_OG_PROCESS_RX,
	SXE2_SW_DFX_OG_PROCESS_TX,
	SXE2_SW_DFX_OUTPUT_TO_SWE,
	SXE2_SW_DFX_OUTPUT_TO_RG,
	SXE2_SW_DFX_MEMORY_HT1_IN,
	SXE2_SW_DFX_MEMORY_HT1_OUT,
	SXE2_SW_DFX_MEMORY_HT2_IN,
	SXE2_SW_DFX_MEMORY_HT2_OUT,
	SXE2_SW_DFX_MEMORY_KT_IN,
	SXE2_SW_DFX_MEMORY_KT_OUT,
	SXE2_SW_DFX_SWE_OG_IN,
	SXE2_SW_DFX_SWE_TX_IN,
	SXE2_SW_DFX_SWE_RX_IN,
	SXE2_SW_DFX_SWE_OUTPUT_ACTION,
	SXE2_SW_DFX_PIPE_HASH_MISS,
	SXE2_SW_DFX_PIPE_HASH_HIT,
	SXE2_SW_DFX_PIPE_KT_HIT,
	SXE2_SW_DFX_PIPE_HI1_HIT,
	SXE2_SW_DFX_PIPE_HI2_HIT,
	SXE2_SW_DFX_PIPE_FKOT_HIT,
	SXE2_SW_DFX_PIPE_HW_SEARCH_ERR,

	SXE2_SW_DFX_MAX,
};

struct sxe2_fwc_switch_dfx_stats {
	__le32 stats[SXE2_SW_DFX_MAX];
};

enum sxe2_ipsec_stats_index {
	SXE2_IPSEC_STATS_TX_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_TX_SOP_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_TX_LEN_ERR_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_TX_PKTID_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_TX_OVER_2K_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_TX_DIS_DROP_PKT_CNT_MAC0,

	SXE2_IPSEC_STATS_RX_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_RX_NOT_SEC_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_RX_TCAM_NOT_MATCH_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_RX_LEN_ERR_PKT_CNT_MAC0,
	SXE2_IPSEC_STATS_RX_OVER_2K_PKTS_CNT_MAC0,
	SXE2_IPSEC_STATS_RX_ICV_OK_PKTS_CNT_MAC0,
	SXE2_IPSEC_STATS_RX_ICV_FAIL_PKTS_CNT_MAC0,
	SXE2_IPSEC_STATS_RX_NO_BUFFER_DROP_PKTS_CNT_MAC0,
	SXE2_IPSEC_STATS_RX_PKTID_DROP_PKTS_CNT_MAC0,

	SXE2_IPSEC_STATS_TX_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_TX_SOP_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_TX_LEN_ERR_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_TX_PKTID_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_TX_OVER_2K_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_TX_DIS_DROP_PKT_CNT_MAC1,

	SXE2_IPSEC_STATS_RX_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_RX_NOT_SEC_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_RX_TCAM_NOT_MATCH_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_RX_LEN_ERR_PKT_CNT_MAC1,
	SXE2_IPSEC_STATS_RX_OVER_2K_PKTS_CNT_MAC1,
	SXE2_IPSEC_STATS_RX_ICV_OK_PKTS_CNT_MAC1,
	SXE2_IPSEC_STATS_RX_ICV_FAIL_PKTS_CNT_MAC1,
	SXE2_IPSEC_STATS_RX_NO_BUFFER_DROP_PKTS_CNT_MAC1,
	SXE2_IPSEC_STATS_RX_PKTID_DROP_PKTS_CNT_MAC1,

	SXE2_IPSEC_STATS_TX_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_TX_SOP_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_TX_LEN_ERR_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_TX_PKTID_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_TX_OVER_2K_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_TX_DIS_DROP_PKT_CNT_MAC2,

	SXE2_IPSEC_STATS_RX_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_RX_NOT_SEC_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_RX_TCAM_NOT_MATCH_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_RX_LEN_ERR_PKT_CNT_MAC2,
	SXE2_IPSEC_STATS_RX_OVER_2K_PKTS_CNT_MAC2,
	SXE2_IPSEC_STATS_RX_ICV_OK_PKTS_CNT_MAC2,
	SXE2_IPSEC_STATS_RX_ICV_FAIL_PKTS_CNT_MAC2,
	SXE2_IPSEC_STATS_RX_NO_BUFFER_DROP_PKTS_CNT_MAC2,
	SXE2_IPSEC_STATS_RX_PKTID_DROP_PKTS_CNT_MAC2,

	SXE2_IPSEC_STATS_TX_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_TX_SOP_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_TX_LEN_ERR_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_TX_PKTID_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_TX_OVER_2K_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_TX_DIS_DROP_PKT_CNT_MAC3,

	SXE2_IPSEC_STATS_RX_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_RX_NOT_SEC_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_RX_TCAM_NOT_MATCH_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_RX_LEN_ERR_PKT_CNT_MAC3,
	SXE2_IPSEC_STATS_RX_OVER_2K_PKTS_CNT_MAC3,
	SXE2_IPSEC_STATS_RX_ICV_OK_PKTS_CNT_MAC3,
	SXE2_IPSEC_STATS_RX_ICV_FAIL_PKTS_CNT_MAC3,
	SXE2_IPSEC_STATS_RX_NO_BUFFER_DROP_PKTS_CNT_MAC3,
	SXE2_IPSEC_STATS_RX_PKTID_DROP_PKTS_CNT_MAC3,

	SXE2_IPSEC_STATS_MAX,
};

struct sxe2_ipsec_stats {
	__le64 stats[SXE2_IPSEC_STATS_MAX];
};

struct sxe2_fwc_vsi_vlan_filter {
	__le16 vsi_hw_id;
	u8 enable;
	u8 resv;
};

struct sxe2_fwc_vsi_src_prune {
	__le16 vsi_hw_id;
	u8 enable;
	u8 resv;
};

struct sxe2_fwc_vsi_loopback {
	__le16 vsi_hw_id;
	u8 enable;
	u8 resv;
};

struct sxe2_fwc_vsi_spoofchk {
	__le16 vsi_hw_id;
	u8 mac_enable;
	u8 vlan_enable;
};

struct sxe2_fwc_switch_dfx_irq {
	u8 enable;
	u8 resv[3];
};

struct sxe2_rss_vsi_hctrl {
	__le16 vsi_hw_id;
	u8 hash_type;
	u8 resv;
};

struct sxe2_rss_lut_cfg {
	__le16 vsi_hw_id;
	u8 lut_type;
	u8 global_lut_id;
	__le16 lut_size;
	u8 resv[2];
	u8 lut[];
};

struct sxe2_rss_core_lut_info {
	u8 lut[SXE2_RSS_CORE_LUT_SIZE];
};

struct sxe2_rss_hkey_cfg {
	__le16 vsi_hw_id;
	u8 resv[2];
	u8 key[];
};

struct sxe2_rss_symm_fv {
	u8 fv_idx : 5;
	u8 rsv    : 2;
	u8 valid  : 1;
};

struct sxe2_rss_symm_fv_cfg {
	__le16 prof_id;
	u8 rsv[2];
	struct sxe2_rss_symm_fv fv[SXE2_RSS_FV_CNT];
};

struct sxe2_rss_trace_recorder {
	u8 trace_status0;
	u8 rsv0[3];
	__le32 profile_id0;
	__le32 fv[SXE2_RSS_FV_TRACE_CNT];
	u8 trace_status1;
	u8 rsv1[3];
	__le32 hash1;
	u8 trace_status2;
	u8 rsv2[3];
	__le32 hash2;
	u8 profile_id2;
	u8 bad_profile;
	__le16 q_index;
	u8 thread_id;
	u8 rsv3[1];
	__le16 vsi;
};

struct sxe2_fwc_xlt2_entry {
	__le16 vsi_hw_idx;
	__le16 vsig;
};

struct sxe2_fwc_tcam_entry {
	__le16 addr;
	u8 key[SXE2_TCAM_KEY_LEN];
	u8 prof_id;
	u8 rsv;
};

struct sxe2_fwc_es_entry {
	u8 prof_id;
	u8 cnt;
	struct sxe2_es_fv fv[SXE2_FV_CNT_MAX];
};

struct sxe2_fwc_prof_section {
	u8 type;
	u8 rsv[1];
	__le16 offset;
	__le16 size;
};

struct sxe2_fwc_prof_buf {
	__le16 entry_cnt;
	__le16 data_end;
	struct sxe2_fwc_prof_section sect[];
};

struct sxe2_fwc_prof_pkg {
	u8 blk;
	u8 buf[];
};

struct sxe2_fwc_tcam_idx {
	u8 blk;
	u8 rsv;
	__le16 tcam_idx;
};

enum sxe2_fwc_tcam_action {
	SXE2_FWC_TCAM_ACTION_ADD,
	SXE2_FWC_TCAM_ACTION_DEL,
};

struct sxe2_fwc_tcam_info {
	u8 action;
	__le16 tcam_idx;
};

struct sxe2_fwc_tcam_idx_batch {
	u8 blk;
	u16 tcam_cnt;
	struct sxe2_fwc_tcam_info tcam_info[];
};

struct sxe2_fwc_prof_id {
	u8 blk;
	u8 rsv;
	__le16 prof_id;
};

struct sxe2_fwc_mask_idx {
	u8 blk;
	u8 rsv;
	__le16 mask_idx;
};

struct sxe2_fwc_mask_val {
	u8 blk;
	u8 rsv;
	__le16 mask_idx;
	__le16 fv_idx;
	__le16 mask;
};

struct sxe2_fwc_mask_sel {
	u8 blk;
	u8 rsv;
	__le16 prof_id;
	__le32 mask_sel;
};

struct sxe2_fwc_fnav_kt_entry {
	u8 is_add;
	u8 prof_id;
	u8 fdid_prio;
	u8 toq_prio;
	u8 drop;
	u8 stat_ena;
	u8 to_queue;
	u8 inputset[SXE2_FNAV_INPUT_CNT * 2];
	u8 fd_space;
	__le16 ori_vsi;
	__le16 vsi;
	__le16 flow_id;
	__le16 qindex;
	__le16 stat_cnt;
	u8 rsv1[2];
	__le32 fdid;
};

struct sxe2_fwc_fnav_kt_resp {
	__le32 gcnt_pf;
	__le32 bcnt_global;
};

struct sxe2_fnav_hit_info {
	__le32 hit_flg      : 4;
	__le32 ck1          : 13;
	__le32 ht_index1    : 11;
	__le32 ck2_3_0      : 4;

	__le32 ck2_12_4     : 9;
	__le32 ht_index2    : 11;
	__le32 ht1_avl      : 8;
	__le32 ht2_avl_3_0  : 4;

	__le32 ht2_avl_7_4  : 4;
	__le32 kt_index     : 15;
	__le32 entry_vld    : 1;
	__le32 qindex       : 11;
	__le32 stat_0       : 1;

	__le32 stat_13_1    : 13;
	__le32 stat_ena     : 2;
	__le32 evict_ena    : 1;
	__le32 toqueue      : 3;
	__le32 toqueue_prio : 3;
	__le32 ad_drop      : 1;
	__le32 fdid_8_0     : 9;

	__le32 fdid_31_9    : 23;
	__le32 fdid_prio    : 3;
	__le32 flow_id_5_0  : 6;

	__le32 flow_id_15_6 : 10;
	__le32 ad_fd_vsi    : 10;
	__le32 gl_space     : 1;
	__le32 pf_space     : 1;
	__le32 vsi_space    : 1;
	__le32 ad2          : 4;
	__le32 inset_511_507 : 5;

	__le32 inset_506_475;

	__le32 inset_474_443;

	__le32 inset_442_411;

	__le32 inset_410_379;

	__le32 inset_378_347;

	__le32 inset_346_315;

	__le32 inset_314_283;

	__le32 inset_282_251;

	__le32 inset_250_219;

	__le32 inset_218_187;

	__le32 inset_186_155;

	__le32 inset_154_123;

	__le32 inset_122_91;

	__le32 inset_90_59;

	__le32 inset_58_27;

	__le32 inset_26_0     : 27;
	__le32 profile_id_4_0 : 5;

	__le32 profile_id_6_5 : 2;
	__le32 rsv0           : 1;
	__le32 vsi            : 10;
	__le32 rsv1           : 6;
	__le32 fail_sts       : 3;
	__le32 cmd            : 4;
	__le32 thread_id_5_0  : 6;

	__le32 thread_id_6    : 1;
	__le32 pf             : 3;
	__le32 vf_vm          : 10;
	__le32 function_type  : 2;
	__le32 bypass_ft      : 1;
	__le32 pcmd           : 2;
	__le32 comp_report    : 2;
	__le32 fd_vsi         : 10;
	__le32 comp_queue     : 1;

	__le32 not_enabled    : 1;
	__le32 bad_profile_id : 1;
	__le32 drop           : 1;
	__le32 round_drop     : 1;
	__le32 round_cnt      : 4;
	__le32 rsv2           : 24;
};

struct sxe2_fnav_addition_info {
	__le32 fd_profile_id   : 7;
	__le32 hit_flg         : 4;
	__le32 rlt_sel         : 2;
	__le32 dst_vsi         : 10;
	__le32 rlt_queue_8_0   : 9;

	__le32 rlt_queue_10_9  : 2;
	__le32 rlt_toqueue     : 3;
	__le32 rlt_toqueue_pri : 3;
	__le32 drop            : 1;
	__le32 cmd             : 4;
	__le32 bypass_absq     : 1;
	__le32 fd_search_ena   : 1;
	__le32 pkt_id          : 7;
	__le32 deflt_qindx_pri : 3;
	__le32 sa_toqueue_pri  : 3;
	__le32 rsv               : 3;
	__le32 search_rss_fs_hit : 1;

	__le32 bypass_rss        : 1;
	__le32 rsv1              : 31;
};

struct sxe2_fnav_trace_recorder {
	u8 trace_status0;
	u8 trace_status1;
	struct sxe2_fnav_hit_info hit_info;
	struct sxe2_fnav_addition_info addition_info;
	u8 trace_status2;
};

struct sxe2_fnav_glspace_cnt {
	__le32 bcnt;
	__le32 gcnt;
};

#define SXE2_FNAV_MAX_COUNTER_BANK_NUM (2)

enum sxe2_fnav_counter_bank_type {
	SXE2_FNAV_COUNTER_BANK_0,
	SXE2_FNAV_COUNTER_BANK_1,
	SXE2_FNAV_COUNTER_BANK_ALL,
	SXE2_FNAV_COUNTER_BANK_MAX,
};

struct sxe2_fwc_fnav_stats_req {
	u8 is_clear;
	u8 bank_type;
	__le16 counter_idx;
};

struct sxe2_fwc_fnav_stats_resp {
	__le64 stats[SXE2_FNAV_MAX_COUNTER_BANK_NUM];
};

struct sxe2_fwc_fnav_match_req {
	__le16 vsi_id;
	__le16 stat_idx;
};

struct sxe2_fwc_fnav_match_req_batch {
	u8 is_clear;
	u8 bank_type;
	__le16 stat_cnt;
	struct sxe2_fwc_fnav_match_req match_req[];
};

struct sxe2_fwc_fnav_match_rsp_batch {
	__le16 stat_cnt;
	__le64 fnav_match[];
};

struct sxe2_fwc_fnav_dlft_compq_req {
	__le16 vsi_idx_in_dev;
	__le16 rxq_idx_in_func;
};

struct sxe2_fnav_vsispace_cnt {
	__le32 bcnt;
	__le32 gcnt;
	__le16 vsi_id;
};

struct sxe2_fnav_space_cnt {
	__le32 bcnt_global;
	__le32 gcnt_global;
	__le32 bcnt_pf;
	__le32 gcnt_pf;
	__le32 bcnt_vsi;
	__le32 gcnt_vsi;
	__le16 vsi_id;
};

struct sxe2_vf_fnav_clear_ctxt {
	__le16 vf_indev;
	u8 io_close;
};

enum sxe2_rxft_dbg_ppe_info_type {
	SXE2_RXFT_PPE_INFO_TX_IN,
	SXE2_RXFT_PPE_INFO_TX_EX,
	SXE2_RXFT_PPE_INFO_RX_IN,
	SXE2_RXFT_PPE_INFO_RX_EX,
	SXE2_RXFT_PPE_INFO_LP_IN,
	SXE2_RXFT_PPE_INFO_LP_EX,
	SXE2_RXFT_PPE_INFO_TYPE_MAX,
};

struct sxe2_rxft_ppe_info {
	struct {
		__le32 data[SXE2_RXFT_PPE_INFO_REG_CNT];
	} info[SXE2_RXFT_PPE_INFO_TYPE_MAX];
};

struct sxe2_rxq_ctxt {
	__le64 base_addr;
	__le16 depth;

	__le16 dbuff_len;
	__le16 hbuff_len;
	u8 hsplit_type;
	u8 desc_type;
	u8 crc_strip;
	u8 l2tag1_show;
	u8 hsplit_0;
	u8 hsplit_1;
	u8 inner_vlan_strip;

	u8 lro_enable;
	u8 cpuid;
	__le16 max_frame_size;
	__le16 lro_desc_max;
	u8 relax_data;
	u8 relax_wb_desc;
	u8 relax_rd_desc;

	u8 tphrdesc_enable;
	u8 tphwdesc_enable;
	u8 tphdata_enable;
	u8 tphhead_enable;

	u8 low_desc_waterline;
	__le16 vfid;
	u8 pfid;
	u8 vfen;
	__le16 vsi_id;

	u8 pref_enable;
	__le16 head;
};

struct sxe2_fwc_cfg_rxq_req {
	u8 pf_idx;
	__le16 idx_in_dev;
	struct sxe2_rxq_ctxt rxq_ctxt;
};

struct sxe2_fwc_local_mib_set {
	__le16 mib_len;
	u8 mib_buffer[];
};

struct sxe2_fwc_local_mib_get {
	u8 mib_len;
	u8 mib_buffer[];
};

struct sxe2_fwc_fw_agent {
	u8 enable;
	u8 resv[3];
};

#ifndef FW_LLDP_STATE
#define FW_LLDP_STATE
enum sxe2LldpStatus {
	sxe2_lldp_enabled_rx_tx = 0,
	sxe2_lldp_enabled_tx_only,
	sxe2_lldp_enabled_rx_only,
	sxe2_lldp_disabled,
};
#endif

struct sxe2_fwc_lldp_fw_agent {
	u8 status;
	u8 resv[3];
};

struct sxe2_fwc_notify_lldp_fw_agent {
	u8 stats;
	u8 resv[3];
};

struct sxe2_fwc_lldp_stats {
	u8 rx_state;
	u8 tx_state;
	u8 lldp_enable;
	u8 admin_status;
	__le32 tx_failed;
	__le32 tx_frames_out_total;
	__le32 tx_lldpdu_length_errors;
	__le32 rx_ageouts_total;
	__le32 rx_frames_discarded_total;
	__le32 rx_frames_in_errors_total;
	__le32 rx_frames_in_total;
	__le32 rx_tlvs_discarded_total;
	__le32 rx_tlvs_unrecognized_total;
};

struct sxe2_fwc_lldp_mibs_info {
	u8 count;
	u8 resv[3];
};

struct sxe2_fwc_lldp_mibs_dump_req {
	u8 index;
	u8 resv[3];
};

struct sxe2_lldp_mibs_tl {
	__le16 offset;
	__le16 length;
};

struct sxe2_lldp_mibs_ets {
	u8 willing;
	u8 cbs;
	u8 maxtcs;
	u8 prioTable[SXE2_MAX_TRAFFIC_CLASS];
	u8 tcbwtable[SXE2_MAX_TRAFFIC_CLASS];
	u8 tsatable[SXE2_MAX_TRAFFIC_CLASS];
};

struct sxe2_lldp_mibs_pfc {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcena;
};

struct sxe2_lldp_mibs_app {
	__le16 protId;
	u8 priority;
	u8 selector;
};

struct sxe2_fwc_lldp_mibs_dump_resp {
	u8 index;
	u8 resv1[3];
	u8 buffer[SXE2_LLDP_FRAME_MAX_SIZE];
	__le16 size;
	u8 num_apps;
	u8 resv2[3];
	struct sxe2_lldp_mibs_ets ets_cfg;
	struct sxe2_lldp_mibs_ets ets_rec;
	struct sxe2_lldp_mibs_pfc pfc_cfg;
	struct sxe2_lldp_mibs_app app_cfg[SXE2_DCBX_MAX_APPS];
};

enum sxe2FlowCtrlMode {
	SXE2_FC_MODE_DISABLE,
	SXE2_FC_MODE_LFC,
	SXE2_FC_MODE_PFC,
	SXE2_FC_MDDE_COUNT,
};

struct sxe2_fwc_lfc_info {
	u8 rx_en;
	u8 tx_en;
	u8 tc_num;
	u8 fc_mode;
	__le32 port_size;
	__le32 high_water[SXE2_MAX_TRAFFIC_CLASS];
	__le32 low_water[SXE2_MAX_TRAFFIC_CLASS];
	__le16 pause_time[SXE2_MAX_TRAFFIC_CLASS];
	u8 priority;
	u8 resv1;
};

struct sxe2_mdd_vf_req {
	__le16 vf_idx;
	u8 q_mapping_mode;
	u8 reserve;
};

struct sxe2_fwc_mdd_req {
	__le16 vf_cnt;
	u8 mdd_check;
	u8 reserve;
	struct sxe2_mdd_vf_req vfs[];
};

struct sxe2_mdd_vf_resp {
	__le16 vf_idx;
	u8 mdd;
	u8 reserve;
};

struct sxe2_fwc_mdd_resp {
	__le32 vf_mdd_tx_event;
	__le32 pf_mdd_tx_event;

	u8 vf_mdd_rx_event;
	u8 pf_mdd_rx_event;

	__le16 mdd_vf_cnt;
	struct sxe2_mdd_vf_resp mdd_vfs[];
};

struct sxe2_fwc_ptp_filter_addr {
	u8 filter_type;
	__le32 ipv4;
	__le32 ipv6[4];
	__le32 mac[2];
};

struct sxe2_fwc_ptp_correction {
	__le32 ingress_corr_nanosec;
	__le32 ingress_corr_subnanosec;
	__le32 egress_corr_nanosec;
	__le32 egress_corr_subnanosec;
	__le32 ingress_sync_corr;
	__le32 egress_sync_corr;
};

struct sxe2_fwc_ptp_init_req {
	u8 sample_type;
	u8 threshold;
	struct sxe2_fwc_ptp_filter_addr filter_addr;
	struct sxe2_fwc_ptp_correction corr;
};

enum sxe2_rx_timestamp_mode {
	SXE2_RX_TIMESTAMP_MODE_PTP = 0,
	SXE2_RX_TIMESTAMP_MODE_ALL_1024,
	SXE2_RX_TIMESTAMP_MODE_ALL_2048,
	SXE2_RX_TIMESTAMP_MODE_ALL_4096,
	SXE2_RX_TIMESTAMP_MODE_ALL_8192,
	SXE2_RX_TIMESTAMP_MODE_ALL_16384,
	SXE2_RX_TIMESTAMP_MODE_MAX,
};

struct sxe2_fwc_ptp_mode_set_req {
	u8 mode;
};

#define SXE2_IPSEC_KEY_LEN (32)
#define SXE2_IPV6_ADDR_LEN (4)
struct sxe2_fwc_ipsec_txsa_add_req {
	__le32 mode;
	u8 encrypt_keys[SXE2_IPSEC_KEY_LEN];
	u8 auth_keys[SXE2_IPSEC_KEY_LEN];
	u8 func_type;
	u8 func_id;
	u8 drv_id;
};

struct sxe2_fwc_ipsec_txsa_set_req {
	__le32 mode;
	__le32 sa_index;
	u8 encrypt_keys[SXE2_IPSEC_KEY_LEN];
	u8 auth_keys[SXE2_IPSEC_KEY_LEN];
	u8 func_type;
	u8 func_id;
	u8 drv_id;
};

struct sxe2_fwc_ipsec_txsa_add_resp {
	__le16 index;
};

struct sxe2_fwc_ipsec_rxsa_add_req {
	__le32 mode;
	__le32 spi;
	__le32 ipaddr[SXE2_IPV6_ADDR_LEN];
	__le32 udp_port;
	u8 sport_en;
	u8 dport_en;
	u8 is_over_sdn;
	u8 sdn_group_id;
	u8 encrypt_keys[SXE2_IPSEC_KEY_LEN];
	u8 auth_keys[SXE2_IPSEC_KEY_LEN];
	u8 func_type;
	u8 func_id;
	u8 drv_id;
};

struct sxe2_fwc_ipsec_rxsa_set_req {
	__le32 mode;
	__le32 spi;
	__le32 ipaddr[SXE2_IPV6_ADDR_LEN];
	__le32 sa_index;
	__le32 udp_port;
	u8 sport_en;
	u8 dport_en;
	u8 encrypt_keys[SXE2_IPSEC_KEY_LEN];
	u8 auth_keys[SXE2_IPSEC_KEY_LEN];
	u8 func_type;
	u8 func_id;
	u8 drv_id;
};

struct sxe2_fwc_ipsec_rxsa_add_resp {
	u8 ip_id;
	u8 udp_group_id;
	__le16 sa_idx;
};

struct sxe2_fwc_ipsec_txsa_del_req {
	__le16 sa_idx;
	u8 func_type;
	u8 func_id;
	u8 drv_id;
};

struct sxe2_fwc_ipsec_rxsa_del_req {
	u8 ip_id;
	u8 group_id;
	__le16 sa_idx;
	__le32 spi;
	u8 func_type;
	u8 func_id;
	u8 drv_id;
};

struct sxe2_fwc_ipsec_switch_op_req {
	u8 dir;
	u8 op;
	__le16 mac_id;
};

struct sxe2_fwc_ipsec_drv_clr_req {
	u8 func_type;
	u8 func_id;
	u8 drv_id;
	u8 rsv;
};

#define SXE2_IPSEC_WDRR_COUNT (4)
struct sxe2_fwc_ipsec_wdrr_req {
	__le16 tx_wdrr[SXE2_IPSEC_WDRR_COUNT];
	__le16 rx_wdrr_iqm[SXE2_IPSEC_WDRR_COUNT];
	__le16 rx_wdrr_oqm[SXE2_IPSEC_WDRR_COUNT];
};

struct sxe2_fwc_ipsec_capa_resq {
	__le16 tx_sa_cnt;
	__le16 rx_sa_cnt;
	__le16 ip_id_cnt;
	__le16 udp_group_cnt;
};

#define MACSEC_PN_LEN_MAX (2)
#define MACSEC_SALT_COUNT (3)
#define MACSEC_KEY_LEN    (4)

enum sxe2_macsec_validate_mode {
	SXE2_MACSEC_VALIDATE_DISABLED = 0,
	SXE2_MACSEC_VALIDATE_CHECK = 1,
	SXE2_MACSEC_VALIDATE_STRICT = 2,
	SXE2_MACSEC_VALIDATE_END,
};

struct sxe2_fw_macsec_sa {
	u8 active;
	u8 an_value;
	__le32 pn[MACSEC_PN_LEN_MAX];
	__le32 ssci;
	__le32 salt[MACSEC_SALT_COUNT];
	__le32 key[MACSEC_KEY_LEN];
};

struct sxe2_fw_macsec_txsc {
	u8 active;
	u8 xpn;
	u8 aisci;
	u8 es;
	u8 encrypt;
	__le64 sci;
};

struct sxe2_fw_macsec_rxsc {
	u8 active;
	u8 xpn;
	u8 protect;
	u8 validate_mode;
	__le64 sci;
};

struct sxe2_fwc_ddp_state {
	u8      act_pfid;
	u8      pad;
	__le16  ver;
	__le32  state;
};

struct flm_link_cap {
	u32 speed;
	u32 fecMode;

	u8 an;
	u8 lscEn;
};

enum sxe2_fec_mode {
	SXE2_ETHTOOL_FEC_NONE = 0,
	SXE2_ETHTOOL_FEC_OFF  = 1,
	SXE2_ETHTOOL_FEC_BASER = 2,
	SXE2_ETHTOOL_FEC_RS = 3,
	SXE2_ETHTOOL_FEC_AUTO = 15,
	SXE2_ETHTOOL_FEC_MAX,
};

enum flm_link_speed_fec {
	FEC_MOD_UNNKOW = 0x0,
	FEC_MOD_10G    = 0x7,
	FEC_MOD_50G    = 0xC,
	FEC_MOD_25G    = 0xF,
	FEC_MOD_100G   = 0XD,
};

enum flm_link_speed_info {
	FEC_MOD_SPEED_UNNKOW = 0x0,
	FEC_MOD_SPEED_10G    = 0x2,
	FEC_MOD_SPEED_25G    = 0x4,
	FEC_MOD_SPEED_50G    = 0x8,
	FEC_MOD_SPEED_100G   = 0X10,
};

enum sxe2_speed_mode {
	SXE2_ETHTOOL_SPEED_UNKNOWN = 0,
	SXE2_ETHTOOL_SPEED_10GB = 10000,
	SXE2_ETHTOOL_SPEED_25GB = 25000,
	SXE2_ETHTOOL_SPEED_50GB = 50000,
	SXE2_ETHTOOL_SPEED_100GB = 100000,
	SXE2_ETHTOOL_SPEED_AUTO  = 200000,
};

struct flm_link_fec_result {
	u8 result;
	u8 resv[3];
	u32 port;
};

struct configure_fc {
	u8 rx_en;
	u8 tx_en;
	u8 resv[2];
};

struct configure_an {
	u32           port;
	u32           speed;
	u32           fec_mode;
	u32           lt_en;
	struct configure_fc fc_mode;
	u32           an_en;
};

enum sxe2_fw_connect_mode {
	SXE2_FW_CONNECT_MODE_DAC,
	SXE2_FW_CONNECT_MODE_AOC,
	SXE2_FW_CONNECT_MODE_TRANSCEIVER,
	SXE2_FW_CONNECT_MODE_BACKPLANE,
	SXE2_FW_CONNECT_MDDE_UNKNOWN,
};

enum flm_link_speed {
	FLM_FW_SPEED_10G = 0,
	FLM_FW_SPEED_25G = 1,
	FLM_FW_SPEED_50G = 2,
	FLM_FW_SPEED_100G = 3,
	FLM_FW_SPEED_AUTO = 15,
	FLM_FW_SPEED_MAX
};

struct flm_link_ret {
	u32 speed;
	u32 module_type;
	u32 link_status;
	u32 fec_mode;
	struct configure_fc fc_mode;
};

struct ethtool_flm_link_info {
	s32 speed;
	u32 link_status;
};

struct flm_link_info_pasist {
	u8 speed;
	u8 link_status;
	u8 fec_mode;
	u8 resv;
	struct configure_fc fc_mode;
};

struct sxe2_fw_loop_back_config {
	u8 enable;
	u8 resv[3];
};

struct flm_link_info {
	u32           port_num;
	u32           is_link_up;
	u32           module_type;
	u32           is_an_enable;
	u32           speed;
	u32           fec;
	struct configure_fc fc_mode;
};

struct flm_link_config {
	u32           port_num;
	u32           speed;
	u32           fec;
	u32           port;
};

struct flm_link_result {
	u8 result;
	u8 resv[3];
	u32 port;
};

struct flm_ethtool_get_link_req {
	u32           port_num;
};

enum sxe2_support_fec_mode {
	SXE2_SUPPORTR_FEC_NONE = 0,
	SXE2_SUPPORTR_FEC_BASER = 1,
	SXE2_SUPPORTR_FEC_RS = 2,
	SXE2_SUPPORTR_FEC_AUTO = 15,
	SXE2_SUPPORTR_FEC_MAX,
};

enum sxe2_advertis_fec_mode {
	SXE2_ADVERTIS_FEC_NONE = 0,
	SXE2_ADVERTIS_FEC_BASER = 1,
	SXE2_ADVERTIS_FEC_RS = 2,
	SXE2_ADVERTIS_FEC_AUTO = 15,
	SXE2_ADVERTIS_FEC_MAX,
};

enum sxe2_support_speed_duplex_mode {
	SXE2_SUPPORTR_SPEED_10G,
	SXE2_SUPPORTR_SPEED_25G,
	SXE2_SUPPORTR_SPEED_50G,
	SXE2_SUPPORTR_SPEED_100G,
	SXE2_SUPPORTR_SPEED_AUTO = 15,
	SXE2_SUPPORTR_SPEED_MAX,
};

enum sxe2_support_duplex {
	HALF_DUPLEX = 0,
	FULL_DUPLEX = 1,
	MAX_DUPLEX,
};

enum sxe2_duplex_type {
	CURRENT_HALF_DUPLEX = 0,
	CURRENT_FULL_DUPLEX = 1,
	CURRENT_MAX_DUPLEX,
};

enum sxe2_support_media_type {
	SXE2_MEDIA_UNKNOWN = 0,
	SXE2_MEDIA_FIBER,
	SXE2_MEDIA_BASET,
	SXE2_MEDIA_BACKPLANE,
	SXE2_MEDIA_DA,
};

enum sxe2_support_pause_frame {
	SCGEB_EN_TX_LINK_PAUSE,
	SCGEB_EN_RX_LINK_PAUSE,
	SCGEB_EN_TX_RX_LINK_PAUSE,
	SCGEB_DIS_EN_LINK_PAUSE,
};

enum sxe2_an_status {
	SXE2_AN_ENABLE = 0,
	SXE2_AN_TRANSMIT_DISABLE = 1,
	SXE2_AN_ABILITY_DETECT = 2,
	SXE2_AN_ACKNOWLEDGE_DETECT = 3,
	SXE2_AN_COMPLETE_ACKNOWLEDGE = 4,
	SXE2_AN_NEXT_PAGE_WAIT = 5,
	SXE2_AN_LINK_STATUS_CHECK = 6,
	SXE2_AN_PARALLET_DETECT_FAULT = 7,
	SXE2_AN_GOOD_CHECK = 8,
	SXE2_AN_GOOD = 9,
};

struct sxe2_pause_publicity_ability {
	u8 bit_pause;
	u8 bit_asym;
	u8 resv[2];
};

struct sxe2_local_suppet_advertis_an_en {
	u8 suppert_an;
	u8 advertis_an;
	u8 resv[2];
};

struct sxe2_peer_suppet_an_en {
	u8 suppert_an;
	u8 resv[3];
};

enum sxe2_current_media_type {
	CURRENT_MEDIA_UNKNOWN = 0,
	CURRENT_MEDIA_FIBER,
	CURRENT_MEDIA_BASET,
	CURRENT_MEDIA_BACKPLANE,
	CURRENT_MEDIA_DA,
};

struct sxe2_current_an_en {
	u8 current_an;
	u8 resv[3];
};

enum flm_fec_mode {
	FLM_FEC_NONE = 0,
	FLM_FEC_BSFEC = 1,
	FLM_FEC_528 = 2,
	FLM_FEC_544 = 3,
	FLM_FEC_AUTO = 15,
	FLM_FEC_MAX
};

enum flm_link_status {
	FLM_PORT_DOWN = 0,
	FLM_PORT_UP = 1,
	FLM_PORT_MAX = 2
};

struct fec_ability_supported {
	u32 fec_br : 1;
	u32 fec_528 : 1;
	u32 fec_544 : 1;
	u32 rec : 29;
};

struct spec_entry {
	u8 spec_id;
	u8 reserved[3];
	enum flm_link_speed speed;
	s8 spec_name[16];
};

struct optical_module {
	char vendor[SXE2_FLM_VENDOR_LEN];
	char vendor_pn[SXE2_FLM_VENDOR_PN_LEN];
	u8  module_type;
	u8  current_connection;
};

struct optical_warning_info {
	u8 vendor[SXE2_HOST_FLM_VENDOR_LEN];
	u8 vendor_pn[SXE2_HOST_FLM_VENDOR_PN_LEN];
	bool is_warning;
};

struct __an_mode {
	u32 pause;
	u32 speed_ability_10Gkr;
	u32 speed_ability_25Gkrcr;
	u32 speed_ability_25Gkrcr_s;
	u32 speed_ability_100Gcr4;
	u32 speed_ability_100Gkr4;
	u32 fec_ability_10g;

	u32 fec_en_10g;
	u32 fec_bsfec_25g;
	u32 fec_rs528_25g;
	u8 Consortium_25g_50g_en;
};

struct __an_np_mode {
	u32 speed_ability_25Gkr;
	u32 speed_ability_25Gcr;
	u32 speed_ability_50Gkr2;
	u32 speed_ability_50Gcr2;
	u32 fec_ability_rs528;
	u32 fec_ability_bsfec;
	u32 fec_en_rs528;
	u32 fec_en_bsfec;
};

struct __an_orig_speed_fec {
	u32 orig_speed;
	u32 orig_fec;
};

struct sxe2_an_publicity {
	struct __an_mode an_mode;

	struct __an_np_mode  an_np_mode;
};

struct support_speed_ability_mode {
	u32 ability_speed_25Gkr;
	u32 ability_speed_25Gcr;
	u32 ability_speed_50Gkr2;
	u32 ability_speed_50Gcr2;
	u32 ability_speed_10Gkr;
	u32 ability_speed_25Gkrcr;
	u32 ability_speed_25Gkrcr_s;
	u32 ability_speed_100Gcr4;
	u32 ability_speed_100Gkr4;
	u32 ability_speed_100Gsr4;
};

struct sxe2_fwc_link_state_resp {
	u8 link;
	u8 resv[3];
};

struct flm_ethtool_get_link_resp {
	u8 specs_list[32];
	u32 sxe2_ana_fsm;
	struct optical_module optical_module;
	struct configure_fc configed_pause_result;
	struct configure_fc partner_pause_result;
	struct sxe2_pause_publicity_ability local_pause;

	struct sxe2_local_suppet_advertis_an_en local_an_en;
	enum flm_fec_mode local_fec_mode;
	struct sxe2_pause_publicity_ability partner_pause;
	struct sxe2_peer_suppet_an_en partner_an_en;
	enum sxe2_duplex_type support_duplx;
	enum sxe2_current_media_type current_media;
	struct sxe2_current_an_en current_an_en;
	struct fec_ability_supported advertis_fec;
	struct fec_ability_supported partner_fec;
	struct sxe2_an_publicity an_publicity;
};

struct sxe2_msg_ethtool_info {
	struct flm_ethtool_get_link_resp cfg;
	struct support_speed_ability_mode ability;
	u8 usr_link_speed;
};

struct sxe2_fwc_udp_tunnel_ref_add_req {
	u8 type;
	__le16 port;
};

struct sxe2_fwc_udp_tunnel_ref_delete_req {
	u8 type;
	u8 clear;
};

struct sxe2_fwc_udp_tunnel_ref_get_req {
	u8 type;
};

struct sxe2_fwc_udp_tunnel_ref_get_resp {
	u8 type;
	u8 enable;
	u8 dst;
	u8 src;
	__le16 port;
	u8 used;
	u8 rsvd;
};

struct sxe2_fw_ncd_core_num_config_req {
	u8 core_num;
	u8 resv[3];
};

struct sxe2_fw_ncd_core_pri_queue {
	u8 core_id;
	u8 pri;
	__le16 queue_id;
};

struct sxe2_fw_ncd_switch_tag_req {
	u8 loc;
	u8 len;
	u8 en;
	u8 mac_id;
};

struct sxe2_fw_ncd_switch_tag_resp {
	u8 loc;
	u8 len;
	u8 resv[2];
};

struct sxe2_fw_ncd_txlen_adj_req {
	u8 mac_id;
	u8 len;
	u8 resv[2];
};

struct sxe2_fw_ncd_txlen_adj_resp {
	u8 mac_id;
	u8 len;
	u8 resv[2];
};

struct sxe2_fw_ncd_sdf_req {
	__le16 eth_type;
	__le16 mask;
	u8  en;
	u8  resv;
};

struct sxe2_fw_ncd_sdf_resp {
	__le16 eth_type;
	__le16 mask;
};

struct sxe2_fw_ncd_sdn_udp_req_resp {
	__le16 start_port;
	__le16 end_port;
	u8  ph_len;
	u8  udp_grp_id;
	u8  used_count;
	u8  resv;
};

struct sxe2_fw_ncd_sdn_req_resp {
	union {
		__le32 ipv4_addr;
		__le32 ipv6_addr[4];
	} dest_addr;
__le16 used_count;
	u8 is_ipv4;
	u8 udp_grp_id;
	u8 ip_id;
	u8 resv[3];
};

struct sxe2_fw_ncd_sdn_ipsec_query_req {
	__le16 udp_port;
	u8 resv[2];
};

struct sxe2_fw_ncd_sdn_ipsec_query_resp {
	u8 find;
	u8 udp_grp_id;
	u8 resv[2];
};

struct sxe2_fw_ncd_sdn_ipsec_udp_req {
	__le32 port_bmp;
	__le16 start_port;
	u8  udp_grp_id;
	u8  resv;
};

struct sxe2_fw_ncd_app_port_req {
	u8 idx;
	u8 is_tcp;
	u8 sport_en;
	u8 dport_en;
};

struct sxe2_fw_ncd_pkt_pri_req {
	u8 idx;
	u8 pri;
	u8 resv[2];
};

struct sxe2_fw_ncd_udf_capa_get_resp {
	__le32 sdn_ip_addr;
	__le32 sdn_udp_ipsec_bm;
	__le16 sdn_udp_ipsec_sp;
	__le16 sdn_udp_start_port;
	__le16 sdn_udp_end_port;
	__le16 sdf_eth_type;
	__le16 sdf_mask;
	u8 sdf_en;
	u8 switch_tag_en;
	u8 switch_tag_len;
	u8 switch_tag_loc;
	u8 txlen_adj_len[4];
	u8 sdn_udp_ph_len;
	u8 sdn_ip_type;
	u8 sdn_ip_udp_grp_id;
	u8 spec_proto_port_type;
	u8 spec_ptype_pri_level;
	u8 resv;
};

#define BFD_INTQ_CMD_SRC_IRQ       (0)
#define BFD_INTQ_CMD_SRC_POLLING   (1)
#define BFD_INTQ_CMD_BUF_LEN	   (64)

struct sxe2_fwc_bfd_config_set_req {
	__le16 max_sess;
	u8  scan_interval;
	u8  bfd_en;
};

struct sxe2_fwc_bfd_intq_info_get_req {
	u8 src;
	u8 sess_num;
	u8 resv[2];
};

struct sxe2_fwc_bfd_intq_info_get_resp {
	u8 buf_empty;
	u8 valid_len;
	u8 resv[2];
	struct {
		__le16 sess_id;
		u8 reason;
		u8 sess_state;
	} data[BFD_INTQ_CMD_BUF_LEN];
};

struct sxe2_fwc_bfd_kt_entry {
	u8 is_add;
	u8 prof_id;
	u8 rsv[2];
	u8 inputset[SXE2_BFD_FV_CNT_MAX * 2];
	__le16 vsi;
	__le16 sess_id;
	__le32 fdid;
};

struct sxe2_fwc_bfd_kt_entry_resp {
	__le16 kt_index;
	u8 resv[2];
};

struct sxe2_fwc_bfd_sess_cfg_set_req {
	__le16 sess_id;
	u8  valid;
	u8  sess_mode;
	__le16 kt_index;
	u8  mac_id;
	u8  tc_id;
	u8  tx_en;
	u8  rx_en;
	__le16 tx_interval;
	__le32 rx_interval;
	__le16 ppt_id;
	u8 state;
	u8 rsv;
};

struct sxe2_fwc_bfd_sess_state_get_req {
	__le16 sess_id;
	u8 rsv[2];
};

struct sxe2_fwc_bfd_sess_state_get_resp {
	u8  state;
	u8  aging_state;
	__le16 prof_id;
	__le16 rx_cnt;
	__le16 tx_cnt;
};

struct sxe2_fwc_bfd_capability_get_resp {
	__le16 max_sess;
	__le16 max_package_profile;
	__le16 min_scan_interval;
	__le16 bfde_vsi;
	__le16 max_pkt_buf;
	__le16 max_edit_cmd;
	__le16 max_csum_desc;
	u8 rsv[2];
};

#define SXE2_BYTES_PER_PKT_BUF_ENT    (32)
#define SXE2_PKT_BUF_MAX_PER_PROF     (16)
#define SXE2_PKT_BUF_SIZE_MAX \
		(SXE2_BYTES_PER_PKT_BUF_ENT * SXE2_PKT_BUF_MAX_PER_PROF)

#define SXE2_BYTES_PER_EDIT_CMD	(8)
#define SXE2_EDIT_CMD_PER_ENT	(4)
#define SXE2_EDIT_CMD_MAX		(16)
#define SXE2_EDIT_CMD_ENT_MAX (SXE2_EDIT_CMD_MAX / SXE2_EDIT_CMD_PER_ENT)
#define SXE2_BYTES_PER_EDIT_CMD_ENT (SXE2_BYTES_PER_EDIT_CMD * SXE2_EDIT_CMD_PER_ENT)
#define SXE2_EDIT_CMD_SIZE_MAX (SXE2_EDIT_CMD_MAX * SXE2_BYTES_PER_EDIT_CMD)

struct sxe2_bfd_edit_cmd_req {
	struct {
		u8 code;
		u8 size;
		__le16 loc;
	} instr[SXE2_EDIT_CMD_PER_ENT];
};

struct sxe2_fwc_bfd_pack_prof_set_req {
	__le16 prof_id;
	u8  rsv[2];

	struct {
		__le16 pkt_addr;
		u8  pkt_len;
		u8  pkt_lbo;
		u8  data[SXE2_PKT_BUF_SIZE_MAX];
	} pkt_buffer;

	struct {
		__le16 edit_cmd_addr;
		u8  edit_cmd_len;
		struct sxe2_bfd_edit_cmd_req cmd[SXE2_EDIT_CMD_MAX];
	} edit_cmd;

	__le16 csum_desc_addr;
	u8  csum_desc_len;
	u8  rsv0;
	struct {
		__le16 start_addr;
		__le16 csum_loc;
		__le16 csum_len;
		u8  result_negate;
		u8  rsv1;
		__le32 chk_data;
		struct sxe2_bfd_edit_cmd_req cmd[SXE2_EDIT_CMD_PER_ENT];
	} csum_desc[2];
};

struct sxe2_fwc_bfd_meta_key_len_req {
	__le16 prof_id;
	__le16 key_len;
};

struct sxe2_tx_fault_count_mib {
	u64 tx_fault_count;
};

struct single_link_result {
	u32	       port_num;
	u32	       is_link_up;
	u32	       speed;
	u32	       fec;
	struct configure_fc fc_mode;
};

struct configure_fixed {
	u32	       port;
	u32	       speed;
	u32	       fec_mode;
	u32	       port_mode;
	u32	       an_en;
	u32	       lt_en;
	struct configure_fc fc_mode;
	s32 pcsRet;
};

struct all_link_status {
	u32 dut_status;
	u32 sb_status;
};

struct sxe2_fwc_txpa_dfx {
	u32 txpa_in_all;
	u32 txpa_out_all;
	u32 txpa_in_drop;
	u32 txpa_out_drop;
	u32 txpa_in_err;
	u32 txpa_out_err;
};

struct sxe2_fwc_txfb_dfx {
	u32 txfb_in_all;
	u32 txfb_in_drop;
	u32 txfb_out_all;
	u32 txfb_out_drop;
	u32 txfb_internal_drop;
};

struct sxe2_fwc_rxpa_dfx {
	u32 rxpa_in_all;
	u32 rxpa_out_all;
	u32 rxpa_in_drop;
	u32 rxpa_out_drop;
	u32 rxpa_in_err;
	u32 rxpa_out_err;
};

struct sxe2_fwc_rxfb_dfx {
	u32 rxfb_tx_in_all;
	u32 rxfb_rx_in_all;
	u32 rxfb_tx_in_drop;
	u32 rxfb_rx_in_drop;
	u32 rxfb_out_all;
	u32 rxfb_out_drop;
	u32 rxfb_internal_drop;
};

struct sxe2_fwc_switch_dfx {
	u32 tx_all;
	u32 tx_drop;
	u32 rx_all;
	u32 rx_drop;
};

struct sxe2_fwc_rxft_dfx {
	u32 tx_in_all;
	u32 tx_in_drop;
	u32 tx_out_all;
	u32 tx_out_drop;
	u32 rx_in_all;
	u32 rx_in_drop;
	u32 rx_out_all;
	u32 rx_out_drop;
	u32 lp_in_all;
	u32 lp_in_drop;
	u32 lp_out_all;
	u32 lp_out_drop;
};

struct sxe2_fwc_ppe_dfx {
	struct sxe2_fwc_txpa_dfx txpa[4];
	struct sxe2_fwc_txfb_dfx txfb;
	struct sxe2_fwc_rxpa_dfx rxpa[4];
	struct sxe2_fwc_rxfb_dfx rxfb;
	struct sxe2_fwc_switch_dfx sw;
	struct sxe2_fwc_rxft_dfx rxft;
};

#define SXE2_ACL_LUT_ENTRY_WIDTH         (5)
#define SXE2_ACL_ACTION_TCAM_CNT            (16)
#define SXE2_ACL_ACTION_MEM_CNT     (20)
#define SXE2_ACL_ACTION_NUM_PER_ENTRY    (2)
#define SXE2_ACL_ACTION_TCAM_DEPTH       (512)
#define SXE2_ACL_ACTION_MEM_DEPTH        (512)

struct sxe2_fwc_acl_lut_alloc_req {
	__le16 width;
	__le16 depth;
	u8 act_pairs_per_entry;

	u8 concurr;
	u8 num_dependent_alloc_ids;
	__le16 alloc_ids[SXE2_ACL_ACTION_TCAM_CNT - 1];
};

struct sxe2_fwc_acl_lut_alloc_resp {
	__le16 alloc_id;

	__le16 first_entry;
	__le16 last_entry;

	u8 first_tcam;
	u8 last_tcam;

	u8 act_mem[SXE2_ACL_ACTION_MEM_CNT];
};

struct sxe2_fwc_acl_lut_dealloc_req {
	__le16 alloc_id;
	u8 rsv[2];
};

struct sxe2_fwc_acl_prof_sel_base_req {
	__le16 prof_id;

	u8 byte_selection[30];
	u8 word_selection[32];
	u8 dword_selection[15];
	u8 pf_scenario_num[8];
};

struct sxe2_acl_entry_data {
	struct {
		u8 val[SXE2_ACL_LUT_ENTRY_WIDTH];
		u8 enable;
		u8 reserved[2];
	} entry_key, entry_key_invert;
};

struct sxe2_fwc_acl_lut_entry_set_req {
	u8 tcam_idx;
	__le16 entry_idx;
	u8 rsv;

	struct sxe2_acl_entry_data data;
};

struct sxe2_acl_act_entry_data {
	u8 prio;
	u8 mdid;
	__le16 value;
};

struct sxe2_fwc_acl_act_entry_set_req {
	u8 act_mem_idx;
	__le16 act_entry_idx;
	u8 rsv;

	struct sxe2_acl_act_entry_data data[SXE2_ACL_ACTION_NUM_PER_ENTRY];
};

struct sxe2_fwc_acl_scen_alloc_req {
	struct {
		u8 tcam_select[SXE2_ACL_LUT_ENTRY_WIDTH];
		u8 enable;
#define SXE2_ACL_ALLOC_SCEN_START_CMP		BIT(0)
#define SXE2_ACL_ALLOC_SCEN_START_SET		BIT(1)
		u8 start_cmp_set;
		u8 rsv;
	} tcam_cfg[SXE2_ACL_ACTION_TCAM_CNT];

#define SXE2_ACL_ACT_MEM_EN                BIT(4)
	u8 act_mem_cfg[SXE2_ACL_ACTION_MEM_CNT];
};

struct sxe2_fwc_acl_scen_alloc_resp {
	__le16 scen_id;
	u8 rsv[2];
};

struct sxe2_fwc_acl_scen_dealloc_req {
	__le16 scen_id;
	u8 rsv[2];
};

struct sxe2_fwc_acl_prof_querey_req {
	__le16 prof_id;
};

struct sxe2_fwc_acl_prof_querey_resp {
	u8 byte_selection[30];
	u8 word_selection[32];
	u8 dword_selection[15];
	u8 pf_scenario_num[8];
};

struct sxe2_acl_hit_info {
	__le32 profile_id    : 7;
	__le32 rsv0          : 25;

	__le32 fv1     : 16;
	__le32 fv0       : 16;

	__le32 fv3     : 16;
	__le32 fv2       : 16;

	__le32 fv5     : 16;
	__le32 fv4       : 16;

	__le32 fv7     : 16;
	__le32 fv6       : 16;

	__le32 fv9     : 16;
	__le32 fv8       : 16;

	__le32 fv11    : 16;
	__le32 fv10       : 16;

	__le32 fv13     : 16;
	__le32 fv12       : 16;

	__le32 fv15     : 16;
	__le32 fv14       : 16;

	__le32 fv17     : 16;
	__le32 fv16       : 16;

	__le32 fv19     : 16;
	__le32 fv18       : 16;

	__le32 fv21     : 16;
	__le32 fv20       : 16;

	__le32 fv23     : 16;
	__le32 fv22       : 16;

	__le32 fv25     : 16;
	__le32 fv24       : 16;

	__le32 fv27     : 16;
	__le32 fv26       : 16;

	__le32 fv29     : 16;
	__le32 fv28       : 16;

	__le32 fv31     : 16;
	__le32 fv30       : 16;
};

struct sxe2_acl_dfx_info {
	__le32 og_inbuf_hdr_cnt;
	__le32 og_inbuf_info_cnt;
	__le32 og_proc_hdr_cnt;
	__le32 og_proc_info_cnt;
	__le32 og_to_engine_cnt;
	__le32 og_in_rg_cnt;
	__le32 og_out_rg_cnt;
	__le32 sel_base_cnt;
	__le32 key_gen_cnt;
	__le32 key_gen_to_lkt_cnt;
	__le32 act_mem_cnt;
	__le32 osc_act_cnt;
	__le32 osc_pkt_cnt;
	__le32 acl_rxft_cnt;
	__le32 acl_recv_drop_cnt;
	__le32 acl_action_drop_cnt;
	__le32 acl_vsi_disable_drop_cnt;
	__le32 prfl_tcam_hit_cnt;
	__le32 prfl_tcam_miss_cnt;
	__le32 prfl_tcam_bypss_cnt;
	__le32 act_tcam_hit_cnt[16];
	__le32 act_tcam_miss_cnt[16];

	__le16 act_idx_first[16];
	__le16 act_idx_last[16];
	__le32 act_key_first_low[16];
	__le32 act_key_first_high[16];
	__le32 act_key_last_low[16];
	__le32 act_key_last_high[16];

	__le64 key_first;
	__le64 key_last;

	u8 first_prfl_id;
	u8 last_prfl_id;
	u8 first_scen_id;
	u8 last_scen_id;
	__le16 first_prfl_tcam_idx;
	__le16 last_prfl_tcam_idx;

	__le16 first_cascade;
	__le16 last_cascade;
	__le16 first_stack;
	__le16 last_stack;
	__le16 first_tcam_en;
	__le16 last_tcam_en;
};

struct sxe2_acl_trace_recorder {
	u8 trace_status0;
	u8 trace_status2;
	u8 rsv[2];
	struct sxe2_acl_hit_info hit_info;
};

struct sxe2_vf_queue_info {
	__le16 rxq_base;
	__le16 rxq_cnt;
	__le16 txq_base;
	__le16 txq_cnt;
};

struct sxe2_fwc_vf_queue_info {
	u8 pf_id;
	u16 vf_cnt;
	u8 rsv[1];
	struct sxe2_vf_queue_info queue_info[];
};

#pragma pack()

#endif
