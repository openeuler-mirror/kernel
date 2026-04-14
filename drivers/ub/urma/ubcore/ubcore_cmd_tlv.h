/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Description: ubcore cmd tlv parse header, ubcore cmd struct consists of
 * type/length/value, ioctl operations are copyed and parsed by tlv form
 * Author: Chen Yutao
 * Create: 2024-08-06
 * Note:
 * History: 2024-08-06: create file
 */

#ifndef UBCORE_CMD_TLV_H
#define UBCORE_CMD_TLV_H

#include <linux/types.h>
#include "ubcore_cmd.h"
#include "ubcore_uvs_cmd.h"

#define UBCORE_CMD_OUT_TYPE_INIT 0x80

struct ubcore_cmd_attr {
	uint8_t type; /* See enum ubcore_cmd_xxx_type */
	uint8_t flag;
	uint16_t field_size;
	union {
		struct {
			uint32_t el_num : 20; /* Array element number if field is in an array */
			uint32_t el_size : 12; /* Array element size if field is in an array */
		} bs;
		uint32_t value;
	} attr_data;
	uint64_t data;
};

struct ubcore_cmd_spec {
	uint8_t type; /* See ubcore_cmd_xxx_type_t */
	uint8_t flag;
	uint16_t field_size;
	union {
		struct {
			uint32_t el_num : 20; /* Array element number if field is in an array */
			uint32_t el_size : 12; /* Array element size if field is in an array */
		} bs;
		uint32_t value;
	} attr_data;
	uint64_t data;
};

/* Attention: for all these below enums, */
/* new element should ONLY be added into the bottom */
/* See struct ubcore_cmd_channel_init */
enum ubcore_cmd_channel_init_type {
	/* In type */
	CHANNEL_INIT_IN_MUE_NAME,
	CHANNEL_INIT_IN_USERSPACE_IN,
	CHANNEL_INIT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CHANNEL_INIT_OUT_KERNEL_OUT = UBCORE_CMD_OUT_TYPE_INIT,
	CHANNEL_INIT_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_set_mue_cfg */
enum ubcore_cmd_set_mue_cfg_type {
	/* In type */
	SET_MUE_CFG_IN_MUE_MUE_NAME,
	SET_MUE_CFG_IN_MUE_CFG_MASK,
	SET_MUE_CFG_IN_MUE_CFG_SUSPEND_PERIOD,
	SET_MUE_CFG_IN_MUE_CFG_SUSPEND_CNT,
	SET_MUE_CFG_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_create_tpg, in/out type should be continuous */
enum ubcore_cmd_create_tpg_type {
	/* In type */
	CREATE_TPG_IN_MUE_NAME,
	CREATE_TPG_IN_LOCAL_EID,
	CREATE_TPG_IN_PEER_EID,
	CREATE_TPG_IN_TRANS_MODE,
	CREATE_TPG_IN_DSCP,
	CREATE_TPG_IN_CC_ALG,
	CREATE_TPG_IN_CC_PATTERN_IDX,
	CREATE_TPG_IN_TP_CNT,
	CREATE_TPG_IN_LOCAL_NET_ADDR,
	CREATE_TPG_IN_FLAG,
	CREATE_TPG_IN_LOCAL_JETTY,
	CREATE_TPG_IN_UE_IDX,
	CREATE_TPG_IN_PEER_JETTY,
	CREATE_TPG_IN_TP_TRANS_MODE,
	CREATE_TPG_IN_RETRY_NUM,
	CREATE_TPG_IN_RETRY_FACTOR,
	CREATE_TPG_IN_ACK_TIMEOUT,
	CREATE_TPG_IN_TP_DSCP,
	CREATE_TPG_IN_OOR_CNT,
	CREATE_TPG_IN_TA_TRANS_TYPE,
	CREATE_TPG_IN_TA_TYPE,
	CREATE_TPG_IN_JETTY_ID,
	CREATE_TPG_IN_TJETTY_ID,
	CREATE_TPG_IN_IS_TARGET,
	CREATE_TPG_IN_NUM, /* Only for calculating number of types */
	/* out type */
	CREATE_TPG_OUT_TPGN = UBCORE_CMD_OUT_TYPE_INIT,
	CREATE_TPG_OUT_TPN,
	CREATE_TPG_OUT_MAX_MTU,
	CREATE_TPG_OUT_LOCAL_MTU,
	CREATE_TPG_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_create_vtp, in/out type should be continuous */
enum ubcore_cmd_create_vtp_type {
	/* In type */
	CREATE_VTP_IN_MUE_NAME,
	CREATE_VTP_IN_TPGN,
	CREATE_VTP_IN_PEER_TPGN,
	CREATE_VTP_IN_TP_ATTR_FLAG,
	CREATE_VTP_IN_TP_ATTR_PEER_TPN,
	CREATE_VTP_IN_TP_ATTR_STATE,
	CREATE_VTP_IN_TP_ATTR_TX_PSN,
	CREATE_VTP_IN_TP_ATTR_RX_PSN,
	CREATE_VTP_IN_TP_ATTR_MTU,
	CREATE_VTP_IN_TP_ATTR_CC_APTTERN_IDX,
	CREATE_VTP_IN_TP_ATTR_PEER_EXT_ADDR,
	CREATE_VTP_IN_TP_ATTR_PEER_EXT_LEN,
	CREATE_VTP_IN_TP_ATTR_OOS_CNT,
	CREATE_VTP_IN_TP_ATTR_LOCAL_NETADDR_IDX,
	CREATE_VTP_IN_TP_ATTR_PEER_NETADDR,
	CREATE_VTP_IN_TP_ATTR_DATA_UDP_START,
	CREATE_VTP_IN_TP_ATTR_ACK_UDP_START,
	CREATE_VTP_IN_TP_ATTR_UDP_RANGE,
	CREATE_VTP_IN_TP_ATTR_HOP_LIMIT,
	CREATE_VTP_IN_TP_ATTR_FLOW_LABEL,
	CREATE_VTP_IN_TP_ATTR_PORT_ID,
	CREATE_VTP_IN_TP_ATTR_MN,
	CREATE_VTP_IN_TP_ATTR_PEER_TRANS_TYPE,
	CREATE_VTP_IN_TP_ATTR_MASK,
	CREATE_VTP_IN_CFG_UE_IDX,
	CREATE_VTP_IN_CFG_VTPN,
	CREATE_VTP_IN_CFG_LOCAL_JETTY,
	CREATE_VTP_IN_CFG_LOCAL_EID,
	CREATE_VTP_IN_CFG_PEER_EID,
	CREATE_VTP_IN_CFG_PEER_JETTY,
	CREATE_VTP_IN_CFG_FLAG,
	CREATE_VTP_IN_CFG_TRANS_MODE,
	CREATE_VTP_IN_CFG_VALUE,
	CREATE_VTP_IN_EID_IDX,
	CREATE_VTP_IN_UPI,
	CREATE_VTP_IN_SHARE_MODE,
	CREATE_VTP_IN_NUM,
	/* Out type */
	CREATE_VTP_OUT_RTR_TP_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	CREATE_VTP_OUT_RTS_TP_CNT,
	CREATE_VTP_OUT_VTPN,
	CREATE_VTP_OUT_NUM
};

/* See struct ubcore_cmd_modify_tpg, in/out type should be continuous */
enum ubcore_cmd_modify_tpg_type {
	/* In type */
	MODIFY_TPG_IN_MUE_NAME,
	MODIFY_TPG_IN_PEER_TP_CNT,
	MODIFY_TPG_IN_TPGN,
	MODIFY_TPG_IN_PEER_TPGN,
	MODIFY_TPG_IN_TP_ATTR_FLAG,
	MODIFY_TPG_IN_TP_ATTR_PEER_TPN,
	MODIFY_TPG_IN_TP_ATTR_STATE,
	MODIFY_TPG_IN_TP_ATTR_TX_PSN,
	MODIFY_TPG_IN_TP_ATTR_RX_PSN,
	MODIFY_TPG_IN_TP_ATTR_MTU,
	MODIFY_TPG_IN_TP_ATTR_CC_PATTERN_IDX,
	MODIFY_TPG_IN_TP_ATTR_PEER_EXT_ADDR,
	MODIFY_TPG_IN_TP_ATTR_PEER_EXT_LEN,
	MODIFY_TPG_IN_TP_ATTR_OOS_CNT,
	MODIFY_TPG_IN_TP_ATTR_LOCAL_NETADDR_IDX,
	MODIFY_TPG_IN_TP_ATTR_PEER_NETADDR,
	MODIFY_TPG_IN_TP_ATTR_DATA_UDP_START,
	MODIFY_TPG_IN_TP_ATTR_ACK_UDP_START,
	MODIFY_TPG_IN_TP_ATTR_UDP_RANGE,
	MODIFY_TPG_IN_TP_ATTR_HOP_LIMIT,
	MODIFY_TPG_IN_TP_ATTR_FLOW_LABEL,
	MODIFY_TPG_IN_TP_ATTR_PORT_ID,
	MODIFY_TPG_IN_TP_ATTR_MN,
	MODIFY_TPG_IN_TP_ATTR_PEER_TRANS_TYPE,
	MODIFY_TPG_IN_RTR_MASK,
	MODIFY_TPG_IN_TA_TRANS_TYPE,
	MODIFY_TPG_IN_TA_TYPE,
	MODIFY_TPG_IN_TA_JETTY_ID,
	MODIFY_TPG_IN_TA_TJETTY_ID,
	MODIFY_TPG_IN_TA_IS_TARGET,
	MODIFY_TPG_IN_UDRV_IN_ADDR,
	MODIFY_TPG_IN_UDRV_IN_LEN,
	MODIFY_TPG_IN_UDRV_OUT_ADDR,
	MODIFY_TPG_IN_UDRV_OUT_LEN,
	MODIFY_TPG_IN_NUM,
	/* Out type */
	MODIFY_TPG_OUT_RTR_TP_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	MODIFY_TPG_OUT_RTS_TP_CNT,
	MODIFY_TPG_OUT_NUM
};

/* See struct ubcore_cmd_modify_tpg_map_vtp, in/out type should be continuous */
enum ubcore_cmd_modify_tpg_map_vtp_type {
	/* In type */
	MODIFY_TPG_MAP_VTP_IN_MUE_NAME,
	MODIFY_TPG_MAP_VTP_IN_PEER_TP_CNT,
	MODIFY_TPG_MAP_VTP_IN_TPGN,
	MODIFY_TPG_MAP_VTP_IN_PEER_TPGN,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_FLAG,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_PEER_TPN,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_STATE,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_TX_PSN,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_RX_PSN,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_MTU,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_CC_PATTERN_IDX,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_PEER_EXT_ADDR,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_PEER_EXT_LEN,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_OOS_CNT,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_LOCAL_NETADDR_IDX,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_PEER_NETADDR,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_DATA_UDP_START,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_ACK_UDP_START,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_UDP_RANGE,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_HOP_LIMIT,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_FLOW_LABEL,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_PORT_ID,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_MN,
	MODIFY_TPG_MAP_VTP_IN_TP_ATTR_PEER_TRANS_TYPE,
	MODIFY_TPG_MAP_VTP_IN_RTR_MASK,
	MODIFY_TPG_MAP_VTP_IN_CFG_UE_IDX,
	MODIFY_TPG_MAP_VTP_IN_CFG_VTPN,
	MODIFY_TPG_MAP_VTP_IN_CFG_LOCAL_JETTY,
	MODIFY_TPG_MAP_VTP_IN_CFG_LOCAL_EID,
	MODIFY_TPG_MAP_VTP_IN_CFG_PEER_EID,
	MODIFY_TPG_MAP_VTP_IN_CFG_PEER_JETTY,
	MODIFY_TPG_MAP_VTP_IN_CFG_FLAG,
	MODIFY_TPG_MAP_VTP_IN_CFG_TRANS_MODE,
	MODIFY_TPG_MAP_VTP_IN_CFG_VALUE,
	MODIFY_TPG_MAP_VTP_IN_ROLE,
	MODIFY_TPG_MAP_VTP_IN_EID_IDX,
	MODIFY_TPG_MAP_VTP_IN_UPI,
	MODIFY_TPG_MAP_VTP_IN_SHARE_MODE,
	MODIFY_TPG_MAP_VTP_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	MODIFY_TPG_MAP_VTP_OUT_RTR_TP_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	MODIFY_TPG_MAP_VTP_OUT_RTS_TP_CNT,
	MODIFY_TPG_MAP_VTP_OUT_VTPN,
	MODIFY_TPG_MAP_VTP_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_modify_tpg_tp_cnt, in/out type should be continuous */
enum ubcore_cmd_modify_tpg_tp_cnt_type {
	/* In type */
	MODIFY_TPG_TP_CNT_IN_MUE_MUE_NAME,
	MODIFY_TPG_TP_CNT_IN_TPGN_FOR_MODIFY,
	MODIFY_TPG_TP_CNT_IN_TP_CNT,
	MODIFY_TPG_TP_CNT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	MODIFY_TPG_TP_CNT_OUT_TPGN = UBCORE_CMD_OUT_TYPE_INIT,
	MODIFY_TPG_TP_CNT_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_create_target_tpg, in/out type should be continuous */
enum ubcore_cmd_create_target_tpg_type {
	/* In type */
	CREATE_TARGET_TPG_IN_MUE_NAME,
	CREATE_TARGET_TPG_IN_TPG_CFG_LOCAL_EID,
	CREATE_TARGET_TPG_IN_TPG_CFG_PEER_EID,
	CREATE_TARGET_TPG_IN_TPG_CFG_TRANS_MODE,
	CREATE_TARGET_TPG_IN_TPG_CFG_DSCP,
	CREATE_TARGET_TPG_IN_TPG_CFG_CC_ALG,
	CREATE_TARGET_TPG_IN_TPG_CFG_CC_PATTERN_IDX,
	CREATE_TARGET_TPG_IN_TPG_CFG_TP_CNT,
	CREATE_TARGET_TPG_IN_TPG_CFG_LOCAL_NET_ADDR,
	CREATE_TARGET_TPG_IN_TP_CFG_FLAG,
	CREATE_TARGET_TPG_IN_TP_CFG_LOCAL_JETTY,
	CREATE_TARGET_TPG_IN_TP_CFG_UE_IDX,
	CREATE_TARGET_TPG_IN_TP_CFG_PEER_JETTY,
	CREATE_TARGET_TPG_IN_TP_CFG_TRANS_MODE,
	CREATE_TARGET_TPG_IN_TP_CFG_RETRY_NUM,
	CREATE_TARGET_TPG_IN_TP_CFG_RETRY_FACTOR,
	CREATE_TARGET_TPG_IN_TP_CFG_ACK_TIMEOUT,
	CREATE_TARGET_TPG_IN_TP_CFG_DSCP,
	CREATE_TARGET_TPG_IN_TP_CFG_OOR_CNT,
	CREATE_TARGET_TPG_IN_PEER_TPGN,
	CREATE_TARGET_TPG_IN_RTR_ATTR_FLAG,
	CREATE_TARGET_TPG_IN_RTR_ATTR_PEER_TPN,
	CREATE_TARGET_TPG_IN_RTR_ATTR_STATE,
	CREATE_TARGET_TPG_IN_RTR_ATTR_TX_PSN,
	CREATE_TARGET_TPG_IN_RTR_ATTR_RX_PSN,
	CREATE_TARGET_TPG_IN_RTR_ATTR_MTU,
	CREATE_TARGET_TPG_IN_RTR_ATTR_CC_PATTERN_IDX,
	CREATE_TARGET_TPG_IN_RTR_ATTR_PEER_EXT_ADDR,
	CREATE_TARGET_TPG_IN_RTR_ATTR_PEER_EXT_LEN,
	CREATE_TARGET_TPG_IN_RTR_ATTR_OOS_CNT,
	CREATE_TARGET_TPG_IN_RTR_ATTR_LOCAL_NET_ADDR_IDX,
	CREATE_TARGET_TPG_IN_RTR_ATTR_PEER_NET_ADDR,
	CREATE_TARGET_TPG_IN_RTR_ATTR_DATA_UDP_START,
	CREATE_TARGET_TPG_IN_RTR_ATTR_ACK_UDP_START,
	CREATE_TARGET_TPG_IN_RTR_ATTR_UDP_RANGE,
	CREATE_TARGET_TPG_IN_RTR_ATTR_HOP_LIMIT,
	CREATE_TARGET_TPG_IN_RTR_ATTR_FLOW_LABEL,
	CREATE_TARGET_TPG_IN_RTR_ATTR_PORT_ID,
	CREATE_TARGET_TPG_IN_RTR_ATTR_MN,
	CREATE_TARGET_TPG_IN_RTR_ATTR_PEER_TRANS_TYPE,
	CREATE_TARGET_TPG_IN_RTR_MASK,
	CREATE_TARGET_TPG_IN_TA_DATA_TRANS_TYPE,
	CREATE_TARGET_TPG_IN_TA_DATA_TA_TYPE,
	CREATE_TARGET_TPG_IN_TA_DATA_JETTY_ID,
	CREATE_TARGET_TPG_IN_TA_DATA_TJETTY_ID,
	CREATE_TARGET_TPG_IN_TA_DATA_IS_TARGET,
	CREATE_TARGET_TPG_IN_PEER_MTU,
	CREATE_TARGET_TPG_IN_UDATA_IN_ADDR,
	CREATE_TARGET_TPG_IN_UDATA_IN_LEN,
	CREATE_TARGET_TPG_IN_UDATA_OUT_ADDR,
	CREATE_TARGET_TPG_IN_UDATA_OUT_LEN,
	CREATE_TARGET_TPG_IN_UDRV_EXT_IN_ADDR,
	CREATE_TARGET_TPG_IN_UDRV_EXT_IN_LEN,
	CREATE_TARGET_TPG_IN_UDRV_EXT_OUT_ADDR,
	CREATE_TARGET_TPG_IN_UDRV_EXT_OUT_LEN,
	CREATE_TARGET_TPG_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_TARGET_TPG_OUT_TPGN = UBCORE_CMD_OUT_TYPE_INIT,
	CREATE_TARGET_TPG_OUT_TPN,
	CREATE_TARGET_TPG_OUT_RTS_TP_CNT,
	CREATE_TARGET_TPG_OUT_LOCAL_MTU,
	CREATE_TARGET_TPG_OUT_UDRV_EXT_IN_ADDR,
	CREATE_TARGET_TPG_OUT_UDRV_EXT_IN_LEN,
	CREATE_TARGET_TPG_OUT_UDRV_EXT_OUT_ADDR,
	CREATE_TARGET_TPG_OUT_UDRV_EXT_OUT_LEN,
	CREATE_TARGET_TPG_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_modify_target_tpg, in/out type should be continuous */
enum ubcore_cmd_modify_target_tpg_type {
	/* In type */
	MODIFY_TARGET_TPG_IN_MUE_NAME,
	MODIFY_TARGET_TPG_IN_PEER_TP_CNT,
	MODIFY_TARGET_TPG_IN_TPGN,
	MODIFY_TARGET_TPG_IN_PEER_TPGN,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_FLAG,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_PEER_TPN,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_STATE,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_TX_PSN,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_RX_PSN,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_MTU,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_CC_PATTERN_IDX,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_PEER_EXT_ADDR,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_PEER_EXT_LEN,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_OOS_CNT,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_LOCAL_NET_ADDR_IDX,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_PEER_NET_ADDR,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_DATA_UDP_START,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_ACK_UDP_START,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_UDP_RANGE,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_HOP_LIMIT,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_FLOW_LABEL,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_PORT_ID,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_MN,
	MODIFY_TARGET_TPG_IN_RTR_ATTR_PEER_TRANS_TYPE,
	MODIFY_TARGET_TPG_IN_RTR_MASK,
	MODIFY_TARGET_TPG_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	MODIFY_TARGET_TPG_OUT_RTR_TP_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	MODIFY_TARGET_TPG_OUT_RTS_TP_CNT,
	MODIFY_TARGET_TPG_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_destroy_vtp */
enum ubcore_cmd_destroy_vtp_type {
	/* In type */
	DESTROY_VTP_IN_MUE_MUE_NAME,
	DESTROY_VTP_IN_MODE,
	DESTROY_VTP_IN_LOCAL_JETTY,
	DESTROY_VTP_IN_ROLE,
	DESTROY_VTP_IN_LOCAL_EID,
	DESTROY_VTP_IN_PEER_EID,
	DESTROY_VTP_IN_PEER_JETTY,
	DESTROY_VTP_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_destroy_tpg, in/out type should be continuous */
enum ubcore_cmd_destroy_tpg_type {
	/* In type */
	DESTROY_TPG_IN_MUE_MUE_NAME,
	DESTROY_TPG_IN_TPGN,
	DESTROY_TPG_IN_TA_DATA_TRANS_TYPE,
	DESTROY_TPG_IN_TA_DATA_TA_TYPE,
	DESTROY_TPG_IN_TA_DATA_JETTY_ID,
	DESTROY_TPG_IN_TA_DATA_TJETTY_ID,
	DESTROY_TPG_IN_TA_DATA_IS_TARGET,
	DESTROY_TPG_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DESTROY_TPG_OUT_DESTROYED_TP_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	DESTROY_TPG_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_opt_sip, in/out type should be continuous */
enum ubcore_cmd_opt_sip_type {
	/* In type */
	OPT_SIP_IN_INFO_DEV_NAME,
	OPT_SIP_IN_INFO_ADDR,
	OPT_SIP_IN_INFO_PREFIX_LEN,
	OPT_SIP_IN_INFO_PORT_CNT,
	OPT_SIP_IN_INFO_PORT_ID,
	OPT_SIP_IN_INFO_MTU,
	OPT_SIP_IN_INFO_NETDEV_NAME,
	OPT_SIP_IN_INFO_IS_ACTIVE,
	OPT_SIP_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	OPT_SIP_OUT_SIP_IDX = UBCORE_CMD_OUT_TYPE_INIT,
	OPT_SIP_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_map_vtp, in/out type should be continuous */
enum ubcore_cmd_map_vtp_type {
	/* In type */
	MAP_VTP_IN_MUE_NAME,
	MAP_VTP_IN_VTP_UE_IDX,
	MAP_VTP_IN_VTP_VTPN,
	MAP_VTP_IN_VTP_LOCAL_JETTY,
	MAP_VTP_IN_VTP_LOCAL_EID,
	MAP_VTP_IN_VTP_PEER_EID,
	MAP_VTP_IN_VTP_PEER_JETTY,
	MAP_VTP_IN_VTP_FLAG,
	MAP_VTP_IN_VTP_TRANS_MODE,
	MAP_VTP_IN_VTP_VALUE,
	MAP_VTP_IN_ROLE,
	MAP_VTP_IN_EID_IDX,
	MAP_VTP_IN_UPI,
	MAP_VTP_IN_SHARE_MODE,
	MAP_VTP_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	MAP_VTP_OUT_VTPN = UBCORE_CMD_OUT_TYPE_INIT,
	MAP_VTP_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_create_utp, in/out type should be continuous */
enum ubcore_cmd_create_utp_type {
	/* In type */
	CREATE_UTP_IN_MUE_NAME,
	CREATE_UTP_IN_UTP_CFG_FLAG,
	CREATE_UTP_IN_UTP_CFG_UDP_START,
	CREATE_UTP_IN_UTP_CFG_UDP_RANGE,
	CREATE_UTP_IN_UTP_CFG_LOCAL_NET_ADDR_IDX,
	CREATE_UTP_IN_UTP_CFG_LOCAL_NET_ADDR,
	CREATE_UTP_IN_UTP_CFG_PEER_NET_ADDR,
	CREATE_UTP_IN_UTP_CFG_FLOW_LABEL,
	CREATE_UTP_IN_UTP_CFG_DSCP,
	CREATE_UTP_IN_UTP_CFG_HOP_LIMIT,
	CREATE_UTP_IN_UTP_CFG_PORT_ID,
	CREATE_UTP_IN_UTP_CFG_MTU,
	CREATE_UTP_IN_VTP_UE_IDX,
	CREATE_UTP_IN_VTP_VTPN,
	CREATE_UTP_IN_VTP_LOCAL_JETTY,
	CREATE_UTP_IN_VTP_LOCAL_EID,
	CREATE_UTP_IN_VTP_PEER_EID,
	CREATE_UTP_IN_VTP_PEER_JETTY,
	CREATE_UTP_IN_VTP_FLAG,
	CREATE_UTP_IN_VTP_TRANS_MODE,
	CREATE_UTP_IN_VTP_VALUE,
	CREATE_UTP_IN_EID_IDX,
	CREATE_UTP_IN_UPI,
	CREATE_UTP_IN_SHARE_MODE,
	CREATE_UTP_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_UTP_OUT_IDX = UBCORE_CMD_OUT_TYPE_INIT,
	CREATE_UTP_OUT_VTPN,
	CREATE_UTP_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_destroy_utp */
enum ubcore_cmd_destroy_utp_type {
	/* In type */
	DESTROY_UTP_IN_MUE_NAME,
	DESTROY_UTP_IN_UTP_IDX,
	DESTROY_UTP_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_get_dev_feature, in/out type should be continuous */
enum ubcore_cmd_get_dev_feature_type {
	/* In type */
	GET_DEV_FEATURE_IN_DEV_NAME,
	GET_DEV_FEATURE_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_DEV_FEATURE_OUT_FEATURE = UBCORE_CMD_OUT_TYPE_INIT,
	GET_DEV_FEATURE_OUT_MAX_UEID_CNT,
	GET_DEV_FEATURE_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_restore_tp_error */
enum ubcore_cmd_restore_tp_error_type {
	/* In type */
	RESTORE_TP_ERROR_IN_MUE_MUE_NAME,
	RESTORE_TP_ERROR_IN_TPN,
	RESTORE_TP_ERROR_IN_DATA_UDP_START,
	RESTORE_TP_ERROR_IN_ACK_UDP_START,
	RESTORE_TP_ERROR_IN_RX_PSN,
	RESTORE_TP_ERROR_IN_TX_PSN,
	RESTORE_TP_ERROR_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_restore_tp_suspend */
enum ubcore_cmd_restore_tp_suspend_type {
	/* In type */
	RESTORE_TP_SUSPEND_IN_MUE_MUE_NAME,
	RESTORE_TP_SUSPEND_IN_TPGN,
	RESTORE_TP_SUSPEND_IN_TPN,
	RESTORE_TP_SUSPEND_IN_DATA_UDP_START,
	RESTORE_TP_SUSPEND_IN_ACK_UDP_START,
	RESTORE_TP_SUSPEND_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_change_tp_to_error */
enum ubcore_cmd_change_tp_to_error_type {
	/* In type */
	CHANGE_TP_TO_ERROR_IN_MUE_MUE_NAME,
	CHANGE_TP_TO_ERROR_IN_TPN,
	CHANGE_TP_TO_ERROR_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_set_upi */
enum ubcore_cmd_set_upi_type {
	/* In type */
	SET_UPI_IN_DEV_NAME,
	SET_UPI_IN_UPI,
	SET_UPI_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_show_upi, in/out type should be continuous */
enum ubcore_cmd_show_upi_type {
	/* In type */
	SHOW_UPI_IN_DEV_NAME,
	SHOW_UPI_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	SHOW_UPI_OUT_UPI = UBCORE_CMD_OUT_TYPE_INIT,
	SHOW_UPI_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_config_function_migrate_state, in/out type should be continuous */
enum ubcore_cmd_cfg_fm_state_type {
	/* In type */
	CFG_FM_STATE_IN_UE_IDX,
	CFG_FM_STATE_IN_MUE_NAME,
	CFG_FM_STATE_IN_UEID_CFG, /* struct ubcore_ueid_cfg is regarded as a whole */
	CFG_FM_STATE_IN_CFG_CNT,
	CFG_FM_STATE_IN_STATE,
	CFG_FM_STATE_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CFG_FM_STATE_OUT_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	CFG_FM_STATE_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_set_vport_cfg */
enum ubcore_cmd_set_vport_cfg_type {
	/* In type */
	SET_VPORT_CFG_IN_MASK,
	SET_VPORT_CFG_IN_DEV_NAME,
	SET_VPORT_CFG_IN_UE_IDX,
	SET_VPORT_CFG_IN_PATTERN,
	SET_VPORT_CFG_IN_VIRT,
	SET_VPORT_CFG_IN_MIN_JETTY_CNT,
	SET_VPORT_CFG_IN_MAX_JETTY_CNT,
	SET_VPORT_CFG_IN_MIN_JFR_CNT,
	SET_VPORT_CFG_IN_MAX_JFR_CNT,
	SET_VPORT_CFG_IN_TP_CNT,
	SET_VPORT_CFG_IN_SLICE,
	SET_VPORT_CFG_IN_UVS_NAME,
	SET_VPORT_CFG_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_modify_vtp */
enum ubcore_cmd_modify_vtp_type {
	/* In type */
	MODIFY_VTP_IN_MUE_NAME,
	MODIFY_VTP_IN_VTP_UE_IDX,
	MODIFY_VTP_IN_VTP_VTPN,
	MODIFY_VTP_IN_VTP_LOCAL_JETTY,
	MODIFY_VTP_IN_VTP_LOCAL_EID,
	MODIFY_VTP_IN_VTP_PEER_EID,
	MODIFY_VTP_IN_VTP_PEER_JETTY,
	MODIFY_VTP_IN_VTP_FLAG,
	MODIFY_VTP_IN_VTP_TRANS_MODE,
	MODIFY_VTP_IN_VTP_VALUE,
	MODIFY_VTP_IN_CFG_CNT,
	MODIFY_VTP_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_get_dev_info, in/out type should be continuous */
enum ubcore_cmd_get_dev_info_type {
	/* In type */
	GET_DEV_INFO_IN_TARGET_MUE_NAME,
	GET_DEV_INFO_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_DEV_INFO_OUT_MAX_MTU = UBCORE_CMD_OUT_TYPE_INIT,
	GET_DEV_INFO_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_create_ctp, in/out type should be continuous */
enum ubcore_cmd_create_ctp_type {
	/* In type */
	CREATE_CTP_IN_MUE_NAME,
	CREATE_CTP_IN_CTP_CFG_PEER_NET_ADDR,
	CREATE_CTP_IN_CTP_CFG_CNA_LEN,
	CREATE_CTP_IN_VTP_UE_IDX,
	CREATE_CTP_IN_VTP_VTPN,
	CREATE_CTP_IN_VTP_LOCAL_JETTY,
	CREATE_CTP_IN_VTP_LOCAL_EID,
	CREATE_CTP_IN_VTP_PEER_EID,
	CREATE_CTP_IN_VTP_PEER_JETTY,
	CREATE_CTP_IN_VTP_FLAG,
	CREATE_CTP_IN_VTP_TRANS_MODE,
	CREATE_CTP_IN_VTP_VALUE,
	CREATE_CTP_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_CTP_OUT_IDX = UBCORE_CMD_OUT_TYPE_INIT,
	CREATE_CTP_OUT_VTPN,
	CREATE_CTP_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_destroy_ctp, in/out type should be continuous */
enum ubcore_cmd_destroy_ctp_type {
	/* In type */
	DESTROY_CTP_IN_MUE_NAME,
	DESTROY_CTP_IN_CTP_IDX,
	DESTROY_CTP_IN_NUM, /* Only for calculating number of types */
};

/* See struct ubcore_cmd_change_tpg_to_error, in/out type should be continuous */
enum ubcore_cmd_change_tpg_to_error_type {
	/* In type */
	CHANGE_TPG_TO_ERROR_IN_TPGN,
	CHANGE_TPG_TO_ERROR_IN_MUE_MUE_NAME,
	CHANGE_TPG_TO_ERROR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CHANGE_TPG_TO_ERROR_OUT_TP_ERROR_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	CHANGE_TPG_TO_ERROR_OUT_CHANGE_TP_TO_ERR_FAIL_CNT,
	CHANGE_TPG_TO_ERROR_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_opt_eid */
enum ubcore_cmd_opt_eid_type {
	/* In type */
	OPT_EID_IN_DEV_NAME,
	OPT_EID_IN_UPI,
	OPT_EID_IN_UE_IDX,
	OPT_EID_IN_EID,
	OPT_EID_IN_EID_INDEX,
	OPT_EID_IN_UPDATE_EID_TBL,
	OPT_EID_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_opt_query_ue_idx, in/out type should be continuous */
enum ubcore_cmd_opt_query_ue_idx_type {
	/* In type */
	OPT_QUERY_UE_IDX_IN_DEV_NAME,
	OPT_QUERY_UE_IDX_IN_DEVID_RAW,
	OPT_QUERY_UE_IDX_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	OPT_QUERY_UE_IDX_OUT_UE_IDX = UBCORE_CMD_OUT_TYPE_INIT,
	OPT_QUERY_UE_IDX_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_opt_config_dscp_vl */
enum ubcore_cmd_opt_config_dscp_vl_type {
	/* In type */
	OPT_CONFIG_DSCP_VL_IN_DEV_NAME,
	OPT_CONFIG_DSCP_VL_IN_DSCP,
	OPT_CONFIG_DSCP_VL_IN_VL,
	OPT_CONFIG_DSCP_VL_IN_NUM_VALUE,
	OPT_CONFIG_DSCP_VL_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_map_target_vtp */
enum ubcore_cmd_map_target_vtp_type {
	/* In type */
	MAP_TARGET_VTP_IN_MUE_NAME,
	MAP_TARGET_VTP_IN_VTP_UE_IDX,
	MAP_TARGET_VTP_IN_VTP_VTPN,
	MAP_TARGET_VTP_IN_VTP_LOCAL_JETTY,
	MAP_TARGET_VTP_IN_VTP_LOCAL_EID,
	MAP_TARGET_VTP_IN_VTP_PEER_EID,
	MAP_TARGET_VTP_IN_VTP_PEER_JETTY,
	MAP_TARGET_VTP_IN_VTP_FLAG,
	MAP_TARGET_VTP_IN_VTP_TRANS_MODE,
	MAP_TARGET_VTP_IN_VTP_VALUE,
	MAP_TARGET_VTP_IN_ROLE,
	MAP_TARGET_VTP_IN_EID_IDX,
	MAP_TARGET_VTP_IN_UPI,
	MAP_TARGET_VTP_IN_SHARE_MODE,
	MAP_TARGET_VTP_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_list_migrate_entry, in/out type should be continuous */
enum ubcore_cmd_list_migrate_entry_type {
	/* In type */
	LIST_MIG_ENTRY_IN_MUE_NAME,
	LIST_MIG_ENTRY_IN_CNT,
	LIST_MIG_ENTRY_IN_UE_IDX_LIST,
	LIST_MIG_ENTRY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	LIST_MIG_ENTRY_OUT_STATS_LIST = UBCORE_CMD_OUT_TYPE_INIT,
	LIST_MIG_ENTRY_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_opt_query_dscp_vl, in/out type should be continuous */
enum ubcore_cmd_opt_query_dscp_vl_type {
	/* In type */
	OPT_QUERY_DSCP_VL_IN_DEV_NAME,
	OPT_QUERY_DSCP_VL_IN_DSCP,
	OPT_QUERY_DSCP_VL_IN_NUM_VALUE,
	OPT_QUERY_DSCP_VL_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	OPT_QUERY_DSCP_VL_OUT_VL = UBCORE_CMD_OUT_TYPE_INIT,
	OPT_QUERY_DSCP_VL_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_opt_dfx_query_stats, in/out type should be continuous */
enum ubcore_cmd_opt_dfx_query_stats_type {
	/* In type */
	OPT_DFX_QUERY_STATS_IN_DEV_NAME,
	OPT_DFX_QUERY_STATS_IN_TYPE,
	OPT_DFX_QUERY_STATS_IN_ID,
	OPT_DFX_QUERY_STATS_IN_EXT,
	OPT_DFX_QUERY_STATS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	OPT_DFX_QUERY_STATS_OUT_TX_PKT = UBCORE_CMD_OUT_TYPE_INIT,
	OPT_DFX_QUERY_STATS_OUT_RX_PKT,
	OPT_DFX_QUERY_STATS_OUT_TX_BYTES,
	OPT_DFX_QUERY_STATS_OUT_RX_BYTES,
	OPT_DFX_QUERY_STATS_OUT_TX_PKT_ERR,
	OPT_DFX_QUERY_STATS_OUT_RX_PKT_ERR,
	OPT_DFX_QUERY_STATS_OUT_TX_TIMEOUT_CNT,
	OPT_DFX_QUERY_STATS_OUT_RX_CE_PKT,
	OPT_DFX_QUERY_STATS_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_opt_dfx_query_res, in/out type should be continuous */
enum ubcore_cmd_opt_dfx_query_res_type {
	/* In type */
	DFX_QUERY_RES_IN_DEV_NAME,
	DFX_QUERY_RES_IN_TYPE,
	DFX_QUERY_RES_IN_KEY,
	DFX_QUERY_RES_IN_KEY_EXT,
	DFX_QUERY_RES_IN_KEY_CNT,
	DFX_QUERY_RES_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	/* vtp, see struct ubcore_res_vtp_val */
	DFX_QUERY_RES_OUT_VTP_UE_IDX = UBCORE_CMD_OUT_TYPE_INIT,
	DFX_QUERY_RES_OUT_VTP_VTPN,
	DFX_QUERY_RES_OUT_VTP_LOCAL_EID,
	DFX_QUERY_RES_OUT_VTP_LOCAL_JETTY,
	DFX_QUERY_RES_OUT_VTP_PEER_EID,
	DFX_QUERY_RES_OUT_VTP_PEER_JETTY,
	DFX_QUERY_RES_OUT_VTP_FLAG,
	DFX_QUERY_RES_OUT_VTP_TRANS_MODE,
	DFX_QUERY_RES_OUT_VTP_TPGN,
	/* tp, see struct ubcore_res_tp_val */
	DFX_QUERY_RES_OUT_TP_TPN,
	DFX_QUERY_RES_OUT_TP_TX_PSN,
	DFX_QUERY_RES_OUT_TP_RX_PSN,
	DFX_QUERY_RES_OUT_TP_DSCP,
	DFX_QUERY_RES_OUT_TP_OOR_EN,
	DFX_QUERY_RES_OUT_TP_SEL_RET_EN,
	DFX_QUERY_RES_OUT_TP_STATE,
	DFX_QUERY_RES_OUT_TP_DATA_UDP_START,
	DFX_QUERY_RES_OUT_TP_ACK_UDP_START,
	DFX_QUERY_RES_OUT_TP_UDP_RANGE,
	DFX_QUERY_RES_OUT_TP_SPRAY_EN,
	/* tpg, see struct ubcore_res_dfx_tpg_info */
	DFX_QUERY_RES_OUT_TPG_TP_CNT,
	DFX_QUERY_RES_OUT_TPG_DSCP,
	DFX_QUERY_RES_OUT_TPG_TP_STATE,
	DFX_QUERY_RES_OUT_TPG_TPN,
	/* utp, see struct ubcore_res_utp_val */
	DFX_QUERY_RES_OUT_UTP_UTPN,
	DFX_QUERY_RES_OUT_UTP_DATA_UDP_START,
	DFX_QUERY_RES_OUT_UTP_UDP_RANGE,
	DFX_QUERY_RES_OUT_UTP_FLAG,
	/* mue, see struct ubcore_res_dev_tp_val */
	DFX_QUERY_RES_OUT_MUE_VTP_CNT,
	DFX_QUERY_RES_OUT_MUE_TP_CNT,
	DFX_QUERY_RES_OUT_MUE_TPG_CNT,
	DFX_QUERY_RES_OUT_MUE_UTP_CNT,
	DFX_QUERY_RES_OUT_VPORT_EID_USE_CNT,
	DFX_QUERY_RES_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_discover_dmac, in/out type should be continuous */
enum ubcore_cmd_discover_dmac_type {
	/* In type */
	DISCOVER_DMAC_IN_SIP,
	DISCOVER_DMAC_IN_DIP,
	DISCOVER_DMAC_IN_MUE_NAME,
	DISCOVER_DMAC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DISCOVER_DMAC_OUT_DMAC = UBCORE_CMD_OUT_TYPE_INIT,
	DISCOVER_DMAC_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_clear_vice_tpg */
enum ubcore_cmd_clear_vice_tpg_type {
	/* In type */
	CLEAR_VICE_TPG_IN_MUE_NAME,
	CLEAR_VICE_TPG_IN_LOCATION,
	CLEAR_VICE_TPG_IN_LOCAL_EID,
	CLEAR_VICE_TPG_IN_PEER_EID,
	CLEAR_VICE_TPG_IN_TPGN,
	CLEAR_VICE_TPG_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_user_ctl_arg. Note: all of in/out parameters should be copied from user */
/* So they are IN type */
enum ubcore_cmd_user_ctl_type {
	/* In type */
	USER_CTL_IN_MUE_NAME,
	USER_CTL_IN_ADDR,
	USER_CTL_IN_LEN,
	USER_CTL_IN_OPCODE,
	USER_CTL_OUT_ADDR,
	USER_CTL_OUT_LEN,
	/* No need to handle rsv */
	USER_CTL_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_register_uvs_info */
enum ubcore_cmd_register_uvs_info_type {
	/* In type */
	REGISTER_UVS_INFO_IN_UVS_NAME,
	REGISTER_UVS_INFO_IN_UVS_POLICY,
	REGISTER_UVS_INFO_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_unregister_uvs_info */
enum ubcore_cmd_unregister_uvs_info_type {
	/* In type */
	UNREGISTER_UVS_INFO_IN_UVS_NAME,
	UNREGISTER_UVS_INFO_IN_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_get_vtp_table_cnt */
enum ubcore_cmd_get_vtp_table_cnt_type {
	/* Out type */
	GET_VTP_TABLE_CNT_OUT_VTP_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	GET_VTP_TABLE_CNT_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_restored_vtp_entry, in/out type should be continuous */
enum ubcore_cmd_restored_vtp_entry_type {
	/* In type */
	RESTORE_VTP_IN_VTP_CNT,
	RESTORE_VTP_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	RESTORE_VTP_OUT_VTP_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	RESTORE_VTP_OUT_ENTRY,
	RESTORE_VTP_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_get_tpg_table_cnt */
enum ubcore_cmd_get_tpg_table_cnt_type {
	/* Out type */
	GET_TPG_TABLE_CNT_OUT_TPG_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	GET_TPG_TABLE_CNT_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_restored_tpg_entry, in/out type should be continuous */
enum ubcore_cmd_restored_tpg_entry_type {
	/* In type */
	RESTORE_TPG_IN_TPG_CNT,
	RESTORE_TPG_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	RESTORE_TPG_OUT_TPG_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	RESTORE_TPG_OUT_ENTRY,
	RESTORE_TPG_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_get_ue_table_cnt */
enum ubcore_cmd_get_ue_table_cnt_type {
	/* Out type */
	GET_UE_TABLE_CNT_OUT_UE_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	GET_UE_TABLE_CNT_OUT_NUM /* Only for calculating number of types */
};

/* See struct ubcore_cmd_restored_ue_entry, in/out type should be continuous */
enum ubcore_cmd_restored_ue_entry_type {
	/* In type */
	RESTORE_UE_IN_UE_CNT,
	RESTORE_UE_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	RESTORE_UE_OUT_ENTRY = UBCORE_CMD_OUT_TYPE_INIT,
	RESTORE_UE_OUT_NUM /* Only for calculating number of types */
};

enum ubcore_cmd_list_mue_type {
	/* In type */
	LIST_MUE_IN_NUM, /* Only for calculating number of types */

	/* Out type */
	LIST_MUE_OUT_MUE_CNT = UBCORE_CMD_OUT_TYPE_INIT,
	LIST_MUE_OUT_MUE_NAME,
	LIST_MUE_OUT_NETDEV_NAME,
	LIST_MUE_OUT_NUM /* Only for calculating number of types */
};

enum ubcore_cmd_set_topo_type {
	/* In type */
	SET_TOPO_IN_TOPO_INFO,
	SET_TOPO_IN_TOPO_NUM,
	SET_TOPO_IN_NUM /* Only for calculating number of types */
};

enum ubcore_cmd_get_topo_type {
	/* Out type */
	GET_TOPO_OUT_TOPO_MAP,
	GET_TOPO_OUT_NUM /* Only for calculating number of types */
};

enum ubcore_get_route_list_type {
	GET_ROUTE_LIST_IN_ROUTE_PAIR,
	GET_ROUTE_LIST_IN_NUM,

	GET_ROUTE_LIST_OUT_ROUTE_LIST = UBCORE_CMD_OUT_TYPE_INIT,
	GET_ROUTE_LIST_OUT_NUM,
};

enum ubcore_get_path_set_type {
	GET_PATH_SET_IN_SRC_BONDING_EID,
	GET_PATH_SET_IN_DST_BONDING_EID,
	GET_PATH_SET_IN_TP_TYPE,
	GET_PATH_SET_IN_MULTI_PATH,
	GET_PATH_SET_IN_NUM,

	GET_PATH_SET_OUT_PATH_SET = UBCORE_CMD_OUT_TYPE_INIT,
	GET_PATH_SET_OUT_NUM,
};

int ubcore_mue_tlv_parse(struct ubcore_cmd_hdr *hdr, void *arg);
int ubcore_mue_tlv_append(struct ubcore_cmd_hdr *hdr, void *arg);
int ubcore_global_tlv_parse(struct ubcore_cmd_hdr *hdr, void *arg);
int ubcore_global_tlv_append(struct ubcore_cmd_hdr *hdr, void *arg);

int ubcore_mue_tlv_parse_post(struct ubcore_cmd_hdr *hdr, void *arg);

#endif
