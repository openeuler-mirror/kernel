/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
/* @zpzheng */

#include "nsevf_adminq_cmd.h"
#include "nsevf.h"
#include "nsevf_alloc.h"
#include "nsevf_prototype.h"

#define NSEVF_FDIR_CTL_FILTER_MODE_SIGNATURE 0x0
#define NSEVF_FDIR_CTL_FILTER_MODE_PERFECT 0x1

#define NSEVF_FDIR_FLEX_CFG_BASE_L2_HDR 0x0
#define NSEVF_FDIR_FLEX_CFG_BASE_L3_HDR 0x1
#define NSEVF_FDIR_FLEX_CFG_BASE_L4_HDR 0x2
#define NSEVF_FDIR_FLEX_CFG_BASE_L4_PAYLOAD 0x3

/* nsevf_fdir_utilq_config_payload */
/* port */
#define NSEVF_FDIR_PORT_DPORT_S 16
#define NSEVF_FDIR_PORT_DPORT_M NSE_M(0xFFFF, 16)

#define NSEVF_FDIR_PORT_SPORT_S 0
#define NSEVF_FDIR_PORT_SPORT_M NSE_M(0xFFFF, 0)

/* flex */
#define NSEVF_FDIR_FLEX_FLEX_DATA_S 16
#define NSEVF_FDIR_FLEX_FLEX_DATA_M NSE_M(0xFFFF, 16)

#define NSEVF_FDIR_FLEX_VSI_S 8
#define NSEVF_FDIR_FLEX_VSI_M NSE_M(0xFF, 8)

#define NSEVF_FDIR_FLEX_PTYPE_S 0
#define NSEVF_FDIR_FLEX_PTYPE_M NSE_M(0xFF, 0)

/* hash */
#define NSEVF_FDIR_HASH_SW_IDX_S 16
#define NSEVF_FDIR_HASH_SW_IDX_M NSE_M(0xFFFF, 16)

#define NSEVF_FDIR_HASH_SIG_HASH_S 16
#define NSEVF_FDIR_HASH_SIG_HASH_M NSE_M(0x1FFF, 16)

#define NSEVF_FDIR_HASH_SIG_PF_S 29
#define NSEVF_FDIR_HASH_SIG_PF_M NSE_M(0x3, 29)

#define NSEVF_FDIR_HASH_VLD_S 15
#define NSEVF_FDIR_HASH_VLD_M BIT(15)

#define NSEVF_FDIR_HASH_BUCKET_HASH_S 0
#define NSEVF_FDIR_HASH_BUCKET_HASH_M NSE_M(0x7FFF, 0)

/* cmd */
#define NSEVF_FDIR_CMD_FLAG_S 31
#define NSEVF_FDIR_CMD_FLAG_M BIT(31)

#define NSEVF_FDIR_CMD_FLAG_QUEUE 0x0
#define NSEVF_FDIR_CMD_FLAG_ACTION 0x1

#define NSEVF_FDIR_CMD_QUEUE_ACTION_S 16
#define NSEVF_FDIR_CMD_QUEUE_ACTION_M NSE_M(0x7FFF, 16)

#define NSEVF_FDIR_CMD_QUEUE_EN_S 15
#define NSEVF_FDIR_CMD_QUEUE_EN_M BIT(15)

#define NSEVF_FDIR_CMD_COLLISION_S 12
#define NSEVF_FDIR_CMD_COLLISION_M BIT(12)

#define NSEVF_FDIR_CMD_LAST_S 11
#define NSEVF_FDIR_CMD_LAST_M BIT(11)

#define NSEVF_FDIR_CMD_INT_S 10
#define NSEVF_FDIR_CMD_INT_M BIT(10)

#define NSEVF_FDIR_CMD_DROP_S 9
#define NSEVF_FDIR_CMD_DROP_M BIT(9)

#define NSEVF_FDIR_CMD_CLEARHT_S 8
#define NSEVF_FDIR_CMD_CLEARHT_M BIT(8)

#define NSEVF_FDIR_CMD_RM_VSI_ALL_S 4
#define NSEVF_FDIR_CMD_RM_VSI_ALL_M BIT(4)

#define NSEVF_FDIR_CMD_UPDATE_S 3
#define NSEVF_FDIR_CMD_UPDATE_M BIT(3)

#define NSEVF_FDIR_CMD_VLD_S 2
#define NSEVF_FDIR_CMD_VLD_M BIT(2)

#define NSEVF_FDIR_CMD_OP_S 0
#define NSEVF_FDIR_CMD_OP_M NSE_M(0x3, 0)

#define NSEVF_FDIR_CMD_OP_NONE 0x0
#define NSEVF_FDIR_CMD_OP_ADD 0x1
#define NSEVF_FDIR_CMD_OP_REMOVE 0x2
#define NSEVF_FDIR_CMD_OP_QUERY 0x3

/* aqc */
#define NSEVF_AQ_OPC_CATEGORY_RCF 0x7

#define NSEVF_AQ_OPC_FDIR_CONF_FILTER_BY_UTILQ 0x1A

/* special ID, indicates: to AQM utilQ, then to RPP RCF */
#define NSEVF_AQ_MAILBOX_ID_UTILQ 0x1FE

int nsevf_add_ethtool_ntuple(struct nsevf_adapter *adapter,
			     struct ethtool_rxnfc *cmd);
int nsevf_del_ethtool_ntuple(struct nsevf_adapter *adapter,
			     struct ethtool_rxnfc *cmd);
int nsevf_get_ethtool_ntuple(struct nsevf_adapter *adapter,
			     struct ethtool_rxnfc *cmd);
int nsevf_get_ethtool_ntuple_ids(struct nsevf_adapter *adapter,
				 struct ethtool_rxnfc *cmd, u32 *rule_locs);

void nsevf_del_ethool_ntuple_all(struct nsevf_adapter *adapter, bool in_reset);

void nsevf_fdir_dump_cb(struct nsevf_adapter *adapter);

void nsevf_fdir_pre_init(struct nsevf_adapter *adapter);
void nsevf_fdir_init(struct nsevf_adapter *adapter);
void nsevf_fdir_deinit(struct nsevf_adapter *adapter, bool in_reset);

void nsevf_fdir_rebuild(struct nsevf_adapter *adapter);
