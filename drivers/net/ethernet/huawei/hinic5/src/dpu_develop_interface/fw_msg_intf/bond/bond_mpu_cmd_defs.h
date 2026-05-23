/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : bond_mpu_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Driver and mpu interaction bond related definitions
 */

#ifndef BOND_MPU_CMD_DEFS_H
#define BOND_MPU_CMD_DEFS_H

#include "mpu_cmd_base_defs.h"
#include "bond_common_defs.h"

/**
 * @brief enum bond_mpu_cmd
 * @details Inherited bond cmd enumeration type used in version 23, mbox message and OVS binding, see enum tag_ovs_mpu_cmd
 */
enum bond_mpu_cmd {
	MPU_CMD_BOND_CREATE = 17,	/* Create bond, temporarily keep it to 17
					 * @see struct tag_ovs_bond_cmd
					 */
	MPU_CMD_BOND_DELETE = 18,	/**< Delete bond @see struct tag_ovs_bond_cmd */
	MPU_CMD_BOND_SET_ATTR = 19,	/**< Set bond attributes @see struct tag_ovs_bond_cmd */
	MPU_CMD_BOND_GET_ATTR = 20,	/**< Get bond attributes, @see struct tag_bond_get */
};

/**
 * bond set attr: Variables before bond_name must be consistent with struct bond_attr definition
 */
typedef struct tag_ovs_bond_cmd {
	u16 bond_mode;			/* bond mode:1 for active-backup,
					 * 2 for balance-xor,4 for 802.3ad
					 */
	u16 bond_id;			/**< bond id */
	u16 up_delay;			/**< default:200ms */
	u16 down_delay;			/**< default:200ms */
	u32 active_slaves        : 8;	/**< active port slaves(bitmaps) */
	u32 slaves               : 8;	/**< bond port id bitmaps */
	u32 lacp_collect_slaves  : 8;	/**< bond port id bitmaps */
	u32 xmit_hash_policy     : 8;	/* xmit hash:0 for layer 2 ,
					 * 1 for layer 2+3 ,2 for layer 3+4
					 */
	u32 first_roce_func;		/**< RoCE used */
	u32 bond_pf_bitmap;		/**< all PFs under the bond */
	u32 user_bitmap;
	u8  bond_name[BOND_NAME_MAX_LEN];	/**< bond name, length must be less than 16 */
} ovs_bond_cmd_s;

/**
 * Create/Delete bond and set attribute command struct defination.
 */
struct hinic5_bond_cmd {
	struct mgmt_msg_head comm_head;
	u16 sub_cmd;
	u16 rsvd;
	ovs_bond_cmd_s attr;
};

/**
 * bond per port statistics
 */
#pragma pack(4)
typedef struct tag_bond_port_stat {
	/** mpu provide */
	u64 rx_pkts;
	u64 rx_bytes;
	u64 rx_drops;
	u64 rx_errors;

	u64 tx_pkts;
	u64 tx_bytes;
	u64 tx_drops;
	u64 tx_errors;
} hinic5_bond_port_stat_s;
#pragma pack()

/**
 * bond port attribute
 */
typedef struct tag_bond_port_attr {
	u8 duplex;
	u8 status;
	u8 rsvd0[2];
	u32 speed;
} hinic5_bond_port_attr_s;

/**
 * Get bond information command struct defination
 * @see OVS_MPU_CMD_BOND_GET_ATTR
 */
typedef struct tag_bond_get {
	u16 bond_id_vld;	/* bond_id_vld=1: used bond_id get bond info;
				 * bond_id_vld=0: used bond_name get bond info
				 */
	u16 bond_id;		/**< if bond_id_vld=1 input, else output */
	u8  bond_name[BOND_NAME_MAX_LEN];	/**< if bond_id_vld=0 input, else output */

	u16 bond_mode;		/* bond mode:1 for active-backup,
				 * 2 for balance-xor,4 for 802.3ad
				 */
	u8  active_slaves;	/**< active port slaves(bitmaps) */
	u8  slaves;		/**< bond port id bitmaps */

	u8  lacp_collect_slaves; /**< bond port id bitmaps */
	u8  xmit_hash_policy;    /**< xmit hash:0 for layer 2 ,1 for layer 2+3 ,2 for layer 3+4 */
	u16 rsvd0;               /**< in order to 4B aligned */

	hinic5_bond_port_stat_s stat[BOND_PORT_MAX_NUM];
	hinic5_bond_port_attr_s attr[BOND_PORT_MAX_NUM];
} hinic5_bond_get_s;

/* BOND OPCODE operation type definition */
#define BOND_CFG_OPCODE_GET 0x0
#define BOND_CFG_OPCODE_SET 0x1

/* BOND configuration BITMAP definition */
#define BOND_CFG_BITMAP_ARP_EN 0x1UL

#endif