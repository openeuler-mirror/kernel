/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : bond_cfm_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : cfm bond data structure
 */

#ifndef BOND_CFM_CMD_H
#define BOND_CFM_CMD_H

#include "bond_mpu_cmd_defs.h"
#include "nic_mpu_cmd_structs.h"

#define ETH_ALEN 6     /* Ethernet address length */

#define BOND_MAX_PORT_NUM 4     /* Maximum number of ports supported by bond */
#define BOND_MAX_HOST_NUM 4     /* Maximum number of hosts supported by bond */

/**
 * @brief enum bond_mpu_type
 * @details bonding type, full offload bond or half offload bond
 */
enum bond_mpu_type {
	BOND_TYPE_HALF,
	BOND_TYPE_FULL,
	BOND_TYPE_BUTT
};

struct bond_half_data_s {
	u16 bond_mode;                /* bond mode:1 for active-backup,
				       * 2 for balance-xor,4 for 802.3ad
				       */
	u16 bond_id;                  /* bond id */
	u16 up_delay;                 /* default:200ms */
	u16 down_delay;               /* default:200ms */
	u32 active_slaves        : 8; /* active port slaves(bitmaps) */
	u32 slaves               : 8; /* bond port id bitmaps */
	u32 lacp_collect_slaves  : 8; /* slave bitmap available for LACP packet send/receive */
	u32 hash_policy          : 8; /* hash:0 for layer 2 ,1 for layer 2+3 ,2 for layer 3+4 */
	u32 first_roce_func;          /* RoCE used */
	u32 bond_pf_bitmap;           /* slave pf bitmap */
	u32 user_bitmap;              /* user bitmap */
	u8  bond_name[BOND_NAME_MAX_LEN];   /* bond name, length must be less than 16 */
	u32 rsvd[8];
};

struct bond_full_data_s {
	u32 bond_id;     /* bond device number, valid on output, filled when mpu operation succeeds */
	u32 master_slave_port_id;     /* master/slave port id, smallest port id as master port */
	u32 slave_bitmap;     /* bond port id bitmap */
	u32 poll_timeout;     /* bond device link check time */
	u32 up_delay;     /* reserved for now */
	u32 down_delay;     /* reserved for now */
	u32 bond_mode;     /* reserved for now */
	u32 xmit_hash_policy;     /* hash policy, used for microcode routing logic */
	u8  lacp_rate;            /* lacp negotiation rate, 0 for slow, 1 for fast */
	u8 rsvd1[3];      /* reserved field */
	u32 rsvd[9];     /* reserved field */
};

typedef union tag_cfm_bond_data {
	struct bond_half_data_s bond_half_data;
	struct bond_full_data_s bond_full_data;
} cfm_bond_data_u;

typedef struct tag_cfm_bond_cmd {
	struct mgmt_msg_head comm_head;
	u16 sub_cmd;
	u8  rsvd0;
	u8  bond_type;
	cfm_bond_data_u data;
	u8 rsvd1[32];
} cfm_bond_cmd_s;

/**
 * @brief Defines a structure for storing bond status information
 * @details This structure contains various information about bond status,
 * such as bond_id, link status, slave port status, port count, etc.,
 * and also contains lacp information for each port,
 * as well as the number of times each host successfully and failed to report lacp negotiation results.
 */
typedef struct tag_bond_full_get {
	u32 bond_id;     /* bond id */
	u32 bon_mmi_status;     /* link status of this bond sub-device */
	u32 active_bitmap;     /* slave port status of this bond sub-device */
	u32 port_count;     /* number of this bond sub-device */
	struct lacp_port_info port_info[BOND_MAX_PORT_NUM];/* lacp information for each port */
	u64 success_report_cnt[BOND_MAX_HOST_NUM];/* number of times each host successfully reported lacp negotiation result */
	u64 fail_report_cnt[BOND_MAX_HOST_NUM]; /* number of times each host failed to report lacp negotiation result */
	u64 poll_timeout;     /* poll timeout */
	u64 fast_periodic_timeout;     /* fast periodic timeout */
	u64 slow_periodic_timeout;     /* slow periodic timeout */
	u64 short_timeout;     /* short timeout */
	u64 long_timeout;     /* long timeout */
	u64 aggregate_wait_timeout;     /* aggregate wait timeout */
	u64 tx_period_timeout;     /* tx period timeout */
	u64 rx_marker_timer;     /* RX marker timer */
	u8 bond_mode;     /* bond mode */
	u8 arp_dual_en;     /* arp dual send enable flag */
	u8 rsvd[6];     /* reserved field */
} bond_full_get_s;

typedef union tag_cfm_bond_get_s {
	hinic5_bond_get_s bond_half_data;
	bond_full_get_s bond_full_data;
} cfm_bond_get_u;

typedef struct tag_cfm_bond_info_get {
	struct mgmt_msg_head comm_head;
	u16 sub_cmd;
	u8  rsvd0;
	u8  bond_type;
	cfm_bond_get_u data;
} cfm_bond_info_get_s;

/* bond configuration information structure */
typedef struct tag_cfm_bond_cfg_cmd {
	struct mgmt_msg_head head;        /* message header */
	u32 cfg_bitmap;                   /* bond cfg bitmap */
	u8  bond_name[BOND_NAME_MAX_LEN]; /* if bond_id_vld=0 input, else output */
	u8  op_code;                      /* operation type: 0: query GET, 1: configure SET */
	u8  arp_en;                       /* ARP dual send enable */
	u8  rsvd0[2];                     /* reserved field */
	u32 rsvd1[58];                    /* reserved field */
} cfm_bond_cfg_cmd_s;

/**
 * @brief Defines the information required to create a bond device
 * @details This structure contains various parameters required to create a bond device,
 * such as bond device number, master/slave port id, bond port id bitmap, etc.
 */
struct hinic5_create_bond_info {
	u32 bond_id;     /* bond device number, valid on output, filled when mpu operation succeeds */
	u32 master_slave_port_id;     /* master/slave port id, smallest port id as master port */
	u32 slave_bitmap;     /* bond port id bitmap */
	u32 poll_timeout;     /* bond device link check time */
	u32 up_delay;     /* reserved for now */
	u32 down_delay;     /* reserved for now */
	u32 bond_mode;     /* reserved for now */
	u32 xmit_hash_policy;     /* hash policy, used for microcode routing logic */
	u8  lacp_rate;            /* lacp negotiation rate, 0 for slow, 1 for fast */
	u8 rsvd1[3];      /* reserved field */
	u32 rsvd[1];     /* reserved field */
};

/**
 * @brief Message interface structure for creating bond
 * @details This structure is used for the message interface to create bond
 */
struct hinic5_cmd_create_bond {
	struct hinic5_mgmt_msg_head head;     /* command message header */
	struct hinic5_create_bond_info create_bond_info;     /* information for creating bond */
};

#endif /* BOND_CFM_CMD_H */
