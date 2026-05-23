/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_pub_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef NIC_PUB_CMD_H
#define NIC_PUB_CMD_H

#include "hinic5_mt.h"

/* Queue information related */

/**
 * @brief struct hinic5_tx_hw_page
 * @details Structure for storing hardware page information
 */
struct hinic5_tx_hw_page {
	u64 phy_addr;       /* Physical address */
	u64 *map_addr;      /* Mapped address */
};

enum hinic5_show_set {
	HINIC5_SHOW_SSET_IO_STATS = 1,
};

#define HINIC5_SHOW_ITEM_LEN 32
/**
 * @brief struct hinic5_show_item
 * @details Structure for display items
 */
struct hinic5_show_item {
	char name[HINIC5_SHOW_ITEM_LEN];	/* Item name */
	u8 hexadecimal;	/* Value display mode, 0 for decimal, 1 for hexadecimal */
	u8 rsvd[7];	/* Reserved field */
	u64 value;	/* Item value */
};

/**
 * @brief struct wqe_info
 * @details Structure for storing work queue related information
 */
struct wqe_info {
	int q_id;               /* Queue ID */
	void *slq_handle;       /* Queue handle */
	unsigned int wqe_id;    /* Work queue element ID */
};

/**
 * @brief struct nic_sq_info
 * @details Structure for storing network interface send queue information
 */
struct nic_sq_info {
	u16 q_id;           /* Queue ID */
	u16 pi;             /* Producer index */
	u16 ci;             /* Consumer index */
	u16 fi;             /* Hardware consumer index */
	u32 q_depth;        /* Queue depth */
	u16 pi_reverse;     /* Reverse producer index */
	u16 wqebb_size;     /* Work queue element size */
	u8 priority;        /* Priority */
	u64 ci_wqe_page_addr;   /* SQ WQ first page address */
	u64 cla_addr;       /* WQ block address */
	void *slq_handle;   /* Send queue handle */
	struct hinic5_tx_hw_page direct_wqe;    /* Direct work queue element */
	struct hinic5_tx_hw_page doorbell;      /* Doorbell */
	u32 page_idx;       /* Page index */
	u32 glb_sq_id;      /* Global send queue ID */
};

/**
 * @brief struct nic_rq_info
 * @details Structure for storing network interface receive queue information
 */
struct nic_rq_info {
	u16 q_id;       /* Queue ID */
	u16 delta;      /* Delta */
	u16 hw_ci;
	u16 ci;         /* Consumer index */
	u16 sw_pi;      /* Software producer index */
	u16 wqebb_size; /* Work queue element size */
	u16 q_depth;    /* Queue depth */
	u16 buf_len;    /* Buffer length */

	void *slq_handle;       /* Receive queue handle */
	u64 ci_wqe_page_addr;   /* Consumer index work queue element page address */
	u64 ci_cla_tbl_addr;    /* Consumer index cache line aligned table address */

	u8 coalesc_timer_cfg;   /* Interrupt timeout, unit 5us */
	u8 pending_limt;        /* Interrupt aggregation count, unit 8pkt */
	u16 msix_idx;           /* MSI-X index */
	u32 msix_vector;        /* MSI-X vector */
};

/* QOS related */

#define MT_DCB_OPCODE_WR   BIT(0)  /* 1 - write, 0 - read */

/**
 * @brief struct hinic5_mt_dcb_state
 * @details Structure for storing multi-task data center bridge (DCB) state information
 */
struct hinic5_mt_dcb_state {
	struct mt_msg_head head;    /* Message head */

	u16 op_code; /* Operation code 0 - get dcb state, 1 - set dcb state */
	u8 state;    /* State 0 - disable,       1 - enable dcb  */
	u8 rsvd;     /* Reserved field */
};

#define CMD_QOS_DEV_TRUST     BIT(0)
#define CMD_QOS_DEV_DFT_COS   BIT(1)
#define CMD_QOS_DEV_PCP2COS   BIT(2)
#define CMD_QOS_DEV_DSCP2COS  BIT(3)

/**
 * @brief struct hinic5_mt_qos_dev_cfg
 * @details Structure for configuring QoS device
 */
struct hinic5_mt_qos_dev_cfg {
	struct mt_msg_head head;    /* Message head */

	u8 op_code;       /* 0: get 1: set */
	u8 rsvd0;
	u16 cfg_bitmap;   /* bit0 - trust, bit1 - dft_cos,
			   * bit2 - pcp2cos, bit3 - dscp2cos
			   */

	u8 trust;         /* 0 - pcp, 1 - dscp */
	u8 dft_cos;
	u16 rsvd1;
	u8 pcp2cos[8];    /* Must configure all 8 together */
	u8 dscp2cos[64];  /* When configuring dscp2cos, if cos value is set to 0xFF,
			   * the driver will ignore this dscp priority configuration,
			   * allowing multiple dscp to cos mappings to be configured at once
			   */
	u32 rsvd2[4];
};

/**
 * @brief struct hinic5_mt_qos_cos_cfg
 * @details Structure for configuring HINIC5 multi-queue QoS class settings
 */
struct hinic5_mt_qos_cos_cfg {
	struct mt_msg_head head; /* Message head, contains message type and length information */

	u8 port_id; /* Port ID, used to identify the port to which the message belongs */
	u8 func_cos_bitmap; /* Function class bitmap, used to identify enabled status of each function class */
	u8 port_cos_bitmap; /* Port class bitmap, used to identify enabled status of each port class */
	u8 func_max_cos_num; /* Maximum number of function classes, used to limit the number of function classes */
	u32 rsvd2[4];
};

enum nic_driver_cmd_type {
	NIC_TOOL_CMD_START = 0x120, /* New platform command codes start from 0x120,
				     * old command codes are uniformly defined in @driver_cmd_type
				     */

	/* MACsec tool command set */
	MACSEC_TOOL_OP_LIST = 0x120, /* Get all macsec configuration information from driver memory */
	MACSEC_TOOL_OP_DUMP,         /* Get all macsec configuration information from chip */
	MACSEC_TOOL_OP_MIB,          /* Get SC MIB information or PORT MIB information from chip */
	MACSEC_TOOL_OP_ADD,          /* Add SC or SA configuration */
	MACSEC_TOOL_OP_DEL,          /* Delete SC or SA configuration */
	MACSEC_TOOL_OP_SET,          /* Modify SC configuration */
	MACSEC_TOOL_OP_FLUSH,        /* Clear macsec configuration managed by a device */
	MACSEC_TOOL_OP_MAX = 0x12F,

	NIC_CMD_EXTEND_RSV_START = 0x200,
	/* NIC tool reserved command codes, products use command codes in this range */
	NIC_CMD_EXTEND_RSV_END = 0x2FF,
};

#endif /* NIC_PUB_CMD_H */
