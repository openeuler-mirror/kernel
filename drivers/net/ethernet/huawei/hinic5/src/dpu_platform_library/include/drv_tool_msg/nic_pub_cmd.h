/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_pub_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   :
 */

#ifndef NIC_PUB_CMD_H
#define NIC_PUB_CMD_H

#include "hinic5_mt.h"

/* Queue information related */

/**
 * @brief struct hinic5_tx_hw_page
 * @details struct for storing hardware page information
 */
struct hinic5_tx_hw_page {
	u64 phy_addr;       /**< physical address */
	u64 *map_addr;      /**< mapped address */
};

enum hinic5_show_set {
	HINIC5_SHOW_SSET_IO_STATS = 1,
};

#define HINIC5_SHOW_ITEM_LEN 32
/**
 * @brief struct hinic5_show_item
 * @details struct for display items
 */
struct hinic5_show_item {
	char name[HINIC5_SHOW_ITEM_LEN];    /**< item name */
	u8 hexadecimal;                     /**< value display format, 0 means decimal, 1 means hexadecimal */
	u8 rsvd[7];                         /**< reserved field */
	u64 value;                          /**< item value */
};

/**
 * @brief struct wqe_info
 * @details struct for storing work queue related information
 */
struct wqe_info {
	int q_id;               /**< queue ID */
	void *slq_handle;       /**< queue handle */
	unsigned int wqe_id;    /**< work queue element ID */
};

/**
 * @brief struct nic_sq_info
 * @details struct for storing network interface transmit queue information
 */
struct nic_sq_info {
	u16 q_id;           /**< queue ID */
	u16 pi;             /**< producer index */
	u16 ci;             /**< consumer index */
	u16 fi;             /**< hardware consumer index */
	u32 q_depth;        /**< queue depth */
	u16 pi_reverse;     /**< reverse producer index */
	u16 wqebb_size;     /**< work queue element size */
	u8 priority;        /**< priority */
	u64 ci_wqe_page_addr;   /**< sq wq first page address */
	u64 cla_addr;       /**< wq block address */
	void *slq_handle;   /**< transmit queue handle */
	struct hinic5_tx_hw_page direct_wqe;    /**< direct work queue element */
	struct hinic5_tx_hw_page doorbell;      /**< doorbell */
	u32 page_idx;       /**< page index */
	u32 glb_sq_id;      /**< global transmit queue ID */
};

/**
 * @brief struct nic_rq_info
 * @details struct for storing network interface receive queue information
 */
struct nic_rq_info {
	u16 q_id;       /**< queue ID */
	u16 delta;      /**< delta */
	u16 hw_ci;
	u16 ci;         /**< consumer index */
	u16 sw_pi;      /**< software producer index */
	u16 wqebb_size; /**< work queue element size */
	u16 q_depth;    /**< queue depth */
	u16 buf_len;    /**< buffer length */

	void *slq_handle;       /**< receive queue handle */
	u64 ci_wqe_page_addr;   /**< consumer index work queue element page address */
	u64 ci_cla_tbl_addr;    /**< consumer index cache line aligned table address */

	u8 coalesc_timer_cfg;   /**< interrupt timeout, unit 5us */
	u8 pending_limt;        /**< interrupt coalescing count, unit 8pkt */
	u16 msix_idx;           /**< MSI-X index */
	u32 msix_vector;        /**< MSI-X vector */
};

/* QOS related */

#define MT_DCB_OPCODE_WR   BIT(0)  /* 1 - write, 0 - read */

/**
 * @brief struct hinic5_mt_dcb_state
 * @details struct for storing Data Center Bridging (DCB) state information
 */
struct hinic5_mt_dcb_state {
	struct mt_msg_head head;    /**< message header */

	u16 op_code; /**< operation code 0 - get dcb state, 1 - set dcb state */
	u8 state;    /**< state 0 - disable,       1 - enable dcb  */
	u8 rsvd;     /**< reserved field */
};

#define CMD_QOS_DEV_TRUST     BIT(0)
#define CMD_QOS_DEV_DFT_COS   BIT(1)
#define CMD_QOS_DEV_PCP2COS   BIT(2)
#define CMD_QOS_DEV_DSCP2COS  BIT(3)

/**
 * @brief struct hinic5_mt_qos_dev_cfg
 * @details struct for configuring QoS device
 */
struct hinic5_mt_qos_dev_cfg {
	struct mt_msg_head head;    /**< message header */

	u8 op_code;       /**< 0: get 1: set */
	u8 rsvd0;
	u16 cfg_bitmap;   /**< bit0 - trust, bit1 - dft_cos, bit2 - pcp2cos, bit3 - dscp2cos */

	u8 trust;         /**< 0 - pcp, 1 - dscp */
	u8 dft_cos;
	u16 rsvd1;
	u8 pcp2cos[8];    /**< must configure 8 together */
	u8 dscp2cos[64];  /**< When configuring dscp2cos, if the cos value is set to 0xFF, the driver ignores the configuration for this dscp priority. Multiple dscp-to-cos mappings can be configured at once */
	u32 rsvd2[4];
};

/**
 * @brief struct hinic5_mt_qos_cos_cfg
 * @details struct for configuring HINIC5 multi-queue Quality of Service (QoS) category settings
 */
struct hinic5_mt_qos_cos_cfg {
	struct mt_msg_head head;    /**< message header, contains message type and length information */

	u8 port_id;                 /**< port ID, used to identify the port the message belongs to */
	u8 func_cos_bitmap;         /**< function category bitmap, used to indicate the enable status of each function category */
	u8 port_cos_bitmap;         /**< port category bitmap, used to indicate the enable status of each port category */
	u8 func_max_cos_num;        /**< maximum number of function categories, used to limit the number of function categories */
	u32 rsvd2[4];
};

enum nic_driver_cmd_type {
	NIC_TOOL_CMD_START = 0x120, /**< New platform command words start from 0x120, old command words are uniformly defined in @driver_cmd_type */

	/* MACsec tool command set */
	MACSEC_TOOL_OP_LIST = 0x120, /**< Get all macsec configuration info from driver memory */
	MACSEC_TOOL_OP_DUMP,         /**< Get all macsec configuration info from chip side */
	MACSEC_TOOL_OP_MIB,          /**< Get SC MIB info or PORT MIB info from chip side */
	MACSEC_TOOL_OP_ADD,          /**< Add SC or SA configuration */
	MACSEC_TOOL_OP_DEL,          /**< Delete SC or SA configuration */
	MACSEC_TOOL_OP_SET,          /**< Modify SC configuration */
	MACSEC_TOOL_OP_FLUSH,        /**< Clear macsec configuration managed by a device */
	MACSEC_TOOL_OP_MAX = 0x12F,

	NIC_CMD_EXTEND_RSV_START = 0x200,
	/* NIC tool reserved command words, products use command words in this range */
	NIC_CMD_EXTEND_RSV_END = 0x2FF,
};

#endif /* NIC_PUB_CMD_H */