/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mag_mpu_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : serdes/mag cmd definition between driver and mpu
 */

#ifndef MAG_MPU_CMD_DEFS_H
#define MAG_MPU_CMD_DEFS_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#elif defined(__WIN__)
#include "base_type.h"
#else
#include "typedef.h"
#endif
#include "mpu_cmd_base_defs.h"

struct mag_port_info {
	u8 port_type;
	u8 autoneg_cap;
	u8 autoneg_state;
	u8 duplex;
	u8 speed;
	u8 fec;
	u32 supported_mode;
	u32 advertised_mode;
	u32 supported_fec_mode;
};

enum mag_cmd_port_speed {
	PORT_SPEED_NOT_SET = 0,
	PORT_SPEED_10MB = 1,
	PORT_SPEED_100MB = 2,
	PORT_SPEED_1GB = 3,
	PORT_SPEED_10GB = 4,
	PORT_SPEED_25GB = 5,
	PORT_SPEED_40GB = 6,
	PORT_SPEED_50GB = 7,
	PORT_SPEED_100GB = 8,
	PORT_SPEED_200GB = 9,
	PORT_SPEED_400GB = 10,
	PORT_SPEED_800GB = 11,
	PORT_SPEED_UNKNOWN
};

enum mag_cmd_port_an {
	PORT_AN_NOT_SET = 0,
	PORT_CFG_AN_ON = 1,
	PORT_CFG_AN_OFF = 2
};

enum mag_cmd_port_adapt {
	PORT_ADAPT_NOT_SET = 0,
	PORT_CFG_ADAPT_ON = 1,
	PORT_CFG_ADAPT_OFF = 2
};

enum mag_cmd_prbs_scr_en {
	PRBS_SCR_EN_OFF = 0,
	PRBS_SCR_EN_ON = 1,
	PRBS_SCR_EN_END
};

enum mag_cmd_dirction {
	DIRECTION_TX = 0,
	DIRECTION_RX = 1,
	DIRECTION_TXRX = 2,
	DIRECTION_END
};

enum mag_cmd_port_sriov {
	PORT_SRIOV_NOT_SET = 0,
	PORT_CFG_SRIOV_ON = 1,
	PORT_CFG_SRIOV_OFF = 2
};

enum mag_cmd_port_fec {
	PORT_FEC_NOT_SET = 0,
	PORT_FEC_RSFEC = 1,
	PORT_FEC_BASEFEC = 2,
	PORT_FEC_NOFEC = 3,
	PORT_FEC_LLRSFEC = 4,
	PORT_FEC_AUTO = 5
};

enum mag_cmd_port_lanes {
	PORT_LANES_NOT_SET = 0,
	PORT_LANES_X1 = 1,
	PORT_LANES_X2 = 2,
	PORT_LANES_X4 = 4,
	PORT_LANES_X8 = 8 /* reserved for future use */
};

enum mag_cmd_port_duplex {
	PORT_DUPLEX_HALF = 0,
	PORT_DUPLEX_FULL = 1
};

enum mag_cmd_wire_node {
	WIRE_NODE_UNDEF = 0,
	CABLE_10G = 1,
	FIBER_10G = 2,
	CABLE_25G = 3,
	FIBER_25G = 4,
	CABLE_40G = 5,
	FIBER_40G = 6,
	CABLE_50G = 7,
	FIBER_50G = 8,
	CABLE_100G = 9,
	FIBER_100G = 10,
	CABLE_200G = 11,
	FIBER_200G = 12,
	CABLE_400G = 13,
	FIBER_400G = 14,
	CABLE_800G = 15,
	FIBER_800G = 16,
	WIRE_NODE_NUM
};

#define CABLE_10G_SPEED     (1 << PORT_SPEED_10GB)
#define CABLE_25G_SPEED     ((1 << PORT_SPEED_25GB) | (1 << PORT_SPEED_10GB))
#define CABLE_40G_SPEED     ((1 << PORT_SPEED_40GB) | (1 << PORT_SPEED_10GB))
#define CABLE_50G_SPEED     ((1 << PORT_SPEED_50GB) | (1 << PORT_SPEED_25GB) | (1 << PORT_SPEED_10GB))
#define CABLE_100G_SPEED    ((1 << PORT_SPEED_100GB) | (1 << PORT_SPEED_50GB) | (1 << PORT_SPEED_40GB) | \
							(1 << PORT_SPEED_25GB) | (1 << PORT_SPEED_10GB))
#define CABLE_200G_SPEED    ((1 << PORT_SPEED_200GB) | (1 << PORT_SPEED_100GB) | (1 << PORT_SPEED_50GB) | \
							(1 << PORT_SPEED_40GB) | (1 << PORT_SPEED_25GB) | (1 << PORT_SPEED_10GB))
#define CABLE_400G_SPEED    ((1 << PORT_SPEED_400GB) | (1 << PORT_SPEED_200GB) | (1 << PORT_SPEED_100GB) | \
							(1 << PORT_SPEED_50GB) | (1 << PORT_SPEED_40GB) | (1 << PORT_SPEED_25GB) | (1 << PORT_SPEED_10GB))
#define CABLE_800G_SPEED    ((1 << PORT_SPEED_800GB) | (1 << PORT_SPEED_400GB) | (1 << PORT_SPEED_200GB) | \
							(1 << PORT_SPEED_100GB) | (1 << PORT_SPEED_50GB) | (1 << PORT_SPEED_40GB) | (1 << PORT_SPEED_25GB) | (1 << PORT_SPEED_10GB))
#define FIBER_10G_SPEED     (1 << PORT_SPEED_10GB)
#define FIBER_25G_SPEED     (1 << PORT_SPEED_25GB)
#define FIBER_40G_SPEED     (1 << PORT_SPEED_40GB)
#define FIBER_50G_SPEED     (1 << PORT_SPEED_50GB)
#define FIBER_100G_SPEED    (1 << PORT_SPEED_100GB)
#define FIBER_200G_SPEED    (1 << PORT_SPEED_200GB)
#define FIBER_400G_SPEED    (1 << PORT_SPEED_400GB)
#define FIBER_800G_SPEED    (1 << PORT_SPEED_800GB)

enum mag_cmd_cnt_type {
	MAG_RX_RSFEC_DEC_CW_CNT = 0,
	MAG_RX_RSFEC_CORR_CW_CNT = 1,
	MAG_RX_RSFEC_UNCORR_CW_CNT = 2,
	MAG_RX_PCS_BER_CNT = 3,
	MAG_RX_PCS_ERR_BLOCK_CNT = 4,
	MAG_RX_PCS_E_BLK_CNT = 5,
	MAG_RX_PCS_DEC_ERR_BLK_CNT = 6,
	MAG_RX_PCS_LANE_BIP_ERR_CNT = 7,
	MAG_CNT_NUM
};

/* mag_cmd_set_port_cfg config bitmap */
#define MAG_CMD_SET_SPEED 0x1
#define MAG_CMD_SET_AUTONEG 0x2
#define MAG_CMD_SET_FEC 0x4
#define MAG_CMD_SET_LANES 0x8
struct mag_cmd_set_port_cfg {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd0[3];

	u32 config_bitmap;
	u8 speed;
	u8 autoneg;
	u8 fec;
	u8 lanes;
	u8 rsvd1[19];
	u8 adapt_en;    /* Added for cross-DIE, tool has not enabled this capability yet */
};

/* mag supported/advertised link mode bitmap */
enum mag_cmd_link_mode {
	LINK_MODE_GE = 0,
	LINK_MODE_10GE_BASE_R = 1,
	LINK_MODE_25GE_BASE_R = 2,
	LINK_MODE_40GE_BASE_R4 = 3,
	LINK_MODE_50GE_BASE_R = 4,
	LINK_MODE_50GE_BASE_R2 = 5,
	LINK_MODE_100GE_BASE_R = 6,
	LINK_MODE_100GE_BASE_R2 = 7,
	LINK_MODE_100GE_BASE_R4 = 8,
	LINK_MODE_200GE_BASE_R2 = 9,
	LINK_MODE_200GE_BASE_R4 = 10,
	LINK_MODE_200GE_BASE_R8 = 11,
	LINK_MODE_400GE_BASE_R4 = 12,
	LINK_MODE_400GE_BASE_R8 = 13,
	LINK_MODE_800GE_BASE_R8 = 14,
	LINK_MODE_MAX_NUMBERS,

	LINK_MODE_UNKNOWN = 0xFFFF
};

enum mag_cmd_himac_prbs_type {
	HIMAC_PRBS_NOT_SET = 0,
	HIMAC_PRBS13,
	HIMAC_PRBS15,
	HIMAC_PRBS31,
	HIMAC_PRBS58,
	HIMAC_PRBS_DISABLE,
	HIMAC_PRBS_END
};

#define LINK_MODE_GE_BIT 0x1u
#define LINK_MODE_10GE_BASE_R_BIT 0x2u
#define LINK_MODE_25GE_BASE_R_BIT 0x4u
#define LINK_MODE_40GE_BASE_R4_BIT 0x8u
#define LINK_MODE_50GE_BASE_R_BIT 0x10u
#define LINK_MODE_50GE_BASE_R2_BIT 0x20u
#define LINK_MODE_100GE_BASE_R_BIT 0x40u
#define LINK_MODE_100GE_BASE_R2_BIT 0x80u
#define LINK_MODE_100GE_BASE_R4_BIT 0x100u
#define LINK_MODE_200GE_BASE_R2_BIT 0x200u
#define LINK_MODE_200GE_BASE_R4_BIT 0x400u
#define LINK_MODE_200GE_BASE_R8_BIT 0x800u
#define LINK_MODE_400GE_BASE_R4_BIT 0x1000u
#define LINK_MODE_400GE_BASE_R8_BIT 0x2000u
#define LINK_MODE_800GE_BASE_R8_BIT 0x4000u

#define CABLE_10GE_BASE_R_BIT LINK_MODE_10GE_BASE_R_BIT
#define CABLE_25GE_BASE_R_BIT (LINK_MODE_25GE_BASE_R_BIT | LINK_MODE_10GE_BASE_R_BIT)
#define CABLE_40GE_BASE_R4_BIT LINK_MODE_40GE_BASE_R4_BIT
#define CABLE_50GE_BASE_R_BIT (LINK_MODE_50GE_BASE_R_BIT | LINK_MODE_25GE_BASE_R_BIT | \
	LINK_MODE_10GE_BASE_R_BIT)
#define CABLE_50GE_BASE_R2_BIT LINK_MODE_50GE_BASE_R2_BIT
#define CABLE_100GE_BASE_R_BIT (LINK_MODE_100GE_BASE_R_BIT | LINK_MODE_50GE_BASE_R_BIT | \
	LINK_MODE_25GE_BASE_R_BIT | LINK_MODE_10GE_BASE_R_BIT)
#define CABLE_100GE_BASE_R2_BIT (LINK_MODE_100GE_BASE_R2_BIT | LINK_MODE_50GE_BASE_R2_BIT)
#define CABLE_100GE_BASE_R4_BIT (LINK_MODE_100GE_BASE_R4_BIT | LINK_MODE_40GE_BASE_R4_BIT)
#define CABLE_200GE_BASE_R2_BIT (LINK_MODE_200GE_BASE_R2_BIT | LINK_MODE_100GE_BASE_R2_BIT | \
	LINK_MODE_50GE_BASE_R2_BIT)
#define CABLE_200GE_BASE_R4_BIT (LINK_MODE_200GE_BASE_R4_BIT | LINK_MODE_100GE_BASE_R4_BIT | \
	LINK_MODE_40GE_BASE_R4_BIT)
#define CABLE_200GE_BASE_R8_BIT LINK_MODE_200GE_BASE_R8_BIT
#define CABLE_400GE_BASE_R4_BIT (LINK_MODE_400GE_BASE_R4_BIT | LINK_MODE_200GE_BASE_R4_BIT | \
	LINK_MODE_100GE_BASE_R4_BIT | LINK_MODE_40GE_BASE_R4_BIT)
#define CABLE_400GE_BASE_R8_BIT (LINK_MODE_400GE_BASE_R8_BIT | LINK_MODE_200GE_BASE_R8_BIT)
#define CABLE_800GE_BASE_R8_BIT (LINK_MODE_800GE_BASE_R8_BIT | LINK_MODE_400GE_BASE_R8_BIT | \
	LINK_MODE_200GE_BASE_R8_BIT)

struct mag_cmd_get_port_info {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd0[3];

	u8 wire_type;
	u8 an_support;
	u8 an_en;
	u8 duplex;

	u8 speed;
	u8 fec;
	u8 lanes;
	u8 rsvd1;

	u32 supported_mode;
	u32 advertised_mode;
	u32 supported_fec_mode;
	u8 rsvd2[4];
};

#define MAG_CMD_OPCODE_GET 0
#define MAG_CMD_OPCODE_SET 1
struct mag_cmd_set_port_adapt {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 opcode; /* 0:get adapt info  1:set adapt */
	u8 enable;
	u8 rsvd0;
	u32 speed_mode;
	u32 rsvd1[3];
};

#define MAG_CMD_LP_MODE_SDS_S_TX2RX 1
#define MAG_CMD_LP_MODE_SDS_P_RX2TX 2
#define MAG_CMD_LP_MODE_SDS_P_TX2RX 3
#define MAG_CMD_LP_MODE_MAC_RX2TX 4
struct mag_cmd_cfg_loopback_mode {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 opcode; /* 0:get loopback mode  1:set loopback mode */
	u8 lp_mode;
	u8 lp_en; /* 0:disable  1:enable */

	u32 rsvd0[2];
};

#define MAG_CMD_PORT_DISABLE 0x0
#define MAG_CMD_TX_ENABLE 0x1
#define MAG_CMD_RX_ENABLE 0x2
/* the physical port is disable only when all pf of the port are set to down,
 * if any pf is enable, the port is enable
 */
struct mag_cmd_set_port_enable {
	struct mgmt_msg_head head;

	u16 function_id; /* function_id should not more than the max support pf_id(32) */
	u16 rsvd0;

	u8 state; /* bitmap bit0:tx_en bit1:rx_en */
	u8 rsvd1[3];
};

struct mag_cmd_get_port_enable {
	struct mgmt_msg_head head;

	u8 port;
	u8 state; /* bitmap bit0:tx_en bit1:rx_en */
	u8 rsvd0[2];
};

#define PMA_FOLLOW_DEFAULT 0x0
#define PMA_FOLLOW_ENABLE 0x1
#define PMA_FOLLOW_DISABLE 0x2
#define PMA_FOLLOW_GET 0x4
/* the physical port disable link follow only when all pf of the port are set to follow disable */
struct mag_cmd_set_link_follow {
	struct mgmt_msg_head head;

	u16 function_id; /* function_id should not more than the max support pf_id(32) */
	u16 rsvd0;

	u8 follow;
	u8 rsvd1[3];
};

/* firmware also use this cmd report link event to driver */
struct mag_cmd_get_link_status {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 status; /* 0:link down  1:link up */
	u8 rsvd0[2];
};

struct mag_cmd_set_pma_enable {
	struct mgmt_msg_head head;

	u16 function_id; /* function_id should not more than the max support pf_id(32) */
	u16 enable;
};

struct mag_cmd_cfg_an_type {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 opcode; /* 0:get an type  1:set an type */
	u8 rsvd0[2];

	u32 an_type; /* 0:ieee   1:25G/50 eth consortium */
};

struct mag_cmd_get_link_time {
	struct mgmt_msg_head head;
	u8 port_id;
	u8 rsvd0[3];

	u32 link_up_begin;
	u32 link_up_end;
	u32 link_down_begin;
	u32 link_down_end;
};

struct mag_cmd_cfg_fec_mode {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 opcode; /* 0:get fec mode  1:set fec mode */
	u8 advertised_fec;
	u8 supported_fec;
};

/* speed */
#define PANGEA_ADAPT_10G_BITMAP     0xd
#define PANGEA_ADAPT_25G_BITMAP     0x72
#define PANGEA_ADAPT_40G_BITMAP     0x680
#define PANGEA_ADAPT_100G_BITMAP    0x1900
#define PANGEA_ADAPT_200G_BITMAP    0x1c000

/* speed and fec */
#define PANGEA_10G_NO_BITMAP        0x8
#define PANGEA_10G_BASE_BITMAP      0x4
#define PANGEA_25G_NO_BITMAP        0x10
#define PANGEA_25G_BASE_BITMAP      0x20
#define PANGEA_25G_RS_BITMAP        0x40
#define PANGEA_40G_NO_BITMAP        0x400
#define PANGEA_40G_BASE_BITMAP      0x200
#define PANGEA_100G_NO_BITMAP       0x800
#define PANGEA_100G_RS_BITMAP       0x1000
#define PANGEA_200G_RS_BITMAP       0x8000
#define PANGEA_200G_LLRS_BITMAP     0x10000

/* adapt or fec */
#define PANGEA_ADAPT_ADAPT_BITMAP   0x4183
#define PANGEA_ADAPT_NO_BITMAP      0xc18
#define PANGEA_ADAPT_BASE_BITMAP    0x224
#define PANGEA_ADAPT_RS_BITMAP      0x9040
#define PANGEA_ADAPT_LLRS_BITMAP    0x10000

/* default cfg */
#define PANGEA_ADAPT_CFG_10G_CR     0x200d
#define PANGEA_ADAPT_CFG_10G_SRLR   0xd
#define PANGEA_ADAPT_CFG_25G_CR     0x207f
#define PANGEA_ADAPT_CFG_25G_SRLR   0x72
#define PANGEA_ADAPT_CFG_40G_CR4    0x2680
#define PANGEA_ADAPT_CFG_40G_SRLR4  0x680
#define PANGEA_ADAPT_CFG_100G_CR4   0x3f80
#define PANGEA_ADAPT_CFG_100G_SRLR4 0x1900
#define PANGEA_ADAPT_CFG_200G_CR4   0x1ff80
#define PANGEA_ADAPT_CFG_200G_SRLR4 0x1c000

typedef union {
	struct {
		u32 adapt_10g : 1;  /* [0]   adapt_10g  */
		u32 adapt_25g : 1;  /* [1]   adapt_25g  */
		u32 base_10g : 1;   /* [2]   base_10g   */
		u32 no_10g : 1;     /* [3]   no_10g     */
		u32 no_25g : 1;     /* [4]   no_25g     */
		u32 base_25g : 1;   /* [5]   base_25g   */
		u32 rs_25g : 1;     /* [6]   rs_25g     */
		u32 adapt_40g : 1;  /* [7]   adapt_40g  */
		u32 adapt_100g : 1; /* [8]   adapt_100g */
		u32 base_40g : 1;   /* [9]   base_40g   */
		u32 no_40g : 1;     /* [10]  no_40g     */
		u32 no_100g : 1;    /* [11]  no_100g    */
		u32 rs_100g : 1;    /* [12]  rs_100g    */
		u32 auto_neg : 1;   /* [13]  auto_neg   */
		u32 adapt_200g : 1; /* [14]  adapt_200g */
		u32 rs_200g : 1;    /* [15]  rs_200g    */
		u32 llrs_200g : 1;  /* [16]  llrs_200g  */
		u32 rsvd0 : 15;     /* [31:17] reserved */
	} bits;

	u32 value;
} pangea_adapt_bitmap_u;

#define PANGEA_ADAPT_GET 0x0
#define PANGEA_ADAPT_SET 0x1
struct mag_cmd_set_pangea_adapt {
	struct mgmt_msg_head head;

	u16 port_id;
	u8 opcode; /* 0:get adapt info  1:cfg adapt info */
	u8 wire_type;

	pangea_adapt_bitmap_u cfg_bitmap;
	pangea_adapt_bitmap_u cur_bitmap;
	u32 rsvd1[3];
};

struct mag_cmd_restore_link_cfg {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd[7];
};

struct mag_cmd_activate_bios_link_cfg {
	struct mgmt_msg_head head;

	u32 rsvd[8];
};

/* led type */
enum mag_led_type {
	MAG_CMD_LED_TYPE_ALARM = 0x0,
	MAG_CMD_LED_TYPE_LOW_SPEED = 0x1,
	MAG_CMD_LED_TYPE_HIGH_SPEED = 0x2
};

/* led mode */
enum mag_led_mode {
	MAG_CMD_LED_MODE_DEFAULT = 0x0,
	MAG_CMD_LED_MODE_FORCE_ON = 0x1,
	MAG_CMD_LED_MODE_FORCE_OFF = 0x2,
	MAG_CMD_LED_MODE_FORCE_BLINK_1HZ = 0x3,
	MAG_CMD_LED_MODE_FORCE_BLINK_2HZ = 0x4,
	MAG_CMD_LED_MODE_FORCE_BLINK_4HZ = 0x5,
	MAG_CMD_LED_MODE_1HZ = 0x6,
	MAG_CMD_LED_MODE_2HZ = 0x7,
	MAG_CMD_LED_MODE_4HZ = 0x8
};

/* the led is report alarm  when any pf of the port is alram */
struct mag_cmd_set_led_cfg {
	struct mgmt_msg_head head;

	u16 function_id;
	u8 type;
	u8 mode;
};

#define XSFP_INFO_MAX_SIZE 640
/* xsfp wire type, refer to cmis protocol definition */
enum mag_wire_type {
	MAG_CMD_WIRE_TYPE_UNKNOWN = 0x0,
	MAG_CMD_WIRE_TYPE_MM = 0x1,
	MAG_CMD_WIRE_TYPE_SM = 0x2,
	MAG_CMD_WIRE_TYPE_COPPER = 0x3,
	MAG_CMD_WIRE_TYPE_ACC = 0x4,
	MAG_CMD_WIRE_TYPE_BASET = 0x5,
	MAG_CMD_WIRE_TYPE_AOC = 0x40,
	MAG_CMD_WIRE_TYPE_ELECTRIC = 0x41,
	MAG_CMD_WIRE_TYPE_BACKPLANE = 0x42
};

struct mag_cmd_get_xsfp_info {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 wire_type;
	u16 out_len;
	u32 rsvd;
	u8 sfp_info[XSFP_INFO_MAX_SIZE];
};

#define MAG_CMD_XSFP_DISABLE 0x0
#define MAG_CMD_XSFP_ENABLE 0x1
/* the sfp is disable only when all pf of the port are set sfp down,
 * if any pf is enable, the sfp is enable
 */
struct mag_cmd_set_xsfp_enable {
	struct mgmt_msg_head head;

	u32 port_id;
	u32 status; /* 0:on 1:off */
};

#define MAG_CMD_XSFP_PRESENT 0x0
#define MAG_CMD_XSFP_ABSENT 0x1
struct mag_cmd_get_xsfp_present {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 abs_status; /* 0:present, 1:absent */
	u8 rsvd[2];
};

#define MAG_CMD_XSFP_READ 0x0
#define MAG_CMD_XSFP_WRITE 0x1

#define MAG_CMD_MISC_BANK_ID_MASK 0x03 /* bit [0:1]: means cmis bank_id */
struct mag_cmd_set_xsfp_rw {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 operation; /* 0: read; 1: write */
	u8 value;
	u8 rsvd0;
	u32 devaddr;
	u32 offset;
	u8 misc;       /* bit [0:1]: means cmis bank_id, bit [2:7]: reserved */
	/*
		for qsfp and cmis, means upper page id.
		for qsfp, if not specified, read the upper page specified last time.
		for cmis, page_id must be specified.
	*/
	u8 page_id;
	u16 rsvd1;
};

#define MAG_PARAM_TYPE_DEFAULT_CFG 0x0
#define MAG_PARAM_TYPE_BIOS_CFG 0x1
#define MAG_PARAM_TYPE_TOOL_CFG 0x2
#define MAG_PARAM_TYPE_FINAL_CFG 0x3
#define MAG_PARAM_TYPE_WIRE_INFO 0x4
#define MAG_PARAM_TYPE_ADAPT_INFO 0x5
#define MAG_PARAM_TYPE_MAX_CNT 0x6
struct param_head {
	u8 valid_len;
	u8 info_type;
	u8 rsvd[2];
};

struct mag_port_link_param {
	struct param_head head;

	u8 an;
	u8 fec;
	u8 speed;
	u8 rsvd0;

	u32 used;
	u32 an_fec_ability;
	u32 an_speed_ability;
	u32 an_pause_ability;
};

struct mag_port_wire_info {
	struct param_head head;

	u8 status;
	u8 rsvd0[3];

	u8 wire_type;
	u8 default_fec;
	u8 speed;
	u8 rsvd1;
	u32 speed_ability;
};

struct mag_port_adapt_info {
	struct param_head head;

	u32 adapt_en;
	u32 flash_adapt;
	u32 rsvd0[2];

	u32 wire_node;
	u32 an_en;
	u32 speed;
	u32 fec;
};

struct mag_port_param_info {
	u8 parameter_cnt;
	u8 lane_id;
	u8 lane_num;
	u8 rsvd0;

	struct mag_port_link_param default_cfg;
	struct mag_port_link_param bios_cfg;
	struct mag_port_link_param tool_cfg;
	struct mag_port_link_param final_cfg;

	struct mag_port_wire_info wire_info;
	struct mag_port_adapt_info adapt_info;
};

#define XSFP_VENDOR_NAME_LEN 16
#define XSFP_VENDOR_SN_LEN 16

struct mag_cmd_event_port_info {
	/* Message header common info 8+4=12B */
	struct mgmt_msg_head head;
	u8 port_id;
	u8 event_type;
	u8 rsvd0[2];

	/* Optical module related 16+4*3+4+16+8=56B */
	u8 vendor_name[XSFP_VENDOR_NAME_LEN];
	u32 port_type;                           /* fiber / copper */
	u32 port_sub_type;                       /* sr / lr */
	u32 cable_length;                        /* 1/3/5m */
	u8 cable_temp;                           /* Temperature */
	u8 max_speed;                            /* Optical module maximum speed */
	u8 sfp_type;                             /* sfp/qsfp */
	u8 rsvd1;
	u32 power[4];                            /* Optical power */

	u8 an_state;
	u8 fec;
	u16 speed;

	u8 gpio_insert;                          /* 0:present  1:absent */
	u8 alos;
	u8 rx_los;                               /* Get from gpio */
	u8 pma_ctrl;                             /* eth_ctrl.pma_ctrl.bits.rf_en; */

	/* himac related info 4*5+4=32B */
	u32 pma_fifo_reg;                        /* himac pma fifo status */
	u32 pma_signal_ok_reg;                   /* himac pma signal ok status */
	u32 pcs_64_66b_reg;                      /* himac V600 does not have this register */
	u32 rf_lf;                               /* himac rxmac lf rf status */
	u8 pcs_link;                             /* himac pcs link status */
	u8 pcs_mac_link;                         /* link_state after link thread judgment */
	u8 tx_enable;                            /* himac txmac enable status */
	u8 rx_enable;                            /* himac rxmac enable status */
	u32 pcs_err_cnt;                         /* himac pcs ber err cnt */

	u8 eq_data[38];
	u8 rsvd2[2];

	/* link thread related dfx 4+4+128+128+4=268 */
	u32 his_link_machine_state;
	u32 cur_link_machine_state;
	u8 his_machine_state_data[128];
	u8 cur_machine_state_data[128];
	u8 his_machine_state_length;
	u8 cur_machine_state_length;

	/* an/adapt/link thread configuration info 4+4*24+16+36= */
	struct mag_port_param_info param_info;

	/* Auto-negotiation (an) and adaptation (adapt) related info 4+8=12B */
	u32 speed_ability;                       /* supported_mode & advertised_mode */
	u32 fec_ability;                         /* supported FEC modes */
	u8 duplex;

	/* Cable SN ASCII representation 16B */
	u8 vendor_sn[XSFP_VENDOR_SN_LEN];
	u32 osfp_power[4]; /* 4-channel optical power */

	/* serdes txrx key parameters */
	u8 sds_txrx_para[8][10];
	u8 ds_mask;

	/* Ensure compatibility */
	u8 rsvd3[238]; /* Reserve 238 bytes */
};

struct mag_cmd_port_stats {
	u64 mac_tx_fragment_pkt_num;
	u64 mac_tx_undersize_pkt_num;
	u64 mac_tx_undermin_pkt_num;
	u64 mac_tx_64_oct_pkt_num;
	u64 mac_tx_65_127_oct_pkt_num;
	u64 mac_tx_128_255_oct_pkt_num;
	u64 mac_tx_256_511_oct_pkt_num;
	u64 mac_tx_512_1023_oct_pkt_num;
	u64 mac_tx_1024_1518_oct_pkt_num;
	u64 mac_tx_1519_2047_oct_pkt_num;
	u64 mac_tx_2048_4095_oct_pkt_num;
	u64 mac_tx_4096_8191_oct_pkt_num;
	u64 mac_tx_8192_9216_oct_pkt_num;
	u64 mac_tx_9217_12287_oct_pkt_num;
	u64 mac_tx_12288_16383_oct_pkt_num;
	u64 mac_tx_1519_max_bad_pkt_num;
	u64 mac_tx_1519_max_good_pkt_num;
	u64 mac_tx_oversize_pkt_num;
	u64 mac_tx_jabber_pkt_num;
	u64 mac_tx_bad_pkt_num;
	u64 mac_tx_bad_oct_num;
	u64 mac_tx_good_pkt_num;
	u64 mac_tx_good_oct_num;
	u64 mac_tx_total_pkt_num;
	u64 mac_tx_total_oct_num;
	u64 mac_tx_uni_pkt_num;
	u64 mac_tx_multi_pkt_num;
	u64 mac_tx_broad_pkt_num;
	u64 mac_tx_pause_num;
	u64 mac_tx_pfc_pkt_num;
	u64 mac_tx_pfc_pri0_pkt_num;
	u64 mac_tx_pfc_pri1_pkt_num;
	u64 mac_tx_pfc_pri2_pkt_num;
	u64 mac_tx_pfc_pri3_pkt_num;
	u64 mac_tx_pfc_pri4_pkt_num;
	u64 mac_tx_pfc_pri5_pkt_num;
	u64 mac_tx_pfc_pri6_pkt_num;
	u64 mac_tx_pfc_pri7_pkt_num;
	u64 mac_tx_control_pkt_num;
	u64 mac_tx_err_all_pkt_num;
	u64 mac_tx_from_app_good_pkt_num;
	u64 mac_tx_from_app_bad_pkt_num;

	u64 mac_rx_fragment_pkt_num;
	u64 mac_rx_undersize_pkt_num;
	u64 mac_rx_undermin_pkt_num;
	u64 mac_rx_64_oct_pkt_num;
	u64 mac_rx_65_127_oct_pkt_num;
	u64 mac_rx_128_255_oct_pkt_num;
	u64 mac_rx_256_511_oct_pkt_num;
	u64 mac_rx_512_1023_oct_pkt_num;
	u64 mac_rx_1024_1518_oct_pkt_num;
	u64 mac_rx_1519_2047_oct_pkt_num;
	u64 mac_rx_2048_4095_oct_pkt_num;
	u64 mac_rx_4096_8191_oct_pkt_num;
	u64 mac_rx_8192_9216_oct_pkt_num;
	u64 mac_rx_9217_12287_oct_pkt_num;
	u64 mac_rx_12288_16383_oct_pkt_num;
	u64 mac_rx_1519_max_bad_pkt_num;
	u64 mac_rx_1519_max_good_pkt_num;
	u64 mac_rx_oversize_pkt_num;
	u64 mac_rx_jabber_pkt_num;
	u64 mac_rx_bad_pkt_num;
	u64 mac_rx_bad_oct_num;
	u64 mac_rx_good_pkt_num;
	u64 mac_rx_good_oct_num;
	u64 mac_rx_total_pkt_num;
	u64 mac_rx_total_oct_num;
	u64 mac_rx_uni_pkt_num;
	u64 mac_rx_multi_pkt_num;
	u64 mac_rx_broad_pkt_num;
	u64 mac_rx_pause_num;
	u64 mac_rx_pfc_pkt_num;
	u64 mac_rx_pfc_pri0_pkt_num;
	u64 mac_rx_pfc_pri1_pkt_num;
	u64 mac_rx_pfc_pri2_pkt_num;
	u64 mac_rx_pfc_pri3_pkt_num;
	u64 mac_rx_pfc_pri4_pkt_num;
	u64 mac_rx_pfc_pri5_pkt_num;
	u64 mac_rx_pfc_pri6_pkt_num;
	u64 mac_rx_pfc_pri7_pkt_num;
	u64 mac_rx_control_pkt_num;
	u64 mac_rx_sym_err_pkt_num;
	u64 mac_rx_fcs_err_pkt_num;
	u64 mac_rx_send_app_good_pkt_num;
	u64 mac_rx_send_app_bad_pkt_num;
	u64 mac_rx_unfilter_pkt_num;
};

struct mag_cmd_port_stats_info {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd0[3];
};

struct mag_cmd_get_port_stat {
	struct mgmt_msg_head head;

	struct mag_cmd_port_stats counter;
	u64 rsvd1[15];
};

struct mag_cmd_clr_port_stat {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd0[3];
};

struct mag_cmd_get_pcs_err_cnt {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd0[3];

	u32 pcs_err_cnt;
};

struct mag_cmd_get_mag_cnt {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 len;
	u8 rsvd0[2];

	u32 mag_csr[128];
};

struct mag_cmd_dump_antrain_info {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 len;
	u8 rsvd0[2];

	u32 antrain_csr[256];
};

typedef struct {
	u8 minimum_value[2];                    /* LPL PM data 2 bytes – minimum value */
	u8 average_value[2];                    /* LPL PM data 2 bytes – average (mean) value */
	u8 maximum_value[2];                    /* LPL PM data 2 bytes – maximum value */
} cdb_pam4_ltp_6bytes;

typedef struct {
	u8 minimum_value[2];                    /* LPL PM data 2 bytes – minimum value */
	u8 average_value[2];                    /* LPL PM data 2 bytes – average (mean) value */
	u8 maximum_value[2];                    /* LPL PM data 2 bytes – maximum value */
	u8 current_value[2];                    /* LPL PM data 2 bytes – an optional current value */
} cdb_pam4_ltp_8bytes;

typedef struct {
	u8 rsv[2];                              /* 136~137 reserved */
	u8 max_ref_pot;                         /* 138 Channels 1-8 maximum reflection intensity point whether has return loss abnormal alarm, bit0-7: indicates channels 1-8, 0: no abnormal alarm, 1 indicates alarm (recommend cleaning the link) */
	u8 sec_ref_pot;                         /* 139 Channels 1-8 second largest reflection intensity point whether has return loss abnormal alarm, bit0-7: indicates channels 1-8, 0: no abnormal alarm, 1 indicates alarm (recommend cleaning the link) */
	u8 max_ref_val[8];                      /* 140~147 Channels 1-8 maximum reflection intensity, unsigned data, unit: -0.2 dB, e.g.: 0x0A indicates return loss intensity of -2db */
	u8 max_ref_pos[8][3];                   /* 148~171 Position of channels 1-8 maximum reflection intensity point, unsigned data, unit: 0.1m, reporting 0xFFFFFFh indicates invalid value (maximum reflection point not detected) */
	u8 sec_ref_val[8];                      /* 172~179 Channels 1-8 second largest reflection intensity, unsigned data, unit: -0.2 dB, e.g.: 0x0A indicates return loss intensity of -2db */
	u8 sec_ref_pos[8][3];                   /* 180~203 Position of channels 1-8 second largest reflection intensity point, unsigned data, unit: 0.1m, reporting 0xFFFFFFh indicates invalid value (second largest reflection point not detected) */
	u8 far_ref_val[8];                      /* 204~211 Channels 1-8 farthest reflection intensity, unsigned data, unit: -0.2 dB, e.g.: 0x0A indicates return loss intensity of -2db */
	u8 far_ref_pos[8][3];                   /* 212~235 Position of channels 1-8 farthest reflection intensity point, unsigned data, unit: 0.1m, reporting 0xFFFFFFh indicates invalid value (farthest reflection point not detected) */
	u8 peer_tx_alarm;                       /* 236 Peer TX optical port whether has alarm, bit0-7: TX optical ports 1-8, 0: no abnormal alarm, 1 indicates alarm (recommend cleaning the link) */
	u8 peer_tx_val[8];                      /* 237~244 Peer TX optical ports 1-8 alarm degree, unsigned data */
	u8 local_rx_alarm;                      /* 245 Local RX optical port whether has alarm, bit0-7: RX optical ports 1-8, 0: no abnormal alarm, 1 indicates alarm (recommend cleaning the link) */
	u8 local_rx_val[8];                     /* 246~253 Local RX optical ports 1-8 alarm degree, unsigned data */
	u8 rsv1[2];                             /* 254~255 reserved */
} cdb_dirt_detection;

typedef struct {
	u8 resv0[14];                   /* Reg 0-13: Lower Memory: Page 00h */
	u8 temperature_msb;             /* Reg 14: Module Monitor 1: Temperature1 MSB */
	u8 temperature_lsb;             /* Reg 15: Module Monitor 1: Temperature1 LSB */
	u8 volt_supply[2];              /*
					 * Reg 16-17: Internally measured 3.3 volt
					 * input supply voltage: in 100 µV increments.
					 */
	u8 resv1[67];                   /* Reg 18-84 */
	u8 media_type;                  /* Reg 85: Table 8-12 Byte 85 Module Media Type Encodings */

	u8 electrical_interface_id;     /* Reg 86: ID from SFF-8024 IDs for Host Electrical Interfaces */
	u8 media_interface_id;          /* Reg 87: ID from table selected by Byte 85 (see Table 8-12) */
	u8 lane_count;                  /*
					 * Reg 88: Lane Count, ApSel Code: 0001b.
					 *   bit 7-4: Host Lane Count.
					 *   bit 3-0: Media Lane Count.
					 */
	u8 lane_assignment_options;     /*
					 * Reg 89: Bits 0-7 form a bit map corresponding to Host Lanes 1-8.
					 * A set bit indicates that the Application may begin on the corresponding
					 * host lane.
					 */
	u8 resv2[38];                   /* Reg 90-127 */
} qsfp_cmis_lower_page_00_s;

typedef struct {
	u8 identifier;                  /* Reg 128: Type of Serial Module - See SFF-8024. */
	u8 vendor_name[16];             /* Reg 129-144: Vendor name (ASCII) */
	u8 vendor_oui[3];               /* Reg 145-147: Vendor IEEE company ID */
	u8 vendor_pn[16];               /* Reg 148-163: Part number provided by vendor (ASCII) */
	u8 vendor_rev[2];               /* Reg 164-165: Revision level for part number provided by vendor (ASCII) */
	u8 vendor_sn[16];               /* Reg 166-181: Vendor Serial Number (ASCII) */
	u8 date_code[8];                /* Reg 182-189: Vendor's manufacturing date code */
	u8 clei_code[10];               /* Reg 190-199: Common Language Equipment Identification code */
	u8 power_character[2];          /* Reg 200-201: Module power characteristics */
	u8 cable_len;                   /*
					 * Reg 202: bit 7-6: Length multiplier field (Copper or active cable).
					 * Reg 202: bit 5-0: Link length base value in meters.
					 *   To calculate actual link length use multiplier in bits 7-6.
					 */
	u8 connector;                   /* Reg 203: Type of connector present in the module. See SFF-8024 for codes */
	u8 copper_cable_attenuation[6]; /* Reg 204-209: Copper Cable Attenuation */
	u8 near_end_implementation;     /* Reg 210: Cable Assembly Lane Information, Near end implementation */
	u8 far_end_config;              /* Reg 211: Cable Assembly Lane Information: Far End Configuration */
	u8 media_technology;            /* Reg 212: Media Interface Technology encodings */
	u8 resv0[43];                   /* Reg 213-255 */
} qsfp_cmis_upper_page_00_s;

typedef struct {
	u8 firmware_rev[2];             /* Reg 128-129: Numeric representation of inactive module firmware revision */
	u8 hardware_rev[2];             /* Reg 130-131: Numeric representation of module hardware revision */
	u8 smf_len_km;                  /*
					 * Reg 132: bit 7-6: Link length multiplier for SMF fiber.
					 *   00 = 0.1 (1 t0 6.3 km)
					 *   01 = 1 (1 to 63 km)
					 *   10, 11 = reserved
					 * Reg 132: bit 5-0: Base link length for SMF fiber.
					 *   Must be multiplied by value in bits 7-6 to calculate actual link length in km.
					 */
	u8 om5_len;                     /* Reg 133: Link length supported for OM5 fiber, units of 2 m */
	u8 om4_len;                     /* Reg 134: Link length supported for OM4 fiber, units of 2 m */
	u8 om3_len;                     /* Reg 135: Link length supported for EBW 50/125 µm fiber (OM3), units of 2m */
	u8 om2_len;                     /* Reg 136: Link length supported for 50/125 µm fiber (OM2), units of 1m */
	u8 resv0;                       /* Reg 137: Reserved */
	u8 wavelength[2];               /* Reg 138-139: Nominal laser wavelength (Wavelength = value / 20 in nm) */
	u8 wavelength_tolerance[2];     /*
					 * Reg 140-141: Guaranteed range of laser wavelength (+/- value)
					 * from Nominal wavelength.(Wavelength Tol. = value/200 in nm).
					 */
	u8 pages_implement;             /* Reg 142: Implemented pages advertising */
	u8 resv1[16];                   /* Reg 143-158 */
	u8 monitor_implement[2];        /*
					 * Reg 159-160: Implemented Monitors Advertisement.
					 * Reg 159: bit 7-6: Reserved.
					 *          bit 5: Custom monitor implemented
					 *          bit 4-2: Aux3 ~ Aux1 monitor implemented
					 *          bit 1: Internal 3.3 Volts monitor implemented
					 *          bit 0: Temperature monitor implemented
					 * Reg 160: bit 7-5: Reserved.
					 *          bit 4-3: Tx Bias current measurement and threshold multiplier.
					 *                   00b = multiply x1
					 *                   01b = multiply x2
					 *                   10b = multiply x4
					 *                   11b = reserved
					 *          bit 2: Rx Optical Input Power monitor implemented
					 *          bit 1: Tx Output Optical Power monitor implemented
					 *          bit 0: Tx Bias monitor implemented
					 */
	u8 resv2[95];                   /* Reg 161-255 */
} qsfp_cmis_upper_page_01_s;

typedef struct {
	u8 temperature_high_alarm[2];   /* Reg 128-129: Threshold for internally measured temperature monitor */
	u8 temperature_low_alarm[2];    /* Reg 130-131: Threshold for internally measured temperature monitor */
	u8 temperature_high_warn[2];    /* Reg 132-133: Threshold for internally measured temperature monitor */
	u8 temperature_low_warn[2];     /* Reg 134-135: Threshold for internally measured temperature monitor */
	u8 volt_high_alarm[2];          /*
					 * Reg 136-137: Thresholds for internally measured 3.3 volt
					 * input supply voltage: in 100 µV increments.
					 */
	u8 volt_low_alarm[2];           /*
					 * Reg 138-139:Thresholds for internally measured 3.3 volt
					 * input supply voltage: in 100 µV increments.
					 */
	u8 volt_high_warn[2];           /*
					 * Reg 140-141: Thresholds for internally measured 3.3 volt
					 * input supply voltage: in 100 µV increments.
					 */
	u8 volt_low_warn[2];            /*
					 * Reg 142-143: Thresholds for internally measured 3.3 volt
					 * input supply voltage: in 100 µV increments.
					 */
	u8 resv0[32];                   /* Reg 144-175: Upper Memory: Page 02H */
	u8 tx_power_high_alarm[2];      /* Reg 176-177: Threshold for Tx optical power monitor */
	u8 tx_power_low_alarm[2];       /* Reg 178-179: Threshold for Tx optical power monitor */
	u8 tx_power_high_warn[2];       /* Reg 180-181: Threshold for Tx optical power monitor */
	u8 tx_power_low_warn[2];        /* Reg 182-183: Threshold for Tx optical power monitor */
	u8 tx_bias_high_alarm[2];       /*
					 * Reg 184-185: Threshold for Tx bias monitor: unsigned inter in 2uA increments,
					 * times the multiplier from Table 8-33.
					 */
	u8 tx_bias_low_alarm[2];        /*
					 * Reg 186-187: Threshold for Tx bias monitor: unsigned inter in 2uA increments,
					 * times the multiplier from Table 8-33.
					 */
	u8 tx_bias_high_warn[2];        /*
					 * Reg 188-189: Threshold for Tx bias monitor: unsigned inter in 2uA increments,
					 * times the multiplier from Table 8-33.
					 */
	u8 tx_bias_low_warn[2];         /*
					 * Reg 190-191: Threshold for Tx bias monitor: unsigned inter in 2uA increments,
					 * times the multiplier from Table 8-33.
					 */
	u8 rx_power_high_alarm[2];      /* Reg 192-193: Threshold for Rx optical power monitor */
	u8 rx_power_low_alarm[2];       /* Reg 194-195: Threshold for Rx optical power monitor */
	u8 rx_power_high_warn[2];       /* Reg 196-197: Threshold for Rx optical power monitor */
	u8 rx_power_low_warn[2];        /* Reg 198-199: Threshold for Rx optical power monitor */
	u8 resv1[56];                   /* Reg 200-255 */
} qsfp_cmis_upper_page_02_s;

typedef struct {
	u8 resv0[2];                    /* Reg 128-129: Upper Memory: Page 10H */
	u8 tx_disable;                  /* Reg 130: Tx disable, 0b=enabled, 1b=disabled */
	u8 resv1[125];                  /* Reg 131-255 */
} qsfp_cmis_upper_page_10_s;

typedef struct {
	u8 resv0[7];                    /* Reg 128-134: Upper Memory: Page 11H */
	u8 tx_fault;                    /* Reg 135: Latched Tx Fault flag, media lane 1 ~ 8 */
	u8 tx_los;                      /* Reg 136: Latched Tx LOS flag, lane 1 ~ 8 */
	u8 tx_cdr_lol;                  /* Reg 137: Latched Tx CDR LOL flag, lane 1 ~ 8 */
	u8 resv1[9];                    /* Reg 138-146 */
	u8 rx_los;                      /* Reg 147: Latched Rx LOS flag, media lane 1 ~ 8. Clear on Read */
	u8 rx_cdr_lol;                  /* Reg 148: Latched Rx CDR LOL flag, media lane 1 ~ 8. Clear on Read */
	u8 resv2[5];                    /* Reg 149-153 */
	u8 tx_power[16];                /* Reg 154-169: Internally measured Tx output optical power */
	u8 tx_bias[16];                 /*
					 * Reg 170-185: Internally measured Tx bias current monitor: unsinged integer
					 * in 2uA increments, times the multiplier from Table 8-33(Page 01H: Reg 160).
					 */
	u8 rx_power[16];                /* Reg 186-201: Internally measured Rx input optical power */
	u8 resv3[54];                   /* Reg 202-255 */
} qsfp_cmis_upper_page_11_s;

typedef struct {
	u8 resv0[2];                            /* Reg 128-129: Upper Memory: Page 13H */
	u8 diagnostic_reporting_capabilities;   /* Reg 130: The diagnostic reporting capabilities of the module are advertised */
	u8 resv1[125];                          /* Reg 131-255 */
} qsfp_cmis_upper_page_13_s;

#define CMIS_LANE_NUM                       8
typedef struct ber_lane_s {
	u8 ber[CMIS_LANE_NUM][2];
} ber_lane;

typedef struct {
	u8 diagnostics_selector;                /* Reg 128: This selects the content of the data in bytes 192-255: Page 14H */
	u8 resv0;                               /* Reg 129 */
	u8 custom[2];                           /* Reg 130-131 */
	u8 latched_diagnostics_flags[8];        /* Reg 132-139 */
	u8 resv1[52];                           /* Reg 140-191 */
	union {
		u8 contents[64];
		struct {
			u8 host_peak_detect_lane1[2];   /* Reg 192-193 */
			u8 host_peak_detect_lane2[2];
			u8 host_peak_detect_lane3[2];
			u8 host_peak_detect_lane4[2];
			u8 host_peak_detect_lane5[2];
			u8 host_peak_detect_lane6[2];
			u8 host_peak_detect_lane7[2];
			u8 host_peak_detect_lane8[2];
			u8 host_snr_lane1[2];           /* Reg 208-209 */
			u8 host_snr_lane2[2];
			u8 host_snr_lane3[2];
			u8 host_snr_lane4[2];
			u8 host_snr_lane5[2];
			u8 host_snr_lane6[2];
			u8 host_snr_lane7[2];
			u8 host_snr_lane8[2];
			u8 media_peak_detect_lane1[2];  /* Reg 224-225 */
			u8 media_peak_detect_lane2[2];
			u8 media_peak_detect_lane3[2];
			u8 media_peak_detect_lane4[2];
			u8 media_peak_detect_lane5[2];
			u8 media_peak_detect_lane6[2];
			u8 media_peak_detect_lane7[2];
			u8 media_peak_detect_lane8[2];
			u8 media_snr_lane1[2];          /* Reg 240-241 */
			u8 media_snr_lane2[2];
			u8 media_snr_lane3[2];
			u8 media_snr_lane4[2];
			u8 media_snr_lane5[2];
			u8 media_snr_lane6[2];
			u8 media_snr_lane7[2];
			u8 media_snr_lane8[2];
		} snr_and_peak_detect;

		struct {
			ber_lane host_ber;              /* Reg 192-193 */
			ber_lane media_ber;             /* Reg 208-209 */
		} host_and_media_ber;
	} err_info;                             /* Reg 192-255: Contents defined by Diagnostics Selector */
} qsfp_cmis_upper_page_14_s;

typedef struct {
	u8 resv0[8];                            /* Reg 128-135: Upper Memory: Page 9FH */
	union {
		u8 val[120];                        /* Reg 136-255: LPL PM data 120 bytes */
		cdb_pam4_ltp_6bytes ltp6[8];        /* Reg 136-183: LPL PM data: lane1~8 PAM4 LTP, Each LTP contains 6 bytes of data. */
		cdb_pam4_ltp_8bytes ltp8[8];        /* Reg 136-199: LPL PM data: lane1~8 PAM4 LTP, Each LTP contains 8 bytes of data. */
		cdb_dirt_detection dirt0;           /* Reg 136-255: Report maximum reflection, second largest reflection, farthest reflection and TX optical port detection info. */
	} lpl_pm_data;
} qsfp_cmis_upper_page_9f_s;

typedef struct {
	u8 resv0[16];                           /* Reg 128-143: Upper Memory: Page B7H */
	u8 ret_loss_status[8];                  /* Reg 144-151: Optical link return loss detection status on lane 1~8 */
	u8 ret_loss_overview;                   /* Reg 152: Optical link return loss detection overview */
	u8 resv1[103];                          /* Reg 153-255 */
} qsfp_cmis_upper_page_b7_s;

/* The default byte order (storage order) of numeric data types is defined in section 8.1.3.5 (big endian). In the case of non-default storage order (little endian), the non-default byte order must be explicitly specified. */
typedef struct {
	qsfp_cmis_lower_page_00_s lower_page_00;    /* QSFP-DD-CMIS lower page 00 128-byte data */
	qsfp_cmis_upper_page_00_s upper_page_00;    /* QSFP-DD-CMIS upper page 00 128-byte data */
	qsfp_cmis_upper_page_01_s upper_page_01;    /* QSFP-DD-CMIS upper page 01 128-byte data */
	qsfp_cmis_upper_page_02_s upper_page_02;    /* QSFP-DD-CMIS upper page 02 128-byte data */
	qsfp_cmis_upper_page_10_s upper_page_10;    /* QSFP-DD-CMIS upper page 10 128-byte data */
	qsfp_cmis_upper_page_11_s upper_page_11;    /* QSFP-DD-CMIS upper page 11 128-byte data */
	qsfp_cmis_upper_page_13_s upper_page_13;    /* QSFP-DD-CMIS upper page 13 128-byte data */
	qsfp_cmis_upper_page_14_s upper_page_14;    /* QSFP-DD-CMIS upper page 14 128-byte data */
	qsfp_cmis_upper_page_9f_s upper_page_9f;    /* QSFP-DD-CMIS upper page 9f 128-byte data */
	qsfp_cmis_upper_page_b7_s upper_page_b7;    /* QSFP-DD-CMIS upper page b7 128-byte data */
} qsfp_cmis_info_s;

#define MGMT_TLV_U8_SIZE        1
#define MGMT_TLV_U16_SIZE       2
#define MGMT_TLV_U32_SIZE       4

#define MGMT_TLV_GET_U8(addr)          (*((u8 *)(void *)(addr)))
#define MGMT_TLV_SET_U8(addr, value)   ((*((u8 *)(void *)(addr))) = ((u8)(value)))

#define MGMT_TLV_GET_U16(addr)         (*((u16 *)(void *)(addr)))
#define MGMT_TLV_SET_U16(addr, value)  ((*((u16 *)(void *)(addr))) = ((u16)(value)))

#define MGMT_TLV_GET_U32(addr)         (*((u32 *)(void *)(addr)))
#define MGMT_TLV_SET_U32(addr, value)  ((*((u32 *)(void *)(addr))) = ((u32)(value)))

#endif
