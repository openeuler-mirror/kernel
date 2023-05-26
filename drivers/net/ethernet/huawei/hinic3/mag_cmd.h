/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: serdes/mag cmd definition between driver and mpu
 * Author: ETH group
 * Create: 2021-07-30
 */

#ifndef MAG_CMD_H
#define MAG_CMD_H

#include "mgmt_msg_base.h"

/* serdes/mag消息命令字定义 */
enum mag_cmd {
	/* serdes命令字，统一封装所有serdes命令 */
	SERDES_CMD_PROCESS = 0,

	/* mag命令字，按功能划分 */
	/* 端口配置相关 0-29 */
	MAG_CMD_SET_PORT_CFG = 1,
	MAG_CMD_SET_PORT_ADAPT = 2,
	MAG_CMD_CFG_LOOPBACK_MODE = 3,

	MAG_CMD_GET_PORT_ENABLE = 5,
	MAG_CMD_SET_PORT_ENABLE = 6,
	MAG_CMD_GET_LINK_STATUS = 7,
	MAG_CMD_SET_LINK_FOLLOW = 8,
	MAG_CMD_SET_PMA_ENABLE = 9,
	MAG_CMD_CFG_FEC_MODE = 10,

	MAG_CMD_CFG_AN_TYPE = 12, /* reserved for future use */
	MAG_CMD_CFG_LINK_TIME = 13,

	MAG_CMD_SET_PANGEA_ADAPT = 15,

	/* bios link配置相关 30-49 */
	MAG_CMD_CFG_BIOS_LINK_CFG = 31,
	MAG_CMD_RESTORE_LINK_CFG = 32,
	MAG_CMD_ACTIVATE_BIOS_LINK_CFG = 33,

	/* 光模块、LED、PHY等外设配置管理 50-99 */
	/* LED */
	MAG_CMD_SET_LED_CFG = 50,

	/* PHY */
	MAG_CMD_GET_PHY_INIT_STATUS = 55, /* reserved for future use */

	/* 光模块 */
	MAG_CMD_GET_XSFP_INFO = 60,
	MAG_CMD_SET_XSFP_ENABLE = 61,
	MAG_CMD_GET_XSFP_PRESENT = 62,
	MAG_CMD_SET_XSFP_RW = 63, /* sfp/qsfp single byte read/write, for equipment test */
	MAG_CMD_CFG_XSFP_TEMPERATURE = 64,

	/* 事件上报 100-149 */
	MAG_CMD_WIRE_EVENT = 100,
	MAG_CMD_LINK_ERR_EVENT = 101,

	/* DFX、Counter相关 */
	MAG_CMD_EVENT_PORT_INFO = 150,
	MAG_CMD_GET_PORT_STAT = 151,
	MAG_CMD_CLR_PORT_STAT = 152,
	MAG_CMD_GET_PORT_INFO = 153,
	MAG_CMD_GET_PCS_ERR_CNT = 154,
	MAG_CMD_GET_MAG_CNT = 155,
	MAG_CMD_DUMP_ANTRAIN_INFO = 156,

	MAG_CMD_MAX = 0xFF
};

/* serdes cmd struct define */
#define CMD_ARRAY_BUF_SIZE 64
#define SERDES_CMD_DATA_BUF_SIZE 512
struct serdes_in_info {
	u32 chip_id : 16;
	u32 macro_id : 16;
	u32 start_sds_id : 16;
	u32 sds_num : 16;

	u32 cmd_type : 8; /* reserved for iotype */
	u32 sub_cmd : 8;
	u32 rw : 1; /* 0: read, 1: write */
	u32 rsvd : 15;

	u32 val;
	union {
		char field[CMD_ARRAY_BUF_SIZE];
		u32 addr;
		u8 *ex_param;
	};
};

struct serdes_out_info {
	u32 str_len; /* out_str length */
	u32 result_offset;
	u32 type; /* 0:data; 1:string */
	char out_str[SERDES_CMD_DATA_BUF_SIZE];
};

struct serdes_cmd_in {
	struct mgmt_msg_head head;

	struct serdes_in_info serdes_in;
};

struct serdes_cmd_out {
	struct mgmt_msg_head head;

	struct serdes_out_info serdes_out;
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
	WIRE_NODE_NUM
};

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
	u8 rsvd1[20];
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
	LINK_MODE_MAX_NUMBERS,

	LINK_MODE_UNKNOWN = 0xFFFF
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

#define CABLE_10GE_BASE_R_BIT LINK_MODE_10GE_BASE_R_BIT
#define CABLE_25GE_BASE_R_BIT (LINK_MODE_25GE_BASE_R_BIT | LINK_MODE_10GE_BASE_R_BIT)
#define CABLE_40GE_BASE_R4_BIT LINK_MODE_40GE_BASE_R4_BIT
#define CABLE_50GE_BASE_R_BIT (LINK_MODE_50GE_BASE_R_BIT | LINK_MODE_25GE_BASE_R_BIT | \
	LINK_MODE_10GE_BASE_R_BIT)
#define CABLE_50GE_BASE_R2_BIT LINK_MODE_50GE_BASE_R2_BIT
#define CABLE_100GE_BASE_R2_BIT (LINK_MODE_100GE_BASE_R2_BIT | LINK_MODE_50GE_BASE_R2_BIT)
#define CABLE_100GE_BASE_R4_BIT (LINK_MODE_100GE_BASE_R4_BIT | LINK_MODE_40GE_BASE_R4_BIT)
#define CABLE_200GE_BASE_R4_BIT (LINK_MODE_200GE_BASE_R4_BIT | LINK_MODE_100GE_BASE_R4_BIT | \
	LINK_MODE_40GE_BASE_R4_BIT)

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
	u8 rsvd2[8];
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
#define MAG_CMD_LP_MODE_MAC_TX2RX 5
#define MAG_CMD_LP_MODE_TXDP2RXDP 6
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
	u8 fec;
	u8 rsvd0;
};

struct mag_cmd_cfg_bios_link_cfg {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 opcode; /* 0:get bios link info  1:set bios link cfg */
	u8 clear;
	u8 rsvd0;

	u32 wire_type;
	u8 an_en;
	u8 speed;
	u8 fec;
	u8 rsvd1;
	u32 speed_mode;
	u32 rsvd2[3];
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
struct mag_cmd_set_xsfp_rw {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 operation; /* 0: read; 1: write */
	u8 value;
	u8 rsvd0;
	u32 devaddr;
	u32 offset;
	u32 rsvd1;
};

struct mag_cmd_cfg_xsfp_temperature {
	struct mgmt_msg_head head;

	u8 opcode; /* 0:read  1:write */
	u8 rsvd0[3];
	s32 max_temp;
	s32 min_temp;
};

struct mag_cmd_get_xsfp_temperature {
	struct mgmt_msg_head head;

	s16 sfp_temp[8];
	u8 rsvd[32];
	s32 max_temp;
	s32 min_temp;
};

/* xsfp plug event */
struct mag_cmd_wire_event {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 status; /* 0:present, 1:absent */
	u8 rsvd[2];
};

/* link err type definition */
#define MAG_CMD_ERR_XSFP_UNKNOWN 0x0
struct mag_cmd_link_err_event {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 link_err_type;
	u8 rsvd[2];
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
struct mag_cmd_event_port_info {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 event_type;
	u8 rsvd0[2];

	// 光模块相关
	u8 vendor_name[XSFP_VENDOR_NAME_LEN];
	u32 port_type;     /* fiber / copper */
	u32 port_sub_type; /* sr / lr */
	u32 cable_length;  /* 1/3/5m */
	u8 cable_temp;     /* 温度 */
	u8 max_speed;      /* 光模块最大速率 */
	u8 sfp_type;       /* sfp/qsfp */
	u8 rsvd1;
	u32 power[4]; /* 光功率 */

	u8 an_state;
	u8 fec;
	u16 speed;

	u8 gpio_insert; /* 0:present  1:absent */
	u8 alos;
	u8 rx_los;
	u8 pma_ctrl;

	u32 pma_fifo_reg;
	u32 pma_signal_ok_reg;
	u32 pcs_64_66b_reg;
	u32 rf_lf;
	u8 pcs_link;
	u8 pcs_mac_link;
	u8 tx_enable;
	u8 rx_enable;
	u32 pcs_err_cnt;

	u8 eq_data[38];
	u8 rsvd2[2];

	u32 his_link_machine_state;
	u32 cur_link_machine_state;
	u8 his_machine_state_data[128];
	u8 cur_machine_state_data[128];
	u8 his_machine_state_length;
	u8 cur_machine_state_length;

	struct mag_port_param_info param_info;
	u8 rsvd3[360];
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

#define MAG_SFP_PORT_NUM 24
/* 芯片光模块温度结构体定义 */
struct mag_cmd_sfp_temp_in_info {
	struct mgmt_msg_head head; /* 8B */
	u8 opt_type;               /* 0:read operation 1:cfg operation */
	u8 rsv[3];
	s32 max_temp; /* 芯片光模块阈值 */
	s32 min_temp; /* 芯片光模块阈值 */
};

struct mag_cmd_sfp_temp_out_info {
	struct mgmt_msg_head head;           /* 8B */
	s16 sfp_temp_data[MAG_SFP_PORT_NUM]; /* 读出的温度 */
	s32 max_temp;                        /* 芯片光模块阈值 */
	s32 min_temp;                        /* 芯片光模块阈值 */
};

#endif
