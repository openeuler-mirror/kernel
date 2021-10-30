/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_CHIPITF_H
#define SPFC_CHIPITF_H

#include "unf_type.h"
#include "unf_log.h"
#include "spfc_utils.h"
#include "spfc_module.h"

#include "spfc_service.h"

/* CONF_API_CMND */
#define SPFC_MBOX_CONFIG_API (0x00)
#define SPFC_MBOX_CONFIG_API_STS (0xA0)

/* GET_CHIP_INFO_API_CMD */
#define SPFC_MBOX_GET_CHIP_INFO (0x01)
#define SPFC_MBOX_GET_CHIP_INFO_STS (0xA1)

/* PORT_RESET */
#define SPFC_MBOX_PORT_RESET (0x02)
#define SPFC_MBOX_PORT_RESET_STS (0xA2)

/* SFP_SWITCH_API_CMND */
#define SPFC_MBOX_PORT_SWITCH (0x03)
#define SPFC_MBOX_PORT_SWITCH_STS (0xA3)

/* CONF_AF_LOGIN_API_CMND */
#define SPFC_MBOX_CONFIG_LOGIN_API (0x06)
#define SPFC_MBOX_CONFIG_LOGIN_API_STS (0xA6)

/* BUFFER_CLEAR_DONE_CMND */
#define SPFC_MBOX_BUFFER_CLEAR_DONE (0x07)
#define SPFC_MBOX_BUFFER_CLEAR_DONE_STS (0xA7)

#define SPFC_MBOX_GET_UP_STATE (0x09)
#define SPFC_MBOX_GET_UP_STATE_STS (0xA9)

/* GET CLEAR DONE STATE */
#define SPFC_MBOX_GET_CLEAR_STATE (0x0E)
#define SPFC_MBOX_GET_CLEAR_STATE_STS (0xAE)

/* CONFIG TIMER */
#define SPFC_MBOX_CONFIG_TIMER (0x10)
#define SPFC_MBOX_CONFIG_TIMER_STS (0xB0)

/* Led Test */
#define SPFC_MBOX_LED_TEST (0x12)
#define SPFC_MBOX_LED_TEST_STS (0xB2)

/* set esch */
#define SPFC_MBOX_SET_ESCH (0x13)
#define SPFC_MBOX_SET_ESCH_STS (0xB3)

/* set get tx serdes */
#define SPFC_MBOX_SET_GET_SERDES_TX (0x14)
#define SPFC_MBOX_SET_GET_SERDES_TX_STS (0xB4)

/* get rx serdes */
#define SPFC_MBOX_GET_SERDES_RX (0x15)
#define SPFC_MBOX_GET_SERDES_RX_STS (0xB5)

/* i2c read write */
#define SPFC_MBOX_I2C_WR_RD (0x16)
#define SPFC_MBOX_I2C_WR_RD_STS (0xB6)

/* GET UCODE STATS CMD */
#define SPFC_MBOX_GET_UCODE_STAT (0x18)
#define SPFC_MBOX_GET_UCODE_STAT_STS (0xB8)

/* gpio read write */
#define SPFC_MBOX_GPIO_WR_RD (0x19)
#define SPFC_MBOX_GPIO_WR_RD_STS (0xB9)

#define SPFC_MBOX_SEND_DEFAULT_SQ_INFO (0x26)
#define SPFC_MBOX_SEND_DEFAULT_SQ_INFO_STS (0xc6)

/* FC: DRV->UP */
#define SPFC_MBOX_SEND_ELS_CMD (0x2A)
#define SPFC_MBOX_SEND_VPORT_INFO (0x2B)

/* FC: UP->DRV */
#define SPFC_MBOX_RECV_FC_LINKUP (0x40)
#define SPFC_MBOX_RECV_FC_LINKDOWN (0x41)
#define SPFC_MBOX_RECV_FC_DELCMD (0x42)
#define SPFC_MBOX_RECV_FC_ERROR (0x43)

#define LOOP_MAP_VALID (1)
#define LOOP_MAP_INVALID (0)

#define SPFC_MBOX_SIZE (1024)
#define SPFC_MBOX_HEADER_SIZE (4)

#define UNDEFINEOPCODE (0)

#define VALUEMASK_L 0x00000000FFFFFFFF
#define VALUEMASK_H 0xFFFFFFFF00000000

#define STATUS_OK (0)
#define STATUS_FAIL (1)

enum spfc_drv2up_unblock_msg_cmd_code {
	SPFC_SEND_ELS_CMD,
	SPFC_SEND_ELS_CMD_FAIL,
	SPFC_RCV_ELS_CMD_RSP,
	SPFC_SEND_CONFIG_LOGINAPI,
	SPFC_SEND_CONFIG_LOGINAPI_FAIL,
	SPFC_RCV_CONFIG_LOGIN_API_RSP,
	SPFC_SEND_CLEAR_DONE,
	SPFC_SEND_CLEAR_DONE_FAIL,
	SPFC_RCV_CLEAR_DONE_RSP,
	SPFC_SEND_VPORT_INFO_DONE,
	SPFC_SEND_VPORT_INFO_FAIL,
	SPFC_SEND_VPORT_INFO_RSP,
	SPFC_MBOX_CMD_BUTT
};

/* up to dirver cmd code */
enum spfc_up2drv_msg_cmd_code {
	SPFC_UP2DRV_MSG_CMD_LINKUP = 0x1,
	SPFC_UP2DRV_MSG_CMD_LINKDOWN = 0x2,
	SPFC_UP2DRV_MSG_CMD_BUTT
};

/* up to driver handle templete */
struct spfc_up2drv_msg_handle {
	u8 cmd;
	u32 (*spfc_msg_up2driver_handler)(struct spfc_hba_info *hba, void *buf_in);
};

/* tile to driver cmd code */
enum spfc_tile2drv_msg_cmd_code {
	SPFC_TILE2DRV_MSG_CMD_SCAN_DONE,
	SPFC_TILE2DRV_MSG_CMD_FLUSH_DONE,
	SPFC_TILE2DRV_MSG_CMD_BUTT
};

/* tile to driver handle templete */
struct spfc_tile2drv_msg_handle {
	u8 cmd;
	u32 (*spfc_msg_tile2driver_handler)(struct spfc_hba_info *hba, u8 cmd, u64 val);
};

/* Mbox Common Header */
struct spfc_mbox_header {
	u8 cmnd_type;
	u8 length;
	u8 port_id;
	u8 reserved;
};

/* open or close the sfp */
struct spfc_inmbox_port_switch {
	struct spfc_mbox_header header;
	u32 op_code : 8;
	u32 rsvd0 : 24;
	u32 rsvd1[6];
};

struct spfc_inmbox_send_vport_info {
	struct spfc_mbox_header header;

	u64 sys_port_wwn;
	u64 sys_node_name;

	u32 nport_id : 24;
	u32 vpi : 8;
};

struct spfc_outmbox_port_switch_sts {
	struct spfc_mbox_header header;

	u16 reserved1;
	u8 reserved2;
	u8 status;
};

/* config API */
struct spfc_inmbox_config_api {
	struct spfc_mbox_header header;

	u32 op_code : 8;
	u32 reserved1 : 24;

	u8 topy_mode;
	u8 sfp_speed;
	u8 max_speed;
	u8 hard_alpa;

	u8 port_name[UNF_WWN_LEN];

	u32 slave : 1;
	u32 auto_sneg : 1;
	u32 reserved2 : 30;

	u32 rx_6432g_bb_credit : 16; /* 160 */
	u32 rx_16g_bb_credit : 16;   /* 80 */
	u32 rx_84g_bb_credit : 16;   /* 50 */
	u32 rdy_cnt_bf_fst_frm : 16; /* 8 */

	u32 esch_32g_value;
	u32 esch_16g_value;
	u32 esch_8g_value;
	u32 esch_4g_value;
	u32 esch_64g_value;
	u32 esch_bust_size;
};

struct spfc_outmbox_config_api_sts {
	struct spfc_mbox_header header;
	u16 reserved1;
	u8 reserved2;
	u8 status;
};

/* Get chip info */
struct spfc_inmbox_get_chip_info {
	struct spfc_mbox_header header;
};

struct spfc_outmbox_get_chip_info_sts {
	struct spfc_mbox_header header;
	u8 status;
	u8 board_type;
	u8 rvsd0[2];
	u64 wwpn;
	u64 wwnn;
	u64 rsvd1;
};

/* Get reg info */
struct spfc_inmbox_get_reg_info {
	struct spfc_mbox_header header;
	u32 op_code : 1;
	u32 reg_len : 8;
	u32 rsvd1 : 23;
	u32 reg_addr;
	u32 reg_value_l32;
	u32 reg_value_h32;
	u32 rsvd2[27];
};

/* Get reg info sts */
struct spfc_outmbox_get_reg_info_sts {
	struct spfc_mbox_header header;

	u16 rsvd0;
	u8 rsvd1;
	u8 status;
	u32 reg_value_l32;
	u32 reg_value_h32;
	u32 rsvd2[28];
};

/* Config login API */
struct spfc_inmbox_config_login {
	struct spfc_mbox_header header;

	u32 op_code : 8;
	u32 reserved1 : 24;

	u16 tx_bb_credit;
	u16 reserved2;

	u32 rtov;
	u32 etov;

	u32 rt_tov_tag : 1;
	u32 ed_tov_tag : 1;
	u32 bb_credit : 6;
	u32 bb_scn : 8;
	u32 lr_flag : 16;
};

struct spfc_outmbox_config_login_sts {
	struct spfc_mbox_header header;

	u16 reserved1;
	u8 reserved2;
	u8 status;
};

/* port reset */
#define SPFC_MBOX_SUBTYPE_LIGHT_RESET (0x0)
#define SPFC_MBOX_SUBTYPE_HEAVY_RESET (0x1)

struct spfc_inmbox_port_reset {
	struct spfc_mbox_header header;

	u32 op_code : 8;
	u32 reserved : 24;
};

struct spfc_outmbox_port_reset_sts {
	struct spfc_mbox_header header;

	u16 reserved1;
	u8 reserved2;
	u8 status;
};

/* led test */
struct spfc_inmbox_led_test {
	struct spfc_mbox_header header;

	/* 0->act type;1->low speed;1->high speed */
	u8 led_type;
	/* 0:twinkle;1:light on;2:light off;0xff:defalut */
	u8 led_mode;
	u8 resvd[ARRAY_INDEX_2];
};

struct spfc_outmbox_led_test_sts {
	struct spfc_mbox_header header;

	u16 rsvd1;
	u8 rsvd2;
	u8 status;
};

/* set esch */
struct spfc_inmbox_set_esch {
	struct spfc_mbox_header header;

	u32 esch_value;
	u32 esch_bust_size;
};

struct spfc_outmbox_set_esch_sts {
	struct spfc_mbox_header header;

	u16 rsvd1;
	u8 rsvd2;
	u8 status;
};

struct spfc_inmbox_set_serdes_tx {
	struct spfc_mbox_header header;

	u8 swing;	  /* amplitude setting */
	char serdes_pre1; /* pre1 setting */
	char serdes_pre2; /* pre2 setting */
	char serdes_post; /* post setting */
	u8 serdes_main;	  /* main setting */
	u8 op_code;	  /* opcode,0:setting;1:read */
	u8 rsvd[ARRAY_INDEX_2];
};

struct spfc_outmbox_set_serdes_tx_sts {
	struct spfc_mbox_header header;
	u16 rvsd0;
	u8 rvsd1;
	u8 status;
	u8 swing;
	char serdes_pre1;
	char serdes_pre2;
	char serdes_post;
	u8 serdes_main;
	u8 rsvd2[ARRAY_INDEX_3];
};

struct spfc_inmbox_i2c_wr_rd {
	struct spfc_mbox_header header;
	u8 op_code; /* 0 write, 1 read */
	u8 rsvd[ARRAY_INDEX_3];

	u32 dev_addr;
	u32 offset;
	u32 wr_data;
};

struct spfc_outmbox_i2c_wr_rd_sts {
	struct spfc_mbox_header header;
	u8 status;
	u8 resvd[ARRAY_INDEX_3];

	u32 rd_data;
};

struct spfc_inmbox_gpio_wr_rd {
	struct spfc_mbox_header header;
	u8 op_code; /* 0 write,1 read */
	u8 rsvd[ARRAY_INDEX_3];

	u32 pin;
	u32 wr_data;
};

struct spfc_outmbox_gpio_wr_rd_sts {
	struct spfc_mbox_header header;
	u8 status;
	u8 resvd[ARRAY_INDEX_3];

	u32 rd_data;
};

struct spfc_inmbox_get_serdes_rx {
	struct spfc_mbox_header header;

	u8 op_code;
	u8 h16_macro;
	u8 h16_lane;
	u8 rsvd;
};

struct spfc_inmbox_get_serdes_rx_sts {
	struct spfc_mbox_header header;
	u16 rvsd0;
	u8 rvsd1;
	u8 status;
	int left_eye;
	int right_eye;
	int low_eye;
	int high_eye;
};

struct spfc_ser_op_m_l {
	u8 op_code;
	u8 h16_macro;
	u8 h16_lane;
	u8 rsvd;
};

/* get sfp info */
#define SPFC_MBOX_GET_SFP_INFO_MB_LENGTH 1
#define OFFSET_TWO_DWORD 2
#define OFFSET_ONE_DWORD 1

struct spfc_inmbox_get_sfp_info {
	struct spfc_mbox_header header;
};

struct spfc_outmbox_get_sfp_info_sts {
	struct spfc_mbox_header header;

	u32 rcvd : 8;
	u32 length : 16;
	u32 status : 8;
};

/* get ucode stats */
#define SPFC_UCODE_STAT_NUM 64

struct spfc_outmbox_get_ucode_stat {
	struct spfc_mbox_header header;
};

struct spfc_outmbox_get_ucode_stat_sts {
	struct spfc_mbox_header header;

	u16 rsvd;
	u8 rsvd2;
	u8 status;

	u32 ucode_stat[SPFC_UCODE_STAT_NUM];
};

/* uP-->Driver asyn event API */
struct spfc_link_event {
	struct spfc_mbox_header header;

	u8 link_event;
	u8 reason;
	u8 speed;
	u8 top_type;

	u8 alpa_value;
	u8 reserved1;
	u16 paticpate : 1;
	u16 ac_led : 1;
	u16 yellow_speed_led : 1;
	u16 green_speed_led : 1;
	u16 reserved2 : 12;

	u8 loop_map_info[128];
};

enum spfc_up_err_type {
	SPFC_UP_ERR_DRV_PARA = 0,
	SPFC_UP_ERR_SFP = 1,
	SPFC_UP_ERR_32G_PUB = 2,
	SPFC_UP_ERR_32G_UA = 3,
	SPFC_UP_ERR_32G_MAC = 4,
	SPFC_UP_ERR_NON32G_DFX = 5,
	SPFC_UP_ERR_NON32G_MAC = 6,
	SPFC_UP_ERR_BUTT

};

enum spfc_up_err_value {
	/* ERR type 0 */
	SPFC_DRV_2_UP_PARA_ERR = 0,

	/* ERR type 1 */
	SPFC_SFP_SPEED_ERR,

	/* ERR type 2 */
	SPFC_32GPUB_UA_RXESCH_FIFO_OF,
	SPFC_32GPUB_UA_RXESCH_FIFO_UCERR,

	/* ERR type 3 */
	SPFC_32G_UA_UATX_LEN_ABN,
	SPFC_32G_UA_RXAFIFO_OF,
	SPFC_32G_UA_TXAFIFO_OF,
	SPFC_32G_UA_RXAFIFO_UCERR,
	SPFC_32G_UA_TXAFIFO_UCERR,

	/* ERR type 4 */
	SPFC_32G_MAC_RX_BBC_FATAL,
	SPFC_32G_MAC_TX_BBC_FATAL,
	SPFC_32G_MAC_TXFIFO_UF,
	SPFC_32G_MAC_PCS_TXFIFO_UF,
	SPFC_32G_MAC_RXBBC_CRDT_TO,
	SPFC_32G_MAC_PCS_RXAFIFO_OF,
	SPFC_32G_MAC_PCS_TXFIFO_OF,
	SPFC_32G_MAC_FC2P_RXFIFO_OF,
	SPFC_32G_MAC_FC2P_TXFIFO_OF,
	SPFC_32G_MAC_FC2P_CAFIFO_OF,
	SPFC_32G_MAC_PCS_RXRSFECM_UCEER,
	SPFC_32G_MAC_PCS_RXAFIFO_UCEER,
	SPFC_32G_MAC_PCS_TXFIFO_UCEER,
	SPFC_32G_MAC_FC2P_RXFIFO_UCEER,
	SPFC_32G_MAC_FC2P_TXFIFO_UCEER,

	/* ERR type 5 */
	SPFC_NON32G_DFX_FC1_DFX_BF_FIFO,
	SPFC_NON32G_DFX_FC1_DFX_BP_FIFO,
	SPFC_NON32G_DFX_FC1_DFX_RX_AFIFO_ERR,
	SPFC_NON32G_DFX_FC1_DFX_TX_AFIFO_ERR,
	SPFC_NON32G_DFX_FC1_DFX_DIRQ_RXBUF_FIFO1,
	SPFC_NON32G_DFX_FC1_DFX_DIRQ_RXBBC_TO,
	SPFC_NON32G_DFX_FC1_DFX_DIRQ_TXDAT_FIFO,
	SPFC_NON32G_DFX_FC1_DFX_DIRQ_TXCMD_FIFO,
	SPFC_NON32G_DFX_FC1_ERR_R_RDY,

	/* ERR type 6 */
	SPFC_NON32G_MAC_FC1_FAIRNESS_ERROR,

	SPFC_ERR_VALUE_BUTT

};

struct spfc_up_error_event {
	struct spfc_mbox_header header;

	u8 link_event;
	u8 error_level;
	u8 error_type;
	u8 error_value;
};

struct spfc_inmbox_clear_done {
	struct spfc_mbox_header header;
};

/* receive els cmd */
struct spfc_inmbox_rcv_els {
	struct spfc_mbox_header header;
	u16 pkt_type;
	u16 pkt_len;
	u8 frame[ARRAY_INDEX_0];
};

/* FCF event type */
enum spfc_fcf_event_type {
	SPFC_FCF_SELECTED = 0,
	SPFC_FCF_DEAD,
	SPFC_FCF_CLEAR_VLINK,
	SPFC_FCF_CLEAR_VLINK_APPOINTED
};

struct spfc_nport_id_info {
	u32 nport_id : 24;
	u32 vp_index : 8;
};

struct spfc_inmbox_fcf_event {
	struct spfc_mbox_header header;

	u8 fcf_map[ARRAY_INDEX_3];
	u8 event_type;

	u8 fcf_mac_h4[ARRAY_INDEX_4];

	u16 vlan_info;
	u8 fcf_mac_l2[ARRAY_INDEX_2];

	struct spfc_nport_id_info nport_id_info[UNF_SPFC_MAXNPIV_NUM + 1];
};

/* send els cmd */
struct spfc_inmbox_send_els {
	struct spfc_mbox_header header;

	u8 oper_code;
	u8 rsvd[ARRAY_INDEX_3];

	u8 resvd;
	u8 els_cmd_type;
	u16 pkt_len;

	u8 fcf_mac_h4[ARRAY_INDEX_4];

	u16 vlan_info;
	u8 fcf_mac_l2[ARRAY_INDEX_2];

	u8 fc_frame[SPFC_FC_HEAD_LEN + UNF_FLOGI_PAYLOAD_LEN];
};

struct spfc_inmbox_send_els_sts {
	struct spfc_mbox_header header;

	u16 rx_id;
	u16 err_code;

	u16 ox_id;
	u16 rsvd;
};

struct spfc_inmbox_get_clear_state {
	struct spfc_mbox_header header;
	u32 resvd[31];
};

struct spfc_outmbox_get_clear_state_sts {
	struct spfc_mbox_header header;
	u16 rsvd1;
	u8 state;  /* 1--clear doing. 0---clear done. */
	u8 status; /* 0--ok,!0---fail */
	u32 rsvd2[30];
};

#define SPFC_FIP_MODE_VN2VF (0)
#define SPFC_FIP_MODE_VN2VN (1)

/* get up state */
struct spfc_inmbox_get_up_state {
	struct spfc_mbox_header header;

	u64 cur_jiff_time;
};

/* get port state */
struct spfc_inmbox_get_port_info {
	struct spfc_mbox_header header;
};

struct spfc_outmbox_get_up_state_sts {
	struct spfc_mbox_header header;

	u8 status;
	u8 rsv0;
	u16 rsv1;
	struct unf_port_dynamic_info dymic_info;
};

struct spfc_outmbox_get_port_info_sts {
	struct spfc_mbox_header header;

	u32 status : 8;
	u32 fe_16g_cvis_tts : 8;
	u32 bb_scn : 8;
	u32 loop_credit : 8;

	u32 non_loop_rx_credit : 8;
	u32 non_loop_tx_credit : 8;
	u32 sfp_speed : 8;
	u32 present : 8;
};

struct spfc_inmbox_config_timer {
	struct spfc_mbox_header header;

	u16 op_code;
	u16 fun_id;
	u32 user_data;
};

struct spfc_inmbox_config_srqc {
	struct spfc_mbox_header header;

	u16 valid;
	u16 fun_id;
	u32 srqc_gpa_hi;
	u32 srqc_gpa_lo;
};

struct spfc_outmbox_config_timer_sts {
	struct spfc_mbox_header header;

	u8 status;
	u8 rsv[ARRAY_INDEX_3];
};

struct spfc_outmbox_config_srqc_sts {
	struct spfc_mbox_header header;

	u8 status;
	u8 rsv[ARRAY_INDEX_3];
};

struct spfc_inmbox_default_sq_info {
	struct spfc_mbox_header header;
	u32 sq_cid;
	u32 sq_xid;
	u16 func_id;
	u16 valid;
};

struct spfc_outmbox_default_sq_info_sts {
	struct spfc_mbox_header header;
	u8 status;
	u8 rsv[ARRAY_INDEX_3];
};

/* Generic Inmailbox and Outmailbox */
union spfc_inmbox_generic {
	struct {
		struct spfc_mbox_header header;
		u32 rsvd[(SPFC_MBOX_SIZE - SPFC_MBOX_HEADER_SIZE) / sizeof(u32)];
	} generic;

	struct spfc_inmbox_port_switch port_switch;
	struct spfc_inmbox_config_api config_api;
	struct spfc_inmbox_get_chip_info get_chip_info;
	struct spfc_inmbox_config_login config_login;
	struct spfc_inmbox_port_reset port_reset;
	struct spfc_inmbox_set_esch esch_set;
	struct spfc_inmbox_led_test led_test;
	struct spfc_inmbox_get_sfp_info get_sfp_info;
	struct spfc_inmbox_clear_done clear_done;
	struct spfc_outmbox_get_ucode_stat get_ucode_stat;
	struct spfc_inmbox_get_clear_state get_clr_state;
	struct spfc_inmbox_send_vport_info send_vport_info;
	struct spfc_inmbox_get_up_state get_up_state;
	struct spfc_inmbox_config_timer timer_config;
	struct spfc_inmbox_config_srqc config_srqc;
	struct spfc_inmbox_get_port_info get_port_info;
};

union spfc_outmbox_generic {
	struct {
		struct spfc_mbox_header header;
		u32 rsvd[(SPFC_MBOX_SIZE - SPFC_MBOX_HEADER_SIZE) / sizeof(u32)];
	} generic;

	struct spfc_outmbox_port_switch_sts port_switch_sts;
	struct spfc_outmbox_config_api_sts config_api_sts;
	struct spfc_outmbox_get_chip_info_sts get_chip_info_sts;
	struct spfc_outmbox_get_reg_info_sts get_reg_info_sts;
	struct spfc_outmbox_config_login_sts config_login_sts;
	struct spfc_outmbox_port_reset_sts port_reset_sts;
	struct spfc_outmbox_led_test_sts led_test_sts;
	struct spfc_outmbox_set_esch_sts esch_set_sts;
	struct spfc_inmbox_get_serdes_rx_sts serdes_rx_get_sts;
	struct spfc_outmbox_set_serdes_tx_sts serdes_tx_set_sts;
	struct spfc_outmbox_i2c_wr_rd_sts i2c_wr_rd_sts;
	struct spfc_outmbox_gpio_wr_rd_sts gpio_wr_rd_sts;
	struct spfc_outmbox_get_sfp_info_sts get_sfp_info_sts;
	struct spfc_outmbox_get_ucode_stat_sts get_ucode_stat_sts;
	struct spfc_outmbox_get_clear_state_sts get_clr_state_sts;
	struct spfc_outmbox_get_up_state_sts get_up_state_sts;
	struct spfc_outmbox_config_timer_sts timer_config_sts;
	struct spfc_outmbox_config_srqc_sts config_srqc_sts;
	struct spfc_outmbox_get_port_info_sts get_port_info_sts;
	struct spfc_outmbox_default_sq_info_sts default_sq_sts;
};

u32 spfc_get_chip_msg(void *hba, void *mac);
u32 spfc_config_port_table(struct spfc_hba_info *hba);
u32 spfc_port_switch(struct spfc_hba_info *hba, bool turn_on);
u32 spfc_get_loop_map(void *hba, void *buf);
u32 spfc_get_workable_bb_credit(void *hba, void *bb_credit);
u32 spfc_get_workable_bb_scn(void *hba, void *bb_scn);
u32 spfc_get_port_current_info(void *hba, void *port_info);
u32 spfc_get_port_fec(void *hba, void *para_out);

u32 spfc_get_loop_alpa(void *hba, void *alpa);
u32 spfc_get_topo_act(void *hba, void *topo_act);
u32 spfc_config_login_api(struct spfc_hba_info *hba, struct unf_port_login_parms *login_parms);
u32 spfc_mb_send_and_wait_mbox(struct spfc_hba_info *hba, const void *in_mbox, u16 in_size,
			       union spfc_outmbox_generic *out_mbox);
void spfc_up_msg2driver_proc(void *hwdev_handle, void *pri_handle, u16 cmd,
			     void *buf_in, u16 in_size, void *buf_out, u16 *out_size);

u32 spfc_mb_reset_chip(struct spfc_hba_info *hba, u8 sub_type);
u32 spfc_clear_sq_wqe_done(struct spfc_hba_info *hba);
u32 spfc_update_fabric_param(void *hba, void *para_in);
u32 spfc_update_port_param(void *hba, void *para_in);
u32 spfc_update_fdisc_param(void *hba, void *vport_info);
u32 spfc_mbx_get_fw_clear_stat(struct spfc_hba_info *hba, u32 *clear_state);
u32 spfc_get_chip_capability(void *hwdev_handle, struct spfc_chip_info *chip_info);
u32 spfc_mbx_config_default_session(void *hba, u32 flag);

#endif
