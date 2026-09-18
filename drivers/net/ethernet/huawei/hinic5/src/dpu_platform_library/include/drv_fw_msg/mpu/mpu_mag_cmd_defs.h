/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_mag_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/07/20
 * Last Modified : 2026/09/16
 * Description   : mpu mag cmd
 */

#ifndef MPU_MAG_CMD_DEFS_H
#define MPU_MAG_CMD_DEFS_H

#include "base_type.h"
#include "mpu_cmd_base_defs.h"

/* serdes cmd struct define */
#define CMD_ARRAY_BUF_SIZE 64
#define SERDES_CMD_DATA_BUF_SIZE 512
#define RX_RSFEC_PHY_DFX_STA_TBL_SIZE 25

#define VL_NUM      16
#define LANE_NUM    8

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

struct mag_cmd_ber_cor_cnt {
	u32 corr_lane_sym_cnt;
	u32 lane_cor0_cnt;
	u32 lane_cor1_cnt;
	u32 cfg_speed;
};

union mag_cmd_ber_data_u {
	struct mag_cmd_ber_cor_cnt cor_cnt;
	u32 data[RX_RSFEC_PHY_DFX_STA_TBL_SIZE];
};

struct mag_cmd_get_himac_ber {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 op_type;
	u8 rsvd0[2];

	union mag_cmd_ber_data_u ber_data;
};

struct mag_cmd_op_himac_thrd {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 op_type;
	u8 cur_status;
	u8 rsvd0;
};

struct mag_cmd_get_himac_bandwidth {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 txrx_sel;
	u8 rsvd0[2];
	u32 win_size;

	u64 rate_mbps;
	u64 packet_rate;
	u32 rate_byte_h;
	u32 rate_byte_l;
	u32 rate_pkt;
	u32 cal_time_us;
	u32 ipg;
};

struct mag_cmd_himac_prbs {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 direction;
	u8 prbs_type;
	u8 scr_en;

	u8 fec_link_status;
	u8 sync_status;
	u8 rsvd0[2];
	u32 cw_cnt;
	u32 err_cnt;
};

struct mag_cmd_wire_event {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 status; /* 0:present, 1:absent */
	u8 rsvd[2];
};

#define MAG_SFP_PORT_NUM 24
/* chip optical module temperature struct definition */
struct mag_cmd_sfp_temp_in_info {
	struct mgmt_msg_head head; /* 8B */
	u8 opt_type;               /* 0:read operation 1:cfg operation */
	u8 rsv[3];
	s32 max_temp; /* chip optical module threshold */
	s32 min_temp; /* chip optical module threshold */
};

struct mag_cmd_sfp_temp_out_info {
	struct mgmt_msg_head head;           /* 8B */
	s16 sfp_temp_data[MAG_SFP_PORT_NUM]; /* read temperature */
	s32 max_temp;                        /* chip optical module threshold */
	s32 min_temp;                        /* chip optical module threshold */
};

struct mgmt_tlv_info {
	u16 type;
	u16 length;
	u8 value[0]; // When value is page content, data composition: page_id(4byte) + page_context(128byte)
};

struct mag_bios_cfg {
	u8 speed;      /* enum of port speed */
	u8 auto_neg;   /* auto-negotiation switch 0 - field invalid 1 - on 2 - off */
	u8 lanes;      /* lane num */
	u8 fec;        /* FEC mode, refer to enum mag_cmd_port_fec */
	u8 auto_adapt; /* adaptive mode configuration 0 - invalid configuration 1 - enable 2 - disable */
};

struct speed_mode_map_s {
	u8 speed_mode;
	u32 real_speed;
};

typedef struct tag_mag_cmd_set_xsfp_tlv_req {
	struct mgmt_msg_head head;

    /*
     * Parse according to struct mgmt_tlv_info format.
     * +---------------------------------------------+
     * |        TYPE        |  LEN  |      VALUE     |
     * +--------------------+-------+----------------+
     * | MAG_XSFP_TYPE_PAGE |   4   |   Page Number  |
     * +---------------------------------------------+
     *
     * Notes:
     * 1. Page numbering definition: lower page 00h is numbered 0, upper page 00h is numbered 1, and so on.
     * 2. Specification: currently supports up to 10 Pages, among which: lower page 00h, upper page 00h/01h/02h/10h/11h are mandatory, and the remaining 4 are extension reserved.
     */
	u8 tlv_buf[0];
} mag_cmd_set_xsfp_tlv_req;

typedef struct tag_mag_cmd_get_xsfp_tlv_rsp {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd[3];

    /*
     * Assemble according to struct mgmt_tlv_info format.
     * +----------------------------------------------------------------------+
     * |          TYPE           |      LEN     |             VALUE           |
     * +-------------------------+--------------+-----------------------------+
     * | MAG_XSFP_TYPE_WIRE_TYPE |       4      |           Wire Type         |
     * +-------------------------+--------------+-----------------------------+
     * |    MAG_XSFP_TYPE_PAGE   | 4 + Page Len | Page Number + Page Content  |
     * +----------------------------------------------------------------------+
     *
     * Notes:
     * 1. Page numbering definition: lower page 00h is numbered 0, upper page 00h is numbered 1, and so on.
     * 2. The caller needs to allocate sufficient space (including space for the end Type and end Length).
     */
	u8 tlv_buf[0];
} mag_cmd_get_xsfp_tlv_rsp;

typedef struct tag_mag_cmd_set_xsfp_tlv_rsp {
	struct mgmt_msg_head head;
} mag_cmd_set_xsfp_tlv_rsp;

typedef struct tag_mag_cmd_get_xsfp_tlv_req {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd;
	u16 rsp_buf_len; /* In the response: buffer space length for storing TLV format data */
} mag_cmd_get_xsfp_tlv_req;

typedef struct {
	u32 ubmac_nl_id;
	u32 ubmac_port_id;

	u32 ubmac_port_info;                            // PORT_INFO
	u32 ubmac_port_link_sta;                        // PORT_LINK_STA
	u32 ubmac_phy_link_status_1;                    // PHY_LINK_STA_1
	u32 ubmac_phy_link_status_2;                    // PHY_LINK_STA_2
	u32 ubmac_phy_link_status_3;                    // PHY_LINK_STA_3
	u32 ubmac_phy_link_err_status;                  // PHY_LINK_ERR_STA
	u32 ubmac_fec_err_bit_num_low;                  // ST_MAC_FEC_ERR_BIT_NUM_LOW
	u32 ubmac_fec_err_bit_num_high;                 // ST_MAC_FEC_ERR_BIT_NUM_HIGH
	u32 ubmac_fec_decoding_fail_num_low;            // ST_MAC_FEC_DECODING_FAIL_NUM_LOW
	u32 ubmac_fec_decoding_fail_num_high;           // ST_MAC_FEC_DECODING_FAIL_NUM_HIGH

	u32 ubmac_dl_vl_enable;                         // CFG_LINK_CAP_11
	u32 ubmac_dl_rx_flit_cnt[VL_NUM];               // RX_FLIT_CNT_0 ~ 15
	u32 ubmac_dl_tx_flit_cnt[VL_NUM];               // TX_FLIT_CNT_0 ~ 15
	u32 ubmac_dl_crd_exist_cnt[VL_NUM];             // ST_CRD_0 ~ 15
	u32 ubmac_dl_crd_compensate_cnt[VL_NUM];        // ST_CRD_COMPENSATE_0 ~ 15
	u32 ubmac_dl_crd_vn_return_limit[VL_NUM];       // DATA_LINK_PFM_OPT_CFG_0 ~ 7
	u32 ubmac_dl_crd_vn_l1crd_limit[VL_NUM];        // DATA_LINK_PFM_OPT_CFG_8 ~ 15

	u32 ubmac_pfa_tx_fast_err_pkt_int_cnt;          // PFA_TX_FAST_ERR_PKT_IN_CNT
	u32 ubmac_pfa_tx_fast_pkt_int_cnt;              // PFA_TX_FAST_PKT_IN_CNT
	u32 ubmac_pfa_tx_norm_pkt_int_cnt;              // PFA_TX_NORM_PKT_IN_CNT
	u32 ubmac_pfa_rx_pkt_int_cnt;                   // PFA_RX_PKT_IN_CNT
	u32 ubmac_pfa_tx_norm_err_pkt_int_cnt;          // PFA_TX_NORM_ERR_PKT_IN_CNT
	u32 ubmac_pfa_rx_err_pkt_int_cnt;               // PFA_RX_ERR_PKT_IN_CNT
	u32 ubmac_pfa_tx_fast_short_pkt_cnt;            // PFA_TX_FAST_SHORT_PKT_CNT
	u32 ubmac_pfa_tx_fast_long_pkt_cnt;             // PFA_TX_FAST_LONG_PKT_CNT
	u32 ubmac_pfa_tx_fast_mode_err_pkt_cnt;         // PFA_TX_FAST_MODE_ERR_PKT_CNT
	u32 ubmac_pfa_tx_norm_short_pkt_cnt;            // PFA_TX_NORM_SHORT_PKT_CNT
	u32 ubmac_pfa_tx_norm_long_pkt_cnt;             // PFA_TX_NORM_LONG_PKT_CNT
	u32 ubmac_pfa_tx_norm_mode_err_pkt_cnt;         // PFA_TX_NORM_MODE_ERR_PKT_CNT
	u32 ubmac_pfa_rx_short_pkt_cnt;                 // PFA_RX_SHORT_PKT_CNT
	u32 ubmac_pfa_rx_mode_err_pkt_cnt;              // PFA_RX_MODE_ERR_PKT_CNT
	u32 ubmac_pfa_dfx_tx_pkt_len_chk_en;            // PFA_DFX_TX_PKT_LEN_CHK_EN
	u32 ubmac_pfa_dfx_rx_pkt_len_chk_en;            // PFA_DFX_RX_PKT_LEN_CHK_EN
	u32 ubmac_pfa_dfx_pkt_info_chk_en;              // PFA_DFX_PKT_INFO_CHK_EN
	u32 ubmac_pfa_dfx_tx_fifo_state;                // PFA_DFX_TX_FIFO_STATE
	u32 ubmac_pfa_dfx_rx_fifo_state;                // PFA_DFX_RX_FIFO_STATE
	u32 ubmac_pfa_dfx_work_mode;                    // PFA_DFX_WORK_MODE
	u32 ubmac_pfa_dfx_tx_adp_fifo_state;            // PFA_DFX_TX_ADP_FIFO_STATE
	u32 ubmac_pfa_tx_fast_lng_pkt_in_cnt;           // PFA_TX_FAST_LNG_PKT_IN_CNT
	u32 ubmac_pfa_tx_fast_lng_err_pkt_in_cnt;       // PFA_TX_FAST_LNG_ERR_PKT_IN_CNT
	u32 ubmac_pfa_tx_fast_lng_short_pkt_cnt;        // PFA_TX_FAST_LNG_SHORT_PKT_CNT
	u32 ubmac_pfa_tx_fast_lng_long_pkt_cnt;         // PFA_TX_FAST_LNG_LONG_PKT_CNT
	u32 ubmac_pfa_tx_fast_lng_mode_err_pkt_cnt;     // PFA_TX_FAST_LNG_MODE_ERR_PKT_CNT

	u32 ubmac_pcs_lane_tsb_crc_cnt[LANE_NUM];       // ST_LANE0_TSB_CRC_CNT ~ 7
} ubmac_counter_info_s;

typedef struct {
	struct mgmt_msg_head head;  /* 8B */
	u8 nl_id;                   /* nl id 0~2 */
	u8 port_id;                 /* port id 0~7 */
	u8 rsvd;
} ubmac_counter_cmd_req;

typedef struct {
	struct mgmt_msg_head head;  /* 8B */
	ubmac_counter_info_s ubmac_cnt_info;
} ubmac_counter_cmd_resp;

/* Because the firmware returns the rate field as u8 which cannot well carry data above 200Ge,
	data above 200Ge needs to be converted before display.
	Refer to chip_attr_get_port_speed for conversion.
	The above content refers to tool-side modifications.
*/
typedef enum {
	PORT_SPEED_MODE_START = 200,
	PORT_SPEED_MODE_400G = 201,
	PORT_SPEED_MODE_800G = 202,
	PORT_SPEED_MODE_END = 203,
} port_speed_mode_e;

typedef enum {
	PORT_SPEED_UNKOWN = 0,
	PORT_SPEED_1G = 1,
	PORT_SPEED_10G = 10,
	PORT_SPEED_25G = 25,
	PORT_SPEED_40G = 40,
	PORT_SPEED_50G = 50,
	PORT_SPEED_100G = 100,
	PORT_SPEED_200G = 200,
	PORT_SPEED_400G = 400,
	PORT_SPEED_800G = 800
} port_speed_e;

#endif