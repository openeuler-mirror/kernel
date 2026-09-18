/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_sfp_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/07/20
 * Last Modified : 2026/09/16
 * Description   : mpu sfp cmd
 */

#ifndef MPU_SFP_CMD_DEFS_H
#define MPU_SFP_CMD_DEFS_H

#include "base_type.h"
#include "mpu_cmd_base_defs.h"

#define XSFP_CMIS_INFO_MAX_SIZE 1536
#define QSFP_CMIS_PAGE_SIZE                 128
#define XSFP_CMIS_PARSE_PAGE_NUM    10

/* optical_speed */
#define XSFP_MAC_SPEED_UNKNOWN 0   /* unknown */
#define XSFP_MAC_SPEED_10M 10      /* 10 Mbps */
#define XSFP_MAC_SPEED_100M 100    /* 100 Mbps */
#define XSFP_MAC_SPEED_1G 1000     /* 1000 Mbps   = 1 Gbps */
#define XSFP_MAC_SPEED_10G 10000   /* 10000 Mbps  = 10 Gbps */
#define XSFP_MAC_SPEED_25G 25000   /* 25000 Mbps  = 25 Gbps */
#define XSFP_MAC_SPEED_40G 40000   /* 40000 Mbps  = 40 Gbps */
#define XSFP_MAC_SPEED_50G 50000   /* 50000 Mbps  = 50 Gbps */
#define XSFP_MAC_SPEED_100G 100000 /* 100000 Mbps = 100 Gbps */
#define XSFP_MAC_SPEED_200G 200000 /* 200000 Mbps = 200 Gbps */
#define XSFP_MAC_SPEED_400G 400000 /* 400000 Mbps = 400 Gbps */
#define XSFP_MAC_SPEED_800G 800000 /* 800000 Mbps = 800 Gbps */

#define QSFP_CMIS_PAGE_00H                  0x00 /* Lower: Control and Essentials, Upper: Administrative Information */
#define QSFP_CMIS_PAGE_01H                  0x01 /* Advertising */
#define QSFP_CMIS_PAGE_02H                  0x02 /* Module and lane Thresholds */
#define QSFP_CMIS_PAGE_03H                  0x03 /* User EEPROM */
#define QSFP_CMIS_PAGE_04H                  0x04 /* Laser Capabilities Advertising (Page 04h, Optional) */
#define QSFP_CMIS_PAGE_05H                  0x05
#define QSFP_CMIS_PAGE_06H                  0x06
#define QSFP_CMIS_PAGE_07H                  0x07
#define QSFP_CMIS_PAGE_10H                  0x10 /* Lane and Data Path Control */
#define QSFP_CMIS_PAGE_11H                  0x11 /* Lane Status */
#define QSFP_CMIS_PAGE_12H                  0x12
#define QSFP_CMIS_PAGE_13H                  0x13
#define QSFP_CMIS_PAGE_14H                  0x14
#define QSFP_CMIS_PAGE_9FH                  0x9f
#define QSFP_CMIS_PAGE_B7H                  0xb7
#define QSFP_CMIS_PAGE_B8H                  0xb8

#define MGMT_TLV_TYPE_END       0xFFFF
enum mag_xsfp_type {
    /* Reason for skipping 0x00 and defining Type starting from 0x01: to distinguish from memset data */
	MAG_XSFP_TYPE_PAGE      = 0x01,
	MAG_XSFP_TYPE_WIRE_TYPE = 0x02,
	MAG_XSFP_TYPE_END       = MGMT_TLV_TYPE_END
};

typedef struct {
	u8 resv0[QSFP_CMIS_PAGE_SIZE];  /* Reg 128-255: Upper Memory: Page 03H */
} qsfp_cmis_upper_page_03_s;

typedef struct mag_parse_tlv_info {
	u8 tlv_page_info[XSFP_CMIS_INFO_MAX_SIZE + 1];
	u32 tlv_page_info_len;
	u32 tlv_page_num[XSFP_CMIS_PARSE_PAGE_NUM];
	u32 wire_type;
	u8 id;
} parse_tlv_info;

typedef struct drv_tag_mag_cmd_get_xsfp_tlv_rsp {
	struct mgmt_msg_head head;

	u8 port_id;
	u8 rsvd[3];

	u8 tlv_buf[XSFP_CMIS_INFO_MAX_SIZE];
} drv_mag_cmd_get_xsfp_tlv_rsp;

#endif