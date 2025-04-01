/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe_msg.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE_MSG_H__
#define __SXE_MSG_H__

#ifdef SXE_HOST_DRIVER
#include <linux/types.h>
#endif

#define SXE_MAC_ADDR_LEN 6

#define SXE_HDC_CMD_HDR_SIZE sizeof(struct sxe_hdc_cmd_hdr)
#define SXE_HDC_MSG_HDR_SIZE sizeof(struct sxe_hdc_drv_cmd_msg)

enum sxe_cmd_type {
	SXE_CMD_TYPE_CLI,
	SXE_CMD_TYPE_DRV,
	SXE_CMD_TYPE_UNKNOWN,
};

struct sxe_hdc_cmd_hdr {
	u8 cmd_type;
	u8 cmd_sub_type;
	u8 reserve[6];
};

enum sxefwstate {
	SXE_FW_START_STATE_UNDEFINED = 0x00,
	SXE_FW_START_STATE_INIT_BASE = 0x10,
	SXE_FW_START_STATE_SCAN_DEVICE = 0x20,
	SXE_FW_START_STATE_FINISHED = 0x30,
	SXE_FW_START_STATE_UPGRADE = 0x31,
	SXE_FW_RUNNING_STATE_ABNOMAL = 0x40,
	SXE_FW_START_STATE_MASK = 0xF0,
};

struct sxefwstateinfo {
	u8 socstatus;
	char statbuff[32];
};

enum msievt {
	MSI_EVT_SOC_STATUS = 0x1,
	MSI_EVT_HDC_FWOV = 0x2,
	MSI_EVT_HDC_TIME_SYNC = 0x4,

	MSI_EVT_MAX = 0x80000000,
};

enum sxefwhdcstate {
	SXE_FW_HDC_TRANSACTION_IDLE = 0x01,
	SXE_FW_HDC_TRANSACTION_BUSY,

	SXE_FW_HDC_TRANSACTION_ERR,
};

enum sxe_hdc_cmd_opcode {
	SXE_CMD_SET_WOL = 1,
	SXE_CMD_LED_CTRL,
	SXE_CMD_SFP_READ,
	SXE_CMD_SFP_WRITE,
	SXE_CMD_TX_DIS_CTRL = 5,
	SXE_CMD_TINE_SYNC,
	SXE_CMD_RATE_SELECT,
	SXE_CMD_R0_MAC_GET,
	SXE_CMD_LOG_EXPORT,
	SXE_CMD_FW_VER_GET = 10,
	SXE_CMD_PCS_SDS_INIT,
	SXE_CMD_AN_SPEED_GET,
	SXE_CMD_AN_CAP_GET,
	SXE_CMD_GET_SOC_INFO,
	SXE_CMD_MNG_RST = 15,

	SXE_CMD_MAX,
};

enum sxe_hdc_cmd_errcode {
	SXE_ERR_INVALID_PARAM = 1,
};

struct sxe_hdc_drv_cmd_msg {
	u16 opcode;
	u16 errcode;
	union datalength {
		u16 req_len;
		u16 ack_len;
	} length;
	u8 reserve[8];
	u64 traceid;
	u8 body[0];
};

struct sxe_sfp_rw_req {
	u16 offset;
	u16 len;
	u8 write_data[0];
};

struct sxe_sfp_read_resp {
	u16 len;
	u8 resp[0];
};

enum sxe_sfp_rate {
	SXE_SFP_RATE_1G = 0,
	SXE_SFP_RATE_10G = 1,
};

struct sxe_sfp_rate_able {
	enum sxe_sfp_rate rate;
};

struct sxe_spp_tx_able {
	bool isdisable;
};

struct sxe_default_mac_addr_resp {
	u8 addr[SXE_MAC_ADDR_LEN];
};

struct sxe_mng_rst {
	bool enable;
};

#endif
