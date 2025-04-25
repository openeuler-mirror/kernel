/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe_cli.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE_CLI_H__
#define __SXE_CLI_H__

#ifdef SXE_HOST_DRIVER
#include <linux/types.h>
#endif

#define SXE_VERION_LEN (32)
#define SXE_MAC_NUM (128)
#define SXE_PORT_TRANSCEIVER_LEN (32)
#define SXE_PORT_VENDOR_LEN (32)
#define SXE_CHIP_TYPE_LEN (32)
#define SXE_VPD_SN_LEN (16)
#define SXE_SOC_RST_TIME (0x93A80)
#define SXE_SFP_TEMP_THRESHOLD_INTERVAL (3)
#define MGC_TERMLOG_INFO_MAX_LEN (12 * 1024)
#define SXE_REGS_DUMP_MAX_LEN (12 * 1024)
#define SXE_PRODUCT_NAME_LEN (32)

enum sxe_led_mode {
	SXE_IDENTIFY_LED_BLINK_ON   = 0,
	SXE_IDENTIFY_LED_BLINK_OFF,
	SXE_IDENTIFY_LED_ON,
	SXE_IDENTIFY_LED_OFF,
	SXE_IDENTIFY_LED_RESET,
};

struct sxe_led_ctrl {
	u32 mode;
	u32 duration;

};

struct sxe_led_ctrl_resp {
	u32 ack;
};

enum portlinkspeed {
	PORT_LINK_NO = 0,
	PORT_LINK_100M = 1,
	PORT_LINK_1G = 2,
	PORT_LINK_10G = 3,
};

struct syssocinfo {
	s8 fwver[SXE_VERION_LEN];
	s8 optver[SXE_VERION_LEN];
	u8 socstatus;
	u8 pad[3];
	s32 soctemp;
	u64 chipid;
	s8 chiptype[SXE_CHIP_TYPE_LEN];
	s8 pba[SXE_VPD_SN_LEN];
	s8 productname[SXE_PRODUCT_NAME_LEN];
};

struct sysportinfo {
	u64 mac[SXE_MAC_NUM];
	u8 isportabs;
	u8 linkstat;
	u8 linkspeed;

	u8 issfp : 1;
	u8 isgetinfo : 1;
	u8 rvd : 6;
	s8 opticalmodtemp;
	u8 pad[3];
	s8 transceivertype[SXE_PORT_TRANSCEIVER_LEN];
	s8 vendorname[SXE_PORT_VENDOR_LEN];
	s8 vendorpn[SXE_PORT_VENDOR_LEN];
};

struct sysinforesp {
	struct syssocinfo socinfo;
	struct sysportinfo portinfo;
};

enum sfptemptdmode {
	SFP_TEMP_THRESHOLD_MODE_ALARM = 0,
	SFP_TEMP_THRESHOLD_MODE_WARN,
};

struct sfptemptdset {
	u8 mode;
	u8 pad[3];
	s8 hthreshold;
	s8 lthreshold;
};

struct sxelogexportresp {
	u16 curloglen;
	u8 isend;
	u8 pad;
	s32 sessionid;
	s8 data[0];
};

enum sxelogexporttype  {
	SXE_LOG_EXPORT_REQ = 0,
	SXE_LOG_EXPORT_FIN,
	SXE_LOG_EXPORT_ABORT,
};

struct sxelogexportreq {
	u8 isalllog;
	u8 cmdtype;
	u8 isbegin;
	u8 pad;
	s32 sessionid;
	u32 loglen;
};

struct socrstreq {
	u32 time;
};

struct regsdumpresp {
	u32 curdwlen;
	u8 data[0];
};

enum {
	SXE_MFG_PART_NUMBER_LEN = 8,
	SXE_MFG_SERIAL_NUMBER_LEN = 16,
	SXE_MFG_REVISION_LEN = 4,
	SXE_MFG_OEM_STR_LEN = 64,
	SXE_MFG_SXE_BOARD_ASSEMBLY_LEN = 32,
	SXE_MFG_SXE_BOARD_TRACE_NUM_LEN = 16,
	SXE_MFG_SXE_MAC_ADDR_CNT = 2,
};

struct sxemfginfo {
	u8 partnumber[SXE_MFG_PART_NUMBER_LEN];
	u8 serialnumber[SXE_MFG_SERIAL_NUMBER_LEN];
	u32 mfgdate;
	u8 revision[SXE_MFG_REVISION_LEN];
	u32 reworkdate;
	u8 pad[4];
	u64 macaddr[SXE_MFG_SXE_MAC_ADDR_CNT];
	u8 boardtracenum[SXE_MFG_SXE_BOARD_TRACE_NUM_LEN];
	u8 boardassembly[SXE_MFG_SXE_BOARD_ASSEMBLY_LEN];
	u8 extra1[SXE_MFG_OEM_STR_LEN];
	u8 extra2[SXE_MFG_OEM_STR_LEN];
};

struct sxelldpinfo {
	u8 lldpstate;
	u8 pad[3];
};

struct regsdumpreq {
	u32 baseaddr;
	u32 dwlen;
};

enum sxe_pcs_mode {
	SXE_PCS_MODE_1000BASE_KX_WO = 0,
	SXE_PCS_MODE_1000BASE_KX_W,
	SXE_PCS_MODE_SGMII,
	SXE_PCS_MODE_10GBASE_KR_WO,
	SXE_PCS_MODE_AUTO_NEGT_73,
	SXE_PCS_MODE_LPBK_PHY_TX2RX,
	SXE_PCS_MODE_LPBK_PHY_RX2TX,
	SXE_PCS_MODE_LPBK_PCS_RX2TX,
	SXE_PCS_MODE_BUTT,
};

enum sxe_remote_fault {
	SXE_REMOTE_FALUT_NO_ERROR = 0,
	SXE_REMOTE_FALUT_OFFLINE,
	SXE_REMOTE_FALUT_LINK_FAILURE,
	SXE_REMOTE_FALUT_AUTO_NEGOTIATION,
	SXE_REMOTE_UNKNOWN,
};

struct sxe_phy_cfg {
	enum sxe_pcs_mode mode;
	u32 mtu;
};

enum sxe_an_speed {
	SXE_AN_SPEED_NO_LINK = 0,
	SXE_AN_SPEED_100M,
	SXE_AN_SPEED_1G,
	SXE_AN_SPEED_10G,
	SXE_AN_SPEED_UNKNOWN,
};

enum sxe_phy_pause_cap {
	SXE_PAUSE_CAP_NO_PAUSE = 0,
	SXE_PAUSE_CAP_ASYMMETRIC_PAUSE,
	SXE_PAUSE_CAP_SYMMETRIC_PAUSE,
	SXE_PAUSE_CAP_BOTH_PAUSE,
	SXE_PAUSE_CAP_UNKNOWN,
};

enum sxe_phy_duplex_type {
	SXE_FULL_DUPLEX	= 0,
	SXE_HALF_DUPLEX	= 1,
	SXE_UNKNOWN_DUPLEX,
};

struct sxe_phy_an_cap {
	enum sxe_remote_fault remote_fault;
	enum sxe_phy_pause_cap pause_cap;
	enum sxe_phy_duplex_type duplex_cap;
};

struct sxe_an_cap {
	struct sxe_phy_an_cap local;
	struct sxe_phy_an_cap peer;
};
#endif
