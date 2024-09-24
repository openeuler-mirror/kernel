/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_ADMINQ_H_
#define _NBL_ADMINQ_H_

#include "nbl_resource.h"

/* SPI Bank Index */
#define	BANKID_DESC_BANK		0xA0
#define	BANKID_BOOT_BANK		0xA1
#define	BANKID_SR_BANK0			0xA2
#define	BANKID_SR_BANK1			0xA3
#define	BANKID_OSI_BANK0		0xA4
#define	BANKID_OSI_BANK1		0xA5
#define	BANKID_FSI_BANK0		0xA6
#define	BANKID_FSI_BANK1		0xA7
#define	BANKID_PHY_BANK			0xA8
#define	BANKID_NVM_BANK0		0xA9
#define	BANKID_NVM_BANK1		0xAA
#define	BANKID_LOG_BANK			0xAB

#define NBL_ADMINQ_IDX_LEN		4096

#define NBL_MAX_PHY_I2C_RESP_SIZE	128

#define I2C_DEV_ADDR_A0			0x50
#define I2C_DEV_ADDR_A2			0x51

/* SFF moudle register addresses: 8 bit valid */
#define SFF_8472_IDENTIFIER		0x0
#define SFF_8472_10GB_CAPABILITY	0x3  /* check sff-8472 table 5-3 */
#define SFF_8472_1GB_CAPABILITY		0x6  /* check sff-8472 table 5-3 */
#define SFF_8472_CABLE_TECHNOLOGY	0x8  /* check sff-8472 table 5-3 */
#define SFF_8472_EXTENDED_CAPA		0x24  /* check sff-8024 table 4-4 */
#define SFF_8472_CABLE_SPEC_COMP	0x3C
#define SFF_8472_DIAGNOSTIC		0x5C  /* digital diagnostic monitoring, relates to A2 */
#define SFF_8472_COMPLIANCE		0x5E  /* the specification revision version */
#define SFF_8472_VENDOR_NAME		0x14
#define SFF_8472_VENDOR_NAME_LEN	16  /* 16 bytes, from offset 0x14 to offset 0x23 */
#define SFF_8472_VENDOR_PN		0x28
#define SFF_8472_VENDOR_PN_LEN		16
#define SFF_8472_VENDOR_OUI		0x25  /* name and oui cannot all be empty */
#define SFF_8472_VENDOR_OUI_LEN		3
#define SFF_8472_SIGNALING_RATE		0xC
#define SFF_8472_SIGNALING_RATE_MAX	0x42
#define SFF_8472_SIGNALING_RATE_MIN	0x43
/* optional status/control bits: soft rate select and tx disable */
#define SFF_8472_OSCB			0x6E
/* extended status/control bits */
#define SFF_8472_ESCB			0x76
#define SFF8636_DEVICE_TECH_OFFSET	0x93

#define SFF_8636_VENDOR_ENCODING	0x8B
#define SFF_8636_ENCODING_PAM4		0x8

/* SFF status code */
#define SFF_IDENTIFIER_SFP		0x3
#define SFF_IDENTIFIER_QSFP28		0x11
#define SFF_IDENTIFIER_PAM4		0x1E
#define SFF_PASSIVE_CABLE		0x4
#define SFF_ACTIVE_CABLE		0x8
#define SFF_8472_ADDRESSING_MODE	0x4
#define SFF_8472_UNSUPPORTED		0x00
#define SFF_8472_10G_SR_BIT		4  /* 850nm, short reach */
#define SFF_8472_10G_LR_BIT		5  /* 1310nm, long reach */
#define SFF_8472_10G_LRM_BIT		6  /* 1310nm, long reach multimode */
#define SFF_8472_10G_ER_BIT		7  /* 1550nm, extended reach */
#define SFF_8472_1G_SX_BIT		0
#define SFF_8472_1G_LX_BIT		1
#define SFF_8472_1G_CX_BIT		2
#define SFF_8472_1G_T_BIT		3
#define SFF_8472_SOFT_TX_DISABLE	6
#define SFF_8472_SOFT_RATE_SELECT	4
#define SFF_8472_EMPTY_ASCII		20
#define SFF_DDM_IMPLEMENTED		0x40
#define SFF_COPPER_UNSPECIFIED		0
#define SFF_COPPER_8431_APPENDIX_E	1
#define SFF_COPPER_8431_LIMITING	4
#define SFF_8636_TURNPAGE_ADDR		(127)
#define SFF_8638_PAGESIZE		(128)

#define SFF_8636_TEMP			(0x60)
#define SFF_8636_TEMP_MAX		(0x4)
#define SFF_8636_TEMP_CIRT		(0x0)

#define SFF_8636_QSFP28_TEMP		(0x16)
#define SFF_8636_QSFP28_TEMP_MAX	(0x204)
#define SFF_8636_QSFP28_TEMP_CIRT	(0x200)

/* Firmware version */
#define FIRMWARE_MAGIC		"M181FWV0"
#define BCD2BYTE(b)		({ typeof(b) _b = (b);			\
				(((_b) & 0xF) + (((_b) >> 4) & 0xF) * 10); })
#define BCD2SHORT(s)		({ typeof(s) _s = (s);			\
				(((_s) & 0xF) + (((_s) >> 4) & 0xF) * 10 + \
				(((_s) >> 8) & 0xF) * 100 + (((_s) >> 12) & 0xF) * 1000); })

/* VSI fixed number of queues*/
#define NBL_VSI_PF_REAL_QUEUE_NUM(num)		(((num) * 2) + NBL_DEFAULT_REP_HW_QUEUE_NUM)
#define NBL_VSI_VF_REAL_QUEUE_NUM(num)		(num)

#define NBL_ADMINQ_PFA_TLV_PFVF_RING_ID	(0x5805)

enum {
	NBL_FW_VERSION_BANK0 = 0,
	NBL_FW_VERSION_BANK1 = 1,
	NBL_FW_VERSION_RUNNING_BANK = 2,
};

enum {
	NBL_ADMINQ_NVM_BANK_REPAIR = 0,
	NBL_ADMINQ_NVM_BANK_SWITCH,
};

enum {
	NBL_ADMINQ_BANK_INDEX_SPI_BOOT = 2,
	NBL_ADMINQ_BANK_INDEX_NVM_BANK = 3,
};

struct nbl_leonis_eth_tx_stats {
	u64 frames_txd;
	u64 frames_txd_ok;
	u64 frames_txd_badfcs;
	u64 unicast_frames_txd_ok;
	u64 multicast_frames_txd_ok;
	u64 broadcast_frames_txd_ok;
	u64 macctrl_frames_txd_ok;
	u64 fragment_frames_txd;
	u64 fragment_frames_txd_ok;
	u64 pause_macctrl_frames_txd;
	u64 pause_macctrl_toggle_frames_txd;
	u64 pfc_macctrl_frames_txd;
	u64 pfc_macctrl_toggle_frames_txd_0;
	u64 pfc_macctrl_toggle_frames_txd_1;
	u64 pfc_macctrl_toggle_frames_txd_2;
	u64 pfc_macctrl_toggle_frames_txd_3;
	u64 pfc_macctrl_toggle_frames_txd_4;
	u64 pfc_macctrl_toggle_frames_txd_5;
	u64 pfc_macctrl_toggle_frames_txd_6;
	u64 pfc_macctrl_toggle_frames_txd_7;
	u64 verify_frames_txd;
	u64 respond_frames_txd;
	u64 frames_txd_sizerange0;
	u64 frames_txd_sizerange1;
	u64 frames_txd_sizerange2;
	u64 frames_txd_sizerange3;
	u64 frames_txd_sizerange4;
	u64 frames_txd_sizerange5;
	u64 frames_txd_sizerange6;
	u64 frames_txd_sizerange7;
	u64 undersize_frames_txd_goodfcs;
	u64 oversize_frames_txd_goodfcs;
	u64 undersize_frames_txd_badfcs;
	u64 oversize_frames_txd_badfcs;
	u64 octets_txd;
	u64 octets_txd_ok;
	u64 octets_txd_badfcs;
};

struct nbl_leonis_eth_rx_stats {
	u64 frames_rxd;
	u64 frames_rxd_ok;
	u64 frames_rxd_badfcs;
	u64 undersize_frames_rxd_goodfcs;
	u64 undersize_frames_rxd_badfcs;
	u64 oversize_frames_rxd_goodfcs;
	u64 oversize_frames_rxd_badfcs;
	u64 frames_rxd_misc_error;
	u64 frames_rxd_misc_dropped;
	u64 unicast_frames_rxd_ok;
	u64 multicast_frames_rxd_ok;
	u64 broadcast_frames_rxd_ok;
	u64 pause_macctrl_frames_rxd;
	u64 pfc_macctrl_frames_rxd;
	u64 pfc_macctrl_frames_rxd_0;
	u64 pfc_macctrl_frames_rxd_1;
	u64 pfc_macctrl_frames_rxd_2;
	u64 pfc_macctrl_frames_rxd_3;
	u64 pfc_macctrl_frames_rxd_4;
	u64 pfc_macctrl_frames_rxd_5;
	u64 pfc_macctrl_frames_rxd_6;
	u64 pfc_macctrl_frames_rxd_7;
	u64 macctrl_frames_rxd;
	u64 verify_frames_rxd_ok;
	u64 respond_frames_rxd_ok;
	u64 fragment_frames_rxd_ok;
	u64 fragment_frames_rxd_smdc_nocontext;
	u64 fragment_frames_rxd_smds_seq_error;
	u64 fragment_frames_rxd_smdc_seq_error;
	u64 fragment_frames_rxd_frag_cnt_error;
	u64 frames_assembled_ok;
	u64 frames_assembled_error;
	u64 frames_rxd_sizerange0;
	u64 frames_rxd_sizerange1;
	u64 frames_rxd_sizerange2;
	u64 frames_rxd_sizerange3;
	u64 frames_rxd_sizerange4;
	u64 frames_rxd_sizerange5;
	u64 frames_rxd_sizerange6;
	u64 frames_rxd_sizerange7;
	u64 octets_rxd;
	u64 octets_rxd_ok;
	u64 octets_rxd_badfcs;
	u64 octets_rxd_dropped;
};

struct nbl_leonis_eth_stats {
	struct nbl_leonis_eth_tx_stats tx_stats;
	struct nbl_leonis_eth_rx_stats rx_stats;
};

struct nbl_leonis_eth_stats_info {
	const char *descp;
};

#endif
