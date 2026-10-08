/* SPDX-License-Identifier: GPL-2.0 */
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
#define SFF_8638_PAGESIZE		(128U)
#define SFF_8638_PAGE0_SIZE		(256U)

#define SFF_8636_TEMP			(0x60)
#define SFF_8636_TEMP_MAX		(0x4)
#define SFF_8636_TEMP_CIRT		(0x0)

#define SFF_8636_QSFP28_TEMP		(0x16)
#define SFF_8636_QSFP28_TEMP_MAX	(0x204)
#define SFF_8636_QSFP28_TEMP_CIRT	(0x200)

#define NBL_ADMINQ_ETH_WOL_REG_OFFSET_LEONIS	(0x1604000 + 0x500)
#define NBL_ADMINQ_ETH_WOL_REG_OFFSET_DRACO	(0x1600500)

/* Firmware version */
#define BCD2BYTE(b)		({ typeof(b) _b = (b);			\
				(((_b) & 0xF) + (((_b) >> 4) & 0xF) * 10); })
#define BCD2SHORT(s)		({ typeof(s) _s = (s);			\
				(((_s) & 0xF) + (((_s) >> 4) & 0xF) * 10 + \
				(((_s) >> 8) & 0xF) * 100 + (((_s) >> 12) & 0xF) * 1000); })

/* VSI fixed number of queues*/
#define NBL_VSI_PF_LEGAL_QUEUE_NUM(num)		((num) + NBL_DEFAULT_REP_HW_QUEUE_NUM)
#define NBL_VSI_PF_MAX_QUEUE_NUM(num)		(((num) * 2) + NBL_DEFAULT_REP_HW_QUEUE_NUM)
#define NBL_VSI_VF_REAL_QUEUE_NUM(num)		(num)

#define	NBL_ADMINQ_RESID_FSI_SECTION_HBC	(0x3000)
#define	NBL_ADMINQ_RESID_FSI_TLV_SERIAL_NUMBER	(0x3801)
#define NBL_ADMINQ_PFA_TLV_VF_NUM		(0x5804)
#define NBL_ADMINQ_PFA_TLV_NET_RING_NUM		(0x5805)
#define NBL_ADMINQ_PFA_TLV_REP_RING_NUM		(0x5806)
#define NBL_ADMINQ_PFA_TLV_ECPU_RING_NUM	(0x5807)
#define NBL_ADMINQ_PFA_TLV_RDMA_CAP		(0x5808)
#define NBL_ADMINQ_PFA_TLV_RDMA_MEM_TYPE	(0x5809)
#define NBL_ADMINQ_PFA_TLV_INTERNAL_CFG		(0x580e)

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
	u64 unsupported_opcodes_rx;
};

struct nbl_leonis_eth_stats {
	struct nbl_leonis_eth_tx_stats tx_stats;
	struct nbl_leonis_eth_rx_stats rx_stats;
};

struct nbl_eth_stats_info {
	const char *descp;
};

struct nbl_draco_eth_tx_stats {
	u64 frames_txd;
	u64 frames_txd_ok;
	u64 unicast_frames_txd;
	u64 multicast_frames_txd;
	u64 multicast_frames_txd_ok;
	u64 broadcast_frames_txd;
	u64 broadcast_frames_txd_ok;
	u64 underflow_error_frames_txd;
	u64 pause_frames_txd;
	u64 vlan_frames_txd;
	u64 frames_txd_sizerange0;
	u64 frames_txd_sizerange1;
	u64 frames_txd_sizerange2;
	u64 frames_txd_sizerange3;
	u64 frames_txd_sizerange4;
	u64 frames_txd_sizerange5;
	u64 octets_txd;
};

struct nbl_draco_eth_rx_stats {
	u64 frames_rxd;
	u64 undersize_frames_rxd_good;
	u64 oversize_frames_rxd_good;
	u64 unicast_frames_rxd_ok;
	u64 multicast_frames_rxd_ok;
	u64 broadcast_frames_rxd_ok;
	u64 crc_error_frames_rxd;
	u64 runt_error_frames_rxd;
	u64 jabber_error_frames_rxd;
	u64 length_error_frames_rxd;
	u64 out_of_range_type_frames_rxd;
	u64 pause_frames_rxd;
	u64 vlan_frames_rxd;
	u64 watchdog_error_frames_rxd;
	u64 frames_rxd_sizerange0;
	u64 frames_rxd_sizerange1;
	u64 frames_rxd_sizerange2;
	u64 frames_rxd_sizerange3;
	u64 frames_rxd_sizerange4;
	u64 frames_rxd_sizerange5;
	u64 octets_rxd;
	u64 octets_rxd_ok;
};

struct nbl_draco_eth_stats {
	struct nbl_draco_eth_tx_stats tx_stats;
	struct nbl_draco_eth_rx_stats rx_stats;
};

union nbl_eth_stats_union {
	struct nbl_leonis_eth_stats leonis;
	struct nbl_draco_eth_stats draco;
};

#define OFFSET_U64(type, member) (offsetof(type, member) / sizeof(u64))

#define ETH_STATIS_LOC(off, vld) (((off) << 1) + (vld))
#define ETH_STATIS_OFFSET(f) (((f) >> 1) & 0x7FFF)
#define ETH_STATIS_VLD(f) ((f) & 0x1)
#define ETH_STATIS_GET(ptr, off, vld) ((vld) ? (ptr)[(off)] : 0)

enum {
	NBL_MACCTRL_FRAME_TX_OK,
	NBL_MACCTRL_FRAME_RX,
	NBL_UNSUPPORTED_OPCODES_RX,
	NBL_PAUSE_FRAME_TX,
	NBL_PAUSE_FRAME_RX,
	NBL_FRAME_RX_BADFCS,
	NBL_FRAME_RX,
	NBL_FRAME_RX_OK,
	NBL_UNDERSIZE_FRAME_RX_GOODFAS,
	NBL_OVERSIZE_FRAME_RX_GOODFAS,
	NBL_OCTETS_RX_OK,
	NBL_OCTETS_TX_OK,
	NBL_FRAME_TX_OK,
	NBL_MUL_FRAME_TXD_OK,
	NBL_BROAD_FRAME_TXD_OK,
	NBL_MUL_FRAME_RXD_OK,
	NBL_BROAD_FRAME_RXD_OK,
	NBL_UNI_FRAME_RXD_OK,
	NBL_UNDERSIZE_FRAME_RX_BADFAS,
	NBL_OVERSIZE_FRAME_RX_BADFAS,
	NBL_FRAME_RX_sizerange0,
	NBL_FRAME_RX_sizerange1,
	NBL_FRAME_RX_sizerange2,
	NBL_FRAME_RX_sizerange3,
	NBL_FRAME_RX_sizerange4,
	NBL_FRAME_RX_sizerange5,
	NBL_FRAME_RX_sizerange6,
	NBL_FRAME_RX_sizerange7,
	NBL_FRAME_TX_sizerange0,
	NBL_FRAME_TX_sizerange1,
	NBL_FRAME_TX_sizerange2,
	NBL_FRAME_TX_sizerange3,
	NBL_FRAME_TX_sizerange4,
	NBL_FRAME_TX_sizerange5,
	NBL_FRAME_TX_sizerange6,
	NBL_FRAME_TX_sizerange7,
	NBL_ETH_STATISC_MAX,
};

struct nbl_port_key {
	u32 id; /* port id */
	u32 subop; /* 1: read, 2: write */
	u64 data[]; /* [47:0]: data, [55:48]: rsvd, [63:56]: key */
};

#define NBL_PORT_KEY_ILLEGAL 0x0
#define NBL_PORT_KEY_CAPABILITIES 0x1
#define NBL_PORT_KEY_ENABLE 0x2 /* BIT(0): NBL_PORT_FLAG_ENABLE_NOTIFY */
#define NBL_PORT_KEY_DISABLE 0x3
#define NBL_PORT_KEY_ADVERT 0x4
#define NBL_PORT_KEY_LOOPBACK 0x5 /* 0: disable eth loopback, 1: enable eth loopback */
#define NBL_PORT_KEY_MODULE_SWITCH 0x6 /* 0: sfp off, 1: sfp on */
#define NBL_PORT_KEY_MAC_ADDRESS 0x7
#define NBL_PORT_KEY_LED_BLINK 0x8
#define NBL_PORT_KEY_RESTORE_DEFAULTE_CFG 11
#define NBL_PORT_KEY_SET_PFC_CFG 12
#define NBL_PORT_KEY_GET_LINK_STATUS_OPCODE 17

enum {
	NBL_PORT_SUBOP_READ = 1,
	NBL_PORT_SUBOP_WRITE = 2,
};

#define NBL_PORT_FLAG_ENABLE_NOTIFY	BIT(0)
#define NBL_PORT_ENABLE_LOOPBACK	1
#define NBL_PORT_DISABLE_LOOPBCK	0
#define NBL_PORT_SFP_ON			1
#define NBL_PORT_SFP_OFF		0
#define NBL_PORT_KEY_KEY_SHIFT		56
#define NBL_PORT_KEY_DATA_MASK		0xFFFFFFFFFFFF

#endif
