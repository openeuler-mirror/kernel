/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_TYPE_H_
#define _NSE_TYPE_H_

#define NSE_DEBUG_EXT

#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

#include "nse_defs.h"
#include "nse_status.h"
#include "nse_hw_reg.h"
#include "nse_hw_conf.h"
#include "nse_fw_conf.h"
#include "nse_devids.h"
#include "nse_osdep.h"
#include "nse_lan_tx_rx.h"
#include "nse_controlq.h"
#include "nse_flex_type.h"
#include "nse_protocol_type.h"
#include "nse_adminq_cmd.h"

static inline bool nse_is_tc_ena(unsigned long bitmap, u8 tc)
{
	return test_bit(tc, &bitmap);
}

static inline u64 round_up_64bit(u64 a, u32 b)
{
	return div64_u64(((a) + (b) / 2), (b));
}

static inline u32 nse_round_to_num(u32 N, u32 R)
{
	return ((((N) % (R)) < ((R) / 2)) ? (((N) / (R)) * (R)) :
		((((N) + (R) - 1) / (R)) * (R)));
}

/* Driver always calls main vsi_handle first */
#define NSE_MAIN_VSI_HANDLE		0

/* Switch from ms to the 1usec global time (this is the GTIME resolution) */
#define NSE_MS_TO_GTIME(time)		((time) * 1000)

/* Data type manipulation macros. */
#define NSE_HI_WORD(x)		((u16)(((x) >> 16) & 0xFFFF))
#define NSE_LO_WORD(x)		((u16)((x) & 0xFFFF))
#define NSE_HI_BYTE(x)		((u8)(((x) >> 8) & 0xFF))
#define NSE_LO_BYTE(x)		((u8)((x) & 0xFF))

/* debug masks - set these bits in hw->debug_mask to control output */
#define NSE_DBG_SYS			BIT_ULL(1)
#define NSE_DBG_MISC		BIT_ULL(2)
#define NSE_DBG_FW			BIT_ULL(3)
#define NSE_DBG_LMAC_PHY	BIT_ULL(4)
#define NSE_DBG_LAN			BIT_ULL(5)
#define NSE_DBG_DCB			BIT_ULL(6)
#define NSE_DBG_SCHED		BIT_ULL(7)
#define NSE_DBG_RCF			BIT_ULL(8)
#define NSE_DBG_PTP			BIT_ULL(9)
#define NSE_DBG_SW			BIT_ULL(10)
#define NSE_DBG_RDMA		BIT_ULL(11)
#define NSE_DBG_NVM			BIT_ULL(12)
#define NSE_DBG_SCHED_AQC	BIT_ULL(13)
#define NSE_DBG_SRIOV		BIT_ULL(14)

/* the following "_DETAIL" are for periodic logic, lower their level to be less noisy */
#define NSE_DBG_LMAC_PHY_DETAIL	BIT_ULL(15)
#define NSE_DBG_MISC_DETAIL		BIT_ULL(16)

#define NSE_DBG_AQM_MSG			BIT_ULL(27)
#define NSE_DBG_AQM_DESC		BIT_ULL(28)
#define NSE_DBG_AQM_BUF			BIT_ULL(29)
#define NSE_DBG_AQM_ALL		(NSE_DBG_AQM_MSG		| \
				 NSE_DBG_AQM_DESC	| \
				 NSE_DBG_AQM_BUF)

#define NSE_DBG_USER		BIT_ULL(31)
#define NSE_DBG_ALL		0xFFFFFFFFFFFFFFFFULL

#ifndef __always_unused
#define __always_unused
#endif

/* Vendor ID */
#ifndef PCI_VENDOR_ID_TRUSTNETIC
#define PCI_VENDOR_ID_TRUSTNETIC                0x8088
#endif

/* MAC types */
enum nse_mac_type {
	NSE_MAC_TYPE_UNKNOWN = 0,
	NSE_MAC_TYPE_AMBER,
	NSE_MAC_TYPE_MOONSTONE,
};

/* Software VSI types. */
enum nse_vsi_type {
	NSE_VSI_PF = 0,
	NSE_VSI_VF = 1,

	NSE_VSI_OFFLOAD_MACVLAN = 2,

	NSE_VSI_SWITCHDEV_CTRL = 3,

	NSE_VSI_LB = 4,
	NSE_VSI_ADI = 5,
};

static inline bool nse_is_vsi_type_under_vf_drv(enum nse_vsi_type type)
{
	return (type == NSE_VSI_VF) ||
			(type == NSE_VSI_ADI);
}

static inline bool nse_is_vsi_type_under_pf_drv(enum nse_vsi_type type)
{
	return !nse_is_vsi_type_under_vf_drv(type);
}

enum nse_vsi_mode {
	NSE_VSI_MODE_NATIVE	= 0,
	NSE_VSI_MODE_VIRTIO,
	NSE_VSI_MODE_MAX,
};

/* Different data queue types: These are mainly for SW consumption. */
enum nse_q {
	NSE_DATA_Q_CMPL,
	NSE_DATA_Q_RX,
	NSE_DATA_Q_TX,
};

enum nse_fc_mode {
	NSE_FC_LFC_NONE = 0,
	NSE_FC_LFC_RX_PAUSE,
	NSE_FC_LFC_TX_PAUSE,
	NSE_FC_LFC_FULL,
	NSE_FC_PFC,
};

/* Flow control (FC) parameters (including LFC or PFC) */
struct nse_fc_info {
	enum nse_fc_mode current_mode;	/* FC mode in effect */
	enum nse_fc_mode req_mode;	/* FC mode requested by caller */

	bool autoneg_lfc;
};

struct nse_link_info {
	u32 link_status;		/* 1 (NSE_AQ_LINK_UP) for UP, 0 for down */
	u32 link_speed;			/* a NSE_AQ_LINK_SPEED_* value */
};

/* <<SFF-8024>> /4.2 Transceiver References /Table 4-1 Identifier Values */
#define SFF_DEV_ID_SFP_SFF8472		0x3
#define SFF_DEV_ID_QSFP				0xC
#define SFF_DEV_ID_QSFP_PLUS		0xD
#define SFF_DEV_ID_QSFP28			0x11
#define SFF_DEV_ID_MICRO_QSFP		0x17
#define SFF_DEV_ID_QSFP_PLUS_CMIS	0x1E
#define SFF_DEV_ID_SFP_PLUS_CMIS	0x20

static inline bool is_sff_dev_id_is_cmis(u8 dev_id)
{
	if (dev_id == SFF_DEV_ID_QSFP_PLUS_CMIS ||
		dev_id == SFF_DEV_ID_SFP_PLUS_CMIS)
		return true;

	return false;
}

/*  <<SFF-8024>> /4.5 Extended Specification Compliance References /Table 4-4 Extended Specification
 * Compliance Codes
 */
#define SFF_EXT_COMPLIANCE_100GbaseSR4_25GbaseSR				0x2
#define SFF_EXT_COMPLIANCE_100GbaseSR4							0x2
#define SFF_EXT_COMPLIANCE_25GbaseSR							0x2

#define SFF_EXT_COMPLIANCE_100GbaseLR4_25GbaseLR				0x3
#define SFF_EXT_COMPLIANCE_100GbaseLR4							0x3
#define SFF_EXT_COMPLIANCE_25GbaseLR							0x3

#define	SFF_EXT_COMPLIANCE_100GbaseER4_25GbaseER				0x4
#define	SFF_EXT_COMPLIANCE_100GbaseER4							0x4
#define	SFF_EXT_COMPLIANCE_25GbaseER							0x4

#define	SFF_EXT_COMPLIANCE_100GbaseSR10							0x5

#define	SFF_EXT_COMPLIANCE_100G_CWDM4							0x6

#define SFF_EXT_COMPLIANCE_100GbaseCR4_25GbaseCR_50GbaseCR2_RS_FEC	0xB
#define SFF_EXT_COMPLIANCE_100GbaseCR4								0xB
#define SFF_EXT_COMPLIANCE_25GbaseCR_RS_FEC							0xB
#define SFF_EXT_COMPLIANCE_50GbaseCR2_RS_FEC						0xB

#define SFF_EXT_COMPLIANCE_25GbaseCR_50GbaseCR2_BASER_FEC		0xC
#define SFF_EXT_COMPLIANCE_25GbaseCR_BASER_FEC					0xC
#define SFF_EXT_COMPLIANCE_50GbaseCR2_BASER_FEC					0xC

#define SFF_EXT_COMPLIANCE_25GbaseCR_50GbaseCR2_NO_FEC			0xD
#define SFF_EXT_COMPLIANCE_25GbaseCR_NO_FEC						0xD
#define SFF_EXT_COMPLIANCE_50GbaseCR2_NO_FEC					0xD

#define SFF_EXT_COMPLIANCE_40G_SWDM4							0x1F
#define SFF_EXT_COMPLIANCE_100G_SWDM4							0x20

#define SFF_EXT_COMPLIANCE_400GbaseCR4							0x3F

#define SFF_EXT_COMPLIANCE_200GbaseCR4							0x40
#define SFF_EXT_COMPLIANCE_200GbaseSR4							0x41
#define SFF_EXT_COMPLIANCE_200GbaseDR4							0x42
#define SFF_EXT_COMPLIANCE_200GbaseLR4							0x46

#define SFF_EXT_COMPLIANCE_400GbaseDR4							0x47

#define SFF_EXT_COMPLIANCE_400GbaseFR4							0x48

#define SFF_EXT_COMPLIANCE_400GbaseLR4							0x49

struct cmis_int_status {
	bool valid;

	u8 global_status;		/* 8.2.2 Global Status Information */

	u8 flags_summary[4];	/* 8.2.3 Flags Summary */

	u8 mod_level_flags[6];	/* 8.2.4 Module-Level Flags */

	u8 mod_fault_info;		/* 8.2.10 Module Fault Information */

	u8 lane_specific_flags[20];		/* 8.9.3 Lane-Specific Flags */
									/*  we only read Bank 0,
									 * Page 11h
									 *  it is unlikely we have a
									 * CMIS module whose lane
									 * cnt > 8
									 */
};

struct xsfp_cmis_info {
	/* CMIS memory
	 *
	 *		8.1.2 Map of Supported Pages and Banks
	 *
	 *			Table 8-1 List of CMIS Pages
	 *
	 *
	 *		8.2 Lower Memory (Control and Status Essentials)
	 *		8.3 Page 00h (Administrative Information)
	 *
	 *		8.4 Page 01h (Advertising)
	 *
	 *		8.8 Banked Page 10h (Lane Control and Data Path Control)
	 *		8.9 Banked Page 11h (Lane Status and Data Path Status)
	 *
	 *			8 lanes group, 4 of 256
	 */

	u8 mem_lp_up0[256];
	u8 mem_up1[128];
	u8 mem_up10[4][128];
	u8 mem_up11[4][128];

	struct cmis_int_status int_status;
	struct cmis_int_status int_status_old;

	/* the following fields are parsing result of mem */
	/*  byte 2 - bit 7: 0b: Paged memory (Pages 00h-02h, 10h-11h supported), 1b: Flat memory
	 * (Page 00h supported only)
	 */
	u8 mem_model;
					/*  Flat memory modules support only Lower Memory and Page
					 * 00h which is fixed mapped to Upper Memory.
					 */
					/*  Paged memory modules must additionally support Pages
					 * 01h, 02h and Bank 0 of Pages 10h and 11h
					 */

	/* 8.2.11 Applications Advertising */
	u8 media_type;
	u8 host_if_id;		/* App1 */
	u8 media_if_id;
	u8 host_lane_cnt;
	u8 media_lane_cnt;

	u8 media_lane_info;	/* 8.3.7 Media Lane Information */

	u8 media_if_tech;	/* 8.3.9 Media Interface Technology */

	u8 supported_pages_adv;		/* 8.4.4 Supported Pages Advertising */

	/* 8.4.8 Supported Flags Advertisement */
	bool impl_tx_los;
	bool impl_tx_fault;
	bool impl_rx_los;
};

struct sfp_pin_status {
	bool valid;

	/* current status pins's value - reported by aq-event or aq-cmd get status */
	u32 mod_abs;
	u32 tx_fault;
	u32 rx_los;
};

struct sfp_sff8472_info {
	u8 mem_a0[128];	/* <<SFF-8472>> / 4. Memory Organization / 2 wire address (A0h) */

	/*  the following fields are parsing result of mem_a0, according to <<SFF-8472>>/4 Memory
	 * Organization
	 */
	bool impl_rate_select;	/* byte 65*/
	bool impl_tx_disable;
	bool impl_tx_fault;
	bool impl_rx_los;

	bool need_addr_change;	/* <<SFF-8472>> / 8.9 Addressing Modes */

	u32 cable_tech;		/* byte 8 */
#define SFF8472_CABLE_TECH_ACTIVE		BIT(3)
#define SFF8472_CABLE_TECH_PASSIVE		BIT(2)

	u32 cable_len;

	/* byte: 36 - SFF-8024 - Table 4-4 Extended Specification Compliance Codes */
	u8 compliance_ext_code;

	u8 compliance_10g_eth_codes;	/* byte: 3 - bits: 7 - 4 */
#define SFF8472_10G_ETH_COMPLIANCE_ER	BIT(7)
#define SFF8472_10G_ETH_COMPLIANCE_LRM	BIT(6)
#define SFF8472_10G_ETH_COMPLIANCE_LR	BIT(5)
#define SFF8472_10G_ETH_COMPLIANCE_SR	BIT(4)
};

struct nse_ephy_sfp_info {
	struct sfp_pin_status pin_status;
	struct sfp_pin_status pin_status_old;

	/* mem byte 0 --- <<SFF-8024>> / 4.2 Transceiver References and determine mng_if */
	u8 dev_id;

	enum xsfp_mng_if_type mng_if_type;	/* SFP SFF8472 or CMIS */

	/* sff8472_info - used if mng_if_type == SFF8472 */
	struct sfp_sff8472_info sff8472_info;

	/* cmis_info - used if mng_if_type == CMIS */
	struct xsfp_cmis_info cmis_info;
};

struct qsfp_pin_status {
	bool valid;

	u32 modprsl;
	u32 intl;
};

struct qsfp_sff8636_int_status {
	bool valid;

	u8 status_indicators;

	u8 interrupt_flags[19];
};

struct qsfp_sff8636_info {
	/* <<SFF-8636>> /6.2 Lower Page 00h, /6.3 Upper Page 00h */
	u8 mem_lp_up0[256];

#define SFF8636_STATUS_INDICATORS_INTL				BIT(1)
#define SFF8636_STATUS_INDICATORS_DATA_NOT_READY	BIT(0)

	struct qsfp_sff8636_int_status int_status;
	struct qsfp_sff8636_int_status int_status_old;

	/*  the following fields are parsing result of lp_up_0, according to <<SFF-8636>>/6 Memory
	 * Map
	 */
	u8 mem_model;	/* Bit 2 = 1b: Flat memory, 0b: Paging */

	u8 compliance_10g_40g_100g_eth_codes;	/* 6.3.4 Specification Compliance (00h 131-138) */
	u8 compliance_ext_code;	/* 6.3.23 Extended Specification Compliance Codes (00h 192) */

	u8 connector_type;	/* 6.3.3 Connector Type (00h 130) */
	u8 length_ca_or_of;	/* 6.3.12 Length: Cable Assembly or Optical Fiber (OM4) (00h 146) */
	u8 dev_tech;		/* 6.3.13 Device Technology (00h 147) */

	bool impl_rate_select;	/* 6.3.24 Options (00h 193-195) */
	u8 rate_select_version;	/* 6.3.7 Extended Rate Select Compliance (00h 141) */
#define SFF8636_RATE_SELECT_VERSION_1	0x1
#define SFF8636_RATE_SELECT_VERSION_2	0x2

	bool impl_tx_disable;
	bool impl_tx_fault;
	bool impl_tx_los;
};

struct nse_ephy_qsfp_info {
	/* current status pins's value */
	struct qsfp_pin_status pin_status;
	struct qsfp_pin_status pin_status_old;

	/* mem byte 0 --- <<SFF-8024>> / 4.2 Transceiver References and determine mng_if */
	u8 dev_id;

	enum xsfp_mng_if_type mng_if_type;	/* QSFP SFF8636 or CMIS */

	/* sff8636_info - used if mng_if_type == SFF8636 */
	struct qsfp_sff8636_info sff8636_info;

	/* cmis_info - used if mng_if_type == CMIS */
	struct xsfp_cmis_info cmis_info;
};

struct ephy_ftype_status {
	bool valid;

	u32 present;
	u32 signal_ok;
};

struct nse_ephy_ftype_info {
	struct ephy_ftype_status status;
	struct ephy_ftype_status status_old;
};

struct nse_ephy_info {
	u32 ephy_type;	/* NSE_AQC_EPHY_TYPE_XXX */

	bool is_supported_mod;

	/* bitmap of NSE_AQ_LINK_SPEED_XXX, supported by module */
	u32 mod_supported_link_speeds;
	u64 mod_supported_link_types;	/* bitmap of NSE_ETH_LINK_TYPE_XXX, supported by module */

	u32 mod_media_type;		/* (1 << enum nse_media_type) */

	/* like lpinfo->supported_fec --- RS | BASER | OFF -- MUST NOT include AUTO */
	u32 mod_supported_fec;

	bool mod_an_supported;

	bool cur_temperature_valid;
	int cur_temperature;	/* Decimal, not care about Fraction */

	struct ethtool_link_ksettings mod_lks;

	union {
		struct nse_ephy_sfp_info sfp_info;
		struct nse_ephy_qsfp_info qsfp_info;

		struct nse_ephy_ftype_info ftype_info;
	};
};

struct nse_an_info {
	bool an_supported;
	bool an_enabled;	/* true by default, changeable by ethtool */
};

struct nse_led_info {
	struct nse_aqc_led_cfg init;
	struct nse_aqc_led_cfg dft;
	struct nse_aqc_led_cfg cur;	/* normally, current = dft, may be changed by ethtool -ID */
};

struct nse_lmac_phy_info {
	void *hw;	/* for quick back reference */

	struct mutex mtx;	/* a big one */

	u64 supported_link_types;	/* bitmap of nse_eth_link_types */

	u32 supported_link_speeds;	/* bitmap of NSE_AQ_LINK_SPEED_XXX */

	u32 supported_media_types;	/* (1 << enum nse_media_type_bits) bitmap */

	u32 supported_fec;	/* RS | BASER | OFF -- MUST NOT include AUTO */

	u32 static_flags;
#define LMAC_PHY_STATIC_FLAG_USE_TEST_PHY				BIT(0)
#define LMAC_PHY_STATIC_FLAG_EPHY_FTYPE					BIT(1)
#define LMAC_PHY_STATIC_FLAG_CONSIDER_ALWAYS_LINK_UP	BIT(2)

	u32 dyn_flags;	/* dynamic flags */
/* to prevent egress traffic first and do configuration */
#define LMAC_PHY_DYN_FLAG_NEED_FIRST_FORCE_NOTIFY_LINK_DOWN		BIT(0)
#define LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS				BIT(1)
#define LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN	BIT(2)	/* set fixed link or start AN */
#define LMAC_PHY_DYN_FLAG_NEED_CHECK_AN_RESULT_OR_TIMEOUT		BIT(3)
#define LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO					BIT(4)

#define LMAC_PHY_DYN_FLAG_NOT_RUN_SUBTASK						BIT(31)

	bool prev_notify_link_down;	/* avoid repeated notify link down */

	unsigned long poll_link_info_prev;
	unsigned long poll_link_info_period;
#define NSE_LMAC_PHY_POLL_LINK_INFO_PERIOD	(5 * HZ)
#define NSE_LMAC_PHY_POLL_LINK_INFO_PERIOD_VERY_LONG	(3600 * HZ)

	/* link down too long time, retry deep */
	unsigned long link_down_retry_whole_subtask_prev;
	unsigned long link_down_retry_whole_subtask_period;
#define NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD	(30 * HZ)	/* used when AN enabled */
/* used when AN disabled... */
#define NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD_SHORT	(10 * HZ)
#define NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD_RANDOM_DELTA	(3 * HZ)	/* random delta */


	u32 link_down_reason;
#define NSE_LMAC_PHY_LINK_DOWN_REASON_UNKNOWN						0x0
#define NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY				0x1
#define NSE_LMAC_PHY_LINK_DOWN_REASON_START_LINK_OR_AN_FAIL			0x2
#define NSE_LMAC_PHY_LINK_DOWN_REASON_AN_TIMEOUT					0x3
#define NSE_LMAC_PHY_LINK_DOWN_READON_UPDATE_LINK_INFO_FAIL			0x4
#define NSE_LMAC_PHY_LINK_DOWN_READON_NOTIFY_LINK_INFO_FAIL			0x5
#define NSE_LMAC_PHY_LINK_DOWN_REASON_NOT_UP_YET					0x6

#define NSE_LMAC_PHY_LINK_DOWN_REASON_ALEADY_UP	0xFF	/* not down, already up */

	u32 set_link_or_start_an_extra_flags;	/* use to pass to aq-cmd: set_link and start_an */

	struct nse_ephy_info ephy_info;

	struct nse_fc_info fc_info;		/* flow control */

	struct nse_an_info an_info;

	struct nse_led_info led_info;

	struct nse_link_info link_info;
	struct nse_link_info link_info_old;

	struct ethtool_link_ksettings lks;

	/* if AN disabled, one bit of nse_eth_link_types; if AN enabled, a bitmap */
	u64 req_link_types;
	/*  if AN disabled, then one speed request from ethtool -s speed, if AN enabled, a bitmap
	 * corresponding to req_link_types
	 */
	u32 req_link_speeds;

	/* request from ethtool -s speed N (autoneg off ), and imply AN disabled */
	u32 req_link_speed_from_user;
	/* request from ethtool -s advertuse N (autoneg on), and impl AN enabled */
	u64 req_link_types_from_user;

	/* set from ethtool, (1 << enum nse_eth_fec_bits), including _AUTO */
	u32 req_fec_from_user;

	/* field: u32 req_fec_cur;
	 *
	 * when AN disabled,
	 *
	 *		see: select_fec_with_an_disabled()
	 *
	 *		_cur is given into aq_cmd buffer: set_link -> __le32 fec,
	 *		which is of 2 value cases:
	 *
	 *			FEC_OFF or FEC_BASER or FEC_RS	# 1 bit is set, without FEC_AUTO
	 *
	 *				FW should force the FEC setting specified
	 *
	 *
	 *			FEC_AUTO | (FEC_RS or| FEC_BASER | or| FEC_OFF)
	 *			# with FEC_AUTO, and at least 2 bits in
	 *			# (_RS, _BASER, _OFF) is set
	 *
	 *				FW should do FEC auto switch logic to get link UP
	 *
	 *				Since in index value: _RS_BIT = 0, _BASER_BIT=1, _OFF_BIT=2
	 *				then can write this way
	 *
	 *					if (req_fec_cur & AUTO) {
	 *
	 *						req_fec_cur &= ~AUTO;
	 *
	 *						for (i = 0; i <= _OFF_BIT; i++) {
	 *
	 *							if (!req_fec_cur & BIT(i)) continue;
	 *
	 *							do set link with FEC specified
	 *						}
	 *					}
	 *
	 *				if (FEC_RS | FEC_BASER | FEC_OFF) then switch in order:
	 *				RS -> BASER -> NONE -> (optional) loop to beginning
	 *
	 *				if (FEC_RS | FEC_BASER) then switch in order:
	 *				RS -> BASER -> (optional) loop to beginning
	 *
	 *				if (FEC_RS | FEC_OFF) then switch in order:
	 *				RS -> NONE -> (optional) loop to beginning
	 *
	 *				if (FEC_BASER | FEC_OFF) then switch in order:
	 *				BASER -> NONE -> (optional) loop to beginning
	 *
	 *
	 *				between each switch, FW's better wait for a tiny random time
	 *
	 *
	 * -----------------------------------------------------------------------
	 *
	 * when AN enabled
	 *
	 *		see: select_fec_with_an_enabled()
	 *
	 *		_cur is given into aq-cmd buffer: start_an -> __le32 fec_adv;
	 *		in order to fill in our AN base page advertisement,
	 *
	 *				<<802.3>> / 73.6.5 FEC capability
	 *					# FEC (F2, F3, F0, F1) - D44:D47
	 *
	 *				<<PCS>> / 7.3.11 SR_AN_ADV3 - DATA_47_32
	 *
	 *	AN logic:
	 *
			do_AN(u32 current_fec_adv)
			{
				if (current_fec_adv == FEC_OFF) {

					don't set (F2, F3, F0, F1)

				} else if (current_fec_adv == FEC_BASER) {

					set F0, F1, F3		# which are about BASER FEC

				} else if (current_fec_adv == FEC_RS) {

					set F2 (about RS FEC), but not set F0, F1, F3

				} else if (current_fec_adv == (FEC_RS | FEC_BASER)) {

					set all (F2, F3, F0, F1)
				}

				kick AN and send base page...
			}

			u32 original_fec_adv = aq-cmd buffer: start_an -> __le32 fec_adv;

			if (!(original_fec_adv & FEC_AUTO)) {

				current_fec_adv = original_fec_adv & ~FEC_AUTO;

				do_AN(current_fec_adv);

			} else  {	# with FEC_AUTO

				try to do multi times call to do_AN(), each time
				with different current_fec_adv --- switching....
			}
	 */
	u32 req_fec_cur;

	void *sim_info;
};

/* Information about MAC such as address, etc... */
struct nse_mac_info {
	u8 perm_addr[ETH_ALEN];
	u8 lan_addr[ETH_ALEN];	/* runtime lmac addr + wol addr */
};

/* PCI bus types */
enum nse_bus_type {
	nse_bus_unknown = 0,
	nse_bus_pci_express,
	nse_bus_embedded, /* Is device Embedded versus card */
	nse_bus_reserved
};

/* PCI bus speeds */
enum nse_pcie_bus_speed {
	nse_pcie_speed_unknown	= 0xff,
	nse_pcie_speed_2_5GT	= 0x14,
	nse_pcie_speed_5_0GT	= 0x15,
	nse_pcie_speed_8_0GT	= 0x16,
	nse_pcie_speed_16_0GT	= 0x17
};

/* PCI bus widths */
enum nse_pcie_link_width {
	nse_pcie_lnk_width_resrv	= 0x00,
	nse_pcie_lnk_x1			= 0x01,
	nse_pcie_lnk_x2			= 0x02,
	nse_pcie_lnk_x4			= 0x04,
	nse_pcie_lnk_x8			= 0x08,
	nse_pcie_lnk_x12		= 0x0C,
	nse_pcie_lnk_x16		= 0x10,
	nse_pcie_lnk_x32		= 0x20,
	nse_pcie_lnk_width_unknown	= 0xff,
};

/* Reset types used to determine which kind of reset was requested. */
enum nse_reset_req {
	NSE_RESET_POR			= 0,
	NSE_RESET_INVAL			= 0,
	NSE_RESET_NO_RESET		= 0,

	NSE_RESET_PFR			= 1,

	NSE_RESET_HIGH_RESET			= 2,

	NSE_RESET_HIGH_RESET_CORER		= 2,
};

static inline bool nse_is_high_reset_type(enum nse_reset_req r)
{
	return (r > NSE_RESET_PFR);	//>= NSE_RESET_HIGH_RESET
}

/* Bus parameters */
struct nse_bus_info {
	enum nse_pcie_bus_speed speed;
	enum nse_pcie_link_width width;
	enum nse_bus_type type;
	u16 domain_num;
	u16 device;
	u8 func;
	u8 bus_num;
};

struct nse_hw_func_caps {
	bool func_caps_valid;	/* the whole struct contains valid data */

	u8 hw_platform_valid;
	u32 hw_platform;

	/* basic info */
	u8 pcore_id;
	u8 pcore_pf_id;
	u8 dma_id;
	u8 dma_pf_id;
	u8 chan_id;
	u8 chan_pf_id;
	u8 lan_id;

	enum nse_pf_type pf_type;

	u8 mh_dpu_peer_pcore_id;
	u8 mh_dpu_peer_pcore_pf_id;

	u8 lan_bitmap;

	u8 pcore_0_pf_bitmap;
	u8 pcore_1_pf_bitmap;
	u8 cur_pcore_pf_bitmap;

	/* vsi space info */
	u8 vsi_space_valid;
	u8 first_vsi;
	u8 last_vsi;

	/* lan-rxq space info */
	u8 lanrxq_space_valid;
	u16 first_lanrxq;
	u16 last_lanrxq;

	/* lan-txq space info */
	u8 lantxq_space_valid;
	u16 first_lantxq;
	u16 last_lantxq;

	/* irq space info */
	u8 irq_space_valid;
	u16 first_irq;
	u16 last_irq;

	/* VF space info */
	u8 vf_space_valid;
	u8 first_vf;
	u8 vf_num;	/* max VF supported */

	/* lan-tx-cq space info */
	u8 lan_txcq_space_valid;
	u16 first_lan_txcq;
	u16 last_lan_txcq;

	/* rdma-qset space info */
	u8 rdma_qset_space_valid;
	u16 first_rdma_qset;
	u16 last_rdma_qset;

	u8 supported_link_types_speeds_from_fw;	/* if told by FW */
	u32 supported_link_speeds;
	u64 supported_link_types;
};

#define nse_for_each_traffic_class(_i)	\
	for ((_i) = 0; (_i) < NSE_MAX_TRAFFIC_CLASS; (_i)++)

struct nse_sched_node {
	void *hw;		/* for quick back reference */

	struct nse_sched_node *parent;

	struct list_head direct_children_list;
	struct list_head direct_sibling;

	/* next sibling in the same layer, like in pi->sib_head */
	struct nse_sched_node *layer_sibling;

	unsigned int num_children;

	unsigned int layer_id;

	u32 tnid;	/* seid = (tnid >> 1), idx_in_se = (tnid & 0x1) */

	u32 suid;
	u32 logic_idx_in_su;
	u32 old_suid;
	u32 old_logic_idx_in_su;

	u32 flags;
#define NSE_SCHED_NODE_FLAG_INITIAL_NODE	0x1

	u16 vsi_handle;
	u16 vsi_abs_id;

	/* only make sense to LEAF-node */
	u16 qid;
	u16 qid_type;

	u8 in_use;			/* suspended or in use */

	u8 tc_num;
	u8 owner;
#define NSE_SCHED_NODE_OWNER_LAN	0
#define NSE_SCHED_NODE_OWNER_AE		1
#define NSE_SCHED_NODE_OWNER_RDMA	2

	struct nse_sch_node_param sch_param;

	u16 my_cir_contri_to_port_node;	/* valid for port-node */
};

#define NSE_TXSCHED_GET_NODE_TNID(x) ((x)->tnid)

/* The aggregator type determines if identifier is for a VSI group,
 * aggregator group, aggregator of queues, or queue group.
 */
enum nse_agg_type {
	NSE_AGG_TYPE_UNKNOWN = 0,
	NSE_AGG_TYPE_TC,
	NSE_AGG_TYPE_AGG, /* aggregator */
	NSE_AGG_TYPE_VSI,
	NSE_AGG_TYPE_QG,
	NSE_AGG_TYPE_Q
};

#define NSE_SCHED_DFLT_BURST_SIZE	(15 * 1024)	/* in bytes (15k) */

enum nse_bw_type {
	NSE_BW_TYPE_PIR,
	NSE_BW_TYPE_CIR,
	NSE_BW_TYPE_CNT		/* This must be last */
};

struct nse_bw_type_info {
	DECLARE_BITMAP(bw_t_bitmap, NSE_BW_TYPE_CNT);
	u32 pir_user_bw;	/* in kbps */
	u32 cir_user_bw;	/* in kbps */
};

/* VSI queue context structure for given TC */
struct nse_q_ctx {
	u16  q_handle;
	u32  q_tnid;
	/* bw_t_info saves queue BW information explicitly configured by user */
	struct nse_bw_type_info bw_t_info;
};

struct nse_sched_vsi_info {
	struct nse_sched_node *vsi_node[NSE_MAX_TRAFFIC_CLASS];
	struct nse_sched_node *ag_node[NSE_MAX_TRAFFIC_CLASS];
	u16 max_lanq[NSE_MAX_TRAFFIC_CLASS];
	u16 max_rdmaq[NSE_MAX_TRAFFIC_CLASS];

	/* bw_t_info saves VSI BW information explicitly configured by user */
	struct nse_bw_type_info bw_t_info[NSE_MAX_TRAFFIC_CLASS];
};

#define NSE_MAX_USER_PRIORITY		8

struct nse_qos_cfg {
	struct nse_dcbx_cfg local_dcbx_cfg;	/* Oper/Local Cfg */
	struct nse_dcbx_cfg desired_dcbx_cfg;	/* use it for desired -> local conf change */
	struct nse_dcbx_cfg remote_dcbx_cfg;	/* Peer Cfg */

#define NSE_QOS_DCBX_MODE_HOST		0x0
#define NSE_QOS_DCBX_MODE_FW	0x1	/* equal to NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA */
	u8 dcbx_mode;

	/* ugly, moonstone specific logic */
	struct nse_aqc_qos_db_cfg fc_chk_saved_db_cfg;
	struct nse_aqc_qos_db_cfg fc_chk_poll_db_cfg;
};

struct nse_sched_layer_info {
	/* descriptive name of this layer, no actual use, only for display */
	char layer_name[32];

	u32 layer_id;

	/* max children number of a node allowed in this layer */
	u16 max_children;
#define NSE_SCHED_LAYER_MAX_CHILDREN_NUM_1		1	/* only used in initial-tree */
#define NSE_SCHED_LAYER_MAX_CHILDREN_NUM_2		2	/* only used in initial-tree */
#define NSE_SCHED_LAYER_MAX_CHILDREN_NUM_4		4	/* only used in initial-tree */
#define NSE_SCHED_LAYER_MAX_CHILDREN_NUM_8		8
#define NSE_SCHED_LAYER_MAX_CHILDREN_NUM_16		16

	u16 flags;
/* indicate this layer is sw_entry_point_layer */
#define NSE_SCHED_LAYER_FLAG_SW_ENTRY_POINT		0x1
};

struct nse_sched_info {
	struct mutex sched_lock;	/* protect access to TXSched tree */

	u8 sched_state;
#define NSE_SCHED_STATE_INIT	0x0
#define NSE_SCHED_STATE_READY	0x1

	/* Tx Scheduler values */
	unsigned int tree_scheme;

	unsigned int layers_num;
	struct nse_sched_layer_info layers_info[NSE_SCH_TREE_MAX_LAYERS_NUM];

	unsigned int port_node_tnid;
	unsigned int tc_node_tnid_start;
	unsigned int tc_node_tnid_end;

	unsigned int node_space_start;
	unsigned int node_space_size;

	unsigned int layer_id_sw_entry_point;

	unsigned int layer_id_vsi;
	unsigned int layer_id_qgrp;
	unsigned int layer_id_leaf;

	/* shortcut to layer_info->max_children[] */
	u16 max_children[NSE_SCH_TREE_MAX_LAYERS_NUM];

	struct nse_sched_node *root;	/* Root Node per Port */
	struct nse_sched_node *port_node;
	struct nse_sched_node *tc_nodes[NSE_MAX_TRAFFIC_CLASS];

	struct nse_sched_node *
		layer_sibling_head[NSE_MAX_TRAFFIC_CLASS][NSE_SCH_TREE_MAX_LAYERS_NUM];

	struct nse_bw_type_info root_node_bw_t_info;
	struct nse_bw_type_info tc_node_bw_t_info[NSE_MAX_TRAFFIC_CLASS];

	unsigned int max_bandwidth_per_lan_port;		/* Kbps */
	unsigned int max_bandwidth_per_lan_channel;		/* Kbps */

	u64 *factor_tbl;	/* NSE_SCHED_FACTOR_TBL_LEN */
};

struct nse_port_info {
	struct nse_hw *hw;		/* back pointer to HW instance */

	u16 sw_id;			/* Initial switch ID belongs to port */
	u16 pf_vf_num;
	u8 lport;
#define NSE_LPORT_MASK			0xff

	struct nse_mac_info mac;

	struct nse_lmac_phy_info lmac_phy_info;

	struct nse_sched_info sched_info;

	struct nse_qos_cfg qos_cfg;
	u8 dflt_eth_grp_id;
	u8 curr_eth_grp_id;
	u8 is_vf:1;
};

/* member of hw->switch_info->lut_list array, indexed by lut_id
 * multi recipes in different profile will be mapping to one lut info
 * so this lut_info struct represent for recipe template
 */
struct nse_lut_info {
	u16 lut_id;
	struct list_head filt_rules;
	struct mutex filt_rule_lock;

	struct list_head filt_replay_rules;

	/*below definitions are used for advanced situation*/

	struct list_head fv_list; /* associated profiles of this lut */
	struct list_head lut_group_list; /*intermediate lut/recipe group of chained lut */
	u8 n_grp_count;
	u8 is_root;
	u16 root_lut_id; /*temp variable, used for return value*/

	enum nse_sw_tunnel_type tun_type;

	bool is_lpm;

	/* chain id where this lut belong to */
	u8 chain_id;

	struct nse_fv_word ext_words[NSE_MAX_CHAIN_WORDS];
	u16 word_masks[NSE_MAX_CHAIN_WORDS];
	u8 n_ext_words; /* valid num of ext_words */
	u8 big_lut;
	u8 lut_created;
	u8 adv_rule;
	u8 priority;
	u8 hw_prio;
	u8 result_index; /* valid in intermedian lut, but not useful for root lut */
	struct nse_prot_lkup_ext lkup_exts; /* valid only for root lut */

	/* result index bitmap used by this chained recipe,
	 *  max is 4 bits. valid only for root lut
	 */
	DECLARE_BITMAP(res_idxs, NSE_MAX_FV_WORDS);
};

struct nse_profile_info {
	u16 profile_id;
	u8 en; /*profile is enabled or disabled*/
	u8 chain_id;
	u8 profile_type;
	struct nse_fv fv_ptr;
	/*lookup table which this profile associated with*/
	DECLARE_BITMAP(lut_bitmap, NSE_MAX_NUM_LUTS);
	u8 total_recipe_num;
	u8 used_recipe_num;
	u8 fe_num;
	u8 local_rcp; /*num of local rcp by fw*/
	u8 lut_id[NSE_MAX_NUM_RCPS];
};

#define NSE_SW_STATS_PERIOD msecs_to_jiffies(1000)

struct nse_sw_sflow_info {
	u32 group_num;
	u32 rate;
	u32 trunc_size;
};

struct nse_sw_sflow {
	struct nse_sw_sflow_info sflow_info;
	refcount_t ref_cnt;
};

struct nse_sw_stats {
	spinlock_t counters_idr_lock; /* protects counters_idr */
	struct idr counters_idr;
	struct list_head counters;
	struct llist_head addlist;
	struct llist_head dellist;

	struct workqueue_struct *wq;
	struct delayed_work work;

	struct mutex rd_lock;
	struct nse_dma_mem dma_buf;

	unsigned long next_query;
	unsigned long sampling_interval; /* jiffies */
};

struct nse_switch_info {
	struct nse_hw *hw; /*back to hw*/

	struct list_head vsi_list_map_head;
	struct mutex vsi_list_lock;

	struct list_head task_list_head;
	struct mutex task_list_lock;

	struct list_head encap_list_head;
	struct mutex encap_tbl_lock;

	struct list_head m_encap_list_head;
	struct mutex m_encap_lock;

	struct list_head meter_list_head;
	struct mutex meter_list_lock;

	struct list_head ddata_list_head; /*du_data_list_head*/
	struct mutex du_data_lock;

	struct nse_lut_info *lut_list; /* it is array */

	/*below definitions are used for advanced situation*/
	struct nse_sw_sflow *sflow;
	struct nse_sw_stats	sw_stats; /*sw counter*/
	u16 prof_res_bm_init;
	DECLARE_BITMAP(prof_res_bm[NSE_MAX_NUM_PROFILES], NSE_MAX_FV_WORDS);
	struct nse_profile_info *profile_list; /* it is array, num is NSE_MAX_NUM_PROFILES */
	u16 max_used_prof_index; /* max profile index of above profile_list*/

	bool lpm_en;
};

#define NSE_LEGACY_MAC_TALBE_ENTRY_NUM 16
#define NSE_LEGACY_VLAN_TALBE_ENTRY_NUM 8
#define NSE_LEGACY_ETHTYPE_TALBE_ENTRY_NUM 8

struct nse_legacy_mac_fltr {
	u8 addr[ETH_ALEN];
	u16 state; /* bitmask */
	u8 vsi_list;
};

struct nse_legacy_vlan_fltr {
	u16 vid;
	u16 state; /* bitmask */
	u8 vsi_list;
};

struct nse_legacy_ethtype_fltr {
	u16 ethtype;
	u16 state; /* bitmask */
	u8 vsi_list;
};

struct nse_legacy_switch {
	struct nse_hw *hw; /*back to hw*/

	struct list_head mac_replay_list;
	struct mutex mac_tbl_lock;
	u32 num_mac_entries;
	struct nse_legacy_mac_fltr mac_table[NSE_LEGACY_MAC_TALBE_ENTRY_NUM];

	struct list_head vlan_replay_list;
	struct mutex vlan_tbl_lock;
	u32 num_vlan_entries;
	struct nse_legacy_vlan_fltr vlan_table[NSE_LEGACY_VLAN_TALBE_ENTRY_NUM];

	struct list_head ethtype_replay_list;
	struct mutex ethtype_tbl_lock;
	u32 num_ethtype_entries;
	struct nse_legacy_ethtype_fltr ethtype_table[NSE_LEGACY_ETHTYPE_TALBE_ENTRY_NUM];

};

struct nse_fdir_input_stream {
	u8 pad0;
	u8 vsi;
	__le16 flex_bytes;
	__le16 dst_port;
	__le16 src_port;
	__le32 dst_ip[4];
	__le32 src_ip[4];
	u8 ptype;
	u8 pad1;
} __packed;

struct nse_fdir_utilq_config_payload {
	__le32 ip6_sa1;
	__le32 ip6_sa2;
	__le32 ip6_sa3;
	__le32 sa0;

	__le32 da;
	__le32 port;

	__le32 flex;
	__le32 hash;

	__le32 cmd;

	__le32 rsv;
} __packed;

struct nse_fdir_vsi_hw_input_mask_info {
	struct nse_aqc_fdir_get_set_vsi_input_mask hw_input_mask;

	/* which part are now with valid value --- corresponding to hw_input_mask fields */
	unsigned int valid_reg_flex_cfg;	/* use it as bool */
	/* use it as refcnt, except for FDIR_MASK_IDX_OTHER */
	unsigned int valid_reg_mask[7];
};

struct nse_fdir_filter {
	struct hlist_node hnode;

	struct nse_fdir_input_stream input_stream;
	struct nse_fdir_input_stream input_stream_mask;

	struct nse_fdir_vsi_hw_input_mask_info expected_vsi_hw_input_mask_info;

	u16 bkt_hash;	/* Lookup Table HASH */
	u16 sig_hash;	/* Signature HASH, only used in signature mode */

	u16 sw_idx;

	u16 is_action_drop;

	u16 action_rxq_abs_id;

	/* save fsp input for quick GET */
	struct ethtool_rx_flow_spec	fs;
};

struct nse_fdir_ntuple_userdef {
	u16 flex_fltr;	/* 0 for false, 1 for true */

	u16 flex_base;
	u16 flex_offset;
	u16 flex_word;
};

struct nse_fdir_cb {
	struct nse_hw *hw;

	struct hlist_head filter_list;
	unsigned int filter_count;

	/* current, also as backup */
	struct nse_fdir_vsi_hw_input_mask_info vsi_hw_input_mask_info;
	/* about configure to HW */
	struct nse_fdir_vsi_hw_input_mask_info vsi_hw_input_mask_info_tohw;

	/* this field is just for easy reference - their actual setting are in vsi_hw_input_mask */
	struct nse_fdir_ntuple_userdef flex_setting;

	struct nse_ctl_q_info utilq;
	bool utilq_initialized;

	u16 drp_rxq_rel_id;
	u16 drp_txq_rel_id;

	struct mutex lock;

	struct nse_aqc_fdir_query_setting setting;

	u32 mode;	/* 0 - signature, 1 - perfect */

	u32 max_num_pfilter;
	u32 max_num_sfilter;
	u32 max_num_pfilter_pf_vsi; /* fdir perfect filter alloced to PF main vsi */
	u32 max_num_sfilter_pf_vsi; /* fdir signature filter alloced to PF main vsi */
	u32 max_num_pfilter_vfs; /* fdir perfect filter alloced to vf */
	u32 max_num_sfilter_vfs; /* fdir signature filter alloced to vf */
};

struct nse_logall_info_entry {
	u64 bitmap_addr;
	u32 bitmap_len;
	u16 vsi_id;
	u8 entry_sts;
#define NSE_LOGALL_INFO_ENTRY_OCCUPIED 1
	u8 pad;
};

/* Port hardware description */
struct nse_hw {
	u8 __iomem *hw_addr;
	u8 __iomem *hw_addr_bar2;

	void *back;

	struct mutex fwmng_lock;	/* for serializing fwmng */

	struct nse_port_info *port_info;

	struct nse_fdir_cb fdir_cb;

	struct nse_logall_info_entry logall_ctl_array[8];

	u64 debug_mask;		/* BITMAP for debug mask */
	enum nse_mac_type mac_type;

	enum nse_nic_type nic_type;

	/* pci info */
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;

	/* basic info from nse_hw_func_caps, for easy reference */
	u8 pcore_id;
	u8 pcore_pf_id;
	u8 dma_id;
	u8 dma_pf_id;
	u8 chan_id;
	u8 chan_pf_id;
	u8 lan_id;

	enum nse_pf_type pf_type;
	bool is_mh_dpu_secondary_pf;

	u8 mh_dpu_peer_pcore_id;
	u8 mh_dpu_peer_pcore_pf_id;

	u8 lan_bitmap;
	/* do I have any sibling PF using the same Channel ? */
	bool is_only_lan_in_chan;
	bool is_only_pf_in_dma;		/* do I have any sibling PF using the same DMA ? */

	u8 cur_pcore_pf_bitmap;

	struct nse_hw_conf hw_conf;
	struct nse_fw_conf fw_conf;

	struct nse_aqc_xchg_ver_fw_ver fw_ver;
	bool refused_by_fw;

	struct nse_hw_func_caps func_caps;	/* function capabilities */

	struct nse_vsi_ctx *vsi_ctx[NSE_MAX_VSI];
	u8 evb_veb;		/* true for VEB, false for VEPA */

	bool high_reset_ongoing;	/* true if HW is in reset, false otherwise */

	struct nse_bus_info bus;

	struct nse_switch_info *switch_info;	/* switch filter lists */

	struct nse_legacy_switch *legacy_switch; /*legacy switch filters*/

	/* Control Queue info */
	struct nse_ctl_q_info adminq;	/* Also use it to acchieve PF mailboxq */

#define NSE_ITR_GRAN_FIXED		2
	u8 itr_gran;
#define NSE_INTRL_GRAN_FIXED	4
	u8 intrl_gran;

	/* true if VSIs can share unicast MAC addr */
	u8 umac_shared;

	u16 stag_ethertype;	/* host order, ETH_P_8021Q or ETH_P_8021AD */

	/* stats info of adminQ / mailboxQ / utilQ.
	 */
	struct {
		u64 sq_total_cnt;
		u64 sq_success_cnt;
		u64 sq_fail_cnt;
		u64 sq_fail_timeout_cnt;

		u64 sq_total_ns;
		u64 sq_success_ns;
		u64 sq_fail_ns;
		u64 sq_fail_timeout_ns;

		u64 aq_cmd_shutdown_time;
		u64 aq_cmd_shutdown_cnt;

		u64 aq_sq_wait_for_fw_pause_disable_fail_cnt;
		u64 aq_sq_wait_for_fw_pause_disable_fail_time;

		u64 aq_sq_wait_for_sw_pause_fail_cnt;
		u64 aq_sq_wait_for_sw_pause_fail_time;

		u64 aq_sq_wait_for_sw_disable_fail_cnt;
		u64 aq_sq_wait_for_sw_disable_fail_time;

		u64 aq_rq_wait_for_fw_pause_disable_fail_cnt;
		u64 aq_rq_wait_for_fw_pause_disable_fail_time;

		u64 aq_rq_wait_for_sw_pause_fail_cnt;
		u64 aq_rq_wait_for_sw_pause_fail_time;

		u64 aq_rq_wait_for_sw_disable_fail_cnt;
		u64 aq_rq_wait_for_sw_disable_fail_time;

		u64 mq_cmd_shutdown_time;
		u64 mq_cmd_shutdown_cnt;

		u64 mq_sq_wait_for_fw_pause_disable_fail_cnt;
		u64 mq_sq_wait_for_fw_pause_disable_fail_time;

		u64 mq_sq_wait_for_sw_pause_fail_cnt;
		u64 mq_sq_wait_for_sw_pause_fail_time;

		u64 mq_sq_wait_for_sw_disable_fail_cnt;
		u64 mq_sq_wait_for_sw_disable_fail_time;

		u64 mq_rq_wait_for_fw_pause_disable_fail_cnt;
		u64 mq_rq_wait_for_fw_pause_disable_fail_time;

		u64 mq_rq_wait_for_sw_pause_fail_cnt;
		u64 mq_rq_wait_for_sw_pause_fail_time;

		u64 mq_rq_wait_for_sw_disable_fail_cnt;
		u64 mq_rq_wait_for_sw_disable_fail_time;

		u64 uq_sq_wait_for_sw_pause_fail_cnt;
		u64 uq_sq_wait_for_sw_pause_fail_time;

		u64 uq_sq_wait_for_sw_disable_fail_cnt;
		u64 uq_sq_wait_for_sw_disable_fail_time;
	} controlq_stats;
};

static inline bool nse_is_nic_use_ephy(enum nse_nic_type nic_type)
{
	return (nic_type == NSE_NIC_TYPE_1000BASE_T ||
			nic_type == NSE_NIC_TYPE_SFP ||
			nic_type == NSE_NIC_TYPE_QSFP);
}

struct nse_vsi_sw_stats {
	u64 rx_pkts;
	u64 rx_bytes;
	u64 tx_pkts;
	u64 tx_bytes;

	u64 tx_linearize;
	u64 tx_restart;
	u64 tx_busy;

	u64 rx_csum_good;
	u64 rx_csum_bad;

	u64 fdir_match;
	u64 fdir_miss;

	u64 rx_buf_failed;
	u64 rx_page_failed;
#ifdef NSE_ADD_PROBES
	u64 rx_page_reuse;
#endif /* NSE_ADD_PROBES */
};

struct nse_vsi_hw_stats_raw {
	struct nse_aqc_rc_dma_chan_per_vsi_stats raw_vsi_stats;
};

struct nse_vsi_hw_stats {
	u64 rx_drop_err;
	u64 rx_drop_no_desc;
	u64 rx_dpkt;
	u64 rx_goct;
	u64 rx_gpkt;
	u64 rx_mpkt;
	u64 rx_bpkt;

	u64 rx_upkt;

	u64 tx_gptc;
	u64 tx_gotc;
	u64 tx_dptc;
	u64 tx_mptc;
	u64 tx_bptc;

	u64 tx_uptc;
};

struct nse_hw_port_stats_raw {
	/* raw HW stats collected by the port */
	struct nse_aqc_lmac_stats raw_lmac_stats;
	struct nse_aqc_rc_dma_chan_total_stats raw_dma_chan_total_stats;
};

/* Statistics collected by the MAC */
struct nse_hw_port_stats {
	u64 tx_pkts_good_bad;
	u64 tx_pkts_good;
	u64 tx_pkts_bad;
	u64 tx_bytes_good_bad;
	u64 tx_bytes_good;
	u64 tx_bytes_bad;
	u64 tx_broadcast_good_bad;
	u64 tx_broadcast_good;
	u64 tx_broadcast_bad;
	u64 tx_multicast_good_bad;
	u64 tx_multicast_good;
	u64 tx_multicast_bad;
	u64 tx_unicast_good_bad;
	u64 tx_unicast_good;
	u64 tx_unicast_bad;
	u64 tx_64_good_bad;
	u64 tx_64_to_127_good_bad;
	u64 tx_128_to_255_good_bad;
	u64 tx_256_to_511_good_bad;
	u64 tx_512_to_1023_good_bad;
	u64 tx_1024_to_max_good_bad;
	u64 tx_underflow_error;
	u64 tx_lfc;
	u64 tx_pfc;

	u64 rx_pkts_good_bad;
	u64 rx_pkts_good;
	u64 rx_pkts_bad;
	u64 rx_bytes_good_bad;
	u64 rx_bytes_good;
	u64 rx_bytes_bad;
	u64 rx_broadcast_good_bad;
	u64 rx_broadcast_good;
	u64 rx_broadcast_bad;
	u64 rx_multicast_good_bad;
	u64 rx_multicast_good;
	u64 rx_multicast_bad;
	u64 rx_unicast_good_bad;
	u64 rx_unicast_good;
	u64 rx_unicast_bad;
	u64 rx_64_good_bad;
	u64 rx_64_to_127_good_bad;
	u64 rx_128_to_255_good_bad;
	u64 rx_256_to_511_good_bad;
	u64 rx_512_to_1023_good_bad;
	u64 rx_1024_to_max_good_bad;
	u64 rx_undersize_good;
	u64 rx_oversize_good;
	u64 rx_crc_error;
	u64 rx_runt_error;
	u64 rx_jabber_error;
	u64 rx_length_error;
	u64 rx_out_of_range;

	u64 rx_lfc;
	u64 rx_pfc;

	u64 rx_error;

	u64 fdir_match;
	u64 fdir_miss;

	/* detailed stats of lfc and pfc --- in addition to: rx_pause, rx_fpc, tx_pause, tx_pfc */
	u64 tx_lfc_xoff;
	u64 tx_lfc_xon;
	u64 rx_lfc_xoff;
	u64 rx_lfc_xon;
	u64 tx_pfc_xoff[8];
	u64 tx_pfc_xon[8];
	u64 rx_pfc_xoff[8];
	u64 rx_pfc_xon[8];
};

static inline void
nse_aqc_fill_generic_common_hdr_dft(struct nse_hw *hw, struct nse_aqc_generic_common_hdr *hdr,
									u16 vsi_abs_id)
{
	memset(hdr, 0, sizeof(*hdr));

	hdr->magic = 0x88;

	hdr->pcore_id = hw->pcore_id;
	hdr->pcore_pf_id = hw->pcore_pf_id;

	hdr->dma_id = hw->dma_id;
	hdr->dma_pf_id = hw->dma_pf_id;

	hdr->chan_id = hw->chan_id;
	hdr->chan_pf_id = hw->chan_pf_id;

	hdr->lan_id = hw->lan_id;

	hdr->vsi_abs_id = cpu_to_le16(vsi_abs_id);
};

void nse_aqc_dump_generic_common_hdr(struct nse_hw *hw, struct nse_aqc_generic_common_hdr *hdr);

/*nse_sw_fwd_act_type is related to lut node only,
 * that means signal action in lut node.
 * If Node state, NSE_LARGE_ACT is used.
 */
enum nse_sw_fwd_act_type {
	NSE_FWD_TO_VSI = 0,
	NSE_FWD_TO_VSI_LIST,
	NSE_FWD_TO_Q,
	NSE_FWD_TO_QGRP,
	NSE_DROP_PACKET,
	NSE_FWD_TO_LAN, /*to Lan only*/
	NSE_LARGE_ACT,
	NSE_FAST_ACT,
	NSE_FWD_BMC,
	NSE_INVAL_ACT
};

/*nse_sw_du_act_type is used to node state du action only,
 * NSE_LARGE_ACT is used in lut node
 */
enum nse_sw_du_act_type {
	NSE_DU_ACT_FWD_TO_VSI = 0,
	NSE_DU_ACT_FWD_TO_VSI_LIST,
	NSE_DU_ACT_FWD_TO_Q,
	NSE_DU_ACT_FWD_TO_QGRP,
	NSE_DU_ACT_FWD_TO_LAN,
	NSE_DU_ACT_DROP_PACKET,
	NSE_DU_ACT_COUNT_PACKET,
	NSE_DU_ACT_COUNT_BYTE,
	NSE_DU_ACT_NOP,
	NSE_DU_ACT_DECAP,
	NSE_DU_ACT_METER,
	NSE_DU_ACT_SFLOW,
	NSE_DU_ACT_DUP,
	NSE_DU_ACT_GOTO_CHAIN,
	NSE_DU_ACT_SET_GENERIC_MD,
	NSE_DU_ACT_INVAL_ACT
};

#endif /* _NSE_TYPE_H_ */

