/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_lldp_tlv.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_LLDP_TLV_H__
#define __SXE2_LLDP_TLV_H__

#include <linux/netdevice.h>
#include <linux/types.h>
#include "sxe2_cmd.h"

#define SXE2_TLV_STATUS_OPER		0x1
#define SXE2_TLV_STATUS_SYNC		0x2
#define SXE2_TLV_STATUS_ERR		0x4
#define SXE2_APP_PROT_ID_ISCSI_860	0x035c
#define SXE2_APP_SEL_ETHTYPE		0x1
#define SXE2_APP_SEL_TCPIP		0x2
#define SXE2_CEE_APP_SEL_ETHTYPE	0x0
#define SXE2_CEE_APP_SEL_TCPIP		0x1

#define SXE2_DCBX_STATUS_NOT_STARTED	0
#define SXE2_DCBX_STATUS_IN_PROGRESS	1
#define SXE2_DCBX_STATUS_DONE		2
#define SXE2_DCBX_STATUS_DIS		7

#define SXE2_TLV_TYPE_END		0
#define SXE2_TLV_TYPE_ORG		127

#define SXE2_IEEE_8021QAZ_OUI		0x0080C2
#define SXE2_IEEE_SUBTYPE_ETS_CFG	9
#define SXE2_IEEE_SUBTYPE_ETS_REC	10
#define SXE2_IEEE_SUBTYPE_PFC_CFG	11
#define SXE2_IEEE_SUBTYPE_APP_PRI	12

#define SXE2_CEE_DCBX_OUI		0x001B21
#define SXE2_CEE_DCBX_TYPE		2

#define SXE2_CEE_SUBTYPE_PG_CFG	2
#define SXE2_CEE_SUBTYPE_PFC_CFG	3
#define SXE2_CEE_SUBTYPE_APP_PRI	4
#define SXE2_CEE_MAX_FEAT_TYPE		3

#define SXE2_LLDP_TLV_LEN_S		0
#define SXE2_LLDP_TLV_LEN_M		(0x01FF << SXE2_LLDP_TLV_LEN_S)
#define SXE2_LLDP_TLV_TYPE_S		9
#define SXE2_LLDP_TLV_TYPE_M		(0x7F << SXE2_LLDP_TLV_TYPE_S)
#define SXE2_LLDP_TLV_SUBTYPE_S		0
#define SXE2_LLDP_TLV_SUBTYPE_M		(0xFF << SXE2_LLDP_TLV_SUBTYPE_S)
#define SXE2_LLDP_TLV_OUI_S		8
#define SXE2_LLDP_TLV_OUI_M		(0xFFFFFFUL << SXE2_LLDP_TLV_OUI_S)

#define SXE2_IEEE_ETS_MAXTC_S		0
#define SXE2_IEEE_ETS_MAXTC_M		(0x7 << SXE2_IEEE_ETS_MAXTC_S)
#define SXE2_IEEE_ETS_CBS_S		6
#define SXE2_IEEE_ETS_CBS_M		BIT(SXE2_IEEE_ETS_CBS_S)
#define SXE2_IEEE_ETS_WILLING_S		7
#define SXE2_IEEE_ETS_WILLING_M	BIT(SXE2_IEEE_ETS_WILLING_S)
#define SXE2_IEEE_ETS_PRIO_0_S		0
#define SXE2_IEEE_ETS_PRIO_0_M		(0x7 << SXE2_IEEE_ETS_PRIO_0_S)
#define SXE2_IEEE_ETS_PRIO_1_S		4
#define SXE2_IEEE_ETS_PRIO_1_M		(0x7 << SXE2_IEEE_ETS_PRIO_1_S)
#define SXE2_CEE_PGID_PRIO_0_S		0
#define SXE2_CEE_PGID_PRIO_0_M		(0xF << SXE2_CEE_PGID_PRIO_0_S)
#define SXE2_CEE_PGID_PRIO_1_S		4
#define SXE2_CEE_PGID_PRIO_1_M		(0xF << SXE2_CEE_PGID_PRIO_1_S)
#define SXE2_CEE_PGID_STRICT		15

#define SXE2_IEEE_TSA_STRICT		0
#define SXE2_IEEE_TSA_ETS		2

#define SXE2_IEEE_PFC_CAP_S		0
#define SXE2_IEEE_PFC_CAP_M		(0xF << SXE2_IEEE_PFC_CAP_S)
#define SXE2_IEEE_PFC_MBC_S		6
#define SXE2_IEEE_PFC_MBC_M		BIT(SXE2_IEEE_PFC_MBC_S)
#define SXE2_IEEE_PFC_WILLING_S		7
#define SXE2_IEEE_PFC_WILLING_M		BIT(SXE2_IEEE_PFC_WILLING_S)

#define SXE2_IEEE_APP_SEL_S		0
#define SXE2_IEEE_APP_SEL_M		(0x7 << SXE2_IEEE_APP_SEL_S)
#define SXE2_IEEE_APP_PRIO_S		5
#define SXE2_IEEE_APP_PRIO_M		(0x7 << SXE2_IEEE_APP_PRIO_S)

#define SXE2_LLDPDU_SIZE		1500
#define SXE2_TLV_HEADER_LEN		2

#define SXE2_IEEE_ETS_TLV_LEN		25
#define SXE2_IEEE_PFC_TLV_LEN		6
#define SXE2_IEEE_APP_TLV_LEN		11

#define SXE2_DSCP_UP_TLV_LEN		148
#define SXE2_DSCP_ENF_TLV_LEN		132
#define SXE2_DSCP_TC_BW_TLV_LEN		33
#define SXE2_DSCP_PFC_TLV_LEN		6

#define SXE2_IEEE_TLV_ID_ETS_CFG	3
#define SXE2_IEEE_TLV_ID_ETS_REC	4
#define SXE2_IEEE_TLV_ID_PFC_CFG	5
#define SXE2_IEEE_TLV_ID_APP_PRI	6
#define SXE2_TLV_ID_END_OF_LLDPPDU	7
#define SXE2_TLV_ID_START		SXE2_IEEE_TLV_ID_ETS_CFG
#define SXE2_TLV_ID_DSCP_UP		3
#define SXE2_TLV_ID_DSCP_ENF		4
#define SXE2_TLV_ID_DSCP_TC_BW		5
#define SXE2_TLV_ID_DSCP_TO_PFC	6

struct sxe2_lldp_org_tlv {
	__be16 typelen;
	__be32 ouisubtype;
	u8 tlvinfo[];
} __packed;

struct sxe2_cee_tlv_hdr {
	__be16 typelen;
	u8 operver;
	u8 maxver;
};

struct sxe2_cee_ctrl_tlv {
	struct sxe2_cee_tlv_hdr hdr;
	__be32 seqno;
	__be32 ackno;
};

struct sxe2_cee_feat_tlv {
	struct sxe2_cee_tlv_hdr hdr;
	u8 en_will_err;
#define SXE2_CEE_FEAT_TLV_ENA_M		0x80
#define SXE2_CEE_FEAT_TLV_WILLING_M	0x40
#define SXE2_CEE_FEAT_TLV_ERR_M		0x20
	u8 subtype;
	u8 tlvinfo[];
};

struct sxe2_cee_app_prio {
	__be16 protocol;
	u8 upper_oui_sel;
#define SXE2_CEE_APP_SELECTOR_M	0x03
	__be16 lower_oui;
	u8 prio_map;
} __packed;

void sxe2_dcb_cfg_to_lldp(u8 *lldpmib, u16 *miblen,
			  struct sxe2_dcbx_cfg *dcbcfg);

s32 sxe2_fw_dcbx_agent_cfg_get(struct sxe2_adapter *adapter,
			       struct sxe2_dcbx_cfg *dcbcfg);

s32 sxe2_lldp_to_dcb_cfg(u8 *lldpmib, struct sxe2_dcbx_cfg *dcbcfg);

#endif
