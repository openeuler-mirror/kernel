// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_lldp_tlv.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_dcb.h"
#include "sxe2_dcb_nl.h"
#include "sxe2_lldp_tlv.h"
#include <net/dcbnl.h>

static void sxe2_ieee_ets_common_tlv_add(u8 *buf, struct sxe2_dcb_ets_cfg *ets_cfg)
{
	u32 i;
	u8 offset = 0;
	u8 priority0, priority1;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS / 2; i++) {
		priority0 = ets_cfg->prio_tbl[i * 2] & 0xF;
		priority1 = ets_cfg->prio_tbl[i * 2 + 1] & 0xF;
		buf[offset] = (u8)(priority0 << SXE2_IEEE_ETS_PRIO_1_S) | priority1;
		offset++;
	}

	sxe2_for_each_tc(i) {
		buf[offset] = ets_cfg->tcbw_tbl[i];
		buf[IEEE_8021QAZ_MAX_TCS + offset] = ets_cfg->tsa_tbl[i];
		offset++;
	}
}

static void sxe2_ieee_ets_tlv_add(struct sxe2_lldp_org_tlv *tlv,
				  struct sxe2_dcbx_cfg *dcbcfg)
{
	u16 typelen;
	u32 ouisubtype;
	u8  maxtcwilling = 0;
	u8  *buf = tlv->tlvinfo;
	struct sxe2_dcb_ets_cfg *etscfg;

	typelen = ((SXE2_TLV_TYPE_ORG << SXE2_LLDP_TLV_TYPE_S) |
		   SXE2_IEEE_ETS_TLV_LEN);
	tlv->typelen = htons(typelen);

	ouisubtype = ((SXE2_IEEE_8021QAZ_OUI << SXE2_LLDP_TLV_OUI_S) |
		      SXE2_IEEE_SUBTYPE_ETS_CFG);

	tlv->ouisubtype = htonl(ouisubtype);

	etscfg = &dcbcfg->ets;

	if (etscfg->willing)
		maxtcwilling = BIT(SXE2_IEEE_ETS_WILLING_S);
	maxtcwilling |= etscfg->maxtcs & SXE2_IEEE_ETS_MAXTC_M;
	buf[0] = maxtcwilling;

	sxe2_ieee_ets_common_tlv_add(&buf[1], etscfg);
}

static void sxe2_ieee_etsrec_tlv_add(struct sxe2_lldp_org_tlv *tlv,
				     struct sxe2_dcbx_cfg *dcbcfg)
{
	u16 typelen;
	u32 ouisubtype;
	u8 *buf = tlv->tlvinfo;
	struct sxe2_dcb_ets_cfg *etsrec;

	typelen = ((SXE2_TLV_TYPE_ORG << SXE2_LLDP_TLV_TYPE_S) |
		   SXE2_IEEE_ETS_TLV_LEN);
	tlv->typelen = htons(typelen);

	ouisubtype = ((SXE2_IEEE_8021QAZ_OUI << SXE2_LLDP_TLV_OUI_S) |
		      SXE2_IEEE_SUBTYPE_ETS_REC);
	tlv->ouisubtype = htonl(ouisubtype);

	etsrec = &dcbcfg->etsrec;

	sxe2_ieee_ets_common_tlv_add(&buf[1], etsrec);
}

static void sxe2_ieee_pfc_tlv_add(struct sxe2_lldp_org_tlv *tlv,
				  struct sxe2_dcbx_cfg *dcbcfg)
{
	u8 *buf = tlv->tlvinfo;
	u32 ouisubtype;
	u16 typelen;

	typelen = ((SXE2_TLV_TYPE_ORG << SXE2_LLDP_TLV_TYPE_S) |
		   SXE2_IEEE_PFC_TLV_LEN);
	tlv->typelen = htons(typelen);

	ouisubtype = ((SXE2_IEEE_8021QAZ_OUI << SXE2_LLDP_TLV_OUI_S) |
		      SXE2_IEEE_SUBTYPE_PFC_CFG);
	tlv->ouisubtype = htonl(ouisubtype);

	buf[0] = 0;
	buf[1] = 0;
	if (dcbcfg->pfc.willing)
		buf[0] = BIT(SXE2_IEEE_PFC_WILLING_S);

	if (dcbcfg->pfc.mbc)
		buf[0] |= BIT(SXE2_IEEE_PFC_MBC_S);

	buf[0] |= (u8)(dcbcfg->pfc.cap & 0xF);
	buf[1] = dcbcfg->pfc.enable;
}

static void sxe2_ieee_app_pri_tlv_add(struct sxe2_lldp_org_tlv *tlv,
				      struct sxe2_dcbx_cfg *dcbcfg)
{
	u16 typelen, len, offset = 0;
	u8 priority, selector, i = 0;
	u8 *buf = tlv->tlvinfo;
	u32 ouisubtype;

	if (dcbcfg->numapps == 0)
		return;
	ouisubtype = ((SXE2_IEEE_8021QAZ_OUI << SXE2_LLDP_TLV_OUI_S) |
		      SXE2_IEEE_SUBTYPE_APP_PRI);
	tlv->ouisubtype = htonl(ouisubtype);

	offset++;
	while (i < dcbcfg->numapps) {
		priority = dcbcfg->app[i].prio & 0x7;
		selector = dcbcfg->app[i].selector & 0x7;
		buf[offset] = (u8)(priority << SXE2_IEEE_APP_PRIO_S) | selector;
		buf[offset + 1] = (dcbcfg->app[i].prot_id >> 0x8) & 0xFF;
		buf[offset + 2] = dcbcfg->app[i].prot_id & 0xFF;

		offset += 3;
		i++;
		if (i >= SXE2_DCBX_MAX_APPS)
			break;
	}

	len = sizeof(tlv->ouisubtype) + 1 + (i * 3);
	typelen = ((SXE2_TLV_TYPE_ORG << SXE2_LLDP_TLV_TYPE_S) | (len & 0x1FF));
	tlv->typelen = htons(typelen);
}

static void sxe2_dscp_up_tlv_add(struct sxe2_lldp_org_tlv *tlv,
				 struct sxe2_dcbx_cfg *dcbcfg)
{
	u8 *buf = tlv->tlvinfo;
	u32 ouisubtype;
	u16 typelen;
	int i;

	typelen = ((SXE2_TLV_TYPE_ORG << SXE2_LLDP_TLV_TYPE_S) |
		   SXE2_DSCP_UP_TLV_LEN);
	tlv->typelen = htons(typelen);

	ouisubtype = (u32)((SXE2_DSCP_OUI << SXE2_LLDP_TLV_OUI_S) |
			   SXE2_DSCP_SUBTYPE_DSCP2UP);
	tlv->ouisubtype = htonl(ouisubtype);

	for (i = 0; i < SXE2_DSCP_NUM_VAL; i++) {
		buf[i] = dcbcfg->dscp_map[i];
		buf[i + SXE2_DSCP_IPV6_OFFSET] = dcbcfg->dscp_map[i];
	}

	buf[i] = 0;

	buf[i + SXE2_DSCP_IPV6_OFFSET] = 0;
}

#define SXE2_BYTES_PER_TC 8
static void sxe2_dscp_enf_tlv_add(struct sxe2_lldp_org_tlv *tlv)
{
	u8 *buf = tlv->tlvinfo;
	u32 ouisubtype;
	u16 typelen;

	typelen = ((SXE2_TLV_TYPE_ORG << SXE2_LLDP_TLV_TYPE_S) |
		   SXE2_DSCP_ENF_TLV_LEN);
	tlv->typelen = htons(typelen);

	ouisubtype = (u32)((SXE2_DSCP_OUI << SXE2_LLDP_TLV_OUI_S) |
			   SXE2_DSCP_SUBTYPE_ENFORCE);
	tlv->ouisubtype = htonl(ouisubtype);

	(void)memset(buf, 0, 2 * (IEEE_8021QAZ_MAX_TCS * SXE2_BYTES_PER_TC));
}

static void sxe2_dscp_tc_bw_tlv_add(struct sxe2_lldp_org_tlv *tlv,
				    struct sxe2_dcbx_cfg *dcbcfg)
{
	u32 i;
	u16 typelen;
	u8 offset = 0;
	u32 ouisubtype;
	u8 *buf = tlv->tlvinfo;
	struct sxe2_dcb_ets_cfg *etscfg;

	typelen = ((SXE2_TLV_TYPE_ORG << SXE2_LLDP_TLV_TYPE_S) |
		   SXE2_DSCP_TC_BW_TLV_LEN);
	tlv->typelen = htons(typelen);

	ouisubtype = (u32)((SXE2_DSCP_OUI << SXE2_LLDP_TLV_OUI_S) |
			   SXE2_DSCP_SUBTYPE_TCBW);
	tlv->ouisubtype = htonl(ouisubtype);

	etscfg = &dcbcfg->ets;
	buf[0] = etscfg->maxtcs & SXE2_IEEE_ETS_MAXTC_M;

	offset = 5;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		buf[offset] = etscfg->tcbw_tbl[i];
		buf[offset + IEEE_8021QAZ_MAX_TCS] = etscfg->tsa_tbl[i];
		buf[offset + IEEE_8021QAZ_MAX_TCS * 2] = etscfg->prio_tbl[i];
		offset++;
	}
}

static void sxe2_dscp_pfc_tlv_add(struct sxe2_lldp_org_tlv *tlv,
				  struct sxe2_dcbx_cfg *dcbcfg)
{
	u16 typelen;
	u32 ouisubtype;
	u8 *buf = tlv->tlvinfo;

	typelen = ((SXE2_TLV_TYPE_ORG << SXE2_LLDP_TLV_TYPE_S) |
		   SXE2_DSCP_PFC_TLV_LEN);
	tlv->typelen = htons(typelen);

	ouisubtype = (u32)((SXE2_DSCP_OUI << SXE2_LLDP_TLV_OUI_S) |
			   SXE2_DSCP_SUBTYPE_PFC);
	tlv->ouisubtype = htonl(ouisubtype);

	buf[0] = dcbcfg->pfc.cap & 0xF;
	buf[1] = dcbcfg->pfc.enable;
}

STATIC void sxe2_dcb_tlv_add(struct sxe2_lldp_org_tlv *tlv,
			     struct sxe2_dcbx_cfg *dcbcfg, u16 tlvid)
{
	if (dcbcfg->qos_mode == SXE2_QOS_MODE_VLAN) {
		switch (tlvid) {
		case SXE2_IEEE_TLV_ID_ETS_CFG:
			sxe2_ieee_ets_tlv_add(tlv, dcbcfg);
			break;
		case SXE2_IEEE_TLV_ID_ETS_REC:
			sxe2_ieee_etsrec_tlv_add(tlv, dcbcfg);
			break;
		case SXE2_IEEE_TLV_ID_PFC_CFG:
			sxe2_ieee_pfc_tlv_add(tlv, dcbcfg);
			break;
		case SXE2_IEEE_TLV_ID_APP_PRI:
			sxe2_ieee_app_pri_tlv_add(tlv, dcbcfg);
			break;
		default:
			break;
		}
	} else {
		switch (tlvid) {
		case SXE2_TLV_ID_DSCP_UP:
			sxe2_dscp_up_tlv_add(tlv, dcbcfg);
			break;
		case SXE2_TLV_ID_DSCP_ENF:
			sxe2_dscp_enf_tlv_add(tlv);
			break;
		case SXE2_TLV_ID_DSCP_TC_BW:
			sxe2_dscp_tc_bw_tlv_add(tlv, dcbcfg);
			break;
		case SXE2_TLV_ID_DSCP_TO_PFC:
			sxe2_dscp_pfc_tlv_add(tlv, dcbcfg);
			break;
		default:
			break;
		}
	}
}

void sxe2_dcb_cfg_to_lldp(u8 *lldpmib, u16 *miblen,
			  struct sxe2_dcbx_cfg *dcbcfg)
{
	u16 typelen;
	struct sxe2_lldp_org_tlv *tlv;
	u16 len, offset = 0, tlvid = SXE2_TLV_ID_START;

	tlv = (struct sxe2_lldp_org_tlv *)lldpmib;
	while (1) {
		sxe2_dcb_tlv_add(tlv, dcbcfg, tlvid++);

		typelen = ntohs(tlv->typelen);
		len = (typelen & SXE2_LLDP_TLV_LEN_M) >> SXE2_LLDP_TLV_LEN_S;
		if (len)
			offset += len + SXE2_TLV_HEADER_LEN;

		if (tlvid >= SXE2_TLV_ID_END_OF_LLDPPDU || offset > SXE2_LLDPDU_SIZE)
			break;

		if (len)
			tlv = (struct sxe2_lldp_org_tlv *)((char *)tlv +
							   sizeof(tlv->typelen) + len);
	}

	*miblen = offset;
}

static void sxe2_ieee_ets_common_tlv_parse(u8 *buf, struct sxe2_dcb_ets_cfg *ets_cfg)
{
	u8 offset = 0;
	int i;

	for (i = 0; i < 4; i++) {
		ets_cfg->prio_tbl[i * 2] =
			FIELD_GET(SXE2_IEEE_ETS_PRIO_1_M, buf[offset]);
		ets_cfg->prio_tbl[i * 2 + 1] =
			FIELD_GET(SXE2_IEEE_ETS_PRIO_0_M, buf[offset]);
		offset++;
	}

	sxe2_for_each_tc(i) {
		ets_cfg->tcbw_tbl[i] = buf[offset];
		ets_cfg->tsa_tbl[i] = buf[IEEE_8021QAZ_MAX_TCS + offset++];
	}
}

static void sxe2_ieee_etscfg_tlv_parse(struct sxe2_lldp_org_tlv *tlv,
				       struct sxe2_dcbx_cfg *dcbcfg)
{
	struct sxe2_dcb_ets_cfg *etscfg;
	u8 *buf = tlv->tlvinfo;

	etscfg = &dcbcfg->ets;
	etscfg->willing = FIELD_GET((u32)SXE2_IEEE_ETS_WILLING_M, buf[0]);
	etscfg->cbs = FIELD_GET((u32)SXE2_IEEE_ETS_CBS_M, buf[0]);
	etscfg->maxtcs = FIELD_GET(SXE2_IEEE_ETS_MAXTC_M, buf[0]);

	sxe2_ieee_ets_common_tlv_parse(&buf[1], etscfg);
}

static void sxe2_ieee_etsrec_tlv_parse(struct sxe2_lldp_org_tlv *tlv,
				       struct sxe2_dcbx_cfg *dcbcfg)
{
	u8 *buf = tlv->tlvinfo;

	sxe2_ieee_ets_common_tlv_parse(&buf[1], &dcbcfg->etsrec);
}

static void sxe2_ieee_pfccfg_tlv_parse(struct sxe2_lldp_org_tlv *tlv,
				       struct sxe2_dcbx_cfg *dcbcfg)
{
	u8 *buf = tlv->tlvinfo;

	dcbcfg->pfc.willing = FIELD_GET((u32)SXE2_IEEE_PFC_WILLING_M, buf[0]);
	dcbcfg->pfc.mbc = FIELD_GET((u32)SXE2_IEEE_PFC_MBC_M, buf[0]);
	dcbcfg->pfc.cap = FIELD_GET(SXE2_IEEE_PFC_CAP_M, buf[0]);
	dcbcfg->pfc.enable = buf[1];
}

static void sxe2_ieee_app_tlv_parse(struct sxe2_lldp_org_tlv *tlv,
				    struct sxe2_dcbx_cfg *dcbcfg)
{
	u16 offset = 0;
	u16 typelen;
	u32 i = 0;
	u16 len;
	u8 *buf;

	typelen = ntohs(tlv->typelen);
	len = FIELD_GET(SXE2_LLDP_TLV_LEN_M, typelen);
	buf = tlv->tlvinfo;

	len -= (sizeof(tlv->ouisubtype) + 1);

	offset++;

	while (offset < len) {
		dcbcfg->app[i].prio = FIELD_GET(SXE2_IEEE_APP_PRIO_M, buf[offset]);
		dcbcfg->app[i].selector = FIELD_GET(SXE2_IEEE_APP_SEL_M, buf[offset]);
		dcbcfg->app[i].prot_id = (u16)((buf[offset + 1] << 0x8) | buf[offset + 2]);
		offset += 3;
		i++;
		if (i >= SXE2_DCBX_MAX_APPS)
			break;
	}

	dcbcfg->numapps = i;
}

STATIC void sxe2_ieee_tlv_parse(struct sxe2_lldp_org_tlv *tlv, struct sxe2_dcbx_cfg *dcbcfg)
{
	u32 ouisubtype;
	u8 subtype;

	ouisubtype = ntohl(tlv->ouisubtype);
	subtype = (u8)FIELD_GET(SXE2_LLDP_TLV_SUBTYPE_M, ouisubtype);
	switch (subtype) {
	case SXE2_IEEE_SUBTYPE_ETS_CFG:
		sxe2_ieee_etscfg_tlv_parse(tlv, dcbcfg);
		break;
	case SXE2_IEEE_SUBTYPE_ETS_REC:
		sxe2_ieee_etsrec_tlv_parse(tlv, dcbcfg);
		break;
	case SXE2_IEEE_SUBTYPE_PFC_CFG:
		sxe2_ieee_pfccfg_tlv_parse(tlv, dcbcfg);
		break;
	case SXE2_IEEE_SUBTYPE_APP_PRI:
		sxe2_ieee_app_tlv_parse(tlv, dcbcfg);
		break;
	default:
		break;
	}
}

STATIC void sxe2_cee_pgcfg_tlv_parse(struct sxe2_cee_feat_tlv *tlv, struct sxe2_dcbx_cfg *dcbcfg)
{
	struct sxe2_dcb_ets_cfg *etscfg;
	u8 *buf = tlv->tlvinfo;
	u16 offset = 0;
	int i;

	etscfg = &dcbcfg->ets;

	if (tlv->en_will_err & SXE2_CEE_FEAT_TLV_WILLING_M)
		etscfg->willing = 1;

	etscfg->cbs = 0;
	for (i = 0; i < 4; i++) {
		etscfg->prio_tbl[i * 2] =
			FIELD_GET(SXE2_CEE_PGID_PRIO_1_M, buf[offset]);
		etscfg->prio_tbl[i * 2 + 1] =
			FIELD_GET(SXE2_CEE_PGID_PRIO_0_M, buf[offset]);
		offset++;
	}

	sxe2_for_each_tc(i) {
		etscfg->tcbw_tbl[i] = buf[offset++];

		if (etscfg->prio_tbl[i] == SXE2_CEE_PGID_STRICT)
			dcbcfg->ets.tsa_tbl[i] = SXE2_IEEE_TSA_STRICT;
		else
			dcbcfg->ets.tsa_tbl[i] = SXE2_IEEE_TSA_ETS;
	}

	etscfg->maxtcs = buf[offset];
}

STATIC void sxe2_cee_pfccfg_tlv_parse(struct sxe2_cee_feat_tlv *tlv,
				      struct sxe2_dcbx_cfg *dcbcfg)
{
	u8 *buf = tlv->tlvinfo;

	if (tlv->en_will_err & SXE2_CEE_FEAT_TLV_WILLING_M)
		dcbcfg->pfc.willing = 1;

	dcbcfg->pfc.enable = buf[0];
	dcbcfg->pfc.cap = buf[1];
}

STATIC void sxe2_cee_app_tlv_parse(struct sxe2_cee_feat_tlv *tlv, struct sxe2_dcbx_cfg *dcbcfg)
{
	u16 len, typelen, offset = 0;
	struct sxe2_cee_app_prio *app;
	u8 i;

	typelen = ntohs(tlv->hdr.typelen);
	len = FIELD_GET(SXE2_LLDP_TLV_LEN_M, typelen);

	dcbcfg->numapps = len / sizeof(*app);
	if (!dcbcfg->numapps)
		return;
	if (dcbcfg->numapps > SXE2_DCBX_MAX_APPS)
		dcbcfg->numapps = SXE2_DCBX_MAX_APPS;

	for (i = 0; i < dcbcfg->numapps; i++) {
		u8 up, selector;

		app = (struct sxe2_cee_app_prio *)(tlv->tlvinfo + offset);
		for (up = 0; up < SXE2_MAX_USER_PRIORITY; up++)
			if (app->prio_map & BIT(up))
				break;

		dcbcfg->app[i].prio = up;

		selector = (app->upper_oui_sel & SXE2_CEE_APP_SELECTOR_M);
		switch (selector) {
		case SXE2_CEE_APP_SEL_ETHTYPE:
			dcbcfg->app[i].selector = SXE2_APP_SEL_ETHTYPE;
			break;
		case SXE2_CEE_APP_SEL_TCPIP:
			dcbcfg->app[i].selector = SXE2_APP_SEL_TCPIP;
			break;
		default:
			dcbcfg->app[i].selector = selector;
		}

		dcbcfg->app[i].prot_id = ntohs(app->protocol);
		offset += sizeof(*app);
	}
}

STATIC void sxe2_cee_tlv_parse(struct sxe2_lldp_org_tlv *tlv, struct sxe2_dcbx_cfg *dcbcfg)
{
	struct sxe2_cee_feat_tlv *sub_tlv;
	u8 subtype, feat_tlv_count = 0;
	u16 len, tlvlen, typelen;
	u32 ouisubtype;

	ouisubtype = ntohl(tlv->ouisubtype);
	subtype = (u8)FIELD_GET(SXE2_LLDP_TLV_SUBTYPE_M, ouisubtype);
	if (subtype != SXE2_CEE_DCBX_TYPE)
		return;

	typelen = ntohs(tlv->typelen);
	tlvlen = FIELD_GET(SXE2_LLDP_TLV_LEN_M, typelen);
	len = sizeof(tlv->typelen) + sizeof(ouisubtype) +
		sizeof(struct sxe2_cee_ctrl_tlv);
	if (tlvlen <= len)
		return;

	sub_tlv = (struct sxe2_cee_feat_tlv *)((char *)tlv + len);
	while (feat_tlv_count < SXE2_CEE_MAX_FEAT_TYPE) {
		u16 sublen;

		typelen = ntohs(sub_tlv->hdr.typelen);
		sublen = FIELD_GET(SXE2_LLDP_TLV_LEN_M, typelen);
		subtype = FIELD_GET(SXE2_LLDP_TLV_TYPE_M, typelen);
		switch (subtype) {
		case SXE2_CEE_SUBTYPE_PG_CFG:
			sxe2_cee_pgcfg_tlv_parse(sub_tlv, dcbcfg);
			break;
		case SXE2_CEE_SUBTYPE_PFC_CFG:
			sxe2_cee_pfccfg_tlv_parse(sub_tlv, dcbcfg);
			break;
		case SXE2_CEE_SUBTYPE_APP_PRI:
			sxe2_cee_app_tlv_parse(sub_tlv, dcbcfg);
			break;
		default:
			return;
		}
		feat_tlv_count++;
		sub_tlv = (struct sxe2_cee_feat_tlv *)
			  ((char *)sub_tlv + sizeof(sub_tlv->hdr.typelen) +
			   sublen);
	}
}

static void sxe2_parse_org_tlv(struct sxe2_lldp_org_tlv *tlv, struct sxe2_dcbx_cfg *dcbcfg)
{
	u32 ouisubtype;
	u32 oui;

	ouisubtype = ntohl(tlv->ouisubtype);
	oui = FIELD_GET((u32)SXE2_LLDP_TLV_OUI_M, ouisubtype);

	switch (oui) {
	case SXE2_IEEE_8021QAZ_OUI:
		sxe2_ieee_tlv_parse(tlv, dcbcfg);
		break;
	case SXE2_CEE_DCBX_OUI:
		sxe2_cee_tlv_parse(tlv, dcbcfg);
		break;
	default:
		break;
	}
}

s32 sxe2_lldp_to_dcb_cfg(u8 *lldpmib, struct sxe2_dcbx_cfg *dcbcfg)
{
	struct sxe2_lldp_org_tlv *tlv;
	u16 offset = 0;
	u16 typelen;
	u16 type;
	u16 len;

	if (!lldpmib || !dcbcfg)
		return -EINVAL;

	tlv = (struct sxe2_lldp_org_tlv *)lldpmib;
	while (1) {
		typelen = ntohs(tlv->typelen);
		type = FIELD_GET(SXE2_LLDP_TLV_TYPE_M, typelen);
		len = FIELD_GET(SXE2_LLDP_TLV_LEN_M, typelen);
		offset += sizeof(typelen) + len;

		if (type == SXE2_TLV_TYPE_END || offset > SXE2_LLDPDU_SIZE)
			break;

		switch (type) {
		case SXE2_TLV_TYPE_ORG:
			sxe2_parse_org_tlv(tlv, dcbcfg);
			break;
		default:
			break;
		}

		tlv = (struct sxe2_lldp_org_tlv *)
		      ((char *)tlv + sizeof(tlv->typelen) + len);
	}

	return 0;
}

STATIC s32 sxe2_fw_dcbx_local_mib_get(struct sxe2_adapter *adapter,
				      struct sxe2_fwc_local_mib_get *mib)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_MIB_GET, NULL, 0, mib,
				  (sizeof(struct sxe2_fwc_local_mib_get) + SXE2_LLDPDU_SIZE));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("add vsi failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_fw_dcbx_agent_cfg_get(struct sxe2_adapter *adapter,
			       struct sxe2_dcbx_cfg *dcbcfg)
{
	s32 ret;
	struct sxe2_fwc_local_mib_get *mib;
	int i;

	mib = devm_kzalloc(&adapter->pdev->dev, (sizeof(struct sxe2_fwc_local_mib_get) +
			   SXE2_LLDPDU_SIZE), GFP_KERNEL);
	if (!mib)
		return -ENOMEM;

	ret = sxe2_fw_dcbx_local_mib_get(adapter, mib);
	if (!ret)
		ret = sxe2_lldp_to_dcb_cfg(mib->mib_buffer, dcbcfg);

	devm_kfree(&adapter->pdev->dev, mib);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		dcbcfg->usr_bw_value[i] = 0;
		dcbcfg->hw_bw_value[i] = SXE2_TXSCHED_DFLT_BW;
	}

	return ret;
}
