// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_drv_init.h"
#include "dpp_drv_acl.h"
#include "dpp_drv_hash.h"
#include "dpp_drv_eram.h"
#include "dpp_drv_sdt.h"
#include "dpp_dev.h"
#include "dpp_dtb.h"
#include "dpp_hash.h"
#include "dpp_dtb_table.h"
#include "dpp_dtb_table_api.h"
#include "dpp_tbl_comm.h"
#include "dpp_tbl_pkt_cap.h"
#include "dpp_nppu_reg.h"
#include "dpp_reg_info.h"
#include "dpp_reg_api.h"
#include "dpp_sdt.h"
#include "dpp_drv_qos.h"
#include "dpp_dtb_table_api.h"
#include "dpp_kernel_init.h"
#include "dpp_dev.h"
#include "dpp_pktrx_api.h"

static u32 g_speed_limit = DH_PKT_CAP_SPEED_DEFAULT;

static u32 dpp_pkt_capture_key_word_mode_table_insert(struct dpp_pf_info_t *pf_info, u32 tcam_index,
						      u16 key_word_offest, u8 key_word_length);
static u32 dpp_pkt_capture_key_word_mode_table_delete(struct dpp_pf_info_t *pf_info,
						      u32 tcam_index);
static u32 dpp_pkt_capture_tcam_index_to_mask(u32 tcam_index, u8 capture_pkt_flag,
					      struct zxdh_pkt_cap_normal_configure *config,
					      struct zxdh_pkt_cap_mask *rule_mask);
u32 dpp_pkt_capture_init(struct dpp_pf_info_t *pf_info)
{
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_pkt_capture_disable_all(pf_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_disable_all");

	rc = dpp_pkt_capture_table_flush(pf_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_table_flush");

	rc = dpp_pkt_capture_speed_set(pf_info, DH_PKT_CAP_SPEED_DEFAULT);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_table_flush");

	return DPP_OK;
}
u32 dpp_pkt_capture_uninit(struct dpp_pf_info_t *pf_info)
{
	u32 rc = DPP_OK;
	u32 last_flag = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dev_last_check(&dev, &last_flag);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_last_check");

	if (last_flag) {
		rc = dpp_pkt_capture_disable_all(pf_info);
		ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_disable_all");

		rc = dpp_pkt_capture_table_flush(pf_info);
		ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_table_flush");
	}

	return DPP_OK;
}
u32 dpp_pkt_capture_enable(struct dpp_pf_info_t *pf_info, enum zxdh_pkt_cap_point capture_pkt_flag)
{
	u32 rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(capture_pkt_flag, DH_PKT_CAP_POINT_PANEL_RX,
			      DH_PKT_CAP_POINT_RDMA_TX);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_write_1(
		&dev, DH_PKT_CAP_POINT_IN_MF_GLOBAL_OFFSET + capture_pkt_flag,
		DH_PKT_CAP_POINT_IN_MF_GLOBAL_OFFSET + capture_pkt_flag, 1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_write_1");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_enable);
u32 dpp_pkt_capture_disable(struct dpp_pf_info_t *pf_info, enum zxdh_pkt_cap_point capture_pkt_flag)
{
	u32 rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(capture_pkt_flag, DH_PKT_CAP_POINT_PANEL_RX,
			      DH_PKT_CAP_POINT_RDMA_TX);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_write_1(
		&dev, DH_PKT_CAP_POINT_IN_MF_GLOBAL_OFFSET + capture_pkt_flag,
		DH_PKT_CAP_POINT_IN_MF_GLOBAL_OFFSET + capture_pkt_flag, 0);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_write_1");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_disable);
u32 dpp_pkt_capture_disable_all(struct dpp_pf_info_t *pf_info)
{
	u32 rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_write_1(
		&dev, DH_PKT_CAP_POINT_IN_MF_GLOBAL_OFFSET,
		DH_PKT_CAP_POINT_IN_MF_GLOBAL_OFFSET + DH_PKT_CAP_POINT_IN_MF_GLOBAL_LENGTH - 1, 0);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_write_1");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_disable_all);
u32 dpp_pkt_capture_enable_status_get(struct dpp_pf_info_t *pf_info,
				      struct zxdh_pkt_cap_enable_status *enable_status)
{
	u32 rc = DPP_OK;
	u32 pktrxGlbalCfg = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(enable_status);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_get_1(&dev, &pktrxGlbalCfg);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_get_1");

	pktrxGlbalCfg >>= DH_PKT_CAP_POINT_IN_MF_GLOBAL_OFFSET;

	enable_status->panel_rx_enable_status = (pktrxGlbalCfg >> DH_PKT_CAP_POINT_PANEL_RX) & 1U;
	enable_status->panel_tx_enable_status = (pktrxGlbalCfg >> DH_PKT_CAP_POINT_PANEL_TX) & 1U;
	enable_status->vqm_rx_enable_status = (pktrxGlbalCfg >> DH_PKT_CAP_POINT_VQM_RX) & 1U;
	enable_status->vqm_tx_enable_status = (pktrxGlbalCfg >> DH_PKT_CAP_POINT_VQM_TX) & 1U;
	enable_status->rdma_rx_enable_status = (pktrxGlbalCfg >> DH_PKT_CAP_POINT_RDMA_RX) & 1U;
	enable_status->rdma_tx_enable_status = (pktrxGlbalCfg >> DH_PKT_CAP_POINT_RDMA_TX) & 1U;

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_enable_status_get);
u32 dpp_pkt_capture_rule_index_to_tcam_index(u32 rule_index, enum zxdh_pkt_cap_mode rule_mode,
					     enum zxdh_pkt_cap_point capture_pkt_flag,
					     u32 *tcam_index)
{
	ZXIC_COMM_CHECK_POINT(tcam_index);
	ZXIC_COMM_CHECK_INDEX(rule_mode, DH_PKT_CAP_MODE_NORMAL, DH_PKT_CAP_MODE_KEY_WORD);

	if (rule_mode == DH_PKT_CAP_MODE_NORMAL) {
		ZXIC_COMM_CHECK_INDEX(capture_pkt_flag, DH_PKT_CAP_POINT_PANEL_RX,
				      DH_PKT_CAP_POINT_RDMA_TX);
		ZXIC_COMM_CHECK_INDEX(rule_index, 0, DH_PKT_CAP_POINT_NORMAL_RULE_NUM - 1);
		*tcam_index = capture_pkt_flag * DH_PKT_CAP_POINT_NORMAL_RULE_NUM + rule_index;
	} else {
		ZXIC_COMM_CHECK_INDEX(capture_pkt_flag, DH_PKT_CAP_POINT_PANEL_RX,
				      DH_PKT_CAP_POINT_VQM_TX);
		ZXIC_COMM_CHECK_INDEX(rule_index, 0, DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM - 1);
		*tcam_index = DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM +
			      capture_pkt_flag * DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM + rule_index;
	}

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_rule_index_to_tcam_index);
u32 dpp_pkt_capture_tcam_index_to_rule_index(u32 tcam_index, enum zxdh_pkt_cap_mode *rule_mode,
					     u32 *rule_index)
{
	ZXIC_COMM_CHECK_POINT(rule_index);
	ZXIC_COMM_CHECK_POINT(rule_mode);
	ZXIC_COMM_CHECK_INDEX(tcam_index, 0, DH_PKT_CAP_TCAM_ITEM_NUM - 1);

	if (tcam_index < DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) {
		*rule_mode = DH_PKT_CAP_MODE_NORMAL;
		*rule_index = tcam_index % DH_PKT_CAP_POINT_NORMAL_RULE_NUM;
	} else {
		*rule_mode = DH_PKT_CAP_MODE_KEY_WORD;
		*rule_index = tcam_index % DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM;
	}

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_tcam_index_to_rule_index);

static u32 dpp_pkt_capture_tcam_index_to_mask(u32 tcam_index, u8 capture_pkt_flag,
					      struct zxdh_pkt_cap_normal_configure *config,
					      struct zxdh_pkt_cap_mask *rule_mask)
{
	ZXIC_COMM_CHECK_POINT(rule_mask);
	ZXIC_COMM_CHECK_INDEX(tcam_index, 0, DH_PKT_CAP_TCAM_ITEM_NUM - 1);

	ZXIC_COMM_MEMSET(rule_mask, 0xFF, sizeof(struct zxdh_pkt_cap_mask));

	rule_mask->capture_pkt_flag_mask = 0;

	if (tcam_index < DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) {
		if (config->sourceid) {
			if (capture_pkt_flag <= DH_PKT_CAP_POINT_PANEL_TX) {
				rule_mask->panel_id_mask = 0;
			} else if (capture_pkt_flag <= DH_PKT_CAP_POINT_VQM_TX) {
				rule_mask->vqm_vfid_mask = 0;
			} else if (capture_pkt_flag <= DH_PKT_CAP_POINT_RDMA_TX) {
				rule_mask->vhca_id_mask = 0;
			} else {
				ZXIC_COMM_TRACE_ERROR("capture_pkt_flag = %d is error.\n",
						      capture_pkt_flag);
				return DPP_ERR;
			}
		}

		if (config->protocol)
			rule_mask->protocol_mask = 0;

		if (config->ethtype)
			rule_mask->ethtype_mask = 0;

		if (config->dmac)
			ZXIC_COMM_MEMSET(rule_mask->dmac_mask, 0, 6);

		if (config->smac)
			ZXIC_COMM_MEMSET(rule_mask->smac_mask, 0, 6);

		if (config->sip)
			ZXIC_COMM_MEMSET(rule_mask->sip_mask, 0, 16);

		if (config->dip)
			ZXIC_COMM_MEMSET(rule_mask->dip_mask, 0, 16);

		if (config->sport)
			rule_mask->sport_mask = 0;

		if (config->dport)
			rule_mask->dport_mask = 0;

		if (config->qp)
			rule_mask->qp_mask = 0;
	} else {
		rule_mask->capture_pkt_flag_mask = 0;
		rule_mask->key_word_len_mask = 0;
		rule_mask->key_word_off_mask = 0;
		ZXIC_COMM_MEMSET(rule_mask->key_word_mask, 0, 15);
	}

	return DPP_OK;
}

static u32 dpp_pkt_capture_key_word_mode_table_insert(struct dpp_pf_info_t *pf_info, u32 tcam_index,
						      u16 key_word_offest, u8 key_word_length)
{
	struct dpp_dev_t dev = { 0 };
	struct zxdh_pkt_cap_kw_mode_t kw_mode = { 0 };

	u32 queue = 0;
	u32 eram_index = 0;
	u32 rule_index = 0;

	u32 sdt_no = ZXDH_SDT_CAP_KEYWORD_ATTR_TABLE;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_INDEX(tcam_index, DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM,
			      DH_PKT_CAP_TCAM_ITEM_NUM - 1);
	ZXIC_COMM_CHECK_INDEX(key_word_offest, 0, 8191);
	ZXIC_COMM_CHECK_INDEX(key_word_length, 1, 15);

	eram_index = (tcam_index - DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) /
		     DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM;
	rule_index = (tcam_index - DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) %
		     DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM;
	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, eram_index, &kw_mode);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	kw_mode.hit_flag = 1;

	if (rule_index == 0) {
		kw_mode.rule1_key_word_len = key_word_length;
		kw_mode.rule1_key_word_off = key_word_offest;
	} else {
		kw_mode.rule2_key_word_len = key_word_length;
		kw_mode.rule2_key_word_off = key_word_offest;
	}

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, eram_index, &kw_mode);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u eram_index: %u rule_index: %u kw_off: %u kw_len: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, eram_index, rule_index,
		key_word_offest, key_word_length);

	return DPP_OK;
}

static u32 dpp_pkt_capture_key_word_mode_table_delete(struct dpp_pf_info_t *pf_info, u32 tcam_index)
{
	struct dpp_dev_t dev = { 0 };
	struct zxdh_pkt_cap_kw_mode_t kw_mode = { 0 };

	u32 queue = 0;
	u32 eram_index = 0;
	u32 rule_index = 0;

	u32 sdt_no = ZXDH_SDT_CAP_KEYWORD_ATTR_TABLE;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_INDEX(tcam_index, DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM,
			      DH_PKT_CAP_TCAM_ITEM_NUM - 1);

	eram_index = (tcam_index - DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) /
		     DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM;
	rule_index = (tcam_index - DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) %
		     DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM;
	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, eram_index, &kw_mode);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	if (rule_index == 0) {
		kw_mode.rule1_key_word_len = 0;
		kw_mode.rule1_key_word_off = 0;
	} else {
		kw_mode.rule2_key_word_len = 0;
		kw_mode.rule2_key_word_off = 0;
	}

	if (kw_mode.rule1_key_word_len == 0 && kw_mode.rule2_key_word_len == 0)
		kw_mode.hit_flag = 0;

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, eram_index, &kw_mode);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u eram_index: %u rule_index: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, eram_index, rule_index);

	return DPP_OK;
}
u32 dpp_pkt_capture_item_insert(struct dpp_pf_info_t *pf_info, struct zxdh_pkt_cap_rule *rule)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;

	u32 sdt_no = ZXDH_SDT_CAPTURE_PKT_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_pkt_cap_t pkt_cap_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(rule);
	ZXIC_COMM_CHECK_INDEX(rule->tcam_index, 0, DH_PKT_CAP_TCAM_ITEM_NUM - 1);
	ZXIC_COMM_CHECK_INDEX(rule->pkt_cap_key.capture_pkt_flag, DH_PKT_CAP_POINT_PANEL_RX,
			      DH_PKT_CAP_POINT_RDMA_TX);

	ZXIC_COMM_MEMSET(&pkt_cap_entry.key, 0, sizeof(struct zxdh_pkt_cap_key));
	ZXIC_COMM_MEMSET(&pkt_cap_entry.mask, 0xFF, sizeof(struct zxdh_pkt_cap_mask));
	ZXIC_COMM_MEMSET(&pkt_cap_entry.entry, 0, sizeof(struct zxdh_pkt_cap_entry));

	rc = dpp_pkt_capture_tcam_index_to_mask(rule->tcam_index,
						rule->pkt_cap_key.capture_pkt_flag,
						&rule->rule_config, &pkt_cap_entry.mask);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_tcam_index_to_mask");

	if (rule->tcam_index >= DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) {
		ZXIC_COMM_CHECK_INDEX(rule->pkt_cap_key.capture_pkt_flag, DH_PKT_CAP_POINT_PANEL_RX,
				      DH_PKT_CAP_POINT_VQM_TX);
		ZXIC_COMM_CHECK_INDEX(rule->pkt_cap_key.key_word_off, 0, 8191);
		ZXIC_COMM_CHECK_INDEX(rule->pkt_cap_key.key_word_len, 1, 15);

		rc = dpp_pkt_capture_key_word_mode_table_insert(pf_info, rule->tcam_index,
								rule->pkt_cap_key.key_word_off,
								rule->pkt_cap_key.key_word_len);
		ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_key_word_mode_table_insert");
	}

	pkt_cap_entry.index = rule->tcam_index;

	rc = ZXIC_COMM_MEMCPY(&(pkt_cap_entry.key), &(rule->pkt_cap_key),
			      sizeof(struct zxdh_pkt_cap_key));
	ZXIC_COMM_CHECK_RC(rc, "ZXIC_COMM_MEMCPY");

	pkt_cap_entry.entry.hit_flag = 0;
	pkt_cap_entry.entry.value_flag = 1;
	pkt_cap_entry.entry.index = rule->tcam_index;
	pkt_cap_entry.entry.vqm_vfid = rule->dst_vqm_vfid;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_apt_dtb_acl_entry_insert(&dev, queue, sdt_no, &pkt_cap_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_dtb_acl_entry_insert");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, rule->tcam_index);

	ZXIC_COMM_PRINT("[%s] rule_config:\n", __func__);
	ZXIC_COMM_PRINT("\t sourceid : %u\n", rule->rule_config.sourceid);
	ZXIC_COMM_PRINT("\t dmac     : %u\n", rule->rule_config.dmac);
	ZXIC_COMM_PRINT("\t smac     : %u\n", rule->rule_config.smac);
	ZXIC_COMM_PRINT("\t ethtype  : %u\n", rule->rule_config.ethtype);
	ZXIC_COMM_PRINT("\t sip      : %u\n", rule->rule_config.sip);
	ZXIC_COMM_PRINT("\t dip      : %u\n", rule->rule_config.dip);
	ZXIC_COMM_PRINT("\t sport    : %u\n", rule->rule_config.sport);
	ZXIC_COMM_PRINT("\t dport    : %u\n", rule->rule_config.dport);
	ZXIC_COMM_PRINT("\t protocol : %u\n", rule->rule_config.protocol);
	ZXIC_COMM_PRINT("\t qp       : %u\n", rule->rule_config.qp);

	ZXIC_COMM_PRINT("[%s] rule_key:\n", __func__);
	dpp_data_print((u8 *)(&(pkt_cap_entry.key)), sizeof(struct zxdh_pkt_cap_key));

	ZXIC_COMM_PRINT("[%s] rule_mask:\n", __func__);
	dpp_data_print((u8 *)(&(pkt_cap_entry.mask)), sizeof(struct zxdh_pkt_cap_mask));

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_item_insert);
u32 dpp_pkt_capture_item_delete(struct dpp_pf_info_t *pf_info, u32 tcam_index)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;

	u32 sdt_no = ZXDH_SDT_CAPTURE_PKT_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_pkt_cap_t pkt_cap_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(tcam_index, 0, DH_PKT_CAP_TCAM_ITEM_NUM - 1);

	ZXIC_COMM_MEMSET(&pkt_cap_entry.key, 0xFF, sizeof(struct zxdh_pkt_cap_key));
	ZXIC_COMM_MEMSET(&pkt_cap_entry.mask, 0, sizeof(struct zxdh_pkt_cap_mask));
	ZXIC_COMM_MEMSET(&pkt_cap_entry.entry, 0, sizeof(struct zxdh_pkt_cap_entry));

	if (tcam_index >= DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) {
		rc = dpp_pkt_capture_key_word_mode_table_delete(pf_info, tcam_index);
		ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_key_word_mode_table_delete");
	}

	pkt_cap_entry.index = tcam_index;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_apt_dtb_acl_entry_insert(&dev, queue, sdt_no, &pkt_cap_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_dtb_acl_entry_insert");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, tcam_index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_item_delete);
u32 dpp_pkt_capture_table_dump(struct dpp_pf_info_t *pf_info, struct zxdh_pkt_cap_rule *rule_array,
			       u32 *entry_num)
{
	struct dpp_dev_t dev = { 0 };
	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_CAPTURE_PKT_TABLE;
	u32 rc = DPP_OK;
	u32 i = 0;
	u32 rule_array_index = 0;
	u32 dump_num = 0;
	u32 data_byte_size = 0;
	u32 table_depth = 0;
	struct zxdh_pkt_cap_t pkt_cap_entry = { 0 };
	struct dpp_acl_entry_ex_t acl_entry = { 0 };
	struct dpp_dtb_acl_entry_info_t *p_entry_arr = NULL;
	struct dpp_sdt_tbl_etcam_t sdt_etcam_info = { 0 };
	u8 *data_buff = NULL;
	u8 *mask_buff = NULL;
	u32 *eram_buff = NULL;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(entry_num);
	ZXIC_COMM_CHECK_POINT(rule_array);
	ZXIC_COMM_CHECK_INDEX_LOWER(*entry_num, 1);

	ZXIC_COMM_MEMSET(rule_array, 0, *entry_num * sizeof(struct zxdh_pkt_cap_rule));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_soft_sdt_tbl_get(&dev, sdt_no, &sdt_etcam_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_soft_sdt_tbl_get");

	table_depth = sdt_etcam_info.etcam_table_depth;
	ZXIC_COMM_CHECK_INDEX_LOWER(table_depth, 1);

	data_byte_size = DPP_ETCAM_ENTRY_SIZE_GET(sdt_etcam_info.etcam_key_mode);

	p_entry_arr = (struct dpp_dtb_acl_entry_info_t *)ZXIC_COMM_MALLOC(
		table_depth * sizeof(struct dpp_dtb_acl_entry_info_t));
	ZXIC_COMM_CHECK_POINT(p_entry_arr);

	for (i = 0; i < table_depth; i++) {
		data_buff = (u8 *)ZXIC_COMM_MALLOC(data_byte_size * sizeof(u8));
		if (!data_buff) {
			ZXIC_COMM_TRACE_ERROR("ZXIC_COMM_MALLOC data_buff filed.\n");
			goto err_to_free;
		}
		ZXIC_COMM_MEMSET(data_buff, 0, data_byte_size * sizeof(u8));
		p_entry_arr[i].key_data = data_buff;

		mask_buff = (u8 *)ZXIC_COMM_MALLOC(data_byte_size * sizeof(u8));
		if (!mask_buff) {
			ZXIC_COMM_TRACE_ERROR("ZXIC_COMM_MALLOC mask_buff filed.\n");
			goto err_to_free;
		}
		ZXIC_COMM_MEMSET(mask_buff, 0, data_byte_size * sizeof(u8));
		p_entry_arr[i].key_mask = mask_buff;

		eram_buff = (u32 *)ZXIC_COMM_MALLOC(2 * sizeof(u32));
		if (!eram_buff) {
			ZXIC_COMM_TRACE_ERROR("ZXIC_COMM_MALLOC eram_buff filed.\n");
			goto err_to_free;
		}
		ZXIC_COMM_MEMSET(eram_buff, 0, 2 * sizeof(u32));
		p_entry_arr[i].p_as_rslt = (u8 *)eram_buff;

		mask_buff = NULL;
		data_buff = NULL;
		eram_buff = NULL;
	}

	rc = dpp_dtb_acl_dump(&dev, queue, sdt_no, (u8 *)p_entry_arr, &dump_num);
	if (rc != DPP_OK) {
		ZXIC_COMM_TRACE_ERROR("dpp_dtb_acl_dump filed, rc = %d\n", rc);
		goto err_to_free;
	}

	if (dump_num == table_depth) {
		for (i = 0; i < dump_num; i++) {
			acl_entry.key_data = p_entry_arr[i].key_data;
			acl_entry.key_mask = p_entry_arr[i].key_mask;
			acl_entry.p_as_rslt = p_entry_arr[i].p_as_rslt;
			acl_entry.pri = p_entry_arr[i].handle;

			rc = dpp_apt_get_pkt_cap_data(&pkt_cap_entry, &acl_entry);
			if (rc != 0) {
				ZXIC_COMM_TRACE_ERROR("dpp_apt_get_pkt_cap_data filed, rc = %d\n",
						      rc);
				goto err_to_free;
			}

			if (pkt_cap_entry.entry.value_flag) {
				rule_array[rule_array_index].tcam_index = pkt_cap_entry.index;
				rule_array[rule_array_index].dst_vqm_vfid =
					pkt_cap_entry.entry.vqm_vfid;
				ZXIC_COMM_MEMCPY(&(rule_array[rule_array_index].pkt_cap_key),
						 &(pkt_cap_entry.key),
						 sizeof(struct zxdh_pkt_cap_key));

				if (pkt_cap_entry.index <
				    DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM) {
					if (pkt_cap_entry.mask.panel_id_mask != 0xF ||
					    pkt_cap_entry.mask.vqm_vfid_mask != 0xFFFF ||
					    pkt_cap_entry.mask.vhca_id_mask != 0xFFFF) {
						rule_array[rule_array_index].rule_config.sourceid =
							1;
					}

					if (pkt_cap_entry.mask.protocol_mask != 0xFF) {
						rule_array[rule_array_index].rule_config.protocol =
							1;
					}

					if (pkt_cap_entry.mask.ethtype_mask != 0xFFFF) {
						rule_array[rule_array_index].rule_config.ethtype =
							1;
					}

					if (pkt_cap_entry.mask.dmac_mask[0] != 0xFF)
						rule_array[rule_array_index].rule_config.dmac = 1;

					if (pkt_cap_entry.mask.smac_mask[0] != 0xFF)
						rule_array[rule_array_index].rule_config.smac = 1;

					if (pkt_cap_entry.mask.sip_mask[0] != 0xFF)
						rule_array[rule_array_index].rule_config.sip = 1;

					if (pkt_cap_entry.mask.dip_mask[0] != 0xFF)
						rule_array[rule_array_index].rule_config.dip = 1;

					if (pkt_cap_entry.mask.sport_mask != 0xFFFF)
						rule_array[rule_array_index].rule_config.sport = 1;

					if (pkt_cap_entry.mask.dport_mask != 0xFFFF)
						rule_array[rule_array_index].rule_config.dport = 1;

					if (pkt_cap_entry.mask.qp_mask != 0xFFFFFF)
						rule_array[rule_array_index].rule_config.qp = 1;
				}

				ZXIC_COMM_PRINT("rule [%u] tcam_index   = %u\n", rule_array_index,
						rule_array[rule_array_index].tcam_index);
				ZXIC_COMM_PRINT("rule [%u] dst_vqm_vfid = %u\n", rule_array_index,
						rule_array[rule_array_index].dst_vqm_vfid);
				ZXIC_COMM_PRINT("rule [%u] rule_config.sourceid  = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.sourceid);
				ZXIC_COMM_PRINT("rule [%u] rule_config.dmac      = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.dmac);
				ZXIC_COMM_PRINT("rule [%u] rule_config.smac      = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.smac);
				ZXIC_COMM_PRINT("rule [%u] rule_config.ethtype   = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.ethtype);
				ZXIC_COMM_PRINT("rule [%u] rule_config.sip       = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.sip);
				ZXIC_COMM_PRINT("rule [%u] rule_config.dip       = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.dip);
				ZXIC_COMM_PRINT("rule [%u] rule_config.protocol  = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.protocol);
				ZXIC_COMM_PRINT("rule [%u] rule_config.sport     = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.sport);
				ZXIC_COMM_PRINT("rule [%u] rule_config.dport     = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.dport);
				ZXIC_COMM_PRINT("rule [%u] rule_config.qp        = %u\n",
						rule_array_index,
						rule_array[rule_array_index].rule_config.qp);
				ZXIC_COMM_PRINT("rule [%u] l2_info:\n", rule_array_index);
				ZXIC_COMM_PRINT("\t dmac:\n");
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.dmac[0],
						rule_array[rule_array_index].pkt_cap_key.dmac[1],
						rule_array[rule_array_index].pkt_cap_key.dmac[2],
						rule_array[rule_array_index].pkt_cap_key.dmac[3],
						rule_array[rule_array_index].pkt_cap_key.dmac[4],
						rule_array[rule_array_index].pkt_cap_key.dmac[5]);
				ZXIC_COMM_PRINT("\t smac:\n");
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.smac[0],
						rule_array[rule_array_index].pkt_cap_key.smac[1],
						rule_array[rule_array_index].pkt_cap_key.smac[2],
						rule_array[rule_array_index].pkt_cap_key.smac[3],
						rule_array[rule_array_index].pkt_cap_key.smac[4],
						rule_array[rule_array_index].pkt_cap_key.smac[5]);
				ZXIC_COMM_PRINT("\t ethtype:\n");
				ZXIC_COMM_PRINT("\t\t 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.ethtype);
				ZXIC_COMM_PRINT("rule [%u] l3_info:\n", rule_array_index);
				ZXIC_COMM_PRINT("\t sip:\n");
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.sip[0],
						rule_array[rule_array_index].pkt_cap_key.sip[1],
						rule_array[rule_array_index].pkt_cap_key.sip[2],
						rule_array[rule_array_index].pkt_cap_key.sip[3]);
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.sip[4],
						rule_array[rule_array_index].pkt_cap_key.sip[5],
						rule_array[rule_array_index].pkt_cap_key.sip[6],
						rule_array[rule_array_index].pkt_cap_key.sip[7]);
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.sip[8],
						rule_array[rule_array_index].pkt_cap_key.sip[9],
						rule_array[rule_array_index].pkt_cap_key.sip[10],
						rule_array[rule_array_index].pkt_cap_key.sip[11]);
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.sip[12],
						rule_array[rule_array_index].pkt_cap_key.sip[13],
						rule_array[rule_array_index].pkt_cap_key.sip[14],
						rule_array[rule_array_index].pkt_cap_key.sip[15]);
				ZXIC_COMM_PRINT("\t dip:\n");
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.dip[0],
						rule_array[rule_array_index].pkt_cap_key.dip[1],
						rule_array[rule_array_index].pkt_cap_key.dip[2],
						rule_array[rule_array_index].pkt_cap_key.dip[3]);
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.dip[4],
						rule_array[rule_array_index].pkt_cap_key.dip[5],
						rule_array[rule_array_index].pkt_cap_key.dip[6],
						rule_array[rule_array_index].pkt_cap_key.dip[7]);
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.dip[8],
						rule_array[rule_array_index].pkt_cap_key.dip[9],
						rule_array[rule_array_index].pkt_cap_key.dip[10],
						rule_array[rule_array_index].pkt_cap_key.dip[11]);
				ZXIC_COMM_PRINT("\t\t 0x%x 0x%x 0x%x 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.dip[12],
						rule_array[rule_array_index].pkt_cap_key.dip[13],
						rule_array[rule_array_index].pkt_cap_key.dip[14],
						rule_array[rule_array_index].pkt_cap_key.dip[15]);
				ZXIC_COMM_PRINT("\t protocol:\n");
				ZXIC_COMM_PRINT("\t\t 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.protocol);
				ZXIC_COMM_PRINT("rule [%u] l4_info:\n", rule_array_index);
				ZXIC_COMM_PRINT("\t dport: 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.dport);
				ZXIC_COMM_PRINT("\t sport: 0x%x\n",
						rule_array[rule_array_index].pkt_cap_key.sport);
				ZXIC_COMM_PRINT("rule [%u] qp: 0x%x\n", rule_array_index,
						rule_array[rule_array_index].pkt_cap_key.qp);
				ZXIC_COMM_PRINT(
					"rule [%u] pkt_cap_flag: %u\n", rule_array_index,
					rule_array[rule_array_index].pkt_cap_key.capture_pkt_flag);
				ZXIC_COMM_PRINT("rule [%u] panel_id: 0x%x\n", rule_array_index,
						rule_array[rule_array_index].pkt_cap_key.panel_id);
				ZXIC_COMM_PRINT("rule [%u] vqm_vfid: 0x%x\n", rule_array_index,
						rule_array[rule_array_index].pkt_cap_key.vqm_vfid);
				ZXIC_COMM_PRINT("rule [%u] vhca_id: 0x%x\n", rule_array_index,
						rule_array[rule_array_index].pkt_cap_key.vhca_id);
				ZXIC_COMM_PRINT(
					"rule [%u] kw_len: 0x%x\n", rule_array_index,
					rule_array[rule_array_index].pkt_cap_key.key_word_len);
				ZXIC_COMM_PRINT(
					"rule [%u] kw_off: 0x%x\n", rule_array_index,
					rule_array[rule_array_index].pkt_cap_key.key_word_off);
				ZXIC_COMM_PRINT("rule [%u] kw:\n", rule_array_index);
				ZXIC_COMM_PRINT(
					"\t\t 0x%x 0x%x 0x%x 0x%x\n",
					rule_array[rule_array_index].pkt_cap_key.key_word[0],
					rule_array[rule_array_index].pkt_cap_key.key_word[1],
					rule_array[rule_array_index].pkt_cap_key.key_word[2],
					rule_array[rule_array_index].pkt_cap_key.key_word[3]);
				ZXIC_COMM_PRINT(
					"\t\t 0x%x 0x%x 0x%x 0x%x\n",
					rule_array[rule_array_index].pkt_cap_key.key_word[4],
					rule_array[rule_array_index].pkt_cap_key.key_word[5],
					rule_array[rule_array_index].pkt_cap_key.key_word[6],
					rule_array[rule_array_index].pkt_cap_key.key_word[7]);
				ZXIC_COMM_PRINT(
					"\t\t 0x%x 0x%x 0x%x 0x%x\n",
					rule_array[rule_array_index].pkt_cap_key.key_word[8],
					rule_array[rule_array_index].pkt_cap_key.key_word[9],
					rule_array[rule_array_index].pkt_cap_key.key_word[10],
					rule_array[rule_array_index].pkt_cap_key.key_word[11]);
				ZXIC_COMM_PRINT(
					"\t\t 0x%x 0x%x 0x%x\n",
					rule_array[rule_array_index].pkt_cap_key.key_word[12],
					rule_array[rule_array_index].pkt_cap_key.key_word[13],
					rule_array[rule_array_index].pkt_cap_key.key_word[14]);

				rule_array_index++;
				*entry_num = (*entry_num) - 1;

				if (*entry_num == 0)
					break;
			}
		}

		*entry_num = rule_array_index;
	} else {
		ZXIC_COMM_TRACE_ERROR("dpp_dtb_acl_dump filed, dump_num = %d\n", dump_num);
		goto err_to_free;
	}

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u pkt cap tcam table dump succeeded.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no);

	for (i = 0; i < table_depth; i++) {
		if (p_entry_arr[i].key_data)
			ZXIC_COMM_FREE(p_entry_arr[i].key_data);

		if (p_entry_arr[i].key_mask)
			ZXIC_COMM_FREE(p_entry_arr[i].key_mask);

		if (sdt_etcam_info.as_en) {
			if (p_entry_arr[i].p_as_rslt)
				ZXIC_COMM_FREE(p_entry_arr[i].p_as_rslt);
		}
	}

	ZXIC_COMM_FREE(p_entry_arr);

	return DPP_OK;

err_to_free:
	for (i = 0; i < table_depth; i++) {
		if (p_entry_arr[i].key_data)
			ZXIC_COMM_FREE(p_entry_arr[i].key_data);

		if (p_entry_arr[i].key_mask)
			ZXIC_COMM_FREE(p_entry_arr[i].key_mask);

		if (sdt_etcam_info.as_en) {
			if (p_entry_arr[i].p_as_rslt)
				ZXIC_COMM_FREE(p_entry_arr[i].p_as_rslt);
		}
	}

	ZXIC_COMM_FREE(p_entry_arr);
	return DPP_ERR;
}
EXPORT_SYMBOL(dpp_pkt_capture_table_dump);
u32 dpp_pkt_capture_table_flush(struct dpp_pf_info_t *pf_info)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;

	u32 sdt_no = ZXDH_SDT_CAPTURE_PKT_TABLE;
	u32 rc = DPP_OK;
	u32 tcam_index = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_dtb_etcam_table_flush(&dev, queue, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_etcam_table_flush");

	for (tcam_index = DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM;
	     tcam_index < DH_PKT_CAP_TCAM_ITEM_NUM; tcam_index++) {
		rc = dpp_pkt_capture_key_word_mode_table_delete(pf_info, tcam_index);
		ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_key_word_mode_table_delete");
	}

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u.\n", __func__, pf_info->slot,
			pf_info->vport, sdt_no);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_table_flush);
u32 dpp_pkt_capture_speed_set(struct dpp_pf_info_t *pf_info, u32 speed_kbps)
{
	u32 rc = DPP_OK;
	struct dpp_stat_car_profile_cfg_t cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(speed_kbps, DH_PKT_CAP_SPEED_MIN, DH_PKT_CAP_SPEED_MAX);

	ZXIC_COMM_MEMSET(&cfg, 0, sizeof(struct dpp_stat_car_profile_cfg_t));

	cfg.profile_id = 511;
	cfg.cir = speed_kbps;
	cfg.cbs = 1280000;

	rc = dpp_car_queue_cfg_set(pf_info, 0, 30000, 0, 1, 511);
	ZXIC_COMM_CHECK_RC(rc, "dpp_car_queue_cfg_set");

	rc = dpp_car_profile_cfg_set(pf_info, 0, 0, 511, &cfg);
	ZXIC_COMM_CHECK_RC(rc, "dpp_car_profile_cfg_set");

	g_speed_limit = speed_kbps;

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x speed_kbps: %u.\n", __func__, pf_info->slot,
			pf_info->vport, speed_kbps);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_speed_set);
u32 dpp_pkt_capture_speed_get(struct dpp_pf_info_t *pf_info, u32 *speed_kbps)
{
	// u32 rc     = DPP_OK;
	// DPP_STAT_CAR_PROFILE_CFG_T cfg = {0};

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(speed_kbps);

	// rc = dpp_car_profile_cfg_get(pf_info, 0, 0, 511, &cfg);
	// ZXIC_COMM_CHECK_RC(rc, "dpp_car_profile_cfg_set");

	*speed_kbps = g_speed_limit;

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x speed_kbps: %u.\n", __func__, pf_info->slot,
			pf_info->vport, *speed_kbps);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pkt_capture_speed_get);
