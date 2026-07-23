// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se_api.h"
#include "dpp_stat_api.h"
#include "dpp_drv_init.h"
#include "dpp_drv_acl.h"
#include "dpp_drv_hash.h"
#include "dpp_drv_eram.h"
#include "dpp_hash.h"
#include "dpp_apt_se.h"
#include "dpp_tbl_pkt_cap.h"
#include "dpp_dtb_table_api.h"
#include "dpp_tbl_api.h"
extern struct dpp_dev_mngr_t *dpp_dev_mgr_get(void);

#define DPP_FLOW_INIT_START ((u32)(0))
#define DPP_FLOW_INIT_SUCCESS ((u32)(1))

u32 dpp_flow_init_status[DPP_PCIE_SLOT_MAX] = { DPP_FLOW_INIT_START };

void dpp_flow_init_status_init(void)
{
	ZXIC_COMM_MEMSET_S(dpp_flow_init_status, sizeof(dpp_flow_init_status), DPP_FLOW_INIT_START,
			   sizeof(dpp_flow_init_status));
}

DPP_STATUS dpp_flow_init_status_set(struct dpp_dev_t *dev, u32 status)
{
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(status, DPP_FLOW_INIT_START, DPP_FLOW_INIT_SUCCESS);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, (DPP_PCIE_SLOT_MAX - 1));

	dpp_flow_init_status[slot] = status;

	return DPP_OK;
}

static DPP_STATUS dpp_drv_se_func_set(struct dpp_apt_se_res_t *p_se_res)
{
	u32 index = 0;
	struct se_apt_eram_convert_t *pAptEramCov = NULL;
	struct se_apt_acl_convert_t *pAptAclCov = NULL;
	struct se_apt_hash_convert_t *pAptHashCov = NULL;
	struct dpp_apt_eram_table_t *pTempEramTbl = NULL;
	struct dpp_apt_acl_table_t *pTempAclTbl = NULL;
	struct dpp_apt_hash_table_t *pTempHashTbl = NULL;

	ZXIC_COMM_CHECK_POINT(p_se_res);

	for (index = 0; index < (p_se_res->eram_num); index++) {
		pTempEramTbl = &(p_se_res->eram_tbl[index]);
		pAptEramCov = se_eram_callback_get(pTempEramTbl->sdtNo);
		if (pAptEramCov) {
			pTempEramTbl->eram_set_func = pAptEramCov->eram_set_func;
			pTempEramTbl->eram_get_func = pAptEramCov->eram_get_func;
		}
	}
	for (index = 0; index < (p_se_res->acl_num); index++) {
		pTempAclTbl = &(p_se_res->acl_tbl[index]);
		pAptAclCov = se_acl_callback_get(pTempAclTbl->sdtNo);
		if (pAptAclCov) {
			pTempAclTbl->acl_set_func = pAptAclCov->acl_set_func;
			pTempAclTbl->acl_get_func = pAptAclCov->acl_get_func;
		}
	}
	for (index = 0; index < (p_se_res->hash_tbl_num); index++) {
		pTempHashTbl = &(p_se_res->hash_tbl[index]);
		pAptHashCov = se_hash_callback_get(pTempHashTbl->sdtNo);
		if (pAptHashCov) {
			pTempHashTbl->hash_set_func = pAptHashCov->hash_set_func;
			pTempHashTbl->hash_get_func = pAptHashCov->hash_get_func;
		}
	}
	return DPP_OK;
}

DPP_STATUS dpp_bar_msg_num_init(struct dpp_dev_t *dev)
{
	u32 rc = 0;
	u32 bar_msg_num = 0xFFFFFFFF;
	u32 dev_id = 0;
	u16 slot = 0;
	struct dpp_dev_cfg_t *p_dev_info = NULL;
	struct dpp_dev_mngr_t *p_dev_mgr = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(dev_id, DPP_DEV_CHANNEL_MAX - 1);
	if ((DEV_PCIE_SLOT(dev) < DPP_PCIE_SLOT_MAX) &&
	    (dpp_flow_init_status[DEV_PCIE_SLOT(dev)] == DPP_FLOW_INIT_SUCCESS))
		return DPP_OK;

	slot = dev->pcie_channel.slot;
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot, 0, DPP_PCIE_SLOT_MAX - 1);

	p_dev_mgr = dpp_dev_mgr_get();
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_dev_mgr);
	if (!p_dev_mgr->is_init) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id,
					  "ErrorCode[ 0x%x]: Device Manager is not init!!!\n",
					  DPP_RC_DEV_MGR_NOT_INIT);
		return DPP_RC_DEV_MGR_NOT_INIT;
	}

	p_dev_info = p_dev_mgr->p_dev_array[dev_id];
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_dev_info);

	rc = dpp_pcie_bar_msg_num_get(dev, &bar_msg_num);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_pcie_bar_msg_num_get");

	p_dev_info->bar_msg_num[slot] = bar_msg_num;
	dev->pcie_channel.bar_msg_num = bar_msg_num;
	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x bar_msg_num: %u.\n", __func__, slot,
			dev->pcie_channel.vport, bar_msg_num);
	return DPP_OK;
}

DPP_STATUS dpp_flow_init(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_pf_info_t pf_info = { 0 };
	struct dpp_apt_se_res_t *p_se_res = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_PCIE_SLOT(dev), 0, DPP_PCIE_SLOT_MAX - 1);
	if ((DEV_PCIE_SLOT(dev) < DPP_PCIE_SLOT_MAX) &&
	    (dpp_flow_init_status[DEV_PCIE_SLOT(dev)] == DPP_FLOW_INIT_SUCCESS))
		return DPP_OK;

	pf_info.slot = dev->pcie_channel.slot;
	pf_info.vport = dev->pcie_channel.vport;

	ZXIC_COMM_TRACE_NOTICE("[%s] slot:%d start.\n", __func__, DEV_PCIE_SLOT(dev));

	rc = dpp_se_res_mem_alloc(dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_se_res_mem_alloc");

	rc = dpp_agent_se_res_get(dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_agent_se_res_get");

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(dev);
	ZXIC_COMM_CHECK_POINT(p_se_res);

	rc = dpp_drv_se_func_set(p_se_res);
	ZXIC_COMM_CHECK_RC(rc, "dpp_drv_se_func_set");

	// hash init
	rc = dpp_apt_hash_global_res_init(dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_global_res_init");

	rc = dpp_apt_hash_func_res_init(dev, p_se_res->hash_func_num, p_se_res->hash_func);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_func_res_init");

	rc = dpp_apt_hash_bulk_res_init(dev, p_se_res->hash_bulk_num, p_se_res->hash_bulk);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_bulk_res_init");

	// tbl-res must be initialized after fun-res and buld-res
	rc = dpp_apt_hash_tbl_res_init(dev, p_se_res->hash_tbl_num, p_se_res->hash_tbl);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_tbl_res_init");

	// eram init
	rc = dpp_apt_eram_res_init(dev, p_se_res->eram_num, p_se_res->eram_tbl);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_eram_res_init");

	// init acl
	rc = dpp_apt_acl_res_init(dev, p_se_res->acl_num, p_se_res->acl_tbl);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_acl_res_init");

#ifdef DPP_FLOW_HW_INIT
	rc = dpp_stat_ppu_eram_baddr_set(dev, p_se_res->stat_cfg.eram_baddr);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_ppu_eram_baddr_set");

	rc = dpp_stat_ppu_eram_depth_set(dev, p_se_res->stat_cfg.eram_depth);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_ppu_eram_depth_set");
#endif

	rc = dpp_pkt_capture_init(&pf_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pkt_capture_init");

	rc = dpp_stat_tbl_get(dev, p_se_res);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_tbl_get");

	rc = dpp_flow_init_status_set(dev, DPP_FLOW_INIT_SUCCESS);
	ZXIC_COMM_CHECK_RC(rc, "dpp_flow_init_status_set");

	ZXIC_COMM_PRINT("[%s] success.\n", __func__);

	return DPP_OK;
}

DPP_STATUS dpp_flow_uninit(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 slot = 0;
	u32 last_flag = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = dev->pcie_channel.slot;
	pf_info.vport = dev->pcie_channel.vport;

	rc = dpp_dev_last_check(dev, &last_flag);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dev_last_check");

	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, (DPP_PCIE_SLOT_MAX - 1));

	ZXIC_COMM_TRACE_NOTICE("[%s] slot[%d] last_flag[%d] start.\n", __func__, slot, last_flag);

	if (last_flag) {
		rc = dpp_hash_soft_uninstall(dev);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_hash_soft_uninstall");

		rc = dpp_apt_hash_global_res_uninit(dev);
		ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_global_res_uninit");

		rc = dpp_apt_acl_soft_res_uninit(dev);
		ZXIC_COMM_CHECK_RC(rc, "dpp_apt_acl_global_res_uninit");

		rc = dpp_se_res_mem_free(dev);
		ZXIC_COMM_CHECK_RC(rc, "dpp_se_res_mem_free");

		dpp_flow_init_status[slot] = DPP_FLOW_INIT_START;
	} else {
		rc = dpp_unicast_all_mac_soft_delete(&pf_info);
		ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_unicast_all_mac_soft_delete");

		rc = dpp_multicast_all_mac_soft_delete(&pf_info);
		ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_multicast_all_mac_soft_delete");
	}

	ZXIC_COMM_PRINT("[%s] slot[%d] success.\n", __func__, slot);

	return DPP_OK;
}

DPP_STATUS dpp_flow_data_all_flush(struct dpp_dev_t *dev, u32 queue_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_apt_se_res_t *p_se_res = NULL;

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(dev);
	ZXIC_COMM_CHECK_POINT(p_se_res);
	rc = dpp_apt_hash_func_flush_hardware_all(dev, p_se_res->hash_func_num, p_se_res->hash_func,
						  queue_id);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_apt_hash_func_flush_hardware");

	return rc;
}
