// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_np_init.h"
#include "dpp_dev.h"
#include "dpp_dtb.h"
#include "dpp_init.h"
#include "dpp_kernel_init.h"
#include "dpp_netlink.h"
#include "dpp_dtb_table_api.h"
#include "dpp_drv_init.h"
#include "dpp_tbl_comm.h"
#include "dpp_apt_se.h"
#include "dpp_cmd_init.h"
#include "dpp_agent_channel.h"
#include "dpp_hash.h"
#include "dpp_sdt_mgr.h"
#include "dpp_tbl_pkt_cap.h"
#include "dpp_drv_sdt.h"
#include "dpp_tbl_api.h"

#include <linux/module.h>

__weak int debug_print;
module_param(debug_print, int, 0644);

u32 dpp_vport_register(struct dpp_pf_info_t *pf_info, struct pci_dev *p_dev)
{
	struct dpp_dev_t dev = { 0 };

	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_dev);
	ZXIC_COMM_CHECK_INDEX_EQUAL_RETURN_OK(IS_PF(pf_info->vport), 0);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x register start.\n", __func__,
			       pf_info->slot, pf_info->vport);

	rc = dpp_dev_pcie_channel_add(pf_info, p_dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_pcie_channel_add");

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_bar_msg_num_init(&dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_bar_msg_num_init");

	rc = dpp_dtb_init(&dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_init");

	rc = dpp_apt_dtb_res_init(&dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_dtb_res_init");

	rc = dpp_vport_mgr_init(pf_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_mgr_init");

	rc = dpp_flow_init(&dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_flow_init");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x register success.\n", __func__, pf_info->slot,
			pf_info->vport);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_register);

u32 dpp_vport_unregister(struct dpp_pf_info_t *pf_info)
{
	struct dpp_dev_t dev = { 0 };
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX_EQUAL_RETURN_OK(IS_PF(pf_info->vport), 0);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x unregister start.\n", __func__,
			       pf_info->slot, pf_info->vport);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pkt_capture_uninit(pf_info);
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_pkt_capture_uninit");

	rc = dpp_dtb_queue_release_ex(&dev);
	if (rc != DPP_OK) {
		rc = dpp_dtb_queue_release_soft(&dev);
		ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_dtb_queue_release_soft");
	}

	rc = dpp_flow_uninit(&dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_flow_uninit");

	rc = dpp_dev_pcie_channel_del(pf_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_pcie_channel_del");

	rc = dpp_vport_mgr_release(pf_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_mgr_release");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x unregister success.\n", __func__,
			pf_info->slot, pf_info->vport);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_unregister);

u32 dpp_vport_reset(struct dpp_pf_info_t *pf_info)
{
	u32 rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] start.\n", __func__);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_release_soft(&dev);
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_dtb_queue_release_soft");

	rc = dpp_rdma_trans_item_soft_delete(pf_info);
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_rdma_trans_item_soft_delete");

	rc = dpp_unicast_all_mac_soft_delete(pf_info);
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_unicast_all_mac_soft_delete");

	rc = dpp_multicast_all_mac_soft_delete(pf_info);
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_multicast_all_mac_soft_delete");

	rc = dpp_dev_pcie_channel_del(pf_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_pcie_channel_del");

	rc = dpp_vport_mgr_release(pf_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_mgr_release");

	ZXIC_COMM_PRINT("[%s] success.\n", __func__);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_reset);

u32 dpp_dev_status_set(struct dpp_pf_info_t *pf_info, u32 dev_status)
{
	u16 slot = 0;
	u16 channel_id = 0;
	u32 dev_id = 0;

	struct dpp_dev_cfg_t *p_dev_info = NULL;
	struct dpp_dev_mngr_t *p_dev_mgr = NULL;

	ZXIC_COMM_CHECK_DEV_POINT(dev_id, pf_info);

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

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

	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_dev_info->pcie_channel[slot][channel_id].device);

	p_dev_info->pcie_channel[slot][channel_id].dev_status = dev_status;

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_dev_status_set);

static int __init dpp_np_init(void)
{
	u32 rc = DPP_OK;

	ZXIC_COMM_TRACE_NOTICE("[%s] start.\n", __func__);

	rc = dpp_init(0);
	ZXIC_COMM_CHECK_RC(rc, "dpp_init");

	rc = dpp_agent_channel_init();
	ZXIC_COMM_CHECK_RC(rc, "dpp_agent_channel_init");

	rc = dpp_netlink_init();
	ZXIC_COMM_CHECK_RC(rc, "dpp_netlink_init");

	rc = dpp_cmd_init();
	ZXIC_COMM_CHECK_RC(rc, "dpp_cmd_init");

	ZXIC_COMM_PRINT("[%s] success.\n", __func__);

	return DPP_OK;
}

u32 dpp_np_online_uninstall(void)
{
	u32 rc = DPP_OK;

	rc = dpp_hash_tbl_clr(0);
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_hash_tbl_clr");

	//rc = dpp_acl_res_destroy(0);
	//ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_acl_res_destroy");

	rc = dpp_dtb_mgr_destory_all();
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_dtb_mgr_destory_all");

	rc = dpp_sdt_mgr_destroy(0);
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_sdt_mgr_destroy");

	rc = dpp_dev_del(0);
	ZXIC_COMM_CHECK_RC_NONE(rc, "dpp_dev_del");

	return DPP_OK;
}

static void __exit dpp_np_exit(void)
{
	ZXIC_COMM_TRACE_NOTICE("[%s] start.\n", __func__);

	dpp_netlink_exit();
	dpp_agent_channel_exit();
	dpp_np_online_uninstall();

	ZXIC_COMM_PRINT("[%s] success.\n", __func__);
}

module_init(dpp_np_init);
module_exit(dpp_np_exit);

MODULE_LICENSE("GPL");
