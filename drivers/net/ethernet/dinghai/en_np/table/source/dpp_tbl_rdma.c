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
#include "dpp_tbl_mac.h"
#include "dpp_tbl_api.h"

void dpp_rdma_trans_item_print(struct zxdh_rdma_trans_t *rdma_trans)
{
	ZXIC_COMM_TRACE_NOTICE("key--mac: %02x:%02x:%02x:%02x:%02x:%02x.\n",
			       rdma_trans->key.mac_addr[0], rdma_trans->key.mac_addr[1],
			       rdma_trans->key.mac_addr[2], rdma_trans->key.mac_addr[3],
			       rdma_trans->key.mac_addr[4], rdma_trans->key.mac_addr[5]);
	ZXIC_COMM_TRACE_NOTICE("key--rsv: 0x%02x\n", rdma_trans->key.rsv);

	ZXIC_COMM_TRACE_NOTICE("entry--rdma_vhca_id: 0x%02x\n", rdma_trans->entry.rdma_vhca_id);
	ZXIC_COMM_TRACE_NOTICE("entry--rsv:          0x%02x\n", rdma_trans->entry.rsv);
	ZXIC_COMM_TRACE_NOTICE("entry--hit_flag:     0x%02x\n", rdma_trans->entry.hit_flag);
}

u32 dpp_add_rdma_trans_item(struct dpp_pf_info_t *pf_info, const void *mac, const u16 vhcaId)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_RDMA_ENTRY_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_rdma_trans_t rdma_trans = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(mac);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	ZXIC_COMM_MEMSET(&rdma_trans, 0, sizeof(struct zxdh_rdma_trans_t));

	ZXIC_COMM_MEMCPY(rdma_trans.key.mac_addr, mac, 6);
	rdma_trans.entry.rdma_vhca_id = vhcaId & 0x3ff;
	rdma_trans.entry.hit_flag = 0x00;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_hash_insert(&dev, queue, sdt_no, &rdma_trans);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_hash_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u rdma_vhca_id: %u mac: %02x:%02x:%02x:%02x:%02x:%02x success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, rdma_trans.entry.rdma_vhca_id,
		rdma_trans.key.mac_addr[0], rdma_trans.key.mac_addr[1], rdma_trans.key.mac_addr[2],
		rdma_trans.key.mac_addr[3], rdma_trans.key.mac_addr[4], rdma_trans.key.mac_addr[5]);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_add_rdma_trans_item);

u32 dpp_del_rdma_trans_item(struct dpp_pf_info_t *pf_info, const void *mac)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_RDMA_ENTRY_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_rdma_trans_t rdma_trans = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(mac);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	ZXIC_COMM_MEMSET(&rdma_trans, 0, sizeof(struct zxdh_rdma_trans_t));

	ZXIC_COMM_MEMCPY(rdma_trans.key.mac_addr, mac, 6);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_hash_delete(&dev, queue, sdt_no, &rdma_trans);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_hash_delete", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u rdma_vhca_id: %u mac: %02x:%02x:%02x:%02x:%02x:%02x success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, rdma_trans.entry.rdma_vhca_id,
		rdma_trans.key.mac_addr[0], rdma_trans.key.mac_addr[1], rdma_trans.key.mac_addr[2],
		rdma_trans.key.mac_addr[3], rdma_trans.key.mac_addr[4], rdma_trans.key.mac_addr[5]);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_del_rdma_trans_item);

u32 dpp_rdma_trans_item_soft_delete(struct dpp_pf_info_t *pf_info)
{
	struct dpp_dev_t dev = { 0 };

	u32 rc = DPP_OK;
	u32 sdt_no = ZXDH_SDT_RDMA_ENTRY_TABLE;
	u32 last_flag = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dev_last_check(&dev, &last_flag);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_last_check");

	if (last_flag) {
		rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
		ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
		ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

		rc = dpp_hash_soft_delete_by_sdt(&dev, sdt_no);
		ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_hash_soft_delete_by_sdt", DEV_PCIE_LOCK(&dev));

		rc = dpp_vport_table_unlock(pf_info, sdt_no);
		ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");
	}

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x success.\n", __func__, pf_info->slot,
			pf_info->vport);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_rdma_trans_item_soft_delete);
