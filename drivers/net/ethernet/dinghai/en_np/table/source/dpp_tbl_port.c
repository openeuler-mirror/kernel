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
#include "dpp_tbl_api.h"
#include "dpp_tbl_comm.h"
#include "dpp_tbl_port.h"
#include "dpp_tbl_diag.h"

u32 dpp_vport_create(struct dpp_pf_info_t *pf_info)
{
	u32 rc = DPP_OK;

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	rc = dpp_vport_create_by_vqm_vfid(pf_info, VQM_VFID(pf_info->vport));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_create_by_vqm_vfid");

	rc = dpp_vport_attr_set(pf_info, SRIOV_VPORT_IS_VF, !IS_PF(pf_info->vport));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	rc = dpp_vport_attr_set(pf_info, SRIOV_VPORT_PF_VQM_VFID,
				OWNER_PF_VQM_VFID(pf_info->vport));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x success.\n", __func__, pf_info->slot,
			pf_info->vport);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_create);

u32 dpp_vport_create_by_vqm_vfid(struct dpp_pf_info_t *pf_info, u32 vqm_vfid)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_SRIOV_VPORT_ATTR_TABLE;
	u32 index = vqm_vfid;
	u32 rc = DPP_OK;

	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u start.\n",
			       __func__, pf_info->slot, pf_info->vport, sdt_no, index);

	ZXIC_COMM_MEMSET(&port_attr_entry, 0, sizeof(struct zxdh_sriov_vport_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	port_attr_entry.hit_flag = 1;

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, index, &port_attr_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_create_by_vqm_vfid);

u32 dpp_vport_delete(struct dpp_pf_info_t *pf_info)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_SRIOV_VPORT_ATTR_TABLE;
	u32 index = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	index = VQM_VFID(pf_info->vport);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u start.\n",
			       __func__, pf_info->slot, pf_info->vport, sdt_no, index);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_clear(&dev, queue, sdt_no, index);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_clear", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_delete);

u32 dpp_vport_attr_set(struct dpp_pf_info_t *pf_info, u32 attr, u32 value)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_SRIOV_VPORT_ATTR_TABLE;
	u32 index = 0;
	u32 rc = DPP_OK;

	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(attr, 0,
			      (u32)((sizeof(struct zxdh_sriov_vport_t) / sizeof(u32)) - 1));

	index = VQM_VFID(pf_info->vport);

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u attr: %s(%u) value: %u start.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, index,
		dpp_vport_table_attr_name_get(attr), attr, value);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, index, &port_attr_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	port_attr_entry.hit_flag = 1;
	*((((u32 *)(&port_attr_entry)) + attr)) = value;

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, index, &port_attr_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	if (attr == SRIOV_VPORT_HASH_SEARCH_INDEX) {
		rc = dpp_soft_hash_index_set(&dev, value);
		ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_soft_hash_index_set", DEV_PCIE_LOCK(&dev));
	}

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u attr: %s(%u) value: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, index,
		dpp_vport_table_attr_name_get(attr), attr, value);
	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_attr_set);

u32 dpp_vport_attr_get(struct dpp_pf_info_t *pf_info, struct zxdh_sriov_vport_t *port_attr_entry)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_SRIOV_VPORT_ATTR_TABLE;
	u32 index = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(port_attr_entry);

	index = VQM_VFID(pf_info->vport);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x index: %u start.\n", __func__,
			       pf_info->slot, pf_info->vport, index);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, index, port_attr_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_INDEX_NOT_EQUAL_UNLOCK(port_attr_entry->hit_flag, 1, DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x index: %u success.\n", __func__,
			       pf_info->slot, pf_info->vport, index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_attr_get);

u32 dpp_vport_rx_flow_hash_set(struct dpp_pf_info_t *pf_info, u32 hash_mode)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_RSS_HASH_FACTOR;

	rc = dpp_vport_attr_set(pf_info, attr, hash_mode & 0xff);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_rx_flow_hash_set);

u32 dpp_vport_base_qid_get(struct dpp_pf_info_t *pf_info, u32 *base_qid)
{
	u32 rc = DPP_OK;

	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(base_qid);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	rc = dpp_vport_attr_get(pf_info, &port_attr_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_get");

	*base_qid = port_attr_entry.port_base_qid;

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x factor: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, *base_qid);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_base_qid_get);

u32 dpp_vport_rx_flow_hash_get(struct dpp_pf_info_t *pf_info, u32 *hash_mode)
{
	u32 rc = DPP_OK;

	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(hash_mode);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	rc = dpp_vport_attr_get(pf_info, &port_attr_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_get");

	*hash_mode = port_attr_entry.rss_hash_factor;

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x factor: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, *hash_mode);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_rx_flow_hash_get);

u32 dpp_vport_hash_index_get(struct dpp_pf_info_t *pf_info, u32 *hash_index)
{
	u32 rc = DPP_OK;

	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(hash_index);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	rc = dpp_vport_attr_get(pf_info, &port_attr_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_get");

	*hash_index = port_attr_entry.hash_search_index;

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x hash_search_index: %u success.\n",
			       __func__, pf_info->slot, pf_info->vport, *hash_index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_hash_index_get);

u32 dpp_vport_hash_funcs_set(struct dpp_pf_info_t *pf_info, u8 funcs)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_HASH_ALG;

	rc = dpp_vport_attr_set(pf_info, attr, funcs & 0x0f);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_hash_funcs_set);

u32 dpp_vport_rss_en_set(struct dpp_pf_info_t *pf_info, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_RSS_EN_OFF;

	rc = dpp_vport_attr_set(pf_info, attr, enable & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_rss_en_set);

u32 dpp_vport_fd_en_set(struct dpp_pf_info_t *pf_info, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_FD_EN_OFF;

	rc = dpp_vport_attr_set(pf_info, attr, enable & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_fd_en_set);

u32 dpp_vport_virtio_en_set(struct dpp_pf_info_t *pf_info, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_VIRTIO_EN_OFF;

	rc = dpp_vport_attr_set(pf_info, attr, enable & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_virtio_en_set);

u32 dpp_vport_virtio_version_set(struct dpp_pf_info_t *pf_info, u8 version)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_VIRTIO_VERSION;

	rc = dpp_vport_attr_set(pf_info, attr, version & 0x3);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_virtio_version_set);

u32 dpp_vport_promisc_en_set(struct dpp_pf_info_t *pf_info, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_PROMISC_EN;

	rc = dpp_vport_attr_set(pf_info, attr, enable & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_promisc_en_set);

u32 dpp_vport_business_vlan_offload_en_set(struct dpp_pf_info_t *pf_info, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_BUSINESS_VLAN_OFFLOAD_EN;

	rc = dpp_vport_attr_set(pf_info, attr, enable & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_business_vlan_offload_en_set);

u32 dpp_vport_vlan_offload_en_set(struct dpp_pf_info_t *pf_info, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_VLAN_OFFLOAD_EN;

	rc = dpp_vport_attr_set(pf_info, attr, enable & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_vlan_offload_en_set);
