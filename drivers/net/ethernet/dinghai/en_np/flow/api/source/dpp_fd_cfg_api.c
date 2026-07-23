// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_flow_comm.h"
#include "dpp_tbl_fd_cfg.h"
#include "dpp_dev.h"

u32 dpp_tbl_fd_cfg_add(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 handle,
		       struct zxdh_fd_cfg_t *p_fd_cfg)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_fd_cfg);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_acl_entry_insert_ex(&dev, queue, sdt_no, handle, p_fd_cfg);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_acl_entry_insert_ex", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_tbl_fd_cfg_add);

u32 dpp_tbl_fd_cfg_del(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 handle)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_acl_entry_del_ex(&dev, queue, sdt_no, handle);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_acl_entry_del_ex", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_tbl_fd_cfg_del);

u32 dpp_tbl_fd_cfg_get(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 handle,
		       struct zxdh_fd_cfg_t *p_fd_cfg)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_fd_cfg);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_acl_entry_get_ex(&dev, queue, sdt_no, handle, p_fd_cfg);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_acl_entry_get_ex", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_tbl_fd_cfg_get);

u32 dpp_tbl_fd_cfg_search(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 handle,
			  struct zxdh_fd_cfg_t *p_fd_cfg)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_fd_cfg);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_acl_entry_search_ex(&dev, queue, sdt_no, handle, p_fd_cfg);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_acl_entry_search_ex", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_tbl_fd_cfg_search);
