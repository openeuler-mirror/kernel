// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se.h"
#include "dpp_dev.h"
#include "dpp_dtb_table_api.h"
#include "dpp_dtb_table.h"
#include "dpp_kernel_init.h"
#include "dpp_drv_sdt.h"
#include "dpp_tbl_comm.h"
#include "dpp_dtb_cfg.h"
#include "dpp_dtb.h"

#define DTB_QUEUE_ACK_SIZE (16)
#define DTB_QUEUE_ELEMENT_NUM (32)
#define DTB_QUEUE_ELEMENT_DATA_SIZE (16 * 1024 + DTB_QUEUE_ACK_SIZE) //16k+16
#define DTB_QUEUE_DATA_SIZE (DTB_QUEUE_ELEMENT_DATA_SIZE * DTB_QUEUE_ELEMENT_NUM)
#define DTB_QUEUE_ELEMENT_DUMP_SIZE (16 * 1024 + DTB_QUEUE_ACK_SIZE) //16K+16
#define DTB_QUEUE_DUMP_SIZE (DTB_QUEUE_ELEMENT_DUMP_SIZE * DTB_QUEUE_ELEMENT_NUM)
#define DTB_QUEUE_DMA_SIZE (DTB_QUEUE_DATA_SIZE + DTB_QUEUE_DUMP_SIZE)

struct se_apt_callback_t g_apt_se_callback[DPP_PCIE_SLOT_MAX][DPP_DEV_SDT_ID_MAX] = { { { 0 } } };
s32 dpp_apt_table_key_cmp(void *p_new_key, void *p_old_key, u32 key_len)
{
	ZXIC_COMM_CHECK_POINT(p_new_key);
	ZXIC_COMM_CHECK_POINT(p_old_key);

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_NO_ASSERT(key_len, (u32)ZXIC_SIZEOF(u32));
	return ZXIC_COMM_MEMCMP((u32 *)p_new_key, (u32 *)p_old_key, ZXIC_SIZEOF(u32));
}
struct se_apt_callback_t *dpp_apt_get_func(struct dpp_dev_t *dev, u32 sdt_no)
{
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT_RETURN_NULL(dev);
	ZXIC_COMM_CHECK_INDEX_RETURN_NULL_NO_ASSERT(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX_RETURN_NULL_NO_ASSERT(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	return &g_apt_se_callback[slot][sdt_no];
}
u32 dpp_apt_get_sdt_partner(struct dpp_dev_t *dev, u32 sdt_no)
{
	struct se_apt_callback_t *pAptCallback = NULL;

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	if (pAptCallback == ZXIC_NULL)
		return ZXIC_UINT32_MAX;

	if (DPP_SDT_TBLT_eTCAM == pAptCallback->table_type)
		return pAptCallback->se_func_info.aclFunc.sdt_partner;

	return ZXIC_UINT32_MAX;
}
DPP_STATUS dpp_apt_set_callback(struct dpp_dev_t *dev, u32 sdt_no, u32 table_type, void *pData)
{
	struct se_apt_callback_t *aptFunc = NULL;

	aptFunc = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_POINT(aptFunc);

	aptFunc->sdtNo = sdt_no;
	aptFunc->table_type = table_type;

	switch (table_type) {
	case DPP_SDT_TBLT_eRAM: {
		aptFunc->se_func_info.eramFunc.opr_mode =
			((struct dpp_apt_eram_table_t *)pData)->opr_mode;
		aptFunc->se_func_info.eramFunc.rd_mode =
			((struct dpp_apt_eram_table_t *)pData)->rd_mode;
		aptFunc->se_func_info.eramFunc.eram_set_func =
			((struct dpp_apt_eram_table_t *)pData)->eram_set_func;
		aptFunc->se_func_info.eramFunc.eram_get_func =
			((struct dpp_apt_eram_table_t *)pData)->eram_get_func;
		break;
	}
	case DPP_SDT_TBLT_DDR3: {
		aptFunc->se_func_info.ddrFunc.ddr_tbl_depth =
			((struct dpp_apt_ddr_table_t *)pData)->ddr_table_depth;
		aptFunc->se_func_info.ddrFunc.ddr_set_func =
			((struct dpp_apt_ddr_table_t *)pData)->ddr_set_func;
		aptFunc->se_func_info.ddrFunc.ddr_get_func =
			((struct dpp_apt_ddr_table_t *)pData)->ddr_get_func;
		break;
	}
	case DPP_SDT_TBLT_HASH: {
		aptFunc->se_func_info.hashFunc.hash_set_func =
			((struct dpp_apt_hash_table_t *)pData)->hash_set_func;
		aptFunc->se_func_info.hashFunc.hash_get_func =
			((struct dpp_apt_hash_table_t *)pData)->hash_get_func;
		break;
	}
	case DPP_SDT_TBLT_eTCAM: {
		aptFunc->se_func_info.aclFunc.sdt_partner =
			((struct dpp_apt_acl_table_t *)pData)->sdt_partner;
		aptFunc->se_func_info.aclFunc.acl_set_func =
			((struct dpp_apt_acl_table_t *)pData)->acl_set_func;
		aptFunc->se_func_info.aclFunc.acl_get_func =
			((struct dpp_apt_acl_table_t *)pData)->acl_get_func;
		break;
	}
	default: {
		ZXIC_COMM_TRACE_ERROR("dpp_apt_se_set_callback table_type[ %d ] is invalid!\n",
				      table_type);
		return DPP_ERR;
	}
	}

	return DPP_OK;
}

DPP_STATUS dpp_apt_sw_list_insert(struct _rb_cfg *rb_cfg, void *pData, u32 len)
{
	u32 dev_id = 0;
	u8 *p_rb_key = NULL;
	struct _rb_tn *p_rb_new = NULL;
	struct _rb_tn *p_rb_rtn = NULL;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(rb_cfg);
	ZXIC_COMM_CHECK_POINT(pData);

	p_rb_key = (u8 *)ZXIC_COMM_MALLOC(len);
	ZXIC_COMM_CHECK_POINT(p_rb_key);
	ZXIC_COMM_MEMSET(p_rb_key, 0x0, len);
	ZXIC_COMM_MEMCPY(p_rb_key, pData, len);

	p_rb_new = (struct _rb_tn *)ZXIC_COMM_MALLOC(sizeof(struct _rb_tn));
	if (NULL == (p_rb_new)) {
		ZXIC_COMM_FREE(p_rb_key);
		ZXIC_COMM_TRACE_ERROR("\n ICM %s:%d[Error:POINT NULL] ! FUNCTION : %s!\n", __FILE__,
				      __LINE__, __func__);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	ZXIC_COMM_MEMSET(p_rb_new, 0, ZXIC_SIZEOF(struct _rb_tn));
	INIT_RBT_TN(p_rb_new, p_rb_key);

	rc = zxic_comm_rb_insert(rb_cfg, p_rb_new, &p_rb_rtn);
	if (rc == ZXIC_RBT_RC_UPDATE) {
		ZXIC_COMM_CHECK_POINT(p_rb_rtn);
		ZXIC_COMM_MEMCPY(p_rb_rtn->p_key, pData, len);
		ZXIC_COMM_FREE(p_rb_new);
		ZXIC_COMM_FREE(p_rb_key);
		ZXIC_COMM_TRACE_DEV_DEBUG(dev_id, "update exist entry!\n");
		return DPP_OK;
	}

	return rc;
}

DPP_STATUS dpp_apt_sw_list_search(struct _rb_cfg *rb_cfg, void *pData, u32 len)
{
	u32 rc = DPP_OK;
	struct _rb_tn *p_rb_rtn = NULL;

	ZXIC_COMM_CHECK_POINT(rb_cfg);

	rc = zxic_comm_rb_search(rb_cfg, pData, &p_rb_rtn);
	if (rc != DPP_OK)
		return rc;
	//ZXIC_COMM_CHECK_RC_NO_ASSERT( rc, "zxic_comm_rb_search");

	ZXIC_COMM_MEMCPY(pData, p_rb_rtn->p_key, len);
	return rc;
}

DPP_STATUS dpp_apt_sw_list_delete(struct _rb_cfg *rb_cfg, void *pData, u32 len)
{
	u32 rc = DPP_OK;
	struct _rb_tn *p_rb_rtn = NULL;

	ZXIC_COMM_CHECK_POINT(rb_cfg);

	rc = zxic_comm_rb_delete(rb_cfg, pData, &p_rb_rtn);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "zxic_comm_rb_delete");
	ZXIC_COMM_FREE(p_rb_rtn->p_key);
	ZXIC_COMM_FREE(p_rb_rtn);

	return rc;
}

DPP_STATUS dpp_apt_get_zblock_index(u32 zblock_bitmap, u32 *zblk_idx)
{
	u32 index0 = 0;
	u32 index1 = 0;

	ZXIC_COMM_CHECK_POINT(zblk_idx);

	for (index0 = 0; index0 < 32; index0++) {
		if ((zblock_bitmap >> index0) & 0x1) {
			*(zblk_idx + index1) = index0;
			index1++;
		}
	}

	return DPP_OK;
}

DPP_STATUS dpp_apt_dtb_res_init(struct dpp_dev_t *dev)
{
	u32 rc = DPP_OK;
	u32 queue_id = 0;
	u32 dma_size = 2 * DTB_QUEUE_DMA_SIZE;
	u16 vport = 0;
	struct zxic_mutex_t *p_self_recover_mutex = NULL;
	enum dpp_dev_mutex_type_e mutex = 0;

	struct dtb_queue_dma_addr_info tDmaAddrInfo = { 0 };

	ZXIC_COMM_CHECK_POINT_NO_ASSERT(dev);
	vport = DEV_PCIE_VPORT(dev);

	mutex = DPP_DEV_MUTEX_T_SELF_RECOVER;
	rc = dpp_dev_opr_mutex_get(dev, (u32)mutex, &p_self_recover_mutex);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_self_recover_mutex);
	ZXIC_COMM_CHECK_RC(rc, "zxic_comm_mutex_lock");

	rc = dpp_dtb_queue_requst_ex(dev, "pf", &queue_id);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_queue_requst", p_self_recover_mutex);

	ZXIC_COMM_MEMSET(&tDmaAddrInfo, 0x00, sizeof(struct dtb_queue_dma_addr_info));
	rc = dpp_dtb_queue_dma_mem_alloc(dev, queue_id, dma_size);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_queue_dma_mem_alloc", p_self_recover_mutex);

	rc = dpp_dtb_queue_dma_mem_get(dev, queue_id, &tDmaAddrInfo);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_queue_dma_mem_get", p_self_recover_mutex);

	rc = dpp_dtb_queue_down_table_addr_set(dev, queue_id, tDmaAddrInfo.dma_phy_addr,
					       tDmaAddrInfo.dma_vir_addr);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_queue_down_table_addr_set", p_self_recover_mutex);

	rc = dpp_dtb_queue_dump_table_addr_set(dev, queue_id,
					       tDmaAddrInfo.dma_phy_addr + DTB_QUEUE_DMA_SIZE,
					       tDmaAddrInfo.dma_vir_addr + DTB_QUEUE_DMA_SIZE);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_queue_dump_table_addr_set", p_self_recover_mutex);

	rc = dpp_dtb_user_info_set(dev, queue_id, vport, 0);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_user_info_set", p_self_recover_mutex);

	rc = zxic_comm_mutex_unlock(p_self_recover_mutex);
	ZXIC_COMM_CHECK_RC(rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
DPP_STATUS dpp_apt_se_callback_init(struct dpp_dev_t *dev)
{
	u32 sdt_no = 0;
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	for (sdt_no = 0; sdt_no < DPP_DEV_SDT_ID_MAX; sdt_no++)
		ZXIC_COMM_MEMSET(&g_apt_se_callback[slot][sdt_no], 0x0,
				 sizeof(struct se_apt_callback_t));

	return DPP_OK;
}
DPP_STATUS dpp_apt_sdt_res_deinit(struct dpp_dev_t *dev, u32 sdt_no)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	rc = dpp_sdt_tbl_write(dev, sdt_no, 0, NULL, 1);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_sdt_tbl_write");

	ZXIC_COMM_MEMSET(&g_apt_se_callback[DEV_ID(dev)][sdt_no], 0x0,
			 sizeof(struct se_apt_callback_t));

	return DPP_OK;
}
