// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/***************************************************************************
 *
 * DEPARTMENT       : ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 ***************************************************************************
 */

#include "zxic_common.h"
#include "dpp_dev.h"
#include "dpp_module.h"
#include "dpp_se.h"
#include "dpp_se_cfg.h"
#include "dpp_hash.h"
#include "dpp_acl.h"

struct dpp_se_cfg *dpp_se_cfg[DPP_PCIE_SLOT_MAX] = { 0 };

static u16 g_lpm_crc[SE_ZBLK_NUM] = { 0x1021, 0x8005, 0x3D65, 0xab47, 0x3453, 0x0357, 0x0589,
				      0xa02b, 0x1021, 0x8005, 0x3D65, 0xab47, 0x3453, 0x0357,
				      0x0589, 0xa02b, 0x1021, 0x8005, 0x3D65, 0xab47, 0x3453,
				      0x0357, 0x0589, 0xa02b, 0x1021, 0x8005, 0x3D65, 0xab47,
				      0x3453, 0x0357, 0x0589, 0xa02b };

#if DPP_WRITE_FILE_EN
static char *prefix_str = "./dpp_se_data";
#endif
DPP_STATUS dpp_se_cfg_set(struct dpp_dev_t *dev, struct dpp_se_cfg *p_se_cfg)
{
	u64 se_cfg_ptr = 0;
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT(p_se_cfg);
	ZXIC_COMM_CHECK_POINT(dev);

	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);
	dpp_se_cfg[slot] = p_se_cfg;
	ZXIC_COMM_CHECK_POINT(dpp_se_cfg[slot]);

	se_cfg_ptr = ZXIC_COMM_PTR_TO_VAL(p_se_cfg);
	ZXIC_COMM_TRACE_INFO("p_se_cfg address 0x%llx.\n", se_cfg_ptr);

	return DPP_OK;
}
DPP_STATUS dpp_se_cfg_get(struct dpp_dev_t *dev, struct dpp_se_cfg **p_se_cfg)
{
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	*p_se_cfg = dpp_se_cfg[slot];
	ZXIC_COMM_CHECK_POINT(*p_se_cfg);

	ZXIC_COMM_TRACE_DEBUG("p_se_cfg address %p.\n", (*p_se_cfg));

	return DPP_OK;
}

DPP_STATUS dpp_se_init(struct dpp_dev_t *dev, struct dpp_se_cfg *p_se_cfg)
{
	u32 i = 0;
	u32 j = 0;
	u32 dev_id = 0;

#if LPM_THREAD_HW_WRITE_EN
	u32 rtn = 0;
#endif

	struct se_zblk_cfg *p_zblk_cfg = NULL;
	struct se_zcell_cfg *p_zcell_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_se_cfg);

	// dev_id = ZXIC_COMM_PTR_TO_VAL(p_se_cfg->p_client) & 0xFFFFFFFF;
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(dev_id, DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_MEMSET(p_se_cfg, 0, sizeof(struct dpp_se_cfg));
	ZXIC_COMM_MEMCPY_S(&p_se_cfg->dev, sizeof(struct dpp_dev_t), dev, sizeof(struct dpp_dev_t));
	p_se_cfg->dev_id = dev_id;
	dpp_se_cfg_set(dev, p_se_cfg);

	//p_se_cfg->p_as_rslt_wrt_fun = dpp_se_lpm_as_rslt_write;
	p_se_cfg->p_client = ZXIC_COMM_VAL_TO_PTR(dev_id);

	for (i = 0; i < SE_ZBLK_NUM; i++) {
		p_zblk_cfg = DPP_SE_GET_ZBLK_CFG(p_se_cfg, i);

		p_zblk_cfg->zblk_idx = i;
		p_zblk_cfg->is_used = 0;
		p_zblk_cfg->hash_arg = g_lpm_crc[i];
		p_zblk_cfg->zcell_bm = 0;
		INIT_D_NODE(&p_zblk_cfg->zblk_dn, p_zblk_cfg);

		for (j = 0; j < SE_ZCELL_NUM; j++) {
			p_zcell_cfg = &p_zblk_cfg->zcell_info[j];

			p_zcell_cfg->zcell_idx = (i << 2) + j;
			p_zcell_cfg->item_used = 0;
			p_zcell_cfg->mask_len = 0;

			INIT_D_NODE(&p_zcell_cfg->zcell_dn, p_zcell_cfg);

			p_zcell_cfg->zcell_avl.p_key = p_zcell_cfg;
		}
	}

#if DPP_WRITE_FILE_EN
	/*    icm_trace_set_log_dir(prefix_str);*/
	dpp_se_file_mng_init();
#else

#endif

#if LPM_THREAD_HW_WRITE_EN
	for (i = 0; i < MAX_ITEM_INFO_BAK_NUM; i++) {
		rtn = zxic_comm_mutex_create(&(p_se_cfg->cache_index_mutex[i]));
		ZXIC_COMM_CHECK_RC(rtn, "zxic_comm_mutex_create");
	}

	rtn = zxic_comm_liststack_creat(MAX_ITEM_INFO_BAK_NUM, &p_se_cfg->p_thread_liststack_mng);
	ZXIC_COMM_CHECK_RC(rtn, "zxic_comm_liststack_creat");
#endif

	return DPP_OK;
}
DPP_STATUS dpp_se_client_init(struct dpp_se_cfg *p_se_cfg, void *p_client)
{
	ZXIC_COMM_CHECK_POINT(p_se_cfg);

	p_se_cfg->p_client = p_client;
	p_se_cfg->reg_base = SYS_SE_BASE_ADDR + MODULE_SE_ALG_BASE_ADDR;
	// p_se_cfg->p_write32_fun = dpp_se_reg_write32;
	// p_se_cfg->p_read32_fun  = dpp_se_reg_read32;

	return DPP_OK;
}

DPP_STATUS dpp_se_fun_init(struct dpp_se_cfg *p_se_cfg, u8 id, u32 fun_type)
{
	struct func_id_info *p_fun_info = NULL;

	ZXIC_COMM_CHECK_POINT(p_se_cfg);
	ZXIC_COMM_CHECK_INDEX(id, 0, MAX_FUN_NUM - 1);
	ZXIC_COMM_CHECK_INDEX(fun_type, FUN_HASH, FUN_MAX - 1);

	p_fun_info = DPP_GET_FUN_INFO(p_se_cfg, id);

	if (p_fun_info->is_used) {
		ZXIC_COMM_TRACE_ERROR("\n Error[0x%x], fun_id [%d] is already used!",
				      DPP_SE_RC_FUN_INVALID, id);
		return DPP_SE_RC_FUN_INVALID;
	}

	p_fun_info->fun_id = id;
	p_fun_info->is_used = 1;

	switch (fun_type) {
	case (FUN_LPM): {
		/* p_fun_info->fun_type = FUN_LPM;
		 * p_fun_info->fun_ptr = ZXIC_COMM_MALLOC(sizeof(DPP_ROUTE_CFG));
		 * ZXIC_COMM_CHECK_POINT(p_fun_info->fun_ptr);
		 * ZXIC_COMM_MEMSET(p_fun_info->fun_ptr,0,sizeof(DPP_ROUTE_CFG));
		 * ((DPP_ROUTE_CFG*)(p_fun_info->fun_ptr))->p_se_cfg = p_se_cfg;
		 */

		//dpp_func_lpm_create(p_se_cfg, id);

	} break;

	case (FUN_HASH): {
		p_fun_info->fun_type = FUN_HASH;
		p_fun_info->fun_ptr = ZXIC_COMM_MALLOC(sizeof(struct dpp_hash_cfg));
		ZXIC_COMM_CHECK_POINT(p_fun_info->fun_ptr);
		ZXIC_COMM_MEMSET(p_fun_info->fun_ptr, 0, sizeof(struct dpp_hash_cfg));
		((struct dpp_hash_cfg *)(p_fun_info->fun_ptr))->p_se_info = p_se_cfg;
	} break;

	default: {
		ZXIC_COMM_TRACE_ERROR("\n Error,unrecgnized fun_type[ %d] ", fun_type);
		ZXIC_COMM_ASSERT(0);
		return DPP_SE_RC_BASE;
	} break;
	}

	return DPP_OK;
}

DPP_STATUS dpp_se_fun_deinit(struct dpp_se_cfg *p_se_cfg, u8 id, u32 fun_type)
{
	struct func_id_info *p_fun_info = NULL;

	ZXIC_COMM_CHECK_POINT(p_se_cfg);
	ZXIC_COMM_CHECK_INDEX(id, 0, MAX_FUN_NUM - 1);
	ZXIC_COMM_CHECK_INDEX(fun_type, FUN_HASH, FUN_MAX - 1);

	p_fun_info = DPP_GET_FUN_INFO(p_se_cfg, id);

	if (p_fun_info->is_used == 0) {
		ZXIC_COMM_TRACE_ERROR("\n Error[0x%x], fun_id [%d] is already deinit!",
				      DPP_SE_RC_FUN_INVALID, id);
		return DPP_SE_RC_FUN_INVALID;
	}

	switch (fun_type) {
	case (FUN_LPM): {
		/*            dpp_func_lpm_destory(p_se_cfg, id);*/
	} break;

	case (FUN_HASH): {
		if (p_fun_info->fun_ptr) {
			ZXIC_COMM_FREE(p_fun_info->fun_ptr);
			p_fun_info->fun_ptr = NULL;
		}
	} break;

	default: {
		ZXIC_COMM_TRACE_ERROR("\n Error,unrecgnized fun_type[ %d] ", fun_type);
		ZXIC_COMM_ASSERT(0);
		return DPP_SE_RC_BASE;
	} break;
	}

	p_fun_info->fun_id = id;
	p_fun_info->is_used = 0;

	return DPP_OK;
}
