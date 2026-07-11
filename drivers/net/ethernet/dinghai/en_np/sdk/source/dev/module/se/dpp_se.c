// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_reg.h"
#include "dpp_se_api.h"
#include "dpp_etcam.h"
#include "dpp_se.h"
#include "dpp_dev.h"
#include "dpp_se_cfg.h"
#include "dpp_sdt.h"
#include "dpp_smmu14k_reg.h"
#include "dpp_se4k_reg.h"

#define SE_OPR_WR (0)
#define SE_OPR_RD (1)
#define SE_CLS_MAX (8)
#define SE_SMMU1_PAGE_MAX (5)
#define SE_LPMID_OFF (4)

static struct smmu1_kschd_hash_ddr_cfg_t g_smmu1_kschd_hash[DPP_DEV_CHANNEL_MAX][DPP_HASH_ID_NUM]
							   [HASH_BULK_NUM] = { { { { 0 } } } };

u32 g_lpm_dat_wr_type_flag = 2;
u8 g_lpm_hw_dat_buf[LPM_HW_DAT_BUFF_SIZE_MAX] = { 0 };
u32 g_lpm_hw_dat_offset;

#define GET_SMMU1_KSCHD_HASH_CFG(dev_id, hash_id, bulk_id) \
	(&g_smmu1_kschd_hash[dev_id][hash_id][bulk_id])

#define SMMU1_WDAT0_R (SYS_SE_BASE_ADDR + MODULE_SE_SMMU1_BASE_ADDR + 0x0)
#define SMMU1_CMD0_R (SYS_SE_BASE_ADDR + MODULE_SE_SMMU1_BASE_ADDR + 0x40)
#define SMMU1_CMD1_R (SYS_SE_BASE_ADDR + MODULE_SE_SMMU1_BASE_ADDR + 0x44)
#define SMMU1_CMD0_F_ADDR_START (30)
#define SMMU1_CMD0_F_ADDR_WIDTH (2)
#define SMMU1_CMD0_F_ECC_EN_START (5)
#define SMMU1_CMD0_F_ECC_EN_WIDTH (1)
#define SMMU1_CMD0_F_DDR_MODE_START (3)
#define SMMU1_CMD0_F_DDR_MODE_WIDTH (2)
#define SMMU1_CMD0_F_BK_INFO_START (0)
#define SMMU1_CMD0_F_BK_INFO_WIDTH (3)

#define SMMU1_CMD1_F_DDR_WR_START (30)
#define SMMU1_CMD1_F_DDR_WR_WIDTH (1)
#define SMMU1_CMD1_F_ADDR_START (0)
#define SMMU1_CMD1_F_ADDR_WIDTH (30)

#if ZXIC_REAL("SMMU0")
DPP_STATUS dpp_se_done_status_check(struct dpp_dev_t *dev, u32 reg_no, u32 pos)
{
	DPP_STATUS rc = DPP_OK;

	u32 data = 0;
	u32 rd_cnt = 0;
	u32 done_flag = 0;

#ifdef DPP_FOR_LLT
	u32 done_sig = 0xffffffff;

	rc = dpp_reg_write32(dev_id, reg_no, done_sig);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_reg_write32");
#endif

	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);

	while (!done_flag) {
		rc = dpp_reg_read32(dev, reg_no, 0, 0, &data);
		if (rc != ZXIC_OK) {
			ZXIC_COMM_TRACE_ERROR("\n [ErrorCode:0x%x] !-- dpp_reg_read32 Fail!\n", rc);
			return rc;
		}

		done_flag = (data >> pos) & 0x1;

		if (done_flag)
			break;

		if (rd_cnt > DPP_RD_CNT_MAX * DPP_RD_CNT_MAX) {
			ZXIC_COMM_TRACE_ERROR("Error!!! dpp se rd reg_no [%d] is overtime!\n",
					      reg_no);
			return DPP_ERR;
		}

		rd_cnt++;
		/*zxic_comm_usleep(1000);*/
	}

	return rc;
}
DPP_STATUS dpp_se_smmu0_ind_write(struct dpp_dev_t *dev, u32 base_addr, u32 index, u32 wrt_mode,
				  u32 *p_data)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;
	u32 temp_idx = 0;
	struct zxic_mutex_t *p_ind_mutex = NULL;

	struct dpp_smmu0_smmu0_cpu_ind_cmd_t cpu_ind_cmd = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), wrt_mode, ERAM128_OPR_128b, ERAM128_OPR_1b);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), base_addr, 0, SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1);

	rc = dpp_dev_opr_mutex_get(dev, DPP_DEV_MUTEX_T_SMMU0, &p_ind_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_ind_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	rc = dpp_se_done_status_check(dev, SMMU0_SMMU0_WR_ARB_CPU_RDYr, 0);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_se_done_status_check", p_ind_mutex);

	switch (wrt_mode) {
	case ERAM128_OPR_128b: {
		if ((0xFFFFFFFF - (base_addr)) < (index)) {
			ZXIC_COMM_TRACE_DEV_ERROR(
				DEV_ID(dev),
				"ICM %s:%d[Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION :%s !\n",
				__FILE__, __LINE__, base_addr, index, __func__);
			rc = zxic_comm_mutex_unlock(p_ind_mutex);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
			return ZXIC_PAR_CHK_INVALID_INDEX;
		}
		if ((base_addr + index) > (SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1)) {
			ZXIC_COMM_PRINT("dpp se_smmu0_ind_write : index out of range !\n");
			rc = zxic_comm_mutex_unlock(p_ind_mutex);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
			return DPP_ERR;
		}

		temp_idx = index << 7;

		for (i = 0; i < 4; i++) {
			rc = dpp_reg_write(dev, SMMU0_SMMU0_CPU_IND_WDAT0r + i, 0, 0,
					   p_data + 3 - i);
			ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_reg_write",
						      p_ind_mutex);
		}

		break;
	}

	case ERAM128_OPR_64b: {
		if ((base_addr + (index >> 1)) > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
			ZXIC_COMM_PRINT("dpp se_smmu0_ind_write : index out of range !\n");
			rc = zxic_comm_mutex_unlock(p_ind_mutex);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
			return DPP_ERR;
		}

		temp_idx = index << 6;

		for (i = 0; i < 2; i++) {
			rc = dpp_reg_write(dev, SMMU0_SMMU0_CPU_IND_WDAT0r + i, 0, 0,
					   p_data + 1 - i);
			ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_reg_write",
						      p_ind_mutex);
		}

		break;
	}

	case ERAM128_OPR_1b: {
		if ((base_addr + (index >> 7)) > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
			ZXIC_COMM_PRINT("dpp se_smmu0_ind_write : index out of range !\n");
			rc = zxic_comm_mutex_unlock(p_ind_mutex);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
			return DPP_ERR;
		}

		temp_idx = index;
		rc = dpp_reg_write(dev, SMMU0_SMMU0_CPU_IND_WDAT0r, 0, 0, p_data);
		ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_reg_write", p_ind_mutex);
		break;
	}
	}

	cpu_ind_cmd.cpu_ind_rw = SE_OPR_WR;
	cpu_ind_cmd.cpu_req_mode = wrt_mode;
	if ((0xFFFFFFFF - (temp_idx)) < ((base_addr << 7) & DPP_ERAM128_BADDR_MASK)) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			DEV_ID(dev),
			"ICM %s:%d[Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION :%s !\n",
			__FILE__, __LINE__, temp_idx, ((base_addr << 7) & DPP_ERAM128_BADDR_MASK),
			__func__);
		zxic_comm_mutex_unlock(p_ind_mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	cpu_ind_cmd.cpu_ind_addr = ((base_addr << 7) & DPP_ERAM128_BADDR_MASK) + temp_idx;

	rc = dpp_reg_write(dev, SMMU0_SMMU0_CPU_IND_CMDr, 0, 0, &cpu_ind_cmd);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_reg_write", p_ind_mutex);

	rc = zxic_comm_mutex_unlock(p_ind_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
DPP_STATUS dpp_se_smmu0_ind_read(struct dpp_dev_t *dev, u32 base_addr, u32 index, u32 rd_mode,
				 u32 rd_clr_mode, u32 *p_data)
{
	DPP_STATUS rc = DPP_OK;

	u32 i = 0;
	u32 row_index = 0;
	u32 col_index = 0;
	u32 temp_data[4] = { 0 };
	u32 *p_temp_data = NULL;

	struct dpp_smmu0_smmu0_cpu_ind_cmd_t cpu_ind_cmd = { 0 };

	struct zxic_mutex_t *p_ind_mutex = NULL;

	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), rd_clr_mode, RD_MODE_HOLD, RD_MODE_CLEAR);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), rd_mode, ERAM128_OPR_128b, ERAM128_OPR_32b);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), base_addr, 0, SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1);

	rc = dpp_dev_opr_mutex_get(dev, DPP_DEV_MUTEX_T_SMMU0, &p_ind_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_ind_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	rc = dpp_se_done_status_check(dev, SMMU0_SMMU0_WR_ARB_CPU_RDYr, 0);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "time_out", p_ind_mutex);

	if (rd_clr_mode == RD_MODE_HOLD) {
		cpu_ind_cmd.cpu_ind_rw = SE_OPR_RD;
		cpu_ind_cmd.cpu_ind_rd_mode = RD_MODE_HOLD;
		cpu_ind_cmd.cpu_req_mode = ERAM128_OPR_128b;

		switch (rd_mode) {
		case ERAM128_OPR_128b: {
			if ((0xFFFFFFFF - (base_addr)) < (index)) {
				zxic_comm_mutex_unlock(p_ind_mutex);
				ZXIC_COMM_TRACE_DEV_ERROR(
					DEV_ID(dev),
					"ICM %s:%d[Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION :%s !\n",
					__FILE__, __LINE__, base_addr, index, __func__);
				return ZXIC_PAR_CHK_INVALID_INDEX;
			}
			if (base_addr + index > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
				ZXIC_COMM_PRINT("dpp se_smmu0_ind_read : index out of range !\n");
				zxic_comm_mutex_unlock(p_ind_mutex);
				return DPP_ERR;
			}

			row_index = (index << 7) & DPP_ERAM128_BADDR_MASK;
			break;
		}

		case ERAM128_OPR_64b: {
			if ((base_addr + (index >> 1)) > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
				ZXIC_COMM_PRINT("dpp se_smmu0_ind_read : index out of range !\n");
				zxic_comm_mutex_unlock(p_ind_mutex);
				return DPP_ERR;
			}

			row_index = (index << 6) & DPP_ERAM128_BADDR_MASK;
			col_index = index & 0x1;
			break;
		}

		case ERAM128_OPR_32b: {
			if ((base_addr + (index >> 2)) > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
				ZXIC_COMM_PRINT("dpp se_smmu0_ind_read : index out of range !\n");
				zxic_comm_mutex_unlock(p_ind_mutex);
				return DPP_ERR;
			}

			row_index = (index << 5) & DPP_ERAM128_BADDR_MASK;
			col_index = index & 0x3;
			break;
		}

		case ERAM128_OPR_1b: {
			if ((base_addr + (index >> 7)) > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
				ZXIC_COMM_PRINT("dpp se_smmu0_ind_read : index out of range !\n");
				zxic_comm_mutex_unlock(p_ind_mutex);
				return DPP_ERR;
			}

			row_index = index & DPP_ERAM128_BADDR_MASK;
			col_index = index & 0x7F;
			break;
		}
		}

		cpu_ind_cmd.cpu_ind_addr = ((base_addr << 7) & DPP_ERAM128_BADDR_MASK) + row_index;
	}

	else {
		cpu_ind_cmd.cpu_ind_rw = SE_OPR_RD;
		cpu_ind_cmd.cpu_ind_rd_mode = RD_MODE_CLEAR;

		switch (rd_mode) {
		case ERAM128_OPR_128b: {
			if ((0xFFFFFFFF - (base_addr)) < (index)) {
				ZXIC_COMM_TRACE_DEV_ERROR(
					DEV_ID(dev),
					"ICM %s:%d[Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION :%s !\n",
					__FILE__, __LINE__, base_addr, index, __func__);
				zxic_comm_mutex_unlock(p_ind_mutex);
				return ZXIC_PAR_CHK_INVALID_INDEX;
			}
			if (base_addr + index > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
				ZXIC_COMM_PRINT("dpp se_smmu0_ind_read : index out of range !\n");
				zxic_comm_mutex_unlock(p_ind_mutex);
				return DPP_ERR;
			}

			row_index = (index << 7);
			cpu_ind_cmd.cpu_req_mode = ERAM128_OPR_128b;
			break;
		}

		case ERAM128_OPR_64b: {
			if ((base_addr + (index >> 1)) > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
				ZXIC_COMM_PRINT("dpp se_smmu0_ind_read : index out of range !\n");
				zxic_comm_mutex_unlock(p_ind_mutex);
				return DPP_ERR;
			}

			row_index = (index << 6);
			cpu_ind_cmd.cpu_req_mode = 2;
			break;
		}

		case ERAM128_OPR_32b: {
			if ((base_addr + (index >> 2)) > SE_SMMU0_ERAM_ADDR_NUM_TOTAL - 1) {
				ZXIC_COMM_PRINT("dpp se_smmu0_ind_read : index out of range !\n");
				zxic_comm_mutex_unlock(p_ind_mutex);
				return DPP_ERR;
			}

			row_index = (index << 5);
			cpu_ind_cmd.cpu_req_mode = 1;
			break;
		}

		case ERAM128_OPR_1b: {
			ZXIC_COMM_TRACE_DEV_ERROR(
				DEV_ID(dev),
				"Param Error! rd_clr_mode[%d] or rd_mode[%d] error!\n ",
				rd_clr_mode, rd_mode);
			zxic_comm_mutex_unlock(p_ind_mutex);
			ZXIC_COMM_ASSERT(0);
			return DPP_ERR;
		}
		}

		cpu_ind_cmd.cpu_ind_addr = ((base_addr << 7) & DPP_ERAM128_BADDR_MASK) + row_index;
	}

	rc = dpp_reg_write(dev, SMMU0_SMMU0_CPU_IND_CMDr, 0, 0, &cpu_ind_cmd);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_reg_write", p_ind_mutex);

	rc = dpp_se_done_status_check(dev, SMMU0_SMMU0_CPU_IND_RD_DONEr, 0);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "time_out", p_ind_mutex);

	p_temp_data = temp_data;
	for (i = 0; i < 4; i++) {
		rc = dpp_reg_read(dev, SMMU0_SMMU0_CPU_IND_RDAT0r + i, 0, 0, p_temp_data + 3 - i);
		ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(dev), rc, "dpp_reg_read", p_ind_mutex);
	}

	if (rd_clr_mode == RD_MODE_HOLD) {
		switch (rd_mode) {
		case ERAM128_OPR_128b: {
			/* ZXIC_COMM_MEMCPY(p_data, &temp_data[0], (128 / 8)); */
			/* modify by ghm for coverity @20200714 */
			ZXIC_COMM_MEMCPY(p_data, p_temp_data, (128 / 8));
			break;
		}

		case ERAM128_OPR_64b: {
			/* ZXIC_COMM_MEMCPY(p_data, &temp_data[(1 - col_index) << 1], (64 / 8)); */
			/* modify by ghm for coverity @20200714 */
			ZXIC_COMM_MEMCPY(p_data, p_temp_data + ((1 - col_index) << 1), (64 / 8));
			break;
		}

		case ERAM128_OPR_32b: {
			ZXIC_COMM_MEMCPY(p_data, p_temp_data + ((3 - col_index)), (32 / 8));
			break;
		}

		case ERAM128_OPR_1b: {
			ZXIC_COMM_UINT32_GET_BITS(p_data[0], *(p_temp_data + (3 - col_index / 32)),
						  (col_index % 32), 1);
			break;
		}
		}
	} else {
		switch (rd_mode) {
		case ERAM128_OPR_128b: {
			ZXIC_COMM_MEMCPY(p_data, p_temp_data, (128 / 8));
			break;
		}

		case ERAM128_OPR_64b: {
			ZXIC_COMM_MEMCPY(p_data, p_temp_data, (64 / 8));
			break;
		}

		case ERAM128_OPR_32b: {
			ZXIC_COMM_MEMCPY(p_data, p_temp_data, (64 / 8));
			break;
		}
		}
	}

	rc = zxic_comm_mutex_unlock(p_ind_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return rc;
}

#endif

#if ZXIC_REAL("SMMU1")
DPP_STATUS dpp_se_smmu1_hash_tbl_cfg_set(struct dpp_dev_t *dev, u32 hash_id, u32 tbl_id, u32 ecc_en,
					 u32 baddr)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_smmu14k_se_smmu1_hash0_tbl0_cfg_t hash_tbl_cfg = { 0 };

	struct smmu1_kschd_hash_ddr_cfg_t *p_hash_ddr_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(hash_id, DPP_HASH_ID_MAX);
	ZXIC_COMM_CHECK_INDEX_UPPER(tbl_id, HASH_BULK_ID_MAX);
	ZXIC_COMM_CHECK_INDEX_UPPER(ecc_en, 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(baddr, DPP_SE_SMMU1_MAX_BADDR_NO_SHARE);

	/* save to soft buffer */
	p_hash_ddr_cfg = GET_SMMU1_KSCHD_HASH_CFG(DEV_ID(dev), hash_id, tbl_id);
	p_hash_ddr_cfg->baddr = baddr;
	p_hash_ddr_cfg->crcen = ecc_en;
	p_hash_ddr_cfg->mode = SMMU1_DDR_SRH_256b; /* alg search ddr mode, not write mode */

	hash_tbl_cfg.hash0_tbl0_ecc_en = ecc_en;
	hash_tbl_cfg.hash0_tbl0_baddr = baddr;

#ifdef DPP_FLOW_HW_INIT
	rc = dpp_reg_write(dev, SMMU14K_SE_SMMU1_HASH0_TBL0_CFGr + hash_id * HASH_BULK_NUM + tbl_id,
			   0, 0, &hash_tbl_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");
#endif

	return rc;
}
DPP_STATUS dpp_se_smmu1_hash_tbl_soft_cfg_get(struct dpp_dev_t *dev, u32 hash_id, u32 bulk_id,
					      u32 *p_ecc_en, u32 *p_base_addr)
{
	struct smmu1_kschd_hash_ddr_cfg_t *p_schd_hash = NULL;

	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(hash_id, DPP_HASH_ID_MAX);
	ZXIC_COMM_CHECK_INDEX_UPPER(bulk_id, HASH_BULK_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_base_addr);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_ecc_en);

	/* read from soft buffer */
	p_schd_hash = GET_SMMU1_KSCHD_HASH_CFG(DEV_ID(dev), hash_id, bulk_id);
	*p_base_addr = p_schd_hash->baddr;
	*p_ecc_en = p_schd_hash->crcen;

	return DPP_OK;
}

#endif

#if ZXIC_REAL("ALG")
DPP_STATUS dpp_se_zblk_serv_cfg_set(struct dpp_dev_t *dev, u32 zblk_idx, u32 serv_sel, u32 hash_id,
				    u32 enable)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_zblock_service_configure_t zblk_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);

	zblk_cfg.hash_channel_sel = hash_id;
	zblk_cfg.service_sel = serv_sel;
	zblk_cfg.st_en = enable;
	rtn = dpp_reg_write(dev, SE4K_SE_ALG_ZBLOCK_SERVICE_CONFIGUREr,
			    ((ZBLK_ADDR_CONV(zblk_idx) >> 3) & 0x3),
			    (ZBLK_ADDR_CONV(zblk_idx) & 0x7), &zblk_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_se_zcell_mono_cfg_set(struct dpp_dev_t *dev, u32 zblk_idx, u32 zcell0_bulk_id,
				     u32 zcell0_mono_flag, u32 zcell1_bulk_id, u32 zcell1_mono_flag,
				     u32 zcell2_bulk_id, u32 zcell2_mono_flag, u32 zcell3_bulk_id,
				     u32 zcell3_mono_flag)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_zblock_hash_zcell_mono_t zblk_zcell_mono_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);

	zblk_zcell_mono_cfg.ha_zcell0_tbl_id = zcell0_bulk_id;
	zblk_zcell_mono_cfg.ha_zcell0_mono_flag = zcell0_mono_flag;
	zblk_zcell_mono_cfg.ha_zcell1_tbl_id = zcell1_bulk_id;
	zblk_zcell_mono_cfg.ha_zcell1_mono_flag = zcell1_mono_flag;
	zblk_zcell_mono_cfg.ha_zcell2_tbl_id = zcell2_bulk_id;
	zblk_zcell_mono_cfg.ha_zcell2_mono_flag = zcell2_mono_flag;
	zblk_zcell_mono_cfg.ha_zcell3_tbl_id = zcell3_bulk_id;
	zblk_zcell_mono_cfg.ha_zcell3_mono_flag = zcell3_mono_flag;

	rtn = dpp_reg_write(dev, SE4K_SE_ALG_ZBLOCK_HASH_ZCELL_MONOr,
			    ((ZBLK_ADDR_CONV(zblk_idx) >> 3) & 0x3),
			    (ZBLK_ADDR_CONV(zblk_idx) & 0x7), &zblk_zcell_mono_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_se_zcell_mono_cfg_get(struct dpp_dev_t *dev, u32 zblk_idx, u32 *zcell0_bulk_id,
				     u32 *zcell0_mono_flag, u32 *zcell1_bulk_id,
				     u32 *zcell1_mono_flag, u32 *zcell2_bulk_id,
				     u32 *zcell2_mono_flag, u32 *zcell3_bulk_id,
				     u32 *zcell3_mono_flag)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_zblock_hash_zcell_mono_t zblk_zcell_mono_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zcell0_bulk_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zcell0_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zcell1_bulk_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zcell1_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zcell2_bulk_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zcell2_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zcell3_bulk_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zcell3_mono_flag);

	rtn = dpp_reg_read(dev, SE4K_SE_ALG_ZBLOCK_HASH_ZCELL_MONOr,
			   ((ZBLK_ADDR_CONV(zblk_idx) >> 3) & 0x3),
			   (ZBLK_ADDR_CONV(zblk_idx) & 0x7), &zblk_zcell_mono_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	*zcell0_bulk_id = zblk_zcell_mono_cfg.ha_zcell0_tbl_id;
	*zcell0_mono_flag = zblk_zcell_mono_cfg.ha_zcell0_mono_flag;
	*zcell1_bulk_id = zblk_zcell_mono_cfg.ha_zcell1_tbl_id;
	*zcell1_mono_flag = zblk_zcell_mono_cfg.ha_zcell1_mono_flag;
	*zcell2_bulk_id = zblk_zcell_mono_cfg.ha_zcell2_tbl_id;
	*zcell2_mono_flag = zblk_zcell_mono_cfg.ha_zcell2_mono_flag;
	*zcell3_bulk_id = zblk_zcell_mono_cfg.ha_zcell3_tbl_id;
	*zcell3_mono_flag = zblk_zcell_mono_cfg.ha_zcell3_mono_flag;

	return DPP_OK;
}
DPP_STATUS
dpp_se_zreg_mono_cfg_set(struct dpp_dev_t *dev, u32 zblk_idx, u32 zreg0_bulk_id,
			 u32 zreg0_mono_flag, u32 zreg1_bulk_id, u32 zreg1_mono_flag,
			 u32 zreg2_bulk_id, u32 zreg2_mono_flag, u32 zreg3_bulk_id,
			 u32 zreg3_mono_flag)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_zlock_hash_zreg_mono_t zblk_zreg_mono_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);

	zblk_zreg_mono_cfg.ha_zreg0_tbl_id = zreg0_bulk_id;
	zblk_zreg_mono_cfg.ha_zreg0_mono_flag = zreg0_mono_flag;
	zblk_zreg_mono_cfg.ha_zreg1_tbl_id = zreg1_bulk_id;
	zblk_zreg_mono_cfg.ha_zreg1_mono_flag = zreg1_mono_flag;
	zblk_zreg_mono_cfg.ha_zreg2_tbl_id = zreg2_bulk_id;
	zblk_zreg_mono_cfg.ha_zreg2_mono_flag = zreg2_mono_flag;
	zblk_zreg_mono_cfg.ha_zreg3_tbl_id = zreg3_bulk_id;
	zblk_zreg_mono_cfg.ha_zreg3_mono_flag = zreg3_mono_flag;

	rtn = dpp_reg_write(dev, SE4K_SE_ALG_ZLOCK_HASH_ZREG_MONOr,
			    ((ZBLK_ADDR_CONV(zblk_idx) >> 3) & 0x3),
			    (ZBLK_ADDR_CONV(zblk_idx) & 0x7), &zblk_zreg_mono_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_se_zreg_mono_cfg_get(struct dpp_dev_t *dev, u32 zblk_idx, u32 *zreg0_bulk_id,
				    u32 *zreg0_mono_flag, u32 *zreg1_bulk_id, u32 *zreg1_mono_flag,
				    u32 *zreg2_bulk_id, u32 *zreg2_mono_flag, u32 *zreg3_bulk_id,
				    u32 *zreg3_mono_flag)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_zlock_hash_zreg_mono_t zblk_zreg_mono_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zreg0_bulk_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zreg0_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zreg1_bulk_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zreg1_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zreg2_bulk_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zreg2_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zreg3_bulk_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), zreg3_mono_flag);

	rtn = dpp_reg_read(dev, SE4K_SE_ALG_ZLOCK_HASH_ZREG_MONOr,
			   ((ZBLK_ADDR_CONV(zblk_idx) >> 3) & 0x3),
			   (ZBLK_ADDR_CONV(zblk_idx) & 0x7), &zblk_zreg_mono_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	*zreg0_bulk_id = zblk_zreg_mono_cfg.ha_zreg0_tbl_id;
	*zreg0_mono_flag = zblk_zreg_mono_cfg.ha_zreg0_mono_flag;
	*zreg1_bulk_id = zblk_zreg_mono_cfg.ha_zreg1_tbl_id;
	*zreg1_mono_flag = zblk_zreg_mono_cfg.ha_zreg1_mono_flag;
	*zreg2_bulk_id = zblk_zreg_mono_cfg.ha_zreg2_tbl_id;
	*zreg2_mono_flag = zblk_zreg_mono_cfg.ha_zreg2_mono_flag;
	*zreg3_bulk_id = zblk_zreg_mono_cfg.ha_zreg3_tbl_id;
	*zreg3_mono_flag = zblk_zreg_mono_cfg.ha_zreg3_mono_flag;

	return DPP_OK;
}
DPP_STATUS dpp_se_hash_zcam_mono_flags_set(struct dpp_dev_t *dev, u32 hash0_mono_flag,
					   u32 hash1_mono_flag, u32 hash2_mono_flag,
					   u32 hash3_mono_flag)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_hash_mono_flag_t hash_mono_flag = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);

	hash_mono_flag.hash0_mono_flag = hash0_mono_flag;
	hash_mono_flag.hash1_mono_flag = hash1_mono_flag;
	hash_mono_flag.hash2_mono_flag = hash2_mono_flag;
	hash_mono_flag.hash3_mono_flag = hash3_mono_flag;

	rtn = dpp_reg_write(dev, SE4K_SE_ALG_HASH_MONO_FLAGr, 0, 0, &hash_mono_flag);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_se_hash_zcam_mono_flags_get(struct dpp_dev_t *dev, u32 *hash0_mono_flag,
					   u32 *hash1_mono_flag, u32 *hash2_mono_flag,
					   u32 *hash3_mono_flag)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_hash_mono_flag_t hash_mono_flag = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash0_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash1_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash2_mono_flag);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash3_mono_flag);

	rtn = dpp_reg_read(dev, SE4K_SE_ALG_HASH_MONO_FLAGr, 0, 0, &hash_mono_flag);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	*hash0_mono_flag = hash_mono_flag.hash0_mono_flag;
	*hash1_mono_flag = hash_mono_flag.hash1_mono_flag;
	*hash2_mono_flag = hash_mono_flag.hash2_mono_flag;
	*hash3_mono_flag = hash_mono_flag.hash3_mono_flag;

	return DPP_OK;
}
DPP_STATUS dpp_se_hash_ext_cfg_set(struct dpp_dev_t *dev, u32 hash_id, u32 ext_mode, u32 flag)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_hash0_ext_cfg_rgt_t hash_ext_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(hash_id, DPP_HASH_ID_MAX);

	hash_ext_cfg.hash0_ext_flag = flag;
	hash_ext_cfg.hash0_ext_mode = ext_mode;

	rtn = dpp_reg_write(dev, SE4K_SE_ALG_HASH0_EXT_CFG_RGTr + hash_id, 0, 0, &hash_ext_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_se_hash_ext_cfg_get(struct dpp_dev_t *dev, u32 hash_id, u32 *p_content_type,
				   u32 *p_flag)
{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_hash0_ext_cfg_rgt_t hash_ext_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(hash_id, DPP_HASH_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_content_type);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_flag);

	rtn = dpp_reg_read(dev, SE4K_SE_ALG_HASH0_EXT_CFG_RGTr + hash_id, 0, 0, &hash_ext_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_read");

	*p_content_type = hash_ext_cfg.hash0_ext_mode;
	*p_flag = hash_ext_cfg.hash0_ext_flag;

	return DPP_OK;
}
DPP_STATUS dpp_se_hash_tbl_depth_set(struct dpp_dev_t *dev, u32 hash_id, u32 hash_tbl0_depth,
				     u32 hash_tbl1_depth, u32 hash_tbl2_depth, u32 hash_tbl3_depth,
				     u32 hash_tbl4_depth, u32 hash_tbl5_depth, u32 hash_tbl6_depth,
				     u32 hash_tbl7_depth)

{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_hash0_tbl30_depth_t hash_tbl30_depth = { 0 };
	struct dpp_se4k_se_alg_hash0_tbl74_depth_t hash_tbl74_depth = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(hash_id, DPP_HASH_ID_MAX);

	hash_tbl30_depth.hash0_tbl0_depth = hash_tbl0_depth;
	hash_tbl30_depth.hash0_tbl1_depth = hash_tbl1_depth;
	hash_tbl30_depth.hash0_tbl2_depth = hash_tbl2_depth;
	hash_tbl30_depth.hash0_tbl3_depth = hash_tbl3_depth;
	hash_tbl74_depth.hash0_tbl4_depth = hash_tbl4_depth;
	hash_tbl74_depth.hash0_tbl5_depth = hash_tbl5_depth;
	hash_tbl74_depth.hash0_tbl6_depth = hash_tbl6_depth;
	hash_tbl74_depth.hash0_tbl7_depth = hash_tbl7_depth;

	rtn = dpp_reg_write(dev, SE4K_SE_ALG_HASH0_TBL30_DEPTHr + 2 * hash_id, 0, 0,
			    &hash_tbl30_depth);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	rtn = dpp_reg_write(dev, SE4K_SE_ALG_HASH0_TBL74_DEPTHr + 2 * hash_id, 0, 0,
			    &hash_tbl74_depth);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_se_hash_tbl_depth_get(struct dpp_dev_t *dev, u32 hash_id, u32 *hash_tbl0_depth,
				     u32 *hash_tbl1_depth, u32 *hash_tbl2_depth,
				     u32 *hash_tbl3_depth, u32 *hash_tbl4_depth,
				     u32 *hash_tbl5_depth, u32 *hash_tbl6_depth,
				     u32 *hash_tbl7_depth)

{
	DPP_STATUS rtn = DPP_OK;

	struct dpp_se4k_se_alg_hash0_tbl30_depth_t hash_tbl30_depth = { 0 };
	struct dpp_se4k_se_alg_hash0_tbl74_depth_t hash_tbl74_depth = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(hash_id, DPP_HASH_ID_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash_tbl0_depth);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash_tbl1_depth);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash_tbl2_depth);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash_tbl3_depth);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash_tbl4_depth);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash_tbl5_depth);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash_tbl6_depth);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), hash_tbl7_depth);

	rtn = dpp_reg_read(dev, SE4K_SE_ALG_HASH0_TBL30_DEPTHr + 2 * hash_id, 0, 0,
			   &hash_tbl30_depth);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_read");

	rtn = dpp_reg_read(dev, SE4K_SE_ALG_HASH0_TBL74_DEPTHr + 2 * hash_id, 0, 0,
			   &hash_tbl74_depth);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_read");

	*hash_tbl0_depth = hash_tbl30_depth.hash0_tbl0_depth;
	*hash_tbl1_depth = hash_tbl30_depth.hash0_tbl1_depth;
	*hash_tbl2_depth = hash_tbl30_depth.hash0_tbl2_depth;
	*hash_tbl3_depth = hash_tbl30_depth.hash0_tbl3_depth;
	*hash_tbl4_depth = hash_tbl74_depth.hash0_tbl4_depth;
	*hash_tbl5_depth = hash_tbl74_depth.hash0_tbl5_depth;
	*hash_tbl6_depth = hash_tbl74_depth.hash0_tbl6_depth;
	*hash_tbl7_depth = hash_tbl74_depth.hash0_tbl7_depth;

	return DPP_OK;
}

#endif
