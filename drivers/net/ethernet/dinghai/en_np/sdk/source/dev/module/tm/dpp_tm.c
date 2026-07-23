// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_reg_api.h"
#include "dpp_reg_info.h"
#include "dpp_etm_reg.h"
#include "dpp_module.h"
#include "dpp_tm_api.h"
//#include "dpp_tm_diag.h"
#include "dpp_tm.h"
#include "dpp_dev.h"

struct dpp_tm_shape_para g_dpp_etm_shape_para_table[DPP_PCIE_SLOT_MAX][DPP_ETM_SHAP_TABEL_ID_MAX]
						   [DPP_TM_SHAP_MAP_ID_MAX] = { { { { 0 } } } };

struct zxic_mutex_t g_dpp_tm_global_var_rw_mutex;
u32 g_dpp_tm_global_var_rw_mutex_flag;

DPP_STATUS dpp_tm_global_var_mutex_init(void)
{
	DPP_STATUS rc = DPP_OK;

	if (!g_dpp_tm_global_var_rw_mutex_flag) {
		rc = zxic_comm_mutex_create(&g_dpp_tm_global_var_rw_mutex);
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_mutex_create");

		g_dpp_tm_global_var_rw_mutex_flag = 1;
	}

	return DPP_OK;
}

#if ZXIC_REAL("TM_CFGMT")

DPP_STATUS dpp_tm_cfgmt_cpu_check(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 input = 0x5a5a5a5a;
	u32 output = 0;
	struct dpp_etm_cfgmt_cpu_check_reg_t cpu_access_input = { 0 };
	struct dpp_etm_cfgmt_cpu_check_reg_t cpu_access_output = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	cpu_access_input.cpu_check_reg = input;
	rc = dpp_reg_write(dev, ETM_CFGMT_CPU_CHECK_REGr, 0, 0, &cpu_access_input);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_read(dev, ETM_CFGMT_CPU_CHECK_REGr, 0, 0, &cpu_access_output);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	output = cpu_access_output.cpu_check_reg;

	/*  */
	if (input != output) {
		ZXIC_COMM_TRACE_ERROR("dpp_tm_cpu_check :input != output");
		return DPP_ERR;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cfgmt_sa_work_mode_set(struct dpp_dev_t *dev, enum dpp_tm_work_mode_e mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cfgmt_tm_sa_work_mode_t tm_sa_mode = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, DPP_TM_WORK_MODE_TM,
					    DPP_TM_WORK_MODE_TM);

	tm_sa_mode.tm_sa_work_mode = mode;
	rc = dpp_reg_write(dev, ETM_CFGMT_TM_SA_WORK_MODEr, 0, 0, &tm_sa_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cfgmt_sa_work_mode_get(struct dpp_dev_t *dev, enum dpp_tm_work_mode_e *p_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cfgmt_tm_sa_work_mode_t tm_sa_mode = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_mode);

	*p_mode = DPP_TM_WORK_MODE_INVALID;

	rc = dpp_reg_read(dev, ETM_CFGMT_TM_SA_WORK_MODEr, 0, 0, &tm_sa_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_mode = tm_sa_mode.tm_sa_work_mode;

	return DPP_OK;
}

DPP_STATUS dpp_tm_cfgmt_ddr_attach_set(struct dpp_dev_t *dev, u32 ddr_num)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cfgmt_cfgmt_ddr_attach_t ddr_attach = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), ddr_num, 0, 0x3FF);

	ddr_attach.cfgmt_ddr_attach = ddr_num;
	rc = dpp_reg_write(dev, ETM_CFGMT_CFGMT_DDR_ATTACHr, 0, 0, &ddr_attach);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cfgmt_ddr_attach_get(struct dpp_dev_t *dev, u32 *p_ddr_num)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cfgmt_cfgmt_ddr_attach_t ddr_attach = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_ddr_num);

	rc = dpp_reg_read(dev, ETM_CFGMT_CFGMT_DDR_ATTACHr, 0, 0, &ddr_attach);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	if (ddr_attach.cfgmt_ddr_attach == 1)
		*p_ddr_num = 1;
	else if (ddr_attach.cfgmt_ddr_attach == 3)
		*p_ddr_num = 2;
	else if (ddr_attach.cfgmt_ddr_attach == 7)
		*p_ddr_num = 3;
	else if (ddr_attach.cfgmt_ddr_attach == 15)
		*p_ddr_num = 4;
	else if (ddr_attach.cfgmt_ddr_attach == 31)
		*p_ddr_num = 5;
	else if (ddr_attach.cfgmt_ddr_attach == 63)
		*p_ddr_num = 6;
	else if (ddr_attach.cfgmt_ddr_attach == 127)
		*p_ddr_num = 7;
	else if (ddr_attach.cfgmt_ddr_attach == 255)
		*p_ddr_num = 8;

	return DPP_OK;
}

DPP_STATUS dpp_tm_cfgmt_qmu_work_mode_set(struct dpp_dev_t *dev, enum dpp_tm_qmu_work_mode_e mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cfgmt_qmu_work_mode_t qmu_mode = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, DPP_TM_QMU_WORK_MODE_2M,
					    DPP_TM_QMU_WORK_MODE_4M);

	qmu_mode.qmu_work_mode = mode;
	rc = dpp_reg_write(dev, ETM_CFGMT_QMU_WORK_MODEr, 0, 0, &qmu_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cfgmt_qmu_work_mode_get(struct dpp_dev_t *dev,
					  enum dpp_tm_qmu_work_mode_e *p_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cfgmt_qmu_work_mode_t qmu_mode = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_mode);

	rc = dpp_reg_read(dev, ETM_CFGMT_QMU_WORK_MODEr, 0, 0, &qmu_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_mode = qmu_mode.qmu_work_mode;

	return DPP_OK;
}

DPP_STATUS dpp_tm_cfgmt_blk_size_set(struct dpp_dev_t *dev, u32 size)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cfgmt_cfgmt_blksize_t blk_size = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	switch (size) {
	case 256: {
		blk_size.cfgmt_blksize = DPP_ETM_BLK_SIZE_256_B;
		break;
	}

	case 512: {
		blk_size.cfgmt_blksize = DPP_ETM_BLK_SIZE_512_B;
		break;
	}

	case 1024: {
		blk_size.cfgmt_blksize = DPP_ETM_BLK_SIZE_1024_B;
		break;
	}

	default: {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "dpp tm_cfgmt_blk_size_set:TM set block size error!\n");
		return DPP_ERR;
	}
	}

	rc = dpp_reg_write(dev, ETM_CFGMT_CFGMT_BLKSIZEr, 0, 0, &blk_size);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cfgmt_blk_size_get(struct dpp_dev_t *dev, u32 *p_size)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cfgmt_cfgmt_blksize_t blk_size = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_size);

	rc = dpp_reg_read(dev, ETM_CFGMT_CFGMT_BLKSIZEr, 0, 0, &blk_size);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	switch (blk_size.cfgmt_blksize) {
	case DPP_ETM_BLK_SIZE_256_B: {
		*p_size = 256;
		break;
	}

	case DPP_ETM_BLK_SIZE_512_B: {
		*p_size = 512;
		break;
	}

	case DPP_ETM_BLK_SIZE_1024_B: {
		*p_size = 1024;
		break;
	}

	default: {
		*p_size = 256;
	}
	}

	return DPP_OK;
}
#endif

#if ZXIC_REAL("TM_CGAVD")

DPP_STATUS dpp_tm_cgavd_cfg_mode_set(struct dpp_dev_t *dev, u32 mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_cfgmt_byte_mode_t cgavd_cfg_mode = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, 0, 1);

	rc = dpp_reg_read(dev, ETM_CGAVD_CFGMT_BYTE_MODEr, 0, 0, &cgavd_cfg_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	cgavd_cfg_mode.cfgmt_byte_mode = mode;

	rc = dpp_reg_write(dev, ETM_CGAVD_CFGMT_BYTE_MODEr, 0, 0, &cgavd_cfg_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_cfg_mode_get(struct dpp_dev_t *dev, u32 *p_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_cfgmt_byte_mode_t cgavd_cfg_mode = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_mode);

	rc = dpp_reg_read(dev, ETM_CGAVD_CFGMT_BYTE_MODEr, 0, 0, &cgavd_cfg_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_mode = cgavd_cfg_mode.cfgmt_byte_mode;

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_en_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 en)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_etm_cgavd_cgavd_sub_en_t cgavd_sub_en = { 0 };

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SA_LEVEL);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), en, 0, 1);

	rc = dpp_reg_read(dev, ETM_CGAVD_CGAVD_SUB_ENr, 0, 0, &cgavd_sub_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	if (level == QUEUE_LEVEL)
		cgavd_sub_en.cgavd_flow_sub_en = en;

	else if (level == PP_LEVEL)
		cgavd_sub_en.cgavd_pp_sub_en = en;

	else if (level == SYS_LEVEL)
		cgavd_sub_en.cgavd_sys_sub_en = en;

	rc = dpp_reg_write(dev, ETM_CGAVD_CGAVD_SUB_ENr, 0, 0, &cgavd_sub_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_en_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 *p_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_cgavd_sub_en_t cgavd_sub_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SA_LEVEL);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_en);

	*p_en = 0xffffffff;

	rc = dpp_reg_read(dev, ETM_CGAVD_CGAVD_SUB_ENr, 0, 0, &cgavd_sub_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	if (level == QUEUE_LEVEL)
		*p_en = cgavd_sub_en.cgavd_flow_sub_en;

	else if (level == PP_LEVEL)
		*p_en = cgavd_sub_en.cgavd_pp_sub_en;

	else if (level == SYS_LEVEL)
		*p_en = cgavd_sub_en.cgavd_sys_sub_en;

	else if (level == SA_LEVEL)
		*p_en = cgavd_sub_en.cgavd_sa_sub_en;

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_dp_sel_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
				   enum dpp_tm_cgavd_dp_sel_e dp_sel)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_cgavd_dp_sel_t cgavd_dp_sel = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), dp_sel, DP_SEL_DP, DP_SEL_PKT_LEN);

	rc = dpp_reg_read(dev, ETM_CGAVD_CGAVD_DP_SELr, 0, 0, &cgavd_dp_sel);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	if (level == QUEUE_LEVEL) {
		if (dp_sel == DP_SEL_DP) {
			cgavd_dp_sel.flow_dp_sel_high = 0;
			cgavd_dp_sel.flow_dp_sel_mid = 0;
			cgavd_dp_sel.flow_dp_sel_low = 1;
		} else if (dp_sel == DP_SEL_TC) {
			cgavd_dp_sel.flow_dp_sel_high = 0;
			cgavd_dp_sel.flow_dp_sel_mid = 1;
			cgavd_dp_sel.flow_dp_sel_low = 0;
		} else if (dp_sel == DP_SEL_PKT_LEN) {
			cgavd_dp_sel.flow_dp_sel_high = 1;
			cgavd_dp_sel.flow_dp_sel_mid = 0;
			cgavd_dp_sel.flow_dp_sel_low = 0;
		}
	}

	else if (level == PP_LEVEL) {
		if (dp_sel == DP_SEL_DP) {
			cgavd_dp_sel.pp_dp_sel_high = 0;
			cgavd_dp_sel.pp_dp_sel_mid = 0;
			cgavd_dp_sel.pp_dp_sel_low = 1;
		} else if (dp_sel == DP_SEL_TC) {
			cgavd_dp_sel.pp_dp_sel_high = 0;
			cgavd_dp_sel.pp_dp_sel_mid = 1;
			cgavd_dp_sel.pp_dp_sel_low = 0;
		} else if (dp_sel == DP_SEL_PKT_LEN) {
			cgavd_dp_sel.pp_dp_sel_high = 1;
			cgavd_dp_sel.pp_dp_sel_mid = 0;
			cgavd_dp_sel.pp_dp_sel_low = 0;
		}
	}

	else if (level == SYS_LEVEL) {
		if (dp_sel == DP_SEL_DP) {
			cgavd_dp_sel.sys_dp_sel_high = 0;
			cgavd_dp_sel.sys_dp_sel_mid = 0;
			cgavd_dp_sel.sys_dp_sel_low = 1;
		} else if (dp_sel == DP_SEL_TC) {
			cgavd_dp_sel.sys_dp_sel_high = 0;
			cgavd_dp_sel.sys_dp_sel_mid = 1;
			cgavd_dp_sel.sys_dp_sel_low = 0;
		} else if (dp_sel == DP_SEL_PKT_LEN) {
			cgavd_dp_sel.sys_dp_sel_high = 1;
			cgavd_dp_sel.sys_dp_sel_mid = 0;
			cgavd_dp_sel.sys_dp_sel_low = 0;
		}
	}

	rc = dpp_reg_write(dev, ETM_CGAVD_CGAVD_DP_SELr, 0, 0, &cgavd_dp_sel);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_method_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 id,
				   enum dpp_tm_cgavd_method_e method)
{
	DPP_STATUS rc = DPP_OK;
	u32 q_avg_q_len_reg_index = 0;
	u32 q_td_th_reg_index = 0;
	u32 q_ca_mtd_reg_index = 0;
	u32 pp_avg_q_len_reg_index = 0;
	u32 pp_td_th_reg_index = 0;
	u32 pp_ca_mtd_reg_index = 0;
	u32 sys_avg_q_len_reg_index = 0;
	u32 sys_td_th_reg_index = 0;
	u32 sys_ca_mtd_reg_index = 0;

	struct dpp_etm_cgavd_flow_ca_mtd_t q_cgavd_method = { 0 };
	struct dpp_etm_cgavd_pp_ca_mtd_t pp_cgavd_method = { 0 };
	struct dpp_etm_cgavd_sys_cgavd_metd_t sys_cgavd_method = { 0 };
	struct dpp_etm_cgavd_flow_avg_q_len_t flow_avg_q_len = { 0 };
	struct dpp_etm_cgavd_pp_avg_q_len_t pp_avg_q_len = { 0 };
	struct dpp_etm_cgavd_sys_avg_q_len_t sys_avg_q_len = { 0 };
	struct dpp_etm_cgavd_flow_td_th_t q_td_th = { 0 };
	struct dpp_etm_cgavd_pp_td_th_t pp_td_th = { 0 };
	struct dpp_etm_cgavd_sys_td_th_t sys_td_th = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);

	q_avg_q_len_reg_index = ETM_CGAVD_FLOW_AVG_Q_LENr;
	q_td_th_reg_index = ETM_CGAVD_FLOW_TD_THr;
	q_ca_mtd_reg_index = ETM_CGAVD_FLOW_CA_MTDr;
	pp_avg_q_len_reg_index = ETM_CGAVD_PP_AVG_Q_LENr;
	pp_td_th_reg_index = ETM_CGAVD_PP_TD_THr;
	pp_ca_mtd_reg_index = ETM_CGAVD_PP_CA_MTDr;
	sys_avg_q_len_reg_index = ETM_CGAVD_SYS_AVG_Q_LENr;
	sys_td_th_reg_index = ETM_CGAVD_SYS_TD_THr;
	sys_ca_mtd_reg_index = ETM_CGAVD_SYS_CGAVD_METDr;

	switch (level) {
	case (QUEUE_LEVEL): {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_Q_NUM - 1);

		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), method, TD_METHOD,
						    WRED_GRED_METHOD);

		if (method == 1) { /* WRED，，wred */
			rc = dpp_reg_read(dev, q_avg_q_len_reg_index, 0, id, &flow_avg_q_len);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

			rc = dpp_reg_write(dev, q_avg_q_len_reg_index, 0, id, &flow_avg_q_len);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		if (method == 0) { /* TD，，TD */
			rc = dpp_reg_read(dev, q_td_th_reg_index, 0, id, &q_td_th);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

			rc = dpp_reg_write(dev, q_td_th_reg_index, 0, id, &q_td_th);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		/* ,0-TD,1-WRED */
		q_cgavd_method.flow_ca_mtd = method;
		rc = dpp_reg_write(dev, q_ca_mtd_reg_index, 0, id, &q_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		break;
	}

	case (PP_LEVEL): {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_TM_PP_NUM - 1);
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), method, TD_METHOD,
						    WRED_GRED_METHOD);

		if (method == 1) { /* WRED，，wred */
			rc = dpp_reg_read(dev, pp_avg_q_len_reg_index, 0, id, &pp_avg_q_len);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

			rc = dpp_reg_write(dev, pp_avg_q_len_reg_index, 0, id, &pp_avg_q_len);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		if (method == 0) { /* TD，，TD */
			rc = dpp_reg_read(dev, pp_td_th_reg_index, 0, id, &pp_td_th);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
			rc = dpp_reg_write(dev, pp_td_th_reg_index, 0, id, &pp_td_th);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		/* ,0-TD,1-WRED */
		pp_cgavd_method.pp_ca_mtd = method;
		rc = dpp_reg_write(dev, pp_ca_mtd_reg_index, 0, id, &pp_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		break;
	}

	case (SYS_LEVEL): {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), method, TD_METHOD,
						    WRED_GRED_METHOD);

		if (method == 1) { /* GRED，，gred */
			rc = dpp_reg_read(dev, sys_avg_q_len_reg_index, 0, 0, &sys_avg_q_len);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

			rc = dpp_reg_write(dev, sys_avg_q_len_reg_index, 0, 0, &sys_avg_q_len);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		if (method == 0) { /* TD，，TD */
			rc = dpp_reg_read(dev, sys_td_th_reg_index, 0, 0, &sys_td_th);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

			rc = dpp_reg_write(dev, sys_td_th_reg_index, 0, 0, &sys_td_th);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		/* ,0-TD,1-GRED */
		sys_cgavd_method.sys_cgavd_metd = method;
		rc = dpp_reg_write(dev, sys_ca_mtd_reg_index, 0, 0, &sys_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		break;
	}

	default: {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "method=%u error!\n", (method));
		return DPP_ERR;
	}
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_method_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 id,
				   enum dpp_tm_cgavd_method_e *p_method)
{
	DPP_STATUS rc = DPP_OK;
	u32 q_ca_mtd_reg_index = 0;
	u32 pp_ca_mtd_reg_index = 0;
	u32 sys_ca_mtd_reg_index = 0;

	struct dpp_etm_cgavd_flow_ca_mtd_t q_cgavd_method = { 0 };
	struct dpp_etm_cgavd_pp_ca_mtd_t pp_cgavd_method = { 0 };
	struct dpp_etm_cgavd_sys_cgavd_metd_t sys_cgavd_method = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_method);

	*p_method = INVALID_METHOD;

	q_ca_mtd_reg_index = ETM_CGAVD_FLOW_CA_MTDr;
	pp_ca_mtd_reg_index = ETM_CGAVD_PP_CA_MTDr;
	sys_ca_mtd_reg_index = ETM_CGAVD_SYS_CGAVD_METDr;

	if (level == QUEUE_LEVEL) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_Q_NUM - 1);

		rc = dpp_reg_read(dev, q_ca_mtd_reg_index, 0, id, &q_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		*p_method = q_cgavd_method.flow_ca_mtd;
	}

	else if (level == PP_LEVEL) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_TM_PP_NUM - 1);

		rc = dpp_reg_read(dev, pp_ca_mtd_reg_index, 0, id, &pp_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		*p_method = pp_cgavd_method.pp_ca_mtd;
	} else {
		rc = dpp_reg_read(dev, sys_ca_mtd_reg_index, 0, 0, &sys_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		*p_method = sys_cgavd_method.sys_cgavd_metd;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_q_len_use_cpu_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
				    u32 q_len_use_cpu_set_en, u32 q_len_cpu_set)
{
	DPP_STATUS rc = DPP_OK;
	u32 rd_cpu_or_ram_reg_index = 0;
	u32 q_cpu_set_q_len_reg_index = 0;
	u32 pp_cpu_set_q_len_reg_index = 0;
	u32 sys_cpu_set_q_len_reg_index = 0;

	struct dpp_etm_cgavd_rd_cpu_or_ram_t len_use_cpu_set_en = { 0 };
	struct dpp_etm_cgavd_flow_cpu_set_q_len_t flow_q_len_cpu_set = { 0 };
	struct dpp_etm_cgavd_pp_cpu_set_q_len_t pp_q_len_cpu_set = { 0 };
	struct dpp_etm_cgavd_sys_cpu_set_q_len_t sys_q_len_cpu_set = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_len_use_cpu_set_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_len_cpu_set, 0, 0x1ffffff);

	rd_cpu_or_ram_reg_index = ETM_CGAVD_RD_CPU_OR_RAMr;
	q_cpu_set_q_len_reg_index = ETM_CGAVD_FLOW_CPU_SET_Q_LENr;
	pp_cpu_set_q_len_reg_index = ETM_CGAVD_PP_CPU_SET_Q_LENr;
	sys_cpu_set_q_len_reg_index = ETM_CGAVD_SYS_CPU_SET_Q_LENr;

	rc = dpp_reg_read(dev, rd_cpu_or_ram_reg_index, 0, 0, &len_use_cpu_set_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	switch (level) {
	case (QUEUE_LEVEL): {
		len_use_cpu_set_en.cpu_sel_flow_q_len_en = q_len_use_cpu_set_en;
		rc = dpp_reg_write(dev, rd_cpu_or_ram_reg_index, 0, 0, &len_use_cpu_set_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		if (q_len_use_cpu_set_en == 1) {
			flow_q_len_cpu_set.flow_cpu_set_q_len = q_len_cpu_set;
			rc = dpp_reg_write(dev, q_cpu_set_q_len_reg_index, 0, 0,
					   &flow_q_len_cpu_set);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		break;
	}

	case (PP_LEVEL): {
		len_use_cpu_set_en.cpu_sel_pp_q_len_en = q_len_use_cpu_set_en;
		rc = dpp_reg_write(dev, rd_cpu_or_ram_reg_index, 0, 0, &len_use_cpu_set_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		if (q_len_use_cpu_set_en == 1) {
			pp_q_len_cpu_set.pp_cpu_set_q_len = q_len_cpu_set;
			rc = dpp_reg_write(dev, pp_cpu_set_q_len_reg_index, 0, 0,
					   &pp_q_len_cpu_set);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		break;
	}

	case (SYS_LEVEL): {
		len_use_cpu_set_en.cpu_sel_sys_q_len_en = q_len_use_cpu_set_en;
		rc = dpp_reg_write(dev, rd_cpu_or_ram_reg_index, 0, 0, &len_use_cpu_set_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		if (q_len_use_cpu_set_en == 1) {
			sys_q_len_cpu_set.sys_cpu_set_q_len = q_len_cpu_set;
			rc = dpp_reg_write(dev, sys_cpu_set_q_len_reg_index, 0, 0,
					   &sys_q_len_cpu_set);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		break;
	}

	default: {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "level=%u error!\n", level);
		return DPP_ERR;
	}
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_q_avg_len_use_cpu_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
					u32 q_avg_len_use_cpu_set_en, u32 q_avg_len_cpu_set)
{
	DPP_STATUS rc = DPP_OK;
	u32 rd_cpu_or_ram_reg_index = 0;
	u32 q_cpu_set_avg_len_reg_index = 0;
	u32 pp_cpu_set_avg_len_reg_index = 0;
	u32 sys_cpu_set_avg_len_reg_index = 0;

	struct dpp_etm_cgavd_rd_cpu_or_ram_t avg_len_use_cpu_set_en = { 0 };
	struct dpp_etm_cgavd_flow_cpu_set_avg_len_t flow_q_avg_len_cpu_set = { 0 };
	struct dpp_etm_cgavd_pp_cpu_set_avg_q_len_t pp_q_avg_len_cpu_set = { 0 };
	struct dpp_etm_cgavd_sys_cpu_set_avg_len_t sys_q_avg_len_cpu_set = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_avg_len_use_cpu_set_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_avg_len_cpu_set, 0, 0x1ffffff);

	rd_cpu_or_ram_reg_index = ETM_CGAVD_RD_CPU_OR_RAMr;
	q_cpu_set_avg_len_reg_index = ETM_CGAVD_FLOW_CPU_SET_AVG_LENr;
	pp_cpu_set_avg_len_reg_index = ETM_CGAVD_PP_CPU_SET_AVG_Q_LENr;
	sys_cpu_set_avg_len_reg_index = ETM_CGAVD_SYS_CPU_SET_AVG_LENr;

	rc = dpp_reg_read(dev, rd_cpu_or_ram_reg_index, 0, 0, &avg_len_use_cpu_set_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	switch (level) {
	case (QUEUE_LEVEL): {
		avg_len_use_cpu_set_en.cpu_sel_flow_avg_q_len_en = q_avg_len_use_cpu_set_en;
		rc = dpp_reg_write(dev, rd_cpu_or_ram_reg_index, 0, 0, &avg_len_use_cpu_set_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		if (q_avg_len_use_cpu_set_en == 1) {
			flow_q_avg_len_cpu_set.flow_cpu_set_avg_len = q_avg_len_cpu_set;
			rc = dpp_reg_write(dev, q_cpu_set_avg_len_reg_index, 0, 0,
					   &flow_q_avg_len_cpu_set);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		break;
	}

	case (PP_LEVEL): {
		avg_len_use_cpu_set_en.cpu_sel_pp_avg_q_len_en = q_avg_len_use_cpu_set_en;
		rc = dpp_reg_write(dev, rd_cpu_or_ram_reg_index, 0, 0, &avg_len_use_cpu_set_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		if (q_avg_len_use_cpu_set_en == 1) {
			pp_q_avg_len_cpu_set.pp_cpu_set_avg_q_len = q_avg_len_cpu_set;
			rc = dpp_reg_write(dev, pp_cpu_set_avg_len_reg_index, 0, 0,
					   &pp_q_avg_len_cpu_set);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		break;
	}

	case (SYS_LEVEL): {
		avg_len_use_cpu_set_en.cpu_sel_sys_avg_q_len_en = q_avg_len_use_cpu_set_en;
		rc = dpp_reg_write(dev, rd_cpu_or_ram_reg_index, 0, 0, &avg_len_use_cpu_set_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		if (q_avg_len_use_cpu_set_en == 1) {
			sys_q_avg_len_cpu_set.sys_cpu_set_avg_len = q_avg_len_cpu_set;
			rc = dpp_reg_write(dev, sys_cpu_set_avg_len_reg_index, 0, 0,
					   &sys_q_avg_len_cpu_set);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
		}

		break;
	}

	default: {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "level=%u error!\n", level);
		return DPP_ERR;
	}
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_flow_que_len_get(struct dpp_dev_t *dev, u32 que_id, u32 *p_len)
{
	DPP_STATUS rc = DPP_OK;
	u32 blk_size = 0;
	u32 cgavd_cfg_mode = 0;

	struct dpp_etm_cgavd_flow_q_len_t dpp_tm_flow_len = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_len);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), que_id, 0, DPP_ETM_Q_NUM - 1);

	rc = dpp_reg_read(dev, ETM_CGAVD_FLOW_Q_LENr, 0, que_id, &dpp_tm_flow_len);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	rc = dpp_tm_cgavd_cfg_mode_get(dev, &cgavd_cfg_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_cfg_mode_get");

	if (cgavd_cfg_mode == DPP_TM_CGAVD_BLOCK_MODE) {
		rc = dpp_tm_cfgmt_blk_size_get(dev, &blk_size);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cfgmt_blk_size_get");

		*p_len = ((dpp_tm_flow_len.flow_q_len * blk_size) / DPP_TM_CGAVD_KILO_UL);
	} else if (cgavd_cfg_mode == DPP_TM_CGAVD_ZXIC_UINT8_MODE) {
		*p_len = ((dpp_tm_flow_len.flow_q_len) / DPP_TM_CGAVD_KILO_UL);
	} else {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "dpp tm_flow_que_len_get:cgavd_cfg_mode is err!!\n");
		return DPP_ERR;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_td_byte_block_th_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
					     u32 id, u32 byte_block_th)
{
	DPP_STATUS rc = DPP_OK;
	u32 q_td_th_reg_index = 0;
	u32 q_ca_mtd_reg_index = 0;
	u32 pp_td_th_reg_index = 0;
	u32 pp_ca_mtd_reg_index = 0;
	u32 sys_td_th_reg_index = 0;
	u32 sys_ca_mtd_reg_index = 0;
	u32 read_times = 50;
	struct dpp_etm_cgavd_flow_ca_mtd_t q_cgavd_method = { 0 };
	struct dpp_etm_cgavd_flow_td_th_t q_td_th = { 0 };
	struct dpp_etm_cgavd_pp_ca_mtd_t pp_cgavd_method = { 0 };
	struct dpp_etm_cgavd_pp_td_th_t pp_td_th = { 0 };
	struct dpp_etm_cgavd_sys_cgavd_metd_t sys_cgavd_method = { 0 };
	struct dpp_etm_cgavd_sys_td_th_t sys_td_th = { 0 };
	u32 qlist_clr_done_flag = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);

	q_td_th_reg_index = ETM_CGAVD_FLOW_TD_THr;
	q_ca_mtd_reg_index = ETM_CGAVD_FLOW_CA_MTDr;
	pp_td_th_reg_index = ETM_CGAVD_PP_TD_THr;
	pp_ca_mtd_reg_index = ETM_CGAVD_PP_CA_MTDr;
	sys_td_th_reg_index = ETM_CGAVD_SYS_TD_THr;
	sys_ca_mtd_reg_index = ETM_CGAVD_SYS_CGAVD_METDr;

	if (level == QUEUE_LEVEL) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_Q_NUM - 1);
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), byte_block_th, 0, 0x1fffffff);

		q_td_th.flow_td_th = byte_block_th;
		rc = dpp_reg_write(dev, q_td_th_reg_index, 0, id, &q_td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		q_cgavd_method.flow_ca_mtd = TD_METHOD;

		rc = dpp_reg_write(dev, q_ca_mtd_reg_index, 0, id, &q_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		/* add by zhmy begin@20151103 */
		if (byte_block_th == 0) {
			do {
				rc = dpp_tm_qmu_qlist_qcfg_clr_done_get(dev, &qlist_clr_done_flag);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(
					DEV_ID(dev), rc, "dpp_tm_qmu_qlist_qcfg_clr_done_get");

				read_times--;

				if (qlist_clr_done_flag == 1)
					break;

				zxic_comm_delay(10);
			} while (read_times > 0);

			if (read_times == 0) {
				ZXIC_COMM_TRACE_DEV_ERROR(
					DEV_ID(dev),
					"dpp_tm_qmu_qlist_qcfg_clr_done_get time out\n");
				return DPP_ERR;
			}
		}

		/* add by zhmy end@20151103 */
	}

	else if (level == PP_LEVEL) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_TM_PP_NUM - 1);
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), byte_block_th, 0, 0x1fffffff);

		pp_td_th.pp_td_th = byte_block_th;
		rc = dpp_reg_write(dev, pp_td_th_reg_index, 0, id, &pp_td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		pp_cgavd_method.pp_ca_mtd = TD_METHOD;
		rc = dpp_reg_write(dev, pp_ca_mtd_reg_index, 0, id, &pp_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), byte_block_th, 0, 0x1fffffff);

		sys_td_th.sys_td_th = byte_block_th;
		rc = dpp_reg_write(dev, sys_td_th_reg_index, 0, 0, &sys_td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		sys_cgavd_method.sys_cgavd_metd = TD_METHOD;

		rc = dpp_reg_write(dev, sys_ca_mtd_reg_index, 0, 0, &sys_cgavd_method);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_td_th_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 id,
				  u32 td_th)
{
	DPP_STATUS rc = DPP_OK;
	u32 blk_size = 0;
	u32 blk_th = 0;
	u32 cgavd_cfg_mode = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), td_th, 0, 512 * 1024);

	td_th = (u32)(td_th * DPP_TM_CGAVD_KILO_UL);

	rc = dpp_tm_cgavd_cfg_mode_get(dev, &cgavd_cfg_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_cfg_mode_get");

	if (cgavd_cfg_mode == DPP_TM_CGAVD_BLOCK_MODE) {
		rc = dpp_tm_cfgmt_blk_size_get(dev, &blk_size);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cfgmt_blk_size_get");

		if (blk_size != 0) {
			blk_th = (td_th / blk_size);
			blk_th = (td_th % blk_size == 0) ? (blk_th) : ((blk_th) + 1);
		}

		rc = dpp_tm_cgavd_td_byte_block_th_set(dev, level, id, blk_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
						 "dpp_tm_cgavd_td_byte_block_th_set");
	} else if (cgavd_cfg_mode == DPP_TM_CGAVD_ZXIC_UINT8_MODE) {
		rc = dpp_tm_cgavd_td_byte_block_th_set(dev, level, id, td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
						 "dpp_tm_cgavd_td_byte_block_th_set");
	} else {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "dpp tm_cgavd_td_th_set err!!\n");
		return DPP_ERR;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_td_byte_block_th_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
					     u32 id, u32 *p_byte_block_th)
{
	DPP_STATUS rc = DPP_OK;
	u32 q_td_th_reg_index = 0;
	u32 pp_td_th_reg_index = 0;
	u32 sys_td_th_reg_index = 0;
	struct dpp_etm_cgavd_flow_td_th_t q_td_th = { 0 };
	struct dpp_etm_cgavd_pp_td_th_t pp_td_th = { 0 };
	struct dpp_etm_cgavd_sys_td_th_t sys_td_th = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_byte_block_th);

	if (level == QUEUE_LEVEL)
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_Q_NUM - 1);

	else if (level == PP_LEVEL)
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_TM_PP_NUM - 1);
	else
		ZXIC_COMM_PRINT("sys:id is not to be checked!!\n");

	q_td_th_reg_index = ETM_CGAVD_FLOW_TD_THr;
	pp_td_th_reg_index = ETM_CGAVD_PP_TD_THr;
	sys_td_th_reg_index = ETM_CGAVD_SYS_TD_THr;

	if (level == QUEUE_LEVEL) {
		rc = dpp_reg_read(dev, q_td_th_reg_index, 0, id, &q_td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		*p_byte_block_th = q_td_th.flow_td_th;
	}

	else if (level == PP_LEVEL) {
		rc = dpp_reg_read(dev, pp_td_th_reg_index, 0, id, &pp_td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		*p_byte_block_th = pp_td_th.pp_td_th;
	} else {
		rc = dpp_reg_read(dev, sys_td_th_reg_index, 0, 0, &sys_td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		*p_byte_block_th = sys_td_th.sys_td_th;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_td_th_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level, u32 id,
				  u32 *p_td_th)
{
	DPP_STATUS rc = DPP_OK;
	u32 cgavd_cfg_mode = 0;
	u32 block_byte_th = 0;
	u32 blk_size = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, SYS_LEVEL);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_td_th);

	*p_td_th = 0;

	if (level == QUEUE_LEVEL)
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_Q_NUM - 1);

	else if (level == PP_LEVEL)
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_TM_PP_NUM - 1);
	else
		ZXIC_COMM_PRINT("sys:id is not to be checked!!\n");

	rc = dpp_tm_cgavd_td_byte_block_th_get(dev, level, id, &block_byte_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_td_byte_block_th_get");

	rc = dpp_tm_cgavd_cfg_mode_get(dev, &cgavd_cfg_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_cfg_mode_get");

	if (cgavd_cfg_mode == DPP_TM_CGAVD_BLOCK_MODE) {
		rc = dpp_tm_cfgmt_blk_size_get(dev, &blk_size);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cfgmt_blk_size_get");

		*p_td_th = (block_byte_th * blk_size) / DPP_TM_CGAVD_KILO_UL;
	} else if (cgavd_cfg_mode == DPP_TM_CGAVD_ZXIC_UINT8_MODE) {
		*p_td_th = (block_byte_th / DPP_TM_CGAVD_KILO_UL);
	} else {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "dpp tm_cgavd_td_th_get err!!\n");
		return DPP_ERR;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_dyn_th_en_set(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
				      u32 id, u32 en)
{
	DPP_STATUS rc = DPP_OK;
	u32 q_dyn_th_en_reg_index = 0;
	u32 pp_wrd_grp_th_en_reg_index = 0;

	struct dpp_etm_cgavd_flow_dynamic_th_en_t q_dyn_th_en = { 0 };
	struct dpp_etm_cgavd_pp_wred_grp_th_en_t pp_dyn_th_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, PP_LEVEL);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), en, 0, 1);

	q_dyn_th_en_reg_index = ETM_CGAVD_FLOW_DYNAMIC_TH_ENr;
	pp_wrd_grp_th_en_reg_index = ETM_CGAVD_PP_WRED_GRP_TH_ENr;

	if (level == QUEUE_LEVEL) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_Q_NUM - 1);

		q_dyn_th_en.flow_dynamic_th_en = en;
		rc = dpp_reg_write(dev, q_dyn_th_en_reg_index, 0, id, &q_dyn_th_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_TM_PP_NUM - 1);

		rc = dpp_reg_read(dev, pp_wrd_grp_th_en_reg_index, 0, id, &pp_dyn_th_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		pp_dyn_th_en.pp_wred_grp_th_en = en;
		rc = dpp_reg_write(dev, pp_wrd_grp_th_en_reg_index, 0, id, &pp_dyn_th_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_dyn_th_en_get(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
				      u32 id, u32 *p_en)
{
	DPP_STATUS rc = DPP_OK;
	u32 q_dyn_th_en_reg_index = 0;
	u32 pp_wrd_grp_th_en_reg_index = 0;

	struct dpp_etm_cgavd_flow_dynamic_th_en_t q_dyn_th_en = { 0 };
	struct dpp_etm_cgavd_pp_wred_grp_th_en_t pp_dyn_th_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, PP_LEVEL);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_en);

	q_dyn_th_en_reg_index = ETM_CGAVD_FLOW_DYNAMIC_TH_ENr;
	pp_wrd_grp_th_en_reg_index = ETM_CGAVD_PP_WRED_GRP_TH_ENr;

	if (level == QUEUE_LEVEL) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_Q_NUM - 1);

		rc = dpp_reg_read(dev, q_dyn_th_en_reg_index, 0, id, &q_dyn_th_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		*p_en = q_dyn_th_en.flow_dynamic_th_en;
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_TM_PP_NUM - 1);

		rc = dpp_reg_read(dev, pp_wrd_grp_th_en_reg_index, 0, id, &pp_dyn_th_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		*p_en = pp_dyn_th_en.pp_wred_grp_th_en;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_equal_pkt_len_en_set(struct dpp_dev_t *dev, u32 en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_equal_pkt_len_en_t equal_pkt_len_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), en, 0, 1);

	equal_pkt_len_en.equal_pkt_len_en = en;
	rc = dpp_reg_write(dev, ETM_CGAVD_EQUAL_PKT_LEN_ENr, 0, 0, &equal_pkt_len_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_equal_pkt_len_en_get(struct dpp_dev_t *dev, u32 *p_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_equal_pkt_len_en_t equal_pkt_len_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_en);

	*p_en = 0xffffffff;
	rc = dpp_reg_read(dev, ETM_CGAVD_EQUAL_PKT_LEN_ENr, 0, 0, &equal_pkt_len_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	*p_en = equal_pkt_len_en.equal_pkt_len_en;

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_equal_pkt_len_para_set(struct dpp_dev_t *dev,
					       struct dpp_tm_equal_pkt_len_para_t *p_equal_pkt_len)
{
	/*  */
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;

	/*  */
	struct dpp_etm_cgavd_equal_pkt_len0_t equal_pkt_len0 = { 0 };

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_equal_pkt_len);

	for (i = 0; i < 8; i++) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), p_equal_pkt_len->equal_pkt_len[i],
						    0x0, 0x7fff);
		equal_pkt_len0.equal_pkt_len0 = p_equal_pkt_len->equal_pkt_len[i];
		rc = dpp_reg_write(dev, ETM_CGAVD_EQUAL_PKT_LEN0r + i, 0, 0, &equal_pkt_len0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_equal_pkt_len_para_get(struct dpp_dev_t *dev,
					       struct dpp_tm_equal_pkt_len_para_t *p_equal_pkt_len)
{
	/*  */
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;

	/*  */
	struct dpp_etm_cgavd_equal_pkt_len0_t equal_pkt_len0 = { 0 };

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_equal_pkt_len);

	for (i = 0; i < 8; i++) {
		ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT(ETM_CGAVD_EQUAL_PKT_LEN0r, i);
		rc = dpp_reg_read(dev, ETM_CGAVD_EQUAL_PKT_LEN0r + i, 0, 0, &equal_pkt_len0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		p_equal_pkt_len->equal_pkt_len[i] = equal_pkt_len0.equal_pkt_len0;
	}

	return DPP_OK;
}

DPP_STATUS
dpp_tm_cgavd_equal_pkt_len_th_para_set(struct dpp_dev_t *dev,
				       struct dpp_tm_equal_pkt_len_th_para_t *p_equal_pkt_len_th)
{
	/*  */
	DPP_STATUS rc = 0;
	u32 i = 0;

	/*  */
	struct dpp_etm_cgavd_equal_pkt_len_th0_t equal_pkt_len_th0 = { 0 };

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_equal_pkt_len_th);

	for (i = 0; i < 7; i++) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(
			DEV_ID(dev), p_equal_pkt_len_th->equal_pkt_len_th[i], 0x0, 0x7fff);

		if (i <= 5) {
			ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(
				DEV_ID(dev), p_equal_pkt_len_th->equal_pkt_len_th[i + 1],
				p_equal_pkt_len_th->equal_pkt_len_th[i], 0x7fff);
		}

		equal_pkt_len_th0.equal_pkt_len_th0 = p_equal_pkt_len_th->equal_pkt_len_th[i];
		rc = dpp_reg_write(dev, ETM_CGAVD_EQUAL_PKT_LEN_TH0r + i, 0, 0, &equal_pkt_len_th0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS
dpp_tm_cgavd_equal_pkt_len_th_para_get(struct dpp_dev_t *dev,
				       struct dpp_tm_equal_pkt_len_th_para_t *p_equal_pkt_len_th)
{
	/*  */
	DPP_STATUS rc = 0;
	u32 i = 0;

	/*  */
	struct dpp_etm_cgavd_equal_pkt_len_th0_t equal_pkt_len_th0 = { 0 };

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_equal_pkt_len_th);

	for (i = 0; i < 7; i++) {
		ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), i,
								 ETM_CGAVD_EQUAL_PKT_LEN_TH0r);
		rc = dpp_reg_read(dev, ETM_CGAVD_EQUAL_PKT_LEN_TH0r + i, 0, 0, &equal_pkt_len_th0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		p_equal_pkt_len_th->equal_pkt_len_th[i] = equal_pkt_len_th0.equal_pkt_len_th0;
	}

	return DPP_OK;
}

DPP_STATUS
dpp_tm_cgavd_amplify_gene_para_set(struct dpp_dev_t *dev,
				   struct dpp_tm_amplify_gene_para_t *p_amplify_gene_para)
{
	/*  */
	DPP_STATUS rc = 0;
	u32 i = 0;

	/*  */
	struct dpp_etm_cgavd_amplify_gene0_t amplify_gene0 = { 0 };

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_amplify_gene_para);

	for (i = 0; i < 16; i++) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(
			DEV_ID(dev), p_amplify_gene_para->amplify_gene[i], 0x0, 0xfff);
		amplify_gene0.amplify_gene0 = p_amplify_gene_para->amplify_gene[i];
		rc = dpp_reg_write(dev, ETM_CGAVD_AMPLIFY_GENE0r + i, 0, 0, &amplify_gene0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS
dpp_tm_cgavd_amplify_gene_para_get(struct dpp_dev_t *dev,
				   struct dpp_tm_amplify_gene_para_t *p_amplify_gene_para)
{
	/*  */
	DPP_STATUS rc = 0;
	u32 i = 0;

	/*  */
	struct dpp_etm_cgavd_amplify_gene0_t amplify_gene0 = { 0 };

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_amplify_gene_para);

	for (i = 0; i < 16; i++) {
		ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT(ETM_CGAVD_AMPLIFY_GENE0r, i);
		rc = dpp_reg_read(dev, ETM_CGAVD_AMPLIFY_GENE0r + i, 0, 0, &amplify_gene0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		p_amplify_gene_para->amplify_gene[i] = amplify_gene0.amplify_gene0;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_uniform_th_en_set(struct dpp_dev_t *dev, u32 en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_uniform_td_th_en_t uniform_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), en, 0, 1);

	uniform_en.uniform_td_th_en = en;
	rc = dpp_reg_write(dev, ETM_CGAVD_UNIFORM_TD_TH_ENr, 0, 0, &uniform_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_uniform_th_en_get(struct dpp_dev_t *dev, u32 *p_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_uniform_td_th_en_t uniform_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_en);

	rc = dpp_reg_read(dev, ETM_CGAVD_UNIFORM_TD_TH_ENr, 0, 0, &uniform_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_en = uniform_en.uniform_td_th_en;

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_uniform_byte_block_th_set(struct dpp_dev_t *dev, u32 byte_block_uni_th)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_uniform_td_th_t uniform_block_th = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), byte_block_uni_th, 0, 0x1fffffff);

	uniform_block_th.uniform_td_th = byte_block_uni_th;
	rc = dpp_reg_write(dev, ETM_CGAVD_UNIFORM_TD_THr, 0, 0, &uniform_block_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_uniform_th_set(struct dpp_dev_t *dev, u32 uni_th)
{
	DPP_STATUS rc = DPP_OK;
	u32 blk_size = 0;
	u32 blk_th = 0;
	u32 cgavd_cfg_mode = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW(DEV_ID(dev), uni_th, DPP_TM_CGAVD_KILO_UL);
	if ((uni_th * DPP_TM_CGAVD_KILO_UL) > 0x1fffffff)
		uni_th = 0x1fffffff;
	else
		uni_th = (uni_th * DPP_TM_CGAVD_KILO_UL);

	rc = dpp_tm_cgavd_cfg_mode_get(dev, &cgavd_cfg_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_cfg_mode_get");

	if (cgavd_cfg_mode == DPP_TM_CGAVD_BLOCK_MODE) {
		rc = dpp_tm_cfgmt_blk_size_get(dev, &blk_size);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cfgmt_blk_size_get");

		if (blk_size != 0) {
			blk_th = (uni_th / blk_size);
			blk_th = (uni_th % blk_size == 0) ? (blk_th) : ((blk_th) + 1);
		}

		rc = dpp_tm_cgavd_uniform_byte_block_th_set(dev, blk_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
						 "dpp_tm_cgavd_uniform_byte_block_th_set");
	} else if (cgavd_cfg_mode == DPP_TM_CGAVD_ZXIC_UINT8_MODE) {
		rc = dpp_tm_cgavd_uniform_byte_block_th_set(dev, uni_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
						 "dpp_tm_cgavd_uniform_byte_block_th_set");
	} else {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "dpp tm_cgavd_uniform_th_set err!!\n");
		return DPP_ERR;
	}

	return DPP_OK;
}

DPP_STATUS
dpp_tm_cgavd_uniform_byte_block_th_get(struct dpp_dev_t *dev, u32 *p_byte_block_uni_th)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_uniform_td_th_t uniform_block_th = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_byte_block_uni_th);

	rc = dpp_reg_read(dev, ETM_CGAVD_UNIFORM_TD_THr, 0, 0, &uniform_block_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_byte_block_uni_th = uniform_block_th.uniform_td_th;

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_uniform_th_get(struct dpp_dev_t *dev, u32 *p_uni_th)
{
	DPP_STATUS rc = DPP_OK;
	u32 blk_size = 0;
	u32 cgavd_cfg_mode = 0;
	u32 block_byte_th = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_uni_th);

	rc = dpp_tm_cgavd_uniform_byte_block_th_get(dev, &block_byte_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_uniform_byte_block_th_get");

	rc = dpp_tm_cgavd_cfg_mode_get(dev, &cgavd_cfg_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_cfg_mode_get");

	if (cgavd_cfg_mode == DPP_TM_CGAVD_BLOCK_MODE) {
		rc = dpp_tm_cfgmt_blk_size_get(dev, &blk_size);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cfgmt_blk_size_get");

		*p_uni_th = (block_byte_th * blk_size) / DPP_TM_CGAVD_KILO_UL;

	} else if (cgavd_cfg_mode == DPP_TM_CGAVD_ZXIC_UINT8_MODE) {
		*p_uni_th = (block_byte_th / DPP_TM_CGAVD_KILO_UL);
	} else {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "dpp tm_cgavd_uniform_th_get err!!\n");
		return DPP_ERR;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_q_pri_set(struct dpp_dev_t *dev, u32 q_id, u32 pri)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_q_pri_t q_pri = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), pri, 0, 4);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_id, 0, DPP_ETM_Q_NUM - 1);

	q_pri.qpri_flow_cfg_din = pri;
	rc = dpp_reg_write(dev, ETM_CGAVD_Q_PRIr, 0, q_id, &q_pri);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_q_map_pp_set(struct dpp_dev_t *dev, u32 q_id, u32 pp_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_pp_num_t pp_num = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_id, 0, DPP_ETM_Q_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), pp_id, 0, DPP_TM_PP_NUM - 1);

	pp_num.pp_num = pp_id;
	rc = dpp_reg_write(dev, ETM_CGAVD_PP_NUMr, 0, q_id, &pp_num);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_q_map_pp_get(struct dpp_dev_t *dev, u32 q_id, u32 *p_pp_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_pp_num_t pp_num = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_pp_id);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_id, 0, DPP_ETM_Q_NUM - 1);

	*p_pp_id = 0xffffffff;
	rc = dpp_reg_read(dev, ETM_CGAVD_PP_NUMr, 0, q_id, &pp_num);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_pp_id = pp_num.pp_num;

	return DPP_OK;
}

DPP_STATUS dpp_tm_tc_map_flow_set(struct dpp_dev_t *dev, u32 tc_id, u32 flow_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_cfg_tc_flowid_dat_t cfg_tc_flow = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), tc_id, 0, DPP_TM_TC_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), flow_id, 0, DPP_ETM_Q_NUM - 1);

	cfg_tc_flow.cfg_tc_flowid_dat = flow_id;
	rc = dpp_reg_write(dev, ETM_CGAVD_CFG_TC_FLOWID_DATr, 0, tc_id, &cfg_tc_flow);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_tc_map_flow_get(struct dpp_dev_t *dev, u32 tc_id, u32 *flow_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_cgavd_cfg_tc_flowid_dat_t cfg_tc_flow = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), flow_id);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), tc_id, 0, DPP_TM_TC_NUM - 1);

	*flow_id = 0xffffffff;
	rc = dpp_reg_read(dev, ETM_CGAVD_CFG_TC_FLOWID_DATr, 0, tc_id, &cfg_tc_flow);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*flow_id = cfg_tc_flow.cfg_tc_flowid_dat;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_qos_sign_set(struct dpp_dev_t *dev, u32 q_id, u32 qos_sign)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_etm_cgavd_qos_sign_t qmu_qos_sign = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), qos_sign, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_id, 0, DPP_ETM_Q_NUM - 1);

	qmu_qos_sign.qos_sign_flow_cfg_din = qos_sign;

	rc = dpp_reg_write(dev, ETM_CGAVD_QOS_SIGNr, 0, q_id, &qmu_qos_sign);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
#endif

#if ZXIC_REAL("TM_QMU")

DPP_STATUS dpp_tm_qmu_credit_value_get(struct dpp_dev_t *dev, u32 *p_credit_value)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_qsch_credit_value_t credit_val = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_credit_value);

	*p_credit_value = 0;

	rc = dpp_reg_read(dev, ETM_QMU_QCFG_QSCH_CREDIT_VALUEr, 0, 0, &credit_val);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_credit_value = credit_val.qcfg_qsch_credit_value;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_wr_aged_en_set(struct dpp_dev_t *dev, u32 aged_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_csch_aged_cfg_t aged_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aged_en, 0, 1);

	aged_cfg.qcfg_csch_aged_cfg = aged_en;

	rc = dpp_reg_write(dev, ETM_QMU_QCFG_CSCH_AGED_CFGr, 0, 0, &aged_cfg);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_wr_aged_scan_time_set(struct dpp_dev_t *dev, u32 scan_time)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_csch_aged_scan_time_t aged_scan_time = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), scan_time, 0, 0xffffffff);

	aged_scan_time.qcfg_csch_aged_scan_time = scan_time;

	rc = dpp_reg_write(dev, ETM_QMU_QCFG_CSCH_AGED_SCAN_TIMEr, 0, 0, &aged_scan_time);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_wr_aged_scan_time_get(struct dpp_dev_t *dev, u32 *p_scan_time)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_csch_aged_scan_time_t aged_scan_time = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_scan_time);

	rc = dpp_reg_read(dev, ETM_QMU_QCFG_CSCH_AGED_SCAN_TIMEr, 0, 0, &aged_scan_time);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_scan_time = aged_scan_time.qcfg_csch_aged_scan_time;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_qlist_qcfg_clr_done_get(struct dpp_dev_t *dev, u32 *p_clr_done_flag)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qlist_qcfg_clr_done_t clr_done_flag = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_clr_done_flag);

	rc = dpp_reg_read(dev, ETM_QMU_QLIST_QCFG_CLR_DONEr, 0, 0, &clr_done_flag);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_clr_done_flag = clr_done_flag.qlist_qcfg_clr_done;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_qsch_port_shape_set(struct dpp_dev_t *dev, u32 port_id, u32 token_add_num,
					  u32 token_gap, u32 token_depth, u32 shape_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_qsch_shap_param_t qsch_shap_param = { 0 };
	struct dpp_etm_qmu_qcfg_qsch_shap_token_t qsch_shap_token_depth = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), shape_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_add_num, 0, 0xfff);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_gap, 0, 0xfff);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_depth, 0, 0x1f000);

	/*  */
	qsch_shap_token_depth.qcfg_qsch_shap_token = token_depth;
	rc = dpp_reg_write(dev, ETM_QMU_QCFG_QSCH_SHAP_TOKENr, 0, port_id, &qsch_shap_token_depth);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	qsch_shap_param.qcfg_qsch_shap_en = shape_en;
	qsch_shap_param.qcfg_qsch_shap_param1 = token_add_num;
	qsch_shap_param.qcfg_qsch_shap_param2 = token_gap;
	rc = dpp_reg_write(dev, ETM_QMU_QCFG_QSCH_SHAP_PARAMr, 0, port_id, &qsch_shap_param);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_port_shape_set(struct dpp_dev_t *dev, u32 port_id, u32 token_add_num,
				     u32 token_gap, u32 token_depth, u32 shape_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_csw_shap_parameter_t csw_shap_param = { 0 };
	struct dpp_etm_qmu_qcfg_csw_shap_token_depth_t csw_shap_token_depth = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), shape_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_add_num, 0, 0xfff);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_gap, 0, 0xfff);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_depth, 0, 0x1ee00);

	/*  */
	csw_shap_token_depth.qcfg_csw_shap_token_depth = token_depth;
	rc = dpp_reg_write(dev, ETM_QMU_QCFG_CSW_SHAP_TOKEN_DEPTHr, 0, port_id,
			   &csw_shap_token_depth);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	csw_shap_param.qcfg_csw_shap_en = shape_en;
	csw_shap_param.qcfg_csw_shap_parameter = (token_add_num << 12) | token_gap;
	rc = dpp_reg_write(dev, ETM_QMU_QCFG_CSW_SHAP_PARAMETERr, 0, port_id, &csw_shap_param);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_port_shape_get(struct dpp_dev_t *dev, u32 port_id, u32 *p_token_add_num,
				     u32 *p_token_gap, u32 *p_token_depth, u32 *p_shape_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_csw_shap_parameter_t csw_shap_param = { 0 };
	struct dpp_etm_qmu_qcfg_csw_shap_token_depth_t csw_shap_token_depth = { 0 };

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_token_add_num);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_token_gap);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_token_depth);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_shape_en);

	rc = dpp_reg_read(dev, ETM_QMU_QCFG_CSW_SHAP_PARAMETERr, 0, port_id, &csw_shap_param);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_shape_en = csw_shap_param.qcfg_csw_shap_en;
	*p_token_add_num = (csw_shap_param.qcfg_csw_shap_parameter >> 12) & 0xfff;
	*p_token_gap = csw_shap_param.qcfg_csw_shap_parameter & 0xfff;

	rc = dpp_reg_read(dev, ETM_QMU_QCFG_CSW_SHAP_TOKEN_DEPTHr, 0, port_id,
			  &csw_shap_token_depth);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_token_depth = csw_shap_token_depth.qcfg_csw_shap_token_depth;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_spec_qnum_set(struct dpp_dev_t *dev, u32 qnum)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_observe_qnum_set_t observe_qnum = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), qnum, 0, DPP_ETM_Q_NUM - 1);

	observe_qnum.observe_qnum_set = qnum;
	rc = dpp_reg_write(dev, ETM_QMU_OBSERVE_QNUM_SETr, 0, 0, &observe_qnum);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_spec_qnum_get(struct dpp_dev_t *dev, u32 *p_qnum)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_observe_qnum_set_t observe_qnum = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_qnum);

	rc = dpp_reg_read(dev, ETM_QMU_OBSERVE_QNUM_SETr, 0, 0, &observe_qnum);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_qnum = observe_qnum.observe_qnum_set;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_spec_group_set(struct dpp_dev_t *dev, u32 group_num)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_observe_batch_set_t observe_batch = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), group_num, 0, 7);

	observe_batch.observe_batch_set = group_num;
	rc = dpp_reg_write(dev, ETM_QMU_OBSERVE_BATCH_SETr, 0, 0, &observe_batch);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_spec_group_get(struct dpp_dev_t *dev, u32 *p_group_num)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_observe_batch_set_t observe_batch = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_group_num);

	rc = dpp_reg_read(dev, ETM_QMU_OBSERVE_BATCH_SETr, 0, 0, &observe_batch);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_group_num = observe_batch.observe_batch_set;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_auto_credit_que_set(struct dpp_dev_t *dev, u32 first_que, u32 last_que)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_cfg_qsch_autocrfrstque_t qsch_autocrfrstque = { 0 };
	struct dpp_etm_qmu_cfg_qsch_autocrlastque_t qsch_autocrlastque = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), first_que, 0, DPP_ETM_Q_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), last_que, 0, DPP_ETM_Q_NUM - 1);

	if (first_que > last_que) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "[dev_id %d] first_que > last_que, err!!!\n",
					  DEV_ID(dev));

		return DPP_ERR;
	}

	qsch_autocrfrstque.cfg_qsch_autocrfrstque = first_que;
	rc = dpp_reg_write(dev, ETM_QMU_CFG_QSCH_AUTOCRFRSTQUEr, 0, 0, &qsch_autocrfrstque);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	qsch_autocrlastque.cfg_qsch_autocrlastque = last_que;
	rc = dpp_reg_write(dev, ETM_QMU_CFG_QSCH_AUTOCRLASTQUEr, 0, 0, &qsch_autocrlastque);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_auto_credit_que_get(struct dpp_dev_t *dev, u32 *p_first_que, u32 *p_last_que)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_cfg_qsch_autocrfrstque_t qsch_autocrfrstque = { 0 };
	struct dpp_etm_qmu_cfg_qsch_autocrlastque_t qsch_autocrlastque = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_first_que);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_que);

	rc = dpp_reg_read(dev, ETM_QMU_CFG_QSCH_AUTOCRFRSTQUEr, 0, 0, &qsch_autocrfrstque);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	*p_first_que = qsch_autocrfrstque.cfg_qsch_autocrfrstque;

	rc = dpp_reg_read(dev, ETM_QMU_CFG_QSCH_AUTOCRLASTQUEr, 0, 0, &qsch_autocrlastque);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	*p_last_que = qsch_autocrlastque.cfg_qsch_autocrlastque;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_auto_credit_rate_set(struct dpp_dev_t *dev, u32 auto_crdt_en,
					   u32 auto_crdt_rate)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_cfg_qsch_auto_credit_control_en_t credit_control_en = { 0 };
	struct dpp_etm_qmu_cfg_qsch_autocreditrate_t autocredit_rate = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), auto_crdt_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), auto_crdt_rate, 0, 0xfffff);

	credit_control_en.cfg_qsch_auto_credit_control_en = auto_crdt_en;
	rc = dpp_reg_write(dev, ETM_QMU_CFG_QSCH_AUTO_CREDIT_CONTROL_ENr, 0, 0, &credit_control_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	autocredit_rate.cfg_qsch_autocreditrate = auto_crdt_rate;
	rc = dpp_reg_write(dev, ETM_QMU_CFG_QSCH_AUTOCREDITRATEr, 0, 0, &autocredit_rate);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_auto_credit_rate_get(struct dpp_dev_t *dev, u32 *p_auto_crdt_en,
					   u32 *p_auto_crdt_rate)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_cfg_qsch_auto_credit_control_en_t credit_control_en = { 0 };
	struct dpp_etm_qmu_cfg_qsch_autocreditrate_t autocredit_rate = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_auto_crdt_en);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_auto_crdt_rate);

	rc = dpp_reg_read(dev, ETM_QMU_CFG_QSCH_AUTO_CREDIT_CONTROL_ENr, 0, 0, &credit_control_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	*p_auto_crdt_en = credit_control_en.cfg_qsch_auto_credit_control_en;

	rc = dpp_reg_read(dev, ETM_QMU_CFG_QSCH_AUTOCREDITRATEr, 0, 0, &autocredit_rate);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	*p_auto_crdt_rate = autocredit_rate.cfg_qsch_autocreditrate;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_qcfg_csch_congest_th_set(struct dpp_dev_t *dev, u32 port_id,
					       u32 qmu_congest_th)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_csch_congest_th_t qcfg_csch_congest_th = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), qmu_congest_th, 0, 0x1ffff);

	qcfg_csch_congest_th.qcfg_csch_congest_th = qmu_congest_th;
	rc = dpp_reg_write(dev, ETM_QMU_QCFG_CSCH_CONGEST_THr, 0, port_id, &qcfg_csch_congest_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_qcfg_csch_congest_th_get(struct dpp_dev_t *dev, u32 port_id,
					       u32 *p_qmu_congest_th)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_qcfg_csch_congest_th_t qcfg_csch_congest_th = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_qmu_congest_th);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);

	rc = dpp_reg_read(dev, ETM_QMU_QCFG_CSCH_CONGEST_THr, 0, port_id, &qcfg_csch_congest_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_qmu_congest_th = qcfg_csch_congest_th.qcfg_csch_congest_th;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_qcfg_csch_sp_fc_th_set(struct dpp_dev_t *dev, u32 port_id, u32 q_pri,
					     u32 qmu_sp_fc_th)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	struct dpp_etm_qmu_qcfg_csch_sp_fc_th_t qcfg_csch_sp_fc_th = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_pri, 0, 4);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), qmu_sp_fc_th, 0, 0x1ffff);

	index = port_id * 5 + q_pri;
	qcfg_csch_sp_fc_th.qcfg_csch_sp_fc_th = qmu_sp_fc_th;

	rc = dpp_reg_write(dev, ETM_QMU_QCFG_CSCH_SP_FC_THr, 0, index, &qcfg_csch_sp_fc_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_qcfg_csch_sp_fc_th_get(struct dpp_dev_t *dev, u32 port_id, u32 q_pri,
					     u32 *p_qmu_sp_fc_th)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	struct dpp_etm_qmu_qcfg_csch_sp_fc_th_t qcfg_csch_sp_fc_th = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_pri, 0, 4);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_qmu_sp_fc_th);

	index = port_id * 5 + q_pri;

	rc = dpp_reg_read(dev, ETM_QMU_QCFG_CSCH_SP_FC_THr, 0, index, &qcfg_csch_sp_fc_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_qmu_sp_fc_th = qcfg_csch_sp_fc_th.qcfg_csch_sp_fc_th;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_fc_cnt_mode_set(struct dpp_dev_t *dev, u32 mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_fc_cnt_mode_t fc_cnt_mode_reg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, 0, 1);

	fc_cnt_mode_reg.fc_cnt_mode = mode;
	rc = dpp_reg_write(dev, ETM_QMU_FC_CNT_MODEr, 0, 0, &fc_cnt_mode_reg);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_fc_cnt_mode_get(struct dpp_dev_t *dev, u32 *p_mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_fc_cnt_mode_t fc_cnt_mode_reg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_mode);

	rc = dpp_reg_read(dev, ETM_QMU_FC_CNT_MODEr, 0, 0, &fc_cnt_mode_reg);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*p_mode = fc_cnt_mode_reg.fc_cnt_mode;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_observe_portfc_set(struct dpp_dev_t *dev, u32 port_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_observe_portfc_spec_t observe_portfc_reg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);

	observe_portfc_reg.observe_portfc_spec = port_id;
	rc = dpp_reg_write(dev, ETM_QMU_OBSERVE_PORTFC_SPECr, 0, 0, &observe_portfc_reg);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_observe_qnum_set(struct dpp_dev_t *dev, u32 q_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_observe_qnum_set_t observe_qnum_reg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), q_id, 0, DPP_ETM_Q_NUM - 1);

	observe_qnum_reg.observe_qnum_set = q_id;
	rc = dpp_reg_write(dev, ETM_QMU_OBSERVE_PORTFC_SPECr, 0, 0, &observe_qnum_reg);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_observe_batch_set(struct dpp_dev_t *dev, u32 batch_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_observe_batch_set_t observe_batch_reg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), batch_id, 0, 7);

	observe_batch_reg.observe_batch_set = batch_id;
	rc = dpp_reg_write(dev, ETM_QMU_OBSERVE_BATCH_SETr, 0, 0, &observe_batch_reg);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_tm_qmu_pkt_aging_set(struct dpp_dev_t *dev, u32 aging_en, u32 aging_interval,
				    u32 aging_step_interval, u32 aging_start_qnum,
				    u32 aging_end_qnum, u32 aging_pkt_num, u32 aging_req_aful_th)
{
	/*  */
	DPP_STATUS rc = DPP_OK;
	u32 age_pkt_num_reg_index = 0;
	u32 age_step_interval_reg_index = 0;
	u32 age_interval_reg_index = 0;
	u32 age_qnum_reg_index = 0;
	u32 age_req_aful_th_reg_index = 0;
	u32 age_en_reg_index = 0;

	/*  */
	struct dpp_etm_qmu_cfgmt_qmu_pkt_age_en_t cfg_age_en = { 0 };
	struct dpp_etm_qmu_cfgmt_pkt_age_step_interval_t cfg_age_step_interval = { 0 };
	struct dpp_etm_qmu_cfgmt_qmu_pkt_age_interval_t cfg_age_interval = { 0 };
	struct dpp_etm_qmu_cfgmt_qmu_pkt_age_start_end_t cfg_age_qnum = { 0 };
	struct dpp_etm_qmu_cfgmt_pkt_age_req_aful_th_t cfg_age_req_aful_th = { 0 };
	struct dpp_etm_qmu_cfgmt_age_pkt_num_t cfg_age_pkt_num = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_step_interval, 0, 0xff);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_interval, 0, 0xffff);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_req_aful_th, 0, 0x3f);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_pkt_num, 0, 0xf);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_start_qnum, 0, DPP_ETM_Q_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_end_qnum, 0, DPP_ETM_Q_NUM - 1);
	age_pkt_num_reg_index = ETM_QMU_CFGMT_AGE_PKT_NUMr;
	age_step_interval_reg_index = ETM_QMU_CFGMT_PKT_AGE_STEP_INTERVALr;
	age_interval_reg_index = ETM_QMU_CFGMT_QMU_PKT_AGE_INTERVALr;
	age_qnum_reg_index = ETM_QMU_CFGMT_QMU_PKT_AGE_START_ENDr;
	age_req_aful_th_reg_index = ETM_QMU_CFGMT_PKT_AGE_REQ_AFUL_THr;
	age_en_reg_index = ETM_QMU_CFGMT_QMU_PKT_AGE_ENr;

	cfg_age_en.cfgmt_qmu_pkt_age_en = aging_en;
	cfg_age_step_interval.cfgmt_pkt_age_step_interval = aging_step_interval;
	cfg_age_interval.cfgmt_qmu_pkt_age_interval = aging_interval;
	cfg_age_qnum.cfgmt_qmu_pkt_age_start = aging_start_qnum;
	cfg_age_qnum.cfgmt_qmu_pkt_age_end = aging_end_qnum;
	cfg_age_req_aful_th.cfgmt_pkt_age_req_aful_th = aging_req_aful_th;
	cfg_age_pkt_num.cfgmt_age_pkt_num = aging_pkt_num;

	rc = dpp_reg_write(dev, age_pkt_num_reg_index, 0, 0, &cfg_age_pkt_num);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_write(dev, age_step_interval_reg_index, 0, 0, &cfg_age_step_interval);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_write(dev, age_interval_reg_index, 0, 0, &cfg_age_interval);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_write(dev, age_qnum_reg_index, 0, 0, &cfg_age_qnum);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_write(dev, age_req_aful_th_reg_index, 0, 0, &cfg_age_req_aful_th);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_write(dev, age_en_reg_index, 0, 0, &cfg_age_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_tm_qmu_pkt_age_time_set(struct dpp_dev_t *dev, u32 aging_en, u32 aging_time,
				       u32 aging_que_start, u32 aging_que_end)
{
	/*  */
	DPP_STATUS rc = DPP_OK;
	u32 aging_interval = 0;
	//DPP_CRM_CSR_PLL_CLK_SEL_T pll_clk_sel_t = {0};
	// u32 sys_clk = 0;
	// u32 sys_clk_temp[8]={200,250,300,500,600,800,1000,1200};

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_en, 0, 1);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_que_start, 0, DPP_ETM_Q_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), aging_que_end, 0, DPP_ETM_Q_NUM - 1);

	if (aging_interval == 0)
		aging_interval = 1; /* ，0 */

	rc = dpp_tm_qmu_pkt_aging_set(dev, aging_en, aging_interval, 1, aging_que_start,
				      aging_que_end, 1, 0xa);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_qmu_pkt_aging_set");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_pfc_en_set(struct dpp_dev_t *dev, u32 pfc_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_cfgmt_qmu_pfc_en_t qmu_pfc_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), pfc_en, 0, 1);

	qmu_pfc_en.cfgmt_qmu_pfc_en = pfc_en;
	rc = dpp_reg_write(dev, ETM_QMU_CFGMT_QMU_PFC_ENr, 0, 0, &qmu_pfc_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_pfc_en_get(struct dpp_dev_t *dev, u32 *pfc_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_qmu_cfgmt_qmu_pfc_en_t qmu_pfc_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pfc_en);

	*pfc_en = 0xffffffff;
	rc = dpp_reg_read(dev, ETM_QMU_CFGMT_QMU_PFC_ENr, 0, 0, &qmu_pfc_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*pfc_en = qmu_pfc_en.cfgmt_qmu_pfc_en;

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_port_pfc_make_set(struct dpp_dev_t *dev, u32 port_id, u32 port_en)
{
	DPP_STATUS rc = DPP_OK;
	u32 value = 0;
	struct dpp_etm_qmu_cfgmt_qmu_pfc_mask_1_t pfc_mask_31_0 = { 0 };
	struct dpp_etm_qmu_cfgmt_qmu_pfc_mask_2_t pfc_mask_63_32 = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_en, 0, 1);

	if (port_id <= 31) {
		/* port_id:[0-31] */
		rc = dpp_reg_read(dev, ETM_QMU_CFGMT_QMU_PFC_MASK_1r, 0, 0, &pfc_mask_31_0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		value = pfc_mask_31_0.cfgmt_qmu_pfc_mask_1;

		if (port_en == 0)
			value = value & (~(1u << port_id));
		else
			value = value | (1u << port_id);

		pfc_mask_31_0.cfgmt_qmu_pfc_mask_1 = value;

		rc = dpp_reg_write(dev, ETM_QMU_CFGMT_QMU_PFC_MASK_1r, 0, 0, &pfc_mask_31_0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	} else {
		/* port_id:[32-63] */
		rc = dpp_reg_read(dev, ETM_QMU_CFGMT_QMU_PFC_MASK_2r, 0, 0, &pfc_mask_63_32);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		value = pfc_mask_63_32.cfgmt_qmu_pfc_mask_2;

		if (port_en == 0)
			value = value & (~(1u << (port_id - 32)));
		else
			value = value | (1u << (port_id - 32));

		pfc_mask_63_32.cfgmt_qmu_pfc_mask_2 = value;

		rc = dpp_reg_write(dev, ETM_QMU_CFGMT_QMU_PFC_MASK_2r, 0, 0, &pfc_mask_63_32);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_qmu_port_pfc_make_get(struct dpp_dev_t *dev, u32 port_id, u32 *p_port_en)
{
	DPP_STATUS rc = DPP_OK;
	u32 value = 0;
	struct dpp_etm_qmu_cfgmt_qmu_pfc_mask_1_t pfc_mask_31_0 = { 0 };
	struct dpp_etm_qmu_cfgmt_qmu_pfc_mask_2_t pfc_mask_63_32 = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_port_en);

	if (port_id <= 31) {
		/* port_id:[0-31] */
		rc = dpp_reg_read(dev, ETM_QMU_CFGMT_QMU_PFC_MASK_1r, 0, 0, &pfc_mask_31_0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		value = pfc_mask_31_0.cfgmt_qmu_pfc_mask_1;

		*p_port_en = 1 & (value >> port_id);
	} else {
		/* port_id:[32-63] */
		rc = dpp_reg_read(dev, ETM_QMU_CFGMT_QMU_PFC_MASK_2r, 0, 0, &pfc_mask_63_32);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		value = pfc_mask_63_32.cfgmt_qmu_pfc_mask_2;

		*p_port_en = 1 & (value >> (port_id - 32));
	}

	return DPP_OK;
}
#endif

#if ZXIC_REAL("TM_CRDT")
DPP_STATUS dpp_etm_crdt_fq_set(struct dpp_dev_t *dev, u32 fq_num, u32 fq2_num, u32 fq4_num,
			       u32 fq8_num)
{
	DPP_STATUS rc = DPP_OK;
	u32 total_fq_num = 0;
	struct dpp_etm_crdt_th_wfq_fq_t etm_crdt_th_wfqfq_t = { 0 };
	struct dpp_etm_crdt_th_wfq2_fq2_t etm_crdt_th_wfqfq2_t = { 0 };
	struct dpp_etm_crdt_th_wfq4_fq4_t etm_crdt_th_wfqfq4_t = { 0 };
	u32 th_wfq_fq_index = ETM_CRDT_TH_WFQ_FQr;
	u32 th_wfq_fq2_index = ETM_CRDT_TH_WFQ2_FQ2r;
	u32 th_wfq_fq4_index = ETM_CRDT_TH_WFQ4_FQ4r;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	/* :fq */
	ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(DEV_ID(dev), fq2_num, 2);
	ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(DEV_ID(dev), fq4_num, 4);
	ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(DEV_ID(dev), fq8_num, 8);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), fq_num, fq2_num * 2);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), fq_num + fq2_num * 2,
							 fq4_num * 4);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(
		DEV_ID(dev), fq_num + fq2_num * 2 + fq4_num * 4, fq8_num * 8);

	total_fq_num = (fq_num + fq2_num * 2 + fq4_num * 4 + fq8_num * 8);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), total_fq_num, 0, DPP_ETM_FQ_NUM);

	/*  */
	if ((fq_num != 0 && fq_num % 8 != 0) || (fq2_num != 0 && fq2_num % 4 != 0) ||
	    (fq4_num != 0 && fq4_num % 2 != 0)) {
		//ZXIC_COMM__TRACE_ERR("Bad parameter: sp_num or wfq_num %8 != 0 !");
		return DPP_ERR;
	}

	/* ：th_fq：th_fq = fq_num/8 */
	rc = dpp_reg_read(dev, th_wfq_fq_index, 0, 0, &etm_crdt_th_wfqfq_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	etm_crdt_th_wfqfq_t.th_fq = (fq_num / 8);
	rc = dpp_reg_write(dev, th_wfq_fq_index, 0, 0, &etm_crdt_th_wfqfq_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	/* th_fq2：th_fq2 = (th_fq + fq2_num/4) */
	rc = dpp_reg_read(dev, th_wfq_fq2_index, 0, 0, &etm_crdt_th_wfqfq2_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	etm_crdt_th_wfqfq2_t.th_fq2 = (etm_crdt_th_wfqfq_t.th_fq + fq2_num / 4);
	rc = dpp_reg_write(dev, th_wfq_fq2_index, 0, 0, &etm_crdt_th_wfqfq2_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	/* th_fq4：th_fq4 = (th_fq2 + fq4_num/2) */
	rc = dpp_reg_read(dev, th_wfq_fq4_index, 0, 0, &etm_crdt_th_wfqfq4_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	etm_crdt_th_wfqfq4_t.th_fq4 = (etm_crdt_th_wfqfq2_t.th_fq2 + fq4_num / 2);
	rc = dpp_reg_write(dev, th_wfq_fq4_index, 0, 0, &etm_crdt_th_wfqfq4_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_wfqsp_set(struct dpp_dev_t *dev, u32 sp_num, u32 wfq_num, u32 wfq2_num,
				 u32 wfq4_num, u32 wfq8_num)
{
	DPP_STATUS rc = DPP_OK;
	u32 total_wfqsp_num = 0;
	struct dpp_etm_crdt_th_sp_t etm_crdt_th_sp_t = { 0 };
	struct dpp_etm_crdt_th_wfq_fq_t etm_crdt_th_wfqfq_t = { 0 };
	struct dpp_etm_crdt_th_wfq2_fq2_t etm_crdt_th_wfqfq2_t = { 0 };
	struct dpp_etm_crdt_th_wfq4_fq4_t etm_crdt_th_wfqfq4_t = { 0 };
	u32 th_sp_index = ETM_CRDT_TH_SPr;
	u32 th_wfq_fq_index = ETM_CRDT_TH_WFQ_FQr;
	u32 th_wfq_fq2_index = ETM_CRDT_TH_WFQ2_FQ2r;
	u32 th_wfq_fq4_index = ETM_CRDT_TH_WFQ4_FQ4r;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	/*  */
	ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(DEV_ID(dev), wfq2_num, 2);
	ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(DEV_ID(dev), wfq4_num, 4);
	ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(DEV_ID(dev), wfq8_num, 8);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), sp_num, wfq_num);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), sp_num + wfq_num,
							 wfq2_num * 2);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(
		DEV_ID(dev), sp_num + wfq_num + wfq2_num * 2, wfq4_num * 4);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(
		DEV_ID(dev), sp_num + wfq_num + wfq2_num * 2 + wfq4_num * 4, wfq8_num * 8);
	/*  */
	total_wfqsp_num = (sp_num + wfq_num + wfq2_num * 2 + wfq4_num * 4 + wfq8_num * 8);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), total_wfqsp_num, 0, DPP_ETM_WFQSP_NUM);

	/*  */
	if ((sp_num != 0 && sp_num % 8 != 0) || (wfq_num != 0 && wfq_num % 8 != 0) ||
	    (wfq2_num != 0 && wfq2_num % 4 != 0) || (wfq4_num != 0 && wfq4_num % 2 != 0)) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "Bad parameter: sp_num or wfq_num mod 8 != 0 !\n");
		return DPP_ERR;
	}

	th_sp_index = ETM_CRDT_TH_SPr;
	th_wfq_fq_index = ETM_CRDT_TH_WFQ_FQr;
	th_wfq_fq2_index = ETM_CRDT_TH_WFQ2_FQ2r;
	th_wfq_fq4_index = ETM_CRDT_TH_WFQ4_FQ4r;

	/* ：th_sp：th_sp=      sp_num/8 */
	rc = dpp_reg_read(dev, th_sp_index, 0, 0, &etm_crdt_th_sp_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	etm_crdt_th_sp_t.th_sp = (sp_num / 8);
	rc = dpp_reg_write(dev, th_sp_index, 0, 0, &etm_crdt_th_sp_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	/* th_wfq：th_wfq = (th_sp + wfq_num/8)       */
	rc = dpp_reg_read(dev, th_wfq_fq_index, 0, 0, &etm_crdt_th_wfqfq_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	etm_crdt_th_wfqfq_t.th_wfq = (etm_crdt_th_sp_t.th_sp + wfq_num / 8);
	rc = dpp_reg_write(dev, th_wfq_fq_index, 0, 0, &etm_crdt_th_wfqfq_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	/* th_wfq2：th_wfq2 = (th_wfq +      wfq2_num/4) */
	rc = dpp_reg_read(dev, th_wfq_fq2_index, 0, 0, &etm_crdt_th_wfqfq2_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	etm_crdt_th_wfqfq2_t.th_wfq2 = (etm_crdt_th_wfqfq_t.th_wfq + wfq2_num / 4);
	rc = dpp_reg_write(dev, th_wfq_fq2_index, 0, 0, &etm_crdt_th_wfqfq2_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	/* th_wfq4：th_wfq4 = (th_wfq2 +      wfq4_num/2) */
	rc = dpp_reg_read(dev, th_wfq_fq4_index, 0, 0, &etm_crdt_th_wfqfq4_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	etm_crdt_th_wfqfq4_t.th_wfq4 = (etm_crdt_th_wfqfq2_t.th_wfq2 + wfq4_num / 2);
	rc = dpp_reg_write(dev, th_wfq_fq4_index, 0, 0, &etm_crdt_th_wfqfq4_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS
dpp_tm_crdt_wfqsp_get(struct dpp_dev_t *dev,
		      struct dpp_tm_crdt_spwfq_start_num_t *p_spwfq_start_num)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_crdt_th_sp_t etm_crdt_th_sp_t = { 0 };
	struct dpp_etm_crdt_th_wfq_fq_t etm_crdt_th_wfqfq_t = { 0 };
	struct dpp_etm_crdt_th_wfq2_fq2_t etm_crdt_th_wfqfq2_t = { 0 };
	struct dpp_etm_crdt_th_wfq4_fq4_t etm_crdt_th_wfqfq4_t = { 0 };
	u32 th_sp_index = ETM_CRDT_TH_SPr;
	u32 th_wfq_fq_index = ETM_CRDT_TH_WFQ_FQr;
	u32 th_wfq_fq2_index = ETM_CRDT_TH_WFQ2_FQ2r;
	u32 th_wfq_fq4_index = ETM_CRDT_TH_WFQ4_FQ4r;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_spwfq_start_num);

	/* ：th_sp：th_sp=      sp_num/8 */
	rc = dpp_reg_read(dev, th_sp_index, 0, 0, &etm_crdt_th_sp_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	/* th_wfq：th_wfq = (th_sp + wfq_num/8)       */
	rc = dpp_reg_read(dev, th_wfq_fq_index, 0, 0, &etm_crdt_th_wfqfq_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	/* th_wfq2：th_wfq2 = (th_wfq +      wfq2_num/4) */
	rc = dpp_reg_read(dev, th_wfq_fq2_index, 0, 0, &etm_crdt_th_wfqfq2_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	/* th_wfq4：th_wfq4 = (th_wfq2 +      wfq4_num/2) */
	rc = dpp_reg_read(dev, th_wfq_fq4_index, 0, 0, &etm_crdt_th_wfqfq4_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	/*  */
	p_spwfq_start_num->start_num_fq = 0;
	p_spwfq_start_num->start_num_fq2 = etm_crdt_th_wfqfq_t.th_fq * 8;
	p_spwfq_start_num->start_num_fq4 = etm_crdt_th_wfqfq2_t.th_fq2 * 8;
	p_spwfq_start_num->start_num_fq8 = etm_crdt_th_wfqfq4_t.th_fq4 * 8;
	p_spwfq_start_num->start_num_sp = DPP_ETM_WFQSP_OFFSET;
	p_spwfq_start_num->start_num_wfq = (DPP_ETM_WFQSP_OFFSET + etm_crdt_th_sp_t.th_sp * 8);
	p_spwfq_start_num->start_num_wfq2 = (DPP_ETM_WFQSP_OFFSET + etm_crdt_th_wfqfq_t.th_wfq * 8);
	p_spwfq_start_num->start_num_wfq4 =
		(DPP_ETM_WFQSP_OFFSET + etm_crdt_th_wfqfq2_t.th_wfq2 * 8);
	p_spwfq_start_num->start_num_wfq8 =
		(DPP_ETM_WFQSP_OFFSET + etm_crdt_th_wfqfq4_t.th_wfq4 * 8);

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_sch_type_get(struct dpp_dev_t *dev, u32 se_id, u32 *item_num,
				    u32 *sch_type_num)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_tm_crdt_spwfq_start_num_t spwfq_start_num_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), item_num);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);

	rc = dpp_tm_crdt_wfqsp_get(dev, &spwfq_start_num_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_wfqsp_get");

	if (se_id < spwfq_start_num_t.start_num_fq2) {
		*item_num = 1;
		*sch_type_num = 5;
	} else if (se_id < spwfq_start_num_t.start_num_fq4) {
		*item_num = 2;
		*sch_type_num = 6;
	} else if (se_id < spwfq_start_num_t.start_num_fq8) {
		*item_num = 4;
		*sch_type_num = 7;
	} else if (se_id < spwfq_start_num_t.start_num_sp) {
		*item_num = 8;
		*sch_type_num = 8;
	} else if (se_id < spwfq_start_num_t.start_num_wfq) {
		*item_num = 1;
		*sch_type_num = 0;
	} else if (se_id < spwfq_start_num_t.start_num_wfq2) {
		*item_num = 1;
		*sch_type_num = 1;
	} else if (se_id < spwfq_start_num_t.start_num_wfq4) {
		*item_num = 2;
		*sch_type_num = 2;
	} else if (se_id < spwfq_start_num_t.start_num_wfq8) {
		*item_num = 4;
		*sch_type_num = 3;
	} else {
		*item_num = 8;
		*sch_type_num = 4;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_pp_para_get(struct dpp_dev_t *dev, u32 pp_id, u32 *p_weight,
				   u32 *p_sp_mapping)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_etm_crdt_pp_cfg_t pp_cfg_r = { 0 };
	struct dpp_etm_crdt_pp_weight_t pp_weight_r = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), pp_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_weight);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_sp_mapping);

	rc = dpp_reg_read(dev, ETM_CRDT_PP_WEIGHTr, 0, pp_id, &pp_weight_r);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	*p_weight = pp_weight_r.pp_weight;

	rc = dpp_reg_read(dev, ETM_CRDT_PP_CFGr, 0, pp_id, &pp_cfg_r);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	*p_sp_mapping = pp_cfg_r.pp_cfg;

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_se_pp_link_set(struct dpp_dev_t *dev, u32 se_id, u32 pp_id, u32 weight,
				      u32 sp_mapping)
{
	DPP_STATUS rc = DPP_OK;
	u32 delay_time = 10;

	struct dpp_etm_crdt_pp_cfg_t pp_cfg = { 0 };
	struct dpp_etm_crdt_pp_weight_t pp_weight = { 0 };
	struct dpp_etm_crdt_pp_cfg_t pp_cfg_r = { 0 };
	struct dpp_etm_crdt_pp_weight_t pp_weight_r = { 0 };
	struct dpp_tm_sch_se_para_t sch_se_para_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), pp_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), weight, 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), sp_mapping, DPP_TM_SCH_SP_0,
					    DPP_TM_SCH_SP_8);

	/* : , */
	sch_se_para_t.se_linkid = DPP_ETM_PORT_LINKID_BASE + pp_id;

	rc = dpp_tm_crdt_se_link_wr(dev, se_id, &sch_se_para_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_se_link_wr");

	/* CRDT */
	rc = dpp_tm_crdt_idle_check(dev);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_idle_check");

	pp_weight.pp_weight = weight;
	rc = dpp_reg_write(dev, ETM_CRDT_PP_WEIGHTr, 0, pp_id, &pp_weight);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	/* ， */
#if (ETM_WRITE_CHECK)
	{
		zxic_comm_delay(delay_time);
		rc = dpp_reg_read(dev, ETM_CRDT_PP_WEIGHTr, 0, pp_id, &pp_weight_r);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		if (pp_weight_r.pp_weight != pp_weight.pp_weight) {
			ZXIC_COMM_TRACE_DEV_ERROR(
				DEV_ID(dev),
				"dpp_tm_crdt_pp_para_set pp[0x%x] wt_pp_weight[0x%x] rd_pp_weight[0x%x]\n",
				pp_id, pp_weight.pp_weight, pp_weight_r.pp_weight);
			return DPP_ERR;
		}
	}
#endif

	/* CRDT */
	rc = dpp_tm_crdt_idle_check(dev);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_idle_check");

	pp_cfg.pp_cfg = sp_mapping;
	rc = dpp_reg_write(dev, ETM_CRDT_PP_CFGr, 0, pp_id, &pp_cfg);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	/* ， */
#if (ETM_WRITE_CHECK)
	{
		zxic_comm_delay(delay_time);
		rc = dpp_reg_read(dev, ETM_CRDT_PP_CFGr, 0, pp_id, &pp_cfg_r);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		if (pp_cfg_r.pp_cfg != pp_cfg.pp_cfg) {
			ZXIC_COMM_TRACE_DEV_ERROR(
				DEV_ID(dev),
				"dpp_tm_crdt_pp_para_set pp[0x%x] wt_pp_cfg[0x%x] rd_pp_cfg[0x%x]\n",
				pp_id, pp_cfg.pp_cfg, pp_cfg_r.pp_cfg);
			return DPP_ERR;
		}
	}
#endif

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_flow_link_wr(struct dpp_dev_t *dev, u32 flow_id,
				    struct dpp_tm_sch_flow_para_t *p_flow_para)

{
	DPP_STATUS rc = DPP_OK;
	u32 flow_id_e = 0;
	u32 c_linkid;
	u32 c_weight;
	u32 c_sp;
	u32 mode;
	u32 e_linkid;
	u32 e_weight;
	u32 e_sp;
	struct dpp_etm_crdt_flowque_para_tbl_t etm_crdt_flow_para_tbl_t = { 0 };

	/*  */
	c_linkid = p_flow_para->c_linkid;
	c_weight = p_flow_para->c_weight;
	c_sp = p_flow_para->c_sp;
	mode = p_flow_para->mode;
	e_linkid = p_flow_para->e_linkid;
	e_weight = p_flow_para->e_weight;
	e_sp = p_flow_para->e_sp;
	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_flow_para);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), c_weight, 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), e_weight, 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), c_sp, 0, DPP_TM_SCH_SP_NUM);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), e_sp, 0, DPP_TM_SCH_SP_NUM);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, 0, 1);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), flow_id, 0, DPP_ETM_Q_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), c_linkid, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), e_linkid, 0, DPP_ETM_FQSPWFQ_NUM - 1);

	/*  */

	if (mode == 1)
		flow_id_e = (flow_id + 0x2400);

	/* c */
	etm_crdt_flow_para_tbl_t.flowque_link = c_linkid;
	etm_crdt_flow_para_tbl_t.flowque_w = c_weight;
	etm_crdt_flow_para_tbl_t.flowque_pri = c_sp;

	rc = dpp_reg_write(dev, ETM_CRDT_FLOWQUE_PARA_TBLr, 0, flow_id, &etm_crdt_flow_para_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	zxic_comm_delay(5);

	/* mode-1  */
	if (mode == 1) {
		/* e */
		etm_crdt_flow_para_tbl_t.flowque_link = e_linkid;
		etm_crdt_flow_para_tbl_t.flowque_w = e_weight;
		etm_crdt_flow_para_tbl_t.flowque_pri = e_sp;

		rc = dpp_reg_write(dev, ETM_CRDT_FLOWQUE_PARA_TBLr, 0, flow_id_e,
				   &etm_crdt_flow_para_tbl_t);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	zxic_comm_delay(5);

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_flow_link_set(struct dpp_dev_t *dev, u32 flow_id, u32 c_linkid, u32 c_weight,
				     u32 c_sp, u32 mode, u32 e_linkid, u32 e_weight, u32 e_sp)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_tm_sch_flow_para_t sch_flow_para_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	/*  */
	sch_flow_para_t.c_linkid = c_linkid;
	sch_flow_para_t.c_weight = c_weight;
	sch_flow_para_t.c_sp = c_sp;
	sch_flow_para_t.mode = mode;
	sch_flow_para_t.e_linkid = e_linkid;
	sch_flow_para_t.e_weight = e_weight;
	sch_flow_para_t.e_sp = e_sp;

	rc = dpp_tm_crdt_flow_link_wr(dev, flow_id, &sch_flow_para_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_flow_link_wr");

	return DPP_OK;
}

DPP_STATUS
dpp_tm_crdt_flow_link_more_set(struct dpp_dev_t *dev, u32 flow_id_s, u32 flow_id_e, u32 c_linkid,
			       u32 c_weight, u32 c_sp, u32 mode, u32 e_linkid, u32 e_weight,
			       u32 e_sp)
{
	DPP_STATUS rc = DPP_OK;
	u32 flow_id = 0;
	struct dpp_tm_sch_flow_para_t sch_flow_para_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	if (flow_id_s > flow_id_e) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "Bad parameters!  flow_id_s > flow_id_e !\n");
		return DPP_ERR;
	}

	/*  */
	sch_flow_para_t.c_linkid = c_linkid;
	sch_flow_para_t.c_weight = c_weight;
	sch_flow_para_t.c_sp = c_sp;
	sch_flow_para_t.mode = mode;
	sch_flow_para_t.e_linkid = e_linkid;
	sch_flow_para_t.e_weight = e_weight;
	sch_flow_para_t.e_sp = e_sp;

	for (flow_id = flow_id_s; flow_id <= flow_id_e; flow_id++) {
		rc = dpp_tm_crdt_flow_link_wr(dev, flow_id, &sch_flow_para_t);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_flow_link_wr");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_se_link_wr(struct dpp_dev_t *dev, u32 se_id,
				  struct dpp_tm_sch_se_para_t *p_sch_se_para)
{
	DPP_STATUS rc = DPP_OK;
	u32 se_linkid = 0;
	u32 se_weight = 0;
	u32 se_sp = 0;
	u32 se_insw = 0; /*  */
	u32 item_num = 0; /*  */
	u32 sch_type_num = 0;
	u32 i = 0;
	struct dpp_etm_crdt_se_para_tbl_t etm_crdt_se_para_tbl_t = { 0 };

	/*  */
	se_linkid = p_sch_se_para->se_linkid;
	se_weight = p_sch_se_para->se_weight;
	se_sp = p_sch_se_para->se_sp;

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight, 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_sp, 0, DPP_TM_SCH_SP_NUM);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_insw, 0, 0);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);

	if (se_linkid > DPP_ETM_FQSPWFQ_NUM) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_linkid, DPP_TM_PP_LINKID_PORT0,
						    DPP_TM_PP_LINKID_PORT63);
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_linkid, 0,
						    DPP_ETM_FQSPWFQ_NUM - 1);
	}

	/*  */

	/* ：sp/fq/wfq，wfqx/fqx=2/4/8 */
	rc = dpp_tm_crdt_sch_type_get(dev, se_id, &item_num, &sch_type_num);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_sch_type_get");

	/* : */
	etm_crdt_se_para_tbl_t.se_link = se_linkid;
	etm_crdt_se_para_tbl_t.se_w = se_weight;
	etm_crdt_se_para_tbl_t.se_pri = se_sp;
	etm_crdt_se_para_tbl_t.se_insw = se_insw;
	etm_crdt_se_para_tbl_t.cp_token_en = 1;

	for (i = 0; i < item_num; i++) {
		rc = dpp_reg_write(dev, ETM_CRDT_SE_PARA_TBLr, 0, se_id + i,
				   &etm_crdt_se_para_tbl_t);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_se_link_set(struct dpp_dev_t *dev, u32 se_id, u32 se_linkid, u32 se_weight,
				   u32 se_sp)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_tm_sch_se_para_t sch_se_para_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	/*  */
	sch_se_para_t.se_linkid = se_linkid;
	sch_se_para_t.se_weight = se_weight;
	sch_se_para_t.se_sp = se_sp;

	rc = dpp_tm_crdt_se_link_wr(dev, se_id, &sch_se_para_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_se_link_wr");

	return DPP_OK;
}

DPP_STATUS
dpp_tm_crdt_se_link_insw_wr(struct dpp_dev_t *dev, u32 se_id,
			    struct dpp_tm_sch_se_para_insw_t *p_sch_se_para_insw)
{
	u32 rc = DPP_OK;
	u32 se_linkid; /**  id */

	u32 se_sp; /** sp,[0-3],4，, */
	u32 se_weight[8] = { 0 }; /** WFQ8[1~511]，WFQ2/4 ， */
	u32 se_insw = 1; /*  */
	u32 item_num = 1; /*  */
	u32 sch_type_num = 0;
	u32 item_num_link = 0; /*  */
	u32 sch_type_num_link = 0;
	u32 i = 0;
	struct dpp_etm_crdt_se_para_tbl_t etm_crdt_se_para_tbl_t = { 0 };

	/*  */
	se_linkid = p_sch_se_para_insw->se_linkid;
	se_sp = p_sch_se_para_insw->se_sp;
	se_weight[0] = p_sch_se_para_insw->se_weight[0];
	se_weight[1] = p_sch_se_para_insw->se_weight[1];
	se_weight[2] = p_sch_se_para_insw->se_weight[2];
	se_weight[3] = p_sch_se_para_insw->se_weight[3];
	se_weight[4] = p_sch_se_para_insw->se_weight[4];
	se_weight[5] = p_sch_se_para_insw->se_weight[5];
	se_weight[6] = p_sch_se_para_insw->se_weight[6];
	se_weight[7] = p_sch_se_para_insw->se_weight[7];

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_sp, 0, DPP_TM_SCH_SP_NUM - 5);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_insw, 1, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight[0], 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight[1], 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight[2], 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight[3], 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight[4], 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight[5], 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight[6], 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight[7], 0, DPP_TM_SCH_WEIGHT_MAX);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_linkid, 0, DPP_ETM_FQSPWFQ_NUM - 1);

	/*  */

	/* ：sp/fq/wfq，wfqx/fqx=2/4/8 */
	rc = dpp_tm_crdt_sch_type_get(dev, se_id, &item_num, &sch_type_num);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_sch_type_get");
	rc = dpp_tm_crdt_sch_type_get(dev, se_linkid, &item_num_link, &sch_type_num_link);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_sch_type_get");

	/* :，<= */
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), item_num, 1, 8);

	if (se_id % item_num != 0 || item_num > item_num_link) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			DEV_ID(dev), "dpp crdt_se_link_insw_wr NOT CORRECT,bad parameters!\n");
		return DPP_ERR;
	}

	etm_crdt_se_para_tbl_t.se_pri = se_sp;
	etm_crdt_se_para_tbl_t.se_insw = se_insw;
	etm_crdt_se_para_tbl_t.cp_token_en = 1;

	for (i = 0; i < item_num; i++) {
		etm_crdt_se_para_tbl_t.se_link = (se_linkid + i);
		etm_crdt_se_para_tbl_t.se_w = se_weight[i];

		rc = dpp_reg_write(dev, ETM_CRDT_SE_PARA_TBLr, 0, se_id + i,
				   &etm_crdt_se_para_tbl_t);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_se_link_insw_set(struct dpp_dev_t *dev, u32 se_id, u32 se_linkid,
					u32 se_weight, u32 se_sp)
{
	u32 rc = DPP_OK;
	struct dpp_tm_sch_se_para_insw_t sch_se_para_insw_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	/*  */
	sch_se_para_insw_t.se_linkid = se_linkid;
	sch_se_para_insw_t.se_sp = se_sp;
	sch_se_para_insw_t.se_weight[0] = se_weight;
	sch_se_para_insw_t.se_weight[1] = se_weight;
	sch_se_para_insw_t.se_weight[2] = se_weight;
	sch_se_para_insw_t.se_weight[3] = se_weight;
	sch_se_para_insw_t.se_weight[4] = se_weight;
	sch_se_para_insw_t.se_weight[5] = se_weight;
	sch_se_para_insw_t.se_weight[6] = se_weight;
	sch_se_para_insw_t.se_weight[7] = se_weight;

	rc = dpp_tm_crdt_se_link_insw_wr(dev, se_id, &sch_se_para_insw_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_se_link_insw_wr");

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_se_link_insw_single_set(struct dpp_dev_t *dev, u32 se_id, u32 se_linkid,
					       u32 se_weight, u32 se_sp)
{
	u32 rc = DPP_OK;
	u32 se_insw = 1; /*  */
	struct dpp_etm_crdt_se_para_tbl_t etm_crdt_se_para_tbl_t = { 0 };

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_sp, 0, DPP_TM_SCH_SP_NUM - 5);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_insw, 1, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_weight, 0, DPP_TM_SCH_WEIGHT_MAX);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_linkid, 0, DPP_ETM_FQSPWFQ_NUM - 1);

	/*  */

	/* :se_linkid1,
	 * se_weight，[1-511]
	 * se_sp:，[0-3]，
	 * se_insw 1
	 */
	etm_crdt_se_para_tbl_t.se_pri = se_sp;
	etm_crdt_se_para_tbl_t.se_insw = se_insw;
	etm_crdt_se_para_tbl_t.cp_token_en = 1;
	etm_crdt_se_para_tbl_t.se_link = se_linkid;
	etm_crdt_se_para_tbl_t.se_w = se_weight;

	rc = dpp_reg_write(dev, ETM_CRDT_SE_PARA_TBLr, 0, se_id, &etm_crdt_se_para_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_se_para_get(struct dpp_dev_t *dev, u32 se_id,
				   struct dpp_etm_crdt_se_para_tbl_t *p_se_para_tbl)
{
	DPP_STATUS rc = DPP_OK;

	/*  */
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_se_para_tbl);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);

	rc = dpp_reg_read(dev, ETM_CRDT_SE_PARA_TBLr, 0, se_id, p_se_para_tbl);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_flow_link_state_get(struct dpp_dev_t *dev, u32 flow_id, u32 *link_state)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_crdt_flowque_ins_tbl_t crdt_flow_ins_tbl_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), link_state);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), flow_id, 0, DPP_ETM_CRDT_NUM);

	rc = dpp_reg_read(dev, ETM_CRDT_FLOWQUE_INS_TBLr, 0, flow_id, &crdt_flow_ins_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*link_state = crdt_flow_ins_tbl_t.flowque_ins;

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_se_link_state_get(struct dpp_dev_t *dev, u32 se_id, u32 *link_state)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_crdt_se_ins_tbl_t crdt_se_ins_tbl_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), link_state);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);

	rc = dpp_reg_read(dev, ETM_CRDT_SE_INS_TBLr, 0, se_id, &crdt_se_ins_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*link_state = crdt_se_ins_tbl_t.se_ins_flag;

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_del_cmd_idle(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 read_times = 30;
	struct dpp_etm_crdt_flow_del_cmd_t crdt_del_cmd_busy = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	do {
		rc = dpp_reg_read(dev, ETM_CRDT_FLOW_DEL_CMDr, 0, 0, &crdt_del_cmd_busy);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		read_times--;
		zxic_comm_delay(5);
	} while ((0 != (crdt_del_cmd_busy.flow_del_busy)) && (read_times > 0));

	if (read_times == 0) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "CRDT Del command busy!\n");
		return DPP_ERR;
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_del_link_set(struct dpp_dev_t *dev, u32 id)
{
	DPP_STATUS rc = DPP_OK;
	u32 c_sta = 0;
	u32 e_sta = 0;
	u32 flow_e = 0;
	u32 link_state = 0; /**/
	u32 read_times = 300;
	u32 crdt_del_cmd_reg_index = 0;
	struct dpp_etm_crdt_flow_del_cmd_t crdt_del_cmd_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_SCH_DEL_NUM);
	flow_e = DPP_ETM_Q_NUM;

	/* 1 */
	do {
		/* ： */
		if (id <= DPP_ETM_CRDT_NUM) {
			/*  */
			rc = dpp_tm_crdt_flow_link_state_get(dev, id, &c_sta);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
							 "dpp_tm_crdt_flow_link_state_get");

			rc = dpp_tm_crdt_flow_link_state_get(dev, id + DPP_ETM_Q_NUM, &e_sta);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
							 "dpp_tm_crdt_flow_link_state_get");

			link_state = c_sta || e_sta;
		} else {
			/**/
			rc = dpp_tm_crdt_se_link_state_get(dev, id - DPP_ETM_SHAP_SEID_BASE,
							   &link_state);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
							 "dpp_tm_crdt_se_link_state_get");
		}

		if (link_state == 0)
			break;
		read_times--;
		zxic_comm_delay(1);
	} while (read_times > 0);

	if (read_times == 0) {
		ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT(id, flow_e);
		ZXIC_COMM_TRACE_ERROR(
			"id: 0x%08x ins_flag is always 1 (Maybe it's because cir equal zero) !!!\n",
			id);
		/* ，！。zhaoyan*/
	}

	/**/
	rc = dpp_tm_crdt_del_cmd_idle(dev);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_del_cmd_idle");

	/**/
	crdt_del_cmd_reg_index = ETM_CRDT_FLOW_DEL_CMDr;
	crdt_del_cmd_t.flow_alt_cmd = 1;
	crdt_del_cmd_t.flow_alt_ind = id;

	/* ：c，e */
	if (id < DPP_ETM_Q_NUM) {
		rc = dpp_reg_write(dev, crdt_del_cmd_reg_index, 0, 0, &crdt_del_cmd_t);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		/*e：*/
		rc = dpp_tm_crdt_del_cmd_idle(dev);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_del_cmd_idle");
		crdt_del_cmd_t.flow_alt_ind = (id + DPP_ETM_Q_NUM);
		rc = dpp_reg_write(dev, crdt_del_cmd_reg_index, 0, 0, &crdt_del_cmd_t);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	} else {
		rc = dpp_reg_write(dev, crdt_del_cmd_reg_index, 0, 0, &crdt_del_cmd_t);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_del_se_link_set(struct dpp_dev_t *dev, u32 id_s, u32 id_e)
{
	DPP_STATUS rc = DPP_OK;
	u32 se_id_offset = 0;
	u32 id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id_s, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id_e, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	se_id_offset = DPP_ETM_SHAP_SEID_BASE;

	if (id_s > id_e) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "Bad parameters!  id_s > id_e!\n");
		return DPP_ERR;
	}

	for (id = id_s; id <= id_e; id++) {
		ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), id, se_id_offset);
		rc = dpp_tm_crdt_del_link_set(dev, id + se_id_offset);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_del_link_set");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_del_flow_link_set(struct dpp_dev_t *dev, u32 id_s, u32 id_e)
{
	DPP_STATUS rc = DPP_OK;
	u32 id = 0;
	u32 q_td_th = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id_s, 0, DPP_ETM_CRDT_NUM);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id_e, 0, DPP_ETM_CRDT_NUM);

	if (id_s > id_e) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "Bad parameters!  id_s > id_e !\n");
		return DPP_ERR;
	}

	for (id = id_s; id <= id_e; id++) {
		rc = dpp_tm_cgavd_td_th_get(dev, QUEUE_LEVEL, id, &q_td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_td_th_get");

		if (q_td_th != 0) {
			ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
						  "queue TD_TH is not equal 0 !  q_td_th != 0 !\n");
			return DPP_ERR;
		}
	}

	for (id = id_s; id <= id_e; id++) {
		rc = dpp_tm_crdt_del_link_set(dev, id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_crdt_del_link_set");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_port_congest_en_set(struct dpp_dev_t *dev, u32 port_id, u32 port_en)
{
	DPP_STATUS rc = DPP_OK;
	u32 value = 0;
	struct dpp_etm_crdt_congest_token_disable_31_0_t disable_31_0 = { 0 };
	struct dpp_etm_crdt_congest_token_disable_63_32_t disable_63_32 = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_en, 0, 1);

	if (port_id <= 31) {
		/* port_id:[0-31] */
		rc = dpp_reg_read(dev, ETM_CRDT_CONGEST_TOKEN_DISABLE_31_0r, 0, 0, &disable_31_0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		value = disable_31_0.congest_token_disable_31_0;

		if (port_en == 0)
			value = value & (~(1u << port_id));
		else
			value = value | (1u << port_id);

		disable_31_0.congest_token_disable_31_0 = value;

		rc = dpp_reg_write(dev, ETM_CRDT_CONGEST_TOKEN_DISABLE_31_0r, 0, 0, &disable_31_0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	} else {
		/* port_id:[32-63] */
		rc = dpp_reg_read(dev, ETM_CRDT_CONGEST_TOKEN_DISABLE_63_32r, 0, 0, &disable_63_32);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		value = disable_63_32.congest_token_disable_63_32;

		if (port_en == 0)
			value = value & (~(1u << (port_id - 32)));
		else
			value = value | (1u << (port_id - 32));

		disable_63_32.congest_token_disable_63_32 = value;

		rc = dpp_reg_write(dev, ETM_CRDT_CONGEST_TOKEN_DISABLE_63_32r, 0, 0,
				   &disable_63_32);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_port_congest_en_get(struct dpp_dev_t *dev, u32 port_id, u32 *p_port_en)
{
	DPP_STATUS rc = DPP_OK;
	u32 value = 0;
	struct dpp_etm_crdt_congest_token_disable_31_0_t disable_31_0 = { 0 };
	struct dpp_etm_crdt_congest_token_disable_63_32_t disable_63_32 = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_port_en);

	if (port_id <= 31) {
		/* port_id:[0-31] */
		rc = dpp_reg_read(dev, ETM_CRDT_CONGEST_TOKEN_DISABLE_31_0r, 0, 0, &disable_31_0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		value = disable_31_0.congest_token_disable_31_0;

		*p_port_en = 1 & (value >> port_id);
	} else {
		/* port_id:[32-63] */
		rc = dpp_reg_read(dev, ETM_CRDT_CONGEST_TOKEN_DISABLE_63_32r, 0, 0, &disable_63_32);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

		value = disable_63_32.congest_token_disable_63_32;

		*p_port_en = 1 & (value >> (port_id - 32));
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_crdt_idle_check(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 read_times = 30;
	struct dpp_etm_crdt_cfg_state_t is_idle_flag = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	do {
		rc = dpp_reg_read(dev, ETM_CRDT_CFG_STATEr, 0, 0, &is_idle_flag);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		read_times--;
		zxic_comm_delay(5);

	} while ((is_idle_flag.cfg_state == 1) && (read_times > 0));

	if (read_times == 0) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "crdt rw time out\n");
		return DPP_ERR;
	}

	return DPP_OK;
}

#endif

#if ZXIC_REAL("TM_SHAPE")

DPP_STATUS dpp_tm_shape_flow_db_en_set(struct dpp_dev_t *dev, u32 db_en, u32 mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_crdt_db_token_t tm_shape_db_en_t = { 0 };
	struct dpp_etm_shap_token_mode_switch_t tm_shap_db_mode_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), db_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, 0, 1);

	tm_shape_db_en_t.db_token = db_en;
	tm_shap_db_mode_t.token_mode_switch = mode;

	rc = dpp_reg_write(dev, ETM_CRDT_DB_TOKENr, 0, 0, &tm_shape_db_en_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_write(dev, ETM_SHAP_TOKEN_MODE_SWITCHr, 0, 0, &tm_shap_db_mode_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_flow_db_en_get(struct dpp_dev_t *dev, u32 *db_en, u32 *mode)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_crdt_db_token_t tm_shape_db_en_t = { 0 };
	struct dpp_etm_shap_token_mode_switch_t tm_shap_db_mode_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), db_en);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), mode);

	rc = dpp_reg_read(dev, ETM_CRDT_DB_TOKENr, 0, 0, &tm_shape_db_en_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	rc = dpp_reg_read(dev, ETM_SHAP_TOKEN_MODE_SWITCHr, 0, 0, &tm_shap_db_mode_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*db_en = tm_shape_db_en_t.db_token;
	*mode = tm_shap_db_mode_t.token_mode_switch;

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_token_grain_get(struct dpp_dev_t *dev, u32 *token_grain)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_shap_token_grain_t tm_shape_token_grain_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), token_grain);

	rc = dpp_reg_read(dev, ETM_SHAP_TOKEN_GRAINr, 0, 0, &tm_shape_token_grain_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*token_grain = tm_shape_token_grain_t.token_grain;

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_map_table_set(struct dpp_dev_t *dev, u32 id, u32 profile_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_shap_shap_bucket_map_tbl_t tm_shape_map_tbl_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), profile_id, 0, 127);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_SCH_DEL_NUM);

	tm_shape_map_tbl_t.shap_map = profile_id;

	rc = dpp_reg_write(dev, ETM_SHAP_SHAP_BUCKET_MAP_TBLr, 0, id, &tm_shape_map_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_map_table_get(struct dpp_dev_t *dev, u32 id, u32 *profile_id)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_etm_shap_shap_bucket_map_tbl_t tm_shape_map_tbl_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), profile_id);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), id, 0, DPP_ETM_SCH_DEL_NUM);

	rc = dpp_reg_read(dev, ETM_SHAP_SHAP_BUCKET_MAP_TBLr, 0, id, &tm_shape_map_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	*profile_id = tm_shape_map_tbl_t.shap_map;

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_find_map_id(struct dpp_dev_t *dev, u32 id, u32 cir, u32 cbs)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;
	u32 table_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 2);

	/* id：2K128 */
	table_id = id / 2048;

	for (i = 1; i < 128; i++) {
		if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i].shape_cir == cir &&
		    g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i].shape_cbs == cbs) {
			rc = dpp_tm_shape_map_table_set(dev, id, i);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
							 "dpp_tm_shape_map_table_set");
			g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i].shape_num++;

			return 1;
		}
	}

	return 0;
}

DPP_STATUS dpp_tm_shape_flow_para_set(struct dpp_dev_t *dev, u32 flow_id, u32 cir, u32 cbs,
				      u32 db_en, u32 eir, u32 ebs)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);

	rc = dpp_etm_shape_flow_para_set(dev, flow_id, cir, cbs, db_en, eir, ebs);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_etm_shape_flow_para_set");

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_flow_para_get(struct dpp_dev_t *dev, u32 flow_id, u32 mode, u32 *p_para_id,
				      struct dpp_tm_shape_para *p_flow_para_tbl)
{
	DPP_STATUS rc = DPP_OK;
	u32 flow_id_e = 0;
	u32 table_id = 0;
	u32 profile_id = 0;
	u32 bucket_para_n = 0;
	u32 bucket_depth = 0; /* ， */
	u32 bucket_rate = 0; /* ，4096 */
	u32 token_grain = 0; /*  */
	u32 token_grain_kb[8] = { 128, 64, 32, 16, 8, 4, 2, 1 }; /*  */
	struct dpp_etm_shap_bkt_para_tbl_t shap_para_tbl_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, 0, 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_flow_para_tbl);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), flow_id, 0, DPP_ETM_Q_NUM - 1);

	flow_id_e = flow_id + DPP_ETM_Q_NUM;

	table_id = flow_id / 2048;

	/*profile_id*/
	if (mode) {
		table_id = flow_id_e / 2048;
		rc = dpp_tm_shape_map_table_get(dev, flow_id_e, &profile_id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get");
	} else {
		rc = dpp_tm_shape_map_table_get(dev, flow_id, &profile_id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get");
	}

	/**/
	bucket_para_n = table_id * 128 + profile_id;

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), bucket_para_n, 0, 0xAFF);

	rc = dpp_reg_read(dev, ETM_SHAP_BKT_PARA_TBLr, 0, bucket_para_n, &shap_para_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	bucket_depth = shap_para_tbl_t.bucket_depth;
	bucket_rate = shap_para_tbl_t.bucket_rate;

	/**/
	rc = dpp_tm_shape_token_grain_get(dev, &token_grain);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_token_grain_get");
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_grain, 0, 7);

	*p_para_id = bucket_para_n;
	p_flow_para_tbl->shape_cbs = bucket_depth * token_grain_kb[token_grain];
	p_flow_para_tbl->shape_cir =
		(u64)bucket_rate * DPP_TM_SYS_HZ * 8 / ((u64)4096 * DPP_TM_KILO_ULL * 64);

	return DPP_OK;
}

DPP_STATUS dpp_etm_shape_flow_para_set(struct dpp_dev_t *dev, u32 flow_id, u32 cir, u32 cbs,
				       u32 db_en, u32 eir, u32 ebs)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;
	u32 table_id = 0;
	u32 profile_id = 0;
	u32 total_para_id = 0;
	u32 get_profile_success_flag_c = 0; /*  */
	u32 get_profile_success_flag_e = 0; /*  */

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 2);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), flow_id, 0, DPP_ETM_Q_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), cir, DPP_TM_SHAPE_CIR_MIN,
					    DPP_TM_SHAPE_CIR_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), cbs, DPP_TM_SHAPE_CBS_MIN,
					    DPP_TM_SHAPE_CBS_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), db_en, 0, 1);

	if (db_en) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), eir, DPP_TM_SHAPE_CIR_MIN,
						    DPP_TM_SHAPE_CIR_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), ebs, DPP_TM_SHAPE_CBS_MIN,
						    DPP_TM_SHAPE_CBS_MAX);
	}

	rc = dpp_tm_global_var_mutex_init();
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_global_var_mutex_init");

	rc = zxic_comm_mutex_lock(&g_dpp_tm_global_var_rw_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	/****/
	rc = dpp_tm_shape_flow_db_en_set(dev, db_en, 0);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_tm_shape_flow_db_en_set",
						&g_dpp_tm_global_var_rw_mutex);

	/******STEP1:profile_id******/
	/**c**/
	rc = dpp_tm_shape_map_table_get(dev, flow_id, &profile_id);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get",
						&g_dpp_tm_global_var_rw_mutex);

	if (profile_id > 0 && (profile_id < DPP_TM_SHAP_MAP_ID_MAX)) {
		/***: id：2K128***/
		table_id = flow_id / 2048;

		if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
		    .shape_num != 0) {
			g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
				.shape_num--;

			if (0 ==
			    g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
				    .shape_num) {
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
					.shape_cbs = 0;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
					.shape_cir = 0;
			}
		}
	}

	/**e**/
	rc = dpp_tm_shape_map_table_get(dev, (flow_id + DPP_ETM_Q_NUM), &profile_id);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get",
						&g_dpp_tm_global_var_rw_mutex);

	if (profile_id > 0 && (profile_id < DPP_TM_SHAP_MAP_ID_MAX)) {
		/**/
		table_id = (flow_id + DPP_ETM_Q_NUM) / 2048;

		if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
		    .shape_num != 0) {
			g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
				.shape_num--;

			if (0 ==
			    g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
				    .shape_num) {
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
					.shape_cbs = 0;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
					.shape_cir = 0;
			}
		}
	}

	/******STEP2:******/
	if (cbs == 0) {
		/*ce,*/
		rc = dpp_tm_shape_map_table_set(dev, (flow_id), 0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
							"dpp_tm_shape_map_table_set",
							&g_dpp_tm_global_var_rw_mutex);
		rc = dpp_tm_shape_map_table_set(dev, (flow_id + DPP_ETM_Q_NUM), 0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
							"dpp_tm_shape_map_table_set",
							&g_dpp_tm_global_var_rw_mutex);

		rc = zxic_comm_mutex_unlock(&g_dpp_tm_global_var_rw_mutex);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_OK;
	}

	if (ebs == 0 || db_en == 0) {
		/*e*/
		rc = dpp_tm_shape_map_table_set(dev, (flow_id + DPP_ETM_Q_NUM), 0);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
							"dpp_tm_shape_map_table_set",
							&g_dpp_tm_global_var_rw_mutex);
		get_profile_success_flag_e = 1;
	}

	/******STEP3:,******/
	/*  :c */
	if (ebs == 0) {
		/* cbs>0，c：cprofile */
		rc = dpp_tm_shape_find_map_id(dev, flow_id, cir, cbs);

		if (rc)
			get_profile_success_flag_c = 1;
		else
			get_profile_success_flag_c = 0;

	} else {
		/* cbs>0,ebs>0：cprofile */
		rc = dpp_tm_shape_find_map_id(dev, flow_id, cir, cbs);

		if (rc)
			get_profile_success_flag_c = 1;
		else
			get_profile_success_flag_c = 0;

		/* eprofile */
		rc = dpp_tm_shape_find_map_id(dev, flow_id + DPP_ETM_Q_NUM, eir, ebs);

		if (rc)
			get_profile_success_flag_e = 1;
		else
			get_profile_success_flag_e = 0;
	}

	/******STEP4:profile******/
	if (!get_profile_success_flag_c) {
		/* id：2K128 */
		table_id = flow_id / 2048;

		for (i = 1; i < 128; i++) {
			if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i].shape_num ==
			    0) {
				/**********id********/
				rc = dpp_tm_shape_map_table_set(dev, flow_id, i);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_map_table_set",
					&g_dpp_tm_global_var_rw_mutex);

				/*****************/
				total_para_id = table_id * 128 + i;
				rc = dpp_tm_shape_para_set(dev, total_para_id, cir, cbs);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_para_set",
					&g_dpp_tm_global_var_rw_mutex);

				/**************/
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_cir = cir;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_cbs = cbs;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_num++;

				get_profile_success_flag_c = 1;
				break;
			}
		}
	}

	if (!get_profile_success_flag_e && ebs) {
		/* id：2K128 */
		table_id = (flow_id + DPP_ETM_Q_NUM) / 2048;

		for (i = 1; i < 128; i++) {
			if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i].shape_num ==
			    0) {
				/**********id********/
				rc = dpp_tm_shape_map_table_set(dev, (flow_id + DPP_ETM_Q_NUM), i);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_map_table_set",
					&g_dpp_tm_global_var_rw_mutex);

				/*****************/
				total_para_id = table_id * 128 + i;
				rc = dpp_tm_shape_para_set(dev, total_para_id, eir, ebs);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_para_set",
					&g_dpp_tm_global_var_rw_mutex);

				/**************/
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_cir = eir;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_cbs = ebs;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_num++;

				get_profile_success_flag_e = 1;
				break;
			}
		}
	}

	if (!get_profile_success_flag_c || !get_profile_success_flag_e) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "Failure!  Profile resource are FULL!\n");
		rc = zxic_comm_mutex_unlock(&g_dpp_tm_global_var_rw_mutex);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

		return DPP_ERR;
	}

	rc = zxic_comm_mutex_unlock(&g_dpp_tm_global_var_rw_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_se_para_set(struct dpp_dev_t *dev, u32 se_id, u32 pir, u32 pbs, u32 db_en,
				    u32 cir, u32 cbs)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);

	rc = dpp_etm_shape_se_para_set(dev, se_id, pir, pbs, db_en, cir, cbs);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_etm_shape_se_para_set");

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_se_para_get(struct dpp_dev_t *dev, u32 se_id, u32 mode, u32 *p_para_id,
				    struct dpp_tm_shape_para *p_se_para_tbl)
{
	DPP_STATUS rc = DPP_OK;
	u32 real_se_id = 0;
	u32 se_id_c = 0;
	u32 table_id = 0;
	u32 profile_id = 0;
	u32 bucket_para_n = 0;
	u32 bucket_depth = 0; /* ， */
	u32 bucket_rate = 0; /* ，4096 */
	u32 token_grain = 0; /*  */
	u32 token_grain_kb[8] = { 128, 64, 32, 16, 8, 4, 2, 1 }; /*  */
	struct dpp_etm_shap_bkt_para_tbl_t shap_para_tbl_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, 0, 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para_id);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_se_para_tbl);

	real_se_id = (se_id + DPP_ETM_SHAP_SEID_BASE);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), real_se_id, 0, DPP_ETM_SCH_DEL_NUM);

	se_id_c = real_se_id + 4;

	table_id = real_se_id / 2048;

	/*profile_id*/
	if (mode) {
		rc = dpp_tm_shape_map_table_get(dev, se_id_c, &profile_id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get");
	} else {
		rc = dpp_tm_shape_map_table_get(dev, real_se_id, &profile_id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get");
	}

	/**/
	bucket_para_n = table_id * 128 + profile_id;

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), bucket_para_n, 0, 0xAFF);

	rc = dpp_reg_read(dev, ETM_SHAP_BKT_PARA_TBLr, 0, bucket_para_n, &shap_para_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	bucket_depth = shap_para_tbl_t.bucket_depth;
	bucket_rate = shap_para_tbl_t.bucket_rate;

	/**/
	rc = dpp_tm_shape_token_grain_get(dev, &token_grain);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_token_grain_get");
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_grain, 0, 7);

	*p_para_id = bucket_para_n;
	p_se_para_tbl->shape_cbs = bucket_depth * token_grain_kb[token_grain];
	p_se_para_tbl->shape_cir =
		(u64)bucket_rate * DPP_TM_SYS_HZ * 8 / ((u64)4096 * DPP_TM_KILO_ULL * 64);

	return DPP_OK;
}

DPP_STATUS dpp_etm_shape_se_para_set(struct dpp_dev_t *dev, u32 se_id, u32 pir, u32 pbs, u32 db_en,
				     u32 cir, u32 cbs)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;
	u32 real_se_id = 0;
	u32 sch_type = 0;
	u32 sch_type_num = 0;
	u32 table_id = 0;
	u32 profile_id = 0;
	u32 total_para_id = 0;
	u32 get_profile_success_flag_p = 0; /* p */
	u32 get_profile_success_flag_c = 0; /* c */
	struct dpp_etm_crdt_se_para_tbl_t crdt_se_para_tabl_t = { 0 }; /*cp,FQ8/WFQ8*/

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 2);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), pir, DPP_TM_SHAPE_CIR_MIN,
					    DPP_TM_SHAPE_CIR_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), pbs, DPP_TM_SHAPE_CBS_MIN,
					    DPP_TM_SHAPE_CBS_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), db_en, 0, 1);

	real_se_id = (se_id + DPP_ETM_SHAP_SEID_BASE);

	if (db_en) {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), cir, DPP_TM_SHAPE_CIR_MIN,
						    DPP_TM_SHAPE_CIR_MAX);
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), cbs, DPP_TM_SHAPE_CBS_MIN,
						    DPP_TM_SHAPE_CBS_MAX);
	}

	rc = dpp_tm_global_var_mutex_init();
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_global_var_mutex_init");

	rc = zxic_comm_mutex_lock(&g_dpp_tm_global_var_rw_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	rc = dpp_tm_crdt_sch_type_get(dev, se_id, &sch_type, &sch_type_num);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_tm_crdt_sch_type_get",
						&g_dpp_tm_global_var_rw_mutex);

	/**:crdtse_id**/
	if (sch_type == 8) {
		for (i = 0; i < 8; i++) {
			rc = dpp_reg_read(dev, ETM_CRDT_SE_PARA_TBLr, 0, se_id + i,
					  &crdt_se_para_tabl_t);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_reg_read",
								&g_dpp_tm_global_var_rw_mutex);

			crdt_se_para_tabl_t.cp_token_en = db_en;

			rc = dpp_reg_write(dev, ETM_CRDT_SE_PARA_TBLr, 0, se_id + i,
					   &crdt_se_para_tabl_t);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_reg_write",
								&g_dpp_tm_global_var_rw_mutex);
		}
	}

	/******STEP1:profile_id******/
	/**p**/
	rc = dpp_tm_shape_map_table_get(dev, real_se_id, &profile_id);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get",
						&g_dpp_tm_global_var_rw_mutex);

	if (profile_id > 0 && (profile_id < DPP_TM_SHAP_MAP_ID_MAX)) {
		/***: id：2K128***/
		table_id = real_se_id / 2048;

		if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
			.shape_num != 0) {
			g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
				.shape_num--;
		}
	}

	if (sch_type == 8) {
		/**c**/
		rc = dpp_tm_shape_map_table_get(dev, (real_se_id + 4), &profile_id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
							"dpp_tm_shape_map_table_get",
							&g_dpp_tm_global_var_rw_mutex);

		if (profile_id > 0 && (profile_id < DPP_TM_SHAP_MAP_ID_MAX)) {
			/**/
			table_id = (real_se_id + 4) / 2048;

			if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
				    .shape_num != 0) {
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id]
					.shape_num--;
			}
		}
	}

	/******STEP2:******/
	if (sch_type < 8) {
		/**FQ8/WFQ8：**/
		if (pbs == 0) {
			/*p,*/
			rc = dpp_tm_shape_map_table_set(dev, (real_se_id), 0);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
								"dpp_tm_shape_map_table_set",
								&g_dpp_tm_global_var_rw_mutex);

			rc = zxic_comm_mutex_unlock(&g_dpp_tm_global_var_rw_mutex);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

			return DPP_OK;
		}
	} else {
		/**FQ8/WFQ8：**/
		if (pbs == 0 && db_en == 0) {
			/*：p,*/
			rc = dpp_tm_shape_map_table_set(dev, (real_se_id), 0);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
								"dpp_tm_shape_map_table_set",
								&g_dpp_tm_global_var_rw_mutex);

			rc = zxic_comm_mutex_unlock(&g_dpp_tm_global_var_rw_mutex);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

			return DPP_OK;
		}

		if (pbs == 0 && db_en == 1 && cbs == 0) {
			/*：p+c，*/
			rc = dpp_tm_shape_map_table_set(dev, (real_se_id), 0);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
								"dpp_tm_shape_map_table_set",
								&g_dpp_tm_global_var_rw_mutex);
			rc = dpp_tm_shape_map_table_set(dev, (real_se_id + 4), 0);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
								"dpp_tm_shape_map_table_set",
								&g_dpp_tm_global_var_rw_mutex);

			rc = zxic_comm_mutex_unlock(&g_dpp_tm_global_var_rw_mutex);
			ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

			return DPP_OK;
		}
	}

	/******STEP3:,******/
	/* FQ8/WFQ8：p，cflag1 */
	if (sch_type < 8) {
		/* pprofile */
		rc = dpp_tm_shape_find_map_id(dev, real_se_id, pir, pbs);

		if (rc)
			get_profile_success_flag_p = 1;
		else
			get_profile_success_flag_p = 0;

		get_profile_success_flag_c = 1;
	} else {
		/* FQ8/WFQ8：p+c */
		if (db_en == 0) {
			/* ：pprofile */
			rc = dpp_tm_shape_find_map_id(dev, real_se_id, pir, pbs);

			if (rc)
				get_profile_success_flag_p = 1;
			else
				get_profile_success_flag_p = 0;

			get_profile_success_flag_c = 1;
		} else {
			/* ：pprofile */
			if (pbs == 0) {
				rc = dpp_tm_shape_map_table_set(dev, real_se_id, 0);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_map_table_set",
					&g_dpp_tm_global_var_rw_mutex);

				get_profile_success_flag_p = 1;
			} else {
				rc = dpp_tm_shape_find_map_id(dev, real_se_id, pir, pbs);

				if (rc)
					get_profile_success_flag_p = 1;
				else
					get_profile_success_flag_p = 0;
			}

			/* cprofile */
			if (cbs == 0) {
				rc = dpp_tm_shape_map_table_set(dev, (real_se_id + 4), 0);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_map_table_set",
					&g_dpp_tm_global_var_rw_mutex);

				get_profile_success_flag_c = 1;
			} else {
				rc = dpp_tm_shape_find_map_id(dev, (real_se_id + 4), cir, cbs);

				if (rc)
					get_profile_success_flag_c = 1;
				else
					get_profile_success_flag_c = 0;
			}
		}
	}

	/******STEP4:profile******/
	if (!get_profile_success_flag_p) {
		/* id：2K128 */
		table_id = real_se_id / 2048;

		for (i = 1; i < 128; i++) {
			if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i].shape_num ==
			    0) {
				/**********id********/
				rc = dpp_tm_shape_map_table_set(dev, real_se_id, i);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_map_table_set",
					&g_dpp_tm_global_var_rw_mutex);

				/*****************/
				total_para_id = table_id * 128 + i;
				rc = dpp_tm_shape_para_set(dev, total_para_id, pir, pbs);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_para_set",
					&g_dpp_tm_global_var_rw_mutex);

				/**************/
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_cir = pir;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_cbs = pbs;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_num++;

				get_profile_success_flag_p = 1;
				break;
			}
		}
	}

	if (!get_profile_success_flag_c) {
		/* id：2K128 */
		table_id = (real_se_id + 4) / 2048;

		for (i = 1; i < 128; i++) {
			if (g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i].shape_num ==
			    0) {
				/**********id********/
				rc = dpp_tm_shape_map_table_set(dev, (real_se_id + 4), i);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_map_table_set",
					&g_dpp_tm_global_var_rw_mutex);

				/*****************/
				total_para_id = table_id * 128 + i;
				rc = dpp_tm_shape_para_set(dev, total_para_id, cir, cbs);
				ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(
					DEV_ID(dev), rc, "dpp_tm_shape_para_set",
					&g_dpp_tm_global_var_rw_mutex);

				/**************/
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_cir = cir;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_cbs = cbs;
				g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][i]
					.shape_num++;

				get_profile_success_flag_c = 1;
				break;
			}
		}
	}

	if (!get_profile_success_flag_p || !get_profile_success_flag_c) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "Failure!  Profile resource are FULL!\n");

		rc = zxic_comm_mutex_unlock(&g_dpp_tm_global_var_rw_mutex);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_ERR;
	}

	rc = zxic_comm_mutex_unlock(&g_dpp_tm_global_var_rw_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_para_set(struct dpp_dev_t *dev, u32 total_para_id, u32 cir, u32 cbs)
{
	DPP_STATUS rc = DPP_OK;
	u32 bucket_depth = 0; /* ， */
	u32 bucket_rate = 0; /* ，4096 */
	u32 token_grain = 0; /*  */
	u32 token_grain_kb[8] = { 128, 64, 32, 16, 8, 4, 2, 1 }; /*  */
	struct dpp_etm_shap_bkt_para_tbl_t shap_para_tbl_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), cir, DPP_TM_SHAPE_CIR_MIN,
					    DPP_TM_SHAPE_CIR_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), cbs, DPP_TM_SHAPE_CBS_MIN,
					    DPP_TM_SHAPE_CBS_MAX);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), total_para_id, 0, 0xAFF);

	/********* :Begin ********/

	rc = dpp_tm_shape_token_grain_get(dev, &token_grain);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_token_grain_get");
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_grain, 0, 7);

	if (cbs < token_grain_kb[token_grain] && (cbs != 0))
		bucket_depth = 1; /* 1 */
	else
		bucket_depth = cbs / token_grain_kb[token_grain];

	if (bucket_depth > DPP_TM_SHAPE_CBS_REG_MAX)
		bucket_depth = DPP_TM_SHAPE_CBS_REG_MAX;

	bucket_rate = (u64)4096 * cir * DPP_TM_KILO_ULL * 64 / ((u64)DPP_TM_SYS_HZ * 8);
	shap_para_tbl_t.bucket_rate = bucket_rate;
	shap_para_tbl_t.bucket_depth = bucket_depth;

	rc = dpp_reg_write(dev, ETM_SHAP_BKT_PARA_TBLr, 0, total_para_id, &shap_para_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_para_get(struct dpp_dev_t *dev, u32 total_para_id,
				 struct dpp_tm_shape_para *p_shap_para_tbl)
{
	DPP_STATUS rc = DPP_OK;
	u32 token_grain = 0; /*  */
	u32 token_grain_kb[8] = { 128, 64, 32, 16, 8, 4, 2, 1 }; /*  */
	struct dpp_etm_shap_bkt_para_tbl_t shap_para_tbl_t = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_shap_para_tbl);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), total_para_id, 0, 0xAFF);

	/**/
	rc = dpp_reg_read(dev, ETM_SHAP_BKT_PARA_TBLr, 0, total_para_id, &shap_para_tbl_t);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	/********* : ********/
	rc = dpp_tm_shape_token_grain_get(dev, &token_grain);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_token_grain_get");
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), token_grain, 0, 7);

	p_shap_para_tbl->shape_cbs = shap_para_tbl_t.bucket_depth * token_grain_kb[token_grain];
	p_shap_para_tbl->shape_cir = (u64)shap_para_tbl_t.bucket_rate * DPP_TM_SYS_HZ * 8 /
				     ((u64)4096 * DPP_TM_KILO_ULL * 64);

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_pp_para_set(struct dpp_dev_t *dev, u32 port_id,
				    const struct dpp_tm_shape_pp_para_t *p_para)
{
	DPP_STATUS rc = DPP_OK;
	u32 cir = 0; /*  */
	u32 cbs = 0; /* Credit */
	u32 qmu_credit_value = 0;
	struct dpp_etm_crdt_pp_weight_ram_t pp_weight = { 0 };
	struct dpp_etm_crdt_pp_cbs_shape_en_ram_t pp_cbs_shape_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), p_para->c_en, 0, 1);

	if (p_para->c_en == 0) {
		rc = dpp_reg_read(dev, ETM_CRDT_PP_CBS_SHAPE_EN_RAMr, 0, port_id, &pp_cbs_shape_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");
		pp_cbs_shape_en.pp_c_shap_en = p_para->c_en;
		rc = dpp_reg_write(dev, ETM_CRDT_PP_CBS_SHAPE_EN_RAMr, 0, port_id,
				   &pp_cbs_shape_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	} else {
		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), p_para->cir, DPP_TM_SHAPE_CIR_MIN,
						    DPP_TM_SHAPE_CIR_MAX);

		rc = dpp_tm_qmu_credit_value_get(dev, &qmu_credit_value);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_qmu_credit_value_get");

		cir = p_para->cir;
		cir = (u32)(((u64)cir * DPP_TM_KILO_ULL) / DPP_TM_SHAPE_CIR_STEP);

		if (cir > 0x3FFFFFE)
			cir = 0x3FFFFFE;

		if (qmu_credit_value != 0) {
			cbs = p_para->cbs;
			cbs = cbs * DPP_TM_KILO_UL / qmu_credit_value;
		}

		if (cbs < DPP_TM_SHAPE_DEFAULT_CBS)
			cbs = DPP_TM_SHAPE_DEFAULT_CBS;

		ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), cbs, DPP_TM_SHAPE_DEFAULT_CBS,
						    0x1ffff);

		pp_cbs_shape_en.pp_cbs = cbs;
		pp_weight.pp_c_weight = cir;
		pp_cbs_shape_en.pp_c_shap_en = p_para->c_en;

		rc = dpp_reg_write(dev, ETM_CRDT_PP_WEIGHT_RAMr, 0, port_id, &pp_weight);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");

		rc = dpp_reg_write(dev, ETM_CRDT_PP_CBS_SHAPE_EN_RAMr, 0, port_id,
				   &pp_cbs_shape_en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_pp_para_get(struct dpp_dev_t *dev, u32 port_id,
				    struct dpp_tm_shape_pp_para_t *p_para)
{
	DPP_STATUS rc = DPP_OK;
	u32 cbs = 0;
	u32 cir = 0;
	u32 qmu_credit_value = 0;

	struct dpp_etm_crdt_pp_weight_ram_t pp_weight = { 0 };
	struct dpp_etm_crdt_pp_cbs_shape_en_ram_t pp_cbs_shape_en = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);

	rc = dpp_tm_qmu_credit_value_get(dev, &qmu_credit_value);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_qmu_credit_value_get");

	rc = dpp_reg_read(dev, ETM_CRDT_PP_WEIGHT_RAMr, 0, port_id, &pp_weight);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	rc = dpp_reg_read(dev, ETM_CRDT_PP_CBS_SHAPE_EN_RAMr, 0, port_id, &pp_cbs_shape_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_reg_read");

	cbs = pp_cbs_shape_en.pp_cbs;
	cir = pp_weight.pp_c_weight;
	p_para->c_en = pp_cbs_shape_en.pp_c_shap_en;
	p_para->cir = (u32)((u64)cir * DPP_TM_SHAPE_CIR_STEP / DPP_TM_KILO_ULL);
	p_para->cbs = (cbs * qmu_credit_value / DPP_TM_KILO_UL);

	return DPP_OK;
}

DPP_STATUS dpp_tm_shape_pp_para_wr(struct dpp_dev_t *dev, u32 port_id, u32 cir, u32 cbs, u32 c_en)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_tm_shape_pp_para_t para = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), c_en, 0, 1);

	para.cir = cir;
	para.cbs = cbs;
	para.c_en = c_en;

	rc = dpp_tm_shape_pp_para_set(dev, port_id, &para);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_pp_para_set");

	return DPP_OK;
}

DPP_STATUS
dpp_tm_shape_flow_para_array_get(struct dpp_dev_t *dev, u32 flow_id, u32 mode,
				 struct dpp_tm_shape_para *p_flow_para_tbl)
{
	DPP_STATUS rc = DPP_OK;
	u32 flow_id_e = 0;
	u32 table_id = 0;
	u32 profile_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), mode, 0, 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_flow_para_tbl);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), flow_id, 0, DPP_ETM_Q_NUM - 1);

	flow_id_e = flow_id + DPP_ETM_Q_NUM;

	table_id = flow_id / 2048;

	/*profile_id*/
	if (mode) {
		table_id = flow_id_e / 2048;
		rc = dpp_tm_shape_map_table_get(dev, flow_id_e, &profile_id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get");
	} else {
		rc = dpp_tm_shape_map_table_get(dev, flow_id, &profile_id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_shape_map_table_get");
	}

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), profile_id, 0, DPP_TM_SHAP_MAP_ID_MAX - 1);

	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), table_id, 0,
					    DPP_ETM_SHAP_TABEL_ID_MAX - 1);
	p_flow_para_tbl->shape_cbs =
		g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id].shape_cbs;
	p_flow_para_tbl->shape_cir =
		g_dpp_etm_shape_para_table[DEV_PCIE_SLOT(dev)][table_id][profile_id].shape_cir;

	return DPP_OK;
}
#endif

#if ZXIC_REAL("TM_EXTEND_API")

DPP_STATUS dpp_tm_cgavd_td_th_together_wr(struct dpp_dev_t *dev, u32 level, u32 id, u32 td_th,
					  u32 num)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, PP_LEVEL);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), id, num);

	for (i = 0; i < num; i++) {
		rc = dpp_tm_cgavd_td_th_set(dev, level, id + i, td_th);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_td_th_set");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_td_th_together_get(struct dpp_dev_t *dev, u32 level, u32 id, u32 num)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;
	u32 td_th = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, PP_LEVEL);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), id, num);

	for (i = 0; i < num; i++) {
		rc = dpp_tm_cgavd_td_th_get(dev, level, id + i, &td_th);
		zxic_comm_delay(5);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_td_th_get");

		ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), id, i);
		if (level == QUEUE_LEVEL)
			ZXIC_COMM_PRINT("   flow_id: 0x%x,   td_th: 0x%x\n", id + i, td_th);
		else
			ZXIC_COMM_PRINT("   pp_id: 0x%x,   td_th: 0x%x\n", id + i, td_th);
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_cgavd_dyn_th_en_set_more(struct dpp_dev_t *dev, enum dpp_tm_cgavd_level_e level,
					   u32 id, u32 en, u32 num)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), level, QUEUE_LEVEL, PP_LEVEL);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(DEV_ID(dev), id, num);

	for (i = 0; i < num; i++) {
		rc = dpp_tm_cgavd_dyn_th_en_set(dev, level, id + i, en);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_tm_cgavd_dyn_th_en_set");
	}

	return DPP_OK;
}

DPP_STATUS dpp_tm_clr_shape_para(struct dpp_dev_t *dev)
{
	memset(g_dpp_etm_shape_para_table, 0, sizeof(g_dpp_etm_shape_para_table));

	return DPP_OK;
}
#endif
