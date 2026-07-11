// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_reg.h"
#include "dpp_pbu_api.h"
#include "dpp_pbu.h"
#include "dpp_dev.h"

#define MF_MAX_BIT (4095)
#define MF_START_BIT (2047)
#define PKT_MAX_BIT (2047)
#define CAP_MAX_NUM (64)
#define PKT_BUFF_NUM (128)
#define PKT_BUF_SIZE (32)
DPP_STATUS dpp_pbu_port_th_set(struct dpp_dev_t *dev, u32 port_id,
			       struct dpp_pbu_port_th_para_t *p_para)
{
	DPP_STATUS rc = 0;
	u32 *p_data = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), port_id, 0, DPP_PBU_PORT_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->lif_th, 0, DPP_PBU_PORT_TH_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->lif_prv, 0, DPP_PBU_PORT_TH_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_prv, 0, DPP_PBU_PORT_TH_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_th_cos7, 0, DPP_PBU_PORT_TH_MAX);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_th_cos6, 0, p_para->idma_th_cos7);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_th_cos5, 0, p_para->idma_th_cos6);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_th_cos4, 0, p_para->idma_th_cos5);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_th_cos3, 0, p_para->idma_th_cos4);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_th_cos2, 0, p_para->idma_th_cos3);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_th_cos1, 0, p_para->idma_th_cos2);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->idma_th_cos0, 0, p_para->idma_th_cos1);

	p_data = (u32 *)p_para;

	rc = dpp_reg_write(dev, NPPU_PBU_CFG_MEMID_0_PBU_FC_IDMATH_RAMr, 0, port_id, p_data);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_pbu_port_th_get(struct dpp_dev_t *dev, u32 port_id,
			       struct dpp_pbu_port_th_para_t *p_para)
{
	DPP_STATUS rc = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), port_id, 0, DPP_PBU_PORT_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para);

	rc = dpp_reg_read(dev, NPPU_PBU_CFG_MEMID_0_PBU_FC_IDMATH_RAMr, 0, port_id, (u32 *)p_para);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	return DPP_OK;
}
DPP_STATUS dpp_pbu_port_cos_th_set(struct dpp_dev_t *dev, u32 port_id,
				   struct dpp_pbu_port_cos_th_para_t *p_para)
{
	DPP_STATUS rc = 0;
	u32 i = 0;
	u32 tmp_index = 0;
	u32 *p_data = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), port_id, 0, DPP_PBU_PORT_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para);

	if (port_id < DPP_PBU_LIF1_PORT_NUM) {
		tmp_index = port_id;

	} else if (port_id == DPP_PBU_TM_LOOP_PORT_NUM) {
		tmp_index = 56;

	} else {
		ZXIC_COMM_TRACE_DEV_ERROR(
			DEV_ID(dev), "dpp pbu_port_cos_th_set: please check input port:%d !!!!!!\n",
			port_id);
		return DPP_OK;
	}

	for (i = 0; i < DPP_PBU_COS_NUM; i++) {
		if (i == 0) {
			ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->cos_th[i], 0,
						  DPP_PBU_PORT_COS_MAX_TH);
		} else {
			ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_para->cos_th[i],
						  p_para->cos_th[i - 1], DPP_PBU_PORT_COS_MAX_TH);
		}
	}

	p_data = (u32 *)p_para;

	rc = dpp_reg_write(dev, NPPU_PBU_CFG_MEMID_1_PBU_FC_MACTH_RAMr, 0, tmp_index, p_data);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_pbu_port_cos_th_get(struct dpp_dev_t *dev, u32 port_id,
				   struct dpp_pbu_port_cos_th_para_t *p_para)
{
	DPP_STATUS rc = 0;
	u32 tmp_index = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), port_id, 0, DPP_PBU_PORT_NUM - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para);

	if (port_id < DPP_PBU_LIF1_PORT_NUM)
		tmp_index = port_id;
	else if (port_id == DPP_PBU_TM_LOOP_PORT_NUM)
		tmp_index = 56;
	else
		return DPP_OK;

	rc = dpp_reg_read(dev, NPPU_PBU_CFG_MEMID_1_PBU_FC_MACTH_RAMr, 0, tmp_index, (u32 *)p_para);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	return DPP_OK;
}
DPP_STATUS dpp_pbu_pfc_delay_time_set(struct dpp_dev_t *dev, u64 delayTime)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_nppu_pbu_cfg_cfg_pfc_rdy_high_time_t pbuDelayHighTime = { 0 };
	struct dpp_nppu_pbu_cfg_cfg_pfc_rdy_low_time_t pbuDelayLowTime = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	pbuDelayHighTime.cfg_pfc_rdy_high_time = (u32)(delayTime >> 32);
	pbuDelayLowTime.cfg_pfc_rdy_low_time = (u32)(delayTime & 0x00000000FFFFFFFF);

	rc = dpp_reg_write(dev, NPPU_PBU_CFG_CFG_PFC_RDY_HIGH_TIMEr, 0, 0, &pbuDelayHighTime);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_write(dev, NPPU_PBU_CFG_CFG_PFC_RDY_LOW_TIMEr, 0, 0, &pbuDelayLowTime);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
DPP_STATUS dpp_pbu_pfc_delay_time_get(struct dpp_dev_t *dev, u64 *delayTime)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_nppu_pbu_cfg_cfg_pfc_rdy_high_time_t pbuDelayHighTime = { 0 };
	struct dpp_nppu_pbu_cfg_cfg_pfc_rdy_low_time_t pbuDelayLowTime = { 0 };

	ZXIC_COMM_CHECK_POINT(delayTime);
	ZXIC_COMM_CHECK_POINT(dev);

	rc = dpp_reg_read(dev, NPPU_PBU_CFG_CFG_PFC_RDY_HIGH_TIMEr, 0, 0, &pbuDelayHighTime);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	rc = dpp_reg_read(dev, NPPU_PBU_CFG_CFG_PFC_RDY_LOW_TIMEr, 0, 0, &pbuDelayLowTime);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*delayTime = (((u64)pbuDelayHighTime.cfg_pfc_rdy_high_time) << 32) |
		     (u64)pbuDelayLowTime.cfg_pfc_rdy_low_time;

	return DPP_OK;
}
