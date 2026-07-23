// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_drv_fc.h"
DPP_STATUS dpp_port_th_set(struct dpp_pf_info_t *pf_info, u32 port_id,
			   struct dpp_pbu_port_th_para_t *p_para)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_POINT(p_para);

	ret = dpp_pbu_port_th_set(&dev, port_id, p_para);
	ZXIC_COMM_CHECK_RC(ret, "dpp_pbu_port_th_set");

	return ret;
}
EXPORT_SYMBOL(dpp_port_th_set);
DPP_STATUS dpp_port_th_get(struct dpp_pf_info_t *pf_info, u32 port_id,
			   struct dpp_pbu_port_th_para_t *p_para)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_POINT(p_para);

	ret = dpp_pbu_port_th_get(&dev, port_id, p_para);
	ZXIC_COMM_CHECK_RC(ret, "dpp_pbu_port_th_get");

	return ret;
}
EXPORT_SYMBOL(dpp_port_th_get);
DPP_STATUS dpp_port_cos_th_set(struct dpp_pf_info_t *pf_info, u32 port_id,
			       struct dpp_pbu_port_cos_th_para_t *p_para)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_POINT(p_para);

	ret = dpp_pbu_port_cos_th_set(&dev, port_id, p_para);
	ZXIC_COMM_CHECK_RC(ret, "dpp_pbu_port_cos_th_set");

	return ret;
}
EXPORT_SYMBOL(dpp_port_cos_th_set);
DPP_STATUS dpp_port_cos_th_get(struct dpp_pf_info_t *pf_info, u32 port_id,
			       struct dpp_pbu_port_cos_th_para_t *p_para)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_POINT(p_para);

	ret = dpp_pbu_port_cos_th_get(&dev, port_id, p_para);
	ZXIC_COMM_CHECK_RC(ret, "dpp_pbu_port_cos_th_get");

	return ret;
}
EXPORT_SYMBOL(dpp_port_cos_th_get);
DPP_STATUS dpp_pfc_delay_time_set(struct dpp_pf_info_t *pf_info, u64 delayTime)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_pbu_pfc_delay_time_set(&dev, delayTime);
	ZXIC_COMM_CHECK_RC(ret, "dpp_pbu_pfc_delay_time_set");

	return ret;
}
EXPORT_SYMBOL(dpp_pfc_delay_time_set);
DPP_STATUS dpp_pfc_delay_time_get(struct dpp_pf_info_t *pf_info, u64 *delayTime)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(delayTime);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_pbu_pfc_delay_time_get(&dev, delayTime);
	ZXIC_COMM_CHECK_RC(ret, "dpp_pbu_pfc_delay_time_get");

	return ret;
}
EXPORT_SYMBOL(dpp_pfc_delay_time_get);
