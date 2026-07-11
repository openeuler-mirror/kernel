// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_tbl_cfg.h"
#include "dpp_dev.h"
#include "dpp_pktrx_cfg.h"
#include "dpp_pktrx_api.h"
#include "dpp_agent_channel.h"

u32 dpp_glb_cfg_set_0(struct dpp_pf_info_t *pf_info, u32 glb_cfg_data_0)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_set_0(&dev, glb_cfg_data_0);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_set_0");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_glb_cfg_set_0);

u32 dpp_glb_cfg_set_1(struct dpp_pf_info_t *pf_info, u32 glb_cfg_data_1)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_set_1(&dev, glb_cfg_data_1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_set_1");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_glb_cfg_set_1);

u32 dpp_glb_cfg_set_2(struct dpp_pf_info_t *pf_info, u32 glb_cfg_data_2)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_set_2(&dev, glb_cfg_data_2);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_set_2");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_glb_cfg_set_2);

u32 dpp_glb_cfg_set_3(struct dpp_pf_info_t *pf_info, u32 glb_cfg_data_3)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_set_3(&dev, glb_cfg_data_3);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_set_3");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_glb_cfg_set_3);

u32 dpp_glb_cfg_get_0(struct dpp_pf_info_t *pf_info, u32 *p_glb_cfg_data_0)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_glb_cfg_data_0);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_get_0(&dev, p_glb_cfg_data_0);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_get_0");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_glb_cfg_get_0);

u32 dpp_glb_cfg_get_1(struct dpp_pf_info_t *pf_info, u32 *p_glb_cfg_data_1)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_glb_cfg_data_1);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_get_1(&dev, p_glb_cfg_data_1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_get_1");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_glb_cfg_get_1);

u32 dpp_glb_cfg_get_2(struct dpp_pf_info_t *pf_info, u32 *p_glb_cfg_data_2)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_glb_cfg_data_2);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_get_2(&dev, p_glb_cfg_data_2);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_get_2");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_glb_cfg_get_2);

u32 dpp_glb_cfg_get_3(struct dpp_pf_info_t *pf_info, u32 *p_glb_cfg_data_3)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_glb_cfg_data_3);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_get_3(&dev, p_glb_cfg_data_3);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_get_3");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_glb_cfg_get_3);

u32 dpp_l2d_psn_cfg_set(struct dpp_pf_info_t *pf_info, u8 psn_cfg)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };
	struct zxic_mutex_t *p_mutex = NULL;

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dev_opr_mutex_get(&dev, DPP_DEV_MUTEX_T_PKTRX_MF_GLB_CFG_1, &p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "zxic_comm_mutex_lock");

	rc = dpp_agent_channel_psn_cfg_l2d_write(&dev, psn_cfg);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(&dev), rc, "dpp_agent_channel_psn_cfg_l2d_write",
				      p_mutex);

	rc = zxic_comm_mutex_unlock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_l2d_psn_cfg_set);

u32 dpp_l2d_psn_cfg_get(struct dpp_pf_info_t *pf_info, u32 *p_psn_cfg)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };
	struct zxic_mutex_t *p_mutex = NULL;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_psn_cfg);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dev_opr_mutex_get(&dev, DPP_DEV_MUTEX_T_PKTRX_MF_GLB_CFG_1, &p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "zxic_comm_mutex_lock");

	rc = dpp_agent_channel_psn_cfg_l2d_read(&dev, p_psn_cfg);
	ZXIC_COMM_CHECK_DEV_RC_UNLOCK(DEV_ID(&dev), rc, "dpp_agent_channel_psn_cfg_l2d_read",
				      p_mutex);

	rc = zxic_comm_mutex_unlock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_l2d_psn_cfg_get);

u32 dpp_pktrx_mcode_glb_cfg_write(struct dpp_pf_info_t *pf_info, u32 start_bit_no, u32 end_bit_no,
				  u32 glb_cfg_data_1)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_mcode_glb_cfg_write_1(&dev, start_bit_no, end_bit_no, glb_cfg_data_1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_mcode_glb_cfg_write_1");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_pktrx_mcode_glb_cfg_write);

u32 dpp_mcode_feature_get(struct dpp_pf_info_t *pf_info, u32 index, u64 *feature)
{
	u32 rc = 0;
	struct dpp_dev_t dev = { 0 };
	struct dpp_pktrx_phyport_udf_table_t phy_udf_table = { 0 };

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_MCODE_FEATURE_LIST_NUM - 1);
	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(feature);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_pktrx_udf_table_get(&dev, 11 + index / 2, &phy_udf_table);
	ZXIC_COMM_CHECK_RC(rc, "dpp_pktrx_udf_table_get");

	*feature =
		ZXIC_COMM_COUNTER64_BUILD(phy_udf_table.port_based_user_data[(index % 2) * 2],
					  phy_udf_table.port_based_user_data[(index % 2) * 2 + 1]);

	return 0;
}
EXPORT_SYMBOL(dpp_mcode_feature_get);
