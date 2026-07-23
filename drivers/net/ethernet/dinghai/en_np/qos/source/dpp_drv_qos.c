// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_drv_qos.h"
DPP_STATUS dpp_cosq_gsch_id_add(struct dpp_pf_info_t *pf_info, u32 pp_port, u32 numq, u32 level,
				u32 flags, u64 *p_gsch_id)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 num = 0;
	u32 *gsch_id = ZXIC_NULL;
	u32 gsch_id_h = 0;
	u32 gsch_id_l = 0;
	u64 temp_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	gsch_id = (u32 *)ZXIC_COMM_MALLOC(G_SCH_ID_LEN);
	ZXIC_COMM_CHECK_POINT(gsch_id);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "dpp_dev_get", gsch_id);

	ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX, gsch_id);
	ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(pp_port, 0, DPP_TM_PP_NUM - 1, gsch_id);
	ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(level, 0, DPP_CRDT_LEVEL_MAX, gsch_id);
	ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(flags, 0, DPP_SCHE_TYPE_MAX, gsch_id);
	num = ((flags == FLOW_SCHE) ? numq : 1);

	ret = dpp_agent_channel_tm_seid_request(&dev, pp_port, pf_info->vport, level, flags, num,
						gsch_id);
	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "dpp_agent_channel_tm_seid_request", gsch_id);

	gsch_id_h = *(gsch_id + 1);
	gsch_id_l = *gsch_id;

	temp_id = ((u64)gsch_id_h) << 32 | ((u64)gsch_id_l);

	if (DPP_OK != (u32)(temp_id >> 56)) {
		ZXIC_COMM_FREE(gsch_id);
		return DPP_ERR;
	}

	*p_gsch_id = temp_id;
	ZXIC_COMM_FREE(gsch_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_cosq_gsch_id_add);
DPP_STATUS dpp_cosq_gsch_id_delete(struct dpp_pf_info_t *pf_info, u32 pp_port, u64 gsch_id)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 sche_level = 0;
	u32 sche_type = 0;
	u32 num = 1;
	u32 se_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pp_port, 0, DPP_TM_PP_NUM - 1);

	DPP_TM_CRDT_LEVEL_GET(gsch_id, sche_level);
	DPP_TM_CRDT_TYPE_GET(gsch_id, sche_type);
	DPP_TM_CRDT_SE_ID_GET(gsch_id, se_id);

	ret = dpp_agent_channel_tm_seid_release(&dev, pp_port, pf_info->vport, sche_level,
						sche_type, num, se_id);
	ZXIC_COMM_CHECK_RC(ret, "dpp_agent_channel_tm_seid_release");

	// if (DPP_OK != ret)
	// {
	//     return DPP_ERR;
	// }

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_cosq_gsch_id_delete);
DPP_STATUS dpp_sch_base_node_get(struct dpp_pf_info_t *pf_info, u32 pp_port, u64 *p_gsch_id)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 *gsch_id = ZXIC_NULL;
	u32 gsch_id_h = 0;
	u32 gsch_id_l = 0;
	u64 temp_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	gsch_id = (u32 *)ZXIC_COMM_MALLOC(G_SCH_ID_LEN);
	ZXIC_COMM_CHECK_POINT(gsch_id);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "dpp_dev_get", gsch_id);

	ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX, gsch_id);
	ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(pp_port, 0, DPP_TM_PP_NUM - 1, gsch_id);

	ret = dpp_agent_channel_tm_base_node_get(&dev, pp_port, pf_info->vport, gsch_id);
	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "dpp_agent_channel_tm_base_node_get", gsch_id);

	gsch_id_h = *(gsch_id + 1);
	gsch_id_l = *gsch_id;

	temp_id = ((u64)gsch_id_h) << 32 | ((u64)gsch_id_l);
	if (DPP_OK != (u32)(temp_id >> 56)) {
		ZXIC_COMM_FREE(gsch_id);
		return DPP_ERR;
	}

	*p_gsch_id = temp_id;
	ZXIC_COMM_FREE(gsch_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_sch_base_node_get);
DPP_STATUS dpp_crdt_se_pp_link_set(struct dpp_pf_info_t *pf_info, u32 se_id, u32 pp_id, u32 weight,
				   u32 sp_mapping)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pp_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(weight, 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(sp_mapping, DPP_TM_SCH_SP_0, DPP_TM_SCH_SP_8);

	ret = dpp_tm_crdt_se_pp_link_set(&dev, se_id, pp_id, weight, sp_mapping);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_crdt_se_pp_link_set");

	return ret;
}
EXPORT_SYMBOL(dpp_crdt_se_pp_link_set);
DPP_STATUS dpp_crdt_se_link_set(struct dpp_pf_info_t *pf_info, u32 se_id, u32 se_linkid,
				u32 se_weight, u32 se_sp)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(se_id, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(se_linkid, 0, DPP_ETM_FQSPWFQ_NUM - 1);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(se_weight, 0, DPP_TM_SCH_WEIGHT_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(se_sp, DPP_TM_SCH_SP_0, DPP_TM_SCH_SP_8);

	ret = dpp_tm_crdt_se_link_set(&dev, se_id, se_linkid, se_weight, se_sp);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_crdt_se_link_set");

	return ret;
}
EXPORT_SYMBOL(dpp_crdt_se_link_set);
DPP_STATUS dpp_crdt_flow_link_set(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 c_linkid,
				  u32 c_weight, u32 c_sp, u32 mode, u32 e_linkid, u32 e_weight,
				  u32 e_sp)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_tm_crdt_flow_link_set(&dev, flow_id, c_linkid, c_weight, c_sp, mode, e_linkid,
					e_weight, e_sp);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_crdt_flow_link_set");

	return ret;
}
EXPORT_SYMBOL(dpp_crdt_flow_link_set);
DPP_STATUS dpp_crdt_del_flow_link_set(struct dpp_pf_info_t *pf_info, u32 id_s, u32 id_e)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(id_s, 0, DPP_ETM_CRDT_NUM);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(id_e, 0, DPP_ETM_CRDT_NUM);

	ret = dpp_tm_crdt_del_flow_link_set(&dev, id_s, id_e);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_crdt_del_flow_link_set");

	return ret;
}
EXPORT_SYMBOL(dpp_crdt_del_flow_link_set);
DPP_STATUS dpp_crdt_del_se_link_set(struct dpp_pf_info_t *pf_info, u32 id_s, u32 id_e)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(id_s, 0, DPP_ETM_FQSPWFQ_NUM);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(id_e, 0, DPP_ETM_FQSPWFQ_NUM);

	ret = dpp_tm_crdt_del_se_link_set(&dev, id_s, id_e);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_crdt_del_se_link_set");

	return ret;
}
EXPORT_SYMBOL(dpp_crdt_del_se_link_set);
DPP_STATUS dpp_port_shape_set(struct dpp_pf_info_t *pf_info, u32 pp_port, u32 cir, u32 cbs,
			      u32 c_en)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pp_port, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(c_en, 0, 1);

	// ret = dpp_tm_shape_pp_para_wr(&dev, pp_port, cir, cbs, c_en);
	// ZXIC_COMM_CHECK_RC(ret, "dpp_tm_shape_pp_para_wr");

	ret = dpp_agent_channel_tm_port_shape(&dev, pp_port, cir, cbs, c_en);
	ZXIC_COMM_CHECK_RC(ret, "dpp_agent_channel_tm_port_shape");

	return ret;
}
EXPORT_SYMBOL(dpp_port_shape_set);
DPP_STATUS dpp_port_shape_get(struct dpp_pf_info_t *pf_info, u32 pp_port,
			      struct dpp_tm_shape_pp_para_t *p_para)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	struct dpp_tm_shape_pp_para_t pp_shap_para = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pp_port, 0, DPP_TM_PP_NUM - 1);

	ret = dpp_tm_shape_pp_para_get(&dev, pp_port, &pp_shap_para);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_shape_pp_para_get");

	p_para->c_en = pp_shap_para.c_en;
	p_para->cir = pp_shap_para.cir;
	p_para->cbs = pp_shap_para.cbs;

	return ret;
}
EXPORT_SYMBOL(dpp_port_shape_get);
DPP_STATUS dpp_se_shape_set(struct dpp_pf_info_t *pf_info, u32 se_id, u32 pir, u32 pbs, u32 db_en,
			    u32 cir, u32 cbs)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	// ret = dpp_tm_shape_se_para_set(&dev, se_id, pir, pbs, db_en, cir, cbs);
	// ZXIC_COMM_CHECK_RC(ret, "dpp_tm_shape_se_para_set");

	ret = dpp_agent_channel_tm_se_shape(&dev, se_id, pir, pbs, db_en, cir, cbs);
	ZXIC_COMM_CHECK_RC(ret, "dpp_agent_channel_tm_se_shape");

	return ret;
}
EXPORT_SYMBOL(dpp_se_shape_set);
DPP_STATUS dpp_flow_shape_set(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 cir, u32 cbs,
			      u32 db_en, u32 eir, u32 ebs)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	// ret = dpp_tm_shape_flow_para_set(&dev, flow_id, cir, cbs, db_en, eir, ebs);
	// ZXIC_COMM_CHECK_RC(ret, "dpp_tm_shape_flow_para_set");

	ret = dpp_agent_channel_tm_flow_shape(&dev, flow_id, cir, cbs, db_en, eir, ebs);
	ZXIC_COMM_CHECK_RC(ret, "dpp_agent_channel_tm_flow_shape");

	return ret;
}
EXPORT_SYMBOL(dpp_flow_shape_set);
DPP_STATUS dpp_flow_map_port_set(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 port)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_tm_cgavd_q_map_pp_set(&dev, flow_id, port);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_cgavd_q_map_pp_set");

	return ret;
}
EXPORT_SYMBOL(dpp_flow_map_port_set);
DPP_STATUS dpp_flow_map_port_get(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 *p_port)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 pp_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_tm_cgavd_q_map_pp_get(&dev, flow_id, &pp_id);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_cgavd_q_map_pp_get");

	*p_port = pp_id;

	return ret;
}
EXPORT_SYMBOL(dpp_flow_map_port_get);
DPP_STATUS dpp_flow_td_th_set(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 td_th)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	// ret = dpp_tm_cgavd_td_th_set(&dev, QUEUE_LEVEL, flow_id, td_th);
	// ZXIC_COMM_CHECK_RC(ret, "dpp_tm_cgavd_td_th_set");

	ret = dpp_agent_channel_tm_td_set(&dev, QUEUE_LEVEL, flow_id, td_th);
	ZXIC_COMM_CHECK_RC(ret, "dpp_agent_channel_tm_td_set");

	return ret;
}
EXPORT_SYMBOL(dpp_flow_td_th_set);
DPP_STATUS dpp_flow_td_th_get(struct dpp_pf_info_t *pf_info, u32 flow_id, u32 *p_td_th)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 td_th = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_tm_cgavd_td_th_get(&dev, QUEUE_LEVEL, flow_id, &td_th);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_cgavd_td_th_get");

	*p_td_th = td_th;

	return ret;
}
EXPORT_SYMBOL(dpp_flow_td_th_get);
DPP_STATUS dpp_blk_size_set(struct dpp_pf_info_t *pf_info, u32 size)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ret = dpp_tm_cfgmt_blk_size_set(&dev, size);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_tm_cfgmt_blk_size_set");

	return ret;
}
EXPORT_SYMBOL(dpp_blk_size_set);
DPP_STATUS dpp_qmu_pfc_en_set(struct dpp_pf_info_t *pf_info, u32 pfc_en)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pfc_en, 0, 1);

	ret = dpp_tm_qmu_pfc_en_set(&dev, pfc_en);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_qmu_pfc_en_set");

	return ret;
}
EXPORT_SYMBOL(dpp_qmu_pfc_en_set);
DPP_STATUS dpp_qmu_pfc_en_get(struct dpp_pf_info_t *pf_info, u32 *p_pfc_en)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 pfc_en = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pfc_en, 0, 1);

	ret = dpp_tm_qmu_pfc_en_get(&dev, &pfc_en);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_qmu_pfc_en_set");

	*p_pfc_en = pfc_en;

	return ret;
}
EXPORT_SYMBOL(dpp_qmu_pfc_en_get);
DPP_STATUS dpp_qmu_port_pfc_set(struct dpp_pf_info_t *pf_info, u32 port_id, u32 port_en)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(port_id, 0, DPP_TM_PP_NUM - 1);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(port_en, 0, 1);

	ret = dpp_tm_qmu_port_pfc_make_set(&dev, port_id, port_en);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_qmu_port_pfc_make_set");

	return ret;
}
EXPORT_SYMBOL(dpp_qmu_port_pfc_set);
DPP_STATUS dpp_qmu_port_pfc_get(struct dpp_pf_info_t *pf_info, u32 port_id, u32 *p_port_en)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 port_en = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(port_id, 0, DPP_TM_PP_NUM - 1);

	ret = dpp_tm_qmu_port_pfc_make_get(&dev, port_id, &port_en);
	ZXIC_COMM_CHECK_RC(ret, "dpp_tm_qmu_port_pfc_make_get");

	*p_port_en = port_en;

	return ret;
}
EXPORT_SYMBOL(dpp_qmu_port_pfc_get);
DPP_STATUS dpp_car_profile_id_add(struct dpp_pf_info_t *pf_info, u32 flags, u64 *p_profile_id)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 *profile_id = ZXIC_NULL;
	u32 profile_id_h = 0;
	u32 profile_id_l = 0;
	u64 temp_profile_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	profile_id = (u32 *)ZXIC_COMM_MALLOC(G_PROFILE_ID_LEN);
	ZXIC_COMM_CHECK_POINT(profile_id);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "dpp_dev_get", profile_id);

	ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX,
						    profile_id);
	ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(flags, 0, CAR_TYPE_MAX, profile_id);

	ret = dpp_agent_channel_plcr_profileid_request(&dev, pf_info->vport, flags, profile_id);
	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "dpp_agent_channel_plcr_profileid_request", profile_id);

	profile_id_h = *(profile_id + 1);
	profile_id_l = *profile_id;

	temp_profile_id = ((u64)profile_id_l) << 32 | ((u64)profile_id_h);

	if (DPP_OK != (u32)(temp_profile_id >> 56)) {
		ZXIC_COMM_FREE(profile_id);
		return DPP_ERR;
	}

	*p_profile_id = temp_profile_id;
	ZXIC_COMM_FREE(profile_id);

	return ret;
}
EXPORT_SYMBOL(dpp_car_profile_id_add);
DPP_STATUS dpp_car_profile_id_delete(struct dpp_pf_info_t *pf_info, u32 flags, u64 profile_id)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };
	u32 profileid = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	DPP_CAR_PROFILE_ID_GET(profile_id, profileid);

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(flags, 0, CAR_TYPE_MAX);

	ret = dpp_agent_channel_plcr_profileid_release(&dev, pf_info->vport, flags, profileid);
	ZXIC_COMM_CHECK_RC(ret, "dpp_agent_channel_plcr_profileid_release");

	// if (DPP_OK != ret)
	// {
	//     return DPP_ERR;
	// }

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_car_profile_id_delete);
DPP_STATUS dpp_car_queue_cfg_set(struct dpp_pf_info_t *pf_info, u32 car_type, u32 flow_id,
				 u32 drop_flag, u32 plcr_en, u32 profile_id)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_stat_car_queue_cfg_set(&dev, car_type, flow_id, drop_flag, plcr_en, profile_id);
	ZXIC_COMM_CHECK_RC(ret, "dpp_stat_car_queue_cfg_set");

	return ret;
}
EXPORT_SYMBOL(dpp_car_queue_cfg_set);
DPP_STATUS dpp_car_queue_cfg_get(struct dpp_pf_info_t *pf_info, u32 car_type, u32 flow_id,
				 u32 *p_drop_flag, u32 *p_plcr_en, u32 *p_profile_id)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_CHECK_DEV_POINT(0, p_drop_flag);
	ZXIC_COMM_CHECK_DEV_POINT(0, p_plcr_en);
	ZXIC_COMM_CHECK_DEV_POINT(0, p_profile_id);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_stat_car_queue_cfg_get(&dev, car_type, flow_id, p_drop_flag, p_plcr_en,
					 p_profile_id);
	ZXIC_COMM_CHECK_RC(ret, "dpp_stat_car_queue_cfg_get");

	return ret;
}
EXPORT_SYMBOL(dpp_car_queue_cfg_get);
DPP_STATUS dpp_car_profile_cfg_set(struct dpp_pf_info_t *pf_info, u32 car_type, u32 pkt_sign,
				   u32 profile_id, void *p_car_profile_cfg)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_POINT(p_car_profile_cfg);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_agent_channel_plcr_car_rate(&dev, car_type, pkt_sign, profile_id,
					      p_car_profile_cfg);
	ZXIC_COMM_CHECK_RC(ret, "dpp_agent_channel_plcr_car_rate");

	return ret;
}
EXPORT_SYMBOL(dpp_car_profile_cfg_set);
DPP_STATUS dpp_car_profile_cfg_get(struct dpp_pf_info_t *pf_info, u32 car_type, u32 pkt_sign,
				   u32 profile_id, void *p_car_profile_cfg)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_POINT(p_car_profile_cfg);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_stat_car_profile_cfg_get(&dev, car_type, pkt_sign, profile_id, p_car_profile_cfg);
	ZXIC_COMM_CHECK_RC(ret, "dpp_stat_car_profile_cfg_get");

	return ret;
}
EXPORT_SYMBOL(dpp_car_profile_cfg_get);
DPP_STATUS dpp_car_queue_map_set(struct dpp_pf_info_t *pf_info, u32 car_type, u32 flow_id,
				 u32 map_flow_id, u32 map_sp)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_stat_car_queue_map_set(&dev, car_type, flow_id, map_flow_id, map_sp);
	ZXIC_COMM_CHECK_RC(ret, "dpp_stat_car_queue_map_set");

	return ret;
}
EXPORT_SYMBOL(dpp_car_queue_map_set);
DPP_STATUS dpp_car_queue_map_get(struct dpp_pf_info_t *pf_info, u32 car_type, u32 flow_id,
				 u32 *p_map_flow_id, u32 *p_map_sp)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ret = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(ret, "dpp_dev_get");

	ZXIC_COMM_CHECK_POINT(p_map_flow_id);
	ZXIC_COMM_CHECK_POINT(p_map_sp);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(pf_info->vport, 0, DPP_VPORT_NUM_MAX);

	ret = dpp_stat_car_queue_map_get(&dev, car_type, flow_id, p_map_flow_id, p_map_sp);
	ZXIC_COMM_CHECK_RC(ret, "dpp_stat_car_queue_map_get");

	return ret;
}
EXPORT_SYMBOL(dpp_car_queue_map_get);
