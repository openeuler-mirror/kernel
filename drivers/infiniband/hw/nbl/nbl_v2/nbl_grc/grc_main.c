// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <linux/version.h>
#include "nbl_compat.h"
#include "grc_hw_rdma.h"
#include "grc_common_v2.h"
#include "grc_main.h"
#include "grc_cqp.h"
#include "grc_mailbox.h"
#include "grc_gid.h"
#include "grc_counters.h"
#include "grc_flr.h"
#include "nbl_rdma_module.h"

static struct nbl_obj_cnt hmc_obj_total_cnt = {
	.qp_num = SZ_256K,	/* 256k qp */
	.cq_num = SZ_512K,	/* 512k cq */
	.pble_num = SZ_256M,	/* 256M pble */
	.mr_num = SZ_16M,	/* 16M mrte */
	.srq_num = SZ_64K,	/* 64k srq */
};

static const struct nbl_grc_abnormal_module draco_abnormal_modules[] = {
	{ "rdma_top", 0x01000000 },
	{ "cqpp", 0x01010000 },
	{ "hdma", 0x01020000 },
	{ "txp", 0x01030000 },
	{ "txmr", 0x01040000 },
	{ "txm", 0x01050000 },
	{ "rxp", 0x01060000 },
	{ "rxmr", 0x01070000 },
	{ "rxm", 0x01080000 },
	{ "raqp", 0x01090000 },
	{ "ceaq", 0x010a0000 },
	{ "prob", 0x010b0000 },
	{ "adpt", 0x010c0000 },
	{ "qpcc", 0x010d0000 },
	{ "cqcc", 0x010e0000 },
	{ "mrtc", 0x010f0000 },
	{ "pblc", 0x01100000 },
	{ "cc", 0x01110000 },
	{ "sqrqec", 0x01120000 },
	{ "irqec", 0x01130000 },
	{ "orqec", 0x01140000 },
	{ "unapec", 0x01150000 },
	{ "raqec", 0x01160000 },
	{ "tqp", 0x01170000 },
	{ "resv", 0x01180000 },
	{ "stat", 0x01190000 },
	{ "srqc", 0x01200000 },
	{ "pdc", 0x01210000 },
	{ "iorqec", 0x01220000 },
	{ "osqec", 0x01230000 },
	{ "ntfqp", 0x01240000 },
};

static const struct nbl_grc_cache_layout draco_caches[] = {
	{
		.type = NBL_CACHE_QPCC,
		.low_threshold_addr = NBL_QPCC_REG_ADDR(NBL_REG_QPCC_BASE,
					NBL_QPCC_IDLE_BLOCK_FIFO_THR_LOW_OFF),
		.high_threshold_addr = NBL_QPCC_REG_ADDR(NBL_REG_QPCC_BASE,
					 NBL_QPCC_IDLE_BLOCK_FIFO_THR_HIGH_OFF),
		.almost_full_threshold_addr = NBL_QPCC_REG_ADDR(NBL_REG_QPCC_BASE,
						NBL_QPCC_CLR_CAM_AFULL_THR_OFF),
		.depth = NBL_QPCC_CACHE_DEPTH,
	},
	{
		.type = NBL_CACHE_CQCC,
		.low_threshold_addr = NBL_CQCC_REG_ADDR(NBL_REG_CQCC_BASE,
					NBL_CQCC_IDLE_BLOCK_FIFO_THR_LOW_OFF),
		.high_threshold_addr = NBL_CQCC_REG_ADDR(NBL_REG_CQCC_BASE,
					 NBL_CQCC_IDLE_BLOCK_FIFO_THR_HIGH_OFF),
		.almost_full_threshold_addr = NBL_CQCC_REG_ADDR(NBL_REG_CQCC_BASE,
						NBL_CQCC_CLR_CAM_AFULL_THR_OFF),
		.depth = NBL_CQCC_CACHE_DEPTH,
	},
	{
		.type = NBL_CACHE_MRTC,
		.low_threshold_addr = NBL_MRTC_REG_ADDR(NBL_REG_MRTC_BASE,
					NBL_MRTC_IDLE_BLOCK_FIFO_THR_LOW_OFF),
		.high_threshold_addr = NBL_MRTC_REG_ADDR(NBL_REG_MRTC_BASE,
					 NBL_MRTC_IDLE_BLOCK_FIFO_THR_HIGH_OFF),
		.almost_full_threshold_addr = NBL_MRTC_REG_ADDR(NBL_REG_MRTC_BASE,
						NBL_MRTC_CLR_CAM_AFULL_THR_OFF),
		.depth = NBL_MRTC_CACHE_DEPTH,
	},
	{
		.type = NBL_CACHE_SRQC,
		.low_threshold_addr = NBL_SRQC_REG_ADDR(NBL_REG_SRQC_BASE,
					NBL_SRQC_IDLE_BLOCK_FIFO_THR_LOW_OFF),
		.high_threshold_addr = NBL_SRQC_REG_ADDR(NBL_REG_SRQC_BASE,
					 NBL_SRQC_IDLE_BLOCK_FIFO_THR_HIGH_OFF),
		.almost_full_threshold_addr = NBL_SRQC_REG_ADDR(NBL_REG_SRQC_BASE,
						NBL_SRQC_CLR_CAM_AFULL_THR_OFF),
		.depth = NBL_SRQC_CACHE_DEPTH,
	},
	{
		.type = NBL_CACHE_SQRQEC,
		.low_threshold_addr = NBL_SQRQEC_REG_ADDR(NBL_REG_SQRQEC_BASE,
					  NBL_SQRQEC_IDLE_BLOCK_FIFO_THR_LOW_OFF),
		.high_threshold_addr = NBL_SQRQEC_REG_ADDR(NBL_REG_SQRQEC_BASE,
					   NBL_SQRQEC_IDLE_BLOCK_FIFO_THR_HIGH_OFF),
		.almost_full_threshold_addr = NBL_SQRQEC_REG_ADDR(NBL_REG_SQRQEC_BASE,
						  NBL_SQRQEC_CLR_CAM_AFULL_THR_OFF),
		.depth = NBL_SQRQEC_CACHE_DEPTH,
	},
};

static const struct nbl_grc_register_layout draco_grc_regs = {
	.rdma_top_base = NBL_REG_RDMA_TOP,
	.cqpp_base = NBL_REG_CQPP_BASE,
	.hdma_base = NBL_REG_HDMA_BASE,
	.txp_base = NBL_REG_TXP_BASE,
	.txmr_base = NBL_REG_TXMR_BASE,
	.txm_base = NBL_REG_TXM_BASE,
	.rxp_base = NBL_REG_RXP_BASE,
	.raqp_base = NBL_REG_RAQP_BASE,
	.ceaq_base = NBL_REG_CEAQ_BASE,
	.qpcc_base = NBL_REG_QPCC_BASE,
	.cqcc_base = NBL_REG_CQCC_BASE,
	.mrtc_base = NBL_REG_MRTC_BASE,
	.sqrqec_base = NBL_REG_SQRQEC_BASE,
	.stat_base = NBL_REG_STAT_BASE,
	.srqc_base = NBL_REG_SRQC_BASE,
	.cc_base = NBL_REG_CC_BASE,
	.ntfqp_base = NBL_REG_NTFQP_BASE,
	.dsch_base = NBL_GRC_DSCH_BASE,
	.uqm_base = NBL_GRC_UQM_BASE,
	.pcomp_base = NBL_GRC_PCOMP_BASE,
	.ped_base = NBL_GRC_PED_BASE,
	.epro_base = NBL_GRC_EPRO_BASE,
	.ipro_base = NBL_GRC_IPRO_BASE,
	.top_ctrl_base = NBL_REG_TOP_CTRL_BASE_V2,
	.abnormal_modules = draco_abnormal_modules,
	.abnormal_module_count = ARRAY_SIZE(draco_abnormal_modules),
	.caches = draco_caches,
	.cache_count = ARRAY_SIZE(draco_caches),
};

static const struct nbl_grc_register_layout orion_grc_regs = {
	.rdma_top_base = NBL_REG_RDMA_TOP_V5,
	.cqpp_base = NBL_REG_CQPP_BASE_V5,
	.hdma_base = NBL_REG_HDMA_BASE_V5,
	.txp_base = NBL_REG_TXP_BASE_V5,
	.txmr_base = NBL_REG_TXMR_BASE_V5,
	.txm_base = NBL_REG_TXM_BASE_V5,
	.rxp_base = NBL_REG_RXP_BASE_V5,
	.raqp_base = NBL_REG_RAQP_BASE_V5,
	.ceaq_base = NBL_REG_CEAQ_BASE_V5,
	.qpcc_base = NBL_REG_QPCC_V5,
	.cqcc_base = NBL_REG_CQCC_V5,
	.mrtc_base = NBL_REG_MRTC_V5,
	.sqrqec_base = NBL_REG_SQRQEC_V5,
	.stat_base = NBL_REG_STAT_BASE_V5,
	.srqc_base = NBL_REG_SRQC_V5,
	.cc_base = NBL_REG_CC_BASE_V5,
	.ntfqp_base = NBL_REG_NTFQP_BASE_V5,
	.dsch_base = NBL_REG_DSCH_BASE_V5,
	.uqm_base = NBL_REG_UQM_BASE_V5,
	.pcomp_base = NBL_REG_PCOMPLETER_HOST_BASE_V5,
	.ped_base = NBL_REG_UPED_BASE_V5,
	.epro_base = NBL_REG_EPRO_BASE_V5,
	.ipro_base = NBL_REG_IPRO_BASE_V5,
	.top_ctrl_base = NBL_REG_TOP_CTRL_BASE_V5,
	/* TODO: Split these tables when Orion module bases differ. */
	.abnormal_modules = draco_abnormal_modules,
	.abnormal_module_count = ARRAY_SIZE(draco_abnormal_modules),
	.caches = draco_caches,
	.cache_count = ARRAY_SIZE(draco_caches),
};

static const struct nbl_grc_product_desc grc_product_descs[NBL_GRC_PRODUCT_MAX] = {
	[NBL_GRC_PRODUCT_DRACO] = {
		.name = "Draco",
		.id = NBL_GRC_PRODUCT_DRACO,
		.regs = &draco_grc_regs,
		.resource_ops = &grc_resource_ops,
		.dsch_ops = &grc_dsch_ops,
		.stat_ops = &grc_stat_ops,
		.global_ops = &grc_global_ops,
	},
	[NBL_GRC_PRODUCT_ORION] = {
		.name = "Orion",
		.id = NBL_GRC_PRODUCT_ORION,
		.regs = &orion_grc_regs,
		.resource_ops = &grc_resource_ops,
		.dsch_ops = &grc_dsch_ops,
		.stat_ops = &grc_stat_ops,
		.global_ops = &grc_global_ops,
	},
};

static int nbl_grc_init_qpn_range(struct nbl_grc *grc)
{
	u16 rf_num;
	struct nbl_grc_res_cfg *res_cfg = &grc->res_cfg;
	struct device *dev = &grc->grc_dev->adev.dev;

	res_cfg->addr_mode = grc->sd_addr_mode;
	res_cfg->vf_cnt = grc->core_dev.rdma_cap_my_num;

	rf_num = grc->core_dev.rdma_cap_num;
	if (rf_num > NBL_RDMA_TOTAL_FUNCTION_NUM) {
		grc_pr_warn("invalid rdma function_num=%u,use default 64\n", rf_num);
		rf_num = NBL_RDMA_TOTAL_FUNCTION_NUM;
	} else if (rf_num < grc->core_dev.eth_mode) {
		grc_pr_warn("rdma function_num=%u less than pf,use default %u\n",
			    rf_num, grc->core_dev.eth_mode);
		rf_num = grc->core_dev.eth_mode;
	} else {
		rf_num = roundup_pow_of_two(rf_num);
	}

	res_cfg->qp_per_vf = hmc_obj_total_cnt.qp_num / rf_num;
	res_cfg->total_qp_cnt = res_cfg->qp_per_vf * res_cfg->vf_cnt;
	dev_info(dev, "got vf_cnt=%u,rdma_cap_num=%u,total_qp_cnt=%#x,from templae cfg,func_id=%u",
		 res_cfg->vf_cnt, grc->core_dev.rdma_cap_num, res_cfg->total_qp_cnt,
		 grc->core_dev.function_id);
	return 0;
}

static int grc_hbf_tbl_init(struct nbl_grc *grc)
{
	grc->hbf_tbl = kcalloc(1, sizeof(struct nbl_hbf_tbl), GFP_KERNEL);
	if (!grc->hbf_tbl)
		return -ENOMEM;

	grc->hbf_tbl->tbl_size = NBL_RDMA_TOTAL_FUNCTION_NUM;
	return 0;
}

static void grc_hbf_tbl_free(struct nbl_grc *grc)
{
	if (grc && grc->hbf_tbl)
		kfree(grc->hbf_tbl);
}

static void grc_set_hw_bdf_tbl(struct nbl_grc *grc, bool host_en, u32 bdf_num, u16 func_id)
{
	grc->resource_ops->set_bdf_func_id_map(grc, host_en, bdf_num, func_id);
}

static inline u32 nbl_get_sd_alignment(struct nbl_grc *grc)
{
	return grc->sd_addr_mode == NBL_HMC_PROFILE_LOW_SPEC_HIGH_EFFICIENCY ?
		SZ_4K : SZ_2M;
}

static u16 nbl_get_obj_sz(u8 obj_type)
{
	int hmc_obj_sz[NBL_HMC_MAX] = {
		NBL_HMC_QPC_SZ,
		NBL_HMC_CQC_SZ,
		NBL_HMC_PBL_SZ,
		NBL_HMC_MRTE_SZ,
		NBL_HMC_SRQC_SZ,
	};

	WARN_ON(obj_type >= NBL_HMC_MAX);

	return hmc_obj_sz[obj_type];
}

static void grc_init_sd_range(struct nbl_grc *grc, u16 function_id)
{
	u32 fn_obj_size = 0;
	u32 sd_size = nbl_get_sd_alignment(grc);
	u32 sd_num;
	u32 *obj_num = (u32 *)&grc->dev_objs[function_id];
	u32 obj_size;
	int i;
	u32 align_size = grc->sd_addr_mode == NBL_HMC_PROFILE_HUGEPAGE ? SZ_2M : NBL_HMC_QPC_SZ;

	for (i = 0; i < NBL_HMC_MAX; i++) {
		obj_size = nbl_get_obj_sz(i);
		fn_obj_size += ALIGN(*obj_num * obj_size, align_size);
		obj_num++;
	}
	sd_num = DIV_ROUND_UP(fn_obj_size, sd_size);

	grc_pr_notice("resv sd_num=0x%x", sd_num);
	grc->hmc_sd_range[function_id].start = function_id * sd_num;
	grc->hmc_sd_range[function_id].cnt = sd_num;
}

static int grc_set_usr_res_profile(struct nbl_grc *grc, u16 fn_id)
{
	struct nbl_obj_cnt *objs = &grc->dev_objs[fn_id];
	struct nbl_grc_res_cfg *res_cfg = &grc->res_cfg;

	objs->qp_num = res_cfg->qp_per_vf;
	if (objs->qp_num > res_cfg->total_qp_cnt) {
		grc_pr_err("grc has not enough qp,req_qp_num=0x%x,available_qps=0x%x\n",
			   objs->qp_num, res_cfg->total_qp_cnt);
		return -EINVAL;
	}

	res_cfg->total_qp_cnt -= objs->qp_num;
	objs->cq_num = objs->qp_num * (hmc_obj_total_cnt.cq_num / hmc_obj_total_cnt.qp_num);
	objs->pble_num = objs->qp_num * (hmc_obj_total_cnt.pble_num / hmc_obj_total_cnt.qp_num);
	objs->mr_num = objs->qp_num * (hmc_obj_total_cnt.mr_num / hmc_obj_total_cnt.qp_num);
	objs->srq_num = objs->qp_num / (hmc_obj_total_cnt.qp_num / hmc_obj_total_cnt.srq_num);

	grc_init_sd_range(grc, fn_id);
	return 0;
}

static void grc_get_function_id(struct nbl_grc *grc, void *req_msg, u16 req_msg_len,
				struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 i;
	u16 func_id;
	struct nbl_hbf_entry *entry;
	struct grc_resp_msg resp_msg;
	struct get_function_id_req *req = GRC_GET_CACHE_MSG_DATA(req_msg);
	int ret;

	grc_pr_debug("get func_id req,host_id=%u,bdf_num=0x%x\n", req->host_id, req->bdf_num);
	for (i = 0; i < grc->hbf_tbl->tbl_size; i++) {
		entry = &grc->hbf_tbl->entries[i];
		if (req->host_id == entry->host_id && req->bdf_num == entry->bdf_num) {
			grc_pr_err("function id already exist,host_id=0x%x,bdf_num=0x%x\n",
				   req->host_id, req->bdf_num);
			func_id = entry->func_id;
			goto vfid_exist;
		}
	}

	if (req->is_pf) {
		func_id = grc->core_dev.real_function;
	} else {
		ret = grc->resource_ops->get_hw_inst_id(grc, NBL_INST_VFID, &func_id);
		if (ret) {
			resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
			resp_msg.msg_len = 1;
			goto func_id_err;
		}
		grc_set_hw_bdf_tbl(grc, true, req->bdf_num, func_id);
	}

	ret = grc_set_usr_res_profile(grc, func_id);
	if (ret) {
		if (!req->is_pf) {
			grc_set_hw_bdf_tbl(grc, false, req->bdf_num, func_id);
			grc->resource_ops->put_hw_inst_id(grc, NBL_INST_VFID, func_id);
		}
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		resp_msg.msg_len = 1;
		goto func_id_err;
	}

	grc_pr_debug("success assign function_id=%u\n", func_id);

	grc->hbf_tbl->entries[func_id].host_id = req->host_id;
	grc->hbf_tbl->entries[func_id].bdf_num = req->bdf_num;
	grc->hbf_tbl->entries[func_id].func_id = func_id;
	grc->hbf_tbl->entries[func_id].valid = true;

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &func_id, sizeof(func_id));
	resp_msg.msg_len = sizeof(func_id) + 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
	grc_pr_debug("get func_id succeed,host_id=%u,bdf_num=0x%x fn_id:%d\n",
		     req->host_id, req->bdf_num, func_id);
	return;

vfid_exist:
	grc_set_hw_bdf_tbl(grc, true, func_id, req->bdf_num);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &func_id, sizeof(func_id));
	resp_msg.msg_len = sizeof(func_id) + 1;
func_id_err:
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_free_function_id(struct nbl_grc *grc, void *req_msg, u16 msg_len,
				 struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 i;
	int ret_val;
	struct nbl_hbf_entry *entry;
	struct grc_resp_msg resp_msg;
	struct free_function_id_req *req = GRC_GET_CACHE_MSG_DATA(req_msg);

	if (req->function_id > NBL_RDMA_CQP_MAX_FUN_ID) {
		grc_pr_err("invalid function_id=%u\n", req->function_id);
		goto invalid_param;
	}

	for (i = 0; i < grc->hbf_tbl->tbl_size; i++) {
		entry = &grc->hbf_tbl->entries[i];
		if (entry->func_id == req->function_id &&
		    entry->host_id == req->host_id &&
		    entry->bdf_num == req->bdf_num && entry->valid) {
			if (!req->is_pf) {
				ret_val = grc->resource_ops->put_hw_inst_id(grc,
									   NBL_INST_VFID,
									   req->function_id);
				if (ret_val)
					goto invalid_param;

				grc_set_hw_bdf_tbl(grc, false, 0, req->function_id);
			}

			grc->res_cfg.total_qp_cnt += grc->res_cfg.qp_per_vf;
			memset(entry, 0, sizeof(*entry));
			resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
			resp_msg.msg_len = 1;
			grc_pr_debug(
				"free_fn_id_req,host_id=0x%x,bdf_num=0x%x,fn_id=%u\n",
				req->host_id, req->bdf_num, req->function_id);

			mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
			memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
			return;
		}
	}

	grc_pr_notice("not match free_fn_id_req,host_id=0x%x,bdf_num=0x%x,fn_id=%u\n",
		      req->host_id, req->bdf_num, req->function_id);

invalid_param:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

bool nbl_func_id_valid(struct nbl_grc *grc, u16 function_id)
{
	int i;

	if (function_id > NBL_RDMA_CQP_MAX_FUN_ID)
		return false;

	for (i = 0; i < grc->hbf_tbl->tbl_size; i++) {
		if (grc->hbf_tbl->entries[i].func_id == function_id &&
		    grc->hbf_tbl->entries[i].valid)
			return true;
	}

	return false;
}

static inline u8 nbl_get_pgsz_type(struct nbl_grc *grc)
{
	return grc->sd_addr_mode == NBL_HMC_PROFILE_HUGEPAGE ? NBL_HMC_HUGEPAGE :
	       NBL_HMC_STANDARD_PAGE;
}

static inline u8 nbl_get_address_level(struct nbl_grc *grc)
{
	return grc->sd_addr_mode == NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY ?
	       NBL_HMC_ADDRESS_LEVEL1 :
	       NBL_HMC_ADDRESS_LEVEL0;
}

static void nbl_fill_voa_tbl(struct nbl_grc *grc, u16 function_id, bool valid)
{
	int i;
	u32 obj_base;
	u16 real_obj_sz;
	u32 obj_total_sz;
	int voa_len = 0;
	u32 align_sz = NBL_HMC_QPC_SZ;
	u8 voa_str[VOA_TBL_STR_LEN] = {0};
	u32 sd_sz = nbl_get_sd_alignment(grc);
	u32 *obj_num = (u32 *)&grc->dev_objs[function_id];
	union nbl_hmc_voa_entry *voa_ent = grc->voa_tbl[function_id];
	struct nbl_hmc_sd_range *sd_range = &grc->hmc_sd_range[function_id];

	if (!valid) {
		memset(voa_ent, 0, sizeof(grc->voa_tbl[function_id]));
		return;
	}

	for (i = 0; i < NBL_HMC_MAX; i++) {
		real_obj_sz = nbl_get_obj_sz(i);
		voa_ent[i].key.obj_sz = ilog2(real_obj_sz);
		voa_ent[i].key.page_mode = nbl_get_address_level(grc);
		voa_ent[i].key.page_sz = nbl_get_pgsz_type(grc);
		voa_ent[i].key.obj_max_cnt = *obj_num;
		voa_ent[i].key.obj_idx_start = voa_ent[i].key.obj_max_cnt * function_id;
		if (i == NBL_HMC_PBL)
			voa_ent[i].key.obj_idx_start = 0;
		voa_ent[i].key.valid = 1;
		if (i == 0 && function_id == NBL_RDMA_FIRST_FUNCTION_ID) {
			obj_base = 0;
		} else {
			if (i == 0 && function_id != NBL_RDMA_FIRST_FUNCTION_ID) {
				obj_base = sd_range->start * sd_sz;
			} else {
				if (grc->sd_addr_mode == NBL_HMC_ADDRESS_LEVEL0)
					align_sz = SZ_2M;

				obj_total_sz = voa_ent[i - 1].key.obj_max_cnt *
					(1 << voa_ent[i - 1].key.obj_sz);
				obj_base =
					ALIGN((voa_ent[i - 1].key.obj_ba << NBL_HMC_MAX_OBJ_LOG_SZ)
					      + obj_total_sz, align_sz);
			}
		}

		voa_ent[i].key.obj_ba = obj_base >> ilog2(NBL_HMC_QPC_SZ);
		obj_num++;

		voa_len += snprintf(voa_str + voa_len, sizeof(voa_str) - voa_len,
				    VOA_TBL_ENTRY_FORMAT_NEW, i, voa_ent[i].key.valid,
				    voa_ent[i].key.obj_ba, voa_ent[i].key.obj_max_cnt,
				    voa_ent[i].key.obj_idx_start, voa_ent[i].key.obj_sz,
				    voa_ent[i].key.page_sz, voa_ent[i].key.page_mode);
	}

	grc_pr_debug("%s", voa_str);
}

static int nbl_setup_voa(struct nbl_grc *grc, u16 func_id, bool valid)
{
	union nbl_hmc_voa_entry *voa_ent = grc->voa_tbl[func_id];
	int ret_val;
	u64 temp = 0;
	__be64 cmd_in[NBL_CMD_INPUT_SIZE / sizeof(u64)] = {0};
	__be64 cmd_out[NBL_CMD_OUTPUT_SIZE / sizeof(u64)] = {0};

	nbl_fill_voa_tbl(grc, func_id, valid);

	nbl_64bit_write(cmd_in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_UPDATE_VOA);
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_VFID, func_id);
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_QPC_HIGH, voa_ent[NBL_HMC_QP].data[VOA_ENT_LAST_DW]);

	memcpy(&temp, voa_ent[NBL_HMC_QP].data, sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_QPC_LOW, temp);

	memcpy(&temp, &voa_ent[NBL_HMC_CQ].data[VOA_ENT_MIDDLE_DW], sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_CQC_HIGH, temp);

	nbl_64bit_write(cmd_in, NBL_CQP_VOA_CQC_LOW, voa_ent[NBL_HMC_CQ].data[VOA_ENT_FIRST_DW]);
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_PBL_HIGH, voa_ent[NBL_HMC_PBL].data[VOA_ENT_LAST_DW]);

	memcpy(&temp, &voa_ent[NBL_HMC_PBL], sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_PBL_LOW, temp);

	memcpy(&temp, &voa_ent[NBL_HMC_MR].data[VOA_ENT_MIDDLE_DW], sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_MR_HIGH, temp);

	nbl_64bit_write(cmd_in, NBL_CQP_VOA_MR_LOW,
			voa_ent[NBL_HMC_MR].data[VOA_ENT_FIRST_DW]);
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_SRQ_HIGH,
			voa_ent[NBL_HMC_SRQ].data[VOA_ENT_LAST_DW]);

	memcpy(&temp, &voa_ent[NBL_HMC_SRQ], sizeof(temp));
	nbl_64bit_write(cmd_in, NBL_CQP_VOA_SRQ_LOW, temp);

	ret_val = grc_cmd_exec(grc, cmd_in, NBL_CMD_INPUT_SIZE, cmd_out, NBL_CMD_OUTPUT_SIZE);
	if (ret_val) {
		grc_pr_err("set fn_id=%u voa tbl cqp cmd err=%d\n", func_id, ret_val);
		return ret_val;
	}

	grc_pr_notice("set voa tbl cmd for func_id=%u success\n", func_id);
	return 0;
}

static void grc_set_voa_tbl(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp)
{
	int ret_val;
	u16 func_id;
	struct grc_resp_msg resp_msg;

	func_id = *(u16 *)GRC_GET_CACHE_MSG_DATA(msg);

	if (!nbl_func_id_valid(grc, func_id)) {
		grc_pr_err("invalid function_id=%u\n", func_id);
		goto err_exit;
	}

	ret_val = nbl_setup_voa(grc, func_id, true);
	if (ret_val)
		goto err_exit;

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);

	return;

err_exit:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_clear_sd_range(struct nbl_grc *grc, u16 fn_id)
{
	struct nbl_hmc_sd_range *sd_range = &grc->hmc_sd_range[fn_id];

	memset(sd_range, 0, sizeof(*sd_range));
	grc->resource_ops->set_sd_range(grc, fn_id, sd_range->start, sd_range->cnt,
					 false);
}

static void grc_destroy_voa_tbl(struct nbl_grc *grc, void *msg, u16 msg_len,
				struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 function_id = *(u16 *)GRC_GET_CACHE_MSG_DATA(msg);
	int ret_val;
	struct grc_resp_msg resp_msg;

	if (!nbl_func_id_valid(grc, function_id)) {
		grc_pr_err("invalid function_id=%u\n", function_id);
		goto destroy_voa_err;
	}

	ret_val = nbl_setup_voa(grc, function_id, false);
	if (ret_val)
		goto destroy_voa_err;

	grc_clear_sd_range(grc, function_id);
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);

	return;

destroy_voa_err:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_get_voa_tbl(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 function_id = *(u16 *)GRC_GET_CACHE_MSG_DATA(msg);
	union nbl_hmc_voa_entry *voa_ent;
	u32 data_len;
	struct grc_resp_msg resp_msg;

	if (!nbl_func_id_valid(grc, function_id)) {
		grc_pr_err("invalid function_id=%u\n", function_id);
		goto query_voa_err;
	}

	voa_ent = grc->voa_tbl[function_id];
	data_len = sizeof(grc->voa_tbl[function_id]);
	memcpy(resp_msg.msg + 1, voa_ent, data_len);
	resp_msg.msg_len = data_len + 1;

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);

	return;

query_voa_err:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_set_sd_register(struct nbl_grc *grc, void *msg, u16 msg_len,
				struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 function_id = *(u16 *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;
	struct nbl_hmc_sd_range *sdr = &grc->hmc_sd_range[function_id];

	if (!nbl_func_id_valid(grc, function_id)) {
		grc_pr_err("%s invalid function_id=%u\n", __func__, function_id);
		goto err_exit;
	}

	grc->resource_ops->set_sd_range(grc, function_id, sdr->start, sdr->cnt, true);
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
	return;

err_exit:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_get_sd_range(struct nbl_grc *grc, void *msg, u16 msg_len,
			     struct nbl_chan_rdma_resp *mbx_resp)
{
	struct nbl_hmc_sd_range sd_range;
	u16 function_id = *(u16 *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;
	struct nbl_hmc_sd_range *sdr = grc->hmc_sd_range;

	if (!nbl_func_id_valid(grc, function_id)) {
		grc_pr_err("%s invalid function_id=%u\n", __func__, function_id);
		goto err_sd_range;
	}

	grc->resource_ops->get_sd_range(grc, function_id, &sd_range.start,
					 &sd_range.cnt);

	if (sd_range.start != sdr[function_id].start ||
	    sd_range.cnt != sdr[function_id].cnt) {
		grc_pr_err("sw sd_range.start=%u,cnt=%u not equal hw sd_range(%u %u),fn_id%u\n",
			   sdr[function_id].start, sdr[function_id].cnt,
			   sd_range.start, sd_range.cnt, function_id);
		goto err_sd_range;
	}

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &sd_range, sizeof(sd_range));
	resp_msg.msg_len = sizeof(sd_range) + 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);

	return;

err_sd_range:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_get_init_params(struct nbl_grc *grc, void *msg, u16 msg_len,
				struct nbl_chan_rdma_resp *mbx_resp)
{
	struct nbl_init_params init_params = {0};
	struct grc_resp_msg resp_msg;

	init_params.sd_addr_mode = grc->sd_addr_mode;
	init_params.atomic_cap = grc->atomic_cap;
	init_params.devx_umem_num = grc->devx_umem_num;

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &init_params, sizeof(init_params));
	resp_msg.msg_len = sizeof(init_params) + 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static bool nbl_grc_raw_reg_offset_valid(struct nbl_grc *grc, u32 offset)
{
	resource_size_t bar0_size = pci_resource_len(grc->core_dev.pdev, 0);

	return IS_ALIGNED(offset, sizeof(u32)) && bar0_size >= sizeof(u32) &&
		offset <= bar0_size - sizeof(u32);
}

static void grc_write_reg(struct nbl_grc *grc, void *msg, u16 msg_len,
			  struct nbl_chan_rdma_resp *mbx_resp)
{
	void __iomem *regs_addr;
	struct rw_dw_reg *req = (struct rw_dw_reg *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg = {};

	if (!nbl_grc_raw_reg_offset_valid(grc, req->offset)) {
		grc_pr_err("invalid BAR0 register offset 0x%x\n", req->offset);
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		goto send_resp;
	}

	regs_addr = grc->core_dev.hw_addr + req->offset;
#if NBL_RW_RDMA_REG
	writel(req->data, regs_addr);
#endif
	grc_pr_debug("write reg addr %p, offset 0x%x, val 0x%x\n",
		      regs_addr, req->offset, req->data);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;

send_resp:
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_read_reg(struct nbl_grc *grc, void *msg, u16 msg_len,
			 struct nbl_chan_rdma_resp *mbx_resp)
{
	void __iomem *regs_addr;
	struct rw_dw_reg *req = (struct rw_dw_reg *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg = {};

	if (!nbl_grc_raw_reg_offset_valid(grc, req->offset)) {
		grc_pr_err("invalid BAR0 register offset 0x%x\n", req->offset);
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		resp_msg.msg_len = 1;
		goto send_resp;
	}

	regs_addr = grc->core_dev.hw_addr + req->offset;
#if NBL_RW_RDMA_REG
	req->data = readl(regs_addr);
#endif
	grc_pr_debug("read reg addr %p, offset 0x%x, get val 0x%x\n",
		      regs_addr, req->offset, req->data);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, req, sizeof(*req));
	resp_msg.msg_len = sizeof(*req) + 1;

send_resp:
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_vf_cqp_init(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp)
{
	struct cqp_init_req *req =
		(struct cqp_init_req *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;

	grc_pr_debug("grc recv function_id=%u,phys_addr=0x%llx,cmd_max_num=%u,enable=%u",
		     req->function_id, req->phys_addr, req->cmd_max_num, req->enable);
	grc->resource_ops->set_cqp_info(grc, req->function_id, req->phys_addr,
			       req->cmd_max_num, req->enable ? true : false);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_set_pcomplete_host(struct nbl_grc *grc, void *msg, u16 msg_len,
				   struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct notify_info_req *req = GRC_GET_CACHE_MSG_DATA(msg);
	u16 pcie_fn_id = req->pcie_fn_id;

	grc->resource_ops->set_rdma_pfid_map_tbl(grc, pcie_fn_id,
						  req->function_id, req->valid);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void nbl_grc_cc_params_set(struct nbl_grc *grc, void *msg, u16 msg_len,
				  struct nbl_chan_rdma_resp *mbx_resp)
{
	u32 offset;
	u32 var;
	int data_len = 0;
	u8 *cc_msg;
	struct grc_resp_msg resp_msg;

	cc_msg = (u8 *)GRC_GET_CACHE_MSG_DATA(msg);
	offset = *(u32 *)cc_msg;
	data_len += sizeof(offset);
	var = *(u32 *)(cc_msg + data_len);
	data_len += sizeof(var);
	grc_pr_debug("cc params set offset:%u, var:%u\n", offset, var);
	/* call callback interface to write register */
	grc->resource_ops->set_cc_params(grc, offset, var);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void nbl_grc_set_vf_enable(struct nbl_grc *grc, void *msg, u16 msg_len,
				  struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct set_hdma_vf_enable_req *vf_enable_req =
		(struct set_hdma_vf_enable_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc_pr_debug("hdma set vf enable,function_id=%u,enable=%u\n",
		      vf_enable_req->function_id, vf_enable_req->enable);

	if (!nbl_func_id_valid(grc, vf_enable_req->function_id)) {
		grc_pr_err("hdma set vf enable,invalid function_id=%u\n",
			   vf_enable_req->function_id);
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		resp_msg.msg_len = 1;
		goto exit;
	}

	grc->resource_ops->set_vf_enable(grc, vf_enable_req->function_id,
					 vf_enable_req->enable);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

exit:
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_set_rdma_dsch_info(struct nbl_grc *grc, void *msg, u16 msg_len,
				   struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct set_rdma_dsch_req *req = (struct set_rdma_dsch_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc->dsch_ops->set_rdma_dsch(grc, req->function_id, req->host_id,
				req->dport_id, req->is_valid);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
	grc_pr_debug("set_rdma_dsch_info success,function_id=%u,host_id=%u,valid=%u\n",
		      req->function_id, req->host_id, req->is_valid);
}

static void grc_update_rdma_dsch_info(struct nbl_grc *grc, void *msg, u16 msg_len,
				      struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct set_rdma_dsch_req *req = (struct set_rdma_dsch_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc->dsch_ops->update_rdma_dsch(grc, req->function_id, req->host_id,
				   req->dport_id, req->is_valid);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
	grc_pr_debug("update_rdma_dsch dport_id=%u,function_id=%u,host_id=%u,valid=%u\n",
		      req->dport_id, req->function_id, req->host_id, req->is_valid);
}

static void grc_get_armcq_flush_state(struct nbl_grc *grc, void *msg, u16 msg_len,
				      struct nbl_chan_rdma_resp *mbx_resp)
{
	int status;
	u32 check_base;
	struct get_armcq_flush_status_req *req =
		(struct get_armcq_flush_status_req *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;

	check_base = (req->function_id < 32) ? ASIC_ARMCQ_L_STATUS : ASIC_ARMCQ_H_STATUS;
	status = grc->resource_ops->hw_get_flush_status(grc, req->function_id,
							 check_base);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &status, sizeof(status));
	resp_msg.msg_len = sizeof(status) + 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_cqp_cmd_exec(struct nbl_grc *grc, void *msg, u16 msg_len,
			     struct nbl_chan_rdma_resp *mbx_resp)
{
	int ret;
	struct grc_resp_msg resp_msg;
	struct grc_cqp_cmd_req *req = (struct grc_cqp_cmd_req *)GRC_GET_CACHE_MSG_DATA(msg);
	__be64 cmd_out[NBL_CMD_OUTPUT_SIZE / sizeof(u64)] = {0};

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	ret = grc_cmd_exec(grc, req->cmd_in, req->in_size, cmd_out, sizeof(cmd_out));
	if (ret) {
		grc_pr_err("grc exec cqp cmd ret=%d\n", ret);
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	}

	resp_msg.msg_len = 1;
	memcpy(resp_msg.msg + 1, cmd_out, sizeof(cmd_out));
	resp_msg.msg_len += sizeof(cmd_out);
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_set_dump_cfg(struct nbl_grc *grc, void *msg, u16 msg_len,
			     struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct set_vf_dump_req *req = (struct set_vf_dump_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc->resource_ops->set_hw_dump_cfg(grc, req->vsi_id, req->rx_vlan_vsi_id,
				  ARRAY_SIZE(req->rx_vlan_vsi_id), req->function_id,
				  req->enable_flag, req->is_lag);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_set_vfid_vsi_map(struct nbl_grc *grc, void *msg, u16 msg_len,
				 struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct set_vfid_vsi_map_req *req =
		(struct set_vfid_vsi_map_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc_pr_debug("grc set_vfid_vsi_map,function_id=%u,vsi_id=%u,valid=%u\n",
		     req->function_id, req->vsi_id, req->valid);

	grc->resource_ops->set_vfid_vsi_map(grc, req->function_id, req->vsi_id,
					    req->valid);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_ena_rdma_intrl(struct nbl_grc *grc, void *msg, u16 msg_len,
			       struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct nbl_ena_rdma_intrl_req *req =
		(struct nbl_ena_rdma_intrl_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc_pr_debug("grc nbl_ena_rdma_intrl,global_msix_i=%u,devfn=0x%x,bus=0x%x,valid=%u\n",
		      req->msix_global_idx, req->devfn, req->bus, req->valid);

	grc->resource_ops->ena_rdma_intrl(grc, req->msix_global_idx,
				 req->devfn, req->bus, req->valid);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_set_glo_q_pf_map(struct nbl_grc *grc, void *msg, u16 msg_len,
				 struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 pf_id = grc->core_dev.real_function;
	u16 function_id = *(u16 *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;

	grc->resource_ops->set_hw_pf_tbl(grc, function_id, pf_id);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_clear_cache(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct clear_cache_req *req =
		(struct clear_cache_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc_pr_notice("clear cache type %u\n", req->cache_type);
	grc->resource_ops->clear_hw_cache(grc, req->cache_type);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_mbx_msg_process(struct nbl_grc *grc, void *msg, u16 msg_len,
			 struct nbl_chan_rdma_resp *mbx_resp)
{
	u8 op_code;

	op_code = grc_get_msg_opcode(msg);
	grc_pr_debug("grc recv msg op_code=%u\n", op_code);
	switch (op_code) {
	case GRC_MSG_OP_REGISTER_CLIENT:
		grc_add_vf_flr_client(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_UNREGISTER_CLIENT:
		grc_del_vf_flr_client(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_GET_FUNCTION_ID:
		grc_get_function_id(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_FREE_FUNC_ID:
		grc_free_function_id(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SET_VOA:
		grc_set_voa_tbl(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_DESTROY_VOA:
		grc_destroy_voa_tbl(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_GET_VOA_TBL:
		grc_get_voa_tbl(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SET_SD_RANGE:
		grc_set_sd_register(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_GET_SD_RANGE:
		grc_get_sd_range(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_GET_INIT_PARAM:
		grc_get_init_params(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_CQP_INIT:
		grc_vf_cqp_init(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_WRITE_REG:
		grc_write_reg(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_READ_REG:
		grc_read_reg(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_ADD_SRC_ADDR_INFO:
		grc_add_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_DEL_SRC_ADDR_INFO:
		grc_del_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SEND_SRC_ADDR_INFO:
		grc_send_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_STAT_ID_ADD:
		nbl_grc_add_stat_id(msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_STAT_ID_DEL:
		nbl_grc_del_stat_id(msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_STAT_ID_MOD:
		nbl_grc_mod_stat_id(msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_USED_CNT_GET:
		nbl_grc_get_used_cnt(msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_HW_STAT_GET:
		grc_hw_stat_read(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_HW_STAT_CLEAR:
		grc_hw_stat_clear(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_ERRCODE_EN:
		grc_hw_stat_errcode_enable(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SET_NOTIFY_INFO:
		grc_set_pcomplete_host(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SET_DSCH:
		grc_set_rdma_dsch_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_CC_REG_SET:
		nbl_grc_cc_params_set(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SET_VF_ENABLE:
		nbl_grc_set_vf_enable(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SET_VFID_VSI_MAP:
		grc_set_vfid_vsi_map(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_ENA_RDMA_INTRL:
		grc_ena_rdma_intrl(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_UPDATE_DSCH:
		grc_update_rdma_dsch_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_QUERY_FMR_NOFENCE:
		break;
	case GRC_MSG_OP_SET_GLO_Q_VF_PF_MAP:
		grc_set_glo_q_pf_map(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_GET_SRC_ADDR_INFO:
		grc_get_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_GET_ARMCQ_FLUSH_STATUS:
		grc_get_armcq_flush_state(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_GRC_CQP_CMD:
		grc_cqp_cmd_exec(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SET_VF_DUMP_CFG:
		grc_set_dump_cfg(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_CHK_GID_IN_SRC_ADDR:
		grc_chk_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_UPDATE_IDX_SRC_ADDR:
		grc_update_idx_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_CLEAR_CACHE:
		grc_clear_cache(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_PRINT_SRC_ADDR_TBL:
		grc_print_src_addr_tbl(grc, msg, msg_len, mbx_resp);
		break;
	default:
		grc_pr_err("unsupported op_code=%u\n", op_code);
	}
}

static void grc_abnormal_event_process(struct nbl_grc *grc)
{
	queue_work(grc->admin_wq, &grc->abnormal_task);
}

static int grc_abn_event(struct notifier_block *notifier,
			 unsigned long event, void *data)
{
	struct nbl_grc *grc = container_of(notifier, struct nbl_grc,
					  grc_abn_nb);

	if (event != NBL_CORE_EVT_ABN)
		return NOTIFY_DONE;

	grc_abnormal_event_process(grc);
	return NOTIFY_OK;
}

static u32 g_queue_info[NBL_SD_TYPE_MAX] = {
	NBL_RQDB_ARM_SIZE,
	NBL_TQ_RTO_SIZE,
	NBL_DBQ_SIZE,
	NBL_TQ_RNR_SIZE
};

static int nbl_alloc_global_queue_mem(struct nbl_grc *grc, u32 queue_len,
				      struct nbl_gl_sdtbl_info *sd_info)
{
	u16 idx;
	int err_code;
	u32 alloc_len = SZ_2M;
	u32 len = ALIGN(queue_len, SZ_2M);
	struct device *dma_dev = NBL_COREDEV_TO_DMA_DEV(&grc->core_dev);

	sd_info->max_num = len / SZ_2M;
	sd_info->list = kcalloc(sd_info->max_num, sizeof(struct nbl_dma_mem), GFP_KERNEL);
	if (!sd_info->list)
		return -ENOMEM;

	for (idx = 0; idx < sd_info->max_num; idx++) {
		sd_info->list[idx].va = dma_alloc_coherent(dma_dev, alloc_len,
							   &sd_info->list[idx].pa, GFP_KERNEL);
		if (!sd_info->list[idx].va) {
			err_code = -ENOMEM;
			goto free_sd_list;
		}

		grc_pr_debug("[%u]alloc_len=0x%x,va=%p,pa=0x%llx\n", idx, alloc_len,
			      sd_info->list[idx].va, (u64)sd_info->list[idx].pa);
		sd_info->list[idx].size = alloc_len;
	}

	sd_info->cnt = sd_info->max_num;

	return 0;

free_sd_list:
	while (idx--) {
		struct nbl_dma_mem *mem = &sd_info->list[idx];

		dma_free_coherent(dma_dev, mem->size, mem->va, mem->pa);
	}
	kfree(sd_info->list);
	return err_code;
}

static void nbl_free_global_queue_mem(struct nbl_grc *grc, struct nbl_gl_sdtbl_info *sd_info)
{
	u16 idx;
	struct nbl_dma_mem *mem;
	struct device *dma_dev = NBL_COREDEV_TO_DMA_DEV(&grc->core_dev);

	for (idx = 0; idx < sd_info->cnt; idx++) {
		mem = &sd_info->list[idx];
		dma_free_coherent(dma_dev, mem->size, mem->va, mem->pa);
	}

	kfree(sd_info->list);
	memset(sd_info, 0, sizeof(struct nbl_gl_sdtbl_info));
}

static int nbl_fill_glo_sd_buf(struct nbl_grc *grc, u64 *sd_addr_buf)
{
	int i, j;
	u16 k = 0;
	u16 hw_sd_idx;
	u64 sd_entry;
	struct nbl_gl_sdtbl_info *sd_info;
	struct nbl_dma_mem *glo_sd_mem;

	for (i = 0; i < NBL_SD_TYPE_MAX; i++) {
		sd_info = &grc->glo_sd_res[i];
		for (j = 0; j < sd_info->cnt; j++) {
			hw_sd_idx = j + k;
			glo_sd_mem = &sd_info->list[j];
			sd_entry = cpu_to_be64(glo_sd_mem->pa | NBL_SD_VALID);
			memcpy(sd_addr_buf + hw_sd_idx, &sd_entry, sizeof(sd_entry));
			grc_pr_debug("[%u] big_endian sd_entry=0x%llx", hw_sd_idx, sd_entry);
			if (hw_sd_idx > NBL_MAX_GLOBAL_SD_CNT) {
				grc_pr_err("global sd should not over than hw tbl(%u)",
					   NBL_MAX_GLOBAL_SD_CNT);
				return -ENOMEM;
			}
		}

		k += NBL_HW_MAX_GLO_QUEUE_SD_NUM;
	}

	return 0;
}

static int nbl_update_hw_sdtbl_with_buf(struct nbl_grc *grc, u8 sd_type, u16 sd_entry_num,
					u32 hw_sd_idx, dma_addr_t buf_pa, u64 *buf_va)
{
	int err_code = 0;
	__be64 *in;
	u64 sd_entry;
	int i;
	u32 sd_offset = SD_ENTRY_BYTE_OFFSET / SD_ENTRY_SIZE;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_UPDATE_SD);
	nbl_64bit_write(in, NBL_CQPSQ_SD_TYPE, sd_type);
	nbl_64bit_write(in, NBL_CQPSQ_SD_NUM, sd_entry_num);
	nbl_64bit_write(in, NBL_CQPSQ_SD_START, hw_sd_idx);

	nbl_64bit_write(in, NBL_CQPSQ_SD_BUF_ADDR, buf_pa);

	if (sd_entry_num <= MAX_INLINE_SD_NUM_PER_CMD && buf_va) {
		for (i = 0; i < sd_entry_num; i++) {
			sd_entry = *(buf_va + i);
			nbl_64bit_write(in + sd_offset + i,
					NBL_CQPSQ_SD_ENTRY, be64_to_cpu(sd_entry));
		}
	}

	err_code = grc_cmd_exec(grc, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		grc_pr_err("update glo sd_cmd failed,err=%d,hw_sd_idx=%d",
			   err_code, hw_sd_idx);
	kfree(in);
	return err_code;
}

static int nbl_set_hw_glo_sdtbl(struct nbl_grc *grc, bool is_add)
{
	u16 k = NBL_MAX_GLOBAL_SD_CNT;
	u32 sd_num;
	int err_code;
	u64 *sd_addr_buf;
	struct nbl_dma_mem sd_buf;
	struct device *dma_dev = NBL_COREDEV_TO_DMA_DEV(&grc->core_dev);
	u16 hw_sd_idx = grc->core_dev.real_function * NBL_MAX_GLOBAL_SD_CNT;

	sd_buf.size = SZ_4K;
	sd_buf.va = dma_alloc_coherent(dma_dev, sd_buf.size, &sd_buf.pa, GFP_KERNEL);
	if (!sd_buf.va)
		return -ENOMEM;

	sd_addr_buf = sd_buf.va;
	sd_num = sd_buf.size / sizeof(u64);

	if (is_add) {
		err_code = nbl_fill_glo_sd_buf(grc, sd_addr_buf);
		if (err_code)
			goto fill_sd_err;
	}

	err_code = nbl_update_hw_sdtbl_with_buf(grc, NBL_CQP_CMD_SD_TYPE_GLOBAL, k, hw_sd_idx,
						sd_buf.pa, sd_buf.va);
	if (err_code) {
		grc_pr_err("update global sd_tbl err=%d,is_add=%u", err_code, is_add);
		goto fill_sd_err;
	}

	dma_free_coherent(dma_dev, sd_buf.size, sd_buf.va, sd_buf.pa);
	return 0;

fill_sd_err:
	dma_free_coherent(dma_dev, sd_buf.size, sd_buf.va, sd_buf.pa);
	return err_code;
}

static int nbl_grc_global_sd_init(struct nbl_grc *grc)
{
	int idx;
	int err_code = 0;
	struct nbl_gl_sdtbl_info *glo_sd_res;

	for (idx = 0; idx < NBL_SD_TYPE_MAX; idx++) {
		glo_sd_res = &grc->glo_sd_res[idx];
		err_code = nbl_alloc_global_queue_mem(grc, g_queue_info[idx], glo_sd_res);
		if (err_code)
			goto free_gl_sd;
	}

	err_code = nbl_set_hw_glo_sdtbl(grc, true);
	if (err_code)
		goto free_gl_sd;

	return 0;
free_gl_sd:
	while (idx--) {
		glo_sd_res = &grc->glo_sd_res[idx];
		nbl_free_global_queue_mem(grc, glo_sd_res);
	}
	return err_code;
}

static void nbl_grc_global_sd_deinit(struct nbl_grc *grc)
{
	int idx;
	int err_code;
	struct nbl_gl_sdtbl_info *glo_sd_res;

	err_code = nbl_set_hw_glo_sdtbl(grc, false);
	if (err_code)
		grc_pr_err("free hw global sdtbl err=%d\n", err_code);

	for (idx = 0; idx < NBL_SD_TYPE_MAX; idx++) {
		glo_sd_res = &grc->glo_sd_res[idx];
		nbl_free_global_queue_mem(grc, glo_sd_res);
	}
}

static void grc_set_admin_cqp_bdf_tbl(struct nbl_grc *grc, bool enable)
{
	u32 bdf_num;
	struct nbl_core_export *core_info = &grc->core_dev;

	bdf_num = PCI_DEVID(core_info->real_bus,
				 PCI_DEVFN(core_info->real_dev,
					   core_info->real_function));
	grc_pr_debug("admin pf bdf_num=0x%x\n", bdf_num);

	grc_set_hw_bdf_tbl(grc, enable, bdf_num, core_info->real_function);
}

static void nbl_set_admin_vf_enable(struct nbl_grc *grc, u8 enable)
{
	grc->resource_ops->set_vf_enable(grc, grc->core_dev.real_function, enable);
}

static void nbl_grc_abnormal_event_handler(struct work_struct *work)
{
	struct nbl_grc *grc = container_of(work, struct nbl_grc, abnormal_task);

	grc->resource_ops->get_abnormal_event(grc);
}

static int nbl_fill_core_dev_info(struct nbl_grc *grc, struct nbl_core_export *core_info)
{
	grc->core_dev = *core_info;
	grc->pf_num = core_info->eth_mode;

	grc->sd_addr_mode = core_info->rdma_mem_type;
	grc_pr_notice("get sd_addr_mode=%u from nbl_core, set default\n", grc->sd_addr_mode);
	if (grc->sd_addr_mode != NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY &&
	    grc->sd_addr_mode != NBL_HMC_PROFILE_HUGEPAGE) {
		grc_pr_warn("invalid sd addr mode, set default\n");
		grc->sd_addr_mode = NBL_HMC_PROFILE_HUGEPAGE;
	}

	return 0;
}

static const struct nbl_grc_product_desc *nbl_grc_product_lookup(u16 device_id)
{
	switch (device_id) {
	case ASIC_V2R1_PF_DEVICE_ID:
	case DRACO_RDMA_PF_START_DEVICE_ID...DRACO_RDMA_PF_END_DEVICE_ID:
		return &grc_product_descs[NBL_GRC_PRODUCT_DRACO];
	case ORION_RDMA_PF_DEVICE_ID:
		return &grc_product_descs[NBL_GRC_PRODUCT_ORION];
	default:
		return NULL;
	}
}

static bool nbl_grc_product_ops_valid(const struct nbl_grc_product_desc *product)
{
	const struct nbl_grc_resource_ops *resource_ops = product->resource_ops;
	const struct nbl_grc_dsch_ops *dsch_ops = product->dsch_ops;
	const struct nbl_grc_stat_ops *stat_ops = product->stat_ops;
	const struct nbl_grc_global_ops *global_ops = product->global_ops;

	return resource_ops && resource_ops->set_sd_range && resource_ops->get_sd_range &&
		resource_ops->set_bdf_func_id_map && resource_ops->set_hw_pf_tbl &&
		resource_ops->set_src_addr_info && resource_ops->set_cqp_info &&
		resource_ops->set_cqp_pi && resource_ops->set_rdma_pfid_map_tbl &&
		resource_ops->set_cc_params && resource_ops->set_vf_enable &&
		resource_ops->set_vfid_vsi_map && resource_ops->ena_rdma_intrl &&
		resource_ops->get_abnormal_event && resource_ops->get_hw_inst_id &&
		resource_ops->put_hw_inst_id && resource_ops->hw_get_flush_status &&
		resource_ops->set_hw_dump_cfg && resource_ops->clear_hw_cache &&
		dsch_ops && dsch_ops->set_rdma_dsch && dsch_ops->update_rdma_dsch &&
		stat_ops && stat_ops->set_hw_stat && stat_ops->get_hw_stat &&
		stat_ops->enable_errcode_hw_stat && stat_ops->get_hw_status &&
		global_ops && global_ops->get_hw_global_cfg_flag &&
		global_ops->set_hw_global_cfg;
}

static bool nbl_grc_base_valid(u32 base, resource_size_t bar0_size)
{
	return base && IS_ALIGNED(base, sizeof(u32)) && base < bar0_size;
}

static bool nbl_grc_abnormal_layout_valid(
		const struct nbl_grc_register_layout *regs,
		resource_size_t bar0_size)
{
	u32 i;

	if (!regs->abnormal_modules || !regs->abnormal_module_count ||
	    regs->abnormal_module_count > NBL_GRC_ABNORMAL_EVENT_BITS)
		return false;

	for (i = 0; i < regs->abnormal_module_count; i++) {
		const struct nbl_grc_abnormal_module *module =
			&regs->abnormal_modules[i];

		if (!module->name ||
		    !nbl_grc_base_valid(module->status_addr, bar0_size))
			return false;
	}

	return true;
}

static bool nbl_grc_cache_layout_valid(
		const struct nbl_grc_register_layout *regs,
		resource_size_t bar0_size)
{
	u32 i;

	if (!regs->caches || !regs->cache_count)
		return false;

	for (i = 0; i < regs->cache_count; i++) {
		const struct nbl_grc_cache_layout *cache = &regs->caches[i];

		if (!cache->depth ||
		    !nbl_grc_base_valid(cache->low_threshold_addr, bar0_size) ||
		    !nbl_grc_base_valid(cache->high_threshold_addr, bar0_size) ||
		    !nbl_grc_base_valid(cache->almost_full_threshold_addr,
					bar0_size))
			return false;
	}

	return true;
}

static bool nbl_grc_register_layout_valid(struct nbl_grc *grc,
					  const struct nbl_grc_register_layout *regs)
{
	resource_size_t bar0_size = pci_resource_len(grc->core_dev.pdev, 0);

	return regs && bar0_size &&
		nbl_grc_base_valid(regs->rdma_top_base, bar0_size) &&
		nbl_grc_base_valid(regs->cqpp_base, bar0_size) &&
		nbl_grc_base_valid(regs->hdma_base, bar0_size) &&
		nbl_grc_base_valid(regs->txp_base, bar0_size) &&
		nbl_grc_base_valid(regs->txmr_base, bar0_size) &&
		nbl_grc_base_valid(regs->txm_base, bar0_size) &&
		nbl_grc_base_valid(regs->rxp_base, bar0_size) &&
		nbl_grc_base_valid(regs->raqp_base, bar0_size) &&
		nbl_grc_base_valid(regs->ceaq_base, bar0_size) &&
		nbl_grc_base_valid(regs->qpcc_base, bar0_size) &&
		nbl_grc_base_valid(regs->cqcc_base, bar0_size) &&
		nbl_grc_base_valid(regs->mrtc_base, bar0_size) &&
		nbl_grc_base_valid(regs->sqrqec_base, bar0_size) &&
		nbl_grc_base_valid(regs->stat_base, bar0_size) &&
		nbl_grc_base_valid(regs->srqc_base, bar0_size) &&
		nbl_grc_base_valid(regs->cc_base, bar0_size) &&
		nbl_grc_base_valid(regs->ntfqp_base, bar0_size) &&
		nbl_grc_base_valid(regs->dsch_base, bar0_size) &&
		nbl_grc_base_valid(regs->uqm_base, bar0_size) &&
		nbl_grc_base_valid(regs->pcomp_base, bar0_size) &&
		nbl_grc_base_valid(regs->ped_base, bar0_size) &&
		nbl_grc_base_valid(regs->epro_base, bar0_size) &&
		nbl_grc_base_valid(regs->ipro_base, bar0_size) &&
		nbl_grc_base_valid(regs->top_ctrl_base, bar0_size) &&
		nbl_grc_abnormal_layout_valid(regs, bar0_size) &&
		nbl_grc_cache_layout_valid(regs, bar0_size);
}

static int nbl_grc_product_bind(struct nbl_grc *grc)
{
	const struct nbl_grc_product_desc *product;
	u16 device_id = grc->core_dev.pdev->device;

	product = nbl_grc_product_lookup(device_id);
	if (!product) {
		grc_pr_err("device id [%#x] not supported", device_id);
		return -ENODEV;
	}

	if (!product->name || product->id >= NBL_GRC_PRODUCT_MAX ||
	    !nbl_grc_register_layout_valid(grc, product->regs) ||
	    !nbl_grc_product_ops_valid(product)) {
		grc_pr_err("invalid GRC product descriptor for device [%#x]", device_id);
		return -EINVAL;
	}

	grc->product = product;
	grc->resource_ops = product->resource_ops;
	grc->dsch_ops = product->dsch_ops;
	grc->stat_ops = product->stat_ops;
	grc->global_ops = product->global_ops;
	grc_pr_notice("bound GRC product %s for device [%#x]", product->name, device_id);
	return 0;
}

static void nbl_init_global_cfg(struct nbl_grc *grc)
{
	u32 global_cfg_enable;

	global_cfg_enable = grc->global_ops->get_hw_global_cfg_flag(grc);

	if (!global_cfg_enable)
		grc->global_ops->set_hw_global_cfg(grc);
}

static void nbl_grc_set_atomic(struct nbl_grc *grc, struct nbl_core_export *core_info)
{
	bool is_support_atomic = false;
	u16 pcie_ctl2 = 0;
	int rc = pci_enable_atomic_ops_to_root(
		core_info->pdev, PCI_EXP_DEVCAP2_ATOMIC_COMP64);

	if (!rc) {
		pcie_capability_read_word(core_info->pdev, PCI_EXP_DEVCTL2, &pcie_ctl2);
		is_support_atomic = (pcie_ctl2 & PCI_EXP_DEVCTL2_ATOMIC_REQ);
	}

	if (is_support_atomic)
		grc->atomic_cap = IB_ATOMIC_GLOB;
	else
		grc->atomic_cap = IB_ATOMIC_NONE;
}

static void nbl_grc_set_devx_umem_num(struct nbl_grc *grc)
{
	grc->devx_umem_num = (u64)NBL_MAX_DEVX_UMEM * grc->res_cfg.qp_per_vf /
		hmc_obj_total_cnt.qp_num;
}

static void grc_flr_init(struct nbl_grc *grc)
{
	mutex_init(&grc->dev_info_lock);
	INIT_LIST_HEAD(&grc->dev_info_head);
}

static int grc_flr_event(struct notifier_block *notifier,
			 unsigned long event, void *data)
{
	struct nbl_grc *grc = container_of(notifier, struct nbl_grc,
					  grc_flr_nb);

	if (event != NBL_CORE_EVT_FLR || !data)
		return NOTIFY_DONE;

	grc_flr_event_queue_work(grc, *(u16 *)data);
	return NOTIFY_OK;
}

static int grc_register_event_notifiers(struct nbl_grc *grc,
					struct nbl_core_export *core_info)
{
	int ret;

	grc->grc_abn_nb.notifier_call = grc_abn_event;
	ret = blocking_notifier_chain_register(&core_info->grc_abn_nh,
					       &grc->grc_abn_nb);
	if (ret)
		goto register_abn_err;

	grc->grc_flr_nb.notifier_call = grc_flr_event;
	ret = blocking_notifier_chain_register(&core_info->grc_flr_nh,
					       &grc->grc_flr_nb);
	if (ret)
		goto register_flr_err;

	return 0;

register_flr_err:
	grc->grc_flr_nb.notifier_call = NULL;
	blocking_notifier_chain_unregister(&core_info->grc_abn_nh,
					   &grc->grc_abn_nb);
register_abn_err:
	grc->grc_abn_nb.notifier_call = NULL;
	return ret;
}

static void grc_unregister_event_notifiers(struct nbl_grc *grc,
					   struct nbl_core_export *core_info)
{
	if (grc->grc_flr_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->grc_flr_nh,
						   &grc->grc_flr_nb);
		grc->grc_flr_nb.notifier_call = NULL;
	}

	if (grc->grc_abn_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->grc_abn_nh,
						   &grc->grc_abn_nb);
		grc->grc_abn_nb.notifier_call = NULL;
	}
}

int nbl_grc_probe_v2(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	struct nbl_adev *adev = container_of(aux_dev, struct nbl_adev, adev);
	struct nbl_core_export *core_info = adev->core_info;
	struct nbl_grc *grc;
	int ret;

	grc_pr_notice("probe grc dev for %s", dev_name(&aux_dev->dev));
	grc = kzalloc(sizeof(*grc), GFP_KERNEL);
	if (!grc)
		return -ENOMEM;

	spin_lock_init(&grc->grp_list_lock);
	ret = nbl_fill_core_dev_info(grc, core_info);
	if (ret)
		goto fill_core_dev_err;
	grc->grc_dev = adev;
	ret = nbl_grc_product_bind(grc);
	if (ret)
		goto fill_core_dev_err;

	nbl_init_global_cfg(grc);
	nbl_grc_init_qpn_range(grc);
	nbl_grc_set_devx_umem_num(grc);
	grc_init_src_addr_rsrc(grc);
	grc_pr_debug("grc pdev=%p,hw_addr=%p,real_hw_addr=0x%llx",
		      grc->core_dev.pdev, grc->core_dev.hw_addr, grc->core_dev.real_hw_addr);

	ret = grc_hbf_tbl_init(grc);
	if (ret) {
		grc_pr_err("hbf_tbl init err=%d", ret);
		goto hbf_tbl_err;
	}

	grc_set_admin_cqp_bdf_tbl(grc, true);
	nbl_set_admin_vf_enable(grc, 1);
	ret = grc_cqp_init(grc);
	if (ret)
		goto cmd_init_err;

	ret = nbl_grc_global_sd_init(grc);
	if (ret)
		goto global_sd_init_err;

	ret = grc_mailbox_init(grc, core_info);
	if (ret)
		goto mailbox_init_err;

	grc->admin_wq = create_singlethread_workqueue("grc_admin_wq");
	if (!grc->admin_wq) {
		ret = -ENOMEM;
		goto admin_wq_init_err;
	}

	INIT_WORK(&grc->abnormal_task, nbl_grc_abnormal_event_handler);
	nbl_rdma_stat_init();
	nbl_grc_set_atomic(grc, core_info);
	grc_flr_init(grc);
	ret = grc_register_event_notifiers(grc, core_info);
	if (ret)
		goto event_notifier_err;

	dev_set_drvdata(&aux_dev->dev, grc);
	grc_pr_notice("probe grc dev for %s ok", dev_name(&aux_dev->dev));
	return 0;

event_notifier_err:
	nbl_rdma_stat_deinit();
	destroy_workqueue(grc->admin_wq);
admin_wq_init_err:
	grc_mailbox_destroy(grc, core_info);
mailbox_init_err:
	nbl_grc_global_sd_deinit(grc);
global_sd_init_err:
	grc_cqp_cleanup(grc);
cmd_init_err:
	grc_hbf_tbl_free(grc);
hbf_tbl_err:
fill_core_dev_err:
	kfree(grc);
	return ret;
}

void nbl_grc_remove_v2(struct auxiliary_device *adev)
{
	struct nbl_grc *grc = dev_get_drvdata(&adev->dev);
	struct nbl_adev *aux_dev = container_of(adev, struct nbl_adev, adev);

	grc_pr_notice("remove grc dev for %s", dev_name(&adev->dev));
	grc_unregister_event_notifiers(grc, aux_dev->core_info);
	grc_mailbox_destroy(grc, aux_dev->core_info);
	nbl_grc_global_sd_deinit(grc);
	grc_cqp_cleanup(grc);

	grc_del_src_addr_rsrc(grc);
	nbl_rdma_stat_deinit();
	grc_hbf_tbl_free(grc);
	grc_set_admin_cqp_bdf_tbl(grc, false);
	nbl_set_admin_vf_enable(grc, 0);
	destroy_workqueue(grc->admin_wq);
	grc_pr_notice("remove grc dev for %s OK", dev_name(&adev->dev));
	memset(grc, 0, sizeof(*grc));
	kfree(grc);
}
