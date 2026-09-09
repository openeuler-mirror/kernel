// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <linux/version.h>
#include "../nbl_rdma/nbl_adapt.h"
#include <linux/dma-map-ops.h>
#include "grc_hw_rdma.h"
#include "grc_main.h"
#include "grc_cqp.h"
#include "grc_mailbox.h"
#include "grc_gid.h"
#include "grc_counters.h"

static u8 fmr_nofence = NBL_FMR_NOFENCE_DISABLE;

/* 4KB page size with level1, or 2MB page size with level0 */
static u32 hmc_hugepage_profile[NBL_HMC_MAX] = {
	1 << 18,  /* 256k qp */
	  1 << 19,  /* 512k cq */
	  1 << 28,  /* 256M pble */
	  1 << 24,  /* 16M mrte */
};

/* 4KB page size with level0 */
static u32 hmc_stdpage_profile[NBL_HMC_MAX] = {
	1 << 13,  /* 8k qp */
	  1 << 14,  /* 16k cq */
	  1 << 18,  /* 256k pble */
	  1 << 15,  /* 32k mrte */
};

static void grc_set_obj_cnt(struct nbl_grc *grc)
{
	u16 rf_num;

	grc->sd_addr_mode = grc->core_dev.mem_type;
	if (grc->sd_addr_mode > NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY) {
		grc_pr_warn("invalid sd addr mode, set default\n");
		grc->sd_addr_mode = NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY;
	}

	grc_pr_debug("grc->pf_num=%u,got from kernel driver\n", grc->pf_num);

	grc->available_qps = grc->sd_addr_mode == NBL_HMC_PROFILE_LOW_SPEC_HIGH_EFFICIENCY ?
		hmc_stdpage_profile[NBL_HMC_QP] : hmc_hugepage_profile[NBL_HMC_QP];

	rf_num = grc->core_dev.rdma_cap_num;
	grc_pr_warn("recv rdma function_num=%u from template,sd_addr_mode=%u\n",
		    rf_num, grc->sd_addr_mode);
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

	grc->total_rf_num = rf_num;
	grc->qps_per_rf = grc->available_qps / rf_num;
	grc_pr_debug("sd_addr_mode=%d,pf_num=%u,total_qps=0x%x\n",
		      grc->sd_addr_mode, grc->pf_num, grc->available_qps);
}

static int grc_hbf_tbl_init(struct nbl_grc *grc)
{
	u32 mem_len;

	mem_len = sizeof(struct nbl_hbf_tbl) +
		sizeof(struct nbl_hbf_entry) * NBL_RDMA_TOTAL_FUNCTION_NUM;

	grc->hbf_tbl = kcalloc(1, mem_len, GFP_KERNEL);
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

static void grc_set_hw_bdf_tbl(struct nbl_grc *grc, u32 host_id, u32 bdf_num, u16 func_id)
{
	grc->ops->set_bdf_func_id_map(&grc->core_dev, host_id, bdf_num, func_id);
}

static inline u32 nbl_get_sd_alignment(struct nbl_grc *grc)
{
	return grc->sd_addr_mode == NBL_HMC_PROFILE_LOW_SPEC_HIGH_EFFICIENCY ?
		SZ_4K : SZ_2M;
}

static int grc_assign_sd_range(struct nbl_grc *grc, struct nbl_hmc_spec *fn_spec, u16 fn_id)
{
	u32 sd_num;
	u32 sd_size = nbl_get_sd_alignment(grc);
	u32 fn_obj_size = 0;
	int start_sd;
	u32 align_sz = grc->sd_addr_mode == NBL_HMC_PROFILE_HUGEPAGE ? SZ_2M : NBL_HMC_QPC_SZ;

	fn_obj_size += ALIGN(fn_spec->qp_num * NBL_HMC_QPC_SZ, align_sz);
	fn_obj_size += ALIGN(fn_spec->cq_num * NBL_HMC_CQC_SZ, align_sz);
	fn_obj_size += ALIGN(fn_spec->pble_num * NBL_HMC_PBL_SZ, align_sz);
	fn_obj_size += ALIGN(fn_spec->mr_num * NBL_HMC_MRTE_SZ, align_sz);
	sd_num = DIV_ROUND_UP(fn_obj_size, sd_size);
	start_sd = bitmap_find_next_zero_area(grc->allocated_sds,
					      NBL_RDMA_HMC_SD_MAX_CNT,
					      sd_num * fn_id, sd_num, 0);
	if (start_sd >= NBL_RDMA_HMC_SD_MAX_CNT) {
		grc_pr_err("cannot alloc continuous sd range,sd_num=%u,vfid=%u,qp_num=0x%x\n",
			   sd_num, fn_id, fn_spec->qp_num);
		return -ENOMEM;
	}
	bitmap_set(grc->allocated_sds, start_sd, sd_num);
	grc->hmc_sd_range[fn_id].start = start_sd;
	grc->hmc_sd_range[fn_id].cnt = sd_num;
	grc_pr_debug("assign fn_id[%d] sd range,start_sd=%u,sd_num=%u\n", fn_id,
		     start_sd, sd_num);
	return 0;
}

static int grc_set_usr_res_profile(struct nbl_grc *grc, u16 fn_id)
{
	int ret = 0;
	struct nbl_hmc_spec *fn_spec = &grc->fn_objs[fn_id];

	fn_spec->qp_num = grc->qps_per_rf;
	if (grc->sd_addr_mode == NBL_HMC_PROFILE_LOW_SPEC_HIGH_EFFICIENCY) {
		fn_spec->cq_num = fn_spec->qp_num *
			(hmc_stdpage_profile[NBL_HMC_CQ] / hmc_stdpage_profile[NBL_HMC_QP]);
		fn_spec->pble_num = fn_spec->qp_num *
			(hmc_stdpage_profile[NBL_HMC_PBL] / hmc_stdpage_profile[NBL_HMC_QP]);
		fn_spec->mr_num = fn_spec->qp_num *
			(hmc_stdpage_profile[NBL_HMC_MR] / hmc_stdpage_profile[NBL_HMC_QP]);
	} else {
		fn_spec->cq_num = fn_spec->qp_num *
			(hmc_hugepage_profile[NBL_HMC_CQ] / hmc_hugepage_profile[NBL_HMC_QP]);
		fn_spec->pble_num = fn_spec->qp_num *
			(hmc_hugepage_profile[NBL_HMC_PBL] / hmc_hugepage_profile[NBL_HMC_QP]);
		fn_spec->mr_num = fn_spec->qp_num *
			(hmc_hugepage_profile[NBL_HMC_MR] / hmc_hugepage_profile[NBL_HMC_QP]);
	}

	if (fn_spec->qp_num > grc->available_qps) {
		grc_pr_err("grc has not enough qp,req_qp_num=0x%x,available_qps=0x%x\n",
			   fn_spec->qp_num, grc->available_qps);
		return -ENOMEM;
	}

	grc->available_qps -= grc->qps_per_rf;
	ret = grc_assign_sd_range(grc, fn_spec, fn_id);
	if (ret) {
		grc_pr_err("failed assign sd range for function=0x%x\n", fn_id);
		return ret;
	}

	grc_pr_debug("set user resource profile,function_id=%u,qp_num=0x%x",
		      fn_id, fn_spec->qp_num);
	return ret;
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
			goto func_id_err;
		}
	}

	func_id = find_first_zero_bit(grc->function_id_tbl, NBL_RDMA_TOTAL_FUNCTION_NUM);
	if (func_id > NBL_RDMA_CQP_MAX_FUN_ID) {
		grc_pr_err("no function id can be used\n");
		goto func_id_err;
	}

	ret = grc_set_usr_res_profile(grc, func_id);
	if (ret)
		goto func_id_err;

	set_bit(func_id, grc->function_id_tbl);
	grc_pr_debug("success assign function_id=%u\n", func_id);

	grc->hbf_tbl->entries[func_id].host_id = req->host_id;
	grc->hbf_tbl->entries[func_id].bdf_num = req->bdf_num;
	grc->hbf_tbl->entries[func_id].func_id = func_id;
	grc->hbf_tbl->entries[func_id].valid = true;

	grc_set_hw_bdf_tbl(grc, req->host_id, req->bdf_num, func_id);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &func_id, sizeof(func_id));
	resp_msg.msg_len = sizeof(func_id) + 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
	grc_pr_debug("get func_id succeed,host_id=%u,bdf_num=0x%x fn_id:%d\n",
		     req->host_id, req->bdf_num, func_id);
	return;

func_id_err:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_free_function_id(struct nbl_grc *grc, void *req_msg, u16 msg_len,
				 struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 i;
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
			memset(entry, 0, sizeof(*entry));
			__clear_bit(req->function_id, grc->function_id_tbl);

			resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
			resp_msg.msg_len = 1;
			grc_pr_debug(
				"free_fn_id_req,host_id=0x%x,bdf_num=0x%x,fn_id=%u\n",
				req->host_id, req->bdf_num, req->function_id);
			grc->available_qps += grc->qps_per_rf;
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

static bool nbl_func_id_valid(struct nbl_grc *grc, u16 function_id)
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

static int nbl_get_hmc_obj_sz(int obj_type)
{
	switch (obj_type) {
	case NBL_HMC_QP:
		return NBL_HMC_QPC_SZ;
	case NBL_HMC_CQ:
		return NBL_HMC_CQC_SZ;
	case NBL_HMC_PBL:
		return NBL_HMC_PBL_SZ;
	case NBL_HMC_MR:
		return NBL_HMC_MRTE_SZ;
	default:
		grc_pr_err("func_name:%s unsupported obj_type=%d\n", __func__,
			   obj_type);
		return -1;
	}
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

static int nbl_setup_voa(struct nbl_grc *grc, u16 func_id)
{
	int i;
	struct nbl_hmc_voa_entry *voa_ent = grc->voa_tbl[func_id];
	int real_obj_sz = 0;
	u32 sd_sz = nbl_get_sd_alignment(grc);
	u32 obj_total_sz;
	u32 obj_base;
	u32 align_sz = NBL_HMC_QPC_SZ;
	int ret_val;
	u64 temp = 0;
	__be64 cmd_in[NBL_CMD_INPUT_SIZE / sizeof(u64)] = {0};
	__be64 cmd_out[NBL_CMD_OUTPUT_SIZE / sizeof(u64)] = {0};

	grc->nbl_hmc_obj_spec[func_id][NBL_HMC_QP] = grc->fn_objs[func_id].qp_num;
	grc->nbl_hmc_obj_spec[func_id][NBL_HMC_CQ] = grc->fn_objs[func_id].cq_num;
	grc->nbl_hmc_obj_spec[func_id][NBL_HMC_PBL] = grc->fn_objs[func_id].pble_num;
	grc->nbl_hmc_obj_spec[func_id][NBL_HMC_MR] = grc->fn_objs[func_id].mr_num;
	for (i = 0; i < NBL_HMC_MAX; i++) {
		real_obj_sz = nbl_get_hmc_obj_sz(i);
		if (real_obj_sz == -1)
			return -EINVAL;

		voa_ent[i].obj_sz = ilog2(real_obj_sz);
		voa_ent[i].addr_mode = nbl_get_address_level(grc);
		voa_ent[i].page_sz = nbl_get_pgsz_type(grc);
		voa_ent[i].obj_max_cnt = grc->nbl_hmc_obj_spec[func_id][i];
		voa_ent[i].valid = 1;
		if (i == 0 && func_id == NBL_RDMA_FIRST_FUNCTION_ID) {
			obj_base = 0;
		} else {
			if (i == 0 && func_id != NBL_RDMA_FIRST_FUNCTION_ID) {
				obj_base = grc->hmc_sd_range[func_id].start * sd_sz;
			} else {
				if (grc->sd_addr_mode == NBL_HMC_PROFILE_HUGEPAGE)
					align_sz = SZ_2M;

				obj_total_sz = voa_ent[i - 1].obj_max_cnt *
					(1 << voa_ent[i - 1].obj_sz);
				obj_base = ALIGN((voa_ent[i - 1].obj_ba << NBL_HMC_MAX_OBJ_LOG_SZ)
						 + obj_total_sz, align_sz);
			}
		}

		voa_ent[i].obj_ba = obj_base >> NBL_HMC_MAX_OBJ_LOG_SZ;

		grc_pr_debug(
			"obj[%d].obj_sz:%u addr_mode:%u page_sz:%u obj_max_cnt:%d valid:%d obj_ba:%#x\n",
			i, voa_ent[i].obj_sz, voa_ent[i].addr_mode,
			voa_ent[i].page_sz, voa_ent[i].obj_max_cnt,
			voa_ent[i].valid, voa_ent[i].obj_ba);
	}

	set_64bit_val(cmd_in, 0, FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_UPDATE_VOA) |
		      FIELD_PREP(NBL_CQPSQ_VF_ID, func_id));

	for (i = 0; i < NBL_HMC_MAX; i++) {
		memcpy(&temp, &voa_ent[i], sizeof(voa_ent[i]));
		set_64bit_val(cmd_in, 32 + i * 8, temp);
		temp = 0;
	}

	ret_val = grc_cmd_exec(grc, cmd_in, NBL_CMD_INPUT_SIZE, cmd_out, NBL_CMD_OUTPUT_SIZE);
	if (ret_val) {
		grc_pr_err("set voa tbl cqp cmd err=%d\n", ret_val);
		return ret_val;
	}

	grc_pr_debug("set voa tbl cmd for func_id=%u success\n", func_id);
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

	ret_val = nbl_setup_voa(grc, func_id);
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

	bitmap_clear(grc->allocated_sds, sd_range->start, sd_range->cnt);
	memset(sd_range, 0, sizeof(*sd_range));
	grc->ops->set_sd_range(&grc->core_dev, fn_id, sd_range->start, sd_range->cnt, false);
}

static void grc_destroy_voa_tbl(struct nbl_grc *grc, void *msg, u16 msg_len,
				struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 function_id = *(u16 *)GRC_GET_CACHE_MSG_DATA(msg);
	struct nbl_hmc_voa_entry *voa_ent;
	int ret_val;
	int i;
	u64 temp = 0;
	__be64 cmd_in[NBL_CMD_INPUT_SIZE / sizeof(u64)] = {0};
	__be64 cmd_out[NBL_CMD_OUTPUT_SIZE / sizeof(u64)] = {0};
	struct grc_resp_msg resp_msg;

	if (!nbl_func_id_valid(grc, function_id)) {
		grc_pr_err("invalid function_id=%u\n", function_id);
		goto destroy_voa_err;
	}

	voa_ent = grc->voa_tbl[function_id];

	set_64bit_val(cmd_in, 0, FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_UPDATE_VOA) |
		      FIELD_PREP(NBL_CQPSQ_VF_ID, function_id));

	for (i = 0; i < NBL_HMC_MAX; i++)
		set_64bit_val(cmd_in, 32 + i * 8, temp);

	ret_val = grc_cmd_exec(grc, cmd_in, NBL_CMD_INPUT_SIZE, cmd_out, NBL_CMD_OUTPUT_SIZE);
	if (ret_val) {
		grc_pr_err("destroy voa tbl cmd err=%d\n", ret_val);
		goto destroy_voa_err;
	}

	grc_clear_sd_range(grc, function_id);
	memset(voa_ent, 0, sizeof(grc->voa_tbl[function_id]));
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
	struct nbl_hmc_voa_entry *voa_ent;
	struct nbl_hmc_voa_entry hw_voa_ent[NBL_HMC_MAX];
	int ret_val;
	int i;
	u64 temp = 0;
	__be64 cmd_in[NBL_CMD_INPUT_SIZE / sizeof(u64)] = {0};
	__be64 cmd_out[NBL_CMD_OUTPUT_SIZE / sizeof(u64)] = {0};
	struct grc_resp_msg resp_msg;

	if (!nbl_func_id_valid(grc, function_id)) {
		grc_pr_err("invalid function_id=%u\n", function_id);
		goto query_voa_err;
	}

	voa_ent = grc->voa_tbl[function_id];

	set_64bit_val(cmd_in, 0, FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_VOA) |
		      FIELD_PREP(NBL_CQPSQ_VF_ID, function_id));

	for (i = 0; i < NBL_HMC_MAX; i++) {
		memcpy(&temp, voa_ent + i, sizeof(struct nbl_hmc_voa_entry));
		grc_pr_debug("sw [%d].voa_ent=0x%llx\n", i, temp);
		temp = 0;
		set_64bit_val(cmd_in, 32 + i * 8, temp);
	}

	ret_val = grc_cmd_exec(grc, cmd_in, NBL_CMD_INPUT_SIZE, cmd_out, NBL_CMD_OUTPUT_SIZE);
	if (ret_val) {
		grc_pr_err("query voa tbl cmd err=%d\n", ret_val);
		goto query_voa_err;
	}

	for (i = 0; i < NBL_HMC_MAX; i++) {
		get_64bit_val(cmd_out, 32 + i * 8, &temp);
		grc_pr_debug("hw [%d].voa_ent=0x%llx\n", i, temp);
		memcpy(hw_voa_ent + i, &temp, sizeof(temp));
	}

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
#if NBL_GRC_DEBUG_STUB
	memcpy(resp_msg.msg + 1, voa_ent, sizeof(hw_voa_ent));
#else
	memcpy(resp_msg.msg + 1, hw_voa_ent, sizeof(hw_voa_ent));
#endif
	resp_msg.msg_len = sizeof(hw_voa_ent) + 1;

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

	grc->ops->set_sd_range(&grc->core_dev, function_id, sdr->start, sdr->cnt, true);
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

	grc->ops->get_sd_range(&grc->core_dev, function_id, &sd_range.start, &sd_range.cnt);

	if (sd_range.start != sdr[function_id].start ||
	    sd_range.cnt != sdr[function_id].cnt) {
		grc_pr_err("sw sd_range.start=%u,cnt=%u not equal hw reg sd_range\n",
			   sdr[function_id].start, sdr[function_id].cnt);
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

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &init_params, sizeof(init_params));
	resp_msg.msg_len = sizeof(init_params) + 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_write_reg(struct nbl_grc *grc, void *msg, u16 msg_len,
			  struct nbl_chan_rdma_resp *mbx_resp)
{
	void *regs_addr;
	struct rw_dw_reg *req = (struct rw_dw_reg *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;

	regs_addr = grc->core_dev.hw_addr + req->offset;
#if NBL_RW_RDMA_REG
	writel(req->data, regs_addr);
#endif
	grc_pr_debug("write reg addr %p, offset 0x%x, val 0x%x\n",
		      regs_addr, req->offset, req->data);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_read_reg(struct nbl_grc *grc, void *msg, u16 msg_len,
			 struct nbl_chan_rdma_resp *mbx_resp)
{
	void *regs_addr;
	struct rw_dw_reg *req = (struct rw_dw_reg *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;

	regs_addr = grc->core_dev.hw_addr + req->offset;
#if NBL_RW_RDMA_REG
	req->data = readl(regs_addr);
#endif
	grc_pr_debug("read reg addr %p, offset 0x%x, get val 0x%x\n",
		      regs_addr, req->offset, req->data);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, req, sizeof(*req));
	resp_msg.msg_len = sizeof(*req) + 1;

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
	grc->ops->set_cqp_info(&grc->core_dev, req->function_id, req->phys_addr,
			       req->cmd_max_num, req->enable ? true : false);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static int rdma_pfid_map_entry_exist_idx(struct nbl_grc *grc, u64 target)
{
	u64 key;
	int ix;
	struct rdma_host_notify *hn = grc->host_notify;

	if (hn->pfid_map_tbl_entries == 0)
		return -1;

	ix = 0;
	while (ix < hn->pfid_map_tbl_entries) {
		key = hn->pfid_map_tbl[ix].ddata & NBL_PCOMP_HOST_BAR_ADDR_MASK;
		if (key == target)
			return ix;
		ix++;
	}

	return -1;
}

static void grc_set_pcomplete_host(struct nbl_grc *grc, void *msg, u16 msg_len,
				   struct nbl_chan_rdma_resp *mbx_resp)
{
	int entry;
	int entry_hit;
	int next_pfid_base;
	u64 notify_addr, key, op_key;
	union nbl_rdma_pfid_map_tbl_reg invalid_entry;
	struct notify_info_req *req =
		(struct notify_info_req *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;
	struct rdma_host_notify *hn = grc->host_notify;

	memset(&invalid_entry, 0xFF, sizeof(union nbl_rdma_pfid_map_tbl_reg));
	/* 1, calc key */

	notify_addr = req->bar0_phy_addr + RDMA_HOST_NOTIFY_OFFSET;
	op_key = (notify_addr & NBL_PCOMP_HOST_BAR_ADDR_MASK);

	grc_pr_debug("notify_addr=0x%llx,function_id=%u,host_id=%u",
		     notify_addr, req->function_id, req->host_id);
	/* 2, check exist */
	entry_hit = rdma_pfid_map_entry_exist_idx(grc, op_key);
	if (req->valid) {
		if (hn->pfid_map_tbl_entries == (NBL_PCOMP_HOST_PFID_MAX_TBL_ENTRY / 2)) {
			grc_pr_err("No enough pfid map entries left\n");
			resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
			goto err_inval;
		}
		if (entry_hit >= 0) {
			grc_pr_debug(
				"pfid map entries(0x%llx) already existed!\n",
				op_key);
			/* update function id */
			if (hn->pfid_map_tbl[entry_hit].key.pfid !=
			    req->function_id) {
				grc_pr_debug(
					"pfid:%d neq function_id:%d, need to update!\n",
					hn->pfid_map_tbl[entry_hit].key.pfid,
					req->function_id);

				hn->pfid_map_tbl[entry_hit].ddata = 0;
				hn->pfid_map_tbl[entry_hit].key.bar_addr =
					(op_key >> 13);
				hn->pfid_map_tbl[entry_hit].key.pfid =
					req->function_id;
				goto update;
			} else
				goto exist_out;
		}

		/* Move the bigger entries to the end to make room for the entries of dev */
		for (entry = hn->pfid_map_tbl_entries - 1; entry >= 0; entry--) {
			key = hn->pfid_map_tbl[entry].ddata & NBL_PCOMP_HOST_BAR_ADDR_MASK;
			if (key > op_key)
				memcpy(&hn->pfid_map_tbl[entry + 1],
				       &hn->pfid_map_tbl[entry],
				       sizeof(hn->pfid_map_tbl[0]));
			else
				break;
		}

		/* Fill the pfid map entry into the whole */
		hn->pfid_map_tbl[entry + 1].ddata = 0;
		hn->pfid_map_tbl[entry + 1].key.bar_addr = (op_key >> 13);
		hn->pfid_map_tbl[entry + 1].key.pfid = req->function_id;

		/* update total number */
		hn->pfid_map_tbl_entries++;
	} else {
		if (entry_hit < 0) {
			grc_pr_err("No pfid map entries matched!\n");
			resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
			goto err_inval;
		}

		/* Move the bigger entries to the beginning to occupy the room of dev's entries */
		for (entry = 0; entry < hn->pfid_map_tbl_entries; entry++) {
			key = hn->pfid_map_tbl[entry].ddata & NBL_PCOMP_HOST_BAR_ADDR_MASK;
			if (key > op_key)
				memcpy(&hn->pfid_map_tbl[entry - 1],
				       &hn->pfid_map_tbl[entry],
				       sizeof(hn->pfid_map_tbl[0]));
		}
		/* update total number */
		hn->pfid_map_tbl_entries--;
	}

update:
	/* 3. Retrieve the next map table to be used */
	next_pfid_base = hn->pfid_map_tbl_sel ? NBL_PCOMP_HOST_PFID_MASTER_TBL_BASE :
			 NBL_PCOMP_HOST_PFID_SLAVE_TBL_BASE;

	/* 4. Write the updated qid_map_tbl into HW */
	for (entry = 0; entry < (NBL_PCOMP_HOST_PFID_MAX_TBL_ENTRY / 2); entry++) {
		if (entry < hn->pfid_map_tbl_entries) {
#if NBL_RW_RDMA_REG
			grc->ops->set_rdma_pfid_map_tbl(&grc->core_dev, next_pfid_base + entry,
					&hn->pfid_map_tbl[entry]);
#endif
			grc_pr_debug("set rdma pfid table entry %d, val 0x%x, 0x%x\n",
				     next_pfid_base + entry,
				     hn->pfid_map_tbl[entry].data[0],
				     hn->pfid_map_tbl[entry].data[1]);
		} else {
			/* Invalid the rest of map tbl entries */
#if NBL_RW_RDMA_REG
			grc->ops->set_rdma_pfid_map_tbl(&grc->core_dev, next_pfid_base + entry,
					&invalid_entry);
#endif
			grc_pr_debug("set rdma pfid table entry %d, val 0x%x, 0x%x\n",
				     next_pfid_base + entry,
				     invalid_entry.data[0], invalid_entry.data[1]);
		}
	}

	/* 5. Write tbl select and ready into HW */
	hn->pfid_map_tbl_sel ^= 1;
	grc->ops->set_rdma_tbl_sel(&grc->core_dev, hn->pfid_map_tbl_sel);
	grc->ops->set_rdma_tbl_ready(&grc->core_dev, 0x1);

exist_out:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
err_inval:
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
	grc->ops->set_cc_params(&grc->core_dev, offset, var);

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

	grc->ops->set_vf_enable(&grc->core_dev, vf_enable_req->function_id, vf_enable_req->enable);

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

	grc->ops->set_rdma_dsch(&grc->core_dev, req->function_id, req->host_id,
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

	grc->ops->update_rdma_dsch(&grc->core_dev, req->function_id, req->host_id,
				   req->dport_id, req->is_valid);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
	grc_pr_debug("update_rdma_dsch dport_id=%u,function_id=%u,host_id=%u,valid=%u\n",
		      req->dport_id, req->function_id, req->host_id, req->is_valid);
}

static void grc_set_vfid_vsi_map(struct nbl_grc *grc, void *msg, u16 msg_len,
				 struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct set_vfid_vsi_map_req *req =
		(struct set_vfid_vsi_map_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc_pr_debug("grc set_vfid_vsi_map,function_id=%u,vsi_id=%u,valid=%u\n",
		     req->function_id, req->vsi_id, req->valid);

	grc->ops->set_vfid_vsi_map(&grc->core_dev, req->function_id, req->vsi_id, req->valid);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_set_dif_vf_en(struct nbl_grc *grc, void *msg, u16 msg_len,
			      struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	bool *is_off = (bool *)GRC_GET_CACHE_MSG_DATA(msg);

	grc->ops->set_dif_vf_off(&grc->core_dev, *is_off);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
	grc_pr_debug("set_dif_vf_off val:%#x\n", *is_off);
}

static void grc_clear_cache(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct clear_cache_req *req =
		(struct clear_cache_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc_pr_notice("clear cache type %u\n", req->cache_type);
	grc->ops->clear_hw_cache(&grc->core_dev, req->cache_type);

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

	grc->ops->ena_rdma_intrl(&grc->core_dev, req->msix_global_idx,
				 req->devfn, req->bus, req->valid);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static int grc_add_dev_info_node(struct nbl_grc *grc, struct dev_info *info)
{
	struct dev_info_node *node, *tmp;

	spin_lock(&grc->dev_info_lock);
	list_for_each_entry_safe(node, tmp, &grc->dev_info_head, list) {
		if (node->info.vsi_id == info->vsi_id) {
			grc_pr_notice(
				"found exist node of vsi:%d, remove it.\n",
				info->vsi_id);
			list_del(&node->list);
			kfree(node);
		}
	}
	spin_unlock(&grc->dev_info_lock);
	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->info.vsi_id = info->vsi_id;
	node->info.real_bdf = info->real_bdf;
	node->info.function_id = info->function_id;
	node->info.eth_id = info->eth_id;
	spin_lock(&grc->dev_info_lock);
	list_add(&node->list, &grc->dev_info_head);
	spin_unlock(&grc->dev_info_lock);

	return 0;
}

static void grc_register_client(struct nbl_grc *grc, void *req_msg,
				u16 req_msg_len,
				struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct dev_info *req = GRC_GET_CACHE_MSG_DATA(req_msg);

	grc_pr_debug("register client vsi:%d bdf:%#x vf_id:%d eth_id:%d\n",
		     req->vsi_id, req->real_bdf, req->function_id, req->eth_id);
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;

	grc->active_rf_num += 1;
	if (grc_add_dev_info_node(grc, req)) {
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		grc->active_rf_num -= 1;
		goto exit;
	}
exit:
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_del_dev_info_node(struct nbl_grc *grc, u16 vsi_id)
{
	struct dev_info_node *node, *tmp;

	spin_lock(&grc->dev_info_lock);
	list_for_each_entry_safe(node, tmp, &grc->dev_info_head, list) {
		if (node->info.vsi_id == vsi_id) {
			list_del(&node->list);
			kfree(node);
		}
	}
	spin_unlock(&grc->dev_info_lock);
}

static void grc_unregister_client(struct nbl_grc *grc, void *req_msg,
				  u16 req_msg_len,
				  struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct dev_info *req = GRC_GET_CACHE_MSG_DATA(req_msg);

	grc->active_rf_num -= 1;
	grc_pr_debug(
		"unregister client vsi:%d bdf:%#x vf_id:%d eth_id:%d\n",
		req->vsi_id, req->real_bdf, req->function_id, req->eth_id);

	grc_del_dev_info_node(grc, req->vsi_id);
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_mbx_msg_process(struct auxiliary_device *aux_dev, void *msg, u16 msg_len,
			 struct nbl_chan_rdma_resp *mbx_resp)
{
	u8 op_code;
	struct nbl_grc *grc = dev_get_drvdata(&aux_dev->dev);

	op_code = grc_get_msg_opcode(msg);
	grc_pr_debug("af_grc recv msg op_code=%u\n", op_code);
	switch (op_code) {
	case GRC_MSG_OP_REGISTER_CLIENT:
		grc_register_client(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_UNREGISTER_CLIENT:
		grc_unregister_client(grc, msg, msg_len, mbx_resp);
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
	case GRC_MSG_OP_GET_ECN_STAT:
		break;
	case GRC_MSG_OP_ADD_SRC_ADDR_INFO:
		grc_add_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_DEL_SRC_ADDR_INFO:
		grc_del_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_GET_SRC_ADDR_INFO:
		grc_get_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_SEND_SRC_ADDR_INFO:
		grc_send_src_addr_info(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_STAT_ID_ADD:
		grc_add_stat_id(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_STAT_ID_DEL:
		grc_del_stat_id(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_STAT_ID_MOD:
		grc_mod_stat_id(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_USED_CNT_GET:
		grc_get_used_cnt(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_HW_STAT_GET:
		nbl_grc_hw_stat_read(grc, msg, msg_len, mbx_resp);
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
		grc_query_fmr_nofnece_info(grc, mbx_resp);
		break;
	case GRC_MSG_OP_SET_DIF_VF_EN:
		grc_set_dif_vf_en(grc, msg, msg_len, mbx_resp);
		break;
	case GRC_MSG_OP_CLEAR_CACHE:
		grc_clear_cache(grc, msg, msg_len, mbx_resp);
		break;
	default:
		grc_pr_err("unsupported op_code=%u\n", op_code);
	}
}

void grc_abnormal_event_process(struct auxiliary_device *aux_dev)
{
	struct nbl_grc *grc = dev_get_drvdata(&aux_dev->dev);

	queue_work(grc->admin_wq, &grc->abnormal_task);
}

static int find_and_free_function_id(struct nbl_grc *grc, u32 host_id, u32 bdf,
				     int funcid)
{
	u16 i;
	struct nbl_hbf_entry *entry;

	if (funcid > NBL_RDMA_CQP_MAX_FUN_ID) {
		grc_pr_err("invalid function_id=%u\n", funcid);
		return -EINVAL;
	}

	for (i = 0; i < grc->hbf_tbl->tbl_size; i++) {
		entry = &grc->hbf_tbl->entries[i];
		if (entry->func_id == funcid && entry->host_id == host_id &&
		    entry->bdf_num == bdf) {
			memset(entry, 0, sizeof(*entry));
			__clear_bit(funcid, grc->function_id_tbl);

			grc->available_qps += grc->qps_per_rf;
			return 0;
		}
	}

	grc_pr_notice(
		"not match free_fn_id_req,host_id=0x%x,bdf_num=0x%x,fn_id=%u\n",
		host_id, bdf, funcid);
	return -ENODATA;
}

static void nbl_flr_restore_res(struct nbl_grc *grc, struct dev_info *info)
{
	grc->ops->set_vfid_vsi_map(&grc->core_dev, info->function_id,
				   info->vsi_id, false);

	grc->ops->set_cqp_info(&grc->core_dev, info->function_id, 0, 0, false);

	grc->ops->set_rdma_dsch(&grc->core_dev, info->function_id,
				HOST_ID_TYPE_HOST, info->eth_id, false);

	grc->ops->set_vf_enable(&grc->core_dev, info->function_id, false);

	find_and_free_function_id(grc, HOST_ID_TYPE_HOST, info->real_bdf,
				  info->function_id);

	grc->active_rf_num -= 1;
}

static void nbl_grc_flr_event_handler(struct work_struct *work)
{
	struct nbl_grc_flr_work *flr_work =
		container_of(work, struct nbl_grc_flr_work, work);
	struct nbl_grc *grc = flr_work->grc;
	struct dev_info_node *node, *tmp;

	spin_lock(&grc->dev_info_lock);
	list_for_each_entry_safe(node, tmp, &grc->dev_info_head, list) {
		if (node->info.vsi_id == flr_work->vsi_id) {
			grc_pr_debug(
				"found node of vsi:%d bdf:%#x vfid:%d eth_id:%d\n",
				flr_work->vsi_id, node->info.real_bdf,
				node->info.function_id, node->info.eth_id);

			nbl_flr_restore_res(grc, &node->info);

			list_del(&node->list);
			kfree(node);
			break;
		}
	}
	spin_unlock(&grc->dev_info_lock);

	kfree(flr_work);
}

static void grc_flr_event_queue_work(struct auxiliary_device *aux_dev, u16 vsi_id)
{
	struct nbl_grc *grc = dev_get_drvdata(&aux_dev->dev);
	struct nbl_grc_flr_work *flr_work =
		kzalloc(sizeof(*flr_work), GFP_KERNEL);

	if (!flr_work)
		return;

	flr_work->grc = grc;
	flr_work->vsi_id = vsi_id;
	INIT_WORK(&flr_work->work, nbl_grc_flr_event_handler);
	queue_work(grc->admin_wq, &flr_work->work);
}

static int grc_high_temp_event_process(struct auxiliary_device *aux_dev,
				       enum nbl_core_reset_event event)
{
	struct nbl_grc *grc = dev_get_drvdata(&aux_dev->dev);

	grc_pr_notice("grc recv high temp event=%d\n", event);
	if (event != NBL_CORE_FATAL_ERR_EVENT)
		return -EINVAL;

	while (grc->active_rf_num > 0)
		grc->active_rf_num--;

	grc->has_high_temp_alarm = true;

	return 0;
}

u32 g_queue_info[NBL_SD_TYPE_MAX] = {
	NBL_DBQ_SIZE,
	NBL_TQ_RTO_SIZE,
	NBL_TQ_RNR_SIZE
};

static int nbl_alloc_global_queue_mem(struct nbl_grc *grc, u32 queue_len,
				      struct nbl_gl_sdtbl_info *sd_info)
{
	u16 idx;
	int err_code;
	u32 alloc_len;
	u32 len = ALIGN(queue_len, SZ_4K);
	struct device *dma_dev = NBL_COREDEV_TO_DMA_DEV(&grc->core_dev);

	sd_info->max_num = len / SZ_4K;
	sd_info->list = kcalloc(sd_info->max_num, sizeof(struct nbl_dma_mem), GFP_KERNEL);
	if (!sd_info->list)
		return -ENOMEM;

	alloc_len = min_t(u32, len, SZ_4M);
	for (idx = 0; idx < sd_info->max_num; idx++) {
		sd_info->list[idx].va = dma_alloc_coherent(dma_dev, alloc_len,
							   &sd_info->list[idx].pa, GFP_KERNEL);
		if (!sd_info->list[idx].va) {
			if (alloc_len <= SZ_4K) {
				err_code = -ENOMEM;
				goto free_sd_list;
			}
			alloc_len >>= 1;
			idx--;
			continue;
		}

		grc_pr_debug("[%u]alloc_len=0x%x,va=%p,pa=0x%llx\n", idx, alloc_len,
			      sd_info->list[idx].va, sd_info->list[idx].pa);
		sd_info->list[idx].size = alloc_len;

		if (queue_len - alloc_len <= 0)
			break;
		queue_len -= alloc_len;
	}

	if (idx < sd_info->max_num)
		sd_info->cnt = idx + 1;
	else
		sd_info->cnt = idx;

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

static int nbl_config_hw_sdtbl(struct nbl_grc *grc, int sd_type,
			       struct nbl_gl_sdtbl_info *sd_info, bool is_add)
{
	u32 i, j;
	__be64 *in;
	u64 sd_entry;
	u64 be_sd_entry;
	u32 sd_idx = 0;
	int err_code;
	u64 *sd_addr_buf;
	u16 sd_entry_num = 0;
	struct nbl_dma_mem sd_buf;
	u64 out[NBL_CMD_OUTPUT_SIZE / sizeof(u64)] = {0};
	struct device *dma_dev = NBL_COREDEV_TO_DMA_DEV(&grc->core_dev);

	sd_buf.size = SZ_4K;
	sd_buf.va = dma_alloc_coherent(dma_dev, sd_buf.size, &sd_buf.pa, GFP_KERNEL);
	if (!sd_buf.va)
		return -ENOMEM;

	in = kcalloc(1, NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		dma_free_coherent(dma_dev, sd_buf.size, sd_buf.va, sd_buf.pa);
		return -ENOMEM;
	}

	sd_addr_buf = sd_buf.va;
	/* 3.fill sd entry */
	grc_pr_debug("sd_info->cnt=%u,is_add=%d\n", sd_info->cnt, is_add);
	for (i = 0; i < sd_info->cnt; i++) {
		u32 num = sd_info->list[i].size / SZ_4K;

		grc_pr_debug("[%u]this buf(size=0x%x,start_pa=0x%llx) split %u 4KB page\n",
			      i, sd_info->list[i].size, sd_info->list[i].pa, num);
		for (j = 0; j < num; j++) {
			sd_entry = (u64)(sd_info->list[i].pa + SZ_4K * j);
			if (is_add)
				sd_entry |= NBL_SD_VALID;

			be_sd_entry = cpu_to_be64(sd_entry);

			memcpy(sd_addr_buf + sd_entry_num, &be_sd_entry, sizeof(be_sd_entry));
			sd_entry_num++;
			if (sd_entry_num == 64) {
				set_64bit_val(in, 0,
					      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_UPDATE_SD) |
						FIELD_PREP(NBL_CQPSQ_SD_TYPE, sd_type) |
						FIELD_PREP(NBL_CQPSQ_SD_NUM, 64) |
						FIELD_PREP(NBL_CQPSQ_SD_START, sd_idx));
				set_64bit_val(in, 8, sd_buf.pa);

				err_code = grc_cmd_exec(grc, in, NBL_CMD_INPUT_SIZE,
							out, NBL_CMD_OUTPUT_SIZE);
				if (err_code) {
					grc_pr_err("set glo_q cmd err=%d,type=%d,sta_idx=0x%x\n",
						   err_code, sd_type, sd_idx);
					goto clean_cmd;
				}

				sd_idx += sd_entry_num;
				sd_entry_num = 0;
				memset(sd_buf.va, 0, sd_buf.size);
			}
		}
	}

	if (sd_entry_num) {
		set_64bit_val(in, 0, FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_UPDATE_SD) |
			      FIELD_PREP(NBL_CQPSQ_SD_TYPE, sd_type) |
			      FIELD_PREP(NBL_CQPSQ_SD_NUM, sd_entry_num) |
			      FIELD_PREP(NBL_CQPSQ_SD_START, sd_idx));
		set_64bit_val(in, 8, sd_buf.pa);
		err_code = grc_cmd_exec(grc, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);
		if (err_code) {
			grc_pr_err("final set global sd tbl err=%d,sd_type=%d,start_idx=0x%x,sd_entry_num=%u\n",
				   err_code, sd_type, sd_idx, sd_entry_num);
			goto clean_cmd;
		}
	}

	kfree(in);
	dma_free_coherent(dma_dev, sd_buf.size, sd_buf.va, sd_buf.pa);
	return 0;

clean_cmd:
	kfree(in);
	dma_free_coherent(dma_dev, sd_buf.size, sd_buf.va, sd_buf.pa);
	return err_code;
}

static int nbl_setup_global_sdtbl(struct nbl_grc *grc, u8 sd_type, u32 queue_len,
				  struct nbl_gl_sdtbl_info *sd_info)
{
	int err_code = 0;

	grc_pr_debug("begin init global queue,sd_type=%u,len=0x%x\n", sd_type, queue_len);
	/* 1.alloc dma mem block by queue_len */
	err_code = nbl_alloc_global_queue_mem(grc, queue_len, sd_info);
	if (err_code)
		return err_code;

	/* 2.fill hw global sd tbl */
	err_code = nbl_config_hw_sdtbl(grc, sd_type, sd_info, true);
	if (err_code)
		nbl_free_global_queue_mem(grc, sd_info);

	return err_code;
}

static void nbl_free_global_sdtbl(struct nbl_grc *grc, u8 sd_type,
				  struct nbl_gl_sdtbl_info *sd_info)
{
	int err_code;

	err_code = nbl_config_hw_sdtbl(grc, sd_type, sd_info, false);
	if (err_code)
		grc_pr_err("%s free hw global sdtbl err=%d\n", __func__, err_code);

	nbl_free_global_queue_mem(grc, sd_info);
}

static int nbl_grc_global_sd_init(struct nbl_grc *grc)
{
	int idx;
	int err_code = 0;

	for (idx = 0; idx < NBL_SD_TYPE_MAX; idx++) {
		err_code = nbl_setup_global_sdtbl(
			grc, idx + 1, g_queue_info[idx], &grc->sd_res[idx]);
		if (err_code)
			goto free_gl_sd;
	}

	return 0;
free_gl_sd:
	while (idx--)
		nbl_free_global_sdtbl(grc, idx + 1, &grc->sd_res[idx]);
	return err_code;
}

static void nbl_grc_global_sd_deinit(struct nbl_grc *grc)
{
	int idx;

	for (idx = 0; idx < NBL_SD_TYPE_MAX; idx++)
		nbl_free_global_sdtbl(grc, idx + 1, &grc->sd_res[idx]);
}

static void nbl_grc_eot_table_init(struct nbl_grc *grc)
{
	grc->ops->set_eot_table(&grc->core_dev, true);
}

static void nbl_grc_eot_table_deinit(struct nbl_grc *grc)
{
	grc->ops->set_eot_table(&grc->core_dev, false);
}

static void grc_set_admin_cqp_bdf_tbl(struct nbl_grc *grc)
{
	u32 bdf_num;
	struct nbl_core_dev_info *cdev_info = &grc->core_dev;

	bdf_num = PCI_DEVID(cdev_info->real_bus, PCI_DEVFN(cdev_info->real_dev,
					   cdev_info->real_function));
	grc_pr_debug("admin pf bdf_num=0x%x\n", bdf_num);

	grc_set_hw_bdf_tbl(grc, HOST_ID_TYPE_HOST, bdf_num, NBL_RDMA_ADMIN_CQP_FUNCTION_NUM);
}

static int nbl_host_notify_init(struct nbl_grc *grc)
{
	struct rdma_host_notify *hn;

	hn = kzalloc(sizeof(*hn), GFP_KERNEL);
	if (!hn)
		return -ENOMEM;

	hn->pfid_map_tbl_entries = 0;
	hn->pfid_map_tbl_sel = 0x1;
	grc->host_notify = hn;
	return 0;
}

static void nbl_host_notify_deinit(struct nbl_grc *grc)
{
	if (grc && grc->host_notify)
		kfree(grc->host_notify);
}

static void nbl_set_admin_vf_enable(struct nbl_grc *grc, u8 enable)
{
	grc->ops->set_vf_enable(&grc->core_dev, NBL_RDMA_ADMIN_CQP_FUNCTION_NUM, enable);

	if (enable)
		grc->ops->set_hdma_dif_vfid(&grc->core_dev, NBL_RDMA_ADMIN_CQP_FUNCTION_NUM);
	else
		grc->ops->set_hdma_dif_vfid(&grc->core_dev, 0);
}

static void nbl_set_epro_cfg_err(struct nbl_grc *grc, u8 mask)
{
	grc->ops->set_epro_cfg_err(&grc->core_dev, mask);
}

static void nbl_set_txp_sw_db_wqe_cap(struct nbl_grc *grc)
{
	grc->ops->set_sw_db_wqe_cap(&grc->core_dev);
}

static void nbl_init_net_tc_tbl(struct nbl_grc *grc)
{
	grc->ops->init_net_tc_tbl(&grc->core_dev);
}

static void nbl_grc_abnormal_event_handler(struct work_struct *work)
{
	struct nbl_grc *grc = container_of(work, struct nbl_grc, abnormal_task);

	grc->ops->get_abnormal_event(&grc->core_dev);
}

static int nbl_fill_core_dev_info(struct nbl_grc *grc, struct nbl_core_dev_info *cdev_info)
{
	grc->core_dev = *cdev_info;
	grc->pf_num = cdev_info->eth_mode;

	return 0;
}

static void nbl_grc_set_rqdb_int_mask(struct nbl_grc *grc)
{
	grc->ops->set_rqdb_int_mask(&grc->core_dev);
}

static void nbl_grc_set_qos_default_cfg(struct nbl_grc *grc)
{
	grc->ops->set_qos_default_cfg(&grc->core_dev);
}

static void nbl_grc_set_dif_vf_off(struct nbl_grc *grc, bool is_off)
{
	grc->ops->set_dif_vf_off(&grc->core_dev, is_off);
}

static inline bool nbl_dma_iommu_status(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;

	return (dev->iommu_group && iommu_get_domain_for_dev(dev));
}

static inline bool nbl_dma_remap_status(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	const struct dma_map_ops *ops = get_dma_ops(dev);

	return !!ops;
}

static void nbl_reserve_low_64k_iova(struct pci_dev *pdev)
{
	bool iommu_status, remap_status;
	struct iommu_domain *iommu;
	struct iommu_dma_cookie *cookie;
	struct iova_domain *iovad;
	unsigned long lo;
	unsigned long hi;
	struct iova *iova;
	int i;

	iommu_status = nbl_dma_iommu_status(pdev);
	remap_status = nbl_dma_remap_status(pdev);
	grc_pr_debug("iommu_status:%d remap_status:%d\n", iommu_status,
		     remap_status);
	if (!iommu_status || !remap_status)
		return;
	iommu = iommu_get_domain_for_dev(&pdev->dev);
	cookie = iommu->iova_cookie;
	/* iommu=on and pt=off */
	if (cookie && cookie->type == IOMMU_DMA_IOVA_COOKIE) {
		iovad = &cookie->iovad;
		/* per page reserve  */
		for (i = 0; i < NBL_RESERVE_RANGE_IOVA / iovad->granule; i++) {
			lo = iova_pfn(iovad, NBL_RESERVE_START_IOVA +
						     iovad->granule * i);
			hi = iova_pfn(iovad, NBL_RESERVE_START_IOVA +
						     iovad->granule * (i + 1));
			/* iova just for debug */
			iova = reserve_iova(iovad, lo, hi);
			if (!iova)
				grc_pr_err(
					"iova pfn lo:%#lx hi:%#lx reserve failed!\n",
					lo, hi);
			grc_pr_debug("lo:%#lx hi:%#lx iova:%p\n", lo, hi, iova);
		}
	}
}

int nbl_grc_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	struct nbl_aux_dev *adev = container_of(aux_dev, struct nbl_aux_dev, adev);
	struct nbl_core_dev_info *cdev_info = adev->cdev_info;
	struct nbl_grc *grc;
	int ret;

	nbl_reserve_low_64k_iova(cdev_info->pdev);

	grc = kzalloc(sizeof(*grc), GFP_KERNEL);
	if (!grc)
		return -ENOMEM;

	ret = nbl_fill_core_dev_info(grc, cdev_info);
	if (ret)
		goto host_notify_err;
	grc_set_obj_cnt(grc);

	spin_lock_init(&grc->grp_list_lock);

	grc->ops = &hw_rdma_ops;

	nbl_init_src_addr_rsrc(grc);
	grc_pr_debug("grc pdev=%p,hw_addr=%p,real_hw_addr=0x%llx",
		      grc->core_dev.pdev, grc->core_dev.hw_addr, grc->core_dev.real_hw_addr);

	nbl_grc_eot_table_init(grc);

	nbl_grc_set_dif_vf_off(grc, false);

	ret = nbl_host_notify_init(grc);
	if (ret) {
		grc_pr_err("host_notify_init err=%d", ret);
		goto host_notify_err;
	}

	ret = grc_hbf_tbl_init(grc);
	if (ret) {
		grc_pr_err("hbf_tbl init err=%d", ret);
		goto hbf_tbl_err;
	}

	nbl_set_epro_cfg_err(grc, 1);
	nbl_set_txp_sw_db_wqe_cap(grc);
	grc_set_admin_cqp_bdf_tbl(grc);
	nbl_set_admin_vf_enable(grc, 1);
	nbl_set_fmr_nofence(grc, fmr_nofence);
	ret = grc_cqp_init(grc);
	if (ret)
		goto cmd_init_err;

	ret = nbl_grc_global_sd_init(grc);
	if (ret)
		goto global_sd_init_err;

	grc_mailbox_init(adev);

	grc->admin_wq = create_singlethread_workqueue("grc_admin_wq");
	if (!grc->admin_wq)
		goto admin_wq_init_err;

	INIT_WORK(&grc->abnormal_task, nbl_grc_abnormal_event_handler);
	nbl_init_net_tc_tbl(grc);
	nbl_rdma_stat_init(grc);

	nbl_grc_set_rqdb_int_mask(grc);
	nbl_grc_set_qos_default_cfg(grc);

	adev->abnormal_event_process = grc_abnormal_event_process;
	spin_lock_init(&grc->dev_info_lock);
	INIT_LIST_HEAD(&grc->dev_info_head);
	adev->process_flr_event = grc_flr_event_queue_work;
	adev->reset_event_notify = grc_high_temp_event_process;
	dev_set_drvdata(&aux_dev->dev, grc);
	return 0;

admin_wq_init_err:
	grc_mailbox_destroy(adev);
global_sd_init_err:
	grc_cqp_cleanup(grc);
cmd_init_err:
	nbl_set_fmr_nofence(grc, 0);
	grc_hbf_tbl_free(grc);
hbf_tbl_err:
	nbl_host_notify_deinit(grc);
host_notify_err:
	kfree(grc);
	return ret;
}

void nbl_grc_remove(struct auxiliary_device *adev)
{
	struct nbl_grc *grc = dev_get_drvdata(&adev->dev);
	struct nbl_aux_dev *aux_dev = container_of(adev, struct nbl_aux_dev, adev);

	nbl_grc_global_sd_deinit(grc);
	grc_cqp_cleanup(grc);
	grc_mailbox_destroy(aux_dev);

	nbl_del_src_addr_rsrc(grc);
	nbl_rdma_stat_deinit(grc);
	grc_hbf_tbl_free(grc);
	nbl_host_notify_deinit(grc);
	if (!grc->has_high_temp_alarm) {
		nbl_grc_eot_table_deinit(grc);
		nbl_set_fmr_nofence(grc, 0);
		nbl_set_admin_vf_enable(grc, 0);
		nbl_set_epro_cfg_err(grc, 0);
	}
	aux_dev->abnormal_event_process = NULL;
	aux_dev->process_flr_event = NULL;
	aux_dev->reset_event_notify = NULL;
	destroy_workqueue(grc->admin_wq);
	memset(grc, 0, sizeof(*grc));
	kfree(grc);
}
