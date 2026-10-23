// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2026, NEBULARMATRIX */

#include <linux/bitfield.h>
#include "grc_main.h"
#include "grc_cqp.h"
#include "grc_mailbox.h"
#include "grc_hw_rdma.h"
#include "grc_flr.h"

static int grc_add_dev_info_node(struct nbl_grc *grc, struct dev_info *vf_info)
{
	struct dev_info_node *node, *tmp;
	struct dev_info_node *new_node;

	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
		return -ENOMEM;
	memcpy(&new_node->vf_info, vf_info, sizeof(*vf_info));

	mutex_lock(&grc->dev_info_lock);
	list_for_each_entry_safe(node, tmp, &grc->dev_info_head, list) {
		if (node->vf_info.vsi_id == vf_info->vsi_id) {
			grc_pr_notice("found exist node vsi:%d,ethid:%u,rdma vfid:%u remove it.\n",
				      vf_info->vsi_id, vf_info->eth_id, vf_info->function_id);
			list_del(&node->list);
			kfree(node);
		}
	}

	list_add(&new_node->list, &grc->dev_info_head);
	mutex_unlock(&grc->dev_info_lock);

	return 0;
}

static void grc_del_dev_info_node(struct nbl_grc *grc, u16 vsi_id)
{
	struct dev_info_node *node, *tmp;

	mutex_lock(&grc->dev_info_lock);
	list_for_each_entry_safe(node, tmp, &grc->dev_info_head, list) {
		if (node->vf_info.vsi_id == vsi_id) {
			list_del(&node->list);
			kfree(node);
		}
	}
	mutex_unlock(&grc->dev_info_lock);
}

void grc_add_vf_flr_client(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp)
{
	int err;
	struct dev_info vf_info;
	struct grc_resp_msg resp_msg;
	struct register_client_req *req = GRC_GET_CACHE_MSG_DATA(msg);

	dev_dbg(&grc->grc_dev->adev.dev, "add FLR client,vsi_id=%u,vfid=%u,bdf=%#x,ethid=%u\n",
		req->vsi_id, req->function_id, req->real_bdf, req->eth_id);

	vf_info.vsi_id = req->vsi_id;
	vf_info.real_bdf = req->real_bdf;
	vf_info.function_id = req->function_id;
	vf_info.eth_id = req->eth_id;
	err = grc_add_dev_info_node(grc, &vf_info);
	if (err) {
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		goto add_err;
	}

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
add_err:
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_del_vf_flr_client(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct register_client_req *req = GRC_GET_CACHE_MSG_DATA(msg);

	dev_dbg(&grc->grc_dev->adev.dev, "del FLR client,vsi_id=%u,vfid=%u,bdf=%#x,ethid=%u\n",
		req->vsi_id, req->function_id, req->real_bdf, req->eth_id);

	grc_del_dev_info_node(grc, req->vsi_id);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

static void grc_flush_s1_cache_cmd(u32 qpn, u16 flush_vfid,
				   struct nbl_grc *grc, bool vf_flush_flag)
{
	int ret = 0;
	__be64 *in;
	u16 function_id = flush_vfid;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_FLUSH_CACHE);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_TYPE, FLUSH_CACHE_S1);
	nbl_64bit_write(in, NBL_CQP_V2_FLUSH_FLAG, vf_flush_flag);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_QPN, qpn);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_VFID, function_id);

	ret = grc_cmd_exec(grc, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		dev_err(&grc->core_dev.pdev->dev, "flush s1 cache fail=%d,flush_flag=%u,vfid=%u\n",
			ret, vf_flush_flag, function_id);
	kfree(in);
}

static void grc_flush_s2_cache(struct nbl_grc *grc, u16 flush_vfid)
{
	int err_code = 0;
	__be64 *in;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_FLUSH_CACHE);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_TYPE, FLUSH_CACHE_S2);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_VFID, flush_vfid);

	err_code = grc_cmd_exec(grc, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		dev_err(&grc->core_dev.pdev->dev, "flush s2_cache cmd err=%d", err_code);

	kfree(in);
}

static void grc_flush_pdc_cache(struct nbl_grc *grc, u16 flush_vfid)
{
	int ret = 0;
	__be64 *in;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_FLUSH_CACHE);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_TYPE, FLUSH_CACHE_PDC);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_VFID, flush_vfid);

	ret = grc_cmd_exec(grc, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		dev_err(&grc->core_dev.pdev->dev, "CQP QP FLUSH CACHE PDC failed(%u)\n", ret);
	kfree(in);
}

static void find_and_free_function_id(struct nbl_grc *grc, u16 bdf_num, int fn_id)
{
	u16 i;
	int ret_val;
	struct nbl_hbf_entry *entry;

	if (!nbl_func_id_valid(grc, fn_id)) {
		grc_pr_err("invalid function_id=%u\n", fn_id);
		return;
	}

	for (i = 0; i < grc->hbf_tbl->tbl_size; i++) {
		entry = &grc->hbf_tbl->entries[i];
		if (entry->func_id == fn_id && entry->bdf_num == bdf_num) {
			ret_val = grc->resource_ops->put_hw_inst_id(grc,
								  NBL_INST_VFID, fn_id);
			if (ret_val)
				return;

			memset(entry, 0, sizeof(*entry));
			grc->res_cfg.total_qp_cnt += grc->res_cfg.qp_per_vf;
			grc->resource_ops->set_bdf_func_id_map(grc, false, 0,
								      fn_id);
			return;
		}
	}

	grc_pr_err("not match free_fn_id_req,bdf_num=0x%x,fn_id=%u\n", bdf_num, fn_id);
}

static void grc_flr_restore_res(struct nbl_grc *grc, struct dev_info *info)
{
	grc->resource_ops->set_vfid_vsi_map(grc, info->function_id,
					    info->vsi_id, false);

	grc->resource_ops->set_cqp_info(grc, info->function_id, 0, 0, false);

	grc->dsch_ops->set_rdma_dsch(grc, info->function_id,
				     HOST_ID_TYPE_HOST, info->eth_id, false);

	grc_flush_s1_cache_cmd(0, info->function_id, grc, true);
	grc_flush_s2_cache(grc, info->function_id);
	grc_flush_pdc_cache(grc, info->function_id);

	grc->resource_ops->set_vf_enable(grc, info->function_id, false);

	find_and_free_function_id(grc, info->real_bdf, info->function_id);
}

static void grc_flr_event_handler(struct work_struct *work)
{
	struct grc_flr_work *flr_work =
		container_of(work, struct grc_flr_work, work);
	struct nbl_grc *grc = flr_work->grc;
	struct dev_info_node *node, *tmp;

	mutex_lock(&grc->dev_info_lock);
	list_for_each_entry_safe(node, tmp, &grc->dev_info_head, list) {
		if (node->vf_info.vsi_id == flr_work->vsi_id) {
			grc_pr_notice("found node vsi:%d bdf:%#x vfid:%d eth_id:%d\n",
				      flr_work->vsi_id, node->vf_info.real_bdf,
				      node->vf_info.function_id, node->vf_info.eth_id);

			grc_flr_restore_res(grc, &node->vf_info);

			list_del(&node->list);
			kfree(node);
			break;
		}
	}
	mutex_unlock(&grc->dev_info_lock);

	kfree(flr_work);
}

void grc_flr_event_queue_work(struct nbl_grc *grc, u16 vsi_id)
{
	struct grc_flr_work *flr_work =
		kzalloc(sizeof(*flr_work), GFP_KERNEL);

	dev_info(&grc->grc_dev->adev.dev, "[rdma] grc recv FLR vsi_id=%u", vsi_id);
	if (!flr_work)
		return;

	flr_work->grc = grc;
	flr_work->vsi_id = vsi_id;
	INIT_WORK(&flr_work->work, grc_flr_event_handler);
	queue_work(grc->admin_wq, &flr_work->work);
}
