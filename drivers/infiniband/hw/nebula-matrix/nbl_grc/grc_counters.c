// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "grc_main.h"
#include "grc_mailbox.h"
#include "grc_counters.h"

void nbl_rdma_stat_init(struct nbl_grc *grc)
{
	int i;

	for (i = 0; i < NBL_STATS_GROUP_NUM; i++) {
		grc->stat_info.stat_id_used_cnt[i] = 0;
		INIT_LIST_HEAD(&grc->stat_info.stat_head[i]);
		spin_lock_init(&grc->stat_info.stat_head_lock[i]);
	}
	spin_lock_init(&grc->stat_lock);
}

void nbl_rdma_stat_deinit(struct nbl_grc *grc)
{
	int i;
	struct nbl_qp_func *cur_node;
	struct nbl_qp_func *tmp_node;

	for (i = 0; i < NBL_STATS_GROUP_NUM; i++) {
		if (grc->stat_info.stat_id_used_cnt[i] == 0)
			continue;

		grc->stat_info.stat_id_used_cnt[i] = 0;

		spin_lock(&grc->stat_info.stat_head_lock[i]);
		list_for_each_entry_safe(cur_node, tmp_node,
					  &grc->stat_info.stat_head[i], list) {
			list_del(&cur_node->list);
			kfree(cur_node);
		}
		spin_unlock(&grc->stat_info.stat_head_lock[i]);
	}
}

void grc_add_stat_id(struct nbl_grc *grc, void *req_msg, u16 msg_len,
		     struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 *msg;
	u16 func_id;
	u32 qpn;
	u8 stat_id;
	struct nbl_qp_func *new_node;
	struct grc_resp_msg resp_msg;

	msg = (u16 *)GRC_GET_CACHE_MSG_DATA(req_msg);
	func_id = *msg;
	qpn = *(u32 *)(msg + 1);

	grc_pr_debug("add_stat_id func_id:%d, qpn:%d.\n", func_id, qpn);

	/* get avail id */
	for (stat_id = NBL_STATS_GROUP_START_NUM; stat_id < NBL_STATS_GROUP_NUM;
	     stat_id++) {
		if (grc->stat_info.stat_id_used_cnt[stat_id] == 0)
			break;
	}

	if (stat_id == NBL_STATS_GROUP_NUM)
		goto error_occur;

	new_node = kcalloc(1, sizeof(struct nbl_qp_func), GFP_KERNEL);
	if (!new_node)
		goto error_occur;

	new_node->func_id = func_id;
	new_node->qpn = qpn;
	INIT_LIST_HEAD(&new_node->list);

	spin_lock(&grc->stat_info.stat_head_lock[stat_id]);
	list_add_tail(&new_node->list, &grc->stat_info.stat_head[stat_id]);
	spin_unlock(&grc->stat_info.stat_head_lock[stat_id]);

	grc->stat_info.stat_id_used_cnt[stat_id]++;

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &stat_id, sizeof(stat_id));
	resp_msg.msg_len = sizeof(stat_id) + 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);

	return;

error_occur:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_del_stat_id(struct nbl_grc *grc, void *req_msg, u16 msg_len,
		     struct nbl_chan_rdma_resp *mbx_resp)
{
	u8 *msg;
	u8 stat_id;
	u16 func_id;
	u32 qpn;
	struct nbl_qp_func *cur_node;
	struct nbl_qp_func *tmp_node;
	bool found = false;
	struct grc_resp_msg resp_msg;

	msg = (u8 *)GRC_GET_CACHE_MSG_DATA(req_msg);
	stat_id = *msg;
	func_id = *(u16 *)(msg + sizeof(stat_id));
	qpn = *(u32 *)(msg + sizeof(stat_id) + sizeof(func_id));

	grc_pr_debug("del_stat_id stat_id:%d, func_id:%d, qpn:%d.\n",
		      stat_id, func_id, qpn);

	if (grc->stat_info.stat_id_used_cnt[stat_id] == 0)
		goto error_occur;

	spin_lock(&grc->stat_info.stat_head_lock[stat_id]);
	list_for_each_entry_safe(cur_node, tmp_node,
				  &grc->stat_info.stat_head[stat_id], list) {
		if (cur_node->func_id == func_id && cur_node->qpn == qpn) {
			found = true;
			list_del(&cur_node->list);
			kfree(cur_node);
			break;
		}
	}
	spin_unlock(&grc->stat_info.stat_head_lock[stat_id]);

	if (found) {
		grc->stat_info.stat_id_used_cnt[stat_id]--;

		resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
		resp_msg.msg_len = 1;

		mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
		memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
		return;
	}

error_occur:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_mod_stat_id(struct nbl_grc *grc, void *req_msg, u16 msg_len,
		     struct nbl_chan_rdma_resp *mbx_resp)
{
	u8 *msg;
	u8 stat_id_old;
	u8 stat_id_new;
	u16 func_id;
	u32 qpn;
	struct nbl_qp_func *cur_node;
	struct nbl_qp_func *tmp_node;
	struct nbl_qp_func *new_node;
	bool found = false;
	int data_len = 0;
	struct grc_resp_msg resp_msg;

	msg = (u8 *)GRC_GET_CACHE_MSG_DATA(req_msg);
	stat_id_old = *msg;
	data_len += sizeof(stat_id_old);

	stat_id_new = *(u8 *)(msg + data_len);
	data_len += sizeof(stat_id_new);

	func_id = *(u16 *)(msg + data_len);
	data_len += sizeof(func_id);

	qpn = *(u32 *)(msg + data_len);
	data_len += sizeof(qpn);
	grc_pr_debug("mod_stat_id old:%d, new:%d, func_id:%d, qpn:%d.\n",
		      stat_id_old, stat_id_new, func_id, qpn);

	/* del old stat-id */
	if (grc->stat_info.stat_id_used_cnt[stat_id_old] != 0) {
		spin_lock(&grc->stat_info.stat_head_lock[stat_id_old]);
		list_for_each_entry_safe(
			cur_node, tmp_node,
			&grc->stat_info.stat_head[stat_id_old], list) {
			if (cur_node->func_id == func_id && cur_node->qpn == qpn) {
				found = true;
				list_del(&cur_node->list);
				kfree(cur_node);
				break;
			}
		}
		spin_unlock(&grc->stat_info.stat_head_lock[stat_id_old]);

		if (!found)
			goto error_occur;

		grc->stat_info.stat_id_used_cnt[stat_id_old]--;
	}

	/* add new stat-id */
	new_node = kcalloc(1, sizeof(struct nbl_qp_func), GFP_KERNEL);
	if (!new_node)
		goto error_occur;

	new_node->func_id = func_id;
	new_node->qpn = qpn;
	INIT_LIST_HEAD(&new_node->list);

	spin_lock(&grc->stat_info.stat_head_lock[stat_id_new]);
	list_add_tail(&new_node->list, &grc->stat_info.stat_head[stat_id_new]);
	spin_unlock(&grc->stat_info.stat_head_lock[stat_id_new]);

	grc->stat_info.stat_id_used_cnt[stat_id_new]++;

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);

	return;

error_occur:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_get_used_cnt(struct nbl_grc *grc, void *msg, u16 msg_len,
		      struct nbl_chan_rdma_resp *mbx_resp)
{
	u8 stat_id;
	u32 used_cnt;
	struct grc_resp_msg resp_msg;

	stat_id = *(u8 *)GRC_GET_CACHE_MSG_DATA(msg);
	used_cnt = grc->stat_info.stat_id_used_cnt[stat_id];
	grc_pr_debug("get_used_cnt stat_id:%d, used_cnt:%d.\n", stat_id, used_cnt);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	memcpy(resp_msg.msg + 1, &used_cnt, sizeof(used_cnt));
	resp_msg.msg_len = sizeof(used_cnt) + 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

int get_hw_status(struct nbl_grc *grc)
{
	u32 status;

	/* call callback interface to read register */
	grc->ops->get_hw_status(&grc->core_dev, &status);

	return RS_32(status, NBL_STATS_OP_STATUS);
}

void nbl_grc_hw_stat_read(struct nbl_grc *grc, void *req_msg, u16 msg_len,
			  struct nbl_chan_rdma_resp *mbx_resp)
{
	u32 op_info;
	u32 pa_l;
	u32 pa_h;
	u16 func_id;
	int data_len = 0;
	u8 *msg;
	struct grc_resp_msg resp_msg;

	msg = (u8 *)GRC_GET_CACHE_MSG_DATA(req_msg);
	op_info = *(u32 *)msg;
	data_len += sizeof(op_info);

	pa_l = *(u32 *)(msg + data_len);
	data_len += sizeof(pa_l);

	pa_h = *(u32 *)(msg + data_len);
	data_len += sizeof(pa_h);

	func_id = *(uint16_t *)(msg + data_len);
	data_len += sizeof(func_id);
	grc_pr_debug("hw_read info:0x%x, pa_l:0x%x, pa_h:0x%x, func_id:%d\n",
		     op_info, pa_l, pa_h, func_id);

	if (get_hw_status(grc) != 0) {
		resp_msg.msg[0] = NBL_GRC_CACHE_MSG_RESP_BUSY;
		resp_msg.msg_len = 1;
		grc_pr_err("HW is busy, please clear again later.\n");
		mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
		memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
		return;
	}

	/* call callback interface to write register */
	spin_lock(&grc->stat_lock);
	grc->ops->get_hw_stat(&grc->core_dev, op_info, pa_l, pa_h, func_id);
	spin_unlock(&grc->stat_lock);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_hw_stat_clear(struct nbl_grc *grc, void *msg, u16 msg_len,
		       struct nbl_chan_rdma_resp *mbx_resp)
{
	u32 op_info;
	struct grc_resp_msg resp_msg;

	op_info = *(u32 *)GRC_GET_CACHE_MSG_DATA(msg);
	grc_pr_debug("hw_clear op_info:0x%x.\n", op_info);

	if (get_hw_status(grc) != 0) {
		resp_msg.msg[0] = NBL_GRC_CACHE_MSG_RESP_BUSY;
		resp_msg.msg_len = 1;
		grc_pr_err("HW is busy, please clear again later.\n");
		mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
		memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
		return;
	}

	/* call callback interface to write register */
	spin_lock(&grc->stat_lock);
	grc->ops->set_hw_stat(&grc->core_dev, op_info);
	spin_unlock(&grc->stat_lock);

	grc_pr_debug("Clear successfully.\n");
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_hw_stat_errcode_enable(struct nbl_grc *grc, void *msg, u16 msg_len,
				struct nbl_chan_rdma_resp *mbx_resp)
{
	bool enable = *(bool *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;

	if (get_hw_status(grc) != 0) {
		resp_msg.msg[0] = NBL_GRC_CACHE_MSG_RESP_BUSY;
		resp_msg.msg_len = 1;
		grc_pr_err("HW is busy, please try again later.\n");
		mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
		memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
		return;
	}

	/* call callback interface to write register */
	spin_lock(&grc->stat_lock);
	grc->ops->enable_errcode_hw_stat(&grc->core_dev, (u32)enable);
	spin_unlock(&grc->stat_lock);

	grc_pr_debug("Configuration succeeded.\n");
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}
