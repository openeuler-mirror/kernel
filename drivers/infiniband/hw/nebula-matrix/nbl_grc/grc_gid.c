// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include "grc_main.h"
#include "grc_mailbox.h"
#include "grc_gid.h"

void nbl_init_src_addr_rsrc(struct nbl_grc *grc)
{
	spin_lock_init(&grc->src_addr_rsrc.idx_lock);
	memset(grc->src_addr_rsrc.idx_bitmap, 0,
	       sizeof(grc->src_addr_rsrc.idx_bitmap));
	memset(grc->src_addr_rsrc.addr_tbl, 0,
	       sizeof(grc->src_addr_rsrc.addr_tbl));
}

void nbl_del_src_addr_rsrc(struct nbl_grc *grc)
{
	spin_lock(&grc->src_addr_rsrc.idx_lock);
	memset(grc->src_addr_rsrc.idx_bitmap, 0,
	       sizeof(grc->src_addr_rsrc.idx_bitmap));
	memset(grc->src_addr_rsrc.addr_tbl, 0,
	       sizeof(grc->src_addr_rsrc.addr_tbl));
	spin_unlock(&grc->src_addr_rsrc.idx_lock);
}

void grc_add_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 src_addr_index = 0;
	struct nbl_grc_add_src_addr_info_req *info_req =
		(struct nbl_grc_add_src_addr_info_req *)GRC_GET_CACHE_MSG_DATA(msg);
	struct grc_resp_msg resp_msg;

	spin_lock(&grc->src_addr_rsrc.idx_lock);

	/* alloc src addr index */
	src_addr_index = find_first_zero_bit(grc->src_addr_rsrc.idx_bitmap,
					     MAX_SRC_ADDR_SIZE);
	if (src_addr_index == MAX_SRC_ADDR_SIZE) {
		grc_pr_warn("no available src addr index,%u\n", src_addr_index);
		spin_unlock(&grc->src_addr_rsrc.idx_lock);
		goto error;
	}
	set_bit(src_addr_index, grc->src_addr_rsrc.idx_bitmap);
	grc_pr_debug("grc:%p src_addr_index:%d, function_id:%d.\n", grc,
		     src_addr_index, info_req->function_id);
	/* fill src addr tbl info */
	grc->src_addr_rsrc.addr_tbl[src_addr_index].function_id =
		info_req->function_id;
	grc->src_addr_rsrc.addr_tbl[src_addr_index].sgid_index =
		info_req->sgid_index;
	memcpy(grc->src_addr_rsrc.addr_tbl[src_addr_index].sgid, info_req->sgid,
	       NBL_SRC_IP_SIZE);

	spin_unlock(&grc->src_addr_rsrc.idx_lock);

	/* fill result of rsep info */
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;

	/* fill src addr index of resp info */
	memcpy(resp_msg.msg + 1, &src_addr_index, sizeof(src_addr_index));
	resp_msg.msg_len = sizeof(src_addr_index) + 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);

	return;
error:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_del_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp)
{
	struct nbl_grc_del_src_addr_info_req *info_req =
		(struct nbl_grc_del_src_addr_info_req *)GRC_GET_CACHE_MSG_DATA(msg);
	struct nbl_src_addr_tbl *entry = NULL;
	u16 src_addr_index = info_req->src_addr_index;
	u16 sgid_index = info_req->sgid_index;
	u16 function_id = info_req->function_id;
	struct grc_resp_msg resp_msg;

	if (info_req->src_addr_index >= MAX_SRC_ADDR_SIZE) {
		grc_pr_err("invalid src_addr_index=%u\n", src_addr_index);
		goto invalid_param;
	}

	grc_pr_debug("grc:%p src_addr_index:%d, function_id:%d.\n", grc,
		     src_addr_index, info_req->function_id);
	entry = &grc->src_addr_rsrc.addr_tbl[src_addr_index];
	if (entry->sgid_index != sgid_index || entry->function_id != function_id) {
		grc_pr_err("the sgid_index or function_id is not same as addr_tbl.\n");
		grc_pr_err("the info_req sgid_index is %u, function_id is %u.\n",
			sgid_index, function_id);
		grc_pr_err("the addr_tbl sgid_index is %u, function_id is %u.\n",
			entry->sgid_index, entry->function_id);
		goto invalid_param;
	}

	/* del src addr tbl info */
	spin_lock(&grc->src_addr_rsrc.idx_lock);
	__clear_bit(src_addr_index, grc->src_addr_rsrc.idx_bitmap);
	memset(entry, 0, sizeof(*entry));
	spin_unlock(&grc->src_addr_rsrc.idx_lock);

	/* fill resp info */
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
	return;

invalid_param:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_get_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp)
{
	struct nbl_grc_get_src_addr_info_req *info_req =
		(struct nbl_grc_get_src_addr_info_req *)GRC_GET_CACHE_MSG_DATA(msg);
	struct nbl_src_addr_tbl *addr_tbl = grc->src_addr_rsrc.addr_tbl;
	struct nbl_grc_get_src_addr_info_resp info_resp;
	struct grc_resp_msg resp_msg;
	uint16_t src_addr_index;
	uint16_t sgid_index = info_req->sgid_index;
	uint16_t function_id = info_req->function_id;
	uint16_t i;

	for (i = 0; i < MAX_SRC_ADDR_SIZE; i++) {
		if (addr_tbl[i].function_id == function_id &&
		    addr_tbl[i].sgid_index == sgid_index) {
			break;
		}
	}

	if (i == MAX_SRC_ADDR_SIZE) {
		grc_pr_err("can not find valid src_addr_index, the function_id=%u, the sgid_idx=%u\n",
			function_id, sgid_index);
		goto invalid_param;
	}

	src_addr_index = i;
	memset(&info_resp, 0, sizeof(info_resp));
	info_resp.src_addr_index = src_addr_index;
	memcpy(info_resp.sgid, addr_tbl[src_addr_index].sgid, NBL_SRC_IP_SIZE);

	grc_pr_debug("grc:%p src_addr_index:%d, function_id:%d.\n", grc,
		     src_addr_index, info_req->function_id);
	/* fill result of resp info */
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;

	/* fill src addr index and srp ip info */
	memcpy(resp_msg.msg + 1, &info_resp, sizeof(info_resp));
	resp_msg.msg_len = sizeof(info_resp) + 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);

	return;

invalid_param:
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_send_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp)
{
	struct nbl_grc_send_src_addr_info_req *info_req =
		(struct nbl_grc_send_src_addr_info_req *)GRC_GET_CACHE_MSG_DATA(msg);
	u16 src_addr_index = info_req->src_addr_index;
	struct grc_resp_msg resp_msg;

	/* call callback interface to write register */
	grc->ops->set_src_addr_info(&grc->core_dev, info_req->smac, info_req->sip,
				    info_req->insert_vlan_ipv4_valid, src_addr_index);

	/* fill resp info */
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;

	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}
