// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include "grc_main.h"
#include "grc_mailbox.h"
#include "grc_gid.h"
#include "grc_hw_rdma.h"

void grc_init_src_addr_rsrc(struct nbl_grc *grc)
{
	spin_lock_init(&grc->src_addr_rsrc.addr_tbl_lock);
	memset(grc->src_addr_rsrc.addr_tbl, 0,
	       sizeof(grc->src_addr_rsrc.addr_tbl));
}

void grc_del_src_addr_rsrc(struct nbl_grc *grc)
{
	memset(grc->src_addr_rsrc.addr_tbl, 0,
	       sizeof(grc->src_addr_rsrc.addr_tbl));
}

static void grc_fill_src_addr_tbl_direct(struct nbl_grc *grc, u16 src_addr_idx,
	u8 *sip, u16 function_id, u16 sgid_idx, u8 *seq_num)
{
	unsigned long flags;
	u8 tmp_seq;

	spin_lock_irqsave(&grc->src_addr_rsrc.addr_tbl_lock, flags);
	tmp_seq = grc->src_addr_rsrc.addr_tbl[src_addr_idx].seq_num + 1;
	if (tmp_seq == NBL_SRC_ADDR_INDEX_SEQ_NUM_MAX)
		tmp_seq = 0;

	/* fill src addr tbl info */
	grc->src_addr_rsrc.addr_tbl[src_addr_idx].function_id = function_id;
	grc->src_addr_rsrc.addr_tbl[src_addr_idx].sgid_index = sgid_idx;
	memcpy(grc->src_addr_rsrc.addr_tbl[src_addr_idx].sgid, sip, NBL_SRC_IP_SIZE);
	grc->src_addr_rsrc.addr_tbl[src_addr_idx].seq_num = tmp_seq;

	spin_unlock_irqrestore(&grc->src_addr_rsrc.addr_tbl_lock, flags);
	*seq_num = tmp_seq;
}

static void grc_update_idx_src_addr_info_direct(struct nbl_grc *grc,
	u16 src_addr_index, u16 sgid_index)
{
	struct nbl_src_addr_tbl *entry;
	unsigned long flags;

	spin_lock_irqsave(&grc->src_addr_rsrc.addr_tbl_lock, flags);
	entry = &grc->src_addr_rsrc.addr_tbl[src_addr_index];
	entry->sgid_index = sgid_index;
	spin_unlock_irqrestore(&grc->src_addr_rsrc.addr_tbl_lock, flags);
}

static void grc_chk_src_addr_info_direct(struct nbl_grc *grc,
	u16 function_id, union ib_gid *ib_gid, u8 *found)
{
	struct nbl_src_addr_tbl *addr_tbl = grc->src_addr_rsrc.addr_tbl;
	u16 max_src_addr_size = MAX_SRC_ADDR_SIZE_V2;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&grc->src_addr_rsrc.addr_tbl_lock, flags);
	for (i = 0; i < max_src_addr_size; i++) {
		if (addr_tbl[i].function_id == function_id &&
			!memcmp(addr_tbl[i].sgid, ib_gid->raw, NBL_SRC_IP_SIZE)) {
			break;
		}
	}
	spin_unlock_irqrestore(&grc->src_addr_rsrc.addr_tbl_lock, flags);

	if (i < max_src_addr_size)
		*found = 1;
	else
		*found = 0;
}

static int grc_get_src_addr_info_direct(struct nbl_grc *grc, u16 function_id,
	u16 gid_idx, u16 *src_addr_index, u8 *src_ip, u8 *seq_num)
{
	struct nbl_src_addr_tbl *addr_tbl = grc->src_addr_rsrc.addr_tbl;
	u16 max_src_addr_size = MAX_SRC_ADDR_SIZE_V2;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&grc->src_addr_rsrc.addr_tbl_lock, flags);
	for (i = 0; i < max_src_addr_size; i++) {
		if (addr_tbl[i].function_id == function_id &&
		    addr_tbl[i].sgid_index == gid_idx) {
			break;
		}
	}
	spin_unlock_irqrestore(&grc->src_addr_rsrc.addr_tbl_lock, flags);

	if (i == max_src_addr_size) {
		grc_pr_err(
			"can not find valid src_addr_index, the function_id=%u, the sgid_idx=%u\n",
			function_id, gid_idx);
		return -EINVAL;
	}

	*src_addr_index = i;
	if (src_ip)
		memcpy(src_ip, addr_tbl[i].sgid, NBL_SRC_IP_SIZE);

	if (seq_num)
		*seq_num = addr_tbl[i].seq_num;

	return 0;
}

static int grc_del_src_addr_entry_direct(struct nbl_grc *grc,
	u16 function_id, u16 sgid_index, u16 src_addr_index)
{
	struct  nbl_src_addr_tbl *entry = NULL;
	u8 tmp_seq_num;
	unsigned long flags;

	entry = &grc->src_addr_rsrc.addr_tbl[src_addr_index];
	if (entry->sgid_index != sgid_index || entry->function_id != function_id) {
		grc_pr_err("Err, del src addr(fun %u, gid idx %u) with src idx %u, not match\n",
			function_id, sgid_index, src_addr_index);
		grc_pr_err("src add table data is (fun %u, gid idx %u) with src idx %u\n",
			entry->function_id, entry->sgid_index, src_addr_index);
		return -EINVAL;
	}

	/* del src addr tbl info */
	spin_lock_irqsave(&grc->src_addr_rsrc.addr_tbl_lock, flags);
	tmp_seq_num = grc->src_addr_rsrc.addr_tbl[src_addr_index].seq_num;
	memset(entry, 0, sizeof(*entry));
	grc->src_addr_rsrc.addr_tbl[src_addr_index].seq_num = tmp_seq_num;
	spin_unlock_irqrestore(&grc->src_addr_rsrc.addr_tbl_lock, flags);

	return 0;
}

void grc_add_src_addr_info(struct nbl_grc *grc,
	void *msg, u16 msg_len, struct nbl_chan_rdma_resp *mbx_resp)
{
	u16 src_addr_idx;
	int ret;
	struct grc_resp_msg resp_msg;

	ret = grc->resource_ops->get_hw_inst_id(grc, NBL_INST_SMAC_IP_INDEX,
						&src_addr_idx);
	if (ret) {
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		resp_msg.msg_len = 1;
		goto get_src_addr_idx_err;
	}

	memcpy(resp_msg.msg + 1, &src_addr_idx, sizeof(src_addr_idx));
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = sizeof(src_addr_idx) + 1;

get_src_addr_idx_err:
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_del_src_addr_info(struct nbl_grc *grc,
	void *msg, u16 msg_len, struct nbl_chan_rdma_resp *mbx_resp)
{
	int ret;
	struct grc_resp_msg resp_msg;
	struct nbl_grc_del_src_addr_info_req *req = GRC_GET_CACHE_MSG_DATA(msg);

	ret = grc_del_src_addr_entry_direct(grc,
			req->function_id, req->sgid_idx, req->src_addr_index);
	if (ret) {
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		goto put_src_addr_idx_err;
	}

	ret = grc->resource_ops->put_hw_inst_id(grc, NBL_INST_SMAC_IP_INDEX,
						req->src_addr_index);
	if (ret) {
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		goto put_src_addr_idx_err;
	}

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;

put_src_addr_idx_err:
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_send_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct nbl_grc_send_src_addr_info_req *req = GRC_GET_CACHE_MSG_DATA(msg);
	u8 seq_num;

	grc_fill_src_addr_tbl_direct(grc, req->src_addr_index,
		req->sip, req->function_id, req->sgid_idx, &seq_num);

	grc_pr_debug("grc set src addr idx=%u, seq_num=%u, sgid_idx=%u",
		    req->src_addr_index, seq_num, req->sgid_idx);

	grc->resource_ops->set_src_addr_info(grc, req->smac, req->sip,
					 req->src_addr_index, seq_num);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_get_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp)
{
	int ret;
	struct grc_resp_msg resp_msg;
	struct nbl_get_src_addr_info_req *req = GRC_GET_CACHE_MSG_DATA(msg);
	struct nbl_get_src_addr_info_resp resp = {0};

	ret = grc_get_src_addr_info_direct(grc, req->function_id, req->sgid_idx,
				&resp.src_addr_index, resp.sip, &resp.seq_num);
	if (ret) {
		resp_msg.msg[0] = NBL_GRC_MSG_RESP_ERR;
		resp_msg.msg_len = 1;
		goto get_src_addr_info_err;
	}

	memcpy(resp_msg.msg + 1, &resp, sizeof(resp));
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = sizeof(resp) + 1;

get_src_addr_info_err:
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_chk_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct nbl_chk_src_addr_info_req *req = GRC_GET_CACHE_MSG_DATA(msg);
	struct nbl_chk_src_addr_info_resp resp = {0};

	grc_chk_src_addr_info_direct(grc, req->function_id, &req->ib_gid,
					   &resp.found);

	memcpy(resp_msg.msg + 1, &resp, sizeof(resp));
	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = sizeof(resp) + 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_update_idx_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp)
{
	struct grc_resp_msg resp_msg;
	struct nbl_grc_update_idx_src_addr_info_req *req = GRC_GET_CACHE_MSG_DATA(msg);

	grc_update_idx_src_addr_info_direct(grc, req->src_addr_index, req->sgid_idx);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void grc_print_src_addr_tbl(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp)
{
	int i, j = 0;
	u32 print_cnt;
	unsigned long flags;
	u32 max_entry = MAX_SRC_ADDR_SIZE_V2 / grc->core_dev.eth_mode;
	struct grc_resp_msg resp_msg;
	struct nbl_src_addr_tbl *addr_tbl = grc->src_addr_rsrc.addr_tbl;
	struct print_grc_src_addr_tbl_req *req =
		(struct print_grc_src_addr_tbl_req *)GRC_GET_CACHE_MSG_DATA(msg);

	grc_pr_notice("print grc src_addr tbl,cnt=%u\n", req->print_cnt);
	print_cnt = min_t(u32, max_entry, req->print_cnt);
	spin_lock_irqsave(&grc->src_addr_rsrc.addr_tbl_lock, flags);
	for (i = max_entry * grc->core_dev.real_function; i < MAX_SRC_ADDR_SIZE_V2; i++) {
		if (j >= print_cnt)
			break;
		grc_pr_notice("function_id=%u,src_addr_idx=%d,sgid_index=%u,sgid=%pI6,seqnum=%u\n",
			      addr_tbl[i].function_id, i, addr_tbl[i].sgid_index,
			      addr_tbl[i].sgid, addr_tbl[i].seq_num);
		j++;
	}

	spin_unlock_irqrestore(&grc->src_addr_rsrc.addr_tbl_lock, flags);

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;
	resp_msg.msg_len = 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}
