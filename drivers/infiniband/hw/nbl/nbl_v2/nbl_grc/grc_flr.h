/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2026, NEBULARMATRIX */

#ifndef NBL_GRC_FLR_H
#define NBL_GRC_FLR_H

struct dev_info {
	u16	vsi_id;
	u16	real_bdf;
	u16	function_id;
	u16	eth_id;
};
struct dev_info_node {
	struct list_head list;
	struct dev_info vf_info;
};

struct grc_flr_work {
	struct work_struct work;
	struct nbl_grc *grc;
	u16 vsi_id;
};

void grc_add_vf_flr_client(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp);
void grc_del_vf_flr_client(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp);
void grc_flr_event_queue_work(struct nbl_grc *grc, u16 vsi_id);

#endif /* NBL_GRC_FLR_H */
