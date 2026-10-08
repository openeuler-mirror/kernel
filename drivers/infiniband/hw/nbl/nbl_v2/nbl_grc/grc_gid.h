/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef __GRC_GID_H
#define __GRC_GID_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>

void grc_init_src_addr_rsrc(struct nbl_grc *grc);
void grc_del_src_addr_rsrc(struct nbl_grc *grc);
void grc_add_src_addr_info(struct nbl_grc *grc,
	void *msg, u16 msg_len, struct nbl_chan_rdma_resp *mbx_resp);
void grc_del_src_addr_info(struct nbl_grc *grc,
	void *msg, u16 msg_len, struct nbl_chan_rdma_resp *mbx_resp);
void grc_send_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp);
void grc_get_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp);
void grc_chk_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp);
void grc_update_idx_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp);
void grc_print_src_addr_tbl(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp);
#endif /* __GRC_GID_H */
