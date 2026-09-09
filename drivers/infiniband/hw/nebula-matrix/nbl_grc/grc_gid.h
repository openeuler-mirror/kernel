/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef __GRC_GID_H
#define __GRC_GID_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include "grc_main.h"

#define NBL_SRC_IP_SIZE 16
#define NBL_SRC_MAC_SIZE 6
#define NBL_REG_IPV4_VALID 0x1
#define NBL_REG_VLAN_TAG 0x2
#define NBL_SRC_ADDR_INFO_ENTRY_SIZE 32 /* 256bit, 32Byte */

struct nbl_grc_add_src_addr_info_req {
	u16 function_id;
	u16 sgid_index;
	u8 sgid[16];
};

struct nbl_grc_del_src_addr_info_req {
	u16 src_addr_index;
	u16 sgid_index;
	u16 function_id;
	u8 rsv[2];
};

struct nbl_grc_get_src_addr_info_req {
	u16 function_id;
	u16 sgid_index;
};

struct nbl_grc_get_src_addr_info_resp {
	u16 src_addr_index;
	u8 rsv[2];
	u8 sgid[16];
};

struct nbl_grc_send_src_addr_info_req {
	u16 src_addr_index;
	u8 smac[6];
	u8 sip[16];
	u8 insert_vlan_ipv4_valid;
	u8 rsv[3];
};

void nbl_init_src_addr_rsrc(struct nbl_grc *grc);
void nbl_del_src_addr_rsrc(struct nbl_grc *grc);
void grc_add_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp);
void grc_del_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp);
void grc_get_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			   struct nbl_chan_rdma_resp *mbx_resp);
void grc_send_src_addr_info(struct nbl_grc *grc, void *msg, u16 msg_len,
			    struct nbl_chan_rdma_resp *mbx_resp);

#endif /* __GRC_GID_H */
