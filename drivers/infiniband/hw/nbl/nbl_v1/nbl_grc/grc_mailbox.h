/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_GRC_MAILBOX_V1_H
#define NBL_GRC_MAILBOX_V1_H

struct grc_mbx_work_ent {
	void *in;
	int in_size;
	void *out;
	int out_size;
	struct completion handling;
	struct completion done;
	struct work_struct work;
	struct delayed_work dwork;
	struct nbl_grc *grc;
	int ret;
	u8 status; /* 0 for cmd exec success, 1 for failed */
};

struct grc_mbx_msg_header {
	u8 rsv;
	u8 op_code;
	u8 payload_len;
};

#define GRC_GET_CACHE_MSG_DATA(mbx_msg) ((mbx_msg) + sizeof(struct grc_mbx_msg_header))

int grc_mailbox_init_v1(struct nbl_grc *grc,
			struct nbl_core_export *core_info);
void grc_mailbox_destroy_v1(struct nbl_grc *grc,
			    struct nbl_core_export *core_info);
u8 grc_get_msg_opcode_v1(void *msg_buf);

#endif /* NBL_GRC_MAILBOX_V1_H */
