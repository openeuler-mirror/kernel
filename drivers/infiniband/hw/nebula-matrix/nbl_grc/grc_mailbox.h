/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_GRC_MAILBOX_H
#define NBL_GRC_MAILBOX_H

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

void grc_mailbox_init(struct nbl_aux_dev *aux_dev);
void grc_mailbox_destroy(struct nbl_aux_dev *aux_dev);
u8 grc_get_msg_opcode(void *msg_buf);

#endif /* NBL_GRC_MAILBOX_H */
