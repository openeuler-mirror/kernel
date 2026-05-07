// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include "grc_main.h"
#include "grc_mailbox.h"

u8 grc_get_msg_opcode(void *msg_buf)
{
	struct grc_mbx_msg_header *mbx_msg_head = (struct grc_mbx_msg_header *)msg_buf;

	return mbx_msg_head->op_code;
}

void grc_mailbox_init(struct nbl_aux_dev *aux_dev)
{
	aux_dev->recv = grc_mbx_msg_process;
}

void grc_mailbox_destroy(struct nbl_aux_dev *aux_dev)
{
	aux_dev->recv = NULL;
}
