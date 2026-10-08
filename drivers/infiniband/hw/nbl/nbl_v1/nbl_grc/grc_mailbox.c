// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include "grc_main.h"
#include "grc_mailbox.h"

u8 grc_get_msg_opcode_v1(void *msg_buf)
{
	struct grc_mbx_msg_header *mbx_msg_head = (struct grc_mbx_msg_header *)msg_buf;

	return mbx_msg_head->op_code;
}

static int grc_chan_rcv_event_v1(struct notifier_block *notifier,
				 unsigned long event, void *data)
{
	struct nbl_grc *grc = container_of(notifier, struct nbl_grc,
					  grc_ch_rcv_nb);
	struct nbl_chan_rdma_prm *prm = data;

	if (event != NBL_CORE_EVT_GRC_CHAN_RCV || !prm ||
	    !prm->req || !prm->resp)
		return NOTIFY_DONE;

	grc_mbx_msg_process_v1(grc, prm->req->req_data, prm->req->data_len,
			       prm->resp);
	return NOTIFY_OK;
}

int grc_mailbox_init_v1(struct nbl_grc *grc,
			struct nbl_core_export *core_info)
{
	int ret;

	grc->grc_ch_rcv_nb.notifier_call = grc_chan_rcv_event_v1;
	ret = blocking_notifier_chain_register(&core_info->grc_ch_rcv_nh,
					       &grc->grc_ch_rcv_nb);
	if (ret)
		grc->grc_ch_rcv_nb.notifier_call = NULL;

	return ret;
}

void grc_mailbox_destroy_v1(struct nbl_grc *grc,
			    struct nbl_core_export *core_info)
{
	if (!grc->grc_ch_rcv_nb.notifier_call)
		return;

	blocking_notifier_chain_unregister(&core_info->grc_ch_rcv_nh,
					   &grc->grc_ch_rcv_nb);
	grc->grc_ch_rcv_nb.notifier_call = NULL;
}
