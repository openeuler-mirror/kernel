/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef _NBL_MAILBOX_H
#define _NBL_MAILBOX_H

#include "main.h"

#define NBL_MBX_TIMEOUT_MSEC 30 /* time for mbx to finish a request */
#define NBL_MBX_WQ_TIMEOUT_MSEC 5 /* wait time work is being schduled */

struct mbx_resp_msg_header {
	u8 ret_code;
	u8 msg_len;
};

struct nbl_mbx_work_ent {
	void *in;
	int in_size;
	void *out;
	int out_size;
	struct completion done;
	struct work_struct work;
	struct delayed_work dwork;
	struct nbl_mbx *mbx;
	int ret;    /* 0 for cmd exec success, 1 for failed */
	struct nbl_pci_f *rf;
};

int nbl_mbx_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out, int out_size);
int nbl_mbx_roce_init(struct nbl_pci_f *rf);
void nbl_mbx_roce_exit(struct nbl_pci_f *rf);

#endif /* _NBL_MAILBOX_H */
