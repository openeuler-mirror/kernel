/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_TLP_H
#define NBL_IB_TLP_H

#include "main.h"

#define RDMA_TLP_WRITE_OFFSET 0x0200
#define RDMA_TLP_READ_OFFSET_MIN 64
#define TLP_RD_REG_LEN 4

#define NBL_TLP_WQ_TIMEOUT_MSEC 5 /* wait time work is being schduled */

struct tlp_read_msg_header {
	u8 ret_code;
	u8 msg_len;
};

struct nbl_tlp_work_ent {
	void *in;
	int in_size;
	void *out;
	int out_size;
	struct completion done;
	struct work_struct work;
	struct delayed_work dwork;
	struct nbl_tlp *tlp;
	int ret;    /* 0 for cmd exec success, 1 for failed */
};

int nbl_tlp_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out,
		int out_size);
int nbl_tlp_init(struct nbl_pci_f *rf);
void nbl_tlp_exit(struct nbl_pci_f *rf);

#endif /* NBL_IB_TLP_H */
