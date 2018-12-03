/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2018 Hisilicon Limited. */
#ifndef HISI_ZIP_H
#define HISI_ZIP_H

#include <linux/list.h>
#include "../qm.h"

#undef pr_fmt
#define pr_fmt(fmt)	"hisi_zip: " fmt

enum hisi_zip_error_type {
	/* negative compression */
	HZIP_NC_ERR = 0x0d,
};

struct hisi_zip_ctrl;

struct hisi_zip {
	struct hisi_qm qm;
	struct list_head list;
	struct hisi_zip_ctrl *ctrl;
};

struct hisi_zip_sqe {
	__u32 consumed;
	__u32 produced;
	__u32 comp_data_length;
	__u32 dw3;
	__u32 input_data_length;
	__u32 lba_l;
	__u32 lba_h;
	__u32 dw7;
	__u32 dw8;
	__u32 dw9;
	__u32 dw10;
	__u32 priv_info;
	__u32 dw12;
	__u32 tag;
	__u32 dest_avail_out;
	__u32 rsvd0;
	__u32 comp_head_addr_l;
	__u32 comp_head_addr_h;
	__u32 source_addr_l;
	__u32 source_addr_h;
	__u32 dest_addr_l;
	__u32 dest_addr_h;
	__u32 stream_ctx_addr_l;
	__u32 stream_ctx_addr_h;
	__u32 cipher_key1_addr_l;
	__u32 cipher_key1_addr_h;
	__u32 cipher_key2_addr_l;
	__u32 cipher_key2_addr_h;
	__u32 rsvd1[4];
};

struct hisi_zip *find_zip_device(int node);
int hisi_zip_register_to_crypto(void);
void hisi_zip_unregister_from_crypto(void);
#endif
