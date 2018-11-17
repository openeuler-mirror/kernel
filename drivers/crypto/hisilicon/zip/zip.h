/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_ZIP_H
#define HISI_ZIP_H

#include <linux/list.h>
#include "../qm.h"

#define HZIP_SQE_SIZE			128
#define HZIP_SQ_SIZE			(HZIP_SQE_SIZE * QM_Q_DEPTH)
#define QM_CQ_SIZE			(QM_CQE_SIZE * QM_Q_DEPTH)
#define HZIP_PF_DEF_Q_NUM		64
#define HZIP_PF_DEF_Q_BASE		0

struct hisi_zip {
	struct qm_info qm;
	struct list_head list;

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	struct vfio_spimdev *spimdev;
#endif
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

extern struct list_head hisi_zip_list;

#endif
