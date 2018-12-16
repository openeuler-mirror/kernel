/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HISI_ZIP_DRV_H__
#define __HISI_ZIP_DRV_H__

#include <linux/types.h>
#include "../wd.h"

/* this is unnecessary big, the hardware should optimize it */
struct hisi_zip_msg {
	__u32 consumed;
	__u32 produced;
	__u32 comp_date_length;
	__u32 dw3;
	__u32 input_date_length;
	__u32 lba_l;
	__u32 lba_h;
	__u32 dw7; /* ... */
	__u32 dw8; /* ... */
	__u32 dw9; /* ... */
	__u32 dw10; /* ... */
	__u32 priv_info;
	__u32 dw12; /* ... */
	__u32 tag;
	__u32 dest_avail_out;
	__u32 ctx_dw0;
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
	__u32 ctx_dw1;
	__u32 ctx_dw2;
	__u32 isize;
	__u32 checksum;
};

struct hisi_acc_zip_sqc {
	__u16 sqn;
};

#define DOORBELL_CMD_SQ		0
#define DOORBELL_CMD_CQ		1

int hisi_zip_set_queue_dio(struct wd_queue *q);
void hisi_zip_unset_queue_dio(struct wd_queue *q);
int hisi_zip_add_to_dio_q(struct wd_queue *q, void *req);
int hisi_zip_get_from_dio_q(struct wd_queue *q, void **resp);
int hisi_zip_get_capa(struct wd_capa *capa);

#define ZIP_GET_DMA_PAGES		_IOW('d', 3, unsigned long long)
#define ZIP_PUT_DMA_PAGES		_IOW('d', 4, unsigned long long)
#define HACC_QM_SET_OPTYPE		_IOW('d', 5, unsigned long long)

#endif
