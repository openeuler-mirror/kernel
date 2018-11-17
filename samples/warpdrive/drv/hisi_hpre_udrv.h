/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_HPRE_UDRV_H__
#define HISI_HPRE_UDRV_H__

#include <linux/types.h>
#include "../wd.h"

#define HPRE_SQE_SIZE		64
#define HPRE_CQE_SIZE		16
#define HPRE_EQ_DEPTH		1024

/* cqe shift */
#define HPRE_CQE_PHASE(cq)		(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define HPRE_CQE_SQ_NUM(cq)		((*((__u32 *)(cq) + 2)) >> 16)
#define HPRE_CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

#define HPRE_BAR2_SIZE			(4 * 1024 * 1024)

#define HPRE_DOORBELL_OFFSET		0x1000

#define SQE_DONE_FLAG_SHIFT		30

enum hpre_alg_type {
	HPRE_ALG_NC_NCRT = 0x0,
	HPRE_ALG_NC_CRT = 0x1,
	HPRE_ALG_KG_STD = 0x2,
	HPRE_ALG_KG_CRT = 0x3,
	HPRE_ALG_DH_G2 = 0x4,
	HPRE_ALG_DH = 0x5,
	HPRE_ALG_PRIME = 0x6,
	HPRE_ALG_MOD = 0x7,
	HPRE_ALG_MOD_INV = 0x8,
	HPRE_ALG_MUL = 0x9,
	HPRE_ALG_COPRIME = 0xA
};


struct hpre_cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7; /* phase, status */
};

struct hpre_sqe {
	__u32 alg	: 5;

	/* error type */
	__u32 etype	:11;
	__u32 resv0	: 14;

	__u32 done	: 2;

	__u32 task_len1	: 8;
	__u32 task_len2	: 8;
	__u32 mrttest_num : 8;
	__u32 resv1	: 8;

	__u32 low_key;
	__u32 hi_key;
	__u32 low_in;
	__u32 hi_in;
	__u32 low_out;
	__u32 hi_out;

	__u32 tag	:16;
	__u32 resv2	:16;
	__u32 rsvd1[7];
};

struct hpre_queue_info {
	int ver;
	struct hpre_sqe cache_sqe;
	void *dma_buf;
	unsigned long long dma_page;
	void *sq_base;
	void *sq_buf;
	void *cq_base;
	void *doorbell_base;
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	int cqc_phase;
	void *recv;
	int is_sq_full;
	int (*db)(struct hpre_queue_info *q, __u8 cmd, __u16 index,
		  __u8 priority);
};

int hpre_set_queue_dio(struct wd_queue *q);
void hpre_unset_queue_dio(struct wd_queue *q);
int hpre_add_to_dio_q(struct wd_queue *q, void *req);
int hpre_get_from_dio_q(struct wd_queue *q, void **resp);
int hpre_get_capa(struct wd_capa *capa);

#define HPRE_QM_SET_QP		_IOR('d', 1, unsigned long long)
#define HPRE_QM_SET_PASID	_IOW('d', 2, unsigned long)
#define HPRE_GET_DMA_PAGES		_IOW('d', 3, unsigned long long)
#define HPRE_PUT_DMA_PAGES		_IOW('d', 4, unsigned long long)

#define DOORBELL_CMD_SQ		0
#define DOORBELL_CMD_CQ		1

#endif
