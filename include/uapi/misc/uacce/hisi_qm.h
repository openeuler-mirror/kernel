/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_HISI_QM_H
#define _UAPI_HISI_QM_H

#include <linux/types.h>
#define QM_CQE_SIZE			16

/* default queue depth for sq/cq/eq */
#define QM_Q_DEPTH			1024

/* page number for queue file region */
#define QM_DOORBELL_PAGE_NR	1
#define QM_DKO_PAGE_NR		4
#define QM_DUS_PAGE_NR		36

#define QM_DOORBELL_PG_START 0
#define QM_DKO_PAGE_START (QM_DOORBELL_PG_START + QM_DOORBELL_PAGE_NR)
#define QM_DUS_PAGE_START (QM_DKO_PAGE_START + QM_DKO_PAGE_NR)
#define QM_SS_PAGE_START (QM_DUS_PAGE_START + QM_DUS_PAGE_NR)

#define QM_DOORBELL_OFFSET      0x340
#define QM_V2_DOORBELL_OFFSET   0x1000

struct cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7;
};

/**
 * struct hisi_qp_ctx - User data for hisi qp.
 * @id: qp_index return to user space
 * @qc_type: Accelerator algorithm type
 */
struct hisi_qp_ctx {
	__u16 id;
	__u16 qc_type;
};

/**
 * struct hisi_qp_info - User data for hisi qp.
 * @sqe_size: Submission queue element size
 * @sq_depth: The number of sqe
 * @cq_depth: The number of cqe
 * @reserved: Reserved data
 */
struct hisi_qp_info {
	__u32 sqe_size;
	__u16 sq_depth;
	__u16 cq_depth;
	__u64 reserved;
};

#define HISI_QM_API_VER_BASE "hisi_qm_v1"
#define HISI_QM_API_VER2_BASE "hisi_qm_v2"
#define HISI_QM_API_VER3_BASE "hisi_qm_v3"

/* UACCE_CMD_QM_SET_QP_CTX: Set qp algorithm type */
#define UACCE_CMD_QM_SET_QP_CTX	_IOWR('H', 10, struct hisi_qp_ctx)
/* UACCE_CMD_QM_SET_QP_INFO: Set qp depth and BD size */
#define UACCE_CMD_QM_SET_QP_INFO _IOWR('H', 11, struct hisi_qp_info)
#endif
