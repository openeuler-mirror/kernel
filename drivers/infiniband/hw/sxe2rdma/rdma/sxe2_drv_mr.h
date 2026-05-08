/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mr.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_MR_H__
#define __SXE2_DRV_MR_H__

#include "sxe2_compat.h"

#define SXE2_HW_PAGE_SIZE	4096
#define SXE2_HW_PAGE_SIZE_1G	(1 << 30)
#define SXE2_CQPSQ_STAG_IDX_S	8
#define SXE2_MR_NOTALLOCED_PBLE 0
#define SXE2_MR_ALLOCED_PBLE	1
#define SXE2_MR_NOTALLOCED_KEY	0
#define SXE2_MR_ALLOCED_KEY	1
#define SXE2_MR_TYPE_MR		0
#define SXE2_IP_ADDR_LEN	4
#define SXE2_QPS_PER_PUSH_PAGE	16
#define SXE2_FPTE_LINER_ADDR	(1 << 21)

#define SXE2_UNUSED_PARA(para) ((void)(para))

enum sxe2_mr_mode {
	MR_ACCESS_MODE_PHY    = 0,
	MR_ACCESS_MODE_FIRST  = MR_TABLE_FIRST_MODE,
	MR_ACCESS_MODE_SECOND = MR_TABLE_SECOND_MODE,
	MR_ACCESS_MODE_THREE  = MR_TABLE_THIRD_MODE,
};

static inline struct sxe2_rdma_device *ibdev_to_rdmadev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct sxe2_rdma_device, ibdev);
}

static inline struct sxe2_rdma_pd *ibpd_to_vendor_pd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct sxe2_rdma_pd, ibpd);
}

static inline u8 sxe2_get_mr_access(int access)
{
	u8 hw_access = 0;

	hw_access |= (access & IB_ACCESS_LOCAL_WRITE) ?
			     SXE2_ACCESS_FLAGS_LOCALWRITE :
			     0;
	hw_access |= (access & IB_ACCESS_REMOTE_WRITE) ?
			     SXE2_ACCESS_FLAGS_REMOTEWRITE :
			     0;
	hw_access |= (access & IB_ACCESS_REMOTE_READ) ?
			     SXE2_ACCESS_FLAGS_REMOTEREAD :
			     0;
	hw_access |= (access & IB_ACCESS_MW_BIND) ?
			     SXE2_ACCESS_FLAGS_BIND_WINDOW :
			     0;
	hw_access |= SXE2_ACCESS_FLAGS_LOCALREAD;

	return hw_access;
}
struct ib_mr *sxe2_kreg_user_mr(struct ib_pd *pd, u64 start, u64 len, u64 virt,
				int access, struct ib_udata *udata);
#ifdef DEREG_ME_V1
int sxe2_kdereg_mr(struct ib_mr *ib_mr);
#else
int sxe2_kdereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata);
#endif
#ifdef RDMA_ALLOC_MR_VER_1
struct ib_mr *sxe2_kalloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_num_sg, struct ib_udata *udata);
#else
struct ib_mr *sxe2_kalloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_num_sg);
#endif
int sxe2_kmap_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_nents,
		    unsigned int *sg_offset);
struct ib_mr *sxe2_kget_dma_mr(struct ib_pd *pd, int acc);
#ifdef REREG_MR_VER_1
int sxe2_krereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start, u64 len,
			u64 virt, int new_access, struct ib_pd *new_pd,
			struct ib_udata *udata);

#else
struct ib_mr *sxe2_krereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
				  u64 len, u64 virt, int new_access,
				  struct ib_pd *new_pd, struct ib_udata *udata);
#endif

#ifndef REG_USER_MR_DMABUF_VER_1
struct ib_mr *sxe2_kreg_user_mr_dmabuf(struct ib_pd *pd, u64 start, u64 len,
				       u64 virt, int fd, int access,
				       struct ib_udata *udata);
#endif

u32 sxe2_create_stag(struct sxe2_rdma_device *rdma_dev);
bool sxe2_check_mr_contiguous(struct sxe2_mr *vendor_mr);
void sxe2_print_wqe_info(struct sxe2_rdma_ctx_dev *dev, void *wqe_info,
			 u8 mq_cmd);
void sxe2_set_mq_wqe(struct sxe2_rdma_ctx_dev *dev, __le64 *wqe,
		     void *wqe_info);

#endif
