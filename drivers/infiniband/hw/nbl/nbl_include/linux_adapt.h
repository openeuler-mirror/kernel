/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef LINUX_ADAPT_H
#define LINUX_ADAPT_H

#include <linux/iommu.h>
#include <linux/iova.h>
#include <linux/version.h>

#define IB_QP_ATTR_STANDARD_BITS GENMASK(20, 0)

#define ENABLE_UMR 0
#define HW_SUP_DMABUF_INV 0

enum iommu_dma_cookie_type {
	IOMMU_DMA_IOVA_COOKIE,
	IOMMU_DMA_MSI_COOKIE,
};
struct iommu_dma_cookie {
	enum iommu_dma_cookie_type type;
	union {
		/* Full allocator for IOMMU_DMA_IOVA_COOKIE */
		struct {
			struct iova_domain iovad;

			struct iova_fq __percpu *fq; /* Flush queue */
			/* Number of TLB flushes that have been started */
			atomic64_t fq_flush_start_cnt;
			/* Number of TLB flushes that have been finished */
			atomic64_t fq_flush_finish_cnt;
			/* Timer to regularily empty the flush queues */
			struct timer_list fq_timer;
			/* 1 when timer is active, 0 when not */
			atomic_t fq_timer_on;
		};
		/* Trivial linear page allocator for IOMMU_DMA_MSI_COOKIE */
		dma_addr_t msi_iova;
	};
	struct list_head msi_page_list;

	/* Domain for flush queue callback; NULL if flush queue not in use */
	struct iommu_domain *fq_domain;
};

#endif /* LINUX_ADAPT_H */
