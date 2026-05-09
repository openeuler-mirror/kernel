/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_SEGMENT_H__
#define __UDMA_SEGMENT_H__

#include "udma_dev.h"

struct udma_segment {
	struct ubcore_target_seg core_tseg;
	struct udma_umem *umem;
	struct page *first_page;
	uint32_t token_value;
	bool token_value_valid;
	bool kernel_mode;
	uint32_t tid;
	uint64_t addr;
	uint64_t length;
};

static inline struct udma_segment *to_udma_seg(struct ubcore_target_seg *seg)
{
	return container_of(seg, struct udma_segment, core_tseg);
}

struct ubcore_target_seg *udma_register_seg(struct ubcore_device *ub_dev,
					    struct ubcore_seg_cfg *cfg,
					    struct ubcore_udata *udata);
int udma_unregister_seg(struct ubcore_target_seg *seg);
struct ubcore_target_seg *udma_import_seg(struct ubcore_device *dev,
					  struct ubcore_target_seg_cfg *cfg,
					  struct ubcore_udata *udata);
int udma_unimport_seg(struct ubcore_target_seg *tseg);
void udma_destroy_seg_tree_table(struct udma_dev *udma_dev);

#endif /* __UDMA_SEGMENT_H__ */
