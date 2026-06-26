/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2026 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_SEG_TREE_H__
#define __UDMA_SEG_TREE_H__

#include "udma_ctx.h"
#include "udma_segment.h"

#define BISECTOR 2

struct udma_seg_tree_node {
	uint64_t start;
	uint64_t end;
	uint64_t vm_start;
	uint64_t vm_end;
	int ref_count;
	int lazy;
	struct udma_seg_tree_node *left;
	struct udma_seg_tree_node *right;
};

struct udma_seg_tree {
	struct udma_seg_tree_node *root;
	struct mutex lock;
	refcount_t ctx_refcnt;
};

struct udma_range_list_node {
	uint64_t start;
	uint64_t length;
	struct udma_range_list_node *next;
};

struct udma_range_list {
	struct udma_range_list_node *head;
	struct udma_range_list_node *tail;
};

void udma_range_list_destroy(struct udma_range_list *list);
int udma_range_list_rollback(struct udma_range_list *list, struct udma_range_list_node *node);
struct udma_seg_tree *udma_seg_tree_init(void);
void udma_seg_tree_destroy(struct udma_seg_tree *tree);
int udma_seg_range_occupy(struct udma_context *ctx, struct udma_segment *seg,
			  struct udma_range_list *list);
int udma_seg_range_release(struct udma_context *ctx, struct udma_segment *seg,
			   struct udma_range_list *list);

#endif /* UDMA_SEG_TREE_H */
