// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2026 HiSilicon Technologies CO., Ltd. All rights reserved. */

#include <linux/limits.h>
#include <linux/slab.h>
#include "udma_common.h"
#include "udma_seg_tree.h"

#define MAX_ADDR_BITS 52
#define MAX_VADDR ((1ULL << MAX_ADDR_BITS) - 1)
#define MAX_SEG_STACK_SIZE (MAX_ADDR_BITS - PAGE_SHIFT + 1)

static int udma_add_to_range_list(struct udma_range_list *list,
				  uint64_t start, uint64_t end)
{
	struct udma_range_list_node *node = NULL;

	if (list->head == NULL) {
		node = kzalloc(sizeof(struct udma_range_list_node), GFP_KERNEL);
		if (!node)
			return -ENOMEM;

		node->start = start;
		node->length = end - start + 1;
		list->head = list->tail = node;
		return 0;
	}

	if (list->tail->start + list->tail->length == start) {
		list->tail->length += end - start + 1;
		return 0;
	}

	node = kzalloc(sizeof(struct udma_range_list_node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->start = start;
	node->length = end - start + 1;
	list->tail->next = node;
	list->tail = node;

	return 0;
}

void udma_range_list_destroy(struct udma_range_list *list)
{
	struct udma_range_list_node *node = list->head;
	struct udma_range_list_node *next = NULL;

	while (node != NULL) {
		next = node->next;
		kfree(node);
		node = next;
	}

	list->head = NULL;
	list->tail = NULL;
}

int udma_range_list_rollback(struct udma_range_list *list,
			     struct udma_range_list_node *node)
{
	struct udma_range_list_node *tmpnode, *newnode;

	if (!node)
		return -EINVAL;

	tmpnode = kzalloc(sizeof(struct udma_range_list_node), GFP_KERNEL);
	if (!tmpnode)
		return -ENOMEM;

	tmpnode->start = node->start;
	tmpnode->length = node->length;
	tmpnode->next = NULL;

	newnode = list->head;

	if (list->head == NULL) {
		list->head = tmpnode;
	} else {
		while (newnode != NULL && newnode->next != NULL)
			newnode = newnode->next;

		newnode->next = tmpnode;
		list->tail = tmpnode;
	}

	return 0;
}

static struct udma_seg_tree_node *udma_seg_tree_node_create(uint64_t start,
							    uint64_t end)
{
	struct udma_seg_tree_node *node;

	node = kzalloc(sizeof(struct udma_seg_tree_node), GFP_KERNEL);
	if (!node)
		return NULL;

	node->start = start;
	node->end = end;
	node->vm_start = ULONG_MAX;
	node->vm_end = ULONG_MAX;

	return node;
}

void udma_seg_tree_destroy(struct udma_seg_tree *tree)
{
	struct udma_seg_tree_node *stack[MAX_SEG_STACK_SIZE];
	struct udma_seg_tree_node *cur;
	uint64_t count = 0;

	if (!tree)
		return;

	mutex_destroy(&tree->lock);

	if (!tree->root) {
		kfree(tree);
		return;
	}

	stack[count++] = tree->root;
	while (count > 0) {
		cur = stack[--count];
		if (cur->left)
			stack[count++] = cur->left;

		if (cur->right)
			stack[count++] = cur->right;

		kfree(cur);
	}

	kfree(tree);
}

static int udma_seg_push_down_update(struct udma_seg_tree_node *node)
{
	uint64_t mid;

	if (!node || node->start == node->end)
		return 0;

	mid = node->start + (node->end - node->start) / BISECTOR;
	if (!node->left)
		node->left = udma_seg_tree_node_create(node->start, mid);

	if (!node->right)
		node->right = udma_seg_tree_node_create(mid + 1, node->end);

	if (!node->left || !node->right) {
		kfree(node->left);
		node->left = NULL;
		kfree(node->right);
		node->right = NULL;
		return -ENOMEM;
	}

	if (node->lazy == 0)
		return 0;

	node->left->ref_count += node->lazy;
	node->left->lazy += node->lazy;
	node->right->ref_count += node->lazy;
	node->right->lazy += node->lazy;
	node->lazy = 0;

	return 0;
}

static void udma_rollback_seg_tree(struct udma_seg_tree_node *root,
				   struct udma_segment *seg, int val,
				   struct udma_seg_tree_node *stop)
{
	struct udma_seg_tree_node *stack[MAX_SEG_STACK_SIZE];
	struct udma_seg_tree_node *cur = NULL;
	uint64_t count = 0;
	uint64_t ul;
	uint64_t ur;

	if (!root || !seg || !seg->length || !stop)
		return;

	ul = seg->addr;
	ur = seg->addr + PAGE_ALIGN(seg->length) - 1;

	stack[count++] = root;

	while (count > 0 && cur != stop) {
		cur = stack[--count];
		if (!cur || ur < cur->start || ul > cur->end)
			continue;

		if (cur->left == NULL && cur->right == NULL &&
		    ul <= cur->start && cur->end <= ur) {
			cur->ref_count -= val;
			cur->lazy -= val;
		}

		if (cur->right)
			stack[count++] = cur->right;

		if (cur->left)
			stack[count++] = cur->left;
	}
}

static int udma_seg_update_range(struct udma_context *ctx,
				 struct udma_segment *seg,
				 int val,
				 struct udma_range_list *list)
{
	struct udma_seg_tree_node *stack[MAX_SEG_STACK_SIZE];
	struct udma_seg_tree_node *cur;
	uint64_t count = 0;
	int old_count = 0;
	int ret = 0;
	uint64_t ul;
	uint64_t ur;

	if (seg->length == 0)
		return -EINVAL;

	ul = seg->addr;
	ur = seg->addr + PAGE_ALIGN(seg->length) - 1;

	stack[count++] = ctx->seg_tree->root;
	while (count > 0) {
		cur = stack[--count];
		if (!cur || ur < cur->start || ul > cur->end)
			continue;

		if (cur->left == NULL && cur->right == NULL &&
		    ul <= cur->start && cur->end <= ur) {
			old_count = cur->ref_count;
			cur->ref_count += val;
			cur->lazy += val;
			if ((old_count == 0 && cur->ref_count == 1) ||
			    (old_count == 1 && cur->ref_count == 0)) {
				ret = udma_add_to_range_list(list,
					cur->start, cur->end);
				if (ret != 0) {
					cur->ref_count -= val;
					cur->lazy -= val;
					dev_err(ctx->dev->dev,
						"add to range list failed.\n");
					goto rollback;
				}

				cur->vm_start = seg->vm_start;
				cur->vm_end = seg->vm_end;
			}

			continue;
		}

		ret = udma_seg_push_down_update(cur);
		if (ret != 0) {
			dev_err(ctx->dev->dev, "push down update failed.\n");
			goto rollback;
		}

		if (cur->right)
			stack[count++] = cur->right;

		if (cur->left)
			stack[count++] = cur->left;
	}

	return 0;

rollback:
	udma_rollback_seg_tree(ctx->seg_tree->root, seg, val, cur);
	udma_range_list_destroy(list);

	return ret;
}

struct udma_seg_tree *udma_seg_tree_init(void)
{
	struct udma_seg_tree *tree;

	tree = kzalloc(sizeof(struct udma_seg_tree), GFP_KERNEL);
	if (!tree)
		return NULL;

	tree->root = udma_seg_tree_node_create(0, MAX_VADDR);
	if (!tree->root) {
		kfree(tree);
		return NULL;
	}

	mutex_init(&tree->lock);
	refcount_set(&tree->ctx_refcnt, 1);

	return tree;
}

typedef int (*range_check)(struct udma_seg_tree_node *, struct udma_segment *);

static int range_check_occupy(struct udma_seg_tree_node *node,
			      struct udma_segment *seg)
{
	if (node->vm_start == ULONG_MAX || node->vm_end == ULONG_MAX)
		return 0;

	if (node->vm_start == seg->vm_start && node->vm_end == seg->vm_end)
		return 0;

	return -EINVAL;
}

static int udma_seg_range_check(struct udma_context *ctx,
				struct udma_segment *seg,
				range_check check)
{
	struct udma_seg_tree_node *stack[MAX_SEG_STACK_SIZE];
	struct udma_seg_tree_node *cur;
	uint64_t count = 0;
	uint64_t start;
	uint64_t end;

	start = seg->addr;
	end = seg->addr + PAGE_ALIGN(seg->length) - 1;
	if (ctx->seg_tree->root->start < end &&
	    ctx->seg_tree->root->end >= start)
		stack[count++] = ctx->seg_tree->root;

	while (count > 0) {
		cur = stack[--count];
		if (cur->left &&
		    cur->left->start < end && cur->left->end >= start)
			stack[count++] = cur->left;

		if (cur->right &&
		    cur->right->start < end && cur->right->end >= start)
			stack[count++] = cur->right;

		if (!cur->left && !cur->right &&
		    !(cur->start >= end || cur->end < start) &&
		    check(cur, seg))
			return -EINVAL;
	}

	return 0;
}

int udma_seg_range_occupy(struct udma_context *ctx, struct udma_segment *seg,
			  struct udma_range_list *list)
{
	if (!ctx || !ctx->seg_tree || !ctx->seg_tree->root ||
	    !ctx->dev || !ctx->dev->dev || !seg || !list)
		return -EINVAL;

	list->head = list->tail = NULL;

	if (udma_seg_range_check(ctx, seg, range_check_occupy) != 0)
		dev_info_ratelimited(ctx->dev->dev,
			"the mv_start and/or mv_end of VMA was modified.\n");

	return udma_seg_update_range(ctx, seg, 1, list);
}

int udma_seg_range_release(struct udma_context *ctx, struct udma_segment *seg,
			   struct udma_range_list *list)
{
	if (!ctx || !ctx->seg_tree || !ctx->seg_tree->root ||
	    !ctx->dev || !ctx->dev->dev || !seg || !list)
		return -EINVAL;

	list->head = list->tail = NULL;

	seg->vm_start = ULONG_MAX;
	seg->vm_end = ULONG_MAX;

	return udma_seg_update_range(ctx, seg, -1, list);
}
