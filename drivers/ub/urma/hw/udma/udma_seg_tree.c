// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2026 HiSilicon Technologies CO., Ltd. All rights reserved. */

#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/slab.h>
#include "udma_common.h"
#include "udma_seg_tree.h"

#define MAX_ADDR_BITS 52
#define MAX_VADDR ((1ULL << MAX_ADDR_BITS) - 1)
#define MAX_SEG_STACK_SIZE 41

static int udma_add_to_range_list(struct udma_range_list *list, uint64_t start,
				  uint64_t end)
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
}

int udma_range_list_rollback(struct udma_range_list *list, struct udma_range_list_node *node)
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

static struct udma_seg_tree_node *udma_seg_tree_node_create(uint64_t start, uint64_t end)
{
	struct udma_seg_tree_node *node = kzalloc(sizeof(struct udma_seg_tree_node),
						  GFP_KERNEL);
	if (!node)
		return NULL;

	node->start = start;
	node->end = end;
	node->vm_start = ULONG_MAX;
	node->vm_end = ULONG_MAX;
	mutex_init(&node->lock);
	refcount_set(&node->ctx_refcnt, 1);

	return node;
}

void udma_seg_tree_destroy(struct udma_seg_tree_node *node)
{
	struct udma_seg_tree_node *stack[MAX_SEG_STACK_SIZE];
	struct udma_seg_tree_node *cur;
	uint64_t count = 0;

	if (!node)
		return;

	mutex_destroy(&node->lock);

	stack[count++] = node;
	while (count > 0) {
		cur = stack[--count];
		if (cur->left)
			stack[count++] = cur->left;

		if (cur->right)
			stack[count++] = cur->right;

		kfree(cur);
	}
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

static int udma_seg_update_range(struct udma_seg_tree_node *root, uint64_t ul, uint64_t ur,
				 int val, struct udma_range_list *list, struct vm_area_struct *vma)
{
	struct udma_seg_tree_node *stack[MAX_SEG_STACK_SIZE];
	struct udma_seg_tree_node *cur;
	uint64_t count = 0;
	int old_count = 0;
	int ret = 0;

	if (!root || ul > ur)
		return -EINVAL;

	stack[count++] = root;
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
				udma_add_to_range_list(list, cur->start, cur->end);

				if (vma == NULL) {
					cur->vm_start = ULONG_MAX;
					cur->vm_end = ULONG_MAX;
				} else {
					cur->vm_start = vma->vm_start;
					cur->vm_end = vma->vm_end;
				}
			}

			continue;
		}

		ret = udma_seg_push_down_update(cur);
		if (ret != 0)
			return ret;

		if (cur->right)
			stack[count++] = cur->right;

		if (cur->left)
			stack[count++] = cur->left;
	}

	return 0;
}

struct udma_seg_tree_node *udma_seg_range_init(void)
{
	return udma_seg_tree_node_create(0, MAX_VADDR);
}

typedef int (*range_check)(struct udma_seg_tree_node *, struct vm_area_struct *);

static int range_check_occupy(struct udma_seg_tree_node *node, struct vm_area_struct *vm)
{
	if (node->vm_start == ULONG_MAX && node->vm_end == ULONG_MAX)
		return 0;

	if (node->vm_start == vm->vm_start && node->vm_end == vm->vm_end)
		return 0;

	return -EINVAL;
}

static int udma_seg_range_check(struct udma_seg_tree_node *root, uint64_t start, uint64_t end,
				range_check check, struct udma_context *ctx,
				struct vm_area_struct *vma)
{
	struct udma_seg_tree_node *stack[MAX_SEG_STACK_SIZE];
	struct udma_seg_tree_node *cur;
	uint64_t count = 0;

	if (!root)
		return -EINVAL;

	if (root->start < vma->vm_end && root->end >= vma->vm_start)
		stack[count++] = root;

	while (count > 0) {
		cur = stack[--count];
		if (cur->left && cur->left->start < vma->vm_end && cur->left->end >= vma->vm_start)
			stack[count++] = cur->left;

		if (cur->right && cur->right->start < vma->vm_end &&
		    cur->right->end >= vma->vm_start)
			stack[count++] = cur->right;

		if (cur->left == NULL && cur->right == NULL &&
			!(cur->start >= vma->vm_end || cur->end < vma->vm_start) &&
			check(cur, vma)) {
			dev_err(ctx->dev->dev,
				"failed to check, segment range is mismatch with vm info.\n");
			return -EINVAL;
		}
	}

	return 0;
}

int udma_seg_range_occupy(struct udma_seg_tree_node *root, uint64_t start,
			  uint64_t end, struct udma_range_list *list, struct udma_context *ctx)
{
	struct vm_area_struct *vma = NULL;
	int ret = 0;

	if (start > end || !root || !list)
		return -EINVAL;

	list->head = list->tail = NULL;

	mmap_read_lock(current->mm);
	vma = vma_lookup(current->mm, start);
	if (!vma) {
		dev_err(ctx->dev->dev, "failed to vma_lookup.\n");
		ret = -EINVAL;
		goto unlock_mm;
	}

	if (udma_seg_range_check(root, start, end, range_check_occupy, ctx, vma)) {
		ret = -EINVAL;
		goto unlock_mm;
	}

	ret = udma_seg_update_range(root, start, end, 1, list, vma);

unlock_mm:
	mmap_read_unlock(current->mm);

	return ret;
}

int udma_seg_range_release(struct udma_seg_tree_node *root, uint64_t start,
			    uint64_t end, struct udma_range_list *list)
{
	if (start > end || !root || !list)
		return -EINVAL;

	list->head = list->tail = NULL;

	return udma_seg_update_range(root, start, end, -1, list, NULL);
}
