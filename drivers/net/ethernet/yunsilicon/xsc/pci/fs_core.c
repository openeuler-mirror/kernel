// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/mutex.h>
#include <net/devlink.h>
#include "common/vport.h"
#include "common/xsc_eswitch.h"
#include "common/xsc_core.h"
#include "common/fs_core.h"
#include "common/fs_cmd.h"
#include "fs_ft_pool.h"
#include "devlink.h"
#include "xsc_flow.h"

#ifdef CONFIG_XSC_TRACE_DEBUG
#define CREATE_TRACE_POINTS
#include "diag/fs_tracepoint.h"
#endif

#define INIT_TREE_NODE_ARRAY_SIZE(...)	(sizeof((struct init_tree_node[]){__VA_ARGS__}) /\
					 sizeof(struct init_tree_node))

#define ADD_PRIO(num_prios_val, min_level_val, num_levels_val, caps_val,\
		 ...) {.type = FS_TYPE_PRIO,\
	.min_ft_level = min_level_val,\
	.num_levels = num_levels_val,\
	.num_leaf_prios = num_prios_val,\
	.caps = caps_val,\
	.children = (struct init_tree_node[]) {__VA_ARGS__},\
	.ar_size = INIT_TREE_NODE_ARRAY_SIZE(__VA_ARGS__) \
}

#define ADD_MULTIPLE_PRIO(num_prios_val, num_levels_val, ...)\
	ADD_PRIO(num_prios_val, 0, num_levels_val, {},\
		 __VA_ARGS__)\

#define ADD_NS(def_miss_act, ...) {.type = FS_TYPE_NAMESPACE,	\
	.def_miss_action = def_miss_act,\
	.children = (struct init_tree_node[]) {__VA_ARGS__},\
	.ar_size = INIT_TREE_NODE_ARRAY_SIZE(__VA_ARGS__) \
}

#define INIT_CAPS_ARRAY_SIZE(...) (sizeof((long[]){__VA_ARGS__}) /\
				   sizeof(long))

#define FS_CAP(cap) (__xsc_bit_off(flow_table_nic_cap, cap))

#define FS_REQUIRED_CAPS(...) {.arr_sz = INIT_CAPS_ARRAY_SIZE(__VA_ARGS__), \
			       .caps = (long[]) {__VA_ARGS__} }

#define FS_CHAINING_CAPS \
	FS_REQUIRED_CAPS(FS_CAP(flow_table_properties_nic_receive.flow_modify_en), \
			 FS_CAP(flow_table_properties_nic_receive.modify_root), \
			 FS_CAP(flow_table_properties_nic_receive.identified_miss_table_mode), \
			 FS_CAP(flow_table_properties_nic_receive.flow_table_modify))

#define OFFLOADS_MAX_FT 1
#define OFFLOADS_NUM_PRIOS 1
#define OFFLOADS_MIN_LEVEL (OFFLOADS_NUM_PRIOS)

#define LAG_PRIO_NUM_LEVELS 1
#define LAG_NUM_PRIOS 1
#define LAG_MIN_LEVEL (OFFLOADS_MIN_LEVEL + 1)

#define ROOT_NS_FT_MAX_LEVEL (LAG_MIN_LEVEL + 1)

struct node_caps {
	size_t	arr_sz;
	long	*caps;
};

static struct init_tree_node {
	enum fs_node_type	type;
	struct init_tree_node *children;
	int ar_size;
	struct node_caps caps;
	int min_ft_level;
	int num_leaf_prios;
	int prio;
	int num_levels;
	enum xsc_flow_table_miss_action def_miss_action;
} root_fs = {
	.type = FS_TYPE_NAMESPACE,
	.ar_size = 0,
};

enum fs_i_lock_class {
	FS_LOCK_GRANDPARENT,
	FS_LOCK_PARENT,
	FS_LOCK_CHILD
};

static const struct rhashtable_params rhash_fte = {
	.key_len = sizeof_field(struct fs_fte, val) - sizeof(struct xsc_ifc_flow_attr),
	.key_offset = offsetof(struct fs_fte, val) + sizeof(struct xsc_ifc_flow_attr),
	.head_offset = offsetof(struct fs_fte, hash),
	.automatic_shrinking = true,
	.min_size = 1,
};

static const struct rhashtable_params rhash_fg = {
	.key_len = sizeof(struct xsc_ifc_fte_match_param),
	.key_offset = offsetof(struct xsc_flow_group, mask.match_mask),
	.head_offset = offsetof(struct xsc_flow_group, hash),
	.automatic_shrinking = true,
	.min_size = 1,
};

static void del_hw_flow_table(struct fs_node *node);
static void del_hw_flow_group(struct fs_node *node);
static void del_hw_fte(struct fs_node *node);
static void del_sw_flow_table(struct fs_node *node);
static void del_sw_flow_group(struct fs_node *node);
static void del_sw_fte(struct fs_node *node);
static void del_sw_prio(struct fs_node *node);
static void del_sw_ns(struct fs_node *node);
/* Delete rule (destination) is special case that
 * requires to lock the FTE for all the deletion process.
 */
static void del_sw_hw_rule(struct fs_node *node);
static bool xsc_flow_dests_cmp(struct xsc_flow_destination *d1,
			       struct xsc_flow_destination *d2);
static void cleanup_root_ns(struct xsc_flow_root_namespace *root_ns);
static struct xsc_flow_rule *find_flow_rule(struct fs_fte *fte,
					    struct xsc_flow_destination *dest);

static void tree_init_node(struct fs_node *node,
			   void (*del_hw_func)(struct fs_node *),
			   void (*del_sw_func)(struct fs_node *))
{
	refcount_set(&node->refcount, 1);
	INIT_LIST_HEAD(&node->list);
	INIT_LIST_HEAD(&node->children);
	init_rwsem(&node->lock);
	node->del_hw_func = del_hw_func;
	node->del_sw_func = del_sw_func;
	node->active = false;
}

static void tree_add_node(struct fs_node *node, struct fs_node *parent)
{
	if (parent)
		refcount_inc(&parent->refcount);
	node->parent = parent;

	/* Parent is the root */
	if (!parent)
		node->root = node;
	else
		node->root = parent->root;
}

static int tree_get_node(struct fs_node *node)
{
	return refcount_inc_not_zero(&node->refcount);
}

static void nested_down_read_ref_node(struct fs_node *node,
				      enum fs_i_lock_class class)
{
	if (node) {
		down_read_nested(&node->lock, class);
		refcount_inc(&node->refcount);
	}
}

static void nested_down_write_ref_node(struct fs_node *node,
				       enum fs_i_lock_class class)
{
	if (node) {
		down_write_nested(&node->lock, class);
		refcount_inc(&node->refcount);
	}
}

static void down_write_ref_node(struct fs_node *node, bool locked)
{
	if (node) {
		if (!locked)
			down_write(&node->lock);
		refcount_inc(&node->refcount);
	}
}

static void up_read_ref_node(struct fs_node *node)
{
	refcount_dec(&node->refcount);
	up_read(&node->lock);
}

static void up_write_ref_node(struct fs_node *node, bool locked)
{
	refcount_dec(&node->refcount);
	if (!locked)
		up_write(&node->lock);
}

static void tree_put_node(struct fs_node *node, bool locked)
{
	struct fs_node *parent_node = node->parent;

	if (refcount_dec_and_test(&node->refcount)) {
		if (node->del_hw_func)
			node->del_hw_func(node);
		if (parent_node) {
			down_write_ref_node(parent_node, locked);
			list_del_init(&node->list);
		}
		node->del_sw_func(node);
		if (parent_node)
			up_write_ref_node(parent_node, locked);
		node = NULL;
	}
	if (!node && parent_node)
		tree_put_node(parent_node, locked);
}

static int tree_remove_node(struct fs_node *node, bool locked)
{
	if (refcount_read(&node->refcount) > 1) {
		refcount_dec(&node->refcount);
		return -EEXIST;
	}
	tree_put_node(node, locked);
	return 0;
}

static struct fs_prio *find_prio(struct xsc_flow_namespace *ns,
				 unsigned int prio)
{
	struct fs_prio *iter_prio;

	fs_for_each_prio(iter_prio, ns) {
		if (iter_prio->prio == prio)
			return iter_prio;
	}

	return NULL;
}

static bool is_fwd_next_action(u32 action)
{
	return action & (XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_PRIO |
			 XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_NS);
}

static bool is_fwd_dest_type(enum xsc_flow_destination_type type)
{
	return type == XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE_NUM ||
		type == XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE ||
		type == XSC_FLOW_DESTINATION_TYPE_UPLINK ||
		type == XSC_FLOW_DESTINATION_TYPE_VPORT ||
		type == XSC_FLOW_DESTINATION_TYPE_FLOW_SAMPLER ||
		type == XSC_FLOW_DESTINATION_TYPE_TIR ||
		type == XSC_FLOW_DESTINATION_TYPE_RANGE ||
		type == XSC_FLOW_DESTINATION_TYPE_TABLE_TYPE ||
		type == XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE ||
		type == XSC_FLOW_DESTINATION_TYPE_FLOW_CHAIN;
}

static bool check_valid_spec(const struct xsc_flow_spec *spec)
{
	int i;

	for (i = 0; i < XSC_ST_SZ_DW_MATCH_PARAM; i++)
		if (spec->match_value[i] & ~spec->match_mask[i]) {
			pr_warn("xsc_core: match_value differs from match_mask\n");
			return false;
		}

	return true;
}

struct xsc_flow_root_namespace *find_root(struct fs_node *node)
{
	struct fs_node *root;
	struct xsc_flow_namespace *ns;

	root = node->root;

	if (WARN_ON(root->type != FS_TYPE_NAMESPACE)) {
		pr_warn("xsc: flow steering node is not in tree or garbaged\n");
		return NULL;
	}

	ns = container_of(root, struct xsc_flow_namespace, node);
	return container_of(ns, struct xsc_flow_root_namespace, ns);
}

static inline struct xsc_flow_steering *get_steering(struct fs_node *node)
{
	struct xsc_flow_root_namespace *root = find_root(node);

	if (root)
		return root->dev->priv.steering;
	return NULL;
}

static inline struct xsc_core_device *get_dev(struct fs_node *node)
{
	struct xsc_flow_root_namespace *root = find_root(node);

	if (root)
		return root->dev;
	return NULL;
}

static void del_sw_ns(struct fs_node *node)
{
	kfree(node);
}

static void del_sw_prio(struct fs_node *node)
{
	kfree(node);
}

static void del_hw_flow_table(struct fs_node *node)
{
	struct xsc_flow_root_namespace *root;
	struct xsc_flow_table *ft;
	struct xsc_core_device *dev;
	int err;

	fs_get_obj(ft, node);
	dev = get_dev(&ft->node);
	root = find_root(&ft->node);

#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_fs_del_ft(ft);
#endif

	if (node->active) {
		err = root->cmds->destroy_flow_table(dev, ft);
		if (err)
			xsc_core_warn(dev, "flow steering can't destroy ft\n");
	}
}

static void del_sw_flow_table(struct fs_node *node)
{
	struct xsc_flow_table *ft;
	struct fs_prio *prio;

	fs_get_obj(ft, node);

	rhltable_destroy(&ft->fgs_hash);
	if (ft->node.parent) {
		fs_get_obj(prio, ft->node.parent);
		prio->num_ft--;
	}
	kfree(ft);
}

static void modify_fte(struct fs_fte *fte)
{
	struct xsc_flow_root_namespace *root;
	struct xsc_flow_table *ft;
	struct xsc_flow_group *fg;
	struct xsc_core_device *dev;
	int err;

	fs_get_obj(fg, fte->node.parent);
	fs_get_obj(ft, fg->node.parent);
	dev = get_dev(&fte->node);

	root = find_root(&ft->node);
	err = root->cmds->update_fte(root->dev, ft, fg, fte->modify_mask, fte);
	if (err)
		xsc_core_warn(dev, "can't del rule fg id=%d fte_index=%d\n",
			      fg->id, fte->index);
	fte->modify_mask = 0;
}

static void del_sw_hw_rule(struct fs_node *node)
{
	struct xsc_flow_rule *rule;
	struct fs_fte *fte;

	fs_get_obj(rule, node);
	fs_get_obj(fte, rule->node.parent);
#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_fs_del_rule(rule);
#endif
	if (is_fwd_next_action(rule->sw_action)) {
		mutex_lock(&rule->dest_attr.ft->lock);
		list_del(&rule->next_ft);
		mutex_unlock(&rule->dest_attr.ft->lock);
	}

	if (rule->dest_attr.type == XSC_FLOW_DESTINATION_TYPE_COUNTER) {
		--fte->dests_size;
		fte->modify_mask |=
			BIT(XSC_SET_FTE_MODIFY_ENABLE_MASK_ACTION) |
			BIT(XSC_SET_FTE_MODIFY_ENABLE_MASK_FLOW_COUNTERS);
		fte->action.action &= ~XSC_FLOW_CONTEXT_ACTION_COUNT;
		goto out;
	}

	if (rule->dest_attr.type == XSC_FLOW_DESTINATION_TYPE_PORT) {
		--fte->dests_size;
		fte->modify_mask |= BIT(XSC_SET_FTE_MODIFY_ENABLE_MASK_ACTION);
		fte->action.action &= ~XSC_FLOW_CONTEXT_ACTION_ALLOW;
		goto out;
	}

	if (is_fwd_dest_type(rule->dest_attr.type)) {
		--fte->dests_size;
		--fte->fwd_dests;

		if (!fte->fwd_dests)
			fte->action.action &=
				~XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
		fte->modify_mask |=
			BIT(XSC_SET_FTE_MODIFY_ENABLE_MASK_DESTINATION_LIST);
		goto out;
	}
out:
	kfree(rule);
}

static void del_hw_fte(struct fs_node *node)
{
	struct xsc_flow_root_namespace *root;
	struct xsc_flow_table *ft;
	struct xsc_flow_group *fg;
	struct xsc_core_device *dev;
	struct fs_fte *fte;
	int err;

	fs_get_obj(fte, node);
	fs_get_obj(fg, fte->node.parent);
	fs_get_obj(ft, fg->node.parent);

#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_fs_del_fte(fte);
#endif
	WARN_ON(fte->dests_size);
	dev = get_dev(&ft->node);
	root = find_root(&ft->node);
	if (node->active) {
		err = root->cmds->delete_fte(root->dev, ft, fte);
		if (err)
			xsc_core_warn(dev,
				      "flow steering can't delete fte in index %d of flow group id %d\n",
				      fte->index, fg->id);
		node->active = false;
	}
}

static void del_sw_fte(struct fs_node *node)
{
	struct xsc_flow_steering *steering = get_steering(node);
	struct xsc_flow_group *fg;
	struct fs_fte *fte;
	int err;

	fs_get_obj(fte, node);
	fs_get_obj(fg, fte->node.parent);

	err = rhashtable_remove_fast(&fg->ftes_hash,
				     &fte->hash,
				     rhash_fte);
	WARN_ON(err);
	ida_free(&fg->fte_allocator, fte->index - fg->start_index);
	kmem_cache_free(steering->ftes_cache, fte);
}

static void del_hw_flow_group(struct fs_node *node)
{
	struct xsc_flow_root_namespace *root;
	struct xsc_flow_group *fg;
	struct xsc_flow_table *ft;
	struct xsc_core_device *dev;

	fs_get_obj(fg, node);
	fs_get_obj(ft, fg->node.parent);
	dev = get_dev(&ft->node);
#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_fs_del_fg(fg);
#endif

	root = find_root(&ft->node);
	if (fg->node.active && root->cmds->destroy_flow_group(root->dev, ft, fg))
		xsc_core_warn(dev, "flow steering can't destroy fg %d of ft %d\n",
			      fg->id, ft->id);
}

static void del_sw_flow_group(struct fs_node *node)
{
	struct xsc_flow_steering *steering = get_steering(node);
	struct xsc_flow_group *fg;
	struct xsc_flow_table *ft;
	int err;

	fs_get_obj(fg, node);
	fs_get_obj(ft, fg->node.parent);

	rhashtable_destroy(&fg->ftes_hash);
	ida_destroy(&fg->fte_allocator);
	if (ft->autogroup.active &&
	    fg->max_ftes == ft->autogroup.group_size &&
	    fg->start_index < ft->autogroup.max_fte)
		ft->autogroup.num_groups--;
	err = rhltable_remove(&ft->fgs_hash, &fg->hash, rhash_fg);
	WARN_ON(err);
	kmem_cache_free(steering->fgs_cache, fg);
}

static int insert_fte(struct xsc_flow_group *fg, struct fs_fte *fte)
{
	int index;
	int ret;

	index = ida_alloc_max(&fg->fte_allocator, fg->max_ftes - 1, GFP_KERNEL);
	if (index < 0)
		return index;

	fte->index = index + fg->start_index;
	ret = rhashtable_insert_fast(&fg->ftes_hash,
				     &fte->hash,
				     rhash_fte);
	if (ret)
		goto err_ida_remove;

	tree_add_node(&fte->node, &fg->node);
	list_add_tail(&fte->node.list, &fg->node.children);
	return 0;

err_ida_remove:
	ida_free(&fg->fte_allocator, index);
	return ret;
}

static struct fs_fte *alloc_fte(struct xsc_flow_table *ft,
				const struct xsc_flow_spec *spec,
				struct xsc_flow_act *flow_act)
{
	struct xsc_flow_steering *steering = get_steering(&ft->node);
	struct fs_fte *fte;

	fte = kmem_cache_zalloc(steering->ftes_cache, GFP_KERNEL);
	if (!fte)
		return ERR_PTR(-ENOMEM);

	memcpy(fte->val, &spec->match_attr, sizeof(fte->val));
	fte->node.type = FS_TYPE_FLOW_ENTRY;
	fte->action = *flow_act;
	fte->flow_context = spec->flow_context;

	tree_init_node(&fte->node, del_hw_fte, del_sw_fte);

	return fte;
}

static void dealloc_flow_group(struct xsc_flow_steering *steering,
			       struct xsc_flow_group *fg)
{
	rhashtable_destroy(&fg->ftes_hash);
	kmem_cache_free(steering->fgs_cache, fg);
}

static struct xsc_flow_group *alloc_flow_group(struct xsc_flow_steering *steering,
					       u8 match_mask_enable,
					       void *match_attr,
					       const void *match_mask,
					       int start_index,
					       int end_index)
{
	struct xsc_flow_group *fg;
	int ret;

	fg = kmem_cache_zalloc(steering->fgs_cache, GFP_KERNEL);
	if (!fg)
		return ERR_PTR(-ENOMEM);

	ret = rhashtable_init(&fg->ftes_hash, &rhash_fte);
	if (ret) {
		kmem_cache_free(steering->fgs_cache, fg);
		return ERR_PTR(ret);
	}

	ida_init(&fg->fte_allocator);
	fg->mask.match_mask_enable = match_mask_enable;
	memcpy(&fg->mask.match_mask, match_mask,
	       sizeof(fg->mask.match_mask));
	memcpy(&fg->mask.match_attr, match_attr,
	       sizeof(fg->mask.match_attr));
	fg->node.type = FS_TYPE_FLOW_GROUP;
	fg->start_index = start_index;
	fg->max_ftes = end_index - start_index + 1;

	return fg;
}

static struct xsc_flow_group *alloc_insert_flow_group(struct xsc_flow_table *ft,
						      u64 match_mask_enable,
						      void *match_attr,
						      const void *match_mask,
						      int start_index,
						      int end_index,
						      struct list_head *prev)
{
	struct xsc_flow_steering *steering = get_steering(&ft->node);
	struct xsc_flow_group *fg;
	int ret;

	fg = alloc_flow_group(steering, match_mask_enable, match_attr,
			      match_mask, start_index, end_index);
	if (IS_ERR(fg))
		return fg;

	/* initialize refcnt, add to parent list */
	ret = rhltable_insert(&ft->fgs_hash, &fg->hash, rhash_fg);
	if (ret) {
		dealloc_flow_group(steering, fg);
		return ERR_PTR(ret);
	}

	tree_init_node(&fg->node, del_hw_flow_group, del_sw_flow_group);
	tree_add_node(&fg->node, &ft->node);
	/* Add node to group list */
	list_add(&fg->node.list, prev);
	atomic_inc(&ft->node.version);

	return fg;
}

static struct xsc_flow_table *alloc_flow_table(int level, u16 vport,
					       enum fs_flow_table_type table_type,
					       enum fs_flow_table_op_mod op_mod,
					       u32 flags)
{
	struct xsc_flow_table *ft;
	int ret;

	ft  = kzalloc(sizeof(*ft), GFP_KERNEL);
	if (!ft)
		return ERR_PTR(-ENOMEM);

	ret = rhltable_init(&ft->fgs_hash, &rhash_fg);
	if (ret) {
		kfree(ft);
		return ERR_PTR(ret);
	}

	ft->level = level;
	ft->node.type = FS_TYPE_FLOW_TABLE;
	ft->op_mod = op_mod;
	ft->type = table_type;
	ft->vport = vport;
	ft->flags = flags;
	INIT_LIST_HEAD(&ft->fwd_rules);
	mutex_init(&ft->lock);

	return ft;
}

/* If reverse is false, then we search for the first flow table in the
 * root sub-tree from start(closest from right), else we search for the
 * last flow table in the root sub-tree till start(closest from left).
 */
static struct xsc_flow_table *find_closest_ft_recursive(struct fs_node  *root,
							struct list_head *start,
							bool reverse,
							bool ignore_chains_attr)
{
#define list_advance_entry(pos, reverse)		\
	((reverse) ? list_prev_entry(pos, list) : list_next_entry(pos, list))

#define list_for_each_advance_continue(pos, head, reverse)	\
	for (pos = list_advance_entry(pos, reverse);		\
	     &pos->list != (head);				\
	     pos = list_advance_entry(pos, reverse))

	struct fs_node *iter = list_entry(start, struct fs_node, list);
	struct xsc_flow_table *ft = NULL;

	if (!root && !ignore_chains_attr)
		return NULL;

	list_for_each_advance_continue(iter, &root->children, reverse) {
		if (iter->type == FS_TYPE_FLOW_TABLE) {
			fs_get_obj(ft, iter);
			return ft;
		}
		ft = find_closest_ft_recursive(iter, &iter->children, reverse,
					       ignore_chains_attr);
		if (ft)
			return ft;
	}

	return ft;
}

static struct fs_node *find_prio_chains_parent(struct fs_node *parent,
					       struct fs_node **child)
{
	struct fs_node *node = NULL;

	while (parent && parent->type != FS_TYPE_PRIO_CHAINS) {
		node = parent;
		parent = parent->parent;
	}

	if (child)
		*child = node;

	return parent;
}

/* If reverse is false then return the first flow table next to the passed node
 * in the tree, else return the last flow table before the node in the tree.
 * If skip is true, skip the flow tables in the same prio_chains prio.
 */
static struct xsc_flow_table *find_closest_ft(struct fs_node *node, bool reverse,
					      bool skip)
{
	struct fs_node *prio_chains_parent = NULL;
	struct xsc_flow_table *ft = NULL;
	struct fs_node *curr_node;
	struct fs_node *parent;

	if (skip)
		prio_chains_parent = find_prio_chains_parent(node, NULL);
	parent = node->parent;
	curr_node = node;
	while (!ft && parent) {
		if (parent != prio_chains_parent)
			ft = find_closest_ft_recursive(parent, &curr_node->list, reverse,
						       parent->type != FS_TYPE_PRIO_CHAINS);
		curr_node = parent;
		parent = curr_node->parent;
	}
	return ft;
}

/* Assuming all the tree is locked by mutex chain lock */
static struct xsc_flow_table *find_next_chained_ft(struct fs_node *node)
{
	return find_closest_ft(node, false, true);
}

/* Assuming all the tree is locked by mutex chain lock */
static struct xsc_flow_table *find_prev_chained_ft(struct fs_node *node)
{
	return find_closest_ft(node, true, true);
}

static struct xsc_flow_table *find_next_fwd_ft(struct xsc_flow_table *ft,
					       struct xsc_flow_act *flow_act)
{
	struct fs_prio *prio;
	bool next_ns;

	next_ns = flow_act->action & XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_NS;
	fs_get_obj(prio, next_ns ? ft->ns->node.parent : ft->node.parent);

	return find_next_chained_ft(&prio->node);
}

static int connect_fts_in_prio(struct xsc_core_device *dev,
			       struct fs_prio *prio,
			       struct xsc_flow_table *ft)
{
	struct xsc_flow_root_namespace *root = find_root(&prio->node);
	struct xsc_flow_table *iter;
	int err;

	fs_for_each_ft(iter, prio) {
		err = root->cmds->modify_flow_table(root->dev, iter, ft);
		if (err) {
			xsc_core_err(dev,
				     "Failed to modify flow table id %d, type %d, err %d\n",
				     iter->id, iter->type, err);
			/* The driver is out of sync with the FW */
			return err;
		}
	}
	return 0;
}

static struct xsc_flow_table *find_closet_ft_prio_chains(struct fs_node *node,
							 struct fs_node *parent,
							 struct fs_node **child,
							 bool reverse)
{
	struct xsc_flow_table *ft;

	ft = find_closest_ft(node, reverse, false);

	if (ft && parent == find_prio_chains_parent(&ft->node, child))
		return ft;

	return NULL;
}

/* Connect flow tables from previous priority of prio to ft */
static int connect_prev_fts(struct xsc_core_device *dev,
			    struct xsc_flow_table *ft,
			    struct fs_prio *prio)
{
	struct fs_node *prio_parent, *parent = NULL, *child, *node;
	struct xsc_flow_table *prev_ft;
	int err = 0;

	prio_parent = find_prio_chains_parent(&prio->node, &child);

	/* return directly if not under the first sub ns of prio_chains prio */
	if (prio_parent && !list_is_first(&child->list, &prio_parent->children))
		return 0;

	prev_ft = find_prev_chained_ft(&prio->node);
	while (prev_ft) {
		struct fs_prio *prev_prio;

		fs_get_obj(prev_prio, prev_ft->node.parent);
		err = connect_fts_in_prio(dev, prev_prio, ft);
		if (err)
			break;

		if (!parent) {
			parent = find_prio_chains_parent(&prev_prio->node, &child);
			if (!parent)
				break;
		}

		node = child;
		prev_ft = find_closet_ft_prio_chains(node, parent, &child, true);
	}
	return err;
}

static int update_root_ft_create(struct xsc_flow_table *ft, struct fs_prio
				 *prio)
{
	struct xsc_flow_root_namespace *root = find_root(&prio->node);
	struct xsc_ft_underlay_qp *uqp;
	int min_level = INT_MAX;
	int err = 0;
	u32 qpn;

	if (root->root_ft)
		min_level = root->root_ft->level;

	if (ft->level >= min_level)
		return 0;

	if (list_empty(&root->underlay_qpns)) {
		/* Don't set any QPN (zero) in case QPN list is empty */
		qpn = 0;
		err = root->cmds->update_root_ft(root->dev, ft, qpn, false);
	} else {
		list_for_each_entry(uqp, &root->underlay_qpns, list) {
			qpn = uqp->qpn;
			err = root->cmds->update_root_ft(root->dev, ft,
							 qpn, false);
			if (err)
				break;
		}
	}

	if (err)
		xsc_core_warn(root->dev,
			      "Update root flow table of id(%u) qpn(%d) failed\n",
			      ft->id, qpn);
	else
		root->root_ft = ft;

	return err;
}

static int _xsc_modify_rule_destination(struct xsc_flow_rule *rule,
					struct xsc_flow_destination *dest)
{
	struct xsc_flow_root_namespace *root;
	struct xsc_flow_table *ft;
	struct xsc_flow_group *fg;
	struct fs_fte *fte;
	int modify_mask = BIT(XSC_SET_FTE_MODIFY_ENABLE_MASK_DESTINATION_LIST);
	int err = 0;

	fs_get_obj(fte, rule->node.parent);
	if (!(fte->action.action & XSC_FLOW_CONTEXT_ACTION_FWD_DEST))
		return -EINVAL;
	down_write_ref_node(&fte->node, false);
	fs_get_obj(fg, fte->node.parent);
	fs_get_obj(ft, fg->node.parent);

	memcpy(&rule->dest_attr, dest, sizeof(*dest));
	root = find_root(&ft->node);
	err = root->cmds->update_fte(root->dev, ft, fg,
				     modify_mask, fte);
	up_write_ref_node(&fte->node, false);

	return err;
}

int xsc_modify_rule_destination(struct xsc_flow_handle *handle,
				struct xsc_flow_destination *new_dest,
				struct xsc_flow_destination *old_dest)
{
	int i;

	if (!old_dest) {
		if (handle->num_rules != 1)
			return -EINVAL;
		return _xsc_modify_rule_destination(handle->rule[0],
						    new_dest);
	}

	for (i = 0; i < handle->num_rules; i++) {
		if (xsc_flow_dests_cmp(old_dest, &handle->rule[i]->dest_attr))
			return _xsc_modify_rule_destination(handle->rule[i],
							    new_dest);
	}

	return -EINVAL;
}

/* Modify/set FWD rules that point on old_next_ft to point on new_next_ft  */
static int connect_fwd_rules(struct xsc_core_device *dev,
			     struct xsc_flow_table *new_next_ft,
			     struct xsc_flow_table *old_next_ft)
{
	struct xsc_flow_destination dest = {};
	struct xsc_flow_rule *iter;
	int err = 0;

	/* new_next_ft and old_next_ft could be NULL only
	 * when we create/destroy the anchor flow table.
	 */
	if (!new_next_ft || !old_next_ft)
		return 0;

	dest.type = XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = new_next_ft;

	mutex_lock(&old_next_ft->lock);
	list_splice_init(&old_next_ft->fwd_rules, &new_next_ft->fwd_rules);
	mutex_unlock(&old_next_ft->lock);
	list_for_each_entry(iter, &new_next_ft->fwd_rules, next_ft) {
		if ((iter->sw_action & XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_NS) &&
		    iter->ft->ns == new_next_ft->ns)
			continue;

		err = _xsc_modify_rule_destination(iter, &dest);
		if (err)
			pr_err("xsc_core: failed to modify rule to point on flow table %d\n",
			       new_next_ft->id);
	}
	return 0;
}

static int connect_flow_table(struct xsc_core_device *dev, struct xsc_flow_table *ft,
			      struct fs_prio *prio)
{
	struct xsc_flow_table *next_ft, *first_ft;
	int err = 0;
	struct xsc_eswitch *esw = dev->priv.eswitch;

	/* Connect_prev_fts and update_root_ft_create are mutually exclusive */

	first_ft = list_first_entry_or_null(&prio->node.children,
					    struct xsc_flow_table, node.list);
	if (!first_ft || first_ft->level > ft->level) {
		err = connect_prev_fts(dev, ft, prio);
		if (err)
			return err;

		next_ft = first_ft ? first_ft : find_next_chained_ft(&prio->node);
		err = connect_fwd_rules(dev, ft, next_ft);
		if (err)
			return err;
	}

	if (esw->esw_caps.modify_root)
		err = update_root_ft_create(ft, prio);
	return err;
}

static void list_add_flow_table(struct xsc_flow_table *ft,
				struct fs_prio *prio)
{
	struct list_head *prev = &prio->node.children;
	struct xsc_flow_table *iter;

	fs_for_each_ft(iter, prio) {
		if (iter->level > ft->level)
			break;
		prev = &iter->node.list;
	}
	list_add(&ft->node.list, prev);
}

static struct xsc_flow_table *__xsc_create_flow_table(struct xsc_flow_namespace *ns,
						      struct xsc_flow_table_attr *ft_attr,
						      enum fs_flow_table_op_mod op_mod,
						      u16 vport)
{
	struct xsc_flow_root_namespace *root = find_root(&ns->node);
	bool unmanaged = ft_attr->flags & XSC_FLOW_TABLE_UNMANAGED;
	struct xsc_flow_table *next_ft;
	struct fs_prio *fs_prio = NULL;
	struct xsc_flow_table *ft;
	int err;

	if (!root) {
		pr_err("xsc: flow steering failed to find root of namespace\n");
		return ERR_PTR(-ENODEV);
	}

	mutex_lock(&root->chain_lock);
	fs_prio = find_prio(ns, ft_attr->prio);
	if (!fs_prio) {
		err = -EINVAL;
		goto unlock_root;
	}
	if (!unmanaged) {
		/* The level is related to the priority level range. */
		if (ft_attr->level >= fs_prio->num_levels) {
			err = -ENOSPC;
			goto unlock_root;
		}

		ft_attr->level += fs_prio->start_level;
	}

	/* The level is related to the priority level range. */
	ft = alloc_flow_table(ft_attr->level, vport, root->table_type,
			      op_mod, ft_attr->flags);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		goto unlock_root;
	}

	tree_init_node(&ft->node, del_hw_flow_table, del_sw_flow_table);
	next_ft = unmanaged ? ft_attr->next_ft :
			      find_next_chained_ft(&fs_prio->node);
	ft->def_miss_action = ns->def_miss_action;
	ft->ns = ns;
	err = root->cmds->create_flow_table(root->dev, ft, ft_attr, next_ft);
	if (err)
		goto free_ft;

	if (!unmanaged) {
		err = connect_flow_table(root->dev, ft, fs_prio);
		if (err)
			goto destroy_ft;
	}

	ft->node.active = true;
	down_write_ref_node(&fs_prio->node, false);
	if (!unmanaged) {
		tree_add_node(&ft->node, &fs_prio->node);
		list_add_flow_table(ft, fs_prio);
	} else {
		ft->node.root = fs_prio->node.root;
	}
	fs_prio->num_ft++;
	up_write_ref_node(&fs_prio->node, false);
	mutex_unlock(&root->chain_lock);

#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_fs_add_ft(ft);
#endif
	return ft;
destroy_ft:
	root->cmds->destroy_flow_table(root->dev, ft);
free_ft:
	rhltable_destroy(&ft->fgs_hash);
	kfree(ft);
unlock_root:
	mutex_unlock(&root->chain_lock);
	return ERR_PTR(err);
}

struct xsc_flow_table *xsc_create_flow_table(struct xsc_flow_namespace *ns,
					     struct xsc_flow_table_attr *ft_attr)
{
	return __xsc_create_flow_table(ns, ft_attr, FS_FT_OP_MOD_NORMAL, 0);
}
EXPORT_SYMBOL(xsc_create_flow_table);

u32 xsc_flow_table_id(struct xsc_flow_table *ft)
{
	return ft->id;
}
EXPORT_SYMBOL(xsc_flow_table_id);

struct xsc_flow_table *
xsc_create_vport_flow_table(struct xsc_flow_namespace *ns,
			    struct xsc_flow_table_attr *ft_attr, u16 vport)
{
	return __xsc_create_flow_table(ns, ft_attr, FS_FT_OP_MOD_NORMAL, vport);
}

struct xsc_flow_table*
xsc_create_lag_demux_flow_table(struct xsc_flow_namespace *ns, int prio, u32 level)
{
	struct xsc_flow_table_attr ft_attr = {};

	ft_attr.level = level;
	ft_attr.prio  = prio;
	ft_attr.max_fte = 1;

	return __xsc_create_flow_table(ns, &ft_attr, FS_FT_OP_MOD_LAG_DEMUX, 0);
}
EXPORT_SYMBOL(xsc_create_lag_demux_flow_table);

struct xsc_flow_table*
xsc_create_auto_grouped_flow_table(struct xsc_flow_namespace *ns,
				   struct xsc_flow_table_attr *ft_attr)
{
	int num_reserved_entries = ft_attr->autogroup.num_reserved_entries;
	int max_num_groups = ft_attr->autogroup.max_num_groups;
	struct xsc_flow_table *ft;
	int autogroups_max_fte;

	ft = xsc_create_flow_table(ns, ft_attr);
	if (IS_ERR(ft))
		return ft;

	autogroups_max_fte = ft->max_fte - num_reserved_entries;
	if (max_num_groups > autogroups_max_fte)
		goto err_validate;
	if (num_reserved_entries > ft->max_fte)
		goto err_validate;

	/* Align the number of groups according to the largest group size */
	if (autogroups_max_fte / (max_num_groups + 1) > MAX_FLOW_GROUP_SIZE)
		max_num_groups = (autogroups_max_fte / MAX_FLOW_GROUP_SIZE) - 1;

	ft->autogroup.active = true;
	ft->autogroup.required_groups = max_num_groups;
	ft->autogroup.max_fte = autogroups_max_fte;
	/* We save place for flow groups in addition to max types */
	ft->autogroup.group_size = autogroups_max_fte / (max_num_groups + 1);

	return ft;

err_validate:
	xsc_destroy_flow_table(ft);
	return ERR_PTR(-ENOSPC);
}
EXPORT_SYMBOL(xsc_create_auto_grouped_flow_table);

struct xsc_flow_group *xsc_create_flow_group(struct xsc_flow_table *ft, u32 *fg_in)
{
	struct xsc_flow_root_namespace *root = find_root(&ft->node);
	void *match_mask = XSC_ADDR_OF(create_flow_group_in,
					    fg_in, match_mask);
	void *match_attr = XSC_ADDR_OF(create_flow_group_in,
					    fg_in, match_attr);
	u8 match_mask_enable = XSC_GET(flow_attr, match_attr,
				       match_mask_enable);
	int start_index = XSC_GET(flow_attr, match_attr,
				   start_flow_index);
	int end_index = XSC_GET(flow_attr, match_attr,
				 end_flow_index);
	struct xsc_flow_group *fg;
	int err;

	if (ft->autogroup.active && start_index < ft->autogroup.max_fte)
		return ERR_PTR(-EPERM);

	down_write_ref_node(&ft->node, false);
	fg = alloc_insert_flow_group(ft, match_mask_enable,
				     match_attr,
				     match_mask,
				     start_index, end_index,
				     ft->node.children.prev);
	up_write_ref_node(&ft->node, false);
	if (IS_ERR(fg))
		return fg;

	err = root->cmds->create_flow_group(root->dev, ft, fg_in, fg);
	if (err) {
		tree_put_node(&fg->node, false);
		return ERR_PTR(err);
	}

#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_fs_add_fg(fg, match_attr);
#endif

	fg->node.active = true;

	return fg;
}
EXPORT_SYMBOL(xsc_create_flow_group);

static struct xsc_flow_rule *alloc_rule(struct xsc_flow_destination *dest)
{
	struct xsc_flow_rule *rule;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return NULL;

	INIT_LIST_HEAD(&rule->next_ft);
	rule->node.type = FS_TYPE_FLOW_DEST;
	if (dest)
		memcpy(&rule->dest_attr, dest, sizeof(*dest));
	else
		rule->dest_attr.type = XSC_FLOW_DESTINATION_TYPE_NONE;

	return rule;
}

static struct xsc_flow_handle *alloc_handle(int num_rules)
{
	struct xsc_flow_handle *handle;

	handle = kzalloc(struct_size(handle, rule, num_rules), GFP_KERNEL);
	if (!handle)
		return NULL;

	handle->num_rules = num_rules;

	return handle;
}

static void destroy_flow_handle(struct fs_fte *fte,
				struct xsc_flow_handle *handle,
				struct xsc_flow_destination *dest,
				int i)
{
	for (; --i >= 0;) {
		if (refcount_dec_and_test(&handle->rule[i]->node.refcount)) {
			fte->dests_size--;
			list_del(&handle->rule[i]->node.list);
			kfree(handle->rule[i]);
		}
	}
	kfree(handle);
}

static struct xsc_flow_handle *
create_flow_handle(struct fs_fte *fte,
		   struct xsc_flow_destination *dest,
		   int dest_num,
		   int *modify_mask,
		   bool *new_rule)
{
	struct xsc_flow_handle *handle;
	struct xsc_flow_rule *rule = NULL;
	static int count = BIT(XSC_SET_FTE_MODIFY_ENABLE_MASK_FLOW_COUNTERS);
	static int dst = BIT(XSC_SET_FTE_MODIFY_ENABLE_MASK_DESTINATION_LIST);
	int type;
	int i = 0;

	handle = alloc_handle((dest_num) ? dest_num : 1);
	if (!handle)
		return ERR_PTR(-ENOMEM);

	do {
		if (dest) {
			rule = find_flow_rule(fte, dest + i);
			if (rule) {
				refcount_inc(&rule->node.refcount);
				goto rule_found;
			}
		}

		*new_rule = true;
		rule = alloc_rule(dest + i);
		if (!rule)
			goto free_rules;

		/* Add dest to dests list- we need flow tables to be in the
		 * end of the list for forward to next prio rules.
		 */
		tree_init_node(&rule->node, NULL, del_sw_hw_rule);
		if (dest &&
		    (dest[i].type != XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE ||
		     dest[i].type != XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE ||
		     dest[i].type != XSC_FLOW_DESTINATION_TYPE_FLOW_CHAIN))
			list_add(&rule->node.list, &fte->node.children);
		else
			list_add_tail(&rule->node.list, &fte->node.children);

		if (dest) {
			fte->dests_size++;

			if (is_fwd_dest_type(dest[i].type))
				fte->fwd_dests++;

			type = dest[i].type ==
				XSC_FLOW_DESTINATION_TYPE_COUNTER;
			*modify_mask |= type ? count : dst;
		}
rule_found:
		handle->rule[i] = rule;
	} while (++i < dest_num);

	return handle;

free_rules:
	destroy_flow_handle(fte, handle, dest, i);
	return ERR_PTR(-ENOMEM);
}

/* fte should not be deleted while calling this function */
static struct xsc_flow_handle *
add_rule_fte(struct fs_fte *fte,
	     struct xsc_flow_group *fg,
	     struct xsc_flow_destination *dest,
	     int dest_num,
	     bool update_action)
{
	struct xsc_flow_root_namespace *root;
	struct xsc_flow_handle *handle;
	struct xsc_flow_table *ft;
	int modify_mask = 0;
	int err;
	bool new_rule = false;

	handle = create_flow_handle(fte, dest, dest_num, &modify_mask,
				    &new_rule);
	if (IS_ERR(handle) || !new_rule)
		goto out;

	if (update_action)
		modify_mask |= BIT(XSC_SET_FTE_MODIFY_ENABLE_MASK_ACTION);

	fs_get_obj(ft, fg->node.parent);
	root = find_root(&fg->node);
	if (!(fte->status & FS_FTE_STATUS_EXISTING))
		err = root->cmds->create_fte(root->dev, ft, fg, fte);
	else
		err = root->cmds->update_fte(root->dev, ft, fg, modify_mask, fte);
	if (err)
		goto free_handle;

	fte->node.active = true;
	fte->status |= FS_FTE_STATUS_EXISTING;
	atomic_inc(&fg->node.version);

out:
	return handle;

free_handle:
	destroy_flow_handle(fte, handle, dest, handle->num_rules);
	return ERR_PTR(err);
}

static struct xsc_flow_group *alloc_auto_flow_group(struct xsc_flow_table  *ft,
						    const struct xsc_flow_spec *spec)
{
	struct list_head *prev = &ft->node.children;
	u32 max_fte = ft->autogroup.max_fte;
	unsigned int candidate_index = 0;
	unsigned int group_size = 0;
	struct xsc_flow_group *fg;

	if (!ft->autogroup.active)
		return ERR_PTR(-ENOENT);

	if (ft->autogroup.num_groups < ft->autogroup.required_groups)
		group_size = ft->autogroup.group_size;

	/*  max_fte == ft->autogroup.max_types */
	if (group_size == 0)
		group_size = 1;

	/* sorted by start_index */
	fs_for_each_fg(fg, ft) {
		if (candidate_index + group_size > fg->start_index)
			candidate_index = fg->start_index + fg->max_ftes;
		else
			break;
		prev = &fg->node.list;
	}

	if (candidate_index + group_size > max_fte)
		return ERR_PTR(-ENOSPC);

	fg = alloc_insert_flow_group(ft,
				     spec->match_mask_enable,
				     (void *)&spec->match_attr,
				     spec->match_mask,
				     candidate_index,
				     candidate_index + group_size - 1,
				     prev);
	if (IS_ERR(fg))
		goto out;

	if (group_size == ft->autogroup.group_size)
		ft->autogroup.num_groups++;

out:
	return fg;
}

static int create_auto_flow_group(struct xsc_flow_table *ft,
				  struct xsc_flow_group *fg)
{
	struct xsc_flow_root_namespace *root = find_root(&ft->node);
	int inlen = XSC_ST_SZ_BYTES(create_flow_group_in);
	void *match_mask, *match_attr;
	int err;
	u32 *in;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	match_attr = XSC_ADDR_OF(create_flow_group_in, in, match_attr);
	memcpy(match_attr, &fg->mask.match_attr, sizeof(fg->mask.match_attr));
	XSC_SET(flow_attr, match_attr, match_mask_enable,
		fg->mask.match_mask_enable);
	XSC_SET(flow_attr, match_attr, start_flow_index, fg->start_index);
	XSC_SET(flow_attr, match_attr, end_flow_index, (fg->start_index +
		fg->max_ftes - 1));

	match_mask = XSC_ADDR_OF(create_flow_group_in, in, match_mask);
	memcpy(match_mask, fg->mask.match_mask, sizeof(fg->mask.match_mask));

	err = root->cmds->create_flow_group(root->dev, ft, in, fg);
	if (!err) {
		fg->node.active = true;
#ifdef CONFIG_XSC_TRACE_DEBUG
		trace_xsc_fs_add_fg(fg, match_attr);
#endif
	}

	kvfree(in);
	return err;
}

static bool xsc_pkt_reformat_cmp(struct xsc_pkt_reformat *p1,
				 struct xsc_pkt_reformat *p2)
{
	return p1->owner == p2->owner &&
		(p1->owner == XSC_FLOW_RESOURCE_OWNER_FW ?
		 p1->id == p2->id :
		 xsc_fs_action_get_pkt_reformat_id(p1) ==
		 xsc_fs_action_get_pkt_reformat_id(p2));
}

static bool xsc_flow_dests_cmp(struct xsc_flow_destination *d1,
			       struct xsc_flow_destination *d2)
{
	if (d1->type == d2->type) {
		if (((d1->type == XSC_FLOW_DESTINATION_TYPE_VPORT ||
		      d1->type == XSC_FLOW_DESTINATION_TYPE_UPLINK) &&
		    d1->vport.num == d2->vport.num &&
		    d1->vport.flags == d2->vport.flags &&
		    ((d1->vport.flags & XSC_FLOW_DEST_VPORT_VHCA_ID) ?
		    d1->vport.vhca_id == d2->vport.vhca_id : true) &&
		    ((d1->vport.flags & XSC_FLOW_DEST_VPORT_REFORMAT_ID) ?
		      xsc_pkt_reformat_cmp(d1->vport.pkt_reformat,
					   d2->vport.pkt_reformat) : true)) ||
		    (d1->type == XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE && d1->ft == d2->ft) ||
		    (d1->type == XSC_FLOW_DESTINATION_TYPE_TIR &&
		     d1->tir_num == d2->tir_num) ||
		    (d1->type == XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE_NUM &&
		     d1->ft_num == d2->ft_num) ||
		    (d1->type == XSC_FLOW_DESTINATION_TYPE_FLOW_SAMPLER &&
		     d1->sampler_id == d2->sampler_id) ||
		    (d1->type == XSC_FLOW_DESTINATION_TYPE_RANGE &&
		     d1->range.field == d2->range.field &&
		     d1->range.hit_ft == d2->range.hit_ft &&
		     d1->range.miss_ft == d2->range.miss_ft &&
		     d1->range.min == d2->range.min &&
		     d1->range.max == d2->range.max))
			return true;
	}

	return false;
}

static struct xsc_flow_rule *find_flow_rule(struct fs_fte *fte,
					    struct xsc_flow_destination *dest)
{
	struct xsc_flow_rule *rule;

	list_for_each_entry(rule, &fte->node.children, node.list) {
		if (xsc_flow_dests_cmp(&rule->dest_attr, dest))
			return rule;
	}
	return NULL;
}

static bool check_conflicting_actions_vlan(const struct xsc_fs_vlan *vlan0,
					   const struct xsc_fs_vlan *vlan1)
{
	return vlan0->ethtype != vlan1->ethtype ||
	       vlan0->vid != vlan1->vid ||
	       vlan0->prio != vlan1->prio;
}

static bool check_conflicting_actions(const struct xsc_flow_act *act1,
				      const struct xsc_flow_act *act2)
{
	u32 action1 = act1->action;
	u32 action2 = act2->action;
	u32 xored_actions;

	xored_actions = action1 ^ action2;

	/* if one rule only wants to count, it's ok */
	if (action1 == XSC_FLOW_CONTEXT_ACTION_COUNT ||
	    action2 == XSC_FLOW_CONTEXT_ACTION_COUNT)
		return false;

	if (xored_actions & (XSC_FLOW_CONTEXT_ACTION_DROP  |
			     XSC_FLOW_CONTEXT_ACTION_PACKET_REFORMAT |
			     XSC_FLOW_CONTEXT_ACTION_DECAP |
			     XSC_FLOW_CONTEXT_ACTION_MOD_HDR  |
			     XSC_FLOW_CONTEXT_ACTION_VLAN_POP |
			     XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH |
			     XSC_FLOW_CONTEXT_ACTION_VLAN_POP_2 |
			     XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH_2))
		return true;

	if (action1 & XSC_FLOW_CONTEXT_ACTION_PACKET_REFORMAT &&
	    act1->pkt_reformat != act2->pkt_reformat)
		return true;

	if (action1 & XSC_FLOW_CONTEXT_ACTION_MOD_HDR &&
	    act1->modify_hdr != act2->modify_hdr)
		return true;

	if (action1 & XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH &&
	    check_conflicting_actions_vlan(&act1->vlan[0], &act2->vlan[0]))
		return true;

	if (action1 & XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH_2 &&
	    check_conflicting_actions_vlan(&act1->vlan[1], &act2->vlan[1]))
		return true;

	return false;
}

static int check_conflicting_ftes(struct fs_fte *fte,
				  const struct xsc_flow_context *flow_context,
				  const struct xsc_flow_act *flow_act)
{
	if (check_conflicting_actions(flow_act, &fte->action)) {
		xsc_core_warn(get_dev(&fte->node),
			      "Found two FTEs with conflicting actions\n");
		return -EEXIST;
	}

	if ((flow_context->flags & FLOW_CONTEXT_HAS_TAG) &&
	    fte->flow_context.flow_tag != flow_context->flow_tag) {
		xsc_core_warn(get_dev(&fte->node),
			      "FTE flow tag %u already exists with different flow tag %u\n",
			      fte->flow_context.flow_tag,
			      flow_context->flow_tag);
		return -EEXIST;
	}

	return 0;
}

static struct xsc_flow_handle *add_rule_fg(struct xsc_flow_group *fg,
					   const struct xsc_flow_spec *spec,
					   struct xsc_flow_act *flow_act,
					   struct xsc_flow_destination *dest,
					   int dest_num, struct fs_fte *fte)
{
	struct xsc_flow_handle *handle;
	int old_action;
	int i;
	int ret;

	ret = check_conflicting_ftes(fte, &spec->flow_context, flow_act);
	if (ret)
		return ERR_PTR(ret);

	old_action = fte->action.action;
	fte->action.action |= flow_act->action;
	handle = add_rule_fte(fte, fg, dest, dest_num,
			      old_action != flow_act->action);
	if (IS_ERR(handle)) {
		fte->action.action = old_action;
		return handle;
	}

#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_fs_set_fte(fte, false);
#endif

	/* Link newly added rules into the tree. */
	for (i = 0; i < handle->num_rules; i++) {
		if (!handle->rule[i]->node.parent) {
			tree_add_node(&handle->rule[i]->node, &fte->node);
#ifdef CONFIG_XSC_TRACE_DEBUG
			trace_xsc_fs_add_rule(handle->rule[i], i);
#endif
		}
	}
	return handle;
}

static bool counter_is_valid(u32 action)
{
	return (action & (XSC_FLOW_CONTEXT_ACTION_DROP |
			  XSC_FLOW_CONTEXT_ACTION_ALLOW |
			  XSC_FLOW_CONTEXT_ACTION_FWD_DEST));
}

static bool dest_is_valid(struct xsc_flow_destination *dest,
			  struct xsc_flow_act *flow_act,
			  struct xsc_flow_table *ft)
{
	bool ignore_level = flow_act->flags & FLOW_ACT_IGNORE_FLOW_LEVEL;
	u32 action = flow_act->action;

	if (dest && dest->type == XSC_FLOW_DESTINATION_TYPE_COUNTER)
		return counter_is_valid(action);

	if (!(action & XSC_FLOW_CONTEXT_ACTION_FWD_DEST))
		return true;

	if (ignore_level) {
		if (dest->type == XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE &&
		    ft->type != dest->ft->type)
			return false;
	}

	if (!dest || (dest->type == XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE &&
		      (dest->ft->level <= ft->level && !ignore_level)))
		return false;
	return true;
}

struct match_list {
	struct list_head	list;
	struct xsc_flow_group *g;
};

static void free_match_list(struct match_list *head, bool ft_locked)
{
	struct match_list *iter, *match_tmp;

	list_for_each_entry_safe(iter, match_tmp, &head->list,
				 list) {
		tree_put_node(&iter->g->node, ft_locked);
		list_del(&iter->list);
		kfree(iter);
	}
}

static int build_match_list(struct match_list *match_head,
			    struct xsc_flow_table *ft,
			    const struct xsc_flow_spec *spec,
			    struct xsc_flow_group *fg,
			    bool ft_locked)
{
	struct rhlist_head *tmp, *list;
	struct xsc_flow_group *g;

	rcu_read_lock();
	INIT_LIST_HEAD(&match_head->list);
	/* Collect all fgs which has a matching match_mask */
	list = rhltable_lookup(&ft->fgs_hash, spec->match_mask, rhash_fg);
	/* RCU is atomic, we can't execute FW commands here */
	rhl_for_each_entry_rcu(g, tmp, list, hash) {
		struct match_list *curr_match;

		if (fg && fg != g)
			continue;

		if (unlikely(!tree_get_node(&g->node)))
			continue;

		curr_match = kmalloc(sizeof(*curr_match), GFP_ATOMIC);
		if (!curr_match) {
			rcu_read_unlock();
			free_match_list(match_head, ft_locked);
			return -ENOMEM;
		}
		curr_match->g = g;
		list_add_tail(&curr_match->list, &match_head->list);
	}
	rcu_read_unlock();
	return 0;
}

static u64 matched_fgs_get_version(struct list_head *match_head)
{
	struct match_list *iter;
	u64 version = 0;

	list_for_each_entry(iter, match_head, list)
		version += (u64)atomic_read(&iter->g->node.version);
	return version;
}

static struct fs_fte *
lookup_fte_locked(struct xsc_flow_group *g,
		  const u32 *match_value,
		  bool take_write)
{
	struct fs_fte *fte_tmp;

	if (take_write)
		nested_down_write_ref_node(&g->node, FS_LOCK_PARENT);
	else
		nested_down_read_ref_node(&g->node, FS_LOCK_PARENT);
	fte_tmp = rhashtable_lookup_fast(&g->ftes_hash, match_value,
					 rhash_fte);
	if (!fte_tmp || !tree_get_node(&fte_tmp->node)) {
		fte_tmp = NULL;
		goto out;
	}
	if (!fte_tmp->node.active) {
		tree_put_node(&fte_tmp->node, false);
		fte_tmp = NULL;
		goto out;
	}

	nested_down_write_ref_node(&fte_tmp->node, FS_LOCK_CHILD);
out:
	if (take_write)
		up_write_ref_node(&g->node, false);
	else
		up_read_ref_node(&g->node);
	return fte_tmp;
}

struct xsc_flow_handle *add_to_miss_fg(struct xsc_flow_table *ft,
				       struct xsc_flow_group *fg,
				       const struct xsc_flow_spec *spec,
				       struct xsc_flow_act *flow_act,
				       struct xsc_flow_destination *dest,
				       int dest_num)
{
	struct xsc_flow_steering *steering = get_steering(&ft->node);
	struct xsc_flow_handle *rule = NULL;
	struct fs_fte *fte;
	int err;

	fte = alloc_fte(ft, spec, flow_act);
	if (IS_ERR(fte))
		return ERR_PTR(-ENOMEM);

	nested_down_write_ref_node(&fg->node, FS_LOCK_PARENT);

	err = insert_fte(fg, fte);
	if (err) {
		up_write_ref_node(&fg->node, false);
		goto err_release_fg;
	}

	nested_down_write_ref_node(&fte->node, FS_LOCK_CHILD);
	up_write_ref_node(&fg->node, false);

	rule = add_rule_fg(fg, spec, flow_act, dest, dest_num, fte);
	up_write_ref_node(&fte->node, false);
	if (IS_ERR(rule)) {
		pr_err("%s: Failed to add miss fte in flow group%d\n",
		       __func__, fg->id);
		tree_put_node(&fte->node, false);
	}
	return rule;

err_release_fg:
	kmem_cache_free(steering->ftes_cache, fte);
	return rule;
}

static struct xsc_flow_handle *
try_add_to_existing_fg(struct xsc_flow_table *ft,
		       struct list_head *match_head,
		       const struct xsc_flow_spec *spec,
		       struct xsc_flow_act *flow_act,
		       struct xsc_flow_destination *dest,
		       int dest_num,
		       int ft_version)
{
	struct xsc_flow_steering *steering = get_steering(&ft->node);
	struct xsc_flow_group *g;
	struct xsc_flow_handle *rule;
	struct match_list *iter;
	bool take_write = false;
	struct fs_fte *fte;
	u64  version = 0;
	bool try_again = false;
	int err;

	fte = alloc_fte(ft, spec, flow_act);
	if (IS_ERR(fte))
		return  ERR_PTR(-ENOMEM);

search_again_locked:
	if (flow_act->flags & FLOW_ACT_NO_APPEND)
		goto skip_search;
	version = matched_fgs_get_version(match_head);
	/* Try to find an fte with identical match value and attempt update its
	 * action.
	 */
	list_for_each_entry(iter, match_head, list) {
		struct fs_fte *fte_tmp;

		g = iter->g;
		fte_tmp = lookup_fte_locked(g, spec->match_value, take_write);
		if (!fte_tmp)
			continue;
		rule = add_rule_fg(g, spec, flow_act, dest, dest_num, fte_tmp);
		/* No error check needed here, because insert_fte() is not called */
		up_write_ref_node(&fte_tmp->node, false);
		tree_put_node(&fte_tmp->node, false);
		kmem_cache_free(steering->ftes_cache, fte);
		return rule;
	}

skip_search:
	/* No group with matching fte found, or we skipped the search.
	 * Try to add a new fte to any matching fg.
	 */

	/* Check the ft version, for case that new flow group
	 * was added while the fgs weren't locked
	 */
	if (atomic_read(&ft->node.version) != ft_version) {
		rule = ERR_PTR(-EAGAIN);
		goto out;
	}

	/* Check the fgs version. If version have changed it could be that an
	 * FTE with the same match value was added while the fgs weren't
	 * locked.
	 */
	if (!(flow_act->flags & FLOW_ACT_NO_APPEND) &&
	    version != matched_fgs_get_version(match_head)) {
		take_write = true;
		goto search_again_locked;
	}

	list_for_each_entry(iter, match_head, list) {
		g = iter->g;

		nested_down_write_ref_node(&g->node, FS_LOCK_PARENT);

		if (!g->node.active) {
			try_again = true;
			up_write_ref_node(&g->node, false);
			continue;
		}

		err = insert_fte(g, fte);
		if (err) {
			up_write_ref_node(&g->node, false);
			if (err == -ENOSPC)
				continue;
			kmem_cache_free(steering->ftes_cache, fte);
			return ERR_PTR(err);
		}

		nested_down_write_ref_node(&fte->node, FS_LOCK_CHILD);
		up_write_ref_node(&g->node, false);
		rule = add_rule_fg(g, spec, flow_act, dest, dest_num, fte);
		up_write_ref_node(&fte->node, false);
		if (IS_ERR(rule))
			tree_put_node(&fte->node, false);
		return rule;
	}
	if (try_again)
		err = -EAGAIN;
	else
		err = -ENOENT;
	rule = ERR_PTR(err);
out:
	kmem_cache_free(steering->ftes_cache, fte);
	return rule;
}

static struct xsc_flow_handle *
_xsc_add_flow_rules(struct xsc_flow_table *ft, const struct xsc_flow_spec *spec,
		    struct xsc_flow_act *flow_act,
		    struct xsc_flow_destination *dest, int dest_num)
{
	struct xsc_flow_steering *steering = get_steering(&ft->node);
	struct xsc_flow_handle *rule;
	struct match_list match_head;
	struct xsc_flow_group *g;
	bool take_write = false;
	struct fs_fte *fte;
	int version;
	int err;
	int i;

	if (!check_valid_spec(spec))
		return ERR_PTR(-EINVAL);

	if (flow_act->fg && ft->autogroup.active)
		return ERR_PTR(-EINVAL);

	if (dest && dest_num <= 0)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < dest_num; i++) {
		if (!dest_is_valid(&dest[i], flow_act, ft))
			return ERR_PTR(-EINVAL);
	}
	nested_down_read_ref_node(&ft->node, FS_LOCK_GRANDPARENT);
search_again_locked:
	version = atomic_read(&ft->node.version);

	/* Collect all fgs which has a matching match_mask */
	err = build_match_list(&match_head, ft, spec, flow_act->fg, take_write);
	if (err) {
		if (take_write)
			up_write_ref_node(&ft->node, false);
		else
			up_read_ref_node(&ft->node);
		return ERR_PTR(err);
	}

	if (!take_write)
		up_read_ref_node(&ft->node);

	rule = try_add_to_existing_fg(ft, &match_head.list, spec, flow_act, dest,
				      dest_num, version);
	free_match_list(&match_head, take_write);
	if (!IS_ERR(rule) ||
	    (PTR_ERR(rule) != -ENOENT && PTR_ERR(rule) != -EAGAIN)) {
		if (take_write)
			up_write_ref_node(&ft->node, false);
		return rule;
	}

	if (!take_write) {
		nested_down_write_ref_node(&ft->node, FS_LOCK_GRANDPARENT);
		take_write = true;
	}

	if (PTR_ERR(rule) == -EAGAIN ||
	    version != atomic_read(&ft->node.version))
		goto search_again_locked;

	g = alloc_auto_flow_group(ft, spec);
	if (IS_ERR(g)) {
		rule = ERR_CAST(g);
		up_write_ref_node(&ft->node, false);
		return rule;
	}

	fte = alloc_fte(ft, spec, flow_act);
	if (IS_ERR(fte)) {
		up_write_ref_node(&ft->node, false);
		err = PTR_ERR(fte);
		goto err_alloc_fte;
	}

	nested_down_write_ref_node(&g->node, FS_LOCK_PARENT);
	up_write_ref_node(&ft->node, false);

	err = create_auto_flow_group(ft, g);
	if (err)
		goto err_release_fg;

	err = insert_fte(g, fte);
	if (err)
		goto err_release_fg;

	nested_down_write_ref_node(&fte->node, FS_LOCK_CHILD);
	up_write_ref_node(&g->node, false);
	rule = add_rule_fg(g, spec, flow_act, dest, dest_num, fte);
	up_write_ref_node(&fte->node, false);
	if (IS_ERR(rule))
		tree_put_node(&fte->node, false);
	tree_put_node(&g->node, false);

	return rule;

err_release_fg:
	up_write_ref_node(&g->node, false);
	kmem_cache_free(steering->ftes_cache, fte);
err_alloc_fte:
	tree_put_node(&g->node, false);
	return ERR_PTR(err);
}

struct xsc_flow_handle *xsc_add_flow_rules(struct xsc_flow_table *ft,
					   const struct xsc_flow_spec *spec,
					   struct xsc_flow_act *flow_act,
					   struct xsc_flow_destination *dest,
					   int num_dest)
{
	struct xsc_flow_root_namespace *root = find_root(&ft->node);
	static const struct xsc_flow_spec zero_spec = {};
	struct xsc_flow_destination *gen_dest = NULL;
	struct xsc_flow_table *next_ft = NULL;
	struct xsc_flow_handle *handle = NULL;
	u32 sw_action = flow_act->action;
	int i;

	if (!spec)
		spec = &zero_spec;

	if (!is_fwd_next_action(sw_action))
		return _xsc_add_flow_rules(ft, spec, flow_act, dest, num_dest);

	mutex_lock(&root->chain_lock);
	next_ft = find_next_fwd_ft(ft, flow_act);
	if (!next_ft) {
		pr_err("%s: can't find fwd ft\n", __func__);
		handle = ERR_PTR(-EOPNOTSUPP);
		goto unlock;
	}

	gen_dest = kcalloc(num_dest + 1, sizeof(*dest), GFP_KERNEL);
	if (!gen_dest) {
		handle = ERR_PTR(-ENOMEM);
		goto unlock;
	}
	for (i = 0; i < num_dest; i++)
		gen_dest[i] = dest[i];
	gen_dest[i].type = XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	gen_dest[i].ft = next_ft;
	dest = gen_dest;
	num_dest++;
	flow_act->action &= ~(XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_PRIO |
			      XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_NS);
	flow_act->action |= XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
	handle = _xsc_add_flow_rules(ft, spec, flow_act, dest, num_dest);
	if (IS_ERR(handle))
		goto unlock;

	if (list_empty(&handle->rule[num_dest - 1]->next_ft)) {
		mutex_lock(&next_ft->lock);
		list_add(&handle->rule[num_dest - 1]->next_ft,
			 &next_ft->fwd_rules);
		mutex_unlock(&next_ft->lock);
		handle->rule[num_dest - 1]->sw_action = sw_action;
		handle->rule[num_dest - 1]->ft = ft;
	}
unlock:
	mutex_unlock(&root->chain_lock);
	kfree(gen_dest);
	return handle;
}
EXPORT_SYMBOL(xsc_add_flow_rules);

void xsc_del_flow_rules(struct xsc_flow_handle *handle)
{
	struct fs_fte *fte;
	int i;

	if (!handle)
		return;

	/* In order to consolidate the HW changes we lock the FTE for other
	 * changes, and increase its refcount, in order not to perform the
	 * "del" functions of the FTE. Will handle them here.
	 * The removal of the rules is done under locked FTE.
	 * After removing all the handle's rules, if there are remaining
	 * rules, it means we just need to modify the FTE in FW, and
	 * unlock/decrease the refcount we increased before.
	 * Otherwise, it means the FTE should be deleted. First delete the
	 * FTE in FW. Then, unlock the FTE, and proceed the tree_put_node of
	 * the FTE, which will handle the last decrease of the refcount, as
	 * well as required handling of its parent.
	 */
	fs_get_obj(fte, handle->rule[0]->node.parent);
	down_write_ref_node(&fte->node, false);
	for (i = handle->num_rules - 1; i >= 0; i--)
		tree_remove_node(&handle->rule[i]->node, true);
	if (list_empty(&fte->node.children)) {
		fte->node.del_hw_func(&fte->node);
		/* Avoid double call to del_hw_fte */
		fte->node.del_hw_func = NULL;
		up_write_ref_node(&fte->node, false);
		tree_put_node(&fte->node, false);
	} else if (fte->dests_size) {
		if (fte->modify_mask)
			modify_fte(fte);
		up_write_ref_node(&fte->node, false);
	} else {
		up_write_ref_node(&fte->node, false);
	}
	kfree(handle);
}
EXPORT_SYMBOL(xsc_del_flow_rules);

/* Assuming prio->node.children(flow tables) is sorted by level */
static struct xsc_flow_table *find_next_ft(struct xsc_flow_table *ft)
{
	struct fs_node *prio_parent, *child;
	struct fs_prio *prio;

	fs_get_obj(prio, ft->node.parent);

	if (!list_is_last(&ft->node.list, &prio->node.children))
		return list_next_entry(ft, node.list);

	prio_parent = find_prio_chains_parent(&prio->node, &child);

	if (prio_parent && list_is_first(&child->list, &prio_parent->children))
		return find_closest_ft(&prio->node, false, false);

	return find_next_chained_ft(&prio->node);
}

static int update_root_ft_destroy(struct xsc_flow_table *ft)
{
	struct xsc_flow_root_namespace *root = find_root(&ft->node);
	struct xsc_ft_underlay_qp *uqp;
	struct xsc_flow_table *new_root_ft = NULL;
	int err = 0;
	u32 qpn;

	if (root->root_ft != ft)
		return 0;

	new_root_ft = find_next_ft(ft);
	if (!new_root_ft) {
		root->root_ft = NULL;
		return 0;
	}

	if (list_empty(&root->underlay_qpns)) {
		/* Don't set any QPN (zero) in case QPN list is empty */
		qpn = 0;
		err = root->cmds->update_root_ft(root->dev, new_root_ft,
						 qpn, false);
	} else {
		list_for_each_entry(uqp, &root->underlay_qpns, list) {
			qpn = uqp->qpn;
			err = root->cmds->update_root_ft(root->dev,
							 new_root_ft, qpn,
							 false);
			if (err)
				break;
		}
	}

	if (err)
		xsc_core_warn(root->dev,
			      "Update root flow table of id(%u) qpn(%d) failed\n",
			      ft->id, qpn);
	else
		root->root_ft = new_root_ft;

	return 0;
}

/* Connect flow table from previous priority to
 * the next flow table.
 */
static int disconnect_flow_table(struct xsc_flow_table *ft)
{
	struct xsc_core_device *dev = get_dev(&ft->node);
	struct xsc_flow_table *next_ft;
	struct fs_prio *prio;
	int err = 0;

	err = update_root_ft_destroy(ft);
	if (err)
		return err;

	fs_get_obj(prio, ft->node.parent);
	if  (!(list_first_entry(&prio->node.children,
				struct xsc_flow_table,
				node.list) == ft))
		return 0;

	next_ft = find_next_ft(ft);
	err = connect_fwd_rules(dev, next_ft, ft);
	if (err)
		return err;

	err = connect_prev_fts(dev, next_ft, prio);
	if (err)
		xsc_core_warn(dev, "Failed to disconnect flow table %d\n", ft->id);
	return err;
}

int xsc_destroy_flow_table(struct xsc_flow_table *ft)
{
	struct xsc_flow_root_namespace *root;
	int err = 0;

	if (!ft)
		return 0;

	root = find_root(&ft->node);
	mutex_lock(&root->chain_lock);
	if (!(ft->flags & XSC_FLOW_TABLE_UNMANAGED))
		err = disconnect_flow_table(ft);
	if (err) {
		mutex_unlock(&root->chain_lock);
		return err;
	}
	if (tree_remove_node(&ft->node, false))
		xsc_core_warn(get_dev(&ft->node),
			      "Flow table %d wasn't destroyed, refcount > 1\n", ft->id);
	mutex_unlock(&root->chain_lock);

	return err;
}
EXPORT_SYMBOL(xsc_destroy_flow_table);

void xsc_destroy_flow_group(struct xsc_flow_group *fg)
{
	if (!fg)
		return;

	if (tree_remove_node(&fg->node, false))
		xsc_core_warn(get_dev(&fg->node),
			      "Flow group %d wasn't destroyed, refcount > 1\n", fg->id);
}
EXPORT_SYMBOL(xsc_destroy_flow_group);

struct xsc_flow_namespace *xsc_get_fdb_sub_ns(struct xsc_core_device *dev, int n)
{
	struct xsc_flow_steering *steering = dev->priv.steering;

	if (!steering || !steering->fdb_sub_ns)
		return NULL;

	return steering->fdb_sub_ns[n];
}
EXPORT_SYMBOL(xsc_get_fdb_sub_ns);

static bool is_nic_rx_ns(enum xsc_flow_namespace_type type)
{
	switch (type) {
	case XSC_FLOW_NAMESPACE_BYPASS:
	case XSC_FLOW_NAMESPACE_LAG:
	case XSC_FLOW_NAMESPACE_OFFLOADS:
		return true;
	default:
		return false;
	}
}

struct xsc_flow_namespace *xsc_get_flow_namespace(struct xsc_core_device *dev,
						  enum xsc_flow_namespace_type type)
{
	struct xsc_flow_steering *steering = dev->priv.steering;
	struct xsc_flow_root_namespace *root_ns;
	int prio = 0;
	struct fs_prio *fs_prio;
	struct xsc_flow_namespace *ns;

	if (!steering)
		return NULL;

	switch (type) {
	case XSC_FLOW_NAMESPACE_FDB:
		if (steering->fdb_root_ns)
			return &steering->fdb_root_ns->ns;
		return NULL;
	case XSC_FLOW_NAMESPACE_FDB_BYPASS:
		root_ns = steering->fdb_root_ns;
		prio = FDB_BYPASS_PATH;
		break;
	default: /* Must be NIC RX */
		WARN_ON(!is_nic_rx_ns(type));
		root_ns = steering->root_ns;
		prio = type;
		break;
	}

	if (!root_ns)
		return NULL;

	fs_prio = find_prio(&root_ns->ns, prio);
	if (!fs_prio)
		return NULL;

	ns = list_first_entry(&fs_prio->node.children,
			      typeof(*ns),
			      node.list);

	return ns;
}
EXPORT_SYMBOL(xsc_get_flow_namespace);

static struct fs_prio *_fs_create_prio(struct xsc_flow_namespace *ns,
				       unsigned int prio,
				       int num_levels,
				       enum fs_node_type type)
{
	struct fs_prio *fs_prio;

	fs_prio = kzalloc(sizeof(*fs_prio), GFP_KERNEL);
	if (!fs_prio)
		return ERR_PTR(-ENOMEM);

	fs_prio->node.type = type;
	tree_init_node(&fs_prio->node, NULL, del_sw_prio);
	tree_add_node(&fs_prio->node, &ns->node);
	fs_prio->num_levels = num_levels;
	fs_prio->prio = prio;
	list_add_tail(&fs_prio->node.list, &ns->node.children);

	return fs_prio;
}

static struct fs_prio *fs_create_prio_chained(struct xsc_flow_namespace *ns,
					      unsigned int prio,
					      int num_levels)
{
	return _fs_create_prio(ns, prio, num_levels, FS_TYPE_PRIO_CHAINS);
}

static struct fs_prio *fs_create_prio(struct xsc_flow_namespace *ns,
				      unsigned int prio, int num_levels)
{
	return _fs_create_prio(ns, prio, num_levels, FS_TYPE_PRIO);
}

static struct xsc_flow_namespace *fs_init_namespace(struct xsc_flow_namespace
						     *ns)
{
	ns->node.type = FS_TYPE_NAMESPACE;

	return ns;
}

static struct xsc_flow_namespace *fs_create_namespace(struct fs_prio *prio,
						      int def_miss_act)
{
	struct xsc_flow_namespace *ns;

	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);

	fs_init_namespace(ns);
	ns->def_miss_action = def_miss_act;
	tree_init_node(&ns->node, NULL, del_sw_ns);
	tree_add_node(&ns->node, &prio->node);
	list_add_tail(&ns->node.list, &prio->node.children);

	return ns;
}

static int create_leaf_prios(struct xsc_flow_namespace *ns, int prio,
			     struct init_tree_node *prio_metadata)
{
	struct fs_prio *fs_prio;
	int i;

	for (i = 0; i < prio_metadata->num_leaf_prios; i++) {
		fs_prio = fs_create_prio(ns, prio++, prio_metadata->num_levels);
		if (IS_ERR(fs_prio))
			return PTR_ERR(fs_prio);
	}
	return 0;
}

static int init_root_tree_recursive(struct xsc_flow_steering *steering,
				    struct init_tree_node *init_node,
				    struct fs_node *fs_parent_node,
				    struct init_tree_node *init_parent_node,
				    int prio)
{
	int max_ft_level = ROOT_NS_FT_MAX_LEVEL;
	struct xsc_flow_namespace *fs_ns;
	struct fs_prio *fs_prio;
	struct fs_node *base;
	int i;
	int err;

	if (init_node->type == FS_TYPE_PRIO) {
		if (init_node->min_ft_level > max_ft_level)
			return 0;

		fs_get_obj(fs_ns, fs_parent_node);
		if (init_node->num_leaf_prios)
			return create_leaf_prios(fs_ns, prio, init_node);
		fs_prio = fs_create_prio(fs_ns, prio, init_node->num_levels);
		if (IS_ERR(fs_prio))
			return PTR_ERR(fs_prio);
		base = &fs_prio->node;
	} else if (init_node->type == FS_TYPE_NAMESPACE) {
		fs_get_obj(fs_prio, fs_parent_node);
		fs_ns = fs_create_namespace(fs_prio, init_node->def_miss_action);
		if (IS_ERR(fs_ns))
			return PTR_ERR(fs_ns);
		base = &fs_ns->node;
	} else {
		return -EINVAL;
	}
	prio = 0;
	for (i = 0; i < init_node->ar_size; i++) {
		err = init_root_tree_recursive(steering, &init_node->children[i],
					       base, init_node, prio);
		if (err)
			return err;
		if (init_node->children[i].type == FS_TYPE_PRIO &&
		    init_node->children[i].num_leaf_prios) {
			prio += init_node->children[i].num_leaf_prios;
		}
	}

	return 0;
}

static int init_root_tree(struct xsc_flow_steering *steering,
			  struct init_tree_node *init_node,
			  struct fs_node *fs_parent_node)
{
	int err;
	int i;

	for (i = 0; i < init_node->ar_size; i++) {
		err = init_root_tree_recursive(steering, &init_node->children[i],
					       fs_parent_node,
					       init_node, i);
		if (err)
			return err;
	}
	return 0;
}

static void del_sw_root_ns(struct fs_node *node)
{
	struct xsc_flow_root_namespace *root_ns;
	struct xsc_flow_namespace *ns;

	fs_get_obj(ns, node);
	root_ns = container_of(ns, struct xsc_flow_root_namespace, ns);
	mutex_destroy(&root_ns->chain_lock);
	kfree(node);
}

static struct xsc_flow_root_namespace
*create_root_ns(struct xsc_flow_steering *steering,
		enum fs_flow_table_type table_type)
{
	const struct xsc_flow_cmds *cmds = xsc_fs_cmd_get_default(table_type);
	struct xsc_flow_root_namespace *root_ns;
	struct xsc_flow_namespace *ns;

	/* Create the root namespace */
	root_ns = kzalloc(sizeof(*root_ns), GFP_KERNEL);
	if (!root_ns)
		return NULL;

	root_ns->dev = steering->dev;
	root_ns->table_type = table_type;
	root_ns->cmds = cmds;

	INIT_LIST_HEAD(&root_ns->underlay_qpns);

	ns = &root_ns->ns;
	fs_init_namespace(ns);
	mutex_init(&root_ns->chain_lock);
	tree_init_node(&ns->node, NULL, del_sw_root_ns);
	tree_add_node(&ns->node, NULL);

	return root_ns;
}

static void set_prio_attrs_in_prio(struct fs_prio *prio, int acc_level);

static int set_prio_attrs_in_ns(struct xsc_flow_namespace *ns, int acc_level)
{
	struct fs_prio *prio;

	fs_for_each_prio(prio, ns) {
		 /* This updates prio start_level and num_levels */
		set_prio_attrs_in_prio(prio, acc_level);
		acc_level += prio->num_levels;
	}
	return acc_level;
}

static void set_prio_attrs_in_prio(struct fs_prio *prio, int acc_level)
{
	struct xsc_flow_namespace *ns;
	int acc_level_ns = acc_level;

	prio->start_level = acc_level;
	fs_for_each_ns(ns, prio) {
		/* This updates start_level and num_levels of ns's priority descendants */
		acc_level_ns = set_prio_attrs_in_ns(ns, acc_level);

		/* If this a prio with chains, and we can jump from one chain
		 * (namespace) to another, so we accumulate the levels
		 */
		if (prio->node.type == FS_TYPE_PRIO_CHAINS)
			acc_level = acc_level_ns;
	}

	if (!prio->num_levels)
		prio->num_levels = acc_level_ns - prio->start_level;
	WARN_ON(prio->num_levels < acc_level_ns - prio->start_level);
}

static void set_prio_attrs(struct xsc_flow_root_namespace *root_ns)
{
	struct xsc_flow_namespace *ns = &root_ns->ns;
	struct fs_prio *prio;
	int start_level = 0;

	fs_for_each_prio(prio, ns) {
		set_prio_attrs_in_prio(prio, start_level);
		start_level += prio->num_levels;
	}
}

static int init_root_ns(struct xsc_flow_steering *steering)
{
	int err;

	steering->root_ns = create_root_ns(steering, FS_FT_NIC_RX);
	if (!steering->root_ns)
		return -ENOMEM;

	err = init_root_tree(steering, &root_fs, &steering->root_ns->ns.node);
	if (err)
		goto out_err;

	set_prio_attrs(steering->root_ns);

	return 0;

out_err:
	cleanup_root_ns(steering->root_ns);
	steering->root_ns = NULL;
	return err;
}

static void clean_tree(struct fs_node *node)
{
	if (node) {
		struct fs_node *iter;
		struct fs_node *temp;

		tree_get_node(node);
		list_for_each_entry_safe(iter, temp, &node->children, list)
			clean_tree(iter);
		tree_put_node(node, false);
		tree_remove_node(node, false);
	}
}

static void cleanup_root_ns(struct xsc_flow_root_namespace *root_ns)
{
	if (!root_ns)
		return;

	clean_tree(&root_ns->ns.node);
}

/* FT and tc chains are stored in the same array so we can re-use the
 * xsc_get_fdb_sub_ns() and tc api for FT chains.
 * When creating a new ns for each chain store it in the first available slot.
 * Assume tc chains are created and stored first and only then the FT chain.
 */
static void store_fdb_sub_ns_prio_chain(struct xsc_flow_steering *steering,
					struct xsc_flow_namespace *ns)
{
	int chain = 0;

	while (steering->fdb_sub_ns[chain])
		++chain;

	steering->fdb_sub_ns[chain] = ns;
}

static int create_fdb_sub_ns_prio_chain(struct xsc_flow_steering *steering,
					struct fs_prio *maj_prio)
{
	struct xsc_flow_namespace *ns;
	struct fs_prio *min_prio;
	int prio;

	ns = fs_create_namespace(maj_prio, XSC_FLOW_TABLE_MISS_ACTION_DEF);
	if (IS_ERR(ns))
		return PTR_ERR(ns);

	for (prio = 0; prio < FDB_TC_MAX_PRIO; prio++) {
		min_prio = fs_create_prio(ns, prio, FDB_TC_LEVELS_PER_PRIO);
		if (IS_ERR(min_prio))
			return PTR_ERR(min_prio);
	}

	store_fdb_sub_ns_prio_chain(steering, ns);

	return 0;
}

static int create_fdb_chains(struct xsc_flow_steering *steering,
			     int fs_prio, int chains)
{
	struct fs_prio *maj_prio;
	int levels;
	int chain;
	int err;

	levels = FDB_TC_LEVELS_PER_PRIO * FDB_TC_MAX_PRIO * chains;
	maj_prio = fs_create_prio_chained(&steering->fdb_root_ns->ns,
					  fs_prio, levels);
	if (IS_ERR(maj_prio))
		return PTR_ERR(maj_prio);

	for (chain = 0; chain < chains; chain++) {
		err = create_fdb_sub_ns_prio_chain(steering, maj_prio);
		if (err)
			return err;
	}

	return 0;
}

static int create_fdb_fast_path(struct xsc_flow_steering *steering)
{
	int err;

	steering->fdb_sub_ns = kcalloc(FDB_NUM_CHAINS,
				       sizeof(*steering->fdb_sub_ns),
				       GFP_KERNEL);
	if (!steering->fdb_sub_ns)
		return -ENOMEM;

	err = create_fdb_chains(steering, FDB_TC_OFFLOAD, FDB_TC_MAX_CHAIN + 1);
	if (err)
		return err;

	err = create_fdb_chains(steering, FDB_FT_OFFLOAD, 1);
	if (err)
		return err;

	return 0;
}

static int create_fdb_bypass(struct xsc_flow_steering *steering)
{
	struct xsc_flow_namespace *ns;
	struct fs_prio *prio;
	int i;

	prio = fs_create_prio(&steering->fdb_root_ns->ns, FDB_BYPASS_PATH, 0);
	if (IS_ERR(prio))
		return PTR_ERR(prio);

	ns = fs_create_namespace(prio, XSC_FLOW_TABLE_MISS_ACTION_DEF);
	if (IS_ERR(ns))
		return PTR_ERR(ns);

	for (i = 0; i < XSC_BY_PASS_NUM_REGULAR_PRIOS; i++) {
		prio = fs_create_prio(ns, i, 1);
		if (IS_ERR(prio))
			return PTR_ERR(prio);
	}

	return 0;
}

static void cleanup_fdb_root_ns(struct xsc_flow_steering *steering, bool clean_fc)
{
	cleanup_root_ns(steering->fdb_root_ns);
	steering->fdb_root_ns = NULL;
	kfree(steering->fdb_sub_ns);
	steering->fdb_sub_ns = NULL;
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	if (clean_fc)
		xsc_cleanup_fc_stats(steering->dev);
#endif
}

static int init_fdb_root_ns(struct xsc_flow_steering *steering)
{
	struct fs_prio *maj_prio;
	int err;

	steering->fdb_root_ns = create_root_ns(steering, FS_FT_FDB);
	if (!steering->fdb_root_ns)
		return -ENOMEM;

	err = xsc_fs_get_capabilities(steering->dev, XSC_FLOW_NAMESPACE_FDB);
	if (err)
		goto err;

	err = create_fdb_bypass(steering);
	if (err)
		goto out_err;

	err = create_fdb_fast_path(steering);
	if (err)
		goto out_err;

	maj_prio = fs_create_prio(&steering->fdb_root_ns->ns, FDB_TC_MISS, 1);
	if (IS_ERR(maj_prio)) {
		err = PTR_ERR(maj_prio);
		goto out_err;
	}

#ifdef CONFIG_XSC_OFFLOAD_METER
	maj_prio = fs_create_prio(&steering->fdb_root_ns->ns, FDB_MISS_METER, 2);
	if (IS_ERR(maj_prio)) {
		err = PTR_ERR(maj_prio);
		goto out_err;
	}
#endif

#ifdef CONFIG_XSC_OFFLOAD_OVS
	maj_prio = fs_create_prio(&steering->fdb_root_ns->ns, FDB_BR_OFFLOAD, 4);
	if (IS_ERR(maj_prio)) {
		err = PTR_ERR(maj_prio);
		goto out_err;
	}
#endif

#ifdef CONFIG_XSC_OFFLOAD_TUN
	maj_prio = fs_create_prio(&steering->fdb_root_ns->ns, FDB_SLOW_PATH, 1);
	if (IS_ERR(maj_prio)) {
		err = PTR_ERR(maj_prio);
		goto out_err;
	}
#endif

#ifdef CONFIG_XSC_OFFLOAD_TUN
	/* We put this priority last, knowing that nothing will get here
	 * unless explicitly forwarded to. This is possible because the
	 * slow path tables have catch all rules and nothing gets passed
	 * those tables.
	 */
	maj_prio = fs_create_prio(&steering->fdb_root_ns->ns, FDB_PER_VPORT, 1);
	if (IS_ERR(maj_prio)) {
		err = PTR_ERR(maj_prio);
		goto out_err;
	}
#endif

	set_prio_attrs(steering->fdb_root_ns);

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	err = xsc_init_fc_stats(steering->dev);
	if (err)
		goto out_err;
#endif
	return 0;

out_err:
	cleanup_fdb_root_ns(steering, false);
err:
	return err;
}

u32 xsc_fs_get_capabilities(struct xsc_core_device *dev, enum xsc_flow_namespace_type type)
{
	struct xsc_flow_root_namespace *root;
	struct xsc_flow_namespace *ns;

	ns = xsc_get_flow_namespace(dev, type);
	if (!ns)
		return 0;

	root = find_root(&ns->node);
	if (!root)
		return 0;

	return root->cmds->get_capabilities(root->dev, root->table_type);
}

void xsc_fs_core_cleanup(struct xsc_core_device *dev)
{
	struct xsc_flow_steering *steering;

	if (!is_support_tc_offload(dev))
		return;

	steering = dev->priv.steering;

	cleanup_root_ns(steering->root_ns);
	cleanup_fdb_root_ns(steering, true);
}

int xsc_fs_core_init(struct xsc_core_device *dev)
{
	struct xsc_flow_steering *steering = dev->priv.steering;
	int err;

	if (!is_support_tc_offload(dev))
		return 0;

	if (dev->caps.ft_support & BIT(FS_FT_NIC_RX)) {
		err = init_root_ns(steering);
		if (err)
			goto err;
	}

	if (XSC_ESWITCH_MANAGER(dev) &&
	    (dev->caps.ft_support & BIT(FS_FT_FDB))) {
		err = init_fdb_root_ns(steering);
		if (err)
			goto err_root_ns;
	}

	return 0;

err_root_ns:
	cleanup_root_ns(steering->root_ns);
err:
	return err;
}

void xsc_fs_core_free(struct xsc_core_device *dev)
{
	struct xsc_flow_steering *steering;

	if (!is_support_tc_offload(dev))
		return;

	steering = dev->priv.steering;

	kmem_cache_destroy(steering->ftes_cache);
	kmem_cache_destroy(steering->fgs_cache);
	kfree(steering);
	xsc_ft_pool_destroy(dev);
}

int xsc_fs_core_alloc(struct xsc_core_device *dev)
{
	struct xsc_flow_steering *steering;
	int err = 0;

	if (!is_support_tc_offload(dev))
		return 0;

	err = xsc_ft_pool_init(dev);
	if (err)
		goto err;

	steering = kzalloc(sizeof(*steering), GFP_KERNEL);
	if (!steering) {
		err = -ENOMEM;
		goto err;
	}

	steering->dev = dev;
	dev->priv.steering = steering;
	steering->mode = XSC_FLOW_STEERING_MODE_SMFS;

	steering->fgs_cache = kmem_cache_create("xsc_fs_fgs",
						sizeof(struct xsc_flow_group), 0,
						0, NULL);
	steering->ftes_cache = kmem_cache_create("xsc_fs_ftes", sizeof(struct fs_fte), 0,
						 0, NULL);
	if (!steering->ftes_cache || !steering->fgs_cache) {
		err = -ENOMEM;
		goto err;
	}

	return 0;

err:
	xsc_fs_core_free(dev);
	return err;
}

int xsc_fs_add_rx_underlay_qpn(struct xsc_core_device *dev, u32 underlay_qpn)
{
	struct xsc_flow_root_namespace *root = dev->priv.steering->root_ns;
	struct xsc_ft_underlay_qp *new_uqp;
	int err = 0;

	new_uqp = kzalloc(sizeof(*new_uqp), GFP_KERNEL);
	if (!new_uqp)
		return -ENOMEM;

	mutex_lock(&root->chain_lock);

	if (!root->root_ft) {
		err = -EINVAL;
		goto update_ft_fail;
	}

	err = root->cmds->update_root_ft(root->dev, root->root_ft, underlay_qpn,
					 false);
	if (err) {
		xsc_core_warn(dev, "Failed adding underlay QPN (%u) to root FT err(%d)\n",
			      underlay_qpn, err);
		goto update_ft_fail;
	}

	new_uqp->qpn = underlay_qpn;
	list_add_tail(&new_uqp->list, &root->underlay_qpns);

	mutex_unlock(&root->chain_lock);

	return 0;

update_ft_fail:
	mutex_unlock(&root->chain_lock);
	kfree(new_uqp);
	return err;
}
EXPORT_SYMBOL(xsc_fs_add_rx_underlay_qpn);

int xsc_fs_remove_rx_underlay_qpn(struct xsc_core_device *dev, u32 underlay_qpn)
{
	struct xsc_flow_root_namespace *root = dev->priv.steering->root_ns;
	struct xsc_ft_underlay_qp *uqp;
	bool found = false;
	int err = 0;

	mutex_lock(&root->chain_lock);
	list_for_each_entry(uqp, &root->underlay_qpns, list) {
		if (uqp->qpn == underlay_qpn) {
			found = true;
			break;
		}
	}

	if (!found) {
		xsc_core_warn(dev, "Failed finding underlay qp (%u) in qpn list\n",
			      underlay_qpn);
		err = -EINVAL;
		goto out;
	}

	err = root->cmds->update_root_ft(root->dev, root->root_ft, underlay_qpn,
					 true);
	if (err)
		xsc_core_warn(dev, "Failed removing underlay QPN (%u) from root FT err(%d)\n",
			      underlay_qpn, err);

	list_del(&uqp->list);
	mutex_unlock(&root->chain_lock);
	kfree(uqp);

	return 0;

out:
	mutex_unlock(&root->chain_lock);
	return err;
}
EXPORT_SYMBOL(xsc_fs_remove_rx_underlay_qpn);

static struct xsc_flow_root_namespace
*get_root_namespace(struct xsc_core_device *dev, enum xsc_flow_namespace_type ns_type)
{
	struct xsc_flow_namespace *ns;

	ns = xsc_get_flow_namespace(dev, ns_type);
	if (!ns)
		return NULL;

	return find_root(&ns->node);
}

struct xsc_modify_hdr *xsc_modify_header_alloc(struct xsc_core_device *dev,
					       u8 ns_type, u8 num_actions,
					       void *modify_actions)
{
	struct xsc_flow_root_namespace *root;
	struct xsc_modify_hdr *modify_hdr;
	int err;

	root = get_root_namespace(dev, ns_type);
	if (!root) {
		esw_warn(dev, "root namespace %d not exist\n", ns_type);
		return ERR_PTR(-EOPNOTSUPP);
	}

	modify_hdr = kzalloc(sizeof(*modify_hdr), GFP_KERNEL);
	if (!modify_hdr)
		return ERR_PTR(-ENOMEM);

	modify_hdr->ns_type = ns_type;
	err = root->cmds->modify_header_alloc(root->dev, ns_type, num_actions,
					      modify_actions, modify_hdr);
	if (err) {
		kfree(modify_hdr);
		return ERR_PTR(err);
	}

	return modify_hdr;
}
EXPORT_SYMBOL(xsc_modify_header_alloc);

void xsc_modify_header_dealloc(struct xsc_core_device *dev,
			       struct xsc_modify_hdr *modify_hdr)
{
	struct xsc_flow_root_namespace *root;

	root = get_root_namespace(dev, modify_hdr->ns_type);
	if (WARN_ON(!root))
		return;
	root->cmds->modify_header_dealloc(root->dev, modify_hdr);
	kfree(modify_hdr);
}
EXPORT_SYMBOL(xsc_modify_header_dealloc);

struct xsc_pkt_reformat *xsc_packet_reformat_alloc(struct xsc_core_device *dev,
						   struct xsc_pkt_reformat_params *params,
						   enum xsc_flow_namespace_type ns_type)
{
	struct xsc_pkt_reformat *pkt_reformat;
	struct xsc_flow_root_namespace *root;
	int err;

	root = get_root_namespace(dev, ns_type);
	if (!root)
		return ERR_PTR(-EOPNOTSUPP);

	pkt_reformat = kzalloc(sizeof(*pkt_reformat), GFP_KERNEL);
	if (!pkt_reformat)
		return ERR_PTR(-ENOMEM);

	pkt_reformat->ns_type = ns_type;
	pkt_reformat->reformat_type = params->type;
	err = root->cmds->packet_reformat_alloc(root->dev, params, ns_type,
						pkt_reformat);
	if (err) {
		kfree(pkt_reformat);
		return ERR_PTR(err);
	}

	return pkt_reformat;
}
EXPORT_SYMBOL(xsc_packet_reformat_alloc);

void xsc_packet_reformat_dealloc(struct xsc_core_device *dev,
				 struct xsc_pkt_reformat *pkt_reformat)
{
	struct xsc_flow_root_namespace *root;

	root = get_root_namespace(dev, pkt_reformat->ns_type);
	if (WARN_ON(!root))
		return;
	root->cmds->packet_reformat_dealloc(root->dev, pkt_reformat);
	kfree(pkt_reformat);
}
EXPORT_SYMBOL(xsc_packet_reformat_dealloc);

int xsc_flow_namespace_set_peer(struct xsc_flow_root_namespace *ns,
				struct xsc_flow_root_namespace *peer_ns,
				u16 peer_vhca_id)
{
	if (peer_ns && ns->mode != peer_ns->mode) {
		xsc_core_err(ns->dev,
			     "Can't peer namespace of different steering mode\n");
		return -EINVAL;
	}

	return ns->cmds->set_peer(ns, peer_ns, peer_vhca_id);
}

/* This function should be called only at init stage of the namespace.
 * It is not safe to call this function while steering operations
 * are executed in the namespace.
 */
int xsc_flow_namespace_set_mode(struct xsc_flow_namespace *ns,
				enum xsc_flow_steering_mode mode)
{
	struct xsc_flow_root_namespace *root;
	const struct xsc_flow_cmds *cmds = NULL;
	int err;

	root = find_root(&ns->node);
	if (&root->ns != ns)
	/* Can't set cmds to non root namespace */
		return -EINVAL;

	if (root->table_type != FS_FT_FDB)
		return -EOPNOTSUPP;

	if (root->mode == mode)
		return 0;

	if (mode == XSC_FLOW_STEERING_MODE_SMFS)
		cmds = xsc_fs_cmd_get_fw_cmds();
	if (!cmds)
		return -EOPNOTSUPP;

	err = cmds->create_ns(root);
	if (err) {
		xsc_core_err(root->dev,
			     "Failed to create flow namespace (%d)\n", err);
		return err;
	}

	root->cmds->destroy_ns(root);
	root->cmds = cmds;
	root->mode = mode;

	return 0;
}
