// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_type.h"
#include "nse_sched.h"
#include "nse_sched_aqc.h"
#include "nse_switch.h"

#include "nse_sched_internal.h"

static bool is_forward_twin(u32 prev_tnid, u32 next_tnid)
{
	if (prev_tnid & 0x1)		/* not node-0 in SE */
		return false;

	if (!(next_tnid & 0x1))		/* not node-1 in SE */
		return false;

	if ((prev_tnid + 1) != next_tnid)	/* not twins in same SE */
		return false;

	return true;
}

/* lockless, caller must acquire sched_lock
 */
struct nse_sched_node *
nse_sched_find_node_by_tnid(struct nse_sched_node *start_node, u32 tnid)
{
	struct nse_hw *hw = (struct nse_hw *)start_node->hw;
	struct nse_sched_info *si = &hw->port_info->sched_info;
	struct nse_sched_node *cur = NULL;

	/* The TNID is same as that of the start_node */
	if (NSE_TXSCHED_GET_NODE_TNID(start_node) == tnid)
		return start_node;

	/* The node has no children or is at the max layer */
	if (!start_node->num_children ||
	    start_node->layer_id >= si->layers_num ||
	    start_node->layer_id == si->layer_id_leaf)
		return NULL;

	/* Check if TNID matches to any of the children nodes */
	list_for_each_entry(cur, &start_node->direct_children_list, direct_sibling) {
		if (NSE_TXSCHED_GET_NODE_TNID(cur) == tnid)
			return cur;
	}

	/* Search within each child's sub-tree */
	list_for_each_entry(cur, &start_node->direct_children_list, direct_sibling) {
		struct nse_sched_node *tmp;

		tmp = nse_sched_find_node_by_tnid(cur, tnid);
		if (tmp)
			return tmp;
	}

	return NULL;
}

struct nse_sched_node *nse_sched_get_node(struct nse_port_info *pi, u32 tnid)
{
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *node;

	if (!pi)
		return NULL;

	/* Find the node starting from root */
	mutex_lock(&si->sched_lock);
	node = nse_sched_find_node_by_tnid(si->root, tnid);
	mutex_unlock(&si->sched_lock);

	if (!node)
		nse_debug(pi->hw, NSE_DBG_SCHED, "Node not found for tnid=0x%x\n", tnid);

	return node;
}

/**
 * nse_sched_get_first_node - get the first node of the given layer
 * @pi: port information structure
 * @parent: pointer the base node of the subtree
 * @layer: layer number
 *
 * This function retrieves the first node of the given layer from the subtree
 */
static struct nse_sched_node *
nse_sched_get_first_node(struct nse_port_info *pi,
			 struct nse_sched_node *parent, u8 layer)
{
	struct nse_sched_info *si = &pi->sched_info;

	return si->layer_sibling_head[parent->tc_num][layer];
}

/**
 * nse_sched_get_tc_node - get pointer to TC node
 * @pi: port information structure
 * @tc: TC number
 *
 * This function returns the TC node pointer
 */
struct nse_sched_node *nse_sched_get_tc_node(struct nse_port_info *pi, u8 tc)
{
	struct nse_sched_info *si = &pi->sched_info;

	if (!si->root)
		return NULL;

	return si->tc_nodes[tc];
}

/**
 * nse_sched_get_vsi_layer - get the current VSI layer number
 * @hw: pointer to the HW struct
 *
 * This function returns the current VSI layer number
 */
static u8 nse_sched_get_vsi_layer(struct nse_hw *hw)
{
	struct nse_sched_info *si = &hw->port_info->sched_info;

	return si->layer_id_vsi;
}

/**
 * nse_sched_get_qgrp_layer - get the current queue group layer number
 * @hw: pointer to the HW struct
 *
 * This function returns the current queue group layer number
 */
static u8 nse_sched_get_qgrp_layer(struct nse_hw *hw)
{
	struct nse_sched_info *si = &hw->port_info->sched_info;

	return si->layer_id_qgrp;
}

/**
 * nse_sched_get_vsi_node - Get a VSI node based on VSI ID
 * @pi: pointer to the port information structure
 * @tc_node: pointer to the TC node
 * @vsi_handle: software VSI handle
 *
 * This function retrieves a VSI node for a given VSI ID from a given
 * TC branch
 */
struct nse_sched_node *
nse_sched_get_vsi_node(struct nse_port_info *pi, struct nse_sched_node *tc_node,
		       u16 vsi_handle)
{
	struct nse_sched_node *node;
	u8 vsi_layer;

	vsi_layer = nse_sched_get_vsi_layer(pi->hw);
	node = nse_sched_get_first_node(pi, tc_node, vsi_layer);

	/* Check whether it already exists */
	while (node) {
		if (node->vsi_handle == vsi_handle)
			return node;
		node = node->layer_sibling;
	}

	return node;
}

/**
 * nse_sched_find_node_in_subtree - Find node in part of base node subtree
 * @hw: pointer to the HW struct
 * @base: pointer to the base node
 * @node: pointer to the node to search
 *
 * This function checks whether a given node is part of the base node
 * subtree or not
 */
bool
nse_sched_find_node_in_subtree(struct nse_hw *hw, struct nse_sched_node *base,
			       struct nse_sched_node *node)
{
	struct nse_sched_node *child = NULL;

	list_for_each_entry(child, &base->direct_children_list, direct_sibling) {
		if (child == node)
			return true;

		if (child->layer_id > node->layer_id)
			return false;

		if (nse_sched_find_node_in_subtree(hw, child, node))
			return true;
	}

	return false;
}

/**
 * nse_sched_get_free_qparent - Get a free LAN or RDMA queue group node
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc: branch number
 * @owner: LAN or RDMA
 *
 * This function retrieves a free LAN or RDMA queue group node
 */
struct nse_sched_node *
nse_sched_get_free_qparent(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
			   u8 owner)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *vsi_node, *qgrp_node;
	struct nse_vsi_ctx *vsi_ctx;
	u8 qgrp_layer, vsi_layer;
	u16 max_children;

	qgrp_layer = nse_sched_get_qgrp_layer(hw);
	vsi_layer = nse_sched_get_vsi_layer(hw);
	max_children = si->max_children[qgrp_layer];

	vsi_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi_ctx)
		return NULL;
	vsi_node = vsi_ctx->sched.vsi_node[tc];
	/* validate invalid VSI ID */
	if (!vsi_node)
		return NULL;

	/* If the queue group and vsi layer are same then queues
	 * are all attached directly to VSI
	 */
	if (qgrp_layer == vsi_layer)
		return vsi_node;

	/* get the first queue group node from VSI sub-tree */
	qgrp_node = nse_sched_get_first_node(pi, vsi_node, qgrp_layer);
	while (qgrp_node) {
		/* make sure the qgroup node is part of the VSI subtree */
		if (nse_sched_find_node_in_subtree(pi->hw, vsi_node, qgrp_node))
			if (qgrp_node->num_children < max_children &&
			    qgrp_node->owner == owner)
				break;
		qgrp_node = qgrp_node->layer_sibling;
	}

	return qgrp_node;
}

void nse_sched_fill_cmd_data_add_node_one(struct nse_port_info *pi,
				struct nse_aqc_qos_sch_add_node_one *cmd_data,
				struct nse_sched_node *parent,
				struct nse_sched_node **prev_sibling_pptr,
				struct nse_sched_node **next_sibling_pptr,
				bool is_leaf, u16 qid, u16 qid_type)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_node *prev_sibling = NULL, *next_sibling = NULL, *cur = NULL;
	bool exist_free_twin = false;
	u32 new_child_tnid = 0;
	u32 leaf_node_qid;

	memset(cmd_data, 0, sizeof(*cmd_data));

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	/**********************
	 *
	 * determine if can allocate a free twin-node of an existing node
	 *
	 **********************/

	if (!parent->num_children) {
		exist_free_twin = false;
		prev_sibling = NULL;
		next_sibling = NULL;
	} else {
		list_for_each_entry(cur, &parent->direct_children_list, direct_sibling) {
			prev_sibling = NULL;
			next_sibling = NULL;

			if (!(cur->tnid & 0x1)) {
				if (list_is_last(&cur->direct_sibling,
				    &parent->direct_children_list)) {
					exist_free_twin = true;

					new_child_tnid = cur->tnid + 1;		/* my twin-node-1 */

					/* new_child have prev_sibling, that is me as twin-node-0 */
					prev_sibling = cur;
					next_sibling = NULL;	/* new_child have no next_sibling */

					break;
				}

				next_sibling = list_next_entry(cur, direct_sibling);

				if (next_sibling->tnid != (cur->tnid + 1)) {
					exist_free_twin = true;

					/* my twin-node-1 */
					new_child_tnid = cur->tnid + 1;

					/*  new_child would have prev_sibling, that is me as
					 * twin-node-0
					 */
					prev_sibling = cur;

					/* new_child would grab my next_sibling */

					break;
				}

				exist_free_twin = false;
			} else {
				if (list_is_first(&cur->direct_sibling,
				    &parent->direct_children_list)) {
					exist_free_twin = true;

					new_child_tnid = cur->tnid - 1;		/* my twin-node-0 */

					prev_sibling = NULL;	/* new_child have no prev_sibling */
					/* new_child have next_silbing, that is me as twin-node-1 */
					next_sibling = cur;

					break;
				}

				prev_sibling = list_prev_entry(cur, direct_sibling);

				if (prev_sibling->tnid != (cur->tnid - 1)) {
					exist_free_twin = true;
					/* my twin-node-0 */
					new_child_tnid = cur->tnid - 1;

					/* new_child would grab my prev_sibling
					 * new_child have next_silbing, that is me as
					 * twin-node-1
					 */
					next_sibling = cur;

					break;
				}

				exist_free_twin = false;
			}
		}
	}

	/**********************
	 *
	 * fill in aq-cmd buff
	 *
	 **********************/
	cmd_data->parent_tnid = cpu_to_le32(parent->tnid);
	cmd_data->parent_suid = cpu_to_le32(parent->suid);
	cmd_data->parent_logic_idx_in_su = cpu_to_le32(parent->logic_idx_in_su);

	if (exist_free_twin) {
		cmd_data->flags |= cpu_to_le32(ADD_NODE_ONE_FLAG_SUGGEST_CHILD_TNID);
		cmd_data->new_child_tnid = cpu_to_le32(new_child_tnid);

		if (prev_sibling) {
			cmd_data->flags |= cpu_to_le32(ADD_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID);
			cmd_data->prev_sibling_tnid = cpu_to_le32(prev_sibling->tnid);
		}

		if (next_sibling) {
			cmd_data->flags |= cpu_to_le32(ADD_NODE_ONE_FLAG_SUGGEST_NEXT_SIBLING_TNID);
			cmd_data->next_sibling_tnid = cpu_to_le32(next_sibling->tnid);
		}
	} else {
		if (parent->num_children) {
			prev_sibling = list_last_entry(&parent->direct_children_list,
						       struct nse_sched_node, direct_sibling);

			cmd_data->flags |= cpu_to_le32(ADD_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID);
			cmd_data->prev_sibling_tnid = cpu_to_le32(prev_sibling->tnid);

			next_sibling = NULL;
		} else {
			prev_sibling = NULL;

			next_sibling = NULL;

			/* not set flags: SUGGEST_PREV_SIBLING_TNID and SUGGEST_NEXT_SIBLING_TNID */
		}
	}

	if (is_leaf) {
		cmd_data->flags |= cpu_to_le32(ADD_NODE_ONE_FLAG_LEAF);

		if (qid_type == QID_TYPE_RDMA_QSET)
			leaf_node_qid = BIT(10) + qid;
		else
			leaf_node_qid = qid;

		cmd_data->leaf_node_qid = cpu_to_le32(leaf_node_qid);
	}

	*prev_sibling_pptr = prev_sibling;
	*next_sibling_pptr = next_sibling;
}

/* runtime version of link_initial_parent_child(), more complicated */
static void link_parent_child(struct nse_sched_node *parent,
							struct nse_sched_node *child,
							struct nse_sched_node *prev_sibling,
			      struct nse_sched_node __always_unused *next_sibling)
{
	struct nse_sched_node *n;
	u32 suid = 0;

	child->parent = parent;
	parent->num_children++;

	if (!prev_sibling) {	/* new_child is new big_brother */

		list_add(&child->direct_sibling, &parent->direct_children_list);
	} else {					/* add after prev_sibling */

		list_add(&child->direct_sibling, &prev_sibling->direct_sibling);
	}

	/* current big-brother. might be newly added child
	 *
	 * get its SU.
	 */
	n = list_first_entry(&parent->direct_children_list,
						struct nse_sched_node, direct_sibling);

	suid = (n->tnid >> 1);

	/* refresh each children's suid and logic_idx_in_su
	 *
	 * HW synchronization would be later in nse_sched_update_direct_children_logic_idx_in_su()
	 */

	list_for_each_entry(n, &parent->direct_children_list, direct_sibling) {
		n->old_suid = n->suid;
		n->old_logic_idx_in_su = n->logic_idx_in_su;

		n->suid = suid;

		if (n->direct_sibling.prev != &parent->direct_children_list)
			prev_sibling = list_prev_entry(n, direct_sibling);
		else
			prev_sibling = NULL;

		if (!prev_sibling) {	/* n is big_brother */
			n->logic_idx_in_su = (n->tnid & 0x1);
		} else {
			if (is_forward_twin(prev_sibling->tnid, n->tnid)) {
				n->logic_idx_in_su = prev_sibling->logic_idx_in_su + 1;
			} else {
				/* prev_sibling is node-0 in prev_SE */
				if (!(prev_sibling->tnid & 0x1)) {
					/* I am node-0 in my_SE */
					if (!(n->tnid & 0x1)) {
						n->logic_idx_in_su = prev_sibling->logic_idx_in_su +
							2;
					/* I am node-1 in my_SE */
					} else {
						n->logic_idx_in_su = prev_sibling->logic_idx_in_su +
							3;
					}
				/* prev_sibling is node-1 in prev_SE */
				} else {
					/* I am node-0 in my_SE */
					if (!(n->tnid & 0x1)) {
						n->logic_idx_in_su = prev_sibling->logic_idx_in_su +
							1;
					/* I am node-1 in my_SE */
					} else {
						n->logic_idx_in_su = prev_sibling->logic_idx_in_su +
							2;
					}
				}
			}
		}

		/* newly add child have its old = new,
		 *  because it does not have any children for now, then no need to update last
		 * children SE's NXT_PTR
		 */
		if (n == child) {
			n->old_suid = n->suid;
			n->old_logic_idx_in_su = n->logic_idx_in_su;
		}
	}
}

static void unlink_parent_child(struct nse_sched_node *parent,
							struct nse_sched_node *child)
{
	struct nse_hw *hw = (struct nse_hw *)parent->hw;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *prev_sibling = NULL;
	u32 suid = 0;

	if (child->parent != parent) {
		dev_err(dev, "[%s]: how come child(TNID=%d)->parent != parent(TNID=%d)?\n",
						__func__,
						child->tnid, parent->tnid);

		list_del_init(&child->direct_sibling);	//still unlink from list, anyway
		return;
	}

	list_del_init(&child->direct_sibling);
	parent->num_children--;

	if (!list_empty(&parent->direct_children_list)) {
		/* big_brother */
		child = list_first_entry(&parent->direct_children_list,
								struct nse_sched_node,
									direct_sibling);

		suid = (child->tnid >> 1);

		/* update SUID and logic_idx_in_su in remaining SW-node
		 *
		 *  later HW synchronization would be later in
		 * nse_sched_update_direct_children_logic_idx_in_su()
		 */
		list_for_each_entry(child, &parent->direct_children_list, direct_sibling) {
			child->old_suid = child->suid;
			child->old_logic_idx_in_su = child->logic_idx_in_su;

			child->suid = suid;

			if (child->direct_sibling.prev != &parent->direct_children_list)
				prev_sibling = list_prev_entry(child, direct_sibling);
			else
				prev_sibling = NULL;

			if (!prev_sibling) {	/* I am big_brother */
				child->logic_idx_in_su = (child->tnid & 0x1);
			} else {
				if (is_forward_twin(prev_sibling->tnid, child->tnid)) {
					child->logic_idx_in_su = prev_sibling->logic_idx_in_su + 1;
				} else {
					u32 delta;

					/* prev_sibling is the last node of the previous SE:
					 * node-0 of that SE is followed by +2/+3 depending
					 * on whether I am node-0 or node-1 of my_SE, node-1
					 * is followed by +1/+2.
					 */
					if (!(prev_sibling->tnid & 0x1))
						delta = (child->tnid & 0x1) ? 3 : 2;
					else
						delta = (child->tnid & 0x1) ? 2 : 1;

					child->logic_idx_in_su =
						prev_sibling->logic_idx_in_su + delta;
				}
			}
		}
	}
}

enum nse_status nse_sched_fill_cmd_data_del_node_one_and_unlink_sw_node(struct nse_port_info *pi,
				struct nse_aqc_qos_sch_del_node_one *cmd_data,
				struct nse_sched_node *parent,
				u32 tnid,
				struct nse_sched_node **node_pptr,
				struct nse_sched_node **prev_sibling_pptr,
				struct nse_sched_node **next_sibling_pptr,
				bool is_leaf)
{
	struct nse_hw *hw = pi->hw;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *prev_sibling = NULL, *next_sibling = NULL,
		*cur = NULL, *sib_tail_child = NULL;
	enum nse_status status = NSE_ERR_DOES_NOT_EXIST;
	u32 i = 0, flags = 0;

	*node_pptr = NULL;
	*prev_sibling_pptr = NULL;
	*next_sibling_pptr = NULL;

	memset(cmd_data, 0, sizeof(*cmd_data));

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	prev_sibling = NULL;
	next_sibling = NULL;

	if (!parent->num_children) {
		status = NSE_ERR_DOES_NOT_EXIST;
		goto out;
	} else {
		list_for_each_entry(cur, &parent->direct_children_list, direct_sibling) {
			if (cur->tnid == tnid) {
				*node_pptr = cur;

				if (!list_is_first(&cur->direct_sibling,
				    &parent->direct_children_list)) {
					prev_sibling = list_prev_entry(cur, direct_sibling);
				}

				if (!list_is_last(&cur->direct_sibling,
				    &parent->direct_children_list)) {
					next_sibling = list_next_entry(cur, direct_sibling);
				}

				goto fill_cmd_data;
			}
		}

		status = NSE_ERR_DOES_NOT_EXIST;
		goto out;
	}

fill_cmd_data:
	/**********************
	 *
	 * fill in aq-cmd buff
	 *
	 **********************/
	cmd_data->parent_tnid = cpu_to_le32(parent->tnid);
	cmd_data->parent_suid = cpu_to_le32(parent->suid);
	cmd_data->parent_logic_idx_in_su = cpu_to_le32(parent->logic_idx_in_su);

	cmd_data->child_tnid = cpu_to_le32(tnid);

	if (prev_sibling) {
		flags |= DEL_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID;
		cmd_data->prev_sibling_tnid = cpu_to_le32(prev_sibling->tnid);

		if (!is_forward_twin(prev_sibling->tnid, (*node_pptr)->tnid)) {
			flags |= DEL_NODE_ONE_FLAG_PREV_SE;
			cmd_data->prev_se = cpu_to_le32((prev_sibling->tnid >> 1));
		} else {
			if (!list_is_first(&prev_sibling->direct_sibling,
			    &parent->direct_children_list)) {
				/* prev_sibling is my forward_twin in same SE,
				 * then prev_prev_siblingwould definitely be another SE
				 */
				cur = list_prev_entry(prev_sibling, direct_sibling);

				flags |= DEL_NODE_ONE_FLAG_PREV_SE;
				cmd_data->prev_se = cpu_to_le32((cur->tnid >> 1));
			}
		}
	}

	if (next_sibling) {
		flags |= DEL_NODE_ONE_FLAG_SUGGEST_NEXT_SIBLING_TNID;
		cmd_data->next_sibling_tnid = cpu_to_le32(next_sibling->tnid);

		if (!is_forward_twin((*node_pptr)->tnid, next_sibling->tnid)) {
			flags |= DEL_NODE_ONE_FLAG_NEXT_SE;
			cmd_data->next_se = cpu_to_le32((next_sibling->tnid >> 1));
		} else {
			if (!list_is_last(&next_sibling->direct_sibling,
			    &parent->direct_children_list)) {
				/* I and next_sibling are twin in same SE,
				 * then next_next_siblingwould definitely be another SE
				 */
				cur = list_next_entry(next_sibling, direct_sibling);

				flags |= DEL_NODE_ONE_FLAG_NEXT_SE;
				cmd_data->next_se = cpu_to_le32((cur->tnid >> 1));
			}
		}
	}

	if ((*node_pptr)->tnid & 0x1) {	/* node-1 in SE */

		if (!prev_sibling || !is_forward_twin(prev_sibling->tnid, (*node_pptr)->tnid))
			flags |= DEL_NODE_ONE_FLAG_DEL_CHILD_SE;
	} else {							/* node-0 in SE */

		if (!next_sibling || !is_forward_twin((*node_pptr)->tnid, next_sibling->tnid))
			flags |= DEL_NODE_ONE_FLAG_DEL_CHILD_SE;
	}

	if (flags & DEL_NODE_ONE_FLAG_DEL_CHILD_SE) {
		if (!prev_sibling)	/* equal to: no prev_se */
			flags |= DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_HEAD;

		if (!next_sibling)	/* equal to: no next_se */
			flags |= DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_TAIL;

		if (prev_sibling && next_sibling)	/* equal to: has prev_se && has next_se */
			flags |= DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_MIDDLE;
	}

	flags |= DEL_NODE_ONE_FLAG_NEED_LOCK_PARENT_SE;

	if ((flags & DEL_NODE_ONE_FLAG_PREV_SE) &&		/* prev_se is already set before */
		(flags & DEL_NODE_ONE_FLAG_DEL_CHILD_SE))
		flags |= DEL_NODE_ONE_FLAG_NEED_LOCK_PREV_SE;

	if (is_leaf) {
		flags |= DEL_NODE_ONE_FLAG_LEAF;

		cmd_data->qid = cpu_to_le16((*node_pptr)->qid);
		cmd_data->qid_type = cpu_to_le16((*node_pptr)->qid_type);

		if ((*node_pptr)->qid_type == QID_TYPE_LAN_TXQ)
			cmd_data->leaf_qid2lnid = cpu_to_le32((u32)(*node_pptr)->qid);
		else	/* QID_TYPE_RDMA_QSET */
			cmd_data->leaf_qid2lnid = cpu_to_le32(((u32)(*node_pptr)->qid) +
				hw->hw_conf.sched_qid2lnid_table_tdm_pe_boundary_offset);
	}

	unlink_parent_child(parent, *node_pptr);

	if (list_empty(&parent->direct_children_list))
		flags |= DEL_NODE_ONE_FLAG_SU_BECOME_EMPTY;

	/*  the following statement must after unlink_parent_child(), which update remain nodes's
	 * suid and logic_idx_in_su
	 */

	i = 0;
	sib_tail_child = NULL;

	if (!is_leaf) {	/* not a LEAF-node, but a inter-parent nodes */

		/* scan remaing sib_nodes, see who has SUID and logical_idx changes */
		list_for_each_entry(cur, &parent->direct_children_list, direct_sibling) {
			if (!cur->num_children)	/* no need for remain sib_node without children */
				continue;

			if (cur->suid == cur->old_suid &&	/* no change */
				cur->logic_idx_in_su == cur->old_logic_idx_in_su)
				continue;

			sib_tail_child = list_last_entry(&cur->direct_children_list,
							 struct nse_sched_node, direct_sibling);

			cmd_data->remain_sib_tail_child_se[i] = cpu_to_le32((sib_tail_child->tnid >>
									    1));
			cmd_data->remain_sib_tail_child_se_new_ptr[i] = cpu_to_le32(cur->suid);
			cmd_data->remain_sib_tail_child_se_new_idx[i] =
				cpu_to_le32(cur->logic_idx_in_su);

			i++;

			if (i > DEL_NODE_ONE_EXISTING_SIB_TAIL_CHILD_SE_CNT_MAX) {
				dev_err(dev, "[%s, %d] BAD\n", __func__, __LINE__);
				status = NSE_ERR_OUT_OF_RANGE;
				goto out;
			}
		}

		cmd_data->remain_sib_tail_child_se_cnt = cpu_to_le32(i);

	} else {	/* LEAF-node */

		list_for_each_entry(cur, &parent->direct_children_list, direct_sibling) {
			if (cur->suid == cur->old_suid &&	/* no change */
				cur->logic_idx_in_su == cur->old_logic_idx_in_su)
				continue;

			/* surely existing old sibling LEAF-node have QID2LNID */
			if (cur->qid_type == QID_TYPE_LAN_TXQ)
				cmd_data->remain_leaf_sib_qid2lnid[i] = cpu_to_le32((u32)cur->qid);
			else	/* QID_TYPE_RDMA_QSET */
				cmd_data->remain_leaf_sib_qid2lnid[i] = cpu_to_le32((u32)cur->qid +
					hw->hw_conf.sched_qid2lnid_table_tdm_pe_boundary_offset);

			cmd_data->remain_leaf_sib_qid2lnid_new_ptr[i] = cur->suid;
			cmd_data->remain_leaf_sib_qid2lnid_new_idx[i] = cur->logic_idx_in_su;

			i++;

			if (i > DEL_NODE_ONE_EXISTING_LEAF_SIB_QID2LNID_CNT_MAX) {
				dev_err(dev, "[%s, %d] BAD sanity\n", __func__, __LINE__);
				status = NSE_ERR_OUT_OF_RANGE;
				goto out;
			}
		}

		cmd_data->remain_leaf_sib_qid2lnid_cnt = cpu_to_le32(i);
	}

	cmd_data->flags = cpu_to_le32(flags);

	status = NSE_SUCCESS;

out:
	*prev_sibling_pptr = prev_sibling;
	*next_sibling_pptr = next_sibling;

	return status;
}

static bool
sanity_check_se_cnt_in_su(struct nse_sched_node *parent)
{
	u32 se_cnt = 0;
	struct nse_sched_node *n = NULL, *prev_sibling = NULL;

	list_for_each_entry(n, &parent->direct_children_list, direct_sibling) {
		if (n->direct_sibling.prev != &parent->direct_children_list)
			prev_sibling = list_prev_entry(n, direct_sibling);
		else
			prev_sibling = NULL;

		if (!prev_sibling) {
			se_cnt++;		// = 1
		} else {
			if (!is_forward_twin(prev_sibling->tnid, n->tnid))
				se_cnt++;
		}
	}

	return (se_cnt <= 8);	/* NSE_SCHED_LAYER_MAX_CHILDREN_NUM_16 / 2 */
}

static void
nse_sched_save_node_sch_param(struct nse_port_info *pi, struct nse_sch_node_param *dst,
			      struct nse_sch_node_param *src)
{
	/* don't memcpy(dst, src); ....
	 */

	dst->valid_section = src->valid_section;

	if (le16_to_cpu(src->valid_section) & NSE_SCH_NODE_PARAM_SECTION_ARB_MODE_VALID)
		dst->arb_mode = src->arb_mode;

	if (le16_to_cpu(src->valid_section) & NSE_SCH_NODE_PARAM_SECTION_SP_VAL_VALID)
		dst->sp_val = src->sp_val;

	if (le16_to_cpu(src->valid_section) & NSE_SCH_NODE_PARAM_SECTION_NODE_TYPE_VALID)
		dst->node_type = src->node_type;

	if (le16_to_cpu(src->valid_section) & NSE_SCH_NODE_PARAM_SECTION_PIR_VALID) {
		dst->pir_factor_int = src->pir_factor_int;
		dst->pir_factor_df_int = src->pir_factor_df_int;
		dst->pir_factor_df_df = src->pir_factor_df_df;

		dst->pir = nse_sched_factor_val_to_idx(pi, le16_to_cpu(dst->pir_factor_int),
						       le16_to_cpu(dst->pir_factor_df_int),
						       le16_to_cpu(dst->pir_factor_df_df));

		if (!dst->pir)
			dst->valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID));
	} else {
		dst->pir = 0;
		dst->pir_factor_int = dst->pir_factor_df_int = dst->pir_factor_df_df = 0;
	}

	if (le16_to_cpu(src->valid_section) & NSE_SCH_NODE_PARAM_SECTION_CIR_VALID) {
		dst->cir_factor_int = src->cir_factor_int;
		dst->cir_factor_df_int = src->cir_factor_df_int;
		dst->cir_factor_df_df = src->cir_factor_df_df;

		dst->cir = nse_sched_factor_val_to_idx(pi, le16_to_cpu(dst->cir_factor_int),
						       le16_to_cpu(dst->cir_factor_df_int),
						       le16_to_cpu(dst->cir_factor_df_df));

		if (!dst->cir)
			dst->valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID));
	} else {
		dst->cir = 0;
		dst->cir_factor_int = dst->cir_factor_df_int = dst->cir_factor_df_df = 0;
	}

	if (le16_to_cpu(src->valid_section) & NSE_SCH_NODE_PARAM_SECTION_TC_VAL_VALID)
		dst->tc_val = src->tc_val;

	if (le16_to_cpu(src->valid_section) & NSE_SCH_NODE_PARAM_SECTION_PORT_ID_VALID)
		dst->port_id = src->port_id;
}

enum nse_status
nse_sched_add_one_sw_node(struct nse_port_info *pi, struct nse_sched_node *tc_node,
			struct nse_sched_node *parent, u8 layer,
			struct nse_sched_node *prev_sibling, struct nse_sched_node *next_sibling,
			u32 new_node_tnid,
			struct nse_aqc_qos_sch_add_node_one *cmd_data,
			struct nse_sched_node **new_node_pptr)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *new_node, *layer_prev_sibling;

	new_node = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
		return NSE_ERR_NO_MEMORY;

	new_node->hw = hw;

	INIT_LIST_HEAD(&new_node->direct_children_list);
	INIT_LIST_HEAD(&new_node->direct_sibling);

	new_node->layer_id = layer;
	new_node->tnid = new_node_tnid;
	new_node->in_use = true;

	nse_sched_save_node_sch_param(pi, &new_node->sch_param, &cmd_data->sch_param);

	link_parent_child(parent, new_node, prev_sibling, next_sibling);

	if (!sanity_check_se_cnt_in_su(parent)) {
		dev_err(nse_hw_to_dev(hw), "FAIL: sanity_check_se_cnt_in_su()");

		/* like unlink_parent_child(), but don't use unlink_parent_child() */
		list_del_init(&new_node->direct_sibling);
		parent->num_children--;

		devm_kfree(nse_hw_to_dev(hw), new_node);

		return NSE_ERR_NOT_SUPPORTED;
	}

	new_node->layer_sibling = NULL;
	new_node->tc_num = tc_node->tc_num;

	if (layer != si->layer_id_leaf) {
		layer_prev_sibling = nse_sched_get_first_node(pi, tc_node, layer);
		/* definitely we have this != */
		if (layer_prev_sibling && layer_prev_sibling != new_node) {
			while (layer_prev_sibling->layer_sibling)
				layer_prev_sibling = layer_prev_sibling->layer_sibling;

			layer_prev_sibling->layer_sibling = new_node;
		}

		if (!si->layer_sibling_head[tc_node->tc_num][layer])
			si->layer_sibling_head[tc_node->tc_num][layer] = new_node;
	}

	if (new_node_pptr)
		*new_node_pptr = new_node;

	return NSE_SUCCESS;
}

static enum nse_status
nse_sched_add_one_inter_node(struct nse_port_info *pi, struct nse_sched_node *tc_node,
			struct nse_sched_node *parent, u8 layer,
			struct nse_aqc_qos_sch_add_node_one *cmd_data,
			u32 *new_node_tnid)
{
	struct nse_hw *hw = pi->hw;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *prev_sibling = NULL, *next_sibling = NULL;
	enum nse_status status = 0;

	/**********************
	 *
	 * fill in cmd data for adding a inter_node.
	 *
	 **********************/

	nse_sched_fill_cmd_data_add_node_one(pi, cmd_data,
					     parent,
					     &prev_sibling, &next_sibling,
					     false, 0, 0);

	nse_sched_aqc_fill_node_default_sch_param(hw, &cmd_data->sch_param, false, tc_node->tc_num);

	/**********************
	 *
	 * issue aq-cmd: NSE_AQ_OPC_QOS_SCH_ADD_NODE_ONE
	 *
	 **********************/

	status = nse_sched_aqc_add_node_one(hw, cmd_data);

	if (status) {
		dev_err(dev, "FAIL: sched_aqc_add_node_one(), status=%d(%s)\n",
						status, nse_stat_str(status));

		goto out;
	}

	*new_node_tnid = le32_to_cpu(cmd_data->new_child_tnid);

	/**********************
	 *
	 * aq-cmd success, HW-node created, then create SW-node in SW-tree
	 *
	 **********************/

	status = nse_sched_add_one_sw_node(pi, tc_node, parent, layer,
					   prev_sibling, next_sibling,
					   *new_node_tnid,
											cmd_data,
											NULL);

	if (status) {
		dev_err(dev, "FAIL: sched_add_one_sw_node(), status=%d(%s), HW-node (tnid=%d) may leak\n",
						status, nse_stat_str(status),
						*new_node_tnid);
		goto out;
	}

	status = NSE_SUCCESS;

out:
	return status;
}

/**
 * nse_sched_add_elems - add nodes to HW and SW DB
 * @pi: port information structure
 * @tc_node: pointer to the branch node
 * @parent: pointer to the parent node
 * @layer: layer number to add nodes
 * @num_nodes: number of nodes
 * @num_nodes_added: pointer to num nodes added
 * @first_node_tnid: if new nodes are added then return the TNID of first node
 *
 * This function add nodes to HW as well as to SW DB for a given layer
 */
static enum nse_status
nse_sched_add_elems(struct nse_port_info *pi, struct nse_sched_node *tc_node,
		    struct nse_sched_node *parent, u8 layer, u16 num_nodes,
		    u16 *num_nodes_added, u32 *first_node_tnid)
{
	struct nse_hw *hw = pi->hw;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_qos_sch_add_node_one *cmd_data = NULL;
	u32 new_node_tnid;
	u16 i = 0;
	enum nse_status status = 0;

	cmd_data = devm_kzalloc(dev, sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	for (i = 0; i < num_nodes; i++) {
		status = nse_sched_add_one_inter_node(pi, tc_node,
						      parent, layer, cmd_data, &new_node_tnid);
		if (status) {
			dev_err(dev, "FAIL: nse_sched_add_one_inter_node( %d-th times )\n", i);
			goto out;
		}

		if (i == 0)
			*first_node_tnid = new_node_tnid;
	}

	*num_nodes_added = num_nodes;

out:
	if (!cmd_data)
		devm_kfree(dev, cmd_data);

	return status;
}

void
nse_sched_del_one_sw_node(struct nse_hw *hw, struct nse_sched_node *parent,
						struct nse_sched_node *node,
						bool already_unlinked)
{
	struct nse_port_info *pi = hw->port_info;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *p = NULL;

	if (!already_unlinked)
		unlink_parent_child(parent, node);

	/* For LEAF-node,
	 *		we don't add it to layer_sibling in nse_sched_add_one_sw_node()
	 *		we don't unlink it from layer_sibling here.
	 */
	if (node->layer_id != si->layer_id_leaf) {
		p = nse_sched_get_first_node(pi, node, node->layer_id);
		while (p) {
			if (p->layer_sibling == node) {
				p->layer_sibling = node->layer_sibling;
				break;
			}
			p = p->layer_sibling;
		}

		/* update the sibling head if head is getting removed */
		if (si->layer_sibling_head[node->tc_num][node->layer_id] == node)
			si->layer_sibling_head[node->tc_num][node->layer_id] =
				node->layer_sibling;
	}

	devm_kfree(dev, node);
}

void
del_one_node(struct nse_hw *hw, struct nse_sched_node *parent, struct nse_sched_node *node,
						struct nse_aqc_qos_sch_del_node_one *cmd_data)
{
	struct nse_port_info *pi = hw->port_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *prev_sibling = NULL, *next_sibling = NULL, *dummy = NULL;
	bool already_unlinked = false;
	enum nse_status status = 0;

	if (nse_sched_no_need_to_del_hw_node(hw))
		goto delete_sw_node;

	/**********************
	 *
	 *  fill in cmd data for deleting a HW-node (an inter-node, should without any children at
	 * this moment)
	 *
	 **********************/

	status = nse_sched_fill_cmd_data_del_node_one_and_unlink_sw_node(pi, cmd_data,
							parent, node->tnid, &dummy,
								&prev_sibling, &next_sibling,
							false);
	if (status) {
		/* skip aq-cmd to del HW-node, but just del SW-node
		 */
		dev_err(dev, "FAIL: sched_fill_cmd_data_del_node_one_and_unlink_sw_node() return %d(%s)\n",
					status, nse_stat_str(status));

		if (node == dummy)
			already_unlinked = true;

		goto delete_sw_node;
	}

	already_unlinked = true;

	/**********************
	 *
	 * issue aq-cmd: NSE_AQ_OPC_QOS_SCH_DEL_NODE_ONE
	 *
	 **********************/

	status = nse_sched_aqc_del_node_one(hw, cmd_data);

	if (status)
		dev_err(dev, "FAIL: sched_aqc_del_node_one(), status=%d(%s)\n",
						status, nse_stat_str(status));

delete_sw_node:

	nse_sched_del_one_sw_node(hw, parent, node, already_unlinked);
}

bool nse_sched_no_need_to_del_hw_node(struct nse_hw *hw)
{
	if (hw->high_reset_ongoing)
		return true;

	return false;
}

/**
 * ice_free_sched_node - Free a Tx scheduler node from SW DB
 * @pi: port information structure
 * @node: pointer to the ice_sched_node struct
 *
 * This function frees up a node from SW DB as well as from HW
 *
 * This function needs to be called with the port_info->sched_lock held
 */
void nse_free_sched_node(struct nse_port_info *pi, struct nse_sched_node *node,
			 struct nse_aqc_qos_sch_del_node_one *cmd_data)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *parent, *child;
	struct list_head *child_ptr, *tmp;
	bool cmd_data_alloc_internally = false;

	if (!cmd_data) {
		cmd_data_alloc_internally = true;

		cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);

		if (!cmd_data) {
			nse_sched_del_one_sw_node(hw, node->parent, node, false);
			return;
		}
	}

	if (!list_empty(&node->direct_children_list)) {
		list_for_each_prev_safe(child_ptr, tmp, &node->direct_children_list) {
			child = list_entry(child_ptr, struct nse_sched_node, direct_sibling);
			nse_free_sched_node(pi, child, cmd_data);
		}
	}

	/* at this moment, I don't have any children.
	 */

	parent = node->parent;

	/* root has no parent */
	if (parent) {
		if (node->layer_id >= si->layer_id_sw_entry_point &&
			node->layer_id != si->layer_id_leaf) {
			del_one_node(hw, parent, node, cmd_data);
		} else if (node->layer_id == si->layer_id_leaf) {
			nse_sched_del_one_sw_node(hw, parent, node, false);
		} else if (node->layer_id < si->layer_id_sw_entry_point) {
			/* for initial-nodes, we only delete its SW-nodes
			 */
			nse_sched_del_one_sw_node(hw, parent, node, false);
		}
	} else {
		/* for SW-root-node, deallocate it directly.
		 */
		devm_kfree(nse_hw_to_dev(hw), node);
	}

	if (cmd_data_alloc_internally)
		kfree(cmd_data);
}

/**
 * nse_sched_add_nodes_to_hw_layer - Add nodes to hw layer
 * @pi: port information structure
 * @tc_node: pointer to TC node
 * @parent: pointer to parent node
 * @layer: layer number to add nodes
 * @num_nodes: number of nodes to be added
 * @first_node_tnid: pointer to the first node TNID
 * @num_nodes_added: pointer to number of nodes added
 *
 * Add nodes into specific hw layer.
 */
static enum nse_status
nse_sched_add_nodes_to_hw_layer(struct nse_port_info *pi,
				struct nse_sched_node *tc_node,
				struct nse_sched_node *parent, u8 layer,
				u16 num_nodes, u32 *first_node_tnid,
				u16 *num_nodes_added)
{
	struct nse_sched_info *si = &pi->sched_info;
	u16 max_child_nodes;

	*num_nodes_added = 0;

	if (!num_nodes)
		return 0;

	if (!parent || layer < si->layer_id_sw_entry_point)
		return NSE_ERR_PARAM;

	/* max children per node per layer */
	max_child_nodes = si->max_children[parent->layer_id];

	/* current number of children + required nodes exceed max children */
	if ((parent->num_children + num_nodes) > max_child_nodes) {
		/* Fail if the parent is a TC node */
		if (parent == tc_node)
			return NSE_ERR_CFG;
		return NSE_ERR_MAX_LIMIT;
	}

	return nse_sched_add_elems(pi, tc_node, parent, layer, num_nodes,
				   num_nodes_added, first_node_tnid);
}

/**
 * nse_sched_add_nodes_to_layer - Add nodes to a given layer
 * @pi: port information structure
 * @tc_node: pointer to TC node
 * @parent: pointer to parent node
 * @layer: layer number to add nodes
 * @num_nodes: number of nodes to be added
 * @first_node_tnid: pointer to the first node TNID
 * @num_nodes_added: pointer to number of nodes added
 *
 * This function add nodes to a given layer.
 */
static enum nse_status
nse_sched_add_nodes_to_layer(struct nse_port_info *pi,
			     struct nse_sched_node *tc_node,
			     struct nse_sched_node *parent, u8 layer,
			     u16 num_nodes, u32 *first_node_tnid,
			     u16 *num_nodes_added)
{
	struct nse_sched_info *si = &pi->sched_info;
	u32 *first_tnid_ptr = first_node_tnid;
	u16 new_num_nodes = num_nodes;
	enum nse_status status = 0;

	*num_nodes_added = 0;
	while (*num_nodes_added < num_nodes) {
		u16 max_child_nodes, num_added = 0;
#ifdef __CHECKER__
		/* cppcheck-suppress unusedVariable */
#endif /* __CHECKER__ */
		u32 temp;

		status = nse_sched_add_nodes_to_hw_layer(pi, tc_node, parent,
							 layer,	new_num_nodes,
							 first_tnid_ptr,
							 &num_added);
		if (!status)
			*num_nodes_added += num_added;
		/* added more nodes than requested ? */
		if (*num_nodes_added > num_nodes) {
			nse_debug(pi->hw, NSE_DBG_SCHED, "added extra nodes %d %d\n", num_nodes,
				  *num_nodes_added);
			status = NSE_ERR_CFG;
			break;
		}
		/* break if all the nodes are added successfully */
		if (!status && (*num_nodes_added == num_nodes))
			break;
		/* break if the error is not max limit */
		if (status && status != NSE_ERR_MAX_LIMIT)
			break;
		/* Exceeded the max children */
		max_child_nodes = si->max_children[parent->layer_id];
		/* utilize all the spaces if the parent is not full */
		if (parent->num_children < max_child_nodes) {
			new_num_nodes = max_child_nodes - parent->num_children;
		} else {
			/* This parent is full, try the next sibling */
			parent = parent->layer_sibling;
			/* Don't modify the first node TNID memory if the
			 * first node was added already in the above call.
			 * Instead send some temp memory for all other
			 * recursive calls.
			 */
			if (num_added)
				first_tnid_ptr = &temp;

			new_num_nodes = num_nodes - *num_nodes_added;
		}
	}
	return status;
}

/**
 * nse_sched_calc_vsi_support_nodes - calculate number of VSI support nodes
 * @pi: pointer to the port info structure
 * @tc_node: pointer to TC node
 * @num_nodes: pointer to num nodes array
 *
 * This function calculates the number of supported nodes needed to add this
 * VSI into Tx tree including the VSI, parent and intermediate nodes in below
 * layers
 */
static void
nse_sched_calc_vsi_support_nodes(struct nse_port_info *pi,
				 struct nse_sched_node *tc_node, u16 *num_nodes)
{
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *node;
	u8 vsil;
	unsigned int i;

	vsil = nse_sched_get_vsi_layer(pi->hw);
	for (i = vsil; i >= si->layer_id_sw_entry_point; i--) {
		/* Add intermediate nodes if TC has no children and
		 * need at least one node for VSI
		 */
		if (!tc_node->num_children || i == vsil) {
			num_nodes[i]++;
		} else {
			/* If intermediate nodes are reached max children
			 * then add a new one.
			 */
			node = nse_sched_get_first_node(pi, tc_node, (u8)i);
			/* scan all the siblings */
			while (node) {
				if (node->num_children <
				    si->max_children[i])
					break;
				node = node->layer_sibling;
			}

			/* tree has one intermediate node to add this new VSI.
			 * So no need to calculate supported nodes for below
			 * layers.
			 */
			if (node)
				break;
			/* all the nodes are full, allocate a new one */
			num_nodes[i]++;
		}
	}

	nse_debug(pi->hw, NSE_DBG_SCHED, "[%s] computes num_nodes[] =\n", __func__);
	for (i = si->layer_id_sw_entry_point; i <= vsil; i++) {
		nse_debug(pi->hw, NSE_DBG_SCHED, "\t num_nodes[layer_id = %d (%s)] = %d\n",
							i, si->layers_info[i].layer_name,
								num_nodes[i]);
	}
}

/**
 * nse_sched_add_vsi_support_nodes - add VSI supported nodes into Tx tree
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc_node: pointer to TC node
 * @num_nodes: pointer to num nodes array
 *
 * This function adds the VSI supported nodes into Tx tree including the
 * VSI, its parent and intermediate nodes in below layers
 */
static enum nse_status
nse_sched_add_vsi_support_nodes(struct nse_port_info *pi, u16 vsi_handle,
				struct nse_sched_node *tc_node, u16 *num_nodes)
{
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *parent = tc_node;
	u32 first_node_tnid;
	u16 num_added = 0;
	u8 i, vsil;

	if (!pi)
		return NSE_ERR_PARAM;

	vsil = nse_sched_get_vsi_layer(pi->hw);
	for (i = si->layer_id_sw_entry_point; i <= vsil; i++) {
		enum nse_status status;

		status = nse_sched_add_nodes_to_layer(pi, tc_node, parent,
						      i, num_nodes[i],
						      &first_node_tnid,
						      &num_added);
		if (status || num_nodes[i] != num_added)
			return NSE_ERR_CFG;

		/* The newly added node can be a new parent for the next
		 * layer nodes
		 */
		if (num_added) {
			parent = nse_sched_find_node_by_tnid(tc_node,
							     first_node_tnid);
		} else {
			parent = list_first_entry_or_null(&parent->direct_children_list,
							  struct nse_sched_node,
								  direct_sibling);
		}

		if (!parent)
			return NSE_ERR_CFG;

		if (i == vsil)
			parent->vsi_handle = vsi_handle;
	}

	return 0;
}

/**
 * nse_sched_add_vsi_to_topo - add a new VSI into tree
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc: TC number
 *
 * This function adds a new VSI into scheduler tree
 */
static enum nse_status
nse_sched_add_vsi_to_topo(struct nse_port_info *pi, u16 vsi_handle, u8 tc)
{
	u16 num_nodes[NSE_SCH_TREE_MAX_LAYERS_NUM] = { 0 };
	struct nse_sched_node *tc_node;

	tc_node = nse_sched_get_tc_node(pi, tc);
	if (!tc_node)
		return NSE_ERR_PARAM;

	/* calculate number of supported nodes needed for this VSI */
	nse_sched_calc_vsi_support_nodes(pi, tc_node, num_nodes);

	/* add VSI supported nodes to TC subtree */
	return nse_sched_add_vsi_support_nodes(pi, vsi_handle, tc_node,
					       num_nodes);
}

/**
 * nse_alloc_lan_q_ctx - allocate LAN queue contexts for the given VSI and TC
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 * @tc: TC number
 * @new_numqs: number of queues
 */
static enum nse_status
nse_alloc_lan_q_ctx(struct nse_hw *hw, u16 vsi_handle, u8 tc, u16 new_numqs)
{
	struct nse_vsi_ctx *vsi_ctx;
	struct nse_q_ctx *q_ctx;

	vsi_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi_ctx)
		return NSE_ERR_PARAM;
	/* allocate LAN queue contexts */
	if (!vsi_ctx->lan_q_ctx[tc]) {
		vsi_ctx->lan_q_ctx[tc] = devm_kcalloc(nse_hw_to_dev(hw),
						      new_numqs,
						      sizeof(*q_ctx),
						      GFP_KERNEL);
		if (!vsi_ctx->lan_q_ctx[tc])
			return NSE_ERR_NO_MEMORY;

		vsi_ctx->lan_q_ctx[tc]->q_handle = NSE_INVAL_Q_HANDLE;
		vsi_ctx->lan_q_ctx[tc]->q_tnid = NSE_SCHED_INVAL_TNID;

		vsi_ctx->num_lan_q_entries[tc] = new_numqs;
		return 0;
	}
	/* num queues are increased, update the queue contexts */
	if (new_numqs > vsi_ctx->num_lan_q_entries[tc]) {
		u16 prev_num = vsi_ctx->num_lan_q_entries[tc];

		q_ctx = devm_kcalloc(nse_hw_to_dev(hw), new_numqs,
				     sizeof(*q_ctx), GFP_KERNEL);
		if (!q_ctx)
			return NSE_ERR_NO_MEMORY;
		memcpy(q_ctx, vsi_ctx->lan_q_ctx[tc],
		       prev_num * sizeof(*q_ctx));
		devm_kfree(nse_hw_to_dev(hw), vsi_ctx->lan_q_ctx[tc]);
		vsi_ctx->lan_q_ctx[tc] = q_ctx;
		vsi_ctx->num_lan_q_entries[tc] = new_numqs;
	}
	return 0;
}

/**
 * nse_alloc_rdma_q_ctx - allocate RDMA queue contexts for the given VSI and TC
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 * @tc: TC number
 * @new_numqs: number of queues
 */
static enum nse_status
nse_alloc_rdma_q_ctx(struct nse_hw *hw, u16 vsi_handle, u8 tc, u16 new_numqs)
{
	struct nse_vsi_ctx *vsi_ctx;
	struct nse_q_ctx *q_ctx;

	vsi_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi_ctx)
		return NSE_ERR_PARAM;
	/* allocate RDMA queue contexts */
	if (!vsi_ctx->rdma_q_ctx[tc]) {
		vsi_ctx->rdma_q_ctx[tc] = devm_kcalloc(nse_hw_to_dev(hw),
						       new_numqs,
						       sizeof(*q_ctx),
						       GFP_KERNEL);
		if (!vsi_ctx->rdma_q_ctx[tc])
			return NSE_ERR_NO_MEMORY;

		vsi_ctx->rdma_q_ctx[tc]->q_handle = NSE_INVAL_Q_HANDLE;
		vsi_ctx->rdma_q_ctx[tc]->q_tnid = NSE_SCHED_INVAL_TNID;

		vsi_ctx->num_rdma_q_entries[tc] = new_numqs;
		return 0;
	}
	/* num queues are increased, update the queue contexts */
	if (new_numqs > vsi_ctx->num_rdma_q_entries[tc]) {
		u16 prev_num = vsi_ctx->num_rdma_q_entries[tc];

		q_ctx = devm_kcalloc(nse_hw_to_dev(hw), new_numqs,
				     sizeof(*q_ctx), GFP_KERNEL);
		if (!q_ctx)
			return NSE_ERR_NO_MEMORY;
		memcpy(q_ctx, vsi_ctx->rdma_q_ctx[tc],
		       prev_num * sizeof(*q_ctx));
		devm_kfree(nse_hw_to_dev(hw), vsi_ctx->rdma_q_ctx[tc]);
		vsi_ctx->rdma_q_ctx[tc] = q_ctx;
		vsi_ctx->num_rdma_q_entries[tc] = new_numqs;
	}
	return 0;
}

/**
 * nse_sched_calc_vsi_child_nodes - calculate number of VSI child nodes
 * @hw: pointer to the HW struct
 * @num_qs: number of queues
 * @num_nodes: num nodes array
 *
 * This function calculates the number of VSI child nodes based on the
 * number of queues.
 */
static void
nse_sched_calc_vsi_child_nodes(struct nse_hw *hw, u16 num_qs, u16 *num_nodes)
{
	struct nse_sched_info *si = &hw->port_info->sched_info;
	u16 num = num_qs;
	u8 i, qgl, vsil;

	qgl = nse_sched_get_qgrp_layer(hw);
	vsil = nse_sched_get_vsi_layer(hw);

	/* calculate num nodes from queue group to VSI layer */
	for (i = qgl; i > vsil; i--) {
		/* round to the next integer if there is a remainder */
		num = DIV_ROUND_UP(num, si->max_children[i]);

		/* need at least one node */
		num_nodes[i] = num ? num : 1;
	}

	nse_debug(hw, NSE_DBG_SCHED, "[%s] computes num_nodes[] =\n", __func__);
	for (i = (vsil + 1); i <= qgl; i++) {
		nse_debug(hw, NSE_DBG_SCHED, "\t num_nodes[layer_id = %d (%s)] = %d\n",
			  i, si->layers_info[i].layer_name, num_nodes[i]);
	}
}

/**
 * nse_sched_add_vsi_child_nodes - add VSI child nodes to tree
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc_node: pointer to the TC node
 * @num_nodes: pointer to the num nodes that needs to be added per layer
 * @owner: node owner (LAN or RDMA)
 *
 * This function adds the VSI child nodes to tree. It gets called for
 * LAN and RDMA separately.
 */
static enum nse_status
nse_sched_add_vsi_child_nodes(struct nse_port_info *pi, u16 vsi_handle,
			      struct nse_sched_node *tc_node, u16 *num_nodes,
			      u8 owner)
{
	struct nse_sched_node *parent, *node;
	struct nse_hw *hw = pi->hw;
	u32 first_node_tnid;
	u16 num_added = 0;
	u8 i, qgl, vsil;

	qgl = nse_sched_get_qgrp_layer(hw);
	vsil = nse_sched_get_vsi_layer(hw);

	parent = nse_sched_get_vsi_node(pi, tc_node, vsi_handle);

	for (i = vsil + 1; i <= qgl; i++) {
		enum nse_status status;

		if (!parent)
			return NSE_ERR_CFG;

		status = nse_sched_add_nodes_to_layer(pi, tc_node, parent, i,
						      num_nodes[i],
						      &first_node_tnid,
						      &num_added);
		if (status || num_nodes[i] != num_added)
			return NSE_ERR_CFG;

		/* The newly added node can be a new parent for the next
		 * layer nodes
		 */
		if (num_added) {
			parent = nse_sched_find_node_by_tnid(tc_node,
							     first_node_tnid);
			node = parent;
			while (node) {
				node->owner = owner;
				node = node->layer_sibling;
			}
		} else {
			parent = list_first_entry_or_null(&parent->direct_children_list,
							  struct nse_sched_node, direct_sibling);
		}
	}

	return 0;
}

/**
 * nse_sched_update_vsi_child_nodes - update VSI child nodes
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc: TC number
 * @new_numqs: new number of max queues
 * @owner: owner of this subtree
 *
 * This function updates the VSI child nodes based on the number of queues
 */
static enum nse_status
nse_sched_update_vsi_child_nodes(struct nse_port_info *pi, u16 vsi_handle,
				 u8 tc, u16 new_numqs, u8 owner)
{
	u16 new_num_nodes[NSE_SCH_TREE_MAX_LAYERS_NUM] = { 0 };
	struct nse_sched_node *vsi_node;
	struct nse_sched_node *tc_node;
	struct nse_vsi_ctx *vsi_ctx;
	enum nse_status status = 0;
	struct nse_hw *hw = pi->hw;
	u16 prev_numqs;

	tc_node = nse_sched_get_tc_node(pi, tc);
	if (!tc_node)
		return NSE_ERR_CFG;

	vsi_node = nse_sched_get_vsi_node(pi, tc_node, vsi_handle);
	if (!vsi_node)
		return NSE_ERR_CFG;

	vsi_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi_ctx)
		return NSE_ERR_PARAM;

	if (owner == NSE_SCHED_NODE_OWNER_LAN)
		prev_numqs = vsi_ctx->sched.max_lanq[tc];
	else
		prev_numqs = vsi_ctx->sched.max_rdmaq[tc];

	/* num queues are not changed or less than the previous number */
	if (new_numqs <= prev_numqs)
		return status;

	if (owner == NSE_SCHED_NODE_OWNER_LAN) {
		status = nse_alloc_lan_q_ctx(hw, vsi_handle, tc, new_numqs);
		if (status)
			return status;
	} else {
		status = nse_alloc_rdma_q_ctx(hw, vsi_handle, tc, new_numqs);
		if (status)
			return status;
	}

	if (new_numqs)
		nse_sched_calc_vsi_child_nodes(hw, new_numqs, new_num_nodes);

	/* Keep the max number of queue configuration all the time. Update the
	 * tree only if number of queues > previous number of queues. This may
	 * leave some extra nodes in the tree if number of queues < previous
	 * number but that wouldn't harm anything. Removing those extra nodes
	 * may complicate the code if those nodes are part of SRL or
	 * individually rate limited.
	 */
	status = nse_sched_add_vsi_child_nodes(pi, vsi_handle, tc_node,
					       new_num_nodes, owner);
	if (status)
		return status;

	if (owner == NSE_SCHED_NODE_OWNER_LAN)
		vsi_ctx->sched.max_lanq[tc] = new_numqs;
	else
		vsi_ctx->sched.max_rdmaq[tc] = new_numqs;

	return 0;
}

/**
 * nse_sched_cfg_vsi - configure the new/existing VSI
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc: TC number
 * @maxqs: max number of queues
 * @owner: LAN or RDMA
 * @enable: TC enabled or disabled
 *
 * This function adds/updates VSI nodes based on the number of queues. If TC is
 * enabled and VSI is in suspended state then resume the VSI back. If TC is
 * disabled then suspend the VSI if it is not already.
 */
enum nse_status
nse_sched_cfg_vsi(struct nse_port_info *pi, u16 vsi_handle, u8 tc, u16 maxqs,
		  u8 owner, bool enable)
{
	struct nse_sched_node *vsi_node, *tc_node;
	struct nse_vsi_ctx *vsi_ctx;
	enum nse_status status = 0;
	struct nse_hw *hw = pi->hw;

	nse_debug(hw, NSE_DBG_SCHED, "sched_cfg_vsi(vsi_handle=%d, tc=%d, maxqs=%d, owner=%d, enable=%d)\n",
								vsi_handle, tc, maxqs,
									owner, enable);

	tc_node = nse_sched_get_tc_node(pi, tc);
	if (!tc_node)
		return NSE_ERR_PARAM;
	vsi_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi_ctx)
		return NSE_ERR_PARAM;
	vsi_node = nse_sched_get_vsi_node(pi, tc_node, vsi_handle);

	/* suspend the VSI if TC is not enabled */
	if (!enable) {
		if (vsi_node && vsi_node->in_use) {
			status = nse_sched_suspend_node_one(hw, vsi_node->tnid);
			if (!status)
				vsi_node->in_use = false;
		}
		return status;
	}

	/* TC is enabled, if it is a new VSI then add it to the tree */
	if (!vsi_node) {
		status = nse_sched_add_vsi_to_topo(pi, vsi_handle, tc);
		if (status)
			return status;

		vsi_node = nse_sched_get_vsi_node(pi, tc_node, vsi_handle);
		if (!vsi_node)
			return NSE_ERR_CFG;

		vsi_ctx->sched.vsi_node[tc] = vsi_node;
		vsi_node->in_use = true;
		/* invalidate the max queues whenever VSI gets added first time
		 * into the scheduler tree (boot or after reset). We need to
		 * recreate the child nodes all the time in these cases.
		 */
		vsi_ctx->sched.max_lanq[tc] = 0;
		vsi_ctx->sched.max_rdmaq[tc] = 0;
	}

	/* update the VSI child nodes */
	status = nse_sched_update_vsi_child_nodes(pi, vsi_handle, tc, maxqs,
						  owner);
	if (status)
		return status;

	/* TC is enabled, resume the VSI if it is in the suspend state */
	if (!vsi_node->in_use) {
		status = nse_sched_resume_node_one(hw, vsi_node->tnid);
		if (!status)
			vsi_node->in_use = true;
	}

	return status;
}

/**
 * nse_sched_is_leaf_node_present - check for a leaf node in the sub-tree
 * @node: pointer to the sub-tree node
 *
 * This function checks for a leaf node presence in a given sub-tree node.
 */
static bool nse_sched_is_leaf_node_present(struct nse_sched_node *node)
{
	struct nse_hw *hw = (struct nse_hw *)node->hw;
	struct nse_sched_info *si = &hw->port_info->sched_info;
	struct nse_sched_node *child;

	list_for_each_entry(child, &node->direct_children_list, direct_sibling) {
		if (nse_sched_is_leaf_node_present(child))
			return true;
	}

	/* check for a leaf node */
	return (node->layer_id == si->layer_id_leaf);
}

/**
 * nse_sched_rm_vsi_cfg - remove the VSI and its children nodes
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @owner: LAN or RDMA
 *
 * This function removes the VSI and its LAN or RDMA children nodes from the
 * scheduler tree.
 */
static enum nse_status
nse_sched_rm_vsi_cfg(struct nse_port_info *pi, u16 vsi_handle, u8 owner)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_vsi_ctx *vsi_ctx;
	u8 i;
	enum nse_status status = NSE_ERR_PARAM;

	nse_debug(hw, NSE_DBG_SCHED, "%s(vsi_handle=%d, owner=%d)\n",
							__func__, vsi_handle, owner);

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return status;

	mutex_lock(&si->sched_lock);

	vsi_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi_ctx)
		goto exit_sched_rm_vsi_cfg;

	nse_for_each_traffic_class(i) {
		struct nse_sched_node *vsi_node, *tc_node, *vsi_parent, *child;
		struct list_head *child_ptr, *tmp_ptr;

		tc_node = nse_sched_get_tc_node(pi, i);
		if (!tc_node)
			continue;

		vsi_node = nse_sched_get_vsi_node(pi, tc_node, vsi_handle);
		if (!vsi_node)
			continue;

		if (nse_sched_is_leaf_node_present(vsi_node)) {
			dev_err(dev, "VSI has leaf nodes in TC %d\n", i);
			status = NSE_ERR_IN_USE;
			goto exit_sched_rm_vsi_cfg;
		}

		vsi_parent = vsi_node->parent;

		list_for_each_prev_safe(child_ptr, tmp_ptr, &vsi_node->direct_children_list) {
			child = list_entry(child_ptr, struct nse_sched_node, direct_sibling);

			if (child->owner == owner)
				nse_free_sched_node(pi, child, NULL);
		}

		/* remove the VSI if it has no children */
		if (!vsi_node->num_children) {
			(void)nse_sched_unset_node_cir(pi, vsi_node, true);

			nse_free_sched_node(pi, vsi_node, NULL);
			vsi_ctx->sched.vsi_node[i] = NULL;
		}

		if (owner == NSE_SCHED_NODE_OWNER_LAN)
			vsi_ctx->sched.max_lanq[i] = 0;
		else
			vsi_ctx->sched.max_rdmaq[i] = 0;
	}

	status = 0;

exit_sched_rm_vsi_cfg:
	mutex_unlock(&si->sched_lock);
	return status;
}

/**
 * nse_rm_vsi_lan_cfg - remove VSI and its LAN children nodes
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 *
 * This function clears the VSI and its LAN children nodes from scheduler tree
 * for all TCs.
 */
enum nse_status nse_rm_vsi_lan_cfg(struct nse_port_info *pi, u16 vsi_handle)
{
	return nse_sched_rm_vsi_cfg(pi, vsi_handle, NSE_SCHED_NODE_OWNER_LAN);
}

/**
 * nse_rm_vsi_rdma_cfg - remove VSI and its RDMA children nodes
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 *
 * This function clears the VSI and its RDMA children nodes from scheduler tree
 * for all TCs.
 */
enum nse_status nse_rm_vsi_rdma_cfg(struct nse_port_info *pi, u16 vsi_handle)
{
	return nse_sched_rm_vsi_cfg(pi, vsi_handle, NSE_SCHED_NODE_OWNER_RDMA);
}

enum nse_status
nse_sched_get_node_sch_param(struct nse_hw *hw,
							u32 tnid, struct nse_sch_node_param *param)
{
	struct nse_aqc_qos_sch_get_set_node_param_one *cmd_data = NULL;
	enum nse_status ret;

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data) {
		ret = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd_data->tnid = cpu_to_le32(tnid);

	ret = nse_sched_aqc_get_or_set_node_param_one(hw, cmd_data, true);

	if (!ret)
		nse_sched_save_node_sch_param(hw->port_info, param, &cmd_data->sch_param);

out:
	kfree(cmd_data);

	return ret;
}

void
nse_sched_node_sch_param_compute_pir_cir(struct nse_port_info *pi,
				u32 rate_kbps, struct nse_sched_rl_factor *rl_factor)
{
	u64 result;

	/* user_bw = 0 means not enforce any limit.
	 */
	if (!rate_kbps) {
		rl_factor->factor_idx = 0;
		rl_factor->factor_int = 0;
		rl_factor->factor_df_int = 0;
		rl_factor->factor_df_df = 0;
	} else {
		result = div_u64((u64)rate_kbps * NSE_SCHED_FACTOR_TBL_LEN,
				 pi->sched_info.max_bandwidth_per_lan_channel);

		if (result == 0)
			result = NSE_SCH_NODE_PARAM_PIR_CIR_MIN_VAL;
		else if (result > NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL)
			result = NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL;

		rl_factor->factor_idx = (u16)result;

		rl_factor->factor_int = (u16)(pi->sched_info.factor_tbl[result - 1] >> 32);
		rl_factor->factor_df_int = (u16)(pi->sched_info.factor_tbl[result - 1] >> 16);
		rl_factor->factor_df_df = (u16)(pi->sched_info.factor_tbl[result - 1]);
	}
}

void
nse_sched_node_sch_param_compute_pir_cir_by_idx(struct nse_port_info *pi,
				struct nse_sched_rl_factor *rl_factor)
{
	if (rl_factor->factor_idx &&
		rl_factor->factor_idx < NSE_SCHED_FACTOR_TBL_LEN) {
		rl_factor->factor_int =
			(u16)(pi->sched_info.factor_tbl[(rl_factor->factor_idx - 1)] >> 32);
		rl_factor->factor_df_int =
			(u16)(pi->sched_info.factor_tbl[(rl_factor->factor_idx - 1)] >> 16);
		rl_factor->factor_df_df =
			(u16)(pi->sched_info.factor_tbl[(rl_factor->factor_idx - 1)]);
	} else {
		rl_factor->factor_idx = 0;
		rl_factor->factor_int = 0;
		rl_factor->factor_df_int = 0;
		rl_factor->factor_df_df = 0;
	}
}

enum nse_status
nse_sched_conf_node_sch_param_pir(struct nse_hw *hw,
									struct nse_sched_node *node,
									u16 op,
				  struct nse_sched_rl_factor *rlf)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_qos_sch_conf_pir *cmd_data;
	enum nse_status ret;

	nse_debug(hw, NSE_DBG_SCHED, "[%s] op=%d, factor (idx=%d, int=%d, df_int=%d, df_df=%d)\n",
								__func__, op, rlf->factor_idx,
									rlf->factor_int,
									rlf->factor_df_int,
									rlf->factor_df_df);

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data) {
		ret = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd_data->tnid = cpu_to_le32(node->tnid);

	cmd_data->op = cpu_to_le16(op);
	cmd_data->pir = cpu_to_le16(rlf->factor_idx);
	cmd_data->factor_int = cpu_to_le16(rlf->factor_int);
	cmd_data->factor_df_int = cpu_to_le16(rlf->factor_df_int);
	cmd_data->factor_df_df = cpu_to_le16(rlf->factor_df_df);

	ret = nse_sched_aqc_conf_pir(hw, cmd_data);
	if (ret) {
		dev_err(dev, "FAIL: sched_aqc_conf_pir(tnid=%d, op=%d, pir=%d), ret=%d\n",
						node->tnid, op, rlf->factor_idx, ret);
		goto out;
	}

	if (cmd_data->conf_status) {
		dev_err(dev, "FAIL: sched_aqc_conf_pir(tnid=%d, op=%d, pir=%d), conf_status=%d\n",
						node->tnid, op, rlf->factor_idx,
							cmd_data->conf_status);
		ret = NSE_ERR_CFG;
		goto out;
	}

out:
	kfree(cmd_data);

	return ret;
}

enum nse_status
nse_sched_conf_node_sch_param_cir(struct nse_hw *hw,
									struct nse_sched_node *node,
									u16 op,
				  struct nse_sched_rl_factor *rlf,
									u8 *conf_status)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_qos_sch_conf_cir *cmd_data;
	enum nse_status ret;

	nse_debug(hw, NSE_DBG_SCHED, "[%s] op=%d, factor (idx=%d, int=%d, df_int=%d, df_df=%d)\n",
								__func__, op, rlf->factor_idx,
									rlf->factor_int,
									rlf->factor_df_int,
									rlf->factor_df_df);

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data) {
		ret = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd_data->tnid = cpu_to_le32(node->tnid);

	cmd_data->op = cpu_to_le16(op);

	cmd_data->cir = cpu_to_le16(rlf->factor_idx);
	cmd_data->factor_int = cpu_to_le16(rlf->factor_int);
	cmd_data->factor_df_int = cpu_to_le16(rlf->factor_df_int);
	cmd_data->factor_df_df = cpu_to_le16(rlf->factor_df_df);

	ret = nse_sched_aqc_conf_cir(hw, cmd_data);
	if (ret) {
		dev_err(dev, "FAIL: sched_aqc_conf_cir(tnid=%d, op=%d, cir=%d), ret=%d(%s)\n",
						node->tnid, op, rlf->factor_idx,
							ret, nse_stat_str(ret));
		goto out;
	}

	if (conf_status)
		*conf_status = cmd_data->conf_status;

	if (cmd_data->conf_status) {
		dev_err(dev, "FAIL: sched_aqc_conf_cir(tnid=%d, op=%d, cir=%d), conf_status=%d(%s)\n",
						node->tnid, op, rlf->factor_idx,
						cmd_data->conf_status,
							nse_aq_str(cmd_data->conf_status));
		ret = NSE_ERR_CFG;
		goto out;
	}

out:
	kfree(cmd_data);

	return ret;
}

static void nse_set_clear_cir_user_bw(struct nse_bw_type_info *bw_t_info, u32 user_bw)
{
	if (user_bw) {
		set_bit(NSE_BW_TYPE_CIR, bw_t_info->bw_t_bitmap);
		bw_t_info->cir_user_bw = user_bw;
	} else {
		clear_bit(NSE_BW_TYPE_CIR, bw_t_info->bw_t_bitmap);
		bw_t_info->cir_user_bw = 0;
	}
}

static void nse_set_clear_pir_user_bw(struct nse_bw_type_info *bw_t_info, u32 user_bw)
{
	if (user_bw) {
		set_bit(NSE_BW_TYPE_PIR, bw_t_info->bw_t_bitmap);
		bw_t_info->pir_user_bw = user_bw;
	} else {
		clear_bit(NSE_BW_TYPE_PIR, bw_t_info->bw_t_bitmap);
		bw_t_info->pir_user_bw = 0;
	}
}

static void nse_sched_save_q_bw(struct nse_q_ctx *q_ctx, enum nse_bw_type bw_type, u32 user_bw)
{
	if (bw_type == NSE_BW_TYPE_PIR)
		nse_set_clear_pir_user_bw(&q_ctx->bw_t_info, user_bw);
	else if (bw_type == NSE_BW_TYPE_CIR)
		nse_set_clear_cir_user_bw(&q_ctx->bw_t_info, user_bw);
}

enum nse_status
nse_sched_set_q_pir(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		 u16 q_handle, u32 user_bw)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *node;
	struct nse_q_ctx *q_ctx;
	struct nse_sched_rl_factor rlf;
	enum nse_status status = NSE_ERR_PARAM;

	if (!nse_is_vsi_valid(pi->hw, vsi_handle)) {
		dev_err(dev, "[%s] BAD: invalid vsi_handle=%d\n", __func__, vsi_handle);
		return NSE_ERR_PARAM;
	}

	mutex_lock(&si->sched_lock);

	q_ctx = nse_get_lan_q_ctx(pi->hw, vsi_handle, tc, q_handle);
	if (!q_ctx) {
		dev_err(dev, "[%s] BAD: lan_q_ctx (vsi_handle=%d, tc=%d, q_handle=%d) not exist\n",
					__func__, vsi_handle, tc, q_handle);
		goto exit_q_pir;
	}

	if (q_ctx->q_tnid == NSE_SCHED_INVAL_TNID ||
		q_ctx->q_tnid < hw->hw_conf.sched_node_table_initial_tree_size) {
		dev_err(dev, "[%s] BAD: invalid lan_q_ctx->q_tnid=%d, maybe VSI not open and LEAF-node not created yet\n",
					__func__, q_ctx->q_tnid);
		goto exit_q_pir;
	}

	node = nse_sched_find_node_by_tnid(si->root, q_ctx->q_tnid);
	if (!node) {
		dev_err(dev, "[%s] BAD: tx-sched LEAF-node (q_tnid=%d) not found\n",
					__func__, q_ctx->q_tnid);
		goto exit_q_pir;
	}

	nse_sched_node_sch_param_compute_pir_cir(pi, user_bw, &rlf);

	status = nse_sched_conf_node_sch_param_pir(pi->hw, node,
					rlf.factor_idx ? NSE_AQC_QOS_SCH_CONF_PIR_OP_SET :
						NSE_AQC_QOS_SCH_CONF_PIR_OP_RESET,
					&rlf);
	if (!status) {
		nse_sched_save_q_bw(q_ctx, NSE_BW_TYPE_PIR, user_bw);

		if (rlf.factor_idx)
			node->sch_param.valid_section |= cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID);
		else
			node->sch_param.valid_section &= ~cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID);

		node->sch_param.pir = cpu_to_le16(rlf.factor_idx);
		node->sch_param.pir_factor_int = cpu_to_le16(rlf.factor_int);
		node->sch_param.pir_factor_df_int = cpu_to_le16(rlf.factor_df_int);
		node->sch_param.pir_factor_df_df = cpu_to_le16(rlf.factor_df_df);
	}

exit_q_pir:
	mutex_unlock(&si->sched_lock);
	return status;
}

static enum nse_status
nse_sched_set_q_cir_recursive(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		 u16 q_handle, u32 user_bw)
{
	enum nse_status status = NSE_ERR_PARAM;
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *node, *parent_node;
	struct nse_q_ctx *q_ctx;
	u16 user_bw_cir = 0, cir_delta = 0, parent_cir = 0;
	bool add_or_sub;	/* 1 for add, 0 for sub */
	u16 op;
	struct nse_sched_rl_factor rlf;
	u8 conf_status;

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return NSE_ERR_PARAM;

	mutex_lock(&si->sched_lock);

	q_ctx = nse_get_lan_q_ctx(hw, vsi_handle, tc, q_handle);
	if (!q_ctx)
		goto exit_q_cir;

	node = nse_sched_find_node_by_tnid(si->root, q_ctx->q_tnid);
	if (!node)
		goto exit_q_cir;

	nse_sched_node_sch_param_compute_pir_cir(pi, user_bw, &rlf);

	user_bw_cir = rlf.factor_idx;

	if (user_bw_cir) {
		if (node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
			if (user_bw_cir > le16_to_cpu(node->sch_param.cir)) {
				add_or_sub = true;
				cir_delta = user_bw_cir - le16_to_cpu(node->sch_param.cir);
			} else if (user_bw_cir < le16_to_cpu(node->sch_param.cir)) {
				add_or_sub = false;
				cir_delta = le16_to_cpu(node->sch_param.cir) - user_bw_cir;
			} else {	/* ==, do nothing. */
				status = NSE_SUCCESS;
				goto save_q_bw;
			}
		} else {
			add_or_sub = true;
			cir_delta = user_bw_cir;
		}
	} else {
		if (node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
			add_or_sub = false;
			cir_delta = le16_to_cpu(node->sch_param.cir);
		} else {
			status = NSE_SUCCESS;
			goto save_q_bw;
		}
	}

	/* check subtree (including port-node) to see if OK to add
	 */
	if (add_or_sub) {
		status = nse_sched_get_node_sch_param(hw, si->port_node->tnid,
						      &si->port_node->sch_param);
		if (status) {
			dev_err(dev, "FAIL: get current sch-param of port-node(TNID=%d)\n",
				si->port_node->tnid);
			status = NSE_ERR_CFG;
			goto exit_q_cir;
		}

		parent_node = node->parent;

		while (parent_node != si->root) {
			if (parent_node->sch_param.valid_section &
			    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
				parent_cir = le16_to_cpu(parent_node->sch_param.cir);

				if ((parent_cir + cir_delta) > NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL) {
					dev_err(dev, "[%s] a ancestor (tnid=%d, in layer=%d) can not afford ADD this CIR: avail_cir=%d (ask ADD cir=%d)\n",
								__func__, parent_node->tnid,
									parent_node->layer_id,
						(NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL -
						 parent_cir), cir_delta);

					status = NSE_ERR_OUT_OF_RANGE;
					goto exit_q_cir;
				}
			}

			parent_node = parent_node->parent;
		}
	}

	/* conf_cir to all intermediate parent_node and this node itself.
	 */
	parent_node = node;
	while (parent_node != si->root) {
		if (add_or_sub) {
			rlf.factor_idx = le16_to_cpu(parent_node->sch_param.cir) + cir_delta;
		} else {
			if (le16_to_cpu(parent_node->sch_param.cir) > cir_delta)
				rlf.factor_idx = le16_to_cpu(parent_node->sch_param.cir) -
					cir_delta;
			else
				rlf.factor_idx = 0;
		}

		nse_sched_node_sch_param_compute_pir_cir_by_idx(pi, &rlf);

		op = (rlf.factor_idx) ? NSE_AQC_QOS_SCH_CONF_CIR_OP_SET :
			NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;

		status = nse_sched_conf_node_sch_param_cir(hw, parent_node, op,
							   &rlf, &conf_status);
		if (status) {
			dev_err(dev, "[%s] FAIL: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
							__func__, status, nse_stat_str(status),
							parent_node->tnid, op, rlf.factor_idx);
			goto exit_q_cir;
		}

		/* no need to sync get port_node's param from HW,
		 * because they are all in this PF instance's control,
		 * so we just update its param in SW-level
		 */
		if (add_or_sub) {
			parent_cir = le16_to_cpu(parent_node->sch_param.cir) + cir_delta;

			parent_node->sch_param.cir = cpu_to_le16(parent_cir);

			parent_node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
		} else {	/* OP_SUB */

			parent_cir = le16_to_cpu(parent_node->sch_param.cir);

			if (!parent_cir ||
				cir_delta >= parent_cir) {
				parent_node->sch_param.cir = 0;

				parent_node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
			} else {
				parent_cir -= cir_delta;

				parent_node->sch_param.cir = cpu_to_le16(parent_cir);

				parent_node->sch_param.valid_section |= (le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
			}
		}

		parent_node = parent_node->parent;
	}

save_q_bw:
	if (!status)
		/* just save TXQ-node, not any parent */
		nse_sched_save_q_bw(q_ctx, NSE_BW_TYPE_CIR, user_bw);

exit_q_cir:
	mutex_unlock(&si->sched_lock);
	return status;
}

static enum nse_status
nse_sched_set_q_cir_direct(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		 u16 q_handle, u32 user_bw)
{
	enum nse_status status = NSE_ERR_PARAM;
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *node;
	struct nse_q_ctx *q_ctx;
	u16 op;
	struct nse_sched_rl_factor rlf;
	u8 conf_status;

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return NSE_ERR_PARAM;

	mutex_lock(&si->sched_lock);

	q_ctx = nse_get_lan_q_ctx(hw, vsi_handle, tc, q_handle);
	if (!q_ctx)
		goto exit_q_cir;

	node = nse_sched_find_node_by_tnid(si->root, q_ctx->q_tnid);
	if (!node)
		goto exit_q_cir;

	nse_sched_node_sch_param_compute_pir_cir(pi, user_bw, &rlf);

	if (rlf.factor_idx) {
		if ((node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) &&
			(rlf.factor_idx == le16_to_cpu(node->sch_param.cir))) {
			/* ==, do nothing. */
			status = NSE_SUCCESS;
			goto save_q_bw;
		}
	} else {
		if (!(node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID))) {
			status = NSE_SUCCESS;
			goto save_q_bw;
		}
	}

	op = (rlf.factor_idx) ? NSE_AQC_QOS_SCH_CONF_CIR_OP_SET : NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;

	status = nse_sched_conf_node_sch_param_cir(hw, node, op,
						   &rlf, &conf_status);
	if (status) {
		dev_err(dev, "[%s] FAIL: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
						__func__, status, nse_stat_str(status),
						node->tnid, op, rlf.factor_idx);

		goto exit_q_cir;
	}

	node->sch_param.cir = cpu_to_le16(rlf.factor_idx);
	if (rlf.factor_idx)
		node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
	else
		node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));

save_q_bw:
	if (!status)
		nse_sched_save_q_bw(q_ctx, NSE_BW_TYPE_CIR, user_bw);

exit_q_cir:
	mutex_unlock(&si->sched_lock);
	return status;
}

enum nse_status
nse_sched_set_q_cir(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		 u16 q_handle, u32 user_bw)
{
	if (nse_sch_use_cir_transfer)
		return nse_sched_set_q_cir_direct(pi, vsi_handle, tc, q_handle, user_bw);
	else
		return nse_sched_set_q_cir_recursive(pi, vsi_handle, tc, q_handle, user_bw);
}

/**
 * nse_sched_get_node_by_id_type - get node from ID type
 * @pi: port information structure
 * @id: identifier
 * @agg_type: type of aggregator
 * @tc: traffic class
 *
 * This function returns node identified by ID of type aggregator, and
 * based on traffic class (TC). This function needs to be called with
 * the scheduler lock held.
 */
static struct nse_sched_node *
nse_sched_get_node_by_id_type(struct nse_port_info *pi, u32 id,
			      enum nse_agg_type agg_type, u8 tc)
{
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *node = NULL;

	switch (agg_type) {
	case NSE_AGG_TYPE_VSI: {
		struct nse_vsi_ctx *vsi_ctx;
		u16 vsi_handle = (u16)id;

		if (!nse_is_vsi_valid(pi->hw, vsi_handle))
			break;
		/* Get sched_vsi_info */
		vsi_ctx = nse_get_vsi_ctx(pi->hw, vsi_handle);
		if (!vsi_ctx)
			break;
		node = vsi_ctx->sched.vsi_node[tc];
		break;
	}

	case NSE_AGG_TYPE_Q:
		/* The current implementation allows single queue to modify */
		node = nse_sched_find_node_by_tnid(si->root, id);
		break;

	case NSE_AGG_TYPE_QG: {
		struct nse_sched_node *child_node;

		/* The current implementation allows single qg to modify */
		child_node = nse_sched_find_node_by_tnid(si->root, id);
		if (!child_node)
			break;
		node = child_node->parent;
		break;
	}

	default:
		break;
	}

	return node;
}

static void
nse_sched_save_vsi_bw(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
								enum nse_bw_type bw_type,
									u32 user_bw)
{
	struct nse_vsi_ctx *vsi_ctx;

	if (!nse_is_vsi_valid(pi->hw, vsi_handle))
		return;
	vsi_ctx = nse_get_vsi_ctx(pi->hw, vsi_handle);
	if (!vsi_ctx)
		return;

	if (bw_type == NSE_BW_TYPE_PIR)
		nse_set_clear_pir_user_bw(&vsi_ctx->sched.bw_t_info[tc], user_bw);
	else if (bw_type == NSE_BW_TYPE_CIR)
		nse_set_clear_cir_user_bw(&vsi_ctx->sched.bw_t_info[tc], user_bw);
}

enum nse_status
nse_sched_set_vsi_pir_per_tc(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		u32 user_bw)
{
	enum nse_status status = NSE_ERR_PARAM;
	struct nse_sched_node *node;
	struct nse_sched_rl_factor rlf;
	struct nse_sched_info *si = &pi->sched_info;

	if (!pi)
		return status;

	mutex_lock(&si->sched_lock);

	node = nse_sched_get_node_by_id_type(pi, vsi_handle, NSE_AGG_TYPE_VSI, tc);
	if (!node) {
		dev_err(nse_hw_to_dev(pi->hw), "[%s, %d] Wrong id, agg type, or tc\n",
				__func__, __LINE__);
		goto exit_vsi_pir;
	}

	nse_sched_node_sch_param_compute_pir_cir(pi, user_bw, &rlf);

	status = nse_sched_conf_node_sch_param_pir(pi->hw, node,
					rlf.factor_idx ? NSE_AQC_QOS_SCH_CONF_PIR_OP_SET :
						NSE_AQC_QOS_SCH_CONF_PIR_OP_RESET,
					&rlf);
	if (!status) {
		nse_sched_save_vsi_bw(pi, vsi_handle, tc, NSE_BW_TYPE_PIR, user_bw);

		if (rlf.factor_idx)
			node->sch_param.valid_section |= cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID);
		else
			node->sch_param.valid_section &= ~cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID);

		node->sch_param.pir = cpu_to_le16(rlf.factor_idx);
		node->sch_param.pir_factor_int = cpu_to_le16(rlf.factor_int);
		node->sch_param.pir_factor_df_int = cpu_to_le16(rlf.factor_df_int);
		node->sch_param.pir_factor_df_df = cpu_to_le16(rlf.factor_df_df);
	}

exit_vsi_pir:

	mutex_unlock(&si->sched_lock);
	return status;
}

static enum nse_status
nse_sched_set_vsi_cir_per_tc_recursive(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		u32 user_bw)
{
	enum nse_status status = NSE_ERR_PARAM;
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *node, *parent_node;
	u16 cir_delta = 0, parent_cir = 0;
	bool add_or_sub;	/* 1 for add, 0 for sub */
	u16 op;
	struct nse_sched_rl_factor rlf;
	u8 conf_status;

	if (!pi)
		return status;

	mutex_lock(&si->sched_lock);

	node = nse_sched_get_node_by_id_type(pi, vsi_handle, NSE_AGG_TYPE_VSI, tc);
	if (!node) {
		dev_err(nse_hw_to_dev(pi->hw), "[%s, %d] Wrong id, agg type, or tc\n",
				__func__, __LINE__);
		goto exit_vsi_cir;
	}

	nse_sched_node_sch_param_compute_pir_cir(pi, user_bw, &rlf);

	if (rlf.factor_idx) {
		if (node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
			if (rlf.factor_idx > le16_to_cpu(node->sch_param.cir)) {
				add_or_sub = true;
				cir_delta = rlf.factor_idx - le16_to_cpu(node->sch_param.cir);
			} else if (rlf.factor_idx < le16_to_cpu(node->sch_param.cir)) {
				add_or_sub = false;
				cir_delta = le16_to_cpu(node->sch_param.cir) - rlf.factor_idx;
			} else {	/* ==, do nothing. */
				status = NSE_SUCCESS;
				goto save_vsi_bw;
			}
		} else {
			add_or_sub = true;
			cir_delta = rlf.factor_idx;
		}
	} else {
		if (node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
			add_or_sub = false;
			cir_delta = le16_to_cpu(node->sch_param.cir);
		} else {
			status = NSE_SUCCESS;
			goto save_vsi_bw;
		}
	}

	/* check subtree (including port-node) to see if OK to add
	 */
	if (add_or_sub) {
		status = nse_sched_get_node_sch_param(hw, si->port_node->tnid,
						      &si->port_node->sch_param);
		if (status) {
			dev_err(dev, "FAIL: get current sch-param of port-node(TNID=%d)\n",
				si->port_node->tnid);
			status = NSE_ERR_CFG;
			goto exit_vsi_cir;
		}

		parent_node = node->parent;

		while (parent_node != si->root) {
			if (parent_node->sch_param.valid_section &
			    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
				parent_cir = le16_to_cpu(parent_node->sch_param.cir);

				if ((parent_cir + cir_delta) > NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL) {
					dev_err(dev, "[%s] a ancestor (tnid=%d, in layer=%d) can not afford ADD this CIR: avail_cir=%d (ask ADD cir=%d)\n",
								__func__, parent_node->tnid,
									parent_node->layer_id,
						(NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL -
						 parent_cir), cir_delta);

					status = NSE_ERR_OUT_OF_RANGE;
					goto exit_vsi_cir;
				}
			}

			parent_node = parent_node->parent;
		}
	}

	/* conf_cir to all intermediate parent_node and this node itself.
	 */
	parent_node = node;
	while (parent_node != si->root) {
		if (add_or_sub) {
			rlf.factor_idx = le16_to_cpu(parent_node->sch_param.cir) + cir_delta;
		} else {
			if (le16_to_cpu(parent_node->sch_param.cir) > cir_delta)
				rlf.factor_idx = le16_to_cpu(parent_node->sch_param.cir) -
					cir_delta;
			else
				rlf.factor_idx = 0;
		}

		nse_sched_node_sch_param_compute_pir_cir_by_idx(pi, &rlf);

		op = (rlf.factor_idx) ? NSE_AQC_QOS_SCH_CONF_CIR_OP_SET :
			NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;

		status = nse_sched_conf_node_sch_param_cir(hw, parent_node, op,
							   &rlf, &conf_status);
		if (status) {
			dev_err(dev, "[%s] FAIL: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
							__func__, status, nse_stat_str(status),
							parent_node->tnid, op, rlf.factor_idx);

			goto exit_vsi_cir;
		}

		/* no need to sync get port_node's param from HW,
		 * because they are all in this PF instance's control,
		 * so we just update its param in SW-level
		 */
		if (add_or_sub) {
			parent_cir = le16_to_cpu(parent_node->sch_param.cir) + cir_delta;

			parent_node->sch_param.cir = cpu_to_le16(parent_cir);

			parent_node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
		} else {	/* OP_SUB */

			parent_cir = le16_to_cpu(parent_node->sch_param.cir);

			if (!parent_cir ||
				cir_delta >= parent_cir) {
				parent_node->sch_param.cir = 0;

				parent_node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
			} else {
				parent_cir -= cir_delta;

				parent_node->sch_param.cir = cpu_to_le16(parent_cir);

				parent_node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
			}
		}

		parent_node = parent_node->parent;
	}

save_vsi_bw:
	if (!status)
		nse_sched_save_vsi_bw(pi, vsi_handle, tc, NSE_BW_TYPE_CIR, user_bw);

exit_vsi_cir:
	mutex_unlock(&si->sched_lock);
	return status;
}

static enum nse_status
nse_sched_set_vsi_cir_per_tc_direct(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		u32 user_bw)
{
	enum nse_status status = NSE_ERR_PARAM;
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *node;
	u16 op;
	struct nse_sched_rl_factor rlf;
	u8 conf_status;

	if (!pi)
		return status;

	mutex_lock(&si->sched_lock);

	node = nse_sched_get_node_by_id_type(pi, vsi_handle, NSE_AGG_TYPE_VSI, tc);
	if (!node) {
		dev_err(dev, "[%s, %d] Wrong id, agg type, or tc\n",
				__func__, __LINE__);

		status = NSE_ERR_DOES_NOT_EXIST;

		goto exit_vsi_cir;
	}

	nse_sched_node_sch_param_compute_pir_cir(pi, user_bw, &rlf);

	if (rlf.factor_idx) {
		if ((node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) &&
			(rlf.factor_idx == le16_to_cpu(node->sch_param.cir))) {
			status = NSE_SUCCESS;
			goto save_vsi_bw;
		}
	} else {
		if (!(node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID))) {
			status = NSE_SUCCESS;
			goto save_vsi_bw;
		}
	}

	op = (rlf.factor_idx) ? NSE_AQC_QOS_SCH_CONF_CIR_OP_SET : NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;

	status = nse_sched_conf_node_sch_param_cir(hw, node, op,
						   &rlf, &conf_status);
	if (status) {
		dev_err(dev, "[%s] FAIL: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
						__func__, status, nse_stat_str(status),
						node->tnid, op, rlf.factor_idx);

		goto exit_vsi_cir;
	}

	node->sch_param.cir = cpu_to_le16(rlf.factor_idx);
	if (rlf.factor_idx)
		node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
	else
		node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));

save_vsi_bw:
	if (!status)
		nse_sched_save_vsi_bw(pi, vsi_handle, tc, NSE_BW_TYPE_CIR, user_bw);

exit_vsi_cir:
	mutex_unlock(&si->sched_lock);
	return status;
}

enum nse_status
nse_sched_set_vsi_cir_per_tc(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		u32 user_bw)
{
	if (nse_sch_use_cir_transfer)
		return nse_sched_set_vsi_cir_per_tc_direct(pi, vsi_handle, tc, user_bw);
	else
		return nse_sched_set_vsi_cir_per_tc_recursive(pi, vsi_handle, tc, user_bw);
}

enum nse_status
nse_sched_set_tc_cir(struct nse_port_info *pi, u8 tc, u32 tc_bw)
{
	enum nse_status status = NSE_ERR_PARAM;
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *node;
	u32 rate_kbps;
	u16 op;
	struct nse_sched_rl_factor rlf;
	u8 conf_status;

	if (!pi)
		return status;

	if (!tc_bw || tc_bw >= 100)
		rate_kbps = 0;
	else
		rate_kbps = (tc_bw * si->max_bandwidth_per_lan_port) / 100;

	nse_sched_node_sch_param_compute_pir_cir(pi, rate_kbps, &rlf);

	nse_debug(hw, NSE_DBG_SCHED, "[%s] tc=%d, tc_bw=%d, rate_kbps=%d\n",
		  __func__, tc, tc_bw, rate_kbps);
	nse_debug(hw, NSE_DBG_SCHED, "\t computd rlf: factor_idx=%d, factor_int=%d, factor_df_int=%d, factor_df_df=%d\n",
									rlf.factor_idx,
										rlf.factor_int,
										rlf.factor_df_int,
										rlf.factor_df_df);

	mutex_lock(&si->sched_lock);

	node = nse_sched_get_tc_node(pi, tc);
	if (!node) {
		dev_err(dev, "[%s, %d] TC-node (tc=%d) not found\n",
				__func__, __LINE__, tc);

		status = NSE_ERR_DOES_NOT_EXIST;

		goto exit_tc_cir;
	}

	op = (rlf.factor_idx) ? NSE_AQC_QOS_SCH_CONF_CIR_OP_SET : NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;

	status = nse_sched_conf_node_sch_param_cir(hw, node, op,
						   &rlf, &conf_status);
	if (status) {
		dev_err(dev, "[%s] FAIL: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
						__func__, status, nse_stat_str(status),
						node->tnid, op, rlf.factor_idx);

		goto exit_tc_cir;
	}

	node->sch_param.cir = cpu_to_le16(rlf.factor_idx);
	if (rlf.factor_idx)
		node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
	else
		node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));

exit_tc_cir:
	mutex_unlock(&si->sched_lock);
	return status;
}

void
nse_sched_set_tc_cir_by_dcbxcfg(struct nse_hw *hw, struct nse_dcbx_cfg *local_dcbx_cfg)
{
	struct device *dev = nse_hw_to_dev(hw);
	u8 tc;
	enum nse_status status;

	for (tc = 0; tc < NSE_MAX_TRAFFIC_CLASS; tc++) {
		status = nse_sched_set_tc_cir(hw->port_info, tc,
					      (u32)local_dcbx_cfg->etscfg.tcbwtable[tc]);
		if (status)
			dev_info(dev, "WARN: fail set_tc_cir(tc=%d, tc_bw=%d)\n",
				 tc, local_dcbx_cfg->etscfg.tcbwtable[tc]);
	}
}

static enum nse_status
nse_sched_unset_node_cir_recursive(struct nse_port_info *pi,
				   struct nse_sched_node *node, bool locked)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *parent_node = NULL;
	u16 cir, parent_cir;
	u16 op;
	struct nse_sched_rl_factor rlf;
	u8 conf_status;

	if (!locked)
		mutex_lock(&si->sched_lock);

	/* no CIR on this node. */
	if (!(node->sch_param.valid_section & le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) ||
		!node->sch_param.cir)
		goto out;

	/* sync get port_node's param (including current CIR) */
	status = nse_sched_get_node_sch_param(hw, si->port_node->tnid, &si->port_node->sch_param);
	if (status) {
		dev_info(dev, "[%s] WARN: status=%d(%s), sched_get_node_sch_param(hw, si->port_node)\n",
							__func__, status, nse_stat_str(status));
		goto out;

		status = 0;
	}

	cir = le16_to_cpu(node->sch_param.cir);

	/* SUB CIR to all intermediate parent_node and this node itself, including port-node. */
	parent_node = node;
	while (parent_node != si->root) {
		if (parent_node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
			if (le16_to_cpu(parent_node->sch_param.cir) > cir) {
				op = NSE_AQC_QOS_SCH_CONF_CIR_OP_SET;
				rlf.factor_idx = le16_to_cpu(parent_node->sch_param.cir) - cir;
			} else {
				op = NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;
				rlf.factor_idx = 0;
			}
		} else
			continue;

		nse_sched_node_sch_param_compute_pir_cir_by_idx(pi, &rlf);

		status = nse_sched_conf_node_sch_param_cir(hw, parent_node, op,
							   &rlf, &conf_status);
		if (status)
			dev_info(dev, "[%s] WARN: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
							__func__, status, nse_stat_str(status),
							parent_node->tnid, op, rlf.factor_idx);

		parent_cir = le16_to_cpu(parent_node->sch_param.cir);

		if (parent_cir > cir) {
			parent_cir -= cir;
			parent_node->sch_param.cir = cpu_to_le16(parent_cir);
		} else {
			parent_node->sch_param.cir = 0;
			parent_node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
		}

		parent_node = parent_node->parent;
	}

out:
	if (!locked)
		mutex_unlock(&si->sched_lock);

	return status;
}

enum nse_status
nse_sched_unset_node_cir(struct nse_port_info *pi, struct nse_sched_node *node, bool locked)
{
	/* no need do anything, because the node is gonna be deleted */
	if (nse_sch_use_cir_transfer)
		return NSE_SUCCESS;
	else
		return nse_sched_unset_node_cir_recursive(pi, node, locked);
}

enum nse_status
nse_sched_set_port_node_pir(struct nse_port_info *pi, bool full)
{
	/* set port node pir according to current PHY speed */
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *node;
	struct nse_sched_rl_factor rlf;
	enum nse_status status = NSE_ERR_PARAM;
	u32 port_bw;

	if (!si->port_node)
		return status;

	if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)	/* don't set port-node PIR for moonstone */
		return NSE_SUCCESS;

	mutex_lock(&si->sched_lock);

	node = si->port_node;

	if (full)
		port_bw = si->max_bandwidth_per_lan_port;
	else
		port_bw = si->max_bandwidth_per_lan_port / 100;		/* 1/100 */

	nse_sched_node_sch_param_compute_pir_cir(pi, port_bw, &rlf);

	status = nse_sched_conf_node_sch_param_pir(hw, node,
				rlf.factor_idx ? NSE_AQC_QOS_SCH_CONF_PIR_OP_SET :
					NSE_AQC_QOS_SCH_CONF_PIR_OP_RESET,
				&rlf);
	if (status) {
		if (rlf.factor_idx)
			node->sch_param.valid_section |= cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID);
		else
			node->sch_param.valid_section &= ~cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID);

		node->sch_param.pir = cpu_to_le16(rlf.factor_idx);
		node->sch_param.pir_factor_int = cpu_to_le16(rlf.factor_int);
		node->sch_param.pir_factor_df_int = cpu_to_le16(rlf.factor_df_int);
		node->sch_param.pir_factor_df_df = cpu_to_le16(rlf.factor_df_df);
	}

	mutex_unlock(&si->sched_lock);

	return status;
}

static enum nse_status
nse_sched_replay_node_bw_pir(struct nse_port_info *pi, struct nse_sched_node *node,
			u32 pir_user_bw)
{
	struct nse_sched_rl_factor rlf;
	enum nse_status status = NSE_SUCCESS;

	nse_sched_node_sch_param_compute_pir_cir(pi, pir_user_bw, &rlf);

	if (rlf.factor_idx)
		status = nse_sched_conf_node_sch_param_pir(pi->hw, node,
							   NSE_AQC_QOS_SCH_CONF_PIR_OP_SET, &rlf);

	return status;
}

static enum nse_status
nse_sched_replay_node_bw_cir_recursive(struct nse_port_info *pi, struct nse_sched_node *node,
			u32 cir_user_bw)
{
	struct device *dev = nse_hw_to_dev(pi->hw);
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *parent_node;
	u16 parent_cir, rlf_cir;
	u8 op;
	u8 conf_status;
	struct nse_sched_rl_factor rlf;
	enum nse_status status = NSE_SUCCESS;

	nse_sched_node_sch_param_compute_pir_cir(pi, cir_user_bw, &rlf);

	if (!rlf.factor_idx)
		return NSE_SUCCESS;

	rlf_cir = rlf.factor_idx;	/* save for later use */

	status = nse_sched_get_node_sch_param(pi->hw, si->port_node->tnid,
					      &si->port_node->sch_param);
	if (status) {
		dev_err(dev, "FAIL: get current sch-param of port-node(TNID=%d)\n",
			si->port_node->tnid);
		status = NSE_ERR_CFG;

		goto out;
	}

	parent_node = node->parent;

	/* check subtree (including port-node) to see if OK to add */
	while (parent_node != si->root) {
		if (parent_node->sch_param.valid_section &
		    le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID)) {
			parent_cir = le16_to_cpu(parent_node->sch_param.cir);

			if ((parent_cir + rlf_cir) > NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL) {
				dev_err(dev, "[%s] a ancestor (tnid=%d, in layer=%d) can not afford ADD this CIR: remain cir=%d (ask cir=%d)\n",
							__func__, parent_node->tnid,
								parent_node->layer_id,
							(NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL -
							 parent_cir), rlf_cir);

				status = NSE_ERR_OUT_OF_RANGE;

				goto out;
			}
		}

		parent_node = parent_node->parent;
	}

	/* conf_cir to all intermediate parent_node and this node itself.
	 */
	parent_node = node;
	while (parent_node != si->root) {
		rlf.factor_idx = le16_to_cpu(parent_node->sch_param.cir) + rlf_cir;

		nse_sched_node_sch_param_compute_pir_cir_by_idx(pi, &rlf);

		op = (rlf.factor_idx) ? NSE_AQC_QOS_SCH_CONF_CIR_OP_SET :
			NSE_AQC_QOS_SCH_CONF_CIR_OP_RESET;
		op = NSE_AQC_QOS_SCH_CONF_CIR_OP_SET;

		status = nse_sched_conf_node_sch_param_cir(pi->hw, parent_node, op,
							   &rlf, &conf_status);
		if (status) {
			dev_err(dev, "[%s] WARN: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
							__func__, status, nse_stat_str(status),
							parent_node->tnid, op, rlf.factor_idx);

			goto out;
		}

		/* no need to sync get port_node's param from HW,
		 * because they are all in this PF instance's control,
		 * so we just update its param in SW-level
		 */
		parent_cir = rlf.factor_idx;

		parent_node->sch_param.cir = cpu_to_le16(parent_cir);

		if (parent_cir)
			parent_node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
		else
			parent_node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_PIR_VALID));

		parent_node = parent_node->parent;
	}

	status = NSE_SUCCESS;

out:
	return status;
}

static enum nse_status
nse_sched_replay_node_bw_cir_direct(struct nse_port_info *pi, struct nse_sched_node *node,
			u32 cir_user_bw)
{
	struct device *dev = nse_hw_to_dev(pi->hw);
	u8 conf_status;
	struct nse_sched_rl_factor rlf;
	enum nse_status status = NSE_SUCCESS;

	nse_sched_node_sch_param_compute_pir_cir(pi, cir_user_bw, &rlf);

	if (!rlf.factor_idx)
		return NSE_SUCCESS;

	status = nse_sched_conf_node_sch_param_cir(pi->hw, node, NSE_AQC_QOS_SCH_CONF_CIR_OP_SET,
						   &rlf, &conf_status);
	if (status) {
		dev_info(dev, "[%s] WARN: status=%d(%s), sched_conf_node_sch_param_cir(node=%d, op=%d, cir=%d)\n",
						__func__, status, nse_stat_str(status),
						node->tnid, NSE_AQC_QOS_SCH_CONF_CIR_OP_SET,
							rlf.factor_idx);
		goto out;
	} else {
		node->sch_param.cir = cpu_to_le16(rlf.factor_idx);
		if (rlf.factor_idx)
			node->sch_param.valid_section |= le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID);
		else
			node->sch_param.valid_section &= ~(le16_to_cpu(NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
	}

out:
	return status;
}

static enum nse_status
nse_sched_replay_node_bw_cir(struct nse_port_info *pi, struct nse_sched_node *node,
			u32 cir_user_bw)
{
	if (nse_sch_use_cir_transfer)
		return nse_sched_replay_node_bw_cir_direct(pi, node, cir_user_bw);
	else
		return nse_sched_replay_node_bw_cir_recursive(pi, node, cir_user_bw);
}

/**
 * nse_sched_replay_node_bw - replay node(s) BW
 * @hw: pointer to the HW struct
 * @node: sched node to configure
 * @bw_t_info: BW type information
 *
 * This function restores node's BW from bw_t_info. The caller needs
 * to hold the scheduler lock.
 */
enum nse_status
nse_sched_replay_node_bw(struct nse_hw *hw, struct nse_sched_node *node,
			 struct nse_bw_type_info *bw_t_info)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_port_info *pi = hw->port_info;
	struct device *dev = nse_hw_to_dev(hw);

	if (!node)
		return NSE_ERR_PARAM;
	if (bitmap_empty(bw_t_info->bw_t_bitmap, NSE_BW_TYPE_CNT))
		return NSE_SUCCESS;

	if (test_bit(NSE_BW_TYPE_PIR, bw_t_info->bw_t_bitmap)) {
		status = nse_sched_replay_node_bw_pir(pi, node, bw_t_info->pir_user_bw);

		if (status)
			dev_warn(dev, "WARN: sched_replay_node_bw_pir(node=%d, pir_user_bw=%d) fail\n",
						node->tnid, bw_t_info->pir_user_bw);
	}

	if (test_bit(NSE_BW_TYPE_CIR, bw_t_info->bw_t_bitmap)) {
		status = nse_sched_replay_node_bw_cir(pi, node, bw_t_info->cir_user_bw);

		if (status)
			dev_warn(dev, "WARN: sched_replay_node_bw_cir(node=%d, cir_user_bw=%d) fail\n",
						node->tnid, bw_t_info->cir_user_bw);
	}

	return status;
}

/**
 * nse_sched_replay_q_bw - replay queue type node BW
 * @pi: port information structure
 * @q_ctx: queue context structure
 *
 * This function replays queue type node bandwidth. This function needs to be
 * called with scheduler lock held.
 */
enum nse_status
nse_sched_replay_q_bw(struct nse_port_info *pi, struct nse_q_ctx *q_ctx)
{
	struct nse_sched_info *si = &pi->sched_info;
	struct nse_sched_node *q_node;

	/* Following also checks the presence of node in tree */
	q_node = nse_sched_find_node_by_tnid(si->root, q_ctx->q_tnid);
	if (!q_node)
		return NSE_ERR_PARAM;
	return nse_sched_replay_node_bw(pi->hw, q_node, &q_ctx->bw_t_info);
}

enum nse_status
nse_sched_replay_vsi_bw(struct nse_hw *hw, u16 vsi_handle,
			unsigned long *tc_bitmap)
{
	struct nse_sched_node *vsi_node, *tc_node;
	struct nse_port_info *pi = hw->port_info;
	struct nse_bw_type_info *bw_t_info;
	struct nse_vsi_ctx *vsi_ctx;
	enum nse_status status = 0;
	u8 tc;

	vsi_ctx = nse_get_vsi_ctx(pi->hw, vsi_handle);
	if (!vsi_ctx)
		return NSE_ERR_PARAM;
	nse_for_each_traffic_class(tc) {
		if (!nse_is_tc_ena(*tc_bitmap, tc))
			continue;
		tc_node = nse_sched_get_tc_node(pi, tc);
		if (!tc_node)
			continue;
		vsi_node = nse_sched_get_vsi_node(pi, tc_node, vsi_handle);
		if (!vsi_node)
			continue;
		bw_t_info = &vsi_ctx->sched.bw_t_info[tc];
		status = nse_sched_replay_node_bw(hw, vsi_node, bw_t_info);
		if (status)
			break;
	}
	return status;
}

void nse_sched_dump_node(struct nse_sched_node *n)
{
	struct nse_hw *hw = (struct nse_hw *)n->hw;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *cur = NULL;

	dev_info(dev, "TNID=%d, in_use=%d\n", n->tnid, n->in_use);
	dev_info(dev, "layer_id=%d\n", n->layer_id);
	if (n->parent)
		dev_info(dev, "parent TNID=%d\n", n->parent->tnid);
	dev_info(dev, "flags=%d\n", n->flags);
	dev_info(dev, "vsi_handle=%d, vsi_abs_id=%d\n", n->vsi_handle, n->vsi_abs_id);
	dev_info(dev, "qid=%d, qid_type=%d\n", n->qid, n->qid_type);
	dev_info(dev, "tc_num=%d\n", n->tc_num);
	dev_info(dev, "owner=%d\n", n->owner);
	dev_info(dev, "num_children=%d\n", n->num_children);
	if (n->num_children) {
		dev_info(dev, "children TNID:\n");
		list_for_each_entry(cur, &n->direct_children_list, direct_sibling) {
			dev_info(dev, "\t %d\n", cur->tnid);
		}
	}

	dev_info(dev, "sch_param:\n");

		dev_info(dev, "\t valid_section=%X\n", le16_to_cpu(n->sch_param.valid_section));
		dev_info(dev, "\t\t ARB_MODE_VALID=%d\n",
			 !!(le16_to_cpu(n->sch_param.valid_section) &
			    NSE_SCH_NODE_PARAM_SECTION_ARB_MODE_VALID));
		dev_info(dev, "\t\t SP_VAL_VALID=%d\n", !!(le16_to_cpu(n->sch_param.valid_section) &
			 NSE_SCH_NODE_PARAM_SECTION_SP_VAL_VALID));
		dev_info(dev, "\t\t NODE_TYPE_VALID=%d\n",
			 !!(le16_to_cpu(n->sch_param.valid_section) &
			    NSE_SCH_NODE_PARAM_SECTION_NODE_TYPE_VALID));
		dev_info(dev, "\t\t PIR_VALID=%d\n", !!(le16_to_cpu(n->sch_param.valid_section) &
			 NSE_SCH_NODE_PARAM_SECTION_PIR_VALID));
		dev_info(dev, "\t\t CIR_VALID=%d\n", !!(le16_to_cpu(n->sch_param.valid_section) &
			 NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
		dev_info(dev, "\t\t TC_VAL_VALID=%d\n", !!(le16_to_cpu(n->sch_param.valid_section) &
			 NSE_SCH_NODE_PARAM_SECTION_TC_VAL_VALID));
		dev_info(dev, "\t\t PORT_ID_VALID=%d\n",
			 !!(le16_to_cpu(n->sch_param.valid_section) &
			    NSE_SCH_NODE_PARAM_SECTION_PORT_ID_VALID));

		dev_info(dev, "\t arb_mode=%d\n", le16_to_cpu(n->sch_param.arb_mode));
		dev_info(dev, "\t sp_val=%d\n", le16_to_cpu(n->sch_param.sp_val));
		dev_info(dev, "\t node_type=%d\n", le16_to_cpu(n->sch_param.node_type));
		dev_info(dev, "\t pir=%d\n", le16_to_cpu(n->sch_param.pir));
		dev_info(dev, "\t cir=%d\n", le16_to_cpu(n->sch_param.cir));
		dev_info(dev, "\t tc_val=%d\n", le16_to_cpu(n->sch_param.tc_val));
		dev_info(dev, "\t port_id=%d\n", le16_to_cpu(n->sch_param.port_id));
}

void nse_sched_dump_node_branch_to_root(struct nse_sched_node *n)
{
	struct nse_hw *hw = (struct nse_hw *)n->hw;
	struct device *dev = nse_hw_to_dev(hw);

	do {
		dev_info(dev, "TNID=%d, layer_id=%d\n",
						n->tnid, n->layer_id);
		n = n->parent;
	} while (n);
}

void nse_sched_dump_node_subtree(struct nse_sched_node *n, unsigned int ident_cnt, char *linebuf)
{
	struct nse_hw *hw = (struct nse_hw *)n->hw;
	struct nse_sched_info *si = &hw->port_info->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *child = NULL;
	unsigned int pos = 0;
	unsigned int i = 0;

	if (!linebuf)
		return;

	for (i = 0; i < ident_cnt; i++)
		pos += sprintf(linebuf + pos, "    ");

	if (n->layer_id == NSE_SCHED_LAYER_ID_PORT) {
		pos += sprintf(linebuf + pos, "(%s, lan_id=%d): ",
						si->layers_info[n->layer_id].layer_name,
						hw->lan_id);
	} else if (n->layer_id == NSE_SCHED_LAYER_ID_TC) {
		pos += sprintf(linebuf + pos, "(%s, TC=%d): ",
						si->layers_info[n->layer_id].layer_name,
						n->tc_num);
	} else if (n->layer_id == si->layer_id_vsi) {
		pos += sprintf(linebuf + pos, "(%s, vsi_handle=%d): ",
						si->layers_info[n->layer_id].layer_name,
						n->vsi_handle);
	} else if (n->layer_id > si->layer_id_vsi &&
				n->layer_id < si->layer_id_leaf) {
		pos += sprintf(linebuf + pos, "(%s, owner=(%d, %s)): ",
						si->layers_info[n->layer_id].layer_name,
						n->owner,
						(n->owner == NSE_SCHED_NODE_OWNER_LAN) ?
							"LAN" : "RDMA");
	} else {
		pos += sprintf(linebuf + pos, "(%s): ",
						si->layers_info[n->layer_id].layer_name);
	}

	pos += sprintf(linebuf + pos, "TNID=%d, SUID=%d, idx_in_su=%d",
					n->tnid, n->suid, n->logic_idx_in_su);

	if (n->layer_id == si->layer_id_leaf) {
		pos += sprintf(linebuf + pos, ", qid=%d, qid_type=%d",
					n->qid, n->qid_type);
	}

	pos += sprintf(linebuf + pos, "\n");

	dev_info(dev, "%s", linebuf);

	list_for_each_entry(child, &n->direct_children_list, direct_sibling) {
		nse_sched_dump_node_subtree(child, ident_cnt+1, linebuf);
	}
}

void nse_sched_dump_layer_infos(struct nse_hw *hw)
{
	int i = 0;
	struct nse_sched_info *si = &hw->port_info->sched_info;
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "sch_layers_num=%d\n", si->layers_num);
	dev_info(dev, "sch_layer_id_sw_entry_point=%d\n", si->layer_id_sw_entry_point);
	dev_info(dev, "sch_layer_id_vsi=%d\n", si->layer_id_vsi);
	dev_info(dev, "sch_layer_id_qgrp=%d\n", si->layer_id_qgrp);
	dev_info(dev, "sch_layer_id_leaf=%d\n", si->layer_id_leaf);

	for (i = 0; i < si->layers_num; i++)
		dev_info(dev, "sch_max_children[%d]=%d\n", i, si->max_children[i]);

	dev_info(dev, "detailed info of each layers:\n");

	for (i = 0; i < si->layers_num; i++) {
		dev_info(dev, "\t layer-%d (%s)\n",
			i, si->layers_info[i].layer_name);

		dev_info(dev, "\t\t layer_id=%d\n",
					si->layers_info[i].layer_id);

		dev_info(dev, "\t\t max_children=%d\n",
					si->layers_info[i].max_children);

		dev_info(dev, "\t\t flags=0x%X\n\n",
					si->layers_info[i].flags);
	}

	dev_info(dev, "TC-nodes of this PF:\n");

	for (i = 0; i < NSE_MAX_TRAFFIC_CLASS; i++) {
		if (si->tc_nodes[i]) {
			dev_info(dev, "\t TC=%d, TNID=%d\n",
								si->tc_nodes[i]->tc_num,
								si->tc_nodes[i]->tnid);
		} else {
			dev_info(dev,
		"\t TC=%d, !!! this TC-node not exist --- FPGA only create less TC-node\n", i);
		}
	}
}

static enum nse_status
nse_sched_init_determine_initial_nodes_tnid(struct nse_hw *hw);

static enum nse_status nse_sched_init_layers_info(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_layer_info *layer_info = NULL;
	struct nse_sched_info *si = &hw->port_info->sched_info;
	u16 dflt_max_children = 0;
	unsigned int i = 0;
	enum nse_status status;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_ASIC) {
			si->tree_scheme = nse_sch_tree_scheme;

			if (si->tree_scheme != NSE_SCH_TREE_SCHEME_10_LAYERS
				&& si->tree_scheme != NSE_SCH_TREE_SCHEME_8_LAYERS) {
				dev_info(dev, "[%s, %d] invalid sch_tree_scheme: %d --- make it to default (8)\n",
						__func__, __LINE__, si->tree_scheme);

				si->tree_scheme = NSE_SCH_TREE_SCHEME_8_LAYERS;
			}

		} else {	/* FPGA */
			si->tree_scheme = NSE_SCH_TREE_SCHEME_7_LAYERS;
		}

	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		si->tree_scheme = NSE_SCH_TREE_SCHEME_6_LAYERS;

	} else {
		dev_err(nse_hw_to_dev(hw), "[%s] unsupported mac_type = %d\n",
			__func__, hw->mac_type);

		return NSE_ERR_NOT_SUPPORTED;
	}

	si->layers_num = si->tree_scheme;	/* also used as number */

	if (si->layers_num == NSE_SCH_TREE_SCHEME_10_LAYERS)
		dflt_max_children = NSE_SCHED_LAYER_MAX_CHILDREN_NUM_8;
	else
		dflt_max_children = NSE_SCHED_LAYER_MAX_CHILDREN_NUM_16;

	memset(si->layers_info, 0, sizeof(si->layers_info));

	i = 0;

	/* all schemes: layer-0: ROOT-layer
	 *
	 *		Root node representing the whole DMA / LAN-Channel
	 */

	layer_info = &si->layers_info[i];

	strscpy(layer_info->layer_name, "ROOT", sizeof(layer_info->layer_name));

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_ASIC)
			layer_info->max_children = NSE_SCHED_LAYER_MAX_CHILDREN_NUM_4;
		else
			layer_info->max_children = NSE_SCHED_LAYER_MAX_CHILDREN_NUM_2;

	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		layer_info->max_children = NSE_SCHED_LAYER_MAX_CHILDREN_NUM_1;
	}

	layer_info->layer_id = i;

	i++;

	layer_info = &si->layers_info[i];

	strscpy(layer_info->layer_name, "PORT", sizeof(layer_info->layer_name));

	/* 8 TC-nodes under a PORT */
	layer_info->max_children = NSE_SCHED_LAYER_MAX_CHILDREN_NUM_8;

	layer_info->layer_id = i;

	i++;

	/* scheme (7, 8, 10): layer-2: TC-layer
	 *
	 *		contains 8 TC-nodes under each PORT-node
	 *
	 * scheme (6): layer-2: TC-layer
	 *
	 *		contains 8 TC-nodes under each ROOT/PORT-node
	 */
	layer_info = &si->layers_info[i];

	strscpy(layer_info->layer_name, "TC", sizeof(layer_info->layer_name));

	layer_info->max_children = dflt_max_children;	/* 8 or 16 nodes under a TC-node */

	layer_info->layer_id = i;

	i++;

	if (si->tree_scheme > NSE_SCH_TREE_SCHEME_6_LAYERS) {
		layer_info = &si->layers_info[i];

		strscpy(layer_info->layer_name, "AGG", sizeof(layer_info->layer_name));

		layer_info->max_children = dflt_max_children;

		/* this layer is sw_entry_point_layer */
		layer_info->flags = NSE_SCHED_LAYER_FLAG_SW_ENTRY_POINT;

		si->layer_id_sw_entry_point = i;

		layer_info->layer_id = i;

		i++;
	}

	if (si->tree_scheme > NSE_SCH_TREE_SCHEME_7_LAYERS) {
		layer_info = &si->layers_info[i];

		snprintf(layer_info->layer_name, 32, "inter-%d", i);

		layer_info->max_children = dflt_max_children;

		layer_info->layer_id = i;

		i++;

		if (si->tree_scheme == NSE_SCH_TREE_SCHEME_10_LAYERS) {
			/* layer-5: a intermediate layer */
			layer_info = &si->layers_info[i];

			snprintf(layer_info->layer_name, 32, "inter-%d", i);

			layer_info->max_children = dflt_max_children;

			layer_info->layer_id = i;

			i++;
		}
	}

	/* scheme (10): layer-6: VSI layer
	 *
	 * scheme (8): layer-5: VSI layer
	 *
	 * scheme (7): layer-4: VSI layer
	 *
	 * scheme (6): layer-3: VSI layer		# also as sch_layer_id_sw_entry_point
	 */

	si->layer_id_vsi = i;

	if (si->tree_scheme == NSE_SCH_TREE_SCHEME_6_LAYERS)
		si->layer_id_sw_entry_point = i;

	layer_info = &si->layers_info[i];

	strscpy(layer_info->layer_name, "VSI", sizeof(layer_info->layer_name));

	layer_info->max_children = dflt_max_children;

	layer_info->layer_id = i;

	i++;

	if (si->tree_scheme == NSE_SCH_TREE_SCHEME_10_LAYERS) {
		/* 10-layers scheme:	layer-7: a intermediate layer */
		layer_info = &si->layers_info[i];

		snprintf(layer_info->layer_name, 32, "inter-%d", i);

		layer_info->max_children = dflt_max_children;

		layer_info->layer_id = i;

		i++;
	}

	/* scheme (10): layer-8: QGRP layer
	 *
	 * scheme (8): layer-6: QGRP layer
	 *
	 * scheme (7): layer-5: QGRP layer
	 *
	 * scheme (6): layer-4: QGRP layer
	 */

	si->layer_id_qgrp = i;

	layer_info = &si->layers_info[i];

	strscpy(layer_info->layer_name, "QGRP", sizeof(layer_info->layer_name));

	layer_info->max_children = dflt_max_children;

	layer_info->layer_id = i;

	i++;

	/* scheme (10): layer-9: LEAF layer
	 *
	 * scheme (8): layer-7: LEAF layer
	 *
	 * scheme (7): layer-6: LEAF layer
	 *
	 * scheme (6): layer-5: LEAF layer
	 */

	si->layer_id_leaf = i;

	layer_info = &si->layers_info[i];

	strscpy(layer_info->layer_name, "LEAF", sizeof(layer_info->layer_name));

	layer_info->max_children = 0;	/* LEAF node does not have children */

	layer_info->layer_id = i;

	i++;

	if (i != si->layers_num) {
		dev_err(dev, "[%s, %d] coding error happen above\n",
				__func__, __LINE__);

		return NSE_ERR_NOT_SUPPORTED;
	}

	for (i = 0; i < si->layers_num; i++)
		si->max_children[i] = si->layers_info[i].max_children;

	status = nse_sched_init_determine_initial_nodes_tnid(hw);

	return status;
}

void nse_sched_clear_layers_info(struct nse_hw *hw)
{
	struct nse_sched_info *si = &hw->port_info->sched_info;

	si->layers_num = 0;
	memset(si->layers_info, 0, sizeof(si->layers_info));

	si->layer_id_sw_entry_point = 0;
	si->layer_id_vsi = 0;
	si->layer_id_qgrp = 0;
	si->layer_id_leaf = 0;

	memset(si->max_children, 0, sizeof(si->max_children));
}

/*  This function is only used for SW-initial-tree, it should be more simple, but write so as a
 * warm-up for link_parent_child()
 */
static void
link_initial_parent_child(struct nse_sched_node *parent, struct nse_sched_node *child)
{
	struct nse_sched_node *near_sibling = NULL;
	struct nse_sched_node *cur = NULL;
	u32 suid;
	int i = 0;

	list_for_each_entry(cur, &parent->direct_children_list, direct_sibling) {
		if ((cur->tnid == (child->tnid + 1)) ||
			(cur->tnid == (child->tnid - 1))) {
			near_sibling = cur;
			break;
		}
	}

	child->parent = parent;
	parent->num_children++;

	if (!near_sibling) {
		/* have existing near_sibling.
		 *
		 * add new child to the tail.
		 */
		list_add_tail(&child->direct_sibling, &parent->direct_children_list);
	} else {
		/* have existing near_sibling.
		 *
		 * try to make their SW-node adjcent.
		 */
		if (near_sibling->tnid == (child->tnid - 1)) {
			/* add new after near_sibling */
			list_add(&child->direct_sibling, &near_sibling->direct_sibling);
		} else {	/* twin_in_same_se->tnid == (child->tnid + 1)*/

			/* add new before twin_in_same_se
			 *
			 *	--- [*] should be familiar with internal of list_add_tail(new, head)
			 *			its internal is: __list_add(new, head->prev, head);
			 *			so its effect is add new before near_sibling.
			 */
			list_add_tail(&child->direct_sibling, &near_sibling->direct_sibling);
		}
	}

	/* get big-brother, it may be changed after new child addition. */
	cur = list_first_entry(&parent->direct_children_list,
			       struct nse_sched_node, direct_sibling);
	suid = (cur->tnid >> 1);

	i = 0;

	list_for_each_entry(child, &parent->direct_children_list, direct_sibling) {
		child->suid = suid;
		child->logic_idx_in_su = i++;

		child->old_suid = child->suid;
		child->old_logic_idx_in_su = child->logic_idx_in_su;
	}
}

static enum nse_status
nse_sched_add_initial_node(struct nse_port_info *pi, unsigned int layer_id,
			   u32 parent_tnid, u32 child_tnid)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_node *new_node = NULL, *parent_node = NULL;
	enum nse_status status;

	mutex_lock(&si->sched_lock);

	if (layer_id >= NSE_SCHED_LAYER_ID_INITIAL_LAYER_MAX) {
		dev_err(dev, "[%s, %d] BAD layer_id = %d\n", __func__, __LINE__, layer_id);
		status = NSE_ERR_PARAM;
		goto out;
	}

	if (layer_id == NSE_SCHED_LAYER_ID_ROOT) {	/* add ROOT-node */

		if (si->root) {
			dev_err(dev, "[%s, %d] SW-ROOT-node already exist\n",
				__func__, __LINE__);
			status = NSE_ERR_EPERM;
			goto out;
		}

		new_node = devm_kzalloc(dev, sizeof(*new_node), GFP_KERNEL);

		if (!new_node) {
			status = NSE_ERR_NO_MEMORY;
			goto out;
		}

		new_node->hw = (struct nse_hw *)hw;
		INIT_LIST_HEAD(&new_node->direct_children_list);
		INIT_LIST_HEAD(&new_node->direct_sibling);

		new_node->layer_id = layer_id;

		new_node->tnid = child_tnid;
		new_node->suid = NSE_SCHED_INITIAL_SE_ROOT_SEID;
		new_node->logic_idx_in_su = 0;

		new_node->flags |= NSE_SCHED_NODE_FLAG_INITIAL_NODE;
		new_node->in_use = true;	/* always in_use */

		si->root = new_node;

	} else {		/* add other non-ROOT initial node */

		if (!si->root) {
			dev_err(dev, "[%s, %d] SW-ROOT-node not created yet\n",
				__func__, __LINE__);
			status = NSE_ERR_NOT_READY;
			goto out;
		}

		parent_node = nse_sched_find_node_by_tnid(si->root, parent_tnid);
		if (!parent_node) {
			dev_err(dev, "[%s, %d] SW-parent-node (tnid=%d) not created yet\n",
							__func__, __LINE__,
							parent_tnid);
			status = NSE_ERR_NOT_READY;
			goto out;
		}

		if (parent_node->num_children >= si->max_children[parent_node->layer_id]) {
			dev_err(dev, "[%s, %d] SW-parent-node (tnid=%d) can not add new child-node, parent layer_id=%d, parent_max_chidren=%d\n",
							__func__, __LINE__,
				parent_tnid, parent_node->layer_id,
					si->max_children[parent_node->layer_id]);
			status = NSE_ERR_MAX_LIMIT;
			goto out;
		}

		new_node = devm_kzalloc(dev, sizeof(*new_node), GFP_KERNEL);
		if (!new_node) {
			status = NSE_ERR_NO_MEMORY;
			goto out;
		}

		new_node->hw = (struct nse_hw *)hw;
		INIT_LIST_HEAD(&new_node->direct_children_list);
		INIT_LIST_HEAD(&new_node->direct_sibling);

		new_node->layer_id = layer_id;

		new_node->tnid = child_tnid;

		new_node->flags |= NSE_SCHED_NODE_FLAG_INITIAL_NODE;
		new_node->in_use = true;	/* always in_use */

		link_initial_parent_child(parent_node, new_node);
	}

	status = NSE_SUCCESS;

out:
	mutex_unlock(&si->sched_lock);

	return status;
}

static enum nse_status
nse_sched_init_sw_initial_tree_amber_fpga(struct nse_port_info *pi)
{
	enum nse_status status;
	u32 i;

	/* ROOT-layer */
	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_ROOT,
											0,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID);
	if (status)
		goto out;

	/* PORT-layer */
	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_PORT,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID,
					    NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_0_TNID);
	if (status)
		goto out;

	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_PORT,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID,
					    NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_1_TNID);
	if (status)
		goto out;

	/* TC-layer */
	for (i = NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_0_TC_TNID_START;
			i < NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_0_TC_TNID_END;
			i++) {
		status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_TC,
						    NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_0_TNID,
												i);
		if (status)
			goto out;
	}

	for (i = NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_1_TC_TNID_START;
			i < NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_1_TC_TNID_END;
			i++) {
		status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_TC,
						    NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_1_TNID,
												i);
		if (status)
			goto out;
	}

	status = NSE_SUCCESS;

out:
	return status;
}

static enum nse_status
nse_sched_init_determine_initial_nodes_tnid_amber_fpga(struct nse_hw *hw)
{
	struct nse_sched_info *si = &hw->port_info->sched_info;
	u32 port_node_tnid;
	u32 tc_node_start, tc_node_end;

	if (!(hw->lan_id & 0x1)) {	/* LAN-0 in channel */
		port_node_tnid = NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_0_TNID;
		tc_node_start = NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_0_TC_TNID_START;
		tc_node_end = NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_0_TC_TNID_END;
	} else {
		port_node_tnid = NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_1_TNID;
		tc_node_start = NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_1_TC_TNID_START;
		tc_node_end = NSE_AMBER_FPGA_SCHED_INITIAL_NODE_PORT_1_TC_TNID_END;
	}

	si->port_node_tnid = port_node_tnid;
	si->tc_node_tnid_start = tc_node_start;
	si->tc_node_tnid_end = tc_node_end;

	return NSE_SUCCESS;
}

static enum nse_status
nse_sched_init_sw_initial_tree_amber_asic(struct nse_port_info *pi)
{
	enum nse_status status;
	u32 i;

	/* ROOT-layer */
	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_ROOT,
											0,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID);
	if (status)
		goto out;

	/* PORT-layer */
	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_PORT,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID,
					    NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_0_TNID);
	if (status)
		goto out;

	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_PORT,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID,
					    NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_1_TNID);
	if (status)
		goto out;

	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_PORT,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID,
					    NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_2_TNID);
	if (status)
		goto out;

	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_PORT,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID,
					    NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_3_TNID);
	if (status)
		goto out;

	/* TC-layer */
	for (i = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_0_TC_TNID_START;
			i < NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_0_TC_TNID_END;
			i++) {
		status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_TC,
						    NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_0_TNID,
												i);
		if (status)
			goto out;
	}

	for (i = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_1_TC_TNID_START;
			i < NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_1_TC_TNID_END;
			i++) {
		status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_TC,
						    NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_1_TNID,
												i);
		if (status)
			goto out;
	}

	for (i = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_2_TC_TNID_START;
			i < NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_2_TC_TNID_END;
			i++) {
		status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_TC,
						    NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_2_TNID,
												i);
		if (status)
			goto out;
	}

	for (i = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_3_TC_TNID_START;
			i < NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_3_TC_TNID_END;
			i++) {
		status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_TC,
						    NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_3_TNID,
												i);
		if (status)
			goto out;
	}

	status = NSE_SUCCESS;

out:
	return status;
}

static enum nse_status
nse_sched_init_determine_initial_nodes_tnid_amber_asic(struct nse_hw *hw)
{
	struct nse_sched_info *si = &hw->port_info->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	u32 port_node_tnid;
	u32 tc_node_start, tc_node_end;

	if (hw->lan_id == 0) {
		port_node_tnid = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_0_TNID;
		tc_node_start = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_0_TC_TNID_START;
		tc_node_end = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_0_TC_TNID_END;
	} else if (hw->lan_id == 1) {
		port_node_tnid = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_1_TNID;
		tc_node_start = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_1_TC_TNID_START;
		tc_node_end = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_1_TC_TNID_END;
	} else if (hw->lan_id == 2) {
		port_node_tnid = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_2_TNID;
		tc_node_start = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_2_TC_TNID_START;
		tc_node_end = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_2_TC_TNID_END;
	} else if (hw->lan_id == 3) {
		port_node_tnid = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_3_TNID;
		tc_node_start = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_3_TC_TNID_START;
		tc_node_end = NSE_AMBER_ASIC_SCHED_INITIAL_NODE_PORT_3_TC_TNID_END;
	} else {
		dev_err(dev, "[%s, %d] BAD hw->lan_id=%d\n", __func__, __LINE__, hw->lan_id);
		return NSE_ERR_PARAM;
	}

	si->port_node_tnid = port_node_tnid;
	si->tc_node_tnid_start = tc_node_start;
	si->tc_node_tnid_end = tc_node_end;

	return NSE_SUCCESS;
}

static enum nse_status
nse_sched_init_sw_initial_tree_moonstone(struct nse_port_info *pi)
{
	enum nse_status status;
	u32 i;

	/* ROOT-layer */
	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_ROOT,
											0,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID);
	if (status)
		goto out;

	/* PORT-layer */
	status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_PORT,
					    NSE_SCHED_INITIAL_NODE_ROOT_TNID,
					    NSE_MOONSTONE_SCHED_INITIAL_NODE_PORT_0_TNID);
	if (status)
		goto out;

	/* TC-layer */
	for (i = NSE_MOONSTONE_SCHED_INITIAL_NODE_PORT_0_TC_TNID_START;
			i < NSE_MOONSTONE_SCHED_INITIAL_NODE_PORT_0_TC_TNID_END;
			i++) {
		status = nse_sched_add_initial_node(pi, NSE_SCHED_LAYER_ID_TC,
						    NSE_MOONSTONE_SCHED_INITIAL_NODE_PORT_0_TNID,
												i);
		if (status)
			goto out;
	}

	status = NSE_SUCCESS;

out:
	return status;
}

static enum nse_status
nse_sched_init_determine_initial_nodes_tnid_moonstone(struct nse_hw *hw)
{
	struct nse_sched_info *si = &hw->port_info->sched_info;
	u32 port_node_tnid;
	u32 tc_node_start, tc_node_end;

	port_node_tnid = NSE_MOONSTONE_SCHED_INITIAL_NODE_PORT_0_TNID;
	tc_node_start = NSE_MOONSTONE_SCHED_INITIAL_NODE_PORT_0_TC_TNID_START;
	tc_node_end = NSE_MOONSTONE_SCHED_INITIAL_NODE_PORT_0_TC_TNID_END;

	si->port_node_tnid = port_node_tnid;
	si->tc_node_tnid_start = tc_node_start;
	si->tc_node_tnid_end = tc_node_end;

	return NSE_SUCCESS;
}

enum nse_status
nse_sched_init_sw_initial_tree(struct nse_port_info *pi)
{
	struct nse_hw *hw = pi->hw;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_ASIC)
			return nse_sched_init_sw_initial_tree_amber_asic(pi);
		else
			return nse_sched_init_sw_initial_tree_amber_fpga(pi);

	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		return nse_sched_init_sw_initial_tree_moonstone(pi);

	} else {
		dev_err(nse_hw_to_dev(hw), "[%s] unsupported mac_type = %d\n",
			__func__, hw->mac_type);

		return NSE_ERR_NOT_SUPPORTED;
	}
}

static enum nse_status
nse_sched_init_determine_initial_nodes_tnid(struct nse_hw *hw)
{
	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_ASIC)
			return nse_sched_init_determine_initial_nodes_tnid_amber_asic(hw);
		else
			return nse_sched_init_determine_initial_nodes_tnid_amber_fpga(hw);

	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		return nse_sched_init_determine_initial_nodes_tnid_moonstone(hw);

	} else {
		dev_err(nse_hw_to_dev(hw), "[%s] unsupported mac_type = %d\n",
			__func__, hw->mac_type);

		return NSE_ERR_NOT_SUPPORTED;
	}
}

static enum nse_status
nse_sched_init_determine_initial_nodes(struct nse_port_info *pi)
{
	struct nse_hw *hw = pi->hw;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_info *si = &pi->sched_info;
	u32 port_node_tnid;
	u32 tc_node_start, tc_node_end;
	u8 tc = 0;
	enum nse_status status = NSE_ERR_DOES_NOT_EXIST;

	port_node_tnid = si->port_node_tnid;
	tc_node_start = si->tc_node_tnid_start;
	tc_node_end = si->tc_node_tnid_end;

	mutex_lock(&si->sched_lock);

	si->port_node = nse_sched_find_node_by_tnid(si->root, port_node_tnid);
	if (!si->port_node) {
		dev_err(dev, "[%s] port_node (TNID=%d) not found\n",
						__func__, port_node_tnid);
		status = NSE_ERR_DOES_NOT_EXIST;
		goto out;
	}

	status = nse_sched_get_node_sch_param(hw, si->port_node->tnid, &si->port_node->sch_param);
	if (status) {
		dev_err(dev, "[%s] port_node (TNID=%d) param FAIL to get\n",
						__func__, port_node_tnid);
		goto out;
	}

	for (tc = 0; tc_node_start < tc_node_end; tc++, tc_node_start++) {
		si->tc_nodes[tc] = nse_sched_find_node_by_tnid(si->root, tc_node_start);

		if (!si->tc_nodes[tc]) {
			dev_err(dev, "[%s] tc_node (TNID=%d, tc=%d) not found\n",
						__func__, tc_node_start, tc);
			status = NSE_ERR_DOES_NOT_EXIST;
			goto out;
		}

		status = nse_sched_get_node_sch_param(hw,
						si->tc_nodes[tc]->tnid,
						&si->tc_nodes[tc]->sch_param);
		if (status) {
			dev_err(dev, "[%s] tc_node (TNID=%d, tc=%d) param FAIL to get\n",
						__func__, tc_node_start, tc);
			goto out;
		}

		si->tc_nodes[tc]->tc_num = tc;
	}

	status = NSE_SUCCESS;

out:
	mutex_unlock(&si->sched_lock);

	return status;
}

static enum nse_status nse_sched_init_port(struct nse_port_info *pi)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status;

	nse_sched_init_factor_tbl(pi);

	mutex_init(&si->sched_lock);

	status = nse_sched_init_sw_initial_tree(pi);
	if (status) {
		dev_err(dev, "FAIL: sched_init_sw_initial_tree(), status=%d(%s)\n",
			status, nse_stat_str(status));
		goto out;
	}

	status = nse_sched_init_determine_initial_nodes(pi);
	if (status) {
		dev_err(dev, "FAIL: sched_init_determine_initial_nodes(), status=%d(%s)\n",
			status, nse_stat_str(status));
		goto out;
	}

	status = nse_sched_set_port_node_pir(pi, true);
	if (status)	/* don't consider a error, just warn */
		dev_warn(dev, "WARN: sched_set_port_node_pir(), status=%d(%s)\n",
			 status, nse_stat_str(status));

	pi->sched_info.sched_state = NSE_SCHED_STATE_READY;

	status = NSE_SUCCESS;

out:
	if (status && si->root) {
		nse_free_sched_node(pi, si->root, NULL);
		si->root = NULL;
	}

	return status;
}

/**
 * nse_sched_clear_tx_topo - clears the scheduler tree nodes
 * @pi: port information structure
 *
 * This function removes all the nodes from HW as well as from SW DB.
 */
static void nse_sched_clear_tx_topo(struct nse_port_info *pi)
{
	struct nse_sched_info *si;

	if (!pi)
		return;

	si = &pi->sched_info;

	if (si->root) {
		nse_free_sched_node(pi, si->root, NULL);
		si->root = NULL;
	}
}

/**
 * nse_sched_clear_port - clear the scheduler elements from SW DB for a port
 * @pi: port information structure
 *
 * Cleanup scheduling elements from SW DB
 */
void nse_sched_clear_port(struct nse_port_info *pi)
{
	struct nse_hw *hw;
	struct nse_sched_info *si;

	if (!pi)
		return;

	hw = pi->hw;
	si = &pi->sched_info;

	if (si->sched_state != NSE_SCHED_STATE_READY)
		return;

	pi->sched_info.sched_state = NSE_SCHED_STATE_INIT;

	mutex_lock(&si->sched_lock);

	nse_sched_clear_tx_topo(pi);

	memset(si->tc_nodes, 0, sizeof(si->tc_nodes));

	mutex_unlock(&si->sched_lock);
	mutex_destroy(&si->sched_lock);
}

/**
 * nse_sched_cleanup_all - cleanup scheduler elements from SW DB for all ports
 * @hw: pointer to the HW struct
 *
 * Cleanup scheduling elements from SW DB for all the ports
 */
void nse_sched_cleanup_all(struct nse_hw *hw)
{
	if (!hw)
		return;

	nse_sched_clear_port(hw->port_info);

	nse_sched_clear_layers_info(hw);
}

enum nse_status nse_sched_init(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status;

	status = nse_sched_set_bypass(hw, nse_bypass_sched);
	if (status) {
		dev_err(dev, "FAIL: sched_set_bypass(%d): %d (%s)\n",
						status, nse_bypass_sched, nse_stat_str(status));
		goto out;
	}

	status = nse_sched_init_layers_info(hw);
	if (status) {
		dev_err(dev, "FAIL: sched_init_layers_info(): %d (%s)\n",
						status, nse_stat_str(status));
		goto out;
	}

	status = nse_sched_aqc_pf_init(hw);
	if (status) {
		dev_err(dev, "FAIL: sched_aqc_pf_init(): %d (%s)\n",
						status, nse_stat_str(status));
		goto out;
	}

	/* Initialize port_info struct with scheduler data */
	status = nse_sched_init_port(hw->port_info);
	if (status) {
		dev_err(dev, "FAIL: sched_init_port(): %d (%s)\n",
						status, nse_stat_str(status));
		goto out;
	}

out:
	return status;
}

