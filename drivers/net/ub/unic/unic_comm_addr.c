// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <net/ipv6.h>
#include <linux/spinlock.h>

#include "unic_comm_addr.h"

struct unic_comm_addr_node *
unic_comm_find_addr_node(struct list_head *list, const u8 *addr, u16 node_mask)
{
	struct unic_comm_addr_node *addr_node, *tmp;

	list_for_each_entry_safe(addr_node, tmp, list, node) {
		if (unic_comm_addr_equal(addr_node->unic_addr, addr,
					 addr_node->node_mask, node_mask))
			return addr_node;
	}

	return NULL;
}

void unic_comm_update_addr_state(struct unic_comm_addr_node *addr_node,
				 enum UNIC_COMM_ADDR_STATE state)
{
	switch (state) {
	case UNIC_COMM_ADDR_TO_ADD:
		if (addr_node->state == UNIC_COMM_ADDR_TO_DEL)
			addr_node->state = UNIC_COMM_ADDR_ACTIVE;
		break;
	case UNIC_COMM_ADDR_TO_DEL:
		if (addr_node->state == UNIC_COMM_ADDR_TO_ADD) {
			list_del(&addr_node->node);
			kfree(addr_node);
		} else {
			addr_node->state = UNIC_COMM_ADDR_TO_DEL;
		}
		break;
	case UNIC_COMM_ADDR_ACTIVE:
		if (addr_node->state == UNIC_COMM_ADDR_TO_ADD)
			addr_node->state = UNIC_COMM_ADDR_ACTIVE;
		break;
	default:
		break;
	}
}

int unic_comm_update_addr_list(struct list_head *list,
			       spinlock_t *addr_list_lock,
			       enum UNIC_COMM_ADDR_STATE state,
			       const u8 *addr)
{
	struct unic_comm_addr_node *addr_node;

	spin_lock_bh(addr_list_lock);

	/* if the addr is already in the addr list, no need to add a new
	 * one into it, just check the addr state, convert it to a new
	 * state, or just remove it, or do nothing.
	 */
	addr_node = unic_comm_find_addr_node(list, addr, UNIC_COMM_ADDR_NO_MASK);
	if (addr_node) {
		unic_comm_update_addr_state(addr_node, state);
		spin_unlock_bh(addr_list_lock);
		return 0;
	}

	/* if this addr is never added, unnecessary to delete */
	if (state == UNIC_COMM_ADDR_TO_DEL) {
		spin_unlock_bh(addr_list_lock);
		return -ENOENT;
	}

	addr_node = kzalloc(sizeof(*addr_node), GFP_ATOMIC);
	if (!addr_node) {
		spin_unlock_bh(addr_list_lock);
		return -ENOMEM;
	}

	addr_node->state = state;
	memcpy(addr_node->unic_addr, addr, UNIC_ADDR_LEN);
	list_add_tail(&addr_node->node, list);

	spin_unlock_bh(addr_list_lock);

	return 0;
}

void unic_comm_sync_from_addr_del_list(struct list_head *del_list,
				       struct list_head *addr_list)
{
	struct unic_comm_addr_node *addr_node, *tmp, *new_node;

	list_for_each_entry_safe(addr_node, tmp, del_list, node) {
		new_node = unic_comm_find_addr_node(addr_list,
						    addr_node->unic_addr,
						    UNIC_COMM_ADDR_NO_MASK);
		if (new_node) {
			/* If the addr exists in the addr list, it means
			 * received a new TO_ADD request during the time window
			 * of configuring the addr, so we just need
			 * to change the addr node state to ACTIVE.
			 */
			new_node->state = UNIC_COMM_ADDR_ACTIVE;
			list_del(&addr_node->node);
			kfree(addr_node);
		} else {
			list_move_tail(&addr_node->node, addr_list);
		}
	}
}

void unic_comm_sync_from_addr_add_list(struct list_head *add_list,
				       struct list_head *addr_list,
				       bool *all_added)
{
	struct unic_comm_addr_node *addr_node, *tmp, *new_node;

	list_for_each_entry_safe(addr_node, tmp, add_list, node) {
		if (*all_added && addr_node->state == UNIC_COMM_ADDR_TO_ADD)
			*all_added = false;

		/* If the addr from tmp_add_list is not in the
		 * addr_list, it means have received a TO_DEL request
		 * during the time window of adding the addr. If addr_node
		 * state is ACTIVE, then change its state to TO_DEL,
		 * then it will be removed at next time. If is TO_ADD,
		 * it means this address hasn't been added successfully,
		 * so just remove the addr node.
		 */
		new_node = unic_comm_find_addr_node(addr_list,
						    addr_node->unic_addr,
						    UNIC_COMM_ADDR_NO_MASK);
		if (new_node) {
			unic_comm_update_addr_state(new_node, addr_node->state);
			list_del(&addr_node->node);
			kfree(addr_node);
		} else if (addr_node->state == UNIC_COMM_ADDR_ACTIVE) {
			addr_node->state = UNIC_COMM_ADDR_TO_DEL;
			list_move_tail(&addr_node->node, addr_list);
		} else {
			list_del(&addr_node->node);
			kfree(addr_node);
		}
	}
}

bool unic_comm_sync_addr_table(struct unic_vport *vport,
			       struct list_head *list,
			       spinlock_t *addr_list_lock,
			       void (*sync)(struct unic_vport *vport,
					    struct list_head *list),
			       void (*unsync)(struct unic_vport *vport,
					      struct list_head *list))
{
	struct unic_comm_addr_node *addr_node, *tmp, *new_node;
	struct list_head tmp_add_list, tmp_del_list;
	bool all_added = true;

	INIT_LIST_HEAD(&tmp_add_list);
	INIT_LIST_HEAD(&tmp_del_list);

	/* move the addr to the tmp_add_list and tmp_del_list, then
	 * we can add/delete these addr outside the spin lock
	 */
	spin_lock_bh(addr_list_lock);

	list_for_each_entry_safe(addr_node, tmp, list, node) {
		switch (addr_node->state) {
		case UNIC_COMM_ADDR_TO_DEL:
			list_move_tail(&addr_node->node, &tmp_del_list);
			break;
		case UNIC_COMM_ADDR_TO_ADD:
			new_node = kzalloc(sizeof(*new_node), GFP_ATOMIC);
			if (!new_node)
				goto stop_traverse;
			memcpy(new_node->unic_addr, addr_node->unic_addr,
			       UNIC_ADDR_LEN);
			new_node->state = addr_node->state;
			new_node->is_pfc = addr_node->is_pfc;
			new_node->node_mask = addr_node->node_mask;
			list_add_tail(&new_node->node, &tmp_add_list);
			break;
		default:
			break;
		}
	}

stop_traverse:
	spin_unlock_bh(addr_list_lock);

	/* delete first, in order to get max addr table space for adding */
	if (unsync)
		unsync(vport, &tmp_del_list);
	if (sync)
		sync(vport, &tmp_add_list);

	/* if some addr were added/deleted fail, move back to the
	 * addr_list, and retry at next time.
	 */
	spin_lock_bh(addr_list_lock);

	unic_comm_sync_from_addr_del_list(&tmp_del_list, list);
	unic_comm_sync_from_addr_add_list(&tmp_add_list, list, &all_added);

	spin_unlock_bh(addr_list_lock);

	return all_added;
}

int unic_convert_ip_addr(struct unic_dev *unic_dev, struct sockaddr *addr,
			 struct in6_addr *ip_addr)
{
	__be32 v4addr;

	switch (addr->sa_family) {
	case AF_INET:
		/* we transform ipv4 addr to ipv6 addr for later configuring */
		v4addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
		ipv6_addr_set_v4mapped(v4addr, ip_addr);
		break;
	case AF_INET6:
		memcpy(ip_addr, &((struct sockaddr_in6 *)addr)->sin6_addr,
		       sizeof(struct in6_addr));
		break;
	default:
		unic_err(unic_dev, "invalid IP protocol type, sa_family = %u.\n",
			 addr->sa_family);
		return -EINVAL;
	}
	return 0;
}
