// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "hclge_comm_unic_addr.h"

static struct hclge_comm_unic_addr_node *
hclge_comm_unic_find_addr_node(struct list_head *list, const u8 *addr)
{
	struct hclge_comm_unic_addr_node *addr_node, *tmp;

	list_for_each_entry_safe(addr_node, tmp, list, node)
		if (hclge_comm_unic_addr_equal((const u8 *)&addr_node->unic_addr,
					       addr))
			return addr_node;

	return NULL;
}

static void
hclge_comm_unic_update_addr_node(struct hclge_comm_unic_addr_node *addr_node,
				 enum HCLGE_COMM_ADDR_NODE_STATE state)
{
	switch (state) {
	/* from set_rx_mode or tmp_add_list */
	case HCLGE_COMM_UNIC_ADDR_TO_ADD:
		if (addr_node->state == HCLGE_COMM_UNIC_ADDR_TO_DEL)
			addr_node->state = HCLGE_COMM_UNIC_ADDR_ACTIVE;
		break;
	/* only from set_rx_mode */
	case HCLGE_COMM_UNIC_ADDR_TO_DEL:
		if (addr_node->state == HCLGE_COMM_UNIC_ADDR_TO_ADD) {
			list_del(&addr_node->node);
			kfree(addr_node);
		} else {
			addr_node->state = HCLGE_COMM_UNIC_ADDR_TO_DEL;
		}
		break;
	/* only from tmp_add_list, the addr_node->state won't be
	 * ACTIVE.
	 */
	case HCLGE_COMM_UNIC_ADDR_ACTIVE:
		if (addr_node->state == HCLGE_COMM_UNIC_ADDR_TO_ADD)
			addr_node->state = HCLGE_COMM_UNIC_ADDR_ACTIVE;
		break;
	}
}

void hclge_comm_unic_sync_from_addr_del_list(struct list_head *del_list,
					     struct list_head *addr_list)
{
	struct hclge_comm_unic_addr_node *addr_node, *tmp, *new_node;

	list_for_each_entry_safe(addr_node, tmp, del_list, node) {
		new_node = hclge_comm_unic_find_addr_node(addr_list,
							  addr_node->unic_addr);
		if (new_node) {
			/* If the addr exists in the addr list, it means
			 * received a new TO_ADD request during the time window
			 * of configuring the addr, so we just need
			 * to change the addr node state to ACTIVE.
			 */
			new_node->state = HCLGE_COMM_UNIC_ADDR_ACTIVE;
			list_del(&addr_node->node);
			kfree(addr_node);
		} else {
			list_move_tail(&addr_node->node, addr_list);
		}
	}
}

static void
hclge_comm_unic_sync_from_addr_add_list(struct list_head *add_list,
					struct list_head *addr_list,
					bool *all_added)
{
	struct hclge_comm_unic_addr_node *addr_node, *tmp, *new_node;

	list_for_each_entry_safe(addr_node, tmp, add_list, node) {
		if (*all_added &&
		    addr_node->state == HCLGE_COMM_UNIC_ADDR_TO_ADD)
			*all_added = false;

		/* If the addr from tmp_add_list is not in the
		 * addr_list, it means have received a TO_DEL request
		 * during the time window of adding the addr. If addr_node
		 * state is ACTIVE, then change its state to TO_DEL,
		 * then it will be removed at next time. If is TO_ADD,
		 * it means this address hasn't been added successfully,
		 * so just remove the addr node.
		 */
		new_node = hclge_comm_unic_find_addr_node(addr_list,
							  addr_node->unic_addr);
		if (new_node) {
			hclge_comm_unic_update_addr_node(new_node,
							 addr_node->state);
			list_del(&addr_node->node);
			kfree(addr_node);
		} else if (addr_node->state == HCLGE_COMM_UNIC_ADDR_ACTIVE) {
			addr_node->state = HCLGE_COMM_UNIC_ADDR_TO_DEL;
			list_move_tail(&addr_node->node, addr_list);
		} else {
			list_del(&addr_node->node);
			kfree(addr_node);
		}
	}
}

int hclge_comm_unic_update_addr_list(struct list_head *list,
				     spinlock_t *addr_list_lock,
				     enum HCLGE_COMM_ADDR_NODE_STATE state,
				     const unsigned char *addr)
{
	struct hclge_comm_unic_addr_node *addr_node;

	spin_lock_bh(addr_list_lock);

	/* if the addr is already in the addr list, no need to add a new
	 * one into it, just check the addr state, convert it to a new
	 * state, or just remove it, or do nothing.
	 */
	addr_node = hclge_comm_unic_find_addr_node(list, addr);
	if (addr_node) {
		hclge_comm_unic_update_addr_node(addr_node, state);
		spin_unlock_bh(addr_list_lock);
		return 0;
	}

	/* if this addr is never added, unnecessary to delete */
	if (state == HCLGE_COMM_UNIC_ADDR_TO_DEL) {
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

bool hclge_comm_unic_sync_addr_table(struct hnae3_handle *handle,
				     struct list_head *list,
				     spinlock_t *addr_list_lock,
				     void (*sync)(struct hnae3_handle *,
						  struct list_head *),
				     void (*unsync)(struct hnae3_handle *,
						    struct list_head *))
{
	struct hclge_comm_unic_addr_node *addr_node, *tmp, *new_node;
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
		case HCLGE_COMM_UNIC_ADDR_TO_DEL:
			list_move_tail(&addr_node->node, &tmp_del_list);
			break;
		case HCLGE_COMM_UNIC_ADDR_TO_ADD:
			new_node = kzalloc(sizeof(*new_node), GFP_ATOMIC);
			if (!new_node)
				goto stop_traverse;
			memcpy(new_node->unic_addr, addr_node->unic_addr,
			       UNIC_ADDR_LEN);
			new_node->state = addr_node->state;
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
		unsync(handle, &tmp_del_list);
	if (sync)
		sync(handle, &tmp_add_list);

	/* if some addr were added/deleted fail, move back to the
	 * addr_list, and retry at next time.
	 */
	spin_lock_bh(addr_list_lock);

	hclge_comm_unic_sync_from_addr_del_list(&tmp_del_list, list);
	hclge_comm_unic_sync_from_addr_add_list(&tmp_add_list, list,
						&all_added);

	spin_unlock_bh(addr_list_lock);

	return all_added;
}

int hclge_comm_unic_convert_ip_addr(const struct sockaddr *addr,
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
		return -EINVAL;
	}
	return 0;
}

static void
hclge_comm_unic_func_guid_cmd_prepare(u8 *guid,
				      struct hclge_comm_func_guid_cmd *req)
{
	req->entry_vld = HCLGE_COMM_FUNC_GUID_ENTRY_VALID_EN;
	memcpy(req->guid, guid, UBL_ALEN);
}

void hclge_comm_unic_set_func_guid(struct hclge_comm_hw *hw, u8 **guid)
{
	struct hclge_comm_func_guid_cmd *req;
	struct hclge_desc desc;
	int ret;

	if (!*guid)
		return;

	req = (struct hclge_comm_func_guid_cmd *)desc.data;

	hclge_comm_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMM_CFG_FUNC_GUID,
					false);
	hclge_comm_unic_func_guid_cmd_prepare(*guid, req);

	ret = hclge_comm_cmd_send(hw, &desc, 1);
	if (ret)
		dev_warn(&hw->cmq.csq.pdev->dev,
			 "set guid failed for cmd_send, ret = %d.\n", ret);
	else
		*guid = NULL;
}

void hclge_comm_unic_rm_func_guid(struct hclge_comm_hw *hw, u8 **guid)
{
	struct hclge_comm_func_guid_cmd *req;
	struct hclge_desc desc;
	int ret;

	if (*guid)
		return;

	req = (struct hclge_comm_func_guid_cmd *)desc.data;

	hclge_comm_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMM_CFG_FUNC_GUID,
					false);
	req->entry_vld = 0;
	ret = hclge_comm_cmd_send(hw, &desc, 1);
	if (ret)
		dev_warn(&hw->cmq.csq.pdev->dev,
			 "failed to delete func guid for cmd_send, ret = %d.\n",
			 ret);
}

static bool hclge_comm_unic_is_valid_func_guid(u8 *guid)
{
	u8 invalid_guid_zero[UBL_ALEN] = {0};
	u8 invalid_guid_all_one[UBL_ALEN];

	memset(invalid_guid_all_one, 0xff, UBL_ALEN);
	if (!(memcmp(guid, invalid_guid_all_one, HCLGE_COMM_MGUID_PREFIX_LEN) &&
	      memcmp(guid, invalid_guid_zero, UBL_ALEN)))
		return false;

	return true;
}

static void hclge_comm_unic_guid_le_to_net_trans(u8 *src_guid, u8 *dest_guid)
{
	int i;

	for (i = 0; i < UBL_ALEN; i++)
		dest_guid[i] = src_guid[UBL_ALEN - i - 1];
}

int hclge_comm_unic_get_func_guid(struct hclge_comm_hw *hw, u8 *guid)
{
	struct hclge_desc desc;
	bool is_random = false;
	int ret;

	hclge_comm_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMM_GET_FUNC_GUID,
					true);
	ret = hclge_comm_cmd_send(hw, &desc, 1);
	if (ret) {
		dev_err(&hw->cmq.csq.pdev->dev,
			"failed to get function GUID, ret = %d\n", ret);
		return ret;
	}

	hclge_comm_unic_guid_le_to_net_trans((u8 *)desc.data, guid);
	while (unlikely(!hclge_comm_unic_is_valid_func_guid(guid))) {
		get_random_bytes(guid, UBL_ALEN);
		is_random = true;
	}

	if (unlikely(is_random))
		dev_warn(&hw->cmq.csq.pdev->dev,
			 "using random GUID %02x:%02x:...:%02x:%02x\n",
			 guid[0], guid[1],
			 guid[UBL_ALEN - 2], guid[UBL_ALEN - 1]);

	return 0;
}
