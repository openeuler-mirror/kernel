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

#include <linux/inet.h>
#include <linux/in6.h>
#include <net/ipv6.h>

#include "hclgevf_main.h"
#include "hclge_comm_unic_addr.h"
#include "hclge_mbx.h"
#include "hclgevf_unic_ip.h"

int hclgevf_unic_update_ip_list(struct hnae3_handle *handle,
				enum HCLGE_COMM_ADDR_NODE_STATE state,
				const struct sockaddr *addr)
{
	struct hclgevf_dev *hdev = container_of(handle, struct hclgevf_dev, nic);
	struct in6_addr ip_addr;
	int ret;

	hclge_comm_unic_convert_ip_addr(addr, &ip_addr);

	ret = hclge_comm_unic_update_addr_list(&hdev->ip_table.ip_list,
					       &hdev->ip_table.ip_list_lock,
					       state,
					       (const unsigned char *)&ip_addr);
	if (ret == -ENOENT)
		dev_err(&hdev->pdev->dev,
			"failed to delete ip %pI6c from ip list\n",
			ip_addr.s6_addr);

	return ret;
}

static void
hclgevf_unic_prepare_ip_msg(u8 code, int index,
			    struct hclge_comm_unic_addr_node *ip_node,
			    struct hclge_vf_to_pf_msg *send_msg)
{
	memset(send_msg, 0, sizeof(struct hclge_vf_to_pf_msg));
	send_msg->code = code;

	if (ip_node->state == HCLGE_COMM_UNIC_ADDR_TO_ADD)
		send_msg->subcode = HCLGE_UNIC_MBX_IP_TABLE_ADD;
	else
		send_msg->subcode = HCLGE_UNIC_MBX_IP_TABLE_REMOVE;

	if (index == 0) {
		send_msg->data[0] = HCLGE_COMM_UNIC_IPV6_UPPER_LEN;
		memcpy(&send_msg->data[HCLGE_COMM_UNIC_MSG_IPADDR_POS],
		       &ip_node->ip_addr.s6_addr,
		       sizeof(u8) * HCLGE_COMM_UNIC_IPV6_UPPER_LEN);
	} else {
		send_msg->data[0] = HCLGE_COMM_UNIC_IPV6_LOWER_LEN;
		memcpy(&send_msg->data[HCLGE_COMM_UNIC_MSG_IPADDR_POS],
		       &ip_node->ip_addr.s6_addr[HCLGE_COMM_UNIC_IPV6_UPPER_LEN],
		       sizeof(u8) * HCLGE_COMM_UNIC_IPV6_LOWER_LEN);
	}
}

static int
hclgevf_unic_add_del_ip_addr(struct hclgevf_dev *hdev,
			     struct hclge_comm_unic_addr_node *ip_node)
{
	struct hclge_vf_to_pf_msg send_msg;
	int ret;

	hclgevf_unic_prepare_ip_msg(HCLGE_UNIC_MBX_SET_IP, 0, ip_node,
				    &send_msg);
	ret = hclgevf_send_mbx_msg(hdev, &send_msg, false, NULL, 0);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"VF send ip address to PF failed, ret=%d", ret);
		return ret;
	}

	hclgevf_unic_prepare_ip_msg(HCLGE_UNIC_MBX_SET_IP, 1, ip_node,
				    &send_msg);
	ret = hclgevf_send_mbx_msg(hdev, &send_msg, false, NULL, 0);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"VF send ip address to PF failed, ret=%d", ret);
		return ret;
	}
	return 0;
}

static void hclgevf_unic_config_ip_list(struct hnae3_handle *h,
					struct list_head *list)
{
	struct hclgevf_dev *hdev = container_of(h, struct hclgevf_dev, nic);
	struct hclge_comm_unic_addr_node *ip_node, *tmp;
	int ret;

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		ret = hclgevf_unic_add_del_ip_addr(hdev, ip_node);
		if  (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to configure ip %pI6c, state = %d, ret = %d\n",
				ip_node->ip_addr.s6_addr, ip_node->state, ret);
			return;
		}
		if (ip_node->state == HCLGE_COMM_UNIC_ADDR_TO_ADD) {
			ip_node->state = HCLGE_COMM_UNIC_ADDR_ACTIVE;
		} else {
			list_del(&ip_node->node);
			kfree(ip_node);
		}
	}
}

void hclgevf_unic_clear_ip_list(struct hclgevf_dev *hdev)
{
	struct hclge_comm_unic_addr_node *ip_node, *tmp;
	struct list_head *list;

	list = &hdev->ip_table.ip_list;

	spin_lock_bh(&hdev->ip_table.ip_list_lock);
	list_for_each_entry_safe(ip_node, tmp, list, node) {
		list_del(&ip_node->node);
		kfree(ip_node);
	}
	spin_unlock_bh(&hdev->ip_table.ip_list_lock);
}

void hclgevf_unic_sync_ip_list(struct hclgevf_dev *hdev)
{
	(void)hclge_comm_unic_sync_addr_table(&hdev->nic,
					      &hdev->ip_table.ip_list,
					      &hdev->ip_table.ip_list_lock,
					      hclgevf_unic_config_ip_list,
					      hclgevf_unic_config_ip_list);
}
