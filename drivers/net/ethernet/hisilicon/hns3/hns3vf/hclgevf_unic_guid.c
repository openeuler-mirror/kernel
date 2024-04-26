// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2023 Hisilicon Limited.

#include <linux/etherdevice.h>

#include "ubl.h"
#include "hclgevf_main.h"
#include "hclge_comm_unic_addr.h"
#include "hclge_comm_cmd.h"
#include "hclge_mbx.h"
#include "hclgevf_unic_guid.h"

int hclgevf_unic_update_guid_list(struct hnae3_handle *handle,
				  enum HCLGE_COMM_ADDR_NODE_STATE state,
				  const unsigned char *addr)
{
	struct hclgevf_dev *hdev = container_of(handle, struct hclgevf_dev, nic);
	char format_guid_addr[HCLGE_COMM_FORMAT_GUID_ADDR_LEN];
	int ret;

	ret = hclge_comm_unic_update_addr_list(&hdev->mc_guid_list,
					       &hdev->mguid_list_lock,
					       state, addr);
	if (ret == -ENOENT) {
		hclge_comm_format_guid_addr(format_guid_addr, addr);
		dev_err(&hdev->pdev->dev,
			"failed to delete guid %s from mc guid list\n",
			format_guid_addr);
	}

	return ret;
}

static int
hclgevf_unic_add_del_mc_guid(struct hclgevf_dev *hdev,
			     struct hclge_comm_unic_addr_node *guid_node)
{
	struct hclge_vf_to_pf_msg send_msg = {0};

	send_msg.code = HCLGE_MBX_SET_MGUID;
	if (guid_node->state == HCLGE_COMM_UNIC_ADDR_TO_ADD)
		send_msg.subcode = HCLGE_MBX_MC_GUID_MC_ADD;
	else
		send_msg.subcode = HCLGE_MBX_MC_GUID_MC_DELETE;

	memcpy(send_msg.data, &guid_node->proto, sizeof(__le16));
	return hclgevf_send_mbx_msg(hdev, &send_msg, false, NULL, 0);
}

static void hclgevf_unic_config_mguid_list(struct hnae3_handle *h,
					   struct list_head *list)
{
	struct hclgevf_dev *hdev = container_of(h, struct hclgevf_dev, nic);
	char format_guid_addr[HCLGE_COMM_FORMAT_GUID_ADDR_LEN];
	struct hclge_comm_unic_addr_node *guid_node, *tmp;
	int ret;

	list_for_each_entry_safe(guid_node, tmp, list, node) {
		ret = hclgevf_unic_add_del_mc_guid(hdev, guid_node);
		if (ret) {
			hclge_comm_format_guid_addr(format_guid_addr,
						    guid_node->mguid);
			dev_err(&hdev->pdev->dev,
				"failed to configure mc guid %s, state = %d, ret = %d\n",
				format_guid_addr, guid_node->state, ret);
			return;
		}
		if (guid_node->state == HCLGE_COMM_UNIC_ADDR_TO_ADD) {
			guid_node->state = HCLGE_COMM_UNIC_ADDR_ACTIVE;
		} else {
			list_del(&guid_node->node);
			kfree(guid_node);
		}
	}
}

void hclgevf_unic_sync_mc_guid_list(struct hclgevf_dev *hdev)
{
	(void)hclge_comm_unic_sync_addr_table(&hdev->nic,
					      &hdev->mc_guid_list,
					      &hdev->mguid_list_lock,
					      hclgevf_unic_config_mguid_list,
					      hclgevf_unic_config_mguid_list);
}

static void hclgevf_unic_clear_guid_list(struct list_head *list)
{
	struct hclge_comm_unic_addr_node *guid_node, *tmp;

	list_for_each_entry_safe(guid_node, tmp, list, node) {
		list_del(&guid_node->node);
		kfree(guid_node);
	}
}

void hclgevf_unic_uninit_mc_guid_list(struct hclgevf_dev *hdev)
{
	spin_lock_bh(&hdev->mguid_list_lock);

	hclgevf_unic_clear_guid_list(&hdev->mc_guid_list);

	spin_unlock_bh(&hdev->mguid_list_lock);
}

void hclgevf_unic_set_func_guid(struct hnae3_handle *handle, u8 *guid)
{
	struct hclgevf_dev *hdev = hclgevf_ae_get_hdev(handle);

	hdev->hw.func_guid = guid;
}

int hclgevf_unic_get_func_guid(struct hnae3_handle *handle, u8 *guid)
{
	struct hclgevf_dev *hdev = hclgevf_ae_get_hdev(handle);

	return hclge_comm_unic_get_func_guid(&hdev->hw.hw, guid);
}
