// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2019 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hns3_enet.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_version.h"

static int hns3_cae_get_commit_id(struct hnae3_handle *handle, u8 *commit_id,
				  u32 *ncl_version)
{
#define COMMIT_ID_LEN	8
	struct hclge_vport *vport = hns3_cae_get_vport(handle);
	struct hns3_cae_commit_id_param *resp;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret, i;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_IMP_COMMIT_ID_GET, true);
	resp = (struct hns3_cae_commit_id_param *)(desc.data);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get commit id failed %d\n", ret);
		return ret;
	}

	for (i = 0; i < COMMIT_ID_LEN; i++)
		commit_id[i] = resp->commit_id[i];

	commit_id[COMMIT_ID_LEN] = '\0';
	*ncl_version = resp->ncl_version;

	return 0;
}

int hns3_cae_get_fw_ver(struct hns3_nic_priv *nic_dev, void *buf_in,
			u32 in_size, void *buf_out, u32 out_size)
{
	struct hns3_cae_firmware_ver_param *out_buf;
	struct hnae3_handle *handle;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	bool check;
	u32 fw_ver;

	check = !buf_out ||
		out_size < sizeof(struct hns3_cae_firmware_ver_param);
	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	handle = nic_dev->ae_handle;
	vport = container_of(handle, struct hclge_vport, nic);
	hdev = vport->back;
	out_buf = (struct hns3_cae_firmware_ver_param *)buf_out;

	if (hns3_cae_get_commit_id(handle, out_buf->commit_id,
				   &out_buf->ncl_version))
		return -EFAULT;

	fw_ver = hdev->fw_version;
	out_buf->imp_ver = fw_ver;

	if (!fw_ver)
		return -EFAULT;

	return 0;
}

int hns3_cae_get_driver_ver(struct hns3_nic_priv *nic_dev,
			    void *buf_in, u32 in_size,
			    void *buf_out, u32 out_size)
{
	if (!buf_out || out_size < sizeof(HNAE_DRIVER_VERSION))
		return -ENOMEM;

	strncpy(buf_out, HNAE_DRIVER_VERSION, sizeof(HNAE_DRIVER_VERSION));

	return 0;
}
