// SPDX-License-Identifier: GPL-2.0+
/* Hisilicon UNIC Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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

#include "hclge_main.h"
#include "hclge_err.h"
#include "hclge_debugfs.h"
#include "hclge_udma.h"

static const struct hclge_dbg_status_dfx_info hclge_dbg_rst_info_ub[] = {
	{HCLGE_RAS_PF_OTHER_INT_STS_REG_UB, "UB RAS interrupt status"}
};

static int hclge_init_udma_base_info(struct hclge_vport *vport)
{
	struct hnae3_handle *udma = &vport->udma;
	struct hnae3_handle *nic = &vport->nic;
	struct hclge_dev *hdev = vport->back;

	if (hdev->num_msi < hdev->num_nic_msi + hdev->num_udma_msi)
		return -EINVAL;

	udma->udmainfo.num_vectors = hdev->num_udma_msi;
	udma->udmainfo.base_vector = hdev->num_nic_msi;

	udma->udmainfo.netdev = nic->kinfo.netdev;
	udma->udmainfo.udma_io_base = hdev->hw.hw.io_base;
	udma->udmainfo.udma_mem_base = hdev->hw.hw.mem_base;

	udma->pdev = nic->pdev;
	udma->ae_algo = nic->ae_algo;
	udma->numa_node_mask = nic->numa_node_mask;

	return 0;
}

int hclge_notify_udma_client(struct hclge_dev *hdev,
			     enum hnae3_reset_notify_type type)
{
	struct hnae3_handle *handle = &hdev->vport[0].udma;
	struct hnae3_client *client = hdev->udma_client;
	int ret;

	if (!test_bit(HCLGE_STATE_UDMA_REGISTERED, &hdev->state) || !client)
		return 0;

	if (!client->ops->reset_notify)
		return -EOPNOTSUPP;

	ret = client->ops->reset_notify(handle, type);
	if (ret)
		dev_err(&hdev->pdev->dev, "notify udma client failed %d(%d)",
			type, ret);

	return ret;
}

int hclge_init_udma_client_instance(struct hnae3_ae_dev *ae_dev,
				    struct hclge_vport *vport)
{
	struct hclge_dev *hdev = ae_dev->priv;
	struct hnae3_client *client;
	u32 rst_cnt;
	int ret;

	if (!hnae3_dev_udma_supported(ae_dev) || !hdev->udma_client ||
	    !hdev->nic_client)
		return 0;

	client = hdev->udma_client;
	ret = hclge_init_udma_base_info(vport);
	if (ret)
		return ret;

	rst_cnt = hdev->rst_stats.reset_cnt;
	ret = client->ops->init_instance(&vport->udma);
	if (ret)
		return ret;

	set_bit(HCLGE_STATE_UDMA_REGISTERED, &hdev->state);
	if (test_bit(HCLGE_STATE_RST_HANDLING, &hdev->state) ||
	    rst_cnt != hdev->rst_stats.reset_cnt) {
		ret = -EBUSY;
		goto init_udma_err;
	}

	hnae3_set_client_init_flag(client, ae_dev, 1);

	return 0;

init_udma_err:
	clear_bit(HCLGE_STATE_UDMA_REGISTERED, &hdev->state);
	while (test_bit(HCLGE_STATE_RST_HANDLING, &hdev->state))
		msleep(HCLGE_WAIT_RESET_DONE);

	hdev->udma_client->ops->uninit_instance(&vport->udma, 0);

	return ret;
}

u32 hclge_get_udma_error_reg(struct hclge_dev *hdev)
{
	u32 hw_err_src_reg = 0;

	if (hnae3_dev_ubl_supported(hdev->ae_dev) ||
	    hnae3_dev_udma_supported(hdev->ae_dev))
		hw_err_src_reg = hclge_read_dev(&hdev->hw,
						HCLGE_RAS_PF_OTHER_INT_STS_REG_UB);

	return hw_err_src_reg;
}

void hclge_dbg_dump_udma_rst_info(struct hclge_dev *hdev, char *buf, int len,
				  int *pos)
{
	u32 i, offset;

	if (hnae3_dev_ubl_supported(hdev->ae_dev) ||
	    hnae3_dev_udma_supported(hdev->ae_dev)) {
		for (i = 0; i < ARRAY_SIZE(hclge_dbg_rst_info_ub); i++) {
			offset = hclge_dbg_rst_info_ub[i].offset;
			*pos += scnprintf(buf + *pos, len - *pos, "%s: 0x%x\n",
					  hclge_dbg_rst_info_ub[i].message,
					  hclge_read_dev(&hdev->hw, offset));
		}
	}
}
