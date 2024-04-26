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

#include "hclgevf_main.h"
#include "hclgevf_udma.h"

int hclgevf_notify_udma_client(struct hclgevf_dev *hdev,
			       enum hnae3_reset_notify_type type)
{
	struct hnae3_client *client = hdev->udma_client;
	struct hnae3_handle *handle = &hdev->udma;
	int ret;

	if (!test_bit(HCLGEVF_STATE_UDMA_REGISTERED, &hdev->state) || !client)
		return 0;

	if (!client->ops->reset_notify)
		return -EOPNOTSUPP;

	ret = client->ops->reset_notify(handle, type);
	if (ret)
		dev_err(&hdev->pdev->dev, "notify udma client failed %d(%d)",
			type, ret);
	return ret;
}

static int hclgevf_init_udma_base_info(struct hclgevf_dev *hdev)
{
	struct hnae3_handle *udma = &hdev->udma;
	struct hnae3_handle *nic = &hdev->nic;

	if (hdev->num_msi_left < udma->udmainfo.num_vectors ||
	    hdev->num_msi_left == 0)
		return -EINVAL;

	udma->udmainfo.num_vectors = hdev->num_udma_msix;
	udma->udmainfo.base_vector = hdev->roce_base_msix_offset;

	udma->udmainfo.netdev = nic->kinfo.netdev;
	udma->udmainfo.udma_io_base = hdev->hw.hw.io_base;
	udma->udmainfo.udma_mem_base = hdev->hw.hw.mem_base;

	udma->pdev = nic->pdev;
	udma->ae_algo = nic->ae_algo;
	udma->numa_node_mask = nic->numa_node_mask;

	return 0;
}

int hclgevf_init_udma_client_instance(struct hnae3_ae_dev *ae_dev,
				      struct hnae3_client *client)
{
	struct hclgevf_dev *hdev = ae_dev->priv;
	int ret;

	if (!hnae3_dev_udma_supported(ae_dev) || !hdev->udma_client ||
	    !hdev->nic_client)
		return 0;

	ret = hclgevf_init_udma_base_info(hdev);
	if (ret)
		return ret;

	ret = client->ops->init_instance(&hdev->udma);
	if (ret)
		return ret;

	set_bit(HCLGEVF_STATE_UDMA_REGISTERED, &hdev->state);
	hnae3_set_client_init_flag(client, ae_dev, 1);

	return 0;
}
