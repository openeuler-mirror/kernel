// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/platform_device.h>
#include <acpi/pcc.h>
#include "hisi_mem_ras.h"

#define DRV_NAME "hisi_mem_ras"
#define MAX_PCC_CMD_RETRIES	500ULL

struct hisi_mem_register_ctx {
	struct device *dev;
	u8 chan_id;
	int err;
};

static acpi_status hisi_mem_get_chan_id_cb(struct acpi_resource *ares, void *context)
{
	struct acpi_resource_generic_register *reg;
	struct hisi_mem_register_ctx *ctx = context;

	if (ares->type != ACPI_RESOURCE_TYPE_GENERIC_REGISTER)
		return AE_OK;

	reg = &ares->data.generic_reg;
	if (reg->space_id != ACPI_ADR_SPACE_PLATFORM_COMM) {
		dev_err(ctx->dev, "Bad register resource.\n");
		ctx->err = -EINVAL;
		return AE_ERROR;
	}
	ctx->chan_id = reg->access_size;

	return AE_OK;
}

static int hisi_mem_get_pcc_chan_id(struct hisi_mem_dev *hdev)
{
	struct platform_device *pdev = hdev->pdev;
	struct acpi_device *adev = ACPI_COMPANION(&pdev->dev);
	struct hisi_mem_register_ctx ctx = {0};
	acpi_handle handle = adev->handle;
	acpi_status status;

	if (!acpi_has_method(handle, METHOD_NAME__CRS)) {
		dev_err(&pdev->dev, "No _CRS method.\n");
		return -ENODEV;
	}

	ctx.dev = &pdev->dev;
	status = acpi_walk_resources(handle, METHOD_NAME__CRS,
				     hisi_mem_get_chan_id_cb, &ctx);
	if (ACPI_FAILURE(status))
		return ctx.err;

	hdev->chan_id = ctx.chan_id;
	return 0;
}

static void hisi_mem_chan_tx_done(struct mbox_client *cl, void *mssg, int ret)
{
	if (ret < 0)
		pr_debug("TX did not complete: CMD sent:0x%x, ret:%d\n",
			 *(u8 *)mssg, ret);
	else
		pr_debug("TX completed. CMD sent:0x%x, ret:%d\n",
			 *(u8 *)mssg, ret);
}

static void hisi_mem_pcc_rx_callback(struct mbox_client *cl, void *mssg)
{
	struct hisi_mem_mbox_client_info *cl_info =
			container_of(cl, struct hisi_mem_mbox_client_info, client);

	complete(&cl_info->done);
}

static void hisi_mem_unregister_pcc_channel(struct hisi_mem_dev *hdev)
{
	struct hisi_mem_mbox_client_info *cl_info = &hdev->cl_info;

	pcc_mbox_free_channel(cl_info->pcc_chan);
}

static int hisi_mem_register_pcc_channel(struct hisi_mem_dev *hdev)
{
	struct hisi_mem_mbox_client_info *cl_info = &hdev->cl_info;
	struct mbox_client *cl = &cl_info->client;
	struct platform_device *pdev = hdev->pdev;
	struct pcc_mbox_chan *pcc_chan;
	int rc;

	cl->dev = &pdev->dev;
	cl->tx_block = false;
	cl->knows_txdone = true;
	cl->tx_done = hisi_mem_chan_tx_done;
	cl->rx_callback = hisi_mem_pcc_rx_callback;
	pcc_chan = pcc_mbox_request_channel(cl, hdev->chan_id);
	if (IS_ERR(pcc_chan))
		return dev_err_probe(&pdev->dev, -ENODEV, "PCC channel request failed.\n");

	if (pcc_chan->shmem_size > HISI_MEM_PCC_SHARE_MEM_BYTES_MAX ||
	    pcc_chan->shmem_size < HISI_MEM_PCC_SHARE_MEM_BYTES_MIN) {
		rc = dev_err_probe(&pdev->dev, -EINVAL, "Unsupported PCC shmem size 0x%llx.\n",
				   pcc_chan->shmem_size);
		goto err_mbx_channel_free;
	}

	/*
	 * pcc_chan->latency is just a nominal value. In reality the remote
	 * processor could be much slower to reply. So add an arbitrary amount
	 * of wait on top of nominal.
	 */
	cl_info->deadline_us = MAX_PCC_CMD_RETRIES * pcc_chan->latency;
	cl_info->pcc_chan = pcc_chan;
	init_completion(&cl_info->done);
	if (!pcc_chan->mchan->mbox->txdone_irq) {
		rc = dev_err_probe(&pdev->dev, -EINVAL, "PCC IRQ in PCCT isn't supported.\n");
		goto err_mbx_channel_free;
	}

	cl_info->pcc_comm_addr = devm_ioremap(&pdev->dev, pcc_chan->shmem_base_addr,
					      pcc_chan->shmem_size);
	if (!cl_info->pcc_comm_addr) {
		rc = dev_err_probe(&pdev->dev, -ENOMEM,
				   "Failed to ioremap PCC communication region for channel-%u.\n",
				   hdev->chan_id);
		goto err_mbx_channel_free;
	}

	return 0;

err_mbx_channel_free:
	pcc_mbox_free_channel(cl_info->pcc_chan);
	return rc;
}

static int hisi_mem_wait_cmd_complete_by_irq(struct hisi_mem_dev *hdev)
{
	struct hisi_mem_mbox_client_info *cl_info = &hdev->cl_info;
	struct platform_device *pdev = hdev->pdev;

	if (!wait_for_completion_timeout(&cl_info->done, usecs_to_jiffies(cl_info->deadline_us))) {
		dev_err(&pdev->dev, "PCC command executed timeout!\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static inline void hisi_mem_fill_ext_pcc_shared_mem_region(struct hisi_mem_dev *hdev, u8 cmd,
							   struct hisi_mem_desc *desc,
							   void __iomem *comm_space,
							   u32 space_size)
{
	struct hisi_mem_mbox_client_info *cl_info = &hdev->cl_info;
	struct acpi_pcct_ext_pcc_shared_memory tmp = {
		.signature = PCC_SIGNATURE | hdev->chan_id,
		.flags = PCC_CMD_COMPLETION_NOTIFY,
		.length = cl_info->pcc_chan->shmem_size,
		.command = cmd,
	};

	memcpy_toio(hdev->cl_info.pcc_comm_addr, &tmp, sizeof(tmp));

	/* Copy the message to the PCC comm space */
	memcpy_toio(comm_space, desc, space_size);
}

static int hisi_mem_pcc_cmd_send(struct hisi_mem_dev *hdev, u8 cmd,
				 struct hisi_mem_desc *desc)
{
	struct hisi_mem_mbox_client_info *cl_info = &hdev->cl_info;
	struct platform_device *pdev = hdev->pdev;
	void __iomem *comm_space;
	u32 space_size;
	int ret;

	mutex_lock(&hdev->lock);
	comm_space = cl_info->pcc_comm_addr + sizeof(struct acpi_pcct_ext_pcc_shared_memory);
	space_size = cl_info->pcc_chan->shmem_size - sizeof(struct acpi_pcct_ext_pcc_shared_memory);
	hisi_mem_fill_ext_pcc_shared_mem_region(hdev, cmd, desc, comm_space, space_size);
	reinit_completion(&cl_info->done);

	/* Ring doorbell */
	ret = mbox_send_message(cl_info->pcc_chan->mchan, &cmd);
	if (ret < 0) {
		dev_err(&pdev->dev, "Send PCC mbox message failed, ret = %d.\n", ret);
		goto end;
	}

	ret = hisi_mem_wait_cmd_complete_by_irq(hdev);
	if (ret)
		goto end;

	/* Copy response data */
	memcpy_fromio(desc, comm_space, space_size);

end:
	mbox_chan_txdone(cl_info->pcc_chan->mchan, ret);
	mutex_unlock(&hdev->lock);
	return ret;
}

static int check_fw_ret_status(struct device *dev, u8 status, char *cmd_desc)
{
	if (status == HISI_MEM_RAS_NO_RES) {
		dev_info(dev, "%s failed due to no resource.\n", cmd_desc);
		return -ENOSPC;
	} else if (status != HISI_MEM_RAS_OK) {
		dev_info(dev, "%s failed due to error code %u.\n", cmd_desc, status);
		return -ENXIO;
	}

	return 0;
}

static struct page *trans_and_check_paddr(struct device *dev, const char *buf, u64 *paddr)
{
	struct page *page;
	u64 paddr_tmp;

	if (kstrtoull(buf, 16, &paddr_tmp))
		return NULL;

	page = pfn_to_online_page(__phys_to_pfn(paddr_tmp));
	if (!page) {
		dev_info(dev, "The page of paddr 0x%llx is not online page.\n", paddr_tmp);
		return NULL;
	}

	*paddr = paddr_tmp;
	return page;
}

static ssize_t acls_query_store(struct device *dev, struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct platform_device *pdev = container_of(dev, struct platform_device, dev);
	struct hisi_mem_dev *hdev = platform_get_drvdata(pdev);
	struct hisi_mem_desc desc = {0};
	struct page *page;
	u64 paddr;
	int ret;

	page = trans_and_check_paddr(dev, buf, &paddr);
	if (!page)
		return -EINVAL;

	desc.req.req_head.subcmd = HISI_MEM_RAS_QUERY;
	desc.req.data[0] = lower_32_bits(paddr);
	desc.req.data[1] = upper_32_bits(paddr);
	ret = hisi_mem_pcc_cmd_send(hdev, HISI_MEM_RAS_ACLS, &desc);
	if (ret) {
		dev_err(dev, "ACLS query failed, ret = %d.\n", ret);
		return -EIO;
	}

	ret = check_fw_ret_status(dev, desc.rsp.rsp_head.ret_status, "ACLS query");
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_WO(acls_query);

static ssize_t acls_repair_store(struct device *dev, struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct platform_device *pdev = container_of(dev, struct platform_device, dev);
	struct hisi_mem_dev *hdev = platform_get_drvdata(pdev);
	struct hisi_mem_desc desc = {0};
	struct page *page;
	u64 paddr;
	int ret;

	page = trans_and_check_paddr(dev, buf, &paddr);
	if (!page)
		return -EINVAL;

	if (hdev->mem_type == MEMORY_TYPE_HBM && !PageHWPoison(page)) {
		dev_info(dev, "The page of paddr 0x%llx is not unpoisoned.\n", paddr);
		return -EIO;
	}

	desc.req.req_head.subcmd = HISI_MEM_RAS_DO_REPAIR;
	desc.req.data[0] = lower_32_bits(paddr);
	desc.req.data[1] = upper_32_bits(paddr);
	ret = hisi_mem_pcc_cmd_send(hdev, HISI_MEM_RAS_ACLS, &desc);
	if (ret) {
		dev_err(dev, "ACLS repair failed, ret = %d.\n", ret);
		return -EIO;
	}

	ret = check_fw_ret_status(dev, desc.rsp.rsp_head.ret_status, "ACLS repair");
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_WO(acls_repair);

static ssize_t sppr_query_store(struct device *dev, struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct platform_device *pdev = container_of(dev, struct platform_device, dev);
	struct hisi_mem_dev *hdev = platform_get_drvdata(pdev);
	struct hisi_mem_desc desc = {0};
	struct page *page;
	u64 paddr;
	int ret;

	page = trans_and_check_paddr(dev, buf, &paddr);
	if (!page)
		return -EINVAL;

	desc.req.req_head.subcmd = HISI_MEM_RAS_QUERY;
	desc.req.data[0] = lower_32_bits(paddr);
	desc.req.data[1] = upper_32_bits(paddr);
	ret = hisi_mem_pcc_cmd_send(hdev, HISI_MEM_RAS_SPPR, &desc);
	if (ret) {
		dev_err(dev, "SPPR query failed, ret = %d.\n", ret);
		return -EIO;
	}

	ret = check_fw_ret_status(dev, desc.rsp.rsp_head.ret_status, "SPPR query");
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_WO(sppr_query);

static ssize_t sppr_repair_store(struct device *dev, struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct platform_device *pdev = container_of(dev, struct platform_device, dev);
	struct hisi_mem_dev *hdev = platform_get_drvdata(pdev);
	struct hisi_mem_desc desc = {0};
	struct page *page;
	u64 paddr;
	int ret;

	page = trans_and_check_paddr(dev, buf, &paddr);
	if (!page)
		return -EINVAL;

	if (hdev->mem_type == MEMORY_TYPE_HBM && !PageHWPoison(page)) {
		dev_info(dev, "The page of paddr 0x%llx is not poisoned.\n", paddr);
		return -EIO;
	}

	desc.req.req_head.subcmd = HISI_MEM_RAS_DO_REPAIR;
	desc.req.data[0] = lower_32_bits(paddr);
	desc.req.data[1] = upper_32_bits(paddr);
	ret = hisi_mem_pcc_cmd_send(hdev, HISI_MEM_RAS_SPPR, &desc);
	if (ret) {
		dev_err(dev, "SPPR repair failed, ret = %d.\n", ret);
		return -EIO;
	}

	ret = check_fw_ret_status(dev, desc.rsp.rsp_head.ret_status, "SPPR repair");
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_WO(sppr_repair);

static const char * const memory_type_name[MEMORY_TYPE_MAX] = {
	"HBM",
	"DDR",
};

static ssize_t memory_type_show(struct device *dev, struct device_attribute *attr,
				char *buf)
{
	struct platform_device *pdev = container_of(dev, struct platform_device, dev);
	struct hisi_mem_dev *hdev = platform_get_drvdata(pdev);
	int ret;

	if (hdev->mem_type < MEMORY_TYPE_MAX)
		ret = sysfs_emit(buf, "%s\n", memory_type_name[hdev->mem_type]);
	else
		ret = sysfs_emit(buf, "Unknown\n");

	return ret;
}
static DEVICE_ATTR_RO(memory_type);

static ssize_t memory_type_supported_show(struct device *dev, struct device_attribute *attr,
					  char *buf)
{
	int ret = 0;
	int i;

	ret += sysfs_emit_at(buf, ret, "%s", memory_type_name[0]);
	for (i = 1; i < MEMORY_TYPE_MAX; i++)
		ret += sysfs_emit_at(buf, ret, " %s", memory_type_name[i]);

	ret += sysfs_emit_at(buf, ret, "\n");

	return ret;
}
static DEVICE_ATTR_RO(memory_type_supported);

static int hisi_mem_ras_get_attribute(struct hisi_mem_dev *hdev)
{
	struct platform_device *pdev = hdev->pdev;
	struct hisi_mem_desc desc = {0};
	int ret;

	ret = hisi_mem_pcc_cmd_send(hdev, HISI_MEM_RAS_CAP, &desc);
	if (ret)
		return dev_err_probe(&pdev->dev, -EIO, "Get attribute failed, ret = %d.\n", ret);

	if (desc.rsp.rsp_head.ret_status)
		return dev_err_probe(&pdev->dev, -EIO, "Device in bad status %u.\n",
				     desc.rsp.rsp_head.ret_status);

	if (desc.rsp.rsp_head.mem_type >= MEMORY_TYPE_MAX)
		return dev_err_probe(&pdev->dev, -EIO, "Unsupported memory type %u.\n",
				     desc.rsp.rsp_head.mem_type);

	hdev->mem_type = desc.rsp.rsp_head.mem_type;
	hdev->ras_cap = desc.rsp.rsp_head.ras_cap;

	return 0;
}

static struct attribute *memory_type_attrs[] = {
	&dev_attr_memory_type.attr,
	&dev_attr_memory_type_supported.attr,
	NULL,
};

static struct attribute_group memory_type_attr_group = {
	.attrs = memory_type_attrs,
};

static struct attribute *acls_attrs[] = {
	&dev_attr_acls_query.attr,
	&dev_attr_acls_repair.attr,
	NULL,
};

static struct attribute_group acls_attr_group = {
	.attrs = acls_attrs,
};

static struct attribute *sppr_attrs[] = {
	&dev_attr_sppr_query.attr,
	&dev_attr_sppr_repair.attr,
	NULL,
};

static struct attribute_group sppr_attr_group = {
	.attrs = sppr_attrs,
};

static int hisi_mem_create_sysfs_files(struct hisi_mem_dev *hdev)
{
	struct platform_device *pdev = hdev->pdev;
	int ret;

	if (hdev->ras_cap & HISI_MEM_CAP_ACLS_EN) {
		ret = sysfs_create_group(&pdev->dev.kobj, &acls_attr_group);
		if (ret) {
			dev_err(&pdev->dev, "Create ACLS sysfs group failed, ret = %d.\n", ret);
			return ret;
		}
	}

	if (hdev->ras_cap & HISI_MEM_CAP_SPPR_EN) {
		ret = sysfs_create_group(&pdev->dev.kobj, &sppr_attr_group);
		if (ret) {
			dev_err(&pdev->dev, "Create SPPR sysfs group failed, ret = %d.\n", ret);
			goto acls_files;
		}
	}

	ret = sysfs_create_group(&pdev->dev.kobj, &memory_type_attr_group);
	if (ret) {
		dev_err(&pdev->dev, "Create memory type file failed, ret =%d.\n", ret);
		goto sppr_files;
	}

	return 0;

sppr_files:
	if (hdev->ras_cap & HISI_MEM_CAP_SPPR_EN)
		sysfs_remove_group(&pdev->dev.kobj, &sppr_attr_group);

acls_files:
	if (hdev->ras_cap & HISI_MEM_CAP_ACLS_EN)
		sysfs_remove_group(&pdev->dev.kobj, &acls_attr_group);

	return ret;
}

static void hisi_mem_remove_sysfs_files(struct hisi_mem_dev *hdev)
{
	struct platform_device *pdev = hdev->pdev;

	sysfs_remove_group(&pdev->dev.kobj, &memory_type_attr_group);
	if (hdev->ras_cap & HISI_MEM_CAP_SPPR_EN)
		sysfs_remove_group(&pdev->dev.kobj, &sppr_attr_group);

	if (hdev->ras_cap & HISI_MEM_CAP_ACLS_EN)
		sysfs_remove_group(&pdev->dev.kobj, &acls_attr_group);
}

static int hisi_mem_ras_probe(struct platform_device *pdev)
{
	struct hisi_mem_dev *hdev;
	int ret;

	hdev = devm_kzalloc(&pdev->dev, sizeof(struct hisi_mem_dev), GFP_KERNEL);
	if (!hdev)
		return -ENOMEM;

	hdev->pdev = pdev;
	mutex_init(&hdev->lock);
	platform_set_drvdata(pdev, hdev);
	ret = hisi_mem_get_pcc_chan_id(hdev);
	if (ret)
		return ret;

	ret = hisi_mem_register_pcc_channel(hdev);
	if (ret)
		return ret;

	ret = hisi_mem_ras_get_attribute(hdev);
	if (ret)
		goto unregister_pcc_chan;

	ret = hisi_mem_create_sysfs_files(hdev);
	if (ret)
		goto unregister_pcc_chan;

	return 0;

unregister_pcc_chan:
	hisi_mem_unregister_pcc_channel(hdev);

	return ret;
}

static int hisi_mem_ras_remove(struct platform_device *pdev)
{
	struct hisi_mem_dev *hdev = platform_get_drvdata(pdev);

	hisi_mem_remove_sysfs_files(hdev);
	hisi_mem_unregister_pcc_channel(hdev);

	return 0;
}

static const struct acpi_device_id hisi_mem_acpi_match[] = {
	{ "HISI0521", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hisi_mem_acpi_match);

static struct platform_driver hisi_mem_ras_driver = {
	.probe = hisi_mem_ras_probe,
	.remove = hisi_mem_ras_remove,
	.driver = {
		.name = "hisi_mem_ras",
		.acpi_match_table = hisi_mem_acpi_match,
	},
};
module_platform_driver(hisi_mem_ras_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xiaofei Tan <tanxiaofei@huawei.com>");
MODULE_DESCRIPTION("HISILICON Memory RAS driver");
MODULE_ALIAS("platform:" DRV_NAME);
