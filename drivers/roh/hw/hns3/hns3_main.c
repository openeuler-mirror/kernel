// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2022 Hisilicon Limited.

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/debugfs.h>
#include "core.h"
#include "hnae3.h"
#include "hns3_device.h"
#include "hns3_common.h"
#include "hns3_cmdq.h"
#include "hns3_verbs.h"
#include "hns3_intr.h"

static struct workqueue_struct *hns3_roh_wq;
static struct dentry *hns3_roh_dfx_root;

static const struct pci_device_id hns3_roh_pci_tbl[] = {
	{ PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_100G_ROH), 0 },
	{ PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_200G_ROH), 0 },
	{ PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_400G_ROH), 0 },
	{
		0,
	}
};
MODULE_DEVICE_TABLE(pci, hns3_roh_pci_tbl);

static void hns3_roh_unregister_device(struct hns3_roh_device *hroh_dev)
{
	hroh_dev->active = false;
	roh_unregister_device(&hroh_dev->roh_dev);
}

static int hns3_roh_register_device(struct hns3_roh_device *hroh_dev)
{
	struct roh_device *rohdev = &hroh_dev->roh_dev;
	struct device *dev = hroh_dev->dev;
	int ret;

	if (!strlen(rohdev->name))
		strscpy(rohdev->name, "hns3_%d", ROH_DEVICE_NAME_MAX);

	rohdev->owner = THIS_MODULE;
	rohdev->dev.parent = dev;
	rohdev->netdev = hroh_dev->netdev;

	rohdev->ops.set_eid = hns3_roh_set_eid;
	rohdev->ops.alloc_hw_stats = hns3_roh_alloc_hw_stats;
	rohdev->ops.get_hw_stats = hns3_roh_get_hw_stats;

	ret = hns3_roh_get_link_status(hroh_dev, &rohdev->link_status);
	if (ret) {
		dev_err(dev, "failed to get link status, ret = %d\n", ret);
		return ret;
	}

	ret = roh_register_device(rohdev);
	if (ret) {
		dev_err(dev, "failed to register roh device, ret = %d\n", ret);
		return ret;
	}

	hroh_dev->active = true;

	return 0;
}

void hns3_roh_mbx_task_schedule(struct hns3_roh_device *hroh_dev)
{
	if (!test_and_set_bit(HNS3_ROH_SW_STATE_MBX_SERVICE_SCHED, &hroh_dev->state))
		mod_delayed_work(hns3_roh_wq, &hroh_dev->srv_task, 0);
}

void hns3_roh_task_schedule(struct hns3_roh_device *hroh_dev, unsigned long delay_time)
{
	mod_delayed_work(hns3_roh_wq, &hroh_dev->srv_task, delay_time);
}

static void hns3_roh_mbx_service_task(struct hns3_roh_device *hroh_dev)
{
	if (!test_and_clear_bit(HNS3_ROH_SW_STATE_MBX_SERVICE_SCHED,
				&hroh_dev->state) ||
		test_and_set_bit(HNS3_ROH_SW_STATE_MBX_HANDLING, &hroh_dev->state))
		return;

	hns3_roh_mbx_handler(hroh_dev);

	clear_bit(HNS3_ROH_SW_STATE_MBX_HANDLING, &hroh_dev->state);
}

static void hns3_roh_poll_service_task(struct hns3_roh_device *hroh_dev)
{
	unsigned long delta = round_jiffies_relative(HZ);

	hns3_roh_update_link_status(hroh_dev);

	if (time_is_after_jiffies(hroh_dev->last_processed + HZ)) {
		delta = jiffies - hroh_dev->last_processed;
		if (delta < round_jiffies_relative(HZ)) {
			delta = round_jiffies_relative(HZ) - delta;
			goto out;
		}
	}

	hroh_dev->last_processed = jiffies;

out:
	hns3_roh_task_schedule(hroh_dev, delta);
}

static void hns3_roh_service_task(struct work_struct *work)
{
	struct hns3_roh_device *hroh_dev =
		container_of(work, struct hns3_roh_device, srv_task.work);

	hns3_roh_mbx_service_task(hroh_dev);

	hns3_roh_poll_service_task(hroh_dev);
}

static void hns3_roh_dev_sw_state_init(struct hns3_roh_device *hroh_dev)
{
	clear_bit(HNS3_ROH_SW_STATE_MBX_SERVICE_SCHED, &hroh_dev->state);
	clear_bit(HNS3_ROH_SW_STATE_MBX_HANDLING, &hroh_dev->state);
}

static int hns3_roh_init_hw(struct hns3_roh_device *hroh_dev)
{
	struct device *dev = hroh_dev->dev;
	int ret;

	ret = hroh_dev->hw->cmdq_init(hroh_dev);
	if (ret) {
		dev_err(dev, "failed to init cmdq, ret = %d\n", ret);
		return ret;
	}

	ret = hns3_roh_init_irq(hroh_dev);
	if (ret) {
		dev_err(dev, "failed to init irq, ret = %d\n", ret);
		goto err_free_cmdq;
	}

	return 0;

err_free_cmdq:
	hroh_dev->hw->cmdq_exit(hroh_dev);
	return ret;
}

static void hns3_roh_uninit_hw(struct hns3_roh_device *hroh_dev)
{
	hns3_roh_uninit_irq(hroh_dev);

	hroh_dev->hw->cmdq_exit(hroh_dev);
}

static int hns3_roh_init(struct hns3_roh_device *hroh_dev)
{
	struct device *dev = hroh_dev->dev;
	int ret;

	ret = hns3_roh_init_hw(hroh_dev);
	if (ret) {
		dev_err(dev, "failed to init hw resources, ret = %d\n", ret);
		return ret;
	}

	ret = hns3_roh_register_device(hroh_dev);
	if (ret) {
		dev_err(dev, "failed to register roh device, ret = %d\n", ret);
		goto err_uninit_hw;
	}

	INIT_DELAYED_WORK(&hroh_dev->srv_task, hns3_roh_service_task);

	hns3_roh_enable_vector(&hroh_dev->abn_vector, true);

	hns3_roh_dev_sw_state_init(hroh_dev);

	hns3_roh_task_schedule(hroh_dev, round_jiffies_relative(HZ));

	dev_info(dev, "%s driver init success.\n", HNS3_ROH_NAME);

	return 0;

err_uninit_hw:
	hns3_roh_uninit_hw(hroh_dev);
	return ret;
}

static void hns3_roh_exit(struct hns3_roh_device *hroh_dev)
{
	cancel_delayed_work_sync(&hroh_dev->srv_task);

	hns3_roh_unregister_device(hroh_dev);

	hns3_roh_uninit_hw(hroh_dev);

	dev_info(&hroh_dev->pdev->dev,
		 "%s driver uninit success.\n", HNS3_ROH_NAME);
}

static const struct hns3_roh_hw hns3_roh_hw = {
	.cmdq_init = hns3_roh_cmdq_init,
	.cmdq_exit = hns3_roh_cmdq_exit,
};

static int hns3_roh_get_cfg_from_frame(struct hns3_roh_device *hroh_dev,
					struct hnae3_handle *handle)
{
	hroh_dev->pdev = handle->pdev;
	hroh_dev->dev = &handle->pdev->dev;

	hroh_dev->netdev = handle->rohinfo.netdev;
	hroh_dev->reg_base = handle->rohinfo.roh_io_base;

	hroh_dev->intr_info.vector_offset = handle->rohinfo.base_vector;
	hroh_dev->intr_info.vector_num = handle->rohinfo.num_vectors;
	if (hroh_dev->intr_info.vector_num < HNS3_ROH_MIN_VECTOR_NUM) {
		dev_err(hroh_dev->dev,
			"just %d intr resources, not enough(min: %d).\n",
			hroh_dev->intr_info.vector_num, HNS3_ROH_MIN_VECTOR_NUM);
		return -EINVAL;
	}

	hroh_dev->hw = &hns3_roh_hw;

	hroh_dev->priv->handle = handle;

	return 0;
}

static void hns3_roh_dfx_init(struct hns3_roh_device *hroh_dev);
static int __hns3_roh_init_instance(struct hnae3_handle *handle)
{
	struct hns3_roh_device *hroh_dev;
	int ret;

	hroh_dev = (struct hns3_roh_device *)roh_alloc_device(sizeof(*hroh_dev));
	if (!hroh_dev) {
		dev_err(&handle->pdev->dev, "failed to alloc roh dev.\n");
		return -ENOMEM;
	}

	hroh_dev->priv = kzalloc(sizeof(*hroh_dev->priv), GFP_KERNEL);
	if (!hroh_dev->priv) {
		ret = -ENOMEM;
		goto err_roh_alloc_device;
	}

	ret = hns3_roh_get_cfg_from_frame(hroh_dev, handle);
	if (ret) {
		dev_err(hroh_dev->dev, "failed to get cfg from frame, ret = %d\n", ret);
		goto err_kzalloc;
	}

	ret = hns3_roh_init(hroh_dev);
	if (ret) {
		dev_err(hroh_dev->dev, "failed to init roh, ret = %d\n", ret);
		goto err_kzalloc;
	}

	handle->priv = hroh_dev;

	set_bit(HNS3_ROH_STATE_INITED, &handle->rohinfo.reset_state);

	hns3_roh_dfx_init(hroh_dev);

	return 0;

err_kzalloc:
	kfree(hroh_dev->priv);
err_roh_alloc_device:
	roh_dealloc_device(&hroh_dev->roh_dev);
	return ret;
}

static void hns3_roh_dfx_uninit(struct hns3_roh_device *hroh_dev);
static void __hns3_roh_uninit_instance(struct hnae3_handle *handle)
{
	struct hns3_roh_device *hroh_dev = (struct hns3_roh_device *)handle->priv;

	if (!hroh_dev)
		return;

	hns3_roh_dfx_uninit(hroh_dev);

	if (!test_and_clear_bit(HNS3_ROH_STATE_INITED, &handle->rohinfo.reset_state))
		netdev_warn(hroh_dev->netdev, "already uninitialized\n");

	hns3_roh_enable_vector(&hroh_dev->abn_vector, false);

	handle->priv = NULL;

	hns3_roh_exit(hroh_dev);

	kfree(hroh_dev->priv);

	roh_dealloc_device(&hroh_dev->roh_dev);
}

static int hns3_roh_init_instance(struct hnae3_handle *handle)
{
	struct device *dev = &handle->pdev->dev;
	const struct pci_device_id *id;
	int ret;

	id = pci_match_id(hns3_roh_pci_tbl, handle->pdev);
	if (!id)
		return 0;

	if (id->driver_data) {
		dev_err(dev, "not support vf.\n");
		return -EINVAL;
	}

	ret = __hns3_roh_init_instance(handle);
	if (ret) {
		dev_err(dev, "failed to init instance, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

static void hns3_roh_uninit_instance(struct hnae3_handle *handle, bool reset)
{
	__hns3_roh_uninit_instance(handle);
}

static int hns3_roh_reset_notify_init(struct hnae3_handle *handle)
{
	struct device *dev = &handle->pdev->dev;
	int ret;

	ret = __hns3_roh_init_instance(handle);
	if (ret) {
		dev_err(dev, "failed to reinit in roh reset process, ret = %d\n", ret);
		handle->priv = NULL;
		clear_bit(HNS3_ROH_STATE_INITED, &handle->rohinfo.reset_state);
	}

	return 0;
}

static int hns3_roh_reset_notify_uninit(struct hnae3_handle *handle)
{
	msleep(HNS3_ROH_HW_RST_UNINT_DELAY);
	__hns3_roh_uninit_instance(handle);

	return 0;
}

static int hns3_roh_reset_notify(struct hnae3_handle *handle,
				 enum hnae3_reset_notify_type type)
{
	int ret = 0;

	switch (type) {
	case HNAE3_INIT_CLIENT:
		ret = hns3_roh_reset_notify_init(handle);
		break;
	case HNAE3_UNINIT_CLIENT:
		ret = hns3_roh_reset_notify_uninit(handle);
		break;
	case HNAE3_DOWN_CLIENT:
		set_bit(HNS3_ROH_STATE_CMD_DISABLE, &handle->rohinfo.reset_state);
		break;
	default:
		break;
	}

	return ret;
}

static const struct hnae3_client_ops hns3_roh_ops = {
	.init_instance = hns3_roh_init_instance,
	.uninit_instance = hns3_roh_uninit_instance,
	.reset_notify = hns3_roh_reset_notify,
};

static struct hnae3_client hns3_roh_client = {
	.name = "hns3_roh_hw",
	.type = HNAE3_CLIENT_ROH,
	.ops = &hns3_roh_ops,
};

static ssize_t hns3_roh_dfx_cmd_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *pos)
{
#define HNS3_ROH_DFX_READ_LEN 256
	int uncopy_bytes;
	char *buf;
	int len;

	if (*pos != 0)
		return 0;

	if (count < HNS3_ROH_DFX_READ_LEN)
		return -ENOSPC;

	buf = kzalloc(HNS3_ROH_DFX_READ_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len = scnprintf(buf, HNS3_ROH_DFX_READ_LEN, "%s\n", "echo help to cmd to get help info");
	uncopy_bytes = copy_to_user(buffer, buf, len);

	kfree(buf);

	if (uncopy_bytes)
		return -EFAULT;

	return (*pos = len);
}

static void hns3_roh_dfx_help(struct hns3_roh_device *hroh_dev)
{
	dev_info(hroh_dev->dev, "dev info\n");
}

static void hns3_roh_dfx_dump_dev_info(struct hns3_roh_device *hroh_dev)
{
	struct device *dev = hroh_dev->dev;

	dev_info(dev, "PCIe device id: 0x%x\n", hroh_dev->pdev->device);
	dev_info(dev, "PCIe device name: %s\n", pci_name(hroh_dev->pdev));
	dev_info(dev, "Network device name: %s\n", netdev_name(hroh_dev->netdev));
	dev_info(dev, "BAR2~3 base addr: 0x%llx\n", (u64)hroh_dev->reg_base);

	dev_info(dev, "Base vector: %d\n", hroh_dev->intr_info.base_vector);
	dev_info(dev, "ROH vector offset: %d\n", hroh_dev->intr_info.vector_offset);
	dev_info(dev, "ROH vector num: %d\n", hroh_dev->intr_info.vector_num);

	dev_info(dev, "ABN vector0 irq: %d\n", hroh_dev->abn_vector.vector_irq);
	dev_info(dev, "ABN vector0 addr: 0x%llx\n", (u64)hroh_dev->abn_vector.addr);
	dev_info(dev, "ABN vector0 name: %s\n", hroh_dev->abn_vector.name);
}

static int hns3_roh_dfx_check_cmd(struct hns3_roh_device *hroh_dev, char *cmd_buf)
{
	int ret = 0;

	if (strncmp(cmd_buf, "help", strlen("help")) == 0)
		hns3_roh_dfx_help(hroh_dev);
	else if (strncmp(cmd_buf, "dev info", strlen("dev info")) == 0)
		hns3_roh_dfx_dump_dev_info(hroh_dev);
	else
		ret = -EOPNOTSUPP;
	return ret;
}

static ssize_t hns3_roh_dfx_cmd_write(struct file *filp, const char __user *buffer,
				      size_t count, loff_t *pos)
{
#define HNS3_ROH_DFX_WRITE_LEN 1024
	struct hns3_roh_device *hroh_dev = filp->private_data;
	char *cmd_buf, *cmd_buf_tmp;
	int uncopied_bytes;
	int ret;

	if (*pos != 0)
		return 0;

	if (count > HNS3_ROH_DFX_WRITE_LEN)
		return -ENOSPC;

	cmd_buf = kzalloc(count + 1, GFP_KERNEL);
	if (!cmd_buf)
		return count;

	uncopied_bytes = copy_from_user(cmd_buf, buffer, count);
	if (uncopied_bytes) {
		kfree(cmd_buf);
		return -EFAULT;
	}

	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = cmd_buf_tmp - cmd_buf + 1;
	}

	ret = hns3_roh_dfx_check_cmd(hroh_dev, cmd_buf);
	if (ret)
		hns3_roh_dfx_help(hroh_dev);

	kfree(cmd_buf);
	cmd_buf = NULL;

	return count;
}

static const struct file_operations hns3_roh_dfx_cmd_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = hns3_roh_dfx_cmd_read,
	.write = hns3_roh_dfx_cmd_write,
};

static void hns3_roh_dfx_init(struct hns3_roh_device *hroh_dev)
{
	const char *name = pci_name(hroh_dev->pdev);
	struct dentry *entry;

	if (IS_ERR_OR_NULL(hns3_roh_dfx_root))
		return;

	hroh_dev->dfx_debugfs = debugfs_create_dir(name, hns3_roh_dfx_root);
	if (IS_ERR_OR_NULL(hroh_dev->dfx_debugfs))
		return;

	entry = debugfs_create_file("hns3_roh_dfx", 0600,
				    hroh_dev->dfx_debugfs, hroh_dev,
				    &hns3_roh_dfx_cmd_fops);
	if (IS_ERR_OR_NULL(entry)) {
		debugfs_remove_recursive(hroh_dev->dfx_debugfs);
		hroh_dev->dfx_debugfs = NULL;
		return;
	}
}

static void hns3_roh_dfx_uninit(struct hns3_roh_device *hroh_dev)
{
	if (IS_ERR_OR_NULL(hroh_dev->dfx_debugfs))
		return;

	debugfs_remove_recursive(hroh_dev->dfx_debugfs);
	hroh_dev->dfx_debugfs = NULL;
}

static void hns3_roh_dfx_register_debugfs(const char *dir_name)
{
	hns3_roh_dfx_root = debugfs_create_dir(dir_name, NULL);
}

static void hns3_roh_dfx_unregister_debugfs(void)
{
	if (IS_ERR_OR_NULL(hns3_roh_dfx_root))
		return;

	debugfs_remove_recursive(hns3_roh_dfx_root);
	hns3_roh_dfx_root = NULL;
}

static int __init hns3_roh_module_init(void)
{
	int ret;

	hns3_roh_wq = alloc_workqueue("%s", 0, 0, HNS3_ROH_NAME);
	if (!hns3_roh_wq) {
		pr_err("%s: failed to create wq.\n", HNS3_ROH_NAME);
		return -ENOMEM;
	}

	hns3_roh_dfx_register_debugfs(HNS3_ROH_NAME);

	ret = hnae3_register_client(&hns3_roh_client);
	if (ret)
		goto out;

	return 0;

out:
	hns3_roh_dfx_unregister_debugfs();
	destroy_workqueue(hns3_roh_wq);
	return ret;
}

static void __exit hns3_roh_module_cleanup(void)
{
	hnae3_unregister_client(&hns3_roh_client);

	hns3_roh_dfx_unregister_debugfs();

	destroy_workqueue(hns3_roh_wq);
}

module_init(hns3_roh_module_init);
module_exit(hns3_roh_module_cleanup);

MODULE_LICENSE("GPL");
MODULE_VERSION(HNS3_ROH_VERSION);
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Hisilicon Hip09 Family ROH Driver");
