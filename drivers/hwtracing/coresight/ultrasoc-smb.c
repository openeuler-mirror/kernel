// SPDX-License-Identifier: MIT/GPL 
/*
 * Siemens System Memory Buffer driver.
 * Copyright(c) 2021, HiSilicon Limited.
 */

#include <linux/acpi.h>
#include <linux/circ_buf.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>

#include "ultrasoc-smb.h"

DEFINE_CORESIGHT_DEVLIST(sink_devs, "smb");

static bool smb_buffer_is_empty(struct smb_drv_data *drvdata)
{
	u32 buf_status = readl(drvdata->base + SMB_LB_INT_STS);

	return buf_status & BIT(0) ? false : true;
}

static bool smb_buffer_cmp_pointer(struct smb_drv_data *drvdata)
{
	u32 wr_offset, rd_offset;

	wr_offset = readl(drvdata->base + SMB_LB_WR_ADDR);
	rd_offset = readl(drvdata->base + SMB_LB_RD_ADDR);
	return wr_offset == rd_offset;
}

static void smb_reset_buffer_status(struct smb_drv_data *drvdata)
{
	writel(0xf, drvdata->base + SMB_LB_INT_STS);
}

/* Purge data remaining in hardware path to SMB. */
static void smb_purge_data(struct smb_drv_data *drvdata)
{
	writel(0x1, drvdata->base + SMB_LB_PURGE);
}

static void smb_update_data_size(struct smb_drv_data *drvdata)
{
	struct smb_data_buffer *sdb = &drvdata->sdb;
	u32 write_offset;

	smb_purge_data(drvdata);
	if (smb_buffer_cmp_pointer(drvdata)) {
		if (smb_buffer_is_empty(drvdata))
			sdb->data_size = 0;
		else
			sdb->data_size = sdb->buf_size;
		return;
	}

	write_offset = readl(drvdata->base + SMB_LB_WR_ADDR) - sdb->start_addr;
	sdb->data_size = CIRC_CNT(write_offset, sdb->rd_offset, sdb->buf_size);
}

static int smb_open(struct inode *inode, struct file *file)
{
	struct smb_drv_data *drvdata = container_of(file->private_data,
						    struct smb_drv_data, miscdev);

	if (local_cmpxchg(&drvdata->reading, 0, 1))
		return -EBUSY;

	return 0;
}

static ssize_t smb_read(struct file *file, char __user *data, size_t len, loff_t *ppos)
{
	struct smb_drv_data *drvdata = container_of(file->private_data,
						    struct smb_drv_data, miscdev);
	struct smb_data_buffer *sdb = &drvdata->sdb;
	struct device *dev = &drvdata->csdev->dev;
	unsigned long flags;
	int to_copy = 0;

	spin_lock_irqsave(&drvdata->spinlock, flags);

	if (!sdb->data_size) {
		smb_update_data_size(drvdata);
		if (!sdb->data_size)
			goto out;
	}

	if (atomic_read(drvdata->csdev->refcnt)) {
		to_copy = -EBUSY;
		goto out;
	}

	to_copy = min(sdb->data_size, len);

	/* Copy parts of trace data when the read pointer will wrap around SMB buffer. */
	if (sdb->rd_offset + to_copy > sdb->buf_size)
		to_copy = sdb->buf_size - sdb->rd_offset;

	if (copy_to_user(data, (void *)sdb->buf_base + sdb->rd_offset, to_copy)) {
		dev_dbg(dev, "Failed to copy data to user.\n");
		to_copy = -EFAULT;
		goto out;
	}

	*ppos += to_copy;
	sdb->data_size -= to_copy;
	sdb->rd_offset += to_copy;
	sdb->rd_offset %= sdb->buf_size;
	writel(sdb->start_addr + sdb->rd_offset, drvdata->base + SMB_LB_RD_ADDR);
	dev_dbg(dev, "%d bytes copied.\n", to_copy);
out:
	if (!sdb->data_size)
		smb_reset_buffer_status(drvdata);
	spin_unlock_irqrestore(&drvdata->spinlock, flags);
	return to_copy;
}

static int smb_release(struct inode *inode, struct file *file)
{
	struct smb_drv_data *drvdata = container_of(file->private_data,
						    struct smb_drv_data, miscdev);
	local_set(&drvdata->reading, 0);
	return 0;
}

static const struct file_operations smb_fops = {
	.owner		= THIS_MODULE,
	.open		= smb_open,
	.read		= smb_read,
	.release	= smb_release,
	.llseek		= no_llseek,
};

smb_reg(read_pos, SMB_LB_RD_ADDR);
smb_reg(write_pos, SMB_LB_WR_ADDR);
smb_reg(buf_status, SMB_LB_INT_STS);

static ssize_t buf_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct smb_drv_data *drvdata = dev_get_drvdata(dev->parent);

	return sysfs_emit(buf, "0x%lx\n", drvdata->sdb.buf_size);
}
static DEVICE_ATTR_RO(buf_size);

static struct attribute *smb_sink_attrs[] = {
	&dev_attr_read_pos.attr,
	&dev_attr_write_pos.attr,
	&dev_attr_buf_status.attr,
	&dev_attr_buf_size.attr,
	NULL,
};

static const struct attribute_group smb_sink_group = {
	.attrs = smb_sink_attrs,
	.name = "status",
};

static const struct attribute_group *smb_sink_groups[] = {
	&smb_sink_group,
	NULL,
};

static int smb_set_perf_buffer(struct perf_output_handle *handle)
{
	struct cs_buffers *buf = etm_perf_sink_config(handle);
	u32 head;

	if (!buf)
		return -EINVAL;

	/* Wrap head around to the amount of space we have */
	head = handle->head & ((buf->nr_pages << PAGE_SHIFT) - 1);

	/* Find the page to write to and offset within that page */
	buf->cur = head / PAGE_SIZE;
	buf->offset = head % PAGE_SIZE;

	local_set(&buf->data_size, 0);

	return 0;
}

static void smb_enable_hw(struct smb_drv_data *drvdata)
{
	writel(0x1, drvdata->base + SMB_GLOBAL_EN);
}

static void smb_disable_hw(struct smb_drv_data *drvdata)
{
	writel(0x0, drvdata->base + SMB_GLOBAL_EN);
}

static int smb_enable_sysfs(struct smb_drv_data *drvdata)
{
	if (drvdata->mode == CS_MODE_PERF)
		return -EBUSY;

	if (drvdata->mode == CS_MODE_SYSFS)
		return 0;

	smb_enable_hw(drvdata);
	drvdata->mode = CS_MODE_SYSFS;
	return 0;
}

static int smb_enable_perf(struct smb_drv_data *drvdata, void *data)
{
	struct device *dev = &drvdata->csdev->dev;
	struct perf_output_handle *handle = data;
	pid_t pid;

	if (drvdata->mode == CS_MODE_SYSFS) {
		dev_err(dev, "Device is already in used by sysfs.\n");
		return -EBUSY;
	}

	/* Get a handle on the pid of the target process*/
	pid = task_pid_nr(handle->event->owner);
	if (drvdata->pid != -1 && drvdata->pid != pid) {
		dev_err(dev, "Device is already in used by other session.\n");
		return -EBUSY;
	}
	/* The sink is already enabled by this session. */
	if (drvdata->pid == pid)
		return 0;

	if (smb_set_perf_buffer(handle))
		return -EINVAL;

	smb_enable_hw(drvdata);
	drvdata->pid = pid;
	drvdata->mode = CS_MODE_PERF;

	return 0;
}

static int smb_enable(struct coresight_device *csdev, u32 mode, void *data)
{
	struct smb_drv_data *drvdata = dev_get_drvdata(csdev->dev.parent);
	unsigned long flags;
	int ret = -EINVAL;

	/* Do nothing if trace data is reading by other interface now. */
	if (local_read(&drvdata->reading))
		return -EBUSY;

	spin_lock_irqsave(&drvdata->spinlock, flags);

	if (mode == CS_MODE_SYSFS)
		ret = smb_enable_sysfs(drvdata);

	if (mode == CS_MODE_PERF)
		ret = smb_enable_perf(drvdata, data);

	spin_unlock_irqrestore(&drvdata->spinlock, flags);

	if (ret)
		return ret;

	atomic_inc(csdev->refcnt);
	dev_dbg(&csdev->dev, "Ultrasoc SMB enabled.\n");

	return 0;
}

static int smb_disable(struct coresight_device *csdev)
{
	struct smb_drv_data *drvdata = dev_get_drvdata(csdev->dev.parent);
	unsigned long flags;

	spin_lock_irqsave(&drvdata->spinlock, flags);

	if (atomic_dec_return(csdev->refcnt)) {
		spin_unlock_irqrestore(&drvdata->spinlock, flags);
		return -EBUSY;
	}

	WARN_ON_ONCE(drvdata->mode == CS_MODE_DISABLED);
	smb_disable_hw(drvdata);

	/*
	 * Data remaining in hardware path will be sent to SMB after purge, so needs to
	 * synchronize the read pointer to write pointer in perf mode.
	 */
	smb_purge_data(drvdata);
	if (drvdata->mode == CS_MODE_PERF)
		writel(readl(drvdata->base + SMB_LB_WR_ADDR), drvdata->base + SMB_LB_RD_ADDR);

	/* Dissociate from the target process. */
	drvdata->pid = -1;
	drvdata->mode = CS_MODE_DISABLED;
	spin_unlock_irqrestore(&drvdata->spinlock, flags);

	dev_dbg(&csdev->dev, "Ultrasoc SMB disabled.\n");
	return 0;
}

static void *smb_alloc_buffer(struct coresight_device *csdev,
			      struct perf_event *event, void **pages,
			      int nr_pages, bool overwrite)
{
	struct cs_buffers *buf;
	int node;

	node = (event->cpu == -1) ? NUMA_NO_NODE : cpu_to_node(event->cpu);
	buf = kzalloc_node(sizeof(struct cs_buffers), GFP_KERNEL, node);
	if (!buf)
		return NULL;

	buf->snapshot = overwrite;
	buf->nr_pages = nr_pages;
	buf->data_pages = pages;

	return buf;
}

static void smb_free_buffer(void *config)
{
	struct cs_buffers *buf = config;

	kfree(buf);
}

static void smb_sync_perf_buffer(struct smb_drv_data *drvdata,
				 struct cs_buffers *buf, unsigned long data_size)
{
	struct smb_data_buffer *sdb = &drvdata->sdb;
	char **dst_pages = (char **)buf->data_pages;
	unsigned long buf_offset = buf->offset;
	unsigned int cur = buf->cur;
	unsigned long to_copy;

	while (data_size) {
		/* Copy parts of trace data when the read pointer will wrap around SMB buffer. */
		if (sdb->rd_offset + PAGE_SIZE - buf_offset > sdb->buf_size)
			to_copy = sdb->buf_size - sdb->rd_offset;
		else
			to_copy = min(data_size, PAGE_SIZE - buf_offset);

		memcpy_fromio(dst_pages[cur] + buf_offset, sdb->buf_base + sdb->rd_offset, to_copy);

		buf_offset += to_copy;
		if (buf_offset >= PAGE_SIZE) {
			buf_offset = 0;
			cur++;
			cur %= buf->nr_pages;
		}
		data_size -= to_copy;
		/* ensure memcpy finished before update the read pointer */
		sdb->rd_offset += to_copy;
		sdb->rd_offset %= sdb->buf_size;
	}

	sdb->data_size = 0;
	writel(sdb->start_addr + sdb->rd_offset, drvdata->base + SMB_LB_RD_ADDR);
	smb_reset_buffer_status(drvdata);
}

static unsigned long smb_update_buffer(struct coresight_device *csdev,
				       struct perf_output_handle *handle,
				       void *sink_config)
{
	struct smb_drv_data *drvdata = dev_get_drvdata(csdev->dev.parent);
	struct smb_data_buffer *sdb = &drvdata->sdb;
	struct cs_buffers *buf = sink_config;
	unsigned long data_size = 0;
	unsigned long flags;
	bool lost = false;

	if (!buf)
		return 0;

	spin_lock_irqsave(&drvdata->spinlock, flags);

	/* Don't do anything if another tracer is using this sink. */
	if (atomic_read(csdev->refcnt) != 1)
		goto out;

	smb_update_data_size(drvdata);
	data_size = sdb->data_size;
	if (data_size > handle->size) {
		sdb->rd_offset += data_size - handle->size;
		sdb->rd_offset %= sdb->buf_size;
		data_size = handle->size;
		lost = true;
	}

	smb_sync_perf_buffer(drvdata, buf, data_size);
	if (!buf->snapshot && lost)
		perf_aux_output_flag(handle, PERF_AUX_FLAG_TRUNCATED);

out:
	spin_unlock_irqrestore(&drvdata->spinlock, flags);
	return data_size;
}

static const struct coresight_ops_sink smb_cs_ops = {
	.enable		= smb_enable,
	.disable	= smb_disable,
	.alloc_buffer	= smb_alloc_buffer,
	.free_buffer	= smb_free_buffer,
	.update_buffer	= smb_update_buffer,
};

static const struct coresight_ops cs_ops = {
	.sink_ops	= &smb_cs_ops,
};

static int smb_init_data_buffer(struct platform_device *pdev, struct smb_data_buffer *sdb)
{
	struct resource *res;
	void __iomem *base;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (IS_ERR(res)) {
		dev_err(&pdev->dev, "SMB device failed to get resource.\n");
		return -EINVAL;
	}

	sdb->start_addr = res->start & SMB_BASE_LOW_MASK;
	sdb->buf_size = resource_size(res);
	if (sdb->buf_size == 0)
		return -EINVAL;

	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	sdb->buf_base = base;

	return 0;
}

static void smb_init_hw(struct smb_drv_data *drvdata)
{
	u32 value;

	/* First disable smb and clear the status of SMB buffer */
	smb_reset_buffer_status(drvdata);
	smb_disable_hw(drvdata);
	smb_purge_data(drvdata);

	/* Using smb in single-end mode, and set other configures default */
	value = SMB_BUF_CFG_STREAMING | SMB_BUF_SINGLE_END | SMB_BUF_EN;
	writel(value, drvdata->base + SMB_LB_CFG_LO);
	value = SMB_MSG_FILTER(0x0, 0xff);
	writel(value, drvdata->base + SMB_LB_CFG_HI);

	writel(SMB_GLOBAL_CFG, drvdata->base + SMB_CFG_REG);
	writel(SMB_GLB_INT_CFG, drvdata->base + SMB_GLOBAL_INT);
	writel(SMB_BUF_INT_CFG, drvdata->base + SMB_LB_INT_CTRL);
}

static int smb_register_sink(struct platform_device *pdev, struct smb_drv_data *drvdata)
{
	struct coresight_platform_data *pdata = NULL;
	struct coresight_desc desc = { 0 };
	int ret;

	pdata = coresight_get_platform_data(&pdev->dev);
	if (IS_ERR(pdata))
		return PTR_ERR(pdata);

	desc.type = CORESIGHT_DEV_TYPE_SINK;
	desc.subtype.sink_subtype = CORESIGHT_DEV_SUBTYPE_SINK_BUFFER;
	desc.ops = &cs_ops;
	desc.pdata = pdata;
	desc.dev = &pdev->dev;
	desc.groups = smb_sink_groups;
	desc.name = coresight_alloc_device_name(&sink_devs, &pdev->dev);
	if (!desc.name) {
		dev_err(&pdev->dev, "Failed to alloc coresight device name.");
		return -ENOMEM;
	}

	drvdata->csdev = coresight_register(&desc);
	if (IS_ERR(drvdata->csdev))
		return PTR_ERR(drvdata->csdev);

	drvdata->miscdev.name = desc.name;
	drvdata->miscdev.minor = MISC_DYNAMIC_MINOR;
	drvdata->miscdev.fops = &smb_fops;
	ret = misc_register(&drvdata->miscdev);
	if (ret) {
		coresight_unregister(drvdata->csdev);
		dev_err(&pdev->dev, "Failed to register misc, ret=%d.\n", ret);
	}

	return ret;
}

static void smb_unregister_sink(struct smb_drv_data *drvdata)
{
	misc_deregister(&drvdata->miscdev);
	coresight_unregister(drvdata->csdev);
}

/*
 * Send ultrasoc messge to control hardwares on the tracing path,
 * using DSM calls to avoid exposing ultrasoc message format.
 */
static int smb_config_inport(struct device *dev, bool enable)
{
	u32 flag = enable ? 1 : 0;
	union acpi_object *obj;
	guid_t guid;

	if (guid_parse("82ae1283-7f6a-4cbe-aa06-53e8fb24db18", &guid)) {
		dev_err(dev, "Get GUID failed.\n");
		return -EINVAL;
	}

	obj = acpi_evaluate_dsm(ACPI_HANDLE(dev), &guid, 0, flag, NULL);
	if (!obj)
		dev_err(dev, "ACPI handle failed!\n");
	else
		ACPI_FREE(obj);

	return 0;
}

static int smb_probe(struct platform_device *pdev)
{
	struct smb_drv_data *drvdata;
	int ret;

	drvdata = devm_kzalloc(&pdev->dev, sizeof(*drvdata), GFP_KERNEL);
	if (!drvdata)
		return -ENOMEM;

	drvdata->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(drvdata->base)) {
		dev_err(&pdev->dev, "Failed to ioremap resource.\n");
		return PTR_ERR(drvdata->base);
	}

	ret = smb_init_data_buffer(pdev, &drvdata->sdb);
	if (ret) {
		dev_err(&pdev->dev, "Failed to init buffer, ret = %d.\n", ret);
		return ret;
	}

	smb_init_hw(drvdata);
	spin_lock_init(&drvdata->spinlock);
	drvdata->pid = -1;

	ret = smb_register_sink(pdev, drvdata);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register smb sink.\n");
		return ret;
	}

	ret = smb_config_inport(&pdev->dev, true);
	if (ret) {
		smb_unregister_sink(drvdata);
		return ret;
	}

	platform_set_drvdata(pdev, drvdata);
	return 0;
}

static int smb_remove(struct platform_device *pdev)
{
	struct smb_drv_data *drvdata = platform_get_drvdata(pdev);
	int ret;

	ret = smb_config_inport(&pdev->dev, false);
	if (ret)
		return ret;

	smb_unregister_sink(drvdata);
	return 0;
}

#ifdef CONFIG_ACPI
static const struct acpi_device_id ultrasoc_smb_acpi_match[] = {
	{"HISI03A1", 0},
	{},
};
MODULE_DEVICE_TABLE(acpi, ultrasoc_smb_acpi_match);
#endif

static struct platform_driver smb_driver = {
	.driver = {
		.name = "ultrasoc-smb",
		.acpi_match_table = ACPI_PTR(ultrasoc_smb_acpi_match),
		.suppress_bind_attrs = true,
	},
	.probe = smb_probe,
	.remove = smb_remove,
};
module_platform_driver(smb_driver);

MODULE_DESCRIPTION("Ultrasoc smb driver");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Jonathan Zhou <jonathan.zhouwen@huawei.com>");
MODULE_AUTHOR("Qi Liu <liuqi115@huawei.com>");
