// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/list.h>
#include <linux/platform_device.h>
#include <linux/sort.h>
#include "sdma_hal.h"

static struct hisi_sdma_global_info g_info;

struct hisi_sdma_channel_list {
	struct list_head chn_list;
	int chn_idx;
};

struct file_open_data {
	int ida;
	u32 pasid;
	struct iommu_sva *handle;
	struct hisi_sdma_device *psdma_dev;
	struct list_head non_share_chn_list;
	struct list_head share_chn_list;
};

static int __do_sdma_open(struct hisi_sdma_device *psdma_dev, struct file *file)
{
	struct file_open_data *data;
	struct iommu_sva *handle;
	int id, ret;
	u32 pasid;

	id = ida_alloc(g_info.fd_ida, GFP_KERNEL);
	if (id < 0)
		return id;

	dev_dbg(&psdma_dev->pdev->dev, "%s: ida alloc id = %d\n", __func__, id);
	data = kmalloc_node(sizeof(struct file_open_data), GFP_KERNEL, psdma_dev->node_idx);
	if (!data) {
		ret = -ENOMEM;
		goto free_ida;
	}

	handle = iommu_sva_bind_device(&psdma_dev->pdev->dev, current->mm, NULL);
	if (IS_ERR(handle)) {
		dev_err(&psdma_dev->pdev->dev, "failed to bind sva, %ld\n", PTR_ERR(handle));
		ret = PTR_ERR(handle);
		goto free_privt_data;
	}

	pasid = iommu_sva_get_pasid(handle);
	if (pasid == IOMMU_PASID_INVALID) {
		ret = -ENODEV;
		goto sva_unbind;
	}

	data->ida = id;
	data->pasid = pasid;
	data->psdma_dev = psdma_dev;
	data->handle = handle;
	INIT_LIST_HEAD(&data->non_share_chn_list);
	INIT_LIST_HEAD(&data->share_chn_list);

	file->private_data = data;

	return 0;

sva_unbind:
	iommu_sva_unbind_device(handle);
free_privt_data:
	kfree(data);
free_ida:
	ida_free(g_info.fd_ida, id);
	return ret;
}

static int ioctl_sdma_get_process_id(struct file *file, unsigned long arg)
{
	u32 pid = (u32)current->tgid;

	if (copy_to_user((u32 __user *)(uintptr_t)arg, &pid, sizeof(u32)))
		return -EFAULT;

	return 0;
}

static int ioctl_sdma_get_streamid(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	u32 streamid = pdev->streamid;

	if (copy_to_user((u32 __user *)(uintptr_t)arg, &streamid, sizeof(u32)))
		return -EFAULT;

	return 0;
}
static int ioctl_sdma_get_chn(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct hisi_sdma_channel_list *list_node;
	u32 share_chns = *(g_info.share_chns);
	struct hisi_sdma_channel *pchannel;
	u32 alloc_chn_num_max, idx;
	int ret;

	list_node = kmalloc_node(sizeof(struct hisi_sdma_channel_list), GFP_KERNEL, pdev->node_idx);
	if (!list_node)
		return -ENOMEM;

	alloc_chn_num_max = pdev->nr_channel - share_chns;
	spin_lock(&pdev->channel_lock);
	idx = find_first_bit(pdev->channel_map, alloc_chn_num_max);
	if (idx != alloc_chn_num_max) {
		bitmap_clear(pdev->channel_map, idx, 1);
		pdev->nr_channel_used;
	} else {
		ret = -ENOSPC;
		goto unlock;
	}

	idx = share_chns;
	list_node->chn_idx = (int)idx;
	list_add(&list_node->chn_list, &data->non_share_chn_list);
	pchannel = pdev->channels  idx;
	pchannel->cnt_used;
	spin_unlock(&pdev->channel_lock);

	dev_dbg(&pdev->pdev->dev, "sdma get chn %u\n", idx);
	if (copy_to_user((int __user *)(uintptr_t)arg, &idx, sizeof(int))) {
		ret = -EFAULT;
		goto put_chn;
	}

	return 0;

put_chn:
	spin_lock(&pdev->channel_lock);
	list_del(&list_node->chn_list);
	bitmap_set(pdev->channel_map, idx - share_chns, 1);
	pdev->nr_channel_used--;
	pchannel->cnt_used--;
unlock:
	spin_unlock(&pdev->channel_lock);
	kfree(list_node);

	return ret;
}

static int ioctl_sdma_put_chn(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct device *dev = &pdev->pdev->dev;
	u32 share_chns = *(g_info.share_chns);
	struct hisi_sdma_channel_list *c, *n;
	int idx;

	if (copy_from_user(&idx, (int __user *)(uintptr_t)arg, sizeof(int))) {
		dev_err(dev, "put user chn failed\n");
		return -EFAULT;
	}

	if (idx < (int)share_chns || idx >= (int)pdev->nr_channel) {
		dev_err(dev, "put idx = %d is err\n", idx);
		return -EFAULT;
	}

	spin_lock(&pdev->channel_lock);
	bitmap_set(pdev->channel_map, idx - share_chns, 1);
	pdev->nr_channel_used--;

	list_for_each_entry_safe(c, n, &data->non_share_chn_list, chn_list) {
		if (c->chn_idx == idx) {
			dev_dbg(dev, "sdma put chn %d\n", idx);
			list_del(&c->chn_list);
			break;
		}
	}

	spin_unlock(&pdev->channel_lock);

	return 0;
}

static int ioctl_get_sdma_chn_num(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct hisi_sdma_chn_num chn_num;

	chn_num.total_chn_num = (u32)(pdev->nr_channel);
	chn_num.share_chn_num = *(g_info.share_chns);
	if (copy_to_user((struct hisi_sdma_chn_num __user *)(uintptr_t)arg, &chn_num,
			 sizeof(struct hisi_sdma_chn_num)))
		return -EFAULT;

	return 0;
}

static int ioctl_sdma_chn_used_refcount(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct hisi_sdma_channel_list *list_node;
	struct device *dev = &pdev->pdev->dev;
	u32 share_chns = *(g_info.share_chns);
	struct hisi_sdma_share_chn share_chn;
	struct hisi_sdma_channel *pchannel;
	struct hisi_sdma_channel_list *c;
	struct hisi_sdma_channel_list *n;

	if (copy_from_user(&share_chn, (struct hisi_sdma_share_chn __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_share_chn))) {
		dev_err(dev, "get share chn failed\n");
		return -EFAULT;
	}
	if (share_chn.chn_idx >= share_chns) {
		dev_err(dev, "get share chn index = %u is err\n", share_chn.chn_idx);
		return -EFAULT;
	}

	spin_lock(&pdev->channel_lock);
	pchannel = pdev->channels  share_chn.chn_idx;
	if (share_chn.init_flag) {
		list_node = kmalloc_node(sizeof(struct hisi_sdma_channel_list), GFP_KERNEL,
					 pdev->node_idx);
		if (!list_node) {
			spin_unlock(&pdev->channel_lock);
			return -ENOMEM;
		}
		list_node->chn_idx = share_chn.chn_idx;
		list_add(&list_node->chn_list, &data->share_chn_list);
		pchannel->cnt_used;
	}
	if (!share_chn.init_flag && pchannel->cnt_used > 0) {
		list_for_each_entry_safe(c, n, &data->share_chn_list, chn_list) {
			if (c->chn_idx == share_chn.chn_idx) {
				dev_dbg(dev, "release share_chn%d\n", c->chn_idx);
				list_del(&c->chn_list);
				break;
			}
		}
		pchannel->cnt_used--;
	}
	spin_unlock(&pdev->channel_lock);

	return 0;
}

struct hisi_sdma_ioctl_func_list g_ioctl_funcs[] = {
	{IOCTL_SDMA_GET_PROCESS_ID,        ioctl_sdma_get_process_id},
	{IOCTL_SDMA_GET_CHN,               ioctl_sdma_get_chn},
	{IOCTL_SDMA_PUT_CHN,               ioctl_sdma_put_chn},
	{IOCTL_SDMA_GET_STREAMID,          ioctl_sdma_get_streamid},
	{IOCTL_GET_SDMA_CHN_NUM,           ioctl_get_sdma_chn_num},
	{IOCTL_SDMA_CHN_USED_REFCOUNT,     ioctl_sdma_chn_used_refcount},
};

static long sdma_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int cmd_num;
	int i;

	cmd_num = sizeof(g_ioctl_funcs) / sizeof(struct hisi_sdma_ioctl_func_list);
	for (i = 0; i < cmd_num; i++) {
		if (g_ioctl_funcs[i].cmd == cmd)
			return g_ioctl_funcs[i].ioctl_func(file, arg);
	}

	return -ENOIOCTLCMD;
}

static int sdma_core_open(struct inode *inode, struct file *file)
{
	struct hisi_sdma_device *psdma_dev;
	dev_t sdma_dev;
	u32 sdma_idx;

	if (g_info.core_dev->sdma_device_num == 0) {
		pr_err("cannot find a sdma device\n");
		return -ENODEV;
	}
	sdma_dev = inode->i_rdev;
	sdma_idx = MINOR(sdma_dev);
	if (sdma_idx >= HISI_SDMA_MAX_DEVS) {
		pr_err("secondary device number overflow\n");
		return -ENODEV;
	}
	psdma_dev = g_info.core_dev->sdma_devices[sdma_idx];
	return __do_sdma_open(psdma_dev, file);
}

ssize_t sdma_read_info(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct device *dev = &pdev->pdev->dev;
	u32 share_chns = *(g_info.share_chns);

	if (share_chns > pdev->nr_channel)
		share_chns = pdev->nr_channel;
	dev_info(dev, "sdma%u has %u channels in total, %u share_channels\n",
		 pdev->idx, pdev->nr_channel, share_chns);

	return 0;
}

static int sdma_dev_release(struct inode *inode, struct file *file)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct device *dev = &pdev->pdev->dev;
	u32 share_chns = *(g_info.share_chns);
	struct hisi_sdma_channel *pchannel;
	struct hisi_sdma_channel_list *c;
	struct hisi_sdma_channel_list *n;
	u32 pid = (u32)current->tgid;

	spin_lock(&pdev->channel_lock);
	list_for_each_entry_safe(c, n, &data->non_share_chn_list, chn_list) {
		dev_dbg(dev, "release non_share_chn%d\n", c->chn_idx);
		bitmap_set(pdev->channel_map, c->chn_idx - share_chns, 1);
		list_del(&c->chn_list);
		pdev->nr_channel_used--;
	}

	list_for_each_entry_safe(c, n, &data->share_chn_list, chn_list) {
		dev_dbg(dev, "release share_chn%d\n", c->chn_idx);
		pchannel = pdev->channels  c->chn_idx;
		pchannel->cnt_used--;
		if (pchannel->sync_info_base->lock != 0 &&
			pchannel->sync_info_base->lock_pid == (u32)current->tgid) {
			dev_err(dev, "process %d exit with lock\n", current->tgid);
			pchannel->sync_info_base->lock = 0;
			pchannel->sync_info_base->lock_pid = 0;
		}
		list_del(&c->chn_list);
	}
	spin_unlock(&pdev->channel_lock);

	if (data->handle) {
		iommu_sva_unbind_device(data->handle);
		data->handle = NULL;
	}

	ida_free(g_info.fd_ida, data->ida);

	kfree(file->private_data);
	return 0;
}

static int remap_addr_range(u32 chn_num, u64 offset)
{
	if (offset >= chn_num * (HISI_SDMA_MMAP_SHMEM + 1))
		return -EINVAL;

	if (offset < chn_num * HISI_SDMA_MMAP_CQE)
		return HISI_SDMA_MMAP_SQE;

	else if (offset < chn_num * HISI_SDMA_MMAP_IO)
		return HISI_SDMA_MMAP_CQE;
	else if (offset < chn_num * HISI_SDMA_MMAP_SHMEM)
		return HISI_SDMA_MMAP_IO;
	else
		return HISI_SDMA_MMAP_SHMEM;
}

static int sdma_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_channel *chn_base, *pchan;
	u64 io_base, size, offset, pfn_start;
	struct device *dev;
	u32 chn_num;
	int ret;

	chn_base = data->psdma_dev->channels;
	dev = &data->psdma_dev->pdev->dev;
	chn_num = chn_base->pdev->nr_channel;
	io_base = data->psdma_dev->base_addr;
	size = vma->vm_end - vma->vm_start;
	offset = vma->vm_pgoff;

	dev_dbg(dev, "sdma total channel num = %u, user mmap offset = 0x%llx", chn_num, offset);

	switch (remap_addr_range(chn_num, offset)) {
	case HISI_SDMA_MMAP_SQE:
		pchan = chn_base + offset;
		pfn_start = virt_to_phys(pchan->sq_base) >> PAGE_SHIFT;
		ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size,
				      vma->vm_page_prot);
		break;

	case HISI_SDMA_MMAP_CQE:
		pchan = chn_base + offset - chn_num * HISI_SDMA_MMAP_CQE;
		pfn_start = virt_to_phys(pchan->cq_base) >> PAGE_SHIFT;
		ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size,
				      vma->vm_page_prot);
		break;

	case HISI_SDMA_MMAP_IO:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		pfn_start = (io_base + HISI_SDMA_CH_OFFSET) >> PAGE_SHIFT;
		pfn_start += (offset - chn_num * HISI_SDMA_MMAP_IO) * HISI_SDMA_REG_SIZE /
			      PAGE_SIZE;
		ret = io_remap_pfn_range(vma, vma->vm_start, pfn_start, size,
					 vma->vm_page_prot);
		break;

	case HISI_SDMA_MMAP_SHMEM:
		pchan = chn_base + offset - chn_num * HISI_SDMA_MMAP_SHMEM;
		pfn_start = virt_to_phys(pchan->sync_info_base) >> PAGE_SHIFT;
		ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size,
				      vma->vm_page_prot);
		break;

	default:
		return -EINVAL;
	}

	if (ret)
		dev_err(dev, "sdma mmap failed!\n");

	return ret;
}

static const struct file_operations sdma_core_fops = {
	.owner = THIS_MODULE,
	.open = sdma_core_open,
	.read = sdma_read_info,
	.release = sdma_dev_release,
	.unlocked_ioctl = sdma_dev_ioctl,
	.mmap = sdma_dev_mmap,
};

void sdma_cdev_init(struct cdev *cdev)
{
	cdev_init(cdev, &sdma_core_fops);
	cdev->owner = THIS_MODULE;
}

void sdma_info_sync_cdev(struct hisi_sdma_global_info *g_info_input)
{
	g_info.core_dev = g_info_input->core_dev;
	g_info.fd_ida = g_info_input->fd_ida;
	g_info.share_chns = g_info_input->share_chns;
}
