// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/list.h>
#include <linux/platform_device.h>
#include <linux/sort.h>

#include "sdma_hal.h"
#include "sdma_umem.h"
#include "sdma_auth.h"

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

struct hisi_sdma_numa_domain {
	int idx;
	int pxm;
};

struct pasid_info {
	u32 src_pasid;
	u32 dst_pasid;
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

static int ioctl_get_sdma_num(struct file *file, unsigned long arg)
{
	u32 num = g_info.core_dev->sdma_device_num;

	if (copy_to_user((int __user *)(uintptr_t)arg, &num, sizeof(int)))
		return -EFAULT;

	return 0;
}
static int ioctl_sdma_unpin_umem(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	u64 cookie;
	int ret;

	if (copy_from_user(&cookie, (u64 __user *)(uintptr_t)arg, sizeof(u64)))
		return -EFAULT;

	ret = sdma_umem_release(cookie);
	if (ret)
		dev_err(&data->psdma_dev->pdev->dev, "umem release fail!\n");

	return ret;
}

static int ioctl_sdma_pin_umem(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_umem_info umemInfo;
	int ret;

	if (copy_from_user(&umemInfo, (struct hisi_sdma_umem_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_umem_info)))
		return -EFAULT;

	ret = sdma_umem_get((u64)umemInfo.vma, umemInfo.size, data->ida, &umemInfo.cookie);
	if (ret < 0)
		return ret;

	if (copy_to_user((struct hisi_sdma_umem_info __user *)(uintptr_t)arg, &umemInfo,
			 sizeof(struct hisi_sdma_umem_info))) {
		sdma_umem_release(umemInfo.cookie);
		return -EFAULT;
	}

	return 0;
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
		pdev->nr_channel_used++;
	} else {
		ret = -ENOSPC;
		goto unlock;
	}

	idx += share_chns;
	list_node->chn_idx = (int)idx;
	list_add(&list_node->chn_list, &data->non_share_chn_list);
	pchannel = pdev->channels + idx;
	pchannel->cnt_used++;
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
			kfree(c);
			break;
		}
	}

	spin_unlock(&pdev->channel_lock);

	return 0;
}

static int cmp(const void *a, const void *b)
{
	const struct hisi_sdma_numa_domain *x = a, *y = b;

	if (x->pxm > y->pxm)
		return -1;
	if (x->pxm < y->pxm)
		return 1;
	return 0;
}

static int ioctl_get_near_sdmaid(struct file *file, unsigned long arg)
{
	u32 num = g_info.core_dev->sdma_device_num;
	struct hisi_sdma_numa_domain *sdma_numa;
	struct hisi_sdma_device *sdma_dev;
	struct device *dev;
	int sdma_id = -1;
	int nid;
	u32 i;

	nid = numa_node_id();
	if (nid < 0) {
		pr_err("numa_node not reported!\n");
		return 0;
	}

	sdma_numa = kcalloc(num, sizeof(struct hisi_sdma_numa_domain), GFP_KERNEL);
	if (!sdma_numa)
		return -ENOMEM;

	for (i = 0; i < num; i++) {
		sdma_dev = g_info.core_dev->sdma_devices[i];
		dev = &sdma_dev->pdev->dev;
		sdma_numa[i].idx = sdma_dev->idx;
		sdma_numa[i].pxm = sdma_dev->node_idx;
		if (sdma_numa[i].pxm < 0) {
			dev_err(dev, "sdma%d PXM domain not reported!\n", sdma_numa[i].idx);
			goto ret_idx;
		}
		dev_dbg(dev, "sdma%d PXM = %d\n", sdma_numa[i].idx, sdma_numa[i].pxm);
	}

	sort(sdma_numa, num, sizeof(struct hisi_sdma_numa_domain), cmp, NULL);

	for (i = 0; i < num; i++) {
		if (nid >= sdma_numa[i].pxm) {
			sdma_id = sdma_numa[i].idx;
			goto ret_idx;
		}
	}
	pr_err("Nearest sdma not found! process nid = %d\n", nid);

ret_idx:
	kfree(sdma_numa);
	if (copy_to_user((int __user *)(uintptr_t)arg, &sdma_id, sizeof(int)))
		return -EFAULT;

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

static int ioctl_sdma_mpamcfg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct hisi_sdma_mpamcfg cfg;

	if (copy_from_user(&cfg,
			   (struct hisi_sdma_mpamcfg __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_mpamcfg)))
		return -EFAULT;

	sdma_common_mpamid_cfg(pdev->common_base, &cfg);

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
	pchannel = pdev->channels + share_chn.chn_idx;
	if (share_chn.init_flag) {
		list_node = kmalloc_node(sizeof(struct hisi_sdma_channel_list), GFP_KERNEL,
					 pdev->node_idx);
		if (!list_node) {
			spin_unlock(&pdev->channel_lock);
			return -ENOMEM;
		}
		list_node->chn_idx = share_chn.chn_idx;
		list_add(&list_node->chn_list, &data->share_chn_list);
		pchannel->cnt_used++;
	}
	if (!share_chn.init_flag && pchannel->cnt_used > 0) {
		list_for_each_entry_safe(c, n, &data->share_chn_list, chn_list) {
			if (c->chn_idx == share_chn.chn_idx) {
				dev_dbg(dev, "release share_chn%d\n", c->chn_idx);
				list_del(&c->chn_list);
				kfree(c);
				break;
			}
		}
		pchannel->cnt_used--;
	}
	spin_unlock(&pdev->channel_lock);

	return 0;
}

static int ioctl_sdma_add_authority_ht(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct hisi_sdma_pid_info pid_info;
	u32 *pid_list = NULL;
	int list_num;
	int ret;

	if (copy_from_user(&pid_info, (struct hisi_sdma_pid_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_pid_info))) {
		dev_err(&pdev->pdev->dev, "get hisi_sdma_pid_info failed\n");
		return -EFAULT;
	}
	list_num = pid_info.num;
	pid_list = kmalloc_node(list_num * sizeof(int), GFP_KERNEL, pdev->node_idx);
	if (!pid_list)
		return -ENOMEM;

	if (copy_from_user(pid_list, (void __user *)pid_info.pid_list_addr,
			   list_num * sizeof(u32))) {
		dev_err(&pdev->pdev->dev, "get pid_list failed\n");
		ret = -EFAULT;
		goto free_list;
	}
	ret = sdma_auth_add(data->pasid, list_num, pid_list);

free_list:
	kfree(pid_list);
	return ret;
}

static int sdma_verify_src_dst(struct file_open_data *data, struct pasid_info *pasid,
			       struct hisi_sdma_sqe_task task_list)
{
	struct device *dev = &data->psdma_dev->pdev->dev;
	u32 pid = (u32)current->tgid;
	int ret = -1;

	if (task_list.opcode == HISI_SDMA_HBM_CACHE_PRELOAD_MODE) {
		pasid->src_pasid = data->pasid;
		pasid->dst_pasid = 0;
		dev_dbg(dev, "unter hbm cach preload mode\n");
		return 0;
	}

	if (pid == task_list.src_process_id) {
		pasid->src_pasid = data->pasid;
		ret = sdma_check_authority(pasid->src_pasid, task_list.dst_process_id,
					   current->tgid, &pasid->dst_pasid);
	} else if (pid == task_list.dst_process_id) {
		pasid->dst_pasid = data->pasid;
		ret = sdma_check_authority(pasid->dst_pasid, task_list.src_process_id,
					   current->tgid, &pasid->src_pasid);
	}

	if (ret < 0)
		dev_err(dev, "no authority:tgid[%u] src_pid[%u] dst_pid[%u]\n",
			pid, task_list.src_process_id, task_list.dst_process_id);

	return ret;
}

static void sdma_fill_sqe(struct hisi_sdma_sq_entry *sq_entry, struct hisi_sdma_sqe_task *task,
			  struct pasid_info pasid, u32 sq_tail, u32 streamid)
{
	sq_entry->opcode          = task->opcode;
	sq_entry->src_streamid    = streamid;
	sq_entry->dst_streamid    = streamid;
	sq_entry->src_addr_l      = (u32)(task->src_addr & 0xffffffff);
	sq_entry->src_addr_h      = (u32)(task->src_addr >> 32);
	sq_entry->dst_addr_l      = (u32)(task->dst_addr & 0xffffffff);
	sq_entry->dst_addr_h      = (u32)(task->dst_addr >> 32);
	sq_entry->length_move     = task->length;
	sq_entry->sns             = 1;
	sq_entry->dns             = 1;
	sq_entry->comp_en         = 1;
	sq_entry->mpamns          = 1;
	sq_entry->sssv            = 1;
	sq_entry->dssv            = 1;
	sq_entry->src_substreamid = pasid.src_pasid;
	sq_entry->dst_substreamid = pasid.dst_pasid;
	sq_entry->sqe_id          = sq_tail;
	sq_entry->src_stride_len  = task->src_stride_len;
	sq_entry->dst_stride_len  = task->dst_stride_len;
	sq_entry->stride_num      = task->stride_num;
	sq_entry->stride          = task->stride_num ? 1 : 0;
	sq_entry->mpam_partid     = task->mpam_partid;
	sq_entry->pmg             = task->pmg;
	sq_entry->qos             = task->qos;
}

static int sdma_send_task_kernel(struct file_open_data *data, struct hisi_sdma_task_info *task_info,
				 struct hisi_sdma_sqe_task *task_list)
{
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct hisi_sdma_channel *pchannel;
	struct hisi_sdma_sq_entry *sqe;
	struct pasid_info pasid;
	u32 sq_tail;
	int ret;
	u32 i;

	pchannel = pdev->channels + task_info->chn;
	sq_tail = pchannel->sync_info_base->sq_tail;
	for (i = 0; i < task_info->task_cnt; i++) {
		if (task_info->req_cnt != 0) {
			if (task_list[i].length == 0) {
				task_info->req_cnt--;
				continue;
			}
		}
		ret = sdma_verify_src_dst(data, &pasid, task_list[i]);
		if (ret < 0) {
			dev_err(&pdev->pdev->dev, "no correct pid\n");
			return ret;
		}
		sqe = pchannel->sq_base + sq_tail;
		sdma_fill_sqe(sqe, &task_list[i], pasid, sq_tail, pdev->streamid);
		sq_tail = (sq_tail + 1) & (HISI_SDMA_SQ_LENGTH - 1);
	}
	sdma_channel_set_sq_tail(pchannel, sq_tail);
	pchannel->sync_info_base->sq_tail = sq_tail;

	return 0;
}

static int ioctl_sdma_send_task(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_task_info task_info;
	struct hisi_sdma_sqe_task *task_list;
	int ret;

	if (copy_from_user(&task_info, (struct hisi_sdma_task_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_task_info))) {
		dev_err(&data->psdma_dev->pdev->dev, "get hisi_sdma_task_info failed\n");
		return -EFAULT;
	}
	task_list = kcalloc_node(task_info.task_cnt, sizeof(struct hisi_sdma_sqe_task), GFP_KERNEL,
				 data->psdma_dev->node_idx);
	if (!task_list)
		return -ENOMEM;

	if (copy_from_user(task_list, (void __user *)task_info.task_addr,
			   task_info.task_cnt * sizeof(struct hisi_sdma_sqe_task))) {
		dev_err(&data->psdma_dev->pdev->dev, "get hisi_sdma_sqe_task failed\n");
		ret = -EFAULT;
		goto free_list;
	}
	ret = sdma_send_task_kernel(data, &task_info, task_list);
	if (ret < 0)
		dev_err(&data->psdma_dev->pdev->dev, "exec sdma_send_task_kernel failed\n");

	if (copy_to_user((struct hisi_sdma_task_info __user *)(uintptr_t)arg, &task_info,
			 sizeof(struct hisi_sdma_task_info))) {
		dev_err(&data->psdma_dev->pdev->dev, "set hisi_sdma_task_info failed\n");
		ret = -EFAULT;
	}

free_list:
	kfree(task_list);
	return ret;
}

static int sdma_operation_reg(struct hisi_sdma_device *pdev, unsigned long arg,
			      u32 (*get_func)(struct hisi_sdma_channel *),
			      void (*set_func)(struct hisi_sdma_channel *, u32))
{
	struct device *dev = &pdev->pdev->dev;
	struct hisi_sdma_reg_info reg_info;
	struct hisi_sdma_channel *pchannel;

	if (copy_from_user(&reg_info, (struct hisi_sdma_reg_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_reg_info))) {
		dev_err(dev, "get hisi_sdma_reg_info failed\n");
		return -EFAULT;
	}

	pchannel = pdev->channels + reg_info.chn;
	if (reg_info.type == HISI_SDMA_READ_REG) {
		reg_info.reg_value = get_func(pchannel);
		if (copy_to_user((struct hisi_sdma_reg_info __user *)(uintptr_t)arg, &reg_info,
				 sizeof(struct hisi_sdma_reg_info)))
			return -EFAULT;
	} else if (reg_info.type == HISI_SDMA_WRITE_REG) {
		if (!set_func)
			dev_err(dev, "write operation not supported\n");
		else
			set_func(pchannel, reg_info.reg_value);
	}

	return 0;
}

static int ioctl_sdma_sq_head_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;

	return sdma_operation_reg(pdev, arg, sdma_channel_get_sq_head, NULL);
}

static int ioctl_sdma_sq_tail_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;

	return sdma_operation_reg(pdev, arg, sdma_channel_get_sq_tail, sdma_channel_set_sq_tail);
}

static int ioctl_sdma_cq_head_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;

	return sdma_operation_reg(pdev, arg, sdma_channel_get_cq_head, sdma_channel_set_cq_head);
}

static int ioctl_sdma_cq_tail_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;

	return sdma_operation_reg(pdev, arg, sdma_channel_get_cq_tail, NULL);
}

static int ioctl_sdma_dfx_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct hisi_sdma_reg_info reg_info;
	struct hisi_sdma_channel *pchannel;
	struct device *dev;

	dev = &pdev->pdev->dev;
	if (copy_from_user(&reg_info, (struct hisi_sdma_reg_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_reg_info))) {
		dev_err(dev, "get hisi_sdma_dfx_reg failed\n");
		return -EFAULT;
	}

	pchannel = pdev->channels + reg_info.chn;
	reg_info.reg_value = sdma_channel_get_dfx(pchannel);
	if (copy_to_user((struct hisi_sdma_reg_info __user *)(uintptr_t)arg, &reg_info,
			 sizeof(struct hisi_sdma_reg_info)))
		return -EFAULT;

	return 0;
}

static int ioctl_sdma_sqe_cnt_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct hisi_sdma_reg_info reg_info;
	struct hisi_sdma_channel *pchannel;
	struct device *dev;

	dev = &pdev->pdev->dev;
	if (copy_from_user(&reg_info, (struct hisi_sdma_reg_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_reg_info))) {
		dev_err(dev, "get hisi_sdma_reg_info failed\n");
		return -EFAULT;
	}

	pchannel = pdev->channels + reg_info.chn;
	if (reg_info.type == HISI_SDMA_CLR_NORMAL_SQE_CNT)
		sdma_channel_clr_normal_sqe_cnt(pchannel);
	else if (reg_info.type == HISI_SDMA_CLR_ERR_SQE_CNT)
		sdma_channel_clr_err_sqe_cnt(pchannel);

	return 0;
}

struct hisi_sdma_ioctl_func_list g_ioctl_funcs[] = {
	{IOCTL_SDMA_GET_PROCESS_ID,		ioctl_sdma_get_process_id},
	{IOCTL_SDMA_GET_CHN,			ioctl_sdma_get_chn},
	{IOCTL_SDMA_PUT_CHN,			ioctl_sdma_put_chn},
	{IOCTL_SDMA_GET_STREAMID,		ioctl_sdma_get_streamid},
	{IOCTL_SDMA_PIN_UMEM,			ioctl_sdma_pin_umem},
	{IOCTL_SDMA_UNPIN_UMEM,			ioctl_sdma_unpin_umem},
	{IOCTL_GET_SDMA_NUM,			ioctl_get_sdma_num},
	{IOCTL_GET_NEAR_SDMAID,			ioctl_get_near_sdmaid},
	{IOCTL_GET_SDMA_CHN_NUM,		ioctl_get_sdma_chn_num},
	{IOCTL_SDMA_MPAMID_CFG,			ioctl_sdma_mpamcfg},
	{IOCTL_SDMA_CHN_USED_REFCOUNT,		ioctl_sdma_chn_used_refcount},
	{IOCTL_SDMA_ADD_AUTH_HT,		ioctl_sdma_add_authority_ht},
	{IOCTL_SDMA_SEND_TASK,			ioctl_sdma_send_task},
	{IOCTL_SDMA_SQ_HEAD_REG,		ioctl_sdma_sq_head_reg},
	{IOCTL_SDMA_SQ_TAIL_REG,		ioctl_sdma_sq_tail_reg},
	{IOCTL_SDMA_CQ_HEAD_REG,		ioctl_sdma_cq_head_reg},
	{IOCTL_SDMA_CQ_TAIL_REG,		ioctl_sdma_cq_tail_reg},
	{IOCTL_SDMA_DFX_REG,			ioctl_sdma_dfx_reg},
	{IOCTL_SDMA_SQE_CNT_REG,		ioctl_sdma_sqe_cnt_reg},
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
		kfree(c);
		pdev->nr_channel_used--;
	}

	list_for_each_entry_safe(c, n, &data->share_chn_list, chn_list) {
		dev_dbg(dev, "release share_chn%d\n", c->chn_idx);
		pchannel = pdev->channels + c->chn_idx;
		pchannel->cnt_used--;
		if (pchannel->sync_info_base->lock != 0 &&
			pchannel->sync_info_base->lock_pid == (u32)current->tgid) {
			dev_err(dev, "process %d exit with lock\n", current->tgid);
			pchannel->sync_info_base->lock = 0;
			pchannel->sync_info_base->lock_pid = 0;
		}
		list_del(&c->chn_list);
		kfree(c);
	}
	spin_unlock(&pdev->channel_lock);

	if (data->handle) {
		iommu_sva_unbind_device(data->handle);
		data->handle = NULL;
	}

	sdma_hash_free_entry(data->ida);
	sdma_free_authority_ht_with_pid(pid);
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
