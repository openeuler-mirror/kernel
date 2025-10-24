// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/list.h>
#include <linux/platform_device.h>
#include <linux/sort.h>
#include <linux/mm.h>
#include <linux/refcount.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>

#include "sdma_hal.h"
#include "sdma_umem.h"
#include "sdma_auth.h"

#define mn_to_sdma(mn)	container_of(mn, struct hisi_sdma_mn, mn)

DEFINE_MUTEX(sdma_pid_lock);

static struct hisi_sdma_global_info g_info;

struct hisi_sdma_channel_list {
	struct list_head chn_list;
	u32 chn_idx;
};

struct file_open_data {
	int ida;
	u32 pasid;
	struct iommu_sva *handle;
	struct hisi_sdma_device *psdma_dev;
	struct list_head non_share_chn_list;
	struct list_head share_chn_list;
	struct mm_struct *cur_file_mm;
};

struct hisi_sdma_mn {
	refcount_t refs;
	struct mmu_notifier mn;
	struct file_open_data *data;
	struct list_head list;
};

struct hisi_sdma_numa_domain {
	int idx;
	int pxm;
};

struct pasid_info {
	u32 src_pasid;
	u32 dst_pasid;
};

static struct hisi_sdma_pid_ref_hte *sdma_search_pid_ref(u32 pid)
{
	struct hisi_sdma_pid_ref_hte *entry = NULL;

	hash_for_each_possible(g_info.sdma_pid_ref_ht, entry, node, pid) {
		if (entry->pid == pid)
			return entry;
	}

	return NULL;
}

static int sdma_add_pid_ref(u32 pid, u16 node_idx)
{
	struct hisi_sdma_pid_ref_hte *entry = NULL;

	mutex_lock(&sdma_pid_lock);
	entry = sdma_search_pid_ref(pid);
	if (!entry) {
		entry = kmalloc_node(sizeof(struct hisi_sdma_pid_ref_hte), GFP_ATOMIC, node_idx);
		if (!entry) {
			mutex_unlock(&sdma_pid_lock);
			return -ENOMEM;
		}
		entry->pid = pid;
		entry->ref = 1;
		hash_add(g_info.sdma_pid_ref_ht, &entry->node, entry->pid);
	} else
		entry->ref++;

	mutex_unlock(&sdma_pid_lock);

	return 0;
}

static void sdma_del_pid_ref(u32 pid)
{
	struct hisi_sdma_pid_ref_hte *entry = NULL;

	mutex_lock(&sdma_pid_lock);
	entry = sdma_search_pid_ref(pid);
	if (entry) {
		entry->ref--;
		if (entry->ref == 0) {
			hash_del(&entry->node);
			kfree(entry);
			sdma_free_authority_ht_with_pid(pid);
		}
	}
	mutex_unlock(&sdma_pid_lock);
}

void sdma_clear_pid_ref(void)
{
	struct hisi_sdma_pid_ref_hte *entry = NULL;
	struct hlist_node *tmp;
	u32 bkt;

	mutex_lock(&sdma_pid_lock);
	hash_for_each_safe(g_info.sdma_pid_ref_ht, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
	mutex_unlock(&sdma_pid_lock);
}

static struct hisi_sdma_channel_node *sdma_search_ida_ref(struct hisi_sdma_channel *pchannel,
							  int ida)
{
	struct hisi_sdma_channel_node *entry;

	hash_for_each_possible(pchannel->sdma_ida_ht, entry, node, ida) {
		if (entry->ida == ida)
			return entry;
	}

	return NULL;
}

static int sdma_add_ida_ref(struct hisi_sdma_channel *pchannel, int ida)
{
	struct hisi_sdma_channel_node *entry;

	spin_lock(&pchannel->owner_chn_lock);
	entry = sdma_search_ida_ref(pchannel, ida);
	if (entry == NULL) {
		entry = kzalloc(sizeof(struct hisi_sdma_channel_node), GFP_ATOMIC);
		if (entry == NULL) {
			spin_unlock(&pchannel->owner_chn_lock);
			return -ENOMEM;
		}
		entry->ida = ida;
		entry->ref = 1;
		hash_add(pchannel->sdma_ida_ht, &entry->node, entry->ida);
	} else
		entry->ref++;
	spin_unlock(&pchannel->owner_chn_lock);

	return 0;
}

static bool sdma_del_ida_ref(struct hisi_sdma_channel *pchannel, int ida)
{
	struct hisi_sdma_channel_node *entry;

	spin_lock(&pchannel->owner_chn_lock);
	entry = sdma_search_ida_ref(pchannel, ida);
	if (entry != NULL) {
		entry->ref--;
		if (entry->ref == 0) {
			hash_del(&entry->node);
			kfree(entry);
		}
	} else {
		spin_unlock(&pchannel->owner_chn_lock);
		return false;
	}
	spin_unlock(&pchannel->owner_chn_lock);

	return true;
}

static void sdma_add_ida_val(struct hisi_sdma_channel *pchannel, int ida)
{
	spin_lock(&pchannel->owner_chn_lock);
	pchannel->ida = ida;
	spin_unlock(&pchannel->owner_chn_lock);
}

static void sdma_reset_ida_val(struct hisi_sdma_channel *pchannel)
{
	spin_lock(&pchannel->owner_chn_lock);
	pchannel->ida = -1;
	spin_unlock(&pchannel->owner_chn_lock);
}

static bool sdma_check_ida_val(struct hisi_sdma_channel *pchannel, int ida)
{
	spin_lock(&pchannel->owner_chn_lock);
	if (pchannel->ida != ida) {
		spin_unlock(&pchannel->owner_chn_lock);
		return false;
	}
	spin_unlock(&pchannel->owner_chn_lock);

	return true;
}

void sdma_clear_ida_ref(struct hisi_sdma_channel *pchannel)
{
	struct hisi_sdma_channel_node *entry;
	struct hlist_node *tmp;
	u32 bkt;

	if (pchannel == NULL || pchannel->sdma_ida_ht == NULL)
		return;

	spin_lock(&pchannel->owner_chn_lock);
	hash_for_each_safe(pchannel->sdma_ida_ht, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
	spin_unlock(&pchannel->owner_chn_lock);
}

static int sdma_wait_cq_writeback(struct hisi_sdma_channel *pchannel)
{
	u32 cq_tail;
	u32 cnt = 0;

	while (!sdma_channel_is_quiescent(pchannel) && cnt++ < SDMA_POLL_TIMEOUT) {
		cq_tail = sdma_channel_get_cq_tail(pchannel);
		sdma_channel_set_cq_head(pchannel, cq_tail);
		pchannel->sync_info_base->cq_head = (u16)cq_tail;
		pchannel->sync_info_base->cq_tail = (u16)cq_tail;
		pchannel->sync_info_base->sq_head = (u16)cq_tail;
		msleep(SDMA_POLL_DELAY);
	}

	if (cnt > SDMA_POLL_TIMEOUT)
		return -ETIMEDOUT;

	return 0;
}

static void sdma_pause_single_channel(struct hisi_sdma_channel *pchannel,
				      struct hisi_sdma_device *psdma_dev)
{
	int ret;

	sdma_channel_set_pause(pchannel);

	ret = sdma_wait_cq_writeback(pchannel);
	if (ret < 0)
		pr_warn("Task unfinished for sdma %u channel %u, please wait.\n",
			psdma_dev->idx, pchannel->idx);
}

static void sdma_pause_channels(struct hisi_sdma_device *psdma_dev)
{
	struct hisi_sdma_channel *pchannel;
	int i;

	pr_warn("Process exit abnormally. Pause sdma%u proactively.\n", psdma_dev->idx);
	for (i = 0; i < HISI_SDMA_DEFAULT_CHANNEL_NUM; i++) {
		pchannel = psdma_dev->channels + i;
		sdma_pause_single_channel(pchannel, psdma_dev);
	}
}

static void sdma_mmu_release_pause(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct hisi_sdma_device *psdma_dev;
	struct hisi_sdma_mn *sdma_mn;
	struct file_open_data *data;
	u64 start_jiffies;
	int ref_cnt;

	sdma_mn = mn_to_sdma(mn);
	data = sdma_mn->data;
	if (!data)
		return;

	psdma_dev = data->psdma_dev;
	ref_cnt = refcount_read(&sdma_mn->refs);
	atomic_sub(ref_cnt, &psdma_dev->sdma_dev_ref_cnt);

	if (atomic_inc_return(&psdma_dev->dev_exit_ref_cnt) == 1) {
		sdma_pause_channels(psdma_dev);
		atomic_set(&psdma_dev->dev_exit_flag, 1);
	} else {
		start_jiffies = get_jiffies_64();
		while (atomic_read(&psdma_dev->dev_exit_flag) != 1) {
			if (time_is_before_jiffies64((u64)(start_jiffies + HZ)))
				break;
			cond_resched();
		}
	}
}

static void sdma_resume_device(struct hisi_sdma_device *psdma_dev)
{
	struct hisi_sdma_channel *pchannel;
	int i;

	pr_warn("Resume sdma%u now.\n", psdma_dev->idx);
	for (i = 0; i < HISI_SDMA_DEFAULT_CHANNEL_NUM; i++) {
		pchannel = psdma_dev->channels + i;
		if (sdma_channel_is_paused(pchannel) && sdma_channel_is_quiescent(pchannel))
			sdma_channel_write_resume(pchannel);
	}
}

static void sdma_mmu_release_resume(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct hisi_sdma_device *psdma_dev;
	struct hisi_sdma_mn *sdma_mn;
	struct file_open_data *data;
	int ref_cnt;

	sdma_mn = mn_to_sdma(mn);
	data = sdma_mn->data;
	if (!data)
		return;

	psdma_dev = data->psdma_dev;
	ref_cnt = refcount_read(&sdma_mn->refs);
	if (atomic_sub_return(ref_cnt, &psdma_dev->sdma_dev_ref_cnt) == 0) {
		sdma_resume_device(psdma_dev);
		atomic_set(&psdma_dev->dev_exit_ref_cnt, 0);
		atomic_set(&psdma_dev->dev_exit_flag, 0);
	}
}

static void sdma_mmu_notifier_free(struct mmu_notifier *mn)
{
	kfree(mn_to_sdma(mn));
}

static const struct mmu_notifier_ops sdma_pause_mmu_notifier_ops = {
	.release	= sdma_mmu_release_pause,
	.free_notifier	= sdma_mmu_notifier_free,
};

static const struct mmu_notifier_ops sdma_resume_mmu_notifier_ops = {
	.release	= sdma_mmu_release_resume,
	.free_notifier	= sdma_mmu_notifier_free,
};

static struct hisi_sdma_mn *search_resume_mmu_notifier(struct mm_struct *mm,
						       struct hisi_sdma_device *psdma_dev)
{
	struct hisi_sdma_mn *sdma_mn;

	list_for_each_entry(sdma_mn, &psdma_dev->sdma_resume_mm_list, list) {
		if (sdma_mn->mn.mm == mm) {
			refcount_inc(&sdma_mn->refs);
			return sdma_mn;
		}
	}

	return NULL;
}

static struct hisi_sdma_mn *search_pause_mmu_notifier(struct mm_struct *mm,
						      struct hisi_sdma_device *psdma_dev)
{
	struct hisi_sdma_mn *sdma_mn;

	list_for_each_entry(sdma_mn, &psdma_dev->sdma_pause_mm_list, list) {
		if (sdma_mn->mn.mm == mm) {
			refcount_inc(&sdma_mn->refs);
			return sdma_mn;
		}
	}

	return NULL;
}

static int sdma_pause_mmu_handler(struct file_open_data *data)
{
	struct hisi_sdma_device *psdma_dev = data->psdma_dev;
	struct hisi_sdma_mn *sdma_mn;
	int ret = 0;

	atomic_inc(&psdma_dev->sdma_dev_ref_cnt);

	mutex_lock(&psdma_dev->mutex_lock);
	sdma_mn = search_pause_mmu_notifier(data->cur_file_mm, psdma_dev);
	if (sdma_mn) {
		mutex_unlock(&psdma_dev->mutex_lock);
		return ret;
	}

	sdma_mn = kzalloc(sizeof(*sdma_mn), GFP_KERNEL);
	if (!sdma_mn) {
		ret = -ENOMEM;
		goto pause_unlock;
	}

	refcount_set(&sdma_mn->refs, 1);
	sdma_mn->data = data;
	sdma_mn->mn.ops = &sdma_pause_mmu_notifier_ops;
	ret = mmu_notifier_register(&sdma_mn->mn, data->cur_file_mm);
	if (ret)
		goto pause_free;

	list_add(&sdma_mn->list, &psdma_dev->sdma_pause_mm_list);
	mutex_unlock(&psdma_dev->mutex_lock);

	return ret;

pause_free:
	kfree(sdma_mn);
pause_unlock:
	mutex_unlock(&psdma_dev->mutex_lock);
	atomic_dec(&psdma_dev->sdma_dev_ref_cnt);

	return ret;
}

static int sdma_resume_mmu_handler(struct file_open_data *data)
{
	struct hisi_sdma_device *psdma_dev = data->psdma_dev;
	struct hisi_sdma_mn *sdma_mn;
	int ret = 0;

	atomic_inc(&psdma_dev->sdma_dev_ref_cnt);

	mutex_lock(&psdma_dev->mutex_lock);
	sdma_mn = search_resume_mmu_notifier(data->cur_file_mm, psdma_dev);
	if (sdma_mn) {
		mutex_unlock(&psdma_dev->mutex_lock);
		return ret;
	}

	sdma_mn = kzalloc(sizeof(*sdma_mn), GFP_KERNEL);
	if (!sdma_mn) {
		ret = -ENOMEM;
		goto resume_unlock;
	}

	refcount_set(&sdma_mn->refs, 1);
	sdma_mn->data = data;
	sdma_mn->mn.ops = &sdma_resume_mmu_notifier_ops;
	ret = mmu_notifier_register(&sdma_mn->mn, data->cur_file_mm);
	if (ret)
		goto resume_free;

	list_add(&sdma_mn->list, &psdma_dev->sdma_resume_mm_list);
	mutex_unlock(&psdma_dev->mutex_lock);

	return ret;

resume_free:
	kfree(sdma_mn);
resume_unlock:
	mutex_unlock(&psdma_dev->mutex_lock);
	atomic_dec(&psdma_dev->sdma_dev_ref_cnt);

	return ret;
}

static void sdma_put_mmu_notifier(struct hisi_sdma_mn *sdma_mn)
{
	if (!refcount_dec_and_test(&sdma_mn->refs))
		return;

	list_del(&sdma_mn->list);
	mmu_notifier_put(&sdma_mn->mn);
}

static void sdma_put_resume_mmu_notifier(struct hisi_sdma_device *psdma_dev)
{
	struct mm_struct *mm = current->mm;
	struct hisi_sdma_mn *sdma_mn;

	atomic_dec(&psdma_dev->sdma_dev_ref_cnt);

	mutex_lock(&psdma_dev->mutex_lock);
	list_for_each_entry(sdma_mn, &psdma_dev->sdma_resume_mm_list, list) {
		if (sdma_mn->mn.mm == mm) {
			sdma_put_mmu_notifier(sdma_mn);
			break;
		}
	}
	mutex_unlock(&psdma_dev->mutex_lock);
}

static void sdma_put_pause_mmu_notifier(struct hisi_sdma_device *psdma_dev)
{
	struct mm_struct *mm = current->mm;
	struct hisi_sdma_mn *sdma_mn;

	atomic_dec(&psdma_dev->sdma_dev_ref_cnt);

	mutex_lock(&psdma_dev->mutex_lock);
	list_for_each_entry(sdma_mn, &psdma_dev->sdma_pause_mm_list, list) {
		if (sdma_mn->mn.mm == mm) {
			sdma_put_mmu_notifier(sdma_mn);
			break;
		}
	}
	mutex_unlock(&psdma_dev->mutex_lock);
}

static int __do_sdma_open(struct hisi_sdma_device *psdma_dev, struct file *file)
{
	struct mm_struct *mm = current->mm;
	struct file_open_data *data;
	struct iommu_sva *handle;
	int id, ret;
	u32 pasid;

	id = ida_alloc(g_info.fd_ida, GFP_KERNEL);
	if (id < 0)
		return id;

	ret = sdma_add_pid_ref((u32)current->tgid, psdma_dev->node_idx);
	if (ret != 0) {
		dev_err(&psdma_dev->pdev->dev, "Alloc pid_ref hash failed\n");
		goto free_ida;
	}

	dev_dbg(&psdma_dev->pdev->dev, "Ida alloc id = %d\n", id);
	data = kmalloc_node(sizeof(struct file_open_data), GFP_KERNEL, psdma_dev->node_idx);
	if (!data) {
		ret = -ENOMEM;
		goto free_pid_ref_ht;
	}
	data->psdma_dev = psdma_dev;
	data->cur_file_mm = mm;

	ret = sdma_resume_mmu_handler(data);
	if (ret != 0)
		goto free_privt_data;

	handle = iommu_sva_bind_device(&psdma_dev->pdev->dev, mm, NULL);
	if (IS_ERR(handle)) {
		dev_err(&psdma_dev->pdev->dev, "Failed to bind sva, %ld\n", PTR_ERR(handle));
		ret = (int)PTR_ERR(handle);
		goto mmu_resume_unreg;
	}

	pasid = iommu_sva_get_pasid(handle);
	if (pasid == IOMMU_PASID_INVALID) {
		ret = -ENODEV;
		goto sva_unbind;
	}

	ret = sdma_pause_mmu_handler(data);
	if (ret != 0)
		goto sva_unbind;

	data->ida = id;
	data->pasid = pasid;
	data->handle = handle;
	INIT_LIST_HEAD(&data->non_share_chn_list);
	INIT_LIST_HEAD(&data->share_chn_list);

	file->private_data = data;

	return 0;

sva_unbind:
	iommu_sva_unbind_device(handle);
mmu_resume_unreg:
	sdma_put_resume_mmu_notifier(psdma_dev);
free_privt_data:
	kfree(data);
free_pid_ref_ht:
	sdma_del_pid_ref(current->tgid);
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
	int ida;

	if (copy_from_user(&cookie, (u64 __user *)(uintptr_t)arg, sizeof(u64)))
		return -EFAULT;

	ida = (int)(cookie >> COOKIE_IDA_SHIFT);
	if (ida != data->ida) {
		dev_err(&data->psdma_dev->pdev->dev, "Invalid process unpin umem!\n");
		return -EPERM;
	}

	ret = sdma_umem_release(cookie);
	if (ret)
		dev_err(&data->psdma_dev->pdev->dev, "Umem release fail!\n");

	return ret;
}

static int ioctl_sdma_pin_umem(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_umem_info umemInfo;
	int ret;

	if (copy_from_user(&umemInfo, (struct hisi_sdma_umem_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_umem_info))) {
		dev_err(&data->psdma_dev->pdev->dev, "Umem_info copy from user failed!\n");
		return -EFAULT;
	}

	ret = sdma_umem_get((u64)umemInfo.vma, umemInfo.size, data->ida, &umemInfo.cookie);
	if (ret < 0)
		return ret;

	if (copy_to_user((struct hisi_sdma_umem_info __user *)(uintptr_t)arg, &umemInfo,
			 sizeof(struct hisi_sdma_umem_info))) {
		sdma_umem_release(umemInfo.cookie);
		dev_err(&data->psdma_dev->pdev->dev, "Umem_info copy to user failed!\n");
		return -EFAULT;
	}

	return 0;
}

static int ioctl_sdma_get_process_id(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	u32 pid = (u32)current->tgid;
	u32 pasid = data->pasid;

	if (*(g_info.sdma_mode) == HISI_SDMA_FAST_MODE) {
		if (copy_to_user((u32 __user *)(uintptr_t)arg, &pasid, sizeof(u32)))
			return -EFAULT;
	} else {
		if (copy_to_user((u32 __user *)(uintptr_t)arg, &pid, sizeof(u32)))
			return -EFAULT;
	}

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

	list_node = kmalloc_node(sizeof(struct hisi_sdma_channel_list), GFP_KERNEL,
				 pdev->node_idx);
	if (!list_node)
		return -ENOMEM;

	alloc_chn_num_max = pdev->nr_channel - share_chns;
	spin_lock(&pdev->channel_lock);
	idx = find_first_bit(pdev->channel_map, alloc_chn_num_max);
	if (idx != alloc_chn_num_max) {
		bitmap_clear(pdev->channel_map, idx, 1);
		pdev->nr_channel_used++;
	} else {
		dev_err(&pdev->pdev->dev, "Fail to allocate usable exclusive chn!\n");
		ret = -ENOSPC;
		goto unlock;
	}

	idx += share_chns;
	list_node->chn_idx = idx;
	list_add(&list_node->chn_list, &data->non_share_chn_list);
	pchannel = pdev->channels + idx;
	pchannel->cnt_used++;
	sdma_add_ida_val(pchannel, data->ida);

	if (copy_to_user((u32 __user *)(uintptr_t)arg, &idx, sizeof(u32))) {
		ret = -EFAULT;
		goto put_chn;
	}
	spin_unlock(&pdev->channel_lock);
	dev_dbg(&pdev->pdev->dev, "SDMA get chn %u\n", idx);

	return 0;

put_chn:
	list_del(&list_node->chn_list);
	bitmap_set(pdev->channel_map, idx - share_chns, 1);
	pdev->nr_channel_used--;
	pchannel->cnt_used--;
	sdma_reset_ida_val(pchannel);
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
	struct hisi_sdma_channel *pchannel;
	u32 idx;

	if (copy_from_user(&idx, (u32 __user *)(uintptr_t)arg, sizeof(u32))) {
		dev_err(dev, "Put user chn failed\n");
		return -EFAULT;
	}

	if (idx < share_chns || idx >= pdev->nr_channel) {
		dev_err(dev, "Put idx = %u is err\n", idx);
		return -EFAULT;
	}

	pchannel = pdev->channels + idx;
	if (!sdma_check_ida_val(pchannel, data->ida)) {
		dev_err(dev, "Invalid process put chn by sdma exclusive channel%u\n", idx);
		return -EPERM;
	}

	spin_lock(&pdev->channel_lock);
	list_for_each_entry_safe(c, n, &data->non_share_chn_list, chn_list) {
		if (c->chn_idx == idx) {
			bitmap_set(pdev->channel_map, idx - share_chns, 1);
			pdev->nr_channel_used--;
			pchannel->cnt_used--;
			sdma_reset_ida_val(pchannel);
			dev_dbg(dev, "SDMA put chn %u\n", idx);
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

static int ioctl_get_near_sdmaid(struct file *file SDMA_UNUSED, unsigned long arg)
{
	struct hisi_sdma_numa_domain sdma_numa[HISI_SDMA_MAX_DEVS];
	u32 num = g_info.core_dev->sdma_device_num;
	struct hisi_sdma_device *sdma_dev;
	struct device *dev;
	int sdma_id = -1;
	int nid;
	u32 i;

	nid = numa_node_id();
	if (nid < 0) {
		pr_err("SDMA numa_node not reported!\n");
		return -EINVAL;
	}
	if (num <= 0 || num > HISI_SDMA_MAX_DEVS) {
		pr_err("Device num wrong, cannot use sdma!\n");
		return -ENOENT;
	}

	for (i = 0; i < num; i++) {
		sdma_dev = g_info.core_dev->sdma_devices[i];
		dev = &sdma_dev->pdev->dev;
		sdma_numa[i].idx = sdma_dev->idx;
		sdma_numa[i].pxm = sdma_dev->node_idx;
		if (sdma_numa[i].pxm < 0) {
			dev_err(dev, "SDMA%d PXM domain not reported!\n", sdma_numa[i].idx);
			return -ENODATA;
		}
		dev_dbg(dev, "SDMA%d PXM = %d\n", sdma_numa[i].idx, sdma_numa[i].pxm);
	}

	sort(sdma_numa, num, sizeof(struct hisi_sdma_numa_domain), cmp, NULL);
	for (i = 0; i < num; i++) {
		if (nid >= sdma_numa[i].pxm) {
			sdma_id = sdma_numa[i].idx;
			break;
		}
	}
	if (sdma_id < 0) {
		pr_err("Nearest sdma not found! process nid = %d, sdmaid = %d\n", nid, sdma_id);
		return -ENODATA;
	}
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

	if (copy_from_user(&cfg, (struct hisi_sdma_mpamcfg __user *)(uintptr_t)arg,
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
	int ida = data->ida;

	if (copy_from_user(&share_chn, (struct hisi_sdma_share_chn __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_share_chn))) {
		dev_err(dev, "Get share chn failed\n");
		return -EFAULT;
	}
	if (share_chn.chn_idx >= share_chns) {
		dev_err(dev, "Get share chn index = %u is err\n", share_chn.chn_idx);
		return -EFAULT;
	}

	spin_lock(&pdev->channel_lock);
	pchannel = pdev->channels + share_chn.chn_idx;
	if (share_chn.init_flag) {
		list_node = kmalloc_node(sizeof(struct hisi_sdma_channel_list), GFP_ATOMIC,
					 pdev->node_idx);
		if (!list_node) {
			spin_unlock(&pdev->channel_lock);
			return -ENOMEM;
		}

		if (sdma_add_ida_ref(pchannel, ida)) {
			kfree(list_node);
			dev_err(dev, "Alloc channel node error\n");
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
				if (!sdma_del_ida_ref(pchannel, ida)) {
					dev_err(dev, "Invalid process deinit share chn!\n");
					spin_unlock(&pdev->channel_lock);
					return -EPERM;
				}
				pchannel->cnt_used--;
				if (pchannel->cnt_used == 0) {
					pchannel->sync_info_base->err_cnt = 0;
					pchannel->sync_info_base->lock_pid = 0;
					/* clear lockpid before release lock */
					wmb();
					pchannel->sync_info_base->lock = 0;
				}
				dev_dbg(dev, "Release share_chn%u\n", c->chn_idx);
				list_del(&c->chn_list);
				kfree(c);
				break;
			}
		}
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
	u32 list_num;
	int ret;

	if (*(g_info.sdma_mode) == HISI_SDMA_FAST_MODE)
		return 0;

	if (copy_from_user(&pid_info, (struct hisi_sdma_pid_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_pid_info))) {
		dev_err(&pdev->pdev->dev, "Get hisi_sdma_pid_info failed\n");
		return -EFAULT;
	}
	list_num = pid_info.num;
	if (list_num > HISI_SDMA_MAX_ALLOC_SIZE / sizeof(u32) || list_num == 0) {
		dev_err(&pdev->pdev->dev, "Invalid pid_list num:%u\n", list_num);
		return -EINVAL;
	}
	pid_list = kmalloc_node(list_num * sizeof(u32), GFP_KERNEL, pdev->node_idx);
	if (!pid_list)
		return -ENOMEM;

	if (copy_from_user(pid_list, (void __user *)pid_info.pid_list_addr,
			   list_num * sizeof(u32))) {
		dev_err(&pdev->pdev->dev, "Get pid_list failed\n");
		ret = -EFAULT;
		goto free_list;
	}
	ret = sdma_auth_add(data->pasid, list_num, pid_list);

free_list:
	kfree(pid_list);

	return ret;
}

static int sdma_verify_src_dst(struct file_open_data *data, struct pasid_info *pasid,
			       struct hisi_sdma_sqe_task *task_list)
{
	struct device *dev = &data->psdma_dev->pdev->dev;
	u32 pid = (u32)current->tgid;
	int ret = -EPERM;

	if (task_list->opcode == HISI_SDMA_HBM_CACHE_PRELOAD_MODE) {
		pasid->src_pasid = data->pasid;
		pasid->dst_pasid = 0;
		dev_dbg(dev, "Under hbm cache preload mode\n");
		return 0;
	}

	if (pid == task_list->src_process_id) {
		pasid->src_pasid = data->pasid;
		ret = sdma_check_authority(pasid->src_pasid, task_list->dst_process_id,
					   current->tgid, &pasid->dst_pasid);
	} else if (pid == task_list->dst_process_id) {
		pasid->dst_pasid = data->pasid;
		ret = sdma_check_authority(pasid->dst_pasid, task_list->src_process_id,
					   current->tgid, &pasid->src_pasid);
	}

	if (ret < 0)
		dev_err(dev, "No authority:tgid[%u] src_pid[%u] dst_pid[%u]\n",
			pid, task_list->src_process_id, task_list->dst_process_id);

	return ret;
}

static void sdma_fill_sqe(struct hisi_sdma_sq_entry *sq_entry, struct hisi_sdma_sqe_task *task,
			  struct pasid_info *pasid, u32 sq_tail, u32 streamid)
{
	sq_entry->opcode          = task->opcode;
	sq_entry->src_streamid    = (u16)streamid;
	sq_entry->dst_streamid    = (u16)streamid;
	sq_entry->src_addr_l      = (u32)(task->src_addr & 0xffffffff);
	sq_entry->src_addr_h      = (u32)(task->src_addr >> HISI_SDMA_LOW_ADDR_SHIFT);
	sq_entry->dst_addr_l      = (u32)(task->dst_addr & 0xffffffff);
	sq_entry->dst_addr_h      = (u32)(task->dst_addr >> HISI_SDMA_LOW_ADDR_SHIFT);
	sq_entry->length_move     = task->length;
	sq_entry->sns             = 1;
	sq_entry->dns             = 1;
	sq_entry->comp_en         = 1;
	sq_entry->mpamns          = 1;
	sq_entry->sssv            = 1;
	sq_entry->dssv            = 1;
	sq_entry->src_substreamid = (u16)(pasid->src_pasid);
	sq_entry->dst_substreamid = (u16)(pasid->dst_pasid);
	sq_entry->sqe_id          = (u16)sq_tail;
	sq_entry->src_stride_len  = task->src_stride_len;
	sq_entry->dst_stride_len  = task->dst_stride_len;
	sq_entry->stride_num      = task->stride_num;
	sq_entry->stride          = task->stride_num ? 1 : 0;
	sq_entry->mpam_partid     = task->mpam_partid;
	sq_entry->pmg             = task->pmg;
	sq_entry->qos             = task->qos;
}

static int sdma_check_channel_permission(struct hisi_sdma_channel *pchannel, int ida, u32 chn)
{
	u32 share_chns = *(g_info.share_chns);
	struct hisi_sdma_channel_node *entry;

	if (chn < share_chns) {
		entry = sdma_search_ida_ref(pchannel, ida);
		if (entry == NULL)
			return -EPERM;
	} else if (chn < HISI_SDMA_DEFAULT_CHANNEL_NUM && pchannel->ida != ida) {
		return -EPERM;
	}

	return 0;
}

static int sdma_send_task_kernel(struct file_open_data *data,
				 struct hisi_sdma_task_info *task_info,
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
	spin_lock(&pchannel->owner_chn_lock);
	ret = sdma_check_channel_permission(pchannel, data->ida, task_info->chn);
	if (ret != 0) {
		dev_err(&pdev->pdev->dev, "Invalid process send task by channel %u\n",
			task_info->chn);
		spin_unlock(&pchannel->owner_chn_lock);
		return -EPERM;
	}
	sq_tail = sdma_channel_get_sq_tail(pchannel);
	if (sq_tail >= HISI_SDMA_SQ_LENGTH) {
		spin_unlock(&pchannel->owner_chn_lock);
		dev_err(&pdev->pdev->dev, "Sq_tail in share mem wrong, sq_tail = %u\n", sq_tail);
		return -EINVAL;
	}
	for (i = 0; i < task_info->task_cnt; i++) {
		if (task_info->req_cnt != 0) {
			/* not send/record tasks whose length == 0 */
			if (task_list[i].length == 0) {
				task_info->req_cnt--;
				continue;
			}
		}
		ret = sdma_verify_src_dst(data, &pasid, &task_list[i]);
		if (ret < 0) {
			spin_unlock(&pchannel->owner_chn_lock);
			dev_err(&pdev->pdev->dev, "No correct pid\n");
			return ret;
		}
		sqe = pchannel->sq_base + sq_tail;
		sdma_fill_sqe(sqe, &task_list[i], &pasid, sq_tail, pdev->streamid);
		sq_tail = (sq_tail + 1) & (HISI_SDMA_SQ_LENGTH - 1);
	}
	sdma_channel_set_sq_tail(pchannel, sq_tail);
	pchannel->sync_info_base->sq_tail = (u16)sq_tail;
	spin_unlock(&pchannel->owner_chn_lock);

	return 0;
}

static u32 sdma_channel_free_sqe_cnt(struct hisi_sdma_channel *pchannel)
{
	u32 head = sdma_channel_get_sq_head(pchannel);
	u32 tail = sdma_channel_get_sq_tail(pchannel);
	u32 res_cnt;

	if (tail >= head)
		res_cnt = HISI_SDMA_SQ_LENGTH - (tail - head) - 1;
	else
		res_cnt = head - tail - 1;

	return res_cnt;
}

static int sdma_task_info_validate(struct file_open_data *data,
				   struct hisi_sdma_task_info *task_info)
{
	struct hisi_sdma_channel *pchannel;
	u32 free_sqe_cnt;

	if (task_info->chn >= data->psdma_dev->nr_channel) {
		dev_err(&data->psdma_dev->pdev->dev, "Invalid channel num:%u!\n", task_info->chn);
		return -EINVAL;
	}
	pchannel = data->psdma_dev->channels + task_info->chn;
	free_sqe_cnt = sdma_channel_free_sqe_cnt(pchannel);
	if (task_info->task_cnt > HISI_SDMA_MAX_ALLOC_SIZE / sizeof(struct hisi_sdma_sqe_task) ||
	    task_info->task_cnt > free_sqe_cnt || task_info->task_cnt == 0) {
		dev_err(&data->psdma_dev->pdev->dev, "Invalid send task cnt:%u!\n",
			task_info->task_cnt);
		return -EINVAL;
	}

	return 0;
}

static int ioctl_sdma_send_task(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct device *dev = &data->psdma_dev->pdev->dev;
	struct hisi_sdma_task_info task_info;
	struct hisi_sdma_sqe_task *task_list;
	int ret;

	if (copy_from_user(&task_info, (struct hisi_sdma_task_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_task_info))) {
		dev_err(dev, "Get hisi_sdma_task_info failed\n");
		return -EFAULT;
	}
	ret = sdma_task_info_validate(data, &task_info);
	if (ret != 0)
		return ret;

	task_list = kcalloc_node(task_info.task_cnt, sizeof(struct hisi_sdma_sqe_task), GFP_KERNEL,
				 data->psdma_dev->node_idx);
	if (!task_list)
		return -ENOMEM;

	if (copy_from_user(task_list, (void __user *)task_info.task_addr,
			   task_info.task_cnt * sizeof(struct hisi_sdma_sqe_task))) {
		dev_err(dev, "Get hisi_sdma_sqe_task failed\n");
		ret = -EFAULT;
		goto free_list;
	}
	ret = sdma_send_task_kernel(data, &task_info, task_list);
	if (ret < 0) {
		dev_err(dev, "Execute sdma_send_task_kernel failed\n");
		goto free_list;
	}

	if (copy_to_user((struct hisi_sdma_task_info __user *)(uintptr_t)arg, &task_info,
			 sizeof(struct hisi_sdma_task_info))) {
		dev_err(dev, "Set hisi_sdma_task_info failed\n");
		ret = -EFAULT;
	}

free_list:
	kfree(task_list);

	return ret;
}

/* register value should be between cq_head(software update) and cq_tail(hardware updated) */
static bool sdma_cq_head_validate(struct hisi_sdma_channel *pchan, u32 reg_value)
{
	u32 cq_tail;
	u32 cq_head;

	if (reg_value >= HISI_SDMA_CQ_LENGTH)
		return false;

	cq_head = sdma_channel_get_cq_head(pchan);
	cq_tail = sdma_channel_get_cq_tail(pchan);
	if (cq_tail > cq_head) {
		if (reg_value <= cq_tail && reg_value >= cq_head)
			return true;
	} else {
		if (reg_value <= cq_tail || reg_value >= cq_head)
			return true;
	}

	return false;
}

static int sdma_operation_reg(struct file_open_data *data, unsigned long arg,
			      u32 (*get_func)(struct hisi_sdma_channel *),
			      void (*set_func)(struct hisi_sdma_channel *, u32))
{
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct device *dev = &pdev->pdev->dev;
	struct hisi_sdma_reg_info reg_info;
	struct hisi_sdma_channel *pchannel;

	if (copy_from_user(&reg_info, (struct hisi_sdma_reg_info __user *)(uintptr_t)arg,
			   sizeof(struct hisi_sdma_reg_info))) {
		dev_err(dev, "Get hisi_sdma_reg_info failed\n");
		return -EFAULT;
	}

	if (reg_info.chn >= pdev->nr_channel) {
		dev_err(dev, "Invalid channel num:%u!\n", reg_info.chn);
		return -EINVAL;
	}
	pchannel = pdev->channels + reg_info.chn;
	spin_lock(&pchannel->owner_chn_lock);
	if (sdma_check_channel_permission(pchannel, data->ida, reg_info.chn) != 0) {
		spin_unlock(&pchannel->owner_chn_lock);
		dev_err(dev, "Invalid process operate channel%u!\n", reg_info.chn);
		return -EPERM;
	}

	if (reg_info.type == HISI_SDMA_READ_REG) {
		reg_info.reg_value = get_func(pchannel);
		if (copy_to_user((struct hisi_sdma_reg_info __user *)(uintptr_t)arg, &reg_info,
				 sizeof(struct hisi_sdma_reg_info))) {
			spin_unlock(&pchannel->owner_chn_lock);
			dev_err(dev, "Copy reg_info to user failed\n");
			return -EFAULT;
		}
	} else if (reg_info.type == HISI_SDMA_WRITE_REG) {
		if (set_func) {
			if (reg_info.reg_value == sdma_channel_get_cq_head(pchannel)) {
				spin_unlock(&pchannel->owner_chn_lock);
				return 0;
			}
			if (sdma_cq_head_validate(pchannel, reg_info.reg_value)) {
				set_func(pchannel, reg_info.reg_value);
			} else {
				spin_unlock(&pchannel->owner_chn_lock);
				dev_err(dev, "Cq_head value illegal!\n");
				return -EINVAL;
			}
		}
	}
	spin_unlock(&pchannel->owner_chn_lock);

	return 0;
}

static int ioctl_sdma_sq_head_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;

	return sdma_operation_reg(data, arg, sdma_channel_get_sq_head, NULL);
}

static int ioctl_sdma_sq_tail_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;

	return sdma_operation_reg(data, arg, sdma_channel_get_sq_tail, NULL);
}

static int ioctl_sdma_cq_head_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;

	return sdma_operation_reg(data, arg, sdma_channel_get_cq_head, sdma_channel_set_cq_head);
}

static int ioctl_sdma_cq_tail_reg(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;

	return sdma_operation_reg(data, arg, sdma_channel_get_cq_tail, NULL);
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
		dev_err(dev, "Dfx_reg copy from user failed\n");
		return -EFAULT;
	}

	if (reg_info.chn >= pdev->nr_channel) {
		dev_err(dev, "Invalid channel num:%u!\n", reg_info.chn);
		return -EINVAL;
	}
	pchannel = pdev->channels + reg_info.chn;
	spin_lock(&pchannel->owner_chn_lock);
	if (sdma_check_channel_permission(pchannel, data->ida, reg_info.chn) != 0) {
		spin_unlock(&pchannel->owner_chn_lock);
		dev_err(dev, "Invalid process operate channel%u dfx!\n", reg_info.chn);
		return -EPERM;
	}
	spin_unlock(&pchannel->owner_chn_lock);
	reg_info.reg_value = sdma_channel_get_dfx(pchannel);
	if (copy_to_user((struct hisi_sdma_reg_info __user *)(uintptr_t)arg, &reg_info,
			 sizeof(struct hisi_sdma_reg_info))) {
		dev_err(dev, "Dfx_reg copy to user failed\n");
		return -EFAULT;
	}

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
		dev_err(dev, "Get hisi_sdma_reg_info failed\n");
		return -EFAULT;
	}
	if (reg_info.chn >= pdev->nr_channel) {
		dev_err(dev, "Invalid channel num:%u!\n", reg_info.chn);
		return -EINVAL;
	}

	pchannel = pdev->channels + reg_info.chn;
	spin_lock(&pchannel->owner_chn_lock);
	if (sdma_check_channel_permission(pchannel, data->ida, reg_info.chn) != 0) {
		spin_unlock(&pchannel->owner_chn_lock);
		dev_err(dev, "Invalid process operate channel%u sqe reg!\n", reg_info.chn);
		return -EPERM;
	}
	spin_unlock(&pchannel->owner_chn_lock);
	if (reg_info.type == HISI_SDMA_CLR_NORMAL_SQE_CNT)
		sdma_channel_clr_normal_sqe_cnt(pchannel);
	else if (reg_info.type == HISI_SDMA_CLR_ERR_SQE_CNT)
		sdma_channel_clr_err_sqe_cnt(pchannel);

	return 0;
}

static int ioctl_get_sdma_mode(struct file *file SDMA_UNUSED, unsigned long arg)
{
	bool mode = *(g_info.sdma_mode);

	if (copy_to_user((bool __user *)(uintptr_t)arg, &mode, sizeof(bool)))
		return -EFAULT;

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
	{IOCTL_GET_SDMA_MODE,			ioctl_get_sdma_mode},
};

static long sdma_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int cmd_num;
	int i;

	cmd_num = ARRAY_SIZE(g_ioctl_funcs);
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
		pr_err("Cannot find a sdma device\n");
		return -ENODEV;
	}
	sdma_dev = inode->i_rdev;
	sdma_idx = MINOR(sdma_dev);
	if (sdma_idx >= HISI_SDMA_MAX_DEVS) {
		pr_err("Wrong id of sdma device\n");
		return -ENODEV;
	}
	psdma_dev = g_info.core_dev->sdma_devices[sdma_idx];
	if (!psdma_dev) {
		pr_err("Cannot find sdma%u\n", sdma_idx);
		return -ENODEV;
	}

	return __do_sdma_open(psdma_dev, file);
}

ssize_t sdma_read_info(struct file *file, char __user *buf SDMA_UNUSED, size_t size SDMA_UNUSED,
		       loff_t *ppos SDMA_UNUSED)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	struct device *dev = &pdev->pdev->dev;
	u32 share_chns = *(g_info.share_chns);
	bool mode = *(g_info.sdma_mode);

	if (mode == HISI_SDMA_FAST_MODE)
		dev_info(dev, "SDMA is running unter fast mode\n");
	else
		dev_info(dev, "SDMA is running unter safe mode\n");

	if (share_chns > pdev->nr_channel)
		share_chns = pdev->nr_channel;
	dev_info(dev, "SDMA%u has %u channels in total, %u share_channels\n",
		 pdev->idx, pdev->nr_channel, share_chns);

	return 0;
}

static int sdma_dev_release(struct inode *inode SDMA_UNUSED, struct file *file)
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
		dev_dbg(dev, "Release non_share_chn%u\n", c->chn_idx);
		pchannel = pdev->channels + c->chn_idx;
		pchannel->cnt_used--;
		sdma_reset_ida_val(pchannel);
		bitmap_set(pdev->channel_map, c->chn_idx - share_chns, 1);
		list_del(&c->chn_list);
		kfree(c);
		pdev->nr_channel_used--;
	}

	list_for_each_entry_safe(c, n, &data->share_chn_list, chn_list) {
		dev_dbg(dev, "Release share_chn%u\n", c->chn_idx);
		pchannel = pdev->channels + c->chn_idx;
		pchannel->cnt_used--;
		if (pchannel->sync_info_base->lock != 0 &&
			pchannel->sync_info_base->lock_pid == (u32)current->tgid) {
			dev_warn(dev, "Process %d exit with lock\n", current->tgid);
			pchannel->sync_info_base->lock_pid = 0;
			/* clear lockpid before release lock */
			wmb();
			pchannel->sync_info_base->lock = 0;
		}
		if (pchannel->cnt_used == 0) {
			pchannel->sync_info_base->err_cnt = 0;
			pchannel->sync_info_base->lock_pid = 0;
			/* clear lockpid before release lock */
			wmb();
			pchannel->sync_info_base->lock = 0;
		}
		sdma_del_ida_ref(pchannel, data->ida);
		list_del(&c->chn_list);
		kfree(c);
	}
	spin_unlock(&pdev->channel_lock);

	/* mm could be flushed by exec/fork, we don't put mmu_notifier at this time */
	if (current->mm == data->cur_file_mm)
		sdma_put_pause_mmu_notifier(pdev);

	if (data->handle)
		iommu_sva_unbind_device(data->handle);

	if (current->mm == data->cur_file_mm)
		sdma_put_resume_mmu_notifier(pdev);

	sdma_hash_free_entry(data->ida);
	sdma_del_pid_ref(pid);
	ida_free(g_info.fd_ida, data->ida);

	kfree(file->private_data);
	file->private_data = NULL;

	return 0;
}

static int remap_addr_range(u32 chn_num, u64 offset, u64 size, struct hisi_sdma_channel *chn_base,
			    int ida)
{
	u64 reg_max_size = max_t(u64, HISI_SDMA_REG_SIZE, PAGE_SIZE);
	u64 sq_max_size = max_t(u64, HISI_SDMA_SQ_SIZE, PAGE_SIZE);
	u64 cq_max_size = max_t(u64, HISI_SDMA_CQ_SIZE, PAGE_SIZE);
	struct hisi_sdma_channel *pchannel;
	bool mode = *(g_info.sdma_mode);
	u64 sync_size;

	sync_size = (u64)((sizeof(struct hisi_sdma_queue_info) + PAGE_SIZE - ALIGN_NUM) /
		    PAGE_SIZE * PAGE_SIZE);

	if (offset >= chn_num * (HISI_SDMA_MMAP_SHMEM + 1)) {
		pr_err("SDMA mmap offset exceed range\n");
		return -EINVAL;
	}

	pchannel = chn_base + offset % chn_num;
	spin_lock(&pchannel->owner_chn_lock);
	if (sdma_check_channel_permission(pchannel, ida, pchannel->idx)) {
		spin_unlock(&pchannel->owner_chn_lock);
		pr_err("SDMA invalid process mmap\n");
		return -EPERM;
	}
	spin_unlock(&pchannel->owner_chn_lock);

	if (offset < chn_num * HISI_SDMA_MMAP_CQE) {
		if (mode == HISI_SDMA_SAFE_MODE || size > sq_max_size) {
			pr_err("SDMA mmap size exceed sqe range\n");
			return -EINVAL;
		}
		return HISI_SDMA_MMAP_SQE;
	} else if (offset < chn_num * HISI_SDMA_MMAP_IO) {
		if (size > cq_max_size) {
			pr_err("SDMA mmap size exceed cqe range\n");
			return -EINVAL;
		}
		return HISI_SDMA_MMAP_CQE;
	} else if (offset < chn_num * HISI_SDMA_MMAP_SHMEM) {
		if (mode == HISI_SDMA_SAFE_MODE || size > reg_max_size) {
			pr_err("SDMA not support io reg mmap\n");
			return -EINVAL;
		}
		return HISI_SDMA_MMAP_IO;
	} else {
		if (size > sync_size) {
			pr_err("SDMA mmap size exceed share mem range\n");
			return -EINVAL;
		}
		return HISI_SDMA_MMAP_SHMEM;
	}
}

static int sdma_vma_remap(struct vm_area_struct *vma)
{
	pr_err("SDMA vma remap not supported!\n");
	return -EINVAL;
}

static const struct vm_operations_struct sdma_vm_ops = {
	.mremap = sdma_vma_remap,
};

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
	vma->vm_ops = &sdma_vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_WIPEONFORK | VM_DONTCOPY | VM_IO;

	dev_dbg(dev, "SDMA total channel num = %u, user mmap offset = 0x%llx", chn_num, offset);
	switch (remap_addr_range(chn_num, offset, size, chn_base, data->ida)) {
	case HISI_SDMA_MMAP_SQE:
		pchan = chn_base + offset;
		pfn_start = virt_to_phys(pchan->sq_base) >> PAGE_SHIFT;
		ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size, vma->vm_page_prot);
		break;

	case HISI_SDMA_MMAP_CQE:
		pchan = chn_base + offset - chn_num * HISI_SDMA_MMAP_CQE;
		pfn_start = virt_to_phys(pchan->cq_base) >> PAGE_SHIFT;
		ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size, vma->vm_page_prot);
		break;

	case HISI_SDMA_MMAP_IO:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		pfn_start = (io_base + HISI_SDMA_CH_OFFSET) >> PAGE_SHIFT;
		pfn_start += (offset - chn_num * HISI_SDMA_MMAP_IO) * HISI_SDMA_REG_SIZE /
			     PAGE_SIZE;
		ret = io_remap_pfn_range(vma, vma->vm_start, pfn_start, size, vma->vm_page_prot);
		break;

	case HISI_SDMA_MMAP_SHMEM:
		pchan = chn_base + offset - chn_num * HISI_SDMA_MMAP_SHMEM;
		pfn_start = virt_to_phys(pchan->sync_info_base) >> PAGE_SHIFT;
		ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size, vma->vm_page_prot);
		break;

	default:
		return -EINVAL;
	}
	if (ret)
		dev_err(dev, "SDMA mmap failed!\n");

	return ret;
}

static const struct file_operations sdma_cdev_core_fops = {
	.owner		= THIS_MODULE,
	.open		= sdma_core_open,
	.read		= sdma_read_info,
	.release	= sdma_dev_release,
	.unlocked_ioctl	= sdma_dev_ioctl,
	.mmap		= sdma_dev_mmap,
};

void sdma_cdev_init(struct cdev *cdev)
{
	cdev_init(cdev, &sdma_cdev_core_fops);
	cdev->owner = THIS_MODULE;
}

void sdma_info_sync_cdev(struct hisi_sdma_core_device *p, u32 *share_chns, struct ida *fd_ida,
			 bool *safe_mode)
{
	struct hisi_sdma_global_info *sdma_global_info = &g_info;

	sdma_global_info->core_dev = p;
	sdma_global_info->fd_ida = fd_ida;
	sdma_global_info->share_chns = share_chns;
	sdma_global_info->sdma_mode = safe_mode;

	hash_init(sdma_global_info->sdma_pid_ref_ht);
}
