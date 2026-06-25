/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : ossl_knl_linux.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/vmalloc.h>
#include "ossl_knl_linux.h"

#define OSSL_MINUTE_BASE (60)

#if (KERNEL_VERSION(2, 6, 36) > LINUX_VERSION_CODE)
#ifdef __LINX_6_0_60__
unsigned int _work_busy(struct work_struct *work)
{
	if (work_pending(work))
		return WORK_BUSY_PENDING;
	else
		return WORK_BUSY_RUNNING;
}
#endif /* work_busy */
#endif

#if (KERNEL_VERSION(3, 4, 0) > LINUX_VERSION_CODE)
void _kc_skb_add_rx_frag(struct sk_buff *skb, int i, struct page *page,
			 int off, int size, unsigned int truesize)
{
	skb_fill_page_desc(skb, i, page, off, size);
	skb->len += size;
	skb->data_len += size;
	skb->truesize += truesize;
}

#endif /* < 3.4.0 */
#ifdef NEED_PCI_SRIOV_GET_TOTALVFS
/*
 * pci_sriov_get_totalvfs -- get total VFs supported on this device
 * @dev: the PCI PF device
 *
 * For a PCIe device with SRIOV support, return the PCIe
 * SRIOV capability value of TotalVFs.  Otherwise 0.
 */
int pci_sriov_get_totalvfs(struct pci_dev *dev)
{
	int sriov_cap_pos;
	u16 total_vfs = 0;

	if (dev->is_virtfn)
		return 0;

	sriov_cap_pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	pci_read_config_word(dev, sriov_cap_pos + PCI_SRIOV_TOTAL_VF,
			     &total_vfs);

	return total_vfs;
}
#endif

#if (KERNEL_VERSION(3, 10, 0) > LINUX_VERSION_CODE)
/*
 * pci_vfs_assigned - returns number of VFs are assigned to a guest
 * @dev: the PCI device
 *
 * Returns number of VFs belonging to this device that are assigned to a guest.
 * If device is not a physical function returns -ENODEV.
 */
int pci_vfs_assigned(struct pci_dev *dev)
{
	unsigned int vfs_assigned = 0;
#ifdef HAVE_PCI_DEV_FLAGS_ASSIGNED
	struct pci_dev *vfdev;
	unsigned short dev_id = 0;
	int sriov_cap_pos;

	/* only search if we are a PF. */
	if (dev->is_virtfn)
		return 0;

	/* determine the device ID for the VFs, the vendor ID will be the
	 * same as the PF so there is no need to check for that one.
	 */
	sriov_cap_pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	pci_read_config_word(dev, sriov_cap_pos + PCI_SRIOV_VF_DID, &dev_id);

	/* loop through all the VFs to see if we own any that are assigned. */
	vfdev = pci_get_device(dev->vendor, dev_id, NULL);
	while (vfdev) {
		/* It is considered assigned if it is a virtual function with
		 * our dev as the physical function and the assigned bit is set.
		 */
		if (vfdev->is_virtfn && vfdev->physfn == dev &&
		    (vfdev->dev_flags & PCI_DEV_FLAGS_ASSIGNED))
			vfs_assigned++;

		vfdev = pci_get_device(dev->vendor, dev_id, vfdev);
	}
#endif /* HAVE_PCI_DEV_FLAGS_ASSIGNED */

	return (int)vfs_assigned;
}

#endif /* 3.10.0 */
#if (KERNEL_VERSION(3, 13, 0) > LINUX_VERSION_CODE)
int kc_dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
	int ret;

	ret = dma_set_mask(dev, mask);
	if (!ret)
		ret = dma_set_coherent_mask(dev, mask);

	return ret;
}

#endif /* 3.13.0 */
#if (KERNEL_VERSION(3, 14, 0) > LINUX_VERSION_CODE)
int pci_enable_msix_range(struct pci_dev *dev, struct msix_entry *entries,
			  int min_vec, int max_vec)
{
	int nvec = max_vec;
	int ret;

	if (max_vec < min_vec)
		return -ERANGE;

	do {
		ret = pci_enable_msix(dev, entries, nvec);
		if (ret < 0) {
			return ret;
		} else if (ret > 0) {
			if (ret < min_vec)
				return -ENOSPC;
			nvec = ret;
		}
	} while (ret != 0);

	return nvec;
}

#endif

#if (KERNEL_VERSION(3, 19, 0) > LINUX_VERSION_CODE)
#endif  /* < 3.19.0 */

#ifdef NEED_CPUMASK_LOCAL_SPREAD
unsigned int cpumask_local_spread(unsigned int i, int node)
{
	int cpu;
	unsigned int num = i;

	/* Wrap: we always want a cpu. */
	num %= (unsigned int)num_online_cpus();

	if (node == -1) {
		for_each_cpu(cpu, cpu_online_mask) {
			if (num-- == 0)
				return (unsigned int)cpu;
		}
	} else {
		/* NUMA first. */
		for_each_cpu_and(cpu, cpumask_of_node(node), cpu_online_mask) {
			if (num-- == 0)
				return (unsigned int)cpu;
		}

		for_each_cpu(cpu, cpu_online_mask) {
			/* Skip NUMA nodes, done above. */
			if (cpumask_test_cpu(cpu, cpumask_of_node(node)) != 0)
				continue;

			if (num-- == 0)
				return (unsigned int)cpu;
		}
	}

	WARN_ON(num != 0);
	return 0;
}
#endif

struct file *hinic5_file_creat(const char *file_name)
{
	return filp_open(file_name, O_CREAT | O_RDWR | O_APPEND, 0);
}

struct file *hinic5_file_open(const char *file_name)
{
	return filp_open(file_name, O_RDONLY, 0);
}

void hinic5_file_close(struct file *file_handle)
{
	(void)filp_close(file_handle, NULL);
}

u32 hinic5_get_file_size(struct file *file_handle)
{
	struct inode *file_inode = NULL;

#if (KERNEL_VERSION(3, 19, 0) > LINUX_VERSION_CODE)
	file_inode = file_handle->f_dentry->d_inode;
#else
	file_inode = file_handle->f_inode;
#endif

	return (u32)(file_inode->i_size);
}

void hinic5_set_file_position(struct file *file_handle, u32 position)
{
	file_handle->f_pos = position;
}

int hinic5_file_read(struct file *file_handle, char *log_buffer, u32 rd_length,
	      u32 *file_pos)
{
	if (!file_handle || !log_buffer || rd_length == 0)
		return -EINVAL;

#if (KERNEL_VERSION(4, 5, 0) > LINUX_VERSION_CODE)
	return (int)file_handle->f_op->read(file_handle, log_buffer, rd_length,
					    &file_handle->f_pos);
#elif (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	return (int)vfs_read(file_handle, log_buffer, rd_length,
			     &file_handle->f_pos);
#else
	return (int)kernel_read(file_handle, log_buffer, rd_length,
				&file_handle->f_pos);

#endif
}

u32 hinic5_file_write(struct file *file_handle, const char *log_buffer, u32 wr_length)
{
	if (!file_handle || !log_buffer || wr_length == 0)
		return -EINVAL;

#if (KERNEL_VERSION(4, 5, 0) > LINUX_VERSION_CODE)
	return (u32)file_handle->f_op->write(file_handle, log_buffer,
					     wr_length, &file_handle->f_pos);
#elif (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	return (u32)vfs_write(file_handle,
			      (__force const char __user *)log_buffer,
			      wr_length, &file_handle->f_pos);
#else
	return (u32)kernel_write(file_handle, log_buffer, wr_length,
				 &file_handle->f_pos);

#endif
}

static int _linux_thread_func(void *thread)
{
	struct sdk_thread_info *info = (struct sdk_thread_info *)thread;

	while (!kthread_should_stop())
		info->thread_fn(info->data);

	return 0;
}

int hinic5_creat_thread(struct sdk_thread_info *thread_info)
{
	thread_info->thread_obj = kthread_run(_linux_thread_func, thread_info,
					      thread_info->name);
	if (!thread_info->thread_obj)
		return -EFAULT;

	return 0;
}

void hinic5_stop_thread(struct sdk_thread_info *thread_info)
{
	if (thread_info->thread_obj)
		(void)kthread_stop(thread_info->thread_obj);
}

void hinic5_utctime_to_localtime(u64 utctime, u64 *localtime)
{
	*localtime = utctime - (u64)(sys_tz.tz_minuteswest * OSSL_MINUTE_BASE);
}

#ifndef HAVE_TIMER_SETUP
void initialize_timer(const void *adapter_hdl, struct timer_list *timer)
{
	if (!adapter_hdl || !timer)
		return;

	init_timer(timer);
}
#endif

void hinic5_add_to_timer(struct timer_list *timer, u64 period)
{
	if (!timer)
		return;

	add_timer(timer);
}

void hinic5_stop_timer(struct timer_list *timer) {}

void hinic5_delete_timer(struct timer_list *timer)
{
	if (!timer)
		return;

	del_timer_sync(timer);
}

u64 hinic5_ossl_get_real_time(void)
{
	struct timeval tv = {0};
	u64 tv_msec;

	do_gettimeofday(&tv);

	tv_msec = (u64)tv.tv_sec * MSEC_PER_SEC + (u64)tv.tv_usec / USEC_PER_MSEC;
	return tv_msec;
}

#ifdef NEED_MATH64_MUL_U64_U64_DIV_U64
u64 mul_u64_u64_div_u64(u64 a, u64 b, u64 c)
{
	u64 res = 0, div, rem;
	int shift;

	/* 62: can a * b overflow ? */
	if (ilog2(a) + ilog2(b) > 62) {
		/*
		 * (b * a) / c is equal to
		 *
		 *      (b / c) * a +
		 *      (b % c) * a / c
		 *
		 * if nothing overflows. Can the 1st multiplication
		 * overflow? Yes, but we do not care: this can only
		 * happen if the end result can't fit in u64 anyway.
		 *
		 * So the code below does
		 *
		 *      res = (b / c) * a;
		 *      b = b % c;
		 */
		div = div64_u64_rem(b, c, &rem);
		res = div * a;
		b = rem;

		/* 62: if a * b overflow ? b and c both move right shift until a * b not overflow */
		shift = ilog2(a) + ilog2(b) - 62;
		if (shift > 0) {
			/* drop precision */
			b >>= shift;
			c >>= shift;
			if (!c)
				return res;
		}
	}

	return res + div64_u64(a * b, c);
}
EXPORT_SYMBOL(mul_u64_u64_div_u64);
#endif

#if KERNEL_VERSION(5, 10, 0) > LINUX_VERSION_CODE
int sysfs_emit(char *buf, const char *fmt, ...)
{
	va_list args;
	int len;

	if (WARN(!buf || offset_in_page(buf),
		 "invalid %s: buf:%p\n", __func__, buf))
		return 0;

	va_start(args, fmt);
	len = vscnprintf(buf, PAGE_SIZE, fmt, args);
	va_end(args);

	return len;
}
#endif
