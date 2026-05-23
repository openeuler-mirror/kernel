/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_lld.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <net/addrconf.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/inetdevice.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/aer.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/mm.h>

#include "ossl_knl.h"
#include "hinic5_mt.h"
#include "hinic5_common.h"
#include "hinic5_crm.h"
#include "hinic5_id_tbl.h"
#include "hinic5_sriov.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_nictool.h"
#include "hinic5_hw.h"
#include "hinic5_hinic5_vram.h"
#include "hinic5_fast_msg_init.h"
#include "hinic5_profile.h"
#include "hinic5_hwdev.h"
#include "hinic5_prof_adap.h"
#include "hinic5_fw_update.h"
#include "mpu_inband_cmd_defs.h"
#include "hinic5_bus.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_lld_private.h"
#include "hinic5_hw_comm.h"
#include "hinic5_lld.h"

static bool use_hinic5_vram;
module_param(use_hinic5_vram, bool, 0644);
MODULE_PARM_DESC(use_hinic5_vram, "use HINIC5_VRAM or not (only used in sdi_nanoos) - default is false");

static bool disable_attach;
module_param(disable_attach, bool, 0444);
MODULE_PARM_DESC(disable_attach, "disable_attach or not - default is false");

static bool disable_vf_load;
module_param(disable_vf_load, bool, 0444);
MODULE_PARM_DESC(disable_vf_load,
		 "Disable virtual functions probe or not - default is false");

bool hinic5_is_disable_vf_load(void)
{
	return disable_vf_load;
}

#define HINIC5_WAIT_SRIOV_CFG_TIMEOUT	40000 /* same as default mbox timeout */

#define HINIC5_SYNC_YEAR_OFFSET 1900
#define HINIC5_SYNC_MONTH_OFFSET 1

MODULE_AUTHOR("Huawei Technologies CO., Ltd");
MODULE_DESCRIPTION(HINIC5_DRV_DESC);
MODULE_VERSION(HINIC5_DRV_VERSION);
MODULE_LICENSE("GPL");

#if !(defined(HAVE_SRIOV_CONFIGURE) || defined(HAVE_RHEL6_SRIOV_CONFIGURE))
static DEVICE_ATTR(sriov_numvfs, 0644,
			hinic5_sriov_numvfs_show, hinic5_sriov_numvfs_store);
static DEVICE_ATTR(sriov_totalvfs, 0444,
			sriov_totalvfs_show, NULL);
#endif /* !(HAVE_SRIOV_CONFIGURE || HAVE_RHEL6_SRIOV_CONFIGURE) */

struct hinic5_uld_info hinic5_g_uld_info[SERVICE_T_MAX] = { {0} };

#define HINIC5_EVENT_PROCESS_TIMEOUT	10000
struct mutex		hinic5_g_uld_mutex;  // Global mutex to protect ULD operations

#define HINIC5_PROC_DIR "hisdk5"
struct proc_dir_entry *g_proc_dir;

void hinic5_uld_lock_init(void)
{
	mutex_init(&hinic5_g_uld_mutex);
}

static const char *s_uld_name[SERVICE_T_MAX] = {
	"nic", "ovs", "roce", "toe", "ioe", "fc", "vbs", "ipsec", "virtio",
	"migrate", "ppa", "custom", "vroce", "ub", "jbof", "macsec", "dmmu",
	"cfm", "bifur", "hihtr"};

const char **hinic5_get_uld_names(void)
{
	return s_uld_name;
}

const struct hinic5_uld_info *hinic5_get_uld_info_by_type(enum hinic5_service_type type)
{
	if (type >= SERVICE_T_MAX)
		return NULL;

	return &hinic5_g_uld_info[type];
}

static int attach_uld(struct hinic5_adev *adev, enum hinic5_service_type type,
		      const struct hinic5_uld_info *uld_info)
{
	void *uld_dev = NULL;
	int err;

	mutex_lock(&adev->adev_mutex);

	if (adev->uld_dev[type]) {
		sdk_err(adev->dev,
			"%s driver has attached\n",
			s_uld_name[type]);
		err = 0;
		goto out_unlock;
	}

	if (!uld_info || !uld_info->probe || !uld_info->remove) {
		err = 0;
		goto out_unlock;
	}

	atomic_set(&adev->uld_ref_cnt[type], 0);
	err = uld_info->probe(&adev->lld_dev, &uld_dev, adev->uld_dev_name[type]);
	if (err != 0) {
		sdk_info(adev->dev,
			 "cannot add object for %s driver\n",
			 s_uld_name[type]);
		goto probe_failed;
	}

	adev->uld_dev[type] = uld_dev;
	set_bit(type, &adev->uld_state);
	mutex_unlock(&adev->adev_mutex);

	sdk_info(adev->dev,
		 "Attach %s driver succeed\n", s_uld_name[type]);
	return 0;

probe_failed:
out_unlock:
	mutex_unlock(&adev->adev_mutex);

	return err;
}

static void wait_uld_unused(struct hinic5_adev *adev, enum hinic5_service_type type)
{
	u32 loop_cnt = 0;
	u32 print_cnt = 0;

	while (atomic_read(&adev->uld_ref_cnt[type]) != 0) {
		loop_cnt++;
		if ((loop_cnt % PRINT_ULD_DETACH_TIMEOUT_INTERVAL == 0) &&
		    print_cnt < PRINT_ULD_DETACH_TIMES) {
			sdk_err(adev->dev, "Wait for uld unused for %lds, reference count: %d\n",
				(PRINT_ULD_DETACH_TIMES_INTERVAL * loop_cnt / MSEC_PER_SEC),
				atomic_read(&adev->uld_ref_cnt[type]));

			print_cnt++;
		}

		usleep_range(ULD_LOCK_MIN_USLEEP_TIME, ULD_LOCK_MAX_USLEEP_TIME);
	}
}

static void detach_uld(struct hinic5_adev *adev,
		       enum hinic5_service_type type)
{
	struct hinic5_uld_info *uld_info = &hinic5_g_uld_info[type];
	ulong end;
	bool timeout = true;

	mutex_lock(&adev->adev_mutex);
	if (!adev->uld_dev[type]) {
		mutex_unlock(&adev->adev_mutex);
		return;
	}

	end = jiffies + msecs_to_jiffies(HINIC5_EVENT_PROCESS_TIMEOUT);
	do {
		if (!test_and_set_bit(type, &adev->state)) {
			timeout = false;
			break;
		}
		usleep_range(900, 1000); /* sleep 900 us ~ 1000 us */
	} while (time_before(jiffies, end));

	if (timeout && !test_and_set_bit(type, &adev->state))
		timeout = false;

	spin_lock_bh(&adev->uld_lock);
	clear_bit(type, &adev->uld_state);
	spin_unlock_bh(&adev->uld_lock);

	wait_uld_unused(adev, type);

	uld_info->remove(&adev->lld_dev, adev->uld_dev[type]);

	adev->uld_dev[type] = NULL;
	if (!timeout)
		clear_bit(type, &adev->state);

	sdk_info(adev->dev,
		 "Detach %s driver succeed\n",
		 s_uld_name[type]);
	mutex_unlock(&adev->adev_mutex);
}

static void attach_ulds(struct hinic5_adev *adev)
{
	int type;

	hinic5_lld_hold();
	mutex_lock(&hinic5_g_uld_mutex);

	for (type = SERVICE_T_NIC; type < SERVICE_T_MAX; type++) {
		if (hinic5_g_uld_info[type].probe) {
			/* vf in VM can not disable service load */
			if ((hinic5_adev_is_virtfn(adev) != 0) &&
			    (!hinic5_get_vf_service_load(adev, (u16)type))) {
				sdk_info(adev->dev, "VF device disable service_type = %d load in host\n",
					 type);
				continue;
			}
			attach_uld(adev, (enum hinic5_service_type)type, &hinic5_g_uld_info[type]);
		}
	}
	mutex_unlock(&hinic5_g_uld_mutex);
	hinic5_lld_put();
}

static void detach_ulds(struct hinic5_adev *adev)
{
	int type;

	hinic5_lld_hold();
	mutex_lock(&hinic5_g_uld_mutex);
	for (type = SERVICE_T_MAX - 1; type > SERVICE_T_NIC; type--) {
		if (hinic5_g_uld_info[type].probe)
			detach_uld(adev, (enum hinic5_service_type)type);
	}

	if (hinic5_g_uld_info[SERVICE_T_NIC].probe)
		detach_uld(adev, SERVICE_T_NIC);
	mutex_unlock(&hinic5_g_uld_mutex);
	hinic5_lld_put();
}

int hinic5_register_uld(enum hinic5_service_type type,
			struct hinic5_uld_info *uld_info)
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;
	struct list_head *chip_list = NULL;

	if (type >= SERVICE_T_MAX) {
		pr_err("Unknown type %d of up layer driver to register\n",
		       type);
		return -EINVAL;
	}

	if (!uld_info || !uld_info->probe || !uld_info->remove) {
		pr_err("Invalid information of %s driver to register\n",
		       s_uld_name[type]);
		return -EINVAL;
	}

	hinic5_lld_hold();
	mutex_lock(&hinic5_g_uld_mutex);

	if (hinic5_g_uld_info[type].probe) {
		pr_err("%s driver has registered\n", s_uld_name[type]);
		mutex_unlock(&hinic5_g_uld_mutex);
		hinic5_lld_put();
		return -EINVAL;
	}

	chip_list = get_hinic5_chip_list();
	memcpy(&hinic5_g_uld_info[type], uld_info, sizeof(struct hinic5_uld_info));
	list_for_each_entry(chip_node, chip_list, node) {
		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (attach_uld(adev, type, uld_info) != 0) {
				sdk_info(adev->dev,
					 "Cannot attach %s driver\n",
					 s_uld_name[type]);
#ifdef CONFIG_MODULE_PROF
				adev->bus_ops->fault_process(adev, hinic5_func_max_vf(adev->hwdev));
				break;
#else
				continue;
#endif
			}
		}
	}

	mutex_unlock(&hinic5_g_uld_mutex);
	hinic5_lld_put();

	pr_info("Register %s driver succeed\n", s_uld_name[type]);
	return 0;
}
EXPORT_SYMBOL(hinic5_register_uld);

void hinic5_unregister_uld(enum hinic5_service_type type)
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;
	struct hinic5_uld_info *uld_info = NULL;
	struct list_head *chip_list = NULL;

	if (type >= SERVICE_T_MAX) {
		pr_err("Unknown type %d of up layer driver to unregister\n",
		       type);
		return;
	}

	hinic5_lld_hold();
	mutex_lock(&hinic5_g_uld_mutex);
	chip_list = get_hinic5_chip_list();
	list_for_each_entry(chip_node, chip_list, node) {
		/* detach vf first */
		list_for_each_entry(adev, &chip_node->func_list, node)
			if (hinic5_func_type(adev->hwdev) == TYPE_VF)
				detach_uld(adev, type);

		list_for_each_entry(adev, &chip_node->func_list, node)
			if (hinic5_func_type(adev->hwdev) == TYPE_PF)
				detach_uld(adev, type);

		list_for_each_entry(adev, &chip_node->func_list, node)
			if (hinic5_func_type(adev->hwdev) == TYPE_PPF)
				detach_uld(adev, type);
	}

	uld_info = &hinic5_g_uld_info[type];
	memset(uld_info, 0, sizeof(struct hinic5_uld_info));
	mutex_unlock(&hinic5_g_uld_mutex);
	hinic5_lld_put();
}
EXPORT_SYMBOL(hinic5_unregister_uld);

int hinic5_attach_nic(struct hinic5_lld_dev *lld_dev)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev)
		return -EINVAL;

	adev = to_hinic5_adev(lld_dev);
	return attach_uld(adev, SERVICE_T_NIC, &hinic5_g_uld_info[SERVICE_T_NIC]);
}
EXPORT_SYMBOL(hinic5_attach_nic);

void hinic5_detach_nic(const struct hinic5_lld_dev *lld_dev)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev)
		return;

	adev = to_hinic5_adev(lld_dev);
	detach_uld(adev, SERVICE_T_NIC);
}
EXPORT_SYMBOL(hinic5_detach_nic);

int hinic5_attach_service(const struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev || type >= SERVICE_T_MAX)
		return -EINVAL;

	adev = to_hinic5_adev(lld_dev);
	if (!adev)
		return -EINVAL;

	return attach_uld(adev, type, &hinic5_g_uld_info[type]);
}
EXPORT_SYMBOL(hinic5_attach_service);

void hinic5_detach_service(const struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev || type >= SERVICE_T_MAX)
		return;

	adev = to_hinic5_adev(lld_dev);
	detach_uld(adev, type);
}
EXPORT_SYMBOL(hinic5_detach_service);

static void hinic5_sync_time_to_fmw(struct hinic5_adev *adev)
{
	struct timeval tv = {0};
	struct rtc_time rt_time = {0};
	u64 tv_msec;
	int err;

	do_gettimeofday(&tv);

	tv_msec = (u64)(tv.tv_sec * MSEC_PER_SEC + tv.tv_usec / USEC_PER_MSEC);
	err = hinic5_sync_time(adev->hwdev, tv_msec);
	if (err != 0) {
		sdk_err(adev->dev, "Synchronize UTC time to firmware failed, errno:%d.\n",
			err);
	} else {
		rtc_time_to_tm(tv.tv_sec, &rt_time);
		sdk_info(adev->dev, "Synchronize UTC time to firmware succeed. UTC time %d-%02d-%02d %02d:%02d:%02d.\n",
			 rt_time.tm_year + HINIC5_SYNC_YEAR_OFFSET,
			 rt_time.tm_mon + HINIC5_SYNC_MONTH_OFFSET,
			 rt_time.tm_mday, rt_time.tm_hour,
			 rt_time.tm_min, rt_time.tm_sec);
	}
}

static void send_uld_dev_event(struct hinic5_adev *adev,
			       struct hinic5_event_info *event)
{
	int type;

	for (type = SERVICE_T_NIC; type < SERVICE_T_MAX; type++) {
		if (test_and_set_bit((u32)type, &adev->state)) {
			sdk_warn(adev->dev, "Svc: 0x%x, event: 0x%x can't handler, %s is in detach\n",
				 event->service, event->type, s_uld_name[type]);
			continue;
		}

		if (hinic5_g_uld_info[type].event && adev->uld_dev[type])
			hinic5_g_uld_info[type].event(&adev->lld_dev,
					       adev->uld_dev[type], event);
		clear_bit((u32)type, &adev->state);
	}
}

static void send_event_to_dst_pf(struct hinic5_adev *adev, u16 func_id,
				 struct hinic5_event_info *event)
{
	struct hinic5_adev *des_dev = NULL;

	hinic5_lld_hold();
	list_for_each_entry(des_dev, &adev->chip_node->func_list, node) {
		if (adev->lld_state == HINIC5_IN_REMOVE)
			continue;

		if (hinic5_func_type(des_dev->hwdev) == TYPE_VF)
			continue;

		if (hinic5_global_func_id(des_dev->hwdev) == func_id) {
			send_uld_dev_event(des_dev, event);
			break;
		}
	}
	hinic5_lld_put();
}

static void send_event_to_all_pf(struct hinic5_adev *adev,
				 struct hinic5_event_info *event)
{
	struct hinic5_adev *des_adev = NULL;

	hinic5_lld_hold();
	list_for_each_entry(des_adev, &adev->chip_node->func_list, node) {
		if (adev->lld_state == HINIC5_IN_REMOVE)
			continue;

		if (hinic5_func_type(des_adev->hwdev) == TYPE_VF)
			continue;

		send_uld_dev_event(des_adev, event);
	}
	hinic5_lld_put();
}

static void hinic5_event_process(void *adapter, struct hinic5_event_info *event)
{
	struct hinic5_adev *adev = adapter;
	struct hinic5_fault_event *fault = (void *)event->event_data;
	u16 func_id;

	if ((event->service == EVENT_SRV_COMM && event->type == EVENT_COMM_FAULT) &&
	    fault->fault_level == FAULT_LEVEL_SERIOUS_FLR &&
	    fault->event.chip.func_id < hinic5_max_pf_num(adev->hwdev)) {
		func_id = fault->event.chip.func_id;
		send_event_to_dst_pf(adapter, func_id, event);
		return;
	}

	if (event->type == EVENT_COMM_MGMT_WATCHDOG)
		send_event_to_all_pf(adapter, event);
	else
		send_uld_dev_event(adapter, event);
}

static void uld_def_init(struct hinic5_adev *adev)
{
	int type;

	for (type = 0; type < SERVICE_T_MAX; type++) {
		atomic_set(&adev->uld_ref_cnt[type], 0);
		clear_bit(type, &adev->uld_state);
	}

	spin_lock_init(&adev->uld_lock);
}

#ifdef CONFIG_X86
/**
 * cfg_order_reg - when cpu model is haswell or broadwell, should configure dma
 * order register to zero
 * @adev: adev
 **/
static void cfg_order_reg(struct hinic5_adev *adev)
{
	u8 cpu_model[] = {0x3c, 0x3f, 0x45, 0x46, 0x3d, 0x47, 0x4f, 0x56};
	struct cpuinfo_x86 *cpuinfo = NULL;
	u32 i;

	if (hinic5_func_type(adev->hwdev) == TYPE_VF)
		return;

	cpuinfo = &cpu_data(0);
	for (i = 0; i < sizeof(cpu_model); i++) {
		if (cpu_model[i] == cpuinfo->x86_model)
			hinic5_set_pcie_order_cfg(adev->hwdev);
	}
}

#endif

int hinic5_set_vf_load_state(struct hinic5_lld_dev *lld_dev, bool vf_load_state)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev) {
		pr_err("lld_dev is null.\n");
		return -EINVAL;
	}

	adev = to_hinic5_adev(lld_dev);
	if (hinic5_func_type(adev->hwdev) == TYPE_VF)
		return 0;

	adev->disable_vf_load = !vf_load_state;
	sdk_info(adev->dev, "Current function %s vf load in host\n",
		 vf_load_state ? "enable" : "disable");

	return 0;
}
EXPORT_SYMBOL(hinic5_set_vf_load_state);

static void set_vf_load_state(struct hinic5_adev *adev)
{
	/* In bm mode, slave host will load vfs in default */
	if (IS_BMGW_SLAVE_HOST(((struct hinic5_hwdev *)adev->hwdev)) &&
	    hinic5_func_type(adev->hwdev) != TYPE_VF)
		hinic5_set_vf_load_state(&adev->lld_dev, false);

	if (!disable_attach) {
#ifndef __HIFC__
		if ((hinic5_func_type(adev->hwdev) != TYPE_VF) &&
		    hinic5_is_multi_bm(adev->hwdev)) {
			adev->bus_ops->virt_configure(adev, hinic5_func_max_vf(adev->hwdev));
		}
#endif
	}
}

#define HINIC5_CSR_BASIC_SIZE 0x1000
#define HINIC5_CSR_MGMT_SIZE  0x10000

static int hinic5_vpmd_proc_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err;
	u64 pfn, vma_size, bar_size, ofst, check_size;
	struct hinic5_adev *adev = NULL;

	if (!file || !vma || vma->vm_end < vma->vm_start)
		return -EINVAL;

	adev = (struct hinic5_adev *)PDE_DATA(file_inode(file));
	if (!adev)
		return -EINVAL;

	ofst = vma->vm_pgoff << PAGE_SHIFT;
	if (ofst == 0) {
		pfn = adev->cfg_base_phy >> PAGE_SHIFT;
		bar_size = adev->cfg_base_len;
	} else if (ofst == HINIC5_CSR_BASIC_SIZE) {
		pfn = adev->mgmt_base_phy >> PAGE_SHIFT;
		bar_size = adev->mgmt_base_len;
	} else if (ofst == HINIC5_CSR_BASIC_SIZE + HINIC5_CSR_MGMT_SIZE) {
		pfn = adev->db_base_phy >> PAGE_SHIFT;
		bar_size = adev->db_dwqe_len;
	} else {
		pr_err("invalid offset:0x%llx", ofst);
		return -EINVAL;
	}

	vma_size = vma->vm_end - vma->vm_start;
	/* bar_size align pagesize, check vma_size */
	check_size = ALIGN(bar_size, PAGE_SIZE);
	if (vma_size > check_size) {
		pr_err("invalid vma_size:0x%llx, check_size:0x%llx, bar_size:0x%llx",
		       vma_size, check_size, bar_size);
		return -EINVAL;
	}

	vm_flags_set(vma, VM_IO);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	err = remap_pfn_range(vma, vma->vm_start, (unsigned long)pfn,
			      (unsigned long)vma_size, vma->vm_page_prot);
	if (err != 0) {
		pr_err("mmap vpmd failed, err %d\n", err);
		return err;
	}

	return 0;
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops hinic5_vpmd_proc_fops = {
	.proc_open = NULL,
	.proc_mmap = hinic5_vpmd_proc_mmap,
	.proc_read = NULL,
	.proc_release = NULL,
};

#else
static const struct file_operations hinic5_vpmd_proc_fops = {
	.owner = THIS_MODULE,
	.open = NULL,
	.llseek = NULL,
	.mmap = hinic5_vpmd_proc_mmap,
	.read = NULL,
	.release = NULL,
};
#endif

static int hinic5_init_vpmd_proc(struct hinic5_adev *adev)
{
	strscpy(adev->vpmd_proc_name, dev_name(adev->dev), sizeof(adev->vpmd_proc_name));
	adev->vpmd_proc = proc_create_data(&adev->vpmd_proc_name[0], 0640, g_proc_dir,
					   &hinic5_vpmd_proc_fops, adev);
	if (!adev->vpmd_proc) {
		sdk_err(adev->dev, "init vpmd proc failed, vpmd_proc_name:%s.",
			adev->vpmd_proc_name);
		return -ENOMEM;
	}

	return 0;
}

static bool hinic5_need_ht_gpa(struct hinic5_hwdev *hwdev)
{
	if (COMM_SUPPORT_HT_GPA(hwdev))
		return true;
	return hinic5_func_type(hwdev) == TYPE_PPF;
}

int hinic5_func_init(struct hinic5_adev *adev)
{
	struct hinic5_init_para init_para = {0};
	bool hinic5_cqm_init_en = false;
	int err;

	uld_def_init(adev);

	init_para.adapter_hdl = adev;
	init_para.dev_hdl = adev->dev;
#ifdef __UEFI__
	init_para.busdev_hdl = adev->bus_dev;
#endif
	init_para.fers2_reg_base = adev->fers2_reg_base;
	init_para.cfg_reg_base = adev->cfg_reg_base;
	init_para.intr_reg_base = adev->intr_reg_base;
	init_para.mgmt_reg_base = adev->mgmt_reg_base;
	init_para.db_base = adev->db_base;
	init_para.db_base_phy = adev->db_base_phy;
	init_para.db_dwqe_len = adev->db_dwqe_len;
	init_para.hwdev = &adev->hwdev;
	init_para.chip_node = adev->chip_node;
	init_para.probe_fault_level = adev->probe_fault_level;

	err = hinic5_init_hwdev(&init_para);
	if (err != 0) {
		adev->hwdev = NULL;
		adev->probe_fault_level = init_para.probe_fault_level;
		sdk_err(adev->dev, "Failed to initialize hardware device\n");
		return -EFAULT;
	}

	if (COMM_SUPPORT_FAST_MSG((struct hinic5_hwdev *)adev->hwdev)) {
		err = hinic5_fast_msg_init(adev->hwdev);
		if (err != 0) {
			sdk_err(adev->dev, "Failed to fast msg\n");
			goto fast_msg_init_err;
		}
	}

	if (hinic5_need_ht_gpa(adev->hwdev)) {
		err = hinic5_ht_gpa_init(adev->hwdev);
		if (err != 0) {
			sdk_err(adev->dev, "Failed to init bank gpa\n");
			hinic5_ht_gpa_deinit(adev->hwdev);
			goto ht_gpa_init_err;
		}
	}

	err = hinic5_fw_update_init(adev->hwdev);
	if (err != 0) {
		sdk_err(adev->dev, "Failed to init firmware maintenance\n");
		goto fw_update_init_err;
	}

	hinic5_cqm_init_en = hinic5_need_init_stateful_default(adev->hwdev);
	if (hinic5_cqm_init_en) {
		err = hinic5_stateful_init(adev->hwdev);
		if (err != 0) {
			sdk_err(adev->dev, "Failed to init stateful\n");
			goto stateful_init_err;
		}
	}

	adev->lld_dev.dev = adev->dev;
	adev->lld_dev.hwdev = adev->hwdev;

	if (hinic5_func_type(adev->hwdev) != TYPE_VF)
		set_bit(HINIC5_FUNC_PERSENT, &adev->sriov_info.state);

	err = hinic5_event_register(adev->hwdev, adev, hinic5_event_process);
	if (err != 0) {
		sdk_err(adev->dev, "Failed to register callback for event, err = %d\n", err);
		goto event_register_err;
	}

	if (hinic5_func_type(adev->hwdev) != TYPE_VF)
		hinic5_sync_time_to_fmw(adev);

	/* dbgtool init */
	hinic5_lld_lock_chip_node();
	err = hinic5_nictool_k_init(adev->hwdev, adev->chip_node);
	if (err != 0) {
		hinic5_lld_unlock_chip_node();
		sdk_err(adev->dev, "Failed to initialize dbgtool\n");
		goto nictool_init_err;
	}
	list_add_tail(&adev->node, &adev->chip_node->func_list);
	hinic5_lld_unlock_chip_node();

	set_vf_load_state(adev);

	err = hinic5_init_vpmd_proc(adev);
	if (err != 0) {
		sdk_err(adev->dev, "Failed to init vpmd proc\n");
		goto init_vpmd_proc_err;
	}

	if (!disable_attach) {
		attach_ulds(adev);
#ifdef CONFIG_X86
		cfg_order_reg(adev);
#endif
	}

	return 0;

init_vpmd_proc_err:
	hinic5_lld_lock_chip_node();
	hinic5_nictool_k_uninit(adev->hwdev, adev->chip_node);
	hinic5_lld_unlock_chip_node();
nictool_init_err:
	hinic5_event_unregister(adev->hwdev);
event_register_err:
	if (hinic5_cqm_init_en)
		hinic5_stateful_deinit(adev->hwdev);
stateful_init_err:
	hinic5_fw_update_deinit(adev->hwdev);
fw_update_init_err:
	if (hinic5_need_ht_gpa(adev->hwdev))
		hinic5_ht_gpa_deinit(adev->hwdev);
ht_gpa_init_err:
	if (COMM_SUPPORT_FAST_MSG((struct hinic5_hwdev *)adev->hwdev))
		hinic5_fast_msg_deinit(adev->hwdev);
fast_msg_init_err:
	hinic5_free_hwdev(adev->hwdev);
	adev->hwdev = NULL;

	return err;
}

static void hinic5_deinit_vpmd_proc(struct hinic5_adev *adev)
{
	remove_proc_entry(adev->vpmd_proc_name, g_proc_dir);
	adev->vpmd_proc = NULL;
}

void hinic5_func_deinit(struct hinic5_adev *adev)
{
	/* When function deinit, disable mgmt initiative report events firstly,
	 * then flush mgmt work-queue.
	 */
	hinic5_disable_mgmt_msg_report(adev->hwdev);

	hinic5_flush_mgmt_workq(adev->hwdev);

	hinic5_lld_lock_chip_node();
	list_del(&adev->node);
	hinic5_lld_unlock_chip_node();

	detach_ulds(adev);

	hinic5_wait_lld_dev_unused(adev);

	hinic5_deinit_vpmd_proc(adev);

	hinic5_lld_lock_chip_node();
	hinic5_nictool_k_uninit(adev->hwdev, adev->chip_node);
	hinic5_lld_unlock_chip_node();

	hinic5_event_unregister(adev->hwdev);

	hinic5_free_stateful(adev->hwdev);

	hinic5_fw_update_deinit(adev->hwdev);

	if (hinic5_need_ht_gpa(adev->hwdev))
		hinic5_ht_gpa_deinit(adev->hwdev);

	if (COMM_SUPPORT_FAST_MSG((struct hinic5_hwdev *)adev->hwdev))
		hinic5_fast_msg_deinit(adev->hwdev);

	hinic5_free_hwdev(adev->hwdev);
	adev->hwdev = NULL;
}

void wait_sriov_cfg_complete(struct hinic5_adev *adev)
{
	struct hinic5_sriov_info *sriov_info = NULL;
	ulong end;

	sriov_info = &adev->sriov_info;
	clear_bit(HINIC5_FUNC_PERSENT, &sriov_info->state);
	usleep_range(9900, 10000); /* sleep 9900 us ~ 10000 us */

	end = jiffies + msecs_to_jiffies(HINIC5_WAIT_SRIOV_CFG_TIMEOUT);
	do {
		if (!test_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state) &&
		    !test_bit(HINIC5_SRIOV_DISABLE, &sriov_info->state))
			return;

		usleep_range(9900, 10000); /* sleep 9900 us ~ 10000 us */
	} while (time_before(jiffies, end));
}

bool hinic5_get_vf_service_load(struct hinic5_adev *adev, u16 service)
{
	struct hinic5_adev *pf_adev = NULL;

	if (!adev) {
		pr_err("adev is null.\n");
		return false;
	}

	pf_adev = hinic5_adev_get_pf_adev(adev);
	if (!pf_adev) {
		sdk_err(adev->dev, "pf_adev is null.\n");
		return false;
	}

	if (service >= SERVICE_T_MAX) {
		sdk_err(adev->dev, "service_type = %u state is error\n",
			service);
		return false;
	}

	return !pf_adev->disable_srv_load[service];
}

int hinic5_set_vf_service_load(struct hinic5_lld_dev *lld_dev, u16 service,
			       bool vf_srv_load)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev) {
		pr_err("lld_dev is null.\n");
		return -EINVAL;
	}

	adev = to_hinic5_adev(lld_dev);

	if (service >= SERVICE_T_MAX) {
		sdk_err(adev->dev, "service_type = %u state is error\n",
			service);
		return -EFAULT;
	}

	if (hinic5_func_type(adev->hwdev) == TYPE_VF)
		return 0;

	adev->disable_srv_load[service] = !vf_srv_load;
	sdk_info(adev->dev, "Current function %s vf load in host\n",
		 vf_srv_load ? "enable" : "disable");

	return 0;
}
EXPORT_SYMBOL(hinic5_set_vf_service_load);

int probe_func_param_init(struct hinic5_adev *adev)
{
	if (!adev)
		return -EFAULT;

	mutex_lock(&adev->adev_mutex);
	if (adev->lld_state >= HINIC5_PROBE_START) {
		sdk_warn(adev->dev, "Don not probe repeat\n");
		mutex_unlock(&adev->adev_mutex);
		return -EEXIST;
	}
	adev->lld_state = HINIC5_PROBE_START;
	mutex_unlock(&adev->adev_mutex);

	return 0;
}

static int hinic5_sdk_proc_init(void)
{
	g_proc_dir = proc_mkdir(HINIC5_PROC_DIR, NULL);
	if (!g_proc_dir)
		return -EPERM;
	return 0;
}

static void hinic5_sdk_proc_deinit(void)
{
	if (!g_proc_dir)
		return;

	proc_remove(g_proc_dir);
	g_proc_dir = NULL;
}

int hinic5_lld_init(void)
{
	int err;

	pr_info("%s - version %s\n", HINIC5_DRV_DESC, HINIC5_DRV_VERSION);
	memset(hinic5_g_uld_info, 0, sizeof(hinic5_g_uld_info));

	hinic5_lld_lock_init();
	hinic5_uld_lock_init();
	set_use_hinic5_vram_flag(use_hinic5_vram);

	if (use_hinic5_vram) {
		err = hisdk5_hinic5_vram_init();
		if (err != 0)
			return err;
	}

	err = hinic5_sdk_proc_init();
	if (err != 0) {
		pr_err("create vpmd dir failed\n");
		goto dir_create_err;
	}

	err = hinic5_module_pre_init();
	if (err != 0) {
		pr_err("Init custom failed\n");
		goto module_pre_init_err;
	}

	err = hinic5_register_driver();
	if (err != 0)
		goto register_driver_err;

	return 0;

register_driver_err:
	hinic5_module_post_exit();

module_pre_init_err:
	hinic5_sdk_proc_deinit();

dir_create_err:
	if (use_hinic5_vram)
		hisdk5_hinic5_vram_deinit();

	return err;
}

void hinic5_lld_exit(void)
{
	if (use_hinic5_vram)
		hisdk5_hinic5_vram_deinit();

	hinic5_unregister_driver();
	hinic5_module_post_exit();
	hinic5_sdk_proc_deinit();
}

static bool is_uld_with_cleanup(enum hinic5_service_type type)
{
	const enum hinic5_service_type uld_with_cleanup[] = {
		SERVICE_T_IPSEC,
	};
	u32 uld_with_cleanup_size = sizeof(uld_with_cleanup) / sizeof(enum hinic5_service_type);
	u32 i;

	for (i = 0; i < uld_with_cleanup_size; i++) {
		if (uld_with_cleanup[i] == type)
			return true;
	}
	return false;
}

void hinic5_uld_cleanup_before_unregister(enum hinic5_service_type type, void (*cleanup)(void *))
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;
	struct list_head *chip_list = NULL;

	if (!is_uld_with_cleanup(type)) {
		pr_info("this service does not support cleanup.\n");
		return;
	}

	if (!cleanup) {
		pr_info("this service no need to cleanup.\n");
		return;
	}

	hinic5_lld_hold();
	mutex_lock(&hinic5_g_uld_mutex);
	chip_list = get_hinic5_chip_list();
	list_for_each_entry(chip_node, chip_list, node) {
		/* detach vf first */
		list_for_each_entry(adev, &chip_node->func_list, node)
			if (hinic5_func_type(adev->hwdev) == TYPE_VF)
				cleanup(adev->uld_dev[type]);

		list_for_each_entry(adev, &chip_node->func_list, node)
			if (hinic5_func_type(adev->hwdev) == TYPE_PF)
				cleanup(adev->uld_dev[type]);

		list_for_each_entry(adev, &chip_node->func_list, node)
			if (hinic5_func_type(adev->hwdev) == TYPE_PPF)
				cleanup(adev->uld_dev[type]);
	}
	mutex_unlock(&hinic5_g_uld_mutex);
	hinic5_lld_put();
}
EXPORT_SYMBOL(hinic5_uld_cleanup_before_unregister);

int hinic5_get_vf_num(struct hinic5_lld_dev *lld_dev)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev) {
		pr_err("lld_dev is null.\n");
		return -EINVAL;
	}

	adev = to_hinic5_adev(lld_dev);
	return hinic5_adev_get_vf_num(adev);
}
EXPORT_SYMBOL(hinic5_get_vf_num);

int hinic5_get_chip_node_id(struct hinic5_lld_dev *lld_dev, u64 *chip_node_id)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev) {
		pr_err("lld_dev is null.\n");
		return -EINVAL;
	}

	adev = to_hinic5_adev(lld_dev);
	*chip_node_id = adev->chip_node->id;

	return 0;
}
EXPORT_SYMBOL(hinic5_get_chip_node_id);
