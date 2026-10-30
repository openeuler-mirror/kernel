// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

/* sdk include */
#include "hinic3_crm.h"
#include "hinic3_hw.h"
#include "hinic3_cqm.h"
#include "hinic3_lld.h"
#include "hinic3_mt.h"

#include "bifur_common.h"
#include "bifur_vf_mgr.h"
#include "bifur_pfile.h"
#include "bifur_event.h"
#include "bifur_main.h"
#define BIFUR_DRV_DESC "BIFUR Offload Driver"
#define BIFUR_DRV_VERSION ""

#define BIFUR_WAIT_TIMES 1000
#define BIFUR_REMOVE_TIMESTEP 10
#define BIFUR_KWRITE_BUF_SIZE 20
#define BIFUR_DPDK_KDRIVER_TYPE 3

#define BIFUR_SET_ENABLE 0xc0
#define BIFUR_GET_ENABLE 0xc1

static char *g_bifur_dpdk_kdriver = "vfio-pci";
module_param(g_bifur_dpdk_kdriver, charp, 0644);
MODULE_PARM_DESC(g_bifur_dpdk_kdriver,
		 "for dpdk kernel driver module (default:\"igb_uio\", options:\"vfio-pci\", \"uio_pci_generic\")");
static const char *g_bifur_dpdk_kdriver_all[BIFUR_DPDK_KDRIVER_TYPE] = {
	"igb_uio",
	"vfio-pci",
	"uio_pci_generic"
};

/* bifur global manager struct */
static struct bifur_adapter *g_bifur_adapter;

static void bifur_destroy_dev(struct bifur_lld_dev *bifur_dev);
static void wait_bifur_dev_unused(struct bifur_lld_dev *bifur_dev);

struct bifur_adapter *bifur_get_adp(void)
{
	return g_bifur_adapter;
}

void bifur_dev_hold(struct bifur_lld_dev *bifur_dev)
{
	atomic_inc(&bifur_dev->bifur_dev.bifur_dev_ref);
}

void bifur_dev_put(struct bifur_lld_dev *bifur_dev)
{
	atomic_dec(&bifur_dev->bifur_dev.bifur_dev_ref);
}

void bifur_dev_list_lock(void)
{
	mutex_lock(&g_bifur_adapter->bifur_dev_mutex);
}

void bifur_dev_list_unlock(void)
{
	mutex_unlock(&g_bifur_adapter->bifur_dev_mutex);
}

static int bifur_alloc_adapter(void)
{
	/* alloc driver global adapter struct */
	if (!g_bifur_adapter) {
		g_bifur_adapter = kzalloc(sizeof(*g_bifur_adapter), GFP_KERNEL);
		if (!g_bifur_adapter)
			return -ENOMEM;
	}

	/* init global adapter */
	INIT_LIST_HEAD(&g_bifur_adapter->lld_dev_head);
	mutex_init(&g_bifur_adapter->bifur_dev_mutex);

	g_bifur_adapter->event_workq = create_singlethread_workqueue("bifur_eventq");
	if (!g_bifur_adapter->event_workq) {
		kfree(g_bifur_adapter);
		g_bifur_adapter = NULL;
		pr_err("Create bifur event_workq fail");
		return -ENOMEM;
	}

	pr_info("Alloc bifur adapter success\n");
	return 0;
}

static void bifur_free_adapter(void)
{
	destroy_workqueue(g_bifur_adapter->event_workq);

	kfree(g_bifur_adapter);
	g_bifur_adapter = NULL;
	pr_info("Free adapter success\n");
}

static bool bifur_check_dpdk_kdriver(void)
{
	bool is_valid_driver = false;
	int i;

	for (i = 0; i < BIFUR_DPDK_KDRIVER_TYPE; ++i) {
		if (!strcmp(g_bifur_dpdk_kdriver, g_bifur_dpdk_kdriver_all[i]))
			is_valid_driver = true;
	}

	return is_valid_driver;
}

static int bifur_open_and_write_file(const char *file_path, const char *buf, int open_flags,
									 umode_t open_mode)
{
	struct file *fp = NULL;
	loff_t f_pos = 0;
	int err = 0;

	fp = filp_open(file_path, open_flags, open_mode);
	if (IS_ERR(fp)) {
		pr_err("Open %s failed, err %ld\n", file_path, PTR_ERR(fp));
		return -ENOENT;
	}

	err = kernel_write(fp, buf, strlen(buf), &f_pos);
	if (err < 0) {
		pr_err("Write %s to file %s failed, err %d\n", buf, file_path, err);
		(void)filp_close(fp, NULL);
		return err;
	}

	(void)filp_close(fp, NULL);

	return 0;
}

static int bifur_enable_disable_vfs(struct bifur_lld_dev *bifur_dev, u16 num_vfs)
{
	int err = 0;
	char file_path[BIFUR_FILE_PATH_SIZE] = {};
	char buf[BIFUR_KWRITE_BUF_SIZE] = {};
	struct pci_dev *pdev = bifur_dev->lld_dev->pdev;

	/* write vf num to /sys/bus/pci/devices/%s/sriov_numvfs */
	err = snprintf(file_path, BIFUR_FILE_PATH_SIZE,
				   "/sys/bus/pci/devices/%s/sriov_numvfs", pci_name(pdev));
	if (err == -1) {
		pr_err("Snprintf bifur pci dev sriov_numvfs file path, err %d!\n", err);
		return err;
	}

	err = snprintf(buf, BIFUR_KWRITE_BUF_SIZE, "%u", num_vfs);
	if (err == -1) {
		pr_err("Snprintf bifur numvfs str, err %d!\n", err);
		return err;
	}

	err = bifur_open_and_write_file(file_path, buf, O_WRONLY | O_TRUNC, 0);
	if (err != 0) {
		pr_info("Enable vf of pf failed, dbdf:0x%s, sriov_nums:%u\n",
			pci_name(pdev), num_vfs);
		return err;
	}

	pr_info("Enable vf of pf success, dbdf:0x%s, sriov_nums:%u\n", pci_name(pdev), num_vfs);

	return 0;
}

int bifur_enable_disable_vf_all(bool enable)
{
	int err = 0;
	int num_vfs = enable ? BIFUR_VF_NUM : 0;
	struct bifur_lld_dev *bifur_dev = NULL;
	struct bifur_lld_dev *tmp_dev = NULL;
	struct bifur_adapter *adp = bifur_get_adp();
	struct list_head *head = &adp->lld_dev_head;

	list_for_each_entry_safe(bifur_dev, tmp_dev, head, list) {
		if (bifur_dev->pf_type != BIFUR_RESOURCE_PF)
			continue;

		bifur_dev_hold(bifur_dev);
		err = bifur_enable_disable_vfs(bifur_dev, num_vfs);
		bifur_dev_put(bifur_dev);
		if (err)
			return err;
	}

	return 0;
}

static int bifur_one_unbind_driver(u32 dbdf, const char *driver)
{
	int err = 0;
	char file_path[BIFUR_FILE_PATH_SIZE] = {};
	char buf[BIFUR_KWRITE_BUF_SIZE] = {};

	/* write pci dbdf to /sys/bus/pci/drivers/%s/unbind */
	err = snprintf(file_path, BIFUR_FILE_PATH_SIZE,
		       "/sys/bus/pci/drivers/%s/unbind", driver);
	if (err == -1) {
		pr_err("Snprintf bifur driver unbind file path, err %d!\n", err);
		return err;
	}

	err = snprintf(buf, BIFUR_KWRITE_BUF_SIZE, "%.4x:%.2x:%.2x.%x",
		       PCI_DBDF_DOM(dbdf), PCI_DBDF_BUS(dbdf),
		       PCI_DBDF_DEVID(dbdf), PCI_DBDF_FUNCTION(dbdf));
	if (err == -1) {
		pr_err("Snprintf bifur pci dev dbdf str, err %d!\n", err);
		return err;
	}

	err = bifur_open_and_write_file(file_path, buf, O_WRONLY | O_APPEND, 0);
	if (err != 0) {
		pr_info("Unbind vf from driver %s failed\n", driver);
		return err;
	}

	pr_info("Unbind vf from driver %s success\n", driver);

	return 0;
}

static int bifur_one_bind_dpdk(u32 dbdf)
{
	int err = 0;
	char file_path[BIFUR_FILE_PATH_SIZE] = {};
	char buf[BIFUR_KWRITE_BUF_SIZE] = {};
	const char *kernel_driver = "hisdk3";

	bifur_one_unbind_driver(dbdf, kernel_driver);

	err = snprintf(file_path, BIFUR_FILE_PATH_SIZE,
		       "/sys/bus/pci/devices/%.4x:%.2x:%.2x.%x/driver_override",
		       PCI_DBDF_DOM(dbdf), PCI_DBDF_BUS(dbdf),
		       PCI_DBDF_DEVID(dbdf), PCI_DBDF_FUNCTION(dbdf));
	if (err == -1) {
		pr_err("Snprintf bifur pci dev driver_override file path, err %d!\n", err);
		return err;
	}

	(void)strscpy(buf, g_bifur_dpdk_kdriver, sizeof(buf));

	err = bifur_open_and_write_file(file_path, buf, O_WRONLY | O_TRUNC, 0);
	if (err != 0)
		return err;

	err = snprintf(file_path, BIFUR_FILE_PATH_SIZE,
				   "/sys/bus/pci/drivers/%s/bind", g_bifur_dpdk_kdriver);
	if (err == -1) {
		pr_err("Snprintf bifur dpdk driver bind file path, err %d!\n", err);
		return err;
	}

	err = snprintf(buf, BIFUR_KWRITE_BUF_SIZE, "%.4x:%.2x:%.2x.%x",
		       PCI_DBDF_DOM(dbdf), PCI_DBDF_BUS(dbdf),
		       PCI_DBDF_DEVID(dbdf), PCI_DBDF_FUNCTION(dbdf));
	if (err == -1) {
		pr_err("Snprintf bifur pci dev dbdf str, err %d!\n", err);
		return err;
	}

	err = bifur_open_and_write_file(file_path, buf, O_WRONLY | O_APPEND, 0);
	if (err != 0)
		return err;

	return 0;
}

static int bifur_bind_unbind_dpdk(struct bifur_lld_dev *bifur_dev, bool enable)
{
	int err = 0;
	u32 dbdf = 0;
	int i;

	for (i = 0; i < bifur_dev->vf_mgr->vf_sum; ++i) {
		dbdf = bifur_dev->vf_mgr->vf_info[i].vf_dbdf;
		if (enable)
			err = bifur_one_bind_dpdk(dbdf);
		else
			err = bifur_one_unbind_driver(dbdf, g_bifur_dpdk_kdriver);
		if (err) {
			pr_err("Bind/Unbind failed for vf %08x\n", dbdf);
			return err;
		}
	}

	return 0;
}

static int bifur_bind_unbind_dpdk_all(bool enable)
{
	int err = 0;
	struct bifur_lld_dev *bifur_dev = NULL;
	struct bifur_lld_dev *tmp_dev = NULL;
	struct bifur_adapter *adp = bifur_get_adp();
	struct list_head *head = &adp->lld_dev_head;

	list_for_each_entry_safe(bifur_dev, tmp_dev, head, list) {
		if (bifur_dev->pf_type != BIFUR_RESOURCE_PF)
			continue;

		bifur_dev_hold(bifur_dev);
		err = bifur_bind_unbind_dpdk(bifur_dev, enable);
		bifur_dev_put(bifur_dev);
		if (err)
			return err;
	}

	return 0;
}

static int bifur_probe_vf(struct hinic3_lld_dev *lld_dev)
{
	struct bifur_lld_dev *bifur_dev = NULL;
	struct bifur_vf_mgr *vf_mgr = NULL;
	struct bifur_vf_info *vf_info = NULL;
	u32 vf_dbdf;
	int ret;

	bifur_dev = bifur_get_resource_dev();
	if (!bifur_dev)
		return -ENODEV;

	vf_mgr = bifur_dev->vf_mgr;
	vf_dbdf = PCI_DBDF(pci_domain_nr(lld_dev->pdev->bus), lld_dev->pdev->bus->number,
			   PCI_DBDF_DEVID(lld_dev->pdev->devfn),
			   PCI_DBDF_FUNCTION(lld_dev->pdev->devfn));
	if (vf_mgr->vf_sum >= BIFUR_VF_NUM) {
		bifur_dev_put(bifur_dev);
		BIFUR_DEV_ERR(lld_dev, "current_vf_sum(%u) >= BIFUR_VF_NUM(%u)\n",
			      vf_mgr->vf_sum, BIFUR_VF_NUM);
		return -ENOMEM;
	}

	mutex_lock(&bifur_dev->vf_mgr->vf_mgr_mutex);
	vf_info = &vf_mgr->vf_info[vf_mgr->vf_sum];
	vf_mgr->vf_sum++;
	vf_info->vf_dbdf = vf_dbdf;
	vf_info->glb_func_id = hinic3_global_func_id(lld_dev->hwdev);
	vf_info->in_use = 0;
	vf_info->vf_mgr = vf_mgr;
	ret = snprintf(vf_info->name, (size_t)BIFURNAMSIZ, "bifur%04x", vf_dbdf);
	if (ret < 0) {
		mutex_unlock(&bifur_dev->vf_mgr->vf_mgr_mutex);
		BIFUR_DEV_ERR(lld_dev, "set name failed, ret(%d)\n", ret);
		bifur_dev_put(bifur_dev);
		return ret;
	}
	bifur_vf_cdev_init(vf_info);
	mutex_unlock(&bifur_dev->vf_mgr->vf_mgr_mutex);

	bifur_dev_put(bifur_dev);

	return 0;
}

static int bifur_remove_vf(struct bifur_lld_dev *bifur_dev)
{
	struct bifur_vf_info *vf_info = NULL;
	struct bifur_vf_mgr *vf_mgr = NULL;
	int i;

	if (!bifur_dev)
		return -ENODEV;
	vf_mgr = bifur_dev->vf_mgr;

	mutex_lock(&vf_mgr->vf_mgr_mutex);
	for (i = 0; i < vf_mgr->vf_sum; ++i) {
		vf_info = &vf_mgr->vf_info[i];
		bifur_vf_cdev_uninit(vf_info);
	}
	mutex_unlock(&vf_mgr->vf_mgr_mutex);
	return 0;
}

static int bifur_probe(struct hinic3_lld_dev *lld_dev, void **uld_dev, char *uld_dev_name)
{
	struct bifur_lld_dev *bifur_dev = NULL;
	struct bifur_adapter *adp = bifur_get_adp();
	int err = 0;

	if (!uld_dev || !lld_dev || !lld_dev->pdev || !lld_dev->hwdev) {
		pr_err("Bifur probe failed for invalid param, lld_dev or uld_dev\n");
		return -EINVAL;
	}

	if (hinic3_func_type(lld_dev->hwdev) == TYPE_VF) {
		*uld_dev = NULL;
		if (hinic3_support_bifur(lld_dev->hwdev, NULL)) {
			err = bifur_probe_vf(lld_dev);
			return err;
		}
		return 0;
	}

	bifur_dev = kzalloc(sizeof(*bifur_dev), GFP_KERNEL);
	if (!bifur_dev) {
		BIFUR_DEV_ERR(lld_dev, "Alloc bifur lld dev failed\n");
		return -ENOMEM;
	}

	/* init bifur dev */
	bifur_dev->lld_dev = lld_dev;

	if (hinic3_support_bifur(lld_dev->hwdev, NULL)) {
		if (lld_dev->pdev->subsystem_device == BIFUR_RESOURCE_PF_SSID) {
			bifur_dev->pf_type = BIFUR_RESOURCE_PF;
			err = bifur_alloc_vf_mgr(bifur_dev);
			if (err) {
				kfree(bifur_dev);
				bifur_dev = NULL;
				return err;
			}
		} else {
			bifur_dev->pf_type = BIFUR_SHARED_PF;
		}
	} else {
		bifur_dev->pf_type = BIFUR_EXCLUSIVE_PF;
	}
	pr_info("bifur_dev->pf_type: %d\n", bifur_dev->pf_type);

	INIT_WORK(&bifur_dev->netdev_link, bifur_netdev_event);
	bifur_dev->dbdf = PCI_DBDF(pci_domain_nr(lld_dev->pdev->bus), lld_dev->pdev->bus->number,
				   PCI_DBDF_DEVID(lld_dev->pdev->devfn),
				   PCI_DBDF_FUNCTION(lld_dev->pdev->devfn));

	atomic_set(&bifur_dev->bifur_dev.bifur_dev_ref, 0);
	bifur_dev->bifur_dev.has_created = true;

	bifur_dev_list_lock();
	list_add_tail(&bifur_dev->list, &adp->lld_dev_head);
	bifur_dev_list_unlock();

	*uld_dev = bifur_dev;

	BIFUR_DEV_INFO(lld_dev, "bifur driver probe\n");

	return 0;
}

static void bifur_remove(struct hinic3_lld_dev *lld_dev, void *uld_dev)
{
	struct bifur_lld_dev *bifur_dev = (struct bifur_lld_dev *)uld_dev;

	if (!bifur_dev)
		return;

	if (bifur_dev->pf_type == BIFUR_RESOURCE_PF) {
		(void)bifur_remove_vf(bifur_dev);
		bifur_free_vf_mgr(bifur_dev);
	}

	/* delete bifur device */
	bifur_dev_list_lock();
	list_del(&bifur_dev->list);
	bifur_dev_list_unlock();

	(void)cancel_work_sync(&bifur_dev->netdev_link);
	wait_bifur_dev_unused(bifur_dev);

	bifur_destroy_dev(bifur_dev);

	kfree(bifur_dev);
	bifur_dev = NULL;

	BIFUR_DEV_INFO(lld_dev, "bifur driver remove\n");
}

static int get_bifur_drv_version(struct drv_version_info *ver_info, u32 *out_size)
{
	int err;

	if (*out_size != sizeof(*ver_info)) {
		pr_err("Unexpected out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(*ver_info));
		return -EINVAL;
	}

	err = snprintf(ver_info->ver, sizeof(ver_info->ver), "%s",
			BIFUR_DRV_VERSION);
	if (err == -1) {
		pr_err("Snprintf bifur version err\n");
		return -EFAULT;
	}

	return 0;
}

static int bifur_enable_vfs(u8 bond_bifur_en)
{
	int err;

	err = bifur_enable_disable_vf_all(true);
	if (err) {
		pr_err("Enable bifur vf failed. err(%d)\n", err);
		return err;
	}

	err = bifur_bind_unbind_dpdk_all(true);
	if (err) {
		(void)bifur_enable_disable_vf_all(false);
		pr_err("Bind bifur vf to dpdk failed. err(%d)\n", err);
		return err;
	}

	bifur_set_bond_enable(bond_bifur_en);
	return 0;
}

static int bifur_disable_vfs(void)
{
	int err;

	bifur_set_bond_enable(BIFUR_DISABLED);

	err = bifur_enable_disable_vf_all(false);
	if (err) {
		pr_err("Disable bifur vf failed. err(%d)\n", err);
		return err;
	}
	return 0;
}

static int bifur_set_vfs_enable_state(struct bifur_adapter *adp, int set_enable,
				      int *out_enable, u32 *out_size)
{
	int err;
	u8 bond_bifur_en;

	if (set_enable != BIFUR_ENABLED && set_enable != BIFUR_DISABLED) {
		pr_err("Input params invalid. set_enable(%d)\n", set_enable);
		return -EINVAL;
	}

	if (*out_size != sizeof(*out_enable)) {
		pr_err("Unexpected out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(*out_enable));
		return -EINVAL;
	}

	bifur_dev_list_lock();
	if ((u8)set_enable == adp->bifur_enabled) {
		*out_enable = adp->bifur_enabled;
		bifur_dev_list_unlock();
		pr_info("Bifur enabled status has been set. set_enable(%d)\n", set_enable);
		return 0;
	}
	bond_bifur_en = adp->bond_bifur_enabled;
	adp->bifur_enabled = set_enable;
	bifur_dev_list_unlock();

	if (set_enable == BIFUR_ENABLED)
		err = bifur_enable_vfs(bond_bifur_en);
	else
		err = bifur_disable_vfs();

	bifur_dev_list_lock();
	if (err != 0)
		adp->bifur_enabled = !set_enable;
	*out_enable = adp->bifur_enabled;
	bifur_dev_list_unlock();

	return err;
}

static int bifur_get_bifur_enabled(struct bifur_adapter *adp, int *enabled_status, u32 *out_size)
{
	if (*out_size != sizeof(*enabled_status)) {
		pr_err("Unexpected out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(*enabled_status));
		return -EINVAL;
	}

	bifur_dev_list_lock();
	*enabled_status = adp->bifur_enabled;
	bifur_dev_list_unlock();
	return 0;
}

static int bifur_ioctl(void *uld_dev, u32 cmd, const void *buf_in, u32 in_size,
		       void *buf_out, u32 *out_size)
{
	struct bifur_adapter *adp = bifur_get_adp();
	struct bifur_lld_dev *bifur_dev = (struct bifur_lld_dev *)uld_dev;

	if (!uld_dev || !out_size || !buf_out) {
		pr_err("[BIFUR] %s: Input params is null. out_size(%d), buf_out(%d)\n",
		       __func__, (int)(!out_size), (int)(!buf_out));
		return -EINVAL;
	}

	if (!hinic3_support_bifur(bifur_dev->lld_dev->hwdev, NULL)) {
		pr_err("[BIFUR] %s: %s Not support bifurcation\n", __func__,
		       pci_name(bifur_dev->lld_dev->pdev));
		return -EINVAL;
	}

	if (cmd == GET_DRV_VERSION)
		return get_bifur_drv_version((struct drv_version_info *)buf_out, out_size);

	if (cmd == BIFUR_SET_ENABLE)
		return bifur_set_vfs_enable_state(adp, *(int *)buf_in, (int *)buf_out, out_size);
	else if (cmd == BIFUR_GET_ENABLE)
		return bifur_get_bifur_enabled(adp, (int *)buf_out, out_size);

	pr_err("Not support cmd %u for bifur\n", cmd);
	return 0;
}

static struct hinic3_uld_info bifur_uld_info = {
	.probe = bifur_probe,
	.remove = bifur_remove,
	.suspend = NULL,
	.resume = NULL,
	.ioctl = bifur_ioctl,
};

static __init int hibifur_init(void)
{
	int err = 0;

	pr_info("%s - version %s\n", BIFUR_DRV_DESC,
		BIFUR_DRV_VERSION);

	if (!bifur_check_dpdk_kdriver()) {
		pr_err("Invalid dpdk kernel driver type: %s\n", g_bifur_dpdk_kdriver);
		return -EINVAL;
	}

	err = bifur_alloc_adapter();
	if (err != 0)
		return -ENOMEM;

	err = hinic3_register_uld(SERVICE_T_BIFUR, &bifur_uld_info);
	if (err != 0) {
		pr_err("Register bifur uld failed\n");
		goto register_uld_err;
	}

	err = bifur_global_dev_init();
	if (err) {
		pr_err("Register bifur global cdev failed\n");
		goto global_dev_init_err;
	}

	err = bifur_register_net_event();
	if (err) {
		pr_err("Register bifur global cdev failed\n");
		goto register_event_err;
	}

	err = bifur_bond_init();
	if (err != 0) {
		pr_err("Bifur bond status init failed\n");
		goto bond_init_err;
	}

	return 0;

bond_init_err:
	bifur_unregister_net_event();
register_event_err:
	bifur_global_dev_uninit();
global_dev_init_err:
	hinic3_unregister_uld(SERVICE_T_BIFUR);
register_uld_err:
	bifur_free_adapter();
	return err;
}

static __exit void hibifur_exit(void)
{
	struct bifur_adapter *adp = bifur_get_adp();
	u8 bifur_enabled = BIFUR_DISABLED;

	bifur_bond_exit();
	bifur_unregister_net_event();
	bifur_global_dev_uninit();

	bifur_dev_list_lock();
	if (adp->bifur_enabled) {
		bifur_enabled = adp->bifur_enabled;
		adp->bifur_enabled = BIFUR_DISABLED;
	}
	bifur_dev_list_unlock();

	if (bifur_enabled) {
		(void)bifur_bind_unbind_dpdk_all(false);
		(void)bifur_enable_disable_vf_all(false);
	}

	hinic3_unregister_uld(SERVICE_T_BIFUR);
	bifur_free_adapter();

	pr_info("%s exit\n", BIFUR_DRV_DESC);
}

struct bifur_lld_dev *bifur_get_resource_dev(void)
{
	struct bifur_lld_dev *bifur_dev = NULL;
	struct bifur_lld_dev *tmp_dev = NULL;
	struct bifur_adapter *adp = bifur_get_adp();
	struct list_head *head = &adp->lld_dev_head;

	bifur_dev_list_lock();

	/* found the bifur_lld_dev of resource pf */
	list_for_each_entry_safe(bifur_dev, tmp_dev, head, list) {
		if (bifur_dev->pf_type == BIFUR_RESOURCE_PF) {
			bifur_dev_hold(bifur_dev);
			bifur_dev_list_unlock();
			pr_info("Find resource pf DBDF 0x%08x\n", bifur_dev->dbdf);
			return bifur_dev;
		}
	}

	bifur_dev_list_unlock();

	pr_err("Can't find resource pf\n");
	return NULL;
}

struct bifur_lld_dev *bifur_get_shared_dev_by_dbdf(u32 dbdf)
{
	struct bifur_lld_dev *bifur_dev = NULL;
	struct bifur_lld_dev *tmp_dev = NULL;
	struct bifur_adapter *adp = bifur_get_adp();
	struct list_head *head = &adp->lld_dev_head;

	bifur_dev_list_lock();

	 /* found the bifur_lld_dev of shared pf */
	list_for_each_entry_safe(bifur_dev, tmp_dev, head, list) {
		if (bifur_dev->pf_type == BIFUR_SHARED_PF && dbdf == bifur_dev->dbdf) {
			bifur_dev_hold(bifur_dev);
			bifur_dev_list_unlock();
			pr_info("Find shared pf DBDF 0x%08x\n", bifur_dev->dbdf);
			return bifur_dev;
		}
	}

	bifur_dev_list_unlock();

	pr_err("Can't find shared pf 0x%x\n", dbdf);
	return NULL;
}

static void wait_bifur_dev_unused(struct bifur_lld_dev *bifur_dev)
{
	int i;

	for (i = 0; i < BIFUR_WAIT_TIMES; i++) {
		if (!atomic_read(&bifur_dev->bifur_dev.bifur_dev_ref))
			break;

		msleep(BIFUR_REMOVE_TIMESTEP);
	}

	if (i == BIFUR_WAIT_TIMES) {
		BIFUR_DEV_WARN(bifur_dev->lld_dev,
			       "destroy BIFUR device failed, bifur_dev_ref(%d) can not be 0 after %d ms\n",
			       atomic_read(&bifur_dev->bifur_dev.bifur_dev_ref),
			       (BIFUR_WAIT_TIMES * BIFUR_REMOVE_TIMESTEP));
	}
}

static void bifur_destroy_dev(struct bifur_lld_dev *bifur_dev)
{
	if (!bifur_dev->bifur_dev.has_created)
		return;

	bifur_dev->bifur_dev.has_created = false;

	BIFUR_DEV_INFO(bifur_dev->lld_dev, "Destroy BIFUR device success\n");
}

module_init(hibifur_init);
module_exit(hibifur_exit);

MODULE_AUTHOR("Huawei Technologies CO., Ltd");
MODULE_DESCRIPTION(BIFUR_DRV_DESC);
MODULE_VERSION(BIFUR_DRV_VERSION);
MODULE_LICENSE("GPL");
