// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Huawei Technologies Co., Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <net/addrconf.h>
#include <linux/kernel.h>
#include <linux/pci.h>
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

#include "ossl_knl.h"
#include "hinic3_mt.h"
#include "hinic3_common.h"
#include "hinic3_crm.h"
#include "hinic3_pci_id_tbl.h"
#include "hinic3_sriov.h"
#include "hinic3_dev_mgmt.h"
#include "hinic3_nictool.h"
#include "hinic3_hw.h"
#include "hinic3_lld.h"

#include "hinic3_profile.h"
#include "hinic3_hwdev.h"
#include "hinic3_prof_adap.h"
#include "comm_msg_intf.h"

static bool disable_vf_load;
module_param(disable_vf_load, bool, 0444);
MODULE_PARM_DESC(disable_vf_load,
		 "Disable virtual functions probe or not - default is false");

static bool disable_attach;
module_param(disable_attach, bool, 0444);
MODULE_PARM_DESC(disable_attach, "disable_attach or not - default is false");

#define HINIC3_WAIT_SRIOV_CFG_TIMEOUT	15000

MODULE_AUTHOR("Huawei Technologies CO., Ltd");
MODULE_DESCRIPTION(HINIC3_DRV_DESC);
MODULE_VERSION(HINIC3_DRV_VERSION);
MODULE_LICENSE("GPL");

#if !(defined(HAVE_SRIOV_CONFIGURE) || defined(HAVE_RHEL6_SRIOV_CONFIGURE))
static DEVICE_ATTR(sriov_numvfs, 0664,
			hinic3_sriov_numvfs_show, hinic3_sriov_numvfs_store);
static DEVICE_ATTR(sriov_totalvfs, 0444,
			hinic3_sriov_totalvfs_show, NULL);
#endif /* !(HAVE_SRIOV_CONFIGURE || HAVE_RHEL6_SRIOV_CONFIGURE) */

static struct attribute *hinic3_attributes[] = {
#if !(defined(HAVE_SRIOV_CONFIGURE) || defined(HAVE_RHEL6_SRIOV_CONFIGURE))
	&dev_attr_sriov_numvfs.attr,
	&dev_attr_sriov_totalvfs.attr,
#endif /* !(HAVE_SRIOV_CONFIGURE || HAVE_RHEL6_SRIOV_CONFIGURE) */
	NULL
};

static const struct attribute_group hinic3_attr_group = {
	.attrs		= hinic3_attributes,
};

struct hinic3_uld_info g_uld_info[SERVICE_T_MAX] = { {0} };

#define HINIC3_EVENT_PROCESS_TIMEOUT	10000
struct mutex		g_uld_mutex;

void hinic3_uld_lock_init(void)
{
	mutex_init(&g_uld_mutex);
}

static const char *s_uld_name[SERVICE_T_MAX] = {
	"nic", "ovs", "roce", "toe", "ioe",
	"fc", "vbs", "ipsec", "virtio", "migrate", "ppa", "custom"};

const char **hinic3_get_uld_names(void)
{
	return s_uld_name;
}

static int attach_uld(struct hinic3_pcidev *dev, enum hinic3_service_type type,
		      const struct hinic3_uld_info *uld_info)
{
	void *uld_dev = NULL;
	int err;

	mutex_lock(&dev->pdev_mutex);

	if (dev->uld_dev[type]) {
		sdk_err(&dev->pcidev->dev,
			"%s driver has attached to pcie device\n",
			s_uld_name[type]);
		err = 0;
		goto out_unlock;
	}

	atomic_set(&dev->uld_ref_cnt[type], 0);

	err = uld_info->probe(&dev->lld_dev, &uld_dev, dev->uld_dev_name[type]);
	if (err) {
		sdk_err(&dev->pcidev->dev,
			"Failed to add object for %s driver to pcie device\n",
			s_uld_name[type]);
		goto probe_failed;
	}

	dev->uld_dev[type] = uld_dev;
	set_bit(type, &dev->uld_state);
	mutex_unlock(&dev->pdev_mutex);

	sdk_info(&dev->pcidev->dev,
		 "Attach %s driver to pcie device succeed\n", s_uld_name[type]);
	return 0;

probe_failed:
out_unlock:
	mutex_unlock(&dev->pdev_mutex);

	return err;
}

static void wait_uld_unused(struct hinic3_pcidev *dev, enum hinic3_service_type type)
{
	u32 loop_cnt = 0;

	while (atomic_read(&dev->uld_ref_cnt[type])) {
		loop_cnt++;
		if (loop_cnt % PRINT_ULD_DETACH_TIMEOUT_INTERVAL == 0)
			sdk_err(&dev->pcidev->dev, "Wait for uld unused for %lds, reference count: %d\n",
				loop_cnt / MSEC_PER_SEC, atomic_read(&dev->uld_ref_cnt[type]));

		usleep_range(ULD_LOCK_MIN_USLEEP_TIME, ULD_LOCK_MAX_USLEEP_TIME);
	}
}

static void detach_uld(struct hinic3_pcidev *dev,
		       enum hinic3_service_type type)
{
	struct hinic3_uld_info *uld_info = &g_uld_info[type];
	unsigned long end;
	bool timeout = true;

	mutex_lock(&dev->pdev_mutex);
	if (!dev->uld_dev[type]) {
		mutex_unlock(&dev->pdev_mutex);
		return;
	}

	end = jiffies + msecs_to_jiffies(HINIC3_EVENT_PROCESS_TIMEOUT);
	do {
		if (!test_and_set_bit(type, &dev->state)) {
			timeout = false;
			break;
		}
		usleep_range(900, 1000); /* sleep 900 us ~ 1000 us */
	} while (time_before(jiffies, end));

	if (timeout && !test_and_set_bit(type, &dev->state))
		timeout = false;

	spin_lock_bh(&dev->uld_lock);
	clear_bit(type, &dev->uld_state);
	spin_unlock_bh(&dev->uld_lock);

	wait_uld_unused(dev, type);

	uld_info->remove(&dev->lld_dev, dev->uld_dev[type]);

	dev->uld_dev[type] = NULL;
	if (!timeout)
		clear_bit(type, &dev->state);

	sdk_info(&dev->pcidev->dev,
		 "Detach %s driver from pcie device succeed\n",
		 s_uld_name[type]);
	mutex_unlock(&dev->pdev_mutex);
}

static void attach_ulds(struct hinic3_pcidev *dev)
{
	enum hinic3_service_type type;
	struct pci_dev *pdev = dev->pcidev;

	lld_hold();
	mutex_lock(&g_uld_mutex);

	for (type = SERVICE_T_NIC; type < SERVICE_T_MAX; type++) {
		if (g_uld_info[type].probe) {
			if (pdev->is_virtfn &&
			    (!hinic3_get_vf_service_load(pdev, (u16)type))) {
				sdk_info(&pdev->dev, "VF device disable service_type = %d load in host\n",
					 type);
				continue;
			}
			attach_uld(dev, type, &g_uld_info[type]);
		}
	}
	mutex_unlock(&g_uld_mutex);
	lld_put();
}

static void detach_ulds(struct hinic3_pcidev *dev)
{
	enum hinic3_service_type type;

	lld_hold();
	mutex_lock(&g_uld_mutex);
	for (type = SERVICE_T_MAX - 1; type > SERVICE_T_NIC; type--) {
		if (g_uld_info[type].probe)
			detach_uld(dev, type);
	}

	if (g_uld_info[SERVICE_T_NIC].probe)
		detach_uld(dev, SERVICE_T_NIC);
	mutex_unlock(&g_uld_mutex);
	lld_put();
}

int hinic3_register_uld(enum hinic3_service_type type,
			struct hinic3_uld_info *uld_info)
{
	struct card_node *chip_node = NULL;
	struct hinic3_pcidev *dev = NULL;
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

	lld_hold();
	mutex_lock(&g_uld_mutex);

	if (g_uld_info[type].probe) {
		pr_err("%s driver has registered\n", s_uld_name[type]);
		mutex_unlock(&g_uld_mutex);
		lld_put();
		return -EINVAL;
	}

	chip_list = get_hinic3_chip_list();
	memcpy(&g_uld_info[type], uld_info, sizeof(*uld_info));
	list_for_each_entry(chip_node, chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (attach_uld(dev, type, uld_info)) {
				sdk_err(&dev->pcidev->dev,
					"Attach %s driver to pcie device failed\n",
					s_uld_name[type]);
#ifdef CONFIG_MODULE_PROF
				hinic3_probe_fault_process(dev->pcidev, FAULT_LEVEL_HOST);
				break;
#else
				continue;
#endif
			}
		}
	}

	mutex_unlock(&g_uld_mutex);
	lld_put();

	pr_info("Register %s driver succeed\n", s_uld_name[type]);
	return 0;
}
EXPORT_SYMBOL(hinic3_register_uld);

void hinic3_unregister_uld(enum hinic3_service_type type)
{
	struct card_node *chip_node = NULL;
	struct hinic3_pcidev *dev = NULL;
	struct hinic3_uld_info *uld_info = NULL;
	struct list_head *chip_list = NULL;

	if (type >= SERVICE_T_MAX) {
		pr_err("Unknown type %d of up layer driver to unregister\n",
		       type);
		return;
	}

	lld_hold();
	mutex_lock(&g_uld_mutex);
	chip_list = get_hinic3_chip_list();
	list_for_each_entry(chip_node, chip_list, node) {
		/* detach vf first */
		list_for_each_entry(dev, &chip_node->func_list, node)
			if (hinic3_func_type(dev->hwdev) == TYPE_VF)
				detach_uld(dev, type);

		list_for_each_entry(dev, &chip_node->func_list, node)
			if (hinic3_func_type(dev->hwdev) == TYPE_PF)
				detach_uld(dev, type);

		list_for_each_entry(dev, &chip_node->func_list, node)
			if (hinic3_func_type(dev->hwdev) == TYPE_PPF)
				detach_uld(dev, type);
	}

	uld_info = &g_uld_info[type];
	memset(uld_info, 0, sizeof(*uld_info));
	mutex_unlock(&g_uld_mutex);
	lld_put();
}
EXPORT_SYMBOL(hinic3_unregister_uld);

int hinic3_attach_nic(struct hinic3_lld_dev *lld_dev)
{
	struct hinic3_pcidev *dev = NULL;

	if (!lld_dev)
		return -EINVAL;

	dev = container_of(lld_dev, struct hinic3_pcidev, lld_dev);
	return attach_uld(dev, SERVICE_T_NIC, &g_uld_info[SERVICE_T_NIC]);
}
EXPORT_SYMBOL(hinic3_attach_nic);

void hinic3_detach_nic(const struct hinic3_lld_dev *lld_dev)
{
	struct hinic3_pcidev *dev = NULL;

	if (!lld_dev)
		return;

	dev = container_of(lld_dev, struct hinic3_pcidev, lld_dev);
	detach_uld(dev, SERVICE_T_NIC);
}
EXPORT_SYMBOL(hinic3_detach_nic);

int hinic3_attach_service(const struct hinic3_lld_dev *lld_dev, enum hinic3_service_type type)
{
	struct hinic3_pcidev *dev = NULL;

	if (!lld_dev || type >= SERVICE_T_MAX)
		return -EINVAL;

	dev = container_of(lld_dev, struct hinic3_pcidev, lld_dev);
	return attach_uld(dev, type, &g_uld_info[type]);
}
EXPORT_SYMBOL(hinic3_attach_service);

void hinic3_detach_service(const struct hinic3_lld_dev *lld_dev, enum hinic3_service_type type)
{
	struct hinic3_pcidev *dev = NULL;

	if (!lld_dev || type >= SERVICE_T_MAX)
		return;

	dev = container_of(lld_dev, struct hinic3_pcidev, lld_dev);
	detach_uld(dev, type);
}
EXPORT_SYMBOL(hinic3_detach_service);

static void hinic3_sync_time_to_fmw(struct hinic3_pcidev *pdev_pri)
{
	struct timeval tv = {0};
	struct rtc_time rt_time = {0};
	u64 tv_msec;
	int err;

	do_gettimeofday(&tv);

	tv_msec = (u64)(tv.tv_sec * MSEC_PER_SEC + tv.tv_usec / USEC_PER_MSEC);
	err = hinic3_sync_time(pdev_pri->hwdev, tv_msec);
	if (err) {
		sdk_err(&pdev_pri->pcidev->dev, "Synchronize UTC time to firmware failed, errno:%d.\n",
			err);
	} else {
		rtc_time_to_tm((unsigned long)(tv.tv_sec), &rt_time);
		sdk_info(&pdev_pri->pcidev->dev, "Synchronize UTC time to firmware succeed. UTC time %d-%02d-%02d %02d:%02d:%02d.\n",
			 rt_time.tm_year + HINIC3_SYNC_YEAR_OFFSET,
			 rt_time.tm_mon + HINIC3_SYNC_MONTH_OFFSET,
			 rt_time.tm_mday, rt_time.tm_hour,
			 rt_time.tm_min, rt_time.tm_sec);
	}
}

static void send_uld_dev_event(struct hinic3_pcidev *dev,
			       struct hinic3_event_info *event)
{
	enum hinic3_service_type type;

	for (type = SERVICE_T_NIC; type < SERVICE_T_MAX; type++) {
		if (test_and_set_bit(type, &dev->state)) {
			sdk_warn(&dev->pcidev->dev, "Svc: 0x%x, event: 0x%x can't handler, %s is in detach\n",
				 event->service, event->type, s_uld_name[type]);
			continue;
		}

		if (g_uld_info[type].event)
			g_uld_info[type].event(&dev->lld_dev,
					       dev->uld_dev[type], event);
		clear_bit(type, &dev->state);
	}
}

static void send_event_to_dst_pf(struct hinic3_pcidev *dev, u16 func_id,
				 struct hinic3_event_info *event)
{
	struct hinic3_pcidev *des_dev = NULL;

	lld_hold();
	list_for_each_entry(des_dev, &dev->chip_node->func_list, node) {
		if (dev->lld_state == HINIC3_IN_REMOVE)
			continue;

		if (hinic3_func_type(des_dev->hwdev) == TYPE_VF)
			continue;

		if (hinic3_global_func_id(des_dev->hwdev) == func_id) {
			send_uld_dev_event(des_dev, event);
			break;
		}
	}
	lld_put();
}

static void send_event_to_all_pf(struct hinic3_pcidev *dev,
				 struct hinic3_event_info *event)
{
	struct hinic3_pcidev *des_dev = NULL;

	lld_hold();
	list_for_each_entry(des_dev, &dev->chip_node->func_list, node) {
		if (dev->lld_state == HINIC3_IN_REMOVE)
			continue;

		if (hinic3_func_type(des_dev->hwdev) == TYPE_VF)
			continue;

		send_uld_dev_event(des_dev, event);
	}
	lld_put();
}

static void hinic3_event_process(void *adapter, struct hinic3_event_info *event)
{
	struct hinic3_pcidev *dev = adapter;
	struct hinic3_fault_event *fault = (void *)event->event_data;
	u16 func_id;

	if ((event->service == EVENT_SRV_COMM && event->type == EVENT_COMM_FAULT) &&
	    fault->fault_level == FAULT_LEVEL_SERIOUS_FLR &&
	    fault->event.chip.func_id < hinic3_max_pf_num(dev->hwdev)) {
		func_id = fault->event.chip.func_id;
		return send_event_to_dst_pf(adapter, func_id, event);
	}

	if (event->type == EVENT_COMM_MGMT_WATCHDOG)
		send_event_to_all_pf(adapter, event);
	else
		send_uld_dev_event(adapter, event);
}

static void uld_def_init(struct hinic3_pcidev *pci_adapter)
{
	int type;

	for (type = 0; type < SERVICE_T_MAX; type++) {
		atomic_set(&pci_adapter->uld_ref_cnt[type], 0);
		clear_bit(type, &pci_adapter->uld_state);
	}

	spin_lock_init(&pci_adapter->uld_lock);
}

static int mapping_bar(struct pci_dev *pdev,
		       struct hinic3_pcidev *pci_adapter)
{
	int cfg_bar;

	cfg_bar = HINIC3_IS_VF_DEV(pdev) ?
			HINIC3_VF_PCI_CFG_REG_BAR : HINIC3_PF_PCI_CFG_REG_BAR;

	pci_adapter->cfg_reg_base = pci_ioremap_bar(pdev, cfg_bar);
	if (!pci_adapter->cfg_reg_base) {
		sdk_err(&pdev->dev,
			"Failed to map configuration regs\n");
		return -ENOMEM;
	}

	pci_adapter->intr_reg_base = pci_ioremap_bar(pdev,
						     HINIC3_PCI_INTR_REG_BAR);
	if (!pci_adapter->intr_reg_base) {
		sdk_err(&pdev->dev,
			"Failed to map interrupt regs\n");
		goto map_intr_bar_err;
	}

	if (!HINIC3_IS_VF_DEV(pdev)) {
		pci_adapter->mgmt_reg_base =
			pci_ioremap_bar(pdev, HINIC3_PCI_MGMT_REG_BAR);
		if (!pci_adapter->mgmt_reg_base) {
			sdk_err(&pdev->dev,
				"Failed to map mgmt regs\n");
			goto map_mgmt_bar_err;
		}
	}

	pci_adapter->db_base_phy = pci_resource_start(pdev, HINIC3_PCI_DB_BAR);
	pci_adapter->db_dwqe_len = pci_resource_len(pdev, HINIC3_PCI_DB_BAR);
	pci_adapter->db_base = pci_ioremap_bar(pdev, HINIC3_PCI_DB_BAR);
	if (!pci_adapter->db_base) {
		sdk_err(&pdev->dev,
			"Failed to map doorbell regs\n");
		goto map_db_err;
	}

	return 0;

map_db_err:
	if (!HINIC3_IS_VF_DEV(pdev))
		iounmap(pci_adapter->mgmt_reg_base);

map_mgmt_bar_err:
	iounmap(pci_adapter->intr_reg_base);

map_intr_bar_err:
	iounmap(pci_adapter->cfg_reg_base);

	return -ENOMEM;
}

static void unmapping_bar(struct hinic3_pcidev *pci_adapter)
{
	iounmap(pci_adapter->db_base);

	if (!HINIC3_IS_VF_DEV(pci_adapter->pcidev))
		iounmap(pci_adapter->mgmt_reg_base);

	iounmap(pci_adapter->intr_reg_base);
	iounmap(pci_adapter->cfg_reg_base);
}

static int hinic3_pci_init(struct pci_dev *pdev)
{
	struct hinic3_pcidev *pci_adapter = NULL;
	int err;

	pci_adapter = kzalloc(sizeof(*pci_adapter), GFP_KERNEL);
	if (!pci_adapter) {
		sdk_err(&pdev->dev,
			"Failed to alloc pci device adapter\n");
		return -ENOMEM;
	}
	pci_adapter->pcidev = pdev;
	mutex_init(&pci_adapter->pdev_mutex);

	pci_set_drvdata(pdev, pci_adapter);

	err = pci_enable_device(pdev);
	if (err) {
		sdk_err(&pdev->dev, "Failed to enable PCI device\n");
		goto pci_enable_err;
	}

	err = pci_request_regions(pdev, HINIC3_DRV_NAME);
	if (err) {
		sdk_err(&pdev->dev, "Failed to request regions\n");
		goto pci_regions_err;
	}

	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64)); /* 64 bit DMA mask */
	if (err) {
		sdk_warn(&pdev->dev, "Couldn't set 64-bit DMA mask\n");
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32)); /* 32 bit DMA mask */
		if (err) {
			sdk_err(&pdev->dev, "Failed to set DMA mask\n");
			goto dma_mask_err;
		}
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64)); /* 64 bit DMA mask */
	if (err) {
		sdk_warn(&pdev->dev,
			 "Couldn't set 64-bit coherent DMA mask\n");
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32)); /* 32 bit DMA mask */
		if (err) {
			sdk_err(&pdev->dev,
				"Failed to set coherent DMA mask\n");
			goto dma_consistnet_mask_err;
		}
	}

	return 0;

dma_consistnet_mask_err:
dma_mask_err:
	pci_clear_master(pdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_release_regions(pdev);

pci_regions_err:
	pci_disable_device(pdev);

pci_enable_err:
	pci_set_drvdata(pdev, NULL);
	kfree(pci_adapter);

	return err;
}

static void hinic3_pci_deinit(struct pci_dev *pdev)
{
	struct hinic3_pcidev *pci_adapter = pci_get_drvdata(pdev);

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(pci_adapter);
}

#ifdef CONFIG_X86
/**
 * cfg_order_reg - when cpu model is haswell or broadwell, should configure dma
 * order register to zero
 * @pci_adapter: pci_adapter
 **/
/*lint -save -e40 */
static void cfg_order_reg(struct hinic3_pcidev *pci_adapter)
{
	u8 cpu_model[] = {0x3c, 0x3f, 0x45, 0x46, 0x3d, 0x47, 0x4f, 0x56};
	struct cpuinfo_x86 *cpuinfo = NULL;
	u32 i;

	if (hinic3_func_type(pci_adapter->hwdev) == TYPE_VF)
		return;

	cpuinfo = &cpu_data(0);
	for (i = 0; i < sizeof(cpu_model); i++) {
		if (cpu_model[i] == cpuinfo->x86_model)
			hinic3_set_pcie_order_cfg(pci_adapter->hwdev);
	}
}

/*lint -restore*/
#endif

static int hinic3_func_init(struct pci_dev *pdev, struct hinic3_pcidev *pci_adapter)
{
	struct hinic3_init_para init_para = {0};
	bool cqm_init_en = false;
	int err;

	init_para.adapter_hdl = pci_adapter;
	init_para.pcidev_hdl = pdev;
	init_para.dev_hdl = &pdev->dev;
	init_para.cfg_reg_base = pci_adapter->cfg_reg_base;
	init_para.intr_reg_base = pci_adapter->intr_reg_base;
	init_para.mgmt_reg_base = pci_adapter->mgmt_reg_base;
	init_para.db_base = pci_adapter->db_base;
	init_para.db_base_phy = pci_adapter->db_base_phy;
	init_para.db_dwqe_len = pci_adapter->db_dwqe_len;
	init_para.hwdev = &pci_adapter->hwdev;
	init_para.chip_node = pci_adapter->chip_node;
	init_para.probe_fault_level = pci_adapter->probe_fault_level;
	err = hinic3_init_hwdev(&init_para);
	if (err) {
		pci_adapter->hwdev = NULL;
		pci_adapter->probe_fault_level = init_para.probe_fault_level;
		sdk_err(&pdev->dev, "Failed to initialize hardware device\n");
		return -EFAULT;
	}

	cqm_init_en = hinic3_need_init_stateful_default(pci_adapter->hwdev);
	if (cqm_init_en) {
		err = hinic3_stateful_init(pci_adapter->hwdev);
		if (err) {
			sdk_err(&pdev->dev, "Failed to init stateful\n");
			goto stateful_init_err;
		}
	}

	pci_adapter->lld_dev.pdev = pdev;

	pci_adapter->lld_dev.hwdev = pci_adapter->hwdev;
	if (hinic3_func_type(pci_adapter->hwdev) != TYPE_VF)
		set_bit(HINIC3_FUNC_PERSENT, &pci_adapter->sriov_info.state);

	hinic3_event_register(pci_adapter->hwdev, pci_adapter,
			      hinic3_event_process);

	if (hinic3_func_type(pci_adapter->hwdev) != TYPE_VF)
		hinic3_sync_time_to_fmw(pci_adapter);

	/* dbgtool init */
	lld_lock_chip_node();
	err = nictool_k_init(pci_adapter->hwdev, pci_adapter->chip_node);
	if (err) {
		lld_unlock_chip_node();
		sdk_err(&pdev->dev, "Failed to initialize dbgtool\n");
		goto nictool_init_err;
	}
	list_add_tail(&pci_adapter->node, &pci_adapter->chip_node->func_list);
	lld_unlock_chip_node();

	if (!disable_attach) {
		attach_ulds(pci_adapter);

		if (hinic3_func_type(pci_adapter->hwdev) != TYPE_VF) {
			err = sysfs_create_group(&pdev->dev.kobj,
						 &hinic3_attr_group);
			if (err) {
				sdk_err(&pdev->dev, "Failed to create sysfs group\n");
				goto create_sysfs_err;
			}
		}

#ifdef CONFIG_X86
		cfg_order_reg(pci_adapter);
#endif
	}

	return 0;

create_sysfs_err:
	detach_ulds(pci_adapter);

	lld_lock_chip_node();
	list_del(&pci_adapter->node);
	lld_unlock_chip_node();

	wait_lld_dev_unused(pci_adapter);

	lld_lock_chip_node();
	nictool_k_uninit(pci_adapter->hwdev, pci_adapter->chip_node);
	lld_unlock_chip_node();

nictool_init_err:
	hinic3_event_unregister(pci_adapter->hwdev);
	if (cqm_init_en)
		hinic3_stateful_deinit(pci_adapter->hwdev);
stateful_init_err:
	hinic3_free_hwdev(pci_adapter->hwdev);

	return err;
}

static void hinic3_func_deinit(struct pci_dev *pdev)
{
	struct hinic3_pcidev *pci_adapter = pci_get_drvdata(pdev);

	/* When function deinit, disable mgmt initiative report events firstly,
	 * then flush mgmt work-queue.
	 */
	hinic3_disable_mgmt_msg_report(pci_adapter->hwdev);

	hinic3_flush_mgmt_workq(pci_adapter->hwdev);

	lld_lock_chip_node();
	list_del(&pci_adapter->node);
	lld_unlock_chip_node();

	detach_ulds(pci_adapter);

	wait_lld_dev_unused(pci_adapter);

	lld_lock_chip_node();
	nictool_k_uninit(pci_adapter->hwdev, pci_adapter->chip_node);
	lld_unlock_chip_node();

	hinic3_event_unregister(pci_adapter->hwdev);

	hinic3_free_stateful(pci_adapter->hwdev);

	hinic3_free_hwdev(pci_adapter->hwdev);
}

static void wait_sriov_cfg_complete(struct hinic3_pcidev *pci_adapter)
{
	struct hinic3_sriov_info *sriov_info;
	unsigned long end;

	sriov_info = &pci_adapter->sriov_info;
	clear_bit(HINIC3_FUNC_PERSENT, &sriov_info->state);
	usleep_range(9900, 10000); /* sleep 9900 us ~ 10000 us */

	end = jiffies + msecs_to_jiffies(HINIC3_WAIT_SRIOV_CFG_TIMEOUT);
	do {
		if (!test_bit(HINIC3_SRIOV_ENABLE, &sriov_info->state) &&
		    !test_bit(HINIC3_SRIOV_DISABLE, &sriov_info->state))
			return;

		usleep_range(9900, 10000); /* sleep 9900 us ~ 10000 us */
	} while (time_before(jiffies, end));
}

bool hinic3_get_vf_load_state(struct pci_dev *pdev)
{
	struct hinic3_pcidev *pci_adapter = NULL;
	struct pci_dev *pf_pdev = NULL;

	if (!pdev) {
		pr_err("pdev is null.\n");
		return false;
	}

	/* vf used in vm */
	if (pci_is_root_bus(pdev->bus))
		return false;

	if (pdev->is_virtfn)
		pf_pdev = pdev->physfn;
	else
		pf_pdev = pdev;

	pci_adapter = pci_get_drvdata(pf_pdev);
	if (!pci_adapter) {
		sdk_err(&pdev->dev, "pci_adapter is null.\n");
		return false;
	}

	return !pci_adapter->disable_vf_load;
}

int hinic3_set_vf_load_state(struct pci_dev *pdev, bool vf_load_state)
{
	struct hinic3_pcidev *pci_adapter = NULL;

	if (!pdev) {
		pr_err("pdev is null.\n");
		return -EINVAL;
	}

	pci_adapter = pci_get_drvdata(pdev);
	if (!pci_adapter) {
		sdk_err(&pdev->dev, "pci_adapter is null.\n");
		return -EINVAL;
	}

	if (hinic3_func_type(pci_adapter->hwdev) == TYPE_VF)
		return 0;

	pci_adapter->disable_vf_load = !vf_load_state;
	sdk_info(&pci_adapter->pcidev->dev, "Current function %s vf load in host\n",
		 vf_load_state ? "enable" : "disable");

	return 0;
}
EXPORT_SYMBOL(hinic3_set_vf_load_state);

bool hinic3_get_vf_service_load(struct pci_dev *pdev, u16 service)
{
	struct hinic3_pcidev *pci_adapter = NULL;
	struct pci_dev *pf_pdev = NULL;

	if (!pdev) {
		pr_err("pdev is null.\n");
		return false;
	}

	if (pdev->is_virtfn)
		pf_pdev = pdev->physfn;
	else
		pf_pdev = pdev;

	pci_adapter = pci_get_drvdata(pf_pdev);
	if (!pci_adapter) {
		sdk_err(&pdev->dev, "pci_adapter is null.\n");
		return false;
	}

	if (service >= SERVICE_T_MAX) {
		sdk_err(&pdev->dev, "service_type = %u state is error\n",
			service);
		return false;
	}

	return !pci_adapter->disable_srv_load[service];
}

int hinic3_set_vf_service_load(struct pci_dev *pdev, u16 service,
			       bool vf_srv_load)
{
	struct hinic3_pcidev *pci_adapter = NULL;

	if (!pdev) {
		pr_err("pdev is null.\n");
		return -EINVAL;
	}

	if (service >= SERVICE_T_MAX) {
		sdk_err(&pdev->dev, "service_type = %u state is error\n",
			service);
		return -EFAULT;
	}

	pci_adapter = pci_get_drvdata(pdev);
	if (!pci_adapter) {
		sdk_err(&pdev->dev, "pci_adapter is null.\n");
		return -EINVAL;
	}

	if (hinic3_func_type(pci_adapter->hwdev) == TYPE_VF)
		return 0;

	pci_adapter->disable_srv_load[service] = !vf_srv_load;
	sdk_info(&pci_adapter->pcidev->dev, "Current function %s vf load in host\n",
		 vf_srv_load ? "enable" : "disable");

	return 0;
}
EXPORT_SYMBOL(hinic3_set_vf_service_load);

static int hinic3_remove_func(struct hinic3_pcidev *pci_adapter)
{
	struct pci_dev *pdev = pci_adapter->pcidev;

	mutex_lock(&pci_adapter->pdev_mutex);
	if (pci_adapter->lld_state != HINIC3_PROBE_OK) {
		sdk_warn(&pdev->dev, "Current function don not need remove\n");
		mutex_unlock(&pci_adapter->pdev_mutex);
		return 0;
	}
	pci_adapter->lld_state = HINIC3_IN_REMOVE;
	mutex_unlock(&pci_adapter->pdev_mutex);

	hinic3_detect_hw_present(pci_adapter->hwdev);

	hisdk3_remove_pre_process(pci_adapter->hwdev);

	if (hinic3_func_type(pci_adapter->hwdev) != TYPE_VF) {
		sysfs_remove_group(&pdev->dev.kobj, &hinic3_attr_group);
		wait_sriov_cfg_complete(pci_adapter);
		hinic3_pci_sriov_disable(pdev);
	}

	hinic3_func_deinit(pdev);

	lld_lock_chip_node();
	free_chip_node(pci_adapter);
	lld_unlock_chip_node();

	unmapping_bar(pci_adapter);

	mutex_lock(&pci_adapter->pdev_mutex);
	pci_adapter->lld_state = HINIC3_NOT_PROBE;
	mutex_unlock(&pci_adapter->pdev_mutex);

	sdk_info(&pdev->dev, "Pcie device removed function\n");

	return 0;
}

static void hinic3_remove(struct pci_dev *pdev)
{
	struct hinic3_pcidev *pci_adapter = pci_get_drvdata(pdev);

	if (!pci_adapter)
		return;

	sdk_info(&pdev->dev, "Pcie device remove begin\n");

	hinic3_remove_func(pci_adapter);

	hinic3_pci_deinit(pdev);
	hinic3_probe_pre_unprocess(pdev);

	sdk_info(&pdev->dev, "Pcie device removed\n");
}

static int probe_func_param_init(struct hinic3_pcidev *pci_adapter)
{
	struct pci_dev *pdev = NULL;

	if (!pci_adapter)
		return -EFAULT;

	pdev = pci_adapter->pcidev;
	if (!pdev)
		return -EFAULT;

	mutex_lock(&pci_adapter->pdev_mutex);
	if (pci_adapter->lld_state >= HINIC3_PROBE_START) {
		sdk_warn(&pdev->dev, "Don not probe repeat\n");
		mutex_unlock(&pci_adapter->pdev_mutex);
		return 0;
	}
	pci_adapter->lld_state = HINIC3_PROBE_START;
	mutex_unlock(&pci_adapter->pdev_mutex);

	return 0;
}

static int hinic3_probe_func(struct hinic3_pcidev *pci_adapter)
{
	struct pci_dev *pdev = pci_adapter->pcidev;
	int err;

	err = probe_func_param_init(pci_adapter);
	if (err)
		return err;

	err = mapping_bar(pdev, pci_adapter);
	if (err) {
		sdk_err(&pdev->dev, "Failed to map bar\n");
		goto map_bar_failed;
	}

	uld_def_init(pci_adapter);

	/* if chip information of pcie function exist, add the function into chip */
	lld_lock_chip_node();
	err = alloc_chip_node(pci_adapter);
	if (err) {
		lld_unlock_chip_node();
		sdk_err(&pdev->dev, "Failed to add new chip node to global list\n");
		goto alloc_chip_node_fail;
	}
	lld_unlock_chip_node();

	err = hinic3_func_init(pdev, pci_adapter);
	if (err)
		goto func_init_err;

	if (hinic3_func_type(pci_adapter->hwdev) != TYPE_VF) {
		err = hinic3_set_bdf_ctxt(pci_adapter->hwdev, pdev->bus->number,
					  PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
		if (err) {
			sdk_err(&pdev->dev, "Failed to set BDF info to MPU\n");
			goto set_bdf_err;
		}
	}

	hinic3_probe_success(pci_adapter->hwdev);

	mutex_lock(&pci_adapter->pdev_mutex);
	pci_adapter->lld_state = HINIC3_PROBE_OK;
	mutex_unlock(&pci_adapter->pdev_mutex);

	return 0;

set_bdf_err:
	hinic3_func_deinit(pdev);

func_init_err:
	lld_lock_chip_node();
	free_chip_node(pci_adapter);
	lld_unlock_chip_node();

alloc_chip_node_fail:
	unmapping_bar(pci_adapter);

map_bar_failed:
	sdk_err(&pdev->dev, "Pcie device probe function failed\n");
	return err;
}

static int hinic3_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hinic3_pcidev *pci_adapter = NULL;
	u16 probe_fault_level = FAULT_LEVEL_SERIOUS_FLR;
	int err;

	sdk_info(&pdev->dev, "Pcie device probe begin\n");

	err = hinic3_probe_pre_process(pdev);
	if (err != 0 && err != HINIC3_NOT_PROBE)
		goto out;

	if (err == HINIC3_NOT_PROBE)
		return 0;

	err = hinic3_pci_init(pdev);
	if (err)
		goto pci_init_err;

	pci_adapter = pci_get_drvdata(pdev);
	pci_adapter->disable_vf_load = disable_vf_load;
	pci_adapter->id = *id;
	pci_adapter->lld_state = HINIC3_NOT_PROBE;
	pci_adapter->probe_fault_level = probe_fault_level;
	lld_dev_cnt_init(pci_adapter);

	if (pdev->is_virtfn && (!hinic3_get_vf_load_state(pdev))) {
		sdk_info(&pdev->dev, "VF device disable load in host\n");
		return 0;
	}

	err = hinic3_probe_func(pci_adapter);
	if (err)
		goto hinic3_probe_func_fail;

	sdk_info(&pdev->dev, "Pcie device probed\n");
	return 0;

hinic3_probe_func_fail:
	probe_fault_level = pci_adapter->probe_fault_level;
	hinic3_pci_deinit(pdev);

pci_init_err:
	hinic3_probe_pre_unprocess(pdev);

out:
	hinic3_probe_fault_process(pdev, probe_fault_level);
	sdk_err(&pdev->dev, "Pcie device probe failed\n");
	return err;
}

static int hinic3_get_pf_info(struct pci_dev *pdev, u16 service,
			      struct hinic3_hw_pf_infos **pf_infos)
{
	struct hinic3_pcidev *dev = pci_get_drvdata(pdev);
	int err;

	if (service >= SERVICE_T_MAX) {
		sdk_err(&pdev->dev, "Current vf do not supports set service_type = %u state in host\n",
			service);
		return -EFAULT;
	}

	*pf_infos = kzalloc(sizeof(struct hinic3_hw_pf_infos), GFP_KERNEL);
	err = hinic3_get_hw_pf_infos(dev->hwdev, *pf_infos, HINIC3_CHANNEL_COMM);
	if (err) {
		kfree(*pf_infos);
		sdk_err(&pdev->dev, "Get chipf pf info failed, ret %d\n", err);
		return -EFAULT;
	}

	return 0;
}

static int hinic3_set_func_en(struct pci_dev *des_pdev, struct hinic3_pcidev *dst_dev,
			      bool en, u16 vf_func_id)
{
	int err;

	/* unload invalid vf func id */
	if (!en && vf_func_id != hinic3_global_func_id(dst_dev->hwdev) &&
	    !strcmp(des_pdev->driver->name, HINIC3_DRV_NAME)) {
		pr_err("dst_dev func id:%u, vf_func_id:%u\n",
		       hinic3_global_func_id(dst_dev->hwdev), vf_func_id);
		mutex_unlock(&dst_dev->pdev_mutex);
		return -EFAULT;
	}

	if (!en && dst_dev->lld_state == HINIC3_PROBE_OK) {
		mutex_unlock(&dst_dev->pdev_mutex);
		hinic3_remove_func(dst_dev);
	} else if (en && dst_dev->lld_state == HINIC3_NOT_PROBE) {
		mutex_unlock(&dst_dev->pdev_mutex);
		err = hinic3_probe_func(dst_dev);
		if (err)
			return -EFAULT;
	}

	return 0;
}

static int get_vf_service_state_param(struct pci_dev *pdev, struct hinic3_pcidev **dev_ptr,
				      u16 service, struct hinic3_hw_pf_infos **pf_infos)
{
	int err;

	if (!pdev)
		return -EINVAL;

	*dev_ptr = pci_get_drvdata(pdev);
	if (!(*dev_ptr))
		return -EINVAL;

	err = hinic3_get_pf_info(pdev, service, pf_infos);
	if (err)
		return err;

	return 0;
}

#define BUS_MAX_DEV_NUM 256
static int hinic3_dst_pdev_valid(struct hinic3_pcidev *dst_dev,  struct pci_dev **des_pdev_ptr,
				 u16 vf_devfn, bool en)
{
	u16 bus;

	bus = dst_dev->pcidev->bus->number + vf_devfn / BUS_MAX_DEV_NUM;
	*des_pdev_ptr = pci_get_domain_bus_and_slot(pci_domain_nr(dst_dev->pcidev->bus),
					       bus, vf_devfn % BUS_MAX_DEV_NUM);
	if (!(*des_pdev_ptr)) {
		pr_err("des_pdev is NULL\n");
		return -EFAULT;
	}

	if ((*des_pdev_ptr)->driver == NULL) {
		pr_err("des_pdev_ptr->driver is NULL\n");
		return -EFAULT;
	}

	/* OVS sriov hw scene, when vf bind to vf_io return error. */
	if ((!en && strcmp((*des_pdev_ptr)->driver->name, HINIC3_DRV_NAME))) {
		pr_err("vf bind driver:%s\n", (*des_pdev_ptr)->driver->name);
		return -EFAULT;
	}

	return 0;
}

static int paramerter_is_unexpected(struct hinic3_pcidev *dst_dev, u16 *func_id, u16 *vf_start,
				    u16 *vf_end, u16 vf_func_id)
{
	if (hinic3_func_type(dst_dev->hwdev) == TYPE_VF)
		return -EPERM;

	*func_id = hinic3_global_func_id(dst_dev->hwdev);
	*vf_start = hinic3_glb_pf_vf_offset(dst_dev->hwdev) + 1;
	*vf_end = *vf_start + hinic3_func_max_vf(dst_dev->hwdev);
	if (vf_func_id < *vf_start || vf_func_id > *vf_end)
		return -EPERM;

	return 0;
}

int hinic3_set_vf_service_state(struct pci_dev *pdev, u16 vf_func_id, u16 service, bool en)
{
	struct hinic3_hw_pf_infos *pf_infos = NULL;
	struct hinic3_pcidev *dev = NULL, *dst_dev = NULL;
	struct pci_dev *des_pdev = NULL;
	u16 vf_start, vf_end, vf_devfn, func_id;
	int err;
	bool find_dst_dev = false;

	err = get_vf_service_state_param(pdev, &dev, service, &pf_infos);
	if (err)
		return err;

	lld_hold();
	list_for_each_entry(dst_dev, &dev->chip_node->func_list, node) {
		if (paramerter_is_unexpected(dst_dev, &func_id, &vf_start, &vf_end, vf_func_id))
			continue;

		vf_devfn = pf_infos->infos[func_id].vf_offset + (vf_func_id - vf_start) +
			(u16)dst_dev->pcidev->devfn;
		err = hinic3_dst_pdev_valid(dst_dev, &des_pdev, vf_devfn, en);
		if (err) {
			sdk_err(&pdev->dev, "Can not get vf func_id %u from pf %u\n",
				 vf_func_id, func_id);
			lld_put();
			goto free_pf_info;
		}

		dst_dev = pci_get_drvdata(des_pdev);
		/* When enable vf scene, if vf bind to vf-io, return ok */
		if (strcmp(des_pdev->driver->name, HINIC3_DRV_NAME) ||
		    !dst_dev || (!en && dst_dev->lld_state != HINIC3_PROBE_OK) ||
		    (en && dst_dev->lld_state != HINIC3_NOT_PROBE)) {
			lld_put();
			goto free_pf_info;
		}

		if (en)
			pci_dev_put(des_pdev);
		mutex_lock(&dst_dev->pdev_mutex);
		find_dst_dev = true;
		break;
	}
	lld_put();

	if (!find_dst_dev) {
		err = -EFAULT;
		sdk_err(&pdev->dev, "Invalid parameter vf_id %u \n", vf_func_id);
		goto free_pf_info;
	}

	err = hinic3_set_func_en(des_pdev, dst_dev, en, vf_func_id);

free_pf_info:
	kfree(pf_infos);
	return err;
}
EXPORT_SYMBOL(hinic3_set_vf_service_state);

/*lint -save -e133 -e10*/
static const struct pci_device_id hinic3_pci_table[] = {
	{PCI_VDEVICE(HUAWEI, HINIC3_DEV_ID_STANDARD), 0},
	{PCI_VDEVICE(HUAWEI, HINIC3_DEV_ID_DPU_PF), 0},
	{PCI_VDEVICE(HUAWEI, HINIC3_DEV_ID_SDI_5_0_PF), 0},
	{PCI_VDEVICE(HUAWEI, HINIC3_DEV_ID_SDI_5_1_PF), 0},
	{PCI_VDEVICE(HUAWEI, HINIC3_DEV_ID_VF), 0},
	{0, 0}

};

/*lint -restore*/

MODULE_DEVICE_TABLE(pci, hinic3_pci_table);

/**
 * hinic3_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 *
 * Since we only need error detecting not error handling, so we
 * always return PCI_ERS_RESULT_CAN_RECOVER to tell the AER
 * driver that we don't need reset(error handling).
 */
static pci_ers_result_t hinic3_io_error_detected(struct pci_dev *pdev,
						 pci_channel_state_t state)
{
	struct hinic3_pcidev *pci_adapter = NULL;

	sdk_err(&pdev->dev,
		"Uncorrectable error detected, log and cleanup error status: 0x%08x\n",
		state);

	pci_cleanup_aer_uncorrect_error_status(pdev);
	pci_adapter = pci_get_drvdata(pdev);
	if (pci_adapter)
		hinic3_record_pcie_error(pci_adapter->hwdev);

	return PCI_ERS_RESULT_CAN_RECOVER;
}

static void hinic3_shutdown(struct pci_dev *pdev)
{
	struct hinic3_pcidev *pci_adapter = pci_get_drvdata(pdev);

	sdk_info(&pdev->dev, "Shutdown device\n");

	if (pci_adapter)
		hinic3_shutdown_hwdev(pci_adapter->hwdev);

	pci_disable_device(pdev);

	if (pci_adapter)
		hinic3_set_api_stop(pci_adapter->hwdev);
}

#ifdef HAVE_RHEL6_SRIOV_CONFIGURE
static struct pci_driver_rh hinic3_driver_rh = {
	.sriov_configure = hinic3_pci_sriov_configure,
};
#endif

/* Cause we only need error detecting not error handling, so only error_detected
 * callback is enough.
 */
static struct pci_error_handlers hinic3_err_handler = {
	.error_detected = hinic3_io_error_detected,
};

static struct pci_driver hinic3_driver = {
	.name		 = HINIC3_DRV_NAME,
	.id_table	 = hinic3_pci_table,
	.probe		 = hinic3_probe,
	.remove		 = hinic3_remove,
	.shutdown	 = hinic3_shutdown,
#if defined(HAVE_SRIOV_CONFIGURE)
	.sriov_configure = hinic3_pci_sriov_configure,
#elif defined(HAVE_RHEL6_SRIOV_CONFIGURE)
	.rh_reserved = &hinic3_driver_rh,
#endif
	.err_handler	 = &hinic3_err_handler
};

int hinic3_lld_init(void)
{
	int err;

	pr_info("%s - version %s\n", HINIC3_DRV_DESC, HINIC3_DRV_VERSION);
	memset(g_uld_info, 0, sizeof(g_uld_info));

	hinic3_lld_lock_init();
	hinic3_uld_lock_init();

	err = hinic3_module_pre_init();
	if (err) {
		pr_err("Init custom failed\n");
		return err;
	}

	err = pci_register_driver(&hinic3_driver);
	if (err) {
		hinic3_module_post_exit();
		return err;
	}

	return 0;
}

void hinic3_lld_exit(void)
{
	pci_unregister_driver(&hinic3_driver);

	hinic3_module_post_exit();
}

