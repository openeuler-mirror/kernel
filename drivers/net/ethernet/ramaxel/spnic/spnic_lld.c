// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/aer.h>
#include <linux/debugfs.h>

#include "sphw_common.h"
#include "sphw_mt.h"
#include "sphw_crm.h"
#include "spnic_lld.h"
#include "spnic_pci_id_tbl.h"
#include "spnic_sriov.h"
#include "spnic_dev_mgmt.h"
#include "sphw_hw.h"
#include "spnic_nic_dev.h"

static bool disable_vf_load;
module_param(disable_vf_load, bool, 0444);
MODULE_PARM_DESC(disable_vf_load, "Disable virtual functions probe or not - default is false");

static bool disable_attach;
module_param(disable_attach, bool, 0444);
MODULE_PARM_DESC(disable_attach, "disable_attach or not - default is false");

#define SPNIC_WAIT_SRIOV_CFG_TIMEOUT	15000
#define SPNIC_SYNC_YEAR_OFFSET		1900

MODULE_AUTHOR("Ramaxel Technologies CO., Ltd");
MODULE_DESCRIPTION(SPNIC_DRV_DESC);
MODULE_VERSION(SPNIC_DRV_VERSION);
MODULE_LICENSE("GPL");

struct spnic_uld_info g_uld_info[SERVICE_T_MAX] = { {0} };

#define SPHW_EVENT_PROCESS_TIMEOUT	10000

static const char *s_uld_name[SERVICE_T_MAX] = {
	"nic", "ovs", "roce", "toe", "ioe",
	"fc", "vbs", "ipsec", "virtio", "migrate"};

static int attach_uld(struct spnic_pcidev *dev, enum sphw_service_type type,
		      struct spnic_uld_info *uld_info)
{
	void *uld_dev = NULL;
	int err;

	mutex_lock(&dev->pdev_mutex);

	if (dev->uld_dev[type]) {
		sdk_err(&dev->pcidev->dev, "%s driver has attached to pcie device\n",
			s_uld_name[type]);
		err = 0;
		goto out_unlock;
	}

	err = uld_info->probe(&dev->lld_dev, &uld_dev, dev->uld_dev_name[type]);
	if (err || !uld_dev) {
		sdk_err(&dev->pcidev->dev, "Failed to add object for %s driver to pcie device\n",
			s_uld_name[type]);
		goto probe_failed;
	}

	dev->uld_dev[type] = uld_dev;
	mutex_unlock(&dev->pdev_mutex);

	sdk_info(&dev->pcidev->dev, "Attach %s driver to pcie device succeed\n", s_uld_name[type]);
	return 0;

probe_failed:
out_unlock:
	mutex_unlock(&dev->pdev_mutex);

	return err;
}

static void detach_uld(struct spnic_pcidev *dev, enum sphw_service_type type)
{
	struct spnic_uld_info *uld_info = &g_uld_info[type];
	unsigned long end;
	bool timeout = true;

	mutex_lock(&dev->pdev_mutex);
	if (!dev->uld_dev[type]) {
		mutex_unlock(&dev->pdev_mutex);
		return;
	}

	end = jiffies + msecs_to_jiffies(SPHW_EVENT_PROCESS_TIMEOUT);
	do {
		if (!test_and_set_bit(type, &dev->state)) {
			timeout = false;
			break;
		}
		usleep_range(900, 1000);
	} while (time_before(jiffies, end));

	if (timeout && !test_and_set_bit(type, &dev->state))
		timeout = false;

	uld_info->remove(&dev->lld_dev, dev->uld_dev[type]);
	dev->uld_dev[type] = NULL;
	if (!timeout)
		clear_bit(type, &dev->state);

	sdk_info(&dev->pcidev->dev, "Detach %s driver from pcie device succeed\n",
		 s_uld_name[type]);
	mutex_unlock(&dev->pdev_mutex);
}

static void attach_ulds(struct spnic_pcidev *dev)
{
	enum sphw_service_type type;
	struct pci_dev *pdev = dev->pcidev;

	for (type = SERVICE_T_NIC; type < SERVICE_T_MAX; type++) {
		if (g_uld_info[type].probe) {
			if (pdev->is_virtfn && (!spnic_get_vf_service_load(pdev, (u16)type))) {
				sdk_info(&pdev->dev, "VF device disable service_type = %d load in host\n",
					 type);
				continue;
			}
			attach_uld(dev, type, &g_uld_info[type]);
		}
	}
}

static void detach_ulds(struct spnic_pcidev *dev)
{
	enum sphw_service_type type;

	for (type = SERVICE_T_MAX - 1; type > SERVICE_T_NIC; type--) {
		if (g_uld_info[type].probe)
			detach_uld(dev, type);
	}

	if (g_uld_info[SERVICE_T_NIC].probe)
		detach_uld(dev, SERVICE_T_NIC);
}

int spnic_register_uld(enum sphw_service_type type, struct spnic_uld_info *uld_info)
{
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;

	if (type >= SERVICE_T_MAX) {
		pr_err("Unknown type %d of up layer driver to register\n", type);
		return -EINVAL;
	}

	if (!uld_info || !uld_info->probe || !uld_info->remove) {
		pr_err("Invalid information of %s driver to register\n", s_uld_name[type]);
		return -EINVAL;
	}

	lld_hold();

	if (g_uld_info[type].probe) {
		pr_err("%s driver has registered\n", s_uld_name[type]);
		lld_put();
		return -EINVAL;
	}

	memcpy(&g_uld_info[type], uld_info, sizeof(*uld_info));
	list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (attach_uld(dev, type, uld_info)) {
				sdk_err(&dev->pcidev->dev, "Attach %s driver to pcie device failed\n",
					s_uld_name[type]);
				continue;
			}
		}
	}

	lld_put();

	pr_info("Register %s driver succeed\n", s_uld_name[type]);
	return 0;
}

void spnic_unregister_uld(enum sphw_service_type type)
{
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;
	struct spnic_uld_info *uld_info = NULL;

	if (type >= SERVICE_T_MAX) {
		pr_err("Unknown type %d of up layer driver to unregister\n", type);
		return;
	}

	lld_hold();
	list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
		/* detach vf first */
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (sphw_func_type(dev->hwdev) != TYPE_VF)
				continue;

			detach_uld(dev, type);
		}

		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (sphw_func_type(dev->hwdev) == TYPE_VF)
				continue;

			detach_uld(dev, type);
		}
	}

	uld_info = &g_uld_info[type];
	memset(uld_info, 0, sizeof(*uld_info));
	lld_put();
}

int spnic_attach_nic(struct spnic_lld_dev *lld_dev)
{
	struct spnic_pcidev *dev = NULL;

	if (!lld_dev)
		return -EINVAL;

	dev = container_of(lld_dev, struct spnic_pcidev, lld_dev);
	return attach_uld(dev, SERVICE_T_NIC, &g_uld_info[SERVICE_T_NIC]);
}

void spnic_detach_nic(struct spnic_lld_dev *lld_dev)
{
	struct spnic_pcidev *dev = NULL;

	if (!lld_dev)
		return;

	dev = container_of(lld_dev, struct spnic_pcidev, lld_dev);
	detach_uld(dev, SERVICE_T_NIC);
}

static void sphw_sync_time_to_fmw(struct spnic_pcidev *pdev_pri)
{
	struct tm tm = {0};
	u64 tv_msec;
	int err;

	tv_msec = ktime_to_ms(ktime_get_real());
	err = sphw_sync_time(pdev_pri->hwdev, tv_msec);
	if (err) {
		sdk_err(&pdev_pri->pcidev->dev, "Synchronize UTC time to firmware failed, errno:%d.\n",
			err);
	} else {
		time64_to_tm(tv_msec / MSEC_PER_SEC, 0, &tm);
		sdk_info(&pdev_pri->pcidev->dev, "Synchronize UTC time to firmware succeed. UTC time %ld-%02d-%02d %02d:%02d:%02d.\n",
			 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
			 tm.tm_min, tm.tm_sec);
	}
}

static void send_uld_dev_event(struct spnic_pcidev *dev,
			       struct sphw_event_info *event)
{
	enum sphw_service_type type;

	for (type = SERVICE_T_NIC; type < SERVICE_T_MAX; type++) {
		if (test_and_set_bit(type, &dev->state)) {
			sdk_warn(&dev->pcidev->dev, "Event: 0x%x can't handler, %s is in detach\n",
				 event->type, s_uld_name[type]);
			continue;
		}

		if (g_uld_info[type].event)
			g_uld_info[type].event(&dev->lld_dev, dev->uld_dev[type], event);
		clear_bit(type, &dev->state);
	}
}

static void send_event_to_dst_pf(struct spnic_pcidev *dev, u16 func_id,
				 struct sphw_event_info *event)
{
	struct spnic_pcidev *des_dev = NULL;

	lld_hold();
	list_for_each_entry(des_dev, &dev->chip_node->func_list, node) {
		if (sphw_func_type(des_dev->hwdev) == TYPE_VF)
			continue;

		if (sphw_global_func_id(des_dev->hwdev) == func_id) {
			send_uld_dev_event(des_dev, event);
			break;
		}
	}
	lld_put();
}

void spnic_event_process(void *adapter, struct sphw_event_info *event)
{
	struct spnic_pcidev *dev = adapter;
	u16 func_id;

	if (event->type == SPHW_EVENT_FAULT &&
	    event->info.fault_level == FAULT_LEVEL_SERIOUS_FLR &&
	    event->info.event.chip.func_id < sphw_max_pf_num(dev->hwdev)) {
		func_id = event->info.event.chip.func_id;
		return send_event_to_dst_pf(adapter, func_id, event);
	}

	send_uld_dev_event(adapter, event);
}

#define SPNIC_IS_VF_DEV(pdev)	((pdev)->device == SPNIC_DEV_ID_VF)

static int mapping_bar(struct pci_dev *pdev, struct spnic_pcidev *pci_adapter)
{
	int cfg_bar;

	cfg_bar = SPNIC_IS_VF_DEV(pdev) ? SPNIC_VF_PCI_CFG_REG_BAR : SPNIC_PF_PCI_CFG_REG_BAR;

	pci_adapter->cfg_reg_base = pci_ioremap_bar(pdev, cfg_bar);
	if (!pci_adapter->cfg_reg_base) {
		sdk_err(&pdev->dev, "Failed to map configuration regs\n");
		return -ENOMEM;
	}

	pci_adapter->intr_reg_base = pci_ioremap_bar(pdev, SPNIC_PCI_INTR_REG_BAR);
	if (!pci_adapter->intr_reg_base) {
		sdk_err(&pdev->dev,
			"Failed to map interrupt regs\n");
		goto map_intr_bar_err;
	}

	if (!SPNIC_IS_VF_DEV(pdev)) {
		pci_adapter->mgmt_reg_base = pci_ioremap_bar(pdev, SPNIC_PCI_MGMT_REG_BAR);
		if (!pci_adapter->mgmt_reg_base) {
			sdk_err(&pdev->dev, "Failed to map mgmt regs\n");
			goto map_mgmt_bar_err;
		}
	}

	pci_adapter->db_base_phy = pci_resource_start(pdev, SPNIC_PCI_DB_BAR);
	pci_adapter->db_dwqe_len = pci_resource_len(pdev, SPNIC_PCI_DB_BAR);
	pci_adapter->db_base = pci_ioremap_bar(pdev, SPNIC_PCI_DB_BAR);
	if (!pci_adapter->db_base) {
		sdk_err(&pdev->dev, "Failed to map doorbell regs\n");
		goto map_db_err;
	}

	return 0;

map_db_err:
	if (!SPNIC_IS_VF_DEV(pdev))
		iounmap(pci_adapter->mgmt_reg_base);

map_mgmt_bar_err:
	iounmap(pci_adapter->intr_reg_base);

map_intr_bar_err:
	iounmap(pci_adapter->cfg_reg_base);

	return -ENOMEM;
}

static void unmapping_bar(struct spnic_pcidev *pci_adapter)
{
	iounmap(pci_adapter->db_base);

	if (!SPNIC_IS_VF_DEV(pci_adapter->pcidev))
		iounmap(pci_adapter->mgmt_reg_base);

	iounmap(pci_adapter->intr_reg_base);
	iounmap(pci_adapter->cfg_reg_base);
}

static int spnic_pci_init(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = NULL;
	int err;

	pci_adapter = kzalloc(sizeof(*pci_adapter), GFP_KERNEL);
	if (!pci_adapter) {
		sdk_err(&pdev->dev, "Failed to alloc pci device adapter\n");
		return -ENOMEM;
	}
	pci_adapter->pcidev = pdev;
	mutex_init(&pci_adapter->pdev_mutex);

	pci_set_drvdata(pdev, pci_adapter);

	/* to do CONFIG_PCI_IOV */

	err = pci_enable_device(pdev);
	if (err) {
		sdk_err(&pdev->dev, "Failed to enable PCI device\n");
		goto pci_enable_err;
	}

	err = pci_request_regions(pdev, SPNIC_NIC_DRV_NAME);
	if (err) {
		sdk_err(&pdev->dev, "Failed to request regions\n");
		goto pci_regions_err;
	}

	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		sdk_warn(&pdev->dev, "Couldn't set 64-bit DMA mask\n");
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			sdk_err(&pdev->dev, "Failed to set DMA mask\n");
			goto dma_mask_err;
		}
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		sdk_warn(&pdev->dev, "Couldn't set 64-bit coherent DMA mask\n");
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			sdk_err(&pdev->dev, "Failed to set coherent DMA mask\n");
			goto dma_consistnet_mask_err;
		}
	}

	return 0;

dma_consistnet_mask_err:
dma_mask_err:
	pci_clear_master(pdev);
	pci_release_regions(pdev);

pci_regions_err:
	pci_disable_device(pdev);

pci_enable_err:
	pci_set_drvdata(pdev, NULL);
	kfree(pci_adapter);

	return err;
}

static void spnic_pci_deinit(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = pci_get_drvdata(pdev);

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
static void cfg_order_reg(struct spnic_pcidev *pci_adapter)
{
	u8 cpu_model[] = {0x3c, 0x3f, 0x45, 0x46, 0x3d, 0x47, 0x4f, 0x56};
	struct cpuinfo_x86 *cpuinfo = NULL;
	u32 i;

	if (sphw_func_type(pci_adapter->hwdev) == TYPE_VF)
		return;

	cpuinfo = &cpu_data(0);
	for (i = 0; i < sizeof(cpu_model); i++) {
		if (cpu_model[i] == cpuinfo->x86_model)
			sphw_set_pcie_order_cfg(pci_adapter->hwdev);
	}
}
#endif

static int spnic_func_init(struct pci_dev *pdev, struct spnic_pcidev *pci_adapter)
{
	struct sphw_init_para init_para = {0};
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
	err = sphw_init_hwdev(&init_para);
	if (err) {
		pci_adapter->hwdev = NULL;
		sdk_err(&pdev->dev, "Failed to initialize hardware device\n");
		return -EFAULT;
	}

	pci_adapter->lld_dev.pdev = pdev;
	pci_adapter->lld_dev.hwdev = pci_adapter->hwdev;
	if (sphw_func_type(pci_adapter->hwdev) != TYPE_VF)
		set_bit(SPNIC_FUNC_PERSENT, &pci_adapter->sriov_info.state);

	sphw_event_register(pci_adapter->hwdev, pci_adapter, spnic_event_process);

	if (sphw_func_type(pci_adapter->hwdev) != TYPE_VF)
		sphw_sync_time_to_fmw(pci_adapter);

	lld_lock_chip_node();
	list_add_tail(&pci_adapter->node, &pci_adapter->chip_node->func_list);
	lld_unlock_chip_node();

	if (!disable_attach) {
		attach_ulds(pci_adapter);
#ifdef CONFIG_X86
		cfg_order_reg(pci_adapter);
#endif
	}

	sdk_info(&pdev->dev, "Pcie device probed\n");

	return 0;
}

static void spnic_func_deinit(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = pci_get_drvdata(pdev);

	/* When function deinit, disable mgmt initiative report events firstly,
	 * then flush mgmt work-queue.
	 */
	sphw_disable_mgmt_msg_report(pci_adapter->hwdev);

	sphw_flush_mgmt_workq(pci_adapter->hwdev);

	lld_lock_chip_node();
	list_del(&pci_adapter->node);
	lld_unlock_chip_node();

	wait_lld_dev_unused(pci_adapter);

	detach_ulds(pci_adapter);

	sphw_event_unregister(pci_adapter->hwdev);

	sphw_free_hwdev(pci_adapter->hwdev);
}

static inline void wait_sriov_cfg_complete(struct spnic_pcidev *pci_adapter)
{
	struct spnic_sriov_info *sriov_info;
	unsigned long end;

	sriov_info = &pci_adapter->sriov_info;
	clear_bit(SPNIC_FUNC_PERSENT, &sriov_info->state);
	usleep_range(9900, 10000);

	end = jiffies + msecs_to_jiffies(SPNIC_WAIT_SRIOV_CFG_TIMEOUT);
	do {
		if (!test_bit(SPNIC_SRIOV_ENABLE, &sriov_info->state) &&
		    !test_bit(SPNIC_SRIOV_DISABLE, &sriov_info->state))
			return;

		usleep_range(9900, 10000);
	} while (time_before(jiffies, end));
}

bool spnic_get_vf_load_state(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = NULL;
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

int spnic_set_vf_load_state(struct pci_dev *pdev, bool vf_load_state)
{
	struct spnic_pcidev *pci_adapter = NULL;

	if (!pdev) {
		pr_err("pdev is null.\n");
		return -EINVAL;
	}

	pci_adapter = pci_get_drvdata(pdev);
	if (!pci_adapter) {
		sdk_err(&pdev->dev, "pci_adapter is null.\n");
		return -EINVAL;
	}

	if (sphw_func_type(pci_adapter->hwdev) == TYPE_VF)
		return 0;

	pci_adapter->disable_vf_load = !vf_load_state;
	sdk_info(&pci_adapter->pcidev->dev, "Current function %s vf load in host\n",
		 vf_load_state ? "enable" : "disable");

	return 0;
}

bool spnic_get_vf_service_load(struct pci_dev *pdev, u16 service)
{
	struct spnic_pcidev *pci_adapter = NULL;
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

int spnic_set_vf_service_load(struct pci_dev *pdev, u16 service, bool vf_srv_load)
{
	struct spnic_pcidev *pci_adapter = NULL;

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

	if (sphw_func_type(pci_adapter->hwdev) == TYPE_VF)
		return 0;

	pci_adapter->disable_srv_load[service] = !vf_srv_load;
	sdk_info(&pci_adapter->pcidev->dev, "Current function %s vf load in host\n",
		 vf_srv_load ? "enable" : "disable");

	return 0;
}

static int enable_vf_service_state(struct spnic_pcidev *dst_dev, u16 service)
{
	int err;

	err = sphw_get_dev_cap(dst_dev->hwdev);
	if (err) {
		sdk_err(&dst_dev->pcidev->dev, "Failed to get current device capabilities\n");
		return -EFAULT;
	}
	return attach_uld(dst_dev, service, &g_uld_info[service]);
}

int spnic_set_vf_service_state(struct pci_dev *pdev, u16 vf_func_id, u16 service, bool en)
{
	struct spnic_pcidev *dev = NULL;
	struct spnic_pcidev *dst_dev = NULL;
	int err = -EFAULT;

	if (!pdev)
		return -EINVAL;

	dev = pci_get_drvdata(pdev);
	if (!dev)
		return -EFAULT;

	if (service >= SERVICE_T_MAX) {
		sdk_err(&pdev->dev, "Current vf do not supports set service_type = %u state in host\n",
			service);
		return -EFAULT;
	}

	/* find func_idx pci_adapter and disable or enable service */
	lld_hold();
	list_for_each_entry(dst_dev, &dev->chip_node->func_list, node) {
		if (sphw_global_func_id(dst_dev->hwdev) != vf_func_id)
			continue;
		if (en) {
			err = enable_vf_service_state(dst_dev, service);
			if (err)
				sdk_err(&dev->pcidev->dev, "Failed to set functio_id = %u service_type = %u\n",
					vf_func_id, service);
		} else {
			detach_uld(dst_dev, service);
			err = 0;
		}
		break;
	}
	lld_put();

	return err;
}

static void spnic_remove(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = pci_get_drvdata(pdev);

	if (!pci_adapter)
		return;

	sdk_info(&pdev->dev, "Pcie device remove begin\n");

	sphw_detect_hw_present(pci_adapter->hwdev);

	if (sphw_func_type(pci_adapter->hwdev) != TYPE_VF) {
		wait_sriov_cfg_complete(pci_adapter);
		spnic_pci_sriov_disable(pdev);
	}

	spnic_func_deinit(pdev);

	lld_lock_chip_node();
	free_chip_node(pci_adapter);
	lld_unlock_chip_node();

	unmapping_bar(pci_adapter);
	spnic_pci_deinit(pdev);

	sdk_info(&pdev->dev, "Pcie device removed\n");
}

static int spnic_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct spnic_pcidev *pci_adapter = NULL;
	int err;

	sdk_info(&pdev->dev, "Pcie device probe begin\n");

	if (pdev->is_virtfn && (!spnic_get_vf_load_state(pdev))) {
		sdk_info(&pdev->dev, "VF device disable load in host\n");
		return 0;
	}

	err = spnic_pci_init(pdev);
	if (err)
		return err;

	pci_adapter = pci_get_drvdata(pdev);
	err = mapping_bar(pdev, pci_adapter);
	if (err) {
		sdk_err(&pdev->dev, "Failed to map bar\n");
		goto map_bar_failed;
	}

	pci_adapter->disable_vf_load = disable_vf_load;
	pci_adapter->id = *id;
	lld_dev_cnt_init(pci_adapter);

	/* if chip information of pcie function exist, add the function into chip */
	lld_lock_chip_node();
	err = alloc_chip_node(pci_adapter);
	if (err) {
		lld_unlock_chip_node();
		sdk_err(&pdev->dev,
			"Failed to add new chip node to global list\n");
		goto alloc_chip_node_fail;
	}

	lld_unlock_chip_node();

	err = spnic_func_init(pdev, pci_adapter);
	if (err)
		goto func_init_err;

	if (sphw_func_type(pci_adapter->hwdev) != TYPE_VF) {
		err = sphw_set_bdf_ctxt(pci_adapter->hwdev, pdev->bus->number,
					PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
		if (err) {
			sdk_err(&pdev->dev, "Failed to set BDF info to MPU\n");
			goto set_bdf_err;
		}
	}

	return 0;

set_bdf_err:
	spnic_func_deinit(pdev);

func_init_err:
	lld_lock_chip_node();
	free_chip_node(pci_adapter);
	lld_unlock_chip_node();

alloc_chip_node_fail:
	unmapping_bar(pci_adapter);

map_bar_failed:
	spnic_pci_deinit(pdev);

	sdk_err(&pdev->dev, "Pcie device probe failed\n");
	return err;
}

static const struct pci_device_id spnic_pci_table[] = {
	{PCI_VDEVICE(RAMAXEL, SPNIC_DEV_ID_PF_STD), 0},
	{PCI_VDEVICE(RAMAXEL, SPNIC_DEV_ID_VF), 0},
	{PCI_VDEVICE(RAMAXEL, SPNIC_DEV_ID_VF_HV), 0},
	{0, 0}
};

MODULE_DEVICE_TABLE(pci, spnic_pci_table);

/**
 * spnic_io_error_detected - called when PCI error is detected
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
static pci_ers_result_t spnic_io_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct spnic_pcidev *pci_adapter = NULL;

	sdk_err(&pdev->dev,
		"Uncorrectable error detected, log and cleanup error status: 0x%08x\n",
		state);

	pci_aer_clear_nonfatal_status(pdev);
	pci_adapter = pci_get_drvdata(pdev);

	if (pci_adapter)
		sphw_record_pcie_error(pci_adapter->hwdev);

	return PCI_ERS_RESULT_CAN_RECOVER;
}

static void spnic_shutdown(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = pci_get_drvdata(pdev);

	sdk_err(&pdev->dev, "Shutdown device\n");

	if (pci_adapter)
		sphw_shutdown_hwdev(pci_adapter->hwdev);

	pci_disable_device(pdev);
}

/* Cause we only need error detecting not error handling, so only error_detected
 * callback is enough.
 */
static struct pci_error_handlers spnic_err_handler = {
	.error_detected = spnic_io_error_detected,
};

static struct pci_driver spnic_driver = {
	.name		 = SPNIC_NIC_DRV_NAME,
	.id_table	 = spnic_pci_table,
	.probe		 = spnic_probe,
	.remove		 = spnic_remove,
	.shutdown	 = spnic_shutdown,
	.sriov_configure = spnic_pci_sriov_configure,
	.err_handler	 = &spnic_err_handler
};

static __init int spnic_lld_init(void)
{
	int err;

	pr_info("%s - version %s\n", SPNIC_DRV_DESC, SPNIC_DRV_VERSION);
	memset(g_uld_info, 0, sizeof(g_uld_info));

	spnic_lld_lock_init();

	err = spnic_register_uld(SERVICE_T_NIC, &nic_uld_info);
	if (err) {
		pr_err("Register spnic uld failed\n");
		return err;
	}

	return pci_register_driver(&spnic_driver);
}

static __exit void spnic_lld_exit(void)
{
	pci_unregister_driver(&spnic_driver);
	spnic_unregister_uld(SERVICE_T_NIC);
}

module_init(spnic_lld_init);
module_exit(spnic_lld_exit);
