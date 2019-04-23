// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/acpi.h>
#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/if_vlan.h>
#include <net/rtnetlink.h>
#include "../../kcompat.h"
#include "../../hns3pf/hclge_cmd.h"
#include "../../hns3pf/hclge_main.h"
#include "../../hnae3.h"
#include "hclge_ext.h"
#include "hclge_main_it.h"
#include "../../hns3pf/hclge_err.h"

#ifdef CONFIG_HNS3_TEST
#include "hclge_test.h"
#endif

#ifdef CONFIG_EXT_TEST

#define HCLGE_RESET_MAX_FAIL_CNT	1

static nic_event_fn_t nic_event_call;

int nic_register_event(nic_event_fn_t event_call)
{
	if (!event_call) {
		pr_err("register event handle is null.\n");
		return -EINVAL;
	}

	nic_event_call = event_call;

	pr_info("netdev register success.\n");
	return 0;
}
EXPORT_SYMBOL(nic_register_event);

int nic_unregister_event(void)
{
	nic_event_call = NULL;
	return 0;
}
EXPORT_SYMBOL(nic_unregister_event);

void nic_call_event(struct net_device *netdev,
		    enum hnae3_reset_type_custom event_t)
{
	if (nic_event_call)
		nic_event_call(netdev, event_t);

	netdev_info(netdev, "report reset event %d\n", event_t);
}
EXPORT_SYMBOL(nic_call_event);

bool hclge_reset_done_it(struct hnae3_handle *handle,  bool done)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct net_device *netdev;

	netdev = hdev->vport[0].nic.netdev;

	if (done) {
		dev_info(&hdev->pdev->dev, "Report Reset DONE!\n");
		nic_call_event(netdev, HNAE3_RESET_DONE_CUSTOM);
	}

	if (hdev->reset_fail_cnt >= HCLGE_RESET_MAX_FAIL_CNT) {
		dev_err(&hdev->pdev->dev, "Report Reset fail!\n");
		nic_call_event(netdev, HNAE3_PORT_FAULT);
	}

	return done;
}

pci_ers_result_t hclge_handle_hw_ras_error_it(struct hnae3_ae_dev *ae_dev)
{
	struct hclge_dev *hdev = ae_dev->priv;
	struct device *dev = &hdev->pdev->dev;
	enum hnae3_reset_type_custom reset_type;
	struct net_device *netdev;
	u32 status;

	netdev = hdev->vport[0].nic.netdev;

	status = hclge_read_dev(&hdev->hw, HCLGE_RAS_PF_OTHER_INT_STS_REG);

	if (status & HCLGE_RAS_REG_NFE_MASK ||
	    status & HCLGE_RAS_REG_ROCEE_ERR_MASK)
		ae_dev->hw_err_reset_req = 0;

	/* Handling Non-fatal HNS RAS errors */
	if (status & HCLGE_RAS_REG_NFE_MASK) {
		dev_warn(dev,
			 "HNS Non-Fatal RAS error(status=0x%x) identified\n",
			 status);
		hclge_handle_all_ras_errors(hdev);

		reset_type = ae_dev->ops->set_default_reset_request(ae_dev,
			&ae_dev->hw_err_reset_req);

		if (reset_type != HNAE3_NONE_RESET_CUSTOM)
			nic_call_event(netdev, reset_type);
	} else {
		if (test_bit(HCLGE_STATE_RST_HANDLING, &hdev->state) ||
		    hdev->pdev->revision < 0x21) {
			ae_dev->override_pci_need_reset = 1;
			return PCI_ERS_RESULT_RECOVERED;
		}
	}

	if (status & HCLGE_RAS_REG_ROCEE_ERR_MASK) {
		dev_warn(dev, "ROCEE uncorrected RAS error identified\n");
		hclge_handle_rocee_ras_error(ae_dev);
	}

	if ((status & HCLGE_RAS_REG_NFE_MASK ||
	     status & HCLGE_RAS_REG_ROCEE_ERR_MASK) &&
	    ae_dev->hw_err_reset_req) {
		ae_dev->override_pci_need_reset = 0;
		return PCI_ERS_RESULT_NEED_RESET;
	}
	ae_dev->override_pci_need_reset = 1;

	return PCI_ERS_RESULT_RECOVERED;
}

#endif

#ifdef CONFIG_IT_VALIDATION

#define HCLGE_NAME_IT			"hclge"

EXPORT_SYMBOL(hclge_get_vport);
EXPORT_SYMBOL(hclge_cmd_set_promisc_mode);
EXPORT_SYMBOL(hclge_promisc_param_init);

struct pci_device_id ae_algo_pci_tbl_it[] = {
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_GE), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_25GE), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_25GE_RDMA), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_25GE_RDMA_MACSEC), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_50GE_RDMA), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_50GE_RDMA_MACSEC), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_100G_RDMA_MACSEC), 0},

#ifdef CONFIG_HNS3_X86
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_X86_25_GE), 0},
#endif

	/* required last entry */
	{0, }
};

int hclge_init_it(void)
{
	pr_info("%s is initializing\n", HCLGE_NAME_IT);
#ifdef CONFIG_HNS3_TEST
	hclge_ops.send_cmdq = hclge_send_cmdq;
#endif

#ifdef CONFIG_EXT_TEST
	hclge_ops.handle_hw_ras_error = hclge_handle_hw_ras_error_it;
	hclge_ops.reset_done = hclge_reset_done_it;
#endif

	ae_algo.pdev_id_table = ae_algo_pci_tbl_it;
	hnae3_register_ae_algo(&ae_algo);

	return 0;
}
module_init(hclge_init_it);
#endif
