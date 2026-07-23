// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "main.h"
/* TODO: Adding this here is not ideal. Can we remove this warning now? */
#include "icrdma_hw.h"
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include "zrdma_kcompat.h"

#define DRV_VER_MAJOR 1
#define DRV_VER_MINOR 8
#define DRV_VER_BUILD 46
#define DRV_VER \
	__stringify(DRV_VER_MAJOR) "." __stringify(DRV_VER_MINOR) "." __stringify(DRV_VER_BUILD)

#define FW_MAJOR_VER 0
#define FW_MINOR_FW_VER 0
#define FW_MINOR_DRV_VER 0

#define DRV_MAJOR_VER 0
#define DRV_NET_MINOR_VER 0
#define DRV_RDMA_MINOR_VER 0
#define ZXDH_FW_VER_OFFSET 0x5400
#define MODULE_RDMA_ID 11

struct rdma_sriov_glb_info pf_sriov_glb_info[HOST_RDMA_MAX_PF] = { 0 };

static u8 resource_profile;

module_param(resource_profile, byte, 0444);
MODULE_PARM_DESC(resource_profile,
		 "Resource Profile: 0=PF only(default), 1=Weighted VF, 2=Even Distribution");

static unsigned int limits_sel = 3;

module_param(limits_sel, uint, 0444);
MODULE_PARM_DESC(limits_sel, "Resource limits selector, Range: 0-7, default=3");

static unsigned int gen1_limits_sel = 1;

module_param(gen1_limits_sel, uint, 0444);
MODULE_PARM_DESC(gen1_limits_sel, "x722 resource limits selector, Range: 0-5, default=1");

static unsigned int roce_ena = 1;

module_param(roce_ena, uint, 0444);
MODULE_PARM_DESC(
	roce_ena,
	"RoCE enable: 1=enable RoCEv2 on all ports (not supported on x722), 0=iWARP(default)");

static ulong roce_port_cfg;
module_param(roce_port_cfg, ulong, 0444);
MODULE_PARM_DESC(roce_port_cfg, "RoCEv2 per port enable: 1=port0, 2=port1 (not supported on X722)");
static bool en_rem_endpoint_trk;

module_param(en_rem_endpoint_trk, bool, 0444);
MODULE_PARM_DESC(en_rem_endpoint_trk,
		 "Remote Endpoint Tracking: 1=enabled (not supported on x722), 0=disabled(default)");

static u8 fragment_count_limit = 6;

module_param(fragment_count_limit, byte, 0444);
MODULE_PARM_DESC(
	fragment_count_limit,
	"adjust maximum values for queue depth and inline data size, default=4, Range: 2-13");

static bool dcqcn_enable;

module_param(dcqcn_enable, bool, 0444);
MODULE_PARM_DESC(dcqcn_enable, "enables DCQCN algorithm for RoCEv2 on all ports, default=false ");

static bool dcqcn_cc_cfg_valid;

module_param(dcqcn_cc_cfg_valid, bool, 0444);
MODULE_PARM_DESC(dcqcn_cc_cfg_valid, "set DCQCN parameters to be valid, default=false");

static u8 dcqcn_min_dec_factor = 1;

module_param(dcqcn_min_dec_factor, byte, 0444);
MODULE_PARM_DESC(
	dcqcn_min_dec_factor,
	"set minimum percentage factor by which tx rate can be changed for CNP, Range: 1-100, default=1");

static u8 dcqcn_min_rate_MBps;

module_param(dcqcn_min_rate_MBps, byte, 0444);
MODULE_PARM_DESC(dcqcn_min_rate_MBps,
		 "set minimum rate limit value, in MBits per second, default=0");

static u8 dcqcn_F;

module_param(dcqcn_F, byte, 0444);
MODULE_PARM_DESC(dcqcn_F,
		 "set number of times to stay in each stage of bandwidth recovery, default=0");

static unsigned short dcqcn_T;

module_param(dcqcn_T, ushort, 0444);
MODULE_PARM_DESC(
	dcqcn_T,
	"set number of usecs that should elapse before increasing the CWND in DCQCN mode, default=0");

static unsigned int dcqcn_B;

module_param(dcqcn_B, uint, 0444);
MODULE_PARM_DESC(
	dcqcn_B,
	"set number of MSS to add to the congestion window in additive increase mode, default=0");

static unsigned short dcqcn_rai_factor;

module_param(dcqcn_rai_factor, ushort, 0444);
MODULE_PARM_DESC(
	dcqcn_rai_factor,
	"set number of MSS to add to the congestion window in additive increase mode, default=0");

static unsigned short dcqcn_hai_factor;

module_param(dcqcn_hai_factor, ushort, 0444);
MODULE_PARM_DESC(
	dcqcn_hai_factor,
	"set number of MSS to add to the congestion window in hyperactive increase mode, default=0");

static unsigned int dcqcn_rreduce_mperiod;

module_param(dcqcn_rreduce_mperiod, uint, 0444);
MODULE_PARM_DESC(
	dcqcn_rreduce_mperiod,
	"set minimum time between 2 consecutive rate reductions for a single flow, default=0");

static u8 display_drv_side_fw_ver;

module_param(display_drv_side_fw_ver, byte, 0444);
MODULE_PARM_DESC(display_drv_side_fw_ver, "display fw ver, display=1, not display=0");

static u8 display_drv_side_net_ver;

module_param(display_drv_side_net_ver, byte, 0444);
MODULE_PARM_DESC(display_drv_side_net_ver, "display drv ver, display=1, not display=0");

static void zxdh_destory_eth_info_hlist(struct zxdh_device *iwdev);

MODULE_ALIAS("zrdma");
MODULE_AUTHOR("ZTE Corporation");
MODULE_DESCRIPTION("ZTE(R) Ethernet Protocol Driver for RDMA");
MODULE_LICENSE("Dual BSD/GPL");
#ifdef RDMA_VERSION
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
MODULE_VERSION(TOSTRING(RDMA_VERSION));
#else
MODULE_VERSION(DRV_VER);
#endif
int zxdh_vf_update_np_tbl(struct zxdh_pci_f *rf);

int zxdh_vf_update_np_tbl(struct zxdh_pci_f *rf)
{
	u32 cnt = 0, val = 0, status = 0;
	struct iidc_core_dev_info *cdev_info = rf->cdev;
	struct zxdh_sc_dev *dev = &rf->sc_dev;

	writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

	zxdh_sc_send_mailbox_cmd(dev, ZTE_ZXDH_OP_REQ_NP_MAC_DEL, cdev_info->vport_id,
				 ether_addr_to_u64(rf->iwdev->mac_addr), 0, rf->vf_id);

	do {
		val = readl(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE);
		if (cnt++ > ZXDH_MAILBOX_CYC_NUM * dev->hw_attrs.max_done_count) {
			pr_info("vhca_id:%d waiting completed NP_MAC_DEL mailbox too long time,timeout!\n",
				dev->vhca_id);
			status = -ETIMEDOUT;
			break;
		}
		if (dev->hw_attrs.self_health == true) {
			status = -ETIMEDOUT;
			break;
		}
		udelay(ZXDH_MAILBOX_SLEEP_TIME);
	} while (!val);

	if (!rf->iwdev->netdev->dev_addr) {
		pr_err("[%s] dev_addr is null!\n", __func__);
		status = -EINVAL;
		return status;
	}

	writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

	zxdh_sc_send_mailbox_cmd(dev, ZTE_ZXDH_OP_REQ_NP_MAC_ADD, cdev_info->vport_id,
				 ether_addr_to_u64(rf->iwdev->netdev->dev_addr), 0, rf->vf_id);

	do {
		val = readl(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE);
		if (cnt++ > ZXDH_MAILBOX_CYC_NUM * dev->hw_attrs.max_done_count) {
			pr_info("vhca_id:%d waiting completed NP_MAC_ADD mailbox too long time,timeout!\n",
				dev->vhca_id);
			status = -ETIMEDOUT;
			break;
		}
		if (dev->hw_attrs.self_health == true) {
			status = -ETIMEDOUT;
			break;
		}
		udelay(ZXDH_MAILBOX_SLEEP_TIME);
	} while (!val);

	return status;
}

void zxdh_update_dpp_mac_tbl(struct zxdh_device *iwdev, struct iidc_core_dev_info *cdev_info)
{
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_pci_f *rf = iwdev->rf;

	pf_info.vport = cdev_info->vport_id;
	pf_info.slot = cdev_info->slot_id;
	if (iwdev->rf->sc_dev.np_mode_low_lat) {
		if (!iwdev->netdev->dev_addr) {
			pr_err("[%s] dev_addr is null!\n", __func__);
			return;
		}

		if (ether_addr_cmp(iwdev->mac_addr, iwdev->netdev->dev_addr) == 0) {
			pr_warn("%s[%d]: mac_addr is equal to dev_addr(%02x:%02x:%02x:%02x:%02x:%02x)\n",
				__func__, __LINE__, iwdev->mac_addr[0], iwdev->mac_addr[1],
				iwdev->mac_addr[2], iwdev->mac_addr[3], iwdev->mac_addr[4],
				iwdev->mac_addr[5]);
		}

		if (!iwdev->rf->ftype) {
			pr_info("%s[%d]: dpp del/add rdma trans item\n", __func__, __LINE__);
			dpp_del_rdma_trans_item(&pf_info, iwdev->mac_addr);
			dpp_add_rdma_trans_item(&pf_info, iwdev->netdev->dev_addr,
						iwdev->rf->sc_dev.vhca_id);
		} else {
			zxdh_vf_update_np_tbl(rf);
		}
		ether_addr_copy(iwdev->mac_addr, iwdev->netdev->dev_addr);
	}
}

static enum ib_port_state get_port_state(struct net_device *netdev)
{
	if (netif_carrier_ok(netdev) && netif_running(netdev))
		return IB_PORT_ACTIVE;

	return IB_PORT_DOWN;
}

static int zxdh_netdevice_event(struct notifier_block *not_blk, unsigned long event, void *arg)
{
	struct ib_device *ibdev;
	struct zxdh_device *iwdev;
	enum ib_port_state state;
	struct net_device *netdev = netdev_notifier_info_to_dev(arg);

	ibdev = ib_device_get_by_netdev(netdev, RDMA_DRIVER_ZXDH);
	if (!ibdev)
		return NOTIFY_DONE;
	iwdev = to_iwdev(ibdev);

	switch (event) {
	case NETDEV_CHANGE:
	case NETDEV_UP:
	case NETDEV_DOWN:
		if (!refcount_read(&iwdev->trace_switch.t_switch))
			break;
		state = get_port_state(netdev);
		if (state == IB_PORT_ACTIVE)
			ibdev_notice(ibdev, "IB port up\n");
		else
			ibdev_notice(ibdev, "IB port down\n");
		break;
	case NETDEV_CHANGEMTU:
		pr_info("%s changed mtu to %d\n", netdev->name, netdev->mtu);
		break;
	case NETDEV_CHANGEADDR:
		pr_info("%s[%d]: process NETDEV_CHANGEADDR event,update dpp mac tbl\n", __func__,
			__LINE__);
		zxdh_update_dpp_mac_tbl(iwdev, iwdev->rf->cdev);
		break;
	default:
		pr_info("%s[%d]: ignoring netdev event=%ld for %s\n", __func__, __LINE__, event,
			netdev->name);
		break;
	}

	ib_device_put(ibdev);
	return NOTIFY_DONE;
}

static struct notifier_block zxdh_netdevice_notifier = { .notifier_call = zxdh_netdevice_event };

static void zxdh_register_notifiers(void)
{
	register_netdevice_notifier(&zxdh_netdevice_notifier);
}

static void zxdh_unregister_notifiers(void)
{
	unregister_netdevice_notifier(&zxdh_netdevice_notifier);
}

extern struct zxdh_rdma_hb_if hwbond_ops;
/**
 * set_protocol_used - set protocol_used against HW generation and roce_ena flag
 * @rf: RDMA PCI function
 * @roce_ena: RoCE enabled bit flag
 */
static inline void set_protocol_used(struct zxdh_pci_f *rf, uint roce_ena)
{
	switch (rf->rdma_ver) {
	case ZXDH_GEN_2:
		rf->protocol_used = roce_ena & BIT(PCI_FUNC(rf->pcidev->devfn)) ?
						  ZXDH_ROCE_PROTOCOL_ONLY :
						  ZXDH_IWARP_PROTOCOL_ONLY;

		break;
	case ZXDH_GEN_1:
		rf->protocol_used = ZXDH_IWARP_PROTOCOL_ONLY;
		break;
	}
}

/**
 * zxdh_set_rf_user_cfg_params - Setup RF configurations from module parameters
 * @rf: RDMA PCI function
 */
void zxdh_set_rf_user_cfg_params(struct zxdh_pci_f *rf)
{
	/*TODO: Fixup range checks on all integer module params */
	if (limits_sel > 7)
		limits_sel = 7;

	if (gen1_limits_sel > 5)
		gen1_limits_sel = 5;

	rf->limits_sel = (rf->rdma_ver == ZXDH_GEN_1) ? gen1_limits_sel : limits_sel;
	if (roce_ena)
		pr_warn_once("zrdma: Because roce_ena is ENABLED, roce_port_cfg will be ignored.");
	set_protocol_used(rf, roce_ena ? 0xFFFFFFFF : roce_port_cfg);
	rf->rsrc_profile = (resource_profile < ZXDH_HMC_PROFILE_EQUAL) ?
					 (u8)resource_profile + ZXDH_HMC_PROFILE_DEFAULT :
					 ZXDH_HMC_PROFILE_DEFAULT;

	rf->en_rem_endpoint_trk = en_rem_endpoint_trk;
	rf->fragcnt_limit = fragment_count_limit;
	if (rf->fragcnt_limit > 13 || rf->fragcnt_limit < 2) {
		rf->fragcnt_limit = 6;
		pr_warn_once(
			"zrdma: Requested [%d] fragment count limit out of range (2-13), setting to default=6.",
			fragment_count_limit);
	}
	rf->dcqcn_ena = dcqcn_enable;

	/* Skip over all checking if no dcqcn */
	if (!dcqcn_enable)
		return;

	rf->dcqcn_params.cc_cfg_valid = dcqcn_cc_cfg_valid;
	rf->dcqcn_params.dcqcn_b = dcqcn_B;

#define DCQCN_B_MAX GENMASK(25, 0)
	if (rf->dcqcn_params.dcqcn_b > DCQCN_B_MAX) {
		rf->dcqcn_params.dcqcn_b = DCQCN_B_MAX;
		pr_warn_once("zrdma: Requested [%d] dcqcn_b value too high, setting to %d.",
			     dcqcn_B, rf->dcqcn_params.dcqcn_b);
	}

#define DCQCN_F_MAX 8
	rf->dcqcn_params.dcqcn_f = dcqcn_F;
	if (dcqcn_F > DCQCN_F_MAX) {
		rf->dcqcn_params.dcqcn_f = DCQCN_F_MAX;
		pr_warn_once("zrdma: Requested [%d] dcqcn_f value too high, setting to %d.",
			     dcqcn_F, DCQCN_F_MAX);
	}

	rf->dcqcn_params.dcqcn_t = dcqcn_T;
	rf->dcqcn_params.hai_factor = dcqcn_hai_factor;
	rf->dcqcn_params.min_dec_factor = dcqcn_min_dec_factor;
	if (dcqcn_min_dec_factor < 1 || dcqcn_min_dec_factor > 100) {
		rf->dcqcn_params.dcqcn_b = 1;
		pr_warn_once(
			"zrdma: Requested [%d] dcqcn_min_dec_factor out of range (1-100) , setting to default=1",
			dcqcn_min_dec_factor);
	}

	rf->dcqcn_params.min_rate = dcqcn_min_rate_MBps;
	rf->dcqcn_params.rai_factor = dcqcn_rai_factor;
	rf->dcqcn_params.rreduce_mperiod = dcqcn_rreduce_mperiod;
}

static void zxdh_iidc_event_handler(struct iidc_core_dev_info *cdev_info, struct iidc_event *event)
{
}

/**
 * zxdh_request_reset - Request a reset
 * @rf: RDMA PCI function
 */
static void zxdh_request_reset(struct zxdh_pci_f *rf)
{
	struct iidc_core_dev_info *cdev_info = rf->cdev;

	if (rf->sc_dev.hw_attrs.self_health == false)
		dev_warn(idev_to_dev(&rf->sc_dev), "Requesting a reset\n");
	rf->sc_dev.vchnl_up = false;
	cdev_info->ops->request_reset(rf->cdev, IIDC_PFR);
}

/**
 * zxdh_dev_ibevent - indicate dev event
 * @iwdev: zrdma device
 */
static void zxdh_dev_ibevent(struct zxdh_device *iwdev)
{
	struct ib_event event;

	event.device = &iwdev->ibdev;
	event.element.port_num = 1;
	event.event = IB_EVENT_DEVICE_FATAL;
	ib_dispatch_event(&event);
}

static int rdma_get_rp_link_status(struct pci_dev *pdev)
{
	struct pci_dev *rp_dev = NULL;
	int pcie_cap = 0;
	u16 data = 0;

	rp_dev = pcie_find_root_port(pdev);
	if (!rp_dev) {
		pr_err("rdma can not find RP\n");
		return -ENODEV;
	}
	pcie_cap = pci_find_capability(rp_dev, PCI_CAP_ID_EXP);
	if (!pcie_cap) {
		pr_err("rdma can not find PCI Express CAP\n");
		return -ENXIO;
	}
	pci_read_config_word(rp_dev, pcie_cap + PCI_EXP_LNKSTA, &data);
	return (data & PCI_EXP_LNKSTA_DLLLA) ? ZXDH_PCIE_LINK_UP : ZXDH_PCIE_LINK_DOWN;
}

static int rdma_get_upstream_port_link_status(struct pci_dev *pdev)
{
	struct pci_dev *up_stream_dev = NULL;
	int pcie_cap = 0;
	u16 data = 0;

	up_stream_dev = pci_upstream_bridge(pdev);
	if (!up_stream_dev) {
		pr_err("rdma can not find RP\n");
		return -ENODEV;
	}
	pcie_cap = pci_find_capability(up_stream_dev, PCI_CAP_ID_EXP);
	if (!pcie_cap) {
		pr_err("rdma can not find PCI Express CAP\n");
		return -ENXIO;
	}
	pci_read_config_word(up_stream_dev, pcie_cap + PCI_EXP_LNKSTA, &data);
	return (data & PCI_EXP_LNKSTA_DLLLA) ? ZXDH_PCIE_LINK_UP : ZXDH_PCIE_LINK_DOWN;
}

static int zxdh_rdma_check_remove_state(struct pci_dev *pdev)
{
	if (!rdma_get_rp_link_status(pdev))
		return ZXDH_PCIE_LINK_DOWN;

	return rdma_get_upstream_port_link_status(pdev);
}

static int zxdh_rdma_hotplug_event(struct zxdh_pci_f *rf)
{
	struct zxdh_ceq *iwceq;
	u32 i;

	if (!rf)
		return -ENODEV;

	rf->sc_dev.hw_attrs.cqp_timeout_threshold = CQP_MIN_TIMEOUT_THRESHOLD;
	rf->sc_dev.hw_attrs.max_done_count = ZXDH_MIN_DONE_COUNT;
	rf->sc_dev.hw_attrs.self_health = true;

	if (rf->aeq.irq_sta == true) {
		rf->aeq.irq_sta = false;
		irq_set_affinity_hint(rf->aeq.irq, NULL);
		free_irq(rf->aeq.irq, rf);
	}

	for (i = 0; i < rf->ceqs_count; i++) {
		iwceq = &rf->ceqlist[i];
		if (iwceq->irq_sta == true) {
			iwceq->irq_sta = false;
			irq_set_affinity_hint(iwceq->irq, NULL);
			free_irq(iwceq->irq, iwceq);
		}
	}
	pr_info("vhca_id:%d rdma quick remove start\n", rf->sc_dev.vhca_id);
	return 0;
}
static int process_rdma_health_event(struct net_device *netdev)
{
	struct zxdh_device *iwdev;
	struct zxdh_pci_f *rf;
	struct zxdh_ceq *iwceq;
	u32 i;

	iwdev = zxdh_device_get_by_source_netdev(netdev);
	if (!iwdev)
		return -ENODEV;
	rf = iwdev->rf;
	if (!rf)
		return -ENODEV;

	rf->sc_dev.hw_attrs.cqp_timeout_threshold = CQP_MIN_TIMEOUT_THRESHOLD;
	rf->sc_dev.hw_attrs.max_done_count = ZXDH_MIN_DONE_COUNT;
	rf->sc_dev.hw_attrs.self_health = true;

	if (rf->aeq.irq_sta == true) {
		rf->aeq.irq_sta = false;
		irq_set_affinity_hint(rf->aeq.irq, NULL);
		free_irq(rf->aeq.irq, rf);
	}

	for (i = 0; i < rf->ceqs_count; i++) {
		iwceq = &rf->ceqlist[i];
		if (iwceq->irq_sta == true) {
			iwceq->irq_sta = false;
			irq_set_affinity_hint(iwceq->irq, NULL);
			free_irq(iwceq->irq, iwceq);
		}
	}
	zxdh_dev_ibevent(iwdev);

	pr_info("vhca_id:%d rdma_self_health\n", rf->sc_dev.vhca_id);
	return 0;
}

static struct zxdh_pci_f *zxdh_get_rf_from_pdev(struct pci_dev *pdev)
{
	struct zxdh_pci_f *rf = NULL;
	int i;

	for (i = 0; i < HOST_RDMA_MAX_PF; i++) {
		if (pf_sriov_glb_info[i].rdma_pf_enable && pf_sriov_glb_info[i].pdev == pdev) {
			rf = pf_sriov_glb_info[i].rf;
			break;
		}
	}

	return rf;
}

static void update_vf_pblem_info(struct zxdh_sc_dev *dev, u16 num_vfs, u64 vf_pblem_cnt)
{
	struct zxdh_vfdev *vf_dev = NULL;
	struct zxdh_hmc_obj_info *hmc_obj;
	u16 vf_id;

	dev->hmc_pf_manager_info.vf_pblemr_cnt = vf_pblem_cnt;
	pr_info("%s %d Update vf pblem cnt to 0x%llx\n", __func__, __LINE__, vf_pblem_cnt);

	for (vf_id = 0; vf_id < num_vfs; vf_id++) {
		vf_dev = zxdh_find_vf_dev(dev, vf_id);
		if (vf_dev) {
			hmc_obj = vf_dev->hmc_info.hmc_obj;
			hmc_obj[ZXDH_HMC_IW_PBLE_MR].max_cnt =
				dev->hmc_pf_manager_info.vf_pblemr_cnt;
			hmc_obj[ZXDH_HMC_IW_PBLE_MR].cnt = dev->hmc_pf_manager_info.vf_pblemr_cnt;
			hmc_obj[ZXDH_HMC_IW_PBLE_MR].size =
				dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE_MR].size;
			hmc_obj[ZXDH_HMC_IW_PBLE_MR].type =
				dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE_MR].type;
			hmc_obj[ZXDH_HMC_IW_PBLE_MR].base =
				dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE_MR].base +
				(dev->hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE_MR].cnt +
				 hmc_obj[ZXDH_HMC_IW_PBLE_MR].cnt * vf_id) *
					hmc_obj[ZXDH_HMC_IW_PBLE_MR].size;
			zxdh_put_vfdev(dev, vf_dev);
			vf_dev = NULL;
		} else {
			continue;
		}
	}
}

static int process_rdma_sriov_event(void *data)
{
	struct zxdh_rdma_sriov_event_info *sriov_info;
	struct zxdh_pci_f *rf;
	u64 vf_pblem_cnt;
	int ret = 0;

	if (!data)
		return -EINVAL;

	sriov_info = (struct zxdh_rdma_sriov_event_info *)data;
	rf = zxdh_get_rf_from_pdev(sriov_info->pdev);
	if (rf && rf->sc_dev.active_vfs_num == sriov_info->num_vfs)
		return 0;

	ret = set_rdma_vf_num(sriov_info, &vf_pblem_cnt);
	if (ret) {
		pr_err("%s set_rdma_vf_num failed, ret=%d\n", __func__, ret);
		return ret;
	}

	if (rf) {
		rf->sc_dev.active_vfs_num = sriov_info->num_vfs;
		update_vf_pblem_info(&rf->sc_dev, sriov_info->num_vfs, vf_pblem_cnt);
	}

	return 0;
}

/***
 * @brief zxdh_rdma event handler
 *
 * @param netdev zxdh_net device，Netdev is the network structure pointer
 * corresponding to the PF or VF that needs to release resources
 * @param event_type，Types of events handled
 * @param data，Incoming parameters, default NULL
 * @return Return value 0 is OK, error is another value
 */
static int zxdh_rdma_event_handler(struct net_device *netdev, u8 event_type, void *data)
{
	int ret = 0;

	switch (event_type) {
	case ZXDH_RDMA_HEALTH_EVENT:
		ret = process_rdma_health_event(netdev);
		break;
	case ZXDH_RDMA_SRIOV_EVENT:
		ret = process_rdma_sriov_event(data);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static u32 zxdh_get_sq_delta(u32 head, u32 tail, u32 size)
{
	u32 delta = 0;

	if ((head > size) || (tail > size))
		return delta;
	if (head > tail)
		delta = (head - tail);
	else if (head < tail)
		delta = (head + size - tail);

	return delta;
}

static void zxdh_self_health_wait_res_free(u32 delta)
{
	if (delta <= 10)
		mdelay(5);
	else if (delta <= 26)
		mdelay(15);
	else if (delta <= 50)
		mdelay(30);
	else if (delta <= 100)
		mdelay(100);
	else if (delta <= 150)
		mdelay(150);
	else
		mdelay(200);
}

void zxdh_handle_internal_error(struct zxdh_pci_f *rf)
{
	struct zxdh_qp *qp;
	struct zxdh_cq *send_cq;
	struct zxdh_sc_dev *dev;
	__le64 *cqe;
	unsigned long flags_qp;
	unsigned long flags_cp;
	u32 wqe_idx;
	u64 hdr;
	bool wait_flag = false;
	struct zxdh_ring temp_sq_ring;
	struct zxdh_cq_uk temp_cq;
	u32 delta = 0;

	qp = rf->iwdev->qp1;
	if (!qp)
		return;

	dev = &rf->sc_dev;
	if (!dev)
		return;

	if (dev->hw_attrs.self_health == false)
		return;
	spin_lock_irqsave(&qp->lock, flags_qp);
	if (ZXDH_RING_CURRENT_HEAD(qp->sc_qp.qp_uk.sq_ring) !=
	    ZXDH_RING_CURRENT_TAIL(qp->sc_qp.qp_uk.sq_ring)) {
		delta = zxdh_get_sq_delta(qp->sc_qp.qp_uk.sq_ring.head,
					  qp->sc_qp.qp_uk.sq_ring.tail,
					  qp->sc_qp.qp_uk.sq_ring.size);
		wait_flag = true;
		temp_sq_ring.head = qp->sc_qp.qp_uk.sq_ring.head;
		temp_sq_ring.tail = qp->sc_qp.qp_uk.sq_ring.tail;
		temp_sq_ring.size = qp->sc_qp.qp_uk.sq_ring.size;
		pr_info("%s vhca_id:%d\n", __func__, dev->vhca_id);
		send_cq = qp->iwscq;
		temp_cq.cq_base = send_cq->sc_cq.cq_uk.cq_base;
		temp_cq.cq_ring.head = send_cq->sc_cq.cq_uk.cq_ring.head;
		temp_cq.cq_ring.tail = send_cq->sc_cq.cq_uk.cq_ring.tail;
		temp_cq.cq_ring.size = send_cq->sc_cq.cq_uk.cq_ring.size;
		temp_cq.polarity = send_cq->sc_cq.cq_uk.polarity;
		spin_lock_irqsave(&send_cq->lock, flags_cp);
		if (!send_cq->user_mode)
			send_cq->armed = false;
		if (send_cq->ibcq.comp_handler && (send_cq->sc_cq.cq_uk.valid_cq == true)) {
			do {
				cqe = ZXDH_GET_CURRENT_EXTENDED_CQ_ELEM(&temp_cq);
				set_64bit_val(cqe, 8, qp->ctx_info.qp_compl_ctx);
				set_64bit_val(cqe, 24, 0);
				hdr = FIELD_PREP(IRDMACQ_QPID, qp->ibqp.qp_num);

				dma_wmb(); /* make sure WQE is written before valid bit is set */
				set_64bit_val(cqe, 16, hdr);
				wqe_idx = ZXDH_RING_CURRENT_TAIL(temp_sq_ring);
				hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_OP_TYPE_UD_SEND) |
				      FIELD_PREP(ZXDH_CQ_WQEIDX, wqe_idx) |
				      FIELD_PREP(ZXDH_CQ_ERROR, 1) |
				      FIELD_PREP(ZXDH_CQ_MAJERR, ZXDH_FLUSH_MAJOR_ERR) |
				      FIELD_PREP(ZXDH_CQ_MINERR, FLUSH_GENERAL_ERR) |
				      FIELD_PREP(IRDMACQ_SOEVENT, 1) |
				      FIELD_PREP(ZXDH_CQ_VALID, temp_cq.polarity) |
				      FIELD_PREP(ZXDH_CQ_SQ, ZXDH_CQE_QTYPE_SQ) |
				      FIELD_PREP(ZXDH_CQ_TYPE, 0);
				dma_wmb(); /* make sure WQE is written before valid bit is set */

				set_64bit_val(cqe, 0, hdr);
				pr_info("%s vhca_id:%d wqe_idx:%d sq_head:%d sq_tail:%d cq_head:%d\n",
					__func__, dev->vhca_id, wqe_idx, temp_sq_ring.head,
					temp_sq_ring.tail, temp_cq.cq_ring.head);
				ZXDH_RING_SET_TAIL(
					temp_sq_ring,
					wqe_idx + qp->sc_qp.qp_uk.sq_wrtrk_array[wqe_idx].quanta);
				ZXDH_RING_MOVE_HEAD_NOCHECK(temp_cq.cq_ring);
				if (!ZXDH_RING_CURRENT_HEAD(temp_cq.cq_ring))
					temp_cq.polarity ^= 1;
			} while (temp_sq_ring.head != temp_sq_ring.tail);
			send_cq->ibcq.comp_handler(&send_cq->ibcq, send_cq->ibcq.cq_context);
		}
		spin_unlock_irqrestore(&send_cq->lock, flags_cp);
	}
	spin_unlock_irqrestore(&qp->lock, flags_qp);
	if (wait_flag == true) {
		cancel_delayed_work_sync(&qp->dwork_flush);
		zxdh_self_health_wait_res_free(delta);
	}
}

static void zxdh_store_rdma_pf_glb(struct zxdh_pci_f *rf)
{
	int i;

	for (i = 0; i < HOST_RDMA_MAX_PF; i++) {
		if (pf_sriov_glb_info[i].rdma_pf_enable) {
			continue;
		} else {
			pf_sriov_glb_info[i].pdev = rf->pcidev;
			pf_sriov_glb_info[i].rf = rf;
			pf_sriov_glb_info[i].rdma_pf_enable = true;
			break;
		}
	}

	if (i >= HOST_RDMA_MAX_PF)
		pr_err("rdma_pf_num over limit:%d\n", HOST_RDMA_MAX_PF);
}

static void zxdh_delete_rdma_pf_glb(struct zxdh_pci_f *rf)
{
	int i;

	for (i = 0; i < HOST_RDMA_MAX_PF; i++) {
		if (pf_sriov_glb_info[i].rdma_pf_enable && pf_sriov_glb_info[i].rf == rf) {
			pf_sriov_glb_info[i].pdev = NULL;
			pf_sriov_glb_info[i].rf = NULL;
			pf_sriov_glb_info[i].rdma_pf_enable = false;
			break;
		}
	}
}

static int zxdh_remove(struct zxdh_auxiliary_device *aux_dev)
{
	u32 cnt = 0, val = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct iidc_auxiliary_dev *iidc_adev =
		container_of(aux_dev, struct iidc_auxiliary_dev, adev);
	struct iidc_core_dev_info *cdev_info = iidc_adev->cdev_info;
	struct zxdh_device *iwdev = dev_get_drvdata(&aux_dev->dev);
	struct zxdh_sc_dev *dev = &iwdev->rf->sc_dev;
	u64 cqp_status_phy_addr = 0;
	u32 cqp_status = 0xFFFF;
	int ret = 0;

	if (zxdh_rdma_check_remove_state(iwdev->rf->pcidev) == ZXDH_PCIE_LINK_DOWN)
		zxdh_rdma_hotplug_event(iwdev->rf);

	dev->driver_load = false;
	if ((iwdev->rf->ftype == 0) && (dev->hw_attrs.self_health == false)) {
		pf_info.vport = cdev_info->vport_id;
		pf_info.slot = cdev_info->slot_id;
		pr_info("%s[%d]: dpp del rdma trans item\n", __func__, __LINE__);
		dpp_del_rdma_trans_item(&pf_info, iwdev->mac_addr);
	}

	if ((iwdev->rf->ftype == 1) && (dev->hw_attrs.self_health == false)) {
		cqp_status_phy_addr =
			C_RDMA_CQP_STATUS_PHY_ADDR + iwdev->rf->sc_dev.vhca_id_pf * 0x1000;
		ret = zxdh_rdma_reg_read(iwdev->rf, cqp_status_phy_addr, &cqp_status);
		if (ret) {
			pr_err("%s[%d]: rdma reg read failed!\n", __func__, __LINE__);
			goto clean_ib_resource;
		}

		pr_info("vf remove: ep_id=%d,pf_id=%d,vf_id=%d,vhca_id=%d, vhca_id_pf=%d,cqp_status=%d\n",
			iwdev->rf->ep_id, iwdev->rf->pf_id, iwdev->rf->vf_id,
			iwdev->rf->sc_dev.vhca_id, iwdev->rf->sc_dev.vhca_id_pf, cqp_status);

		if (cqp_status != 1) {
			pr_err("vf rdma remove: The RDMA device for EP%d PF%d corresponding to VF%d does not exist!\n",
			       iwdev->rf->ep_id, iwdev->rf->pf_id, iwdev->rf->vf_id);
			goto clean_ib_resource;
		}

		if (!dev->hmc_use_dpu_ddr) {
			pr_info("[%s]  hmc_use_dpu_ddr: %d\n", __func__, dev->hmc_use_dpu_ddr);
			zxdh_set_smmu_invalid(iwdev->rf);
		}

		if (iwdev->rf->sc_dev.np_mode_low_lat) {
			writel(0,
			       (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

			zxdh_sc_send_mailbox_cmd(&iwdev->rf->sc_dev, ZTE_ZXDH_OP_REQ_NP_MAC_DEL,
						 cdev_info->vport_id,
						 ether_addr_to_u64(iwdev->mac_addr), 0,
						 iwdev->rf->vf_id);

			do {
				val = readl(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE);
				if (cnt++ > 200 * dev->hw_attrs.max_done_count) {
					pr_info("vhca_id:%d waiting completed NP_MAC_DEL mailbox too long time,timeout!\n",
						dev->vhca_id);
					break;
				}
				if (dev->hw_attrs.self_health == true)
					break;
				udelay(dev->hw_attrs.max_sleep_count);
			} while (!val);
		}

		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

		zxdh_sc_send_mailbox_cmd(&iwdev->rf->sc_dev, ZTE_ZXDH_OP_DEL_HMC_OBJ_RANGE,
					 cdev_info->vport_id, ether_addr_to_u64(iwdev->mac_addr), 0,
					 iwdev->rf->vf_id);

		do {
			val = readl(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE);
			if (cnt++ > 200 * dev->hw_attrs.max_done_count) {
				pr_info("vhca_id:%d waiting completed DEL_HMC mailbox too long time,timeout!\n",
					dev->vhca_id);
				break;
			}
			if (dev->hw_attrs.self_health == true)
				break;
			udelay(dev->hw_attrs.max_sleep_count);
		} while (!val);
	}

	zxdh_handle_internal_error(iwdev->rf);
clean_ib_resource:
	zrdma_cleanup_rdma_tools_cfg(iwdev->rf);
	zrdma_cleanup_debugfs_entry(iwdev->rf);
	zxdh_ib_unregister_device(iwdev);
	zxdh_destory_eth_info_hlist(iwdev);

	if (!iwdev->rf->ftype)
		zxdh_delete_rdma_pf_glb(iwdev->rf);

	pr_info("INIT: Gen2 PF[%d] device remove success\n", PCI_FUNC(cdev_info->pdev->devfn));
	return 0;
}

/**
 * zxdh_shutdown - trigger when reboot
 * @aux_dev: auxiliary device ptr
 */
static void zxdh_shutdown(struct zxdh_auxiliary_device *aux_dev)
{
	zxdh_remove(aux_dev);
}

#ifdef MSIX_DEBUG

static int ft_debug_msix_interrupt(struct pci_dev *pdev, struct msix_entry *msix, u32 msix_num)
{
	struct msix_entry *temp_msix;
	int ret;
	int i;

	temp_msix = msix;
	if (pci_enable_device(pdev)) {
		pr_info("%s enable pcie msix failed!\n", __func__);
		return -1;
	}
	ret = pci_alloc_irq_vectors_affinity(pdev, msix_num, msix_num, PCI_IRQ_MSIX, NULL);
	if (ret < 0) {
		pr_info("%s alloc irq vectors failed!\n", __func__);
		return -1;
	}
	pr_info("%s alloc irq vectors ret:%d\n", __func__, ret);

	for (i = 0; i < msix_num; i++) {
		temp_msix->vector = pci_irq_vector(pdev, i);
		temp_msix->entry = i;
		pr_info("%s vector:%d entry:%d\n", __func__, temp_msix->vector, temp_msix->entry);
		temp_msix++;
	}

	return 0;
}
#endif
static void zxdh_cfg_dpp(struct zxdh_device *iwdev, struct iidc_core_dev_info *cdev_info)
{
	struct dpp_pf_info_t pf_info = { 0 };
	u32 ret = 0;

	pf_info.vport = cdev_info->vport_id;
	pf_info.slot = cdev_info->slot_id;

	if (!iwdev->rf->sc_dev.np_mode_low_lat) {
		dpp_vport_vhca_id_add(&pf_info, iwdev->rf->sc_dev.vhca_id);
		ret = dpp_vport_attr_set(&pf_info, EGR_FLAG_VHCA, iwdev->rf->sc_dev.vhca_id);
		if (ret != 0) {
			pr_err("%s[%d]: dpp vport attr set EGR_FLAG_VHCA fail! ret=%u!\n", __func__,
			       __LINE__, ret);
			return;
		}
		ret = dpp_vport_attr_set(&pf_info, EGR_FLAG_RDMA_OFFLOAD_EN_OFF,
					 EGR_RDMA_OFFLOAD_EN);
		if (ret != 0) {
			pr_err("%s[%d]: dpp vport attr set OFFLOAD_EN_OFF fail! ret=%u!\n",
			       __func__, __LINE__, ret);
			return;
		}
	} else {
		if (!iwdev->netdev->dev_addr) {
			pr_err("[%s] netdev dev_addr is null!\n", __func__);
			return;
		}

		pr_info("%s[%d]: dpp add rdma trans item\n", __func__, __LINE__);
		dpp_add_rdma_trans_item(&pf_info, iwdev->netdev->dev_addr,
					iwdev->rf->sc_dev.vhca_id);
		ether_addr_copy(iwdev->mac_addr, iwdev->netdev->dev_addr);
	}
}

static void zxdh_init_eth_info_hlist(struct zxdh_device *iwdev)
{
	int i = 0;

	iwdev->eth_info_hlist =
		kmalloc(sizeof(struct hlist_head) * ETH_INFO_HASH_COUNT, GFP_ATOMIC);
	if (!iwdev->eth_info_hlist)
		return;
	for (i = 0; i < ETH_INFO_HASH_COUNT; i++)
		INIT_HLIST_HEAD(&iwdev->eth_info_hlist[i]);
	mutex_init(&iwdev->eth_info_list_mtx_lock);
}

static void zxdh_destory_eth_info_hlist(struct zxdh_device *iwdev)
{
	struct zxdh_eth_info *hnode = NULL;
	struct hlist_node *hlist = NULL;
	int i = 0;
	int valid_hlist_num = 0;

	for (i = 0; i < ETH_INFO_HASH_COUNT; i++) {
		hlist_for_each_entry_safe(hnode, hlist, &iwdev->eth_info_hlist[i], list) {
			valid_hlist_num++;
			hlist_del(&hnode->list);
			kfree(hnode); // kmalloc in zxdh_eth_info_hlist_add
		}
	}
	kfree(iwdev->eth_info_hlist);
	iwdev->eth_info_hlist = NULL;

	pr_info("%s[%d]: valid_hlist_num=%d\n", __func__, __LINE__, valid_hlist_num);
}

void zxdh_eth_info_hlist_display(struct zxdh_device *iwdev)
{
	struct zxdh_eth_info *hnode = NULL;
	struct hlist_node *hlist = NULL;
	int i = 0;
	int valid_hlist_num = 0;
	int valid_node_num = 0;
	int ip_cfg_ref_num = 0;

	for (i = 0; i < ETH_INFO_HASH_COUNT; i++) {
		if (!hlist_empty(&iwdev->eth_info_hlist[i]))
			valid_hlist_num++;

		hlist_for_each_entry_safe(hnode, hlist, &iwdev->eth_info_hlist[i], list) {
			valid_node_num++;
			ip_cfg_ref_num += hnode->ip_cfg_ref_cnt;
			pr_info("%s[%d]:src_ip=0x%x-0x%x-0x%x-0x%x,dst_ip=0x%x-0x%x-0x%x-0x%x\n",
				__func__, __LINE__, hnode->rdma_to_eth_ip_para.src_ip[0],
				hnode->rdma_to_eth_ip_para.src_ip[1],
				hnode->rdma_to_eth_ip_para.src_ip[2],
				hnode->rdma_to_eth_ip_para.src_ip[3],
				hnode->rdma_to_eth_ip_para.dst_ip[0],
				hnode->rdma_to_eth_ip_para.dst_ip[1],
				hnode->rdma_to_eth_ip_para.dst_ip[2],
				hnode->rdma_to_eth_ip_para.dst_ip[3]);
			pr_info("%s[%d]: hlist key=%d, name=%s, ip_cfg_ref_cnt=%d\n", __func__,
				__LINE__, i, hnode->rdma_to_eth_ip_para.ifname,
				hnode->ip_cfg_ref_cnt);
		}
	}
	pr_info("%s[%d]: valid_hlist_num=%d, valid_node_num=%d, ip_cfg_ref_num=%d\n", __func__,
		__LINE__, valid_hlist_num, valid_node_num, ip_cfg_ref_num);
}

static int zxdh_eth_info_cmp(struct zxdh_rdma_to_eth_ip_para *ip_para, struct zxdh_eth_info *info2)
{
	if (ip_para->src_ip[0] == info2->rdma_to_eth_ip_para.src_ip[0] &&
	    ip_para->src_ip[1] == info2->rdma_to_eth_ip_para.src_ip[1] &&
	    ip_para->src_ip[2] == info2->rdma_to_eth_ip_para.src_ip[2] &&
	    ip_para->src_ip[3] == info2->rdma_to_eth_ip_para.src_ip[3] &&
	    ip_para->dst_ip[0] == info2->rdma_to_eth_ip_para.dst_ip[0] &&
	    ip_para->dst_ip[1] == info2->rdma_to_eth_ip_para.dst_ip[1] &&
	    ip_para->dst_ip[2] == info2->rdma_to_eth_ip_para.dst_ip[2] &&
	    ip_para->dst_ip[3] == info2->rdma_to_eth_ip_para.dst_ip[3] &&
	    memcmp(ip_para->ifname, info2->rdma_to_eth_ip_para.ifname, strlen(ip_para->ifname)) ==
		    0) {
		return 0;
	}

	return 1;
}

static u32 src_dst_ipv4_hash(const struct zxdh_rdma_to_eth_ip_para *ip_para)
{
	u32 hash = jhash(&ip_para->src_ip[3], sizeof(ip_para->src_ip[3]), 0);
	u32 key = jhash(&ip_para->dst_ip[3], sizeof(ip_para->dst_ip[3]), hash);

	return key % ETH_INFO_HASH_COUNT;
}

static u32 src_dst_ipv6_hash(const struct zxdh_rdma_to_eth_ip_para *ip_para)
{
	u32 hash = jhash(ip_para->src_ip, sizeof(ip_para->src_ip), 0);
	u32 key = jhash(ip_para->dst_ip, sizeof(ip_para->dst_ip), hash);

	return key % ETH_INFO_HASH_COUNT;
}

int zxdh_eth_info_hlist_add(struct zxdh_device *iwdev, struct zxdh_rdma_to_eth_ip_para *ip_para)
{
	struct zxdh_eth_info *hnode = NULL;
	struct hlist_node *hlist = NULL;
	char s_straddr[INET6_ADDRSTRLEN + 20];
	char d_straddr[INET6_ADDRSTRLEN + 20];
	u32 key = 0;

	if (ip_para->ipv4 == true) {
		key = src_dst_ipv4_hash(ip_para);
		scnprintf(s_straddr, sizeof(s_straddr), "%pI4", &ip_para->src_ip[3]);
		scnprintf(d_straddr, sizeof(d_straddr), "%pI4", &ip_para->dst_ip[3]);
	} else {
		key = src_dst_ipv6_hash(ip_para);
		scnprintf(s_straddr, sizeof(s_straddr), "%pI6", ip_para->src_ip);
		scnprintf(d_straddr, sizeof(d_straddr), "%pI6", ip_para->dst_ip);
	}

	hlist_for_each_entry_safe(hnode, hlist, &iwdev->eth_info_hlist[key], list) {
		if (zxdh_eth_info_cmp(ip_para, hnode) == 0) {
			hnode->ip_cfg_ref_cnt += 1;
			goto finish;
		}
	}

	hnode = kmalloc(sizeof(struct zxdh_eth_info), GFP_ATOMIC);
	if (!hnode)
		return -1;

	INIT_HLIST_NODE(&hnode->list);
	memcpy(&hnode->rdma_to_eth_ip_para, ip_para, sizeof(struct zxdh_rdma_to_eth_ip_para));
	hnode->netdev = iwdev->netdev;
	hnode->ip_cfg_ref_cnt = 1;
	hlist_add_head(&hnode->list, &iwdev->eth_info_hlist[key]);

	rdma_update_remote_ip(ip_para);
	zxdh_eth_info_hlist_display(iwdev);

finish:
	return 0;
}

int zxdh_eth_info_hlist_delete(struct zxdh_device *iwdev, struct zxdh_rdma_to_eth_ip_para *ip_para)
{
	struct zxdh_eth_info *hnode = NULL;
	struct hlist_node *hlist = NULL;
	char s_straddr[INET6_ADDRSTRLEN + 20];
	char d_straddr[INET6_ADDRSTRLEN + 20];
	u32 key;

	if (ip_para->ipv4 == true) {
		key = src_dst_ipv4_hash(ip_para);
		scnprintf(s_straddr, sizeof(s_straddr), "%pI4", &ip_para->src_ip[3]);
		scnprintf(d_straddr, sizeof(d_straddr), "%pI4", &ip_para->dst_ip[3]);
	} else {
		key = src_dst_ipv6_hash(ip_para);
		scnprintf(s_straddr, sizeof(s_straddr), "%pI6", ip_para->src_ip);
		scnprintf(d_straddr, sizeof(d_straddr), "%pI6", ip_para->dst_ip);
	}

	if (hlist_empty(&iwdev->eth_info_hlist[key])) {
		pr_err("%s: hlist key(%d) not exit, ipv4=%d, name=%s, src_mac=0x%llx, dst_mac=0x%llx\n",
		       __func__, key, ip_para->ipv4, ip_para->ifname, ip_para->src_mac,
		       ip_para->dst_mac);
		pr_err("%s: src_ip=0x%x-0x%x-0x%x-0x%x, dst_ip=0x%x-0x%x-0x%x-0x%x\n", __func__,
		       ip_para->src_ip[0], ip_para->src_ip[1], ip_para->src_ip[2],
		       ip_para->src_ip[3], ip_para->dst_ip[0], ip_para->dst_ip[1],
		       ip_para->dst_ip[2], ip_para->dst_ip[3]);
		return -1;
	}

	hlist_for_each_entry_safe(hnode, hlist, &iwdev->eth_info_hlist[key], list) {
		if (zxdh_eth_info_cmp(ip_para, hnode) == 0) {
			hnode->ip_cfg_ref_cnt -= 1;
			if (hnode->ip_cfg_ref_cnt == 0) {
				hlist_del(&hnode->list);
				kfree(hnode); // kmalloc in zxdh_eth_info_hlist_add
				rdma_update_remote_ip(ip_para);
				zxdh_eth_info_hlist_display(iwdev);
			} else {
				pr_debug(
					"%s key=%u, ipv4=%d, name=%s, s_mac=0x%llx, d_mac=0x%llx, ref_cnt=%d\n",
					__func__, key, ip_para->ipv4, ip_para->ifname,
					ip_para->src_mac, ip_para->dst_mac, hnode->ip_cfg_ref_cnt);

				pr_debug(
					"%s src_ip=0x%x-0x%x-0x%x-0x%x, dst_ip=0x%x-0x%x-0x%x-0x%x\n",
					__func__, ip_para->src_ip[0], ip_para->src_ip[1],
					ip_para->src_ip[2], ip_para->src_ip[3], ip_para->dst_ip[0],
					ip_para->dst_ip[1], ip_para->dst_ip[2], ip_para->dst_ip[3]);
			}
			return 0;
		}
	}
	pr_err("%s[%d]: key=%u, ipv4=%d, name=%s, src_mac=0x%llx, dst_mac=0x%llx\n", __func__,
	       __LINE__, key, ip_para->ipv4, ip_para->ifname, ip_para->src_mac, ip_para->dst_mac);

	pr_err("%s[%d]: src_ip=0x%x-0x%x-0x%x-0x%x, dst_ip=0x%x-0x%x-0x%x-0x%x\n", __func__,
	       __LINE__, ip_para->src_ip[0], ip_para->src_ip[1], ip_para->src_ip[2],
	       ip_para->src_ip[3], ip_para->dst_ip[0], ip_para->dst_ip[1], ip_para->dst_ip[2],
	       ip_para->dst_ip[3]);
	return -1;
}

static void zxdh_fill_device_info(struct zxdh_device *iwdev, struct iidc_core_dev_info *cdev_info)
{
	struct zxdh_pci_f *rf = iwdev->rf;

	rf->ftype = (cdev_info->vport_id >> 11) & 0x1;
	rf->pf_id = (cdev_info->vport_id >> 8) & 0x7;
	rf->sc_dev.ep_id = (cdev_info->vport_id >> 12) & 0x7;
	rf->ep_id = rf->sc_dev.ep_id;
	rf->sc_dev.driver_load = true;
	rf->sc_dev.last_time = 0;

	rf->cdev = cdev_info;
	rf->pcidev = cdev_info->pdev;
	rf->hw.pci_hw_addr = cdev_info->hw_addr;

	rf->msix_count = cdev_info->msix_count;
#ifdef MSIX_DEBUG
	ft_debug_msix_interrupt(cdev_info->pdev, cdev_info->msix_entries, rf->msix_count);
#endif
	rf->msix_entries = cdev_info->msix_entries;
	rf->sc_dev.max_ceqs = (rf->msix_count - 1);
	rf->protocol_used = cdev_info->rdma_protocol == IIDC_RDMA_PROTOCOL_ROCEV2 ?
					  ZXDH_ROCE_PROTOCOL_ONLY :
					  ZXDH_IWARP_PROTOCOL_ONLY;
	rf->rdma_ver = ZXDH_GEN_2;
	rf->rsrc_profile = ZXDH_HMC_PROFILE_DEFAULT;
	rf->rst_to = ZXDH_RST_TIMEOUT_HZ;
	rf->gen_ops.request_reset = zxdh_request_reset;
	rf->check_fc = zxdh_check_fc_for_qp;
	rf->qp_index = 0;

	/* Can override limits_sel, protocol_used */
	zxdh_set_rf_user_cfg_params(rf);
	rf->iwdev = iwdev;

	INIT_LIST_HEAD(&iwdev->ah_list);
	mutex_init(&iwdev->ah_list_lock);
	iwdev->netdev = cdev_info->netdev;
	iwdev->source_netdev = cdev_info->netdev;
	iwdev->init_state = INITIAL_STATE;
	iwdev->roce_cwnd = ZXDH_ROCE_CWND_DEFAULT;
	iwdev->roce_ackcreds = ZXDH_ROCE_ACKCREDS_DEFAULT;
	iwdev->rcv_wnd = ZXDH_CM_DEFAULT_RCV_WND_SCALED;
	iwdev->rcv_wscale = ZXDH_CM_DEFAULT_RCV_WND_SCALE;
	iwdev->qp1 = NULL;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	iwdev->iwarp_ecn_en = true;
	iwdev->iwarp_rtomin = 5;
	iwdev->up_up_map = ZXDH_DEFAULT_UP_UP_MAP;
#endif
	if (rf->protocol_used == ZXDH_ROCE_PROTOCOL_ONLY) {
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
		iwdev->roce_rtomin = 5;
#endif
		//iwdev->roce_dcqcn_en = iwdev->rf->dcqcn_ena;
		iwdev->roce_dcqcn_en = true; //dcqcn/ecn is set to default on
		iwdev->roce_mode = true;
	}

	zxdh_init_eth_info_hlist(iwdev);
}

static void zxdh_to_iidc(struct iidc_core_dev_info *cdev_info, struct zxdh_auxiliary_dev *iidc_adev)
{
	cdev_info->pdev = iidc_adev->zxdh_info->pdev;
	cdev_info->adev = iidc_adev->zxdh_info->adev;
	cdev_info->hw_addr = iidc_adev->zxdh_info->hw_addr;
	cdev_info->cdev_info_id = iidc_adev->zxdh_info->cdev_info_id;
	cdev_info->ver = iidc_adev->zxdh_info->ver;
	cdev_info->auxiliary_priv = iidc_adev->zxdh_info->auxiliary_priv;
	cdev_info->vport_id = iidc_adev->zxdh_info->vport_id;
	cdev_info->slot_id = iidc_adev->zxdh_info->slot_id;
	cdev_info->rdma_protocol = iidc_adev->zxdh_info->rdma_protocol;
	cdev_info->qos_info = iidc_adev->zxdh_info->qos_info;
	cdev_info->msix_entries = &iidc_adev->zxdh_info->msix_entries;
	cdev_info->msix_count = iidc_adev->zxdh_info->msix_count;
	cdev_info->ops = iidc_adev->zxdh_info->ops;
	cdev_info->netdev = iidc_adev->rdma_ops->get_rdma_netdev(iidc_adev->parent);
}

static int zxdh_fw_ver_check(struct iidc_core_dev_info *cdev_info)
{
	struct zxdh_fw_compat *ver = NULL;
	u64 addr_offset = 0;
	u8 fw_minor_fw_ver = FW_MINOR_FW_VER;
	u8 fw_minor_drv_ver = FW_MINOR_DRV_VER;

	addr_offset = ZXDH_FW_VER_OFFSET + (MODULE_RDMA_ID - 2) * sizeof(struct zxdh_fw_compat);
	ver = (struct zxdh_fw_compat *)((void __iomem *)cdev_info->hw_addr + addr_offset);
	if (ver->module_id == (MODULE_RDMA_ID - 1)) {
		addr_offset =
			ZXDH_FW_VER_OFFSET + (MODULE_RDMA_ID - 3) * sizeof(struct zxdh_fw_compat);
		ver = (struct zxdh_fw_compat *)((void __iomem *)cdev_info->hw_addr + addr_offset);
		if (ver->module_id == (MODULE_RDMA_ID - 2)) {
			addr_offset = ZXDH_FW_VER_OFFSET +
				      (MODULE_RDMA_ID - 1) * sizeof(struct zxdh_fw_compat);
			ver = (struct zxdh_fw_compat *)((void __iomem *)cdev_info->hw_addr +
							addr_offset);
			if (ver->module_id == MODULE_RDMA_ID) {
				if (ver->major != FW_MAJOR_VER) {
					pr_err("fw major rdma side ver:%u-%u-%u is not match fw side ver:%u-%u-%u\n",
					       FW_MAJOR_VER, FW_MINOR_FW_VER, FW_MINOR_DRV_VER,
					       ver->major, ver->fw_minor, ver->drv_minor);
					return -EINVAL;
				}

				if (fw_minor_fw_ver > ver->fw_minor) {
					pr_err("fw minor rdma side ver:%u-%u-%u is higher than fw side ver:%u-%u-%u\n",
					       FW_MAJOR_VER, FW_MINOR_FW_VER, FW_MINOR_DRV_VER,
					       ver->major, ver->fw_minor, ver->drv_minor);
					return -EINVAL;
				}

				if (fw_minor_drv_ver < ver->drv_minor) {
					pr_err("fw rdma minor rdma side ver:%u-%u-%u is lower than fw side ver:%u-%u-%u\n",
					       FW_MAJOR_VER, FW_MINOR_FW_VER, FW_MINOR_DRV_VER,
					       ver->major, ver->fw_minor, ver->drv_minor);
					return -EINVAL;
				}
				pr_info("[%s] fw ver match success!\n", __func__);
			}
		}
	}
	return 0;
}

static int zxdh_drv_ver_check(struct iidc_core_dev_info *cdev_info)
{
	u8 net_major = 0;
	u8 net_minor = 0;
	u8 rdma_minor = 0;
	u8 drv_net_minor_ver = DRV_NET_MINOR_VER;
	u8 drv_rdma_minor_ver = DRV_RDMA_MINOR_VER;

	net_major = (u8)FIELD_GET(ZXDH_NET_MAJOR_IDX, cdev_info->ver.support);
	net_minor = (u8)FIELD_GET(ZXDH_NET_MINOR_IDX, cdev_info->ver.support);
	rdma_minor = (u8)FIELD_GET(ZXDH_RDMA_MINOR_IDX, cdev_info->ver.support);

	if (net_major != DRV_MAJOR_VER) {
		pr_err("drv major rdma side ver:%u-%u-%u is not match net side ver:%u-%u-%u\n",
		       DRV_MAJOR_VER, DRV_NET_MINOR_VER, DRV_RDMA_MINOR_VER, net_major, net_minor,
		       rdma_minor);
		return -EINVAL;
	}

	if (drv_net_minor_ver > net_minor) {
		pr_err("drv net minor rdma side ver:%u-%u-%u is higher than net side ver:%u-%u-%u\n",
		       DRV_MAJOR_VER, DRV_NET_MINOR_VER, DRV_RDMA_MINOR_VER, net_major, net_minor,
		       rdma_minor);
		return -EINVAL;
	}

	if (drv_rdma_minor_ver < rdma_minor) {
		pr_err("drv rdma minor rdma side ver:%u-%u-%u is lower than net side ver:%u-%u-%u\n",
		       DRV_MAJOR_VER, DRV_NET_MINOR_VER, DRV_RDMA_MINOR_VER, net_major, net_minor,
		       rdma_minor);
		return -EINVAL;
	}
	return 0;
}

static int zxdh_compat_ver_check(struct iidc_core_dev_info *cdev_info)
{
	if (zxdh_fw_ver_check(cdev_info))
		return -EINVAL;

	if (zxdh_drv_ver_check(cdev_info))
		return -EINVAL;
	return 0;
}

static void zxdh_rdma_init_sriov(struct zxdh_pci_f *rf)
{
	struct zxdh_rdma_sriov_event_info sriov_info;
	u64 vf_pblem_cnt;
	int active_vf_num = pci_num_vf(rf->pcidev);
	struct iidc_core_dev_info *cdev_info = rf->cdev;
	int ret = 0;

	if (active_vf_num <= 0)
		return;

	sriov_info.pdev = cdev_info->pdev;
	sriov_info.bar0_virt_addr = (u64)(uintptr_t)cdev_info->hw_addr;
	sriov_info.vport_id = cdev_info->vport_id;
	sriov_info.num_vfs = active_vf_num;

	if (set_rdma_vf_num(&sriov_info, &vf_pblem_cnt)) {
		pr_err("%s set_rdma_vf_num failed, ret=%d\n", __func__, ret);
		return;
	}

	rf->sc_dev.active_vfs_num = active_vf_num;
	pr_info("%s active_vf_num:%d vf_pblem_cnt:0x%llx\n", __func__, active_vf_num, vf_pblem_cnt);
}

static int zxdh_clear_l2d(struct zxdh_sc_dev *dev, u64 l2d_pa, u64 size)
{
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct zxdh_pci_f *rf = dev_to_rf(dev);
	int status;

	if (!dev)
		return -ENOMEM;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	dev->nof_clear_dpu_mem.size = size;
	dev->nof_clear_dpu_mem.va = dma_alloc_coherent(dev->hw->device, dev->nof_clear_dpu_mem.size,
						       &dev->nof_clear_dpu_mem.pa, GFP_KERNEL);
	if (!dev->nof_clear_dpu_mem.va) {
		zxdh_put_cqp_request(&rf->cqp, cqp_request);
		return -ENOMEM;
	}
	memset(dev->nof_clear_dpu_mem.va, 0, dev->nof_clear_dpu_mem.size);

	cqp_info = &cqp_request->info;
	cqp_info->post_sq = 1;
	cqp_info->cqp_cmd = ZXDH_OP_DMA_WRITE;
	cqp_info->in.u.dma_writeread.cqp = dev->cqp;
	cqp_info->in.u.dma_writeread.src_dest.src = dev->nof_clear_dpu_mem.pa;
	cqp_info->in.u.dma_writeread.src_dest.len = dev->nof_clear_dpu_mem.size;
	cqp_info->in.u.dma_writeread.src_dest.dest = l2d_pa;

	cqp_info->in.u.dma_writeread.src_path_index.vhca_id = dev->vhca_id;
	cqp_info->in.u.dma_writeread.src_path_index.obj_id = ZXDH_DMA_OBJ_ID;
	cqp_info->in.u.dma_writeread.src_path_index.path_select = ZXDH_INDICATE_HOST_NOSMMU;
	cqp_info->in.u.dma_writeread.src_path_index.inter_select = ZXDH_INTERFACE_NOTCACHE;

	cqp_info->in.u.dma_writeread.dest_path_index.vhca_id = dev->vhca_id;
	cqp_info->in.u.dma_writeread.dest_path_index.obj_id = ZXDH_DMA_OBJ_ID;
	cqp_info->in.u.dma_writeread.dest_path_index.path_select = ZXDH_INDICATE_DPU_DDR;
	cqp_info->in.u.dma_writeread.dest_path_index.inter_select = ZXDH_INTERFACE_NOTCACHE;
	pr_info("%s[%d]: clear l2d pa=0x%llx size=0x%x\n", __func__, __LINE__, l2d_pa,
		dev->nof_clear_dpu_mem.size);
	cqp_info->in.u.dma_writeread.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);

	dma_free_coherent(dev->hw->device, dev->nof_clear_dpu_mem.size,
			  dev->nof_clear_dpu_mem.va, dev->nof_clear_dpu_mem.pa);
	dev->nof_clear_dpu_mem.va = NULL;

	return status;
}

static int zxdh_get_srq_l2d_info(struct zxdh_pci_f *rf,
				 struct dh_get_srq_l2d_addr_resp *srq_l2d_info)
{
	int ret = 0;
	u32 function_id = 0;
	u8 rep_valid = 0;
	u16 rep_len = 0;
	u8 *rep_ptr;
	struct zxdh_mgr mgr = { 0 };
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct dh_get_srq_l2d_addr_req get_cmd = { 0 };
	struct iidc_core_dev_info *cdev_info;
	size_t recv_len;
	void *recv_buffer;
	struct dh_get_srq_l2d_addr_resp *get_resp;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (!rf) {
		pr_err("%s[%d]: rf is null\n", __func__, __LINE__);
		return -EINVAL;
	}
	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;

	function_id = DH_FUNC_ID_GEN(rf->ftype, rf->ep_id, 0, rf->pf_id, rf->vf_id);

	cdev_info = (struct iidc_core_dev_info *)rf->cdev;
	// query pcie id
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	recv_len = ZXDH_CHAN_REPS_LEN + sizeof(struct dh_get_srq_l2d_addr_resp);
	recv_buffer = kzalloc(recv_len, GFP_KERNEL);
	if (!recv_buffer)
		return -ENOMEM;

	// commnad preparation
	get_cmd.op_code = GET_SRQ_L2D_ADDR;
	get_cmd.function_id = function_id;
	pr_info("%s[%d]: function_id=0x%x ftype=%d ep_id=%d pf_id=%d vf_id=%d\n", __func__,
		__LINE__, function_id, rf->ftype, rf->ep_id, rf->pf_id, rf->vf_id);

	// get message preparation
	in.payload_addr = (void *)&get_cmd;
	in.payload_len = sizeof(struct dh_get_srq_l2d_addr_req);
	in.src = rf->ftype == 0 ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RDMA;
	in.virt_addr = (u64)(uintptr_t)cdev_info->hw_addr + ZXDH_BAR_CHAN_OFFSET;
	in.src_pcieid = mgr.pcie_id;

	// resv buffer preparation
	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_len;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;
		cnt++;
	} while (cnt < cnt_num);

	if (ret) {
		pr_err("[%s] message send failed, ret=%d cnt=%d\n", __func__, ret, cnt);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_ptr = (u8 *)recv_buffer;
	rep_valid = *rep_ptr;
	if (rep_valid != MSG_REP_VALID) {
		pr_err("[%s] response message invalid, rep_valid=0x%x\n", __func__, rep_valid);
		kfree(recv_buffer);
		return -EPROTO;
	}

	rep_len = *(u16 *)(rep_ptr + MSG_REP_LEN_OFFSET);
	if (rep_len != (recv_len - ZXDH_CHAN_REPS_LEN)) {
		pr_err("[%s] response length invalid, rep_len=0x%x recv_len=0x%zx\n", __func__,
		       rep_len, recv_len);
		kfree(recv_buffer);
		return -EPROTO;
	}

	get_resp = (struct dh_get_srq_l2d_addr_resp *)(rep_ptr + ZXDH_CHAN_REPS_LEN);
	if (get_resp->status_code != BAR_MSG_STATUS_OK) {
		pr_err("[%s] response status invalid, statuc_code=0x%x\n", __func__,
		       get_resp->status_code);
		kfree(recv_buffer);
		return -EPROTO;
	}

	memcpy(srq_l2d_info, get_resp, sizeof(struct dh_get_srq_l2d_addr_resp));
	pr_info("%s[%d]: resp srq_l2d_paddr=0x%llx srq_l2d_size=0x%x\n", __func__, __LINE__,
		get_resp->srq_l2d_paddr, get_resp->srq_l2d_size);

	// *outdata = get_resp->val;
	kfree(recv_buffer);
	recv_buffer = NULL;
	return 0;
}

static void zxdh_set_srq_l2d_info(struct zxdh_pci_f *rf)
{
	struct dh_get_srq_l2d_addr_resp srq_l2d_info = { 0 };
	int ret = 0;

	if (!rf) {
		pr_err("%s[%d] error: rf is null\n", __func__, __LINE__);
		return;
	}

	ret = zxdh_get_srq_l2d_info(rf, &srq_l2d_info);
	if (ret) {
		rf->srq_l2d_base_paddr = 0;
		rf->srq_l2d_size = 0;
		rf->rdma_ext_bar_offset = 0;
		pr_warn("%s: ret=%d srq_paddr=0x%llx srq_size=0x%x ext_offset=0x%x status=%d\n",
			__func__, ret, srq_l2d_info.srq_l2d_paddr, srq_l2d_info.srq_l2d_size,
			srq_l2d_info.rdma_ext_bar_offset, srq_l2d_info.status_code);
	} else {
		rf->srq_l2d_base_paddr = srq_l2d_info.srq_l2d_paddr;
		rf->srq_l2d_size = srq_l2d_info.srq_l2d_size;
		rf->rdma_ext_bar_offset = srq_l2d_info.rdma_ext_bar_offset;
		pr_debug("%s: srq_paddr=0x%llx srq_size=0x%x ext_offset=0x%x status=%d\n", __func__,
			 srq_l2d_info.srq_l2d_paddr, srq_l2d_info.srq_l2d_size,
			 srq_l2d_info.rdma_ext_bar_offset, srq_l2d_info.status_code);
	}
}

static int zxdh_probe(struct zxdh_auxiliary_device *aux_dev,
		      const struct zxdh_auxiliary_device_id *id)
{
	struct zxdh_auxiliary_dev *iidc_adev =
		container_of(aux_dev, struct zxdh_auxiliary_dev, adev);
	struct zxdh_device *iwdev;
	struct zxdh_pci_f *rf;
	int err;
	struct zxdh_handler *hdl;
	struct iidc_core_dev_info *cdev_info =
		kzalloc(sizeof(struct iidc_core_dev_info), GFP_KERNEL);

	if (!cdev_info)
		return -ENOMEM;
	zxdh_to_iidc(cdev_info, iidc_adev);

	if (zxdh_compat_ver_check(cdev_info)) {
		kfree(cdev_info);
		return -EINVAL;
	}

	if (cdev_info->ver.major != IIDC_MAJOR_VER) {
		pr_err("version mismatch:\n");
		pr_err("expected major ver %d, caller specified major ver %d\n", IIDC_MAJOR_VER,
		       cdev_info->ver.major);
		pr_err("expected minor ver %d, caller specified minor ver %d\n", IIDC_MINOR_VER,
		       cdev_info->ver.minor);
		kfree(cdev_info);
		return -EINVAL;
	}
	if (cdev_info->ver.minor != IIDC_MINOR_VER)
		pr_info("probe: minor version mismatch: expected %0d.%0d caller specified %0d.%0d\n",
			IIDC_MAJOR_VER, IIDC_MINOR_VER, cdev_info->ver.major, cdev_info->ver.minor);

	iwdev = ib_alloc_device(zxdh_device, ibdev);
	if (!iwdev) {
		kfree(cdev_info);
		return -ENOMEM;
	}
	iwdev->rf = kzalloc(sizeof(*rf), GFP_KERNEL);
	if (!iwdev->rf) {
		ib_dealloc_device(&iwdev->ibdev);
		kfree(cdev_info);
		return -ENOMEM;
	}
	zxdh_fill_device_info(iwdev, cdev_info);
	zxdh_req_cmd_ver(iwdev->rf);

	zxdh_set_srq_l2d_info(iwdev->rf);

	if (!iwdev->rf->ftype)
		zxdh_rdma_init_sriov(iwdev->rf);

	err = zxdh_manager_init(iwdev->rf, cdev_info);
	if (err != 0) {
		pr_warn("zxdh_manager_init failed!\n");
		goto err_mgr_init;
	}

	if (!iwdev->rf->ftype)
		zxdh_cfg_dpp(iwdev, cdev_info);

	rf = iwdev->rf;

	hdl = kzalloc(sizeof(*hdl), GFP_KERNEL);
	if (!hdl) {
		kfree(cdev_info);
		kfree(iwdev->rf);
		ib_dealloc_device(&iwdev->ibdev);
		return -ENOMEM;
	}

	hdl->iwdev = iwdev;
	iwdev->hdl = hdl;

	err = zxdh_ctrl_init_hw(rf);
	if (err)
		goto err_ctrl_init;

	err = zxdh_rt_init_hw(iwdev);
	if (err)
		goto err_rt_init;

	if (rf->srq_l2d_base_paddr != 0 && rf->srq_l2d_size != 0)
		zxdh_clear_l2d(&rf->sc_dev, rf->srq_l2d_base_paddr, rf->srq_l2d_size);

	err = zxdh_ib_register_device(iwdev);
	if (err)
		goto err_ibreg;

	zxdh_add_handler(hdl);
	refcount_set(&iwdev->trace_switch.t_switch, 0);
	dev_set_drvdata(&aux_dev->dev, iwdev);
	if (!rf->ftype)
		zxdh_store_rdma_pf_glb(rf);

	create_debugfs_entry(rf);
	if (!rf->ftype)
		zxdh_hwbond_register_rdma_ops(&hwbond_ops);
	pr_info("INIT: device[%d] probe success\n", rf->sc_dev.vhca_id);
	return 0;

err_ibreg:
	zxdh_rt_deinit_hw(iwdev);
err_rt_init:
	zxdh_ctrl_deinit_hw(rf);
#ifdef MSIX_DEBUG
	pci_free_irq_vectors(cdev_info->pdev);
#endif
err_ctrl_init:
	kfree(hdl);
err_mgr_init:
	kfree(iwdev->rf);
	ib_dealloc_device(&iwdev->ibdev);
	kfree(cdev_info);

	return err;
}

static const struct zxdh_auxiliary_device_id zxdh_auxiliary_id_table[] = {
	{
		.name = ZXDH_PF_NAME "." ZXDH_RDMA_DEV_NAME,
	},
	{},
};

MODULE_DEVICE_TABLE(auxiliary, zxdh_auxiliary_id_table);

static struct iidc_auxiliary_drv zxdh_auxiliary_drv = {
	.adrv = {
		.name = ZXDH_RDMA_DEV_NAME,
		.id_table = zxdh_auxiliary_id_table,
		.probe = zxdh_probe,
		.remove = zxdh_remove,
		.shutdown = zxdh_shutdown,
	},
	.event_handler = zxdh_iidc_event_handler,
};

static void zxdh_show_ver(void)
{
	if (display_drv_side_fw_ver == 1)
		pr_info("zrdma driver side fw version: %d.%d.%d\n", FW_MAJOR_VER, FW_MINOR_FW_VER,
			FW_MINOR_DRV_VER);
	if (display_drv_side_net_ver == 1)
		pr_info("zrdma driver side network version: %d.%d.%d\n", DRV_MAJOR_VER,
			DRV_NET_MINOR_VER, DRV_RDMA_MINOR_VER);
}

static int __init zxdh_init_module(void)
{
	int ret;

#ifdef RDMA_VERSION
	pr_info("zrdma driver version: %s\n", TOSTRING(RDMA_VERSION));
#else
	pr_info("zrdma driver version: %d.%d.%d\n", DRV_VER_MAJOR, DRV_VER_MINOR, DRV_VER_BUILD);
#endif
	zxdh_show_ver();

	zrdma_register_debugfs();
	ret = zxdh_auxiliary_driver_register(&zxdh_auxiliary_drv.adrv);
	if (ret)
		return ret;

	pr_info("[%s] install hwbond callback function\n", __func__);
	zxdh_hwbond_register_rdma_ops(&hwbond_ops);
	zxdh_rdma_events_register(&zxdh_rdma_event_handler);
	zxdh_register_notifiers();

	return 0;
}

static void __exit zxdh_exit_module(void)
{
	zxdh_unregister_notifiers();

	pr_info("[%s] remove hwbond callback function\n", __func__);
	hwbond_ops.cfg_rdma_hb_master = NULL;
	hwbond_ops.cfg_rdma_hb_speed = NULL;
	zxdh_hwbond_unregister_rdma_ops();
	zxdh_rdma_events_unregister();
	zxdh_auxiliary_driver_unregister(&zxdh_auxiliary_drv.adrv);
	zrdma_unregister_debugfs();
}

module_init(zxdh_init_module);
module_exit(zxdh_exit_module);
