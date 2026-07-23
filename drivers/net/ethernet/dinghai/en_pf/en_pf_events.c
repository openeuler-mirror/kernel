// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/dinghai/driver.h>
#include <linux/notifier.h>
#include <linux/dinghai/events.h>
#include <linux/dinghai/dh_cmd.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include "en_pf_events.h"
#include "../en_pf.h"
#include "../msg_common.h"
#include "en_pf_eq.h"
#include "../en_aux.h"

static s32 riscv2pf_notifier(struct notifier_block *, unsigned long, void *);
static s32 riscv_ready_notifier(struct notifier_block *, unsigned long, void *);
static s32 vf2pf_notifier(struct notifier_block *, unsigned long, void *);
static s32 riscv_ext_pps_notifier(struct notifier_block *, unsigned long, void *);
static s32 riscv_local_pps_notifier(struct notifier_block *nb, unsigned long type, void *data);

static struct dh_nb pf_events[] = {
	{ .nb.notifier_call = riscv_ready_notifier, .event_type = DH_EVENT_TYPE_RISCV_READY },
	{ .nb.notifier_call = vf2pf_notifier, .event_type = DH_EVENT_TYPE_NOTIFY_VF_TO_PF },
	{ .nb.notifier_call = riscv_ext_pps_notifier,
	  .event_type = DH_EVENT_TYPE_NOTIFY_RISC_EXT_PPS },
	{ .nb.notifier_call = riscv_local_pps_notifier,
	  .event_type = DH_EVENT_TYPE_NOTIFY_RISC_LOCAL_PPS },
	{ .nb.notifier_call = riscv2pf_notifier, .event_type = DH_EVENT_TYPE_NOTIFY_ANY },
};

static s32 riscv2pf_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct dh_core_dev *dh_dev = (struct dh_core_dev *)event_nb->ctx;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	zxdh_events_work_enqueue(dh_dev, &pf_dev->riscv2pf_msg_proc_work);

	return NOTIFY_OK;
}

static s32 riscv_ready_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct dh_core_dev *dh_dev = (struct dh_core_dev *)event_nb->ctx;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u64 virt_addr = pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_OFFSET;

	zxdh_bar_reset_valid(virt_addr);
	zxdh_events_work_enqueue(dh_dev, &pf_dev->riscv_ready_work);

	return NOTIFY_OK;
}

static s32 vf2pf_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct dh_core_dev *dh_dev = (struct dh_core_dev *)event_nb->ctx;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	LOG_DEBUG("is called\n");

	zxdh_events_work_enqueue(dh_dev, &pf_dev->vf2pf_msg_proc_work);

	return NOTIFY_OK;
}

static s32 riscv_ext_pps_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct dh_core_dev *dh_dev = (struct dh_core_dev *)event_nb->ctx;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	zxdh_events_work_enqueue(dh_dev, &pf_dev->riscv_ext_pps_work);

	return NOTIFY_OK;
}

static s32 riscv_local_pps_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct dh_core_dev *dh_dev = (struct dh_core_dev *)event_nb->ctx;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	zxdh_events_work_enqueue(dh_dev, &pf_dev->riscv_local_pps_work);

	return NOTIFY_OK;
}

extern s32 zxdh_plug_aux_dev(struct dh_core_dev *dh_dev);

static void riscv2pf_msg_proc_work_handler(struct work_struct *_work)
{
	struct zxdh_pf_device *pf_dev =
		container_of(_work, struct zxdh_pf_device, riscv2pf_msg_proc_work);

	u16 src = MSG_CHAN_END_RISC;
	u16 dst = MSG_CHAN_END_PF;
	u64 virt_addr = pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_OFFSET;

	if (pf_dev->aux_comp_flag != 1)
		return;

	zxdh_bar_irq_recv(src, dst, virt_addr, NULL);
}

static void vf2pf_msg_proc_work_handler(struct work_struct *_work)
{
	struct zxdh_pf_device *pf_dev =
		container_of(_work, struct zxdh_pf_device, vf2pf_msg_proc_work);

	u16 src = MSG_CHAN_END_VF;
	u16 dst = MSG_CHAN_END_PF;
	u64 virt_addr =
		pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_OFFSET + ZXDH_BAR_PFVF_MSG_OFFSET;

	if (pf_dev->aux_comp_flag != 1)
		return;

	zxdh_bar_irq_recv(src, dst, virt_addr, pf_dev);
}

static void riscv_ready_work_handler(struct work_struct *_work)
{
	struct zxdh_pf_device *pf_dev =
		container_of(_work, struct zxdh_pf_device, riscv_ready_work);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	if (pf_dev->aux_comp_flag != 1)
		return;

	zxdh_plug_aux_dev(dh_dev);
}

s32 findFirstSetBit(u8 link_up_val)
{
	u8 i = 0;

	for (; i < 8; i++) {
		if (link_up_val & (1 << i))
			return i;
	}
	return -1;
}

s32 get_link_up_phyport(u8 link_up_val, struct zxdh_pf_device *pf_dev, u8 *phyport_val)
{
	int16_t first_link_up_idx = -1;
	u8 port_num = pf_dev->port_resource.pannel_num;
	struct zxdh_pannle_port *port;
	s32 idx = 0;

	first_link_up_idx = findFirstSetBit(link_up_val);
	if (first_link_up_idx < 0)
		return -1;

	for (idx = 0; idx < port_num; idx++) {
		port = &pf_dev->port_resource.port[idx];
		if (port->link_check_bit == first_link_up_idx) {
			*phyport_val = port->phyport;
			LOG_DEBUG("first link_up idx %d <-> phyport 0x%x\n", first_link_up_idx,
				  port->phyport);
			return 0;
		}
	}

	return -1;
}

static void link_info_irq_update_vf_bond_pf_work_handler(struct work_struct *_work)
{
	struct zxdh_pf_device *pf_dev =
		container_of(_work, struct zxdh_pf_device, link_info_irq_update_vf_bond_pf_work);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct zxdh_vf_item *vf_item = NULL;
	s32 err = 0;
	u16 vf_idx = 0;
	struct pci_dev *pdev = dh_dev->pdev;
	u16 num_vfs = 0;
	u8 link_up_val = 0;
	u8 phyport_val = 0;
	u8 link_info = 0;
	u16 func_no = 0;
	u16 pf_no = FIND_PF_ID(pf_dev->pcie_id);
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (pf_dev->aux_comp_flag != 1)
		return;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg)
		return;

	zxdh_pf_get_link_info_from_vqm(dh_dev, &link_up_val);
	LOG_DEBUG("[pf_level] bond_pf pcie_id:0x%x read from VQM, val: 0x%x\n", pf_dev->pcie_id,
		  link_up_val);
	pf_dev->link_up = (link_up_val == 0) ? FALSE : TRUE;

	if (pf_dev->link_up) {
		if (get_link_up_phyport(link_up_val, pf_dev, &phyport_val) < 0) {
			LOG_ERR("failed to get link up phyport\n");
			kfree(msg);
			return;
		}
		link_up_val = 1;
	}

	link_info = (phyport_val & 0x0F) << 4 | (link_up_val & 0x0F);
	msg->payload.hdr_to_agt.op_code = AGENT_DEV_STATUS_NOTIFY;
	msg->payload.hdr_to_agt.pcie_id = pf_dev->pcie_id;
	num_vfs = pci_num_vf(pdev);
	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vf_item = zxdh_pf_get_vf_item(dh_dev, vf_idx);
		if (vf_item->link_forced == FALSE && vf_item->is_probed) {
			func_no = GET_FUNC_NO(pf_no, vf_idx);
			msg->payload.pcie_msix_msg.func_no[msg->payload.pcie_msix_msg.num++] =
				func_no;
			zxdh_pf_set_vf_link_info(dh_dev, vf_idx, link_info);
			LOG_DEBUG(
				"[pf_level] bond_pf pcie_id:0x%x write phyport[0x%x] and link_up[%d] to VF[%d] VQM[0x%x]\n",
				pf_dev->pcie_id, phyport_val, link_up_val, vf_idx, link_info);
		}
	}
	LOG_DEBUG("vf num:%d\n", msg->payload.pcie_msix_msg.num);
	if (msg->payload.pcie_msix_msg.num > 0) {
		err = zxdh_pf_msg_send_cmd(dh_dev, MODULE_MAC, msg, msg, &para);
		if (err != 0)
			LOG_ERR("failed to update VF link info\n");
	}

	kfree(msg);
}

static void init_vf_link_info_work_handler(struct work_struct *_work)
{
	struct zxdh_pf_device *pf_dev =
		container_of(_work, struct zxdh_pf_device, init_vf_link_info_work);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct zxdh_vf_item *vf_item = NULL;
	s32 err = 0;
	u16 vf_idx = 0;
	struct pci_dev *pdev = dh_dev->pdev;
	u16 num_vfs = 0;
	u8 link_up_val = 0;
	u8 link_info = 0;
	u16 func_no = 0;
	u16 pf_no = FIND_PF_ID(pf_dev->pcie_id);
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	if (pf_dev->aux_comp_flag != 1)
		return;

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%zu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return;
	}

	zxdh_pf_get_link_info_from_vqm(dh_dev, &link_up_val);
	pf_dev->link_up = (link_up_val == 0) ? FALSE : TRUE;

	if (zxdh_pf_is_upf(dh_dev)) {
		link_info = (pf_dev->phy_port & 0x0F) << 4 | (link_up_val & 0x0F);
		LOG_DEBUG("upf update vf link_info: %u\n", link_info);
	} else {
		link_info = pf_dev->link_up ? 1 : 0;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_DEV_STATUS_NOTIFY;
	msg->payload.hdr_to_agt.pcie_id = pf_dev->pcie_id;

	num_vfs = pci_num_vf(pdev);
	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vf_item = zxdh_pf_get_vf_item(dh_dev, vf_idx);
		if (vf_item->link_forced == FALSE && vf_item->is_probed) {
			func_no = GET_FUNC_NO(pf_no, vf_idx);
			msg->payload.pcie_msix_msg.func_no[msg->payload.pcie_msix_msg.num++] =
				func_no;
			zxdh_pf_set_vf_link_info(dh_dev, vf_idx, link_info);
			LOG_DEBUG("pcie_id:0x%x init VF[%d] VQM[0x%x]\n", pf_dev->pcie_id, vf_idx,
				  link_info);
		}
	}
	LOG_DEBUG("pcie_id:0x%x vf num:%d\n", pf_dev->pcie_id, msg->payload.pcie_msix_msg.num);
	if (msg->payload.pcie_msix_msg.num > 0) {
		err = zxdh_pf_msg_send_cmd(dh_dev, MODULE_MAC, msg, msg, &para);
		if (err != 0)
			LOG_ERR("failed to update VF link info\n");
	}

	kfree(msg);
}

static void riscv_extern_pps_handler(struct work_struct *_work)
{
#ifdef PTP_DRIVER_INTERFACE_EN
	struct zxdh_pf_device *pf_dev =
		container_of(_work, struct zxdh_pf_device, riscv_ext_pps_work);
	msix_extern_pps_irq_from_risc_handler(pf_dev);
#endif
}

static void riscv_local_pps_handler(struct work_struct *_work)
{
#ifdef PTP_DRIVER_INTERFACE_EN
	struct zxdh_pf_device *pf_dev =
		container_of(_work, struct zxdh_pf_device, riscv_local_pps_work);
	msix_local_pps_irq_from_risc_handler(pf_dev);
#endif
}

static void mac_info_pf_work_handler(struct work_struct *_work)
{
	struct zxdh_pf_device *pf_dev =
		container_of(_work, struct zxdh_pf_device, mac_info_pf_work);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct zxdh_vf_item *vf_item = NULL;
	struct pci_dev *pdev = dh_dev->pdev;
	u16 vf_vport = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct MAC_VPORT_INFO *unicast_mac_arry = NULL;
	u32 current_unicast_num = 0;
	s32 retval = 0;
	u32 i = 0;
	u32 j = 0;
	s32 num_vfs = 0;
	u32 val = 0;
	u8 vf_flag[ZXDH_VF_NUM] = { 0 };
	u8 sum_flag = 0;
	u8 ep_id = (pf_dev->pcie_id >> 12) & 0x7;
	u8 pf_id = (pf_dev->pcie_id >> 8) & 0x7;

	if (pf_dev->aux_comp_flag != 1)
		return;

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return;

	unicast_mac_arry = kzalloc(sizeof(struct MAC_VPORT_INFO) * UNICAST_MAX_NUM, GFP_KERNEL);
	if (!unicast_mac_arry) {
		LOG_ERR("kzalloc unicast_mac_arry failed\n");
		return;
	}

	num_vfs = pci_num_vf(pdev);
	if (num_vfs == 0) {
		kfree(unicast_mac_arry);
		return;
	}

	for (i = 0; i < num_vfs; i++) {
		val = ioread8((void __iomem *)(uintptr_t)(
			pf_dev->pci_ioremap_addr[0] + ZXDH_MAC_FLAG_BAR_OFFSET +
			ep_id * ZXDH_EP_FLAG_SIZE + pf_id * ZXDH_PF_FLAG_SIZE + i));
		if (val == 1) {
			vf_flag[sum_flag] = i;
			iowrite8(0, (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
								ZXDH_MAC_FLAG_BAR_OFFSET +
								ep_id * ZXDH_EP_FLAG_SIZE +
								pf_id * ZXDH_PF_FLAG_SIZE + i));
			sum_flag++;
		}
	}

	for (i = 0; i < sum_flag; i++) {
		vf_item = zxdh_pf_get_vf_item(dh_dev, vf_flag[i]);
		pf_info.slot = pf_dev->slot_id;
		pf_info.vport = pf_dev->vport;
		vf_vport = vf_item->vport;
		retval = dpp_unicast_mac_dump(&pf_info, unicast_mac_arry, &current_unicast_num);
		if (retval != 0) {
			kfree(unicast_mac_arry);
			LOG_ERR("dpp_unicast_mac_dump failed, retval:%d\n", retval);
			return;
		}

		for (j = 0; j < current_unicast_num; j++) {
			if (vf_vport == unicast_mac_arry[j].vport) {
				retval = dpp_del_mac(&pf_info, unicast_mac_arry[j].addr,
						     unicast_mac_arry[j].sriov_vlan_tpid,
						     unicast_mac_arry[j].sriov_vlan_id);
				if (retval != 0) {
					LOG_ERR("dpp_del_mac failed, ret: %d\n", retval);
					kfree(unicast_mac_arry);
					return;
				}
				LOG_INFO("dpp_del_mac success, vport: 0x%x\n", vf_vport);
			}
		}

		vf_item->is_probed = false;
	}

	kfree(unicast_mac_arry);
}

void zxdh_pf_nh_attach(struct dh_core_dev *dev, struct dh_nb *nb, bool attach)
{
	struct dh_eq_table *eq_table = &dev->eq_table;

	if (attach)
		dh_eq_notifier_register(eq_table, nb);
	else
		dh_eq_notifier_unregister(eq_table, nb);
}

s32 dh_pf_events_init(struct dh_core_dev *dev)
{
	struct dh_events *events = NULL;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	s32 i = 0;
	s32 ret = 0;
	u32 evt_num = ARRAY_SIZE(pf_events);

	if (pf_dev->bond_num != 0)
		evt_num -= 1;
	events = kzalloc((sizeof(*events) + evt_num * sizeof(struct dh_event_nb)), GFP_KERNEL);
	if (unlikely(!events)) {
		LOG_ERR("events kzalloc failed: %p\n", events);
		ret = -ENOMEM;
		goto err_events_kzalloc;
	}

	events->evt_num = evt_num;
	events->dev = dev;
	dev->events = events;
	events->wq = create_singlethread_workqueue("dh_pf_events");
	if (!events->wq) {
		LOG_ERR("events->wq create_singlethread_workqueue failed: %p\n", events->wq);
		ret = -ENOMEM;
		goto err_create_wq;
	}

	INIT_WORK(&pf_dev->riscv_ready_work, riscv_ready_work_handler);
	INIT_WORK(&pf_dev->riscv2pf_msg_proc_work, riscv2pf_msg_proc_work_handler);
	INIT_WORK(&pf_dev->vf2pf_msg_proc_work, vf2pf_msg_proc_work_handler);
	INIT_WORK(&pf_dev->link_info_irq_update_vf_bond_pf_work,
		  link_info_irq_update_vf_bond_pf_work_handler);
	INIT_WORK(&pf_dev->init_vf_link_info_work, init_vf_link_info_work_handler);
	INIT_WORK(&pf_dev->riscv_ext_pps_work, riscv_extern_pps_handler);
	INIT_WORK(&pf_dev->riscv_local_pps_work, riscv_local_pps_handler);
	INIT_WORK(&pf_dev->mac_info_pf_work, mac_info_pf_work_handler);

	for (i = 0; i < evt_num; i++) {
		events->notifiers[i].nb = pf_events[i];
		events->notifiers[i].ctx = dev;
		dh_eq_notifier_register(&dev->eq_table, &events->notifiers[i].nb);
	}

	return 0;

err_create_wq:
	kfree(events);
err_events_kzalloc:
	return ret;
}

void dh_pf_events_uninit(struct dh_core_dev *dev)
{
	struct dh_events *events = dev->events;
	s32 i = 0;

	for (i = events->evt_num - 1; i >= 0; i--)
		dh_eq_notifier_unregister(&dev->eq_table, &events->notifiers[i].nb);

	zxdh_events_cleanup(dev);
}

void dh_pf_sriov_cap_cfg_uninit(struct dh_core_dev *dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);

	if (dev->coredev_type == DH_COREDEV_PF && pf_dev->pf_sriov_cap_base) {
		iounmap((void *)pf_dev->pf_sriov_cap_base);
		pf_dev->pf_sriov_cap_base = NULL;
	}
}
