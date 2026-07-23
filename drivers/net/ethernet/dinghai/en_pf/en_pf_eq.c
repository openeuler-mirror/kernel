// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/eq.h>
#include <linux/dinghai/driver.h>
#include <linux/dinghai/helper.h>
#include <linux/dinghai/dh_cmd.h>
#include <linux/list.h>
#include "en_pf_irq.h"
#include "en_pf_eq.h"
#include "../msg_common.h"
#include "../en_pf.h"

static s32 create_async_eqs(struct dh_core_dev *dev);

s32 dh_pf_eq_table_init(struct dh_core_dev *dev)
{
	struct dh_pf_eq_table *table_priv = NULL;

	table_priv = kvzalloc(sizeof(*table_priv), GFP_KERNEL);
	if (unlikely(!table_priv)) {
		LOG_ERR("dh_pf_eq_table kvzalloc failed\n");
		return -ENOMEM;
	}

	dh_eq_table_init(dev, table_priv);

	return 0;
}

u16 zxdh_pf_get_vqs_channels_num(struct dh_core_dev *dh_dev)
{
	if ((dh_dev->pdev->device == ZXDH_INICA_BOND_DEVICE_ID) ||
	    (dh_dev->pdev->device == ZXDH_INICB_BOND_DEVICE_ID) ||
	    (dh_dev->pdev->device == ZXDH_INICC_BOND_DEVICE_ID) ||
	    (dh_dev->pdev->device == ZXDH_INICA_UPF_BOND_DEVICE_ID) ||
	    (dh_dev->pdev->device == ZXDH_DPUA_BOND_DEVICE_ID) ||
	    (dh_dev->pdev->device == ZXDH_INICD_BOND0_DEVICE_ID) ||
	    (dh_dev->pdev->device == ZXDH_INICD_BOND1_DEVICE_ID)) {
		return ZXDH_BOND_VQS_CHANNELS_NUM;
	}

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return ZXDH_VF_VQS_CHANNELS_NUM;
	return ZXDH_VQS_CHANNELS_NUM;
}

void zxdh_pf_switch_irq(struct dh_core_dev *dh_dev, s32 i, s32 op)
{
	if (op) {
		enable_irq(i);
		return;
	}

	disable_irq(i);
}

s32 zxdh_pf_vq_irqs_request(struct dh_core_dev *dh_dev, struct dh_irq **vq_irqs, s32 vq_channels,
			    void *data)
{
	struct dh_irq_table *irq_table = &dh_dev->irq_table;
	struct dh_pf_irq_table *pf_irq_table = irq_table->priv;
	s32 ret = 0;
	s32 vqs_irq_num = vq_channels;
	int numa = dev_to_node(dh_dev->device);

	pf_irq_table->pf_vq_pool->data = data;
	ret = dh_irq_affinity_irqs_request_auto(pf_irq_table->pf_vq_pool, vq_irqs, vqs_irq_num,
						numa);
	if (ret < vqs_irq_num) {
		LOG_ERR("the actual obtain irq_num %d < need request irq_num %d\n", ret,
			vqs_irq_num);
		return -1;
	}

	return ret;
}

void zxdh_pf_affinity_irqs_release(struct dh_core_dev *dh_dev, struct dh_irq **vq_irqs,
				   s32 num_irqs)
{
	struct dh_irq_table *irq_table = &dh_dev->irq_table;
	struct dh_pf_irq_table *pf_irq_table = irq_table->priv;

	dh_irq_affinity_irqs_release(pf_irq_table->pf_vq_pool, vq_irqs, num_irqs);
}

static s32 destroy_async_eq(struct dh_core_dev *dev)
{
	struct dh_eq_table *eq_table = &dev->eq_table;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct msix_para in = { 0 };
	s32 err = 0;

	if (pf_dev->quick_remove)
		return 0;

	in.vector_risc = ZXDH_PF_INVALID_MSIX_VEC;
	in.vector_pfvf = ZXDH_PF_INVALID_MSIX_VEC;
	in.vector_mpf = ZXDH_PF_INVALID_MSIX_VEC;
	in.driver_type = MSG_CHAN_END_PF;
	in.pdev = dev->pdev;
	in.virt_addr = pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_OFFSET;
	in.pcie_id = pf_dev->pcie_id;

	mutex_lock(&eq_table->lock);

	err = zxdh_bar_enable_chan(&in, &pf_dev->vport);
	if (err != 0)
		LOG_ERR("zxdh_bar_disable_chan failed\n");

	mutex_unlock(&eq_table->lock);

	return err;
}

s32 dh_pf_eq_table_create(struct dh_core_dev *dev)
{
	s32 err = 0;

	err = create_async_eqs(dev);
	if (err != 0) {
		LOG_ERR("Failed to create async EQs: %d\n", err);
		return err;
	}

	return 0;
}

/*create eventq*/
static s32 create_async_eq(struct dh_core_dev *dev, struct dh_irq *riscv, struct dh_irq *pf)
{
	struct dh_eq_table *eq_table = &dev->eq_table;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct msix_para in = { 0 };
	int ret = 0;

	in.vector_risc = riscv->index;
	in.vector_pfvf = pf->index;
	in.vector_mpf = ZXDH_PF_INVALID_MSIX_VEC;

	in.driver_type = MSG_CHAN_END_PF;
	in.pdev = dev->pdev;
	in.virt_addr = pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_OFFSET;
	in.pcie_id = pf_dev->pcie_id;

	if (dev->coredev_type == DH_COREDEV_PF)
		bar_chan_pf_init_spinlock(pf_dev->pcie_id, pf_dev->pci_ioremap_addr[0]);

	mutex_lock(&eq_table->lock);

	LOG_DEBUG("msix vector riscv: %d, pfvf: %d\n", riscv->index, pf->index);
	ret = zxdh_bar_enable_chan(&in, &pf_dev->vport);
	if (!ret)
		pf_dev->bar_chan_valid = true;

	mutex_unlock(&eq_table->lock);

	return ret;
}

static s32 dh_eq_async_riscv_int(struct notifier_block *nb, unsigned long action, void *data)
{
	struct dh_eq_async *eq_riscv_async = container_of(nb, struct dh_eq_async, irq_nb);
	struct dh_core_dev *dev = (struct dh_core_dev *)eq_riscv_async->priv;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct dh_eq_table *eq_table = &dev->eq_table;
	struct dh_events *events = dev->events;
	struct dh_event_nb *event_nb = NULL;
	u64 virt_addr = 0;
	s32 event_type = 0;
	u16 event_idx = 0;
	u16 i = 0;
	u8 src = MSG_CHAN_END_RISC;
	u8 dst = MSG_CHAN_END_VF;

	if (dev->coredev_type == DH_COREDEV_PF)
		dst = MSG_CHAN_END_PF;

	virt_addr = pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_OFFSET;
	event_idx = zxdh_get_event_id(virt_addr, src, dst);
	event_type = dh_eq_event_type_get(event_idx);

	if (!events) {
		LOG_ERR("riscv_irq trigger, events is null\n");
		return 0;
	}

	for (i = 0; i < events->evt_num; i++) {
		event_nb = &events->notifiers[i];
		if (event_type == event_nb->nb.event_type) {
			LOG_DEBUG("en_pf event_type[%d] is called\n", event_type);
			atomic_notifier_call_chain(&eq_table->nh[event_type], event_type, NULL);
			return NOTIFY_STOP_MASK;
		}
	}

	return 0;
}

static s32 dh_eq_async_pf_int(struct notifier_block *nb, unsigned long action, void *data)
{
	struct dh_eq_async *eq_riscv_async = container_of(nb, struct dh_eq_async, irq_nb);
	struct dh_core_dev *dev = (struct dh_core_dev *)eq_riscv_async->priv;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct dh_eq_table *eq_table = &dev->eq_table;
	struct dh_events *events = dev->events;
	struct dh_event_nb *event_nb = NULL;
	u64 virt_addr = 0;
	s32 event_type = 0;
	u16 event_idx = 0;
	u16 i = 0;

	if (dev->coredev_type == DH_COREDEV_VF)
		return 0;

	virt_addr = pf_dev->pci_ioremap_addr[0] + ZXDH_BAR_MSG_OFFSET + ZXDH_BAR_PFVF_MSG_OFFSET;
	event_idx = zxdh_get_event_id(virt_addr, MSG_CHAN_END_VF, MSG_CHAN_END_PF);
	event_type = dh_eq_event_type_get(event_idx);

	for (i = 0; i < events->evt_num; i++) {
		event_nb = &events->notifiers[i];

		if (event_type == event_nb->nb.event_type) {
			LOG_DEBUG("en_pf async pf/vf irq_handler called\n");
			atomic_notifier_call_chain(&eq_table->nh[event_type], event_type, NULL);
			return NOTIFY_STOP_MASK;
		}
	}

	return 0;
}

static s32 dh_eq_async_link_info_int_bond_pf(struct notifier_block *nb, unsigned long action,
					     void *data)
{
	struct dh_eq_async *eq_riscv_async = container_of(nb, struct dh_eq_async, irq_nb);
	struct dh_core_dev *dev = (struct dh_core_dev *)eq_riscv_async->priv;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);

	if (!zxdh_pf_is_bond(dev)) {
		LOG_DEBUG("isn't bond_pf exit\n");
		return 0;
	}

	zxdh_events_work_enqueue(dev, &pf_dev->link_info_irq_update_vf_bond_pf_work);
	return 0;
}

static s32 dh_eq_async_extpps_int(struct notifier_block *nb, unsigned long action, void *data)
{
	struct dh_eq_async *eq_pps_async = container_of(nb, struct dh_eq_async, irq_nb);
	struct dh_core_dev *dev = (struct dh_core_dev *)eq_pps_async->priv;
	struct dh_eq_table *eq_table = &dev->eq_table;

	atomic_notifier_call_chain(&eq_table->nh[DH_EVENT_TYPE_NOTIFY_RISC_EXT_PPS],
				   DH_EVENT_TYPE_NOTIFY_RISC_EXT_PPS, NULL);
	return 0;
}

static s32 dh_eq_async_local_pps_int(struct notifier_block *nb, unsigned long action, void *data)
{
	struct dh_eq_async *eq_pps_async = container_of(nb, struct dh_eq_async, irq_nb);
	struct dh_core_dev *dev = (struct dh_core_dev *)eq_pps_async->priv;
	struct dh_eq_table *eq_table = &dev->eq_table;

	atomic_notifier_call_chain(&eq_table->nh[DH_EVENT_TYPE_NOTIFY_RISC_LOCAL_PPS],
				   DH_EVENT_TYPE_NOTIFY_RISC_LOCAL_PPS, NULL);
	return 0;
}

static s32 dh_eq_async_mac_info_pf(struct notifier_block *nb, unsigned long action, void *data)
{
	struct dh_eq_async *eq_riscv_async = container_of(nb, struct dh_eq_async, irq_nb);
	struct dh_core_dev *dh_dev = (struct dh_core_dev *)eq_riscv_async->priv;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return 0;

	zxdh_events_work_enqueue(dh_dev, &pf_dev->mac_info_pf_work);
	return 0;
}

static s32 dh_eq_rsv_int(struct notifier_block *nb, unsigned long action, void *data)
{
	LOG_DEBUG("%s is called\n", __func__);
	return 0;
}

static struct dh_pf_async_irq_table dh_pf_async_irq_tbl[] = {
	{ "link_info", dh_eq_async_link_info_int_bond_pf },
	{ "riscv", dh_eq_async_riscv_int },
	{ "pf", dh_eq_async_pf_int },
	{ "expps", dh_eq_async_extpps_int },
	{ "localpps", dh_eq_async_local_pps_int },
	{ "rsv", dh_eq_rsv_int },
	{ "mac_info", dh_eq_async_mac_info_pf },
};

static struct dh_pf_async_irq_table dh_vf_async_irq_tbl[] = {
	{ "link_info", dh_eq_async_link_info_int_bond_pf },
	{ "riscv", dh_eq_async_riscv_int },
	{ "pf", dh_eq_async_pf_int },
	{ "expps", dh_eq_async_extpps_int },
	{ "localpps", dh_eq_async_local_pps_int },
};

static void cleanup_async_eq(struct dh_core_dev *dev, struct dh_eq_async *eq, const char *name)
{
	dh_eq_disable(dev, &eq->core, &eq->irq_nb);
}

static void destroy_async_eqs(struct dh_core_dev *dev)
{
	struct dh_eq_table *table = &dev->eq_table;
	struct dh_pf_eq_table *table_priv = table->priv;
	const struct dh_pf_async_irq_table *irq_tbl;
	s32 tbl_size = 0;
	s32 i = 0;

	if (dev->coredev_type == DH_COREDEV_PF) {
		irq_tbl = dh_pf_async_irq_tbl;
		tbl_size = ARRAY_SIZE(dh_pf_async_irq_tbl);
	} else {
		irq_tbl = dh_vf_async_irq_tbl;
		tbl_size = ARRAY_SIZE(dh_vf_async_irq_tbl);
	}

	for (i = 0; i < tbl_size; ++i)
		cleanup_async_eq(dev, &table_priv->async_eq_tbl[i], irq_tbl[i].name);

	destroy_async_eq(dev);
	dh_irqs_release_vectors(table_priv->async_irq_tbl, tbl_size);
}

void dh_pf_eq_table_destroy(struct dh_core_dev *dev)
{
	destroy_async_eqs(dev);
}

static s32 create_async_eqs(struct dh_core_dev *dev)
{
	struct dh_eq_table *table = &dev->eq_table;
	struct dh_pf_eq_table *table_priv = table->priv;
	struct dh_eq_param param = {};
	s32 err = 0;
	const struct dh_pf_async_irq_table *irq_tbl;
	s32 tbl_size = 0;
	s32 i = 0;
	s32 j = 0;
	s32 k = 0;

	if (dev->coredev_type == DH_COREDEV_PF) {
		irq_tbl = dh_pf_async_irq_tbl;
		tbl_size = ARRAY_SIZE(dh_pf_async_irq_tbl);
	} else {
		irq_tbl = dh_vf_async_irq_tbl;
		tbl_size = ARRAY_SIZE(dh_vf_async_irq_tbl);
	}

	for (i = 0; i < tbl_size; ++i) {
		table_priv->async_irq_tbl[i] = dh_pf_async_irq_request(dev);
		if (IS_ERR(table_priv->async_irq_tbl[i])) {
			err = PTR_ERR(table_priv->async_irq_tbl[i]);
			LOG_ERR("Failed to get async_irq_tbl[%d]\n", i);
			goto err_async_irq_request;
		}
	}

	err = create_async_eq(dev, table_priv->async_irq_tbl[1], table_priv->async_irq_tbl[2]);
	if (err != 0) {
		LOG_ERR("Failed to create async_eq\n");
		goto err_async_irq_request;
	}

	param.nent = 10;
	param.event_type = DH_EVENT_QUEUE_TYPE_RISCV;
	for (j = 0; j < tbl_size; ++j) {
		param.irq = table_priv->async_irq_tbl[j];
		err = setup_async_eq(dev, &table_priv->async_eq_tbl[j], &param,
				     irq_tbl[j].async_int, irq_tbl[j].name, dev);
		if (err != 0) {
			LOG_ERR("Failed to setup async_eq_tbl[%d]\n", j);
			goto err_setup_async_eq;
		}
	}

	return 0;

err_setup_async_eq:
	for (k = 0; k < j; ++k)
		cleanup_async_eq(dev, &table_priv->async_eq_tbl[j], irq_tbl[j].name);

	destroy_async_eq(dev);
err_async_irq_request:
	dh_irqs_release_vectors(table_priv->async_irq_tbl, i);
	return err;
}

s32 zxdh_pf_async_eq_enable(struct dh_core_dev *dh_dev, struct dh_eq_async *eq, const char *name,
			    bool attach)
{
	struct dh_eq_table *table = &dh_dev->eq_table;
	struct dh_pf_eq_table *table_priv = table->priv;
	s32 err = 0;
	const struct dh_pf_async_irq_table *irq_tbl;
	s32 tbl_size = 0;
	s32 i = 0;

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		irq_tbl = dh_pf_async_irq_tbl;
		tbl_size = ARRAY_SIZE(dh_pf_async_irq_tbl);
	} else {
		irq_tbl = dh_vf_async_irq_tbl;
		tbl_size = ARRAY_SIZE(dh_vf_async_irq_tbl);
	}

	for (i = 0; i < tbl_size; ++i) {
		if (strcmp(irq_tbl[i].name, name) == 0) {
			eq->core.irq = table_priv->async_irq_tbl[i];
			break;
		}
	}

	if (i == tbl_size) {
		LOG_ERR("failed to find %s irq\n", name);
		return -1;
	}

	LOG_DEBUG("%s attach[%d] irq[%d]\n", name, attach, eq->core.irq->index);
	if (attach) {
		err = dh_eq_enable(dh_dev, &eq->core, &eq->irq_nb);
		if (err != 0)
			LOG_WARN("failed to enable EQ %d\n", err);
	} else {
		dh_eq_disable(dh_dev, &eq->core, &eq->irq_nb);
	}

	return err;
}

void zxdh_pf_get_link_info_from_vqm(struct dh_core_dev *dh_dev, u8 *link_up)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u32 dev_link_up = 0;

	dev_link_up =
		ioread32((void __iomem *)((uintptr_t)pf_dev->device + ZXDH_DEV_MAC_HIGH_OFFSET));
	*link_up = (dev_link_up >> 16) & 0xff;

	LOG_DEBUG("dev pcieid:0x%x ******** link_up: %d ********\n", pf_dev->pcie_id, *link_up);
}

void zxdh_pf_set_vf_link_info(struct dh_core_dev *dh_dev, u16 vf_idx, u8 link_up)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u32 dev_link_up = 0;

	LOG_DEBUG("dev pcieid:0x%x write link_val %d to vf%d\n", pf_dev->pcie_id, link_up, vf_idx);

	if (pf_dev->pf_sriov_cap_base) {
		dev_link_up = ioread32((void __iomem *)(pf_dev->pf_sriov_cap_base +
							(pf_dev->sriov_bar_size) * vf_idx +
							pf_dev->dev_cfg_bar_off +
							ZXDH_DEV_MAC_HIGH_OFFSET));
		dev_link_up = (dev_link_up & ~(0xFF << 16)) | ((u32)(link_up) << 16);
		iowrite32(dev_link_up,
			  (void __iomem *)(pf_dev->pf_sriov_cap_base +
					   (pf_dev->sriov_bar_size) * vf_idx +
					   pf_dev->dev_cfg_bar_off + ZXDH_DEV_MAC_HIGH_OFFSET));
	}
}

bool zxdh_pf_get_vf_is_probe(struct dh_core_dev *dh_dev, u16 vf_idx)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u32 dev_link_up = 0;
	struct zxdh_vf_item *vf_item = NULL;
	u16 num_vfs = 0;

	num_vfs = pci_num_vf(dh_dev->pdev);
	if (vf_idx >= num_vfs) {
		LOG_ERR("invalid VF idx: %d\n", vf_idx);
		return false;
	}

	if (pf_dev->pf_sriov_cap_base) {
		dev_link_up = ioread32((void __iomem *)(pf_dev->pf_sriov_cap_base +
							(pf_dev->sriov_bar_size) * vf_idx +
							pf_dev->dev_cfg_bar_off +
							ZXDH_DEV_MAC_HIGH_OFFSET));
	}

	vf_item = &pf_dev->vf_item[vf_idx];
	return ((((u8)((dev_link_up >> 16) & 0xff)) != 0xff) && (vf_item->is_probed));
}

void zxdh_pf_set_pf_phy_port(struct dh_core_dev *dh_dev, u8 phy_port)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	pf_dev->phy_port = phy_port;
#ifdef CONFIG_DINGHAI_TSN
	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		if (!pf_dev->tsn) {
			LOG_ERR("pf_dev->tsn is null\n");
			return;
		}
		pf_dev->tsn->phy_port_id = phy_port;
	}
#endif
}

u8 zxdh_pf_get_pf_phy_port(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->phy_port;
}

void zxdh_pf_set_pf_link_up(struct dh_core_dev *dh_dev, bool link_up)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	pf_dev->link_up = link_up;
}

bool zxdh_pf_get_pf_link_up(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->link_up;
}

s32 zxdh_pf_call_aux_events(struct dh_core_dev *dev, s32 event_type)
{
	struct dh_eq_table *eq_table = &dev->eq_table;
	s32 err = 0;

	atomic_notifier_call_chain(&eq_table->nh[event_type], event_type, &err);
	if (err != 0)
		return err;

	if (event_type == DH_EVENT_TYPE_AUX_LOAD)
		zxdh_pf_status_ok(dev);

	return 0;
}

s32 zxdh_pf_call_aux_events_with_data(struct dh_core_dev *dev, s32 event_type, void *data)
{
	struct dh_eq_table *eq_table = &dev->eq_table;

	atomic_notifier_call_chain(&eq_table->nh[event_type], event_type, data);
	return 0;
}
