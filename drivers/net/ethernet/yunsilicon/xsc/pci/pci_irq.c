// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include "common/driver.h"
#include "common/xsc_hsi.h"
#include "common/xsc_core.h"
#ifdef CONFIG_RFS_ACCEL
#include <linux/cpu_rmap.h>
#endif
#include "fw/xsc_flow.h"
#include "fw/xsc_fw.h"
#include "common/tunnel_cmd.h"

enum xsc_eq_type {
	XSC_EQ_TYPE_COMP,
	XSC_EQ_TYPE_ASYNC,
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	XSC_EQ_TYPE_PF,
#endif
};

struct xsc_irq {
	struct atomic_notifier_head nh;
	cpumask_var_t mask;
	char name[XSC_MAX_IRQ_NAME];
};

struct xsc_irq_table {
	struct xsc_irq *irq;
	int nvec;
#ifdef CONFIG_RFS_ACCEL
	struct cpu_rmap *rmap;
#endif
};


struct xsc_msix_resource *g_msix_xres;

static irqreturn_t xsc_dma_read_msix_handler(int irq, void *dev_id)
{
	xsc_dma_read_done_complete();
	return IRQ_HANDLED;
}

static int xsc_dma_read_msix_init(struct xsc_core_device *xdev)
{
	int err;
	char *name = "xsc_dma_read_done";
	struct xsc_dev_resource *dev_res = xdev->dev_res;
	int irqn;
	int vecid = 0;

	snprintf(dev_res->irq_info[XSC_DMA_READ_DONE_VEC].name, XSC_MAX_IRQ_NAME, "%s@pci:%s",
		 name, pci_name(xdev->pdev));
	irqn = pci_irq_vector(xdev->pdev, XSC_DMA_READ_DONE_VEC);
	err = request_irq(irqn, xsc_dma_read_msix_handler, 0,
			  dev_res->irq_info[XSC_DMA_READ_DONE_VEC].name, (void *)xdev);

	vecid = (xdev->msix_vec_base + XSC_DMA_READ_DONE_VEC);
	xsc_set_read_done_msix_vector(xdev, vecid);

	return err;
}

static void xsc_free_irq(struct xsc_core_device *xdev, unsigned int vector)
{
	unsigned int irqn = 0;

	irqn = pci_irq_vector(xdev->pdev, vector);
	disable_irq(irqn);

	if (xsc_fw_is_available(xdev))
		free_irq(irqn, xdev);
}

static void xsc_dma_read_msix_fini(struct xsc_core_device *xdev)
{
	if (xdev->caps.msix_enable && xsc_core_is_pf(xdev))
		xsc_free_irq(xdev, XSC_DMA_READ_DONE_VEC);
}

struct xsc_eq *xsc_eq_get(struct xsc_core_device *dev, int i)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	struct xsc_eq *eq, *n;
	struct xsc_eq *eq_ret = NULL;

	spin_lock(&table->lock);
	list_for_each_entry_safe(eq, n, &table->comp_eqs_list, list) {
		if (eq->index == i) {
			eq_ret = eq;
			break;
		}
	}
	spin_unlock(&table->lock);

	return eq_ret;
}
EXPORT_SYMBOL(xsc_eq_get);

void mask_cpu_by_node(int node, struct cpumask *dstp)
{
	int i;

	for (i = 0; i < nr_cpu_ids; i++) {
		if (node == cpu_to_node(i))
			cpumask_set_cpu(i, dstp);
	}
}
EXPORT_SYMBOL(mask_cpu_by_node);

static int set_comp_irq_affinity_hint(struct xsc_core_device *dev, int i)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	int vecidx = table->eq_vec_comp_base + i;
	struct xsc_eq *eq = xsc_eq_get(dev, i);
	unsigned int irqn;
	int ret;

	irqn = pci_irq_vector(dev->pdev, vecidx);
	if (!zalloc_cpumask_var(&eq->mask, GFP_KERNEL)) {
		xsc_core_err(dev, "zalloc_cpumask_var rx cpumask failed");
		return -ENOMEM;
	}

	if (!zalloc_cpumask_var(&dev->xps_cpumask, GFP_KERNEL)) {
		xsc_core_err(dev, "zalloc_cpumask_var tx cpumask failed");
		return -ENOMEM;
	}

	mask_cpu_by_node(dev->priv.numa_node, eq->mask);
	ret = irq_set_affinity_hint(irqn, eq->mask);

	return ret;
}

static void clear_comp_irq_affinity_hint(struct xsc_core_device *dev, int i)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	int vecidx = table->eq_vec_comp_base + i;
	struct xsc_eq *eq = xsc_eq_get(dev, i);
	int irqn;

	irqn = pci_irq_vector(dev->pdev, vecidx);
	irq_set_affinity_hint(irqn, NULL);
	free_cpumask_var(eq->mask);
}

static int set_comp_irq_affinity_hints(struct xsc_core_device *dev)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	int nvec = table->num_comp_vectors;
	int err;
	int i;

	for (i = 0; i < nvec; i++) {
		err = set_comp_irq_affinity_hint(dev, i);
		if (err)
			goto err_out;
	}

	return 0;

err_out:
	for (i--; i >= 0; i--)
		clear_comp_irq_affinity_hint(dev, i);
	free_cpumask_var(dev->xps_cpumask);

	return err;
}

static void clear_comp_irq_affinity_hints(struct xsc_core_device *dev)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	int nvec = table->num_comp_vectors;
	int i;

	for (i = 0; i < nvec; i++)
		clear_comp_irq_affinity_hint(dev, i);
	free_cpumask_var(dev->xps_cpumask);
}

struct cpumask *
xsc_comp_irq_get_affinity_mask(struct xsc_core_device *dev, int vector)
{
	struct xsc_eq *eq = xsc_eq_get(dev, vector);

	if (unlikely(!eq))
		return NULL;

	return eq->mask;
}
EXPORT_SYMBOL(xsc_comp_irq_get_affinity_mask);

static int xsc_alloc_irq_vectors(struct xsc_core_device *dev)
{
	struct xsc_dev_resource *dev_res = dev->dev_res;
	struct xsc_eq_table *table = &dev_res->eq_table;
	int nvec = dev->caps.msix_num;
	int nvec_base;
	int err;

	if (xsc_core_is_pf(dev))
		nvec_base = XSC_EQ_VEC_COMP_BASE;
	else
		/*VF device not need dma read done vector.*/
		nvec_base = (XSC_EQ_VEC_COMP_BASE - 1);

	if (nvec <= nvec_base) {
		xsc_core_warn(dev, "failed to alloc irq vector(%d)\n", nvec);
		return -ENOMEM;
	}

	dev_res->irq_info = kcalloc(nvec, sizeof(*dev_res->irq_info), GFP_KERNEL);
	if (!dev_res->irq_info)
		return -ENOMEM;

	nvec = pci_alloc_irq_vectors(dev->pdev, nvec_base + 1, nvec, PCI_IRQ_MSIX);
	if (nvec < 0) {
		err = nvec;
		goto err_free_irq_info;
	}

	table->eq_vec_comp_base = nvec_base;
	table->num_comp_vectors = nvec - nvec_base;
	dev->msix_vec_base = dev->caps.msix_base;
	xsc_core_info(dev,
		      "alloc msix_vec_num=%d, comp_num=%d, max_msix_num=%d, msix_vec_base=%d\n",
		      nvec, table->num_comp_vectors, dev->caps.msix_num, dev->msix_vec_base);

	return 0;

err_free_irq_info:
	pci_free_irq_vectors(dev->pdev);
	kfree(dev_res->irq_info);
	return err;
}

static void xsc_free_irq_vectors(struct xsc_core_device *dev)
{
	struct xsc_dev_resource *dev_res = dev->dev_res;

	if (!xsc_fw_is_available(dev))
		return;

	pci_free_irq_vectors(dev->pdev);
	kfree(dev_res->irq_info);
}

int xsc_vector2eqn(struct xsc_core_device *dev, int vector, int *eqn,
		   unsigned int *irqn)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	struct xsc_eq *eq, *n;
	int err = -ENOENT;

	if (!dev->caps.msix_enable)
		return 0;

	spin_lock(&table->lock);
	list_for_each_entry_safe(eq, n, &table->comp_eqs_list, list) {
		if (eq->index == vector) {
			*eqn = eq->eqn;
			*irqn = eq->irqn;
			err = 0;
			break;
		}
	}
	spin_unlock(&table->lock);

	return err;
}
EXPORT_SYMBOL(xsc_vector2eqn);

static void free_comp_eqs(struct xsc_core_device *dev)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	struct xsc_eq *eq, *n;

	spin_lock(&table->lock);
	list_for_each_entry_safe(eq, n, &table->comp_eqs_list, list) {
		list_del(&eq->list);
		spin_unlock(&table->lock);
		if (xsc_destroy_unmap_eq(dev, eq))
			xsc_core_warn(dev, "failed to destroy EQ 0x%x\n", eq->eqn);
		kfree(eq);
		spin_lock(&table->lock);
	}
	spin_unlock(&table->lock);
}

static int alloc_comp_eqs(struct xsc_core_device *dev)
{
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	char name[XSC_MAX_IRQ_NAME];
	struct xsc_eq *eq;
	int ncomp_vec;
	int nent;
	int err;
	int i;

	INIT_LIST_HEAD(&table->comp_eqs_list);
	ncomp_vec = table->num_comp_vectors;
	nent = XSC_COMP_EQ_SIZE;

	for (i = 0; i < ncomp_vec; i++) {
		eq = kzalloc(sizeof(*eq), GFP_KERNEL);
		if (!eq) {
			err = -ENOMEM;
			goto clean;
		}

		snprintf(name, XSC_MAX_IRQ_NAME, "xsc_comp%d", i);
		err = xsc_create_map_eq(dev, eq,
					i + table->eq_vec_comp_base, nent, name);
		if (err) {
			kfree(eq);
			goto clean;
		}

		eq->index = i;
		spin_lock(&table->lock);
		list_add_tail(&eq->list, &table->comp_eqs_list);
		spin_unlock(&table->lock);
	}

	return 0;

clean:
	free_comp_eqs(dev);
	return err;
}

static irqreturn_t xsc_cmd_handler(int irq, void *arg)
{
	struct xsc_core_device *dev = (struct xsc_core_device *)arg;
	int err;

	disable_irq_nosync(dev->cmd.irqn);
	err = xsc_cmd_err_handler(dev);
	if (!err)
		xsc_cmd_resp_handler(dev);
	enable_irq(dev->cmd.irqn);

	return IRQ_HANDLED;
}

static int xsc_request_irq_for_cmdq(struct xsc_core_device *dev, u8 vecidx)
{
	struct xsc_dev_resource *dev_res = dev->dev_res;

	xsc_set_cmdq_msix_vector(dev, dev->msix_vec_base + vecidx);

	snprintf(dev_res->irq_info[vecidx].name, XSC_MAX_IRQ_NAME, "%s@pci:%s",
		 "xsc_cmd", pci_name(dev->pdev));
	dev->cmd.irqn = pci_irq_vector(dev->pdev, vecidx);
	return request_irq(dev->cmd.irqn, xsc_cmd_handler, 0,
		dev_res->irq_info[vecidx].name, dev);
}

static void xsc_free_irq_for_cmdq(struct xsc_core_device *dev)
{
	xsc_free_irq(dev, XSC_VEC_CMD);
}

static void xsc_change_to_share_mode(struct xsc_core_device *dev)
{
	write_lock(&dev->board_info->mr_sync_lock);
	if (dev->board_info->resource_access_mode == EXCLUSIVE_MODE) {
		xsc_sync_mr_to_fw(dev);
		dev->board_info->resource_access_mode = SHARE_MODE;
		xsc_destroy_res(dev);
	}
	write_unlock(&dev->board_info->mr_sync_lock);
}

static void xsc_change_to_exclusive_mode(struct xsc_core_device *dev)
{
	write_lock(&dev->board_info->mr_sync_lock);
	if (dev->board_info->resource_access_mode == SHARE_MODE) {
		xsc_create_res(dev);
		xsc_sync_mr_from_fw(dev);
		dev->board_info->resource_access_mode = EXCLUSIVE_MODE;
	}
	write_unlock(&dev->board_info->mr_sync_lock);
}

static void xsc_event_work(struct work_struct *work)
{
	int err;
	struct xsc_event_query_type_mbox_in in;
	struct xsc_event_query_type_mbox_out out;
	struct xsc_core_device *dev = container_of(work, struct xsc_core_device, event_work);
	u8 event;

	/*query cmd_type cmd*/
	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_EVENT_TYPE);

	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(dev, "failed to query event type, err=%d, stats=%d\n",
			     err, out.hdr.status);
		return;
	}

	event = out.ctx.resp_cmd_type;
	while (event) {
		if (event & XSC_CMD_EVENT_RESP_CHANGE_LINK) {
			if (dev->link_event_handler)
				dev->link_event_handler(dev);
			xsc_core_dbg(dev, "event cmdtype=%04x\n", out.ctx.resp_cmd_type);
			event &= ~XSC_CMD_EVENT_RESP_CHANGE_LINK;
		} else if (event & XSC_CMD_EVENT_RESP_TEMP_WARN) {
			xsc_core_warn(dev, "[Minor]nic chip temperature high warning\n");
			event &= ~XSC_CMD_EVENT_RESP_TEMP_WARN;
		} else if (event & XSC_CMD_EVENT_RESP_OVER_TEMP_PROTECTION) {
			xsc_core_warn(dev, "[Critical]nic chip was over-temperature\n");
			event &= ~XSC_CMD_EVENT_RESP_OVER_TEMP_PROTECTION;
		} else if (event & XSC_CMD_EVENT_RECV_TUNNEL_CMD_REQ) {
			xsc_tunnel_cmd_recv_req(dev);
			event &= ~XSC_CMD_EVENT_RECV_TUNNEL_CMD_REQ;
		} else if (event & XSC_CMD_EVENT_RECV_TUNNEL_CMD_RSP) {
			xsc_tunnel_cmd_recv_resp(dev);
			event &= ~XSC_CMD_EVENT_RECV_TUNNEL_CMD_RSP;
		} else if (event & XSC_CMD_EVENT_CHANGE_TO_SHARE) {
			xsc_change_to_share_mode(dev);
			event &= ~XSC_CMD_EVENT_CHANGE_TO_SHARE;
		} else if (event & XSC_CMD_EVENT_CHANGE_TO_EXCLUSIVE) {
			xsc_change_to_exclusive_mode(dev);
			event &= ~XSC_CMD_EVENT_CHANGE_TO_EXCLUSIVE;
		} else {
			xsc_core_info(dev, "unknown event cmdtype=%04x\n", out.ctx.resp_cmd_type);
			event = 0;
		}
	}
}

static irqreturn_t xsc_event_handler(int irq, void *arg)
{
	struct xsc_core_device *dev = (struct xsc_core_device *)arg;

	xsc_core_dbg(dev, "cmd event hint irq: %d\n", irq);

	schedule_work(&dev->event_work);

	return IRQ_HANDLED;
}

static int xsc_request_irq_for_event(struct xsc_core_device *dev)
{
	struct xsc_dev_resource *dev_res = dev->dev_res;

	snprintf(dev_res->irq_info[XSC_VEC_CMD_EVENT].name, XSC_MAX_IRQ_NAME, "%s@pci:%s",
		 "xsc_eth_event", pci_name(dev->pdev));
	return request_irq(pci_irq_vector(dev->pdev, XSC_VEC_CMD_EVENT), xsc_event_handler, 0,
			dev_res->irq_info[XSC_VEC_CMD_EVENT].name, dev);
}

static void xsc_free_irq_for_event(struct xsc_core_device *dev)
{
	xsc_free_irq(dev, XSC_VEC_CMD_EVENT);
}

static int xsc_cmd_enable_msix(struct xsc_core_device *xdev)
{
	struct xsc_msix_table_info_mbox_in in;
	struct xsc_msix_table_info_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ENABLE_MSIX);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		xsc_core_err(xdev, "xsc_cmd_exec enable msix failed %d\n", err);
		return err;
	}

	return 0;
}

int xsc_irq_eq_create(struct xsc_core_device *dev)
{
	int err;

	if (dev->caps.msix_enable == 0)
		return 0;

	err = xsc_alloc_irq_vectors(dev);
	if (err) {
		xsc_core_err(dev, "enable msix failed, err=%d\n", err);
		goto err_alloc_irq;
	}

	err = xsc_start_eqs(dev);
	if (err) {
		xsc_core_err(dev, "failed to start EQs, err=%d\n", err);
		goto err_start_eqs;
	}

	err = alloc_comp_eqs(dev);
	if (err) {
		xsc_core_err(dev, "failed to alloc comp EQs, err=%d\n", err);
		goto err_alloc_comp_eqs;
	}

	err = xsc_request_irq_for_cmdq(dev, XSC_VEC_CMD);
	if (err) {
		xsc_core_err(dev, "failed to request irq for cmdq, err=%d\n", err);
		goto err_request_cmd_irq;
	}

	err = xsc_request_irq_for_event(dev);
	if (err) {
		xsc_core_err(dev, "failed to request irq for event, err=%d\n", err);
		goto err_request_event_irq;
	}
	INIT_WORK(&dev->event_work, xsc_event_work);

	if (dev->caps.msix_enable && xsc_core_is_pf(dev)) {
		err = xsc_dma_read_msix_init(dev);
		if (err) {
			xsc_core_err(dev, "dma read msix init failed %d.\n", err);
			goto err_dma_read_msix;
		}
	}

	err = set_comp_irq_affinity_hints(dev);
	if (err) {
		xsc_core_err(dev, "failed to alloc affinity hint cpumask, err=%d\n", err);
		goto err_set_affinity;
	}

	xsc_cmd_use_events(dev);
	err = xsc_cmd_enable_msix(dev);
	if (err) {
		xsc_core_err(dev, "xsc_cmd_enable_msix failed %d.\n", err);
		xsc_cmd_use_polling(dev);
		goto err_set_affinity;
	}
	return 0;

err_set_affinity:
	xsc_dma_read_msix_fini(dev);
err_dma_read_msix:
	xsc_free_irq_for_event(dev);
err_request_event_irq:
	xsc_free_irq_for_cmdq(dev);
err_request_cmd_irq:
	free_comp_eqs(dev);
err_alloc_comp_eqs:
	xsc_stop_eqs(dev);
err_start_eqs:
	xsc_free_irq_vectors(dev);
err_alloc_irq:
	return err;
}

int xsc_irq_eq_destroy(struct xsc_core_device *dev)
{
	if (dev->caps.msix_enable == 0)
		return 0;

	xsc_stop_eqs(dev);
	clear_comp_irq_affinity_hints(dev);
	free_comp_eqs(dev);

	xsc_dma_read_msix_fini(dev);
	xsc_free_irq_for_event(dev);
	xsc_free_irq_for_cmdq(dev);
	xsc_free_irq_vectors(dev);

	return 0;
}

