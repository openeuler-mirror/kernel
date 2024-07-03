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

struct xsc_msix_resource {
	u16 msix_max_num;
	u16 msix_vec_base;
	u16 msix_vec_end;
	unsigned long *msix_vec_tbl;
	atomic_t refcount;
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
	u32 value = 0;
	int vecid = 0;

	snprintf(dev_res->irq_info[XSC_DMA_READ_DONE_VEC].name, XSC_MAX_IRQ_NAME, "%s@pci:%s",
		 name, pci_name(xdev->pdev));
	irqn = pci_irq_vector(xdev->pdev, XSC_DMA_READ_DONE_VEC);
	err = request_irq(irqn, xsc_dma_read_msix_handler, 0,
			  dev_res->irq_info[XSC_DMA_READ_DONE_VEC].name, (void *)xdev);

	vecid = (xdev->msix_vec_base + XSC_DMA_READ_DONE_VEC);
	value = ((1 << 12) | (vecid & 0xfff));
	REG_WR32(xdev, HIF_IRQ_TBL2IRQ_TBL_RD_DONE_INT_MSIX_REG_ADDR, value);

	return err;
}

static void xsc_dma_read_msix_fini(struct xsc_core_device *xdev)
{
	if (xdev->caps.msix_enable && xsc_core_is_pf(xdev))
		free_irq(pci_irq_vector(xdev->pdev, XSC_DMA_READ_DONE_VEC), xdev);
}

#if defined(MSIX_SUPPORT) && !defined(XSC_MSIX_BAR_EMUL)
static void xsc_write_msix_ctrl_tbl(struct xsc_core_device *xdev, u32 func_idx, u32 func_mask)
{
	struct xsc_core_device *pf_xdev;

	if (!xsc_core_is_pf(xdev))
		pf_xdev = pci_get_drvdata(xdev->pdev->physfn);
	else
		pf_xdev = xdev;

	REG_WR32(pf_xdev, HIF_IRQ_CONTROL_TBL_MEM_ADDR + func_idx * 4, func_mask);
}

static void xsc_msix_ctrl_tbl_func_fini(struct xsc_core_device *xdev, u32 func_id)
{
	return xsc_write_msix_ctrl_tbl(xdev, func_id, 1);
}

static void xsc_msix_ctrl_tbl_func_init(struct xsc_core_device *xdev, u32 func_id)
{
	xsc_write_msix_ctrl_tbl(xdev, func_id, 0);
}

static int xsc_msix_mask_tbl_bit_write(struct xsc_core_device *xdev,
				       u32 vector_id,
				       u32 mask_or_unmask)
{
	u32 v;
	struct xsc_core_device *pf_xdev;

	if (!xsc_core_is_pf(xdev))
		pf_xdev = pci_get_drvdata(xdev->pdev->physfn);
	else
		pf_xdev = xdev;

	if (vector_id >= BIT(xdev->caps.log_max_msix))
		return -1;
	if (!(mask_or_unmask == 0 || mask_or_unmask == 1))
		return -1;

	v = (((mask_or_unmask == 1) ? 0x3 : 0x2) << 12) | vector_id;

	REG_WR32(pf_xdev, HIF_IRQ_INT_DB_REG_ADDR, v);

	return 0;
}

static void xsc_msix_check_vtr_tbl_idle(struct xsc_core_device *xdev, u32 *idle)
{
	u32 is_busy;
	struct xsc_core_device *pf_xdev;

	if (!xsc_core_is_pf(xdev))
		pf_xdev = pci_get_drvdata(xdev->pdev->physfn);
	else
		pf_xdev = xdev;

	*idle = 0;
	do {
		is_busy = REG_RD32(pf_xdev, HIF_IRQ_CFG_VECTOR_TABLE_BUSY_REG_ADDR);
		if (is_busy == 0)
			break;

		usleep_range(2000, 3000);
	} while (is_busy);

	*idle = 1;
}

int xsc_msix_vector_tbl_write(struct xsc_core_device *xdev, u32 vector_id,
			      u32 laddr, u32 uaddr, u32 data,
			      u32 func_id, u32 vector_en)
{
	int ret = 0;
	u32 idle = 0;
	u32 tmp;
	struct xsc_core_device *pf_xdev;

	if (!xsc_core_is_pf(xdev))
		pf_xdev = pci_get_drvdata(xdev->pdev->physfn);
	else
		pf_xdev = xdev;

	if (vector_id >= BIT(xdev->caps.log_max_msix) ||
	    !check_caps_funcid_valid(&xdev->caps) ||
	    func_id >= get_xsc_funcid_end(&xdev->caps) ||
	    vector_en > 1) {
		xsc_core_err(xdev, "%s: invalid input params: func_id=%d\n",
			     __func__, func_id);
		return -EINVAL;
	}

	REG_WR32(pf_xdev, HIF_IRQ_CFG_VECTOR_TABLE_ADDR_REG_ADDR, vector_id);
	xsc_msix_check_vtr_tbl_idle(pf_xdev, &idle);
	if (idle) {
		REG_WR32(pf_xdev, HIF_IRQ_CFG_VECTOR_TABLE_CMD_REG_ADDR, 0);
		REG_WR32(pf_xdev, HIF_IRQ_CFG_VECTOR_TABLE_MSG_LADDR_REG_ADDR, laddr);
		REG_WR32(pf_xdev, HIF_IRQ_CFG_VECTOR_TABLE_MSG_UADDR_REG_ADDR, uaddr);
		REG_WR32(pf_xdev, HIF_IRQ_CFG_VECTOR_TABLE_MSG_DATA_REG_ADDR, data);

		tmp = ((vector_en & 0x1) << 11) | (func_id & 0x7FF);
		REG_WR32(pf_xdev, HIF_IRQ_CFG_VECTOR_TABLE_CTRL_REG_ADDR, tmp);
		REG_WR32(pf_xdev, HIF_IRQ_CFG_VECTOR_TABLE_START_REG_ADDR, 1);
	} else {
		xsc_core_err(xdev, "VTR tbl is busy.\n");
		ret = -1;
	}

	return ret;
}

int xsc_read_msix_tbl_info(struct xsc_core_device *xdev, u16 index, struct msi_msg *msg)
{
	struct xsc_msix_table_info_mbox_in in;
	struct xsc_msix_table_info_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_MSIX_TBL_INFO);
	in.index = cpu_to_be16(index);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		xsc_core_err(xdev, "xsc cmd ops get msix tbl failed %d\n", err);
		return err;
	}
	msg->address_lo = be32_to_cpu(out.addr_lo);
	msg->address_hi = be32_to_cpu(out.addr_hi);
	msg->data = be32_to_cpu(out.data);
	return 0;
}

static int xsc_msix_ctrl_tbl_init(struct xsc_core_device *xdev)
{
	if (!check_caps_funcid_valid(&xdev->caps) ||
	    xdev->glb_func_id >= get_xsc_funcid_end(&xdev->caps))
		return -1;

	xsc_msix_ctrl_tbl_func_init(xdev, xdev->glb_func_id);

	xsc_core_dbg(xdev, "glb_funcid=%d\n", xdev->glb_func_id);
	return 0;
}

static int xsc_msix_ctrl_tbl_fini(struct xsc_core_device *xdev)
{
	if (!check_caps_funcid_valid(&xdev->caps) ||
	    xdev->glb_func_id >= get_xsc_funcid_end(&xdev->caps))
		return -1;

	xsc_msix_ctrl_tbl_func_fini(xdev, xdev->glb_func_id);

	xsc_core_dbg(xdev, "glb_funcid=%d\n", xdev->glb_func_id);
	return 0;
}

static int xsc_msix_mask_tbl_ops(struct xsc_core_device *xdev, u32 value)
{
	int err;
	int i;
	int vec_offset;
	struct xsc_eq_table *table = &xdev->dev_res->eq_table;

	if (table->num_comp_vectors == 0)
		return -1;

	xsc_core_dbg(xdev, "num_comp_vectors=%d\n", table->num_comp_vectors);

	for (i = 0; i < table->num_comp_vectors + table->eq_vec_comp_base; i++) {
		vec_offset = xdev->msix_vec_base + i;
		err = xsc_msix_mask_tbl_bit_write(xdev, vec_offset, value);
		if (err != 0)
			return err;
	}

	return 0;
}

static int xsc_msix_mask_tbl_init(struct xsc_core_device *xdev)
{
	return xsc_msix_mask_tbl_ops(xdev, 0);
}

static int xsc_msix_mask_tbl_fini(struct xsc_core_device *xdev)
{
	return xsc_msix_mask_tbl_ops(xdev, 1);
}

static int xsc_msix_vector_tbl_ops(struct xsc_core_device *xdev, u32 vector_en)
{
	int err;
	int i;
	int vec_size;
	u16 index;
	struct pci_dev *pdev = xdev->pdev;
	struct msi_desc *entry;
	struct msi_msg *msgs;

	struct xsc_eq_table *table = &xdev->dev_res->eq_table;

	if (table->num_comp_vectors == 0)
		return -1;

	xsc_core_dbg(xdev, "num_comp_vectors=%d\n", table->num_comp_vectors);
	vec_size = table->num_comp_vectors + table->eq_vec_comp_base;
	msgs = kcalloc(vec_size, sizeof(struct msi_msg), GFP_KERNEL);
	err = 0;

	i = xdev->msix_vec_base;
	index = 0;
	for_each_pci_msi_entry(entry, pdev) {
		if (vector_en == 1) {
			err = xsc_read_msix_tbl_info(xdev, index, &msgs[index]);
			if (err) {
				xsc_core_err(xdev, "failed to get msix tbl %d\n", err);
				goto out;
			}
		}
		i++;
		index++;
	}

	i = xdev->msix_vec_base;
	index = 0;
	for_each_pci_msi_entry(entry, pdev) {
		err = xsc_msix_vector_tbl_write(xdev, i,
						msgs[index].address_lo,
						msgs[index].address_hi,
						msgs[index].data,
						xdev->glb_func_id,
						vector_en);
		i++;
		index++;
	}

out:
	kfree(msgs);
	return err;
}

static int xsc_msix_vector_tbl_init(struct xsc_core_device *xdev)
{
	return xsc_msix_vector_tbl_ops(xdev, 1);
}

static int xsc_msix_vector_tbl_fini(struct xsc_core_device *xdev)
{
	return xsc_msix_vector_tbl_ops(xdev, 0);
}

int xsc_msix_mask_set_vec(struct xsc_core_device *xdev, u32 vec, u32 value)
{
	int err = 0;

	int max_msix = 1 << xdev->caps.log_max_msix;

	if (vec >= max_msix) {
		xsc_core_err(xdev, "failed to set msix mask.vec=%d\n", vec);
		return -1;
	}

	err = xsc_msix_mask_tbl_bit_write(xdev, vec, value);

	return err;
}
#endif

static int xsc_msix_tbl_init(struct xsc_core_device *xdev)
{
#if defined(MSIX_SUPPORT) && !defined(XSC_MSIX_BAR_EMUL)
	int err;

	err = xsc_msix_vector_tbl_init(xdev);
	if (err) {
		xsc_core_err(xdev, "xsc_msix_vector_tbl_init failed: err=%d\n", err);
		return -1;
	}

	err = xsc_msix_ctrl_tbl_init(xdev);
	if (err) {
		xsc_core_err(xdev, "xsc_msix_ctrl_tbl_init failed: err=%d\n", err);
		return -1;
	}

	err = xsc_msix_mask_tbl_init(xdev);
	if (err) {
		xsc_core_err(xdev, "xsc_msix_mask_tbl_init failed: err=%d\n", err);
		return -1;
	}
#endif
	return 0;
}

static int xsc_msix_tbl_fini(struct xsc_core_device *xdev)
{
#if defined(MSIX_SUPPORT) && !defined(XSC_MSIX_BAR_EMUL)
	int err;

	err = xsc_msix_vector_tbl_fini(xdev);
	if (err) {
		xsc_core_err(xdev, "xsc_msix_vector_tbl_fini failed: err=%d\n", err);
		return -1;
	}

	err = xsc_msix_mask_tbl_fini(xdev);
	if (err) {
		xsc_core_err(xdev, "xsc_msix_mask_tbl_fini failed: err=%d\n", err);
		return -1;
	}

	err = xsc_msix_ctrl_tbl_fini(xdev);
	if (err) {
		xsc_core_err(xdev, "xsc_msix_ctrl_tbl_fini failed: err=%d\n", err);
		return -1;
	}
#endif
	return 0;
}

static struct xsc_eq *xsc_eq_get(struct xsc_core_device *dev, int i)
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
#ifdef XSC_MSIX_BAR_EMUL
	dev->msix_vec_base = dev->caps.msix_base;
#endif
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

#ifdef XSC_DEBUG
	xsc_core_dbg(dev, "cmdq hint irq: %d\n", irq);
#endif
	disable_irq_nosync(dev->cmd.irqn);
	err = xsc_cmd_err_handler(dev);
	if (!err)
		xsc_cmd_resp_handler(dev);
	enable_irq(dev->cmd.irqn);

	return IRQ_HANDLED;
}

int xsc_request_irq_for_cmdq(struct xsc_core_device *dev, u8 vecidx)
{
	struct xsc_dev_resource *dev_res = dev->dev_res;

	writel(dev->msix_vec_base + vecidx, REG_ADDR(dev, dev->cmd.reg.msix_vec_addr));

	snprintf(dev_res->irq_info[vecidx].name, XSC_MAX_IRQ_NAME, "%s@pci:%s",
		 "xsc_cmd", pci_name(dev->pdev));
	dev->cmd.irqn = pci_irq_vector(dev->pdev, vecidx);
	return request_irq(dev->cmd.irqn, xsc_cmd_handler, 0,
		dev_res->irq_info[vecidx].name, dev);
}

void xsc_free_irq_for_cmdq(struct xsc_core_device *dev)
{
	free_irq(dev->cmd.irqn, dev);
}

static irqreturn_t xsc_event_handler(int irq, void *arg)
{
	struct xsc_core_device *dev = (struct xsc_core_device *)arg;

	xsc_core_dbg(dev, "cmd event hint irq: %d\n", irq);

	if (!dev->eth_priv)
		return IRQ_NONE;

	if (!dev->event_handler)
		return IRQ_NONE;

	dev->event_handler(dev->eth_priv);

	return IRQ_HANDLED;
}

int xsc_request_irq_for_event(struct xsc_core_device *dev)
{
	struct xsc_dev_resource *dev_res = dev->dev_res;

	snprintf(dev_res->irq_info[XSC_VEC_CMD_EVENT].name, XSC_MAX_IRQ_NAME, "%s@pci:%s",
		 "xsc_eth_event", pci_name(dev->pdev));

	return request_irq(pci_irq_vector(dev->pdev, XSC_VEC_CMD_EVENT), xsc_event_handler, 0,
			dev_res->irq_info[XSC_VEC_CMD_EVENT].name, dev);
}

void xsc_free_irq_for_event(struct xsc_core_device *dev)
{
	free_irq(pci_irq_vector(dev->pdev, XSC_VEC_CMD_EVENT), dev);
}

#ifdef XSC_MSIX_BAR_EMUL
int xsc_cmd_enable_msix(struct xsc_core_device *xdev)
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
#endif

int xsc_irq_eq_create(struct xsc_core_device *dev)
{
	int err;
#if !defined XSC_MSIX_BAR_EMUL
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
#endif

	if (dev->caps.msix_enable == 0)
		return 0;

	err = xsc_alloc_irq_vectors(dev);
	if (err) {
		xsc_core_err(dev, "enable msix failed, err=%d\n", err);
		goto err_alloc_irq;
	}

#if !defined XSC_MSIX_BAR_EMUL
	/*MUST place afer xsc_alloc_irq_vectors, and MUST place before xsc_start_eqs*/
	err = xsc_alloc_continuous_msix_vec(dev, table->num_comp_vectors + table->eq_vec_comp_base);
	if (err) {
		xsc_core_err(dev, "alloc msix vec res failed, err=%d\n", err);
		goto err_alloc_msix_vec;
	}
#endif

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

	if (dev->caps.msix_enable && xsc_core_is_pf(dev)) {
		err = xsc_dma_read_msix_init(dev);
		if (err) {
			xsc_core_err(dev, "dma read msix init failed %d.\n", err);
			goto err_dma_read_msix;
		}
	}

	err = xsc_msix_tbl_init(dev);
	if (err) {
		xsc_core_err(dev, "failed to init msix tbl, err=%d\n", err);
		goto err_msix_tbl_init;
	}

	err = set_comp_irq_affinity_hints(dev);
	if (err) {
		xsc_core_err(dev, "failed to alloc affinity hint cpumask, err=%d\n", err);
		goto err_set_affinity;
	}

	xsc_cmd_use_events(dev);
#ifdef XSC_MSIX_BAR_EMUL
	err = xsc_cmd_enable_msix(dev);
	if (err) {
		xsc_core_err(dev, "xsc_cmd_enable_msix failed %d.\n", err);
		xsc_cmd_use_polling(dev);
		goto err_set_affinity;
	}
#endif
	return 0;

err_set_affinity:
	xsc_msix_tbl_fini(dev);
err_msix_tbl_init:
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
#if !defined XSC_MSIX_BAR_EMUL
	xsc_free_continuous_msix_vec(dev);
err_alloc_msix_vec:
#endif
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
	xsc_free_continuous_msix_vec(dev);
	xsc_free_irq_vectors(dev);
	xsc_msix_tbl_fini(dev);

	return 0;
}
