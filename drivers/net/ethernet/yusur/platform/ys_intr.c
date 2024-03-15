// SPDX-License-Identifier: GPL-2.0

#include "ys_intr.h"
#include "ys_ndev.h"
#include "ys_pdev.h"

#include "ys_debug.h"

static int ys_get_nic_max_required_vectors(struct ys_pdev_priv *pdev_priv)
{
	const struct ys_pdev_hw *nic_type = pdev_priv->nic_type;
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	int ret = 0;

	/* If the NIC supports MSIX, the maximum MSIX IRQ count should
	 * be checked. If the NIC supports MSI, the maximum MSI IRQ
	 * count should be checked. If both MSIX and MSI are disabled,
	 * an error should be reported.
	 */
	if (nic_type->irq_flag | PCI_IRQ_MSIX)
		ret = pci_msix_vec_count(pdev_priv->pdev);

	if (ret <= 0 && (nic_type->irq_flag | PCI_IRQ_MSI))
		ret = pci_msi_vec_count(pdev_priv->pdev);

	if (nic_type->irq_sum > 0)
		ret = min(ret, nic_type->irq_sum);

	if (ret > 0)
		irq_table->max = ret;

	return ret;
}

static int ys_alloc_irq_vectors(struct ys_pdev_priv *pdev_priv)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	int ret;

	ret = ys_get_nic_max_required_vectors(pdev_priv);
	if (ret <= 0) {
		ys_dev_err("Get MSI or MSI-X max irq count error: %d", ret);
		return ret;
	}

	ret = pci_alloc_irq_vectors(pdev_priv->pdev, 1, irq_table->max,
				    pdev_priv->nic_type->irq_flag);
	if (ret <= 0) {
		ys_dev_err("Failed to allocate irqs");
		irq_table->max = 0;
		return ret;
	} else if (ret < irq_table->max) {
		irq_table->max = ret;
	}

	return ret;
}

static int ys_free_irq(struct ys_pdev_priv *pdev_priv, int index)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;

	if (index >= irq_table->max)
		return -EINVAL;

	if (IS_ERR_OR_NULL(irq_table->irqs)) {
		ys_dev_err("Missing irq table irqs");
		return -EINVAL;
	}

	mutex_lock(&irq_table->lock);

	irq = &irq_table->irqs[index];
	if (irq->state == YS_IRQ_STATE_UNREGISTERED) {
		mutex_unlock(&irq_table->lock);
		return 0;
	}

	if (irq->state == YS_IRQ_STATE_REGISTERED)
		pci_free_irq(pdev_priv->pdev, irq->index, irq);

	ys_debug("Free irq %d vector %d with name %s", index,
		 irq->irqn, pdev_priv->nic_type->func_name);

	irq->state = YS_IRQ_STATE_UNREGISTERED;
	memset(&irq->sub, 0, sizeof(struct ys_irq_sub));
	irq_table->used--;

	mutex_unlock(&irq_table->lock);

	return 0;
}

static int ys_request_irq(struct ys_pdev_priv *pdev_priv, int index,
			  struct ys_irq_sub *sub)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;
	int ret;

	if (index >= irq_table->max)
		return -EINVAL;

	if (IS_ERR_OR_NULL(sub))
		return -EINVAL;

	if (IS_ERR_OR_NULL(irq_table->irqs)) {
		ys_dev_err("Missing irq table irqs");
		return -EINVAL;
	}

	if (sub->irq_type < YS_IRQ_TYPE_QUEUE &&
	    sub->irq_type > YS_IRQ_TYPE_HW_PRIVATE) {
		ys_dev_err("Invalid sub irq type: %d", sub->irq_type);
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(sub->handler)) {
		ys_dev_err("Missing irq handler");
		return -EINVAL;
	}

	mutex_lock(&irq_table->lock);

	irq = &irq_table->irqs[index];
	if (irq->state != YS_IRQ_STATE_UNREGISTERED) {
		mutex_unlock(&irq_table->lock);
		ys_dev_err("Irq %d(%d) has already been registered",
			   index, irq->state);
		return -EINVAL;
	}

	irq->sub = *sub;
	if (irq->sub.bh_type == YS_IRQ_BH_WORK) {
		if (IS_ERR_OR_NULL(irq->sub.bh.work_handler)) {
			memset(&irq->sub, 0, sizeof(struct ys_irq_sub));
			mutex_unlock(&irq_table->lock);
			ys_dev_err("Irq %d(%d) missing work_handler",
				   index, irq->sub.bh_type);
			return -EINVAL;
		}
		INIT_WORK(&irq->sub.bh.work, irq->sub.bh.work_handler);
	}

	if (irq->sub.devname)
		ret = pci_request_irq(pdev_priv->pdev,
				      irq->index,
				      irq->sub.handler,
				      irq->sub.bh.thread_fn,
				      irq, irq->sub.devname);
	else
		ret = pci_request_irq(pdev_priv->pdev,
				      irq->index,
				      irq->sub.handler,
				      irq->sub.bh.thread_fn,
				      irq, "%s-%d-bdf:%d%d%d",
				      pdev_priv->nic_type->func_name, index,
				      pdev_priv->pdev->bus->number,
				      PCI_SLOT(pdev_priv->pdev->devfn),
				      PCI_FUNC(pdev_priv->pdev->devfn));

	if (ret < 0) {
		memset(&irq->sub, 0, sizeof(struct ys_irq_sub));
		mutex_unlock(&irq_table->lock);
		ys_dev_err("Failed to request irq index %d virq %d", index,
			   irq->irqn);
		return ret;
	}

	irq->state = YS_IRQ_STATE_REGISTERED;
	irq_table->used++;

	mutex_unlock(&irq_table->lock);

	ys_debug("Request irq %d vector %d", index, irq->irqn);

	return 0;
}

static int ys_register_fixed_irq(struct pci_dev *pdev, int index,
				 struct ys_irq_sub *sub)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	return ys_request_irq(pdev_priv, index, sub);
}

static int ys_register_any_irq(struct pci_dev *pdev, int *index,
			       struct ys_irq_sub *sub)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;
	int idle = -1;
	int ret;
	int i;

	for (i = 0; i < irq_table->max; i++) {
		irq = &irq_table->irqs[i];
		if (irq->state == YS_IRQ_STATE_UNREGISTERED) {
			idle = i;
			break;
		}
	}

	if (idle < 0)
		return -EINVAL;

	ret = ys_request_irq(pdev_priv, idle, sub);
	if (ret == 0) {
		*index = idle;
		ret = idle;
	}

	return ret;
}

static int ys_unregister_fixed_irq(struct pci_dev *pdev, int index)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	return ys_free_irq(pdev_priv, index);
}

static int ys_irqs_change_notify(struct notifier_block *nb, unsigned long mode,
				 void *data)
{
	struct ys_irq_nb *irq_nb = (struct ys_irq_nb *)data;
	int ret;

	switch (mode) {
	case YS_IRQ_NB_REGISTER_FIXED:
		ret = ys_register_fixed_irq(irq_nb->pdev, irq_nb->index,
					    &irq_nb->sub);
		break;
	case YS_IRQ_NB_REGISTER_ANY:
		ret = ys_register_any_irq(irq_nb->pdev, &irq_nb->index,
					  &irq_nb->sub);
		break;
	case YS_IRQ_NB_UNREGISTER:
		ret = ys_unregister_fixed_irq(irq_nb->pdev, irq_nb->index);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static struct notifier_block irqs_change_nb = {
	.notifier_call = ys_irqs_change_notify,
};

int ys_irq_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;
	int ret;
	int i;

	mutex_init(&irq_table->lock);
	BLOCKING_INIT_NOTIFIER_HEAD(&irq_table->nh);

	ret = ys_alloc_irq_vectors(pdev_priv);
	if (ret <= 0) {
		ys_dev_err("Alloc irq vectors error: %d", ret);
		goto irq_fail;
	}

	ys_dev_info("Alloc irq vectors count: %d", irq_table->max);

	irq_table->irqs = kcalloc(irq_table->max, sizeof(*irq), GFP_KERNEL);
	if (!irq_table->irqs) {
		ret = -ENOMEM;
		ys_dev_err("Alloc irqs error");
		goto irq_fail;
	}

	for (i = 0; i < irq_table->max; i++) {
		irq = &irq_table->irqs[i];
		irq->state = YS_IRQ_STATE_UNREGISTERED;
		irq->index = i;
		irq->irqn = pci_irq_vector(pdev_priv->pdev, i);
		irq->pdev = pdev_priv->pdev;
	}

	ret = blocking_notifier_chain_register(&irq_table->nh, &irqs_change_nb);
	if (ret < 0)
		goto irq_fail;

	ys_dev_info("ys irq init success!");
	return 0;
irq_fail:
	return ret;
}

void ys_irq_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	int i;

	if (!IS_ERR_OR_NULL(irq_table->irqs)) {
		blocking_notifier_chain_unregister(&irq_table->nh,
						   &irqs_change_nb);
		for (i = 0; i < irq_table->max; i++)
			ys_free_irq(pdev_priv, i);
		kfree(irq_table->irqs);
		pdev_priv->irq_table.irqs = NULL;
	}

	if (irq_table->max > 0) {
		pci_free_irq_vectors(pdev);
		irq_table->max = 0;
		irq_table->used = 0;
	}

	mutex_destroy(&irq_table->lock);
}
