// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/irqdomain.h>

#include <asm/irq_impl.h>

static struct irq_domain *msi_default_domain;
static DEFINE_RAW_SPINLOCK(vector_lock);
DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
	[0 ... PERCPU_MSI_IRQS - 1] = 0,
};

struct sw64_msi_chip_data {
	spinlock_t cdata_lock;
	unsigned long msi_config;
	unsigned long rc_node;
	unsigned long rc_index;
	unsigned int msi_config_index;
	unsigned int dst_coreid;
	unsigned int vector;
	unsigned int prev_coreid;
	unsigned int prev_vector;
	bool move_in_progress;
};

static struct sw64_msi_chip_data *alloc_sw_msi_chip_data(struct irq_data *irq_data)
{
	struct sw64_msi_chip_data *data;
	int node;

	node = irq_data_get_node(irq_data);
	data = kzalloc_node(sizeof(*data), GFP_KERNEL, node);
	if (!data)
		return NULL;
	spin_lock_init(&data->cdata_lock);
	return data;
}

static void irq_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct sw64_msi_chip_data *chip_data;

	chip_data = irq_data_get_irq_chip_data(data->parent_data);
	msg->address_hi = MSI_ADDR_BASE_HI;
	msg->address_lo = MSI_ADDR_BASE_LO;
	msg->data = chip_data->msi_config_index;
}

static bool find_free_core_vector(const struct cpumask *search_mask, int *found_coreid, int *found_vector)
{
	int vector, coreid;
	bool found = false, find_once_global = false;

	coreid = cpumask_first(search_mask);
try_again:
	for (vector = 0; vector < 256; vector++) {
		while (per_cpu(vector_irq, coreid)[vector]) {
			coreid = cpumask_next(coreid, search_mask);
			if (coreid >= nr_cpu_ids) {
				if (vector == 255) {
					if (find_once_global) {
						printk("No global free vector\n");
						return found;
					}
					printk("No local free vector\n");
					search_mask = cpu_online_mask;
					coreid = cpumask_first(search_mask);
					find_once_global = true;
					goto try_again;
				}
				coreid = cpumask_first(search_mask);
				break;
			}
		}
		if (!per_cpu(vector_irq, coreid)[vector])
			break;
	}

	found = true;
	*found_coreid = coreid;
	*found_vector = vector;
	return found;
}

static unsigned long set_piu_msi_config(struct pci_controller *hose, int found_coreid,
		int msiconf_index, int found_vector)
{
	unsigned int reg;
	unsigned long msi_config;
	int phy_coreid;

	msi_config = (1UL << 62) | ((unsigned long)found_vector << 10);
	phy_coreid = cpu_to_rcid(found_coreid);
	msi_config |= ((phy_coreid >> 5) << 6) | (phy_coreid & 0x1f);
	reg = MSICONFIG0 + (unsigned long)(msiconf_index << 7);
	write_piu_ior0(hose->node, hose->index, reg, msi_config);
	msi_config = read_piu_ior0(hose->node, hose->index, reg);
	set_bit(msiconf_index, hose->piu_msiconfig);

	return msi_config;
}

static int sw64_set_affinity(struct irq_data *d, const struct cpumask *cpumask, bool force)
{
	struct sw64_msi_chip_data *cdata;
	struct pci_controller *hose;
	struct irq_data *irqd;
	struct msi_desc *entry;
	struct cpumask searchmask;
	unsigned long flags, msi_config;
	int found_vector, found_coreid;

	/* Is this valid ? */
	if (cpumask_any_and(cpumask, cpu_online_mask) >= nr_cpu_ids)
		return -EINVAL;

	irqd = irq_domain_get_irq_data(msi_default_domain->parent, d->irq);
	/* Don't do anything if the interrupt isn't started */
	if (!irqd_is_started(irqd))
		return IRQ_SET_MASK_OK;

	cdata = irqd->chip_data;
	if (!cdata)
		return -ENOMEM;

	/* If existing target coreid is already in the new mask, and is online then do nothing.*/
	if (cpu_online(cdata->dst_coreid) && cpumask_test_cpu(cdata->dst_coreid, cpumask))
		return IRQ_SET_MASK_OK;

	raw_spin_lock_irqsave(&vector_lock, flags);

	cpumask_and(&searchmask, cpumask, cpu_online_mask);
	if (!find_free_core_vector(&searchmask, &found_coreid, &found_vector)) {
		raw_spin_unlock_irqrestore(&vector_lock, flags);
		return -ENOSPC;
	}

	/* update new setting */
	entry = irq_get_msi_desc(irqd->irq);
	hose = (struct pci_controller *)msi_desc_to_pci_sysdata(entry);
	spin_lock(&cdata->cdata_lock);
	per_cpu(vector_irq, found_coreid)[found_vector] = irqd->irq;
	msi_config = set_piu_msi_config(hose, found_coreid, cdata->msi_config_index, found_vector);
	cdata->prev_vector = cdata->vector;
	cdata->prev_coreid = cdata->dst_coreid;
	cdata->dst_coreid = found_coreid;
	cdata->vector = found_vector;
	cdata->msi_config = msi_config;
	cdata->move_in_progress = true;
	spin_unlock(&cdata->cdata_lock);
	cpumask_copy(irq_data_get_affinity_mask(irqd), &searchmask);

	raw_spin_unlock_irqrestore(&vector_lock, flags);

	return 0;
}

static void chip_irq_ack(struct irq_data *data)
{
}

static struct irq_chip pci_msi_controller = {
	.name                   = "PCI-MSI",
	.irq_unmask             = pci_msi_unmask_irq,
	.irq_mask               = pci_msi_mask_irq,
	.irq_ack                = chip_irq_ack,
	.irq_compose_msi_msg    = irq_msi_compose_msg,
	.flags                  = IRQCHIP_SKIP_SET_WAKE,
	.irq_set_affinity	= sw64_set_affinity,
};

static int __assign_irq_vector(int virq, unsigned int nr_irqs,
		struct irq_domain *domain, struct pci_controller *hose)
{
	struct irq_data *irq_data;
	const struct cpumask *mask;
	struct cpumask searchmask;
	struct sw64_msi_chip_data *cdata;
	int msiconf_index, coreid, node;
	int i, found_vector, found_coreid;
	unsigned long msi_config;
	int start_index;

	if (unlikely((nr_irqs > 1) && (!is_power_of_2(nr_irqs))))
		nr_irqs = __roundup_pow_of_two(nr_irqs);

	msiconf_index = bitmap_find_next_zero_area(hose->piu_msiconfig, 256, 0,
			nr_irqs, nr_irqs - 1);

	if (msiconf_index >= 256) {
		printk("No free msi on PIU!\n");
		return -ENOSPC;
	}

	start_index = msiconf_index;
	irq_data = irq_domain_get_irq_data(domain, virq);
	BUG_ON(!irq_data);
	irq_data->chip = &pci_msi_controller;

	if (irqd_affinity_is_managed(irq_data)) {
		mask = irq_data_get_affinity_mask(irq_data);
		cpumask_and(&searchmask, mask, cpu_online_mask);
	} else {
		node = irq_data_get_node(irq_data);
		cpumask_copy(&searchmask, cpumask_of_node(node));
	}

	coreid = cpumask_first(&searchmask);
	if (coreid >= nr_cpu_ids)
		cpumask_copy(&searchmask, cpu_online_mask);

	for (i = 0; i < nr_irqs; i++) {
		if (!find_free_core_vector(&searchmask, &found_coreid, &found_vector))
			return -ENOSPC;

		per_cpu(vector_irq, found_coreid)[found_vector] = virq + i;

		if (i) {
			irq_data = irq_domain_get_irq_data(domain, virq + i);
			irq_data->chip = &pci_msi_controller;
		}

		cdata = alloc_sw_msi_chip_data(irq_data);
		if (!cdata) {
			printk("error alloc irq chip data\n");
			return -ENOMEM;
		}

		irq_data->chip_data = cdata;
		msiconf_index = start_index + i;
		msi_config = set_piu_msi_config(hose, found_coreid, msiconf_index, found_vector);

		cdata->dst_coreid = found_coreid;
		cdata->vector = found_vector;
		cdata->rc_index = hose->index;
		cdata->rc_node = hose->node;
		cdata->msi_config = msi_config;
		cdata->msi_config_index = msiconf_index;
		cdata->prev_coreid = found_coreid;
		cdata->prev_vector = found_vector;
		cdata->move_in_progress = false;
	}
	return 0;
}

static int assign_irq_vector(int irq, unsigned int nr_irqs,
		struct irq_domain *domain, struct pci_controller *hose)
{
	int err;
	unsigned long flags;

	raw_spin_lock_irqsave(&vector_lock, flags);
	err = __assign_irq_vector(irq, nr_irqs, domain, hose);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
	return err;
}

static void sw64_vector_free_irqs(struct irq_domain *domain,
		unsigned int virq, unsigned int nr_irqs)
{
	int i;
	struct irq_data *irq_data;
	unsigned long flags;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_domain_get_irq_data(domain, virq + i);
		if (irq_data && irq_data->chip_data) {
			struct sw64_msi_chip_data *cdata;
			struct msi_desc *entry;
			struct pci_controller *hose;

			raw_spin_lock_irqsave(&vector_lock, flags);
			cdata = irq_data->chip_data;
			entry = irq_get_msi_desc(virq + i);
			if (entry) {
				hose = (struct pci_controller *)msi_desc_to_pci_sysdata(entry);
				clear_bit(cdata->msi_config_index, hose->piu_msiconfig);
			}
			irq_domain_reset_irq_data(irq_data);
			per_cpu(vector_irq, cdata->dst_coreid)[cdata->vector] = 0;
			kfree(cdata);
			raw_spin_unlock_irqrestore(&vector_lock, flags);
		}
	}
}

static void sw64_irq_free_descs(unsigned int virq, unsigned int nr_irqs)
{
	if (is_guest_or_emul())
		return irq_free_descs(virq, nr_irqs);

	return irq_domain_free_irqs(virq, nr_irqs);
}

void arch_teardown_msi_irqs(struct pci_dev *dev)
{
	struct msi_desc *desc;
	int i;

	for_each_pci_msi_entry(desc, dev) {
		if (desc->irq) {
			for (i = 0; i < desc->nvec_used; i++)
				sw64_irq_free_descs(desc->irq + i, 1);
			desc->irq = 0;
		}
	}
}

static int sw64_vector_alloc_irqs(struct irq_domain *domain, unsigned int virq,
		unsigned int nr_irqs, void *arg)
{
	int err;
	struct irq_alloc_info *info = arg;
	struct pci_controller *hose;

	if (arg == NULL)
		return -ENODEV;
	hose = info->msi_dev->sysdata;
	err = assign_irq_vector(virq, nr_irqs, domain, hose);
	if (err)
		goto error;
	return 0;
error:
	sw64_vector_free_irqs(domain, virq, nr_irqs);
	return err;
}

static int pci_msi_prepare(struct irq_domain *domain, struct device *dev,
		int nvec, msi_alloc_info_t *arg)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct msi_desc *desc = first_pci_msi_entry(pdev);

	memset(arg, 0, sizeof(*arg));
	arg->msi_dev = pdev;
	if (desc->msi_attrib.is_msix)
		arg->type = IRQ_ALLOC_TYPE_MSIX;
	else
		arg->type = IRQ_ALLOC_TYPE_MSI;
	return 0;
}

static struct msi_domain_ops pci_msi_domain_ops = {
	.msi_prepare    = pci_msi_prepare,
};

static struct msi_domain_info pci_msi_domain_info = {
	.flags          = MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
			  MSI_FLAG_MULTI_PCI_MSI | MSI_FLAG_PCI_MSIX,
	.ops            = &pci_msi_domain_ops,
	.chip           = &pci_msi_controller,
	.handler        = handle_edge_irq,
	.handler_name   = "edge",
};

static int sw64_irq_map(struct irq_domain *d, unsigned int virq, irq_hw_number_t hw)
{
	irq_set_chip_and_handler(virq, &sw64_irq_chip, handle_level_irq);
	irq_set_status_flags(virq, IRQ_LEVEL);
	return 0;
}

const struct irq_domain_ops sw64_msi_domain_ops = {
	.map    = sw64_irq_map,
	.alloc  = sw64_vector_alloc_irqs,
	.free   = sw64_vector_free_irqs,
};

int arch_setup_msi_irqs(struct pci_dev *pdev, int nvec, int type)
{
	struct irq_domain *domain;
	int err;

	if (is_guest_or_emul())
		return sw64_setup_vt_msi_irqs(pdev, nvec, type);

	domain = msi_default_domain;
	if (domain == NULL)
		return -ENOSYS;
	err = msi_domain_alloc_irqs(domain, &pdev->dev, nvec);
	return err;
}

void arch_init_msi_domain(struct irq_domain *parent)
{
	struct irq_domain *sw64_irq_domain;

	if (is_guest_or_emul())
		return;

	sw64_irq_domain = irq_domain_add_tree(NULL, &sw64_msi_domain_ops, NULL);
	BUG_ON(sw64_irq_domain == NULL);
	irq_set_default_host(sw64_irq_domain);
	msi_default_domain = pci_msi_create_irq_domain(NULL,
			&pci_msi_domain_info, sw64_irq_domain);
	if (!msi_default_domain)
		pr_warn("failed to initialize irqdomain for MSI/MSI-x.\n");
}

static void irq_move_complete(struct sw64_msi_chip_data *cdata, int coreid, int vector)
{
	if (likely(!cdata->move_in_progress))
		return;
	if (vector == cdata->vector && cdata->dst_coreid == coreid) {
		raw_spin_lock(&vector_lock);
		cdata->move_in_progress = 0;
		per_cpu(vector_irq, cdata->prev_coreid)[cdata->prev_vector] = 0;
		raw_spin_unlock(&vector_lock);
	}
}

void handle_pci_msi_interrupt(unsigned long type, unsigned long vector, unsigned long pci_msi1_addr)
{
	int i, msi_index = 0;
	int vector_index = 0, logical_cid;
	unsigned long value = 0;
	unsigned long int_pci_msi[3];
	unsigned long *ptr;
	struct irq_data *irq_data;
	struct sw64_msi_chip_data *cdata;

	if (is_guest_or_emul()) {
		handle_irq(vector);
		return;
	}

	ptr = (unsigned long *)pci_msi1_addr;
	int_pci_msi[0] = *ptr;
	int_pci_msi[1] = *(ptr + 1);
	int_pci_msi[2] = *(ptr + 2);

	logical_cid = smp_processor_id();

	for (i = 0; i < 4; i++) {
		vector_index = i * 64;
		while (vector != 0) {
			int irq = 0;
			int piu_index = 0;

			msi_index = find_next_bit(&vector, 64, msi_index);
			if (msi_index == 64) {
				msi_index = 0;
				continue;
			}

			irq = per_cpu(vector_irq, logical_cid)[vector_index + msi_index];
			irq_data = irq_domain_get_irq_data(msi_default_domain->parent, irq);
			cdata = irq_data_get_irq_chip_data(irq_data);
			spin_lock(&cdata->cdata_lock);
			irq_move_complete(cdata, logical_cid, vector_index + msi_index);
			piu_index = cdata->msi_config_index;
			value = cdata->msi_config | (1UL << 63);
			write_piu_ior0(cdata->rc_node, cdata->rc_index, MSICONFIG0 + (piu_index << 7), value);
			spin_unlock(&cdata->cdata_lock);
			handle_irq(irq);

			vector = vector & (~(1UL << msi_index));
		}

		vector = int_pci_msi[i % 3];
	}
}

MODULE_LICENSE("GPL v2");
