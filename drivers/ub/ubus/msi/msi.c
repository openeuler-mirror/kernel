// SPDX-License-Identifier: GPL-2.0+
/*
 * Only support for irqdomain.c.
 */

#include <linux/msi.h>
#include <ub/ubus/ubus.h>
#include <uapi/ub/ubus/ubus_regs.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>

unsigned int ub_irq_calc_affinity_vectors(unsigned int minvec,
					  unsigned int maxvec,
					  const struct irq_affinity *affd)
{
	return irq_calc_affinity_vectors(minvec, maxvec, affd);
}
EXPORT_SYMBOL_GPL(ub_irq_calc_affinity_vectors);

struct ub_device_id_manager {
	struct idr device_id_idr;
	spinlock_t lock;
};

static struct ub_device_id_manager ub_entity_idm = {
	.device_id_idr = IDR_INIT(ub_entity_idm.device_id_idr),
	.lock = __SPIN_LOCK_UNLOCKED(ub_entity_idm.lock),
};

int ub_interrupt_id_alloc(struct ub_entity *uent)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&ub_entity_idm.lock);
	id = idr_alloc(&ub_entity_idm.device_id_idr, uent,
		       uent->ubc->attr.int_id_start, uent->ubc->attr.int_id_end,
		       GFP_NOWAIT);
	spin_unlock(&ub_entity_idm.lock);
	idr_preload_end();

	if (id < 0)
		return id;
	uent->intr_device_id = id;

	return 0;
}

void ub_interrupt_id_free(struct ub_entity *uent)
{
	spin_lock(&ub_entity_idm.lock);
	idr_remove(&ub_entity_idm.device_id_idr, uent->intr_device_id);
	spin_unlock(&ub_entity_idm.lock);
}
EXPORT_SYMBOL_GPL(ub_interrupt_id_free);

struct ub_entity *msi_desc_to_ub_entity(struct msi_desc *desc)
{
	return to_ub_entity(desc->dev);
}

void __iomem *ub_vector_desc_addr(struct msi_desc *desc)
{
	return desc->ub_intr.vector_base + (desc->ub_intr.intr_attrib.entry_nr *
					    UB_INTR_VECTOR_ENTRY_SIZE);
}

static void __iomem *ub_addr_desc_base_addr(struct msi_desc *desc)
{
	return desc->ub_intr.addr_base;
}

static void ub_int_type1_update_mask(struct msi_desc *desc, u32 clear, u32 set)
{
	raw_spinlock_t *lock = &msi_desc_to_ub_entity(desc)->usi_lock;
	unsigned long flags;

	raw_spin_lock_irqsave(lock, flags);
	desc->ub_intr.intr_attrib.mask &= ~clear;
	desc->ub_intr.intr_attrib.mask |= set;
	ub_cfg_write_dword(msi_desc_to_ub_entity(desc), UB_INT_TYPE1_INT_MASK,
			   desc->ub_intr.intr_attrib.mask);
	raw_spin_unlock_irqrestore(lock, flags);
}

static void ub_int_type1_mask(struct msi_desc *desc, u32 mask)
{
	ub_int_type1_update_mask(desc, 0, mask);
}

static void ub_int_type2_mask(struct msi_desc *desc)
{
	void __iomem *addr = ub_vector_desc_addr(desc);
	u16 addr_index;
	u32 reg_val;

	desc->ub_intr.intr_attrib.mask = 1;
	addr_index = desc->ub_intr.intr_attrib.addr_index;
	reg_val = UB_INTR_VECTOR_MASK_MASK | (u32)addr_index;

	writel(reg_val, addr + UB_INTR_VECTOR_ADDR_INDEX);
}

static void ub_usi_desc_mask(struct msi_desc *desc, u32 nr)
{
	if (desc->ub_intr.intr_attrib.is_type1)
		ub_int_type1_mask(desc, nr);
	else
		ub_int_type2_mask(desc);
}

void ub_msi_mask_irq(struct irq_data *data)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);

	ub_usi_desc_mask(desc, (u32)BIT(data->irq - desc->irq));
}

static void ub_int_type1_unmask_irq(struct msi_desc *desc, u32 mask)
{
	ub_int_type1_update_mask(desc, mask, 0);
}

static void ub_int_type2_unmask_irq(struct msi_desc *desc)
{
	void __iomem *addr = ub_vector_desc_addr(desc);
	u16 addr_index;

	desc->ub_intr.intr_attrib.mask = 0;
	addr_index = desc->ub_intr.intr_attrib.addr_index;
	writel((u32)addr_index, addr + UB_INTR_VECTOR_ADDR_INDEX);
}

static void ub_usi_desc_unmask(struct msi_desc *desc, u32 nr)
{
	if (desc->ub_intr.intr_attrib.is_type1)
		ub_int_type1_unmask_irq(desc, nr);
	else
		ub_int_type2_unmask_irq(desc);
}

void ub_msi_unmask_irq(struct irq_data *data)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);

	ub_usi_desc_unmask(desc, (u32)BIT(data->irq - desc->irq));
}

static void __iomem *ub_intr_find_one_addr(struct msi_msg *msg,
					   struct msi_desc *entry,
					   u8 *is_new)
{
	void __iomem *first_unused_base = NULL;
	void __iomem *base;
	u32 addr_l, addr_h, valid, i;
	u16 first_unused_id;
	u32 addr_cnt = entry->ub_intr.addr_num + 1;

	base = ub_addr_desc_base_addr(entry);

	for (i = 0; i < addr_cnt; i++, base += UB_INTR_ADDR_ENTRY_SIZE) {
		valid = readl(base + UB_INTR_ADDR_TOKENID) & UB_INTR_ADDR_VALID_MASK;
		if (!valid) {
			if (!first_unused_base) {
				first_unused_base = base;
				first_unused_id = i;
			}
			continue;
		}
		addr_l = readl(base + UB_INTR_ADDR_ADDR_L);
		addr_h = readl(base + UB_INTR_ADDR_ADDR_H);
		if (msg->address_lo == addr_l && msg->address_hi == addr_h) {
			entry->ub_intr.intr_attrib.addr_index = i;
			*is_new = 0;
			return base;
		}
	}

	if (!first_unused_base)
		return NULL;
	*is_new = 1;

	entry->ub_intr.intr_attrib.addr_index = first_unused_id;

	return first_unused_base;
}

static void ub_int_type1_clear_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	struct ub_entity *uent = msi_desc_to_ub_entity(entry);
	int ret;

	/*
	 * In the interrupt release process,
	 * the kernel uses spin_lock_irqsave.
	 * If the message times out while this lock is held,
	 * the hardware watchdog will be triggered.
	 */
	ret = ub_cfg_write_byte(uent, UB_INT_TYPE1_ENABLE, 0);
	if (ret == -ETIMEDOUT) {
		pr_err("ub int type1 clear UB_INT_TYPE1_ENABLE failed\n");
		return;
	}

	ret = ub_cfg_write_dword(uent, UB_INT_TYPE1_EN_INT_NUM, 0);
	if (ret == -ETIMEDOUT) {
		pr_err("ub int type1 clear UB_INT_TYPE1_EN_INT_NUM failed\n");
		return;
	}

	ret = ub_cfg_write_dword(uent, UB_INT_TYPE1_INT_DATA, 0);
	if (ret == -ETIMEDOUT) {
		pr_err("ub int type1 clear UB_INT_TYPE1_INT_DATA failed\n");
		return;
	}

	ret = ub_cfg_write_dword(uent, UB_INT_TYPE1_INT_ADDR_L, 0);
	if (ret == -ETIMEDOUT) {
		pr_err("ub int type1 clear UB_INT_TYPE1_INT_ADDR_L failed\n");
		return;
	}

	ret = ub_cfg_write_dword(uent, UB_INT_TYPE1_INT_ADDR_H, 0);
	if (ret == -ETIMEDOUT) {
		pr_err("ub int type1 clear UB_INT_TYPE1_INT_ADDR_H failed\n");
		return;
	}
}

static void ub_int_type2_clear_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	void __iomem *vector_base;

	vector_base = ub_vector_desc_addr(entry);
	if (!vector_base) {
		WARN_ON(1);
		return;
	}

	writel(0, vector_base + UB_INTR_VECTOR_ID);
	/* clear interrupt index(bit 0~15), keep mask(bit 16) */
	writel(UB_INTR_VECTOR_MASK_MASK,
	       vector_base + UB_INTR_VECTOR_ADDR_INDEX);
}

static void __ub_clear_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	if (entry->ub_intr.intr_attrib.is_type1)
		ub_int_type1_clear_msg(entry, msg);
	else
		ub_int_type2_clear_msg(entry, msg);
}

static void ub_int_type1_set_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	struct ub_entity *uent = msi_desc_to_ub_entity(entry);

	ub_cfg_write_byte(uent, UB_INT_TYPE1_ENABLE, 1);
	ub_cfg_write_dword(uent, UB_INT_TYPE1_EN_INT_NUM,
			   (u32)ilog2(__roundup_pow_of_two(entry->nvec_used)));
	ub_cfg_write_dword(uent, UB_INT_TYPE1_INT_DATA, msg->data);
	ub_cfg_write_dword(uent, UB_INT_TYPE1_INT_ADDR_L, msg->address_lo);
	ub_cfg_write_dword(uent, UB_INT_TYPE1_INT_ADDR_H, msg->address_hi);
}

static void ub_int_type2_set_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	struct ub_entity *uent = msi_desc_to_ub_entity(entry);
	void __iomem *vector_base, *addr_base;
	unsigned long val;
	u32 reg_val;
	u8 is_new;

	vector_base = ub_vector_desc_addr(entry);
	if (!vector_base) {
		WARN_ON(1);
		return;
	}

	addr_base = ub_intr_find_one_addr(msg, entry, &is_new);
	if (addr_base) {
		writel(msg->data, vector_base + UB_INTR_VECTOR_ID);
		reg_val = readl(vector_base + UB_INTR_VECTOR_ADDR_INDEX) &
			  ~UB_INTR_VECTOR_ADDR_INDEX_MASK;
		reg_val |= entry->ub_intr.intr_attrib.addr_index;
		writel(reg_val, vector_base + UB_INTR_VECTOR_ADDR_INDEX);
		if (is_new) {
			writel(msg->address_lo, addr_base + UB_INTR_ADDR_ADDR_L);
			writel(msg->address_hi, addr_base + UB_INTR_ADDR_ADDR_H);
			writel(ub_get_dst_eid(uent), addr_base + UB_INTR_ADDR_DSTEID_0);
			val = uent->tid & UB_INTR_ADDR_TOKENID_MASK;
			writel(val, addr_base + UB_INTR_ADDR_TOKENID);
			/* valid bit must be placed at the end. */
			set_bit(UB_INTR_ADDR_VALID_BIT, &val);
			writel(val, addr_base + UB_INTR_ADDR_TOKENID);
		}
	} else {
		WARN_ON(1);
	}
}

static void __ub_set_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	if (entry->ub_intr.intr_attrib.is_type1)
		ub_int_type1_set_msg(entry, msg);
	else
		ub_int_type2_set_msg(entry, msg);
}

void ub_write_interruptid(struct ub_entity *uent)
{
	if (!uent->intr_type1)
		ub_cfg_write_dword(uent, UB_INT_ID, uent->intr_device_id);
	else
		ub_cfg_write_dword(uent, UB_INT_TYPE1_INT_ID, uent->intr_device_id);
}

void __ub_write_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	bool unmasked = false;

	if (!entry->ub_intr.intr_attrib.is_type1)
		unmasked = !(entry->ub_intr.intr_attrib.mask);

	if (unmasked)
		ub_usi_desc_mask(entry, 0);

	if (msg->address_lo == 0 && msg->address_hi == 0)
		__ub_clear_msi_msg(entry, msg);
	else
		__ub_set_msi_msg(entry, msg);

	if (unmasked)
		ub_usi_desc_unmask(entry, 0);

	entry->msg = *msg;
	if (entry->write_msi_msg)
		entry->write_msi_msg(entry, entry->write_msi_msg_data);
}

u32 ub_intr_addr_count(struct ub_entity *uent)
{
	u32 addr_num = 0;
	int ret;

	ret = ub_cfg_read_word(uent, UB_NUM_OF_INTR_ADDR_TBL, (u16 *)&addr_num);
	if (ret)
		return 0;
	/*
	 * The value of this field is N, indicating that the interrupt address table
	 * supported by the function entity supports N+1 interrupt address.
	 */
	addr_num += 1;

	return addr_num;
}
EXPORT_SYMBOL_GPL(ub_intr_addr_count);

u32 ub_intr_vec_count(struct ub_entity *uent)
{
	u32 vector_num = 0;
	int ret;

	ret = ub_cfg_read_word(uent, UB_NUM_OF_INTR_VECTOR_TBL, (u16 *)&vector_num);
	if (ret)
		return 0;
	/*
	 * The value of this field is N, indicating that the interrupt vector table
	 * supported by the function entity supports N+1 interrupt vectors.
	 */
	vector_num += 1;

	return vector_num;
}
EXPORT_SYMBOL_GPL(ub_intr_vec_count);

static int ub_prepare_msi_desc(struct ub_entity *uent, struct msi_desc *desc)
{
	void __iomem *vec_desc_addr;
	u32 addr_cnt, vec_cnt;

	addr_cnt = ub_intr_addr_count(uent);
	if (addr_cnt == 0)
		return -EINVAL;

	vec_cnt = ub_intr_vec_count(uent);
	if (vec_cnt == 0)
		return -EINVAL;

	desc->nvec_used = 1;
	desc->ub_intr.intr_attrib.is_type1 = 0;
	desc->ub_intr.addr_base = uent->intr_addr_base;
	desc->ub_intr.vector_base = uent->intr_vector_base;
	desc->ub_intr.addr_num = (u16)(addr_cnt - 1);
	desc->ub_intr.vec_num = (u16)(vec_cnt - 1);

	vec_desc_addr = ub_vector_desc_addr(desc);
	desc->ub_intr.intr_attrib.mask = !!(readl(vec_desc_addr + UB_INTR_VECTOR_ADDR_INDEX) &
					 UB_INTR_VECTOR_MASK_MASK);

	return 0;
}

static int ub_setup_msi_descs(struct ub_entity *uent,
			      struct ub_usi_entry *entries, int nvec,
			      struct irq_affinity_desc *masks)
{
	struct irq_affinity_desc *curmsk;
	struct msi_desc desc;
	int ret = 0, i;

	memset(&desc, 0, sizeof(desc));

	if (uent->intr_type1) {
		desc.ub_intr.intr_attrib.is_type1 = 1;
		desc.nvec_used = nvec;
		desc.affinity = masks;
		ret = ub_cfg_read_dword(uent, UB_INT_TYPE1_INT_MASK,
					&desc.ub_intr.intr_attrib.mask);
		if (ret)
			return ret;

		return msi_insert_msi_desc(&uent->dev, &desc);
	}

	for (i = 0, curmsk = masks; i < nvec; i++, curmsk++) {
		desc.msi_index = entries ? entries[i].entry : i;
		desc.ub_intr.intr_attrib.entry_nr = desc.msi_index;
		desc.affinity = masks ? curmsk : NULL;
		ret = ub_prepare_msi_desc(uent, &desc);
		if (ret)
			break;
		ret = msi_insert_msi_desc(&uent->dev, &desc);
		if (ret)
			break;
	}
	return ret;
}

static int ub_setup_intr_irqs(struct ub_entity *uent, int nvec)
{
	struct irq_domain *domain;

	domain = dev_get_msi_domain(&uent->dev);
	if (domain && irq_domain_is_hierarchy(domain))
		return msi_domain_alloc_irqs_all_locked(&uent->dev, 0, nvec);

	pr_info("default irq alloc to be done...\n");

	return -ENOSPC;
}

static void ub_update_entries(struct ub_entity *uent, struct ub_usi_entry *entries)
{
	struct msi_desc *desc;

	if (entries) {
		msi_for_each_desc(desc, &uent->dev, MSI_DESC_ALL) {
			entries->vector = desc->irq;
			entries++;
		}
	}
}

static void ub_msi_teardown_msi_irqs(struct ub_entity *uent)
{
	struct irq_domain *domain;

	domain = dev_get_msi_domain(&uent->dev);
	if (domain && irq_domain_is_hierarchy(domain))
		msi_domain_free_irqs_all_locked(&uent->dev, 0);
	else
		pr_info("default irq free to be done.\n");
}

static void free_msi_irqs(struct ub_entity *uent)
{
	ub_msi_teardown_msi_irqs(uent);

	if (uent->intr_addr_base) {
		iounmap(uent->intr_addr_base);
		uent->intr_addr_base = NULL;
	}
	if (uent->intr_vector_base) {
		iounmap(uent->intr_vector_base);
		uent->intr_vector_base = NULL;
	}
}

int usi_setup_interrupts(struct ub_entity *uent, struct ub_usi_entry *entries,
			 int nvec, struct irq_affinity *affd)
{
	struct irq_affinity_desc *masks = NULL;
	int ret;

	if (affd)
		masks = irq_create_affinity_masks(nvec, affd);

	msi_lock_descs(&uent->dev);
	ret = ub_setup_msi_descs(uent, entries, nvec, masks);
	if (ret)
		goto out_free;

	ret = ub_setup_intr_irqs(uent, nvec);
	if (ret)
		goto out_free;

	ub_update_entries(uent, entries);
	goto out_unlock;

out_free:
	free_msi_irqs(uent);
out_unlock:
	msi_unlock_descs(&uent->dev);
	kfree(masks);
	return ret;
}
EXPORT_SYMBOL_GPL(usi_setup_interrupts);

void ub_disable_intr(struct ub_entity *uent)
{
	u32 i, addr_num;
	void *intr_addr;

	if (!uent || !uent->intr_enabled)
		return;

	if (uent->intr_type1) {
		ub_cfg_write_byte(uent, UB_INT_TYPE1_ENABLE, 0);
		ub_cfg_write_dword(uent, UB_INT_TYPE1_INT_MASK, GENMASK(31, 0));
	} else {
		addr_num = ub_intr_addr_count(uent);
		for (i = 0; i < addr_num; i++) {
			intr_addr = uent->intr_addr_base + i * UB_INTR_ADDR_ENTRY_SIZE;
			writel(0, intr_addr + UB_INTR_ADDR_TOKENID);
			writel(0, intr_addr + UB_INTR_ADDR_DSTEID_0);
			writel(0, intr_addr + UB_INTR_ADDR_ADDR_L);
			writel(0, intr_addr + UB_INTR_ADDR_ADDR_H);
		}

		ub_cfg_write_byte(uent, UB_INT_MASK, 1);
		ub_cfg_write_byte(uent, UB_INT_EN, 0);
	}

	uent->intr_enabled = 0;
	ub_interrupt_id_free(uent);
	free_msi_irqs(uent);
}
EXPORT_SYMBOL_GPL(ub_disable_intr);

int ub_setup_msi_context(struct ub_entity *uent)
{
	return msi_setup_device_data(&uent->dev);
}
EXPORT_SYMBOL_GPL(ub_setup_msi_context);
