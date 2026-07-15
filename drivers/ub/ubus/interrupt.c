// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus interrupt: " fmt

#include <linux/irqdomain.h>
#include <linux/bitops.h>
#include <linux/msi.h>
#include <linux/irq.h>
#include <ub/ubfi/ubfi.h>
#include <linux/of.h>
#include <linux/msi_api.h>
#include <linux/interrupt.h>

#include "ubus.h"
#include "interrupt.h"

enum ub_intr_tbl_type {
	UB_INTR_VECTOR_TBL,
	UB_INTR_ADDR_TBL
};

struct ub_intr_vector_tbl {
	unsigned int vector;
	unsigned int addr_index : 16;
	unsigned int mask : 1;
	unsigned int reserved : 15;
};

struct ub_intr_addr_tbl {
	unsigned int intr_addr_l;
	unsigned int intr_addr_h;
	unsigned int token_id : 20;
	unsigned int valid : 1;
	unsigned int reserved0 : 11;
	unsigned int dst_eid_0;
	unsigned int dst_eid_1;
	unsigned int dst_eid_2;
	unsigned int dst_eid_3;
};

void ub_intr_init(struct ub_entity *uent)
{
	if (uent->cfg1_bitmap[0] & UB_INT_TYPE2_CAP_BIT)
		uent->intr_type1 = 0;
	else if (uent->cfg1_bitmap[0] & UB_INT_TYPE1_CAP_BIT)
		uent->intr_type1 = 1;
	else
		uent->no_intr = 1;
}

u32 ub_int_type1_vec_count(struct ub_entity *uent)
{
	u16 vector_num = 0;
	int ret;

	ret = ub_cfg_read_word(uent, UB_INT_TYPE1_SUP_INT_NUM, &vector_num);
	if (ret)
		return 0;

	/* Mapping between the number of bitmaps and vectors defined in the protocol */
	vector_num = 1 << vector_num;

	return vector_num;
}
EXPORT_SYMBOL_GPL(ub_int_type1_vec_count);

static void __iomem *ub_intr_map_region(struct ub_entity *uent,
					enum ub_intr_tbl_type type, int nr_entries)
{
	u32 addr_reg_l, addr_reg_h, offset_l, offset_h;
	resource_size_t tb_phys_addr;
	unsigned long flags, sz;
	u64 offset;
	int ret;

	if (nr_entries <= 0)
		return NULL;
	if (type == UB_INTR_VECTOR_TBL) {
		addr_reg_l = UB_INT_VECTOR_TBL_SA_L;
		addr_reg_h = UB_INT_VECTOR_TBL_SA_H;
		sz = (unsigned long)(nr_entries * UB_INTR_VECTOR_ENTRY_SIZE);
	} else {
		addr_reg_l = UB_INT_ADDR_TBL_SA_L;
		addr_reg_h = UB_INT_ADDR_TBL_SA_H;
		sz = (unsigned long)(nr_entries * UB_INTR_ADDR_ENTRY_SIZE);
	}

	ret = ub_cfg_read_dword(uent, addr_reg_l, &offset_l);
	ret |= ub_cfg_read_dword(uent, addr_reg_h, &offset_h);
	if (ret) {
		ub_err(uent, "read addr register failed, ret=%d\n", ret);
		return NULL;
	}

	offset = ((u64)offset_h << 32) | offset_l;

	flags = ub_resource_flags(uent, 0);
	if (!flags || (flags & IORESOURCE_UNSET))
		return NULL;

	if (offset + sz > ub_resource_len(uent, 0)) {
		ub_err(uent, "UB interrupt table(type:%u) off:%#llx + sz:%#lx is out of range!\n",
		       type, offset, sz);
		return NULL;
	}
	tb_phys_addr = ub_resource_start(uent, 0) + offset;

	return ioremap(tb_phys_addr, sz);
}

static int int_type1_capability_init(struct ub_entity *uent,
				     struct ub_usi_entry *entries, int nvec,
				     struct irq_affinity *affd)
{
	int ret;

	uent->intr_enabled = 1;

	ret = usi_setup_interrupts(uent, entries, nvec, affd);
	if (ret)
		goto out_disable;

	ub_cfg_write_byte(uent, UB_INT_TYPE1_ENABLE, 1);
	return 0;

out_disable:
	uent->intr_enabled = 0;

	return ret;
}

static int int_type2_capability_init(struct ub_entity *uent,
				     struct ub_usi_entry *entries, int nvec,
				     struct irq_affinity *affd)
{
	void __iomem *vector_base, *addr_base;
	int vector_num, addr_num;
	int ret;

	uent->intr_enabled = 1;

	vector_num = (int)ub_intr_vec_count(uent);
	/* Request & Map UB interrupt table region */
	vector_base = ub_intr_map_region(uent, UB_INTR_VECTOR_TBL, vector_num);
	if (!vector_base) {
		ret = -ENOMEM;
		goto out_disable;
	}
	addr_num = (int)ub_intr_addr_count(uent);
	addr_base = ub_intr_map_region(uent, UB_INTR_ADDR_TBL, addr_num);
	if (!addr_base) {
		iounmap(vector_base);
		ret = -ENOMEM;
		goto out_disable;
	}
	uent->intr_vector_base = vector_base;
	uent->intr_addr_base = addr_base;

	ret = usi_setup_interrupts(uent, entries, nvec, affd);
	if (ret)
		goto out_disable;

	ub_cfg_write_byte(uent, UB_INT_MASK, 0);
	ub_cfg_write_byte(uent, UB_INT_EN, 1);

	return 0;

out_disable:
	uent->intr_enabled = 0;

	return ret;
}

static int ub_msi_supported(struct ub_entity *uent, int nvec)
{
	if (!uent || uent->no_intr || nvec < 1)
		return 0;

	return 1;
}

static int ub_usi_entry_invalid_check(struct ub_usi_entry *ents,
				      int nvec, int nr_ents)
{
	int i, j;

	if (!ents)
		return 0;

	for (i = 0; i < nvec; i++) {
		if (ents[i].entry >= nr_ents)
			return -EINVAL;

		for (j = i + 1; j < nvec; j++)
			if (ents[i].entry == ents[j].entry)
				return -EINVAL;
	}

	return 0;
}

static int __ub_enable_usi_range(struct ub_entity *uent,
				 struct ub_usi_entry *entries, int minvec,
				 int maxvec, struct irq_affinity *affd)
{
	int hwsize, nvec = maxvec;
	int ret;

	if (maxvec < minvec)
		return -ERANGE;

	if (!ub_msi_supported(uent, nvec))
		return -EINVAL;

	if (uent->intr_type1)
		hwsize = (int)ub_int_type1_vec_count(uent);
	else
		hwsize = (int)ub_intr_vec_count(uent);
	if (hwsize == 0) {
		ub_err(uent, "int vector cnt is zero.\n");
		return -ENOSPC;
	}

	ret = ub_usi_entry_invalid_check(entries, nvec, hwsize);
	if (ret)
		return ret;

	if (hwsize < nvec)
		nvec = hwsize;
	if (nvec < minvec)
		return -ENOSPC;

	ret = ub_setup_msi_context(uent);
	if (ret)
		return ret;

	if (!ub_setup_usi_device_domain(uent, hwsize)) {
		ub_err(uent, "ub setup device domain failed.\n");
		return -ENODEV;
	}

	if (affd) {
		nvec = ub_irq_calc_affinity_vectors(minvec, nvec, affd);
		if (nvec < minvec) {
			ub_err(uent, "irq calc affd failed.\n");
			return -ENOSPC;
		}
	}

	if (uent->intr_type1)
		ret = int_type1_capability_init(uent, entries, nvec, affd);
	else
		ret = int_type2_capability_init(uent, entries, nvec, affd);
	if (ret)
		return ret;

	return nvec;
}

int ub_alloc_irq_vectors_affinity(struct ub_entity *uent, unsigned int min_vecs,
				  unsigned int max_vecs, unsigned int flags,
				  struct irq_affinity *affd)
{
	struct irq_affinity msi_default_affd = {};

	if (flags & UB_IRQ_AFFINITY) {
		if (!affd)
			affd = &msi_default_affd;
	} else {
		if (WARN_ON(affd))
			affd = NULL;
	}

	return __ub_enable_usi_range(uent, NULL, min_vecs, max_vecs, affd);
}
EXPORT_SYMBOL_GPL(ub_alloc_irq_vectors_affinity);

int ub_irq_vector(struct ub_entity *uent, unsigned int nr)
{
	unsigned int irq;

	if (!uent)
		return -EINVAL;

	if (uent->intr_enabled) {
		irq = msi_get_virq(&uent->dev, nr);
		return irq ? (int)irq : -EINVAL;
	}

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(ub_irq_vector);

const struct cpumask *ub_irq_get_affinity(struct ub_entity *dev, int nr)
{
	int idx, irq = ub_irq_vector(dev, nr);
	struct msi_desc *desc;

	if (WARN_ON_ONCE(irq <= 0))
		return NULL;

	desc = irq_get_msi_desc(irq);
	/* Interrupts can be allocated without affinity descriptor */
	if (!desc->affinity)
		return NULL;

	/*
	 * INT_TYPE1 has a mask array in the descriptor.
	 * INT_TYPE2 has a single mask.
	 */
	idx = dev->intr_type1 ? nr : 0;
	return &desc->affinity[idx].mask;
}
EXPORT_SYMBOL_GPL(ub_irq_get_affinity);
