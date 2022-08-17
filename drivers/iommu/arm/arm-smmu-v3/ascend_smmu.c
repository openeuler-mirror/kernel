// SPDX-License-Identifier: GPL-2.0+
/*
 * Huawei Ascend accelerator common code for SMMUv3 ATOS feature implementations.
 *
 * Copyright (C) 2020-2021 Huawei Technologies Co., Ltd
 *
 * Author: Binfeng Wu <wubinfeng@huawei.com>
 *
 * This driver is intended to provide an interface for translating IPA to PA
 * based on the SMMUv3 ATOS feature.
 *
 */

#include <linux/bitfield.h>
#include <linux/iopoll.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/ascend_smmu.h>

#define AGENT_SMMU_IDR1			0x4
#define IDR1_SSIDSIZE			GENMASK(10, 6)
#define IDR1_SIDSIZE			GENMASK(5, 0)

#define AGENT_SMMU_CR0			0x20
#define CR0_SMMUEN			(1 << 0)

#define AGENT_SMMU_ATOS_CTRL		0x100

#define ENHANCED_ATOS_UNIT_ADDR		0x1700	/* first unit */
#define ENHANCED_ATOS_UNIT_SIZE		0x18

#define ENHANCED_ATOS_SID		0x0
#define ENHANCED_ATOS_STREAMID_MASK	GENMASK_ULL(31, 0)
#define ENHANCED_ATOS_SUBSTREAMID_MASK	GENMASK_ULL(51, 32)
#define ENHANCED_ATOS_SSID_VALID_MASK	GENMASK_ULL(52, 52)

#define ENHANCED_ATOS_ADDR		0x8
#define ENHANCED_ATOS_ADDR_ADDR_MASK	GENMASK_ULL(63, 12)
#define ENHANCED_ATOS_ADDR_TYPE_MASK	GENMASK_ULL(11, 10)
#define ENHANCED_ATOS_ADDR_TYPE_S1	0x01
#define ENHANCED_ATOS_ADDR_PnU_MASK	GENMASK_ULL(9, 9)
#define ENHANCED_ATOS_ADDR_RnW_MASK	GENMASK_ULL(8, 8)
#define ENHANCED_ATOS_ADDR_InD_MASK	GENMASK_ULL(7, 7)
#define ENHANCED_ATOS_ADDR_HTTUI_MASK	GENMASK_ULL(6, 6)

#define ENHANCED_ATOS_PAR		0x10
#define ENHANCED_ATOS_PAR_FAULT		(1 << 0)
#define ENHANCED_ATOS_PAR_SIZE		(1 << 11)
#define ENHANCED_ATOS_PAR_ADDR_MASK	GENMASK_ULL(51, 12)
#define ENHANCED_ATOS_PAR_FAULTCODE	GENMASK_ULL(11, 4)
#define ENHANCED_ATOS_PAR_REASON	GENMASK_ULL(2, 1)

#define AGENT_SMMU_POLL_US		5
#define AGENT_SMMU_TIMEOUT_US		250
#define MAX_REGISTERS			32

static LIST_HEAD(agent_smmu_list);
static DEFINE_SPINLOCK(agent_smmu_lock);

struct agent_smmu {
	struct device *dev;
	void __iomem *base;
	unsigned int max_sid;
	unsigned int max_ssid;
	rwlock_t rw_lock;
	DECLARE_BITMAP(regs, MAX_REGISTERS);

	struct list_head list;
	u64 device_id;	/* DIE id */
};

struct agent_smmu *agent_smmu_unlocked_find(u64 device_id)
{
	struct agent_smmu *temp = NULL;

	list_for_each_entry(temp, &agent_smmu_list, list) {
		if (temp->device_id == device_id) {
			return temp;
		}
	}
	return NULL;
}

static int agent_smmu_register(struct agent_smmu *agent)
{
	struct device *dev = agent->dev;

	spin_lock(&agent_smmu_lock);
	if (agent_smmu_unlocked_find(agent->device_id)) {
		dev_err(dev, "already added for %lld.\n", agent->device_id);
		spin_unlock(&agent_smmu_lock);
		return -EFAULT;
	}
	list_add_tail(&agent->list, &agent_smmu_list);
	spin_unlock(&agent_smmu_lock);

	return 0;
}

static void agent_smmu_unregister(struct agent_smmu *agent)
{
	spin_lock(&agent_smmu_lock);
	list_del(&agent->list);
	spin_unlock(&agent_smmu_lock);
}

static int agent_smmu_platform_probe(struct platform_device *pdev)
{
	struct agent_smmu *agent = NULL;
	struct device *dev = &pdev->dev;
	struct resource *res = NULL;
	u32 reg = 0;
	int ret = 0;
	acpi_status status = AE_OK;

	agent = devm_kzalloc(dev, sizeof(*agent), GFP_KERNEL);
	if (!agent) {
		dev_err(dev, "failed to allocate agent smmu.\n");
		return -ENOMEM;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res || resource_size(res) + 1 < ENHANCED_ATOS_UNIT_ADDR +
	    ENHANCED_ATOS_UNIT_SIZE * MAX_REGISTERS) {
		dev_err(dev, "MMIO region is null or too small, check it.\n");
		ret = -EINVAL;
		goto err_free;
	}

	// agent smmu may probe as smmu in device, so keep using ioreamp
	agent->base = ioremap(res->start, resource_size(res));
	if (!agent->base) {
		dev_err(dev, "unable to map agent smmu.\n");
		ret = -ENOMEM;
		goto err_free;
	}

	/* check agent smmu is enabled */
	reg = readl_relaxed(agent->base + AGENT_SMMU_CR0);
	if (!(reg & CR0_SMMUEN)) {
		dev_err(dev, "agent smmu is not enabled, check it.\n");
		ret = -EPERM;
		goto err_iounmap;
	}

	status = acpi_evaluate_integer(ACPI_HANDLE(&pdev->dev), METHOD_NAME__UID,
				       NULL, &agent->device_id);
	if (ACPI_FAILURE(status) || agent_smmu_register(agent)) {
		dev_err(dev, "agent smmu UID 0x%x has been probed.\n", status);
		ret = -EINVAL;
		goto err_iounmap;
	}

	reg = readl_relaxed(agent->base + AGENT_SMMU_IDR1);
	agent->max_sid = (1U << FIELD_GET(IDR1_SIDSIZE, reg)) - 1;
	agent->max_ssid = (1U << FIELD_GET(IDR1_SSIDSIZE, reg)) - 1;
	bitmap_zero(agent->regs, MAX_REGISTERS);
	rwlock_init(&agent->rw_lock);
	agent->dev = dev;
	platform_set_drvdata(pdev, agent);

	dev_info(dev, "agent smmu 0x%llx probed successfully.\n", agent->device_id);
	return ret;
err_iounmap:
	iounmap(agent->base);
	agent->base = NULL;
err_free:
	devm_kfree(dev, agent);
	return ret;
}

static int agent_smmu_platform_remove(struct platform_device *pdev)
{
	struct agent_smmu *agent = platform_get_drvdata(pdev);

	agent_smmu_unregister(agent);
	iounmap(agent->base);
	agent->dev = NULL;
	agent->base = NULL;
	dev_info(&pdev->dev, "agent smmu removed successfully.\n");
	return 0;
}

static void set_registers_unlocked(struct agent_smmu *agent, unsigned long *avl_regs,
			  unsigned long *loc_regs, int nr)
{
	int idx = 0;

	while (nr > 0) {
		idx = find_next_bit(avl_regs, MAX_REGISTERS, idx);
		set_bit(idx, loc_regs);
		set_bit(idx, agent->regs);
		nr--;
		idx++;
	}
}

/**
 * registers_acquire - take up available registers(some reg may keep unavailable
 * state) from agent smmu according to the number of 'need', mark them in
 * 'loc_regs' and return the number of registers in procession
 *
 * @agent: agent smmu
 * @loc_regs: bitmap recored user's available registers
 * @need: the number of task still need to be processed
 */
static int registers_acquire(struct agent_smmu *agent, unsigned long *loc_regs,
			     int need)
{
	int rest = 0;
	u32 avl_regs_state = 0;
	DECLARE_BITMAP(avl_regs, MAX_REGISTERS);

	write_lock(&agent->rw_lock);
	if (bitmap_full(agent->regs, MAX_REGISTERS)) {
		rest = 0;
	} else {
		avl_regs_state = readl_relaxed(agent->base + AGENT_SMMU_ATOS_CTRL);
		avl_regs_state = ~avl_regs_state;
		bitmap_from_arr32(avl_regs, &avl_regs_state, MAX_REGISTERS);
		bitmap_andnot(avl_regs, avl_regs, agent->regs, MAX_REGISTERS);
		rest = bitmap_weight(avl_regs, MAX_REGISTERS);
	}
	set_registers_unlocked(agent, avl_regs, loc_regs, need > rest ? rest : need);
	write_unlock(&agent->rw_lock);

	return bitmap_weight(loc_regs, MAX_REGISTERS);
}

static void write_enhanced_atos(struct agent_smmu *agent, int regs_idx, u64 sid,
				u64 addr, dma_addr_t iova)
{
	void __iomem *unit_base;

	unit_base = agent->base + ENHANCED_ATOS_UNIT_ADDR +
		    ENHANCED_ATOS_UNIT_SIZE * regs_idx;
	addr |= iova & ENHANCED_ATOS_ADDR_ADDR_MASK;

	writeq_relaxed(addr, unit_base + ENHANCED_ATOS_ADDR);
	writeq_relaxed(sid, unit_base + ENHANCED_ATOS_SID);
}

static int get_section_mask(u64 par, u64 *section_mask)
{
	int i = 0;

	// using default page size 4KB according to spec
	*section_mask = ~((1 << 12) - 1);

	// e.g. PAR[Size] is 1 && PAR[14:12] is 0 && PAR[15] is 1, then lowest
	// bit is 15, so section size is 2^(12+3+1) = 64KB
	if (par & ENHANCED_ATOS_PAR_SIZE) {
		par = FIELD_GET(ENHANCED_ATOS_PAR_ADDR_MASK, par);
		if (!par) {
			pr_err("agent smmu: err happen in agent smmu PAR[11]\n");
			return -EFAULT;
		}

		par = (par ^ (par - 1)) >> 1;
		for (i = 0; par; i++) {
			par >>= 1;
		}
		*section_mask = ~((1 << (12 + i + 1)) - 1);
	}
	return 0;
}

static int read_enhanced_atos(struct agent_smmu *agent, int regs_idx, int idx,
			      u32 state, struct agent_smmu_atos_data *data)
{
	void __iomem *unit_base = NULL;
	u64 par = 0;
	int ret = 0;
	u64 section_mask = 0;
	u64 section = 0;
	int i = 0;

	unit_base = agent->base + ENHANCED_ATOS_UNIT_ADDR +
		    ENHANCED_ATOS_UNIT_SIZE * regs_idx;
	par = readq_relaxed(unit_base + ENHANCED_ATOS_PAR);

	if (state & (1 << regs_idx)) {
		return -EBUSY;
	} else if (par & ENHANCED_ATOS_PAR_FAULT) {
		data->pa[idx] = par & ENHANCED_ATOS_PAR_FAULTCODE;
		data->pa[idx] |= par & ENHANCED_ATOS_PAR_REASON;
		pr_err("agent smmu: err happened, get PAR 0x%llx\n", par);
		return -EFAULT;
	} else {
		ret = get_section_mask(par, &section_mask);
		if (ret)
			return ret;
		// use ENHANCED_ATOS_PAR_ADDR_MASK not section_mask
		// since ADDR[63,52] is ATTR or IMPDEF which we don't want
		data->pa[idx] = (par & ENHANCED_ATOS_PAR_ADDR_MASK & section_mask) |
				(data->iova[idx] & ~section_mask);
		section = data->iova[idx] & section_mask;

		for (i = idx + 1; i < data->nr; i++) {
			if ((data->iova[i] & section_mask) != section)
				break;
			data->pa[i] = (par & ENHANCED_ATOS_PAR_ADDR_MASK & section_mask) |
				      (data->iova[i] & ~section_mask);
		}
	}
	return 0;
}

#define bitmap_for_each_set_bit(i, src, nbits) \
	for ((i) = 0; ((i) = find_next_bit((src), (nbits), (i))) < (nbits); (i) += 1)

int agent_smmu_iova_to_phys(struct agent_smmu_atos_data *data, int *succeed)
{
	struct agent_smmu *agent = NULL;
	int ret = 0;
	int i;
	u64 sid = 0;
	u64 addr = 0;
	int idx = 0;
	u32 state = 0;
	DECLARE_BITMAP(loc_regs, MAX_REGISTERS);
	DECLARE_BITMAP(bitmask, MAX_REGISTERS);
	u32 bitmask_u32;

	if (!data || !data->iova || !data->pa || data->nr <= 0 || !succeed) {
		return -EINVAL;
	}

	// now only HTTUI = 1 is allowed
	if (!data->httui) {
		pr_err("agent smmu: check httui, make sure is valid\n");
		return -EINVAL;
	}

	spin_lock(&agent_smmu_lock);
	agent = agent_smmu_unlocked_find(data->device_id);
	if (!agent || !get_device(agent->dev)) {
		pr_err("agent smmu: %lld has been removed or hasn't initialized.\n",
		       data->device_id);
		spin_unlock(&agent_smmu_lock);
		return -EINVAL;
	}
	spin_unlock(&agent_smmu_lock);

	if (data->sid > agent->max_sid || data->ssid > agent->max_ssid) {
		pr_err("agent smmu: sid or ssid out of acceptable range.\n");
		ret = -EINVAL;
		goto put_device;
	}

	*succeed = 0;
	/* make sure default return is 0 because 0 make sence too */
	for (i = 0; i < data->nr; i++) {
		data->pa[i] = 0;
	}
	/* joint sid and addr first*/
	sid = FIELD_PREP(ENHANCED_ATOS_STREAMID_MASK, data->sid);
	sid |= FIELD_PREP(ENHANCED_ATOS_SUBSTREAMID_MASK, data->ssid);
	sid |= FIELD_PREP(ENHANCED_ATOS_SSID_VALID_MASK, data->ssid ? 1 : 0);
	addr |= FIELD_PREP(ENHANCED_ATOS_ADDR_TYPE_MASK, ENHANCED_ATOS_ADDR_TYPE_S1);
	addr |= FIELD_PREP(ENHANCED_ATOS_ADDR_PnU_MASK, data->pnu ? 1 : 0);
	addr |= FIELD_PREP(ENHANCED_ATOS_ADDR_RnW_MASK, data->rnw ? 1 : 0);
	addr |= FIELD_PREP(ENHANCED_ATOS_ADDR_InD_MASK, data->ind ? 1 : 0);
	addr |= FIELD_PREP(ENHANCED_ATOS_ADDR_HTTUI_MASK, data->httui ? 1 : 0);
	bitmap_zero(loc_regs, MAX_REGISTERS);
	if (!registers_acquire(agent, loc_regs, data->nr)) {
		pr_err("agent smmu: busy now, try again later.\n");
		ret = -EBUSY;
		goto put_device;
	}

	idx = *succeed;
	while (idx < data->nr) {
		bitmap_zero(bitmask, MAX_REGISTERS);

		bitmap_for_each_set_bit(i, loc_regs, MAX_REGISTERS) {
			if (idx >= data->nr)
				break;
			write_enhanced_atos(agent, i, sid, addr, data->iova[idx++]);
			bitmap_set(bitmask, i, MAX_REGISTERS);
		}

		bitmap_to_arr32(&bitmask_u32, bitmask, MAX_REGISTERS);
		writel(bitmask_u32, agent->base + AGENT_SMMU_ATOS_CTRL);
		readl_poll_timeout(agent->base + AGENT_SMMU_ATOS_CTRL, state,
				   !(state & bitmask_u32), AGENT_SMMU_POLL_US,
				   AGENT_SMMU_TIMEOUT_US);

		idx = *succeed;
		bitmap_for_each_set_bit(i, bitmask, MAX_REGISTERS) {
			if (idx >= data->nr)
				break;

			if (data->pa[idx] != 0) {
				idx++;
				continue;
			}
			ret = read_enhanced_atos(agent, i, idx, state, data);
			if (ret) {
				*succeed = idx;
				pr_err("agent smmu: translate failed, reason %d\n", ret);
				goto free_bits;
			}
			idx++;
		}
		*succeed = idx;
	}

free_bits:
	write_lock(&agent->rw_lock);
	bitmap_andnot(agent->regs, agent->regs, loc_regs, MAX_REGISTERS);
	write_unlock(&agent->rw_lock);
put_device:
	put_device(agent->dev);
	return ret;
}
EXPORT_SYMBOL_GPL(agent_smmu_iova_to_phys);

static const struct acpi_device_id agent_smmu_acpi_match[] = {
	{"SMMU0000", 0},
	{}
};
MODULE_DEVICE_TABLE(acpi, agent_smmu_acpi_match);

static struct platform_driver agent_smmu_driver = {
	.driver = {
		.name = "agent_smmu_platform",
		.acpi_match_table = agent_smmu_acpi_match,
	},
	.probe = agent_smmu_platform_probe,
	.remove = agent_smmu_platform_remove,
};
module_platform_driver(agent_smmu_driver);
