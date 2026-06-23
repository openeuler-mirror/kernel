// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, The Linux Foundation. All rights reserved.
 */

#include <linux/pci.h>
#include <linux/bitops.h>
#include <asm/rmi_cmds.h>
#include <asm/hisi_cca_da.h>
#include <linux/crash_dump.h>
#include <linux/io-pgtable.h>

#include "arm-smmu-v3.h"
#include "arm-r-smmu-v3.h"

#define STRTAB_L1_DESC_DWORDS		1

/*
 * Add realm IRQs index based on arm_smmu_msi_index
 * Struct arm_r_smmu_msi_index need keep same as struct arm_smmu_msi_index
 */
enum arm_r_smmu_msi_index {
	EVTQ_MSI_INDEX,
	GERROR_MSI_INDEX,
	PRIQ_MSI_INDEX,
	R_EVTQ_MSI_INDEX,
	R_GERROR_MSI_INDEX,
	ARM_R_SMMU_MAX_MSIS,
};

#define ARM_R_SMMU_MAX_CFGS 0x3

#define realm_smmu_read_poll_timeout(addr, val, cond, delay_us, timeout_us) \
	realm_read_poll_timeout(rmi_smmu_reg_read32, val, cond, delay_us, \
				timeout_us, false, smmu->realm.ioaddr, addr)

/* Add realm IRQs cfg based on arm_smmu_msi_cfg */
static phys_addr_t arm_r_smmu_msi_cfg[ARM_R_SMMU_MAX_MSIS][ARM_R_SMMU_MAX_CFGS] = {
	[R_EVTQ_MSI_INDEX] = {
		SMMU_R_EVENTQ_IRQ_CFG0,
		SMMU_R_EVENTQ_IRQ_CFG1,
		SMMU_R_EVENTQ_IRQ_CFG2,
	},
	[R_GERROR_MSI_INDEX] = {
		SMMU_R_GERROR_IRQ_CFG0,
		SMMU_R_GERROR_IRQ_CFG1,
		SMMU_R_GERROR_IRQ_CFG2,
	},
};

bool arm_smmu_support_rme(struct arm_smmu_device *smmu)
{
	if (!is_support_rme())
		return false;

	return smmu->realm.enabled;
}

static int realm_smmu_write_reg_sync(struct arm_smmu_device *smmu, u32 val,
				     unsigned int reg_off, unsigned int ack_off)
{
	int ret;
	u32 reg;

	ret = rmi_smmu_reg_write32(smmu->realm.ioaddr, reg_off, val);
	if (ret)
		return ret;

	return realm_smmu_read_poll_timeout(ack_off, reg, reg == val, 1,
					    ARM_SMMU_POLL_TIMEOUT_US);
}

void realm_smmu_write_ste(struct arm_smmu_master *master, u32 sid,
			  const struct arm_smmu_ste *target)
{
	u64 ns_vttbr, ste_0_cfg;
	bool lvl_strtab;
	struct arm_smmu_ste *rste;
	struct arm_smmu_device *smmu = master->smmu;

	if (!arm_smmu_support_rme(smmu))
		return;

	if (!rme_is_pcipc_ns_dev(master->dev))
		return;

	ste_0_cfg = FIELD_GET(STRTAB_STE_0_CFG, le64_to_cpu(target->data[0]));
	if (ste_0_cfg != STRTAB_STE_0_CFG_S2_TRANS && ste_0_cfg != 0)
		return;

	lvl_strtab = !!(smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB);
	if (lvl_strtab) {
		if (realm_smmu_init_l2_strtab(smmu, sid))
			return;
	}

	rste = (struct arm_smmu_ste *)get_zeroed_page(GFP_KERNEL);
	if (!rste) {
		dev_err(smmu->dev, "failed to allocate realm ste page\n");
		return;
	}

	memcpy(rste, target, sizeof(struct arm_smmu_ste));

	if (rste->data[3] & STRTAB_STE_3_S2TTB_MASK) {
		ns_vttbr = rme_get_ns_vttbr(master->dev);
		rste->data[3] =  ns_vttbr & STRTAB_STE_3_S2TTB_MASK;
	}

	if (rmi_smmu_ste_write(smmu->realm.ioaddr, sid, virt_to_phys(rste),
			       lvl_strtab))
		dev_err(smmu->dev, "failed to write realm ste\n");

	free_page((unsigned long)rste);
}

static bool is_realm_dev_attach(struct arm_smmu_domain *smmu_domain)
{
	return smmu_domain->realm || smmu_domain->pcipc_ns;
}

static bool is_realm_dev_detach(struct arm_smmu_domain *smmu_domain,
				struct arm_smmu_master *master)
{
	if (!smmu_domain->realm && rme_is_realm_dev(master->dev))
		return true;
	else if (!smmu_domain->pcipc_ns && rme_is_pcipc_ns_dev(master->dev))
		return true;
	else
		return false;
}

void realm_smmu_attach_dev(struct arm_smmu_domain *smmu_domain,
			   struct arm_smmu_master *master, struct device *dev)
{
	int i, j;
	bool attach;
	u64 vttbr, ns_vttbr;
	struct arm_smmu_device *smmu = master->smmu;
	struct realm_smmu_device *realm = &smmu->realm;
	const struct io_pgtable_cfg *pgtbl_cfg =
		&io_pgtable_ops_to_pgtable(smmu_domain->pgtbl_ops)->cfg;

	if (!arm_smmu_support_rme(smmu))
		return;

	if (smmu_domain->stage != ARM_SMMU_DOMAIN_S2)
		return;

	if (is_realm_dev_attach(smmu_domain)) {
		smmu->realm.forward_cmd = true;
		attach = true;
	} else if (is_realm_dev_detach(smmu_domain, master))
		attach = false;
	else
		return;

	vttbr = pgtbl_cfg->realm_s2_cfg.vttbr;
	ns_vttbr = pgtbl_cfg->realm_s2_cfg.ns_vttbr;

	if (attach)
		rme_add_dev_entry(dev, vttbr, smmu_domain->realm, ns_vttbr,
				  smmu_domain->pcipc_ns);
	else
		rme_remove_dev_entry(dev);

	write_lock(&realm->fwd_lock);
	for (i = 0; i < master->num_streams; i++) {
		u32 sid = master->streams[i].id;
		/* Bridged PCI devices may end up with duplicated IDs */
		for (j = 0; j < i; j++)
			if (master->streams[j].id == sid)
				break;
		if (j < i)
			continue;

		if (attach)
			bitmap_set(realm->sid_bitmap, sid, 1);
		else
			bitmap_clear(realm->sid_bitmap, sid, 1);
	}

	if (attach)
		bitmap_set(realm->vmid_bitmap, smmu_domain->s2_cfg.vmid, 1);

	write_unlock(&realm->fwd_lock);
}

void realm_smmu_domain_clear(struct arm_smmu_domain *smmu_domain)
{
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (!arm_smmu_support_rme(smmu))
		return;

	write_lock(&smmu->realm.fwd_lock);
	bitmap_clear(smmu->realm.vmid_bitmap, smmu_domain->s2_cfg.vmid, 1);
	write_unlock(&smmu->realm.fwd_lock);
}

static bool is_realm_sid(struct arm_smmu_device *smmu, u32 sid)
{
	struct realm_smmu_device *realm = &smmu->realm;
	bool ret;

	read_lock(&realm->fwd_lock);
	ret = bitmap_read(realm->sid_bitmap, sid, 1);
	read_unlock(&realm->fwd_lock);

	return ret;
}

static bool is_realm_vmid(struct arm_smmu_device *smmu, u32 vmid)
{
	struct realm_smmu_device *realm = &smmu->realm;
	bool ret;

	read_lock(&realm->fwd_lock);
	ret = bitmap_read(realm->vmid_bitmap, vmid, 1);
	read_unlock(&realm->fwd_lock);

	return ret;
}

static bool realm_smmu_need_forward(struct arm_smmu_device *smmu, u64 cmd0, u64 cm1)
{
	u64 opcode = FIELD_GET(CMDQ_0_OP, cmd0);

	switch (opcode) {
	case CMDQ_OP_TLBI_EL2_ALL:
	case CMDQ_OP_TLBI_NSNH_ALL:
		return true;
	case CMDQ_OP_PREFETCH_CFG:
	case CMDQ_OP_CFGI_CD:
	case CMDQ_OP_CFGI_STE:
	case CMDQ_OP_CFGI_CD_ALL:
		return is_realm_sid(smmu, FIELD_GET(CMDQ_CFGI_0_SID, cmd0));
	case CMDQ_OP_CFGI_ALL:
		return true;
	case CMDQ_OP_TLBI_NH_VA:
	case CMDQ_OP_TLBI_S2_IPA:
	case CMDQ_OP_TLBI_NH_ASID:
	case CMDQ_OP_TLBI_S12_VMALL:
		return is_realm_vmid(smmu, FIELD_GET(CMDQ_TLBI_0_VMID, cmd0));
	case CMDQ_OP_ATC_INV:
		return is_realm_sid(smmu, FIELD_GET(CMDQ_ATC_0_SID, cmd0));
	case CMDQ_OP_PRI_RESP:
		return is_realm_sid(smmu, FIELD_GET(CMDQ_PRI_0_SID, cmd0));
	case CMDQ_OP_RESUME:
		return is_realm_sid(smmu, FIELD_GET(CMDQ_RESUME_0_SID, cmd0));
	case CMDQ_OP_CMD_SYNC:
		return false;
	default:
		break;
	}

	return false;
}

int realm_smmu_cmdq_issue_cmdlist(struct arm_smmu_device *smmu, u64 *cmds,
				  int n, bool sync)
{
	int i, ret;
	u64 *rcmds;
	u64 cmd0, cmd1;
	u32 forward_cnt = 0;

	if (!arm_smmu_support_rme(smmu))
		return 0;

	if (n * CMDQ_ENT_DWORDS * sizeof(*cmds) > PAGE_SIZE) {
		dev_err(smmu->dev, "cmdq batch too large\n");
		return -EINVAL;
	}

	rcmds = (u64 *)get_zeroed_page(GFP_KERNEL);
	if (!rcmds)
		return -ENOMEM;

	for (i = 0; i < n; i++) {
		cmd0 = cmds[i * CMDQ_ENT_DWORDS];
		cmd1 = cmds[i * CMDQ_ENT_DWORDS + 1];
		if (realm_smmu_need_forward(smmu, cmd0, cmd1)) {
			rcmds[forward_cnt * CMDQ_ENT_DWORDS] = cmd0;
			rcmds[forward_cnt * CMDQ_ENT_DWORDS + 1] = cmd1;
			forward_cnt++;
		}
	}

	if (!forward_cnt) {
		free_page((unsigned long)rcmds);
		return 0;
	}

	ret = rmi_smmu_send_cmdlist(smmu->realm.ioaddr, virt_to_phys(rcmds),
				    forward_cnt, sync);
	if (ret)
		dev_err(smmu->dev, "issue realm cmd failed\n");

	free_page((unsigned long)rcmds);

	return ret;
}

static int realm_smmu_init_queue(struct arm_smmu_device *smmu,
				 struct realm_smmu_queue *q, int ent_dwords,
				 int queue_type, const char *name)
{
	__le64 *base;
	size_t qsz;
	int ret;

	do {
		qsz = ((1 << q->max_n_shift) * ent_dwords) << 3;
		base = dma_alloc_coherent(smmu->dev, qsz, &q->base_dma,
					      GFP_KERNEL);
		if (base || qsz < PAGE_SIZE)
			break;

		q->max_n_shift--;
	} while (1);

	if (!base) {
		dev_err(smmu->dev,
			"failed to allocate queue (0x%zx bytes) for %s\n",
			qsz, name);
		return -ENOMEM;
	}

	if (!WARN_ON(q->base_dma & (qsz - 1))) {
		dev_info(smmu->dev, "allocated %u entries for %s\n",
			 1 << q->max_n_shift, name);
	}

	ret = granule_delegate_range(q->base_dma, qsz);
	if (ret)
		goto out_free;

	ret = realm_config_queue(SMMU_QUEUE_INIT, smmu->realm.ioaddr,
				 queue_type, q->base_dma, q->max_n_shift);
	if (ret)
		goto out_undelegate;

	q->base = base;
	return 0;

out_undelegate:
	if (WARN_ON(granule_undelegate_range(q->base_dma, qsz)))
		return ret;
out_free:
	dma_free_coherent(smmu->dev, qsz, q->base, q->base_dma);
	return ret;
}

static int realm_smmu_init_strtab_2lvl(struct arm_smmu_device *smmu)
{
	int ret;
	void *strtab;
	struct realm_smmu_strtab_cfg *cfg = &smmu->realm.strtab_cfg;
	size_t l1size = cfg->num_l1_ents * (STRTAB_L1_DESC_DWORDS << 3);

	strtab = dma_alloc_coherent(smmu->dev, l1size, &cfg->strtab_dma,
				    GFP_KERNEL);
	if (!strtab)
		return -ENOMEM;

	ret = granule_delegate_range(cfg->strtab_dma, l1size);
	if (ret)
		goto out_free_strtab;

	cfg->l1_desc = kcalloc(cfg->num_l1_ents, sizeof(*cfg->l1_desc),
			       GFP_KERNEL);
	if (!cfg->l1_desc) {
		ret = -ENOMEM;
		goto out_undelegate;
	}

	ret = realm_config_strtab(SMMU_STRTAB_INIT, smmu->realm.ioaddr,
				  cfg->strtab_dma, cfg->strtab_base_cfg);
	if (ret) {
		dev_err(smmu->dev, "failed to init realm linear strtab\n");
		goto out_free_l1_desc;
	}

	cfg->strtab.l1_desc = strtab;

	return 0;

out_free_l1_desc:
	kfree(cfg->l1_desc);
out_undelegate:
	if (WARN_ON(granule_undelegate_range(cfg->strtab_dma, l1size)))
		return ret;
out_free_strtab:
	dma_free_coherent(smmu->dev, l1size, strtab, cfg->strtab_dma);
	return ret;
}

static int realm_smmu_init_strtab_linear(struct arm_smmu_device *smmu)
{
	int ret;
	void *strtab;
	struct realm_smmu_strtab_cfg *cfg = &smmu->realm.strtab_cfg;
	size_t l1size = (1 << smmu->sid_bits) * sizeof(cfg->strtab.linear[0]);

	strtab = dma_alloc_coherent(smmu->dev, l1size, &cfg->strtab_dma,
				    GFP_KERNEL);
	if (!strtab)
		return -ENOMEM;

	ret = granule_delegate_range(cfg->strtab_dma, l1size);
	if (ret)
		goto out_free;

	ret = realm_config_strtab(SMMU_STRTAB_INIT, smmu->realm.ioaddr,
				  cfg->strtab_dma, cfg->strtab_base_cfg);
	if (ret) {
		dev_err(smmu->dev, "failed to init realm linear strtab\n");
		goto out_undelegate;
	}

	cfg->strtab.linear = strtab;
	return 0;

out_undelegate:
	if (WARN_ON(granule_undelegate_range(cfg->strtab_dma, l1size)))
		return ret;
out_free:
	dma_free_coherent(smmu->dev, l1size, strtab, cfg->strtab_dma);
	return ret;
}

static int realm_smmu_init_strtab(struct arm_smmu_device *smmu)
{
	int ret;
	u32 reg;
	struct realm_smmu_strtab_cfg *cfg = &smmu->realm.strtab_cfg;

	/* Reuse num_l1_ents and strtab_base_cfg */
	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB) {
		cfg->num_l1_ents = smmu->strtab_cfg.l2.num_l1_ents;
		reg = FIELD_PREP(STRTAB_BASE_CFG_FMT,
				 STRTAB_BASE_CFG_FMT_2LVL) |
		      FIELD_PREP(STRTAB_BASE_CFG_LOG2SIZE,
				 ilog2(cfg->num_l1_ents) + STRTAB_SPLIT) |
		      FIELD_PREP(STRTAB_BASE_CFG_SPLIT, STRTAB_SPLIT);
		cfg->strtab_base_cfg = reg;
		ret = realm_smmu_init_strtab_2lvl(smmu);
	} else {
		cfg->num_l1_ents = smmu->strtab_cfg.linear.num_ents;
		reg = FIELD_PREP(STRTAB_BASE_CFG_FMT,
				 STRTAB_BASE_CFG_FMT_LINEAR) |
		      FIELD_PREP(STRTAB_BASE_CFG_LOG2SIZE, smmu->sid_bits);
		cfg->strtab_base_cfg = reg;
		ret = realm_smmu_init_strtab_linear(smmu);
	}

	return ret;
}

static irqreturn_t arm_r_smmu_revtq_thread(int irq, void *dev)
{
	int i, ret;
	struct arm_smmu_device *smmu = dev;
	static DEFINE_RATELIMIT_STATE(rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	u64 evt[EVTQ_ENT_DWORDS];
	u8 id;

	do {
		ret = rmi_smmu_read_event(smmu->realm.ioaddr, evt);
		if (ret)
			break;

		id = FIELD_GET(EVTQ_0_ID, evt[0]);
		if (!__ratelimit(&rs))
			continue;

		dev_info(smmu->dev, "event 0x%02x received:\n", id);
		for (i = 0; i < ARRAY_SIZE(evt); ++i)
			dev_info(smmu->dev, "\t0x%016llx\n",
					(unsigned long long)evt[i]);
		cond_resched();
	} while (true);

	return IRQ_HANDLED;
}

static irqreturn_t arm_smmu_realm_gerror_handler(int irq, void *dev)
{
	u32 gerror, gerrorn, active;
	struct arm_smmu_device *smmu = dev;
	int ret;

	ret = rmi_smmu_reg_read32(smmu->realm.ioaddr, SMMU_R_GERROR, &gerror);
	if (ret) {
		dev_err(smmu->dev, "R_SMMU: Cannot read gerror\n");
		return IRQ_HANDLED;
	}

	ret = rmi_smmu_reg_read32(smmu->realm.ioaddr, SMMU_R_GERRORN, &gerrorn);
	if (ret) {
		dev_err(smmu->dev, "R_SMMU: Cannot read gerrorn\n");
		return IRQ_HANDLED;
	}

	active = gerror ^ gerrorn;
	if (!(active & GERROR_ERR_MASK))
		return IRQ_NONE; /* No errors pending */

	dev_warn(smmu->dev,
		 "R_SMMU: unexpected global error reported (0x%08x), this could be serious\n",
		 active);

	if (active & GERROR_SFM_ERR)
		dev_err(smmu->dev, "R_SMMU: device has entered Service Failure Mode!\n");

	if (active & GERROR_MSI_GERROR_ABT_ERR)
		dev_warn(smmu->dev, "R_SMMU: GERROR MSI write aborted\n");

	if (active & GERROR_MSI_PRIQ_ABT_ERR)
		dev_warn(smmu->dev, "R_SMMU: PRIQ MSI write aborted\n");

	if (active & GERROR_MSI_EVTQ_ABT_ERR)
		dev_warn(smmu->dev, "R_SMMU: EVTQ MSI write aborted\n");

	if (active & GERROR_MSI_CMDQ_ABT_ERR)
		dev_warn(smmu->dev, "R_SMMU: CMDQ MSI write aborted\n");

	if (active & GERROR_PRIQ_ABT_ERR)
		dev_err(smmu->dev, "R_SMMU: PRIQ write aborted -- events may have been lost\n");

	if (active & GERROR_EVTQ_ABT_ERR)
		dev_err(smmu->dev, "R_SMMU: EVTQ write aborted -- events may have been lost\n");

	if (active & GERROR_CMDQ_ERR)
		dev_err(smmu->dev, "R_SMMU: cmdq err\n");

	ret = rmi_smmu_reg_write32(smmu->realm.ioaddr, SMMU_R_GERRORN, gerror);
	if (ret)
		dev_err(smmu->dev, "R_SMMU: Cannot write gerrorn\n");

	return IRQ_HANDLED;
}

static void realm_smmu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	struct device *dev = msi_desc_to_dev(desc);
	struct arm_smmu_device *smmu = dev_get_drvdata(dev);
	u32 mem_attr = ARM_SMMU_MEMATTR_DEVICE_nGnRE;
	phys_addr_t doorbell;
	phys_addr_t *cfg;
	int ret;

	doorbell = (((u64)msg->address_hi) << 32) | msg->address_lo;
	doorbell &= MSI_CFG0_ADDR_MASK;
	doorbell |= MSI_CFG0_NS;

#ifdef CONFIG_ARM_SMMU_V3_PM
	/* Saves the msg (base addr of msi irq) and restores it during resume */
	desc->msg.address_lo = msg->address_lo;
	desc->msg.address_hi = msg->address_hi;
	desc->msg.data = msg->data;
#endif

	if (desc->msi_index != R_EVTQ_MSI_INDEX && desc->msi_index != R_GERROR_MSI_INDEX) {
		dev_err(dev, "Unsupport msi_index : %u\n", desc->msi_index);
		return;
	}

	cfg = arm_r_smmu_msi_cfg[desc->msi_index];

	ret = rmi_smmu_reg_write64(smmu->realm.ioaddr, cfg[0], doorbell);
	if (ret) {
		dev_err(dev, "Unable to write msi doorbell to %#llx\n", cfg[0]);
		return;
	}

	ret = rmi_smmu_reg_write32(smmu->realm.ioaddr, cfg[1], msg->data);
	if (ret) {
		dev_err(dev, "Unable to write msi data to %#llx\n", cfg[1]);
		return;
	}

	ret = rmi_smmu_reg_write32(smmu->realm.ioaddr, cfg[2], mem_attr);
	if (ret) {
		dev_err(dev, "Unable to write msi attr to %#llx\n", cfg[2]);
		return;
	}
}

static void realm_smmu_setup_msis(struct arm_smmu_device *smmu)
{
	int ret;
	struct device *dev = smmu->dev;

	ret = platform_msi_domain_alloc_range_irqs(dev, R_EVTQ_MSI_INDEX,
		R_GERROR_MSI_INDEX, realm_smmu_write_msi_msg);
	if (ret) {
		dev_warn(dev, "R_SMMU: failed to allocate msis\n");
		return;
	}

	smmu->realm.revtq.irq = msi_get_virq(dev, R_EVTQ_MSI_INDEX);
	smmu->realm.rgerr_irq = msi_get_virq(dev, R_GERROR_MSI_INDEX);
}

static int realm_smmu_setup_unique_irqs(struct arm_smmu_device *smmu)
{
	int irq, ret;
	struct realm_smmu_device *realm = &smmu->realm;
	u32 irqen_flags = IRQ_CTRL_EVTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN;

	if (!realm->support_msi)
		return -EINVAL;

	/* Disable IRQs first */
	ret = realm_smmu_write_reg_sync(smmu, 0, SMMU_R_IRQ_CTRL,
					SMMU_R_IRQ_CTRLACK);
	if (ret) {
		dev_err(smmu->dev, "failed to disable realm irqs\n");
		return ret;
	}

	realm_smmu_setup_msis(smmu);

	irq = realm->revtq.irq;
	if (irq) {
		ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
						arm_r_smmu_revtq_thread,
						IRQF_ONESHOT,
						"arm-smmu-v3-revtq", smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable evtq irq\n");
	} else {
		dev_warn(smmu->dev, "no revtq irq - events will not be reported!\n");
	}

	irq = realm->rgerr_irq;
	if (irq) {
		ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
						arm_smmu_realm_gerror_handler,
						IRQF_ONESHOT,
						"arm-smmu-v3-rgerror", smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable gerror irq\n");
	} else {
		dev_warn(smmu->dev, "no rgerr irq - errors will not be reported!\n");
	}

	/* Enable interrupt generation on the realm smmu */
	ret = realm_smmu_write_reg_sync(smmu, irqen_flags, SMMU_R_IRQ_CTRL,
					SMMU_R_IRQ_CTRLACK);
	if (ret)
		dev_warn(smmu->dev, "failed to enable realm irqs\n");

	return 0;
}

void arm_r_smmu_device_init(struct arm_smmu_device *smmu, resource_size_t ioaddr)
{
	int ret;
	u32 idr0, enables = 0;
	struct realm_smmu_device *realm = &smmu->realm;

	if (!is_support_rme() || is_realm_world())
		return;

	ret = rmi_smmu_reg_read32(ioaddr, SMMU_R_IDR0, &idr0);
	if (ret)
		return;

	realm->ioaddr = ioaddr;
	if (idr0 & R_IDR0_MSI)
		realm->support_msi = true;

	if (smmu->features & ARM_SMMU_FEAT_E2H) {
		ret = rmi_smmu_reg_write32(ioaddr, SMMU_R_CR2, CR2_E2H);
		if (ret) {
			dev_err(smmu->dev, "failed to write realm SMMU_R_CR2\n");
			return;
		}
	}

	realm->sid_bitmap = devm_bitmap_zalloc(smmu->dev, 1 << smmu->sid_bits,
					       GFP_KERNEL);
	if (!realm->sid_bitmap)
		return;

	realm->vmid_bitmap = devm_bitmap_zalloc(smmu->dev, 1 << smmu->vmid_bits,
						GFP_KERNEL);
	if (!realm->vmid_bitmap)
		return;

	rwlock_init(&realm->fwd_lock);

	realm->rcmdq.max_n_shift = smmu->cmdq.q.llq.max_n_shift;
	/* realm cmdq */
	ret = realm_smmu_init_queue(smmu, &realm->rcmdq, CMDQ_ENT_DWORDS,
				    SMMU_R_CMDQ, "rcmdq");
	if (ret)
		goto err_remove_device;

	/* If SMMU support ATS, SMMU-R should enable ATSCHK */
	if (idr0 & IDR0_ATS)
		enables |= CR0_ATSCHK;

	enables |= CR0_CMDQEN;
	ret = realm_smmu_write_reg_sync(smmu, enables, SMMU_R_CR0, SMMU_R_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable realm command queue\n");
		goto err_remove_device;
	}

	realm->revtq.max_n_shift = smmu->evtq.q.llq.max_n_shift;
	/* realm evtq */
	ret = realm_smmu_init_queue(smmu, &realm->revtq, EVTQ_ENT_DWORDS,
				    SMMU_R_EVTQ, "revtq");
	if (ret)
		goto err_remove_device;

	enables |= CR0_EVTQEN;
	ret = realm_smmu_write_reg_sync(smmu, enables, SMMU_R_CR0, SMMU_R_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable realm event queue\n");
		goto err_remove_device;
	}

	ret = realm_smmu_init_strtab(smmu);
	if (ret)
		goto err_remove_device;

	ret = realm_smmu_setup_unique_irqs(smmu);
	if (ret) {
		dev_err(smmu->dev, "RME failed to setup irqs\n");
		goto err_remove_device;
	}

	if (is_kdump_kernel())
		enables &= ~CR0_EVTQEN;

	/* Enable the SMMU interface */
	enables |= CR0_SMMUEN;

	ret = realm_smmu_write_reg_sync(smmu, enables, SMMU_R_CR0, SMMU_R_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable realm smmu interface\n");
		goto err_remove_device;
	}

	realm->enabled = true;
	return;

err_remove_device:
	arm_r_smmu_device_remove(smmu);
}

static void arm_r_smmu_free_l2_strtab(struct arm_smmu_device *smmu,
				      struct realm_smmu_strtab_cfg *cfg)
{
	size_t size = (1 << STRTAB_SPLIT) * sizeof(struct arm_smmu_ste);
	struct arm_smmu_strtab_l1_desc *desc;
	unsigned int i;

	if (!cfg->l1_desc)
		return;

	for (i = 0; i < cfg->num_l1_ents; i++) {
		desc = &cfg->l1_desc[i];
		if (!desc->l2ptr)
			continue;
		realm_config_strtab_l2(SMMU_STRTAB_L2_DEINIT,
				       smmu->realm.ioaddr, cfg->strtab_dma,
				       i, desc->l2ptr_dma, desc->span);
		if (WARN_ON(granule_undelegate_range(desc->l2ptr_dma, size)))
			continue;
		dma_free_coherent(smmu->dev, size, desc->l2ptr, desc->l2ptr_dma);
	}
	kfree(cfg->l1_desc);
}

void arm_r_smmu_device_remove(struct arm_smmu_device *smmu)
{
	size_t l1size, qsz;
	struct realm_smmu_queue *q;
	unsigned long ioaddr = smmu->realm.ioaddr;
	struct realm_smmu_device *realm = &smmu->realm;
	struct realm_smmu_strtab_cfg *cfg = &realm->strtab_cfg;

	if (!is_support_rme() || is_realm_world())
		return;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB) {
		l1size = cfg->num_l1_ents * (STRTAB_L1_DESC_DWORDS << 3);
		arm_r_smmu_free_l2_strtab(smmu, cfg);
	} else {
		l1size = cfg->num_l1_ents * sizeof(cfg->strtab.linear[0]);
	}

	if (cfg->strtab.linear) {
		realm_config_strtab(SMMU_STRTAB_DEINIT, ioaddr, cfg->strtab_dma,
				    cfg->strtab_base_cfg);
		if (!WARN_ON(granule_undelegate_range(cfg->strtab_dma, l1size)))
			dma_free_coherent(smmu->dev, l1size, cfg->strtab.linear,
					  cfg->strtab_dma);
	}

	if (realm->rcmdq.base) {
		q = &realm->rcmdq;
		realm_config_queue(SMMU_QUEUE_DEINIT, ioaddr, SMMU_R_CMDQ,
				   q->base_dma, q->max_n_shift);
		qsz = ((1 << q->max_n_shift) * CMDQ_ENT_DWORDS) << 3;
		if (!WARN_ON(granule_undelegate_range(q->base_dma, qsz)))
			dma_free_coherent(smmu->dev, qsz, q->base, q->base_dma);
	}

	if (realm->revtq.base) {
		q = &realm->revtq;
		realm_config_queue(SMMU_QUEUE_DEINIT, ioaddr, SMMU_R_EVTQ,
				   q->base_dma, q->max_n_shift);
		qsz = ((1 << q->max_n_shift) * EVTQ_ENT_DWORDS) << 3;
		if (!WARN_ON(granule_undelegate_range(q->base_dma, qsz)))
			dma_free_coherent(smmu->dev, qsz, q->base, q->base_dma);
	}
}
