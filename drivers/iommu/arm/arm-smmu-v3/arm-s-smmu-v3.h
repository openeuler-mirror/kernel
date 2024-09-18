/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#ifndef _ARM_S_SMMU_V3_H
#define _ARM_S_SMMU_V3_H
#ifdef CONFIG_HISI_VIRTCCA_HOST

#include <linux/platform_device.h>
#include <asm/kvm_tmi.h>
#include <asm/virtcca_cvm_host.h>

#define MAX_CC_DEV_NUM_ORDER    8
#define MASK_DEV_FUNCTION       0xfff8
#define MASK_DEV_BUS            0xff

#define DEV_BUS_NUM             0x8
#define DEV_FUNCTION_NUM        0x3

#define STE_ENTRY_SIZE          0x40

#define SMMU_PCIE_CORE_IS_VALID 0x1

#define ARM_S_SMMU_MAX_IDS      (1 << 5)
#define ARM_S_SMMU_INVALID_ID   0
#define ARM_S_SMMU_MAX_CFGS     0x3

#define ARM_S_SMMU_CMD_COUNT          0x2
#define ARM_S_QUEUE_SHIFT_SIZE        0x3
#define ARM_S_SMMU_MASK_UPPER_32_BIT  0xffffffff

#define ARM_S_SMMU_REG_32_BIT   0x20
#define ARM_S_SMMU_REG_64_BIT   0x40

/* Secure MMIO registers */
#define ARM_SMMU_S_IDR0         0x8000
#define S_IDR0_STALL_MODEL      GENMASK(25, 24)
#define S_IDR0_ECMDQ            (1 << 31)
#define S_IDR0_MSI              (1 << 13)

#define ARM_SMMU_S_IDR1         0x8004
#define S_IDR1_SECURE_IMPL      (1 << 31)
#define S_IDR1_SEL2             (1 << 29)
#define S_IDR1_SIDSIZE          GENMASK(5, 0)

#define ARM_SMMU_S_IDR3         0x800c
#define S_IDR3_SAMS             (1 << 6)

#define ARM_SMMU_S_CR0          0x8020
#define S_CR0_SIF               (1 << 9)
#define S_CR0_NSSTALLD          (1 << 5)
#define S_CR0_CMDQEN            (1 << 3)
#define S_CR0_EVTQEN            (1 << 2)
#define S_CR0_SMMUEN            (1 << 0)

#define ARM_SMMU_S_CR0ACK       0x8024

#define ARM_SMMU_S_CR1          0x8028
#define S_CR1_TABLE_SH          GENMASK(11, 10)
#define S_CR1_TABLE_OC          GENMASK(9, 8)
#define S_CR1_TABLE_IC          GENMASK(7, 6)
#define S_CR1_QUEUE_SH          GENMASK(5, 4)
#define S_CR1_QUEUE_OC          GENMASK(3, 2)
#define S_CR1_QUEUE_IC          GENMASK(1, 0)

/* S_CR1 cacheability fields don't quite follow the usual TCR-style encoding */
#define S_CR1_CACHE_NC          0
#define S_CR1_CACHE_WB          1
#define S_CR1_CACHE_WT          2

#define ARM_SMMU_S_CR2          0x802c
#define S_CR2_PTM               (1 << 2)
#define S_CR2_RECINVSID         (1 << 1)
#define S_CR2_E2H               (1 << 0)

#define ARM_SMMU_S_INIT         U(0x803c)
/* SMMU_S_INIT register fields */
#define SMMU_S_INIT_INV_ALL     (1UL << 0)

#define ARM_SMMU_S_GBPA         0x8044
#define S_GBPA_UPDATE           (1 << 31)
#define S_GBPA_ABORT            (1 << 20)

#define ARM_SMMU_S_IRQ_CTRL     0x8050
#define S_IRQ_CTRL_EVTQ_IRQEN   (1 << 2)
#define S_IRQ_CTRL_GERROR_IRQEN (1 << 0)

#define ARM_SMMU_S_IRQ_CTRLACK      0x8054

#define ARM_SMMU_S_GERROR           0x8060
#define S_GERROR_SFM_ERR            (1 << 8)
#define S_GERROR_MSI_GERROR_ABT_ERR (1 << 7)
#define S_GERROR_MSI_EVTQ_ABT_ERR   (1 << 5)
#define S_GERROR_MSI_CMDQ_ABT_ERR   (1 << 4)
#define S_GERROR_EVTQ_ABT_ERR       (1 << 2)
#define S_GERROR_CMDQ_ERR           (1 << 0)

#define ARM_SMMU_S_GERRORN          0x8064

#define ARM_SMMU_S_GERROR_IRQ_CFG0  0x8068
#define ARM_SMMU_S_GERROR_IRQ_CFG1  0x8070
#define ARM_SMMU_S_GERROR_IRQ_CFG2  0x8074

#define ARM_SMMU_S_STRTAB_BASE      0x8080
#define S_STRTAB_BASE_RA_SHIFT      62
#define S_STRTAB_BASE_RA            (1UL << S_STRTAB_BASE_RA_SHIFT)
#define S_STRTAB_BASE_ADDR_MASK     GENMASK_ULL(51, 6)

#define ARM_SMMU_S_STRTAB_BASE_CFG  0x8088
#define S_STRTAB_BASE_CFG_FMT       GENMASK(17, 16)
#define S_STRTAB_BASE_CFG_SPLIT     GENMASK(10, 6)
#define S_STRTAB_BASE_CFG_LOG2SIZE  GENMASK(5, 0)

#define ARM_SMMU_S_CMDQ_BASE        0x8090
#define ARM_SMMU_S_CMDQ_PROD        0x8098
#define ARM_SMMU_S_CMDQ_CONS        0x809c
#define S_CMDQ_BASE_ADDR_MASK       GENMASK_ULL(51, 5)
#define S_CMDQ_BASE_RA_SHIFT        62

#define ARM_SMMU_S_EVTQ_BASE        0x80a0
#define ARM_SMMU_S_EVTQ_PROD        0x80a8
#define ARM_SMMU_S_EVTQ_CONS        0x80ac
#define ARM_SMMU_S_EVTQ_IRQ_CFG0    0x80b0
#define ARM_SMMU_S_EVTQ_IRQ_CFG1    0x80b8
#define ARM_SMMU_S_EVTQ_IRQ_CFG2    0x80bc
#define S_EVTQ_BASE_ADDR_MASK       GENMASK_ULL(51, 5)
#define S_EVTQ_BASE_WA_SHIFT        62

/*
 * BIT1 is PRIQEN, BIT4 is ATSCHK in SMMU_CRO
 * BIT1 and BIT4 are RES0 in SMMU_S_CRO
 */
#define SMMU_S_CR0_RESERVED 0xFFFFFC12

#define virtcca_cvm_read_poll_timeout_atomic(op, val, cond, delay_us, timeout_us, \
					delay_before_read, args...) \
({ \
	u64 __timeout_us = (timeout_us); \
	u64 rv = 0; \
	int result = 0; \
	unsigned long __delay_us = (delay_us); \
	ktime_t __timeout = ktime_add_us(ktime_get(), __timeout_us); \
	if (delay_before_read && __delay_us) \
		udelay(__delay_us); \
	for (;;) { \
		rv = op(args); \
		if (rv >> 32) { \
			result = -ENXIO; \
			break; \
		} \
		(val) = (u32)rv; \
		if (cond) \
			break; \
		if (__timeout_us && \
		    ktime_compare(ktime_get(), __timeout) > 0) { \
			rv = op(args); \
			if (rv >> 32) { \
				result = -ENXIO; \
				break; \
			} \
			(val) = (u32)rv; \
			break; \
		} \
		if (__delay_us) \
			udelay(__delay_us); \
		cpu_relax(); \
	} \
	result ? result : ((cond) ? 0 : -ETIMEDOUT); \
})

/* Has the root bus device number switched to secure */
bool is_cc_dev(u32 sid);

void virtcca_smmu_cmdq_write_entries(struct arm_smmu_device *smmu, u64 *cmds,
	struct arm_smmu_ll_queue *llq, struct arm_smmu_queue *q,
	int n, bool sync);
bool virtcca_smmu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg);
u32 virtcca_smmu_tmi_dev_attach(struct arm_smmu_domain *arm_smmu_domain,
	struct kvm *kvm);
void _arm_smmu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg);
void virtcca_smmu_device_init(struct platform_device *pdev,
	struct arm_smmu_device *smmu, resource_size_t ioaddr, bool resume, bool disable_bypass);

static inline bool virtcca_smmu_enable(struct arm_smmu_device *smmu)
{
	return smmu->s_smmu_id != ARM_S_SMMU_INVALID_ID;
}


static inline void virtcca_smmu_set_irq_cfg(struct arm_smmu_device *smmu)
{
	if (tmi_smmu_write(smmu->ioaddr, ARM_SMMU_S_GERROR_IRQ_CFG0, 0, 64)) {
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		dev_err(smmu->dev, "S_SMMU: s gerror irq cfg0 failed\n");
	}
	if (tmi_smmu_write(smmu->ioaddr, ARM_SMMU_S_EVTQ_IRQ_CFG0, 0, 64)) {
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		dev_err(smmu->dev, "S_SMMU: write s evtq irq cfg0 failed\n");
	}
}

static inline void virtcca_smmu_set_stage(struct iommu_domain *domain,
	struct arm_smmu_domain *smmu_domain)
{
	if (!is_virtcca_cvm_enable())
		return;

	if (domain->secure)
		smmu_domain->stage = ARM_SMMU_DOMAIN_S2;
}
#endif
#endif /* _ARM_S_SMMU_V3_H */
