/* SPDX-License-Identifier: GPL-2.0 */
/*
 * VIP-SMT support for ARM64
 *
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 */

#ifndef __ASM_VIP_SMT_H
#define __ASM_VIP_SMT_H

#include <linux/types.h>
#include <linux/cpumask.h>
#include <asm/cpu.h>

#ifdef CONFIG_ARM64_VIP_SMT

/*
 * VIP-SMT Register encodings
 * Format: sys_reg(Op0, Op1, CRn, CRm, Op2)
 */
#define sys_ifu_actlr1			sys_reg(3, 1, 15, 4, 0)
#define sys_ooo_dec_rob_sha_ctlr	sys_reg(3, 1, 15, 8, 6)
#define sys_ooo_dec_dsp_ctlr		sys_reg(3, 1, 15, 2, 5)

/*
 * IFU_ACTLR1_EL1 bit definitions (only defined bits can be accessed)
 */
#define IFU_ACTLR1_IMPL_SMT_QOS_SCH1_EN		(UL(0x1) << (63))
#define IFU_ACTLR1_IMPL_SMT_QOS_SCH1_THR_SHIFT	(59)
#define IFU_ACTLR1_IMPL_SMT_QOS_SCH1_THR_MASK	GENMASK_ULL(62, 59)
#define IFU_ACTLR1_IMPL_SMT_QOS_SCH2_EN		(UL(0x1) << (58))
#define IFU_ACTLR1_IMPL_SMT_QOS_SCH2_PLUS_EN	(UL(0x1) << (57))
#define IFU_ACTLR1_IMPL_SMT_QOS_SCH2_THR_SHIFT	(49)
#define IFU_ACTLR1_IMPL_SMT_QOS_SCH2_THR_MASK	GENMASK_ULL(56, 49)
#define IFU_ACTLR1_IMPL_SMT_QOS_SCH2_TWICE_EN	(UL(0x1) << (48))
#define ifu_actlr1_allow_mask	(IFU_ACTLR1_IMPL_SMT_QOS_SCH1_EN |	\
				 IFU_ACTLR1_IMPL_SMT_QOS_SCH1_THR_MASK |\
				 IFU_ACTLR1_IMPL_SMT_QOS_SCH2_EN |	\
				 IFU_ACTLR1_IMPL_SMT_QOS_SCH2_PLUS_EN |	\
				 IFU_ACTLR1_IMPL_SMT_QOS_SCH2_THR_MASK |\
				 IFU_ACTLR1_IMPL_SMT_QOS_SCH2_TWICE_EN)

/*
 * OOO_DEC_ROB_SHA_CTLR_EL1 bit definitions
 */
#define OOO_DEC_ROB_SHA_CTLR_OOO_DEC_SMT_QOS_TSLOT_EN	(UL(0x1) << (59))
#define OOO_DEC_ROB_SHA_CTLR_OOO_ROB_STARVE_QOS_THRED_SHIFT	(57)
#define OOO_DEC_ROB_SHA_CTLR_OOO_ROB_STARVE_QOS_THRED_MASK	GENMASK_ULL(58, 57)
#define OOO_DEC_ROB_SHA_CTLR_OOO_ROB_STARVE_QOS_SAFE_MODE	(UL(0x1) << (56))
#define OOO_DEC_ROB_SHA_CTLR_OOO_DEV_QOS_MODEL_SEL		(UL(0x1) << (55))
#define OOO_DEC_ROB_SHA_CTLR_OOO_FRC_IFU_THREAD_RR		(UL(0x1) << (50))
#define ooo_dec_rob_sha_ctlr_allow_mask	(OOO_DEC_ROB_SHA_CTLR_OOO_DEC_SMT_QOS_TSLOT_EN |	\
					 OOO_DEC_ROB_SHA_CTLR_OOO_ROB_STARVE_QOS_THRED_MASK |	\
					 OOO_DEC_ROB_SHA_CTLR_OOO_ROB_STARVE_QOS_SAFE_MODE |	\
					 OOO_DEC_ROB_SHA_CTLR_OOO_DEV_QOS_MODEL_SEL |		\
					 OOO_DEC_ROB_SHA_CTLR_OOO_FRC_IFU_THREAD_RR)

/*
 * OOO_DEC_DSP_CTLR_EL1 bit definitions
 */
#define OOO_DEC_DSP_CTLR_OOO_DSP_THRESHOLD		(UL(0x1) << (63))
#define OOO_DEC_DSP_CTLR_OOO_ISSQ_THRESHOLD_ISU_SHIFT	(49)
#define OOO_DEC_DSP_CTLR_OOO_ISSQ_THRESHOLD_ISU_MASK	GENMASK_ULL(51, 49)
#define OOO_DEC_DSP_CTLR_OOO_ISSQ_THRESHOLD_ALU_SHIFT	(46)
#define OOO_DEC_DSP_CTLR_OOO_ISSQ_THRESHOLD_ALU_MASK	GENMASK_ULL(48, 46)
#define OOO_DEC_DSP_CTLR_OOO_SMT_QOS_EN			(UL(0x1) << (37))
#define OOO_DEC_DSP_CTLR_OOO_DEC_THREAD_CYCLE_FRC_SHIFT	(32)
#define OOO_DEC_DSP_CTLR_OOO_DEC_THREAD_CYCLE_FRC_MASK	GENMASK_ULL(33, 32)
#define OOO_DEC_DSP_CTLR_OOO_DEC_ICOUNT_CFG_SHIFT		(30)
#define OOO_DEC_DSP_CTLR_OOO_DEC_ICOUNT_CFG_MASK		GENMASK_ULL(31, 30)
#define ooo_dec_dsp_ctlr_allow_mask	(OOO_DEC_DSP_CTLR_OOO_DSP_THRESHOLD |		\
				 OOO_DEC_DSP_CTLR_OOO_ISSQ_THRESHOLD_ISU_MASK |	\
				 OOO_DEC_DSP_CTLR_OOO_ISSQ_THRESHOLD_ALU_MASK |	\
				 OOO_DEC_DSP_CTLR_OOO_SMT_QOS_EN |			\
				 OOO_DEC_DSP_CTLR_OOO_DEC_THREAD_CYCLE_FRC_MASK |	\
				 OOO_DEC_DSP_CTLR_OOO_DEC_ICOUNT_CFG_MASK)

/*
 * Field definition for sysfs interface
 * Used to parse FIELD_NAME=value format input
 */
struct vip_smt_field {
	const char *name;	/* Field name, e.g., "SCH1_EN" */
	u64 bitmask;		/* Corresponding bitmask */
};

/*
 * VIP-SMT control states
 */
enum vip_smt_control {
	VIP_SMT_ENABLED,
	VIP_SMT_DISABLED,
	VIP_SMT_FORCE_DISABLED,
};

/*
 * API functions
 */
bool vip_smt_available(void);
int vip_smt_cpu_sysfs_create(unsigned int cpu, struct cpuinfo_arm64 *info);
bool has_vip_smt_support(const struct arm64_cpu_capabilities *entry, int __unused);
void vip_smt_enter_idle(void);
void vip_smt_exit_idle(void);
#else
static inline void vip_smt_enter_idle(void) { }
static inline void vip_smt_exit_idle(void) { }
#endif /* CONFIG_ARM64_VIP_SMT */

#endif /* __ASM_VIP_SMT_H */
