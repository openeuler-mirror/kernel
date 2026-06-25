/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, The Linux Foundation. All rights reserved.
 */

#ifndef __ASM_KVM_RME_HISI_CCA_H
#define __ASM_KVM_RME_HISI_CCA_H
#ifdef CONFIG_HISI_CCA

#include <asm/kvm_host.h>
#include <linux/kvm_host.h>

int rmi_cca_hisi_delegate_range_get(unsigned long start_addr, unsigned long size, void *realm_p);

static inline int rmi_cca_hisi_undelegate_range(unsigned long start_addr,
						unsigned long size)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_UNDELEGATE_RANGE,
		start_addr, size
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

static inline int rmi_cca_hisi_block_create(unsigned long rd,
					    unsigned long data,
					    unsigned long ipa,
					    unsigned long src,
					    unsigned long flags)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_BLOCK_DATA_CREATE,
		rd, data, ipa, src, flags
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

static inline int rmi_cca_hisi_block_create_unknown(unsigned long rd,
						    unsigned long data,
						    unsigned long ipa,
						    unsigned long level)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_BLOCK_DATA_CREATE_UNKNOWN,
		rd, data, ipa, level
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

static inline int rmi_cca_hisi_data_destroy(unsigned long rd, unsigned long ipa,
					    unsigned long *pa,
					    unsigned long *size,
					    unsigned long *granule_type,
					    unsigned long *top_ipa)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_DATA_DESTROY,
		rd, ipa
	};

	arm_smccc_1_2_smc(&regs, &regs);

	*pa = regs.a1;
	*size = regs.a2;
	*granule_type = regs.a3;
	*top_ipa = regs.a4;

	return regs.a0;
}

static inline int rmi_cca_hisi_data_destroy_level(unsigned long rd,
						  unsigned long ipa,
						  unsigned long *data_out,
						  unsigned long *top_out,
						  unsigned long *level)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_DATA_DESTROY,
		rd, ipa
	};

	arm_smccc_1_2_smc(&regs, &regs);

	if (data_out)
		*data_out = regs.a1;
	if (top_out)
		*top_out = regs.a2;
	if (level)
		*level = regs.a3;

	return regs.a0;
}

/**
 * rmi_cca_hisi_read_log() - Read RME firmware log
 * @addr:    PA of the buffer to store the log
 * @size:    Size of the log buffer
 * @mode:    Log reading mode, 0 :copy; 1 :consume
 * @out_len: Pointer to store the actual length of the log read
 *
 * Read RME firmware log into the specified buffer using SMC call.
 *
 * Return: RMI return code
 */
static inline int rmi_cca_hisi_read_log(unsigned long addr,
					unsigned long size,
					unsigned long mode,
					unsigned long *out_len)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_READ_LOG,
		addr, size, mode
	};

	arm_smccc_1_2_smc(&regs, &regs);

	if (out_len)
		*out_len = regs.a1;

	return regs.a0;
}

/**
 * rmi_cca_hisi_set_log_level() - Set log verbosity (10-ERROR to 50-VERBOSE)
 * @level:    Verbosity level [0，10, 20, 30, 40, 50]
 *
 * Set the verbosity level of RME firmware log output.
 *
 * Return: RMI return code
 */
static inline int rmi_cca_hisi_set_log_level(unsigned long level)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_SET_LOG_LEVEL, level
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_cca_hisi_set_log_mode() - Set RME firmware log output mode
 * @mode: 0-off, 1-uart, 2-buffer, 3-both
 *
 * Select the destination or behavior of RME firmware log output.
 *
 * Return: RMI return code
 */
static inline int rmi_cca_hisi_set_log_mode(unsigned long mode)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_SET_LOG_MODE, mode
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

int realm_hisi_cca_populate_region(struct kvm *kvm, phys_addr_t ipa_base,
				   phys_addr_t ipa_end, phys_addr_t *ipa_top,
				   u32 flags);

int realm_hisi_cca_map_ram(struct kvm *kvm,
			   struct arm_rme_map_ram_args *args);

void realm_hisi_cca_destroy_data_range(struct kvm *kvm, unsigned long start,
				       unsigned long end);

int realm_hisi_cca_set_ipa_state(struct kvm_vcpu *vcpu, unsigned long start,
				 unsigned long end, unsigned long ripas,
				 unsigned long *top_ipa);

void realm_hisi_cca_init_debug(void);
#endif /* CONFIG_HISI_CCA */
#endif
