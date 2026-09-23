/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#ifndef __ASM_RMI_CMDS_H
#define __ASM_RMI_CMDS_H

#include <linux/arm-smccc.h>

#include <asm/rmi_smc.h>

struct rtt_entry {
	unsigned long walk_level;
	unsigned long desc;
	int state;
	int ripas;
};

#ifdef CONFIG_HISI_CCA
bool folio_isolate_lru(struct folio *folio);

bool rme_isolate_hugetlb(struct folio *folio);
#endif

/**
 * rmi_data_create() - Create a data granule
 * @rd: PA of the RD
 * @data: PA of the target granule
 * @ipa: IPA at which the granule will be mapped in the guest
 * @src: PA of the source granule
 * @flags: RMI_MEASURE_CONTENT if the contents should be measured
 *
 * Create a new data granule, copying contents from a non-secure granule.
 *
 * Return: RMI return code
 */
static inline int rmi_data_create(unsigned long rd, unsigned long data,
				  unsigned long ipa, unsigned long src,
				  unsigned long flags)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_DATA_CREATE, rd, data, ipa, src,
			     flags, &res);

	return res.a0;
}

/**
 * rmi_data_create_unknown() - Create a data granule with unknown contents
 * @rd: PA of the RD
 * @data: PA of the target granule
 * @ipa: IPA at which the granule will be mapped in the guest
 *
 * Return: RMI return code
 */
static inline int rmi_data_create_unknown(unsigned long rd,
					  unsigned long data,
					  unsigned long ipa)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_DATA_CREATE_UNKNOWN, rd, data, ipa, &res);

	return res.a0;
}

/**
 * rmi_data_destroy() - Destroy a data granule
 * @rd: PA of the RD
 * @ipa: IPA at which the granule is mapped in the guest
 * @data_out: PA of the granule which was destroyed
 * @top_out: Top IPA of non-live RTT entries
 *
 * Unmap a protected IPA from stage 2, transitioning it to DESTROYED.
 * The IPA cannot be used by the guest unless it is transitioned to RAM again
 * by the realm guest.
 *
 * Return: RMI return code
 */
static inline int rmi_data_destroy(unsigned long rd, unsigned long ipa,
				   unsigned long *data_out,
				   unsigned long *top_out)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_DATA_DESTROY, rd, ipa, &res);

	if (data_out)
		*data_out = res.a1;
	if (top_out)
		*top_out = res.a2;

	return res.a0;
}

/**
 * rmi_features() - Read feature register
 * @index: Feature register index
 * @out: Feature register value is written to this pointer
 *
 * Return: RMI return code
 */
static inline int rmi_features(unsigned long index, unsigned long *out)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_FEATURES, index, &res);

	if (out)
		*out = res.a1;
	return res.a0;
}

int rmi_granule_delegate(unsigned long phys);

int rmi_granule_delegate_get(unsigned long phys, void *realm_p);

/**
 * rmi_granule_undelegate() - Undelegate a granule
 * @phys: PA of the granule
 *
 * Undelegate a granule to allow use by the normal world. Will fail if the
 * granule is in use.
 *
 * Return: RMI return code
 */
static inline int rmi_granule_undelegate(unsigned long phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_GRANULE_UNDELEGATE, phys, &res);

	return res.a0;
}

#define GRANULE_DELEGATE_SIZE 4096

static inline int granule_undelegate_range(unsigned long phys, size_t size)
{
	size_t off;
	int ret;

	if (!phys)
		return -EINVAL;

	for (off = 0; off < size; off += GRANULE_DELEGATE_SIZE) {
		ret = rmi_granule_undelegate(phys + off);
		if (ret)
			return ret;
	}

	return 0;
}

static inline int granule_delegate_range(unsigned long phys, size_t size)
{
	size_t off;
	int ret = 0;

	for (off = 0; off < size; off += GRANULE_DELEGATE_SIZE) {
		ret = rmi_granule_delegate(phys + off);
		if (ret)
			break;
	}

	if (ret) {
		if (off >= GRANULE_DELEGATE_SIZE)
			granule_undelegate_range(phys, off - GRANULE_DELEGATE_SIZE);
	}

	return ret;
}

/**
 * rmi_psci_complete() - Complete pending PSCI command
 * @calling_rec: PA of the calling REC
 * @target_rec: PA of the target REC
 * @status: Status of the PSCI request
 *
 * Completes a pending PSCI command which was called with an MPIDR argument, by
 * providing the corresponding REC.
 *
 * Return: RMI return code
 */
static inline int rmi_psci_complete(unsigned long calling_rec,
				    unsigned long target_rec,
				    unsigned long status)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PSCI_COMPLETE, calling_rec, target_rec,
			     status, &res);

	return res.a0;
}

/**
 * rmi_realm_activate() - Active a realm
 * @rd: PA of the RD
 *
 * Mark a realm as Active signalling that creation is complete and allowing
 * execution of the realm.
 *
 * Return: RMI return code
 */
static inline int rmi_realm_activate(unsigned long rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REALM_ACTIVATE, rd, &res);

	return res.a0;
}

/**
 * rmi_realm_create() - Create a realm
 * @rd: PA of the RD
 * @params: PA of realm parameters
 *
 * Create a new realm using the given parameters.
 *
 * Return: RMI return code
 */
static inline int rmi_realm_create(unsigned long rd, unsigned long params)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REALM_CREATE, rd, params, &res);

	return res.a0;
}

/**
 * rmi_realm_destroy() - Destroy a realm
 * @rd: PA of the RD
 *
 * Destroys a realm, all objects belonging to the realm must be destroyed first.
 *
 * Return: RMI return code
 */
static inline int rmi_realm_destroy(unsigned long rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REALM_DESTROY, rd, &res);

	return res.a0;
}

/**
 * rmi_rec_aux_count() - Get number of auxiliary granules required
 * @rd: PA of the RD
 * @aux_count: Number of granules written to this pointer
 *
 * A REC may require extra auxiliary granules to be delegated for the RMM to
 * store metadata (not visible to the normal world) in. This function provides
 * the number of granules that are required.
 *
 * Return: RMI return code
 */
static inline int rmi_rec_aux_count(unsigned long rd, unsigned long *aux_count)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REC_AUX_COUNT, rd, &res);

	if (aux_count)
		*aux_count = res.a1;
	return res.a0;
}

/**
 * rmi_rec_create() - Create a REC
 * @rd: PA of the RD
 * @rec: PA of the target REC
 * @params: PA of REC parameters
 *
 * Create a REC using the parameters specified in the struct rec_params pointed
 * to by @params.
 *
 * Return: RMI return code
 */
static inline int rmi_rec_create(unsigned long rd, unsigned long rec,
				 unsigned long params)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REC_CREATE, rd, rec, params, &res);

	return res.a0;
}

/**
 * rmi_rec_destroy() - Destroy a REC
 * @rec: PA of the target REC
 *
 * Destroys a REC. The REC must not be running.
 *
 * Return: RMI return code
 */
static inline int rmi_rec_destroy(unsigned long rec)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REC_DESTROY, rec, &res);

	return res.a0;
}

/**
 * rmi_rec_enter() - Enter a REC
 * @rec: PA of the target REC
 * @run_ptr: PA of RecRun structure
 *
 * Starts (or continues) execution within a REC.
 *
 * Return: RMI return code
 */
static inline int rmi_rec_enter(unsigned long rec, unsigned long run_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REC_ENTER, rec, run_ptr, &res);

	return res.a0;
}

/**
 * rmi_rtt_create() - Creates an RTT
 * @rd: PA of the RD
 * @rtt: PA of the target RTT
 * @ipa: Base of the IPA range described by the RTT
 * @level: Depth of the RTT within the tree
 *
 * Creates an RTT (Realm Translation Table) at the specified level for the
 * translation of the specified address within the realm.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_create(unsigned long rd, unsigned long rtt,
				 unsigned long ipa, long level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_CREATE, rd, rtt, ipa, level, &res);

	return res.a0;
}

/**
 * rmi_rtt_destroy() - Destroy an RTT
 * @rd: PA of the RD
 * @ipa: Base of the IPA range described by the RTT
 * @level: Depth of the RTT within the tree
 * @out_rtt: Pointer to write the PA of the RTT which was destroyed
 * @out_top: Pointer to write the top IPA of non-live RTT entries
 *
 * Destroys an RTT. The RTT must be non-live, i.e. none of the entries in the
 * table are in ASSIGNED or TABLE state.
 *
 * Return: RMI return code.
 */
static inline int rmi_rtt_destroy(unsigned long rd,
				  unsigned long ipa,
				  long level,
				  unsigned long *out_rtt,
				  unsigned long *out_top)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_DESTROY, rd, ipa, level, &res);

	if (out_rtt)
		*out_rtt = res.a1;
	if (out_top)
		*out_top = res.a2;

	return res.a0;
}

/**
 * rmi_rtt_fold() - Fold an RTT
 * @rd: PA of the RD
 * @ipa: Base of the IPA range described by the RTT
 * @level: Depth of the RTT within the tree
 * @out_rtt: Pointer to write the PA of the RTT which was destroyed
 *
 * Folds an RTT. If all entries with the RTT are 'homogeneous' the RTT can be
 * folded into the parent and the RTT destroyed.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_fold(unsigned long rd, unsigned long ipa,
			       long level, unsigned long *out_rtt)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_FOLD, rd, ipa, level, &res);

	if (out_rtt)
		*out_rtt = res.a1;

	return res.a0;
}

/**
 * rmi_rtt_init_ripas() - Set RIPAS for new realm
 * @rd: PA of the RD
 * @base: Base of target IPA region
 * @top: Top of target IPA region
 * @out_top: Top IPA of range whose RIPAS was modified
 *
 * Sets the RIPAS of a target IPA range to RAM, for a realm in the NEW state.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_init_ripas(unsigned long rd, unsigned long base,
				     unsigned long top, unsigned long *out_top)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_INIT_RIPAS, rd, base, top, &res);

	if (out_top)
		*out_top = res.a1;

	return res.a0;
}

/**
 * rmi_rtt_map_unprotected() - Map NS granules into a realm
 * @rd: PA of the RD
 * @ipa: Base IPA of the mapping
 * @level: Depth within the RTT tree
 * @desc: RTTE descriptor
 *
 * Create a mapping from an Unprotected IPA to a Non-secure PA.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_map_unprotected(unsigned long rd,
					  unsigned long ipa,
					  long level,
					  unsigned long desc)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_MAP_UNPROTECTED, rd, ipa, level,
			     desc, &res);

	return res.a0;
}

/**
 * rmi_rtt_read_entry() - Read an RTTE
 * @rd: PA of the RD
 * @ipa: IPA for which to read the RTTE
 * @level: RTT level at which to read the RTTE
 * @rtt: Output structure describing the RTTE
 *
 * Reads a RTTE (Realm Translation Table Entry).
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_read_entry(unsigned long rd, unsigned long ipa,
				     long level, struct rtt_entry *rtt)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_READ_ENTRY,
		rd, ipa, level
	};

	arm_smccc_1_2_smc(&regs, &regs);

	rtt->walk_level = regs.a1;
	rtt->state = regs.a2 & 0xFF;
	rtt->desc = regs.a3;
	rtt->ripas = regs.a4 & 0xFF;

	return regs.a0;
}

/**
 * rmi_rtt_set_ripas() - Set RIPAS for an running realm
 * @rd: PA of the RD
 * @rec: PA of the REC making the request
 * @base: Base of target IPA region
 * @top: Top of target IPA region
 * @out_top: Pointer to write top IPA of range whose RIPAS was modified
 *
 * Completes a request made by the realm to change the RIPAS of a target IPA
 * range.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_set_ripas(unsigned long rd, unsigned long rec,
				    unsigned long base, unsigned long top,
				    unsigned long *out_top)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_SET_RIPAS, rd, rec, base, top, &res);

	if (out_top)
		*out_top = res.a1;

	return res.a0;
}

/**
 * rmi_rtt_unmap_unprotected() - Remove a NS mapping
 * @rd: PA of the RD
 * @ipa: Base IPA of the mapping
 * @level: Depth within the RTT tree
 * @out_top: Pointer to write top IPA of non-live RTT entries
 *
 * Removes a mapping at an Unprotected IPA.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_unmap_unprotected(unsigned long rd,
					    unsigned long ipa,
					    long level,
					    unsigned long *out_top)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_UNMAP_UNPROTECTED, rd, ipa,
			     level, &res);

	if (out_top)
		*out_top = res.a1;

	return res.a0;
}

#ifdef CONFIG_HISI_CCADA_HOST
/**
 * rmi_dev_init() - Initialize the dev info
 * @dev_bdf: Bdf of the pci dev
 * @pa: Pa of the delegated page
 *
 * Initialize the dev info with the delegated memory.
 *
 * Return: RMI return code
 */
static inline int rmi_dev_init(unsigned long dev_bdf, unsigned long pa)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_INIT,
		dev_bdf, pa
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_root_dev_delegate() - Delegate the root dev
 * @params_addr: PA of the struct rmi_dev_delegate_params
 * @out_dev_bdf: dev bdf returned from rmm
 *
 * Request the rmm to delegate root dev and protect the device under it.
 *
 * Return: RMI return code
 */
static inline int rmi_root_dev_delegate(unsigned long params_addr,
					unsigned long *out_dev_bdf)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_ROOT_DEV_DELEGATE,
		params_addr
	};

	arm_smccc_1_2_smc(&regs, &regs);

	if (regs.a0 == RMI_ERROR_DEV_INFO)
		*out_dev_bdf = regs.a1;

	return regs.a0;
}

/**
 * rmi_dev_delegate() - Delegate the assigned dev
 * @dev_bdf: BDF of the pci device assigned to realm
 * @root_bdf: BDF of the root dev
 *
 * Request the rmm to delegate device mmio range.
 *
 * Return: RMI return code
 */
static inline int rmi_dev_delegate(unsigned long dev_bdf, unsigned long root_bdf)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_DELEGATE,
		dev_bdf, root_bdf
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_dev_attach() - Attach the device to realm
 * @dev_bdf: BDF of the pci device assigned to realm
 * @rd: PA of the RD
 * @smmu_addr: Base address of the smmu device
 * @s2_vmid: Stage 2 vmid
 * @lvl_strtab: Strtab level
 *
 * Request the rmm to attach the device to realm and config ste for the device.
 *
 * Return: RMI return code
 */
static inline int rmi_dev_attach(unsigned long dev_bdf, unsigned long rd,
				 unsigned long smmu_addr, unsigned long s2_vmid,
				 unsigned long lvl_strtab)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_ATTACH,
		dev_bdf, rd, smmu_addr, s2_vmid, lvl_strtab
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_dev_detach() - Detach the device from realm
 * @dev_bdf: BDF of the pci device assigned to realm
 *
 * Request the rmm to detach the device from realm.
 *
 * Return: RMI return code
 */
static inline int rmi_dev_detach(unsigned long dev_bdf)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_DETACH,
		dev_bdf,
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_dev_undelegate() - Undelegate the device
 * @dev_bdf: BDF of the pci device assigned to realm
 *
 * Request the rmm to undelegate device mmio range.
 *
 * Return: RMI return code
 */
static inline int rmi_dev_undelegate(unsigned long bdf)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_UNDELEGATE,
		bdf
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_dev_map() - Create a dev mmio mapping
 * @rd: PA of the RD
 * @ipa: IPA at which the granule will be mapped in the guest
 * @rtt: Output structure describing the RTTE
 *
 * Map a dev mmio IPA to a PA, create a stage 2 mapping.
 *
 * Return: RMI return code
 */
static inline int rmi_dev_map(unsigned long rd, unsigned long pa,
			      unsigned long ipa)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_MAP,
		rd, pa, ipa
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_dev_unmap() - Destroy a dev Granule
 * @rd: PA of the RD
 * @ipa: IPA at which the granule is mapped in the guest
 * @data_out: PA of the granule which was destroyed
 * @top_out: Top IPA of non-live RTT entries
 *
 * Unmap a dev mmio IPA from stage 2.
 *
 * Return: RMI return code
 */

static inline int rmi_dev_unmap(unsigned long rd, unsigned long ipa,
				unsigned long *data_out, unsigned long *top_out)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_UNMAP,
		rd, ipa
	};

	arm_smccc_1_2_smc(&regs, &regs);

	*data_out = regs.a1;
	*top_out = regs.a2;

	return regs.a0;
}

#define MMIO_REG_READ 0
#define MMIO_REG_WRITE 1

/**
 * rmi_dev_mmio_read() - Transfer to rmm to read dev mmio
 * @reg: The dev mmio register reading from
 * @bits: Reading size
 * @value: Value returned from rmm
 * @dev_bdf: BDF of the pci device
 *
 * Transfer to rmm to read value from dev mmio.
 *
 * Return: RMI return code
 */
static inline int rmi_dev_mmio_read(unsigned long reg, unsigned long bits,
				    unsigned long *value, unsigned long dev_bdf)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_MMIO_RW,
		reg,
		MMIO_REG_READ,
		0,
		bits,
		dev_bdf,
	};

	arm_smccc_1_2_smc(&regs, &regs);

	if (regs.a0 == 0)
		*value = regs.a1;

	return regs.a0;
}

/**
 * rmi_dev_mmio_write() - Transfer to rmm to write dev mmio
 * @reg: The dev mmio register writing to
 * @bits: Writing size
 * @value: Target writing value
 * @dev_bdf: BDF of the pci device
 *
 * Transfer to rmm to write value to dev mmio.
 *
 * Return: RMI return code
 */
static inline int rmi_dev_mmio_write(unsigned long reg, unsigned long bits,
				     unsigned long value, unsigned long dev_bdf)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_DEV_MMIO_RW,
		reg,
		MMIO_REG_WRITE,
		value,
		bits,
		dev_bdf,
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

#define SMMU_R_REG_32_BIT 32
#define SMMU_R_REG_64_BIT 64

/**
 * rmi_smmu_reg_read() - Read realm smmu register
 * @ioaddr: PA of the realm smmu
 * @reg: Offset of the register
 * @bits: Register read bits
 * @value: Pointer to read result
 *
 * Read realm smmu register for given offset
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_reg_read(unsigned long ioaddr, unsigned long reg,
				    unsigned long bits, unsigned long *value)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_REG_RW,
		ioaddr,
		MMIO_REG_READ,
		reg,
		0,
		bits,
	};

	arm_smccc_1_2_smc(&regs, &regs);

	if (regs.a0 == 0)
		*value = regs.a1;

	return regs.a0;
}

static inline int rmi_smmu_reg_read32(unsigned long ioaddr, unsigned long reg,
				      u32 *value)
{
	unsigned long reg_value;
	int ret;

	ret = rmi_smmu_reg_read(ioaddr, reg, SMMU_R_REG_32_BIT, &reg_value);
	if (!ret)
		*value = (u32)reg_value;

	return ret;
}

/**
 * rmi_smmu_reg_write() - Write realm smmu register
 * @ioaddr: PA of the realm smmu
 * @reg: Offset of the register
 * @bits: Register write bits
 * @value: Value to write
 *
 * Write realm smmu register for given offset
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_reg_write(unsigned long ioaddr, unsigned long reg,
				     unsigned long bits, unsigned long value)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_REG_RW,
		ioaddr,
		MMIO_REG_WRITE,
		reg,
		value,
		bits,
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

static inline int rmi_smmu_reg_write32(unsigned long ioaddr, unsigned long reg,
				       u32 value)
{
	return rmi_smmu_reg_write(ioaddr, reg, SMMU_R_REG_32_BIT,
				  (unsigned long)value);
}

static inline int rmi_smmu_reg_write64(unsigned long ioaddr, unsigned long reg,
				       unsigned long value)
{
	return rmi_smmu_reg_write(ioaddr, reg, SMMU_R_REG_64_BIT, value);
}

/**
 * rmi_smmu_config() - Config realm smmu
 * @config: Config type
 * @ioaddr: PA of the realm smmu
 * @ns_params: PA of the non-secure params
 *
 * Config realm smmu strtab and realm smmu queue
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_config(unsigned long config, unsigned long ioaddr,
				  unsigned long ns_params)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_CONFIG,
		config, ioaddr, ns_params
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

enum smmu_config {
	SMMU_STRTAB_INIT,
	SMMU_STRTAB_DEINIT,
	SMMU_STRTAB_L2_INIT,
	SMMU_STRTAB_L2_DEINIT,
	SMMU_QUEUE_INIT,
	SMMU_QUEUE_DEINIT,
};

struct queue_params {
	unsigned long queue_type;
	unsigned long q_base;
	unsigned long q_log2;
};

struct strtab_params {
	unsigned long strtab_base;
	unsigned long strtab_base_cfg;
};

struct strtab_l2_params {
	unsigned long strtab_base;
	unsigned long sid;
	unsigned long l2_pa;
	unsigned long span;
};

static inline int realm_smmu_config(unsigned long config, unsigned long ioaddr,
				    void *params, unsigned long size)
{
	void *ns_params;
	int ret;

	ns_params = (void *)get_zeroed_page(GFP_KERNEL);
	if (!ns_params)
		return -ENOMEM;

	if (size > PAGE_SIZE) {
		free_page((unsigned long)ns_params);
		return -EINVAL;
	}

	memcpy(ns_params, params, size);
	ret = rmi_smmu_config(config, ioaddr, virt_to_phys(ns_params));

	free_page((unsigned long)ns_params);

	return ret;
}

/**
 * realm_config_queue() - Config realm smmu queue
 * @config: Config type
 * @ioaddr: PA of the realm smmu
 * @queue_type: Smmu command queue or event queue
 * @q_base: PA of smmu queue
 * @q_log2: Number of smmu queue entity
 *
 * Config realm smmu queue
 *
 * Return: RMI return code
 */
static inline int realm_config_queue(enum smmu_config config,
				     unsigned long ioaddr,
				     unsigned long queue_type,
				     unsigned long q_base,
				     unsigned long q_log2)
{
	struct queue_params params = {
		.queue_type = queue_type,
		.q_base = q_base,
		.q_log2 = q_log2,
	};

	return realm_smmu_config(config, ioaddr, (void *)&params, sizeof(params));
}

/**
 * realm_config_strtab() - Config realm smmu stream table
 * @config: Config type
 * @ioaddr: PA of the realm smmu
 * @strtab_base: PA of realm smmu stream table
 * @strtab_base_cfg: Stream table's format and size config
 *
 * Config realm smmu stream table
 *
 * Return: RMI return code
 */
static inline int realm_config_strtab(enum smmu_config config,
				      unsigned long ioaddr,
				      unsigned long strtab_base,
				      unsigned long strtab_base_cfg)
{
	struct strtab_params params = {
		.strtab_base = strtab_base,
		.strtab_base_cfg = strtab_base_cfg,
	};

	return realm_smmu_config(config, ioaddr, (void *)&params, sizeof(params));
}

/**
 * realm_config_strtab_l2() - Config realm smmu level-2 stream table
 * @config: Config type
 * @ioaddr: PA of the realm smmu
 * @strtab_base: PA of realm smmu stream table
 * @sid: Stream id of device
 * @l2_pa: PA of realm smmu level-2 stream table
 * @span: Span of realm smmu level-2 stream table
 *
 * Config realm smmu level-2 stream table
 *
 * Return: RMI return code
 */
static inline int realm_config_strtab_l2(enum smmu_config config,
					 unsigned long ioaddr,
					 unsigned long strtab_base,
					 unsigned long sid,
					 unsigned long l2_pa,
					 unsigned long span)
{
	struct strtab_l2_params params = {
		.strtab_base = strtab_base,
		.sid = sid,
		.l2_pa = l2_pa,
		.span = span,
	};

	return realm_smmu_config(config, ioaddr, (void *)&params, sizeof(params));
}

/**
 * rmi_smmu_read_event() - Read realm smmu event
 * @ioaddr: PA of the realm smmu
 * @evt: Realm event message
 *
 * Read realm smmu event
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_read_event(unsigned long ioaddr, u64 *evt)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_READ_EVENT,
		ioaddr
	};

	arm_smccc_1_2_smc(&regs, &regs);

	evt[0] = regs.a1;
	evt[1] = regs.a2;
	evt[2] = regs.a3;
	evt[3] = regs.a4;

	return regs.a0;
}

/**
 * rmi_smmu_send_cmdlist() - Write realm smmu command
 * @ioaddr: PA of the realm smmu
 * @rcmds: PA of the realm command
 * @n: Number of realm command
 * @sync: Whether a synchronization command is issued at the end
 *
 * Write realm smmu command
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_send_cmdlist(unsigned long ioaddr,
					unsigned long rcmds,
					unsigned long n,
					unsigned long sync)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_SEND_CMDLIST,
		ioaddr, rcmds, n, sync
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_smmu_map() - Create non-secure mapping from iova to pa for the realm smmu
 * @pgd: Realm page table dentry
 * @iova: Start iova
 * @pa: Start pa
 * @prot: Prot of the PTE(page table entry)
 * @page_attr: Size and page count of mappings
 * @map_cnt: Number of successful mappings
 *
 * Create multiple non-secure mapping from iova to pa in the realm smmu stage-2
 * page table
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_map(unsigned long pgd, unsigned long iova,
			       unsigned long pa, unsigned long prot,
			       unsigned long page_attr, unsigned long *map_cnt)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_MAP,
		pgd, iova, pa, prot, page_attr
	};

	arm_smccc_1_2_smc(&regs, &regs);

	*map_cnt = regs.a1;

	return regs.a0;
}

/**
 * rmi_smmu_page_table_create() - Create realm page-table for given iova and level
 * @pgd: Realm page table dentry
 * @iova: Given iova
 * @tbl_entry: Relam page table entry's PA and attribute
 * @tbl_size: Relam page table size
 * @lvl: Create page table at given level
 *
 * Create realm page-table for given iova and level
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_page_table_create(unsigned long pgd,
					     unsigned long iova,
					     unsigned long tbl_entry,
					     unsigned long tbl_size,
					     unsigned long lvl)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_PAGE_TABLE_CREATE,
		pgd, iova, tbl_entry, tbl_size, lvl
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_smmu_page_table_destroy() - Destroy realm page-table for given iova and level
 * @pgd: Realm page table dentry
 * @iova: Given iova
 * @tbl_pa: PA of realm page table
 * @tbl_size: Relam page table size
 * @lvl: Create page table at given level
 *
 * Destroy realm page-table for given iova and level
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_page_table_destroy(unsigned long pgd,
					      unsigned long iova,
					      unsigned long tbl_pa,
					      unsigned long tbl_size,
					      unsigned long lvl)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_PAGE_TABLE_DESTROY,
		pgd, iova, tbl_pa, tbl_size, lvl
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

/**
 * rmi_smmu_read_pte() - Read realm PTE
 * @pgd: Realm page table dentry
 * @iova: Given iova
 * @lvl: Level of PTE
 * @pte: Value of PTE
 *
 * Read realm PTE(Page table entry) for given iova and level
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_read_pte(unsigned long pgd, unsigned long iova,
				    unsigned long lvl, unsigned long *pte)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_READ_PTE,
		pgd, iova, lvl
	};

	arm_smccc_1_2_smc(&regs, &regs);

	*pte = regs.a1;
	return regs.a0;
}

/**
 * rmi_smmu_ste_write() - Write realm smmu stream table entry
 * @smmu_addr: PA of the realm smmu
 * @sid: Steam id
 * @ste_pa: PA of stream table entry
 * @lvl_strtab: Level of stream table
 *
 * Write realm smmu stream table entry
 *
 * Return: RMI return code
 */
static inline int rmi_smmu_ste_write(unsigned long smmu_addr,
				     unsigned long sid,
				     unsigned long ste_pa,
				     unsigned long lvl_strtab)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCADA_SMMU_STE_WRITE,
		smmu_addr, sid, ste_pa, lvl_strtab
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

#endif

#endif /* __ASM_RMI_CMDS_H */
