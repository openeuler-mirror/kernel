// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#include <linux/arm-smccc.h>
#include <asm/kvm_tmi.h>
#include <asm/memory.h>
#include <asm/virtcca_cvm_host.h>
#include <asm/virtcca_cvm_guest.h>
#include <asm/kvm_emulate.h>

/**
 * mmio_va_to_pa - To convert the virtual address of the mmio space
 * to a physical address, it is necessary to implement this interface
 * because the kernel insterface __pa has an error when converting the
 * physical address of the virtual address of the mmio space
 * @addr:	MMIO virtual address
 */
u64 mmio_va_to_pa(const void __iomem *addr)
{
	uint64_t pa, par_el1;

	asm volatile(
		"AT S1E1W, %0\n"
		::"r"((uint64_t)(addr))
	);
	isb();
	asm volatile(
		"mrs %0, par_el1\n"
		: "=r"(par_el1)
	);

	pa = ((uint64_t)(addr) & (PAGE_SIZE - 1)) |
		(par_el1 & ULL(0x000ffffffffff000));

	if (par_el1 & UL(1 << 0))
		return (uint64_t)(addr);
	else
		return pa;
}
EXPORT_SYMBOL(mmio_va_to_pa);

int virtcca_io_mem_abort(struct kvm_vcpu *vcpu, unsigned long hva, phys_addr_t fault_ipa)
{
	struct virtcca_cvm *cvm = vcpu->kvm->arch.virtcca_cvm;

	if (!vcpu_is_tec(vcpu) || !(fault_ipa >= cvm->mmio_start && fault_ipa < cvm->mmio_end))
		return -EPERM;

	if (kvm_is_error_hva(hva) && kvm_vcpu_dabt_is_cm(vcpu)) {
		kvm_incr_pc(vcpu);
		return 1;
	}

	fault_ipa |= kvm_vcpu_get_hfar(vcpu) & ((1 << 12) - 1);
	return io_mem_abort(vcpu, fault_ipa);
}

u64 tmi_version(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_VERSION_REQ, &res);
	return res.a1;
}

u64 tmi_data_create(u64 numa_set, u64 rd, u64 map_addr, u64 src, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DATA_CREATE, numa_set, rd, map_addr, src, level, &res);
	return res.a1;
}


u64 tmi_cvm_activate(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_CVM_ACTIVATE, rd, &res);
	return res.a1;
}

u64 tmi_cvm_create(u64 params_ptr, u64 numa_set, bool vtimer_adjust)
{
	struct arm_smccc_res res;

	/* vtimer_adjust enable to reduce vtimer irq */
	params_ptr = params_ptr | (vtimer_adjust ? 1UL : 0UL);
	arm_smccc_1_1_smc(TMI_TMM_CVM_CREATE, params_ptr, numa_set, &res);
	return res.a1;
}

u64 tmi_cvm_destroy(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_CVM_DESTROY, rd, &res);
	return res.a1;
}

u64 tmi_tec_create(u64 numa_set, u64 rd, u64 mpidr, u64 params_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_CREATE, numa_set, rd, mpidr, params_ptr, &res);
	return res.a1;
}

u64 tmi_tec_destroy(u64 tec)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_DESTROY, tec, &res);
	return res.a1;
}

u64 tmi_tec_enter(u64 tec, u64 run_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_ENTER, tec, run_ptr, &res);
	return res.a1;
}

u64 tmi_ttt_create(u64 numa_set, u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_CREATE, numa_set, rd, map_addr, level, &res);
	return res.a1;
}

u64 tmi_psci_complete(u64 calling_tec, u64 target_tec)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_PSCI_COMPLETE, calling_tec, target_tec, &res);
	return res.a1;
}

u64 tmi_features(u64 index)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_FEATURES, index, &res);
	return res.a1;
}

u64 tmi_mem_info_show(u64 mem_info_addr)
{
	struct arm_smccc_res res;
	u64 pa_addr = __pa(mem_info_addr);

	arm_smccc_1_1_smc(TMI_TMM_MEM_INFO_SHOW, pa_addr, &res);
	return res.a1;
}
EXPORT_SYMBOL_GPL(tmi_mem_info_show);

u64 tmi_ttt_map_range(u64 rd, u64 map_addr, u64 size, u64 cur_node, u64 target_node)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_MAP_RANGE, rd, map_addr, size, cur_node, target_node, &res);
	return res.a1;
}

u64 tmi_ttt_destroy(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_DESTROY, rd, &res);
	return res.a1;
}

/* Used to create smmu command queue and event queue */
u64 tmi_smmu_queue_create(u64 params_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_SMMU_QUEUE_CREATE, params_ptr, &res);
	return res.a1;
}
EXPORT_SYMBOL_GPL(tmi_smmu_queue_create);

/**
 * tmi_smmu_queue_write - Write command to command queue
 * @cmd0:	Command consists of 128 bits, cmd0 is the low 64 bits
 * @cmd1:	Cmdq is the high 64 bits of command
 * @smmu_id:	SMMU ID
 */
u64 tmi_smmu_queue_write(uint64_t cmd0, uint64_t cmd1, u64 smmu_id)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_SMMU_QUEUE_WRITE, cmd0, cmd1, smmu_id, &res);
	return res.a1;
}
EXPORT_SYMBOL_GPL(tmi_smmu_queue_write);

/* Create smmu L2 stream table and sync stream table entry */
u64 tmi_smmu_ste_create(u64 params_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_SMMU_STE_CREATE, params_ptr, &res);
	return res.a1;
}
EXPORT_SYMBOL_GPL(tmi_smmu_ste_create);

/**
 * tmi_mmio_map - Map mmio stage2 translation for device
 * @rd:	CVM handle
 * @map_addr:	IPA from guest view
 * @level:	Page table mapping level
 * @ttte:	Physical address mapped by page table
 */
u64 tmi_mmio_map(u64 rd, u64 map_addr, u64 level, u64 ttte)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MMIO_MAP, rd, map_addr, level, ttte, &res);
	return res.a1;
}

/**
 * tmi_mmio_unmap - Unmap mmio stage2 translation for device
 * @rd:	CVM handle
 * @map_addr:	IPA from guest view
 * @level:	Page table mapping level
 */
u64 tmi_mmio_unmap(u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MMIO_UNMAP, rd, map_addr, level, &res);
	return res.a1;
}

/**
 * tmi_mmio_write - Write device mmio
 * @addr:	MMIO address
 * @val:	Val to write
 * @bits:	The number of bits of val
 * @dev_num:	Device bdf number
 */
u64 tmi_mmio_write(u64 addr, u64 val, u64 bits, u64 dev_num)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MMIO_WRITE, addr, val, bits, dev_num, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_mmio_write);

/**
 * tmi_mmio_read - Read device mmio
 * @addr:	MMIO address
 * @bits:	Read data bit
 * @dev_num:	Device bdf number
 */
u64 tmi_mmio_read(u64 addr, u64 bits, u64 dev_num)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MMIO_READ, addr, bits, dev_num, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_mmio_read);

/* Delegate root port and enable pcipc capability */
u64 tmi_dev_delegate(u64 params)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DEV_DELEGATE, params, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_dev_delegate);

/**
 * tmi_dev_attach - Attach device and configure L2 ste before activate CVM
 * @vdev:	Device bdf number
 * @rd:	CVM handle
 * @smmu_id:	SMMU ID
 * @smmu_vmid:	SMMU vmid
 */
u64 tmi_dev_attach(u64 vdev, u64 rd, u64 smmu_id, u64 smmu_vmid)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DEV_ATTACH, vdev, rd, smmu_id, smmu_vmid, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_dev_attach);

/* Handle smmu device event queue when an event queue interrupt is triggered */
u64 tmi_handle_s_evtq(u64 smmu_id)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_HANDLE_S_EVTQ, smmu_id, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_handle_s_evtq);

/* Create smmu device command/event queue and L1 stream table */
u64 tmi_smmu_device_reset(u64 params)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_SMMU_DEVICE_RESET, params, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_smmu_device_reset);

/* Check smmu device base addr */
u64 tmi_smmu_pcie_core_check(u64 smmu_base)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_SMMU_PCIE_CORE_CHECK, smmu_base, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_smmu_pcie_core_check);

/**
 * tmi_smmu_write - Write smmu secure register
 * @smmu_base:	SMMU base address
 * @reg_offset:	SMMU register
 * @val:	Val to write
 * @bits:	Bits to write
 */
u64 tmi_smmu_write(u64 smmu_base, u64 reg_offset, u64 val, u64 bits)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_SMMU_WRITE, smmu_base, reg_offset, val, bits, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_smmu_write);

/**
 * tmi_smmu_read - Read smmu secure register
 * @smmu_base:	SMMU base address
 * @reg_offset:	SMMU register
 * @bits:	Bits to read
 */
u64 tmi_smmu_read(u64 smmu_base, u64 reg_offset, u64 bits)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_SMMU_READ, smmu_base, reg_offset, bits, &res);
	return res.a1;
}
EXPORT_SYMBOL(tmi_smmu_read);

/* Create device ttt */
u64 tmi_dev_ttt_create(u64 numa_set, u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DEV_TTT_CREATE, numa_set, rd, map_addr, level, &res);
	return res.a1;
}

u64 tmi_kae_init(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_KAE_INIT, &res);
	return res.a1;
}

u64 tmi_kae_enable(u64 rd, u64 numa_set, u64 is_enable)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_KAE_ENABLE, rd, numa_set, is_enable, &res);
	return res.a1;
}

u64 tmi_tmm_info_show(u64 option, u64 tmm_info_addr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_INFO_SHOW, option, tmm_info_addr, &res);
	return res.a1;
}
EXPORT_SYMBOL_GPL(tmi_tmm_info_show);

u64 tmi_dev_create(u64 params)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DEV_CREATE, params, &res);
	return res.a1;
}

u64 tmi_dev_destroy(u64 dev_num, u64 clean)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DEV_DESTROY, dev_num, clean, &res);
	return res.a1;
}

/* additional TMI call for migration */
u64 tmi_get_mig_config(void)
{
	struct arm_smccc_res res;

	/* calculate the max number of these pages(rd,vcpu) */
	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_GET_MIG_CONFIG, &res);
	return res.a1;
}

u64 tmi_mig_stream_create(u64 rd, u64 numa_set)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_MIG_STREAM_CREATE, rd, numa_set, &res);
	return res.a1;
}

u64 tmi_set_tmm_memslot(u64 rd, u64 mig_memslot_param)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_SET_TMM_MEMSLOT,
		rd, mig_memslot_param, &res);
	return res.a1;
}

u64 tmi_update_cvm_info(u64 rd, u64 cvm_update_info_addr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_MIG_UPDATE_CVM_INFO, rd,
		__pa(cvm_update_info_addr), &res);
	return res.a1;
}

struct arm_smccc_res tmi_mem_region_protect(u64 rd, u64 start, u64 end)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_MIG_MEM_REGION_PROTECT,
		rd, start, end, &res);
	return res;
}

u64 tmi_import_commit(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_MIG_IMPORT_COMMIT, rd, &res);
	return res.a1;
}

u64 tmi_dump_checksum(u64 rd, u64 gpa_list_addr, u64 crc_result_addr, u64 granularity)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_DUMP_CHECKSUM,
		rd, gpa_list_addr, crc_result_addr, granularity, &res);
	return res.a1;
}

u64 tmi_export_abort(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_MIG_EXPORT_ABORT, rd, &res);
	return res.a1;
}

struct arm_smccc_res tmi_export_immutable(u64 rd, u64 hpa_and_size_pa,
	u64 page_or_list, u64 mig_cmd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_EXPORT_IMMUTABLE,
		rd, hpa_and_size_pa, page_or_list, mig_cmd, &res);
	return res;
}

u64 tmi_import_immutable(u64 rd, u64 hpa_and_size_pa,
						u64 page_or_list, u64 mig_cmd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_IMPORT_IMMUTABLE,
		rd, hpa_and_size_pa, page_or_list, mig_cmd, &res);
	return res.a1;
}

u64 tmi_export_track(u64 rd, u64 hpa_and_size_pa, u64 mig_cmd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_EXPORT_TRACK,
		rd, hpa_and_size_pa, mig_cmd, &res);
	return res.a1;
}

u64 tmi_import_track(u64 rd, u64 hpa_and_size_pa, u64 mig_cmd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_IMPORT_TRACK,
		rd, hpa_and_size_pa, mig_cmd, &res);
	return res.a1;
}

struct arm_smccc_res tmi_import_mem(u64 rd, u64 mig_mem_param)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_IMPORT_MEM, rd, mig_mem_param, &res);
	return res;
}

struct arm_smccc_res tmi_export_mem(u64 rd, u64 mig_mem_param)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_EXPORT_MEM,
		rd, mig_mem_param, &res);
	return res;
}

struct arm_smccc_res tmi_export_tec(u64 tec_pa, u64 mbmd_addr_and_size,
	u64 page_list_pa, u64 stream_info_pa)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_EXPORT_TEC,
		tec_pa, mbmd_addr_and_size, page_list_pa, stream_info_pa, &res);
	return res;
}

u64 tmi_import_tec(u64 tec_pa, u64 mbmd_addr_and_size, u64 page_list_pa, u64 stream_info_pa)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_IMPORT_TEC,
		tec_pa, mbmd_addr_and_size, page_list_pa, stream_info_pa, &res);
	return res.a1;
}

struct arm_smccc_res tmi_is_zero_page(u64 rd, u64 gpa_list_info_val)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_IS_ZERO_PAGE,
		rd, gpa_list_info_val, &res);
	return res;
}

struct arm_smccc_res tmi_import_zero_page(u64 rd, u64 gpa_list_info_val)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_DATA, TMI_TMM_MIG_IMPORT_ZERO_PAGE,
		rd, gpa_list_info_val, &res);
	return res;
}

struct arm_smccc_res tmi_export_pause(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_CONTROL, TMI_TMM_MIG_EXPORT_PAUSE, rd, &res);
	return res;
}

u64 tmi_bind_clean(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_ATTESTATION, TMI_TMM_MIG_BIND_CLEAN, rd, &res);
	return res.a1;
}
struct arm_smccc_res tmi_bind_peek(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_MIG_ATTESTATION, TMI_TMM_MIG_BIND_PEEK, rd, &res);
	return res;
}

u64 tmi_mig_integrity_checksum_init(unsigned long dst_rd, unsigned long queue_pa)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(
		TMI_TMM_MIG_ATTESTATION,
		TMI_TMM_MIG_INTEGRITY_CHECKSUM_INIT,
		dst_rd, queue_pa, &res);
	return res.a1;
}

u64 tmi_mig_integrity_checksum_loop(uint64_t rd, uint64_t thread_id)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(
		TMI_TMM_MIG_ATTESTATION, TMI_TMM_MIG_INTEGRITY_CHECKSUM_LOOP, rd, thread_id, &res);
	return res.a1;
}

u64 tmi_mig_get_migration_key(uint64_t rd, uint64_t hsot_mig_agent_attr_p)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(
		TMI_TMM_MIG_CONTROL,
		TMI_TMM_MIG_GET_MIG_KEY,
		rd, __pa(hsot_mig_agent_attr_p), &res);
	return res.a1;
}

u64 tmi_mig_set_migration_key(uint64_t rd, uint64_t hsot_mig_agent_attr_p)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(
		TMI_TMM_MIG_CONTROL,
		TMI_TMM_MIG_SET_MIG_KEY,
		rd, __pa(hsot_mig_agent_attr_p), &res);
	return res.a1;
}
