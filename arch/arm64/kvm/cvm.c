// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <asm/kvm_tmi.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/stage2_pgtable.h>
#include <linux/arm-smccc.h>
#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

/* Protects access to cvm_vmid_bitmap */
static DEFINE_SPINLOCK(cvm_vmid_lock);
static unsigned long *cvm_vmid_bitmap;
DEFINE_STATIC_KEY_FALSE(kvm_cvm_is_available);
DEFINE_STATIC_KEY_FALSE(kvm_cvm_is_enable);
#define SIMD_PAGE_SIZE 0x3000

static int __init setup_cvm_host(char *str)
{
	int ret;
	unsigned int val;

	if (!str)
		return 0;

	ret = kstrtouint(str, 10, &val);
	if (ret) {
		pr_warn("Unable to parse cvm_guest.\n");
	} else {
		if (val)
			static_branch_enable(&kvm_cvm_is_enable);
	}
	return ret;
}
early_param("cvm_host", setup_cvm_host);

u64 cvm_phys_to_phys(u64 phys)
{
	return phys;
}

u64 phys_to_cvm_phys(u64 phys)
{
	return phys;
}

static int cvm_vmid_init(void)
{
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	cvm_vmid_bitmap = bitmap_zalloc(vmid_count, GFP_KERNEL);
	if (!cvm_vmid_bitmap) {
		kvm_err("%s: Couldn't allocate cvm vmid bitmap\n", __func__);
		return -ENOMEM;
	}
	return 0;
}

static unsigned long tmm_feat_reg0;

static bool tmm_supports(unsigned long feature)
{
	return !!u64_get_bits(tmm_feat_reg0, feature);
}

bool kvm_cvm_supports_sve(void)
{
	return tmm_supports(TMI_FEATURE_REGISTER_0_SVE_EN);
}

bool kvm_cvm_supports_pmu(void)
{
	return tmm_supports(TMI_FEATURE_REGISTER_0_PMU_EN);
}

u32 kvm_cvm_ipa_limit(void)
{
	return u64_get_bits(tmm_feat_reg0, TMI_FEATURE_REGISTER_0_S2SZ);
}

u32 kvm_cvm_get_num_brps(void)
{
	return u64_get_bits(tmm_feat_reg0, TMI_FEATURE_REGISTER_0_NUM_BPS);
}

u32 kvm_cvm_get_num_wrps(void)
{
	return u64_get_bits(tmm_feat_reg0, TMI_FEATURE_REGISTER_0_NUM_WPS);
}

static int cvm_vmid_reserve(void)
{
	int ret;
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	spin_lock(&cvm_vmid_lock);
	ret = bitmap_find_free_region(cvm_vmid_bitmap, vmid_count, 0);
	spin_unlock(&cvm_vmid_lock);

	return ret;
}

static void cvm_vmid_release(unsigned int vmid)
{
	spin_lock(&cvm_vmid_lock);
	bitmap_release_region(cvm_vmid_bitmap, vmid, 0);
	spin_unlock(&cvm_vmid_lock);
}

static u32 __kvm_pgd_page_idx(struct kvm_pgtable *pgt, u64 addr)
{
	u64 shift = ARM64_HW_PGTABLE_LEVEL_SHIFT(pgt->start_level - 1);
	u64 mask = BIT(pgt->ia_bits) - 1;

	return (addr & mask) >> shift;
}

static u32 kvm_pgd_pages(u32 ia_bits, u32 start_level)
{
	struct kvm_pgtable pgt = {
		.ia_bits		= ia_bits,
		.start_level	= start_level,
	};
	return __kvm_pgd_page_idx(&pgt, -1ULL) + 1;
}

int kvm_arm_create_cvm(struct kvm *kvm)
{
	int ret;
	struct kvm_pgtable *pgt = kvm->arch.mmu.pgt;
	unsigned int pgd_sz;

	if (!kvm_is_cvm(kvm) || kvm_cvm_state(kvm) != CVM_STATE_NONE)
		return 0;

	ret = cvm_vmid_reserve();
	if (ret < 0)
		return ret;

	kvm->arch.cvm.cvm_vmid = ret;

	pgd_sz = kvm_pgd_pages(pgt->ia_bits, pgt->start_level);

	kvm->arch.cvm.params->ttt_base = phys_to_cvm_phys(kvm->arch.mmu.pgd_phys);
	kvm->arch.cvm.params->measurement_algo = 0;
	kvm->arch.cvm.params->ttt_level_start = kvm->arch.mmu.pgt->start_level;
	kvm->arch.cvm.params->ttt_num_start = pgd_sz;
	kvm->arch.cvm.params->s2sz = VTCR_EL2_IPA(kvm->arch.vtcr);
	kvm->arch.cvm.params->vmid = kvm->arch.cvm.cvm_vmid;
	kvm->arch.cvm.params->ns_vtcr = kvm->arch.vtcr;
	kvm->arch.cvm.params->vttbr_el2 = kvm->arch.mmu.pgd_phys;
	ret = tmi_cvm_create(kvm->arch.cvm.rd, __pa(kvm->arch.cvm.params));
	if (!ret)
		kvm_info("KVM creates cVM: %d\n", kvm->arch.cvm.cvm_vmid);

	WRITE_ONCE(kvm->arch.cvm.state, CVM_STATE_NEW);
	kfree(kvm->arch.cvm.params);
	kvm->arch.cvm.params = NULL;
	return ret;
}

int cvm_create_rd(struct kvm *kvm)
{
	if (!static_key_enabled(&kvm_cvm_is_available))
		return -EFAULT;

	kvm->arch.cvm.rd = tmi_mem_alloc(kvm->arch.cvm.rd, NO_NUMA,
		TMM_MEM_TYPE_RD, TMM_MEM_MAP_SIZE_MAX);
	if (!kvm->arch.cvm.rd) {
		kvm_err("tmi_mem_alloc for cvm rd failed: %d\n", kvm->arch.cvm.cvm_vmid);
		return -ENOMEM;
	}
	kvm->arch.is_cvm = true;
	return 0;
}

void kvm_free_rd(struct kvm *kvm)
{
	int ret;

	if (!kvm->arch.cvm.rd)
		return;

	ret = tmi_mem_free(kvm->arch.cvm.rd, NO_NUMA, TMM_MEM_TYPE_RD, TMM_MEM_MAP_SIZE_MAX);
	if (ret)
		kvm_err("tmi_mem_free for cvm rd failed: %d\n", kvm->arch.cvm.cvm_vmid);
	else
		kvm->arch.cvm.rd = 0;
}

void kvm_destroy_cvm(struct kvm *kvm)
{
	uint32_t cvm_vmid = kvm->arch.cvm.cvm_vmid;

	kfree(kvm->arch.cvm.params);
	kvm->arch.cvm.params = NULL;

	if (kvm_cvm_state(kvm) == CVM_STATE_NONE)
		return;

	cvm_vmid_release(cvm_vmid);

	WRITE_ONCE(kvm->arch.cvm.state, CVM_STATE_DYING);

	if (!tmi_cvm_destroy(kvm->arch.cvm.rd))
		kvm_info("KVM has destroyed cVM: %d\n", kvm->arch.cvm.cvm_vmid);

	kvm_free_rd(kvm);
}

static int kvm_get_host_numa_node_by_ipa(uint64_t ipa, struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_numa_info *numa_info = &vcpu->kvm->arch.cvm.numa_info;

	for (i = 0; i < numa_info->numa_cnt && i < MAX_NUMA_NODE; i++) {
		struct kvm_numa_node *numa_node = &numa_info->numa_nodes[i];

		if (ipa >= numa_node->ipa_start &&
			ipa < (numa_node->ipa_start + numa_node->ipa_size))
			return numa_node->host_numa_node;
	}
	return NO_NUMA;
}

static int kvm_cvm_ttt_create(struct cvm *cvm,
			unsigned long addr,
			int level,
			phys_addr_t phys)
{
	addr = ALIGN_DOWN(addr, cvm_ttt_level_mapsize(level - 1));
	return tmi_ttt_create(phys, cvm->rd, addr, level);
}

int kvm_cvm_create_ttt_levels(struct kvm *kvm, struct cvm *cvm,
			unsigned long ipa,
			int level,
			int max_level,
			struct kvm_mmu_memory_cache *mc)
{
	if (WARN_ON(level == max_level))
		return 0;

	while (level++ < max_level) {
		phys_addr_t ttt;

		ttt = tmi_mem_alloc(cvm->rd, NO_NUMA,
			TMM_MEM_TYPE_TTT, TMM_MEM_MAP_SIZE_MAX);
		if (ttt == 0)
			return -ENOMEM;

		if (kvm_cvm_ttt_create(cvm, ipa, level, ttt)) {
			(void)tmi_mem_free(ttt, NO_NUMA, TMM_MEM_TYPE_TTT, TMM_MEM_MAP_SIZE_MAX);
			return -ENXIO;
		}
	}

	return 0;
}

static int kvm_cvm_create_protected_data_page(struct kvm *kvm, struct cvm *cvm,
			unsigned long ipa, int level,
			struct page *src_page, phys_addr_t dst_phys)
{
	phys_addr_t src_phys;
	int ret;

	src_phys = page_to_phys(src_page);
	ret = tmi_data_create(dst_phys, cvm->rd, ipa, src_phys, level);
	if (TMI_RETURN_STATUS(ret) == TMI_ERROR_TTT_WALK) {
		/* Create missing RTTs and retry */
		int level_fault = TMI_RETURN_INDEX(ret);

		ret = kvm_cvm_create_ttt_levels(kvm, cvm, ipa, level_fault,
			level, NULL);
		if (ret)
			goto err;
		ret = tmi_data_create(dst_phys, cvm->rd, ipa, src_phys, level);
	}
	WARN_ON(ret);

	if (ret)
		goto err;

	return 0;

err:
	return -ENXIO;
}

static u64 cvm_granule_size(u32 level)
{
	return BIT(ARM64_HW_PGTABLE_LEVEL_SHIFT(level));
}

int kvm_cvm_populate_par_region(struct kvm *kvm,
			phys_addr_t ipa_base,
			phys_addr_t ipa_end,
			phys_addr_t dst_phys)
{
	struct cvm *cvm = &kvm->arch.cvm;
	struct kvm_memory_slot *memslot;
	gfn_t base_gfn, end_gfn;
	int idx;
	phys_addr_t ipa;
	int ret = 0;
	int level = TMM_TTT_LEVEL_3;
	unsigned long map_size = cvm_granule_size(level);

	base_gfn = gpa_to_gfn(ipa_base);
	end_gfn = gpa_to_gfn(ipa_end);

	idx = srcu_read_lock(&kvm->srcu);
	memslot = gfn_to_memslot(kvm, base_gfn);
	if (!memslot) {
		ret = -EFAULT;
		goto out;
	}

	/* We require the region to be contained within a single memslot */
	if (memslot->base_gfn + memslot->npages < end_gfn) {
		ret = -EINVAL;
		goto out;
	}

	mmap_read_lock(current->mm);

	ipa = ipa_base;
	while (ipa < ipa_end) {
		struct page *page;
		kvm_pfn_t pfn;

		/*
		 * FIXME: This causes over mapping, but there's no good
		 * solution here with the ABI as it stands
		 */
		ipa = ALIGN_DOWN(ipa, map_size);

		pfn = gfn_to_pfn_memslot(memslot, gpa_to_gfn(ipa));

		if (is_error_pfn(pfn)) {
			ret = -EFAULT;
			break;
		}

		page = pfn_to_page(pfn);

		ret = kvm_cvm_create_protected_data_page(kvm, cvm, ipa, level, page, dst_phys);
		if (ret)
			goto err_release_pfn;

		ipa += map_size;
		dst_phys += map_size;
		kvm_release_pfn_dirty(pfn);
err_release_pfn:
		if (ret) {
			kvm_release_pfn_clean(pfn);
			break;
		}
	}

	mmap_read_unlock(current->mm);
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

static int kvm_sel2_map_protected_ipa(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	gpa_t gpa, gpa_data_end, gpa_end, data_size;
	u64 map_size, dst_phys;
	u64 l2_granule = cvm_granule_size(2);	/* 2MB */
	u64 numa_id;
	int cur_numa_id;

	/* 2MB alignment below addresses*/
	gpa = vcpu->kvm->arch.cvm.loader_start;
	gpa_end = vcpu->kvm->arch.cvm.loader_start + vcpu->kvm->arch.cvm.ram_size;
	data_size = vcpu->kvm->arch.cvm.initrd_start - vcpu->kvm->arch.cvm.loader_start +
		vcpu->kvm->arch.cvm.initrd_size;
	data_size = round_up(data_size, l2_granule);
	gpa_data_end = vcpu->kvm->arch.cvm.loader_start + data_size + l2_granule;
	gpa = round_down(gpa, l2_granule);
	gpa_end = round_up(gpa_end, l2_granule);
	gpa_data_end = round_up(gpa_data_end, l2_granule);

	/* get numa_id */
	numa_id = kvm_get_host_numa_node_by_ipa(gpa, vcpu);
	map_size = l2_granule;
	do {
		dst_phys = tmi_mem_alloc(vcpu->kvm->arch.cvm.rd, numa_id,
			TMM_MEM_TYPE_CVM_PA, map_size);
		if (!dst_phys) {
			ret = -ENOMEM;
			kvm_err("[%s] call tmi_mem_alloc failed.\n", __func__);
			goto out;
		}

		ret = kvm_cvm_populate_par_region(vcpu->kvm, gpa, gpa + map_size, dst_phys);
		if (ret) {
			kvm_err("kvm_cvm_populate_par_region fail:%d.\n", ret);
			goto out;
		}
		gpa += map_size;
	} while (gpa < gpa_data_end);

	cur_numa_id = numa_node_id();
	if (cur_numa_id < 0) {
		ret = -EFAULT;
		kvm_err("get current numa node fail\n");
		goto out;
	}

	/* Map gpa range to secure mem without copy data from host.
	 * The cvm gpa map pages will free by destroy cvm.
	 */
	ret = tmi_ttt_map_range(vcpu->kvm->arch.cvm.rd, gpa_data_end,
		gpa_end - gpa_data_end, cur_numa_id, numa_id);
	if (ret)
		kvm_err("tmi_ttt_map_range fail:%d.\n", ret);
out:
	return ret;
}

int kvm_create_tec(struct kvm_vcpu *vcpu)
{
	int ret;
	int i;
	struct tmi_tec_params *params_ptr;
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	uint64_t mpidr = kvm_vcpu_get_mpidr_aff(vcpu);

	params_ptr = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!params_ptr)
		return -ENOMEM;

	for (i = 0; i < TEC_CREATE_NR_GPRS; ++i)
		params_ptr->gprs[i] = vcpu_regs->regs[i];

	params_ptr->pc = vcpu_regs->pc;

	if (vcpu->vcpu_id == 0)
		params_ptr->flags = TMI_RUNNABLE;
	else
		params_ptr->flags = TMI_NOT_RUNNABLE;
	params_ptr->ram_size = vcpu->kvm->arch.cvm.ram_size;
	ret = tmi_tec_create(vcpu->arch.tec.tec, vcpu->kvm->arch.cvm.rd, mpidr, __pa(params_ptr));

	kfree(params_ptr);

	return ret;
}

static int kvm_create_all_tecs(struct kvm *kvm)
{
	int ret = 0;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	if (READ_ONCE(kvm->arch.cvm.state) == CVM_STATE_ACTIVE)
		return -1;

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!vcpu->arch.tec.tec_created) {
			ret = kvm_create_tec(vcpu);
			if (ret) {
				mutex_unlock(&kvm->lock);
				return ret;
			}
			vcpu->arch.tec.tec_created = true;
		}
	}
	mutex_unlock(&kvm->lock);
	return ret;
}

static int config_cvm_sve(struct kvm *kvm, struct kvm_cap_arm_tmm_config_item *cfg)
{
	struct tmi_cvm_params *params = kvm->arch.cvm.params;

	int max_sve_vq = u64_get_bits(tmm_feat_reg0,
			  TMI_FEATURE_REGISTER_0_SVE_VL);

	if (!kvm_cvm_supports_sve())
		return -EINVAL;

	if (cfg->sve_vq > max_sve_vq)
		return -EINVAL;

	params->sve_vl = cfg->sve_vq;
	params->flags |= TMI_CVM_PARAM_FLAG_SVE;

	return 0;
}

static int config_cvm_pmu(struct kvm *kvm, struct kvm_cap_arm_tmm_config_item *cfg)
{
	struct tmi_cvm_params *params = kvm->arch.cvm.params;

	int max_pmu_num_ctrs = u64_get_bits(tmm_feat_reg0,
			  TMI_FEATURE_REGISTER_0_PMU_NUM_CTRS);

	if (!kvm_cvm_supports_pmu())
		return -EINVAL;

	if (cfg->num_pmu_cntrs > max_pmu_num_ctrs)
		return -EINVAL;

	params->pmu_num_cnts = cfg->num_pmu_cntrs;
	params->flags |= TMI_CVM_PARAM_FLAG_PMU;

	return 0;
}

static int kvm_tmm_config_cvm(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	struct kvm_cap_arm_tmm_config_item cfg;
	int r = 0;

	if (kvm_cvm_state(kvm) != CVM_STATE_NONE)
		return -EBUSY;

	if (copy_from_user(&cfg, (void __user *)cap->args[1], sizeof(cfg)))
		return -EFAULT;

	switch (cfg.cfg) {
	case KVM_CAP_ARM_TMM_CFG_SVE:
		r = config_cvm_sve(kvm, &cfg);
		break;
	case KVM_CAP_ARM_TMM_CFG_PMU:
		r = config_cvm_pmu(kvm, &cfg);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

int kvm_cvm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r = 0;

	mutex_lock(&kvm->lock);
	switch (cap->args[0]) {
	case KVM_CAP_ARM_TMM_CONFIG_CVM_HOST:
		r = kvm_tmm_config_cvm(kvm, cap);
		break;
	case KVM_CAP_ARM_TMM_CREATE_CVM:
		r = kvm_arm_create_cvm(kvm);
		break;
	default:
		r = -EINVAL;
		break;
	}
	mutex_unlock(&kvm->lock);

	return r;
}

void kvm_destroy_tec(struct kvm_vcpu *vcpu)
{
	int ret = 0;

	if (!vcpu_is_tec(vcpu))
		return;

	if (tmi_tec_destroy(vcpu->arch.tec.tec) != 0)
		kvm_err("%s vcpu id : %d failed!\n", __func__, vcpu->vcpu_id);

	ret = tmi_mem_free(vcpu->arch.tec.tec, NO_NUMA, TMM_MEM_TYPE_TEC, TMM_MEM_MAP_SIZE_MAX);
	if (ret != 0)
		kvm_err("tmi_mem_free for cvm tec failed\n");
	vcpu->arch.tec.tec = 0;
	kfree(vcpu->arch.tec.tec_run);
}

static int tmi_check_version(void)
{
	uint64_t res;
	int version_major;
	int version_minor;

	res = tmi_version();
	if (res == SMCCC_RET_NOT_SUPPORTED)
		return -ENXIO;

	version_major = TMI_ABI_VERSION_GET_MAJOR(res);
	version_minor = TMI_ABI_VERSION_GET_MINOR(res);

	if (version_major != TMI_ABI_VERSION_MAJOR) {
		kvm_err("Unsupported TMI_ABI (version %d %d)\n", version_major,
			 version_minor);
		return -ENXIO;
	}

	kvm_info("TMI ABI version %d,%d\n", version_major, version_minor);
	return 0;
}

static int kvm_kick_boot_vcpu(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;

	if (READ_ONCE(kvm->arch.cvm.state) == CVM_STATE_ACTIVE)
		return 0;

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (i == 0)
			kvm_vcpu_kick(vcpu);
	}
	mutex_unlock(&kvm->lock);
	return 0;
}

int kvm_arm_cvm_first_run(struct kvm_vcpu *vcpu)
{
	int ret = 0;

	if (READ_ONCE(vcpu->kvm->arch.cvm.state) == CVM_STATE_ACTIVE)
		return ret;

	if (vcpu->vcpu_id == 0) {
		ret = kvm_create_all_tecs(vcpu->kvm);
		if (ret != 0)
			return ret;
	} else {
		kvm_kick_boot_vcpu(vcpu->kvm);
	}

	mutex_lock(&vcpu->kvm->lock);

	if (vcpu->vcpu_id == 0) {
		ret = kvm_sel2_map_protected_ipa(vcpu);
		if (ret) {
			kvm_err("Map protected ipa failed!\n");
			goto unlock_exit;
		}
		ret = tmi_cvm_activate(vcpu->kvm->arch.cvm.rd);
		if (ret) {
			kvm_err("tmi_cvm_activate failed!\n");
			goto unlock_exit;
		}

		WRITE_ONCE(vcpu->kvm->arch.cvm.state, CVM_STATE_ACTIVE);
		kvm_info("cVM%d is activated!\n", vcpu->kvm->arch.cvm.cvm_vmid);
	}
unlock_exit:
	mutex_unlock(&vcpu->kvm->lock);

	return ret;
}

int kvm_tec_enter(struct kvm_vcpu *vcpu)
{
	struct tmi_tec_run *run = vcpu->arch.tec.tec_run;

	if (READ_ONCE(vcpu->kvm->arch.cvm.state) != CVM_STATE_ACTIVE)
		return -EINVAL;

	/* set/clear TWI TWE flags */
	if (vcpu->arch.hcr_el2 & HCR_TWI)
		run->tec_entry.flags |= TEC_ENTRY_FLAG_TRAP_WFI;
	else
		run->tec_entry.flags &= ~TEC_ENTRY_FLAG_TRAP_WFI;

	if (vcpu->arch.hcr_el2 & HCR_TWE)
		run->tec_entry.flags |= TEC_ENTRY_FLAG_TRAP_WFE;
	else
		run->tec_entry.flags &= ~TEC_ENTRY_FLAG_TRAP_WFE;

	return tmi_tec_enter(vcpu->arch.tec.tec, __pa(run));
}

int cvm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target)
{
	int ret;

	ret = tmi_psci_complete(calling->arch.tec.tec, target->arch.tec.tec);
	if (ret)
		return -EINVAL;
	return 0;
}

int kvm_arch_tec_init(struct kvm_vcpu *vcpu)
{
	vcpu->arch.tec.tec_run = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!vcpu->arch.tec.tec_run)
		return -ENOMEM;

	vcpu->arch.tec.tec = tmi_mem_alloc(vcpu->kvm->arch.cvm.rd, NO_NUMA,
		TMM_MEM_TYPE_TEC, TMM_MEM_MAP_SIZE_MAX);
	if (vcpu->arch.tec.tec == 0) {
		kvm_info("KVM tmi_mem_alloc failed:%d\n", vcpu->vcpu_id);
		return -ENOMEM;
	}
	kvm_info("KVM inits cVM VCPU:%d\n", vcpu->vcpu_id);

	return 0;
}

int kvm_init_tmm(void)
{
	int ret;

	if (PAGE_SIZE != SZ_4K)
		return 0;

	if (tmi_check_version())
		return 0;

	ret = cvm_vmid_init();
	if (ret)
		return ret;

	tmm_feat_reg0 = tmi_features(0);
	kvm_info("TMM feature0: 0x%lx\n", tmm_feat_reg0);

	static_branch_enable(&kvm_cvm_is_available);

	return 0;
}

int kvm_init_cvm_vm(struct kvm *kvm)
{
	struct tmi_cvm_params *params;

	params = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!params)
		return -ENOMEM;

	kvm->arch.cvm.params = params;

	return 0;
}

int kvm_load_user_data(struct kvm *kvm, unsigned long arg)
{
	struct kvm_user_data user_data;
	void __user *argp = (void __user *)arg;

	if (!kvm_is_cvm(kvm))
		return -EFAULT;

	if (copy_from_user(&user_data, argp, sizeof(user_data)))
		return -EFAULT;

	kvm->arch.cvm.loader_start = user_data.loader_start;
	kvm->arch.cvm.initrd_start = user_data.initrd_start;
	kvm->arch.cvm.initrd_size = user_data.initrd_size;
	kvm->arch.cvm.ram_size = user_data.ram_size;
	memcpy(&kvm->arch.cvm.numa_info, &user_data.numa_info, sizeof(struct kvm_numa_info));

	return 0;
}

void kvm_cvm_vcpu_put(struct kvm_vcpu *vcpu)
{
	kvm_timer_vcpu_put(vcpu);
	kvm_vgic_put(vcpu);
	vcpu->cpu = -1;
}
unsigned long cvm_psci_vcpu_affinity_info(struct kvm_vcpu *vcpu,
	unsigned long target_affinity, unsigned long lowest_affinity_level)
{
	struct kvm_vcpu *target_vcpu;

	if (lowest_affinity_level != 0)
		return PSCI_RET_INVALID_PARAMS;

	target_vcpu = kvm_mpidr_to_vcpu(vcpu->kvm, target_affinity);
	if (!target_vcpu)
		return PSCI_RET_INVALID_PARAMS;

	cvm_psci_complete(vcpu, target_vcpu);
	return PSCI_RET_SUCCESS;
}

int kvm_cvm_vcpu_set_events(struct kvm_vcpu *vcpu,
	bool serror_pending, bool ext_dabt_pending)
{
	if (serror_pending)
		return -EINVAL;

	if (ext_dabt_pending) {
		if (!(((struct tmi_tec_run *)vcpu->arch.tec.tec_run)->tec_entry.flags &
			TEC_ENTRY_FLAG_EMUL_MMIO))
			return -EINVAL;

		((struct tmi_tec_run *)vcpu->arch.tec.tec_run)->tec_entry.flags
				&= ~TEC_ENTRY_FLAG_EMUL_MMIO;
		((struct tmi_tec_run *)vcpu->arch.tec.tec_run)->tec_entry.flags
				|= TEC_ENTRY_FLAG_INJECT_SEA;
	}
	return 0;
}
