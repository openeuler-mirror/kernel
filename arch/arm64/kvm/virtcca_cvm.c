// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>
#include <linux/miscdevice.h>
#include <linux/nmi.h>
#include <linux/rwlock.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/arm-smccc.h>
#include <asm/kvm_tmi.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/virtcca_coda.h>
#include <asm/kvm_tmm.h>
#include <asm/stage2_pgtable.h>
#include <asm/virtcca_cvm_host.h>
#include <asm/virtcca_cvm_tsi.h>
#include <asm/virtcca_coda.h>
#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>
#include <uapi/linux/vm_sockets.h>
#include <net/sock.h>
#include <net/af_vsock.h>

/* Protects access to cvm_vmid_bitmap */
static DEFINE_SPINLOCK(cvm_vmid_lock);
static unsigned long *cvm_vmid_bitmap;
DECLARE_STATIC_KEY_FALSE(virtcca_cvm_is_enable);
static bool virtcca_vtimer_adjust;
static int virtcca_migcvm_enabled;
#define SIMD_PAGE_SIZE 0x3000
#define UEFI_MAX_SIZE 0x8000000
#define UEFI_DTB_START 0x40000000
#define DTB_MAX_SIZE 0x200000

#define SEC_CRC_PATH			"/tmp/sec_memory_check"
#define NS_CRC_PATH				"/tmp/ns_memory_check"
#define CRC_DUMP_CHUNK_SIZE		512
#define FILE_NAME_LEN			256

#define DEFAULT_IPA_START		0x40000000
#define CRC_POLYNOMIAL			0xEDB88320
#define CRC_LEN					512
#define CRC_SHIFT				8
#define MAX_MAC_PAGES_PER_ARR	256
#define MAX_BUF_PAGES			512

/* migvm vsock retry times */
#define SEND_RETRY_LIMIT		5
#define RECV_RETRY_LIMIT		5
#define CONNECT_RETRY_LIMIT		3
#define TMI_IMPORT_TIMEOUT_MS	70000
#define TMI_TRACK_TIMEOUT_MS	20

static struct virtcca_mig_capabilities g_virtcca_mig_caps;
static struct migcvm_agent_listen_cids g_migcvm_agent_listen_cid;
static uint32_t virtcca_crc32_table[CRC_LEN];

static struct crc_config g_crc_configs[2] = {
	[0] = { .is_secure = false, .enabled = false }, /* non-secure mem */
	[1] = { .is_secure = true, .enabled = false }  /* secure mem */
};

struct virtcca_usr_data_key_attr {
	uint8_t msk[DATA_KEY_MSK_LEN];
	uint8_t rand_iv[DATA_KEY_IV_LEN];
	uint8_t tag[DATA_KEY_TAG_LEN];
	uint64_t data_rand_iv;
};

static int kvm_virtcca_mig_stream_ops_init(void);
static void kvm_virtcca_mig_stream_ops_exit(void);
static int virtcca_mig_capabilities_setup(struct virtcca_cvm *cvm);
static bool virtcca_is_migration_source(struct virtcca_cvm *cvm);
static void virtcca_mig_state_release(struct virtcca_cvm *cvm);
static int virtcca_mig_state_create(struct virtcca_cvm *cvm);
static int virtcca_save_migvm_cid(struct kvm *guest_kvm, struct kvm_virtcca_mig_cmd *cmd);
static int virtcca_migvm_agent_ratstls(struct kvm *kvm, struct kvm_virtcca_mig_cmd *cmd);
static int virtcca_migvm_agent_ratstls_dst(struct kvm *kvm, struct kvm_virtcca_mig_cmd *cmd);
static int virtcca_mig_export_abort(struct kvm *kvm);
static void virtcca_crc32_init(void);
static int virtcca_mig_notify(struct kvm *kvm, struct kvm_virtcca_mig_cmd *cmd);
static int virtcca_wait_for_verifier_state(struct kvm *kvm, int expected_state);
static int virtcca_mig_verifier_register(struct kvm *kvm,
						struct virtcca_mig_dst_host_info *dst_host_info);
static int virtcca_mig_verifier_delete(struct kvm *kvm);
static int virtcca_mig_get_notify(struct virtcca_tmi_cmd *cmd);
static int virtcca_get_dstvm_rd(struct virtcca_tmi_cmd *cmd);
static int virtcca_migvm_mem_checksum_loop(struct virtcca_tmi_cmd *cmd);

bool is_virtcca_available(void)
{
	return static_key_enabled(&virtcca_cvm_is_enable);
}
EXPORT_SYMBOL_GPL(is_virtcca_available);

int kvm_enable_virtcca_cvm(struct kvm *kvm)
{
	if (!static_key_enabled(&virtcca_cvm_is_enable))
		return -EFAULT;

	kvm->arch.is_virtcca_cvm = true;
	return 0;
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

static bool kvm_cvm_supports_sve(void)
{
	return tmm_supports(TMI_FEATURE_REGISTER_0_SVE_EN);
}

static bool kvm_cvm_supports_pmu(void)
{
	return tmm_supports(TMI_FEATURE_REGISTER_0_PMU_EN);
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

/*
 * the configurable physical numa range in QEMU is 0-127,
 * but in real scenarios, 0-63 is sufficient.
 */
static u64 kvm_get_host_numa_set_by_vcpu(u64 vcpu, struct kvm *kvm)
{
	int64_t i;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct kvm_numa_info *numa_info = &cvm->numa_info;

	for (i = 0; i < numa_info->numa_cnt && i < MAX_NUMA_NODE; i++) {
		if (test_bit(vcpu, (unsigned long *)numa_info->numa_nodes[i].cpu_id))
			return numa_info->numa_nodes[i].host_numa_nodes[0];
	}
	return NO_NUMA;
}

static u64 kvm_get_first_binded_numa_set(struct kvm *kvm)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct kvm_numa_info *numa_info = &cvm->numa_info;

	if (numa_info->numa_cnt > 0)
		return numa_info->numa_nodes[0].host_numa_nodes[0];
	return NO_NUMA;
}

int kvm_arm_create_cvm(struct kvm *kvm)
{
	int ret;
	struct kvm_pgtable *pgt = kvm->arch.mmu.pgt;
	unsigned int pgd_sz;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	/* get affine host numa set by default vcpu 0 */
	u64 numa_set = kvm_get_host_numa_set_by_vcpu(0, kvm);

	if (!kvm_is_realm(kvm) || virtcca_cvm_state(kvm) != CVM_STATE_NONE)
		return 0;

	if (!cvm->params) {
		ret = -EFAULT;
		goto out;
	}

	ret = cvm_vmid_reserve();
	if (ret < 0)
		goto out;

	cvm->cvm_vmid = ret;

	pgd_sz = kvm_pgd_pages(pgt->ia_bits, pgt->start_level);

	cvm->params->ttt_level_start = kvm->arch.mmu.pgt->start_level;
	cvm->params->ttt_num_start = pgd_sz;
	cvm->params->s2sz = VTCR_EL2_IPA(kvm->arch.vtcr);
	cvm->params->vmid = cvm->cvm_vmid;
	cvm->params->ns_vtcr = kvm->arch.vtcr;
	cvm->params->vttbr_el2 = kvm->arch.mmu.pgd_phys;
	memcpy(cvm->params->rpv, &cvm->cvm_vmid, sizeof(cvm->cvm_vmid));
	cvm->rd = tmi_cvm_create(__pa(cvm->params), numa_set, virtcca_vtimer_adjust);
	if (!cvm->rd) {
		kvm_err("KVM creates cVM failed: %d\n", cvm->cvm_vmid);
		ret = -ENOMEM;
		goto out;
	}

	if (cvm->params->mig_enable) {
		ret = kvm_virtcca_mig_stream_ops_init();  /* init the migration main struct */
		if (ret) {
			kvm_err("KVM support migstream ops init failed: %d\n", cvm->cvm_vmid);
			ret = -ENOMEM;
			goto out;
		}

		ret = virtcca_mig_capabilities_setup(cvm);
		if (ret) {
			kvm_err("KVM support migration cap setup failed: %d\n", cvm->cvm_vmid);
			ret = -ENOMEM;
			goto out;
		}

		/* this state might along with the protected memory */
		ret = virtcca_mig_state_create(cvm);
		if (ret) {
			kvm_err("KVM support mig state create failed: %d\n", cvm->cvm_vmid);
			ret = -ENOMEM;
			goto out;
		}
	} else {
		pr_warn("Migration Capability is not set\n");
	}

	if (cvm->params->migration_migvm_cap) {
		if (virtcca_migcvm_enabled) {
			pr_err("Mig-CVM is already exist\n");
			ret = -EFAULT;
			goto out;
		}

		virtcca_migcvm_enabled = 1;

		cvm->mig_cvm_info = kzalloc(sizeof(struct mig_cvm), GFP_KERNEL_ACCOUNT);
		if (!cvm->mig_cvm_info) {
			ret = -ENOMEM;
			goto out;
		}
		pr_info("This CVM is Mig-CVM\n");
		cvm->mig_cvm_info->is_migcvm = 1;
	}

	WRITE_ONCE(cvm->state, CVM_STATE_NEW);
	ret = 0;
out:
	kfree(cvm->params);
	cvm->params = NULL;
	if (ret < 0) {
		kfree(cvm);
		kvm->arch.virtcca_cvm = NULL;
	}
	return ret;
}

void kvm_destroy_cvm(struct kvm *kvm)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	int ret;
	uint32_t cvm_vmid;
#ifdef CONFIG_HISI_VIRTCCA_CODA
	struct arm_smmu_domain *arm_smmu_domain;
	struct list_head smmu_domain_group_list;
#endif

	if (!kvm_is_realm(kvm) || !cvm)
		return;

	/* disable mig config and clean binding state*/
	if (cvm->mig_state) {
		virtcca_mig_state_release(cvm);
		kvm_virtcca_mig_stream_ops_exit();
		ret = tmi_bind_clean(cvm->rd);
		if (ret)
			pr_err("KVM destroy cVM mig tmi_bind_clean failed\n");
		kfree(cvm->mig_state);
	}

	kfree(cvm->mig_cvm_info);

#ifdef CONFIG_HISI_VIRTCCA_CODA
	/* Unmap the cvm with arm smmu domain */
	kvm_get_arm_smmu_domain(kvm, &smmu_domain_group_list);
	list_for_each_entry(arm_smmu_domain, &smmu_domain_group_list, node) {
		if (arm_smmu_domain && arm_smmu_domain->kvm && arm_smmu_domain->kvm == kvm)
			arm_smmu_domain->kvm = NULL;
	}
#endif

	cvm_vmid = cvm->cvm_vmid;

	if (virtcca_cvm_state(kvm) == CVM_STATE_NONE)
		return;

	WRITE_ONCE(cvm->state, CVM_STATE_DYING);

	u64 numa_set = kvm_get_first_binded_numa_set(kvm);

	if (tmi_kae_enable(cvm->rd, numa_set, 0))
		kvm_err("vf destroy failed!\n");

	do {
		touch_nmi_watchdog();
		ret = tmi_ttt_destroy(cvm->rd);
	} while (ret == TMI_ERROR_TTT_DESTROY_AGAIN);

	/*
	 * Considering that lower versions of TMM do not support
	 * the tmi_ttt_destroy interface.
	 */
	if (ret)
		pr_warn("KVM destroy cVM ttt failed\n");

	if (!tmi_cvm_destroy(cvm->rd))
		kvm_info("KVM has destroyed cVM: %d\n", cvm->cvm_vmid);

	virtcca_mig_verifier_delete(kvm);
	cvm_vmid_release(cvm_vmid);
	cvm->is_mapped = false;
	kfree(cvm);
	kvm->arch.virtcca_cvm = NULL;
}

static int kvm_cvm_ttt_create(struct virtcca_cvm *cvm,
			unsigned long addr,
			int level,
			u64 numa_set)
{
	addr = ALIGN_DOWN(addr, cvm_ttt_level_mapsize(level - 1));
	return tmi_ttt_create(numa_set, cvm->rd, addr, level);
}

static int kvm_cvm_create_ttt_levels(struct kvm *kvm, struct virtcca_cvm *cvm,
			unsigned long ipa,
			int level,
			int max_level,
			struct kvm_mmu_memory_cache *mc)
{
	int ret = 0;
	if (WARN_ON(level == max_level))
		return 0;

	while (level++ < max_level) {
		u64 numa_set = kvm_get_first_binded_numa_set(kvm);

		ret = kvm_cvm_ttt_create(cvm, ipa, level, numa_set);
		if (ret)
			return -ENXIO;
	}

	return 0;
}

static int kvm_cvm_create_protected_data_page(struct kvm *kvm, struct virtcca_cvm *cvm,
			unsigned long ipa, int level, struct page *src_page, u64 numa_set)
{
	phys_addr_t src_phys = 0;
	int ret;

	if (src_page)
		src_phys = page_to_phys(src_page);
	ret = tmi_data_create(numa_set, cvm->rd, ipa, src_phys, level);

	if (TMI_RETURN_STATUS(ret) == TMI_ERROR_TTT_WALK) {
		/* Create missing RTTs and retry */
		int level_fault = TMI_RETURN_INDEX(ret);

		ret = kvm_cvm_create_ttt_levels(kvm, cvm, ipa, level_fault,
			level, NULL);
		if (ret)
			goto err;
		ret = tmi_data_create(numa_set, cvm->rd, ipa, src_phys, level);
	}
	if (ret)
		goto err;

	return 0;

err:
	kvm_err("Cvm create protected data page fail:%d\n", ret);
	return ret;
}

static u64 cvm_granule_size(u32 level)
{
	return BIT(ARM64_HW_PGTABLE_LEVEL_SHIFT(level));
}

static bool is_data_create_region(phys_addr_t ipa_base,
			struct kvm_cap_arm_tmm_populate_region_args *args)
{
	if ((ipa_base >= args->populate_ipa_base1 &&
		ipa_base < args->populate_ipa_base1 + args->populate_ipa_size1) ||
		(ipa_base >= args->populate_ipa_base2 &&
		ipa_base < args->populate_ipa_base2 + args->populate_ipa_size2))
		return true;
	return false;
}

static int kvm_cvm_populate_par_region(struct kvm *kvm, u64 numa_set,
			phys_addr_t ipa_base, phys_addr_t ipa_end,
			struct kvm_cap_arm_tmm_populate_region_args *args)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
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
		struct page *page = NULL;
		kvm_pfn_t pfn = 0;

		/*
		 * FIXME: This causes over mapping, but there's no good
		 * solution here with the ABI as it stands
		 */
		ipa = ALIGN_DOWN(ipa, map_size);

		if (is_data_create_region(ipa, args)) {
			pfn = gfn_to_pfn_memslot(memslot, gpa_to_gfn(ipa));
			if (is_error_pfn(pfn)) {
				ret = -EFAULT;
				break;
			}

			page = pfn_to_page(pfn);
		}

		ret = kvm_cvm_create_protected_data_page(kvm, cvm, ipa, level, page, numa_set);
		if (ret)
			goto err_release_pfn;

		ipa += map_size;
		if (pfn)
			kvm_release_pfn_dirty(pfn);
err_release_pfn:
		if (ret) {
			if (pfn)
				kvm_release_pfn_clean(pfn);
			break;
		}
	}

	mmap_read_unlock(current->mm);
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

int kvm_finalize_vcpu_tec(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	int i;
	u64 numa_set;
	struct tmi_tec_params *params_ptr = NULL;
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	u64 mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	struct virtcca_cvm *cvm = vcpu->kvm->arch.virtcca_cvm;
	struct virtcca_cvm_tec *tec = &vcpu->arch.tec;

	if (tec->tec_created)
		return 0;

	mutex_lock(&vcpu->kvm->lock);
	tec->run = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!tec->run) {
		ret = -ENOMEM;
		goto tec_free;
	}
	params_ptr = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!params_ptr) {
		ret = -ENOMEM;
		goto tec_free;
	}

	for (i = 0; i < TEC_CREATE_NR_GPRS; ++i)
		params_ptr->gprs[i] = vcpu_regs->regs[i];

	params_ptr->pc = vcpu_regs->pc;

	if (vcpu->vcpu_id == 0)
		params_ptr->flags = TMI_RUNNABLE;
	else
		params_ptr->flags = TMI_NOT_RUNNABLE;
	params_ptr->ram_size = cvm->ram_size;
	numa_set = kvm_get_host_numa_set_by_vcpu(vcpu->vcpu_id, vcpu->kvm);
	tec->tec = tmi_tec_create(numa_set, cvm->rd, mpidr, __pa(params_ptr));

	tec->tec_created = true;
	kfree(params_ptr);
	mutex_unlock(&vcpu->kvm->lock);
	return ret;

tec_free:
	kfree(tec->run);
	kfree(params_ptr);
	mutex_unlock(&vcpu->kvm->lock);
	return ret;
}

static int config_cvm_hash_algo(struct tmi_cvm_params *params,
			struct kvm_cap_arm_tmm_config_item *cfg)
{
	switch (cfg->hash_algo) {
	case KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256:
		if (!tmm_supports(TMI_FEATURE_REGISTER_0_HASH_SHA_256))
			return -EINVAL;
		break;
	case KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512:
		if (!tmm_supports(TMI_FEATURE_REGISTER_0_HASH_SHA_512))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	params->measurement_algo = cfg->hash_algo;
	return 0;
}

static int config_cvm_sve(struct kvm *kvm, struct kvm_cap_arm_tmm_config_item *cfg)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct tmi_cvm_params *params;
	int max_sve_vq;

	params = cvm->params;
	max_sve_vq = u64_get_bits(tmm_feat_reg0,
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
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct tmi_cvm_params *params;
	int max_pmu_num_ctrs;

	params = cvm->params;
	max_pmu_num_ctrs = u64_get_bits(tmm_feat_reg0,
			  TMI_FEATURE_REGISTER_0_PMU_NUM_CTRS);

	if (!kvm_cvm_supports_pmu())
		return -EINVAL;

	if (cfg->num_pmu_cntrs > max_pmu_num_ctrs)
		return -EINVAL;

	params->pmu_num_cnts = cfg->num_pmu_cntrs;
	params->flags |= TMI_CVM_PARAM_FLAG_PMU;

	return 0;
}

static int config_cvm_kae(struct kvm *kvm, struct kvm_cap_arm_tmm_config_item *cfg)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct tmi_cvm_params *params;

	params = cvm->params;

	if (cfg->kae_vf_num > KVM_CAP_ARM_TMM_MAX_KAE_VF_NUM)
		return -EINVAL;

	params->kae_vf_num = cfg->kae_vf_num;
	memcpy(params->sec_addr, cfg->sec_addr, cfg->kae_vf_num * sizeof(u64));
	memcpy(params->hpre_addr, cfg->hpre_addr, cfg->kae_vf_num * sizeof(u64));

	return 0;
}

/* Get the qemu's transport migration config */
static int config_cvm_migration(struct kvm *kvm, struct kvm_cap_arm_tmm_config_item *cfg)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct tmi_cvm_params *params;

	params = cvm->params;
	params->mig_enable = cfg->mig_enable;
	params->mig_src = cfg->mig_src;
	return 0;
}

static int config_cvm_migvm(struct kvm *kvm, struct kvm_cap_arm_tmm_config_item *cfg)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct tmi_cvm_params *params;

	params = cvm->params;

	params->migration_migvm_cap = cfg->migration_migvm_cap;
	return 0;
}

static int kvm_tmm_config_cvm(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct kvm_cap_arm_tmm_config_item cfg;
	int r = 0;

	if (virtcca_cvm_state(kvm) != CVM_STATE_NONE)
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
	case KVM_CAP_ARM_TMM_CFG_HASH_ALGO:
		r = config_cvm_hash_algo(cvm->params, &cfg);
		break;
	case KVM_CAP_ARM_TMM_CFG_KAE:
		r = config_cvm_kae(kvm, &cfg);
		break;
	case KVM_CAP_ARM_TMM_CFG_MIG:	/* enable the mig config of cvm */
		r = config_cvm_migration(kvm, &cfg);
		break;
	case KVM_CAP_ARM_TMM_CFG_MIG_CVM:
		r = config_cvm_migvm(kvm, &cfg);
		break;

	default:
		r = -EINVAL;
	}

	return r;
}

int kvm_cvm_map_range(struct kvm *kvm)
{
	int ret = 0;
	u64 curr_numa_set;
	int idx;
	u64 l2_granule = cvm_granule_size(TMM_TTT_LEVEL_2);
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct kvm_numa_info *numa_info = &cvm->numa_info;
	gpa_t gpa;

	curr_numa_set = kvm_get_first_binded_numa_set(kvm);
	gpa = round_up(cvm->dtb_end, l2_granule);
	for (idx = 0; idx < numa_info->numa_cnt; idx++) {
		struct kvm_numa_node *numa_node = &numa_info->numa_nodes[idx];

		if (idx)
			gpa = numa_node->ipa_start;
		if (gpa >= numa_node->ipa_start &&
			gpa < numa_node->ipa_start + numa_node->ipa_size) {
			ret = tmi_ttt_map_range(cvm->rd, gpa,
						numa_node->ipa_size - gpa + numa_node->ipa_start,
						curr_numa_set, numa_node->host_numa_nodes[0]);
			if (ret) {
				kvm_err("tmi_ttt_map_range failed: %d.\n", ret);
				return ret;
			}
		}
	}
	/* Vfio driver will pin memory in advance,
	 * if the ram already mapped, activate cvm
	 * does not need to map twice
	 */
	cvm->is_mapped = true;
	return ret;
}


static int kvm_cvm_mig_map_range(struct kvm *kvm)
{
	int ret = 0;
	u64 curr_numa_set;
	int idx;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct kvm_numa_info *numa_info = &cvm->numa_info;
	struct kvm_numa_node *numa_node;
	gpa_t gpa;

	curr_numa_set = kvm_get_first_binded_numa_set(kvm);
	/* uefi boot */
	if (cvm->ipa_start == UEFI_LOADER_START) {
		gpa = cvm->ipa_start;
		numa_node = &numa_info->numa_nodes[0];
		ret = tmi_ttt_map_range(cvm->rd, gpa,
						UEFI_SIZE,
						curr_numa_set, numa_node->host_numa_nodes[0]);
		if (ret) {
			kvm_err("tmi_ttt_map_range failed: %d.\n", ret);
			return ret;
		}
	}

	for (idx = 0; idx < numa_info->numa_cnt; idx++) {
		numa_node = &numa_info->numa_nodes[idx];
		gpa = numa_node->ipa_start;
		if (gpa >= numa_node->ipa_start &&
			gpa < numa_node->ipa_start + numa_node->ipa_size) {
			ret = tmi_ttt_map_range(cvm->rd, gpa,
						numa_node->ipa_size,
						curr_numa_set, numa_node->host_numa_nodes[0]);
			if (ret) {
				kvm_err("tmi_ttt_map_range failed: %d.\n", ret);
				return ret;
			}
		}
	}
	/* Vfio driver will pin memory in advance,
	 * if the ram already mapped, activate cvm
	 * does not need to map twice
	 */
	cvm->is_mapped = true;
	return ret;
}


static int kvm_activate_cvm(struct kvm *kvm)
{
#ifdef CONFIG_HISI_VIRTCCA_CODA
	int ret;
	struct arm_smmu_domain *arm_smmu_domain;
	struct list_head smmu_domain_group_list;
#endif
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;

	if (cvm->mig_state) {
		if (cvm->mig_state->mig_src == VIRTCCA_MIG_DST)
			return 0;

		virtcca_mig_export_abort(kvm);
	}

	if (virtcca_cvm_state(kvm) == CVM_STATE_ACTIVE) {
		kvm_info("cVM%d is already activated!\n", cvm->cvm_vmid);
		return 0;
	}

	if (virtcca_cvm_state(kvm) != CVM_STATE_NEW)
		return -EINVAL;

	if (!cvm->is_mapped && kvm_cvm_map_range(kvm))
		return -EFAULT;

#ifdef CONFIG_HISI_VIRTCCA_CODA
	kvm_get_arm_smmu_domain(kvm, &smmu_domain_group_list);
	list_for_each_entry(arm_smmu_domain, &smmu_domain_group_list, node) {
		if (arm_smmu_domain) {
			ret = virtcca_tmi_dev_attach(arm_smmu_domain, kvm);
			if (ret)
				return ret;
		}
	}
#endif

	u64 numa_set = kvm_get_first_binded_numa_set(kvm);

	if (tmi_kae_enable(cvm->rd, numa_set, 1)) {
		kvm_err("tmi_kae_enable failed!\n");
		return -ENXIO;
	}

	if (tmi_cvm_activate(cvm->rd)) {
		kvm_err("tmi_cvm_activate failed!\n");
		return -ENXIO;
	}

	WRITE_ONCE(cvm->state, CVM_STATE_ACTIVE);
	kvm_info("cVM%d is activated!\n", cvm->cvm_vmid);
	return 0;
}

static int kvm_populate_ram_region(struct kvm *kvm, u64 map_size,
			phys_addr_t ipa_base, phys_addr_t ipa_end,
			struct kvm_cap_arm_tmm_populate_region_args *args)
{
	phys_addr_t gpa;
	u64 numa_set = kvm_get_first_binded_numa_set(kvm);

	for (gpa = ipa_base; gpa < ipa_end; gpa += map_size) {
		if (kvm_cvm_populate_par_region(kvm, numa_set, gpa, gpa + map_size, args)) {
			kvm_err("kvm_cvm_populate_par_region failed: %d\n", -EFAULT);
			return -EFAULT;
		}
	}
	return 0;
}

static int kvm_populate_ipa_cvm_range(struct kvm *kvm,
				struct kvm_cap_arm_tmm_populate_region_args *args)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	u64 l2_granule = cvm_granule_size(TMM_TTT_LEVEL_2);
	phys_addr_t ipa_base1, ipa_end2;

	/*
	 * if cvm comes from live migraion, mem is already maped.
	 * Set mig_state to VIRTCCA_MIG_SRC, init live migration structs.
	 */
	if (cvm->mig_state) {
		if (cvm->mig_state->mig_src == VIRTCCA_MIG_DST) {
			cvm->mig_state->mig_src = VIRTCCA_MIG_SRC;
			kvm_info("the ipa range is populated before migraion\n");
			return 0;
		}
	}

	if (virtcca_cvm_state(kvm) != CVM_STATE_NEW)
		return -EINVAL;
	if (!IS_ALIGNED(args->populate_ipa_base1, PAGE_SIZE) ||
		!IS_ALIGNED(args->populate_ipa_size1, PAGE_SIZE) ||
		!IS_ALIGNED(args->populate_ipa_base2, PAGE_SIZE) ||
		!IS_ALIGNED(args->populate_ipa_size2, PAGE_SIZE))
		return -EINVAL;

	if (args->populate_ipa_base2 < args->populate_ipa_base1 + args->populate_ipa_size1 ||
		cvm->dtb_end < args->populate_ipa_base2 + args->populate_ipa_size2)
		return -EINVAL;

	if (args->flags & ~TMI_MEASURE_CONTENT)
		return -EINVAL;
	ipa_base1 = round_down(args->populate_ipa_base1, l2_granule);
	ipa_end2 = round_up(args->populate_ipa_base2 + args->populate_ipa_size2, l2_granule);

	cvm->ipa_start = ipa_base1;

	/* uefi boot, uefi image and uefi ram from 0 to 128M */
	if (ipa_base1 == UEFI_LOADER_START) {
		phys_addr_t ipa_base2 = round_down(args->populate_ipa_base2, l2_granule);
		phys_addr_t ipa_end1 = round_up(args->populate_ipa_base1
			+ args->populate_ipa_size1, l2_granule);
		int uefi_ret = kvm_populate_ram_region(kvm, l2_granule, ipa_base1, ipa_end1, args);

		if (!uefi_ret) {
			uefi_ret = kvm_populate_ram_region(kvm, l2_granule, ipa_base2, ipa_end2,
				args);
		}
		return uefi_ret;
	}
	/* direct boot */
	return kvm_populate_ram_region(kvm, l2_granule, ipa_base1, ipa_end2, args);
}

int kvm_cvm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r = 0;

	switch (cap->args[0]) {
	case KVM_CAP_ARM_TMM_CONFIG_CVM_HOST:
		r = kvm_tmm_config_cvm(kvm, cap);
		break;
	case KVM_CAP_ARM_TMM_CREATE_RD:
		r = kvm_arm_create_cvm(kvm);
		break;
	case KVM_CAP_ARM_TMM_POPULATE_CVM: {
		struct kvm_cap_arm_tmm_populate_region_args args;
		void __user *argp = u64_to_user_ptr(cap->args[1]);

		if (copy_from_user(&args, argp, sizeof(args))) {
			r = -EFAULT;
			break;
		}
		r = kvm_populate_ipa_cvm_range(kvm, &args);
		break;
	}
	case KVM_CAP_ARM_TMM_ACTIVATE_CVM:
		r = kvm_activate_cvm(kvm);
		break;
	default:
		r = -EINVAL;
		break;
	}

	return r;
}

void kvm_destroy_tec(struct kvm_vcpu *vcpu)
{
	struct virtcca_cvm_tec *tec = &vcpu->arch.tec;

	if (!vcpu_is_rec(vcpu))
		return;

	if (tmi_tec_destroy(tec->tec) != 0)
		kvm_err("%s vcpu id : %d failed!\n", __func__, vcpu->vcpu_id);

	tec->tec = 0;
	kfree(tec->run);
}

static int tmi_check_version(void)
{
	u64 res;
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
	if (version_minor < TMI_ABI_VERSION_MINOR)
		virtcca_vtimer_adjust = false;
	else
		virtcca_vtimer_adjust = true;

	kvm_info("TMI ABI version %d,%d\n", version_major, version_minor);
	return 0;
}

static struct cpumask cvm_wfx_no_trap_mask;
static DEFINE_SPINLOCK(cvm_wfx_config_lock);

static ssize_t cvm_wfx_trap_config_store(struct kobject *kobj,
								struct kobj_attribute *attr,
								const char *buf, size_t count)
{
	spin_lock(&cvm_wfx_config_lock);
	if (cpumask_parse(buf, &cvm_wfx_no_trap_mask) < 0)
		return -EINVAL;
	spin_unlock(&cvm_wfx_config_lock);

	return count;
}

static ssize_t cvm_wfx_trap_config_show(struct kobject *kobj,
								struct kobj_attribute *attr,
								char *buf)
{
	int ret;

	ret = scnprintf(buf, PAGE_SIZE, "%*pb\n", cpumask_pr_args(&cvm_wfx_no_trap_mask));

	return ret;
}

static struct kobj_attribute cvm_wfx_trap_config_attr = __ATTR_RW(cvm_wfx_trap_config);

static int __init cvm_wfx_trap_config_init(void)
{
	cpumask_clear(&cvm_wfx_no_trap_mask);

	return sysfs_create_file(kernel_kobj, &cvm_wfx_trap_config_attr.attr);
}
late_initcall(cvm_wfx_trap_config_init);

int kvm_tec_enter(struct kvm_vcpu *vcpu)
{
	struct tmi_tec_run *run;
	struct virtcca_cvm_tec *tec = &vcpu->arch.tec;
	struct virtcca_cvm *cvm = vcpu->kvm->arch.virtcca_cvm;

	run = (struct tmi_tec_run *)tec->run;
	if (READ_ONCE(cvm->state) != CVM_STATE_ACTIVE)
		return -EINVAL;

	/* set/clear TWI TWE flags */
	if ((vcpu->arch.hcr_el2 & HCR_TWI) &&
		!cpumask_test_cpu(vcpu->vcpu_id, &cvm_wfx_no_trap_mask))
		run->enter.flags |= TEC_ENTRY_FLAG_TRAP_WFI;
	else
		run->enter.flags &= ~TEC_ENTRY_FLAG_TRAP_WFI;

	if ((vcpu->arch.hcr_el2 & HCR_TWE) &&
		!cpumask_test_cpu(vcpu->vcpu_id, &cvm_wfx_no_trap_mask))
		run->enter.flags |= TEC_ENTRY_FLAG_TRAP_WFE;
	else
		run->enter.flags &= ~TEC_ENTRY_FLAG_TRAP_WFE;

	return tmi_tec_enter(tec->tec, __pa(run));
}

int cvm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target, unsigned long status)
{
	int ret;
	struct virtcca_cvm_tec *calling_tec = &calling->arch.tec;
	struct virtcca_cvm_tec *target_tec = &target->arch.tec;

	ret = tmi_psci_complete(calling_tec->tec, target_tec->tec);
	if (ret)
		return -EINVAL;
	return 0;
}

void kvm_init_tmm(void)
{
	int ret;

	if (PAGE_SIZE != SZ_4K)
		return;

	if (tmi_check_version())
		return;

	if (tmi_kae_init())
		pr_warn("kvm [%i]: Warning: kae init failed!\n", task_pid_nr(current));

	ret = cvm_vmid_init();
	if (ret)
		return;

	tmm_feat_reg0 = tmi_features(0);
	kvm_info("TMM feature0: 0x%lx\n", tmm_feat_reg0);

	static_branch_enable(&kvm_rme_is_available);
	static_branch_enable(&virtcca_cvm_is_enable);

	return;
}

u64 virtcca_get_tmi_version(void)
{
	u64 res = tmi_version();

	if (res == SMCCC_RET_NOT_SUPPORTED)
		return 0;
	return res;
}

static bool is_numa_ipa_range_valid(struct kvm_numa_info *numa_info)
{
	unsigned long i;
	struct kvm_numa_node *numa_node, *prev_numa_node;

	prev_numa_node = NULL;
	for (i = 0; i < numa_info->numa_cnt; i++) {
		numa_node = &numa_info->numa_nodes[i];
		if (numa_node->ipa_start + numa_node->ipa_size < numa_node->ipa_start)
			return false;
		if (prev_numa_node &&
			numa_node->ipa_start < prev_numa_node->ipa_start + prev_numa_node->ipa_size)
			return false;
		prev_numa_node = numa_node;
	}
	if (numa_node->ipa_start + numa_node->ipa_size > CVM_IPA_MAX_VAL)
		return false;
	return true;
}

static inline bool is_dtb_info_has_extend_data(u64 dtb_info)
{
	return dtb_info & 0x1;
}

static int virtcca_get_bind_info(struct kvm *kvm, struct kvm_virtcca_mig_cmd *cmd)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct virtcca_bind_info info;
	struct arm_smccc_res ret;

	if (copy_from_user(&info, (void __user *)cmd->data,
			sizeof(struct virtcca_bind_info))) {
		return -EFAULT;
	}

	if (cmd->flags || info.version != KVM_CVM_MIGVM_VERSION)
		return -EINVAL;

	if (!virtcca_migcvm_enabled) {
		ret.a0 = virtcca_wait_for_verifier_state(kvm, VIRTCCA_MIG_KEY_UPDATED);
		if (ret.a0)
			info.premig_done = false;
		else
			info.premig_done = true;

		if (copy_to_user((void __user *)cmd->data, &info,
			sizeof(struct virtcca_bind_info))) {
			return -EFAULT;
		}

		return 0;
	}

	ret = tmi_bind_peek(cvm->rd);
	if (ret.a1 == TMI_SUCCESS) {
		if (ret.a2 == SLOT_IS_READY)
			info.premig_done = true;
		else
			info.premig_done = false;

		if (copy_to_user((void __user *)cmd->data, &info,
			sizeof(struct virtcca_bind_info))) {
			return -EFAULT;
		}
		return ret.a1;
	}

	pr_err("%s: failed, err=%lx\n", __func__, ret.a1);
	return -EIO;
}

int kvm_migcvm_ioctl(struct kvm *kvm, unsigned long arg)
{
	struct kvm_virtcca_mig_cmd cvm_cmd;
	int ret = 0;
	void __user *argp = (void __user *)arg;

	mutex_lock(&kvm->lock);
	if (copy_from_user(&cvm_cmd, argp, sizeof(struct kvm_virtcca_mig_cmd))) {
		pr_err("%s: copy from user failed", __func__);
		ret = -EINVAL;
		goto out;
	}

	if (cvm_cmd.id < KVM_CVM_MIGCVM_SET_CID || cvm_cmd.id >= KVM_CVM_MIG_STREAM_START) {
		pr_err("%s: invalid cvm_cmd.id: %u", __func__, cvm_cmd.id);
		ret = -EINVAL;
		goto out;
	}

	switch (cvm_cmd.id) {
	case KVM_CVM_MIGCVM_SET_CID:
		ret = virtcca_save_migvm_cid(kvm, &cvm_cmd);
		break;
	case KVM_CVM_MIG_NOTIFY:
		ret = virtcca_mig_notify(kvm, &cvm_cmd);
		break;
	case KVM_CVM_GET_BIND_STATUS:
		ret = virtcca_get_bind_info(kvm, &cvm_cmd);
		break;
	case KVM_CVM_MIG_EXPORT_ABORT:
		ret = virtcca_mig_export_abort(kvm);
		break;
	default:
		ret = -EINVAL;
	}
out:
	mutex_unlock(&kvm->lock);
	return ret;
}

int kvm_load_user_data(struct kvm *kvm, unsigned long arg)
{
	struct kvm_user_data user_data;
	void __user *argp = (void __user *)arg;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct kvm_numa_info *numa_info;

	if (!kvm_is_realm(kvm))
		return -EFAULT;

	if (copy_from_user(&user_data, argp, sizeof(user_data)))
		return -EINVAL;

	numa_info = &user_data.numa_info;
	if (numa_info->numa_cnt > MAX_NUMA_NODE)
		return -EINVAL;

	if (numa_info->numa_cnt > 0) {
		unsigned long i, total_size = 0;
		struct kvm_numa_node *numa_node = &numa_info->numa_nodes[0];
		unsigned long ipa_end = numa_node->ipa_start + numa_node->ipa_size;

		if (!is_numa_ipa_range_valid(numa_info))
			return -EINVAL;

		if ((user_data.loader_start != numa_node->ipa_start) ||
			(user_data.data_start + user_data.data_size < user_data.data_start))
			return -EINVAL;

		if (is_dtb_info_has_extend_data(user_data.dtb_info)) {
			/* Direct boot, check DTB address is in IPA range */
			if (user_data.data_start + user_data.data_size > ipa_end)
				return -EINVAL;
		} else {
			/*
			 * UEFI boot, check MMIO address range is within the valid limit (less than
			 * loader_start)
			 */
			if (user_data.data_start + user_data.data_size > user_data.loader_start)
				return -EINVAL;
		}

		for (i = 0; i < numa_info->numa_cnt; i++)
			total_size += numa_info->numa_nodes[i].ipa_size;
		if (total_size != user_data.ram_size)
			return -EINVAL;
	}

	if (is_dtb_info_has_extend_data(user_data.dtb_info))
		cvm->dtb_end = user_data.data_start + user_data.data_size;
	else {
		cvm->dtb_end = user_data.loader_start + user_data.dtb_info;
		cvm->mmio_start = user_data.data_start;
		cvm->mmio_end = user_data.data_start + user_data.data_size;
	}

	cvm->loader_start = user_data.loader_start;
	cvm->ram_size = user_data.ram_size;
	memcpy(&cvm->numa_info, numa_info, sizeof(struct kvm_numa_info));

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

	cvm_psci_complete(vcpu, target_vcpu, PSCI_RET_SUCCESS);
	return PSCI_RET_SUCCESS;
}

int kvm_cvm_vcpu_set_events(struct kvm_vcpu *vcpu,
	bool serror_pending, bool ext_dabt_pending)
{
	struct tmi_tec_run *run = vcpu->arch.tec.run;
	if (serror_pending)
		return -EINVAL;

	if (ext_dabt_pending) {
		if (!(run->enter.flags & REC_ENTER_FLAG_EMULATED_MMIO))
			return -EINVAL;
		run->enter.flags &= ~REC_ENTER_FLAG_EMULATED_MMIO;
		run->enter.flags |= REC_ENTER_FLAG_INJECT_SEA;
	}
	return 0;
}

int kvm_init_cvm_vm(struct kvm *kvm)
{
	struct tmi_cvm_params *params;
	struct virtcca_cvm *cvm;

	if (kvm->arch.virtcca_cvm) {
		kvm_info("cvm already create.\n");
		return 0;
	}

	cvm = (struct virtcca_cvm *)kzalloc(sizeof(struct virtcca_cvm), GFP_KERNEL_ACCOUNT);
	if (!cvm)
		return -ENOMEM;

	kvm->arch.virtcca_cvm = cvm;
	params = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!params) {
		kfree(kvm->arch.virtcca_cvm);
		kvm->arch.virtcca_cvm = NULL;
		return -ENOMEM;
	}

	cvm->params = params;
	WRITE_ONCE(cvm->state, CVM_STATE_NONE);

	kvm_enable_virtcca_cvm(kvm);
	return 0;
}

extern struct vgic_global kvm_vgic_global_state;

u32 kvm_cvm_vgic_nr_lr(void)
{
	return kvm_vgic_global_state.nr_lr;
}

static struct cca_operations virtcca_operations = {
	.enable_cap = kvm_cvm_enable_cap,
	.init_realm_vm = kvm_init_cvm_vm,
	.realm_vm_enter = kvm_tec_enter,
	.realm_vm_exit = handle_cvm_exit,
	.init_sel2_hypervisor = kvm_init_tmm,
	.psci_complete = cvm_psci_complete,
	.destroy_vm = kvm_destroy_cvm,
	.create_vcpu = kvm_finalize_vcpu_tec,
	.destroy_vcpu = kvm_destroy_tec,
	.vgic_nr_lr = kvm_cvm_vgic_nr_lr,
};

static int __init virtcca_register(void)
{
	return cca_operations_register(VIRTCCA_CVM, &virtcca_operations);
}
core_initcall(virtcca_register);

#ifdef CONFIG_HISI_VIRTCCA_CODA
/*
 * Coda (Confidential Device Assignment) feature
 * enable devices to pass directly to confidential virtual machines
 */

/**
 * is_in_virtcca_ram_range - Check if the iova belongs
 * to the cvm ram range
 * @kvm: The handle of kvm
 * @iova: Ipa address
 *
 * Returns:
 * %true if the iova belongs to cvm ram
 * %false if the iova is not within the scope of cvm ram
 */
bool is_in_virtcca_ram_range(struct kvm *kvm, uint64_t iova)
{
	if (!is_virtcca_cvm_enable())
		return false;

	struct virtcca_cvm *virtcca_cvm = kvm->arch.virtcca_cvm;

	if (iova >= virtcca_cvm->loader_start &&
		iova < virtcca_cvm->loader_start + virtcca_cvm->ram_size)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(is_in_virtcca_ram_range);

/**
 * is_virtcca_iova_need_vfio_dma - Whether the vfio need
 * to map the dma address
 * @kvm: The handle of kvm
 * @iova: Ipa address
 *
 * Returns:
 * %true if virtcca cvm ram is nort mapped or
 * virtcca_cvm_ram is mapped and the iova does not
 * belong to cvm ram range
 * %false if virtcca_cvm_ram is mapped and the iova belong
 * to cvm ram range
 */
bool is_virtcca_iova_need_vfio_dma(struct kvm *kvm, uint64_t iova)
{
	if (!is_virtcca_cvm_enable())
		return false;

	struct virtcca_cvm *virtcca_cvm = kvm->arch.virtcca_cvm;

	if (!virtcca_cvm->is_mapped)
		return true;

	return !is_in_virtcca_ram_range(kvm, iova);
}
EXPORT_SYMBOL_GPL(is_virtcca_iova_need_vfio_dma);

static int kvm_cvm_dev_ttt_create(struct virtcca_cvm *cvm,
			unsigned long addr,
			int level,
			u64 numa_set)
{
	addr = ALIGN_DOWN(addr, cvm_ttt_level_mapsize(level - 1));
	return tmi_dev_ttt_create(numa_set, cvm->rd, addr, level);
}

/* CVM create ttt level information about device */
static int kvm_cvm_create_dev_ttt_levels(struct kvm *kvm, struct virtcca_cvm *cvm,
	unsigned long ipa, int level, int max_level, struct kvm_mmu_memory_cache *mc)
{
	int ret = 0;

	while (level++ < max_level) {
		u64 numa_set = kvm_get_first_binded_numa_set(kvm);

		ret = kvm_cvm_dev_ttt_create(cvm, ipa, level, numa_set);
		if (ret)
			return -ENXIO;
	}

	return 0;
}

/**
 * cvm_map_max_level_size - MMIO Map according to largest possible granularity
 * @map_start: The start of map address
 * @map_end: The end of map address
 * @map_size: Map range
 *
 * Returns:
 * %level the map level
 * %-ENXIO if no suitable mapping level was found
 */
static int cvm_map_max_level_size(unsigned long map_start, unsigned long map_end,
	unsigned long *map_size)
{
	int level = 1;

	*map_size = tmm_granule_size(level);
	if (IS_ALIGNED(map_start, *map_size) &&
	(map_start + *map_size <= map_end))
		return level;

	level++;
	*map_size = tmm_granule_size(level);
	if (IS_ALIGNED(map_start, *map_size) &&
	(map_start + *map_size <= map_end))
		return level;

	level++;
	*map_size = tmm_granule_size(level);
	if (IS_ALIGNED(map_start, *map_size) &&
	(map_start + *map_size <= map_end))
		return level;

	pr_err("level not allow to map size\n");
	return -ENXIO;
}

/**
 * cvm_map_unmap_ipa_range - Vfio driver map or
 * unmap cvm ipa
 * @kvm: The handle of kvm
 * @ipa_base: Ipa address
 * @pa: Physical address
 * @map_size: Map range
 * @is_map: Map type
 *
 * Returns:
 * %0 if cvm map/unmap address successfully
 * %-ENXIO if map/unmap failed
 */
int cvm_map_unmap_ipa_range(struct kvm *kvm, phys_addr_t ipa_base,
	phys_addr_t pa, unsigned long map_size, uint32_t is_map)
{
	unsigned long map_start;
	unsigned long map_end;
	int level;
	struct virtcca_cvm *virtcca_cvm = kvm->arch.virtcca_cvm;
	phys_addr_t rd = virtcca_cvm->rd;
	unsigned long phys = pa;
	int ret = 0;

	map_start = ipa_base;
	map_end = map_start + map_size;
	while (map_start < map_end) {
		level = cvm_map_max_level_size(map_start, map_end, &map_size);
		if (level < 0) {
			ret = -ENXIO;
			goto err;
		}
		if (is_map)
			ret = tmi_mmio_map(rd, map_start, level, phys);
		else
			ret = tmi_mmio_unmap(rd, map_start, level);

		if (TMI_RETURN_STATUS(ret) == TMI_ERROR_TTT_WALK) {
			/* Create missing TTTs and retry */
			int level_fault = TMI_RETURN_INDEX(ret);

			if (is_map) {
				ret = kvm_cvm_create_dev_ttt_levels(kvm, virtcca_cvm, map_start,
					level_fault, CVM_TTT_MAX_LEVEL, NULL);
				if (ret)
					goto err;
				ret = tmi_mmio_map(rd, map_start, level, phys);
			} else {
				ret = tmi_mmio_unmap(rd, map_start, level_fault);
				map_size = tmm_granule_size(level_fault);
			}
		}

		if (ret)
			goto err;

		map_start += map_size;
		phys += map_size;
	}

	return 0;

err:
	if (!tmi_cvm_destroy(rd))
		kvm_info("Vfio map failed, kvm has destroyed cVM: %d\n", virtcca_cvm->cvm_vmid);
	return -ENXIO;
}

/**
 * kvm_cvm_map_ipa_mmio - Map the mmio address when page fault
 * @kvm: The handle of kvm
 * @ipa_base: Ipa address
 * @pa: Physical address
 * @map_size: Map range
 *
 * Returns:
 * %0 if cvm map address successfully
 * %-ENXIO if map failed
 */
int kvm_cvm_map_ipa_mmio(struct kvm *kvm, phys_addr_t ipa_base,
	phys_addr_t pa, unsigned long map_size)
{
	unsigned long size;
	gfn_t gfn;
	kvm_pfn_t pfn;
	struct virtcca_cvm *virtcca_cvm = kvm->arch.virtcca_cvm;
	phys_addr_t rd = virtcca_cvm->rd;
	unsigned long ipa = ipa_base;
	unsigned long phys = pa;
	int ret = 0;

	if (WARN_ON(!IS_ALIGNED(ipa, map_size)))
		return -EINVAL;

	for (size = 0; size < map_size; size += PAGE_SIZE) {
		ret = tmi_mmio_map(rd, ipa, CVM_TTT_MAX_LEVEL, phys);
		if (ret == TMI_ERROR_TTT_CREATED) {
			ret = 0;
			goto label;
		}
		if (TMI_RETURN_STATUS(ret) == TMI_ERROR_TTT_WALK) {
			/* Create missing TTTs and retry */
			int level_fault = TMI_RETURN_INDEX(ret);

			ret = kvm_cvm_create_dev_ttt_levels(kvm, virtcca_cvm, ipa, level_fault,
					CVM_TTT_MAX_LEVEL, NULL);

			if (ret)
				goto err;
			ret = tmi_mmio_map(rd, ipa, CVM_TTT_MAX_LEVEL, phys);
		}

		if (ret)
			goto err;
label:
		if (size + PAGE_SIZE >= map_size)
			break;

		ipa += PAGE_SIZE;
		gfn = gpa_to_gfn(ipa);
		pfn = gfn_to_pfn(kvm, gfn);
		kvm_set_pfn_accessed(pfn);
		kvm_release_pfn_clean(pfn);
		phys = (uint64_t)__pfn_to_phys(pfn);

	}

	return 0;

err:
	if (!tmi_cvm_destroy(rd))
		kvm_info("MMIO map failed, kvm has destroyed cVM: %d\n", virtcca_cvm->cvm_vmid);
	return -ENXIO;
}

/* Page fault map ipa */
int kvm_cvm_map_ipa(struct kvm *kvm, phys_addr_t ipa, kvm_pfn_t pfn,
	unsigned long map_size, enum kvm_pgtable_prot prot, int ret)
{
	if (!is_virtcca_cvm_enable() || !kvm_is_realm(kvm))
		return ret;

	if (kvm->arch.virtcca_cvm->mig_state &&
	kvm->arch.virtcca_cvm->mig_state->mig_src == VIRTCCA_MIG_SRC) {
		if (ipa >= kvm->arch.virtcca_cvm->swiotlb_start &&
			ipa < kvm->arch.virtcca_cvm->swiotlb_end) {
			return ret;
		}
	}

	struct page *dst_page = pfn_to_page(pfn);
	phys_addr_t dst_phys = page_to_phys(dst_page);

	if (WARN_ON(!(prot & KVM_PGTABLE_PROT_W)))
		return -EFAULT;

	if (prot & KVM_PGTABLE_PROT_DEVICE)
		return kvm_cvm_map_ipa_mmio(kvm, ipa, dst_phys, map_size);

	return 0;
}

/* Set device secure flag */
void virtcca_cvm_set_secure_flag(void *vdev, void *info)
{
	if (!is_virtcca_cvm_enable())
		return;

	if (!is_cc_dev(pci_dev_id(((struct vfio_pci_core_device *)vdev)->pdev)))
		return;

	((struct vfio_device_info *)info)->flags |= VFIO_DEVICE_FLAGS_SECURE;
}
EXPORT_SYMBOL_GPL(virtcca_cvm_set_secure_flag);

/**
 * cvm_arm_smmu_domain_set_kvm - Associate SMMU domain with CVM
 * @dev: The Device under the iommu group
 *
 * Returns:
 * %0 if smmu_domain has been associate cvm or associate cvm successfully
 * %-ENXIO if the iommu group does not have smmu domain
 */
int cvm_arm_smmu_domain_set_kvm(struct device *dev, void *data)
{
	struct kvm *kvm;
	struct iommu_domain *domain;
	struct arm_smmu_domain *arm_smmu_domain = NULL;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return -ENXIO;

	arm_smmu_domain = to_smmu_domain(domain);
	if (arm_smmu_domain->kvm)
		return 1;

	kvm = virtcca_arm_smmu_get_kvm(arm_smmu_domain);
	if (kvm && kvm_is_realm(kvm))
		arm_smmu_domain->kvm = kvm;

	return 1;
}

int virtcca_cvm_arm_smmu_domain_set_kvm(void *group)
{
	int ret;

	ret = iommu_group_for_each_dev((struct iommu_group *)group,
		(void *)NULL, cvm_arm_smmu_domain_set_kvm);
	return ret;
}

/* now bypass the migCVM, config staightly 1 is source, 2 is dest*/
static bool virtcca_is_migration_source(struct virtcca_cvm *cvm)
{
	if (!cvm || !cvm->mig_state) {
		pr_err("Error: cvm or cvm->params is NULL\n");
		return false;
	}

	if (cvm->mig_state->mig_src == VIRTCCA_MIG_SRC)
		return true;

	return false;
}

/* read the max-migs , max of rd/tec pages support */
static int virtcca_mig_capabilities_setup(struct virtcca_cvm *cvm)
{
	uint64_t res;
	uint16_t immutable_state_pages, rd_state_pages, tec_state_pages;

	res = tmi_get_mig_config();
	virtcca_crc32_init();

	g_virtcca_mig_caps.max_migs = (uint32_t)(res >> 48) & 0xFFFF;

	immutable_state_pages = (uint32_t)(res >> 32) & 0xFFFF;

	rd_state_pages = (uint32_t)(res >> 16) & 0xFFFF;

	tec_state_pages = (uint32_t)res & 0xFFFF;
	/*
	 * The minimal number of pages required. It hould be large enough to
	 * store all the non-memory states.
	 */
	g_virtcca_mig_caps.nonmem_state_pages = max3(immutable_state_pages,
		rd_state_pages, tec_state_pages);

	return 0;
}

static void virtcca_mig_stream_get_virtcca_mig_attr(struct virtcca_mig_stream *stream,
	struct kvm_dev_virtcca_mig_attr *attr)
{
	attr->version = KVM_DEV_VIRTCCA_MIG_ATTR_VERSION;
	attr->max_migs = g_virtcca_mig_caps.max_migs;
	attr->buf_list_pages = stream->buf_list_pages;
}

static int virtcca_mig_stream_get_attr(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	struct virtcca_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;

	switch (attr->group) {
	case KVM_DEV_VIRTCCA_MIG_ATTR: {
		struct kvm_dev_virtcca_mig_attr virtcca_mig_attr;

		if (attr->attr != sizeof(struct kvm_dev_virtcca_mig_attr))
			return -EINVAL;

		virtcca_mig_stream_get_virtcca_mig_attr(stream, &virtcca_mig_attr);
		if (copy_to_user(uaddr, &virtcca_mig_attr, sizeof(virtcca_mig_attr)))
			return -EFAULT;
		break;
	}
	default:
		return -EINVAL;
	}

	return 0;
}
/*  this func is to check and cut the max page num of a stream */
static int virtcca_mig_stream_set_virtcca_mig_attr(struct virtcca_mig_stream *stream,
	struct kvm_dev_virtcca_mig_attr *attr)
{
	uint32_t req_pages = attr->buf_list_pages;
	uint32_t min_pages = g_virtcca_mig_caps.nonmem_state_pages;

	if (req_pages > VIRTCCA_MIG_BUF_LIST_PAGES_MAX) {
		stream->buf_list_pages = VIRTCCA_MIG_BUF_LIST_PAGES_MAX;
		pr_warn("Cut the buf_list_npages to the max supported num\n");
	} else if (req_pages < min_pages) {
		stream->buf_list_pages = min_pages;
	} else {
		stream->buf_list_pages = req_pages;
	}

	return 0;
}

static void virtcca_crc32_init(void)
{
	for (uint32_t i = 0; i < CRC_LEN; i++) {
		uint32_t c = i;

		for (size_t j = 0; j < CRC_SHIFT; j++) {
			if (c & 1)
				c = CRC_POLYNOMIAL ^ (c >> 1);
			else
				c >>= 1;
		}
		virtcca_crc32_table[i] = c;
	}
}

static uint32_t virtcca_crc32_compute(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xFFFFFFFF;

	for (size_t i = 0; i < len; i++) {
		uint8_t index = (crc ^ data[i]) & 0xFF;

		crc = virtcca_crc32_table[index] ^ (crc >> CRC_SHIFT);
	}
	return crc ^ 0xFFFFFFFF;
}

int virtcca_config_crc(uint64_t crc_addr_start, uint64_t crc_addr_end,
					  uint64_t crc_granularity, bool is_secure)
{
	struct crc_config *config = &g_crc_configs[is_secure];
	const char *mem_type = is_secure ? SEC_MEM : NON_SEC_MEM;

	/* disable crc check */
	if (crc_granularity == 0) {
		memset(config, 0, sizeof(*config));
		pr_info("Virtcca migration %s memory crc check disabled", mem_type);
		return 0;
	}

	if (crc_addr_start >= crc_addr_end ||
		(crc_granularity != SZ_2M && crc_granularity != SZ_4K) ||
		crc_addr_end - crc_addr_start < crc_granularity) {
		pr_err("%s: invalid input parameters", __func__);
		return -EINVAL;
	}

	config->ipa_start = ALIGN(crc_addr_start, crc_granularity);
	config->ipa_end = ALIGN_DOWN(crc_addr_end, crc_granularity);
	config->granularity = crc_granularity;
	config->enabled = true;

	pr_info("Virtcca migration %s memory crc check enabled", mem_type);
	return 0;
}
EXPORT_SYMBOL_GPL(virtcca_config_crc);

static bool virtcca_is_valid_crc_params_for_cvm(struct kvm *kvm, bool is_secure)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct crc_config *config = &g_crc_configs[is_secure];
	uint64_t cvm_addr_start = is_secure ? cvm->ipa_start : cvm->swiotlb_start;
	uint64_t cvm_addr_end = is_secure ? (DEFAULT_IPA_START + cvm->ram_size) : cvm->swiotlb_end;

	if (config->ipa_start < cvm_addr_start || config->ipa_end > cvm_addr_end)
		return false;
	return true;
}

static int virtcca_prepare_crc_file(struct virtcca_cvm *cvm, char *file_name,
						   size_t name_size, bool is_secure)
{
	struct file *file_p = NULL;
	loff_t pos = 0;
	int ret = 0;
	const char *crc_file_path = is_secure ? SEC_CRC_PATH : NS_CRC_PATH;

	if (!file_name) {
		pr_err("Invalid file name");
		return -EINVAL;
	}

	snprintf(file_name, name_size, "%s_%u", crc_file_path, cvm->cvm_vmid);
	file_p = filp_open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(file_p)) {
		ret = PTR_ERR(file_p);
		pr_err("Failed to open file %s: %d\n", file_name, ret);
		return -EIO;
	}

	ret = kernel_write(file_p, "=== crc check start ===\n",
		strlen("=== crc check start ===\n"), &pos);
	if (ret < 0)
		pr_err("Failed to write file header: %d\n", ret);

	filp_close(file_p, NULL);
	return ret;
}

static int virtcca_dump_array_to_file(uint64_t *gpa_list, uint64_t *crc_result,
	int gpa_nums, char *file_name)
{
	loff_t pos = 0;
	char *buf = NULL;
	int i, len;
	int ret = 0;
	struct file *file_p = NULL;

	if (file_name == NULL) {
		pr_err("%s: invalid input.", __func__);
		return -EINVAL;
	}

	file_p = filp_open(file_name, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (IS_ERR(file_p)) {
		pr_err("%s: failed to open file", __func__);
		return -EIO;
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto cleanup;
	}

	for (i = 0; i < gpa_nums; i++) {
		len = snprintf(buf, PAGE_SIZE, "gpa = 0x%llx crc = 0x%llx\n",
						gpa_list[i], crc_result[i]);
		ret = kernel_write(file_p, buf, len, &pos);
		if (ret < 0) {
			pr_err("%s: write error at %d\n", __func__, i);
			ret = -EIO;
			goto cleanup;
		}
	}

cleanup:
	kfree(buf);
	if (file_p)
		filp_close(file_p, NULL);
	return ret;
}

static uint32_t __virtcca_execute_ns_crc_dump(struct kvm *kvm, uint64_t target_ipa,
	unsigned char *crc_buf, uint64_t crc_granularity)
{
	uint64_t crc_buf_offset = 0;
	int ret;

	while (crc_buf_offset < crc_granularity) {
		gfn_t gfn = target_ipa >> PAGE_SHIFT;
		/* The default granularity of the swiotlb range is 4K. */
		ret = kvm_read_guest_page(kvm, gfn, crc_buf + crc_buf_offset, 0, SZ_4K);
		if (ret < 0) {
			pr_err("read swiotlb page failed, ret = %d", ret);
			return 0;
		}
		crc_buf_offset += SZ_4K;
	}

	return virtcca_crc32_compute((uint8_t *)crc_buf, crc_granularity);
}

static int virtcca_execute_crc_dump(struct kvm *kvm, struct crc_config *config, char *file_name)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	uint64_t crc_granularity = config->granularity;
	uint64_t gpa_start = config->ipa_start;
	uint64_t gpa_end = config->ipa_end;
	uint64_t crc_addr = gpa_start;
	uint64_t *gpa_list = NULL;
	uint64_t *crc_result = NULL;
	unsigned char *crc_buf = NULL;
	uint64_t actual_chunk_size = 0;
	uint64_t valid_count = 0;
	int ret = 0;

	if (!file_name || !config) {
		pr_err("execute_crc_dump_new: invalid input");
		return -EINVAL;
	}

	gpa_list = kcalloc(CRC_DUMP_CHUNK_SIZE, sizeof(uint64_t), GFP_KERNEL);
	crc_result = kcalloc(CRC_DUMP_CHUNK_SIZE, sizeof(uint64_t), GFP_KERNEL);
	crc_buf = kzalloc(crc_granularity, GFP_KERNEL);
	if (!crc_result || !gpa_list || !crc_buf) {
		pr_err("execute_crc_dump_new: memory allocation failed");
		ret = -ENOMEM;
		goto cleanup;
	}

	while (crc_addr < gpa_end) {
		valid_count = 0;
		actual_chunk_size = min_t(uint64_t, CRC_DUMP_CHUNK_SIZE,
			(gpa_end - crc_addr) / crc_granularity);
		if (actual_chunk_size <= 0)
			break;
		if (config->is_secure) {
			for (int i = 0; i < actual_chunk_size; i++) {
				uint64_t addr = crc_addr + i * crc_granularity;

				if (addr >= UEFI_SIZE && addr < DEFAULT_IPA_START)
					continue; /* skip the uefi reversed area */
				gpa_list[valid_count++] = addr;
			}

			if (valid_count == 0) {
				crc_addr += actual_chunk_size * crc_granularity;
				continue;
			}
			ret = tmi_dump_checksum(cvm->rd, virt_to_phys(gpa_list),
				virt_to_phys(crc_result), crc_granularity);
			if (ret) {
				pr_err("tmi_dump_checksum failed: %d", ret);
				ret = -EIO;
				goto cleanup;
			}
		} else {
			for (int i = 0; i < actual_chunk_size; i++) {
				gpa_list[i] = crc_addr + i * crc_granularity;
				crc_result[i] = __virtcca_execute_ns_crc_dump(kvm, gpa_list[i],
					crc_buf, crc_granularity);
				valid_count++;
			}
		}

		ret = virtcca_dump_array_to_file(gpa_list, crc_result, valid_count, file_name);
		if (ret < 0) {
			pr_err("dump crc to file failed: %d", ret);
			ret = -EIO;
			goto cleanup;
		}

		memset(gpa_list, 0, actual_chunk_size * sizeof(uint64_t));
		memset(crc_result, 0, actual_chunk_size * sizeof(uint64_t));
		crc_addr += actual_chunk_size * crc_granularity;
		touch_softlockup_watchdog();
	}

	ret = 0;
cleanup:
	kfree(crc_result);
	kfree(gpa_list);
	kfree(crc_buf);
	return ret;
}

static int virtcca_dump_crc(struct kvm *kvm, bool is_secure)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct crc_config *config = &g_crc_configs[is_secure];
	char file_name[FILE_NAME_LEN];
	const char *mem_type = is_secure ? SEC_MEM : NON_SEC_MEM;
	int ret = 0;

	if (!cvm->mig_state) {
		pr_err("%s: invalid mig_state", __func__);
		return -EINVAL;
	}

	if (!config->enabled) {
		pr_err("%s disabled!", __func__);
		return 0;
	}

	if (!virtcca_is_valid_crc_params_for_cvm(kvm, config->is_secure)) {
		pr_err("%s: invalid input parameters", __func__);
		return -EINVAL;
	}

	ret = virtcca_prepare_crc_file(cvm, file_name, sizeof(file_name), config->is_secure);
	if (ret < 0) {
		pr_err("%s: create file failed", __func__);
		return -EIO;
	}

	ret = virtcca_execute_crc_dump(kvm, config, file_name);
	if (ret) {
		pr_err("%s: CRC dump execution failed", __func__);
		return -EIO;
	}

	pr_info("virtcca dump %s crc success", mem_type);
	return 0;
}

static int virtcca_mig_stream_mbmd_setup(struct virtcca_mig_mbmd *mbmd)
{
	struct page *page;
	unsigned long mbmd_size = PAGE_SIZE;
	int order = get_order(mbmd_size);

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	mbmd->data = page_address(page);
	mbmd->hpa_and_size = page_to_phys(page) | (mbmd_size - 1) << 52;

	return 0;
}

static void virtcca_mig_stream_buf_list_cleanup(struct virtcca_mig_buf_list *buf_list)
{
	int i;
	kvm_pfn_t pfn;
	struct page *page;

	if (!buf_list->entries)
		return;

	for (i = 0; i < MAX_BUF_PAGES; i++) {
		pfn = buf_list->entries[i].pfn;
		if (!pfn)
			break;
		page = pfn_to_page(pfn);
		__free_page(page);
	}
	free_page((unsigned long)buf_list->entries);
}

static int virtcca_mig_stream_buf_list_alloc(struct virtcca_mig_buf_list *buf_list)
{
	struct page *page;

	/*
	 * Allocate the buf list page, which has 512 entries pointing to up to
	 * 512 pages used as buffers to export/import migration data.
	 */
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	buf_list->entries = page_address(page);
	buf_list->hpa = page_to_phys(page);

	return 0;
}

static int virtcca_mig_stream_buf_list_setup(struct virtcca_mig_buf_list *buf_list, uint32_t npages)
{
	int i;
	struct page *page;

	if (!npages) {
		pr_err("Userspace should set_attr on the device first\n");
		return -EINVAL;
	}

	if (virtcca_mig_stream_buf_list_alloc(buf_list))
		return -ENOMEM;

	for (i = 0; i < npages; i++) {
		page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!page) {
			virtcca_mig_stream_buf_list_cleanup(buf_list);
			return -ENOMEM;
		}
		buf_list->entries[i].pfn = page_to_pfn(page);
	}

	/* Mark unused entries as invalid */
	for (i = npages; i < MAX_BUF_PAGES; i++)
		buf_list->entries[i].invalid = true;

	return 0;
}

static int virtcca_mig_stream_page_list_setup(struct virtcca_mig_page_list *page_list,
	struct virtcca_mig_buf_list *buf_list, uint32_t npages)
{
	struct page *page;
	uint32_t i;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	page_list->entries = page_address(page);
	page_list->info.pfn = page_to_pfn(page);

	/* Reuse the buffers from the buffer list for pages list */
	for (i = 0; i < npages; i++)
		page_list->entries[i] = __pfn_to_phys(buf_list->entries[i].pfn);
	page_list->info.last_entry = npages - 1;

	return 0;
}

/* this function is used to setup the page list for migration */
static int virtcca_mig_stream_gpa_list_setup(struct virtcca_mig_gpa_list *gpa_list)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	gpa_list->info.pfn = page_to_pfn(page);
	gpa_list->entries = page_address(page);

	return 0;
}

static int virtcca_mig_stream_mac_list_setup(struct virtcca_mig_mac_list *mac_list)
{
	struct page *page;

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, 0);
	if (!page)
		return -ENOMEM;

	mac_list->entries = page_address(page);
	mac_list->hpa = page_to_phys(page);

	return 0;
}

static int virtcca_mig_stream_setup(struct virtcca_mig_stream *stream, bool mig_src)
{
	int ret;

	ret = virtcca_mig_stream_mbmd_setup(&stream->mbmd);
	if (ret)
		goto err_mbmd;

	ret = virtcca_mig_stream_buf_list_setup(&stream->mem_buf_list, stream->buf_list_pages);
	if (ret)
		goto err_mem_buf_list;

	ret = virtcca_mig_stream_page_list_setup(&stream->page_list,
		&stream->mem_buf_list, stream->buf_list_pages);
	if (ret)
		goto err_page_list;

	ret = virtcca_mig_stream_gpa_list_setup(&stream->gpa_list);
	if (ret)
		goto err_gpa_list;

	ret = virtcca_mig_stream_mac_list_setup(&stream->mac_list[0]);
	if (ret)
		goto err_mac_list0;
	/*
	 * The 2nd mac list is needed only when the buf list uses more than
	 * 256 entries
	 */
	if (stream->buf_list_pages > MAX_MAC_PAGES_PER_ARR) {
		ret = virtcca_mig_stream_mac_list_setup(&stream->mac_list[1]);
		if (ret)
			goto err_mac_list1;
	}

	/* The lists used by the destination rd only */
	if (!mig_src) {
		ret = virtcca_mig_stream_buf_list_alloc(&stream->dst_buf_list);
		if (ret)
			goto err_dst_buf_list;
		ret = virtcca_mig_stream_buf_list_alloc(&stream->import_mem_buf_list);
		if (ret)
			goto err_import_mem_buf_list;
	}

	return 0;
err_import_mem_buf_list:
	free_page((unsigned long)stream->dst_buf_list.entries);
err_dst_buf_list:
	if (stream->mac_list[1].entries)
		free_page((unsigned long)stream->mac_list[1].entries);
err_mac_list1:
	free_page((unsigned long)stream->mac_list[0].entries);
err_mac_list0:
	free_page((unsigned long)stream->gpa_list.entries);
err_gpa_list:
	free_page((unsigned long)stream->page_list.entries);
err_page_list:
	virtcca_mig_stream_buf_list_cleanup(&stream->mem_buf_list);
err_mem_buf_list:
	free_page((unsigned long)stream->mbmd.data);
err_mbmd:
	pr_err("%s failed\n", __func__);
	return ret;
}

/* check the attr is enough */
static int virtcca_mig_stream_set_attr(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	struct virtcca_cvm *cvm = dev->kvm->arch.virtcca_cvm;
	struct virtcca_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;
	int ret;

	switch (attr->group) {
	case KVM_DEV_VIRTCCA_MIG_ATTR: {
		struct kvm_dev_virtcca_mig_attr virtcca_mig_attr;

		if (copy_from_user(&virtcca_mig_attr, uaddr, sizeof(virtcca_mig_attr)))
			return -EFAULT;

		if (virtcca_mig_attr.version != KVM_DEV_VIRTCCA_MIG_ATTR_VERSION)
			return -EINVAL;

		ret = virtcca_mig_stream_set_virtcca_mig_attr(stream, &virtcca_mig_attr);
		if (ret)
			break;

		ret = virtcca_mig_stream_setup(stream,
					   virtcca_is_migration_source(cvm));
		break;
	}
	default:
		return -EINVAL;
	}

	return ret;
}

static bool virtcca_mig_stream_in_mig_buf_list(uint32_t i, uint32_t max_pages)
{
	if (i >= VIRTCCA_MIG_STREAM_BUF_LIST_MAP_OFFSET &&
		i < VIRTCCA_MIG_STREAM_BUF_LIST_MAP_OFFSET + max_pages)
		return true;

	return false;
}

static vm_fault_t virtcca_mig_stream_fault(struct vm_fault *vmf)
{
	struct kvm_device *dev = vmf->vma->vm_file->private_data;
	struct virtcca_mig_stream *stream = dev->private;
	struct page *page;
	kvm_pfn_t pfn;
	uint32_t i;

	/* See linear_page_index for pgoff */
	if (vmf->pgoff == VIRTCCA_MIG_STREAM_MBMD_MAP_OFFSET) {
		page = virt_to_page(stream->mbmd.data);
	} else if (vmf->pgoff == VIRTCCA_MIG_STREAM_GPA_LIST_MAP_OFFSET) {
		page = virt_to_page(stream->gpa_list.entries);
	} else if (vmf->pgoff == VIRTCCA_MIG_STREAM_MAC_LIST_MAP_OFFSET ||
		   vmf->pgoff == VIRTCCA_MIG_STREAM_MAC_LIST_MAP_OFFSET + 1) {
		i = vmf->pgoff - VIRTCCA_MIG_STREAM_MAC_LIST_MAP_OFFSET;
		if (stream->mac_list[i].entries) {
			page = virt_to_page(stream->mac_list[i].entries);
		} else {
			pr_err("%s: mac list page %d not allocated\n", __func__, i);
			return VM_FAULT_SIGBUS;
		}
	} else if (virtcca_mig_stream_in_mig_buf_list(vmf->pgoff, stream->buf_list_pages)) {
		i = vmf->pgoff - VIRTCCA_MIG_STREAM_BUF_LIST_MAP_OFFSET;
		pfn = stream->mem_buf_list.entries[i].pfn;
		page = pfn_to_page(pfn);
	} else {
		pr_err("%s: VM_FAULT_SIGBUS\n", __func__);
		return VM_FAULT_SIGBUS;
	}

	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct virtcca_mig_stream_ops = {
	.fault = virtcca_mig_stream_fault,
};

static int virtcca_mig_stream_mmap(struct kvm_device *dev, struct vm_area_struct *vma)
{
	vma->vm_ops = &virtcca_mig_stream_ops;
	return 0;
}

static int virtcca_mig_export_state_immutable(struct kvm *kvm, struct virtcca_mig_stream *stream,
	uint64_t __user *data)
{
	struct virtcca_mig_page_list *page_list = &stream->page_list;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	union virtcca_mig_stream_info stream_info = {.val = 0};
	struct arm_smccc_res ret;

	ret = tmi_export_immutable(cvm->rd, stream->mbmd.hpa_and_size,
		page_list->info.val, stream_info.val);
	if (ret.a1 == TMI_SUCCESS) {
		stream->idx = stream->mbmd.data->migs_index;
		if (copy_to_user(data, &ret.a2, sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: failed, err=%lu\n", __func__, ret.a1);
		return -EIO;
	}
	return 0;
}

static int virtcca_mig_import_state_immutable(struct kvm *kvm, struct virtcca_mig_stream *stream,
	uint64_t __user *data)
{
	struct virtcca_mig_page_list *page_list = &stream->page_list;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	union virtcca_mig_stream_info stream_info = {.val = 0};
	struct mig_cvm_update_info *update_info = NULL;
	uint64_t ret, npages;
	int res = 0;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	page_list->info.last_entry = npages - 1;

	ret = tmi_import_immutable(cvm->rd, stream->mbmd.hpa_and_size,
		page_list->info.val, stream_info.val);
	if (ret == TMI_SUCCESS) {
		stream->idx = stream->mbmd.data->migs_index;
	} else {
		pr_err("%s: failed, err=%llu\n", __func__, ret);
		return -EIO;
	}

	update_info = kmalloc(sizeof(struct mig_cvm_update_info), GFP_KERNEL);
	if (!update_info)
		return -ENOMEM;

	ret = tmi_update_cvm_info(cvm->rd, (uint64_t)update_info);
	if (ret) {
		pr_err("tmi_update_cvm_info failed, err=%llu", ret);
		res = -EIO;
		goto out;
	}

	cvm->swiotlb_start = update_info->swiotlb_start;
	cvm->swiotlb_end = update_info->swiotlb_end;
	cvm->ipa_start = update_info->ipa_start;

	ret = kvm_cvm_mig_map_range(kvm);
	if (ret) {
		pr_err("kvm_cvm_mig_map_range: failed, err=%llu\n", ret);
		res = -EIO;
	}

out:
	kfree(update_info);
	return res;
}

static void virtcca_mig_buf_list_set_valid(struct virtcca_mig_buf_list *mem_buf_list,
						uint64_t num)
{
	int i;

	for (i = 0; i < num; i++)
		mem_buf_list->entries[i].invalid = false;

	for (i = num; i < MAX_BUF_PAGES; i++) {
		if (!mem_buf_list->entries[i].invalid)
			mem_buf_list->entries[i].invalid = true;
		else
			break;
	}
}

static int virtcca_mig_mem_param_setup(struct tmi_mig_mem *mig_mem_param)
{
	struct page *page;
	unsigned long mig_mem_param_size = PAGE_SIZE;
	int order = get_order(mig_mem_param_size);

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	mig_mem_param->data = page_address(page);
	mig_mem_param->addr_and_size = page_to_phys(page) | (mig_mem_param_size - 1) << 52;

	return 0;
}

static int64_t virtcca_mig_stream_export_mem(struct kvm *kvm,
					 struct virtcca_mig_stream *stream,
					 uint64_t __user *data)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct virtcca_mig_state *mig_state = cvm->mig_state;
	struct virtcca_mig_gpa_list *gpa_list = &stream->gpa_list;
	union virtcca_mig_stream_info stream_info = {.val = 0};

	struct tmi_mig_mem mig_mem_param = {0};
	struct tmi_mig_mem_data *mig_mem_param_data;
	uint64_t npages, gpa_list_info_val;
	struct arm_smccc_res tmi_res = { 0 };
	int ret;

	if (mig_state->bugged)
		return -EBADF;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	if (npages > stream->buf_list_pages)
		return -EINVAL;

	ret = virtcca_mig_mem_param_setup(&mig_mem_param);
	if (ret)
		goto out;

	mig_mem_param_data = mig_mem_param.data;
	if (!mig_mem_param_data) {
		ret = -ENOMEM;
		goto out;
	}

	gpa_list->info.first_entry = 0;
	gpa_list->info.last_entry = npages - 1;
	virtcca_mig_buf_list_set_valid(&stream->mem_buf_list, npages);
	stream_info.index = stream->idx;

	mig_mem_param_data->gpa_list_info = gpa_list->info.val;
	mig_mem_param_data->mig_buff_list_pa = stream->mem_buf_list.hpa;
	mig_mem_param_data->mig_cmd = stream_info.val;
	mig_mem_param_data->mbmd_hpa_and_size = stream->mbmd.hpa_and_size;
	mig_mem_param_data->mac_pa0 = stream->mac_list[0].hpa;
	mig_mem_param_data->mac_pa1 = stream->mac_list[1].hpa;

	tmi_res = tmi_export_mem(cvm->rd, mig_mem_param.addr_and_size);

	ret = tmi_res.a1;
	gpa_list_info_val = tmi_res.a2;

	if (ret == TMI_SUCCESS) {
		if (copy_to_user(data, &gpa_list_info_val, sizeof(uint64_t)))
			ret = -EFAULT;
	} else
		ret = -EIO;

out:
	if (mig_mem_param.data)
		free_pages((unsigned long)mig_mem_param.data, get_order(PAGE_SIZE));

	return ret;
}

static int virtcca_mig_stream_import_mem(struct kvm *kvm, struct virtcca_mig_stream *stream,
	uint64_t __user *data)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct virtcca_mig_state *mig_state = cvm->mig_state;
	struct virtcca_mig_gpa_list *gpa_list = &stream->gpa_list;
	union virtcca_mig_stream_info stream_info = {.val = 0};

	struct tmi_mig_mem mig_mem_param = {0};
	struct tmi_mig_mem_data *mig_mem_param_data;

	uint64_t npages = 0;
	uint64_t gpa_list_info_val = 0;
	uint64_t ret = 0;
	struct arm_smccc_res tmi_res;

	if (mig_state->bugged)
		return -EBADF;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	if (npages > stream->buf_list_pages)
		return -EINVAL;

	ret = virtcca_mig_mem_param_setup(&mig_mem_param);
	if (ret)
		goto out;

	mig_mem_param_data = mig_mem_param.data;
	if (!mig_mem_param_data) {
		ret = -ENOMEM;
		goto out;
	}

	gpa_list->info.first_entry = 0;
	gpa_list->info.last_entry = npages - 1;
	virtcca_mig_buf_list_set_valid(&stream->mem_buf_list, npages);
	stream_info.index = stream->idx;

	mig_mem_param_data->gpa_list_info = gpa_list->info.val;
	mig_mem_param_data->mig_buff_list_pa = stream->mem_buf_list.hpa;
	mig_mem_param_data->mig_cmd = stream_info.val;
	mig_mem_param_data->mbmd_hpa_and_size = stream->mbmd.hpa_and_size;
	mig_mem_param_data->mac_pa0 = stream->mac_list[0].hpa;
	mig_mem_param_data->mac_pa1 = stream->mac_list[1].hpa;

	tmi_res = tmi_import_mem(cvm->rd, mig_mem_param.addr_and_size);

	ret = tmi_res.a1;
	gpa_list_info_val = tmi_res.a2;

	if (ret == TMI_SUCCESS) {
		if (copy_to_user(data, &gpa_list_info_val, sizeof(uint64_t)))
			ret = -EFAULT;
	} else
		ret = -EIO;

out:
	if (mig_mem_param.data)
		free_pages((unsigned long)mig_mem_param.data, get_order(PAGE_SIZE));

	return ret;
}

static int virtcca_mig_memslot_param_setup(struct tmi_mig_memslot *mig_mem_param)
{
	struct page *page;
	unsigned long mig_mem_param_size = PAGE_SIZE;
	int order = get_order(mig_mem_param_size);

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	mig_mem_param->data = page_address(page);
	mig_mem_param->addr_and_size = page_to_phys(page) | (mig_mem_param_size - 1) << 52;

	return 0;
}

static void virtcca_set_tmm_memslot(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct tmi_mig_memslot mig_memslot_param = {0};
	struct tmi_mig_memslot_data *mig_memslot_param_data;
	struct page *dirty_bitmap_page;
	unsigned int dirty_bitmap_list_len;
	uint64_t dirty_bitmap_addr;
	int ret;

	if (memslot->base_gfn << PAGE_SHIFT < cvm->ipa_start)
		return;

	ret = virtcca_mig_memslot_param_setup(&mig_memslot_param);
	if (ret)
		return;

	mig_memslot_param_data = mig_memslot_param.data;
	if (!mig_memslot_param_data) {
		ret = -ENOMEM;
		return;
	}

	unsigned long bitmap_size_bytes = kvm_dirty_bitmap_bytes(memslot);

	dirty_bitmap_list_len = DIV_ROUND_UP(bitmap_size_bytes, SZ_2M);

	dirty_bitmap_addr = (uint64_t)memslot->dirty_bitmap;
	for (int i = 0; i < dirty_bitmap_list_len; i++) {
		dirty_bitmap_page = vmalloc_to_page((uint64_t *)dirty_bitmap_addr);
		mig_memslot_param_data->dirty_bitmap_list[i] = page_to_phys(dirty_bitmap_page);
		dirty_bitmap_addr += SZ_2M;
	}
	mig_memslot_param_data->base_gfn = memslot->base_gfn;
	mig_memslot_param_data->npages = memslot->npages;
	mig_memslot_param_data->memslot_id = memslot->id;

	tmi_set_tmm_memslot(cvm->rd, mig_memslot_param.addr_and_size);
}

static int virtcca_mig_export_track(struct kvm *kvm, struct virtcca_mig_stream *stream,
	uint64_t __user *data)
{
	union virtcca_mig_stream_info stream_info = {.val = 0};
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	uint64_t in_order, ret;

	if (copy_from_user(&in_order, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	stream_info.in_order = !!in_order;
	ret = tmi_export_track(cvm->rd, stream->mbmd.hpa_and_size, stream_info.val);
	if (ret != TMI_SUCCESS) {
		pr_err("%s: failed, err=%llu\n", __func__, ret);
		return -EIO;
	}
	return 0;
}

static inline bool virtcca_mig_epoch_is_start_token(struct virtcca_mig_mbmd_data *data)
{
	return data->mig_epoch == VIRTCCA_MIG_EPOCH_START_TOKEN;
}

static int virtcca_mig_import_track(struct kvm *kvm,
				struct virtcca_mig_stream *stream)
{
	union virtcca_mig_stream_info stream_info = {.val = 0};
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	uint64_t ret;

	ret = tmi_import_track(cvm->rd, stream->mbmd.hpa_and_size, stream_info.val);
	if (ret != TMI_SUCCESS) {
		pr_err("tmi_import_track failed, err=%llu\n", ret);
		return -EIO;
	}
	return 0;
}

static int virtcca_mig_import_end(struct kvm *kvm)
{
	uint64_t ret;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	unsigned long timeout = jiffies + msecs_to_jiffies(TMI_IMPORT_TIMEOUT_MS);

	if (!cvm) {
		pr_err("%s: cvm is not initialized\n", __func__);
		return -EINVAL;
	}

	do {
		ret = tmi_import_commit(cvm->rd);
		msleep(TMI_TRACK_TIMEOUT_MS);

		if (time_after(jiffies, timeout)) {
			pr_err("tmi_import_commit timeout (%d ms)", TMI_IMPORT_TIMEOUT_MS);
			ret = ETIMEDOUT;
			break;
		}
	} while (ret == TMI_IMPORT_INCOMPLETE);

	if (ret != TMI_SUCCESS) {
		pr_err("%s: failed, err=%llu\n", __func__, ret);
		return -EIO;
	}

	virtcca_mig_state_release(cvm);
	cvm->swiotlb_start = 0;
	cvm->swiotlb_end = 0;

	WRITE_ONCE(cvm->state, CVM_STATE_ACTIVE);

	return 0;
}

static int virtcca_mig_export_state_tec(struct kvm *kvm, struct virtcca_mig_stream *stream,
	uint64_t __user *data)
{
	struct kvm_vcpu *vcpu;
	struct virtcca_cvm_tec *tec;
	struct virtcca_mig_state *mig_state = kvm->arch.virtcca_cvm->mig_state;
	union virtcca_mig_stream_info stream_info = {.val = 0};
	struct arm_smccc_res ret;

	if (mig_state->vcpu_export_next_idx >= atomic_read(&kvm->online_vcpus)) {
		pr_err("%s: vcpu_export_next_idx %d >= online_vcpus %d\n",
			__func__, mig_state->vcpu_export_next_idx,
			atomic_read(&kvm->online_vcpus));
		return -EINVAL;
	}

	vcpu = kvm_get_vcpu(kvm, mig_state->vcpu_export_next_idx);
	tec = &vcpu->arch.tec;

	stream_info.index = stream->idx;


	ret = tmi_export_tec(tec->tec, stream->mbmd.hpa_and_size,
		stream->page_list.info.val, stream_info.val);

	if (ret.a1 == TMI_SUCCESS) {
		mig_state->vcpu_export_next_idx++;
		if (copy_to_user(data, &(ret.a2), sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: failed, err=%lu\n", __func__, ret.a1);
		return -EIO;
	}

	return 0;
}

static uint16_t mig_mbmd_get_vcpu_idx(struct virtcca_mig_mbmd_data *data)
{
	return *(uint16_t *)data->type_specific_info;
}

static int virtcca_mig_import_state_tec(struct kvm *kvm, struct virtcca_mig_stream *stream,
	uint64_t __user *data)
{
	struct kvm_vcpu *vcpu;
	struct virtcca_cvm_tec *tec;
	union virtcca_mig_stream_info stream_info = {.val = 0};
	uint64_t ret;
	uint64_t npages;
	uint16_t vcpu_idx;
	unsigned long timeout = jiffies + msecs_to_jiffies(TMI_IMPORT_TIMEOUT_MS);

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	stream->page_list.info.last_entry = npages - 1;

	vcpu_idx = mig_mbmd_get_vcpu_idx(stream->mbmd.data);
	vcpu = kvm_get_vcpu(kvm, vcpu_idx);
	tec = &vcpu->arch.tec;

	do {
		ret = tmi_import_tec(tec->tec, stream->mbmd.hpa_and_size,
			stream->page_list.info.val, stream_info.val);
		if (ret != TMI_SUCCESS && ret != TMI_IMPORT_INCOMPLETE) {
			pr_err("%s: failed, err=%llu\n", __func__, ret);
			return -EIO;
		}
		if (time_after(jiffies, timeout)) {
			pr_err("%s timeout (%d ms)", __func__, TMI_IMPORT_TIMEOUT_MS);
			return -ETIMEDOUT;
		}
		msleep(20);
	} while (ret == TMI_IMPORT_INCOMPLETE);

	return 0;
}

static int virtcca_mig_get_mig_info(struct kvm *kvm, uint64_t __user *data)
{
	struct virtCCAMigInfo migInfo;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;

	migInfo.swiotlb_start = cvm->swiotlb_start;
	migInfo.swiotlb_end = cvm->swiotlb_end;

	if (copy_to_user(data, &(migInfo), sizeof(struct virtCCAMigInfo)))
		return -EFAULT;

	return 0;
}

static int virtcca_mig_is_zero_page(struct kvm *kvm,
		struct virtcca_mig_stream *stream, uint64_t __user *data)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct virtcca_mig_gpa_list *gpa_list = &stream->gpa_list;

	int ret;
	struct arm_smccc_res tmi_res = { 0 };
	bool is_zero_page = false;

	tmi_res = tmi_is_zero_page(cvm->rd, gpa_list->info.val);

	ret = tmi_res.a1;
	if (tmi_res.a2)
		is_zero_page = true;

	if (ret == TMI_SUCCESS) {
		if (copy_to_user(data, &is_zero_page, sizeof(bool)))
			ret = -EFAULT;
	} else
		ret = -EIO;

	return ret;
}

static int virtcca_mig_import_zero_page(struct kvm *kvm,
		struct virtcca_mig_stream *stream, uint64_t __user *data)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct arm_smccc_res tmi_res = { 0 };
	uint64_t gpa = (uint64_t)data;
	int ret;

	tmi_res = tmi_import_zero_page(cvm->rd, gpa);

	ret = tmi_res.a1;
	if (ret) {
		pr_err("%s: err=%d\n", __func__, ret);
		ret = -EIO;
	}

	return ret;
}

static int virtcca_mig_export_pause(struct kvm *kvm,
		struct virtcca_mig_stream *stream, uint64_t __user *data)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct arm_smccc_res tmi_res = { 0 };

	tmi_res = tmi_export_pause(cvm->rd);
	if (tmi_res.a1) {
		pr_err("%s: err=%lu\n", __func__, tmi_res.a1);
		return -EIO;
	}

	return tmi_res.a1;
}

/* add qemu ioctl struct to fit this func */
static long virtcca_mig_stream_ioctl(struct kvm_device *dev, unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = dev->kvm;
	struct virtcca_mig_stream *stream = dev->private;
	void __user *argp = (void __user *)arg;
	struct kvm_virtcca_mig_cmd cvm_cmd;
	int r;

	mutex_lock(&kvm->lock);
	if (copy_from_user(&cvm_cmd, argp, sizeof(struct kvm_virtcca_mig_cmd))) {
		r = -EFAULT;
		goto out;
	}

	if (ioctl != KVM_CVM_MIG_IOCTL)
		return -EINVAL;

	switch (cvm_cmd.id) {
	case KVM_CVM_MIG_EXPORT_STATE_IMMUTABLE:
		r = virtcca_mig_export_state_immutable(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_IMPORT_STATE_IMMUTABLE:
		r = virtcca_mig_import_state_immutable(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_EXPORT_MEM:
		r = virtcca_mig_stream_export_mem(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_IMPORT_MEM:
		r = virtcca_mig_stream_import_mem(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_EXPORT_TRACK:
		r = virtcca_mig_export_track(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_IMPORT_TRACK:
		r = virtcca_mig_import_track(kvm, stream);
		break;
	case KVM_CVM_MIG_EXPORT_STATE_TEC:
		r = virtcca_mig_export_state_tec(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_IMPORT_STATE_TEC:
		r = virtcca_mig_import_state_tec(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_IMPORT_END:
		r = virtcca_mig_import_end(kvm);
		break;
	case KVM_CVM_MIG_CRC:
		r = 0;
		virtcca_dump_crc(kvm, true);
		virtcca_dump_crc(kvm, false);
		break;
	case KVM_CVM_MIG_GET_MIG_INFO:
		r = virtcca_mig_get_mig_info(kvm, (uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_IS_ZERO_PAGE:
		r = virtcca_mig_is_zero_page(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_IMPORT_ZERO_PAGE:
		r = virtcca_mig_import_zero_page(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	case KVM_CVM_MIG_EXPORT_PAUSE:
		r = virtcca_mig_export_pause(kvm, stream,
					(uint64_t __user *)cvm_cmd.data);
		break;
	default:
		r = -EINVAL;
	}

out:
	mutex_unlock(&kvm->lock);
	return r;
}

static int virtcca_mig_do_stream_create(struct kvm *kvm,
	struct virtcca_mig_stream *stream, hpa_t *migsc_addr)
{
	u64 numa_set = kvm_get_host_numa_set_by_vcpu(0, kvm);
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	hpa_t migsc_pa = 0;
	struct mig_cvm_update_info *update_info = NULL;
	uint64_t ret = 0;

	if (!migsc_addr) {
		pr_err("invalid migsc_addr!");
		return -1;
	}

	/* now just create stream in tmm */
	migsc_pa = tmi_mig_stream_create(cvm->rd, numa_set);
	if (!migsc_pa)
		kvm_err("virtcca mig stream create failed!\n");

	*migsc_addr = migsc_pa;

	update_info = kmalloc(sizeof(struct mig_cvm_update_info), GFP_KERNEL);
	if (!update_info)
		return -ENOMEM;

	ret = tmi_update_cvm_info(cvm->rd, (uint64_t)update_info);
	if (ret) {
		pr_err("tmi_update_cvm_info failed, err=%llu", ret);
		kfree(update_info);
		return -EIO;
	}
	cvm->swiotlb_start = update_info->swiotlb_start;
	cvm->swiotlb_end = update_info->swiotlb_end;

	kfree(update_info);
	return 0;
}

static int virtcca_mig_session_init(struct kvm *kvm)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct virtcca_mig_state *mig_state = cvm->mig_state;
	struct virtcca_mig_gpa_list *blockw_gpa_list = &mig_state->blockw_gpa_list;
	int ret = 0;

	if (virtcca_mig_do_stream_create(kvm, &mig_state->backward_stream,
		&mig_state->backward_migsc_paddr))
		return -EIO;

	if (virtcca_is_migration_source(cvm))
		ret = virtcca_mig_stream_gpa_list_setup(blockw_gpa_list);

	return ret;
}

static void virtcca_mig_session_exit(struct virtcca_mig_state *mig_state)
{
	if (mig_state->blockw_gpa_list.entries) {
		free_pages((uint64_t)mig_state->blockw_gpa_list.entries, 0);
		mig_state->blockw_gpa_list.entries = NULL;
		mig_state->blockw_gpa_list.info.pfn = 0;
	}
}

static int virtcca_mig_stream_create(struct kvm_device *dev, u32 type)
{
	struct kvm *kvm = dev->kvm;
	struct virtcca_cvm *cvm = dev->kvm->arch.virtcca_cvm;
	struct virtcca_mig_state *mig_state = cvm->mig_state;
	struct virtcca_mig_stream *stream;
	int ret;

	stream = kzalloc(sizeof(struct virtcca_mig_stream), GFP_KERNEL_ACCOUNT);
	if (!stream)
		return -ENOMEM;

	dev->private = stream;
	/* set the stream idx of the cvm */
	stream->idx = atomic_inc_return(&mig_state->streams_created) - 1;

	if (stream->idx > 0) {
		atomic_set(&mig_state->streams_created, 0);
		mig_state->vcpu_export_next_idx = 0;
		stream->idx = 0;
	}

	if (!stream->idx) {
		ret = virtcca_mig_session_init(kvm); /* if is the first stream, call this func */
		if (ret)
			goto err_mig_session_init;
		mig_state->default_stream = stream;
	}

	ret = virtcca_mig_do_stream_create(kvm, stream, &mig_state->migsc_paddrs[stream->idx]);
	if (ret)
		goto err_stream_create;

	return 0;
err_stream_create:
	virtcca_mig_session_exit(mig_state);
err_mig_session_init:
	atomic_dec(&mig_state->streams_created);
	kfree(stream);
	return ret;
}

static void virtcca_mig_state_release(struct virtcca_cvm *cvm)
{
	struct virtcca_mig_state *mig_state = cvm->mig_state;

	if (!mig_state)
		return;

	mig_state->vcpu_export_next_idx = 0;
	mig_state->backward_migsc_paddr = 0;

	atomic_dec(&mig_state->streams_created);
	if (!atomic_read(&mig_state->streams_created))
		virtcca_mig_session_exit(mig_state);
}


static void virtcca_mig_stream_release(struct kvm_device *dev)
{
	struct virtcca_mig_stream *stream = dev->private;

	free_page((unsigned long)stream->mbmd.data);
	virtcca_mig_stream_buf_list_cleanup(&stream->mem_buf_list);
	free_page((unsigned long)stream->page_list.entries);
	free_page((unsigned long)stream->gpa_list.entries);
	free_page((unsigned long)stream->mac_list[0].entries);
	/*
	 * The 2nd mac list page is allocated conditionally when
	 * stream->buf_list_pages is larger than 256.
	 */
	if (stream->mac_list[1].entries)
		free_page((unsigned long)stream->mac_list[1].entries);
	if (stream->dst_buf_list.entries)
		free_page((unsigned long)stream->dst_buf_list.entries);
	if (stream->import_mem_buf_list.entries)
		free_page((unsigned long)stream->import_mem_buf_list.entries);
	/*print the elements of the stream*/
	kfree(stream);
}

static int virtcca_mig_state_create(struct virtcca_cvm *cvm)
{
	struct virtcca_mig_state *mig_state = cvm->mig_state;
	hpa_t *migsc_paddrs = NULL;

	mig_state = NULL;
	cvm->mig_cvm_info = NULL;
	mig_state = kzalloc(sizeof(struct virtcca_mig_state), GFP_KERNEL_ACCOUNT);
	if (!mig_state)
		goto out;

	migsc_paddrs = kcalloc(g_virtcca_mig_caps.max_migs, sizeof(hpa_t), GFP_KERNEL_ACCOUNT);
	if (!migsc_paddrs)
		goto out;

	cvm->mig_cvm_info = kzalloc(sizeof(struct mig_cvm), GFP_KERNEL_ACCOUNT);
	mig_state->mig_src = cvm->params->mig_src;
	if (!cvm->mig_cvm_info)
		goto out;

	mig_state->migsc_paddrs = migsc_paddrs;
	cvm->mig_state = mig_state;

	return 0;

out:
	kfree(mig_state);
	kfree(migsc_paddrs);
	kfree(cvm->mig_cvm_info);
	return -ENOMEM;
}

static int virtcca_save_migvm_cid(struct kvm *kvm, struct kvm_virtcca_mig_cmd *cmd)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct mig_cvm *mig_cvm_usr;
	struct mig_cvm *mig_cvm_info = cvm->mig_cvm_info;

	if (mig_cvm_info == NULL) {
		pr_info("guest_mig_cvm_info is NULL\n");
		return -EINVAL;
	}

	mig_cvm_usr = kmalloc(sizeof(struct mig_cvm), GFP_KERNEL);
	if (!mig_cvm_usr)
		return -ENOMEM;
	if (copy_from_user(mig_cvm_usr, (void __user *)cmd->data,
			sizeof(struct mig_cvm))) {
		kfree(mig_cvm_usr);
		return -EFAULT;
	}

	if (cmd->flags || mig_cvm_usr->version != KVM_CVM_MIGVM_VERSION) {
		kfree(mig_cvm_usr);
		return -EINVAL;
	}

	memcpy(&mig_cvm_info->migvm_cid, &mig_cvm_usr->migvm_cid, sizeof(uint64_t));
	g_migcvm_agent_listen_cid.cid = mig_cvm_info->migvm_cid;

	kfree(mig_cvm_usr);
	return 0;
}

static int send_and_wait_ack(struct socket *sock, struct bind_msg_s *req_msg)
{
	int ret;
	struct kvec vec;
	struct msghdr hdr;
	struct bind_msg_s ack_msg = {0};
	int retry = 0;

	memset(&hdr, 0, sizeof(hdr));
	vec.iov_base = req_msg;
	vec.iov_len = sizeof(*req_msg);
	/* set vsock hdr */
	hdr.msg_flags = MSG_NOSIGNAL;
	iov_iter_kvec(&hdr.msg_iter, WRITE, &vec, 1, vec.iov_len);

	if (req_msg->payload_len > MAX_PAYLOAD_SIZE) {
		pr_err("Payload size %u exceeds limit\n", req_msg->payload_len);
		ret = -EINVAL;
		goto out;
	}

	/* send request to migcvm agent, expect ack from migcvm agent */
	retry = 0;
	do {
		ret = kernel_sendmsg(sock, &hdr, &vec, 1, vec.iov_len);
		if (ret == -EINTR) {
			pr_warn("sendmsg interrupted by signal, retry %d\n", retry);
			retry++;
			continue;
		}
		break;
	} while (retry < SEND_RETRY_LIMIT);

	if (ret < 0) {
		pr_err("Failed to send request, ret=%d\n", ret);
		goto out;
	} else if (ret != sizeof(*req_msg)) {
		pr_err("Partial send, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

	/* reset ack buffer */
	vec.iov_base = &ack_msg;
	vec.iov_len = sizeof(ack_msg);

	retry = 0;
	do {
		ret = kernel_recvmsg(sock, &hdr, &vec, 1, sizeof(ack_msg), hdr.msg_flags);
		if (ret == -EINTR) {
			pr_warn("recvmsg interrupted by signal, retry %d\n", retry);
			retry++;
			continue;
		}
		break;
	} while (retry < RECV_RETRY_LIMIT);

	if (ret < 0) {
		pr_err("Failed to recv ack, ret=%d\n", ret);
		goto out;
	} else if (ret != sizeof(ack_msg)) {
		pr_err("Partial ack recv ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

	/* validate ack message */
	if (ack_msg.payload_type != VSOCK_MSG_ACK ||
		ack_msg.session_id != req_msg->session_id ||
		ack_msg.success == 0) {
		pr_err("ACK validation failed, the payload_type=%d, session_id=%llu, success=%d\n",
			   ack_msg.payload_type, ack_msg.session_id, ack_msg.success);
		ret = -EPROTO;
		goto out;
	}
	pr_info("ACK validation passed\n");
	ret = 0;

out:
	return ret;
}

/* vsock connection*/
/* step 1: send to mig-cvm agent: the migrated rd, the destination platform ip*/
/* step 2: wait for mig-cvm agent's response */
static int notify_migcvm_agent(uint64_t cid, struct virtcca_mig_dst_host_info *dst_host_info,
							   uint64_t guest_rd, bool is_src)
{
	struct socket *sock = NULL;
	int ret = 0;
	int retry_count = 3;
	int error = 0, len = sizeof(error);
	int connect_retry = 0;
	long old_sndtimeo = 0, old_rcvtimeo = 0;
	const unsigned long timeout = 5 * HZ;

	struct sockaddr_vm sa = {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = is_src ? MIGCVM_AGENT_PORT_SRC : MIGCVM_AGENT_PORT_DST
	};
	struct bind_msg_s bind_msg = {0};

	ret = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &sock);
	if (ret < 0) {
		pr_err("Failed to create socket, error: %d\n", ret);
		return ret;
	}

	/* save original receive timeout, and set 5s timeout for migcvm ack */
	if (sock->sk) {
		old_sndtimeo = sock->sk->sk_sndtimeo;
		old_rcvtimeo = sock->sk->sk_rcvtimeo;
		sock->sk->sk_sndtimeo = timeout;
		sock->sk->sk_rcvtimeo = timeout;
	}

	connect_retry = 0;
	do {
		ret = kernel_connect(sock, (struct sockaddr *)&sa, sizeof(sa), O_NONBLOCK);
		if (ret == -EINTR) {
			pr_warn("connect interrupted by signal, retry %d\n", connect_retry);
			schedule_timeout_uninterruptible(HZ / 10);
			connect_retry++;
			continue;
		}
		break;
	} while (connect_retry < CONNECT_RETRY_LIMIT);

	if (ret < 0) {
		if (sock->ops && sock->ops->getsockopt)
			sock->ops->getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&error, &len);
		if (error) {
			pr_err("Connect failed (cid=%llu, port=%d, err=%d)\n",
				   cid, sa.svm_port, error);
			ret = -error;
			goto cleanup;
		}
	}

	if (strscpy(bind_msg.cmd, is_src ? "START_CLIENT" : "START_SERVER",
				sizeof(bind_msg.cmd)) < 0) {
		pr_err("Command string too long\n");
		ret = -EINVAL;
		goto cleanup;
	}

	bind_msg.session_id = get_jiffies_64();
	bind_msg.payload_type = is_src ? PAYLOAD_TYPE_ALL : PAYLOAD_TYPE_ULL;
	bind_msg.payload.ull_payload = guest_rd;
	bind_msg.payload_len = MAX_PAYLOAD_SIZE;
	if (is_src) {
		if (!dst_host_info) {
			pr_err("No destination host info provided for source\n");
			ret = -EINVAL;
			goto cleanup;
		}
		bind_msg.payload_len = strlen(dst_host_info->dst_ip) + 1;
		if (strscpy(bind_msg.payload.char_payload, dst_host_info->dst_ip,
			sizeof(bind_msg.payload.char_payload)) < 0) {
			pr_err("Destination IP too long\n");
			ret = -EINVAL;
			goto cleanup;
		}
	}

	do {
		ret = send_and_wait_ack(sock, &bind_msg);
		if (!ret)
			break;
		pr_warn("Send/ACK failed, retrying (%d left)\n", retry_count - 1);
		retry_count--;
		/* a delay time */
		schedule_timeout_uninterruptible(HZ / 10);
	} while (retry_count > 0);

	if (ret)
		pr_err("Failed to get bind info after retries, error=%d\n", ret);

cleanup:
	if (sock) {
		if (sock->sk) {
			sock->sk->sk_sndtimeo = old_sndtimeo;
			sock->sk->sk_rcvtimeo = old_rcvtimeo;
		}
		if (ret == 0)
			kernel_sock_shutdown(sock, SHUT_RDWR);
		sock_release(sock);
	}
	return ret;
}

static int virtcca_migvm_agent_ratstls_dst(struct kvm *kvm, struct kvm_virtcca_mig_cmd *cmd)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct virtcca_mig_dst_host_info dst_info;
	struct arm_smccc_res tmi_ret;
	int ret = 0;

	if (g_migcvm_agent_listen_cid.cid == 0) {
		pr_err("there is no cid of migcvm, cannot migrate virtCCA cVM\n");
		return -EINVAL;
	}

	if (copy_from_user(&dst_info, (void __user *)cmd->data,
		sizeof(struct virtcca_mig_dst_host_info))) {
		return -EFAULT;
	}

	if (cmd->flags || dst_info.version != KVM_CVM_MIGVM_VERSION) {
		pr_err("invalid flags or version, flags is %u, version is %u\n",
			cmd->flags, dst_info.version);
		return -EINVAL;
	}
	/* check if the slot is binded*/
	tmi_ret = tmi_bind_peek(cvm->rd);
	if (tmi_ret.a1 == TMI_SUCCESS) {
		if (tmi_ret.a2 <= SLOT_NOT_BINDED) {
			pr_err("%s: failed, err=%lu\n", __func__, tmi_ret.a1);
			return -EINVAL;
		}
	} else {
		pr_err("%s: failed, err=%lu\n", __func__, tmi_ret.a1);
		return -EINVAL;
	}

	ret = notify_migcvm_agent(g_migcvm_agent_listen_cid.cid, NULL, cvm->rd, false);
	if (ret != 0) {
		pr_err("%s: notify_migcvm_agent failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	return ret;
}

static int virtcca_migvm_agent_ratstls(struct kvm *kvm, struct kvm_virtcca_mig_cmd *cmd)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct virtcca_mig_dst_host_info dst_info;
	struct arm_smccc_res tmi_ret;
	int ret = 0;

	if (g_migcvm_agent_listen_cid.cid == 0) {
		pr_err("there is no cid of migcvm, cannot migrate virtCCA cVM\n");
		return -EINVAL;
	}

	if (copy_from_user(&dst_info, (void __user *)cmd->data,
		sizeof(struct virtcca_mig_dst_host_info))) {
		return -EFAULT;
	}

	if (cmd->flags || dst_info.version != KVM_CVM_MIGVM_VERSION) {
		pr_err("invalid flags or version, flags is %u, version is %u\n",
			cmd->flags, dst_info.version);
		return -EINVAL;
	}

	/* now the dst ip is none, and dst port is 0,
	 * it should be add check into this (after qemu input)
	 */
	if (!cvm->mig_cvm_info)
		return -EINVAL;

	if (strscpy(cvm->mig_cvm_info->dst_ip, dst_info.dst_ip,
		sizeof(cvm->mig_cvm_info->dst_ip)) < 0) {
		pr_err("save dst_ip failed\n");
		return -EINVAL;
	}
	cvm->mig_cvm_info->dst_port = dst_info.dst_port;
	/* check if the slot is binded*/
	tmi_ret = tmi_bind_peek(cvm->rd);
	if (tmi_ret.a1 == TMI_SUCCESS) {
		if (tmi_ret.a2 <= SLOT_NOT_BINDED) {
			pr_err("%s: failed, err=%lu\n", __func__, tmi_ret.a1);
			return -EINVAL;
		}
	} else {
		pr_err("%s: failed, err=%lu\n", __func__, tmi_ret.a1);
		return -EINVAL;
	}

	ret = notify_migcvm_agent(g_migcvm_agent_listen_cid.cid, &dst_info, cvm->rd, true);
	if (ret != 0) {
		pr_info("%s: notify_migcvm_agent failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}
	return ret;
}

static struct kvm_device_ops kvm_virtcca_mig_stream_ops = {
	.name = "kvm-virtcca-mig-stream",
	.get_attr = virtcca_mig_stream_get_attr,
	.set_attr = virtcca_mig_stream_set_attr,
	.mmap = virtcca_mig_stream_mmap,
	.ioctl = virtcca_mig_stream_ioctl,
	.create = virtcca_mig_stream_create,
	.destroy = virtcca_mig_stream_release,
};

static atomic_t g_mig_streams_used = ATOMIC_INIT(0);

static int kvm_virtcca_mig_stream_ops_init(void)
{
	int ret = 0;

	if (!atomic_read(&g_mig_streams_used))
		ret = kvm_register_device_ops(&kvm_virtcca_mig_stream_ops,
			KVM_DEV_TYPE_VIRTCCA_MIG_STREAM);

	if (!ret)
		atomic_inc(&g_mig_streams_used);

	return ret;
}

static void kvm_virtcca_mig_stream_ops_exit(void)
{
	atomic_dec(&g_mig_streams_used);
	if (!atomic_read(&g_mig_streams_used))
		kvm_unregister_device_ops(KVM_DEV_TYPE_VIRTCCA_MIG_STREAM);
}

static void virtcca_enable_log_dirty(struct kvm *kvm, uint64_t start, uint64_t end)
{
	struct arm_smccc_res res;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;

	res = tmi_mem_region_protect(cvm->rd, start, end);
	if (res.a1 != 0)
		pr_err("tmi_mem_region_protect failed!\n");
}

static int virtcca_mig_export_abort(struct kvm *kvm)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	phys_addr_t target_ipa = cvm->swiotlb_start;
	struct kvm_pgtable *pgt = kvm->arch.mmu.pgt;
	int level;
	uint64_t granule;
	uint64_t ret = 0;

	ret = tmi_export_abort(cvm->rd);
	if (ret) {
		pr_err("%s: err=%llu\n", __func__, ret);
		return -EIO;
	}

	if (target_ipa == 0)
		return 0;

	while (target_ipa < cvm->swiotlb_end) {
		ret = kvm_pgtable_get_leaf(pgt, target_ipa, NULL, &level);
		if (ret) {
			pr_err("%s: err=%llu\n", __func__, ret);
			ret = -EIO;
			break;
		}

		granule = kvm_granule_size(level);
		ret = virtcca_stage2_update_leaf_attrs(pgt, target_ipa, granule,
		KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R | KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W, 0, NULL, NULL, 0);
		if (ret) {
			pr_err("%s: err=%llu\n", __func__, ret);
			ret = -EIO;
			break;
		}

		kvm_call_hyp(__kvm_tlb_flush_vmid_ipa_nsh, pgt->mmu, target_ipa, level);
		target_ipa += granule;
	}

	virtcca_mig_state_release(cvm);
	cvm->swiotlb_start = 0;
	cvm->swiotlb_end = 0;

	return ret;
}

static int virtcca_kvm_alloc_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	unsigned long dirty_bytes = kvm_dirty_bitmap_bytes(memslot);
	unsigned long dirty_bitmap_size = ALIGN(dirty_bytes, SZ_2M);
	int current_node;

	current_node = numa_node_id();
	if (current_node < 0) {
		pr_err("Failed to get current NUMA node.");
		return -EINVAL;
	}

	memslot->dirty_bitmap = __vmalloc_node_range(dirty_bitmap_size * 2, SZ_2M,
								VMALLOC_START, VMALLOC_END, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL,
								VM_ALLOW_HUGE_VMAP, current_node, __builtin_return_address(0));
	if (!memslot->dirty_bitmap)
		return -ENOMEM;

	return 0;
}

int virtcca_kvm_prepare_dirty_bitmap(struct kvm *kvm, void *new)
{
	int r;
	struct kvm_memory_slot *memslot = (struct kvm_memory_slot *)new;

	r = virtcca_kvm_alloc_dirty_bitmap(memslot);
	if (r)
		return r;

	virtcca_set_tmm_memslot(kvm, memslot);
	if (kvm_dirty_log_manual_protect_and_init_set(kvm))
		bitmap_set(memslot->dirty_bitmap, 0, memslot->npages);
	return 0;
}

void virtcca_kvm_enable_log_dirty(struct kvm *kvm, void *new, bool *flush)
{
	struct kvm_memory_slot *memslot = (struct kvm_memory_slot *)new;

	if (!kvm_is_realm(kvm))
		return;

	spin_lock((spinlock_t *)&(kvm)->mmu_lock);

	phys_addr_t start = (memslot->base_gfn) << PAGE_SHIFT;
	phys_addr_t end = (memslot->base_gfn + memslot->npages) << PAGE_SHIFT;

	*flush = true;
	virtcca_enable_log_dirty(kvm, start, end);

	spin_unlock((spinlock_t *)&(kvm)->mmu_lock);
}

bool virtcca_kvm_is_realm(struct kvm *kvm)
{
	return kvm_is_realm(kvm);
}

bool virtcca_kvm_adjust_dirty_log_range(struct kvm *kvm, phys_addr_t *start, phys_addr_t *end)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;

	if (*end <= cvm->ipa_start || *start >= cvm->ipa_start + cvm->ram_size)
		return true;

	if (*start >= cvm->swiotlb_end || *end <= cvm->swiotlb_start)
		return false;
	*start = (*start < cvm->swiotlb_start) ? cvm->swiotlb_start : *start;
	*end = (*end < cvm->swiotlb_end) ? *end : cvm->swiotlb_end;

	return false;
}

static LIST_HEAD(virtcca_mig_verifier_list);
static DEFINE_RWLOCK(verifier_list_rwlock);
#define VIRTCCA_MIG_STATE_WAIT_TIMEOUT 3000

int virtcca_mig_verifier_register(struct kvm *kvm, struct virtcca_mig_dst_host_info *dst_host_info)
{
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;
	struct virtcca_mig_verifier *verifier = NULL;
	int ret = 0;

	write_lock(&verifier_list_rwlock);
	list_for_each_entry(verifier, &virtcca_mig_verifier_list, list) {
		if (verifier->cvm_vmid == cvm->cvm_vmid) {
			if (dst_host_info->is_src) {
				strscpy(verifier->dst_ip,
						dst_host_info->dst_ip,
						sizeof(verifier->dst_ip));
				verifier->dst_port = dst_host_info->dst_port;
			}

			atomic_set(&verifier->status, VIRTCCA_MIG_UPDATED);
			verifier->is_src = dst_host_info->is_src;
			pr_warn("CVM is already registered to verifer list, update it\n");
			write_unlock(&verifier_list_rwlock);
			return 0;
		}
	}

	verifier = kmalloc(sizeof(struct virtcca_mig_verifier), GFP_KERNEL);
	if (!verifier) {
		write_unlock(&verifier_list_rwlock);
		return -ENOMEM;
	}

	strscpy(verifier->name, dst_host_info->name, sizeof(verifier->name));
	strscpy(verifier->dst_ip, dst_host_info->dst_ip, sizeof(verifier->dst_ip));
	verifier->dst_port = dst_host_info->dst_port;
	verifier->is_src = dst_host_info->is_src;
	verifier->rd = cvm->rd;
	verifier->cvm_vmid = cvm->cvm_vmid;
	init_waitqueue_head(&verifier->wait_queue);
	atomic_set(&verifier->status, VIRTCCA_MIG_NEW);

	INIT_LIST_HEAD(&verifier->list);

	list_add_tail(&verifier->list, &virtcca_mig_verifier_list);
	write_unlock(&verifier_list_rwlock);

	return ret;
}

int virtcca_mig_verifier_delete(struct kvm *kvm)
{
	struct virtcca_mig_verifier *verifier, *tmp;
	struct virtcca_cvm *cvm = kvm->arch.virtcca_cvm;

	write_lock(&verifier_list_rwlock);
	list_for_each_entry_safe(verifier, tmp, &virtcca_mig_verifier_list, list) {
		if (verifier->cvm_vmid == cvm->cvm_vmid) {
			list_del(&verifier->list);
			write_unlock(&verifier_list_rwlock);
			kfree(verifier);
			pr_info("Removed CVM ID %d from verifer list\n", cvm->cvm_vmid);
			return 0;
		}
	}
	write_unlock(&verifier_list_rwlock);
	return 0;
}

static int virtcca_mig_notify(struct kvm *kvm, struct kvm_virtcca_mig_cmd *cmd)
{
	struct virtcca_mig_dst_host_info mig_host_info;
	int ret = 0;

	if (copy_from_user(&mig_host_info, (void __user *)cmd->data,
			sizeof(struct virtcca_mig_dst_host_info)))
		return -EFAULT;

	if (virtcca_migcvm_enabled) {
		mig_host_info.migcvm_enabled = 1;
		if (mig_host_info.is_src)
			ret = virtcca_migvm_agent_ratstls(kvm, cmd);
		else
			ret = virtcca_migvm_agent_ratstls_dst(kvm, cmd);
	} else {
		mig_host_info.migcvm_enabled = 0;
		ret = virtcca_mig_verifier_register(kvm, &mig_host_info);
	}

	if (ret) {
		pr_err("%s failed! ret = %d\n", __func__, ret);
		return ret;
	}

	if (copy_to_user((void __user *)cmd->data, &mig_host_info,
			sizeof(struct virtcca_mig_dst_host_info))) {
		pr_err("%s: copy data to user failed!\n", __func__);
		return -EFAULT;
	}

	return ret;
}

static int virtcca_mig_flat_list_to_agent(void __user *user_data)
{
	struct virtcca_mig_verifier *verifier;
	struct virtcca_mig_agent_notify_info *agent_data = NULL;
	int notify_count = 0;
	int i = 0;
	int ret = 0;

	read_lock(&verifier_list_rwlock);

	list_for_each_entry(verifier, &virtcca_mig_verifier_list, list) {
		if (atomic_read(&verifier->status) < VIRTCCA_MIG_NOTIFIED && verifier->is_src)
			notify_count++;
	}

	if (notify_count == 0) {
		read_unlock(&verifier_list_rwlock);
		return 0;
	}

	notify_count = min(notify_count, CVM_MIG_SYNC_NUM_MAX);
	agent_data = kmalloc_array(notify_count,
						sizeof(struct virtcca_mig_agent_notify_info),
						GFP_KERNEL);
	if (!agent_data) {
		read_unlock(&verifier_list_rwlock);
		return -ENOMEM;
	}

	list_for_each_entry(verifier, &virtcca_mig_verifier_list, list) {
		if (atomic_read(&verifier->status) < VIRTCCA_MIG_NOTIFIED && verifier->is_src) {
			if (i >= notify_count)
				break;

			strscpy(agent_data[i].name, verifier->name, sizeof(agent_data[i].name));
			strscpy(agent_data[i].dst_ip,
					verifier->dst_ip,
					sizeof(agent_data[i].dst_ip));
			agent_data[i].rd = verifier->rd;
			agent_data[i].dst_port = verifier->dst_port;
			agent_data[i].cvm_vmid = verifier->cvm_vmid;
			agent_data[i].is_src = verifier->is_src;
			atomic_set(&verifier->status, VIRTCCA_MIG_NOTIFIED);

			i++;
		}
	}
	read_unlock(&verifier_list_rwlock);

	if (i > 0) {
		if (copy_to_user(user_data, agent_data,
				sizeof(struct virtcca_mig_agent_notify_info) * i))
			ret = -EFAULT;
		else
			ret = i;
	}

	kfree(agent_data);
	return ret;
}

static int virtcca_mig_get_notify(struct virtcca_tmi_cmd *cmd)
{
	int count = 0;

	count = virtcca_mig_flat_list_to_agent((void __user *)cmd->data);

	if (count < 0)
		return count;

	cmd->ret_val = count;
	return 0;
}

static int virtcca_migvm_mem_checksum_loop(struct virtcca_tmi_cmd *cmd)
{
	unsigned long ret;
	struct virtcca_migvm_checksum_info checksuminfo;

	if (copy_from_user(&checksuminfo, (void __user *)cmd->data, sizeof(checksuminfo)))
		return -EFAULT;

	ret = tmi_mig_integrity_checksum_loop(checksuminfo.guest_rd, checksuminfo.thread_id);
	cmd->ret_val = ret;

	return ret;
}

static int virtcca_get_dstvm_rd(struct virtcca_tmi_cmd *cmd)
{
	struct virtcca_mig_verifier *verifier;
	char cvm_name[CVM_NAME_LEN] = {0};

	if (copy_from_user(&cvm_name, (void __user *)cmd->data, sizeof(cvm_name)))
		return -EFAULT;

	read_lock(&verifier_list_rwlock);
	list_for_each_entry(verifier, &virtcca_mig_verifier_list, list) {
		if (!strcmp(verifier->name, cvm_name)) {
			cmd->ret_val = verifier->rd;
			read_unlock(&verifier_list_rwlock);
			return 0;
		}
	}

	read_unlock(&verifier_list_rwlock);
	return -1;
}

static int virtcca_update_verifier_state_by_rd(uint64_t rd, uint16_t verifier_state)
{
	struct virtcca_mig_verifier *verifier;

	read_lock(&verifier_list_rwlock);
	list_for_each_entry(verifier, &virtcca_mig_verifier_list, list) {
		if (verifier->rd == rd) {
			pr_info("%s: update verifier state to %u\n", __func__, verifier_state);
			atomic_set(&verifier->status, verifier_state);
			read_unlock(&verifier_list_rwlock);
			return 0;
		}
	}
	read_unlock(&verifier_list_rwlock);
	return -1;
}

static int virtcca_wait_for_verifier_state(struct kvm *kvm, int expected_state)
{
	struct virtcca_mig_verifier *verifier;
	unsigned long timeout = msecs_to_jiffies(VIRTCCA_MIG_STATE_WAIT_TIMEOUT);
	uint64_t rd = kvm->arch.virtcca_cvm->rd;

	read_lock(&verifier_list_rwlock);
	list_for_each_entry(verifier, &virtcca_mig_verifier_list, list) {
		if (verifier->rd == rd) {
			long time_left = wait_event_timeout(verifier->wait_queue,
						atomic_read(&verifier->status) == expected_state,
						timeout);
			read_unlock(&verifier_list_rwlock);
			if (time_left <= 0) {
				pr_err("Timeout waiting for verifier state %d\n", expected_state);
				return -ETIMEDOUT;
			}
			return 0;
		}
	}
	read_unlock(&verifier_list_rwlock);
	return -1;
}

static int virtcca_mig_src_get_key(struct virtcca_tmi_cmd *cmd)
{
	unsigned long ret = 0;
	struct virtcca_mig_host_agent_info agent_info = {0};
	struct mig_host_key_info *key_info = NULL;

	if (copy_from_user(&agent_info, (void __user *)cmd->data,
			sizeof(struct virtcca_mig_host_agent_info)))
		return -EFAULT;

	if (agent_info.content) {
		if (!access_ok(agent_info.content, agent_info.size)) {
			pr_err("%s: invalid content address\n", __func__);
			return -EFAULT;
		}
	} else {
		pr_err("%s: invalid content pointer\n", __func__);
		return -EFAULT;
	}

	if (sizeof(struct mig_host_key_info) != agent_info.size) {
		pr_err("%s: size mismatch\n", __func__);
		return -EINVAL;
	}

	key_info = kmalloc(sizeof(struct mig_host_key_info), GFP_KERNEL);
	if (!key_info)
		return -ENOMEM;

	ret = tmi_mig_get_migration_key(agent_info.rd, (uint64_t)key_info);
	if (ret) {
		pr_err("%s: tmi_mig_get_migration_key failed\n", __func__);
		goto out;
	}
	cmd->ret_val = ret;

	if (copy_to_user(agent_info.content, key_info, agent_info.size)) {
		pr_err("%s: copy to user failed\n", __func__);
		ret = -EFAULT;
		goto out;
	}

	virtcca_update_verifier_state_by_rd(agent_info.rd, VIRTCCA_MIG_KEY_UPDATED);

out:
	kfree(key_info);

	return ret;
}

static int virtcca_mig_dst_set_key(struct virtcca_tmi_cmd *cmd)
{
	unsigned long ret = 0;
	struct virtcca_mig_host_agent_info agent_info = {0};
	struct mig_host_key_info *key_info = NULL;

	if (copy_from_user(&agent_info, (void __user *)cmd->data,
			sizeof(struct virtcca_mig_host_agent_info)))
		return -EFAULT;

	if (!agent_info.content || !agent_info.size) {
		pr_err("%s: invalid content or size\n", __func__);
		return -EINVAL;
	}

	if (!access_ok(agent_info.content, agent_info.size)) {
		pr_err("%s: invalid user address\n", __func__);
		return -EFAULT;
	}

	if (sizeof(struct mig_host_key_info) != agent_info.size) {
		pr_err("%s: size mismatch\n", __func__);
		return -EINVAL;
	}

	key_info = kzalloc(sizeof(struct mig_host_key_info), GFP_KERNEL);
	if (!key_info)
		return -ENOMEM;

	if (copy_from_user(key_info, (void __user *)agent_info.content,
			sizeof(struct mig_host_key_info))) {
		ret = -EFAULT;
		goto out;
	}

	ret = tmi_mig_set_migration_key(agent_info.rd, (uint64_t)key_info);
	if (ret) {
		pr_err("%s: tmi_mig_set_migration_key failed\n", __func__);
		ret = -EFAULT;
		goto out;
	}

	virtcca_update_verifier_state_by_rd(agent_info.rd, VIRTCCA_MIG_KEY_UPDATED);
out:
	kfree(key_info);

	return ret;
}

static int virtcca_data_key_gen(struct virtcca_tmi_cmd *cmd)
{
	int ret = 0;
	struct virtcca_usr_data_key_attr *key_attr = NULL;

	if (!cmd->data) {
		pr_err("%s: cmd->data is NULL\n", __func__);
		return -EINVAL;
	}

	key_attr = kmalloc(sizeof(struct virtcca_usr_data_key_attr), GFP_KERNEL);
	if (!key_attr)
		return -ENOMEM;

	if (copy_from_user(key_attr, (void __user *)cmd->data,
						sizeof(struct virtcca_usr_data_key_attr))) {
		pr_err("%s: failed to copy key_attr from user\n", __func__);
		ret = -EFAULT;
		goto out;
	}

	ret = tmi_data_key_gen((uint64_t)key_attr);
	if (ret) {
		pr_err("%s: data key gen failed, ret=%d\n", __func__, ret);
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user((void __user *)cmd->data, key_attr,
		sizeof(struct virtcca_usr_data_key_attr))) {
		ret = -EFAULT;
		goto out;
	}

out:
	kfree(key_attr);
	return ret;
}

void virtcca_raw_data_kern_ctx_cleanup(void *ctx_p)
{
	struct virtcca_raw_data_kern_ctx *ctx = (struct virtcca_raw_data_kern_ctx *)ctx_p;

	if (!ctx)
		return;

	kfree(ctx->kern_key_attr);
	kfree(ctx->ciphertext_buf);
	kfree(ctx->plaintext_buf);
	kfree(ctx->kern_attr);
	ctx->kern_key_attr = NULL;
	ctx->kern_attr = NULL;
	ctx->ciphertext_buf = NULL;
	ctx->plaintext_buf = NULL;
}

int virtcca_raw_data_attr_user_to_kernel(void *usr_data_p, void *ctx_p)
{
	int ret = 0;
	struct virtcca_raw_data_kern_ctx *ctx = (struct virtcca_raw_data_kern_ctx *)ctx_p;
	struct virtcca_usr_data_key_enc_s *usr_data =
		(struct virtcca_usr_data_key_enc_s *)usr_data_p;

	if (!ctx || !usr_data) {
		pr_err("%s: Invalid params\n", __func__);
		return -ENOMEM;
	}

	ctx->kern_key_attr = NULL;
	ctx->kern_attr = NULL;
	ctx->ciphertext_buf = NULL;
	ctx->plaintext_buf = NULL;
	ctx->usr_ciphertext_p = usr_data->raw_data_attr.ciphertext_p;
	ctx->usr_plaintext_p = usr_data->raw_data_attr.plaintext_p;

	ctx->kern_key_attr = kmalloc(sizeof(struct virtcca_key_attr_s), GFP_KERNEL);
	if (!ctx->kern_key_attr)
		return -ENOMEM;

	memcpy(ctx->kern_key_attr, &usr_data->key_attr,
			sizeof(struct virtcca_key_attr_s));

	ctx->kern_attr = kmalloc(sizeof(struct virtcca_raw_data_attr_s), GFP_KERNEL);
	if (!ctx->kern_attr) {
		kfree(ctx->kern_key_attr);
		ctx->kern_key_attr = NULL;
		return -ENOMEM;
	}
	memcpy(ctx->kern_attr, &usr_data->raw_data_attr,
			sizeof(struct virtcca_raw_data_attr_s));

	if (ctx->kern_attr->mode == DATA_ENC_MODE && ctx->kern_attr->ciphertext_len > 0) {
		ctx->ciphertext_buf = kmalloc(ctx->kern_attr->ciphertext_len, GFP_KERNEL);
		if (!ctx->ciphertext_buf) {
			ret = -ENOMEM;
			goto err;
		}
		if (copy_from_user(ctx->ciphertext_buf,
			(void __user *)ctx->usr_ciphertext_p,
			ctx->kern_attr->ciphertext_len)) {
			pr_err("%s: failed to copy ciphertext from user, usr_p=0x%llx, len=%u\n",
				__func__, ctx->usr_ciphertext_p, ctx->kern_attr->ciphertext_len);
			ret = -EFAULT;
			goto err;
		}
		ctx->kern_attr->ciphertext_p = (uint64_t)ctx->ciphertext_buf;
	} else if (ctx->kern_attr->mode == DATA_DEC_MODE && ctx->kern_attr->ciphertext_len > 0) {
		ctx->ciphertext_buf = kmalloc(ctx->kern_attr->ciphertext_len, GFP_KERNEL);
		if (!ctx->ciphertext_buf) {
			ret = -ENOMEM;
			goto err;
		}
		if (copy_from_user(ctx->ciphertext_buf,
			(void __user *)ctx->usr_ciphertext_p,
			ctx->kern_attr->ciphertext_len)) {
			pr_err("%s: failed to copy ciphertext from user, usr_p=0x%llx, len=%u\n",
				__func__, ctx->usr_ciphertext_p, ctx->kern_attr->ciphertext_len);
			ret = -EFAULT;
			goto err;
		}
		ctx->kern_attr->ciphertext_p = (uint64_t)ctx->ciphertext_buf;
	} else {
		pr_info("%s: ciphertext_len is 0, skip ciphertext copy\n", __func__);
	}

	if (ctx->kern_attr->mode == DATA_ENC_MODE && ctx->kern_attr->plaintext_len > 0) {
		ctx->plaintext_buf = kmalloc(ctx->kern_attr->plaintext_len, GFP_KERNEL);
		if (!ctx->plaintext_buf) {
			ret = -ENOMEM;
			goto err;
		}
		if (copy_from_user(ctx->plaintext_buf,
			(void __user *)ctx->usr_plaintext_p,
			ctx->kern_attr->plaintext_len)) {
			pr_err("%s: failed to copy plaintext from user, usr_p=0x%llx, len=%u\n",
				__func__, ctx->usr_plaintext_p, ctx->kern_attr->plaintext_len);
			ret = -EFAULT;
			goto err;
		}
	} else if (ctx->kern_attr->mode == DATA_DEC_MODE && ctx->kern_attr->plaintext_len > 0) {
		ctx->plaintext_buf = kzalloc(ctx->kern_attr->plaintext_len, GFP_KERNEL);
		if (!ctx->plaintext_buf) {
			ret = -ENOMEM;
			goto err;
		}
	} else {
		pr_info("%s: plaintext_len is 0, skip plaintext copy\n", __func__);
	}
	return 0;
err:
	virtcca_raw_data_kern_ctx_cleanup(ctx);
	return ret;
}

int virtcca_raw_data_attr_kernel_to_user(void __user *usr_data_up, void *usr_data_p,
						void *ctx_p)
{
	int ret = 0;
	struct virtcca_raw_data_kern_ctx *ctx = (struct virtcca_raw_data_kern_ctx *)ctx_p;
	struct virtcca_usr_data_key_enc_s *usr_data =
		(struct virtcca_usr_data_key_enc_s *)usr_data_p;

	if (!ctx || !usr_data || !usr_data_up) {
		pr_err("%s: Invalid params\n", __func__);
		return -ENOMEM;
	}

	if (ctx->kern_attr->mode == DATA_ENC_MODE && ctx->ciphertext_buf) {
		if (copy_to_user((void __user *)ctx->usr_ciphertext_p,
			ctx->ciphertext_buf, ctx->kern_attr->ciphertext_len)) {
			pr_err("%s: failed to copy ciphertext to user, usr_p=0x%llx, len=%u\n",
				__func__, ctx->usr_ciphertext_p, ctx->kern_attr->ciphertext_len);
			ret = -EFAULT;
			goto out;
		}
	}

	if (ctx->kern_attr->mode == DATA_DEC_MODE && ctx->plaintext_buf) {
		if (copy_to_user((void __user *)ctx->usr_plaintext_p,
			ctx->plaintext_buf, ctx->kern_attr->plaintext_len)) {
			pr_err("%s: failed to copy plaintext to user, usr_p=0x%llx, len=%u\n",
				__func__, ctx->usr_plaintext_p, ctx->kern_attr->plaintext_len);
			ret = -EFAULT;
			goto out;
		}
	}

	memcpy(&usr_data->raw_data_attr.tag, &ctx->kern_attr->tag,
			DATA_KEY_TAG_LEN);
	memcpy(&usr_data->key_attr, ctx->kern_key_attr,
			sizeof(struct virtcca_key_attr_s));

	if (copy_to_user(usr_data_up, usr_data,
		sizeof(struct virtcca_usr_data_key_enc_s))) {
		pr_err("%s: failed to copy usr_data to user\n", __func__);
		ret = -EFAULT;
	}

out:
	virtcca_raw_data_kern_ctx_cleanup(ctx);
	return ret;
}

static int virtcca_data_key_enc(struct virtcca_tmi_cmd *cmd)
{
	int ret = 0;
	struct virtcca_usr_data_key_enc_s *usr_data = NULL;
	struct virtcca_raw_data_kern_ctx kern_ctx = {0};

	if (!cmd->data) {
		pr_err("%s: cmd->data is NULL\n", __func__);
		return -EINVAL;
	}

	usr_data = kmalloc(sizeof(struct virtcca_usr_data_key_enc_s), GFP_KERNEL);
	if (!usr_data)
		return -ENOMEM;

	if (copy_from_user(usr_data, (void __user *)cmd->data,
						sizeof(struct virtcca_usr_data_key_enc_s))) {
		pr_err("%s: failed to copy usr_data from user\n", __func__);
		ret = -EFAULT;
		goto out;
	}

	if (usr_data->raw_data_attr.mode != DATA_ENC_MODE &&
		usr_data->raw_data_attr.mode != DATA_DEC_MODE) {
		pr_err("%s: invalid mode %d, must be %d(ENC) or %d(DEC)\n",
			__func__, usr_data->raw_data_attr.mode, DATA_ENC_MODE, DATA_DEC_MODE);
		ret = -EINVAL;
		goto out;
	}

	if (usr_data->raw_data_attr.ciphertext_len > MAX_DATA_KEY_BUF_SIZE ||
		usr_data->raw_data_attr.plaintext_len > MAX_DATA_KEY_BUF_SIZE) {
		pr_err("%s: buffer size exceeds limit, ciphertext_len=%u, plaintext_len=%u, max=%d\n",
			__func__, usr_data->raw_data_attr.ciphertext_len,
			usr_data->raw_data_attr.plaintext_len, MAX_DATA_KEY_BUF_SIZE);
		ret = -EINVAL;
		goto out;
	}

	if (!access_ok((void __user *)usr_data->raw_data_attr.ciphertext_p,
							usr_data->raw_data_attr.ciphertext_len) ||
		!access_ok((void __user *)usr_data->raw_data_attr.plaintext_p,
							usr_data->raw_data_attr.plaintext_len)) {
		pr_err("%s: invalid user data pointer\n", __func__);
		ret = -EFAULT;
		goto out;
	}

	ret = virtcca_raw_data_attr_user_to_kernel(usr_data, &kern_ctx);
	if (ret)
		goto out;

	if (kern_ctx.ciphertext_buf)
		kern_ctx.kern_attr->ciphertext_p = (uint64_t)__pa(kern_ctx.ciphertext_buf);
	if (kern_ctx.plaintext_buf)
		kern_ctx.kern_attr->plaintext_p = (uint64_t)__pa(kern_ctx.plaintext_buf);

	ret = tmi_data_key_enc((uint64_t)kern_ctx.kern_key_attr, (uint64_t)kern_ctx.kern_attr);
	if (ret) {
		pr_err("%s: tmi_data_key_enc failed, ret=%d\n", __func__, ret);
		ret = -EFAULT;
		goto out_cleanup;
	}

	ret = virtcca_raw_data_attr_kernel_to_user((void __user *)cmd->data,
							usr_data, &kern_ctx);
	if (ret)
		goto out;

	goto out;

out_cleanup:
	virtcca_raw_data_kern_ctx_cleanup(&kern_ctx);
out:
	kfree(usr_data);

	return ret;
}


static long virtcca_tmi_ioctl_wrapper(struct file *file, unsigned int cmd, unsigned long arg);
static const struct file_operations tmm_tmi_fops = {
	.owner		  = THIS_MODULE,
	.unlocked_ioctl = virtcca_tmi_ioctl_wrapper
};

static struct miscdevice ioctl_dev = {
	MISC_DYNAMIC_MINOR,
	"tmi",
	&tmm_tmi_fops,
};

static int virtcca_tmi_ioctl(unsigned long arg)
{
	struct virtcca_tmi_cmd tmi_cmd = {0};
	int ret = 0;
	void __user *argp = (void __user *)arg;

	if (!access_ok((void __user *)arg, sizeof(struct virtcca_tmi_cmd))) {
		pr_err("invalid user address %p\n", (void __user *)arg);
		return -EFAULT;
	}

	if (copy_from_user(&tmi_cmd, argp, sizeof(struct virtcca_tmi_cmd)))
		return -EINVAL;

	if (virtcca_migcvm_enabled &&
		tmi_cmd.id >= VIRTCCA_TMI_GET_NOTIFY &&
		tmi_cmd.id <= VIRTCCA_GET_DSTVM_RD) {
		pr_err("migcvm is running, host mig agent is disabled!");
		ret = -EINVAL;
		goto out;
	}

	switch (tmi_cmd.id) {
	case VIRTCCA_TMI_IOCTL_VERSION:
		pr_info("This is a tmi ioctl\n");
		break;
	case VIRTCCA_TMI_GET_NOTIFY:
		ret = virtcca_mig_get_notify(&tmi_cmd);
		break;
	case VIRTCCA_GET_MIGVM_MEM_CHECKSUM:
		ret = virtcca_migvm_mem_checksum_loop(&tmi_cmd);
		break;
	case VIRTCCA_GET_DSTVM_RD:
		ret = virtcca_get_dstvm_rd(&tmi_cmd);
		break;
	case VIRTCCA_GET_MIG_KEY:
		ret = virtcca_mig_src_get_key(&tmi_cmd);
		break;
	case VIRTCCA_SET_MIG_KEY:
		ret = virtcca_mig_dst_set_key(&tmi_cmd);
		break;
	case VIRTCCA_DATA_KEY_GEN:
		ret = virtcca_data_key_gen(&tmi_cmd);
		break;
	case VIRTCCA_DATA_KEY_ENC:
		ret = virtcca_data_key_enc(&tmi_cmd);
		break;
	default:
		pr_err("Invalid tmi cmd!\n");
		ret = -EINVAL;
	}

out:
	if (copy_to_user(argp, &tmi_cmd, sizeof(struct virtcca_tmi_cmd)))
		return -EFAULT;

	return ret;
}

static long virtcca_tmi_ioctl_wrapper(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	if (!file)
		return -EINVAL;

	switch (cmd) {
	case VIRTCCA_TMI_IOCTL_ENTER:
		ret = virtcca_tmi_ioctl(arg);
		break;
	default:
		pr_err("tmm_tmi: unknown ioctl command (0x%x)!\n", cmd);
		return -ENOTTY;
	}

	return ret;
}

static int __init tmm_tmi_init(void)
{
	int ret;

	if (!is_virtcca_cvm_enable())
		return -EIO;

	ret = misc_register(&ioctl_dev);
	if (ret) {
		pr_err("tmm_tmi: misc device register failed (%d)!\n", ret);
		return ret;
	}

	return 0;
}

static void __exit tmm_tmi_exit(void)
{
	misc_deregister(&ioctl_dev);
	pr_info("tmm_tmi: module unloaded.\n");
}

module_init(tmm_tmi_init);
module_exit(tmm_tmi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_DESCRIPTION("Interacting with TMM through TMI interface from user space.");

#endif
