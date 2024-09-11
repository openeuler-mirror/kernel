/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#ifndef __TMM_TMI_H
#define __TMM_TMI_H
#ifdef CONFIG_HISI_VIRTCCA_HOST
#include <linux/kvm_host.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_pgtable.h>
#include <linux/virtio_ring.h>
#include <asm/sysreg.h>

#define NO_NUMA			0 /* numa bitmap */

#define TMM_TTT_LEVEL_2 2
#define TMM_TTT_LEVEL_3 3

/* TMI error codes. */
#define TMI_SUCCESS				0
#define TMI_ERROR_INPUT			1
#define TMI_ERROR_MEMORY		2
#define TMI_ERROR_ALIAS			3
#define TMI_ERROR_IN_USE		4
#define TMI_ERROR_CVM_STATE		5
#define TMI_ERROR_OWNER			6
#define TMI_ERROR_TEC			7
#define TMI_ERROR_TTT_WALK		8
#define TMI_ERROR_TTT_ENTRY		9
#define TMI_ERROR_NOT_SUPPORTED	10
#define TMI_ERROR_INTERNAL		11
#define TMI_ERROR_CVM_POWEROFF		12
#define TMI_ERROR_TTT_CREATED		13

#define TMI_RETURN_STATUS(ret)		((ret) & 0xFF)
#define TMI_RETURN_INDEX(ret)		(((ret) >> 8) & 0xFF)

#define TMI_FEATURE_REGISTER_0_S2SZ			GENMASK(7, 0)
#define TMI_FEATURE_REGISTER_0_LPA2			BIT(8)
#define TMI_FEATURE_REGISTER_0_SVE_EN			BIT(9)
#define TMI_FEATURE_REGISTER_0_SVE_VL			GENMASK(13, 10)
#define TMI_FEATURE_REGISTER_0_NUM_BPS			GENMASK(17, 14)
#define TMI_FEATURE_REGISTER_0_NUM_WPS			GENMASK(21, 18)
#define TMI_FEATURE_REGISTER_0_PMU_EN			BIT(22)
#define TMI_FEATURE_REGISTER_0_PMU_NUM_CTRS	GENMASK(27, 23)
#define TMI_FEATURE_REGISTER_0_HASH_SHA_256	BIT(28)
#define TMI_FEATURE_REGISTER_0_HASH_SHA_512	BIT(29)

#define TMI_CVM_PARAM_FLAG_LPA2	BIT(0)
#define TMI_CVM_PARAM_FLAG_SVE		BIT(1)
#define TMI_CVM_PARAM_FLAG_PMU		BIT(2)

#define TMI_NOT_RUNNABLE	0
#define TMI_RUNNABLE		1

/*
 *	The number of GPRs (starting from X0) that are
 *	configured by the host when a TEC is created.
 */
#define TEC_CREATE_NR_GPRS		(8U)

struct tmi_tec_params {
	uint64_t gprs[TEC_CREATE_NR_GPRS];
	uint64_t pc;
	uint64_t flags;
	uint64_t ram_size;
};

struct tmi_smmu_ste_params {
	uint64_t ns_src;     /* non-secure STE source address */
	uint64_t sid;        /* stream id */
	uint64_t smmu_id;    /* smmu id */
};

struct tmi_smmu_cfg_params {
	uint64_t smmu_id;    /* smmu id */
	uint64_t ioaddr;     /* smmu base address */
	uint8_t strtab_base_RA_bit : 1; /* Read-Allocate hint */
	uint8_t q_base_RA_WA_bit : 1; /* Write-Allocate hint*/
	uint8_t is_cmd_queue : 1;    /* Whether to configure command queue */
};

#define TMI_SMMU_CMD_QUEUE  1
#define TMI_SMMU_EVT_QUEUE  2
struct tmi_smmu_queue_params {
	uint64_t ns_src;     /* non-secure queue source address */
	uint64_t smmu_base_addr;       /* smmu base address */
	uint64_t size;       /* queue size */
	uint64_t smmu_id;    /* smmu id */
	uint64_t type;       /* cmdq or evtq */
};

#define MAX_DEV_PER_PORT 256
struct tmi_dev_delegate_params {
	/* BDF of PCIe root bus, F=0. BD are used to calculate APB base and port number. */
	uint16_t root_bd;
	uint16_t num_dev; /* number of attachable devices */
	uint32_t _reserved; /* padding for 64-bit alignment */
	uint16_t devs[MAX_DEV_PER_PORT]; /* BDF of each attachable device */
};

#define TEC_ENTRY_FLAG_EMUL_MMIO        (1UL << 0U)
#define TEC_ENTRY_FLAG_INJECT_SEA       (1UL << 1U)
#define TEC_ENTRY_FLAG_TRAP_WFI         (1UL << 2U)
#define TEC_ENTRY_FLAG_TRAP_WFE         (1UL << 3U)

#define TMI_EXIT_SYNC       0
#define TMI_EXIT_IRQ        1
#define TMI_EXIT_FIQ        2
#define TMI_EXIT_PSCI       3
#define TMI_EXIT_HOST_CALL  5
#define TMI_EXIT_SERROR     6

/*
 * The number of GPRs (starting from X0) per voluntary exit context.
 * Per SMCCC.
 */
 #define TEC_EXIT_NR_GPRS       (31U)

/* Maximum number of Interrupt Controller List Registers. */
#define TEC_GIC_NUM_LRS         (16U)

struct tmi_tec_entry {
	uint64_t flags;
	uint64_t gprs[TEC_EXIT_NR_GPRS];
	uint64_t gicv3_lrs[TEC_GIC_NUM_LRS];
	uint64_t gicv3_hcr;
};

struct tmi_tec_exit {
	uint64_t exit_reason;
	uint64_t esr;
	uint64_t far;
	uint64_t hpfar;
	uint64_t gprs[TEC_EXIT_NR_GPRS];
	uint64_t gicv3_hcr;
	uint64_t gicv3_lrs[TEC_GIC_NUM_LRS];
	uint64_t gicv3_misr;
	uint64_t gicv3_vmcr;
	uint64_t cntv_ctl;
	uint64_t cntv_cval;
	uint64_t cntp_ctl;
	uint64_t cntp_cval;
	uint64_t imm;
	uint64_t pmu_ovf_status;
};

struct tmi_tec_run {
	struct tmi_tec_entry tec_entry;
	struct tmi_tec_exit tec_exit;
};

#define TMI_FNUM_MIN_VALUE	U(0x150)
#define TMI_FNUM_MAX_VALUE	U(0x18F)

/******************************************************************************
 * Bit definitions inside the function id as per the SMC calling convention
 ******************************************************************************/
#define FUNCID_TYPE_SHIFT       31
#define FUNCID_CC_SHIFT         30
#define FUNCID_OEN_SHIFT        24
#define FUNCID_NUM_SHIFT        0

#define FUNCID_TYPE_MASK        0x1
#define FUNCID_CC_MASK          0x1
#define FUNCID_OEN_MASK         0x3f
#define FUNCID_NUM_MASK         0xffff

#define FUNCID_TYPE_WIDTH       1
#define FUNCID_CC_WIDTH         1
#define FUNCID_OEN_WIDTH        6
#define FUNCID_NUM_WIDTH        16

#define SMC_64                  1
#define SMC_32                  0
#define SMC_TYPE_FAST           1
#define SMC_TYPE_STD            0

/*****************************************************************************
 * Owning entity number definitions inside the function id as per the SMC
 * calling convention
 *****************************************************************************/
#define OEN_ARM_START           0
#define OEN_ARM_END             0
#define OEN_CPU_START           1
#define OEN_CPU_END             1
#define OEN_SIP_START           2
#define OEN_SIP_END             2
#define OEN_OEM_START           3
#define OEN_OEM_END             3
#define OEN_STD_START           4	/* Standard Calls */
#define OEN_STD_END             4
#define OEN_TAP_START           48	/* Trusted Applications */
#define OEN_TAP_END             49
#define OEN_TOS_START           50	/* Trusted OS */
#define OEN_TOS_END             63
#define OEN_LIMIT               64

/* Get TMI fastcall std FID from function number */
#define TMI_FID(smc_cc, func_num)	\
	((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT)	|	\
	((smc_cc) << FUNCID_CC_SHIFT)			|	\
	(OEN_STD_START << FUNCID_OEN_SHIFT)		|	\
	((func_num) << FUNCID_NUM_SHIFT))

#define U(_x) (_x##U)

#define TMI_NO_MEASURE_CONTENT	U(0)
#define TMI_MEASURE_CONTENT	U(1)

#define CVM_IPA_MAX_VAL  (1UL << 48)

/*
 * SMC_TMM_INIT_COMPLETE is the only function in the TMI that originates from
 * the CVM world and is handled by the SPMD. The remaining functions are
 * always invoked by the Normal world, forward by SPMD and handled by the
 * TMM.
 */
#define TMI_FNUM_VERSION_REQ            U(0x260)
#define TMI_FNUM_MEM_INFO_SHOW          U(0x261)
#define TMI_FNUM_DATA_CREATE            U(0x262)
#define TMI_FNUM_DATA_DESTROY           U(0x263)
#define TMI_FNUM_CVM_ACTIVATE           U(0x264)
#define TMI_FNUM_CVM_CREATE             U(0x265)
#define TMI_FNUM_CVM_DESTROY            U(0x266)
#define TMI_FNUM_TEC_CREATE             U(0x267)
#define TMI_FNUM_TEC_DESTROY            U(0x268)
#define TMI_FNUM_TEC_ENTER              U(0x269)
#define TMI_FNUM_TTT_CREATE             U(0x26A)
#define TMI_FNUM_PSCI_COMPLETE          U(0x26B)
#define TMI_FNUM_FEATURES               U(0x26C)
#define TMI_FNUM_TTT_MAP_RANGE          U(0x26D)
#define TMI_FNUM_TTT_UNMAP_RANGE        U(0x26E)
#define TMI_FNUM_INF_TEST               U(0x270)

#define TMI_FNUM_SMMU_QUEUE_CREATE      U(0x277)
#define TMI_FNUM_SMMU_QUEUE_WRITE       U(0x278)
#define TMI_FNUM_SMMU_STE_CREATE        U(0x279)
#define TMI_FNUM_MMIO_MAP               U(0x27A)
#define TMI_FNUM_MMIO_UNMAP             U(0x27B)
#define TMI_FNUM_MMIO_WRITE             U(0x27C)
#define TMI_FNUM_MMIO_READ              U(0x27D)
#define TMI_FNUM_DEV_DELEGATE           U(0x27E)
#define TMI_FNUM_DEV_ATTACH             U(0x27F)
#define TMI_FNUM_HANDLE_S_EVTQ          U(0x280)
#define TMI_FNUM_SMMU_DEVICE_RESET      U(0x281)
#define TMI_FNUM_SMMU_WRITE             U(0x282)
#define TMI_FNUM_SMMU_READ              U(0x283)
#define TMI_FNUM_SMMU_PCIE_CORE_CHECK   U(0x284)
#define TMI_FNUM_DEV_TTT_CREATE         U(0x285)

/* TMI SMC64 PIDs handled by the SPMD */
#define TMI_TMM_VERSION_REQ             TMI_FID(SMC_64, TMI_FNUM_VERSION_REQ)
#define TMI_TMM_DATA_CREATE             TMI_FID(SMC_64, TMI_FNUM_DATA_CREATE)
#define TMI_TMM_DATA_DESTROY            TMI_FID(SMC_64, TMI_FNUM_DATA_DESTROY)
#define TMI_TMM_CVM_ACTIVATE            TMI_FID(SMC_64, TMI_FNUM_CVM_ACTIVATE)
#define TMI_TMM_CVM_CREATE              TMI_FID(SMC_64, TMI_FNUM_CVM_CREATE)
#define TMI_TMM_CVM_DESTROY             TMI_FID(SMC_64, TMI_FNUM_CVM_DESTROY)
#define TMI_TMM_TEC_CREATE              TMI_FID(SMC_64, TMI_FNUM_TEC_CREATE)
#define TMI_TMM_TEC_DESTROY             TMI_FID(SMC_64, TMI_FNUM_TEC_DESTROY)
#define TMI_TMM_TEC_ENTER               TMI_FID(SMC_64, TMI_FNUM_TEC_ENTER)
#define TMI_TMM_TTT_CREATE              TMI_FID(SMC_64, TMI_FNUM_TTT_CREATE)
#define TMI_TMM_PSCI_COMPLETE           TMI_FID(SMC_64, TMI_FNUM_PSCI_COMPLETE)
#define TMI_TMM_FEATURES                TMI_FID(SMC_64, TMI_FNUM_FEATURES)
#define TMI_TMM_MEM_INFO_SHOW           TMI_FID(SMC_64, TMI_FNUM_MEM_INFO_SHOW)
#define TMI_TMM_TTT_MAP_RANGE           TMI_FID(SMC_64, TMI_FNUM_TTT_MAP_RANGE)
#define TMI_TMM_TTT_UNMAP_RANGE         TMI_FID(SMC_64, TMI_FNUM_TTT_UNMAP_RANGE)
#define TMI_TMM_INF_TEST                TMI_FID(SMC_64, TMI_FNUM_INF_TEST)

#define TMI_TMM_SMMU_QUEUE_CREATE       TMI_FID(SMC_64, TMI_FNUM_SMMU_QUEUE_CREATE)
#define TMI_TMM_SMMU_QUEUE_WRITE        TMI_FID(SMC_64, TMI_FNUM_SMMU_QUEUE_WRITE)
#define TMI_TMM_SMMU_STE_CREATE         TMI_FID(SMC_64, TMI_FNUM_SMMU_STE_CREATE)
#define TMI_TMM_MMIO_MAP                TMI_FID(SMC_64, TMI_FNUM_MMIO_MAP)
#define TMI_TMM_MMIO_UNMAP              TMI_FID(SMC_64, TMI_FNUM_MMIO_UNMAP)
#define TMI_TMM_MMIO_WRITE              TMI_FID(SMC_64, TMI_FNUM_MMIO_WRITE)
#define TMI_TMM_MMIO_READ               TMI_FID(SMC_64, TMI_FNUM_MMIO_READ)
#define TMI_TMM_DEV_DELEGATE            TMI_FID(SMC_64, TMI_FNUM_DEV_DELEGATE)
#define TMI_TMM_DEV_ATTACH              TMI_FID(SMC_64, TMI_FNUM_DEV_ATTACH)
#define TMI_TMM_HANDLE_S_EVTQ           TMI_FID(SMC_64, TMI_FNUM_HANDLE_S_EVTQ)
#define TMI_TMM_SMMU_DEVICE_RESET       TMI_FID(SMC_64, TMI_FNUM_SMMU_DEVICE_RESET)
#define TMI_TMM_SMMU_WRITE              TMI_FID(SMC_64, TMI_FNUM_SMMU_WRITE)
#define TMI_TMM_SMMU_READ               TMI_FID(SMC_64, TMI_FNUM_SMMU_READ)
#define TMI_TMM_SMMU_PCIE_CORE_CHECK    TMI_FID(SMC_64, TMI_FNUM_SMMU_PCIE_CORE_CHECK)
#define TMI_TMM_DEV_TTT_CREATE          TMI_FID(SMC_64, TMI_FNUM_DEV_TTT_CREATE)

#define TMI_ABI_VERSION_GET_MAJOR(_version) ((_version) >> 16)
#define TMI_ABI_VERSION_GET_MINOR(_version) ((_version) & 0xFFFF)

#define TMI_ABI_VERSION_MAJOR			U(0x2)

/* KVM_CAP_ARM_TMM on VM fd */
#define KVM_CAP_ARM_TMM_CONFIG_CVM_HOST		0
#define KVM_CAP_ARM_TMM_CREATE_RD		1
#define KVM_CAP_ARM_TMM_POPULATE_CVM		2
#define KVM_CAP_ARM_TMM_ACTIVATE_CVM		3

#define KVM_CAP_ARM_TMM_MEASUREMENT_ALGO_SHA256		0
#define KVM_CAP_ARM_TMM_MEASUREMENT_ALGO_SHA512		1

#define KVM_CAP_ARM_TMM_RPV_SIZE 64

/* List of configuration items accepted for KVM_CAP_ARM_TMM_CONFIG_CVM_HOST */
#define KVM_CAP_ARM_TMM_CFG_RPV					0
#define KVM_CAP_ARM_TMM_CFG_HASH_ALGO				1
#define KVM_CAP_ARM_TMM_CFG_SVE					2
#define KVM_CAP_ARM_TMM_CFG_DBG					3
#define KVM_CAP_ARM_TMM_CFG_PMU					4

DECLARE_STATIC_KEY_FALSE(virtcca_cvm_is_available);

struct kvm_cap_arm_tmm_config_item {
	__u32 cfg;
	union {
		/* cfg == KVM_CAP_ARM_TMM_CFG_RPV */
		struct {
			__u8	rpv[KVM_CAP_ARM_TMM_RPV_SIZE];
		};

		/* cfg == KVM_CAP_ARM_TMM_CFG_HASH_ALGO */
		struct {
			__u32	hash_algo;
		};

		/* cfg == KVM_CAP_ARM_TMM_CFG_SVE */
		struct {
			__u32	sve_vq;
		};

		/* cfg == KVM_CAP_ARM_TMM_CFG_DBG */
		struct {
			__u32	num_brps;
			__u32	num_wrps;
		};

		/* cfg == KVM_CAP_ARM_TMM_CFG_PMU */
		struct {
			__u32	num_pmu_cntrs;
		};
		/* Fix the size of the union */
		__u8	reserved[256];
	};
};

#define KVM_ARM_TMM_POPULATE_FLAGS_MEASURE	(1U << 0)
struct kvm_cap_arm_tmm_populate_region_args {
	__u64 populate_ipa_base1;
	__u64 populate_ipa_size1;
	__u64 populate_ipa_base2;
	__u64 populate_ipa_size2;
	__u32 flags;
	__u32 reserved[3];
};

static inline bool tmm_is_addr_ttt_level_aligned(uint64_t addr, int level)
{
	uint64_t mask = (1 << (12 + 9 * (3 - level))) - 1;

	return (addr & mask) == 0;
}

#define ID_AA64PFR0_SEL2_MASK      	ULL(0xf)
#define ID_AA64PFR0_SEL2_SHIFT		36

static inline bool is_armv8_4_sel2_present(void)
{
	return ((read_sysreg(id_aa64pfr0_el1) >> ID_AA64PFR0_SEL2_SHIFT) &
			ID_AA64PFR0_SEL2_MASK) == 1UL;
}

u64 tmi_version(void);
u64 tmi_data_create(u64 data, u64 rd, u64 map_addr, u64 src, u64 level);
u64 tmi_data_destroy(u64 rd, u64 map_addr, u64 level);
u64 tmi_cvm_activate(u64 rd);
u64 tmi_cvm_create(u64 params_ptr, u64 numa_set);
u64 tmi_cvm_destroy(u64 rd);
u64 tmi_tec_create(u64 numa_set, u64 rd, u64 mpidr, u64 params_ptr);
u64 tmi_tec_destroy(u64 tec);
u64 tmi_tec_enter(u64 tec, u64 run_ptr);
u64 tmi_ttt_create(u64 numa_set, u64 rd, u64 map_addr, u64 level);
u64 tmi_psci_complete(u64 calling_tec, u64 target_tec);
u64 tmi_features(u64 index);
u64 tmi_ttt_map_range(u64 rd, u64 map_addr, u64 size, u64 cur_node, u64 target_node);
u64 tmi_ttt_unmap_range(u64 rd, u64 map_addr, u64 size, u64 node_id);
u64 tmi_mem_info_show(u64 mem_info_addr);

u64 tmi_dev_ttt_create(u64 numa_set, u64 rd, u64 map_addr, u64 level);
u64 tmi_smmu_queue_create(u64 params_ptr);
u64 tmi_smmu_queue_write(uint64_t cmd0, uint64_t cmd1, u64 smmu_id);
u64 tmi_smmu_ste_create(u64 params_ptr);
u64 tmi_mmio_map(u64 rd, u64 map_addr, u64 level, u64 ttte);
u64 tmi_mmio_unmap(u64 rd, u64 map_addr, u64 level);
u64 tmi_mmio_write(u64 addr, u64 val, u64 bits, u64 dev_num);
u64 tmi_mmio_read(u64 addr, u64 bits, u64 dev_num);
u64 tmi_dev_delegate(u64 params);
u64 tmi_dev_attach(u64 vdev, u64 rd, u64 smmu_id);
u64 tmi_handle_s_evtq(u64 smmu_id);
u64 tmi_smmu_device_reset(u64 params);
u64 tmi_smmu_pcie_core_check(u64 smmu_base);
u64 tmi_smmu_write(u64 smmu_base, u64 reg_offset, u64 val, u64 bits);
u64 tmi_smmu_read(u64 smmu_base, u64 reg_offset, u64 bits);

void kvm_cvm_vcpu_put(struct kvm_vcpu *vcpu);
int kvm_load_user_data(struct kvm *kvm, unsigned long arg);
unsigned long cvm_psci_vcpu_affinity_info(struct kvm_vcpu *vcpu,
	unsigned long target_affinity, unsigned long lowest_affinity_level);
int kvm_cvm_vcpu_set_events(struct kvm_vcpu *vcpu,
	bool serror_pending, bool ext_dabt_pending);
int kvm_init_cvm_vm(struct kvm *kvm);
int kvm_enable_virtcca_cvm(struct kvm *kvm);
int kvm_cvm_map_ipa(struct kvm *kvm, phys_addr_t ipa, kvm_pfn_t pfn,
	unsigned long map_size, enum kvm_pgtable_prot prot, int ret);
void virtcca_cvm_set_secure_flag(void *vdev, void *info);
#endif
#endif
