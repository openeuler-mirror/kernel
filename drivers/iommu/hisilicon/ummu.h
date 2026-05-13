/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU Device's implementations
 */

#ifndef __UMMU_H__
#define __UMMU_H__

#include <linux/bitfield.h>
#include <linux/ummu_core.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/init.h>

#include "perm_table.h"

#define LOCAL_TECT_TAG 0

extern bool hw_bypass;
extern struct platform_driver ummu_driver;
extern const struct ummu_core_ops ummu_ops;
extern const struct ummu_device_helper ummu_helper;

#define MSI_IOVA_BASE 0x8000000
#define MSI_IOVA_LENGTH 0x100000

#define EID_HIGH_SZ_SHIFT 64
#define UMMU_CTRL_PAGE_SIZE ((PAGE_SIZE == SZ_4K) ? SZ_4K : SZ_64K)

/* target context table structures */
struct ummu_l1_tct_desc {
	__le64		*l2ptr;
	phys_addr_t	l2ptr_phys;
};

bool ummu_sva_separated_enabled(void);

enum ummu_device_msi_index {
	EVTQ_MSI_INDEX,
	GERROR_MSI_INDEX,
#if IS_ENABLED(CONFIG_UB_UBMEM_UMMU)
	RESERVED_MSI_INDEX,
#endif
	UMMU_MAX_MSIS,
};

struct ummu_tct_desc {
	u32	asid;
	u64	ttbr;
	u32	tcr0;
	u32	tcr1;
	u64	mair;
	u8		mapt_en;
	u8		token_en;
	u8		mapt_mode;
	phys_addr_t	mapt_blk_phys;
	u8		blk_size_order;
	phys_addr_t	mapt_blk_tbl_phys;
	u8		blk_tbl_size_order;
};

struct ummu_tct_desc_cfg {
	__le64				*tct_ptr;
	phys_addr_t			tct_phys_addr;
	struct ummu_l1_tct_desc		*l1_tct_desc;
	unsigned int			l1_tcte_num;
	u8				tct_fmt;
	u8				tcte_max_bits;
	struct kref			ref;
};

/* translation stage1 table config */
struct ummu_s1_cfg {
	struct ummu_tct_desc_cfg *tct_cfg;
	struct ummu_tct_desc tct;
	struct ummu_mapt_info io_pt_cfg;
};

/* translation stage2 table config */
struct ummu_s2_cfg {
	u16	vmid;
	u64	vttbr;
	u64	vtcr;
};

enum ummu_domain_stage {
	UMMU_DOMAIN_S1 = 0,
	UMMU_DOMAIN_S2,
};

enum ummu_sva_mode {
	UMMU_MODE_DMA = 0,
	UMMU_MODE_KSVA,
	UMMU_MODE_SVA,
	UMMU_MODE_SVA_DISABLE_PTB,
	UMMU_MODE_SVA_SEPARATE_PG,
	UMMU_MODE_END,
};

struct ummu_ll_queue {
	union {
		u64 val;
		struct {
			u32 prod;
			u32 cons;
		};
		struct {
			atomic_t prod;
			atomic_t cons;
		} atomic;
		u8 __pad[SMP_CACHE_BYTES];
	} ____cacheline_aligned_in_smp;
	u32 log2size;
};

struct ummu_queue {
	struct ummu_ll_queue llq;
	__le64 *base;
	phys_addr_t base_pa;
	u64 q_base;

	size_t ent_dwords;
	u32 __iomem *prod_reg;
	u32 __iomem *cons_reg;
};

struct ummu_mcmdq {
	struct ummu_queue q;
	atomic_long_t *valid_map;
	atomic_t owner_prod;
	u32 mcmdq_prod;
	rwlock_t mcmdq_lock;
	atomic_t lock;
	int configured;
	int shared;
	void __iomem *base;
};

struct ummu_evtq {
	struct ummu_queue q;
	struct iopf_queue *iopf;
	u32 max_stalls;
};

struct ummu_capability {
#define UMMU_FEAT_2_LVL_TECT		BIT(0)
#define UMMU_FEAT_2_LVL_TCT		BIT(1)
#define UMMU_FEAT_MCMDQ			BIT(2)
#define UMMU_FEAT_EVENTQ		BIT(3)
#define UMMU_FEAT_SEV			BIT(4)
#define UMMU_FEAT_TRANS_S1		BIT(5)
#define UMMU_FEAT_TRANS_S2		BIT(6)
#define UMMU_FEAT_RANGE_INV		BIT(7)
#define UMMU_FEAT_STALLS		BIT(8)
#define UMMU_FEAT_STALL_FORCE		BIT(9)
#define UMMU_FEAT_MSI			BIT(10)
#define UMMU_FEAT_HYP			BIT(11)
#define UMMU_FEAT_HA			BIT(12)
#define UMMU_FEAT_HD			BIT(13)
#define UMMU_FEAT_MTM			BIT(14)
#define UMMU_FEAT_COHERENCY		BIT(15)
#define UMMU_FEAT_BBML1			BIT(16)
#define UMMU_FEAT_BBML2			BIT(17)
#define UMMU_FEAT_VAX			BIT(18)
#define UMMU_FEAT_BTM			BIT(19)
#define UMMU_FEAT_SVA			BIT(20)
#define UMMU_FEAT_E2H			BIT(21)
#define UMMU_FEAT_MAPT			BIT(22)
#define UMMU_FEAT_RANGE_PLBI		BIT(23)
#define UMMU_FEAT_TOKEN_CHK		BIT(24)
#define UMMU_FEAT_PERMQ			BIT(25)
#define UMMU_FEAT_NESTING		BIT(26)
#define UMMU_FEAT_FREE_BIT		BIT(27)
	u32 features;
	u32 deid_bits;
	u32 tid_bits;
	u64 pgsize_bitmap;
	u32 ias;
	u32 oas;
	u64 ptsize_bitmap;
#define UMMU_OPT_MSIPOLL		(1UL << 0)
#define UMMU_OPT_DOUBLE_PLBI		(1UL << 1)
#define UMMU_OPT_KCMD_PLBI		(1UL << 2)
#define UMMU_OPT_CHK_MAPT_CONTINUITY	(1UL << 3)
#define UMMU_OPT_MCMDQ_DECREASE		(1UL << 4)
#define UMMU_OPT_SYNC_WITH_PLBI		(1UL << 5)
#define UMMU_OPT_KV_CAM_CONTINUITY	(1UL << 6)
#define UMMU_OPT_UMAU			(1UL << 7)
	u32 options;

#define UMMU_MAX_ASIDS			(1UL << 16)
	unsigned int asid_bits;
#define UMMU_MAX_VMIDS			(1UL << 16)
	unsigned int vmid_bits;

	u32 mcmdq_log2num;
	u32 mcmdq_log2size;
	u32 evtq_log2num;
	u32 evtq_log2size;
	u32 permq_num;
	struct {
		u32 cmdq_num;
		u32 cplq_num;
	} permq_ent_num;
	u32 mtm_gp_max;
	u32 mtm_id_max;
};

struct ummu_permq_addr {
	void *va;
	phys_addr_t pa;
};

struct ummu_permq_desc {
	struct ummu_permq_addr pcmdq;
	struct ummu_permq_addr pcplq;
};

struct ummu_permq_context_cfg {
	void *tbl_va;
	phys_addr_t tbl_pa;
	u64 tbl_reg_addr;
	struct xarray permq_xa; /* container of struct ummu_permq_desc */
	struct mutex permq_rel_mutex;
};

struct ummu_hash_table_cfg {
	u16 bank_depth;
	u8 bank_num;
	u8 hash_width;
	u8 hash_sel;
	void *kv_tbl_vaddr;
	u64 kv_tbl_reg_addr;
	u32 kv_tbl_reg_cfg;

	u16 cam_tbl_depth;
	void *cam_tbl_vaddr;
	u64 cam_tbl_reg_addr;
	u32 cam_tbl_reg_cfg;
};

/* ummu device inner helper functions */
enum ummu_dom_cfg_sync_type {
	SYNC_TYPE_NONE,
	SYNC_DOM_ALL_CFG,
	SYNC_DOM_MUTI_CFG,
	SYNC_CLEAR_DOM_ALL_CFG,
};

#define UMMU_GATHER_MAX_CNT 12
struct logic_ummu_plb {
	u32 opcode;
	union {
		struct {
			u64 va;
			u64 size;
		} plbi_va;
		struct {
			u64 lvl_idx;
			u64 lvl_offset;
		} plbi_f_bit;
	};
};
struct ummu_plbi_gather {
	void *cookie;
	struct logic_ummu_plb plbis[UMMU_GATHER_MAX_CNT];
	u32 data_cnt;
};

struct ummu_device_helper {
	void (*sync_tlb)(struct iommu_domain *domain,
			 struct iommu_iotlb_gather *iotlb_gather);
	int (*sync_dom_cfg)(struct ummu_base_domain *src, struct ummu_base_domain *dst,
			    enum ummu_dom_cfg_sync_type type);
	struct iommu_domain *(*alloc_domain_nested)(
		struct iommu_domain *parent, u32 flags,
		const struct iommu_user_data *user_data);
	int (*cache_invalidate_user)(struct iommu_domain *domain,
				     struct iommu_user_data_array *array);
	void (*plbi_free_bit)(struct iommu_domain *domain, u32 next_lvl_idx,
			      u32 next_lvl_offset);
	void (*sync_iotlb_all)(struct iommu_domain *domain);
};

struct ummu_device {
	struct device *dev;
	void __iomem *base;
	void __iomem *permq_ctrl_page;

	struct ummu_capability cap;

	u32 nr_mcmdq;
	struct ummu_mcmdq *__percpu *mcmdq;
	struct ummu_evtq evtq;

	struct ummu_tect_cfg *tect_cfg;
	struct ummu_hash_table_cfg hash_tbl_cfg;
	struct ummu_tct_desc_cfg *local_tct_cfg;
	struct ummu_permq_context_cfg permq_ctx_cfg;

	struct ummu_core_device core_dev;
	struct ummu_dev_impl_ops *impl_ops;
	const struct ummu_device_helper *helper_ops;
	struct list_head list;
};

struct ummu_dev_impl_ops {
	int (*hw_probe)(struct ummu_device *ummu);
	int (*mcmdq_cfg)(struct ummu_device *ummu);
	void (*write_msi_msg)(struct msi_desc *desc, struct msi_msg *msg);
	void (*set_msis)(struct ummu_device *ummu);
	void (*setup_irqs)(struct ummu_device *ummu);
	int (*dev_probe)(struct ummu_device *ummu);
	void (*dev_remove)(struct ummu_device *ummu);
};

struct ummu_domain_cfgs {
	struct io_pgtable_ops *pgtbl_ops;
	enum ummu_domain_stage stage;
	enum ummu_sva_mode sva_mode;

	u32 tecte_tag;

	union {
		struct ummu_s1_cfg	s1_cfg;
		struct ummu_s2_cfg	s2_cfg;
	};
	bool btm_enabled : 1;
	bool nested_parent : 1;
};

struct ummu_domain {
	struct mutex init_mutex; /* protect domain resources */
	struct ummu_base_domain base_domain;
	u32 qid;
	bool has_cfged;
	bool dirty_tracking;
	struct ummu_domain_cfgs cfgs;
	struct kvm *kvm;
};

/* UMMU private data for each master */
struct ummu_master {
	struct ummu_device	*ummu;
	struct device		*dev;
	bool			sva_enabled;
	bool			iopf_enabled;
	bool			ksva_enabled;
	refcount_t		sva_ref;
	refcount_t		ksva_ref;
};

static inline
struct ummu_device *core_to_ummu_device(struct ummu_core_device *ummu_core_dev)
{
	return container_of(ummu_core_dev, struct ummu_device, core_dev);
}

static inline struct ummu_domain *to_ummu_domain(struct iommu_domain *dom)
{
	struct ummu_base_domain *base_dom =
			container_of(dom, struct ummu_base_domain, domain);

	return container_of(base_dom, struct ummu_domain, base_domain);
}

int ummu_write_reg_sync(struct ummu_device *ummu, u32 val,
			u32 reg_off, u32 ack_off);

/**
 * Indicates whether the UMMU supports mapt blk extension.
 *
 * Return: true on success or false on error.
 */
bool ummu_get_mapt_blk_exp(void);

/**
 * Obtain the size of the mapt block.
 *
 * Return: The default value or >2M returns 64K.
 * otherwise, it returns the configuration parameter.
 */
size_t ummu_get_mapt_base_blk_size(void);

int ummu_bypass_dev_domain_type(struct device *dev);
#endif /* __UMMU_H__ */
