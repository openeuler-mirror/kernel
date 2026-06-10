/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., All rights reserved.
 * Description: UMMU-CORE defines and function prototypes.
 */

#ifndef _UMMU_CORE_H_
#define _UMMU_CORE_H_

#include <uapi/linux/ummu_core.h>
#include <linux/iommu.h>
#include <linux/uuid.h>
#include <linux/xarray.h>
#include <linux/property.h>

#define eid_t u128

#define UB_MAX_TID_BITS 20U
#define UB_MAX_TID ((1 << UB_MAX_TID_BITS) - 1)

#define UMMU_NO_TID 0U
#define UMMU_INVALID_TID UB_MAX_TID

#define UMMU_DEV_WRITE 1
#define UMMU_DEV_READ 2
#define UMMU_DEV_ATOMIC 4

#define UMMU_SVA_SHARE_MODE 0
#define UMMU_SVA_SEPARATE_MODE 1

/**
 * enum eid_type - the eid type
 *
 * @EID_NONE: nommal EID type
 * @EID_BYPASS: ummu address translations are bypassed
 * @EID_TYPE_MAX: max of eid type
 */
enum eid_type {
	EID_NONE = 0,
	EID_BYPASS,
	EID_TYPE_MAX,
};

/**
 * enum tid_alloc_mode - tid different allocated mode
 *
 * @TID_ALLOC_TRANSPARENT: use pasid as tid, no need to assign again
 * @TID_ALLOC_ASSIGNED: pre-allocated tid, no need to assign again
 * @TID_ALLOC_NORMAL: alloc tid normal
 */
enum tid_alloc_mode {
	TID_ALLOC_TRANSPARENT = 0,
	TID_ALLOC_ASSIGNED = 1,
	TID_ALLOC_NORMAL = 2,
};

/**
 * enum ummu_resource_type - SVA resource type
 *
 * @UMMU_BLOCK: mapt block
 * @UMMU_QUEUE: permission queue
 * @UMMU_QUEUE_LIST: permission queue for multi ummu
 * @UMMU_CNT: ummu count
 * @UMMU_TID_RES: tid resource
 */
enum ummu_resource_type {
	UMMU_BLOCK,
	UMMU_QUEUE,
	UMMU_QUEUE_LIST,
	UMMU_CNT,
	UMMU_TID_RES,
};

enum default_tid_ops_types {
	PASID_OPS,
	DEFAULT_OPS,
	TID_OPS_MAX,
};

enum ummu_device_config_type {
	UMMU_MPAM,
};

enum ummu_device_config_command {
	UMMU_COMMAND_SET,
	UMMU_COMMAND_GET,
};

/**
 * enum ummu_register_type - ummu device register type
 *
 * @REGISTER_TYPE_GLOBAL: register as the global iommu device
 * @REGISTER_TYPE_NORMAL: register to the iommu framework
 * @REGISTER_TYPE_MAX: max of ummu device register type
 */
enum ummu_register_type {
	REGISTER_TYPE_GLOBAL,
	REGISTER_TYPE_NORMAL,
	REGISTER_TYPE_MAX,
};

struct iova_slot;
struct ummu_tid_manager;
struct ummu_base_domain;
struct ummu_core_device;

/**
 * struct block_args - param related to mapt block
 * @index: mapt block index
 * @block_size_order: block size in PAGE_SIZE
 * @out_addr: allocated physical address
 */
struct block_args {
	u32 index;
	int block_size_order;
	phys_addr_t out_addr;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
};

/**
 * struct queue_args - param related to queue
 * @pcmdq_base: base address of command queue
 * @pcplq_base: base address of completion queue
 * @ctrl_page: base address of permission queue
 */
struct queue_args {
	phys_addr_t pcmdq_base;
	phys_addr_t pcplq_base;
	phys_addr_t ctrl_page;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
};

/**
 * struct tid_args - param related to tid
 * @pcmdq_order: base address of command queue
 * @pcplq_order: base address of completion queue
 * @blk_exp_size: block size in PAGE_SIZE
 * @hw_cap: cap of hardware
 */
struct tid_args {
	u8 pcmdq_order;
	u8 pcplq_order;
	size_t blk_exp_size;
	u64 hw_cap;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
};

/**
 * struct resource_args - SVA resource related args
 * @type: SVA resource type
 * @block: arg related to mapt block
 * @queue: arg related to mapt queue for UMMU_QUEUE
 * @queues: arg related to mapt queue for UMMU_QUEUE_LIST in multi ummu mode
 * @tid_res: tid resource
 * @ummu_cnt: return value number of ummu
 * @block_index: block index for release
 */
struct resource_args {
	enum ummu_resource_type type;
	union {
		struct block_args block;
		struct queue_args queue;
		struct queue_args *queues;
		struct tid_args tid_res;
		u32 ummu_cnt;
		u32 block_index;
	};
	int align;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
};

/**
 * struct ummu_param - param related to tid
 * @mode: mapt mode: table mode or entry mode
 */
struct ummu_param {
	enum ummu_mapt_mode mode;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
};

/**
 * struct ummu_tid_param - param related to alloc tid
 * @device: device pointer
 * @mode: mapt mode: table mode or entry mode
 * @alloc_mode: tid alloc mode
 * @assign_tid: assigned tid, for TID_ALLOC_TRANSPARENT or TID_ALLOC_ASSIGNED
 * @domain_type: more about domain-types in iommu.h
 * @mm: memory descriptor for TID
 */
struct ummu_tid_param {
	struct device *device;
	enum ummu_mapt_mode mode;
	enum tid_alloc_mode alloc_mode;
	u32 assign_tid;
	u32 domain_type;
	struct mm_struct *mm;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ummu_matt_domain - SVA separated page table context
 * @l_tid: Token ID for local access to memory
 * @r_tid: Token ID for remote memory access, optional
 * @mm: Address space of the process to which the mapped memory belongs
 */
struct ummu_matt_domain {
	u32 l_tid;
	u32 r_tid;
	struct mm_struct *mm;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
};

/**
 * struct tdev_attr - attr for tdev
 * @name: tdev name
 * @priv: private data pointer
 * @priv_len: private data length
 * @dma_attr: dma mode
 * @mode: mapt mode
 * @usva: tdev used for usva
 */
struct tdev_attr {
	const char *name;
	u8 *priv;
	u32 priv_len;
	enum dev_dma_attr dma_attr;
	enum ummu_mapt_mode mode;
	bool usva;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct tdev_opt - option for tdev
 * @mm: mm of the process that creates tid
 * @share_by_mm: indicates whether the same mm returns the same tid.
 *               true: share tid for same mm
 *               false: allocate new tid
 */
struct tdev_opt {
	struct mm_struct *mm;
	bool share_by_mm;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
};

/**
 * struct ummu_invalid_cfg_param - param of invalid tid config
 * @mm: mm of the process that creates tid
 * @tid: tid to invalidate
 */
struct ummu_invalid_cfg_param {
	struct mm_struct *mm;
	u32 tid;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
};

/**
 * struct ummu_core_ops - ummu ops for normal use, expand from iommu_ops.
 * @get_resource: Get resource for SVA.
 * @put_resource: Put resource for SVA.
 * @add_eid: Add EID to the UMMU device.
 * @del_eid: Add EID to the UMMU device.
 * @invalidate_cfg: invalid configuration table by tid.
 * @cfg_syn_all: synchronize all configuration table.
 * @cfg_syn: synchronize configuration table by tid.
 * @tdev_support_attr: Check whether the UMMU device supports the tdev attribute.
 * @get_hw_cap: Get UMMU capability for device.
 * @dev_config: UMMU device config.
 * @tlb_inv_walk: Synchronously invalidate all intermediate TLB state
 *                (sometimes referred to as the "walk cache") for a virtual
 *                address range.
 */
struct ummu_core_ops {
	int (*get_resource)(struct ummu_base_domain *d, struct resource_args *arg);
	void (*put_resource)(struct ummu_base_domain *d, struct resource_args *arg);
	int (*add_eid)(struct ummu_core_device *dev, guid_t *guid, eid_t eid,
		       enum eid_type type);
	void (*del_eid)(struct ummu_core_device *dev, guid_t *guid, eid_t eid,
			enum eid_type type);
	int (*invalidate_cfg)(struct ummu_base_domain *d);
	void (*cfg_sync_all)(struct ummu_base_domain *d);
	void (*cfg_sync)(struct ummu_base_domain *d);
	bool (*tdev_support_attr)(struct ummu_core_device *dev, struct tdev_attr *attr);
	int (*get_hw_cap)(struct device *dev, u32 *hw_cap);
	KABI_USE(1, int (*dev_config)(struct device *dev, int type, int command, void *data))
	KABI_USE(2, void (*tlb_inv_walk)(struct iommu_domain *domain, unsigned long iova,
					 size_t size, size_t granule))

	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
};

/**
 * struct ummu_core_device - ummu-core defined iommu device type
 * @list: used to link all ummu-core devices
 * @tid_manager: tid domain manager.
 * @iommu: iommu prototype
 * @ops: ummu-core defined iommu operations
 */
struct ummu_core_device {
	struct list_head list;
	struct ummu_tid_manager *tid_manager;
	struct iommu_device iommu;
	const struct ummu_core_ops *ops;
	struct device *ummu_core_root;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
};

/**
 * struct ummu_base_domain - domain info
 * @domain: iommu domain
 * @core_dev: ummu device
 * @parent: point to father domain
 * @list: base address of domain list
 * @tid: token id
 */
struct ummu_base_domain {
	struct iommu_domain domain;
	struct ummu_core_device *core_dev;
	struct iommu_domain *parent;
	struct list_head list;
	u32 tid;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct tid_ops - ummu ops for normal use, expand from iommu_ops
 * @alloc_tid_manager: alloc manager for tid
 * @free_tid_manager: free all tid and manager for tid
 * @alloc_tid: alloc tid func
 * @free_tid: free tid func
 */
struct tid_ops {
	struct ummu_tid_manager *(*alloc_tid_manager)(
		struct ummu_core_device *core_device, u32 min_tid,
		u32 max_tid);
	void (*free_tid_manager)(struct ummu_tid_manager *manager);
	int (*alloc_tid)(struct ummu_tid_manager *manager,
			 struct ummu_tid_param *param, u32 *tidp);
	void (*free_tid)(struct ummu_tid_manager *manager, u32 tid);

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ummu_tid_manager - assigned tid manager
 * @ops: ummu tid ops for normal use, expand from iommu_ops
 * @token_ids: xarray of assigned tid
 * @min_tid: min tid range for alloc
 * @max_tid: max tid range for alloc
 */
struct ummu_tid_manager {
	const struct tid_ops *ops;
	struct xarray token_ids;
	u32 min_tid;
	u32 max_tid;
	void *tid_data;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ummu_core_tid_args - tid related args
 * @tid_ops: ummu tid ops for normal use, expand from iommu_ops
 * @max_tid: max tid range for alloc
 * @min_tid: min tid range for alloc
 */
struct ummu_core_tid_args {
	const struct tid_ops *tid_ops;
	u32 max_tid;
	u32 min_tid;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
};

/**
 * struct ummu_core_init_args - ummu core init args
 * @core_ops: the ummu device need ummu core ops capability
 * @tid_args: parameters related to tid
 * @iommu_ops: iommu_ops is mandatory
 * @hwdev: related hwdev
 */
struct ummu_core_init_args {
	const struct ummu_core_ops *core_ops;
	struct ummu_core_tid_args tid_args;
	const struct iommu_ops *iommu_ops;
	struct device *hwdev;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
};

/**
 * struct ummu_mpam - Memory traffic monitoring of the UB device
 * @eid:		entity id
 * @tid:		tid; when set to UMMU_INVALID_TID, the I/O of the device
 *			identified by eid is tagged with MPAM.
 *			When tid is valid, the I/O of the device identified
 *			by tid is tagged with MPAM.
 * @partid:		mpam partition id
 * @pmg:		mpam pmg
 */
struct ummu_mpam {
	eid_t eid;
	int tid;
	int partid;
	int pmg;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

#if IS_ENABLED(CONFIG_UB_UMMU_CORE_DRIVER)
extern const struct tid_ops *ummu_core_tid_ops[TID_OPS_MAX];
#endif /* CONFIG_UB_UMMU_CORE_DRIVER */

static inline struct ummu_core_device *to_ummu_core(struct iommu_device *iommu)
{
	return container_of(iommu, struct ummu_core_device, iommu);
}

static inline struct ummu_base_domain *
to_ummu_base_domain(struct iommu_domain *dom)
{
	return container_of(dom, struct ummu_base_domain, domain);
}

static inline void tdev_attr_init(struct tdev_attr *attr)
{
	attr->dma_attr = DEV_DMA_COHERENT;
	attr->name = NULL;
	attr->priv = NULL;
	attr->priv_len = 0;
	attr->mode = MAPT_MODE_END;
	attr->usva = false;
}

#ifdef CONFIG_UB_UMMU_CORE
/* EID API */
/**
 * ummu_core_add_eid() - Add a new EID to the UMMU.
 * @guid: entity/device identity.
 * @eid: entity id to be added.
 * @type: eid type.
 *
 * Return: 0 on success, or an error.
 */
int ummu_core_add_eid(guid_t *guid, eid_t eid, enum eid_type type);
/**
 * ummu_core_del_eid() - Delete an EID from the UMMU.
 * @guid: entity/device identity.
 * @eid: entity id to be deleted.
 * @type: eid type.
 */
void ummu_core_del_eid(guid_t *guid, eid_t eid, enum eid_type type);

/* UMMU IOVA API */
/**
 * dma_alloc_iova() - Allocate a range of IOVA. The input iova size might be aligned.
 * @dev: related device.
 * @size: iova size.
 * @attrs: dma attributes.
 * @iovap: iova address returned here.
 * @sizep: iova size returned here.
 *
 * Return: iova slot which managed the iova range, or an ERR_PTR.
 */
struct iova_slot *dma_alloc_iova(struct device *dev, size_t size,
				 unsigned long attrs, dma_addr_t *iovap,
				 size_t *sizep);

/**
 * dma_free_iova() - Free a range of IOVA.
 * The API is not thread-safe.
 * @slot: iova slot, generated from dma_alloc_iova.
 */
void dma_free_iova(struct iova_slot *slot);

/**
 * ummu_fill_pages() - Fill a range of IOVA. It allocates pages and maps pages to the iova.
 * The API is not thread-safe.
 * Deprecated: Use ummu_core_fill_pages() instead.
 * @slot: iova slot, generated from dma_alloc_iova.
 * @iova: iova start.
 * @nr_pages: fill pages count.
 *
 * Return: 0 on success, or an error number.
 */
int ummu_fill_pages(struct iova_slot *slot, dma_addr_t iova, unsigned long nr_pages);

/**
 * ummu_drain_pages() - Drain a range of IOVA. It unmaps iova and releases pages.
 * The API is not thread-safe.
 * Deprecated: Use ummu_core_drain_pages() instead.
 * @slot: iova slot, generated from dma_alloc_iova.
 * @iova: iova start.
 * @nr_pages: drain pages count.
 *
 * Return: 0 on success, or an error number.
 */
int ummu_drain_pages(struct iova_slot *slot, dma_addr_t iova, unsigned long nr_pages);

/**
 * ummu_core_fill_pages() - Fill a range of IOVA, It allocates pages and maps pages to the iova.
 * The API is not thread-safe.
 * @slot: iova slot, generated from dma_alloc_iova.
 * @iova: iova start.
 * @nr_pages: fill pages count.
 * @gfp: GFP flags for memory allocation(e.g., GFP_KERNEL, __GFP_ZERO).
 *
 * Return: 0 on success, or an error number.
 */
int ummu_core_fill_pages(struct iova_slot *slot, dma_addr_t iova,
			 unsigned long nr_pages, gfp_t gfp);

/**
 * ummu_core_drain_pages() - Drain a range of IOVA, It unmaps iova and releases pages.
 * The API is not thread-safe.
 * @slot: iova slot, generated from dma_alloc_iova.
 * @iova: iova start.
 * @nr_pages: drain pages count.
 *
 * Return: 0 on success, or an error number.
 */
int ummu_core_drain_pages(struct iova_slot *slot, dma_addr_t iova, unsigned long nr_pages);

/**
 * ummu_core_tlb_inv_walk() - Synchronously invalidate all intermediate TLB state
 * (sometimes referred to as the "walk cache") for a virtual address range.
 * @domain: iommu domain
 * @iova: IOVA representing the start of the range to be flushed
 * @size: IOVA representing the end of the range to be flushed (inclusive)
 * @granule: The interval at which to perform the flush
 */
void ummu_core_tlb_inv_walk(struct iommu_domain *domain, unsigned long iova,
			    size_t size, size_t granule);

#else
static inline int ummu_core_add_eid(guid_t *guid, eid_t eid, enum eid_type type)
{
	return -EOPNOTSUPP;
}

static inline void ummu_core_del_eid(guid_t *guid, eid_t eid,
				     enum eid_type type)
{
}

static inline struct iova_slot *dma_alloc_iova(struct device *dev, size_t size,
					       unsigned long attrs,
					       dma_addr_t *iovap, size_t *sizep)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void dma_free_iova(struct iova_slot *slot)
{
}
static inline int ummu_fill_pages(struct iova_slot *slot, dma_addr_t iova,
				  unsigned long nr_pages)
{
	return -EOPNOTSUPP;
}

static inline int ummu_drain_pages(struct iova_slot *slot, dma_addr_t iova,
				   unsigned long nr_pages)
{
	return -EOPNOTSUPP;
}

static inline int ummu_core_fill_pages(struct iova_slot *slot, dma_addr_t iova,
				       unsigned long nr_pages, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static inline int ummu_core_drain_pages(struct iova_slot *slot, dma_addr_t iova,
					unsigned long nr_pages)
{
	return -EOPNOTSUPP;
}

static inline void ummu_core_tlb_inv_walk(struct iommu_domain *domain, unsigned long iova,
					  size_t size, size_t granule)
{
}

#endif /* CONFIG_UB_UMMU_CORE */

#if IS_ENABLED(CONFIG_UB_UMMU_CORE_DRIVER)
/* UMMU SVA API */
/**
 * ummu_sva_grant_range() - Grant va range permission to sva.
 * @Deprecated: use iommu_sva_grant instead.
 * @sva: related sva handle.
 * @va: va start
 * @size: va size
 * @perm: permission
 * @cookie: struct ummu_token_info*
 *
 * .. code-block:: c
 *
 *		if (!cookie) {
 *			do not use cookie check.
 *		} else if (cookie->input == 0) {
 *			use this cookie->tokenval
 *		} else if (cookie->input == 1) {
 *			cookie->tokenval = generate new one
 *		} else {
 *			invalid para
 *		}
 * Return: 0 on success, or an error.
 */
int ummu_sva_grant_range(struct iommu_sva *sva, void *va, size_t size, int perm,
			 void *cookie);

/**
 * ummu_sva_ungrant_range() - Ungrant va range permission from sva.
 * @Deprecated: use iommu_sva_ungrant instead.
 * @sva: related sva handle.
 * @va: va start
 * @size: va size
 * @cookie: va related cookie,struct ummu_token_info*
 *
 * .. code-block:: c
 *
 *		if (!cookie) {
 *			do not use cookie check.
 *		} else {
 *			ungrant by cookie->tokenval
 *		}
 *
 * Return: 0 an success, or an error.
 */
int ummu_sva_ungrant_range(struct iommu_sva *sva, void *va, size_t size,
			   void *cookie);

/**
 * ummu_get_tid() - Get tid from dev or sva.
 * @dev: related device.
 * @sva: if sva is set, return sva mode related tid; otherwise
 *	 return the dma mode tid.
 * @tidp: tid returned here.
 *
 * Return: 0 on success, or an error.
 */
int ummu_get_tid(struct device *dev, struct iommu_sva *sva, u32 *tidp);

/**
 * ummu_core_get_domain_by_tid() - Get iommu_domain by tid and dev.
 * @dev: related device.
 * @tid: tid
 *
 * Return: iommu_domain or NULL if failed.
 */
struct iommu_domain *ummu_core_get_domain_by_tid(struct device *dev,
						 u32 tid);

/**
 * ummu_is_ksva() - Check whether the UMMU works in ksva mode.
 * @Deprecated: use iommu_is_ksva_domain instead.
 * @domain: related iommu domain
 *
 * Return: true or false.
 */
bool ummu_is_ksva(struct iommu_domain *domain);

/**
 * ummu_is_sva() - Check whether the UMMU works in sva mode.
 * @Deprecated: use iommu_is_ksva_domain instead.
 * @domain: related iommu domain
 *
 * Return: true or false.
 */
bool ummu_is_sva(struct iommu_domain *domain);

/**
 * ummu_get_sva_mode() - Get the device SVA working mode
 * @dev: device with SVA feature enabled
 * Return: UMMU_SVA_SHARE_MODE - sva share mode
 *	   UMMU_SVA_SEPARATE_MODE - sva separate mode
 *	   other - invalid mode
 */
int ummu_get_sva_mode(struct device *dev);

/**
 * ummu_sva_get_features() - Get the sva feature of a peripheral.
 * @dev: the device that work on sva mode
 * Return: 32-bit value. bit HW_CAP_IOPF: 0- no IOPF cap; 1- with IOPF cap
 */
u32 ummu_sva_get_features(struct device *dev);

/**
 * ummu_sva_bind_device() - Bind device to a process mm.
 * @Deprecated: use iommu_sva_bind_device_isolated instead.
 * @dev: related device.
 * @mm: process memory management.
 * @drvdata: ummu_param related to tid.
 *
 * .. code-block:: c
 *
 *		if (!drvdata) {
 *			sva is in the bypass mapt mode.
 *		} else {
 *			follow the drvdata->mode to set mapt mode.
 *		}
 *
 * Return: sva handle or NULL if failed.
 */
struct iommu_sva *ummu_sva_bind_device(struct device *dev, struct mm_struct *mm,
				       struct ummu_param *drvdata);

/**
 * ummu_ksva_bind_device() - Bind device to kernel mm.
 * @Deprecated: use iommu_ksva_bind_device instead.
 * @dev: related device.
 * @drvdata: ummu_param related to tid. ksva doesn't support bypass mapt.
 *
 * Return: sva handle or NULL if failed.
 */
struct iommu_sva *ummu_ksva_bind_device(struct device *dev,
					struct ummu_param *drvdata);
/**
 * ummu_sva_unbind_device() - Unbind device to a process mm.
 * @Deprecated: use iommu_sva_unbind_device_isolated instead.
 */
void ummu_sva_unbind_device(struct iommu_sva *handle);
/**
 * ummu_ksva_unbind_device() - Unbind device to kernel mm.
 * @Deprecated: use iommu_ksva_unbind_device instead.
 */
void ummu_ksva_unbind_device(struct iommu_sva *handle);

/* UMMU CORE API */
/**
 * ummu_core_device_init() - Initialiase ummu core device.
 * @ummu_core: ummu core device.
 * @args: ummu core init args.
 *
 * UMMU driver should carefully choose the args based on its requirement.
 *	iommu_ops is mandatory.
 *	a. the ummu device need tid allocation capability.
 *
 *		a.1 default tid strategies satisfy the ummu device
 *			-> set tid_ops form ummu_core_tid_ops[TID_OPS_MAX]
 *		a.2 default tid strategies do not satisfy the ummu device
 *			-> implement a new tid_ops in the driver.
 *
 *	b. the ummu device need ummu core ops capability.
 *		-> set core_ops.
 *
 *	c. the ummu device has related hwdev.
 *		-> set hwdev.
 */
int ummu_core_device_init(struct ummu_core_device *ummu_core,
			  struct ummu_core_init_args *args);
/**
 * ummu_core_device_deinit() - Deinitialiase ummu core device.
 * @ummu_core: ummu core device.
 */
void ummu_core_device_deinit(struct ummu_core_device *ummu_core);

/**
 * ummu_core_device_register() - Register ummu core device to the ummu framework.
 * @ummu_core: ummu core device.
 * @type: register type.
 *
 *	REGISTER_TYPE_GLOBAL: register the ummu device as the global device,
 *		The ummu device will be the device handle all request.
 *		e.g. 1. add_eid/del_eid 2. provide ubus iommu ops. etc.
 *
 *	REGISTER_TYPE_NORMAL: follow the iommu_device register. will not be
 *		related to the global device. it work as a normal iommu device.
 */
int ummu_core_device_register(struct ummu_core_device *ummu_core,
			      enum ummu_register_type type);
/**
 * ummu_core_device_unregister() - Unregister ummu core device from the ummu framework.
 * @dev: the ummu_core device tid belongs to.
 */
void ummu_core_device_unregister(struct ummu_core_device *dev);

/**
 * ummu_core_invalidate_cfg_table() - Invalidate ummu global configuration by tid.
 * @Deprecated: use ummu_core_invalidate_cfg instead.
 * @tid: tid
 * Return: 0 on success, or an error.
 */
int ummu_core_invalidate_cfg_table(u32 tid);

/**
 * ummu_core_invalidate_cfg() - Invalidate ummu global configuration by param.
 * @param: tid index parameter to invalidate.
 * Return: 0 on success, or an error.
 */
int ummu_core_invalidate_cfg(struct ummu_invalid_cfg_param *param);

/* UMMU TID API */
/**
 * ummu_core_alloc_tid() - Alloc a tid from ummu framework, and alloc related pasid.
 * @dev: the allocated tid will be attached to.
 * @drvdata: ummu_tid_param related to tid
 * @tidp: the allocated tid returned here.
 *
 * Return: 0 on success, or an error.
 */
int ummu_core_alloc_tid(struct ummu_core_device *dev,
			struct ummu_tid_param *drvdata, u32 *tidp);

/**
 * ummu_core_free_tid() - Free a tid to ummu framework.
 * @dev: the ummu_core device tid belongs to.
 * @tid: token id.
 */
void ummu_core_free_tid(struct ummu_core_device *dev, u32 tid);

/**
 * ummu_core_get_mapt_mode() - Get mapt_mode related to the tid.
 * @dev: the ummu_core device tid belongs to.
 * @tid: token id.
 *
 * Return: ummu_mapt_mode, negative for an error.
 */
enum ummu_mapt_mode ummu_core_get_mapt_mode(struct ummu_core_device *dev,
					    u32 tid);

/**
 * ummu_core_get_device() - Get device related to the tid.
 * It will increase the ref count of the device.
 * @dev: the ummu_core device tid belongs to.
 * @tid: token id.
 *
 * Return: device or NULL if failed.
 */
struct device *ummu_core_get_device(struct ummu_core_device *dev, u32 tid);
void ummu_core_put_device(struct device *dev);

/**
 * ummu_core_alloc_tdev() - Allocate a virtual device to hold a tid.
 * @attr: attributes of tdev
 * @ptid: tid pointer
 * Return: device on success or NULL error.
 */
struct device *ummu_core_alloc_tdev(struct tdev_attr *attr, u32 *ptid);

/**
 * ummu_alloc_tdev_separated() - Allocate a virtual device for sva separated mode.
 * @Deprecated: use ummu_core_alloc_separate_tdev instead.
 * @ptid: tid pointer
 * Return: device on success or NULL error.
 */
struct device *ummu_alloc_tdev_separated(u32 *ptid);

/**
 * ummu_core_free_tdev() - Free the virtual device
 * @dev: Return value allocated by ummu_core_alloc_tdev
 *
 * Return: 0 on success or an error.
 */
int ummu_core_free_tdev(struct device *dev);

/**
 * ummu_core_get_tid_type() - Get ummu_tid_type related to the tid.
 * @dev: the ummu_core device tid belongs to.
 * @tid: token id.
 * @tid_type: out param, ummu_tid_type
 *
 * Return: 0 on success , others for an error.
 */
int ummu_core_get_tid_type(struct ummu_core_device *dev, u32 tid,
			   u32 *tid_type);

/**
 * ummu_core_dev_config() - ummu core dev config
 * @dev: pointer to the device
 * @type: defined in enum ummu_device_config_type (e.g., UMMU_MPAM)
 * @command: operation command, e.g., UMMU_COMMAND_SET or UMMU_COMMAND_GET
 * @data: pointer to configuration data (e.g., struct ummu_mpam *)
 *
 * Return: 0 on success , others for an error.
 */
int ummu_core_dev_config(struct device *dev, int type, int command, void *data);

#else
static inline int ummu_sva_grant_range(struct iommu_sva *sva, void *va,
				       size_t size, int perm, void *cookie)
{
	return -EOPNOTSUPP;
}

static inline int ummu_sva_ungrant_range(struct iommu_sva *sva, void *va,
					 size_t size, void *cookie)
{
	return -EOPNOTSUPP;
}

static inline int ummu_get_tid(struct device *dev, struct iommu_sva *sva,
			       u32 *tidp)
{
	return -EOPNOTSUPP;
}

static inline struct iommu_domain *
ummu_core_get_domain_by_tid(struct device *dev, u32 tid)
{
	return NULL;
}

static inline bool ummu_is_ksva(struct iommu_domain *domain)
{
	return false;
}

static inline bool ummu_is_sva(struct iommu_domain *domain)
{
	return false;
}

static inline int ummu_get_sva_mode(struct device *dev)
{
	return 0;
}

static inline u32 ummu_sva_get_features(struct device *dev)
{
	return 0;
}

static inline struct iommu_sva *ummu_sva_bind_device(struct device *dev,
						     struct mm_struct *mm,
						     struct ummu_param *drvdata)
{
	return NULL;
}

static inline struct iommu_sva *
ummu_ksva_bind_device(struct device *dev, struct ummu_param *drvdata)
{
	return NULL;
}

static inline void ummu_sva_unbind_device(struct iommu_sva *handle)
{
}
static inline void ummu_ksva_unbind_device(struct iommu_sva *handle)
{
}
static inline int ummu_core_device_init(struct ummu_core_device *ummu_core,
					struct ummu_core_init_args *args)
{
	return -EOPNOTSUPP;
}

static inline void ummu_core_device_deinit(struct ummu_core_device *ummu_core)
{
}
static inline int ummu_core_device_register(struct ummu_core_device *ummu_core,
					    enum ummu_register_type type)
{
	return -EOPNOTSUPP;
}

static inline void ummu_core_device_unregister(struct ummu_core_device *dev)
{
}
static inline int ummu_core_invalidate_cfg_table(u32 tid)
{
	return -EOPNOTSUPP;
}

static inline int ummu_core_invalidate_cfg(struct ummu_invalid_cfg_param *param)
{
	return -EOPNOTSUPP;
}

static inline int ummu_core_alloc_tid(struct ummu_core_device *dev,
				      struct ummu_tid_param *drvdata,
				      u32 *tidp)
{
	return -EOPNOTSUPP;
}

static inline void ummu_core_free_tid(struct ummu_core_device *dev,
				      u32 tid)
{
}
static inline enum ummu_mapt_mode
ummu_core_get_mapt_mode(struct ummu_core_device *dev, u32 tid)
{
	return MAPT_MODE_END;
}

static inline struct device *ummu_core_get_device(struct ummu_core_device *dev,
						  u32 tid)
{
	return NULL;
}

static inline void ummu_core_put_device(struct device *dev)
{
}

static inline struct device *ummu_core_alloc_tdev(struct tdev_attr *attr, u32 *ptid)
{
	return NULL;
}

static inline struct device *ummu_alloc_tdev_separated(u32 *ptid)
{
	return NULL;
}

static inline int ummu_core_free_tdev(struct device *dev)
{
	return -EOPNOTSUPP;
}

static inline int ummu_core_get_tid_type(struct ummu_core_device *dev, u32 tid,
					 u32 *tid_type)
{
	return -EOPNOTSUPP;
}

static inline int ummu_core_dev_config(struct device *dev, int type, int command, void *data)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_UB_UMMU_CORE_DRIVER */

#if IS_ENABLED(CONFIG_UB_UMMU_SVA_SEPARATED_PAGES)
/**
 * ummu_core_alloc_separate_tdev() - Allocate a virtual device for sva separated mode.
 * @opt: option for tdev
 * @ptid: tid pointer
 * Return: device on success or NULL error.
 */
struct device *ummu_core_alloc_separate_tdev(struct tdev_opt *opt, u32 *ptid);
/**
 * ummu_sva_matt_map() - Mapping interface in SVA-separated page table mode.
 * @matt_domain: page table mapping context.
 * @addr: mapping start address.
 * @sgt: sg_table object for mapping memory.
 * @prot: permission information.
 *
 * Return: 0 on success , others for an error.
 */
int ummu_sva_matt_map(struct ummu_matt_domain *matt_domain,
		      unsigned long addr, struct sg_table *sgt,
		      int prot);
/**
 * ummu_sva_matt_unmap() - unmapping interface in SVA-separated page table mode.
 * @matt_domain: page table unmapping context.
 * @addr: unmapping start address.
 * @size: unmapping memory size.
 *
 * Return: 0 on success , others for an error.
 */
int ummu_sva_matt_unmap(struct ummu_matt_domain *matt_domain,
			unsigned long addr, size_t size);
#else
static inline struct device *ummu_core_alloc_separate_tdev(
				struct tdev_opt *opt, u32 *ptid)
{
	return NULL;
}

static inline int ummu_sva_matt_map(struct ummu_matt_domain *matt_domain,
				    unsigned long addr, struct sg_table *sgt,
				    int prot)
{
	return -EINVAL;
}

static inline int ummu_sva_matt_unmap(struct ummu_matt_domain *matt_domain,
				      unsigned long addr, size_t size)
{
	return -EINVAL;
}
#endif /* CONFIG_UB_UMMU_SVA_SEPARATED_PAGES */

#endif /* _UMMU_CORE_H_ */
