/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifndef __LINUX_IOMMU_H
#define __LINUX_IOMMU_H

#include <linux/scatterlist.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/mmu_notifier.h>
#include <linux/of.h>
#include <uapi/linux/iommu.h>

#define IOMMU_READ	(1 << 0)
#define IOMMU_WRITE	(1 << 1)
#define IOMMU_CACHE	(1 << 2) /* DMA cache coherency */
#define IOMMU_NOEXEC	(1 << 3)
#define IOMMU_MMIO	(1 << 4) /* e.g. things like MSI doorbells */
/*
 * Where the bus hardware includes a privilege level as part of its access type
 * markings, and certain devices are capable of issuing transactions marked as
 * either 'supervisor' or 'user', the IOMMU_PRIV flag requests that the other
 * given permission flags only apply to accesses at the higher privilege level,
 * and that unprivileged transactions should have as little access as possible.
 * This would usually imply the same permissions as kernel mappings on the CPU,
 * if the IOMMU page table format is equivalent.
 */
#define IOMMU_PRIV	(1 << 5)

struct iommu_ops;
struct iommu_group;
struct bus_type;
struct device;
struct iommu_domain;
struct notifier_block;
struct iommu_fault_event;

/* iommu fault flags */
#define IOMMU_FAULT_READ		(1 << 0)
#define IOMMU_FAULT_WRITE		(1 << 1)
#define IOMMU_FAULT_EXEC		(1 << 2)
#define IOMMU_FAULT_PRIV		(1 << 3)

typedef int (*iommu_fault_handler_t)(struct iommu_domain *,
			struct device *, unsigned long, int, void *);
typedef int (*iommu_dev_fault_handler_t)(struct iommu_fault_event *, void *);
typedef int (*iommu_mm_exit_handler_t)(struct device *dev, int pasid, void *);

#define IOMMU_SVA_FEAT_IOPF		(1 << 0)

struct iommu_domain_geometry {
	dma_addr_t aperture_start; /* First address that can be mapped    */
	dma_addr_t aperture_end;   /* Last address that can be mapped     */
	bool force_aperture;       /* DMA only allowed in mappable range? */
};

/* Domain feature flags */
#define __IOMMU_DOMAIN_PAGING	(1U << 0)  /* Support for iommu_map/unmap */
#define __IOMMU_DOMAIN_DMA_API	(1U << 1)  /* Domain for use in DMA-API
					      implementation              */
#define __IOMMU_DOMAIN_PT	(1U << 2)  /* Domain is identity mapped   */

/*
 * This are the possible domain-types
 *
 *	IOMMU_DOMAIN_BLOCKED	- All DMA is blocked, can be used to isolate
 *				  devices
 *	IOMMU_DOMAIN_IDENTITY	- DMA addresses are system physical addresses
 *	IOMMU_DOMAIN_UNMANAGED	- DMA mappings managed by IOMMU-API user, used
 *				  for VMs
 *	IOMMU_DOMAIN_DMA	- Internally used for DMA-API implementations.
 *				  This flag allows IOMMU drivers to implement
 *				  certain optimizations for these domains
 */
#define IOMMU_DOMAIN_BLOCKED	(0U)
#define IOMMU_DOMAIN_IDENTITY	(__IOMMU_DOMAIN_PT)
#define IOMMU_DOMAIN_UNMANAGED	(__IOMMU_DOMAIN_PAGING)
#define IOMMU_DOMAIN_DMA	(__IOMMU_DOMAIN_PAGING |	\
				 __IOMMU_DOMAIN_DMA_API)

struct iommu_domain {
	unsigned type;
	const struct iommu_ops *ops;
	unsigned long pgsize_bitmap;	/* Bitmap of page sizes in use */
	iommu_fault_handler_t handler;
	void *handler_token;
	struct iommu_domain_geometry geometry;
	void *iova_cookie;

	struct list_head mm_list;
};

struct io_mm {
	int			pasid;
	/* IOMMU_SVA_FEAT_* */
	unsigned long		flags;
	struct list_head	devices;
	struct kref		kref;
#if defined(CONFIG_MMU_NOTIFIER)
	struct mmu_notifier	notifier;
#endif
	struct mm_struct	*mm;

	/* Release callback for this mm */
	void (*release)(struct io_mm *io_mm);
	/* For postponed release */
	struct rcu_head		rcu;
};

enum iommu_cap {
	IOMMU_CAP_CACHE_COHERENCY,	/* IOMMU can enforce cache coherent DMA
					   transactions */
	IOMMU_CAP_INTR_REMAP,		/* IOMMU supports interrupt isolation */
	IOMMU_CAP_NOEXEC,		/* IOMMU_NOEXEC flag */
};

/*
 * Following constraints are specifc to FSL_PAMUV1:
 *  -aperture must be power of 2, and naturally aligned
 *  -number of windows must be power of 2, and address space size
 *   of each window is determined by aperture size / # of windows
 *  -the actual size of the mapped region of a window must be power
 *   of 2 starting with 4KB and physical address must be naturally
 *   aligned.
 * DOMAIN_ATTR_FSL_PAMUV1 corresponds to the above mentioned contraints.
 * The caller can invoke iommu_domain_get_attr to check if the underlying
 * iommu implementation supports these constraints.
 */

enum iommu_attr {
	DOMAIN_ATTR_GEOMETRY,
	DOMAIN_ATTR_PAGING,
	DOMAIN_ATTR_WINDOWS,
	DOMAIN_ATTR_FSL_PAMU_STASH,
	DOMAIN_ATTR_FSL_PAMU_ENABLE,
	DOMAIN_ATTR_FSL_PAMUV1,
	DOMAIN_ATTR_NESTING,	/* two stages of translation */
	DOMAIN_ATTR_DMA_USE_FLUSH_QUEUE,
	DOMAIN_ATTR_MAX,
};

/* These are the possible reserved region types */
enum iommu_resv_type {
	/* Memory regions which must be mapped 1:1 at all times */
	IOMMU_RESV_DIRECT,
	/* Arbitrary "never map this or give it to a device" address ranges */
	IOMMU_RESV_RESERVED,
	/* Hardware MSI region (untranslated) */
	IOMMU_RESV_MSI,
	/* Software-managed MSI translation window */
	IOMMU_RESV_SW_MSI,
};

/**
 * struct iommu_resv_region - descriptor for a reserved memory region
 * @list: Linked list pointers
 * @start: System physical start address of the region
 * @length: Length of the region in bytes
 * @prot: IOMMU Protection flags (READ/WRITE/...)
 * @type: Type of the reserved region
 */
struct iommu_resv_region {
	struct list_head	list;
	phys_addr_t		start;
	size_t			length;
	int			prot;
	enum iommu_resv_type	type;
};

/**
 * enum page_response_code - Return status of fault handlers, telling the IOMMU
 * driver how to proceed with the fault.
 *
 * @IOMMU_FAULT_STATUS_SUCCESS: Fault has been handled and the page tables
 *	populated, retry the access. This is "Success" in PCI PRI.
 * @IOMMU_FAULT_STATUS_FAILURE: General error. Drop all subsequent faults from
 *	this device if possible. This is "Response Failure" in PCI PRI.
 * @IOMMU_FAULT_STATUS_INVALID: Could not handle this fault, don't retry the
 *	access. This is "Invalid Request" in PCI PRI.
 */
enum page_response_code {
	IOMMU_PAGE_RESP_SUCCESS = 0,
	IOMMU_PAGE_RESP_INVALID,
	IOMMU_PAGE_RESP_FAILURE,
};

/**
 * Generic page response information based on PCI ATS and PASID spec.
 * @addr: servicing page address
 * @pasid: contains process address space ID
 * @resp_code: response code
 * @page_req_group_id: page request group index
 * @type: group or stream/single page response
 * @private_data: uniquely identify device-specific private data for an
 *                individual page response
 */
struct page_response_msg {
	u64 addr;
	u32 pasid;
	enum page_response_code resp_code;
	u32 pasid_present:1;
	u32 page_req_group_id;
	u64 private_data;
};

/**
 * iopf_queue_flush_t - Flush low-level page fault queue
 *
 * Report all faults currently pending in the low-level page fault queue
 */
struct iopf_queue;
typedef int (*iopf_queue_flush_t)(void *cookie, struct device *dev);

#ifdef CONFIG_IOMMU_API

/**
 * enum page_request_handle_t - Return page request/response handler status
 *
 * @IOMMU_FAULT_STATUS_HANDLED: Stop processing the fault, and do not send a
 *	reply to the device.
 * @IOMMU_FAULT_STATUS_CONTINUE: Fault was not handled. Call the next handler,
 *	or terminate.
 */
enum page_request_handle_t {
	IOMMU_PAGE_RESP_HANDLED = 0,
	IOMMU_PAGE_RESP_CONTINUE,
};

struct iommu_sva_param {
	unsigned long features;
	unsigned int min_pasid;
	unsigned int max_pasid;
	struct list_head mm_list;
	iommu_mm_exit_handler_t mm_exit;
};

/**
 * struct iommu_ops - iommu ops and capabilities
 * @capable: check capability
 * @domain_alloc: allocate iommu domain
 * @domain_free: free iommu domain
 * @attach_dev: attach device to an iommu domain
 * @detach_dev: detach device from an iommu domain
 * @sva_device_init: initialize Shared Virtual Adressing for a device
 * @sva_device_shutdown: shutdown Shared Virtual Adressing for a device
 * @mm_alloc: allocate io_mm
 * @mm_free: free io_mm
 * @mm_attach: attach io_mm to a device. Install PASID entry if necessary
 * @mm_detach: detach io_mm from a device. Remove PASID entry and
 *             flush associated TLB entries.
 * @mm_invalidate: Invalidate a range of mappings for an mm
 * @map: map a physically contiguous memory region to an iommu domain
 * @unmap: unmap a physically contiguous memory region from an iommu domain
 * @flush_tlb_all: Synchronously flush all hardware TLBs for this domain
 * @tlb_range_add: Add a given iova range to the flush queue for this domain
 * @tlb_sync: Flush all queued ranges from the hardware TLBs and empty flush
 *            queue
 * @iova_to_phys: translate iova to physical address
 * @add_device: add device to iommu grouping
 * @remove_device: remove device from iommu grouping
 * @device_group: find iommu group for a particular device
 * @domain_get_attr: Query domain attributes
 * @domain_set_attr: Change domain attributes
 * @get_resv_regions: Request list of reserved regions for a device
 * @put_resv_regions: Free list of reserved regions for a device
 * @apply_resv_region: Temporary helper call-back for iova reserved ranges
 * @domain_window_enable: Configure and enable a particular window for a domain
 * @domain_window_disable: Disable a particular window for a domain
 * @domain_set_windows: Set the number of windows for a domain
 * @domain_get_windows: Return the number of windows for a domain
 * @of_xlate: add OF master IDs to iommu grouping
 * @pgsize_bitmap: bitmap of all possible supported page sizes
 * @bind_pasid_table: bind pasid table pointer for guest SVM
 * @unbind_pasid_table: unbind pasid table pointer and restore defaults
 * @sva_invalidate: invalidate translation caches of shared virtual address
 * @page_response: handle page request response
 */
struct iommu_ops {
	bool (*capable)(enum iommu_cap);

	/* Domain allocation and freeing by the iommu driver */
	struct iommu_domain *(*domain_alloc)(unsigned iommu_domain_type);
	void (*domain_free)(struct iommu_domain *);

	int (*attach_dev)(struct iommu_domain *domain, struct device *dev);
	void (*detach_dev)(struct iommu_domain *domain, struct device *dev);
	int (*sva_device_init)(struct device *dev,
			       struct iommu_sva_param *param);
	void (*sva_device_shutdown)(struct device *dev,
				    struct iommu_sva_param *param);
	struct io_mm *(*mm_alloc)(struct iommu_domain *domain,
				  struct mm_struct *mm,
				  unsigned long flags);
	void (*mm_free)(struct io_mm *io_mm);
	int (*mm_attach)(struct iommu_domain *domain, struct device *dev,
			 struct io_mm *io_mm, bool attach_domain);
	void (*mm_detach)(struct iommu_domain *domain, struct device *dev,
			  struct io_mm *io_mm, bool detach_domain);
	void (*mm_invalidate)(struct iommu_domain *domain, struct device *dev,
			      struct io_mm *io_mm, unsigned long vaddr,
			      size_t size);
	int (*map)(struct iommu_domain *domain, unsigned long iova,
		   phys_addr_t paddr, size_t size, int prot);
	size_t (*unmap)(struct iommu_domain *domain, unsigned long iova,
		     size_t size);
	void (*flush_iotlb_all)(struct iommu_domain *domain);
	void (*iotlb_range_add)(struct iommu_domain *domain,
				unsigned long iova, size_t size);
	void (*iotlb_sync)(struct iommu_domain *domain);
	phys_addr_t (*iova_to_phys)(struct iommu_domain *domain, dma_addr_t iova);
	int (*add_device)(struct device *dev);
	void (*remove_device)(struct device *dev);
	struct iommu_group *(*device_group)(struct device *dev);
	int (*domain_get_attr)(struct iommu_domain *domain,
			       enum iommu_attr attr, void *data);
	int (*domain_set_attr)(struct iommu_domain *domain,
			       enum iommu_attr attr, void *data);

	/* Request/Free a list of reserved regions for a device */
	void (*get_resv_regions)(struct device *dev, struct list_head *list);
	void (*put_resv_regions)(struct device *dev, struct list_head *list);
	void (*apply_resv_region)(struct device *dev,
				  struct iommu_domain *domain,
				  struct iommu_resv_region *region);

	/* Window handling functions */
	int (*domain_window_enable)(struct iommu_domain *domain, u32 wnd_nr,
				    phys_addr_t paddr, u64 size, int prot);
	void (*domain_window_disable)(struct iommu_domain *domain, u32 wnd_nr);
	/* Set the number of windows per domain */
	int (*domain_set_windows)(struct iommu_domain *domain, u32 w_count);
	/* Get the number of windows per domain */
	u32 (*domain_get_windows)(struct iommu_domain *domain);

	int (*of_xlate)(struct device *dev, struct of_phandle_args *args);

	bool (*is_attach_deferred)(struct iommu_domain *domain, struct device *dev);

	int (*bind_pasid_table)(struct iommu_domain *domain, struct device *dev,
				struct pasid_table_config *pasidt_binfo);
	void (*unbind_pasid_table)(struct iommu_domain *domain,
				struct device *dev);
	int (*sva_invalidate)(struct iommu_domain *domain,
		struct device *dev, struct tlb_invalidate_info *inv_info);
	int (*page_response)(struct device *dev, struct page_response_msg *msg);

	unsigned long pgsize_bitmap;

#ifdef CONFIG_SMMU_BYPASS_DEV
#ifndef __GENKSYMS__
	int (*device_domain_type)(struct device *dev, unsigned int *type);
#endif
#endif
};

/**
 * struct iommu_device - IOMMU core representation of one IOMMU hardware
 *			 instance
 * @list: Used by the iommu-core to keep a list of registered iommus
 * @ops: iommu-ops for talking to this iommu
 * @dev: struct device for sysfs handling
 */
struct iommu_device {
	struct list_head list;
	const struct iommu_ops *ops;
	struct fwnode_handle *fwnode;
	struct device *dev;
};

/*  Generic fault types, can be expanded IRQ remapping fault */
enum iommu_fault_type {
	IOMMU_FAULT_DMA_UNRECOV = 1,	/* unrecoverable fault */
	IOMMU_FAULT_PAGE_REQ,		/* page request fault */
};

enum iommu_fault_reason {
	IOMMU_FAULT_REASON_UNKNOWN = 0,

	/* IOMMU internal error, no specific reason to report out */
	IOMMU_FAULT_REASON_INTERNAL,

	/* Could not access the PASID table */
	IOMMU_FAULT_REASON_PASID_FETCH,

	/*
	 * PASID is out of range (e.g. exceeds the maximum PASID
	 * supported by the IOMMU) or disabled.
	 */
	IOMMU_FAULT_REASON_PASID_INVALID,

	/* Could not access the page directory (Invalid PASID entry) */
	IOMMU_FAULT_REASON_PGD_FETCH,

	/* Could not access the page table entry (Bad address) */
	IOMMU_FAULT_REASON_PTE_FETCH,

	/* Protection flag check failed */
	IOMMU_FAULT_REASON_PERMISSION,
};

/**
 * struct iommu_fault_event - Generic per device fault data
 *
 * - PCI and non-PCI devices
 * - Recoverable faults (e.g. page request), information based on PCI ATS
 * and PASID spec.
 * - Un-recoverable faults of device interest
 * - DMA remapping and IRQ remapping faults
 *
 * @list pending fault event list, used for tracking responses
 * @type contains fault type.
 * @reason fault reasons if relevant outside IOMMU driver, IOMMU driver internal
 *         faults are not reported
 * @addr: tells the offending page address
 * @pasid: contains process address space ID, used in shared virtual memory(SVM)
 * @rid: requestor ID
 * @page_req_group_id: page request group index
 * @last_req: last request in a page request group
 * @pasid_valid: indicates if the PRQ has a valid PASID
 * @prot: page access protection flag, e.g. IOMMU_FAULT_READ, IOMMU_FAULT_WRITE
 * @device_private: if present, uniquely identify device-specific
 *                  private data for an individual page request.
 * @iommu_private: used by the IOMMU driver for storing fault-specific
 *                 data. Users should not modify this field before
 *                 sending the fault response.
 * @expire: time limit in jiffies will wait for page response
 */
struct iommu_fault_event {
	struct list_head list;
	enum iommu_fault_type type;
	enum iommu_fault_reason reason;
	u64 addr;
	u32 pasid;
	u32 page_req_group_id;
	u32 last_req : 1;
	u32 pasid_valid : 1;
	u32 prot;
	u64 device_private;
	u64 iommu_private;
	u64 expire;
};

/**
 * struct iommu_fault_param - per-device IOMMU fault data
 * @dev_fault_handler: Callback function to handle IOMMU faults at device level
 * @data: handler private data
 * @faults: holds the pending faults which needs response, e.g. page response.
 * @timer: track page request pending time limit
 * @lock: protect pending PRQ event list
 */
struct iommu_fault_param {
	iommu_dev_fault_handler_t handler;
	struct list_head faults;
	struct timer_list timer;
	struct mutex lock;
	void *data;
};

/**
 * struct iommu_param - collection of per-device IOMMU data
 *
 * @fault_param: IOMMU detected device fault reporting data
 * @sva_param: SVA parameters
 * @iopf_param: I/O Page Fault queue and data
 *
 * TODO: migrate other per device data pointers under iommu_dev_data, e.g.
 *	struct iommu_group	*iommu_group;
 *	struct iommu_fwspec	*iommu_fwspec;
 */
struct iommu_param {
	struct mutex lock;
	struct iommu_fault_param *fault_param;
	struct iommu_sva_param *sva_param;
	struct iopf_device_param *iopf_param;
};

int  iommu_device_register(struct iommu_device *iommu);
void iommu_device_unregister(struct iommu_device *iommu);
int  iommu_device_sysfs_add(struct iommu_device *iommu,
			    struct device *parent,
			    const struct attribute_group **groups,
			    const char *fmt, ...) __printf(4, 5);
void iommu_device_sysfs_remove(struct iommu_device *iommu);
int  iommu_device_link(struct iommu_device   *iommu, struct device *link);
void iommu_device_unlink(struct iommu_device *iommu, struct device *link);

static inline void iommu_device_set_ops(struct iommu_device *iommu,
					const struct iommu_ops *ops)
{
	iommu->ops = ops;
}

static inline void iommu_device_set_fwnode(struct iommu_device *iommu,
					   struct fwnode_handle *fwnode)
{
	iommu->fwnode = fwnode;
}

static inline struct iommu_device *dev_to_iommu_device(struct device *dev)
{
	return (struct iommu_device *)dev_get_drvdata(dev);
}

#define IOMMU_GROUP_NOTIFY_ADD_DEVICE		1 /* Device added */
#define IOMMU_GROUP_NOTIFY_DEL_DEVICE		2 /* Pre Device removed */
#define IOMMU_GROUP_NOTIFY_BIND_DRIVER		3 /* Pre Driver bind */
#define IOMMU_GROUP_NOTIFY_BOUND_DRIVER		4 /* Post Driver bind */
#define IOMMU_GROUP_NOTIFY_UNBIND_DRIVER	5 /* Pre Driver unbind */
#define IOMMU_GROUP_NOTIFY_UNBOUND_DRIVER	6 /* Post Driver unbind */

extern int bus_set_iommu(struct bus_type *bus, const struct iommu_ops *ops);
extern bool iommu_present(struct bus_type *bus);
extern bool iommu_capable(struct bus_type *bus, enum iommu_cap cap);
extern struct iommu_domain *iommu_domain_alloc(struct bus_type *bus);
extern struct iommu_group *iommu_group_get_by_id(int id);
extern void iommu_domain_free(struct iommu_domain *domain);
extern int iommu_attach_device(struct iommu_domain *domain,
			       struct device *dev);
extern void iommu_detach_device(struct iommu_domain *domain,
				struct device *dev);
extern int iommu_bind_pasid_table(struct iommu_domain *domain,
		struct device *dev, struct pasid_table_config *pasidt_binfo);
extern void iommu_unbind_pasid_table(struct iommu_domain *domain,
				struct device *dev);
extern int iommu_sva_invalidate(struct iommu_domain *domain,
		struct device *dev, struct tlb_invalidate_info *inv_info);

extern struct iommu_domain *iommu_get_domain_for_dev(struct device *dev);
extern struct iommu_domain *iommu_get_dma_domain(struct device *dev);
extern int iommu_map(struct iommu_domain *domain, unsigned long iova,
		     phys_addr_t paddr, size_t size, int prot);
extern size_t iommu_unmap(struct iommu_domain *domain, unsigned long iova,
			  size_t size);
extern size_t iommu_unmap_fast(struct iommu_domain *domain,
			       unsigned long iova, size_t size);
extern size_t iommu_map_sg(struct iommu_domain *domain, unsigned long iova,
			   struct scatterlist *sg,unsigned int nents, int prot);
extern phys_addr_t iommu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova);
extern void iommu_set_fault_handler(struct iommu_domain *domain,
			iommu_fault_handler_t handler, void *token);

extern void iommu_get_resv_regions(struct device *dev, struct list_head *list);
extern void iommu_put_resv_regions(struct device *dev, struct list_head *list);
extern int iommu_request_dm_for_dev(struct device *dev);
extern struct iommu_resv_region *
iommu_alloc_resv_region(phys_addr_t start, size_t length, int prot,
			enum iommu_resv_type type);
extern int iommu_get_group_resv_regions(struct iommu_group *group,
					struct list_head *head);

extern int iommu_attach_group(struct iommu_domain *domain,
			      struct iommu_group *group);
extern void iommu_detach_group(struct iommu_domain *domain,
			       struct iommu_group *group);
extern struct iommu_group *iommu_group_alloc(void);
extern void *iommu_group_get_iommudata(struct iommu_group *group);
extern void iommu_group_set_iommudata(struct iommu_group *group,
				      void *iommu_data,
				      void (*release)(void *iommu_data));
extern int iommu_group_set_name(struct iommu_group *group, const char *name);
extern int iommu_group_add_device(struct iommu_group *group,
				  struct device *dev);
extern void iommu_group_remove_device(struct device *dev);
extern int iommu_group_for_each_dev(struct iommu_group *group, void *data,
				    int (*fn)(struct device *, void *));
extern struct iommu_group *iommu_group_get(struct device *dev);
extern struct iommu_group *iommu_group_ref_get(struct iommu_group *group);
extern void iommu_group_put(struct iommu_group *group);
extern int iommu_group_register_notifier(struct iommu_group *group,
					 struct notifier_block *nb);
extern int iommu_group_unregister_notifier(struct iommu_group *group,
					   struct notifier_block *nb);
extern int iommu_register_device_fault_handler(struct device *dev,
					iommu_dev_fault_handler_t handler,
					void *data);

extern int iommu_unregister_device_fault_handler(struct device *dev);

extern int iommu_report_device_fault(struct device *dev,
				     struct iommu_fault_event *evt);

extern int iommu_page_response(struct device *dev,
			       struct page_response_msg *msg);
extern int iommu_group_id(struct iommu_group *group);
extern struct iommu_group *iommu_group_get_for_dev(struct device *dev);
extern struct iommu_domain *iommu_group_default_domain(struct iommu_group *);

extern int iommu_domain_get_attr(struct iommu_domain *domain, enum iommu_attr,
				 void *data);
extern int iommu_domain_set_attr(struct iommu_domain *domain, enum iommu_attr,
				 void *data);
extern struct iommu_domain *iommu_group_share_domain(struct iommu_group *group);
extern struct iommu_domain *iommu_group_unshare_domain(
						struct iommu_group *group);

/* Window handling function prototypes */
extern int iommu_domain_window_enable(struct iommu_domain *domain, u32 wnd_nr,
				      phys_addr_t offset, u64 size,
				      int prot);
extern void iommu_domain_window_disable(struct iommu_domain *domain, u32 wnd_nr);

extern int report_iommu_fault(struct iommu_domain *domain, struct device *dev,
			      unsigned long iova, int flags);

static inline void iommu_flush_tlb_all(struct iommu_domain *domain)
{
	if (domain->ops->flush_iotlb_all)
		domain->ops->flush_iotlb_all(domain);
}

static inline void iommu_tlb_range_add(struct iommu_domain *domain,
				       unsigned long iova, size_t size)
{
	if (domain->ops->iotlb_range_add)
		domain->ops->iotlb_range_add(domain, iova, size);
}

static inline void iommu_tlb_sync(struct iommu_domain *domain)
{
	if (domain->ops->iotlb_sync)
		domain->ops->iotlb_sync(domain);
}

/* PCI device grouping function */
extern struct iommu_group *pci_device_group(struct device *dev);
/* Generic device grouping function */
extern struct iommu_group *generic_device_group(struct device *dev);

/**
 * struct iommu_fwspec - per-device IOMMU instance data
 * @ops: ops for this device's IOMMU
 * @iommu_fwnode: firmware handle for this device's IOMMU
 * @iommu_priv: IOMMU driver private data for this device
 * @num_ids: number of associated device IDs
 * @ids: IDs which this device may present to the IOMMU
 */
struct iommu_fwspec {
	const struct iommu_ops	*ops;
	struct fwnode_handle	*iommu_fwnode;
	void			*iommu_priv;
	u32			flags;
	unsigned int		num_ids;
	unsigned int		num_pasid_bits;
	bool			can_stall;
	u32			ids[1];
};

/* Firmware disabled ATS in the root complex */
#define IOMMU_FWSPEC_PCI_NO_ATS			(1 << 0)

int iommu_fwspec_init(struct device *dev, struct fwnode_handle *iommu_fwnode,
		      const struct iommu_ops *ops);
void iommu_fwspec_free(struct device *dev);
int iommu_fwspec_add_ids(struct device *dev, u32 *ids, int num_ids);
const struct iommu_ops *iommu_ops_from_fwnode(struct fwnode_handle *fwnode);

extern int iommu_sva_bind_device(struct device *dev, struct mm_struct *mm,
				int *pasid, unsigned long flags, void *drvdata);
extern int iommu_sva_unbind_device(struct device *dev, int pasid);

#else /* CONFIG_IOMMU_API */

struct iommu_ops {};
struct iommu_group {};
struct iommu_fwspec {};
struct iommu_device {};
struct iommu_fault_param {};

static inline bool iommu_present(struct bus_type *bus)
{
	return false;
}

static inline bool iommu_capable(struct bus_type *bus, enum iommu_cap cap)
{
	return false;
}

static inline struct iommu_domain *iommu_domain_alloc(struct bus_type *bus)
{
	return NULL;
}

static inline struct iommu_group *iommu_group_get_by_id(int id)
{
	return NULL;
}

static inline void iommu_domain_free(struct iommu_domain *domain)
{
}

static inline int iommu_attach_device(struct iommu_domain *domain,
				      struct device *dev)
{
	return -ENODEV;
}

static inline void iommu_detach_device(struct iommu_domain *domain,
				       struct device *dev)
{
}

static inline struct iommu_domain *iommu_get_domain_for_dev(struct device *dev)
{
	return NULL;
}

static inline int iommu_map(struct iommu_domain *domain, unsigned long iova,
			    phys_addr_t paddr, size_t size, int prot)
{
	return -ENODEV;
}

static inline size_t iommu_unmap(struct iommu_domain *domain,
				 unsigned long iova, size_t size)
{
	return 0;
}

static inline size_t iommu_unmap_fast(struct iommu_domain *domain,
				      unsigned long iova, int gfp_order)
{
	return 0;
}

static inline size_t iommu_map_sg(struct iommu_domain *domain,
				  unsigned long iova, struct scatterlist *sg,
				  unsigned int nents, int prot)
{
	return 0;
}

static inline void iommu_flush_tlb_all(struct iommu_domain *domain)
{
}

static inline void iommu_tlb_range_add(struct iommu_domain *domain,
				       unsigned long iova, size_t size)
{
}

static inline void iommu_tlb_sync(struct iommu_domain *domain)
{
}

static inline int iommu_domain_window_enable(struct iommu_domain *domain,
					     u32 wnd_nr, phys_addr_t paddr,
					     u64 size, int prot)
{
	return -ENODEV;
}

static inline void iommu_domain_window_disable(struct iommu_domain *domain,
					       u32 wnd_nr)
{
}

static inline phys_addr_t iommu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
	return 0;
}

static inline void iommu_set_fault_handler(struct iommu_domain *domain,
				iommu_fault_handler_t handler, void *token)
{
}

static inline void iommu_get_resv_regions(struct device *dev,
					struct list_head *list)
{
}

static inline void iommu_put_resv_regions(struct device *dev,
					struct list_head *list)
{
}

static inline int iommu_get_group_resv_regions(struct iommu_group *group,
					       struct list_head *head)
{
	return -ENODEV;
}

static inline int iommu_request_dm_for_dev(struct device *dev)
{
	return -ENODEV;
}

static inline int iommu_attach_group(struct iommu_domain *domain,
				     struct iommu_group *group)
{
	return -ENODEV;
}

static inline void iommu_detach_group(struct iommu_domain *domain,
				      struct iommu_group *group)
{
}

static inline struct iommu_group *iommu_group_alloc(void)
{
	return ERR_PTR(-ENODEV);
}

static inline void *iommu_group_get_iommudata(struct iommu_group *group)
{
	return NULL;
}

static inline void iommu_group_set_iommudata(struct iommu_group *group,
					     void *iommu_data,
					     void (*release)(void *iommu_data))
{
}

static inline int iommu_group_set_name(struct iommu_group *group,
				       const char *name)
{
	return -ENODEV;
}

static inline int iommu_group_add_device(struct iommu_group *group,
					 struct device *dev)
{
	return -ENODEV;
}

static inline void iommu_group_remove_device(struct device *dev)
{
}

static inline int iommu_group_for_each_dev(struct iommu_group *group,
					   void *data,
					   int (*fn)(struct device *, void *))
{
	return -ENODEV;
}

static inline struct iommu_group *iommu_group_get(struct device *dev)
{
	return NULL;
}

static inline void iommu_group_put(struct iommu_group *group)
{
}

static inline int iommu_group_register_notifier(struct iommu_group *group,
						struct notifier_block *nb)
{
	return -ENODEV;
}

static inline int iommu_group_unregister_notifier(struct iommu_group *group,
						  struct notifier_block *nb)
{
	return 0;
}

static inline int iommu_register_device_fault_handler(struct device *dev,
					iommu_dev_fault_handler_t handler,
					void *data)
{
	return 0;
}

static inline int iommu_unregister_device_fault_handler(struct device *dev)
{
	return 0;
}

static inline int iommu_report_device_fault(struct device *dev,
					    struct iommu_fault_event *evt)
{
	return 0;
}

static inline int iommu_page_response(struct device *dev,
				      struct page_response_msg *msg)
{
	return -ENODEV;
}

static inline int iommu_group_id(struct iommu_group *group)
{
	return -ENODEV;
}

static inline int iommu_domain_get_attr(struct iommu_domain *domain,
					enum iommu_attr attr, void *data)
{
	return -EINVAL;
}

static inline int iommu_domain_set_attr(struct iommu_domain *domain,
					enum iommu_attr attr, void *data)
{
	return -EINVAL;
}

static inline int  iommu_device_register(struct iommu_device *iommu)
{
	return -ENODEV;
}

static inline void iommu_device_set_ops(struct iommu_device *iommu,
					const struct iommu_ops *ops)
{
}

static inline void iommu_device_set_fwnode(struct iommu_device *iommu,
					   struct fwnode_handle *fwnode)
{
}

static inline struct iommu_device *dev_to_iommu_device(struct device *dev)
{
	return NULL;
}

static inline void iommu_device_unregister(struct iommu_device *iommu)
{
}

static inline int  iommu_device_sysfs_add(struct iommu_device *iommu,
					  struct device *parent,
					  const struct attribute_group **groups,
					  const char *fmt, ...)
{
	return -ENODEV;
}

static inline void iommu_device_sysfs_remove(struct iommu_device *iommu)
{
}

static inline int iommu_device_link(struct device *dev, struct device *link)
{
	return -EINVAL;
}

static inline void iommu_device_unlink(struct device *dev, struct device *link)
{
}

static inline int iommu_fwspec_init(struct device *dev,
				    struct fwnode_handle *iommu_fwnode,
				    const struct iommu_ops *ops)
{
	return -ENODEV;
}

static inline void iommu_fwspec_free(struct device *dev)
{
}

static inline int iommu_fwspec_add_ids(struct device *dev, u32 *ids,
				       int num_ids)
{
	return -ENODEV;
}

static inline
const struct iommu_ops *iommu_ops_from_fwnode(struct fwnode_handle *fwnode)
{
	return NULL;
}

static inline
struct iommu_domain *iommu_group_share_domain(struct iommu_group *group)
{
	return NULL;
}

static inline
struct iommu_domain *iommu_group_unshare_domain(struct iommu_group *group)
{
	return NULL;
}

static inline
int iommu_bind_pasid_table(struct iommu_domain *domain, struct device *dev,
			struct pasid_table_config *pasidt_binfo)
{
	return -EINVAL;
}

static inline
void iommu_unbind_pasid_table(struct iommu_domain *domain, struct device *dev)
{
}

static inline int iommu_sva_invalidate(struct iommu_domain *domain,
		struct device *dev, struct tlb_invalidate_info *inv_info)
{
	return -EINVAL;
}

static inline int iommu_sva_bind_device(struct device *dev,
					struct mm_struct *mm, int *pasid,
					unsigned long flags, void *drvdata)
{
	return -ENODEV;
}

static inline int iommu_sva_unbind_device(struct device *dev, int pasid)
{
	return -ENODEV;
}

#endif /* CONFIG_IOMMU_API */

#ifdef CONFIG_IOMMU_SVA
extern int iommu_sva_device_init(struct device *dev, unsigned long features,
				 unsigned int max_pasid,
				 iommu_mm_exit_handler_t mm_exit);
extern int iommu_sva_device_shutdown(struct device *dev);
extern int __iommu_sva_bind_device(struct device *dev, struct mm_struct *mm,
				   int *pasid, unsigned long flags,
				   void *drvdata);
extern int __iommu_sva_unbind_device(struct device *dev, int pasid);
extern void __iommu_sva_unbind_dev_all(struct device *dev);

extern struct mm_struct *iommu_sva_find(int pasid);
#else /* CONFIG_IOMMU_SVA */
static inline int iommu_sva_device_init(struct device *dev,
					unsigned long features,
					unsigned int max_pasid,
					iommu_mm_exit_handler_t mm_exit)
{
	return -ENODEV;
}

static inline int iommu_sva_device_shutdown(struct device *dev)
{
	return -ENODEV;
}

static inline int __iommu_sva_bind_device(struct device *dev,
					  struct mm_struct *mm, int *pasid,
					  unsigned long flags, void *drvdata)
{
	return -ENODEV;
}

static inline int __iommu_sva_unbind_device(struct device *dev, int pasid)
{
	return -ENODEV;
}

static inline void __iommu_sva_unbind_dev_all(struct device *dev)
{
}

static inline struct mm_struct *iommu_sva_find(int pasid)
{
	return NULL;
}
#endif /* CONFIG_IOMMU_SVA */

#ifdef CONFIG_IOMMU_PAGE_FAULT
extern int iommu_queue_iopf(struct iommu_fault_event *evt, void *cookie);

extern int iopf_queue_add_device(struct iopf_queue *queue, struct device *dev);
extern int iopf_queue_remove_device(struct device *dev);
extern int iopf_queue_flush_dev(struct device *dev);
extern struct iopf_queue *
iopf_queue_alloc(const char *name, iopf_queue_flush_t flush, void *cookie);
extern void iopf_queue_free(struct iopf_queue *queue);
#else /* CONFIG_IOMMU_PAGE_FAULT */
static inline int iommu_queue_iopf(struct iommu_fault_event *evt, void *cookie)
{
	return -ENODEV;
}

static inline int iopf_queue_add_device(struct iopf_queue *queue,
					struct device *dev)
{
	return -ENODEV;
}

static inline int iopf_queue_remove_device(struct device *dev)
{
	return -ENODEV;
}

static inline int iopf_queue_flush_dev(struct device *dev)
{
	return -ENODEV;
}

static inline struct iopf_queue *
iopf_queue_alloc(const char *name, iopf_queue_flush_t flush, void *cookie)
{
	return NULL;
}

static inline void iopf_queue_free(struct iopf_queue *queue)
{
}
#endif /* CONFIG_IOMMU_PAGE_FAULT */

#ifdef CONFIG_IOMMU_DEBUGFS
extern	struct dentry *iommu_debugfs_dir;
void iommu_debugfs_setup(void);
#else
static inline void iommu_debugfs_setup(void) {}
#endif

#endif /* __LINUX_IOMMU_H */
