// SPDX-License-Identifier: GPL-2.0-only
/*
 * CSV driver for KVM
 *
 * HYGON CSV support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#include <linux/kvm_host.h>
#include <linux/psp.h>
#include <linux/psp-sev.h>
#include <linux/psp-hygon.h>
#include <linux/memory.h>
#include <linux/kvm_types.h>
#include <linux/rbtree.h>
#include <linux/srcu.h>
#include <linux/hugetlb.h>
#include <asm/cacheflush.h>
#include <asm/e820/api.h>
#include <asm/csv.h>
#include <asm/fpu/api.h>
#include "kvm_cache_regs.h"
#include "svm.h"
#include "csv.h"
#include "x86.h"

#include "trace.h"

#undef  pr_fmt
#define pr_fmt(fmt) "CSV: " fmt

/* Function and variable pointers for hooks */
struct hygon_kvm_hooks_table hygon_kvm_hooks;

/* enable/disable CSV3 support */
static bool csv3_enabled = true;

static struct kvm_x86_ops csv_x86_ops;
static const char csv_vm_mnonce[] = "VM_ATTESTATION";
static DEFINE_MUTEX(csv_cmd_batch_mutex);

static int __csv_issue_ringbuf_cmds(int fd, int *psp_ret)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = csv_issue_ringbuf_cmds_external_user(f.file, psp_ret);

	fdput(f);
	return ret;
}

static int csv_issue_ringbuf_cmds(struct kvm *kvm, int *psp_ret)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __csv_issue_ringbuf_cmds(sev->fd, psp_ret);
}

int csv_vm_attestation(struct kvm *kvm, unsigned long gpa, unsigned long len)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_attestation_report *data = NULL;
	struct page **pages;
	unsigned long guest_uaddr, n;
	int ret = 0, offset, error;

	if (!sev_guest(kvm) || !hygon_kvm_hooks.sev_hooks_installed)
		return -ENOTTY;

	/*
	 * The physical address of guest must valid and page aligned, and
	 * the length of guest memory region must be page size aligned.
	 */
	if (!gpa || (gpa & ~PAGE_MASK) || (len & ~PAGE_MASK)) {
		pr_err("invalid guest address or length\n");
		return -EFAULT;
	}

	guest_uaddr = gfn_to_hva(kvm, gpa_to_gfn(gpa));
	pages = hygon_kvm_hooks.sev_pin_memory(kvm, guest_uaddr, len, &n, FOLL_WRITE);
	if (IS_ERR(pages))
		return PTR_ERR(pages);

	/*
	 * The attestation report must be copied into contiguous memory region,
	 * lets verify that userspace memory pages are contiguous before we
	 * issue commmand.
	 */
	if (hygon_kvm_hooks.get_num_contig_pages(0, pages, n) != n) {
		ret = -EINVAL;
		goto e_unpin_memory;
	}

	ret = -ENOMEM;
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto e_unpin_memory;

	/* csv_vm_mnonce indicates attestation request from guest */
	if (sizeof(csv_vm_mnonce) >= sizeof(data->mnonce)) {
		ret = -EINVAL;
		goto e_free;
	}

	memcpy(data->mnonce, csv_vm_mnonce, sizeof(csv_vm_mnonce));

	offset = guest_uaddr & (PAGE_SIZE - 1);
	data->address = __sme_page_pa(pages[0]) + offset;
	data->len = len;

	data->handle = sev->handle;
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, SEV_CMD_ATTESTATION_REPORT,
					    data, &error);

	if (ret)
		pr_err("vm attestation ret %#x, error %#x\n", ret, error);

e_free:
	kfree(data);
e_unpin_memory:
	hygon_kvm_hooks.sev_unpin_memory(kvm, pages, n);
	return ret;
}

/*--1024--1023--1024--1023--*/
#define TRANS_MEMPOOL_1ST_BLOCK_OFFSET		0
#define TRANS_MEMPOOL_2ND_BLOCK_OFFSET		(1024 << PAGE_SHIFT)
#define TRANS_MEMPOOL_3RD_BLOCK_OFFSET		(2047 << PAGE_SHIFT)
#define TRANS_MEMPOOL_4TH_BLOCK_OFFSET		(3071 << PAGE_SHIFT)
#define TRANS_MEMPOOL_BLOCKS_MAX_OFFSET		(4094 << PAGE_SHIFT)
#define TRANS_MEMPOOL_BLOCK_NUM			4
#define TRANS_MEMPOOL_BLOCK_SIZE		(1024 * PAGE_SIZE)

static size_t g_mempool_offset;
void *g_trans_mempool[TRANS_MEMPOOL_BLOCK_NUM] = { 0, };

static void csv_reset_mempool_offset(void)
{
	g_mempool_offset = 0;
}

static void csv_free_trans_mempool(void)
{
	int i;

	for (i = 0; i < TRANS_MEMPOOL_BLOCK_NUM; i++) {
		kfree(g_trans_mempool[i]);
		g_trans_mempool[i] = NULL;
	}

	csv_reset_mempool_offset();
}

static int csv_alloc_trans_mempool(void)
{
	int i;

	for (i = 0; i < TRANS_MEMPOOL_BLOCK_NUM; i++) {
		WARN_ONCE(g_trans_mempool[i],
			  "g_trans_mempool[%d] was tainted\n", i);

		g_trans_mempool[i] = kzalloc(TRANS_MEMPOOL_BLOCK_SIZE, GFP_KERNEL);
		if (!g_trans_mempool[i])
			goto free_trans_mempool;
	}

	csv_reset_mempool_offset();
	return 0;

free_trans_mempool:
	csv_free_trans_mempool();
	pr_warn("Fail to allocate mem pool, CSV(2) live migration will very slow\n");

	return -ENOMEM;
}

static void *get_trans_data_from_mempool(size_t size)
{
	void *trans = NULL;
	char *trans_data = NULL;
	int i;
	size_t offset;

	if (g_mempool_offset < TRANS_MEMPOOL_2ND_BLOCK_OFFSET) {
		i = 0;
		offset = g_mempool_offset - TRANS_MEMPOOL_1ST_BLOCK_OFFSET;
	} else if (g_mempool_offset < TRANS_MEMPOOL_3RD_BLOCK_OFFSET) {
		i = 1;
		offset = g_mempool_offset - TRANS_MEMPOOL_2ND_BLOCK_OFFSET;
	} else if (g_mempool_offset < TRANS_MEMPOOL_4TH_BLOCK_OFFSET) {
		i = 2;
		offset = g_mempool_offset - TRANS_MEMPOOL_3RD_BLOCK_OFFSET;
	} else if (g_mempool_offset < TRANS_MEMPOOL_BLOCKS_MAX_OFFSET) {
		i = 3;
		offset = g_mempool_offset - TRANS_MEMPOOL_4TH_BLOCK_OFFSET;
	} else {
		pr_err("mempool is full (offset: %lu)\n", g_mempool_offset);
		return NULL;
	}

	trans_data = (char *)g_trans_mempool[i];
	if (!trans_data)
		return NULL;

	trans = &trans_data[offset];
	g_mempool_offset += size;

	return trans;
}

static int
csv_send_update_data_to_ringbuf(struct kvm *kvm,
				int prio,
				uintptr_t data_ptr,
				struct csv_ringbuf_infos *ringbuf_infos)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_data *data;
	struct kvm_sev_send_update_data params;
	struct csv_ringbuf_info_item *item;
	void *hdr, *trans_data;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)data_ptr,
			sizeof(struct kvm_sev_send_update_data)))
		return -EFAULT;

	/*
	 * userspace shouldn't query either header or trans length in ringbuf
	 * mode.
	 */
	if (!params.trans_len || !params.hdr_len)
		return -EINVAL;

	if (!params.trans_uaddr || !params.guest_uaddr ||
	    !params.guest_len || !params.hdr_uaddr)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if (params.guest_len > PAGE_SIZE || (params.guest_len + offset) > PAGE_SIZE)
		return -EINVAL;

	/* Pin guest memory */
	guest_page = hygon_kvm_hooks.sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
						    PAGE_SIZE, &n, 0);
	if (IS_ERR(guest_page))
		return PTR_ERR(guest_page);

	/* Allocate memory for header and transport buffer */
	ret = -ENOMEM;
	hdr = kzalloc(params.hdr_len, GFP_KERNEL);
	if (!hdr)
		goto e_unpin;

	trans_data = get_trans_data_from_mempool(params.trans_len);
	if (!trans_data)
		goto e_free_hdr;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto e_free_hdr;

	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;
	data->trans_address = __psp_pa(trans_data);
	data->trans_len = params.trans_len;

	/* The SEND_UPDATE_DATA command requires C-bit to be always set. */
	data->guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) +
				offset;
	data->guest_address |= *hygon_kvm_hooks.sev_me_mask;
	data->guest_len = params.guest_len;
	data->handle = sev->handle;

	ret = csv_fill_cmd_queue(prio, SEV_CMD_SEND_UPDATE_DATA, data, 0);
	if (ret)
		goto e_free;

	/*
	 * Create item to save page info and pointer, which will be freed
	 * in function csv_command_batch because it will be used after PSP
	 * return for copy_to_user.
	 */
	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		ret = -ENOMEM;
		goto e_free;
	}

	item->pages = guest_page;
	item->n = n;
	item->hdr_vaddr = (uintptr_t)hdr;
	item->hdr_uaddr = params.hdr_uaddr;
	item->hdr_len = params.hdr_len;
	item->trans_vaddr = (uintptr_t)trans_data;
	item->trans_uaddr = params.trans_uaddr;
	item->trans_len = params.trans_len;
	item->data_vaddr = (uintptr_t)data;

	ringbuf_infos->item[ringbuf_infos->num++] = item;

	/* copy to ring buffer success, data freed after commands completed */
	return 0;

e_free:
	kfree(data);
e_free_hdr:
	kfree(hdr);
e_unpin:
	hygon_kvm_hooks.sev_unpin_memory(kvm, guest_page, n);
	return ret;
}

static int
csv_send_update_data_copy_to_user(struct kvm *kvm,
				  struct csv_ringbuf_infos *ringbuf_infos)
{
	int i, ret = 0;

	for (i = 0; i < ringbuf_infos->num; i++) {
		struct csv_ringbuf_info_item *item = ringbuf_infos->item[i];

		/* copy transport buffer to user space */
		if (copy_to_user((void __user *)item->trans_uaddr,
				 (void *)item->trans_vaddr, item->trans_len)) {
			ret = -EFAULT;
			break;
		}

		/* Copy packet header to userspace. */
		if (copy_to_user((void __user *)item->hdr_uaddr,
				 (void *)item->hdr_vaddr, item->hdr_len)) {
			ret = -EFAULT;
			break;
		}
	}

	return ret;
}

static int
csv_receive_update_data_to_ringbuf(struct kvm *kvm,
				   int prio,
				   uintptr_t data_ptr,
				   struct csv_ringbuf_infos *ringbuf_infos)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_receive_update_data params;
	struct sev_data_receive_update_data *data;
	struct csv_ringbuf_info_item *item;
	void *hdr = NULL, *trans = NULL;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)data_ptr,
			sizeof(struct kvm_sev_receive_update_data)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.guest_uaddr || !params.guest_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if (params.guest_len > PAGE_SIZE || (params.guest_len + offset) > PAGE_SIZE)
		return -EINVAL;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr))
		return PTR_ERR(hdr);

	ret = -ENOMEM;
	trans = get_trans_data_from_mempool(params.trans_len);
	if (!trans)
		goto e_free_hdr;

	if (copy_from_user(trans, (void __user *)params.trans_uaddr,
			params.trans_len)) {
		ret = -EFAULT;
		goto e_free_hdr;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto e_free_hdr;

	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;
	data->trans_address = __psp_pa(trans);
	data->trans_len = params.trans_len;

	/* Pin guest memory */
	guest_page = hygon_kvm_hooks.sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
						    PAGE_SIZE, &n, FOLL_WRITE);
	if (IS_ERR(guest_page)) {
		ret = PTR_ERR(guest_page);
		goto e_free;
	}

	/*
	 * Flush (on non-coherent CPUs) before RECEIVE_UPDATE_DATA, the PSP
	 * encrypts the written data with the guest's key, and the cache may
	 * contain dirty, unencrypted data.
	 */
	hygon_kvm_hooks.sev_clflush_pages(guest_page, n);

	/* The RECEIVE_UPDATE_DATA command requires C-bit to be always set. */
	data->guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) +
				offset;
	data->guest_address |= *hygon_kvm_hooks.sev_me_mask;
	data->guest_len = params.guest_len;
	data->handle = sev->handle;

	ret = csv_fill_cmd_queue(prio, SEV_CMD_RECEIVE_UPDATE_DATA, data, 0);

	if (ret)
		goto e_unpin;

	/*
	 * Create item to save page info and pointer, whitch will be freed
	 * in function csv_command_batch because it will be used after PSP
	 * return for copy_to_user.
	 */
	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		ret = -ENOMEM;
		goto e_unpin;
	}

	item->pages = guest_page;
	item->n = n;
	item->hdr_vaddr = (uintptr_t)hdr;
	item->trans_vaddr = (uintptr_t)trans;
	item->data_vaddr = (uintptr_t)data;

	ringbuf_infos->item[ringbuf_infos->num++] = item;

	/* copy to ring buffer success, data freed after commands completed */
	return 0;

e_unpin:
	hygon_kvm_hooks.sev_unpin_memory(kvm, guest_page, n);
e_free:
	kfree(data);
e_free_hdr:
	kfree(hdr);

	return ret;
}

static int csv_ringbuf_infos_free(struct kvm *kvm,
				  struct csv_ringbuf_infos *ringbuf_infos)
{
	int i;

	for (i = 0; i < ringbuf_infos->num; i++) {
		struct csv_ringbuf_info_item *item = ringbuf_infos->item[i];

		if (item) {
			if (item->data_vaddr)
				kfree((void *)item->data_vaddr);

			if (item->hdr_vaddr)
				kfree((void *)item->hdr_vaddr);

			if (item->pages)
				hygon_kvm_hooks.sev_unpin_memory(kvm, item->pages,
								 item->n);

			kfree(item);

			ringbuf_infos->item[i] = NULL;
		}
	}

	return 0;
}

typedef int (*csv_ringbuf_input_fn)(struct kvm *kvm, int prio,
				    uintptr_t data_ptr,
				    struct csv_ringbuf_infos *ringbuf_infos);
typedef int (*csv_ringbuf_output_fn)(struct kvm *kvm,
				     struct csv_ringbuf_infos *ringbuf_infos);

static int get_cmd_helpers(__u32 cmd,
			   csv_ringbuf_input_fn *to_ringbuf_fn,
			   csv_ringbuf_output_fn *to_user_fn)
{
	int ret = 0;

	/* copy commands to ring buffer*/
	switch (cmd) {
	case KVM_SEV_SEND_UPDATE_DATA:
		*to_ringbuf_fn = csv_send_update_data_to_ringbuf;
		*to_user_fn = csv_send_update_data_copy_to_user;
		break;
	case KVM_SEV_RECEIVE_UPDATE_DATA:
		*to_ringbuf_fn = csv_receive_update_data_to_ringbuf;
		*to_user_fn = NULL;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int csv_command_batch(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	int ret;
	struct kvm_csv_command_batch params;
	uintptr_t node_addr;
	struct csv_ringbuf_infos *ringbuf_infos;
	csv_ringbuf_input_fn csv_cmd_to_ringbuf_fn = NULL;
	csv_ringbuf_output_fn csv_copy_to_user_fn = NULL;
	int prio = CSV_COMMAND_PRIORITY_HIGH;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_csv_command_batch)))
		return -EFAULT;

	/* return directly if node list is NULL */
	if (!params.csv_batch_list_uaddr)
		return 0;

	/* ring buffer init */
	if (csv_ring_buffer_queue_init())
		return -EINVAL;

	if (get_cmd_helpers(params.command_id,
			    &csv_cmd_to_ringbuf_fn, &csv_copy_to_user_fn)) {
		ret = -EINVAL;
		goto err_free_ring_buffer;
	}

	ringbuf_infos = kzalloc(sizeof(*ringbuf_infos), GFP_KERNEL);
	if (!ringbuf_infos) {
		ret = -ENOMEM;
		goto err_free_ring_buffer;
	}

	node_addr = (uintptr_t)params.csv_batch_list_uaddr;
	while (node_addr) {
		struct kvm_csv_batch_list_node node;

		if (copy_from_user(&node, (void __user *)node_addr,
				sizeof(struct kvm_csv_batch_list_node))) {
			ret = -EFAULT;
			goto err_free_ring_buffer_infos_items;
		}

		if (ringbuf_infos->num > SVM_RING_BUFFER_MAX) {
			pr_err("%s: ring num is too large:%d, cmd:0x%x\n",
				__func__, ringbuf_infos->num, params.command_id);

			ret = -EINVAL;
			goto err_free_ring_buffer_infos_items;
		}

		if (csv_cmd_to_ringbuf_fn(kvm, prio,
					  (uintptr_t)node.cmd_data_addr,
					  ringbuf_infos)) {
			ret = -EFAULT;
			goto err_free_ring_buffer_infos_items;
		}

		/* 1st half set to HIGH queue, 2nd half set to LOW queue */
		if (ringbuf_infos->num == SVM_RING_BUFFER_MAX / 2)
			prio = CSV_COMMAND_PRIORITY_LOW;

		node_addr = node.next_cmd_addr;
	}

	/* ring buffer process */
	ret = csv_issue_ringbuf_cmds(kvm, &argp->error);
	if (ret)
		goto err_free_ring_buffer_infos_items;

	ret = csv_check_stat_queue_status(&argp->error);
	if (ret)
		goto err_free_ring_buffer_infos_items;

	if (csv_copy_to_user_fn && csv_copy_to_user_fn(kvm, ringbuf_infos)) {
		ret = -EFAULT;
		goto err_free_ring_buffer_infos_items;
	}

err_free_ring_buffer_infos_items:
	csv_ringbuf_infos_free(kvm, ringbuf_infos);
	kfree(ringbuf_infos);
	csv_reset_mempool_offset();

err_free_ring_buffer:
	csv_ring_buffer_queue_free();

	return ret;
}

struct encrypt_data_block {
	struct {
		u64 npages:	12;
		u64 pfn:	52;
	} entry[512];
};

union csv3_page_attr {
	struct {
		u64 reserved:	1;
		u64 rw:		1;
		u64 reserved1:	49;
		u64 mmio:	1;
		u64 reserved2:	12;
	};
	u64 val;
};

struct guest_paddr_block {
	struct {
		u64 share:	1;
		u64 reserved:	11;
		u64 gfn:	52;
	} entry[512];
};

struct trans_paddr_block {
	u64	trans_paddr[512];
};

struct vmcb_paddr_block {
	u64	vmcb_paddr[512];
};

enum csv3_pg_level {
	CSV3_PG_LEVEL_NONE,
	CSV3_PG_LEVEL_4K,
	CSV3_PG_LEVEL_2M,
	CSV3_PG_LEVEL_NUM
};

/*
 * Manage shared page in rbtree, the node within the rbtree
 * is indexed by track_hva. @track_page points to the page mapped by @track_hva
 * in NPT.
 */
struct shared_page {
	struct rb_node node;
	/* The hva corresponds to @track_page. */
	u64 track_hva;
	/* Page order of @track_page. */
	unsigned int order;
	/*
	 * This field is NULL when @order equals 0, but must point to a
	 * valid bitmap when @order > 0 (i.e., for huge pages and THP).
	 */
	unsigned long *bitmap;
	/*
	 * Pointer to the head page of the page block.
	 * Always points to the head page, whether @order is 0 (a single 4K
	 * page) or greater (a huge page or THP).
	 */
	struct page *track_page;
};

struct shared_page_mgr {
	/* The root of the manager tree */
	struct rb_root root;
	/* The count of shared_page entries in the manager tree */
	u64 count;
	/* The total pages tracked by the manager */
	unsigned long nr_pages;
};

struct kvm_csv_info {
	struct kvm_sev_info *sev;

	bool csv3_active;	/* CSV3 enabled guest */

	struct kmem_cache *sp_slab;	/* shared page slab */
	struct shared_page_mgr sp_mgr;	/* shared page manager */
	struct mutex sp_lock;		/* shared page lock */

	struct list_head smr_list; /* List of guest secure memory regions */
	struct list_head hugetlb_list; /* List of 1G hugetlb (if used) */
	unsigned long nodemask; /* Nodemask where CSV3 guest's memory resides */

	/* The following 5 fields record the extension status for current VM */
	bool fw_ext_valid;	/* if @fw_ext field is valid */
	u32 fw_ext;		/* extensions supported by current platform */
	bool kvm_ext_valid;	/* if @kvm_ext field is valid */
	u32 kvm_ext;		/* extensions supported by KVM */
	u32 inuse_ext;		/* extensions inused by current VM */

#ifdef CONFIG_SYSFS
	unsigned long npt_size;
	unsigned long pri_mem;
#endif
};

struct kvm_svm_csv {
	struct kvm_svm kvm_svm;
	struct kvm_csv_info csv_info;
};

enum csv_mem_type {
	CSV_METADATA,
	CSV_SEC_MEM,
};

struct secure_memory_region {
	struct list_head list;
	u64 npages;
	u64 hpa;
	enum csv_mem_type type;
};

struct csv3_hugetlb {
	struct list_head list;
	struct page *page;
};

#ifdef CONFIG_SYSFS
static void update_csv_share_mem(struct page *page, bool add)
{
	int nid = page_to_nid(page);

	if (add)
		atomic_long_add(page_size(page), &csv3_shared_mem[nid]);
	else
		atomic_long_sub(page_size(page), &csv3_shared_mem[nid]);
}
#else
static void update_csv_share_mem(struct page *page, bool add) { }
#endif	/* CONFIG_SYSFS */

/**
 * insert_shared_page_entry_locked - Insert a shared_page into the manager tree
 * @mgr:    Pointer to the shared page manager (must be valid).
 * @new_sp: The shared_page to insert.
 * @old_sp: Pointer to store conflicting entry if insertion fails (can be NULL).
 *
 * Attempts to insert @new_sp into the rbtree of @mgr. If an entry with the
 * same key (e.g., track_hva) already exists, the insertion is aborted and
 * the existing entry is returned via @old_sp.
 *
 * The caller must hold the appropriate lock protecting @mgr.
 *
 * Return:
 * %true if @new_sp was successfully inserted;
 * %false if a duplicate exists (in which case @old_sp is set if non-NULL).
 */
static bool insert_shared_page_entry_locked(struct shared_page_mgr *mgr,
					    struct shared_page *new_sp,
					    struct shared_page **old_sp)
{
	struct shared_page *sp_iter;
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *parent = NULL;

	root = &mgr->root;
	new = &(root->rb_node);

	/* Figure out where to put new node */
	while (*new) {
		sp_iter = rb_entry(*new, struct shared_page, node);
		parent = *new;

		if (new_sp->track_hva < sp_iter->track_hva) {
			new = &((*new)->rb_left);
		} else if (new_sp->track_hva > sp_iter->track_hva) {
			new = &((*new)->rb_right);
		} else {
			trace_kvm_csv3_sp_insert_dup(page_to_pfn(new_sp->track_page),
						     new_sp->track_hva,
						     new_sp->order,
						     page_to_pfn(sp_iter->track_page),
						     sp_iter->track_hva,
						     sp_iter->order);

			/*
			 * If found the same @track_page during insertion, the
			 * @track_page must be pinned more than once.
			 */
			if (new_sp->track_page == sp_iter->track_page &&
			    ((hpage_pincount_available(sp_iter->track_page) &&
			      compound_pincount(sp_iter->track_page) < 2) ||
			     (!hpage_pincount_available(sp_iter->track_page) &&
			      ((unsigned int)page_ref_count(sp_iter->track_page)
				< GUP_PIN_COUNTING_BIAS * 2))))
				pr_err_ratelimited("%s: SP_MGR_ERR: pfn:0x%lx"
						   " order:%d pincount < 2\n",
						   __func__,
						   page_to_pfn(sp_iter->track_page),
						   sp_iter->order);

			if (old_sp)
				*old_sp = sp_iter;
			return false;
		}
	}

	trace_kvm_csv3_sp_insert(page_to_pfn(new_sp->track_page),
				 new_sp->track_hva,
				 new_sp->order);

	/* Add new node and rebalance tree. */
	rb_link_node(&new_sp->node, parent, new);
	rb_insert_color(&new_sp->node, root);

	/* Update shared page statistics */
	mgr->count++;
	mgr->nr_pages += 1UL << new_sp->order;
	update_csv_share_mem(new_sp->track_page, true);

	return true;
}

/**
 * search_shared_page_entry_locked - Search for a shared page covering @hva
 * @mgr: Pointer to the shared page manager.
 * @hva: Host virtual address to search for.
 *
 * Searches the rbtree of @mgr for a shared page that maps @hva. The search
 * iterates through supported page orders (e.g., 4K, 2M, 1G) in ascending order
 * (starting from order 0).
 *
 * The caller must hold the lock protecting @mgr.
 *
 * Return: Pointer to matching shared_page, or NULL if not found.
 */
static
struct shared_page *search_shared_page_entry_locked(struct shared_page_mgr *mgr,
						    u64 hva)
{
	struct shared_page *sp;
	struct rb_root *root;
	struct rb_node *node;
	u64 track_hva;
	unsigned int order = 0;

again:
	track_hva = (hva & ~((1ULL << (order + PAGE_SHIFT)) - 1));

	root = &mgr->root;
	node = root->rb_node;
	while (node) {
		sp = rb_entry(node, struct shared_page, node);
		if (track_hva < sp->track_hva)
			node = node->rb_left;
		else if (track_hva > sp->track_hva)
			node = node->rb_right;
		else if (track_hva == hva || sp->order == order) {
			return sp;
		} else {
			/*
			 * The aligned HVA hits an entry of a different order.
			 * Fall through to retry with the next larger order,
			 * because the requested HVA may still be covered by a
			 * larger compound page.
			 */
			break;
		}
	}

	if (order == 0) {
		order = PMD_SHIFT - PAGE_SHIFT;
		goto again;
	} else if (order == (PMD_SHIFT - PAGE_SHIFT)) {
		order = PUD_SHIFT - PAGE_SHIFT;
		goto again;
	}

	return NULL;
}

/**
 * shared_page_entry_set_bit_locked - Set bitmap in a shared page entry if found
 * @mgr: Pointer to the shared page manager (caller must hold its lock).
 * @hva: Host virtual address identifying the 4K subpage of a compound page.
 * @sp:  Optional hint pointer to the shared_page entry; if NULL, the entry is
 *       looked up in @mgr's rbtree using @hva.
 *
 * If @sp is NULL, the function searches for the entry in the manager's tree.
 *
 * For compound pages (@order > 0), a bitmap tracks which 4K subpages are
 * shared memory for CSV3 VM. The bit corresponding to the offset of @hva within
 * the compound page is set atomically.
 *
 * On every successful found (including repeated hits), a trace event
 * kvm_csv3_sp_hit is emitted with the PFN, order.
 *
 * Return:
 * Pointer to the shared_page entry if found, or NULL if no entry covers @hva.
 */
static
struct shared_page *shared_page_entry_set_bit_locked(struct shared_page_mgr *mgr,
						     u64 hva,
						     struct shared_page *sp)
{
	/* If @sp is NULL, we need search entry from the manager tree. */
	if (!sp)
		sp = search_shared_page_entry_locked(mgr, hva);

	if (sp) {
		if (sp->order) {
			unsigned int pg_off = (hva & ~sp->track_hva) >> PAGE_SHIFT;

			set_bit(pg_off, sp->bitmap);
		}

		trace_kvm_csv3_sp_hit(page_to_pfn(sp->track_page),
				      sp->track_hva, hva, sp->order);
	}

	return sp;
}

/**
 * remove_shared_page_entry_locked - Release the shared state of a 4K subpage.
 * @mgr: Pointer to the shared page manager (lock must be held by caller).
 * @hva: Host virtual address identifying the subpage.
 * @released: Set to true if the shared state of @hva was released.
 *
 * A shared_page entry tracks the 4K subpages of a compound page that are
 * shared memory of a CSV3 VM. Releasing @hva clears the corresponding bitmap
 * bit. The entry is removed from the manager only when none of its subpages is
 * shared anymore and the underlying physical page is not pinned by any other
 * user. Otherwise the entry is kept and the page stays pinned.
 *
 * If the page is found to be pinned more than once, nothing is released as
 * the page is used by multiple users.
 *
 * Context: Caller must hold the lock protecting @mgr.
 *
 * Return:
 *   Pointer to the removed shared_page entry if the entry was removed from
 *   the manager, or NULL if @hva is not tracked, the page is pinned more than
 *   once, or the entry was kept because some subpages are still shared.
 *   @released tells whether the shared state of @hva was released.
 */
static
struct shared_page *remove_shared_page_entry_locked(struct shared_page_mgr *mgr,
						    u64 hva,
						    bool *released)
{
	struct shared_page *sp;

	*released = false;

	sp = search_shared_page_entry_locked(mgr, hva);
	if (sp) {
		/*
		 * The @sp->track_page may be pinned more than once in some
		 * scenarios, such as device passthrough. We don't remove this
		 * entry from the tree. Check this before clearing the bitmap
		 * bit, otherwise the shared subpage tracking of a pinned page
		 * would be lost.
		 */
		if ((hpage_pincount_available(sp->track_page) &&
		     compound_pincount(sp->track_page) >= 2) ||
		    (!hpage_pincount_available(sp->track_page) &&
		     ((unsigned int)page_ref_count(sp->track_page) >= GUP_PIN_COUNTING_BIAS * 2))) {
			return NULL;
		}

		/* From here on the shared state of @hva is released. */
		*released = true;

		/*
		 * The bitmap records the 4K subpages within the compound page
		 * that are shared memory of VM. Clear the bit for this @hva.
		 */
		if (sp->order) {
			unsigned int pg_off = (hva & ~sp->track_hva) >> PAGE_SHIFT;

			clear_bit(pg_off, sp->bitmap);
			if (!bitmap_empty(sp->bitmap, 1U << sp->order))
				return NULL;
		}

		trace_kvm_csv3_sp_remove(page_to_pfn(sp->track_page),
					 sp->track_hva, sp->order);

		rb_erase(&sp->node, &mgr->root);
		mgr->count--;
		mgr->nr_pages -= 1UL << sp->order;
		update_csv_share_mem(sp->track_page, false);
	}

	return sp;
}

/**
 * alloc_shared_page_entry - Allocate and initialize a shared_page entry for a
 *                           given page
 * @csv:  Pointer to the KVM CSV info structure containing the slab cache.
 * @hva:  Host virtual address associated with the page (used for alignment and
 *        tracking).
 * @page: The physical page being tracked (may be a base or compound/huge page).
 *
 * Allocates a new struct shared_page from the slab cache in @csv, initializes
 * it to represent the memory region covered by @page at virtual address @hva.
 * If @page is a compound page (order > 0), a bitmap is allocated to track
 * touched 4K subpages, and the bit corresponding to the 4K offset of @hva
 * within the compound page is set. For order-0 pages, no bitmap is allocated.
 * The @track_hva field is aligned to the start of the page block (i.e.,
 * compound page boundary if applicable).
 *
 * Return:
 * Pointer to the newly allocated and initialized shared_page on success,
 * or NULL on allocation failure (either slab or bitmap).
 */
struct shared_page *alloc_shared_page_entry(struct kvm_csv_info *csv,
					    u64 hva,
					    struct page *page)
{
	struct shared_page *sp;
	unsigned int order;
	unsigned int pg_off;

	sp = kmem_cache_zalloc(csv->sp_slab, GFP_KERNEL);
	if (!sp)
		return NULL;

	order = compound_order(compound_head(page));
	if (order) {
		unsigned long *bitmap = kvzalloc(BITS_TO_LONGS(1U << order)
							* sizeof(unsigned long),
						 GFP_KERNEL);
		if (!bitmap) {
			kmem_cache_free(csv->sp_slab, sp);
			return NULL;
		}
		sp->bitmap = bitmap;
		pg_off = (hva >> PAGE_SHIFT) & ((1U << order) - 1);
		set_bit(pg_off, sp->bitmap);
	}

	sp->track_hva = hva & ~((1ULL << (order + PAGE_SHIFT)) - 1);
	sp->order = order;
	sp->track_page = compound_head(page);

	return sp;
}

/**
 * free_shared_page_entry - Free a shared_page entry and its associated
 *                          resources
 * @csv: Pointer to the KVM CSV info structure containing the slab cache.
 * @sp:  The shared_page entry to free.
 *
 * The caller must ensure that @sp is no longer in use (e.g., already removed
 * from any rbtree) before calling this function.
 */
void free_shared_page_entry(struct kvm_csv_info *csv, struct shared_page *sp)
{
	if (!sp)
		return;

	kvfree(sp->bitmap);
	kmem_cache_free(csv->sp_slab, sp);
}

static inline struct kvm_svm_csv *to_kvm_svm_csv(struct kvm *kvm)
{
	return (struct kvm_svm_csv *)container_of(kvm, struct kvm_svm, kvm);
}

static int to_csv3_pg_level(int level)
{
	int ret;

	switch (level) {
	case PG_LEVEL_4K:
		ret = CSV3_PG_LEVEL_4K;
		break;
	case PG_LEVEL_2M:
		ret = CSV3_PG_LEVEL_2M;
		break;
	default:
		ret = CSV3_PG_LEVEL_NONE;
	}

	return ret;
}

static bool csv3_guest(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	return sev_es_guest(kvm) && csv->csv3_active;
}

static inline void csv3_init_update_npt(struct csv3_data_update_npt *update_npt,
					gpa_t gpa, u32 error, u32 handle)
{
	memset(update_npt, 0x00, sizeof(*update_npt));

	update_npt->gpa = gpa & PAGE_MASK;
	update_npt->error_code = error;
	update_npt->handle = handle;
}

static int csv3_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_init_data params;
	struct kmem_cache *sp_slab;
	char   slab_name[0x40];

	if (unlikely(csv->csv3_active))
		return -EINVAL;

	if (unlikely(!sev->es_active))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	memset(slab_name, 0, sizeof(slab_name));
	snprintf(slab_name, sizeof(slab_name), "csv3_%d_sp_slab", sev->asid);
	sp_slab = kmem_cache_create(slab_name, sizeof(struct shared_page),
				    0, 0, NULL);
	if (!sp_slab)
		return -ENOMEM;

	csv->sp_slab = sp_slab;
	csv->sp_mgr.root = RB_ROOT;

	csv->csv3_active = true;
	csv->sev = sev;
	csv->nodemask = (unsigned long)params.nodemask;

	INIT_LIST_HEAD(&csv->smr_list);
	INIT_LIST_HEAD(&csv->hugetlb_list);
	mutex_init(&csv->sp_lock);

	return 0;
}

static bool csv3_is_mmio_pfn(kvm_pfn_t pfn)
{
	return !e820__mapped_raw_any(pfn_to_hpa(pfn),
				     pfn_to_hpa(pfn + 1) - 1,
				     E820_TYPE_RAM);
}

/**
 * csv3_free_smr_list - Free secure_memory_region structure from CSV3 VM's
 *			smr_list.
 * There are 3 types memory described by secure_memory_region structure:
 *   - Guest private memory, NPT, metadata (e.g., VMSA) allocated from CMA.
 *     The CMA should be released when remove it from CSV3 VM's smr_list.
 *   - Guest private memory allocated from 1G hugetlb.
 *     The caller should release the 1G hugetlb pages.
 *   - Guest metadata (e.g., VMSA) allocated from system-reserved memory
 *     pool, used only when guest private memory is allocated from 1G
 *     hugetlb. This memory should be free back to the pool.
 */
static void csv3_free_smr_list(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct secure_memory_region *smr;
	struct list_head *pos, *q;
	enum csv_smr_source source = get_csv_smr_source();

	list_for_each_safe(pos, q, &csv->smr_list) {
		smr = list_entry(pos, struct secure_memory_region, list);
		if (smr) {
			if (source == USE_CMA)
				csv_release_to_contiguous(smr->hpa,
						smr->npages << PAGE_SHIFT);

			if (smr->type == CSV_METADATA)
				csv_free_metadata(smr->hpa);

			list_del(&smr->list);
			kfree(smr);
		}
	}
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static void csv3_free_1G_hugetlb_pages(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_hugetlb *hugetlb;
	struct list_head *pos, *q;

	list_for_each_safe(pos, q, &csv->hugetlb_list) {
		hugetlb = list_entry(pos, struct csv3_hugetlb, list);
		if (hugetlb) {
			put_page(hugetlb->page);
			list_del(&hugetlb->list);
			kfree(hugetlb);
		}
	}
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static int csv3_alloc_1G_hugetlb_pages(struct kvm *kvm,
					unsigned long size,
					nodemask_t *nodemask)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct hstate *h = hstate_sizelog(PUD_SHIFT);
	struct page *page;
	struct csv3_hugetlb *hugetlb;
	int huge_count;
	int i;

	if (!h)
		return -ENOMEM;

	huge_count = ALIGN(size, PUD_SIZE) / PUD_SIZE;

	for (i = 0; i < huge_count; i++) {
		hugetlb = kzalloc(sizeof(*hugetlb), GFP_KERNEL_ACCOUNT);
		if (!hugetlb)
			goto err;

		page = alloc_huge_page_nodemask(h, numa_mem_id(),
						nodemask, GFP_KERNEL);
		if (!page) {
			kfree(hugetlb);
			goto err;
		}

		hugetlb->page = page;
		list_add_tail(&hugetlb->list, &csv->hugetlb_list);
	}

	return 0;

err:
	csv3_free_1G_hugetlb_pages(kvm);

	return -ENOMEM;
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static int csv3_init_1G_hugetlb_smrs(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_hugetlb *hugetlb;
	struct secure_memory_region *smr;
	struct list_head *pos, *q;
	u64 hpa;
	u32 smr_entry_shift;
	int smr_count;
	int i;
	int ret = 0;

	smr_entry_shift = csv_get_smr_entry_shift();
	smr_count = PUD_SIZE / (1UL << smr_entry_shift);

	list_for_each_safe(pos, q, &csv->hugetlb_list) {
		hugetlb = list_entry(pos, struct csv3_hugetlb, list);
		if (!hugetlb) {
			WARN_ON(1);
			ret = -ENOMEM;
			goto err;
		}

		hpa = page_to_pfn(hugetlb->page) << PAGE_SHIFT;
		for (i = 0; i < smr_count; i++) {
			smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
			if (!smr) {
				ret = -ENOMEM;
				goto err;
			}

			smr->hpa = hpa + i * (1UL << smr_entry_shift);
			list_add_tail(&smr->list, &csv->smr_list);
		}
	}

	return 0;

err:
	csv3_free_smr_list(kvm);

	return ret;
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static u64 csv3_get_1G_hugetlb_smr(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct secure_memory_region *smr;
	struct list_head *pos, *q;
	u64 hpa = 0;

	list_for_each_safe(pos, q, &csv->smr_list) {
		smr = list_entry(pos, struct secure_memory_region, list);
		if (smr) {
			hpa = smr->hpa;
			list_del(&smr->list);
			kfree(smr);
			break;
		}
	}

	return hpa;
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static int csv3_set_hugetlb_smr(struct kvm *kvm, unsigned long vm_size,
				nodemask_t *nodemask, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_set_guest_private_memory *set_guest_private_memory;
	struct secure_memory_region *smr;
	struct csv3_data_memory_region *regions;

	LIST_HEAD(tmp_list);
	struct list_head *pos, *q;
	u32 i = 0, count = 0, remainder;
	int ret = 0;
	u64 nr_smr = 0;
	u32 smr_entry_shift;

	bool metadata_allocated = false;

	set_guest_private_memory = kzalloc(sizeof(*set_guest_private_memory),
					GFP_KERNEL_ACCOUNT);
	if (!set_guest_private_memory)
		return -ENOMEM;

	regions = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!regions) {
		kfree(set_guest_private_memory);
		return -ENOMEM;
	}

	ret = csv3_alloc_1G_hugetlb_pages(kvm, vm_size, nodemask);
	if (ret)
		goto done;

	ret = csv3_init_1G_hugetlb_smrs(kvm);
	if (ret)
		goto e_free_hugetlb;

	smr_entry_shift = csv_get_smr_entry_shift();
	nr_smr = vm_size >> smr_entry_shift;
	nr_smr += 1;

	remainder = nr_smr;
	for (i = 0; i < nr_smr; i++) {
		smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
		if (!smr) {
			ret = -ENOMEM;
			goto e_free_smr;
		}

		if (metadata_allocated == false) {
			smr->hpa = csv_alloc_metadata();
			smr->type = CSV_METADATA;
			metadata_allocated = true;
		} else {
			smr->hpa = csv3_get_1G_hugetlb_smr(kvm);
			smr->type = CSV_SEC_MEM;
		}
		if (!smr->hpa) {
			kfree(smr);
			ret = -ENOMEM;
			goto e_free_smr;
		}

		smr->npages = ((1UL << smr_entry_shift) >> PAGE_SHIFT);
		list_add_tail(&smr->list, &tmp_list);

		regions[count].size = (1UL << smr_entry_shift);
		regions[count].base_address = smr->hpa;
		count++;

		if (count >= (PAGE_SIZE / sizeof(regions[0])) || (remainder == count)) {
			set_guest_private_memory->nregions = count;
			set_guest_private_memory->handle = sev->handle;
			set_guest_private_memory->regions_paddr = __sme_pa(regions);

			/* set secury memory region for launch enrypt data */
			ret = hygon_kvm_hooks.sev_issue_cmd(kvm,
						CSV3_CMD_SET_GUEST_PRIVATE_MEMORY,
						set_guest_private_memory, &argp->error);
			if (ret)
				goto e_free_smr;

			memset(regions, 0, PAGE_SIZE);
			remainder -= count;
			count = 0;
		}
	}

	list_splice(&tmp_list, &csv->smr_list);

#ifdef CONFIG_SYSFS
	/* The NPT is allocated from global SMCR */
	csv->npt_size = 0;
	/**
	 * Don't account for guest private memory since:
	 *   - VMSAs are allocated from system-reserverd memory pool.
	 *   - CSV3 private memory is allocated from 1G hugetlb.
	 */
	csv->pri_mem = 0;
#endif

	goto done;

e_free_smr:
	/* Remove temporary smr_list */
	if (!list_empty(&tmp_list)) {
		list_for_each_safe(pos, q, &tmp_list) {
			smr = list_entry(pos, struct secure_memory_region, list);
			if (smr) {
				if (smr->type == CSV_METADATA)
					csv_free_metadata(smr->hpa);

				list_del(&smr->list);
				kfree(smr);
			}
		}
	}
	/* Remove smr_list created by csv3_init_1G_hugetlb_smrs() */
	csv3_free_smr_list(kvm);

e_free_hugetlb:
	csv3_free_1G_hugetlb_pages(kvm);

done:
	kfree(set_guest_private_memory);
	kfree(regions);

	return ret;
}

/*
 * Calculate the npt size according to the input VM size, return the SMR number
 * for the NPT.
 *
 * This helper function is used when CSV3 private memory is allocated from CMA.
 */
static u32 csv3_get_vm_npt_smr_number(unsigned long vm_size)
{
	u64 nr_pages = vm_size >> PAGE_SHIFT;
	u32 smr_entry_shift, nr_smr;
	u64 size;

	/*
	 * NPT secure memory size
	 *
	 * PTEs_entries = nr_pages
	 * PDEs_entries = nr_pages / 512
	 * PDPEs_entries = nr_pages / (512 * 512)
	 * PML4Es_entries = nr_pages / (512 * 512 * 512)
	 *
	 * Totals_entries = nr_pages + nr_pages / 512 + nr_pages / (512 * 512) +
	 *		nr_pages / (512 * 512 * 512) <= nr_pages + nr_pages / 256
	 *
	 * Total_NPT_size = (Totals_entries / 512) * PAGE_SIZE = ((nr_pages +
	 *      nr_pages / 256) / 512) * PAGE_SIZE = nr_pages * 8 + nr_pages / 32
	 *      <= nr_pages * 9
	 *
	 */
	smr_entry_shift = csv_get_smr_entry_shift();
	size = ALIGN(nr_pages * 9, 1UL << smr_entry_shift);
	nr_smr = size >> smr_entry_shift;

	return nr_smr;
}

/**
 * This helper function is used when CSV3 private memory is allocated from CMA.
 */
static int csv3_set_cma_smr(struct kvm *kvm, unsigned long vm_size,
			    nodemask_t *nodemask, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_set_guest_private_memory *set_guest_private_memory;
	struct secure_memory_region *smr;
	struct csv3_data_memory_region *regions;

	LIST_HEAD(tmp_list);
	struct list_head *pos, *q;
	u32 i = 0, count = 0, remainder;
	int ret = 0;
	u64 nr_smr = 0;
	u32 smr_entry_shift;

	set_guest_private_memory = kzalloc(sizeof(*set_guest_private_memory),
					GFP_KERNEL_ACCOUNT);
	if (!set_guest_private_memory)
		return -ENOMEM;

	regions = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!regions) {
		kfree(set_guest_private_memory);
		return -ENOMEM;
	}

	smr_entry_shift = csv_get_smr_entry_shift();

	/**
	 * If @csv_smcr_num is zero or the firmware does not support explicit
	 * NPT reservation in SMCR, both VMSA and NPT are allocated from CMA.
	 * Otherwise, the NPT is already reserved in SMCR, and only a single
	 * SMR is needed for the VMSA.
	 */
	if (!csv_smcr_num || hygon_csv_build < 2407)
		nr_smr = (vm_size >> smr_entry_shift)
				+ 1 + csv3_get_vm_npt_smr_number(vm_size);
	else
		nr_smr = (vm_size >> smr_entry_shift) + 1;

	remainder = nr_smr;
	for (i = 0; i < nr_smr; i++) {
		smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
		if (!smr) {
			ret = -ENOMEM;
			goto e_free_smr;
		}

		smr->hpa = csv_alloc_from_contiguous((1UL << smr_entry_shift),
						nodemask,
						get_order(1 << smr_entry_shift));
		if (!smr->hpa) {
			kfree(smr);
			ret = -ENOMEM;
			goto e_free_smr;
		}

		smr->npages = ((1UL << smr_entry_shift) >> PAGE_SHIFT);
		list_add_tail(&smr->list, &tmp_list);

		regions[count].size = (1UL << smr_entry_shift);
		regions[count].base_address = smr->hpa;
		count++;

		if (count >= (PAGE_SIZE / sizeof(regions[0])) || (remainder == count)) {
			set_guest_private_memory->nregions = count;
			set_guest_private_memory->handle = sev->handle;
			set_guest_private_memory->regions_paddr = __sme_pa(regions);

			/* set secury memory region for launch enrypt data */
			ret = hygon_kvm_hooks.sev_issue_cmd(kvm,
						CSV3_CMD_SET_GUEST_PRIVATE_MEMORY,
						set_guest_private_memory, &argp->error);
			if (ret)
				goto e_free_smr;

			memset(regions, 0, PAGE_SIZE);
			remainder -= count;
			count = 0;
		}
	}

	list_splice(&tmp_list, &csv->smr_list);

#ifdef CONFIG_SYSFS
	/**
	 * The NPT can be allocated from either CMA or global SMCR.
	 * Only account for it when allocated from CMA.
	 */
	if (!csv_smcr_num || hygon_csv_build < 2407)
		csv->npt_size = csv3_get_vm_npt_smr_number(vm_size)
							<< smr_entry_shift;
	else
		csv->npt_size = 0;
	csv->pri_mem = (nr_smr << smr_entry_shift) - csv->npt_size;
	atomic_long_add(csv->npt_size, &csv3_npt_size);
	atomic_long_add(csv->pri_mem, &csv3_pri_mem);
#endif

	goto done;

e_free_smr:
	/* Remove temporary smr_list */
	if (!list_empty(&tmp_list)) {
		list_for_each_safe(pos, q, &tmp_list) {
			smr = list_entry(pos, struct secure_memory_region, list);
			if (smr) {
				csv_release_to_contiguous(smr->hpa,
							smr->npages << PAGE_SHIFT);
				list_del(&smr->list);
				kfree(smr);
			}
		}
	}
done:
	kfree(set_guest_private_memory);
	kfree(regions);

	return ret;
}

static int csv3_set_guest_private_memory(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;
	nodemask_t nodemask;
	nodemask_t *nodemask_ptr;

	u32 i = 0;
	int ret = 0;
	u32 smr_entry_shift;

	unsigned int flags = FOLL_HWPOISON;
	u64 npages, nr_pages = 0;
	struct page *page;

	unsigned long vm_size;
	enum csv_smr_source source;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	/* The smr_list should be initialized only once */
	if (!list_empty(&csv->smr_list))
		return -EFAULT;

	nodes_clear(nodemask);
	for_each_set_bit(i, &csv->nodemask, BITS_PER_LONG)
		if (i < MAX_NUMNODES)
			node_set(i, nodemask);

	nodemask_ptr = csv->nodemask ? &nodemask : &node_online_map;

	/* Get guest secure memory size */
	kvm_for_each_memslot(memslot, slots) {
		if (memslot->flags & KVM_MEM_READONLY)
			continue;

		npages = get_user_pages_unlocked(memslot->userspace_addr, 1,
						&page, flags);
		if (npages != 1)
			continue;

		nr_pages += memslot->npages;

		put_page(page);
	}

	smr_entry_shift = csv_get_smr_entry_shift();
	vm_size = ALIGN((nr_pages << PAGE_SHIFT), 1UL << smr_entry_shift);

	/**
	 * Allocation policy for NPT and VMSA based on CSV3 private memory
	 * source:
	 *
	 * - When CSV3 private memory is allocated from 1GB hugepages:
	 *     * NPT is allocated from the global SMCR.
	 *     * VMSA is allocated from system-reserved memory pool.
	 *
	 * - When CSV3 private memory is allocated from CMA:
	 *     * VMSA is allocated from CMA.
	 *     * NPT is allocated from the global SMCR if it was reserved at
	 *	 host boot time; otherwise, it is allocated from CMA.
	 */
	source = get_csv_smr_source();
	if (source == USE_HUGETLB) {
		ret = csv3_set_hugetlb_smr(kvm, vm_size, nodemask_ptr, argp);
	} else if (source == USE_CMA) {
		ret = csv3_set_cma_smr(kvm, vm_size, nodemask_ptr, argp);
	} else {
		pr_warn_once("CSV3: no guest private memory source configured\n");
		ret = -EFAULT;
	}

	return ret;
}

/**
 * csv3_launch_encrypt_data_alt_1 - The legacy handler to encrypt CSV3
 * guest's memory before VMRUN.
 */
static int csv3_launch_encrypt_data_alt_1(struct kvm *kvm,
					  struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_launch_encrypt_data params;
	struct csv3_data_launch_encrypt_data *encrypt_data = NULL;
	struct encrypt_data_block *blocks = NULL;
	u8 *data = NULL;
	u32 offset;
	u32 num_entries, num_entries_in_block;
	u32 num_blocks, num_blocks_max;
	u32 i, n;
	unsigned long pfn, pfn_sme_mask;
	int ret = 0;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params))) {
		ret = -EFAULT;
		goto exit;
	}

	if ((params.len & ~PAGE_MASK) || !params.len || !params.uaddr) {
		ret = -EINVAL;
		goto exit;
	}

	/*
	 * If userspace request to invoke CSV3_CMD_SET_GUEST_PRIVATE_MEMORY
	 * explicitly, we should not calls to csv3_set_guest_private_memory()
	 * here.
	 */
	if (!(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_SET_PRIV_MEM)) {
		/* Allocate all the guest memory from CMA */
		ret = csv3_set_guest_private_memory(kvm, argp);
		if (ret)
			goto exit;
	}

	num_entries = params.len / PAGE_SIZE;
	num_entries_in_block = ARRAY_SIZE(blocks->entry);
	num_blocks = (num_entries + num_entries_in_block - 1) / num_entries_in_block;
	num_blocks_max = ARRAY_SIZE(encrypt_data->data_blocks);

	if (num_blocks >= num_blocks_max) {
		ret = -EINVAL;
		goto exit;
	}

	data = vzalloc(params.len);
	if (!data) {
		ret = -ENOMEM;
		goto exit;
	}
	if (copy_from_user(data, (void __user *)params.uaddr, params.len)) {
		ret = -EFAULT;
		goto data_free;
	}

	blocks = vzalloc(num_blocks * sizeof(*blocks));
	if (!blocks) {
		ret = -ENOMEM;
		goto data_free;
	}

	for (offset = 0, i = 0, n = 0; offset < params.len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + data);
		pfn_sme_mask = __sme_set(pfn << PAGE_SHIFT) >> PAGE_SHIFT;
		if (offset && ((blocks[n].entry[i].pfn + 1) == pfn_sme_mask))
			blocks[n].entry[i].npages += 1;
		else {
			if (offset) {
				i = (i + 1) % num_entries_in_block;
				n = (i == 0) ? (n + 1) : n;
			}
			blocks[n].entry[i].pfn = pfn_sme_mask;
			blocks[n].entry[i].npages = 1;
		}
	}

	encrypt_data = kzalloc(sizeof(*encrypt_data), GFP_KERNEL);
	if (!encrypt_data) {
		ret = -ENOMEM;
		goto block_free;
	}

	encrypt_data->handle = csv->sev->handle;
	encrypt_data->length = params.len;
	encrypt_data->gpa = params.gpa;
	for (i = 0; i <= n; i++) {
		encrypt_data->data_blocks[i] =
		__sme_set(vmalloc_to_pfn((void *)blocks + i * sizeof(*blocks)) << PAGE_SHIFT);
	}

	clflush_cache_range(data, params.len);
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_LAUNCH_ENCRYPT_DATA,
					    encrypt_data, &argp->error);

	kfree(encrypt_data);
block_free:
	vfree(blocks);
data_free:
	vfree(data);
exit:
	return ret;
}

#define MAX_ENTRIES_PER_BLOCK							\
	(sizeof(((struct encrypt_data_block *)0)->entry) /			\
	 sizeof(((struct encrypt_data_block *)0)->entry[0]))
#define MAX_BLOCKS_PER_CSV3_LUP_DATA						\
	(sizeof(((struct csv3_data_launch_encrypt_data *)0)->data_blocks) /	\
	 sizeof(((struct csv3_data_launch_encrypt_data *)0)->data_blocks[0]))
#define MAX_ENTRIES_PER_CSV3_LUP_DATA						\
	(MAX_BLOCKS_PER_CSV3_LUP_DATA * MAX_ENTRIES_PER_BLOCK)

/**
 * __csv3_launch_encrypt_data - The helper for handler
 * csv3_launch_encrypt_data_alt_2.
 */
static int __csv3_launch_encrypt_data(struct kvm *kvm,
				      struct kvm_sev_cmd *argp,
				      struct kvm_csv3_launch_encrypt_data *params,
				      void *src_buf,
				      unsigned int start_pgoff,
				      unsigned int end_pgoff)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_launch_encrypt_data *data = NULL;
	struct encrypt_data_block *block = NULL;
	struct page **pages = NULL;
	unsigned long len, remain_len;
	unsigned long pfn, pfn_sme_mask, last_pfn;
	unsigned int pgoff = start_pgoff;
	int i, j;
	int ret = -ENOMEM;

	/* Alloc command buffer for CSV3_CMD_LAUNCH_ENCRYPT_DATA command */
	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* Alloc pages for data_blocks[] in the command buffer */
	len = ARRAY_SIZE(data->data_blocks) * sizeof(struct page *);
	pages = kzalloc(len, GFP_KERNEL_ACCOUNT);
	if (!pages)
		goto e_free_data;

	for (i = 0; i < ARRAY_SIZE(data->data_blocks); i++) {
		pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!pages[i])
			goto e_free_pages;
	}

	i = 0;
	while (i < ARRAY_SIZE(data->data_blocks) && pgoff < end_pgoff) {
		block = (struct encrypt_data_block *)page_to_virt(pages[i]);

		j = 0;
		last_pfn = 0;
		while (j < ARRAY_SIZE(block->entry) && pgoff < end_pgoff) {
			pfn = vmalloc_to_pfn(src_buf + (pgoff << PAGE_SHIFT));
			pfn_sme_mask = __sme_set(pfn << PAGE_SHIFT) >> PAGE_SHIFT;

			/*
			 * One entry can record a number of contiguous physical
			 * pages. If the current page is not adjacent to the
			 * previous physical page, we should record the page to
			 * the next entry. If entries of current block is used
			 * up, we should try the next block.
			 */
			if (last_pfn && (last_pfn + 1 == pfn)) {
				block->entry[j].npages++;
			} else if (j < (ARRAY_SIZE(block->entry) - 1)) {
				/* @last_pfn == 0 means fill in entry[0] */
				if (likely(last_pfn != 0))
					j++;
				block->entry[j].pfn = pfn_sme_mask;
				block->entry[j].npages = 1;
			} else {
				break;
			}

			/*
			 * Succeed to record one page, increase the page offset.
			 * We also record the pfn of current page so that we can
			 * record the contiguous physical pages into one entry.
			 */
			last_pfn = pfn;
			pgoff++;
		}

		i++;
	}

	if (pgoff < end_pgoff) {
		pr_err("CSV3: Fail to fill in LAUNCH_ENCRYPT_DATA command!\n");
		goto e_free_pages;
	}

	len = (end_pgoff - start_pgoff) << PAGE_SHIFT;
	clflush_cache_range(src_buf + (start_pgoff << PAGE_SHIFT), len);

	/* Fill in command buffer */
	data->handle = csv->sev->handle;

	if (start_pgoff == 0) {
		data->gpa = params->gpa;
		len -= params->gpa & ~PAGE_MASK;
	} else {
		data->gpa = (params->gpa & PAGE_MASK) + (start_pgoff << PAGE_SHIFT);
	}
	remain_len = params->len - (data->gpa - params->gpa);

	data->length = (len <= remain_len) ? len : remain_len;

	for (j = 0; j < i; j++)
		data->data_blocks[j] = __sme_set(page_to_phys(pages[j]));

	/* Issue command */
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_LAUNCH_ENCRYPT_DATA,
							data, &argp->error);

e_free_pages:
	for (i = 0; i < ARRAY_SIZE(data->data_blocks); i++) {
		if (pages[i])
			__free_page(pages[i]);
	}
	kfree(pages);
e_free_data:
	kfree(data);

	return ret;
}

/**
 * csv3_launch_encrypt_data_alt_2 - The handler to support encrypt CSV3
 * guest's memory before VMRUN. This handler support issue API command
 * multiple times, both the GPA and length of the memory region are not
 * required to be 4K-aligned.
 */
static int csv3_launch_encrypt_data_alt_2(struct kvm *kvm,
					  struct kvm_sev_cmd *argp)
{
	struct kvm_csv3_launch_encrypt_data params;
	void *buffer = NULL;
	unsigned long len;
	unsigned int total_pages, start_pgoff, next_pgoff;
	int ret = 0;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params))) {
		return -EFAULT;
	}

	/* Both the GPA and length must be 16 Bytes aligned at least */
	if (!params.len ||
	    !params.uaddr ||
	    !IS_ALIGNED(params.len, 16) ||
	    !IS_ALIGNED(params.gpa, 16)) {
		return -EINVAL;
	}

	/*
	 * Alloc buffer to save source data. When we copy source data from
	 * userspace to the buffer, the data in the first page of the buffer
	 * should keep the offset as params.gpa.
	 */
	len = PAGE_ALIGN((params.gpa & ~PAGE_MASK) + params.len);
	total_pages = len >> PAGE_SHIFT;
	next_pgoff = 0;

	buffer = vzalloc(len);
	if (!buffer)
		return -ENOMEM;

	if (copy_from_user(buffer + (params.gpa & ~PAGE_MASK),
			   (void __user *)params.uaddr, params.len)) {
		ret = -EFAULT;
		goto e_free_buffer;
	}

	/*
	 * If the source data is too large, we should issue command more than
	 * once. The LAUNCH_ENCRYPT_DATA API updates not only the measurement
	 * of the data, but also the measurement of the metadata correspond to
	 * the data. The guest owner is obligated to verify the launch
	 * measurement, so guest owner must be aware of the launch measurement
	 * of each LAUNCH_ENCRYPT_DATA API command. If we processing pages more
	 * than MAX_ENTRIES_PER_CSV3_LUP_DATA in each API command, the guest
	 * owner could not able to calculate the correct measurement and fail
	 * to verify the launch measurement. For this reason, we limit the
	 * maximum number of pages processed by each API command to
	 * MAX_ENTRIES_PER_CSV3_LUP_DATA.
	 */
	while (next_pgoff < total_pages) {
		start_pgoff = next_pgoff;
		next_pgoff += MAX_ENTRIES_PER_CSV3_LUP_DATA;

		if (next_pgoff > total_pages)
			next_pgoff = total_pages;

		ret = __csv3_launch_encrypt_data(kvm, argp, &params,
						 buffer, start_pgoff, next_pgoff);
		if (ret)
			goto e_free_buffer;
	}

e_free_buffer:
	vfree(buffer);
	return ret;
}

static int csv3_launch_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (!(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_MULT_LUP_DATA))
		return csv3_launch_encrypt_data_alt_1(kvm, argp);

	return csv3_launch_encrypt_data_alt_2(kvm, argp);
}

static int csv3_sync_vmsa(struct vcpu_svm *svm)
{
	struct vmcb_save_area *save = &svm->vmcb->save;

	/* Check some debug related fields before encrypting the VMSA */
	if (svm->vcpu.guest_debug || (save->dr7 & ~DR7_FIXED_1))
		return -EINVAL;

	/* Sync registgers per spec. */
	save->rax = svm->vcpu.arch.regs[VCPU_REGS_RAX];
	save->rbx = svm->vcpu.arch.regs[VCPU_REGS_RBX];
	save->rcx = svm->vcpu.arch.regs[VCPU_REGS_RCX];
	save->rdx = svm->vcpu.arch.regs[VCPU_REGS_RDX];
	save->rsp = svm->vcpu.arch.regs[VCPU_REGS_RSP];
	save->rbp = svm->vcpu.arch.regs[VCPU_REGS_RBP];
	save->rsi = svm->vcpu.arch.regs[VCPU_REGS_RSI];
	save->rdi = svm->vcpu.arch.regs[VCPU_REGS_RDI];
#ifdef CONFIG_X86_64
	save->r8  = svm->vcpu.arch.regs[VCPU_REGS_R8];
	save->r9  = svm->vcpu.arch.regs[VCPU_REGS_R9];
	save->r10 = svm->vcpu.arch.regs[VCPU_REGS_R10];
	save->r11 = svm->vcpu.arch.regs[VCPU_REGS_R11];
	save->r12 = svm->vcpu.arch.regs[VCPU_REGS_R12];
	save->r13 = svm->vcpu.arch.regs[VCPU_REGS_R13];
	save->r14 = svm->vcpu.arch.regs[VCPU_REGS_R14];
	save->r15 = svm->vcpu.arch.regs[VCPU_REGS_R15];
#endif
	save->rip = svm->vcpu.arch.regs[VCPU_REGS_RIP];

	/* Sync some non-GPR registers before encrypting */
	save->xcr0 = svm->vcpu.arch.xcr0;
	save->pkru = svm->vcpu.arch.pkru;
	save->xss  = svm->vcpu.arch.ia32_xss;
	save->dr6  = svm->vcpu.arch.dr6;

	pr_debug("Virtual Machine Save Area (VMSA):\n");
	print_hex_dump_debug("", DUMP_PREFIX_NONE, 16, 1, save, sizeof(*save), false);

	memcpy(svm->vmsa, save, sizeof(*save));
	return 0;
}

static int csv3_launch_encrypt_vmcb(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_launch_encrypt_vmcb *encrypt_vmcb = NULL;
	struct kvm_vcpu *vcpu;
	int ret = 0;
	unsigned long i = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	encrypt_vmcb = kzalloc(sizeof(*encrypt_vmcb), GFP_KERNEL);
	if (!encrypt_vmcb) {
		ret = -ENOMEM;
		goto exit;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		ret = csv3_sync_vmsa(svm);
		if (ret)
			goto e_free;
		clflush_cache_range(svm->vmsa, PAGE_SIZE);
		clflush_cache_range(svm->vmcb, PAGE_SIZE);
		encrypt_vmcb->handle = csv->sev->handle;
		encrypt_vmcb->vcpu_id = i;
		encrypt_vmcb->vmsa_addr = __sme_pa(svm->vmsa);
		encrypt_vmcb->vmsa_len = PAGE_SIZE;
		encrypt_vmcb->shadow_vmcb_addr = __sme_pa(svm->vmcb);
		encrypt_vmcb->shadow_vmcb_len = PAGE_SIZE;
		ret = hygon_kvm_hooks.sev_issue_cmd(kvm,
						CSV3_CMD_LAUNCH_ENCRYPT_VMCB,
						encrypt_vmcb, &argp->error);
		if (ret)
			goto e_free;

		svm->vmcb_pa = encrypt_vmcb->secure_vmcb_addr;

		/*
		 * CSV3 guests maintain an encrypted version of their FPU
		 * state which is restored and saved on VMRUN and VMEXIT.
		 * Mark vcpu->arch.guest_fpu->fpstate as scratch so it won't
		 * do xsave/xrstor on it.
		 */
		fpstate_set_confidential(&vcpu->arch.guest_fpu);

		svm->vcpu.arch.guest_state_protected = true;
	}

e_free:
	kfree(encrypt_vmcb);
exit:
	return ret;
}

static int csv3_launch_finish_ex(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_launch_finish_ex params;
	struct csv3_data_launch_finish_ex *finish_ex = NULL;
	int ret = 0;

	if (!csv3_guest(kvm) ||
	    !(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_LFINISH_EX))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	finish_ex = kzalloc(sizeof(*finish_ex), GFP_KERNEL);
	if (!finish_ex)
		return -ENOMEM;

	finish_ex->handle = csv->sev->handle;
	memcpy(finish_ex->host_data, params.host_data, KVM_CSV3_HOST_DATA_SIZE);
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_LAUNCH_FINISH_EX,
						finish_ex, &argp->error);

	kfree(finish_ex);

	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
csv3_send_encrypt_data_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
				     struct kvm_csv3_send_encrypt_data *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_send_encrypt_data data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_DATA,
					    &data, &argp->error);

	params->hdr_len = data.hdr_len;
	params->trans_len = data.trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params, sizeof(*params)))
		ret = -EFAULT;

	return ret;
}

#define CSV3_SEND_ENCRYPT_DATA_MIGRATE_PAGE  0x00000000
#define CSV3_SEND_ENCRYPT_DATA_SET_READONLY  0x00000001
static int csv3_send_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_send_encrypt_data data;
	struct kvm_csv3_send_encrypt_data params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct guest_paddr_block *guest_block;
	unsigned long pfn;
	u32 offset;
	int ret = 0;
	int i;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return csv3_send_encrypt_data_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.guest_addr_data ||
	    !params.guest_addr_len || !params.hdr_uaddr)
		return -EINVAL;

	if (params.guest_addr_len > sizeof(*guest_block))
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	if ((params.trans_len & PAGE_MASK) == 0 ||
	    (params.trans_len & ~PAGE_MASK) != 0)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	guest_block = kzalloc(sizeof(*guest_block), GFP_KERNEL_ACCOUNT);
	if (!guest_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}

	if (copy_from_user(guest_block,
			   (void __user *)(uintptr_t)params.guest_addr_data,
			   params.guest_addr_len)) {
		ret = -EFAULT;
		goto e_free_guest_block;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_guest_block;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}
	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;

	data.guest_block = __psp_pa(guest_block);
	data.guest_len = params.guest_addr_len;
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(guest_block, PAGE_SIZE);

	data.flag = CSV3_SEND_ENCRYPT_DATA_SET_READONLY;
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_DATA,
					    &data, &argp->error);
	if (ret)
		goto e_free_trans_data;

	kvm_flush_remote_tlbs(kvm);

	data.flag = CSV3_SEND_ENCRYPT_DATA_MIGRATE_PAGE;
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_DATA,
					    &data, &argp->error);
	if (ret)
		goto e_free_trans_data;

	ret = -EFAULT;
	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len))
		goto e_free_trans_data;

	/* copy guest address block to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.guest_addr_data,
			 guest_block, params.guest_addr_len))
		goto e_free_trans_data;

	/* copy packet header to userspace. */
	if (copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			 params.hdr_len))
		goto e_free_trans_data;

	ret = 0;
e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_guest_block:
	kfree(guest_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
csv3_send_encrypt_context_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
					struct kvm_csv3_send_encrypt_context *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_send_encrypt_context data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_CONTEXT,
					    &data, &argp->error);

	params->hdr_len = data.hdr_len;
	params->trans_len = data.trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params, sizeof(*params)))
		ret = -EFAULT;

	return ret;
}

static int csv3_send_encrypt_context(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_send_encrypt_context data;
	struct kvm_csv3_send_encrypt_context params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	unsigned long pfn;
	unsigned long i;
	u32 offset;
	int ret = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return csv3_send_encrypt_context_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.hdr_uaddr)
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.handle = sev->handle;

	/* flush hdr, trans data, trans block, secure VMSAs */
	wbinvd_on_all_cpus();

	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_SEND_ENCRYPT_CONTEXT,
					    &data, &argp->error);

	if (ret)
		goto e_free_trans_data;

	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	/* copy packet header to userspace. */
	if (copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			 params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static int csv3_receive_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_receive_encrypt_data data;
	struct kvm_csv3_receive_encrypt_data params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct guest_paddr_block *guest_block;
	unsigned long pfn;
	int i;
	u32 offset;
	int ret = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (unlikely(list_empty(&csv->smr_list))) {
		/* Allocate all the guest memory from CMA */
		ret = csv3_set_guest_private_memory(kvm, argp);
		if (ret)
			goto exit;
	}

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.guest_addr_data || !params.guest_addr_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	if (params.guest_addr_len > sizeof(*guest_block))
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	if (copy_from_user(hdr,
			   (void __user *)(uintptr_t)params.hdr_uaddr,
			   params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_hdr;
	}

	guest_block = kzalloc(sizeof(*guest_block), GFP_KERNEL_ACCOUNT);
	if (!guest_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}

	if (copy_from_user(guest_block,
			   (void __user *)(uintptr_t)params.guest_addr_data,
			   params.guest_addr_len)) {
		ret = -EFAULT;
		goto e_free_guest_block;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_guest_block;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	if (copy_from_user(trans_data,
			   (void __user *)(uintptr_t)params.trans_uaddr,
			   params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.guest_block = __psp_pa(guest_block);
	data.guest_len = params.guest_addr_len;
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(guest_block, PAGE_SIZE);
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_RECEIVE_ENCRYPT_DATA,
					    &data, &argp->error);

e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_guest_block:
	kfree(guest_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static int csv3_receive_encrypt_context(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv3_data_receive_encrypt_context data;
	struct kvm_csv3_receive_encrypt_context params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct vmcb_paddr_block *shadow_vmcb_block;
	struct vmcb_paddr_block *secure_vmcb_block;
	unsigned long pfn;
	u32 offset;
	int ret = 0;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	if (!params.trans_uaddr || !params.trans_len ||
	    !params.hdr_uaddr || !params.hdr_len)
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	if (copy_from_user(hdr,
			   (void __user *)(uintptr_t)params.hdr_uaddr,
			   params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_hdr;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	if (copy_from_user(trans_data,
			   (void __user *)(uintptr_t)params.trans_uaddr,
			   params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	secure_vmcb_block = kzalloc(sizeof(*secure_vmcb_block),
				    GFP_KERNEL_ACCOUNT);
	if (!secure_vmcb_block) {
		ret = -ENOMEM;
		goto e_free_trans_data;
	}

	shadow_vmcb_block = kzalloc(sizeof(*shadow_vmcb_block),
				    GFP_KERNEL_ACCOUNT);
	if (!shadow_vmcb_block) {
		ret = -ENOMEM;
		goto e_free_secure_vmcb_block;
	}

	memset(&data, 0, sizeof(data));

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		if (i >= ARRAY_SIZE(shadow_vmcb_block->vmcb_paddr)) {
			ret = -EINVAL;
			goto e_free_shadow_vmcb_block;
		}
		shadow_vmcb_block->vmcb_paddr[i] = __sme_pa(svm->vmcb);
		data.vmcb_block_len += sizeof(shadow_vmcb_block->vmcb_paddr[0]);
	}

	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.shadow_vmcb_block = __psp_pa(shadow_vmcb_block);
	data.secure_vmcb_block = __psp_pa(secure_vmcb_block);
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(shadow_vmcb_block, PAGE_SIZE);
	clflush_cache_range(secure_vmcb_block, PAGE_SIZE);

	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_RECEIVE_ENCRYPT_CONTEXT,
					    &data, &argp->error);
	if (ret)
		goto e_free_shadow_vmcb_block;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		if (i >= ARRAY_SIZE(secure_vmcb_block->vmcb_paddr)) {
			ret = -EINVAL;
			goto e_free_shadow_vmcb_block;
		}

		svm->vmcb_pa = secure_vmcb_block->vmcb_paddr[i];
		svm->vcpu.arch.guest_state_protected = true;
	}

e_free_shadow_vmcb_block:
	kfree(shadow_vmcb_block);
e_free_secure_vmcb_block:
	kfree(secure_vmcb_block);
e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static void csv3_mark_page_dirty(struct kvm_vcpu *vcpu, gva_t gpa,
				 unsigned long npages)
{
	gfn_t gfn;
	gfn_t gfn_end;

	gfn = gpa >> PAGE_SHIFT;
	gfn_end = gfn + npages;
#ifdef KVM_HAVE_MMU_RWLOCK
	write_lock(&vcpu->kvm->mmu_lock);
#else
	spin_lock(&vcpu->kvm->mmu_lock);
#endif
	for (; gfn < gfn_end; gfn++)
		kvm_vcpu_mark_page_dirty(vcpu, gfn);
#ifdef KVM_HAVE_MMU_RWLOCK
	write_unlock(&vcpu->kvm->mmu_lock);
#else
	spin_unlock(&vcpu->kvm->mmu_lock);
#endif
}

static int csv3_mmio_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, u32 error_code)
{
	int r = 0;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	union csv3_page_attr page_attr = {.mmio = 1};
	union csv3_page_attr page_attr_mask = {.mmio = 1};
	struct csv3_data_update_npt *update_npt;
	int psp_ret;

	if (!hygon_kvm_hooks.sev_hooks_installed)
		return -EFAULT;

	update_npt = kzalloc(sizeof(*update_npt), GFP_KERNEL);
	if (!update_npt) {
		pr_err_ratelimited("Failure allocate npt command: gpa 0x%llx, error code 0x%x\n",
				   (unsigned long long)gpa, error_code);
		r = -ENOMEM;
		goto exit;
	}

	csv3_init_update_npt(update_npt, gpa, error_code,
			     kvm_svm->sev_info.handle);
	update_npt->page_attr = page_attr.val;
	update_npt->page_attr_mask = page_attr_mask.val;
	update_npt->level = CSV3_PG_LEVEL_4K;

	r = hygon_kvm_hooks.sev_issue_cmd(vcpu->kvm, CSV3_CMD_UPDATE_NPT,
					  update_npt, &psp_ret);

	if (psp_ret != SEV_RET_SUCCESS) {
		pr_err_ratelimited("Failure update NPT: gpa 0x%llx, error code 0x%x, ret %d\n",
				   (unsigned long long)gpa, error_code, r);
		r = -EFAULT;
	}

	kfree(update_npt);
exit:
	return r;
}

static int __csv3_page_fault(struct kvm_vcpu *vcpu, gva_t gpa,
			     u32 error_code, struct kvm_memory_slot *slot,
			     int *psp_ret_ptr, kvm_pfn_t pfn, u32 level)
{
	int r = 0;
	struct csv3_data_update_npt *update_npt;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	int psp_ret = 0;

	if (!hygon_kvm_hooks.sev_hooks_installed)
		return -EFAULT;

	update_npt = kzalloc(sizeof(*update_npt), GFP_KERNEL);
	if (!update_npt) {
		pr_err_ratelimited("Failure allocate npt command: gpa 0x%llx, error code 0x%x\n",
				   (unsigned long long)gpa, error_code);
		r = -ENOMEM;
		goto exit;
	}

	csv3_init_update_npt(update_npt, gpa, error_code,
			     kvm_svm->sev_info.handle);

	update_npt->spa = pfn << PAGE_SHIFT;
	update_npt->level = level;

	if (!csv3_is_mmio_pfn(pfn))
		update_npt->spa |= sme_me_mask;

	r = hygon_kvm_hooks.sev_issue_cmd(vcpu->kvm, CSV3_CMD_UPDATE_NPT,
					  update_npt, &psp_ret);

	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	kvm_flush_remote_tlbs(vcpu->kvm);

	csv3_mark_page_dirty(vcpu, update_npt->gpa, update_npt->npages);

	if (psp_ret_ptr)
		*psp_ret_ptr = psp_ret;

	kfree(update_npt);
exit:
	return r;
}

static int csv_pin_shared_memory_locked(struct kvm_vcpu *vcpu,
					struct kvm_memory_slot *slot,
					gfn_t gfn,
					kvm_pfn_t *pfn)
{
	u64 hva;
	kvm_pfn_t tmp_pfn;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct shared_page *sp;
	unsigned int pg_off;
	bool write = !(slot->flags & KVM_MEM_READONLY);

	tmp_pfn = __gfn_to_pfn_memslot(slot, gfn, false, NULL, write,
				       NULL, NULL);
	if (unlikely(is_error_pfn(tmp_pfn))) {
		pr_err_ratelimited("Invalid pfn 0x%llx for gfn 0x%llx\n",
				   (unsigned long long)tmp_pfn, gfn);
		return -EINVAL;
	}

	if (csv3_is_mmio_pfn(tmp_pfn)) {
		*pfn = tmp_pfn;
		return 0;
	}

	hva = __gfn_to_hva_memslot(slot, gfn);

	if (page_maybe_dma_pinned(pfn_to_page(tmp_pfn))) {
		kvm_release_pfn_clean(tmp_pfn);
		/*
		 * If we have already pinned the page when traversing the
		 * memslot, and the pinned page is part of a compound page that
		 * tracked by shared page entry, we must set the corresponding
		 * bit in the @bitmap to reflect that this subpage is shared
		 * memory for CSV3 VM.
		 *
		 * This ensures that all 4K subpages within a compound page can
		 * be accurately tracked, preventing premature removal of pages
		 * that are still be shared memory.
		 */
		shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, NULL);
		*pfn = tmp_pfn;
		return 0;
	}

	kvm_release_pfn_clean(tmp_pfn);

	/*
	 * If the shared page manager does not already track @hva:
	 *   - Pin the page using pin_user_pages();
	 *   - Allocate a new shared_page entry, if the pinned page is part of
	 *     a compound page, allocate a @bitmap and set the bit corresponding
	 *     to this 4K subpage.
	 *
	 * If the @hva is already tracked by the manager, set the corresponding
	 * bit in the @bitmap.
	 */
	sp = shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, NULL);
	if (unlikely(sp)) {
		pr_err_ratelimited("%s: not pinned but in the tree\n", __func__);
		pg_off = (hva & ~sp->track_hva) >> PAGE_SHIFT;
		*pfn = page_to_pfn(sp->track_page) + pg_off;
	} else {
		struct shared_page *old_sp;
		struct page *page;
		int npinned;

		mmap_write_lock(current->mm);
		npinned = pin_user_pages(hva, 1, FOLL_WRITE | FOLL_LONGTERM, &page, NULL);
		mmap_write_unlock(current->mm);
		if (npinned != 1) {
			pr_err_ratelimited("Failure pin gfn:0x%llx\n", gfn);
			/*
			 * GUP returns -ENOMEM when it fails to allocate memory
			 * for the pin or to migrate a long-term pinned page.
			 * Such failures can be transient, so report -EAGAIN to
			 * resume the guest and retry #NPF. Permanent failures
			 * are propagated to userspace.
			 */
			if (npinned == -ENOMEM)
				return -EAGAIN;
			return npinned < 0 ? npinned : -EFAULT;
		}

		sp = alloc_shared_page_entry(csv, hva, page);
		if (!sp) {
			unpin_user_page(page);
			return -ENOMEM;
		}

		if (insert_shared_page_entry_locked(&csv->sp_mgr, sp, &old_sp)) {
			*pfn = page_to_pfn(page);
		} else {
			pr_err_ratelimited("%s: search fail but insertion found\n",
					   __func__);
			unpin_user_page(page);
			free_shared_page_entry(csv, sp);

			shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, old_sp);

			pg_off = (hva & ~old_sp->track_hva) >> PAGE_SHIFT;
			*pfn = page_to_pfn(old_sp->track_page) + pg_off;
		}
	}

	return 0;
}

static int csv3_mapping_level(struct kvm_vcpu *vcpu, gfn_t gfn, kvm_pfn_t pfn,
			      struct kvm_memory_slot *slot)
{
	unsigned long hva;
	int level;
	pte_t *pte;
	int page_num;
	gfn_t gfn_base;

	if (csv3_is_mmio_pfn(pfn)) {
		level = PG_LEVEL_4K;
		goto end;
	}

	if (!PageCompound(pfn_to_page(pfn))) {
		level = PG_LEVEL_4K;
		goto end;
	}

	level = PG_LEVEL_2M;
	page_num = KVM_PAGES_PER_HPAGE(level);
	gfn_base = gfn & ~(page_num - 1);

	/*
	 * 2M aligned guest address in memslot.
	 */
	if ((gfn_base < slot->base_gfn) ||
	    (gfn_base + page_num > slot->base_gfn + slot->npages)) {
		level = PG_LEVEL_4K;
		goto end;
	}

	/*
	 * hva in memslot is 2M aligned.
	 */
	if (__gfn_to_hva_memslot(slot, gfn_base) & ~PMD_MASK) {
		level = PG_LEVEL_4K;
		goto end;
	}

	hva = __gfn_to_hva_memslot(slot, gfn);
	pte = lookup_address_in_mm(vcpu->kvm->mm, hva, &level);
	if (unlikely(!pte)) {
		level = PG_LEVEL_4K;
		goto end;
	}

	/*
	 * Firmware supports 2M/4K level.
	 */
	level = level > PG_LEVEL_2M ? PG_LEVEL_2M : level;

end:
	return to_csv3_pg_level(level);
}

#define RETRY_CSV3_NPF_MAX	10

static int csv3_page_fault(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
			   gfn_t gfn, u32 error_code)
{
	int ret = 0;
	int psp_ret = 0;
	int level;
	kvm_pfn_t pfn = KVM_PFN_NOSLOT;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(vcpu->kvm)->csv_info;
	struct vcpu_svm *svm = to_svm(vcpu);

	if (error_code & PFERR_PRESENT_MASK)
		level = CSV3_PG_LEVEL_4K;
	else {
		mutex_lock(&csv->sp_lock);
		ret = csv_pin_shared_memory_locked(vcpu, slot, gfn, &pfn);
		mutex_unlock(&csv->sp_lock);
		if (ret) {
			/*
			 * -EAGAIN indicates that the page could not be pinned
			 * due to transient memory pressure. Resume the guest to
			 * retry #NPF. Permanent failures are propagated to
			 * userspace.
			 */
			if (ret == -EAGAIN) {
				if (++svm->csv3_npf_retry <= RETRY_CSV3_NPF_MAX) {
					ret = 0;
					goto exit;
				}
				pr_err_ratelimited("CSV3: pin retry limit, gfn 0x%llx\n", gfn);
				svm->csv3_npf_retry = 0;
			}
			goto exit;
		}

		svm->csv3_npf_retry = 0;
		level = csv3_mapping_level(vcpu, gfn, pfn, slot);
	}

	ret = __csv3_page_fault(vcpu, gfn << PAGE_SHIFT, error_code, slot,
				&psp_ret, pfn, level);

	if (psp_ret != SEV_RET_SUCCESS) {
		pr_err_ratelimited("Failure update NPT: gfn 0x%llx, error code 0x%x, psp_ret 0x%x\n",
				   gfn, error_code, psp_ret);
		ret = -EFAULT;
	}
exit:
	return ret;
}

/**
 * csv_release_shared_memory - Release shared pages and notify userspace to
 *			       madvise.
 * @params: Pointer to ioctl input/output structure, containing GPA range
 *	    and output fields.
 *
 * This function processes the KVM_CSV3_RELEASE_SHARED_MEMORY command by:
 *   - Iterating over each page in the specified GPA range;
 *   - For each page, attempting to remove it from the shared page manager;
 *   - If successful, updating the total number of unpinned pages;
 *   - Counting a released subpage of a partially shared compound page
 *     as handled, even though no page is unpinned;
 *   - Setting the start_hva to the first HVA that needs madvise (for
 *     contiguous range).
 *
 * The kernel ensures that:
 *   - Only one thread can modify the shared page manager at a time (via
 *     sp_lock);
 *   - The start_hva is set to the lowest HVA among all removed pages;
 *   - Userspace VMM should call madvise() on [start_hva, start_hva +
 *     unpinned * PAGE_SIZE).
 *
 * Return: 0 on success, negative error code on failure (though none are
 * currently returned).
 */
static int csv_release_shared_memory(struct kvm *kvm,
				     struct kvm_csv3_handle_memory *params)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct shared_page *sp;
	u64 hva;
	gfn_t gfn = gpa_to_gfn(params->gpa);
	u32 num_pages = params->num_pages;
	u32 i;
	int srcu_idx;
	bool released;

	/* Initialize output fields */
	params->start_hva = 0;
	params->unpinned = 0;
	params->handled0 = 0;

	/* Protect shared page manager from concurrent access */
	mutex_lock(&csv->sp_lock);
	for (i = 0; i < num_pages; i++, gfn++) {
		/* gfn_to_hva() reads memslots, which kvm->srcu protects */
		srcu_idx = srcu_read_lock(&kvm->srcu);
		hva = gfn_to_hva(kvm, gfn);
		srcu_read_unlock(&kvm->srcu, srcu_idx);

		/* Stop at the first gfn outside any memslot */
		if (kvm_is_error_hva(hva))
			break;

		if (unlikely(!params->start_hva))
			params->start_hva = hva;

		/*
		 * The madvise requested from user space need provide hva and
		 * length. This handler should fill back a range of contiguous
		 * hva. We maintain start_hva as the smallest hva among all
		 * released pages.
		 */
		if ((params->start_hva >> PAGE_SHIFT)
			+ params->unpinned != (hva >> PAGE_SHIFT))
			break;

		/*
		 * Try to release the shared state of this hva. If the whole entry
		 * was released, it is returned and the tracked page can be
		 * unpinned; otherwise @released tells whether the subpage itself
		 * was released.
		 */
		sp = remove_shared_page_entry_locked(&csv->sp_mgr, hva, &released);
		if (sp) {
			/* Update @unpinned only when an sp is removed */
			params->unpinned += 1U << sp->order;

			/*
			 * If this page is a tail page of a compound page, its
			 * HVA may be smaller than the head page's HVA. Since
			 * madvise must cover the entire compound page, we
			 * update start_hva to the smallest HVA in the range.
			 */
			if (sp->track_hva < params->start_hva) {
				params->handled0 = (1U << sp->order) -
					((params->start_hva - sp->track_hva) >> PAGE_SHIFT);
				params->start_hva = sp->track_hva;
			} else {
				params->handled0 += 1U << sp->order;
			}

			if (page_maybe_dma_pinned(sp->track_page))
				unpin_user_page(sp->track_page);
			else
				pr_err_ratelimited("%s: the track_page was not pinned\n",
						   __func__);
			free_shared_page_entry(csv, sp);
		} else {
			/*
			 * The 4K subpage was released but its compound page is
			 * still shared through other subpages, so there is no page
			 * to unpin. Report it as handled so that userspace can
			 * move forward instead of retrying this page forever.
			 */
			if (released)
				params->handled0 = i + 1;
			break;
		}

		cond_resched();
	}
	mutex_unlock(&csv->sp_lock);

	return 0;
}

static inline unsigned long get_vma_flags(unsigned long addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long vm_flags = 0;

	down_read(&mm->mmap_lock);
	vma = find_vma(mm, addr);
	if (vma && vma->vm_start <= addr)
		vm_flags = vma->vm_flags;
	up_read(&mm->mmap_lock);

	return vm_flags;
}

#define RETRY_CSV3_PIN_MAX	5
#define RETRY_CSV3_ALLOC_SP_MAX	5

/**
 * csv_get_shared_memory - Pin a number of pages specified in the input.
 * @params: Pointer to ioctl input/output structure, containing GPA range and
 *	    output field.
 *
 * This function processes the KVM_CSV3_GET_SHARED_MEMORY command by:
 *   - Iterating over each page in the specified GPA range;
 *   - For each page, checking if it is already tracked in the shared page
 *     manager;
 *   - If not, attempting to pin it and create a new entry;
 *   - Incrementing @pinned for every page that is successfully pinned.
 *   - Incrementing @handled for every GPA that is handled.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int csv_get_shared_memory(struct kvm *kvm,
				 struct kvm_csv3_handle_memory *params)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct shared_page *sp, *old_sp;
	struct page *page;
	unsigned long vm_flags = 0;
	u64 hva;
	gfn_t gfn = gpa_to_gfn(params->gpa);
	u32 num_pages = params->num_pages;
	u32 i;
	int npinned, try_pin, try_alloc_sp, srcu_idx;
	int ret = 0;

	/* Initialize output field */
	params->pinned = 0;
	params->handled1 = 0;

	/* Protect shared page manager from concurrent access */
	mutex_lock(&csv->sp_lock);
	for (i = 0; i < num_pages; i++, gfn++) {
		/* gfn_to_hva() reads memslots, which kvm->srcu protects */
		srcu_idx = srcu_read_lock(&kvm->srcu);
		hva = gfn_to_hva(kvm, gfn);
		srcu_read_unlock(&kvm->srcu, srcu_idx);
		if (kvm_is_error_hva(hva)) {
			/*
			 * If the HVA is invalid (e.g., not mapped), skip this
			 * page. This prevents unnecessary pinning attempts and
			 * continues processing remaining pages.
			 */
			params->handled1++;
			cond_resched();
			continue;
		}

		/*
		 * The GPA range may span several VMAs with different
		 * attributes, so look up the flags for every page.
		 */
		vm_flags = get_vma_flags((unsigned long)hva);

		/*
		 * Reject hugetlbfs-backed pages to prevent severe page
		 * migration pressure when 2M hugetlb is used with CMA.
		 */
		if (!vm_flags || (vm_flags & VM_HUGETLB)) {
			ret = -EINVAL;
			goto out;
		}

		sp = shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, NULL);
		if (sp) {
			params->handled1++;
			cond_resched();
			continue;
		}

		try_pin = 0;
		try_alloc_sp = 0;
retry_pin:
		/*
		 * The page is not yet tracked. We need to pin it and create a
		 * new entry. Acquire mm_write_lock to safely pin the page.
		 */
		mmap_write_lock(current->mm);
		npinned = pin_user_pages(hva, 1, FOLL_WRITE | FOLL_LONGTERM, &page, NULL);
		mmap_write_unlock(current->mm);
		if (npinned != 1) {
			if (++try_pin <= RETRY_CSV3_PIN_MAX)
				goto retry_pin;
			pr_err_ratelimited("%s: try pin fail\n", __func__);
			break;
		}

retry_alloc_sp:
		sp = alloc_shared_page_entry(csv, hva, page);
		if (!sp) {
			if (++try_alloc_sp <= RETRY_CSV3_ALLOC_SP_MAX)
				goto retry_alloc_sp;
			pr_err_ratelimited("%s: try alloc sp fail\n", __func__);
			unpin_user_page(page);
			break;
		}

		if (!insert_shared_page_entry_locked(&csv->sp_mgr, sp, &old_sp)) {
			pr_err_ratelimited("%s: search fail but insertion found\n",
					   __func__);
			unpin_user_page(page);
			free_shared_page_entry(csv, sp);

			shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, old_sp);
		} else {
			/* Update @pinned only upon insertion of a new sp */
			params->pinned += 1U << sp->order;
		}
		params->handled1++;

		cond_resched();
	}

out:
	mutex_unlock(&csv->sp_lock);

	return ret;
}

static void csv_vm_destroy(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_vcpu *vcpu;
	struct list_head *smr_head = &csv->smr_list;
	struct shared_page *sp;
	struct rb_node *node;
	unsigned long i = 0;
	enum csv_smr_source source = get_csv_smr_source();

	if (csv3_guest(kvm)) {
		mutex_lock(&csv->sp_lock);
		while ((node = rb_first(&csv->sp_mgr.root))) {
			sp = rb_entry(node, struct shared_page, node);
			/* Remove shared page entry from the manager tree */
			rb_erase(&sp->node, &csv->sp_mgr.root);
			/* Update shared page statistics */
			csv->sp_mgr.count--;
			csv->sp_mgr.nr_pages -= 1UL << sp->order;
			update_csv_share_mem(sp->track_page, false);
			/* Putback the tracked page to system */
			if (page_maybe_dma_pinned(sp->track_page))
				unpin_user_page(sp->track_page);
			else
				pr_err_ratelimited("%s: the track_page was not pinned\n",
						   __func__);
			free_shared_page_entry(csv, sp);

			cond_resched();
		}
		mutex_unlock(&csv->sp_lock);

		if (csv->sp_mgr.count || csv->sp_mgr.nr_pages)
			pr_err("%s: SP_MGR_ERR: track fault, cnt:%lld nr_pages:0x%lx\n",
			       __func__, csv->sp_mgr.count, csv->sp_mgr.nr_pages);

		kmem_cache_destroy(csv->sp_slab);
		csv->sp_slab = NULL;

		kvm_for_each_vcpu(i, vcpu, kvm) {
			struct vcpu_svm *svm = to_svm(vcpu);

			svm->vmcb_pa = __sme_pa(svm->vmcb);
		}
	}

	if (likely(csv_x86_ops.vm_destroy))
		csv_x86_ops.vm_destroy(kvm);

	if (!csv3_guest(kvm))
		return;

	/* free secure memory region */
	if (!list_empty(smr_head))
		csv3_free_smr_list(kvm);

	/* Free hugetlb if CSV3 private memory is allocated from 1G hugetlb */
	if (source == USE_HUGETLB)
		csv3_free_1G_hugetlb_pages(kvm);

#ifdef CONFIG_SYSFS
	atomic_long_sub(csv->npt_size, &csv3_npt_size);
	atomic_long_sub(csv->pri_mem, &csv3_pri_mem);
#endif
}

static int csv3_handle_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa,
				  u32 error_code)
{
	gfn_t gfn = gpa_to_gfn(gpa);
	struct kvm_memory_slot *slot = gfn_to_memslot(vcpu->kvm, gfn);
	int ret;
	int r = -EIO;

	if (kvm_is_visible_memslot(slot))
		ret = csv3_page_fault(vcpu, slot, gfn, error_code);
	else
		ret = csv3_mmio_page_fault(vcpu, gpa, error_code);

	if (!ret)
		r = 1;

	return r;
}

static int csv_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 exit_code = svm->vmcb->control.exit_code;
	int ret = -EIO;

	/*
	 * NPF for csv3 is dedicated.
	 */
	if (csv3_guest(vcpu->kvm) && exit_code == SVM_EXIT_NPF) {
		gpa_t gpa = __sme_clr(svm->vmcb->control.exit_info_2);
		u64 error_code = svm->vmcb->control.exit_info_1;

		ret = csv3_handle_page_fault(vcpu, gpa, error_code);
	} else {
		if (likely(csv_x86_ops.handle_exit))
			ret = csv_x86_ops.handle_exit(vcpu, exit_fastpath);
	}

	return ret;
}

static void csv_guest_memory_reclaimed(struct kvm *kvm)
{
	if (!csv3_guest(kvm)) {
		if (likely(csv_x86_ops.guest_memory_reclaimed))
			csv_x86_ops.guest_memory_reclaimed(kvm);
	}
}

static int csv3_handle_memory(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_handle_memory params;
	int r = -EINVAL;

	if (!csv3_guest(kvm) ||
	    !(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_SP_MGR))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	switch (params.opcode) {
	case KVM_CSV3_RELEASE_SHARED_MEMORY:
		r = csv_release_shared_memory(kvm, &params);
		break;
	case KVM_CSV3_GET_SHARED_MEMORY:
		r = csv_get_shared_memory(kvm, &params);
		break;
	default:
		goto out;
	}

	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params,
			 sizeof(params)))
		return -EFAULT;

out:
	return r;
};

static int csv_mem_enc_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_sev_cmd sev_cmd;
	int r;

	if (!hygon_kvm_hooks.sev_hooks_installed ||
	    !(*hygon_kvm_hooks.sev_enabled))
		return -ENOTTY;

	if (!argp)
		return 0;

	if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (sev_cmd.id) {
	case KVM_CSV_COMMAND_BATCH:
		mutex_lock(&csv_cmd_batch_mutex);
		r = csv_command_batch(kvm, &sev_cmd);
		mutex_unlock(&csv_cmd_batch_mutex);
		break;
	case KVM_CSV3_INIT:
		if (!csv3_enabled) {
			r = -ENOTTY;
			goto out;
		}
		r = csv3_guest_init(kvm, &sev_cmd);
		break;
	case KVM_CSV3_LAUNCH_ENCRYPT_DATA:
		r = csv3_launch_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_LAUNCH_ENCRYPT_VMCB:
		r = csv3_launch_encrypt_vmcb(kvm, &sev_cmd);
		break;
	case KVM_CSV3_LAUNCH_FINISH_EX:
		r = csv3_launch_finish_ex(kvm, &sev_cmd);
		break;
	case KVM_CSV3_SEND_ENCRYPT_DATA:
		r = csv3_send_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_SEND_ENCRYPT_CONTEXT:
		r = csv3_send_encrypt_context(kvm, &sev_cmd);
		break;
	case KVM_CSV3_RECEIVE_ENCRYPT_DATA:
		r = csv3_receive_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_RECEIVE_ENCRYPT_CONTEXT:
		r = csv3_receive_encrypt_context(kvm, &sev_cmd);
		break;
	case KVM_CSV3_HANDLE_MEMORY:
		r = csv3_handle_memory(kvm, &sev_cmd);
		break;
	case KVM_CSV3_SET_GUEST_PRIVATE_MEMORY:
		r = csv3_set_guest_private_memory(kvm, &sev_cmd);
		break;
	default:
		/*
		 * If the command is compatible between CSV and SEV, the
		 * native implementation of the driver is invoked.
		 * Release the mutex before calling the native ioctl function
		 * because it will acquires the mutex.
		 */
		mutex_unlock(&kvm->lock);
		if (likely(csv_x86_ops.mem_enc_op))
			return csv_x86_ops.mem_enc_op(kvm, argp);
	}

	if (copy_to_user(argp, &sev_cmd, sizeof(struct kvm_sev_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

/**
 * When userspace recognize these extensions, it's suggested that the userspace
 * to enable these extensions through KVM_ENABLE_CAP, then both the userspace
 * and KVM utilise these extensions.
 */
static int csv_get_hygon_coco_extension(struct kvm *kvm)
{
	struct kvm_csv_info *csv;
	size_t len = sizeof(uint32_t);
	int ret = 0;

	if (!kvm || !csv3_guest(kvm))
		return 0;

	csv = &to_kvm_svm_csv(kvm)->csv_info;

	if (csv->fw_ext_valid == false) {
		ret = csv_get_extension_info(&csv->fw_ext, &len);

		if (ret == -ENODEV) {
			pr_err("Unable to interact with CSV firmware!\n");
			return 0;
		} else if (ret == -EINVAL) {
			pr_err("Need %ld bytes to record fw extension!\n", len);
			return 0;
		}

		csv->fw_ext_valid = true;
	}

	/* The kvm_ext field of kvm_csv_info is filled in only if the fw_ext
	 * field of kvm_csv_info is valid.
	 */
	if (csv->kvm_ext_valid == false) {
		if (csv3_guest(kvm)) {
			csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_SET_PRIV_MEM;
			if (csv->fw_ext & CSV_EXT_CSV3_MULT_LUP_DATA)
				csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_MULT_LUP_DATA;
			if (csv->fw_ext & CSV_EXT_CSV3_LFINISH_EX)
				csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_LFINISH_EX;
			csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_SP_MGR;
		}
		csv->kvm_ext_valid = true;
	}

	/* Return extension info only if both fw_ext and kvm_ext fields of
	 * kvm_csv_info are valid.
	 */
	pr_debug("%s: fw_ext=%#x kvm_ext=%#x\n",
		 __func__, csv->fw_ext, csv->kvm_ext);
	return (int)csv->kvm_ext;
}

/**
 * Return 0 means KVM accept the negotiation from userspace. Both the
 * userspace and KVM should not utilise extensions if failed to negotiate.
 */
static int csv_enable_hygon_coco_extension(struct kvm *kvm, u32 arg)
{
	struct kvm_csv_info *csv;

	if (!kvm)
		return -EINVAL;

	csv = &to_kvm_svm_csv(kvm)->csv_info;

	/* Negotiation is accepted only if both the fw_ext and kvm_ext fields
	 * of kvm_csv_info are valid and the virtual machine is a CSV3 guest.
	 */
	if (csv->fw_ext_valid && csv->kvm_ext_valid && csv3_guest(kvm)) {
		csv->inuse_ext = csv->kvm_ext & arg;
		pr_debug("%s: inuse_ext=%#x\n", __func__, csv->inuse_ext);
		return csv->inuse_ext;
	}

	/* Userspace should not utilise the extensions */
	return -EINVAL;
}

void __init csv_hardware_setup(unsigned int max_csv_asid)
{
	/*
	 * Allocate a memory pool to speed up live migration of
	 * the CSV/CSV2 guests. If the allocation fails, no
	 * acceleration is performed at live migration.
	 */
	csv_alloc_trans_mempool();

	/* CSV3 depends on X86_FEATURE_CSV3 */
	if (boot_cpu_has(X86_FEATURE_SEV_ES) && boot_cpu_has(X86_FEATURE_CSV3))
		csv3_enabled = true;
	else
		csv3_enabled = false;

	pr_info("CSV3 %s (ASIDs 1 - %u)\n",
		csv3_enabled ? "enabled" : "disabled", max_csv_asid);
}

void csv_hardware_unsetup(void)
{
	/* Free the memory that allocated in csv_hardware_setup(). */
	csv_free_trans_mempool();
}

void csv_exit(void)
{
}

void __init csv_init(struct kvm_x86_ops *ops)
{
	/*
	 * Hygon CSV is indicated by X86_FEATURE_SEV, return directly if CSV
	 * is unsupported.
	 */
	if (!boot_cpu_has(X86_FEATURE_SEV))
		return;

	memcpy(&csv_x86_ops, ops, sizeof(struct kvm_x86_ops));

	ops->vm_size = sizeof(struct kvm_svm_csv);
	ops->mem_enc_op = csv_mem_enc_ioctl;
	ops->vm_attestation = csv_vm_attestation;
	ops->get_hygon_coco_extension = csv_get_hygon_coco_extension;
	ops->enable_hygon_coco_extension = csv_enable_hygon_coco_extension;

	if (boot_cpu_has(X86_FEATURE_SEV_ES) && boot_cpu_has(X86_FEATURE_CSV3)) {
		ops->vm_destroy = csv_vm_destroy;
		ops->handle_exit = csv_handle_exit;
		ops->guest_memory_reclaimed = csv_guest_memory_reclaimed;
	}
}
