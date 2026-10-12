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
#include <asm/cacheflush.h>
#include <asm/csv.h>
#include <asm/fpu/api.h>
#include "kvm_cache_regs.h"
#include "svm.h"
#include "csv.h"
#include "x86.h"

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

struct kvm_csv_info {
	struct kvm_sev_info *sev;

	bool csv3_active;	/* CSV3 enabled guest */

	struct list_head smr_list; /* List of guest secure memory regions */
	unsigned long nodemask; /* Nodemask where CSV3 guest's memory resides */
};

struct kvm_svm_csv {
	struct kvm_svm kvm_svm;
	struct kvm_csv_info csv_info;
};

struct secure_memory_region {
	struct list_head list;
	u64 npages;
	u64 hpa;
};

static inline struct kvm_svm_csv *to_kvm_svm_csv(struct kvm *kvm)
{
	return (struct kvm_svm_csv *)container_of(kvm, struct kvm_svm, kvm);
}

static bool csv3_guest(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	return sev_es_guest(kvm) && csv->csv3_active;
}

static int csv3_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_init_data params;

	if (unlikely(csv->csv3_active))
		return -EINVAL;

	if (unlikely(!sev->es_active))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	csv->csv3_active = true;
	csv->sev = sev;
	csv->nodemask = (unsigned long)params.nodemask;

	return 0;
}

static int csv3_set_guest_private_memory(struct kvm *kvm)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;
	struct secure_memory_region *smr;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_set_guest_private_memory *set_guest_private_memory;
	struct csv3_data_memory_region *regions;
	nodemask_t nodemask;
	nodemask_t *nodemask_ptr;

	LIST_HEAD(tmp_list);
	struct list_head *pos, *q;
	u32 i = 0, count = 0, remainder;
	int ret = 0, error;
	u64 size = 0, nr_smr = 0, nr_pages = 0;
	u32 smr_entry_shift;

	unsigned int flags = FOLL_HWPOISON;
	int npages;
	struct page *page;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	nodes_clear(nodemask);
	for_each_set_bit(i, &csv->nodemask, BITS_PER_LONG)
		if (i < MAX_NUMNODES)
			node_set(i, nodemask);

	nodemask_ptr = csv->nodemask ? &nodemask : &node_online_map;

	set_guest_private_memory = kzalloc(sizeof(*set_guest_private_memory),
					GFP_KERNEL_ACCOUNT);
	if (!set_guest_private_memory)
		return -ENOMEM;

	regions = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!regions) {
		kfree(set_guest_private_memory);
		return -ENOMEM;
	}

	/* Get guest secure memory size */
	kvm_for_each_memslot(memslot, slots) {
		npages = get_user_pages_unlocked(memslot->userspace_addr, 1,
						&page, flags);
		if (npages != 1)
			continue;

		nr_pages += memslot->npages;

		put_page(page);
	}

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
	size = ALIGN((nr_pages << PAGE_SHIFT), 1UL << smr_entry_shift) +
		ALIGN(nr_pages * 9, 1UL << smr_entry_shift);
	nr_smr = size >> smr_entry_shift;
	remainder = nr_smr;
	for (i = 0; i < nr_smr; i++) {
		smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
		if (!smr) {
			ret = -ENOMEM;
			goto e_free_smr;
		}

		smr->hpa = csv_alloc_from_contiguous((1UL << smr_entry_shift),
						nodemask_ptr,
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
						set_guest_private_memory, &error);
			if (ret)
				goto e_free_smr;

			memset(regions, 0, PAGE_SIZE);
			remainder -= count;
			count = 0;
		}
	}

	list_splice(&tmp_list, &csv->smr_list);

	goto done;

e_free_smr:
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

static int csv3_launch_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
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

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params))) {
		ret = -EFAULT;
		goto exit;
	}

	if ((params.len & ~PAGE_MASK) || !params.len || !params.uaddr) {
		ret = -EINVAL;
		goto exit;
	}

	/* Allocate all the guest memory from CMA */
	ret = csv3_set_guest_private_memory(kvm);
	if (ret)
		goto exit;

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

static int csv3_sync_vmsa(struct vcpu_svm *svm)
{
	struct vmcb_save_area *save = &svm->vmcb->save;

	/* Check some debug related fields before encrypting the VMSA */
	if (svm->vcpu.guest_debug || (save->dr7 & ~DR7_FIXED_1))
		return -EINVAL;

	/* Sync registgers per spec. */
	save->rax = svm->vcpu.arch.regs[VCPU_REGS_RAX];
	save->rdx = svm->vcpu.arch.regs[VCPU_REGS_RDX];
	save->rip = svm->vcpu.arch.regs[VCPU_REGS_RIP];
	save->xcr0 = svm->vcpu.arch.xcr0;
	save->xss  = svm->vcpu.arch.ia32_xss;

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

	ops->mem_enc_op = csv_mem_enc_ioctl;
	ops->vm_attestation = csv_vm_attestation;

	if (boot_cpu_has(X86_FEATURE_SEV_ES) && boot_cpu_has(X86_FEATURE_CSV3))
		ops->vm_size = sizeof(struct kvm_svm_csv);
}
