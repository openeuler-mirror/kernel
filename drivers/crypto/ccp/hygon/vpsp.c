// SPDX-License-Identifier: GPL-2.0-only
/*
 * PSP virtualization
 *
 * Copyright (c) 2023, HYGON CORPORATION. All rights reserved.
 *     Author: Ge Yang <yangge@hygon.cn>
 *
 */

#include <linux/kvm_types.h>
#include <linux/slab.h>
#include <linux/kvm_host.h>
#include <linux/psp-sev.h>
#include <linux/psp.h>
#include <linux/psp-hygon.h>
#include <asm/cpuid.h>
#include <linux/bsearch.h>
#include <linux/sort.h>
#include <linux/bitfield.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>

#include "psp-dev.h"
#include "csv-dev.h"
#include "vpsp.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "vpsp: " fmt
#define VTKM_VM_BIND	0x904

static int vpsp_backup_key(struct key_img_ctl *ctl);
static int vpsp_restore_key(struct key_img_ctl *ctl);
static int vpsp_backup_cmd_ctx(struct cmd_ctx_ctl *ctl);
static int vpsp_restore_cmd_ctx(struct cmd_ctx_ctl *ctl);

/*
 * The file mainly implements the base execution logic of virtual PSP in kernel mode,
 *	which mainly includes:
 *	(1) Preprocess the guest data in the host kernel
 *	(2) The command that has been converted will interact with the channel of the
 *		psp through the driver and try to obtain the execution result
 *	(3) The executed command data is recovered, and then returned to the VM
 *
 * The primary implementation logic of virtual PSP in kernel mode
 * call trace:
 * guest command(vmmcall, KVM_HC_PSP_COPY_FORWARD_OP)
 *		   |
 *	kvm_pv_psp_copy_op---->	| -> kvm_pv_psp_cmd_pre_op
 *				|
 *				| -> vpsp_try_do_cmd/vpsp_try_get_result
 *				|	|<=> psp device driver
 *				|
 *				|
 *				|-> kvm_pv_psp_cmd_post_op
 *
 * guest command(vmmcall, KVM_HC_PSP_FORWARD_OP)
 *		   |
 *	kvm_pv_psp_forward_op-> |-> vpsp_try_do_cmd/vpsp_try_get_result
 *					|<=> psp device driver
 */

/**
 * used to locate the command context,
 * when the guest enters the host via vmmcall
 */
DEFINE_HASHTABLE(vpsp_cmd_ctx_table, 11);
DEFINE_RWLOCK(table_rwlock);
static struct vpsp_cmd_ctx *vpsp_ring_cmd_ctx_lookup[CSV_COMMAND_PRIORITY_NUM]
				[CSV_RING_BUFFER_SIZE / CSV_RING_BUFFER_ESIZE];

static struct vpsp_cmd_ctx *vpsp_hashtable_find_cmd_ctx(gpa_t key1, pid_t key2)
{
	struct vpsp_cmd_ctx *entry = NULL;
	bool is_found = false;

	read_lock(&table_rwlock);
	hash_for_each_possible(vpsp_cmd_ctx_table, entry, node, key1) {
		if (entry->key1 == key1 && entry->key2 == key2) {
			is_found = true;
			break;
		}
	}
	read_unlock(&table_rwlock);
	if (!is_found)
		entry = NULL;

	return entry;
}

static int vpsp_hashtable_save_cmd_ctx_by_pid(pid_t pid, struct vpsp_cmd_ctx *ctx[], uint32_t *nums)
{
	struct vpsp_cmd_ctx *entry = NULL;
	struct hlist_node *tmp;
	int i;

	if (!nums)
		return -EINVAL;
	*nums = 0;

	read_lock(&table_rwlock);
	// Allowed entries to be deleted during traversal
	hash_for_each_safe(vpsp_cmd_ctx_table, i, tmp, entry, node) {
		if (entry->key2 == pid) {
			if (ctx)
				ctx[*nums] = entry;
			++(*nums);
		}
	}
	read_unlock(&table_rwlock);

	return 0;
}

static void vpsp_hashtable_add_cmd_ctx(struct vpsp_cmd_ctx *ctx)
{
	struct vpsp_cmd_ctx *entry = NULL;

	write_lock(&table_rwlock);
	hash_for_each_possible(vpsp_cmd_ctx_table, entry, node, ctx->key1) {
		if (entry->key1 == ctx->key1 &&
				entry->key2 == ctx->key2) {
			vpsp_cmd_ctx_obj_put(entry, true);
			break;
		}
	}
	hash_add(vpsp_cmd_ctx_table, &ctx->node, ctx->key1);
	write_unlock(&table_rwlock);

	vpsp_cmd_ctx_obj_get(ctx);

	pr_debug("add cmd ctx gpa 0x%llx pid %d\n", ctx->key1, ctx->key2);
}

static void vpsp_hashtable_remove_cmd_ctx(struct vpsp_cmd_ctx *ctx)
{
	write_lock(&table_rwlock);
	hash_del(&ctx->node);
	write_unlock(&table_rwlock);

	pr_debug("remove cmd ctx gpa 0x%llx pid %d\n", ctx->key1, ctx->key2);
	vpsp_cmd_ctx_obj_put(ctx, false);
}

/**
 * Create a vpsp_cmd_ctx object and insert it into the
 * vpsp_cmd_ctx_table hash table.
 *
 * @hkey: The key value for the hash table vpsp_cmd_ctx_table
 *
 * Return: the address of the vpsp_cmd_ctx object
 *	   if created successfully, otherwise returns NULL
 */
static struct vpsp_cmd_ctx *vpsp_cmd_ctx_create(gpa_t key1, pid_t key2)
{
	struct vpsp_cmd_ctx *cmd_ctx = kmem_cache_zalloc(vpsp_cmd_ctx_slab, GFP_KERNEL);

	if (cmd_ctx) {
		/**
		 * According to the implementation of refcount,
		 * the initial value must be greater than 0.
		 */
		refcount_set(&cmd_ctx->ref, 1);
		cmd_ctx->statval = PSP_CMD_STATUS_RUNNING;
		cmd_ctx->key1 = key1;
		cmd_ctx->key2 = key2;
		vpsp_hashtable_add_cmd_ctx(cmd_ctx);
	}
	return cmd_ctx;
}

/**
 * Destroys the specified vpsp_cmd_ctx object,
 * indicating it will no longer be accessed.
 *
 * But does not necessarily free the cmd_ctx memory immediately,
 * only additional to perform decrement refcount.
 *
 * Actual memory release occurs when the refcount drops to 0,
 * which may happen during the psp_worker_handler or
 * vpsp_cmd_ctx_destroy process.
 *
 * @cmd_ctx: the vpsp_cmd_ctx object
 */
static void vpsp_cmd_ctx_destroy(struct vpsp_cmd_ctx *cmd_ctx)
{
	if (!cmd_ctx)
		return;

	if (cmd_ctx->statval == VPSP_RUNNING)
		pr_warn("destroy cmd_ctx is running, gpa 0x%llx, pid %d",
			cmd_ctx->key1, cmd_ctx->key2);

	/**
	 * The initial refcount is 1,
	 * need to additional decrement a refcount.
	 */
	vpsp_cmd_ctx_obj_put(cmd_ctx, false);
	vpsp_hashtable_remove_cmd_ctx(cmd_ctx);
}

void vpsp_cmd_ctx_obj_get(struct vpsp_cmd_ctx *cmd_ctx)
{
	refcount_inc(&cmd_ctx->ref);
}

void vpsp_cmd_ctx_obj_put(struct vpsp_cmd_ctx *cmd_ctx, bool force)
{
	do {
		if (refcount_dec_and_test(&cmd_ctx->ref)) {
			kfree(cmd_ctx->data);
			memset(cmd_ctx, 0, sizeof(*cmd_ctx));
			kmem_cache_free(vpsp_cmd_ctx_slab, cmd_ctx);
			force = false;
		}
	} while (force);
}

struct psp_cmdresp_head {
	uint32_t buf_size;
	uint32_t cmdresp_size;
	uint32_t cmdresp_code;
} __packed;

static int check_gpa_range(struct vpsp_dev_ctx *vpsp_ctx, gpa_t addr, uint32_t size)
{
	if (!vpsp_ctx || !addr)
		return -EFAULT;

	if (addr >= vpsp_ctx->gpa_start && (addr + size) <= vpsp_ctx->gpa_end)
		return 0;
	return -EFAULT;
}

static int check_psp_mem_range(struct vpsp_dev_ctx *vpsp_ctx,
			void *data, uint32_t size)
{
	if ((((uintptr_t)data + size - 1) & ~PSP_2MB_MASK) !=
			((uintptr_t)data & ~PSP_2MB_MASK)) {
		pr_err("data %llx, size %d crossing 2MB\n", (u64)data, size);
		return -EFAULT;
	}

	if (vpsp_ctx)
		return check_gpa_range(vpsp_ctx, (gpa_t)data, size);

	return 0;
}

/**
 * Copy Guest data to the Host kernel buffer
 * and allocate a cmd_ctx to insert into the vpsp_cmd_ctx_table.
 */
static int kvm_pv_psp_cmd_pre_op(struct kvm_vpsp *vpsp, gpa_t data_gpa,
		struct vpsp_cmd_ctx **cmd_ctx)
{
	int ret = 0;
	void *data = NULL;
	struct psp_cmdresp_head psp_head;
	uint32_t data_size;

	if (unlikely(!cmd_ctx))
		return -EFAULT;
	*cmd_ctx = NULL;

	if (unlikely(vpsp->read_guest(vpsp->kvm, data_gpa, &psp_head,
					sizeof(struct psp_cmdresp_head))))
		return -EFAULT;

	data_size = psp_head.buf_size;
	if (check_psp_mem_range(NULL, (void *)data_gpa, data_size))
		return -EFAULT;

	data = kzalloc(data_size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	*cmd_ctx = vpsp_cmd_ctx_create(data_gpa, vpsp->kvm->userspace_pid);
	if (!(*cmd_ctx)) {
		ret = -EFAULT;
		goto end;
	}

	if (unlikely(vpsp->read_guest(vpsp->kvm, data_gpa, data, data_size))) {
		ret = -EFAULT;
		goto end;
	}

	(*cmd_ctx)->data = data;
	(*cmd_ctx)->data_size = data_size;
end:
	if (ret) {
		vpsp_cmd_ctx_destroy(*cmd_ctx);
		kfree(data);
	}
	return ret;
}

static int kvm_pv_psp_cmd_post_op(struct kvm_vpsp *vpsp, gpa_t data_gpa,
				struct vpsp_cmd_ctx *cmd_ctx)
{
	int ret = 0;

	/* restore cmdresp's buffer from context */
	if (unlikely(vpsp->write_guest(vpsp->kvm, data_gpa, cmd_ctx->data,
					cmd_ctx->data_size))) {
		pr_err("[%s]: kvm_write_guest for cmdresp data failed\n",
			__func__);
		ret = -EFAULT;
		goto end;
	}
end:
	vpsp_cmd_ctx_destroy(cmd_ctx);
	return ret;
}

static int cmd_type_is_tkm(int cmd)
{
	if (cmd >= TKM_CMD_ID_MIN && cmd <= TKM_CMD_ID_MAX)
		return 1;
	return 0;
}

static int cmd_type_is_allowed(int cmd)
{
	if (cmd >= TKM_PSP_CMDID_OFFSET && cmd <= TKM_CMD_ID_MAX)
		return 1;
	return 0;
}

struct psp_cmdresp_vtkm_vm_bind {
	struct psp_cmdresp_head head;
	uint16_t vid;
	uint32_t vm_handle;
	uint8_t reserved[46];
} __packed;

static int kvm_bind_vtkm(uint32_t vm_handle, uint32_t cmd_id, uint32_t vid, uint32_t *pret)
{
	int ret = 0;
	struct psp_cmdresp_vtkm_vm_bind *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->head.buf_size = sizeof(*data);
	data->head.cmdresp_size = sizeof(*data);
	data->head.cmdresp_code = VTKM_VM_BIND;
	data->vid = vid;
	data->vm_handle = vm_handle;

	ret = psp_do_cmd(cmd_id, data, pret);
	if (ret == -EIO)
		ret = 0;

	kfree(data);
	return ret;
}

static unsigned long vpsp_get_me_mask(void)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned long me_mask;

#define AMD_SME_BIT	BIT(0)
#define AMD_SEV_BIT	BIT(1)
	/*
	 * Check for the SME/SEV feature:
	 *   CPUID Fn8000_001F[EAX]
	 *   - Bit 0 - Secure Memory Encryption support
	 *   - Bit 1 - Secure Encrypted Virtualization support
	 *   CPUID Fn8000_001F[EBX]
	 *   - Bits 5:0 - Pagetable bit position used to indicate encryption
	 */
	eax = 0x8000001f;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	/* Check whether SEV or SME is supported */
	if (!(eax & (AMD_SEV_BIT | AMD_SME_BIT)))
		return 0;

	me_mask = 1UL << (ebx & 0x3f);
	return me_mask;
}

static phys_addr_t gpa_to_hpa(struct kvm_vpsp *vpsp, unsigned long data_gpa)
{
	phys_addr_t hpa = 0;
	unsigned long pfn = vpsp->gfn_to_pfn(vpsp->kvm, data_gpa >> PAGE_SHIFT);
	unsigned long me_mask = sme_get_me_mask();
	struct page *page;

	if (me_mask == 0 && vpsp->is_csv_guest)
		me_mask = vpsp_get_me_mask();

	if (!is_error_pfn(pfn))
		hpa = ((pfn << PAGE_SHIFT) + offset_in_page(data_gpa)) | me_mask;
	else {
		pr_err("[%s] pfn: %lx is invalid, gpa %lx",
				__func__, pfn, data_gpa);
		return 0;
	}

	/*
	 * Using gfn_to_pfn causes the refcount to increment
	 * atomically by one, which needs to be released.
	 */
	page = pfn_to_page(pfn);
	if (PageCompound(page))
		page = compound_head(page);

	put_page(page);

	pr_debug("gpa %lx, hpa %llx\n", data_gpa, hpa);
	return hpa;

}

static int check_cmd_forward_op_permission(struct kvm_vpsp *vpsp, struct vpsp_dev_ctx *vpsp_ctx,
				uint64_t data, uint32_t cmd)
{
	int ret;
	struct vpsp_cmd *vcmd = (struct vpsp_cmd *)&cmd;
	struct psp_cmdresp_head psp_head;

	if (!cmd_type_is_allowed(vcmd->cmd_id)) {
		pr_err("[%s]: unsupported cmd id %x\n", __func__, vcmd->cmd_id);
		return -EINVAL;
	}

	if (vpsp->is_csv_guest) {
		/**
		 * If the gpa address range exists,
		 * it means there must be a legal vid
		 */
		if (!vpsp_ctx || !vpsp_ctx->gpa_start || !vpsp_ctx->gpa_end) {
			pr_err("[%s]: No set gpa range or vid in csv guest\n", __func__);
			return -EPERM;
		}

		ret = check_psp_mem_range(vpsp_ctx, (void *)data, 0);
		if (ret)
			return -EFAULT;
	} else {
		if (!vpsp_ctx && cmd_type_is_tkm(vcmd->cmd_id)
				&& !vpsp_get_default_vid_permission()) {
			pr_err("[%s]: not allowed tkm command without vid\n", __func__);
			return -EPERM;
		}

		// the 'data' is gpa address
		if (unlikely(vpsp->read_guest(vpsp->kvm, data, &psp_head,
					sizeof(struct psp_cmdresp_head))))
			return -EFAULT;

		ret = check_psp_mem_range(vpsp_ctx, (void *)data, psp_head.buf_size);
		if (ret)
			return -EFAULT;
	}
	return 0;
}

static int
check_cmd_copy_forward_op_permission(struct kvm_vpsp *vpsp,
				struct vpsp_dev_ctx *vpsp_ctx,
				uint64_t data, uint32_t cmd)
{
	int ret = 0;
	struct vpsp_cmd *vcmd = (struct vpsp_cmd *)&cmd;

	if (!cmd_type_is_allowed(vcmd->cmd_id)) {
		pr_err("[%s]: unsupported cmd id %x\n", __func__, vcmd->cmd_id);
		return -EINVAL;
	}

	if (vpsp->is_csv_guest) {
		pr_err("[%s]: unsupported run on csv guest\n", __func__);
		ret = -EPERM;
	} else {
		if (!vpsp_ctx && cmd_type_is_tkm(vcmd->cmd_id)
				&& !vpsp_get_default_vid_permission()) {
			pr_err("[%s]: not allowed tkm command without vid\n", __func__);
			ret = -EPERM;
		}
	}
	return ret;
}

static int vpsp_try_bind_vtkm(struct kvm_vpsp *vpsp, struct vpsp_dev_ctx *vpsp_ctx,
				uint32_t cmd, uint32_t *psp_ret)
{
	int ret;
	struct vpsp_cmd *vcmd = (struct vpsp_cmd *)&cmd;

	/**
	 * The vpsp_ctx->locked ensures that kvm_bind_vtkm is
	 * only executed once.
	 *
	 * otherwise error code -62 will be thrown.
	 */
	while (vpsp_ctx && !vpsp_ctx->vm_is_bound && vpsp->is_csv_guest) {
		if (atomic64_xchg(&vpsp_ctx->locked, 1)) {
			cond_resched();
			continue;
		}

		ret = kvm_bind_vtkm(vpsp->vm_handle, vcmd->cmd_id,
					vpsp_ctx->vid, psp_ret);
		if (ret || *psp_ret) {
			pr_err("[%s] kvm bind vtkm failed with ret: %d, pspret: %d\n",
				__func__, ret, *psp_ret);
			atomic64_xchg(&vpsp_ctx->locked, 0);
			return ret;
		}
		vpsp_ctx->vm_is_bound = 1;
		atomic64_xchg(&vpsp_ctx->locked, 0);
	}
	return 0;
}

/**
 * @brief Directly convert the gpa address into hpa and forward it to PSP,
 *	  It is another form of kvm_pv_psp_copy_op, mainly used for csv VMs.
 *
 * @param vpsp points to kvm related data
 * @param cmd psp cmd id, bit 31 indicates queue priority
 * @param data_gpa guest physical address of input data
 * @param psp_ret indicates Asynchronous context information
 *
 * Since the csv guest memory cannot be read or written directly,
 * the shared asynchronous context information is shared through psp_ret and return value.
 */
int kvm_pv_psp_forward_op(struct kvm_vpsp *vpsp, uint32_t cmd,
			gpa_t data_gpa, uint32_t psp_ret)
{
	int ret;
	uint32_t vid = 0;
	struct vpsp_ret psp_async = {0};
	struct vpsp_dev_ctx *vpsp_dev_ctx = NULL;
	struct vpsp_cmd_ctx *cmd_ctx = NULL;
	phys_addr_t hpa;

	vpsp_get_dev_ctx(&vpsp_dev_ctx, vpsp->kvm->userspace_pid);

	ret = check_cmd_forward_op_permission(vpsp, vpsp_dev_ctx, data_gpa, cmd);
	if (unlikely(ret)) {
		pr_err("directly operation not allowed\n");
		goto end;
	}

	ret = vpsp_try_bind_vtkm(vpsp, vpsp_dev_ctx, cmd, (uint32_t *)&psp_async);
	if (unlikely(ret || *(uint32_t *)&psp_async)) {
		pr_err("try to bind vtkm failed (ret %x, psp_async %x)\n",
			ret, *(uint32_t *)&psp_async);
		goto end;
	}

	if (vpsp_dev_ctx)
		vid = vpsp_dev_ctx->vid;

	*((uint32_t *)&psp_async) = psp_ret;

	switch (psp_async.status) {
	case VPSP_INIT:
		cmd_ctx = vpsp_cmd_ctx_create(data_gpa,
			vpsp->kvm->userspace_pid);
		if (unlikely(!cmd_ctx)) {
			ret = -ENOMEM;
			goto end;
		}

		hpa = gpa_to_hpa(vpsp, data_gpa);
		if (unlikely(!hpa)) {
			ret = -EFAULT;
			goto end;
		}
		/* try to send command to the device for execution*/
		ret = vpsp_try_do_cmd(cmd, PUT_PSP_VID(hpa, vid), cmd_ctx, &psp_async);
		if (unlikely(ret)) {
			pr_err("[%s]: vpsp_try_do_cmd failed\n", __func__);
			goto end;
		}
		break;

	case VPSP_RUNNING:
		cmd_ctx = vpsp_hashtable_find_cmd_ctx(data_gpa, vpsp->kvm->userspace_pid);
		if (unlikely(!cmd_ctx)) {
			pr_err("[%s]: vpsp_hashtable_find_cmd_ctx failed, data_gpa %llx\n",
				__func__, data_gpa);
			ret = -EFAULT;
			goto end;
		}

		/* try to get the execution result from ringbuffer*/
		ret = vpsp_try_get_result(cmd_ctx, &psp_async);
		if (unlikely(ret)) {
			pr_err("[%s]: vpsp_try_get_result failed\n", __func__);
			goto end;
		}
		break;

	default:
		pr_err("[%s]: invalid command status\n", __func__);
		break;
	}

	if (psp_async.status == VPSP_FINISH)
		vpsp_cmd_ctx_destroy(cmd_ctx);

end:
	/**
	 * In order to indicate both system errors and PSP errors,
	 * the psp_async.pret field needs to be reused.
	 */
	psp_async.format = VPSP_RET_PSP_FORMAT;
	if (ret) {
		psp_async.format = VPSP_RET_SYS_FORMAT;
		if (ret > 0)
			ret = -ret;
		psp_async.pret = (uint16_t)ret;
		psp_async.status = VPSP_FINISH;
		vpsp_cmd_ctx_destroy(cmd_ctx);
	}
	return *((int *)&psp_async);
}
EXPORT_SYMBOL_GPL(kvm_pv_psp_forward_op);

/**
 * @brief copy data in gpa to host memory and send it to psp for processing.
 *
 * @param vpsp points to kvm related data
 * @param cmd psp cmd id, bit 31 indicates queue priority
 * @param data_gpa guest physical address of input data
 * @param psp_ret_gpa guest physical address of psp_ret
 */
int kvm_pv_psp_copy_forward_op(struct kvm_vpsp *vpsp, int cmd, gpa_t data_gpa, gpa_t psp_ret_gpa)
{
	int ret = 0;
	struct vpsp_ret psp_ret = {0};
	struct vpsp_cmd_ctx *cmd_ctx = NULL;
	struct vpsp_dev_ctx *vpsp_dev_ctx = NULL;
	phys_addr_t data_paddr = 0;
	uint32_t vid = 0;

	vpsp_get_dev_ctx(&vpsp_dev_ctx, vpsp->kvm->userspace_pid);

	ret = check_cmd_copy_forward_op_permission(vpsp, vpsp_dev_ctx, data_gpa, cmd);
	if (unlikely(ret)) {
		pr_err("copy operation not allowed\n");
		return -EPERM;
	}

	if (vpsp_dev_ctx)
		vid = vpsp_dev_ctx->vid;

	if (unlikely(vpsp->read_guest(vpsp->kvm, psp_ret_gpa, &psp_ret,
					sizeof(psp_ret))))
		return -EFAULT;

	switch (psp_ret.status) {
	case VPSP_INIT:
		/* copy data from guest */
		ret = kvm_pv_psp_cmd_pre_op(vpsp, data_gpa, &cmd_ctx);
		if (unlikely(ret)) {
			pr_err("[%s]: kvm_pv_psp_cmd_pre_op failed\n",
					__func__);
			ret = -EFAULT;
			goto end;
		}

		data_paddr = PUT_PSP_VID(__psp_pa(cmd_ctx->data), vid);
		/* try to send command to the device for execution*/
		ret = vpsp_try_do_cmd(cmd, data_paddr, cmd_ctx, (struct vpsp_ret *)&psp_ret);
		if (unlikely(ret)) {
			pr_err("[%s]: vpsp_try_do_cmd failed\n", __func__);
			ret = -EFAULT;
			goto end;
		}

		if (psp_ret.status == VPSP_FINISH) {
			ret = kvm_pv_psp_cmd_post_op(vpsp, data_gpa, cmd_ctx);
			if (unlikely(ret)) {
				pr_err("[%s]: kvm_pv_psp_cmd_post_op failed\n",
						__func__);
				ret = -EFAULT;
				goto end;
			}
		}
		break;

	case VPSP_RUNNING:
		cmd_ctx = vpsp_hashtable_find_cmd_ctx(data_gpa, vpsp->kvm->userspace_pid);
		if (unlikely(!cmd_ctx)) {
			pr_err("[%s]: vpsp_hashtable_find_cmd_ctx failed, data_gpa %llx\n",
				__func__, data_gpa);
			ret = -EFAULT;
			goto end;
		}

		/* try to get the execution result from ringbuffer*/
		ret = vpsp_try_get_result(cmd_ctx, (struct vpsp_ret *)&psp_ret);
		if (unlikely(ret)) {
			pr_err("[%s]: vpsp_try_get_result failed\n", __func__);
			ret = -EFAULT;
			goto end;
		}

		if (psp_ret.status == VPSP_RUNNING) {
			ret = 0;
			goto end;
		} else if (psp_ret.status == VPSP_FINISH) {
			/* copy data to guest */
			ret = kvm_pv_psp_cmd_post_op(vpsp, data_gpa, cmd_ctx);
			cmd_ctx = NULL;
			if (unlikely(ret)) {
				pr_err("[%s]: kvm_pv_psp_cmd_post_op failed\n",
						__func__);
				ret = -EFAULT;
			}
			goto end;
		}
		ret = -EFAULT;
		break;

	default:
		pr_err("[%s]: invalid command status\n", __func__);
		ret = -EFAULT;
		break;
	}
end:
	if (ret) {
		psp_ret.status = VPSP_FINISH;
		vpsp_cmd_ctx_destroy(cmd_ctx);
	}
	/* return psp_ret to guest */
	vpsp->write_guest(vpsp->kvm, psp_ret_gpa, &psp_ret, sizeof(psp_ret));
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_pv_psp_copy_forward_op);

DEFINE_RWLOCK(vpsp_dev_rwlock);

/* VPSP_VID_MAX_ENTRIES determines the maximum number of vms that can set vid.
 * but, the performance of finding vid is determined by g_vpsp_vid_num,
 * so VPSP_VID_MAX_ENTRIES can be set larger.
 */
#define VPSP_VID_MAX_ENTRIES    2048
#define VPSP_VID_NUM_MAX        64

static struct vpsp_dev_ctx g_vpsp_context_array[VPSP_VID_MAX_ENTRIES];
static uint32_t g_vpsp_vid_num;
static int compare_vid_entries(const void *a, const void *b)
{
	return ((struct vpsp_dev_ctx *)a)->pid - ((struct vpsp_dev_ctx *)b)->pid;
}
static void swap_vid_entries(void *a, void *b, int size)
{
	struct vpsp_dev_ctx entry;

	memcpy(&entry, a, size);
	memcpy(a, b, size);
	memcpy(b, &entry, size);
}

/**
 * When 'allow_default_vid' is set to 1,
 * QEMU is allowed to use 'vid 0' by default
 * in the absence of a valid 'vid' setting.
 */
uint32_t allow_default_vid = 1;
void vpsp_set_default_vid_permission(uint32_t is_allow)
{
	allow_default_vid = is_allow;
}

int vpsp_get_default_vid_permission(void)
{
	return allow_default_vid;
}

/**
 * get a vpsp device context from pid
 */
int vpsp_get_dev_ctx(struct vpsp_dev_ctx **ctx, pid_t pid)
{
	struct vpsp_dev_ctx new_entry = {.pid = pid};
	struct vpsp_dev_ctx *existing_entry = NULL;

	read_lock(&vpsp_dev_rwlock);
	existing_entry = bsearch(&new_entry, g_vpsp_context_array, g_vpsp_vid_num,
				sizeof(struct vpsp_dev_ctx), compare_vid_entries);
	read_unlock(&vpsp_dev_rwlock);

	if (!existing_entry)
		return -ENOENT;

	if (ctx)
		*ctx = existing_entry;

	return 0;
}

/**
 * Upon qemu startup, this section checks whether
 * the '-device psp,vid' parameter is specified.
 * If set, it utilizes the 'vpsp_add_vid' function
 * to insert the 'vid' and 'pid' values into the 'g_vpsp_context_array'.
 * The insertion is done in ascending order of 'pid'.
 */
static int vpsp_add_vid(uint32_t vid)
{
	pid_t cur_pid = task_pid_nr(current);
	struct vpsp_dev_ctx new_entry = {.vid = vid, .pid = cur_pid};

	if (vpsp_get_dev_ctx(NULL, cur_pid) == 0)
		return -EEXIST;
	if (g_vpsp_vid_num == VPSP_VID_MAX_ENTRIES)
		return -ENOMEM;
	if (vid >= VPSP_VID_NUM_MAX)
		return -EINVAL;

	write_lock(&vpsp_dev_rwlock);
	memcpy(&g_vpsp_context_array[g_vpsp_vid_num++], &new_entry, sizeof(struct vpsp_dev_ctx));
	sort(g_vpsp_context_array, g_vpsp_vid_num, sizeof(struct vpsp_dev_ctx),
				compare_vid_entries, swap_vid_entries);
	pr_info("PSP: add vid %d, by pid %d, total vid num is %d\n", vid, cur_pid, g_vpsp_vid_num);
	write_unlock(&vpsp_dev_rwlock);
	return 0;
}

/**
 * Upon the virtual machine is shut down,
 * the 'vpsp_del_vid' function is employed to remove
 * the 'vid' associated with the current 'pid'.
 */
static int vpsp_del_vid(void)
{
	pid_t cur_pid = task_pid_nr(current);
	int i, ret = -ENOENT;
	struct vpsp_cmd_ctx **cmd_ctx = NULL;
	uint32_t cmd_ctx_nums = 0;
	int j;

	write_lock(&vpsp_dev_rwlock);
	for (i = 0; i < g_vpsp_vid_num; ++i) {
		if (g_vpsp_context_array[i].pid == cur_pid) {
			/**
			 * In some cases, such as live migration,
			 * there may be residual cmd ctx that needs to be forcibly destroyed.
			 */
			vpsp_hashtable_save_cmd_ctx_by_pid(cur_pid, NULL, &cmd_ctx_nums);
			cmd_ctx = kcalloc(cmd_ctx_nums, sizeof(struct vpsp_cmd_ctx *), GFP_KERNEL);
			if (!cmd_ctx) {
				ret = -ENOMEM;
				goto end;
			}

			vpsp_hashtable_save_cmd_ctx_by_pid(cur_pid, cmd_ctx, &cmd_ctx_nums);
			for (j = 0; j < cmd_ctx_nums; ++j)
				vpsp_cmd_ctx_destroy(cmd_ctx[j]);

			--g_vpsp_vid_num;
			pr_info("PSP: delete vid %d, by pid %d, total vid num is %d\n",
				g_vpsp_context_array[i].vid, cur_pid, g_vpsp_vid_num);
			memmove(&g_vpsp_context_array[i], &g_vpsp_context_array[i + 1],
				sizeof(struct vpsp_dev_ctx) * (g_vpsp_vid_num - i));

			ret = 0;
			goto end;
		}
	}

end:
	write_unlock(&vpsp_dev_rwlock);
	kfree(cmd_ctx);
	return ret;
}

static int vpsp_set_gpa_range(u64 gpa_start, u64 gpa_end)
{
	pid_t cur_pid = task_pid_nr(current);
	struct vpsp_dev_ctx *ctx = NULL;

	vpsp_get_dev_ctx(&ctx, cur_pid);
	if (!ctx) {
		pr_err("PSP: %s get vpsp_context failed from pid %d\n", __func__, cur_pid);
		return -ENOENT;
	}

	ctx->gpa_start = gpa_start;
	ctx->gpa_end = gpa_end;
	pr_info("PSP: set gpa range (start 0x%llx, end 0x%llx), by pid %d\n",
		gpa_start, gpa_end, cur_pid);
	return 0;
}

int do_vpsp_op_ioctl(struct vpsp_dev_ctrl *ctrl)
{
	int ret = 0;
	unsigned char op = ctrl->op;

	switch (op) {
	case VPSP_OP_VID_ADD:
		ret = vpsp_add_vid(ctrl->data.vid);
		break;

	case VPSP_OP_VID_DEL:
		ret = vpsp_del_vid();
		break;

	case VPSP_OP_SET_DEFAULT_VID_PERMISSION:
		vpsp_set_default_vid_permission(ctrl->data.def_vid_perm);
		break;

	case VPSP_OP_GET_DEFAULT_VID_PERMISSION:
		ctrl->data.def_vid_perm = vpsp_get_default_vid_permission();
		break;

	case VPSP_OP_SET_GPA:
		ret = vpsp_set_gpa_range(ctrl->data.gpa.gpa_start, ctrl->data.gpa.gpa_end);
		break;

	case VPSP_OP_BACKUP_KEY:
		ret = vpsp_backup_key(&ctrl->data.key_img_ctl);
		break;

	case VPSP_OP_RESTORE_KEY:
		ret = vpsp_restore_key(&ctrl->data.key_img_ctl);
		break;

	case VPSP_OP_BACKUP_CTX:
		ret = vpsp_backup_cmd_ctx(&ctrl->data.cmd_ctx_ctl);
		break;

	case VPSP_OP_RESTORE_CTX:
		ret = vpsp_restore_cmd_ctx(&ctrl->data.cmd_ctx_ctl);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

struct csv_ringbuffer_queue vpsp_ring_buffer[CSV_COMMAND_PRIORITY_NUM];
static void vpsp_complete_ring_cmd_ctx(int prio, uint32_t index, uint32_t statval)
{
	struct vpsp_cmd_ctx *ctx = vpsp_ring_cmd_ctx_lookup[prio][index];

	if (!ctx)
		return;

	ctx->statval = statval;
	vpsp_ring_cmd_ctx_lookup[prio][index] = NULL;
	vpsp_cmd_ctx_obj_put(ctx, false);
}

static void vpsp_ring_update_head(int prio, uint32_t new_head)
{
	struct csv_ringbuffer_queue *ring_buffer = &vpsp_ring_buffer[prio];
	uint32_t orig_head = cmd_queue_head(&ring_buffer->cmd_ptr);
	uint32_t comple_num = 0, index = orig_head;
	int i, mask = ring_buffer->cmd_ptr.mask;

	if (new_head >= orig_head)
		comple_num = new_head - orig_head;
	else
		comple_num = mask - (orig_head - new_head) + 1;

	for (i = 0; i < comple_num; ++i) {
		index = (orig_head + i) & mask;
		/**
		 * Write the result back to the cmd ctx, after which we can
		 * safely perform the ringbuffer dequeue operation without
		 * waiting for the Guest to retrieve the result.
		 */
		vpsp_complete_ring_cmd_ctx(prio, index,
					   ringbuffer_get_status(ring_buffer, index));
	}
	psp_ringbuffer_dequeue(ring_buffer, NULL, NULL, comple_num);
}

static int vpsp_psp_mutex_trylock(void)
{
	int mutex_enabled = READ_ONCE(hygon_psp_hooks.psp_mutex_enabled);

	if (!hygon_psp_hooks.sev_dev_hooks_installed)
		return -ENODEV;

	if (mutex_enabled)
		return psp_mutex_trylock(&hygon_psp_hooks.psp_misc->data_pg_aligned->mb_mutex);
	else
		return mutex_trylock(hygon_psp_hooks.sev_cmd_mutex);
}

static int vpsp_psp_mutex_unlock(void)
{
	int mutex_enabled = READ_ONCE(hygon_psp_hooks.psp_mutex_enabled);

	if (!hygon_psp_hooks.sev_dev_hooks_installed)
		return -ENODEV;

	if (mutex_enabled)
		psp_mutex_unlock(&hygon_psp_hooks.psp_misc->data_pg_aligned->mb_mutex);
	else
		mutex_unlock(hygon_psp_hooks.sev_cmd_mutex);

	return 0;
}

static void vpsp_ringbuffer_wakeup_locked(struct work_struct *unused)
{
	struct sev_user_data_status data;
	unsigned int hi_head = 0, low_head = 0;

	psp_ringbuffer_get_newhead(&hi_head, &low_head);

	/* update head */
	vpsp_ring_update_head(CSV_COMMAND_PRIORITY_HIGH, hi_head);
	vpsp_ring_update_head(CSV_COMMAND_PRIORITY_LOW, low_head);

	if (!psp_generic_rb_supported) {
		/* exit ringbuf mode by send CMD in mailbox mode */
		psp_do_cmd_locked(SEV_CMD_PLATFORM_STATUS, &data, NULL, 0);
	}
}

int vpsp_do_cmd(int cmd, phys_addr_t phy_addr, int *psp_ret)
{
	int rc;
	int mutex_enabled = READ_ONCE(hygon_psp_hooks.psp_mutex_enabled);

	if (!hygon_psp_hooks.sev_dev_hooks_installed)
		return -ENODEV;

	if (mutex_enabled) {
		if (psp_mutex_lock_timeout(&hygon_psp_hooks.psp_misc->data_pg_aligned->mb_mutex,
					PSP_MUTEX_TIMEOUT) != 1) {
			return -EBUSY;
		}
	} else {
		mutex_lock(hygon_psp_hooks.sev_cmd_mutex);
	}

	rc = psp_do_cmd_locked(cmd, (void *)phy_addr, psp_ret, PSP_DO_CMD_OP_PHYADDR);

	if (mutex_enabled)
		psp_mutex_unlock(&hygon_psp_hooks.psp_misc->data_pg_aligned->mb_mutex);
	else
		mutex_unlock(hygon_psp_hooks.sev_cmd_mutex);

	return rc;
}

/*
 * Try to obtain the result again by the command index, this
 * interface is used in ringbuffer mode
 */
int vpsp_try_get_result(struct vpsp_cmd_ctx *cmd_ctx, struct vpsp_ret *psp_ret)
{
	int ret = 0;
	uint8_t prio = cmd_ctx->rb_prio;
	uint16_t statval = PSP_CMD_STATUS_RUNNING;
	uint32_t index = cmd_ctx->rb_index;
	phys_addr_t phy_addr = cmd_ctx->psp_cmdbuf_paddr;
	struct csv_cmdptr_entry cmd = {0};

	if (!hygon_psp_hooks.sev_dev_hooks_installed)
		return -ENODEV;

	/* Get the retult directly if the command has been executed */
	if (index >= 0) {
		if (cmd_ctx->statval != PSP_CMD_STATUS_RUNNING)
			statval = cmd_ctx->statval;
		else
			statval = ringbuffer_get_status(&vpsp_ring_buffer[prio], index);
		if (statval != PSP_CMD_STATUS_RUNNING) {
			psp_ret->pret = statval;
			psp_ret->status = VPSP_FINISH;
			return 0;
		}
	}

	if (vpsp_psp_mutex_trylock()) {
		/* Use mailbox mode to execute a command if there is only one command */
		if (cmd_queue_size(&vpsp_ring_buffer[prio].cmd_ptr) == 1) {
			uint32_t head = cmd_queue_head(&vpsp_ring_buffer[prio].cmd_ptr);

			/* dequeue command from queue*/
			psp_ringbuffer_dequeue(&vpsp_ring_buffer[prio], &cmd, NULL, 1);
			ret = psp_do_cmd_locked(cmd.cmd_id, (void *)phy_addr,
						(int *)psp_ret, PSP_DO_CMD_OP_PHYADDR);
			psp_ret->status = VPSP_FINISH;
			vpsp_complete_ring_cmd_ctx(prio, head, psp_ret->pret);
			vpsp_psp_mutex_unlock();
			if (unlikely(ret)) {
				if (ret == -EIO) {
					ret = 0;
				} else {
					pr_err("[%s]: psp do cmd error, %d\n",
						__func__, psp_ret->pret);
					ret = -EIO;
					goto end;
				}
			}
		} else {
			psp_worker_register_notify(vpsp_ringbuffer_wakeup_locked);
			ret = psp_do_ringbuffer_cmds_locked(vpsp_ring_buffer, (int *)psp_ret, true);
			if (unlikely(ret)) {
				pr_err("[%s]: psp ringbuf execute failed %d\n",
						__func__, ret);
				psp_ret->status = VPSP_FINISH;
				vpsp_psp_mutex_unlock();
				goto end;
			}
			psp_ret->status = VPSP_RUNNING;
		}
	} else {
		/* Change the command to the running state if getting the mutex fails */
		psp_ret->status = VPSP_RUNNING;
		return 0;
	}
end:
	return ret;
}

/*
 * Send the virtual psp command to the PSP device and try to get the
 * execution result, the interface and the vpsp_try_get_result
 * interface are executed asynchronously. If the execution succeeds,
 * the result is returned to the VM. If the execution fails, the
 * vpsp_try_get_result interface will be used to obtain the result
 * later again
 */
int vpsp_try_do_cmd(int cmd, phys_addr_t phy_addr,
		struct vpsp_cmd_ctx *cmd_ctx, struct vpsp_ret *psp_ret)
{
	int ret = 0;
	int rb_supported;
	int index = -1;
	uint8_t prio = CSV_COMMAND_PRIORITY_LOW;

	if (!hygon_psp_hooks.sev_dev_hooks_installed)
		return -ENODEV;

	/* ringbuffer mode check and parse command prio*/
	rb_supported = vpsp_parse_ringbuffer_cmd_prio(&prio,
			(struct vpsp_cmd *)&cmd);
	if (rb_supported) {
		/* fill command in ringbuffer's queue and get index */
		index = psp_ringbuffer_enqueue(&vpsp_ring_buffer[prio], cmd, phy_addr, 0);
		if (unlikely(index < 0)) {
			/* do mailbox command if queuing failed*/
			ret = vpsp_do_cmd(cmd, phy_addr, (int *)psp_ret);
			if (unlikely(ret)) {
				if (ret == -EIO) {
					ret = 0;
				} else {
					pr_err("[%s]: psp do cmd error, %d\n",
						__func__, psp_ret->pret);
					ret = -EIO;
					goto end;
				}
			}
			psp_ret->status = VPSP_FINISH;
			goto end;
		}

		cmd_ctx->rb_index = index;
		cmd_ctx->rb_prio = prio;
		cmd_ctx->psp_cmdbuf_paddr = phy_addr;
		vpsp_ring_cmd_ctx_lookup[prio][index] = cmd_ctx;
		vpsp_cmd_ctx_obj_get(cmd_ctx);

		/* try to get result from the ringbuffer command */
		ret = vpsp_try_get_result(cmd_ctx, psp_ret);
		if (unlikely(ret)) {
			pr_err("[%s]: vpsp_try_get_result failed %d\n", __func__, ret);
			goto end;
		}
	} else {
		/* mailbox mode */
		ret = vpsp_do_cmd(cmd, phy_addr, (int *)psp_ret);
		if (unlikely(ret)) {
			if (ret == -EIO) {
				ret = 0;
			} else {
				pr_err("[%s]: psp do cmd error, %d\n",
						__func__, psp_ret->pret);
				ret = -EIO;
				goto end;
			}
		}
		psp_ret->status = VPSP_FINISH;
	}

end:
	return ret;
}

/*
 * parse commands from the virtual machine
 */
int vpsp_parse_ringbuffer_cmd_prio(uint8_t *prio,
		struct vpsp_cmd *vcmd)
{
	int rb_supported;

	psp_ringbuffer_check_support();
	rb_supported = (psp_legacy_rb_supported || psp_generic_rb_supported);

	/* parse prio by vcmd */
	if (rb_supported && vcmd->is_high_rb)
		*prio = CSV_COMMAND_PRIORITY_HIGH;
	else
		*prio = CSV_COMMAND_PRIORITY_LOW;
	/* clear rb level bit in vcmd */
	vcmd->is_high_rb = 0;

	return rb_supported;
}

static int vpsp_backup_key(struct key_img_ctl *ctl)
{
	int ret = 0;
	int pspret = 0;
	uint32_t cmdbuf_size;
	uint8_t *img;
	struct vtkm_cmdresp_key_backup *cmdresp = NULL;
	struct vpsp_dev_ctx *vpsp_dev_ctx = NULL;
	uint32_t image_offset;
	pid_t cur_pid = task_tgid_nr(current);

	if (!ctl)
		return -EINVAL;

	vpsp_get_dev_ctx(&vpsp_dev_ctx, cur_pid);
	if (!vpsp_dev_ctx) {
		pr_err("PSP: %s get vpsp_context failed from pid %d\n", __func__, cur_pid);
		return -ENOENT;
	}

	cmdbuf_size = ctl->img_len + sizeof(struct vtkm_cmdresp_key_backup);
	cmdbuf_size = cmdbuf_size > TKM_CMDRESP_MIN_SIZE ? cmdbuf_size : TKM_CMDRESP_MIN_SIZE;
	cmdresp = kzalloc(cmdbuf_size, GFP_KERNEL);
	if (!cmdresp)
		return -ENOMEM;

	cmdresp->head.buf_size = cmdbuf_size;
	cmdresp->head.cmdresp_size = cmdbuf_size;
	cmdresp->head.cmdresp_code = VTKM_KEY_BACKUP;
	cmdresp->vid = vpsp_dev_ctx->vid;
	cmdresp->image_length = 0;
	cmdresp->scheme = KEY_PROT_SAME_GENERATION;

	// get actual image length
	if (!ctl->img_len) {
		ret = psp_do_cmd(TKM_PSP_CMDID_OFFSET, cmdresp, &pspret);
		if (ret == -EIO && pspret == TKM_ERR_SIZE_SMALL) {
			ctl->img_len = cmdresp->image_length;
			ret = 0;
		} else {
			pr_err("psp_do_cmd ret %d, pspret %d\n", ret, pspret);
		}
		goto end;
	}

	image_offset = sizeof(*cmdresp);
	cmdresp->image_location = LOC_FILL_MODE_BIT(image_offset);
	cmdresp->image_length = ctl->img_len;

	ret = psp_do_cmd(TKM_PSP_CMDID_OFFSET, cmdresp, &pspret);
	if (!ret && !pspret) {
		img = (uint8_t *)(((uintptr_t)cmdresp) + image_offset);
		ctl->img_len = cmdresp->image_length;

		if (copy_to_user(ctl->key_img_ptr, img, ctl->img_len))
			return -EFAULT;
	} else {
		pr_err("psp_do_cmd ret %d, pspret %d\n", ret, pspret);
	}

end:
	kfree(cmdresp);
	return ret;
}

static int vpsp_restore_key(struct key_img_ctl *ctl)
{
	int ret = 0;
	int pspret = 0;
	uint32_t cmdbuf_size, image_offset;
	uint8_t *img;
	struct vtkm_cmdresp_key_restore *cmdresp = NULL;
	struct vpsp_dev_ctx *vpsp_dev_ctx = NULL;
	pid_t cur_pid = task_tgid_nr(current);

	if (!ctl || !ctl->img_len)
		return -EINVAL;

	vpsp_get_dev_ctx(&vpsp_dev_ctx, cur_pid);
	if (!vpsp_dev_ctx) {
		pr_err("PSP: %s get vpsp_context failed from pid %d\n", __func__, cur_pid);
		return -ENOENT;
	}

	cmdbuf_size = ctl->img_len + sizeof(struct vtkm_cmdresp_key_restore);
	cmdbuf_size = cmdbuf_size > TKM_CMDRESP_MIN_SIZE ? cmdbuf_size : TKM_CMDRESP_MIN_SIZE;
	cmdresp = kzalloc(cmdbuf_size, GFP_KERNEL);
	if (!cmdresp)
		return -ENOMEM;

	image_offset = sizeof(*cmdresp);

	cmdresp->head.buf_size = cmdbuf_size;
	cmdresp->head.cmdresp_size = cmdbuf_size;
	cmdresp->head.cmdresp_code = VTKM_KEY_RESTORE;
	cmdresp->vid = vpsp_dev_ctx->vid;
	cmdresp->scheme = KEY_PROT_SAME_GENERATION;
	cmdresp->image_location = LOC_FILL_MODE_BIT(image_offset);
	cmdresp->image_length = ctl->img_len;

	img = (uint8_t *)(((uintptr_t)cmdresp) + image_offset);
	if (copy_from_user(img, ctl->key_img_ptr, ctl->img_len)) {
		ret = -EFAULT;
		goto end;
	}

	ret = psp_do_cmd(TKM_PSP_CMDID_OFFSET, cmdresp, &pspret);
end:
	kfree(cmdresp);
	return ret;
}

/**
 * vpsp_cmd_ctx_serialize - Serialize an array of vpsp command contexts
 * @ctx:        Array of command context pointers to serialize
 * @ctx_nums:   [IN] Number of contexts in array
 *              [OUT] Actual number of contexts serialized (on success)
 * @buf:        Output buffer for serialized data (NULL for size query)
 * @buflen:     [IN] Size of output buffer
 *              [OUT] Required buffer size or actual used size
 *
 * VERSION 1 Serialization format:
 *  +------------------------------------------------+
 *  | [HEADER AREA]:                                 |
 *  |                                                |
 *  | struct vpsp_serialized_header                  |
 *  |   magic: 0x56505350 ("VPSP")                   |
 *  |   buffer_len: Total serialized data length     |
 *  |   version: Format version (1)                  |
 *  |   ctx_count: Number of contexts                |
 *  +------------------------------------------------+
 *  | [METADATA AREA]:                               |
 *  |                                                |
 *  | struct vpsp_ctx_serialized[0]                  |
 *  |   gpa: Guest Physical Address                  |
 *  |   statval: Context status value                |
 *  |   data_size: Size of context data              |
 *  |   data_offset: Offset to data in buffer        |
 *  |------------------------------------------------|
 *  | struct vpsp_ctx_serialized[1]                  |
 *  |   ...                                          |
 *  |------------------------------------------------|
 *  |   ... (additional context metadata)            |
 *  +------------------------------------------------+
 *  | [DATA AREA]:                                   |
 *  |                                                |
 *  |   Context 0 data                               |
 *  |------------------------------------------------|
 *  |   Context 1 data                               |
 *  |   ...                                          |
 *  +------------------------------------------------+
 *
 * Return: 0 on success, negative error code on failure:
 *   -EINVAL: Invalid parameters
 *   -ENOBUFS: Buffer too small (query mode)
 */
static int vpsp_cmd_ctx_serialize(struct vpsp_cmd_ctx **ctx,
		uint32_t ctx_nums, uint8_t *buf, uint32_t *buflen)
{
	struct vpsp_serialized_header *header;
	struct vpsp_ctx_serialized *ctx_meta;
	uint32_t total_size = 0;
	uint8_t *data_area = NULL;
	int i;

	if (ctx_nums == 0) {
		*buflen = 0;
		return 0;
	}

	/* calculate total size */
	total_size = sizeof(struct vpsp_serialized_header);
	for (i = 0; i < ctx_nums; i++) {
		total_size += sizeof(struct vpsp_ctx_serialized);
		total_size += ctx[i]->data_size;
	}

	/* ensure buffer is enough */
	if (*buflen < total_size) {
		/* return actual buffer size */
		*buflen = total_size;
		return -ENOBUFS;
	}

	/* fill header */
	header = (struct vpsp_serialized_header *)buf;
	header->magic = VPSP_MAGIC_NUM;
	header->version = VPSP_SERIALIZED_VERSION;
	header->ctx_count = ctx_nums;
	header->buffer_len = total_size;

	/* calculate data storage area address */
	data_area = buf + sizeof(*header) + (ctx_nums * sizeof(struct vpsp_ctx_serialized));

	/* fill serialize information for each vpsp cmd context */
	for (i = 0; i < ctx_nums; i++) {
		ctx_meta = &header->ctx_meta[i];
		ctx_meta->gpa = ctx[i]->key1;
		ctx_meta->statval = ctx[i]->statval;
		ctx_meta->data_size = ctx[i]->data_size;

		/* store pointer data */
		if (ctx[i]->data_size > 0) {
			if (!ctx[i]->data)
				return -EINVAL;

			ctx_meta->data_offset = (uint32_t)(data_area - buf);
			memcpy(data_area, ctx[i]->data, ctx[i]->data_size);
			data_area += ctx[i]->data_size;
		} else {
			/* no data need to storage */
			ctx_meta->data_offset = 0;
		}
	}

	*buflen = total_size;
	return 0;
}

/**
 * vpsp_cmd_ctx_deserialize - Deserialize command contexts from buffer
 * @ctx:        Input vpsp_cmd_ctx pointer array for store context pointers
 * @ctx_nums:   [IN] Capacity of context array
 *              [OUT] Actual number of contexts deserialized
 * @buf:        Input buffer containing serialized data
 * @buflen:     Length of input buffer
 *
 * Deserialization process:
 *  1. Verify magic and version
 *  2. Validate buffer integrity
 *  3. Parse header information
 *  4. Load context data from data area
 *
 * Return: 0 on success, negative error code on failure:
 *   -EINVAL: Invalid header or corrupted data
 *   -ENOBUFS: Insufficient context array capacity
 *   -ENOMEM: Memory allocation failure
 */
static int vpsp_cmd_ctx_deserialize(struct vpsp_cmd_ctx **ctx,
		uint32_t *ctx_nums, uint8_t *buf, uint32_t buflen)
{
	const struct vpsp_serialized_header *header;
	const struct vpsp_ctx_serialized *ctx_meta;
	pid_t cur_pid = task_tgid_nr(current);
	uint32_t parsed_count = 0;
	int i, ret = 0;

	if (!ctx_nums || !buf)
		return -EINVAL;

	if (*ctx_nums && !ctx)
		return -EINVAL;

	/* check header length */
	if (buflen < sizeof(*header))
		return -EINVAL;

	header = (const struct vpsp_serialized_header *)buf;

	/* ensure data is valid */
	if (header->magic != VPSP_MAGIC_NUM || header->version != VPSP_SERIALIZED_VERSION)
		return -EINVAL;

	/* check total size */
	if (buflen < header->buffer_len)
		return -EINVAL;

	/* ensure the vpsp context number is enough */
	if (header->ctx_count > *ctx_nums) {
		/* return actual number */
		*ctx_nums = header->ctx_count;
		return -ENOBUFS;
	}

	/* ensure context count is valid */
	if (header->buffer_len < header->ctx_count * sizeof(struct vpsp_ctx_serialized))
		return -EINVAL;

	/* parse data for vpsp context */
	for (i = 0; i < header->ctx_count; i++) {
		if (!ctx[parsed_count])
			return -ENOBUFS;

		ctx_meta = &header->ctx_meta[i];
		ctx[parsed_count]->key1 = ctx_meta->gpa;
		ctx[parsed_count]->key2 = cur_pid;
		ctx[parsed_count]->statval = ctx_meta->statval;
		ctx[parsed_count]->data_size = ctx_meta->data_size;

		/* alloc new buffer restore data pointer */
		if (ctx_meta->data_size > 0) {
			if (ctx_meta->data_offset == 0 ||
				ctx_meta->data_offset + ctx_meta->data_size > buflen) {
				/* offset invalid */
				ret = -EINVAL;
				goto failed;
			}

			ctx[parsed_count]->data = kmalloc(ctx_meta->data_size, GFP_KERNEL);
			if (!ctx[parsed_count]->data) {
				ret = -ENOMEM;
				goto failed;
			}

			memcpy(ctx[parsed_count]->data, buf + ctx_meta->data_offset,
				ctx_meta->data_size);
		} else {
			ctx[parsed_count]->data = NULL;
		}

		parsed_count++;
	}

	*ctx_nums = parsed_count;
failed:
	while (ret && parsed_count-- > 0) {
		if (ctx[parsed_count]->data_size > 0)
			kfree(ctx[parsed_count]->data);
	}
	return ret;
}

static int vpsp_force_cmd_ctx_completion(struct vpsp_cmd_ctx *ctx[], uint32_t nums)
{
	int i, ret = 0, psp_ret = 0;

	for (i = 0; i < nums; ++i) {
		bool mutex_locked = false;

		while (true) {
			if (ctx[i]->statval != PSP_CMD_STATUS_RUNNING)
				break;

			if (vpsp_psp_mutex_trylock()) {
				mutex_locked = true;
				break;
			}

			cond_resched();
		}

		if (!mutex_locked)
			continue;

		/**
		 * There are commands in a running state update all queued and
		 * pending commands via ringbuffer operations.
		 *
		 * Disable overcommit feature to avoid the additional latency
		 * caused by failing to fully utilize the allocated overcommit size.
		 */
		ret = psp_do_ringbuffer_cmds_locked(vpsp_ring_buffer, (int *)&psp_ret, false);
		if (unlikely(ret)) {
			pr_err("[%s]: psp ringbuffer execute failed %d\n",
					__func__, ret);
			vpsp_psp_mutex_unlock();
			return ret;
		}

		vpsp_ringbuffer_wakeup_locked(NULL);
		vpsp_psp_mutex_unlock();
		break;
	}

	return ret;
}

static int vpsp_backup_cmd_ctx(struct cmd_ctx_ctl *ctl)
{
	int ret = 0;
	uint32_t buflen = 0;
	pid_t cur_pid = task_tgid_nr(current);
	void *cmd_ctx_buffer = NULL;
	struct vpsp_cmd_ctx **cmd_ctx = NULL;
	uint32_t cmd_ctx_nums = 0;

	vpsp_hashtable_save_cmd_ctx_by_pid(cur_pid, NULL, &cmd_ctx_nums);
	cmd_ctx = kcalloc(cmd_ctx_nums, sizeof(struct vpsp_cmd_ctx *), GFP_KERNEL);
	if (!cmd_ctx) {
		ret = -ENOMEM;
		goto end;
	}

	vpsp_hashtable_save_cmd_ctx_by_pid(cur_pid, cmd_ctx, &cmd_ctx_nums);

	/* Check for unprocessed commands pending PSP handling */
	ret = vpsp_force_cmd_ctx_completion(cmd_ctx, cmd_ctx_nums);
	if (ret) {
		pr_err("%s vpsp_force_cmd_ctx_completion failed %d\n", __func__, ret);
		goto end;
	}

	ret = vpsp_cmd_ctx_serialize(cmd_ctx, cmd_ctx_nums, NULL, &buflen);
	if (ret && ret != -ENOBUFS) {
		pr_err("%s vpsp_cmd_ctx_serialize failed %d\n", __func__, ret);
		goto end;
	}

	if (ctl->buffer_len < buflen) {
		ctl->buffer_len = buflen;
		ret = 0;
		goto end;
	}

	cmd_ctx_buffer = kzalloc(ctl->buffer_len, GFP_KERNEL);
	if (!cmd_ctx_buffer) {
		ret = -ENOMEM;
		goto end;
	}

	ret = vpsp_cmd_ctx_serialize(cmd_ctx, cmd_ctx_nums,
		cmd_ctx_buffer, &ctl->buffer_len);
	if (ret) {
		pr_err("%s vpsp_cmd_ctx_serialize failed %d\n", __func__, ret);
		goto end;
	}

	if (copy_to_user(ctl->cmd_ctx_ptr, cmd_ctx_buffer, ctl->buffer_len)) {
		ret = -EFAULT;
		goto end;
	}

	pr_info("migrate(%d) save: serialization length %d, a total of %d cmd ctx were saved\n",
		cur_pid, ctl->buffer_len, cmd_ctx_nums);
end:
	kfree(cmd_ctx);
	kfree(cmd_ctx_buffer);
	return ret;
}

static int vpsp_restore_cmd_ctx(struct cmd_ctx_ctl *ctl)
{
	int ret = 0, i;
	uint32_t cmd_ctx_nums = 0;
	void *cmd_ctx_buffer = NULL;
	pid_t cur_pid = task_tgid_nr(current);
	struct vpsp_cmd_ctx **load_cmd_ctx = NULL;

	pr_info("migrate(%d) load: serialization length %d\n", cur_pid, ctl->buffer_len);

	if (!ctl->buffer_len)
		return 0;

	cmd_ctx_buffer = kzalloc(ctl->buffer_len, GFP_KERNEL);
	if (!cmd_ctx_buffer)
		return -ENOMEM;

	if (copy_from_user(cmd_ctx_buffer, ctl->cmd_ctx_ptr, ctl->buffer_len)) {
		ret = -EFAULT;
		goto end;
	}

	ret = vpsp_cmd_ctx_deserialize(NULL, &cmd_ctx_nums, cmd_ctx_buffer, ctl->buffer_len);
	if (ret && ret != -ENOBUFS) {
		pr_err("%s vpsp_cmd_ctx_deserialize failed %d\n", __func__, ret);
		goto end;
	}

	load_cmd_ctx = kzalloc(cmd_ctx_nums * sizeof(struct vpsp_cmd_ctx *), GFP_KERNEL);
	if (!load_cmd_ctx) {
		ret = -ENOMEM;
		goto end;
	}

	for (i = 0; i < cmd_ctx_nums; ++i) {
		load_cmd_ctx[i] = kmem_cache_zalloc(vpsp_cmd_ctx_slab, GFP_KERNEL);
		if (!load_cmd_ctx[i]) {
			ret = -ENOMEM;
			goto end;
		}
		load_cmd_ctx[i]->key2 = cur_pid;
		refcount_set(&load_cmd_ctx[i]->ref, 1);
	}

	ret = vpsp_cmd_ctx_deserialize(load_cmd_ctx, &cmd_ctx_nums,
			cmd_ctx_buffer, ctl->buffer_len);
	if (ret) {
		pr_err("%s vpsp_cmd_ctx_deserialize failed %d\n", __func__, ret);
		goto end;
	}

	for (i = 0; i < cmd_ctx_nums; ++i)
		vpsp_hashtable_add_cmd_ctx(load_cmd_ctx[i]);

	pr_info("migrate(%d) load: %d command contexts loaded\n", cur_pid, cmd_ctx_nums);
	ret = 0;
end:
	if (ret) {
		for (i = 0; i < cmd_ctx_nums; ++i) {
			if (load_cmd_ctx[i])
				kmem_cache_free(vpsp_cmd_ctx_slab, load_cmd_ctx[i]);
		}
	}

	kfree(load_cmd_ctx);
	kfree(cmd_ctx_buffer);
	return ret;
}
