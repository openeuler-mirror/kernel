// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#include <linux/align.h>
#include <linux/miscdevice.h>
#include <linux/err.h>
#include <linux/mman.h>
#include <linux/hugetlb.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/memory_hotplug.h>
#include <linux/rwlock.h>
#include <linux/idr.h>

#include <ub/ubus/ub-mem-decoder.h>
#include <ub/ubus/ubus.h>

#include "obmm_shm_dev.h"
#include "obmm_cache.h"
#include "obmm_export_region_ops.h"
#include "ubmempool_allocator.h"
#include "obmm_import.h"
#include "obmm_ownership.h"
#include "obmm_lowmem.h"
#include "obmm_preimport.h"
#include "obmm_addr_check.h"
#include "obmm_sysfs.h"
#include "obmm_export.h"
#include "obmm_core.h"

size_t __obmm_memseg_size;

#define UB_MEM_FEATURE_MASK (UB_MEM_BORROW_NC | UB_MEM_BORROW_CC | \
			     UB_MEM_SHARE_NC | UB_MEM_SHARE_CC)

DEFINE_STATIC_KEY_FALSE(obmm_enabled);

/*
 * OBMM centers around regions -- "struct obmm_region". Each region represents
 * a chunk of memory. OBMM exposes its interface to user space through the
 * device interface. Users may manipulate the memory region through ioctl to
 * master device /dev/obmm, and access each memory region through standard file
 * operations like open, close and mmap.
 *
 * To support remote memory access via UB, OBMM models two different types of
 * regions, the export region and the import region. As the name suggests, the
 * export region is physically located on this host (local), while the import
 * region is physically attached to another host (remote).
 *
 * All /dev/obmm operations are essentially region creation and deletion.
 * Currently, a linked list is used to keep track of all active regions.
 *
 * All region device (/dev/obmm_shmdev{region_id}) operations access its own
 * region only. To keep our management in accordance with Linux standard device
 * file, each device file's life cycle should be decided only by its reference
 * counts. Therefore, the master device cannot forcefully remove a region in
 * use. This complicates concurrency control and region life cycle management.
 *
 * concurrency control: when region is created, the only accessor to the region
 * is its creator, and there is no concurrency issues to worry about. The
 * concurrent access starts when we "publish" the region on the region list.
 *
 * All new accessors get the pointer to the region from the region list,
 * directly or indirectly. Most accessors merely read some region attributes.
 * Their read-only nature simplifies concurrency control, and all we need to do
 * is to guarantee that the region will not be freed by others during their
 * access. This is done by the "refcnt" reference counter. Using the conditional
 * atomic instructions, "refcnt" is also in charge of guarding against access
 * before initialization is completed, access during destruction and double-free
 * problems.
 */

static struct obmm_ctx_info g_obmm_ctx_info;
static DEFINE_IDA(g_obmm_region_ida);

/* Return the pointer to region only if the region is active: not in initialization or
 * destruction process.
 */
struct obmm_region *try_get_obmm_region(struct obmm_region *region)
{
	if (region && refcount_inc_not_zero(&region->refcnt))
		return region;
	return NULL;
}
void put_obmm_region(struct obmm_region *region)
{
	if (region)
		refcount_dec(&region->refcnt);
}
void activate_obmm_region(struct obmm_region *region)
{
	refcount_set(&region->refcnt, 1);
}
/* Return whether the disable is success. disable succeed only when the region is active and idle */
static inline bool disable_obmm_region_get(struct obmm_region *region)
{
	return refcount_dec_if_one(&region->refcnt);
}

static struct obmm_region *_search_obmm_region(int regionid)
{
	struct obmm_region *region_now;

	list_for_each_entry(region_now, &g_obmm_ctx_info.regions, node) {
		if (region_now->regionid == regionid)
			return region_now;
	}
	return NULL;
}

struct obmm_region *search_get_obmm_region(int regionid)
{
	struct obmm_region *region;
	unsigned long flags;
	spinlock_t *lock;

	lock = &g_obmm_ctx_info.lock;
	spin_lock_irqsave(lock, flags);
	region = _search_obmm_region(regionid);
	region = try_get_obmm_region(region);
	spin_unlock_irqrestore(lock, flags);

	return region;
}

struct obmm_region *search_deactivate_obmm_region(int regionid)
{
	struct obmm_region *region;
	unsigned long flags;
	spinlock_t *lock;
	bool success;

	lock = &g_obmm_ctx_info.lock;
	spin_lock_irqsave(lock, flags);
	region = _search_obmm_region(regionid);
	success = region && disable_obmm_region_get(region);
	spin_unlock_irqrestore(lock, flags);

	if (!region) {
		pr_err("failed to deactivate: region with mem_id=%d not found.\n", regionid);
		return ERR_PTR(-ENOENT);
	}

	if (!success) {
		pr_err("failed to deactivate: region %d is being used or in creation/destruction process.\n",
		       region->regionid);
		return ERR_PTR(-EBUSY);
	}

	return region;
}

int obmm_query_by_offset(struct obmm_region *reg, unsigned long offset,
			 struct obmm_ext_addr *ext_addr)
{
	int ret;
	struct obmm_export_region *e_reg;
	struct obmm_import_region *i_reg;

	if (reg->type == OBMM_EXPORT_REGION) {
		e_reg = container_of(reg, struct obmm_export_region, region);
		ret = get_offset_detail_export_region(e_reg, offset, ext_addr);
	} else {
		i_reg = container_of(reg, struct obmm_import_region, region);
		ret = get_offset_detail_import(i_reg, offset, ext_addr);
	}
	return ret;
}

int obmm_query_by_pa(unsigned long pa, struct obmm_ext_addr *ext_addr)
{
	int ret = -ENOENT;
	struct obmm_region *region;
	unsigned long flags;
	spinlock_t *lock;

	lock = &g_obmm_ctx_info.lock;

	spin_lock_irqsave(lock, flags);
	list_for_each_entry(region, &g_obmm_ctx_info.regions, node) {
		if (!try_get_obmm_region(region))
			continue;
		if (region->type == OBMM_IMPORT_REGION) {
			struct obmm_import_region *i_reg;

			i_reg = container_of(region, struct obmm_import_region, region);
			ret = get_pa_detail_import(i_reg, pa, ext_addr);
		}
		if (region->type == OBMM_EXPORT_REGION) {
			struct obmm_export_region *e_reg;

			e_reg = container_of(region, struct obmm_export_region, region);
			ret = get_pa_detail_export_region(e_reg, pa, ext_addr);
		}
		put_obmm_region(region);
		if (ret == 0)
			break;
	}
	spin_unlock_irqrestore(lock, flags);

	if (ret)
		return -ENOENT;
	return 0;
}

static int nid_to_package_id(int nid)
{
	const struct cpumask *cpumask;
	int cpu;

	/* the check guard against the dynamic online / offline of local node */
	if (!is_online_local_node(nid))
		return -1;

	/* currently we cannot handle CPU-less local memory node */
	cpumask = cpumask_of_node(nid);
	if (cpumask_empty(cpumask))
		return -1;

	cpu = (int)cpumask_first(cpumask);
	return topology_physical_package_id(cpu);
}

/* return -1 when any of the node is not online or is in different packages (sockets) */
static int get_nodes_package(const nodemask_t *nodes)
{
	int nid, package_id, this_package_id;

	package_id = -1;
	for_each_node_mask(nid, *nodes) {
		this_package_id = nid_to_package_id(nid);
		if (this_package_id == -1)
			return -1;
		if (package_id == -1)
			package_id = this_package_id;
		else if (package_id != this_package_id)
			return -1;
	}
	return package_id;
}

bool nodes_on_same_package(const nodemask_t *nodes)
{
	return get_nodes_package(nodes) != -1;
}

bool validate_scna(u32 scna)
{
	int ret = ub_mem_get_numa_id(scna);

	if (ret < 0) {
		pr_err("%#x is not a known scna, lookup ret=%pe\n", scna, ERR_PTR(ret));
		return false;
	}
	return true;
}

bool validate_obmm_mem_id(__u64 mem_id)
{
	bool valid;

	valid = mem_id >= OBMM_MIN_VALID_REGIONID && mem_id <= OBMM_MAX_VALID_REGIONID;
	if (!valid)
		pr_err("mem_id=%llu is out of valid mem_id range.\n", mem_id);
	return valid;
}

static int insert_obmm_region(struct obmm_region *reg)
{
	struct obmm_region *region_now;
	unsigned long flags;
	spinlock_t *lock;

	lock = &g_obmm_ctx_info.lock;
	spin_lock_irqsave(lock, flags);

	region_now = _search_obmm_region(reg->regionid);
	if (region_now != NULL) {
		spin_unlock_irqrestore(lock, flags);
		pr_err("obmm region already exist, mem_id = %d\n", reg->regionid);
		return -EEXIST;
	}

	list_add(&reg->node, &g_obmm_ctx_info.regions);
	spin_unlock_irqrestore(lock, flags);
	return 0;
}

static void remove_obmm_region(struct obmm_region *reg)
{
	unsigned long flags;
	spinlock_t *lock;

	lock = &g_obmm_ctx_info.lock;

	spin_lock_irqsave(lock, flags);

	list_del(&reg->node);

	spin_unlock_irqrestore(lock, flags);
}

void uninit_obmm_region(struct obmm_region *region)
{
	if (region->ownership_info)
		release_ownership_info(region);
	ida_free(&g_obmm_region_ida, region->regionid);
	mutex_destroy(&region->state_mutex);
}

int init_obmm_region(struct obmm_region *region)
{
	int retval;

	refcount_set(&region->refcnt, 0);
	mutex_init(&region->state_mutex);
	INIT_LIST_HEAD(&region->node);

	retval = ida_alloc_range(&g_obmm_region_ida, OBMM_MIN_VALID_REGIONID,
				 OBMM_MAX_VALID_REGIONID, GFP_KERNEL);
	if (retval < 0) {
		pr_err("Failed to allocate mem_id, ret=%pe\n", ERR_PTR(retval));
		return retval;
	}
	region->regionid = retval;

	return 0;
}

int register_obmm_region(struct obmm_region *region)
{
	int retval;

	/* create device */
	retval = obmm_shm_dev_add(region);
	if (retval) {
		pr_err("Failed to create device %d. ret=%pe\n", region->regionid, ERR_PTR(retval));
		return retval;
	}

	/* insert OBMM_region */
	retval = insert_obmm_region(region);
	if (retval < 0) {
		pr_err("Failed to insert obmm region %d on creation. ret=%pe\n", region->regionid,
		       ERR_PTR(retval));
		obmm_shm_dev_del(region);
		return retval;
	}

	return 0;
}

void deregister_obmm_region(struct obmm_region *region)
{
	remove_obmm_region(region);
	obmm_shm_dev_del(region);
}

int set_obmm_region_priv(struct obmm_region *region, unsigned int priv_len, const void __user *priv)
{
	region->priv_len = 0;
	if (priv_len > OBMM_MAX_PRIV_LEN) {
		pr_err("priv_len=%u too large (limit=%u).\n", priv_len, OBMM_MAX_PRIV_LEN);
		return -EINVAL;
	}

	if (copy_from_user(region->priv, priv, priv_len)) {
		pr_err("failed to save private data.\n");
		return -EFAULT;
	}
	region->priv_len = priv_len;
	return 0;
}

static int obmm_addr_query(struct obmm_cmd_addr_query *cmd_addr_query)
{
	int ret;
	struct obmm_ext_addr ext_addr;
	struct obmm_region *region;

	if (cmd_addr_query->key_type == OBMM_QUERY_BY_PA) {
		pr_debug("obmm_query_by_pa: pa=%#llx\n", cmd_addr_query->pa);
		ret = obmm_query_by_pa(cmd_addr_query->pa, &ext_addr);
		if (ret == 0) {
			cmd_addr_query->mem_id = ext_addr.regionid;
			cmd_addr_query->offset = ext_addr.offset;
		}
		return ret;
	} else if (cmd_addr_query->key_type == OBMM_QUERY_BY_ID_OFFSET) {
		pr_debug("obmm_query_by_id_offset: mem_id=%llu offset=%#llx\n",
			 cmd_addr_query->mem_id, cmd_addr_query->offset);
		if (!validate_obmm_mem_id(cmd_addr_query->mem_id))
			return -ENOENT;
		region = search_get_obmm_region(cmd_addr_query->mem_id);
		if (region == NULL) {
			pr_err("region %llu not found.\n", cmd_addr_query->mem_id);
			return -ENOENT;
		}
		ret = obmm_query_by_offset(region, cmd_addr_query->offset, &ext_addr);
		if (ret == 0)
			cmd_addr_query->pa = ext_addr.pa;
		put_obmm_region(region);
		return ret;
	}
	pr_err("invalid query key type: %u.\n", cmd_addr_query->key_type);
	return -EINVAL;
}

static int obmm_dev_open(struct inode *inode __always_unused, struct file *file __always_unused)
{
	return 0;
}

static int obmm_dev_flush(struct file *file __always_unused, fl_owner_t owner __always_unused)
{
	return 0;
}

static long obmm_dev_ioctl(struct file *file __always_unused, unsigned int cmd, unsigned long arg)
{
	int ret;
	union {
		struct obmm_cmd_export create;
		struct obmm_cmd_import import;
		struct obmm_cmd_unexport unexport;
		struct obmm_cmd_unimport unimport;
		struct obmm_cmd_addr_query query;
		struct obmm_cmd_export_pid export_pid;
		struct obmm_cmd_preimport preimport;
	} cmd_param;

	if (!static_branch_likely(&obmm_enabled)) {
		pr_err("obmm feature not enabled\n");
		return -EOPNOTSUPP;
	}

	switch (cmd) {
	case OBMM_CMD_EXPORT: {
		ret = (int)copy_from_user(&cmd_param.create, (void __user *)arg,
					  sizeof(struct obmm_cmd_export));
		if (ret) {
			pr_err("failed to load export argument\n");
			return -EFAULT;
		}

		ret = obmm_export_from_pool(&cmd_param.create);
		if (ret)
			return ret;

		ret = (int)copy_to_user((void __user *)arg, &cmd_param.create,
					sizeof(struct obmm_cmd_export));
		if (ret) {
			pr_err("failed to write export result\n");
			return -EFAULT;
		}
	} break;
	case OBMM_CMD_IMPORT: {
		ret = (int)copy_from_user(&cmd_param.import, (void __user *)arg,
					  sizeof(struct obmm_cmd_import));
		if (ret) {
			pr_err("failed to load import argument\n");
			return -EFAULT;
		}

		ret = obmm_import(&cmd_param.import);
		if (ret)
			return ret;

		ret = (int)copy_to_user((void __user *)arg, &cmd_param.import,
					sizeof(struct obmm_cmd_import));
		if (ret) {
			pr_err("failed to write import result\n");
			return -EFAULT;
		}
	} break;
	case OBMM_CMD_UNEXPORT: {
		ret = (int)copy_from_user(&cmd_param.unexport, (void __user *)arg,
					  sizeof(struct obmm_cmd_unexport));
		if (ret) {
			pr_err("failed to load unexport argument\n");
			return -EFAULT;
		}

		ret = obmm_unexport(&cmd_param.unexport);
	} break;
	case OBMM_CMD_UNIMPORT: {
		ret = (int)copy_from_user(&cmd_param.unimport, (void __user *)arg,
					  sizeof(struct obmm_cmd_unimport));
		if (ret) {
			pr_err("failed to load unimport argument\n");
			return -EFAULT;
		}

		ret = obmm_unimport(&cmd_param.unimport);
	} break;
	case OBMM_CMD_ADDR_QUERY: {
		ret = (int)copy_from_user(&cmd_param.query, (void __user *)arg,
					  sizeof(struct obmm_cmd_addr_query));
		if (ret) {
			pr_err("failed to load addr_query argument\n");
			return -EFAULT;
		}

		ret = obmm_addr_query(&cmd_param.query);
		if (ret)
			return ret;

		ret = (int)copy_to_user((void __user *)arg, &cmd_param.query,
					sizeof(struct obmm_cmd_addr_query));
		if (ret) {
			pr_err("failed to write obmm_query result\n");
			return -EFAULT;
		}
	} break;
	case OBMM_CMD_EXPORT_PID: {
		ret = (int)copy_from_user(&cmd_param.export_pid, (void __user *)arg,
					  sizeof(struct obmm_cmd_export_pid));
		if (ret) {
			pr_err("Failed to load export_pid param.\n");
			return -EFAULT;
		}

		ret = obmm_export_pid(&cmd_param.export_pid);
		if (ret)
			return ret;

		ret = (int)copy_to_user((void __user *)arg, &cmd_param.export_pid,
					sizeof(struct obmm_cmd_export_pid));
		if (ret) {
			pr_err("failed to write export_pid result.\n");
			return -EFAULT;
		}
	} break;
	case OBMM_CMD_DECLARE_PREIMPORT: {
		ret = (int)copy_from_user(&cmd_param.preimport, (void __user *)arg,
					  sizeof(struct obmm_cmd_preimport));
		if (ret) {
			pr_err("failed to load preimport argument\n");
			return -EFAULT;
		}

		ret = obmm_preimport(&cmd_param.preimport);
		if (ret)
			return ret;

		ret = (int)copy_to_user((void __user *)arg, &cmd_param.preimport,
					sizeof(struct obmm_cmd_preimport));
		if (ret) {
			pr_err("failed to write preimport result\n");
			return -EFAULT;
		}
	} break;
	case OBMM_CMD_UNDECLARE_PREIMPORT: {
		ret = (int)copy_from_user(&cmd_param.preimport, (void __user *)arg,
					  sizeof(struct obmm_cmd_preimport));
		if (ret) {
			pr_err("failed to load preimport argument\n");
			return -EFAULT;
		}

		ret = obmm_unpreimport(&cmd_param.preimport);
	} break;
	default:
		ret = -ENOTTY;
	}

	return ret;
}

const struct file_operations obmm_dev_fops = { .owner = THIS_MODULE,
					       .unlocked_ioctl = obmm_dev_ioctl,
					       .open = obmm_dev_open,
					       .flush = obmm_dev_flush };

static struct miscdevice obmm_dev_handle = { .minor = MISC_DYNAMIC_MINOR,
					     .name = OBMM_DEV_NAME,
					     .fops = &obmm_dev_fops };

static void ubmem_feature_probe(void)
{
	unsigned long long features = ub_feature_get();

	if (features & UB_MEM_FEATURE_MASK)
		static_branch_enable(&obmm_enabled);

	pr_info("ub_feature: %#llx, obmm_enabled: %ld\n", features,
		static_branch_likely(&obmm_enabled));
}

static int __init obmm_init(void)
{
	int ret;

	pr_info("obmm_module: init started\n");

	ubmem_feature_probe();

	ret = ubmempool_allocator_init();
	if (ret) {
		pr_err("Failed to init allocator. ret=%pe\n", ERR_PTR(ret));
		return ret;
	}

	ret = misc_register(&obmm_dev_handle);
	if (ret) {
		pr_err("Failed to register root device. ret=%pe\n", ERR_PTR(ret));
		goto out_allocator_exit;
	}

	spin_lock_init(&g_obmm_ctx_info.lock);
	INIT_LIST_HEAD(&g_obmm_ctx_info.regions);

	ret = obmm_shm_dev_init();
	if (ret) {
		pr_err("failed to initialize obmm_shm_dev. ret=%pe\n", ERR_PTR(ret));
		goto out_misc_deregister;
	}

	module_addr_check_init();

	ret = module_preimport_init();
	if (ret) {
		pr_err("failed to initialize preimport range manager. ret=%pe.\n", ERR_PTR(ret));
		goto out_addr_check_exit;
	}

	ret = lowmem_notify_init();
	if (ret) {
		pr_err("failed to initialize lowmem handler. ret=%pe\n", ERR_PTR(ret));
		goto out_module_import_exit;
	}

	pr_info("obmm_module: init completed\n");
	return ret;

out_module_import_exit:
	module_preimport_exit();
out_addr_check_exit:
	module_addr_check_exit();
	obmm_shm_dev_exit();
out_misc_deregister:
	misc_deregister(&obmm_dev_handle);
out_allocator_exit:
	ubmempool_allocator_exit();
	return ret;
}

static void __exit obmm_exit(void)
{
	pr_info("obmm_module: exit started\n");

	lowmem_notify_exit();
	module_preimport_exit();
	module_addr_check_exit();
	obmm_shm_dev_exit();
	misc_deregister(&obmm_dev_handle);
	ubmempool_allocator_exit();

	pr_info("obmm_module: exit completed\n");
}

module_init(obmm_init);
module_exit(obmm_exit);

MODULE_DESCRIPTION("OBMM Framework's implementations.");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_LICENSE("GPL");
