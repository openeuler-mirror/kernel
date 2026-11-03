// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#include <linux/pgtable.h>
#include <linux/fs.h>
#include <linux/elf.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>

#include "obmm_sysfs.h"
#include "obmm_backend.h"
#include "obmm_preimport.h"

static ssize_t size_show(struct device *dev, struct device_attribute *attr __always_unused,
			 char *buf)
{
	struct obmm_region *region;

	region = container_of(dev, struct obmm_region, device);
	return sysfs_emit(buf, "0x%llx\n", region->mem_size);
}
static DEVICE_ATTR_ADMIN_RO(size);

/* type follows the attached backend and shows "-" when none (switch_state
 * = STRANDED tells why); the export subtype is export_info/memory_from_user.
 */
static ssize_t type_show(struct device *dev,
			 struct device_attribute *attr __always_unused, char *buf)
{
	struct obmm_region *region;
	struct obmm_backend *be;
	const char *str;

	region = container_of(dev, struct obmm_region, device);
	rcu_read_lock();
	if (region_switch_in_flight(region)) {
		rcu_read_unlock();
		return -EAGAIN;
	}
	be = rcu_dereference(region->backend);
	str = "-";
	if (be)
		str = be->type == OBMM_BACKEND_IMPORT ? "import" : "export";
	rcu_read_unlock();

	return sysfs_emit(buf, "%s\n", str);
}
static DEVICE_ATTR_ADMIN_RO(type);

/* binary attribute of the sysfs entry for priv data */
static ssize_t priv_read(struct file *filp __always_unused, struct kobject *kobj,
			 struct bin_attribute *bin_attr __always_unused, char *buf, loff_t off,
			 size_t count)
{
	struct device *dev;
	struct obmm_region *region;
	ssize_t ret;
	loff_t pos;
	unsigned int seq;

	dev = kobj_to_dev(kobj);
	region = container_of(dev, struct obmm_region, device);

	if (off < 0)
		return 0;

	/* bounded by ACTIVE priv_len, not array size; retried on a finisher priv commit */
	do {
		seq = read_seqcount_begin(&region->priv_seq);
		pos = off;
		ret = memory_read_from_buffer(buf, count, &pos, region->priv,
					      READ_ONCE(region->priv_len));
	} while (read_seqcount_retry(&region->priv_seq, seq));

	return ret;
}

static struct bin_attribute bin_attr_priv __ro_after_init = {
	.attr = {
		.name = "priv",
		.mode = 0400,
	},
	.read = priv_read,
	.size = OBMM_MAX_PRIV_LEN,
};

/* show some attribute of a region as string */
#define REGION_FLAG_SHOW(flag)                                                               \
	static ssize_t flag##_show(struct device *dev,                                       \
				   struct device_attribute *attr __always_unused, char *buf) \
	{                                                                                    \
		struct obmm_region *region;                                                  \
		region = container_of(dev, struct obmm_region, device);                      \
		return sysfs_emit(buf, "%d\n", region_##flag(region));                       \
	}                                                                                    \
	static DEVICE_ATTR_ADMIN_RO(flag)

REGION_FLAG_SHOW(allow_mmap);

#define REGION_IDENTITY_FLAG_SHOW(flag)                                                     \
	static ssize_t flag##_show(struct device *dev,                                       \
				   struct device_attribute *attr __always_unused, char *buf) \
	{                                                                                    \
		struct obmm_region *region;                                                  \
											     \
		region = container_of(dev, struct obmm_region, device);                      \
		if (region_switch_in_flight(region))                                         \
			return -EAGAIN;                                                      \
		return sysfs_emit(buf, "%d\n", region_##flag(region));                       \
	}                                                                                    \
	static DEVICE_ATTR_ADMIN_RO(flag)

REGION_IDENTITY_FLAG_SHOW(memory_from_user);
REGION_IDENTITY_FLAG_SHOW(preimport);

/* Shell scalars are single natural-width READ_ONCE loads (views are
 * lockless); only the priv blob and priv_len are multi-step, sequenced by
 * priv_seq.
 */
#define SHELL_FIELD_SHOW(field, fmt)					\
	static ssize_t field##_show(struct device *dev,			\
				    struct device_attribute *attr __always_unused, char *buf) \
	{								\
		struct obmm_region *reg;				\
									\
		reg = container_of(dev, struct obmm_region, device);	\
		return sysfs_emit(buf, fmt "\n", READ_ONCE(reg->field));	\
	}								\
	static DEVICE_ATTR_ADMIN_RO(field)

/* the ACTIVE length, coherent with the priv blob (priv_seq) */
static ssize_t priv_len_show(struct device *dev,
			     struct device_attribute *attr __always_unused, char *buf)
{
	struct obmm_region *reg = container_of(dev, struct obmm_region, device);
	unsigned int len, seq;

	do {
		seq = read_seqcount_begin(&reg->priv_seq);
		len = READ_ONCE(reg->priv_len);
	} while (read_seqcount_retry(&reg->priv_seq, seq));

	return sysfs_emit(buf, "%u\n", len);
}
static DEVICE_ATTR_ADMIN_RO(priv_len);

/* enum obmm_switch_state: 0=IDLE 1=SWAPPING 2=AWAIT_READY 3=FINISHING 4=STRANDED */
SHELL_FIELD_SHOW(switch_state, "%d");
/* first negative errno from the switch flushes or a terminal destroy; reset
 * at each begin.
 */
SHELL_FIELD_SHOW(switch_flush_result, "%d");
/* enum obmm_mmap_granu / enum obmm_mmap_mode */
SHELL_FIELD_SHOW(mmap_granu, "%d");
SHELL_FIELD_SHOW(mmap_mode, "%d");

/* Backend-typed views read reg->backend under rcu_read_lock: it is
 * RCU-published and freed only after a grace period drains the readers, so
 * the read cannot dangle; "-" for a NULL backend or a missing field.
 */
static struct obmm_import_backend *reg_import_backend_rcu(const struct obmm_region *reg)
{
	struct obmm_backend *be = rcu_dereference(reg->backend);

	if (be && be->type == OBMM_BACKEND_IMPORT)
		return obmm_backend_to_import(be);
	return NULL;
}

static struct obmm_export_common *reg_export_common_rcu(const struct obmm_region *reg)
{
	struct obmm_backend *be = rcu_dereference(reg->backend);

	if (!be)
		return NULL;
	return obmm_backend_to_export_common(be);
}

#define IMPORT_FIELD_SHOW(field, fmt)						\
	static ssize_t field##_show(struct device *dev,				\
				    struct device_attribute *attr __always_unused, char *buf) \
	{									\
		struct obmm_region *reg;					\
		struct obmm_import_backend *imp;				\
		ssize_t count;							\
										\
		reg = container_of(dev, struct obmm_region, device);		\
		rcu_read_lock();						\
		if (region_switch_in_flight(reg)) {				\
			rcu_read_unlock();					\
			return -EAGAIN;						\
		}								\
		imp = reg_import_backend_rcu(reg);				\
		if (imp)							\
			count = sysfs_emit(buf, fmt "\n", imp->field);		\
		else								\
			count = sysfs_emit(buf, "-\n");				\
		rcu_read_unlock();						\
		return count;							\
	}									\
	static DEVICE_ATTR_ADMIN_RO(field)

#define EXPORT_FIELD_SHOW(field, fmt)						\
	static ssize_t field##_show(struct device *dev,				\
				    struct device_attribute *attr __always_unused, char *buf) \
	{									\
		struct obmm_region *reg;					\
		struct obmm_export_common *exp;				\
		ssize_t count;							\
										\
		reg = container_of(dev, struct obmm_region, device);		\
		rcu_read_lock();						\
		if (region_switch_in_flight(reg)) {				\
			rcu_read_unlock();					\
			return -EAGAIN;						\
		}								\
		exp = reg_export_common_rcu(reg);				\
		if (exp)								\
			count = sysfs_emit(buf, fmt "\n", exp->field);		\
		else								\
			count = sysfs_emit(buf, "-\n");				\
		rcu_read_unlock();						\
		return count;							\
	}									\
	static DEVICE_ATTR_ADMIN_RO(field)

/* for export region only */
static ssize_t node_mem_size_show(struct device *dev, struct device_attribute *attr __always_unused,
				  char *buf)
{
	unsigned int i;
	ssize_t count;
	struct obmm_region *reg;
	struct obmm_export_common *exp;

	reg = container_of(dev, struct obmm_region, device);
	rcu_read_lock();
	if (region_switch_in_flight(reg)) {
		rcu_read_unlock();
		return -EAGAIN;
	}
	exp = reg_export_common_rcu(reg);
	if (!exp) {
		count = sysfs_emit(buf, "-\n");
		goto out_unlock;
	}

	count = sysfs_emit(buf, "%#llx", exp->node_mem_size[0]);
	for (i = 1; i < exp->node_count; i++)
		count += sysfs_emit_at(buf, count, ",%#llx", exp->node_mem_size[i]);
	count += sysfs_emit_at(buf, count, "\n");
out_unlock:
	rcu_read_unlock();
	return count;
}
static DEVICE_ATTR_ADMIN_RO(node_mem_size);

static ssize_t deid_show(struct device *dev, struct device_attribute *attr __always_unused,
			 char *buf)
{
	struct obmm_import_backend *imp;
	struct obmm_export_common *exp;
	struct obmm_region *reg;
	ssize_t count;

	reg = container_of(dev, struct obmm_region, device);
	rcu_read_lock();
	if (region_switch_in_flight(reg)) {
		rcu_read_unlock();
		return -EAGAIN;
	}
	imp = reg_import_backend_rcu(reg);
	exp = reg_export_common_rcu(reg);
	if (imp)
		count = sysfs_emit(buf, EID_FMT64 "\n", EID_ARGS64_H(imp->deid),
				   EID_ARGS64_L(imp->deid));
	else if (exp)
		count = sysfs_emit(buf, EID_FMT64 "\n", EID_ARGS64_H(exp->deid),
				   EID_ARGS64_L(exp->deid));
	else
		count = sysfs_emit(buf, "-\n");
	rcu_read_unlock();
	return count;
}
static DEVICE_ATTR_ADMIN_RO(deid);

static ssize_t seid_show(struct device *dev, struct device_attribute *attr __always_unused,
			 char *buf)
{
	struct obmm_import_backend *imp;
	struct obmm_region *reg;
	ssize_t count;

	reg = container_of(dev, struct obmm_region, device);
	rcu_read_lock();
	if (region_switch_in_flight(reg)) {
		rcu_read_unlock();
		return -EAGAIN;
	}
	imp = reg_import_backend_rcu(reg);
	if (imp)
		count = sysfs_emit(buf, EID_FMT64 "\n", EID_ARGS64_H(imp->seid),
				   EID_ARGS64_L(imp->seid));
	else
		count = sysfs_emit(buf, "-\n");
	rcu_read_unlock();
	return count;
}
static DEVICE_ATTR_ADMIN_RO(seid);

EXPORT_FIELD_SHOW(tokenid, "0x%x");
EXPORT_FIELD_SHOW(uba, "0x%llx");

IMPORT_FIELD_SHOW(pa, "0x%llx");
IMPORT_FIELD_SHOW(numa_id, "%d");
IMPORT_FIELD_SHOW(dcna, "0x%x");
IMPORT_FIELD_SHOW(scna, "0x%x");

static struct attribute *root_attrs[] __ro_after_init = {
	&dev_attr_size.attr,
	&dev_attr_type.attr,
	&dev_attr_priv_len.attr,
	&dev_attr_allow_mmap.attr,
	&dev_attr_switch_state.attr,
	&dev_attr_switch_flush_result.attr,
	&dev_attr_mmap_granu.attr,
	&dev_attr_mmap_mode.attr,
	NULL,
};

static struct bin_attribute *root_bin_attrs[] __ro_after_init = {
	&bin_attr_priv,
	NULL,
};

static struct attribute *import_numa_attrs[] __ro_after_init = {
	&dev_attr_numa_id.attr,
	&dev_attr_pa.attr,
	&dev_attr_dcna.attr,
	&dev_attr_scna.attr,
	&dev_attr_preimport.attr,
	&dev_attr_seid.attr,
	&dev_attr_deid.attr,
	NULL,
};
static struct attribute *import_mmap_attrs[] __ro_after_init = {
	&dev_attr_pa.attr,
	&dev_attr_dcna.attr,
	&dev_attr_scna.attr,
	&dev_attr_seid.attr,
	&dev_attr_deid.attr,
	NULL,
};

static struct attribute *export_attrs[] __ro_after_init = {
	&dev_attr_node_mem_size.attr,
	&dev_attr_uba.attr,
	&dev_attr_tokenid.attr,
	&dev_attr_memory_from_user.attr,
	&dev_attr_deid.attr,
	NULL,
};

static struct attribute_group root_attrs_group __ro_after_init = {
	.name = NULL,
	.attrs = root_attrs,
	.bin_attrs = root_bin_attrs,
};

#define SYSFS_NUMA_REMOTE 1U

static unsigned int get_import_region_sysfs_index(const struct obmm_region *region)
{
	unsigned int index = 0;

	if (region_numa_remote(region))
		index |= SYSFS_NUMA_REMOTE;

	return index;
}

static const struct attribute_group import_attrs_groups[] = {
	[0] = {
		.name = "import_info",
		.attrs = import_mmap_attrs,
	},
	[SYSFS_NUMA_REMOTE] = {
		.name = "import_info",
		.attrs = import_numa_attrs,
	},
};

static const struct attribute_group export_attrs_group = {
	.name = "export_info",
	.attrs = export_attrs,
};

static const struct attribute_group *obmm_import_attrs_groups_list[][3] = {
	{ &root_attrs_group, &import_attrs_groups[0], NULL },
	{ &root_attrs_group, &import_attrs_groups[1], NULL },
};

static const struct attribute_group *obmm_export_attrs_groups[] = {
	&root_attrs_group,
	&export_attrs_group,
	NULL,
};

const struct attribute_group **obmm_region_get_attr_groups(const struct obmm_region *region)
{
	unsigned int index;

	if (region->created_as == OBMM_EXPORT_REGION)
		return obmm_export_attrs_groups;
	index = get_import_region_sysfs_index(region);
	return obmm_import_attrs_groups_list[index];
}

const struct attribute_group *obmm_region_identity_group(const struct obmm_region *region)
{
	/* the identity group is the element right after the root group */
	return obmm_region_get_attr_groups(region)[1];
}

/* Re-key import_info/ vs export_info/ to the newly attached backend.
 * create-before-remove keeps one group attached; a STRANDED region keeps
 * its last one. Sleepable context only (takes state_mutex).
 */
void obmm_region_sysfs_update_identity(struct obmm_region *region)
{
	const struct attribute_group *target;
	struct obmm_backend *be;

	mutex_lock(&region->state_mutex);
	be = rcu_dereference_protected(region->backend,
			       lockdep_is_held(&region->state_mutex));
	if (!be)
		target = NULL;
	else if (be->type == OBMM_BACKEND_IMPORT)
		target = &import_attrs_groups[0];
	else
		target = &export_attrs_group;
	mutex_unlock(&region->state_mutex);

	if (!target || target == region->sysfs_identity_group)
		return;

	if (sysfs_create_group(&region->device.kobj, target)) {
		pr_err("region %d: failed to attach %s sysfs group after switch\n",
		       region->regionid, target->name);
		return;
	}
	sysfs_remove_group(&region->device.kobj, region->sysfs_identity_group);
	region->sysfs_identity_group = target;
}
