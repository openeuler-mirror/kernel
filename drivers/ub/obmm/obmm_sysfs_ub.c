// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#include <linux/pgtable.h>
#include <linux/elf.h>
#include <linux/mutex.h>

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

static const char *get_type_str(const struct obmm_region *region)
{
	return region->created_as == OBMM_EXPORT_REGION ? "export" : "import";
}

/* show some attribute of a region as string */
#define REGION_ATTR_SHOW(tag)                                                               \
	static ssize_t tag##_show(struct device *dev,                                       \
				  struct device_attribute *attr __always_unused, char *buf) \
	{                                                                                   \
		struct obmm_region *region;                                                 \
		region = container_of(dev, struct obmm_region, device);                     \
		return sysfs_emit(buf, "%s\n", get_##tag##_str(region));                    \
	}                                                                                   \
	static DEVICE_ATTR_ADMIN_RO(tag)

REGION_ATTR_SHOW(type);

static ssize_t priv_len_show(struct device *dev, struct device_attribute *attr __always_unused,
			     char *buf)
{
	struct obmm_region *region;

	region = container_of(dev, struct obmm_region, device);
	return sysfs_emit(buf, "%u\n", region->priv_len);
}
static DEVICE_ATTR_ADMIN_RO(priv_len);

/* binary attribute of the sysfs entry for priv data */
static ssize_t priv_read(struct file *filp __always_unused, struct kobject *kobj,
			 struct bin_attribute *bin_attr __always_unused, char *buf, loff_t off,
			 size_t count)
{
	struct device *dev;
	struct obmm_region *region;

	dev = kobj_to_dev(kobj);
	region = container_of(dev, struct obmm_region, device);

	if (off + count > OBMM_MAX_PRIV_LEN)
		count = OBMM_MAX_PRIV_LEN - off;
	memcpy(buf, region->priv + off, count);

	return count;
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
REGION_FLAG_SHOW(memory_from_user);
REGION_FLAG_SHOW(preimport);

/*
 * Backend-typed views of a region: every show() below reads
 * the memory state through reg->backend, dispatching on the backend type;
 * "-" is shown for a NULL backend (detached corner) or a field the current
 * backend does not carry.
 */
static struct obmm_import_backend *reg_import_backend(const struct obmm_region *reg)
{
	struct obmm_backend *be = reg->backend;

	if (be && be->type == OBMM_BACKEND_IMPORT)
		return obmm_backend_to_import(be);
	return NULL;
}

static struct obmm_export_common *reg_export_common(const struct obmm_region *reg)
{
	struct obmm_backend *be = reg->backend;

	if (!be)
		return NULL;
	return obmm_backend_to_export_common(be);
}

/*
 * Scalar-field show() generators: state_mutex -> typed accessor ->
 * sysfs_emit (or "-" when the current backend does not carry the field or
 * no backend is attached) -> unlock.
 */
#define IMPORT_FIELD_SHOW(field, fmt)						\
	static ssize_t field##_show(struct device *dev,				\
				    struct device_attribute *attr __always_unused, char *buf) \
	{									\
		struct obmm_region *reg;					\
		struct obmm_import_backend *imp;				\
		ssize_t count;							\
										\
		reg = container_of(dev, struct obmm_region, device);		\
		mutex_lock(&reg->state_mutex);					\
		imp = reg_import_backend(reg);					\
		if (imp)							\
			count = sysfs_emit(buf, fmt "\n", imp->field);		\
		else								\
			count = sysfs_emit(buf, "-\n");				\
		mutex_unlock(&reg->state_mutex);					\
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
		mutex_lock(&reg->state_mutex);					\
		exp = reg_export_common(reg);					\
		if (exp)							\
			count = sysfs_emit(buf, fmt "\n", exp->field);		\
		else								\
			count = sysfs_emit(buf, "-\n");				\
		mutex_unlock(&reg->state_mutex);					\
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
	mutex_lock(&reg->state_mutex);
	exp = reg_export_common(reg);
	if (!exp) {
		count = sysfs_emit(buf, "-\n");
		goto out_unlock;
	}

	count = sysfs_emit(buf, "%#llx", exp->node_mem_size[0]);
	for (i = 1; i < exp->node_count; i++)
		count += sysfs_emit_at(buf, count, ",%#llx", exp->node_mem_size[i]);
	count += sysfs_emit_at(buf, count, "\n");
out_unlock:
	mutex_unlock(&reg->state_mutex);
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
	mutex_lock(&reg->state_mutex);
	imp = reg_import_backend(reg);
	exp = reg_export_common(reg);
	if (imp)
		count = sysfs_emit(buf, EID_FMT64 "\n", EID_ARGS64_H(imp->deid),
				   EID_ARGS64_L(imp->deid));
	else if (exp)
		count = sysfs_emit(buf, EID_FMT64 "\n", EID_ARGS64_H(exp->deid),
				   EID_ARGS64_L(exp->deid));
	else
		count = sysfs_emit(buf, "-\n");
	mutex_unlock(&reg->state_mutex);
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
	mutex_lock(&reg->state_mutex);
	imp = reg_import_backend(reg);
	if (imp)
		count = sysfs_emit(buf, EID_FMT64 "\n", EID_ARGS64_H(imp->seid),
				   EID_ARGS64_L(imp->seid));
	else
		count = sysfs_emit(buf, "-\n");
	mutex_unlock(&reg->state_mutex);
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
