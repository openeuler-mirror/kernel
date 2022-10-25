// SPDX-License-Identifier: GPL-2.0
/* 
 * fs/overlayfs/sysfs.c
 * 
 * This file is used for creating a sysfs file for the 
 * overlay file system 
 *
 * Based significantly on the fs/ext4/sysfs.c
 */

#include <linux/kobject.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/namei.h>

#include "ovl_entry.h"

static struct kobject *ovl_root;

enum attr_id_t {
	attr_upper,
	attr_lower,
	attr_work,
	attr_merge,
};

struct ovl_attr {
	struct attribute attr;
	short attr_id;
};

#define OVL_ATTR(_name, _mode)                                                 \
	static struct ovl_attr ovl_attr_##_name = {                            \
		.attr = { .name = __stringify(_name), .mode = _mode },         \
		.attr_id = attr_##_name,                                       \
	}

#define ATTR_LIST(name) &ovl_attr_##name.attr

OVL_ATTR(upper, 0440);
OVL_ATTR(lower, 0440);
OVL_ATTR(work, 0440);
OVL_ATTR(merge, 0440);
static struct attribute *default_attrs[] = { 
	ATTR_LIST(upper), 
	ATTR_LIST(lower),
	ATTR_LIST(work), 
	ATTR_LIST(merge),
	NULL 
};

int ovl_mergedir_backup(struct super_block *sb, const char *str)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	ofs->config.mergedir = kstrdup(str, GFP_KERNEL);
	if (!ofs->config.mergedir)
		return -ENOMEM;
	return 0;
}

static ssize_t ovl_sysfs_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct ovl_fs *ofs = container_of(kobj, struct ovl_fs, kobj);
	struct ovl_attr *ovl_attribute =
		container_of(attr, struct ovl_attr, attr);

	switch (ovl_attribute->attr_id) {
	case attr_upper:
		return snprintf(buf, PAGE_SIZE, "%s\n",
				ofs->config.upperdir);
	case attr_lower:
		return snprintf(buf, PAGE_SIZE, "%s\n",
				ofs->config.lowerdir);
	case attr_work:
		return snprintf(buf, PAGE_SIZE, "%s\n",
				ofs->config.workdir);
	case attr_merge:
		return snprintf(buf, PAGE_SIZE, "%s\n",
				ofs->config.mergedir);
	default:
		return -EPERM;
	}
}

static void ovl_kobj_release(struct kobject *kobj)
{
	struct ovl_fs *ofs = container_of(kobj, struct ovl_fs, kobj);

	complete(&ofs->kobj_unregister);
}

static struct sysfs_ops ovl_sysfs_ops = { 
	.show = ovl_sysfs_show 
};

static struct kobj_type ovl_sb_ktype = { 
	.sysfs_ops = &ovl_sysfs_ops,
	.default_attrs = default_attrs, 
	.release = ovl_kobj_release 
};

int ovl_register_sysfs(struct super_block *sb)
{
	struct ovl_fs *ofs = OVL_FS(sb);
	int err;

	init_completion(&ofs->kobj_unregister);

	err = kobject_init_and_add(&ofs->kobj, &ovl_sb_ktype, 
				   ovl_root, "merge_%d_%d", 
				   MAJOR(sb->s_dev), MINOR(sb->s_dev));
	if (err) {
		kobject_put(&ofs->kobj);
		wait_for_completion(&ofs->kobj_unregister);
	}
	return err;
}

void ovl_unregister_sysfs(struct super_block *sb) 
{
	kobject_del(&OVL_FS(sb)->kobj);
}

int __init ovl_init_sysfs(void)
{
	ovl_root = kobject_create_and_add("overlayfs", fs_kobj);
	if (!ovl_root)
		return -ENOMEM;
	return 0;
}

void ovl_exit_sysfs(void)
{
	kobject_put(ovl_root);
	ovl_root = NULL;
}
