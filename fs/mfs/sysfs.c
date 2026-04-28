// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026. KylinSoft Co., Ltd */

#include "internal.h"

#include <linux/sysfs.h>

enum mfs_attr_id {
	attr_ev_mask,
};

struct mfs_attr {
	struct attribute attr;
	short attr_id;
};

#define MFS_ATTR(_name, _mode, _id) \
static struct mfs_attr mfs_attr_##_name = { \
	.attr = {.name = __stringify(_name), .mode = _mode }, \
	.attr_id = attr_##_id, \
}
#define MFS_ATTR_FUNC(_name, _mode) MFS_ATTR(_name, _mode, _name)
#define ATTR_LIST(name) (&mfs_attr_##name.attr)

MFS_ATTR_FUNC(ev_mask, 0644);
static struct attribute *mfs_ev_attrs[] = {
	ATTR_LIST(ev_mask),
	NULL,
};
ATTRIBUTE_GROUPS(mfs_ev);

static unsigned long mfs_ev_fullmask;

static struct kobject *mfs_root;

static void mfs_ev_release(struct kobject *kobj)
{
	struct mfs_sb_info *sbi = container_of(kobj, struct mfs_sb_info,
					       ev_kobj);
	complete(&sbi->ev_kobj_unregister);
}

static ssize_t mfs_attr_show(struct kobject *kobj,
			     struct attribute *attr, char *buf)
{
	struct mfs_sb_info *sbi = container_of(kobj, struct mfs_sb_info,
					       ev_kobj);
	struct mfs_attr *a = container_of(attr, struct mfs_attr, attr);

	switch (a->attr_id) {
	case attr_ev_mask:
		return sysfs_emit(buf, "%lu\n", sbi->ev_mask);

	default:
		return 0;
	}
}

static ssize_t ev_mask_store(struct mfs_sb_info *sbi,
			     const char *buf, size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;

	val = val & mfs_ev_fullmask;
	sbi->ev_mask = val;
	return count;
}

static ssize_t mfs_attr_store(struct kobject *kobj, struct attribute *attr,
			      const char *buf, size_t len)
{
	struct mfs_sb_info *sbi = container_of(kobj, struct mfs_sb_info,
					       ev_kobj);
	struct mfs_attr *a = container_of(attr, struct mfs_attr, attr);

	switch (a->attr_id) {
	case attr_ev_mask:
		return ev_mask_store(sbi, buf, len);

	default:
		return 0;
	}
}

static const struct sysfs_ops mfs_attr_ops = {
	.show = mfs_attr_show,
	.store = mfs_attr_store,
};

static const struct kobj_type mfs_ev_ktype = {
	.default_groups = mfs_ev_groups,
	.sysfs_ops  = &mfs_attr_ops,
	.release = mfs_ev_release,
};


int mfs_fs_sysfs_init(struct super_block *sb)
{
	struct mfs_sb_info *sbi = MFS_SB(sb);
	int err;

	if (sbi->minor >= 0) { /* event related sysfs config */
		sbi->ev_mask = 0;
		init_completion(&sbi->ev_kobj_unregister);
		err = kobject_init_and_add(&sbi->ev_kobj, &mfs_ev_ktype, mfs_root,
					   "mfs%d", sbi->minor);
		if (err) {
			kobject_put(&sbi->ev_kobj);
			wait_for_completion(&sbi->ev_kobj_unregister);
			return err;
		}
	}

	return 0;
}

void mfs_fs_sysfs_exit(struct super_block *sb)
{
	struct mfs_sb_info *sbi = MFS_SB(sb);

	if (sbi->minor >= 0) { /* event related sysfs config */
		kobject_put(&sbi->ev_kobj);
		wait_for_completion(&sbi->ev_kobj_unregister);
	}
}

int mfs_sysfs_init(void)
{
	mfs_ev_fullmask = 0xFFFF;

	mfs_root = kobject_create_and_add("mfs", fs_kobj);
	if (!mfs_root)
		return -ENOMEM;
	return 0;
}

void mfs_sysfs_exit(void)
{
	kobject_put(mfs_root);
	mfs_root = NULL;
}
