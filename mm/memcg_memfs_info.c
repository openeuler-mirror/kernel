// SPDX-License-Identifier: GPL-2.0+

#include <linux/memcg_memfs_info.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include "../fs/mount.h"

#define SEQ_printf(m, x...)			\
do {						\
	if (m)					\
		seq_printf(m, x);		\
	else					\
		pr_info(x);			\
} while (0)

struct print_files_control {
	struct mem_cgroup *memcg;
	struct seq_file *m;
	unsigned long size_threshold;
	unsigned long max_print_files;

	char *pathbuf;
	unsigned long pathbuf_size;

	const char *fs_type_name;
	struct vfsmount *vfsmnt;
	unsigned long total_print_files;
	unsigned long total_files_size;
};

static bool memfs_enable;
static unsigned long memfs_size_threshold;
static unsigned long memfs_max_print_files = 500;

static const char *const fs_type_names[] = {
	"rootfs",
	"tmpfs",
};

static struct vfsmount *memfs_get_vfsmount(struct super_block *sb)
{
	struct mount *mnt;
	struct vfsmount *vfsmnt;

	lock_mount_hash();
	list_for_each_entry(mnt, &sb->s_mounts, mnt_instance) {
		/*
		 * There may be multiple mount points for a super_block,
		 * just need to print one of these mount points to determine
		 * the file path.
		 */
		vfsmnt = mntget(&mnt->mnt);
		unlock_mount_hash();
		return vfsmnt;
	}
	unlock_mount_hash();

	return NULL;
}

static unsigned long memfs_count_in_mem_cgroup(struct mem_cgroup *memcg,
					       struct address_space *mapping)
{
	XA_STATE(xas, &mapping->i_pages, 0);
	unsigned long size = 0;
	struct page *page, *head;

	rcu_read_lock();
	xas_for_each(&xas, page, ULONG_MAX) {
		if (xas_retry(&xas, page))
			continue;

		if (xa_is_value(page))
			continue;

		head = compound_head(page);
		if ((unsigned long)memcg == head->memcg_data)
			size += PAGE_SIZE;
	}
	rcu_read_unlock();
	return size;
}

static void memfs_show_file_in_mem_cgroup(void *data, struct inode *inode)
{
	struct print_files_control *pfc = data;
	struct dentry *dentry;
	unsigned long size;
	struct path path;
	char *filepath;

	size = memfs_count_in_mem_cgroup(pfc->memcg, inode->i_mapping);
	if (!size || size < pfc->size_threshold)
		return;

	dentry = d_find_alias(inode);
	if (!dentry)
		return;
	path.mnt = pfc->vfsmnt;
	path.dentry = dentry;
	filepath = d_absolute_path(&path, pfc->pathbuf, pfc->pathbuf_size);
	if (!filepath || IS_ERR(filepath))
		filepath = "(too long)";
	pfc->total_print_files++;
	pfc->total_files_size += size;
	dput(dentry);

	/*
	 * To prevent excessive logs, limit the amount of data
	 * that can be output to logs.
	 */
	if (!pfc->m && pfc->total_print_files > pfc->max_print_files)
		return;

	SEQ_printf(pfc->m, "%lukB %llukB %s\n",
		   size >> 10, inode->i_size >> 10, filepath);
}

static void memfs_show_files_in_mem_cgroup(struct super_block *sb, void *data)
{
	struct print_files_control *pfc = data;
	struct inode *inode, *toput_inode = NULL;

	if (strncmp(sb->s_type->name,
		    pfc->fs_type_name, strlen(pfc->fs_type_name)))
		return;

	pfc->vfsmnt = memfs_get_vfsmount(sb);
	if (!pfc->vfsmnt)
		return;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);

		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0 && !need_resched())) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		memfs_show_file_in_mem_cgroup(pfc, inode);

		iput(toput_inode);
		toput_inode = inode;

		cond_resched();
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput_inode);
	mntput(pfc->vfsmnt);
}

void mem_cgroup_print_memfs_info(struct mem_cgroup *memcg, char *pathbuf,
				 struct seq_file *m)
{
	struct print_files_control pfc = {
		.memcg = memcg,
		.m = m,
		.max_print_files = READ_ONCE(memfs_max_print_files),
		.size_threshold = READ_ONCE(memfs_size_threshold),
	};
	int i;

	if (!memfs_enable || !memcg)
		return;

	pfc.pathbuf = pathbuf;
	pfc.pathbuf_size = PATH_MAX;

	for (i = 0; i < ARRAY_SIZE(fs_type_names); i++) {
		pfc.fs_type_name = fs_type_names[i];
		pfc.total_print_files = 0;
		pfc.total_files_size = 0;

		SEQ_printf(m, "Show %s files (memory-size > %lukB):\n",
			   pfc.fs_type_name, pfc.size_threshold >> 10);
		SEQ_printf(m, "<memory-size> <file-size> <path>\n");
		iterate_supers(memfs_show_files_in_mem_cgroup, &pfc);

		SEQ_printf(m, "total files: %lu, total memory-size: %lukB\n",
			   pfc.total_print_files, pfc.total_files_size >> 10);
	}
}

int mem_cgroup_memfs_files_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));
	char *pathbuf;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf) {
		SEQ_printf(m, "Show memfs abort: failed to allocate memory\n");
		return 0;
	}
	mem_cgroup_print_memfs_info(memcg, pathbuf, m);
	kfree(pathbuf);
	return 0;
}

static ssize_t memfs_size_threshold_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *buf)
{
	return sprintf(buf, "%lu\n", READ_ONCE(memfs_size_threshold));
}

static ssize_t memfs_size_threshold_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t len)
{
	unsigned long count;
	int err;

	err = kstrtoul(buf, 10, &count);
	if (err)
		return err;

	WRITE_ONCE(memfs_size_threshold, count);
	return len;
}

static struct kobj_attribute memfs_size_threshold_attr = {
	.attr = {"size_threshold", 0644},
	.show = &memfs_size_threshold_show,
	.store = &memfs_size_threshold_store,
};

static ssize_t memfs_max_print_files_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	return sprintf(buf, "%lu\n", READ_ONCE(memfs_max_print_files));
}

static ssize_t memfs_max_print_files_store(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buf, size_t len)
{
	unsigned long count;
	int err;

	err = kstrtoul(buf, 10, &count);
	if (err)
		return err;

	WRITE_ONCE(memfs_max_print_files, count);
	return len;
}

static struct kobj_attribute memfs_max_print_files_attr = {
	.attr = {"max_print_files_in_oom", 0644},
	.show = &memfs_max_print_files_show,
	.store = &memfs_max_print_files_store,
};

static ssize_t memfs_enable_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", memfs_enable);
}

static ssize_t memfs_enable_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t len)
{
	bool enable;
	int err;

	err = kstrtobool(buf, &enable);
	if (err)
		return err;

	memfs_enable = enable;
	return len;
}

static struct kobj_attribute memfs_enable_attr = {
	.attr = {"enable", 0644},
	.show = &memfs_enable_show,
	.store = &memfs_enable_store,
};

static struct attribute *memfs_attr[] = {
	&memfs_size_threshold_attr.attr,
	&memfs_max_print_files_attr.attr,
	&memfs_enable_attr.attr,
	NULL,
};

static struct attribute_group memfs_attr_group = {
	.attrs = memfs_attr,
};

void mem_cgroup_memfs_info_init(void)
{
	struct kobject *memcg_memfs_kobj;

	if (mem_cgroup_disabled())
		return;

	memcg_memfs_kobj = kobject_create_and_add("memcg_memfs_info", mm_kobj);
	if (unlikely(!memcg_memfs_kobj)) {
		pr_err("failed to create memcg_memfs kobject\n");
		return;
	}

	if (sysfs_create_group(memcg_memfs_kobj, &memfs_attr_group)) {
		pr_err("failed to register memcg_memfs group\n");
		kobject_put(memcg_memfs_kobj);
	}
}
