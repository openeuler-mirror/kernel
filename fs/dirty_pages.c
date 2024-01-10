// SPDX-License-Identifier: GPL-2.0
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "internal.h"

#define DIRTY_ROOT "dirty"		/* proc root directory name */
#define DIRTY_BUFFER_SIZE "buffer_size"	/* proc file to control buffer */
#define DIRTY_PAGES "dirty_list"	/* proc file to obtain diry pages */
#define DIRTY_LIMIT "page_threshold"	/* proc file to filter result */
#define MAX_BUF_NUM 102400		/* max buffer num in number of pages */
#define TERM_STR "terminated\n"		/* tail string for overflowed buffer */
#define UNKNOW_STR "unknown"		/* for unknown file name or fs type */

static char *buf_dirty;		/* buffer to store number of dirty pages */
static unsigned long buf_size;	/* size of buffer in bytes */
static unsigned long buf_num;	/* size of buffer in number of pages */
static unsigned long buf_limit;	/* filter threshold of dirty pages */
static unsigned long lock_word;	/* for exclusive access to buffer */

static bool dirty_pages_lock(void)
{
	if (xchg(&lock_word, 1) == 1)
		return false;
	return true;
}

static void dirty_pages_unlock(void)
{
	lock_word = 0;
}

static unsigned long dump_dirtypages_inode(struct inode *inode)
{
	XA_STATE(xas, &inode->i_mapping->i_pages, 0);
	unsigned long pages = 0;
	void *page;

	if (!mapping_tagged(inode->i_mapping, PAGECACHE_TAG_DIRTY))
		return 0;

	xas_lock_irq(&xas);
	xas_for_each_marked(&xas, page, (pgoff_t)-1, PAGECACHE_TAG_DIRTY) {
		if (++pages % XA_CHECK_SCHED)
			continue;

		xas_pause(&xas);
		xas_unlock_irq(&xas);
		cond_resched();
		xas_lock_irq(&xas);
	}
	xas_unlock_irq(&xas);

	return pages;
}

static char *inode_filename(struct inode *inode)
{
	char *path;
	static char buf[PATH_MAX];
	struct dentry *dentry;

	dentry = d_find_alias(inode);
	if (!dentry)
		return UNKNOW_STR;

	path = dentry_path_raw(dentry, buf, PATH_MAX);
	dput(dentry);

	return IS_ERR_OR_NULL(path) ? UNKNOW_STR : path;
}

static const char *sb_fstype(struct super_block *sb)
{
	if (sb->s_type && sb->s_type->name)
		return sb->s_type->name;
	else
		return UNKNOW_STR;
}

static inline bool is_sb_writable(struct super_block *sb)
{
	if (sb_rdonly(sb))
		return false;

	if (sb->s_writers.frozen == SB_FREEZE_COMPLETE)
		return false;

	return true;
}

/*
 * dump_dirtypages_sb - dump the dirty pages of each inode in the sb
 * @sb the super block
 * @m the seq_file witch is initialized in proc_dpages_open
 *
 * For each inode in the sb, call dump_dirtypages_pages to get the number
 * of dirty pages. And use seq_printf to store the result in the buffer
 * if it's not less than the threshold. The inode in unusual state will
 * be skipped.
 */
static void dump_dirtypages_sb(struct super_block *sb, struct seq_file *m)
{
	struct inode *inode, *toput_inode = NULL;
	unsigned long limit;

	if (!is_sb_writable(sb) || !sb->s_bdev)
		return;

	limit = READ_ONCE(buf_limit);
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		unsigned long dirty_pages;

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}

		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		dirty_pages = dump_dirtypages_inode(inode);
		if (!dirty_pages || dirty_pages < limit)
			goto skip;

		seq_printf(m, "FSType: %s, Dev ID: %u(%u:%u) ino %lu, dirty pages %lu, path %s\n",
			sb_fstype(sb), sb->s_dev, MAJOR(sb->s_dev),
			MINOR(sb->s_dev), inode->i_ino, dirty_pages,
			inode_filename(inode));

		if (seq_has_overflowed(m)) {
			/* keep size > count to avoid overflow in seq_read_iter() */
			m->size += strlen(TERM_STR) + 1;
			seq_puts(m, TERM_STR);
			iput(inode);
			iput(toput_inode);
			return;
		}
skip:
		iput(toput_inode);
		toput_inode = inode;
		cond_resched();
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput_inode);
}

static int proc_dpages_show(struct seq_file *m, void *v)
{
	iterate_supers((void *)dump_dirtypages_sb, (void *)m);
	return 0;
}

static int proc_dpages_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct seq_file *m;

	if (!dirty_pages_lock())
		return -EBUSY;

	if (buf_dirty == NULL || buf_size == 0) {
		pr_warn("dirty_pages: please allocate buffer before getting dirty pages\n");
		dirty_pages_unlock();
		return -ENOMEM;
	}

	ret = single_open(filp, proc_dpages_show, NULL);
	if (ret) {
		dirty_pages_unlock();
		return ret;
	}

	m = (struct seq_file *)filp->private_data;
	memset(buf_dirty, 0, buf_size);
	m->size = buf_size - (strlen(TERM_STR) + 1);
	m->buf = buf_dirty;

	return 0;
}

static int proc_dpages_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	/* we don't want to free the buf */
	m->buf = NULL;
	dirty_pages_unlock();
	return single_release(inode, file);
}

static void free_buf_dirty(void)
{
	if (!buf_dirty)
		return;

	vfree(buf_dirty);
	buf_dirty = NULL;
	buf_size = 0;
	WRITE_ONCE(buf_num, 0);
}

static int proc_buffer_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%lu\n", READ_ONCE(buf_num));
	return 0;
}

static int proc_buffer_open(struct inode *inode, struct file *filp)
{
	int ret;

	if (((filp->f_flags & O_ACCMODE) != O_RDONLY) && !dirty_pages_lock())
		return -EBUSY;

	ret = single_open(filp, proc_buffer_show, NULL);
	if (ret)
		dirty_pages_unlock();

	return ret;
}

static ssize_t proc_buffer_write(struct file *filp, const char __user *buf,
				 size_t count, loff_t *offp)
{
	int ret;
	unsigned long new_buf_num, new_buf_size;
	char *new_buf_dirty;

	ret = kstrtoul_from_user(buf, count, 10, &new_buf_num);
	if (ret != 0 || new_buf_num > MAX_BUF_NUM)
		return -EINVAL;

	if (new_buf_num == buf_num)
		return count;

	if (new_buf_num == 0) {
		free_buf_dirty();
		return count;
	}

	new_buf_size = PAGE_SIZE * new_buf_num;
	new_buf_dirty = vzalloc(new_buf_size);
	if (!new_buf_dirty)
		return -ENOMEM;

	free_buf_dirty();
	buf_dirty = new_buf_dirty;
	buf_size = new_buf_size;
	WRITE_ONCE(buf_num, new_buf_num);

	return count;
}

static int proc_buffer_release(struct inode *inode, struct file *filp)
{
	if ((filp->f_flags & O_ACCMODE) != O_RDONLY)
		dirty_pages_unlock();
	return single_release(inode, filp);
}

static int proc_limit_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%lu\n", READ_ONCE(buf_limit));
	return 0;
}

static int proc_limit_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, proc_limit_show, NULL);
}

static ssize_t proc_limit_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *offp)
{
	int ret;
	unsigned long limit;

	ret = kstrtoul_from_user(buf, count, 10, &limit);
	if (ret != 0)
		return ret;

	WRITE_ONCE(buf_limit, limit);

	return count;
}

static const struct proc_ops proc_dpages_operations = {
	.proc_open           = proc_dpages_open,
	.proc_read           = seq_read,
	.proc_release        = proc_dpages_release,
};

static const struct proc_ops proc_buffer_operations = {
	.proc_open           = proc_buffer_open,
	.proc_read           = seq_read,
	.proc_write          = proc_buffer_write,
	.proc_lseek          = seq_lseek,
	.proc_release        = proc_buffer_release,
};

static const struct proc_ops proc_limit_operations = {
	.proc_open           = proc_limit_open,
	.proc_read           = seq_read,
	.proc_write          = proc_limit_write,
	.proc_lseek          = seq_lseek,
	.proc_release        = single_release,
};

static int __init dpages_proc_init(void)
{
	struct proc_dir_entry *dirty_dir;

	dirty_dir = proc_mkdir(DIRTY_ROOT, NULL);
	if (!dirty_dir)
		return -ENOMEM;

	if (!proc_create(DIRTY_PAGES, 0440, dirty_dir, &proc_dpages_operations))
		goto fail_pages;

	if (!proc_create(DIRTY_BUFFER_SIZE, 0640, dirty_dir,
			 &proc_buffer_operations))
		goto fail_switch;

	if (!proc_create(DIRTY_LIMIT, 0640, dirty_dir, &proc_limit_operations))
		goto fail_limit;

	return 0;

fail_limit:
	remove_proc_entry(DIRTY_BUFFER_SIZE, dirty_dir);
fail_switch:
	remove_proc_entry(DIRTY_PAGES, dirty_dir);
fail_pages:
	remove_proc_entry(DIRTY_ROOT, NULL);
	return -ENOMEM;
}

subsys_initcall(dpages_proc_init);
