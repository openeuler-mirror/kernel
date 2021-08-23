// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/parser.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/bitops.h>
#include <linux/magic.h>
#include <linux/exportfs.h>
#include <linux/random.h>
#include <linux/cred.h>
#include <linux/backing-dev.h>
#include <linux/list.h>
#include <linux/pfn_t.h>
#include <linux/dax.h>
#include <linux/genhd.h>
#include <linux/cdev.h>
#include <uapi/linux/mount.h>
#include "euler.h"
#include "dht.h"
#include "dep.h"
#include "nvalloc.h"
#include "wear.h"

int support_clwb;
int support_clflushopt;
int support_clflush;
int force_nocache_write;
int persist_period = -4;
int persisters_per_socket = 1;
int max_dirty_inodes = 1000000;
int max_dep_nodes = 1000000;
int wear_control;
int wear_threshold = 100000;
int wear_alloc_threshold = 10000;

module_param(persisters_per_socket, int, 0444);
MODULE_PARM_DESC(persisters_per_socket, "Num of Persisters per socket");
module_param(force_nocache_write, int, 0444);
MODULE_PARM_DESC(force_nocache_write, "Force to use nocache data write");
module_param(persist_period, int, 0444);
MODULE_PARM_DESC(persist_period, "Period to wake persisters up");
module_param(max_dirty_inodes, int, 0444);
MODULE_PARM_DESC(max_dirty_inodes,
		 "Limit the max number of dirty inodes allowed");
module_param(max_dep_nodes, int, 0444);
MODULE_PARM_DESC(max_dep_nodes, "Limit the max number of dep nodes allowed");
module_param(wear_control, int, 0444);
MODULE_PARM_DESC(wear_control, "Control wear leveling");
module_param(wear_threshold, int, 0444);
MODULE_PARM_DESC(wear_threshold, "Wear leveling threshold");
module_param(wear_alloc_threshold, int, 0444);
MODULE_PARM_DESC(wear_alloc_threshold,
		 "Wear leveling threshold for allocation");

int num_sockets;

static struct super_operations eufs_sops;

void eufs_error_mng(struct super_block *sb, const char *fmt, ...)
{
	va_list args;

	eufs_info("euler error: ");
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	pr_crit("euler err: remounting filesystem read-only");
	sb->s_flags |= MS_RDONLY;
}

static void eufs_show_params(void)
{
	eufs_info("params: force_nocache_write=%d\n", force_nocache_write);
	eufs_info("params: persist_period=%d\n", persist_period);
	eufs_info("params: persisters_per_socket=%d\n", persisters_per_socket);
}

static void eufs_detect_features(void)
{
	support_clwb = support_clflushopt = support_clflush = 0;
	if (arch_has_clwb()) {
		eufs_info("arch has CLWB support\n");
		support_clwb = 1;
	}

	if (arch_has_clflushopt()) {
		eufs_info("arch has CLFLUSHOPT support\n");
		support_clflushopt = 1;
	}

	if (arch_has_clflush()) {
		eufs_info("arch has CLFLUSH support\n");
		support_clflush = 1;
	}

	if (!support_clwb && !support_clflushopt && !support_clflush)
		eufs_info("arch has no cache flush support\n");
}

static int eufs_get_block_info(struct super_block *sb, struct eufs_sb_info *sbi)
{
	void *virt_addr = NULL;
	pfn_t pfn;
	long size;
	struct dax_device *dax_dev;
	int srcu_id;

	if (!bdev_dax_supported(sb->s_bdev, PAGE_SIZE)) {
		eufs_err(sb, "device does not support DAX\n");
		return -EINVAL;
	}

	dax_dev = dax_get_by_host(sb->s_bdev->bd_disk->disk_name);
	if (!dax_dev) {
		eufs_err(sb, "device does not support DAX\n");
		return -EINVAL;
	}

	srcu_id = dax_read_lock();
	size = dax_direct_access(
		dax_dev, 0, i_size_read(sb->s_bdev->bd_inode) >> PAGE_SHIFT,
		&virt_addr, &pfn);
	dax_read_unlock(srcu_id);
	if (size < 0) {
		fs_put_dax(dax_dev);
		eufs_err(sb, "device DAX error %ld\n", size);
		return size;
	}

	sbi->s_dax_dev = dax_dev;
	sbi->s_bdev = sb->s_bdev;
	sbi->virt_addr = virt_addr;
	sbi->phys_addr = pfn_t_to_pfn(pfn) << PAGE_SHIFT;
	sbi->initsize = (u64)size << PAGE_SHIFT;

	eufs_info("dev %s virt_addr %px phys_addr %llx size %ld\n",
		  sb->s_bdev->bd_disk->disk_name, sbi->virt_addr,
		  sbi->phys_addr, sbi->initsize);

	return 0;
}

enum {
	Opt_init,
	Opt_dax,
	Opt_err
};

static const match_table_t tokens = {
	{ Opt_init, "init" },
	{ Opt_dax, "dax" }, /* DAX is always on. This is for compatibility. */
	{ Opt_err, NULL },
};

static int eufs_parse_options(char *options, struct eufs_sb_info *sbi,
			      bool remount)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_init:
			if (remount)
				goto bad_opt;
			set_opt(sbi->s_mount_opt, FORMAT);
			break;
		case Opt_dax:
			break;
		default:
			goto bad_opt;
		}
	}

	return 0;

bad_opt:
	eufs_info("Bad mount option: \"%s\"\n", p);
	return -EINVAL;
}

static bool eufs_check_size(struct super_block *sb, unsigned long size)
{
	unsigned long minimum_size;

	/* For Super Block */
	minimum_size = 2 << sb->s_blocksize_bits;
	/* For Bitmaps */
	minimum_size += size / EUFS_BLOCK_SIZE / 8;

	if (size < minimum_size)
		return false;

	return true;
}

static __always_inline int eufs_check_super(struct eufs_super_block *ps,
					    const char *typ)
{
	u16 save_crc = 0;
	u16 calc_crc = 0;
	struct eufs_super_block scratch;

	memcpy(&scratch, ps, sizeof(*ps));
	save_crc = scratch.s_sum;
	scratch.s_sum = 0;
	scratch.s_safe_umount = 0;
	calc_crc = crc16(~0, (__u8 *)&scratch, sizeof(scratch));
	if (save_crc != calc_crc) {
		eufs_warn("Recognizing %s super block failed: crc %x mismatch (%x expected)",
			  typ, calc_crc, save_crc);
		return -EIO;
	}
	if (scratch.s_magic != EUFS_SUPER_MAGIC) {
		eufs_warn("Recognizing %s super block failed: magic %x mismatch (%x expected)",
			  typ, scratch.s_magic, EUFS_SUPER_MAGIC);
		return -EIO;
	}
	return 0;
}

static __always_inline int eufs_recognize_fs(struct super_block *sb)
{
	struct eufs_super_block *super;
	struct eufs_super_block *super2;
	int err;

	super = eufs_get_super(sb);
	super2 = (void *)super + EUFS_SB2_OFFSET;
	err = eufs_check_super(super, "primary");
	if (err) {
		err = eufs_check_super(super2, "secondary");
		if (err)
			return -EIO;

		eufs_info("Secondary super block recognized, syncing back to the primary.\n");
		memcpy(super, super2, sizeof(struct eufs_super_block));
		eufs_flush_buffer(super2, sizeof(*super2), false);
		eufs_pbarrier();
	}
	return 0;
}

static __always_inline void eufs_sync_super(struct eufs_super_block *ps)
{
	u16 crc = 0;
	__le32 saved_safe_umount = ps->s_safe_umount;

	ps->s_safe_umount = 0;
	ps->s_wtime = cpu_to_le32(get_seconds());
	ps->s_sum = 0;
	crc = crc16(~0, (__u8 *)ps, sizeof(struct eufs_super_block));
	ps->s_sum = cpu_to_le16(crc);

	eufs_flush_buffer(ps, sizeof(*ps), false);
	eufs_pbarrier();

	/* Keep sync redundant super block */
	memcpy((void *)ps + EUFS_SB2_OFFSET, (void *)ps,
	       sizeof(struct eufs_super_block));
	eufs_flush_buffer((void *)ps + EUFS_SB2_OFFSET, sizeof(*ps), false);
	eufs_pbarrier();
	ps->s_safe_umount = saved_safe_umount;
}

static struct eufs_inode *eufs_init(struct super_block *sb, unsigned long size)
{
	struct eufs_inode __pmem *root_i;
	struct eufs_super_block __pmem *super;
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct nv_dict *dict;

	eufs_info("creating an empty eulerfs of size %lu\n", size);

	sbi->block_start = 0;
	sbi->block_end = ((unsigned long)(size) >> PAGE_SHIFT);

	if (!sbi->virt_addr) {
		eufs_err(sb, "mapping eulerfs image failed\n");
		return ERR_PTR(-EINVAL);
	}

	sb->s_blocksize_bits = EUFS_BLOCK_SIZE_BITS;
	sbi->blocksize = EUFS_BLOCK_SIZE;

	if (!eufs_check_size(sb, size)) {
		eufs_err(sb, "Specified size too small 0x%lx for EulerFS\n",
			 size);
		return ERR_PTR(-EINVAL);
	}

	super = eufs_get_super(sb);

	super->s_sum = 0;
	super->s_magic = cpu_to_le16(EUFS_SUPER_MAGIC);
	super->s_safe_umount = 0;
	super->s_flag = 0;
	super->s_fs_version = cpu_to_le16(1);
	super->s_size = cpu_to_le64(size);
	super->s_virt_addr = cpu_to_le64(sbi->virt_addr);

	sbi->s_crash_ver = 1;
	super->s_crash_ver = cpu_to_le64(1);

	nv_init(sb, true);
	super->s_page_map = cpu_to_le64(p2o(sb, sbi->page_map));
	super->s_mtime = 0;

	root_i = eufs_malloc_pinode(sb);
	if (!root_i)
		return ERR_PTR(-ENOSPC);

	eufs_info("root_i: %px\n", root_i);
	eufs_alloc_persist(sb, root_i, false);

	super->s_root_pi = p2s(sb, root_i);
	eufs_sync_super(super);

	/* ================ init root dir =============== */
	eufs_iwrite_flags(root_i, 0);
	eufs_iwrite_mode(root_i, S_IRUGO | S_IXUGO | S_IWUSR | S_IFDIR);
	eufs_iwrite_version(root_i, 1);
	eufs_iwrite_ctime(root_i, get_seconds());
	eufs_iwrite_ctime_nsec(root_i, 0);
	eufs_iwrite_uid(root_i, from_kuid(&init_user_ns, current_fsuid()));
	eufs_iwrite_gid(root_i, from_kgid(&init_user_ns, current_fsgid()));
	eufs_iwrite_dotdot(root_i, p2o(sb, root_i));
	eufs_iwrite_ext(root_i, 0); /* no ext here */
	eufs_iwrite_generation(root_i, 0);
	eufs_iwrite_nlink(root_i, 2);
	eufs_iwrite_mtime(root_i, get_seconds());
	eufs_iwrite_atime(root_i, get_seconds());
	eufs_iwrite_mtime_nsec(root_i, 0);
	eufs_iwrite_atime_nsec(root_i, 0);
	dict = eufs_zalloc_htable(sb);
	if (!dict)
		return ERR_PTR(-ENOSPC);
	eufs_alloc_persist(sb, dict, false);
	eufs_flush_range(dict, sizeof(struct nv_dict));

	eufs_iwrite_dict(root_i, p2o(sb, dict));
	eufs_iwrite_size(root_i, 0);

	root_i->i_fresh = 2;
	eufs_flush_cacheline(root_i);
	eufs_flush_cacheline(&root_i->i_fresh);
	EUFS_TWIN_PI(root_i)->i_fresh = 1;
	eufs_flush_cacheline(&EUFS_TWIN_PI(root_i)->i_fresh);

	eufs_pbarrier();
	return root_i;
}

static void eufs_destroy_super(struct super_block *sb)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	wear_fini(sb);

	dep_fini(sb);

	nv_fini(sb);

	if (sbi->virt_addr)
		sbi->virt_addr = NULL;
	if (sbi->s_dax_dev)
		fs_put_dax(sbi->s_dax_dev);

	sb->s_fs_info = NULL;

	kfree(sbi);
}

static int eufs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct eufs_super_block __pmem *super;
	struct eufs_inode __pmem *root_pi;
	struct eufs_sb_info *sbi = NULL;
	struct inode *root_i = NULL;
	u32 random = 0;
	int err;

	BUILD_BUG_ON(sizeof(struct eufs_super_block) > EUFS_SB_SIZE);
	BUILD_BUG_ON(sizeof(struct eufs_inode) != 2 * CACHELINE_SIZE);
	BUILD_BUG_ON(sizeof(struct nv_dict_entry) != CACHELINE_SIZE);

	eufs_detect_features();

	sbi = kzalloc(sizeof(struct eufs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->s_draining = false;
	init_waitqueue_head(&sbi->s_draining_wq);
	atomic_set(&sbi->s_nr_dirty_inodes, 0);
	atomic_set(&sbi->s_nr_dep_nodes, 0);

	sb->s_fs_info = sbi;

	err = eufs_get_block_info(sb, sbi);
	if (err)
		goto out;

	get_random_bytes(&random, sizeof(u32));
	atomic_set(&sbi->next_generation, random);

	mutex_init(&sbi->s_lock);
	mutex_init(&sbi->gather_mutex);
	mutex_init(&sbi->sync_mutex);

	err = eufs_parse_options(data, sbi, 0);
	if (err)
		goto out;

	super = eufs_get_super(sb);

	/* Init a new EulerFS instance */
	if (test_opt(sb, FORMAT)) {
		root_pi = eufs_init(sb, sbi->initsize);
		if (IS_ERR(root_pi)) {
			err = PTR_ERR(root_pi);
			goto out;
		}

		goto setup_sb;
	}

	err = eufs_recognize_fs(sb);
	if (err) {
		eufs_crit("No valid EulerFS found. Are you trying to mount a wrong fs?\n");
		goto out;
	}

	sbi->block_start = 0;
	sbi->block_end = ((unsigned long)(super->s_size) >> PAGE_SHIFT);
	sb->s_blocksize_bits = EUFS_BLOCK_SIZE_BITS;
	sbi->blocksize = EUFS_BLOCK_SIZE;

	sbi->page_map = (void *)o2p(sb, super->s_page_map);
	sbi->initsize = (u64)super->s_size;
	eufs_get_layout(sb, false);

	sbi->s_crash_ver = le64_to_cpu(super->s_crash_ver);

	if (!super->s_safe_umount) {
		super->s_crash_ver = cpu_to_le64(++sbi->s_crash_ver);
		eufs_flush_cacheline(&super->s_crash_ver);
		eufs_pbarrier();
	}

	nv_init(sb, false);

	root_pi = (struct eufs_inode *)s2p(sb, super->s_root_pi);

setup_sb:
	super->s_safe_umount = 0;
	eufs_flush_cacheline(&super->s_safe_umount);
	eufs_pbarrier();

	sbi->s_crash_ver = le64_to_cpu(super->s_crash_ver);

	sb->s_magic = le16_to_cpu(super->s_magic);
	sb->s_op = &eufs_sops;
	sb->s_maxbytes = EUFS_MAX_FILE_SIZE;
	sb->s_time_gran = NSEC_PER_SEC;

	err = dep_init(sb);
	if (err)
		goto out;

	wear_init(sb);

	root_i = eufs_iget(sb, root_pi);
	if (IS_ERR(root_i)) {
		err = PTR_ERR(root_i);
		goto out;
	}

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		eufs_err(sb, "alloc root dentry failed\n");
		err = -ENOMEM;
		goto out;
	}

	if (!(sb->s_flags & MS_RDONLY)) {
		u64 mnt_write_time;
		/* update mount time and write time atomically. */
		mnt_write_time = (get_seconds() & 0xFFFFFFFF);
		mnt_write_time = mnt_write_time | (mnt_write_time << 32);

		super->s_mtime = mnt_write_time;

		eufs_flush_buffer(&super->s_mtime, 8, false);
		eufs_pbarrier();
	}

	return 0;

out:
	eufs_destroy_super(sb);
	return err;
}

static int eufs_statfs(struct dentry *d, struct kstatfs *buf)
{
	struct super_block *sb = d->d_sb;
	struct eufs_sb_info *sbi = (struct eufs_sb_info *)sb->s_fs_info;

	u64 npage, ncl;

	nv_stat(sbi, &npage, &ncl);

	buf->f_type = EUFS_SUPER_MAGIC;
	buf->f_bsize = PAGE_SIZE;

	buf->f_blocks = sbi->block_end;

	buf->f_bfree = npage;
	buf->f_bavail = npage;

	buf->f_files = ncl;
	buf->f_ffree = ncl;

	buf->f_namelen = EUFS_MAX_NAME_LEN;
	print_stats(sbi);

	return 0;
}

static int eufs_show_options(struct seq_file *seq, struct dentry *root)
{
	seq_puts(seq, ",dax");

	return 0;
}

static int eufs_remount(struct super_block *sb, int *mntflags, char *data)
{
	unsigned long old_sb_flags;
	unsigned long old_mount_opt;
	struct eufs_super_block *ps;
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	int ret = -EINVAL;

	/* Store the old options */
	mutex_lock(&sbi->s_lock);
	old_sb_flags = sb->s_flags;
	old_mount_opt = sbi->s_mount_opt;

	if (eufs_parse_options(data, sbi, 1))
		goto restore_opt;

	if ((*mntflags & MS_RDONLY) != (sb->s_flags & MS_RDONLY)) {
		u64 mnt_write_time;

		ps = eufs_get_super(sb);
		/* update mount time and write time atomically. */
		mnt_write_time = (get_seconds() & 0xFFFFFFFF);
		mnt_write_time = mnt_write_time | (mnt_write_time << 32);

		ps->s_mtime = mnt_write_time;

		eufs_flush_buffer(&ps->s_mtime, 8, false);
		eufs_pbarrier();
	}

	mutex_unlock(&sbi->s_lock);
	ret = 0;
	return ret;

restore_opt:
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_mount_opt;
	mutex_unlock(&sbi->s_lock);
	return ret;
}

static void eufs_put_super(struct super_block *sb)
{
	struct eufs_super_block *super;

	super = eufs_get_super(sb);

	eufs_sync_super(super);

	super->s_safe_umount = 1;
	eufs_flush_cacheline(&super->s_safe_umount);
	eufs_pbarrier();

	eufs_info("safe unmount.\n");
	eufs_destroy_super(sb);
}

static struct inode *eufs_alloc_inode(struct super_block *sb)
{
	struct eufs_inode_info *vi;

	vi = eufs_alloc_vi();
	if (!vi)
		return NULL;

	INIT_LIST_HEAD(&vi->i_dep_list);

	vi->i_next_dep_seq = 1;
	vi->i_persisted_dep_seq = 0;

	spin_lock_init(&vi->i_owner_lock);
	INIT_LIST_HEAD(&vi->i_owner_list);

	vi->i_lock_transferred = I_TRANS_NONE;
	vi->i_is_persisting = false;
	vi->i_is_dirty = false;

	vi->i_volatile_root = NULL;
	vi->i_volatile_height = 0;

	vi->i_dotdot = 0;

	atomic64_set(&vi->vfs_inode.i_version, 1);

	vi->page_batch.size = 0;
	vi->page_batch.n_used = -1;
	vi->page_batch.batch = NULL;
	INIT_LIST_HEAD(&vi->page_batch.list);

	vi->i_volatile_dict = NULL;

	mutex_init(&vi->i_urgent_mutex);
	mutex_init(&vi->i_dep_lock);
	mutex_init(&vi->i_header_lock);

	init_rwsem(&vi->mmap_rwsem);
	spin_lock_init(&vi->i_dentry_persist_lock);
	mutex_init(&vi->i_leaf_lock);

	return &vi->vfs_inode;
}

static void eufs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	eufs_alloc_batch_fini(&EUFS_I(inode)->page_batch);
	eufs_free_vi(EUFS_I(inode));
}

static void eufs_destroy_inode(struct inode *inode)
{
	if (EUFS_I(inode)->i_volatile_dict) {
		eufs_free_page(EUFS_I(inode)->i_volatile_dict);
		EUFS_I(inode)->i_volatile_dict = NULL;
	}
	call_rcu(&inode->i_rcu, eufs_i_callback);
}

static int eufs_sync_fs(struct super_block *sb, int sync)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	int i;
	int num_persisters = num_sockets * persisters_per_socket;
	int wait_flag;

	if (!sync)
		return 0;

	mutex_lock(&sbi->sync_mutex);

	for (i = 0; i < num_persisters; i++)
		sbi->need_sync[i] = true;

	/* FIXME: Persisters may miss the wake-up message. */
	for (i = 0; i < num_persisters; ++i)
		wake_up_process(sbi->persisters[i]);

	do {
		wait_flag = false;
		for (i = 0; i < num_persisters; i++) {
			if (sbi->need_sync[i] == false)
				continue;
			wait_flag = true;
			wait_event_interruptible(sbi->sync_wq,
						 (sbi->need_sync[i] == false));
		}
	} while (wait_flag);

	mutex_unlock(&sbi->sync_mutex);

	return 0;
}

/*
 * the super block writes are all done "on the fly", so the
 * super block is never in a "dirty" state, so there's no need
 * for write_super.
 */
static struct super_operations eufs_sops = {
	.alloc_inode = eufs_alloc_inode,
	.destroy_inode = eufs_destroy_inode,
	.write_inode = eufs_write_inode,
	.evict_inode = eufs_evict_inode,
	.put_super = eufs_put_super,
	.statfs = eufs_statfs,
	.remount_fs = eufs_remount,
	.show_options = eufs_show_options,
	.sync_fs = eufs_sync_fs,
};

static struct dentry *eufs_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, eufs_fill_super);
}

static struct file_system_type eufs_fs_type = {
	.owner = THIS_MODULE,
	.name = "eulerfs",
	.mount = eufs_mount,
	.kill_sb = kill_block_super,
};

static int __init init_eufs_fs(void)
{
	int rc = 0;
	int cpu;

	BUILD_BUG_ON(sizeof(struct eufs_renamej) != 2 * CACHELINE_SIZE);

	rc = init_page_cache();
	if (rc)
		goto out1;

	rc = init_inodecache();
	if (rc)
		goto out2;

	rc = init_dep_node_cache();
	if (rc)
		goto out3;

	rc = register_filesystem(&eufs_fs_type);
	if (rc)
		goto out4;

	num_sockets = 0;
	for_each_possible_cpu(cpu) {
		int sock = cpu_to_node(cpu);

		if (sock > num_sockets)
			num_sockets = sock;
	}
	num_sockets += 1;
	eufs_info("Num socket: %d\n", num_sockets);

	eufs_show_params();

	return 0;

out4:
	destroy_dep_node_cache();
out3:
	destroy_inodecache();
out2:
	destroy_page_cache();
out1:
	return rc;
}

static void __exit exit_eufs_fs(void)
{
	unregister_filesystem(&eufs_fs_type);
	destroy_inodecache();
	destroy_dep_node_cache();
	destroy_page_cache();
}

module_init(init_eufs_fs);
module_exit(exit_eufs_fs);

MODULE_DESCRIPTION("EulerFS");
MODULE_LICENSE("GPL");
