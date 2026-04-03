// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */

#include "internal.h"

#include <linux/module.h>
#include <linux/magic.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/delay.h>
#include <linux/string.h>

#define CREATE_TRACE_POINTS
#include <trace/events/mfs.h>

/*
 * Used for alloc_inode
 */
static struct kmem_cache *mfs_inode_cachep;

/*
 * Used for dentry info
 */
static struct kmem_cache *mfs_dentry_cachep;

static void mfs_init_once(void *obj)
{
	struct mfs_inode *i = obj;

	inode_init_once(&i->vfs_inode);
}

static struct inode *mfs_alloc_inode(struct super_block *sb)
{
	struct mfs_inode *vi = alloc_inode_sb(sb, mfs_inode_cachep, GFP_KERNEL);

	if (!vi)
		return NULL;
	memset(vi, 0, offsetof(struct mfs_inode, vfs_inode));
	mutex_init(&vi->lock);
	return &vi->vfs_inode;
}

static void mfs_free_inode(struct inode *inode)
{
	struct mfs_inode *vi = MFS_I(inode);

	kmem_cache_free(mfs_inode_cachep, vi);
}

static void mfs_evict_inode(struct inode *inode)
{
	struct mfs_inode *vi = MFS_I(inode);
	struct inode *lower_inode = vi->lower;
	struct inode *cache_inode = vi->cache;

	truncate_inode_pages_final(&inode->i_data);
	if (inode->i_private)
		mfs_free_object(inode->i_private);
	clear_inode(inode);
	if (lower_inode) {
		vi->lower = NULL;
		iput(lower_inode);
	}
	if (cache_inode) {
		vi->cache = NULL;
		iput(cache_inode);
	}
}

int mfs_alloc_dentry_info(struct dentry *dentry)
{
	struct mfs_dentry_info *info =
		kmem_cache_zalloc(mfs_dentry_cachep, GFP_ATOMIC);

	if (!info)
		return -ENOMEM;
	spin_lock_init(&info->lock);
	dentry->d_fsdata = info;
	return 0;
}

void mfs_free_dentry_info(struct dentry *dentry)
{
	if (!dentry || !dentry->d_fsdata)
		return;

	kmem_cache_free(mfs_dentry_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

static void mfs_d_release(struct dentry *dentry)
{
	/* for root, the path will release with super block */
	if (!IS_ROOT(dentry))
		mfs_release_path(dentry);

	mfs_free_dentry_info(dentry);
}

static const struct dentry_operations mfs_dops = {
	.d_release	= mfs_d_release,
};

static int mfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct mfs_sb_info *sbi = MFS_SB(dentry->d_sb);
	int err = vfs_statfs(&sbi->cache, buf);

	buf->f_type = MFS_SUPER_MAGIC;
	/* Use the reserved slot to keep the device id */
	buf->f_spare[0] = sbi->minor;
	return err;
}

static int mfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct mfs_sb_info *sbi = MFS_SB(root->d_sb);

	if (sbi->mtree)
		seq_show_option(seq, "mtree", sbi->mtree);
	if (sbi->cachedir)
		seq_show_option(seq, "cachedir", sbi->cachedir);
	switch (sbi->mode) {
	case MFS_MODE_NONE:
		seq_puts(seq, ",mode=none");
		break;
	case MFS_MODE_LOCAL:
		seq_puts(seq, ",mode=local");
		break;
	case MFS_MODE_REMOTE:
		seq_puts(seq, ",mode=remote");
		break;
	}
	return 0;
}

static const struct super_operations mfs_sops = {
	.alloc_inode	= mfs_alloc_inode,
	.free_inode	= mfs_free_inode,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= mfs_evict_inode,
	.statfs		= mfs_statfs,
	.show_options	= mfs_show_options,
};

enum {
	Opt_mtree,
	Opt_cachedir,
	Opt_mode,
};

static const struct constant_table mfs_param_mode[] = {
	{"none", MFS_MODE_NONE},
	{"local", MFS_MODE_LOCAL},
	{"remote", MFS_MODE_REMOTE},
	{}
};

static const struct fs_parameter_spec mfs_fs_parameters[] = {
	fsparam_string("mtree", Opt_mtree),
	fsparam_string("cachedir", Opt_cachedir),
	fsparam_enum("mode", Opt_mode, mfs_param_mode),
	{}
};

static char *remove_trailing(char *s, char c)
{
	size_t size;
	char *end;

	size = strlen(s);
	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && c == *end)
		end--;
	*(end + 1) = '\0';
	return s;
}

static char *_acquire_set_path(char *inputpath, struct path *target)
{
	char *p, *realp, *path;
	char *res;
	int ret = 0;

	p = kstrdup(inputpath, GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);
	realp = remove_trailing(p, '/');
	if (strlen(realp) == 0) {
		kfree(p);
		return ERR_PTR(-EINVAL);
	}
	ret = kern_path(realp, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, target);
	kfree(p);
	if (ret)
		return ERR_PTR(ret);

	path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!path) {
		path_put(target);
		return ERR_PTR(-ENOMEM);
	}

	realp = d_path(target, path, PATH_MAX);
	if (IS_ERR(realp)) {
		path_put(target);
		res = realp;
		goto free;
	}

	res = kstrdup(realp, GFP_KERNEL);
	if (!res) {
		path_put(target);
		res = ERR_PTR(-ENOMEM);
	}
free:
	kfree(path);
	return res;
}

static int mfs_fc_parse_param(struct fs_context *fc,
				    struct fs_parameter *param)
{
	struct mfs_sb_info *sbi = fc->s_fs_info;
	struct fs_parse_result result;
	struct path target;
	char *p;
	int opt;

	opt = fs_parse(fc, mfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_mtree:
		p = _acquire_set_path(param->string, &target);
		if (IS_ERR(p))
			return PTR_ERR(p);
		sbi->mtree = p;
		pathcpy(&sbi->lower, &target);
		break;
	case Opt_cachedir:
		p = _acquire_set_path(param->string, &target);
		if (IS_ERR(p))
			return PTR_ERR(p);
		sbi->cachedir = p;
		pathcpy(&sbi->cache, &target);
		break;
	case Opt_mode:
		sbi->mode = result.int_32;
		break;
	default:
		return -ENOPARAM;
	}
	return 0;
}

static int mfs_fc_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct mfs_sb_info *sbi = MFS_SB(sb);
	struct inode *inode;
	int err = 0;

	if (!sbi->cachedir || !sbi->mtree) {
		pr_err("Lack of mtree or cachedir option.\n");
		return -EINVAL;
	}

	if (sbi->mode != MFS_MODE_REMOTE) {
		if (strcmp(sbi->cachedir, sbi->mtree)) {
			pr_err("local/none mode require the same mtree and cachedir.\n");
			return -EINVAL;
		}
	} else {
		if (!strcmp(sbi->cachedir, sbi->mtree)) {
			pr_err("remote mode require different mtree and cachedir.\n");
			return -EINVAL;
		}
		if (strlen(sbi->cachedir) > strlen(sbi->mtree) &&
			strncmp(sbi->mtree, sbi->cachedir, strlen(sbi->mtree)) == 0) {
			pr_err("remote mode mtree should not be parent of cachedir.\n");
			return -EINVAL;
		}
	}

	sb->s_stack_depth = max(sbi->lower.mnt->mnt_sb->s_stack_depth,
				sbi->cache.mnt->mnt_sb->s_stack_depth) + 1;
	if (sb->s_stack_depth > 1) {
		pr_err("cannot be stacked on other stackable file system.\n");
		return -EINVAL;
	}

	sb->s_magic = MFS_SUPER_MAGIC;
	sb->s_flags |= SB_RDONLY | SB_NOATIME;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &mfs_sops;
	sb->s_d_op = &mfs_dops;
	err = super_setup_bdi(sb);
	if (err)
		return err;

	if (support_event(sbi)) {
		err = mfs_fs_dev_init(sb);
		if (err)
			return err;
	}

	inode = mfs_iget(sb, d_inode(sbi->lower.dentry), &sbi->cache);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_exit;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}

	err = mfs_alloc_dentry_info(sb->s_root);
	if (err)
		goto out_dput;
	mfs_install_path(sb->s_root, &sbi->lower, &sbi->cache);
	sbi->sb = sb;
	set_bit(MFS_MOUNTED, &sbi->flags);
	return 0;
out_dput:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_exit:
	if (support_event(sbi))
		mfs_fs_dev_exit(sb);
	return err;
}

static int mfs_fc_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, mfs_fc_fill_super);
}

static int mfs_reconfigure(struct fs_context *fc)
{
	return -EOPNOTSUPP;
}

static void mfs_fc_free(struct fs_context *fc)
{
	struct mfs_sb_info *sbi = fc->s_fs_info;

	if (!sbi)
		return;

	if (sbi->mtree) {
		path_put(&sbi->lower);
		kfree(sbi->mtree);
	}
	if (sbi->cachedir) {
		path_put(&sbi->cache);
		kfree(sbi->cachedir);
	}
	kfree(sbi);
}

static const struct fs_context_operations mfs_context_ops = {
	.parse_param	= mfs_fc_parse_param,
	.get_tree	= mfs_fc_get_tree,
	.reconfigure	= mfs_reconfigure,
	.free		= mfs_fc_free,
};

static int mfs_init_fs_context(struct fs_context *fc)
{
	struct mfs_sb_info *sbi;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	init_waitqueue_head(&sbi->caches.pollwq);
	xa_init_flags(&sbi->caches.events, XA_FLAGS_ALLOC);
	sbi->minor = -1;
	fc->s_fs_info = sbi;
	fc->ops = &mfs_context_ops;
	return 0;
}

static void mfs_kill_sb(struct super_block *sb)
{
	struct mfs_sb_info *sbi = MFS_SB(sb);
	struct mfs_caches *caches = &sbi->caches;

	smp_mb__before_atomic();
	clear_bit(MFS_MOUNTED, &sbi->flags);
	smp_mb__after_atomic();
	if (support_event(sbi)) {
		/* The barrier pair to make sure flags is new */
		smp_mb__before_atomic();
		while (test_bit(MFS_CACHE_OPENED, &caches->flags)) {
			static DEFINE_RATELIMIT_STATE(busy_open, 30 * HZ, 1);

			wake_up_all(&caches->pollwq);
			msleep(100);
			if (!__ratelimit(&busy_open))
				continue;
			pr_warn("Pending until close the /dev/mfs%u...\n", sbi->minor);
		}
		/* Ensure flags status is updated */
		smp_mb__after_atomic();
		mfs_fs_dev_exit(sb);
	}
	mfs_destroy_events(sb);
	kill_anon_super(sb);
	if (sbi->mtree) {
		path_put(&sbi->lower);
		kfree(sbi->mtree);
	}
	if (sbi->cachedir) {
		path_put(&sbi->cache);
		kfree(sbi->cachedir);
	}
	kfree(sbi);
	sb->s_fs_info = NULL;
}

static struct file_system_type mfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= MFS_NAME,
	.init_fs_context = mfs_init_fs_context,
	.kill_sb	= mfs_kill_sb,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(MFS_NAME);

static int __init init_mfs_fs(void)
{
	int err;

	mfs_inode_cachep =
		kmem_cache_create("mfs_inode",
				  sizeof(struct mfs_inode), 0,
				  SLAB_RECLAIM_ACCOUNT, mfs_init_once);
	if (!mfs_inode_cachep)
		return -ENOMEM;

	mfs_dentry_cachep =
		kmem_cache_create("mfs_dentry",
				  sizeof(struct mfs_dentry_info), 0,
				  SLAB_RECLAIM_ACCOUNT, NULL);
	if (!mfs_dentry_cachep) {
		err = -ENOMEM;
		goto err_dentryp;
	}

	err = mfs_cache_init();
	if (err)
		goto err_cache;

	err = register_filesystem(&mfs_fs_type);
	if (err)
		goto err_register;

	err = mfs_dev_init();
	if (err)
		goto err_dev;

	pr_info("MFS module loaded\n");
	return 0;
err_dev:
	unregister_filesystem(&mfs_fs_type);
err_register:
	mfs_cache_exit();
err_cache:
	kmem_cache_destroy(mfs_dentry_cachep);
err_dentryp:
	kmem_cache_destroy(mfs_inode_cachep);
	return err;
}

static void __exit exit_mfs_fs(void)
{
	mfs_dev_exit();
	unregister_filesystem(&mfs_fs_type);

	/* Make sure all delayed rcu free inodes are safe to be destroyed. */
	rcu_barrier();
	mfs_cache_exit();
	kmem_cache_destroy(mfs_dentry_cachep);
	kmem_cache_destroy(mfs_inode_cachep);
	pr_info("MFS module unload\n");
}

module_init(init_mfs_fs);
module_exit(exit_mfs_fs);

MODULE_AUTHOR("Hongbo Li <lihongbo22@huawei.com>");
MODULE_AUTHOR("Xiaojia Huang <huangxiaojia2@huawei.com>");
MODULE_DESCRIPTION("MFS filesystem for Linux");
MODULE_LICENSE("GPL");
