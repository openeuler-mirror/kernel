/*
 * Copyright (C) 2022, Alibaba Cloud
 */
#include <linux/fscache.h>
#include "internal.h"

struct fscache_netfs erofs_fscache_netfs = {
	.name = "erofs",
	.version = 0,
};

int erofs_fscache_register(void)
{
	return fscache_register_netfs(&erofs_fscache_netfs);
}

void erofs_fscache_unregister(void)
{
	fscache_unregister_netfs(&erofs_fscache_netfs);
}

const struct fscache_cookie_def erofs_fscache_super_index_def = {
	.name = "EROFS.super",
	.type = FSCACHE_COOKIE_TYPE_INDEX,
	.check_aux = NULL,
};

const struct fscache_cookie_def erofs_fscache_inode_object_def = {
	.name           = "EROFS.uniqueid",
	.type           = FSCACHE_COOKIE_TYPE_DATAFILE,
};

static void erofs_readpage_from_fscache_complete(struct page *page, void *ctx,
						 int error)
{
	if (!error)
		SetPageUptodate(page);
	unlock_page(page);
}

static int erofs_fscache_meta_readpage(struct file *data, struct page *page)
{
	int ret;
	struct super_block *sb = page->mapping->host->i_sb;
	struct erofs_map_dev mdev = {
		.m_deviceid = 0,
		.m_pa = page_offset(page),
	};

	ret = erofs_map_dev(sb, &mdev);
	if (ret)
		goto out;

	ret = fscache_read_or_alloc_page(mdev.m_fscache->cookie, page,
					 erofs_readpage_from_fscache_complete,
					 NULL,
					 GFP_KERNEL);
	switch (ret) {
	case 0: /* page found in fscache, read submitted */
		erofs_dbg("%s: submitted", __func__);
		return ret;
	case -ENOBUFS:	/* page won't be cached */
	case -ENODATA:	/* page not in cache */
		erofs_err(sb, "%s: %d", __func__, ret);
		ret = -EIO;
		goto out;
	default:
		erofs_err(sb, "unknown error ret = %d", ret);
	}

out:
	unlock_page(page);
	return ret;
}

static int erofs_fscache_release_page(struct page *page, gfp_t gfp)
{
	if (WARN_ON(PagePrivate(page)))
		return 0;

	ClearPageFsCache(page);
	return 1;
}

static void erofs_fscache_invalidate_page(struct page *page, unsigned int offset,
					  unsigned int length)
{
	if (offset == 0 && length == PAGE_SIZE)
		ClearPageFsCache(page);
}

static int erofs_fscache_readpage_inline(struct page *page,
					 struct erofs_map_blocks *map)
{
	struct super_block *sb = page->mapping->host->i_sb;
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	erofs_blk_t blknr;
	size_t offset, len;
	void *src, *dst;

	/* For tail packing layout, the offset may be non-zero. */
	offset = erofs_blkoff(map->m_pa);
	blknr = erofs_blknr(map->m_pa);
	len = map->m_llen;

	src = erofs_read_metabuf(&buf, sb, blknr, EROFS_KMAP_ATOMIC);
	if (IS_ERR(src))
		return PTR_ERR(src);

	dst = kmap_atomic(page);
	memcpy(dst, src + offset, len);
	memset(dst + len, 0, PAGE_SIZE - len);
	kunmap_atomic(dst);

	erofs_put_metabuf(&buf);
	SetPageUptodate(page);
	return 0;
}

static int erofs_fscache_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct erofs_map_blocks map;
	struct erofs_map_dev mdev;
	erofs_off_t pos = page_offset(page);
	loff_t pstart;
	int ret;

	map.m_la = pos;
	ret = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW);
	if (ret)
		goto out_unlock;

	if (!(map.m_flags & EROFS_MAP_MAPPED)) {
		zero_user_segment(page, 0, PAGE_SIZE);
		SetPageUptodate(page);
		goto out_unlock;
	}

	if (map.m_flags & EROFS_MAP_META) {
		ret = erofs_fscache_readpage_inline(page, &map);
		goto out_unlock;
	}

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};

	ret = erofs_map_dev(sb, &mdev);
	if (ret)
		goto out_unlock;

	pstart = mdev.m_pa + (pos - map.m_la);
	ret = fscache_read_or_alloc_page2(mdev.m_fscache->cookie, page,
					 erofs_readpage_from_fscache_complete,
					 NULL,
					 GFP_KERNEL, pstart);
	switch (ret) {
	case 0: /* page found in fscache, read submitted */
		erofs_dbg("%s: submitted", __func__);
		return ret;
	case -ENOBUFS:	/* page won't be cached */
	case -ENODATA:	/* page not in cache */
		erofs_err(sb, "%s: %d", __func__, ret);
		ret = -EIO;
		goto out_unlock;
	default:
		erofs_err(sb, "unknown error ret = %d", ret);
	}

out_unlock:
	unlock_page(page);
	return ret;
}

static const struct address_space_operations erofs_fscache_meta_aops = {
	.readpage = erofs_fscache_meta_readpage,
	.releasepage = erofs_fscache_release_page,
	.invalidatepage = erofs_fscache_invalidate_page,
};

const struct address_space_operations erofs_fscache_access_aops = {
	.readpage = erofs_fscache_readpage,
	.releasepage = erofs_fscache_release_page,
	.invalidatepage = erofs_fscache_invalidate_page,
};

int erofs_fscache_register_cookie(struct super_block *sb,
				  struct erofs_fscache **fscache,
				  char *name, bool need_inode)
{
	struct erofs_fscache *ctx;
	struct fscache_cookie *cookie;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	cookie = fscache_acquire_cookie(EROFS_SB(sb)->volume,
					&erofs_fscache_inode_object_def,
					name, strlen(name),
					NULL, 0, NULL, 0, true);
	if (!cookie) {
		erofs_err(sb, "failed to get cookie for %s", name);
		ret = -EINVAL;
		goto err;
	}

	//fscache_use_cookie(cookie, false);
	ctx->cookie = cookie;

	if (need_inode) {
		struct inode *const inode = new_inode(sb);

		if (!inode) {
			erofs_err(sb, "failed to get anon inode for %s", name);
			ret = -ENOMEM;
			goto err_cookie;
		}

		set_nlink(inode, 1);
		inode->i_size = OFFSET_MAX;
		inode->i_mapping->a_ops = &erofs_fscache_meta_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_NOFS);

		ctx->inode = inode;
	}

	*fscache = ctx;
	return 0;

err_cookie:
//	fscache_unuse_cookie(ctx->cookie, NULL, NULL);
	fscache_relinquish_cookie(ctx->cookie, NULL, false);
	ctx->cookie = NULL;
err:
	kfree(ctx);
	return ret;
}

void erofs_fscache_unregister_cookie(struct erofs_fscache **fscache)
{
	struct erofs_fscache *ctx = *fscache;

	if (!ctx)
		return;

	//fscache_unuse_cookie(ctx->cookie, NULL, NULL);
	fscache_relinquish_cookie(ctx->cookie, NULL, false);
	ctx->cookie = NULL;

	iput(ctx->inode);
	ctx->inode = NULL;

	kfree(ctx);
	*fscache = NULL;
}

int erofs_fscache_register_fs(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct fscache_cookie *volume;
	char *name;
	int ret = 0;

	name = kasprintf(GFP_KERNEL, "erofs,%s", sbi->opt.fsid);
	if (!name)
		return -ENOMEM;

	volume = fscache_acquire_cookie(erofs_fscache_netfs.primary_index,
			&erofs_fscache_super_index_def, name, strlen(name),
			NULL, 0, NULL, 0, true);
	if (IS_ERR_OR_NULL(volume)) {
		erofs_err(sb, "failed to register volume for %s", name);
		ret = volume ? PTR_ERR(volume) : -EOPNOTSUPP;
		volume = NULL;
	}
	sbi->volume = volume;
	kfree(name);
	return ret;
}

void erofs_fscache_unregister_fs(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	fscache_relinquish_cookie(sbi->volume, NULL, false);
	sbi->volume = NULL;
}
