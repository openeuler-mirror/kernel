// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/jhash.h>
#include "common/mod_hdr.h"

static u32 hash_mod_hdr_info(struct mod_hdr_key *key)
{
	return jhash(key->actions,
		     key->num_actions * XSC_MH_ACT_SZ, 0);
}

static int cmp_mod_hdr_info(struct mod_hdr_key *a, struct mod_hdr_key *b)
{
	if (a->num_actions != b->num_actions)
		return 1;

	return memcmp(a->actions, b->actions,
		      a->num_actions * XSC_MH_ACT_SZ);
}

void xsc_mod_hdr_tbl_init(struct mod_hdr_tbl *tbl)
{
	mutex_init(&tbl->lock);
	hash_init(tbl->hlist);
}

void xsc_mod_hdr_tbl_destroy(struct mod_hdr_tbl *tbl)
{
	WARN_ON(!hash_empty(tbl->hlist));
	mutex_destroy(&tbl->lock);
}

static struct xsc_mod_hdr_handle *mod_hdr_get(struct mod_hdr_tbl *tbl,
					      struct mod_hdr_key *key,
					      u32 hash_key)
{
	struct xsc_mod_hdr_handle *mh, *found = NULL;

	hash_for_each_possible(tbl->hlist, mh, mod_hdr_hlist, hash_key) {
		if (!cmp_mod_hdr_info(&mh->key, key)) {
			refcount_inc(&mh->refcnt);
			found = mh;
			break;
		}
	}

	return found;
}

struct xsc_mod_hdr_handle *
xsc_mod_hdr_attach(struct xsc_core_device *xdev, struct mod_hdr_tbl *tbl,
		   enum xsc_flow_namespace_type namespace,
		   struct xsc_tc_mod_hdr_acts *mod_hdr_acts)
{
	int num_actions, actions_size, err;
	struct xsc_mod_hdr_handle *mh;
	struct mod_hdr_key key;
	u32 hash_key;

	num_actions  = mod_hdr_acts->num_actions;
	actions_size = XSC_MH_ACT_SZ * num_actions;

	key.actions = mod_hdr_acts->actions;
	key.num_actions = num_actions;

	hash_key = hash_mod_hdr_info(&key);

	mutex_lock(&tbl->lock);
	mh = mod_hdr_get(tbl, &key, hash_key);
	if (mh) {
		mutex_unlock(&tbl->lock);
		wait_for_completion(&mh->res_ready);

		if (mh->compl_result < 0) {
			err = -EREMOTEIO;
			goto attach_header_err;
		}
		goto attach_header;
	}

	mh = kzalloc(sizeof(*mh) + actions_size, GFP_KERNEL);
	if (!mh) {
		mutex_unlock(&tbl->lock);
		return ERR_PTR(-ENOMEM);
	}

	mh->key.actions = (void *)mh + sizeof(*mh);
	memcpy(mh->key.actions, key.actions, actions_size);
	mh->key.num_actions = num_actions;
	refcount_set(&mh->refcnt, 1);
	init_completion(&mh->res_ready);

	hash_add(tbl->hlist, &mh->mod_hdr_hlist, hash_key);
	mutex_unlock(&tbl->lock);

	mh->modify_hdr = xsc_modify_header_alloc(xdev, namespace,
						 mh->key.num_actions,
						 mh->key.actions);
	if (IS_ERR(mh->modify_hdr)) {
		err = PTR_ERR(mh->modify_hdr);
		mh->compl_result = err;
		goto alloc_header_err;
	}
	mh->compl_result = 1;
	complete_all(&mh->res_ready);

attach_header:
	return mh;

alloc_header_err:
	complete_all(&mh->res_ready);
attach_header_err:
	xsc_mod_hdr_detach(xdev, tbl, mh);
	return ERR_PTR(err);
}

void xsc_mod_hdr_detach(struct xsc_core_device *xdev,
			struct mod_hdr_tbl *tbl,
			struct xsc_mod_hdr_handle *mh)
{
	if (!refcount_dec_and_mutex_lock(&mh->refcnt, &tbl->lock))
		return;
	hash_del(&mh->mod_hdr_hlist);
	mutex_unlock(&tbl->lock);

	if (mh->compl_result > 0)
		xsc_modify_header_dealloc(xdev, mh->modify_hdr);

	kfree(mh);
}

struct xsc_modify_hdr *xsc_mod_hdr_get(struct xsc_mod_hdr_handle *mh)
{
	return mh->modify_hdr;
}

char *xsc_mod_hdr_alloc(struct xsc_core_device *xdev, int namespace,
			struct xsc_tc_mod_hdr_acts *mod_hdr_acts)
{
	int new_num_actions, max_hw_actions;
	size_t new_sz, old_sz;
	void *ret;

	if (mod_hdr_acts->num_actions < mod_hdr_acts->max_actions)
		goto out;

	max_hw_actions = xsc_mod_hdr_max_actions(xdev, namespace);
	new_num_actions = min(max_hw_actions,
			      mod_hdr_acts->actions ?
			      mod_hdr_acts->max_actions * 2 : 1);
	if (mod_hdr_acts->max_actions == new_num_actions)
		return ERR_PTR(-ENOSPC);

	new_sz = XSC_MH_ACT_SZ * new_num_actions;
	old_sz = mod_hdr_acts->max_actions * XSC_MH_ACT_SZ;

	if (mod_hdr_acts->is_static) {
		ret = kzalloc(new_sz, GFP_KERNEL);
		if (ret) {
			memcpy(ret, mod_hdr_acts->actions, old_sz);
			mod_hdr_acts->is_static = false;
		}
	} else {
		ret = krealloc(mod_hdr_acts->actions, new_sz, GFP_KERNEL);
		if (ret)
			memset(ret + old_sz, 0, new_sz - old_sz);
	}
	if (!ret)
		return ERR_PTR(-ENOMEM);

	mod_hdr_acts->actions = ret;
	mod_hdr_acts->max_actions = new_num_actions;

out:
	return mod_hdr_acts->actions + (mod_hdr_acts->num_actions * XSC_MH_ACT_SZ);
}

void
xsc_mod_hdr_dealloc(struct xsc_tc_mod_hdr_acts *mod_hdr_acts)
{
	if (!mod_hdr_acts->is_static)
		kfree(mod_hdr_acts->actions);

	mod_hdr_acts->actions = NULL;
	mod_hdr_acts->num_actions = 0;
	mod_hdr_acts->max_actions = 0;
}

char *
xsc_mod_hdr_get_item(struct xsc_tc_mod_hdr_acts *mod_hdr_acts, int pos)
{
	return mod_hdr_acts->actions + (pos * XSC_MH_ACT_SZ);
}

char *xsc_get_mod_action_item(struct mod_hdr_key *action_key, int pos)
{
	return action_key->actions + (pos * XSC_MH_ACT_SZ);
}
