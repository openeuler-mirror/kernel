// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ubdevshm uba record management implementation
 */
#define pr_fmt(fmt) "UBDEVSHM: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/idr.h>
#include <linux/mutex.h>

#include <ub/ubdevshm/ubdevshm.h>
#include "ubdevshm_uba_record.h"
#include "ubdevshm_main.h"

/* IDR for managing uba_record IDs */
static struct idr uba_record_idr;

void ubdevshm_uba_record_init(void)
{
	idr_init(&uba_record_idr);
}

void ubdevshm_uba_record_uninit(void)
{
	idr_destroy(&uba_record_idr);
}

int ubdevshm_create_uba_record(struct access_ctx_inner *ctx_inner,
				struct uba_record **rrec)
{
	struct uba_record *rec;

	rec = kzalloc(sizeof(*rec), GFP_KERNEL);
	if (!rec)
		return -ENOMEM;

	INIT_LIST_HEAD(&rec->node);
	rec->owner = ctx_inner;
	*rrec = rec;
	return 0;
}

int ubdevshm_link_uba_record_to_ctx(struct shm_container *cntr,
				     struct access_ctx_inner *ctx_inner,
				     struct uba_record *rec)
{
	int rec_id;

	down_write(&ubdevshm_rw_semlock);
	rec_id = idr_alloc_cyclic(&uba_record_idr, rec,
				  UBDEVSHM_IDR_MIN_ID, UBDEVSHM_IDR_MAX_ID, GFP_ATOMIC);
	up_write(&ubdevshm_rw_semlock);
	if (rec_id < 0) {
		pr_err("uba record id_alloc err=%d\n", rec_id);
		return rec_id;
	}
	rec->id = rec_id;

	rec->uba.mem_handle = (void *)(unsigned long)rec->id;
	mutex_lock(&cntr->lock);
	list_add_tail(&rec->node, &ctx_inner->uba_list);
	if (!refcount_inc_not_zero(&ctx_inner->acquire_refcnt)) {
		list_del(&rec->node);
		mutex_unlock(&cntr->lock);
		down_write(&ubdevshm_rw_semlock);
		(void)idr_remove(&uba_record_idr, (unsigned long)rec->id);
		up_write(&ubdevshm_rw_semlock);
		pr_err("wrong acquire_refcnt  acquire_refcnt=%d\n",
		       refcount_read(&ctx_inner->acquire_refcnt));
		return -ENOENT;
	}
	mutex_unlock(&cntr->lock);

	return 0;
}

struct access_ctx_inner *ubdevshm_find_get_access_ctx_by_uba_record(u32 rec_id,
								      struct uba_record **rrec)
{
	struct access_ctx_inner *ctx_inner = NULL;
	struct uba_record *rec;

	down_read(&ubdevshm_rw_semlock);
	rec = idr_find(&uba_record_idr, rec_id);
	if (!rec) {
		pr_err("uba record not found by id\n");
		goto err_out;
	}
	ctx_inner = rec->owner;
	if (!refcount_inc_not_zero(&ctx_inner->refcnt)) {
		pr_err("ctx ref is zero\n");
		ctx_inner = NULL;
	}
	*rrec = rec;

err_out:
	up_read(&ubdevshm_rw_semlock);
	return ctx_inner;
}

void ubdevshm_release_uba_record(struct shm_container *cntr, struct uba_record *rec)
{
	mutex_lock(&cntr->lock);
	list_del(&rec->node);
	mutex_unlock(&cntr->lock);

	down_write(&ubdevshm_rw_semlock);
	(void)idr_remove(&uba_record_idr, (unsigned long)rec->id);
	up_write(&ubdevshm_rw_semlock);
	kfree(rec);
}

void ubdevshm_cleanup_uba_records_in_ctx(struct access_ctx_inner *ctx)
{
	struct uba_record *rec, *n;

	list_for_each_entry_safe(rec, n, &ctx->uba_list, node) {
		pr_warn("cleanup leftover uba_record id=%d\n", rec->id);
		list_del(&rec->node);
		(void)idr_remove(&uba_record_idr, (unsigned long)rec->id);
		kfree(rec);
	}
}
