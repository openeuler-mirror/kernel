// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: uburma cmd implementation
 * Author: Qian Guoxin
 * Create: 2021-08-04
 * Note:
 * History: 2021-08-04: Create file
 * History: 2022-07-25: Yan Fangfang Change the prefix uburma_ioctl_ to uburma_cmd_
 */

#include <linux/fs.h>
#include <linux/uaccess.h>

#include "ub/urma/ubcore_uapi.h"
#include "ub/urma/ubcore_types.h"
#include "ub/urma/ubcore_opcode.h"
#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_event.h"
#include "uburma_file_ops.h"
#include "uburma_uobj.h"
#include "uburma_cmd_tlv.h"

#include "uburma_cmd.h"

#define UBURMA_INVALID_TPN UINT_MAX
#define UBURMA_CREATE_JETTY_ARG_IN_RC_SHARE_TP_SHIFT 11

void uburma_cmd_inc(struct uburma_device *ubu_dev)
{
	atomic_inc(&ubu_dev->cmdcnt);
}

void uburma_cmd_dec(struct uburma_device *ubu_dev)
{
	if (atomic_dec_and_test(&ubu_dev->cmdcnt))
		complete(&ubu_dev->cmddone);
}

void uburma_cmd_flush(struct uburma_device *ubu_dev)
{
	uburma_cmd_dec(ubu_dev);
	wait_for_completion(&ubu_dev->cmddone);
}

static inline void fill_udata(struct ubcore_udata *out,
			      struct ubcore_ucontext *ctx,
			      struct uburma_cmd_udrv_priv *udata)
{
	out->uctx = ctx;
	out->udrv_data = (struct ubcore_udrv_priv *)(void *)udata;
}

static int uburma_cmd_create_ctx(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct ubcore_ucontext *ucontext;
	struct uburma_cmd_create_ctx arg;
	struct uburma_uobj *uobj;
	struct uburma_jfae_uobj *jfae;
	union ubcore_eid eid;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	down_write(&file->ucontext_rwsem);

	if (file->ucontext) {
		up_write(&file->ucontext_rwsem);
		uburma_log_err(
			"ucontext eixt, should not create ctx in same fd.\n");
		return -EEXIST;
	}

	(void)memcpy(eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	ucontext = ubcore_alloc_ucontext(
		ubc_dev, arg.in.eid_index,
		(struct ubcore_udrv_priv *)(void *)&arg.udata);
	if (IS_ERR_OR_NULL(ucontext)) {
		up_write(&file->ucontext_rwsem);
		return PTR_ERR(ucontext);
	}
	ucontext->eid = eid;
	uobj = uobj_alloc(UOBJ_CLASS_JFAE, file);
	if (IS_ERR_OR_NULL(uobj)) {
		ret = PTR_ERR(uobj);
		goto free_ctx;
	}

	jfae = container_of(uobj, struct uburma_jfae_uobj, uobj);
	uburma_init_jfae(jfae, ubc_dev);
	ucontext->jfae = uobj;
	arg.out.async_fd = uobj->id;
	file->ucontext = ucontext;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto free_jfae;

	uobj_alloc_commit(uobj);
	up_write(&file->ucontext_rwsem);
	uburma_log_debug("uburma create context success.\n");
	return ret;

free_jfae:
	uobj_alloc_abort(uobj);
free_ctx:
	ubcore_free_ucontext(ubc_dev, ucontext);
	file->ucontext = NULL;
	up_write(&file->ucontext_rwsem);
	return ret;
}

static void uburma_fill_attr(struct ubcore_seg_cfg *cfg,
			     struct uburma_cmd_register_seg *arg)
{
	cfg->va = arg->in.va;
	cfg->len = arg->in.len;
	cfg->flag.value = arg->in.flag;
	cfg->token_value.token = arg->in.token;
	cfg->iova = arg->in.va;
}

static int uburma_cmd_alloc_token_id(struct ubcore_device *ubc_dev,
				     struct uburma_file *file,
				     struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_alloc_token_id arg;
	union ubcore_token_id_flag flag = { 0 };
	struct ubcore_udata udata = { 0 };
	struct ubcore_token_id *token_id;
	struct uburma_uobj *uobj;

	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	flag.bs.multi_seg = arg.flag.bs.multi_seg;
	fill_udata(&udata, file->ucontext, &arg.udata);
	uobj = uobj_alloc(UOBJ_CLASS_TOKEN, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("UOBJ_CLASS_TOKEN alloc fail!\n");
		return -ENOMEM;
	}

	token_id = ubcore_alloc_token_id(ubc_dev, flag, &udata);
	if (IS_ERR_OR_NULL(token_id)) {
		ret = PTR_ERR(token_id);
		goto err_free_uobj;
	}
	uobj->object = token_id;
	arg.out.token_id = token_id->token_id;
	arg.out.handle = (uint64_t)uobj->id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto err_free_token_id;

	uobj_alloc_commit(uobj);
	return 0;

err_free_token_id:
	(void)ubcore_free_token_id(token_id);
err_free_uobj:
	uobj_alloc_abort(uobj);
	return ret;
}

static int uburma_cmd_free_token_id(struct ubcore_device *ubc_dev,
				    struct uburma_file *file,
				    struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_free_token_id arg;
	struct ubcore_token_id *token;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_TOKEN, (int)arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find token id.\n");
		return -EINVAL;
	}

	token = (struct ubcore_token_id *)uobj->object;
	if (arg.in.token_id != token->token_id)
		return -EPERM;

	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("ubcore remove commit token_id failed.\n");

	uobj_put_del(uobj);
	return ret;
}

static int uburma_cmd_register_seg(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_register_seg arg;
	struct ubcore_seg_cfg cfg = { 0 };
	struct ubcore_target_seg *seg;
	struct ubcore_udata udata = { 0 };
	struct uburma_uobj *uobj;
	struct uburma_uobj *token_id_uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	token_id_uobj = uobj_get_read(UOBJ_CLASS_TOKEN,
				      (int)arg.in.token_id_handle, file);
	if (!IS_ERR_OR_NULL(token_id_uobj))
		cfg.token_id = (struct ubcore_token_id *)token_id_uobj->object;

	uburma_fill_attr(&cfg, &arg);
	cfg.eid_index = file->ucontext->eid_index;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_alloc(UOBJ_CLASS_SEG, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("UOBJ_CLASS_SEG alloc fail!\n");
		ret = -ENOMEM;
		goto err_put_token_id;
	}

	seg = ubcore_register_seg(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(seg)) {
		ret = PTR_ERR(seg);
		goto err_free_uobj;
	}
	uobj->object = seg;
	arg.out.token_id = seg->seg.token_id;
	arg.out.handle = (uint64_t)uobj->id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto err_delete_seg;

	if (!IS_ERR_OR_NULL(token_id_uobj))
		uobj_put_read(token_id_uobj);
	uobj_alloc_commit(uobj);
	return 0;

err_delete_seg:
	ubcore_unregister_seg(seg);
err_free_uobj:
	uobj_alloc_abort(uobj);
err_put_token_id:
	if (!IS_ERR_OR_NULL(token_id_uobj))
		uobj_put_read(token_id_uobj);
	return ret;
}

static int uburma_cmd_unregister_seg(struct ubcore_device *ubc_dev,
				     struct uburma_file *file,
				     struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unregister_seg arg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_SEG, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find registered seg.\n");
		return -EINVAL;
	}
	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("ubcore_unregister_seg failed.\n");

	uobj_put_del(uobj);
	return ret;
}

static void uburma_write_async_event(struct ubcore_ucontext *ctx,
				     uint64_t event_data, uint32_t event_type,
				     struct list_head *obj_event_list,
				     uint32_t *counter)
{
	struct uburma_jfae_uobj *jfae;

	rcu_read_lock();
	jfae = rcu_dereference(ctx->jfae);
	if (!jfae) {
		rcu_read_unlock();
		return;
	}
	uburma_write_event(&jfae->jfe, event_data, event_type, obj_event_list,
			   counter);
	rcu_read_unlock();
}

void uburma_jfc_event_cb(struct ubcore_event *event,
			 struct ubcore_ucontext *ctx)
{
	struct uburma_jfc_uobj *jfc_uobj;

	if (!event->element.jfc)
		return;

	jfc_uobj = (struct uburma_jfc_uobj *)
			   event->element.jfc->jfc_cfg.jfc_context;
	uburma_write_async_event(ctx, event->element.jfc->urma_jfc,
				 event->event_type, &jfc_uobj->async_event_list,
				 &jfc_uobj->async_events_reported);
}

void uburma_jfs_event_cb(struct ubcore_event *event,
			 struct ubcore_ucontext *ctx)
{
	struct uburma_jfs_uobj *jfs_uobj;

	if (!event->element.jfs)
		return;

	jfs_uobj = (struct uburma_jfs_uobj *)
			   event->element.jfs->jfs_cfg.jfs_context;
	uburma_write_async_event(ctx, event->element.jfs->urma_jfs,
				 event->event_type, &jfs_uobj->async_event_list,
				 &jfs_uobj->async_events_reported);
}

void uburma_jfr_event_cb(struct ubcore_event *event,
			 struct ubcore_ucontext *ctx)
{
	struct uburma_jfr_uobj *jfr_uobj;

	if (event->element.jfr == NULL)
		return;

	jfr_uobj = (struct uburma_jfr_uobj *)
			   event->element.jfr->jfr_cfg.jfr_context;
	uburma_write_async_event(ctx, event->element.jfr->urma_jfr,
				 event->event_type, &jfr_uobj->async_event_list,
				 &jfr_uobj->async_events_reported);
}

void uburma_jetty_event_cb(struct ubcore_event *event,
			   struct ubcore_ucontext *ctx)
{
	struct uburma_jetty_uobj *jetty_uobj;

	if (!event->element.jetty)
		return;

	jetty_uobj = (struct uburma_jetty_uobj *)
			     event->element.jetty->jetty_cfg.jetty_context;
	uburma_write_async_event(ctx, event->element.jetty->urma_jetty,
				 event->event_type,
				 &jetty_uobj->async_event_list,
				 &jetty_uobj->async_events_reported);
}

void uburma_jetty_grp_event_cb(struct ubcore_event *event,
			       struct ubcore_ucontext *ctx)
{
	struct uburma_jetty_grp_uobj *jetty_grp_uobj;

	if (!event->element.jetty_grp)
		return;

	jetty_grp_uobj =
		(struct uburma_jetty_grp_uobj *)
			event->element.jetty_grp->jetty_grp_cfg.user_ctx;
	uburma_write_async_event(ctx, event->element.jetty_grp->urma_jetty_grp,
				 event->event_type,
				 &jetty_grp_uobj->async_event_list,
				 &jetty_grp_uobj->async_events_reported);
}

static int uburma_cmd_create_jfs(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jfs arg;
	struct ubcore_jfs_cfg cfg = { 0 };
	struct ubcore_udata udata = {};
	struct uburma_jfs_uobj *jfs_uobj;
	struct uburma_uobj *jfc_uobj;
	struct ubcore_jfs *jfs;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	cfg.depth = arg.in.depth;
	cfg.flag.value = arg.in.flag;
	cfg.eid_index = file->ucontext->eid_index;
	cfg.trans_mode = arg.in.trans_mode;
	cfg.max_sge = arg.in.max_sge;
	cfg.max_rsge = arg.in.max_rsge;
	cfg.max_inline_data = arg.in.max_inline_data;
	cfg.rnr_retry = arg.in.rnr_retry;
	cfg.err_timeout = arg.in.err_timeout;
	cfg.priority = arg.in.priority;

	jfs_uobj = (struct uburma_jfs_uobj *)uobj_alloc(UOBJ_CLASS_JFS, file);
	if (IS_ERR_OR_NULL(jfs_uobj)) {
		uburma_log_err("UOBJ_CLASS_JFS alloc fail!\n");
		return -ENOMEM;
	}
	jfs_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jfs_uobj->async_event_list);
	cfg.jfs_context = jfs_uobj;

	jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.jfc_handle, file);
	if (IS_ERR_OR_NULL(jfc_uobj)) {
		uburma_log_err("failed to find jfc, jfc_handle:%llu.\n",
			       arg.in.jfc_handle);
		ret = -EINVAL;
		goto err_alloc_abort;
	}
	cfg.jfc = jfc_uobj->object;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jfs = ubcore_create_jfs(ubc_dev, &cfg, uburma_jfs_event_cb, &udata);
	if (IS_ERR_OR_NULL(jfs)) {
		ret = PTR_ERR(jfs);
		goto err_put_jfc;
	}
	jfs_uobj->uobj.object = jfs;
	jfs->urma_jfs = arg.in.urma_jfs;

	/* Do not release jfae fd until jfs is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jfs;

	arg.out.id = jfs->jfs_id.id;
	arg.out.depth = jfs->jfs_cfg.depth;
	arg.out.max_sge = jfs->jfs_cfg.max_sge;
	arg.out.max_rsge = jfs->jfs_cfg.max_rsge;
	arg.out.max_inline_data = jfs->jfs_cfg.max_inline_data;
	arg.out.handle = jfs_uobj->uobj.id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto err_put_jfae;

	uobj_put_read(jfc_uobj);
	uobj_alloc_commit(&jfs_uobj->uobj);
	return 0;

err_put_jfae:
	uburma_put_jfae(file);
err_delete_jfs:
	ubcore_delete_jfs(jfs);
err_put_jfc:
	uobj_put_read(jfc_uobj);
err_alloc_abort:
	uobj_alloc_abort(&jfs_uobj->uobj);
	return ret;
}

static int uburma_cmd_modify_jfs(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_jfs arg;
	struct ubcore_jfs_attr attr = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_udata udata = {};
	struct ubcore_jfs *jfs;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	attr.mask = arg.in.mask;
	attr.state = arg.in.state;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfs.\n");
		return -EINVAL;
	}

	jfs = (struct ubcore_jfs *)uobj->object;
	ret = ubcore_modify_jfs(jfs, &attr, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("modify jfs failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_query_jfs(struct ubcore_device *ubc_dev,
				struct uburma_file *file,
				struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_query_jfs arg;
	struct ubcore_jfs_attr attr = { 0 };
	struct ubcore_jfs_cfg cfg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_jfs *jfs;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_read(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfs.\n");
		return -EINVAL;
	}

	jfs = (struct ubcore_jfs *)uobj->object;
	ret = ubcore_query_jfs(jfs, &cfg, &attr);
	if (ret != 0) {
		uobj_put_read(uobj);
		uburma_log_err("query jfs failed, ret:%d.\n", ret);
		return ret;
	}

	arg.out.depth = cfg.depth;
	arg.out.flag = cfg.flag.value;
	arg.out.trans_mode = (uint32_t)cfg.trans_mode;
	arg.out.priority = cfg.priority;
	arg.out.max_sge = cfg.max_sge;
	arg.out.max_rsge = cfg.max_rsge;
	arg.out.max_inline_data = cfg.max_inline_data;
	arg.out.rnr_retry = cfg.rnr_retry;
	arg.out.err_timeout = cfg.err_timeout;
	arg.out.state = (uint32_t)attr.state;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_read(uobj);
	return ret;
}

static int uburma_cmd_delete_jfs(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jfs arg;
	struct uburma_jfs_uobj *jfs_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfs");
		return -EINVAL;
	}

	/* To get async_events_reported after obj removed. */
	uobj_get(uobj);
	jfs_uobj = container_of(uobj, struct uburma_jfs_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("delete jfs failed, ret:%d.\n", ret);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.async_events_reported = jfs_uobj->async_events_reported;
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, (void *)&arg);
}

static int uburma_cmd_delete_jfs_batch(struct ubcore_device *ubc_dev,
				       struct uburma_file *file,
				       struct uburma_cmd_hdr *hdr)
{
	struct uburma_jfs_uobj *jfs_uobj = NULL;
	struct uburma_cmd_delete_jfs_batch arg;
	struct uburma_uobj **uobj_arr = NULL;
	uint32_t async_events_reported = 0;
	struct uburma_uobj *uobj = NULL;
	uint32_t bad_jfs_index = 0;
	uint64_t *jfs_arr = NULL;
	uint32_t arr_num;
	int ret_bad;
	int ret;
	int i;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	arr_num = arg.in.jfs_num;
	jfs_arr = kcalloc(arr_num, sizeof(uint64_t), GFP_KERNEL);
	if (!jfs_arr)
		return -ENOMEM;

	ret = uburma_copy_from_user((void *)jfs_arr,
				    (void __user *)arg.in.jfs_ptr,
				    arr_num * sizeof(uint64_t));
	if (ret != 0)
		goto free_jfs_arr;

	uobj_arr = kcalloc(arr_num, sizeof(struct uburma_uobj *), GFP_KERNEL);
	if (!uobj_arr) {
		ret = -ENOMEM;
		goto free_jfs_arr;
	}

	for (i = 0; i < arr_num; ++i) {
		uobj = uobj_get_del(UOBJ_CLASS_JFS, jfs_arr[i], file);
		if (IS_ERR(uobj)) {
			uburma_log_err("failed to find jfs, index is %d.\n", i);
			ret = -EINVAL;
			uobj_put_batch(uobj_arr, i);
			uobj_put_del_batch(uobj_arr, i);
			goto free_uobj_arr;
		}
		uobj_arr[i] = uobj;
		/* To get events_reported after obj removed. */
		uobj_get(uobj);
		jfs_uobj = container_of(uobj, struct uburma_jfs_uobj, uobj);
		async_events_reported += jfs_uobj->async_events_reported;
	}

	ret = uobj_remove_commit_batch(uobj_arr, arr_num, &bad_jfs_index);
	if (ret != 0)
		uburma_log_err("delete jfs failed, ret:%d.\n", ret);

	arg.out.async_events_reported = async_events_reported;
	arg.out.bad_jfs_index = bad_jfs_index;

	uobj_put_batch(uobj_arr, arr_num);
	uobj_put_del_batch(uobj_arr, arr_num);

	ret_bad = uburma_tlv_append(hdr, (void *)&arg);
	if (ret_bad != 0) {
		uburma_log_err("uburma tlv append error, ret:%d.\n", ret_bad);
		ret = ret_bad;
	}

free_uobj_arr:
	kfree(uobj_arr);
free_jfs_arr:
	kfree(jfs_arr);
	return ret;
}

static int uburma_cmd_alloc_jfs(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_alloc_jfs arg;
	struct uburma_uobj *jfc_uobj;
	struct uburma_jfs_uobj *jfs_uobj;
	struct ubcore_jfs_cfg cfg = { 0 };
	struct ubcore_udata udata;
	struct ubcore_jfs *jfs = NULL;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	cfg.depth = arg.in.depth;
	cfg.eid_index = file->ucontext->eid_index;
	cfg.flag.value = arg.in.flag;
	cfg.priority = arg.in.priority;
	cfg.max_sge = arg.in.max_sge;
	cfg.max_rsge = arg.in.max_rsge;
	cfg.max_inline_data = arg.in.max_inline_data;
	cfg.trans_mode = arg.in.trans_mode;
	cfg.rnr_retry = arg.in.rnr_retry;
	cfg.err_timeout = arg.in.err_timeout;

	fill_udata(&udata, file->ucontext, &arg.udata);

	jfs_uobj = (struct uburma_jfs_uobj *)uobj_alloc(UOBJ_CLASS_JFS, file);
	if (IS_ERR_OR_NULL(jfs_uobj)) {
		uburma_log_err("UOBJ_CLASS_JFS alloc fail!\n");
		return -ENOMEM;
	}
	jfs_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jfs_uobj->async_event_list);
	cfg.jfs_context = jfs_uobj;

	jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.jfc_handle, file);
	if (IS_ERR_OR_NULL(jfc_uobj)) {
		uburma_log_err("failed to find jfc, jfc_handle:%llu.\n", arg.in.jfc_handle);
		ret = -EINVAL;
		goto err_alloc_abort;
	}
	cfg.jfc = jfc_uobj->object;
	ret = ubcore_alloc_jfs(ubc_dev, &cfg, uburma_jfs_event_cb, &jfs, &udata);
	if (IS_ERR_OR_NULL(jfs)) {
		uburma_log_err("create jfs or get jfs_id failed.\n");
		ret = PTR_ERR(jfs);
		goto err_put_jfc;
	}
	jfs_uobj->uobj.object = jfs;
	jfs->urma_jfs = arg.in.urma_jfs;

	/* Do not release jfae fd until jfr is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_free_jfs;

	arg.out.id = jfs->jfs_id.id;
	arg.out.depth = jfs->jfs_cfg.depth;
	arg.out.max_sge = jfs->jfs_cfg.max_sge;
	arg.out.max_rsge = jfs->jfs_cfg.max_rsge;
	arg.out.max_inline_data = jfs->jfs_cfg.max_inline_data;
	arg.out.handle = jfs_uobj->uobj.id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto err_put_jfae;

	uobj_put_read(jfc_uobj);
	uobj_alloc_commit(&jfs_uobj->uobj);
	return ret;

err_put_jfae:
	uburma_put_jfae(file);
err_free_jfs:
	(void)ubcore_free_jfs(jfs, &udata);
err_put_jfc:
	uobj_put_read(jfc_uobj);
err_alloc_abort:
	uobj_alloc_abort(&jfs_uobj->uobj);
	return ret;
}

static int uburma_cmd_free_jfs(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_free_jfs arg;
	struct uburma_uobj *uobj;
	struct uburma_jfs_uobj *jfs_uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfs.\n");
		return -EINVAL;
	}

	/* To get events_reported after obj removed. */
	uobj_get(uobj);
	jfs_uobj = container_of(uobj, struct uburma_jfs_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("delete jfs failed, ret:%d.\n", ret);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.async_events_reported = jfs_uobj->async_events_reported;
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, (void *)&arg);
}

static int uburma_cmd_set_jfs_opt(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_set_jfs_opt arg = { 0 };
	struct uburma_uobj *jfs_uobj = NULL;
	struct uburma_uobj *jfc_uobj = NULL;
	struct ubcore_jfc *new_jfc = NULL;
	struct ubcore_udata udata = { 0 };
	struct ubcore_jfs *jfs;

	void __user *ubuf;
	void *kbuf = NULL;
	void *opt_kbuf = NULL;

	uint64_t opt;
	uint32_t len;
	uint64_t jfc_handle;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret)
		return ret;

	opt = arg.in.opt;
	len = arg.in.len;
	ubuf = (void __user *)(uintptr_t)arg.in.buf;

	if (len > 0 && !access_ok(ubuf, len))
		return -EFAULT;

	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = uburma_copy_from_user(kbuf, ubuf, len);
	if (ret) {
		ret = -EFAULT;
		goto err_free_kbuf;
	}

	fill_udata(&udata, file->ucontext, &arg.udata);

	jfs_uobj = uobj_get_write(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR_OR_NULL(jfs_uobj)) {
		ret = -EINVAL;
		goto err_free_kbuf;
	}

	jfs = (struct ubcore_jfs *)jfs_uobj->object;
	opt_kbuf = kbuf;
	if (opt == UBCORE_JFS_BIND_JFC) {
		if (len != sizeof(uint64_t)) {
			ret = -EINVAL;
			goto err_put_jfs;
		}

		memcpy(&jfc_handle, kbuf, sizeof(jfc_handle));

		jfc_uobj = uobj_get_write(UOBJ_CLASS_JFC, jfc_handle, file);
		if (IS_ERR_OR_NULL(jfc_uobj)) {
			ret = -EINVAL;
			goto err_put_jfs;
		}

		new_jfc = (struct ubcore_jfc *)jfc_uobj->object;
		opt_kbuf = &new_jfc;
	}

	ret = ubcore_set_jfs_opt(jfs, opt, opt_kbuf, len, &udata);
	if (ret) {
		uburma_log_err("ubcore_set_jfs_opt failed, ret:%d.\n", ret);
		goto err_put_jfc;
	}

	ret = uburma_tlv_append(hdr, &arg);

err_put_jfc:
	if (jfc_uobj)
		uobj_put_write(jfc_uobj);
err_put_jfs:
	if (jfs_uobj)
		uobj_put_write(jfs_uobj);
err_free_kbuf:
	kfree(kbuf);
	return ret;
}

static int uburma_cmd_get_jfs_opt(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_jfs_opt arg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_udata udata = { 0 };
	struct ubcore_jfs *jfs;
	uint64_t opt;
	uint32_t len;
	int ret;
	void __user *ubuf = NULL;
	void *kbuf = NULL;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	opt = arg.in.opt;
	len = arg.in.len;
	ubuf = (void __user *)(uintptr_t)arg.in.buf;
	if (!access_ok(ubuf, len))
		return -EFAULT;

	fill_udata(&udata, file->ucontext, &arg.udata);
	uobj = uobj_get_write(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfs.\n");
		return -EINVAL;
	}
	jfs = (struct ubcore_jfs *)uobj->object;
	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf) {
		uobj_put_write(uobj);
		return -ENOMEM;
	}

	ret = ubcore_get_jfs_opt(jfs, opt, kbuf, len, &udata);
	if (ret != 0) {
		kfree(kbuf);
		uobj_put_write(uobj);
		uburma_log_err("get_jfs_opt failed, ret:%d.\n", ret);
		return ret;
	}
	ret = uburma_copy_to_user(ubuf, kbuf, len);
	if (ret != 0) {
		kfree(kbuf);
		uobj_put_write(uobj);
		uburma_log_err("copy_to_user failed.\n");
		return ret;
	}
	kfree(kbuf);
	arg.out.buf = arg.in.buf;
	arg.out.len = len;
	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_active_jfs(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_active_jfs arg;
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jfs_opt jfs_opt;
	struct uburma_uobj *jfc_uobj;
	struct ubcore_jfs *jfs;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	if (!access_ok((void __user *)(uintptr_t)arg.in.jfs_opt, sizeof(jfs_opt)))
		return -EFAULT;

	ret = uburma_copy_from_user(&jfs_opt, (void __user *)(uintptr_t)arg.in.jfs_opt,
		sizeof(jfs_opt));
	if (ret != 0) {
		uburma_log_err("Failed to copy jfs_opt,ret %d.\n", ret);
		return ret;
	}

	uobj = uobj_get_write(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfs.\n");
		return -EINVAL;
	}
	jfs = (struct ubcore_jfs *)uobj->object;

	fill_udata(&udata, file->ucontext, &arg.udata);
	(void)memcpy(&jfs->jfs_opt, &jfs_opt, sizeof(jfs_opt));

	jfs->jfs_cfg.depth = arg.in.depth;
	jfs->jfs_cfg.eid_index = file->ucontext->eid_index;
	jfs->jfs_cfg.flag.value = arg.in.flag;
	jfs->jfs_cfg.priority = arg.in.priority;
	jfs->jfs_cfg.max_sge = arg.in.max_sge;
	jfs->jfs_cfg.max_rsge = arg.in.max_rsge;
	jfs->jfs_cfg.max_inline_data = arg.in.max_inline_data;
	jfs->jfs_cfg.trans_mode = arg.in.trans_mode;
	jfs->jfs_cfg.rnr_retry = arg.in.rnr_retry;
	jfs->jfs_cfg.err_timeout = arg.in.err_timeout;

	jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.jfc_handle, file);
	if (IS_ERR_OR_NULL(jfc_uobj)) {
		uburma_log_err("failed to find jfc, jfc_handle:%llu.\n", arg.in.jfc_handle);
		uobj_put_write(uobj);
		ret = -EINVAL;
		return ret;
	}
	jfs->jfs_cfg.jfc = jfc_uobj->object;

	ret = ubcore_active_jfs(jfs, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("active jfs failed, ret:%d.\n", ret);
		return ret;
	}

	arg.out.id = jfs->jfs_id.id;
	arg.out.depth = jfs->jfs_cfg.depth;
	arg.out.max_sge = jfs->jfs_cfg.max_sge;
	arg.out.max_rsge = jfs->jfs_cfg.max_rsge;
	arg.out.max_inline_data = jfs->jfs_cfg.max_inline_data;
	arg.out.handle = uobj->id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	uobj_put_read(jfc_uobj);
	return ret;
}

static int uburma_cmd_deactive_jfs(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_deactive_jfs arg;
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jfs *jfs;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_write(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfr.\n");
		return -EINVAL;
	}

	jfs = (struct ubcore_jfs *)uobj->object;

	fill_udata(&udata, file->ucontext, &arg.udata);

	ret = ubcore_deactive_jfs(jfs, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("active jfs failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_import_seg(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_import_seg arg;
	struct ubcore_target_seg_cfg cfg = { 0 };
	struct ubcore_udata udata = {};
	struct ubcore_target_seg *tseg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_SEG, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("UOBJ_CLASS_TARGET_SEG alloc fail!\n");
		return -ENOMEM;
	}

	(void)memcpy(cfg.seg.ubva.eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	cfg.seg.ubva.va = arg.in.va;
	cfg.seg.len = arg.in.len;
	cfg.seg.attr.value = arg.in.flag;
	cfg.seg.token_id = arg.in.token_id;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tseg = ubcore_import_seg(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(tseg)) {
		uobj_alloc_abort(uobj);
		return PTR_ERR(tseg);
	}

	uobj->object = tseg;
	arg.out.handle = (uint64_t)uobj->id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0) {
		(void)ubcore_unimport_seg(tseg);
		uobj_alloc_abort(uobj);
		return ret;
	}
	uobj_alloc_commit(uobj);
	return ret;
}

static int uburma_cmd_unimport_seg(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unimport_seg arg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_TARGET_SEG, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find imported target seg.\n");
		return -EINVAL;
	}
	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("unimport seg failed.\n");

	uobj_put_del(uobj);
	return ret;
}

static int uburma_cmd_create_jfr(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jfr arg;
	struct uburma_uobj *jfc_uobj;
	struct uburma_jfr_uobj *jfr_uobj;
	struct ubcore_jfr_cfg cfg = { 0 };
	struct ubcore_udata udata = {};
	struct ubcore_jfr *jfr;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	cfg.id = arg.in.id;
	cfg.depth = arg.in.depth;
	cfg.eid_index = file->ucontext->eid_index;
	cfg.flag.value = arg.in.flag;
	cfg.max_sge = arg.in.max_sge;
	cfg.min_rnr_timer = arg.in.min_rnr_timer;
	cfg.trans_mode = arg.in.trans_mode;
	cfg.token_value.token = arg.in.token;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jfr_uobj = (struct uburma_jfr_uobj *)uobj_alloc(UOBJ_CLASS_JFR, file);
	if (IS_ERR_OR_NULL(jfr_uobj)) {
		uburma_log_err("UOBJ_CLASS_JFR alloc fail!\n");
		return -ENOMEM;
	}
	jfr_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jfr_uobj->async_event_list);
	cfg.jfr_context = jfr_uobj;

	jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.jfc_handle, file);
	if (IS_ERR_OR_NULL(jfc_uobj)) {
		uburma_log_err("failed to find jfc, jfc_handle:%llu.\n",
			       arg.in.jfc_handle);
		ret = -EINVAL;
		goto err_alloc_abort;
	}
	cfg.jfc = jfc_uobj->object;

	jfr = ubcore_create_jfr(ubc_dev, &cfg, uburma_jfr_event_cb, &udata);
	if (IS_ERR_OR_NULL(jfr)) {
		ret = PTR_ERR(jfr);
		goto err_put_jfc;
	}
	jfr_uobj->uobj.object = jfr;
	jfr->urma_jfr = arg.in.urma_jfr;

	/* Do not release jfae fd until jfr is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jfr;

	arg.out.id = jfr->jfr_id.id;
	arg.out.depth = jfr->jfr_cfg.depth;
	arg.out.max_sge = jfr->jfr_cfg.max_sge;
	arg.out.handle = jfr_uobj->uobj.id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto err_put_jfae;

	uobj_put_read(jfc_uobj);
	uobj_alloc_commit(&jfr_uobj->uobj);
	return ret;

err_put_jfae:
	uburma_put_jfae(file);
err_delete_jfr:
	(void)ubcore_delete_jfr(jfr);
err_put_jfc:
	uobj_put_read(jfc_uobj);
err_alloc_abort:
	uobj_alloc_abort(&jfr_uobj->uobj);
	return ret;
}

static int uburma_cmd_modify_jfr(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_jfr arg;
	struct uburma_uobj *uobj;
	struct ubcore_jfr_attr attr = { 0 };
	struct ubcore_udata udata = {};
	struct ubcore_jfr *jfr;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	attr.mask = arg.in.mask;
	attr.rx_threshold = arg.in.rx_threshold;
	attr.state = (enum ubcore_jfr_state)arg.in.state;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfr.\n");
		return -EINVAL;
	}

	jfr = (struct ubcore_jfr *)uobj->object;
	ret = ubcore_modify_jfr(jfr, &attr, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("modify jfr failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_query_jfr(struct ubcore_device *ubc_dev,
				struct uburma_file *file,
				struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_query_jfr arg;
	struct ubcore_jfr_attr attr = { 0 };
	struct ubcore_jfr_cfg cfg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_jfr *jfr;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_read(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfr.\n");
		return -EINVAL;
	}

	jfr = (struct ubcore_jfr *)uobj->object;
	ret = ubcore_query_jfr(jfr, &cfg, &attr);
	if (ret != 0) {
		uobj_put_read(uobj);
		uburma_log_err("query jfr failed, ret:%d.\n", ret);
		return ret;
	}

	arg.out.depth = cfg.depth;
	arg.out.flag = cfg.flag.value;
	arg.out.trans_mode = (uint32_t)cfg.trans_mode;
	arg.out.max_sge = cfg.max_sge;
	arg.out.min_rnr_timer = cfg.min_rnr_timer;
	arg.out.token = cfg.token_value.token;
	arg.out.id = cfg.id;

	arg.out.rx_threshold = attr.rx_threshold;
	arg.out.state = (uint32_t)attr.state;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_read(uobj);
	return ret;
}

static int uburma_cmd_delete_jfr(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jfr arg;
	struct uburma_jfr_uobj *jfr_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfr");
		return -EINVAL;
	}

	/* To get async_events_reported after obj removed. */
	uobj_get(uobj);
	jfr_uobj = container_of(uobj, struct uburma_jfr_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("delete jfr failed, ret:%d.\n", ret);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.async_events_reported = jfr_uobj->async_events_reported;
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, (void *)&arg);
}

static int uburma_cmd_delete_jfr_batch(struct ubcore_device *ubc_dev,
				       struct uburma_file *file,
				       struct uburma_cmd_hdr *hdr)
{
	struct uburma_jfr_uobj *jfr_uobj = NULL;
	struct uburma_cmd_delete_jfr_batch arg;
	struct uburma_uobj **uobj_arr = NULL;
	uint32_t async_events_reported = 0;
	struct uburma_uobj *uobj = NULL;
	uint32_t bad_jfr_index = 0;
	uint64_t *jfr_arr = NULL;
	uint32_t arr_num;
	int ret_bad;
	int ret;
	int i;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	arr_num = arg.in.jfr_num;
	jfr_arr = kcalloc(arr_num, sizeof(uint64_t), GFP_KERNEL);
	if (!jfr_arr)
		return -ENOMEM;

	ret = uburma_copy_from_user((void *)jfr_arr,
				    (void __user *)arg.in.jfr_ptr,
				    arr_num * sizeof(uint64_t));
	if (ret != 0)
		goto free_jfr_arr;

	uobj_arr = kcalloc(arr_num, sizeof(struct uburma_uobj *), GFP_KERNEL);
	if (!uobj_arr) {
		ret = -ENOMEM;
		goto free_jfr_arr;
	}

	for (i = 0; i < arr_num; ++i) {
		uobj = uobj_get_del(UOBJ_CLASS_JFR, jfr_arr[i], file);
		uobj_arr[i] = uobj;
		if (IS_ERR(uobj)) {
			uburma_log_err("failed to find jfr, index is %d.\n", i);
			ret = -EINVAL;
			goto free_uobj_arr;
		}
		/* To get events_reported after obj removed. */
		uobj_get(uobj);
		jfr_uobj = container_of(uobj, struct uburma_jfr_uobj, uobj);
		async_events_reported += jfr_uobj->async_events_reported;
	}

	ret = uobj_remove_commit_batch(uobj_arr, arr_num, &bad_jfr_index);
	if (ret != 0)
		uburma_log_err("delete jfr failed, ret:%d.\n", ret);

	arg.out.async_events_reported = async_events_reported;
	arg.out.bad_jfr_index = bad_jfr_index;

	uobj_put_batch(uobj_arr, arr_num);
	uobj_put_del_batch(uobj_arr, arr_num);

	ret_bad = uburma_tlv_append(hdr, (void *)&arg);
	if (ret_bad != 0) {
		uburma_log_err("uburma tlv append error, ret:%d.\n", ret_bad);
		ret = ret_bad;
	}

free_uobj_arr:
	kfree(uobj_arr);
free_jfr_arr:
	kfree(jfr_arr);
	return ret;
}

static int uburma_cmd_alloc_jfr(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_alloc_jfr arg;
	struct uburma_uobj *jfc_uobj;
	struct uburma_jfr_uobj *jfr_uobj;
	struct ubcore_jfr_cfg cfg = { 0 };
	struct ubcore_udata udata;
	struct ubcore_jfr *jfr = NULL;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	cfg.id = arg.in.id;
	cfg.depth = arg.in.depth;
	cfg.eid_index = file->ucontext->eid_index;
	cfg.flag.value = arg.in.flag;
	cfg.max_sge = arg.in.max_sge;
	cfg.min_rnr_timer = arg.in.min_rnr_timer;
	cfg.trans_mode = arg.in.trans_mode;
	cfg.token_value.token = arg.in.token;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jfr_uobj = (struct uburma_jfr_uobj *)uobj_alloc(UOBJ_CLASS_JFR, file);
	if (IS_ERR_OR_NULL(jfr_uobj)) {
		uburma_log_err("UOBJ_CLASS_JFR alloc fail!\n");
		return -ENOMEM;
	}
	jfr_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jfr_uobj->async_event_list);
	cfg.jfr_context = jfr_uobj;

	jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.jfc_handle, file);
	if (IS_ERR_OR_NULL(jfc_uobj)) {
		uburma_log_err("failed to find jfc, jfc_handle:%llu.\n", arg.in.jfc_handle);
		ret = -EINVAL;
		goto err_alloc_abort;
	}
	cfg.jfc = jfc_uobj->object;
	ret = ubcore_alloc_jfr(ubc_dev, &cfg, uburma_jfr_event_cb, &jfr, &udata);
	if (IS_ERR_OR_NULL(jfr)) {
		uburma_log_err("create jfr or get jfr_id failed.\n");
		ret = PTR_ERR(jfr);
		goto err_put_jfc;
	}
	jfr_uobj->uobj.object = jfr;
	jfr->urma_jfr = arg.in.urma_jfr;
	jfr->jfr_opt.is_actived = false;
	jfr->jfr_opt.urma_jfr_id = jfr->jfr_cfg.id;

	/* Do not release jfae fd until jfr is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_free_jfr;

	arg.out.id = jfr->jfr_id.id;
	arg.out.depth = jfr->jfr_cfg.depth;
	arg.out.max_sge = jfr->jfr_cfg.max_sge;
	arg.out.handle = jfr_uobj->uobj.id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto err_put_jfae;

	uobj_put_read(jfc_uobj);
	uobj_alloc_commit(&jfr_uobj->uobj);
	return ret;

err_put_jfae:
	uburma_put_jfae(file);
err_free_jfr:
	(void)ubcore_free_jfr(jfr, &udata);
err_put_jfc:
	uobj_put_read(jfc_uobj);
err_alloc_abort:
	uobj_alloc_abort(&jfr_uobj->uobj);
	return ret;
}

static int uburma_cmd_free_jfr(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_free_jfr arg;
	struct uburma_uobj *uobj;
	struct uburma_jfr_uobj *jfr_uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfr.\n");
		return -EINVAL;
	}

	/* To get events_reported after obj removed. */
	uobj_get(uobj);
	jfr_uobj = container_of(uobj, struct uburma_jfr_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("delete jfr failed, ret:%d.\n", ret);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.async_events_reported = jfr_uobj->async_events_reported;
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, (void *)&arg);
}

static int uburma_cmd_set_jfr_opt(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_set_jfr_opt arg = { 0 };
	struct uburma_uobj *jfr_uobj = NULL;
	struct uburma_uobj *jfc_uobj = NULL;
	struct ubcore_jfc *new_jfc = NULL;
	struct ubcore_udata udata = { 0 };
	struct ubcore_jfr *jfr;

	void __user *ubuf;
	void *kbuf = NULL;
	void *opt_kbuf = NULL;

	uint64_t opt;
	uint32_t len;
	uint64_t jfc_handle;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret)
		return ret;

	opt = arg.in.opt;
	len = arg.in.len;
	ubuf = (void __user *)(uintptr_t)arg.in.buf;

	if (len > 0 && !access_ok(ubuf, len))
		return -EFAULT;

	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = uburma_copy_from_user(kbuf, ubuf, len);
	if (ret) {
		ret = -EFAULT;
		goto err_free_kbuf;
	}

	fill_udata(&udata, file->ucontext, &arg.udata);

	jfr_uobj = uobj_get_write(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(jfr_uobj)) {
		ret = -EINVAL;
		goto err_free_kbuf;
	}

	jfr = (struct ubcore_jfr *)jfr_uobj->object;
	opt_kbuf = kbuf;
	if (opt == UBCORE_JFR_BIND_JFC) {
		if (len != sizeof(uint64_t)) {
			ret = -EINVAL;
			goto err_put_jfr;
		}

		memcpy(&jfc_handle, kbuf, sizeof(jfc_handle));

		jfc_uobj = uobj_get_write(UOBJ_CLASS_JFC, jfc_handle, file);
		if (IS_ERR_OR_NULL(jfc_uobj)) {
			ret = -EINVAL;
			goto err_put_jfr;
		}

		new_jfc = (struct ubcore_jfc *)jfc_uobj->object;
		opt_kbuf = &new_jfc;
	}

	ret = ubcore_set_jfr_opt(jfr, opt, opt_kbuf, len, &udata);
	if (ret) {
		uburma_log_err("ubcore_set_jfr_opt failed, ret:%d.\n", ret);
		goto err_put_jfc;
	}

	ret = uburma_tlv_append(hdr, &arg);

err_put_jfc:
	if (jfc_uobj)
		uobj_put_write(jfc_uobj);
err_put_jfr:
	if (jfr_uobj)
		uobj_put_write(jfr_uobj);
err_free_kbuf:
	kfree(kbuf);
	return ret;
}

static int uburma_cmd_get_jfr_opt(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_jfr_opt arg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_udata udata = { 0 };
	struct ubcore_jfr *jfr;
	uint64_t opt;
	uint32_t len;
	int ret;
	void __user *ubuf = NULL;
	void *kbuf = NULL;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	opt = arg.in.opt;
	len = arg.in.len;
	ubuf = (void __user *)(uintptr_t)arg.in.buf;
	if (!access_ok(ubuf, len))
		return -EFAULT;

	fill_udata(&udata, file->ucontext, &arg.udata);
	uobj = uobj_get_write(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfr.\n");
		return -EINVAL;
	}
	jfr = (struct ubcore_jfr *)uobj->object;
	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf) {
		uobj_put_write(uobj);
		return -ENOMEM;
	}

	ret = ubcore_get_jfr_opt(jfr, opt, kbuf, len, &udata);
	if (ret != 0) {
		kfree(kbuf);
		uobj_put_write(uobj);
		uburma_log_err("get_jfr_opt failed, ret:%d.\n", ret);
		return ret;
	}
	ret = uburma_copy_to_user(ubuf, kbuf, len);
	if (ret != 0) {
		kfree(kbuf);
		uobj_put_write(uobj);
		uburma_log_err("copy_to_user failed.\n");
		return ret;
	}
	kfree(kbuf);
	arg.out.buf = arg.in.buf;
	arg.out.len = len;
	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_active_jfr(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_active_jfr arg;
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jfr_opt jfr_opt;
	struct uburma_uobj *jfc_uobj;
	struct ubcore_jfr *jfr;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	if (!access_ok((void __user *)(uintptr_t)arg.in.urma_jfr_opt, sizeof(jfr_opt)))
		return -EFAULT;

	ret = uburma_copy_from_user(&jfr_opt, (void __user *)(uintptr_t)arg.in.urma_jfr_opt,
		sizeof(jfr_opt));
	if (ret != 0) {
		uburma_log_err("Failed to copy jfr_opt,ret %d.\n", ret);
		return ret;
	}

	uobj = uobj_get_write(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfr.\n");
		return -EINVAL;
	}

	jfr = (struct ubcore_jfr *)uobj->object;
	fill_udata(&udata, file->ucontext, &arg.udata);
	(void)memcpy(&jfr->jfr_opt, &jfr_opt, sizeof(jfr_opt));

	jfr->jfr_cfg.id = jfr_opt.urma_jfr_id;
	jfr->jfr_cfg.depth = arg.in.depth;
	jfr->jfr_cfg.eid_index = file->ucontext->eid_index;
	jfr->jfr_cfg.token_value.token = arg.in.token_value;
	jfr->jfr_cfg.min_rnr_timer = arg.in.min_rnr_timer;
	jfr->jfr_cfg.trans_mode = arg.in.trans_mode;
	jfr->jfr_cfg.max_sge = arg.in.max_sge;
	jfr->jfr_cfg.flag.value = arg.in.flag;

	jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.jfc_handle, file);
	if (IS_ERR_OR_NULL(jfc_uobj)) {
		uburma_log_err("failed to find jfc, jfc_handle:%llu.\n", arg.in.jfc_handle);
		uobj_put_write(uobj);
		ret = -EINVAL;
		return ret;
	}
	jfr->jfr_cfg.jfc = jfc_uobj->object;

	ret = ubcore_active_jfr(jfr, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("active jfr failed, ret:%d.\n", ret);
		return ret;
	}

	arg.out.id = jfr->jfr_id.id;
	arg.out.depth = jfr->jfr_cfg.depth;
	arg.out.handle = uobj->id;
	arg.out.max_sge = jfr->jfr_cfg.max_sge;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	uobj_put_read(jfc_uobj);
	return ret;
}

static int uburma_cmd_deactive_jfr(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_deactive_jfr arg;
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jfr *jfr;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_write(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfr.\n");
		return -EINVAL;
	}

	jfr = (struct ubcore_jfr *)uobj->object;

	fill_udata(&udata, file->ucontext, &arg.udata);

	ret = ubcore_deactive_jfr(jfr, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("deactivate jfr failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_create_jfc(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jfc arg;
	struct uburma_jfc_uobj *jfc_uobj;
	struct uburma_jfce_uobj *jfce;
	struct ubcore_jfc_cfg cfg = { 0 };
	struct ubcore_udata udata = {};
	struct ubcore_jfc *jfc;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	cfg.depth = arg.in.depth;
	cfg.flag.value = arg.in.flag;
	cfg.ceqn = arg.in.ceqn;

	/* jfce may be ERR_PTR */
	jfce = uburma_get_jfce_uobj(arg.in.jfce_fd, file);
	if (arg.in.jfce_fd >= 0 && IS_ERR_OR_NULL(jfce)) {
		uburma_log_err("Failed to get jfce.\n");
		return -EINVAL;
	}

	fill_udata(&udata, file->ucontext, &arg.udata);

	jfc_uobj = (struct uburma_jfc_uobj *)uobj_alloc(UOBJ_CLASS_JFC, file);
	if (IS_ERR_OR_NULL(jfc_uobj)) {
		uburma_log_err("UOBJ_CLASS_JFC alloc fail!\n");
		ret = -1;
		goto err_put_jfce;
	}
	jfc_uobj->comp_events_reported = 0;
	jfc_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jfc_uobj->comp_event_list);
	INIT_LIST_HEAD(&jfc_uobj->async_event_list);
	cfg.jfc_context = jfc_uobj;

	jfc = ubcore_create_jfc(ubc_dev, &cfg, uburma_jfce_handler,
				uburma_jfc_event_cb, &udata);
	if (IS_ERR_OR_NULL(jfc)) {
		ret = PTR_ERR(jfc);
		goto err_alloc_abort;
	}

	jfc_uobj->jfce = (struct uburma_uobj *)jfce;
	jfc_uobj->uobj.object = jfc;
	jfc->urma_jfc = arg.in.urma_jfc;
	spin_lock_init(&jfc_uobj->jfc_lock);

	/* Do not release jfae fd until jfc is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jfc;

	arg.out.id = jfc->id;
	arg.out.depth = jfc->jfc_cfg.depth;
	arg.out.handle = jfc_uobj->uobj.id;
	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto err_put_jfae;

	uobj_alloc_commit(&jfc_uobj->uobj);
	return 0;

err_put_jfae:
	uburma_put_jfae(file);
err_delete_jfc:
	(void)ubcore_delete_jfc(jfc);
err_alloc_abort:
	uobj_alloc_abort(&jfc_uobj->uobj);
err_put_jfce:
	if (!IS_ERR_OR_NULL(jfce))
		uobj_put(&jfce->uobj);
	return ret;
}

static int uburma_cmd_modify_jfc(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_jfc arg;
	struct uburma_uobj *uobj;
	struct ubcore_jfc_attr attr = { 0 };
	struct ubcore_udata udata = {};
	struct ubcore_jfc *jfc;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	attr.mask = arg.in.mask;
	attr.moderate_count = arg.in.moderate_count;
	attr.moderate_period = arg.in.moderate_period;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfc.\n");
		return -EINVAL;
	}

	jfc = (struct ubcore_jfc *)uobj->object;
	ret = ubcore_modify_jfc(jfc, &attr, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("modify jfc failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static void uburma_cleanup_jfce_references(struct uburma_jfc_uobj *jfc_uobj)
{
	unsigned long flag;

	spin_lock_irqsave(&jfc_uobj->jfc_lock, flag);
	jfc_uobj->jfce = NULL;
	spin_unlock_irqrestore(&jfc_uobj->jfc_lock, flag);
}

static int uburma_cmd_delete_jfc(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jfc arg;
	struct uburma_uobj *uobj;
	struct uburma_jfc_uobj *jfc_uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfc.\n");
		return -EINVAL;
	}

	/* To get events_reported after obj removed. */
	uobj_get(uobj);
	jfc_uobj = container_of(uobj, struct uburma_jfc_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("delete jfc failed, ret:%d.\n", ret);
		uburma_cleanup_jfce_references(jfc_uobj);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.comp_events_reported = jfc_uobj->comp_events_reported;
	arg.out.async_events_reported = jfc_uobj->async_events_reported;
	uburma_cleanup_jfce_references(jfc_uobj);
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, (void *)&arg);
}

static int uburma_cmd_active_jfc(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_active_jfc arg;
	struct ubcore_jfc_opt jfc_opt;
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jfc *jfc;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	if (!access_ok((void __user *)(uintptr_t)arg.in.urma_jfc_opt, sizeof(jfc_opt)))
		return -EFAULT;

	ret = uburma_copy_from_user(&jfc_opt, (void __user *)(uintptr_t)arg.in.urma_jfc_opt,
		sizeof(jfc_opt));
	if (ret != 0) {
		uburma_log_err("Failed to copy jfc_opt,ret is %d.\n", ret);
		return ret;
	}

	uobj = uobj_get_write(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfc.\n");
		return -EINVAL;
	}

	jfc = (struct ubcore_jfc *)uobj->object;

	fill_udata(&udata, file->ucontext, &arg.udata);
	(void)memcpy(&jfc->jfc_opt, &jfc_opt, sizeof(jfc_opt));

	jfc->jfc_cfg.depth = arg.in.depth;
	jfc->jfc_cfg.flag.value = arg.in.flag;
	jfc->jfc_cfg.ceqn = arg.in.ceqn;

	ret = ubcore_active_jfc(jfc, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("active jfc failed, ret:%d.\n", ret);
		return ret;
	}

	arg.out.id = jfc->id;
	arg.out.depth = jfc->jfc_cfg.depth;
	arg.out.handle = uobj->id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_deactive_jfc(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_deactive_jfc arg;
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jfc *jfc;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_write(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfc.\n");
		return -EINVAL;
	}

	jfc = (struct ubcore_jfc *)uobj->object;

	fill_udata(&udata, file->ucontext, &arg.udata);

	ret = ubcore_deactive_jfc(jfc, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("active jfc failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}


static int uburma_cmd_delete_jfc_batch(struct ubcore_device *ubc_dev,
				       struct uburma_file *file,
				       struct uburma_cmd_hdr *hdr)
{
	struct uburma_jfc_uobj *jfc_uobj = NULL;
	struct uburma_cmd_delete_jfc_batch arg;
	struct uburma_uobj **uobj_arr = NULL;
	uint32_t async_events_reported = 0;
	uint32_t comp_events_reported = 0;
	struct uburma_uobj *uobj = NULL;
	uint32_t bad_jfc_index = 0;
	uint64_t *jfc_arr = NULL;
	uint32_t arr_num;
	int ret_bad;
	int ret;
	int i;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	arr_num = arg.in.jfc_num;
	jfc_arr = kcalloc(arr_num, sizeof(uint64_t), GFP_KERNEL);
	if (!jfc_arr)
		return -ENOMEM;

	ret = uburma_copy_from_user((void *)jfc_arr,
				    (void __user *)arg.in.jfc_ptr,
				    arr_num * sizeof(uint64_t));
	if (ret != 0)
		goto free_jfc_arr;

	uobj_arr = kcalloc(arr_num, sizeof(struct uburma_uobj *), GFP_KERNEL);
	if (!uobj_arr) {
		ret = -ENOMEM;
		goto free_jfc_arr;
	}

	for (i = 0; i < arr_num; ++i) {
		uobj = uobj_get_del(UOBJ_CLASS_JFC, jfc_arr[i], file);
		uobj_arr[i] = uobj;
		if (IS_ERR(uobj)) {
			uburma_log_err("failed to find jfc, index is %d.\n", i);
			ret = -EINVAL;
			goto free_uobj_arr;
		}
		/* To get events_reported after obj removed. */
		uobj_get(uobj);
		jfc_uobj = container_of(uobj, struct uburma_jfc_uobj, uobj);
		comp_events_reported += jfc_uobj->comp_events_reported;
		async_events_reported += jfc_uobj->async_events_reported;
	}

	ret = uobj_remove_commit_batch(uobj_arr, arr_num, &bad_jfc_index);
	if (ret != 0)
		uburma_log_err("delete jfc failed, ret:%d.\n", ret);

	uobj_put_batch(uobj_arr, arr_num);
	uobj_put_del_batch(uobj_arr, arr_num);

	arg.out.comp_events_reported = comp_events_reported;
	arg.out.async_events_reported = async_events_reported;
	arg.out.bad_jfc_index = bad_jfc_index;

	ret_bad = uburma_tlv_append(hdr, (void *)&arg);
	if (ret_bad != 0) {
		uburma_log_err("uburma tlv append error, ret:%d.\n", ret_bad);
		ret = ret_bad;
	}

free_uobj_arr:
	kfree(uobj_arr);
free_jfc_arr:
	kfree(jfc_arr);
	return ret;
}

static int uburma_cmd_alloc_jfc(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_alloc_jfc arg = { 0 };
	struct uburma_jfc_uobj *jfc_uobj;
	struct uburma_jfce_uobj *jfce;
	struct ubcore_jfc_cfg cfg = { 0 };
	struct ubcore_udata udata;
	struct ubcore_jfc *jfc = NULL;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	cfg.depth = arg.in.depth;
	cfg.flag.value = arg.in.flag;
	cfg.ceqn = arg.in.ceqn;

	/* jfce may be ERR_PTR */
	jfce = uburma_get_jfce_uobj(arg.in.jfce_fd, file);
	if (arg.in.jfce_fd >= 0 && IS_ERR_OR_NULL(jfce)) {
		uburma_log_err("Failed to get jfce.\n");
		return -EINVAL;
	}

	fill_udata(&udata, file->ucontext, &arg.udata);

	jfc_uobj = (struct uburma_jfc_uobj *)uobj_alloc(UOBJ_CLASS_JFC, file);
	if (IS_ERR_OR_NULL(jfc_uobj)) {
		uburma_log_err("UOBJ_CLASS_JFC alloc fail!\n");
		ret = -1;
		goto err_put_jfce;
	}
	jfc_uobj->comp_events_reported = 0;
	jfc_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jfc_uobj->comp_event_list);
	INIT_LIST_HEAD(&jfc_uobj->async_event_list);
	cfg.jfc_context = jfc_uobj;

	ret = ubcore_alloc_jfc(ubc_dev, &cfg, uburma_jfce_handler,
		uburma_jfc_event_cb, &jfc, &udata);
	if (ret != 0) {
		uburma_log_err("alloc jfc or get jfc_id failed.\n");
		goto err_alloc_abort;
	}

	jfc_uobj->jfce = (struct uburma_uobj *)jfce;
	jfc_uobj->uobj.object = jfc;
	jfc->urma_jfc = arg.in.urma_jfc;

	/* Do not release jfae fd until jfc is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_free_jfc;

	arg.out.id = jfc->id;
	arg.out.depth = jfc->jfc_cfg.depth;
	arg.out.handle = jfc_uobj->uobj.id;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0)
		goto err_put_jfae;

	uobj_alloc_commit(&jfc_uobj->uobj);

	uburma_log_info("Finish to alloc jfc, jfc_id: %u.\n", jfc->id);
	return 0;

err_put_jfae:
	uburma_put_jfae(file);
err_free_jfc:
	(void)ubcore_free_jfc(jfc, &udata);
err_alloc_abort:
	uobj_alloc_abort(&jfc_uobj->uobj);
err_put_jfce:
	if (!IS_ERR_OR_NULL(jfce))
		uobj_put(&jfce->uobj);
	return ret;
}

static int uburma_cmd_free_jfc(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_free_jfc arg;
	struct uburma_uobj *uobj;
	struct uburma_jfc_uobj *jfc_uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfc.\n");
		return -EINVAL;
	}

	/* To get events_reported after obj removed. */
	uobj_get(uobj);
	jfc_uobj = container_of(uobj, struct uburma_jfc_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("delete jfc failed, ret:%d.\n", ret);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.comp_events_reported = jfc_uobj->comp_events_reported;
	arg.out.async_events_reported = jfc_uobj->async_events_reported;
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, (void *)&arg);
}

static int uburma_cmd_set_jfc_opt(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_set_jfc_opt arg = { 0 };
	struct uburma_uobj *uobj = { 0 };
	struct ubcore_udata udata = { 0 };
	struct ubcore_jfc *jfc;
	void __user *ubuf = NULL;
	void *kbuf = NULL;
	uint64_t opt;
	uint32_t len;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	opt = arg.in.opt;
	len = arg.in.len;
	ubuf = (void __user *)(uintptr_t)arg.in.buf;
	if (len > 0 && !access_ok(ubuf, len))
		return -EFAULT;
	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = uburma_copy_from_user(kbuf, ubuf, len);
	if (ret != 0) {
		uburma_log_err("copy_from_user failed,len is %u.\n", len);
		kfree(kbuf);
		return ret;
	}
	fill_udata(&udata, file->ucontext, &arg.udata);
	uobj = uobj_get_write(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfc.\n");
		kfree(kbuf);
		return -EINVAL;
	}
	jfc = (struct ubcore_jfc *)uobj->object;

	ret = ubcore_set_jfc_opt(jfc, opt, kbuf, len, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		kfree(kbuf);
		uburma_log_err("set_jfc_opt failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, (void *)&arg);
	kfree(kbuf);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_get_jfc_opt(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_jfc_opt arg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_udata udata = { 0 };
	struct ubcore_jfc *jfc;
	uint64_t opt;
	uint32_t len;
	int ret;
	void __user *ubuf = NULL;
	void *kbuf = NULL;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	opt = arg.in.opt;
	len = arg.in.len;
	ubuf = (void __user *)(uintptr_t)arg.in.buf;
	if (!access_ok(ubuf, len))
		return -EFAULT;

	fill_udata(&udata, file->ucontext, &arg.udata);
	uobj = uobj_get_write(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jfc.\n");
		return -EINVAL;
	}
	jfc = (struct ubcore_jfc *)uobj->object;
	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf) {
		uobj_put_write(uobj);
		return -ENOMEM;
	}

	ret = ubcore_get_jfc_opt(jfc, opt, kbuf, len, &udata);
	if (ret != 0) {
		kfree(kbuf);
		uobj_put_write(uobj);
		uburma_log_err("get_jfc_opt failed, ret:%d.\n", ret);
		return ret;
	}
	ret = uburma_copy_to_user(ubuf, kbuf, len);
	if (ret != 0) {
		kfree(kbuf);
		uobj_put_write(uobj);
		uburma_log_err("copy_to_user failed.\n");
		return ret;
	}
	kfree(kbuf);
	arg.out.buf = arg.in.buf;
	arg.out.len = len;
	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static void fill_create_jetty_attr(struct ubcore_jetty_cfg *cfg,
				   struct uburma_cmd_create_jetty *arg)
{
	cfg->id = arg->in.id;
	cfg->jfs_depth = arg->in.jfs_depth;
	cfg->jfr_depth = arg->in.jfr_depth;
	cfg->flag.bs.share_jfr = arg->in.jetty_flag &
				 0x1; // see urma_jetty_flag
	cfg->flag.bs.lock_free =
		((union ubcore_jfs_flag)arg->in.jfs_flag).bs.lock_free;
	cfg->flag.bs.error_suspend =
		((union ubcore_jfs_flag)arg->in.jfs_flag).bs.error_suspend;
	cfg->flag.bs.outorder_comp =
		((union ubcore_jfs_flag)arg->in.jfs_flag).bs.outorder_comp;
	cfg->flag.bs.order_type =
		((union ubcore_jfs_flag)arg->in.jfs_flag).bs.order_type;
	// see urma_jfs_flag

	cfg->max_send_sge = arg->in.max_send_sge;
	cfg->max_send_rsge = arg->in.max_send_rsge;
	cfg->max_recv_sge = arg->in.max_recv_sge;
	cfg->max_inline_data = arg->in.max_inline_data;
	cfg->priority = arg->in.priority;
	cfg->rnr_retry = arg->in.rnr_retry;
	cfg->err_timeout = arg->in.err_timeout;
	cfg->min_rnr_timer = arg->in.min_rnr_timer;
	cfg->trans_mode = arg->in.trans_mode;
}

static void fill_create_jetty_out(struct uburma_cmd_create_jetty *arg,
	struct ubcore_jetty *jetty)
{
	arg->out.id = jetty->jetty_id.id;
	arg->out.jfs_depth = jetty->jetty_cfg.jfs_depth;
	arg->out.jfr_depth = jetty->jetty_cfg.jfr_depth;
	arg->out.max_send_sge = jetty->jetty_cfg.max_send_sge;
	arg->out.max_send_rsge = jetty->jetty_cfg.max_send_rsge;
	arg->out.max_recv_sge = jetty->jetty_cfg.max_recv_sge;
	arg->out.max_inline_data = jetty->jetty_cfg.max_inline_data;
}

static int uburma_cmd_create_jetty(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jetty arg = { 0 };
	struct uburma_uobj *send_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *recv_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *jfr_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *jetty_grp_uobj = ERR_PTR(-ENOENT);
	struct ubcore_jetty_cfg cfg = { 0 };
	struct uburma_jetty_uobj *jetty_uobj;
	struct ubcore_udata udata = {};
	struct ubcore_jetty *jetty;
	int ret = 0;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	jetty_uobj =
		(struct uburma_jetty_uobj *)uobj_alloc(UOBJ_CLASS_JETTY, file);
	if (IS_ERR_OR_NULL(jetty_uobj)) {
		uburma_log_err("UOBJ_CLASS_JETTY alloc fail!\n");
		return -ENOMEM;
	}
	jetty_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jetty_uobj->async_event_list);
	cfg.jetty_context = jetty_uobj;

	fill_create_jetty_attr(&cfg, &arg);
	cfg.eid_index = file->ucontext->eid_index;
	send_jfc_uobj =
		uobj_get_read(UOBJ_CLASS_JFC, arg.in.send_jfc_handle, file);
	recv_jfc_uobj =
		uobj_get_read(UOBJ_CLASS_JFC, arg.in.recv_jfc_handle, file);
	if (IS_ERR_OR_NULL(send_jfc_uobj) || IS_ERR_OR_NULL(recv_jfc_uobj)) {
		uburma_log_err("failed to find send %llu or recv jfc %llu.\n",
			       arg.in.send_jfc_handle, arg.in.recv_jfc_handle);
		ret = -EINVAL;
		goto err_put;
	}
	cfg.send_jfc = send_jfc_uobj->object;
	cfg.recv_jfc = recv_jfc_uobj->object;
	if (arg.in.jfr_handle != 0) {
		jfr_uobj =
			uobj_get_read(UOBJ_CLASS_JFR, arg.in.jfr_handle, file);
		if (IS_ERR_OR_NULL(jfr_uobj)) {
			uburma_log_err("failed to find jfr, jfr_handle:%llu.\n",
				       arg.in.jfr_handle);
			ret = -EINVAL;
			goto err_put;
		}
		cfg.jfr = jfr_uobj->object;
		cfg.flag.bs.share_jfr = 1;
	}
	if (arg.in.is_jetty_grp != 0) {
		jetty_grp_uobj = uobj_get_read(UOBJ_CLASS_JETTY_GRP,
					       arg.in.jetty_grp_handle, file);
		if (IS_ERR_OR_NULL(jetty_grp_uobj)) {
			uburma_log_err(
				"failed to find jetty_grp, jetty_grp_handle:%llu.\n",
				arg.in.jetty_grp_handle);
			ret = -EINVAL;
			goto err_put;
		}
		cfg.jetty_grp =
			(struct ubcore_jetty_group *)jetty_grp_uobj->object;
	}
	cfg.token_value.token = arg.in.token;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jetty = ubcore_create_jetty(ubc_dev, &cfg, uburma_jetty_event_cb,
				    &udata);
	if (IS_ERR_OR_NULL(jetty)) {
		ret = PTR_ERR(jetty);
		goto err_put;
	}

	jetty_uobj->uobj.object = jetty;
	jetty->urma_jetty = arg.in.urma_jetty;
	/* Do not release jfae fd until jetty is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jetty;

	fill_create_jetty_out(&arg, jetty);
	arg.out.handle = jetty_uobj->uobj.id;

	ret = uburma_tlv_append(hdr, &arg);
	if (ret != 0)
		goto err_put_jfae;

	if (cfg.jetty_grp)
		uobj_put_read(jetty_grp_uobj);
	if (cfg.jfr)
		uobj_put_read(jfr_uobj);
	uobj_put_read(send_jfc_uobj);
	uobj_put_read(recv_jfc_uobj);
	uobj_alloc_commit(&jetty_uobj->uobj);
	return 0;

err_put_jfae:
	uburma_put_jfae(file);
err_delete_jetty:
	(void)ubcore_delete_jetty(jetty);
err_put:
	if (!IS_ERR_OR_NULL(jetty_grp_uobj))
		uobj_put_read(jetty_grp_uobj);
	if (!IS_ERR_OR_NULL(jfr_uobj))
		uobj_put_read(jfr_uobj);
	if (!IS_ERR_OR_NULL(recv_jfc_uobj))
		uobj_put_read(recv_jfc_uobj);
	if (!IS_ERR_OR_NULL(send_jfc_uobj))
		uobj_put_read(send_jfc_uobj);
	uobj_alloc_abort(&jetty_uobj->uobj);
	return ret;
}

static int uburma_cmd_modify_jetty(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_jetty arg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_jetty_attr attr = { 0 };
	struct ubcore_jetty *jetty;
	struct ubcore_udata udata = {};
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	attr.mask = arg.in.mask;
	attr.rx_threshold = arg.in.rx_threshold;
	attr.state = (enum ubcore_jetty_state)arg.in.state;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jetty.\n");
		return -EINVAL;
	}

	jetty = (struct ubcore_jetty *)uobj->object;
	ret = ubcore_modify_jetty(jetty, &attr, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("modify jetty failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, &arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_query_jetty(struct ubcore_device *ubc_dev,
				  struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_query_jetty arg = { 0 };
	struct ubcore_jetty_attr attr = { 0 };
	struct ubcore_jetty_cfg cfg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_jetty *jetty;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_read(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jetty.\n");
		return -EINVAL;
	}

	jetty = (struct ubcore_jetty *)uobj->object;
	ret = ubcore_query_jetty(jetty, &cfg, &attr);
	if (ret != 0) {
		uobj_put_read(uobj);
		uburma_log_err("query jetty failed, ret:%d.\n", ret);
		return ret;
	}

	arg.out.id = cfg.id;
	arg.out.jetty_flag = cfg.flag.value;

	arg.out.jfs_depth = cfg.jfs_depth;
	arg.out.jfs_flag = 0; // todo
	arg.out.trans_mode = (uint32_t)cfg.trans_mode;
	arg.out.priority = cfg.priority;
	arg.out.max_send_sge = cfg.max_send_sge;
	arg.out.max_send_rsge = cfg.max_send_rsge;
	arg.out.max_inline_data = cfg.max_inline_data;
	arg.out.rnr_retry = cfg.rnr_retry;
	arg.out.err_timeout = cfg.err_timeout;

	if (cfg.flag.bs.share_jfr == 1) {
		arg.out.jfr_depth = cfg.jfr_depth;
		arg.out.jfr_flag = 0; // todo
		arg.out.max_recv_sge = cfg.max_recv_sge;
		arg.out.min_rnr_timer = cfg.min_rnr_timer;
		arg.out.token = cfg.token_value.token;
		arg.out.jfr_id = 0; // todo
	}

	arg.out.rx_threshold = attr.rx_threshold;
	arg.out.state = (uint32_t)attr.state;
	ret = uburma_tlv_append(hdr, &arg);
	uobj_put_read(uobj);
	return ret;
}

static int uburma_cmd_delete_jetty(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jetty arg;
	struct uburma_jetty_uobj *jetty_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jetty");
		return -EINVAL;
	}

	/* To get async_events_reported after obj removed. */
	uobj_get(uobj);
	jetty_uobj = container_of(uobj, struct uburma_jetty_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("delete jetty failed, ret:%d.\n", ret);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.async_events_reported = jetty_uobj->async_events_reported;
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, &arg);
}

static int uburma_cmd_delete_jetty_batch(struct ubcore_device *ubc_dev,
					 struct uburma_file *file,
					 struct uburma_cmd_hdr *hdr)
{
	struct uburma_jetty_uobj *jetty_uobj = NULL;
	struct uburma_cmd_delete_jetty_batch arg;
	struct uburma_uobj **uobj_arr = NULL;
	uint32_t async_events_reported = 0;
	struct uburma_uobj *uobj = NULL;
	uint32_t bad_jetty_index = 0;
	uint64_t *jetty_arr = NULL;
	uint32_t arr_num;
	int ret_bad;
	int ret;
	int i;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	arr_num = arg.in.jetty_num;
	jetty_arr = kcalloc(arr_num, sizeof(uint64_t), GFP_KERNEL);
	if (!jetty_arr)
		return -ENOMEM;

	ret = uburma_copy_from_user((void *)jetty_arr,
				    (void __user *)arg.in.jetty_ptr,
				    arr_num * sizeof(uint64_t));
	if (ret != 0)
		goto free_jetty_arr;

	uobj_arr = kcalloc(arr_num, sizeof(struct uburma_uobj *), GFP_KERNEL);
	if (!uobj_arr) {
		ret = -ENOMEM;
		goto free_jetty_arr;
	}

	for (i = 0; i < arr_num; ++i) {
		uobj = uobj_get_del(UOBJ_CLASS_JETTY, jetty_arr[i], file);
		uobj_arr[i] = uobj;
		if (IS_ERR(uobj)) {
			uburma_log_err("failed to find jetty, index is %d.\n",
				       i);
			ret = -EINVAL;
			goto free_uobj_arr;
		}
		/* To get events_reported after obj removed. */
		uobj_get(uobj);
		jetty_uobj = container_of(uobj, struct uburma_jetty_uobj, uobj);
		async_events_reported += jetty_uobj->async_events_reported;
	}

	ret = uobj_remove_commit_batch(uobj_arr, arr_num, &bad_jetty_index);
	if (ret != 0)
		uburma_log_err("delete jetty failed, ret:%d.\n", ret);

	arg.out.async_events_reported = async_events_reported;
	arg.out.bad_jetty_index = bad_jetty_index;

	uobj_put_batch(uobj_arr, arr_num);
	uobj_put_del_batch(uobj_arr, arr_num);

	ret_bad = uburma_tlv_append(hdr, (void *)&arg);
	if (ret_bad != 0) {
		uburma_log_err("uburma tlv append error, ret:%d.\n", ret_bad);
		ret = ret_bad;
	}

free_uobj_arr:
	kfree(uobj_arr);
free_jetty_arr:
	kfree(jetty_arr);
	return ret;
}

static int uburma_cmd_alloc_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_alloc_jetty alloc_arg = {0};
	struct uburma_uobj *send_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *recv_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *jfr_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *jetty_grp_uobj = ERR_PTR(-ENOENT);
	struct ubcore_jetty_cfg cfg = {0};
	struct uburma_jetty_uobj *jetty_uobj;
	struct ubcore_udata udata;
	struct ubcore_jetty *jetty = NULL;
	struct uburma_cmd_create_jetty *arg;
	int ret = 0;

	ret = uburma_tlv_parse(hdr, &alloc_arg);
	if (ret != 0)
		return ret;
	arg = &alloc_arg.create_jetty;

	jetty_uobj = (struct uburma_jetty_uobj *)uobj_alloc(UOBJ_CLASS_JETTY, file);
	if (IS_ERR_OR_NULL(jetty_uobj)) {
		uburma_log_err("UOBJ_CLASS_JETTY alloc fail!\n");
		return -ENOMEM;
	}
	jetty_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jetty_uobj->async_event_list);
	cfg.jetty_context = jetty_uobj;

	fill_create_jetty_attr(&cfg, arg);
	cfg.eid_index = file->ucontext->eid_index;
	send_jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg->in.send_jfc_handle, file);
	recv_jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg->in.recv_jfc_handle, file);
	if (IS_ERR_OR_NULL(send_jfc_uobj) || IS_ERR_OR_NULL(recv_jfc_uobj)) {
		uburma_log_err("failed to find send %llu or recv jfc %llu.\n",
			       arg->in.send_jfc_handle, arg->in.recv_jfc_handle);
		ret = -EINVAL;
		goto err_put;
	}
	cfg.send_jfc = send_jfc_uobj->object;
	cfg.recv_jfc = recv_jfc_uobj->object;
	if (arg->in.jfr_handle != 0) {
		jfr_uobj = uobj_get_read(UOBJ_CLASS_JFR, arg->in.jfr_handle, file);
		if (IS_ERR_OR_NULL(jfr_uobj)) {
			uburma_log_err("failed to find jfr, jfr_handle:%llu.\n",
				arg->in.jfr_handle);
			ret = -EINVAL;
			goto err_put;
		}
		cfg.jfr = jfr_uobj->object;
		cfg.flag.bs.share_jfr = 1;
	}
	if (arg->in.is_jetty_grp != 0) {
		jetty_grp_uobj = uobj_get_read(UOBJ_CLASS_JETTY_GRP,
			arg->in.jetty_grp_handle, file);
		if (IS_ERR_OR_NULL(jetty_grp_uobj)) {
			uburma_log_err("failed to find jetty_grp, jetty_grp_handle:%llu.\n",
				arg->in.jetty_grp_handle);
			ret = -EINVAL;
			goto err_put;
		}
		cfg.jetty_grp = (struct ubcore_jetty_group *)jetty_grp_uobj->object;
	}
	fill_udata(&udata, file->ucontext, &arg->udata);

	ret = ubcore_alloc_jetty(ubc_dev, &cfg, uburma_jetty_event_cb, &jetty, &udata);
	if (ret != 0) {
		uburma_log_err("alloc jetty or get jetty_id failed.\n");
		goto err_put;
	}

	jetty_uobj->uobj.object = jetty;
	jetty->urma_jetty = arg->in.urma_jetty;
	/* Do not release jfae fd until jetty is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jetty;

	fill_create_jetty_out(arg, jetty);
	arg->out.handle = jetty_uobj->uobj.id;

	ret = uburma_tlv_append(hdr, &alloc_arg);
	if (ret != 0)
		goto err_put_jfae;

	if (cfg.jetty_grp)
		uobj_put_read(jetty_grp_uobj);
	if (cfg.jfr)
		uobj_put_read(jfr_uobj);
	uobj_put_read(send_jfc_uobj);
	uobj_put_read(recv_jfc_uobj);
	uobj_alloc_commit(&jetty_uobj->uobj);
	return 0;

err_put_jfae:
	uburma_put_jfae(file);
err_delete_jetty:
	(void)ubcore_free_jetty(jetty, &udata);
err_put:
	if (!IS_ERR_OR_NULL(jetty_grp_uobj))
		uobj_put_read(jetty_grp_uobj);
	if (!IS_ERR_OR_NULL(jfr_uobj))
		uobj_put_read(jfr_uobj);
	if (!IS_ERR_OR_NULL(recv_jfc_uobj))
		uobj_put_read(recv_jfc_uobj);
	if (!IS_ERR_OR_NULL(send_jfc_uobj))
		uobj_put_read(send_jfc_uobj);
	uobj_alloc_abort(&jetty_uobj->uobj);
	return ret;
}

static int uburma_cmd_free_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_free_jetty arg;
	struct uburma_jetty_uobj *jetty_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jetty");
		return -EINVAL;
	}

	/* To get async_events_reported after obj removed. */
	uobj_get(uobj);
	jetty_uobj = container_of(uobj, struct uburma_jetty_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("free jetty failed, ret:%d.\n", ret);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.async_events_reported = jetty_uobj->async_events_reported;
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, &arg);
}

static int uburma_cmd_set_jetty_opt(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_set_jetty_opt arg = { 0 };
	struct uburma_uobj *recv_jfc_uobj = NULL;
	struct uburma_uobj *send_jfc_uobj = NULL;
	struct uburma_uobj *jfr_uobj = NULL;
	struct uburma_uobj *jrp_uobj = NULL;
	struct uburma_uobj *uobj = NULL;
	struct ubcore_udata udata = { 0 };
	struct ubcore_jetty *jetty;
	struct ubcore_jfc *new_recv_jfc;
	struct ubcore_jfc *new_send_jfc;
	struct ubcore_jfr *new_jfr;
	struct ubcore_jetty_group *new_jrp;

	uint64_t recv_jfc_handle;
	uint64_t send_jfc_handle;
	uint64_t jrp_handle;
	uint64_t jfr_handle;

	void __user *ubuf = NULL;
	void *kbuf = NULL;
	void *opt_kbuf = NULL;

	uint64_t opt;
	uint32_t len;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret)
		return ret;

	opt = arg.in.opt;
	len = arg.in.len;
	ubuf = (void __user *)(uintptr_t)arg.in.buf;

	if (len > 0 && !access_ok(ubuf, len))
		return -EFAULT;

	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = uburma_copy_from_user(kbuf, ubuf, len);
	if (ret) {
		ret = -EFAULT;
		goto err_free_kbuf;
	}

	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		ret = -EINVAL;
		goto err_free_kbuf;
	}
	jetty = (struct ubcore_jetty *)uobj->object;

	opt_kbuf = kbuf;

	switch (opt) {
	case UBCORE_JETTY_BIND_RX_JFC:
		if (len != sizeof(uint64_t)) {
			ret = -EINVAL;
			goto err_put_jetty;
		}
		memcpy(&recv_jfc_handle, kbuf, sizeof(recv_jfc_handle));
		recv_jfc_uobj = uobj_get_write(UOBJ_CLASS_JFC, recv_jfc_handle, file);
		if (IS_ERR_OR_NULL(recv_jfc_uobj)) {
			ret = -EINVAL;
			goto err_put_jetty;
		}
		new_recv_jfc = (struct ubcore_jfc *)recv_jfc_uobj->object;
		opt_kbuf = &new_recv_jfc;
		break;
	case UBCORE_JETTY_BIND_JFR:
		if (len != sizeof(uint64_t)) {
			ret = -EINVAL;
			goto err_put_jetty;
		}
		memcpy(&jfr_handle, kbuf, sizeof(jfr_handle));
		jfr_uobj = uobj_get_write(UOBJ_CLASS_JFR, jfr_handle, file);
		if (IS_ERR_OR_NULL(jfr_uobj)) {
			ret = -EINVAL;
			goto err_put_jetty;
		}
		new_jfr = (struct ubcore_jfr *)jfr_uobj->object;
		opt_kbuf = &new_jfr;
		break;
	case UBCORE_JETTY_BIND_JTG:
		if (len != sizeof(uint64_t)) {
			ret = -EINVAL;
			goto err_put_jetty;
		}
		memcpy(&jrp_handle, kbuf, sizeof(jrp_handle));
		jrp_uobj = uobj_get_write(UOBJ_CLASS_JETTY_GRP, jrp_handle, file);
		if (IS_ERR_OR_NULL(jrp_uobj)) {
			ret = -EINVAL;
			goto err_put_jetty;
		}
		new_jrp = (struct ubcore_jetty_group *)jrp_uobj->object;
		opt_kbuf = &new_jrp;
		break;
	case UBCORE_JFS_BIND_JFC:
		if (len != sizeof(uint64_t)) {
			ret = -EINVAL;
			goto err_put_jetty;
		}
		memcpy(&send_jfc_handle, kbuf, sizeof(send_jfc_handle));
		send_jfc_uobj = uobj_get_write(UOBJ_CLASS_JFC, send_jfc_handle, file);
		if (IS_ERR_OR_NULL(send_jfc_uobj)) {
			ret = -EINVAL;
			goto err_put_jetty;
		}
		new_send_jfc = (struct ubcore_jfc *)send_jfc_uobj->object;
		opt_kbuf = &new_send_jfc;
		break;
	default:
		break;
	}

	ret = ubcore_set_jetty_opt(jetty, opt, opt_kbuf, len, &udata);
	if (ret) {
		uburma_log_err("set_jetty_opt failed,ret:%d\n", ret);
		goto err_put_all;
	}
	ret = uburma_tlv_append(hdr, (void *)&arg);

err_put_all:
	if (recv_jfc_uobj)
		uobj_put_write(recv_jfc_uobj);
	if (send_jfc_uobj)
		uobj_put_write(send_jfc_uobj);
	if (jfr_uobj)
		uobj_put_write(jfr_uobj);
	if (jrp_uobj)
		uobj_put_write(jrp_uobj);

err_put_jetty:
	uobj_put_write(uobj);

err_free_kbuf:
	kfree(kbuf);
	return ret;
}

static int uburma_cmd_get_jetty_opt(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_jetty_opt arg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_udata udata = { 0 };
	struct ubcore_jetty *jetty;
	uint64_t opt;
	uint32_t len;
	int ret;
	void __user *ubuf = NULL;
	void *kbuf = NULL;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	opt = arg.in.opt;
	len = arg.in.len;
	ubuf = (void __user *)(uintptr_t)arg.in.buf;
	if (!access_ok(ubuf, len))
		return -EFAULT;

	fill_udata(&udata, file->ucontext, &arg.udata);
	uobj = uobj_get_write(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jetty.\n");
		return -EINVAL;
	}
	jetty = (struct ubcore_jetty *)uobj->object;
	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf) {
		uobj_put_write(uobj);
		return -ENOMEM;
	}

	ret = ubcore_get_jetty_opt(jetty, opt, kbuf, len, &udata);
	if (ret != 0) {
		kfree(kbuf);
		uobj_put_write(uobj);
		uburma_log_err("get_jetty_opt failed, ret:%d.\n", ret);
		return ret;
	}
	ret = uburma_copy_to_user(ubuf, kbuf, len);
	if (ret != 0) {
		kfree(kbuf);
		uobj_put_write(uobj);
		uburma_log_err("copy_to_user failed.\n");
		return -EFAULT;
	}
	kfree(kbuf);
	arg.out.buf = arg.in.buf;
	arg.out.len = len;
	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_active_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_active_jetty arg = { 0 };
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jetty_opt jetty_opt;
	struct ubcore_jetty *jetty;
	struct uburma_uobj *recv_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *send_jfc_uobj = ERR_PTR(-ENOENT);
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	if (!access_ok((void __user *)(uintptr_t)arg.in.jetty_opt, sizeof(jetty_opt)))
		return -EFAULT;
	ret = uburma_copy_from_user(&jetty_opt, (void __user *)(uintptr_t)arg.in.jetty_opt,
		sizeof(jetty_opt));
	if (ret != 0) {
		uburma_log_err("Failed to copy jetty_opt,ret is %d.\n", ret);
		return ret;
	}

	uobj = uobj_get_write(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jetty.\n");
		return -EINVAL;
	}
	jetty = (struct ubcore_jetty *)uobj->object;
	recv_jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.recv_jfc_handle, file);
	send_jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.send_jfc_handle, file);
	if (IS_ERR_OR_NULL(recv_jfc_uobj) || IS_ERR_OR_NULL(send_jfc_uobj)) {
		uburma_log_err("failed to find send jfc %llu or recv jfc %llu.\n",
			arg.in.send_jfc_handle, arg.in.recv_jfc_handle);
		ret = -EINVAL;
		goto err_put;
	}
	jetty->jetty_cfg.recv_jfc = recv_jfc_uobj->object;
	jetty->jetty_cfg.send_jfc = send_jfc_uobj->object;
	jetty->jetty_opt = jetty_opt;
	jetty->jetty_cfg.flag.bs.lock_free = ((union ubcore_jfs_flag)arg.in.flag).bs.lock_free;
	jetty->jetty_cfg.flag.bs.error_suspend =
		((union ubcore_jfs_flag)arg.in.flag).bs.error_suspend;
	jetty->jetty_cfg.flag.bs.outorder_comp =
		((union ubcore_jfs_flag)arg.in.flag).bs.outorder_comp;
	jetty->jetty_cfg.flag.bs.order_type = ((union ubcore_jfs_flag)arg.in.flag).bs.order_type;
	fill_udata(&udata, file->ucontext, &arg.udata);

	ret = ubcore_active_jetty(jetty, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("active jetty failed, ret:%d.\n", ret);
		return ret;
	}

	arg.out.jetty_id = jetty->jetty_id.id;
	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	uobj_put_read(send_jfc_uobj);
	uobj_put_read(recv_jfc_uobj);
	return ret;
err_put:
	if (!IS_ERR_OR_NULL(recv_jfc_uobj))
		uobj_put_read(recv_jfc_uobj);
	if (!IS_ERR_OR_NULL(send_jfc_uobj))
		uobj_put_read(send_jfc_uobj);
	return ret;
}

static int uburma_cmd_deactive_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_deactive_jetty arg;
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jetty *jetty;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_write(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jetty.\n");
		return -EINVAL;
	}

	jetty = (struct ubcore_jetty *)uobj->object;

	fill_udata(&udata, file->ucontext, &arg.udata);

	ret = ubcore_deactive_jetty(jetty, &udata);
	if (ret != 0) {
		uobj_put_write(uobj);
		uburma_log_err("active jetty failed, ret:%d.\n", ret);
		return ret;
	}

	ret = uburma_tlv_append(hdr, (void *)&arg);
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_create_jfce(struct ubcore_device *ubc_dev,
				  struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jfce arg;
	struct uburma_jfce_uobj *jfce;
	struct uburma_uobj *uobj;

	uobj = uobj_alloc(UOBJ_CLASS_JFCE, file);
	if (IS_ERR_OR_NULL(uobj))
		return PTR_ERR(uobj);

	jfce = container_of(uobj, struct uburma_jfce_uobj, uobj);
	uburma_init_jfe(&jfce->jfe);

	arg.out.fd = uobj->id; /* should get fd before commit uobj */
	uobj_alloc_commit(uobj);

	return uburma_tlv_append(hdr, (void *)&arg);
}

static int uburma_cmd_import_jfr(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_import_jfr arg;
	struct ubcore_tjetty_cfg cfg = { 0 };
	struct ubcore_udata udata = {};
	struct ubcore_tjetty *tjfr;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_JFR, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("UOBJ_CLASS_TARGET_JFR alloc fail!\n");
		return -ENOMEM;
	}

	(void)memcpy(cfg.id.eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	cfg.id.id = arg.in.id;
	cfg.flag.value = arg.in.flag;
	cfg.token_value.token = arg.in.token;
	cfg.trans_mode = arg.in.trans_mode;
	cfg.tp_type = (enum ubcore_tp_type)arg.in.tp_type;
	cfg.eid_index = file->ucontext->eid_index;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tjfr = ubcore_import_jfr(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(tjfr)) {
		uobj_alloc_abort(uobj);
		return PTR_ERR(tjfr);
	}

	uobj->object = tjfr;
	arg.out.handle = (uint64_t)uobj->id;
	if (tjfr->vtpn)
		arg.out.tpn = tjfr->vtpn->vtpn;
	else if (tjfr->tp)
		arg.out.tpn = tjfr->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0) {
		ubcore_unimport_jfr(tjfr);
		uobj_alloc_abort(uobj);
		return ret;
	}
	uobj_alloc_commit(uobj);
	return 0;
}

static int uburma_cmd_import_jfr_ex(struct ubcore_device *ubc_dev,
				    struct uburma_file *file,
				    struct uburma_cmd_hdr *hdr)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	struct uburma_cmd_import_jfr_ex arg = { 0 };
	struct ubcore_tjetty_cfg cfg = { 0 };
	struct ubcore_udata udata = { 0 };
	struct ubcore_tjetty *tjfr;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, (void *)&arg);
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_JFR, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("UOBJ_CLASS_TARGET_JFR alloc fail!\n");
		return -ENOMEM;
	}

	(void)memcpy(cfg.id.eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	cfg.id.id = arg.in.id;
	cfg.flag.value = arg.in.flag;
	cfg.token_value.token = arg.in.token;
	cfg.trans_mode = arg.in.trans_mode;
	cfg.tp_type = (enum ubcore_tp_type)arg.in.tp_type;
	cfg.eid_index = file->ucontext->eid_index;

	active_tp_cfg.tp_handle.value = arg.in.tp_handle;
	active_tp_cfg.peer_tp_handle.value = arg.in.peer_tp_handle;
	active_tp_cfg.tag = arg.in.tag;
	active_tp_cfg.tp_attr.tx_psn = arg.in.tx_psn;
	active_tp_cfg.tp_attr.rx_psn = arg.in.rx_psn;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tjfr = ubcore_import_jfr_ex(ubc_dev, &cfg, &active_tp_cfg, &udata);
	if (IS_ERR_OR_NULL(tjfr)) {
		uobj_alloc_abort(uobj);
		return PTR_ERR(tjfr);
	}

	uobj->object = tjfr;
	arg.out.handle = (uint64_t)uobj->id;
	if (tjfr->vtpn)
		arg.out.tpn = tjfr->vtpn->vtpn;
	else if (tjfr->tp)
		arg.out.tpn = tjfr->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	ret = uburma_tlv_append(hdr, (void *)&arg);
	if (ret != 0) {
		ubcore_unimport_jfr(tjfr);
		uobj_alloc_abort(uobj);
		return ret;
	}
	uobj_alloc_commit(uobj);
	return 0;
}

static int uburma_cmd_unimport_jfr(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unimport_jfr arg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_TARGET_JFR, arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find tjfr");
		return -EINVAL;
	}
	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("Remove tjfr uobj failed.\n");

	uobj_put_del(uobj);
	return ret;
}

static int uburma_cmd_import_jetty(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_import_jetty arg;
	struct ubcore_tjetty_cfg cfg = { 0 };
	struct ubcore_tjetty *tjetty;
	struct ubcore_udata udata = {};
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_JETTY, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("UOBJ_CLASS_TARGET_JETTY alloc fail!\n");
		return -ENOMEM;
	}

	(void)memcpy(cfg.id.eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	cfg.id.id = arg.in.id;
	cfg.token_value.token = arg.in.token;
	cfg.trans_mode = (enum ubcore_transport_mode)arg.in.trans_mode;
	cfg.flag.value = arg.in.flag;
	cfg.policy = (enum ubcore_jetty_grp_policy)arg.in.policy;
	cfg.type = (enum ubcore_target_type)arg.in.type;
	cfg.tp_type = (enum ubcore_tp_type)arg.in.tp_type;
	cfg.eid_index = file->ucontext->eid_index;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tjetty = ubcore_import_jetty(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		uobj_alloc_abort(uobj);
		return PTR_ERR(tjetty);
	}

	uobj->object = tjetty;
	arg.out.handle = (uint64_t)uobj->id;
	if (tjetty->vtpn)
		arg.out.tpn = tjetty->vtpn->vtpn;
	else if (tjetty->tp)
		arg.out.tpn = tjetty->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	ret = uburma_tlv_append(hdr, &arg);
	if (ret != 0) {
		(void)ubcore_unimport_jetty(tjetty);
		uobj_alloc_abort(uobj);
		return ret;
	}
	uobj_alloc_commit(uobj);
	return 0;
}

int uburma_unimport_jetty(struct uburma_file *file, bool async,
			  int tjetty_handle)
{
	struct uburma_tjetty_uobj *tjetty_uobj;
	struct uburma_uobj *uobj;
	int ret;

	uobj = uobj_get_del(UOBJ_CLASS_TARGET_JETTY, tjetty_handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find tjetty");
		return -EINVAL;
	}

	uobj_get(uobj);
	tjetty_uobj = container_of(uobj, struct uburma_tjetty_uobj, uobj);
	tjetty_uobj->should_unimport_async = async;
	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("ubcore_unimport_jetty_async failed.\n");

	uobj_put(uobj);
	uobj_put_del(uobj);
	return ret;
}

static int uburma_cmd_unimport_jetty(struct ubcore_device *ubc_dev,
				     struct uburma_file *file,
				     struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unimport_jetty arg;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	return uburma_unimport_jetty(file, false, arg.in.handle);
}

static int uburma_get_jetty_tjetty_objs(struct uburma_file *file,
					uint64_t jetty_handle,
					uint64_t tjetty_handle,
					struct uburma_uobj **jetty_uobj,
					struct uburma_uobj **tjetty_uobj)
{
	*jetty_uobj = uobj_get_read(UOBJ_CLASS_JETTY, jetty_handle, file);
	if (IS_ERR_OR_NULL(*jetty_uobj)) {
		uburma_log_err("failed to find jetty with handle %llu",
			       jetty_handle);
		return -EINVAL;
	}

	*tjetty_uobj =
		uobj_get_read(UOBJ_CLASS_TARGET_JETTY, tjetty_handle, file);
	if (IS_ERR_OR_NULL(*tjetty_uobj)) {
		uobj_put_read(*jetty_uobj);
		uburma_log_err("failed to find target jetty with handle %llu",
			       tjetty_handle);
		return -EINVAL;
	}
	return 0;
}

static inline void uburma_put_jetty_tjetty_objs(struct uburma_uobj *jetty_uobj,
						struct uburma_uobj *tjetty_uobj)
{
	uobj_put_read(jetty_uobj);
	uobj_put_read(tjetty_uobj);
}

static inline void uburma_put_jfs_tjfr_objs(struct uburma_uobj *jetty_uobj,
					    struct uburma_uobj *tjetty_uobj)
{
	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
}

static int uburma_cmd_bind_jetty(struct ubcore_device *ubc_dev,
				 struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_tjetty_uobj *uburma_tjetty;
	struct uburma_cmd_bind_jetty arg;
	struct uburma_uobj *tjetty_uobj;
	struct uburma_uobj *jetty_uobj;
	struct ubcore_tjetty *tjetty;
	struct ubcore_udata udata = {};
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	if (uburma_get_jetty_tjetty_objs(file, arg.in.jetty_handle,
					 arg.in.tjetty_handle, &jetty_uobj,
					 &tjetty_uobj))
		return -EINVAL;

	fill_udata(&udata, file->ucontext, &arg.udata);

	tjetty = (struct ubcore_tjetty *)tjetty_uobj->object;
	ret = ubcore_bind_jetty(jetty_uobj->object, tjetty, &udata);
	if (ret != 0) {
		uburma_log_err("bind jetty failed.\n");
		uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
		return ret;
	}

	if (tjetty->vtpn)
		arg.out.tpn = tjetty->vtpn->vtpn;
	else if (tjetty->tp)
		arg.out.tpn = tjetty->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	uburma_tjetty = (struct uburma_tjetty_uobj *)(tjetty_uobj);
	uburma_tjetty->jetty_uobj = (struct uburma_jetty_uobj *)jetty_uobj;
	ret = uburma_tlv_append(hdr, &arg);
	if (ret != 0)
		(void)ubcore_unbind_jetty(jetty_uobj->object);

	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
	return ret;
}

static int uburma_cmd_bind_jetty_ex(struct ubcore_device *ubc_dev,
				    struct uburma_file *file,
				    struct uburma_cmd_hdr *hdr)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	struct uburma_cmd_bind_jetty_ex arg = { 0 };
	struct ubcore_active_tp_cfg empty_cfg = { 0 };
	struct uburma_tjetty_uobj *uburma_tjetty;
	struct ubcore_udata udata = { 0 };
	struct uburma_uobj *tjetty_uobj;
	struct uburma_uobj *jetty_uobj;
	struct ubcore_tjetty *tjetty;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	if (uburma_get_jetty_tjetty_objs(file, arg.in.jetty_handle,
					 arg.in.tjetty_handle, &jetty_uobj,
					 &tjetty_uobj))
		return -EINVAL;

	active_tp_cfg.tp_handle.value = arg.in.tp_handle;
	active_tp_cfg.peer_tp_handle.value = arg.in.peer_tp_handle;
	active_tp_cfg.tag = arg.in.tag;
	active_tp_cfg.tp_attr.tx_psn = arg.in.tx_psn;
	active_tp_cfg.tp_attr.rx_psn = arg.in.rx_psn;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tjetty = (struct ubcore_tjetty *)tjetty_uobj->object;
	if (memcmp(&active_tp_cfg, &empty_cfg, sizeof(active_tp_cfg)) == 0) {
		uburma_log_info("tp_handle is null, exec ubcore_bind_jetty");
		ret = ubcore_bind_jetty(jetty_uobj->object, tjetty, &udata);
	} else {
		uburma_log_info("tp_handle is null, exec ubcore_bind_jetty_ex");
		ret = ubcore_bind_jetty_ex(jetty_uobj->object, tjetty, &active_tp_cfg,
			   &udata);
	}
	if (ret != 0) {
		uburma_log_err("bind jetty failed, ret: %d.\n", ret);
		uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
		return ret;
	}

	if (tjetty->vtpn)
		arg.out.tpn = tjetty->vtpn->vtpn;
	else if (tjetty->tp)
		arg.out.tpn = tjetty->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	uburma_tjetty = (struct uburma_tjetty_uobj *)(tjetty_uobj);
	uburma_tjetty->jetty_uobj = (struct uburma_jetty_uobj *)jetty_uobj;
	ret = uburma_tlv_append(hdr, &arg);
	if (ret != 0)
		(void)ubcore_unbind_jetty(jetty_uobj->object);

	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
	return ret;
}

int uburma_unbind_jetty(struct uburma_file *file, bool async, int jetty_handle,
			int tjetty_handle)
{
	struct uburma_tjetty_uobj *uburma_tjetty;
	struct uburma_uobj *tjetty_uobj;
	struct uburma_uobj *jetty_uobj;
	int ret;

	if (uburma_get_jetty_tjetty_objs(file, jetty_handle, tjetty_handle,
					 &jetty_uobj, &tjetty_uobj))
		return -EINVAL;

	if (async)
		ret = ubcore_unbind_jetty_async(jetty_uobj->object, 0, NULL);
	else
		ret = ubcore_unbind_jetty(jetty_uobj->object);
	if (ret != 0)
		uburma_log_err("failed to unbind jetty, ret: %d.\n", ret);

	uburma_tjetty = (struct uburma_tjetty_uobj *)(tjetty_uobj);
	uburma_tjetty->jetty_uobj = NULL;

	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
	return ret;
}

static int uburma_cmd_unbind_jetty(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unadvise_jetty arg;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	return uburma_unbind_jetty(file, false, arg.in.jetty_handle,
				   arg.in.tjetty_handle);
}

static int uburma_cmd_create_jetty_grp(struct ubcore_device *ubc_dev,
				       struct uburma_file *file,
				       struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jetty_grp arg;
	struct uburma_jetty_grp_uobj *jetty_grp_uobj;
	struct ubcore_jetty_grp_cfg cfg = { 0 };
	struct ubcore_udata udata = {};
	struct ubcore_jetty_group *jetty_grp;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	arg.in.name[UBCORE_JETTY_GRP_MAX_NAME - 1] = '\0';
	(void)memcpy(cfg.name, arg.in.name, UBCORE_JETTY_GRP_MAX_NAME);
	cfg.name[UBCORE_JETTY_GRP_MAX_NAME - 1] = '\0';

	cfg.token_value.token = arg.in.token;
	cfg.id = arg.in.id;
	cfg.policy = (enum ubcore_jetty_grp_policy)arg.in.policy;
	cfg.flag.value = arg.in.flag;
	cfg.eid_index = file->ucontext->eid_index;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jetty_grp_uobj = (struct uburma_jetty_grp_uobj *)uobj_alloc(
		UOBJ_CLASS_JETTY_GRP, file);
	if (IS_ERR_OR_NULL(jetty_grp_uobj)) {
		uburma_log_err("UOBJ_CLASS_JETTY_GRP alloc fail!\n");
		return -ENOMEM;
	}
	jetty_grp_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jetty_grp_uobj->async_event_list);
	cfg.user_ctx = (uint64_t)jetty_grp_uobj;

	jetty_grp = ubcore_create_jetty_grp(ubc_dev, &cfg,
					    uburma_jetty_grp_event_cb, &udata);
	if (IS_ERR_OR_NULL(jetty_grp)) {
		uburma_log_err("create jetty_grp failed.\n");
		ret = PTR_ERR(jetty_grp);
		goto err_alloc_abort;
	}
	jetty_grp_uobj->uobj.object = jetty_grp;
	jetty_grp->urma_jetty_grp = arg.in.urma_jetty_grp;

	/* Do not release jfae fd until jetty_grp is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jetty_grp;

	arg.out.id = jetty_grp->jetty_grp_id.id;
	arg.out.handle = jetty_grp_uobj->uobj.id;

	ret = uburma_tlv_append(hdr, &arg);
	if (ret != 0)
		goto err_put_jfae;

	uobj_alloc_commit(&jetty_grp_uobj->uobj);
	return ret;

err_put_jfae:
	uburma_put_jfae(file);
err_delete_jetty_grp:
	(void)ubcore_delete_jetty_grp(jetty_grp);
err_alloc_abort:
	uobj_alloc_abort(&jetty_grp_uobj->uobj);
	return ret;
}

static int uburma_cmd_delete_jetty_grp(struct ubcore_device *ubc_dev,
				       struct uburma_file *file,
				       struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jetty_grp arg;
	struct uburma_jetty_grp_uobj *jetty_grp_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JETTY_GRP, (int)arg.in.handle, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("failed to find jetty group");
		return -EINVAL;
	}

	/* To get async_events_reported after obj removed. */
	uobj_get(uobj);
	jetty_grp_uobj = container_of(uobj, struct uburma_jetty_grp_uobj, uobj);

	ret = uobj_remove_commit(uobj);
	if (ret != 0) {
		uburma_log_err("delete jfr failed, ret:%d.\n", ret);
		uobj_put(uobj);
		uobj_put_del(uobj);
		return ret;
	}

	arg.out.async_events_reported = jetty_grp_uobj->async_events_reported;
	uobj_put(uobj);
	uobj_put_del(uobj);
	return uburma_tlv_append(hdr, &arg);
}

static int uburma_fill_user_ctl_info(struct ubcore_ucontext *ctx,
				     struct uburma_cmd_user_ctl *user_ctl,
				     struct ubcore_user_ctl *k_user_ctl)
{
	if (!ctx) {
		uburma_log_err("parameter invalid with ctx nullptr.\n");
		return -EINVAL;
	}

	k_user_ctl->uctx = ctx;
	k_user_ctl->in.addr = user_ctl->in.addr;
	k_user_ctl->in.len = user_ctl->in.len;
	k_user_ctl->in.opcode = user_ctl->in.opcode;

	k_user_ctl->out.addr = user_ctl->out.addr;
	k_user_ctl->out.len = user_ctl->out.len;

	k_user_ctl->udrv_data.in_addr = user_ctl->udrv.in_addr;
	k_user_ctl->udrv_data.in_len = user_ctl->udrv.in_len;
	k_user_ctl->udrv_data.out_addr = user_ctl->udrv.out_addr;
	k_user_ctl->udrv_data.out_len = user_ctl->udrv.out_len;

	return 0;
}

static int uburma_fill_eid_list(struct ubcore_device *dev,
				struct uburma_cmd_get_eid_list *eid_list)
{
	struct ubcore_eid_entry *e;
	uint32_t max_eid_cnt = 0;
	uint32_t eid_cnt = 0;
	uint32_t i;

	spin_lock(&dev->eid_table.lock);
	if (!dev->eid_table.eid_entries) {
		spin_unlock(&dev->eid_table.lock);
		return -EINVAL;
	}

	max_eid_cnt = min(dev->eid_table.eid_cnt, eid_list->in.max_eid_cnt);
	for (i = 0; i < max_eid_cnt; i++) {
		e = &dev->eid_table.eid_entries[i];
		if (!e->valid || !net_eq(e->net, current->nsproxy->net_ns))
			continue;

		eid_list->out.eid_list[eid_cnt].eid_index = e->eid_index;
		eid_list->out.eid_list[eid_cnt].eid = e->eid;
		eid_cnt++;
	}
	eid_list->out.eid_cnt = eid_cnt;
	spin_unlock(&dev->eid_table.lock);
	return 0;
}

static int uburma_cmd_get_eid_list(struct ubcore_device *ubc_dev,
				   struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_eid_list *args;
	int ret;

	args = kcalloc(1, sizeof(struct uburma_cmd_get_eid_list), GFP_KERNEL);
	if (!args)
		return -ENOMEM;

	ret = uburma_tlv_parse(hdr, args);
	if (ret != 0)
		goto out;

	ret = uburma_fill_eid_list(ubc_dev, args);
	if (ret != 0)
		goto out;

	ret = uburma_tlv_append(hdr, args);
out:
	kfree(args);
	return ret;
}

static int uburma_cmd_user_ctl(struct ubcore_device *ubc_dev,
			       struct uburma_file *file,
			       struct uburma_cmd_hdr *hdr)
{
	struct ubcore_user_ctl k_user_ctl = { 0 };
	struct uburma_cmd_user_ctl arg;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	ret = uburma_fill_user_ctl_info(file->ucontext, &arg, &k_user_ctl);
	if (ret != 0)
		return ret;

	ret = ubcore_user_control(ubc_dev, &k_user_ctl);
	if (ret != 0)
		return ret;

	return 0;
}

static int uburma_cmd_get_net_addr_list(struct ubcore_device *ubc_dev,
					struct uburma_file *file,
					struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_net_addr_list arg = { 0 };
	struct uburma_cmd_net_addr_info *netaddr_info;
	struct ubcore_sip_info *entry;
	uint32_t max_netaddr_cnt;
	uint32_t netaddr_cnt = 0;
	size_t netaddr_size;
	uint32_t i;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	max_netaddr_cnt =
		min(ubc_dev->sip_table.max_sip_cnt, arg.in.max_netaddr_cnt);
	netaddr_size =
		max_netaddr_cnt * sizeof(struct uburma_cmd_net_addr_info);
	netaddr_info = kcalloc(1, netaddr_size, GFP_KERNEL);
	if (!netaddr_info)
		return -ENOMEM;

	mutex_lock(&ubc_dev->sip_table.lock);
	if (!ubc_dev->sip_table.entry) {
		mutex_unlock(&ubc_dev->sip_table.lock);
		ret = -EINVAL;
		goto free_list;
	}

	for (i = 0; i < max_netaddr_cnt; i++) {
		entry = &ubc_dev->sip_table.entry[i].sip_info;
		if (entry->is_active) {
			netaddr_info[netaddr_cnt].netaddr = entry->addr;
			netaddr_info[netaddr_cnt].index = i;
			netaddr_cnt++;
		}
	}
	mutex_unlock(&ubc_dev->sip_table.lock);

	if (arg.out.addr != 0 && arg.out.len < netaddr_size) {
		uburma_log_err("Invalid parameter.\n");
		ret = -EINVAL;
		goto free_list;
	}
	arg.out.netaddr_cnt = netaddr_cnt;
	arg.out.len = (uint64_t)netaddr_size;
	ret = copy_to_user((void __user *)(uintptr_t)arg.out.addr, netaddr_info,
			   netaddr_size);
	if (ret != 0) {
		uburma_log_err("Failed to copy data to user space, ret:%d.\n", ret);
		goto free_list;
	}

	ret = uburma_tlv_append(hdr, &arg);

free_list:
	kfree(netaddr_info);
	return ret;
}

static void uburma_fill_tp_cfg(struct uburma_cmd_user_tp_cfg *cmd_tp_cfg,
	struct ubcore_tp_cfg *tp_cfg)
{
	/* Attention: ubcore_tp_cfg_flag is different with uburma_cmd_tp_cfg_flag */
	/* so we cannot fill by value */
	tp_cfg->flag.bs.target = cmd_tp_cfg->flag.bs.target;
	tp_cfg->flag.bs.loopback = cmd_tp_cfg->flag.bs.loopback;
	tp_cfg->flag.bs.dca_enable = cmd_tp_cfg->flag.bs.dca_enable;
	tp_cfg->flag.bs.bonding = cmd_tp_cfg->flag.bs.bonding;

	tp_cfg->trans_mode = cmd_tp_cfg->trans_mode;
	tp_cfg->retry_num = cmd_tp_cfg->retry_num;
	tp_cfg->retry_factor = cmd_tp_cfg->retry_factor;
	tp_cfg->ack_timeout = cmd_tp_cfg->ack_timeout;
	tp_cfg->dscp = cmd_tp_cfg->dscp;
	tp_cfg->oor_cnt = cmd_tp_cfg->oor_cnt;
}

static void uburma_fill_peer_net_addr(struct uburma_cmd_net_addr *cmd_net_addr,
				      struct ubcore_net_addr *net_addr)
{
	if (cmd_net_addr->sin_family == AF_INET) {
		net_addr->type = UBCORE_NET_ADDR_TYPE_IPV4;
		net_addr->net_addr.in4.addr = cmd_net_addr->in4.s_addr;
	} else if (cmd_net_addr->sin_family == AF_INET6) {
		net_addr->type = UBCORE_NET_ADDR_TYPE_IPV6;
		(void)memcpy(net_addr->net_addr.raw, &cmd_net_addr->in6,
			     sizeof(struct in6_addr));
	}

	net_addr->vlan = cmd_net_addr->vlan;
	(void)memcpy(net_addr->mac, cmd_net_addr->mac,
		     UBCORE_MAC_BYTES * sizeof(uint8_t));
	net_addr->prefix_len = cmd_net_addr->prefix_len;
}

static void uburma_fill_tp_attr(struct uburma_cmd_tp_attr *cmd_attr,
	struct ubcore_tp_attr *attr)
{
	attr->flag.value = cmd_attr->flag.value;
	attr->peer_tpn = cmd_attr->peer_tpn;
	attr->state = cmd_attr->state;
	attr->tx_psn = cmd_attr->tx_psn;
	attr->rx_psn = cmd_attr->rx_psn;
	attr->mtu = cmd_attr->mtu;
	attr->cc_pattern_idx = cmd_attr->cc_pattern_idx;
	attr->oos_cnt = cmd_attr->oos_cnt;
	attr->local_net_addr_idx = cmd_attr->local_net_addr_idx;
	uburma_fill_peer_net_addr(&cmd_attr->peer_net_addr,
				  &attr->peer_net_addr);
	attr->data_udp_start = cmd_attr->data_udp_start;
	attr->ack_udp_start = cmd_attr->ack_udp_start;
	attr->udp_range = cmd_attr->udp_range;
	attr->hop_limit = cmd_attr->hop_limit;
	attr->flow_label = cmd_attr->flow_label;
	attr->port_id = cmd_attr->port_id;
	attr->mn = cmd_attr->mn;
	attr->peer_trans_type = cmd_attr->peer_trans_type;
}

/* Attention: cmd_mask is different with mask, so we cannot fill by value */
static void uburma_fill_tp_attr_mask(union uburma_cmd_tp_attr_mask *cmd_mask,
	union ubcore_tp_attr_mask *mask)
{
	mask->bs.flag = cmd_mask->bs.flag;
	mask->bs.peer_tpn = cmd_mask->bs.peer_tpn;
	mask->bs.state = cmd_mask->bs.state;
	mask->bs.tx_psn = cmd_mask->bs.tx_psn;
	mask->bs.rx_psn = cmd_mask->bs.rx_psn;
	mask->bs.mtu = cmd_mask->bs.mtu;
	mask->bs.cc_pattern_idx = cmd_mask->bs.cc_pattern_idx;
	mask->bs.oos_cnt = cmd_mask->bs.oos_cnt;
	mask->bs.local_net_addr_idx = cmd_mask->bs.local_net_addr_idx;
	mask->bs.peer_net_addr = cmd_mask->bs.peer_net_addr;
	mask->bs.data_udp_start = cmd_mask->bs.data_udp_start;
	mask->bs.ack_udp_start = cmd_mask->bs.ack_udp_start;
	mask->bs.udp_range = cmd_mask->bs.udp_range;
	mask->bs.hop_limit = cmd_mask->bs.hop_limit;
	mask->bs.flow_label = cmd_mask->bs.flow_label;
	mask->bs.port_id = cmd_mask->bs.port_id;
	mask->bs.mn = cmd_mask->bs.mn;
	mask->bs.peer_trans_type = cmd_mask->bs.peer_trans_type;
}

static int uburma_modify_user_tp(struct ubcore_device *ubc_dev,
				 struct uburma_cmd_modify_tp *arg)
{
	union ubcore_tp_attr_mask mask = { 0 };
	struct ubcore_tp_cfg tp_cfg = { 0 };
	struct ubcore_tp_attr attr = { 0 };
	int ret;

	if (!ubc_dev || !ubc_dev->ops ||
	    !ubc_dev->ops->modify_user_tp) {
		uburma_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	uburma_fill_tp_cfg(&arg->in.tp_cfg, &tp_cfg);
	uburma_fill_tp_attr(&arg->in.attr, &attr);
	uburma_fill_tp_attr_mask(&arg->in.mask, &mask);

	ret = ubc_dev->ops->modify_user_tp(ubc_dev, arg->in.tpn, &tp_cfg, &attr,
					   mask);
	if (ret != 0)
		uburma_log_err("Failed to modify user tp, ret: %d.\n", ret);

	return ret;
}

static int uburma_cmd_modify_tp(struct ubcore_device *ubc_dev,
				struct uburma_file *file,
				struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_tp *arg;
	int ret;

	arg = kcalloc(1, sizeof(struct uburma_cmd_modify_tp), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;

	ret = uburma_tlv_parse(hdr, arg);
	if (ret != 0)
		goto out;

	ret = uburma_modify_user_tp(ubc_dev, arg);
	if (ret != 0)
		uburma_log_err("Failed to modify user tp, tpn: %u.\n",
			       arg->in.tpn);
out:
	kfree(arg);
	return ret;
}

static void uburma_fill_device_attr(struct ubcore_device *ubc_dev,
	struct uburma_cmd_device_attr *attr)
{
	uint8_t port_cnt, i;

	attr->guid = ubc_dev->attr.guid;
	attr->dev_cap.feature.value = ubc_dev->attr.dev_cap.feature.value;
	attr->dev_cap.max_jfc = ubc_dev->attr.dev_cap.max_jfc;
	attr->dev_cap.max_jfs = ubc_dev->attr.dev_cap.max_jfs;
	attr->dev_cap.max_jfr = ubc_dev->attr.dev_cap.max_jfr;
	attr->dev_cap.max_jetty = ubc_dev->attr.dev_cap.max_jetty;
	attr->dev_cap.max_jetty_grp = ubc_dev->attr.dev_cap.max_jetty_grp;
	attr->dev_cap.max_jetty_in_jetty_grp =
		ubc_dev->attr.dev_cap.max_jetty_in_jetty_grp;
	attr->dev_cap.max_jfc_depth = ubc_dev->attr.dev_cap.max_jfc_depth;
	attr->dev_cap.max_jfs_depth = ubc_dev->attr.dev_cap.max_jfs_depth;
	attr->dev_cap.max_jfr_depth = ubc_dev->attr.dev_cap.max_jfr_depth;
	attr->dev_cap.max_jfs_inline_len =
		ubc_dev->attr.dev_cap.max_jfs_inline_size;
	attr->dev_cap.max_jfs_sge = ubc_dev->attr.dev_cap.max_jfs_sge;
	attr->dev_cap.max_jfs_rsge = ubc_dev->attr.dev_cap.max_jfs_rsge;
	attr->dev_cap.max_jfr_sge = ubc_dev->attr.dev_cap.max_jfr_sge;
	attr->dev_cap.max_msg_size = ubc_dev->attr.dev_cap.max_msg_size;
	attr->dev_cap.max_read_size = ubc_dev->attr.dev_cap.max_read_size;
	attr->dev_cap.max_write_size = ubc_dev->attr.dev_cap.max_write_size;
	attr->dev_cap.max_cas_size = ubc_dev->attr.dev_cap.max_cas_size;
	attr->dev_cap.max_swap_size = ubc_dev->attr.dev_cap.max_swap_size;
	attr->dev_cap.max_fetch_and_add_size =
		ubc_dev->attr.dev_cap.max_fetch_and_add_size;
	attr->dev_cap.max_fetch_and_sub_size =
		ubc_dev->attr.dev_cap.max_fetch_and_sub_size;
	attr->dev_cap.max_fetch_and_and_size =
		ubc_dev->attr.dev_cap.max_fetch_and_and_size;
	attr->dev_cap.max_fetch_and_or_size =
		ubc_dev->attr.dev_cap.max_fetch_and_or_size;
	attr->dev_cap.max_fetch_and_xor_size =
		ubc_dev->attr.dev_cap.max_fetch_and_xor_size;
	attr->dev_cap.atomic_feat.value =
		ubc_dev->attr.dev_cap.atomic_feat.value;
	attr->dev_cap.trans_mode = ubc_dev->attr.dev_cap.trans_mode;
	attr->dev_cap.congestion_ctrl_alg =
		ubc_dev->attr.dev_cap.congestion_ctrl_alg;
	attr->dev_cap.ceq_cnt = ubc_dev->attr.dev_cap.ceq_cnt;
	attr->dev_cap.max_tp_in_tpg = ubc_dev->attr.dev_cap.max_tp_in_tpg;
	attr->dev_cap.max_eid_cnt = ubc_dev->attr.dev_cap.max_eid_cnt;
	attr->dev_cap.page_size_cap = ubc_dev->attr.dev_cap.page_size_cap;
	attr->dev_cap.max_oor_cnt = ubc_dev->attr.dev_cap.max_oor_cnt;
	attr->dev_cap.mn = ubc_dev->attr.dev_cap.mn;
	attr->dev_cap.max_netaddr_cnt = ubc_dev->attr.dev_cap.max_netaddr_cnt;
	attr->dev_cap.rm_order_cap.value = ubc_dev->attr.dev_cap.rm_order_cap.value;
	attr->dev_cap.rc_order_cap.value = ubc_dev->attr.dev_cap.rc_order_cap.value;
	attr->dev_cap.rm_tp_cap.value = ubc_dev->attr.dev_cap.rm_tp_cap.value;
	attr->dev_cap.rc_tp_cap.value = ubc_dev->attr.dev_cap.rc_tp_cap.value;
	attr->dev_cap.um_tp_cap.value = ubc_dev->attr.dev_cap.um_tp_cap.value;
	attr->dev_cap.tp_feature.value = ubc_dev->attr.dev_cap.tp_feature.value;
	(void)memcpy(attr->dev_cap.priority_info, ubc_dev->attr.dev_cap.priority_info,
		UBCORE_MAX_PRIORITY_CNT * sizeof(struct ubcore_sl_info));

	attr->port_cnt = ubc_dev->attr.port_cnt;
	port_cnt = (attr->port_cnt < UBURMA_CMD_MAX_PORT_CNT) ? attr->port_cnt :
		UBURMA_CMD_MAX_PORT_CNT;
	for (i = 0; i < port_cnt; i++)
		attr->port_attr[i].max_mtu = ubc_dev->attr.port_attr[i].max_mtu;

	attr->reserved_jetty_id_min = ubc_dev->attr.reserved_jetty_id_min;
	attr->reserved_jetty_id_max = ubc_dev->attr.reserved_jetty_id_max;
}

static int uburma_fill_device_status(struct ubcore_device *ubc_dev,
	struct uburma_cmd_device_attr *attr)
{
	struct ubcore_device_status status;
	uint8_t port_cnt, i;
	int ret;

	ret = ubcore_query_device_status(ubc_dev, &status);
	if (ret != 0) {
		uburma_log_err("Failed to query device status.\n");
		return ret;
	}

	port_cnt = (attr->port_cnt < UBURMA_CMD_MAX_PORT_CNT) ?
				 attr->port_cnt :
				 UBURMA_CMD_MAX_PORT_CNT;
	for (i = 0; i < port_cnt; i++) {
		attr->port_attr[i].state = status.port_status[i].state;
		attr->port_attr[i].active_width =
			status.port_status[i].active_width;
		attr->port_attr[i].active_speed =
			status.port_status[i].active_speed;
		attr->port_attr[i].active_mtu =
			status.port_status[i].active_mtu;
	}

	return 0;
}

static int uburma_cmd_query_device_attr(struct ubcore_device *ubc_dev,
					struct uburma_file *file,
					struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_query_device_attr *arg;
	int ret;

	arg = kzalloc(sizeof(struct uburma_cmd_query_device_attr), GFP_KERNEL);
	if (IS_ERR_OR_NULL(arg))
		return -ENOMEM;

	ret = uburma_tlv_parse(hdr, arg);
	if (ret != 0)
		goto free_arg;

	if (strnlen(arg->in.dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		uburma_log_err("Invalid dev_name length.\n");
		ret = -EINVAL;
		goto free_arg;
	}

	if (strcmp(arg->in.dev_name, ubc_dev->dev_name) != 0) {
		uburma_log_err("Invalid parameter with error dev_name.\n");
		ret = -EINVAL;
		goto free_arg;
	}
	uburma_fill_device_attr(ubc_dev, &arg->out.attr);
	ret = uburma_fill_device_status(ubc_dev, &arg->out.attr);
	if (ret != 0)
		goto free_arg;

	ret = uburma_tlv_append(hdr, arg);
	if (ret != 0)
		uburma_log_err("Failed to append, ret: %d.\n", ret);
free_arg:
	kfree(arg);
	return ret;
}

struct uburma_import_jetty_async_user_arg {
	struct uburma_notifier_uobj *notifier;
	struct uburma_notify_event *notify;
	struct uburma_uobj *uobj_tjetty;
};

static void uburma_free_notify_event(uint64_t event_data)
{
	kfree((struct uburma_notify_event *)event_data);
}

static void uburma_cmd_import_jetty_async_callback(struct ubcore_tjetty *tjetty,
						   int status, void *user_arg)
{
	struct uburma_import_jetty_async_user_arg *arg = user_arg;
	struct uburma_notifier_uobj *notifier = arg->notifier;
	struct uburma_notify_event *notify_event = arg->notify;
	struct uburma_notify *notify = &notify_event->notify;
	struct uburma_uobj *uobj = arg->uobj_tjetty;

	notify->status = status;
	if (status == 0) {
		uobj->object = tjetty;
		uobj_alloc_commit(uobj);
		if (tjetty->vtpn)
			notify->vtpn = tjetty->vtpn->vtpn;
	} else
		uobj_alloc_abort(uobj);

	notify->status = status;
	if (tjetty->vtpn)
		notify->vtpn = tjetty->vtpn->vtpn;
	uburma_write_event_with_free_fn(&notifier->jfe,
					(uint64_t)(uintptr_t)notify_event, 0,
					NULL, NULL, uburma_free_notify_event);
	uobj_put(&notifier->uobj);
	kfree(user_arg);
}

static struct ubcore_import_cb *
uburma_create_import_callback(struct uburma_cmd_import_jetty_async *arg,
			      struct uburma_file *file,
			      struct uburma_uobj *uobj_tjetty)
{
	struct uburma_import_jetty_async_user_arg *user_arg;
	struct uburma_notifier_uobj *notifier;
	struct uburma_notify_event *notify;
	struct ubcore_import_cb *cb;

	notifier = uburma_get_notifier_uobj(arg->in.fd, file);
	if (IS_ERR_OR_NULL(notifier)) {
		uburma_log_err("failed to find notifier.\n");
		return NULL;
	}

	notify = kzalloc(sizeof(struct uburma_notify_event), GFP_KERNEL);
	if (IS_ERR_OR_NULL(notify)) {
		uburma_log_err("failed to alloc notify.\n");
		goto put_notifier;
	}
	notify->notify.type = UBURMA_IMPORT_JETTY_NOTIFY;
	notify->notify.user_ctx = arg->in.user_ctx;
	notify->notify.urma_jetty = arg->in.urma_tjetty;
	notify->tjetty_handle = uobj_tjetty->id;

	user_arg = kzalloc(sizeof(struct uburma_import_jetty_async_user_arg),
			   GFP_KERNEL);
	if (IS_ERR_OR_NULL(user_arg)) {
		uburma_log_err("failed to alloc user arg.\n");
		goto free_notify;
	}
	user_arg->notifier = notifier;
	user_arg->notify = notify;
	user_arg->uobj_tjetty = uobj_tjetty;

	cb = kzalloc(sizeof(struct ubcore_import_cb), GFP_KERNEL);
	if (IS_ERR_OR_NULL(cb)) {
		uburma_log_err("failed to alloc import callback.\n");
		goto free_user_arg;
	}
	atomic_inc(&user_arg->notifier->incomplete_cnt);
	cb->callback = uburma_cmd_import_jetty_async_callback;
	cb->user_arg = user_arg;
	return cb;

free_user_arg:
	kfree(user_arg);
free_notify:
	kfree(notify);
put_notifier:
	uobj_put(&notifier->uobj);
	return NULL;
}

static void uburma_delete_import_callback(struct ubcore_import_cb *cb)
{
	struct uburma_import_jetty_async_user_arg *user_arg;

	if (!cb)
		return;
	user_arg = cb->user_arg;
	atomic_dec(&user_arg->notifier->incomplete_cnt);
	uobj_put(&user_arg->notifier->uobj);
	kfree(user_arg->notify);
	kfree(user_arg);
	kfree(cb);
}

static int uburma_cmd_import_jetty_async(struct ubcore_device *ubc_dev,
					 struct uburma_file *file,
					 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_import_jetty_async arg;
	struct ubcore_tjetty_cfg cfg = { 0 };
	struct ubcore_tjetty *tjetty;
	struct ubcore_udata udata = {};
	struct uburma_uobj *uobj;
	struct ubcore_import_cb *cb;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_JETTY, file);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("UOBJ_CLASS_TARGET_JETTY alloc fail!\n");
		return -ENOMEM;
	}

	(void)memcpy(cfg.id.eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	cfg.id.id = arg.in.id;
	cfg.token_value.token = arg.in.token;
	cfg.trans_mode = (enum ubcore_transport_mode)arg.in.trans_mode;
	cfg.flag.value = arg.in.flag;
	cfg.policy = (enum ubcore_jetty_grp_policy)arg.in.policy;
	cfg.type = (enum ubcore_target_type)arg.in.type;
	cfg.eid_index = file->ucontext->eid_index;
	fill_udata(&udata, file->ucontext, &arg.udata);

	cb = uburma_create_import_callback(&arg, file, uobj);
	if (IS_ERR_OR_NULL(cb)) {
		uburma_log_err("failed to find notifier.\n");
		uobj_alloc_abort(uobj);
		return -ENOMEM;
	}

	tjetty = ubcore_import_jetty_async(ubc_dev, &cfg, arg.in.timeout, cb,
					   &udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		uburma_log_err("ubcore_import_jetty_async failed.\n");
		uburma_delete_import_callback(cb);
		uobj_alloc_abort(uobj);
		return PTR_ERR(tjetty);
	}

	arg.out.handle = (uint64_t)uobj->id;
	ret = uburma_tlv_append(hdr, &arg);
	if (ret != 0) {
		ubcore_unimport_jetty_async(tjetty, 0, NULL);
		uobj_alloc_abort(uobj);
		return ret;
	}
	return 0;
}

static int uburma_cmd_unimport_jetty_async(struct ubcore_device *ubc_dev,
					   struct uburma_file *file,
					   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unimport_jetty_async arg;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	return uburma_unimport_jetty(file, true, arg.in.handle);
}

struct uburma_bind_jetty_async_user_arg {
	struct uburma_notifier_uobj *notifier;
	struct uburma_notify_event *notify;
};

static void uburma_cmd_bind_jetty_async_callback(struct ubcore_jetty *jetty,
						 struct ubcore_tjetty *tjetty,
						 int status, void *user_arg)
{
	struct uburma_bind_jetty_async_user_arg *arg = user_arg;
	struct uburma_notifier_uobj *notifier = arg->notifier;
	struct uburma_notify_event *notify_event = arg->notify;
	struct uburma_notify *notify = &notify_event->notify;

	notify->status = status;
	if (status == 0 && tjetty->vtpn)
		notify->vtpn = tjetty->vtpn->vtpn;
	uburma_write_event_with_free_fn(&notifier->jfe,
					(uint64_t)(uintptr_t)notify_event, 0,
					NULL, NULL, uburma_free_notify_event);
	kfree(user_arg);
}

static struct ubcore_bind_cb *uburma_create_bind_callback(
	struct uburma_cmd_bind_jetty_async *arg, struct uburma_file *file,
	struct uburma_uobj *uobj_tjetty, struct uburma_uobj *uobj_jetty)
{
	struct uburma_notifier_uobj *notifier;
	struct uburma_notify_event *notify;
	struct uburma_bind_jetty_async_user_arg *user_arg;
	struct ubcore_bind_cb *cb;

	notifier = uburma_get_notifier_uobj(arg->in.fd, file);
	if (IS_ERR_OR_NULL(notifier)) {
		uburma_log_err("failed to find notifier.\n");
		return NULL;
	}

	notify = kzalloc(sizeof(struct uburma_notify_event), GFP_KERNEL);
	if (IS_ERR_OR_NULL(notify)) {
		uburma_log_err("failed to alloc notify.\n");
		goto put_notifier;
	}
	notify->notify.type = UBURMA_BIND_JETTY_NOTIFY;
	notify->notify.user_ctx = arg->in.user_ctx;
	notify->notify.urma_jetty = arg->in.urma_jetty;
	notify->tjetty_handle = uobj_tjetty->id;
	notify->jetty_handle = uobj_jetty->id;

	user_arg = kzalloc(sizeof(struct uburma_bind_jetty_async_user_arg),
			   GFP_KERNEL);
	if (IS_ERR_OR_NULL(user_arg)) {
		uburma_log_err("failed to alloc user arg.\n");
		goto free_notify;
	}
	user_arg->notifier = notifier;
	user_arg->notify = notify;

	cb = kzalloc(sizeof(struct ubcore_bind_cb), GFP_KERNEL);
	if (IS_ERR_OR_NULL(cb)) {
		uburma_log_err("failed to alloc bind callback.\n");
		goto free_user_arg;
	}
	atomic_inc(&user_arg->notifier->incomplete_cnt);
	cb->callback = uburma_cmd_bind_jetty_async_callback;
	cb->user_arg = user_arg;
	return cb;

free_user_arg:
	kfree(user_arg);
free_notify:
	kfree(notify);
put_notifier:
	uobj_put(&notifier->uobj);
	return NULL;
}

static void uburma_delete_bind_callback(struct ubcore_bind_cb *cb)
{
	struct uburma_bind_jetty_async_user_arg *user_arg;

	if (!cb)
		return;
	user_arg = cb->user_arg;
	atomic_dec(&user_arg->notifier->incomplete_cnt);
	uobj_put(&user_arg->notifier->uobj);
	kfree(user_arg->notify);
	kfree(user_arg);
	kfree(cb);
}

static int uburma_cmd_bind_jetty_async(struct ubcore_device *ubc_dev,
				       struct uburma_file *file,
				       struct uburma_cmd_hdr *hdr)
{
	struct uburma_tjetty_uobj *uburma_tjetty;
	struct uburma_cmd_bind_jetty_async arg;
	struct uburma_uobj *tjetty_uobj;
	struct uburma_uobj *jetty_uobj;
	struct ubcore_tjetty *tjetty;
	struct ubcore_udata udata = {};
	struct ubcore_bind_cb *cb;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	if (uburma_get_jetty_tjetty_objs(file, arg.in.jetty_handle,
					 arg.in.tjetty_handle, &jetty_uobj,
					 &tjetty_uobj))
		return -EINVAL;
	fill_udata(&udata, file->ucontext, &arg.udata);

	cb = uburma_create_bind_callback(&arg, file, jetty_uobj, tjetty_uobj);
	if (IS_ERR_OR_NULL(cb)) {
		uburma_log_err("failed to find notifier.\n");
		uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
		return -ENOMEM;
	}

	tjetty = (struct ubcore_tjetty *)tjetty_uobj->object;
	ret = ubcore_bind_jetty_async(jetty_uobj->object, tjetty,
				      arg.in.timeout, cb, &udata);
	if (ret != 0) {
		uburma_log_err("bind jetty async failed.\n");
		uburma_delete_bind_callback(cb);
		uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
		return ret;
	}

	uburma_tjetty = (struct uburma_tjetty_uobj *)(tjetty_uobj);
	uburma_tjetty->jetty_uobj = (struct uburma_jetty_uobj *)(jetty_uobj);
	ret = uburma_tlv_append(hdr, &arg);
	if (ret != 0) {
		ubcore_unbind_jetty_async(jetty_uobj->object, 0, NULL);
		uburma_delete_bind_callback(cb);
	}

	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
	return ret;
}

static int uburma_cmd_unbind_jetty_async(struct ubcore_device *ubc_dev,
					 struct uburma_file *file,
					 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unadvise_jetty arg;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	return uburma_unbind_jetty(file, true, arg.in.jetty_handle,
				   arg.in.tjetty_handle);
}

static int uburma_cmd_create_notifier(struct ubcore_device *ubc_dev,
				      struct uburma_file *file,
				      struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_notifier arg;
	struct uburma_notifier_uobj *notifier;
	struct uburma_uobj *uobj;

	uobj = uobj_alloc(UOBJ_CLASS_NOTIFIER, file);
	if (IS_ERR_OR_NULL(uobj))
		return PTR_ERR(uobj);

	notifier = container_of(uobj, struct uburma_notifier_uobj, uobj);
	uburma_init_jfe(&notifier->jfe);
	atomic_set(&notifier->incomplete_cnt, 0);

	arg.out.fd = uobj->id; /* should get fd before commit uobj */
	uobj_alloc_commit(uobj);

	return uburma_tlv_append(hdr, (void *)&arg);
}

static int uburma_cmd_get_tp_list(struct ubcore_device *ubc_dev,
				  struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_tp_list *arg = NULL;
	struct ubcore_tp_info *tp_list = NULL;
	struct ubcore_get_tp_cfg cfg = { 0 };
	struct ubcore_udata udata = { 0 };
	uint32_t tp_cnt = 0;
	int ret;

	arg = kcalloc(1, sizeof(struct uburma_cmd_get_tp_list), GFP_KERNEL);
	if (IS_ERR_OR_NULL(arg))
		return -ENOMEM;
	ret = uburma_tlv_parse(hdr, arg);
	if (ret != 0)
		goto free_arg;

	if (arg->in.tp_cnt > UBURMA_CMD_MAX_TP_NUM || arg->in.tp_cnt == 0) {
		uburma_log_err("Invalid tp_cnt: %u.\n", arg->in.tp_cnt);
		ret = -EINVAL;
		goto free_arg;
	}

	cfg.flag.value = arg->in.flag;
	cfg.trans_mode = arg->in.trans_mode;
	(void)memcpy(&cfg.local_eid, arg->in.local_eid,
		     sizeof(union ubcore_eid));
	(void)memcpy(&cfg.peer_eid, arg->in.peer_eid, sizeof(union ubcore_eid));
	tp_cnt = arg->in.tp_cnt;
	fill_udata(&udata, file->ucontext, &arg->udata);

	tp_list = kcalloc(tp_cnt, sizeof(struct ubcore_tp_info), GFP_KERNEL);
	if (IS_ERR_OR_NULL(tp_list)) {
		ret = -ENOMEM;
		goto free_arg;
	}
	ret = ubcore_get_tp_list(ubc_dev, &cfg, &tp_cnt, tp_list, &udata);
	if (ret != 0) {
		uburma_log_err("Failed to get tp list, ret: %d.\n", ret);
		goto free_tp_list;
	}
	arg->out.tp_cnt = tp_cnt;
	(void)memcpy(arg->out.tp_handle, tp_list,
		     tp_cnt * sizeof(struct ubcore_tp_info));

	ret = uburma_tlv_append(hdr, arg);
free_tp_list:
	kfree(tp_list);
free_arg:
	kfree(arg);
	return ret;
}

static int uburma_cmd_set_tp_attr(struct ubcore_device *ubc_dev,
				  struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr)
{
	struct ubcore_tp_attr_value tp_attr = { 0 };
	struct uburma_cmd_set_tp_attr arg = { 0 };
	struct ubcore_udata udata = { 0 };
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	if (sizeof(arg.in.tp_attr) != sizeof(struct ubcore_tp_attr_value)) {
		uburma_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	fill_udata(&udata, file->ucontext, &arg.udata);
	(void)memcpy(&tp_attr, arg.in.tp_attr, sizeof(arg.in.tp_attr));

	ret = ubcore_set_tp_attr(ubc_dev, arg.in.tp_handle, arg.in.tp_attr_cnt,
				 arg.in.tp_attr_bitmap, &tp_attr, &udata);
	if (ret != 0)
		uburma_log_err(
			"Failed to set tp attribution values, ret: %d.\n", ret);

	return ret;
}

static int uburma_cmd_get_tp_attr(struct ubcore_device *ubc_dev,
				  struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr)
{
	struct ubcore_tp_attr_value tp_attr = { 0 };
	struct uburma_cmd_get_tp_attr arg = { 0 };
	struct ubcore_udata udata = { 0 };
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	if (sizeof(arg.out.tp_attr) != sizeof(struct ubcore_tp_attr_value)) {
		uburma_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	fill_udata(&udata, file->ucontext, &arg.udata);

	ret = ubcore_get_tp_attr(ubc_dev, arg.in.tp_handle,
				 &arg.out.tp_attr_cnt, &arg.out.tp_attr_bitmap,
				 &tp_attr, &udata);
	if (ret != 0) {
		uburma_log_err(
			"Failed to get tp attribution values, ret: %d.\n", ret);
		return ret;
	}
	(void)memcpy(arg.out.tp_attr, &tp_attr,
		     sizeof(struct ubcore_tp_attr_value));

	return uburma_tlv_append(hdr, &arg);
}

static int uburma_cmd_exchange_tp_info(struct ubcore_device *ubc_dev,
				       struct uburma_file *file,
				       struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_exchange_tp_info arg;
	struct ubcore_get_tp_cfg get_tcp_cfg = {0};
	struct ubcore_udata udata = {0};
	uint64_t peer_tp_handle;
	uint32_t rx_psn;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;
	get_tcp_cfg = arg.in.get_tp_cfg;
	ret = ubcore_exchange_tp_info(ubc_dev, &get_tcp_cfg, arg.in.tp_handle,
		arg.in.tx_psn, &peer_tp_handle, &rx_psn, &udata);
	if (ret != 0) {
		uburma_log_err("Failed to exchange tp info, ret: %d.\n", ret);
		return ret;
	}
	arg.out.peer_tp_handle = peer_tp_handle;
	arg.out.rx_psn = rx_psn;

	ret = uburma_tlv_append(hdr, &arg);
	return ret;
}

static int uburma_cmd_get_eid_by_ip(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_eid_by_ip arg = {0};
	struct ubcore_net_addr net_addr = {0};
	union ubcore_eid eid = {0};
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;
	if (arg.in.net_addr.sin_family == AF_INET6) {
		net_addr.type = UBCORE_NET_ADDR_TYPE_IPV6;
		(void)memcpy(net_addr.net_addr.raw, arg.in.net_addr.in6.s6_addr,
			 UBCORE_NET_ADDR_BYTES);
	} else if (arg.in.net_addr.sin_family == AF_INET) {
		net_addr.type = UBCORE_NET_ADDR_TYPE_IPV4;
		net_addr.net_addr.in4.addr = arg.in.net_addr.in4.s_addr;
	}

	ret = ubcore_get_eid_by_ip(ubc_dev, &net_addr, &eid);
	if (ret != 0) {
		uburma_log_err("Failed to get eid by ip, ret: %d.\n", ret);
		return ret;
	}
	arg.out.eid = eid;

	ret = uburma_tlv_append(hdr, &arg);
	return ret;
}

static int uburma_cmd_get_ip_by_eid(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_ip_by_eid arg = {0};
	struct ubcore_net_addr net_addr = {0};
	union ubcore_eid eid = {0};
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;
	eid = arg.in.eid;
	ret = ubcore_get_ip_by_eid(ubc_dev, &eid, &net_addr);
	if (ret != 0) {
		uburma_log_err("Failed to get eid by ip, ret: %d.\n", ret);
		return ret;
	}
	if (net_addr.type == UBCORE_NET_ADDR_TYPE_IPV6) {
		arg.out.net_addr.sin_family = AF_INET6;
		(void)memcpy(arg.out.net_addr.in6.s6_addr,  net_addr.net_addr.raw,
			 UBCORE_NET_ADDR_BYTES);
	} else if (net_addr.type == UBCORE_NET_ADDR_TYPE_IPV4) {
		arg.out.net_addr.sin_family = AF_INET;
		arg.out.net_addr.in4.s_addr = net_addr.net_addr.in4.addr;
	}

	ret = uburma_tlv_append(hdr, &arg);
	return ret;
}

static int uburma_cmd_get_smac(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_smac arg = {0};
	uint8_t mac[UBCORE_MAC_BYTES] = {0};
	int ret;

	ret = ubcore_get_smac(ubc_dev, mac);
	if (ret != 0) {
		uburma_log_err("Failed to get smac, ret: %d.\n", ret);
		return ret;
	}
	(void)memcpy(arg.out.mac, mac, UBCORE_MAC_BYTES);

	ret = uburma_tlv_append(hdr, &arg);
	return ret;
}

static int uburma_cmd_get_dmac(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct ubcore_net_addr net_addr = {0};
	struct uburma_cmd_get_dmac arg = {0};
	uint8_t mac[UBCORE_MAC_BYTES] = {0};
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;
	if (arg.in.net_addr.sin_family == AF_INET6) {
		net_addr.type = UBCORE_NET_ADDR_TYPE_IPV6;
		(void)memcpy(net_addr.net_addr.raw,  arg.in.net_addr.in6.s6_addr,
			 UBCORE_NET_ADDR_BYTES);
	} else if (arg.in.net_addr.sin_family == AF_INET) {
		net_addr.type = UBCORE_NET_ADDR_TYPE_IPV4;
		net_addr.net_addr.in4.addr = arg.in.net_addr.in4.s_addr;
	} else {
		uburma_log_err
			("ip_type is invalid, sin_family : %d.\n", arg.in.net_addr.sin_family);
		return -EINVAL;
	}

	ret = ubcore_get_dmac(ubc_dev, &net_addr, mac);
	if (ret != 0) {
		uburma_log_err("Failed to get dmac, ret: %d.\n", ret);
		return ret;
	}
	(void)memcpy(arg.out.mac, mac, UBCORE_MAC_BYTES);

	ret = uburma_tlv_append(hdr, &arg);
	return ret;
}

static int uburma_cmd_import_jetty_ex(struct ubcore_device *ubc_dev,
				      struct uburma_file *file,
				      struct uburma_cmd_hdr *hdr)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	struct uburma_cmd_import_jetty_ex arg = { 0 };
	struct ubcore_tjetty_cfg cfg = { 0 };
	struct ubcore_udata udata = { 0 };
	struct ubcore_tjetty *tjetty;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_tlv_parse(hdr, &arg);
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_JETTY, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("Failed to alloc uobj, class_id: %d.\n",
			       UOBJ_CLASS_TARGET_JETTY);
		return -ENOMEM;
	}

	(void)memcpy(cfg.id.eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	cfg.id.id = arg.in.id;
	cfg.token_value.token = arg.in.token;
	cfg.trans_mode = (enum ubcore_transport_mode)arg.in.trans_mode;
	cfg.flag.value = arg.in.flag;
	cfg.policy = (enum ubcore_jetty_grp_policy)arg.in.policy;
	cfg.type = (enum ubcore_target_type)arg.in.type;
	cfg.tp_type = (enum ubcore_tp_type)arg.in.tp_type;
	cfg.eid_index = file->ucontext->eid_index;

	active_tp_cfg.tp_handle.value = arg.in.tp_handle;
	active_tp_cfg.peer_tp_handle.value = arg.in.peer_tp_handle;
	active_tp_cfg.tag = arg.in.tag;
	active_tp_cfg.tp_attr.tx_psn = arg.in.tx_psn;
	active_tp_cfg.tp_attr.rx_psn = arg.in.rx_psn;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tjetty = ubcore_import_jetty_ex(ubc_dev, &cfg, &active_tp_cfg, &udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		uburma_log_err("ubcore_import_jetty failed.\n");
		uobj_alloc_abort(uobj);
		return PTR_ERR(tjetty);
	}

	uobj->object = tjetty;
	arg.out.handle = (uint64_t)uobj->id;
	if (tjetty->vtpn)
		arg.out.tpn = tjetty->vtpn->vtpn;
	else if (tjetty->tp)
		arg.out.tpn = tjetty->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	ret = uburma_tlv_append(hdr, &arg);
	if (ret != 0) {
		(void)ubcore_unimport_jetty(tjetty);
		uobj_alloc_abort(uobj);
		return ret;
	}
	uobj_alloc_commit(uobj);
	return 0;
}

typedef int (*uburma_cmd_handler)(struct ubcore_device *ubc_dev,
				  struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr);

static uburma_cmd_handler g_uburma_cmd_handlers[] = {
	[0] = NULL,
	[UBURMA_CMD_CREATE_CTX] = uburma_cmd_create_ctx,
	[UBURMA_CMD_ALLOC_TOKEN_ID] = uburma_cmd_alloc_token_id,
	[UBURMA_CMD_FREE_TOKEN_ID] = uburma_cmd_free_token_id,
	[UBURMA_CMD_REGISTER_SEG] = uburma_cmd_register_seg,
	[UBURMA_CMD_UNREGISTER_SEG] = uburma_cmd_unregister_seg,
	[UBURMA_CMD_IMPORT_SEG] = uburma_cmd_import_seg,
	[UBURMA_CMD_UNIMPORT_SEG] = uburma_cmd_unimport_seg,
	[UBURMA_CMD_CREATE_JFR] = uburma_cmd_create_jfr,
	[UBURMA_CMD_MODIFY_JFR] = uburma_cmd_modify_jfr,
	[UBURMA_CMD_QUERY_JFR] = uburma_cmd_query_jfr,
	[UBURMA_CMD_DELETE_JFR] = uburma_cmd_delete_jfr,
	[UBURMA_CMD_CREATE_JFS] = uburma_cmd_create_jfs,
	[UBURMA_CMD_MODIFY_JFS] = uburma_cmd_modify_jfs,
	[UBURMA_CMD_QUERY_JFS] = uburma_cmd_query_jfs,
	[UBURMA_CMD_DELETE_JFS] = uburma_cmd_delete_jfs,
	[UBURMA_CMD_CREATE_JFC] = uburma_cmd_create_jfc,
	[UBURMA_CMD_MODIFY_JFC] = uburma_cmd_modify_jfc,
	[UBURMA_CMD_DELETE_JFC] = uburma_cmd_delete_jfc,
	[UBURMA_CMD_CREATE_JFCE] = uburma_cmd_create_jfce,
	[UBURMA_CMD_IMPORT_JFR] = uburma_cmd_import_jfr,
	[UBURMA_CMD_UNIMPORT_JFR] = uburma_cmd_unimport_jfr,
	[UBURMA_CMD_CREATE_JETTY] = uburma_cmd_create_jetty,
	[UBURMA_CMD_MODIFY_JETTY] = uburma_cmd_modify_jetty,
	[UBURMA_CMD_QUERY_JETTY] = uburma_cmd_query_jetty,
	[UBURMA_CMD_DELETE_JETTY] = uburma_cmd_delete_jetty,
	[UBURMA_CMD_IMPORT_JETTY] = uburma_cmd_import_jetty,
	[UBURMA_CMD_UNIMPORT_JETTY] = uburma_cmd_unimport_jetty,
	[UBURMA_CMD_BIND_JETTY] = uburma_cmd_bind_jetty,
	[UBURMA_CMD_UNBIND_JETTY] = uburma_cmd_unbind_jetty,
	[UBURMA_CMD_CREATE_JETTY_GRP] = uburma_cmd_create_jetty_grp,
	[UBURMA_CMD_DESTROY_JETTY_GRP] = uburma_cmd_delete_jetty_grp,
	[UBURMA_CMD_USER_CTL] = uburma_cmd_user_ctl,
	[UBURMA_CMD_GET_EID_LIST] = uburma_cmd_get_eid_list,
	[UBURMA_CMD_GET_NETADDR_LIST] = uburma_cmd_get_net_addr_list,
	[UBURMA_CMD_MODIFY_TP] = uburma_cmd_modify_tp,
	[UBURMA_CMD_QUERY_DEV_ATTR] = uburma_cmd_query_device_attr,
	[UBURMA_CMD_IMPORT_JETTY_ASYNC] = uburma_cmd_import_jetty_async,
	[UBURMA_CMD_UNIMPORT_JETTY_ASYNC] = uburma_cmd_unimport_jetty_async,
	[UBURMA_CMD_BIND_JETTY_ASYNC] = uburma_cmd_bind_jetty_async,
	[UBURMA_CMD_UNBIND_JETTY_ASYNC] = uburma_cmd_unbind_jetty_async,
	[UBURMA_CMD_CREATE_NOTIFIER] = uburma_cmd_create_notifier,
	[UBURMA_CMD_GET_TP_LIST] = uburma_cmd_get_tp_list,
	[UBURMA_CMD_IMPORT_JETTY_EX] = uburma_cmd_import_jetty_ex,
	[UBURMA_CMD_IMPORT_JFR_EX] = uburma_cmd_import_jfr_ex,
	[UBURMA_CMD_BIND_JETTY_EX] = uburma_cmd_bind_jetty_ex,
	[UBURMA_CMD_DELETE_JFS_BATCH] = uburma_cmd_delete_jfs_batch,
	[UBURMA_CMD_DELETE_JFR_BATCH] = uburma_cmd_delete_jfr_batch,
	[UBURMA_CMD_DELETE_JFC_BATCH] = uburma_cmd_delete_jfc_batch,
	[UBURMA_CMD_DELETE_JETTY_BATCH] = uburma_cmd_delete_jetty_batch,
	[UBURMA_CMD_SET_TP_ATTR] = uburma_cmd_set_tp_attr,
	[UBURMA_CMD_GET_TP_ATTR] = uburma_cmd_get_tp_attr,
	[UBURMA_CMD_EXCHANGE_TP_INFO] = uburma_cmd_exchange_tp_info,
	[UBURMA_CMD_GET_EID_BY_IP] = uburma_cmd_get_eid_by_ip,
	[UBURMA_CMD_GET_IP_BY_EID] = uburma_cmd_get_ip_by_eid,
	[UBURMA_CMD_GET_SMAC] = uburma_cmd_get_smac,
	[UBURMA_CMD_GET_DMAC] = uburma_cmd_get_dmac,
	[UBURMA_CMD_ALLOC_JFC] = uburma_cmd_alloc_jfc,
	[UBURMA_CMD_FREE_JFC] = uburma_cmd_free_jfc,
	[UBURMA_CMD_SET_JFC_OPT] = uburma_cmd_set_jfc_opt,
	[UBURMA_CMD_GET_JFC_OPT] = uburma_cmd_get_jfc_opt,
	[UBURMA_CMD_ACTIVE_JFC] = uburma_cmd_active_jfc,
	[UBURMA_CMD_DEACTIVE_JFC] = uburma_cmd_deactive_jfc,
	[UBURMA_CMD_ALLOC_JFR] = uburma_cmd_alloc_jfr,
	[UBURMA_CMD_FREE_JFR] = uburma_cmd_free_jfr,
	[UBURMA_CMD_SET_JFR_OPT] = uburma_cmd_set_jfr_opt,
	[UBURMA_CMD_GET_JFR_OPT] = uburma_cmd_get_jfr_opt,
	[UBURMA_CMD_ACTIVE_JFR] = uburma_cmd_active_jfr,
	[UBURMA_CMD_DEACTIVE_JFR] = uburma_cmd_deactive_jfr,
	[UBURMA_CMD_ALLOC_JFS] = uburma_cmd_alloc_jfs,
	[UBURMA_CMD_FREE_JFS] = uburma_cmd_free_jfs,
	[UBURMA_CMD_SET_JFS_OPT] = uburma_cmd_set_jfs_opt,
	[UBURMA_CMD_GET_JFS_OPT] = uburma_cmd_get_jfs_opt,
	[UBURMA_CMD_ACTIVE_JFS] = uburma_cmd_active_jfs,
	[UBURMA_CMD_DEACTIVE_JFS] = uburma_cmd_deactive_jfs,
	[UBURMA_CMD_ALLOC_JETTY] = uburma_cmd_alloc_jetty,
	[UBURMA_CMD_FREE_JETTY] = uburma_cmd_free_jetty,
	[UBURMA_CMD_SET_JETTY_OPT] = uburma_cmd_set_jetty_opt,
	[UBURMA_CMD_GET_JETTY_OPT] = uburma_cmd_get_jetty_opt,
	[UBURMA_CMD_ACTIVE_JETTY] = uburma_cmd_active_jetty,
	[UBURMA_CMD_DEACTIVE_JETTY] = uburma_cmd_deactive_jetty,
};

static int uburma_cmd_parse(struct ubcore_device *ubc_dev,
			    struct uburma_file *file,
			    struct uburma_cmd_hdr *hdr)
{
	if (hdr->command < UBURMA_CMD_CREATE_CTX ||
	    hdr->command >= UBURMA_CMD_MAX ||
	    g_uburma_cmd_handlers[hdr->command] == NULL) {
		uburma_log_err("bad uburma command: %d.\n", (int)hdr->command);
		return -EINVAL;
	}
	return g_uburma_cmd_handlers[hdr->command](ubc_dev, file, hdr);
}

static inline bool is_cmd_ucontext_free(struct uburma_cmd_hdr *hdr)
{
	return (hdr->command == UBURMA_CMD_CREATE_CTX ||
			hdr->command == UBURMA_CMD_GET_EID_LIST ||
			hdr->command == UBURMA_CMD_QUERY_DEV_ATTR);
}

long uburma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct uburma_cmd_hdr *user_hdr = (struct uburma_cmd_hdr *)arg;
	struct uburma_device *ubu_dev;
	struct ubcore_device *ubc_dev;
	struct uburma_cmd_hdr hdr;
	struct uburma_file *file;
	int srcu_idx;
	long ret;

	if (!filp || !filp->private_data) {
		uburma_log_err("invalid param");
		return -EINVAL;
	}
	file = filp->private_data;
	ubu_dev = file->ubu_dev;
	if (!ubu_dev) {
		uburma_log_err("invalid param");
		return -EINVAL;
	}
	uburma_cmd_inc(ubu_dev);
	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (!ubc_dev) {
		uburma_log_debug("can not find ubcore device.\n");
		ret = -EIO;
		goto srcu_unlock;
	}

	if (cmd == UBURMA_CMD) {
		ret = (long)copy_from_user(&hdr, user_hdr,
					   sizeof(struct uburma_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBURMA_CMD_MAX_ARGS_SIZE) ||
		    (hdr.args_len == 0 || hdr.args_addr == 0)) {
			uburma_log_err(
				"invalid input, hdr.command: %d, ret:%ld, hdr.args_len: %d\n",
				hdr.command, ret, hdr.args_len);
			ret = -EINVAL;
		} else {
			if (!is_cmd_ucontext_free(&hdr)) {
				/* Check ucontext */
				down_read(&file->ucontext_rwsem);
				if (!file->ucontext)
					ret = -EINVAL;
				else
					ret = (long)uburma_cmd_parse(
						ubc_dev, file, &hdr);
				up_read(&file->ucontext_rwsem);
			} else {
				ret = (long)uburma_cmd_parse(ubc_dev, file,
							     &hdr);
			}
		}
	} else {
		uburma_log_err("bad ioctl command.\n");
		ret = -ENOIOCTLCMD;
	}

srcu_unlock:
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	uburma_cmd_dec(ubu_dev);
	return ret;
}
