// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
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
#include <urma/ubcore_uapi.h>
#include <urma/ubcore_types.h>
#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_event.h"
#include "uburma_file_ops.h"
#include "uburma_uobj.h"
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

static inline void fill_udata(struct ubcore_udata *out, struct ubcore_ucontext *ctx,
			      struct uburma_cmd_udrv_priv *udata)
{
	out->uctx = ctx;
	out->udrv_data = (struct ubcore_udrv_priv *)(void *)udata;
}

static int uburma_cmd_create_ctx(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct ubcore_ucontext *ucontext;
	struct uburma_cmd_create_ctx arg;
	struct uburma_uobj *uobj;
	struct uburma_jfae_uobj *jfae;
	union ubcore_eid eid;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_create_ctx));
	if (ret != 0)
		return ret;

	mutex_lock(&file->mutex);

	(void)memcpy(eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	ucontext = ubcore_alloc_ucontext(ubc_dev, arg.in.eid_index,
		(struct ubcore_udrv_priv *)(void *)&arg.udata);
	if (IS_ERR_OR_NULL(ucontext)) {
		mutex_unlock(&file->mutex);
		return PTR_ERR(ucontext);
	}
	ucontext->eid = eid;
	uobj = uobj_alloc(UOBJ_CLASS_JFAE, file);
	if (IS_ERR(uobj)) {
		ret = PTR_ERR(uobj);
		goto free_ctx;
	}

	jfae = container_of(uobj, struct uburma_jfae_uobj, uobj);
	uburma_init_jfae(jfae, ubc_dev);
	ucontext->jfae = uobj;
	arg.out.async_fd = uobj->id;
	file->ucontext = ucontext;

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct uburma_cmd_create_ctx));
	if (ret != 0)
		goto free_jfae;

	uobj_alloc_commit(uobj);
	mutex_unlock(&file->mutex);
	uburma_log_info("uburma create context success.\n");
	return ret;

free_jfae:
	uobj_alloc_abort(uobj);
free_ctx:
	ubcore_free_ucontext(ubc_dev, ucontext);
	mutex_unlock(&file->mutex);
	return ret;
}

static void uburma_fill_attr(struct ubcore_seg_cfg *cfg, struct uburma_cmd_register_seg *arg)
{
	cfg->va = arg->in.va;
	cfg->len = arg->in.len;
	cfg->flag.value = arg->in.flag;
	cfg->token_value.token = arg->in.token;
	cfg->iova = arg->in.va;
}

static int uburma_cmd_alloc_token_id(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_alloc_token_id arg;
	union ubcore_token_id_flag flag = {0};
	struct ubcore_udata udata = { 0 };
	struct ubcore_token_id *token_id;
	struct uburma_uobj *uobj;

	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_alloc_token_id));
	if (ret != 0)
		return ret;

	fill_udata(&udata, file->ucontext, &arg.udata);
	uobj = uobj_alloc(UOBJ_CLASS_TOKEN, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("UOBJ_CLASS_TOKEN alloc fail!\n");
		return -ENOMEM;
	}

	token_id = ubcore_alloc_token_id(ubc_dev, flag, &udata);
	if (IS_ERR_OR_NULL(token_id)) {
		uburma_log_err("ubcore alloc token_id id failed.\n");
		ret = PTR_ERR(token_id);
		goto err_free_uobj;
	}
	uobj->object = token_id;
	arg.out.token_id = token_id->token_id;
	arg.out.handle = uobj->id;

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_alloc_token_id));
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

static int uburma_cmd_free_token_id(struct ubcore_device *ubc_dev, struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_free_token_id arg;
	struct ubcore_token_id *token;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_free_token_id));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_TOKEN, (int)arg.in.handle, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("failed to find token id.\n");
		return -EINVAL;
	}

	token = (struct ubcore_token_id *)uobj->object;
	if (arg.in.token_id != token->token_id) {
		uburma_log_err("ubcore remove token_id failed: non-consistent.\n");
		return -EPERM;
	}
	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("ubcore remove commit token_id failed.\n");

	uobj_put_del(uobj);
	return ret;
}

static int uburma_cmd_register_seg(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_register_seg arg;
	struct ubcore_seg_cfg cfg = { 0 };
	struct ubcore_target_seg *seg;
	struct ubcore_udata udata = { 0 };
	struct uburma_uobj *uobj;
	struct uburma_uobj *token_id_uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_register_seg));
	if (ret != 0)
		return ret;

	token_id_uobj = uobj_get_read(UOBJ_CLASS_TOKEN, (int)arg.in.token_id_handle, file);
	if (!IS_ERR_OR_NULL(token_id_uobj))
		cfg.token_id = (struct ubcore_token_id *)token_id_uobj->object;

	uburma_fill_attr(&cfg, &arg);
	cfg.eid_index = file->ucontext->eid_index;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_alloc(UOBJ_CLASS_SEG, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("UOBJ_CLASS_SEG alloc fail!\n");
		ret = -ENOMEM;
		goto err_put_token_id;
	}

	seg = ubcore_register_seg(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(seg)) {
		uburma_log_err("ubcore_register_seg failed.\n");
		ret = PTR_ERR(seg);
		goto err_free_uobj;
	}
	uobj->object = seg;
	arg.out.token_id = seg->seg.token_id;
	arg.out.handle = uobj->id;

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_register_seg));
	if (ret != 0)
		goto err_delete_seg;

	if (!IS_ERR(token_id_uobj))
		uobj_put_read(token_id_uobj);
	uobj_alloc_commit(uobj);
	return 0;

err_delete_seg:
	ubcore_unregister_seg(seg);
err_free_uobj:
	uobj_alloc_abort(uobj);
err_put_token_id:
	if (!IS_ERR(token_id_uobj))
		uobj_put_read(token_id_uobj);
	return ret;
}

static int uburma_cmd_unregister_seg(struct ubcore_device *ubc_dev, struct uburma_file *file,
				     struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unregister_seg arg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_unregister_seg));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_SEG, arg.in.handle, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("failed to find registered seg.\n");
		return -EINVAL;
	}
	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("ubcore_unregister_seg failed.\n");

	uobj_put_del(uobj);
	return ret;
}

static void uburma_write_async_event(struct ubcore_ucontext *ctx, uint64_t event_data,
				     uint32_t event_type, struct list_head *obj_event_list,
				     uint32_t *counter)
{
	struct uburma_jfae_uobj *jfae;

	rcu_read_lock();
	jfae = rcu_dereference(ctx->jfae);
	if (jfae == NULL) {
		rcu_read_unlock();
		return;
	}
	uburma_write_event(&jfae->jfe, event_data, event_type, obj_event_list, counter);
	rcu_read_unlock();
}

void uburma_jfc_event_cb(struct ubcore_event *event, struct ubcore_ucontext *ctx)
{
	struct uburma_jfc_uobj *jfc_uobj;

	if (event->element.jfc == NULL)
		return;

	jfc_uobj = (struct uburma_jfc_uobj *)event->element.jfc->jfc_cfg.jfc_context;
	uburma_write_async_event(ctx, event->element.jfc->urma_jfc, event->event_type,
				 &jfc_uobj->async_event_list, &jfc_uobj->async_events_reported);
}

void uburma_jfs_event_cb(struct ubcore_event *event, struct ubcore_ucontext *ctx)
{
	struct uburma_jfs_uobj *jfs_uobj;

	if (event->element.jfs == NULL)
		return;

	jfs_uobj = (struct uburma_jfs_uobj *)event->element.jfs->jfs_cfg.jfs_context;
	uburma_write_async_event(ctx, event->element.jfs->urma_jfs, event->event_type,
				 &jfs_uobj->async_event_list, &jfs_uobj->async_events_reported);
}

void uburma_jfr_event_cb(struct ubcore_event *event, struct ubcore_ucontext *ctx)
{
	struct uburma_jfr_uobj *jfr_uobj;

	if (event->element.jfr == NULL)
		return;

	jfr_uobj = (struct uburma_jfr_uobj *)event->element.jfr->jfr_cfg.jfr_context;
	uburma_write_async_event(ctx, event->element.jfr->urma_jfr, event->event_type,
				 &jfr_uobj->async_event_list, &jfr_uobj->async_events_reported);
}

void uburma_jetty_event_cb(struct ubcore_event *event, struct ubcore_ucontext *ctx)
{
	struct uburma_jetty_uobj *jetty_uobj;

	if (event->element.jetty == NULL)
		return;

	jetty_uobj = (struct uburma_jetty_uobj *)event->element.jetty->jetty_cfg.jetty_context;
	uburma_write_async_event(ctx, event->element.jetty->urma_jetty, event->event_type,
				 &jetty_uobj->async_event_list, &jetty_uobj->async_events_reported);
}

void uburma_jetty_grp_event_cb(struct ubcore_event *event, struct ubcore_ucontext *ctx)
{
	struct uburma_jetty_grp_uobj *jetty_grp_uobj;

	if (event->element.jetty_grp == NULL)
		return;

	jetty_grp_uobj =
		(struct uburma_jetty_grp_uobj *)event->element.jetty_grp->jetty_grp_cfg.user_ctx;
	uburma_write_async_event(ctx, event->element.jetty_grp->urma_jetty_grp, event->event_type,
		&jetty_grp_uobj->async_event_list, &jetty_grp_uobj->async_events_reported);
}

static int uburma_cmd_create_jfs(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jfs arg;
	struct ubcore_jfs_cfg cfg = { 0 };
	struct ubcore_udata udata;
	struct uburma_jfs_uobj *jfs_uobj;
	struct uburma_uobj *jfc_uobj;
	struct ubcore_jfs *jfs;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_create_jfs));
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
	if (IS_ERR(jfs_uobj)) {
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
	fill_udata(&udata, file->ucontext, &arg.udata);

	jfs = ubcore_create_jfs(ubc_dev, &cfg, uburma_jfs_event_cb, &udata);
	if (IS_ERR_OR_NULL(jfs)) {
		uburma_log_err("create jfs or get jfs_id failed.\n");
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_create_jfs));
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
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_jfs arg;
	struct ubcore_jfs_attr attr = {0};
	struct uburma_uobj *uobj;
	struct ubcore_udata udata;
	struct ubcore_jfs *jfs;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_modify_jfs));
	if (ret != 0)
		return ret;

	attr.mask = arg.in.mask;
	attr.state = arg.in.state;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(uburma_cmd_modify_jfs));
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_query_jfs(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_query_jfs arg;
	struct ubcore_jfs_attr attr = {0};
	struct ubcore_jfs_cfg cfg = {0};
	struct uburma_uobj *uobj;
	struct ubcore_jfs *jfs;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_query_jfs));
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct uburma_cmd_query_jfs));
	uobj_put_read(uobj);
	return ret;
}

static int uburma_cmd_delete_jfs(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jfs arg;
	struct uburma_jfs_uobj *jfs_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_delete_jfs));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFS, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct uburma_cmd_delete_jfs));
}

static int uburma_cmd_import_seg(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_import_seg arg;
	struct ubcore_target_seg_cfg cfg = { 0 };
	struct ubcore_udata udata;
	struct ubcore_target_seg *tseg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_import_seg));
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_SEG, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("UOBJ_CLASS_TARGET_JFR alloc fail!\n");
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
		uburma_log_err("import seg failed.\n");
		uobj_alloc_abort(uobj);
		return PTR_ERR(tseg);
	}

	uobj->object = tseg;
	arg.out.handle = uobj->id;

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_import_seg));
	if (ret != 0) {
		(void)ubcore_unimport_seg(tseg);
		uobj_alloc_abort(uobj);
		return ret;
	}
	uobj_alloc_commit(uobj);
	return ret;
}

static int uburma_cmd_unimport_seg(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unimport_seg arg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_unimport_seg));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_TARGET_SEG, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jfr arg;
	struct uburma_uobj *jfc_uobj;
	struct uburma_jfr_uobj *jfr_uobj;
	struct ubcore_jfr_cfg cfg = { 0 };
	struct ubcore_udata udata;
	struct ubcore_jfr *jfr;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_create_jfr));
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
	if (IS_ERR(jfr_uobj)) {
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

	jfr = ubcore_create_jfr(ubc_dev, &cfg, uburma_jfr_event_cb, &udata);
	if (IS_ERR_OR_NULL(jfr)) {
		uburma_log_err("create jfr or get jfr_id failed.\n");
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_create_jfr));
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
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_jfr arg;
	struct uburma_uobj *uobj;
	struct ubcore_jfr_attr attr = { 0 };
	struct ubcore_udata udata;
	struct ubcore_jfr *jfr;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_modify_jfr));
	if (ret != 0)
		return ret;

	attr.mask = arg.in.mask;
	attr.rx_threshold = arg.in.rx_threshold;
	attr.state = (enum ubcore_jfr_state)arg.in.state;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_modify_jfr));
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_query_jfr(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct unurma_cmd_query_jfr arg;
	struct ubcore_jfr_attr attr = {0};
	struct ubcore_jfr_cfg cfg = {0};
	struct uburma_uobj *uobj;
	struct ubcore_jfr *jfr;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct unurma_cmd_query_jfr));
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct unurma_cmd_query_jfr));
	uobj_put_read(uobj);
	return ret;
}

static int uburma_cmd_delete_jfr(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jfr arg;
	struct uburma_jfr_uobj *jfr_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_delete_jfr));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFR, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct uburma_cmd_delete_jfr));
}

static int uburma_cmd_create_jfc(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jfc arg;
	struct uburma_jfc_uobj *jfc_uobj;
	struct uburma_jfce_uobj *jfce;
	struct ubcore_jfc_cfg cfg = { 0 };
	struct ubcore_udata udata;
	struct ubcore_jfc *jfc;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_create_jfc));
	if (ret != 0)
		return ret;

	cfg.depth = arg.in.depth;
	cfg.flag.value = arg.in.flag;
	cfg.ceqn = arg.in.ceqn;

	/* jfce may be ERR_PTR */
	jfce = uburma_get_jfce_uobj(arg.in.jfce_fd, file);
	if (arg.in.jfce_fd >= 0 && IS_ERR(jfce)) {
		uburma_log_err("Failed to get jfce.\n");
		return -EINVAL;
	}

	fill_udata(&udata, file->ucontext, &arg.udata);

	jfc_uobj = (struct uburma_jfc_uobj *)uobj_alloc(UOBJ_CLASS_JFC, file);
	if (IS_ERR(jfc_uobj)) {
		uburma_log_err("UOBJ_CLASS_JFC alloc fail!\n");
		ret = -1;
		goto err_put_jfce;
	}
	jfc_uobj->comp_events_reported = 0;
	jfc_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jfc_uobj->comp_event_list);
	INIT_LIST_HEAD(&jfc_uobj->async_event_list);
	cfg.jfc_context = jfc_uobj;

	jfc = ubcore_create_jfc(ubc_dev, &cfg, uburma_jfce_handler, uburma_jfc_event_cb, &udata);
	if (IS_ERR_OR_NULL(jfc)) {
		uburma_log_err("create jfc or get jfc_id failed.\n");
		ret = PTR_ERR(jfc);
		goto err_alloc_abort;
	}

	jfc_uobj->jfce = (struct uburma_uobj *)jfce;
	jfc_uobj->uobj.object = jfc;
	jfc->urma_jfc = arg.in.urma_jfc;

	/* Do not release jfae fd until jfc is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jfc;

	arg.out.id = jfc->id;
	arg.out.depth = jfc->jfc_cfg.depth;
	arg.out.handle = jfc_uobj->uobj.id;
	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_create_jfc));
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
	if (!IS_ERR(jfce))
		uobj_put(&jfce->uobj);
	return ret;
}

static int uburma_cmd_modify_jfc(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_jfc arg;
	struct uburma_uobj *uobj;
	struct ubcore_jfc_attr attr = { 0 };
	struct ubcore_udata udata;
	struct ubcore_jfc *jfc;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_modify_jfc));
	if (ret != 0)
		return ret;

	attr.mask = arg.in.mask;
	attr.moderate_count = arg.in.moderate_count;
	attr.moderate_period = arg.in.moderate_period;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_modify_jfc));
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_delete_jfc(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jfc arg;
	struct uburma_uobj *uobj;
	struct uburma_jfc_uobj *jfc_uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_delete_jfc));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JFC, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct uburma_cmd_delete_jfc));
}

static void fill_create_jetty_attr(struct ubcore_jetty_cfg *cfg,
	struct uburma_cmd_create_jetty *arg)
{
	cfg->id = arg->in.id;
	cfg->jfs_depth = arg->in.jfs_depth;
	cfg->jfr_depth = arg->in.jfr_depth;
	cfg->flag.bs.share_jfr = arg->in.jetty_flag & 0x1;  // see urma_jetty_flag
	cfg->flag.bs.lock_free = ((union ubcore_jfs_flag)arg->in.jfs_flag).bs.lock_free;
	cfg->flag.bs.error_suspend = ((union ubcore_jfs_flag)arg->in.jfs_flag).bs.error_suspend;
	cfg->flag.bs.outorder_comp = ((union ubcore_jfs_flag)arg->in.jfs_flag).bs.outorder_comp;
	cfg->flag.bs.sub_trans_mode = ((union ubcore_jfs_flag)arg->in.jfs_flag).bs.sub_trans_mode;
	// see urma_jfs_flag
	cfg->flag.bs.rc_share_tp = (arg->in.jfs_flag &
		(0x1 << UBURMA_CREATE_JETTY_ARG_IN_RC_SHARE_TP_SHIFT)) > 0 ? 1 : 0;

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
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jetty arg;
	struct uburma_uobj *send_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *recv_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *jfr_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *jetty_grp_uobj = ERR_PTR(-ENOENT);
	struct ubcore_jetty_cfg cfg = {0};
	struct uburma_jetty_uobj *jetty_uobj;
	struct ubcore_udata udata;
	struct ubcore_jetty *jetty;
	int ret = 0;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_create_jetty));
	if (ret != 0)
		return ret;

	jetty_uobj = (struct uburma_jetty_uobj *)uobj_alloc(UOBJ_CLASS_JETTY, file);
	if (IS_ERR(jetty_uobj)) {
		uburma_log_err("UOBJ_CLASS_JETTY alloc fail!\n");
		return -ENOMEM;
	}
	jetty_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jetty_uobj->async_event_list);
	cfg.jetty_context = jetty_uobj;

	fill_create_jetty_attr(&cfg, &arg);
	cfg.eid_index = file->ucontext->eid_index;
	send_jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.send_jfc_handle, file);
	recv_jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.recv_jfc_handle, file);
	if (IS_ERR_OR_NULL(send_jfc_uobj) || IS_ERR_OR_NULL(recv_jfc_uobj)) {
		uburma_log_err("failed to find send %llu or recv jfc %llu.\n",
			       arg.in.send_jfc_handle, arg.in.recv_jfc_handle);
		ret = -EINVAL;
		goto err_put;
	}
	cfg.send_jfc = send_jfc_uobj->object;
	cfg.recv_jfc = recv_jfc_uobj->object;
	if (arg.in.jfr_handle != 0) {
		jfr_uobj = uobj_get_read(UOBJ_CLASS_JFR, arg.in.jfr_handle, file);
		if (IS_ERR_OR_NULL(jfr_uobj)) {
			uburma_log_err("failed to find jfr, jfr_handle:%llu.\n", arg.in.jfr_handle);
			ret = -EINVAL;
			goto err_put;
		}
		cfg.jfr = jfr_uobj->object;
		cfg.flag.bs.share_jfr = 1;
	}
	if (arg.in.is_jetty_grp != 0) {
		jetty_grp_uobj = uobj_get_read(UOBJ_CLASS_JETTY_GRP, arg.in.jetty_grp_handle, file);
		if (IS_ERR_OR_NULL(jetty_grp_uobj)) {
			uburma_log_err("failed to find jetty_grp, jetty_grp_handle:%llu.\n",
				arg.in.jetty_grp_handle);
			ret = -EINVAL;
			goto err_put;
		}
		cfg.jetty_grp = (struct ubcore_jetty_group *)jetty_grp_uobj->object;
	}
	cfg.token_value.token = arg.in.token;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jetty = ubcore_create_jetty(ubc_dev, &cfg, uburma_jetty_event_cb, &udata);
	if (IS_ERR_OR_NULL(jetty)) {
		uburma_log_err("create jetty or get jetty_id failed.\n");
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_create_jetty));
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
	if (!IS_ERR(jetty_grp_uobj))
		uobj_put_read(jetty_grp_uobj);
	if (!IS_ERR(jfr_uobj))
		uobj_put_read(jfr_uobj);
	if (!IS_ERR(recv_jfc_uobj))
		uobj_put_read(recv_jfc_uobj);
	if (!IS_ERR(send_jfc_uobj))
		uobj_put_read(send_jfc_uobj);
	uobj_alloc_abort(&jetty_uobj->uobj);
	return ret;
}

static int uburma_cmd_modify_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_jetty arg;
	struct uburma_uobj *uobj;
	struct ubcore_jetty_attr attr = { 0 };
	struct ubcore_jetty *jetty;
	struct ubcore_udata udata;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_modify_jetty));
	if (ret != 0)
		return ret;

	attr.mask = arg.in.mask;
	attr.rx_threshold = arg.in.rx_threshold;
	attr.state = (enum ubcore_jetty_state)arg.in.state;
	fill_udata(&udata, file->ucontext, &arg.udata);

	uobj = uobj_get_write(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_modify_jetty));
	uobj_put_write(uobj);
	return ret;
}

static int uburma_cmd_query_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_query_jetty arg;
	struct ubcore_jetty_attr attr = {0};
	struct ubcore_jetty_cfg cfg = {0};
	struct uburma_uobj *uobj;
	struct ubcore_jetty *jetty;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_query_jetty));
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
	arg.out.jfs_flag = 0;        // todo
	arg.out.trans_mode = (uint32_t)cfg.trans_mode;
	arg.out.priority = cfg.priority;
	arg.out.max_send_sge = cfg.max_send_sge;
	arg.out.max_send_rsge = cfg.max_send_rsge;
	arg.out.max_inline_data = cfg.max_inline_data;
	arg.out.rnr_retry = cfg.rnr_retry;
	arg.out.err_timeout = cfg.err_timeout;

	if (cfg.flag.bs.share_jfr == 1) {
		arg.out.jfr_depth = cfg.jfr_depth;
		arg.out.jfr_flag = 0;        // todo
		arg.out.max_recv_sge = cfg.max_recv_sge;
		arg.out.min_rnr_timer = cfg.min_rnr_timer;
		arg.out.token = cfg.token_value.token;
		arg.out.jfr_id = 0;        // todo
	}

	arg.out.rx_threshold = attr.rx_threshold;
	arg.out.state = (uint32_t)attr.state;
	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct uburma_cmd_query_jetty));
	uobj_put_read(uobj);
	return ret;
}

static int uburma_cmd_delete_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jetty arg;
	struct uburma_jetty_uobj *jetty_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_delete_jetty));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JETTY, arg.in.handle, file);
	if (IS_ERR(uobj)) {
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
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct uburma_cmd_delete_jetty));
}

static int uburma_cmd_create_jfce(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jfce arg;
	struct uburma_jfce_uobj *jfce;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_create_jfce));
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_JFCE, file);
	if (IS_ERR(uobj))
		return PTR_ERR(uobj);

	jfce = container_of(uobj, struct uburma_jfce_uobj, uobj);
	uburma_init_jfe(&jfce->jfe);

	arg.out.fd = uobj->id; /* should get fd before commit uobj */
	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_create_jfce));
	if (ret != 0) {
		uobj_alloc_abort(uobj);
		return ret;
	}

	uobj_alloc_commit(uobj);
	return ret;
}

static int uburma_cmd_import_jfr(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_import_jfr arg;
	struct ubcore_tjetty_cfg cfg = { 0 };
	struct ubcore_udata udata;
	struct ubcore_tjetty *tjfr;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_import_jfr));
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_JFR, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("UOBJ_CLASS_TARGET_JFR alloc fail!\n");
		return -ENOMEM;
	}

	(void)memcpy(cfg.id.eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	cfg.id.id = arg.in.id;
	cfg.flag.value = arg.in.flag;
	cfg.token_value.token = arg.in.token;
	cfg.trans_mode = arg.in.trans_mode;
	cfg.eid_index = file->ucontext->eid_index;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tjfr = ubcore_import_jfr(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(tjfr)) {
		uburma_log_err("ubcore_import_jfr failed.\n");
		uobj_alloc_abort(uobj);
		return PTR_ERR(tjfr);
	}

	uobj->object = tjfr;
	arg.out.handle = uobj->id;
	if (tjfr->vtpn != NULL)
		arg.out.tpn = tjfr->vtpn->vtpn;
	else if (tjfr->tp != NULL)
		arg.out.tpn = tjfr->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_import_jfr));
	if (ret != 0) {
		ubcore_unimport_jfr(tjfr);
		uobj_alloc_abort(uobj);
		return ret;
	}
	uobj_alloc_commit(uobj);
	return 0;
}

static int uburma_cmd_unimport_jfr(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unimport_jfr arg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_unimport_jfr));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_TARGET_JFR, arg.in.handle, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("failed to find tjfr");
		return -EINVAL;
	}
	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("ubcore_unimport_jfr failed.\n");

	uobj_put_del(uobj);
	return ret;
}

static int uburma_cmd_import_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_import_jetty arg;
	struct ubcore_tjetty_cfg cfg = { 0 };
	struct ubcore_tjetty *tjetty;
	struct ubcore_udata udata;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_import_jetty));
	if (ret != 0)
		return ret;

	uobj = uobj_alloc(UOBJ_CLASS_TARGET_JETTY, file);
	if (IS_ERR(uobj)) {
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

	tjetty = ubcore_import_jetty(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		uburma_log_err("ubcore_import_jetty failed.\n");
		uobj_alloc_abort(uobj);
		return PTR_ERR(tjetty);
	}

	uobj->object = tjetty;
	arg.out.handle = uobj->id;
	if (tjetty->vtpn != NULL)
		arg.out.tpn = tjetty->vtpn->vtpn;
	else if (tjetty->tp != NULL)
		arg.out.tpn = tjetty->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct uburma_cmd_import_jetty));
	if (ret != 0) {
		(void)ubcore_unimport_jetty(tjetty);
		uobj_alloc_abort(uobj);
		return ret;
	}
	uobj_alloc_commit(uobj);
	return 0;
}

static int uburma_cmd_unimport_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unimport_jetty arg;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_unimport_jetty));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_TARGET_JETTY, arg.in.handle, file);
	if (IS_ERR(uobj)) {
		uburma_log_err("failed to find tjetty");
		return -EINVAL;
	}
	ret = uobj_remove_commit(uobj);
	if (ret != 0)
		uburma_log_err("ubcore_unimport_jetty failed.\n");

	uobj_put_del(uobj);
	return ret;
}

static int uburma_get_jetty_tjetty_objs(struct uburma_file *file, uint64_t jetty_handle,
	uint64_t tjetty_handle, struct uburma_uobj **jetty_uobj, struct uburma_uobj **tjetty_uobj)
{
	*jetty_uobj = uobj_get_read(UOBJ_CLASS_JETTY, jetty_handle, file);
	if (IS_ERR_OR_NULL(*jetty_uobj)) {
		uburma_log_err("failed to find jetty with handle %llu", jetty_handle);
		return -EINVAL;
	}

	*tjetty_uobj = uobj_get_read(UOBJ_CLASS_TARGET_JETTY, tjetty_handle, file);
	if (IS_ERR_OR_NULL(*tjetty_uobj)) {
		uobj_put_read(*jetty_uobj);
		uburma_log_err("failed to find target jetty with handle %llu", tjetty_handle);
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

static int uburma_get_jfs_tjfr_objs(struct uburma_file *file, uint64_t jetty_handle,
	uint64_t tjetty_handle, struct uburma_uobj **jetty_uobj,
	struct uburma_uobj **tjetty_uobj)
{
	*jetty_uobj = uobj_get_read(UOBJ_CLASS_JFS, jetty_handle, file);
	if (IS_ERR_OR_NULL(*jetty_uobj)) {
		uburma_log_err("failed to find jfs with handle %llu", jetty_handle);
		return -EINVAL;
	}

	*tjetty_uobj = uobj_get_read(UOBJ_CLASS_TARGET_JFR, tjetty_handle, file);
	if (IS_ERR_OR_NULL(*tjetty_uobj)) {
		uobj_put_read(*jetty_uobj);
		uburma_log_err("failed to find target jfr with handle %llu", tjetty_handle);
		return -EINVAL;
	}
	return 0;
}

static inline void uburma_put_jfs_tjfr_objs(struct uburma_uobj *jetty_uobj,
					    struct uburma_uobj *tjetty_uobj)
{
	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
}

static int uburma_cmd_advise_jfr(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_advise_jetty arg;
	struct uburma_uobj *tjfr_uobj;
	struct uburma_uobj *jfs_uobj;
	struct ubcore_udata udata;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_advise_jetty));
	if (ret != 0)
		return ret;

	if (uburma_get_jfs_tjfr_objs(file, arg.in.jetty_handle, arg.in.tjetty_handle, &jfs_uobj,
				     &tjfr_uobj))
		return -EINVAL;

	fill_udata(&udata, file->ucontext, &arg.udata);

	ret = ubcore_advise_jfr(jfs_uobj->object, tjfr_uobj->object, &udata);
	if (ret != 0)
		uburma_log_err("advise jfr failed.\n");

	uburma_put_jfs_tjfr_objs(jfs_uobj, tjfr_uobj);
	return ret;
}

static int uburma_cmd_unadvise_jfr(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unadvise_jetty arg;
	struct uburma_uobj *tjfr_uobj;
	struct uburma_uobj *jfs_uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_unadvise_jetty));
	if (ret != 0)
		return ret;

	if (uburma_get_jfs_tjfr_objs(file, arg.in.jetty_handle, arg.in.tjetty_handle, &jfs_uobj,
				     &tjfr_uobj))
		return -EINVAL;

	ret = ubcore_unadvise_jfr(jfs_uobj->object, tjfr_uobj->object);
	if (ret != 0)
		uburma_log_err("failed to unadvise jfr.\n");

	uburma_put_jfs_tjfr_objs(jfs_uobj, tjfr_uobj);
	return ret;
}

static int uburma_cmd_advise_jetty(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_advise_jetty arg;
	struct uburma_uobj *tjetty_uobj;
	struct uburma_uobj *jetty_uobj;
	struct ubcore_udata udata;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_advise_jetty));
	if (ret != 0)
		return ret;

	if (uburma_get_jetty_tjetty_objs(file, arg.in.jetty_handle, arg.in.tjetty_handle,
					 &jetty_uobj, &tjetty_uobj))
		return -EINVAL;

	fill_udata(&udata, file->ucontext, &arg.udata);

	ret = ubcore_advise_jetty(jetty_uobj->object, tjetty_uobj->object, &udata);
	if (ret != 0)
		uburma_log_err("advise_jetty failed.\n");

	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
	return ret;
}

static int uburma_cmd_unadvise_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_unadvise_jetty arg;
	struct uburma_uobj *tjetty_uobj;
	struct uburma_uobj *jetty_uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_unadvise_jetty));
	if (ret != 0)
		return ret;

	if (uburma_get_jetty_tjetty_objs(file, arg.in.jetty_handle, arg.in.tjetty_handle,
					 &jetty_uobj, &tjetty_uobj))
		return -EINVAL;

	ret = ubcore_unadvise_jetty(jetty_uobj->object, tjetty_uobj->object);
	if (ret != 0)
		uburma_log_err("failed to unadvise jetty, ret: %d.\n", ret);

	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
	return ret;
}

static int uburma_cmd_bind_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_tjetty_uobj *uburma_tjetty;
	struct uburma_cmd_bind_jetty arg;
	struct uburma_uobj *tjetty_uobj;
	struct uburma_uobj *jetty_uobj;
	struct ubcore_tjetty *tjetty;
	struct ubcore_udata udata;
	int ret;

	ret = uburma_copy_from_user(&arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct uburma_cmd_bind_jetty));
	if (ret != 0)
		return ret;

	if (uburma_get_jetty_tjetty_objs(file, arg.in.jetty_handle, arg.in.tjetty_handle,
					 &jetty_uobj, &tjetty_uobj))
		return -EINVAL;

	fill_udata(&udata, file->ucontext, &arg.udata);

	tjetty = (struct ubcore_tjetty *)tjetty_uobj->object;
	ret = ubcore_bind_jetty(jetty_uobj->object, tjetty, &udata);
	if (ret != 0) {
		uburma_log_err("bind jetty failed.\n");
		uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
		return ret;
	}

	if (tjetty->vtpn != NULL)
		arg.out.tpn = tjetty->vtpn->vtpn;
	else if (tjetty->tp != NULL)
		arg.out.tpn = tjetty->tp->tpn;
	else
		arg.out.tpn = UBURMA_INVALID_TPN;

	uburma_tjetty = (struct uburma_tjetty_uobj *)(tjetty_uobj);
	uburma_tjetty->jetty_uobj = (struct uburma_jetty_uobj *)jetty_uobj;
	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct uburma_cmd_bind_jetty));
	if (ret != 0)
		(void)ubcore_unbind_jetty(jetty_uobj->object);

	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
	return ret;
}

static int uburma_cmd_unbind_jetty(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_tjetty_uobj *uburma_tjetty;
	struct uburma_cmd_unadvise_jetty arg;
	struct uburma_uobj *tjetty_uobj;
	struct uburma_uobj *jetty_uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_unadvise_jetty));
	if (ret != 0)
		return ret;

	if (uburma_get_jetty_tjetty_objs(file, arg.in.jetty_handle, arg.in.tjetty_handle,
					 &jetty_uobj, &tjetty_uobj))
		return -EINVAL;

	ret = ubcore_unbind_jetty(jetty_uobj->object);
	if (ret != 0)
		uburma_log_err("failed to unbind jetty, ret: %d.\n", ret);

	uburma_tjetty = (struct uburma_tjetty_uobj *)(tjetty_uobj);
	uburma_tjetty->jetty_uobj = NULL;

	uburma_put_jetty_tjetty_objs(jetty_uobj, tjetty_uobj);
	return ret;
}

static int uburma_cmd_create_jetty_grp(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jetty_grp arg;
	struct uburma_jetty_grp_uobj *jetty_grp_uobj;
	struct ubcore_jetty_grp_cfg cfg = {0};
	struct ubcore_udata udata;
	struct ubcore_jetty_group *jetty_grp;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_create_jetty_grp));
	if (ret != 0)
		return ret;

	(void)memcpy(cfg.name, arg.in.name, UBCORE_JETTY_GRP_MAX_NAME);
	cfg.name[UBCORE_JETTY_GRP_MAX_NAME - 1] = '\0';

	cfg.token_value.token = arg.in.token;
	cfg.id = arg.in.id;
	cfg.policy = (enum ubcore_jetty_grp_policy)arg.in.policy;
	cfg.flag.value = arg.in.flag;
	cfg.eid_index = file->ucontext->eid_index;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jetty_grp_uobj = (struct uburma_jetty_grp_uobj *)uobj_alloc(UOBJ_CLASS_JETTY_GRP, file);
	if (IS_ERR(jetty_grp_uobj)) {
		uburma_log_err("UOBJ_CLASS_JETTY_GRP alloc fail!\n");
		return -ENOMEM;
	}
	jetty_grp_uobj->async_events_reported = 0;
	INIT_LIST_HEAD(&jetty_grp_uobj->async_event_list);
	cfg.user_ctx = (uint64_t)jetty_grp_uobj;

	jetty_grp = ubcore_create_jetty_grp(ubc_dev, &cfg, uburma_jetty_grp_event_cb, &udata);
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

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct uburma_cmd_create_jetty_grp));
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
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_delete_jetty_grp arg;
	struct uburma_jetty_grp_uobj *jetty_grp_uobj;
	struct uburma_uobj *uobj;
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_delete_jetty_grp));
	if (ret != 0)
		return ret;

	uobj = uobj_get_del(UOBJ_CLASS_JETTY_GRP, (int)arg.in.handle, file);
	if (IS_ERR(uobj)) {
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
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct uburma_cmd_delete_jetty_grp));
}

static int uburma_fill_user_ctl_info(struct ubcore_ucontext *ctx,
	struct uburma_cmd_user_ctl *user_ctl, struct ubcore_user_ctl *k_user_ctl)
{
	if (ctx == NULL) {
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
	int i;

	spin_lock(&dev->eid_table.lock);
	if (dev->eid_table.eid_entries == NULL) {
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
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_eid_list *args;
	int ret;

	args = kcalloc(1, sizeof(struct uburma_cmd_get_eid_list), GFP_KERNEL);
	if (args == NULL)
		return -ENOMEM;

	ret = uburma_copy_from_user(args, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_get_eid_list));
	if (ret != 0)
		goto out;

	ret = uburma_fill_eid_list(ubc_dev, args);
	if (ret != 0)
		goto out;

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, args,
		sizeof(struct uburma_cmd_get_eid_list));
out:
	kfree(args);
	return ret;
}

static int uburma_cmd_user_ctl(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct ubcore_user_ctl k_user_ctl = { 0 };
	struct uburma_cmd_user_ctl user_ctl;
	int ret;

	ret = uburma_copy_from_user(&user_ctl, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_user_ctl));
	if (ret != 0)
		return ret;

	ret = uburma_fill_user_ctl_info(file->ucontext, &user_ctl, &k_user_ctl);
	if (ret != 0)
		return ret;

	ret = ubcore_user_control(ubc_dev, &k_user_ctl);
	if (ret != 0)
		return ret;

	return 0;
}

static int uburma_fill_net_addr_list(struct ubcore_device *dev,
	struct uburma_cmd_get_net_addr_list *netaddr_list)
{
	struct uburma_cmd_net_addr_info *netaddr_info;
	struct ubcore_sip_info *entry;
	uint32_t max_netaddr_cnt;
	uint32_t netaddr_cnt = 0;
	uint64_t len;
	int i;

	max_netaddr_cnt = min(dev->sip_table.max_sip_cnt,
		netaddr_list->in.max_netaddr_cnt);
	len = max_netaddr_cnt * sizeof(struct uburma_cmd_net_addr_info);
	netaddr_info = kcalloc(1, len, GFP_KERNEL);
	if (netaddr_info == NULL)
		return -ENOMEM;

	mutex_lock(&dev->sip_table.lock);
	if (dev->sip_table.entry == NULL) {
		mutex_unlock(&dev->sip_table.lock);
		kfree(netaddr_info);
		return -EINVAL;
	}

	for (i = 0; i < max_netaddr_cnt; i++) {
		entry = &dev->sip_table.entry[i];
		if (entry->is_active) {
			netaddr_info[netaddr_cnt].netaddr = entry->addr;
			netaddr_info[netaddr_cnt].index = i;
			netaddr_cnt++;
		}
	}
	mutex_unlock(&dev->sip_table.lock);

	netaddr_list->out.netaddr_cnt = netaddr_cnt;
	netaddr_list->out.len = len;
	if (uburma_copy_to_user((void __user *)
		(uintptr_t)netaddr_list->out.addr, netaddr_info,
		(unsigned long)len) != 0) {
		kfree(netaddr_info);
		return -1;
	}

	kfree(netaddr_info);
	return 0;
}

static int uburma_cmd_get_net_addr_list(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_get_net_addr_list *args;
	int ret;

	args = kcalloc(1, sizeof(struct uburma_cmd_get_net_addr_list), GFP_KERNEL);
	if (args == NULL)
		return -ENOMEM;

	ret = uburma_copy_from_user(args, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_get_net_addr_list));
	if (ret != 0)
		goto out;

	ret = uburma_fill_net_addr_list(ubc_dev, args);
	if (ret != 0)
		goto out;

	ret = uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, args,
		sizeof(struct uburma_cmd_get_net_addr_list));
out:
	kfree(args);
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
		(void)memcpy(net_addr->net_addr.raw, &cmd_net_addr->in6, sizeof(struct in6_addr));
	}

	net_addr->vlan = cmd_net_addr->vlan;
	(void)memcpy(net_addr->mac, cmd_net_addr->mac, UBCORE_MAC_BYTES);
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
	uburma_fill_peer_net_addr(&cmd_attr->peer_net_addr, &attr->peer_net_addr);
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
	struct uburma_cmd_modify_tp *args)
{
	union ubcore_tp_attr_mask mask = {0};
	struct ubcore_tp_cfg tp_cfg = {0};
	struct ubcore_tp_attr attr = {0};
	int ret;

	if (ubc_dev == NULL || ubc_dev->ops == NULL || ubc_dev->ops->modify_user_tp == NULL) {
		uburma_log_err("Invalid parameter.\n");
		return -1;
	}

	uburma_fill_tp_cfg(&args->in.tp_cfg, &tp_cfg);
	uburma_fill_tp_attr(&args->in.attr, &attr);
	uburma_fill_tp_attr_mask(&args->in.mask, &mask);

	ret = ubc_dev->ops->modify_user_tp(ubc_dev, args->in.tpn, &tp_cfg, &attr, mask);
	if (ret != 0)
		uburma_log_err("Failed to modify user tp, ret: %d.\n", ret);

	return ret;
}

static int uburma_cmd_modify_tp(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_modify_tp *args;
	int ret;

	args = kcalloc(1, sizeof(struct uburma_cmd_modify_tp), GFP_KERNEL);
	if (args == NULL)
		return -ENOMEM;

	ret = uburma_copy_from_user(args, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct uburma_cmd_modify_tp));
	if (ret != 0)
		goto out;

	ret = uburma_modify_user_tp(ubc_dev, args);
	if (ret != 0)
		uburma_log_err("Failed to modify user tp, tpn: %u.\n", args->in.tpn);
out:
	kfree(args);
	return ret;
}

typedef int (*uburma_cmd_handler)(struct ubcore_device *ubc_dev,
	struct uburma_file *file, struct uburma_cmd_hdr *hdr);

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
	[UBURMA_CMD_ADVISE_JFR] = uburma_cmd_advise_jfr,
	[UBURMA_CMD_UNADVISE_JFR] = uburma_cmd_unadvise_jfr,
	[UBURMA_CMD_ADVISE_JETTY] = uburma_cmd_advise_jetty,
	[UBURMA_CMD_UNADVISE_JETTY] = uburma_cmd_unadvise_jetty,
	[UBURMA_CMD_BIND_JETTY] = uburma_cmd_bind_jetty,
	[UBURMA_CMD_UNBIND_JETTY] = uburma_cmd_unbind_jetty,
	[UBURMA_CMD_CREATE_JETTY_GRP] = uburma_cmd_create_jetty_grp,
	[UBURMA_CMD_DESTROY_JETTY_GRP] = uburma_cmd_delete_jetty_grp,
	[UBURMA_CMD_USER_CTL] = uburma_cmd_user_ctl,
	[UBURMA_CMD_GET_EID_LIST] = uburma_cmd_get_eid_list,
	[UBURMA_CMD_GET_NETADDR_LIST] = uburma_cmd_get_net_addr_list,
	[UBURMA_CMD_MODIFY_TP] = uburma_cmd_modify_tp,
};

static int uburma_cmd_parse(struct ubcore_device *ubc_dev, struct uburma_file *file,
			    struct uburma_cmd_hdr *hdr)
{
	if (hdr->command < UBURMA_CMD_CREATE_CTX || hdr->command >= UBURMA_CMD_MAX ||
	    g_uburma_cmd_handlers[hdr->command] == NULL) {
		uburma_log_err("bad uburma command: %d.\n", (int)hdr->command);
		return -EINVAL;
	}
	return g_uburma_cmd_handlers[hdr->command](ubc_dev, file, hdr);
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

	if (filp == NULL || filp->private_data == NULL) {
		uburma_log_err("invalid param");
		return -EINVAL;
	}
	file = filp->private_data;
	ubu_dev = file->ubu_dev;
	if (ubu_dev == NULL) {
		uburma_log_err("invalid param");
		return -EINVAL;
	}
	uburma_cmd_inc(ubu_dev);
	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (!ubc_dev) {
		uburma_log_err("can not find ubcore device.\n");
		ret = -EIO;
		goto srcu_unlock;
	}

	if (cmd == UBURMA_CMD) {
		ret = (long)copy_from_user(&hdr, user_hdr, sizeof(struct uburma_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBURMA_CMD_MAX_ARGS_SIZE) ||
		    (hdr.command != UBURMA_CMD_CREATE_CTX &&
			hdr.command != UBURMA_CMD_GET_EID_LIST && file->ucontext == NULL)) {
			uburma_log_err(
				"invalid input, hdr.command: %d, ret:%ld, hdr.args_len: %d\n",
				hdr.command, ret, hdr.args_len);
			ret = -EINVAL;
		} else {
			ret = (long)uburma_cmd_parse(ubc_dev, file, &hdr);
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
