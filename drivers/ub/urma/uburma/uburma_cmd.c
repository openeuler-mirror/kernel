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
	int ret;

	ret = uburma_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct uburma_cmd_create_ctx));
	if (ret != 0)
		return ret;

	mutex_lock(&file->mutex);

	ucontext = ubcore_alloc_ucontext(ubc_dev, arg.in.uasid,
					 (struct ubcore_udrv_priv *)(void *)&arg.udata);
	if (IS_ERR_OR_NULL(ucontext)) {
		mutex_unlock(&file->mutex);
		return -EPERM;
	}

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

static int uburma_cmd_destroy_ctx(struct ubcore_device *ubc_dev, struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr)
{
	mutex_lock(&file->mutex);
	if (file->ucontext == NULL) {
		mutex_unlock(&file->mutex);
		return -EINVAL;
	}
	uburma_cleanup_uobjs(file, UBURMA_REMOVE_CLOSE);
	ubcore_free_ucontext(ubc_dev, file->ucontext);
	file->ucontext = NULL;
	uburma_log_info("uburma destroy context success.\n");
	mutex_unlock(&file->mutex);
	return 0;
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

static int uburma_cmd_create_jfs(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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
	cfg.trans_mode = arg.in.trans_mode;
	cfg.max_sge = arg.in.max_sge;
	cfg.max_rsge = arg.in.max_rsge;
	cfg.max_inline_data = arg.in.max_inline_data;
	cfg.retry_cnt = arg.in.retry_cnt;
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
	if (IS_ERR(jfc_uobj)) {
		uburma_log_err("failed to find jfc, jfc_handle:%llu.\n", arg.in.jfc_handle);
		ret = -EINVAL;
		goto err_alloc_abort;
	}
	cfg.jfc = jfc_uobj->object;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jfs = ubcore_create_jfs(ubc_dev, &cfg, uburma_jfs_event_cb, &udata);
	if (IS_ERR_OR_NULL(jfs)) {
		uburma_log_err("create jfs or get jfs_id failed.\n");
		ret = -EPERM;
		goto err_put_jfc;
	}
	jfs_uobj->uobj.object = jfs;
	jfs->urma_jfs = arg.in.urma_jfs;

	/* Do not release jfae fd until jfs is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jfs;

	arg.out.id = jfs->id;
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

static int uburma_cmd_delete_jfs(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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
		return ret;
	}

	arg.out.async_events_reported = jfs_uobj->async_events_reported;
	uobj_put(uobj);
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct uburma_cmd_delete_jfs));
}

static int uburma_cmd_create_jfr(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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
	cfg.flag.value = arg.in.flag;
	cfg.trans_mode = arg.in.trans_mode;
	cfg.depth = arg.in.depth;
	cfg.max_sge = arg.in.max_sge;
	cfg.min_rnr_timer = arg.in.min_rnr_timer;
	cfg.ukey.key = arg.in.key;
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
	if (IS_ERR(jfc_uobj)) {
		uburma_log_err("failed to find jfc, jfc_handle:%llu.\n", arg.in.jfc_handle);
		ret = -EINVAL;
		goto err_alloc_abort;
	}
	cfg.jfc = jfc_uobj->object;

	jfr = ubcore_create_jfr(ubc_dev, &cfg, uburma_jfr_event_cb, &udata);
	if (IS_ERR_OR_NULL(jfr)) {
		uburma_log_err("create jfr or get jfr_id failed.\n");
		ret = -EPERM;
		goto err_put_jfc;
	}
	jfr_uobj->uobj.object = jfr;
	jfr->urma_jfr = arg.in.urma_jfr;

	/* Do not release jfae fd until jfr is destroyed */
	ret = uburma_get_jfae(file);
	if (ret != 0)
		goto err_delete_jfr;

	arg.out.id = jfr->id;
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

static int uburma_cmd_modify_jfr(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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

static int uburma_cmd_delete_jfr(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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
		return ret;
	}

	arg.out.async_events_reported = jfr_uobj->async_events_reported;
	uobj_put(uobj);
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct uburma_cmd_delete_jfr));
}

static int uburma_cmd_create_jfc(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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
		ret = -EPERM;
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

static int uburma_cmd_modify_jfc(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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

static int uburma_cmd_delete_jfc(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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
		return ret;
	}

	arg.out.comp_events_reported = jfc_uobj->comp_events_reported;
	arg.out.async_events_reported = jfc_uobj->async_events_reported;
	uobj_put(uobj);
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct uburma_cmd_delete_jfc));
}

static void fill_create_jetty_attr(struct ubcore_jetty_cfg *cfg,
				   const struct uburma_cmd_create_jetty *arg)
{
	cfg->id = arg->in.id;
	cfg->jfs_depth = arg->in.jfs_depth;
	cfg->jfr_depth = arg->in.jfr_depth;
	cfg->flag.value = arg->in.flag;
	cfg->trans_mode = arg->in.trans_mode;
	cfg->max_send_sge = arg->in.max_send_sge;
	cfg->max_send_rsge = arg->in.max_send_rsge;
	cfg->max_recv_sge = arg->in.max_recv_sge;
	cfg->max_inline_data = arg->in.max_inline_data;
	cfg->priority = arg->in.priority;
	cfg->retry_cnt = arg->in.retry_cnt;
	cfg->rnr_retry = arg->in.rnr_retry;
	cfg->err_timeout = arg->in.err_timeout;
	cfg->min_rnr_timer = arg->in.min_rnr_timer;
}

static void fill_create_jetty_out(struct uburma_cmd_create_jetty *arg,
				  const struct ubcore_jetty *jetty)
{
	arg->out.id = jetty->id;
	arg->out.jfs_depth = jetty->jetty_cfg.jfs_depth;
	arg->out.jfr_depth = jetty->jetty_cfg.jfr_depth;
	arg->out.max_send_sge = jetty->jetty_cfg.max_send_sge;
	arg->out.max_send_rsge = jetty->jetty_cfg.max_send_rsge;
	arg->out.max_recv_sge = jetty->jetty_cfg.max_recv_sge;
	arg->out.max_inline_data = jetty->jetty_cfg.max_inline_data;
}

static int uburma_cmd_create_jetty(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_create_jetty arg;
	struct uburma_uobj *send_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *recv_jfc_uobj = ERR_PTR(-ENOENT);
	struct uburma_uobj *jfr_uobj = ERR_PTR(-ENOENT);
	struct ubcore_jetty_cfg cfg = { 0 };
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
	send_jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.send_jfc_handle, file);
	recv_jfc_uobj = uobj_get_read(UOBJ_CLASS_JFC, arg.in.recv_jfc_handle, file);
	if (IS_ERR(send_jfc_uobj) || IS_ERR(recv_jfc_uobj)) {
		uburma_log_err("failed to find send %llu or recv jfc %llu.\n",
			       arg.in.send_jfc_handle, arg.in.recv_jfc_handle);
		ret = -EINVAL;
		goto err_put;
	}
	cfg.send_jfc = send_jfc_uobj->object;
	cfg.recv_jfc = recv_jfc_uobj->object;
	if (cfg.flag.bs.share_jfr != 0) {
		jfr_uobj = uobj_get_read(UOBJ_CLASS_JFR, arg.in.jfr_handle, file);
		if (IS_ERR(jfr_uobj)) {
			uburma_log_err("failed to find jfr, jfr_handle:%llu.\n", arg.in.jfr_handle);
			ret = -EINVAL;
			goto err_put;
		}
		cfg.jfr = jfr_uobj->object;
	}
	cfg.ukey.key = arg.in.key;
	fill_udata(&udata, file->ucontext, &arg.udata);

	jetty = ubcore_create_jetty(ubc_dev, &cfg, uburma_jetty_event_cb, &udata);
	if (IS_ERR_OR_NULL(jetty)) {
		uburma_log_err("create jetty or get jetty_id failed.\n");
		ret = -EPERM;
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
	if (!IS_ERR(jfr_uobj))
		uobj_put_read(jfr_uobj);
	if (!IS_ERR(recv_jfc_uobj))
		uobj_put_read(recv_jfc_uobj);
	if (!IS_ERR(send_jfc_uobj))
		uobj_put_read(send_jfc_uobj);
	uobj_alloc_abort(&jetty_uobj->uobj);
	return ret;
}

static int uburma_cmd_modify_jetty(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
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

static int uburma_cmd_delete_jetty(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
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
		return ret;
	}

	arg.out.async_events_reported = jetty_uobj->async_events_reported;
	uobj_put(uobj);
	return uburma_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct uburma_cmd_delete_jetty));
}

static int uburma_cmd_create_jfce(struct ubcore_device *ubc_dev, struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr)
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

static int uburma_cmd_import_jfr(struct ubcore_device *ubc_dev, struct uburma_file *file,
				 struct uburma_cmd_hdr *hdr)
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
	cfg.id.uasid = arg.in.uasid;
	cfg.id.id = arg.in.id;
	cfg.ukey.key = arg.in.key;
	cfg.trans_mode = arg.in.trans_mode;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tjfr = ubcore_import_jfr(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(tjfr)) {
		uburma_log_err("ubcore_import_jfr failed.\n");
		uobj_alloc_abort(uobj);
		return -EPERM;
	}

	uobj->object = tjfr;
	arg.out.handle = uobj->id;
	if (tjfr->tp != NULL) {
		arg.out.tp_type = 1;
		arg.out.tpn = tjfr->tp->tpn;
	} else {
		arg.out.tpn = UBURMA_INVALID_TPN;
	}

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

static int uburma_cmd_unimport_jfr(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
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
	return ret;
}

static int uburma_cmd_import_jetty(struct ubcore_device *ubc_dev, struct uburma_file *file,
				   struct uburma_cmd_hdr *hdr)
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
	cfg.id.uasid = arg.in.uasid;
	cfg.id.id = arg.in.id;
	cfg.ukey.key = arg.in.key;
	cfg.trans_mode = (enum ubcore_transport_mode)arg.in.trans_mode;
	fill_udata(&udata, file->ucontext, &arg.udata);

	tjetty = ubcore_import_jetty(ubc_dev, &cfg, &udata);
	if (IS_ERR_OR_NULL(tjetty)) {
		uburma_log_err("ubcore_import_jetty failed.\n");
		uobj_alloc_abort(uobj);
		return -EPERM;
	}

	uobj->object = tjetty;
	arg.out.handle = uobj->id;
	if (tjetty->tp != NULL) {
		arg.out.tp_type = 1;
		arg.out.tpn = tjetty->tp->tpn;
	} else {
		arg.out.tpn = UBURMA_INVALID_TPN;
	}

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

static int uburma_cmd_unimport_jetty(struct ubcore_device *ubc_dev, struct uburma_file *file,
				     struct uburma_cmd_hdr *hdr)
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
	return ret;
}

static int uburma_get_jetty_tjetty_objs(struct uburma_file *file, uint64_t jetty_handle,
					uint64_t tjetty_handle, struct uburma_uobj **jetty_uobj,
					struct uburma_uobj **tjetty_uobj)
{
	*jetty_uobj = uobj_get_read(UOBJ_CLASS_JETTY, jetty_handle, file);
	if (IS_ERR(*jetty_uobj)) {
		uburma_log_err("failed to find jetty with handle %llu", jetty_handle);
		return -EINVAL;
	}

	*tjetty_uobj = uobj_get_read(UOBJ_CLASS_TARGET_JETTY, tjetty_handle, file);
	if (IS_ERR(*tjetty_uobj)) {
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
	if (IS_ERR(*jetty_uobj)) {
		uburma_log_err("failed to find jfs with handle %llu", jetty_handle);
		return -EINVAL;
	}

	*tjetty_uobj = uobj_get_read(UOBJ_CLASS_TARGET_JFR, tjetty_handle, file);
	if (IS_ERR(*tjetty_uobj)) {
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

static int uburma_cmd_unadvise_jetty(struct ubcore_device *ubc_dev, struct uburma_file *file,
				     struct uburma_cmd_hdr *hdr)
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

typedef int (*uburma_cmd_handler)(struct ubcore_device *ubc_dev, struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr);

static uburma_cmd_handler g_uburma_cmd_handlers[] = {
	[0] = NULL,
	[UBURMA_CMD_CREATE_CTX] = uburma_cmd_create_ctx,
	[UBURMA_CMD_DESTROY_CTX] = uburma_cmd_destroy_ctx,
	[UBURMA_CMD_CREATE_JFR] = uburma_cmd_create_jfr,
	[UBURMA_CMD_MODIFY_JFR] = uburma_cmd_modify_jfr,
	[UBURMA_CMD_DELETE_JFR] = uburma_cmd_delete_jfr,
	[UBURMA_CMD_CREATE_JFS] = uburma_cmd_create_jfs,
	[UBURMA_CMD_DELETE_JFS] = uburma_cmd_delete_jfs,
	[UBURMA_CMD_CREATE_JFC] = uburma_cmd_create_jfc,
	[UBURMA_CMD_MODIFY_JFC] = uburma_cmd_modify_jfc,
	[UBURMA_CMD_DELETE_JFC] = uburma_cmd_delete_jfc,
	[UBURMA_CMD_CREATE_JFCE] = uburma_cmd_create_jfce,
	[UBURMA_CMD_IMPORT_JFR] = uburma_cmd_import_jfr,
	[UBURMA_CMD_UNIMPORT_JFR] = uburma_cmd_unimport_jfr,
	[UBURMA_CMD_CREATE_JETTY] = uburma_cmd_create_jetty,
	[UBURMA_CMD_MODIFY_JETTY] = uburma_cmd_modify_jetty,
	[UBURMA_CMD_DELETE_JETTY] = uburma_cmd_delete_jetty,
	[UBURMA_CMD_IMPORT_JETTY] = uburma_cmd_import_jetty,
	[UBURMA_CMD_UNIMPORT_JETTY] = uburma_cmd_unimport_jetty,
	[UBURMA_CMD_ADVISE_JFR] = uburma_cmd_advise_jfr,
	[UBURMA_CMD_UNADVISE_JFR] = uburma_cmd_unadvise_jfr,
	[UBURMA_CMD_ADVISE_JETTY] = uburma_cmd_advise_jetty,
	[UBURMA_CMD_UNADVISE_JETTY] = uburma_cmd_unadvise_jetty,
};

static int uburma_cmd_parse(struct ubcore_device *ubc_dev, struct uburma_file *file,
			    struct uburma_cmd_hdr *hdr)
{
	if (hdr->command < UBURMA_CMD_CREATE_CTX || hdr->command > UBURMA_CMD_USER_CTL ||
	    g_uburma_cmd_handlers[hdr->command] == NULL) {
		uburma_log_err("bad uburma command: %d.\n", (int)hdr->command);
		return -EINVAL;
	}
	return g_uburma_cmd_handlers[hdr->command](ubc_dev, file, hdr);
}

long uburma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct uburma_cmd_hdr *user_hdr = (struct uburma_cmd_hdr *)arg;
	struct uburma_file *file = filp->private_data;
	struct uburma_device *ubu_dev = file->ubu_dev;
	struct ubcore_device *ubc_dev;
	struct uburma_cmd_hdr hdr;
	int srcu_idx;
	long ret;

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
		    (hdr.command > UBURMA_CMD_CREATE_CTX && file->ucontext == NULL)) {
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
