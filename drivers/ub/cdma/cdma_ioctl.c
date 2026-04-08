// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <ub/ubus/ubus.h>

#include <uapi/ub/cdma/cdma_abi.h>
#include "cdma.h"
#include "cdma_context.h"
#include "cdma_types.h"
#include "cdma_tp.h"
#include "cdma_jfs.h"
#include "cdma_queue.h"
#include "cdma_event.h"
#include "cdma_jfc.h"
#include "cdma_segment.h"
#include "cdma_uobj.h"
#include "cdma_ioctl.h"

typedef int (*cdma_cmd_handler)(struct cdma_ioctl_hdr *hdr,
				struct cdma_file *cfile);

static void cdma_fill_device_attr(struct cdma_dev *cdev,
				  struct cdma_device_cap *dev_cap)
{
	dev_cap->max_jfc = cdev->caps.jfc.max_cnt;
	dev_cap->max_jfs = cdev->caps.jfs.max_cnt;
	dev_cap->max_jfc_depth = cdev->caps.jfc.depth;
	dev_cap->max_jfs_depth = cdev->caps.jfs.depth;
	dev_cap->max_jfs_sge = cdev->caps.jfs_sge;
	dev_cap->max_jfs_rsge = cdev->caps.jfs_rsge;
	dev_cap->max_msg_size = cdev->caps.max_msg_len;
	dev_cap->trans_mode = cdev->caps.trans_mode;
	dev_cap->ceq_cnt = cdev->caps.comp_vector_cnt;
}

static int cdma_query_dev(struct cdma_ioctl_hdr *hdr, struct cdma_file *cfile)
{
	struct cdma_cmd_query_device_attr_args args = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	unsigned long ret;

	if (!hdr->args_addr || hdr->args_len < sizeof(args))
		return -EINVAL;

	args.out.attr.eid.dw0 = cdev->eid;
	mutex_lock(&cdev->eu_mutex);
	args.out.attr.eu_num = cdev->base.attr.eu_num;
	memcpy(args.out.attr.eus, cdev->base.attr.eus,
	       sizeof(struct eu_info) * cdev->base.attr.eu_num);
	mutex_unlock(&cdev->eu_mutex);
	cdma_fill_device_attr(cdev, &args.out.attr.dev_cap);

	ret = copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &args,
				(u32)sizeof(args));
	if (ret) {
		dev_err(cdev->dev, "query dev copy to user failed, ret = %lu\n",
			ret);
		return -EFAULT;
	}

	return 0;
}

static int cdma_create_ucontext(struct cdma_ioctl_hdr *hdr,
				struct cdma_file *cfile)
{
	struct cdma_create_context_args args = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_context *ctx;
	struct cdma_jfae *jfae;
	int ret;

	if (cfile->uctx) {
		dev_err(cdev->dev, "cdma context has been created.\n");
		return -EEXIST;
	}

	if (!hdr->args_addr || hdr->args_len < sizeof(args))
		return -EINVAL;

	ret = (int)copy_from_user(&args, (void *)hdr->args_addr,
				  (u32)sizeof(args));
	if (ret) {
		dev_err(cdev->dev, "get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	ctx = cdma_alloc_context(cdev, false);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	ctx->jfae = cdma_alloc_jfae(cfile);
	if (!ctx->jfae) {
		dev_err(cdev->dev, "create jfae failed, ctx handle = %d.\n",
			ctx->handle);
		ret = -EFAULT;
		goto free_context;
	}

	jfae = ctx->jfae;
	jfae->ctx = ctx;
	args.out.cqe_size = cdev->caps.cqe_size;
	args.out.dwqe_enable =
		!!(cdev->caps.feature & CDMA_CAP_FEATURE_DIRECT_WQE);
	args.out.async_fd = jfae->fd;
	cfile->uctx = ctx;

	ret = (int)copy_to_user((void *)hdr->args_addr, &args,
				(u32)sizeof(args));
	if (ret) {
		dev_err(cdev->dev, "copy ctx to user failed, ret = %d.\n", ret);
		goto free_jfae;
	}

	return ret;

free_jfae:
	cfile->uctx = NULL;
	cdma_free_jfae(ctx->jfae);
free_context:
	cdma_free_context(cdev, ctx);

	return ret;
}

static int cdma_delete_ucontext(struct cdma_ioctl_hdr *hdr,
				struct cdma_file *cfile)
{
	struct cdma_dev *cdev = cfile->cdev;

	if (!cfile->uctx) {
		dev_err(cdev->dev, "cdma context has not been created.\n");
		return -ENOENT;
	}
	if (!list_empty(&cfile->uctx->queue_list) ||
	    !list_empty(&cfile->uctx->seg_list)) {
		dev_err(cdev->dev,
			"queue/segment is still in use, ctx handle = %d.\n",
			cfile->uctx->handle);
		return -EBUSY;
	}

	cdma_free_context(cdev, cfile->uctx);
	cfile->uctx = NULL;

	return 0;
}

static int cdma_cmd_create_ctp(struct cdma_ioctl_hdr *hdr,
			       struct cdma_file *cfile)
{
	struct cdma_cmd_create_ctp_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_tp_cfg cfg = { 0 };
	struct cdma_base_tp *ctp;
	struct cdma_queue *queue;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len < sizeof(arg) || !cfile->uctx)
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(&cdev->adev->dev,
			"create tp get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_get(cfile, arg.in.queue_id, UOBJ_TYPE_QUEUE);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev,
			"create ctp, get queue uobj failed, queue id = %u.\n",
			arg.in.queue_id);
		return -EINVAL;
	}
	queue = (struct cdma_queue *)uobj->object;

	uobj = cdma_uobj_create(cfile, UOBJ_TYPE_CTP);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "create ctp uobj failed.\n");
		return -ENOMEM;
	}

	cfg.scna = arg.in.scna;
	cfg.dcna = arg.in.dcna;
	cfg.seid = arg.in.seid;
	cfg.deid = arg.in.deid;
	ctp = cdma_create_ctp(cdev, &cfg);
	if (!ctp) {
		dev_err(&cdev->adev->dev, "create tp failed.\n");
		ret = -EINVAL;
		goto delete_obj;
	}
	uobj->object = ctp;

	arg.out.handle = uobj->id;
	arg.out.tpn = ctp->tpn;
	ret = (int)copy_to_user((void *)hdr->args_addr, &arg, (u32)sizeof(arg));
	if (ret) {
		dev_err(&cdev->adev->dev,
			"create tp copy to user data failed, ret = %d.\n", ret);
		ret = -EFAULT;
		goto delete_ctp;
	}

	cdma_set_queue_res(cdev, queue, QUEUE_RES_TP, ctp);

	return 0;

delete_ctp:
	cdma_delete_ctp(cdev, ctp->tp_id, false);
delete_obj:
	cdma_uobj_delete(uobj);

	return ret;
}

static int cdma_cmd_delete_ctp(struct cdma_ioctl_hdr *hdr,
			       struct cdma_file *cfile)
{
	struct cdma_cmd_delete_ctp_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_base_tp *ctp;
	struct cdma_queue *queue;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len < sizeof(arg))
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(&cdev->adev->dev,
			"delete tp get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_get(cfile, arg.in.queue_id, UOBJ_TYPE_QUEUE);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev,
			"delete ctp, get queue uobj failed, queue id = %u.\n",
			arg.in.queue_id);
		return -EINVAL;
	}
	queue = uobj->object;

	uobj = cdma_uobj_get(cfile, arg.in.handle, UOBJ_TYPE_CTP);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "get ctp uobj failed, handle = %llu.\n",
			arg.in.handle);
		return -EINVAL;
	}
	ctp = uobj->object;

	cdma_delete_ctp(cdev, ctp->tp_id, cfile->uctx->invalid);
	cdma_uobj_delete(uobj);
	cdma_set_queue_res(cdev, queue, QUEUE_RES_TP, NULL);

	return ret;
}

static void cdma_config_jfs(struct cdma_jfs_cfg *cfg,
			    const struct cdma_cmd_create_jfs_args *arg)
{
	cfg->depth = arg->in.depth;
	cfg->flag.value = arg->in.flag;
	cfg->eid_index = arg->in.eid_idx;
	cfg->max_sge = arg->in.max_sge;
	cfg->max_rsge = arg->in.max_rsge;
	cfg->rnr_retry = arg->in.rnr_retry;
	cfg->err_timeout = arg->in.err_timeout;
	cfg->priority = arg->in.priority;
	cfg->jfc_id = arg->in.jfc_id;
	cfg->rmt_eid = arg->in.rmt_eid;
	cfg->pld_token_id = arg->in.pld_token_id;
	cfg->tpn = arg->in.tpn;
	cfg->queue_id = arg->in.queue_id;
	cfg->trans_mode = arg->in.trans_mode;
}

static int cdma_cmd_create_jfs(struct cdma_ioctl_hdr *hdr,
			       struct cdma_file *cfile)
{
	struct cdma_cmd_create_jfs_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_jfs_event *jfs_event;
	struct cdma_jfs_cfg cfg = { 0 };
	struct cdma_udata udata = { 0 };
	struct cdma_base_jfs *jfs;
	struct cdma_queue *queue;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len != (u32)sizeof(arg) || !cfile->uctx)
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(&cdev->adev->dev,
			"create jfs get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_get(cfile, arg.in.queue_id, UOBJ_TYPE_QUEUE);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev,
			"create jfs, get queue uobj failed, queue id = %u.\n",
			arg.in.queue_id);
		return -EINVAL;
	}
	queue = (struct cdma_queue *)uobj->object;

	uobj = cdma_uobj_create(cfile, UOBJ_TYPE_JFS);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "create jfs uobj failed.\n");
		return -ENOMEM;
	}

	udata.uctx = cfile->uctx;
	udata.udrv_data = (struct cdma_udrv_priv *)&arg.udata;
	arg.in.queue_id = queue->id;
	cdma_config_jfs(&cfg, &arg);

	jfs = cdma_create_jfs(cdev, &cfg, &udata);
	if (!jfs) {
		dev_err(&cdev->adev->dev, "create jfs failed.\n");
		ret = -EFAULT;
		goto err_create_jfs;
	}

	uobj->object = jfs;
	jfs_event = &jfs->jfs_event;
	jfs_event->async_events_reported = 0;
	INIT_LIST_HEAD(&jfs_event->async_event_list);

	arg.out.id = jfs->id;
	arg.out.handle = uobj->id;
	arg.out.depth = jfs->cfg.depth;
	arg.out.max_sge = jfs->cfg.max_sge;
	arg.out.max_rsge = jfs->cfg.max_rsge;

	ret = (int)copy_to_user((void *)hdr->args_addr, &arg, (u32)sizeof(arg));
	if (ret) {
		ret = -EFAULT;
		dev_err(&cdev->adev->dev,
			"create jfs copy to user data failed, ret = %d.\n",
			ret);
		goto err_copy_to_usr;
	}

	cdma_set_queue_res(cdev, queue, QUEUE_RES_JFS, jfs);

	return 0;
err_copy_to_usr:
	cdma_delete_jfs(cdev, jfs->id);
err_create_jfs:
	cdma_uobj_delete(uobj);
	return ret;
}

static int cdma_cmd_delete_jfs(struct cdma_ioctl_hdr *hdr,
			       struct cdma_file *cfile)
{
	struct cdma_cmd_delete_jfs_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_base_jfs *base_jfs;
	struct cdma_queue *queue;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len != (u32)sizeof(arg))
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(&cdev->adev->dev,
			"delete jfs get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_get(cfile, arg.in.queue_id, UOBJ_TYPE_QUEUE);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev,
			"delete jfs, get queue uobj failed, queue id = %u.\n",
			arg.in.queue_id);
		return -EINVAL;
	}
	queue = uobj->object;

	uobj = cdma_uobj_get(cfile, arg.in.handle, UOBJ_TYPE_JFS);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "get jfs uobj failed, handle = %llu.\n",
			arg.in.handle);
		return -EINVAL;
	}

	base_jfs = uobj->object;
	ret = cdma_delete_jfs(cdev, base_jfs->id);
	if (ret) {
		dev_err(&cdev->adev->dev, "delete jfs failed, ret = %d.\n",
			ret);
		return ret;
	}

	cdma_set_queue_res(cdev, queue, QUEUE_RES_JFS, NULL);
	cdma_uobj_delete(uobj);

	return 0;
}

static int cdma_cmd_create_queue(struct cdma_ioctl_hdr *hdr, struct cdma_file *cfile)
{
	struct cdma_cmd_create_queue_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct queue_cfg cfg = { 0 };
	struct cdma_queue *queue;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len != sizeof(arg) || !cfile->uctx)
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev, "create queue get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_create(cfile, UOBJ_TYPE_QUEUE);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "create queue uobj failed.\n");
		return -ENOMEM;
	}

	cfg.queue_depth = arg.in.queue_depth;
	cfg.dcna = arg.in.dcna;
	cfg.priority = arg.in.priority;
	cfg.rmt_eid.dw0 = arg.in.rmt_eid;
	cfg.user_ctx = arg.in.user_ctx;
	cfg.trans_mode = arg.in.trans_mode;
	queue = cdma_create_queue(cdev, cfile->uctx, &cfg, 0, false);
	if (!queue) {
		dev_err(cdev->dev, "create queue failed.\n");
		ret = -EINVAL;
		goto err_create_queue;
	}

	uobj->object = queue;
	arg.out.queue_id = queue->id;
	arg.out.handle = uobj->id;
	ret = (int)copy_to_user((void *)hdr->args_addr, &arg, (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev, "create queue copy to user failed, ret = %d.\n", ret);
		ret = -EFAULT;
		goto err_copy_to_user;
	}
	list_add_tail(&queue->list, &cfile->uctx->queue_list);

	return 0;
err_copy_to_user:
	cdma_delete_queue(cdev, queue->id);
err_create_queue:
	cdma_uobj_delete(uobj);
	return ret;
}

static int cdma_cmd_delete_queue(struct cdma_ioctl_hdr *hdr, struct cdma_file *cfile)
{
	struct cdma_cmd_delete_queue_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_queue *queue;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len != sizeof(arg))
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev, "delete queue get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_get(cfile, arg.in.handle, UOBJ_TYPE_QUEUE);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "get queue uobj failed, handle = %llu.\n",
			arg.in.handle);
		return -EINVAL;
	}

	queue = (struct cdma_queue *)uobj->object;
	if (queue->jfc || queue->jfs || queue->tp) {
		dev_err(cdev->dev, "jfc/jfs/tp is still in use.");
		return -EBUSY;
	}

	cdma_uobj_delete(uobj);
	list_del(&queue->list);
	ret = cdma_delete_queue(cdev, queue->id);
	if (ret)
		dev_err(cdev->dev, "delete queue failed, ret = %d.\n", ret);

	return ret;
}

static int cdma_cmd_register_seg(struct cdma_ioctl_hdr *hdr,
				 struct cdma_file *cfile)
{
	struct cdma_cmd_register_seg_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct dma_seg_cfg cfg = { 0 };
	struct cdma_segment *seg;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len != sizeof(arg) || !cfile->uctx) {
		dev_err(cdev->dev, "register seg arg invalid.\n");
		return -EINVAL;
	}

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev,
			"register seg get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_create(cfile, UOBJ_TYPE_SEGMENT);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "create seg uobj failed.\n");
		return -ENOMEM;
	}

	cfg.sva = arg.in.addr;
	cfg.len = arg.in.len;
	seg = cdma_register_seg(cdev, &cfg, false, cfile->uctx);
	if (!seg) {
		dev_err(cdev->dev, "register seg failed.\n");
		ret = -EINVAL;
		goto delete_uobj;
	}
	seg->ctx = cfile->uctx;

	list_add_tail(&seg->list, &cfile->uctx->seg_list);
	arg.out.handle = uobj->id;
	uobj->object = seg;

	ret = (int)copy_to_user((void *)hdr->args_addr, &arg, (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev,
			"register seg copy to user failed, ret = %d.\n", ret);
		ret = -EFAULT;
		goto free_seg;
	}
	return 0;

free_seg:
	list_del(&seg->list);
	cdma_unregister_seg(cdev, seg);
delete_uobj:
	cdma_uobj_delete(uobj);

	return ret;
}

static int cdma_cmd_unregister_seg(struct cdma_ioctl_hdr *hdr,
				   struct cdma_file *cfile)
{
	struct cdma_cmd_unregister_seg_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_segment *seg;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len != sizeof(arg)) {
		dev_err(cdev->dev, "unregister seg arg invalid.\n");
		return -EINVAL;
	}

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev,
			"unregister seg get user data failed, ret = %d.\n",
			ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_get(cfile, arg.in.handle, UOBJ_TYPE_SEGMENT);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "get seg uobj failed.\n");
		return -EINVAL;
	}
	seg = uobj->object;
	list_del(&seg->list);
	cdma_unregister_seg(cdev, seg);
	cdma_uobj_delete(uobj);

	return ret;
}

static int cdma_cmd_create_jfc(struct cdma_ioctl_hdr *hdr,
			       struct cdma_file *cfile)
{
	struct cdma_cmd_create_jfc_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_jfc_event *jfc_event;
	struct cdma_jfc_cfg cfg = { 0 };
	struct cdma_udata udata = { 0 };
	struct cdma_base_jfc *jfc;
	struct cdma_queue *queue;
	struct cdma_uobj *uobj;
	int ret = 0;

	if (!hdr->args_addr || hdr->args_len != (u32)sizeof(arg) || !cfile->uctx)
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev, "get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_get(cfile, arg.in.queue_id, UOBJ_TYPE_QUEUE);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev,
			"create jfc, get queue uobj failed, queue id = %u.\n",
			arg.in.queue_id);
		return -EINVAL;
	}
	queue = (struct cdma_queue *)uobj->object;

	uobj = cdma_uobj_create(cfile, UOBJ_TYPE_JFC);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "create jfc uobj failed.\n");
		return -ENOMEM;
	}

	cfg.depth = arg.in.depth;
	cfg.ceqn = arg.in.ceqn;
	cfg.queue_id = queue->id;
	udata.uctx = cfile->uctx;
	udata.udrv_data = (struct cdma_udrv_priv *)&arg.udata;
	jfc = cdma_create_jfc(cdev, &cfg, &udata);
	if (!jfc) {
		dev_err(cdev->dev, "create jfc failed.\n");
		ret = -EFAULT;
		goto err_create_jfc;
	}

	jfc_event = &jfc->jfc_event;
	uobj->object = jfc;
	cdma_init_jfc_event(jfc_event, jfc);

	arg.out.id = jfc->id;
	arg.out.depth = jfc->jfc_cfg.depth;
	arg.out.handle = uobj->id;
	jfc_event->jfce = cdma_get_jfce_from_id(cdev, arg.in.jfce_id);
	if (!jfc_event->jfce) {
		ret = -EFAULT;
		goto err_get_jfce;
	}
	ret = (int)copy_to_user((void *)hdr->args_addr, &arg, (u32)sizeof(arg));
	if (ret != 0) {
		dev_err(cdev->dev, "copy jfc to user failed, ret = %d.\n", ret);
		ret = -EFAULT;
		goto err_copy_to_user;
	} else {
		cdma_set_queue_res(cdev, queue, QUEUE_RES_JFC, jfc);
	}

	return 0;
err_copy_to_user:
err_get_jfce:
	cdma_delete_jfc(cdev, jfc->id, NULL);
err_create_jfc:
	cdma_uobj_delete(uobj);
	return ret;
}

static int cdma_cmd_delete_jfc(struct cdma_ioctl_hdr *hdr,
			       struct cdma_file *cfile)
{
	struct cdma_cmd_delete_jfc_args arg = { 0 };
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_base_jfc *base_jfc;
	struct cdma_queue *queue;
	struct cdma_uobj *uobj;
	int ret;

	if (!hdr->args_addr || hdr->args_len != (u32)sizeof(arg))
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev, "get user data failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	uobj = cdma_uobj_get(cfile, arg.in.queue_id, UOBJ_TYPE_QUEUE);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev,
			"delete jfc, get queue uobj failed, queue id = %u.\n",
			arg.in.queue_id);
		return -EINVAL;
	}
	queue = (struct cdma_queue *)uobj->object;

	uobj = cdma_uobj_get(cfile, arg.in.handle, UOBJ_TYPE_JFC);
	if (IS_ERR(uobj)) {
		dev_err(cdev->dev, "get jfc uobj failed.\n");
		return -EINVAL;
	}

	base_jfc = (struct cdma_base_jfc *)uobj->object;
	ret = cdma_delete_jfc(cdev, base_jfc->id, &arg);
	if (ret) {
		dev_err(cdev->dev, "cdma delete jfc failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	cdma_set_queue_res(cdev, queue, QUEUE_RES_JFC, NULL);
	cdma_uobj_delete(uobj);

	ret = (int)copy_to_user((void *)hdr->args_addr, &arg, (u32)sizeof(arg));
	if (ret) {
		dev_err(cdev->dev,
			"delete jfc copy to user data failed, ret = %d.\n",
			ret);
		return -EFAULT;
	}

	return 0;
}

static int cdma_cmd_create_jfce(struct cdma_ioctl_hdr *hdr,
				struct cdma_file *cfile)
{
	struct cdma_cmd_create_jfce_args arg = { 0 };
	struct cdma_jfce *jfce;
	int ret;

	if (!hdr->args_addr || hdr->args_len != (u32)sizeof(arg))
		return -EINVAL;

	ret = (int)copy_from_user(&arg, (void *)hdr->args_addr,
				  (u32)sizeof(arg));
	if (ret)
		return -EFAULT;

	jfce = cdma_alloc_jfce(cfile);
	if (IS_ERR(jfce))
		return PTR_ERR(jfce);

	arg.out.fd = jfce->fd;
	arg.out.id = jfce->id;
	ret = (int)copy_to_user((void *)hdr->args_addr, &arg, (u32)sizeof(arg));
	if (ret) {
		ret = -EFAULT;
		goto err_out;
	}

	return 0;

err_out:
	cdma_free_jfce(jfce);

	return ret;
}

static cdma_cmd_handler g_cdma_cmd_handler[CDMA_CMD_MAX] = {
	[CDMA_CMD_QUERY_DEV_INFO] = cdma_query_dev,
	[CDMA_CMD_CREATE_CTX] = cdma_create_ucontext,
	[CDMA_CMD_DELETE_CTX] = cdma_delete_ucontext,
	[CDMA_CMD_CREATE_CTP] = cdma_cmd_create_ctp,
	[CDMA_CMD_DELETE_CTP] = cdma_cmd_delete_ctp,
	[CDMA_CMD_CREATE_JFS] = cdma_cmd_create_jfs,
	[CDMA_CMD_DELETE_JFS] = cdma_cmd_delete_jfs,
	[CDMA_CMD_REGISTER_SEG] = cdma_cmd_register_seg,
	[CDMA_CMD_UNREGISTER_SEG] = cdma_cmd_unregister_seg,
	[CDMA_CMD_CREATE_QUEUE] = cdma_cmd_create_queue,
	[CDMA_CMD_DELETE_QUEUE] = cdma_cmd_delete_queue,
	[CDMA_CMD_CREATE_JFC] = cdma_cmd_create_jfc,
	[CDMA_CMD_DELETE_JFC] = cdma_cmd_delete_jfc,
	[CDMA_CMD_CREATE_JFCE] = cdma_cmd_create_jfce,
};

int cdma_cmd_parse(struct cdma_file *cfile, struct cdma_ioctl_hdr *hdr)
{
	struct cdma_dev *cdev = cfile->cdev;
	int ret;

	if (hdr->command >= CDMA_CMD_MAX || !g_cdma_cmd_handler[hdr->command]) {
		dev_err(cdev->dev,
			"invalid cdma user command or no handler, command = %u\n",
			hdr->command);
		return -ENOIOCTLCMD;
	}

	mutex_lock(&cfile->ctx_mutex);
	ret = g_cdma_cmd_handler[hdr->command](hdr, cfile);
	mutex_unlock(&cfile->ctx_mutex);

	return ret;
}
