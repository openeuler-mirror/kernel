// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ub_cm implementation
 * Author: Chen Yutao
 * Create: 2025-01-10
 * Note:
 * History: 2025-01-10: create file
 */

#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_log.h"
#include "ub_mad.h"
#include "ub_cm.h"

#define UBCM_LOG_FILE_PERMISSION (0644)
#define UBCM_MODULE_NAME "ubcm"

struct ubcm_device {
	struct kref kref;
	struct list_head list_node;
	struct ubcore_device *device;
	struct ubmad_agent *agent;
	spinlock_t agent_lock;
};

static struct ubcm_context g_ubcm_ctx = { 0 };
struct ubcm_context *get_ubcm_ctx(void)
{
	return &g_ubcm_ctx;
}

static int ubcm_open(struct inode *i_node, struct file *filp)
{
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	return 0;
}

static int ubcm_close(struct inode *i_node, struct file *filp)
{
	module_put(THIS_MODULE);
	return 0;
}

static const struct file_operations g_ubcm_ops = {
	.owner = THIS_MODULE,
	.open = ubcm_open,
	.release = ubcm_close,
	.unlocked_ioctl = NULL, /* ubcm does not support ioctl currently */
	.compat_ioctl = NULL,
};

static int ubcm_add_device(struct ubcore_device *device);
static void ubcm_remove_device(struct ubcore_device *device, void *client_ctx);

static struct ubcore_client g_ubcm_client = {
	.list_node = LIST_HEAD_INIT(g_ubcm_client.list_node),
	.client_name = UBCM_MODULE_NAME,
	.add = ubcm_add_device,
	.remove = ubcm_remove_device
};

static int ubcm_get_ubc_dev(struct ubcore_device *device)
{
	if (IS_ERR_OR_NULL(device)) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	atomic_inc(&device->use_cnt);
	return 0;
}

static void ubcm_put_ubc_dev(struct ubcore_device *device)
{
	if (IS_ERR_OR_NULL(device)) {
		ubcore_log_err("Invalid parameter.\n");
		return;
	}

	if (atomic_dec_and_test(&device->use_cnt))
		complete(&device->comp);
}

static void ubcm_get_device(struct ubcm_device *cm_dev)
{
	kref_get(&cm_dev->kref);
}

static void ubcm_kref_release(struct kref *kref)
{
	struct ubcm_device *cm_dev =
		container_of(kref, struct ubcm_device, kref);
	struct ubcm_context *cm_ctx = get_ubcm_ctx();
	struct ubmad_agent *agent;

	/* Delayed work should be flushed before resource destroy */
	flush_workqueue(cm_ctx->wq);
	if (!IS_ERR_OR_NULL(cm_dev->agent)) {
		spin_lock(&cm_dev->agent_lock);
		agent = cm_dev->agent;
		cm_dev->agent = NULL;
		spin_unlock(&cm_dev->agent_lock);
		(void)ubmad_unregister_agent(agent);
	}

	if (!IS_ERR_OR_NULL(cm_dev->device)) {
		ubcm_put_ubc_dev(cm_dev->device);
		cm_dev->device = NULL;
	}

	kfree(cm_dev);
}

static void ubcm_put_device(struct ubcm_device *cm_dev)
{
	uint32_t refcnt;

	refcnt = kref_read(&cm_dev->kref);

	kref_put(&cm_dev->kref, ubcm_kref_release);
}

static int ubcm_send_handler(struct ubmad_agent *agent,
			     struct ubmad_send_cr *send_cr)
{
	/* Note: agent & send_buf cannot be NULL, no need to check */
	if (IS_ERR_OR_NULL(send_cr->cr)) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	if (send_cr->cr->status != UBCORE_CR_SUCCESS) {
		ubcore_log_err("Cr status error: %d.\n",
			     (int)send_cr->cr->status);
		return -EINVAL;
	}

	return 0;
}

static int ubcm_recv_handler(struct ubmad_agent *agent,
			     struct ubmad_recv_cr *recv_cr)
{
	/* Note: agent & recv_buf cannot be NULL, no need to check */
	int ret;

	switch (recv_cr->msg_type) {
	case UBMAD_UBC_CONN_REQ:
		ret = ubcore_cm_recv(agent->device,
				     (struct ubcore_cm_recv_cr *)recv_cr);
		if (ret != 0)
			ubcore_log_err(
				"Failed to handle message by ubcore net, ret: %d.\n",
				ret);
		return ret;
	default:
		ubcore_log_err("Invalid msg_type: %u.\n", recv_cr->msg_type);
		return -EINVAL;
	}

	return 0;
}

static int ubcm_add_device(struct ubcore_device *device)
{
	struct ubcm_context *cm_ctx = get_ubcm_ctx();
	struct ubcm_device *cm_dev;
	int ret;

	cm_dev = kzalloc(sizeof(struct ubcm_device), GFP_KERNEL);
	if (cm_dev == NULL)
		return -ENOMEM;

	kref_init(&cm_dev->kref);
	spin_lock_init(&cm_dev->agent_lock);
	ret = ubcm_get_ubc_dev(device);
	if (ret != 0)
		goto put_dev;
	cm_dev->device = device;

	cm_dev->agent = ubmad_register_agent(device, ubcm_send_handler,
					     ubcm_recv_handler, (void *)cm_dev);
	if (IS_ERR_OR_NULL(cm_dev->agent)) {
		ubcore_log_err("Failed to register mad agent.\n");
		ret = PTR_ERR(cm_dev->agent);
		goto put_dev;
	}

	spin_lock(&cm_ctx->device_lock);
	list_add_tail(&cm_dev->list_node, &cm_ctx->device_list);
	spin_unlock(&cm_ctx->device_lock);

	ubcore_set_client_ctx_data(device, &g_ubcm_client, cm_dev);

	return 0;
put_dev:
	/* Note: cm_dev will free */
	ubcm_put_device(cm_dev);
	return ret;
}

static void ubcm_remove_device(struct ubcore_device *device, void *client_ctx)
{
	struct ubcm_device *cm_dev = (struct ubcm_device *)client_ctx;
	struct ubcm_context *cm_ctx = get_ubcm_ctx();

	if (cm_dev == NULL || cm_dev->device != device) {
		ubcore_log_err("Invalid parameter.\n");
		return;
	}
	spin_lock(&cm_ctx->device_lock);
	list_del(&cm_dev->list_node);
	spin_unlock(&cm_ctx->device_lock);

	ubcm_put_device(cm_dev);
}

void ubcm_work_handler(struct work_struct *work)
{
	struct ubcm_work *cm_work = container_of(work, struct ubcm_work, work);
	struct ubmad_send_buf *send_buf = cm_work->send_buf;
	struct ubmad_send_buf *bad_send_buf;
	struct ubcm_device *cm_dev;
	int ret;

	if (IS_ERR_OR_NULL(send_buf)) {
		ubcore_log_err("Invalid parameter.\n");
		goto free_work;
	}

	cm_dev = ubcm_find_get_device(&send_buf->src_eid);
	if (IS_ERR_OR_NULL(cm_dev) || IS_ERR_OR_NULL(cm_dev->device)) {
		ubcore_log_err("Failed to find ubcm device, src_eid: " EID_FMT ".\n",
			EID_ARGS(send_buf->src_eid));
		goto free_send_buf;
	}
	/* Source eid should be default eid0 for wk_jetty */
	send_buf->src_eid = cm_dev->device->eid_table.eid_entries[0].eid;

	ret = ubmad_post_send(cm_dev->device, send_buf, &bad_send_buf);
	if (ret != 0)
		ubcore_log_err("Failed to post send mad, ret: %d.\n", ret);
	ubcm_put_device(cm_dev);

free_send_buf:
	kfree(send_buf);
free_work:
	kfree(cm_work);
}

static int ubcm_base_init(void)
{
	struct ubcm_context *cm_ctx = get_ubcm_ctx();
	int ret;

	INIT_LIST_HEAD(&cm_ctx->device_list);
	spin_lock_init(&cm_ctx->device_lock);

	cm_ctx->wq = alloc_workqueue(UBCM_MODULE_NAME, 0, 1);
	if (IS_ERR_OR_NULL(cm_ctx->wq)) {
		ubcore_log_err("Failed to alloc ubcm workqueue.\n");
		return -ENOMEM;
	}

	ret = ubcore_register_client(&g_ubcm_client);
	if (ret != 0) {
		ubcore_log_err("Failed to register ubcm client, ret: %d.\n", ret);
		destroy_workqueue(cm_ctx->wq);
		cm_ctx->wq = NULL;
	}

	return ret;
}

static void ubcm_base_uninit(void)
{
	struct ubcm_context *cm_ctx = get_ubcm_ctx();
	struct ubcm_device *cm_dev, *next;

	ubcore_unregister_client(&g_ubcm_client);
	destroy_workqueue(cm_ctx->wq);
	cm_ctx->wq = NULL;

	spin_lock(&cm_ctx->device_lock);
	list_for_each_entry_safe(cm_dev, next, &cm_ctx->device_list,
				 list_node) {
		list_del(&cm_dev->list_node);
		ubcm_put_device(cm_dev);
	}
	spin_unlock(&cm_ctx->device_lock);
}

struct ubcm_device *ubcm_find_get_device(union ubcore_eid *eid)
{
	struct ubcm_context *cm_ctx = get_ubcm_ctx();
	struct ubcm_device *cm_dev, *next, *target = NULL;
	struct ubcore_device *dev;
	uint32_t idx;

	spin_lock(&cm_ctx->device_lock);
	list_for_each_entry_safe(cm_dev, next, &cm_ctx->device_list,
				 list_node) {
		dev = cm_dev->device;
		spin_lock(&dev->eid_table.lock);
		if (IS_ERR_OR_NULL(dev->eid_table.eid_entries)) {
			spin_unlock(&dev->eid_table.lock);
			continue;
		}
		for (idx = 0; idx < dev->attr.dev_cap.max_eid_cnt; idx++) {
			if (memcmp(&dev->eid_table.eid_entries[idx].eid, eid,
				   sizeof(union ubcore_eid)) == 0) {
				target = cm_dev;
				(void)ubcm_get_device(target);
				break;
			}
		}
		spin_unlock(&dev->eid_table.lock);
		if (target != NULL)
			break;
	}
	spin_unlock(&cm_ctx->device_lock);

	return target;
}

int ubcm_init(void)
{
	int ret;

	ret = ubmad_init();
	if (ret != 0) {
		ubcore_log_err("Failed to init ub_mad, ret: %d.\n", ret);
		return ret;
	}

	ret = ubcm_base_init();
	if (ret != 0) {
		ubcore_log_err("Failed to init ubcm base, ret: %d.\n", ret);
		goto uninit_mad;
	}

	ubcore_register_cm_send_ops(ubmad_ubc_send);

	ubcore_log_info("ubcm module init success.\n");
	return 0;
uninit_mad:
	ubmad_uninit();
	return ret;
}

void ubcm_uninit(void)
{
	ubcm_base_uninit();
	ubmad_uninit();
	ubcore_log_info("ubcm module exits.\n");
}
