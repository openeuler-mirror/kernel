// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define pr_fmt(fmt) "CDMA: " fmt
#define dev_fmt pr_fmt

#include <linux/list.h>
#include <linux/rwsem.h>
#include "cdma_segment.h"
#include "cdma_dev.h"
#include "cdma_cmd.h"
#include "cdma_context.h"
#include "cdma_queue.h"
#include "cdma_jfc.h"
#include "cdma.h"
#include "cdma_handle.h"
#include <ub/cdma/cdma_api.h>

LIST_HEAD(cdma_client_list);
DECLARE_RWSEM(cdma_clients_rwsem);
DECLARE_RWSEM(cdma_device_rwsem);

/**
 * dma_get_device_list - Get DMA device list
 * @num_devices: DMA device number
 *
 * Users can perform subsequent resource creation operations using a pointer
 * to a DMA device in the list.
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: address of the first device in the list
 */
struct dma_device *dma_get_device_list(u32 *num_devices)
{
	struct cdma_device_attr *attr;
	struct xarray *cdma_devs_tbl;
	struct cdma_dev *cdev = NULL;
	struct dma_device *ret_list;
	unsigned long index;
	u32 count = 0;
	u32 devs_num;

	if (!num_devices)
		return NULL;

	cdma_devs_tbl = get_cdma_dev_tbl(&devs_num);
	if (!devs_num) {
		pr_err("cdma device table is empty\n");
		return NULL;
	}

	ret_list = kcalloc(devs_num, sizeof(struct dma_device), GFP_KERNEL);
	if (!ret_list) {
		*num_devices = 0;
		return NULL;
	}

	xa_for_each(cdma_devs_tbl, index, cdev) {
		attr = &cdev->base.attr;
		if (cdev->status >= CDMA_STATUS_SUSPENDED) {
			pr_warn("not prepared to get device list, eid = 0x%x\n",
				attr->eid.dw0);
			continue;
		}

		mutex_lock(&cdev->eu_mutex);
		if (!attr->eu_num) {
			pr_warn("no eu in cdma dev eid = 0x%x\n", cdev->eid);
			mutex_unlock(&cdev->eu_mutex);
			continue;
		}

		memcpy(&attr->eu, &attr->eus[0], sizeof(attr->eu));
		attr->eid.dw0 = cdev->eid;
		memcpy(&ret_list[count], &cdev->base, sizeof(*ret_list));
		mutex_unlock(&cdev->eu_mutex);
		ret_list[count].private_data =
			kzalloc(sizeof(struct cdma_ctx_res), GFP_KERNEL);
		if (!ret_list[count].private_data)
			break;
		count++;
	}
	*num_devices = count;

	return ret_list;
}
EXPORT_SYMBOL_GPL(dma_get_device_list);

/**
 * dma_free_device_list - Free DMA device list
 * @dev_list: DMA device list
 * @num_devices: DMA device number
 *
 * It can be called after using dev_list and must be called.
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: NA
 */
void dma_free_device_list(struct dma_device *dev_list, u32 num_devices)
{
	int ref_cnt;
	u32 i;

	if (!dev_list)
		return;

	for (i = 0; i < num_devices; i++) {
		ref_cnt = atomic_read(&dev_list[i].ref_cnt);
		if (ref_cnt > 0) {
			pr_warn("the device resource is still in use, eid = 0x%x, cnt = %d\n",
				dev_list[i].attr.eid.dw0, ref_cnt);
			return;
		}
	}

	for (i = 0; i < num_devices; i++)
		kfree(dev_list[i].private_data);

	kfree(dev_list);
}
EXPORT_SYMBOL_GPL(dma_free_device_list);

/**
 * dma_get_device_by_eid - Get the specified EID DMA device
 * @eid: Device eid pointer
 *
 * Choose one to use with the dma_get_device_list function.
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: DMA device structure pointer
 */
struct dma_device *dma_get_device_by_eid(struct dev_eid *eid)
{
	struct cdma_device_attr *attr;
	struct xarray *cdma_devs_tbl;
	struct cdma_dev *cdev = NULL;
	struct dma_device *ret_dev;
	unsigned long index;
	u32 devs_num;

	if (!eid)
		return NULL;

	cdma_devs_tbl = get_cdma_dev_tbl(&devs_num);
	if (!devs_num) {
		pr_err("cdma device table is empty\n");
		return NULL;
	}

	ret_dev = kzalloc(sizeof(struct dma_device), GFP_KERNEL);
	if (!ret_dev)
		return NULL;

	xa_for_each(cdma_devs_tbl, index, cdev) {
		attr = &cdev->base.attr;
		if (cdev->status >= CDMA_STATUS_SUSPENDED) {
			pr_warn("not prepared to get device, eid = 0x%x\n",
				attr->eid.dw0);
			continue;
		}

		mutex_lock(&cdev->eu_mutex);
		if (!cdma_find_seid_in_eus(attr->eus, attr->eu_num, eid,
					   &attr->eu)) {
			mutex_unlock(&cdev->eu_mutex);
			continue;
		}

		memcpy(ret_dev, &cdev->base, sizeof(*ret_dev));
		mutex_unlock(&cdev->eu_mutex);
		ret_dev->private_data =
			kzalloc(sizeof(struct cdma_ctx_res), GFP_KERNEL);
		if (!ret_dev->private_data) {
			kfree(ret_dev);
			return NULL;
		}
		return ret_dev;
	}
	kfree(ret_dev);

	return NULL;
}
EXPORT_SYMBOL_GPL(dma_get_device_by_eid);

/**
 * dma_create_context - Create DMA context
 * @dma_dev: DMA device pointer
 *
 * The context is used to store resources such as Queue and Segment, and
 * returns a pointer to the context information.
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: DMA context ID value
 */
int dma_create_context(struct dma_device *dma_dev)
{
	struct cdma_ctx_res *ctx_res;
	struct cdma_context *ctx;
	struct cdma_dev *cdev;

	if (!dma_dev || !dma_dev->private_data) {
		pr_err("the dma_dev does not exist\n");
		return -EINVAL;
	}

	cdev = get_cdma_dev_by_eid(dma_dev->attr.eid.dw0);
	if (!cdev) {
		pr_err("can't find cdev by eid, eid = 0x%x\n",
		       dma_dev->attr.eid.dw0);
		return -EINVAL;
	}

	if (cdev->status >= CDMA_STATUS_SUSPENDED) {
		pr_warn("not prepared to create context, eid = 0x%x\n",
			dma_dev->attr.eid.dw0);
		return -EINVAL;
	}

	ctx_res = (struct cdma_ctx_res *)dma_dev->private_data;
	if (ctx_res->ctx) {
		pr_err("ctx has been created\n");
		return -EEXIST;
	}

	atomic_inc(&dma_dev->ref_cnt);
	ctx = cdma_alloc_context(cdev, true);
	if (IS_ERR(ctx)) {
		pr_err("alloc context failed, ret = %ld\n", PTR_ERR(ctx));
		atomic_dec(&dma_dev->ref_cnt);
		return PTR_ERR(ctx);
	}
	ctx_res->ctx = ctx;

	return ctx->handle;
}
EXPORT_SYMBOL_GPL(dma_create_context);

/**
 * dma_delete_context - Delete DMA context
 * @dma_dev: DMA device pointer
 * @handle: DMA context ID value
 * Context: Process context, must NOT be called concurrently.
 * Return: NA
 */
void dma_delete_context(struct dma_device *dma_dev, int handle)
{
	struct cdma_ctx_res *ctx_res;
	struct cdma_context *ctx;
	struct cdma_dev *cdev;
	int ref_cnt;

	if (!dma_dev || !dma_dev->private_data)
		return;

	cdev = get_cdma_dev_by_eid(dma_dev->attr.eid.dw0);
	if (!cdev) {
		pr_err("can't find cdev by eid, eid = 0x%x\n",
		       dma_dev->attr.eid.dw0);
		return;
	}

	ctx_res = (struct cdma_ctx_res *)dma_dev->private_data;
	ctx = ctx_res->ctx;
	if (!ctx) {
		dev_err(cdev->dev, "no context needed to be free\n");
		return;
	}

	ref_cnt = atomic_read(&ctx->ref_cnt);
	if (ref_cnt > 0) {
		dev_warn(cdev->dev,
			 "context resource is still in use, cnt = %d\n",
			 ref_cnt);
		return;
	}

	cdma_ref_inc(&cdev->kcmdcnt);
	cdma_free_context(cdev, ctx);
	ctx_res->ctx = NULL;
	atomic_dec(&dma_dev->ref_cnt);
	cdma_ref_dec(&cdev->kcmdcnt, &cdev->kcmddone);
}
EXPORT_SYMBOL_GPL(dma_delete_context);

/**
 * dma_alloc_queue - Alloc DMA queue
 * @dma_dev: DMA device pointer
 * @ctx_id: DMA context ID
 * @cfg: DMA queue configuration information pointer
 *
 * The user uses the queue for DMA read and write operations.
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: DMA queue ID value
 */
int dma_alloc_queue(struct dma_device *dma_dev, int ctx_id, struct queue_cfg *cfg)
{
	struct cdma_ctx_res *ctx_res;
	struct cdma_queue *queue;
	struct cdma_context *ctx;
	struct cdma_dev *cdev;
	int ret;

	if (!cfg || !dma_dev || !dma_dev->private_data)
		return -EINVAL;

	cdev = get_cdma_dev_by_eid(dma_dev->attr.eid.dw0);
	if (!cdev) {
		pr_err("can't find cdev by eid, eid = 0x%x\n",
		       dma_dev->attr.eid.dw0);
		return -EINVAL;
	}

	if (cdev->status >= CDMA_STATUS_SUSPENDED) {
		pr_warn("not prepared to alloc queue, eid = 0x%x\n",
			dma_dev->attr.eid.dw0);
		return -EINVAL;
	}

	ctx = cdma_find_ctx_by_handle(cdev, ctx_id);
	if (!ctx) {
		dev_err(cdev->dev, "invalid ctx_id = %d\n", ctx_id);
		return -EINVAL;
	}
	atomic_inc(&ctx->ref_cnt);

	queue = cdma_create_queue(cdev, ctx, cfg, dma_dev->attr.eu.eid_idx,
				  true);
	if (!queue) {
		dev_err(cdev->dev, "create queue failed\n");
		ret = -EINVAL;
		goto decrease_cnt;
	}

	ctx_res = (struct cdma_ctx_res *)dma_dev->private_data;
	ret = xa_err(
		xa_store(&ctx_res->queue_xa, queue->id, queue, GFP_KERNEL));
	if (ret) {
		dev_err(cdev->dev, "store queue to ctx_res failed, ret = %d\n",
			ret);
		goto free_queue;
	}

	return queue->id;

free_queue:
	cdma_delete_queue(cdev, queue->id);
decrease_cnt:
	atomic_dec(&ctx->ref_cnt);
	return ret;
}
EXPORT_SYMBOL_GPL(dma_alloc_queue);

/**
 * dma_free_queue - Free DMA queue
 * @dma_dev: DMA device pointer
 * @queue_id: DMA queue ID
 * Context: Process context, must NOT be called concurrently.
 * Return: NA
 */
void dma_free_queue(struct dma_device *dma_dev, int queue_id)
{
	struct cdma_ctx_res *ctx_res;
	struct cdma_context *ctx;
	struct cdma_queue *queue;
	struct cdma_dev *cdev;

	if (!dma_dev || !dma_dev->private_data)
		return;

	cdev = get_cdma_dev_by_eid(dma_dev->attr.eid.dw0);
	if (!cdev) {
		pr_err("can't find cdev by eid, eid = 0x%x\n",
		       dma_dev->attr.eid.dw0);
		return;
	}

	ctx_res = (struct cdma_ctx_res *)dma_dev->private_data;
	queue = xa_load(&ctx_res->queue_xa, queue_id);
	if (!queue) {
		dev_err(cdev->dev, "no queue found in this device, id = %d\n",
			queue_id);
		return;
	}
	xa_erase(&ctx_res->queue_xa, queue_id);
	ctx = queue->ctx;

	cdma_ref_inc(&cdev->kcmdcnt);
	cdma_delete_queue(cdev, queue_id);
	atomic_dec(&ctx->ref_cnt);
	cdma_ref_dec(&cdev->kcmdcnt, &cdev->kcmddone);
}
EXPORT_SYMBOL_GPL(dma_free_queue);

/**
 * dma_register_seg - Register local segment
 * @dma_dev: DMA device pointer
 * @ctx_id: DMA context ID
 * @cfg: DMA segment configuration information pointer
 *
 * The segment stores local payload information for operations such as DMA
 * read and write, and returns a pointer to the segment information.
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: DMA segment structure pointer
 */
struct dma_seg *dma_register_seg(struct dma_device *dma_dev, int ctx_id,
				 struct dma_seg_cfg *cfg)
{
	struct cdma_ctx_res *ctx_res;
	struct cdma_segment *seg;
	struct cdma_context *ctx;
	struct dma_seg *ret_seg;
	struct cdma_dev *cdev;
	int ret;

	if (!dma_dev || !dma_dev->private_data || !cfg || !cfg->sva || !cfg->len)
		return NULL;

	cdev = get_cdma_dev_by_eid(dma_dev->attr.eid.dw0);
	if (!cdev) {
		pr_err("can not find normal cdev by eid, eid = 0x%x\n",
		       dma_dev->attr.eid.dw0);
		return NULL;
	}

	if (cdev->status >= CDMA_STATUS_SUSPENDED) {
		pr_warn("not prepared to register segment, eid = 0x%x\n",
			dma_dev->attr.eid.dw0);
		return NULL;
	}

	ctx = cdma_find_ctx_by_handle(cdev, ctx_id);
	if (!ctx) {
		dev_err(cdev->dev, "find ctx by handle failed, handle = %d\n",
			ctx_id);
		return NULL;
	}
	atomic_inc(&ctx->ref_cnt);

	seg = cdma_register_seg(cdev, cfg, true, NULL);
	if (!seg)
		goto decrease_cnt;

	seg->ctx = ctx;
	ret = cdma_seg_grant(cdev, seg, cfg);
	if (ret)
		goto unregister_seg;

	ret_seg = kzalloc(sizeof(struct dma_seg), GFP_KERNEL);
	if (!ret_seg)
		goto ungrant_seg;

	memcpy(ret_seg, &seg->base, sizeof(struct dma_seg));

	ctx_res = (struct cdma_ctx_res *)dma_dev->private_data;
	ret = xa_err(xa_store(&ctx_res->seg_xa, ret_seg->handle, seg,
			      GFP_KERNEL));
	if (ret) {
		dev_err(cdev->dev, "store seg to ctx_res failed, ret = %d\n",
			ret);
		goto free_seg;
	}

	return ret_seg;

free_seg:
	kfree(ret_seg);
ungrant_seg:
	cdma_seg_ungrant(seg);
unregister_seg:
	cdma_unregister_seg(cdev, seg);
decrease_cnt:
	atomic_dec(&ctx->ref_cnt);
	return NULL;
}
EXPORT_SYMBOL_GPL(dma_register_seg);

/**
 * dma_unregister_seg - Unregister local segment
 * @dma_dev: DMA device pointer
 * @dma_seg: DMA segment pointer
 * Context: Process context, must NOT be called concurrently.
 * Return: NA
 */
void dma_unregister_seg(struct dma_device *dma_dev, struct dma_seg *dma_seg)
{
	struct cdma_ctx_res *ctx_res;
	struct cdma_context *ctx;
	struct cdma_segment *seg;
	struct cdma_dev *cdev;

	if (!dma_dev || !dma_dev->private_data || !dma_seg)
		return;

	cdev = get_cdma_dev_by_eid(dma_dev->attr.eid.dw0);
	if (!cdev) {
		pr_err("can not find cdev by eid, eid = 0x%x\n",
		       dma_dev->attr.eid.dw0);
		return;
	}

	ctx_res = (struct cdma_ctx_res *)dma_dev->private_data;
	seg = xa_load(&ctx_res->seg_xa, dma_seg->handle);
	if (!seg) {
		dev_err(cdev->dev,
			"no segment found in this device, handle = %llu\n",
			dma_seg->handle);
		return;
	}
	xa_erase(&ctx_res->seg_xa, dma_seg->handle);
	ctx = seg->ctx;

	cdma_ref_inc(&cdev->kcmdcnt);
	cdma_seg_ungrant(seg);
	cdma_unregister_seg(cdev, seg);
	kfree(dma_seg);
	atomic_dec(&ctx->ref_cnt);
	cdma_ref_dec(&cdev->kcmdcnt, &cdev->kcmddone);
}
EXPORT_SYMBOL_GPL(dma_unregister_seg);

/**
 * dma_import_seg - Import the remote segment
 * @cfg: DMA segment configuration information pointer
 *
 * The segment stores the remote payload information for operations such as
 * DMA read and write, and returns the segment information pointer.
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: DMA segment structure pointer
 */
struct dma_seg *dma_import_seg(struct dma_seg_cfg *cfg)
{
	if (!cfg || !cfg->sva || !cfg->len)
		return NULL;

	return cdma_import_seg(cfg);
}
EXPORT_SYMBOL_GPL(dma_import_seg);

/**
 * dma_unimport_seg - Unimport the remote segment
 * @dma_seg: DMA segment pointer
 * Context: Process context, must NOT be called concurrently.
 * Return: NA
 */
void dma_unimport_seg(struct dma_seg *dma_seg)
{
	if (!dma_seg)
		return;

	cdma_unimport_seg(dma_seg);
}
EXPORT_SYMBOL_GPL(dma_unimport_seg);

static int cdma_param_transfer(struct dma_device *dma_dev, int queue_id,
			       struct cdma_dev **cdev,
			       struct cdma_queue **cdma_queue)
{
	struct cdma_queue *tmp_q;
	struct cdma_dev *tmp_dev;
	u32 eid;

	eid = dma_dev->attr.eid.dw0;
	tmp_dev = get_cdma_dev_by_eid(eid);
	if (!tmp_dev) {
		pr_err("get cdma dev failed, eid = 0x%x\n", eid);
		return -EINVAL;
	}

	if (tmp_dev->status >= CDMA_STATUS_SUSPENDED) {
		pr_warn("not prepared to send packet, eid = 0x%x\n", eid);
		return -EINVAL;
	}

	tmp_q = cdma_find_queue(tmp_dev, queue_id);
	if (!tmp_q) {
		dev_err(tmp_dev->dev, "get resource failed\n");
		return -EINVAL;
	}

	if (!tmp_q->tp || !tmp_q->jfs || !tmp_q->jfc) {
		dev_err(tmp_dev->dev, "get jetty parameters failed\n");
		return -EFAULT;
	}

	*cdev = tmp_dev;
	*cdma_queue = tmp_q;

	return 0;
}

/**
 * dma_write - DMA write operation
 * @dma_dev: DMA device pointer
 * @rmt_seg: the remote segment pointer
 * @local_seg: the local segment pointer
 * @queue_id: DMA queue ID
 *
 * Invoke this interface to initiate a unilateral write operation request,
 * sending the specified number of bytes of data from the designated local
 * memory starting position to the specified destination address.
 * Once the data is successfully written to the remote node, the application
 * can poll the queue to obtain the completion message.
 *
 * Context: Process context. Takes and releases the spin_lock.
 * Return: operation result, DMA_STATUS_OK on success
 */
enum dma_status dma_write(struct dma_device *dma_dev, struct dma_seg *rmt_seg,
			  struct dma_seg *local_seg, int queue_id)
{
	struct cdma_queue *cdma_queue = NULL;
	struct cdma_dev *cdev = NULL;
	struct cdma_tp_cfg *cfg;
	int ret;

	if (!dma_dev || !rmt_seg || !local_seg) {
		pr_err("write input parameters error\n");
		return DMA_STATUS_INVAL;
	}

	ret = cdma_param_transfer(dma_dev, queue_id, &cdev, &cdma_queue);
	if (ret)
		return DMA_STATUS_INVAL;
	cfg = &cdma_queue->tp->cfg;

	ret = cdma_write(cdev, cdma_queue, local_seg, rmt_seg, NULL);
	if (ret) {
		dev_err(cdev->dev, "dma write failed, seid = %u, deid = %u\n",
			cfg->seid, cfg->deid);
		return DMA_STATUS_INVAL;
	}

	return DMA_STATUS_OK;
}
EXPORT_SYMBOL_GPL(dma_write);

/**
 * dma_write_with_notify - DMA write with notify operation
 * @dma_dev: DMA device pointer
 * @rmt_seg: the remote segment pointer
 * @local_seg: the local segment pointer
 * @queue_id: DMA queue ID
 * @data: notify data for write with notify operation
 *
 * Invoke this interface to initiate a write notify operation request for a
 * unilateral operation, which sends a specified number of bytes of data from a
 * designated starting position in local memory to a specified destination address.
 * Once the data is successfully read from the remote node into local memory,
 * the application can poll the queue to obtain the completion message.
 *
 * Context: Process context. Takes and releases the spin_lock.
 * Return: operation result, DMA_STATUS_OK on success
 */
enum dma_status dma_write_with_notify(struct dma_device *dma_dev,
				      struct dma_seg *rmt_seg,
				      struct dma_seg *local_seg, int queue_id,
				      struct dma_notify_data *data)
{
	struct cdma_queue *cdma_queue = NULL;
	struct cdma_dev *cdev = NULL;
	struct cdma_tp_cfg *cfg;
	int ret;

	if (!dma_dev || !rmt_seg || !local_seg || !data || !data->notify_seg) {
		pr_err("write with notify input parameters error\n");
		return DMA_STATUS_INVAL;
	}

	ret = cdma_param_transfer(dma_dev, queue_id, &cdev, &cdma_queue);
	if (ret)
		return DMA_STATUS_INVAL;
	cfg = &cdma_queue->tp->cfg;

	ret = cdma_write(cdev, cdma_queue, local_seg, rmt_seg, data);
	if (ret) {
		dev_err(cdev->dev,
			"dma write with notify failed, seid = %u, deid = %u\n",
			cfg->seid, cfg->deid);
		return DMA_STATUS_INVAL;
	}

	return DMA_STATUS_OK;
}
EXPORT_SYMBOL_GPL(dma_write_with_notify);

/**
 * dma_read - DMA read operation
 * @dma_dev: DMA device pointer
 * @rmt_seg: the remote segment pointer
 * @local_seg: the local segment pointer
 * @queue_id: DMA queue ID
 *
 * Invoke this interface to initiate a unidirectional read operation request,
 * reading data from the specified remote address to the designated local cache
 * starting position.
 * Once the data is successfully read from the remote node to the local memory,
 * the application can poll the queue to obtain the completion message.
 *
 * Context: Process context. Takes and releases the spin_lock.
 * Return: operation result, DMA_STATUS_OK on success
 */
enum dma_status dma_read(struct dma_device *dma_dev, struct dma_seg *rmt_seg,
			 struct dma_seg *local_seg, int queue_id)
{
	struct cdma_queue *cdma_queue = NULL;
	struct cdma_dev *cdev = NULL;
	struct cdma_tp_cfg *cfg;
	int ret;

	if (!dma_dev || !rmt_seg || !local_seg) {
		pr_err("read input parameters error\n");
		return DMA_STATUS_INVAL;
	}

	ret = cdma_param_transfer(dma_dev, queue_id, &cdev, &cdma_queue);
	if (ret)
		return DMA_STATUS_INVAL;
	cfg = &cdma_queue->tp->cfg;

	ret = cdma_read(cdev, cdma_queue, local_seg, rmt_seg);
	if (ret) {
		dev_err(cdev->dev, "dma read failed, seid = %u, deid = %u\n",
			cfg->seid, cfg->deid);
		return DMA_STATUS_INVAL;
	}

	return DMA_STATUS_OK;
}
EXPORT_SYMBOL_GPL(dma_read);

/**
 * dma_cas - DMA cas operation
 * @dma_dev: DMA device pointer
 * @rmt_seg: the remote segment pointer
 * @local_seg: the local segment pointer
 * @queue_id: DMA queue ID
 * @data: compare data and swap data for cas operation
 *
 * Initiate a request for a unilateral atomic CAS operation. Once the operation
 * is successful, the application can poll the queue to obtain the completion
 * message.
 *
 * Context: Process context. Takes and releases the spin_lock.
 * Return: operation result, DMA_STATUS_OK on success
 */
enum dma_status dma_cas(struct dma_device *dma_dev, struct dma_seg *rmt_seg,
			struct dma_seg *local_seg, int queue_id,
			struct dma_cas_data *data)
{
	struct cdma_queue *cdma_queue = NULL;
	struct cdma_dev *cdev = NULL;
	struct cdma_tp_cfg *cfg;
	int ret;

	if (!dma_dev || !rmt_seg || !local_seg || !data) {
		pr_err("cas input parameters error\n");
		return DMA_STATUS_INVAL;
	}

	ret = cdma_param_transfer(dma_dev, queue_id, &cdev, &cdma_queue);
	if (ret)
		return DMA_STATUS_INVAL;
	cfg = &cdma_queue->tp->cfg;

	ret = cdma_cas(cdev, cdma_queue, local_seg, rmt_seg, data);
	if (ret) {
		dev_err(cdev->dev, "dma cas failed, seid = %u, deid = %u\n",
			cfg->seid, cfg->deid);
		return DMA_STATUS_INVAL;
	}

	return DMA_STATUS_OK;
}
EXPORT_SYMBOL_GPL(dma_cas);

/**
 * dma_faa - DMA faa operation
 * @dma_dev: DMA device pointer
 * @rmt_seg: the remote segment pointer
 * @local_seg: the local segment pointer
 * @queue_id: DMA queue ID
 * @add: add data for faa operation
 *
 * Initiate a request for a unilateral atomic FAA operation. Once the operation
 * is successful, the application can poll the queue to obtain the completion
 * message.
 *
 * Context: Process context. Takes and releases the spin_lock.
 * Return: operation result, DMA_STATUS_OK on success
 */
enum dma_status dma_faa(struct dma_device *dma_dev, struct dma_seg *rmt_seg,
			struct dma_seg *local_seg, int queue_id, u64 add)
{
	struct cdma_queue *cdma_queue = NULL;
	struct cdma_dev *cdev = NULL;
	struct cdma_tp_cfg *cfg;
	int ret;

	if (!dma_dev || !rmt_seg || !local_seg) {
		pr_err("faa input parameters error\n");
		return DMA_STATUS_INVAL;
	}

	ret = cdma_param_transfer(dma_dev, queue_id, &cdev, &cdma_queue);
	if (ret)
		return DMA_STATUS_INVAL;
	cfg = &cdma_queue->tp->cfg;

	ret = cdma_faa(cdev, cdma_queue, local_seg, rmt_seg, add);
	if (ret) {
		dev_err(cdev->dev, "dma faa failed, seid = %u, deid = %u\n",
			cfg->seid, cfg->deid);
		return DMA_STATUS_INVAL;
	}

	return DMA_STATUS_OK;
}
EXPORT_SYMBOL_GPL(dma_faa);

/**
 * dma_poll_queue - DMA polling queue
 * @dma_dev: DMA device pointer
 * @queue_id : DMA queue ID
 * @cr_cnt: number of completion record
 * @cr: completion record pointer
 *
 * Poll the DMA channel completion event, and the polling result is returned to
 * the address specified by the parameter cr.
 * The cr data structure includes information such as the result of the request
 * execution, the length of data transferred, and the type of error.
 * The caller must ensure that the number of parameters cr_cnt matches the number
 * of addresses specified by cr.
 *
 * Context: Process context.
 * Return: Polling operation results >0 on success, others on failed
 */
int dma_poll_queue(struct dma_device *dma_dev, int queue_id, u32 cr_cnt,
		   struct dma_cr *cr)
{
	struct cdma_queue *cdma_queue;
	struct cdma_tp_cfg *cfg;
	struct cdma_dev *cdev;
	int npolled;
	u32 eid;

	if (!dma_dev || !cr_cnt || !cr) {
		pr_err("the poll queue input parameter is invalid\n");
		return -EINVAL;
	}

	eid = dma_dev->attr.eid.dw0;
	cdev = get_cdma_dev_by_eid(eid);
	if (!cdev) {
		pr_err("get cdma dev failed, eid = 0x%x\n", eid);
		return -EINVAL;
	}

	if (cdev->status >= CDMA_STATUS_SUSPENDED) {
		pr_warn("not prepared to poll queue, eid = 0x%x\n", eid);
		return -EINVAL;
	}

	cdma_queue = cdma_find_queue(cdev, queue_id);
	if (!cdma_queue || !cdma_queue->jfc) {
		dev_err(cdev->dev, "get cdma queue failed, queue_id = %d\n",
			queue_id);
		return -EINVAL;
	}
	cfg = &cdma_queue->tp->cfg;

	npolled = cdma_poll_jfc(cdma_queue->jfc, cr_cnt, cr);
	if (npolled > 0 && cr->status != DMA_CR_SUCCESS)
		dev_err(cdev->dev, "poll jfc npolled = %d, seid = %u, deid = %u\n",
			npolled, cfg->seid, cfg->deid);

	return npolled;
}
EXPORT_SYMBOL_GPL(dma_poll_queue);

/**
 * dma_register_client - DMA register client
 * @client: DMA device client pointer
 *
 * Register the management software interface to notify the management software
 * that the DMA driver is online. After loading or resetting and restarting the
 * driver, call the add interface to notify the management software to request
 * the resources required by DMA. When the driver is reset, deregistered, or
 * unloaded, call the stop interface to notify the management software to stop
 * using the DMA channel, and then call the remove interface to notify the
 * management software to delete the DMA resources.
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: operation result, 0 on success, others on failed
 */
int dma_register_client(struct dma_client *client)
{
	struct cdma_dev *cdev = NULL;
	struct xarray *cdma_devs_tbl;
	unsigned long index = 0;
	u32 devs_num;

	if (client == NULL || client->client_name == NULL ||
		client->add == NULL || client->remove == NULL ||
		client->stop == NULL) {
		pr_err("invalid parameter\n");
		return -EINVAL;
	}

	if (strnlen(client->client_name, CDMA_CLIENT_NAME) >= CDMA_CLIENT_NAME) {
		pr_err("invalid parameter, client name\n");
		return -EINVAL;
	}

	down_write(&cdma_device_rwsem);

	cdma_devs_tbl = get_cdma_dev_tbl(&devs_num);

	xa_for_each(cdma_devs_tbl, index, cdev) {
		if (client->add && client->add(cdev->eid))
			pr_err("dma client: %s add failed\n",
				client->client_name);
	}
	down_write(&cdma_clients_rwsem);
	list_add_tail(&client->list_node, &cdma_client_list);
	up_write(&cdma_clients_rwsem);
	up_write(&cdma_device_rwsem);

	pr_info("dma client: %s register success\n", client->client_name);
	return 0;
}
EXPORT_SYMBOL_GPL(dma_register_client);

/**
 * dma_unregister_client - DMA unregister client
 * @client: DMA device client pointer
 *
 * Unregister the management software interface, and delete client resources
 *
 * Context: Process context, must NOT be called concurrently.
 * Return: NA
 */
void dma_unregister_client(struct dma_client *client)
{
	struct cdma_dev *cdev = NULL;
	struct xarray *cdma_devs_tbl;
	unsigned long index = 0;
	u32 devs_num;

	if (client == NULL || client->client_name == NULL ||
		client->add == NULL || client->remove == NULL ||
		client->stop == NULL) {
		pr_err("Invalid parameter\n");
		return;
	}

	if (strnlen(client->client_name, CDMA_CLIENT_NAME) >= CDMA_CLIENT_NAME) {
		pr_err("invalid parameter, client name\n");
		return;
	}

	down_write(&cdma_device_rwsem);
	cdma_devs_tbl = get_cdma_dev_tbl(&devs_num);

	xa_for_each(cdma_devs_tbl, index, cdev) {
		if (client->stop && client->remove) {
			client->stop(cdev->eid);
			client->remove(cdev->eid);
		}
	}

	down_write(&cdma_clients_rwsem);
	list_del(&client->list_node);
	up_write(&cdma_clients_rwsem);
	up_write(&cdma_device_rwsem);

	pr_info("dma client: %s unregister success\n", client->client_name);
}
EXPORT_SYMBOL_GPL(dma_unregister_client);
