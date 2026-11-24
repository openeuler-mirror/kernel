/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Default (vanilla) kernel flavor. Selected when no P2P_COMPAT_* macro is set.
 *
 * The 5.15+ NVMe path needs an exported nvme_init_request() and the
 * rq_end_io_ret end-io contract. Mainline exports nvme_init_request()
 * from 5.18 on; plain 5.15-5.17 does not, so use the ubuntu flavor there.
 */
#ifndef P2P_COMPAT_VANILLA_H_
#define P2P_COMPAT_VANILLA_H_

#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/nvme.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "dev.h"

#if P2P_VERSION_LT(5, 15, 0)

#define P2P_LEGACY_KERNEL

#define P2P_NVME_QID_ANY (-1)

/*
 * The NVMe request PDU stores the passthrough command as its first member.
 * Only the legacy completion path needs that pointer to free its owned copy.
 */
struct p2p_nvme_request {
	struct nvme_command *cmd;
};

struct request *nvme_alloc_request(struct request_queue *q,
				   struct nvme_command *cmd,
				   blk_mq_req_flags_t flags, int qid);

static inline struct request *p2p_alloc_nvme_request(struct request_queue *queue,
						     struct nvme_command *cmd)
{
	struct nvme_command *owned_cmd;
	struct request *req;

	owned_cmd = kmemdup(cmd, sizeof(*cmd), GFP_KERNEL);
	if (!owned_cmd)
		return ERR_PTR(-ENOMEM);

	req = nvme_alloc_request(queue, owned_cmd, 0, P2P_NVME_QID_ANY);
	if (IS_ERR(req))
		kfree(owned_cmd);
	return req;
}

static inline void p2p_end_io(struct request *req, blk_status_t status)
{
	struct p2p_nvme_request *nvme_req = blk_mq_rq_to_pdu(req);
	struct nvme_command *cmd = nvme_req->cmd;

	p2p_complete_io(req, status);
	kfree(cmd);
	blk_mq_free_request(req);
}

#else

/*
 * Private prefix of VE Linux 5.15 and Linux 6.6's struct nvme_request through status.
 * Keep the field layout in sync with drivers/nvme/host/nvme.h.
 */
struct p2p_nvme_request {
	struct nvme_command *cmd;
	union nvme_result result;
	u8 genctr;
	u8 retries;
	u8 flags;
	u16 status;
};

#define P2P_NVME_REQ_CANCELLED (1 << 0)

extern void nvme_init_request(struct request *req, struct nvme_command *cmd);

static inline struct request *p2p_alloc_nvme_request(struct request_queue *queue,
						     struct nvme_command *cmd)
{
	struct request *req;

	req = blk_mq_alloc_request(queue,
				   nvme_is_write(cmd) ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN, 0);
	if (!IS_ERR(req))
		nvme_init_request(req, cmd);
	return req;
}

static inline blk_status_t p2p_nvme_passthrough_status(struct request *req, blk_status_t status)
{
	struct p2p_nvme_request *nr = blk_mq_rq_to_pdu(req);

	/* Batched passthrough completion reports block success even on NVMe errors. */
	if (status == BLK_STS_OK && ((nr->flags & P2P_NVME_REQ_CANCELLED) || nr->status))
		return BLK_STS_IOERR;
	return status;
}

static inline enum rq_end_io_ret p2p_end_io(struct request *req, blk_status_t status)
{
	p2p_complete_io(req, p2p_nvme_passthrough_status(req, status));

	return RQ_END_IO_FREE;
}

#endif

#if P2P_VERSION_LT(6, 0, 0)

#define p2p_bdev_handle struct block_device

#define P2P_BDEV_READ_MODE FMODE_READ

static inline p2p_bdev_handle *p2p_bdev_open_by_dev(dev_t dev)
{
	return blkdev_get_by_dev(dev, FMODE_READ, NULL);
}

static inline void p2p_bdev_release(p2p_bdev_handle *handle)
{
	blkdev_put(handle, FMODE_READ);
}

static inline struct block_device *p2p_handle_to_bdev(p2p_bdev_handle *handle)
{
	return handle;
}

static inline struct block_device *p2p_bdev_whole(struct block_device *bdev)
{
#if P2P_VERSION_LT(5, 15, 0)
	return bdev->bd_contains;
#else
	return bdev_whole(bdev);
#endif
}

static inline sector_t p2p_bdev_nr_sectors(struct block_device *bdev)
{
	return i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
}

static inline void p2p_execute_rq_nowait(struct request *req, struct gendisk *disk)
{
#if P2P_VERSION_LT(5, 15, 0)
	blk_execute_rq_nowait(req->q, disk, req, true, req->end_io);
#else
	blk_execute_rq_nowait(disk, req, true, req->end_io);
#endif
}

static inline struct class *p2p_class_create(const char *name)
{
	return class_create(THIS_MODULE, name);
}

#else

#define p2p_bdev_handle struct bdev_handle

#define P2P_BDEV_READ_MODE BLK_OPEN_READ

static inline p2p_bdev_handle *p2p_bdev_open_by_dev(dev_t dev)
{
	return bdev_open_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
}

static inline void p2p_bdev_release(p2p_bdev_handle *handle)
{
	bdev_release(handle);
}

static inline struct block_device *p2p_handle_to_bdev(p2p_bdev_handle *handle)
{
	return handle->bdev;
}

static inline struct block_device *p2p_bdev_whole(struct block_device *bdev)
{
	return bdev_whole(bdev);
}

static inline sector_t p2p_bdev_nr_sectors(struct block_device *bdev)
{
	return bdev_nr_sectors(bdev);
}

static inline void p2p_execute_rq_nowait(struct request *req, struct gendisk *disk)
{
	blk_execute_rq_nowait(req, true);
}

static inline struct class *p2p_class_create(const char *name)
{
	return class_create(name);
}

#endif

#endif
