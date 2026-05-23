/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_fast_msg.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : hisdk5_fast_msg.c
 */

#include <linux/module.h>
#include <linux/moduleparam.h>

#include "ossl_knl.h"
#include "fast_msg_common_define.h"
#include "hinic5_comm_cmd.h"
#include "hinic5_hwdev.h"
#include "hinic5_cmdq.h"

#include "hinic5_fast_msg.h"

int hinic5_fast_msg_register_cb(void *hwdev, u8 mod, hinic5_fast_msg_rq_cb callback, void *pri_data)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hisdk5_fast_msg_to_func *fast_msg_to_func = NULL;

	if (mod >= HINIC5_MOD_MAX || !hwdev)
		return -EINVAL;

	if (!dev->fast_msg_to_func)
		return -EINVAL;

	fast_msg_to_func = dev->fast_msg_to_func;

	if (!fast_msg_to_func->fast_msg_rq_cb[mod]) {
		fast_msg_to_func->fast_msg_rq_cb[mod] = callback;
		fast_msg_to_func->fast_msg_rq_data[mod] = pri_data;
	}
	return 0;
}
EXPORT_SYMBOL(hinic5_fast_msg_register_cb);

void hinic5_fast_msg_unregister_cb(void *hwdev, u8 mod)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hisdk5_fast_msg_to_func *fast_msg_to_func = NULL;

	if (mod >= HINIC5_MOD_MAX || !hwdev)
		return;

	if (!dev->fast_msg_to_func)
		return;

	fast_msg_to_func = dev->fast_msg_to_func;

	if (fast_msg_to_func->fast_msg_rq_cb[mod]) {
		fast_msg_to_func->fast_msg_rq_cb[mod] = NULL;
		fast_msg_to_func->fast_msg_rq_data[mod] = NULL;
	}
}
EXPORT_SYMBOL(hinic5_fast_msg_unregister_cb);

void hinic5_fast_msg_clear_bitmap(void *hwdev, u32 rq_offset)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hinic5_cmd_buf *cmd_buf = NULL;
	hisdk5_fast_msg_buf *fast_msg_buf = NULL;
	u64 out_parm;
	int err;

	if (!hwdev)
		return;

	cmd_buf = hinic5_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		sdk_err(dev->dev_hdl, "Allocate clear bit map cmd buf failed\n");
		return;
	}
	fast_msg_buf = (struct hisdk5_fast_msg_buf *)cmd_buf->buf;
	fast_msg_buf->rq_offset = rq_offset;

	hinic5_cpu_to_be32((void *)fast_msg_buf, sizeof(u32));

	cmd_buf->size = sizeof(u32);

	err = hinic5_send_fast_msg_need_resp(hwdev, HINIC5_MOD_COMM,
		COMM_CMD_UCODE_FAST_MSG_CLEAR, cmd_buf, &out_parm);
	if (err != 0 || out_parm != 0) {
		sdk_err(dev->dev_hdl, "Failed to get fast msg cap, err = 0x%x, out_parm = 0x%llx\n",
			err, out_parm);
	}

	hinic5_free_cmd_buf(hwdev, cmd_buf);
}

static struct hisdk5_fast_msg_buf *hinic5_get_rq_msg(struct hisdk5_fast_msg_to_func *fast_msg, u32 rq_offset)
{
	u32 msg_num_per_page;
	u32 page_index;
	u32 page_offset;

	msg_num_per_page = fast_msg->fast_msg_rq_page_size / FAST_MSG_ENTRY_SIZE;
	page_index = rq_offset / msg_num_per_page;
	page_offset = rq_offset % msg_num_per_page;
	return (struct hisdk5_fast_msg_buf *)
		((u8 *)fast_msg->rq_mem[page_index] + page_offset * FAST_MSG_ENTRY_SIZE_B);
}

static void hinic5_fast_msg_recv_msg(struct hisdk5_fast_msg_to_func *fast_msg, u32 rq_offset)
{
	struct hisdk5_fast_msg_buf *rq_msg = hinic5_get_rq_msg(fast_msg, rq_offset);
	struct hinic5_hwdev *hwdev = fast_msg->hwdev;
	u8 mod = rq_msg->fast_msg_header.mod;

	/* Head has already been converted in the upper half, only convert data here */
	hinic5_be32_to_cpu(rq_msg->fast_msg_data, rq_msg->fast_msg_header.data_len);

	if (fast_msg->fast_msg_rq_cb[mod]) {
		fast_msg->fast_msg_rq_cb[mod](rq_msg, fast_msg->fast_msg_rq_data[mod]);
	} else {
		sdk_err(hwdev->dev_hdl,
			"fast_msg_rq_cb is NULL, src_func: 0x%x, mod: %u, cmd: %u, " \
			"data_len: %u, data: 0x%llx\n",
			rq_msg->fast_msg_header.src_func_id, mod,
			rq_msg->fast_msg_header.cmd, rq_msg->fast_msg_header.data_len,
			*(u64 *)rq_msg->fast_msg_data);
	}

	hinic5_fast_msg_clear_bitmap(fast_msg->hwdev, rq_offset);
}

void hinic5_fast_msg_recv_handler(struct work_struct *work)
{
	struct hisdk5_fast_msg_recv_work *recv_work =
		container_of(work, struct hisdk5_fast_msg_recv_work, work);
	struct hisdk5_fast_msg_recv_entry *entry = NULL;
	struct hisdk5_fast_msg_recv_entry *temp = NULL;
	struct hinic5_hwdev *hwdev = recv_work->fast_msg_to_func->hwdev;

	spin_lock_bh(&recv_work->lock);
	list_for_each_entry_safe(entry, temp, &recv_work->msg_head, entry) {
		list_del_init(&entry->entry);
		spin_unlock_bh(&recv_work->lock);

		if (entry->type == MSG_WORK_ENTRY_RECV_FAST_MSG) {
			hinic5_fast_msg_recv_msg(recv_work->fast_msg_to_func, entry->rq_offset);
		} else if (entry->type == MSG_WORK_ENTRY_FORWARDING) {
			entry->forward_cb(entry->forward_data);
			kfree(entry);
		} else {
			sdk_err(hwdev->dev_hdl, "Invalid msg type: 0x%x\n", entry->type);
		}

		spin_lock_bh(&recv_work->lock);
	}
	spin_unlock_bh(&recv_work->lock);
}

void hinic5_fast_msg_rq_handler(void *pri_handle, u32 ceqe_data)
{
	struct hisdk5_fast_msg_to_func *fast_msg = pri_handle;
	struct hisdk5_fast_msg_recv_work *recv_work = NULL;
	struct hisdk5_fast_msg_buf *rq_msg = NULL;
	struct hinic5_hwdev *hwdev = NULL;
	u32 rq_offset, work_id;

	if (!pri_handle)
		return;

	hwdev = fast_msg->hwdev;
	rq_offset = ceqe_data & FAST_MSG_RQ_OFFSET_MASK;
	if (rq_offset >= fast_msg->fast_msg_rq_depth) {
		sdk_err(hwdev->dev_hdl, "rq offset is invalid, rq_offset: 0x%x, depth: 0x%x\n",
			rq_offset, fast_msg->fast_msg_rq_depth);
		return;
	}

	rq_msg = hinic5_get_rq_msg(fast_msg, rq_offset);
	/* Need to use src_func_id, first convert header */
	hinic5_be32_to_cpu(rq_msg, sizeof(hisdk5_fast_msg_header));

	work_id = rq_msg->fast_msg_header.src_func_id % fast_msg->num_concurrent_work;
	recv_work = &fast_msg->recv_concurrent_work[work_id];

	spin_lock(&recv_work->lock);
	if (list_empty(&fast_msg->recv_entries[rq_offset].entry) != 0) {
		list_add_tail(&fast_msg->recv_entries[rq_offset].entry, &recv_work->msg_head);
		spin_unlock(&recv_work->lock);

		queue_work(fast_msg->workq, &recv_work->work);
	} else {
		spin_unlock(&recv_work->lock);
		sdk_err(hwdev->dev_hdl, "rq offset 0x%x, already in process\n", rq_offset);
	}
}

int hinic5_fast_msg_send(void *hwdev, struct hinic5_cmd_buf *cmd_buf, u64 *out_parm)
{
	struct hinic5_hwdev *dev = hwdev;
	int err;

	if (!hwdev || !cmd_buf || !out_parm)
		return -EINVAL;

	err = hinic5_send_fast_msg_need_resp(hwdev, HINIC5_MOD_COMM,
					     COMM_CMD_UCODE_FAST_MSG_CMD, cmd_buf, out_parm);
	if (err != 0)
		sdk_err(dev->dev_hdl, "Failed to send fast msg, ret = 0x%x\n", err);

	return err;
}
EXPORT_SYMBOL(hinic5_fast_msg_send);

int hinic5_fast_msg_forward(void *hwdev, u16 src_func_id, void *data, hinic5_fast_msg_forward_cb callback)
{
	struct hisdk5_fast_msg_to_func *fast_msg = NULL;
	struct hisdk5_fast_msg_recv_entry *recv_entry = NULL;
	struct hisdk5_fast_msg_recv_work *recv_work = NULL;
	struct hinic5_hwdev *dev = hwdev;
	u32 work_id;

	if (!hwdev || !callback)
		return -EINVAL;

	recv_entry = kzalloc(sizeof(*recv_entry), GFP_KERNEL);
	if (!recv_entry)
		return -ENOMEM;

	INIT_LIST_HEAD(&recv_entry->entry);
	recv_entry->type = MSG_WORK_ENTRY_FORWARDING;
	recv_entry->forward_data = data;
	recv_entry->forward_cb = callback;

	fast_msg = dev->fast_msg_to_func;
	work_id = src_func_id % fast_msg->num_concurrent_work;
	recv_work = &fast_msg->recv_concurrent_work[work_id];
	spin_lock_bh(&recv_work->lock);
	list_add_tail(&recv_entry->entry, &recv_work->msg_head);
	spin_unlock_bh(&recv_work->lock);

	queue_work(fast_msg->workq, &recv_work->work);

	return 0;
}
EXPORT_SYMBOL(hinic5_fast_msg_forward);

bool hinic5_support_fast_msg(void *hwdev)
{
	if (!hwdev) {
		pr_err("Hwdev pointer is NULL for getting fast msg support capability\n");
		return false;
	}

	return COMM_SUPPORT_FAST_MSG((struct hinic5_hwdev *)hwdev);
}
EXPORT_SYMBOL(hinic5_support_fast_msg);
