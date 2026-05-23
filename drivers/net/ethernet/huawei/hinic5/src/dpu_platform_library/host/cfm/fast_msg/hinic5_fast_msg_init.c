/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_fast_msg_init.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : hinic5_fast_msg_init.c
 */

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"

#include "mpu_inband_cmd.h"
#include "hinic5_fast_msg.h"
#include "hinic5_fast_msg_init.h"

int hinic5_fast_msg_cap_get(struct hinic5_hwdev *hwdev, hisdk5_fast_msg_caps *caps)
{
	int err;
	struct comm_cmd_fast_msg_cap fast_msg_cap;
	u16 out_size;

	memset(&fast_msg_cap, 0, sizeof(fast_msg_cap));

	fast_msg_cap.func_id = hinic5_global_func_id(hwdev);
	out_size = sizeof(struct comm_cmd_fast_msg_cap);

	err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM, COMM_MGMT_CMD_GET_FAST_MSG_CAP,
				      &fast_msg_cap, out_size,
				      &fast_msg_cap, &out_size, 0, HINIC5_CHANNEL_COMM);
	if (err != 0 || out_size == 0 || fast_msg_cap.head.status != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to get fast msg cap, ret = %d, status: 0x%x, out size: 0x%x\n",
			err, fast_msg_cap.head.status, out_size);
		return -EINVAL;
	}

	caps->page_size = fast_msg_cap.fast_msg_page_size;
	caps->depth = fast_msg_cap.fast_msg_depth;
	hwdev->fast_msg_to_func->fast_msg_rq_depth = caps->depth;

	return err;
}

void hinic5_fast_msg_rq_buf_deinit(struct hinic5_hwdev *hwdev)
{
	struct hisdk5_fast_msg_to_func *fast_msg_to_func = NULL;
	u32 page_idx;

	if (!hwdev)
		return;

	if (!hwdev->fast_msg_to_func)
		return;

	fast_msg_to_func = hwdev->fast_msg_to_func;

	for (page_idx = 0; page_idx < fast_msg_to_func->fast_msg_rq_page_num; page_idx++) {
		if (fast_msg_to_func->rq_mem[page_idx])
			dma_free_coherent(
				hwdev->dev_hdl,
				fast_msg_to_func->fast_msg_rq_page_size * FAST_MSG_ENTRY_UNIT,
				fast_msg_to_func->rq_mem[page_idx],
				fast_msg_to_func->rq_mem_paddr[page_idx]
			);
	}
}

void hinic5_fast_msg_clear_sml_table(struct hinic5_hwdev *hwdev)
{
	int err;
	struct comm_cmd_clear_fast_msg_sml_table clear_info = {0};
	u16 out_size = sizeof(struct comm_cmd_clear_fast_msg_sml_table);

	clear_info.func_id = hinic5_global_func_id(hwdev);
	err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM, COMM_MGMT_CMD_CLEAR_FAST_MSG_SML,
				      &clear_info, sizeof(clear_info),
				      &clear_info, &out_size, 0, HINIC5_CHANNEL_COMM);
	if (clear_info.head.status == HINIC5_MGMT_CMD_UNSUPPORTED) {
		sdk_warn(hwdev->dev_hdl, "not support clear fastmsg sml table\n");
		return;
	}

	if (err != 0 || out_size == 0 || clear_info.head.status != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to clear fast msg sml table, ret = %d, status: 0x%x, " \
			"out size: 0x%x\n",
			err, clear_info.head.status, out_size);
	}
}

int hinic5_fast_msg_rq_buf_init(struct hinic5_hwdev *hwdev, hisdk5_fast_msg_caps *caps)
{
	int err;
	struct comm_cmd_set_fast_msg_rq_addr rq_addr;
	u16 out_size;
	u32 page_idx;
	void *page_vaddr = NULL;
	dma_addr_t page_paddr;
	gfp_t gfp_hinic5_vram;

	memset(&rq_addr, 0, sizeof(rq_addr));

	rq_addr.func_id = hinic5_global_func_id(hwdev);
	rq_addr.page_num = (caps->depth * FAST_MSG_ENTRY_SIZE) / caps->page_size;
	hwdev->fast_msg_to_func->fast_msg_rq_page_num = rq_addr.page_num;
	hwdev->fast_msg_to_func->fast_msg_rq_page_size = caps->page_size;
	out_size = sizeof(struct comm_cmd_set_fast_msg_rq_addr);

	gfp_hinic5_vram = hinic5_hinic5_vram_get_gfp_hinic5_vram();

	for (page_idx = 0; page_idx < rq_addr.page_num; page_idx++) {
		page_vaddr = dma_zalloc_coherent(hwdev->dev_hdl,
						 caps->page_size * FAST_MSG_ENTRY_UNIT,
						 &page_paddr, GFP_KERNEL | gfp_hinic5_vram);
		if (!page_vaddr) {
			sdk_err(hwdev->dev_hdl,
				"alloc fast msg rq mem failed, page_idx = 0x%x\n", page_idx);
			err = -ENOMEM;
			goto err_handler;
		}

		hwdev->fast_msg_to_func->rq_mem_paddr[page_idx] = page_paddr;
		hwdev->fast_msg_to_func->rq_mem[page_idx] = page_vaddr;
		rq_addr.page_addr[page_idx].rq_page_addr = (u64)page_paddr;
	}

	err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM, COMM_MGMT_CMD_SET_FAST_MSG_RQ_ADDR,
				      &rq_addr, out_size,
				      &rq_addr, &out_size, 0, HINIC5_CHANNEL_COMM);
	if (err != 0 || out_size == 0 || rq_addr.head.status != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to get fast msg cap, ret = %d, status: 0x%x, out size: 0x%x\n",
			err, rq_addr.head.status, out_size);
		err = -EINVAL;
		goto err_handler;
	}

	return err;
err_handler:
	hinic5_fast_msg_rq_buf_deinit(hwdev);
	return err;
}

static void recv_concurrent_work_init(struct hisdk5_fast_msg_to_func *fast_msg)
{
	struct hisdk5_fast_msg_recv_work *recv_work = NULL;
	u32 i;

	for (i = 0; i < fast_msg->num_concurrent_work; i++) {
		recv_work = &fast_msg->recv_concurrent_work[i];
		recv_work->fast_msg_to_func = fast_msg;
		INIT_WORK(&recv_work->work, hinic5_fast_msg_recv_handler);
		INIT_LIST_HEAD(&recv_work->msg_head);
		spin_lock_init(&recv_work->lock);
	}
}

int hinic5_fast_msg_recv_init(struct hinic5_hwdev *hwdev, struct hisdk5_fast_msg_to_func *fast_msg)
{
	u32 i;
	int err;

	err = hinic5_ceq_register_cb(hwdev, fast_msg, HINIC5_FAST_MSG_RQ,
				     hinic5_fast_msg_rq_handler);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Fail to register fast_msg_rq callback\n");
		return err;
	}

	fast_msg->workq = alloc_workqueue(HINIC5_FAST_MSG_WQ_NAME, WQ_MEM_RECLAIM, 0);
	if (!fast_msg->workq) {
		sdk_err(hwdev->dev_hdl, "Fail to alloc fast_msg workq\n");
		err = -EINVAL;
		goto alloc_workq_err;
	}

	fast_msg->recv_entries = kcalloc(fast_msg->fast_msg_rq_depth,
					 sizeof(struct hisdk5_fast_msg_recv_entry), GFP_KERNEL);
	if (!fast_msg->recv_entries) {
		err = -ENOMEM;
		goto alloc_recv_node_err;
	}

	for (i = 0; i < fast_msg->fast_msg_rq_depth; i++) {
		INIT_LIST_HEAD(&fast_msg->recv_entries[i].entry);
		fast_msg->recv_entries[i].type = MSG_WORK_ENTRY_RECV_FAST_MSG;
		fast_msg->recv_entries[i].rq_offset = i;
	}

	fast_msg->num_concurrent_work = FAST_MSG_RECV_MAX_CONCURRENT;
	fast_msg->recv_concurrent_work = kcalloc(
		fast_msg->num_concurrent_work,
		sizeof(struct hisdk5_fast_msg_recv_work),
		GFP_KERNEL
	);
	if (!fast_msg->recv_concurrent_work) {
		err = -ENOMEM;
		goto alloc_recv_work_err;
	}

	recv_concurrent_work_init(fast_msg);

	return 0;

alloc_recv_work_err:
	kfree(fast_msg->recv_entries);

alloc_recv_node_err:
	destroy_workqueue(fast_msg->workq);

alloc_workq_err:
	hinic5_ceq_unregister_cb(hwdev, HINIC5_FAST_MSG_RQ);

	return err;
}

void hinic5_fast_msg_recv_deinit(struct hinic5_hwdev *hwdev, struct hisdk5_fast_msg_to_func *fast_msg)
{
	struct hisdk5_fast_msg_recv_work *recv_work = NULL;
	u32 i;

	hinic5_ceq_unregister_cb(hwdev, HINIC5_FAST_MSG_RQ);
	destroy_workqueue(fast_msg->workq);

	for (i = 0; i < fast_msg->num_concurrent_work; i++) {
		recv_work = &fast_msg->recv_concurrent_work[i];
		spin_lock_deinit(&recv_work->lock);
		destroy_work(&recv_work->work);
	}

	kfree(fast_msg->recv_concurrent_work);
	fast_msg->recv_concurrent_work = NULL;
	kfree(fast_msg->recv_entries);
	fast_msg->recv_entries = NULL;
}

int hinic5_fast_msg_init(void *hwdev)
{
	int err;
	struct hinic5_hwdev *dev = hwdev;
	hisdk5_fast_msg_caps caps;
	struct hisdk5_fast_msg_to_func *fast_msg_to_func = NULL;

	memset(&caps, 0, sizeof(caps));

	fast_msg_to_func = kzalloc(sizeof(struct hisdk5_fast_msg_to_func), GFP_KERNEL);
	if (!fast_msg_to_func) {
		return -ENOMEM;
	}

	dev->fast_msg_to_func = fast_msg_to_func;
	fast_msg_to_func->hwdev = hwdev;

	err = hinic5_fast_msg_cap_get(dev, &caps);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Failed to get fast_msg cap, err: %d\n", err);
		goto err_get_cap;
	}

	err = hinic5_fast_msg_recv_init(dev, fast_msg_to_func);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Failed to init fast_msg recv msg, err: %d\n", err);
		goto err_init_recv_msg;
	}

	err = hinic5_fast_msg_rq_buf_init(hwdev, &caps);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Failed to init fast_msg rq, err: %d\n", err);
		goto err_rq_init;
	}

	return 0;

err_rq_init:
	hinic5_fast_msg_recv_deinit(dev, fast_msg_to_func);

err_init_recv_msg:
err_get_cap:
	kfree(fast_msg_to_func);
	dev->fast_msg_to_func = NULL;
	return err;
}

void hinic5_fast_msg_deinit(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	hinic5_fast_msg_recv_deinit(dev, dev->fast_msg_to_func);
	hinic5_fast_msg_clear_sml_table(hwdev);
	hinic5_fast_msg_rq_buf_deinit(hwdev);

	kfree(dev->fast_msg_to_func);
	dev->fast_msg_to_func = NULL;
}
