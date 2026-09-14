// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UVB info processing module, handles init and window polling.
 * Author: zhangrui
 * Create: 2025-04-18
 */
#define pr_fmt(fmt) "[UVB]: " fmt

#include <linux/io.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/hashtable.h>
#include "cis_info_process.h"
#include "uvb_info_process.h"

/**
Calculate checksum in 4bytes, if size not aligned with 4bytes, padding with 0.
*/
u32 checksum32(const void *data, u32 size)
{
	u64 i;
	u64 sum = 0;
	u32 remainder = size % sizeof(u32);
	u32 *p = (u32 *)data;
	u32 restsize = size - remainder;

	if (!data)
		return (u32)-1;

	for (i = 0; i < restsize; i += sizeof(u32)) {
		sum += *p;
		p++;
	}

	switch (remainder) {
	case 1:
		sum += (*p) & 0x000000FF;
		break;
	case 2:
		sum += (*p) & 0x0000FFFF;
		break;
	case 3:
		sum += (*p) & 0x00FFFFFF;
		break;
	default:
		break;
	}

	return (u32)(sum);
}

static bool is_address_exceed(void *buffer, u32 buffer_size, void *input_address,
			u32 input_size, void *output_address, u32 *output_size)
{
	void *end_of_buffer = buffer + buffer_size;

	if (input_address) {
		if ((input_address < buffer) || (input_address + input_size >= end_of_buffer)) {
			pr_err("input address exceed.\n");
			return true;
		}
	}

	if (output_address && output_size) {
		if ((output_address < buffer + input_size)
			|| (output_address + *output_size >= end_of_buffer)) {
			pr_err("output address exceed.\n");
			return true;
		}
	}

	return false;
}

static int uvb_get_input_data(struct uvb_window *window, void *buffer, u32 buffer_size,
			struct cis_message *msg)
{
	msg->input_size = window->input_data_size;
	if (window->output_data_size == UVB_OUTPUT_SIZE_NULL)
		msg->p_output_size = NULL;
	else
		msg->p_output_size = &window->output_data_size;

	if (!buffer) {
		msg->input = (void *)window->input_data_address;
		msg->output = (void *)window->output_data_address;
	} else {
		msg->input = (window->input_data_address == 0 ? NULL : buffer);
		msg->output = (window->output_data_address == 0 ? NULL :
					((u8 *)buffer + ALIGN(msg->input_size, sizeof(u64))));
		if (is_address_exceed(buffer, buffer_size, msg->input, msg->input_size,
					msg->output, msg->p_output_size)) {
			pr_err("address is exceed\n");
			return -EOVERFLOW;
		}
	}

	if (msg->input_size) {
		if (window->input_data_checksum != checksum32(msg->input, msg->input_size)) {
			pr_err("input data checksum error\n");
			return -EINVAL;
		}
	}
	return 0;
}

static void uvb_return_status(struct uvb_window *window, int status)
{
	window->returned_status = (u32)status;
	window->message_id = ~window->message_id;
}

bool search_local_receiver_id(u32 receiver_id)
{
	bool found = false;
	struct cis_func_node *cis_node;

	rcu_read_lock();
	list_for_each_entry_rcu(cis_node, &g_local_cis_list, link) {
		if (cis_node->receiver_id == receiver_id) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

static int uvb_polling_window(struct uvb_window_description *wd, struct uvb_win_desc_map *uwdm)
{
	int err = -EAGAIN;
	bool found;
	u32 receiver_id, message_id;
	struct uvb_window *window = NULL;
	struct cis_message msg = { 0 };
	msg_handler func;

	window = (struct uvb_window *)uwdm->map_address;
	if (!window) {
		pr_err("polling window failed to map window addr\n");
		return -ENOMEM;
	}
	receiver_id = window->receiver_id;
	message_id = window->message_id;

	if (window->receiver_id) {
		pr_debug("UVB window address: %llx\n", wd->address);
		pr_debug("Version              = %08x\n", window->version);
		pr_debug("Message ID           = %08x\n", window->message_id);
		pr_debug("Sender ID            = %08x\n", window->sender_id);
		pr_debug("Receiver ID          = %08x\n", window->receiver_id);
		pr_debug("Forwarder ID         = %08x\n", window->forwarder_id);
		pr_debug("Input Data Address   = %llx\n", window->input_data_address);
		pr_debug("Input Data Size      = %08x\n", window->input_data_size);
		pr_debug("Output Data Address  = %llx\n", window->output_data_address);
		pr_debug("Output Data Size     = %08x\n", window->output_data_size);
		pr_debug("Returned Status      = %08x\n", window->returned_status);
		pr_debug("Buffer = %llx, size = %08x\n", wd->buffer, wd->size);
	}

	found = search_local_receiver_id(receiver_id);
	if (found) {
		pr_debug("polling window start for callid=%08x, receiverid=%08x\n",
				message_id, receiver_id);
		window->receiver_id = 0;
		/* get input data and check */
		err = uvb_get_input_data(window, uwdm->map_buffer, wd->size, &msg);
		if (err) {
			uvb_return_status(window, err);
			return -EINVAL;
		}
		func = search_local_cis_func(message_id, receiver_id);
		if (func) {
			err = func(&msg);
			if (!err && msg.output && msg.p_output_size && *msg.p_output_size)
				window->output_data_checksum =
					checksum32(msg.output, *msg.p_output_size);
			if (err)
				err = -EPERM;
		} else {
			pr_err("polling window not found local cis func for callid=%08x, receiverid=%08x\n",
					message_id, receiver_id);
			err = -EOPNOTSUPP;
		}
		pr_info("polling window execute local cis func success\n");
		uvb_return_status(window, err);
		return err;
	/* need uvb to forward */
	} else if (window->forwarder_id == UBIOS_MY_USER_ID) {
		pr_info("cis call forward start\n");
		window->forwarder_id = 0;

		err = uvb_get_input_data(window, uwdm->map_buffer, wd->size, &msg);
		if (err) {
			uvb_return_status(window, err);
			return -EINVAL;
		}
		err = cis_call_remote(message_id, UBIOS_MY_USER_ID, receiver_id, &msg, false);
		if (!err && msg.output && msg.p_output_size && *msg.p_output_size)
			window->output_data_checksum =
				checksum32(msg.output, *msg.p_output_size);
		pr_info("cis call forward end\n");
		uvb_return_status(window, err);
		return err;
	}

	return err;
}

int uvb_poll_window(void *data)
{
	int i, j;
	struct uvb *uvb;
	struct uvb_win_desc_map *entry;

	while (!kthread_should_stop()) {
		for (i = 0; i < g_uvb_info->uvb_count; i++) {
			uvb = g_uvb_info->uvbs[i];
			if (!uvb)
				continue;

			if (uvb->window_count == 0)
				continue;

			for (j = 0; j < uvb->window_count; j++) {
				entry = find_uvb_win_desc_map(uvb->wd[j].address);
				if (!entry) {
					pr_err("poll window not found uvb desc entry\n");
					continue;
				}
				uvb_polling_window(&uvb->wd[j], entry);
			}

		}
		msleep(1);
	}

	return 0;
}

int uvb_polling_sync(void *data)
{
	int i, j;
	int index;
	int err;
	struct uvb *uvb;
	struct uvb_win_desc_map *entry;

	for (index = 0; index < UVB_POLL_TIMEOUT_TIMES; index++) {
		for (i = 0; i < g_uvb_info->uvb_count; i++) {
			uvb = g_uvb_info->uvbs[i];
			if (!uvb)
				continue;

			if (uvb->window_count == 0)
				continue;

			for (j = 0; j < uvb->window_count; j++) {
				entry = find_uvb_win_desc_map(uvb->wd[j].address);
				if (!entry) {
					pr_err("poll window not found uvb desc entry\n");
					continue;
				}
				err = uvb_polling_window(&uvb->wd[j], entry);
				if (err == -EAGAIN)
					continue;
				if (err)
					pr_err("uvb poll sync failed,err=%d\n", err);
				return err;
			}
		}
		udelay(UVB_POLL_TIME_INTERVAL);
	}

	pr_err("uvb polling sync timeout occurred after 1s\n");

	return -ETIMEDOUT;
}
EXPORT_SYMBOL(uvb_polling_sync);


