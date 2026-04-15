// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: Server module, used for reporting panic or reboot msg to the
 *              userspace and forward ack msg to the client
 * Author: sxt1001
 * Create: 2025-03-18
 */

#include <acpi/button.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/string.h>

#include "smh_message.h"
#include "sentry_remote_reporter.h"

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][remote server]: " fmt

struct sentry_remote_context sentry_remote_ctx;
DEFINE_SPINLOCK(sentry_buf_lock);

static DEFINE_MUTEX(sentry_msg_info_mutex);

/**
 * send_msg_to_userspace - Send message to userspace with proper tracking
 * @msg: Message to send
 * @comm_type: Communication type (URMA or UVB)
 * @random_id: Random identifier for message tracking
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function sends a message to userspace and tracks it using node message
 * info for acknowledgment handling.
 */
int send_msg_to_userspace(struct sentry_msg_helper_msg *msg, union ubcore_eid dst_eid,
			  enum SENTRY_REMOTE_COMM_TYPE comm_type, uint32_t random_id)
{
	int ret;
	int node_idx = -1;
	int die_index = -1;

	pr_info("send %s message to userspace\n",
		comm_type == COMM_TYPE_URMA ? "urma" : "uvb");

	if (comm_type == COMM_TYPE_URMA) {
		match_index_by_remote_ub_eid(dst_eid, &node_idx, &die_index);
	} else if (comm_type == COMM_TYPE_UVB) {
		int i;

		for (i = 0; i < g_server_cna_valid_num; i++) {
			if (msg->helper_msg_info.remote_info.cna == g_server_cna_array[i]) {
				node_idx = i;
				break;
			}
		}
	}

	if (node_idx < 0) {
		pr_err("Invalid cna: %u or eid: %s of msg, stop to send to userspace\n",
		       msg->helper_msg_info.remote_info.cna,
		       msg->helper_msg_info.remote_info.eid);
		return -EINVAL;
	}

	mutex_lock(&sentry_msg_info_mutex);
	if (sentry_remote_ctx.node_msg_info_list[node_idx].random_id != random_id) {
		pr_info("Get new message from cna: %u, eid: %s\n",
			msg->helper_msg_info.remote_info.cna,
			msg->helper_msg_info.remote_info.eid);
		sentry_remote_ctx.node_msg_info_list[node_idx].start_send_time = ktime_get_ns();
		sentry_remote_ctx.node_msg_info_list[node_idx].msgid = smh_get_new_msg_id();
		sentry_remote_ctx.node_msg_info_list[node_idx].random_id = random_id;
	}
	msg->start_send_time = sentry_remote_ctx.node_msg_info_list[node_idx].start_send_time;
	msg->msgid = sentry_remote_ctx.node_msg_info_list[node_idx].msgid;
	mutex_unlock(&sentry_msg_info_mutex);

	ret = smh_message_send(msg, true);
	return ret;
}

/**
 * send_msg_to_userspace_and_ack - Send message to userspace and wait for acknowledgment
 * @msg: Message to send
 * @comm_type: Communication type (URMA or UVB)
 * @random_id: Random identifier for message tracking
 * @ack_type: Type of acknowledgment expected
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function sends a message to userspace, waits for acknowledgment, and
 * sends acknowledgment back to the remote node.
 */
int send_msg_to_userspace_and_ack(struct sentry_msg_helper_msg *msg,
				  enum SENTRY_REMOTE_COMM_TYPE comm_type,
				  uint32_t random_id, enum sentry_msg_helper_msg_type ack_type)
{
	int ret;
	int times = msg->timeout_time / MILLISECONDS_OF_EACH_MDELAY;
	int i, j;
	union ubcore_eid dst_ubcore_eid;

	if (str_to_eid(msg->helper_msg_info.remote_info.eid, &dst_ubcore_eid) < 0) {
		pr_err("send_msg_to_userspace: invalid dst eid [%s]\n",
				msg->helper_msg_info.remote_info.eid);
		return -EINVAL;
	}

	ret = send_msg_to_userspace(msg, dst_ubcore_eid, comm_type, random_id);
	if (ret) {
		pr_err("Failed to send remote message to userspace\n");
		return ret;
	}

	/* Wait for acknowledgment from userspace */
	for (i = 0; i < times; i++) {
		uint64_t cur_time = ktime_get_ns();

		ret = smh_message_get_ack(msg);
		if (!ret) {
			int sleep_time = MILLISECONDS_OF_EACH_MDELAY -
					(int)((ktime_get_ns() - cur_time) / NSEC_PER_MSEC);
			if (sleep_time > 0)
				msleep_interruptible(sleep_time);
			continue;
		}

		/* Get acknowledgment success, send acknowledgment message */
		struct sentry_binary_msg binary_ack = {0};

		binary_ack.type = ack_type;
		binary_ack.cna = msg->helper_msg_info.remote_info.cna;
		binary_ack.eid = dst_ubcore_eid;
		binary_ack.res = msg->res;

		pr_info("Start to send %s ack msg to %u\n",
			comm_type == COMM_TYPE_URMA ? "urma" : "uvb",
			msg->helper_msg_info.remote_info.cna);

		if (comm_type == COMM_TYPE_URMA) {
			/* Retry URMA acknowledgment sending */
			for (j = 0; j < URMA_ACK_RETRY_NUM; j++) {
				ret = urma_send(&binary_ack,
						msg->helper_msg_info.remote_info.eid, -1);
				if (ret == COMM_PARM_NOT_SET)
					break;
				msleep_interruptible(MILLISECONDS_OF_EACH_MDELAY);
			}
		} else {
			/* UVB is a reliable protocol, no need to resend */
			ret = uvb_send(&binary_ack,
				msg->helper_msg_info.remote_info.cna, false);
		}

		if (ret <= 0) {
			pr_warn("Failed to send %s ack message to client (cna:%u, eid:%s)\n",
				comm_type == COMM_TYPE_URMA ? "urma" : "uvb",
				msg->helper_msg_info.remote_info.cna,
				msg->helper_msg_info.remote_info.eid);
			return -EFAULT;
		}
		return 0;
	}

	return -ETIMEDOUT;
}

/**
 * get_ack_type - Get acknowledgment type for given event type
 * @event_type: Event type to get acknowledgment for
 *
 * Return: Corresponding acknowledgment type
 */
enum sentry_msg_helper_msg_type get_ack_type(enum sentry_msg_helper_msg_type event_type)
{
	enum sentry_msg_helper_msg_type ack_type;

	switch (event_type) {
	case SMH_MESSAGE_PANIC:
		ack_type = SMH_MESSAGE_PANIC_ACK;
		break;
	case SMH_MESSAGE_KERNEL_REBOOT:
		ack_type = SMH_MESSAGE_KERNEL_REBOOT_ACK;
		break;
	default:
		pr_warn("Invalid event type!\n");
		ack_type = SMH_MESSAGE_UNKNOWN;
	}

	return ack_type;
}

/**
 * process_remote_event_msg - Process remote event message in kernel thread context
 * @data: Pointer to child_thread_process_data structure containing message info
 *
 * Return: 0 on success, negative error code on failure
 */
static int process_remote_event_msg(void *data)
{
	int ret;
	enum sentry_msg_helper_msg_type ack_type;
	struct child_thread_process_data *child_data = data;

	try_module_get(THIS_MODULE);

	ack_type = get_ack_type(child_data->msg->type);
	if (ack_type == SMH_MESSAGE_UNKNOWN) {
		ret = -EINVAL;
		goto cleanup_child;
	}

	ret = send_msg_to_userspace_and_ack(child_data->msg, child_data->comm_type,
					    child_data->random_id, ack_type);

cleanup_child:
	kfree(child_data->msg);
	kfree(child_data);
	module_put(THIS_MODULE);
	return ret;
}

/**
 * write_ack_msg_buf - Write acknowledgment message to shared buffer
 * @msg: Acknowledgment message
 * @comm_type: Communication type (URMA or UVB)
 *
 * This function writes an acknowledgment message to a shared buffer for
 * inter-process communication, ensuring thread-safe access.
 */
void write_ack_msg_buf(const struct sentry_msg_helper_msg *msg,
		       enum SENTRY_REMOTE_COMM_TYPE comm_type)
{
	if (atomic_inc_return(&sentry_remote_ctx.remote_event_ack_received) == 1) {
		pr_info("Receive ack message from %s: [%d_%u_%s_%lu]. Start to update buf\n",
			comm_type == COMM_TYPE_URMA ? "URMA" : "UVB",
			msg->type,
			msg->helper_msg_info.remote_info.cna,
			msg->helper_msg_info.remote_info.eid,
			msg->res);

		spin_lock(&sentry_buf_lock);
		memcpy(&sentry_remote_ctx.remote_event_ack_msg_buf, msg,
		       sizeof(sentry_remote_ctx.remote_event_ack_msg_buf));
		spin_unlock(&sentry_buf_lock);
		atomic_set(&sentry_remote_ctx.remote_event_ack_done, 1);
	}
}

/**
 * convert_binary_to_smh_msg - Convert a raw binary message to an SMH helper message
 * @binary_msg: Pointer to the incoming binary message structure
 * @smh_msg: Pointer to the output SMH helper message structure to fill
 * @random_id: Pointer to store extracted random ID for certain message types
 *
 * Return: 0 on success, negative error code on failure:
 *         -EINVAL if any input pointer is NULL or message type is unsupported.
 */
int convert_binary_to_smh_msg(const struct sentry_binary_msg *binary_msg,
			 struct sentry_msg_helper_msg *smh_msg,
			 uint32_t *random_id)
{
	if (!binary_msg || !smh_msg || !random_id)
		return -EINVAL;

	smh_msg->type = binary_msg->type;
	smh_msg->helper_msg_info.remote_info.cna = binary_msg->cna;

	int ret = ubcore_eid_to_str_full(&binary_msg->eid,
			smh_msg->helper_msg_info.remote_info.eid,
			EID_MAX_LEN);
	if (ret) {
		pr_err("%s: covert ubcore eid to string failed\n", __func__);
		return -EINVAL;
	}

	switch (binary_msg->type) {
	case SMH_MESSAGE_PANIC:
	case SMH_MESSAGE_KERNEL_REBOOT:
		smh_msg->timeout_time = binary_msg->timeout_ms;
		*random_id = binary_msg->random_id;
		break;
	case SMH_MESSAGE_PANIC_ACK:
	case SMH_MESSAGE_KERNEL_REBOOT_ACK:
		smh_msg->res = binary_msg->res;
		break;
	default:
		pr_err("%s: invalid msg type\n", __func__);
		return -EINVAL;
	}
	return 0;
}

/**
 * create_kthread_to_process_msg - Create kernel thread to process incoming message
 * @event_msg: Raw event message string
 * @comm_type: Communication type (URMA or UVB)
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function creates a kernel thread to process incoming remote messages,
 * handling both panic/reboot events and acknowledgment messages.
 */
int create_kthread_to_process_msg(const struct sentry_binary_msg *event_msg,
				  enum SENTRY_REMOTE_COMM_TYPE comm_type)
{
	int ret;
	struct sentry_msg_helper_msg msg = {0};
	uint32_t random_id;
	struct child_thread_process_data *child_data;
	struct task_struct *child_thread;

	ret = convert_binary_to_smh_msg(event_msg, &msg, &random_id);
	if (ret) {
		pr_err("convert %s binary data: to smh msg failed\n",
		       comm_type == COMM_TYPE_URMA ? "urma" : "uvb");
		return -EINVAL;
	}

	if (msg.type != SMH_MESSAGE_PANIC && msg.type != SMH_MESSAGE_KERNEL_REBOOT) {
		/* Write acknowledgment message to shared memory */
		write_ack_msg_buf(&msg, comm_type);
		return 0;
	}

	child_data = kzalloc(sizeof(*child_data), GFP_KERNEL);
	if (!child_data) {
		pr_err("Failed to allocate memory for child_data\n");
		return -ENOMEM;
	}

	child_data->msg = kzalloc(sizeof(*child_data->msg), GFP_KERNEL);
	if (!child_data->msg) {
		kfree(child_data);
		pr_err("Failed to allocate memory for child_data->msg\n");
		return -ENOMEM;
	}

	/* Update child thread data */
	memcpy(child_data->msg, &msg, sizeof(*child_data->msg));
	child_data->random_id = random_id;
	child_data->comm_type = comm_type;

	child_thread = kthread_run(process_remote_event_msg, child_data,
				   "sentry_msg_thread_%s_%u",
				   comm_type == COMM_TYPE_URMA ? "urma" : "uvb",
				   random_id);
	if (IS_ERR(child_thread)) {
		kfree(child_data->msg);
		kfree(child_data);
		pr_err("Failed to create child thread\n");
		return PTR_ERR(child_thread);
	}

	return 0;
}

/**
 * process_urma_data - Process URMA data in kernel thread
 * @data: Thread data (unused)
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function runs in a kernel thread to receive and process URMA messages,
 * creating separate threads for message processing.
 */
static int process_urma_data(void *data)
{
	int ret = 0;
	int recv_msg_nodes = 0;
	struct sentry_binary_msg *binary_msg_array;
	int i;

	binary_msg_array = kmalloc_array(MAX_NODE_NUM * MAX_DIE_NUM,
			sizeof(struct sentry_binary_msg), GFP_KERNEL);
	if (!binary_msg_array)
		return -ENOMEM;

	while (!kthread_should_stop()) {
		/* Listen for URMA messages */
		recv_msg_nodes = urma_recv(binary_msg_array, MAX_NODE_NUM * MAX_DIE_NUM);
		if (recv_msg_nodes <= 0) {
			/*
			 * Prevent processes from entering the D state if reboot event
			 * occurs on the current node
			 */
			msleep_interruptible(MILLISECONDS_OF_EACH_MDELAY);
			continue;
		}

		pr_info("urma messages are received, the number of nodes that are successfully received is %d\n",
			recv_msg_nodes);

		for (i = 0; i < recv_msg_nodes; i++) {
			ret = create_kthread_to_process_msg(&binary_msg_array[i], COMM_TYPE_URMA);
			if (ret == -ENOMEM)
				goto free_msg;
		}

		/*
		 * Prevent processes from entering the D state if reboot event
		 * occurs on the current node
		 */
		msleep_interruptible(MILLISECONDS_OF_EACH_MDELAY);
	}

free_msg:
	kfree(binary_msg_array);
	pr_info("Urma receiver thread stopped!\n");
	return ret;
}

/**
 * cis_ubios_remote_msg_cb - UVB remote message callback
 * @cis_msg: CIS message from UVB
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function serves as the callback for UVB remote messages,
 * processing incoming messages through the appropriate mechanism.
 */
int cis_ubios_remote_msg_cb(struct cis_message *cis_msg)
{
	int ret;

	if (cis_msg->input_size != sizeof(struct sentry_binary_msg)) {
		pr_err("%s: invalid input size: %d, expect %lu\n",
			__func__, cis_msg->input_size, sizeof(struct sentry_binary_msg));
		return -EINVAL;
	}
	ret = create_kthread_to_process_msg((struct sentry_binary_msg *)cis_msg->input,
			COMM_TYPE_UVB);
	return ret;
}

/**
 * sentry_panic_reporter_init - Initialize sentry panic reporter module
 *
 * Return: 0 on success, negative error code on failure
 */
int sentry_panic_reporter_init(void)
{
	atomic_set(&sentry_remote_ctx.remote_event_ack_received, 0);
	atomic_set(&sentry_remote_ctx.remote_event_ack_done, 0);

	sentry_remote_ctx.urma_receiver_thread = kthread_run(process_urma_data, NULL, "sentry_urma_kthread");
	if (IS_ERR(sentry_remote_ctx.urma_receiver_thread)) {
		pr_err("Failed to create kernel urma receiver thread.\n");
		return PTR_ERR(sentry_remote_ctx.urma_receiver_thread);
	}

	pr_info("Create kernel urma receiver thread success.\n");
	return 0;
}

/**
 * sentry_panic_reporter_exit - Cleanup sentry panic reporter module
 */
void sentry_panic_reporter_exit(void)
{
	if (sentry_remote_ctx.urma_receiver_thread) {
		kthread_stop(sentry_remote_ctx.urma_receiver_thread);
		sentry_remote_ctx.urma_receiver_thread = NULL;
		pr_info("Kernel urma receiver thread stopped\n");
	}
}
