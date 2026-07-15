// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: Sentry Msg Helper
 * Author: Luckky
 * Create: 2025-02-17
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/ratelimit.h>

#include "smh_message.h"

static DEFINE_RATELIMIT_STATE(msg_log_rs, HZ, 10);

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][message_helper]: " fmt

#define RM_LOG_INFO(fmt, ...)	\
	do {	\
		if (__ratelimit(&msg_log_rs)) {	\
			printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__);	\
		}	\
	} while (0)


#define RM_LOG_WARN(fmt, ...)	\
	do {	\
		if (__ratelimit(&msg_log_rs)) {	\
			printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__);	\
		}	\
	} while (0)

#define RM_LOG_ERR(fmt, ...)	\
	do {	\
		if (__ratelimit(&msg_log_rs)) {	\
			printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__);	\
		}	\
	} while (0)

#define SMH_MESSAGE_BUFFER_LENGTH	256
#define SMH_MESSAGE_BUFFER_MAX_LENGTH	4096


static int smh_message_buffer_length = SMH_MESSAGE_BUFFER_LENGTH;
module_param(smh_message_buffer_length, int, 0444);

/**
 * FIND_AND_REMOVE_TIMEOUT_FROM_LIST - Macro to find and remove message from list
 * @handle: Pointer to store found handle
 * @lock: Spinlock to protect the list
 * @list_head: List head to search
 * @member: List member name in the structure
 * @msgid_target: Target message ID to find
 * @found: Boolean to indicate if message was found
 *
 * This macro searches for a message in the list by ID, removes timeout messages,
 * and returns the found message handle.
 */
#define FIND_AND_REMOVE_TIMEOUT_FROM_LIST(handle, lock, list_head, member, msgid_target, found) \
	do { \
		spin_lock(lock); \
		{ \
			typeof(handle) __cur, __tmp; \
			list_for_each_entry_safe(__cur, __tmp, list_head, member) { \
				if (check_msg_is_timeout(&__cur->msg)) { \
					list_del(&__cur->member); \
					kfree(__cur); \
					handle = NULL; \
					continue; \
				} \
				if (__cur->msg.msgid == (msgid_target)) { \
					found = true; \
					list_del(&__cur->member); \
					handle = __cur; \
					break; \
				} \
			} \
		} \
		spin_unlock(lock); \
	} while (0)

struct smh_msg_handler {
	struct sentry_msg_helper_msg msg;
	bool ack;
	struct list_head ack_list;
	struct list_head get_list;
};

struct smh_msg_ctx {
	struct kfifo msgbuf_send;
	spinlock_t msgbuf_send_lock;

	struct list_head msgbuf_ack;
	spinlock_t msgbuf_ack_lock;

	struct list_head msgbuf_get;
	spinlock_t msgbuf_get_lock;

	struct wait_queue_head user_wq;
};

static struct smh_msg_ctx msg_ctx;
static atomic64_t message_id_generator; /* [1, message_id_generator] */

/**
 * smh_get_new_msg_id - Generate a new unique message ID
 *
 * Return: New message ID
 */
uint64_t smh_get_new_msg_id(void)
{
	return atomic64_inc_return(&message_id_generator);
}
EXPORT_SYMBOL(smh_get_new_msg_id);

/**
 * check_msg_is_timeout - Check if message has timed out
 * @msg: Message to check
 *
 * Return: true if timeout, false otherwise
 */
static bool check_msg_is_timeout(struct sentry_msg_helper_msg *msg)
{
	uint64_t now = ktime_get_ns();
	uint64_t interval_time = (now - msg->start_send_time) / NSEC_PER_MSEC;

	return interval_time > msg->timeout_time;
}

/**
 * smh_message_send - Send a message through the message helper
 * @msg: Message to send
 * @ack: Whether acknowledgment is required
 *
 * Return: 0 on success, negative error code on failure
 */
int smh_message_send(struct sentry_msg_helper_msg *msg, bool ack)
{
	int ret = 0;
	struct smh_msg_handler *handle;

	if (!msg) {
		pr_err("%s: Invalid param, failed to send data\n", __func__);
		return -EINVAL;
	}

	if (!msg->msgid) {
		RM_LOG_ERR("please set the correct msgid by 'smh_get_new_msg_id', stop to send this msg\n");
		return -EINVAL;
	}

	handle = kzalloc(sizeof(*handle), GFP_ATOMIC);
	if (!handle) {
		RM_LOG_ERR("failed to alloc message handle\n");
		return -ENOMEM;
	}

	handle->msg = *msg;
	handle->ack = ack;

	RM_LOG_INFO("%s: %llu start\n", __func__, msg->msgid);

	ret = kfifo_in_spinlocked(&msg_ctx.msgbuf_send, &handle,
				  sizeof(handle), &msg_ctx.msgbuf_send_lock);
	if (!ret) {
		RM_LOG_ERR("error sending message %llu: buffer is full; message dropped\n",
		       msg->msgid);
		kfree(handle);
		return -EAGAIN;
	}

	/* Check if someone is waiting */
	if (waitqueue_active(&msg_ctx.user_wq))
		wake_up(&msg_ctx.user_wq);

	RM_LOG_INFO("%s: %llu end\n", __func__, msg->msgid);

	return 0;
}
EXPORT_SYMBOL(smh_message_send);

/**
 * smh_message_get - Get a message from the message helper
 * @buf: User space buffer to copy message to
 *
 * Return: Number of bytes copied on success, negative error code on failure
 */
ssize_t smh_message_get(void __user *buf)
{
	int ret;
	ssize_t msg_size;
	struct smh_msg_handler *handle = NULL;
	struct smh_msg_handler *handle_ack;
	DEFINE_WAIT(wait);

	if (waitqueue_active(&msg_ctx.user_wq)) {
		RM_LOG_WARN("another process is waiting for message\n");
		return -EPERM;
	}

	do {
		ret = kfifo_out_spinlocked(&msg_ctx.msgbuf_send, &handle,
					   sizeof(handle), &msg_ctx.msgbuf_send_lock);
		if (ret) {
			if (check_msg_is_timeout(&handle->msg)) {
				RM_LOG_INFO("%s: %llu timeout\n", __func__, handle->msg.msgid);
				kfree(handle);
				handle = NULL;
				continue;
			}
			break;
		}

		add_wait_queue_exclusive(&msg_ctx.user_wq, &wait);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&msg_ctx.user_wq, &wait);
		if (signal_pending(current)) {
			RM_LOG_ERR("error reading message: process receive signal\n");
			return -ERESTART;
		}
	} while (1);

	if (!handle)
		return -ENOMSG;

	RM_LOG_INFO("%s: get msg, msgid is %llu\n", __func__, handle->msg.msgid);

	ret = copy_to_user(buf, &handle->msg, sizeof(handle->msg));
	if (ret) {
		RM_LOG_ERR("%s: failed to copy message to user: %d\n", __func__, ret);
		ret = kfifo_in_spinlocked(&msg_ctx.msgbuf_send, &handle,
					  sizeof(handle), &msg_ctx.msgbuf_send_lock);
		if (!ret) {
			RM_LOG_ERR("error recover message %llu: buffer is full; message dropped\n",
			       handle->msg.msgid);
			kfree(handle);
			return -EFAULT;
		}
		return -EAGAIN;
	}

	msg_size = sizeof(handle->msg);
	if (handle->ack) {
		bool found = false;

		spin_lock(&msg_ctx.msgbuf_ack_lock);
		list_for_each_entry(handle_ack, &msg_ctx.msgbuf_ack, ack_list) {
			if (handle_ack->msg.msgid == handle->msg.msgid) {
				found = true;
				break;
			}
		}
		if (!found)
			list_add_tail(&handle->ack_list, &msg_ctx.msgbuf_ack);
		else
			kfree(handle);
		spin_unlock(&msg_ctx.msgbuf_ack_lock);
	} else {
		kfree(handle);
	}

	return msg_size;
}

/**
 * smh_message_ack - Acknowledge a message
 * @msg: Message to acknowledge
 *
 * Return: 0 on success, negative error code on failure
 */
int smh_message_ack(struct sentry_msg_helper_msg *msg)
{
	struct smh_msg_handler *handle;
	bool found = false;

	RM_LOG_INFO("%s: %llu\n", __func__, msg->msgid);

	FIND_AND_REMOVE_TIMEOUT_FROM_LIST(handle, &msg_ctx.msgbuf_ack_lock,
					  &msg_ctx.msgbuf_ack, ack_list,
					  msg->msgid, found);

	if (!found) {
		RM_LOG_ERR("%s: %llu not found, maybe this msg is not exist or has been timeout\n",
			__func__, msg->msgid);
		return -ENOENT;
	}

	handle->msg.res = msg->res;

	spin_lock(&msg_ctx.msgbuf_get_lock);
	list_add_tail(&handle->get_list, &msg_ctx.msgbuf_get);
	spin_unlock(&msg_ctx.msgbuf_get_lock);

	return 0;
}

/**
 * smh_message_get_ack - Get acknowledgment for a message
 * @msg: Message to get acknowledgment for
 *
 * Return: 1 if acknowledgment found, 0 otherwise
 */
int smh_message_get_ack(struct sentry_msg_helper_msg *msg)
{
	struct smh_msg_handler *handle;
	bool found = false;

	if (!msg) {
		pr_err("%s: Invalid param, failed to get data\n", __func__);
		return found;
	}

	FIND_AND_REMOVE_TIMEOUT_FROM_LIST(handle, &msg_ctx.msgbuf_get_lock,
					  &msg_ctx.msgbuf_get, get_list,
					  msg->msgid, found);

	if (found) {
		msg->res = handle->msg.res;
		kfree(handle);
	}

	return found;
}
EXPORT_SYMBOL(smh_message_get_ack);

/**
 * smh_message_init - Initialize the message helper subsystem
 *
 * Return: 0 on success, negative error code on failure
 */
int smh_message_init(void)
{
	int ret;

	if (smh_message_buffer_length <= 0 ||
	    smh_message_buffer_length > SMH_MESSAGE_BUFFER_MAX_LENGTH) {
		RM_LOG_ERR("invalid smh_message_buffer_length\n");
		return -EINVAL;
	}

	ret = kfifo_alloc(&msg_ctx.msgbuf_send,
			  sizeof(struct smh_msg_handler *) * smh_message_buffer_length,
			  GFP_KERNEL);
	if (ret < 0) {
		RM_LOG_ERR("error allocating send message buffer: %d\n", ret);
		return ret;
	}
	spin_lock_init(&msg_ctx.msgbuf_send_lock);

	INIT_LIST_HEAD(&msg_ctx.msgbuf_ack);
	spin_lock_init(&msg_ctx.msgbuf_ack_lock);

	INIT_LIST_HEAD(&msg_ctx.msgbuf_get);
	spin_lock_init(&msg_ctx.msgbuf_get_lock);

	init_waitqueue_head(&msg_ctx.user_wq);
	atomic64_set(&message_id_generator, 0);

	return 0;
}

/**
 * smh_message_exit - Cleanup the message helper subsystem
 */
void smh_message_exit(void)
{
	int ret;
	struct smh_msg_handler *handle, *tmp;

	/* Clean up acknowledgment list */
	spin_lock(&msg_ctx.msgbuf_ack_lock);
	list_for_each_entry_safe(handle, tmp, &msg_ctx.msgbuf_ack, ack_list) {
		list_del(&handle->ack_list);
		kfree(handle);
	}
	spin_unlock(&msg_ctx.msgbuf_ack_lock);

	/* Clean up get list */
	spin_lock(&msg_ctx.msgbuf_get_lock);
	list_for_each_entry_safe(handle, tmp, &msg_ctx.msgbuf_get, get_list) {
		list_del(&handle->get_list);
		kfree(handle);
	}
	spin_unlock(&msg_ctx.msgbuf_get_lock);

	do {
		ret = kfifo_out_spinlocked(&msg_ctx.msgbuf_send, &handle,
				sizeof(handle), &msg_ctx.msgbuf_send_lock);
		if (ret) {
			kfree(handle);
			continue;
		}
		break;
	} while (1);
	kfifo_free(&msg_ctx.msgbuf_send);
}
