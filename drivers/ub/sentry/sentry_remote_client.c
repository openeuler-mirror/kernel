// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: Client module, used for reporting panic or reboot events.
 * Author: sxt1001
 * Create: 2025-03-18
 */

#include <asm/arch_timer.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/delay.h>
#include <linux/panic.h>
#include <linux/panic_notifier.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/reboot.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/mutex.h>

#include "smh_message.h"
#include "sentry_remote_reporter.h"

#define PANIC_TIMEOUT_MS_MIN		0
#define PANIC_TIMEOUT_MS_MAX		3600000
#define KERNEL_REBOOT_TIMEOUT_MS_MIN	0
#define KERNEL_REBOOT_TIMEOUT_MS_MAX	3600000
#define LOCAL_EID_MAX_LEN		(EID_MAX_LEN * MAX_DIE_NUM + 1 + 1)

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][remote client]: " fmt

struct sentry_client_context {
	char eid_str[MAX_DIE_NUM][EID_MAX_LEN];
	char eid_raw_str[LOCAL_EID_MAX_LEN]; /* for proc show */
	union ubcore_eid eid[MAX_DIE_NUM];
	int die_num_configured;

	struct proc_dir_entry *panic_proc_dir;
	struct sentry_binary_msg *msg_array;

	unsigned long panic_timeout_ms;
	unsigned long kernel_reboot_timeout_ms;

	bool panic_enable;
	bool kernel_reboot_enable;
	bool use_uvb;
	bool use_urma;

	bool is_in_panic_status;

	uint32_t random_id;

	bool is_uvb_cis_func_registered;
};

static struct sentry_client_context sentry_client_ctx = {
	.die_num_configured = MAX_DIE_NUM,
	.panic_timeout_ms = 35000,
	.kernel_reboot_timeout_ms = 35000,
	.panic_enable = false,
	.kernel_reboot_enable = false,
	.use_uvb = true,
	.use_urma = true,
	.is_in_panic_status = false,
	.random_id = 0,
	.is_uvb_cis_func_registered = false,
};

/**
 * strcmp_local_eid_from_msg - Compare message EID with local EIDs
 * @msg_eid: EID from message to compare
 *
 * Return: true if EID matches a local EID, false otherwise
 *
 * This function checks if the provided EID matches any of the
 * configured local EIDs.
 */
static bool strcmp_local_eid_from_msg(const char *msg_eid)
{
	for (int i = 0; i < sentry_client_ctx.die_num_configured; i++) {
		if (strlen(sentry_client_ctx.eid_str[i]) == 0) {
			pr_err("local_eid should have %d values, but %d-th value is empty\n",
			       sentry_client_ctx.die_num_configured, i);
			break;
		}
		if (strncmp(msg_eid, sentry_client_ctx.eid_str[i], EID_MAX_LEN) == 0)
			return true;
	}
	return false;
}

/**
 * get_ack_done - Check if acknowledgment is complete for local node
 * @msg: Message to check
 * @ack_type: Expected acknowledgment type
 * @comm_type: Communication type
 *
 * Return: true if acknowledgment is complete, false otherwise
 *
 * This function verifies if the received acknowledgment message
 * matches the expected parameters for the local node.
 */
static bool get_ack_done(const struct sentry_msg_helper_msg *msg,
			 enum sentry_msg_helper_msg_type ack_type,
			 enum SENTRY_REMOTE_COMM_TYPE comm_type)
{
	if (msg->type == ack_type &&
	    msg->helper_msg_info.remote_info.cna == g_local_cna &&
	    strcmp_local_eid_from_msg(msg->helper_msg_info.remote_info.eid)) {
		pr_info("Receive ack message%s: [%d_%u_%s_%lu]\n",
			(comm_type == COMM_TYPE_URMA) ? " from URMA" :
			(comm_type == COMM_TYPE_UVB) ? " from UVB" : "",
			msg->type,
			g_local_cna,
			msg->helper_msg_info.remote_info.eid,
			msg->res);
		return true;
	}
	return false;
}

/**
 * remote_event_handler - Handle remote event sending and acknowledgment
 * @remote_type: Type of remote event
 * @timeout_ms: Timeout in milliseconds
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function handles the sending of remote events (panic/reboot) and
 * waits for acknowledgments from remote nodes, supporting both URMA and UVB.
 */
int remote_event_handler(enum sentry_msg_helper_msg_type remote_type,
			 unsigned long timeout_ms)
{
	int ret;
	bool uvb_send_success = false;
	bool urma_send_success = false;
	enum sentry_msg_helper_msg_type remote_ack_type;
	struct sentry_binary_msg send_data[MAX_DIE_NUM] = {0};
	uint64_t start_count, current_count;
	uint64_t code_run_count, code_run_times_ms;
	uint64_t counts_per_sec = arch_timer_get_cntfrq();
	uint64_t timeout_counts = timeout_ms / 1000 * counts_per_sec;
	bool ack_done = false;
	int recv_msg_nodes;
	int times = timeout_ms / MILLISECONDS_OF_EACH_MDELAY;

	/* Prepare send data for each die */
	for (int i = 0; i < sentry_client_ctx.die_num_configured; i++) {
		if (strlen(sentry_client_ctx.eid_str[i]) == 0) {
			pr_err("local_eid should have %d values, but %d-th value is empty\n",
			       sentry_client_ctx.die_num_configured, i);
			return NOTIFY_OK;
		}

		send_data[i].type = remote_type;
		send_data[i].cna = g_local_cna;
		send_data[i].eid = sentry_client_ctx.eid[i];
		send_data[i].timeout_ms = timeout_ms;
		send_data[i].random_id = sentry_client_ctx.random_id;
	}

	remote_ack_type = get_ack_type(remote_type);
	if (remote_ack_type == SMH_MESSAGE_UNKNOWN)
		return -EINVAL;

	start_count = read_sysreg(cntpct_el0);

	/* Main event sending and acknowledgment loop */
	for (int i = 0; i < times; i++) {
		current_count = read_sysreg(cntpct_el0);
		if (current_count - start_count >= timeout_counts)
			break;

		/* Send via URMA if enabled */
		if (sentry_client_ctx.use_urma) {
			for (int j = 0; j < sentry_client_ctx.die_num_configured; j++) {
				if (strlen(sentry_client_ctx.eid_str[j]) == 0)
					break;

				ret = urma_send(&send_data[j], NULL, j);
				if (ret > 0) {
					urma_send_success = true;
					pr_info("URMA send binary msg [%d]: SUCCESS. die index %d\n",
						i + 1, j);
				}
			}
		}

		/* Send via UVB if enabled */
		if (sentry_client_ctx.use_uvb) {
			ret = uvb_send(&send_data[0], -1,
				       sentry_client_ctx.is_in_panic_status ? true : false);
			if (ret > 0) {
				uvb_send_success = true;
				pr_info("UVB send data [%d]: SUCCESS\n", i + 1);
			}
		}

		/* Handle send failure */
		if (!urma_send_success && !uvb_send_success) {
			pr_warn("UVB && URMA send data: FAILED\n");
			if (sentry_client_ctx.is_in_panic_status)
				mdelay(MILLISECONDS_OF_EACH_MDELAY);
			else
				msleep(MILLISECONDS_OF_EACH_MDELAY);
			continue;
		}

		if (!sentry_client_ctx.is_in_panic_status) {
			/* Not in panic status, check shared buffer */
			if (atomic_read(&sentry_remote_ctx.remote_event_ack_done) != 1) {
				msleep(MILLISECONDS_OF_EACH_MDELAY);
				continue;
			}

			spin_lock(&sentry_buf_lock);
			ack_done = get_ack_done(&sentry_remote_ctx.remote_event_ack_msg_buf,
							remote_ack_type, COMM_TYPE_UNKNOWN);
			spin_unlock(&sentry_buf_lock);
			goto check_ack_and_sleep;
		}
		/* Handle acknowledgment in panic mode */
		if (uvb_send_success) {
			/* In panic status, UVB uses sync mode */
			void *data = NULL;
			ret = uvb_polling_sync(data);

			if (ret < 0 && ret != -ETIMEDOUT) {
				pr_err("uvb_poll_window_sync failed\n");
			} else if (ret == -ETIMEDOUT) {
				pr_info("uvb_polling_sync timeout\n");
			} else if (ret == 0) {
				/* uvb_polling_sync success */
				if (atomic_read(&sentry_remote_ctx.remote_event_ack_done) != 1)
					goto do_urma_recv;

				spin_lock(&sentry_buf_lock);
				ack_done = get_ack_done(&sentry_remote_ctx.remote_event_ack_msg_buf,
								remote_ack_type, COMM_TYPE_UVB);
				spin_unlock(&sentry_buf_lock);
			}
		}

do_urma_recv:
		if (urma_send_success) {
			/* In panic status, poll URMA directly */
			recv_msg_nodes = urma_recv(sentry_client_ctx.msg_array,
							MAX_NODE_NUM * MAX_DIE_NUM);
			if (recv_msg_nodes <= 0)
				goto check_ack_and_sleep;
			pr_info("urma received %d nodes\n", recv_msg_nodes);
			for (int l = 0; l < recv_msg_nodes; l++) {
				struct sentry_msg_helper_msg msg;
				uint32_t random_id_stub;

				/* Convert and check acknowledgment */
				ret = convert_binary_to_smh_msg(&sentry_client_ctx.msg_array[l],
								&msg, &random_id_stub);
				if (ret) {
					pr_warn("convert urma binary data failed\n");
					continue;
				}
				ack_done = get_ack_done(&msg, remote_ack_type,
							COMM_TYPE_URMA);
				if (ack_done)
					break;
			}
		}

check_ack_and_sleep:
		/* Check if acknowledgment received */
		if (ack_done) {
			pr_info("Receive ack message, stop blocking early\n");
			break;
		}

		pr_debug("No ACK for %d polling, wait %d ms\n",
				i, MILLISECONDS_OF_EACH_MDELAY);

		/* Calculate precise sleep time */
		code_run_count = read_sysreg(cntpct_el0) - current_count;
		code_run_times_ms = code_run_count * 1000 / counts_per_sec;

		if (code_run_times_ms < MILLISECONDS_OF_EACH_MDELAY) {
			int sleep_time = MILLISECONDS_OF_EACH_MDELAY - code_run_times_ms;
			if (sentry_client_ctx.is_in_panic_status)
				mdelay(sleep_time);
			else
				msleep(sleep_time);
		}
	}

	return 0;
}

/**
 * check_if_eid_cna_is_set - Check if EID and CNA are properly configured
 *
 * Return: 0 if properly configured, -EINVAL otherwise
 *
 * This function validates that both CNA and EID are properly set
 * before attempting to send remote events.
 */
static int check_if_eid_cna_is_set(void)
{
	size_t eid_len = strlen(sentry_client_ctx.eid_raw_str);

	if (g_local_cna > CNA_MAX_VALUE || eid_len == 0) {
		pr_err("cna or eid not set, ignore current event\n");
		return -EINVAL;
	}
	return 0;
}

/**
 * check_if_urma_or_uvb_is_ready - Check if URMA or UVB communication is ready
 *
 * Return: 0 if at least one communication method is ready, -ENODEV otherwise
 *
 * This function checks the availability of URMA and UVB communication
 * channels and updates the usage flags accordingly.
 */
static int check_if_urma_or_uvb_is_ready(void)
{
	if (sentry_client_ctx.use_urma && !g_is_created_ubcore_resource) {
		pr_info("URMA not ready, disable URMA communication\n");
		sentry_client_ctx.use_urma = false;
	}

	if (sentry_client_ctx.use_uvb && !(g_server_cna_valid_num > 0)) {
		pr_warn("UVB not ready, disable UVB communication\n");
		sentry_client_ctx.use_uvb = false;
	}

	if (!(sentry_client_ctx.use_urma || sentry_client_ctx.use_uvb)) {
		pr_err("both urma and uvb not connected, ignore current event\n");
		return -ENODEV;
	}

	return 0;
}

/**
 * panic_handler - Panic notifier handler
 * @nb: Notifier block
 * @code: Panic code
 * @unused: Unused parameter
 *
 * Return: NOTIFY_OK
 *
 * This function handles system panic events by sending panic notifications
 * to remote nodes and waiting for acknowledgments.
 */
int panic_handler(struct notifier_block *nb, unsigned long code, void *unused)
{
	if (!sentry_client_ctx.panic_enable)
		return NOTIFY_OK;

	sentry_client_ctx.is_in_panic_status = true;
	pr_info("Panic handler: received panic message\n");

	if (check_if_eid_cna_is_set() || check_if_urma_or_uvb_is_ready())
		return NOTIFY_OK;

	pr_info("panic_timeout_ms %lu, cna [%u], eid [%s]\n",
		sentry_client_ctx.panic_timeout_ms, g_local_cna,
		sentry_client_ctx.eid_raw_str);

	set_urma_panic_mode(true);
	remote_event_handler(SMH_MESSAGE_PANIC, sentry_client_ctx.panic_timeout_ms);
	pr_info("Panic handler: Blocking finished\n");

	return NOTIFY_OK;
}

/**
 * kernel_reboot_handler - Kernel reboot notifier handler
 * @nb: Notifier block
 * @code: Reboot code
 * @unused: Unused parameter
 *
 * Return: NOTIFY_OK
 *
 * This function handles kernel reboot events by sending reboot notifications
 * to remote nodes and waiting for acknowledgments.
 */
int kernel_reboot_handler(struct notifier_block *nb, unsigned long code, void *unused)
{
	if (!sentry_client_ctx.kernel_reboot_enable)
		return NOTIFY_OK;

	pr_info("kernel reboot handler: received kernel reboot message\n");

	if (check_if_eid_cna_is_set() || check_if_urma_or_uvb_is_ready())
		return NOTIFY_OK;

	pr_info("kernel_reboot_timeout_ms %lu, cna [%u], eid [%s]\n",
		sentry_client_ctx.kernel_reboot_timeout_ms, g_local_cna,
		sentry_client_ctx.eid_raw_str);

	set_urma_panic_mode(false);
	remote_event_handler(SMH_MESSAGE_KERNEL_REBOOT,
			     sentry_client_ctx.kernel_reboot_timeout_ms);
	pr_info("Kernel reboot handler: Blocking finished\n");

	/* Stop URMA thread proactively */
	sentry_panic_reporter_exit();
	return NOTIFY_OK;
}

/**
 * proc_panic_reporter_enable_file_show - Show panic reporter enable status
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 */
static ssize_t proc_panic_reporter_enable_file_show(struct file *file,
						    char __user *buf, size_t count, loff_t *ppos)
{
	const char *status = sentry_client_ctx.panic_enable ? "on" : "off";
	size_t len = sentry_client_ctx.panic_enable ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, status, len);
}

/**
 * proc_kernel_reboot_reporter_enable_file_show - Show kernel reboot reporter enable status
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 */
static ssize_t proc_kernel_reboot_reporter_enable_file_show(struct file *file,
							    char __user *buf, size_t count, loff_t *ppos)
{
	const char *status = sentry_client_ctx.kernel_reboot_enable ? "on" : "off";
	size_t len = sentry_client_ctx.kernel_reboot_enable ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, status, len);
}

/**
 * proc_reporter_cna_show - Show local CNA value
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 */
static ssize_t proc_reporter_cna_show(struct file *file, char __user *buf,
				      size_t count, loff_t *ppos)
{
	char cna_str[INTEGER_TO_STR_MAX_LEN];

	snprintf(cna_str, sizeof(cna_str), "%u\n", g_local_cna);
	return simple_read_from_buffer(buf, count, ppos, cna_str, strlen(cna_str));
}

/**
 * proc_reporter_eid_show - Show local EID value
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 */
static ssize_t proc_reporter_eid_show(struct file *file, char __user *buf,
				      size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos,
				       sentry_client_ctx.eid_raw_str,
				       strlen(sentry_client_ctx.eid_raw_str));
}

/**
 * proc_panic_enable_file_write - Write handler for panic enable control
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 */
static ssize_t proc_panic_enable_file_write(struct file *file, const char __user *ubuf,
					    size_t cnt, loff_t *ppos)
{
	int ret;
	char enable_str[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for panic mode, only 'off' or 'on' allowed\n");
		return -EINVAL;
	}

	ret = copy_from_user(enable_str, ubuf, cnt);
	if (ret) {
		pr_err("set panic mode failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && enable_str[cnt - 1] == '\n')
		enable_str[cnt - 1] = '\0';

	if (strcmp(enable_str, "on") == 0) {
		if (!crash_kexec_post_notifiers) {
			pr_warn("crash_kexec_post_notifiers disabled, cannot enable panic event\n");
			return -EPERM;
		}
		sentry_client_ctx.panic_enable = true;
	} else if (strcmp(enable_str, "off") == 0) {
		sentry_client_ctx.panic_enable = false;
	} else {
		pr_err("invalid value for panic mode\n");
		return -EINVAL;
	}

	pr_info("%s panic event report\n", sentry_client_ctx.panic_enable ? "enable" : "disable");
	return cnt;
}

/**
 * proc_kernel_reboot_enable_file_write - Write handler for kernel reboot enable control
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 */
static ssize_t proc_kernel_reboot_enable_file_write(struct file *file,
						    const char __user *ubuf,
						    size_t cnt, loff_t *ppos)
{
	int ret;
	char enable_str[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for kernel_reboot mode, only 'off' or 'on' allowed\n");
		return -EINVAL;
	}

	ret = copy_from_user(enable_str, ubuf, cnt);
	if (ret) {
		pr_err("set kernel_reboot mode failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && enable_str[cnt - 1] == '\n')
		enable_str[cnt - 1] = '\0';

	if (strcmp(enable_str, "on") == 0) {
		sentry_client_ctx.kernel_reboot_enable = true;
	} else if (strcmp(enable_str, "off") == 0) {
		sentry_client_ctx.kernel_reboot_enable = false;
	} else {
		pr_err("invalid value for kernel_reboot mode\n");
		return -EINVAL;
	}

	pr_info("%s kernel reboot event report\n",
		    sentry_client_ctx.kernel_reboot_enable ? "enable" : "disable");
	return cnt;
}

/**
 * proc_uvb_comm_file_show - Show UVB communication enable status
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 */
static ssize_t proc_uvb_comm_file_show(struct file *file, char __user *buf,
				       size_t count, loff_t *ppos)
{
	const char *status = sentry_client_ctx.use_uvb ? "on" : "off";
	size_t len = sentry_client_ctx.use_uvb ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, status, len);
}

/**
 * proc_urma_comm_file_show - Show URMA communication enable status
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 */
static ssize_t proc_urma_comm_file_show(struct file *file, char __user *buf,
					size_t count, loff_t *ppos)
{
	const char *status = sentry_client_ctx.use_urma ? "on" : "off";
	size_t len = sentry_client_ctx.use_urma ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, status, len);
}

/**
 * proc_uvb_comm_file_write - Write handler for UVB communication control
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 */
static ssize_t proc_uvb_comm_file_write(struct file *file, const char __user *ubuf,
					size_t cnt, loff_t *ppos)
{
	int ret;
	char enable_str[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for uvb_comm, only 'off' or 'on' allowed\n");
		return -EINVAL;
	}

	ret = copy_from_user(enable_str, ubuf, cnt);
	if (ret) {
		pr_err("set uvb_comm failed\n");
		return -EFAULT;
	}

	/* Remove trailing newline if present */
	if (cnt > 0 && enable_str[cnt - 1] == '\n')
		enable_str[cnt - 1] = '\0';

	if (strcmp(enable_str, "on") == 0) {
		sentry_client_ctx.use_uvb = true;
	} else if (strcmp(enable_str, "off") == 0) {
		if (!sentry_client_ctx.use_urma) {
			pr_err("Cannot disable both URMA and UVB comm modes\n");
			return -EINVAL;
		}
		sentry_client_ctx.use_uvb = false;
	} else {
		pr_err("invalid value for uvb_comm\n");
		return -EINVAL;
	}

	return cnt;
}

/**
 * proc_urma_comm_file_write - Write handler for URMA communication control
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 */
static ssize_t proc_urma_comm_file_write(struct file *file, const char __user *ubuf,
					 size_t cnt, loff_t *ppos)
{
	int ret;
	char enable_str[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for urma_comm, only 'off' or 'on' allowed\n");
		return -EINVAL;
	}

	ret = copy_from_user(enable_str, ubuf, cnt);
	if (ret) {
		pr_err("set urma_comm failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && enable_str[cnt - 1] == '\n')
		enable_str[cnt - 1] = '\0';

	if (strcmp(enable_str, "on") == 0) {
		sentry_client_ctx.use_urma = true;
	} else if (strcmp(enable_str, "off") == 0) {
		if (!sentry_client_ctx.use_uvb) {
			pr_err("Cannot disable both URMA and UVB comm modes\n");
			return -EINVAL;
		}
		sentry_client_ctx.use_urma = false;
	} else {
		pr_err("invalid value for urma_comm\n");
		return -EINVAL;
	}

	return cnt;
}

/**
 * proc_panic_timeout_show - Show panic timeout value
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 */
static ssize_t proc_panic_timeout_show(struct file *file, char __user *buf,
				       size_t count, loff_t *ppos)
{
	char timeout_str[INTEGER_TO_STR_MAX_LEN];

	snprintf(timeout_str, sizeof(timeout_str), "%ld\n",
		 sentry_client_ctx.panic_timeout_ms);
	return simple_read_from_buffer(buf, count, ppos, timeout_str, strlen(timeout_str));
}

/**
 * proc_kernel_reboot_timeout_show - Show kernel reboot timeout value
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 */
static ssize_t proc_kernel_reboot_timeout_show(struct file *file, char __user *buf,
					       size_t count, loff_t *ppos)
{
	char timeout_str[INTEGER_TO_STR_MAX_LEN];

	snprintf(timeout_str, sizeof(timeout_str), "%ld\n",
		 sentry_client_ctx.kernel_reboot_timeout_ms);
	return simple_read_from_buffer(buf, count, ppos, timeout_str, strlen(timeout_str));
}

/**
 * proc_reporter_cna_write - Write handler for CNA configuration
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 */
static ssize_t proc_reporter_cna_write(struct file *file, const char __user *ubuf,
				       size_t cnt, loff_t *ppos)
{
	int ret;
	uint32_t val;

	ret = kstrtou32_from_user(ubuf, cnt, 10, &val);
	if (ret) {
		pr_err("parse input parameter for cna failed\n");
		return ret;
	}

	if (val > CNA_MAX_VALUE) {
		pr_err("set cna failed, max value is %u\n", CNA_MAX_VALUE);
		return -EINVAL;
	}

	if (sentry_client_ctx.is_uvb_cis_func_registered) {
		/* Repeated registration will fail, unregister first */
		unregister_local_cis_func(UBIOS_CALL_ID_PANIC_CALL, UBIOS_USER_ID_UB_DEVICE);
	}

	ret = register_local_cis_func(UBIOS_CALL_ID_PANIC_CALL, UBIOS_USER_ID_UB_DEVICE,
				      cis_ubios_remote_msg_cb);
	if (ret) {
		pr_err("uvb register function failed\n");
		return ret;
	}

	sentry_client_ctx.is_uvb_cis_func_registered = true;
	g_local_cna = val;
	return cnt;
}

/**
 * proc_reporter_eid_write - Write handler for EID configuration
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 */
static ssize_t proc_reporter_eid_write(struct file *file, const char __user *ubuf,
				       size_t cnt, loff_t *ppos)
{
	int ret;
	int eid_num = 0;
	char eid_str_buf[LOCAL_EID_MAX_LEN] = {0};
	char eid_str_buf_tmp[LOCAL_EID_MAX_LEN] = {0};
	char eid_str_array[MAX_DIE_NUM][EID_MAX_LEN] = {0};
	union ubcore_eid eid_ub_buf[MAX_DIE_NUM] = {0};

	if (cnt > LOCAL_EID_MAX_LEN) {
		pr_err("invalid eid info, max len %d, actual %lu\n",
		       LOCAL_EID_MAX_LEN - 1, cnt);
		return -EINVAL;
	}

	ret = copy_from_user(eid_str_buf, ubuf, cnt);
	if (ret) {
		pr_err("set eid failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && eid_str_buf[cnt - 1] == '\n')
		eid_str_buf[cnt - 1] = '\0';

	if (cnt == LOCAL_EID_MAX_LEN && eid_str_buf[cnt - 1] != '\0') {
		pr_err("invalid eid info, max len %d, actual %lu\n",
		       LOCAL_EID_MAX_LEN - 1, cnt);
		return -EINVAL;
	}

	memcpy(eid_str_buf_tmp, eid_str_buf, LOCAL_EID_MAX_LEN);
	ret = process_multi_eid_string(eid_str_buf_tmp, eid_str_array, eid_ub_buf,
				       ";", MAX_DIE_NUM);
	if (ret < 0)
		return ret;

	eid_num = ret;
	ret = sentry_create_urma_resource(eid_ub_buf, eid_num);
	if (ret)
		return ret;

	/* Valid EID, update global EID */
	for (int i = 0; i < eid_num; i++) {
		memcpy(&sentry_client_ctx.eid[i], &eid_ub_buf[i],
		       sizeof(union ubcore_eid));
		snprintf(sentry_client_ctx.eid_str[i], EID_MAX_LEN, "%s",
			 eid_str_array[i]);
	}

	sentry_client_ctx.die_num_configured = eid_num;
	memcpy(sentry_client_ctx.eid_raw_str, eid_str_buf, LOCAL_EID_MAX_LEN);
	return cnt;
}

/**
 * proc_panic_timeout_write - Write handler for panic timeout configuration
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 */
static ssize_t proc_panic_timeout_write(struct file *file, const char __user *ubuf,
					size_t cnt, loff_t *ppos)
{
	int ret;
	unsigned long val;

	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);
	if (ret) {
		pr_err("invalid value for panic_timeout\n");
		return ret;
	}

	if (val < PANIC_TIMEOUT_MS_MIN || val > PANIC_TIMEOUT_MS_MAX) {
		pr_err("panic_timeout range [%d, %d], current %lu\n",
		       PANIC_TIMEOUT_MS_MIN, PANIC_TIMEOUT_MS_MAX, val);
		return -EINVAL;
	}

	sentry_client_ctx.panic_timeout_ms = val;
	return cnt;
}

/**
 * proc_kernel_reboot_timeout_write - Write handler for kernel reboot timeout configuration
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 */
static ssize_t proc_kernel_reboot_timeout_write(struct file *file,
						const char __user *ubuf,
						size_t cnt, loff_t *ppos)
{
	int ret;
	unsigned long val;

	ret = kstrtoul_from_user(ubuf, cnt, 10, &val);
	if (ret) {
		pr_err("parse input parameter for kernel_reboot_timeout failed\n");
		return ret;
	}

	if (val < KERNEL_REBOOT_TIMEOUT_MS_MIN || val > KERNEL_REBOOT_TIMEOUT_MS_MAX) {
		pr_err("kernel_reboot_timeout range [%d, %d], current %lu\n",
		       KERNEL_REBOOT_TIMEOUT_MS_MIN, KERNEL_REBOOT_TIMEOUT_MS_MAX, val);
		return -EINVAL;
	}

	sentry_client_ctx.kernel_reboot_timeout_ms = val;
	return cnt;
}

/* Proc file operations structures */
static const struct proc_ops proc_reporter_cna_file_operations = {
	.proc_read  = proc_reporter_cna_show,
	.proc_write = proc_reporter_cna_write,
};

static const struct proc_ops proc_reporter_eid_file_operations = {
	.proc_read  = proc_reporter_eid_show,
	.proc_write = proc_reporter_eid_write,
};

static const struct proc_ops proc_panic_enable_file_operations = {
	.proc_read  = proc_panic_reporter_enable_file_show,
	.proc_write = proc_panic_enable_file_write,
};

static const struct proc_ops proc_kernel_reboot_enable_file_operations = {
	.proc_read  = proc_kernel_reboot_reporter_enable_file_show,
	.proc_write = proc_kernel_reboot_enable_file_write,
};

static const struct proc_ops proc_uvb_comm_file_operations = {
	.proc_read  = proc_uvb_comm_file_show,
	.proc_write = proc_uvb_comm_file_write,
};

static const struct proc_ops proc_urma_comm_file_operations = {
	.proc_read  = proc_urma_comm_file_show,
	.proc_write = proc_urma_comm_file_write,
};

static const struct proc_ops proc_panic_timeout_file_operations = {
	.proc_read  = proc_panic_timeout_show,
	.proc_write = proc_panic_timeout_write,
};

static const struct proc_ops proc_kernel_reboot_timeout_file_operations = {
	.proc_read  = proc_kernel_reboot_timeout_show,
	.proc_write = proc_kernel_reboot_timeout_write,
};

/**
 * init_sentry_remote_reporter_proc - Initialize proc filesystem entries
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function creates all proc filesystem entries for the remote reporter
 * module, allowing user-space configuration of various parameters.
 */
static int init_sentry_remote_reporter_proc(void)
{
	int ret = 0;

	sentry_client_ctx.panic_proc_dir = proc_mkdir_mode("sentry_remote_reporter",
							   PROC_DIR_PERMISSION, NULL);
	if (!sentry_client_ctx.panic_proc_dir) {
		pr_err("create /proc/sentry_remote_reporter dir failed\n");
		return -ENOMEM;
	}

	ret |= sentry_create_proc_file("cna", sentry_client_ctx.panic_proc_dir,
				       &proc_reporter_cna_file_operations);
	ret |= sentry_create_proc_file("eid", sentry_client_ctx.panic_proc_dir,
				       &proc_reporter_eid_file_operations);
	ret |= sentry_create_proc_file("panic_timeout", sentry_client_ctx.panic_proc_dir,
				       &proc_panic_timeout_file_operations);
	ret |= sentry_create_proc_file("kernel_reboot_timeout",
				       sentry_client_ctx.panic_proc_dir,
				       &proc_kernel_reboot_timeout_file_operations);
	ret |= sentry_create_proc_file("panic", sentry_client_ctx.panic_proc_dir,
				       &proc_panic_enable_file_operations);
	ret |= sentry_create_proc_file("kernel_reboot", sentry_client_ctx.panic_proc_dir,
				       &proc_kernel_reboot_enable_file_operations);
	ret |= sentry_create_proc_file("uvb_comm", sentry_client_ctx.panic_proc_dir,
				       &proc_uvb_comm_file_operations);
	ret |= sentry_create_proc_file("urma_comm", sentry_client_ctx.panic_proc_dir,
				       &proc_urma_comm_file_operations);
	if (ret < 0)
		proc_remove(sentry_client_ctx.panic_proc_dir);

	return ret;
}

/* Notifier blocks for system events */
static struct notifier_block panic_notifier = {
	.notifier_call = panic_handler,
	.priority = INT_MAX,
};

static struct notifier_block kernel_reboot_notifier = {
	.notifier_call = kernel_reboot_handler,
	.priority = INT_MAX,
};

/**
 * sentry_remote_reporter_init - Module initialization function
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function initializes the remote reporter module, including:
 * - Generating random ID
 * - Initializing panic reporter
 * - Allocating message buffers
 * - Registering system notifiers
 * - Creating proc filesystem entries
 */
static int __init sentry_remote_reporter_init(void)
{
	int ret;

	sentry_client_ctx.random_id = get_random_u32();

	ret = sentry_panic_reporter_init();
	if (ret)
		return ret;

	sentry_client_ctx.msg_array = kmalloc_array(MAX_NODE_NUM * MAX_DIE_NUM,
			sizeof(struct sentry_binary_msg),
			GFP_KERNEL);
	if (!sentry_client_ctx.msg_array) {
		pr_err("Failed to allocate memory for msg_array\n");
		ret = -ENOMEM;
		goto stop_kthread;
	}

	ret = register_reboot_notifier(&kernel_reboot_notifier);
	if (ret) {
		pr_err("Failed to register kernel reboot handler: %d\n", ret);
		goto free_msg_array;
	}
	pr_info("Kernel reboot handler registered\n");

	ret = atomic_notifier_chain_register(&panic_notifier_list, &panic_notifier);
	if (ret) {
		pr_err("Failed to register panic handler: %d\n", ret);
		goto unregister_kernel_reboot;
	}

	ret = init_sentry_remote_reporter_proc();
	if (ret) {
		pr_err("Failed to create sentry_remote_reporter proc: %d\n", ret);
		goto unregister_panic;
	}

	pr_info("Panic handler registered\n");
	return 0;

unregister_panic:
	atomic_notifier_chain_unregister(&panic_notifier_list, &panic_notifier);
unregister_kernel_reboot:
	unregister_reboot_notifier(&kernel_reboot_notifier);
free_msg_array:
	kfree(sentry_client_ctx.msg_array);
stop_kthread:
	sentry_panic_reporter_exit();
	return ret;
}

/**
 * sentry_remote_reporter_exit - Module cleanup function
 *
 * This function cleans up all resources allocated by the remote reporter module,
 * including unregistering notifiers, freeing memory, and removing proc entries.
 */
static void __exit sentry_remote_reporter_exit(void)
{
	atomic_notifier_chain_unregister(&panic_notifier_list, &panic_notifier);
	pr_info("Panic handler unregistered\n");

	unregister_reboot_notifier(&kernel_reboot_notifier);
	pr_info("Kernel reboot handler unregistered\n");

	kfree(sentry_client_ctx.msg_array);

	if (sentry_client_ctx.panic_proc_dir)
		proc_remove(sentry_client_ctx.panic_proc_dir);

	sentry_panic_reporter_exit();

	if (sentry_client_ctx.is_uvb_cis_func_registered) {
		unregister_local_cis_func(UBIOS_CALL_ID_PANIC_CALL, UBIOS_USER_ID_UB_DEVICE);
		pr_info("UVB CIS function unregistered\n");
	}
}

module_init(sentry_remote_reporter_init);
module_exit(sentry_remote_reporter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sxt1001");
MODULE_DESCRIPTION("sentry_remote_reporter module");
MODULE_VERSION("1.0");
