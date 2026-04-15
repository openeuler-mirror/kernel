/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: Common Header File for Sentry Module
 * Author: Luckky
 * Create: 2025-02-17
 */

#ifndef SMH_COMMON_TYPE_H
#define SMH_COMMON_TYPE_H

#include <linux/firmware/uvb/cis.h>
#include <ub/ubus/ub-mem-decoder.h>
#include <ub/urma/ubcore_api.h>
#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#define SMH_TYPE ('}')
#define MAX_DIE_NUM 2
#define OOM_EVENT_MAX_NUMA_NODES 8
#define MAX_NODE_NUM 32
#define EID_MAX_LEN 40 // eid str len 39 + '\0'
#define REPORT_COMM_TIME  5000
#define MILLISECONDS_OF_EACH_MDELAY 1000
#define CNA_MAX_VALUE 0xffffff
#define INTEGER_TO_STR_MAX_LEN 22
#define COMM_PARM_NOT_SET (-2)
#define ENABLE_VALUE_MAX_LEN 4 // 'off' + '\0'

#define URMA_REBUILD_THRESHOLD 3
#define URMA_ACK_RETRY_NUM     10

#define PROC_FILE_PERMISSION 0600
#define PROC_DIR_PERMISSION 0550

enum {
    SMH_CMD_MSG_ACK = 0x10,
};

#define SMH_MSG_ACK _IO(SMH_TYPE, SMH_CMD_MSG_ACK)

enum sentry_msg_helper_msg_type {
	SMH_MESSAGE_POWER_OFF,
	SMH_MESSAGE_OOM,
	SMH_MESSAGE_PANIC,
	SMH_MESSAGE_KERNEL_REBOOT,
	SMH_MESSAGE_UB_MEM_ERR,
	SMH_MESSAGE_PANIC_ACK,
	SMH_MESSAGE_KERNEL_REBOOT_ACK,
	SMH_MESSAGE_HEARTBEAT,
	SMH_MESSAGE_HEARTBEAT_ACK,
	SMH_MESSAGE_UNKNOWN,
};

/* Must be 4-byte aligned */
struct sentry_binary_msg {
	uint32_t type;
	uint32_t cna;
	uint32_t timeout_ms;
	uint32_t random_id;
	uint32_t res;
	union ubcore_eid eid;
};

#define URMA_BINARY_MSG_MAX_LEN sizeof(struct sentry_binary_msg)

struct sentry_msg_helper_msg {
    enum sentry_msg_helper_msg_type type;
    uint64_t msgid;
    uint64_t start_send_time;
    uint64_t timeout_time;
    // reboot_info is empty
    union {
		struct {
			int nr_nid;
			int nid[OOM_EVENT_MAX_NUMA_NODES];
			int sync;
			int timeout;
			int reason;
		} oom_info;
		struct {
			uint32_t cna;
			char eid[EID_MAX_LEN];
		} remote_info;
		struct {
			uint64_t pa;
			int mem_type;
			int fault_with_kill;
			enum ras_err_type raw_ubus_mem_err_type;
		} ub_mem_info;
    } helper_msg_info;
    unsigned long res;
};

// urma communication interface
extern int urma_send(const struct sentry_binary_msg *buf, const char *dst_eid, int die_index);
extern int urma_recv(struct sentry_binary_msg *buf_arr, size_t array_size);

// UVB communication interface
extern int uvb_send(const struct sentry_binary_msg *str, uint32_t dst_cna, bool is_sync);

extern uint32_t g_local_cna;
#define UVB_SENDER_ID_SYSSENTRY_INDEX (g_local_cna)
#define UVB_SENDER_ID_SYSSENTRY (UBIOS_USER_ID_RICH_OS | UVB_SENDER_ID_SYSSENTRY_INDEX)
#define UVB_RECEIVER_ID_SYSSENTRY(cna) (UBIOS_USER_ID_UB_DEVICE | (cna))

/*
 * Return 1 when buf is valid ipv4 format, return 0 when buf is invalid ipv4 format
 * or any error occurs.
 *
*/
static inline int is_valid_ipv4(const char *buf)
{
    int ret;
    __be32 addr;

    if (buf == NULL) {
	return 0;
    }

    ret = in4_pton(buf, strnlen(buf, EID_MAX_LEN), (u8 *)&addr, '\0', NULL);
    return ret;
}

static inline int sentry_create_proc_file(const char *name, struct proc_dir_entry *parent,
					  const struct proc_ops *proc_ops)
{
    int ret = 0;

    if (!proc_create(name, PROC_FILE_PERMISSION, parent, proc_ops)) {
		pr_err("create proc file %s failed.\n", name);
		ret = -ENOMEM;
    }
    return ret;
}

/**
 * get_msg_type_name - Convert message type enum to human-readable string
 * @type: The message type enum value (sentry_msg_helper_msg_type)
 *
 * Returns a static string describing the message type. Useful for debugging
 * and logging purposes.
 *
 * Return: Pointer to a constant C string representing the message type.
 *         Returns "unknown" for unrecognized type values.
 */
static inline char *get_msg_type_name(enum sentry_msg_helper_msg_type type)
{
	switch (type) {
	case SMH_MESSAGE_PANIC:
		return "panic";
	case SMH_MESSAGE_KERNEL_REBOOT:
		return "kernel reboot";
	case SMH_MESSAGE_PANIC_ACK:
		return "panic ack";
	case SMH_MESSAGE_KERNEL_REBOOT_ACK:
		return "kernel reboot ack";
	case SMH_MESSAGE_HEARTBEAT:
		return "heartbeat";
	case SMH_MESSAGE_HEARTBEAT_ACK:
		return "heartbeat ack";
	default:
		return "unknown";
	}
}
#endif
