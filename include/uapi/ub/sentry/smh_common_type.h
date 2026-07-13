/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 */

#ifndef SMH_COMMON_TYPE_H
#define SMH_COMMON_TYPE_H

#include <ub/ubus/ub_memory_event.h>
#include <linux/types.h>

#define SMH_TYPE ('}')
#define EID_MAX_LEN 40 /* eid str len 39 + '\0' */
#define OOM_EVENT_MAX_NUMA_NODES 8

/* ---- version query response ---- */
struct smh_version_info {
	__u32 major;
	__u32 minor;
};

/* ---- ioctl infrastructure ---- */
enum {
	SMH_CMD_MSG_ACK = 0x10,
	SMH_CMD_VERSION_CHECK = 0x11,
};

#define SMH_MSG_ACK _IO(SMH_TYPE, SMH_CMD_MSG_ACK)
#define SMH_VERSION_CHECK  _IOR(SMH_TYPE, SMH_CMD_VERSION_CHECK, struct smh_version_info)

/* ---- message types (enum values are the ABI) ---- */
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
	SMH_MESSAGE_LINK_EVENT,
	SMH_MESSAGE_UNKNOWN,
};

/* ---- the primary kernel↔userspace data structure ---- */
struct sentry_msg_helper_msg {
	__u64 msgid;
	__u64 start_send_time;
	__u64 timeout_time;
	enum sentry_msg_helper_msg_type type;
	union {
		struct {
			int nr_nid;
			int nid[OOM_EVENT_MAX_NUMA_NODES];
			int sync;
			int timeout;
			int reason;
		} oom_info;
		struct {
			__u32 cna;
			char eid[EID_MAX_LEN];
		} remote_info;
		struct {
			__u64 pa;
			int mem_type;
			int fault_with_kill;
			enum ras_err_type raw_ubus_mem_err_type;
		} ub_mem_info;
		struct {
			__u16 port_id;
			unsigned int scna;
			int link_event;
		} link_info;
	} helper_msg_info;
	unsigned long res;
};
#endif
