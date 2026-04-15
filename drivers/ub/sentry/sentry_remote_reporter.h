/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: Header File for sentry module
 * Author: sxt1001
 * Create: 2025-03-18
 */

#ifndef SENTRY_REMOTE_REPORTER_H
#define SENTRY_REMOTE_REPORTER_H

#include <ub/urma/ubcore_api.h>
#include <ub/urma/ubcore_uapi.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/types.h>

#include "smh_common_type.h"

extern void set_urma_panic_mode(bool is_panic);

// sentry uvb global variable
extern uint32_t g_server_cna_array[MAX_NODE_NUM];
extern int g_server_cna_valid_num;
extern int cis_ubios_remote_msg_cb(struct cis_message *cis_msg);

// sentry urma global variable and functions
extern bool g_is_created_ubcore_resource;
extern int str_to_eid(const char *buf, union ubcore_eid *eid);
extern int ubcore_eid_to_str_full(const union ubcore_eid *eid, char *dst_eid_str, int len);
extern int match_index_by_remote_ub_eid(union ubcore_eid remote_id, int *node_index, int *die_index);
extern int sentry_create_urma_resource(union ubcore_eid eid[], int eid_num);
extern int process_multi_eid_string(char *eid_buf, char eid_array[][EID_MAX_LEN],
    union ubcore_eid eid_tmp[], const char *sepstr, int eid_max_num);

extern int convert_binary_to_smh_msg(const struct sentry_binary_msg *binary_msg,
		struct sentry_msg_helper_msg *smh_msg,
		uint32_t *random_id);

enum SENTRY_REMOTE_COMM_TYPE {
    COMM_TYPE_URMA,
    COMM_TYPE_UVB,
    COMM_TYPE_UNKNOWN
};

struct child_thread_process_data {
    struct sentry_msg_helper_msg *msg;
    enum SENTRY_REMOTE_COMM_TYPE comm_type;
    uint32_t random_id;
};

struct node_msg_info {
	uint32_t random_id;
	uint64_t start_send_time;
	uint64_t msgid;
};

struct sentry_remote_context {
	struct node_msg_info node_msg_info_list[MAX_NODE_NUM];
	struct sentry_msg_helper_msg remote_event_ack_msg_buf;
	atomic_t remote_event_ack_received;
	atomic_t remote_event_ack_done;
	struct task_struct *urma_receiver_thread;
};

extern spinlock_t sentry_buf_lock;
extern struct sentry_remote_context sentry_remote_ctx;

int sentry_panic_reporter_init(void);
void sentry_panic_reporter_exit(void);

int send_msg_to_userspace_and_ack(struct sentry_msg_helper_msg *msg, enum SENTRY_REMOTE_COMM_TYPE comm_type,
    uint32_t random_id, enum sentry_msg_helper_msg_type ack_type);

void write_ack_msg_buf(const struct sentry_msg_helper_msg *msg, enum SENTRY_REMOTE_COMM_TYPE comm_type);
int create_kthread_to_process_msg(const struct sentry_binary_msg *event_msg,
				  enum SENTRY_REMOTE_COMM_TYPE comm_type);
enum sentry_msg_helper_msg_type get_ack_type(enum sentry_msg_helper_msg_type event_type);
#endif
