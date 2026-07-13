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
#include <linux/firmware/uvb/cis.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/inet.h>
#include <uapi/ub/sentry/smh_common_type.h>


#define MAX_DIE_NUM 2
#define MAX_NODE_NUM 32
#define CNA_MAX_VALUE 0xffffff
#define INTEGER_TO_STR_MAX_LEN 22
#define COMM_PARM_NOT_SET (-2)
// return value for urma_send(ack) msg
#define URMA_ACK_SUCCESS 1

enum SENTRY_REMOTE_COMM_TYPE {
	COMM_TYPE_URMA,
	COMM_TYPE_UVB,
	COMM_TYPE_UNKNOWN
};

struct child_thread_process_data {
	struct sentry_msg_helper_msg *msg;
	enum SENTRY_REMOTE_COMM_TYPE comm_type;
	uint32_t random_id;
	int node_idx;
	struct work_struct work;
};

struct node_msg_private_data {
	uint32_t random_id;
	uint64_t start_send_time;
	uint64_t msgid;
	bool work_pending;
};

struct sentry_remote_context {
	struct node_msg_private_data node_msg_info[MAX_NODE_NUM];
	struct sentry_msg_helper_msg remote_event_ack_msg_buf;
	atomic_t remote_event_ack_received;
	atomic_t remote_event_ack_done;
	struct task_struct *urma_receiver_thread;
	struct workqueue_struct *sentry_msg_wq;
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

extern spinlock_t sentry_buf_lock;
extern struct sentry_remote_context sentry_remote_ctx;
// sentry urma global variable and functions
extern bool g_is_created_ubcore_resource;

// urma communication interface
int urma_send(const struct sentry_binary_msg *buf, const char *dst_eid, int die_index);
int urma_recv(struct sentry_binary_msg *buf_arr, size_t array_size);

// UVB communication interface
int uvb_send(const struct sentry_binary_msg *str, uint32_t dst_cna, bool is_sync);

int cis_ubios_remote_msg_cb(struct cis_message *cis_msg);

// sentry uvb global variable
extern uint32_t g_server_cna_array[MAX_NODE_NUM];
extern int g_server_cna_valid_num;
extern uint32_t g_local_cna;
#define UVB_SENDER_ID_SYSSENTRY_INDEX (g_local_cna)
#define UVB_SENDER_ID_SYSSENTRY (UBIOS_USER_ID_RICH_OS | UVB_SENDER_ID_SYSSENTRY_INDEX)
#define UVB_RECEIVER_ID_SYSSENTRY(cna) (UBIOS_USER_ID_UB_DEVICE | (cna))

int sentry_panic_reporter_init(void);
void sentry_panic_reporter_exit(void);

// sentry uvb comm init/exit
int sentry_uvb_comm_init(void);
void sentry_uvb_comm_exit(void);

// sentry urma comm init/exit
int sentry_urma_comm_init(void);
void sentry_urma_comm_exit(void);

int send_msg_to_userspace_and_ack(struct sentry_msg_helper_msg *msg, enum SENTRY_REMOTE_COMM_TYPE comm_type,
		uint32_t random_id, enum sentry_msg_helper_msg_type ack_type);

void write_ack_msg_buf(const struct sentry_msg_helper_msg *msg, enum SENTRY_REMOTE_COMM_TYPE comm_type);
int create_kthread_to_process_msg(const struct sentry_binary_msg *event_msg,
				  enum SENTRY_REMOTE_COMM_TYPE comm_type);
enum sentry_msg_helper_msg_type get_ack_type(enum sentry_msg_helper_msg_type event_type);

void set_urma_panic_mode(bool is_panic);
int str_to_eid(const char *buf, union ubcore_eid *eid);
int ubcore_eid_to_str_full(const union ubcore_eid *eid, char *dst_eid_str, int len);
int match_index_by_remote_ub_eid(union ubcore_eid remote_id, int *node_index, int *die_index);
int sentry_create_urma_resource(union ubcore_eid eid[], int eid_num);
int process_multi_eid_string(char *eid_buf, char eid_array[][EID_MAX_LEN],
		union ubcore_eid eid_tmp[], const char *sepstr, int eid_max_num);
int convert_binary_to_smh_msg(const struct sentry_binary_msg *binary_msg,
		struct sentry_msg_helper_msg *smh_msg,
		uint32_t *random_id);

/*
 * Return 1 when buf is valid ipv4 format, return 0 when buf is invalid ipv4 format
 * or any error occurs.
 *
 */
static inline int is_valid_ipv4(const char *buf)
{
	int ret;
	__be32 addr;

	if (buf == NULL)
		return 0;

	ret = in4_pton(buf, strnlen(buf, EID_MAX_LEN), (u8 *)&addr, '\0', NULL);
	return ret;
}
#endif
