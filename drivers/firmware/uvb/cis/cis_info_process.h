/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: cis info process header
 * Author: zhangrui
 * Create: 2025-04-18
 */

#ifndef CIS_INFO_PROCESS_H
#define CIS_INFO_PROCESS_H

#include "cis_uvb_interface.h"

#define CIS_USAGE_UVB                    2
#define MAX_UVB_DESC_BITS                8
#define UVB_POLL_TIME_INTERVAL           (100)                  /* 100us */
#define UVB_POLL_TIMEOUT                 (1200)                 /* 1200ms */
#define UVB_TIMEOUT_WINDOW_OBTAIN        (10000)                /* 10000us */
#define UVB_POLL_TIMEOUT_TIMES           (10000)                /* 10000 times */

extern struct list_head  g_local_cis_list;

struct udfi_para {
	u32 message_id;
	u32 sender_id;
	u32 receiver_id;
	u32 forwarder_id;
	void *input;
	u32 input_size;
	void *output;
	u32 *output_size;
};

struct cis_func_node {
	struct list_head link;
	u32 call_id;
	u32 receiver_id;
	msg_handler func;
};

struct uvb_win_desc_map {
	atomic_t lock;
	u64 window_address;
	struct hlist_node node;
	void *map_buffer;   //wd->buffer memremap addr
	void *map_obtain;    //wd->obtain memremap addr
	void *map_address;  //wd->address memremap addr
};

int cis_call_remote(u32 call_id, u32 sender_id, u32 receiver_id,
					struct cis_message *msg,
					bool is_sync);
msg_handler search_local_cis_func(u32 call_id, u32 receiver_id);

static inline u32 ubios_get_user_type(u32 user_id)
{
	return user_id & UBIOS_USER_TYPE_MASK;
}
static inline u32 ubios_get_user_index(u32 user_id)
{
	return user_id & UBIOS_USER_INDEX_MASK;
}

#endif
