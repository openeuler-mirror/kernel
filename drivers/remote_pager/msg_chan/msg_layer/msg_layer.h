/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Generalized Memory Management.
 *
 * Copyright (c) 2023- Huawei, Inc.
 * Author: Chunsheng Luo
 * Co-Author: Jiangtian Feng
 */
#ifndef __MSG_LAYER_H__
#define __MSG_LAYER_H__

#include <linux/string.h>
#include <linux/remote_pager/msg_chan.h>

#define RPG_KMSG_MAX_SIZE (64UL << 10)
#define RPG_KMSG_MAX_PAYLOAD_SIZE \
	(RPG_KMSG_MAX_SIZE - sizeof(struct rpg_kmsg_hdr))

/* Enumerate message priority. XXX Priority is not supported yet. */
enum rpg_kmsg_prio {
	RPG_KMSG_PRIO_LOW,
	RPG_KMSG_PRIO_NORMAL,
	RPG_KMSG_PRIO_HIGH,
};

#define MSG_CHAN_DISABLE 0
#define MSG_CHAN_ENABLE 1

struct rpg_kmsg_hdr {
	int from_nid		:6;
	int to_nid		:6;
	enum rpg_kmsg_prio prio	:2;
	int type		:8;
	size_t size;
} __packed;

struct rpg_kmsg_message {
	struct rpg_kmsg_hdr header;
	unsigned char data[RPG_KMSG_MAX_PAYLOAD_SIZE];
} __packed;

int msg_send_nid(int type, int from_nid, int to_nid, void *msg_data, size_t msg_len);
int msg_send(int chan_id, void *msg_data, size_t msg_len);
int msg_recv(int chan_id, void *buf, size_t len);
int msg_open(int nid);
int msg_close(int nid);
int handle_migrate_page(void *peer_addr, struct page *local_page, size_t size, int dir);

#endif
