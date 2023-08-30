/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __RPG_MSG_CHAN_H__
#define __RPG_MSG_CHAN_H__

#include <linux/printk.h>

/*
 * struct phys_channel_ops - Channel physical layer ops
 * @open: Open the communication channel of node nid and alloc physical resources,
 *        returns the channel ID
 * @notify: Notify peer of chan_id to receive messages
 * @copy_to: Copy the msg_data message from origin to peer
 * @copy_from: Copy the msg_data message from peer to origin
 * @close: Close channel and free physical resources
 */
struct phys_channel_ops {
	char *name;
	int (*open)(int nid);
	int (*notify)(int chan_id);
	int (*copy_to)(int chan_id, void *msg_data, size_t msg_len, int flags);
	int (*copy_from)(int chan_id, void *buf, size_t len, int flags);
	int (*migrate_page)(void *peer_addr, struct page *local_page, size_t size, int dir);
	int (*close)(int chan_id);
};

int msg_layer_install_phy_ops(struct phys_channel_ops *ops, int default_chan_id);
int msg_layer_uninstall_phy_ops(struct phys_channel_ops *ops);

#define log_err(fmt, ...)	pr_err("[%s:%d]" fmt, __func__, __LINE__, ##__VA_ARGS__)
#define log_info(fmt, ...)	pr_info("[%s:%d]" fmt, __func__, __LINE__, ##__VA_ARGS__)

#define MSG_CMD_START		0x1
#define MSG_CMD_IRQ_END		0x2
#define MSG_CMD_FIFO_NO_MEM	0x3
#define MSG_CMD_CHANN_OPEN	0x4

#define CHAN_STAT_ENABLE	1
#define CHAN_STAT_DISABLE	0

#define TO_PEER			0
#define FROM_PEER		1

#endif
