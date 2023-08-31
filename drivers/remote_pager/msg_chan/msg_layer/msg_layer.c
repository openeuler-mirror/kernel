// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generalized Memory Management.
 *
 * Copyright (c) 2023- Huawei, Inc.
 * Author: Chunsheng Luo
 * Co-Author: Jiangtian Feng, Jun Chen
 */
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "msg_layer.h"

#define MAX_NUM_NODES	16
#define MSG_SLEEP_MIN	2
#define MSG_SLEEP_MAX	3

/* Per-node handle */
struct sock_handle {
	int nid;
	int status;
	int chan_id;
	struct task_struct *recv_handler;
};

static struct sock_handle sock_handles[MAX_NUM_NODES];
static struct phys_channel_ops *g_phys_chan_ops;

int msg_send(int chan_id, void *msg_data, size_t msg_len)
{
	int ret = 0;

	if (!g_phys_chan_ops)
		return -ENOENT;

	ret = g_phys_chan_ops->copy_to(chan_id, msg_data, msg_len, 1);
	ret |= g_phys_chan_ops->notify(chan_id);

	return ret;
}

static inline int build_msg(int type, int from_nid, int to_nid, void *msg_data, size_t msg_len)
{
	struct rpg_kmsg_message *msg = (struct rpg_kmsg_message *)msg_data;

	msg->header.type = type;
	msg->header.prio = RPG_KMSG_PRIO_NORMAL;
	msg->header.size = msg_len;
	msg->header.from_nid = from_nid;
	msg->header.to_nid = to_nid;

	return 0;
}

int msg_send_nid(int type, int from_nid, int to_nid, void *msg_data, size_t msg_len)
{
	struct sock_handle *sh = sock_handles + to_nid;

	build_msg(type, from_nid, to_nid, msg_data, msg_len);

	return msg_send(sh->chan_id, msg_data, msg_len);
}
EXPORT_SYMBOL(msg_send_nid);

int msg_recv(int chan_id, void *buf, size_t len)
{
	if (!g_phys_chan_ops)
		return -ENOENT;

	return g_phys_chan_ops->copy_from(chan_id, buf, len, 1);
}

extern int handle_remote_pager_work(void *msg);
static int recv_handler(void *arg)
{
	struct sock_handle *sh = arg;

	log_info("RECV handler for %d is ready ha %ld\n", sh->nid, sizeof(struct rpg_kmsg_hdr));

	while (!kthread_should_stop()) {
		size_t len;
		int ret;
		size_t offset;
		struct rpg_kmsg_hdr header;
		char *data = NULL;
		size_t msg_len = 0;

		/* compose header */
		offset = 0;
		len = sizeof(header);
		while (len > 0) {
			ret = msg_recv(sh->chan_id, (char *)(&header) + offset, len);
			if (ret == -ENOENT) {
				pr_err("no msg chan failed\n");
				usleep_range(MSG_SLEEP_MIN, MSG_SLEEP_MAX);
				break;
			}

			if ((ret == -1) || kthread_should_stop())
				return 0;

			offset += ret;
			len -= ret;
		}

		if (ret < 0)
			break;

		msg_len = header.size;
		if (!msg_len) {
			pr_err("msg_len is zero failed? from_nid %d prio:%d type:%d size:%ld\n",
					header.from_nid, header.prio, header.type, header.size);
			continue;
		}

		/* compose body */
		data = kmalloc(msg_len, GFP_KERNEL);
		BUG_ON(!data && "Unable to alloc a message");
		memcpy(data, &header, sizeof(header));

		offset = sizeof(header);
		len = msg_len - offset;

		while (len > 0) {
			ret = msg_recv(sh->chan_id, data + offset, len);
			if (ret == -1 || kthread_should_stop())
				return 0;

			offset += ret;
			len -= ret;
		}

		if (ret < 0)
			break;

		/* Call pcn_kmsg upper layer */
		handle_remote_pager_work(data);
	}

	return 0;
}

int msg_open(int nid)
{
	int chan_id = 0;
	struct sock_handle *sh = sock_handles + nid;
	struct task_struct *tsk_recv;

	if (sh->status == MSG_CHAN_ENABLE) {
		pr_err("node:%d msg chan is enabled\n", nid);
		return 0;
	}

	if (!g_phys_chan_ops)
		return -ENOENT;

	chan_id = g_phys_chan_ops->open(nid);
	if (chan_id < 0) {
		log_err("open msg channel failed %d\n", chan_id);
		return chan_id;
	}

	tsk_recv = kthread_run(recv_handler, sock_handles + nid, "remote-pager-recv");
	if (IS_ERR(tsk_recv)) {
		log_err("Cannot create %s handler, %ld\n", "remote-pager-recv", PTR_ERR(tsk_recv));
		return PTR_ERR(tsk_recv);
	}

	sh->chan_id = chan_id;
	sh->status = MSG_CHAN_ENABLE;
	sh->nid = nid;
	sh->recv_handler = tsk_recv;

	pr_err("%s chanid %d\n", __func__, chan_id);

	return chan_id;
}
EXPORT_SYMBOL(msg_open);

int msg_close(int nid)
{
	struct sock_handle *sh = sock_handles + nid;

	/* TODO: Get sock_handle, then set sock_handle disable and destroy recv task */
	if (sh->status != MSG_CHAN_ENABLE) {
		pr_err("node:%d msg chan is disabled\n", nid);
		return 0;
	}

	if (sh->recv_handler) {
		kthread_stop(sh->recv_handler);
		sh->recv_handler = NULL;
	}

	if (g_phys_chan_ops)
		g_phys_chan_ops->close(sh->chan_id);

	sh->chan_id = 0;
	sh->status = MSG_CHAN_DISABLE;

	return 0;
}
EXPORT_SYMBOL(msg_close);

int handle_migrate_page(void *peer_addr, struct page *local_page, size_t size, int dir)
{
	if (!g_phys_chan_ops)
		return -ENOENT;

	return g_phys_chan_ops->migrate_page(peer_addr, local_page, size, dir);
}
EXPORT_SYMBOL(handle_migrate_page);

static DEFINE_SPINLOCK(install_lock);
static int default_msg_chan_id;
int msg_layer_install_phy_ops(struct phys_channel_ops *ops, int default_chan_id)
{
	int ret = 0;

	if (!ops) {
		pr_err("install NULL as msg channel\n");
		return -EINVAL;
	}

	spin_lock(&install_lock);
	if (g_phys_chan_ops) {
		ret = -EEXIST;
		pr_err("phy_ops areadly be installed\n");
		goto unlock;
	}

	/* must before msg_open */
	g_phys_chan_ops = ops;
	if (default_chan_id >= 0) {
		ret = msg_open(default_chan_id);
		if (ret) {
			pr_err("can not open msg channel %d\n", default_chan_id);
			g_phys_chan_ops = NULL;
			goto unlock;
		}
	}

	default_msg_chan_id = default_chan_id;

unlock:
	spin_unlock(&install_lock);
	return ret;
}
EXPORT_SYMBOL(msg_layer_install_phy_ops);

int msg_layer_uninstall_phy_ops(struct phys_channel_ops *ops)
{
	if (!ops || ops != g_phys_chan_ops) {
		pr_err("Invalid phy_ops\n");
		return -EINVAL;
	}

	spin_lock(&install_lock);
	if (default_msg_chan_id >= 0)
		msg_close(default_msg_chan_id);

	g_phys_chan_ops = NULL;
	default_msg_chan_id = -1;
	spin_unlock(&install_lock);

	return 0;
}
EXPORT_SYMBOL(msg_layer_uninstall_phy_ops);
MODULE_LICENSE("GPL");
