// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/kthread.h>
#include <net/sock.h>

#include "common/driver.h"

#define QPTS_ELEMENT_MAX_NUM    0x8000 /* 32k */
#define QPTS_UDS_ABSTRACT_NAME  "xsc_qpts_socket"
#define QPTS_UDS_RCV_BUFF_SIZE  0x80000 /* 512K */

static struct xsc_qpt_update_msg *g_ring_buff;
static DEFINE_MUTEX(g_ring_buff_lock);
static unsigned long R;
static unsigned long R_cur;
static unsigned long W;

static struct socket *g_server_sock;
static struct socket *g_client_sock;
static struct task_struct *g_uds_thread;
static DECLARE_WAIT_QUEUE_HEAD(g_uds_wait);

static int read_buff(struct xsc_qpt_update_msg *msg)
{
	int ret = 0;

	mutex_lock(&g_ring_buff_lock);
	if (R_cur != W) {
		*msg = g_ring_buff[R_cur];
		R_cur = (R_cur + 1) % QPTS_ELEMENT_MAX_NUM;
		ret = 1;
	}
	mutex_unlock(&g_ring_buff_lock);

	return ret;
}

static void write_buff(struct xsc_qpt_update_msg *msg)
{
	mutex_lock(&g_ring_buff_lock);
	g_ring_buff[W] = *msg;
	W = (W + 1) % QPTS_ELEMENT_MAX_NUM;
	if (R == W)
		R = (R + 1) % QPTS_ELEMENT_MAX_NUM;
	if (R_cur == W)
		R_cur = (R_cur + 1) % QPTS_ELEMENT_MAX_NUM;
	mutex_unlock(&g_ring_buff_lock);

	wake_up_interruptible(&g_uds_wait);
}

static void clear_buff(void)
{
	mutex_lock(&g_ring_buff_lock);
	W = 0;
	R = 0;
	R_cur = 0;
	mutex_unlock(&g_ring_buff_lock);
}

int qpts_write_one_msg(struct xsc_qpt_update_msg *msg)
{
	if (!msg)
		return -EINVAL;

	write_buff(msg);
	return 0;
}
EXPORT_SYMBOL(qpts_write_one_msg);

static void set_socket_rcvbuf(struct socket *sock, int size)
{
	struct sock *sk = sock->sk;

	sock_set_rcvbuf(sk, size * 2);
}

static int uds_server_thread(void *data)
{
	int ret;
	char c;
	struct xsc_qpt_update_msg msg_buf;
	struct kvec iov;
	struct msghdr msghdr = {.msg_flags = MSG_DONTWAIT};
	struct socket *new_client = NULL;

	pr_info("qpts: UDS thread started\n");

	while (!kthread_should_stop()) {
		ret = kernel_accept(g_server_sock, &new_client, SOCK_NONBLOCK);
		if (!ret) {
			if (!g_client_sock) {
				set_socket_rcvbuf(new_client, QPTS_UDS_RCV_BUFF_SIZE);
				g_client_sock = new_client;
				clear_buff();
				pr_info("qpts: UDS client connected\n");
			} else {
				sock_release(new_client);
				pr_info("qpts: Rejected extra UDS client\n");
			}
		} else {
			if (ret != -ERESTARTSYS && ret != -EINTR && ret != -EAGAIN)
				pr_err("qpts: kernel_accept error %d\n", ret);

			if (!g_client_sock) {
				msleep_interruptible(100);
				continue;
			}
		}

		if (g_client_sock) {
			iov.iov_base = &c;
			iov.iov_len = 1;

			/* Check if the existing client is still active */
			ret = kernel_recvmsg(g_client_sock, &msghdr, &iov,
					     1, 1, MSG_PEEK | MSG_DONTWAIT);
			if (ret == 0 || (ret < 0 && ret != -EAGAIN)) {
				sock_release(g_client_sock);
				g_client_sock = NULL;
				pr_info("qpts: UDS client disconnected, closing client\n");
			}
		}

		ret = wait_event_interruptible_timeout(g_uds_wait,
						       (R_cur != W && g_client_sock) ||
						       kthread_should_stop(),
						       msecs_to_jiffies(1000));
		if (kthread_should_stop())
			break;

		if (ret <= 0)
			continue;

		if (g_client_sock && R_cur != W) {
			ret = read_buff(&msg_buf);
			if (ret <= 0)
				continue;

			iov.iov_base = &msg_buf;
			iov.iov_len = sizeof(msg_buf);

			ret = kernel_sendmsg(g_client_sock, &msghdr, &iov, 1,
					     sizeof(msg_buf));
			if (ret <= 0) {
				pr_err("qpts:send failed %d, %u qp %u ts %llu %02x:%02x.%01x\n",
				       ret, msg_buf.type, msg_buf.data.qpn,
				       msg_buf.data.timestamp, msg_buf.data.bus,
				       msg_buf.data.dev, msg_buf.data.fun);
			}
		}
	}

	if (g_client_sock) {
		sock_release(g_client_sock);
		g_client_sock = NULL;
	}

	return 0;
}

int qpts_init(void)
{
	struct sockaddr_un addr;
	int ret, addrlen, namelen;

	g_ring_buff = kcalloc(QPTS_ELEMENT_MAX_NUM,
			      sizeof(struct xsc_qpt_update_msg), GFP_KERNEL);
	if (!g_ring_buff)
		return -ENOMEM;

	ret = sock_create(PF_UNIX, SOCK_STREAM, 0, &g_server_sock);
	if (ret < 0) {
		pr_err("qpts: sock_create_kern failed %d\n", ret);
		goto err_free_ring;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	namelen = strlen(QPTS_UDS_ABSTRACT_NAME);
	if (namelen < sizeof(addr.sun_path) - 1) {
		addr.sun_path[0] = '\0';
		memcpy(addr.sun_path + 1, QPTS_UDS_ABSTRACT_NAME, namelen);
	}
	addrlen = offsetof(struct sockaddr_un, sun_path) + 1 +
		  strlen(QPTS_UDS_ABSTRACT_NAME);

	ret = kernel_bind(g_server_sock, (struct sockaddr *)&addr, addrlen);
	if (ret < 0) {
		pr_err("qpts: kernel_bind failed %d\n", ret);
		goto err_release_server;
	}

	ret = kernel_listen(g_server_sock, 1);
	if (ret < 0) {
		pr_err("qpts: kernel_listen failed %d\n", ret);
		goto err_release_server;
	}

	g_uds_thread = kthread_run(uds_server_thread, NULL, "qpts_uds");
	if (IS_ERR(g_uds_thread)) {
		pr_err("qpts: kthread_run failed %ld\n", PTR_ERR(g_uds_thread));
		ret = PTR_ERR(g_uds_thread);
		goto err_release_server;
	}

	return 0;

err_release_server:
	sock_release(g_server_sock);
	g_server_sock = NULL;
err_free_ring:
	kfree(g_ring_buff);
	g_ring_buff = NULL;
	return ret;
}

void qpts_fini(void)
{
	/* Wait for the thread to completely exit */
	if (g_uds_thread) {
		wake_up_interruptible(&g_uds_wait);
		kthread_stop(g_uds_thread);
		g_uds_thread = NULL;
	}

	if (g_server_sock) {
		sock_release(g_server_sock);
		g_server_sock = NULL;
	}

	kfree(g_ring_buff);
	g_ring_buff = NULL;
}

