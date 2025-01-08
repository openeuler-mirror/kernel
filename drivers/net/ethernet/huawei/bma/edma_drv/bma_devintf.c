// SPDX-License-Identifier: GPL-2.0
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <asm/ioctls.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/notifier.h>
#include "../include/bma_ker_intf.h"
#include "bma_include.h"
#include "bma_devintf.h"
#include "bma_pci.h"
#include "edma_host.h"

static struct bma_dev_s *g_bma_dev;

static ATOMIC_NOTIFIER_HEAD(bma_int_notify_list);

static int bma_priv_insert_priv_list(struct bma_priv_data_s *priv, u32 type,
				     u32 sub_type)
{
	unsigned long flags = 0;
	int ret = 0;
	struct edma_user_inft_s *user_inft = NULL;

	if (type >= TYPE_MAX || !priv)
		return -EFAULT;

	user_inft = edma_host_get_user_inft(type);

	if (user_inft && user_inft->user_register) {
		ret = user_inft->user_register(priv);
		if (ret) {
			BMA_LOG(DLOG_ERROR, "register failed\n");
			return -EFAULT;
		}
	} else {
		if (!g_bma_dev)
			return -ENXIO;

		if (atomic_dec_and_test(&g_bma_dev->au_count[type]) == 0) {
			BMA_LOG(DLOG_ERROR,
				"busy, init_dev_type.type = %d, au_count = %d\n",
				type,
				atomic_read(&g_bma_dev->au_count[type]));
			atomic_inc(&g_bma_dev->au_count[type]);
			return -EBUSY;	/* already register */
		}

		priv->user.type = type;
		priv->user.sub_type = sub_type;
		priv->user.user_id = 0;

		spin_lock_irqsave(&g_bma_dev->priv_list_lock, flags);

		list_add_rcu(&priv->user.link, &g_bma_dev->priv_list);

		spin_unlock_irqrestore(&g_bma_dev->priv_list_lock, flags);
	}

	return 0;
}

static int bma_priv_delete_priv_list(struct bma_priv_data_s *priv)
{
	unsigned long flags = 0;
	struct edma_user_inft_s *user_inft = NULL;

	if (!priv || priv->user.type >= TYPE_MAX)
		return -EFAULT;
	user_inft = edma_host_get_user_inft(priv->user.type);
	if (user_inft && user_inft->user_register) {
		user_inft->user_unregister(priv);
	} else {
		if (!g_bma_dev)
			return -ENXIO;
		spin_lock_irqsave(&g_bma_dev->priv_list_lock, flags);
		list_del_rcu(&priv->user.link);
		spin_unlock_irqrestore(&g_bma_dev->priv_list_lock, flags);
		/* release the type */
		atomic_inc(&g_bma_dev->au_count[priv->user.type]);
	}
	return 0;
}

static int bma_priv_init(struct bma_priv_data_s **bma_priv)
{
	struct bma_priv_data_s *priv = NULL;

	if (!bma_priv)
		return -EFAULT;

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		BMA_LOG(DLOG_ERROR, "malloc priv failed\n");
		return -ENOMEM;
	}

	memset(priv, 0, sizeof(struct bma_priv_data_s));

	spin_lock_init(&priv->recv_msg_lock);
	INIT_LIST_HEAD(&priv->recv_msgs);
	init_waitqueue_head(&priv->wait);

	priv->user.type = TYPE_UNKNOWN;
	priv->user.sub_type = 0;
	priv->user.dma_transfer = 0;
	priv->user.seq = 0;
	priv->user.cur_recvmsg_nums = 0;
	priv->user.max_recvmsg_nums = DEFAULT_MAX_RECV_MSG_NUMS;

	*bma_priv = priv;

	return 0;
}

static void bma_priv_clean_up(struct bma_priv_data_s *bma_priv)
{
	int ret = 0;
	int i = 0;
	struct bma_priv_data_s *priv = bma_priv;
	struct edma_recv_msg_s *msg = NULL;
	unsigned long flags = 0;

	if (!priv)
		return;

	if (priv->user.type == TYPE_UNKNOWN) {
		BMA_LOG(DLOG_ERROR, "already unknown type\n");
		return;
	}

	spin_lock_irqsave(&priv->recv_msg_lock, flags);
	for (i = 0; i < priv->user.max_recvmsg_nums; i++) {
		ret = edma_host_recv_msg(&g_bma_dev->edma_host, priv, &msg);
		if (ret)
			break;

		kfree(msg);
	}
	spin_unlock_irqrestore(&priv->recv_msg_lock, flags);

	priv->user.type = TYPE_UNKNOWN;
	priv->user.sub_type = 0;
	priv->user.dma_transfer = 0;
	priv->user.seq = 0;
	priv->user.cur_recvmsg_nums = 0;
	priv->user.max_recvmsg_nums = DEFAULT_MAX_RECV_MSG_NUMS;
	kfree(priv);
}

static irqreturn_t bma_irq_handle(int irq, void *data)
{
	struct bma_dev_s *bma_dev = (struct bma_dev_s *)data;

	if (!bma_dev)
		return IRQ_HANDLED;

	bma_dev->edma_host.statistics.b2h_int++;

	if (!is_edma_b2h_int(&bma_dev->edma_host))
		return edma_host_irq_handle(&bma_dev->edma_host);

	return (irqreturn_t)atomic_notifier_call_chain(&bma_int_notify_list, 0,
						       data);
}

int bma_devinft_init(struct bma_pci_dev_s *bma_pci_dev)
{
	int ret = 0;
	int i = 0;
	struct bma_dev_s *bma_dev = NULL;

	if (!bma_pci_dev)
		return -EFAULT;

	bma_dev = kmalloc(sizeof(*bma_dev), (int)GFP_KERNEL);
	if (!bma_dev)
		return -ENOMEM;

	memset(bma_dev, 0, sizeof(struct bma_dev_s));

	bma_dev->bma_pci_dev = bma_pci_dev;
	bma_pci_dev->bma_dev = bma_dev;

	INIT_LIST_HEAD(&bma_dev->priv_list);
	spin_lock_init(&bma_dev->priv_list_lock);

	for (i = 0; i < TYPE_MAX; i++)
		atomic_set(&bma_dev->au_count[i], 1);

	ret = edma_host_init(&bma_dev->edma_host);
	if (ret) {
		BMA_LOG(DLOG_ERROR, "init edma host failed!err = %d\n", ret);
		goto err_free_bma_dev;
	}

	BMA_LOG(DLOG_DEBUG, "irq = %d\n", bma_pci_dev->pdev->irq);

	ret = request_irq(bma_pci_dev->pdev->irq, bma_irq_handle, IRQF_SHARED,
			  "EDMA_IRQ", (void *)bma_dev);
	if (ret) {
		BMA_LOG(DLOG_ERROR, "request_irq failed!err = %d\n", ret);
		goto err_edma_host_exit;
	}

	g_bma_dev = bma_dev;
	BMA_LOG(DLOG_DEBUG, "ok\n");

	return 0;

err_edma_host_exit:
	edma_host_cleanup(&bma_dev->edma_host);

err_free_bma_dev:
	kfree(bma_dev);
	bma_pci_dev->bma_dev = NULL;

	return ret;
}

void bma_devinft_cleanup(struct bma_pci_dev_s *bma_pci_dev)
{
	if (g_bma_dev) {
		if ((bma_pci_dev) && bma_pci_dev->pdev &&
		    bma_pci_dev->pdev->irq) {
			BMA_LOG(DLOG_DEBUG, "irq = %d\n",
				bma_pci_dev->pdev->irq);
			free_irq(bma_pci_dev->pdev->irq,
				 (void *)bma_pci_dev->bma_dev);
		}

		edma_host_cleanup(&g_bma_dev->edma_host);

		if ((bma_pci_dev) && bma_pci_dev->bma_dev) {
			kfree(bma_pci_dev->bma_dev);
			bma_pci_dev->bma_dev = NULL;
		}

		g_bma_dev = NULL;
	}
}

int bma_intf_register_int_notifier(struct notifier_block *nb)
{
	if (!nb)
		return -1;

	return atomic_notifier_chain_register(&bma_int_notify_list, nb);
}
EXPORT_SYMBOL_GPL(bma_intf_register_int_notifier);

void bma_intf_unregister_int_notifier(struct notifier_block *nb)
{
	if (!nb)
		return;

	atomic_notifier_chain_unregister(&bma_int_notify_list, nb);
}
EXPORT_SYMBOL_GPL(bma_intf_unregister_int_notifier);

int bma_intf_register_type(u32 type, u32 sub_type, enum intr_mod support_int,
			   void **handle)
{
	int ret = 0;
	struct bma_priv_data_s *priv = NULL;

	if (!handle)
		return -EFAULT;

	ret = bma_priv_init(&priv);
	if (ret) {
		BMA_LOG(DLOG_ERROR, "bma_priv_init failed! ret = %d\n", ret);
		return ret;
	}

	ret = bma_priv_insert_priv_list(priv, type, sub_type);
	if (ret) {
		bma_priv_clean_up(priv);
		BMA_LOG(DLOG_ERROR,
			"bma_priv_insert_priv_list failed! ret = %d\n", ret);
		return ret;
	}

	if (support_int)
		priv->user.support_int = INTR_ENABLE;

	if (type == TYPE_VETH) {
		priv->specific.veth.pdev = g_bma_dev->bma_pci_dev->pdev;

		priv->specific.veth.veth_swap_phy_addr =
		    g_bma_dev->bma_pci_dev->veth_swap_phy_addr;
		priv->specific.veth.veth_swap_addr =
		    g_bma_dev->bma_pci_dev->veth_swap_addr;
		priv->specific.veth.veth_swap_len =
		    g_bma_dev->bma_pci_dev->veth_swap_len;
	}

	*handle = priv;

	return 0;
}
EXPORT_SYMBOL(bma_intf_register_type);

int bma_intf_unregister_type(void **handle)
{
	struct bma_priv_data_s *priv = NULL;

	if (!handle) {
		BMA_LOG(DLOG_ERROR, "edna_priv is NULL\n");
		return -EFAULT;
	}

	priv = (struct bma_priv_data_s *)*handle;
	*handle = NULL;

	priv->user.cur_recvmsg_nums++;
	wake_up_interruptible(&priv->wait);

	msleep(500);

	bma_priv_delete_priv_list(priv);

	bma_priv_clean_up(priv);

	return 0;
}
EXPORT_SYMBOL(bma_intf_unregister_type);

int bma_intf_check_edma_supported(void)
{
	return !(!g_bma_dev);
}
EXPORT_SYMBOL(bma_intf_check_edma_supported);

int bma_intf_check_dma_status(enum dma_direction_e dir)
{
	return edma_host_check_dma_status(dir);
}
EXPORT_SYMBOL(bma_intf_check_dma_status);

void bma_intf_reset_dma(enum dma_direction_e dir)
{
	edma_host_reset_dma(&g_bma_dev->edma_host, dir);
}
EXPORT_SYMBOL(bma_intf_reset_dma);

void bma_intf_clear_dma_int(enum dma_direction_e dir)
{
	if (dir == BMC_TO_HOST)
		clear_int_dmab2h(&g_bma_dev->edma_host);
	else if (dir == HOST_TO_BMC)
		clear_int_dmah2b(&g_bma_dev->edma_host);
	else
		return;
}
EXPORT_SYMBOL(bma_intf_clear_dma_int);

int bma_intf_start_dma(void *handle, struct bma_dma_transfer_s *dma_transfer)
{
	int ret = 0;
	struct bma_priv_data_s *priv = (struct bma_priv_data_s *)handle;

	if (!handle || !dma_transfer)
		return -EFAULT;

	ret = edma_host_dma_start(&g_bma_dev->edma_host, priv);
	if (ret) {
		BMA_LOG(DLOG_ERROR,
			"edma_host_dma_start failed! result = %d\n", ret);
		return ret;
	}

	ret = edma_host_dma_transfer(&g_bma_dev->edma_host, priv, dma_transfer);
	if (ret)
		BMA_LOG(DLOG_ERROR,
			"edma_host_dma_transfer failed! ret = %d\n", ret);

	ret = edma_host_dma_stop(&g_bma_dev->edma_host, priv);
	if (ret) {
		BMA_LOG(DLOG_ERROR,
			"edma_host_dma_stop failed! result = %d\n", ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(bma_intf_start_dma);

int bma_intf_int_to_bmc(void *handle)
{
	struct bma_priv_data_s *priv = (struct bma_priv_data_s *)handle;

	if (!handle)
		return -EFAULT;

	if (priv->user.support_int == 0) {
		BMA_LOG(DLOG_ERROR, "not support int to bmc.\n");
		return -EFAULT;
	}

	edma_int_to_bmc(&g_bma_dev->edma_host);

	return 0;
}
EXPORT_SYMBOL(bma_intf_int_to_bmc);

int bma_intf_is_link_ok(void)
{
	if (g_bma_dev &&
	    g_bma_dev->edma_host.statistics.remote_status == REGISTERED)
		return 1;
	return 0;
}
EXPORT_SYMBOL(bma_intf_is_link_ok);

int bma_cdev_recv_msg(void *handle, char __user *data, size_t count)
{
	struct bma_priv_data_s *priv = NULL;
	struct edma_recv_msg_s *msg = NULL;
	int result = 0;
	int len = 0;
	unsigned long flags = 0;

	if (!handle || !data || count == 0) {
		BMA_LOG(DLOG_DEBUG, "input NULL point!\n");
		return -EFAULT;
	}

	priv = (struct bma_priv_data_s *)handle;

	spin_lock_irqsave(&priv->recv_msg_lock, flags);
	result = edma_host_recv_msg(&g_bma_dev->edma_host, priv, &msg);
	spin_unlock_irqrestore(&priv->recv_msg_lock, flags);
	if (result != 0)
		return -ENODATA;

	if (msg->msg_len > count) {
		kfree(msg);
		return -EFAULT;
	}

	if (copy_to_user(data, (void *)msg->msg_data, msg->msg_len)) {
		kfree(msg);
		return -EFAULT;
	}

	len = msg->msg_len;

	kfree(msg);

	return len;
}
EXPORT_SYMBOL_GPL(bma_cdev_recv_msg);

static int check_cdev_add_msg_param(struct bma_priv_data_s *handle,
const char __user *msg, size_t msg_len)
{
	struct bma_priv_data_s *priv = NULL;

	if (!handle || !msg || msg_len == 0) {
		BMA_LOG(DLOG_DEBUG, "input NULL point!\n");
		return -EFAULT;
	}

	if (msg_len > CDEV_MAX_WRITE_LEN) {
		BMA_LOG(DLOG_DEBUG, "input data is overlen!\n");
		return -EINVAL;
	}

	priv = handle;

	if (priv->user.type >= TYPE_MAX) {
		BMA_LOG(DLOG_DEBUG, "error type = %d\n", priv->user.type);
		return -EFAULT;
	}

	return 0;
}

static void edma_msg_hdr_init(struct edma_msg_hdr_s *hdr,
				struct bma_priv_data_s *private_data,
				char *msg_buf, size_t msg_len)
{
	hdr->type = private_data->user.type;
	hdr->sub_type = private_data->user.sub_type;
	hdr->user_id = private_data->user.user_id;
	hdr->datalen = msg_len;
	BMA_LOG(DLOG_DEBUG, "msg_len is %zu\n", msg_len);

	memcpy(hdr->data, msg_buf, msg_len);
}

int bma_cdev_add_msg(void *handle, const char __user *msg, size_t msg_len)
{
	struct bma_priv_data_s *priv = NULL;
	struct edma_msg_hdr_s *hdr = NULL;
	unsigned long flags = 0;
	unsigned int total_len = 0;
	int ret = 0;
	struct edma_host_s *phost = &g_bma_dev->edma_host;
	char *msg_buf = NULL;

	ret = check_cdev_add_msg_param(handle, msg, msg_len);
	if (ret != 0)
		return ret;

	priv = (struct bma_priv_data_s *)handle;

	total_len = (unsigned int)(SIZE_OF_MSG_HDR + msg_len);
	if (phost->msg_send_write + total_len > HOST_MAX_SEND_MBX_LEN - SIZE_OF_MBX_HDR) {
		BMA_LOG(DLOG_DEBUG, "msg lost,msg_send_write: %u,msg_len:%u,max_len: %d\n",
				phost->msg_send_write, total_len, HOST_MAX_SEND_MBX_LEN);
		return -ENOSPC;
	}

	msg_buf = (char *)kmalloc(msg_len, GFP_KERNEL);
	if (!msg_buf) {
		BMA_LOG(DLOG_ERROR, "malloc msg_buf failed\n");
		return -ENOMEM;
	}

	if (copy_from_user(msg_buf, msg, msg_len)) {
		BMA_LOG(DLOG_ERROR, "copy_from_user error\n");
		kfree(msg_buf);
		return -EFAULT;
	}

	spin_lock_irqsave(&phost->send_msg_lock, flags);

	hdr = (struct edma_msg_hdr_s *)(phost->msg_send_buf + phost->msg_send_write);
	edma_msg_hdr_init(hdr, priv, msg_buf, msg_len);

	phost->msg_send_write += total_len;
	phost->statistics.send_bytes += total_len;
	phost->statistics.send_pkgs++;
#ifdef EDMA_TIMER
	(void)mod_timer(&phost->timer, jiffies_64);
#endif
	BMA_LOG(DLOG_DEBUG, "msg_send_write = %d\n", phost->msg_send_write);

	ret = msg_len;
	spin_unlock_irqrestore(&g_bma_dev->edma_host.send_msg_lock, flags);
	kfree(msg_buf);
	return ret;
}
EXPORT_SYMBOL_GPL(bma_cdev_add_msg);

unsigned int bma_cdev_check_recv(void *handle)
{
	struct bma_priv_data_s *priv = (struct bma_priv_data_s *)handle;
	unsigned long flags = 0;
	unsigned int result = 0;

	if (priv) {
		spin_lock_irqsave(&priv->recv_msg_lock, flags);

		if (!list_empty(&priv->recv_msgs))
			result = 1;

		spin_unlock_irqrestore(&priv->recv_msg_lock, flags);
	}

	return result;
}
EXPORT_SYMBOL_GPL(bma_cdev_check_recv);

void *bma_cdev_get_wait_queue(void *handle)
{
	struct bma_priv_data_s *priv = (struct bma_priv_data_s *)handle;

	return priv ? ((void *)&priv->wait) : NULL;
}
EXPORT_SYMBOL_GPL(bma_cdev_get_wait_queue);

void bma_intf_set_open_status(void *handle, int s)
{
	struct bma_priv_data_s *priv = (struct bma_priv_data_s *)handle;
	int i = 0;
	int ret = 0;
	unsigned long flags = 0;
	char drv_msg[3] = { 0 };
	struct edma_recv_msg_s *tmp_msg = NULL;

	if (!priv || priv->user.type >= TYPE_MAX)
		return;

	drv_msg[0] = 1;
	drv_msg[1] = priv->user.type;
	drv_msg[2] = s;

	(void)edma_host_send_driver_msg((void *)drv_msg, sizeof(drv_msg),
						DEV_OPEN_STATUS_ANS);

		spin_lock_irqsave(&priv->recv_msg_lock, flags);
		g_bma_dev->edma_host.local_open_status[priv->user.type] = s;

		if (s == DEV_CLOSE && priv->user.cur_recvmsg_nums > 0) {
			for (i = 0; i < priv->user.max_recvmsg_nums; i++) {
				ret = edma_host_recv_msg(&g_bma_dev->edma_host,
							 priv, &tmp_msg);
				if (ret < 0)
					break;

				kfree(tmp_msg);
				tmp_msg = NULL;
			}
		}

		spin_unlock_irqrestore(&priv->recv_msg_lock, flags);
}
EXPORT_SYMBOL_GPL(bma_intf_set_open_status);
