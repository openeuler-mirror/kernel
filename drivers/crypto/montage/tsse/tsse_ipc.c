// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of tsse driver for Linux
 *
 * Copyright © 2023 Montage Technology. All rights reserved.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "tsse_ipc.h"
#include "tsse_dev.h"
#include "tsse_service.h"

struct tsse_msg *get_msginf(void __iomem *d2h)
{
	uint32_t u_len;
	struct tsse_msg *tssemsg;

	struct ipc_header *ipc_info = (struct ipc_header *)d2h;

	u_len = ipc_info->i_len - sizeof(struct ipc_header);

	tssemsg = (struct tsse_msg *)(kzalloc(sizeof(struct tsse_msg) + u_len,
					      GFP_ATOMIC));

	if (!tssemsg) {
		pr_info("%s(): tssemsg kzalloc failed\n", __func__);
		return NULL;
	}

	tssemsg->ipc_payload.header.inst_id = ipc_info->inst_id;
	tssemsg->ipc_payload.header.tgid = ipc_info->tgid;
	tssemsg->ipc_payload.header.i_len = ipc_info->i_len;

	return tssemsg;
}

void ipc_recieve_msg(struct tsse_ipc *tsseipc, struct ipc_msg *msg)
{
	uint32_t u_len = msg->header.i_len - sizeof(struct ipc_header);
	uint32_t *msg_data = NULL;
	void __iomem *d2h = tsseipc->virt_addr + MAIN2HOST_IPC_OFFSET;

	msg_data = (uint32_t *)(d2h + sizeof(struct ipc_header));
	memcpy_fromio(msg->i_data, msg_data, u_len);
	return;

}

int msg_rout(struct tsse_ipc *tsseipc, struct tsse_msg *tssemsg)
{
	int ret = 0;
	struct ipc_msg *msg;
	struct msg_info *info;
	uint32_t msg_class;

	msg = &tssemsg->ipc_payload;

	ipc_recieve_msg(tsseipc, msg);
	info = (struct msg_info *)msg->i_data;
	msg_class = info->msg_class;
	if (msg_class == IPC_MESSAGE_BOOT) {
		service_rout(tsseipc, msg);
		return 0;
	}

	return ret;
}

static irqreturn_t tsse_ipc_d2h_irqhandler(int irq, void *dev_id)
{
	struct tsse_ipc *tsseipc = (struct tsse_ipc *)dev_id;

	writel(0x0, tsseipc->virt_addr + MAIN2HOST_INTR_SET_OFFSET);
	tasklet_hi_schedule(&tsseipc->ipc_handle);
	dev_err(tsseipc->dev, "irq%d\n", irq);
	return IRQ_HANDLED;
}

bool check_send_enbit(struct tsse_ipc *tsseipc)
{
	u32 int_reg;

	int_reg = readl(tsseipc->virt_addr + HOST2MAIN_INTR_SET_OFFSET);
	if ((int_reg & IPC_REGISTER_INT_SET) == 0)
		return true;
	else
		return false;
}
EXPORT_SYMBOL(check_send_enbit);

void notify_device(struct tsse_ipc *tsseipc)
{
	writel(0x1, tsseipc->virt_addr + HOST2MAIN_INTR_SET_OFFSET);
	return;

}
EXPORT_SYMBOL(notify_device);

void ipc_send_msg(struct tsse_ipc *tsseipc, struct ipc_data *msg)
{
	u8 *h2d = NULL;

	h2d = (u8 *)(tsseipc->virt_addr + HOST2MAIN_IPC_OFFSET);
	memcpy_toio(h2d, msg, sizeof(struct ipc_header));
	memcpy_toio(h2d + sizeof(struct ipc_header), (u32 *)msg->i_ptr,
		    msg->header.i_len - sizeof(struct ipc_header));
	return;

}

void ipc_hw_init(struct tsse_ipc *hw_ipc)
{
	writel(0x1, hw_ipc->virt_addr + MAIN2HOST_INTR_ENABLE_OFFSET);
	writel(0x0, hw_ipc->virt_addr + HOST2MAIN_INTR_SET_OFFSET);
	writel(0x0, hw_ipc->virt_addr + MAIN2HOST_INTR_SET_OFFSET);
}

int ipc_init_msg(struct tsse_ipc *tsseipc)
{
	u8 *h2d;
	u32 int_reg;
	u32 rc;
	u32 cmd_len;
	struct ipc_msg *msg;
	struct msg_info *info_msg;

	msg = (struct ipc_msg *)(kzalloc(
		sizeof(struct ipc_msg) + sizeof(struct msg_info), GFP_ATOMIC));

	if (!msg) {
		pr_info("%s(): msg kzalloc failed\n", __func__);
		return -1;
	}
	cmd_len = sizeof(uint32_t);
	msg->header.i_len =
		sizeof(struct ipc_header) + sizeof(struct msg_info) + cmd_len;
	info_msg = (struct msg_info *)msg->i_data;
	info_msg->msg_class = IPC_MESSAGE_BASIC;
	*(msg->i_data + sizeof(struct msg_info) / 4) = IPC_BASIC_CMD_HOST_INIT;

	mutex_lock(&tsseipc->list_lock);
	int_reg = readl(tsseipc->virt_addr + HOST2MAIN_INTR_SET_OFFSET);
	if ((int_reg & IPC_REGISTER_INT_SET) != 0) {
		rc = -1;
		mutex_unlock(&tsseipc->list_lock);
		kfree(msg);
		return rc;
	}
	h2d = (u8 *)(tsseipc->virt_addr + HOST2MAIN_IPC_OFFSET);

	memcpy_toio(h2d, msg, sizeof(struct ipc_header));
	memcpy_toio(h2d + sizeof(struct ipc_header), (u32 *)msg->i_data,
		    sizeof(struct msg_info) + sizeof(uint32_t));

	writel(0x1, tsseipc->virt_addr + HOST2MAIN_INTR_SET_OFFSET);
	mutex_unlock(&tsseipc->list_lock);
	kfree(msg);

	return 0;
}

static void tsse_ipc_bh_handler(unsigned long data)
{
	struct tsse_ipc *tsseipc = (struct tsse_ipc *)data;

	void __iomem *d2h_payload = tsseipc->virt_addr + MAIN2HOST_IPC_OFFSET;
	struct tsse_msg *msg_tsse = get_msginf(d2h_payload);

	if (!msg_tsse) {
		dev_err(tsseipc->dev, "get_msginf is NULL\n");
		return;
	}
	msg_rout(tsseipc, msg_tsse);
}

int tsse_ipc_init(struct pci_dev *pdev)
{
	struct tsse_dev *tdev = pci_to_tsse_dev(pdev);
	struct tsse_ipc *ipc;
	int rc;

	ipc = devm_kzalloc(&pdev->dev, sizeof(*ipc), GFP_KERNEL);
	if (ipc == NULL)
		return -ENOMEM;
	tdev->ipc = ipc;
	ipc->pdev = pdev;
	ipc->dev = &pdev->dev;
	ipc->virt_addr = TSSE_DEV_BARS(tdev)[2].virt_addr;

	mutex_init(&ipc->list_lock);
	tasklet_init(&(ipc->ipc_handle), tsse_ipc_bh_handler,
		     (ulong)(ipc));

	rc = request_threaded_irq(pci_irq_vector(pdev, 0), NULL,
				  tsse_ipc_d2h_irqhandler, IRQF_SHARED,
				  "pf-ipc", ipc);
	ipc_hw_init(ipc);
	ipc_init_msg(ipc);

	return rc;
}
EXPORT_SYMBOL_GPL(tsse_ipc_init);

void tsse_ipc_deinit(void *tdev_t)
{
	struct tsse_ipc *tsseipc;
	struct pci_dev *pdev;
	struct tsse_dev *tdev;

	tdev = tdev_t;
	tsseipc = tdev->ipc;
	pdev = tsseipc->pdev;
	free_irq(pci_irq_vector(pdev, 0), tdev->ipc);
	return;

}
EXPORT_SYMBOL_GPL(tsse_ipc_deinit);
