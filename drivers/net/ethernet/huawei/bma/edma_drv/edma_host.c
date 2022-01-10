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

#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "bma_pci.h"
#include "edma_host.h"

static struct edma_user_inft_s *g_user_func[TYPE_MAX] = { 0 };

static struct bma_dev_s *g_bma_dev;
static int edma_host_dma_interrupt(struct edma_host_s *edma_host);

int edmainfo_show(char *buf)
{
	struct bma_user_s *user_ptr = NULL;
	struct edma_host_s *host_ptr = NULL;
	int len = 0;
	__kernel_time_t running_time = 0;
	static const char * const host_status[] = {
		"deregistered",	"registered", "lost"};

	if (!buf)
		return 0;

	if (!g_bma_dev) {
		len += sprintf(buf, "EDMA IS NOT SUPPORTED");
		return len;
	}

	host_ptr = &g_bma_dev->edma_host;

	GET_SYS_SECONDS(running_time);
	running_time -= host_ptr->statistics.init_time;
	len += sprintf(buf + len,
		    "============================EDMA_DRIVER_INFO============================\n");
	len += sprintf(buf + len, "version      :" BMA_VERSION "\n");

	len += sprintf(buf + len, "running_time :%luD %02lu:%02lu:%02lu\n",
		    running_time / SECONDS_PER_DAY,
		    running_time % SECONDS_PER_DAY / SECONDS_PER_HOUR,
		    running_time % SECONDS_PER_HOUR / SECONDS_PER_MINUTE,
		    running_time % SECONDS_PER_MINUTE);

	len += sprintf(buf + len, "remote_status:%s\n",
		    host_status[host_ptr->statistics.remote_status]);
	len += sprintf(buf + len, "lost_count   :%d\n",
		    host_ptr->statistics.lost_count);
	len += sprintf(buf + len, "b2h_int      :%d\n",
		    host_ptr->statistics.b2h_int);
	len += sprintf(buf + len, "h2b_int      :%d\n",
		    host_ptr->statistics.h2b_int);
	len += sprintf(buf + len, "dma_count    :%d\n",
		    host_ptr->statistics.dma_count);
	len += sprintf(buf + len, "recv_bytes   :%d\n",
		    host_ptr->statistics.recv_bytes);
	len += sprintf(buf + len, "send_bytes   :%d\n",
		    host_ptr->statistics.send_bytes);
	len += sprintf(buf + len, "recv_pkgs    :%d\n",
		    host_ptr->statistics.recv_pkgs);
	len += sprintf(buf + len, "send_pkgs    :%d\n",
		    host_ptr->statistics.send_pkgs);
	len += sprintf(buf + len, "drop_pkgs    :%d\n",
		    host_ptr->statistics.drop_pkgs);
	len += sprintf(buf + len, "fail_count   :%d\n",
		    host_ptr->statistics.failed_count);
	len += sprintf(buf + len, "debug        :%d\n", debug);
	len += sprintf(buf + len,
		    "================================USER_INFO===============================\n");

	list_for_each_entry_rcu(user_ptr, &g_bma_dev->priv_list, link) {
		len += sprintf(buf + len,
			    "type: %d\nsub type: %d\nopen:%d\nmax recvmsg nums: %d\ncur recvmsg nums: %d\n",
			    user_ptr->type, user_ptr->sub_type,
			    host_ptr->local_open_status[user_ptr->type],
			    user_ptr->max_recvmsg_nums,
			    user_ptr->cur_recvmsg_nums);
		len += sprintf(buf + len,
			    "========================================================================\n");
	}

	return len;
}

int is_edma_b2h_int(struct edma_host_s *edma_host)
{
	struct notify_msg *pnm = NULL;

	if (!edma_host)
		return -1;

	pnm = (struct notify_msg *)edma_host->edma_flag;
	if (!pnm) {
		BMA_LOG(DLOG_ERROR, "pnm is 0\n");
		return -1;
	}

	if (IS_EDMA_B2H_INT(pnm->int_flag)) {
		CLEAR_EDMA_B2H_INT(pnm->int_flag);
		return 0;
	}

	return -1;
}

void edma_int_to_bmc(struct edma_host_s *edma_host)
{
	unsigned int data = 0;

	if (!edma_host)
		return;

	edma_host->statistics.h2b_int++;

	data = *(unsigned int *)((char *)edma_host->hostrtc_viraddr +
							 HOSTRTC_INT_OFFSET);

	data |= 0x00000001;

	*(unsigned int *)((char *)edma_host->hostrtc_viraddr +
					  HOSTRTC_INT_OFFSET) = data;
}

static void edma_host_int_to_bmc(struct edma_host_s *edma_host)
{
	struct notify_msg *pnm = NULL;

	if (!edma_host)
		return;

	pnm = (struct notify_msg *)edma_host->edma_flag;
	if (pnm) {
		SET_EDMA_H2B_INT(pnm->int_flag);
		edma_int_to_bmc(edma_host);
	}
}

static int check_status_dmah2b(struct edma_host_s *edma_host)
{
	unsigned int data = 0;
	struct pci_dev *pdev = NULL;

	if (!edma_host)
		return 0;

	pdev = edma_host->pdev;
	if (!pdev)
		return 0;

	(void)pci_read_config_dword(pdev, REG_PCIE1_DMAREAD_STATUS,
				    (u32 *)&data);

	if (data & (1 << SHIFT_PCIE1_DMAREAD_STATUS))
		return 1;	/* ok */
	else
		return 0;	/* busy */
}

static int check_status_dmab2h(struct edma_host_s *edma_host)
{
	unsigned int data = 0;
	struct pci_dev *pdev = NULL;

	if (!edma_host)
		return 0;

	pdev = edma_host->pdev;
	if (!pdev)
		return 0;

	(void)pci_read_config_dword(pdev, REG_PCIE1_DMAWRITE_STATUS,
				    (u32 *)&data);

	if (data & (1 << SHIFT_PCIE1_DMAWRITE_STATUS))
		return 1;	/* ok */
	else
		return 0;	/* busy */
}

void clear_int_dmah2b(struct edma_host_s *edma_host)
{
	unsigned int data = 0;
	struct pci_dev *pdev = NULL;

	if (!edma_host)
		return;

	pdev = edma_host->pdev;
	if (!pdev)
		return;

	(void)pci_read_config_dword(pdev, REG_PCIE1_DMAREADINT_CLEAR,
				    (u32 *)&data);
	data = data & (~((1 << SHIFT_PCIE1_DMAREADINT_CLEAR)));
	data = data | (1 << SHIFT_PCIE1_DMAREADINT_CLEAR);
	(void)pci_write_config_dword(pdev, REG_PCIE1_DMAREADINT_CLEAR, data);
}

void clear_int_dmab2h(struct edma_host_s *edma_host)
{
	unsigned int data = 0;
	struct pci_dev *pdev = NULL;

	if (!edma_host)
		return;

	pdev = edma_host->pdev;
	if (!pdev)
		return;

	(void)pci_read_config_dword(pdev, REG_PCIE1_DMAWRITEINT_CLEAR,
				    (u32 *)&data);
	data = data & (~((1 << SHIFT_PCIE1_DMAWRITEINT_CLEAR)));
	data = data | (1 << SHIFT_PCIE1_DMAWRITEINT_CLEAR);
	(void)pci_write_config_dword(pdev, REG_PCIE1_DMAWRITEINT_CLEAR, data);
}

int edma_host_check_dma_status(enum dma_direction_e dir)
{
	int ret = 0;

	switch (dir) {
	case BMC_TO_HOST:
		ret = check_status_dmab2h(&g_bma_dev->edma_host);
		if (ret == 1)
			clear_int_dmab2h(&g_bma_dev->edma_host);

		break;

	case HOST_TO_BMC:
		ret = check_status_dmah2b(&g_bma_dev->edma_host);
		if (ret == 1)
			clear_int_dmah2b(&g_bma_dev->edma_host);

		break;

	default:
		BMA_LOG(DLOG_ERROR, "direction failed, dir = %d\n", dir);
		ret = -EFAULT;
		break;
	}

	return ret;
}

#ifdef USE_DMA

static int start_transfer_h2b(struct edma_host_s *edma_host, unsigned int len,
			      unsigned int src_h, unsigned int src_l,
			      unsigned int dst_h, unsigned int dst_l)
{
	unsigned long flags = 0;
	struct pci_dev *pdev = edma_host->pdev;

	spin_lock_irqsave(&edma_host->reg_lock, flags);
	/*  read engine enable    */
	(void)pci_write_config_dword(pdev, 0x99c, 0x00000001);
	/*  read ch,ch index 0   */
	(void)pci_write_config_dword(pdev, 0xa6c, 0x80000000);
	/*  ch ctrl,local int enable */
	(void)pci_write_config_dword(pdev, 0xa70, 0x00000008);
	/*  size    */
	(void)pci_write_config_dword(pdev, 0xa78, len);
	/*  src lower 32b    */
	(void)pci_write_config_dword(pdev, 0xa7c, src_l);
	/*  src upper 32b    */
	(void)pci_write_config_dword(pdev, 0xa80, src_h);
	/*  dst lower 32b    */
	(void)pci_write_config_dword(pdev, 0xa84, dst_l);
	/*  dst upper 32b    */
	(void)pci_write_config_dword(pdev, 0xa88, dst_h);
	/*  start read dma,ch 0   */
	(void)pci_write_config_dword(pdev, 0x9a0, 0x00000000);
	spin_unlock_irqrestore(&edma_host->reg_lock, flags);
	return 0;
}

static int start_transfer_b2h(struct edma_host_s *edma_host, unsigned int len,
			      unsigned int src_h, unsigned int src_l,
			      unsigned int dst_h, unsigned int dst_l)
{
	unsigned long flags = 0;
	struct pci_dev *pdev = edma_host->pdev;

	BMA_LOG(DLOG_DEBUG,
		"len = 0x%8x,src_h = 0x%8x,src_l = 0x%8x,dst_h = 0x%8x,dst_l = 0x%8x\n",
		len, src_h, src_l, dst_h, dst_l);

	spin_lock_irqsave(&edma_host->reg_lock, flags);
	/*  write engine enable    */
	(void)pci_write_config_dword(pdev, 0x97c, 0x00000001);
	/*  write ch,ch index 0   */
	(void)pci_write_config_dword(pdev, 0xa6c, 0x00000000);
	/*  ch ctrl,local int enable */
	(void)pci_write_config_dword(pdev, 0xa70, 0x00000008);
	/*  size    */
	(void)pci_write_config_dword(pdev, 0xa78, len);
	/*  src lower 32b    */
	(void)pci_write_config_dword(pdev, 0xa7c, src_l);
	/*  src upper 32b    */
	(void)pci_write_config_dword(pdev, 0xa80, src_h);
	/*  dst lower 32b    */
	(void)pci_write_config_dword(pdev, 0xa84, dst_l);
	/*  dst upper 32b    */
	(void)pci_write_config_dword(pdev, 0xa88, dst_h);
	/*  start write dma,ch 0   */
	(void)pci_write_config_dword(pdev, 0x980, 0x00000000);
	spin_unlock_irqrestore(&edma_host->reg_lock, flags);

	return 0;
}
#endif

static void start_listtransfer_h2b(struct edma_host_s *edma_host,
				   unsigned int list_h, unsigned int list_l)
{
	unsigned long flags = 0;
	struct pci_dev *pdev = NULL;

	if (!edma_host)
		return;

	pdev = edma_host->pdev;
	if (!pdev)
		return;

	spin_lock_irqsave(&edma_host->reg_lock, flags);

	/*  write engine enable    */
	(void)pci_write_config_dword(pdev, 0x700 + 0x29c, 0x00000001);
	/*  write list err enable   */
	(void)pci_write_config_dword(pdev, 0x700 + 0x334, 0x00010000);
	/*  write ch,ch index 0   */
	(void)pci_write_config_dword(pdev, 0x700 + 0x36c, 0x80000000);
	/*  ch ctrl,local int enable */
	(void)pci_write_config_dword(pdev, 0x700 + 0x370, 0x00000300);
	/*  list lower 32b    */
	(void)pci_write_config_dword(pdev, 0x700 + 0x38c, list_l);
	/*  list upper 32b    */
	(void)pci_write_config_dword(pdev, 0x700 + 0x390, list_h);
	/*  start write dma,ch 0   */
	(void)pci_write_config_dword(pdev, 0x700 + 0x2a0, 0x00000000);

	spin_unlock_irqrestore(&edma_host->reg_lock, flags);
}

static void start_listtransfer_b2h(struct edma_host_s *edma_host,
				   unsigned int list_h, unsigned int list_l)
{
	unsigned long flags = 0;
	struct pci_dev *pdev = NULL;

	if (!edma_host)
		return;

	pdev = edma_host->pdev;
	if (!pdev)
		return;

	spin_lock_irqsave(&edma_host->reg_lock, flags);

	/*  write engine enable    */
	(void)pci_write_config_dword(pdev, 0x700 + 0x27c, 0x00000001);
	/*  write list err enable   */
	(void)pci_write_config_dword(pdev, 0x700 + 0x300, 0x00000001);
	/*  write ch,ch index 0   */
	(void)pci_write_config_dword(pdev, 0x700 + 0x36c, 0x00000000);
	/*  ch ctrl,local int enable */
	(void)pci_write_config_dword(pdev, 0x700 + 0x370, 0x00000300);
	/*  list lower 32b    */
	(void)pci_write_config_dword(pdev, 0x700 + 0x38c, list_l);
	/*  list upper 32b    */
	(void)pci_write_config_dword(pdev, 0x700 + 0x390, list_h);
	/*  start write dma,ch 0   */
	(void)pci_write_config_dword(pdev, 0x700 + 0x280, 0x00000000);

	spin_unlock_irqrestore(&edma_host->reg_lock, flags);
}

int edma_host_dma_start(struct edma_host_s *edma_host,
			struct bma_priv_data_s *priv)
{
	struct bma_user_s *puser = NULL;
	struct bma_dev_s *bma_dev = NULL;
	unsigned long flags = 0;

	if (!edma_host || !priv)
		return -EFAULT;

	bma_dev = list_entry(edma_host, struct bma_dev_s, edma_host);

	spin_lock_irqsave(&bma_dev->priv_list_lock, flags);

	list_for_each_entry_rcu(puser, &bma_dev->priv_list, link) {
		if (puser->dma_transfer) {
			spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);
			BMA_LOG(DLOG_ERROR, "type = %d dma is started\n",
				puser->type);

			return -EBUSY;
		}
	}

	priv->user.dma_transfer = 1;

	spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);

	return 0;
}

#ifdef USE_DMA

static int edma_host_dma_h2b(struct edma_host_s *edma_host,
			     struct bma_dma_addr_s *host_addr,
			     struct bma_dma_addr_s *bmc_addr)
{
	int ret = 0;
	struct notify_msg *pnm = (struct notify_msg *)edma_host->edma_flag;
	unsigned long host_h2b_addr = 0;
	unsigned long bmc_h2b_addr = 0;
	unsigned int bmc_h2b_size = 0;
	unsigned int src_h, src_l, dst_h, dst_l;

	if (!host_addr) {
		BMA_LOG(DLOG_ERROR, "host_addr is NULL\n");
		return -EFAULT;
	}

	BMA_LOG(DLOG_DEBUG, "host_addr->dma_addr = 0x%llx\n",
		host_addr->dma_addr);

	if (host_addr->dma_addr)
		host_h2b_addr = (unsigned long)(host_addr->dma_addr);
	else
		host_h2b_addr = edma_host->h2b_addr.dma_addr;

	bmc_h2b_addr = pnm->h2b_addr;
	bmc_h2b_size = pnm->h2b_size;

	BMA_LOG(DLOG_DEBUG,
		"host_h2b_addr = 0x%lx, dma_data_len = %d, bmc_h2b_addr = 0x%lx, bmc_h2b_size = %d\n",
		host_h2b_addr, host_addr->dma_data_len, bmc_h2b_addr,
		bmc_h2b_size);

	if (host_addr->dma_data_len > EDMA_DMABUF_SIZE ||
	    bmc_h2b_addr == 0 ||
	    host_addr->dma_data_len > bmc_h2b_size) {
		BMA_LOG(DLOG_ERROR,
			"dma_data_len too large = %d, bmc_h2b_size = %d\n",
			host_addr->dma_data_len, bmc_h2b_size);
		return -EFAULT;
	}

	edma_host->h2b_state = H2BSTATE_WAITDMA;

	src_h = (unsigned int)((sizeof(unsigned long) == 8) ?
					(host_h2b_addr >> 32) : 0);
	src_l = (unsigned int)(host_h2b_addr & 0xffffffff);
	dst_h = (unsigned int)((sizeof(unsigned long) == 8) ?
					(bmc_h2b_addr >> 32) : 0);
	dst_l = (unsigned int)(bmc_h2b_addr & 0xffffffff);
	(void)start_transfer_h2b(edma_host,
		host_addr->dma_data_len, src_h,
		src_l, dst_h, dst_l);

	(void)mod_timer(&edma_host->dma_timer,
			jiffies_64 + TIMER_INTERVAL_CHECK);

	ret = wait_event_interruptible_timeout(edma_host->wq_dmah2b,
					       (edma_host->h2b_state ==
					      H2BSTATE_IDLE),
					     EDMA_DMA_TRANSFER_WAIT_TIMEOUT);

	if (ret == -ERESTARTSYS) {
		BMA_LOG(DLOG_ERROR, "eintr 1\n");
		ret = -EINTR;
		goto end;
	} else if (ret == 0) {
		BMA_LOG(DLOG_ERROR, "timeout 2\n");
		ret = -ETIMEDOUT;
		goto end;
	} else {
		ret = 0;
		BMA_LOG(DLOG_ERROR, "h2b dma successful\n");
	}

end:

	return ret;
}

static int edma_host_dma_b2h(struct edma_host_s *edma_host,
			     struct bma_dma_addr_s *host_addr,
			     struct bma_dma_addr_s *bmc_addr)
{
	int ret = 0;
	struct notify_msg *pnm = (struct notify_msg *)edma_host->edma_flag;
	unsigned long bmc_b2h_addr = 0;
	unsigned long host_b2h_addr = 0;
	unsigned int src_h, src_l, dst_h, dst_l;

	if (!bmc_addr)
		return -EFAULT;

	if (host_addr->dma_addr)
		host_b2h_addr = (unsigned long)(host_addr->dma_addr);
	else
		host_b2h_addr = edma_host->b2h_addr.dma_addr;

	if (bmc_addr->dma_addr)
		bmc_b2h_addr = (unsigned long)(bmc_addr->dma_addr);
	else
		bmc_b2h_addr = pnm->b2h_addr;

	BMA_LOG(DLOG_DEBUG,
		"bmc_b2h_addr = 0x%lx, host_b2h_addr = 0x%lx, dma_data_len = %d\n",
		bmc_b2h_addr, host_b2h_addr, bmc_addr->dma_data_len);

	if (bmc_addr->dma_data_len > EDMA_DMABUF_SIZE ||
	    bmc_addr->dma_data_len > edma_host->b2h_addr.len) {
		BMA_LOG(DLOG_ERROR,
			"dma_data_len too large = %d, b2h_addr = %d\n",
			host_addr->dma_data_len, edma_host->b2h_addr.len);
		return -EFAULT;
	}

	edma_host->b2h_state = B2HSTATE_WAITDMA;

	src_h = (unsigned int)((sizeof(unsigned long) == 8) ?
					(bmc_b2h_addr >> 32) : 0);
	src_l = (unsigned int)(bmc_b2h_addr & 0xffffffff);
	dst_h = (unsigned int)((sizeof(unsigned long) == 8) ?
					(host_b2h_addr >> 32) : 0);
	dst_l = (unsigned int)(host_b2h_addr & 0xffffffff);
	(void)start_transfer_b2h(edma_host,
		bmc_addr->dma_data_len, src_h,
		src_l, dst_h, dst_l);

	(void)mod_timer(&edma_host->dma_timer,
			jiffies_64 + TIMER_INTERVAL_CHECK);

	ret = wait_event_interruptible_timeout(edma_host->wq_dmab2h,
					       (edma_host->b2h_state ==
					      B2HSTATE_IDLE),
					     EDMA_DMA_TRANSFER_WAIT_TIMEOUT);

	if (ret == -ERESTARTSYS) {
		BMA_LOG(DLOG_ERROR, "eintr 1\n");
		ret = -EINTR;
		goto end;
	} else if (ret == 0) {
		BMA_LOG(DLOG_ERROR, "timeout 2\n");
		ret = -ETIMEDOUT;
		goto end;
	} else {
		BMA_LOG(DLOG_DEBUG, "h2b dma successful\n");
	}

end:

	return ret;
}
#endif

void host_dma_transfer_without_list(struct edma_host_s *edma_host,
				    struct bma_dma_transfer_s *dma_transfer,
					int *return_code)
{
#ifdef USE_DMA
	union transfer_u *transfer = &dma_transfer->transfer;

	switch (dma_transfer->dir) {
	case BMC_TO_HOST:
		*return_code = edma_host_dma_b2h(edma_host,
						 &transfer->nolist.host_addr,
						 &transfer->nolist.bmc_addr);
		break;
	case HOST_TO_BMC:
		*return_code = edma_host_dma_h2b(edma_host,
						 &transfer->nolist.host_addr,
						 &transfer->nolist.bmc_addr);
		break;
	default:
		BMA_LOG(DLOG_ERROR, "direction failed, dir = %d\n",
			dma_transfer->dir);
		*return_code = -EFAULT;
		break;
	}
#endif
}

void host_dma_transfer_withlist(struct edma_host_s *edma_host,
				struct bma_dma_transfer_s *dma_transfer,
					int *return_code)
{
	unsigned int list_h = 0;
	unsigned int list_l = 0;
	union transfer_u *transfer = &dma_transfer->transfer;

	list_h = (unsigned int)((sizeof(unsigned long) == 8) ?
			(transfer->list.dma_addr >> 32) : 0);
	list_l = (unsigned int)(transfer->list.dma_addr
				& 0xffffffff);

	switch (dma_transfer->dir) {
	case BMC_TO_HOST:
		start_listtransfer_b2h(edma_host, list_h, list_l);
		break;
	case HOST_TO_BMC:
		start_listtransfer_h2b(edma_host, list_h, list_l);
		break;
	default:
		BMA_LOG(DLOG_ERROR, "direction failed, dir = %d\n\n",
			dma_transfer->dir);
		*return_code = -EFAULT;
		break;
	}
}

int edma_host_dma_transfer(struct edma_host_s *edma_host,
			   struct bma_priv_data_s *priv,
			   struct bma_dma_transfer_s *dma_transfer)
{
	int ret = 0;
	unsigned long flags = 0;
	struct bma_dev_s *bma_dev = NULL;

	if (!edma_host || !priv || !dma_transfer)
		return -EFAULT;

	bma_dev = list_entry(edma_host, struct bma_dev_s, edma_host);

	spin_lock_irqsave(&bma_dev->priv_list_lock, flags);

	if (priv->user.dma_transfer == 0) {
		spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);
		BMA_LOG(DLOG_ERROR, "dma_transfer = %hhd\n",
			priv->user.dma_transfer);
		return -EFAULT;
	}

	spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);

	edma_host->statistics.dma_count++;

	if (dma_transfer->type == DMA_NOT_LIST) {
		host_dma_transfer_without_list(edma_host,
					       dma_transfer, &ret);
	} else if (dma_transfer->type == DMA_LIST) {
		host_dma_transfer_withlist(edma_host, dma_transfer, &ret);
	} else {
		BMA_LOG(DLOG_ERROR, "type failed! type = %d\n",
			dma_transfer->type);
		return -EFAULT;
	}

	return ret;
}

void edma_host_reset_dma(struct edma_host_s *edma_host, int dir)
{
	u32 data = 0;
	u32 reg_addr = 0;
	unsigned long flags = 0;
	int count = 0;
	struct pci_dev *pdev = NULL;

	if (!edma_host)
		return;

	pdev = edma_host->pdev;
	if (!pdev)
		return;

	if (dir == BMC_TO_HOST)
		reg_addr = REG_PCIE1_DMA_READ_ENGINE_ENABLE;
	else if (dir == HOST_TO_BMC)
		reg_addr = REG_PCIE1_DMA_WRITE_ENGINE_ENABLE;
	else
		return;

	spin_lock_irqsave(&edma_host->reg_lock, flags);

	(void)pci_read_config_dword(pdev, reg_addr, &data);
	data &= ~(1 << SHIFT_PCIE1_DMA_ENGINE_ENABLE);
	(void)pci_write_config_dword(pdev, reg_addr, data);

	while (count++ < 10) {
		(void)pci_read_config_dword(pdev, reg_addr, &data);

		if (0 == (data & (1 << SHIFT_PCIE1_DMA_ENGINE_ENABLE))) {
			BMA_LOG(DLOG_DEBUG, "reset dma succesfull\n");
			break;
		}

		mdelay(100);
	}

	spin_unlock_irqrestore(&edma_host->reg_lock, flags);
	BMA_LOG(DLOG_DEBUG, "reset dma reg_addr=0x%x count=%d data=0x%08x\n",
		reg_addr, count, data);
}

int edma_host_dma_stop(struct edma_host_s *edma_host,
		       struct bma_priv_data_s *priv)
{
	unsigned long flags = 0;
	struct bma_dev_s *bma_dev = NULL;

	if (!edma_host || !priv)
		return -1;

	bma_dev = list_entry(edma_host, struct bma_dev_s, edma_host);

	spin_lock_irqsave(&bma_dev->priv_list_lock, flags);
	priv->user.dma_transfer = 0;
	spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);

	return 0;
}

static int edma_host_send_msg(struct edma_host_s *edma_host)
{
	void *vaddr = NULL;
	unsigned long flags = 0;
	struct edma_mbx_hdr_s *send_mbx_hdr = NULL;
	static unsigned long last_timer_record;

	if (!edma_host)
		return 0;

	send_mbx_hdr = (struct edma_mbx_hdr_s *)edma_host->edma_send_addr;

	if (send_mbx_hdr->mbxlen > 0) {
		if (send_mbx_hdr->mbxlen > HOST_MAX_SEND_MBX_LEN) {
			/*share memory is disable */
			send_mbx_hdr->mbxlen = 0;
			BMA_LOG(DLOG_ERROR, "mbxlen is too long\n");
			return -EFAULT;
		}

		if (time_after(jiffies, last_timer_record + 10 * HZ)) {
			BMA_LOG(DLOG_ERROR, "no response in 10s,clean msg\n");
			edma_host->statistics.failed_count++;
			send_mbx_hdr->mbxlen = 0;
			return -EFAULT;
		}

		BMA_LOG(DLOG_DEBUG,
			"still have msg : mbxlen: %d, msg_send_write: %d\n",
			send_mbx_hdr->mbxlen, edma_host->msg_send_write);

		/*  resend door bell */
		if (time_after(jiffies, last_timer_record + 5 * HZ))
			edma_host_int_to_bmc(edma_host);

		return -EFAULT;
	}

	vaddr =
		(void *)((unsigned char *)edma_host->edma_send_addr +
			 SIZE_OF_MBX_HDR);

	last_timer_record = jiffies;

	spin_lock_irqsave(&edma_host->send_msg_lock, flags);

	if (edma_host->msg_send_write == 0) {
		spin_unlock_irqrestore(&edma_host->send_msg_lock, flags);
		return 0;
	}

	if (edma_host->msg_send_write >
	    HOST_MAX_SEND_MBX_LEN - SIZE_OF_MBX_HDR) {
		BMA_LOG(DLOG_ERROR,
			"Length of send message %u is larger than %zu\n",
			edma_host->msg_send_write,
			HOST_MAX_SEND_MBX_LEN - SIZE_OF_MBX_HDR);
		edma_host->msg_send_write = 0;
		spin_unlock_irqrestore(&edma_host->send_msg_lock, flags);
		return 0;
	}

	memcpy(vaddr, edma_host->msg_send_buf,
	       edma_host->msg_send_write);

	send_mbx_hdr->mbxlen = edma_host->msg_send_write;
	edma_host->msg_send_write = 0;

	spin_unlock_irqrestore(&edma_host->send_msg_lock, flags);

	edma_host_int_to_bmc(edma_host);

	BMA_LOG(DLOG_DEBUG,
		"vaddr: %p, mbxlen : %d, msg_send_write: %d\n", vaddr,
		send_mbx_hdr->mbxlen, edma_host->msg_send_write);

	return -EAGAIN;
}

#ifdef EDMA_TIMER
#ifdef HAVE_TIMER_SETUP
static void edma_host_timeout(struct timer_list *t)
{
	struct edma_host_s *edma_host = from_timer(edma_host, t, timer);
#else
static void edma_host_timeout(unsigned long data)
{
	struct edma_host_s *edma_host = (struct edma_host_s *)data;
#endif
	int ret = 0;
	unsigned long flags = 0;

	ret = edma_host_send_msg(edma_host);
	if (ret < 0) {
		spin_lock_irqsave(&g_bma_dev->edma_host.send_msg_lock, flags);
		(void)mod_timer(&edma_host->timer,
				jiffies_64 + TIMER_INTERVAL_CHECK);
		spin_unlock_irqrestore(&edma_host->send_msg_lock, flags);
	}
}

#ifdef HAVE_TIMER_SETUP
static void edma_host_heartbeat_timer(struct timer_list *t)
{
	struct edma_host_s *edma_host = from_timer(edma_host, t,
						    heartbeat_timer);
#else
static void edma_host_heartbeat_timer(unsigned long data)
{
	struct edma_host_s *edma_host = (struct edma_host_s *)data;
#endif
	struct edma_statistics_s *edma_stats = &edma_host->statistics;
	unsigned int *remote_status = &edma_stats->remote_status;
	static unsigned int bmc_heartbeat;
	struct notify_msg *pnm = (struct notify_msg *)edma_host->edma_flag;

	if (pnm) {
		if (pnm->bmc_registered) {
			if ((pnm->host_heartbeat & 7) == 0) {
				if (bmc_heartbeat != pnm->bmc_heartbeat) {
					if (*remote_status != REGISTERED) {
						BMA_LOG(DLOG_DEBUG,
							"bmc is registered\n");
						*remote_status = REGISTERED;
					}

					bmc_heartbeat = pnm->bmc_heartbeat;
				} else {
					if (*remote_status == REGISTERED) {
						*remote_status = LOST;
						edma_stats->lost_count++;
						BMA_LOG(DLOG_DEBUG,
							"bmc is lost\n");
					}
				}
			}
		} else {
			if (*remote_status == REGISTERED)
				BMA_LOG(DLOG_DEBUG, "bmc is deregistered\n");

			*remote_status = DEREGISTERED;
		}

		pnm->host_heartbeat++;
	}

	(void)mod_timer(&edma_host->heartbeat_timer,
			jiffies_64 + HEARTBEAT_TIMER_INTERVAL_CHECK);
}

#ifdef USE_DMA
#ifdef HAVE_TIMER_SETUP
static void edma_host_dma_timeout(struct timer_list *t)
{
	struct edma_host_s *edma_host = from_timer(edma_host, t, dma_timer);
#else
static void edma_host_dma_timeout(unsigned long data)
{
	struct edma_host_s *edma_host = (struct edma_host_s *)data;
#endif
	int ret = 0;

	ret = edma_host_dma_interrupt(edma_host);
	if (ret < 0)
		(void)mod_timer(&edma_host->dma_timer,
				jiffies_64 + DMA_TIMER_INTERVAL_CHECK);
}
#endif
#else

static int edma_host_thread(void *arg)
{
	struct edma_host_s *edma_host = (struct edma_host_s *)arg;

	BMA_LOG(DLOG_ERROR, "edma host thread\n");

	while (!kthread_should_stop()) {
		wait_for_completion_interruptible_timeout(&edma_host->msg_ready,
							  1 * HZ);
		edma_host_send_msg(edma_host);
		(void)edma_host_dma_interrupt(edma_host);
	}

	BMA_LOG(DLOG_ERROR, "edma host thread exiting\n");

	return 0;
}

#endif

int edma_host_send_driver_msg(const void *msg, size_t msg_len, int subtype)
{
	int ret = 0;
	unsigned long flags = 0;
	struct edma_host_s *edma_host = NULL;
	struct edma_msg_hdr_s *hdr = NULL;
	int total_len = msg_len + SIZE_OF_MSG_HDR;

	if (!msg || !g_bma_dev)
		return -1;

	edma_host = &g_bma_dev->edma_host;
	if (!edma_host)
		return -1;

	spin_lock_irqsave(&edma_host->send_msg_lock, flags);

	if (edma_host->msg_send_write + total_len <=
	    (HOST_MAX_SEND_MBX_LEN - SIZE_OF_MBX_HDR)) {
		hdr = (struct edma_msg_hdr_s *)(edma_host->msg_send_buf +
					      edma_host->msg_send_write);
		hdr->type = TYPE_EDMA_DRIVER;
		hdr->sub_type = subtype;
		hdr->datalen = msg_len;

		memcpy(hdr->data, msg, msg_len);

		edma_host->msg_send_write += total_len;

		spin_unlock_irqrestore(&edma_host->send_msg_lock, flags);

		(void)mod_timer(&edma_host->timer, jiffies_64);
		BMA_LOG(DLOG_DEBUG, "msg_send_write = %d\n",
			edma_host->msg_send_write);
	} else {
		ret = -ENOSPC;
		spin_unlock_irqrestore(&edma_host->send_msg_lock, flags);

		BMA_LOG(DLOG_DEBUG,
			"msg lost,msg_send_write: %d,msg_len:%d,max_len: %d\n",
			edma_host->msg_send_write, total_len,
			HOST_MAX_SEND_MBX_LEN);
	}

	return ret;
}

static int edma_host_insert_recv_msg(struct edma_host_s *edma_host,
				     struct edma_msg_hdr_s *msg_header)
{
	unsigned long flags = 0, msg_flags = 0;
	struct bma_dev_s *bma_dev = NULL;
	struct bma_priv_data_s *priv = NULL;
	struct bma_user_s *puser = NULL;
	struct list_head *entry = NULL;
	struct edma_recv_msg_s *msg_tmp = NULL;
	struct bma_user_s usertmp = { };
	struct edma_recv_msg_s *recv_msg = NULL;

	if (!edma_host || !msg_header ||
	    msg_header->datalen > CDEV_MAX_WRITE_LEN) {
		return -EFAULT;
	}

	bma_dev = list_entry(edma_host, struct bma_dev_s, edma_host);

	recv_msg = kmalloc(sizeof(*recv_msg) + msg_header->datalen, GFP_ATOMIC);
	if (!recv_msg) {
		BMA_LOG(DLOG_ERROR, "malloc recv_msg failed\n");
		return -ENOMEM;
	}

	recv_msg->msg_len = msg_header->datalen;
	memcpy(recv_msg->msg_data, msg_header->data,
	       msg_header->datalen);

	spin_lock_irqsave(&bma_dev->priv_list_lock, flags);
	list_for_each_entry_rcu(puser, &bma_dev->priv_list, link) {
		if (puser->type != msg_header->type ||
		    puser->sub_type != msg_header->sub_type)
			continue;

		priv = list_entry(puser, struct bma_priv_data_s, user);

		memcpy(&usertmp, puser,
		       sizeof(struct bma_user_s));

		spin_lock_irqsave(&priv->recv_msg_lock, msg_flags);

		if (puser->cur_recvmsg_nums >= puser->max_recvmsg_nums ||
		    puser->cur_recvmsg_nums >= MAX_RECV_MSG_NUMS) {
			entry = priv->recv_msgs.next;
			msg_tmp =
			    list_entry(entry, struct edma_recv_msg_s,
				       link);
			list_del(entry);
			puser->cur_recvmsg_nums--;
			kfree(msg_tmp);
		}

		if (edma_host->local_open_status[puser->type]
			== DEV_OPEN) {
			list_add_tail(&recv_msg->link, &priv->recv_msgs);
			puser->cur_recvmsg_nums++;
			usertmp.cur_recvmsg_nums =
			    puser->cur_recvmsg_nums;
			spin_unlock_irqrestore(&priv->recv_msg_lock,
					       msg_flags);

		} else {
			spin_unlock_irqrestore(&priv->recv_msg_lock,
					       msg_flags);
			break;
		}

		wake_up_interruptible(&priv->wait);
		spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);

		BMA_LOG(DLOG_DEBUG,
			"find user, type = %d, sub_type = %d, user_id = %d, insert msg\n",
			usertmp.type, usertmp.sub_type,
			usertmp.user_id);
		BMA_LOG(DLOG_DEBUG,
			"msg_len = %d, cur_recvmsg_nums: %d, max_recvmsg_nums: %d\n",
			recv_msg->msg_len, usertmp.cur_recvmsg_nums,
			usertmp.max_recvmsg_nums);

		return 0;
	}

	spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);
	kfree(recv_msg);
	edma_host->statistics.drop_pkgs++;
	BMA_LOG(DLOG_DEBUG,
		"insert msg failed! not find user, type = %d, sub_type = %d\n",
		msg_header->type, msg_header->sub_type);

	return -EFAULT;
}

int edma_host_recv_msg(struct edma_host_s *edma_host,
		       struct bma_priv_data_s *priv,
		       struct edma_recv_msg_s **msg)
{
	unsigned long flags = 0;
	struct list_head *entry = NULL;
	struct edma_recv_msg_s *msg_tmp = NULL;
	struct bma_dev_s *bma_dev = NULL;

	if (!edma_host || !priv || !msg)
		return -EAGAIN;

	bma_dev = list_entry(edma_host, struct bma_dev_s, edma_host);

	spin_lock_irqsave(&bma_dev->priv_list_lock, flags);

	if (list_empty(&priv->recv_msgs)) {
		priv->user.cur_recvmsg_nums = 0;
		spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);
		BMA_LOG(DLOG_DEBUG, "recv msgs empty\n");
		return -EAGAIN;
	}

	entry = priv->recv_msgs.next;
	msg_tmp = list_entry(entry, struct edma_recv_msg_s, link);
	list_del(entry);

	if (priv->user.cur_recvmsg_nums > 0)
		priv->user.cur_recvmsg_nums--;

	spin_unlock_irqrestore(&bma_dev->priv_list_lock, flags);

	*msg = msg_tmp;

	BMA_LOG(DLOG_DEBUG, "msg->msg_len = %d\n", (int)msg_tmp->msg_len);

	return 0;
}

static int edma_host_msg_process(struct edma_host_s *edma_host,
				 struct edma_msg_hdr_s *msg_header)
{
	struct bma_user_s *user_ptr = NULL;
	char drv_msg[TYPE_MAX * 2 + 1] = { 0 };

	if (!edma_host || !msg_header)
		return 0;

	if (msg_header->type != TYPE_EDMA_DRIVER)
		return -1;

	if (msg_header->sub_type != DEV_OPEN_STATUS_REQ)
		return 0;

	list_for_each_entry_rcu(user_ptr, &g_bma_dev->priv_list, link) {
		drv_msg[drv_msg[0] * 2 + 1] = user_ptr->type;
		drv_msg[drv_msg[0] * 2 + 2] =
		    edma_host->local_open_status[user_ptr->type];
		BMA_LOG(DLOG_DEBUG,
			"send DEV_OPEN_STATUS_ANS index=%d type=%d status=%d\n",
			drv_msg[0], drv_msg[drv_msg[0] * 2 + 1],
			drv_msg[drv_msg[0] * 2 + 2]);
		drv_msg[0]++;
	}

	if (drv_msg[0]) {
		(void)edma_host_send_driver_msg((void *)drv_msg,
						drv_msg[0] * 2 +
						1,
						DEV_OPEN_STATUS_ANS);
		BMA_LOG(DLOG_DEBUG,
			"send DEV_OPEN_STATUS_ANS %d\n",
			drv_msg[0]);
	}

	return 0;
}

void edma_host_isr_tasklet(unsigned long data)
{
	int result = 0;
	u16 len = 0;
	u16 off = 0;
	u16 msg_cnt = 0;
	struct edma_mbx_hdr_s *recv_mbx_hdr = NULL;
	struct edma_host_s *edma_host = (struct edma_host_s *)data;
	struct edma_msg_hdr_s *msg_header = NULL;
	unsigned char *ptr = NULL;

	if (!edma_host)
		return;

	recv_mbx_hdr = (struct edma_mbx_hdr_s *)(edma_host->edma_recv_addr);
	msg_header =
		(struct edma_msg_hdr_s *)((char *)(edma_host->edma_recv_addr) +
				SIZE_OF_MBX_HDR + recv_mbx_hdr->mbxoff);

	off = readw((unsigned char *)edma_host->edma_recv_addr
				+ EDMA_B2H_INT_FLAG);
	len = readw((unsigned char *)edma_host->edma_recv_addr) - off;

	BMA_LOG(DLOG_DEBUG,
		" edma_host->edma_recv_addr = %p, len = %d, off = %d, mbxlen = %d\n",
		edma_host->edma_recv_addr, len, off, recv_mbx_hdr->mbxlen);
	edma_host->statistics.recv_bytes += (recv_mbx_hdr->mbxlen - off);

	if (len == 0) {
		writel(0, (void *)(edma_host->edma_recv_addr));
		return;
	}

	while (recv_mbx_hdr->mbxlen - off) {
		if (len == 0) {
			BMA_LOG(DLOG_DEBUG, " receive done\n");
			break;
		}

		if (len < (SIZE_OF_MSG_HDR + msg_header->datalen)) {
			BMA_LOG(DLOG_ERROR, " len too less, is %d\n", len);
			break;
		}

		edma_host->statistics.recv_pkgs++;

		if (edma_host_msg_process(edma_host, msg_header) == -1) {
			result = edma_host_insert_recv_msg(edma_host,
							   msg_header);
			if (result < 0)
				BMA_LOG(DLOG_DEBUG,
					"edma_host_insert_recv_msg failed\n");
		}

		BMA_LOG(DLOG_DEBUG, "len = %d\n", len);
		BMA_LOG(DLOG_DEBUG, "off = %d\n", off);
		len -= (msg_header->datalen + SIZE_OF_MSG_HDR);
		BMA_LOG(DLOG_DEBUG,
			"msg_header->datalen = %d, SIZE_OF_MSG_HDR=%d\n",
			msg_header->datalen, (int)SIZE_OF_MSG_HDR);
		off += (msg_header->datalen + SIZE_OF_MSG_HDR);

		msg_cnt++;

		ptr = (unsigned char *)msg_header;
		msg_header = (struct edma_msg_hdr_s *)(ptr +
					      (msg_header->datalen +
					       SIZE_OF_MSG_HDR));

		if (msg_cnt > 2) {
			recv_mbx_hdr->mbxoff = off;
			BMA_LOG(DLOG_DEBUG, "len = %d\n", len);
			BMA_LOG(DLOG_DEBUG, "off = %d\n", off);
			BMA_LOG(DLOG_DEBUG, "off works\n");

			tasklet_hi_schedule(&edma_host->tasklet);

			break;
		}

		if (!len) {
			writel(0, (void *)(edma_host->edma_recv_addr));
			recv_mbx_hdr->mbxoff = 0;
		}
	}
}

static int edma_host_dma_interrupt(struct edma_host_s *edma_host)
{
	if (!edma_host)
		return 0;

	if (check_status_dmah2b(edma_host)) {
		clear_int_dmah2b(edma_host);

		edma_host->h2b_state = H2BSTATE_IDLE;
		wake_up_interruptible(&edma_host->wq_dmah2b);
		return 0;
	}

	if (check_status_dmab2h(edma_host)) {
		clear_int_dmab2h(edma_host);

		edma_host->b2h_state = B2HSTATE_IDLE;
		wake_up_interruptible(&edma_host->wq_dmab2h);

		return 0;
	}

	return -EAGAIN;
}

irqreturn_t edma_host_irq_handle(struct edma_host_s *edma_host)
{
	if (edma_host) {
		(void)edma_host_dma_interrupt(edma_host);

		tasklet_hi_schedule(&edma_host->tasklet);
	}

	return IRQ_HANDLED;
}

struct edma_user_inft_s *edma_host_get_user_inft(u32 type)
{
	if (type >= TYPE_MAX) {
		BMA_LOG(DLOG_ERROR, "type error %d\n", type);
		return NULL;
	}

	return g_user_func[type];
}

int edma_host_user_register(u32 type, struct edma_user_inft_s *func)
{
	if (type >= TYPE_MAX) {
		BMA_LOG(DLOG_ERROR, "type error %d\n", type);
		return -EFAULT;
	}

	if (!func) {
		BMA_LOG(DLOG_ERROR, "func is NULL\n");
		return -EFAULT;
	}

	g_user_func[type] = func;

	return 0;
}

int edma_host_user_unregister(u32 type)
{
	if (type >= TYPE_MAX) {
		BMA_LOG(DLOG_ERROR, "type error %d\n", type);
		return -EFAULT;
	}

	g_user_func[type] = NULL;

	return 0;
}

int edma_host_init(struct edma_host_s *edma_host)
{
	int ret = 0;
	struct bma_dev_s *bma_dev = NULL;
	struct notify_msg *pnm = NULL;

	if (!edma_host)
		return -1;

	bma_dev = list_entry(edma_host, struct bma_dev_s, edma_host);
	g_bma_dev = bma_dev;

	edma_host->pdev = bma_dev->bma_pci_dev->pdev;

#ifdef EDMA_TIMER
	#ifdef HAVE_TIMER_SETUP
		timer_setup(&edma_host->timer, edma_host_timeout, 0);
	#else
		setup_timer(&edma_host->timer, edma_host_timeout,
			    (unsigned long)edma_host);
	#endif
	(void)mod_timer(&edma_host->timer, jiffies_64 + TIMER_INTERVAL_CHECK);
#ifdef USE_DMA
	#ifdef HAVE_TIMER_SETUP
		timer_setup(&edma_host->dma_timer, edma_host_dma_timeout, 0);

	#else
		setup_timer(&edma_host->dma_timer, edma_host_dma_timeout,
			    (unsigned long)edma_host);
	#endif
	(void)mod_timer(&edma_host->dma_timer,
			jiffies_64 + DMA_TIMER_INTERVAL_CHECK);
#endif

#else
	init_completion(&edma_host->msg_ready);

	edma_host->edma_thread =
	    kthread_run(edma_host_thread, (void *)edma_host, "edma_host_msg");

	if (IS_ERR(edma_host->edma_thread)) {
		BMA_LOG(DLOG_ERROR, "kernel_run  edma_host_msg failed\n");
		return PTR_ERR(edma_host->edma_thread);
	}
#endif

	edma_host->msg_send_buf = kmalloc(HOST_MAX_SEND_MBX_LEN, GFP_KERNEL);
	if (!edma_host->msg_send_buf) {
		BMA_LOG(DLOG_ERROR, "malloc msg_send_buf failed!");
		ret = -ENOMEM;
		goto failed1;
	}

	edma_host->msg_send_write = 0;

	spin_lock_init(&edma_host->send_msg_lock);

	tasklet_init(&edma_host->tasklet,
		     (void (*)(unsigned long))edma_host_isr_tasklet,
		     (unsigned long)edma_host);

	edma_host->edma_flag = bma_dev->bma_pci_dev->edma_swap_addr;

	edma_host->edma_send_addr =
	    (void *)((unsigned char *)bma_dev->bma_pci_dev->edma_swap_addr +
		     HOST_DMA_FLAG_LEN);
	memset(edma_host->edma_send_addr, 0, SIZE_OF_MBX_HDR);

	edma_host->edma_recv_addr =
	    (void *)((unsigned char *)edma_host->edma_send_addr +
		     HOST_MAX_SEND_MBX_LEN);

	BMA_LOG(DLOG_DEBUG,
		"edma_flag = %p, edma_send_addr = %p, edma_recv_addr = %p\n",
		edma_host->edma_flag, edma_host->edma_send_addr,
		edma_host->edma_recv_addr);

	edma_host->hostrtc_viraddr = bma_dev->bma_pci_dev->hostrtc_viraddr;

	init_waitqueue_head(&edma_host->wq_dmah2b);
	init_waitqueue_head(&edma_host->wq_dmab2h);

	spin_lock_init(&edma_host->reg_lock);

	edma_host->h2b_state = H2BSTATE_IDLE;
	edma_host->b2h_state = B2HSTATE_IDLE;

	#ifdef HAVE_TIMER_SETUP
		timer_setup(&edma_host->heartbeat_timer,
			    edma_host_heartbeat_timer, 0);
	#else
		setup_timer(&edma_host->heartbeat_timer,
			    edma_host_heartbeat_timer,
			    (unsigned long)edma_host);
	#endif
	(void)mod_timer(&edma_host->heartbeat_timer,
			jiffies_64 + HEARTBEAT_TIMER_INTERVAL_CHECK);

	pnm = (struct notify_msg *)edma_host->edma_flag;
	if (pnm)
		pnm->host_registered = REGISTERED;

	GET_SYS_SECONDS(edma_host->statistics.init_time);

#ifdef EDMA_TIMER
	BMA_LOG(DLOG_DEBUG, "timer ok\n");
#else
	BMA_LOG(DLOG_ERROR, "thread ok\n");
#endif
	return 0;

failed1:
#ifdef EDMA_TIMER
	(void)del_timer_sync(&edma_host->timer);
#ifdef USE_DMA
	(void)del_timer_sync(&edma_host->dma_timer);
#endif
#else
	kthread_stop(edma_host->edma_thread);
	complete(&edma_host->msg_ready);
#endif
	return ret;
}

void edma_host_cleanup(struct edma_host_s *edma_host)
{
	struct bma_dev_s *bma_dev = NULL;
	struct notify_msg *pnm = NULL;

	if (!edma_host)
		return;

	bma_dev = list_entry(edma_host, struct bma_dev_s, edma_host);
	(void)del_timer_sync(&edma_host->heartbeat_timer);
	pnm = (struct notify_msg *)edma_host->edma_flag;

	if (pnm)
		pnm->host_registered = DEREGISTERED;

	tasklet_kill(&edma_host->tasklet);

	kfree(edma_host->msg_send_buf);
	edma_host->msg_send_buf = NULL;
#ifdef EDMA_TIMER
	(void)del_timer_sync(&edma_host->timer);
#ifdef USE_DMA
	(void)del_timer_sync(&edma_host->dma_timer);
#endif

#else
	kthread_stop(edma_host->edma_thread);

	complete(&edma_host->msg_ready);
#endif
}
