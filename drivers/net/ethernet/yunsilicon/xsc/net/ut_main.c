// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "common/xsc_hsi.h"
#include "common/xsc_core.h"
#include "common/xsc_cmd.h"

#include "xsc_eth.h"
#include "xsc_accel.h"
#include <linux/kernel.h>
#include <linux/if_vlan.h>
#include "xsc_eth_txrx.h"
#include "xsc_eth_stats.h"
#include "xsc_eth_debug.h"

#ifdef NEED_CREATE_RX_THREAD

extern void xsc_cq_notify_hw(struct xsc_cq *cq);

DEFINE_PER_CPU(bool, txcqe_get);
EXPORT_PER_CPU_SYMBOL(txcqe_get);

u32 xsc_eth_process_napi(struct xsc_adapter *adapter)
{
	int work_done = 0;
	bool err = false;
	int budget = 1;
	int i, chl;
	int errtx = false;
	struct xsc_channel *c;
	struct xsc_rq *prq;
	struct xsc_ch_stats *ch_stats;

	if (adapter->status == XSCALE_ETH_DRIVER_OK) {
		for (chl = 0; chl < adapter->channels.num_chl; chl++) {
			c = &adapter->channels.c[chl];
			prq = &c->qp.rq[0];
			ch_stats = c->stats;
			ch_stats->poll++;

			for (i = 0; i < c->num_tc; i++) {
				errtx |= xsc_poll_tx_cq(&c->qp.sq[i].cq, budget);
				ETH_DEBUG_LOG("errtx=%u.\r\n", errtx);
				if (likely(__this_cpu_read(txcqe_get))) {
					xsc_cq_notify_hw(&c->qp.sq[i].cq);
					__this_cpu_write(txcqe_get, false);
				}
			}

			work_done = xsc_poll_rx_cq(&prq->cq, budget);

			ETH_DEBUG_LOG("work_done=%d.\r\n", work_done);

			if (work_done != 0) {
				xsc_cq_notify_hw(&prq->cq);
				err |= prq->post_wqes(prq);

				ETH_DEBUG_LOG("err=%u.\r\n", err);
			} else {
				ETH_DEBUG_LOG("no-load.\r\n");
			}

			ch_stats->arm++;
		}
	}

	return XSCALE_RET_SUCCESS;
}

int xsc_eth_rx_thread(void *arg)
{
	u32 ret = XSCALE_RET_SUCCESS;
	struct xsc_adapter *adapter = (struct xsc_adapter *)arg;

	while (kthread_should_stop() == 0) {
		if (need_resched())
			schedule();
		ret = xsc_eth_process_napi(adapter);
		if (ret != XSCALE_RET_SUCCESS)
			ETH_DEBUG_LOG("unexpected branch.\r\n");

		ETH_DEBUG_LOG("adapter=%p\r\n", adapter);
	}
	ETH_DEBUG_LOG("do_exit.\r\n");

	return XSCALE_RET_SUCCESS;
}

u32 g_thread_count;
u32 xsc_eth_rx_thread_create(struct xsc_adapter *adapter)
{
	struct task_struct *task = NULL;

	task = kthread_create(xsc_eth_rx_thread, (void *)adapter,
			      "xsc_rx%i", g_thread_count);
	if (!task)
		return XSCALE_RET_ERROR;

	ETH_DEBUG_LOG("thread_count=%d\r\n", g_thread_count);

	kthread_bind(task, g_thread_count);
	wake_up_process(task);
	adapter->task = task;

	g_thread_count++;

	return XSCALE_RET_SUCCESS;
}
#endif /* NEED_CREATE_RX_THREAD */
