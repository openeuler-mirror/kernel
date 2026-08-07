// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kfifo.h>
#include <linux/err.h>
#include <linux/rwlock.h>
#include <linux/version.h>

#include "ubmempool_allocator.h"
#include "obmm_lowmem.h"

static struct notifier_block lowmem_nb;
#define LOWMEM_NOTIFY_PRIORITY 80

/* May be called by lowmem notifier at a very high frequency. */
static int obmm_lowmem_notify_handler(struct notifier_block *nb __always_unused,
				      unsigned long dummy __always_unused, void *parm)
{
	struct reclaim_notify_data *data = parm;
	bool is_huge = false;
	int i;

	if (!data)
		return NOTIFY_DONE;

	pr_debug_ratelimited("got lowmem message. pid=%d sync=%d reason=%u\n", current->pid,
			     data->sync, data->reason);

	if (data->reason != RR_DIRECT_RECLAIM &&
	    data->reason != RR_KSWAPD &&
	    data->reason != RR_HUGEPAGE_RECLAIM)
		return NOTIFY_DONE;

	if (data->reason == RR_HUGEPAGE_RECLAIM)
		is_huge = true;
	/* Accumulate: higher-priority notifiers may have already set nr_freed. */
	for (i = 0; i < data->nr_nid; i++) {
		pr_debug_ratelimited("contract memory on nid: %d\n", data->nid[i]);
		data->nr_freed += ubmempool_contract(data->nid[i], is_huge) >> PAGE_SHIFT;
	}

	return NOTIFY_OK;
}

int lowmem_notify_init(void)
{
	lowmem_nb.notifier_call = obmm_lowmem_notify_handler;
	lowmem_nb.priority = LOWMEM_NOTIFY_PRIORITY;
	return register_reclaim_notifier(&lowmem_nb);
}

void lowmem_notify_exit(void)
{
	unregister_reclaim_notifier(&lowmem_nb);
}
