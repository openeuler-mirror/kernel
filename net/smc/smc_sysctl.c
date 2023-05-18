// SPDX-License-Identifier: GPL-2.0
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  smc_sysctl.c: sysctl interface to SMC subsystem.
 *
 *  Copyright (c) 2022, Alibaba Inc.
 *
 *  Author: Tony Lu <tonylu@linux.alibaba.com>
 *
 */

#include <linux/init.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>

#include "smc_sysctl.h"

static struct ctl_table smc_table[] = {
	{  }
};

int __net_init smc_sysctl_net_init(struct net *net)
{
	struct ctl_table *table;

	table = smc_table;
	if (!net_eq(net, &init_net)) {
		int i;

		table = kmemdup(table, sizeof(smc_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;

		for (i = 0; i < ARRAY_SIZE(smc_table) - 1; i++)
			table[i].data += (void *)net - (void *)&init_net;
	}

	net->smc.smc_hdr = register_net_sysctl(net, "net/smc", table);
	if (!net->smc.smc_hdr)
		goto err_reg;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

void __net_exit smc_sysctl_net_exit(struct net *net)
{
	struct ctl_table *table;

	table = net->smc.smc_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->smc.smc_hdr);
	if (!net_eq(net, &init_net))
		kfree(table);
}
