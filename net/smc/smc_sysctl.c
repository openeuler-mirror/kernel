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
#include "smc_core.h"

static int two = 2;
static int min_sndbuf = SMC_BUF_MIN_SIZE;
static int min_rcvbuf = SMC_BUF_MIN_SIZE;
static int max_sndbuf = INT_MAX / 2;
static int max_rcvbuf = INT_MAX / 2;
static const int net_smc_wmem_init = (64 * 1024);
static const int net_smc_rmem_init = (64 * 1024);

static struct ctl_table smc_table[] = {
	{
		.procname	= "smcr_buf_type",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &two,
	},
	{
		.procname	= "wmem",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_sndbuf,
		.extra2		= &max_sndbuf,
	},
	{
		.procname	= "rmem",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_rcvbuf,
		.extra2		= &max_rcvbuf,
	},
	{
		.procname	= "tcp2smc",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{  }
};

int sysctl_smcr_buf_type(struct net *net)
{
	return READ_ONCE(net->smc->sysctl_smcr_buf_type);
}

int sysctl_smcr_wmem(struct net *net)
{
	return READ_ONCE(net->smc->sysctl_wmem);
}

int sysctl_smcr_rmem(struct net *net)
{
	return READ_ONCE(net->smc->sysctl_rmem);
}

int __net_init smc_sysctl_net_init(struct net *net)
{
	struct ctl_table *table;
	int idx;

	table = smc_table;
	net->smc = kmalloc(sizeof(*net->smc), GFP_KERNEL);
	if (!net->smc)
		goto err_alloc;
	if (!net_eq(net, &init_net)) {
		table = kmemdup(table, sizeof(smc_table), GFP_KERNEL);
		if (!table)
			goto err_table;
	}

	idx = 0;
	net->smc->sysctl_smcr_buf_type = SMCR_PHYS_CONT_BUFS;
	table[idx++].data = &net->smc->sysctl_smcr_buf_type;
	WRITE_ONCE(net->smc->sysctl_wmem, net_smc_wmem_init);
	table[idx++].data = &net->smc->sysctl_wmem;
	WRITE_ONCE(net->smc->sysctl_rmem, net_smc_rmem_init);
	table[idx++].data = &net->smc->sysctl_rmem;
	net->smc->sysctl_tcp2smc = 0;
	table[idx++].data = &net->smc->sysctl_tcp2smc;

	net->smc->smc_hdr = register_net_sysctl(net, "net/smc", table);
	if (!net->smc->smc_hdr)
		goto err_reg;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_table:
	kfree(net->smc);
err_alloc:
	return -ENOMEM;
}

void __net_exit smc_sysctl_net_exit(struct net *net)
{
	struct ctl_table *table;

	table = net->smc->smc_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->smc->smc_hdr);
	if (!net_eq(net, &init_net))
		kfree(table);
	kfree(net->smc);
}
