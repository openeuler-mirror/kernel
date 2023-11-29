/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef _SMC_SYSCTL_H
#define _SMC_SYSCTL_H

#ifdef CONFIG_SYSCTL
int sysctl_smcr_buf_type(struct net *net);
int sysctl_smcr_wmem(struct net *net);
int sysctl_smcr_rmem(struct net *net);
int __net_init smc_sysctl_net_init(struct net *net);
void __net_exit smc_sysctl_net_exit(struct net *net);

#else
static inline int sysctl_smcr_buf_type(struct net *net)
{
	return SMCR_PHYS_CONT_BUFS;
}

static inline int sysctl_smcr_wmem(struct net *net)
{
	return SMC_BUF_MIN_SIZE;
}

static inline int sysctl_smcr_rmem(struct net *net)
{
	return SMC_RMB_DEF_SIZE;
}

static inline int smc_sysctl_net_init(struct net *net)
{
	return 0;
}

static inline void smc_sysctl_net_exit(struct net *net) { }

#endif /* CONFIG_SYSCTL */

#endif /* _SMC_SYSCTL_H */
