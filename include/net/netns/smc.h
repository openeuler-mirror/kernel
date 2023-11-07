/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_SMC_H__
#define __NETNS_SMC_H__

struct netns_smc {
#ifdef CONFIG_SYSCTL
	struct ctl_table_header		*smc_hdr;
#endif
	unsigned int			sysctl_smcr_buf_type;
	int				sysctl_wmem;
	int				sysctl_rmem;
	int				sysctl_tcp2smc;
};
#endif
