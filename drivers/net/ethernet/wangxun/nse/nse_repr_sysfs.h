/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_REPR_SYSFS_H_
#define _NSE_REPR_SYSFS_H_

struct nse_rep_sysfs {
	struct kobject          kobj;
	bool  is_uplink;
	struct nse_pf *pf;
	struct nse_repr *repr;
	int vf_id;
};

void nse_create_uplink_sysfs(struct nse_pf *pf);
void nse_cleanup_uplink_sysfs(struct nse_pf *pf);

void nse_create_rep_sysfs(struct nse_repr *repr);
void nse_cleanup_rep_sysfs(struct nse_repr *repr);

#endif
