/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_DEV_H_
#define _NBL_DEF_DEV_H_

#include "nbl_include.h"

#define NBL_DEV_OPS_TBL_TO_OPS(dev_ops_tbl)	((dev_ops_tbl)->ops)
#define NBL_DEV_OPS_TBL_TO_PRIV(dev_ops_tbl)	((dev_ops_tbl)->priv)

struct nbl_dev_ops {
};

struct nbl_dev_ops_tbl {
	struct nbl_dev_ops *ops;
	void *priv;
};

int nbl_dev_init(void *p, struct nbl_init_param *param);
void nbl_dev_remove(void *p);
int nbl_dev_start(void *p, struct nbl_init_param *param, bool probe_stage);
void nbl_dev_stop(void *p, bool remove_stage);
int nbl_dev_init_emp_class(void);
void nbl_dev_destroy_emp_class(void);

void nbl_dev_user_module_init(void);
void nbl_dev_user_module_destroy(void);
int nbl_dev_create_rep(void *p, int num_vfs);
int nbl_dev_destroy_rep(void *p);

int nbl_dev_setup_vf_config(void *p, int num_vfs);
void nbl_dev_remove_vf_config(void *p);
void nbl_dev_register_dev_name(void *p);
void nbl_dev_get_dev_name(void *p, char *dev_name);
int nbl_dev_resume(void *p);
int nbl_dev_suspend(void *p);
int nbl_dev_dump_ldev(void *p, struct seq_file *m);
#endif
