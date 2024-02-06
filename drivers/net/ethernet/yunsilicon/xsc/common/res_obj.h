/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef RES_OBJ_H
#define RES_OBJ_H

#include <linux/list.h>
#include <linux/radix-tree.h>
#include "common/xsc_core.h"

struct xsc_res_obj {
	struct list_head node;
	struct xsc_bdf_file *file;
	void (*release_method)(void *obj);
	char *data;
	unsigned int datalen;
};

struct xsc_pd_obj {
	struct xsc_res_obj obj;
	unsigned int pdn;
};

struct xsc_mr_obj {
	struct xsc_res_obj obj;
	unsigned int mkey;
};

struct xsc_cq_obj {
	struct xsc_res_obj obj;
	unsigned int cqn;
};

struct xsc_qp_obj {
	struct xsc_res_obj obj;
	unsigned int qpn;
};

struct xsc_pct_obj {
	struct xsc_res_obj obj;
	unsigned int pct_idx;
};

struct xsc_wct_obj {
	struct xsc_res_obj obj;
	unsigned int wct_idx;
};

struct xsc_em_obj {
	struct xsc_res_obj obj;
	unsigned int em_idx[54];
};

struct xsc_flow_pct_v4_add {
	char key[44];
	char mask[44];
	char ad[6];
	unsigned int priority;
};

struct xsc_flow_pct_v4_del {
	char key[44];
	char mask[44];
	unsigned int priority;
};

struct xsc_flow_pct_v6_add {
	char key[44];
	char mask[44];
	char ad[6];
	unsigned int priority;
};

struct xsc_flow_pct_v6_del {
	char key[44];
	char mask[44];
	unsigned int priority;
};

enum RES_OBJ_TYPE {
	RES_OBJ_PD,
	RES_OBJ_MR,
	RES_OBJ_CQ,
	RES_OBJ_QP,
	RES_OBJ_PCT,
	RES_OBJ_WCT,
	RES_OBJ_EM,
	RES_OBJ_MAX
};

static inline unsigned long xsc_idx_to_key(unsigned int obj_type, unsigned int idx)
{
	return ((unsigned long)obj_type << 32) | idx;
}

int xsc_alloc_pd_obj(struct xsc_bdf_file *file, unsigned int pdn,
		     char *data, unsigned int datalen);
void xsc_destroy_pd_obj(struct xsc_bdf_file *file, unsigned int pdn);

int xsc_alloc_mr_obj(struct xsc_bdf_file *file, unsigned int mkey,
		     char *data, unsigned int datalen);
void xsc_destroy_mr_obj(struct xsc_bdf_file *file, unsigned int mkey);

int xsc_alloc_cq_obj(struct xsc_bdf_file *file, unsigned int cqn,
		     char *data, unsigned int datalen);
void xsc_destroy_cq_obj(struct xsc_bdf_file *file, unsigned int cqn);

int xsc_alloc_qp_obj(struct xsc_bdf_file *file, unsigned int qpn,
		     char *data, unsigned int datalen);
void xsc_destroy_qp_obj(struct xsc_bdf_file *file, unsigned int qpn);

int xsc_alloc_pct_obj(struct xsc_bdf_file *file, unsigned int priority,
		      char *data, unsigned int datalen);
void xsc_destroy_pct_obj(struct xsc_bdf_file *file, unsigned int priority);

void xsc_close_bdf_file(struct xsc_bdf_file *file);

#endif
