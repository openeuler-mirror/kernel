/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_TC_CT_H_
#define _NSE_TC_CT_H_

struct nse_tc_flower_fltr;

#define NSE_CT_STATE_TRK_BIT BIT(0)
#define NSE_CT_STATE_ESTABLISHED_BIT BIT(1)
#define NSE_CT_STATE_REPLY_BIT BIT(2)
#define NSE_CT_STATE_NEW_BIT  BIT(3)

#define NSE_CT_CHAIN_ID		6
#define NSE_POST_CT_CHAIN_ID 7

#define NSE_CT_STATE_MDID   0 /*Generic MDID 0*/
#define NSE_CT_FTE_ID_MDID	1 /*Generic MDID 1*/
#define NSE_CT_ZONE_MDID	2 /*Generic MDID 2*/

#define NSE_FTE_ID_MAX 0xFFFF
#define NSE_CT_MAX_LUT_NUM 3

struct nse_tc_ct_priv {
	struct nse_pf *pf;

	/*unique entry id is used to bind pre ct entry and post ct entry*/
	struct idr fte_ids;

	struct rhashtable zone_ht;

	/* is used to get ct entry by slow path's skb*/
	struct rhashtable ct_tuples_ht;

	/* guards parallel adds/dels */
	struct mutex control_lock;

	/* guards ct entry parallel adds/dels */
	struct mutex ct_ctrl_lock;

	/* protects ft entries, including ct entry & tuple 2 hash tables */
	spinlock_t ht_lock;
};

int
nse_parse_tc_ct_match(struct net_device *filter_dev, struct nse_vsi *vsi,
			    struct flow_cls_offload *cls_flower,
			    struct nse_tc_flower_fltr *fltr);

int
nse_tc_ct_add_fltr(struct nse_vsi *vsi,	struct nse_tc_flower_fltr *fltr);

void
nse_tc_ct_del_fltr(struct nse_vsi *vsi,	struct nse_tc_flower_fltr *fltr);

int nse_tc_ct_init(struct nse_pf *pf);

int nse_tc_ct_cleanup(struct nse_pf *pf);

#endif

