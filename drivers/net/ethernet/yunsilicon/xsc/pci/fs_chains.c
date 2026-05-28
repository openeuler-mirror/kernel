// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "fs_chains.h"
#include "fs_ft_pool.h"
#include "common/fs_core.h"
#include "common/xsc_eswitch.h"
//#include "common/tc_priv.h"
#include "common/fs_cmd.h"
#include "common/vport.h"

#define chains_lock(chains) ((chains)->lock)
#define chains_ht(chains) ((chains)->chains_ht)
#define prios_ht(chains) ((chains)->prios_ht)
#define chains_default_ft(chains) ((chains)->chains_default_ft)
#define chains_end_ft(chains) ((chains)->chains_end_ft)
#define FT_TBL_SZ (64 * 1024)

struct xsc_fs_chains {
	struct xsc_core_device *dev;

	struct rhashtable chains_ht;
	struct rhashtable prios_ht;
	/* Protects above chains_ht and prios_ht */
	struct mutex lock;

	struct xsc_flow_table *chains_default_ft;
	struct xsc_flow_table *chains_end_ft;
	struct mapping_ctx *chains_mapping;

	enum xsc_flow_namespace_type ns;
	u32 group_num;
	u32 flags;
	int fs_base_prio;
	int fs_base_level;
};

struct fs_chain {
	struct rhash_head node;

	u32 chain;

	int ref;
	int id;

	struct xsc_fs_chains *chains;
	struct list_head prios_list;
	struct xsc_flow_handle *restore_rule;
	struct xsc_modify_hdr *miss_modify_hdr;
};

struct prio_key {
	u32 chain;
	u32 prio;
	u32 level;
};

struct prio {
	struct rhash_head node;
	struct list_head list;

	struct prio_key key;

	int ref;

	struct fs_chain *chain;
	struct xsc_flow_table *ft;
	struct xsc_flow_table *next_ft;
	struct xsc_flow_group *miss_group;
	struct xsc_flow_handle *miss_rule;
};

static const struct rhashtable_params chain_params = {
	.head_offset = offsetof(struct fs_chain, node),
	.key_offset = offsetof(struct fs_chain, chain),
	.key_len = sizeof_field(struct fs_chain, chain),
	.automatic_shrinking = true,
};

static const struct rhashtable_params prio_params = {
	.head_offset = offsetof(struct prio, node),
	.key_offset = offsetof(struct prio, key),
	.key_len = sizeof_field(struct prio, key),
	.automatic_shrinking = true,
};

bool xsc_chains_prios_supported(struct xsc_fs_chains *chains)
{
	return chains->flags & XSC_CHAINS_AND_PRIOS_SUPPORTED;
}
EXPORT_SYMBOL(xsc_chains_prios_supported);

bool xsc_chains_ignore_flow_level_supported(struct xsc_fs_chains *chains)
{
	return chains->flags & XSC_CHAINS_IGNORE_FLOW_LEVEL_SUPPORTED;
}
EXPORT_SYMBOL(xsc_chains_ignore_flow_level_supported);

bool xsc_chains_backwards_supported(struct xsc_fs_chains *chains)
{
	return xsc_chains_prios_supported(chains) &&
	       xsc_chains_ignore_flow_level_supported(chains);
}
EXPORT_SYMBOL(xsc_chains_backwards_supported);

u32 xsc_chains_get_chain_range(struct xsc_fs_chains *chains)
{
	if (!xsc_chains_prios_supported(chains))
		return 1;

	if (xsc_chains_ignore_flow_level_supported(chains))
		return UINT_MAX - 1;

	/* We should get here only for eswitch case */
	return FDB_TC_MAX_CHAIN;
}
EXPORT_SYMBOL(xsc_chains_get_chain_range);

u32 xsc_chains_get_nf_ft_chain(struct xsc_fs_chains *chains)
{
	return xsc_chains_get_chain_range(chains) + 1;
}
EXPORT_SYMBOL(xsc_chains_get_nf_ft_chain);

u32 xsc_chains_get_prio_range(struct xsc_fs_chains *chains)
{
	if (xsc_chains_ignore_flow_level_supported(chains))
		return UINT_MAX;

	if (!chains->dev->priv.eswitch ||
	    chains->dev->priv.eswitch->mode != XSC_ESWITCH_OFFLOADS)
		return 1;

	/* We should get here only for eswitch case */
	return FDB_TC_MAX_PRIO;
}
EXPORT_SYMBOL(xsc_chains_get_prio_range);

static unsigned int xsc_chains_get_level_range(struct xsc_fs_chains *chains)
{
	if (xsc_chains_ignore_flow_level_supported(chains))
		return UINT_MAX;

	/* Same value for FDB and NIC RX tables */
	return FDB_TC_LEVELS_PER_PRIO;
}

void xsc_chains_set_end_ft(struct xsc_fs_chains *chains, struct xsc_flow_table *ft)
{
	chains_end_ft(chains) = ft;
}

static struct xsc_flow_table *xsc_chains_create_table(struct xsc_fs_chains *chains,
						      u32 chain, u32 prio, u32 level)
{
	struct xsc_flow_table_attr ft_attr = {};
	struct xsc_flow_namespace *ns;
	struct xsc_flow_table *ft;
	int sz;

	if (chains->flags & XSC_CHAINS_FT_TUNNEL_SUPPORTED)
		ft_attr.flags |= (XSC_FLOW_TABLE_TUNNEL_EN_REFORMAT |
				  XSC_FLOW_TABLE_TUNNEL_EN_DECAP);

	sz = (chain == xsc_chains_get_nf_ft_chain(chains)) ? FT_TBL_SZ : MAX_FTE_SZ;
	ft_attr.max_fte = sz;

	/* We use chains_default_ft(chains) as the table's next_ft till
	 * ignore_flow_level is allowed on FT creation and not just for FTEs.
	 * Instead caller should add an explicit miss rule if needed.
	 */
	ft_attr.next_ft = chains_default_ft(chains);

	/* The root table(chain 0, prio 1, level 0) is required to be
	 * connected to the previous fs_core managed prio.
	 * We always create it, as a managed table, in order to align with
	 * fs_core logic.
	 */
	if (!xsc_chains_ignore_flow_level_supported(chains) ||
	    (chain == 0 && prio == 1 && level == 0)) {
		ft_attr.level = chains->fs_base_level;
		ft_attr.prio = chains->fs_base_prio + prio - 1;
		ns = (chains->ns == XSC_FLOW_NAMESPACE_FDB) ?
			xsc_get_fdb_sub_ns(chains->dev, chain) :
			xsc_get_flow_namespace(chains->dev, chains->ns);
	} else {
		ft_attr.flags |= XSC_FLOW_TABLE_UNMANAGED;
		ft_attr.prio = chains->fs_base_prio;
		/* Firmware doesn't allow us to create another level 0 table,
		 * so we create all unmanaged tables as level 1 (base + 1).
		 *
		 * To connect them, we use explicit miss rules with
		 * ignore_flow_level. Caller is responsible to create
		 * these rules (if needed).
		 */
		ft_attr.level = chains->fs_base_level + 1;
		ns = xsc_get_flow_namespace(chains->dev, chains->ns);
	}

	ft_attr.autogroup.num_reserved_entries = 0;
	ft_attr.autogroup.max_num_groups = chains->group_num;
	ft = xsc_create_auto_grouped_flow_table(ns, &ft_attr);
	if (IS_ERR(ft)) {
		xsc_core_warn(chains->dev,
			      "Failed to create chains table err %d (chain: %d, prio: %d, level: %d, size: %d)\n",
			      (int)PTR_ERR(ft), chain, prio, level, sz);
		return ft;
	}

	ft->chain = chain;
	ft->prio = prio;

	return ft;
}

static int create_chain_restore(struct fs_chain *chain)
{
#ifdef CONDIF_XSC_OFFLOAD_CT
	u8 modact[XSC_UN_SZ_BYTES(set_add_copy_action_in)] = {};
	struct xsc_fs_chains *chains = chain->chains;
	struct xsc_modify_hdr *mod_hdr;
	u32 index;
	int err;

	if (chain->chain == xsc_chains_get_nf_ft_chain(chains) ||
	    !xsc_chains_prios_supported(chains))
		return 0;

	chain->id = index;

	if (chains->ns == XSC_FLOW_NAMESPACE_FDB) {
		chain->restore_rule = esw_add_restore_rule(esw, chain->id);
		if (IS_ERR(chain->restore_rule)) {
			err = PTR_ERR(chain->restore_rule);
			goto err_rule;
		}
	} else {
		err = -EINVAL;
		goto err_rule;
	}

	XSC_SET(set_action_in, modact, action_type, XSC_ACTION_TYPE_SET);
	XSC_SET(set_action_in, modact, data, chain->id);
	mod_hdr = xsc_modify_header_alloc(chains->dev, chains->ns, 1, modact);
	if (IS_ERR(mod_hdr)) {
		err = PTR_ERR(mod_hdr);
		goto err_mod_hdr;
	}
	chain->miss_modify_hdr = mod_hdr;

	return 0;

err_mod_hdr:
	if (!IS_ERR_OR_NULL(chain->restore_rule))
		xsc_del_flow_rules(chain->restore_rule);
err_rule:
	return err;
#else
	return 0;
#endif
}

static void destroy_chain_restore(struct fs_chain *chain)
{
	struct xsc_fs_chains *chains = chain->chains;

	if (!chain->miss_modify_hdr)
		return;

	if (chain->restore_rule)
		xsc_del_flow_rules(chain->restore_rule);

	xsc_modify_header_dealloc(chains->dev, chain->miss_modify_hdr);
}

static struct fs_chain *xsc_chains_create_chain(struct xsc_fs_chains *chains, u32 chain)
{
	struct fs_chain *chain_s = NULL;
	int err;

	chain_s = kvzalloc(sizeof(*chain_s), GFP_KERNEL);
	if (!chain_s)
		return ERR_PTR(-ENOMEM);

	chain_s->chains = chains;
	chain_s->chain = chain;
	INIT_LIST_HEAD(&chain_s->prios_list);

	err = create_chain_restore(chain_s);
	if (err)
		goto err_restore;

	err = rhashtable_insert_fast(&chains_ht(chains), &chain_s->node,
				     chain_params);
	if (err)
		goto err_insert;

	return chain_s;

err_insert:
	destroy_chain_restore(chain_s);
err_restore:
	kvfree(chain_s);
	return ERR_PTR(err);
}

static void xsc_chains_destroy_chain(struct fs_chain *chain)
{
	struct xsc_fs_chains *chains = chain->chains;

	rhashtable_remove_fast(&chains_ht(chains), &chain->node,
			       chain_params);

	destroy_chain_restore(chain);
	kvfree(chain);
}

static struct fs_chain *xsc_chains_get_chain(struct xsc_fs_chains *chains, u32 chain)
{
	struct fs_chain *chain_s;

	chain_s = rhashtable_lookup_fast(&chains_ht(chains), &chain,
					 chain_params);
	if (!chain_s) {
		chain_s = xsc_chains_create_chain(chains, chain);
		if (IS_ERR(chain_s))
			return chain_s;
	}

	chain_s->ref++;

	return chain_s;
}

void xsc_set_flow_attr_vport(struct xsc_eswitch *esw,
			     u32 *flow_group_in, u16 vport)
{
	void *match_attr = XSC_ADDR_OF(create_flow_group_in,
				       flow_group_in, match_attr);

	XSC_SET(flow_attr, match_attr, vport, vport);
	XSC_SET(flow_attr, match_attr, vhca_id,
		(esw->dev->pcie_no << 8 | esw->dev->pf_id));

	if (vport > 0 && vport < XSC_VPORT_UPLINK)
		XSC_SET(flow_attr, match_attr, egress, 1);
	else
		XSC_SET(flow_attr, match_attr, ingress, 1);
}

static struct xsc_flow_handle *xsc_chains_add_miss_rule(struct fs_chain *chain,
							struct xsc_flow_table *ft,
							struct xsc_flow_table *next_ft)
{
	struct xsc_fs_chains *chains = chain->chains;
	struct xsc_flow_destination dest = {};
	struct xsc_flow_act act = {};

	act.flags  = FLOW_ACT_NO_APPEND;
	if (xsc_chains_ignore_flow_level_supported(chain->chains))
		act.flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;

	act.action = XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
	dest.type  = XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE;
	dest.ft = next_ft;

	if (chains->chains_mapping && next_ft == chains_end_ft(chains) &&
	    chain->chain != xsc_chains_get_nf_ft_chain(chains) &&
	    xsc_chains_prios_supported(chains)) {
		act.modify_hdr = chain->miss_modify_hdr;
		act.action |= XSC_FLOW_CONTEXT_ACTION_MOD_HDR;
	}

	return xsc_add_flow_rules(ft, NULL, &act, &dest, 1);
}

static int xsc_chains_update_prio_prevs(struct prio *prio, struct xsc_flow_table *next_ft)
{
	struct xsc_flow_handle *miss_rules[FDB_TC_LEVELS_PER_PRIO + 1] = {};
	struct fs_chain *chain = prio->chain;
	struct prio *pos;
	int n = 0, err;

//	if (prio->key.level)
		return 0;

	/* Iterate in reverse order until reaching the level 0 rule of
	 * the previous priority, adding all the miss rules first, so we can
	 * revert them if any of them fails.
	 */
	pos = prio;
	list_for_each_entry_continue_reverse(pos, &chain->prios_list, list) {
		miss_rules[n] = xsc_chains_add_miss_rule(chain, pos->ft, next_ft);
		if (IS_ERR(miss_rules[n])) {
			err = PTR_ERR(miss_rules[n]);
			goto err_prev_rule;
		}

		n++;
		if (!pos->key.level)
			break;
	}

	/* Success, delete old miss rules, and update the pointers. */
	n = 0;
	pos = prio;
	list_for_each_entry_continue_reverse(pos, &chain->prios_list, list) {
		xsc_del_flow_rules(pos->miss_rule);

		pos->miss_rule = miss_rules[n];
		pos->next_ft = next_ft;

		n++;
		if (!pos->key.level)
			break;
	}

	return 0;

err_prev_rule:
	while (--n >= 0)
		xsc_del_flow_rules(miss_rules[n]);

	return err;
}

static void xsc_chains_put_chain(struct fs_chain *chain)
{
	if (--chain->ref == 0)
		xsc_chains_destroy_chain(chain);
}

static struct prio *xsc_chains_create_prio(struct xsc_fs_chains *chains,
					   u32 chain, u32 prio, u32 level)
{
	int inlen = XSC_ST_SZ_BYTES(create_flow_group_in);
	struct xsc_flow_handle *miss_rule = NULL;
	struct xsc_flow_group *miss_group = NULL;
	struct xsc_flow_table *next_ft;
	struct xsc_flow_table *ft;
	struct fs_chain *chain_s;
	struct list_head *pos;
	struct prio *prio_s;
	u32 *flow_group_in;
	void *match_attr;
	int err;

	chain_s = xsc_chains_get_chain(chains, chain);
	if (IS_ERR(chain_s))
		return ERR_CAST(chain_s);

	prio_s = kvzalloc(sizeof(*prio_s), GFP_KERNEL);
	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!prio_s || !flow_group_in) {
		err = -ENOMEM;
		goto err_alloc;
	}

	/* Chain's prio list is sorted by prio and level.
	 * And all levels of some prio point to the next prio's level 0.
	 * Example list (prio, level):
	 * (3,0)->(3,1)->(5,0)->(5,1)->(6,1)->(7,0)
	 * In hardware, we will we have the following pointers:
	 * (3,0) -> (5,0) -> (7,0) -> Slow path
	 * (3,1) -> (5,0)
	 * (5,1) -> (7,0)
	 * (6,1) -> (7,0)
	 */

	/* Default miss for each chain: */
	next_ft = (chain == xsc_chains_get_nf_ft_chain(chains)) ?
		  chains_default_ft(chains) :
		  chains_end_ft(chains);
	list_for_each(pos, &chain_s->prios_list) {
		struct prio *p = list_entry(pos, struct prio, list);

		/* exit on first pos that is larger */
		if (prio < p->key.prio || (prio == p->key.prio &&
					   level < p->key.level)) {
			/* Get next level 0 table */
			next_ft = p->key.level == 0 ? p->ft : p->next_ft;
			break;
		}
	}

	ft = xsc_chains_create_table(chains, chain, prio, level);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		goto err_create;
	}

	if (chain >= 0 && prio > 0)
		goto skip_miss_group;

	match_attr = XSC_ADDR_OF(create_flow_group_in, flow_group_in, match_attr);
	XSC_SET(flow_attr, match_attr, start_flow_index, ft->max_fte - 2);
	XSC_SET(flow_attr, match_attr, end_flow_index, ft->max_fte - 1);

	XSC_SET(flow_attr, match_attr, chain_no, chain);
	XSC_SET(flow_attr, match_attr, priority, prio);
	XSC_SET(flow_attr, match_attr, egress, 1);
	XSC_SET(flow_attr, match_attr, dest_type,
		XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE);
	XSC_SET(flow_attr, match_attr, match_mask_enable,
		XSC_MATCH_MISC_PARAMETERS);
	XSC_SET_FTE_MATCH_ATTR(&((struct xsc_ifc_flow_attr *)match_attr)->match_fields,
			       IN_PORT);

	miss_group = xsc_create_flow_group(ft, flow_group_in);
	if (IS_ERR(miss_group)) {
		err = PTR_ERR(miss_group);
		goto err_group;
	}

	/* Add miss rule to next_ft */
	miss_rule = xsc_chains_add_miss_rule(chain_s, ft, next_ft);
	if (IS_ERR(miss_rule)) {
		err = PTR_ERR(miss_rule);
		goto err_miss_rule;
	}

skip_miss_group:
	prio_s->miss_group = miss_group;
	prio_s->miss_rule = miss_rule;
	prio_s->next_ft = next_ft;
	prio_s->chain = chain_s;
	prio_s->key.chain = chain;
	prio_s->key.prio = prio;
	prio_s->key.level = level;
	prio_s->ft = ft;

	err = rhashtable_insert_fast(&prios_ht(chains), &prio_s->node,
				     prio_params);
	if (err)
		goto err_insert;

	list_add(&prio_s->list, pos->prev);

	/* Table is ready, connect it */
	err = xsc_chains_update_prio_prevs(prio_s, ft);
	if (err)
		goto err_update;

	kvfree(flow_group_in);
	return prio_s;

err_update:
	list_del(&prio_s->list);
	rhashtable_remove_fast(&prios_ht(chains), &prio_s->node,
			       prio_params);
err_insert:
	xsc_del_flow_rules(miss_rule);
err_miss_rule:
	xsc_destroy_flow_group(miss_group);
err_group:
	xsc_destroy_flow_table(ft);
err_create:
err_alloc:
	kvfree(prio_s);
	kvfree(flow_group_in);
	xsc_chains_put_chain(chain_s);
	return ERR_PTR(err);
}

static void xsc_chains_destroy_prio(struct xsc_fs_chains *chains,
				    struct prio *prio)
{
	struct fs_chain *chain = prio->chain;

	WARN_ON(xsc_chains_update_prio_prevs(prio, prio->next_ft));

	list_del(&prio->list);
	rhashtable_remove_fast(&prios_ht(chains), &prio->node,
			       prio_params);
	xsc_del_flow_rules(prio->miss_rule);
	xsc_destroy_flow_group(prio->miss_group);
	xsc_destroy_flow_table(prio->ft);
	xsc_chains_put_chain(chain);
	kvfree(prio);
}

struct xsc_flow_table *xsc_chains_get_table(struct xsc_fs_chains *chains,
					    u32 chain, u32 prio, u32 level)
{
	struct xsc_flow_table *prev_fts;
	struct prio *prio_s;
	struct prio_key key;
	int l = 0;

	if ((chain > xsc_chains_get_chain_range(chains) &&
	     chain != xsc_chains_get_nf_ft_chain(chains)) ||
	    prio > xsc_chains_get_prio_range(chains) ||
	    level > xsc_chains_get_level_range(chains))
		return ERR_PTR(-EOPNOTSUPP);

	/* create earlier levels for correct fs_core lookup when
	 * connecting tables.
	 */
	for (l = 0; l < level; l++) {
		prev_fts = xsc_chains_get_table(chains, chain, prio, l);
		if (IS_ERR(prev_fts)) {
			prio_s = ERR_CAST(prev_fts);
			goto err_get_prevs;
		}
	}

	key.chain = chain;
	key.prio = prio;
	key.level = level;

	mutex_lock(&chains_lock(chains));
	prio_s = rhashtable_lookup_fast(&prios_ht(chains), &key,
					prio_params);
	if (!prio_s) {
		prio_s = xsc_chains_create_prio(chains, chain, prio, level);
		if (IS_ERR(prio_s))
			goto err_create_prio;
	}

	++prio_s->ref;
	mutex_unlock(&chains_lock(chains));

	return prio_s->ft;

err_create_prio:
	mutex_unlock(&chains_lock(chains));
err_get_prevs:
	while (--l >= 0)
		xsc_chains_put_table(chains, chain, prio, l);
	return ERR_CAST(prio_s);
}

void xsc_chains_put_table(struct xsc_fs_chains *chains, u32 chain, u32 prio, u32 level)
{
	struct prio *prio_s;
	struct prio_key key;

	key.chain = chain;
	key.prio = prio;
	key.level = level;

	mutex_lock(&chains_lock(chains));
	prio_s = rhashtable_lookup_fast(&prios_ht(chains), &key,
					prio_params);
	if (!prio_s)
		goto err_get_prio;

	if (--prio_s->ref == 0)
		xsc_chains_destroy_prio(chains, prio_s);
	mutex_unlock(&chains_lock(chains));

	while (level-- > 0)
		xsc_chains_put_table(chains, chain, prio, level);

	return;

err_get_prio:
	mutex_unlock(&chains_lock(chains));
	WARN_ONCE(1,
		  "Couldn't find table: (chain: %d prio: %d level: %d)",
		  chain, prio, level);
}

struct xsc_flow_table *xsc_chains_get_tc_end_ft(struct xsc_fs_chains *chains)
{
	return chains_end_ft(chains);
}

struct xsc_flow_table *xsc_chains_create_global_table(struct xsc_fs_chains *chains)
{
	u32 chain, prio, level;
	int err;

	if (!xsc_chains_ignore_flow_level_supported(chains)) {
		err = -EOPNOTSUPP;
		esw_warn(chains->dev,
			 "Couldn't create global flow table, ignore_flow_level not supported.");
		goto err_ignore;
	}

	chain = xsc_chains_get_chain_range(chains),
	prio = xsc_chains_get_prio_range(chains);
	level = xsc_chains_get_level_range(chains);

	return xsc_chains_create_table(chains, chain, prio, level);

err_ignore:
	return ERR_PTR(err);
}
EXPORT_SYMBOL(xsc_chains_create_global_table);

void xsc_chains_destroy_global_table(struct xsc_fs_chains *chains, struct xsc_flow_table *ft)
{
	xsc_destroy_flow_table(ft);
}
EXPORT_SYMBOL(xsc_chains_destroy_global_table);

static struct xsc_fs_chains *xsc_chains_init(struct xsc_core_device *dev,
					     struct xsc_chains_attr *attr)
{
	struct xsc_fs_chains *chains;
	int err;

	chains = kzalloc(sizeof(*chains), GFP_KERNEL);
	if (!chains)
		return ERR_PTR(-ENOMEM);

	chains->dev = dev;
	chains->flags = attr->flags;
	chains->ns = attr->ns;
	chains->group_num = attr->max_grp_num;
	chains->fs_base_prio = attr->fs_base_prio;
	chains->fs_base_level = attr->fs_base_level;
	chains_default_ft(chains) = chains_end_ft(chains) = attr->default_ft;

	err = rhashtable_init(&chains_ht(chains), &chain_params);
	if (err)
		goto init_chains_ht_err;

	err = rhashtable_init(&prios_ht(chains), &prio_params);
	if (err)
		goto init_prios_ht_err;

	mutex_init(&chains_lock(chains));

	return chains;

init_prios_ht_err:
	rhashtable_destroy(&chains_ht(chains));
init_chains_ht_err:
	kfree(chains);
	return ERR_PTR(err);
}

static void xsc_chains_cleanup(struct xsc_fs_chains *chains)
{
	mutex_destroy(&chains_lock(chains));
	rhashtable_destroy(&prios_ht(chains));
	rhashtable_destroy(&chains_ht(chains));

	kfree(chains);
}

struct xsc_fs_chains *xsc_chains_create(struct xsc_core_device *dev, struct xsc_chains_attr *attr)
{
	struct xsc_fs_chains *chains;

	chains = xsc_chains_init(dev, attr);

	return chains;
}

void xsc_chains_destroy(struct xsc_fs_chains *chains)
{
	xsc_chains_cleanup(chains);
}

void xsc_chains_print_info(struct xsc_fs_chains *chains)
{
	xsc_core_dbg(chains->dev, "Flow table chains groups(%d)\n", chains->group_num);
}
