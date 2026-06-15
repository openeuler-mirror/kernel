// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/tc_flow.h"
#include "post_act.h"
#include "common/xsc_core.h"
#include "common/fs_core.h"
#include "../../pci/fs_chains.h"
#include "common/fs_cmd.h"
#include "common/tc_priv.h"
#include "linux/xarray.h"

struct xsc_post_act {
	enum xsc_flow_namespace_type ns_type;
	struct xsc_fs_chains *chains;
	struct xsc_flow_table *ft;
	struct xsc_adapter *priv;
	struct xarray ids;
};

struct xsc_post_act_handle {
	enum xsc_flow_namespace_type ns_type;
	struct xsc_flow_attr *attr;
	struct xsc_flow_handle *rule;
	u32 id;
};

#define XSC_POST_ACTION_BITS XSC_REG_MAPPING_MBITS(FTEID_TO_REG)
#define XSC_POST_ACTION_MASK XSC_REG_MAPPING_MASK(FTEID_TO_REG)
#define XSC_POST_ACTION_MAX XSC_POST_ACTION_MASK

struct xsc_post_act *xsc_tc_post_act_init(struct xsc_adapter *priv, struct xsc_fs_chains *chains,
					  enum xsc_flow_namespace_type ns_type)
{
	struct xsc_post_act *post_act;
	struct xsc_core_device *xdev = priv->xdev;
	struct xsc_eswitch *esw = xdev->priv.eswitch;
	int err;

	if (!XSC_ESW_FT_CAP(esw->esw_caps, XSC_ESW_CAP_IGNORE_FT_LEVEL)) {
		if (priv->xdev->coredev_type == XSC_COREDEV_PF)
			xsc_core_dbg(priv->xdev, "fw flow level support is missing\n");
		err = -EOPNOTSUPP;
		goto err_check;
	}

	post_act = kzalloc(sizeof(*post_act), GFP_KERNEL);
	if (!post_act) {
		err = -ENOMEM;
		goto err_check;
	}
	post_act->ft = xsc_chains_create_global_table(chains);
	if (IS_ERR(post_act->ft)) {
		err = PTR_ERR(post_act->ft);
		xsc_core_warn(priv->xdev, "failed to create post action table, err: %d\n", err);
		goto err_ft;
	}
	post_act->chains = chains;
	post_act->ns_type = ns_type;
	post_act->priv = priv;
	xa_init_flags(&post_act->ids, XA_FLAGS_ALLOC1);
	return post_act;

err_ft:
	kfree(post_act);
err_check:
	return ERR_PTR(err);
}

void xsc_tc_post_act_destroy(struct xsc_post_act *post_act)
{
	if (IS_ERR_OR_NULL(post_act))
		return;
	xa_destroy(&post_act->ids);
	xsc_chains_destroy_global_table(post_act->chains, post_act->ft);
	kfree(post_act);
}

int xsc_tc_post_act_offload(struct xsc_post_act *post_act, struct xsc_post_act_handle *handle)
{
	struct xsc_flow_spec *spec;
	int err;

	if (IS_ERR(post_act))
		return PTR_ERR(post_act);

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	/* Post action rule matches on fte_id and executes original rule's tc rule action */
	xsc_tc_match_to_reg_match(spec, FTEID_TO_REG, handle->id, XSC_POST_ACTION_MASK);

	handle->rule = xsc_tc_rule_offload(post_act->priv, spec, handle->attr);
	if (IS_ERR(handle->rule)) {
		err = PTR_ERR(handle->rule);
		netdev_warn(post_act->priv->netdev, "Failed to add post action rule");
		goto err_rule;
	}

	kvfree(spec);
	return 0;

err_rule:
	kvfree(spec);
	return err;
}

struct xsc_post_act_handle *xsc_tc_post_act_add(struct xsc_post_act *post_act,
						struct xsc_flow_attr *post_attr)
{
	struct xsc_post_act_handle *handle;
	int err;

	if (IS_ERR(post_act))
		return ERR_CAST(post_act);

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);

	post_attr->chain = 0;
	post_attr->prio = 0;
	post_attr->ft = post_act->ft;
	post_attr->inner_match_level = XSC_MATCH_NONE;
	post_attr->outer_match_level = XSC_MATCH_NONE;
	post_attr->action &= ~XSC_FLOW_CONTEXT_ACTION_DECAP;

	handle->ns_type = post_act->ns_type;
	/* Splits were handled before post action */
	if (handle->ns_type == XSC_FLOW_NAMESPACE_FDB)
		post_attr->esw_attr->split_count = 0;

	err = xa_alloc(&post_act->ids, &handle->id, post_attr,
		       XA_LIMIT(1, XSC_POST_ACTION_MAX), GFP_KERNEL);
	if (err)
		goto err_xarray;

	handle->attr = post_attr;

	return handle;
err_xarray:
	kfree(handle);
	return ERR_PTR(err);
}

void xsc_tc_post_act_unoffload(struct xsc_post_act *post_act,
			       struct xsc_post_act_handle *handle)
{
	xsc_tc_rule_unoffload(post_act->priv, handle->rule, handle->attr);
	handle->rule = NULL;
}

void xsc_tc_post_act_del(struct xsc_post_act *post_act, struct xsc_post_act_handle *handle)
{
	if (!IS_ERR_OR_NULL(handle->rule))
		xsc_tc_post_act_unoffload(post_act, handle);
	xa_erase(&post_act->ids, handle->id);
	kfree(handle);
}

struct xsc_flow_table *xsc_tc_post_act_get_ft(struct xsc_post_act *post_act)
{
	return post_act->ft;
}

/* Allocate a header modify action to write the post action handle fte id to a register. */
int xsc_tc_post_act_set_handle(struct xsc_core_device *dev,
			       struct xsc_post_act_handle *handle,
			       struct xsc_tc_mod_hdr_acts *acts)
{
	return xsc_tc_match_to_reg_set(dev, acts, handle->ns_type, FTEID_TO_REG, handle->id);
}
