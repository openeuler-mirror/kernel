// SPDX-License-Identifier: GPL-2.0
#include "nbl_resource.h"
#include "nbl_tc_tun_leonis.h"

static bool nbl_tc_tun_encap_lookup(void *priv,
				    struct nbl_rule_action *rule_act,
				    struct nbl_tc_flow_param *param)
{
	bool encap_find = false;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_encap_entry *encap_node = NULL;

	mutex_lock(&tc_flow_mgt->encap_tbl_lock);
	if (!tc_flow_mgt->encap_tbl.flow_tab_hash) {
		mutex_unlock(&tc_flow_mgt->encap_tbl_lock);
		nbl_err(common, NBL_DEBUG_FLOW, "encap hash tbl is null.\n");
		encap_find = false;
		goto end;
	}

	encap_node = nbl_common_get_hash_node(tc_flow_mgt->encap_tbl.flow_tab_hash,
					      &rule_act->encap_key);
	if (encap_node) {
		encap_node->ref_cnt++;
		rule_act->encap_idx = encap_node->encap_idx;
		rule_act->vni = encap_node->vni;
		rule_act->tc_tun_encap_out_dev = encap_node->out_dev;
		nbl_debug(common, NBL_DEBUG_FLOW, "encap is exist, vni %d, encap_idx %d",
			  rule_act->vni, rule_act->encap_idx);
		encap_find = true;
	}
	mutex_unlock(&tc_flow_mgt->encap_tbl_lock);
end:
	return encap_find;
}

int nbl_tc_tun_encap_del(void *priv, struct nbl_encap_key *key)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(tc_flow_mgt->res_mgt);
	struct nbl_encap_entry *e = NULL;
	const struct nbl_phy_ops *phy_ops;
	bool del_hw_encap_tbl = false;
	u16 encap_idx = 0;

	res_mgt = tc_flow_mgt->res_mgt;
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (!key) {
		nbl_err(common, NBL_DEBUG_FLOW, "encap_key is null");
		return -EINVAL;
	}

	mutex_lock(&tc_flow_mgt->encap_tbl_lock);

	e = nbl_common_get_hash_node(tc_flow_mgt->encap_tbl.flow_tab_hash, key);
	if (e) {
		if (e->ref_cnt > 1) {
			e->ref_cnt--;
		} else {
			/* remove encap from hw */
			del_hw_encap_tbl = true;
			encap_idx = e->encap_idx;
			/* free soft encap hash node */
			clear_bit(e->encap_idx, tc_flow_mgt->encap_tbl_bmp);
			nbl_common_free_hash_node(tc_flow_mgt->encap_tbl.flow_tab_hash, key);
			tc_flow_mgt->encap_tbl.tab_cnt--;
		}
	}

	mutex_unlock(&tc_flow_mgt->encap_tbl_lock);

	if (del_hw_encap_tbl)
		phy_ops->del_tnl_encap(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), encap_idx);

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl tc del encap_idx: %u, encap_node:%p, del_hw:%d",
		  encap_idx, e, del_hw_encap_tbl);

	return 0;
}

static int nbl_tc_tun_encap_add(void *priv, struct nbl_rule_action *action)
{
	u16 encap_idx;
	int encap_cnt;
	int ret = 0;
	struct nbl_encap_entry e;
	struct nbl_encap_entry *encap_node;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(tc_flow_mgt->res_mgt);
	const struct nbl_phy_ops *phy_ops;

	res_mgt = tc_flow_mgt->res_mgt;
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	mutex_lock(&tc_flow_mgt->encap_tbl_lock);

	encap_idx = (u16)find_first_zero_bit(tc_flow_mgt->encap_tbl_bmp,
					     NBL_TC_ENCAP_TBL_DEPTH);
	if (encap_idx == NBL_TC_ENCAP_TBL_DEPTH) {
		mutex_unlock(&tc_flow_mgt->encap_tbl_lock);
		ret = -ENOSPC;
		nbl_info(common, NBL_DEBUG_FLOW, "encap tbl is full, cnt:%u", encap_idx);
		goto err;
	}

	set_bit(encap_idx, tc_flow_mgt->encap_tbl_bmp);
	action->encap_idx = encap_idx;
	memset(&e, 0, sizeof(e));
	e.ref_cnt = 1;
	e.out_dev = action->tc_tun_encap_out_dev;
	memcpy(e.encap_buf, action->encap_buf, NBL_FLOW_ACTION_ENCAP_TOTAL_LEN);
	e.encap_size = action->encap_size;
	e.encap_idx = action->encap_idx;
	e.vni = action->vni;
	memcpy(&e.key, &action->encap_key, sizeof(action->encap_key));

	/* insert encap_node */
	ret = nbl_common_alloc_hash_node(tc_flow_mgt->encap_tbl.flow_tab_hash,
					 &action->encap_key, &e, (void **)&encap_node);
	if (ret) {
		clear_bit(encap_idx, tc_flow_mgt->encap_tbl_bmp);
		mutex_unlock(&tc_flow_mgt->encap_tbl_lock);
		nbl_info(common, NBL_DEBUG_FLOW, "alloc encap node failed, ret %d!", ret);
		goto err;
	}

	tc_flow_mgt->encap_tbl.tab_cnt++;
	encap_cnt = tc_flow_mgt->encap_tbl.tab_cnt;

	mutex_unlock(&tc_flow_mgt->encap_tbl_lock);

	/* fill act_buf and send to hw */
	phy_ops->add_tnl_encap(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), action->encap_buf,
			       action->encap_idx, action->encap_idx_info);

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl tc add new encap, encap_idx %u, encap_cnt %d vni %u, encap_size %u, out_dev %s",
		  encap_idx, encap_cnt, e.vni, e.encap_size, netdev_name(e.out_dev));

err:
	return ret;
}

/* NBL_TC_TUN_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_TC_TUN_OPS_TBL							\
do {										\
	NBL_TC_TUN_SET_OPS(tc_tun_encap_lookup, nbl_tc_tun_encap_lookup);	\
	NBL_TC_TUN_SET_OPS(tc_tun_encap_del, nbl_tc_tun_encap_del);		\
	NBL_TC_TUN_SET_OPS(tc_tun_encap_add, nbl_tc_tun_encap_add);		\
} while (0)

int nbl_tc_tun_setup_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_TC_TUN_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_TC_TUN_OPS_TBL;
#undef  NBL_TC_TUN_SET_OPS

	return 0;
}

void nbl_tc_tun_remove_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_TC_TUN_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_TC_TUN_OPS_TBL;
#undef  NBL_TC_TUN_SET_OPS
}
