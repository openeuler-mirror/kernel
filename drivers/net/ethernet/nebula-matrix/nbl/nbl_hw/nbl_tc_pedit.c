// SPDX-License-Identifier: GPL-2.0
#include "nbl_tc_pedit.h"
#include "nbl_p4_actions.h"

static int nbl_tc_pedit_get_h_idx(struct nbl_tc_pedit_res_info *pedit_res,
				  struct nbl_common_info *common, struct nbl_tc_pedit_entry *e)
{
	u32 ped_idx = 0;
	int idx = 0;
	bool h_idx_vld = false;
	int ret = -ENOMEM;

	if (pedit_res->pedit_cnt_h >= pedit_res->pedit_num_h) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit over-hlimit (%u-%u)",
			 pedit_res->pedit_num_h, pedit_res->pedit_cnt_h);
		return -ENOBUFS;
	}

	ped_idx = find_first_zero_bit(pedit_res->pedit_pool_h, pedit_res->pedit_num_h);
	WARN_ON(ped_idx >= pedit_res->pedit_num_h);
	for (idx = ped_idx; idx < pedit_res->pedit_num_h; ++idx) {
		/* don't overlap the pool */
		if (idx >= pedit_res->pedit_num)
			break;

		/* only when idx in pool and h_pool are both available, then idx is valid */
		if (!test_bit(idx, pedit_res->pedit_pool_h) &&
		    !test_bit(idx, pedit_res->pedit_pool)) {
			h_idx_vld = true;
			break;
		}
	}

	if (h_idx_vld) {
		nbl_debug(common, NBL_DEBUG_FLOW, "tc_pedit find a vld idx(%u)-(%u-%u)",
			  idx, pedit_res->pedit_num_h, pedit_res->pedit_cnt_h);
		ret = 0;
		/* now set bit in both pool and h_pool */
		set_bit(idx, pedit_res->pedit_pool);
		set_bit(idx, pedit_res->pedit_pool_h);

		/* h_idx occupy 2 bits actually */
		++pedit_res->pedit_cnt;
		++pedit_res->pedit_cnt_h;
		NBL_TC_PEDIT_SET_NODE_H(e);
		NBL_TC_PEDIT_SET_NODE_IDX(e, idx);
	} else {
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit no valid hidx in hpool-(%u-%u)",
			 pedit_res->pedit_num_h, pedit_res->pedit_cnt_h);
	}

	return ret;
}

static int nbl_tc_pedit_get_normal_idx(struct nbl_tc_pedit_res_info *pedit_res,
				       struct nbl_common_info *common,
				       struct nbl_tc_pedit_entry *e)
{
	u32 ped_idx = 0;

	ped_idx = find_first_zero_bit(pedit_res->pedit_pool, pedit_res->pedit_num);
	/* normal ped_idx used up, try get from pedit_h if we got */
	if (ped_idx >= pedit_res->pedit_num && pedit_res->pedit_num_h) {
		nbl_debug(common, NBL_DEBUG_FLOW, "tc_pedit try to get idx from h_pool");

		if (pedit_res->pedit_cnt_h >= pedit_res->pedit_num_h) {
			nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit over-hlimit for normal (%u-%u)",
				 pedit_res->pedit_num_h, pedit_res->pedit_cnt_h);
			return -ENOBUFS;
		}
		ped_idx = find_first_zero_bit(pedit_res->pedit_pool_h, pedit_res->pedit_num_h);
		WARN_ON(ped_idx >= pedit_res->pedit_num_h);
		nbl_debug(common, NBL_DEBUG_FLOW, "tc_pedit get h-idx(%u) success(%u-%u)",
			  ped_idx, pedit_res->pedit_num_h, pedit_res->pedit_cnt_h);
		NBL_TC_PEDIT_SET_NORMAL_IN_H(e);
		++pedit_res->pedit_cnt_h;
		set_bit(ped_idx, pedit_res->pedit_pool_h);
	} else if (ped_idx >= pedit_res->pedit_num) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit get no available idx(%u-%u)",
			 pedit_res->pedit_num, pedit_res->pedit_cnt);
		return -ENOMEM;
	}
	/* get a normal idx */
	nbl_debug(common, NBL_DEBUG_FLOW, "tc_pedit get idx(%u) success(%u-%u)",
		  ped_idx, pedit_res->pedit_num, pedit_res->pedit_cnt);
	set_bit(ped_idx, pedit_res->pedit_pool);

	NBL_TC_PEDIT_SET_NODE_IDX(e, ped_idx);
	return 0;
}

static int nbl_tc_pedit_get_idx(struct nbl_tc_pedit_res_info *pedit_res,
				struct nbl_common_info *common, struct nbl_tc_pedit_entry *e)
{
	int ret = 0;

	if (pedit_res->pedit_cnt >= pedit_res->pedit_num) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit over-limit (%u-%u)",
			 pedit_res->pedit_num, pedit_res->pedit_cnt);
		return -ENOBUFS;
	}

	if (NBL_TC_PEDIT_GET_NODE_H(e))
		ret = nbl_tc_pedit_get_h_idx(pedit_res, common, e);

	else
		ret = nbl_tc_pedit_get_normal_idx(pedit_res, common, e);

	if (ret)
		return ret;
	++pedit_res->pedit_cnt;
	NBL_TC_PEDIT_SET_NODE_VAL(e);
	NBL_TC_PEDIT_SET_NODE_BASE_ID(e, pedit_res->pedit_base_id);
	NBL_TC_PEDIT_INC_NODE_REF(e);
	return 0;
}

static int nbl_tc_pedit_put_idx(struct nbl_tc_pedit_res_info *pedit_res,
				struct nbl_common_info *common, struct nbl_tc_pedit_entry *e)
{
	void *pool_addr;
	bool idx_h = false;

	if (NBL_TC_PEDIT_GET_NODE_H(e)) {
		WARN_ON(NBL_TC_PEDIT_GET_NODE_IDX(e) >= pedit_res->pedit_num_h);
		pool_addr = pedit_res->pedit_pool_h;
		idx_h = true;
		clear_bit(NBL_TC_PEDIT_GET_NODE_IDX(e), pedit_res->pedit_pool);
		pedit_res->pedit_cnt_h--;
		pedit_res->pedit_cnt--;
	} else if (NBL_TC_PEDIT_GET_NORMAL_IN_H(e)) {
		WARN_ON(NBL_TC_PEDIT_GET_NODE_IDX(e) >= pedit_res->pedit_num_h);
		pool_addr = pedit_res->pedit_pool_h;
		idx_h = true;
		pedit_res->pedit_cnt_h--;
	} else {
		WARN_ON(NBL_TC_PEDIT_GET_NODE_IDX(e) >= pedit_res->pedit_num);
		pool_addr = pedit_res->pedit_pool;
	}

	if (!test_bit(NBL_TC_PEDIT_GET_NODE_IDX(e), pool_addr))
		nbl_err(common, NBL_DEBUG_FLOW, "tc_pedit clear a null bit %u in h(%d)",
			NBL_TC_PEDIT_GET_NODE_IDX(e), idx_h ? 1 : 0);

	pedit_res->pedit_cnt--;
	nbl_debug(common, NBL_DEBUG_FLOW, "tc_pedit put idx(%u) success normal(%u-%u)-high(%u-%u)",
		  NBL_TC_PEDIT_GET_NODE_IDX(e), pedit_res->pedit_num, pedit_res->pedit_cnt,
		  pedit_res->pedit_num_h, pedit_res->pedit_cnt_h);
	clear_bit(NBL_TC_PEDIT_GET_NODE_IDX(e), pool_addr);
	NBL_TC_PEDIT_DEC_NODE_REF(e);
	NBL_TC_PEDIT_SET_NODE_INVAL(e);
	return 0;
}

static enum nbl_flow_ped_type nbl_tc_pedit_get_ped_type(enum nbl_flow_ped_type ped_type)
{
	/* default ped_type return directly */
	if (NBL_TC_PEDIT_IS_DEFAULT_TYPE(ped_type))
		return ped_type;

	NBL_TC_PEDIT_UNSET_D_TYPE(ped_type);
	/* we need get the hw recongnize ped_type */
	return ped_type;
}

u16 nbl_tc_pedit_get_hw_id(struct nbl_tc_pedit_entry *ped_node)
{
	return (ped_node->hnode.node_idx + ped_node->hnode.node_base);
}

int nbl_tc_pedit_del_node(struct nbl_tc_pedit_mgt *pedit_mgt,
			  struct nbl_tc_pedit_node_res *pedit_node)
{
	struct nbl_common_info *common = pedit_mgt->common;
	struct nbl_tc_pedit_res_info *pedit_res = pedit_mgt->pedit_res;
	int idx = 0;
	struct nbl_tc_pedit_entry *l_e;
	void *h_e;
	u32 e_ref = 0;
	int ret = -EINVAL;
	void *pedit_tbl;
	enum nbl_flow_ped_type ped_type;

	if (!NBL_TC_PEDIT_GET_NODE_RES_VAL(*pedit_node)) {
		nbl_err(common, NBL_DEBUG_FLOW, "nbl_tc_pedit:node is not valid");
		return -EINVAL;
	}

	mutex_lock(&pedit_mgt->pedit_lock);
	for (idx = 0; idx < NBL_FLOW_PED_RES_MAX; ++idx) {
		l_e = NBL_TC_PEDIT_GET_NODE_RES_ENTRY(*pedit_node, idx);
		if (l_e)
			nbl_debug(common, NBL_DEBUG_FLOW, "nbl_tc_pedit(%u):del %d-%u-%u-(%u-%u)",
				  NBL_TC_PEDIT_GET_NODE_REF(l_e),
				  idx, NBL_TC_PEDIT_GET_NODE_IDX(l_e),
				  nbl_tc_pedit_get_hw_id(l_e),
				  NBL_TC_PEDIT_GET_NORMAL_IN_H(l_e),
				  NBL_TC_PEDIT_GET_NODE_H(l_e));
		else
			continue;

		/* get hw ped_type, cuz resource are stored in hw-style */
		ped_type = nbl_tc_pedit_get_ped_type(idx);
		WARN_ON(!NBL_TC_PEDIT_GET_NODE_VAL(l_e));
		if (NBL_TC_PEDIT_GET_NODE_H(l_e))
			pedit_tbl = pedit_res[ped_type].pedit_tbl_h;
		else
			pedit_tbl = pedit_res[ped_type].pedit_tbl;

		h_e = nbl_common_get_hash_node(pedit_tbl, NBL_TC_PEDIT_GET_KEY(l_e));
		WARN_ON(l_e != h_e);
		e_ref = NBL_TC_PEDIT_GET_NODE_REF(l_e);
		if (e_ref > 1) {
			NBL_TC_PEDIT_DEC_NODE_REF(l_e);
		} else {
			NBL_TC_PEDIT_DEC_NODE_REF(l_e);
			nbl_tc_pedit_put_idx(&pedit_res[ped_type], common, l_e);
			nbl_common_free_hash_node(pedit_tbl, NBL_TC_PEDIT_GET_KEY(l_e));
		}
		ret = 0;
	}
	mutex_unlock(&pedit_mgt->pedit_lock);

	return ret;
}

int nbl_tc_pedit_add_node(struct nbl_tc_pedit_mgt *pedit_mgt,
			  struct nbl_tc_pedit_entry *e,
			  void **e_out, enum nbl_flow_ped_type pedit_type)
{
	struct nbl_tc_pedit_res_info *pedit_res = &pedit_mgt->pedit_res[pedit_type];
	struct nbl_common_info *common = pedit_mgt->common;
	struct nbl_tc_pedit_entry *h_e;
	void *new_e;
	int ret = 0;
	void *pedit_tbl = pedit_res->pedit_tbl;

	if (NBL_TC_PEDIT_GET_NODE_H(e))
		pedit_tbl = pedit_res->pedit_tbl_h;

	if (!pedit_tbl) {
		nbl_err(common, NBL_DEBUG_FLOW, "nbl_tc_pedit add failed: not init type %d",
			pedit_type);
		return -EINVAL;
	}

	mutex_lock(&pedit_mgt->pedit_lock);
	h_e = nbl_common_get_hash_node(pedit_tbl, NBL_TC_PEDIT_GET_KEY(e));
	if (h_e) {
		NBL_TC_PEDIT_INC_NODE_REF(h_e);
		nbl_debug(common, NBL_DEBUG_FLOW, "nbl_tc_pedit:type(%d) exist in %u-%u(%u)",
			  pedit_type, NBL_TC_PEDIT_GET_NODE_IDX(h_e),
			  nbl_tc_pedit_get_hw_id(h_e), NBL_TC_PEDIT_GET_NODE_REF(h_e));
		*e_out = h_e;
		NBL_TC_PEDIT_COPY_NODE(h_e, e);
		goto pedit_add_fin;
	}

	ret = nbl_tc_pedit_get_idx(pedit_res, common, e);
	if (ret)
		goto pedit_add_fin;

	ret = nbl_common_alloc_hash_node(pedit_tbl, NBL_TC_PEDIT_GET_KEY(e), e, &new_e);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "nbl_tc_pedit:type(%d) add hash failed",
			pedit_type);
		nbl_tc_pedit_put_idx(pedit_res, common, e);
		goto pedit_add_fin;
	}

	*e_out = new_e;
	NBL_TC_PEDIT_SET_NODE_ENTRY(e, new_e);
	/* tell caller this is the first node added in hash */
	NBL_TC_PEDIT_SET_NODE_INVAL(e);
pedit_add_fin:
	mutex_unlock(&pedit_mgt->pedit_lock);
	return ret;
}

int nbl_tc_pedit_init(struct nbl_common_info *common,
		      struct nbl_tc_pedit_res_info *pedit_res, u32 max_cnt)
{
	int ret = 0;
	int idx = 0;
	struct nbl_hash_tbl_key tbl_key = {0};

	for (idx = 0; idx < max_cnt; ++idx) {
		if (!pedit_res[idx].pedit_num) {
			nbl_info(common, NBL_DEBUG_FLOW, "nbl_tc_pedit:pedit(%d) skip init", idx);
			continue;
		}
		NBL_HASH_TBL_KEY_INIT(&tbl_key, NBL_COMMON_TO_DEV(common),
				      pedit_res[idx].pedit_key_len,
				      pedit_res[idx].pedit_data_len,
				      pedit_res[idx].pedit_num, false);
		pedit_res[idx].pedit_tbl = nbl_common_init_hash_table(&tbl_key);
		if (!pedit_res[idx].pedit_tbl) {
			nbl_info(common, NBL_DEBUG_FLOW, "nbl_tc_pedit:pedit(%d) init failed",
				 idx);
			return -ENOMEM;
		}

		/* init pedit_h if needed */
		if (pedit_res[idx].pedit_num_h) {
			NBL_HASH_TBL_KEY_INIT(&tbl_key, NBL_COMMON_TO_DEV(common),
					      pedit_res[idx].pedit_key_len,
					      pedit_res[idx].pedit_data_len,
					      pedit_res[idx].pedit_num_h, false);
			pedit_res[idx].pedit_tbl_h = nbl_common_init_hash_table(&tbl_key);
			if (!pedit_res[idx].pedit_tbl_h) {
				nbl_info(common, NBL_DEBUG_FLOW, "tc edit idx %d init failed", idx);
				return -ENOMEM;
			}
		}
	}

	return ret;
}

int nbl_tc_pedit_uninit(struct nbl_tc_pedit_res_info *pedit_res, u32 max_cnt)
{
	int idx = 0;

	if (!pedit_res)
		return -EINVAL;

	for (idx = 0; idx < max_cnt; ++idx) {
		nbl_common_remove_hash_table(pedit_res[idx].pedit_tbl, NULL);
		nbl_common_remove_hash_table(pedit_res[idx].pedit_tbl_h, NULL);
	}

	return 0;
}
