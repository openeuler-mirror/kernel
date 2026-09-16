// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include "nse.h"
#include "nse_acl.h"

/**
 * nse_aq_acl_lut_nodes - add/update/remove acl lut nodes
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_acl_lut_nodes(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_acl_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_ACL_OPC_ADD_LUT_NODE &&
	    opc != NSE_AQ_ACL_OPC_UPDATE_LUT_NODE &&
	    opc != NSE_AQ_ACL_OPC_REMOVE_LUT_NODE &&
	    opc != NSE_AQ_ACL_OPC_GET_LUT_NODE)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_ACL, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_ACL_OPC_ADD_LUT_NODE &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_acl_fill_lut_node - Helper function to fill one acl lut node structure
 * @hw: pointer to the hardware structure
 * @f_info: entry containing packet forwarding information
 * @lut_node: lut node structure to be filled in based on f_info
 * @opc: lut nodes population command type - pass in the command opcode
 */
static void
nse_acl_fill_lut_node(struct nse_hw *hw, struct nse_acl_fltr_info *f_info,
		 struct nse_aqc_lut_node_elem *lut_node,
		 enum nse_adminq_opc_category_acl_subcodes opc)
{
	u16 act = 0;
	u16 lg_act = 0;

	if (opc == NSE_AQ_ACL_OPC_REMOVE_LUT_NODE || opc == NSE_AQ_ACL_OPC_GET_LUT_NODE) {
		lut_node->action = 0;
		lut_node->lut_id = cpu_to_le16(f_info->lkup_type);
		lut_node->node_id = cpu_to_le16(f_info->node_id);
		return;
	}

	switch (f_info->fltr_act) {
	case NSE_ACL_DROP:
		/* set action type to fwd */
		act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		/* set fwd type to Drop */
		act |= (NSE_SINGLE_FWD_DROP << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;
		break;

	case NSE_ACL_METER:
		/* set action type to meter */
		act |= (NSE_SINGLE_ACT_TYPE_METER <<
			NSE_SINGLE_ACT_TYPE_METER_S) &
			NSE_SINGLE_ACT_TYPE_METER_M;

		/* set hw meter id */
		act |= (f_info->meter_id << NSE_SINGLE_METER_ID_S) &
			NSE_SINGLE_METER_ID_M;
		break;

	case NSE_ACL_LARGE_ACT:
		lg_act |= NSE_LUT_NODE_LARGE_ACTION_EN;
		act |= (f_info->lg_action.node_state_id << NSE_SINGLE_LARGE_ACT_ID_S) &
			NSE_SINGLE_LARGE_ACT_ID_M;
		act |= NSE_SINGLE_LARGE_ACT_FULL;
		break;

	default:
		return;
	}

	switch (f_info->lkup_type) {
	case NSE_ACL_LKUP_RX_DEST_VSI:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16((f_info->dst_hw_vsi & NSE_ACL_DEST_VSI_MASK) |
							BIT(NSE_ACL_DEST_VSI_VLD_BIT));
		break;
	case NSE_ACL_LKUP_TX_SRC_VSI:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16(f_info->src_hw_vsi);
		break;
	case NSE_ACL_LKUP_OVS_MISS:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16((f_info->dst_hw_vsi & NSE_ACL_DEST_VSI_MASK) |
							BIT(NSE_ACL_DEST_VSI_VLD_BIT));
		lut_node->key[2] = cpu_to_le16(f_info->src_hw_vsi);
		break;
	default:
		break;
	}

	lut_node->lut_id = cpu_to_le16(f_info->lkup_type);
	lut_node->action = cpu_to_le16(act);
	lut_node->left_ptr = cpu_to_le16(lg_act);

	dev_info(nse_hw_to_dev(hw), "[%s, %d] lut id is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->lut_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] original node_id is 0x%x\n",
		 __func__, __LINE__, cpu_to_le16(lut_node->node_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key0 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[0]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key1 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[1]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key2 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[2]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key3 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[3]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key4 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[4]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] is large action %d\n",
		 __func__, __LINE__, !!lg_act);
	dev_info(nse_hw_to_dev(hw), "[%s, %d] action/node_state_id is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->action));
}

/**
 * nse_acl_add_lut_node - add acl filter's lut node.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
static int
nse_acl_add_lut_node(struct nse_hw *hw,
		struct nse_acl_fltr_info *fltr_info)
{
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lut_node;
	enum nse_status status;
	int err = 0;
	u16 buf_size = struct_size(buf, elem, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;

	nse_acl_fill_lut_node(hw, fltr_info, lut_node,
			 NSE_AQ_ACL_OPC_ADD_LUT_NODE);

	status = nse_aq_acl_lut_nodes(hw, buf, buf_size,
				 NSE_AQ_ACL_OPC_ADD_LUT_NODE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] Failed to add acl lut node\n",
			__func__, __LINE__);
		err = -EIO;
		goto nse_acl_add_fltr_exit;
	}

	fltr_info->node_id = le16_to_cpu(lut_node->node_id);
	dev_info(nse_hw_to_dev(hw), "[%s, %d] returned acl node_id is %d\n",
			__func__, __LINE__,	fltr_info->node_id);

nse_acl_add_fltr_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return err;
}

/**
 * nse_aq_meters - add/update/remove acl meters
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_acl_meters(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_acl_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_ACL_OPC_ADD_METER &&
	    opc != NSE_AQ_ACL_OPC_UPDATE_METER &&
	    opc != NSE_AQ_ACL_OPC_REMOVE_METER &&
	    opc != NSE_AQ_ACL_OPC_GET_METER)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_ACL, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_ACL_OPC_ADD_METER &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_acl_alloc_free_res - command to allocate/free acl resources
 * @hw: pointer to the HW struct
 * @num_entries: number of resource entries in buffer
 * @buf: Indirect buffer to hold data parameters and response
 * @buf_size: size of buffer for indirect commands
 * @opc: pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 * Helper function to allocate/free resources using the admin queue commands
 */
enum nse_status
nse_aq_acl_alloc_free_res(struct nse_hw *hw, u16 num_entries,
		      struct nse_aqc_alloc_free_res_elem *buf, u16 buf_size,
		      enum nse_adminq_opc_category_acl_subcodes opc,
		      struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;

	if (!buf)
		return NSE_ERR_PARAM;

	if (buf_size < flex_array_size(buf, res_id, num_entries))
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_ACL, opc);

	return nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
}

/**
 * nse_aq_acl_alloc_free_meter_id
 * @hw: pointer to the HW struct
 * @meter_id: meter ID returned or used for lookup
 * @opc: acl rules population command type - pass in the command opcode
 *
 * allocates or free a meter id resource
 */
static enum nse_status
nse_aq_acl_alloc_free_meter_id(struct nse_hw *hw,
			u16 *meter_id,
			enum nse_adminq_opc_category_acl_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_ACL_OPC_ALLOC_RESOURCE && opc != NSE_AQ_ACL_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_METER_ID);

	if (opc == NSE_AQ_ACL_OPC_FREE_RESOURCE)
		buf->res_id[0] = cpu_to_le16(*meter_id);

	status = nse_aq_acl_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_acl_alloc_free_meter_id_exit;

	if (opc == NSE_AQ_ACL_OPC_ALLOC_RESOURCE) {
		*meter_id = le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced acl meter id = %d\n",
			__func__, __LINE__, *meter_id);
	} else if (opc == NSE_AQ_ACL_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to acl free meter id = %d\n",
			__func__, __LINE__, *meter_id);
	}

nse_aq_acl_alloc_free_meter_id_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_acl_get_pol_counter_val
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
static enum nse_status
nse_aq_acl_get_pol_counter_val(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc,
		NSE_AQ_OPC_CATEGORY_ACL, NSE_AQ_ACL_OPC_GET_POLICY_COUNTER);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

/**
 * nse_acl_create_meter - creat a acl meter from FW
 *
 * @hw: pointer to the hardware structure
 * @meter_param: pointer to acl meter parameter information
 */
int
nse_acl_create_meter(struct nse_hw *hw,
			struct nse_acl_meter_param *meter_param)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_meters *buf = NULL;
	struct nse_aqc_meter_elem *elem;
	u32 policy_type = 0, cir = 0, cbs = 0;
	u16 buf_size, meter_id = NSE_METER_ID_INVALID;
	int err = 0;

	/*step1: alloc a acl meter id resource*/
	status = nse_aq_acl_alloc_free_meter_id(hw,
				&meter_id, NSE_AQ_ACL_OPC_ALLOC_RESOURCE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] alloc hw acl meter err, err = %d\n",
			__func__, __LINE__, status);
		err = -ENOMEM;
		goto nse_acl_creat_meter_fail;
	}

	/*step2: bulid aqc add meter buf*/
	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto nse_acl_creat_meter_fail;
	}

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->meter_id = cpu_to_le16(meter_id);
	policy_type |= NSE_AQC_METER_ALG_CBSR;

	if (meter_param->mode == NSE_RATE_LIMIT_BPS)
		policy_type &= ~NSE_AQC_METER_MODE_PPS;
	else if (meter_param->mode == NSE_RATE_LIMIT_PPS)
		policy_type |= NSE_AQC_METER_MODE_PPS;
	else {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] meter mode is err, mode = %d\n",
			__func__, __LINE__, meter_param->mode);
		err = -EIO;
		goto nse_acl_creat_meter_fail;
	}

	status = nse_sw_meter_calc_hw_rate(hw, meter_param->rate, &cir);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] calculat hw_rate err, err = %d\n",
			__func__, __LINE__, status);
		err = -EIO;
		goto nse_acl_creat_meter_fail;
	}

	cbs = (meter_param->burst >> NSE_AQC_METER_CBS_S) &
				NSE_AQC_METER_CBS_M;
	cir = (cir >> NSE_AQC_METER_CIR_S) & NSE_AQC_METER_CIR_M;
	elem->cfg.policy_type = cpu_to_le32(policy_type);
	elem->cfg.cbs = cpu_to_le32(cbs);
	elem->cfg.cir = cpu_to_le32(cir);

	dev_info(nse_hw_to_dev(hw),
		"Start to add acl meter: pol_type = 0x%x, cir = 0x%x, cbs = 0x%x, pir = 0x%x, pbs = 0x%x\n",
		policy_type, cir, cbs, le32_to_cpu(elem->cfg.pir), le32_to_cpu(elem->cfg.pbs));

	/*step3: request add meter adminq command*/
	status = nse_aq_acl_meters(hw, buf, buf_size,
				 NSE_AQ_ACL_OPC_ADD_METER, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to aqc add meter, err = %d\n",
			__func__, __LINE__, status);
		err = -EIO;
		goto nse_acl_creat_meter_fail;
	}

	meter_param->meter_id = meter_id;

	devm_kfree(nse_hw_to_dev(hw), buf);

	return 0;

nse_acl_creat_meter_fail:
	if (!buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	if (meter_id != NSE_METER_ID_INVALID)
		nse_aq_acl_alloc_free_meter_id(hw, &meter_id,
						NSE_AQ_ACL_OPC_FREE_RESOURCE);

	return err;
}

/**
 * nse_acl_destroy_meter - destroy a acl meter from FW
 *
 * @hw: pointer to the hardware structure
 * @meter_id: hardware meter id need to be destroyed
 */
int
nse_acl_destroy_meter(struct nse_hw *hw,
			u16 meter_id)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_meters *buf = NULL;
	struct nse_aqc_meter_elem *elem;
	int ret = 0;
	u16 buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->meter_id = cpu_to_le16(meter_id);
	status = nse_aq_acl_meters(hw, buf, buf_size,
				 NSE_AQ_ACL_OPC_REMOVE_METER, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to aq remove acl meters, err = %d\n", status);
		ret = -EIO;
	}

	status = nse_aq_acl_alloc_free_meter_id(hw, &meter_id,
				NSE_AQ_ACL_OPC_FREE_RESOURCE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),	"Failed to aq free acl meter id, id = %d!\n",
					meter_id);
		ret = -EIO;
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;
}

/**
 * nse_acl_is_task_list_needed -
 * judge au task list is needed, according to current fltr actions
 *
 * @act_flags: current fltr actions flag
 */
static bool
nse_acl_is_task_list_needed(u32 act_flags)
{
	return (act_flags & NSE_ACL_LARGE_ACTION_AU_NOP) ||
		(act_flags & NSE_ACL_LARGE_ACTION_AU_DMAC_RW) ||
		(act_flags & NSE_ACL_LARGE_ACTION_AU_SMAC_RW);
}

/**
 * nse_acl_calc_du_data_size -
 * calculate task data size according to actions information
 *
 * @lg_action: current fltr actions information
 */
static u16
nse_acl_calc_du_data_size(struct nse_acl_large_action *lg_action)
{
	u16 data_size = 0;
	u32 act_flags = lg_action->flags;

	if (act_flags & NSE_ACL_LARGE_ACTION_AU_DMAC_RW)
		data_size += NSE_TASK_REWRITE_MAC_DATA_LEN;

	if (act_flags & NSE_ACL_LARGE_ACTION_AU_SMAC_RW)
		data_size += NSE_TASK_REWRITE_MAC_DATA_LEN;

	return data_size;
}

/**
 * nse_acl_calc_au_task_cnt -
 * calculate task count according to actions information
 *
 * @lg_action: current fltr actions information
 */
static u16
nse_acl_calc_au_task_cnt(struct nse_acl_large_action *lg_action)
{
	u16 task_cnt = 0;
	u32 act_flags = lg_action->flags;

	if (act_flags & NSE_ACL_LARGE_ACTION_AU_NOP)
		task_cnt++;

	if (act_flags & NSE_ACL_LARGE_ACTION_AU_DMAC_RW)
		task_cnt++;

	if (act_flags & NSE_ACL_LARGE_ACTION_AU_SMAC_RW)
		task_cnt++;

	if (task_cnt > NSE_MAX_AU_TASK_NUM)
		return 0;

	return task_cnt;
}

/**
 * nse_acl_fill_task_nop -
 *		fill task code and no task data.
 * @cur_task_list: task list object, fill task code to it.
 * @au_task_cnt: index of task in task list.
 * @nop_task_cnt: nop task count
 */
static void
nse_acl_fill_task_nop(struct nse_sw_task_list *cur_task_list,
		u16 *au_task_cnt, u16 nop_task_cnt)
{
	u16 i;

	/*fill task code*/
	for (i = 0; i < nop_task_cnt; i++) {
		cur_task_list->task[*au_task_cnt].task_id =
				NSE_TASK_ID_NOP;
		(*au_task_cnt)++;
	}
}

/**
 * nse_acl_fill_task_rewrite_l2_smac -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
void
nse_acl_fill_task_rewrite_l2_smac(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_acl_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L2_SMAC_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_MAC_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.eth.h_source,
		NSE_TASK_REWRITE_MAC_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_MAC_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.eth.h_source,
		NSE_TASK_REWRITE_MAC_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_MAC_MASK_LEN;
}

/**
 * nse_acl_fill_task_rewrite_l2_dmac -
 *		fill task code and task data.
 * @cur_task_list: task list object, fill task code to it.
 * @du_desc: du data object, fill task data to it.
 * @rw_hdrs: parsed rewrite data.
 * @au_task_cnt: index of task in task list.
 * @cur_para: current parameter of task, data offset in dccm.
 * @cur_data_pos: current data position in du data object.
 */
void
nse_acl_fill_task_rewrite_l2_dmac(struct nse_sw_task_list *cur_task_list,
		struct nse_du_desc *du_desc, struct nse_acl_pedit_headers *rw_hdrs,
		u16 *au_task_cnt, u16 *cur_para, u16 *cur_data_pos)
{
	/*fill task code*/
	cur_task_list->task[*au_task_cnt].task_id =
			NSE_TASK_ID_L2_DMAC_REWRITE;
	cur_task_list->task[*au_task_cnt].data_para = *cur_para;
	*cur_para += NSE_TASK_REWRITE_MAC_PARA_LEN;
	(*au_task_cnt)++;

	/*fill task data*/
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->vals.eth.h_dest,
		NSE_TASK_REWRITE_MAC_VAL_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_MAC_VAL_LEN;
	memcpy(&du_desc->data[*cur_data_pos],
		&rw_hdrs->masks.eth.h_dest,
		NSE_TASK_REWRITE_MAC_MASK_LEN);
	*cur_data_pos += NSE_TASK_REWRITE_MAC_MASK_LEN;
}

/**
 * nse_acl_create_lg_action - create acl filter's large action.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
static int
nse_acl_create_lg_action(struct nse_hw *hw,
		struct nse_acl_fltr_info *fltr_info)
{
	struct nse_acl_large_action *lg_action = &fltr_info->lg_action;
	u32 act_flags = lg_action->flags;
	struct nse_node_state *node_state; /*local, alloc & free locally*/
	struct nse_sw_counter_pair *counter_p = NULL; /*global*/
	struct nse_sw_du_data *du_data = NULL; /*global*/
	struct nse_sw_task_list *task_list = NULL; /*global*/
	struct nse_sw_task_list *cur_task_list = NULL; /*local*/
	u16 du_act_cnt = 0, au_task_cnt = 0, du_desc_cnt = 0;
	int ret = 0, dstry_ret = 0, i = 0;

	node_state = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*node_state),
				 GFP_KERNEL);
	if (!node_state)
		return -ENOMEM;

	nse_init_node_state(node_state);

	/*1. build du action information*/
	if ((act_flags & NSE_ACL_LARGE_ACTION_DU_METER) &&
			lg_action->du_meter_cnt) {
		if (lg_action->du_meter_cnt > NSE_ACL_MAX_DU_METER_ACTIONS) {
			ret = -EINVAL;
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] It's not support due to too many du meter actions\n",
				__func__, __LINE__);
			goto add_large_action_fail;
		}

		for (i = 0; i < lg_action->du_meter_cnt; i++) {
			lg_action->du_meter_id[i] = NSE_METER_ID_INVALID;
			ret = nse_acl_create_meter(hw, &lg_action->du_meter_param[i]);
			if (ret) {
				ret = -EIO;
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to create acl large hw meter\n",
					__func__, __LINE__);
				goto add_large_action_fail;
			}

			lg_action->du_meter_id[i] = lg_action->du_meter_param[i].meter_id;
			node_state->du_action[du_act_cnt].meter_id =
				lg_action->du_meter_id[i];
			node_state->du_action[du_act_cnt++].du_act =
				NSE_DU_ACT_METER;
		}
	}

	if (act_flags & NSE_ACL_LARGE_ACTION_DROP) {
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_DROP_PACKET;
	}

	if (act_flags & NSE_ACL_LARGE_ACTION_GOTO) {
		node_state->du_action[du_act_cnt].dest_chain = 1;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_GOTO_CHAIN;
	}

	if (act_flags & NSE_ACL_LARGE_ACTION_FWD_VSI) {
		node_state->du_action[du_act_cnt].fwd_id.hw_vsi_id =
			lg_action->redirect_vsi;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_FWD_TO_VSI;
	}

	if (act_flags & NSE_ACL_LARGE_ACTION_COUNT) {
		counter_p = nse_sw_creat_counter_pair(hw, true);
		if (!counter_p) {
			ret = -ENOMEM;
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to create acl counter pair\n",
				__func__, __LINE__);
			goto add_large_action_fail;
		}

		node_state->du_action[du_act_cnt].hw_cnt_id =
			counter_p->p_counter.hw_id;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_COUNT_PACKET;

		node_state->du_action[du_act_cnt].hw_cnt_id =
			counter_p->b_counter.hw_id;
		node_state->du_action[du_act_cnt++].du_act =
			NSE_DU_ACT_COUNT_BYTE;

		lg_action->counter_p = counter_p;
	}

	/*2. build au action information*/
	if (nse_acl_is_task_list_needed(act_flags)) {
		u16 d_size = 0, t_cnt = 0;
		u16 cur_para = NSE_TASK_PARA_BASE, alloc_size;
		u16 cur_data_pos = 0;

		t_cnt = nse_acl_calc_au_task_cnt(lg_action);
		if (!t_cnt) {
			ret = -EIO;
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to calculate task count\n",
				__func__, __LINE__);
			goto add_large_action_fail;
		}

		alloc_size = struct_size(cur_task_list, task, t_cnt);
		cur_task_list = devm_kzalloc(nse_hw_to_dev(hw), alloc_size,
					 GFP_KERNEL);
		if (!cur_task_list) {
			ret = -ENOMEM;
			goto add_large_action_fail;
		}
		cur_task_list->task_cnt = t_cnt;

		d_size = nse_acl_calc_du_data_size(lg_action);
		if (d_size) {
			du_data = nse_sw_creat_du_data(hw, d_size);
			if (!du_data) {
				ret = -ENOMEM;
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to creat du data\n",
					__func__, __LINE__);
				goto au_task_fail;
			}
			lg_action->du_data = du_data;
			node_state->du_desc[du_desc_cnt].du_data_id =
								du_data->du_desc.du_data_id;
			node_state->du_desc[du_desc_cnt].data_size =
								du_data->du_desc.data_size;
			du_desc_cnt++;
		}

		if (act_flags & NSE_ACL_LARGE_ACTION_AU_NOP)
			nse_acl_fill_task_nop(cur_task_list, &au_task_cnt, 1);

		if (du_data) {
			struct nse_acl_pedit_headers *rw_hdrs = &lg_action->hdrs;
			struct nse_du_desc *du_desc = &du_data->du_desc;

			if (act_flags & NSE_ACL_LARGE_ACTION_AU_SMAC_RW)
				nse_acl_fill_task_rewrite_l2_smac(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);

			if (act_flags & NSE_ACL_LARGE_ACTION_AU_DMAC_RW)
				nse_acl_fill_task_rewrite_l2_dmac(cur_task_list, du_desc,
					rw_hdrs, &au_task_cnt, &cur_para, &cur_data_pos);

			ret = nse_sw_add_du_data(hw, du_data);
			if (ret) {
				ret = -EIO;
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to add du data\n",
					__func__, __LINE__);
				goto au_task_fail;
			}
		}

		task_list = nse_sw_get_task_list(hw, cur_task_list);
		if (!task_list) {
			ret = -ENOMEM;
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to get task list\n",
				__func__, __LINE__);
			goto au_task_fail;
		}
		lg_action->task_list = task_list;
		node_state->task_list_id = task_list->task_list_id;
		devm_kfree(nse_hw_to_dev(hw), cur_task_list);
	}

	ret = nse_sw_add_node_state(hw, node_state, du_act_cnt,
			au_task_cnt, du_desc_cnt);
	if (ret || node_state->node_state_id == NSE_NODE_STATE_ID_INVALID) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to add acl node state\n",
			__func__, __LINE__);
		goto add_large_action_fail;
	}

	node_state->du_act_cnt = du_act_cnt;
	node_state->au_task_cnt = au_task_cnt;
	node_state->du_desc_cnt = du_desc_cnt;
	lg_action->node_state = *node_state;
	lg_action->node_state_id = node_state->node_state_id;
	devm_kfree(nse_hw_to_dev(hw), node_state);
	return 0;

au_task_fail:
	if (cur_task_list)
		devm_kfree(nse_hw_to_dev(hw), cur_task_list);

add_large_action_fail:
	if (counter_p) {
		dstry_ret = nse_sw_destroy_counter_pair(hw, counter_p);
		lg_action->counter_p = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to destroy acl counter pair\n",
				__func__, __LINE__);
		}
	}

	if (du_data) {
		dstry_ret = nse_sw_destroy_du_data(hw, du_data);
		lg_action->du_data = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to destroy hw du data\n",
				__func__, __LINE__);
		}
	}

	if (task_list) {
		dstry_ret = nse_sw_put_task_list(hw, task_list);
		lg_action->task_list = NULL;
		if (dstry_ret) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to free task list\n",
				__func__, __LINE__);
		}
	}

	for (i = 0; i < lg_action->du_meter_cnt; i++) {
		if (lg_action->du_meter_id[i] == NSE_METER_ID_INVALID)
			continue;

		ret = nse_acl_destroy_meter(hw, lg_action->du_meter_id[i]);
		if (ret)
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to destroy acl hw meter, meter id = %d\n",
				__func__, __LINE__, lg_action->du_meter_id[i]);
	}

	devm_kfree(nse_hw_to_dev(hw), node_state);

	return ret;
}

/**
 * nse_acl_destroy_lg_action - remove acl filter's large action.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
static int
nse_acl_destroy_lg_action(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info)
{
	struct nse_acl_large_action *lg_action = &fltr_info->lg_action;
	int ret = 0, i;

	if (lg_action->node_state_id != NSE_NODE_STATE_ID_INVALID) {
		ret = nse_sw_rem_node_state(hw, &lg_action->node_state_id);
		lg_action->node_state_id = NSE_NODE_STATE_ID_INVALID;
		if (ret)
			dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to remove node state, err = %d\n",
			__func__, __LINE__, ret);
	}

	if (lg_action->counter_p) {
		ret = nse_sw_destroy_counter_pair(hw, lg_action->counter_p);
		lg_action->counter_p = NULL;
		if (ret)
			dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to destroy acl hw counter, err = %d\n",
			__func__, __LINE__, ret);
	}

	if (lg_action->task_list) {
		ret = nse_sw_put_task_list(hw, lg_action->task_list);
		lg_action->task_list = NULL;
		if (ret) {
			dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to free task list, err = %d\n",
			__func__, __LINE__, ret);
		}
	}

	if (lg_action->du_data) {
		ret = nse_sw_destroy_du_data(hw, lg_action->du_data);
		lg_action->du_data = NULL;
		if (ret) {
			dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to destroy hw du data, err = %d\n",
			__func__, __LINE__, ret);
		}
	}

	for (i = 0; i < lg_action->du_meter_cnt; i++) {
		if (lg_action->du_meter_id[i] == NSE_METER_ID_INVALID)
			continue;

		ret = nse_acl_destroy_meter(hw, lg_action->du_meter_id[i]);
		if (ret)
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to destroy acl hw meter, meter id = %d\n",
				__func__, __LINE__, lg_action->du_meter_id[i]);
	}

	return ret;
}

/**
 * nse_acl_add_action - add acl filter's action.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
static int
nse_acl_add_action(struct nse_hw *hw,
		struct nse_acl_fltr_info *fltr_info)
{
	int err = 0;

	switch (fltr_info->fltr_act) {
	case NSE_ACL_METER:
		err = nse_acl_create_meter(hw, &fltr_info->meter_param);
		if (err)
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to create acl hw meter\n",
				__func__, __LINE__);
		else
			fltr_info->meter_id = fltr_info->meter_param.meter_id;

		break;
	case NSE_ACL_LARGE_ACT:
		err = nse_acl_create_lg_action(hw, fltr_info);
		if (err)
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to create acl large action\n",
				__func__, __LINE__);
		break;

	case NSE_ACL_DROP:
	default:
		break;
	}

	return err;
}

/**
 * nse_acl_add_fltr - add acl filter, including action and lut.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
int
nse_acl_add_fltr(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info)
{
	int err = 0;

	if (!fltr_info)
		return -EINVAL;

	fltr_info->meter_id = NSE_METER_ID_INVALID;
	fltr_info->node_id = NSE_NODE_ID_INVALID;

	/*first, start to handle action part of acl filter, such as create meter obj*/
	err = nse_acl_add_action(hw, fltr_info);
	if (err) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] Failed to add acl action, action type = %d\n",
			__func__, __LINE__, fltr_info->fltr_act);
		return err;
	}

	/*second, start to handle lut node of acl filter*/
	return nse_acl_add_lut_node(hw, fltr_info);
}

/**
 * nse_acl_remove_lut_node - remove acl filter's lut node.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
static int
nse_acl_remove_lut_node(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info)
{
	/* Remove the lut node */
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lut_node;
	enum nse_status status;
	int err = 0;
	u16 buf_size = struct_size(buf, elem, 1);

	if (fltr_info->node_id == NSE_NODE_ID_INVALID) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to remove lut node due to invalid id\n",
				__func__, __LINE__);
		return -EINVAL;
	}

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;
	nse_acl_fill_lut_node(hw, fltr_info, lut_node,
			 NSE_AQ_ACL_OPC_REMOVE_LUT_NODE);

	dev_info(nse_hw_to_dev(hw), "[%s, %d] start to remove acl node\n", __func__, __LINE__);
	dev_info(nse_hw_to_dev(hw), "[%s, %d] lut id is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->lut_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] node_id is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->node_id));

	status = nse_aq_acl_lut_nodes(hw, buf, buf_size,
		NSE_AQ_ACL_OPC_REMOVE_LUT_NODE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to remove lut node\n", __func__, __LINE__);
		err = -EIO;
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
	return err;
}

/**
 * nse_acl_remove_action - remove acl filter's action.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
static int
nse_acl_remove_action(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info)
{
	int err = 0;

	switch (fltr_info->fltr_act) {
	case NSE_ACL_METER:
		err = nse_acl_destroy_meter(hw, fltr_info->meter_id);
		if (err)
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to destroy acl hw meter, meter id = %d\n",
				__func__, __LINE__, fltr_info->meter_id);
		break;
	case NSE_ACL_LARGE_ACT:
		err = nse_acl_destroy_lg_action(hw, fltr_info);
		if (err)
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to destroy acl large action\n",
				__func__, __LINE__);
		break;
	case NSE_ACL_DROP:
	default:
		break;
	}

	return err;
}

/**
 * nse_acl_remove_fltr - remove acl filter, including action and lut.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
void
nse_acl_remove_fltr(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info)
{
	int err = 0;

	if (!fltr_info)
		return;

	err = nse_acl_remove_lut_node(hw, fltr_info);
	if (err)
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to remove acl lut node, lut_id = %d, node_id = %d\n",
			__func__, __LINE__, fltr_info->lkup_type, fltr_info->node_id);

	err = nse_acl_remove_action(hw, fltr_info);
	if (err)
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to remove acl action, act type = %d, meter_id = %d\n",
			__func__, __LINE__, fltr_info->fltr_act, fltr_info->meter_id);
}

/**
 * nse_acl_get_meter_stats - get acl filter's meter statistic, including packets and bytes.
 * @hw: pointer to the HW struct
 * @fltr_info: pointer to acl filter information
 */
int
nse_acl_get_meter_stats(struct nse_hw *hw, struct nse_acl_fltr_info *fltr_info)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_policy_counters *buf;
	struct nse_aqc_policy_counter_elem *elem;
	u16 buf_size;
	int err = 0;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	elem = buf->elem;
	buf->count = cpu_to_le16(1);
	elem->policy_id = cpu_to_le16(fltr_info->meter_id);

	status = nse_aq_acl_get_pol_counter_val(hw, buf, buf_size);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to get acl meter statistic, err = %d\n", status);
		err = -EIO;
		goto read_fail;
	}

	fltr_info->packets_dropped = le64_to_cpu(elem->p_counter_val);
	fltr_info->bytes_dropped = le64_to_cpu(elem->b_counter_val);

read_fail:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return err;
}

