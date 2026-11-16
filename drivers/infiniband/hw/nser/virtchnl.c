// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#include "osdep.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "protos.h"
#include "virtchnl.h"
#include "ws.h"

static enum nser_hmc_rsrc_type hmc_rsrc_types[] = {
	NSER_HMC_IW_IRRQ_LITE,
	NSER_HMC_IW_IRRQ,
	NSER_HMC_IW_ORRQ,
	NSER_HMC_IW_XF,
	NSER_HMC_IW_SQCQE,
	NSER_HMC_IW_RQCQE,
	NSER_HMC_IW_CQP,
	NSER_HMC_IW_AEQ,
	NSER_HMC_IW_QP,
	NSER_HMC_IW_CQ,
	NSER_HMC_IW_CEQ,
	NSER_HMC_IW_MR,
	NSER_HMC_IW_MG,
	NSER_HMC_IW_MG_ID,
	NSER_HMC_IW_AH,
	NSER_HMC_IW_ARP,
	NSER_HMC_IW_DUP_IRRQ,
	NSER_HMC_IW_PBLE,
	NSER_HMC_IW_FW,
	NSER_HMC_IW_SQCQEFL,
	NSER_HMC_IW_RQCQEFL,
	NSER_HMC_IW_XFFL,
	NSER_HMC_IW_IRRQ_LITE_FL,
	NSER_HMC_IW_ORRQFL,
};

/**
 * nser_find_vf_dev - get vf struct pointer
 * @dev: shared device pointer
 * @vf_id: virtual function id
 */
struct nser_vfdev *nser_find_vf_dev(struct nser_sc_dev *dev, u16 vf_id)
{
	struct nser_vfdev *vf_dev = NULL;
	unsigned long flags;
	u16 iw_vf_idx;

	spin_lock_irqsave(&dev->vf_dev_lock, flags);
	for (iw_vf_idx = 0; iw_vf_idx < dev->num_vfs; iw_vf_idx++) {
		if (dev->vf_dev[iw_vf_idx] && dev->vf_dev[iw_vf_idx]->vf_id == vf_id) {
			vf_dev = dev->vf_dev[iw_vf_idx];
			refcount_inc(&vf_dev->refcnt);
			break;
		}
	}
	spin_unlock_irqrestore(&dev->vf_dev_lock, flags);

	return vf_dev;
}

/**
 * nser_remove_vf_dev - remove vf_dev
 * @dev: shared device pointer
 * @vf_dev: vf dev to be removed
 */
void nser_remove_vf_dev(struct nser_sc_dev *dev, struct nser_vfdev *vf_dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->vf_dev_lock, flags);
	dev->vf_dev[vf_dev->iw_vf_idx] = NULL;
	spin_unlock_irqrestore(&dev->vf_dev_lock, flags);
}

/**
 * nser_vchnl_pf_send_resp - Send channel version to VF
 * @dev: nser_vchnl_pf_send_resp device pointer
 * @vf_id: Virtual function ID associated with the message
 * @vchnl_msg: Virtual channel message buffer pointer
 * @param: parameter that is passed back to the VF
 * @param_len: length of parameter that's being passed in
 * @resp_code: response code sent back to VF
 */
static void nser_vchnl_pf_send_resp(struct nser_sc_dev *dev, u16 vf_id,
				     struct nser_virtchnl_op_buf *vchnl_msg,
				     void *param, u16 param_len, int resp_code)
{
	int ret_code;
	u8 resp_buf[NSER_VCHNL_MAX_VF_MSG_SIZE] = {};
	struct nser_virtchnl_resp_buf *vchnl_msg_resp;

	vchnl_msg_resp = (struct nser_virtchnl_resp_buf *)resp_buf;
	vchnl_msg_resp->op_ctx = vchnl_msg->op_ctx;
	vchnl_msg_resp->buf_len = NSER_VCHNL_RESP_DEFAULT_SIZE + param_len;
	vchnl_msg_resp->op_ret_code = (s16)resp_code;
	if (param_len)
		memcpy(vchnl_msg_resp->buf, param, param_len);

	ret_code = dev->vchnl_if->vchnl_send(dev, vf_id, resp_buf, vchnl_msg_resp->buf_len);
	if (ret_code)
		nser_dbg(dev, "VIRT: virt channel send failed 0x%x\n", ret_code);
}

/**
 * pf_valid_hmc_rsrc_type - Check obj_type input validation
 * @obj_type: type of hmc resource
 */
static bool pf_valid_hmc_rsrc_type(u16 obj_type)
{
	enum nser_hmc_rsrc_type *valid_rsrcs;
	u8 num_rsrcs, i;


	valid_rsrcs = hmc_rsrc_types;
	num_rsrcs = ARRAY_SIZE(hmc_rsrc_types);

	for (i = 0; i < num_rsrcs; i++) {
		if (obj_type == valid_rsrcs[i])
			return true;
	}

	return false;
}

/**
 * nser_pf_add_hmc_obj - Add HMC Object for VF
 * @vf_dev: pointer to the vf_dev
 * @hmc_obj: hmc_obj to be added
 */
static int nser_pf_add_hmc_obj(struct nser_vfdev *vf_dev,
				struct nser_virtchnl_hmc_obj_range *hmc_obj)
{
	struct nser_sc_dev *dev = vf_dev->pf_dev;
	struct nser_hmc_info *hmc_info = &vf_dev->hmc_info;
	struct nser_hmc_create_obj_info info = {};
	int ret_code;

	if (!vf_dev->pf_hmc_initialized) {
		ret_code = nser_pf_init_vfhmc(vf_dev->pf_dev, (u8)vf_dev->pmf_index);
		if (ret_code)
			return ret_code;
		vf_dev->pf_hmc_initialized = true;
	}

	if (!pf_valid_hmc_rsrc_type(hmc_obj->obj_type)) {
		nser_dbg(dev,
			  "VIRT: invalid hmc_rsrc type detected. vf_id %d obj_type 0x%x\n",
			  vf_dev->vf_id, hmc_obj->obj_type);
		return -EINVAL;
	}

	info.hmc_info = hmc_info;
	info.privileged = false;
	info.rsrc_type = (u32)hmc_obj->obj_type;
	info.entry_type = (info.rsrc_type == NSER_HMC_IW_PBLE) ?
			  NSER_SD_TYPE_PAGED : NSER_SD_TYPE_DIRECT;
	info.start_idx = hmc_obj->start_index;
	info.count = hmc_obj->obj_count;
	nser_dbg(vf_dev->pf_dev,
		  "VIRT: nser_VCHNL_OP_ADD_HMC_OBJ_RANGE.  Add %u type %u objects\n",
		  info.count, info.rsrc_type);

	return nser_sc_create_hmc_obj(vf_dev->pf_dev, &info);
}

/**
 * nser_pf_del_hmc_obj - Delete HMC Object for VF
 * @vf_dev: pointer to the vf_dev
 * @hmc_obj: hmc_obj to be deleted
 */
static int nser_pf_del_hmc_obj(struct nser_vfdev *vf_dev,
				struct nser_virtchnl_hmc_obj_range *hmc_obj)
{
	struct nser_sc_dev *dev = vf_dev->pf_dev;
	struct nser_hmc_info *hmc_info = &vf_dev->hmc_info;
	struct nser_hmc_del_obj_info info = {};

	if (!vf_dev->pf_hmc_initialized)
		return -EINVAL;

	if (!pf_valid_hmc_rsrc_type(hmc_obj->obj_type)) {
		nser_dbg(dev,
			  "VIRT: invalid hmc_rsrc type detected. vf_id %d obj_type 0x%x\n",
			  vf_dev->vf_id, hmc_obj->obj_type);
		return -EINVAL;
	}

	info.hmc_info = hmc_info;
	info.privileged = false;
	info.rsrc_type = (u32)hmc_obj->obj_type;
	info.start_idx = hmc_obj->start_index;
	info.count = hmc_obj->obj_count;
	nser_dbg(vf_dev->pf_dev,
		  "VIRT: nser_VCHNL_OP_DEL_HMC_OBJ_RANGE. Delete %u type %u objects\n",
		  info.count, info.rsrc_type);

	return nser_sc_del_hmc_obj(vf_dev->pf_dev, &info, false);
}

/**
 * nser_pf_manage_ws_node - managing ws node for VF
 * @vf_dev: pointer to the VF Device
 * @ws_node: work scheduler node to be modified
 * @qs_handle: returned qs_handle provided by cqp
 */
static int
nser_pf_manage_ws_node(struct nser_vfdev *vf_dev,
			struct nser_virtchnl_manage_ws_node *ws_node,
			u16 *qs_handle)
{
	int ret_code = 0;
	struct nser_sc_vsi *vsi = vf_dev->vf_vsi;

	if (ws_node->user_pri >= NSER_MAX_USER_PRIORITY)
		return -EINVAL;

	nser_dbg(vf_dev->pf_dev,
		  "VIRT: nser_VCHNL_OP_MANAGE_WS_NODE. Add %d vf_id %d\n",
		  ws_node->add, vf_dev->vf_id);

	if (ws_node->add) {
		ret_code = vsi->dev->ws_add(vsi, ws_node->user_pri);
		if (ret_code)
			nser_dbg(vf_dev->pf_dev,
				  "VIRT: nser_ws_add failed ret_code = %x\n",
				  ret_code);
		else
			*qs_handle = vsi->qos[ws_node->user_pri].qs_handle;
	} else {
		vsi->dev->ws_remove(vsi, ws_node->user_pri);
	}

	return ret_code;
}

/**
 * nser_set_hmc_fcn_info - Populate hmc_fcn_info struct
 * @vf_dev: pointer to VF dev structure
 * @hmc_fcn_info: pointer to HMC fcn info to be filled up
 */
static
void nser_set_hmc_fcn_info(struct nser_vfdev *vf_dev,
			    struct nser_hmc_fcn_info *hmc_fcn_info)
{
	memset(hmc_fcn_info, 0, sizeof(*hmc_fcn_info));

	hmc_fcn_info->vf_id = vf_dev->vf_vsi->vsi_idx;
}

/**
 * nser_get_next_vf_idx - return the next vf_idx available
 * @dev: pointer to RDMA dev structure
 */
static u16 nser_get_next_vf_idx(struct nser_sc_dev *dev)
{
	u16 vf_idx;

	for (vf_idx = 0; vf_idx < dev->num_vfs; vf_idx++) {
		if (!dev->vf_dev[vf_idx])
			break;
	}

	return vf_idx < dev->num_vfs ? vf_idx : NSER_VCHNL_INVALID_VF_IDX;
}

/**
 * nser_put_vfdev - put vfdev and free memory
 * @dev: pointer to RDMA dev structure
 * @vf_dev: pointer to RDMA vf dev structure
 */
void nser_put_vfdev(struct nser_sc_dev *dev, struct nser_vfdev *vf_dev)
{
	if (refcount_dec_and_test(&vf_dev->refcnt)) {
		struct nser_virt_mem virt_mem;

		if (vf_dev->hmc_info.sd_table.sd_entry) {
			virt_mem.va = vf_dev->hmc_info.sd_table.sd_entry;
			virt_mem.size = sizeof(struct nser_hmc_sd_entry) *
					(vf_dev->hmc_info.sd_table.sd_cnt +
					 vf_dev->hmc_info.first_sd_index);
			kfree(virt_mem.va);
		}

		virt_mem.va = vf_dev;
		virt_mem.size = sizeof(*vf_dev);
		kfree(virt_mem.va);
	}
}

/**
 * nser_pf_get_vf_hmc_fcn - Get hmc fcn from CQP for VF
 * @dev: pointer to RDMA dev structure
 * @vf_id: vf id of the hmc fcn requester
 */
static struct nser_vfdev *nser_pf_get_vf_hmc_fcn(struct nser_sc_dev *dev, u16 vf_id)
{
	struct nser_hmc_fcn_info hmc_fcn_info;
	struct nser_virt_mem virt_mem;
	struct nser_vfdev *vf_dev;
	struct nser_sc_vsi *vsi;
	u16 iw_vf_idx = 0;

	iw_vf_idx = nser_get_next_vf_idx(dev);
	if (iw_vf_idx == NSER_VCHNL_INVALID_VF_IDX)
		return NULL;

	virt_mem.size = sizeof(struct nser_vfdev) +
					sizeof(struct nser_hmc_obj_info) * NSER_HMC_IW_MAX;
	virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);

	if (!virt_mem.va)
		return NULL;

	vf_dev = virt_mem.va;
	vf_dev->pf_dev = dev;
	vf_dev->vf_id = vf_id;
	vf_dev->iw_vf_idx = iw_vf_idx;
	vf_dev->pf_hmc_initialized = false;
	vf_dev->hmc_info.hmc_obj = (struct nser_hmc_obj_info *)(&vf_dev[1]);

	nser_dbg(dev, "VIRT: vf_dev %p, hmc_info %p, hmc_obj %p\n", vf_dev,
		  &vf_dev->hmc_info, vf_dev->hmc_info.hmc_obj);
	vsi = nser_update_vsi_ctx(dev, vf_dev, true);
	if (!vsi) {
		nser_dbg(dev, "VIRT: VF%u failed updating vsi ctx .\n", vf_id);
		dev->vf_dev[vf_dev->iw_vf_idx] = NULL;
		kfree(virt_mem.va);
		return NULL;
	}

	refcount_set(&vf_dev->refcnt, 1);
	dev->vf_dev[iw_vf_idx] = vf_dev;
	vf_dev->vf_vsi = vsi;
	vsi->vf_id = (u16)vf_dev->vf_id;
	vsi->vf_dev = vf_dev;

	nser_set_hmc_fcn_info(vf_dev, &hmc_fcn_info);
	if (nser_cqp_manage_hmc_fcn_cmd(dev, &hmc_fcn_info, &vf_dev->pmf_index)) {
		nser_update_vsi_ctx(dev, vf_dev, false);
		dev->vf_dev[vf_dev->iw_vf_idx] = NULL;
		kfree(virt_mem.va);
		nser_dbg(dev,
			  "VIRT: VF%u error CQP Get HMC Function operation.\n",
			  vf_id);
		return NULL;
	}

	nser_dbg(dev, "VIRT: HMC Function allocated = 0x%08x\n",
		  vf_dev->pmf_index);

	/* Caller references vf_dev */
	refcount_inc(&vf_dev->refcnt);
	return vf_dev;
}

/**
 * nser_pf_put_vf_hmc_fcn - Put hmc fcn from CQP for VF
 * @dev: pointer to RDMA dev structure
 * @vf_dev: vf dev structure
 */
void nser_pf_put_vf_hmc_fcn(struct nser_sc_dev *dev, struct nser_vfdev *vf_dev)
{
	struct nser_hmc_fcn_info hmc_fcn_info;

	nser_set_hmc_fcn_info(vf_dev, &hmc_fcn_info);
	hmc_fcn_info.free_fcn = true;
	if (nser_cqp_manage_hmc_fcn_cmd(dev, &hmc_fcn_info, &vf_dev->pmf_index)) {
		nser_dbg(dev,
			  "VIRT: VF%u error CQP Free HMC Function operation.\n",
			  vf_dev->vf_id);
	}

	nser_remove_vf_dev(dev, vf_dev);

	nser_update_vsi_ctx(dev, vf_dev, false);
	nser_put_vfdev(dev, vf_dev);
}

/**
 * nser_recv_pf_worker - PF receive worker processes inbound vchnl request
 * @work: work element for the vchnl request
 */
static void nser_recv_pf_worker(struct work_struct *work)
{
	struct nser_virtchnl_work *vchnl_work;
	struct nser_virtchnl_op_buf *vchnl_msg;

	vchnl_work = container_of(work, struct nser_virtchnl_work, work);
	vchnl_msg = (struct nser_virtchnl_op_buf *)&vchnl_work->vf_msg_buf;
	u16 vf_id = vchnl_work->vf_id, qs_handle = 0, resp_len = 0;
	void *param = vchnl_msg->buf, *resp_param = NULL;
	int resp_code = 0;
	struct nser_sc_dev *dev = vchnl_work->dev;
	struct nser_vfdev *vf_dev = NULL;
	struct nser_virt_mem virt_mem;
	u8 vlan_parse_en;
	u32 vchnl_ver;

	nser_dbg(dev, "VIRT: opcode %u", vchnl_msg->op_code);
	vf_dev = nser_find_vf_dev(dev, vf_id);
	if (vf_dev && vf_dev->reset_en)
		goto free_work;

	switch (vchnl_msg->op_code) {
	case NSER_VCHNL_OP_GET_VER:
		vchnl_ver = NSER_VCHNL_CHNL_VER_V1;
		resp_code = vchnl_msg->op_ver == NSER_VCHNL_OP_GET_VER_V1 ?
						 0 : -EOPNOTSUPP;
		resp_param = &vchnl_ver;
		resp_len = sizeof(vchnl_ver);
		break;
	case NSER_VCHNL_OP_GET_HMC_FCN:
		if (!vf_dev) {
			vf_dev = nser_pf_get_vf_hmc_fcn(dev, vf_id);
			if (!vf_dev) {
				resp_code = -ENODEV;
				break;
			}
		}

		resp_param = &vf_dev->pmf_index;
		resp_len = sizeof(vf_dev->pmf_index);
		break;
	case NSER_VCHNL_OP_PUT_HMC_FCN:
		if (!vf_dev)
			goto free_work;

		nser_pf_put_vf_hmc_fcn(dev, vf_dev);
		break;

	case NSER_VCHNL_OP_ADD_HMC_OBJ_RANGE:
		if (!vf_dev)
			goto free_work;

		resp_code = nser_pf_add_hmc_obj(vf_dev, param);
		break;
	case NSER_VCHNL_OP_DEL_HMC_OBJ_RANGE:
		if (!vf_dev)
			goto free_work;

		resp_code = nser_pf_del_hmc_obj(vf_dev, param);
		break;
	case NSER_VCHNL_OP_MANAGE_WS_NODE:
		if (!vf_dev)
			goto free_work;

		resp_code = nser_pf_manage_ws_node(vf_dev, param, &qs_handle);
		resp_param = &qs_handle;
		resp_len = sizeof(qs_handle);
		break;
	case NSER_VCHNL_OP_VLAN_PARSING:
		if (!vf_dev)
			goto free_work;

		nser_update_vf_vlan_cfg(dev, vf_dev);
		/* In Linux port_vlan_id != 0 indicates port vlan is enabled.
		 * Linux is always in double VLAN mode.
		 */
		vlan_parse_en = !vf_dev->port_vlan_en;
		nser_dbg(dev, "VIRT: vlan_parse_en = 0x%x\n", vlan_parse_en);

		resp_param = &vlan_parse_en;
		resp_len = sizeof(vlan_parse_en);
		break;
	default:
		nser_dbg(dev, "VIRT: Invalid OpCode 0x%x\n",
			  vchnl_msg->op_code);
		resp_code = -EOPNOTSUPP;
	}

	nser_vchnl_pf_send_resp(dev, vf_id, vchnl_msg, resp_param, resp_len, resp_code);
free_work:
	if (vf_dev)
		nser_put_vfdev(dev, vf_dev);

	virt_mem.va = work;
	kfree(virt_mem.va);
}

/**
 * nser_vchnl_pf_verify_msg - validate vf received vchannel message size
 * @vchnl_msg: inbound vf vchannel message
 * @len: length of the virtual channels message
 */
static bool nser_vchnl_pf_verify_msg(struct nser_virtchnl_op_buf *vchnl_msg,
				      u16 len)
{
	u16 op_code = vchnl_msg->op_code;

	if (len > NSER_VCHNL_MAX_VF_MSG_SIZE)
		return false;

	if (len < sizeof(*vchnl_msg))
		return false;

	switch (op_code) {
	case NSER_VCHNL_OP_ADD_HMC_OBJ_RANGE:
	case NSER_VCHNL_OP_DEL_HMC_OBJ_RANGE:
		if (len < NSER_VCHNL_RESP_DEFAULT_SIZE +
			  sizeof(struct nser_virtchnl_hmc_obj_range))
			return false;
		break;
	case NSER_VCHNL_OP_MANAGE_WS_NODE:
		if (len < NSER_VCHNL_RESP_DEFAULT_SIZE +
			  sizeof(struct nser_virtchnl_manage_ws_node))
			return false;
		break;
	case NSER_VCHNL_OP_VLAN_PARSING:
		if (len < NSER_VCHNL_RESP_DEFAULT_SIZE)
			return false;
		break;
	default:
		if (len < NSER_VCHNL_RESP_DEFAULT_SIZE)
			return false;
	}

	return true;
}
/**
 * nser_vchnl_recv_pf - Receive PF virtual channel messages
 * @dev: RDMA device pointer
 * @vf_id: Virtual function ID associated with the message
 * @msg: Virtual channel message buffer pointer
 * @len: Length of the virtual channels message
 */
int nser_vchnl_recv_pf(struct nser_sc_dev *dev, u16 vf_id, u8 *msg, u16 len)
{
	struct nser_virtchnl_work *work;
	struct nser_virt_mem workmem;

	nser_dbg(dev, "VIRT: VF%u: msg %p len %u chnl up %u", vf_id, msg,
		  len, dev->vchnl_up);

	if (!msg || !nser_vchnl_pf_verify_msg((struct nser_virtchnl_op_buf *)msg, len))
		return -EINVAL;

	if (!dev->vchnl_up)
		return -EBUSY;

	workmem.size = sizeof(struct nser_virtchnl_work);
	workmem.va = kzalloc(workmem.size, GFP_KERNEL);
	if (!workmem.va)
		return -ENOMEM;

	work = workmem.va;
	memcpy(&work->vf_msg_buf, msg, len);
	work->dev = dev;
	work->vf_id = vf_id;
	work->len = len;
	INIT_WORK(&work->work, nser_recv_pf_worker);
	queue_work(dev->vchnl_wq, &work->work);

	return 0;
}

/**
 * nser_vchnl_vf_verify_resp - Verify requested response size
 * @vchnl_req: vchnl message requested
 * @resp_len: response length sent from vchnl peer
 */
static int nser_vchnl_vf_verify_resp(struct nser_virtchnl_req *vchnl_req,
				      u16 resp_len)
{
	switch (vchnl_req->vchnl_msg->op_code) {
	case NSER_VCHNL_OP_GET_VER:
	case NSER_VCHNL_OP_GET_HMC_FCN:
	case NSER_VCHNL_OP_PUT_HMC_FCN:
	case NSER_VCHNL_OP_ADD_HMC_OBJ_RANGE:
	case NSER_VCHNL_OP_DEL_HMC_OBJ_RANGE:
	case NSER_VCHNL_OP_MANAGE_STATS_INST:
	case NSER_VCHNL_OP_MCG:
	case NSER_VCHNL_OP_UP_MAP:
	case NSER_VCHNL_OP_MANAGE_WS_NODE:
	case NSER_VCHNL_OP_GET_STATS:
	case NSER_VCHNL_OP_VLAN_PARSING:
		if (resp_len != vchnl_req->parm_len)
			return -EBADMSG;
		break;
	default:
		return -EBADMSG;
	}

	return 0;
}

static int nser_vf_send_sync(struct nser_sc_dev *dev,
			      struct nser_virtchnl_req *vchnl_req)
{
	u16 resp_len = sizeof(dev->vf_recv_buf);
	int ret_code;
	u8 *msg = (u8 *)vchnl_req->vchnl_msg;
	u16 msg_len = vchnl_req->vchnl_msg->buf_len;

	mutex_lock(&dev->vchnl_mutex);
	if (!dev->vchnl_up) {
		ret_code = -ETIMEDOUT;
		goto exit;
	}

	ret_code = dev->vchnl_if->vchnl_send_sync(dev, msg, msg_len,
						  dev->vf_recv_buf, &resp_len);
	if (ret_code) {
		if (ret_code == -ETIMEDOUT)
			dev->vchnl_up = false;
		goto exit;
	}

	ret_code = nser_vchnl_vf_get_resp(dev, vchnl_req);

exit:
	mutex_unlock(&dev->vchnl_mutex);

	return ret_code;
}

/**
 * nser_vchnl_vf_manage_ws_node - manage ws node
 * @dev: RDMA device pointer
 * @add: Add or remove ws node
 * @user_pri: user priority of ws node
 * @qs_handle: qs_handle updated from the vchnl response
 */
int nser_vchnl_vf_manage_ws_node(struct nser_sc_dev *dev, bool add,
				  u8 user_pri, u16 *qs_handle)
{
	struct nser_virtchnl_manage_ws_node *ws_node;
	struct nser_virtchnl_req vchnl_req = {};
	struct nser_virtchnl_op_buf *vchnl_msg;
	int ret_code;

	if (!dev->vchnl_up)
		return -EBUSY;

	vchnl_req.vchnl_msg = kzalloc(NSER_VCHNL_MAX_VF_MSG_SIZE, GFP_KERNEL);
	if (!vchnl_req.vchnl_msg)
		return -ENOMEM;

	if (add) {
		vchnl_req.parm = qs_handle;
		vchnl_req.parm_len = sizeof(*qs_handle);
	}

	vchnl_msg = vchnl_req.vchnl_msg;
	memset(vchnl_msg, 0, sizeof(*vchnl_msg));
	vchnl_msg->op_ctx = (uintptr_t)&vchnl_req;
	vchnl_msg->buf_len = sizeof(*vchnl_msg) +
			     sizeof(struct nser_virtchnl_manage_ws_node);

	vchnl_msg->op_code = NSER_VCHNL_OP_MANAGE_WS_NODE;
	vchnl_msg->op_ver = NSER_VCHNL_OP_MANAGE_WS_NODE_V0;

	ws_node = (struct nser_virtchnl_manage_ws_node *)vchnl_msg->buf;
	memset(ws_node, 0, sizeof(*ws_node));
	ws_node->add = add;
	ws_node->user_pri = user_pri;

	nser_dbg(dev,
		  "VIRT: Sending message: manage_ws_node add = %d, user_pri = %d\n",
		  ws_node->add, ws_node->user_pri);

	ret_code = nser_vf_send_sync(dev, &vchnl_req);
	kfree(vchnl_msg);

	if (ret_code)
		nser_dbg(dev, "VIRT: virt channel send failed 0x%x\n",
			  ret_code);

	return ret_code;
}

/**
 * nser_vchnl_recv_vf - Receive VF virtual channel messages
 * @dev: RDMA device pointer
 * @vf_id: Virtual function ID associated with the message
 * @msg: Virtual channel message buffer pointer
 * @len: Length of the virtual channels message
 */
int nser_vchnl_recv_vf(struct nser_sc_dev *dev, u16 vf_id, u8 *msg, u16 len)
{
	if (len < sizeof(struct nser_virtchnl_resp_buf) || len > NSER_VCHNL_MAX_VF_MSG_SIZE)
		return -EINVAL;

	memcpy(dev->vf_recv_buf, msg, len);
	dev->vf_recv_len = len;

	return 0;
}

/**
 * nser_vchnl_vf_get_ver - Request Channel version
 * @dev: RDMA device pointer
 * @vchnl_ver: Virtual channel message version pointer
 */
int nser_vchnl_vf_get_ver(struct nser_sc_dev *dev, u32 *vchnl_ver)
{
	struct nser_virtchnl_req vchnl_req = {};
	struct nser_virtchnl_op_buf *vchnl_msg;
	int ret_code;

	if (!dev->vchnl_up)
		return -EBUSY;

	vchnl_req.vchnl_msg = kzalloc(NSER_VCHNL_MAX_VF_MSG_SIZE, GFP_KERNEL);
	if (!vchnl_req.vchnl_msg)
		return -ENOMEM;

	vchnl_req.parm = vchnl_ver;
	vchnl_req.parm_len = sizeof(*vchnl_ver);

	vchnl_msg = vchnl_req.vchnl_msg;
	memset(vchnl_msg, 0, sizeof(*vchnl_msg));
	vchnl_msg->op_ctx = (uintptr_t)&vchnl_req;
	vchnl_msg->buf_len = sizeof(*vchnl_msg);
	vchnl_msg->op_code = NSER_VCHNL_OP_GET_VER;
	vchnl_msg->op_ver = NSER_VCHNL_OP_GET_VER_V1;

	ret_code = nser_vf_send_sync(dev, &vchnl_req);
	kfree(vchnl_msg);
	if (ret_code) {
		nser_dbg(dev, "VIRT: virt channel send failed 0x%x\n",
			  ret_code);
		return ret_code;
	}

	if (*vchnl_ver > NSER_VCHNL_CHNL_VER_V1) {
		nser_dbg(dev, "VIRT: %s unsupported vchnl version 0x%0x\n",
			  __func__, *(u32 *)vchnl_req.parm);
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * nser_vchnl_vf_get_hmc_fcn - Request VF HMC Function
 * @dev: RDMA device pointer
 */
int nser_vchnl_vf_get_hmc_fcn(struct nser_sc_dev *dev)
{
	struct nser_virtchnl_req vchnl_req = {};
	struct nser_virtchnl_op_buf *vchnl_msg;
	int ret_code;

	if (!dev->vchnl_up)
		return -EBUSY;

	vchnl_req.vchnl_msg = kzalloc(NSER_VCHNL_MAX_VF_MSG_SIZE, GFP_KERNEL);
	if (!vchnl_req.vchnl_msg)
		return -ENOMEM;

	vchnl_msg = vchnl_req.vchnl_msg;
	memset(vchnl_msg, 0, sizeof(*vchnl_msg));
	vchnl_msg->op_ctx = (uintptr_t)&vchnl_req;
	vchnl_msg->buf_len = sizeof(*vchnl_msg);
	vchnl_msg->op_code = NSER_VCHNL_OP_GET_HMC_FCN;
	vchnl_msg->op_ver = NSER_VCHNL_OP_GET_HMC_FCN_V0;
	ret_code = nser_vf_send_sync(dev, &vchnl_req);
	kfree(vchnl_req.vchnl_msg);
	if (ret_code)
		nser_dbg(dev, "VIRT: virt channel send failed 0x%x\n",
			  ret_code);
	return ret_code;
}

/**
 * nser_vchnl_vf_put_hmc_fcn - Free VF HMC Function
 * @dev: RDMA device pointer
 */
int nser_vchnl_vf_put_hmc_fcn(struct nser_sc_dev *dev)
{
	struct nser_virtchnl_req vchnl_req = {};
	struct nser_virtchnl_op_buf *vchnl_msg;
	int ret_code;

	if (!dev->vchnl_up)
		return -EBUSY;

	vchnl_req.vchnl_msg = kzalloc(NSER_VCHNL_MAX_VF_MSG_SIZE, GFP_KERNEL);
	if (!vchnl_req.vchnl_msg)
		return -ENOMEM;

	vchnl_msg = vchnl_req.vchnl_msg;
	memset(vchnl_msg, 0, sizeof(*vchnl_msg));
	vchnl_msg->op_ctx = (uintptr_t)&vchnl_req;
	vchnl_msg->buf_len = sizeof(*vchnl_msg);
	vchnl_msg->op_code = NSER_VCHNL_OP_PUT_HMC_FCN;
	vchnl_msg->op_ver = NSER_VCHNL_OP_PUT_HMC_FCN_V0;

	ret_code = nser_vf_send_sync(dev, &vchnl_req);
	kfree(vchnl_req.vchnl_msg);

	if (ret_code)
		nser_dbg(dev, "VIRT: Send message failed 0x%0x\n", ret_code);
	return ret_code;
}

/**
 * nser_vchnl_vf_add_hmc_objs - Add HMC Object
 * @dev: RDMA device pointer
 * @rsrc_type: HMC Resource type
 * @start_index: Starting index of the objects to be added
 * @rsrc_count: Number of resources to be added
 */
int nser_vchnl_vf_add_hmc_objs(struct nser_sc_dev *dev,
				enum nser_hmc_rsrc_type rsrc_type,
				u32 start_index, u32 rsrc_count)
{
	struct nser_virtchnl_hmc_obj_range *add_hmc_obj;
	struct nser_virtchnl_req vchnl_req = {};
	struct nser_virtchnl_op_buf *vchnl_msg;
	int ret_code;

	if (!dev->vchnl_up)
		return -EBUSY;

	vchnl_req.vchnl_msg = kzalloc(NSER_VCHNL_MAX_VF_MSG_SIZE, GFP_KERNEL);
	if (!vchnl_req.vchnl_msg)
		return -ENOMEM;

	vchnl_msg = vchnl_req.vchnl_msg;
	memset(vchnl_msg, 0, sizeof(*vchnl_msg));
	vchnl_msg->op_ctx = (uintptr_t)&vchnl_req;
	vchnl_msg->buf_len = sizeof(*vchnl_msg) + sizeof(struct nser_virtchnl_hmc_obj_range);
	vchnl_msg->op_code = NSER_VCHNL_OP_ADD_HMC_OBJ_RANGE;
	vchnl_msg->op_ver = NSER_VCHNL_OP_ADD_HMC_OBJ_RANGE_V0;

	add_hmc_obj = (struct nser_virtchnl_hmc_obj_range *)vchnl_msg->buf;
	memset(add_hmc_obj, 0, sizeof(*add_hmc_obj));
	add_hmc_obj->obj_type = (u16)rsrc_type;
	add_hmc_obj->start_index = start_index;
	add_hmc_obj->obj_count = rsrc_count;
	nser_dbg(dev,
		  "VIRT: Sending message: obj_type = %d, start_index = %d, obj_count = %d\n",
		  add_hmc_obj->obj_type, add_hmc_obj->start_index,
		  add_hmc_obj->obj_count);

	ret_code = nser_vf_send_sync(dev, &vchnl_req);
	kfree(vchnl_msg);

	if (ret_code)
		nser_dbg(dev, "VIRT: Send message failed 0x%0x\n", ret_code);
	return ret_code;
}

/**
 * nser_vchnl_vf_del_hmc_obj - del HMC obj
 * @dev: RDMA device pointer
 * @rsrc_type: HMC Resource type
 * @start_index: Starting index of the object to delete
 * @rsrc_count: Number of resources to be delete
 */
int nser_vchnl_vf_del_hmc_obj(struct nser_sc_dev *dev,
			       enum nser_hmc_rsrc_type rsrc_type,
			       u32 start_index, u32 rsrc_count)
{
	struct nser_virtchnl_hmc_obj_range *hmc_obj;
	struct nser_virtchnl_req vchnl_req = {};
	struct nser_virtchnl_op_buf *vchnl_msg;
	int ret_code;

	if (!dev->vchnl_up)
		return -EBUSY;

	vchnl_req.vchnl_msg = kzalloc(NSER_VCHNL_MAX_VF_MSG_SIZE, GFP_KERNEL);
	if (!vchnl_req.vchnl_msg)
		return -ENOMEM;

	vchnl_msg = vchnl_req.vchnl_msg;
	memset(vchnl_msg, 0, sizeof(*vchnl_msg));
	vchnl_msg->op_ctx = (uintptr_t)&vchnl_req;
	vchnl_msg->buf_len = sizeof(*vchnl_msg) + sizeof(struct nser_virtchnl_hmc_obj_range);
	vchnl_msg->op_code = NSER_VCHNL_OP_DEL_HMC_OBJ_RANGE;
	vchnl_msg->op_ver = NSER_VCHNL_OP_DEL_HMC_OBJ_RANGE_V0;

	hmc_obj = (struct nser_virtchnl_hmc_obj_range *)vchnl_msg->buf;
	memset(hmc_obj, 0, sizeof(*hmc_obj));
	hmc_obj->obj_type = (u16)rsrc_type;
	hmc_obj->start_index = start_index;
	hmc_obj->obj_count = rsrc_count;

	ret_code = nser_vf_send_sync(dev, &vchnl_req);
	kfree(vchnl_msg);

	if (ret_code)
		nser_dbg(dev, "VIRT: Send message failed 0x%0x\n", ret_code);

	return ret_code;
}

/**
 * nser_vchnl_vf_get_vlan_parsing_cfg - Find if vlan should be processed
 * @dev: Dev pointer
 * @vlan_parse_en: vlan parsing enabled
 */
int nser_vchnl_vf_get_vlan_parsing_cfg(struct nser_sc_dev *dev,
					u8 *vlan_parse_en)
{
	int ret_code;
	struct nser_virtchnl_req vchnl_req = {};
	struct nser_virtchnl_op_buf *vchnl_msg;

	if (!dev->vchnl_up)
		return -EBUSY;

	vchnl_req.vchnl_msg = kzalloc(NSER_VCHNL_MAX_VF_MSG_SIZE, GFP_KERNEL);
	if (!vchnl_req.vchnl_msg)
		return -ENOMEM;

	vchnl_req.parm = vlan_parse_en;
	vchnl_req.parm_len = sizeof(*vlan_parse_en);

	vchnl_msg = vchnl_req.vchnl_msg;
	memset(vchnl_msg, 0, sizeof(*vchnl_msg));
	memcpy(vchnl_msg->buf, vlan_parse_en, sizeof(*vlan_parse_en));
	vchnl_msg->buf_len = sizeof(*vchnl_msg) + sizeof(*vlan_parse_en);
	vchnl_msg->op_ctx = (uintptr_t)&vchnl_req;
	vchnl_msg->op_code = NSER_VCHNL_OP_VLAN_PARSING;
	vchnl_msg->op_ver = NSER_VCHNL_OP_VLAN_PARSING_V0;

	ret_code = nser_vf_send_sync(dev, &vchnl_req);
	kfree(vchnl_msg);

	if (ret_code) {
		nser_dbg(dev, "VIRT: virt channel send failed 0x%x\n",
			  ret_code);
		return ret_code;
	}

	*vlan_parse_en = *(u8 *)vchnl_req.parm;
	return 0;
}

/**
 * nser_vchnl_vf_get_resp - Get the inbound vchnl recv response.
 * @dev: Dev pointer
 * @vchnl_req: Vchannel request
 */
int nser_vchnl_vf_get_resp(struct nser_sc_dev *dev,
			    struct nser_virtchnl_req *vchnl_req)
{
	struct nser_virtchnl_resp_buf *vchnl_msg_resp =
		(struct nser_virtchnl_resp_buf *)dev->vf_recv_buf;
	int ret_code;
	u16 resp_len;

	if ((uintptr_t)vchnl_req != (uintptr_t)vchnl_msg_resp->op_ctx) {
		nser_dbg(dev,
			  "VIRT: error vchnl context value does not match\n");
		return -EBADMSG;
	}

	resp_len = dev->vf_recv_len - sizeof(*vchnl_msg_resp);
	resp_len = min(resp_len, vchnl_req->parm_len);

	if (nser_vchnl_vf_verify_resp(vchnl_req, resp_len) != 0)
		return -EBADMSG;

	ret_code = (int)vchnl_msg_resp->op_ret_code;
	if (ret_code)
		return ret_code;

	vchnl_req->resp_len = 0;
	if (vchnl_req->parm_len && vchnl_req->parm && resp_len) {
		memcpy(vchnl_req->parm, vchnl_msg_resp->buf, resp_len);
		vchnl_req->resp_len = resp_len;
		nser_dbg(dev, "VIRT: Got response, data size %u\n", resp_len);
	}

	return 0;
}
