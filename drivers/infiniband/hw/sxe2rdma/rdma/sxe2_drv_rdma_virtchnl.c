// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_virtchnl.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_virtchnl.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_main.h"
#include "sxe2_drv_rdma_qos.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_mbx_public.h"
#include <linux/printk.h>

struct sxe2_rdma_vchnl_dev *
sxe2_vchnl_find_vc_dev(struct sxe2_rdma_ctx_dev *dev, u16 vf_id)
{
	struct sxe2_rdma_vchnl_dev *vc_dev = NULL;
	unsigned long flags		   = 0;
	u16 vf_idx;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	spin_lock_irqsave(&dev->vc_dev_lock, flags);
	for (vf_idx = 0; vf_idx < dev->num_vfs; vf_idx++) {
		if (dev->vc_dev[vf_idx] &&
		    dev->vc_dev[vf_idx]->vf_id == vf_id) {
			vc_dev = dev->vc_dev[vf_idx];
			refcount_inc(&vc_dev->refcnt);
			DRV_RDMA_LOG_DEBUG_BDF(
				"vchnl:vf id %u find vc dev vf idx %u\n", vf_id,
				vf_idx);
			break;
		}
	}
	spin_unlock_irqrestore(&dev->vc_dev_lock, flags);

	return vc_dev;
}

static void sxe2_vchnl_remove_vc_dev(struct sxe2_rdma_ctx_dev *dev,
				     struct sxe2_rdma_vchnl_dev *vc_dev)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&dev->vc_dev_lock, flags);
	dev->vc_dev[vc_dev->vf_idx] = NULL;
	spin_unlock_irqrestore(&dev->vc_dev_lock, flags);
}

int sxe2_vchnl_send_pf(struct sxe2_rdma_ctx_dev *dev, u16 vf_id, u8 *msg,
		       u16 len, u64 session_id)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct aux_core_dev_info *cdev_info =
		(struct aux_core_dev_info *)(to_rdmafunc(dev)->cdev);

	if (!rdma_dev->rdma_func->reset) {
		ret = cdev_info->ops->vc_send(cdev_info, vf_id, msg, len,
					      session_id);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"vchnl:vf id %u vc send err ret=%d\n", vf_id,
				ret);
		}
	}
	return ret;
}

static void sxe2_vchnl_pf_send_resp(struct sxe2_rdma_ctx_dev *dev, u16 vf_id,
				    struct sxe2_vchnl_op_buf *vchnl_msg,
				    void *param, u16 param_len, int resp_code,
				    u64 session_id)
{
	int ret	     = SXE2_OK;
	u8 *resp_buf = NULL;
	struct sxe2_vchnl_resp_buf *vchnl_msg_resp;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	resp_buf = kzalloc(SXE2_VCHNL_MAX_MSG_SIZE, GFP_KERNEL);
	if (!resp_buf) {
		DRV_RDMA_LOG_DEV_ERR("vchnl:resp buf alloc err\n");
		goto end;
	}
	vchnl_msg_resp	       = (struct sxe2_vchnl_resp_buf *)resp_buf;
	vchnl_msg_resp->op_ctx = vchnl_msg->op_ctx;
	vchnl_msg_resp->buf_len =
		sizeof(struct sxe2_vchnl_resp_buf) + param_len;
	vchnl_msg_resp->op_ret = (s16)resp_code;

	if (param_len)
		memcpy(vchnl_msg_resp->buf, param, param_len);

	DRV_RDMA_LOG_DEBUG_BDF(
		"vchnl:pf send resp vf id=%u resp code=%u session id=%llu\n"
		"resp msg op ctx=%#llx op ret=%u buf len=%u\n",
		vf_id, resp_code, session_id, vchnl_msg_resp->op_ctx,
		vchnl_msg_resp->op_ret, vchnl_msg_resp->buf_len);
	ret = sxe2_vchnl_send_pf(dev, vf_id, resp_buf, vchnl_msg_resp->buf_len,
				 session_id);

	kfree(resp_buf);
end:
	return;
}

static int sxe2_vchnl_alloc_vchnl_req_msg(struct sxe2_rdma_ctx_dev *dev,
					  struct sxe2_vchnl_req *vchnl_req,
					  struct sxe2_vchnl_req_init_info *info)
{
	int ret = SXE2_OK;
	struct sxe2_vchnl_op_buf *vchnl_msg;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	vchnl_msg = kzalloc(SXE2_VCHNL_MAX_MSG_SIZE, GFP_KERNEL);
	if (!vchnl_msg) {
		DRV_RDMA_LOG_DEV_ERR("vchnl:alloc vchnl msg mem err\n");
		ret = -ENOMEM;
		goto end;
	}
	vchnl_msg->op_ctx  = (uintptr_t)vchnl_req;
	vchnl_msg->buf_len = sizeof(*vchnl_msg) + info->req_parm_len;
	if (info->req_parm_len)
		memcpy(vchnl_msg->buf, info->req_parm, info->req_parm_len);

	vchnl_msg->op_code = info->op_code;
	vchnl_msg->op_ver  = info->op_ver;

	vchnl_req->vchnl_msg = vchnl_msg;
	vchnl_req->parm	     = info->resp_parm;
	vchnl_req->parm_len  = info->resp_parm_len;
end:
	return ret;
}

static void sxe2_vchnl_free_vchnl_req_msg(struct sxe2_vchnl_req *vchnl_req)
{
	kfree(vchnl_req->vchnl_msg);
}

int sxe2_vchnl_send_sync(struct sxe2_rdma_ctx_dev *dev, u8 *msg, u16 len,
			 u8 *recv_msg, u16 recv_len)
{
	int ret = SXE2_OK;
	struct aux_core_dev_info *cdev_info =
		(struct aux_core_dev_info *)(to_rdmafunc(dev)->cdev);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!rdma_dev->rdma_func->reset) {
		ret = cdev_info->ops->vc_send_sync(cdev_info, msg, len,
						   recv_msg, recv_len);
		if (ret == -ETIMEDOUT) {
			DRV_RDMA_LOG_DEV_ERR(
				"vchnl:virtual channel completion timeout ret=%d\n",
				ret);
			dev->vchnl_up = false;
		}
	}
	return ret;
}

static int sxe2_vchnl_req_verify_resp(struct sxe2_rdma_ctx_dev *dev,
				      struct sxe2_vchnl_req *vchnl_req,
				      u16 resp_len)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	switch (vchnl_req->vchnl_msg->op_code) {
	case SXE2_VCHNL_OP_GET_VER:
	case SXE2_VCHNL_OP_GET_RCMS_FCN:
	case SXE2_VCHNL_OP_PUT_RCMS_FCN:
	case SXE2_VCHNL_OP_INIT_VF_RCMS:
	case SXE2_VCHNL_OP_VLAN_PARSING:
	case SXE2_VCHNL_OP_GATHER_STATS:
	case SXE2_VCHNL_OP_MANAGE_QSET_NODE:
	case SXE2_VCHNL_OP_PBL_SET_FPTE:
	case SXE2_VCHNL_OP_PBL_CLEAR_FPTE:
	case SXE2_VCHNL_OP_GET_VF_OBJ_INFO:
	case SXE2_VCHNL_OP_UPDATE_FPTE:
	case SXE2_VCHNL_OP_GET_PORT_ACTIVE_SPEED:
		if (resp_len != vchnl_req->parm_len) {
			DRV_RDMA_LOG_DEV_ERR(
				"vchnl:op code %u resp len err resp len=%u parm len=%u\n",
				vchnl_req->vchnl_msg->op_code, resp_len,
				vchnl_req->parm_len);
			ret = -EBADMSG;
		}
		break;
	case SXE2_VCHNL_OP_GET_RDMA_CAPS:
		if (resp_len < SXE2_VCHNL_OP_GET_RDMA_CAPS_MIN_SIZE) {
			DRV_RDMA_LOG_DEV_ERR(
				"vchnl:op code %u resp len err resp len=%u min caps size=%u\n",
				vchnl_req->vchnl_msg->op_code, resp_len,
				SXE2_VCHNL_OP_GET_RDMA_CAPS_MIN_SIZE);
			ret = -EBADMSG;
		}
		break;
	default:
		ret = -EBADMSG;
	}

	return ret;
}

static int sxe2_vchnl_req_get_resp(struct sxe2_rdma_ctx_dev *dev,
				   struct sxe2_vchnl_req *vchnl_req)
{
	int ret = SXE2_OK;
	u16 resp_len;
	struct sxe2_vchnl_resp_buf *vchnl_msg_resp =
		(struct sxe2_vchnl_resp_buf *)dev->vc_recv_buf;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if ((uintptr_t)vchnl_req != (uintptr_t)vchnl_msg_resp->op_ctx) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl: vchnl context value does not match req addr=%lx resp ctx=%lx\n",
			(uintptr_t)vchnl_req,
			(uintptr_t)vchnl_msg_resp->op_ctx);
		ret = -EBADMSG;
		goto end;
	}
	resp_len = dev->vc_recv_len - sizeof(*vchnl_msg_resp);
	resp_len = min(resp_len, vchnl_req->parm_len);

	ret = sxe2_vchnl_req_verify_resp(dev, vchnl_req, resp_len);
	if (ret != SXE2_OK) {
		ret = -EBADMSG;
		goto end;
	}
	ret = (int)vchnl_msg_resp->op_ret;
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("vchnl: resp msg op ret err ret=%d\n",
				     ret);
		goto end;
	}
	vchnl_req->resp_len = 0;
	if (vchnl_req->parm_len && vchnl_req->parm && resp_len) {
		memcpy(vchnl_req->parm, vchnl_msg_resp->buf, resp_len);
		vchnl_req->resp_len = resp_len;
		DRV_RDMA_LOG_DEBUG_BDF("vchnl: resp data size=%u\n", resp_len);
	}

end:
	return ret;
}

int sxe2_vchnl_req_send_sync(struct sxe2_rdma_ctx_dev *dev,
			     struct sxe2_vchnl_req_init_info *info)
{
	int ret				= SXE2_OK;
	struct sxe2_vchnl_req vchnl_req = {};
	u16 resp_len			= sizeof(dev->vc_recv_buf);
	u16 msg_len;
	u8 *msg;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	ret = sxe2_vchnl_alloc_vchnl_req_msg(dev, &vchnl_req, info);
	if (ret != SXE2_OK)
		goto end;

	msg_len = vchnl_req.vchnl_msg->buf_len;
	msg	= (u8 *)vchnl_req.vchnl_msg;
	mutex_lock(&dev->vchnl_mutex);
	ret = sxe2_vchnl_send_sync(dev, msg, msg_len, dev->vc_recv_buf,
				   resp_len);
	if (ret != SXE2_OK)
		goto free_req_msg;

	ret = sxe2_vchnl_req_get_resp(dev, &vchnl_req);

free_req_msg:
	mutex_unlock(&dev->vchnl_mutex);
	DRV_RDMA_LOG_DEBUG_BDF(
		"vchnl: virtual channel send sync ret=%d\n"
		"\top=%u op_ver=%u req_len=%u parm_len=%u resp_len=%u\n",
		ret, vchnl_req.vchnl_msg->op_code, vchnl_req.vchnl_msg->op_ver,
		vchnl_req.vchnl_msg->buf_len, vchnl_req.parm_len,
		vchnl_req.resp_len);
	sxe2_vchnl_free_vchnl_req_msg(&vchnl_req);
end:
	return ret;
}

static bool sxe2_vchnl_pf_verify_msg(struct sxe2_rdma_ctx_dev *dev,
				     struct sxe2_vchnl_op_buf *vchnl_msg,
				     u16 len)
{
	bool ret    = true;
	u16 op_code = vchnl_msg->op_code;
	u16 op_size;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	DRV_RDMA_LOG_DEBUG_BDF(
		"vchnl:msg op code=%u op ver=%u buf len=%u op ctx=%#llx\n",
		vchnl_msg->op_code, vchnl_msg->op_ver, vchnl_msg->buf_len,
		vchnl_msg->op_ctx);

	if (len > SXE2_VCHNL_MAX_MSG_SIZE) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl: op %u msg len is out of max msg size msg len=%u max len=%u\n",
			op_code, len, SXE2_VCHNL_MAX_MSG_SIZE);
		ret = false;
		goto end;
	}
	if (len < sizeof(*vchnl_msg)) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl: op %u msg len is less than min size len = %u min len = %zu\n",
			op_code, len, sizeof(*vchnl_msg));
		ret = false;
		goto end;
	}
	switch (op_code) {
	case SXE2_VCHNL_OP_PBL_SET_FPTE:
		op_size = sizeof(struct sxe2_vchnl_pbl_set_fpte_info);
		if (len < sizeof(*vchnl_msg) + op_size) {
			DRV_RDMA_LOG_DEV_ERR(
				"vchnl: op %u msg len err len=%u op size=%u\n",
				op_code, len, op_size);
			ret = false;
			goto end;
		}
		break;
	case SXE2_VCHNL_OP_PBL_CLEAR_FPTE:
		op_size = sizeof(struct sxe2_vchnl_pbl_clear_fpte_info);
		if (len < sizeof(*vchnl_msg) + op_size) {
			DRV_RDMA_LOG_DEV_ERR(
				"vchnl: op %u msg len err len=%u op size=%u\n",
				op_code, len, op_size);
			ret = false;
			goto end;
		}
		break;
	case SXE2_VCHNL_OP_UPDATE_FPTE:
		op_size = sizeof(struct sxe2_rcms_vf_update_fptes_info);
		if (len < sizeof(*vchnl_msg) + op_size) {
			DRV_RDMA_LOG_DEV_ERR(
				"vchnl: op %u msg len err len=%u op size=%u\n",
				op_code, len, op_size);
			ret = false;
			goto end;
		}
		break;
	case SXE2_VCHNL_OP_GET_RCMS_FCN:
	case SXE2_VCHNL_OP_GET_VER:
	case SXE2_VCHNL_OP_PUT_RCMS_FCN:
	case SXE2_VCHNL_OP_VLAN_PARSING:
	case SXE2_VCHNL_OP_GET_RDMA_CAPS:
	case SXE2_VCHNL_OP_INIT_VF_RCMS:
	case SXE2_VCHNL_OP_GATHER_STATS:
	case SXE2_VCHNL_OP_MANAGE_QSET_NODE:
	case SXE2_VCHNL_OP_GET_VF_OBJ_INFO:
	case SXE2_VCHNL_OP_GET_PORT_ACTIVE_SPEED:
		if (len < sizeof(*vchnl_msg)) {
			DRV_RDMA_LOG_DEV_ERR(
				"vchnl: op %u msg len err len=%u op size=%zu\n",
				op_code, len, sizeof(*vchnl_msg));
			ret = false;
			goto end;
		}
		break;
	default:
		ret = false;
	}

end:
	return ret;
}

void sxe2_vchnl_put_vf_dev(struct sxe2_rdma_vchnl_dev **vc_dev)
{
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_dev *dev;

	if (*vc_dev == NULL) {
		DRV_RDMA_LOG_DEBUG("vc_dev is NULL\n");
		return;
	}

	dev	  = (*vc_dev)->pf_dev;
	rdma_dev = to_rdmadev(dev);

	if (refcount_read(&(*vc_dev)->refcnt) == 0)
		return;

	if (refcount_dec_and_test(&(*vc_dev)->refcnt)) {
		kfree(*vc_dev);
		*vc_dev	    = NULL;
		DRV_RDMA_LOG_DEV_DEBUG("vchnl: put vf dev success\n");
	}
}

static void sxe2_vchnl_negotiate_vchnl_rev(struct aux_ver_info *vchnl_ver,
							struct sxe2_rdma_ctx_dev *dev)
{
	struct sxe2_rdma_device *rdma_dev   = to_rdmadev(dev);

	vchnl_ver->major  = rdma_dev->fw_ver.major;
	vchnl_ver->minor  = rdma_dev->fw_ver.minor;
}

static u16 sxe2_vchnl_get_next_vf_idx(struct sxe2_rdma_ctx_dev *dev)
{
	u16 vf_idx;

	for (vf_idx = 0; vf_idx < dev->num_vfs; vf_idx++) {
		if (!dev->vc_dev[vf_idx])
			break;
	}

	return vf_idx < dev->num_vfs ? vf_idx : SXE2_VCHNL_INVALID_VF_IDX;
}

static void sxe2_vchnl_init_vsi_ctx(struct sxe2_rdma_ctx_vsi *vsi,
				    struct sxe2_vsi_init_info *info)
{
	vsi->dev	      = info->dev;
	vsi->back_vsi	      = info->back_vsi;
	vsi->register_qsets   = info->register_qset;
	vsi->unregister_qsets = info->unregister_qset;
	vsi->mtu	      = info->params->mtu;
	vsi->exception_lan_q  = info->exception_lan_q;
	vsi->vsi_idx	      = info->pf_data_vsi_num;
	vsi->vm_vf_type	      = info->vm_vf_type;
	sxe2_rdma_set_qos_info(vsi, info->params);
}

static struct sxe2_rdma_ctx_vsi *
sxe2_vchnl_update_vsi_ctx(struct sxe2_rdma_ctx_dev *dev,
			  struct sxe2_rdma_vchnl_dev *vc_dev, bool enable)
{
	struct sxe2_vsi_init_info vsi_info = {};
	struct sxe2_rdma_l2params l2params[QOS_MAX_QSET_NUM_PER_USER_PRI] = {0};
	struct aux_vf_port_info port_info  = {};
	struct sxe2_rdma_pci_f *rdma_func  = to_rdmafunc(dev);
	struct sxe2_rdma_ctx_vsi *vf_vsi;
	struct aux_core_dev_info *cdev_info = rdma_func->cdev;
	struct sxe2_rdma_device *rdma_dev   = to_rdmadev(dev);

	vf_vsi = vc_dev->vf_vsi;
	if (!vf_vsi && enable) {
		if (!rdma_func->reset &&
		    cdev_info->ops->get_vf_info(cdev_info, vc_dev->vf_id,
						&port_info)) {
			DRV_RDMA_LOG_DEV_ERR("vchnl: get vf info err\n");
			return NULL;
		}
		vf_vsi = kzalloc(sizeof(*vf_vsi), GFP_KERNEL);
		if (!vf_vsi) {
			DRV_RDMA_LOG_DEV_ERR("vchnl: alloc vf vsi mem err\n");
			return NULL;
		}
		vc_dev->port_vlan_en = port_info.port_vlan_id ? true : false;
		l2params[0].up2tc[0] = 0;
		l2params[0].mtu	  = rdma_dev->vsi.mtu;
		l2params[0].num_tc	       = 1;

		vsi_info.vm_vf_type	 = SXE2_PF_TYPE;
		vsi_info.dev		 = dev;
		vsi_info.back_vsi	 = rdma_dev;
		vsi_info.params		 = l2params;
		vsi_info.pf_data_vsi_num = port_info.vport_id;
		vsi_info.register_qset	 = rdma_func->gen_ops.register_qsets;
		vsi_info.unregister_qset = rdma_func->gen_ops.unregister_qsets;
		sxe2_vchnl_init_vsi_ctx(vf_vsi, &vsi_info);
	}
	if (!vf_vsi)
		return NULL;

	if (!enable) {
		kfree(vf_vsi);
		vf_vsi	       = NULL;
		vc_dev->vf_vsi = NULL;
	}

	return vf_vsi;
}

static void
sxe2_vchnl_set_rcms_fcn_info(struct sxe2_rdma_vchnl_dev *vc_dev,
			     struct sxe2_rcms_fcn_info *rcms_fcn_info,
			     bool free_fcn)
{
	u16 abs_vf_id;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(vc_dev->pf_dev);

	memset(rcms_fcn_info, 0, sizeof(*rcms_fcn_info));
	abs_vf_id	     = vc_dev->vf_id + rdma_dev->rdma_func->vfid_base;
	rcms_fcn_info->vf_id = abs_vf_id;
	rcms_fcn_info->protocol_used = vc_dev->protocol_used;
	DRV_RDMA_LOG_DEBUG_BDF("vchnl: rel vf id %u to abs vf id %u\n",
			       vc_dev->vf_id, rcms_fcn_info->vf_id);
}

int sxe2_vchnl_manage_rcms_pm_func_table(struct sxe2_mq_ctx *mq,
					 struct sxe2_rcms_fcn_info *info,
					 u64 scratch, bool post_sq)
{
	int ret = SXE2_OK;
	__le64 *wqe;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);
	struct sxe2_vchnl_manage_rcms_func_table_wqe *manage_func_table_wqe;

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl: mq manage rcms pm func table get wqe err\n");
		ret = -ENOMEM;
		goto end;
	}
	manage_func_table_wqe =
		(struct sxe2_vchnl_manage_rcms_func_table_wqe *)wqe;
	manage_func_table_wqe->vf_id = info->vf_id;
	manage_func_table_wqe->op    = SXE2_MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE;
	manage_func_table_wqe->free_func_table = info->free_fcn;
	dma_wmb();
	manage_func_table_wqe->wqe_valid = mq->polarity;

	print_hex_dump_debug("wqe: manage rcms pm func table wqe",
			     DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     SXE2_MQ_WQE_SIZE * SXE2_PRINT_HEX_MUL_BYTE_8,
			     false);
	if (post_sq)
		sxe2_kpost_mq(mq);
end:
	return ret;
}

static int
sxe2_vchnl_mq_manage_rcms_fcn_cmd(struct sxe2_rdma_ctx_dev *dev,
				  struct sxe2_rcms_fcn_info *rcms_fcn_info,
				  u16 *pmf_idx)
{
	int ret = SXE2_OK;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_vchnl_mq_compl_func_tab_ret ret_val;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		goto end;
	}
	mq_info = &mq_request->info;
	memcpy(&mq_info->in.u.manage_rcms_pm.info, rcms_fcn_info,
	       sizeof(mq_info->in.u.manage_rcms_pm.info));
	mq_info->in.u.manage_rcms_pm.dev     = dev;
	mq_info->mq_cmd			     = MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE;
	mq_info->post_mq		     = 1;
	mq_info->in.u.manage_rcms_pm.scratch = (uintptr_t)mq_request;
	ret	    = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	ret_val.val = mq_request->cmpl_info.op_ret_val;
	if (!ret_val.valid) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl:mange rcms fcn get invalid relative func id\n");
		ret = -EINVAL;
	} else {
		*pmf_idx = ret_val.rel_fid;
	}

	sxe2_kput_mq_request(&rdma_func->mq, mq_request);

end:
	return ret;
}

static struct sxe2_rdma_vchnl_dev *
sxe2_vchnl_pf_get_vf_rcms_fcn(struct sxe2_rdma_ctx_dev *dev, u16 vf_id,
			      enum sxe2_protocol_used protocol_used)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fcn_info rcms_fcn_info;
	struct sxe2_rdma_virt_mem virt_mem;
	struct sxe2_rdma_vchnl_dev *vc_dev;
	struct sxe2_rdma_ctx_vsi *vsi;
	u16 vf_idx = 0;
	u32 size;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	vf_idx = sxe2_vchnl_get_next_vf_idx(dev);
	if (vf_idx == SXE2_VCHNL_INVALID_VF_IDX) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl: get vf idx err\n");
		return NULL;
	}
	size = sizeof(*vc_dev) +
	       sizeof(struct sxe2_rcms_obj_info) * SXE2_RCMS_OBJ_MAX;
	virt_mem.size = size;
	virt_mem.va   = kzalloc(virt_mem.size, GFP_KERNEL);
	if (!virt_mem.va) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl: vf %u alloc vf dev and rcms obj info err\n",
			vf_id);
		return NULL;
	}
	vc_dev			    = virt_mem.va;
	vc_dev->pf_dev		    = dev;
	vc_dev->vf_id		    = vf_id;
	vc_dev->vf_idx		    = vf_idx;
	vc_dev->protocol_used	    = protocol_used;
	vc_dev->pf_rcms_initialized = false;
	vc_dev->rcms_info.rcms_obj  = (struct sxe2_rcms_obj_info *)(&vc_dev[1]);

	vsi = sxe2_vchnl_update_vsi_ctx(dev, vc_dev, true);
	if (!vsi)
		goto free_vc_dev;

	refcount_set(&vc_dev->refcnt, 1);
	dev->vc_dev[vf_idx] = vc_dev;
	vc_dev->vf_vsi	    = vsi;
	vsi->vf_id	    = (u16)vc_dev->vf_id;
	vsi->vc_dev	    = vc_dev;

	sxe2_vchnl_set_rcms_fcn_info(vc_dev, &rcms_fcn_info, false);
	ret = sxe2_vchnl_mq_manage_rcms_fcn_cmd(dev, &rcms_fcn_info,
						&vc_dev->pmf_index);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl: vf %u error mq get rcms function operation\n",
			vf_id);
		goto disable_vport;
	}

	DRV_RDMA_LOG_DEBUG_BDF(
		"vchnl: vf %u mq manage rcms fcn Function pmf idx = %u\n",
		vf_id, vc_dev->pmf_index);

	refcount_inc(&vc_dev->refcnt);
	return vc_dev;

disable_vport:
	sxe2_vchnl_update_vsi_ctx(dev, vc_dev, false);
free_vc_dev:
	dev->vc_dev[vc_dev->vf_idx] = NULL;
	kfree(virt_mem.va);
	return NULL;
}

static enum sxe2_protocol_used
sxe2_vchnl_get_protocol_used(struct sxe2_vchnl_op_buf *vchnl_msg)
{
	return SXE2_ROCE_PROTOCOL_ONLY;
}

void sxe2_vchnl_pf_put_vf_rcms_fcn(struct sxe2_rdma_ctx_dev *dev,
				   struct sxe2_rdma_vchnl_dev **vc_dev)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	DRV_RDMA_LOG_DEBUG_BDF("vchnl: vf %u put rcms fcn start\n",
			       (*vc_dev)->vf_id);
	sxe2_vchnl_remove_vc_dev(dev, *vc_dev);
	sxe2_vchnl_update_vsi_ctx(dev, *vc_dev, false);
	sxe2_vchnl_put_vf_dev(vc_dev);
}

static int sxe2_vchnl_pf_config_vf_rcms(struct sxe2_rdma_vchnl_dev *vc_dev)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vc_dev->pf_dev;
	u8 vf_pmf_idx			  = (u8)(vc_dev->pmf_index);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (vf_pmf_idx < dev->hw_attrs.first_hw_vf_fpm_id ||
	    (vf_pmf_idx >= dev->hw_attrs.first_hw_vf_fpm_id + dev->num_vfs)) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl: invalid vf pmf idx=%u\n",
				     vf_pmf_idx);
		ret = -EINVAL;
		goto end;
	}
	ret = sxe2_rcms_pf_config_vf_fpm_val(vc_dev);

end:
	return ret;
}

static void sxe2_vchnl_update_vf_vlan_cfg(struct sxe2_rdma_ctx_dev *dev,
					  struct sxe2_rdma_vchnl_dev *vc_dev)
{
	int ret				    = SXE2_OK;
	struct aux_core_dev_info *cdev_info = to_rdmafunc(dev)->cdev;
	struct aux_vf_port_info port_info   = {};
	struct sxe2_rdma_device *rdma_dev   = to_rdmadev(dev);

	if (!rdma_dev->rdma_func->reset) {
		ret = cdev_info->ops->get_vf_info(cdev_info, vc_dev->vf_id,
						  &port_info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("vchnl:cdev get vf info ret=%d\n",
					     ret);
			return;
		}
	}
	vc_dev->port_vlan_en = port_info.port_vlan_id ? true : false;
}

static int
sxe2_vchnl_pf_init_vf_rcms(struct sxe2_rdma_vchnl_dev *vc_dev,
			   struct sxe2_vchnl_init_vf_rcms_resp *init_rcms_resp)
{
	int ret = SXE2_OK;
	int i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(vc_dev->pf_dev);

	if (!vc_dev->pf_rcms_initialized) {
		ret = sxe2_vchnl_pf_config_vf_rcms(vc_dev);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl: pf init vf %u rcms ret=%d\n",
				vc_dev->vf_id, ret);
			goto end;
		}
		vc_dev->pf_rcms_initialized = true;
	}
	init_rcms_resp->first_fpte_index = vc_dev->rcms_info.first_fpte_index;
	init_rcms_resp->max_fpte_index	 = vc_dev->rcms_info.max_fpte_index;
	init_rcms_resp->max_fpte_cnt	 = vc_dev->rcms_info.max_fpte_cnt;
	init_rcms_resp->fpte_needed	 = vc_dev->rcms_info.fpte_needed;
	init_rcms_resp->max_ceqs	 = vc_dev->rcms_info.max_ceqs;
	init_rcms_resp->max_db_page_num	 = vc_dev->rcms_info.max_db_page_num;
	init_rcms_resp->db_bar_addr	 = vc_dev->rcms_info.db_bar_addr;
	init_rcms_resp->max_cc_qp_cnt	 = vc_dev->rcms_info.max_cc_qp_cnt;

	for (i = 0; i < SXE2_RCMS_OBJ_MAX; i++) {
		init_rcms_resp->obj_max_cnt[i] =
			vc_dev->rcms_info.rcms_obj[i].cnt;
	}

	init_rcms_resp->pmf_index = vc_dev->pmf_index;
	init_rcms_resp->pf_max_ceqs =
		rdma_dev->rdma_func->ctx_dev.rcms_info->max_ceqs;

end:
	return ret;
}

static int
sxe2_vchnl_pf_get_vf_obj(struct sxe2_rdma_vchnl_dev *vc_dev,
			 struct sxe2_vchnl_vf_obj_resp *init_obj_resp)
{
	int ret = SXE2_OK;
	int i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(vc_dev->pf_dev);

	if (!vc_dev->pf_rcms_initialized) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl: pf del vf %u obj err pf not initialized\n",
			vc_dev->vf_id);
		ret = -EINVAL;
		goto end;
	}

	for (i = 0; i < SXE2_RCMS_OBJ_MAX; i++) {
		init_obj_resp->obj_info[i].size =
			vc_dev->rcms_info.rcms_obj[i].size;
		init_obj_resp->obj_info[i].base =
			vc_dev->rcms_info.rcms_obj[i].base;
	}

end:
	return ret;
}

static int sxe2_vchnl_pf_gather_vf_stats(
	struct sxe2_rdma_vchnl_dev *vc_dev, u32 stats_req_type,
	struct sxe2_rdma_gather_stats_vf *gather_stats_resp)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vc_dev->pf_dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u8 vf_pmf_idx			  = (u8)vc_dev->pmf_index;

	if (vf_pmf_idx < dev->hw_attrs.first_hw_vf_fpm_id ||
	    (vf_pmf_idx >= dev->hw_attrs.first_hw_vf_fpm_id + dev->num_vfs)) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl: invalid vf pmf idx=%u\n",
				     vf_pmf_idx);
		ret = -EINVAL;
		goto end;
	}

	ret = sxe2_kgather_pf_for_vf_stats_val(vc_dev, stats_req_type,
					       gather_stats_resp);

end:
	return ret;
}

static int
sxe2_vchnl_pf_gather_stats(struct sxe2_rdma_vchnl_dev *vc_dev,
			   u32 stats_req_type,
			   struct sxe2_rdma_gather_stats_vf *gather_stats_resp)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(vc_dev->pf_dev);

	ret = sxe2_vchnl_pf_gather_vf_stats(vc_dev, stats_req_type,
					    gather_stats_resp);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl: pf gather stats ret=%d\n", ret);
		goto end;
	}

end:
	return ret;
}

static int sxe2_vchnl_pf_manage_vf_qet_node(
	struct sxe2_rdma_vchnl_dev *vc_dev,
	struct sxe2_vchnl_manage_qet_node_info *qset_info)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(vc_dev->pf_dev);
	struct sxe2_rdma_ctx_vsi *vf_vsi  = vc_dev->vf_vsi;
	u32 user_pri			  = qset_info->user_pri;

	DRV_RDMA_LOG_DEBUG_BDF("vchnl: pf %s vf %u qset id=%u user pri=%u\n",
			       qset_info->add ? "add" : "del", vc_dev->vf_id,
			       qset_info->qset_id, user_pri);
	if (qset_info->add) {
		vf_vsi->qos[user_pri].qset[0].vsi_index = vf_vsi->vsi_idx;
		vf_vsi->qos[user_pri].qset[0].qset_id	= qset_info->qset_id;

		ret = vf_vsi->register_qsets(
			vf_vsi, &vf_vsi->qos[user_pri].qset[0], NULL);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl: pf manage vf %u qset err ret=%d\n",
				vc_dev->vf_id, ret);
			goto end;
		}

		ret = sxe2_qos_qset_bind_pf_tc(
			vf_vsi, vf_vsi->qos[user_pri].qset[0].qset_id,
			vf_vsi->qos[user_pri].qset[0].traffic_class, false,
			rdma_dev->rdma_func->pf_id);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl:pf manage vf %u qset bind pf tc err ret=%d\n",
				vc_dev->vf_id, ret);
			goto qet_bind_tc_err;
		}
		vf_vsi->qos[user_pri].valid = true;
	} else {
		if (!vf_vsi->qos[user_pri].valid ||
		    vf_vsi->qos[user_pri].qset[0].qset_id !=
			    qset_info->qset_id) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl:pf unregister qet user pri\n"
				"\tqset not valid or qset id err=%d\n",
				ret);
			ret = -EINVAL;
			goto end;
		}
		vf_vsi->unregister_qsets(vf_vsi, &vf_vsi->qos[user_pri].qset[0],
					 NULL);
		vf_vsi->qos[user_pri].valid = false;
	}

	goto end;

qet_bind_tc_err:
	vf_vsi->unregister_qsets(vf_vsi, &vf_vsi->qos[user_pri].qset[0], NULL);

end:
	return ret;
}

static bool sxe2_vchnl_pf_verify_update_fpte_msg(
	struct sxe2_rdma_vchnl_dev *vc_dev,
	struct sxe2_rcms_vf_update_fptes_info *update_vf_fpte_info)
{
	bool verify_ret			  = true;
	struct sxe2_rdma_ctx_dev *dev	  = vc_dev->pf_dev;
	struct sxe2_rcms_info *rcms_info  = &vc_dev->rcms_info;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u64 fpte_pa;
	u64 fpte_idx;
	u32 i;
	u8 valid;

	if (update_vf_fpte_info->cnt > SXE2_RCMS_VF_MAX_UPDATE_FPTE_ENTRIES) {
		verify_ret = false;
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl: pf update vf %u fpte cnt err cnt=%u max cnt=%u\n",
			vc_dev->vf_id, update_vf_fpte_info->cnt,
			SXE2_RCMS_VF_MAX_UPDATE_FPTE_ENTRIES);
		goto end;
	}

	for (i = 0; i < update_vf_fpte_info->cnt; i++) {
		fpte_idx = update_vf_fpte_info->entry[i].cmd;
		fpte_pa =
			update_vf_fpte_info->entry[i].data & SXE2_FPTE_PA_MASK;
		valid = (u8)(update_vf_fpte_info->entry[i].data &
			     SXE2_FPTE_PA_VALID_MASK);
		if (fpte_idx < rcms_info->first_fpte_index ||
		    fpte_idx > rcms_info->max_fpte_index) {
			verify_ret = false;
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl: pf update vf %u fpte idx err fpte idx=%u\n",
				vc_dev->vf_id, fpte_idx);
			goto end;
		}
		if ((update_vf_fpte_info->set && (!fpte_pa || !valid)) ||
		    (!update_vf_fpte_info->set && valid)) {
			verify_ret = false;
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl: pf update vf %u fpte pa is NULL fpte idx=%u\n",
				vc_dev->vf_id, fpte_idx);
			goto end;
		}
	}

end:
	return verify_ret;
}

static int sxe2_vchnl_pf_update_fpte(
	struct sxe2_rdma_vchnl_dev *vc_dev,
	struct sxe2_rcms_vf_update_fptes_info *update_vf_fpte_info)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vc_dev->pf_dev;
	struct sxe2_rcms_info *rcms_info  = &vc_dev->rcms_info;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rcms_update_fptes_info *update_fpte_info = NULL;
	bool verify_msg;
	u32 i;

	verify_msg = sxe2_vchnl_pf_verify_update_fpte_msg(vc_dev,
							  update_vf_fpte_info);
	if (!verify_msg) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl: pf update vf %u fpte verify err\n",
			vc_dev->vf_id);
		goto end;
	}

	DRV_RDMA_LOG_DEBUG_BDF("vchnl: pf update vf %u fpte cnt=%u set=%u\n",
			       vc_dev->vf_id, update_vf_fpte_info->cnt,
			       update_vf_fpte_info->set);
	update_fpte_info = kzalloc(
		sizeof(*update_fpte_info), GFP_KERNEL);
	if (!update_fpte_info) {
		DRV_RDMA_LOG_DEV_ERR("vchnl:update fpte info alloc err\n");
		ret = -ENOMEM;
		goto end;
	}
	update_fpte_info->cnt	     = update_vf_fpte_info->cnt;
	update_fpte_info->rcms_fn_id = rcms_info->rcms_fn_id;
	for (i = 0; i < update_fpte_info->cnt; i++) {
		update_fpte_info->entry[i].cmd =
			update_vf_fpte_info->entry[i].cmd;
		update_fpte_info->entry[i].data =
			update_vf_fpte_info->entry[i].data;
		DRV_RDMA_LOG_DEBUG_BDF("vchnl: vf fpte cmd=%llx data=%llx\n",
				       update_fpte_info->entry[i].cmd,
				       update_fpte_info->entry[i].data);
	}
	ret = dev->mq->process_mq_fpt(dev, update_fpte_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl: pf update vf %u fpte err ret=%d\n",
			vc_dev->vf_id, ret);
	}
	kfree(update_fpte_info);
end:
	return ret;
}

static void sxe2_vchnl_opcode_process(struct sxe2_rdma_ctx_dev *dev,
				      struct sxe2_rdma_vchnl_dev *vc_dev,
				      u16 vf_id,
				      struct sxe2_vchnl_work *vchnl_work,
				      struct sxe2_vchnl_op_buf *vchnl_msg)
{
	void *param	 = vchnl_msg->buf;
	void *resp_param = NULL;
	u16 resp_len	 = 0;
	int resp_code	 = 0;
	u8 vlan_parse_en;
	struct aux_ver_info vchnl_ver;
	struct sxe2_vchnl_init_vf_rcms_resp init_rcms_resp;
	struct sxe2_vchnl_vf_obj_resp vf_obj_resp;
	struct sxe2_rdma_device *rdma_dev		   = to_rdmadev(dev);
	struct sxe2_rdma_gather_stats_vf gather_stats_resp = {};
	u32 stats_req_type				   = 0;
	struct sxe2_vchnl_pbl_set_fpte_info *set_fpte_info = NULL;
	struct sxe2_vchnl_pbl_clear_fpte_info *clear_fpte_info = NULL;
	struct sxe2_vchnl_rdma_caps caps		       = {};
	u32 port_active_speed = 0;
	struct aux_core_dev_info *cdev_info =
		(struct aux_core_dev_info *)(rdma_dev->rdma_func->cdev);

	switch (vchnl_msg->op_code) {
	case SXE2_VCHNL_OP_GET_VER:
		sxe2_vchnl_negotiate_vchnl_rev(&vchnl_ver, dev);
		resp_param = &vchnl_ver;
		resp_len   = sizeof(vchnl_ver);
		break;
	case SXE2_VCHNL_OP_PUT_RCMS_FCN:
		sxe2_vchnl_pf_put_vf_rcms_fcn(dev, &vc_dev);
		break;
	case SXE2_VCHNL_OP_INIT_VF_RCMS:
		resp_code = sxe2_vchnl_pf_init_vf_rcms(vc_dev, &init_rcms_resp);
		resp_param = &init_rcms_resp;
		resp_len   = sizeof(init_rcms_resp);
		break;
	case SXE2_VCHNL_OP_GET_VF_OBJ_INFO:
		resp_code  = sxe2_vchnl_pf_get_vf_obj(vc_dev, &vf_obj_resp);
		resp_param = &vf_obj_resp;
		resp_len   = sizeof(vf_obj_resp);
		break;
	case SXE2_VCHNL_OP_VLAN_PARSING:
		sxe2_vchnl_update_vf_vlan_cfg(dev, vc_dev);
		vlan_parse_en = !vc_dev->port_vlan_en;
		DRV_RDMA_LOG_DEBUG_BDF("vchnl:vf %u vlan_parse_en = 0x%x\n",
				       vf_id, vlan_parse_en);
		resp_param = &vlan_parse_en;
		resp_len   = sizeof(vlan_parse_en);
		break;
	case SXE2_VCHNL_OP_GET_RDMA_CAPS:
		caps.hw_rev = dev->hw_attrs.uk_attrs.hw_rev;
		resp_len    = sizeof(caps);
		resp_param  = &caps;
		break;
	case SXE2_VCHNL_OP_GATHER_STATS:
		stats_req_type = *((u32 *)param);
		resp_code  = sxe2_vchnl_pf_gather_stats(vc_dev, stats_req_type,
							&gather_stats_resp);
		resp_param = &gather_stats_resp;
		resp_len   = sizeof(gather_stats_resp);
		break;
	case SXE2_VCHNL_OP_MANAGE_QSET_NODE:
		resp_code = sxe2_vchnl_pf_manage_vf_qet_node(vc_dev, param);
		break;
	case SXE2_VCHNL_OP_PBL_SET_FPTE:
		set_fpte_info = (struct sxe2_vchnl_pbl_set_fpte_info *)param;
		resp_code     = sxe2_pbl_set_fpte(vc_dev->pf_dev,
						  set_fpte_info->fpte_idx,
						  set_fpte_info->page_pa,
						  vc_dev->pmf_index);
		break;
	case SXE2_VCHNL_OP_PBL_CLEAR_FPTE:
		clear_fpte_info =
			(struct sxe2_vchnl_pbl_clear_fpte_info *)param;
		resp_code = sxe2_pbl_clear_fpte(vc_dev->pf_dev,
						clear_fpte_info->fpte_idx,
						clear_fpte_info->pble_cnt,
						vc_dev->pmf_index);
		break;
	case SXE2_VCHNL_OP_UPDATE_FPTE:
		resp_code = sxe2_vchnl_pf_update_fpte(
			vc_dev, (struct sxe2_rcms_vf_update_fptes_info *)param);
		break;
	case SXE2_VCHNL_OP_GET_PORT_ACTIVE_SPEED:
		port_active_speed = cdev_info->ops->rdma_get_link_speed(cdev_info);
		resp_param = &port_active_speed;
		resp_len   = sizeof(port_active_speed);
		break;
	default:
		DRV_RDMA_LOG_DEV_ERR("vchnl:vf %u invalid op code 0x%x\n",
				     vf_id, vchnl_msg->op_code);
		resp_code = -EOPNOTSUPP;
	}

	if ((vc_dev && vc_dev->reset_en) || rdma_dev->rdma_func->reset)
		goto end;

	sxe2_vchnl_pf_send_resp(dev, vf_id, vchnl_msg, resp_param, resp_len,
				resp_code, vchnl_work->session_id);
end:
	return;
}

static void sxe2_vchnl_recv_pf_worker(struct work_struct *work)
{
	struct sxe2_vchnl_work *vchnl_work =
		container_of(work, struct sxe2_vchnl_work, work);
	struct sxe2_vchnl_op_buf *vchnl_msg =
		(struct sxe2_vchnl_op_buf *)&vchnl_work->vf_msg_buf;
	u16 vf_id			   = vchnl_work->vf_id;
	int resp_code			   = 0;
	struct sxe2_rdma_ctx_dev *dev	   = vchnl_work->dev;
	struct sxe2_rdma_vchnl_dev *vc_dev = NULL;
	struct sxe2_rdma_virt_mem virt_mem;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	DRV_RDMA_LOG_DEBUG_BDF("vchnl:vf %u req opcode %u\n", vf_id,
			       vchnl_msg->op_code);
	if (rdma_dev->rdma_func->reset) {
		DRV_RDMA_LOG_DEV_DEBUG("vchnl:pf ready reset\n");
		goto free_work;
	}
	vc_dev = sxe2_vchnl_find_vc_dev(dev, vf_id);
	if (vc_dev && vchnl_msg->op_code == SXE2_VCHNL_OP_GET_RCMS_FCN) {
		sxe2_rdma_free_one_vf(vc_dev);
		vc_dev = NULL;
		DRV_RDMA_LOG_DEBUG_BDF("vchnl:vf %u get fcn but find vc dev\n",
				       vf_id);
	}
	if (vc_dev && vc_dev->reset_en) {
		DRV_RDMA_LOG_DEBUG_BDF("vchnl:vf %u req opcode %u reset en\n",
				       vf_id, vchnl_msg->op_code);
		goto free_work;
	}

	if (vchnl_msg->op_code != SXE2_VCHNL_OP_GET_VER &&
	    vchnl_msg->op_code != SXE2_VCHNL_OP_GET_RDMA_CAPS &&
	    vchnl_msg->op_code != SXE2_VCHNL_OP_GET_RCMS_FCN) {
		if (!vc_dev) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl:vf %u req opcode %u vc dev is null\n",
				vf_id, vchnl_msg->op_code);
			goto free_work;
		}
	}

	if (vchnl_msg->op_code == SXE2_VCHNL_OP_GET_RCMS_FCN) {
		if (!vc_dev) {
			vc_dev = sxe2_vchnl_pf_get_vf_rcms_fcn(
				dev, vf_id,
				sxe2_vchnl_get_protocol_used(vchnl_msg));
			if (!vc_dev) {
				DRV_RDMA_LOG_ERROR_BDF(
					"vchnl:vf %u req opcode %u pf get vf rcms fcn err\n",
					vf_id, vchnl_msg->op_code);
				resp_code = -ENODEV;
			}
		}

		if ((!vc_dev || !vc_dev->reset_en) && !rdma_dev->rdma_func->reset) {
			sxe2_vchnl_pf_send_resp(dev, vf_id, vchnl_msg, NULL, 0,
					resp_code,
					vchnl_work->session_id);
		}
		goto free_work;
	}

	sxe2_vchnl_opcode_process(dev, vc_dev, vf_id, vchnl_work, vchnl_msg);

free_work:
	if (vc_dev)
		sxe2_vchnl_put_vf_dev(&vc_dev);
	virt_mem.va = work;
	kfree(virt_mem.va);
}

int sxe2_vchnl_recv_pf(struct sxe2_rdma_ctx_dev *dev, u16 vf_id, u8 *msg,
		       u16 len, u64 session_id)
{
	int ret = SXE2_OK;
	struct sxe2_vchnl_work *work;
	struct sxe2_rdma_virt_mem workmem;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_vchnl_op_buf *vchnl_msg;
	u16 msg_len;
	bool verify_msg;

	if (!msg) {
		DRV_RDMA_LOG_DEV_ERR("vchnl:msg pointer is NULL err\n");
		ret = -EINVAL;
		goto end;
	}
	DRV_RDMA_LOG_DEBUG_BDF(
		"vchnl:recv vf id=%u msg len=%u session id=%#llx\n", vf_id,
		len, session_id);
	if (len < SXE2VF_MBX_FULL_HDR_SIZE) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl:vf %u vf_id mbx msg too short len=%u\n", vf_id,
			len);
		ret = -EINVAL;
		goto end;
	}

	vchnl_msg =
		(struct sxe2_vchnl_op_buf *)(msg + SXE2VF_MBX_FULL_HDR_SIZE);
	msg_len = len - SXE2VF_MBX_FULL_HDR_SIZE;

	verify_msg = sxe2_vchnl_pf_verify_msg(dev, vchnl_msg, msg_len);
	if (!verify_msg) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:pf verify msg err\n");
		ret = -EINVAL;
		goto end;
	}
	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:vchnl is not up\n");
		ret = -EBUSY;
		goto end;
	}

	workmem.size = sizeof(*work);
	workmem.va   = kzalloc(workmem.size, GFP_KERNEL);
	if (!workmem.va) {
		DRV_RDMA_LOG_DEV_ERR("vchnl:alloc work mem err\n");
		ret = -ENOMEM;
		goto end;
	}
	work = workmem.va;
	memcpy(&work->vf_msg_buf, vchnl_msg, msg_len);
	work->dev	 = dev;
	work->vf_id	 = vf_id;
	work->len	 = msg_len;
	work->session_id = session_id;
	INIT_WORK(&work->work, sxe2_vchnl_recv_pf_worker);
	queue_work(dev->vchnl_wq, &work->work);

end:
	return ret;
}

int sxe2_vchnl_recv_vf(struct sxe2_rdma_ctx_dev *dev, u16 vf_id, u8 *msg,
		       u16 len, u64 session_id)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (len < sizeof(struct sxe2_vchnl_resp_buf)) {
		DRV_RDMA_LOG_DEV_ERR("vchnl:alloc work mem err\n");
		ret = -EINVAL;
		goto end;
	}
	if (len > SXE2_VCHNL_MAX_MSG_SIZE)
		len = SXE2_VCHNL_MAX_MSG_SIZE;

	memcpy(dev->vc_recv_buf, msg, len);
	dev->vc_recv_len = len;
end:
	return ret;
}

int sxe2_vchnl_receive(struct aux_core_dev_info *cdev_info, u32 vf_id, u8 *msg,
		       u16 len, u64 session_id)
{
	int ret = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev =
		dev_get_drvdata(&cdev_info->adev->dev);
	struct sxe2_rdma_ctx_dev *dev = &rdma_dev->rdma_func->ctx_dev;

	if (!len || !msg) {
		DRV_RDMA_LOG_DEV_ERR(
			"vchnl:vchnl receive len or msg pointer err len=%u msg=%p\n",
			len, msg);
		ret = -EINVAL;
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG(
		"vchnl:vchnl receive vf id=%u msg len=%u session id=%#llx\n",
		vf_id, len, session_id);
	ret = dev->vchnl_if->vchnl_recv(dev, (u16)vf_id, msg, len, session_id);
	if (ret != SXE2_OK)
		DRV_RDMA_LOG_ERROR_BDF("vchnl:vchnl receive err ret=%d\n", ret);

end:
	return ret;
}

int sxe2_vchnl_req_get_ver(struct sxe2_rdma_ctx_dev *dev,
			   struct aux_ver_info *ver_res)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}

	info.op_code   = SXE2_VCHNL_OP_GET_VER;
	info.op_ver	   = SXE2_VCHNL_CHNL_VER_V1;
	info.resp_parm	   = (void *)ver_res;
	info.resp_parm_len = sizeof(*ver_res);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:get ver req send sync err ret=%d\n",
				     ret);
		goto end;
	}

	if (ver_res->major != SXE2_FW_COMP_MAJOR_VER) {
		DRV_RDMA_LOG_ERROR("vf: major version compare mismatch, fw vrsion:%d rdma %d\n",
							ver_res->major, SXE2_FW_COMP_MAJOR_VER);
		ret = -EOPNOTSUPP;
		goto end;
	}

	if (ver_res->minor != SXE2_FW_COMP_MINOR_VER) {
		DRV_RDMA_LOG_WARN("vf: minor version compare mismatch, fw vrsion:%d rdma %d.\n",
							ver_res->minor, SXE2_FW_COMP_MINOR_VER);
	}

end:
	return ret;
}

int sxe2_vchnl_req_get_rcms_fcn(struct sxe2_rdma_ctx_dev *dev)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}

	info.op_code = SXE2_VCHNL_OP_GET_RCMS_FCN;
	info.op_ver  = SXE2_VCHNL_OP_GET_RCMS_FCN_V1;

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:get rcms fcn req send sync err ret=%d\n", ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_put_rcms_fcn(struct sxe2_rdma_ctx_dev *dev)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}
	info.op_code = SXE2_VCHNL_OP_PUT_RCMS_FCN;
	info.op_ver  = SXE2_VCHNL_OP_PUT_RCMS_FCN_V1;

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:put rcms fcn req send sync err ret=%d\n", ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_get_vlan_parsing_cfg(struct sxe2_rdma_ctx_dev *dev,
					u8 *vlan_parse_en)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}
	info.op_code	   = SXE2_VCHNL_OP_VLAN_PARSING;
	info.op_ver	   = SXE2_VCHNL_OP_VLAN_PARSING_V1;
	info.resp_parm	   = (void *)vlan_parse_en;
	info.resp_parm_len = sizeof(*vlan_parse_en);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:get vlan parsing cfg req send sync err ret=%d\n",
			ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_get_caps(struct sxe2_rdma_ctx_dev *dev)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}
	info.op_code	   = SXE2_VCHNL_OP_GET_RDMA_CAPS;
	info.op_ver	   = SXE2_VCHNL_OP_GET_RDMA_CAPS_V1;
	info.resp_parm	   = (void *)(&dev->vc_caps);
	info.resp_parm_len = sizeof(dev->vc_caps);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:get caps req send sync err ret=%d\n", ret);
		goto end;
	}

	if (!dev->vc_caps.max_hw_push_len)
		dev->vc_caps.max_hw_push_len = SXE2_RDMA_DEFAULT_MAX_PUSH_LEN;

	if (dev->vc_caps.hw_rev > SXE2_RDMA_GEN_MAX ||
	    dev->vc_caps.hw_rev < SXE2_RDMA_GEN_1) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl: get caps req unsupported hw_rev version %u\n",
			dev->vc_caps.hw_rev);
		ret = -EOPNOTSUPP;
	}

end:
	return ret;
}

int sxe2_vchnl_req_init_vf_rcms(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_vchnl_init_vf_rcms_resp *init_vf_rcms_resp)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}
	info.op_code	   = SXE2_VCHNL_OP_INIT_VF_RCMS;
	info.op_ver	   = SXE2_VCHNL_OP_INIT_VF_RCMS_V1;
	info.resp_parm	   = (void *)init_vf_rcms_resp;
	info.resp_parm_len = sizeof(*init_vf_rcms_resp);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:init vf rcms req send sync err ret=%d\n", ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_get_vf_obj_info(struct sxe2_rdma_ctx_dev *dev,
				   struct sxe2_vchnl_vf_obj_resp *vf_obj_resp)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}
	info.op_code	   = SXE2_VCHNL_OP_GET_VF_OBJ_INFO;
	info.op_ver	   = SXE2_VCHNL_OP_GET_VF_OBJ_INFO_V1;
	info.resp_parm	   = (void *)vf_obj_resp;
	info.resp_parm_len = sizeof(*vf_obj_resp);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:get vf obj req send sync err ret=%d\n", ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_gather_stats(struct sxe2_rdma_ctx_dev *dev,
				struct sxe2_rdma_gather_stats *gather_stats_resp)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	struct sxe2_rdma_gather_stats_vf gather_stats_resp_tx = {};
	struct sxe2_rdma_gather_stats_vf gather_stats_resp_rx = {};
	u32 req_type					      = 0;
#ifdef SXE2_CFG_DEBUG
	u32 i					= 0;
	const struct sxe2_rdma_hw_stat_map *map = dev->hw_stats_map;
#endif

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}

	info.op_code	   = SXE2_VCHNL_OP_GATHER_STATS;
	info.op_ver	   = SXE2_VCHNL_OP_GATHER_STATS_V1;
	req_type	   = SXE2_RDMA_STATS_VF_TX;
	info.req_parm	   = (void *)(&req_type);
	info.req_parm_len  = sizeof(req_type);
	info.resp_parm	   = (void *)(&gather_stats_resp_tx);
	info.resp_parm_len = sizeof(gather_stats_resp_tx);
	if (!rdma_dev->rdma_func->reset) {
		ret = sxe2_vchnl_req_send_sync(dev, &info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl:gather stats req send sync err ret=%d\n",
				ret);
			goto end;
		}
		memcpy(gather_stats_resp, &gather_stats_resp_tx,
		       STATS_VF_TX_BUF_ALL_BYTE);
#ifdef SXE2_CFG_DEBUG
		for (i = 0; i < SXE2_RDMA_HW_STAT_INDEX_IP4RXOCTS; i++) {
			DRV_RDMA_LOG_DEBUG_BDF(
				"vf i %u, bitoff %u, val %#llx\n", i,
				map[i].byteoff, gather_stats_resp->val[i]);
		}
#endif
	} else {
		;
		goto end;
	}

	info.op_code	   = SXE2_VCHNL_OP_GATHER_STATS;
	info.op_ver	   = SXE2_VCHNL_OP_GATHER_STATS_V1;
	req_type	   = SXE2_RDMA_STATS_VF_RX;
	info.req_parm	   = (void *)(&req_type);
	info.req_parm_len  = sizeof(req_type);
	info.resp_parm	   = (void *)(&gather_stats_resp_rx);
	info.resp_parm_len = sizeof(gather_stats_resp_rx);
	if (!rdma_dev->rdma_func->reset) {
		ret = sxe2_vchnl_req_send_sync(dev, &info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl:gather stats req send sync err ret=%d\n",
				ret);
			goto end;
		}
		memcpy(&gather_stats_resp->val[STATS_VF_RX_BUF_START_8BYTE],
		       &gather_stats_resp_rx, STATS_VF_RX_BUF_ALL_BYTE);
#ifdef SXE2_CFG_DEBUG
		for (i = SXE2_RDMA_HW_STAT_INDEX_IP4RXOCTS;
		     i < SXE2_RDMA_HW_STAT_INDEX_MAX; i++) {
			DRV_RDMA_LOG_DEBUG_BDF(
				"vf i %u, bitoff %u, val %#llx\n", i,
				map[i].byteoff, gather_stats_resp->val[i]);
		}
#endif
	}

end:
	return ret;
}

int sxe2_vchnl_req_manage_qet_node(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_vchnl_manage_qet_node_info *qset_info)
{
	int ret				     = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);
	struct sxe2_vchnl_req_init_info info = {};

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}

	info.op_code	  = SXE2_VCHNL_OP_MANAGE_QSET_NODE;
	info.op_ver	  = SXE2_VCHNL_OP_MANAGE_QSET_NODE_V1;
	info.req_parm	  = (void *)(qset_info);
	info.req_parm_len = sizeof(struct sxe2_vchnl_manage_qet_node_info);

	DRV_RDMA_LOG_DEV_DEBUG("vchnl:req %s qet %u node\n",
			       qset_info->add ? "register" : "unregister",
			       qset_info->qset_id);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:manage qset node req send sync err ret=%d\n",
			ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_set_pbl_fpte(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx,
				u64 page_pa)
{
	int ret						  = SXE2_OK;
	struct sxe2_vchnl_pbl_set_fpte_info set_fpte_info = {};
	struct sxe2_vchnl_req_init_info info		  = {};
	struct sxe2_rdma_device *rdma_dev		  = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}

	set_fpte_info.fpte_idx = fpte_idx;
	set_fpte_info.page_pa  = page_pa;

	info.op_code	  = SXE2_VCHNL_OP_PBL_SET_FPTE;
	info.op_ver	  = SXE2_VCHNL_OP_PBL_SET_FPTE_V1;
	info.req_parm	  = (void *)(&set_fpte_info);
	info.req_parm_len = sizeof(set_fpte_info);

	DRV_RDMA_LOG_DEBUG_BDF(
		"vchnl:set pbl fpte idx=%u page pa=0x%llx\n", fpte_idx,
		page_pa);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:set pbl fpte req send sync err ret=%d\n", ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_clear_pbl_fpte(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx,
				  u32 pble_cnt)
{
	int ret						      = SXE2_OK;
	struct sxe2_vchnl_pbl_clear_fpte_info clear_fpte_info = {};
	struct sxe2_vchnl_req_init_info info		      = {};
	struct sxe2_rdma_device *rdma_dev		      = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}

	clear_fpte_info.fpte_idx = fpte_idx;
	clear_fpte_info.pble_cnt = pble_cnt;

	info.op_code	  = SXE2_VCHNL_OP_PBL_CLEAR_FPTE;
	info.op_ver	  = SXE2_VCHNL_OP_PBL_CLEAR_FPTE_V1;
	info.req_parm	  = (void *)(&clear_fpte_info);
	info.req_parm_len = sizeof(clear_fpte_info);

	DRV_RDMA_LOG_DEBUG_BDF("vchnl:clear pbl fpte idx=%u pble cnt=%u\n",
			       fpte_idx, pble_cnt);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:clear pbl fpte req send sync err ret=%d\n", ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_update_fpte(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_rcms_vf_update_fptes_info *update_vf_fpte_info)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				       dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}

	info.op_code	  = SXE2_VCHNL_OP_UPDATE_FPTE;
	info.op_ver	  = SXE2_VCHNL_OP_UPDATE_FPTE_V1;
	info.req_parm	  = (void *)(update_vf_fpte_info);
	info.req_parm_len = sizeof(*update_vf_fpte_info);

	DRV_RDMA_LOG_DEBUG_BDF("vchnl:vf req update fpte set=%u cnt=%u\n",
			       update_vf_fpte_info->set,
			       update_vf_fpte_info->cnt);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"vchnl:add rcms obj req send sync err ret=%d\n", ret);
	}

end:
	return ret;
}

int sxe2_vchnl_req_get_port_active_speed(
	struct sxe2_rdma_ctx_dev *dev,
	u32 *port_active_speed)
{
	int ret				     = SXE2_OK;
	struct sxe2_vchnl_req_init_info info = {};
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(dev);

	if (!dev->vchnl_up) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:not support vchnl up=%u\n",
				     dev->vchnl_up);
		ret = -EBUSY;
		goto end;
	}

	info.op_code	   = SXE2_VCHNL_OP_GET_PORT_ACTIVE_SPEED;
	info.op_ver	       = SXE2_VCHNL_OP_GET_PORT_ACTIVE_SPEED_V1;
	info.resp_parm	   = (void *)port_active_speed;
	info.resp_parm_len = sizeof(*port_active_speed);

	ret = sxe2_vchnl_req_send_sync(dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF("vchnl:get port active speed req send sync err ret=%d\n",
				     ret);
	}
end:
	return ret;
}

int sxe2_vchnl_ctx_init(struct sxe2_rdma_ctx_dev *dev,
			struct sxe2_vchnl_init_info *info)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	dev->vchnl_if			       = info->vchnl_if;
	dev->vchnl_up			       = dev->vchnl_if ? true : false;
	dev->privileged			       = info->privileged;
	dev->vchnl_wq			       = info->vchnl_wq;
	dev->hw_attrs.uk_attrs.hw_rev	       = info->hw_rev;
	dev->hw_attrs.uk_attrs.max_hw_push_len = SXE2_RDMA_DEFAULT_MAX_PUSH_LEN;
	if (!dev->privileged) {
		ret = sxe2_vchnl_req_get_ver(dev, &dev->fw_version);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl: vchnl req get ver err ret=%d\n", ret);
			goto end;
		}

		ret = sxe2_vchnl_req_get_caps(dev);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"vchnl: vchnl req get caps err ret=%d\n", ret);
			goto end;
		}

		dev->hw_attrs.uk_attrs.hw_rev = dev->vc_caps.hw_rev;
		dev->hw_attrs.uk_attrs.max_hw_push_len =
			dev->vc_caps.max_hw_push_len;
	}

end:
	return ret;
}
