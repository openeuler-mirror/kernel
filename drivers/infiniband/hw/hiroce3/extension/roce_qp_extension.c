// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_qp_extension.h"
#include "cfg_mgmt_mpu_cmd_defs.h"

#ifdef ROCE_EXTEND
#include "roce_ctx_api.h"
#include "roce_pd.h"
#endif

int to_roce3_qp_type(enum ib_qp_type qp_type)
{
	switch (qp_type) {
	case IB_QPT_RC:
		return ROCE_QP_ST_RC;

	case IB_QPT_UC:
		return ROCE_QP_ST_UC;

	case IB_QPT_UD:
		return ROCE_QP_ST_UD;

	case IB_QPT_XRC_INI:
	case IB_QPT_XRC_TGT:
		return ROCE_QP_ST_XRC;

	case IB_QPT_GSI:
		return ROCE_QP_ST_UD;

	default:
		return -1;
	}
}

bool roce3_check_qp_modify_ok(enum ib_qp_state cur_state, enum ib_qp_state next_state,
	enum ib_qp_type type, enum ib_qp_attr_mask mask, enum rdma_link_layer ll)
{
	return ib_modify_qp_is_ok(cur_state, next_state, type, mask);
}

#ifndef PANGEA_NOF
int roce3_create_qp_pre_ext(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct ib_qp_init_attr *init_attr)
{
	return 0;
}

int roce3_create_qp_user_pre_ext(struct ib_qp_init_attr *init_attr, struct roce3_qp *rqp, u32 *qpn)
{
	*qpn = ROCE_QP_INVLID_QP_NUM;

	return 0;
}

int roce3_create_qp_user_post_ext(struct ib_pd *ibpd, struct roce3_device *rdev,
	struct roce3_qp *rqp, struct ib_qp_init_attr *init_attr)
{
	return 0;
}

int roce3_qp_modify_cmd_ext(struct tag_cqm_cmd_buf *cqm_cmd_inbuf, struct roce3_qp *rqp,
	struct tag_roce_verbs_qp_attr *qp_attr, u32 optpar)
{
	return 0;
}

bool roce3_need_qpn_lb1_consistent_srqn(const struct roce3_qp *rqp, const struct roce3_device *rdev,
	const struct ib_qp_init_attr *init_attr)
{
	if (init_attr->srq == NULL)
		return false;

	if ((rdev->cfg_info.scence_id == SCENES_ID_CLOUD) ||
		(rdev->cfg_info.scence_id == SCENES_ID_COMPUTE_ROCE) ||
		(rdev->cfg_info.scence_id == SCENES_ID_COMPUTE_STANDARD))
		return true;

	return false;
}

int roce3_is_qp_normal(struct roce3_qp *rqp, struct ib_qp_init_attr *init_attr)
{
	return 1;
}

#ifdef ROCE_EXTEND
static struct roce3_qp *roce3_cdev_lookup_and_check_rqp(struct roce3_device *rdev, u32 qpn)
{
	struct tag_cqm_object *cqm_obj_qp = NULL;
	struct roce3_qp *rqp = NULL;

	cqm_obj_qp = cqm_object_get(rdev->hwdev, CQM_OBJECT_SERVICE_CTX, qpn, false);
	if (cqm_obj_qp == NULL) {
		pr_err("[ROCE, ERR] %s: Can't find rqp according to qpn(0x%x), func_id(%d)\n",
			__func__, qpn, rdev->glb_func_id);
		return NULL;
	}

	rqp = cqmobj_to_roce_qp(cqm_obj_qp);
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_qp);

	if (rqp->qpn >= QPC_ROCE_VBS_QPC_OFFSET_FOR_SQPC) {
		dev_err(rdev->hwdev_hdl, "[ROCE_VBS, ERR] %s: qpn[%u] more than sqpc num offset(%d) for sqpc.\n",
			__func__, rqp->qpn, QPC_ROCE_VBS_QPC_OFFSET_FOR_SQPC);
		return NULL;
	}

	return rqp;
}

static int roce3_alloc_sqpc(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct roce3_vbs_qp *vbs_rqp)
{
	struct tag_cqm_qpc_mpt *qpc_info = NULL;

	/* Call the CQM interface to allocate QPNs and QPCs */
	/* For SQPC, do not need to allocate QPN, QPN is directly spcified in rsvd segment */
	qpc_info = cqm_object_qpc_mpt_create(rdev->hwdev, SERVICE_T_ROCE, CQM_OBJECT_SERVICE_CTX,
		rdev->rdma_cap.dev_rdma_cap.roce_own_cap.qpc_entry_sz,
		NULL, rqp->qpn + QPC_ROCE_VBS_QPC_OFFSET_FOR_SQPC, false);
	if (qpc_info == NULL) {
		dev_err(rdev->hwdev_hdl, "[ROCE_VBS, ERR] %s: Failed to create qpc by cqm object, func_id(%d), qpn(%u)\n",
			__func__, rdev->glb_func_id,
			rqp->qpn + QPC_ROCE_VBS_QPC_OFFSET_FOR_SQPC);
		return -ENOMEM;
	}

	if (qpc_info->xid != (rqp->qpn + QPC_ROCE_VBS_QPC_OFFSET_FOR_SQPC)) {
		dev_err(rdev->hwdev_hdl, "[ROCE_VBS, ERR] %s: Create qpc error, func_id(%d), expect qpn(%d), actual qpn(%d)\n",
			__func__, rdev->glb_func_id,
			rqp->qpn + QPC_ROCE_VBS_QPC_OFFSET_FOR_SQPC, qpc_info->xid);
		hiudk_cqm_object_delete(rdev->hwdev, &(qpc_info->object));
		return -EFAULT;
	}

	vbs_rqp->vbs_sqpc_info = qpc_info;
	rqp->vbs_qp_ptr = (void *)vbs_rqp;

	return 0;
}

long roce3_set_qp_ext_attr(struct roce3_device *rdev, void *buf)
{
	int ret;
	struct roce3_qp *rqp = NULL;
	struct roce3_set_qp_ext_attr_cmd cmd;
	struct roce_qp_context *context = NULL;

	ret = (int)copy_from_user(&cmd, buf, sizeof(cmd));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to copy data from user\n",
			__func__);
		return (long)ret;
	}

	rqp = roce3_cdev_lookup_and_check_rqp(rdev, cmd.qpn);
	if (rqp == NULL) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to look up rqp\n", __func__);
		return -EINVAL;
	}

	context = (struct roce_qp_context *)((void *)rqp->qpc_info->vaddr);
	if (((cmd.attr_mask) & ROCE_QP_VBS_FLAG) != 0) { /*  IBV_QP_VBS_OSD_FLAG */
		context->sw_seg.ucode_seg.common.dw0.bs.ulp_type = ROCE_ULP_VBS;
	}

	return (long)ret;
}

long roce3_vbs_create_sqpc(struct roce3_device *rdev, void *buf)
{
	struct roce3_modify_qp_vbs_cmd cmd;
	struct roce3_vbs_qp *vbs_rqp = NULL;
	struct roce3_qp *rqp = NULL;
	struct roce3_pd *pd = NULL;
	int ret;

	ret = (int)copy_from_user(&cmd, buf, sizeof(cmd));
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to copy data from user\n",
			__func__);
		return (long)ret;
	}

	rqp = roce3_cdev_lookup_and_check_rqp(rdev, cmd.qpn);
	if (rqp == NULL) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Failed to look up rqp\n", __func__);
		return -EINVAL;
	}

	vbs_rqp = kzalloc(sizeof(*vbs_rqp), GFP_KERNEL);
	if (vbs_rqp == NULL)
		return -ENOMEM;

	pd = roce3_get_pd(rqp);
	ret = roce3_db_map_user(to_roce3_ucontext(pd->ibpd.uobject->context),
		cmd.ci_record_addr, &vbs_rqp->db);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE_VBS, ERR] %s: Failed to map db page to user, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto free_rqp;
	}

	ret = roce3_alloc_sqpc(rdev, rqp, vbs_rqp);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE_VBS, ERR] %s: Failed to alloc sqpc, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto free_rqp;
	}

	return 0;

free_rqp:
	kfree(vbs_rqp);

	return (long)ret;
}
#endif

#endif /* !PANGEA_NOF */

#ifndef ROCE_CHIP_TEST
void roce3_set_qp_dif_attr(struct roce3_qp *rqp, const struct ib_qp_init_attr *init_attr,
	const struct roce3_device *rdev)
{
	if (((unsigned int)init_attr->create_flags & IB_QP_CREATE_SIGNATURE_EN) != 0) {
		rqp->signature_en = true;
		dev_info(rdev->hwdev_hdl, "[ROCE] %s: func(%d) qp(%u) roce3_create_qp signature_en.\n",
			__func__, rdev->glb_func_id, rqp->qpn);
	}
}
#endif

#ifndef ROCE_VBS_EN
int roce3_qp_modify_pre_extend(struct roce3_qp *rqp, struct ib_qp_attr *attr,
	int attr_mask, struct ib_udata *udata)
{
	return 0;
}
#endif
