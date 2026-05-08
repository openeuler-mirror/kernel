// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_qos.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_qos.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_hw.h"
#include "sxe2_drv_aux.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_virtchnl.h"

struct sxe2_err_code sxe2_qos_apply_qset_err_code[] = {
	{ "NO ERR", QSET_INVALID_CODE },
	{ "APPLY:NO FREE QSET", NO_FREE_QSET },
	{ "APPLY:FUNCTION EXCEED MAX LIMIT QSET",
	  FUNCTION_EXCEED_MAX_LIMIT_QSET },
};

struct sxe2_err_code sxe2_qos_release_qset_err_code[] = {
	{ "NO ERR", QSET_INVALID_CODE },
	{ "RELEASE:QSET NOT ALLOCED", QSET_NOT_ALLOCED },
	{ "RELEASE:QSET FUNC NOT MATCH", QSET_FUNC_NOT_MATCH },
};

struct sxe2_err_code sxe2_qos_qp_bind_qset_err_code[] = {
	{ "NO ERR", QSET_INVALID_CODE },
	{ "BIND:QP NOT BIND THIS FUNCTION", BIND_QP_NOT_BIND_THIS_FUNCTION },
	{ "BIND:QSET NOT BIND THIS FUNCTION",
	  BIND_QSET_NOT_BIND_THIS_FUNCTION },
	{ "BIND:QP QSET NOT BIND THIS FUNCTION",
	  BIND_QP_QSET_NOT_BIND_THIS_FUNCTION },

	{ "UNBIND:QP NOT BIND THIS FUNCTION",
	  UNBIND_QP_NOT_BIND_THIS_FUNCTION },
	{ "UNBIND:QSET NOT BIND THIS FUNCTION",
	  UNBIND_QSET_NOT_BIND_THIS_FUNCTION },
	{ "UNBIND:QP QSET NOT BIND THIS FUNCTION",
	  UNBIND_QP_QSET_NOT_BIND_THIS_FUNCTION },
	{ "UNBIND:QP UNBIND", UNBIND_QP_UNBIND },
	{ "UNBIND:QP NOT BIND THIS QSET", UNBIND_QP_NOT_BIND_THIS_QSET },

};

static int sxe2_qos_bar_query_qset(struct sxe2_rdma_ctx_dev *dev, u32 qset_id,
				   u32 *func_id)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 pull			  = QOS_QUERY_QSET_REQ_PULL;
	u32 req_reg_val;
	u32 resp_reg_val;
	u32 req_reg_idx;
	u32 resp_reg_idx;

	req_reg_idx  = QSET_QUERY_REQ;
	resp_reg_idx = QSET_QUERY_RESP;

	if (qset_id >= SXE2_FUNC_MAX_QSET_ID) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"qos:query qset input qset id err qset id=%d\n",
			qset_id);
		goto end;
	}

	if (rdma_dev->rdma_func->reset) {
		ret = -EBUSY;
		DRV_RDMA_LOG_DEV_INFO(
			"reset is set, bar will not be performed\n");
		goto end;
	}

	req_reg_val = WRITE_BIT(qset_id, QUERY_QSET_REQ_QSET_ID_M,
				QUERY_QSET_REQ_QSET_ID_S) |
		      WRITE_BIT(1, QUERY_QSET_REQ_VLD_M, QUERY_QSET_REQ_VLD_S);
	SXE2_BAR_WRITE_32(req_reg_val, dev->hw_regs[req_reg_idx]);
	do {
		resp_reg_val = SXE2_BAR_READ_32(dev->hw_regs[resp_reg_idx]);
		if (READ_BIT(resp_reg_val, QUERY_QSET_RESP_DONE_M,
			     QUERY_QSET_RESP_DONE_S) &&
		    !READ_BIT(resp_reg_val, QUERY_QSET_RESP_ERR_M,
			      QUERY_QSET_RESP_ERR_S)) {
			*func_id = READ_BIT(resp_reg_val,
					    QUERY_QSET_RESP_FUNC_ID_M,
					    QUERY_QSET_RESP_FUNC_ID_S);
			resp_reg_val = WRITE_BIT(0, QUERY_QSET_RESP_DONE_M,
						 QUERY_QSET_RESP_DONE_S);
			SXE2_BAR_WRITE_32(resp_reg_val,
					  dev->hw_regs[resp_reg_idx]);
			break;
		} else if (READ_BIT(resp_reg_val, QUERY_QSET_RESP_DONE_M,
				    QUERY_QSET_RESP_DONE_S) &&
			   READ_BIT(resp_reg_val, QUERY_QSET_RESP_ERR_M,
				    QUERY_QSET_RESP_ERR_S)) {
			DRV_RDMA_LOG_DEV_ERR(
				"qos:bar reg query qset not alloced\n");
			ret = -EINVAL;
			resp_reg_val = WRITE_BIT(0, QUERY_QSET_RESP_DONE_M,
						 QUERY_QSET_RESP_DONE_S) |
				       WRITE_BIT(0, QUERY_QSET_RESP_ERR_M,
						 QUERY_QSET_RESP_ERR_S);
			SXE2_BAR_WRITE_32(resp_reg_val,
					  dev->hw_regs[resp_reg_idx]);
			break;
		}
		cond_resched();
	} while ((--pull) != 0);

	if (pull == 0) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"qos:query qset resp reg not done, reg val=0x%x\n",
			resp_reg_val);
	}
end:
	return ret;
}

static int sxe2_qos_bar_apply_qset(struct sxe2_rdma_ctx_dev *dev, u16 *qset_id)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 pull			  = QOS_APPLY_QSET_REQ_PULL;
	u32 req_reg_val;
	u32 resp_reg_val;
	u32 req_reg_idx;
	u32 resp_reg_idx;
	u32 err_code;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	u8 inject_err_code =
		rdma_dev->rdma_func->inject_qos.apply_qset_err_code;
#endif

	req_reg_idx  = QSET_APPLY_REQ;
	resp_reg_idx = QSET_APPLY_RESP;

	if (rdma_dev->rdma_func->reset) {
		ret = -EBUSY;
		DRV_RDMA_LOG_DEV_INFO(
			"reset is set, bar will not be performed\n");
		goto end;
	}

	req_reg_val = WRITE_BIT(1, APPLY_QSET_REQ_REG_VLD_M,
				APPLY_QSET_REQ_REG_VLD_S);
	SXE2_BAR_WRITE_32(req_reg_val, dev->hw_regs[req_reg_idx]);
	do {
		resp_reg_val = SXE2_BAR_READ_32(dev->hw_regs[resp_reg_idx]);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
		if (inject_err_code) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"qos:inject apply qset resp reg val=0x%x\n",
				resp_reg_val);
			resp_reg_val = resp_reg_val | QOS_BAR_APPLY_INJECT_VAL;
		}
#endif
		if (READ_BIT(resp_reg_val, APPLY_QSET_RESP_DONE_M,
			     APPLY_QSET_RESP_DONE_S) &&
		    !READ_BIT(resp_reg_val, APPLY_QSET_RESP_ERR_M,
			      APPLY_QSET_RESP_ERR_S)) {
			*qset_id = (u16)READ_BIT(resp_reg_val,
						 APPLY_QSET_RESP_QSET_ID_M,
						 APPLY_QSET_RESP_QSET_ID_S);
			resp_reg_val = WRITE_BIT(0, APPLY_QSET_RESP_DONE_M,
						 APPLY_QSET_RESP_DONE_S);
			SXE2_BAR_WRITE_32(resp_reg_val,
					  dev->hw_regs[resp_reg_idx]);
			break;
		} else if (READ_BIT(resp_reg_val, APPLY_QSET_RESP_DONE_M,
				    APPLY_QSET_RESP_DONE_S) &&
			   READ_BIT(resp_reg_val, APPLY_QSET_RESP_ERR_M,
				    APPLY_QSET_RESP_ERR_S)) {
			ret = -EINVAL;
			DRV_RDMA_LOG_DEV_ERR(
				"qos:no available qset resource reg\n");
			err_code = READ_BIT(resp_reg_val,
					    APPLY_QSET_RESP_ERR_CODE_M,
					    APPLY_QSET_RESP_ERR_CODE_S);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
			if (inject_err_code) {
				err_code = inject_err_code;
				DRV_RDMA_LOG_DEV_DEBUG(
					"qos:inject apply qset errcode=%d\n",
					err_code);
			}
#endif
			DRV_RDMA_LOG_DEV_ERR(
				"qos:err code:%u err type is %s\n",
				sxe2_qos_apply_qset_err_code[err_code].err_code,
				sxe2_qos_apply_qset_err_code[err_code].err_mean);
			resp_reg_val = WRITE_BIT(0, APPLY_QSET_RESP_DONE_M,
						 APPLY_QSET_RESP_DONE_S) |
				       WRITE_BIT(0, APPLY_QSET_RESP_ERR_M,
						 APPLY_QSET_RESP_ERR_S);
			SXE2_BAR_WRITE_32(resp_reg_val,
					  dev->hw_regs[resp_reg_idx]);
			break;
		}
		cond_resched();
	} while ((--pull) != 0);

	if (pull == 0) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"qos:apply qset resp reg not done, reg val=0x%x\n",
			resp_reg_val);
	}

end:
	return ret;
}

static void sxe2_qos_bar_release_qset(struct sxe2_rdma_ctx_dev *dev,
				      u32 qset_id)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 pull			  = QOS_RELEASE_QSET_REQ_PULL;
	u32 req_reg_val;
	u32 resp_reg_val;
	u32 req_reg_idx;
	u32 resp_reg_idx;
	u32 err_code;
	u32 func_id;
	bool hw_rsrc_clean = false;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	u8 inject_err_code =
		rdma_dev->rdma_func->inject_qos.release_qset_err_code;
#endif

	req_reg_idx  = QSET_RELEASE_REQ;
	resp_reg_idx = QSET_RELEASE_RESP;

	if (qset_id >= SXE2_FUNC_MAX_QSET_ID) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"qos:release qset input qset id err qset id=%d\n",
			qset_id);
		goto end;
	}

	hw_rsrc_clean =
		sxe2_get_hw_rsrc_clean_flag(&rdma_dev->rdma_func->ctx_dev);
	if (rdma_dev->rdma_func->reset && hw_rsrc_clean) {
		ret = -EBUSY;
		DRV_RDMA_LOG_DEV_INFO(
			"reset is set, bar will not be performed\n");
		goto end;
	}

	req_reg_val =
		WRITE_BIT(qset_id, RELEASE_QSET_REQ_QSET_ID_M,
			  RELEASE_QSET_REQ_QSET_ID_S) |
		WRITE_BIT(1, RELEASE_QSET_REQ_VLD_M, RELEASE_QSET_REQ_VLD_S);
	SXE2_BAR_WRITE_32(req_reg_val, dev->hw_regs[req_reg_idx]);
	do {
		resp_reg_val = SXE2_BAR_READ_32(dev->hw_regs[resp_reg_idx]);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
		if (inject_err_code) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"qos:inject release qset resp reg val=0x%x\n",
				resp_reg_val);
			resp_reg_val =
				resp_reg_val | QOS_BAR_RELEASE_INJECT_VAL;
		}
#endif
		if (READ_BIT(resp_reg_val, RELEASE_QSET_RESP_DONE_M,
			     RELEASE_QSET_RESP_DONE_S) &&
		    !READ_BIT(resp_reg_val, RELEASE_QSET_RESP_ERR_M,
			      RELEASE_QSET_RESP_ERR_S)) {
			req_reg_val = WRITE_BIT(0, RELEASE_QSET_RESP_DONE_M,
						RELEASE_QSET_RESP_DONE_S);
			SXE2_BAR_WRITE_32(req_reg_val,
					  dev->hw_regs[resp_reg_idx]);
			break;
		} else if (READ_BIT(resp_reg_val, RELEASE_QSET_RESP_DONE_M,
				    RELEASE_QSET_RESP_DONE_S) &&
			   READ_BIT(resp_reg_val, RELEASE_QSET_RESP_ERR_M,
				    RELEASE_QSET_RESP_ERR_S)) {
			DRV_RDMA_LOG_DEV_ERR("qos:bar reg release qset err\n");
			err_code = READ_BIT(resp_reg_val,
					    RELEASE_QSET_RESP_ERR_CODE_M,
					    RELEASE_QSET_RESP_ERR_CODE_S);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
			if (inject_err_code) {
				err_code = inject_err_code;
				DRV_RDMA_LOG_DEV_DEBUG(
					"qos:inject release qset errcode=%d\n",
					err_code);
			}
#endif
			DRV_RDMA_LOG_DEV_ERR(
				"qos:err code:%u err type is %s\n",
				sxe2_qos_release_qset_err_code[err_code]
					.err_code,
				sxe2_qos_release_qset_err_code[err_code]
					.err_mean);
			if (err_code == QSET_FUNC_NOT_MATCH) {
				ret = sxe2_qos_bar_query_qset(dev, qset_id,
							      &func_id);
				if (ret == SXE2_OK) {
					DRV_RDMA_LOG_DEV_ERR(
						"qos: qset id %u bind func id %u\n",
						qset_id, func_id);
				}
			}

			resp_reg_val = WRITE_BIT(0, RELEASE_QSET_RESP_DONE_M,
						 RELEASE_QSET_RESP_DONE_S) |
				       WRITE_BIT(0, RELEASE_QSET_RESP_ERR_M,
						 RELEASE_QSET_RESP_ERR_S);
			SXE2_BAR_WRITE_32(resp_reg_val,
					  dev->hw_regs[resp_reg_idx]);
			break;
		}
		cond_resched();
	} while ((--pull) != 0);

	if (pull == 0) {
		DRV_RDMA_LOG_DEV_ERR(
			"qos:release qset resp reg not done, reg val=0x%x\n",
			resp_reg_val);
	}
end:
	return;
}

static int sxe2_qos_bar_qp_bind_qset(struct sxe2_rdma_ctx_dev *dev, u32 qpn,
				     u32 qset_id, bool bind)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 pull			  = QOS_RELEASE_QSET_REQ_PULL;
	u32 req_reg_val;
	u32 resp_reg_val;
	u32 req_reg_idx;
	u32 resp_reg_idx;
	u32 err_code;
	u32 cmd;
	u32 func_id;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	u8 inject_err_code =
		rdma_dev->rdma_func->inject_qos.qp_bind_qset_err_code;
#endif

	req_reg_idx  = QSET_QP_BIND_REQ;
	resp_reg_idx = QSET_QP_BIND_RESP;

	if (qset_id >= SXE2_FUNC_MAX_QSET_ID || qpn >= SXE2_FUNC_MAX_QPN) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"qos:qp qset input qset id err qset id=%d, qpn=%d\n",
			qset_id, qpn);
		goto end;
	}

	if (rdma_dev->rdma_func->reset) {
		ret = -EBUSY;
		DRV_RDMA_LOG_DEV_INFO(
			"reset is set, bar will not be performed\n");
		goto end;
	}

	if (bind) {
		cmd = QOS_QP_BIND_QSET_CMD;
		DRV_RDMA_LOG_DEV_DEBUG("qos:bar reg qp %u bind qset %u\n", qpn,
				       qset_id);
	} else {
		cmd = QOS_QP_UNBIND_QSET_CMD;
		DRV_RDMA_LOG_DEV_DEBUG("qos:bar reg qp %u unbind qset %u\n",
				       qpn, qset_id);
	}

	req_reg_val =
		WRITE_BIT(qpn, QP_BIND_QSET_REQ_QPN_M, QP_BIND_QSET_REQ_QPN_S) |
		WRITE_BIT(qset_id, QP_BIND_QSET_REQ_QSET_ID_M,
			  QP_BIND_QSET_REQ_QSET_ID_S) |
		WRITE_BIT(cmd, QP_BIND_QSET_REQ_CMD_M, QP_BIND_QSET_REQ_CMD_S) |
		WRITE_BIT(1, QP_BIND_QSET_REQ_VLD_M, QP_BIND_QSET_REQ_VLD_S);
	SXE2_BAR_WRITE_32(req_reg_val, dev->hw_regs[req_reg_idx]);
	do {
		resp_reg_val = SXE2_BAR_READ_32(dev->hw_regs[resp_reg_idx]);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
		if (inject_err_code) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"qos:inject qp bind qset resp reg val=0x%x\n",
				resp_reg_val);
			resp_reg_val =
				resp_reg_val | QOS_BAR_QP_BIND_INJECT_VAL;
		}
#endif
		if (READ_BIT(resp_reg_val, QP_BIND_QSET_RESP_DONE_M,
			     QP_BIND_QSET_RESP_DONE_S) &&
		    !READ_BIT(resp_reg_val, QP_BIND_QSET_RESP_ERR_M,
			      QP_BIND_QSET_RESP_ERR_S)) {
			req_reg_val = WRITE_BIT(0, QP_BIND_QSET_RESP_DONE_M,
						QP_BIND_QSET_RESP_DONE_S);
			SXE2_BAR_WRITE_32(req_reg_val,
					  dev->hw_regs[resp_reg_idx]);
			break;
		} else if (READ_BIT(resp_reg_val, QP_BIND_QSET_RESP_DONE_M,
				    QP_BIND_QSET_RESP_DONE_S) &&
			   READ_BIT(resp_reg_val, QP_BIND_QSET_RESP_ERR_M,
				    QP_BIND_QSET_RESP_ERR_S)) {
			err_code = READ_BIT(resp_reg_val,
					    QP_BIND_QSET_RESP_ERR_CODE_M,
					    QP_BIND_QSET_RESP_ERR_CODE_S);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
			if (inject_err_code) {
				err_code = inject_err_code;
				DRV_RDMA_LOG_DEV_DEBUG(
					"qos:inject qp bind qset errcode=%d\n",
					err_code);
			}
#endif
			DRV_RDMA_LOG_DEV_ERR(
				"qos:err code:%u err type is %s\n",
				sxe2_qos_qp_bind_qset_err_code[err_code]
					.err_code,
				sxe2_qos_qp_bind_qset_err_code[err_code]
					.err_mean);
			if (err_code == BIND_QSET_NOT_BIND_THIS_FUNCTION ||
			    err_code == BIND_QP_QSET_NOT_BIND_THIS_FUNCTION ||
			    err_code == UNBIND_QSET_NOT_BIND_THIS_FUNCTION ||
			    err_code == UNBIND_QP_QSET_NOT_BIND_THIS_FUNCTION) {
				ret = sxe2_qos_bar_query_qset(dev, qset_id,
							      &func_id);
				if (ret == SXE2_OK) {
					DRV_RDMA_LOG_DEV_ERR(
						"qos: qset id %u bind func id %u\n",
						qset_id, func_id);
				}
			}
			ret = -EINVAL;
			resp_reg_val = WRITE_BIT(0, RELEASE_QSET_RESP_DONE_M,
						 RELEASE_QSET_RESP_DONE_S) |
				       WRITE_BIT(0, RELEASE_QSET_RESP_ERR_M,
						 RELEASE_QSET_RESP_ERR_S);
			SXE2_BAR_WRITE_32(resp_reg_val,
					  dev->hw_regs[resp_reg_idx]);
			break;
		}
		cond_resched();
	} while ((--pull) != 0);

	if (pull == 0) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"qos:qp bind qset resp reg not done, reg val=0x%x\n",
			resp_reg_val);
	}

end:
	return ret;
}

static bool sxe2_qos_qset_in_use(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri,
				 u8 qset_idx)
{
	if (!list_empty(&vsi->qos[user_pri].qset[qset_idx].qp_list) &&
	    vsi->qos[user_pri].qset[qset_idx].qset_qp_cnt != 0) {
		return true;
	}

	return false;
}

static int sxe2_qos_qset_add_qp(struct sxe2_rdma_ctx_dev *dev, u32 qpn,
				u32 qset_id)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	ret = sxe2_qos_bar_qp_bind_qset(dev, qpn, qset_id, true);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("qos:bar qp bind qset ret=%d\n", ret);
		goto end;
	}
end:
	return ret;
}

static int sxe2_qos_qset_rem_qp(struct sxe2_rdma_ctx_dev *dev, u32 qpn,
				u32 qset_id)
{
	int ret				  = SXE2_OK;

	ret = sxe2_qos_bar_qp_bind_qset(dev, qpn, qset_id, false);
	if (ret != SXE2_OK)
		goto end;

end:
	return ret;
}

u8 get_pf_num_by_bitmap(u8 qset_pf)
{
	u8 pf_num = 0;

	if (qset_pf == SXE2_RDMA_PF0)
		pf_num = QOS_MAX_PORT_NUM_LAG_0;
	else if (qset_pf == SXE2_RDMA_PF1)
		pf_num = QOS_MAX_PORT_NUM_LAG_1;

	return pf_num;
}

int sxe2_qos_lan_register_qsets(struct sxe2_rdma_ctx_vsi *vsi,
				struct sxe2_rdma_qset *qset1,
				struct sxe2_rdma_qset *qset2)
{
	int ret				    = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev   = vsi->back_vsi;
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct sxe2_rdma_qset *qset;
	struct aux_rdma_qset_params qset_params		    = {};
	struct aux_rdma_multi_qset_params multi_qset_params = {};

	if (vsi->lag_aa) {
		if (!qset1 || !qset2) {
			ret = -EINVAL;
			DRV_RDMA_LOG_DEV_ERR(
				"qos:lan register multi qset is NULL, ret=%d\n",
				ret);
			goto end;
		}
		multi_qset_params.qset_id[QOS_QSET_IDX_0] =
			qset1->qset_id;
		multi_qset_params.qset_id[QOS_QSET_IDX_1] =
			qset2->qset_id;
		multi_qset_params.tc[QOS_QSET_IDX_0]	   = qset1->traffic_class;
		multi_qset_params.tc[QOS_QSET_IDX_1]	   = qset2->traffic_class;
		multi_qset_params.vport_id = qset2->vsi_index;
		multi_qset_params.num	   = QOS_MAX_QSET_NUM_PER_USER_PRI;
		multi_qset_params.user_pri = qset2->user_pri;

		if (!rdma_dev->rdma_func->reset) {
			ret = cdev_info->ops->alloc_multi_res(
				cdev_info, &multi_qset_params);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"qos:lan register multi qset nodes err ret=%d\n",
					ret);
				goto end;
			}
			qset1->teid = multi_qset_params
					      .teid[QOS_QSET_IDX_0];
			qset2->teid = multi_qset_params
					      .teid[QOS_QSET_IDX_1];
			vsi->qos[qset1->user_pri]
				.teid[QOS_QSET_IDX_0] = qset1->teid;
			vsi->qos[qset1->user_pri]
				.teid[QOS_QSET_IDX_1] = qset2->teid;
			qset1->pf_id = get_pf_num_by_bitmap(
				multi_qset_params
					.qset_port[QOS_QSET_IDX_0]);
			qset2->pf_id = get_pf_num_by_bitmap(
				multi_qset_params
					.qset_port[QOS_QSET_IDX_1]);
		}
		goto end;
	}

	qset = qset1;
	qset_params.qset_id  = qset->qset_id;
	qset_params.tc[QOS_QSET_IDX_0]	     = qset->traffic_class;
	if (vsi->lag_backup) {
		qset_params.tc[QOS_QSET_IDX_1] =
			cdev_info->qos_info[QOS_QSET_IDX_1].up2tc[qset->user_pri];
	}
	qset_params.vport_id = qset->vsi_index;
	qset_params.user_pri = qset->user_pri;
	if (!rdma_dev->rdma_func->reset) {
		ret = cdev_info->ops->alloc_res(cdev_info, &qset_params);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"qos:lan alloc qset node err ret=%d\n", ret);
			goto end;
		}
		qset->teid			 = qset_params.teid;
		qset->pf_id = get_pf_num_by_bitmap(qset_params.qset_port);
		vsi->qos[qset->user_pri].teid[0] = qset->teid;
	}

end:
	return ret;
}

void sxe2_qos_lan_unregister_qsets(struct sxe2_rdma_ctx_vsi *vsi,
				   struct sxe2_rdma_qset *qset1,
				   struct sxe2_rdma_qset *qset2)
{
	int ret					= SXE2_OK;
	struct sxe2_rdma_device *rdma_dev	= vsi->back_vsi;
	struct aux_core_dev_info *cdev_info	= rdma_dev->rdma_func->cdev;
	struct aux_rdma_qset_params qset_params = {};
	struct sxe2_rdma_qset *qset;
	struct aux_rdma_multi_qset_params multi_qset_params = {};

	if (qset1 && qset2) {
		if (!vsi->lag_aa) {
			ret = -EINVAL;
			DRV_RDMA_LOG_DEV_ERR(
				"qos:lan register multi qset is NULL, ret=%d\n",
				ret);
			goto end;
		}
		multi_qset_params.qset_id[QOS_QSET_IDX_0] =
			qset1->qset_id;
		multi_qset_params.qset_id[QOS_QSET_IDX_1] =
			qset2->qset_id;
		multi_qset_params.tc[QOS_QSET_IDX_0]	   = qset1->traffic_class;
		multi_qset_params.tc[QOS_QSET_IDX_1]	   = qset2->traffic_class;
		multi_qset_params.vport_id = qset2->vsi_index;
		multi_qset_params.num	   = QOS_MAX_QSET_NUM_PER_USER_PRI;
		multi_qset_params.user_pri = qset2->user_pri;
		multi_qset_params.teid[QOS_QSET_IDX_0] = qset1->teid;
		multi_qset_params.teid[QOS_QSET_IDX_1] = qset2->teid;

		if (!rdma_dev->rdma_func->reset) {
			ret = cdev_info->ops->free_multi_res(
				cdev_info, &multi_qset_params);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"qos:lan free multi qset nodes err ret=%d\n",
					ret);
			}
		}
		goto end;
	}

	qset = qset1;
	qset_params.qset_id  = qset->qset_id;
	qset_params.tc[QOS_QSET_IDX_0]	     = qset->traffic_class;
	if (vsi->lag_backup) {
		qset_params.tc[QOS_QSET_IDX_1] =
			cdev_info->qos_info[QOS_QSET_IDX_1].up2tc[qset->user_pri];
	}
	qset_params.vport_id = vsi->vsi_idx;
	qset_params.teid     = qset->teid;
	qset_params.user_pri     = qset->user_pri;

	if (!rdma_dev->rdma_func->reset) {
		ret = cdev_info->ops->free_res(cdev_info, &qset_params);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"qos:lan unregister qset node err ret=%d\n",
				ret);
		}
	}

end:
	return;
}

int sxe2_qos_qset_bind_pf_tc(struct sxe2_rdma_ctx_vsi *vsi, u32 qset_id, u8 tc,
			     bool is_pf, u32 func_id)
{
	int ret				    = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	    = vsi->dev;
	struct sxe2_rdma_device *rdma_dev   = to_rdmadev(dev);
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct qos_qset_bind_tc_info info   = {};

	if (qset_id >= SXE2_FUNC_MAX_QSET_ID || tc >= QOS_MAX_TC) {
		DRV_RDMA_LOG_DEV_ERR(
			"qos:qet bind pf tc input parm err qset id=%u tc=%u",
			qset_id, tc);
		ret = -EINVAL;
		goto end;
	}

	if (rdma_dev->rdma_func->reset) {
		ret = -EBUSY;
		DRV_RDMA_LOG_DEV_INFO(
			"reset is set, cdev ops will not be performed\n");
		goto end;
	}

	memset(&info, 0, sizeof(info));
	info.func_id = cpu_to_le32(func_id);
	info.is_pf   = cpu_to_le32((u32)is_pf);
	info.qset_id = cpu_to_le32(qset_id);
	info.tc	     = cpu_to_le32((u32)tc);

	ret = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_QET_BIND_TC,
					    (u8 *)&info, (u16)sizeof(info),
					    NULL, 0);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("qos:aq send qset bind tc err ret=%d\n",
				     ret);
		goto end;
	}

end:
	return ret;
}

int sxe2_qos_qset_bind_pf_tc_bond(struct sxe2_rdma_ctx_vsi *vsi, u32 qset1_id,
				  u32 qset2_id, u8 tc_idx0, u8 tc_idx1, bool is_pf,
				  u32 qset1_pf_id, u32 qset2_pf_id)
{
	int ret				    = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	    = vsi->dev;
	struct sxe2_rdma_device *rdma_dev   = to_rdmadev(dev);
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct qos_qset_bind_tc_info info   = {};

	if ((qset1_id >= SXE2_FUNC_MAX_QSET_ID) || (tc_idx0 >= QOS_MAX_TC) ||
	    (qset2_id >= SXE2_FUNC_MAX_QSET_ID) || (tc_idx1 >= QOS_MAX_TC)) {
		DRV_RDMA_LOG_DEV_ERR(
			"qos:qet bind pf tc input parm err qset1 id=%u, qset2 id=%u, tc1=%u, tc2=%u",
			qset1_id, qset2_id, tc_idx0, tc_idx1);
		ret = -EINVAL;
		goto end;
	}

	if (rdma_dev->rdma_func->reset) {
		DRV_RDMA_LOG_DEV_INFO(
			"reset is set, cdev ops will not be performed\n");
		goto end;
	}

	memset(&info, 0, sizeof(info));
	info.func_id = cpu_to_le32(qset1_pf_id);
	info.is_pf   = cpu_to_le32((u32)is_pf);
	info.qset_id = cpu_to_le32(qset1_id);
	info.tc	     = cpu_to_le32((u32)tc_idx0);
	info.tc_id2	     = cpu_to_le32((u32)tc_idx1);
	info.func_id2	= cpu_to_le32(qset2_pf_id);
	info.qset_id2	= cpu_to_le32(qset2_id);
	info.is_bond_aa = cpu_to_le32((u32)QOS_IS_BOND_AA);

	ret = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_QET_BIND_TC,
					    (u8 *)&info, (u16)sizeof(info),
					    NULL, 0);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("qos:aq send qset bind tc err ret=%d\n",
				     ret);
		goto end;
	}

end:
	return ret;
}

int sxe2_qos_register_qset(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct sxe2_vchnl_manage_qet_node_info qset_info;
	u8 qset_idx = 0;
	u8 active_pf = 0;
	u8 active_pf_tc = 0;

	mutex_lock(&vsi->qos[user_pri].qos_mutex);
	if (vsi->qos[user_pri].valid) {
		DRV_RDMA_LOG_DEV_DEBUG("qos:user pri is valid\n");
		goto end;
	}

	ret = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_qset,
			       rdma_func->max_qsets,
			       &vsi->qos[user_pri].qset[qset_idx].qset_num,
			       &rdma_func->next_qset);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("qos:alloc qset num err\n");
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("qos:user pri %u tclass=%u alloc qset num=%u\n",
			       user_pri, vsi->qos[user_pri].qset[0].traffic_class,
			       vsi->qos[user_pri].qset[qset_idx].qset_num);
	ret = sxe2_qos_bar_apply_qset(
		dev, &vsi->qos[user_pri].qset[qset_idx].qset_id);
	if (ret != SXE2_OK)
		goto qset_apply_err;
	vsi->qos[user_pri].qset[qset_idx].vsi_index = vsi->vsi_idx;
	vsi->qos[user_pri].qset[qset_idx].user_pri = user_pri;

	if (dev->privileged) {
		ret = vsi->register_qsets(
			vsi, &vsi->qos[user_pri].qset[qset_idx], NULL);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"qos:lan register qset node err ret=%d\n", ret);
			goto lan_register_err;
		}
		if (vsi->lag_backup) {
			active_pf = vsi->qos[user_pri].qset[qset_idx].pf_id;
			active_pf_tc = vsi->qos[user_pri].qset[active_pf].traffic_class;
			ret = sxe2_qos_qset_bind_pf_tc(
			vsi, vsi->qos[user_pri].qset[qset_idx].qset_id,
			active_pf_tc, true,
			vsi->qos[user_pri].qset[qset_idx].pf_id);
		} else {
			ret = sxe2_qos_qset_bind_pf_tc(
			vsi, vsi->qos[user_pri].qset[qset_idx].qset_id,
			vsi->qos[user_pri].qset[qset_idx].traffic_class, true,
			rdma_dev->rdma_func->pf_id);
		}

		if (ret != SXE2_OK)
			goto qet_bind_tc_err;
	} else {
		qset_info.qset_id  = vsi->qos[user_pri].qset[qset_idx].qset_id;
		qset_info.user_pri = user_pri;
		qset_info.add	   = true;

		ret = sxe2_vchnl_req_manage_qet_node(dev, &qset_info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"qos: vf lan register qset node err ret=%d\n",
				ret);
			goto lan_register_err;
		}
	}

	vsi->qos[user_pri].qset[qset_idx].qset_qp_cnt	= 0;
	vsi->qos[user_pri].qset[qset_idx].register_flag = true;
	vsi->qos[user_pri].qp_cnt			= 0;
	vsi->qos[user_pri].valid			= true;
	goto end;

qet_bind_tc_err:
	vsi->unregister_qsets(vsi, &vsi->qos[user_pri].qset[qset_idx], NULL);
lan_register_err:
	sxe2_qos_bar_release_qset(dev,
				  vsi->qos[user_pri].qset[qset_idx].qset_id);
qset_apply_err:
	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_qset,
			vsi->qos[user_pri].qset[qset_idx].qset_num);
end:
	mutex_unlock(&vsi->qos[user_pri].qos_mutex);
	return ret;
}

static void sxe2_qos_lag_setup_qset_node(struct sxe2_rdma_ctx_vsi *vsi,
					 struct sxe2_rdma_qset *qset_node,
					 bool first_node)
{
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (first_node) {
		if ((vsi->lag_port_bitmap & SXE2_RDMA_BOTH_PF) ==
		    SXE2_RDMA_PF1) {
			vsi->primary_port_migrated = true;
		} else {
			vsi->primary_port_migrated = false;
		}
	} else {
		if ((vsi->lag_port_bitmap & SXE2_RDMA_BOTH_PF) ==
		    SXE2_RDMA_PF0) {
			vsi->secondary_port_migrated = true;
		} else {
			vsi->secondary_port_migrated = false;
		}
	}
	DRV_RDMA_LOG_DEV_DEBUG(
		"first_node %d, vsi->lag_port_bitmap %u, qset_node->active_port %u,\n"
		"\tprimary_port_migrated%d, secondary_port_migrated %d\n",
		first_node, vsi->lag_port_bitmap, qset_node->active_port,
		vsi->primary_port_migrated, vsi->secondary_port_migrated);
}

int sxe2_qos_register_qset_bond(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	u8 qset_idx			  = QOS_QSET_IDX_0;

	if (!dev->privileged) {
		DRV_RDMA_LOG_DEV_ERR("qos:vf not support bond\n");
		ret = -EPERM;
		goto end;
	}

	mutex_lock(&vsi->qos[user_pri].qos_mutex);
	if (vsi->qos[user_pri].valid) {
		DRV_RDMA_LOG_DEV_DEBUG("qos:user pri is valid\n");
		goto end;
	}

	for (qset_idx = QOS_QSET_IDX_0;
	     qset_idx < QOS_MAX_QSET_NUM_PER_USER_PRI; qset_idx++) {
		ret = sxe2_kalloc_rsrc(
			rdma_func, rdma_func->allocated_qset,
			rdma_func->max_qsets,
			&vsi->qos[user_pri].qset[qset_idx].qset_num,
			&rdma_func->next_qset);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"qos:alloc qset num err, qset_idx %d\n",
				qset_idx);
			qset_idx--;
			goto lan_register_err;
		}
		DRV_RDMA_LOG_DEV_DEBUG(
			"qos:qset_idx %d user pri %u tclass=%u alloc qset num=%u\n",
			qset_idx, user_pri, vsi->qos[user_pri].qset[qset_idx].traffic_class,
			vsi->qos[user_pri].qset[qset_idx].qset_num);
		ret = sxe2_qos_bar_apply_qset(
			dev, &vsi->qos[user_pri].qset[qset_idx].qset_id);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"qos:bar reg qset apply err ret=%d, qset_idx %d\n",
				ret, qset_idx);
			sxe2_kfree_rsrc(
				rdma_func, rdma_func->allocated_qset,
				vsi->qos[user_pri].qset[qset_idx].qset_num);
			qset_idx--;
			goto lan_register_err;
		}
		vsi->qos[user_pri].qset[qset_idx].vsi_index = vsi->vsi_idx;
		vsi->qos[user_pri].qset[qset_idx].user_pri  = user_pri;

		mutex_lock(&vsi->dev->lag_mutex);
		if (qset_idx == QOS_QSET_IDX_0) {
			sxe2_qos_lag_setup_qset_node(
				vsi, &vsi->qos[user_pri].qset[qset_idx], true);
		} else {
			sxe2_qos_lag_setup_qset_node(
				vsi, &vsi->qos[user_pri].qset[qset_idx], false);
		}
		mutex_unlock(&vsi->dev->lag_mutex);
	}

	ret = vsi->register_qsets(
		vsi, &vsi->qos[user_pri].qset[QOS_QSET_IDX_0],
		&vsi->qos[user_pri].qset[QOS_QSET_IDX_1]);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("qos:lan register qset node err ret=%d\n",
				     ret);
		goto lan_register_err;
	}

	ret = sxe2_qos_qset_bind_pf_tc_bond(
		vsi, vsi->qos[user_pri].qset[QOS_QSET_IDX_0].qset_id,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_1].qset_id,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_0].traffic_class,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_1].traffic_class,
		true, vsi->qos[user_pri].qset[QOS_QSET_IDX_0].pf_id,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_1].pf_id);
	if (ret != SXE2_OK)
		goto qet_bind_tc_err;

	vsi->qos[user_pri].qset[QOS_QSET_IDX_0].qset_qp_cnt = 0;
	vsi->qos[user_pri].qset[QOS_QSET_IDX_1].qset_qp_cnt = 0;
	vsi->qos[user_pri].qset[QOS_QSET_IDX_0].register_flag = true;
	vsi->qos[user_pri].qset[QOS_QSET_IDX_1].register_flag = true;
	vsi->qos[user_pri].qp_cnt				       = 0;
	vsi->qos[user_pri].valid				       = true;

	goto end;

qet_bind_tc_err:
	vsi->unregister_qsets(
		vsi, &vsi->qos[user_pri].qset[QOS_QSET_IDX_0],
		&vsi->qos[user_pri].qset[QOS_QSET_IDX_1]);
lan_register_err:
	while ((qset_idx == QOS_QSET_IDX_0) &&
	       (qset_idx == QOS_QSET_IDX_1)) {
		sxe2_qos_bar_release_qset(
			dev, vsi->qos[user_pri].qset[qset_idx].qset_id);
		sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_qset,
				vsi->qos[user_pri].qset[qset_idx].qset_num);
		qset_idx--;
	}
end:
	mutex_unlock(&vsi->qos[user_pri].qos_mutex);
	return ret;
}

void sxe2_qos_unregister_qset(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct sxe2_vchnl_manage_qet_node_info qset_info;

	mutex_lock(&vsi->qos[user_pri].qos_mutex);
	if (!vsi->qos[user_pri].valid)
		goto end;

	if (sxe2_qos_qset_in_use(vsi, user_pri, QOS_QSET_IDX_0))
		goto end;

	if (!vsi->qos[user_pri].qset[QOS_QSET_IDX_0].register_flag) {
		DRV_RDMA_LOG_DEV_INFO(
			"qos: do not register tx schedule success.\n");
		goto release_qset_bar;
	}
	if (dev->privileged) {
		vsi->unregister_qsets(
			vsi,
			&vsi->qos[user_pri].qset[QOS_QSET_IDX_0],
			NULL);
	} else {
		qset_info.qset_id = vsi->qos[user_pri]
					    .qset[QOS_QSET_IDX_0]
					    .qset_id;
		qset_info.user_pri = user_pri;
		qset_info.add	   = false;

		ret = sxe2_vchnl_req_manage_qet_node(dev, &qset_info);
	}
release_qset_bar:
	sxe2_qos_bar_release_qset(
		dev,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_0].qset_id);
	sxe2_kfree_rsrc(
		rdma_func, rdma_func->allocated_qset,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_0].qset_num);
	vsi->qos[user_pri].qset[QOS_QSET_IDX_0].register_flag =
		false;
	vsi->qos[user_pri].valid = false;

end:
	mutex_unlock(&vsi->qos[user_pri].qos_mutex);
}

void sxe2_qos_unregister_qset_bond(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri)
{
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mutex_lock(&vsi->qos[user_pri].qos_mutex);

	if (!vsi->qos[user_pri].valid)
		goto end;

	if (sxe2_qos_qset_in_use(vsi, user_pri, QOS_QSET_IDX_0) ||
	    sxe2_qos_qset_in_use(vsi, user_pri, QOS_QSET_IDX_1)) {
		goto end;
	}

	if (!vsi->qos[user_pri].qp_cnt == 0) {
		DRV_RDMA_LOG_DEV_ERR("qos: qp cnt %u\n",
				     vsi->qos[user_pri].qp_cnt);
		goto end;
	}
	vsi->unregister_qsets(
		vsi, &vsi->qos[user_pri].qset[QOS_QSET_IDX_0],
		&vsi->qos[user_pri].qset[QOS_QSET_IDX_1]);
	sxe2_qos_bar_release_qset(
		dev,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_0].qset_id);
	sxe2_qos_bar_release_qset(
		dev,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_1].qset_id);
	sxe2_kfree_rsrc(
		rdma_func, rdma_func->allocated_qset,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_0].qset_num);
	sxe2_kfree_rsrc(
		rdma_func, rdma_func->allocated_qset,
		vsi->qos[user_pri].qset[QOS_QSET_IDX_1].qset_num);
	vsi->qos[user_pri].valid = false;

end:
	mutex_unlock(&vsi->qos[user_pri].qos_mutex);
}

int sxe2_qos_query_qset_bind_func(struct sxe2_rdma_ctx_vsi *vsi, u32 qset_id,
				  u32 *func_id)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	ret = sxe2_qos_bar_query_qset(dev, qset_id, func_id);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("qos:bar query qset ret=%d\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("qos:qset %u bind function %u ret=%d\n", qset_id,
			       *func_id, ret);

end:
	return ret;
}

int sxe2_qos_qp_add_qos(struct sxe2_rdma_ctx_vsi *vsi,
			struct sxe2_rdma_ctx_qp *qp)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u8 qset_idx			  = 0;

	if (qp->on_qoslist) {
		DRV_RDMA_LOG_DEV_WARN("qos:qp already in qp list\n");
		goto end;
	}
	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	if (!vsi->qos[qp->user_pri].valid) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("qos:qp add qos qset[%u] is invalid\n",
				     qset_idx);
		goto unlock;
	}

	if (!vsi->qos[qp->user_pri].qset[qset_idx].register_flag) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"qos:qp add qos qset[%u] register_flag is invalid\n",
			qset_idx);
		goto unlock;
	}

	DRV_RDMA_LOG_DEV_DEBUG("qos:qp %u add user pri %u qset id=%u\n",
			       qp->qp_common.qpn, qp->user_pri,
			       vsi->qos[qp->user_pri].qset[qset_idx].qset_id);
	ret = sxe2_qos_qset_add_qp(
		dev, qp->qp_common.qpn,
		vsi->qos[qp->user_pri].qset[qset_idx].qset_id);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("qos:qset add qp err ret=%d\n", ret);
		goto unlock;
	}
	vsi->qos[qp->user_pri].qset[qset_idx].qset_qp_cnt++;
	list_add(&qp->list, &vsi->qos[qp->user_pri].qset[qset_idx].qp_list);
	qp->on_qoslist = true;
	vsi->qos[qp->user_pri].qp_cnt++;
	qp->qset_idx = QOS_QSET_IDX_0;

unlock:
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
end:
	return ret;
}

int sxe2_qos_qp_add_qos_bond(struct sxe2_rdma_ctx_vsi *vsi,
			     struct sxe2_rdma_ctx_qp *qp)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (qp->on_qoslist) {
		DRV_RDMA_LOG_DEV_WARN("qos:qp already in qp list\n");
		goto end;
	}
	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	qp->qset_idx ? atomic_inc(&vsi->port2_qp_cnt) :
			       atomic_inc(&vsi->port1_qp_cnt);

	DRV_RDMA_LOG_DEV_DEBUG(
		"qos:qp %u, add user pri %u, qset_idx %u, qset id=%u\n",
		qp->qp_common.qpn, qp->user_pri, qp->qset_idx,
		vsi->qos[qp->user_pri].qset[qp->qset_idx].qset_id);
	ret = sxe2_qos_qset_add_qp(
		dev, qp->qp_common.qpn,
		vsi->qos[qp->user_pri].qset[qp->qset_idx].qset_id);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("qos:qset add qp err ret=%d\n", ret);
		goto unlock;
	}
	vsi->qos[qp->user_pri].qset[qp->qset_idx].qset_qp_cnt++;
	list_add(&qp->list, &vsi->qos[qp->user_pri].qset[qp->qset_idx].qp_list);
	qp->on_qoslist = true;
	vsi->qos[qp->user_pri].qp_cnt++;

unlock:
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
end:
	return ret;
}

int sxe2_qos_qp_rem_qos(struct sxe2_rdma_ctx_vsi *vsi,
			struct sxe2_rdma_ctx_qp *qp)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = vsi->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u8 qset_idx = (qp->qset_idx) ? QOS_QSET_IDX_1 :
				       QOS_QSET_IDX_0;

	DRV_RDMA_LOG_DEV_DEBUG("qos:qp remove user pri=%u qpn=%u qset idx=%u\n",
			       qp->user_pri, qp->qp_common.qpn, qset_idx);
	if (!qp->on_qoslist) {
		DRV_RDMA_LOG_DEV_WARN("qos:qp not in qp list\n");
		goto end;
	}
	mutex_lock(&vsi->qos[qp->user_pri].qos_mutex);
	if (!vsi->qos[qp->user_pri].valid) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("qos:qp rem qos qset[%u] is invalid\n",
				     qset_idx);
		goto unlock;
	}

	ret = sxe2_qos_qset_rem_qp(
		dev, qp->qp_common.qpn,
		vsi->qos[qp->user_pri].qset[qset_idx].qset_id);

	vsi->qos[qp->user_pri].qset[qset_idx].qset_qp_cnt--;
	list_del(&qp->list);
	qp->on_qoslist = false;
	vsi->qos[qp->user_pri].qp_cnt--;

	if (vsi->lag_aa) {
		qp->qset_idx ? atomic_dec(&vsi->port2_qp_cnt) :
			       atomic_dec(&vsi->port1_qp_cnt);
	}

unlock:
	mutex_unlock(&vsi->qos[qp->user_pri].qos_mutex);
end:
	return ret;
}

void sxe2_qos_remove_all_qset(struct sxe2_rdma_ctx_vsi *vsi)
{
	u8 i;

	for (i = 0; i < SXE2_MAX_UESER_PRIORITY; i++) {
		if (vsi->lag_aa)
			sxe2_qos_unregister_qset(vsi, i);
		else
			sxe2_qos_unregister_qset(vsi, i);
	}
}

static int sxe2_qos_qset_rebind_pf_tc(struct sxe2_rdma_device *rdma_dev,
				      struct sxe2_rdma_ctx_vsi *vsi,
				      u8 qset_idx, u8 pf_idx)
{
	int ret	    = 0;
	u8 user_pri = 0;

	for (user_pri = 0; user_pri < SXE2_MAX_USER_PRIORITY; user_pri++) {
		if (!vsi->qos[user_pri].valid)
			continue;

		ret = sxe2_qos_qset_bind_pf_tc(
			vsi, vsi->qos[user_pri].qset[qset_idx].qset_id,
			vsi->qos[user_pri].qset[qset_idx].traffic_class, true,
			pf_idx);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR("qset bind tc err, ret %d\n", ret);
			goto end;
		}
	}

end:
	return ret;
}

static int sxe2_qos_qset_node_move(struct sxe2_rdma_device *rdma_dev,
				   struct sxe2_rdma_ctx_vsi *vsi)
{
	int ret	    = 0;
	u8 qset_idx = 0;
	u8 pf_idx   = 0;

	mutex_lock(&vsi->dev->lag_mutex);

	DRV_RDMA_LOG_DEV_DEBUG(
		"qset node move, lag_port_bitmap %d, primary_port_migrated %d,\n"
		"\tsecondary_port_migrated %d.\n",
		vsi->lag_port_bitmap, vsi->primary_port_migrated,
		vsi->secondary_port_migrated);

	if ((vsi->lag_port_bitmap & SXE2_RDMA_BOTH_PF) == SXE2_RDMA_BOTH_PF) {
		if (vsi->primary_port_migrated == true) {
			vsi->primary_port_migrated = false;
			qset_idx		   = QOS_QSET_IDX_0;
			pf_idx			   = QOS_MAX_PORT_NUM_LAG_0;
			ret = sxe2_qos_qset_rebind_pf_tc(rdma_dev, vsi,
							 qset_idx, pf_idx);
		}

		else if (vsi->secondary_port_migrated == true) {
			vsi->secondary_port_migrated = false;
			qset_idx = QOS_QSET_IDX_1;
			pf_idx	 = QOS_MAX_PORT_NUM_LAG_1;
			ret	 = sxe2_qos_qset_rebind_pf_tc(rdma_dev, vsi,
							      qset_idx, pf_idx);
		}
	} else if (vsi->lag_port_bitmap == SXE2_RDMA_PF1) {
		if (vsi->primary_port_migrated == false) {
			vsi->primary_port_migrated = true;
			qset_idx		   = QOS_QSET_IDX_0;
			pf_idx			   = QOS_MAX_PORT_NUM_LAG_1;
			ret = sxe2_qos_qset_rebind_pf_tc(rdma_dev, vsi,
							 qset_idx, pf_idx);
		}

		if (vsi->secondary_port_migrated == true) {
			vsi->secondary_port_migrated = false;
			qset_idx = QOS_QSET_IDX_1;
			pf_idx	 = QOS_MAX_PORT_NUM_LAG_1;
			ret	 = sxe2_qos_qset_rebind_pf_tc(rdma_dev, vsi,
							      qset_idx, pf_idx);
		}
	} else if (vsi->lag_port_bitmap == SXE2_RDMA_PF0) {
		if (vsi->primary_port_migrated == true) {
			vsi->primary_port_migrated = false;
			qset_idx		   = QOS_QSET_IDX_0;
			pf_idx			   = QOS_MAX_PORT_NUM_LAG_0;
			ret = sxe2_qos_qset_rebind_pf_tc(rdma_dev, vsi,
							 qset_idx, pf_idx);
		}

		if (vsi->secondary_port_migrated == false) {
			vsi->secondary_port_migrated = true;
			qset_idx = QOS_QSET_IDX_1;
			pf_idx	 = QOS_MAX_PORT_NUM_LAG_0;
			ret	 = sxe2_qos_qset_rebind_pf_tc(rdma_dev, vsi,
							      qset_idx, pf_idx);
		}
	}

	mutex_unlock(&vsi->dev->lag_mutex);
	return ret;
}

static int sxe2_qos_qset_node_failover(struct sxe2_rdma_device *rdma_dev,
				       struct sxe2_rdma_ctx_vsi *vsi)
{
	int ret		= 0;
	u8 user_pri	= 0;
	int active_port = 0;
	u8 dest_tc = 0;
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;

	if (vsi->lag_port_bitmap == SXE2_RDMA_PF0) {
		active_port = QOS_MAX_PORT_NUM_LAG_0;
	} else if (vsi->lag_port_bitmap == SXE2_RDMA_PF1) {
		active_port = QOS_MAX_PORT_NUM_LAG_1;
	} else {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("qos: lag_port_bitmap %d, ret=%d\n",
				     vsi->lag_port_bitmap, ret);
	}

	for (user_pri = 0; user_pri < SXE2_MAX_USER_PRIORITY; user_pri++) {
		if (!vsi->qos[user_pri].valid)
			continue;
		dest_tc = cdev_info->qos_info[active_port].up2tc[user_pri];
		ret = sxe2_qos_qset_bind_pf_tc(
			vsi, vsi->qos[user_pri].qset[QOS_QSET_IDX_0].qset_id,
			dest_tc, true, active_port);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("qos:qset bind pf tc err ret=%d\n",
					     ret);
			goto end;
		}
	}

end:
	return ret;
}

void sxe2_rdma_qos_failover_complete(struct sxe2_rdma_device *rdma_dev)
{
	int ret = 0;

	if (rdma_dev->vsi.lag_aa) {
		ret = sxe2_qos_qset_node_move(rdma_dev, &rdma_dev->vsi);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"qos:lag_aa move qset err ret=%d\n", ret);
		}
	} else {
		ret = sxe2_qos_qset_node_failover(rdma_dev, &rdma_dev->vsi);
		if (ret)
			DRV_RDMA_LOG_DEV_ERR("qos:move qset err ret=%d\n", ret);
	}
}

void sxe2_rdma_update_qos_info(struct sxe2_rdma_ctx_vsi *vsi,
			       struct sxe2_rdma_l2params *l2p)
{
	u8 i;
	u8 index;

	for (index = 0; index < QOS_MAX_QSET_NUM_PER_USER_PRI; index++) {
		vsi->qos_rel_bw[index]	   = l2p[index].vsi_rel_bw;
		vsi->qos_prio_type[index] = l2p[index].vsi_prio_type;
		vsi->dscp_mode[index]	   = l2p[index].dscp_mode;
		if (l2p[index].dscp_mode)
			memcpy(vsi->dscp_map[index],
				l2p[index].dscp_map, sizeof(vsi->dscp_map[index]));

		for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
			vsi->qos[i].qset[index].traffic_class = l2p[index].up2tc[i];
			vsi->qos[i].rel_bw[index] =
				l2p[index].tc_info[vsi->qos[i].qset[index].traffic_class].rel_bw;
			vsi->qos[i].prio_type[index] =
				l2p[index].tc_info[vsi->qos[i].qset[index].traffic_class].prio_type;
		}
	}

}

void sxe2_rdma_qos_remove_qsets(struct sxe2_rdma_ctx_vsi *vsi, bool *change_list,
								struct sxe2_rdma_l2params *l2params)
{
	u8 i;
	bool up2tc_changed;

	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
		if (vsi->lag_aa)
			up2tc_changed =
				(vsi->qos[i].qset[0].traffic_class != l2params[0].up2tc[i]) ||
				(vsi->qos[i].qset[1].traffic_class != l2params[1].up2tc[i]);
		else
			up2tc_changed =
				vsi->qos[i].qset[0].traffic_class != l2params[0].up2tc[i];

		mutex_lock(&vsi->qos[i].qos_mutex);
		if (!vsi->qos[i].valid || !up2tc_changed) {
			mutex_unlock(&vsi->qos[i].qos_mutex);
			change_list[i] = false;
			continue;
		}
		change_list[i] = true;
		if (vsi->qos[i].valid) {
			if (vsi->lag_aa)
				vsi->unregister_qsets(
					vsi, &vsi->qos[i].qset[QOS_QSET_IDX_0],
					&vsi->qos[i].qset[QOS_QSET_IDX_1]);
			else
				vsi->unregister_qsets(vsi, &vsi->qos[i].qset[0], NULL);
		}
		mutex_unlock(&vsi->qos[i].qos_mutex);
	}
}

void sxe2_rdma_qos_add_qsets(struct sxe2_rdma_ctx_vsi *vsi, bool *change_list,
								struct sxe2_rdma_l2params *l2params)
{
	u8 i;
	int ret;
	struct sxe2_rdma_ctx_dev *dev		 = vsi->dev;
	struct sxe2_rdma_device *rdma_dev	 = to_rdmadev(dev);
	u8 active_pf = 0;
	u8 active_pf_tc = 0;

	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
		if (!change_list[i])
			continue;

		mutex_lock(&vsi->qos[i].qos_mutex);
		if (vsi->lag_aa) {
			ret = vsi->register_qsets(vsi, &vsi->qos[i].qset[QOS_QSET_IDX_0],
					&vsi->qos[i].qset[QOS_QSET_IDX_1]);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"qos:lan register qset node err ret=%d\n", ret);
				vsi->qos[i].qset[QOS_QSET_IDX_0].register_flag = false;
				vsi->qos[i].qset[QOS_QSET_IDX_1].register_flag = false;
				mutex_unlock(&vsi->qos[i].qos_mutex);
				continue;
			}
			ret = sxe2_qos_qset_bind_pf_tc_bond(
				vsi, vsi->qos[i].qset[QOS_QSET_IDX_0].qset_id,
				vsi->qos[i].qset[QOS_QSET_IDX_1].qset_id,
				vsi->qos[i].qset[QOS_QSET_IDX_0].traffic_class,
				vsi->qos[i].qset[QOS_QSET_IDX_1].traffic_class,
				true, vsi->qos[i].qset[QOS_QSET_IDX_0].pf_id,
				vsi->qos[i].qset[QOS_QSET_IDX_1].pf_id);
			if (ret != SXE2_OK) {
				vsi->qos[i].qset[QOS_QSET_IDX_0].register_flag = false;
				vsi->qos[i].qset[QOS_QSET_IDX_1].register_flag = false;
			}
		} else {
			ret = vsi->register_qsets(vsi, &vsi->qos[i].qset[0],
						NULL);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"qos:lan register qset node err ret=%d\n",
					ret);
				vsi->qos[i].qset[0].register_flag = false;
				mutex_unlock(&vsi->qos[i].qos_mutex);
				continue;
			}
			if (vsi->lag_backup) {
				active_pf = vsi->qos[i].qset[0].pf_id;
				active_pf_tc = vsi->qos[i].qset[active_pf].traffic_class;
				ret = sxe2_qos_qset_bind_pf_tc(
					vsi, vsi->qos[i].qset[0].qset_id,
					active_pf_tc,
					vsi->dev->privileged,
					vsi->qos[i].qset[0].pf_id);
			} else {
				ret = sxe2_qos_qset_bind_pf_tc(
					vsi, vsi->qos[i].qset[0].qset_id,
					vsi->qos[i].qset[0].traffic_class,
					vsi->dev->privileged,
					rdma_dev->rdma_func->pf_id);
			}

			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"qos:qset bind pf(%u) tc(%u) err ret=%d\n",
					rdma_dev->rdma_func->pf_id,
					vsi->qos[i].qset[0].traffic_class, ret);
				vsi->qos[i].qset[0].register_flag = false;
			}
		}
		mutex_unlock(&vsi->qos[i].qos_mutex);
	}
}

void sxe2_rdma_qos_move_qset(struct sxe2_rdma_ctx_vsi *vsi,
			     struct sxe2_rdma_l2params *l2params)
{
	bool change_list[SXE2_MAX_USER_PRIORITY] = {};

	sxe2_rdma_qos_remove_qsets(vsi, change_list, l2params);

	sxe2_rdma_update_qos_info(vsi, l2params);

	sxe2_rdma_qos_add_qsets(vsi, change_list, l2params);
}
