// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_event.h"
#include "roce_event_extension.h"
#include "roce_pub_cmd.h"
#include "hinic3_mt.h"

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

static void roce3_event_report_common_a(const struct roce3_device *rdev, int event_str_index)
{
	switch (event_str_index) {
	case OFED_ET_PATH_MIG:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Path mig. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case OFED_ET_COMM_EST:
		/*lint -e160 -e522*/
		roce3_pr_err_once("[ROCE] %s: [ofed event type] Communication establish. function id: %u\n",
			__func__, rdev->glb_func_id);
		/*lint +e160 +e522*/
		break;

	case OFED_ET_SQ_DRAINED:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Sq drained. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case OFED_ET_SRQ_QP_LAST_WQE:
		/*lint -e160 -e522*/
		roce3_pr_err_once("[ROCE] %s: [ofed event type] Srq/qp last wqe. function id: %u\n",
			__func__, rdev->glb_func_id);
		/*lint +e160 +e522*/
		break;

	case OFED_ET_WQ_CATAS_ERR:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Wq catas error. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case OFED_ET_PATH_MIG_FAILED:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Path mig failed. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;
	default:
		break;
	}
}

static void roce3_event_report_common_b(const struct roce3_device *rdev, int event_str_index)
{
	switch (event_str_index) {
	case OFED_ET_WQ_INVAL_REQ_ERR:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Wq inval req error. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case OFED_ET_WQ_ACCESS_ERR:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Wq access error. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case OFED_ET_CQ_ERR:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Cq error. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case OFED_ET_SRQ_LIMIT:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Srq limit. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case OFED_ET_SRQ_CATAS_ERR:
		pr_err_ratelimited("[ROCE] %s: [ofed event type] Srq catas error. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case NON_OFED_ET_QPC_LOOKUP_ERR:
		pr_err_ratelimited("[ROCE] %s: [non ofed event type] Qpc lookup error. function id: %u\n",
			__func__, rdev->glb_func_id);
		break;

	case NON_OFED_ET_OTHER_TYPE_ERR:
		/*lint -e160 -e522*/
		roce3_pr_err_once("[ROCE] %s: [non ofed event type] other type error. function id: %u\n",
			__func__, rdev->glb_func_id);
		/*lint +e160 +e522*/
		break;
	default:
		break;
	}
}

static void roce3_event_report_common(const struct roce3_device *rdev, int event_str_index)
{
	if (event_str_index <= OFED_ET_PATH_MIG_FAILED)
		roce3_event_report_common_a(rdev, event_str_index);
	else
		roce3_event_report_common_b(rdev, event_str_index);
}

/*
 ****************************************************************************
 Prototype	: roce3_event_report
 Description  : roce3_event_report
 Input		: struct roce3_device *rdev
				int event_str_index
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static void roce3_event_report(struct roce3_device *rdev, int event_str_index)
{
	if (event_str_index <= NON_OFED_ET_OTHER_TYPE_ERR)
		roce3_event_report_common(rdev, event_str_index);
	else
		roce3_event_report_extend(rdev, event_str_index);
}

/*
 ****************************************************************************
 Prototype	: to_qp_event_str_index
 Description  : to_qp_event_str_index
 Input		: u8 event_type
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int to_qp_event_str_index(u8 event_type)
{
	switch (event_type) {
	case ROCE_EVENT_TYPE_PATH_MIG:
		return OFED_ET_PATH_MIG;

	case ROCE_EVENT_TYPE_COMM_EST:
		return OFED_ET_COMM_EST;

	case ROCE_EVENT_TYPE_SQ_DRAINED:
		return OFED_ET_SQ_DRAINED;

	case ROCE_EVENT_TYPE_SRQ_QP_LAST_WQE:
		return OFED_ET_SRQ_QP_LAST_WQE;

	case ROCE_EVENT_TYPE_WQ_CATAS_ERROR:
		return OFED_ET_WQ_CATAS_ERR;

	case ROCE_EVENT_TYPE_PATH_MIG_FAILED:
		return OFED_ET_PATH_MIG_FAILED;

	case ROCE_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
		return OFED_ET_WQ_INVAL_REQ_ERR;

	default:
		return OFED_ET_WQ_ACCESS_ERR;
	}
}

int to_unknown_event_str_index(u8 event_type, const u8 *val)
{
	switch (event_type) {
	case ROCE_EVENT_TYPE_OFED_NO_DEF:
		if (*((u64 *)val) == QPC_LOOKUP_ERR_VALUE)
			return NON_OFED_ET_QPC_LOOKUP_ERR;

		return NON_OFED_ET_OTHER_TYPE_ERR;

	case ROCE_EVENT_TYPE_LOCAL_CATAS_ERROR:
		return NON_OFED_ET_OTHER_TYPE_ERR;

	default:
		return INVAL_ET_ERR;
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_handle_qp_async_event
 Description  : roce3_handle_qp_async_event
 Input		: struct roce3_device *rdev
				u32 qpn
				u8 event_type
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static void roce3_handle_qp_async_event(struct roce3_device *rdev, u32 qpn, u8 event_type)
{
	struct roce3_qp *rqp = NULL;
	struct tag_cqm_object *cqm_obj_queue = NULL;

	cqm_obj_queue = cqm_object_get(rdev->hwdev, CQM_OBJECT_SERVICE_CTX, qpn, false);
	if (cqm_obj_queue == NULL) {
		dev_err_ratelimited(rdev->hwdev_hdl,
			"[ROCE] %s: Failed to get cqm obj queue, func_id(%d), qpn:%u, event_type:%u\n",
			__func__, rdev->glb_func_id, qpn, event_type);
		return;
	}

	rqp = cqmobj_to_roce_qp(cqm_obj_queue);
	roce3_qp_async_event(rdev, rqp, (int)event_type);
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_queue);
}

/*
 ****************************************************************************
 Prototype	: roce3_handle_cq_async_event
 Description  : roce3_handle_cq_async_event
 Input		: struct roce3_device *rdev
				u32 cqn
				u8 event_type
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static void roce3_handle_cq_async_event(struct roce3_device *rdev, u32 cqn, u8 event_type)
{
	struct roce3_cq *rcq = NULL;
	struct tag_cqm_object *cqm_obj_queue = NULL;

	cqm_obj_queue = cqm_object_get(rdev->hwdev, CQM_OBJECT_RDMA_SCQ, cqn, false);
	if (cqm_obj_queue == NULL) {
		dev_err_ratelimited(rdev->hwdev_hdl,
			"[ROCE] %s: Failed to get cqm obj queue, func_id(%d), cqn:%u, event_type:%u\n",
			__func__, rdev->glb_func_id, cqn, event_type);
		return;
	}

	rcq = cqmobj_to_roce3_cq(cqm_obj_queue);
	roce3_cq_async_event(rdev, rcq, (int)event_type);
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_queue);
}

/*
 ****************************************************************************
 Prototype	: roce3_handle_srq_async_event
 Description  : roce3_handle_srq_async_event
 Input		: struct roce3_device *rdev
				u32 srqn
				u8 event_type
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static void roce3_handle_srq_async_event(struct roce3_device *rdev, u32 srqn, u8 event_type)
{
	struct roce3_srq *rsrq = NULL;
	struct tag_cqm_object *cqm_obj_queue = NULL;

	cqm_obj_queue = cqm_object_get(rdev->hwdev, CQM_OBJECT_RDMA_SRQ, srqn, false);
	if (cqm_obj_queue == NULL) {
		dev_err_ratelimited(rdev->hwdev_hdl,
			"[ROCE] %s: Failed to get cqm obj queue, func_id(%d), srqn:%u, event_type:%u\n",
			__func__, rdev->glb_func_id, srqn, event_type);
		return;
	}

	rsrq = cqmobj_to_roce3_srq(cqm_obj_queue);
	roce3_srq_async_event(rdev, rsrq, (int)event_type);
	hiudk_cqm_object_put(rdev->hwdev, cqm_obj_queue);
}

static bool roce3_async_event_need_reset(u8 event_status)
{
	if ((event_status == API_FORMAT_ERROR) || (event_status == UNKNOWN_RESERVED_ERROR1))
		return true;

	return false;
}

u8 roce3_async_event_level(void *svc_hd, u8 event_type, u8 *val)
{
	u8 event_level = FAULT_LEVEL_MAX;
	u8 event_status;
	u64 param = *((u64 *)val);

	if (svc_hd == NULL) {
		pr_err("[ROCE, ERR] %s: Svc_hd is null\n", __func__);
		return FAULT_LEVEL_SUGGESTION;
	}

	event_status = param & 0xff;

	switch (event_type) {
	case ROCE_EVENT_TYPE_PATH_MIG:
	case ROCE_EVENT_TYPE_COMM_EST:
	case ROCE_EVENT_TYPE_SQ_DRAINED:
	case ROCE_EVENT_TYPE_SRQ_QP_LAST_WQE:
	case ROCE_EVENT_TYPE_SRQ_LIMIT:
	case ROCE_EVENT_TYPE_PORT_MNG_CHG_EVENT:
	case ROCE_EVENT_TYPE_PORT_CHANGE:
	case ROCE_EVENT_TYPE_ECC_DETECT:
	case ROCE_EVENT_TYPE_CMD:
	case ROCE_EVENT_TYPE_COMM_CHANNEL:
	case ROCE_EVENT_TYPE_OP_REQUIRED:
		event_level = FAULT_LEVEL_SUGGESTION;
		break;

	case ROCE_EVENT_TYPE_LOCAL_CATAS_ERROR:
	case ROCE_EVENT_TYPE_WQ_INVAL_REQ_ERROR: // ROCE_AEQE_EVENT_QP_REQ_ERR
		if (event_status == API_FORMAT_ERROR)
			return FAULT_LEVEL_SERIOUS_RESET;
		break;

	case ROCE_EVENT_TYPE_WQ_CATAS_ERROR: // ROCE_AEQE_EVENT_WQE_CATAS
		if (roce3_async_event_need_reset(event_status))
			return FAULT_LEVEL_SERIOUS_RESET;
		break;

	case ROCE_EVENT_TYPE_CQ_ERROR: // CQ ERR
		if (roce3_async_event_need_reset(event_status))
			return FAULT_LEVEL_SERIOUS_RESET;
		break;

	default:
		event_level = FAULT_LEVEL_GENERAL;
		break;
	}

	return event_level;
}

static int roce3_async_event_handle_common(u8 event_type, u8 *val, struct roce3_device *rdev)
{
	u32 xid = 0;
	int event_str_index = 0;

	switch (event_type) {
	case ROCE_EVENT_TYPE_PATH_MIG:
	case ROCE_EVENT_TYPE_COMM_EST:
	case ROCE_EVENT_TYPE_SQ_DRAINED:
	case ROCE_EVENT_TYPE_SRQ_QP_LAST_WQE:
	case ROCE_EVENT_TYPE_WQ_CATAS_ERROR:
	case ROCE_EVENT_TYPE_PATH_MIG_FAILED:
	case ROCE_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
	case ROCE_EVENT_TYPE_WQ_ACCESS_ERROR:
		xid = *((u32 *)val);
		roce3_handle_qp_async_event(rdev, xid, event_type);
		event_str_index = to_qp_event_str_index(event_type);
		break;

	case ROCE_EVENT_TYPE_CQ_ERROR:
		xid = *((u32 *)val);
		roce3_handle_cq_async_event(rdev, xid, event_type);
		event_str_index = OFED_ET_CQ_ERR;
		break;

	case ROCE_EVENT_TYPE_SRQ_LIMIT:
		xid = *((u32 *)val);
		roce3_handle_srq_async_event(rdev, xid, event_type);
		event_str_index = OFED_ET_SRQ_LIMIT;
		break;

	case ROCE_EVENT_TYPE_SRQ_CATAS_ERROR:
		xid = *((u32 *)val);
		roce3_handle_srq_async_event(rdev, xid, event_type);
		event_str_index = OFED_ET_SRQ_CATAS_ERR;
		break;

	default:
		event_str_index = to_unknown_event_str_index(event_type, val);
		break;
	}

	return event_str_index;
}

/*
 ****************************************************************************
 Prototype	: roce3_async_event
 Description  : roce3_async_event
 Input		: void *svc_hd
				u8 event_type
				u64 val
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
void roce3_async_event(void *svc_hd, u8 event_type, u8 *val)
{
	int event_str_index = 0;
	struct roce3_device *rdev = NULL;

	if (svc_hd == NULL) {
		pr_err_ratelimited("[ROCE, ERR] %s: Svc_hd is null\n", __func__);
		return;
	}

	rdev = (struct roce3_device *)svc_hd;
	if (event_type <= ROCE_EVENT_TYPE_ODP_PAGE_FAULT)
		event_str_index = roce3_async_event_handle_common(event_type, val, rdev);
	else
		event_str_index = roce3_async_event_handle_extend(event_type, val, rdev);

	roce3_event_report(rdev, event_str_index);
}

static void roce3_handle_sq_hot_plug(struct roce3_qp *rqp, unsigned long flags_qp,
	struct list_head *cq_notify_list)
{
	struct roce3_cq *send_rcq = NULL;
	unsigned long flags_cq = 0;
	unsigned long flags_qp_tmp = flags_qp;

	spin_lock_irqsave(&rqp->sq.lock, flags_qp_tmp);
	if (rqp->sq.tail == rqp->sq.head)
		goto roce_sq_hot_plug_end;

	send_rcq = to_roce3_cq(rqp->ibqp.send_cq);
	spin_lock_irqsave(&send_rcq->lock, flags_cq);
	if (send_rcq->reset_flow_comp && rqp->ibqp.send_cq->comp_handler) {
		if (send_rcq->reset_notify_added == 0) {
			send_rcq->reset_notify_added = 1;
			list_add_tail(&send_rcq->reset_notify, cq_notify_list);
		}
	}
	spin_unlock_irqrestore(&send_rcq->lock, flags_cq);

roce_sq_hot_plug_end:
	spin_unlock_irqrestore(&rqp->sq.lock, flags_qp_tmp);
}

static void roce3_handle_rq_hot_plug(struct roce3_qp *rqp, unsigned long flags_qp,
	struct list_head *cq_notify_list)
{
	struct roce3_cq *recv_rcq = NULL;
	unsigned long flags_cq = 0;
	unsigned long flags_qp_tmp = flags_qp;

	spin_lock_irqsave(&rqp->rq.lock, flags_qp_tmp);
	/* no handling is needed for SRQ */
	if (rqp->ibqp.srq != NULL)
		goto roce_rq_hot_plug_end;
	else if (rqp->rq.tail == rqp->rq.head)
		goto roce_rq_hot_plug_end;

	recv_rcq = to_roce3_cq(rqp->ibqp.recv_cq);
	spin_lock_irqsave(&recv_rcq->lock, flags_cq);
	if (recv_rcq->reset_flow_comp && rqp->ibqp.recv_cq->comp_handler) {
		if (recv_rcq->reset_notify_added == 0) {
			recv_rcq->reset_notify_added = 1;
			list_add_tail(&recv_rcq->reset_notify, cq_notify_list);
		}
	}
	spin_unlock_irqrestore(&recv_rcq->lock, flags_cq);
roce_rq_hot_plug_end:
	spin_unlock_irqrestore(&rqp->rq.lock, flags_qp_tmp);
}

void roce3_handle_hotplug_arm_cq(struct roce3_device *rdev)
{
	struct roce3_qp *rqp = NULL;
	struct roce3_cq *rcq = NULL;
	unsigned long flags_qp = 0;
	unsigned long flags = 0;
	struct list_head cq_notify_list;

	pr_err("[ROCE, ERR] %s: Hotplug arm cq start:\n", __func__);

	INIT_LIST_HEAD(&cq_notify_list);

	/* Go over qp list reside on that rdev, sync with create/destroy qp */
	spin_lock_irqsave(&rdev->reset_flow_resource_lock, flags);
	list_for_each_entry(rqp, &rdev->qp_list, qps_list) {
		roce3_handle_sq_hot_plug(rqp, flags_qp, &cq_notify_list);
		roce3_handle_rq_hot_plug(rqp, flags_qp, &cq_notify_list);
	}

	list_for_each_entry(rcq, &cq_notify_list, reset_notify) {
		rcq->reset_flow_comp(rcq);
	}
	spin_unlock_irqrestore(&rdev->reset_flow_resource_lock, flags);

	pr_err("[ROCE, ERR] %s: Hotplug arm cq end!\n", __func__);
}

void roce3_kernel_hotplug_event_trigger(struct roce3_device *rdev)
{
	int carrier_ok = 0;

	if (rdev->ndev) {
		carrier_ok = netif_carrier_ok(rdev->ndev);
		if (carrier_ok != 0) {
			dev_info(rdev->hwdev_hdl, "[ROCE] %s: Turn off, func_id(%u), name(%s), pci(%s),\n",
				__func__, rdev->glb_func_id,
				rdev->ib_dev.name, pci_name(rdev->pdev));
			netif_carrier_off(rdev->ndev);
		}

		ROCE_MDELAY(ROCE_M_DELAY);
		return;
	}

	dev_info(rdev->hwdev_hdl, "[ROCE] %s: rdev->ndev is NULL\n", __func__);
}

#ifdef ROCE_BONDING_EN
void roce3_handle_bonded_port_state_event(struct roce3_device *rdev)
{
	struct net_device *master = netdev_master_upper_dev_get_rcu(rdev->ndev);
	enum ib_port_state bonded_port_state = IB_PORT_NOP;
	struct roce3_bond_device *bond_dev = NULL;
	enum ib_port_state curr_port_state;
	enum ib_event_type event;
	struct roce3_bond_slave *slave = NULL;
	int i;

	if (master == NULL)
		return;

	bond_dev = rdev->bond_dev;
	if (bond_dev == NULL) {
		pr_err("[ROCE, ERR] %s: No bond_dev found\n", __func__);
		return;
	}

	if (netif_running(master) != 0) {
		mutex_lock(&bond_dev->slave_lock);
		for (i = 0; i < bond_dev->slave_cnt; i++) {
			slave = &bond_dev->slaves[i];
			if (slave->netdev == NULL)
				continue;

			curr_port_state = (netif_running(slave->netdev) &&
				netif_carrier_ok(slave->netdev)) ?
				IB_PORT_ACTIVE :
				IB_PORT_DOWN;

			bonded_port_state = (bonded_port_state != IB_PORT_ACTIVE) ?
				curr_port_state : IB_PORT_ACTIVE;
		}
		mutex_unlock(&bond_dev->slave_lock);
	} else {
		bonded_port_state = IB_PORT_DOWN;
	}

	if (rdev->port_state != bonded_port_state) {
		event = (bonded_port_state == IB_PORT_ACTIVE) ?
			IB_EVENT_PORT_ACTIVE : IB_EVENT_PORT_ERR;
		if (roce3_ifconfig_up_down_event_report(rdev, event) != 0)
			return;
		rdev->port_state = bonded_port_state;
	}
}
#endif
