// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/slab.h>
#include <linux/sched.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_ctrlq.h>
#include "udma_cmd.h"
#include <ub/urma/udma/udma_ctl.h>
#include "udma_eq.h"
#include "udma_common.h"
#include "udma_ctrlq_tp.h"

static void udma_ctrlq_set_tp_msg(struct ubase_ctrlq_msg *msg, void *in,
				  uint16_t in_len, void *out, uint16_t out_len)
{
	msg->service_ver = UBASE_CTRLQ_SER_VER_01;
	msg->service_type = UBASE_CTRLQ_SER_TYPE_TP_ACL;
	msg->need_resp = 1;
	msg->is_resp = 0;
	msg->in_size = in_len;
	msg->in = in;
	msg->out_size = out_len;
	msg->out = out;
}

int udma_ctrlq_remove_single_tp(struct udma_dev *udev, uint32_t tpn, int status)
{
	struct udma_ctrlq_remove_single_tp_req_data tp_cfg_req = {};
	struct ubase_ctrlq_msg msg = {};
	int r_status = 0;
	int ret;

	tp_cfg_req.tpn = tpn;
	tp_cfg_req.tp_status = (uint32_t)status;
	msg.opcode = UDMA_CMD_CTRLQ_REMOVE_SINGLE_TP;
	udma_ctrlq_set_tp_msg(&msg, (void *)&tp_cfg_req,
			      sizeof(tp_cfg_req), &r_status, sizeof(int));

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret)
		dev_err(udev->dev, "remove single tp %u failed, ret %d status %d.\n",
			tpn, ret, r_status);

	return ret;
}

static void udma_notify_ue_tp_flush_done(struct udma_dev *udma_dev, uint8_t ue_idx)
{
#define UDMA_RETRY_TIMES 3
	struct udma_entity_buf ue_buf = {};
	int retry = 0;
	int ret;

	do {
		ret = udma_send_msg_to_ue(udma_dev, &ue_buf, ue_idx, UDMA_CMD_NOTIFY_UE_FLUSH_DONE);
	} while (ret != 0 && retry++ < UDMA_RETRY_TIMES);
	if (ret != 0)
		dev_err(udma_dev->dev, "notify ue %u tp flush done failed, ret %d.\n", ue_idx, ret);

	return;
}

static struct udma_ue_idx_table *udma_find_ue_idx_by_tpn(struct udma_dev *udev,
							 uint32_t tpn)
{
	struct udma_ue_idx_table *tp_ue_idx_info;

	xa_lock(&udev->tpn_ue_idx_table);
	tp_ue_idx_info = xa_load(&udev->tpn_ue_idx_table, tpn);
	if (!tp_ue_idx_info) {
		xa_unlock(&udev->tpn_ue_idx_table);

		return NULL;
	}

	__xa_erase(&udev->tpn_ue_idx_table, tpn);
	xa_unlock(&udev->tpn_ue_idx_table);

	return tp_ue_idx_info;
}

void udma_tp_ae_work(struct work_struct *work)
{
	struct udma_ae_work *ae_work = container_of(work, struct udma_ae_work, work);
	struct udma_ctrlq_tp_flush_done_req_data tp_cfg_req = {};
	struct udma_ue_idx_table *tp_ue_idx_info;
	struct udma_dev *udev = ae_work->udev;
	struct ubase_ctrlq_msg msg = {};
	int ret = 0;
	uint32_t i;

	tp_ue_idx_info = udma_find_ue_idx_by_tpn(udev, ae_work->tpn);
	if (tp_ue_idx_info) {
		for (i = 0; i < tp_ue_idx_info->num; i++)
			udma_notify_ue_tp_flush_done(udev, tp_ue_idx_info->ue_idx[i]);

		kfree(tp_ue_idx_info);
	} else {
		ret = udma_open_ue_rx_with_retry(udev, true, false, false, 0);
		if (ret)
			dev_warn(udev->dev, "udma open ue rx failed in tp ae work.\n");
	}

	tp_cfg_req.tpn = ae_work->tpn;
	msg.opcode = UDMA_CMD_CTRLQ_TP_FLUSH_DONE;
	udma_ctrlq_set_tp_msg(&msg, (void *)&tp_cfg_req, sizeof(tp_cfg_req), NULL, 0);
	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret)
		dev_err(udev->dev, "tp ae work ctrlq tp %u failed, ret %d.\n", ae_work->tpn, ret);

	kfree(ae_work);
}

int udma_ctrlq_tp_flush_done(struct udma_dev *udev, uint32_t tpn)
{
	struct udma_ctrlq_tp_flush_done_req_data tp_cfg_req = {};
	struct udma_ue_idx_table *tp_ue_idx_info;
	struct ubase_ctrlq_msg msg = {};
	int ret = 0;
	uint32_t i;

	tp_ue_idx_info = udma_find_ue_idx_by_tpn(udev, tpn);
	if (tp_ue_idx_info) {
		for (i = 0; i < tp_ue_idx_info->num; i++)
			udma_notify_ue_tp_flush_done(udev, tp_ue_idx_info->ue_idx[i]);

		kfree(tp_ue_idx_info);
	} else {
		ret = udma_open_ue_rx_with_retry(udev, true, false, false, 0);
		if (ret)
			dev_err(udev->dev, "udma open ue rx failed in tp flush done.\n");
	}

	tp_cfg_req.tpn = tpn;
	msg.opcode = UDMA_CMD_CTRLQ_TP_FLUSH_DONE;
	udma_ctrlq_set_tp_msg(&msg, (void *)&tp_cfg_req, sizeof(tp_cfg_req), NULL, 0);
	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret)
		dev_err(udev->dev, "tp flush done ctrlq tp %u failed, ret %d.\n", tpn, ret);

	return ret;
}

int udma_ctrlq_tpn_flush_done(struct udma_dev *dev, struct xarray *ctrlq_tpid_table,
			      uint32_t tp_id, bool is_udata)
{
	struct udma_ctrlq_tpid *tpid_entity;
	uint32_t tp_start;
	uint32_t tp_num;
	int ret = 0;
	uint32_t i;

	xa_lock(ctrlq_tpid_table);
	tpid_entity = xa_load(ctrlq_tpid_table, tp_id);
	if (tpid_entity == NULL) {
		xa_unlock(ctrlq_tpid_table);
		dev_err(dev->dev, "tpid_entity is NULL tp_id %u.\n", tp_id);
		return -EINVAL;
	}

	tp_start = tpid_entity->tpn_start;
	tp_num = tpid_entity->tpn_cnt;
	xa_unlock(ctrlq_tpid_table);

	for (i = 0; i < tp_num; i++) {
		ret = udma_ctrlq_tp_flush_done(dev, tp_start + i);
		if (ret != 0)
			dev_err(dev->dev, "tpn flush done failed tp_id %u tp_start %u tpn %u.\n",
				tp_id, tp_start, i);
	}

	return ret;
}

int udma_ctrlq_notify_tp_port_change(struct udma_dev *udev, uint32_t tpn)
{
	struct udma_ctrlq_tp_port_change_req_data tp_cfg_req = {};
	struct ubase_ctrlq_msg ctrlq_msg = {};
	int ret;

	tp_cfg_req.tpn = tpn;
	ctrlq_msg.opcode = UDMA_CMD_CTRLQ_TP_PORT_CHANGE;
	udma_ctrlq_set_tp_msg(&ctrlq_msg, (void *)&tp_cfg_req, sizeof(tp_cfg_req), NULL, 0);

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &ctrlq_msg);
	if (ret)
		dev_err(udev->dev, "multi-plane tp port change, tp %u failed, ret %d.\n", tpn, ret);

	return ret;
}

int udma_get_dev_resource_ratio(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev_resource_ratio dev_res = {};
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubase_ctrlq_msg ctrlq_msg = {};
	int ret = 0;

	if (udma_check_base_param(in->addr, in->len, sizeof(dev_res.index))) {
		dev_err(udev->dev, "parameter invalid in get dev res, len = %u.\n", in->len);
		return -EINVAL;
	}

	if (out->addr == 0) {
		dev_err(udev->dev, "get dev resource ratio, addr is NULL.\n");
		return -EINVAL;
	}

	memcpy(&dev_res.index, (void *)(uintptr_t)in->addr, sizeof(dev_res.index));

	ret = ubase_get_bus_eid(udev->comdev.adev, &dev_res.eid);
	if (ret) {
		dev_err(udev->dev, "get dev bus eid failed, ret is %d.\n", ret);
		return ret;
	}

	ctrlq_msg.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER;
	ctrlq_msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	ctrlq_msg.need_resp = 1;
	ctrlq_msg.in_size = sizeof(dev_res);
	ctrlq_msg.in = (void *)&dev_res;
	ctrlq_msg.out_size = out->len;
	ctrlq_msg.out = (void *)(uintptr_t)out->addr;
	ctrlq_msg.opcode = UDMA_CTRLQ_GET_DEV_RESOURCE_RATIO;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &ctrlq_msg);
	if (ret)
		dev_err(udev->dev, "get dev res send ctrlq msg failed, ret is %d.\n", ret);

	return ret;
}

static int udma_dev_res_ratio_ctrlq_handler(struct auxiliary_device *adev,
					    uint8_t service_ver, void *data,
					    uint16_t len, uint16_t seq)
{
	struct udma_dev *udev = (struct udma_dev *)get_udma_dev(adev);
	struct udma_ctrlq_event_nb *udma_cb;
	int ret;

	if (service_ver != UBASE_CTRLQ_SER_VER_01) {
		dev_err(udev->dev, "Unsupported server version (%u).\n", service_ver);
		return -EOPNOTSUPP;
	}

	mutex_lock(&udev->npu_nb_mutex);
	udma_cb = xa_load(&udev->npu_nb_table, UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO);
	if (!udma_cb) {
		dev_err(udev->dev, "failed to query npu info cb while xa_load.\n");
		mutex_unlock(&udev->npu_nb_mutex);
		return -EINVAL;
	}

	ret = udma_cb->crq_handler(&udev->ub_dev, data, len);
	if (ret)
		dev_err(udev->dev, "npu crq handler failed, ret = %d.\n", ret);
	mutex_unlock(&udev->npu_nb_mutex);

	return ret;
}

int udma_register_npu_cb(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			 struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct ubase_ctrlq_event_nb ubase_cb = {};
	struct udma_dev *udev = to_udma_dev(dev);
	struct udma_ctrlq_event_nb *udma_cb;
	int ret;

	if (udma_check_base_param(in->addr, in->len, sizeof(udma_cb->crq_handler))) {
		dev_err(udev->dev, "parameter invalid in register npu cb, len = %u.\n", in->len);
		return -EINVAL;
	}

	udma_cb = kzalloc(sizeof(*udma_cb), GFP_KERNEL);
	if (!udma_cb)
		return -ENOMEM;

	udma_cb->opcode = UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO;
	udma_cb->crq_handler = (void *)(uintptr_t)in->addr;

	mutex_lock(&udev->npu_nb_mutex);
	if (xa_load(&udev->npu_nb_table, UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO)) {
		dev_err(udev->dev, "query npu info callback exist.\n");
		ret = -EINVAL;
		goto err_release_udma_cb;
	}
	ret = xa_err(__xa_store(&udev->npu_nb_table, udma_cb->opcode, udma_cb, GFP_KERNEL));
	if (ret) {
		dev_err(udev->dev,
			"save crq nb entry failed, opcode is %u, ret is %d.\n",
			udma_cb->opcode, ret);
		goto err_release_udma_cb;
	}

	ubase_cb.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER;
	ubase_cb.opcode = UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO;
	ubase_cb.back = udev->comdev.adev;
	ubase_cb.crq_handler = udma_dev_res_ratio_ctrlq_handler;
	ret = ubase_ctrlq_register_crq_event(udev->comdev.adev, &ubase_cb);
	if (ret) {
		__xa_erase(&udev->npu_nb_table, UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO);
		dev_err(udev->dev, "ubase register npu crq event failed, ret is %d.\n", ret);
		goto err_release_udma_cb;
	}
	mutex_unlock(&udev->npu_nb_mutex);

	return 0;

err_release_udma_cb:
	mutex_unlock(&udev->npu_nb_mutex);
	kfree(udma_cb);
	return ret;
}

int udma_unregister_npu_cb(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			   struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct udma_ctrlq_event_nb *nb;

	ubase_ctrlq_unregister_crq_event(udev->comdev.adev,
					 UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
					 UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO);

	mutex_lock(&udev->npu_nb_mutex);
	nb = xa_load(&udev->npu_nb_table, UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO);
	if (!nb) {
		dev_warn(udev->dev, "query npu info cb not exist.\n");
		goto err_find_npu_nb;
	}

	__xa_erase(&udev->npu_nb_table, UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO);
	kfree(nb);
	nb = NULL;

err_find_npu_nb:
	mutex_unlock(&udev->npu_nb_mutex);
	return 0;
}

static int udma_ctrlq_get_trans_type(struct udma_dev *dev,
				     enum udma_link_mode mode,
				     enum ubcore_transport_mode trans_mode,
				     enum udma_ctrlq_trans_type *tp_type)
{
#define UDMA_TRANS_MODE_NUM 5
#define UDMA_LINK_MODE_NUM 2

struct udma_ctrlq_trans_map {
	bool is_valid;
	enum udma_ctrlq_trans_type tp_type;
};
	static struct udma_ctrlq_trans_map
		ctrlq_trans_map[UDMA_LINK_MODE_NUM][UDMA_TRANS_MODE_NUM] = {
			{
				{false, UDMA_CTRLQ_TRANS_TYPE_MAX},
				{true, UDMA_CTRLQ_TRANS_TYPE_TP_RM},
				{true, UDMA_CTRLQ_TRANS_TYPE_TP_RC},
				{false, UDMA_CTRLQ_TRANS_TYPE_MAX},
				{true, UDMA_CTRLQ_TRANS_TYPE_TP_UM},
			},
			{
				{false, UDMA_CTRLQ_TRANS_TYPE_MAX},
				{true, UDMA_CTRLQ_TRANS_TYPE_UBOE_RM},
				{true, UDMA_CTRLQ_TRANS_TYPE_UBOE_RC},
				{false, UDMA_CTRLQ_TRANS_TYPE_MAX},
				{true, UDMA_CTRLQ_TRANS_TYPE_UBOE_UM},
			},
	};
	uint8_t transport_mode = (uint8_t)trans_mode;

	if ((transport_mode < UDMA_TRANS_MODE_NUM) &&
	    (mode < UDMA_LINK_MODE_NUM) &&
	    ctrlq_trans_map[mode][transport_mode].is_valid) {
		*tp_type = ctrlq_trans_map[mode][transport_mode].tp_type;
		return 0;
	}

	dev_err(dev->dev, "the trans_mode %u is not support.\n", trans_mode);

	return -EINVAL;
}

static int udma_send_sync_msg_to_mue(struct udma_dev *udev,
				     struct udma_entity_buf *buf, uint32_t opcode)
{
#define UDMA_WAIT_RESP_TIME msecs_to_jiffies(500)

	struct udma_cmdq_wait_info *wait_completion_tmp = NULL;
	struct udma_cmdq_info *info = udev->wait_cmdq_info;
	struct udma_cmdq_wait_info wait_completion = {};
	struct udma_entity_msg *req_msg;
	struct ubase_cmd_buf in;
	uint32_t msg_len;
	int ret;

	msg_len = sizeof(*req_msg) + buf->len;
	req_msg = kzalloc(msg_len, GFP_KERNEL);
	if (!req_msg)
		return -ENOMEM;

	req_msg->opcode = opcode;
	mutex_lock(&info->seq_lock);
	buf->seq_num = ++info->seq_num;
	mutex_unlock(&info->seq_lock);

	init_completion(&wait_completion.ret_completion);

	xa_lock(&info->seq_tbl);
	ret = xa_err(__xa_store(&info->seq_tbl, buf->seq_num, &wait_completion, GFP_ATOMIC));
	xa_unlock(&info->seq_tbl);
	if (ret) {
		dev_err(udev->dev, "save resp completion failed, ret = %d.\n", ret);
		goto post_process;
	}

	(void)memcpy(&req_msg->buf, buf, sizeof(*buf));
	(void)memcpy(req_msg->buf.data, buf->data, buf->len);
	udma_fill_buf(&in, UBASE_OPC_UE_TO_MUE, false, msg_len, req_msg);
	ret = ubase_cmd_send_in(udev->comdev.adev, &in);
	if (ret) {
		xa_erase(&info->seq_tbl, buf->seq_num);
		dev_err(udev->dev, "send req msg cmd failed, ret is %d.\n", ret);
		goto post_process;
	}

	if (!wait_for_completion_timeout(&wait_completion.ret_completion, UDMA_WAIT_RESP_TIME)) {
		dev_err(udev->dev, "wait resp timeout, seq = %u.\n", buf->seq_num);
		ret = -ETIMEDOUT;
	} else {
		ret = wait_completion.ret;
	}

	xa_lock(&info->seq_tbl);
	wait_completion_tmp = xa_load(&info->seq_tbl, buf->seq_num);
	if (wait_completion_tmp)
		__xa_erase(&info->seq_tbl, buf->seq_num);
	xa_unlock(&info->seq_tbl);

post_process:
	kfree(req_msg);

	return ret;
}

int udma_send_resp_to_ue(struct udma_dev *udev,
			 struct udma_entity_msg *req, int ret_val, uint16_t opcode)
{
	struct udma_entity_buf *msg_buf;
	int msg_len;
	int ret;

	msg_len = sizeof(*msg_buf) + sizeof(ret_val);
	msg_buf = kzalloc(msg_len, GFP_KERNEL);
	if (!msg_buf)
		return -ENOMEM;

	msg_buf->seq_num = req->buf.seq_num;
	msg_buf->len = sizeof(ret_val);
	(void)memcpy(msg_buf->data, (uint8_t *)&ret_val, sizeof(ret_val));

	ret = udma_send_msg_to_ue(udev, msg_buf, req->dst_ue_idx, opcode);
	if (ret)
		dev_err(udev->dev, "send resp msg cmd failed, ret is %d.\n", ret);

	kfree(msg_buf);

	return ret;
}

int udma_recv_resp_from_mue(struct udma_dev *udev,
			    struct udma_entity_msg *resp, uint32_t len)
{
	struct udma_cmdq_info *info = udev->wait_cmdq_info;
	struct udma_cmdq_wait_info *wait_completion;

	xa_lock(&info->seq_tbl);
	wait_completion = xa_load(&info->seq_tbl, resp->buf.seq_num);
	if (!wait_completion) {
		xa_unlock(&info->seq_tbl);
		dev_err(udev->dev, "seq_num of crq resp is invalid, seq_num = %u.\n",
				resp->buf.seq_num);
		return -EINVAL;
	}

	if (resp->buf.len != sizeof(wait_completion->ret)) {
		xa_unlock(&info->seq_tbl);
		dev_err(udev->dev, "len of data in crq resp is invalid, len = %u.\n",
				resp->buf.len);
		return -EINVAL;
	}

	__xa_erase(&info->seq_tbl, resp->buf.seq_num);
	wait_completion->ret = *(int *)(resp->buf.data);
	complete(&wait_completion->ret_completion);
	xa_unlock(&info->seq_tbl);

	return 0;
}

void udma_notify_mue_delete_guid(struct udma_dev *dev)
{
	struct udma_entity_buf *ue_buf;
	int ret;

	ue_buf = kzalloc(sizeof(*ue_buf), GFP_KERNEL);
	if (!ue_buf)
		return;

	ue_buf->len = 0;
	ret = udma_send_sync_msg_to_mue(dev, ue_buf, UDMA_CMD_NOTIFY_MUE_DELETE_GUID);
	if (ret)
		dev_err(dev->dev, "fail to notify mue delete guid, ret %d.\n", ret);

	kfree(ue_buf);
}

static int udma_notify_mue_save_tp(struct udma_dev *dev, union ubcore_tp_handle *tp_handle)
{
	uint32_t data_len = (uint32_t)sizeof(struct udma_ue_tp_info);
	struct udma_entity_buf *ue_buf;
	struct udma_ue_tp_info *data;
	int ret;

	ue_buf = kzalloc(sizeof(*ue_buf) + data_len, GFP_KERNEL);
	if (!ue_buf)
		return -ENOMEM;

	data = (struct udma_ue_tp_info *)ue_buf->data;
	data->start_tpn = tp_handle->bs.tpn_start;
	data->tp_cnt = tp_handle->bs.tp_cnt;
	ue_buf->len = data_len;

	ret = udma_send_sync_msg_to_mue(dev, ue_buf, UDMA_CMD_NOTIFY_MUE_SAVE_TP);
	if (ret)
		dev_err(dev->dev, "fail to notify mue save tp, ret %d.\n", ret);

	kfree(ue_buf);

	return ret;
}

static int udma_ctrlq_get_tpid_list(struct udma_dev *udev,
				    struct udma_ctrlq_get_tp_list_req_data *tp_cfg_req,
				    struct ubcore_get_tp_cfg *tpid_cfg,
				    struct udma_ctrlq_tpid_list_rsp *tpid_list_resp)
{
	enum udma_ctrlq_trans_type trans_type;
	struct ubase_ctrlq_msg msg = {};
	enum udma_link_mode link_mode;
	int ret;

	link_mode = tpid_cfg->flag.bs.uboe ? UDMA_LINK_MODE_UBOE : UDMA_LINK_MODE_UB;
	if (tpid_cfg->flag.bs.ctp) {
		tp_cfg_req->trans_type = UDMA_CTRLQ_TRANS_TYPE_CTP;
	} else {
		if (udma_ctrlq_get_trans_type(udev, link_mode, tpid_cfg->trans_mode, &trans_type)) {
			dev_err(udev->dev, "udma get ctrlq trans_type failed, trans_mode = %d.\n",
				tpid_cfg->trans_mode);
			return -EINVAL;
		}
		tp_cfg_req->trans_type = (uint32_t)trans_type;
	}

	udma_swap_endian(tpid_cfg->local_eid.raw, tp_cfg_req->seid,
			 UDMA_EID_SIZE);
	udma_swap_endian(tpid_cfg->peer_eid.raw, tp_cfg_req->deid,
			 UDMA_EID_SIZE);

	udma_ctrlq_set_tp_msg(&msg, (void *)tp_cfg_req, sizeof(*tp_cfg_req),
			      (void *)tpid_list_resp, sizeof(*tpid_list_resp));
	msg.opcode = UDMA_CMD_CTRLQ_GET_TP_LIST;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret)
		dev_err(udev->dev, "ctrlq send msg failed, ret = %d.\n", ret);

	return ret;
}

int udma_get_tp_list(struct ubcore_device *dev, struct ubcore_get_tp_cfg *tpid_cfg,
		     uint32_t *tp_cnt, struct ubcore_tp_info *tp_list,
		     struct ubcore_udata *udata)
{
	struct udma_ctrlq_get_tp_list_req_data tp_cfg_req = {};
	struct udma_ctrlq_tpid_list_rsp tpid_list_resp = {};
	struct udma_dev *udev = to_udma_dev(dev);
	uint32_t i;
	int ret;

	if (current->flags & PF_KTHREAD)
		tp_cfg_req.flag = UDMA_DEFAULT_PID;
	else
		tp_cfg_req.flag = (uint32_t)current->tgid & UDMA_PID_MASK;

	ret = udma_ctrlq_get_tpid_list(udev, &tp_cfg_req, tpid_cfg, &tpid_list_resp);
	if (ret) {
		dev_err(udev->dev, "udma ctrlq get tpid list failed, ret = %d.\n", ret);
		return ret;
	}

	if (tpid_list_resp.tp_list_cnt == 0 || tpid_list_resp.tp_list_cnt > *tp_cnt) {
		dev_err(udev->dev,
			"check tp list count failed, count = %u.\n",
			tpid_list_resp.tp_list_cnt);
		return -EINVAL;
	}

	for (i = 0; i < tpid_list_resp.tp_list_cnt; i++) {
		tp_list[i].tp_handle.bs.tpid = tpid_list_resp.tpid_list[i].tpid;
		tp_list[i].tp_handle.bs.tpn_start = tpid_list_resp.tpid_list[i].tpn_start;
		tp_list[i].tp_handle.bs.tp_cnt =
			tpid_list_resp.tpid_list[i].tpn_cnt & UDMA_TPN_CNT_MASK;
	}
	*tp_cnt = tpid_list_resp.tp_list_cnt;

	return ret;
}

void udma_ctrlq_destroy_tpid_list(struct xarray *ctrlq_tpid_table)
{
	struct udma_ctrlq_tpid *tpid_entity = NULL;
	unsigned long tpid = 0;

	xa_lock(ctrlq_tpid_table);
	if (!xa_empty(ctrlq_tpid_table)) {
		xa_for_each(ctrlq_tpid_table, tpid, tpid_entity) {
			__xa_erase(ctrlq_tpid_table, tpid);
			kfree(tpid_entity);
		}
	}
	xa_unlock(ctrlq_tpid_table);
	xa_destroy(ctrlq_tpid_table);
}

static int udma_k_ctrlq_create_active_tp_msg(struct udma_dev *udev,
					     struct ubcore_active_tp_cfg *active_cfg,
					     uint32_t *tp_id)
{
	struct udma_ctrlq_active_tp_resp_data active_tp_resp = {};
	struct udma_ctrlq_active_tp_req_data active_tp_req = {};
	struct ubase_ctrlq_msg msg = {};
	int ret;

	active_tp_req.local_tp_id = active_cfg->tp_handle.bs.tpid;
	active_tp_req.local_tpn_cnt = active_cfg->tp_handle.bs.tp_cnt;
	active_tp_req.local_tpn_start = active_cfg->tp_handle.bs.tpn_start;
	active_tp_req.local_psn = active_cfg->tp_attr.tx_psn;

	active_tp_req.remote_tp_id = active_cfg->peer_tp_handle.bs.tpid;
	active_tp_req.remote_tpn_cnt = active_cfg->peer_tp_handle.bs.tp_cnt;
	active_tp_req.remote_tpn_start = active_cfg->peer_tp_handle.bs.tpn_start;
	active_tp_req.remote_psn = active_cfg->tp_attr.rx_psn;

	if (debug_switch)
		udma_dfx_ctx_print(udev, "udma create active tp msg info",
				   active_tp_req.local_tp_id,
				   sizeof(struct udma_ctrlq_active_tp_req_data) / sizeof(uint32_t),
				   (uint32_t *)&active_tp_req);

	msg.opcode = UDMA_CMD_CTRLQ_ACTIVE_TP;
	udma_ctrlq_set_tp_msg(&msg, (void *)&active_tp_req, sizeof(active_tp_req),
			      (void *)&active_tp_resp, sizeof(active_tp_resp));

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret) {
		dev_err(udev->dev, "udma active tp send failed, ret = %d.\n", ret);
		return ret;
	}

	*tp_id = active_tp_resp.local_tp_id;

	return ret;
}

int udma_ctrlq_set_active_tp_ex(struct udma_dev *dev,
				struct ubcore_active_tp_cfg *active_cfg)
{
	uint32_t tp_id = active_cfg->tp_handle.bs.tpid;
	int ret;

	ret = udma_k_ctrlq_create_active_tp_msg(dev, active_cfg, &tp_id);
	if (ret)
		return ret;

	active_cfg->tp_handle.bs.tpid = tp_id;

	if (dev->is_ue)
		(void)udma_notify_mue_save_tp(dev, &(active_cfg->tp_handle));

	return 0;
}

static int udma_k_ctrlq_save_tpn(struct udma_dev *udev, uint32_t tp_id, uint32_t *tp_num)
{
	struct udma_ctrlq_tp_info_resp_data tp_info_resp = {};
	struct udma_ctrlq_tp_info_req_data tp_info_req = {};
	struct ubase_ctrlq_msg msg = {};
	int ret;

	tp_info_req.tp_id = tp_id;
	udma_ctrlq_set_tp_msg(&msg, (void *)&tp_info_req, sizeof(tp_info_req),
			      (void *)&tp_info_resp,
			      sizeof(tp_info_resp));
	msg.opcode = UDMA_CMD_CTRLQ_GET_TP_INFO;
	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret) {
		dev_err(udev->dev, "get tp_id = %u info failed, ret = %d.\n", tp_id, ret);
		return ret;
	}

	*tp_num = tp_info_resp.resp_tpn_cnt + tp_info_resp.req_tpn_cnt;

	return 0;
}

int udma_k_ctrlq_deactive_tp(struct udma_dev *udev, union ubcore_tp_handle tp_handle,
			     struct ubcore_udata *udata)
{
	uint32_t tp_id = tp_handle.bs.tpid & UDMA_TPHANDLE_TPID_SHIFT;
	struct udma_ctrlq_deactive_tp_req_data deactive_tp_req = {};
	struct ubase_ctrlq_msg msg = {};
	uint32_t tp_num = 0;
	int ret;

	ret = udma_k_ctrlq_save_tpn(udev, tp_id, &tp_num);
	if (ret != -EAGAIN && ret)
		return ret;

	if (tp_num) {
		ret = udma_close_ue_rx(udev, true, false, false, tp_num);
		if (ret) {
			dev_err(udev->dev, "close ue rx failed in deactivate tp.\n");
			return ret;
		}
	}

	msg.opcode = UDMA_CMD_CTRLQ_DEACTIVE_TP;
	deactive_tp_req.tp_id = tp_id;
	deactive_tp_req.tpn_cnt = tp_handle.bs.tp_cnt;
	deactive_tp_req.start_tpn = tp_handle.bs.tpn_start;
	if ((current->flags & PF_KTHREAD) || udev->status != UDMA_NORMAL)
		deactive_tp_req.pid_flag = UDMA_DEFAULT_PID;
	else
		deactive_tp_req.pid_flag = (uint32_t)current->tgid & UDMA_PID_MASK;

	udma_ctrlq_set_tp_msg(&msg, (void *)&deactive_tp_req, sizeof(deactive_tp_req), NULL, 0);

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret != -EAGAIN && ret) {
		dev_err(udev->dev, "deactivate tp send msg failed, tp_id = %u, ret = %d.\n",
			tp_id, ret);
		if (tp_num)
			udma_open_ue_rx_with_retry(udev, true, false, false, tp_num);
		return ret;
	}

	return (ret == -EAGAIN) ? 0 : ret;
}

int udma_ctrlq_query_ubmem_info(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubase_ctrlq_msg ctrlq_msg = {};
	uint32_t input_buf = 0;
	int ret;

	if (out->addr == 0) {
		dev_err(udev->dev, "query ubmem info failed, addr is NULL.\n");
		return -EINVAL;
	}

	ctrlq_msg.service_type = UDMA_CTRLQ_SER_TYPE_UBMEM;
	ctrlq_msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	ctrlq_msg.need_resp = 1;
	ctrlq_msg.in_size = sizeof(input_buf);
	ctrlq_msg.in = (void *)&input_buf;
	ctrlq_msg.out_size = out->len;
	ctrlq_msg.out = (void *)(uintptr_t)out->addr;
	ctrlq_msg.opcode = UDMA_CTRLQ_QUERY_UBMEM_INFO;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &ctrlq_msg);
	if (ret)
		dev_err(udev->dev,
			"query device ubmem info send ctrlq msg failed, ret is %d.\n", ret);

	return ret;
}

int udma_ctrlq_query_host_ubmem_info(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				     struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubase_ctrlq_msg ctrlq_msg = {};
	struct ubase_bus_eid eid = {};
	int ret = 0;

	if (out->addr == 0) {
		dev_err(udev->dev, "query host ubmem info failed, addr is NULL.\n");
		return -EINVAL;
	}

	ret = ubase_get_bus_eid(udev->comdev.adev, &eid);
	if (ret) {
		dev_err(udev->dev,
			"get dev bus eid failed in query host ubmem info, ret is %d.\n", ret);
		return ret;
	}

	ctrlq_msg.service_type = UDMA_CTRLQ_SER_TYPE_UBMEM;
	ctrlq_msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	ctrlq_msg.need_resp = 1;
	ctrlq_msg.in_size = sizeof(eid);
	ctrlq_msg.in = (void *)&eid;
	ctrlq_msg.out_size = out->len;
	ctrlq_msg.out = (void *)(uintptr_t)out->addr;
	ctrlq_msg.opcode = UDMA_CTRLQ_QUERY_HOST_UBMEM_INFO;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &ctrlq_msg);
	if (ret)
		dev_err(udev->dev,
			"query host ubmem info send ctrlq msg failed, ret is %d.\n", ret);

	return ret;
}

static int udma_set_global_udp_sport_attr(struct udma_dev *udev, const uint32_t tp_attr_bitmap,
					  const struct ubcore_tp_attr_value *tp_attr)
{
	uint8_t udp_attr_bitmap = (tp_attr_bitmap >> UDMA_UDP_ATTR_SHIFT) & UDMA_UDP_ATTR_MASK;
	uint8_t udp_global_bit_enable = (tp_attr_bitmap >> UDMA_UDP_GLOBAL_SHIFT) &
					UDMA_UDP_GLOBAL_MASK;

	if (!udp_global_bit_enable) {
		dev_err(udev->dev,
			"udp_global_en bit failed to take effect in bitmap %u.\n",
			tp_attr_bitmap);
		return -EINVAL;
	}

	if (!tp_attr->udp_global_en) {
		spin_lock(&udev->caps.udp.lock);
		udev->caps.udp.udp_srcport_range = 0;
		udev->caps.udp.data_udp_srcport = 0;
		udev->caps.udp.ack_udp_srcport = 0;
		udev->caps.udp.udp_global_en = 0;
		udev->caps.udp.spray_en = 0;
		spin_unlock(&udev->caps.udp.lock);

		return 0;
	}

	if (udp_attr_bitmap != UDMA_UDP_ATTR_MASK) {
		dev_err(udev->dev,
			"the num of udp sport attr is not sufficient, udp_attr_bitmap = 0x%x.\n",
			udp_attr_bitmap);
		return -EINVAL;
	}

	if (tp_attr->udp_srcport_range > UDMA_UDP_RANGE_MAX) {
		dev_err(udev->dev,
			"global-level udp sport range attr %u exceeds max limit %d.\n",
			tp_attr->udp_srcport_range, UDMA_UDP_RANGE_MAX);
		return -EINVAL;
	}

	spin_lock(&udev->caps.udp.lock);
	udev->caps.udp.udp_srcport_range = tp_attr->udp_srcport_range;
	udev->caps.udp.data_udp_srcport = tp_attr->data_udp_srcport;
	udev->caps.udp.ack_udp_srcport = tp_attr->ack_udp_srcport;
	udev->caps.udp.spray_en = tp_attr->spray_en;
	udev->caps.udp.udp_global_en = 1;
	spin_unlock(&udev->caps.udp.lock);

	return 0;
}

static uint8_t udma_update_tp_attr_cnt(uint32_t tp_attr_bitmap)
{
	uint8_t tp_attr_cnt = 0;

	while (tp_attr_bitmap) {
		tp_attr_cnt += tp_attr_bitmap & 1;
		tp_attr_bitmap >>= 1;
	}

	return tp_attr_cnt;
}

static int udma_fill_tp_attr_req(struct udma_dev *udev, const uint64_t tp_handle,
				 const uint8_t tp_attr_cnt, const uint32_t tp_attr_bitmap,
				 const struct ubcore_tp_attr_value *tp_attr,
				 struct udma_ctrlq_set_tp_attr_req *tp_attr_req)
{
	uint8_t udp_global_bit_enable = (tp_attr_bitmap >> UDMA_UDP_GLOBAL_SHIFT) &
					UDMA_UDP_GLOBAL_MASK;
	union ubcore_tp_handle tp_handle_val;

	if (udp_global_bit_enable && tp_attr->udp_global_en == 1) {
		dev_err(udev->dev,
			"udp_global_en cannot be set to 1 at tpid-level.\n");
		return -EINVAL;
	}

	if (tp_attr->udp_srcport_range > UDMA_UDP_RANGE_MAX) {
		dev_err(udev->dev,
			"tpid-level udp sport range attr %u exceeds max limit %d.\n",
			tp_attr->udp_srcport_range, UDMA_UDP_RANGE_MAX);
		return -EINVAL;
	}

	tp_handle_val.value = tp_handle;
	tp_attr_req->tpid = tp_handle_val.bs.tpid;
	tp_attr_req->tpn_cnt = tp_handle_val.bs.tp_cnt;
	tp_attr_req->tpn_start = tp_handle_val.bs.tpn_start;
	memcpy(&tp_attr_req->tp_attr.tp_attr_value, (void *)tp_attr, sizeof(*tp_attr));

	udma_swap_endian(tp_attr->sip, tp_attr_req->tp_attr.tp_attr_value.sip,
			 UBCORE_IP_ADDR_BYTES);
	udma_swap_endian(tp_attr->dip, tp_attr_req->tp_attr.tp_attr_value.dip,
			 UBCORE_IP_ADDR_BYTES);
	udma_swap_endian(tp_attr->sma, tp_attr_req->tp_attr.tp_attr_value.sma,
			 UBCORE_MAC_BYTES);
	udma_swap_endian(tp_attr->dma, tp_attr_req->tp_attr.tp_attr_value.dma,
			 UBCORE_MAC_BYTES);

	spin_lock(&udev->caps.udp.lock);
	if (udev->caps.udp.udp_global_en) {
		tp_attr_req->tp_attr.tp_attr_value.udp_srcport_range =
			udev->caps.udp.udp_srcport_range;
		tp_attr_req->tp_attr.tp_attr_value.data_udp_srcport =
			udev->caps.udp.data_udp_srcport;
		tp_attr_req->tp_attr.tp_attr_value.ack_udp_srcport = udev->caps.udp.ack_udp_srcport;
		tp_attr_req->tp_attr.tp_attr_value.spray_en = udev->caps.udp.spray_en;
		tp_attr_req->tp_attr.tp_attr_bitmap = (UDMA_UDP_ATTR_MASK << UDMA_UDP_ATTR_SHIFT) |
						       tp_attr_bitmap;
		tp_attr_req->tp_attr_cnt =
			udma_update_tp_attr_cnt(tp_attr_req->tp_attr.tp_attr_bitmap);
		tp_attr_req->tp_attr.tp_attr_value.udp_global_en = 1;
	} else {
		tp_attr_req->tp_attr.tp_attr_value.udp_global_en = 0;
		tp_attr_req->tp_attr.tp_attr_bitmap = tp_attr_bitmap;
		tp_attr_req->tp_attr_cnt = tp_attr_cnt;
	}
	spin_unlock(&udev->caps.udp.lock);

	return 0;
}

int udma_set_tp_attr(struct ubcore_device *dev, const uint64_t tp_handle,
		     const uint8_t tp_attr_cnt, const uint32_t tp_attr_bitmap,
		     const struct ubcore_tp_attr_value *tp_attr, struct ubcore_udata *udata)
{
	struct udma_ctrlq_set_tp_attr_req tp_attr_req = {};
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubase_ctrlq_msg msg = {};
	int ret = 0;

	if (tp_handle == UDMA_GLOBAL_TP_HANDLE) {
		ret = udma_set_global_udp_sport_attr(udev, tp_attr_bitmap, tp_attr);
		if (ret)
			goto err_udp_cfg;

		return ret;
	}

	ret = udma_fill_tp_attr_req(udev, tp_handle, tp_attr_cnt, tp_attr_bitmap,
				    tp_attr, &tp_attr_req);
	if (ret)
		goto err_udp_cfg;

	udma_ctrlq_set_tp_msg(&msg, &tp_attr_req, sizeof(tp_attr_req), NULL, 0);
	msg.opcode = UDMA_CMD_CTRLQ_SET_TP_ATTR;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret)
		dev_err(udev->dev, "set tp attr failed, tpid = %u, ret = %d.\n",
			tp_attr_req.tpid, ret);

	return ret;

err_udp_cfg:
	dev_err(udev->dev, "set udp sport attr failed, ret = %d.\n", ret);
	return ret;
}

static void
udma_get_global_udp_sport_attr(struct udma_dev *udev, uint8_t *tp_attr_cnt,
			       uint32_t *tp_attr_bitmap, struct ubcore_tp_attr_value *tp_attr)
{
	if (!udev->caps.udp.udp_global_en) {
		*tp_attr_bitmap = UDMA_UDP_GLOBAL_MASK << UDMA_UDP_GLOBAL_SHIFT;
		*tp_attr_cnt = udma_update_tp_attr_cnt(*tp_attr_bitmap);
		tp_attr->udp_global_en = 0;

		return;
	}

	spin_lock(&udev->caps.udp.lock);
	tp_attr->udp_srcport_range = udev->caps.udp.udp_srcport_range;
	tp_attr->data_udp_srcport = udev->caps.udp.data_udp_srcport;
	tp_attr->ack_udp_srcport = udev->caps.udp.ack_udp_srcport;
	tp_attr->spray_en = udev->caps.udp.spray_en;
	tp_attr->udp_global_en = 1;
	*tp_attr_bitmap = UDMA_UDP_ATTR_MASK << UDMA_UDP_ATTR_SHIFT;
	*tp_attr_cnt = UDMA_UDP_ATTR_NUM;
	spin_unlock(&udev->caps.udp.lock);
}

int udma_get_tp_attr(struct ubcore_device *dev, const uint64_t tp_handle,
		     uint8_t *tp_attr_cnt, uint32_t *tp_attr_bitmap,
		     struct ubcore_tp_attr_value *tp_attr, struct ubcore_udata *udata)
{
	struct udma_ctrlq_get_tp_attr_resp tp_attr_resp = {};
	struct udma_ctrlq_get_tp_attr_req tp_attr_req = {};
	struct udma_dev *udev = to_udma_dev(dev);
	union ubcore_tp_handle tp_handle_val;
	struct ubase_ctrlq_msg msg = {};
	int ret;

	if (tp_handle == UDMA_GLOBAL_TP_HANDLE) {
		udma_get_global_udp_sport_attr(udev, tp_attr_cnt, tp_attr_bitmap, tp_attr);
		return 0;
	}

	tp_handle_val.value = tp_handle;
	tp_attr_req.tpid.tpid = tp_handle_val.bs.tpid;
	tp_attr_req.tpid.tpn_cnt = tp_handle_val.bs.tp_cnt;
	tp_attr_req.tpid.tpn_start = tp_handle_val.bs.tpn_start;
	udma_ctrlq_set_tp_msg(&msg, &tp_attr_req, sizeof(tp_attr_req), &tp_attr_resp,
			      sizeof(tp_attr_resp));
	msg.opcode = UDMA_CMD_CTRLQ_GET_TP_ATTR;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret) {
		dev_err(udev->dev, "get tp attr failed, tpid = %u, ret = %d.\n",
			tp_attr_req.tpid.tpid, ret);
		return ret;
	}

	*tp_attr_cnt = tp_attr_resp.tp_attr_cnt;
	*tp_attr_bitmap = tp_attr_resp.tp_attr.tp_attr_bitmap;
	memcpy((void *)tp_attr, &tp_attr_resp.tp_attr.tp_attr_value,
	       sizeof(tp_attr_resp.tp_attr.tp_attr_value));
	udma_swap_endian((uint8_t *)tp_attr_resp.tp_attr.tp_attr_value.sip, tp_attr->sip,
			 UBCORE_IP_ADDR_BYTES);
	udma_swap_endian((uint8_t *)tp_attr_resp.tp_attr.tp_attr_value.dip, tp_attr->dip,
			 UBCORE_IP_ADDR_BYTES);
	udma_swap_endian((uint8_t *)tp_attr_resp.tp_attr.tp_attr_value.sma, tp_attr->sma,
			 UBCORE_MAC_BYTES);
	udma_swap_endian((uint8_t *)tp_attr_resp.tp_attr.tp_attr_value.dma, tp_attr->dma,
			 UBCORE_MAC_BYTES);

	return 0;
}

int udma_send_msg_to_ue(struct udma_dev *udma_dev, struct udma_entity_buf *add_buf,
		   uint8_t dst_ue_idx, uint16_t opcode)
{
	struct udma_entity_msg *send_msg;
	struct ubase_cmd_buf in;
	uint32_t msg_len;
	int ret;

	msg_len = sizeof(*send_msg) + add_buf->len;
	send_msg = kzalloc(msg_len, GFP_KERNEL);
	if (!send_msg)
		return -ENOMEM;

	send_msg->dst_ue_idx = dst_ue_idx;
	send_msg->opcode = opcode;

	(void)memcpy(&send_msg->buf, add_buf, sizeof(*add_buf));
	(void)memcpy(send_msg->buf.data, add_buf->data, add_buf->len);

	udma_fill_buf(&in, UBASE_OPC_MUE_TO_UE, false, msg_len, send_msg);

	ret = ubase_cmd_send_in(udma_dev->comdev.adev, &in);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to send msg to ue, ret is %d.\n", ret);

	kfree(send_msg);

	return ret;
}

int udma_active_tp(struct ubcore_device *dev, struct ubcore_active_tp_cfg *active_cfg)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	int ret;

	ret = udma_ctrlq_set_active_tp_ex(udma_dev, active_cfg);
	if (ret)
		dev_err(udma_dev->dev, "Failed to set active tp msg, ret %d.\n", ret);

	return ret;
}

int udma_deactive_tp(struct ubcore_device *dev, union ubcore_tp_handle tp_handle,
		     struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);

	if (debug_switch)
		dev_info_ratelimited(udma_dev->dev, "udma deactivate tp ex tp_id = %u\n",
				     tp_handle.bs.tpid);

	return udma_k_ctrlq_deactive_tp(udma_dev, tp_handle, udata);
}

int udma_query_pair_dev_count(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			      struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubase_ctrlq_msg ctrlq_msg = {};
	struct ubase_bus_eid eid = {};
	int ret;

	if (out->addr == 0) {
		dev_err(udev->dev, "query pair dev count, addr is NULL.\n");
		return -EINVAL;
	}

	ret = ubase_get_bus_eid(udev->comdev.adev, &eid);
	if (ret) {
		dev_err(udev->dev, "get dev bus eid failed, ret is %d.\n", ret);
		return ret;
	}

	ctrlq_msg.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER;
	ctrlq_msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	ctrlq_msg.need_resp = 1;
	ctrlq_msg.in_size = sizeof(eid);
	ctrlq_msg.in = (void *)&eid;
	ctrlq_msg.out_size = out->len;
	ctrlq_msg.out = (void *)(uintptr_t)out->addr;
	ctrlq_msg.opcode = UDMA_CTRLQ_GET_DEV_RESOURCE_COUNT;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &ctrlq_msg);
	if (ret)
		dev_err(udev->dev, "get dev res send ctrlq msg failed, ret is %d.\n", ret);

	return ret;
}

int udma_get_smac(struct ubcore_device *dev, uint8_t *mac)
{
	struct udma_dev *udev = to_udma_dev(dev);
	int ret;

	ret = ubase_get_dev_mac(udev->comdev.adev, mac, UBCORE_MAC_BYTES);
	if (ret)
		dev_err(udev->dev, "Failed to get smac, ret %d.\n", ret);

	return ret;
}

int udma_get_eid_by_ip(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr,
		       union ubcore_eid *eid)
{
	struct udma_ctrlq_get_eid_by_ip_resp eid_by_ip_resp = {};
	struct udma_ctrlq_get_eid_by_ip_req eid_by_ip_req = {};
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubase_ctrlq_msg msg = {};
	int ret;

	eid_by_ip_req.addr_type = net_addr->type;
	udma_swap_endian(net_addr->net_addr.raw, eid_by_ip_req.ip, UDMA_IP_SIZE);
	udma_ctrlq_set_tp_msg(&msg, &eid_by_ip_req, sizeof(eid_by_ip_req), &eid_by_ip_resp,
			      sizeof(eid_by_ip_resp));
	msg.opcode = UDMA_CMD_CTRLQ_GET_EID_BY_IP;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret) {
		dev_err(udev->dev, "get eid by ip failed, addr_type = %u, ret = %d.\n",
			net_addr->type, ret);
		return ret;
	}

	udma_swap_endian(eid_by_ip_resp.eid, eid->raw, UDMA_EID_SIZE);

	return 0;
}

int udma_get_ip_by_eid(struct ubcore_device *dev, const union ubcore_eid *eid,
		       struct ubcore_net_addr *net_addr)
{
	struct udma_ctrlq_get_ip_by_eid_resp ip_by_eid_resp = {};
	struct udma_ctrlq_get_ip_by_eid_req ip_by_eid_req = {};
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubase_ctrlq_msg msg = {};
	int ret;

	ip_by_eid_req.eid_type = UDMA_CTRLQ_EID_TYPE_128;
	udma_swap_endian(eid->raw, ip_by_eid_req.eid, UDMA_EID_SIZE);
	udma_ctrlq_set_tp_msg(&msg, &ip_by_eid_req, sizeof(ip_by_eid_req), &ip_by_eid_resp,
			      sizeof(ip_by_eid_resp));
	msg.opcode = UDMA_CMD_CTRLQ_GET_IP_BY_EID;

	ret = ubase_ctrlq_send_msg(udev->comdev.adev, &msg);
	if (ret) {
		dev_err(udev->dev, "get ip by eid failed, ret = %d.\n", ret);
		return ret;
	}

	net_addr->type = ip_by_eid_resp.addr_type;
	udma_swap_endian(ip_by_eid_resp.ip, net_addr->net_addr.raw, UDMA_IP_SIZE);

	return 0;
}
