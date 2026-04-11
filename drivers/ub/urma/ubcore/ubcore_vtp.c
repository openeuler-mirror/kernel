// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 *
 * Description: ubcore vtp implementation
 * Author: Yan Fangfang
 * Create: 2023-07-14
 * Note:
 * History: 2023-07-14: Create file
 */

#include <linux/slab.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_connect_adapter.h"
#include "ubcore_msg.h"
#include "ubcore_log.h"
#include "ubcore_hash_table.h"
#include "ubcore_priv.h"
#include "ubcore_workqueue.h"
#include "ubcore_msg.h"
#include "ubcore_vtp.h"

#define UBCORE_SYNC_VTPN_MAX_WAIT_TIMES (30 * 1000 / 20)
#define UBCORE_SYNC_REUSE_VTPN_ONE_TIME 20
#define UBCORE_VTPS_ERROR 3

enum ubcore_vtp_task_type { UBCORE_TASK_DESTROY_VTP };

static LIST_HEAD(g_vtp_work_list);
static DEFINE_SPINLOCK(g_vtp_work_lock);

static LIST_HEAD(g_async_disconnect_vtp_work_list);
static DEFINE_SPINLOCK(g_async_disconnect_vtp_work_lock);

struct ubcore_vtp_work {
	struct list_head node; /* add to g_vtp_work_list */
	struct delayed_work delay_work;
	struct ubcore_device *dev;
	struct ubcore_vtpn *vtpn;
	enum ubcore_vtp_task_type type;
	uint32_t retry_times;
};

struct ubcore_vtpn_wait_cb_node_imp {
	struct list_head node;
	struct list_head node_global;
	struct ubcore_vtpn_cb_para para;
	struct ubcore_wait_vtpn_resp_work *wait_work;
};

#define DESTROY_VTP_INI_INTERVAL 3000 /* 3s */
#define DESTROY_VTP_MAX_RETRY_TIMES 9

static struct ubcore_vtpn *ubcore_find_get_vtpn(struct ubcore_device *dev,
						struct ubcore_vtp_param *param);
static int ubcore_free_vtpn(struct ubcore_vtpn *vtpn);
static void ubcore_hash_table_rmv_vtpn(struct ubcore_device *dev,
				       struct ubcore_vtpn *vtpn);

static void ubcore_add_async_disconnect_vtp_work_list(
	struct ubcore_vtpn_wait_cb_node_imp *vtp_work);
static void ubcore_del_async_disconnect_vtp_work_list(
	struct ubcore_vtpn_wait_cb_node_imp *vtp_work);

void ubcore_add_async_wait_list(struct ubcore_vtpn *vtpn,
				struct ubcore_vtpn_cb_para *para,
				struct ubcore_wait_vtpn_resp_work *wait_work)
{
	struct ubcore_vtpn_wait_cb_node_imp *new_node;

	if (vtpn == NULL || para == NULL) {
		ubcore_log_err("invalid parameter");
		return;
	}

	new_node = kzalloc(sizeof(struct ubcore_vtpn_wait_cb_node_imp),
			   GFP_ATOMIC);
	if (new_node == NULL)
		return;

	new_node->para.type = para->type;
	new_node->para.tjetty = para->tjetty;
	new_node->para.jetty = para->jetty;
	new_node->para.import_cb = para->import_cb;
	new_node->para.bind_cb = para->bind_cb;
	new_node->para.unimport_cb = para->unimport_cb;
	new_node->para.unbind_cb = para->unbind_cb;
	new_node->wait_work = wait_work;
	if (para->type == UBCORE_IMPORT_JETTY_VTPN ||
	    para->type == UBCORE_BIND_JETTY_VTPN) {
		list_add_tail(&new_node->node, &vtpn->list);
		INIT_LIST_HEAD(&new_node->node_global);
	} else {
		list_add_tail(&new_node->node, &vtpn->disconnect_list);
		ubcore_add_async_disconnect_vtp_work_list(new_node);
	}
}

void ubcore_del_async_wait_list(struct ubcore_vtpn *vtpn)
{
	struct ubcore_vtpn_wait_cb_node_imp *wait_node, *next;
	struct ubcore_unimport_cb *unimport_cb;
	struct ubcore_unbind_cb *unbind_cb;

	if (vtpn == NULL) {
		ubcore_log_err("invalid parameter");
		return;
	}

	list_for_each_entry_safe(wait_node, next, &vtpn->list, node) {
		if (wait_node->para.type == UBCORE_UNIMPORT_JETTY_VTPN) {
			if (wait_node->para.unimport_cb != NULL) {
				unimport_cb = wait_node->para.unimport_cb;
				unimport_cb->callback(ECONNREFUSED,
						      unimport_cb->user_arg);
				kfree(wait_node->para.unimport_cb);
				wait_node->para.unimport_cb = NULL;
			}
		}
		if (wait_node->para.type == UBCORE_UNBIND_JETTY_VTPN) {
			if (wait_node->para.unbind_cb != NULL) {
				unbind_cb = wait_node->para.unbind_cb;
				unbind_cb->callback(ECONNREFUSED,
						    unbind_cb->user_arg);
				kfree(wait_node->para.unbind_cb);
				wait_node->para.unbind_cb = NULL;
			}
		}
		ubcore_del_async_disconnect_vtp_work_list(wait_node);
		list_del(&wait_node->node);
		kfree(wait_node);
	}
}

static void ubcore_add_async_disconnect_vtp_work_list(
	struct ubcore_vtpn_wait_cb_node_imp *vtp_work)
{
	spin_lock(&g_async_disconnect_vtp_work_lock);
	list_add_tail(&vtp_work->node_global,
		      &g_async_disconnect_vtp_work_list);
	spin_unlock(&g_async_disconnect_vtp_work_lock);
}

static void ubcore_del_async_disconnect_vtp_work_list(
	struct ubcore_vtpn_wait_cb_node_imp *vtp_work)
{
	spin_lock(&g_async_disconnect_vtp_work_lock);
	list_del_init(&vtp_work->node_global);
	spin_unlock(&g_async_disconnect_vtp_work_lock);
}

static void
ubcore_flush_dev_async_disconnect_vtp_work(struct ubcore_device *dev)
{
	struct ubcore_vtpn_wait_cb_node_imp *entry = NULL;
	struct ubcore_vtpn_wait_cb_node_imp *next = NULL;

	spin_lock(&g_async_disconnect_vtp_work_lock);
	list_for_each_entry_safe(entry, next, &g_async_disconnect_vtp_work_list,
				 node_global) {
		if (entry != NULL && entry->wait_work != NULL &&
		    entry->wait_work->dev == dev)
			ubcore_modify_delay_work(UBCORE_DISCONNECT_VTP_ASYNC_WQ,
						 &entry->wait_work->delay_work,
						 0);
	}
	spin_unlock(&g_async_disconnect_vtp_work_lock);
}

void ubcore_add_vtp_work_list(struct ubcore_vtp_work *vtp_work)
{
	spin_lock(&g_vtp_work_lock);
	list_add_tail(&vtp_work->node, &g_vtp_work_list);
	spin_unlock(&g_vtp_work_lock);
}

void ubcore_del_vtp_work_list(struct ubcore_vtp_work *vtp_work)
{
	spin_lock(&g_vtp_work_lock);
	list_del(&vtp_work->node);
	spin_unlock(&g_vtp_work_lock);
}

void ubcore_flush_dev_vtp_work(struct ubcore_device *dev)
{
	struct ubcore_vtp_work *entry = NULL;
	struct ubcore_vtp_work *next = NULL;

	spin_lock(&g_vtp_work_lock);
	list_for_each_entry_safe(entry, next, &g_vtp_work_list, node) {
		if (entry != NULL && entry->dev == dev)
			ubcore_modify_delay_work(UBCORE_VTP_TASK_WQ,
						 &entry->delay_work, 0);
	}
	spin_unlock(&g_vtp_work_lock);

	ubcore_flush_dev_async_disconnect_vtp_work(dev);
}

static int ubcore_handle_create_vtp_resp(struct ubcore_device *dev,
					 struct ubcore_resp *resp,
					 void *user_arg)
{
	struct ubcore_create_vtp_resp *vtp_resp = NULL;
	struct ubcore_vtpn *vtpn = (struct ubcore_vtpn *)user_arg;

	if (resp == NULL || resp->len < sizeof(struct ubcore_create_vtp_resp)) {
		ubcore_log_err("invalid ubcore_create_vtp_resp len");
		return (int)UBCORE_MSG_RESP_FAIL;
	}

	if (vtpn == NULL) {
		ubcore_log_err("invalid user_arg, vtpn == NULL");
		return (int)UBCORE_MSG_RESP_FAIL;
	}

	vtp_resp = (struct ubcore_create_vtp_resp *)resp->data;

	switch (vtp_resp->ret) {
	case UBCORE_MSG_RESP_FAIL:
		ubcore_log_err("failed to create vtp: response error.\n");
		break;
	case UBCORE_MSG_RESP_IN_PROGRESS:
		ubcore_log_err(
			"failed: try to del vtp which is being created. Try again later.\n");
		break;
	case UBCORE_MSG_RESP_RC_JETTY_ALREADY_BIND:
		ubcore_log_err(
			"failed: rc jetty already bind by other jetty.\n");
		break;
	case UBCORE_MSG_RESP_LIMIT_RATE:
		ubcore_log_err(
			"failed: the current link setup speed has reached the maximum value.\n");
		break;
	case UBCORE_MSG_RESP_SUCCESS:
		/* mue may return a new vtpn */
		vtpn->vtpn = vtp_resp->vtpn;
		break;
	default:
		ubcore_log_err(
			"unknown the state of vtp reply to create. state: %d\n",
			vtp_resp->ret);
		break;
	}

	return vtp_resp->ret;
}

static int ubcore_send_create_vtp_req(struct ubcore_device *dev,
				      struct ubcore_vtp_param *p,
				      struct ubcore_vtpn *vtpn)
{
	uint32_t data_len = (uint32_t)sizeof(struct ubcore_create_vtp_req);
	struct ubcore_create_vtp_req *create;
	struct ubcore_req *req;

	req = kzalloc(sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req == NULL)
		return -ENOMEM;
	req->opcode = UBCORE_MSG_CREATE_VTP;
	req->len = data_len;

	create = (struct ubcore_create_vtp_req *)req->data;
	create->vtpn = vtpn->vtpn;
	create->trans_mode = p->trans_mode;
	create->local_eid = p->local_eid;
	create->peer_eid = p->peer_eid;
	create->eid_index = p->eid_index;
	create->local_jetty = p->local_jetty;
	create->peer_jetty = p->peer_jetty;
	(void)strscpy(create->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
	create->virtualization = dev->attr.virtualization;

	kfree(req);
	return 0;
}

static void ubcore_handle_vtpn_wait_list(struct ubcore_vtpn *vtpn,
					 struct ubcore_device *dev,
					 int vtp_state, int status)
{
	struct ubcore_vtpn_wait_cb_node_imp *wait_node, *next;
	struct ubcore_vtpn_cb_para *para;
	struct ubcore_wait_vtpn_resp_work *wait_work;
	struct ubcore_import_cb *import_cb;
	struct ubcore_bind_cb *bind_cb;

	vtpn->state = vtp_state;

	list_for_each_entry_safe(wait_node, next, &vtpn->list, node) {
		ubcore_del_async_disconnect_vtp_work_list(wait_node);

		para = &wait_node->para;
		wait_work = wait_node->wait_work;

		if (wait_work != NULL && status != ETIMEDOUT) {
			cancel_delayed_work_sync(&wait_work->delay_work);
			kfree(wait_work);
		}

		if (para->type == UBCORE_IMPORT_JETTY_VTPN) {
			import_cb = para->import_cb;
			import_cb->callback(para->tjetty, status,
					    import_cb->user_arg);
			kfree(para->import_cb);
			para->import_cb = NULL;
		} else {
			bind_cb = para->bind_cb;
			bind_cb->callback(para->jetty, para->tjetty, status,
					  bind_cb->user_arg);
			kfree(para->bind_cb);
			para->bind_cb = NULL;
		}

		if (status != 0) {
			if (para->type == UBCORE_IMPORT_JETTY_VTPN) {
				mutex_destroy(&para->tjetty->lock);
				(void)dev->ops->unimport_jetty(para->tjetty);
			} else {
				(void)dev->ops->unbind_jetty(para->jetty);
				atomic_dec(&para->jetty->use_cnt);
				atomic_dec(&para->tjetty->use_cnt);
			}
			atomic_dec(&vtpn->use_cnt);
		}

		list_del(&wait_node->node);
		kfree(wait_node);
	}
}

void ubcore_wait_connect_vtp_resp_intime(struct ubcore_msg_session *s,
					 struct ubcore_device *dev,
					 struct ubcore_resp *resp)
{
	struct ubcore_vtp_param param = { 0 };
	struct ubcore_create_vtp_req *create;
	struct ubcore_vtpn *vtpn;
	struct ubcore_req *req;
	int ret;

	ubcore_log_info("Success to wait connect vtp resp intime.\n");
	if (s->req == NULL)
		return;
	req = s->req;
	create = (struct ubcore_create_vtp_req *)req->data;
	param.trans_mode = create->trans_mode;
	param.local_eid = create->local_eid;
	param.peer_eid = create->peer_eid;
	param.local_jetty = create->local_jetty;
	param.peer_jetty = create->peer_jetty;

	vtpn = ubcore_find_get_vtpn(dev, &param);
	if (vtpn == NULL) {
		ubcore_log_err("Failed to find vtpn, seid : " EID_FMT
			       ", deid : " EID_FMT ".\n",
			       EID_ARGS(param.local_eid),
			       EID_ARGS(param.peer_eid));
		return;
	}

	mutex_lock(&vtpn->state_lock);
	if (vtpn->state != UBCORE_VTPS_RESET) {
		mutex_unlock(&vtpn->state_lock);
		ubcore_vtpn_kref_put(vtpn);
		return;
	}

	ret = ubcore_handle_create_vtp_resp(dev, resp, vtpn);
	if (ret != 0) {
		ubcore_handle_vtpn_wait_list(vtpn, dev, UBCORE_VTPS_ERROR,
					     ECONNREFUSED);
		ubcore_hash_table_rmv_vtpn(dev, vtpn);
		mutex_unlock(&vtpn->state_lock);
		ubcore_vtpn_kref_put(vtpn);
		(void)ubcore_free_vtpn(vtpn);
	} else {
		ubcore_handle_vtpn_wait_list(vtpn, dev, UBCORE_VTPS_READY, 0);
		mutex_unlock(&vtpn->state_lock);
		ubcore_vtpn_kref_put(vtpn);
	}
}

static void ubcore_wait_connect_vtp_resp_timeout_inner(
	struct ubcore_vtp_param *param, struct ubcore_device *dev,
	struct ubcore_wait_vtpn_resp_work *wait_work)
{
	struct ubcore_vtpn *vtpn;

	if (param == NULL || dev == NULL) {
		ubcore_log_err("dev or param is null.\n");
		return;
	}

	vtpn = ubcore_find_get_vtpn(dev, param);
	if (vtpn == NULL) {
		ubcore_log_err("Failed to find vtpn.\n");
		return;
	}

	mutex_lock(&vtpn->state_lock);
	if (vtpn->state != UBCORE_VTPS_RESET) {
		mutex_unlock(&vtpn->state_lock);
		ubcore_vtpn_kref_put(vtpn);
		return;
	}

	ubcore_handle_vtpn_wait_list(vtpn, dev, UBCORE_VTPS_ERROR, ETIMEDOUT);
	if (atomic_read(&vtpn->use_cnt) == 0) {
		ubcore_hash_table_rmv_vtpn(dev, vtpn);
		mutex_unlock(&vtpn->state_lock);
		ubcore_vtpn_kref_put(vtpn);
		(void)ubcore_free_vtpn(vtpn);
	} else {
		mutex_unlock(&vtpn->state_lock);
		ubcore_vtpn_kref_put(vtpn);
	}
}

static void ubcore_wait_connect_vtp_resp_timeout(struct work_struct *work)
{
	struct ubcore_wait_vtpn_resp_work *wait_work;
	struct ubcore_msg_session *s;

	ubcore_log_info("Failed to wait connect vtp resp, time out.\n");
	wait_work = container_of(work, struct ubcore_wait_vtpn_resp_work,
				 delay_work.work);

	s = ubcore_find_msg_session(wait_work->msg_id);
	if (s == NULL) {
		ubcore_log_err("Failed to find msg session.\n");
		return;
	}

	if (!ubcore_set_session_finish(s)) {
		ubcore_log_err("Failed to trylock and modify state.\n");
		(void)kref_put(&s->kref, ubcore_free_msg_session);
		return;
	}

	ubcore_wait_connect_vtp_resp_timeout_inner(&wait_work->param,
						   wait_work->dev, wait_work);
	kfree(s->req);
	s->req = NULL;
	(void)kref_put(&s->kref, ubcore_free_msg_session);
	ubcore_destroy_msg_session(s);
	kfree(wait_work);
}

static struct ubcore_wait_vtpn_resp_work *
ubcore_queue_wait_connect_vtp_resp_task(struct ubcore_device *dev,
					struct ubcore_vtp_param *param,
					int timeout)
{
	struct ubcore_wait_vtpn_resp_work *wait_work;
	int ret;

	wait_work =
		kzalloc(sizeof(struct ubcore_wait_vtpn_resp_work), GFP_KERNEL);
	if (wait_work == NULL)
		return NULL;

	wait_work->dev = dev;
	wait_work->s = NULL;
	wait_work->param.trans_mode = param->trans_mode;
	wait_work->param.local_eid = param->local_eid;
	wait_work->param.peer_eid = param->peer_eid;
	wait_work->param.local_jetty = param->local_jetty;
	wait_work->param.peer_jetty = param->peer_jetty;
	wait_work->param.eid_index = param->eid_index;
	wait_work->vtpn = NULL;
	wait_work->msg_id = 0;
	if (timeout <= 0 || timeout > UBCORE_TYPICAL_TIMEOUT)
		wait_work->timeout = UBCORE_TYPICAL_TIMEOUT;
	else
		wait_work->timeout = timeout;

	INIT_DELAYED_WORK(&wait_work->delay_work,
			  ubcore_wait_connect_vtp_resp_timeout);
	ret = ubcore_queue_delayed_work(UBCORE_CONNECT_VTP_ASYNC_WQ,
					&wait_work->delay_work,
					msecs_to_jiffies(wait_work->timeout));
	if (ret != 0) {
		ubcore_log_err("Failed to queue wait connect vtp resp work.\n");
		kfree(wait_work);
		return NULL;
	}
	return wait_work;
}

static struct ubcore_msg_session *
ubcore_create_async_connect_vtp_req(struct ubcore_device *dev,
				    struct ubcore_vtp_param *p,
				    struct ubcore_vtpn *vtpn)
{
	uint32_t data_len = (uint32_t)sizeof(struct ubcore_create_vtp_req);
	struct ubcore_create_vtp_req *create;
	struct ubcore_req *req;
	struct ubcore_msg_session *s;

	req = kzalloc(sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req == NULL)
		return NULL;
	req->opcode = UBCORE_MSG_CREATE_VTP;
	req->len = data_len;

	create = (struct ubcore_create_vtp_req *)req->data;
	create->vtpn = vtpn->vtpn;
	create->trans_mode = p->trans_mode;
	create->local_eid = p->local_eid;
	create->peer_eid = p->peer_eid;
	create->eid_index = p->eid_index;
	create->local_jetty = p->local_jetty;
	create->peer_jetty = p->peer_jetty;
	(void)strscpy(create->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
	create->virtualization = dev->attr.virtualization;

	s = ubcore_create_ue2mue_session(req, vtpn);
	if (s == NULL)
		kfree(req);
	return s;
}

static int ubcore_handle_del_vtp_resp(struct ubcore_device *dev,
				      struct ubcore_resp *resp, void *user_arg)
{
	struct ubcore_destroy_vtp_resp *vtp_resp = NULL;

	if (resp == NULL ||
	    resp->len < sizeof(struct ubcore_destroy_vtp_resp)) {
		ubcore_log_err("invalid parameter");
		return (int)UBCORE_MSG_RESP_FAIL;
	}

	vtp_resp = (struct ubcore_destroy_vtp_resp *)resp->data;
	switch (vtp_resp->ret) {
	case UBCORE_MSG_RESP_SUCCESS:
		break;
	case UBCORE_MSG_RESP_FAIL:
		ubcore_log_err("failed to destroy vtp: response error");
		break;
	case UBCORE_MSG_RESP_IN_PROGRESS:
		ubcore_log_err(
			"failed: try to del vtp which is being deleted. Try again later.\n");
		break;
	/* the status of the delete vtp reply is unknown */
	case UBCORE_MSG_RESP_RC_JETTY_ALREADY_BIND:
	case UBCORE_MSG_RESP_LIMIT_RATE:
	default:
		ubcore_log_err("failed: the state of vtp reply to del is:%d.\n",
			       vtp_resp->ret);
		break;
	}

	return (int)vtp_resp->ret;
}

static int ubcore_send_del_vtp_req(struct ubcore_vtpn *vtpn)
{
	uint32_t data_len = (uint32_t)sizeof(struct ubcore_create_vtp_req);
	struct ubcore_create_vtp_req *destroy;
	struct ubcore_req *req;

	req = kzalloc(sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req == NULL)
		return -ENOMEM;
	req->opcode = UBCORE_MSG_DESTROY_VTP;
	req->len = data_len;

	destroy = (struct ubcore_create_vtp_req *)req->data;
	destroy->vtpn = vtpn->vtpn;
	destroy->trans_mode = vtpn->trans_mode;
	destroy->local_eid = vtpn->local_eid;
	destroy->peer_eid = vtpn->peer_eid;
	destroy->eid_index = vtpn->eid_index;
	destroy->local_jetty = vtpn->local_jetty;
	destroy->peer_jetty = vtpn->peer_jetty;
	(void)strscpy(destroy->dev_name, vtpn->ub_dev->dev_name,
		      UBCORE_MAX_DEV_NAME);
	destroy->virtualization = vtpn->ub_dev->attr.virtualization;

	kfree(req);
	return 0;
}

static void ubcore_handle_disconnect_vtpn_wait_list(struct ubcore_vtpn *vtpn,
						    int status, int vtp_state)
{
	struct ubcore_vtpn_wait_cb_node_imp *wait_node, *next;
	struct ubcore_vtpn_cb_para *para;
	struct ubcore_wait_vtpn_resp_work *wait_work;
	struct ubcore_unimport_cb *unimport_cb;
	struct ubcore_unbind_cb *unbind_cb;

	vtpn->state = vtp_state;
	list_for_each_entry_safe(wait_node, next, &vtpn->disconnect_list,
				 node) {
		ubcore_del_async_disconnect_vtp_work_list(wait_node);

		para = &wait_node->para;
		wait_work = wait_node->wait_work;

		if (wait_work != NULL && status != ETIMEDOUT) {
			cancel_delayed_work_sync(&wait_work->delay_work);
			kfree(wait_work);
		}

		if (para->type == UBCORE_UNIMPORT_JETTY_VTPN) {
			if (para->unimport_cb != NULL) {
				unimport_cb = para->unimport_cb;
				unimport_cb->callback(status,
						      unimport_cb->user_arg);
				kfree(para->unimport_cb);
				para->unimport_cb = NULL;
			}
		} else {
			if (para->unbind_cb != NULL) {
				unbind_cb = para->unbind_cb;
				unbind_cb->callback(status,
						    unbind_cb->user_arg);
				kfree(para->unbind_cb);
				para->unbind_cb = NULL;
			}
		}

		list_del(&wait_node->node);
		kfree(wait_node);
	}
}

void ubcore_wait_disconnect_vtp_resp_intime(struct ubcore_msg_session *s,
					    struct ubcore_device *dev,
					    struct ubcore_resp *resp)
{
	struct ubcore_vtpn *vtpn;
	int ret;

	ubcore_log_info("Success to wait disconnect vtp resp intime.\n");
	vtpn = s->vtpn;
	if (vtpn == NULL) {
		ubcore_log_err("vtpn is null.\n");
		return;
	}

	mutex_lock(&vtpn->state_lock);
	if (vtpn->state == UBCORE_VTPS_ERROR) {
		mutex_unlock(&vtpn->state_lock);
		return;
	}

	ret = ubcore_handle_del_vtp_resp(dev, resp, vtpn);
	if (ret != 0)
		ubcore_handle_disconnect_vtpn_wait_list(vtpn, ECONNREFUSED,
							UBCORE_VTPS_ERROR);
	else
		ubcore_handle_disconnect_vtpn_wait_list(vtpn, 0,
							UBCORE_VTPS_ERROR);
	mutex_unlock(&vtpn->state_lock);

	if (atomic_read(&vtpn->use_cnt) == 0) {
		ubcore_log_info("vtpn use_cnt is 0, destroy vtpn, vtpn: %u.\n",
				vtpn->vtpn);
		if (ret == 0 || ret == -ENOENT ||
		    ubcore_queue_destroy_vtp_task(dev, vtpn, 0) != 0)
			(void)ubcore_free_vtpn(vtpn);
	}
}

static void ubcore_wait_disconnect_vtp_resp_timeout_inner(
	struct ubcore_vtpn *vtpn, struct ubcore_device *dev,
	struct ubcore_wait_vtpn_resp_work *wait_work)
{
	if (vtpn == NULL || dev == NULL) {
		ubcore_log_err("vtpn or dev is null.\n");
		return;
	}

	mutex_lock(&vtpn->state_lock);
	if (vtpn->state == UBCORE_VTPS_ERROR) {
		mutex_unlock(&vtpn->state_lock);
		return;
	}
	ubcore_handle_disconnect_vtpn_wait_list(vtpn, ETIMEDOUT,
						UBCORE_VTPS_ERROR);
	mutex_unlock(&vtpn->state_lock);

	if (atomic_read(&vtpn->use_cnt) == 0) {
		if (ubcore_queue_destroy_vtp_task(dev, vtpn, 0) != 0)
			(void)ubcore_free_vtpn(vtpn);
	}
}

static void ubcore_wait_disconnect_vtp_resp_timeout(struct work_struct *work)
{
	struct ubcore_wait_vtpn_resp_work *wait_work;
	struct ubcore_msg_session *s;

	ubcore_log_info("Failed to wait disconnect vtp resp, time out.\n");
	wait_work = container_of(work, struct ubcore_wait_vtpn_resp_work,
				 delay_work.work);

	s = ubcore_find_msg_session(wait_work->msg_id);
	if (s == NULL) {
		ubcore_log_err("Failed to find msg session.\n");
		return;
	}

	if (!ubcore_set_session_finish(s)) {
		ubcore_log_err("Failed to trylock and modify state.\n");
		(void)kref_put(&s->kref, ubcore_free_msg_session);
		return;
	}

	ubcore_wait_disconnect_vtp_resp_timeout_inner(
		wait_work->vtpn, wait_work->dev, wait_work);
	kfree(s->req);
	s->req = NULL;
	(void)kref_put(&s->kref, ubcore_free_msg_session);
	ubcore_destroy_msg_session(s);
	kfree(wait_work);
}

static struct ubcore_wait_vtpn_resp_work *
ubcore_queue_wait_disconnect_vtp_resp_task(struct ubcore_device *dev,
					   struct ubcore_vtpn *vtpn,
					   int timeout)
{
	struct ubcore_wait_vtpn_resp_work *wait_work;
	int ret;

	wait_work =
		kzalloc(sizeof(struct ubcore_wait_vtpn_resp_work), GFP_KERNEL);
	if (wait_work == NULL)
		return NULL;

	wait_work->dev = dev;
	wait_work->s = NULL;
	wait_work->param.trans_mode = vtpn->trans_mode;
	wait_work->param.local_eid = vtpn->local_eid;
	wait_work->param.peer_eid = vtpn->peer_eid;
	wait_work->param.local_jetty = vtpn->local_jetty;
	wait_work->param.peer_jetty = vtpn->peer_jetty;
	wait_work->param.eid_index = vtpn->eid_index;
	wait_work->vtpn = vtpn;
	wait_work->msg_id = 0;
	if (timeout <= 0 || timeout > UBCORE_DESTROY_TIMEOUT)
		wait_work->timeout = UBCORE_DESTROY_TIMEOUT;
	else
		wait_work->timeout = timeout;

	INIT_DELAYED_WORK(&wait_work->delay_work,
			  ubcore_wait_disconnect_vtp_resp_timeout);
	ret = ubcore_queue_delayed_work(UBCORE_DISCONNECT_VTP_ASYNC_WQ,
					&wait_work->delay_work,
					msecs_to_jiffies(wait_work->timeout));
	if (ret != 0) {
		ubcore_log_err(
			"Failed to queue wait disconnect vtp resp work.\n");
		kfree(wait_work);
		return NULL;
	}
	return wait_work;
}

static struct ubcore_msg_session *
ubcore_create_async_disconnect_vtp_req(struct ubcore_vtpn *vtpn)
{
	uint32_t data_len = (uint32_t)sizeof(struct ubcore_create_vtp_req);
	struct ubcore_create_vtp_req *destroy;
	struct ubcore_req *req;
	struct ubcore_msg_session *s;

	req = kzalloc(sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req == NULL)
		return NULL;
	req->opcode = UBCORE_MSG_DESTROY_VTP;
	req->len = data_len;

	destroy = (struct ubcore_create_vtp_req *)req->data;
	destroy->vtpn = vtpn->vtpn;
	destroy->trans_mode = vtpn->trans_mode;
	destroy->local_eid = vtpn->local_eid;
	destroy->peer_eid = vtpn->peer_eid;
	destroy->eid_index = vtpn->eid_index;
	destroy->local_jetty = vtpn->local_jetty;
	destroy->peer_jetty = vtpn->peer_jetty;
	(void)strscpy(destroy->dev_name, vtpn->ub_dev->dev_name,
		      UBCORE_MAX_DEV_NAME);
	destroy->virtualization = vtpn->ub_dev->attr.virtualization;

	s = ubcore_create_ue2mue_session(req, vtpn);
	if (s == NULL)
		kfree(req);
	return s;
}

static struct ubcore_vtpn *ubcore_alloc_vtpn(struct ubcore_device *dev,
					     struct ubcore_vtp_param *param)
{
	struct ubcore_vtpn *vtpn;

	if (dev->ops == NULL || dev->ops->alloc_vtpn == NULL)
		return ERR_PTR(-EINVAL);

	vtpn = dev->ops->alloc_vtpn(dev);
	if (IS_ERR_OR_NULL(vtpn)) {
		ubcore_log_err("failed to alloc vtpn!, dev_name:%s",
			       dev->dev_name);
		return UBCORE_CHECK_RETURN_ERR_PTR(vtpn, UBCORE_DRV_ERRNO);
	}

	vtpn->ub_dev = dev;
	atomic_set(&vtpn->use_cnt, 0);
	kref_init(&vtpn->ref_cnt);
	init_completion(&vtpn->comp);
	vtpn->trans_mode = param->trans_mode;
	vtpn->local_eid = param->local_eid;
	vtpn->peer_eid = param->peer_eid;
	vtpn->eid_index = param->eid_index;
	vtpn->local_jetty = param->local_jetty;
	vtpn->peer_jetty = param->peer_jetty;
	vtpn->state = UBCORE_VTPS_RESET;
	mutex_init(&vtpn->state_lock);
	INIT_LIST_HEAD(&vtpn->list);
	INIT_LIST_HEAD(&vtpn->disconnect_list);
	return vtpn;
}

static struct ubcore_vtpn *
	ubcore_create_vtpn(struct ubcore_device *dev,
	struct ubcore_vtp_param *param,
	struct ubcore_active_tp_cfg *active_tp_cfg,
	struct ubcore_udata *udata)
{
	struct ubcore_vtpn *vtpn;

	vtpn = kcalloc(1, sizeof(struct ubcore_vtpn), GFP_KERNEL);
	if (IS_ERR_OR_NULL(vtpn))
		return NULL;

	vtpn->ub_dev = dev;
	atomic_set(&vtpn->use_cnt, 0);
	kref_init(&vtpn->ref_cnt);
	init_completion(&vtpn->comp);
	vtpn->trans_mode = param->trans_mode;
	vtpn->local_eid = param->local_eid;
	vtpn->peer_eid = param->peer_eid;
	vtpn->eid_index = param->eid_index;
	vtpn->local_jetty = param->local_jetty;
	vtpn->peer_jetty = param->peer_jetty;
	vtpn->state = UBCORE_VTPS_RESET;
	mutex_init(&vtpn->state_lock);
	INIT_LIST_HEAD(&vtpn->list);
	INIT_LIST_HEAD(&vtpn->disconnect_list);
	if (active_tp_cfg != NULL) {
		vtpn->vtpn = (uint32_t)active_tp_cfg->tp_handle.bs.tpid;
		vtpn->tp_handle = active_tp_cfg->tp_handle.value;
		vtpn->peer_tp_handle = active_tp_cfg->peer_tp_handle.value;
		vtpn->tag = active_tp_cfg->tag;
	}
	if (udata != NULL)
		vtpn->uspace = true;

	return vtpn;
}

static void ubcore_vtpn_kref_release(struct kref *ref_cnt)
{
	struct ubcore_vtpn *vtpn =
		container_of(ref_cnt, struct ubcore_vtpn, ref_cnt);

	complete(&vtpn->comp);
}

void ubcore_vtpn_kref_put(struct ubcore_vtpn *vtpn)
{
	(void)kref_put(&vtpn->ref_cnt, ubcore_vtpn_kref_release);
}

void ubcore_vtpn_get(void *obj)
{
	struct ubcore_vtpn *vtpn = obj;

	kref_get(&vtpn->ref_cnt);
}

static void ubcore_vtp_kref_release(struct kref *ref_cnt)
{
	struct ubcore_vtp *vtp =
		container_of(ref_cnt, struct ubcore_vtp, ref_cnt);
	struct ubcore_device *ub_dev = vtp->ub_dev;

	/* pseudo vtp */
	if (vtp->cfg.vtpn == UINT_MAX) {
		kfree(vtp);
		return;
	}
	if (ub_dev == NULL || ub_dev->ops == NULL ||
	    ub_dev->ops->destroy_vtp == NULL)
		return;
	ub_dev->ops->destroy_vtp(vtp);
}

void ubcore_vtp_kref_put(struct ubcore_vtp *vtp)
{
	ubcore_log_debug("put vtpn:%u, dev:%s,, refcnt to: %u", vtp->cfg.vtpn,
			 vtp->ub_dev->dev_name, kref_read(&vtp->ref_cnt) - 1);
	(void)kref_put(&vtp->ref_cnt, ubcore_vtp_kref_release);
}

void ubcore_vtp_get(void *obj)
{
	struct ubcore_vtp *vtp = obj;

	ubcore_log_debug("get vtpn:%u, dev:%s,, refcnt to: %u", vtp->cfg.vtpn,
			 vtp->ub_dev->dev_name, kref_read(&vtp->ref_cnt) + 1);
	kref_get(&vtp->ref_cnt);
}

static int ubcore_free_vtpn(struct ubcore_vtpn *vtpn)
{
	struct ubcore_device *dev = vtpn->ub_dev;

	if (dev == NULL || dev->ops == NULL || dev->ops->free_vtpn == NULL) {
		ubcore_log_err(
			"dev == NULL || dev->ops == NULL || dev->ops->free_vtpn == NULL");
		return -EINVAL;
	}

	if (atomic_read(&vtpn->use_cnt) > 0) {
		ubcore_log_info("vtpn in use, vtpn id = %u, vtpn use_cnt = %d",
				vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		return 0;
	}
	ubcore_vtpn_kref_put(vtpn);
	wait_for_completion(&vtpn->comp);
	mutex_destroy(&vtpn->state_lock);

	if (vtpn->tp_handle != 0) {
		kfree(vtpn);
		return 0;
	}
	return dev->ops->free_vtpn(vtpn);
}

static int ubcore_free_vtpn_ctrlplane(struct ubcore_vtpn *vtpn)
{
	if (atomic_read(&vtpn->use_cnt) > 0) {
		ubcore_log_info("vtpn in use, vtpn id = %u, vtpn use_cnt = %d",
				vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		return 0;
	}
	ubcore_vtpn_kref_put(vtpn);
	wait_for_completion(&vtpn->comp);
	mutex_destroy(&vtpn->state_lock);

	if (vtpn->tp_handle == 0)
		ubcore_log_err("Invalid tp_handle.\n");

	kfree(vtpn);
	return 0;
}

static struct ubcore_hash_table *
ubcore_get_vtpn_ht(struct ubcore_device *dev,
		   enum ubcore_transport_mode trans_mode)
{
	if (trans_mode == UBCORE_TP_RM)
		return &dev->ht[UBCORE_HT_RM_VTPN];

	if (trans_mode == UBCORE_TP_RC)
		return &dev->ht[UBCORE_HT_RC_VTPN];

	if (trans_mode == UBCORE_TP_UM)
		return &dev->ht[UBCORE_HT_UM_VTPN];

	return NULL;
}

static struct ubcore_vtpn *ubcore_find_get_vtpn(struct ubcore_device *dev,
						struct ubcore_vtp_param *param)
{
	struct ubcore_hash_table *ht;
	uint32_t hash;

	ht = ubcore_get_vtpn_ht(dev, param->trans_mode);
	if (ht == NULL)
		return NULL;

	hash = ubcore_get_vtpn_hash(ht, &param->local_eid);
	return ubcore_hash_table_lookup_get(ht, hash, &param->local_eid);
}

static int ubcore_find_add_vtpn(struct ubcore_device *dev,
				struct ubcore_vtpn *new_vtpn,
				struct ubcore_vtpn **exist_vtpn,
				struct ubcore_vtp_param *p)
{
	struct ubcore_hash_table *ht;
	uint32_t hash;

	ht = ubcore_get_vtpn_ht(dev, new_vtpn->trans_mode);
	if (ht == NULL || ht->head == NULL) {
		ubcore_log_err("hash table's head equals NULL");
		return -EINVAL;
	}
	hash = ubcore_get_vtpn_hash(ht, &new_vtpn->local_eid);

	spin_lock(&ht->lock);
	*exist_vtpn = ubcore_hash_table_lookup_nolock_get(ht, hash,
							  &new_vtpn->local_eid);
	if (*exist_vtpn != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}
	ubcore_hash_table_add_nolock(ht, &new_vtpn->hnode, hash);
	spin_unlock(&ht->lock);
	return 0;
}

static void ubcore_hash_table_rmv_vtpn(struct ubcore_device *dev,
				       struct ubcore_vtpn *vtpn)
{
	struct ubcore_hash_table *ht;

	ht = ubcore_get_vtpn_ht(dev, vtpn->trans_mode);
	if (ht == NULL)
		return;
	ubcore_hash_table_remove(ht, &vtpn->hnode);
}

static struct ubcore_vtpn *ubcore_reuse_vtpn(struct ubcore_device *dev,
					     struct ubcore_vtpn *vtpn)
{
	int i = 0;

	mutex_lock(&vtpn->state_lock);
	if (vtpn->state == UBCORE_VTPS_READY) {
		atomic_inc(&vtpn->use_cnt);
		mutex_unlock(&vtpn->state_lock);
		ubcore_log_info("Success to reuse vtpn:%u", vtpn->vtpn);
		ubcore_vtpn_kref_put(vtpn);
		return vtpn;
	}

	for (i = 0; i < UBCORE_SYNC_VTPN_MAX_WAIT_TIMES; i++) {
		if (vtpn->state == UBCORE_VTPS_READY) {
			atomic_inc(&vtpn->use_cnt);
			mutex_unlock(&vtpn->state_lock);
			ubcore_log_info("Success to reuse vtpn:%u", vtpn->vtpn);
			ubcore_vtpn_kref_put(vtpn);
			return vtpn;
		} else if (vtpn->state == UBCORE_VTPS_RESET) {
			mutex_unlock(&vtpn->state_lock);
			msleep(UBCORE_SYNC_REUSE_VTPN_ONE_TIME);
			mutex_lock(&vtpn->state_lock);
		} else if (vtpn->state == UBCORE_VTPS_WAIT_DESTROY) {
			break;
		}
	}
	ubcore_log_warn("failed to reuse vtpn:%u, use_cnt:%d", vtpn->vtpn,
			atomic_read(&vtpn->use_cnt));
	mutex_unlock(&vtpn->state_lock);
	ubcore_vtpn_kref_put(vtpn);
	return NULL;
}

struct ubcore_vtpn *ubcore_connect_vtp(struct ubcore_device *dev,
				       struct ubcore_vtp_param *param)
{
	struct ubcore_vtpn *exist_vtpn = NULL;
	struct ubcore_vtpn *vtpn;
	int ret;

	if (dev == NULL || param == NULL) {
		ubcore_log_err("Invalid param");
		return ERR_PTR(-EINVAL);
	}

	// 1. try to reuse vtpn
	vtpn = ubcore_find_get_vtpn(dev, param);
	if (vtpn != NULL)
		return ubcore_reuse_vtpn(dev, vtpn);

	// 2. alloc new vtpn
	vtpn = ubcore_alloc_vtpn(dev, param);
	if (IS_ERR_OR_NULL(vtpn)) {
		ubcore_log_err("failed to alloc vtpn!");
		return vtpn;
	}

	// 3. add vtpn to hashtable
	ret = ubcore_find_add_vtpn(dev, vtpn, &exist_vtpn, param);
	if (ret == -EEXIST && exist_vtpn != NULL) {
		exist_vtpn =
			ubcore_reuse_vtpn(dev, exist_vtpn); // reuse immediately
		(void)ubcore_free_vtpn(vtpn);
		return exist_vtpn;
	} else if (ret != 0) {
		(void)ubcore_free_vtpn(vtpn);
		return NULL;
	}

	// 4. Send connecting msg
	mutex_lock(&vtpn->state_lock);
	ret = ubcore_send_create_vtp_req(dev, param, vtpn);
	if (ret == 0) {
		atomic_inc(&vtpn->use_cnt);
		vtpn->state = UBCORE_VTPS_READY;
	} else {
		vtpn->state = UBCORE_VTPS_WAIT_DESTROY;
	}
	mutex_unlock(&vtpn->state_lock);

	// 5. failed roll back
	if (ret != 0) {
		ubcore_log_err("failed to send create vtp req, vtpn:%u",
			       vtpn->vtpn);
		ubcore_hash_table_rmv_vtpn(dev, vtpn);
		(void)ubcore_free_vtpn(vtpn);
		return ERR_PTR(ret);
	}

	ubcore_log_info("connect vtpn:%u, trans_mode:%u", vtpn->vtpn,
			vtpn->trans_mode);
	return vtpn;
}

static int ubcore_active_tp(struct ubcore_device *dev,
			    struct ubcore_active_tp_cfg *active_tp_cfg,
			    struct ubcore_vtpn *vtpn)
{
	int ret;

	if (dev->ops == NULL || dev->ops->active_tp == NULL ||
	    dev->ops->deactive_tp == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->active_tp(dev, active_tp_cfg);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to active tp, ret: %d, dev_name: %s.\n",
			       ret, dev->dev_name);
		return ret;
	}

	vtpn->vtpn = (uint32_t)active_tp_cfg->tp_handle.bs.tpid;
	return 0;
}

struct ubcore_vtpn *
ubcore_find_get_vtpn_ctrlplane(struct ubcore_device *dev,
			       struct ubcore_active_tp_cfg *active_tp_cfg)
{
	struct ubcore_hash_table *ht = &dev->ht[UBCORE_HT_CP_VTPN];
	uint32_t hash;

	hash = ubcore_get_vtpn_hash(ht, &active_tp_cfg->tp_handle.value);
	return ubcore_hash_table_lookup_get(ht, hash,
					    &active_tp_cfg->tp_handle.value);
}

static int ubcore_find_add_vtpn_ctrlplane(struct ubcore_device *dev,
					  struct ubcore_vtpn *new_vtpn,
					  struct ubcore_vtpn **exist_vtpn)
{
	struct ubcore_hash_table *ht = &dev->ht[UBCORE_HT_CP_VTPN];
	uint32_t hash;

	hash = ubcore_get_vtpn_hash(ht, &new_vtpn->tp_handle);

	spin_lock(&ht->lock);
	*exist_vtpn = ubcore_hash_table_lookup_nolock_get(ht, hash,
							  &new_vtpn->tp_handle);
	if (*exist_vtpn != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}
	ubcore_hash_table_add_nolock(ht, &new_vtpn->hnode, hash);
	spin_unlock(&ht->lock);
	return 0;
}

static void ubcore_hash_table_rmv_vtpn_ctrlplane(struct ubcore_device *dev,
						 struct ubcore_vtpn *vtpn)
{
	struct ubcore_hash_table *ht = &dev->ht[UBCORE_HT_CP_VTPN];

	ubcore_hash_table_remove(ht, &vtpn->hnode);
}

struct ubcore_vtpn *
	ubcore_connect_vtp_ctrlplane(struct ubcore_device *dev,
	struct ubcore_vtp_param *param,
	struct ubcore_active_tp_cfg *active_tp_cfg,
	struct ubcore_udata *udata)
{
	struct ubcore_vtpn *exist_vtpn = NULL;
	struct ubcore_vtpn *vtpn;
	struct ubcore_tpid_key key = { 0 };
	struct ubcore_tpid_ctx *ctx;
	struct ubcore_hash_table *ht = &dev->ht[UBCORE_HT_RC_TP_ID];
	int ret;

	key.local_eid = param->local_eid;
	key.peer_eid = param->peer_eid;
	key.local_jetty_id = param->local_jetty;
	key.peer_jetty_id = param->peer_jetty;
	ctx = ubcore_fget_tpid_ctx(dev, &key);

	// 1. try to reuse vtpn
	vtpn = ubcore_find_get_vtpn_ctrlplane(dev, active_tp_cfg);
	if (vtpn != NULL)
		return ubcore_reuse_vtpn(dev, vtpn);

	// 2. alloc new vtpn
	vtpn = ubcore_create_vtpn(dev, param, active_tp_cfg, udata);
	if (IS_ERR_OR_NULL(vtpn)) {
		ubcore_log_err("failed to alloc vtpn.\n");
		return vtpn;
	}

	// 3. add vtpn to hashtable
	ret = ubcore_find_add_vtpn_ctrlplane(dev, vtpn, &exist_vtpn);
	if (ret == -EEXIST && exist_vtpn != NULL) {
		exist_vtpn =
			ubcore_reuse_vtpn(dev, exist_vtpn); // reuse immediately
		(void)ubcore_free_vtpn_ctrlplane(vtpn);
		return exist_vtpn;
	} else if (ret != 0) {
		(void)ubcore_free_vtpn_ctrlplane(vtpn);
		return NULL;
	}

	// 4. active tp
	mutex_lock(&vtpn->state_lock);
	if (ctx && ctx->tp_state == UBCORE_TP_ACTIVE) {
		atomic_inc(&vtpn->use_cnt);
		vtpn->vtpn = (uint32_t)active_tp_cfg->tp_handle.bs.tpid;
		vtpn->tp_handle = ctx->tp_handle;
		vtpn->peer_tp_handle = ctx->peer_tp_handle;
		vtpn->state = UBCORE_VTPS_READY;
		mutex_unlock(&vtpn->state_lock);
		return vtpn;
	}
	ret = ubcore_active_tp(dev, active_tp_cfg, vtpn);
	if (ret == 0) {
		atomic_inc(&vtpn->use_cnt);
		vtpn->vtpn = (uint32_t)active_tp_cfg->tp_handle.bs.tpid;
		vtpn->state = UBCORE_VTPS_READY;
	} else {
		vtpn->state = UBCORE_VTPS_WAIT_DESTROY;
	}
	mutex_unlock(&vtpn->state_lock);

	// 5. failed roll back
	if (ret != 0) {
		ubcore_log_err("failed to active tp, vtpn:%u", vtpn->vtpn);
		ubcore_hash_table_rmv_vtpn_ctrlplane(dev, vtpn);
		(void)ubcore_free_vtpn_ctrlplane(vtpn);
		return ERR_PTR(ret);
	}

	if (ctx) {
		spin_lock(&ht->lock);
		ctx->tp_state = UBCORE_TP_ACTIVE;
		spin_unlock(&ht->lock);
	}


	ubcore_log_info("connect vtpn:%u, trans_mode:%u, tp_handle: %llu.\n",
			vtpn->vtpn, vtpn->trans_mode,
			active_tp_cfg->tp_handle.value);
	return vtpn;
}

struct ubcore_vtpn *
	ubcore_connect_rc_vtp_ctrlplane(struct ubcore_device *dev,
	struct ubcore_vtp_param *param,
	struct ubcore_active_tp_cfg *active_tp_cfg,
	struct ubcore_udata *udata)
{
	struct ubcore_vtpn *exist_vtpn = NULL;
	struct ubcore_vtpn *vtpn;
	int ret;

	// 1. try to reuse vtpn
	vtpn = ubcore_find_get_vtpn_ctrlplane(dev, active_tp_cfg);
	if (vtpn != NULL)
		return ubcore_reuse_vtpn(dev, vtpn);

	// 2. alloc new vtpn
	vtpn = ubcore_create_vtpn(dev, param, active_tp_cfg, udata);
	if (IS_ERR_OR_NULL(vtpn)) {
		ubcore_log_err("failed to alloc vtpn.\n");
		return vtpn;
	}

	// 3. add vtpn to hashtable
	ret = ubcore_find_add_vtpn_ctrlplane(dev, vtpn, &exist_vtpn);
	if (ret == -EEXIST && exist_vtpn != NULL) {
		exist_vtpn =
			ubcore_reuse_vtpn(dev, exist_vtpn); // reuse immediately
		(void)ubcore_free_vtpn_ctrlplane(vtpn);
		return exist_vtpn;
	} else if (ret != 0) {
		(void)ubcore_free_vtpn_ctrlplane(vtpn);
		return NULL;
	}

	// 4. active tp
	mutex_lock(&vtpn->state_lock);
	ret = ubcore_active_tp(dev, active_tp_cfg, vtpn);
	if (ret == 0) {
		atomic_inc(&vtpn->use_cnt);
		vtpn->vtpn = (uint32_t)active_tp_cfg->tp_handle.bs.tpid;
		vtpn->state = UBCORE_VTPS_READY;
	} else {
		vtpn->state = UBCORE_VTPS_WAIT_DESTROY;
	}
	mutex_unlock(&vtpn->state_lock);

	// 5. failed roll back
	if (ret != 0) {
		ubcore_log_err("failed to active tp, vtpn:%u", vtpn->vtpn);
		ubcore_hash_table_rmv_vtpn_ctrlplane(dev, vtpn);
		(void)ubcore_free_vtpn_ctrlplane(vtpn);
		return ERR_PTR(ret);
	}

	ubcore_log_info("connect vtpn:%u, trans_mode:%u, tp_handle: %llu.\n",
			vtpn->vtpn, vtpn->trans_mode,
			active_tp_cfg->tp_handle.value);
	return vtpn;
}

static struct ubcore_vtpn *
ubcore_reuse_vtpn_async(struct ubcore_device *dev, struct ubcore_vtpn *vtpn,
			struct ubcore_vtpn_cb_para *para)
{
	mutex_lock(&vtpn->state_lock);
	if (vtpn->state == UBCORE_VTPS_READY) {
		atomic_inc(&vtpn->use_cnt);
		para->tjetty->vtpn = vtpn;

		if (para->type == UBCORE_IMPORT_JETTY_VTPN) {
			para->import_cb->callback(para->tjetty, 0,
						  para->import_cb->user_arg);
			kfree(para->import_cb);
			para->import_cb = NULL;
		}
		if (para->type == UBCORE_BIND_JETTY_VTPN) {
			para->bind_cb->callback(para->jetty, para->tjetty, 0,
						para->bind_cb->user_arg);
			kfree(para->bind_cb);
			para->bind_cb = NULL;
		}

		mutex_unlock(&vtpn->state_lock);
		ubcore_log_info("Success to reuse ready vtpn:%u", vtpn->vtpn);
		ubcore_vtpn_kref_put(vtpn);
		return vtpn;
	}

	if (vtpn->state == UBCORE_VTPS_RESET) {
		atomic_inc(&vtpn->use_cnt);
		ubcore_add_async_wait_list(vtpn, para, NULL);
		mutex_unlock(&vtpn->state_lock);

		ubcore_log_info("Success to reuse reset vtpn:%u, use_cnt:%d",
				vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		ubcore_vtpn_kref_put(vtpn);
		return vtpn;
	}

	ubcore_log_err("Unknown states, vtpn:%u, state:%d", vtpn->vtpn,
		       (int)vtpn->state);
	mutex_unlock(&vtpn->state_lock);

	ubcore_vtpn_kref_put(vtpn);
	return NULL;
}

struct ubcore_vtpn *ubcore_connect_vtp_async(struct ubcore_device *dev,
					     struct ubcore_vtp_param *param,
					     int timeout,
					     struct ubcore_vtpn_cb_para *para)
{
	struct ubcore_vtpn *exist_vtpn = NULL;
	struct ubcore_vtpn *vtpn;
	struct ubcore_msg_session *s;
	struct ubcore_wait_vtpn_resp_work *wait_work;
	int ret;

	if (dev == NULL || param == NULL || para == NULL) {
		ubcore_log_err("Invalid param");
		return ERR_PTR(-EINVAL);
	}

	// 1. try to reuse vtpn
	vtpn = ubcore_find_get_vtpn(dev, param);
	if (vtpn != NULL)
		return ubcore_reuse_vtpn_async(dev, vtpn, para);

	// 2. alloc new vtpn
	vtpn = ubcore_alloc_vtpn(dev, param);
	if (IS_ERR_OR_NULL(vtpn)) {
		ubcore_log_err("failed to alloc vtpn!");
		return vtpn;
	}

	// 3. add vtpn to hashtable
	ret = ubcore_find_add_vtpn(dev, vtpn, &exist_vtpn, param);
	if (ret == -EEXIST && exist_vtpn != NULL) {
		exist_vtpn = ubcore_reuse_vtpn_async(dev, exist_vtpn,
						     para); // reuse immediately
		(void)ubcore_free_vtpn(vtpn);
		return exist_vtpn;
	} else if (ret != 0) {
		(void)ubcore_free_vtpn(vtpn);
		return NULL;
	}

	// 4. Send connecting msg and do not wait resp
	mutex_lock(&vtpn->state_lock);
	atomic_inc(&vtpn->use_cnt);
	wait_work =
		ubcore_queue_wait_connect_vtp_resp_task(dev, param, timeout);
	if (wait_work == NULL) {
		ubcore_log_err(
			"failed to queue wait connect vtp resp task, vtpn:%u",
			vtpn->vtpn);
		goto ERR_WQ_WORK;
	}

	s = ubcore_create_async_connect_vtp_req(dev, param, vtpn);
	if (s == NULL) {
		ubcore_log_err(
			"failed to create connect vtp req and session, vtpn:%u",
			vtpn->vtpn);
		goto ERR_SESSION;
	}
	wait_work->s = s;
	wait_work->msg_id = s->req->msg_id;
	ubcore_add_async_wait_list(vtpn, para, wait_work);
	mutex_unlock(&vtpn->state_lock);

	ret = ubcore_send_req(dev, s->req);
	if (ret != 0) {
		ubcore_log_err(
			"Failed to send req, msg_id = %u, opcode = %u.\n",
			s->req->msg_id, (uint16_t)s->req->opcode);
		if (!ubcore_set_session_finish(s)) {
			ubcore_log_err(
				"Failed to lock session or session state is finish, msg_id = %u, opcode = %u.\n",
				s->req->msg_id, (uint16_t)s->req->opcode);
			(void)kref_put(&s->kref, ubcore_free_msg_session);
			return vtpn;
		}
		kfree(s->req);
		(void)kref_put(&s->kref, ubcore_free_msg_session);
		ubcore_destroy_msg_session(s);

		mutex_lock(&vtpn->state_lock);
		ubcore_del_async_wait_list(vtpn);
		goto ERR_SESSION;
	}

	ubcore_log_info("connect asynchronously vtpn:%u, trans_mode:%u",
			vtpn->vtpn, vtpn->trans_mode);
	(void)kref_put(&s->kref, ubcore_free_msg_session);
	return vtpn;

ERR_SESSION:
	cancel_delayed_work_sync(&wait_work->delay_work);
	if (wait_work != NULL)
		kfree(wait_work);
ERR_WQ_WORK:
	atomic_dec(&vtpn->use_cnt);
	vtpn->state = UBCORE_VTPS_WAIT_DESTROY;
	ubcore_hash_table_rmv_vtpn(dev, vtpn);
	mutex_unlock(&vtpn->state_lock);
	(void)ubcore_free_vtpn(vtpn);
	return NULL;
}

int ubcore_disconnect_vtp(struct ubcore_vtpn *vtpn)
{
	struct ubcore_device *dev;
	uint64_t tp_handle;
	int ret = 0;

	if (vtpn == NULL || vtpn->ub_dev == NULL)
		return -EINVAL;

	tp_handle = vtpn->tp_handle;
	dev = vtpn->ub_dev;
	mutex_lock(&vtpn->state_lock);
	if (atomic_dec_return(&vtpn->use_cnt) > 0) {
		ubcore_log_info("vtpn in use, vtpn id = %u, vtpn use_cnt = %d",
				vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		mutex_unlock(&vtpn->state_lock);
		return 0;
	}
	if (tp_handle == 0)
		ubcore_hash_table_rmv_vtpn(dev, vtpn);
	else
		ubcore_hash_table_rmv_vtpn_ctrlplane(dev, vtpn);

	if (atomic_read(&vtpn->use_cnt) > 0) {
		mutex_unlock(&vtpn->state_lock);
		return 0;
	}

	if (vtpn->state == UBCORE_VTPS_READY) {
		if (tp_handle != 0)
			ret = ubcore_adapter_layer_disconnect(vtpn);
		else
			ret = ubcore_send_del_vtp_req(vtpn);
		vtpn->state = UBCORE_VTPS_WAIT_DESTROY;
	} else {
		ubcore_log_info("vtp in deleted state, vtpn:%u, state%u",
				vtpn->vtpn, vtpn->state);
	}
	ubcore_log_info_rl("disconnect vtpn:%u, ret:%d, vtp_state:%u",
			   vtpn->vtpn, ret, vtpn->state);
	mutex_unlock(&vtpn->state_lock);

	if (atomic_read(&vtpn->use_cnt) == 0) {
		if (ret == 0 || ret == -ENOENT ||
		    (vtpn->tp_handle == 0 &&
		     ubcore_queue_destroy_vtp_task(dev, vtpn, 0) != 0)) {
			if (tp_handle != 0)
				(void)ubcore_free_vtpn_ctrlplane(vtpn);
			else
				(void)ubcore_free_vtpn(vtpn);
		}
	}

	return (tp_handle != 0) ? ret : 0;
}

int ubcore_disconnect_vtp_async(struct ubcore_vtpn *vtpn, int timeout,
				struct ubcore_vtpn_cb_para *para)
{
	struct ubcore_device *dev;
	struct ubcore_unimport_cb *unimport_cb;
	struct ubcore_unbind_cb *unbind_cb;
	struct ubcore_msg_session *s;
	struct ubcore_wait_vtpn_resp_work *wait_work;
	int ret;

	if (vtpn == NULL || vtpn->ub_dev == NULL || para == NULL)
		return -EINVAL;

	dev = vtpn->ub_dev;
	mutex_lock(&vtpn->state_lock);
	if (atomic_dec_return(&vtpn->use_cnt) > 0) {
		ubcore_log_info("vtpn in use, vtpn id = %u, vtpn use_cnt = %d",
				vtpn->vtpn, atomic_read(&vtpn->use_cnt));

		if (para->unimport_cb != NULL) {
			unimport_cb = para->unimport_cb;
			unimport_cb->callback(0, unimport_cb->user_arg);
			kfree(unimport_cb);
		}

		if (para->unbind_cb != NULL) {
			unbind_cb = para->unbind_cb;
			unbind_cb->callback(0, unbind_cb->user_arg);
			kfree(unbind_cb);
		}
		mutex_unlock(&vtpn->state_lock);
		return 0;
	}

	if (atomic_read(&vtpn->use_cnt) > 0) {
		mutex_unlock(&vtpn->state_lock);
		return 0;
	}

	ubcore_hash_table_rmv_vtpn(dev, vtpn);
	if (vtpn->state == UBCORE_VTPS_READY) {
		vtpn->state = UBCORE_VTPS_WAIT_DESTROY;
		wait_work = ubcore_queue_wait_disconnect_vtp_resp_task(
			dev, vtpn, timeout);
		if (wait_work == NULL) {
			ubcore_log_err(
				"failed to queue wait disconnect vtp resp task, vtpn:%u",
				vtpn->vtpn);
			goto ERR_WQ_WORK;
		}

		s = ubcore_create_async_disconnect_vtp_req(vtpn);
		if (s == NULL) {
			ubcore_log_err(
				"failed to create disconnect vtp req and session, vtpn:%u",
				vtpn->vtpn);
			goto ERR_SESSION;
		}
		wait_work->s = s;
		wait_work->msg_id = s->req->msg_id;
		ubcore_add_async_wait_list(vtpn, para, wait_work);
		mutex_unlock(&vtpn->state_lock);

		ret = ubcore_send_req(dev, s->req);
		if (ret != 0) {
			ubcore_log_err(
				"Failed to send req, msg_id = %u, opcode = %u.\n",
				s->req->msg_id, (uint16_t)s->req->opcode);
			if (!ubcore_set_session_finish(s)) {
				ubcore_log_err(
					"Failed to trylock_and_modify_state, msg_id = %u, opcode = %u.\n",
					s->req->msg_id,
					(uint16_t)s->req->opcode);
				(void)kref_put(&s->kref,
					       ubcore_free_msg_session);
				return 0;
			}
			kfree(s->req);
			(void)kref_put(&s->kref, ubcore_free_msg_session);
			ubcore_destroy_msg_session(s);

			mutex_lock(&vtpn->state_lock);
			ubcore_del_async_wait_list(vtpn);
			goto ERR_SESSION;
		}

		(void)kref_put(&s->kref, ubcore_free_msg_session);
	} else {
		ubcore_log_info("vtp in deleted state, vtpn:%u, state%u",
				vtpn->vtpn, vtpn->state);
		mutex_unlock(&vtpn->state_lock);
	}

	return 0;

ERR_SESSION:
	cancel_delayed_work_sync(&wait_work->delay_work);
	if (wait_work != NULL)
		kfree(wait_work);
ERR_WQ_WORK:
	mutex_unlock(&vtpn->state_lock);
	if (atomic_read(&vtpn->use_cnt) == 0) {
		if (ubcore_queue_destroy_vtp_task(dev, vtpn, 0) != 0)
			(void)ubcore_free_vtpn(vtpn);
	}
	return 0;
}

int ubcore_process_vtp_status_nofity(struct ubcore_device *dev,
				     struct ubcore_vtp_status_notify *msg)
{
	struct ubcore_vtp_param param;
	struct ubcore_vtpn *vtpn;

	if (msg->status != UBCORE_VTPS_DELETED)
		return 0;

	ubcore_log_info("notify vtpn:%u, trans_mode:%u, seid :" EID_FMT
			", deid:" EID_FMT " ",
			msg->vtpn, msg->trans_mode, EID_ARGS(msg->local_eid),
			EID_ARGS(msg->peer_eid));

	memset(&param, 0, sizeof(param));
	param.trans_mode = msg->trans_mode;
	param.local_eid = msg->local_eid;
	param.local_jetty = msg->local_jetty_id;
	param.peer_eid = msg->peer_eid;
	param.peer_jetty = msg->peer_jetty_id;

	vtpn = ubcore_find_get_vtpn(dev, &param);
	if (!vtpn)
		return 0;

	mutex_lock(&vtpn->state_lock);
	if (vtpn->vtpn != msg->vtpn) {
		ubcore_log_warn("ubcore vtpn:%u, msg vtpn%u not equal",
				vtpn->vtpn, msg->vtpn);
		mutex_unlock(&vtpn->state_lock);
		ubcore_vtpn_kref_put(vtpn);
		return 0;
	}

	ubcore_handle_vtpn_wait_list(vtpn, dev, UBCORE_VTPS_ERROR,
				     ECONNREFUSED);
	mutex_unlock(&vtpn->state_lock);

	ubcore_hash_table_rmv_vtpn(dev, vtpn);

	ubcore_log_info("vtpn:%u, trans to delete state", vtpn->vtpn);
	ubcore_vtpn_kref_put(vtpn);
	return 0;
}

static int ubcore_find_add_vtp(struct ubcore_device *dev,
			       enum ubcore_transport_mode mode,
			       struct ubcore_vtp *vtp)
{
	struct ubcore_hash_table *ht = NULL;
	uint32_t hash;

	switch (mode) {
	case UBCORE_TP_RM:
		ht = &dev->ht[UBCORE_HT_RM_VTP];
		hash = ubcore_get_vtp_hash(&vtp->cfg.local_eid);
		break;
	case UBCORE_TP_RC:
		ht = &dev->ht[UBCORE_HT_RC_VTP];
		hash = ubcore_get_rc_vtp_hash(&vtp->cfg.peer_eid);
		break;
	case UBCORE_TP_UM:
		ht = &dev->ht[UBCORE_HT_UM_VTP];
		hash = ubcore_get_vtp_hash(&vtp->cfg.local_eid);
		break;
	default:
		ubcore_log_err("unknown mode");
		return -EINVAL;
	}
	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return -1;
	}
	/* Old entry with the same key exists */
	if (ubcore_hash_table_lookup_nolock(
		    ht, hash, ubcore_ht_key(ht, &vtp->hnode)) != NULL) {
		spin_unlock(&ht->lock);
		ubcore_log_warn("find vtp vtpn:%u hash :%u", vtp->cfg.vtpn,
				hash);
		return -1;
	}
	ubcore_hash_table_add_nolock(ht, &vtp->hnode, hash);
	ubcore_vtp_get(vtp);
	spin_unlock(&ht->lock);

	return 0;
}

static void ubcore_vtp_map_attr(struct ubcore_vtp *vtp,
				struct ubcore_vtp_cfg *cfg)
{
	vtp->cfg.ue_idx = cfg->ue_idx;
	vtp->cfg.local_jetty = cfg->local_jetty;
	vtp->cfg.local_eid = cfg->local_eid;
	vtp->cfg.peer_eid = cfg->peer_eid;
	vtp->cfg.peer_jetty = cfg->peer_jetty;
	vtp->cfg.flag = cfg->flag;
	vtp->cfg.trans_mode = cfg->trans_mode;
}

struct ubcore_vtp *ubcore_create_and_map_vtp(struct ubcore_device *dev,
					     struct ubcore_vtp_cfg *cfg)
{
	struct ubcore_vtp *vtp;
	int ret;

	if (dev->ops == NULL || dev->ops->create_vtp == NULL)
		return ERR_PTR(-EINVAL);

	vtp = dev->ops->create_vtp(dev, cfg, NULL);
	if (IS_ERR_OR_NULL(vtp)) {
		ubcore_log_err("Failed to create vtp");
		if (vtp == NULL)
			return ERR_PTR(-ENOEXEC);
		return vtp;
	}
	kref_init(&vtp->ref_cnt);
	vtp->ub_dev = dev;
	ubcore_vtp_map_attr(vtp, cfg);

	ret = ubcore_find_add_vtp(dev, cfg->trans_mode, vtp);
	if (ret != 0) {
		ubcore_vtp_kref_put(vtp);
		vtp = NULL;
		ubcore_log_err("Failed to add vtp to the vtp table");
		return ERR_PTR(-ENOEXEC);
	}

	return vtp;
}

static void ubcore_remove_vtp(struct ubcore_device *dev,
			      enum ubcore_transport_mode mode,
			      struct ubcore_vtp *vtp)
{
	struct ubcore_hash_table *ht = NULL;
	struct ubcore_vtp *find_vtp = NULL;
	uint32_t hash;

	switch (mode) {
	case UBCORE_TP_RM:
		ht = &dev->ht[UBCORE_HT_RM_VTP];
		hash = ubcore_get_vtp_hash(&vtp->cfg.local_eid);
		break;
	case UBCORE_TP_RC:
		ht = &dev->ht[UBCORE_HT_RC_VTP];
		hash = ubcore_get_rc_vtp_hash(&vtp->cfg.peer_eid);
		break;
	case UBCORE_TP_UM:
		ht = &dev->ht[UBCORE_HT_UM_VTP];
		hash = ubcore_get_vtp_hash(&vtp->cfg.local_eid);
		break;
	default:
		ubcore_log_err("unknown mode");
		return;
	}
	spin_lock(&ht->lock);
	find_vtp = ubcore_hash_table_lookup_nolock(
		ht, hash, ubcore_ht_key(ht, &vtp->hnode));
	if (find_vtp == NULL) {
		spin_unlock(&ht->lock);
		ubcore_log_warn("vtp:%d no find", vtp->cfg.vtpn);
		return;
	}
	ubcore_hash_table_remove_nolock(ht, &find_vtp->hnode);
	/* Pair with kref get in ubcore_find_add_vtp */
	ubcore_vtp_kref_put(find_vtp);
	spin_unlock(&ht->lock);
}

int ubcore_unmap_vtp(struct ubcore_vtp *vtp)
{
	struct ubcore_device *dev = NULL;
	struct ubcore_vtp_cfg cfg;
	int ret = 0;

	if (vtp == NULL)
		return -EINVAL;

	dev = vtp->ub_dev;
	if (dev == NULL || dev->ops == NULL || dev->ops->destroy_vtp == NULL)
		return -EINVAL;

	cfg = vtp->cfg;

	ubcore_remove_vtp(dev, cfg.trans_mode, vtp);

	return ret;
}

int ubcore_check_and_unmap_vtp(struct ubcore_vtp *vtp, uint32_t role)
{
	struct ubcore_device *dev = NULL;
	struct ubcore_vtp *new_vtp = NULL;
	struct ubcore_vtp_cfg cfg;
	int ret = 0;

	if (vtp == NULL || vtp->ub_dev == NULL || vtp->ub_dev->ops == NULL ||
	    vtp->ub_dev->ops->destroy_vtp == NULL)
		return -EINVAL;

	dev = vtp->ub_dev;

	if (vtp->role != UBCORE_VTP_DUPLEX)
		return ubcore_unmap_vtp(vtp);

	cfg = vtp->cfg;

	if (role == UBCORE_VTP_INITIATOR) {
		// delete original vtp, create pseudo vtp
		new_vtp = kcalloc(1, sizeof(struct ubcore_vtp), GFP_KERNEL);
		if (new_vtp == NULL)
			return -ENOMEM;

		new_vtp->ub_dev = dev;
		new_vtp->role = UBCORE_VTP_TARGET;
		new_vtp->eid_idx = vtp->eid_idx;
		new_vtp->upi = vtp->upi;
		new_vtp->share_mode = vtp->share_mode;
		ubcore_vtp_map_attr(new_vtp, &vtp->cfg);
		new_vtp->cfg.vtpn = UINT_MAX;
		kref_init(&new_vtp->ref_cnt);

		ubcore_remove_vtp(dev, cfg.trans_mode, vtp);

		ret = ubcore_find_add_vtp(dev, new_vtp->cfg.trans_mode,
					  new_vtp);
		ubcore_vtp_kref_put(new_vtp);
		if (ret != 0) {
			ubcore_log_err(
				"Failed to add new vtp to the vtp table");
			return -1;
		}
	} else {
		vtp->role = UBCORE_VTP_INITIATOR;
	}

	return ret;
}

struct ubcore_vtp *ubcore_find_vtp(struct ubcore_device *dev,
				   enum ubcore_transport_mode mode,
				   union ubcore_eid *local_eid,
				   union ubcore_eid *peer_eid)
{
	struct ubcore_vtp *vtp_entry;

	switch (mode) {
	case UBCORE_TP_RM:
		vtp_entry = ubcore_hash_table_lookup(
			&dev->ht[UBCORE_HT_RM_VTP],
			ubcore_get_vtp_hash(local_eid), local_eid);
		break;
	case UBCORE_TP_RC:
		vtp_entry = ubcore_hash_table_lookup(
			&dev->ht[UBCORE_HT_RC_VTP],
			ubcore_get_rc_vtp_hash(peer_eid), peer_eid);
		break;
	case UBCORE_TP_UM:
		vtp_entry = ubcore_hash_table_lookup(
			&dev->ht[UBCORE_HT_UM_VTP],
			ubcore_get_vtp_hash(local_eid), local_eid);
		break;
	default:
		ubcore_log_err("unknown mode %u", mode);
		vtp_entry = NULL;
	}
	return vtp_entry;
}

struct ubcore_vtp *ubcore_find_get_vtp(struct ubcore_device *dev,
				       enum ubcore_transport_mode mode,
				       union ubcore_eid *local_eid,
				       union ubcore_eid *peer_eid)
{
	struct ubcore_vtp *vtp_entry;

	switch (mode) {
	case UBCORE_TP_RM:
		vtp_entry = ubcore_hash_table_lookup_get(
			&dev->ht[UBCORE_HT_RM_VTP],
			ubcore_get_vtp_hash(local_eid), local_eid);
		break;
	case UBCORE_TP_RC:
		vtp_entry = ubcore_hash_table_lookup_get(
			&dev->ht[UBCORE_HT_RC_VTP],
			ubcore_get_rc_vtp_hash(peer_eid), peer_eid);
		break;
	case UBCORE_TP_UM:
		vtp_entry = ubcore_hash_table_lookup_get(
			&dev->ht[UBCORE_HT_UM_VTP],
			ubcore_get_vtp_hash(local_eid), local_eid);
		break;
	default:
		ubcore_log_err("unknown mode");
		vtp_entry = NULL;
	}
	return vtp_entry;
}

void ubcore_set_vtp_param(struct ubcore_device *dev, struct ubcore_jetty *jetty,
			  struct ubcore_tjetty_cfg *cfg,
			  struct ubcore_vtp_param *vtp_param)
{
	if (cfg->eid_index >= dev->eid_table.eid_cnt ||
	    IS_ERR_OR_NULL(dev->eid_table.eid_entries)) {
		ubcore_log_err("invalid param, eid_index[%u] >= eid_cnt[%u]",
			       cfg->eid_index, dev->eid_table.eid_cnt);
		return;
	}

	vtp_param->trans_mode = cfg->trans_mode;

	if (is_create_rc_shared_tp(cfg->trans_mode, cfg->flag.bs.order_type,
				   cfg->flag.bs.share_tp))
		vtp_param->trans_mode = UBCORE_TP_RM;

	/*
	 * RM/UM VTP for userspace app: get local eid from ucontext
	 * RM/UM VTP for kernel app: how to get local eid ?
	 * RC VTP: get eid from jetty
	 */
	vtp_param->local_eid = dev->eid_table.eid_entries[cfg->eid_index].eid;
	vtp_param->peer_eid = cfg->id.eid;
	if (jetty != NULL)
		vtp_param->local_jetty = jetty->jetty_id.id;
	else
		vtp_param->local_jetty = 0;

	vtp_param->peer_jetty = cfg->id.id;
	vtp_param->eid_index = cfg->eid_index;
}

uint32_t ubcore_get_all_vtp_cnt(struct ubcore_hash_table *ht,
				struct ubcore_device *dev,
				uint32_t target_uvs_id)
{
	struct ubcore_vtp *vtp;
	uint32_t cnt = 0;
	uint32_t i = 0;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return cnt;
	}

	for (; i < ht->p.size; i++) {
		hlist_for_each_entry(vtp, &ht->head[i], hnode) {
			++cnt;
		}
	}

	spin_unlock(&ht->lock);
	return cnt;
}

static void ubcore_delay_destroy_vtp(struct work_struct *work)
{
	struct ubcore_vtp_work *vtp_work;
	int ret;

	vtp_work = container_of(work, struct ubcore_vtp_work, delay_work.work);
	ubcore_del_vtp_work_list(vtp_work);

	// To handle dev unregistering
	if (!ubcore_check_dev_is_exist(vtp_work->dev->dev_name)) {
		ubcore_log_warn("dev %s not exist\n", vtp_work->dev->dev_name);
		(void)ubcore_free_vtpn(vtp_work->vtpn);
		goto free_work;
	}

	ret = ubcore_send_del_vtp_req(vtp_work->vtpn);

	vtp_work->retry_times++;
	ubcore_log_info("Retry to destroy vtpn:%u, retry_time:%u, ret:%d",
			vtp_work->vtpn->vtpn, vtp_work->retry_times, ret);

	if (ret == 0 || ret == -ENOENT ||
	    ubcore_queue_destroy_vtp_task(vtp_work->dev, vtp_work->vtpn,
					  vtp_work->retry_times) != 0)
		(void)ubcore_free_vtpn(vtp_work->vtpn);

free_work:
	ubcore_put_device(vtp_work->dev);
	kfree(vtp_work);
}

int ubcore_queue_destroy_vtp_task(struct ubcore_device *dev,
				  struct ubcore_vtpn *vtpn,
				  uint32_t retry_times)
{
	struct ubcore_vtp_work *vtp_work;
	uint32_t timeout;
	int ret;

	if (retry_times >= DESTROY_VTP_MAX_RETRY_TIMES)
		return -EINVAL;

	vtp_work = kzalloc(sizeof(struct ubcore_vtp_work), GFP_KERNEL);
	if (vtp_work == NULL)
		return -ENOMEM;

	vtp_work->dev = ubcore_find_device_with_name(
		dev->dev_name); // to prevent dev unregistering
	if (vtp_work->dev == NULL) {
		kfree(vtp_work);
		return -EINVAL;
	}

	vtp_work->vtpn = vtpn;
	vtp_work->type = UBCORE_TASK_DESTROY_VTP;
	vtp_work->retry_times = retry_times;
	INIT_DELAYED_WORK(&vtp_work->delay_work, ubcore_delay_destroy_vtp);

	timeout = (1 << retry_times) * DESTROY_VTP_INI_INTERVAL;

	ubcore_log_info(
		"queue delay work to destroy vtpn:%u, dev:%s, retry_time:%u",
		vtp_work->vtpn->vtpn, dev->dev_name, retry_times);

	ret = ubcore_queue_delayed_work(UBCORE_VTP_TASK_WQ,
					&vtp_work->delay_work,
					msecs_to_jiffies(timeout));
	if (ret != 0) {
		ubcore_log_warn("Fail to queue destroy vtp work");
		ubcore_put_device(vtp_work->dev);
		kfree(vtp_work);
		return ret;
	}

	ubcore_add_vtp_work_list(vtp_work);
	return 0;
}

struct ubcore_vtp **ubcore_get_all_vtp(struct ubcore_hash_table *ht,
				       struct ubcore_device *dev,
				       uint32_t target_uvs_id,
				       uint32_t *dev_vtp_cnt)
{
	struct ubcore_vtp **vtp_entry;
	struct ubcore_vtp *vtp;
	uint32_t i = 0, j = 0;

	*dev_vtp_cnt = ubcore_get_all_vtp_cnt(ht, dev, target_uvs_id);
	if (*dev_vtp_cnt == 0)
		return NULL;

	vtp_entry = kcalloc(
		1, (*dev_vtp_cnt) * (uint32_t)sizeof(struct ubcore_vtp *),
		GFP_KERNEL);
	if (vtp_entry == NULL)
		return NULL;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		kfree(vtp_entry);
		return NULL;
	}

	for (; i < ht->p.size; i++) {
		hlist_for_each_entry(vtp, &ht->head[i], hnode) {
			vtp_entry[j++] = vtp;
		}
	}

	spin_unlock(&ht->lock);
	return vtp_entry;
}
