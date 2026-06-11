// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "ubus hisi vdm: " fmt

#include "../../ubus.h"
#include "../../msg.h"
#include "../../pool.h"
#include "../../instance.h"
#include "../../ubus_entity.h"
#include "../../task.h"
#include "../../link.h"
#include "hisi-msg.h"
#include "hisi-ubus.h"
#include "vdm.h"

struct opcode_func_map {
	u16 sub_opcode;
	u16 idev_pkt_size;
	char print_info[16];
	u8 (*idev_handler)(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt);
	int idev_pld_size;
};

static void ub_vdm_msg_rsp(struct ub_bus_controller *ubc,
				struct vdm_msg_pkt *pkt, u8 status)
{
	struct msg_pkt_header *header = &pkt->header;
	struct msg_info info = {};
	bool local;
	u32 size;
	int ret;

	size = (MSG_PKT_HEADER_SIZE + VENDOR_GUID_PLD_SIZE +
		VDM_MSG_DW0_PLD_SIZE) << MSG_REQ_SIZE_OFFSET;

	local = ub_rsp_msg_init(header, status,
				VENDOR_GUID_PLD_SIZE + VDM_MSG_DW0_PLD_SIZE);

	message_info_init(&info, local ? ubc->uent : NULL, pkt, NULL, size);
	ret = message_response(ubc->mdev, &info, header->msgetah.code);
	if (ret)
		dev_err(&ubc->dev, "send vdm response message failed, ret=%d\n", ret);
}

static int ub_idevice_enable_handle(struct ub_entity *pue, u16 idx, u8 is_mue,
				    struct ue_map *map, u32 ueid)
{
	struct ub_delay_task *task;
	struct ub_entity *dev;
	int ret;

	dev = ub_alloc_ent();
	if (!dev)
		return -ENOMEM;

	task = ub_delay_task_alloc_and_init(dev, NULL, TASK_TYPE_START);
	if (IS_ERR(task)) {
		kfree(dev);
		return PTR_ERR(task);
	}

	dev->pool = true;
	dev->entity_idx = idx;
	dev->pue = ub_entity_get(pue);
	dev->dev.parent = &pue->dev;
	dev->ubc = pue->ubc;
	dev->cna = pue->cna;
	dev->upi = pue->upi;
	dev->user_eid = ueid;

	if (is_mue) {
		dev->is_mue = is_mue;
		dev->uem.start_entity_idx = map->start_entity_idx;
		dev->uem.end_entity_idx = map->end_entity_idx;
		dev->total_ues = map->end_entity_idx - map->start_entity_idx + 1;
		if (map->start_entity_idx == dev->entity_idx)
			dev->total_ues = 0;
		dev->is_vdm_idev = 1;
	}

	ret = ub_setup_ent(dev);
	if (ret < 0) {
		ub_entity_put(pue);
		ub_delay_task_free(task);
		kfree(dev);
		return -ENOEXEC;
	}

	ub_entity_add(dev, pue);
	atomic_set(&dev->ent_mgmt_state, MGMT_STATE_REGISTERING);

	ub_entity_assign_task_src(dev, TASK_SRC_VDM, true);
	queue_work(ub_get_delay_task_wq(), &task->work);
	return 0;
}

/* Should call ub_entity_put after unused */
static u8 ub_get_entity0(struct ub_bus_controller *ubc, struct ub_guid *guid,
			 bool mue, bool reg, struct ub_entity **uent)
{
	struct ub_entity *ent0;
	char buf[SZ_64] = {};

	/* get entity0 by guid in message payload */
	ent0 = ub_get_ent_by_guid(guid);
	if (!ent0) {
		(void)ub_show_guid(guid, buf);
		dev_err(&ubc->dev, "find entity0[%s] in %s %s failed\n", buf,
			mue ? "mue" : "ue", reg ? "reg" : "unreg");
		return UB_MSG_RSP_EXEC_ENODEV;
	}

	if (ent_in_unregistering(ent0)) {
		ub_err(ent0, "entity0 is unregistering in %s %s\n",
		       mue ? "mue" : "ue", reg ? "reg" : "unreg");
		ub_entity_put(ent0);
		return UB_MSG_RSP_EXEC_EBUSY;
	}

	*uent = ent0;
	return UB_MSG_RSP_SUCCESS;
}

static u8 ub_get_ue_map(struct ub_entity *uent, struct idev_pue_reg_pld *pld,
			struct ue_map *map)
{
	u8 status = UB_MSG_RSP_SUCCESS;

	if (!pld->ue_cnt) {
		map->start_entity_idx = pld->pue_entity_idx;
		map->end_entity_idx = pld->pue_entity_idx;
	} else if (pld->ue_cnt !=
		   pld->end_ue_entity_idx - pld->start_ue_entity_idx + 1) {
		ub_err(uent, "Invalid ue cnt: [%u] The ue cnt must be equal to end: [%d] - start: [%d] + 1\n",
		       pld->ue_cnt, pld->end_ue_entity_idx,
		       pld->start_ue_entity_idx);
		status = UB_MSG_RSP_EXEC_EINVAL;
	} else {
		map->start_entity_idx = pld->start_ue_entity_idx;
		map->end_entity_idx = pld->end_ue_entity_idx;
	}

	return status;
}

u8 ub_idevice_pue_add_handler(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct idev_pue_reg_pld *pld = &pkt->pd_reg_pld;
	struct ub_entity *pue, *uent;
	struct ue_map map = {};
	u8 status;
	int ret;

	status = ub_get_entity0(ubc, (struct ub_guid *)pld->guid, true, true,
				&pue);
	if (status)
		goto pue_reg_rsp;

	status = ub_get_ue_map(pue, pld, &map);
	if (status)
		goto put_pue;

	if (!ub_bus_instance_exist(pld->user_eid[0])) {
		ub_err(pue, "mue add msg user eid[%#x] does not exist\n",
		       pld->user_eid[0]);
		status = UB_MSG_RSP_EXEC_EINVAL;
		goto put_pue;
	}

	uent = ub_find_entity(pue, true, pld->pue_entity_idx);
	if (uent) {
		ub_warn(pue, "The mue idx[%u] already exists\n",
			pld->pue_entity_idx);
		ret = ub_create_existed_entity_handler(uent);
		status = err_to_msg_rsp(ret);
		ub_entity_put(uent);
	} else { /* create mue */
		ret = ub_idevice_enable_handle(pue, pld->pue_entity_idx, 1,
					       &map, pld->user_eid[0]);
		if (ret)
			ub_err(pue, "enable mue[%u] failed, ret[%d]\n",
			       pld->pue_entity_idx, ret);
		else
			ub_info(pue, "enable mue[%u] succeeded, user_eid=0x%x\n",
				pld->pue_entity_idx, pld->user_eid[0]);

		status = err_to_msg_rsp(ret);
	}

put_pue:
	ub_entity_put(pue);
pue_reg_rsp:
	ub_vdm_msg_rsp(ubc, pkt, status);
	dev_info(&ubc->dev, "MUE reg: guid[%#llx-%#llx] idx[%u] cnt[%u] start[%u] end[%u] ueid[%#x] status[%#x]\n",
		 *(u64 *)&pld->guid[SZ_2], *(u64 *)pld->guid, pld->pue_entity_idx,
		 pld->ue_cnt, pld->start_ue_entity_idx, pld->end_ue_entity_idx,
		 pld->user_eid[0], status);
	return status;
}

/* API for ue reg/unreg, Should call ub_entity_put after unused */
static u8 ub_get_mue(struct ub_bus_controller *ubc, struct ub_guid *guid,
		     u16 idx, bool reg, struct ub_entity **uent)
{
	struct ub_entity *ent0, *mue;
	u8 status;

	status = ub_get_entity0(ubc, guid, false, reg, &ent0);
	if (status)
		return status;

	if (idx == 0) {
		*uent = ent0;
		return UB_MSG_RSP_SUCCESS;
	}

	mue = ub_find_entity(ent0, true, idx);
	if (!mue) {
		ub_err(ent0, "find mue in ue %s failed\n",
			reg ? "reg" : "unreg");
		ub_entity_put(ent0);
		return UB_MSG_RSP_EXEC_ENODEV;
	}

	ub_entity_put(ent0);

	if (ent_in_unregistering(mue)) {
		ub_err(mue, "mue is unregistering in ue %s\n",
		       reg ? "reg" : "unreg");
		ub_entity_put(mue);
		return UB_MSG_RSP_EXEC_EBUSY;
	}

	*uent = mue;
	return UB_MSG_RSP_SUCCESS;
}

u8 ub_idevice_pue_rls_handler(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct idev_pue_rls_pld *pld = &pkt->pd_rls_pld;
	struct ub_entity *ent0, *mue;
	u8 status;
	int ret;

	status = ub_get_entity0(ubc, (struct ub_guid *)pld->guid, true, false,
				&ent0);
	if (status)
		goto rsp;

	mue = ub_find_entity(ent0, true, pld->pue_entity_idx);
	if (mue) {
		ret = ub_destroy_existed_entity_handler(mue);
		status = err_to_msg_rsp(ret);
		ub_entity_put(mue);
	} else {
		ub_info(ent0, "mue[%u] does not exist in mue unreg\n",
			pld->pue_entity_idx);
		status = UB_MSG_RSP_EXEC_ENODEV;
	}

	ub_entity_put(ent0);
rsp:
	ub_vdm_msg_rsp(ubc, pkt, status);
	dev_info(&ubc->dev, "MUE unreg: guid[%#llx-%#llx] idx[%u] reason[%#x] status[%#x]\n",
		 *(u64 *)&pld->guid[SZ_2], *(u64 *)pld->guid, pld->pue_entity_idx,
		 pld->rls_reason, status);
	return status;
}

static u8 ue_idx_valid_check(struct ub_entity *mue, int idx)
{
	if (idx < mue->uem.start_entity_idx || idx > mue->uem.end_entity_idx) {
		ub_err(mue, "invalid ue entity_idx=%d, start_idx=%d, end_idx=%d\n",
		       idx, mue->uem.start_entity_idx,
		       mue->uem.end_entity_idx);
		return UB_MSG_RSP_EXEC_EINVAL;
	}

	return UB_MSG_RSP_SUCCESS;
}

static u8 ue_reg_para_valid_check(struct ub_entity *mue, int idx, u32 ueid)
{
	int status;

	if (!mue->is_vdm_idev) {
		ub_info(mue,
			"The pue of this vdm ue to be enabled is normal\n");
	} else {
		status = ue_idx_valid_check(mue, idx);
		if (status)
			return status;
	}

	if (!ub_bus_instance_exist(ueid)) {
		ub_err(mue, "ue add msg user eid[%#x] does not exist\n", ueid);
		return UB_MSG_RSP_EXEC_EINVAL;
	}

	return UB_MSG_RSP_SUCCESS;
}

u8 ub_idevice_ue_add_handler(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct idev_ue_reg_pld *pld = &pkt->vd_reg_pld;
	u16 ue_idx = pld->ue_entity_idx;
	u32 ueid = pld->user_eid[0];
	struct ub_entity *mue, *ue;
	int ret, lock = 0;
	u8 status;

	status = ub_get_mue(ubc, (struct ub_guid *)pld->guid,
			    pld->pue_entity_idx, true, &mue);
	if (status)
		goto ue_reg_rsp;

	status = ue_reg_para_valid_check(mue, ue_idx, ueid);
	if (status)
		goto put_mue;

	ue = ub_find_entity(mue, false, ue_idx);
	if (ue) {
		ub_warn(mue, "The ue idx[%u] already exists\n", ue_idx);
		ret = ub_create_existed_entity_handler(ue);
		ub_entity_put(ue);
	} else {
		lock = device_trylock(&mue->dev);
		if (!lock) {
			ub_warn(mue, "mue lock busy\n");
			status = UB_MSG_RSP_EXEC_EBUSY;
			goto put_mue;
		}

		ret = ub_idevice_enable_handle(mue, ue_idx, 0, NULL, ueid);
		if (ret) {
			ub_err(mue, "enable ue[%u] failed, ret[%d]\n", ue_idx,
			       ret);
		} else {
			ub_info(mue, "enable ue[%u] succeeded, user_eid=0x%x\n",
				ue_idx, ueid);
			mue->num_ues += 1;
		}

		if (lock)
			device_unlock(&mue->dev);
	}

	status = err_to_msg_rsp(ret);

put_mue:
	ub_entity_put(mue);
ue_reg_rsp:
	ub_vdm_msg_rsp(ubc, pkt, status);
	dev_info(&ubc->dev, "UE reg: guid[%#llx-%#llx] mue_idx[%u] idx[%u] ueid[%#x] status[%#x]\n",
		 *(u64 *)&pld->guid[SZ_2], *(u64 *)pld->guid, pld->pue_entity_idx,
		 pld->ue_entity_idx, pld->user_eid[0], status);
	return status;
}

u8 ub_idevice_ue_rls_handler(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct idev_ue_rls_pld *pld = &pkt->vd_rls_pld;
	u16 ue_idx = pld->ue_entity_idx;
	struct ub_entity *mue, *ue;
	u8 status;
	int ret;

	status = ub_get_mue(ubc, (struct ub_guid *)pld->guid,
			    pld->pue_entity_idx, false, &mue);
	if (status)
		goto ue_rls_rsp;

	if (!mue->is_vdm_idev) {
		ub_info(mue, "mue of this vdm ue unreg is normal\n");
	} else {
		status = ue_idx_valid_check(mue, ue_idx);
		if (status)
			goto put_mue;
	}

	ue = ub_find_entity(mue, false, ue_idx);
	if (ue) {
		ret = ub_destroy_existed_entity_handler(ue);
		status = err_to_msg_rsp(ret);
		ub_entity_put(ue);
	} else {
		ub_info(mue, "ue[%u] not exist in ue unreg\n", ue_idx);
		status = UB_MSG_RSP_EXEC_ENODEV;
	}

put_mue:
	ub_entity_put(mue);
ue_rls_rsp:
	ub_vdm_msg_rsp(ubc, pkt, status);
	dev_info(&ubc->dev, "UE unreg: guid[%#llx-%#llx] mue_idx[%u] idx[%u] reason[%#x] status[%#x]\n",
		 *(u64 *)&pld->guid[SZ_2], *(u64 *)pld->guid, pld->pue_entity_idx,
		 pld->ue_entity_idx, pld->rls_reason, status);
	return status;
}

static u8 ub_vdm_create_bi_bypass_ummu(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct create_bi_bypass_pld *pld = &pkt->bi_bypass_pld;
	struct msg_pkt_header *header = &pkt->header;
	u8 status = UB_MSG_RSP_SUCCESS;
	struct msg_info q_info = {};
	enum eid_type type;
	bool local;
	u32 size;
	int ret;

	if (pld->m)
		type = EID_BYPASS;
	else
		type = EID_NONE;

	ret = ub_msg_bus_instance_create(ubc, pld->guid, pld->eid[0], pld->upi,
					 type);
	if (ret) {
		dev_err(&ubc->dev, "bi create msg failed ret[%d]\n", ret);
		status = UB_MSG_RSP_EXEC_ENOEXEC;
	}

	size = (MSG_PKT_HEADER_SIZE + VENDOR_GUID_PLD_SIZE +
		VDM_MSG_DW0_PLD_SIZE) << MSG_REQ_SIZE_OFFSET;
	local = ub_rsp_msg_init(header, status,
				VENDOR_GUID_PLD_SIZE + VDM_MSG_DW0_PLD_SIZE);
	message_info_init(&q_info, local ? ubc->uent : NULL, pkt, NULL, size);
	ret = message_response(ubc->mdev, &q_info, header->msgetah.code);
	if (ret) {
		dev_err(&ubc->dev, "create bi bypass rsp msg failed, ret=%d\n", ret);
		status = UB_MSG_RSP_EXEC_ENOEXEC;
	}

	return status;
}

static int ub_vdm_port_enable(struct ub_bus_controller *ubc,
			      struct vdm_msg_pkt *pkt, struct ub_port *port)
{
	int state, ret;

	state = atomic_read(&port->port_mgmt_state);
	if (state == MGMT_STATE_REGISTERING)
		return 0;
	else if (state == MGMT_STATE_UNREGISTERING)
		return -EBUSY;

	/* idle path */
	atomic_set(&port->port_mgmt_state, MGMT_STATE_REGISTERING);

	ret = ublc_link_up_handle(port, TASK_SRC_VPORT);
	if (ret != 0 && ret != -EBUSY)
		atomic_set(&port->port_mgmt_state, MGMT_STATE_IDLE);

	return ret;
}

static int ub_vdm_port_disable(struct ub_bus_controller *ubc,
			       struct vdm_msg_pkt *pkt, struct ub_port *port)
{
	int state, ret;

	state = atomic_read(&port->port_mgmt_state);
	if (state == MGMT_STATE_REGISTERING)
		return -EBUSY;
	else if (state == MGMT_STATE_UNREGISTERING)
		return 0;

	/* idle path */
	atomic_set(&port->port_mgmt_state, MGMT_STATE_UNREGISTERING);

	ret = ublc_link_down_handle(port);
	if (ret)
		atomic_set(&port->port_mgmt_state, MGMT_STATE_IDLE);

	return ret;
}

static u8 ub_vdm_port_mgmt_handler(struct ub_bus_controller *ubc,
				   struct vdm_msg_pkt *pkt)
{
	struct port_mgmt_pld *pld = &pkt->mgmt_pld;
	u8 status = UB_MSG_RSP_EXEC_EINVAL;
	struct ub_port *port;
	int ret;

#define UB_CFG_SUB_CMD_PORT_EN_SET 1
	if (pld->subcmd != UB_CFG_SUB_CMD_PORT_EN_SET) {
		dev_err(&ubc->dev, "vdm port mgmt subcmd[%u] invalid\n",
			pld->subcmd);
		goto port_mgmt_rsp;
	}

	if (pld->flag != VIRTUAL) {
		dev_err(&ubc->dev, "vdm port mgmt flag not vport\n");
		goto port_mgmt_rsp;
	}

	if (!ubc->uent || pld->port_idx >= ubc->uent->port_nums) {
		dev_err(&ubc->dev, "vdm port mgmt port_idx invalid\n");
		goto port_mgmt_rsp;
	}

	port = ubc->uent->ports + pld->port_idx;
	if (port->type != VIRTUAL) {
		dev_err(&ubc->dev, "vdm port mgmt not vport\n");
		goto port_mgmt_rsp;
	}

	if (pld->en)
		ret = ub_vdm_port_enable(ubc, pkt, port);
	else
		ret = ub_vdm_port_disable(ubc, pkt, port);

	status = err_to_msg_rsp(ret);

port_mgmt_rsp:
	ub_vdm_msg_rsp(ubc, pkt, status);
	dev_info(&ubc->dev, "VDM port %s: port_idx[%u] status[%#x]\n",
		 pld->en ? "enable" : "disable", pld->port_idx, status);
	return status;
}

struct opcode_func_map idev_func_mapping[] = {
	{ VDM_SUB_OPCODE_MUE_REG, MSG_IDEV_MUE_REG_SIZE, "MUE register",
	  ub_idevice_pue_add_handler, IDEV_MUE_REG_PLD_TOTAL_SIZE },
	{ VDM_SUB_OPCODE_MUE_RLS, MSG_IDEV_MUE_RLS_SIZE, "MUE release",
	  ub_idevice_pue_rls_handler, IDEV_MUE_RLS_PLD_TOTAL_SIZE },
	{ VDM_SUB_OPCODE_UE_REG, MSG_IDEV_UE_REG_SIZE, "UE register",
	  ub_idevice_ue_add_handler, IDEV_UE_REG_PLD_TOTAL_SIZE },
	{ VDM_SUB_OPCODE_UE_RLS, MSG_IDEV_UE_RLS_SIZE, "UE release",
	  ub_idevice_ue_rls_handler, IDEV_UE_RLS_PLD_TOTAL_SIZE },
	{ VDM_BI_CREATE_BYPASS_UMMU, VDM_BI_CREATE_BYPASS_SIZE, "Vdm bi create",
	  ub_vdm_create_bi_bypass_ummu, VDM_BI_CREATE_BYPASS_UMMU_PLD_SIZE },
	{ VDM_FM2UB_SUB_PORT_MGMT, VDM_PORT_MGMT_SIZE, "Port mgmt",
	  ub_vdm_port_mgmt_handler, VDM_PORT_MGMT_PLD_SIZE },
};

static int ub_vdm_msg_info_handle(struct ub_bus_controller *ubc,
				    struct vdm_msg_pkt *pkt, u16 len,
				    u16 sub_opcode)
{
	int idx;

	for (idx = 0; idx < ARRAY_SIZE(idev_func_mapping); idx++) {
		if (sub_opcode == idev_func_mapping[idx].sub_opcode) {
			if (len < idev_func_mapping[idx].idev_pkt_size) {
				dev_err(&ubc->dev,
					"Message length[%#x] is wrong\n", len);
				return UB_MSG_RSP_EXEC_EINVAL;
			}
			(void)idev_func_mapping[idx].idev_handler(ubc, pkt);
			return UB_MSG_RSP_SUCCESS;
		}
	}

	dev_err(&ubc->dev, "vdm sub opcode is invalid, sub_opcode = %#x\n", sub_opcode);
	return UB_MSG_RSP_EXEC_EINVAL;
}

static int hi_vdm_vendor_handler(struct ub_bus_controller *ubc, void *pkt, u16 len)
{
	struct vdm_msg_pkt *vdm_pkt = (struct vdm_msg_pkt *)pkt;
	struct msg_pkt_dw0 *pld_dw0 = &vdm_pkt->pld_dw0;
	u16 sub_opcode;
	u8 opcode;

	if (len < (MSG_PKT_HEADER_SIZE + VENDOR_GUID_PLD_SIZE +
		   VDM_MSG_DW0_PLD_SIZE)) {
		dev_err(&ubc->dev, "vdm msg len[%#x] is wrong\n", len);
		return UB_MSG_RSP_EXEC_EINVAL;
	}

	opcode = pld_dw0->opcode;
	sub_opcode = pld_dw0->sub_opcode;
	dev_info(&ubc->dev, "vdm msg opcode %#x, sub %#x\n", opcode, sub_opcode);

	switch (opcode) {
	case VDM_OPCODE_FM2UB_COMM_MSG:
		return ub_vdm_msg_info_handle(ubc, vdm_pkt, len, sub_opcode);
	default:
		dev_err(&ubc->dev, "vdm opcode type [%u] not support\n",
			opcode);
	}

	return UB_MSG_RSP_EXEC_EINVAL;
}

void hi_vdm_rx_msg_handler(struct ub_bus_controller *ubc, void *pkt, u16 len)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;
	u8 sub_msg_code = header->msgetah.sub_msg_code;
	u8 status;

	switch (sub_msg_code) {
	case UB_VENDOR_MSG:
		status = hi_vdm_vendor_handler(ubc, pkt, len);
		break;
	default:
		dev_err(&ubc->dev, "vdm sub msg code[%#x] not support\n",
			sub_msg_code);
		status = UB_MSG_RSP_EXEC_EINVAL;
	}

	if (status)
		ub_vdm_msg_rsp(ubc, (struct vdm_msg_pkt *)pkt, status);
}

static struct ub_entity *ub_get_primary_ent(struct ub_entity *uent)
{
	if (is_primary(uent))
		return uent;

	return uent->is_mue ? uent->pue : uent->pue->pue;
}

/*
 * hi_send_entity_enable_msg - send entity enable message
 */
int hi_send_entity_enable_msg(struct ub_entity *uent, u8 enable)
{
	struct entity_enable_pld *enable_pld;
	struct vdm_msg_pkt pkt = {};
	struct msg_info info = {};
	struct msg_pkt_dw0 *pld_dw0;
	struct ub_entity *pue;
	u8 status;
	int ret;

	if (!uent->ubc->cluster)
		return 0;

	ub_msg_pkt_header_init(&pkt.header, uent, ENTITY_ENABLE_PLD_SIZE,
			       code_gen(UB_MSG_CODE_VDM, UB_VENDOR_MSG,
					MSG_REQ), true);

	pkt.guid_high = *(u64 *)(&uent->ubc->uent->guid.dw[SZ_2]);
	pld_dw0 = &pkt.pld_dw0;
	pld_dw0->opcode = VDM_OPCODE_UB2FM_COMM_MSG;
	pld_dw0->sub_opcode = VDM_SUB_OPCODE_ENTITY_ENABLE;
	enable_pld = &pkt.enable_pld;
	enable_pld->enable = enable;
	if (is_device(uent)) {
		enable_pld->entity_type = ENTITY_TYPE_DEV;
		enable_pld->eid[0] = uent->eid;
	} else { /* idev */
		enable_pld->entity_type = ENTITY_TYPE_IDEV;
		pue = ub_get_primary_ent(uent);
		memcpy(enable_pld->guid, pue->guid.dw,
		       sizeof(u32) * UB_GUID_DW_NUM);
		enable_pld->entity_idx = uent->entity_idx;
	}

	message_info_init(&info, uent->ubc->uent, &pkt, &pkt,
			  (ENTITY_ENABLE_MSG_PKT_SIZE << MSG_REQ_SIZE_OFFSET) |
			  ENTITY_ENABLE_MSG_PKT_SIZE);

	ub_info(uent, "Sync request entity enable msg, enable=%u\n", enable);

	ret = hi_message_sync_request_sched(uent->message->mdev, &info,
					    pkt.header.msgetah.code);
	if (ret) {
		ub_err(uent, "msg sync request ret=%d\n", ret);
		return ret;
	}

	status = pkt.header.msgetah.rsp_status;
	if (status != UB_MSG_RSP_SUCCESS) {
		ub_err(uent, "msg rsp status=%#02x\n", status);
		return -EINVAL;
	}

	return 0;
}

int hi_send_port_reset_msg(struct ub_entity *uent, u16 port_idx)
{
	struct port_reset_pld *rst_pld;
	struct vdm_msg_pkt pkt = {};
	struct msg_info info = {};
	struct msg_pkt_dw0 *pld_dw0;
	u8 status;
	int ret;

	if (!uent->ubc->cluster)
		return 0;

	ub_msg_pkt_header_init(&pkt.header, uent, VDM_PORT_RESET_PLD_SIZE,
			       code_gen(UB_MSG_CODE_VDM, UB_VENDOR_MSG,
					MSG_REQ), true);

	pkt.guid_high = *(u64 *)(&uent->ubc->uent->guid.dw[SZ_2]);
	pld_dw0 = &pkt.pld_dw0;
	pld_dw0->opcode = VDM_OPCODE_UB2FM_COMM_MSG;
	pld_dw0->sub_opcode = VDM_SUB_OPCODE_PORT_RESET;
	rst_pld = &pkt.reset_pld;
	rst_pld->port_idx = port_idx;

	message_info_init(&info, uent->ubc->uent, &pkt, &pkt,
			  (VDM_PORT_RESET_SIZE << MSG_REQ_SIZE_OFFSET) |
			  VDM_PORT_RESET_SIZE);

	ub_info(uent, "Sync request port reset msg\n");

	ret = hi_message_sync_request(uent->message->mdev, &info,
				      pkt.header.msgetah.code);
	if (ret) {
		ub_err(uent, "msg sync request ret=%d\n", ret);
		return ret;
	}

	status = pkt.header.msgetah.rsp_status;
	if (status != UB_MSG_RSP_SUCCESS) {
		ub_err(uent, "msg rsp status=%#02x\n", status);
		return -EINVAL;
	}

	return 0;
}

void ub_delay_task_work_vdm(struct work_struct *work)
{
	struct ub_delay_task *task = container_of(work, struct ub_delay_task,
						  work);
	struct ub_entity *uent = task->uent;
	struct ub_port *port;

	switch (task->task_type) {
	case TASK_TYPE_START:
	case TASK_TYPE_ATTACH:
	case TASK_TYPE_REINIT:
		if (!ub_entity_test_task_src(uent, TASK_SRC_VPORT))
			return;

		port = uent->ports[0].r_uent->ports + uent->ports[0].r_index;
		atomic_set(&port->port_mgmt_state, MGMT_STATE_IDLE);
		break;
	case TASK_TYPE_LINKDOWN:
		port = task->port;
		atomic_set(&port->port_mgmt_state, MGMT_STATE_IDLE);
		break;
	case TASK_TYPE_DISABLE:
	case TASK_TYPE_ATTACH_RETRY:
	case TASK_TYPE_REINIT_RETRY:
	default:
		break;
		/* do nothing */
	}
}
