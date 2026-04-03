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

/**
 * inner_ub_get_ent_by_guid - search for device by guid in the idev message
 *
 * @guid:	guid in idev message
 * @dev_list:	&ubc->devs
 */
static struct ub_entity *inner_ub_get_ent_by_guid(guid_t *guid,
					       struct list_head *dev_list)
{
	struct ub_entity *uent;

	list_for_each_entry(uent, dev_list, node)
		if (guid_equal(guid, &uent->guid.id))
			return uent;

	return NULL;
}

/*
 * ub_get_pue - search for physical device by guid and mue_idx
 *
 * First search for entity0 in ubc->dev_list by guid,
 * then search for mue_idx in entity0->mue_list by mue_idx
 */
static struct ub_entity *ub_get_pue(guid_t *guid, u16 mue_idx,
				  struct list_head *dev_list)
{
	struct ub_entity *uent = inner_ub_get_ent_by_guid(guid, dev_list);
	struct ub_entity *pue;

	if (!uent) {
		pr_err("find uent with the guid failed\n");
		return NULL;
	}

	if (is_primary(uent) && mue_idx == 0) {
		ub_info(uent,
			"This uent is primary dev, return uent directly\n");
		return uent;
	}

	list_for_each_entry(pue, &uent->mue_list, node) {
		ub_info(pue, "the pue num=%#x\n", pue->uent_num);
		if (pue->entity_idx == mue_idx)
			return pue;
	}

	return NULL;
}

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

/**
 * ub_idevice_enable_handle - physical/virtual device entity enable handle
 *
 * @pue:	physical device
 * @idx:	index of device entity
 * @is_mue:	whether is physical device. 1 for yes, 0 for no
 * @map:	the mapping of virtual devices
 * @alloc_dev:	a temporary variable used to receive allocated dev and return the information
 */
static int ub_idevice_enable_handle(struct ub_entity *pue, u16 idx, u8 is_mue,
				 struct ue_map *map,
				 struct ub_entity **alloc_dev)
{
	struct ub_entity *dev, *uent;
	int ret;

	list_for_each_entry(uent, &pue->mue_list, node)
		if (uent->entity_idx == idx)
			return -EEXIST;

	list_for_each_entry(uent, &pue->ue_list, node)
		if (uent->entity_idx == idx)
			return -EEXIST;

	dev = ub_alloc_ent();
	if (!dev)
		return -ENOMEM;

	dev->pool = true;
	dev->entity_idx = idx;
	dev->pue = pue;
	dev->dev.parent = &pue->dev;
	dev->ubc = pue->ubc;
	dev->cna = pue->cna;
	dev->upi = pue->upi;

	if (is_mue) {
		dev->is_mue = is_mue;
		dev->uem.start_entity_idx = map->start_entity_idx;
		dev->uem.end_entity_idx = map->end_entity_idx;
		dev->total_ues = map->end_entity_idx - map->start_entity_idx + 1;
		dev->is_vdm_idev = 1;
	}

	ret = ub_setup_ent(dev);
	if (ret < 0) {
		kfree(dev);
		return ret;
	}

	ub_entity_get(pue);
	ub_entity_add(dev, pue);

	*alloc_dev = dev;

	return 0;
}

/**
 * ub_idevice_pue_add_handler - add mue to the bus
 *
 * @ubc:	ub bus controller
 * @pkt:	idev pue message packet, contains header and payload
 */
static u8 ub_idevice_pue_add_handler(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct idev_pue_reg_pld *pld = &pkt->pd_reg_pld;
	struct ub_entity *pue, *alloc_dev = NULL;
	struct ue_map map = {};
	char buf[SZ_64] = {};
	u8 status;
	int ret;

	/* search corresponding device by guid in message payload */
	pue = inner_ub_get_ent_by_guid((guid_t *)pld->guid, &ubc->devs);
	if (!pue) {
		(void)ub_show_guid((struct ub_guid *)pld->guid, buf);
		dev_err(&ubc->dev, "find uent by guid in pue reg func failed\n");
		status = UB_MSG_RSP_EXEC_ENODEV;
		goto pue_reg_rsp;
	}

	map.start_entity_idx = pld->start_ue_entity_idx;
	map.end_entity_idx = pld->end_ue_entity_idx;

	if (!pld->ue_cnt) {
		map.start_entity_idx = pue->entity_idx;
		map.end_entity_idx = pue->entity_idx;
	} else if (pld->ue_cnt != map.end_entity_idx - map.start_entity_idx + 1) {
		dev_err(&ubc->dev, "Invalid ue cnt: [%u]\n"
			"The ue cnt must be equal to end: [%d] - start: [%d] + 1\n",
			pld->ue_cnt, map.end_entity_idx, map.start_entity_idx);
		status = UB_MSG_RSP_EXEC_EINVAL;
		goto pue_reg_rsp;
	}

	if (!ub_bus_instance_exist(pld->user_eid[0])) {
		dev_err(&ubc->dev, "pue add msg user eid[%#x] not exist\n",
			pld->user_eid[0]);
		status = UB_MSG_RSP_EXEC_EINVAL;
		goto pue_reg_rsp;
	}

	/* enable pue */
	ret = ub_idevice_enable_handle(pue, pld->pue_entity_idx, 1, &map,
				    &alloc_dev);
	if (ret == 0) {
		alloc_dev->user_eid = pld->user_eid[0];
		ub_info(pue, "enable idev pue succeeded, user_eid=0x%x\n",
			pld->user_eid[0]);
		status = UB_MSG_RSP_SUCCESS;
	} else if (ret == -EEXIST) {
		ub_err(pue, "The pue idx[%u] is already exist\n",
		       pld->pue_entity_idx);
		status = UB_MSG_RSP_EXEC_EEXIST;
	} else {
		ub_err(pue, "enable idev pue failed\n");
		status = UB_MSG_RSP_EXEC_ENOEXEC;
	}

pue_reg_rsp:
	ub_vdm_msg_rsp(ubc, pkt, status);
	if (status == UB_MSG_RSP_SUCCESS)
		ub_start_ent(alloc_dev);

	return status;
}

/**
 * ub_idevice_pue_rls_handler - send message to the FM to release the idev_pue
 *
 * @ubc:	ub_bus_controller
 * @pkt:	message packet
 */
static u8 ub_idevice_pue_rls_handler(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct idev_pue_rls_pld *pld = &pkt->pd_rls_pld;
	struct ub_entity *uent;
	u8 status;

	/* search device by guid and pue entity idx in message payload */
	uent = ub_get_pue((guid_t *)pld->guid, pld->pue_entity_idx, &ubc->devs);
	if (!uent) {
		dev_err(&ubc->dev, "find pue failed, pue entity_idx in mue rls pkt=%u\n",
			pld->pue_entity_idx);
		status = UB_MSG_RSP_EXEC_ENODEV;
	} else {
		status = UB_MSG_RSP_SUCCESS;
	}

	ub_vdm_msg_rsp(ubc, pkt, status);

	if (status == UB_MSG_RSP_SUCCESS)
		ub_disable_ent(uent);

	return status;
}

/*
 * ub_idevice_ue_add_handler - add ue to the bus
 */
static u8 ub_idevice_ue_add_handler(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct idev_ue_reg_pld *pld = &pkt->vd_reg_pld;
	struct ub_entity *pue, *alloc_dev = NULL;
	u16 ue_entity_idx = pld->ue_entity_idx;
	int start_idx, end_idx, ret;
	int lock = 0;
	u8 status;

	/* check whether pue is registered. */
	pue = ub_get_pue((guid_t *)pld->guid, pld->pue_entity_idx, &ubc->devs);
	if (!pue) {
		dev_err(&ubc->dev, "find pue failed, pue entity_idx in ue reg pkt=%u\n",
			pld->pue_entity_idx);
		status = UB_MSG_RSP_EXEC_ENODEV;
		goto ue_reg_rsp;
	}

	if (pue->is_vdm_idev) {
		start_idx = pue->uem.start_entity_idx;
		end_idx = pue->uem.end_entity_idx;
		if (ue_entity_idx < start_idx || ue_entity_idx > end_idx) {
			ub_err(pue,
			       "invalid ue entity_idx=%u, start_idx=%d, end_idx=%d\n",
			       ue_entity_idx, start_idx, end_idx);
			status = UB_MSG_RSP_EXEC_EINVAL;
			goto ue_reg_rsp;
		}
	} else {
		ub_info(pue,
			"The pue of this vdm ue to be enabled is normal\n");
	}

	if (!ub_bus_instance_exist(pld->user_eid[0])) {
		dev_err(&ubc->dev, "ue add msg user eid[%#x] not exist\n",
			pld->user_eid[0]);
		status = UB_MSG_RSP_EXEC_EINVAL;
		goto ue_reg_rsp;
	}

	lock = device_trylock(&pue->dev);
	if (!lock) {
		status = UB_MSG_RSP_EXEC_EBUSY;
		goto ue_reg_rsp;
	}

	ret = ub_idevice_enable_handle(pue, ue_entity_idx, 0, NULL, &alloc_dev);
	if (ret == 0) {
		alloc_dev->user_eid = pld->user_eid[0];
		ub_info(pue, "enable idev ue succeeded, user_eid=0x%x\n",
			pld->user_eid[0]);
		status = UB_MSG_RSP_SUCCESS;
	} else if (ret == -EEXIST) {
		ub_err(pue, "The ue idx[%u] is already exist\n",
		       ue_entity_idx);
		status = UB_MSG_RSP_EXEC_EEXIST;
	} else {
		ub_err(pue, "enable idev ue failed\n");
		status = UB_MSG_RSP_EXEC_ENOEXEC;
	}

ue_reg_rsp:
	ub_vdm_msg_rsp(ubc, pkt, status);
	if (status == UB_MSG_RSP_SUCCESS) {
		ub_start_ent(alloc_dev);
		pue->num_ues += 1;
	}

	if (lock)
		device_unlock(&pue->dev);

	return status;
}

/**
 * ub_idevice_ue_rls_handler - send message to the FM to release the idev_pue
 *
 * @ubc:	ub_bus_controller
 * @pkt:	message packet
 */
static u8 ub_idevice_ue_rls_handler(struct ub_bus_controller *ubc, struct vdm_msg_pkt *pkt)
{
	struct idev_ue_rls_pld *pld = &pkt->vd_rls_pld;
	struct ub_entity *pue, *vd_dev, *tmp;
	u16 ue_entity_idx = pld->ue_entity_idx;
	u16 start_idx, end_idx;
	int lock = 0;
	u8 status;

	/* search for pue with guid. Return an error if pue does not exist */
	pue = ub_get_pue((guid_t *)pld->guid, pld->pue_entity_idx, &ubc->devs);
	if (!pue) {
		dev_err(&ubc->dev, "find pue failed, pue entity_idx in ue rls pkt=%u\n",
			pld->pue_entity_idx);
		status = UB_MSG_RSP_EXEC_ENODEV;
		goto ue_rls_rsp;
	}

	if (pue->is_vdm_idev) {
		start_idx = pue->uem.start_entity_idx;
		end_idx = pue->uem.end_entity_idx;
		if (ue_entity_idx < start_idx || ue_entity_idx > end_idx) {
			ub_err(pue,
			       "invalid ue entity_idx=%u, start_idx=%u, end_idx=%u\n",
			       ue_entity_idx, start_idx, end_idx);
			status = UB_MSG_RSP_EXEC_EINVAL;
			goto ue_rls_rsp;
		}
	} else {
		ub_info(pue,
			"The pue of this vdm ue to be disabled is normal\n");
	}

	lock = device_trylock(&pue->dev);
	if (!lock) {
		status = UB_MSG_RSP_EXEC_EBUSY;
		goto ue_rls_rsp;
	}

	status = UB_MSG_RSP_EXEC_ENODEV;
	/* otherwise, delete this ue with ue idx in message payload */
	list_for_each_entry_safe(vd_dev, tmp, &pue->ue_list, node)
		if (ue_entity_idx == vd_dev->entity_idx) {
			status = UB_MSG_RSP_SUCCESS;
			break;
		}
	if (status == UB_MSG_RSP_EXEC_ENODEV)
		ub_err(pue, "find vd_dev with entity_idx %u failed\n", ue_entity_idx);

ue_rls_rsp:
	ub_vdm_msg_rsp(ubc, pkt, status);
	if (status == UB_MSG_RSP_SUCCESS) {
		ub_disable_ent(vd_dev);
		pue->num_ues -= 1;
	}

	if (lock)
		device_unlock(&pue->dev);

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
