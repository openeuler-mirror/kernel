// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <ub/ubase/ubase_comm_ctrlq.h>
#include "udma_ctrlq_tp.h"
#include "udma_eq.h"
#include "udma_mue.h"

static uint32_t udma_get_rsp_msg_len(uint8_t opcode)
{
#define UDMA_DEFAULT_CTRLQ_RSP_MSG_LEN 0

	switch (opcode) {
	case UDMA_CMD_CTRLQ_GET_TP_LIST:
		return sizeof(struct udma_ctrlq_tpid_list_rsp);
	case UDMA_CMD_CTRLQ_ACTIVE_TP:
		return sizeof(struct udma_ctrlq_active_tp_resp_data);
	case UDMA_CMD_CTRLQ_GET_TP_ATTR:
		return sizeof(struct udma_ctrlq_get_tp_attr_resp);
	case UDMA_CMD_CTRLQ_GET_TP_INFO:
		return sizeof(struct udma_ctrlq_tp_info_resp_data);
	default:
		return UDMA_DEFAULT_CTRLQ_RSP_MSG_LEN;
	}
}

static void udma_send_ue_msg(struct udma_dev *udev, void *data, uint16_t len,
		uint8_t opcode, bool is_resp)
{
	uint16_t hdr_len = ubase_ctrlq_ue_msg_header_len();
	struct ubase_ctrlq_ue_msg_info msg_info = {};
	uint8_t *rsp_msg = NULL;
	uint32_t total_msg_len;
	uint32_t rsp_msg_len;
	int result;
	int ret;

	rsp_msg_len = udma_get_rsp_msg_len(opcode);
	total_msg_len = rsp_msg_len + hdr_len;

	if (len < hdr_len) {
		dev_err(udev->dev, "send mue2ue msg failed, len(%u) is too small.\n", len);
		return;
	}

	rsp_msg = kzalloc(total_msg_len, GFP_KERNEL);
	if (rsp_msg == NULL)
		return;

	memcpy(rsp_msg, (uint8_t *)data, hdr_len);

	if (is_resp) {
		ubase_ctrlq_parse_ue_msg(udev->comdev.adev, data, len, &msg_info);
		result = msg_info.ret;
	} else {
		result = EINVAL;
	}

	ret = ubase_ctrlq_send_mue2ue_resp(udev->comdev.adev, rsp_msg,
					   total_msg_len, result);
	if (ret)
		dev_err(udev->dev, "udma send mue2ue msg failed, opcode = %u.\n", opcode);

	kfree(rsp_msg);
}

static uint32_t udma_get_req_msg_len(uint8_t opcode)
{
#define UDMA_DEFAULT_CTRLQ_REQ_MSG_LEN 0

	switch (opcode) {
	case UDMA_CMD_CTRLQ_GET_TP_LIST:
		return sizeof(struct udma_ctrlq_get_tp_list_req_data);
	case UDMA_CMD_CTRLQ_ACTIVE_TP:
		return sizeof(struct udma_ctrlq_active_tp_req_data);
	case UDMA_CMD_CTRLQ_DEACTIVE_TP:
		return sizeof(struct udma_ctrlq_deactive_tp_req_data);
	case UDMA_CMD_CTRLQ_SET_TP_ATTR:
		return sizeof(struct udma_ctrlq_set_tp_attr_req);
	case UDMA_CMD_CTRLQ_GET_TP_ATTR:
		return sizeof(struct udma_ctrlq_get_tp_attr_req);
	default:
		return UDMA_DEFAULT_CTRLQ_REQ_MSG_LEN;
	}
}

static int udma_handle_ue_req_msg(struct auxiliary_device *adev, void *data,
				  u16 len, uint8_t opcode)
{
	struct udma_dev *udma_dev;
	uint32_t req_msg_len;
	uint16_t hdr_len;

	if (adev == NULL || data == NULL) {
		pr_err("adev is null %d, data is null %d.\n", adev == NULL, data == NULL);
		return 0;
	}

	udma_dev = get_udma_dev(adev);

	req_msg_len = udma_get_req_msg_len(opcode);
	hdr_len = ubase_ctrlq_ue_msg_header_len();
	if (len < req_msg_len + hdr_len) {
		dev_err(udma_dev->dev,
				"from ue req msg is error, len = %u. opcode = %u\n",
				len, opcode);
		udma_send_ue_msg(udma_dev, data, len, opcode, false);

		return UBASE_CTRLQ_HANDLE_UE_MSG;
	}

	return 0;
}

static int udma_reg_get_tp_list_req_msg(struct auxiliary_device *adev, void *data,
					u16 len)
{
	return udma_handle_ue_req_msg(adev, data, len, UDMA_CMD_CTRLQ_GET_TP_LIST);
}

static int udma_reg_active_tp_req_msg(struct auxiliary_device *adev, void *data,
				      u16 len)
{
	return udma_handle_ue_req_msg(adev, data, len, UDMA_CMD_CTRLQ_ACTIVE_TP);
}

static int udma_reg_deactive_tp_req_msg(struct auxiliary_device *adev, void *data,
					u16 len)
{
	return udma_handle_ue_req_msg(adev, data, len, UDMA_CMD_CTRLQ_DEACTIVE_TP);
}

static int udma_reg_set_tp_attr_req_msg(struct auxiliary_device *adev, void *data,
					u16 len)
{
	return udma_handle_ue_req_msg(adev, data, len, UDMA_CMD_CTRLQ_SET_TP_ATTR);
}

static int udma_reg_get_tp_attr_req_msg(struct auxiliary_device *adev, void *data,
					u16 len)
{
	return udma_handle_ue_req_msg(adev, data, len, UDMA_CMD_CTRLQ_GET_TP_ATTR);
}

static int udma_handle_ue_get_tp_info_msg(struct udma_dev *udev,
					  void *data, uint16_t len)
{
	struct udma_ctrlq_tp_info_resp_data tp_info_resp = {};
	struct ubase_ctrlq_ue_msg_info msg_info = {};
	struct udma_ue_tp_info tp_info = {};
	uint32_t rsp_msg_len;
	uint16_t hdr_len;
	int ret;

	ubase_ctrlq_parse_ue_msg(udev->comdev.adev, data, len, &msg_info);
	if (msg_info.ret) {
		dev_err(udev->dev, "udma get tp info failed, ret = %d.\n", msg_info.ret);
		return -EINVAL;
	}

	hdr_len = ubase_ctrlq_ue_msg_header_len();
	rsp_msg_len = min(len - hdr_len, (uint16_t)sizeof(tp_info_resp));

	memcpy(&tp_info_resp, (uint8_t *)data + hdr_len, rsp_msg_len);
	if (tp_info_resp.resp_tpn_cnt != tp_info_resp.req_tpn_cnt) {
		dev_err(udev->dev, "resp tp cnt = %u not equal to req tp cnt = %u.\n",
			tp_info_resp.resp_tpn_cnt, tp_info_resp.req_tpn_cnt);
		return -EINVAL;
	}

	tp_info.start_tpn = tp_info_resp.resp_start_tpn;
	tp_info.tp_cnt = tp_info_resp.resp_tpn_cnt;
	ret = udma_save_tp_info(udev, &tp_info, msg_info.mbx_ue_id);
	if (ret)
		dev_err(udev->dev, "udma save tp info failed, ret = %d.\n", ret);

	return ret;
}

static int udma_handle_ue_get_tp_list_msg(struct udma_dev *udev,
					  void *data, uint16_t len)
{
	struct udma_ctrlq_tpid_list_rsp tpid_list_resp = {};
	struct ubase_ctrlq_ue_msg_info msg_info = {};
	uint32_t rsp_msg_len;
	uint16_t hdr_len;
	uint32_t i;

	ubase_ctrlq_parse_ue_msg(udev->comdev.adev, data, len, &msg_info);
	if (msg_info.ret) {
		dev_err(udev->dev, "udma get tp list failed, ret = %d.\n", msg_info.ret);
		return -EINVAL;
	}

	hdr_len = ubase_ctrlq_ue_msg_header_len();
	rsp_msg_len = min((uint16_t)(len - hdr_len), (uint16_t)sizeof(tpid_list_resp));

	memcpy(&tpid_list_resp, (uint8_t *)data + hdr_len, rsp_msg_len);
	if (tpid_list_resp.tp_list_cnt == 0) {
		dev_err(udev->dev,
			"check ue tp list count failed, count = %u.\n",
			tpid_list_resp.tp_list_cnt);
		return -EINVAL;
	}

	for (i = 0; i < tpid_list_resp.tp_list_cnt; i++)
		if (tpid_list_resp.tpid_list[i].migr) {
			dev_err(udev->dev, "no support migr. tpid = %u.\n",
			tpid_list_resp.tpid_list[i].tpid);
			return -EINVAL;
		}

	return 0;
}

static int udma_handle_ue_rsp_msg(struct auxiliary_device *adev, void *data,
				  u16 len, uint8_t opcode)
{
	struct udma_dev *udma_dev;
	uint16_t hdr_len;

	if (adev == NULL || data == NULL) {
		pr_err("adev is null %d, data is null %d\n",
		adev == NULL, data == NULL);
		return 0;
	}

	udma_dev = get_udma_dev(adev);
	hdr_len = ubase_ctrlq_ue_msg_header_len();
	if (len <= hdr_len) {
		dev_err(udma_dev->dev,
				"from ctrlq rsp msg is error, len = %u. opcode = %u\n",
				len, opcode);
		goto err_and_send_ue_msg;
	}

	if (opcode == UDMA_CMD_CTRLQ_GET_TP_LIST) {
		if (udma_handle_ue_get_tp_list_msg(udma_dev, data, len)) {
			dev_err(udma_dev->dev,
					"from ctrlq get_tp_list msg is invalid.\n");
			goto err_and_send_ue_msg;
		}
	} else if (opcode == UDMA_CMD_CTRLQ_GET_TP_INFO) {
		if (udma_handle_ue_get_tp_info_msg(udma_dev, data, len)) {
			dev_err(udma_dev->dev, "from ctrlq get_tp_info msg is invalid.\n");
			goto err_and_send_ue_msg;
		}
	}

	return 0;

err_and_send_ue_msg:
	udma_send_ue_msg(udma_dev, data, len, opcode, true);

	return UBASE_CTRLQ_HANDLE_UE_MSG;
}

static int udma_reg_get_tp_list_rsp_msg(struct auxiliary_device *adev, void *data,
					u16 len)
{
	return udma_handle_ue_rsp_msg(adev, data, len, UDMA_CMD_CTRLQ_GET_TP_LIST);
}

static int udma_reg_get_tp_info_msg(struct auxiliary_device *adev, void *data,
				    u16 len)
{
	return udma_handle_ue_rsp_msg(adev, data, len, UDMA_CMD_CTRLQ_GET_TP_INFO);
}

static const struct ubase_ctrlq_ue_msg_nb udma_ue_req[] = {
	{UBASE_CTRLQ_SER_TYPE_TP_ACL, UDMA_CMD_CTRLQ_GET_TP_LIST,
	 NULL, udma_reg_get_tp_list_req_msg},
	{UBASE_CTRLQ_SER_TYPE_TP_ACL, UDMA_CMD_CTRLQ_ACTIVE_TP,
	 NULL, udma_reg_active_tp_req_msg},
	{UBASE_CTRLQ_SER_TYPE_TP_ACL, UDMA_CMD_CTRLQ_DEACTIVE_TP,
	 NULL, udma_reg_deactive_tp_req_msg},
	{UBASE_CTRLQ_SER_TYPE_TP_ACL, UDMA_CMD_CTRLQ_SET_TP_ATTR,
	 NULL, udma_reg_set_tp_attr_req_msg},
	{UBASE_CTRLQ_SER_TYPE_TP_ACL, UDMA_CMD_CTRLQ_GET_TP_ATTR,
	 NULL, udma_reg_get_tp_attr_req_msg},
};

static const struct ubase_ctrlq_ue_msg_nb udma_ue_rsp[] = {
	{UBASE_CTRLQ_SER_TYPE_TP_ACL, UDMA_CMD_CTRLQ_GET_TP_LIST,
	 NULL, udma_reg_get_tp_list_rsp_msg},
	{UBASE_CTRLQ_SER_TYPE_TP_ACL, UDMA_CMD_CTRLQ_GET_TP_INFO,
	 NULL, udma_reg_get_tp_info_msg},
};

static int udma_register_one_ue_msg(struct auxiliary_device *adev,
				    const struct ubase_ctrlq_ue_msg_nb *ue_msg_nb,
				    int (*register_func)(struct auxiliary_device *,
				    struct ubase_ctrlq_ue_msg_nb *))
{
	struct udma_dev *udma_dev = get_udma_dev(adev);
	struct ubase_ctrlq_ue_msg_nb *nb;
	int ret;

	nb = kzalloc(sizeof(*nb), GFP_KERNEL);
	if (nb == NULL)
		return -ENOMEM;

	nb->service_type = ue_msg_nb->service_type;
	nb->opcode = ue_msg_nb->opcode;
	nb->back = adev;
	nb->msg_handler = ue_msg_nb->msg_handler;
	ret = register_func(adev, nb);
	if (ret)
		dev_err(udma_dev->dev,
			"ubase register ue msg failed, opcode = %u, ret is %d.\n",
			nb->opcode, ret);

	kfree(nb);

	return ret;
}

static void udma_unregister_one_ue_msg(struct auxiliary_device *adev,
				       const struct ubase_ctrlq_ue_msg_nb *ue_msg_nb,
				       void (*unregister_func)(struct auxiliary_device *,
				       u8, u8))
{
	unregister_func(adev, ue_msg_nb->service_type, ue_msg_nb->opcode);
}

static int udma_register_ue_msg_event(struct auxiliary_device *adev,
				      const struct ubase_ctrlq_ue_msg_nb ue_msg[],
				      int ue_msg_num,
				      int (*register_func)(struct auxiliary_device *,
				      struct ubase_ctrlq_ue_msg_nb *),
				      void (*unregister_func)(struct auxiliary_device *,
				      u8, u8))
{
	int index;
	int ret;

	for (index = 0; index < ue_msg_num; ++index) {
		ret = udma_register_one_ue_msg(adev, &ue_msg[index],
					       register_func);
		if (ret)
			goto err_unregister;
	}

	return 0;

err_unregister:
	for (index--; index >= 0; index--)
		udma_unregister_one_ue_msg(adev, &ue_msg[index],
					   unregister_func);

	return ret;
}

int udma_register_ue_msg_req_event(struct auxiliary_device *adev)
{
	struct udma_dev *udev = get_udma_dev(adev);

	if (udev->is_ue)
		return 0;

	return udma_register_ue_msg_event(adev, udma_ue_req,
					  ARRAY_SIZE(udma_ue_req),
					  ubase_ctrlq_register_ue_req_event,
					  ubase_ctrlq_unregister_ue_req_event);
}

int udma_register_ue_msg_rsp_event(struct auxiliary_device *adev)
{
	struct udma_dev *udev = get_udma_dev(adev);

	if (udev->is_ue)
		return 0;

	return udma_register_ue_msg_event(adev, udma_ue_rsp,
					  ARRAY_SIZE(udma_ue_rsp),
					  ubase_ctrlq_register_ue_resp_event,
					  ubase_ctrlq_unregister_ue_resp_event);
}

void udma_unregister_ue_msg_req_event(struct auxiliary_device *adev)
{
	struct udma_dev *udev = get_udma_dev(adev);
	int opt_num = ARRAY_SIZE(udma_ue_req);
	int index;

	if (udev->is_ue)
		return;

	for (index = 0; index < opt_num; ++index)
		ubase_ctrlq_unregister_ue_req_event(adev,
						    udma_ue_req[index].service_type,
						    udma_ue_req[index].opcode);
}

void udma_unregister_ue_msg_rsp_event(struct auxiliary_device *adev)
{
	struct udma_dev *udev = get_udma_dev(adev);
	int opt_num = ARRAY_SIZE(udma_ue_rsp);
	int index;

	if (udev->is_ue)
		return;

	for (index = 0; index < opt_num; ++index)
		ubase_ctrlq_unregister_ue_resp_event(adev,
						     udma_ue_rsp[index].service_type,
						     udma_ue_rsp[index].opcode);
}
