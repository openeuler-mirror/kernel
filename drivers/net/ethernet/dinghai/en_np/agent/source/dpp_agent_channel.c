// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_agent_channel.h"
#include "dh_cmd.h"
#include "dpp_dev.h"
#include "dpp_pktrx_api.h"

DPP_STATUS dpp_agent_channel_init(void)
{
	// zxdh_bar_msg_chan_init();
	return DPP_OK;
}

DPP_STATUS dpp_agent_channel_exit(void)
{
	// zxdh_bar_msg_chan_remove();
	return DPP_OK;
}

static void dpp_agent_msg_prt(u8 type, u32 rtn)
{
	switch (rtn) {
	case DPP_RC_CTRLCH_MSG_LEN_ZERO: {
		ZXIC_COMM_TRACE_ERROR("type[%u]:msg len is zero!\n", type);
		break;
	}
	case DPP_RC_CTRLCH_MSG_PRO_ERR: {
		ZXIC_COMM_TRACE_ERROR("type[%u]:msg process error!\n", type);
		break;
	}
	case DPP_RC_CTRLCH_MSG_TYPE_NOT_SUPPORT: {
		ZXIC_COMM_TRACE_ERROR("type[%u]:fw not support the msg!\n", type);
		break;
	}
	case DPP_RC_CTRLCH_MSG_OPER_NOT_SUPPORT: {
		ZXIC_COMM_TRACE_ERROR("type[%u]:fw not support opr of the msg!\n", type);
		break;
	}
	case DPP_RC_CTRLCH_MSG_DROP: {
		ZXIC_COMM_TRACE_ERROR("type[%u]:fw not support,drop msg!\n", type);
		break;
	}
	default:
		break;
	}
}
static DPP_STATUS dpp_agent_bar_msg_check(struct dpp_dev_t *dev, struct dpp_agent_channel_msg *pMsg)
{
	u8 type = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pMsg);

	type = *((u8 *)(pMsg->msg) + 1);
	if (type != DPP_PCIE_BAR_MSG) {
		if (type >= DEV_PCIE_BAR_MSG_NUM(dev)) {
			ZXIC_COMM_TRACE_ERROR("type[%u] > fw_bar_msg_num[%u]!\n", type,
					      DEV_PCIE_BAR_MSG_NUM(dev));
			return DPP_RC_CTRLCH_MSG_TYPE_NOT_SUPPORT;
		}
	}

	return DPP_OK;
}
DPP_STATUS dpp_agent_channel_reg_sync_send(struct dpp_dev_t *dev,
					   struct dpp_agent_channel_reg_msg *pMsg, u32 *pData,
					   u32 rep_len)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pMsg);

	agentMsg.msg = (void *)pMsg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_reg_msg);

	ret = dpp_agent_channel_sync_send(dev, &agentMsg, pData, rep_len);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

	ret = *pData;
	if (ret != DPP_OK) {
		ZXIC_COMM_TRACE_ERROR("%s: dpp_agent_channel_sync_send failed in buffer\n",
				      __func__);
		return DPP_ERR;
	}

	return DPP_OK;
}

DPP_STATUS dpp_agent_channel_sync_send(struct dpp_dev_t *dev, struct dpp_agent_channel_msg *pMsg,
				       u32 *pData, u32 rep_len)
{
	DPP_STATUS ret = DPP_OK;
	u8 *reply_ptr = NULL;
	u8 retry_count = 0;
	u16 reply_msg_len = 0;
	u32 *recv_buffer = NULL;

	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pMsg);
	ZXIC_COMM_CHECK_POINT(pData);

	ret = dpp_agent_bar_msg_check(dev, pMsg);
	ZXIC_COMM_CHECK_RC(ret, "dpp_agent_bar_msg_check");

	recv_buffer = (u32 *)ZXIC_COMM_MALLOC(rep_len + CHANNEL_REPS_LEN);
	ZXIC_COMM_CHECK_POINT(recv_buffer);
	ZXIC_COMM_MEMSET(recv_buffer, 0, rep_len + CHANNEL_REPS_LEN);

	in.virt_addr = DEV_PCIE_MSG_ADDR(dev);
	in.payload_addr = pMsg->msg;
	in.payload_len = pMsg->msg_len;
	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = NP_AGENT_ID;
	in.src_pcieid = DEV_PCIE_ID(dev);

	result.buffer_len = rep_len + CHANNEL_REPS_LEN;
	result.recv_buffer = recv_buffer;

	ZXIC_COMM_TRACE_DEBUG("%s: in.virt_addr 0x%llx.\n", __func__, in.virt_addr);

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if (ret == BAR_MSG_ERR_LOCK_FAILED) {
			retry_count++;
			ZXIC_COMM_TRACE_INFO(
				"zxdh_bar_chan_sync_msg_send return %d, retry %d times...\n", ret,
				retry_count);
			msleep(200);
		} else {
			break;
		}
	} while (retry_count < BAR_MSG_RETRY_MAX_TIME);

	if (retry_count >= BAR_MSG_RETRY_MAX_TIME)
		ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "zxdh_bar_chan_sync_msg_send", recv_buffer);

	if (ret == BAR_MSG_ERR_BAR_ABNORMAL)
		ret = ZXIC_PAR_CHK_BAR_ABNORMAL;
	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "zxdh_bar_chan_sync_msg_send", recv_buffer);

	reply_ptr = (u8 *)(result.recv_buffer);
	if (*reply_ptr == MSG_REP_VALID) {
		reply_msg_len = *(u16 *)(reply_ptr + MSG_REP_LEN_OFFSET);
		ZXIC_COMM_MEMCPY_S(pData, rep_len, reply_ptr + MSG_REP_OFFSET, reply_msg_len);

		ZXIC_COMM_FREE(recv_buffer);
		return DPP_OK;
	}

	ZXIC_COMM_FREE(recv_buffer);

	ZXIC_COMM_TRACE_ERROR("%s: zxdh_bar_chan_sync_msg_send failed.\n", __func__);

	return DPP_ERR;
}

DPP_STATUS dpp_agent_channel_reg_write(struct dpp_dev_t *dev, u32 reg_type, u32 reg_no,
				       u32 reg_width, u32 addr, u32 *pData)
{
	DPP_STATUS ret = 0;
	u32 resp_len = 0;
	u8 *resp_buffer = NULL;

	struct dpp_agent_channel_reg_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pData);

	msgcfg.devId = 0;
	msgcfg.type = DPP_REG_MSG;
	msgcfg.subtype = reg_type;
	msgcfg.oper = DPP_WR;
	msgcfg.reg_no = reg_no;
	msgcfg.addr = addr;
	msgcfg.val_len = reg_width / 4;
	memcpy(msgcfg.val, pData, reg_width);

	resp_len = reg_width + 4;
	resp_buffer = (u8 *)ZXIC_COMM_MALLOC(resp_len);
	ZXIC_COMM_CHECK_POINT(resp_buffer);

	memset(resp_buffer, 0, resp_len);

	ret = dpp_agent_channel_reg_sync_send(dev, &msgcfg, (u32 *)resp_buffer, resp_len);

	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "dpp_agent_channel_reg_sync_send", resp_buffer);

	if (DPP_OK != *((u32 *)resp_buffer)) {
		ZXIC_COMM_TRACE_ERROR("%s: dpp_agent_channel_reg_sync_send failed in buffer\n",
				      __func__);
		ZXIC_COMM_FREE(resp_buffer);
		return DPP_ERR;
	}

	memcpy(pData, resp_buffer + 4, reg_width);

	ZXIC_COMM_FREE(resp_buffer);

	return DPP_OK;
}

DPP_STATUS dpp_agent_channel_reg_read(struct dpp_dev_t *dev, u32 reg_type, u32 reg_no,
				      u32 reg_width, u32 addr, u32 *pData)
{
	DPP_STATUS ret = 0;
	u32 resp_len = 0;
	u8 *resp_buffer = NULL;

	struct dpp_agent_channel_reg_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pData);

	msgcfg.devId = 0;
	msgcfg.type = DPP_REG_MSG;
	msgcfg.subtype = reg_type;
	msgcfg.oper = DPP_RD;
	msgcfg.reg_no = reg_no;
	msgcfg.addr = addr;
	msgcfg.val_len = reg_width / 4;

	resp_len = reg_width + 4;
	resp_buffer = (u8 *)ZXIC_COMM_MALLOC(resp_len);
	ZXIC_COMM_CHECK_POINT(resp_buffer);

	memset(resp_buffer, 0, resp_len);

	ret = dpp_agent_channel_reg_sync_send(dev, &msgcfg, (u32 *)resp_buffer, resp_len);

	ZXIC_COMM_CHECK_RC_MEMORY_FREE(ret, "dpp_agent_channel_reg_sync_send", resp_buffer);

	if (DPP_OK != *((u32 *)resp_buffer)) {
		ZXIC_COMM_TRACE_ERROR("%s: dpp_agent_channel_reg_sync_send failed in buffer\n",
				      __func__);
		ZXIC_COMM_FREE(resp_buffer);
		return DPP_ERR;
	}

	memcpy(pData, resp_buffer + 4, reg_width);

	ZXIC_COMM_FREE(resp_buffer);

	return DPP_OK;
}

DPP_STATUS dpp_agent_channel_dtb_sync_send(struct dpp_dev_t *dev,
					   struct dpp_agent_channel_dtb_msg *pMsg, u32 *pData,
					   u32 rep_len)
{
	DPP_STATUS ret = DPP_OK;

	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pMsg);
	ZXIC_COMM_CHECK_POINT(pData);

	agentMsg.msg = (void *)pMsg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_dtb_msg);

	ret = dpp_agent_channel_sync_send(dev, &agentMsg, pData, rep_len);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

	return DPP_OK;
}

DPP_STATUS dpp_agent_channel_dtb_queue_request(struct dpp_dev_t *dev, const u8 *p_name,
					       u32 vport_info, u32 *p_queue_id)
{
	DPP_STATUS ret = DPP_OK;
	u32 rsp_buff[2] = { 0 };
	u32 msg_result = 0;
	u32 queue_id = 0;

	struct dpp_agent_channel_dtb_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = DEV_ID(dev);
	msgcfg.type = DPP_DTB_MSG;
	msgcfg.oper = QUEUE_REQUEST;
	ZXIC_COMM_MEMCPY(msgcfg.name, p_name, ZXIC_COMM_STRLEN(p_name));
	msgcfg.vport = vport_info;

	ZXIC_COMM_TRACE_INFO("%s: msgcfg.name = %s.\n", __func__, msgcfg.name);

	ret = dpp_agent_channel_dtb_sync_send(dev, &msgcfg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_dtb_sync_send");

	msg_result = rsp_buff[0];
	queue_id = rsp_buff[1];

	ZXIC_COMM_TRACE_INFO("%s: msg_result: %d.\n", __func__, msg_result);
	ZXIC_COMM_TRACE_INFO("%s: queue_id: %d.\n", __func__, queue_id);

	*p_queue_id = queue_id;

	return msg_result;
}

DPP_STATUS dpp_agent_channel_dtb_queue_release(struct dpp_dev_t *dev, const u8 *p_name,
					       u32 queue_id)
{
	DPP_STATUS ret = DPP_OK;
	u32 msg_result = 0;
	u32 rsp_buff[2] = { 0 };

	struct dpp_agent_channel_dtb_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = DEV_ID(dev);
	msgcfg.type = DPP_DTB_MSG;
	msgcfg.oper = QUEUE_RELEASE;
	msgcfg.queue_id = queue_id;
	ZXIC_COMM_MEMCPY(msgcfg.name, p_name, ZXIC_COMM_STRLEN(p_name));

	ZXIC_COMM_TRACE_INFO("%s: msgcfg.name = %s.\n", __func__, msgcfg.name);

	ret = dpp_agent_channel_dtb_sync_send(dev, &msgcfg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_dtb_sync_send");

	msg_result = rsp_buff[0];
	ZXIC_COMM_TRACE_INFO("%s: msg_result: %d.\n", __func__, msg_result);

	return msg_result;
}

DPP_STATUS dpp_agent_channel_dtb_queue_sync_cfg(struct dpp_dev_t *dev, const u8 *p_name,
						u32 vport_info, u32 queue_id)
{
	DPP_STATUS ret = DPP_OK;
	u32 rsp_buff[2] = { 0 };
	u32 msg_result = 0;

	struct dpp_agent_channel_dtb_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = DEV_ID(dev);
	msgcfg.type = DPP_DTB_MSG;
	msgcfg.oper = QUEUE_SYNC_CFG;
	msgcfg.queue_id = queue_id;
	ZXIC_COMM_MEMCPY(msgcfg.name, p_name, ZXIC_COMM_STRLEN(p_name));
	msgcfg.vport = vport_info;

	ZXIC_COMM_TRACE_INFO("%s: msgcfg.name = %s.\n", __func__, msgcfg.name);

	ret = dpp_agent_channel_dtb_sync_send(dev, &msgcfg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_dtb_sync_send");

	msg_result = rsp_buff[0];

	ZXIC_COMM_TRACE_INFO("%s: msg_result: %d.\n", __func__, msg_result);
	ZXIC_COMM_TRACE_INFO("%s: queue_id: %d.\n", __func__, queue_id);

	return msg_result;
}

DPP_STATUS dpp_agent_channel_tm_sync_send(struct dpp_dev_t *dev,
					  struct dpp_agent_channel_tm_msg *pMsg, u32 *pData,
					  u32 rep_len)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pMsg);
	ZXIC_COMM_CHECK_POINT(pData);

	agentMsg.msg = (void *)pMsg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_tm_msg);

	ret = dpp_agent_channel_sync_send(dev, &agentMsg, pData, rep_len);

	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

	return DPP_OK;
}

DPP_STATUS dpp_agent_channel_tm_seid_request(struct dpp_dev_t *dev, u32 port, u32 vport,
					     u32 sche_level, u32 sche_type, u32 num, u32 *p_se_id)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };

	struct dpp_agent_channel_tm_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_se_id);

	msgcfg.devId = 0;
	msgcfg.type = DPP_TM_MSG;
	msgcfg.oper = SEID_REQUEST;
	msgcfg.port = port;
	msgcfg.vport = vport;
	msgcfg.sche_level = sche_level;
	msgcfg.sche_type = sche_type;
	msgcfg.num = num;
	msgcfg.se_id = SCHE_REQ_VALID;

	if (sche_type != FLOW_SCHE)
		msgcfg.num = 1;

	ret = dpp_agent_channel_tm_sync_send(dev, &msgcfg, resp_buffer, sizeof(resp_buffer));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

	memcpy(p_se_id, resp_buffer, sizeof(u32) * SCHE_RSP_LEN);

	return ret;
}

DPP_STATUS dpp_agent_channel_tm_seid_release(struct dpp_dev_t *dev, u32 port, u32 vport,
					     u32 sche_level, u32 sche_type, u32 num, u32 se_id)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };

	struct dpp_agent_channel_tm_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = 0;
	msgcfg.type = DPP_TM_MSG;
	msgcfg.oper = SEID_RELEASE;
	msgcfg.port = port;
	msgcfg.vport = vport;
	msgcfg.sche_level = sche_level;
	msgcfg.sche_type = sche_type;
	msgcfg.num = num;
	msgcfg.se_id = se_id;

	if (sche_type != FLOW_SCHE)
		msgcfg.num = 1;

	ret = dpp_agent_channel_tm_sync_send(dev, &msgcfg, resp_buffer, sizeof(resp_buffer));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

	ret = *(u8 *)resp_buffer;

	return ret;
}

DPP_STATUS dpp_agent_channel_tm_base_node_get(struct dpp_dev_t *dev, u32 port, u32 vport,
					      u32 *p_se_id)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };

	struct dpp_agent_channel_tm_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_se_id);

	msgcfg.devId = 0;
	msgcfg.type = DPP_TM_MSG;
	msgcfg.oper = SEID_QUERY;
	msgcfg.port = port;
	msgcfg.vport = vport;
	msgcfg.sche_level = EPID_LEVEL;
	msgcfg.sche_type = WFQ_SCHE;
	msgcfg.num = 1;
	msgcfg.se_id = SCHE_REQ_VALID;

	ret = dpp_agent_channel_tm_sync_send(dev, &msgcfg, resp_buffer, sizeof(resp_buffer));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

	memcpy(p_se_id, resp_buffer, sizeof(u32) * SCHE_RSP_LEN);

	return ret;
}

DPP_STATUS dpp_agent_channel_plcr_sync_send(struct dpp_dev_t *dev,
					    struct dpp_agent_channel_plcr_msg *pMsg, u32 *pData,
					    u32 rep_len)
{
	DPP_STATUS ret = DPP_OK;
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pMsg);

	agentMsg.msg = (void *)pMsg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_plcr_msg);

	ret = dpp_agent_channel_sync_send(dev, &agentMsg, pData, rep_len);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

	return DPP_OK;
}

DPP_STATUS dpp_agent_channel_plcr_profileid_request(struct dpp_dev_t *dev, u32 vport, u32 car_type,
						    u32 *p_profileid)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };

	struct dpp_agent_channel_plcr_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_profileid);

	msgcfg.devId = 0;
	msgcfg.type = DPP_PLCR_MSG;
	msgcfg.oper = PROFILEID_REQUEST;
	msgcfg.vport = vport;
	msgcfg.car_type = car_type;
	msgcfg.profile_id = PROFILEID_REQ_VALID;

	ret = dpp_agent_channel_plcr_sync_send(dev, &msgcfg, resp_buffer, sizeof(resp_buffer));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_plcr_sync_send");

	memcpy(p_profileid, resp_buffer, sizeof(u32) * SCHE_RSP_LEN);

	return ret;
}

DPP_STATUS dpp_agent_channel_plcr_profileid_release(struct dpp_dev_t *dev, u32 vport, u32 car_type,
						    u32 profileid)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };

	struct dpp_agent_channel_plcr_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = 0;
	msgcfg.type = DPP_PLCR_MSG;
	msgcfg.oper = PROFILEID_RELEASE;
	msgcfg.vport = vport;
	msgcfg.car_type = car_type;
	msgcfg.profile_id = profileid;

	ret = dpp_agent_channel_plcr_sync_send(dev, &msgcfg, resp_buffer, sizeof(resp_buffer));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_plcr_sync_send");

	ret = *(u8 *)resp_buffer;

	return ret;
}

DPP_STATUS dpp_agent_channel_tm_flow_shape(struct dpp_dev_t *dev, u32 flow_id, u32 cir, u32 cbs,
					   u32 db_en, u32 eir, u32 ebs)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };
	u32 resp_len = 8;
	struct dpp_agent_channel_msg agentMsg = { 0 };
	struct dpp_agent_tm_flow_shape_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = 0;
	msgcfg.type = DPP_TM_FLOW_SHAPE;
	msgcfg.flow_id = flow_id;
	msgcfg.cir = cir;
	msgcfg.cbs = cbs;
	msgcfg.db_en = db_en;
	msgcfg.eir = eir;
	msgcfg.ebs = ebs;

	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_tm_flow_shape_msg);

	ret = dpp_agent_channel_sync_send(dev, &agentMsg, resp_buffer, resp_len);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

	ret = *(u8 *)resp_buffer;

	return ret;
}

DPP_STATUS dpp_agent_channel_tm_td_set(struct dpp_dev_t *dev, u32 level, u32 id, u32 td_th)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };
	u32 resp_len = 8;
	struct dpp_agent_channel_msg agentMsg = { 0 };
	struct dpp_agent_tm_td_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = 0;
	msgcfg.type = DPP_TM_TD;
	msgcfg.level = level;
	msgcfg.id = id;
	msgcfg.td_th = td_th;

	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_tm_td_msg);

	ret = dpp_agent_channel_sync_send(dev, &agentMsg, resp_buffer, resp_len);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

	ret = *(u8 *)resp_buffer;

	return ret;
}

DPP_STATUS dpp_agent_channel_tm_se_shape(struct dpp_dev_t *dev, u32 se_id, u32 pir, u32 pbs,
					 u32 db_en, u32 cir, u32 cbs)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };
	u32 resp_len = 8;
	struct dpp_agent_channel_msg agentMsg = { 0 };
	struct dpp_agent_tm_se_shape_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = 0;
	msgcfg.type = DPP_TM_SE_SHAPE;
	msgcfg.se_id = se_id;
	msgcfg.pir = pir;
	msgcfg.pbs = pbs;
	msgcfg.db_en = db_en;
	msgcfg.cir = cir;
	msgcfg.cbs = cbs;

	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_tm_se_shape_msg);

	ret = dpp_agent_channel_sync_send(dev, &agentMsg, resp_buffer, resp_len);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

	ret = *(u8 *)resp_buffer;

	return ret;
}

DPP_STATUS dpp_agent_channel_tm_port_shape(struct dpp_dev_t *dev, u32 pp_port, u32 cir, u32 cbs,
					   u32 c_en)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };
	u32 resp_len = 8;
	struct dpp_agent_channel_msg agentMsg = { 0 };
	struct dpp_agent_tm_pp_shape_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	msgcfg.devId = 0;
	msgcfg.type = DPP_TM_PP_SHAPE;
	msgcfg.pp_port = pp_port;
	msgcfg.cir = cir;
	msgcfg.cbs = cbs;
	msgcfg.c_en = c_en;

	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_tm_pp_shape_msg);

	ret = dpp_agent_channel_sync_send(dev, &agentMsg, resp_buffer, resp_len);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

	ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

	ret = *(u8 *)resp_buffer;

	return ret;
}

DPP_STATUS dpp_agent_channel_plcr_car_rate(struct dpp_dev_t *dev, u32 car_type, u32 pkt_sign,
					   u32 profile_id, void *p_car_profile_cfg)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer[2] = { 0 };
	u32 resp_len = 8;
	u32 i = 0;
	struct dpp_agent_channel_msg agentMsg = { 0 };
	struct dpp_agent_car_pkt_profile_msg msgpktcfg = { 0 };
	struct dpp_agent_car_profile_msg msgcfg = { 0 };
	struct dpp_stat_car_profile_cfg_t *p_stat_car_profile_cfg = NULL;
	struct dpp_stat_car_pkt_profile_cfg_t *p_stat_pkt_car_profile_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);

	if ((car_type == STAT_CAR_A_TYPE) && (pkt_sign == 1)) {
		p_stat_pkt_car_profile_cfg =
			(struct dpp_stat_car_pkt_profile_cfg_t *)p_car_profile_cfg;
		msgpktcfg.devId = 0;
		msgpktcfg.type = DPP_PLCR_CAR_PKT_RATE;
		msgpktcfg.car_level = car_type;
		msgpktcfg.cir = p_stat_pkt_car_profile_cfg->cir;
		msgpktcfg.cbs = p_stat_pkt_car_profile_cfg->cbs;
		msgpktcfg.profile_id = p_stat_pkt_car_profile_cfg->profile_id;
		msgpktcfg.pkt_sign = p_stat_pkt_car_profile_cfg->pkt_sign;
		for (i = 0; i < DPP_CAR_PRI_MAX; i++)
			msgpktcfg.pri[i] = p_stat_pkt_car_profile_cfg->pri[i];

		agentMsg.msg = (void *)&msgpktcfg;
		agentMsg.msg_len = sizeof(struct dpp_agent_car_pkt_profile_msg);

		ret = dpp_agent_channel_sync_send(dev, &agentMsg, resp_buffer, resp_len);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

		ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

		ret = *(u8 *)resp_buffer;
	} else {
		p_stat_car_profile_cfg = (struct dpp_stat_car_profile_cfg_t *)p_car_profile_cfg;
		msgcfg.devId = 0;
		msgcfg.type = DPP_PLCR_CAR_RATE;
		msgcfg.car_level = car_type;
		msgcfg.cir = p_stat_car_profile_cfg->cir;
		msgcfg.cbs = p_stat_car_profile_cfg->cbs;
		msgcfg.profile_id = p_stat_car_profile_cfg->profile_id;
		msgcfg.pkt_sign = p_stat_car_profile_cfg->pkt_sign;
		msgcfg.cd = p_stat_car_profile_cfg->cd;
		msgcfg.cf = p_stat_car_profile_cfg->cf;
		msgcfg.cm = p_stat_car_profile_cfg->cm;
		msgcfg.cir = p_stat_car_profile_cfg->cir;
		msgcfg.cbs = p_stat_car_profile_cfg->cbs;
		msgcfg.eir = p_stat_car_profile_cfg->eir;
		msgcfg.ebs = p_stat_car_profile_cfg->ebs;
		msgcfg.random_disc_e = p_stat_car_profile_cfg->random_disc_e;
		msgcfg.random_disc_c = p_stat_car_profile_cfg->random_disc_c;
		for (i = 0; i < DPP_CAR_PRI_MAX; i++) {
			msgcfg.c_pri[i] = p_stat_car_profile_cfg->c_pri[i];
			msgcfg.e_green_pri[i] = p_stat_car_profile_cfg->e_green_pri[i];
			msgcfg.e_yellow_pri[i] = p_stat_car_profile_cfg->e_yellow_pri[i];
		}

		agentMsg.msg = (void *)&msgcfg;
		agentMsg.msg_len = sizeof(struct dpp_agent_car_profile_msg);

		ret = dpp_agent_channel_sync_send(dev, &agentMsg, resp_buffer, resp_len);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

		//ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_tm_sync_send");

		ret = *(u8 *)resp_buffer;
	}

	return ret;
}

DPP_STATUS dpp_agent_channel_ppu_thash_rsk(struct dpp_dev_t *dev, enum dpp_ppu_thash_rsk_oper oper,
					   struct dpp_ppu_ppu_cop_thash_rsk_t *p_para)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer = 0;
	struct dpp_ppu_ppu_cop_thash_rsk_t thash = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };
	struct dpp_agent_ppu_thash_rsk_msg msgcfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_para);
	ZXIC_COMM_CHECK_INDEX(oper, DPP_PPU_THASH_RSK_RD, DPP_PPU_THASH_RSK_WR);

	switch (oper) {
	case DPP_PPU_THASH_RSK_RD:
		msgcfg.devId = 0;
		msgcfg.type = DPP_PPU_THASH_RSK;
		msgcfg.oper = oper;
		msgcfg.rsv = 0;
		msgcfg.rsk_031_000 = 0;
		msgcfg.rsk_063_032 = 0;
		msgcfg.rsk_095_064 = 0;
		msgcfg.rsk_127_096 = 0;
		msgcfg.rsk_159_128 = 0;
		msgcfg.rsk_191_160 = 0;
		msgcfg.rsk_223_192 = 0;
		msgcfg.rsk_255_224 = 0;
		msgcfg.rsk_287_256 = 0;
		msgcfg.rsk_319_288 = 0;

		agentMsg.msg = (void *)&msgcfg;
		agentMsg.msg_len = sizeof(struct dpp_agent_ppu_thash_rsk_msg);

		ret = dpp_agent_channel_sync_send(dev, &agentMsg, (u32 *)&thash,
						  sizeof(struct dpp_ppu_ppu_cop_thash_rsk_t));
		ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

		memcpy(p_para, &thash, sizeof(struct dpp_ppu_ppu_cop_thash_rsk_t));
		break;

	case DPP_PPU_THASH_RSK_WR:
		msgcfg.devId = 0;
		msgcfg.type = DPP_PPU_THASH_RSK;
		msgcfg.oper = oper;
		msgcfg.rsv = 0;
		msgcfg.rsk_031_000 = p_para->rsk_031_000;
		msgcfg.rsk_063_032 = p_para->rsk_063_032;
		msgcfg.rsk_095_064 = p_para->rsk_095_064;
		msgcfg.rsk_127_096 = p_para->rsk_127_096;
		msgcfg.rsk_159_128 = p_para->rsk_159_128;
		msgcfg.rsk_191_160 = p_para->rsk_191_160;
		msgcfg.rsk_223_192 = p_para->rsk_223_192;
		msgcfg.rsk_255_224 = p_para->rsk_255_224;
		msgcfg.rsk_287_256 = p_para->rsk_287_256;
		msgcfg.rsk_319_288 = p_para->rsk_319_288;

		agentMsg.msg = (void *)&msgcfg;
		agentMsg.msg_len = sizeof(struct dpp_agent_ppu_thash_rsk_msg);

		ret = dpp_agent_channel_sync_send(dev, &agentMsg, &resp_buffer, sizeof(u32));
		ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

		ret = resp_buffer;
		break;

	default:
		ZXIC_COMM_TRACE_ERROR("The message to ppu_thash_rsk is not defined\n");
		ret = DPP_ERR;
		break;
	}

	return ret;
}

DPP_STATUS dpp_agent_channel_pktrx_ind_reg_rw(struct dpp_dev_t *dev, u32 mem_addr, u32 mem_id,
					      u32 oper, u32 len, u32 *p_data)
{
	DPP_STATUS ret = DPP_OK;
	u32 resp_buffer = 0;
	u32 oper_len = 0;
	u32 data[8] = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };
	struct dpp_agent_pktrx_ind_reg_rw_msg pktrx_ind_msg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_data);
	ZXIC_COMM_CHECK_INDEX(mem_id, 0, (MEM_ID_MUX_NUM - 1));
	ZXIC_COMM_CHECK_INDEX(len, 1, 4 * 8);
	ZXIC_COMM_CHECK_INDEX(mem_addr, 0, (1 << 12) - 1);
	ZXIC_COMM_CHECK_INDEX(oper, DPP_PKTRX_IND_REG_RD, DPP_PKTRX_IND_REG_WR);

	ZXIC_COMM_MEMSET_S(&pktrx_ind_msg, sizeof(struct dpp_agent_pktrx_ind_reg_rw_msg), 0,
			   sizeof(struct dpp_agent_pktrx_ind_reg_rw_msg));

	oper_len = (len % 4 != 0) ? (len / 4 + 1) : (len / 4);

	pktrx_ind_msg.devId = 0;
	pktrx_ind_msg.type = DPP_PKTRX_IND_REG_RW_MSG;
	pktrx_ind_msg.oper = oper;
	pktrx_ind_msg.rsv = 0;
	pktrx_ind_msg.mem_addr = mem_addr;
	pktrx_ind_msg.mem_id = mem_id;
	pktrx_ind_msg.len = len;

	agentMsg.msg = (void *)&pktrx_ind_msg;
	agentMsg.msg_len = sizeof(struct dpp_agent_pktrx_ind_reg_rw_msg);

	switch (oper) {
	case DPP_PKTRX_IND_REG_RD:
		ret = dpp_agent_channel_sync_send(dev, &agentMsg, data, 32);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

		ZXIC_COMM_MEMCPY_S(p_data, oper_len * 4, data, oper_len * 4);
		break;

	case DPP_PKTRX_IND_REG_WR:
		ZXIC_COMM_MEMCPY_S(pktrx_ind_msg.ind_data, 32, p_data, oper_len * 4);
		ret = dpp_agent_channel_sync_send(dev, &agentMsg, &resp_buffer, sizeof(u32));
		ZXIC_COMM_CHECK_RC_NO_ASSERT(ret, "dpp_agent_channel_sync_send");

		ret = resp_buffer;
		break;

	default:
		ZXIC_COMM_TRACE_ERROR("The message to ppu_thash_rsk is not defined\n");
		ret = DPP_ERR;
		break;
	}

	return ret;
}
DPP_STATUS dpp_agent_channel_acl_index_request(struct dpp_dev_t *dev, u32 sdt_no, u32 vport,
					       u32 *p_index)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 rsp_buff[2] = { 0 };
	u32 msg_result = 0;
	u32 acl_index = 0;
	struct dpp_agent_channel_acl_msg msgcfg = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_index);

	msgcfg.devId = 0;
	msgcfg.type = DPP_ACL_MSG;
	msgcfg.oper = ACL_INDEX_REQUEST;
	msgcfg.vport = vport;
	msgcfg.sdt_no = sdt_no;

	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_acl_msg);
	rc = dpp_agent_channel_sync_send(dev, &agentMsg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_agent_channel_sync_send");

	msg_result = rsp_buff[0];
	acl_index = rsp_buff[1];

	ZXIC_COMM_TRACE_INFO("dev_id: %d, msg_result: %d\n", dev_id, msg_result);
	ZXIC_COMM_TRACE_INFO("dev_id: %d, acl_index: %d\n", dev_id, acl_index);

	*p_index = acl_index;

	return msg_result;
}
DPP_STATUS dpp_agent_channel_acl_index_release(struct dpp_dev_t *dev, u32 rel_type, u32 sdt_no,
					       u32 vport, u32 index)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 msg_result = 0;
	u32 rsp_buff[2] = { 0 };
	struct dpp_agent_channel_acl_msg msgcfg = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	msgcfg.devId = 0;
	msgcfg.type = DPP_ACL_MSG;
	msgcfg.oper = rel_type;
	msgcfg.index = index;
	msgcfg.sdt_no = sdt_no;
	msgcfg.vport = vport;

	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_acl_msg);
	rc = dpp_agent_channel_sync_send(dev, &agentMsg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_agent_channel_sync_send");

	msg_result = rsp_buff[0];
	ZXIC_COMM_TRACE_INFO("msg_result: %d\n", msg_result);

	return msg_result;
}
DPP_STATUS dpp_agent_channel_stat_clr(struct dpp_dev_t *dev, u32 count_id, u32 rd_mode, u32 num)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 msg_result = 0;
	u32 rsp_buff[2] = { 0 };
	struct dpp_agent_channel_stat_msg msgcfg = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	msgcfg.devId = 0;
	msgcfg.type = DPP_STAT_MSG;
	msgcfg.oper = 0;
	msgcfg.counter_id = count_id;
	msgcfg.rd_mode = rd_mode;
	msgcfg.num = num;

	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_stat_msg);
	rc = dpp_agent_channel_sync_send(dev, &agentMsg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_agent_channel_sync_send");

	msg_result = rsp_buff[0];
	ZXIC_COMM_TRACE_INFO("msg_result: %d\n", msg_result);

	return msg_result;
}
DPP_STATUS dpp_agent_channel_acl_stat_clr(struct dpp_dev_t *dev, u32 sdt_no, u32 vport,
					  u32 counter_id, u32 rd_mode)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;

	u32 msg_result = 0;
	u32 rsp_buff[2] = { 0 };
	struct dpp_agent_channel_acl_msg msgcfg = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	msgcfg.devId = 0;
	msgcfg.type = DPP_ACL_MSG;
	msgcfg.oper = ACL_INDEX_STAT_CLR;
	msgcfg.sdt_no = sdt_no;
	msgcfg.vport = vport;
	msgcfg.counter_id = counter_id;
	msgcfg.rd_mode = rd_mode;

	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_acl_msg);
	rc = dpp_agent_channel_sync_send(dev, &agentMsg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_agent_channel_sync_send");

	msg_result = rsp_buff[0];
	ZXIC_COMM_TRACE_INFO("msg_result: %d\n", msg_result);

	return msg_result;
}
DPP_STATUS dpp_agent_channel_se_res_get(struct dpp_dev_t *dev, u32 sub_type, u32 opr,
					u32 *p_rsp_buff, u32 buff_size)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 msg_result = 0;
	struct dpp_agent_se_res_msg msgcfg = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(opr, 0, RES_REQ_MAX - 1);
	ZXIC_COMM_CHECK_POINT_NO_ASSERT(p_rsp_buff);

	msgcfg.devId = 0;
	msgcfg.type = DPP_RES_MSG;
	msgcfg.sub_type = sub_type;
	msgcfg.oper = opr;
	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_se_res_msg);

	rc = dpp_agent_channel_sync_send(dev, &agentMsg, p_rsp_buff, buff_size);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_agent_channel_sync_send");

	msg_result = p_rsp_buff[0];
	ZXIC_COMM_TRACE_INFO("msg_result: %d\n", msg_result);
	dpp_agent_msg_prt(msgcfg.type, msg_result);

	return msg_result;
}
DPP_STATUS dpp_agent_channel_pcie_bar_request(struct dpp_dev_t *dev, u32 *p_bar_msg_num)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 rsp_buff[2] = { 0 };
	u32 msg_result = 0;
	u32 bar_msg_num = 0;
	struct dpp_agent_channel_pcie_bar_msg msgcfg = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_bar_msg_num);

	msgcfg.devId = 0;
	msgcfg.type = DPP_PCIE_BAR_MSG;
	msgcfg.oper = BAR_MSG_NUM_REQ;
	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_pcie_bar_msg);

	rc = dpp_agent_channel_sync_send(dev, &agentMsg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_agent_channel_dtb_sync_send");

	msg_result = rsp_buff[0];
	bar_msg_num = rsp_buff[1];
	ZXIC_COMM_TRACE_INFO("dev_id: %d, msg_result: %d\n", dev_id, msg_result);
	ZXIC_COMM_TRACE_INFO("dev_id: %d, bar_num: %d\n", dev_id, bar_msg_num);
	dpp_agent_msg_prt(msgcfg.type, msg_result);

	*p_bar_msg_num = bar_msg_num;

	return msg_result;
}
DPP_STATUS dpp_agent_channel_psn_cfg_l2d_write(struct dpp_dev_t *dev, u8 psn_cfg)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 msg_result = 0;
	struct dpp_agent_channel_psn_cfg_msg msgcfg = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	msgcfg.devId = 0;
	msgcfg.type = DPP_PSN_CFG_MSG;
	msgcfg.oper = PSN_CFG_L2D_WR;
	msgcfg.psn = psn_cfg;
	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_psn_cfg_msg);

	rc = dpp_agent_channel_sync_send(dev, &agentMsg, &msg_result, ZXIC_SIZEOF(msg_result));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_agent_channel_sync_send");

	ZXIC_COMM_TRACE_INFO("dev_id: %d, msg_result: %d\n", dev_id, msg_result);
	dpp_agent_msg_prt(msgcfg.type, msg_result);

	return msg_result;
}
DPP_STATUS dpp_agent_channel_psn_cfg_l2d_read(struct dpp_dev_t *dev, u32 *p_psn_cfg)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 rsp_buff[2] = { 0 };
	u32 msg_result = 0;
	struct dpp_agent_channel_psn_cfg_msg msgcfg = { 0 };
	struct dpp_agent_channel_msg agentMsg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_psn_cfg);

	msgcfg.devId = 0;
	msgcfg.type = DPP_PSN_CFG_MSG;
	msgcfg.oper = PSN_CFG_L2D_RD;
	agentMsg.msg = (void *)&msgcfg;
	agentMsg.msg_len = sizeof(struct dpp_agent_channel_psn_cfg_msg);

	rc = dpp_agent_channel_sync_send(dev, &agentMsg, rsp_buff, ZXIC_SIZEOF(rsp_buff));
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_agent_channel_sync_send");

	msg_result = rsp_buff[0];
	ZXIC_COMM_TRACE_NOTICE("dev_id: %d, msg_result: %d\n", dev_id, msg_result);

	dpp_agent_msg_prt(msgcfg.type, msg_result);

	*p_psn_cfg = rsp_buff[1];

	ZXIC_COMM_TRACE_NOTICE("dev_id: %d, psn_cfg: %d\n", dev_id, rsp_buff[1]);

	return msg_result;
}
