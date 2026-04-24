/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _UB_UBASE_COMM_CMD_H_
#define _UB_UBASE_COMM_CMD_H_

#include <linux/auxiliary_bus.h>
#include <linux/types.h>

#define UBASE_CMDQ_MAX_DATA_SIZE	(1024 - 8)

#define UBASE_FW_VERSION_BYTE3_MASK	GENMASK(31, 24)
#define UBASE_FW_VERSION_BYTE2_MASK	GENMASK(23, 16)
#define UBASE_FW_VERSION_BYTE1_MASK	GENMASK(15, 8)
#define UBASE_FW_VERSION_BYTE0_MASK	GENMASK(7, 0)

#define UBASE_CSQ_BASEADDR_L_REG	0x18400
#define UBASE_CSQ_BASEADDR_H_REG	0x18404
#define UBASE_CSQ_DEPTH_REG		0x18408
#define UBASE_CSQ_TAIL_REG		0x18410
#define UBASE_CSQ_HEAD_REG		0x18414
#define UBASE_CRQ_BASEADDR_L_REG	0x18418
#define UBASE_CRQ_BASEADDR_H_REG	0x1841c
#define UBASE_CRQ_DEPTH_REG		0x18420
#define UBASE_CRQ_TAIL_REG		0x18424
#define UBASE_CRQ_HEAD_REG		0x18428

enum ubase_opcode_type {
	/* Generic commands */
	UBASE_OPC_QUERY_FW_VER		= 0x0001,
	UBASE_OPC_QUERY_CTL_INFO	= 0x0003,
	UBASE_OPC_QUERY_DTU_INFO	= 0x0005,
	UBASE_OPC_CONFIG_DTU_TBL	= 0x0006,
	UBASE_OPC_NOTIFY_DRV_CAPS	= 0x0007,
	UBASE_OPC_QUERY_COMM_RSRC_PARAM	= 0x0030,
	UBASE_OPC_QUERY_NIC_RSRC_PARAM	= 0x0031,
	UBASE_OPC_QUERY_LINK_STATUS	= 0x0032,
	UBASE_OPC_CFG_MTU		= 0x0033,
	UBASE_OPC_QUERY_NET_GUID	= 0x0035,
	UBASE_OPC_STATS_MAC_ALL		= 0x0038,
	UBASE_OPC_DFX_REG_NUM		= 0x0039,
	UBASE_OPC_DFX_DL_REG		= 0x0040,
	UBASE_OPC_DFX_NL_REG		= 0x0042,
	UBASE_OPC_DFX_BA_REG		= 0x0043,
	UBASE_OPC_DFX_TP_REG		= 0x0044,
	UBASE_OPC_DFX_TA_REG		= 0x0045,
	UBASE_OPC_QUERY_UE_TA_RSRC	= 0x0046,
	UBASE_OPC_QUERY_BUS_EID		= 0x0047,
	UBASE_OPC_DFX_HIMAC_REG		= 0x0048,
	UBASE_OPC_QUERY_UBCL_CONFIG	= 0x0050,

	/* NL commands */
	UBASE_OPC_VLAN_FILTER_CTRL	= 0x2100,
	UBASE_OPC_VLAN_FILTER_CFG	= 0x2101,
	UBASE_OPC_QUERY_VLAN_TBL	= 0x2102,
	UBASE_OPC_CFG_VL_MAP		= 0x2206,
	UBASE_OPC_CFG_ETS_TC_INFO	= 0x2340,
	UBASE_OPC_QUERY_ETS_TCG_INFO	= 0x2341,
	UBASE_OPC_QUERY_ETS_PORT_INFO	= 0x2342,
	UBASE_OPC_QUERY_VL_AGEING_EN	= 0x2343,
	UBASE_OPC_CFG_PROMISC_MODE	= 0x240A,
	UBASE_OPC_QUERY_MAC		= 0x241A,
	UBASE_OPC_ADD_MAC_TBL		= 0x241B,
	UBASE_OPC_DEL_MAC_TBL		= 0x241C,
	UBASE_OPC_QUERY_MAC_TBL		= 0x241E,
	UBASE_OPC_QUERY_MNG_TBL		= 0x241F,

	/* TP commands */
	UBASE_OPC_TP_TIMER_VA_CONFIG	= 0x3007,
	UBASE_OPC_TP_EXTDB_VA_CONFIG	= 0x3008,
	UBASE_OPC_TP_RSS_CONFIG		= 0x300B,
	UBASE_OPC_QUERY_CTP_VL_OFFSET	= 0x3112,

	/* TA commands */
	UBASE_OPC_TA_EXTDB_VA_CONFIG	= 0x4000,
	UBASE_OPC_TA_TIMER_VA_CONFIG	= 0x4001,
	UBASE_OPC_QUERY_OOR_CAPS	= 0x4200,
	UBASE_OPC_QUERY_TA_SL_VL_MAP	= 0x4201,
	UBASE_OPC_TA_VL_SCH_CONFIG	= 0x4202,
	UBASE_OPC_VL_RATE_LIMIT_CONFIG	= 0x4203,
	UBASE_OPC_QUERY_TM_Q_INFO	= 0x4205,
	UBASE_OPC_QUERY_TM_QS_INFO	= 0x4206,
	UBASE_OPC_QUERY_TM_PRI_INFO	= 0x4207,
	UBASE_OPC_QUERY_TM_PG_INFO	= 0x4208,
	UBASE_OPC_QUERY_TM_PORT_INFO	= 0x4209,
	UBASE_OPC_QUERY_FST_FVT_RQMT	= 0x4212,

	/* DL commands */
	UBASE_OPC_DL_CONFIG_MODE	= 0x5100,
	UBASE_OPC_DL_CONFIG_LB		= 0x5101,
	UBASE_OPC_QUERY_FLUSH_STATUS	= 0x5102,
	UBASE_OPC_START_PERF_STATS	= 0x5103,
	UBASE_OPC_STOP_PERF_STATS	= 0x5104,
	UBASE_OPC_QUERY_UB_PORT_BITMAP	= 0x5105,
	UBASE_OPC_QUERY_UB_DL_PKT_STATS	= 0x5106,

	/* PHY commands */
	UBASE_OPC_CONFIG_SPEED_DUP	= 0x6100,
	UBASE_OPC_CONFIG_AUTONEG_MODE	= 0x6101,
	UBASE_OPC_CONFIG_FEC_MODE	= 0x6102,
	UBASE_OPC_QUERY_PORT_INFO	= 0x6200,
	UBASE_OPC_QUERY_CHIP_INFO	= 0x6201,
	UBASE_OPC_QUERY_FEC_STATS	= 0x6202,
	UBASE_OPC_QUERY_LINK_DIAGNOSIS	= 0x6203,
	UBASE_OPC_CFG_MAC_PAUSE_EN	= 0x6300,
	UBASE_OPC_CFG_PFC_PAUSE_EN	= 0x6301,
	UBASE_OPC_HIMAC_RESET		= 0x6302,

	/* Mailbox commands */
	UBASE_OPC_POST_MB		= 0x7000,
	UBASE_OPC_QUERY_MB_ST		= 0X7001,

	/* Ubctl commands */
	UBASE_OPC_QUERY_PORT_BITMAP	= 0xA017,

	/* Software commands */
	UBASE_OPC_MUE_TO_UE		= 0xF001,
	UBASE_OPC_UE_TO_MUE		= 0xF002,
	UBASE_OPC_CFG_VPORT_BUF		= 0xF003,
	UBASE_OPC_NOTIFY_UE_RESET	= 0xF006,
	UBASE_OPC_QUERY_UE_RST_RDY	= 0xF007,
	UBASE_OPC_RESET_DONE		= 0xF008,
	UBASE_OPC_VPORT_CTX		= 0xF009,
	UBASE_OPC_DESTROY_CTX_RESOURCE	= 0xF00D,
	UBASE_OPC_UE2UE_UBASE		= 0xF00E,
	UBASE_OPC_ACTIVATE_REQ		= 0xF00F,
	UBASE_OPC_ACTIVATE_RESP		= 0xF010,
	UBASE_OPC_UE_ISOLATED_NOTIFY	= 0xF011,
	UBASE_OPC_QUERY_UE_ISOLATED_STATE = 0xF012,
	UBASE_OPC_SET_CTX_VA_REQ	= 0xF013,
	UBASE_OPC_UPDATE_CTX_VA_STATUS	= 0xF014,
	UBASE_OPC_UE_RESET_NOTIFY	= 0xF015,
	UBASE_OPC_PROXY_TO_UBASE	= 0xF017,
	UBASE_OPC_PROXY_TO_UDMA		= 0xF018,
	UBASE_OPC_UE_TO_PROXY		= 0xF019,
	UBASE_OPC_SET_CTX_VA_RESP	= 0xF01A,
};

enum ubase_ue_to_proxy_module {
	UBASE_MODULE_UDMA_TO_PROXY = 0x01,
	UBASE_MODULE_UBASE_TO_PROXY = 0x02,
};

/**
 * struct ubase_cmd_buf - ubase cmd buffer structure
 * @opcode: cmdq opcode
 * @is_read: read or write, true for read, false for write
 * @data_size: valid length of data
 * @data: data buffer
 */
struct ubase_cmd_buf {
	u16	opcode;
	bool	is_read;
	u32	data_size;
	void	*data;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_crq_event_nb - ubase crq event notification block structure
 * @opcode: cmdq crq opcode
 * @back: arbitrary registered pointer
 * @crq_handler: cmdq crq handle function. dev: the struct member variable 'back',
 * data: the crq message data, len: the crq message data length.
 */
struct ubase_crq_event_nb {
	u16 opcode;
	void *back;
	int (*crq_handler)(void *dev, void *data, u32 len);
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_proxy_req_msg - ubase proxy request message structure
 * @bus_ue_id: bus ub entity id
 * @mbx_ue_id: mailbox ub entity id
 * @module: module that sends this request message
 * @opcode: mailbox opcode
 * @seq_num: message sequence number
 * @tag: mailbox queue id
 * @data_len: valid length of request message data
 * @data: request message data
 */
struct ubase_proxy_req_msg {
	__le16 bus_ue_id;
	__le16 mbx_ue_id;
	u16 module;
	u16 opcode;
	u32 seq_num;
	u16 tag;
	u16 data_len;
	u8 data[];
};

/**
 * struct ubase_proxy_resp_msg - ubase proxy response message structure
 * @bus_ue_id: bus ub entity id
 * @mbx_ue_id: mailbox ub entity id
 * @seq_num: message sequence number
 * @ret: return value of the request message execution result
 * @rsv: reserved bits
 * @data_len: valid length of response message data
 * @data: response message data
 */
struct ubase_proxy_resp_msg {
	__le16 bus_ue_id;
	__le16 mbx_ue_id;
	u32 seq_num;
	int ret;
	u8 rsv[2];
	u16 data_len;
	u8 data[];
};

/**
 * struct ubase_proxy_set_ctx_va_cmd - ubase proxy set context va command structure
 * @bus_ue_id: bus ub entity id
 * @mbx_ue_id: mailbox ub entity id
 * @ctx_type: context va type
 * @result: result of context va configuration
 * @rsv: reserved bits
 */
struct ubase_proxy_set_ctx_va_cmd {
	__le16	bus_ue_id;
	__le16	mbx_ue_id;
	__le16	ctx_type;
	u16	result;
	u8	resv[16];
};

/**
 * ubase_fill_inout_buf() - fill ubase cmd buffer
 * @buf: ubase cmd buffer
 * @opcode: cmdq opcode
 * @is_read: read or write, true for read, false for write
 * @data_size: valid length of data
 * @data: data buffer
 *
 * The function is used to assign 'opcode', 'is_read', 'data_size' and 'data'
 * to 'struct ubase_cmd_buf'.
 *
 * Context: Process context.
 */
static inline void ubase_fill_inout_buf(struct ubase_cmd_buf *buf, u16 opcode,
					bool is_read, u32 data_size, void *data)
{
	buf->opcode = opcode;
	buf->is_read = is_read;
	buf->data_size = data_size;
	buf->data = data;
}

int ubase_cmd_send_inout(struct auxiliary_device *aux_dev,
			 struct ubase_cmd_buf *in, struct ubase_cmd_buf *out);
int ubase_cmd_send_in(struct auxiliary_device *aux_dev,
		      struct ubase_cmd_buf *in);
int ubase_cmd_send_inout_ex(struct auxiliary_device *aux_dev,
			    struct ubase_cmd_buf *in, struct ubase_cmd_buf *out,
			    u32 time_out);
int ubase_cmd_send_in_ex(struct auxiliary_device *aux_dev,
			 struct ubase_cmd_buf *in, u32 time_out);

int ubase_cmd_get_data_size(struct auxiliary_device *aux_dev, u16 opcode,
			    u16 *data_size);

int ubase_register_crq_event(struct auxiliary_device *aux_dev,
			     struct ubase_crq_event_nb *nb);
void ubase_unregister_crq_event(struct auxiliary_device *aux_dev, u16 opcode);

#endif /* _UBASE_COMM_CMD_H_ */
