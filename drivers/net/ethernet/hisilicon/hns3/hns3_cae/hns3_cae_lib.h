/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef HNS3_CAE_LIB_H_
#define HNS3_CAE_LIB_H_

#ifndef IFNAMSIZ
#define IFNAMSIZ    16
#endif

#define NIC_TOOL_MAGIC			'x'

enum module_name {
	SEND_TO_DRIVER = 1,
};

enum driver_cmd_type {
	FW_VER = 1,
	DRIVER_VER,
	CHECKSUM_CFG,
	RX_CS_STATISTICS_INFO,
	CLEAN_STASTICS,
	MAX_TSO_SIZE,
	FUNC_TYPE,

	TM_QUEUE_CFG = 100,
	TM_QSET_CFG,
	TM_PRI_CFG,
	TM_PG_CFG,
	TM_PORT_CFG,
	TM_ETS_CFG,

	DCB_MODE_CFG = 150,
	ETS_MODE_CFG,
	PFC_MODE_CFG,

	MAC_LOOP_CFG = 200,

	DFX_INFO_CMD = 250,
	DFX_READ_CMD,
	EVENT_INJECTION_CMD,

	SEND_PKT = 300,

	RX_PRIV_BUFF_WL_CFG = 400,
	RX_COMMON_THRD_CFG,
	RX_COMMON_WL_CFG,
	MAC_PAUSE_EN_CFG,
	PFC_PAUSE_EN_CFG,
	MAC_PAUSE_PARAM_CFG,
	SHOW_PAUSE_CFG,
	SHOW_PRI_MAP_CFG,
	SHOW_RX_PRIV_WL,
	SHOW_RX_COMM_THRES,
	TX_BUFF_CFG,
	RX_BUFF_CFG,
	SHOW_TX_QUEUE_TO_TC,
	L2_PFC_CFG,
	QCN_EN_CFG,

	RESET_CFG = 500,
	TIMEOUT_CFG = 550,

	CLEAN_STATS = 600,
	PROMISC_MODE_CFG = 700,
	QINFO_CFG = 800,

	MACTABLE_CFG = 900,

	PHY_REGISTER_CFG = 1000,
	FD_CFG,

	RSS_GENERIC_CFG,
	REG_CFG,
	COM_REG_CFG,
	GRO_CFG,
	LAMP_CFG,
	M7_CMD_MODE_CFG,	/* M7 cmd */
	GET_BD_BUFF_SIZE,
	QRES_CFG = 1100,
	STAT_CFG,
	IRQ_CFG,

	VLAN_UPMAPPING = 1200,

	EXTERN_INTERFACE_CFG = 1300,
	XSFP_CFG = 1400,
	SHOW_PORT_INFO,
	SHOW_HILINK_PARAM,
	DCQCN_PARM_CFG = 1500,
	DCQCN_GET_MSG_CNT_CMD = 1600,
	LED_CFG_NCL_INFO_CMD
};

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

struct cmd_desc {
	u16 opcode;
	u16 flag;
	u16 retval;
	u16 rsv;
	u32 data[6];
};

struct cmd_desc_param {
	struct cmd_desc reg_desc;
	u32 fw_dw_opcode;
	u32 is_read;
};

#define API_CMD (0x1)
#define API_CHAIN (0x2)

struct msg_module {
	char device_name[IFNAMSIZ];
	unsigned int module;
	u32 msg_formate;	/* cmd type for driver */
	struct {
		u32 in_buff_len;
		u32 out_buff_len;
	} len_info;
	u32 res;
	void *in_buff;
	void *out_buf;
};

struct m7_cmd_para {
	u32 bd_count;
	u32 bd_type;
	void *bd_data;
};

int hns3_cae_common_cmd_send(const struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size, void *buf_out,
			     u32 out_size);

int hns3_m7_cmd_handle(const struct hns3_nic_priv *nic_dev, void *buf_in,
		       u32 in_size, void *buf_out, u32 out_size);
#endif
