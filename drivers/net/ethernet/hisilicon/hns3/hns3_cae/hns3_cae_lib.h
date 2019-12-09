/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef HNS3_CAE_LIB_H_
#define HNS3_CAE_LIB_H_

#ifndef IFNAMSIZ
#define IFNAMSIZ    16
#endif
/* completion overtime in (unit of) jiffies */
#define UP_COMP_TIME_OUT_VAL		10000U
#define UCODE_COMP_TIME_OUT_VAL		0xFF00000
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
	RECV_PKT,

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
	RAS_RESET_CFG = 501,
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
	QRES_CFG = 1100,
	STAT_CFG,
	IRQ_CFG,

	VLAN_UPMAPPING = 1200,

	EXTERN_INTERFACE_CFG = 1300,	/* extern interface test */
	XSFP_CFG = 1400,
	SHOW_PORT_INFO,
	SHOW_HILINK_PARAM,
	DCQCN_PARM_CFG = 1500,
	DCQCN_GET_MSG_CNT_CMD = 1600
};

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

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

enum {
	DCQCN_MASK_AI = 0x0,
	DCQCN_MASK_F,
	DCQCN_MASK_TKP,
	DCQCN_MASK_TMP,
	DCQCN_MASK_ALP,
	DCQCN_MASK_G,
	DCQCN_MASK_AL,
	DCQCN_MASK_MAX_SPEED,
	DCQCN_MASK_CNP_TIME,
	DCQCN_MASK_ALP_SHIFT,
};

#define HINICADM_DCQCN_READ_CFG_MODE	30
#define HINICADM_DCQCN_WRITE_CFG_MODE	31

int hns3_cae_k_init(void);
void hns3_cae_k_uninit(void);

struct hns3_cae_commit_id_param {
	u8 commit_id[8];
	u32 ncl_version;
	u32 rsv[3];
};

struct firmware_ver_param {
	u32 imp_ver;
	u8 commit_id[9];
	u8 rsv[3];
	u32 ncl_version;
};

struct hclge_gro_age_config_cmd {
	u32 ppu_gro_age_cnt;
	u8 rsv[20];
};

struct gro_param {
	u8 is_read;
	u32 age_cnt;
};

struct cfg_dcqcn_param {
	u16 ai;
	u8 f;
	u8 tkp;
	u16 tmp;
	u16 alp;
	u32 max_speed;
	u8 g;
	u8 al;
	u8 cnp_time;
	u8 alp_shift;
	u16 dcqcn_parm_opcode;
	u16 is_get;
	u32 device_number;
};

struct dcqcn_statistic_param {
	u32 dcqcn_rx_cnt;
	u32 dcqcn_tx_cnt;
	u32 dcqcn_db_cnt;
	u32 dcqcn_statistic_enable;
};

enum DEVMEM_RW_TYPE {
	DEVMEM_CFG_WRITE = 0,
	DEVMEM_CFG_READ,
};

#endif
