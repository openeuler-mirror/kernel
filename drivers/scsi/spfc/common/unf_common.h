/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_COMMON_H
#define UNF_COMMON_H

#include "unf_type.h"
#include "unf_fcstruct.h"

/* version num */
#define SPFC_DRV_VERSION "B101"
#define SPFC_DRV_DESC "Ramaxel Memory Technology Fibre Channel Driver"

#define UNF_MAX_SECTORS 0xffff
#define UNF_ORIGIN_HOTTAG_MASK 0x7fff
#define UNF_HOTTAG_FLAG (1 << 15)
#define UNF_PKG_FREE_OXID 0x0
#define UNF_PKG_FREE_RXID 0x1

#define UNF_SPFC_MAXRPORT_NUM (2048)
#define SPFC_DEFAULT_RPORT_INDEX (UNF_SPFC_MAXRPORT_NUM - 1)

/* session use sq num */
#define UNF_SQ_NUM_PER_SESSION 3

extern atomic_t fc_mem_ref;
extern u32 unf_dgb_level;
extern u32 spfc_dif_type;
extern u32 spfc_dif_enable;
extern u8 spfc_guard;
extern int link_lose_tmo;

/* define bits */
#define UNF_BIT(n) (0x1UL << (n))
#define UNF_BIT_0 UNF_BIT(0)
#define UNF_BIT_1 UNF_BIT(1)
#define UNF_BIT_2 UNF_BIT(2)
#define UNF_BIT_3 UNF_BIT(3)
#define UNF_BIT_4 UNF_BIT(4)
#define UNF_BIT_5 UNF_BIT(5)

#define UNF_BITS_PER_BYTE 8

#define UNF_NOTIFY_UP_CLEAN_FLASH 2

/* Echo macro define */
#define ECHO_MG_VERSION_LOCAL 1
#define ECHO_MG_VERSION_REMOTE 2

#define SPFC_WIN_NPIV_NUM 32

#define UNF_GET_NAME_HIGH_WORD(name) (((name) >> 32) & 0xffffffff)
#define UNF_GET_NAME_LOW_WORD(name) ((name) & 0xffffffff)

#define UNF_FIRST_LPORT_ID_MASK 0xffffff00
#define UNF_PORT_ID_MASK 0x000000ff
#define UNF_FIRST_LPORT_ID 0x00000000
#define UNF_SECOND_LPORT_ID 0x00000001
#define UNF_EIGHTH_LPORT_ID 0x00000007
#define SPFC_MAX_COUNTER_TYPE 128

#define UNF_EVENT_ASYN 0
#define UNF_EVENT_SYN 1
#define UNF_GLOBAL_EVENT_ASYN 2
#define UNF_GLOBAL_EVENT_SYN 3

#define UNF_GET_SLOT_ID_BY_PORTID(port_id) (((port_id) & 0x001f00) >> 8)
#define UNF_GET_FUNC_ID_BY_PORTID(port_id) ((port_id) & 0x0000ff)
#define UNF_GET_BOARD_TYPE_AND_SLOT_ID_BY_PORTID(port_id) \
	(((port_id) & 0x00FF00) >> 8)

#define UNF_FC_SERVER_BOARD_8_G 13 /* 8G mode */
#define UNF_FC_SERVER_BOARD_16_G 7 /* 16G mode */
#define UNF_FC_SERVER_BOARD_32_G 6 /* 32G mode */

#define UNF_PORT_TYPE_FC_QSFP 1
#define UNF_PORT_TYPE_FC_SFP 0
#define UNF_PORT_UNGRADE_FW_RESET_ACTIVE 0
#define UNF_PORT_UNGRADE_FW_RESET_INACTIVE 1

enum unf_rport_qos_level {
	UNF_QOS_LEVEL_DEFAULT = 0,
	UNF_QOS_LEVEL_MIDDLE,
	UNF_QOS_LEVEL_HIGH,
	UNF_QOS_LEVEL_BUTT
};

struct buff_list {
	u8 *vaddr;
	dma_addr_t paddr;
};

struct buf_describe {
	struct buff_list *buflist;
	u32 buf_size;
	u32 buf_num;
};

#define IO_STATICS
struct unf_port_info {
	u32 local_nport_id;
	u32 nport_id;
	u32 rport_index;
	u64 port_name;
	enum unf_rport_qos_level qos_level;
	u8 cs_ctrl;
	u8 rsvd0[3];
	u32 sqn_base;
};

struct unf_cfg_item {
	char *puc_name;
	u32 min_value;
	u32 default_value;
	u32 max_value;
};

struct unf_port_param {
	u32 ra_tov;
	u32 ed_tov;
};

/* get wwpn adn wwnn */
struct unf_get_chip_info_argout {
	u8 board_type;
	u64 wwpn;
	u64 wwnn;
	u64 sys_mac;
};

/* get sfp info: present and speed */
struct unf_get_port_info_argout {
	u8 sfp_speed;
	u8 present;
	u8 rsvd[2];
};

/* SFF-8436(QSFP+) Rev 4.7 */
struct unf_sfp_plus_field_a0 {
	u8 identifier;
	/* offset 1~2 */
	struct {
		u8 reserved;
		u8 status;
	} status_indicator;
	/* offset 3~21 */
	struct {
		u8 rx_tx_los;
		u8 tx_fault;
		u8 all_resv;

		u8 ini_complete : 1;
		u8 bit_resv : 3;
		u8 temp_low_warn : 1;
		u8 temp_high_warn : 1;
		u8 temp_low_alarm : 1;
		u8 temp_high_alarm : 1;

		u8 resv : 4;
		u8 vcc_low_warn : 1;
		u8 vcc_high_warn : 1;
		u8 vcc_low_alarm : 1;
		u8 vcc_high_alarm : 1;

		u8 resv8;
		u8 rx_pow[2];
		u8 tx_bias[2];
		u8 reserved[6];
		u8 vendor_specifics[3];
	} interrupt_flag;
	/* offset 22~33 */
	struct {
		u8 temp[2];
		u8 reserved[2];
		u8 supply_vol[2];
		u8 reserveds[2];
		u8 vendor_specific[4];
	} module_monitors;
	/* offset 34~81 */
	struct {
		u8 rx_pow[8];
		u8 tx_bias[8];
		u8 reserved[16];
		u8 vendor_specific[16];
	} channel_monitor_val;

	/* offset 82~85 */
	u8 reserved[4];

	/* offset 86~97 */
	struct {
		/* 86~88 */
		u8 tx_disable;
		u8 rx_rate_select;
		u8 tx_rate_select;

		/* 89~92 */
		u8 rx4_app_select;
		u8 rx3_app_select;
		u8 rx2_app_select;
		u8 rx1_app_select;
		/* 93 */
		u8 power_override : 1;
		u8 power_set : 1;
		u8 reserved : 6;

		/* 94~97 */
		u8 tx4_app_select;
		u8 tx3_app_select;
		u8 tx2_app_select;
		u8 tx1_app_select;
		/* 98~99 */
		u8 reserved2[2];
	} control;
	/* 100~106 */
	struct {
		/* 100 */
		u8 m_rx1_los : 1;
		u8 m_rx2_los : 1;
		u8 m_rx3_los : 1;
		u8 m_rx4_los : 1;
		u8 m_tx1_los : 1;
		u8 m_tx2_los : 1;
		u8 m_tx3_los : 1;
		u8 m_tx4_los : 1;
		/* 101 */
		u8 m_tx1_fault : 1;
		u8 m_tx2_fault : 1;
		u8 m_tx3_fault : 1;
		u8 m_tx4_fault : 1;
		u8 reserved : 4;
		/* 102 */
		u8 reserved1;
		/* 103 */
		u8 mini_cmp_flag : 1;
		u8 rsv : 3;
		u8 m_temp_low_warn : 1;
		u8 m_temp_high_warn : 1;
		u8 m_temp_low_alarm : 1;
		u8 m_temp_high_alarm : 1;
		/* 104 */
		u8 rsv1 : 4;
		u8 m_vcc_low_warn : 1;
		u8 m_vcc_high_warn : 1;
		u8 m_vcc_low_alarm : 1;
		u8 m_vcc_high_alarm : 1;
		/* 105~106 */
		u8 vendor_specific[2];
	} module_channel_mask_bit;
	/* 107~118 */
	u8 resv[12];
	/* 119~126 */
	u8 password_reserved[8];
	/* 127 */
	u8 page_select;
};

/* page 00 */
struct unf_sfp_plus_field_00 {
	/* 128~191 */
	struct {
		u8 id;
		u8 id_ext;
		u8 connector;
		u8 speci_com[6];
		u8 mode;
		u8 speed;
		u8 encoding;
		u8 br_nominal;
		u8 ext_rate_select_com;
		u8 length_smf;
		u8 length_om3;
		u8 length_om2;
		u8 length_om1;
		u8 length_copper;
		u8 device_tech;
		u8 vendor_name[16];
		u8 ex_module;
		u8 vendor_oui[3];
		u8 vendor_pn[16];
		u8 vendor_rev[2];
		/* Wave length or Copper cable Attenuation*/
		u8 wave_or_copper_attenuation[2];
		u8 wave_length_toler[2]; /* Wavelength tolerance */
		u8 max_temp;
		u8 cc_base;
	} base_id_fields;
	/* 192~223 */
	struct {
		u8 options[4];
		u8 vendor_sn[16];
		u8 date_code[8];
		u8 diagn_monit_type;
		u8 enhance_opt;
		u8 reserved;
		u8 ccext;
	} ext_id_fields;
	/* 224~255 */
	u8 vendor_spec_eeprom[32];
};

/* page 01 */
struct unf_sfp_plus_field_01 {
	u8 optional01[128];
};

/* page 02 */
struct unf_sfp_plus_field_02 {
	u8 optional02[128];
};

/* page 03 */
struct unf_sfp_plus_field_03 {
	u8 temp_high_alarm[2];
	u8 temp_low_alarm[2];
	u8 temp_high_warn[2];
	u8 temp_low_warn[2];

	u8 reserved1[8];

	u8 vcc_high_alarm[2];
	u8 vcc_low_alarm[2];
	u8 vcc_high_warn[2];
	u8 vcc_low_warn[2];

	u8 reserved2[8];
	u8 vendor_specific1[16];

	u8 pow_high_alarm[2];
	u8 pow_low_alarm[2];
	u8 pow_high_warn[2];
	u8 pow_low_warn[2];

	u8 bias_high_alarm[2];
	u8 bias_low_alarm[2];
	u8 bias_high_warn[2];
	u8 bias_low_warn[2];

	u8 tx_power_high_alarm[2];
	u8 tx_power_low_alarm[2];
	u8 reserved3[4];

	u8 reserved4[8];

	u8 vendor_specific2[16];
	u8 reserved5[2];
	u8 vendor_specific3[12];
	u8 rx_ampl[2];
	u8 rx_tx_sq_disable;
	u8 rx_output_disable;
	u8 chan_monit_mask[12];
	u8 reserved6[2];
};

struct unf_sfp_plus_info {
	struct unf_sfp_plus_field_a0 sfp_plus_info_a0;
	struct unf_sfp_plus_field_00 sfp_plus_info_00;
	struct unf_sfp_plus_field_01 sfp_plus_info_01;
	struct unf_sfp_plus_field_02 sfp_plus_info_02;
	struct unf_sfp_plus_field_03 sfp_plus_info_03;
};

struct unf_sfp_data_field_a0 {
	/* Offset 0~63 */
	struct {
		u8 id;
		u8 id_ext;
		u8 connector;
		u8 transceiver[8];
		u8 encoding;
		u8 br_nominal; /* Nominal signalling rate, units of 100MBd. */
		u8 rate_identifier; /* Type of rate select functionality */
		/* Link length supported for single mode fiber, units   of km */
		u8 length_smk_km;
		/* Link length supported for single mode fiber,
		 *units of 100 m
		 */
		u8 length_smf;
		/* Link length supported for 50 um OM2 fiber,units of 10 m */
		u8 length_smf_om2;
		/* Link length supported for 62.5 um OM1 fiber, units of 10 m */
		u8 length_smf_om1;
		/*Link length supported for copper/direct attach cable,
		 *units of m
		 */
		u8 length_cable;
		/* Link length supported for 50 um OM3 fiber, units of 10m */
		u8 length_om3;
		u8 vendor_name[16]; /* ASCII */
		/* Code for electronic or optical compatibility*/
		u8 transceiver2;
		u8 vendor_oui[3];  /* SFP vendor IEEE company ID */
		u8 vendor_pn[16];  /* Part number provided by SFP vendor (ASCII)
				    */
		/* Revision level for part number provided by vendor  (ASCII) */
		u8 vendor_rev[4];
		/* Laser wavelength (Passive/Active Cable
		 *Specification Compliance)
		 */
		u8 wave_length[2];
		u8 unallocated;
		/* Check code for Base ID Fields (addresses 0 to 62)*/
		u8 cc_base;
	} base_id_fields;

	/* Offset 64~95 */
	struct {
		u8 options[2];
		u8 br_max;
		u8 br_min;
		u8 vendor_sn[16];
		u8 date_code[8];
		u8 diag_monitoring_type;
		u8 enhanced_options;
		u8 sff8472_compliance;
		u8 cc_ext;
	} ext_id_fields;

	/* Offset 96~255 */
	struct {
		u8 vendor_spec_eeprom[32];
		u8 rsvd[128];
	} vendor_spec_id_fields;
};

struct unf_sfp_data_field_a2 {
	/* Offset 0~119 */
	struct {
		/* 0~39 */
		struct {
			u8 temp_alarm_high[2];
			u8 temp_alarm_low[2];
			u8 temp_warning_high[2];
			u8 temp_warning_low[2];

			u8 vcc_alarm_high[2];
			u8 vcc_alarm_low[2];
			u8 vcc_warning_high[2];
			u8 vcc_warning_low[2];

			u8 bias_alarm_high[2];
			u8 bias_alarm_low[2];
			u8 bias_warning_high[2];
			u8 bias_warning_low[2];

			u8 tx_alarm_high[2];
			u8 tx_alarm_low[2];
			u8 tx_warning_high[2];
			u8 tx_warning_low[2];

			u8 rx_alarm_high[2];
			u8 rx_alarm_low[2];
			u8 rx_warning_high[2];
			u8 rx_warning_low[2];
		} alarm_warn_th;

		u8 unallocated0[16];
		u8 ext_cal_constants[36];
		u8 unallocated1[3];
		u8 cc_dmi;

		/* 96~105 */
		struct {
			u8 temp[2];
			u8 vcc[2];
			u8 tx_bias[2];
			u8 tx_power[2];
			u8 rx_power[2];
		} diag;

		u8 unallocated2[4];

		struct {
			u8 data_rdy_bar_state : 1;
			u8 rx_los : 1;
			u8 tx_fault_state : 1;
			u8 soft_rate_select_state : 1;
			u8 rate_select_state : 1;
			u8 rs_state : 1;
			u8 soft_tx_disable_select : 1;
			u8 tx_disable_state : 1;
		} status_ctrl;
		u8 rsvd;

		/* 112~113 */
		struct {
			/* 112 */
			u8 tx_alarm_low : 1;
			u8 tx_alarm_high : 1;
			u8 tx_bias_alarm_low : 1;
			u8 tx_bias_alarm_high : 1;
			u8 vcc_alarm_low : 1;
			u8 vcc_alarm_high : 1;
			u8 temp_alarm_low : 1;
			u8 temp_alarm_high : 1;

			/* 113 */
			u8 rsvd : 6;
			u8 rx_alarm_low : 1;
			u8 rx_alarm_high : 1;
		} alarm;

		u8 unallocated3[2];

		/* 116~117 */
		struct {
			/* 116 */
			u8 tx_warn_lo : 1;
			u8 tx_warn_hi : 1;
			u8 bias_warn_lo : 1;
			u8 bias_warn_hi : 1;
			u8 vcc_warn_lo : 1;
			u8 vcc_warn_hi : 1;
			u8 temp_warn_lo : 1;
			u8 temp_warn_hi : 1;

			/* 117 */
			u8 rsvd : 6;
			u8 rx_warn_lo : 1;
			u8 rx_warn_hi : 1;
		} warning;

		u8 ext_status_and_ctrl[2];
	} diag;

	/* Offset 120~255 */
	struct {
		u8 vendor_spec[8];
		u8 user_eeprom[120];
		u8 vendor_ctrl[8];
	} general_use_fields;
};

struct unf_sfp_info {
	struct unf_sfp_data_field_a0 sfp_info_a0;
	struct unf_sfp_data_field_a2 sfp_info_a2;
};

struct unf_sfp_err_rome_info {
	struct unf_sfp_info sfp_info;
	struct unf_sfp_plus_info sfp_plus_info;
};

struct unf_err_code {
	u32 loss_of_signal_count;
	u32 bad_rx_char_count;
	u32 loss_of_sync_count;
	u32 link_fail_count;
	u32 rx_eof_a_count;
	u32 dis_frame_count;
	u32 bad_crc_count;
	u32 proto_error_count;
};

/* config file */
enum unf_port_mode {
	UNF_PORT_MODE_UNKNOWN = 0x00,
	UNF_PORT_MODE_TGT = 0x10,
	UNF_PORT_MODE_INI = 0x20,
	UNF_PORT_MODE_BOTH = 0x30
};

enum unf_port_upgrade {
	UNF_PORT_UNSUPPORT_UPGRADE_REPORT = 0x00,
	UNF_PORT_SUPPORT_UPGRADE_REPORT = 0x01,
	UNF_PORT_UPGRADE_BUTT
};

#define UNF_BYTES_OF_DWORD 0x4
static inline void __attribute__((unused)) unf_big_end_to_cpu(u8 *buffer, u32 size)
{
	u32 *buf = NULL;
	u32 word_sum = 0;
	u32 index = 0;

	if (!buffer)
		return;

	buf = (u32 *)buffer;

	/* byte to word */
	if (size % UNF_BYTES_OF_DWORD == 0)
		word_sum = size / UNF_BYTES_OF_DWORD;
	else
		return;

	/* word to byte */
	while (index < word_sum) {
		*buf = be32_to_cpu(*buf);
		buf++;
		index++;
	}
}

static inline void __attribute__((unused)) unf_cpu_to_big_end(void *buffer, u32 size)
{
#define DWORD_BIT 32
#define BYTE_BIT 8
	u32 *buf = NULL;
	u32 word_sum = 0;
	u32 index = 0;
	u32 tmp = 0;

	if (!buffer)
		return;

	buf = (u32 *)buffer;

	/* byte to dword */
	word_sum = size / UNF_BYTES_OF_DWORD;

	/* dword to byte */
	while (index < word_sum) {
		*buf = cpu_to_be32(*buf);
		buf++;
		index++;
	}

	if (size % UNF_BYTES_OF_DWORD) {
		tmp = cpu_to_be32(*buf);
		tmp =
		    tmp >> (DWORD_BIT - (size % UNF_BYTES_OF_DWORD) * BYTE_BIT);
		memcpy(buf, &tmp, (size % UNF_BYTES_OF_DWORD));
	}
}

#define UNF_TOP_AUTO_MASK 0x0f
#define UNF_TOP_UNKNOWN 0xff
#define SPFC_TOP_AUTO 0x0

#define UNF_NORMAL_MODE 0
#define UNF_SET_NOMAL_MODE(mode) ((mode) = UNF_NORMAL_MODE)

/*
 * * SCSI status
 */
#define SCSI_GOOD 0x00
#define SCSI_CHECK_CONDITION 0x02
#define SCSI_CONDITION_MET 0x04
#define SCSI_BUSY 0x08
#define SCSI_INTERMEDIATE 0x10
#define SCSI_INTERMEDIATE_COND_MET 0x14
#define SCSI_RESERVATION_CONFLICT 0x18
#define SCSI_TASK_SET_FULL 0x28
#define SCSI_ACA_ACTIVE 0x30
#define SCSI_TASK_ABORTED 0x40

enum unf_act_topo {
	UNF_ACT_TOP_PUBLIC_LOOP = 0x1,
	UNF_ACT_TOP_PRIVATE_LOOP = 0x2,
	UNF_ACT_TOP_P2P_DIRECT = 0x4,
	UNF_ACT_TOP_P2P_FABRIC = 0x8,
	UNF_TOP_LOOP_MASK = 0x03,
	UNF_TOP_P2P_MASK = 0x0c,
	UNF_TOP_FCOE_MASK = 0x30,
	UNF_ACT_TOP_UNKNOWN
};

#define UNF_FL_PORT_LOOP_ADDR 0x00
#define UNF_INVALID_LOOP_ADDR 0xff

#define UNF_LOOP_ROLE_MASTER_OR_SLAVE 0x0
#define UNF_LOOP_ROLE_ONLY_SLAVE 0x1

#define UNF_TOU16_CHECK(dest, src, over_action)                              \
	do {                                                                 \
		if (unlikely(0xFFFF < (src))) {                              \
			FC_DRV_PRINT(UNF_LOG_REG_ATT, \
				     UNF_ERR, "ToU16 error, src 0x%x ",      \
				     (src));                                 \
			over_action;                                         \
		}                                                            \
		((dest) = (u16)(src));                                       \
	} while (0)

#define UNF_PORT_SPEED_AUTO 0
#define UNF_PORT_SPEED_2_G 2
#define UNF_PORT_SPEED_4_G 4
#define UNF_PORT_SPEED_8_G 8
#define UNF_PORT_SPEED_10_G 10
#define UNF_PORT_SPEED_16_G 16
#define UNF_PORT_SPEED_32_G 32

#define UNF_PORT_SPEED_UNKNOWN (~0)
#define UNF_PORT_SFP_SPEED_ERR 0xFF

#define UNF_OP_DEBUG_DUMP 0x0001
#define UNF_OP_FCPORT_INFO 0x0002
#define UNF_OP_FCPORT_LINK_CMD_TEST 0x0003
#define UNF_OP_TEST_MBX 0x0004

/* max frame size */
#define UNF_MAX_FRAME_SIZE 2112

/* default */
#define UNF_DEFAULT_FRAME_SIZE 2048
#define UNF_DEFAULT_EDTOV 2000
#define UNF_DEFAULT_RATOV 10000
#define UNF_DEFAULT_FABRIC_RATOV 10000
#define UNF_MAX_RETRY_COUNT 3
#define UNF_RRQ_MIN_TIMEOUT_INTERVAL 30000
#define UNF_LOGO_TIMEOUT_INTERVAL 3000
#define UNF_SFS_MIN_TIMEOUT_INTERVAL 15000
#define UNF_WRITE_RRQ_SENDERR_INTERVAL 3000
#define UNF_REC_TOV 3000

#define UNF_WAIT_SEM_TIMEOUT (5000UL)
#define UNF_WAIT_ABTS_RSP_TIMEOUT (20000UL)
#define UNF_MAX_ABTS_WAIT_INTERVAL ((UNF_WAIT_SEM_TIMEOUT - 500) / 1000)

#define UNF_TGT_RRQ_REDUNDANT_TIME 2000
#define UNF_INI_RRQ_REDUNDANT_TIME 500
#define UNF_INI_ELS_REDUNDANT_TIME 2000

/* ELS command values */
#define UNF_ELS_CMND_HIGH_MASK 0xff000000
#define UNF_ELS_CMND_RJT 0x01000000
#define UNF_ELS_CMND_ACC 0x02000000
#define UNF_ELS_CMND_PLOGI 0x03000000
#define UNF_ELS_CMND_FLOGI 0x04000000
#define UNF_ELS_CMND_LOGO 0x05000000
#define UNF_ELS_CMND_RLS 0x0F000000
#define UNF_ELS_CMND_ECHO 0x10000000
#define UNF_ELS_CMND_REC 0x13000000
#define UNF_ELS_CMND_RRQ 0x12000000
#define UNF_ELS_CMND_PRLI 0x20000000
#define UNF_ELS_CMND_PRLO 0x21000000
#define UNF_ELS_CMND_PDISC 0x50000000
#define UNF_ELS_CMND_FDISC 0x51000000
#define UNF_ELS_CMND_ADISC 0x52000000
#define UNF_ELS_CMND_FAN 0x60000000
#define UNF_ELS_CMND_RSCN 0x61000000
#define UNF_FCP_CMND_SRR 0x14000000
#define UNF_GS_CMND_SCR 0x62000000

#define UNF_PLOGI_VERSION_UPPER 0x20
#define UNF_PLOGI_VERSION_LOWER 0x20
#define UNF_PLOGI_CONCURRENT_SEQ 0x00FF
#define UNF_PLOGI_RO_CATEGORY 0x00FE
#define UNF_PLOGI_SEQ_PER_XCHG 0x0001
#define UNF_LGN_INFRAMESIZE 2048

/* CT_IU pream defines */
#define UNF_REV_NPORTID_INIT 0x01000000
#define UNF_FSTYPE_OPT_INIT 0xfc020000
#define UNF_FSTYPE_RFT_ID 0x02170000
#define UNF_FSTYPE_GID_PT 0x01A10000
#define UNF_FSTYPE_GID_FT 0x01710000
#define UNF_FSTYPE_RFF_ID 0x021F0000
#define UNF_FSTYPE_GFF_ID 0x011F0000
#define UNF_FSTYPE_GNN_ID 0x01130000
#define UNF_FSTYPE_GPN_ID 0x01120000

#define UNF_CT_IU_RSP_MASK 0xffff0000
#define UNF_CT_IU_REASON_MASK 0x00ff0000
#define UNF_CT_IU_EXPLAN_MASK 0x0000ff00
#define UNF_CT_IU_REJECT 0x80010000
#define UNF_CT_IU_ACCEPT 0x80020000

#define UNF_FABRIC_FULL_REG 0x00000003

#define UNF_FC4_SCSI_BIT8 0x00000100
#define UNF_FC4_FCP_TYPE 0x00000008
#define UNF_FRAG_REASON_VENDOR 0

/* GID_PT, GID_FT */
#define UNF_GID_PT_TYPE 0x7F000000
#define UNF_GID_FT_TYPE 0x00000008

/*
 *FC4 defines
 */
#define UNF_FC4_FRAME_PAGE_SIZE 0x10
#define UNF_FC4_FRAME_PAGE_SIZE_SHIFT 16

#define UNF_FC4_FRAME_PARM_0_FCP 0x08000000
#define UNF_FC4_FRAME_PARM_0_I_PAIR 0x00002000
#define UNF_FC4_FRAME_PARM_0_GOOD_RSP_CODE 0x00000100
#define UNF_FC4_FRAME_PARM_0_MASK                                 \
	(UNF_FC4_FRAME_PARM_0_FCP | UNF_FC4_FRAME_PARM_0_I_PAIR | \
	 UNF_FC4_FRAME_PARM_0_GOOD_RSP_CODE)
#define UNF_FC4_FRAME_PARM_3_INI 0x00000020
#define UNF_FC4_FRAME_PARM_3_TGT 0x00000010
#define UNF_FC4_FRAME_PARM_3_BOTH \
	(UNF_FC4_FRAME_PARM_3_INI | UNF_FC4_FRAME_PARM_3_TGT)
#define UNF_FC4_FRAME_PARM_3_R_XFER_DIS 0x00000002
#define UNF_FC4_FRAME_PARM_3_W_XFER_DIS 0x00000001
#define UNF_FC4_FRAME_PARM_3_REC_SUPPORT 0x00000400	      /* bit 10 */
#define UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT 0x00000200 /* bit 9 */
#define UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT 0x00000100	      /* bit 8 */
#define UNF_FC4_FRAME_PARM_3_CONF_ALLOW 0x00000080	      /* bit 7 */

#define UNF_FC4_FRAME_PARM_3_MASK                              \
	(UNF_FC4_FRAME_PARM_3_INI | UNF_FC4_FRAME_PARM_3_TGT | \
	 UNF_FC4_FRAME_PARM_3_R_XFER_DIS)

#define UNF_FC4_TYPE_SHIFT 24
#define UNF_FC4_TYPE_MASK 0xff
/* FC4 feature we support */
#define UNF_GFF_ACC_MASK 0xFF000000

/* Reject CT_IU Reason Codes */
#define UNF_CTIU_RJT_MASK 0xffff0000
#define UNF_CTIU_RJT_INVALID_COMMAND 0x00010000
#define UNF_CTIU_RJT_INVALID_VERSION 0x00020000
#define UNF_CTIU_RJT_LOGIC_ERR 0x00030000
#define UNF_CTIU_RJT_INVALID_SIZE 0x00040000
#define UNF_CTIU_RJT_LOGIC_BUSY 0x00050000
#define UNF_CTIU_RJT_PROTOCOL_ERR 0x00070000
#define UNF_CTIU_RJT_UNABLE_PERFORM 0x00090000
#define UNF_CTIU_RJT_NOT_SUPPORTED 0x000B0000

/* FS_RJT Reason code explanations, FC-GS-2 6.5 */
#define UNF_CTIU_RJT_EXP_MASK 0x0000FF00
#define UNF_CTIU_RJT_EXP_NO_ADDTION 0x00000000
#define UNF_CTIU_RJT_EXP_PORTID_NO_REG 0x00000100
#define UNF_CTIU_RJT_EXP_PORTNAME_NO_REG 0x00000200
#define UNF_CTIU_RJT_EXP_NODENAME_NO_REG 0x00000300
#define UNF_CTIU_RJT_EXP_FC4TYPE_NO_REG 0x00000700
#define UNF_CTIU_RJT_EXP_PORTTYPE_NO_REG 0x00000A00

/*
 * LS_RJT defines
 */
#define UNF_FC_LS_RJT_REASON_MASK 0x00ff0000

/*
 * LS_RJT reason code defines
 */
#define UNF_LS_OK 0x00000000
#define UNF_LS_RJT_INVALID_COMMAND 0x00010000
#define UNF_LS_RJT_LOGICAL_ERROR 0x00030000
#define UNF_LS_RJT_BUSY 0x00050000
#define UNF_LS_RJT_PROTOCOL_ERROR 0x00070000
#define UNF_LS_RJT_REQUEST_DENIED 0x00090000
#define UNF_LS_RJT_NOT_SUPPORTED 0x000b0000
#define UNF_LS_RJT_CLASS_ERROR 0x000c0000

/*
 * LS_RJT code explanation
 */
#define UNF_LS_RJT_NO_ADDITIONAL_INFO 0x00000000
#define UNF_LS_RJT_INV_DATA_FIELD_SIZE 0x00000700
#define UNF_LS_RJT_INV_COMMON_SERV_PARAM 0x00000F00
#define UNF_LS_RJT_INVALID_OXID_RXID 0x00001700
#define UNF_LS_RJT_COMMAND_IN_PROGRESS 0x00001900
#define UNF_LS_RJT_INSUFFICIENT_RESOURCES 0x00002900
#define UNF_LS_RJT_COMMAND_NOT_SUPPORTED 0x00002C00
#define UNF_LS_RJT_UNABLE_TO_SUPLY_REQ_DATA 0x00002A00
#define UNF_LS_RJT_INVALID_PAYLOAD_LENGTH 0x00002D00

#define UNF_P2P_LOCAL_NPORT_ID 0x000000EF
#define UNF_P2P_REMOTE_NPORT_ID 0x000000D6

#define UNF_BBCREDIT_MANAGE_NFPORT 0
#define UNF_BBCREDIT_MANAGE_LPORT 1
#define UNF_BBCREDIT_LPORT 0
#define UNF_CONTIN_INCREASE_SUPPORT 1
#define UNF_CLASS_VALID 1
#define UNF_CLASS_INVALID 0
#define UNF_NOT_MEANINGFUL 0
#define UNF_NO_SERVICE_PARAMS 0
#define UNF_CLEAN_ADDRESS_DEFAULT 0
#define UNF_PRIORITY_ENABLE 1
#define UNF_PRIORITY_DISABLE 0
#define UNF_SEQUEN_DELIVERY_REQ 1 /* Sequential delivery requested */

#define UNF_FC_PROTOCOL_CLASS_3 0x0
#define UNF_FC_PROTOCOL_CLASS_2 0x1
#define UNF_FC_PROTOCOL_CLASS_1 0x2
#define UNF_FC_PROTOCOL_CLASS_F 0x3
#define UNF_FC_PROTOCOL_CLASS_OTHER 0x4

#define UNF_RSCN_PORT_ADDR 0x0
#define UNF_RSCN_AREA_ADDR_GROUP 0x1
#define UNF_RSCN_DOMAIN_ADDR_GROUP 0x2
#define UNF_RSCN_FABRIC_ADDR_GROUP 0x3

#define UNF_GET_RSCN_PLD_LEN(cmnd) ((cmnd) & 0x0000ffff)
#define UNF_RSCN_PAGE_LEN 0x4

#define UNF_PORT_LINK_UP 0x0000
#define UNF_PORT_LINK_DOWN 0x0001
#define UNF_PORT_RESET_START 0x0002
#define UNF_PORT_RESET_END 0x0003
#define UNF_PORT_LINK_UNKNOWN 0x0004
#define UNF_PORT_NOP 0x0005
#define UNF_PORT_CORE_FATAL_ERROR 0x0006
#define UNF_PORT_CORE_UNRECOVERABLE_ERROR 0x0007
#define UNF_PORT_CORE_RECOVERABLE_ERROR 0x0008
#define UNF_PORT_LOGOUT 0x0009
#define UNF_PORT_CLEAR_VLINK 0x000a
#define UNF_PORT_UPDATE_PROCESS 0x000b
#define UNF_PORT_DEBUG_DUMP 0x000c
#define UNF_PORT_GET_FWLOG 0x000d
#define UNF_PORT_CLEAN_DONE 0x000e
#define UNF_PORT_BEGIN_REMOVE 0x000f
#define UNF_PORT_RELEASE_RPORT_INDEX 0x0010
#define UNF_PORT_ABNORMAL_RESET 0x0012

/*
 * SCSI begin
 */
#define SCSIOPC_TEST_UNIT_READY 0x00
#define SCSIOPC_INQUIRY 0x12
#define SCSIOPC_MODE_SENSE_6 0x1A
#define SCSIOPC_MODE_SENSE_10 0x5A
#define SCSIOPC_MODE_SELECT_6 0x15
#define SCSIOPC_RESERVE 0x16
#define SCSIOPC_RELEASE 0x17
#define SCSIOPC_START_STOP_UNIT 0x1B
#define SCSIOPC_READ_CAPACITY_10 0x25
#define SCSIOPC_READ_CAPACITY_16 0x9E
#define SCSIOPC_READ_6 0x08
#define SCSIOPC_READ_10 0x28
#define SCSIOPC_READ_12 0xA8
#define SCSIOPC_READ_16 0x88
#define SCSIOPC_WRITE_6 0x0A
#define SCSIOPC_WRITE_10 0x2A
#define SCSIOPC_WRITE_12 0xAA
#define SCSIOPC_WRITE_16 0x8A
#define SCSIOPC_WRITE_VERIFY 0x2E
#define SCSIOPC_VERIFY_10 0x2F
#define SCSIOPC_VERIFY_12 0xAF
#define SCSIOPC_VERIFY_16 0x8F
#define SCSIOPC_REQUEST_SENSE 0x03
#define SCSIOPC_REPORT_LUN 0xA0
#define SCSIOPC_FORMAT_UNIT 0x04
#define SCSIOPC_SEND_DIAGNOSTIC 0x1D
#define SCSIOPC_WRITE_SAME_10 0x41
#define SCSIOPC_WRITE_SAME_16 0x93
#define SCSIOPC_READ_BUFFER 0x3C
#define SCSIOPC_WRITE_BUFFER 0x3B

#define SCSIOPC_LOG_SENSE 0x4D
#define SCSIOPC_MODE_SELECT_10 0x55
#define SCSIOPC_SYNCHRONIZE_CACHE_10 0x35
#define SCSIOPC_SYNCHRONIZE_CACHE_16 0x91
#define SCSIOPC_WRITE_AND_VERIFY_10 0x2E
#define SCSIOPC_WRITE_AND_VERIFY_12 0xAE
#define SCSIOPC_WRITE_AND_VERIFY_16 0x8E
#define SCSIOPC_READ_MEDIA_SERIAL_NUMBER 0xAB
#define SCSIOPC_REASSIGN_BLOCKS 0x07
#define SCSIOPC_ATA_PASSTHROUGH_16 0x85
#define SCSIOPC_ATA_PASSTHROUGH_12 0xa1

/*
 * SCSI end
 */
#define IS_READ_COMMAND(opcode)                                       \
	((opcode) == SCSIOPC_READ_6 || (opcode) == SCSIOPC_READ_10 || \
	 (opcode) == SCSIOPC_READ_12 || (opcode) == SCSIOPC_READ_16)
#define IS_WRITE_COMMAND(opcode)                                        \
	((opcode) == SCSIOPC_WRITE_6 || (opcode) == SCSIOPC_WRITE_10 || \
	 (opcode) == SCSIOPC_WRITE_12 || (opcode) == SCSIOPC_WRITE_16)

#define IS_VERIFY_COMMAND(opcode)                                          \
	((opcode) == SCSIOPC_VERIFY_10 || (opcode) == SCSIOPC_VERIFY_12 || \
	 (opcode) == SCSIOPC_VERIFY_16)

#define FCP_RSP_LEN_VALID_MASK 0x1
#define FCP_SNS_LEN_VALID_MASK 0x2
#define FCP_RESID_OVER_MASK 0x4
#define FCP_RESID_UNDER_MASK 0x8
#define FCP_CONF_REQ_MASK 0x10
#define FCP_SCSI_STATUS_GOOD 0x0

#define UNF_DELAYED_WORK_SYNC(ret, port_id, work, work_symb)     \
	do {                                                                  \
		if (!cancel_delayed_work_sync(work)) {            \
			FC_DRV_PRINT(UNF_LOG_REG_ATT, \
				     UNF_INFO,                                \
				     "[info]LPort or RPort(0x%x) %s worker "  \
				     "can't destroy, or no "                  \
				     "worker",                                \
				     port_id, work_symb);                 \
			ret = UNF_RETURN_ERROR;                           \
		} else {                                                      \
			ret = RETURN_OK;                                  \
		}                                                             \
	} while (0)

#define UNF_GET_SFS_ENTRY(pkg) ((union unf_sfs_u *)(void *)(((struct unf_frame_pkg *)(pkg)) \
							    ->unf_cmnd_pload_bl.buffer_ptr))
/* FLOGI */
#define UNF_GET_FLOGI_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->flogi.flogi_payload))
#define UNF_FLOGI_PAYLOAD_LEN sizeof(struct unf_flogi_fdisc_payload)

/* FLOGI  ACC */
#define UNF_GET_FLOGI_ACC_PAYLOAD(pkg)                   \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg))) \
	       ->flogi_acc.flogi_payload))
#define UNF_FLOGI_ACC_PAYLOAD_LEN sizeof(struct unf_flogi_fdisc_payload)

/* FDISC */
#define UNF_FDISC_PAYLOAD_LEN UNF_FLOGI_PAYLOAD_LEN
#define UNF_FDISC_ACC_PAYLOAD_LEN UNF_FLOGI_ACC_PAYLOAD_LEN

/* PLOGI */
#define UNF_GET_PLOGI_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->plogi.payload))
#define UNF_PLOGI_PAYLOAD_LEN sizeof(struct unf_plogi_payload)

/* PLOGI  ACC */
#define UNF_GET_PLOGI_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->plogi_acc.payload))
#define UNF_PLOGI_ACC_PAYLOAD_LEN sizeof(struct unf_plogi_payload)

/* LOGO */
#define UNF_GET_LOGO_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->logo.payload))
#define UNF_LOGO_PAYLOAD_LEN sizeof(struct unf_logo_payload)

/* ECHO */
#define UNF_GET_ECHO_PAYLOAD(pkg) \
	(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->echo.echo_pld)

/* ECHO PHYADDR */
#define UNF_GET_ECHO_PAYLOAD_PHYADDR(pkg) \
	(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->echo.phy_echo_addr)

#define UNF_ECHO_PAYLOAD_LEN sizeof(struct unf_echo_payload)

/* REC */
#define UNF_GET_REC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->rec.rec_pld))

#define UNF_REC_PAYLOAD_LEN sizeof(struct unf_rec_pld)

/* ECHO ACC */
#define UNF_GET_ECHO_ACC_PAYLOAD(pkg) \
	(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->echo_acc.echo_pld)
#define UNF_ECHO_ACC_PAYLOAD_LEN sizeof(struct unf_echo_payload)

/* RRQ */
#define UNF_GET_RRQ_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->rrq.cmnd))
#define UNF_RRQ_PAYLOAD_LEN \
	(sizeof(struct unf_rrq) - sizeof(struct unf_fc_head))

/* PRLI */
#define UNF_GET_PRLI_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->prli.payload))
#define UNF_PRLI_PAYLOAD_LEN sizeof(struct unf_prli_payload)

/* PRLI ACC */
#define UNF_GET_PRLI_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->prli_acc.payload))
#define UNF_PRLI_ACC_PAYLOAD_LEN sizeof(struct unf_prli_payload)

/* PRLO */
#define UNF_GET_PRLO_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->prlo.payload))
#define UNF_PRLO_PAYLOAD_LEN sizeof(struct unf_prli_payload)

#define UNF_GET_PRLO_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->prlo_acc.payload))
#define UNF_PRLO_ACC_PAYLOAD_LEN sizeof(struct unf_prli_payload)

/* PDISC */
#define UNF_GET_PDISC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->pdisc.payload))
#define UNF_PDISC_PAYLOAD_LEN sizeof(struct unf_plogi_payload)

/* PDISC  ACC */
#define UNF_GET_PDISC_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->pdisc_acc.payload))
#define UNF_PDISC_ACC_PAYLOAD_LEN sizeof(struct unf_plogi_payload)

/* ADISC */
#define UNF_GET_ADISC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->adisc.adisc_payl))
#define UNF_ADISC_PAYLOAD_LEN sizeof(struct unf_adisc_payload)

/* ADISC  ACC */
#define UNF_GET_ADISC_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->adisc_acc.adisc_payl))
#define UNF_ADISC_ACC_PAYLOAD_LEN sizeof(struct unf_adisc_payload)

/* RSCN ACC */
#define UNF_GET_RSCN_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->els_acc.cmnd))
#define UNF_RSCN_ACC_PAYLOAD_LEN \
	(sizeof(struct unf_els_acc) - sizeof(struct unf_fc_head))

/* LOGO ACC */
#define UNF_GET_LOGO_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->els_acc.cmnd))
#define UNF_LOGO_ACC_PAYLOAD_LEN \
	(sizeof(struct unf_els_acc) - sizeof(struct unf_fc_head))

/* RRQ ACC */
#define UNF_GET_RRQ_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->els_acc.cmnd))
#define UNF_RRQ_ACC_PAYLOAD_LEN \
	(sizeof(struct unf_els_acc) - sizeof(struct unf_fc_head))

/* REC ACC */
#define UNF_GET_REC_ACC_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(pkg)))->els_acc.cmnd))
#define UNF_REC_ACC_PAYLOAD_LEN \
	(sizeof(struct unf_els_acc) - sizeof(struct unf_fc_head))

/* GPN_ID */
#define UNF_GET_GPNID_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->gpn_id.ctiu_pream))
#define UNF_GPNID_PAYLOAD_LEN \
	(sizeof(struct unf_gpnid) - sizeof(struct unf_fc_head))

#define UNF_GET_GPNID_RSP_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->gpn_id_rsp.ctiu_pream))
#define UNF_GPNID_RSP_PAYLOAD_LEN \
	(sizeof(struct unf_gpnid_rsp) - sizeof(struct unf_fc_head))

/* GNN_ID */
#define UNF_GET_GNNID_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->gnn_id.ctiu_pream))
#define UNF_GNNID_PAYLOAD_LEN \
	(sizeof(struct unf_gnnid) - sizeof(struct unf_fc_head))

#define UNF_GET_GNNID_RSP_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->gnn_id_rsp.ctiu_pream))
#define UNF_GNNID_RSP_PAYLOAD_LEN \
	(sizeof(struct unf_gnnid_rsp) - sizeof(struct unf_fc_head))

/* GFF_ID */
#define UNF_GET_GFFID_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->gff_id.ctiu_pream))
#define UNF_GFFID_PAYLOAD_LEN \
	(sizeof(struct unf_gffid) - sizeof(struct unf_fc_head))

#define UNF_GET_GFFID_RSP_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->gff_id_rsp.ctiu_pream))
#define UNF_GFFID_RSP_PAYLOAD_LEN \
	(sizeof(struct unf_gffid_rsp) - sizeof(struct unf_fc_head))

/* GID_FT/GID_PT */
#define UNF_GET_GID_PAYLOAD(pkg)                       \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg)) \
	       ->get_id.gid_req.ctiu_pream))

#define UNF_GID_PAYLOAD_LEN (sizeof(struct unf_ctiu_prem) + sizeof(u32))
#define UNF_GET_GID_ACC_PAYLOAD(pkg)                 \
	(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg)) \
	     ->get_id.gid_rsp.gid_acc_pld)
#define UNF_GID_ACC_PAYLOAD_LEN sizeof(struct unf_gid_acc_pld)

/* RFT_ID */
#define UNF_GET_RFTID_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->rft_id.ctiu_pream))
#define UNF_RFTID_PAYLOAD_LEN \
	(sizeof(struct unf_rftid) - sizeof(struct unf_fc_head))

#define UNF_GET_RFTID_RSP_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->rft_id_rsp.ctiu_pream))
#define UNF_RFTID_RSP_PAYLOAD_LEN sizeof(struct unf_ctiu_prem)

/* RFF_ID */
#define UNF_GET_RFFID_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->rff_id.ctiu_pream))
#define UNF_RFFID_PAYLOAD_LEN \
	(sizeof(struct unf_rffid) - sizeof(struct unf_fc_head))

#define UNF_GET_RFFID_RSP_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->rff_id_rsp.ctiu_pream))
#define UNF_RFFID_RSP_PAYLOAD_LEN sizeof(struct unf_ctiu_prem)

/* ACC&RJT */
#define UNF_GET_ELS_ACC_RJT_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->els_rjt.cmnd))
#define UNF_ELS_ACC_RJT_LEN \
	(sizeof(struct unf_els_rjt) - sizeof(struct unf_fc_head))

/* SCR */
#define UNF_SCR_PAYLOAD(pkg) \
	(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->scr.payload)
#define UNF_SCR_PAYLOAD_LEN \
	(sizeof(struct unf_scr) - sizeof(struct unf_fc_head))

#define UNF_SCR_RSP_PAYLOAD(pkg) \
	(&(((union unf_sfs_u *)UNF_GET_SFS_ENTRY(pkg))->els_acc.cmnd))
#define UNF_SCR_RSP_PAYLOAD_LEN \
	(sizeof(struct unf_els_acc) - sizeof(struct unf_fc_head))

#define UNF_GS_RSP_PAYLOAD_LEN \
	(sizeof(union unf_sfs_u) - sizeof(struct unf_fc_head))

#define UNF_GET_XCHG_TAG(pkg)            \
	(((struct unf_frame_pkg *)(pkg)) \
	     ->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX])
#define UNF_GET_ABTS_XCHG_TAG(pkg) \
	((u16)(((pkg)->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]) >> 16))
#define UNF_GET_IO_XCHG_TAG(pkg) \
	((u16)((pkg)->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]))

#define UNF_GET_HOTPOOL_TAG(pkg)           \
	(((struct unf_frame_pkg *)(pkg)) \
	     ->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX])
#define UNF_GET_SID(pkg)                                          \
	(((struct unf_frame_pkg *)(pkg))->frame_head.csctl_sid & \
	 UNF_NPORTID_MASK)
#define UNF_GET_DID(pkg)                                         \
	(((struct unf_frame_pkg *)(pkg))->frame_head.rctl_did & \
	 UNF_NPORTID_MASK)
#define UNF_GET_OXID(pkg) \
	(((struct unf_frame_pkg *)(pkg))->frame_head.oxid_rxid >> 16)
#define UNF_GET_RXID(pkg) \
	((u16)((struct unf_frame_pkg *)(pkg))->frame_head.oxid_rxid)
#define UNF_GET_XID_RELEASE_TIMER(pkg) \
	(((struct unf_frame_pkg *)(pkg))->release_task_id_timer)
#define UNF_GETXCHGALLOCTIME(pkg)        \
	(((struct unf_frame_pkg *)(pkg)) \
	     ->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME])

#define UNF_SET_XCHG_ALLOC_TIME(pkg, xchg)          \
	(((struct unf_frame_pkg *)(pkg))                \
	    ->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = \
	    (((struct unf_xchg *)(xchg))               \
		 ->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME]))
#define UNF_SET_ABORT_INFO_IOTYPE(pkg, xchg)                        \
	(((struct unf_frame_pkg *)(pkg))                                \
	    ->private_data[PKG_PRIVATE_XCHG_ABORT_INFO] |=                \
	    (((u8)(((struct unf_xchg *)(xchg))->data_direction & 0x7)) \
	     << 2))

#define UNF_CHECK_NPORT_FPORT_BIT(els_payload)             \
	(((struct unf_flogi_fdisc_payload *)(els_payload)) \
	     ->fabric_parms.co_parms.nport)

#define UNF_GET_RSP_BUF(pkg) \
	((void *)(((struct unf_frame_pkg *)(pkg))->unf_rsp_pload_bl.buffer_ptr))
#define UNF_GET_RSP_LEN(pkg) \
	(((struct unf_frame_pkg *)(pkg))->unf_rsp_pload_bl.length)

#define UNF_N_PORT 0
#define UNF_F_PORT 1

#define UNF_GET_RA_TOV_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.r_a_tov)
#define UNF_GET_RT_TOV_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.r_t_tov)
#define UNF_GET_E_D_TOV_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.e_d_tov)
#define UNF_GET_E_D_TOV_RESOLUTION_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.e_d_tov_resolution)
#define UNF_GET_BB_SC_N_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.bbscn)
#define UNF_GET_BB_CREDIT_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.bb_credit)

enum unf_pcie_error_code {
	UNF_PCIE_ERROR_NONE = 0,
	UNF_PCIE_DATAPARITYDETECTED = 1,
	UNF_PCIE_SIGNALTARGETABORT,
	UNF_PCIE_RECEIVEDTARGETABORT,
	UNF_PCIE_RECEIVEDMASTERABORT,
	UNF_PCIE_SIGNALEDSYSTEMERROR,
	UNF_PCIE_DETECTEDPARITYERROR,
	UNF_PCIE_CORRECTABLEERRORDETECTED,
	UNF_PCIE_NONFATALERRORDETECTED,
	UNF_PCIE_FATALERRORDETECTED,
	UNF_PCIE_UNSUPPORTEDREQUESTDETECTED,
	UNF_PCIE_AUXILIARYPOWERDETECTED,
	UNF_PCIE_TRANSACTIONSPENDING,

	UNF_PCIE_UNCORRECTINTERERRSTATUS,
	UNF_PCIE_UNSUPPORTREQERRSTATUS,
	UNF_PCIE_ECRCERRORSTATUS,
	UNF_PCIE_MALFORMEDTLPSTATUS,
	UNF_PCIE_RECEIVEROVERFLOWSTATUS,
	UNF_PCIE_UNEXPECTCOMPLETESTATUS,
	UNF_PCIE_COMPLETERABORTSTATUS,
	UNF_PCIE_COMPLETIONTIMEOUTSTATUS,
	UNF_PCIE_FLOWCTRLPROTOCOLERRSTATUS,
	UNF_PCIE_POISONEDTLPSTATUS,
	UNF_PCIE_SURPRISEDOWNERRORSTATUS,
	UNF_PCIE_DATALINKPROTOCOLERRSTATUS,
	UNF_PCIE_ADVISORYNONFATALERRSTATUS,
	UNF_PCIE_REPLAYTIMERTIMEOUTSTATUS,
	UNF_PCIE_REPLAYNUMROLLOVERSTATUS,
	UNF_PCIE_BADDLLPSTATUS,
	UNF_PCIE_BADTLPSTATUS,
	UNF_PCIE_RECEIVERERRORSTATUS,

	UNF_PCIE_BUTT
};

#define UNF_DMA_HI32(a) (((a) >> 32) & 0xffffffff)
#define UNF_DMA_LO32(a) ((a) & 0xffffffff)

#define UNF_WWN_LEN 8
#define UNF_MAC_LEN 6

/* send BLS/ELS/BLS REPLY/ELS REPLY/GS/ */
/* rcvd BLS/ELS/REQ DONE/REPLY DONE */
#define UNF_PKG_BLS_REQ 0x0100
#define UNF_PKG_BLS_REQ_DONE 0x0101
#define UNF_PKG_BLS_REPLY 0x0102
#define UNF_PKG_BLS_REPLY_DONE 0x0103

#define UNF_PKG_ELS_REQ 0x0200
#define UNF_PKG_ELS_REQ_DONE 0x0201

#define UNF_PKG_ELS_REPLY 0x0202
#define UNF_PKG_ELS_REPLY_DONE 0x0203

#define UNF_PKG_GS_REQ 0x0300
#define UNF_PKG_GS_REQ_DONE 0x0301

#define UNF_PKG_TGT_XFER 0x0400
#define UNF_PKG_TGT_RSP 0x0401
#define UNF_PKG_TGT_RSP_NOSGL 0x0402
#define UNF_PKG_TGT_RSP_STATUS 0x0403

#define UNF_PKG_INI_IO 0x0500
#define UNF_PKG_INI_RCV_TGT_RSP 0x0507

/* external sgl struct start */
struct unf_esgl_page {
	u64 page_address;
	dma_addr_t esgl_phy_addr;
	u32 page_size;
};

/* external sgl struct end */
struct unf_esgl {
	struct list_head entry_esgl;
	struct unf_esgl_page page;
};

#define UNF_RESPONE_DATA_LEN 8
struct unf_frame_payld {
	u8 *buffer_ptr;
	dma_addr_t buf_dma_addr;
	u32 length;
};

enum pkg_private_index {
	PKG_PRIVATE_LOWLEVEL_XCHG_ADD = 0,
	PKG_PRIVATE_XCHG_HOT_POOL_INDEX = 1, /* Hot Pool Index */
	PKG_PRIVATE_XCHG_RPORT_INDEX = 2,    /* RPort index */
	PKG_PRIVATE_XCHG_VP_INDEX = 3,	     /* VPort index */
	PKG_PRIVATE_XCHG_SSQ_INDEX,
	PKG_PRIVATE_RPORT_RX_SIZE,
	PKG_PRIVATE_XCHG_TIMEER,
	PKG_PRIVATE_XCHG_ALLOC_TIME,
	PKG_PRIVATE_XCHG_ABORT_INFO,
	PKG_PRIVATE_ECHO_CMD_SND_TIME, /* local send echo cmd time stamp */
	PKG_PRIVATE_ECHO_ACC_RCV_TIME, /* local receive echo acc time stamp */
	PKG_PRIVATE_ECHO_CMD_RCV_TIME, /* remote receive echo cmd time stamp */
	PKG_PRIVATE_ECHO_RSP_SND_TIME, /* remote send echo rsp time stamp */
	PKG_MAX_PRIVATE_DATA_SIZE
};

extern u32 dix_flag;
extern u32 dif_sgl_mode;
extern u32 dif_app_esc_check;
extern u32 dif_ref_esc_check;

#define UNF_DIF_ACTION_NONE 0

enum unf_adm_dif_mode_E {
	UNF_SWITCH_DIF_DIX = 0,
	UNF_APP_REF_ESCAPE,
	ALL_DIF_MODE = 20,
};

#define UNF_DIF_CRC_ERR 0x1001
#define UNF_DIF_APP_ERR 0x1002
#define UNF_DIF_LBA_ERR 0x1003

#define UNF_VERIFY_CRC_MASK (1 << 1)
#define UNF_VERIFY_APP_MASK (1 << 2)
#define UNF_VERIFY_LBA_MASK (1 << 3)

#define UNF_REPLACE_CRC_MASK (1 << 8)
#define UNF_REPLACE_APP_MASK (1 << 9)
#define UNF_REPLACE_LBA_MASK (1 << 10)

#define UNF_DIF_ACTION_MASK (0xff << 16)
#define UNF_DIF_ACTION_INSERT (0x1 << 16)
#define UNF_DIF_ACTION_VERIFY_AND_DELETE (0x2 << 16)
#define UNF_DIF_ACTION_VERIFY_AND_FORWARD (0x3 << 16)
#define UNF_DIF_ACTION_VERIFY_AND_REPLACE (0x4 << 16)

#define UNF_DIF_ACTION_NO_INCREASE_REFTAG (0x1 << 24)

#define UNF_DEFAULT_CRC_GUARD_SEED (0)
#define UNF_CAL_512_BLOCK_CNT(data_len) ((data_len) >> 9)
#define UNF_CAL_BLOCK_CNT(data_len, sector_size) ((data_len) / (sector_size))
#define UNF_CAL_CRC_BLK_CNT(crc_data_len, sector_size) \
	((crc_data_len) / ((sector_size) + 8))

#define UNF_DIF_DOUBLE_SGL (1 << 1)
#define UNF_DIF_SECTSIZE_4KB (1 << 2)
#define UNF_DIF_SECTSIZE_512 (0 << 2)
#define UNF_DIF_LBA_NONE_INCREASE (1 << 3)
#define UNF_DIF_TYPE3 (1 << 4)

#define SECTOR_SIZE_512 512
#define SECTOR_SIZE_4096 4096
#define SPFC_DIF_APP_REF_ESC_NOT_CHECK 1
#define SPFC_DIF_APP_REF_ESC_CHECK 0

struct unf_dif {
	u16 crc;
	u16 app_tag;
	u32 lba;
};

enum unf_io_state { UNF_INI_IO = 0, UNF_TGT_XFER = 1, UNF_TGT_RSP = 2 };

#define UNF_PKG_LAST_RESPONSE 0
#define UNF_PKG_NOT_LAST_RESPONSE 1

struct unf_frame_pkg {
	/* pkt type:BLS/ELS/FC4LS/CMND/XFER/RSP */
	u32 type;
	u32 last_pkg_flag;
	u32 fcp_conf_flag;

#define UNF_FCP_RESPONSE_VALID 0x01
#define UNF_FCP_SENSE_VALID 0x02
	u32 response_and_sense_valid_flag; /* resp and sense vailed flag */
	u32 cmnd;
	struct unf_fc_head frame_head;
	u32 entry_count;
	void *xchg_contex;
	u32 transfer_len;
	u32 residus_len;
	u32 status;
	u32 status_sub_code;
	enum unf_io_state io_state;
	u32 qos_level;
	u32 private_data[PKG_MAX_PRIVATE_DATA_SIZE];
	struct unf_fcp_cmnd *fcp_cmnd;
	struct unf_dif_control_info dif_control;
	struct unf_frame_payld unf_cmnd_pload_bl;
	struct unf_frame_payld unf_rsp_pload_bl;
	struct unf_frame_payld unf_sense_pload_bl;
	void *upper_cmd;
	u32 abts_maker_status;
	u32 release_task_id_timer;
	u8 byte_orders;
	u8 rx_or_ox_id;
	u8 class_mode;
	u8 rsvd;
	u8 *peresp;
	u32 rcvrsp_len;
	ulong timeout;
	u32 origin_hottag;
	u32 origin_magicnum;
};

#define UNF_MAX_SFS_XCHG 2048
#define UNF_RESERVE_SFS_XCHG 128 /* times on exchange mgr num */

struct unf_lport_cfg_item {
	u32 port_id;
	u32 port_mode;	   /* INI(0x20), TGT(0x10), BOTH(0x30) */
	u32 port_topology; /* 0x3:loop , 0xc:p2p  ,0xf:auto */
	u32 max_queue_depth;
	u32 max_io; /* Recommended Value 512-4096 */
	u32 max_login;
	u32 max_sfs_xchg;
	u32 port_speed;	  /* 0:auto 1:1Gbps 2:2Gbps 4:4Gbps 8:8Gbps 16:16Gbps */
	u32 tape_support; /* ape support */
	u32 fcp_conf;	  /* fcp confirm support */
	u32 bbscn;
};

struct unf_port_dynamic_info {
	u32 sfp_posion;
	u32 sfp_valid;
	u32 phy_link;
	u32 firmware_state;
	u32 cur_speed;
	u32 mailbox_timeout_cnt;
};

struct unf_port_intr_coalsec {
	u32 delay_timer;
	u32 depth;
};

struct unf_port_topo {
	u32 topo_cfg;
	enum unf_act_topo topo_act;
};

struct unf_port_transfer_para {
	u32 type;
	u32 value;
};

struct unf_buf {
	u8 *buf;
	u32 buf_len;
};

/* get ucode & up ver */
#define SPFC_VER_LEN (16)
#define SPFC_COMPILE_TIME_LEN (20)
struct unf_fw_version {
	u32 message_type;
	u8 fw_version[SPFC_VER_LEN];
};

struct unf_port_wwn {
	u64 sys_port_wwn;
	u64 sys_node_name;
};

enum unf_port_config_set_op {
	UNF_PORT_CFG_SET_SPEED,
	UNF_PORT_CFG_SET_PORT_SWITCH,
	UNF_PORT_CFG_SET_POWER_STATE,
	UNF_PORT_CFG_SET_PORT_STATE,
	UNF_PORT_CFG_UPDATE_WWN,
	UNF_PORT_CFG_TEST_FLASH,
	UNF_PORT_CFG_UPDATE_FABRIC_PARAM,
	UNF_PORT_CFG_UPDATE_PLOGI_PARAM,
	UNF_PORT_CFG_SET_BUTT
};

enum unf_port_cfg_get_op {
	UNF_PORT_CFG_GET_TOPO_ACT,
	UNF_PORT_CFG_GET_LOOP_MAP,
	UNF_PORT_CFG_GET_SFP_PRESENT,
	UNF_PORT_CFG_GET_FW_VER,
	UNF_PORT_CFG_GET_HW_VER,
	UNF_PORT_CFG_GET_WORKBALE_BBCREDIT,
	UNF_PORT_CFG_GET_WORKBALE_BBSCN,
	UNF_PORT_CFG_GET_FC_SERDES,
	UNF_PORT_CFG_GET_LOOP_ALPA,
	UNF_PORT_CFG_GET_MAC_ADDR,
	UNF_PORT_CFG_GET_SFP_VER,
	UNF_PORT_CFG_GET_SFP_SUPPORT_UPDATE,
	UNF_PORT_CFG_GET_SFP_LOG,
	UNF_PORT_CFG_GET_PCIE_LINK_STATE,
	UNF_PORT_CFG_GET_FLASH_DATA_INFO,
	UNF_PORT_CFG_GET_BUTT,
};

enum unf_port_config_state {
	UNF_PORT_CONFIG_STATE_START,
	UNF_PORT_CONFIG_STATE_STOP,
	UNF_PORT_CONFIG_STATE_RESET,
	UNF_PORT_CONFIG_STATE_STOP_INTR,
	UNF_PORT_CONFIG_STATE_BUTT
};

enum unf_port_config_update {
	UNF_PORT_CONFIG_UPDATE_FW_MINIMUM,
	UNF_PORT_CONFIG_UPDATE_FW_ALL,
	UNF_PORT_CONFIG_UPDATE_BUTT
};

enum unf_disable_vp_mode {
	UNF_DISABLE_VP_MODE_ONLY = 0x8,
	UNF_DISABLE_VP_MODE_REINIT_LINK = 0x9,
	UNF_DISABLE_VP_MODE_NOFAB_LOGO = 0xA,
	UNF_DISABLE_VP_MODE_LOGO_ALL = 0xB
};

struct unf_vport_info {
	u16 vp_index;
	u64 node_name;
	u64 port_name;
	u32 port_mode; /* INI, TGT or both */
	enum unf_disable_vp_mode disable_mode;
	u32 nport_id; /* maybe acquired by lowlevel and update to common */
	void *vport;
};

struct unf_port_login_parms {
	enum unf_act_topo act_topo;

	u32 rport_index;
	u32 seq_cnt : 1;
	u32 ed_tov : 1;
	u32 reserved : 14;
	u32 tx_mfs : 16;
	u32 ed_tov_timer_val;

	u8 remote_rttov_tag;
	u8 remote_edtov_tag;
	u16 remote_bb_credit;
	u16 compared_bbscn;
	u32 compared_edtov_val;
	u32 compared_ratov_val;
	u32 els_cmnd_code;
};

struct unf_mbox_head_info {
	/* mbox header */
	u8 cmnd_type;
	u8 length;
	u8 port_id;
	u8 pad0;

	/* operation */
	u32 opcode : 4;
	u32 pad1 : 28;
};

struct unf_mbox_head_sts {
	/* mbox header */
	u8 cmnd_type;
	u8 length;
	u8 port_id;
	u8 pad0;

	/* operation */
	u16 pad1;
	u8 pad2;
	u8 status;
};

struct unf_low_level_service_op {
	u32 (*unf_ls_gs_send)(void *hba, struct unf_frame_pkg *pkg);
	u32 (*unf_bls_send)(void *hba, struct unf_frame_pkg *pkg);
	u32 (*unf_cmnd_send)(void *hba, struct unf_frame_pkg *pkg);
	u32 (*unf_rsp_send)(void *handle, struct unf_frame_pkg *pkg);
	u32 (*unf_release_rport_res)(void *handle, struct unf_port_info *rport_info);
	u32 (*unf_flush_ini_resp_que)(void *handle);
	u32 (*unf_alloc_rport_res)(void *handle, struct unf_port_info *rport_info);
	u32 (*ll_release_xid)(void *handle, struct unf_frame_pkg *pkg);
	u32 (*unf_xfer_send)(void *handle, struct unf_frame_pkg *pkg);
};

struct unf_low_level_port_mgr_op {
	/* fcport/opcode/input parameter */
	u32 (*ll_port_config_set)(void *fc_port, enum unf_port_config_set_op opcode, void *para_in);

	/* fcport/opcode/output parameter */
	u32 (*ll_port_config_get)(void *fc_port, enum unf_port_cfg_get_op opcode, void *para_out);
};

struct unf_chip_info {
	u8 chip_type;
	u8 chip_work_mode;
	u8 disable_err_flag;
};

struct unf_low_level_functioon_op {
	struct unf_chip_info chip_info;
	/* low level type */
	u32 low_level_type;
	const char *name;
	struct pci_dev *dev;
	u64 sys_node_name;
	u64 sys_port_name;
	struct unf_lport_cfg_item lport_cfg_items;
#define UNF_LOW_LEVEL_MGR_TYPE_ACTIVE 0
#define UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE 1
	const u32 xchg_mgr_type;

#define UNF_NO_EXTRA_ABTS_XCHG 0x0
#define UNF_LL_IOC_ABTS_XCHG 0x1
	const u32 abts_xchg;

#define UNF_CM_RPORT_SET_QUALIFIER 0x0
#define UNF_CM_RPORT_SET_QUALIFIER_REUSE 0x1
#define UNF_CM_RPORT_SET_QUALIFIER_SPFC 0x2

	/* low level pass-through flag. */
#define UNF_LOW_LEVEL_PASS_THROUGH_FIP 0x0
#define UNF_LOW_LEVEL_PASS_THROUGH_FABRIC_LOGIN 0x1
#define UNF_LOW_LEVEL_PASS_THROUGH_PORT_LOGIN 0x2
	u32 passthrough_flag;

	/* low level parameter */
	u32 support_max_npiv_num;
	u32 support_max_ssq_num;
	u32 support_max_speed;
	u32 support_min_speed;
	u32 fc_ser_max_speed;

	u32 support_max_rport;

	u32 support_max_hot_tag_range;
	u32 sfp_type;
	u32 update_fw_reset_active;
	u32 support_upgrade_report;
	u32 multi_conf_support;
	u32 port_type;
#define UNF_LOW_LEVEL_RELEASE_RPORT_SYNC 0x0
#define UNF_LOW_LEVEL_RELEASE_RPORT_ASYNC 0x1
	u8 rport_release_type;
#define UNF_LOW_LEVEL_SIRT_PAGE_MODE_FIXED 0x0
#define UNF_LOW_LEVEL_SIRT_PAGE_MODE_XCHG 0x1
	u8 sirt_page_mode;
	u8 sfp_speed;

	/* IO reference */
	struct unf_low_level_service_op service_op;

	/* Port Mgr reference */
	struct unf_low_level_port_mgr_op port_mgr_op;

	u8 chip_id;
};

struct unf_cm_handle_op {
	/* return:L_Port */
	void *(*unf_alloc_local_port)(void *private_data,
				      struct unf_low_level_functioon_op *low_level_op);

	/* input para:L_Port */
	u32 (*unf_release_local_port)(void *lport);

	/* input para:L_Port, FRAME_PKG_S */
	u32 (*unf_receive_ls_gs_pkg)(void *lport, struct unf_frame_pkg *pkg);

	/* input para:L_Port, FRAME_PKG_S */
	u32 (*unf_receive_bls_pkg)(void *lport, struct unf_frame_pkg *pkg);
	/* input para:L_Port, FRAME_PKG_S */
	u32 (*unf_send_els_done)(void *lport, struct unf_frame_pkg *pkg);

	/* input para:L_Port, FRAME_PKG_S */
	u32 (*unf_receive_marker_status)(void *lport, struct unf_frame_pkg *pkg);
	u32 (*unf_receive_abts_marker_status)(void *lport, struct unf_frame_pkg *pkg);
	/* input para:L_Port, FRAME_PKG_S */
	u32 (*unf_receive_ini_response)(void *lport, struct unf_frame_pkg *pkg);

	int (*unf_get_cfg_parms)(char *section_name,
				 struct unf_cfg_item *cfg_parm, u32 *cfg_value,
				 u32 item_num);

	/* TGT IO interface */
	u32 (*unf_process_fcp_cmnd)(void *lport, struct unf_frame_pkg *pkg);

	/* TGT IO Done */
	u32 (*unf_tgt_cmnd_xfer_or_rsp_echo)(void *lport, struct unf_frame_pkg *pkg);

	u32 (*unf_cm_get_sgl_entry)(void *pkg, char **buf, u32 *buf_len);
	u32 (*unf_cm_get_dif_sgl_entry)(void *pkg, char **buf, u32 *buf_len);

	struct unf_esgl_page *(*unf_get_one_free_esgl_page)(void *lport, struct unf_frame_pkg *pkg);

	/* input para:L_Port, EVENT */
	u32 (*unf_fc_port_event)(void *lport, u32 events, void *input);

	int (*unf_drv_start_work)(void *lport);

	void (*unf_card_rport_chip_err)(struct pci_dev const *pci_dev);
};

u32 unf_get_cm_handle_ops(struct unf_cm_handle_op *cm_handle);
int unf_common_init(void);
void unf_common_exit(void);

#endif
