/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_outband_smbus_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2023/09/22
 * Last Modified : 2026/09/16
 * Description   : SMBUS protocol out-of-band command related structure
 */

#ifndef MPU_OUTBAND_SMBUS_CMD_DEFS_H
#define MPU_OUTBAND_SMBUS_CMD_DEFS_H

#include "ethmac_api.h"
#include "mpu_inband_cmd_defs.h"
#include "mpu_outband_ncsi_cmd_defs.h"

#define SMB_SINGLE_SLICE_LOG_LEN 48
#define MAX_PORT_LEN 8
#define SMB_MAC_ADDR_INFO_LEN (48)
#define SMB_SPU_RAS_LEN (12)
#define SMB_PCIE_UBC_INFO_LEN (48)
#define SMB_PCIE_UBC_INFO_SIZE (4)
#define SMB_MAX_PCIE_UBC_INFO_MAX_SIZE 96

#define SMB_PORT_NUM 24
#define SFP_MAX_PORT_NUM 8 /* Optical module port count */
#define SMB_INFO_MEMORY_LEN 128

#define SMB_VERSION_INFO_MAX_LEN 48

/* Out-of-band management common response message header */
typedef struct {
	u16 errcode;
	u16 opcode;
	u32 total_length;
	u32 length;
} smb_respon_header_s;

typedef struct {
	u16 req_para;
	u16 opcode;
	u32 offset;
	u32 length;
} smb_request_header_s;

/* Out-of-band management message header */
typedef struct {
	u16 reserved;
	u16 opcode;
} smb_ctrl_header_s;

/*
 * Inspection information file structure: smb_inspec_data_header + TLV + TLV + ...
 * For each Tag, if it appears multiple times, it indicates that the Tag is an array
 */
#define SMB_INSPEC_DATA_MAGIC_NUM 0x418deb6f
typedef struct {
	u32 magic_num;  /**< SMB_INSPEC_DATA_MAGIC_NUM */
	u32 data_size;  /**< Total length of inspection information (excluding this header) */
} smb_inspec_data_header;

typedef enum {
	SMB_INSPEC_FW_VERSIONS,  /**< smb_inspec_fw_versions */
	SMB_INSPEC_BASIC_INFO,  /**< smb_inspec_basic_info */
	SMB_INSPEC_RES_USAGE,  /**< smb_inspec_res_usage */
	SMB_INSPEC_CELL_INFO,  /**< chip_cell_info_s */
	SMB_INSPEC_IPSU_PKT_ERR_CNT,  /**< ipsurx_pkt_err_cnt_s */
	SMB_INSPEC_BOARD_INFO,  /**< struct hinic5_board_info */
	SMB_INSPEC_MAG_PORT_STATS,  /**< struct mag_port_stats */
	SMB_INSPEC_MPU_COUNTER,  /**< SRAM_COUNTER_BASE */
	SMB_INSPEC_NPU_COUNTER,  /**< flash_crucial_header_s + crucial_ctr_range_s + npu counters */
} smb_inspec_data_tag_e;

typedef struct {
	u32 tag : 8;  /**< smb_inspec_data_tag_e */
	u32 len : 24;
	u8 val[0];
} smb_inspec_tlv;

/* SMB_INSPEC_FW_VERSIONS */
typedef struct {
	u32 mpu_version;
	u32 npu_version;
	u32 reserved[18];  /**< Reserve 18 u32s for extension */
} smb_inspec_fw_versions;

/* SMB_INSPEC_BASIC_INFO */
typedef struct {
	u16 pcie_cap;
	u16 port_num;
	u16 port_speed_mode;
	u16 work_mode;
	u16 sub_work_mode;
	u16 reserved;
	u16 link_status[MAX_PORT_LEN];
	u16 port_mode[MAX_PORT_LEN];
	u16 speed[MAX_PORT_LEN];
} smb_inspec_basic_info;

/* SMB_INSPEC_RES_USAGE */
typedef struct {
	u32 cpu_usage;
	u32 memory_usage;
	u32 usage_unit;  /**< 4bytes, current unit is 1/10000 */
} smb_inspec_res_usage;

/* SMB_INSPEC_CELL_INFO */
typedef struct {
	u32 total_cell_num;
	u32 free_cell_num;
	u32 pdm_glb_num;
	u32 cpi_octl_cell_num;
	u32 leak_cell_num;
	u32 fq_free_oeid_num;
} chip_cell_info_s;

/* SMB_INSPEC_IPSU_PKT_ERR_CNT */
typedef struct {
	u32 abort_bf_ipsurx_cnt;
	u32 sop_sop_err_cnt;
	u32 dmac_zero_cnt;
	u32 da_sa_equal_cnt;
	u32 arp_posi_ilgl_cnt;
	u32 ipv4_ver_ilgl_cnt;
	u32 ipv4_ihl_ilgl_cnt;
	u32 ipv4_sip_ilgl_cnt;
	u32 ipv4_dip_ilgl_cnt;
	u32 ipv6_ver_ilgl_cnt;
	u32 ipv6_sip_ilgl_cnt;
	u32 ipv6_dip_ilgl_cnt;
	u32 tcp_land_ilgl_cnt;
	u32 rocev1_dgid_ilgl_cnt;
	u32 rocev1_sgid_ilgl_cnt;
	u32 rocev1_ipver_ilgl_cnt;
	u32 rocev1_nxhdr_ilgl_cnt;
	u32 roce_dqp_ilgl_cnt;
	u32 eth_len_ilgl_cnt;
	u32 pkt_min_len_ilgl_cnt;
	u32 pkt_max_len_ilgl_cnt;
	u32 ipv4_cs_ilgl_cnt;
	u32 tcp_cs_ilgl_cnt;
	u32 udp_cs_ilgl_cnt;
	u32 igmp_cs_ilgl_cnt;
	u32 icmpv4_cs_ilgl_cnt;
	u32 icmpv6_cs_ilgl_cnt;
	u32 sctp_cs_ilgl_cnt;
	u32 fc_crc_ilgl_cnt;
	u32 rocev1_plen_ilgl_cnt;
	u32 ib_icrc_ilgl_cnt;
	u32 smac_ilgl_cnt;
	u32 ipv6_udp_cs_zero_cnt;
	u32 rocev2_ipv4_frag_ilgl_cnt;
	u32 rocev2_ipv4_udp_cs_ilgl_cnt;
	u32 rocev2_ipv6_udp_cs_ilgl_cnt;
	u32 to_up_pkt_ilgl_cnt;
	u32 to_bmc_only_pkt_ilgl_cnt;
} ipsurx_pkt_err_cnt_s;

#pragma pack(1) /* One-byte alignment */

typedef struct {
	smb_inspec_data_header header;

	smb_inspec_tlv fw_ver_tlv;
	smb_inspec_fw_versions fw_ver_data;

	smb_inspec_tlv basic_info_tlv;
	smb_inspec_basic_info basic_info_data;

	smb_inspec_tlv res_usage_tlv;
	smb_inspec_res_usage res_usage_data;

	smb_inspec_tlv cell_info_tlv;
	chip_cell_info_s cell_info_data;

	smb_inspec_tlv ipsurx_pkt_err_cnt_tlv;
	ipsurx_pkt_err_cnt_s ipsurx_pkt_err_cnt_data;

	smb_inspec_tlv board_info_tlv;
	struct hinic5_board_info board_info_data;
} smb_inspec_info_s;

typedef union {
    /* Ensure each member of the struct has size of 32 */
	struct {
	u16 id;
	u8 type;
	u8 reserved;
	u16 cap_num;
	u16 opc_data[(SMB_SINGLE_SLICE_LOG_LEN - 6) / 2];
	} first_frame;
	struct {
	u16 opc_data[SMB_SINGLE_SLICE_LOG_LEN / 2];
	} other_frame;
} ability_data_u;

typedef struct {
	smb_respon_header_s res_header;
	ability_data_u ability_data;
	u32 crc32;
} smb_ability_s;

typedef struct {
	smb_respon_header_s res_header;
	u8 health_status;
	u32 crc32;
} smb_device_health_s;

/* Define the common struct 32bytes data u16,example:errcode */
typedef struct {
	smb_respon_header_s res_header;
	u8 data[SMB_SINGLE_SLICE_LOG_LEN];
	u32 crc32;
} smb_com_res_s;

typedef struct {
	smb_respon_header_s res_header;
	s16 temp; /* Actual temperature needs to be multiplied by 10 before sending to master */
	u32 crc32;
} smb_temperature_s;

/* Threshold */
typedef struct {
	s32 max_temp; /**< Chip core temperature threshold */
	s32 min_temp; /**< Chip core temperature threshold */
} smb_temp_threshold_data_s;

/* Core temperature threshold */
typedef struct {
	smb_ctrl_header_s header;
	u32 op_type; /**< 0: read threshold; 1: write threshold */
	smb_temp_threshold_data_s temp_threshold_data; /**< temperature threshold @see smb_temp_threshold_data_s */
	u32 crc32;
} smb_temp_threshold_s;

/* Define the struct read_log 48bytes log，lastword?rrespec */
typedef struct {
	smb_respon_header_s res_header;
	u8 log_data[SMB_SINGLE_SLICE_LOG_LEN]; /* If master's log read length capability is less than this value, handle according to master's capability */
	u32 crc32;
} smb_log_s;

typedef struct {
	smb_respon_header_s res_header;
	u16 board_id;
	u32 crc32;
} smb_board_id_s;

typedef struct {
	smb_respon_header_s res_header;
	u8 pcb_id;
	u32 crc32;
} smb_pcb_id_s;

typedef struct {
	smb_respon_header_s header;
	u8 eeprom_wp_enable;
	u32 crc32;
} smb_eeprom_wp_req_s;

typedef struct {
	smb_respon_header_s header;
	u32 crc32;
} smb_eeprom_wp_rsp_s;

typedef struct {
	smb_respon_header_s res_header;
	s16 phy_temp_data[SMB_PORT_NUM];
	u32 crc32;
} smb_phy_temp_s;

typedef struct {
	smb_respon_header_s res_header;
	s16 sfp_temp_data[SMB_PORT_NUM];
	u32 crc32;
} smb_sfp_temp_s;

typedef struct {
	smb_respon_header_s res_header;
	u16 sfp_id_data[SFP_MAX_PORT_NUM];
	u32 rsvd0;
	u32 rsvd1;
	u32 crc32;
} smb_sfp_id_s;

typedef struct {
	smb_ctrl_header_s header;
	u32 op_type; /**< 0: read threshold; 1: write threshold */
	smb_temp_threshold_data_s sfp_threshold_data; /**< temperature threshold @see smb_temp_threshold_data_s */
	u32 crc32;
} smb_sfp_temp_threshold_s;

typedef struct {
	smb_respon_header_s res_header;
	u8 link_stat[SMB_PORT_NUM];
	u32 crc32;
} smb_link_stat_s;

typedef struct {
	u8 major;
	u8 minor;
	u8 revison; /* If revison is not applicable, fill 0xff */
} firmware_ver_data_s;

typedef struct {
	smb_respon_header_s res_header;
	firmware_ver_data_s ver_data;
	u32 crc32;
} smb_firmware_ver_s;

typedef struct {
	smb_respon_header_s res_header;
	u8 version_str[SMB_VERSION_INFO_MAX_LEN];
	u32 crc32;
} smb_firmware_ver_str_s;

/* DFT out-of-band management common response message header */
typedef struct {
	u16 errcode;
	u16 opcode;
	u32 total_length;
	u32 length;
	u16 sub_opcode;
} smb_dft_respon_header_s;

/* DFT out-of-band management message header */
typedef struct {
	u8 flag;
	u8 req_para;
	u16 opcode;
	u32 offset;
	u32 length;
	u16 sub_opcode;
} smb_dft_ctrl_header_s;

/* SMB_SUB_OPC_DIE_ID command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u32 crc32;
} smb_die_id_req_s;

#define SMB_DIE_ID_MAX_LEN 32
/* SMB_SUB_OPC_DIE_ID command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u8 die_id[SMB_DIE_ID_MAX_LEN];  // SMB_DIE_ID_MAX_LEN
	u32 crc32;
} smb_die_id_rsp_s;

/* SMB_SUB_OPC_SRAM_MBIST command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u32 crc32;
} smb_sram_mbist_req_s;

/* SMB_SUB_OPC_SRAM_MBIST command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 result;
	u32 fail_vector_index;
	u32 fail_test_index;
	u32 bist_fail_data;
	u32 die1_result;
	u32 die1_fail_vector_index;
	u32 die1_fail_test_index;
	u32 die1_bist_fail_data;
	u32 crc32;
} smb_sram_mbist_rsp_s;

/* SMB_SUB_OPC_DCIP_TEST command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u32 crc32;
} smb_dcip_test_req_s;

/* SMB_SUB_OPC_DCIP_TEST command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 status;
	u32 crc32;
} smb_dcip_test_rsp_s;

#define SMB_DFT_PAYLOAD_MAX_LEN 46
#define LEN_OF_VPD_KEYWORD      2
#define SMB_VPD_ITEM_NUM 10
#define SMB_VPD_INFO_LEN 128
#define SMB_DFT_GET_VPD_TOTAL_LEN 130
#define SMB_DFT_PAYLOAD_MAX_LEN 46
/* SMB_SUB_OPC_VPD_SET command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u8 wr_data[SMB_DFT_PAYLOAD_MAX_LEN];
	u32 crc32;
} smb_vpd_set_req_s;

typedef struct {
	u8 key[LEN_OF_VPD_KEYWORD];
	u8 len;
	u8 rsvd;
	u8 data[SMB_VPD_INFO_LEN];
} vpd_info;

typedef struct {
	vpd_info vpd_item[SMB_VPD_ITEM_NUM];
	u32 rsvd ;
} smbus_vpd_info_s;

typedef struct {
	u8 data[SMB_VPD_INFO_LEN];
	u32 key_type;
	u16 key_len;
	u16 rsvd;
} smbus_single_vpd_info_s;

/* SMB_SUB_OPC_VPD_SET command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 crc32;
} smb_vpd_set_rsp_s;

/* SMB_SUB_OPC_VPD_GET command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u32 crc32;
} smb_vpd_get_req_s;

/* SMB_SUB_OPC_VPD_GET command word response packet struct */
typedef union {
	struct {
	u16 vpd_len;
	u8 data[SMB_DFT_PAYLOAD_MAX_LEN - 2];
	} first_frame;
	struct {
	u8 data[SMB_DFT_PAYLOAD_MAX_LEN];
	} other_frame;
} vpd_data_s;

typedef struct {
	smb_dft_respon_header_s res_header;
	vpd_data_s vpd_data;
	u32 crc32;
} smb_vpd_get_rsp_s;

/* SMB_SUB_OPC_RESET command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u32 crc32;
} smb_reset_req_s;

/* SMB_SUB_OPC_RESET command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 status; // 0: No factory reset after power-on reset, 1: Factory reset succeeded after power-on reset, 2: Factory reset failed after power-on reset, 3: In reset process
	u32 crc32;
} smb_reset_rsp_s;

#define SMBUS_GUID_SN_MAX_LEN 8
/* SMB_SUB_OPC_GUID_SET command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u8 guid_sn[SMBUS_GUID_SN_MAX_LEN];
	u32 crc32;
} smb_guid_set_req_s;

/* SMB_SUB_OPC_GUID_SET command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 crc32;
} smb_guid_set_rsp_s;

/* SMB_SUB_OPC_GUID_GET command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u32 crc32;
} smb_guid_get_req_s;

/* SMB_SUB_OPC_GUID_GET command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u8 guid_sn[SMBUS_GUID_SN_MAX_LEN];
	u32 crc32;
} smb_guid_get_rsp_s;

/* SMB_SUB_OPC_I2C_TEST command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u32 crc32;
} smb_i2c_test_req_s;

/* SMB_SUB_OPC_I2C_TEST command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 crc32;
} smb_i2c_test_rsp_s;

/* SMB_SUB_OPC_SET_LOOPBACK command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u8 port_id;
	u32 crc32;
} smb_set_sfp_loopbackmode_req_s;

/* SMB_SUB_OPC_SET_LOOPBACK command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 crc32;
} smb_set_sfp_loopbackmode_rsp_s;

/* SMB_SUB_OPC_GET_SNR command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u8 macro_id;
	u8 lane_id;
	u32 crc32;
} smb_get_serdes_snr_req_s;

/* SMB_SUB_OPC_GET_SNR command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 snr_valid;
	u64 snr_metric;
	u64 snr_metric_his_min;
	u64 snr_err_avg;
	u64 snr_cycles_avg;
	u64 snr_heh_avg;
	u32 crc32;
} smb_get_serdes_snr_rsp_s;

// prbs test
typedef struct {
	smb_dft_ctrl_header_s header;
	u8 macro_id;
	u8 lane_mask;
	u8 direction;
	u8 prbs_type;
	u32 crc32;
} smb_prbs_req_s;

typedef struct {
	smb_dft_respon_header_s header;
	u8 lane_mask;
	u8 code_speed[8];
	u32 errcnt_bits[8];
	u32 crc32;
} smb_dft_prbs_error_code_s;

// mac wirte
typedef struct {
	smb_dft_ctrl_header_s header;
	u8 mac_addr[MAC_ADDRESS_NUM];
	u32 crc32;
} smb_set_mac_addr_s;

// mac read
typedef struct {
	smb_dft_respon_header_s header;
	u8 all_mac[SMB_DFT_PAYLOAD_MAX_LEN];
	u32 crc32;
} smb_get_mac_addr_s;

#define SMBUS_EFUSE_SINGLE_LEN 46
#define SMBUS_EFUSE_BURN_DATA_TOTAL_LEN 256

typedef struct {
	u32 data_len; // Current length
	u32 opt_type; // Current burn type
	u8 data[SMBUS_EFUSE_BURN_DATA_TOTAL_LEN];
} smb_efuse_info_s;

typedef struct {
	smb_dft_ctrl_header_s header;
	u8 data[SMBUS_EFUSE_SINGLE_LEN];
	u32 crc32;
} smb_single_efuse_info_s;

typedef struct { // led set
	smb_dft_ctrl_header_s header;
	u8 port_id;
	u8 mode;
	u32 crc32;
} smb_led_set_req_s;

/* SMB_SUB_OPC_POWER_GET command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u32 crc32;
} smb_power_req_s;

/* SMB_SUB_OPC_POWER_GET command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u32 power;
	u32 crc32;
} smb_power_rsp_s;

/* SMB_SUB_OPC_GPIO_TEST command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u8 pin;
	u8 pin_val;
	u32 crc32;
} smb_pin_req_s;

/* SMB_SUB_OPC_GPIO_TEST command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u8 pin_val;
	u32 crc32;
} smb_pin_rsp_s;

/* SMB_SUB_OPC_H2H command word request packet struct */
typedef struct {
	smb_dft_ctrl_header_s ctrl_header;
	u8 port_id;
	u32 crc32;
} smb_h2h_req_s;

/* SMB_SUB_OPC_H2H command word response packet struct */
typedef struct {
	smb_dft_respon_header_s res_header;
	u64 right_pkt_cnt;
	u64 err_pkt_cnt;
	u32 crc32;
} smb_h2h_rsp_s;

typedef struct {
	smb_respon_header_s res_header;
	s16 spu_tsensor_temp;
	u32 crc32;
} smb_spu_temp_s;

typedef struct {
	smb_respon_header_s res_header;
	u8 pwrlimit_en; /**< 0:open 1:close */
	u32 crc32;
} smb_spu_pwrlimit_en_s;

typedef struct {
	smb_respon_header_s header;
	u8 num_item;
	u32 crc32;
} smb_spu_ras_num_s;

typedef struct {
	smb_respon_header_s header;
	u32 ras_info[SMB_SPU_RAS_LEN]; // Every 4B is imu_to_mcu_ras_info_s struct
	u32 crc32;
} smb_spu_ras_s;

typedef struct {
	smb_request_header_s header;
	u8 slot_id;
	u32 crc32;
} smb_set_slot_id_req_s;

#pragma pack()

/* Get MAC addr */
typedef struct {
	smb_respon_header_s res_header;
	u8 mac_addr[SMB_MAC_ADDR_INFO_LEN];
	u32 crc32;
} smb_mac_addr_s;

typedef struct {
	smb_respon_header_s header;
	u8 link_info;
	u8 ex_speed;
	u16 rsvd;
	u32 crc32;
} smb_phyport_link_info_rep_s;

typedef struct {
	smb_request_header_s header;
	u8 port_id;
} smb_phyport_link_info_req_s;

typedef struct {
	smb_respon_header_s header;
	u32 status;
	u32 crc32;
} smb_xsfp_present_status_rep_s;

typedef struct {
	smb_request_header_s header;
	u8 port_id;
} smb_xsfp_present_status_req_s;

typedef struct {
	smb_respon_header_s res_header;
	u8 link_width;
	u8 link_speed;
	u16 rsvd;
	u32 crc32;
} smb_pcie_ubc_info_s;

typedef struct {
	smb_respon_header_s res_header;
	u16 spu_freq;
	u8 spu_freq_status;
	u8 rsvd;
	u32 crc32;
} smb_spu_freq_resp_s;

/* Define the struct read_write_reg 5*4bytes */
typedef struct {
	u32 addr_h;
	u32 addr_l;
	u32 data_h;
	u32 data_l;
} smb_rw_reg_payload_s;

typedef struct {
	smb_ctrl_header_s header;
	smb_rw_reg_payload_s payload;
	u32 crc32;
} smb_read_write_reg_s;

typedef struct {
	u32 port_speed;
	u8 link_speed;
} smb_speed_map_s;

#endif
