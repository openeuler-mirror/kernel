/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : macsec_mpu_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : COMM Commands between host and MPU(macsec)
 */

#ifndef MACSEC_MPU_CMD_DEFS_H
#define MACSEC_MPU_CMD_DEFS_H

#include "mpu_cmd_base_defs.h"

#define MACSEC_PORT_NUM 4 /**< macsec maximum port specification */
#define MACSEC_SC_NUM 32 /**< macsec maximum SC specification */
#define MACSEC_SA_NUM 64 /**< macsec maximum SA specification */
#define MACSEC_MAX_FEATURE_QWORD 4 /**< macsec maximum feature specification */
#define MACSEC_WHITELIST_DMAC_ID_MAX 16 /**< macsec dmac id maximum template count */
#define MACSEC_WHITELIST_TOOL_IN_BUF_MAX 1024
#define MACSEC_WHITELIST_TOOL_OUT_BUF_MAX 4096
#define MACSEC_WHITELIST_DMAC_ENABLE 1 /**< macsec dmac enable */
#define MACSEC_WHITELIST_DMAC_DISABLE 0 /**< macsec dmac disable */
#define MACSEC_WHITELIST_SERVICE_ENABLE 1 /**< macsec enable */
#define MACSEC_WHITELIST_SERVICE_DISABLE 0 /**< macsec disable */
#define WHITELIST_FUNC_ENABLE 0x1
#define WHITELIST_FUNC_DISABLE 0x0
#define MACSEC_DMAC_TEMPLATE_NUM 16 /**< macsec dmac maximum template count */
#define MACSEC_ETYPE_TEMPLATE_NUM 16 /**< macsec etype maximum template count */
#define MACSEC_VLANID_MAX 4094 /**< macsec vlanid maximum value */
#define MACSEC_VLANID_MIN 1 /**< macsec vlanid minimum value */
#define MACSEC_RXVLANID_MASK_MAX 0xFFF /**< macsec rxvlan mask maximum value */
#define MACSEC_DMAC_VALUE_MAX 0xFFFFFFFFFFFF /**< macsec dmac maximum value */
#define MACSEC_DMAC_MASK_MAX 0xFF /**< macsec dmac mask maximum value */

/**
 * @brief macsec_sa_info_s - SA struct
 * @details Manage SA through this struct
 */
typedef struct tag_macsec_sa_info_s {
	// encryption
	u64 pn_th; /**< The threshold of PN */
	u64 next_pn; /**< NEXTPN number */
	u8 enable_transmit; /**< Indicates if the transmit SA can be used to receive frames */
	u8 rsvd0[7]; /**< for expanding */

	// decryption
	u8 replay_protect; /**< Enable or disable replay protection function */
	u8 enable_receive; /**< Indicates if the transmit SA can be used to receive frames */
	u8 rsvd1[2];
	u32 replay_window; /**< Indicates the replay protection window size */
	u64 lowest_pn; /**< LOWESTPN number */

	// common
	u8 an; /**< an value used by sa */
	u8 confidentiality_offset; /**< The confidentaility protection offset options of the cipher suite */
	u8 current_key_length; /**< Indicate the key length the SA is currently using */
	u8 extended_pn_enable; /**< Indicates to enable the extended packet number while receiving MACsec frames */
	u8 current_crypto_algo; /**< Indicates the crypto algorithm which the SA is currently using */
	u8 rsvd2[7]; /**< for expanding */
	u32 ssci; /**< If extended_pn_enable is 1, use SSCI to compose IV */
	u32 salt[3]; /**< Used to generate IV in extended Packet Number mode, 96bit */
	u32 sak_crc; /**< sak key crc val */
	u64 sci; /**< 64-bit SCI value used to identify an SC */
	u32 sak[8]; /**< cipher suite key,max 256bit */
} macsec_sa_info_s;

/**
 * @brief macsec_sc_info_s - SC struct
 * @details Manage SC through this struct
 */
typedef struct tag_macsec_sc_info_s {
	// encryption
	u8 protect_frames; /**< Protect function for frames */
	u8 protection_mode; /**< Protection options of the Cipher Suite */
	u8 include_sci_enable; /**< Indicates to include the SCI information in SecTAG field */
	u8 use_es_enable; /**< Indicates to enable the ES bit in SecTAG */
	u8 use_scb_enable; /**< Indicates to enable the SCB bit in SecTAG field */
	u8 encoding_sa; /**< The current transmitting SA in use */
	u8 rsvd0[2]; /**< for expanding */

	// decryption
	u8 validate_frames; /**< Uses to control the validation function for frames per SC */
	u8 rsvd1[3]; /**< for expanding */

	// common
	u8 sa_an[4]; /**< AN number used by SA, 4 refer to max num */
	u64 sci; /**< 64-bit SCI value used to identify an SC */
} macsec_sc_info_s; /**< Common head info */

/**
 * @brief macsec_cmd_sc_operation_s - SC management information with host driver
 * @details Through the passing of this information, perform SC create, delete and update, each SC is independent.
 */
typedef struct tag_macsec_cmd_sc_operation_s {
	struct mgmt_msg_head head; /**< Common head info */
	u8 op_code; /**< Operation code, 0: enc get/1: enc set/2: enc update/3: dec get/4: dec set/5: dec update */
	u8 rsvd[3]; /**< reserved for expanding */
	macsec_sc_info_s sc_info; /**< sc information passed between host driver */
} macsec_cmd_sc_operation_s;

/**
 * @brief macsec_cmd_sa_operation_s - SA management information with host driver
 * @details Used for SA create, delete and update, including key management, replay management, PN value, etc.
 */
typedef struct tag_macsec_cmd_sa_operation_s {
	struct mgmt_msg_head head;  /**< Common head info */
	u8 op_code; /**< Operation code, 0: enc get/1: enc set/2: enc update/3: dec get/4: dec set/5: dec update */
	u8 rsvd[3]; /**< reserved for expanding */
	macsec_sa_info_s sa_info; /**< sa information passed between host driver */
} macsec_cmd_sa_operation_s;

/**
 * @brief macsec_port_mib_info_s - PORT MIB specific content
 * @details Includes PORT-level SecTAG exception, integrity protection and encryption protection statistics
 */
typedef struct {
	u64 macsec_mib_txpkts_untagged; /**< Number of packets transmitted without SecTAG */
	u64 macsec_mib_txoctets_protected; /**< Number of bytes transmitted with integrity protection only, no encryption */
	u64 macsec_mib_txoctets_encrypted; /**< Number of bytes transmitted with both integrity protection and encryption */
	u64 macsec_mib_rxpkts_untagged; /**< Number of packets received without SecTAG, not strict mode */
	u64 macsec_mib_rxpkts_notag; /**< Number of packets received without SecTAG, strict mode */
	u64 macsec_mib_rxpkts_badtag; /**< Number of packets received with invalid SecTAG or invalid ICV, V, SC, SL errors */
	u64 macsec_mib_rxpkts_nosa; /**< Number of packets received with unknown SCI or unused SA, validateEnable&C&strict mode not set */
	u64 macsec_mib_rxpkts_nosaerror; /**< Number of packets received with unknown SCI or unused SA, validateEnable&C&strict mode set */
	u64 macsec_mib_rxoctets_validated; /**< Number of bytes received with integrity protection only, no encryption */
	u64 macsec_mib_rxoctets_decrypted; /**< Number of bytes received with both integrity protection and encryption */
} macsec_port_mib_info_s;

/**
 * @brief macsec_sc_mib_info_s - SC MIB specific content
 * @details Includes SC-level integrity protection and encryption protection statistics, replay and security check related statistics
 */
typedef struct {
	u64 macsec_mib_txscpkts_protected; /**< Number of packets transmitted with integrity protection only, no encryption */
	u64 macsec_mib_txscpkts_encrypted; /**< Number of packets transmitted with both integrity protection and encryption */
	u64 macsec_mib_rxscpkts_ok; /**< Number of packets successfully validated and received within replay window */
	u64 macsec_mib_rxscpkts_delayed; /**< Number of packets with PN less than the minimum acceptable PN */
	u64 macsec_mib_rxscpkts_late; /**< Number of packets with ReplayProtect=true and PN less than the lower bound of replay check PN */
	u64 macsec_mib_rxscpkts_unchecked; /**< validateFrames disable, C bit in SecTAG not set, and the packet is not a replay packet */
	u64 macsec_mib_rxscpkts_notvalid; /**< Number of packets with ICV validation failed but discarded due to validateFrames=strict or data encrypted */
	u64 macsec_mib_rxscpkts_invalid; /**< Number of packets with validateFrames=check but data not encrypted (original frame may be recovered) */
} macsec_sc_mib_info_s;

/**
 * @brief macsec_cmd_port_mib_operation_s - PORT MIB management information
 * @details Follows macsec standard protocol, gets MIB information of specified port
 */
typedef struct tag_macsec_cmd_port_mib_operation_s {
	struct mgmt_msg_head head;  /**< Management msg header info, 8B */
	macsec_port_mib_info_s port_mib; /**< port mib info */
	u64 reserved; /**< reserved for expanding */
} macsec_cmd_port_mib_operation_s;

/**
 * @brief macsec_cmd_sc_mib_operation_s - SC MIB management information
 * @details Follows macsec standard protocol, gets MIB information of a single SC
 */
typedef struct tag_macsec_cmd_sc_mib_operation_s {
	struct mgmt_msg_head head;  /**< Management msg header info, 8B */
	macsec_sc_mib_info_s sc_mib; /**< sc mib info */
	u64 sci; /**< 64-bit SCI value used to identify an SC */
	u8 reserved[8]; /**< reserved for expanding */
} macsec_cmd_sc_mib_operation_s;

/**
 * @brief macsec_enc_cnt_u - MACSEC encryption side DFX statistics
 * @details Includes encryption side correctable and uncorrectable exceptions, data path sop and eop exceptions, and statistics for different handling by profile id, etc.
 */
typedef union {
	struct {
		u32 macsec_enc_msop_cnt; /**< Number of MSOP interrupts generated */
		u32 macsec_enc_meop_cnt; /**< Number of MEOP interrupts generated */
		u32 macsec_enc_iadp_ierr_c_cnt; /**< IADP interrupt correctable error statistics */
		u32 macsec_enc_iadp_ierr_u_cnt; /**< IADP interrupt uncorrectable error statistics */
		u32 macsec_enc_oadp_ierr_c_cnt; /**< OADP interrupt correctable error statistics */
		u32 macsec_enc_oadp_ierr_u_cnt; /**< OADP interrupt uncorrectable error statistics */
		u32 macsec_enc_cs_ierr_c_cnt; /**< CS interrupt correctable error statistics */
		u32 macsec_enc_cs_ierr_u_cnt; /**< CS interrupt uncorrectable error statistics */
		u32 macsec_enc_mib_ierr_c_cnt; /**< MIB interrupt correctable error statistics */
		u32 macsec_enc_mib_ierr_u_cnt; /**< MIB interrupt uncorrectable error statistics */
		u32 macsec_enc_dpp_ierr_c_cnt; /**< DPP interrupt correctable error statistics */
		u32 macsec_enc_dpp_ierr_u_cnt; /**< DPP interrupt uncorrectable error statistics */
		u32 macsec_enc_dpp_wrongsa_cnt; /**< DPP wrong SA statistics */
		u32 macsec_enc_dpp_illegal_pkt_cnt; /**< Illegal packet statistics */
		u64 macsec_enc_dpp_profile_id_0_bypass_pkt_cnt; /**< Bypass packet statistics for profile id 0 */
		u32 macsec_enc_dpp_profile_read_all0_bypass_pkt_cnt; /**< Bypass packet statistics for profile id non-0 but profile info is 0 */
		u32 macsec_enc_dpp_profile_id_1_cnt; /**< Packet statistics for profile id 1 */
		u32 macsec_enc_dpp_profile_id_2_cnt; /**< Packet statistics for profile id 2 */
		u32 macsec_enc_dpp_profile_id_3_cnt; /**< Packet statistics for profile id 3 */
		u64 macsec_enc_white_list_plaintext_pkt_cnt; /**< Whitelist passed packet statistics */
		u64 macsec_enc_in_sop_cnt; /**< Number of SOP generated at encryption engine input port */
		u64 macsec_enc_in_eop_cnt; /**< Number of EOP generated at encryption engine input port */
		u64 macsec_enc_in_abort_cnt; /**< Number of drops at encryption engine input port */
		u64 macsec_enc_out_sop_cnt; /**< Number of SOP generated at encryption engine output port */
		u64 macsec_enc_out_eop_cnt; /**< Number of EOP generated at encryption engine output port */
		u64 macsec_enc_out_abort_cnt; /**< Number of drops at encryption engine output port */
		u32 macsec_enc_drop_pkt_cnt; /**< Number of packets dropped at external port */
		u32 macsec_enc_oadp_out_msop_cnt; /**< output sop count statistics */
		u32 macsec_enc_oadp_out_meop_cnt; /**< output eop count statistics */
	} enc_cnt_s;
	u32 cnt_info[0];
} macsec_enc_cnt_u;

/**
 * @brief macsec_dec_cnt_u - MACSEC decryption side DFX statistics
 * @details Includes decryption side correctable and uncorrectable exceptions, data path sop and eop exceptions, and statistics for different handling by profile id, etc.
 */
typedef union {
	struct {
		u32 macsec_dec_msop_cnt; /**< Number of MSOP interrupts generated */
		u32 macsec_dec_meop_cnt; /**< Number of MEOP interrupts generated */
		u32 macsec_dec_iadp_ierr_c_cnt; /**< IADP interrupt correctable error statistics */
		u32 macsec_dec_iadp_ierr_u_cnt; /**< IADP interrupt uncorrectable error statistics */
		u32 macsec_dec_oadp_ierr_c_cnt; /**< OADP interrupt correctable error statistics */
		u32 macsec_dec_oadp_ierr_u_cnt; /**< OADP interrupt uncorrectable error statistics */
		u32 macsec_dec_pa_ierr_c_cnt; /**< PA interrupt correctable error statistics */
		u32 macsec_dec_pa_ierr_u_cnt; /**< PA interrupt uncorrectable error statistics */
		u32 macsec_dec_pg_ierr_c_cnt; /**< PG interrupt correctable error statistics */
		u32 macsec_dec_pg_ierr_u_cnt; /**< PG interrupt uncorrectable error statistics */
		u32 macsec_dec_mib_ierr_c_cnt; /**< MIB interrupt correctable error statistics */
		u32 macsec_dec_mib_ierr_u_cnt; /**< MIB interrupt uncorrectable error statistics */
		u32 macsec_dec_dpp_ierr_u_cnt; /**< DPP interrupt correctable error statistics */
		u32 macsec_dec_dpp_ierr_c_cnt; /**< DPP interrupt uncorrectable error statistics */
		u32 macsec_dec_dpp_ec01_pkt_cnt; /**< E=0 and C=1 statistics */
		u32 macsec_dec_dpp_ec10_pkt_cnt; /**< E=1 and C=0 statistics */
		u32 macsec_dec_dpp_unknownsci_bypass_pkt_cnt; /**< Unknown SCI bypass packet statistics */
		u32 macsec_dec_dpp_illegal_pad_pkt_cnt; /**< Illegal padding packet statistics */
		u64 macsec_dec_dpp_white_list_plaintext_pkt_cnt; /**< Whitelist passed packet statistics */
		u64 macsec_dec_dpp_profile_id_0_bypass_pkt_cnt;      /**< Passed packet statistics for profile id 0 */
		u32 macsec_dec_dpp_profile_read_all0_bypass_pkt_cnt; /**< Bypass packet statistics for profile id non-0 but profile info is 0 */
		u32 macsec_dec_dpp_profile_id_1_pkt_cnt; /**< Packet statistics for profile id 1 */
		u32 macsec_dec_dpp_profile_id_2_pkt_cnt; /**< Packet statistics for profile id 2 */
		u32 macsec_dec_dpp_profile_id_3_pkt_cnt; /**< Packet statistics for profile id 3 */
		u32 macsec_dec_dpp_profile_id_4_pkt_cnt; /**< Packet statistics for profile id 4 */
		u32 macsec_dec_dpp_illegal_pkt_cnt;      /**< Illegal packet statistics */
		u64 macsec_dec_intf_in_sop_cnt; /**< DEC_INTF input port sop statistics */
		u64 macsec_dec_intf_in_eop_cnt; /**< DEC_INTF input port eop statistics */
		u64 macsec_dec_intf_in_abort_cnt; /**< DEC_INTF input port drop statistics */
		u64 macsec_dec_out_sop_cnt; /**< DEC_INTF output port sop statistics */
		u64 macsec_dec_out_eop_cnt; /**< DEC_INTF output port eop statistics */
		u64 macsec_dec_out_abort_cnt; /**< DEC_INTF output port drop statistics */
		u32 macsec_dec_intf_drop_pkt_cnt; /**< Port disable dropped packet statistics */
		u32 macsec_dec_oadp_out_msop_cnt; /**< out msop count statistics */
		u32 macsec_dec_oadp_out_meop_cnt; /**< out meop count statistics */
	} dec_cnt_s;
	u32 cnt_info[0];
} macsec_dec_cnt_u;

/**
 * @brief macsec_cmd_err_cnt_operation_s - macsec internal dfx cnt info acquisition
 * @details Includes statistics of encryption and decryption sides, used for problem localization
 */
typedef struct tag_macsec_cmd_err_cnt_operation_s {
	struct mgmt_msg_head head;  /**< Management msg header info, 8B */
	macsec_enc_cnt_u enc_module_cnt; /**< enc cnt info */
	macsec_dec_cnt_u dec_module_cnt; /**< dec cnt info */
	u8 reserved[4]; /**< reserved for expanding */
} macsec_cmd_err_cnt_operation_s;

/**
 * @brief macsec_cmd_service_operation_s - macsec service management operation
 * @details Includes macsec handling during driver load/unload
 */
typedef struct tag_macsec_cmd_service_operation_s {
	struct mgmt_msg_head head;  /**< Management msg header info, 8B */
	u8 op_code; /**< Operation code, 0: disable macsec/1: enable macsec */
	u8 reserved[7]; /**< reserved for expanding */
} macsec_cmd_service_operation_s;

/**
 * @brief macsec_feature_nego_cmd_s - feature negotiation command struct defination
 * @details Includes macsec feature negotiation handling during driver load
 */
typedef struct tag_macsec_feature_nego_cmd {
	struct mgmt_msg_head head; /**< Management msg header info, 8B */
	u64 s_feature[MACSEC_MAX_FEATURE_QWORD]; /**< macsec features */
	u8 op_code; /**< Operation code, 0: get macsec feature/1: set macsec feature */
	u8 rsvd[7]; /**< reserved for expanding */
} macsec_feature_nego_cmd_s;

/**
 * @brief tag_macsec_flush_cmd_s - MACSEC resource actively cleans up parameters
 * @details Parameters included when issuing flush command
 */
typedef struct tag_macsec_flush_cmd {
	struct mgmt_msg_head head; /**< Management msg header info, 8B */
	u64 sci; /**< 64-bit SCI value used to identify an SC */
	u8 op_code; /**< Operation code, 0: flush sc and sa, 1: flush sa */
	u8 reserved[7]; /**< reserved for expanding */
} tag_macsec_flush_cmd_s;

// macsec whitelist tool supported operation types
typedef enum macsec_whitelist_tool_op {
	MACSEC_WHITELIST_TOOL_OP_ENABLE = 0,
	MACSEC_WHITELIST_TOOL_OP_SET,
	MACSEC_WHITELIST_TOOL_OP_LIST,
	MACSEC_WHITELIST_TOOL_OP_MAX
} macsec_whitelist_tool_op_e;

// macsec whitelist configuration scenarios
typedef enum macsec_whitelist_tool_mode {
	MACSEC_WHITELIST_TOOL_MODE_DMAC = 0,
	MACSEC_WHITELIST_TOOL_MODE_TXVLAN,
	MACSEC_WHITELIST_TOOL_MODE_RXVLAN,
	MACSEC_WHITELIST_TOOL_MODE_ETYPE,
	MACSEC_WHITELIST_TOOL_MODE_MAX
} macsec_whitelist_tool_mode_e;

// inbuf contains one hdr
typedef struct macsec_whitelist_cmd_hdr {
	macsec_whitelist_tool_op_e cmd_type;
	macsec_whitelist_tool_mode_e mode_type;
} macsec_whitelist_cmd_hdr_t;

// inbuf definition
typedef struct macsec_whitelist_info {
	u64 dmac;/**< dmac value */
	u32 vlanid;/**< vlanid value */
	u32 mask;
	u32 dmac_id;
	u32 port;
	u32 dmac_mask;
	u8 dmac_service;
	u8 service;
	u8 etype_control;
	u8 dmac_flag;
	u8 dmac_service_flag;
	u8 vlanid_flag;
	u8 mask_flag;
	u8 etype_flag;
	u8 etype_control_flag;
	u8 rsvd[3];
} macsec_whitelist_info_t;

typedef struct macsec_whitelist_cmd_in {
	struct mgmt_msg_head head;
	macsec_whitelist_cmd_hdr_t hdr;
	macsec_whitelist_info_t buf;
} macsec_whitelist_cmd_in_t;

// outbuf definition
typedef struct macsec_whitelist_cmd_out {
	struct mgmt_msg_head head;
	u64 dmac_list[MACSEC_DMAC_TEMPLATE_NUM];
	u32 dmac_mask_list[MACSEC_DMAC_TEMPLATE_NUM];
	u32 dmac_valid_num;
	u8 dmac_port_list[MACSEC_PORT_NUM];
	u32 txvlan_list[MACSEC_PORT_NUM];
	u32 txvlan_valid_num;
	u32 rxvlan_list[MACSEC_PORT_NUM];
	u32 rxvlan_mask_list[MACSEC_PORT_NUM];
	u32 rxvlan_valid_num;
	u32 etype_list[MACSEC_ETYPE_TEMPLATE_NUM];
} macsec_whitelist_cmd_out_s;

#endif /* MACSEC_MPU_CMD_DEFS_H */
