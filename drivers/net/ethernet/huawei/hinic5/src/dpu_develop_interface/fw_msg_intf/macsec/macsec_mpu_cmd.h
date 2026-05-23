/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : macsec_mpu_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : COMM Commands between host and MPU(macsec)
 */

#ifndef MACSEC_MPU_CMD_H
#define MACSEC_MPU_CMD_H

#include <linux/bits.h>

#ifndef BIT
#define BIT(n) (1UL << (n))
#endif

/**
 * @brief macsec_mgmt_cmd_e - COMM Commands between hinicadm to MPU(macsec)
 * @details Operation codes for interaction between MACSEC and driver, including management of SC, SA, MIB and SERVICE
 */
typedef enum {
	MACSEC_CMD_SC_OP = 0, /* sc operation @see struct tag_macsec_cmd_sc_operation_s */
	MACSEC_CMD_SA_OP, /* sa operation @see struct tag_macsec_cmd_sa_operation_s */
	MACSEC_CMD_GET_PORT_MIB, /* get port mib @see struct tag_macsec_cmd_port_mib_operation_s */
	MACSEC_CMD_GET_SC_MIB, /* get sc mib @see struct tag_macsec_cmd_sc_mib_operation_s */
	MACSEC_CMD_GET_ERR_CNT, /* get error cnt @see struct tag_macsec_cmd_err_cnt_operation_s */
	MACSEC_CMD_SERVICE_OP, /* service op @see struct macsec_cmd_service_operation_s */
	MACSEC_CMD_FEATURE_NEGO_OP, /* macsec feature negotiate op
				     * @see struct macsec_feature_nego_cmd_s
				     */
	MACSEC_CMD_FLUSH_OP, /* macsec resource flush op @see struct tag_macsec_flush_cmd_s */
	MACSEC_CMD_WHITELIST_OP, /* macsec whitelist op @see struct macsec_whitelist_cmd_out */
} macsec_mgmt_cmd_e;

/**
 * @brief macsec_mbox_sc_op_cmd_e - opcode of mailbox sc opcode
 * @details Operation codes for SC encryption/decryption side, including create, delete and update operations
 */
typedef enum {
	MACSEC_CMD_ENC_SC_CREATE = 0, /* enc sc create */
	MACSEC_CMD_ENC_SC_DELETE, /* enc sc delete */
	MACSEC_CMD_ENC_SC_UPDATE, /* enc sc update */
	MACSEC_CMD_ENC_SC_GET_INFO, /* get enc sc */
	MACSEC_CMD_DEC_SC_CREATE, /* dec sc create */
	MACSEC_CMD_DEC_SC_DELETE, /* dec sc delete */
	MACSEC_CMD_DEC_SC_UPDATE, /* dec sc update */
	MACSEC_CMD_DEC_SC_GET_INFO, /* get dec sc */
} macsec_mbox_sc_op_cmd_e;

/**
 * @brief macsec_mbox_sa_op_cmd_e - opcode of mailbox sa opcode
 * @details Operation codes for SA encryption/decryption side, including create, delete and update operations
 */
typedef enum {
	MACSEC_CMD_ENC_SA_CREATE = 0, /* enc sa create */
	MACSEC_CMD_ENC_SA_DELETE, /* enc sa delete */
	MACSEC_CMD_ENC_SA_UPDATE, /* enc sa update */
	MACSEC_CMD_ENC_SA_GET_INFO, /* get enc sa */
	MACSEC_CMD_DEC_SA_CREATE, /* dec sa create */
	MACSEC_CMD_DEC_SA_DELETE, /* dec sa delete */
	MACSEC_CMD_DEC_SA_UPDATE, /* dec sa update */
	MACSEC_CMD_DEC_SA_GET_INFO, /* get dec sa */
} macsec_mbox_sa_op_cmd_e;

/**
 * @brief macsec_mbox_service_op_cmd_e - opcode of mailbox service opcode
 * @details MACSEC service related operations, such as enabling MACSEC when driver loads and disabling MACSEC when driver unloads
 */
typedef enum {
	MACSEC_CMD_SERVICE_OP_MACSEC_DISABLE = 0, /* macsec disable */
	MACSEC_CMD_SERVICE_OP_MACSEC_ENABLE, /* macsec enable */
} macsec_mbox_service_op_cmd_e;

/**
 * @brief macsec_mbox_feature_nego_op_cmd_e - opcode of mailbox feature negotiate opcode
 * @details MACSEC feature negotiation related operations, querying or setting features
 */
typedef enum {
	MACSEC_FEATURE_NEGO_OPCODE_GET = 0, /* feature negotiation get */
	MACSEC_FEATURE_NEGO_OPCODE_SET = 1, /* feature negotiation set (reserve for using) */
} macsec_mbox_feature_nego_op_cmd_e;

/**
 * @brief macsec_mbox_feature_cap_e - list of features supported by macsec
 * @details MACSEC supported feature list
 */
typedef enum {
	MACSEC_F_HARDEN_PATH = BIT(0), /* macsec does not have NPU */
	MACSEC_F_SUPPORT_SM4 = BIT(1), /* macsec support using sm4 */
} macsec_mbox_feature_cap_e;

/**
 * @brief macsec_mbox_flush_op_cmd_e - opcode of mailbox macsec flush opcode
 * @details MACSEC resource cleanup related operations
 */
typedef enum {
	MACSEC_CMD_FLUSH_SC_OP = 0, /* flush sc and sa resource */
	MACSEC_CMD_FLUSH_SA_OP, /* flush sa resource */
} macsec_mbox_flush_op_cmd_e;

#endif /* MACSEC_MPU_CMD_H */
