/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : comm_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : drivermpunpusmu COMM defines
 */

#ifndef COMM_DEFS_H
#define COMM_DEFS_H

/* CMDQ MODULE_TYPE */
typedef enum hinic5_mod_type {
	HINIC5_MOD_DEPRECATED
} hinic5_mod_type_e;

/**
 * @brief Note: The following module macros must use direct numeric definitions, no calculations allowed, otherwise CMDQ REGISTER function will be disabled
 */
#define HINIC5_MOD_COMM     0 /* HW communication module */
#define HINIC5_MOD_L2NIC    1 // (HINIC5_MOD_COMM + 1) /* L2NIC module */
#define HINIC5_MOD_ROCE     2 // (HINIC5_MOD_L2NIC + 1)
#define HINIC5_MOD_PLOG     3 // (HINIC5_MOD_ROCE + 1)
#define HINIC5_MOD_TOE      4 // (HINIC5_MOD_PLOG + 1)
#define HINIC5_MOD_UB       5 // (HINIC5_MOD_TOE + 1)
#define HINIC5_MOD_VROCE    6 // (HINIC5_MOD_UB + 1)
#define HINIC5_MOD_CFGM     7 // (HINIC5_MOD_VROCE + 1) /* Configuration module */
#define HINIC5_MOD_HINIC5_CQM      8 // (HINIC5_MOD_CFGM + 1)
#define HINIC5_MOD_VMSEC    9 // (HINIC5_MOD_HINIC5_CQM + 1)
#define COMM_MOD_FC         10 // (HINIC5_MOD_VMSEC + 1)
#define HINIC5_MOD_OVS      11 // (COMM_MOD_FC + 1)
#define HINIC5_MOD_VBS      12 // (HINIC5_MOD_OVS + 1)
#define HINIC5_MOD_MIGRATE  13 // (HINIC5_MOD_VBS + 1)
#define HINIC5_MOD_HILINK   14 // (HINIC5_MOD_MIGRATE + 1)
#define HINIC5_MOD_CRYPT    15 // (HINIC5_MOD_HILINK + 1) /* secure crypto module */
#define HINIC5_MOD_VIO      16 // (HINIC5_MOD_CRYPT + 1)
#define HINIC5_MOD_IMU      17 // (HINIC5_MOD_VIO + 1)
#define HINIC5_MOD_DFT      18 // (HINIC5_MOD_IMU + 1) /* DFT */
#define HINIC5_MOD_MACSEC   19 // (HINIC5_MOD_DFT + 1)
#define HINIC5_MOD_SW_FUNC  20 // (HINIC5_MOD_MACSEC + 1) /* Software module id, for PF/VF and multi-host */
#define HINIC5_MOD_NST      21 // (HINIC5_MOD_SW_FUNC + 1)
#define HINIC5_MOD_HTN      22 // (HINIC5_MOD_NST + 1)
#define HINIC5_MOD_JBOF     23 // (HINIC5_MOD_HTN + 1)
#define HINIC5_MOD_FAKE_FMSG 24 // (HINIC5_MOD_JBOF + 1)
#define HINIC5_MOD_UBCNET   25 // (HINIC5_MOD_FAKE_FMSG + 1)
#define HINIC5_MOD_CFM      26 // (HINIC5_MOD_UBCNET + 1)
#define HINIC5_MOD_HIHTR    27 // (HINIC5_MOD_CFM + 1)
#define HINIC5_MOD_MAX      28 // (HINIC5_MOD_HIHTR + 1)
#define HINIC5_MOD_HW_MAX   HINIC5_MOD_MAX

#define MODULE_ID(module) #module
#define HINIC5_MOD(module) MODULE_ID(module)

#endif
