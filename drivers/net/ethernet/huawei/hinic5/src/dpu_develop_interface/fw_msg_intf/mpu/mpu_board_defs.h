/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_board_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : COMM board info between Driver and MPU
 */

#ifndef COMM_BOARD_INFO_H
#define COMM_BOARD_INFO_H

#define BOARD_TYPE_TEST_RANGE_START 1 /* Test board range start (inclusive) */
#define BOARD_TYPE_TEST_RANGE_END   29 /* Test board range end (inclusive) */
#define BOARD_TYPE_STRG_RANGE_START 30 /* Storage board range start (inclusive) */
#define BOARD_TYPE_STRG_RANGE_END   99 /* Storage board range end (inclusive) */
#define BOARD_TYPE_CAL_RANGE_START  100 /* Compute board range start (inclusive) */
#define BOARD_TYPE_CAL_RANGE_END    169 /* Compute board range end (inclusive) */
#define BOARD_TYPE_CLD_RANGE_START  170 /* Cloud board range start (inclusive) */
#define BOARD_TYPE_CLD_RANGE_END    239 /* Cloud board range end (inclusive) */
#define BOARD_TYPE_RSVD_RANGE_START 240 /* Reserved board range start (inclusive) */
#define BOARD_TYPE_RSVD_RANGE_END   255 /* Reserved board range end (inclusive) */

typedef enum {
	BOARD_TYPE_MPU_DEFAULT                      = 0,     /* Default config */
	BOARD_TYPE_TEST_EVB_4X25G                   = 1,     /* EVB Board */
	BOARD_TYPE_TEST_CEM_2X100G                  = 2,     /* 2X100G CEM Card */
	BOARD_TYPE_TEST_EVB1_DDIE_2X200G            = 3,     /* 2X200G EVB1 DDIE Card */
	BOARD_TYPE_TEST_EVB1_SMDIE_1X200G           = 4,     /* 1X200G EVB1 SMDIE Card */
	BOARD_TYPE_TEST_EVB1_SSDIE_1X200G           = 5,     /* 1X200G EVB1 SSDIE Card */
	BOARD_TYPE_TEST_EVB2_DDIE_4X100G            = 6,     /* 4X100G EVB2 DDIE Card */
	BOARD_TYPE_TEST_EVB2_SMDIE_2X100G           = 7,     /* 2X100G EVB2 SMDIE Card */
	BOARD_TYPE_TEST_EVB2_SSDIE_2X100G           = 8,     /* 2X100G EVB2 SSDIE Card */
	BOARD_TYPE_TEST_EVB3_DDIE_4X25G             = 9,     /* 4X25G EVB3 DDIE Card */
	BOARD_TYPE_TEST_EVB3_SMDIE_2X25G            = 10,    /* 2X25G EVB3 SMDIE Card */
	BOARD_TYPE_TEST_EVB3_SSDIE_2X25G            = 11,    /* 2X25G EVB3 SSDIE Card */
	BOARD_TYPE_TEST_EVBS_SDIE_4X25G             = 12,    /* 4X25G EVBS SDIE Card */
	BOARD_TYPE_TEST_EVBS_SDIE_2X100G            = 13,    /* 2X100G EVBS SDIE Card */
	BOARD_TYPE_TEST_EVB1_2X400G                 = 14,    /* 2X400G EVB1 Card */
	BOARD_TYPE_TEST_EVB2_1X800G                 = 15,    /* 1X800G EVB2 Card */
	BOARD_TYPE_TEST_EVB3_2X200G_4x50G           = 16,    /* 2X200G_4X50G EVB3 Card */

	BOARD_TYPE_STRG_SMARTIO_4X32G_FC            = 30,    /* 4X32G  SmartIO FC Card */
	BOARD_TYPE_STRG_SMARTIO_4X25G_TIOE          = 31,    /* 4X25GE SmartIO TIOE Card */
	BOARD_TYPE_STRG_SMARTIO_4X25G_ROCE          = 32,    /* 4X25GE SmartIO ROCE Card */
	BOARD_TYPE_STRG_SMARTIO_4X25G_ROCE_AA       = 33,    /* 4X25GE SmartIO ROCE_AA Card */
	BOARD_TYPE_STRG_SMARTIO_4X25G_SRIOV         = 34,    /* 4X25GE SmartIO container Card */
	BOARD_TYPE_STRG_SMARTIO_4X25G_SRIOV_SW      = 35,    /* 4X25GE SmartIO container
							      * switch Card
							      */
	BOARD_TYPE_STRG_4X25G_COMSTORAGE            = 36,    /* 4X25GE compute storage
							      * Onboard Card
							      */
	BOARD_TYPE_STRG_SMARTIO_4X25G_OVS           = 37,    /* 4x25GE SmartIO OVS Card */
	BOARD_TYPE_STRG_2X100G_TIOE                 = 40,    /* 2X100G SmartIO TIOE Card */
	BOARD_TYPE_STRG_2X100G_ROCE                 = 41,    /* 2X100G SmartIO ROCE Card */
	BOARD_TYPE_STRG_2X100G_ROCE_AA              = 42,    /* 2X100G SmartIO ROCE_AA Card */
	BOARD_TYPE_STRG_2X100G_OVS                  = 43,    /* 2x100GE SmartIO OVS Card */
	BOARD_TYPE_STRG_2X100G_TIOE_ATLANTIC        = 44,    /* 2X100GE SmartIO TIOE Card */
	BOARD_TYPE_STRG_4X25G_TIOE_ATLANTIC         = 45,    /* 4X25GE SmartIO TIOE Card */
	BOARD_TYPE_STRG_2X100G_TIOE_SMARTNIC        = 46,    /* 2X100GE ETH Standard Card TIOE */
	BOARD_TYPE_STRG_2X25G_TIOE_SMARTNIC         = 47,    /* 2X25GE ETH Standard Card TIOE */
	BOARD_TYPE_STRG_2X25G_OVS_SMARTNIC          = 48,    /* 2x25GE ETH Standard Card OVS */
	BOARD_TYPE_STRG_2X100G_ROCE_SMARTNIC        = 49,    /* 2X100GE ETH Standard Card ROCE */
	BOARD_TYPE_STRG_SMARTIO_2X25G_COMPUTE       = 50,    /* 2x25GE SmartIO ROCE Card */
	BOARD_TYPE_STRG_2X200G_ROCE_ATLANTIC        = 51,    /* 2X200G SmartIO ROCE Card */
	BOARD_TYPE_STRG_4X25G_OVS_LITE              = 52,    /* 4x25GE SmartIO OVS LITE Card */
	BOARD_TYPE_STRG_2X200G_ROCE                 = 53,    /* 2X200G SmartIO ROCE Card */
	BOARD_TYPE_STRG_SMARTIO_4X64G_FC            = 54,    /* 4X64G FC SmartIO Card */
	BOARD_TYPE_STRG_2X100G_ROCE_SRIOV           = 55,    /* 2X100GE SmartIO Front Container Card */
	BOARD_TYPE_STRG_2X100G_ROCE_SRIOV_SW        = 56,    /* 2X100GE SmartIO Loopback Container Card */
	BOARD_TYPE_STRG_2X200G_ROCE_SRIOV           = 57,    /* 2X200GE SmartIO Front Container Card */
	BOARD_TYPE_STRG_2X200G_ROCE_SRIOV_SW        = 58,    /* 2X200GE SmartIO Loopback Container Card */
	BOARD_TYPE_STRG_2X200G_TIOE                 = 59,    /* 2X200G SmartIO TIOE Card */
	BOARD_TYPE_STRG_DPU_A_SECURE                = 60,    /* Storage Security Card DPU-A */
	BOARD_TYPE_STRG_2X25G_DPU_A_FUNCTION        = 61,    /* 2X25G Storage Function Card DPU-A */
	BOARD_TYPE_STRG_2X25G_DPU_TIOE              = 62,    /* 2X25G DPU Card TIOE */
	BOARD_TYPE_STRG_2X200G_DPU_ROCE             = 63,    /* 2X200G DPU Card ROCE */
	BOARD_TYPE_STRG_4X25G_ROCE_SRIOV            = 76,    /* 4X25GE SmartIO Front Container Card */
	BOARD_TYPE_STRG_2X200G_ROCE_AA              = 77,    /* 2X200G SmartIO ROCE_AA Card */
	BOARD_TYPE_STRG_8X25G_TIOE                  = 78,    /* 8X25GE SmartIO TIOE Card */
	BOARD_TYPE_STRG_2X200G_OVS_LITE             = 79,    /* 2x200GE SmartIO OVS LITE Card */
	BOARD_TYPE_STRG_2X25G_ROCE_SMARTNIC         = 80,    /* 2X25GE ETH Standard Card ROCE */
	BOARD_TYPE_STRG_2X200G_ROCE_SMARTNIC        = 81,    /* 2X200GE ETH Standard Card ROCE */
	BOARD_TYPE_STRG_2X200G_TIOE_SMARTNIC        = 82,    /* 2X200GE ETH Standard Card TIOE */
	BOARD_TYPE_STRG_2X100G_OVS_SMARTNIC         = 83,    /* 2x100GE ETH Standard Card OVS */
	BOARD_TYPE_STRG_2X100G_ROCE_SMARTNIC_LIFT   = 84,    /* 2X100GE ETH Standard Card ROCE */
	BOARD_TYPE_STRG_2X100G_TIOE_SMARTNIC_LIFT   = 85,    /* 2X100GE ETH Standard Card TIOE */

	BOARD_TYPE_CAL_2X25G_NIC_75MPPS             = 100,   /* 2X25G ETH Standard card 75MPPS */
	BOARD_TYPE_CAL_2X25G_NIC_40MPPS             = 101,   /* 2X25G ETH Standard card 40MPPS */
	BOARD_TYPE_CAL_2X100G_DPU                   = 102,   /* 2X100G DPU card */
	BOARD_TYPE_CAL_4X25G_NIC_120MPPS            = 105,   /* 4X25G ETH Standard card 120MPPS */
	BOARD_TYPE_CAL_4X25G_COMSTORAGE             = 106,   /* 4X25GE compute storage
							      * Onboard Card
							      */
	BOARD_TYPE_CAL_2X32G_FC_HBA                 = 110,   /* 2X32G FC HBA card */
	BOARD_TYPE_CAL_2X16G_FC_HBA                 = 111,   /* 2X16G FC HBA card */
	BOARD_TYPE_CAL_2X100G_NIC_120MPPS           = 115,   /* 2X100G ETH Standard card 120MPPS */
	BOARD_TYPE_CAL_2X25G_DPU                    = 116,   /* 2x25G DPU Card */
	BOARD_TYPE_CAL_2X100G_TCE                   = 117,   /* 2X100G TCE Onboard Card */
	BOARD_TYPE_CAL_4X25G_DPU                    = 118,   /* 4x25G DPU Card */
	BOARD_TYPE_CAL_4X25G_SMARTNIC               = 119,   /* 4X25G SmartIO Card */
	BOARD_TYPE_CAL_2X100G_SMARTNIC              = 120,   /* 2X100G SmartIO Card */
	BOARD_TYPE_CAL_6X25G_DPU                    = 121,   /* 6X25G DPU */
	BOARD_TYPE_CAL_4X25G_DPU_BD                 = 122,   /* 4*25G DPU Big Data Card */
	BOARD_TYPE_CAL_2X25G_NIC_4HOST              = 123,   /* 2*25GE TianGong 4HOST Standard Card */
	BOARD_TYPE_CAL_2X200G_NIC_120MPPS           = 124,   /* 2X200G ETH Standard Card 120MPPS */
	BOARD_TYPE_CAL_2X10G_NIC_LOW                = 125,   /* 2X10G ETH Standard Card Low Power */
	BOARD_TYPE_CAL_2X200G_SMARTNIC              = 126,   /* 2*200G SmartIO Card */
	BOARD_TYPE_CAL_2X200G_NIC_INTERNET          = 127,   /* 2*200G Internet Card */
	BOARD_TYPE_CAL_2X100G_NIC_INTERNET          = 128,   /* 2*100G Internet Card */
	BOARD_TYPE_CAL_1X100GR2_OCP                 = 129,   /* 1*100GR2 DSFP56 Interface OCP Card */
	BOARD_TYPE_CAL_2X200G_DPU                   = 130,   /* 2X200G DPU Card */
	BOARD_TYPE_CAL_2X100_OCP                    = 131,   /* 2*100G DSFP56/QSFP56 Interface OCP Card */
	/* 2*400G UBC 1*8 chip half-width card / 2*8 chip half-width large card */
	BOARD_TYPE_CAL_2X400G_POD                   = 132,
	BOARD_TYPE_CAL_2X400G_UB_EXP                = 133,   /* 2*400G A5 Server Card */
	BOARD_TYPE_CAL_2X200G_V2                    = 134,   /* 2*200G PCIE Standard Card */
	BOARD_TYPE_CAL_1X400G                       = 135,   /* 1X400G PCIE Standard Card */

	BOARD_TYPE_CAL_SP23X_2X10G                  = 136,   /* 1872 2*10G PCIE Standard Card */
	BOARD_TYPE_CAL_SP23X_2X25G                  = 137,   /* 1872 2*25G PCIE Standard Card */
	BOARD_TYPE_CAL_SP23X_2X100G                 = 138,   /* 1872 2*100G PCIE Standard Card */
	BOARD_TYPE_CAL_SP23X_2X100G_OCP             = 139,   /* 1872 2*100G OCP Card */
	BOARD_TYPE_CAL_SP23X_1X200G                 = 140,   /* 1872 1*200G PCIE Standard Card */

	BOARD_TYPE_CAL_2X400G_UBX_BOARD             = 141,   /* 1825 2*400G UBX BOARD */
	BOARD_TYPE_CAL_2X400G_UB_EXP_V1             = 142,   /* 1825 2*400G UB EXP Custom Card */

	BOARD_TYPE_CLD_2X100G_SDI5_1                = 170,   /* 2X100G SDI 5.1 Card */
	BOARD_TYPE_CLD_2X25G_SDI5_0_LITE            = 171,   /* 2x25G SDI5.0 Lite Card */
	BOARD_TYPE_CLD_2X100G_SDI5_0                = 172,   /* 2x100G SDI5.0 Card */
	BOARD_TYPE_CLD_2X200G_SDI6_0                = 173,   /* 2x200G SDI6.0 Card */
	BOARD_TYPE_CLD_2X200G_UNIC                  = 174,   /* 2x200G UNIC Card */
	BOARD_TYPE_CLD_4X25G_SDI5_0_C               = 175,   /* 4*25G SDI5.0.C Card */
	BOARD_TYPE_CLD_2X200G_SDI6_1                = 176,   /* 2x200G SDI6.1 Card */
	BOARD_TYPE_CLD_2X400G_SDI_BOX               = 177,   /* 2*400G Cloud Intelligence SDI-BOX Card */

	BOARD_TYPE_MAX_INDEX                        = 0xFF,   /* Maximum card value */
} board_type_define_e;
#endif
