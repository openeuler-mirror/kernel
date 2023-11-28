/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef _CHIP_SCALE_DEFINES_H_
#define _CHIP_SCALE_DEFINES_H_

#define MAIN_CLK_FREQ       (100 * 1000 * 1000)
#define NIF_PORT_NUM        2
#define PCIE_PORT_NUM       1
#define FUNC_ID_NUM         1026
#define MSIX_VEC_NUM        4096
#define PIO_TLPQ_NUM        2

#define PCIE0_PF_NUM        2
#define PCIE0_PF0_VF_NUM    512
#define PCIE0_PF1_VF_NUM    512

#define PCIE1_PF_NUM        0
#define QP_NUM_MAX          32768
#define RAW_QP_NUM_MAX      8192
#define TSO_QP_NUM_MAX      1024
#define CQ_NUM_MAX          32768
#define SQ_SIZE_MAX         1024
#define RQ_SIZE_MAX         1024
#define CQ_SIZE_MAX         32768
#define MPT_SIZE            32768
#define MTT_SIZE            65536
#define GRP_NUM_MAX         1024
#define CLUSTER_NUM_MAX     1

#define PP_PCT_DEPTH                     512
#define PP_PCT_KEY_WIDTH                 352
#define PP_PCT_AD_WIDTH                  42

#define PP_WCT_DEPTH                     64
#define PP_WCT_SHORT_KEY_WIDTH           240
#define PP_WCT_LONG_KEY_WIDTH            480
#define PP_WCT_AD_WIDTH                  19

#define PP_IACL_DEPTH                    16
#define PP_IACL_KEY_WIDTH                463
#define PP_IACL_AD_WIDTH                 38

#define PP_TUNNEL_ENCAP_TBL_DEPTH        10240
#define PP_TUNNEL_ENCAP_TBL_WIDTH        45

#define PP_MIRROR_TBL_DEPTH              256
#define PP_MIRROR_TBL_WIDTH              106

#define PP_IPAT_DEPTH                    2048
#define PP_IPAT_WIDTH                    119

#define PP_EPAT_DEPTH                    2048
#define PP_EPAT_WIDTH                    160

#define PP_ONCHIP_FT_DEPTH               16384
#define PP_ONCHIP_FT_WIDTH               439

#define PP_ONCHIP_FAT_DEPTH              (16384 + 128)
#define PP_ONCHIP_FAT_WIDTH              326

#define PP_ONCHIP_CT_DEPTH               (16384 + 128)
#define PP_ONCHIP_CT_WIDTH               156

#define PP_ONCHIP_VER_TBL_DEPTH          2048
#define PP_ONCHIP_VER_TBL_WIDTH          13

#define PP_BOMT_DEPTH                    1040
#define PP_BOMT_WIDTH                    12

#define PP_PST_DEPTH                     2048
#define PP_PST_WIDTH                     1

#define PRI_NUM             8

#endif
