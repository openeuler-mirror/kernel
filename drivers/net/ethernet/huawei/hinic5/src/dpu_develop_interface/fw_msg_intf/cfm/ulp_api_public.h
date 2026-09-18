/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : ulp_api_public.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : ulp_api_public define. Driver and microcode public struct definition, endianness must be considered when defining structs
 */

#ifndef ULP_API_PUBLIC_H
#define ULP_API_PUBLIC_H

#include "typedef.h"
#include "host_dma_npu_cmd_defs.h"

#define ULP_API_RQ_NUM_INVALID 0xffff
#define ULP_API_BOOT_RQ_NUM 2

typedef struct tag_iocb_udata_s {
	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 rsvd : 17;
		u32 iocb_id : 15;
#else
		u32 iocb_id : 15;   /* iocb_id definition */
		u32 rsvd : 17;
#endif
	} bs;
	u32 value;
	} dw0;

	u32 dw1_rsvd;
} iocb_udata_s;

typedef struct tag_rq_cqe_common {
	u32 data_h;
	u32 data_l;
} rq_cqe_common_s;

/**
 * @union api_rq_cqe_udata_u
 * @brief CQE struct definition for driver and microcode interaction
 */
typedef union tag_api_rq_cqe_udata {
	rq_cqe_common_s udata;
	iocb_udata_s vmio_udata;
} api_rq_cqe_udata_u;

#define ULP_API_RQE_BUF_SIZE 4
/**
 * @union ulp_api_rqe_buf_u
 * @brief RQ BUF struct definition for driver and microcode interaction
 */
typedef union tag_ulp_api_rqe_buf {
	u32 udata[ULP_API_RQE_BUF_SIZE];
} ulp_api_rqe_buf_u;

/**
 * @struct ulp_api_rq_cqe_s
 * @brief RQ CQE struct
 */
typedef struct tag_ulp_api_rq_cqe {
	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 done : 1;
		u32 rsvd : 31;
#else
		u32 rsvd : 31;
		u32 done : 1;
#endif
	} bs;
	u32 value;
	} dw0;

	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 pkt_len : 16;
		u32 rsvd : 16;
#else
		u32 rsvd : 16;
		u32 pkt_len : 16;
#endif
	} bs;
	u32 value;
	} dw1;

	u32 dw2_rsvd;
	u32 dw3_rsvd;

	api_rq_cqe_udata_u rq_cqe_udata;

	u32 dw6_rsvd;
	u32 dw7_rsvd;
} ulp_api_rq_cqe_s;

#endif /* ULP_API_PUBLIC_H */
