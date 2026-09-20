/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HiSilicon PCIe Trace and Tuning (PTT) support
 * Copyright (c) 2022 HiSilicon Technologies Co., Ltd.
 */

#ifndef INCLUDE__HISI_PTT_PKT_DECODER_H__
#define INCLUDE__HISI_PTT_PKT_DECODER_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/bits.h>
#include <linux/bitfield.h>

#define HISI_PTT_8DW_CHECK_MASK			GENMASK(31, 11)
#define HISI_PTT_IS_8DW_PKT			GENMASK(31, 11)
#define HISI_PTT_MAX_SPACE_LEN			10
#define HISI_PTT_FIELD_LENGTH			4
#define HISI_PTT_3DW_HEADER_PROTO_LEN		3
#define HISI_PTT_4DW_HEADER_PROTO_LEN		4
#define HISI_PTT_PATTERN_LEGACY			0
#define HISI_PTT_PATTERN_V1			1

/* Hisi PTT Header DW0 fields for 4DW format
 *
 * bits [31:30] [ 29:25 ][24][23][22][21][    20:11   ][    10:0    ]
 *      |-----|---------|---|---|---|---|-------------|-------------|
 * DW0  [ Fmt ][  Type  ][T9][T8][TH][SO][   Length   ][    Time    ]
 */
#define HISI_PTT_HEAD0_4DW_TIME			GENMASK(10, 0)
#define HISI_PTT_HEAD0_4DW_LEN			GENMASK(20, 11)
#define HISI_PTT_HEAD0_4DW_SO			BIT(21)
#define HISI_PTT_HEAD0_4DW_TH			BIT(22)
#define HISI_PTT_HEAD0_4DW_T8			BIT(23)
#define HISI_PTT_HEAD0_4DW_T9			BIT(24)
#define HISI_PTT_HEAD0_4DW_TYPE			GENMASK(29, 25)
#define HISI_PTT_HEAD0_4DW_FORMAT		GENMASK(31, 30)

/* Hisi PTT Header DW0 fields for 8DW format
 *
 * bits [31:29][28:24][23][22:20][19][18][17][16][15][14][  13:12  ][11:10][    9:0    ]
 *      |------|------|---|------|---|---|---|---|---|---|----------|------|-----------|
 * DW0  [ Fmt ][Type] [T9][ TC ] [T8][A2][LN][TH][TD][EP][ATTR<1:0>][ AT ] [  Length   ]
 */
#define HISI_PTT_HEAD0_8DW_LEN			GENMASK(9, 0)
#define HISI_PTT_HEAD0_8DW_AT			GENMASK(11, 10)
#define HISI_PTT_HEAD0_8DW_ATTR_1_0		GENMASK(13, 12)
#define HISI_PTT_HEAD0_8DW_EP			BIT(14)
#define HISI_PTT_HEAD0_8DW_TD			BIT(15)
#define HISI_PTT_HEAD0_8DW_TH			BIT(16)
#define HISI_PTT_HEAD0_8DW_LN			BIT(17)
#define HISI_PTT_HEAD0_8DW_A2			BIT(18)
#define HISI_PTT_HEAD0_8DW_T8			BIT(19)
#define HISI_PTT_HEAD0_8DW_TC			GENMASK(22, 20)
#define HISI_PTT_HEAD0_8DW_T9			BIT(23)
#define HISI_PTT_HEAD0_8DW_TYPE			GENMASK(28, 24)
#define HISI_PTT_HEAD0_8DW_FORMAT		GENMASK(31, 29)

/* Hisi PTT Header DW1/DW2/DW3 fields for 64-bit Address-Based Routing TLPs
 * Used with Memory rd/wr DMWr and AtomicOp Requests.
 *
 * bits [   31:16    ][  15:8  ][    7:4   ][    3:0    ]
 *      |-------------|---------|-----------|-----------|
 * DW1  [Requester ID][Tag<7:0>][Last DW BE][First DW BE]
 *
 * bits [   31   ][     30:23     ][ 22 ][21][20][  19:16  ][     15:0     ]
 *      |---------|----------------|-----|---|--|-----------|--------------|
 * DW2  [  RSV2   ][Request Segment][RSV1][TV][T][Tag<13:10>][Address<47:32>]
 *
 * bits [     31:2    ][  1:0  ]
 *      |--------------|-------|
 * DW3  [Address<31:2>][PH<1:0>]
 */
#define HISI_PTT_HEAD1_AR64_REQ_ID		GENMASK(31, 16)
#define HISI_PTT_HEAD1_AR64_TAG_7_0		GENMASK(15, 8)
#define HISI_PTT_HEAD1_AR64_LAST_DW_BE		GENMASK(7, 4)
#define HISI_PTT_HEAD1_AR64_FIRST_DW_BE		GENMASK(3, 0)
#define HISI_PTT_HEAD2_AR64_RSV2		BIT(31)
#define HISI_PTT_HEAD2_AR64_REQ_SEG		GENMASK(30, 23)
#define HISI_PTT_HEAD2_AR64_RSV1		BIT(22)
#define HISI_PTT_HEAD2_AR64_TV			BIT(21)
#define HISI_PTT_HEAD2_AR64_T			BIT(20)
#define HISI_PTT_HEAD2_AR64_TAG_13_10		GENMASK(19, 16)
#define HISI_PTT_HEAD2_AR64_ADDR_47_32		GENMASK(15, 0)
#define HISI_PTT_HEAD3_AR64_ADDR_31_2		GENMASK(31, 2)
#define HISI_PTT_HEAD3_AR64_PH_1_0		GENMASK(1, 0)

/* Hisi PTT Header DW1/DW2/DW3 fields for 32-bit Address-Based Routing TLPs
 * Used with Memory rd/wr DMWr, AtomicOp and I/O Requests.
 *
 * bits [   31:16    ][  15:8  ][    7:4   ][    3:0    ]
 *      |-------------|---------|-----------|-----------|
 * DW1  [Requester ID][Tag<7:0>][Last DW BE][First DW BE]
 *
 * For Memory rd/wr DMWr and AtomicOp Requests
 * bits [     31:2    ][  1:0  ]
 *      |--------------|-------|
 * DW2  [Address<31:2>][PH<1:0>]
 *
 * For I/O Transactions
 * bits [     31:2    ][   1:0  ]
 *      |--------------|--------|
 * DW2  [Address<31:2>][Reserved]
 *
 * For Memory rd/wr DMWr and AtomicOp Requests
 * bits [     31:24      ][  23:16 ][ 15:14 ][13:12][11:9] [8 ][7 ][ 6  ][5 ][4][    3:0   ]
 *      |-----------------|---------|--------|------|------|---|---|-----|---|--|----------|
 * DW3  [Request Segments][ST<15:8>][ RSV2  ][  HV ][ AMA ][AV][FM][RSV1][TV][T][Tag<13:10>]
 *
 * For I/O Transactions
 * bits [     31:24      ][  23:8  ][7 ][ 6  ][5 ][4][    3:0   ]
 *      |-----------------|---------|---|-----|---|--|----------|
 * DW3  [Request Segments][  RSV2  ][FM][RSV1][TV][T][Tag<13:10>]
 */
#define HISI_PTT_HEAD1_AR32_REQ_ID		GENMASK(31, 16)
#define HISI_PTT_HEAD1_AR32_TAG_7_0		GENMASK(15, 8)
#define HISI_PTT_HEAD1_AR32_LAST_DW_BE		GENMASK(7, 4)
#define HISI_PTT_HEAD1_AR32_FIRST_DW_BE		GENMASK(3, 0)
#define HISI_PTT_HEAD2_AR32_ADDR_31_2		GENMASK(31, 2)
#define HISI_PTT_HEAD2_AR32_PH_1_0		GENMASK(1, 0)
#define HISI_PTT_HEAD2_AR32_IO_RSV		GENMASK(1, 0)
#define HISI_PTT_HEAD3_AR32_REQ_SEG		GENMASK(31, 24)
#define HISI_PTT_HEAD3_AR32_ST_15_8		GENMASK(23, 16)
#define HISI_PTT_HEAD3_AR32_RSV2		GENMASK(15, 14)
#define HISI_PTT_HEAD3_AR32_HV			GENMASK(13, 12)
#define HISI_PTT_HEAD3_AR32_AMA			GENMASK(11, 9)
#define HISI_PTT_HEAD3_AR32_AV			BIT(8)
#define HISI_PTT_HEAD3_AR32_FM			BIT(7)
#define HISI_PTT_HEAD3_AR32_RSV1		BIT(6)
#define HISI_PTT_HEAD3_AR32_TV			BIT(5)
#define HISI_PTT_HEAD3_AR32_T			BIT(4)
#define HISI_PTT_HEAD3_AR32_TAG_13_10		GENMASK(3, 0)
#define HISI_PTT_HEAD3_AR32_IO_RSV2		GENMASK(23, 8)

/* Hisi PTT Header DW1/DW2/DW3 fields for Configuration Requests
 *
 * bits [   31:16    ][  15:8  ][    7:4   ][    3:0    ]
 *      |-------------|---------|-----------|-----------|
 * DW1  [Requester ID][Tag<7:0>][Last DW BE][First DW BE]
 *
 * bits [     31:16    ][ 15:12 ][    11:8   ][      7:2      ][ 1:0]
 *      |--------------|---------|------------|----------------|----|
 * DW2  [Destination ID][ RSV2  ][Ext Reg Num][Register Number][RSV1]
 *
 * bits [   31   ][       30:23        ][22][21][20][  19:16  ][   15:0   ]
 *      |---------|--------------------|----|---|--|-----------|----------|
 * DW3  [  RSV2  ][Destination Segment][DSV][TV][T][Tag<13:10>][   RSV1   ]
 */
#define HISI_PTT_HEAD1_CFG_REQ_ID		GENMASK(31, 16)
#define HISI_PTT_HEAD1_CFG_TAG_7_0		GENMASK(15, 8)
#define HISI_PTT_HEAD1_CFG_LAST_DW_BE		GENMASK(7, 4)
#define HISI_PTT_HEAD1_CFG_FIRST_DW_BE		GENMASK(3, 0)
#define HISI_PTT_HEAD2_CFG_DST_ID		GENMASK(31, 16)
#define HISI_PTT_HEAD2_CFG_RSV2			GENMASK(15, 12)
#define HISI_PTT_HEAD2_CFG_REG_NUM_EXT		GENMASK(11, 8)
#define HISI_PTT_HEAD2_CFG_REG_NUM		GENMASK(7, 2)
#define HISI_PTT_HEAD2_CFG_RSV1			GENMASK(1, 0)
#define HISI_PTT_HEAD3_CFG_RSV2			BIT(31)
#define HISI_PTT_HEAD3_CFG_DST_SEG		GENMASK(30, 23)
#define HISI_PTT_HEAD3_CFG_DSV			BIT(22)
#define HISI_PTT_HEAD3_CFG_TV			BIT(21)
#define HISI_PTT_HEAD3_CFG_T			BIT(20)
#define HISI_PTT_HEAD3_CFG_TAG_13_10		GENMASK(19, 16)
#define HISI_PTT_HEAD3_CFG_RSV1			GENMASK(15, 0)

/* Hisi PTT Header DW1/DW2/DW3 fields for Completion TLPs
 *
 * bits [    31:16   ][  15:13   ][12 ][   11:0   ]
 *      |-------------|-----------|----|----------|
 * DW1  [Completer ID][Cpl Status][BCM][Byte Count]
 *
 * bits [    31:16   ][  15:8  ][ 7 ][     6:0     ]
 *      |-------------|---------|----|-------------|
 * DW2  [Requester ID][Tag<7:0>][RSV][Lower Address]
 *
 * bits [       31:24       ][       23:16     ][15 ][ 14:6][5][4 ][   3:0    ]
 *      |--------------------|------------------|----|------|--|---|----------|
 * DW3  [Destination Segment][Completer Segment][DSV][ RSV ][TV][T][Tag<13:10>]
 */
#define HISI_PTT_HEAD1_CPL_COM_ID		GENMASK(31, 16)
#define HISI_PTT_HEAD1_CPL_STA			GENMASK(15, 13)
#define HISI_PTT_HEAD1_CPL_BCM			BIT(12)
#define HISI_PTT_HEAD1_CPL_BYTE_CNT		GENMASK(11, 0)
#define HISI_PTT_HEAD2_CPL_REQ_ID		GENMASK(31, 16)
#define HISI_PTT_HEAD2_CPL_TAG_7_0		GENMASK(15, 8)
#define HISI_PTT_HEAD2_CPL_RSV			BIT(7)
#define HISI_PTT_HEAD2_CPL_LO_ADDR		GENMASK(6, 0)
#define HISI_PTT_HEAD3_CPL_DST_SEG		GENMASK(31, 24)
#define HISI_PTT_HEAD3_CPL_COM_SEG		GENMASK(23, 16)
#define HISI_PTT_HEAD3_CPL_DSV			BIT(15)
#define HISI_PTT_HEAD3_CPL_RSV			GENMASK(14, 6)
#define HISI_PTT_HEAD3_CPL_TV			BIT(5)
#define HISI_PTT_HEAD3_CPL_T			BIT(4)
#define HISI_PTT_HEAD3_CPL_TAG_13_10		GENMASK(3, 0)

/* Hisi PTT Header DW1 fields for Message Requests
 *
 * bits [   31:16    ][  15:8  ][     7:0    ]
 *      |-------------|---------|------------|
 * DW1  [Requester ID][Tag<7:0>][Message Code]
 */
#define HISI_PTT_HEAD1_MSG_REQ_ID		GENMASK(31, 16)
#define HISI_PTT_HEAD1_MSG_TAG_7_0		GENMASK(15, 8)
#define HISI_PTT_HEAD1_MSG_CODE			GENMASK(7, 0)

enum hisi_ptt_pkt_type {
	HISI_PTT_4DW_PKT,
	HISI_PTT_8DW_PKT,
	HISI_PTT_PKT_MAX
};

enum hisi_ptt_pkt_msg_type {
	/* Types do not support analysis */
	HISI_PTT_PKT_TYPE_UNKNOWN,
	/* NP-(Memory Read requset: MRd) */
	HISI_PTT_PKT_TYPE_MRD,
	/* P-(Memory write request: MWr) */
	HISI_PTT_PKT_TYPE_MWR,
	/* P-(Deferrable Memory write request: DMWr) */
	HISI_PTT_PKT_TYPE_DMWR,
	/* P-(Message request: Msg, MsgD) */
	HISI_PTT_PKT_TYPE_MSG,
	/* NP-(AtomicOP request: FetchAdd, Swap, CAS) */
	HISI_PTT_PKT_TYPE_ATOM,
	/* NP-(I/O request: IORd, IOWr) */
	HISI_PTT_PKT_TYPE_IO,
	/* NP-(Configuration request: CfgRd0, CfgWr0, CfgRd1, CfgWr1) */
	HISI_PTT_PKT_TYPE_CFG,
	/* CPL-(Completion: Cpl, CplD) */
	HISI_PTT_PKT_TYPE_CPL,
	/* Type max in enumeration*/
	HISI_PTT_PKT_TYPE_MAX
};

struct hisi_ptt_pkt_buf {
	const unsigned char *buf;
	size_t pos;
	size_t len;
	enum hisi_ptt_pkt_type pkt_type;
	enum hisi_ptt_pkt_msg_type pkt_msg_type;
	size_t proto_len;
	size_t pattern;
};

int hisi_ptt_pkt_desc(struct hisi_ptt_pkt_buf *pkt_buf);

#endif
