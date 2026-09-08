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

/* Header DW0 fields for 4DW format */
#define HISI_PTT_HEAD0_4DW_TIME		GENMASK(10, 0)
#define HISI_PTT_HEAD0_4DW_LEN		GENMASK(20, 11)
#define HISI_PTT_HEAD0_4DW_SO		BIT(21)
#define HISI_PTT_HEAD0_4DW_TH		BIT(22)
#define HISI_PTT_HEAD0_4DW_T8		BIT(23)
#define HISI_PTT_HEAD0_4DW_T9		BIT(24)
#define HISI_PTT_HEAD0_4DW_TYPE		GENMASK(29, 25)
#define HISI_PTT_HEAD0_4DW_FORMAT	GENMASK(31, 30)

/* Header DW0 fields for 8DW format */
#define HISI_PTT_HEAD0_8DW_TYPE		GENMASK(28, 24)
#define HISI_PTT_HEAD0_8DW_FORMAT	GENMASK(31, 29)

enum hisi_ptt_pkt_type {
	HISI_PTT_4DW_PKT,
	HISI_PTT_8DW_PKT,
	HISI_PTT_PKT_MAX
};

static int hisi_ptt_pkt_size[] = {
	[HISI_PTT_4DW_PKT]	= 16,
	[HISI_PTT_8DW_PKT]	= 32,
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
};

int hisi_ptt_pkt_desc(struct hisi_ptt_pkt_buf *pkt_buf);

#endif
