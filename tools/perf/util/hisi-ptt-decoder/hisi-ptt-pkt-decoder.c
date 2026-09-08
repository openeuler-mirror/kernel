// SPDX-License-Identifier: GPL-2.0
/*
 * HiSilicon PCIe Trace and Tuning (PTT) support
 * Copyright (c) 2022 HiSilicon Technologies Co., Ltd.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <byteswap.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <asm-generic/unaligned.h>
#include <stdarg.h>

#include "../color.h"
#include "hisi-ptt-pkt-decoder.h"

/*
 * For 8DW format, the bit[31:11] of DW0 is always 0x1fffff, which can be
 * used to distinguish the data format.
 * 8DW format is like:
 *   bits [                 31:11                 ][       10:0       ]
 *        |---------------------------------------|-------------------|
 *    DW0 [                0x1fffff               ][ Reserved (0x7ff) ]
 *    DW1 [                       Prefix                              ]
 *    DW2 [                     Header DW0                            ]
 *    DW3 [                     Header DW1                            ]
 *    DW4 [                     Header DW2                            ]
 *    DW5 [                     Header DW3                            ]
 *    DW6 [                   Reserved (0x0)                          ]
 *    DW7 [                        Time                               ]
 *
 * 4DW format is like:
 *   bits [31:30] [ 29:25 ][24][23][22][21][    20:11   ][    10:0    ]
 *        |-----|---------|---|---|---|---|-------------|-------------|
 *    DW0 [ Fmt ][  Type  ][T9][T8][TH][SO][   Length   ][    Time    ]
 *    DW1 [                     Header DW1                            ]
 *    DW2 [                     Header DW2                            ]
 *    DW3 [                     Header DW3                            ]
 */

enum hisi_ptt_8dw_pkt_field_type {
	HISI_PTT_8DW_CHK_AND_RSV0,
	HISI_PTT_8DW_PREFIX,
	HISI_PTT_8DW_HEAD0,
	HISI_PTT_8DW_HEAD1,
	HISI_PTT_8DW_HEAD2,
	HISI_PTT_8DW_HEAD3,
	HISI_PTT_8DW_RSV1,
	HISI_PTT_8DW_TIME,
	HISI_PTT_8DW_TYPE_MAX
};

enum hisi_ptt_4dw_pkt_field_type {
	HISI_PTT_4DW_HEAD0,
	HISI_PTT_4DW_HEAD1,
	HISI_PTT_4DW_HEAD2,
	HISI_PTT_4DW_HEAD3,
	HISI_PTT_4DW_TYPE_MAX
};

static const char * const hisi_ptt_8dw_pkt_field_name[] = {
	[HISI_PTT_8DW_CHK_AND_RSV0]	= "CHK & RSV0",
	[HISI_PTT_8DW_PREFIX]		= "Prefix",
	[HISI_PTT_8DW_HEAD0]		= "Header DW0",
	[HISI_PTT_8DW_HEAD1]		= "Header DW1",
	[HISI_PTT_8DW_HEAD2]		= "Header DW2",
	[HISI_PTT_8DW_HEAD3]		= "Header DW3",
	[HISI_PTT_8DW_RSV1]		= "RSV1",
	[HISI_PTT_8DW_TIME]		= "Time"
};

static const char * const hisi_ptt_4dw_pkt_field_name[] = {
	[HISI_PTT_4DW_HEAD0]	= "Header DW0",
	[HISI_PTT_4DW_HEAD1]	= "Header DW1",
	[HISI_PTT_4DW_HEAD2]	= "Header DW2",
	[HISI_PTT_4DW_HEAD3]	= "Header DW3",
};

/* TLP message parsers below according to PCIe r6.4 sec 2.2.1.1 & 2.2.1.2 */
static bool hisi_ptt_is_mrd_tlp(uint32_t format, uint32_t type)
{
	return (format == 0 || format == 0x1) && (type == 0);
}

static bool hisi_ptt_is_mwr_tlp(uint32_t format, uint32_t type)
{
	return (format == 0x2 || format == 0x3) && (type == 0);
}

static bool hisi_ptt_is_dmwr_tlp(uint32_t format, uint32_t type)
{
	return (format == 0x2 || format == 0x3) && (type == 0x1b);
}

static bool hisi_ptt_is_msg_tlp(uint32_t format, uint32_t type)
{
	return (format == 0x1 || format == 0x3) && ((type & 0x18) == 0x10);
}

static bool hisi_ptt_is_io_tlp(uint32_t format, uint32_t type)
{
	return (format == 0 || format == 0x2) && (type == 0x2);
}

static bool hisi_ptt_is_atomic_tlp(uint32_t format, uint32_t type)
{
	return (format == 0x2 || format == 0x3) &&
	       (type == 0xc || type == 0xd || type == 0xe);
}

static bool hisi_ptt_is_cfg_tlp(uint32_t format, uint32_t type)
{
	return (format == 0 || format == 0x2) && (type == 0x4 || type == 0x5);
}

static bool hisi_ptt_is_cpl_tlp(uint32_t format, uint32_t type)
{
	return (format == 0  || format == 0x2) && (type == 0xa || type == 0xb);
}

static int hisi_ptt_parse_pkt_msg_type(uint32_t format, uint32_t type)
{
	if (hisi_ptt_is_mrd_tlp(format, type))
		return HISI_PTT_PKT_TYPE_MRD;
	else if (hisi_ptt_is_mwr_tlp(format, type))
		return HISI_PTT_PKT_TYPE_MWR;
	else if (hisi_ptt_is_dmwr_tlp(format, type))
		return HISI_PTT_PKT_TYPE_DMWR;
	else if (hisi_ptt_is_msg_tlp(format, type))
		return HISI_PTT_PKT_TYPE_MSG;
	else if (hisi_ptt_is_atomic_tlp(format, type))
		return HISI_PTT_PKT_TYPE_ATOM;
	else if (hisi_ptt_is_io_tlp(format, type))
		return HISI_PTT_PKT_TYPE_IO;
	else if (hisi_ptt_is_cfg_tlp(format, type))
		return HISI_PTT_PKT_TYPE_CFG;
	else if (hisi_ptt_is_cpl_tlp(format, type))
		return HISI_PTT_PKT_TYPE_CPL;

	return HISI_PTT_PKT_TYPE_UNKNOWN;
}

static int hisi_ptt_parse_pkt_header_proto_len(uint32_t format)
{
	if (format & 0x1)
		return HISI_PTT_4DW_HEADER_PROTO_LEN;

	return HISI_PTT_3DW_HEADER_PROTO_LEN;
}

static void hisi_ptt_parse_pkt_info(struct hisi_ptt_pkt_buf *pkt_buf,
				    uint32_t dw)
{
	uint32_t format, type;

	format = (pkt_buf->pkt_type == HISI_PTT_4DW_PKT) ?
		  FIELD_GET(HISI_PTT_HEAD0_4DW_FORMAT, dw) :
		  FIELD_GET(HISI_PTT_HEAD0_8DW_FORMAT, dw);
	type = (pkt_buf->pkt_type == HISI_PTT_4DW_PKT) ?
		FIELD_GET(HISI_PTT_HEAD0_4DW_TYPE, dw) :
		FIELD_GET(HISI_PTT_HEAD0_8DW_TYPE, dw);

	pkt_buf->pkt_msg_type = hisi_ptt_parse_pkt_msg_type(format, type);
	pkt_buf->proto_len = hisi_ptt_parse_pkt_header_proto_len(format);
}

static void hisi_ptt_print_raw_record(size_t offset, uint32_t value)
{
	const char *color = PERF_COLOR_BLUE;
	uint8_t byte;
	int i;

	printf(".");
	color_fprintf(stdout, color, "  %08zx: ", offset);
	for (i = 0; i < HISI_PTT_FIELD_LENGTH; i++) {
		byte = (value >> (24 - i * 8)) & 0xFF;
		color_fprintf(stdout, color, "%02x ", byte);
	}
	for (i = 0; i < HISI_PTT_MAX_SPACE_LEN; i++)
		color_fprintf(stdout, color, "   ");
}

static void hisi_ptt_print_pkt(struct hisi_ptt_pkt_buf *pkt_buf,
			       const char *desc)
{
	const char *color = PERF_COLOR_BLUE;
	uint32_t value;

	value = get_unaligned_le32(pkt_buf->buf + pkt_buf->pos);
	hisi_ptt_print_raw_record(pkt_buf->pos, value);

	color_fprintf(stdout, color, "  %s\n", desc);
	pkt_buf->pos += HISI_PTT_FIELD_LENGTH;
}

static void hisi_ptt_print_head0(struct hisi_ptt_pkt_buf *pkt_buf)
{
	const char *color = PERF_COLOR_BLUE;
	uint32_t dw;

	dw = get_unaligned_le32(pkt_buf->buf + pkt_buf->pos);
	hisi_ptt_parse_pkt_info(pkt_buf, dw);
	hisi_ptt_print_raw_record(pkt_buf->pos, dw);

	if (pkt_buf->pkt_type == HISI_PTT_4DW_PKT)
		color_fprintf(stdout, color,
			      "  %s %x %s %x %s %x %s %x %s %x %s %x %s %x %s %x\n",
			      "Format",
			      FIELD_GET(HISI_PTT_HEAD0_4DW_FORMAT, dw),
			      "Type", FIELD_GET(HISI_PTT_HEAD0_4DW_TYPE, dw),
			      "T9", FIELD_GET(HISI_PTT_HEAD0_4DW_T9, dw),
			      "T8", FIELD_GET(HISI_PTT_HEAD0_4DW_T8, dw),
			      "TH", FIELD_GET(HISI_PTT_HEAD0_4DW_TH, dw),
			      "SO", FIELD_GET(HISI_PTT_HEAD0_4DW_SO, dw),
			      "Length", FIELD_GET(HISI_PTT_HEAD0_4DW_LEN, dw),
			      "Time", FIELD_GET(HISI_PTT_HEAD0_4DW_TIME, dw));
	else
		color_fprintf(stdout, color, "  %s\n",
			      hisi_ptt_8dw_pkt_field_name[HISI_PTT_8DW_HEAD0]);

	pkt_buf->pos += HISI_PTT_FIELD_LENGTH;
}

static int hisi_ptt_8dw_pkt_desc(struct hisi_ptt_pkt_buf *pkt_buf)
{
	int i;

	for (i = HISI_PTT_8DW_CHK_AND_RSV0; i < HISI_PTT_8DW_TYPE_MAX; i++) {
		/* Do not show 8DW check field and reserved fields */
		if (i == HISI_PTT_8DW_CHK_AND_RSV0 || i == HISI_PTT_8DW_RSV1) {
			pkt_buf->pos += HISI_PTT_FIELD_LENGTH;
			continue;
		}

		if (i == HISI_PTT_8DW_HEAD0) {
			hisi_ptt_print_head0(pkt_buf);
			continue;
		}

		hisi_ptt_print_pkt(pkt_buf, hisi_ptt_8dw_pkt_field_name[i]);
	}

	return hisi_ptt_pkt_size[HISI_PTT_8DW_PKT];
}

static int hisi_ptt_4dw_pkt_desc(struct hisi_ptt_pkt_buf *pkt_buf)
{
	int i;

	hisi_ptt_print_head0(pkt_buf);

	for (i = HISI_PTT_4DW_HEAD1; i < HISI_PTT_4DW_TYPE_MAX; i++)
		hisi_ptt_print_pkt(pkt_buf, hisi_ptt_4dw_pkt_field_name[i]);

	return hisi_ptt_pkt_size[HISI_PTT_4DW_PKT];
}

int hisi_ptt_pkt_desc(struct hisi_ptt_pkt_buf *pkt_buf)
{
	if (pkt_buf->pkt_type == HISI_PTT_8DW_PKT)
		return hisi_ptt_8dw_pkt_desc(pkt_buf);

	return hisi_ptt_4dw_pkt_desc(pkt_buf);
}
