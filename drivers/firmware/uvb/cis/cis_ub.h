/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: cis ub header
 * Create: 2025-12-18
 */

#ifndef CIS_UB_H
#define CIS_UB_H

#include <ub/ubase/ubase_comm_cmd.h>

#define seid_high(eid) (((eid) >> 12) & 0xff)
#define seid_low(eid) ((eid) & 0xfff)
#define eid_gen(eid_h, eid_l) ((eid_h) << 12 | (eid_l))

struct payload {
#define UB_PAYLOAD_TYPE 0x1
	u32 type : 4;
#define UB_PAYLOAD_VERSION 0x1
	u32 version : 4;
	u32 rsvd : 8;
	u32 index : 16;
	u32 message_id;
	u32 sender_id;
	u32 receiver_id;
	union {
		u32 output_buffer_size;
		u32 returned_status;
	};
	u32 data_total_size;
	DECLARE_FLEX_ARRAY(char, data);
};

struct base_header {
	/* DW0 */
	u32 ini_tassn : 16;
	u32 udf_flag : 1;
	u32 rsvd2 : 1;
	u32 poison : 1;
	u32 tk_en : 1;
	u32 ee : 2;
	u32 taver : 2;
#define TAH_OPCODE_MSG 0x10
	u32 ta_opcode : 8;
	/* DW1 */
	u32 ini_rc_id : 20;
	u32 ini_rc_type : 2;
	u32 excl : 1;
	u32 rsvd3 : 1;
	u32 atloc : 1;
	u32 retry : 1;
	u32 se : 1;
	u32 tc_en : 1;
	u32 tak_en : 1;
	u32 odr : 3;
};

struct msg_extended_header {
	u32 plen : 12;
	u32 rsvd : 4;
	u32 rsp_status : 8;
	u32 rsp : 1;
#define UB_MSG_CODE 0x3
	u32 msg_code : 3;
#define UB_SUB_MSG_CODE 0x1
	u32 sub_msg_code : 4;
};

struct compact_network_header {
	/* DW0 */
	u32 dcna : 16;
	u32 scna : 16;
	/* DW1 */
#define NTH_NLP_WITH_TPH 0
#define NTH_NLP_WITHOUT_TPH 1
	u32 nth_nlp : 3;
#define NTH_NLP_WITH_MGMT 0
	u32 mm : 1;
	u32 sl : 4;
	u32 lb : 8;
	u32 cci : 16;
};

struct ub_link_header {
	u32 plen : 14;
	u32 rt : 2;
	u32 cfg : 4;
	u32 rsvd0 : 1;
	u32 vl : 4;
	u32 rsvd1 : 1;
	u32 crd_vl : 4;
	u32 ack : 1;
	u32 crd : 1;
};

#define UB_COMPACT_LINK_CFG 6

struct msg_pkt_header {
	/* DW0 */
	struct ub_link_header ulh;
	/* DW1~DW2 */
struct compact_network_header nth;
	/* DW3 */
	u32 seid_h : 8;
	u32 upi : 16;
#define CTPH_NLP_UPI_40BITS_UEID 2
	u32 ctph_nlp : 4;
	u32 pad : 2;
#define CTPH_OPCODE_NOT_CNP 0
	u32 tp_opcode : 2;
	/* DW4 */
	u32 deid : 20;
	u32 seid_l : 12;
	/* DW5~DW6 */
	struct base_header btah;
	/* DW7 */
	struct msg_extended_header msgetah;

	/* DW8~DW15 */
	struct payload pload;
};

int uvb_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id);
void uvb_remove(struct auxiliary_device *aux_dev);
struct udfi_para;
int cis_call_ub(struct udfi_para *para);
int cis_ext_table_add_from_ub(void *data, u32 data_size, u32 sender_id);

/* Framing support: cmdQ max payload is 1016B, each frame's usable data
 * is max payload minus msg_pkt_header size.
 * IMP returns data_total_size as the total data length; if it exceeds
 * one frame, UVB driver fetches remaining frames by setting index field.
 */
#define UB_FRAME_MAX_DATA    (UBASE_CMDQ_MAX_DATA_SIZE - sizeof(struct msg_pkt_header))

#endif
