/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _EN_1588_PKT_PROC_FUNC_H_
#define _EN_1588_PKT_PROC_FUNC_H_

#include "../en_aux.h"
#include "queue.h"

#define PTP_REG_INFO_NUM 32
#define MAX_PTP_REG_INFO_NUM 64

#define MSGTYPE_OFFSET 20
#define SRCPORTID_OFFSET 16

#define PTP_RET_SUCCESS 0
#define PTP_RET_TIME_ERR (-1)

#define CF_DECIMAL_NS_SIZE 2
#define CF_NS_SIZE 6
#define CF_SIZE 8

#define PTP_TS_5G_LEN 10
#define PTP_TS_TSN_LEN 10
#define PTP_REQRECE_TS_LEN 10

#define PTPHDR_FREQUENCY_OFFSET 54
#define PTPHDR_TSI_OFFSET 86
#define PTPHDR_TSI_TLV_OFFSET 76
#define PTPHDR_TSI_TLV_OFFSET_TWO 44
#define PTPHDR_TSI_TLV_LEN 20
#define ORIGINTIMESTAMP_LEN 10
#define FOLLOWUP_TLV_LEN 32
#define TSITLV_LEN 20
#define SRCPORTID_LEN 10

#define S_SIZE 6
#define NS_SIZE 4
#define S_HOLD 1000000000L

#define CPU_TX_DECIMAL_NS 3
#define CPU_TX_NS 29

struct Bits80_t {
	u8 data[S_SIZE + NS_SIZE];
};

struct time_stamps {
	u64 s;
	u32 ns;
};

struct SkbSharedHwtstamps_t {
	struct time_stamps ts_5g_t;
	struct time_stamps ts_tsn_t;
};

struct ptpHdr_t {
	u8 majorType;
	u8 versionPTP;
	u16 msglen;
	u8 domainNumber;
	u8 minorSdoId;
	u16 flagField;
	u8 correctionField[CF_SIZE];
	u32 msgTypeSpecific;
	u8 srcPortIdentity[SRCPORTID_LEN];
	u16 sequenceId;
	u8 controlField;
	u8 logMsgInterval;
} __packed;

struct ptp_reg_info {
	u32 cfVal[2];
	u32 matchInfo;
};

struct ptp_buff {
	u32 cfCount;
	struct ptp_reg_info ptpRegInfo[PTP_REG_INFO_NUM];
};

struct ptp_update_buff {
	u32 cfCount;
	struct ptp_reg_info ptpRegInfo[MAX_PTP_REG_INFO_NUM];
};

enum {
	/* event message types */
	PTP_MSG_TYPE_SYNC = 0,
	PTP_MSG_TYPE_DELAY_REQ,
	PTP_MSG_TYPE_PDELAY_REQ,
	PTP_MSG_TYPE_PDELAY_RESP,

	/* general message types */
	PTP_MSG_TYPE_FOLLOW_UP = 8,
	PTP_MSG_TYPE_DELAY_RESP,
	PTP_MSG_TYPE_PDELAY_RESP_FOLLOW_UP,
	PTP_MSG_TYPE_ANNOUNCE,
	PTP_MSG_TYPE_SIGNALING,
	PTP_MSG_TYPE_MANAGEMENT
};

u64 htonll(u64 u64_host);

s32 pkt_proc_type_sync(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
		       struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
		       struct zxdh_en_device *en_dev);

s32 pkt_proc_type_delay_req(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			    struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			    struct zxdh_en_device *en_dev);

s32 pkt_proc_type_pdelay_req(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			     struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			     struct zxdh_en_device *en_dev);

s32 pkt_proc_type_pdelay_resp(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			      struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			      struct zxdh_en_device *en_dev);

s32 pkt_proc_type_follow_up(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			    struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			    struct zxdh_en_device *en_dev);

s32 pkt_proc_type_delay_resp(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			     struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			     struct zxdh_en_device *en_dev);

s32 pkt_proc_type_pdelay_resp_follow_up(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr,
					u8 *ptpHdr, struct time_stamps *t5g,
					struct time_stamps *tsn, u32 *thw,
					struct zxdh_en_device *en_dev);

s32 pkt_proc_type_announce(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			   struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			   struct zxdh_en_device *en_dev);

s32 pkt_proc_type_signaling(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			    struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			    struct zxdh_en_device *en_dev);

s32 pkt_proc_type_management(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			     struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			     struct zxdh_en_device *en_dev);

s32 pkt_rcv_type_event(struct zxdh_1588_pd_rx *hdr, u8 *ptpHdr, struct time_stamps *t5g,
		       struct time_stamps *tsn, u32 *thw, struct skb_shared_info *ptSkbSharedInfo,
		       struct zxdh_en_device *en_dev);

s32 pkt_rcv_type_delay_resp(struct zxdh_1588_pd_rx *hdr, u8 *ptpHdr, struct time_stamps *t5g,
			    struct time_stamps *tsn, u32 *thw,
			    struct skb_shared_info *ptSkbSharedInfo, struct zxdh_en_device *en_dev);

#endif /* _EN_1588_PKT_PROC_FUNC_H_ */
