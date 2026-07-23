/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _EN_1588_PKT_PROC_H_
#define _EN_1588_PKT_PROC_H_

#include "en_1588_pkt_proc_func.h"

#define PTP_SUCCESS 0
#define PTP_FAILED (-1)
#define IS_NOT_PTP_MSG 1
#define IS_NOT_STATISTICS_PKT 1
#define DELAY_STATISTICS_FAILED (-1)

s32 pkt_1588_proc_xmit(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, s32 clock_no,
		       struct zxdh_en_device *en_dev, u8 *ptpHdr);
s32 pkt_1588_proc_rcv(struct sk_buff *skb, struct zxdh_1588_pd_rx *hdr, s32 clock_no,
		      struct zxdh_en_device *en_dev);
s32 pi_1588_net_hdr_add(struct sk_buff *skb, struct zxdh_net_hdr_tx *hdr, s32 clock_no,
			struct zxdh_en_device *en_dev);
s32 pkt_delay_statistics_proc(struct sk_buff *skb, struct zxdh_net_hdr_tx *hdr,
			      struct zxdh_en_device *en_dev);
s32 get_hdr_point(u8 *pData, u8 *piTs0ffset, u8 **ptpHdr);

#ifdef PTP_DRIVER_INTERFACE_EN
int get_hw_timestamp(struct zxdh_en_device *en_dev, u32 *hwts);
#endif

#endif /* _EN_1588_PKT_PROC_H_ */
