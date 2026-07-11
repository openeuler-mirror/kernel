// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*****************************************************************************
 * (C) 2023 ZTE Corporation. .
 * : en_1588_pkt_proc.c
 * : PTP
 * /   : Limin / 2023.10.12
 * : 1.0
 *****************************************************************************
 */

#include "en_1588_pkt_proc.h"
#include "en_aux_ioctl.h"
#include "queue.h"
#include "../en_ethtool/ethtool.h"

#define PTP_MESSAGE_HRD_LEN 34
#define IPV6_HDR_LEN 40
#define IPV6_PROT_OFFSET 6
#define UDP_DEST_PORT_OFFSET 2
#define VLAN_TPID 0x8100
#define UDP_PRORT_EVENT_1588 319
#define UDP_PRORT_GENERAL_1588 320

#define PTP_EVENT_TYPE_NOSECURITY 2
#define PTP_EVENT_TYPE_SECURITY 3
#define PTP_GENERAL_TYPE 0
#define PTP_TYPE_OFFSET 4

#define PTP_L4_NEED_QUERY_IPSEC_TABLE 1
#define PTP_TYPE_L4_SECURITY_OFFSET 3

#define ETH_TYPE_PTP 0x88f7
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86dd

#define ETH_TYPE_UDP 0x11
#define ETH_TYPE_TCP 0x06

#define UDP_HDR_LEN 0x08
#define TCP_HDR_LEN 0x14

#define ETHER_TYPE_LEN 2
#define ETHER_MAC_LEN 6
#define L2_PKT_HDR_LEN ((2 * ETHER_MAC_LEN) + ETHER_TYPE_LEN)

#define IP_PROT_OFFSET 9

#define PTP_MSG_ERROR_TYPE 0xff
#define PTPHDR_CF_OFFSET 8

#define VLAN_LEN 4

struct MsgProc_t {
	u8 type;
	s32 (*proc_func)(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			 struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			 struct zxdh_en_device *en_dev);
};

struct MsgRcv_t {
	u8 type;
	s32 (*proc_func)(struct zxdh_1588_pd_rx *hdr, u8 *ptpHdr, struct time_stamps *t5g,
			 struct time_stamps *tsn, u32 *thw, struct skb_shared_info *ptSkbSharedInfo,
			 struct zxdh_en_device *en_dev);
};

struct MsgProc_t g_MsgProcTable[] = { { PTP_MSG_TYPE_SYNC, pkt_proc_type_sync },
				      { PTP_MSG_TYPE_DELAY_REQ, pkt_proc_type_delay_req },
				      { PTP_MSG_TYPE_PDELAY_REQ, pkt_proc_type_pdelay_req },
				      { PTP_MSG_TYPE_PDELAY_RESP, pkt_proc_type_pdelay_resp },

				      { PTP_MSG_TYPE_FOLLOW_UP, pkt_proc_type_follow_up },
				      { PTP_MSG_TYPE_DELAY_RESP, pkt_proc_type_delay_resp },
				      { PTP_MSG_TYPE_PDELAY_RESP_FOLLOW_UP,
					pkt_proc_type_pdelay_resp_follow_up },
				      { PTP_MSG_TYPE_ANNOUNCE, pkt_proc_type_announce },
				      { PTP_MSG_TYPE_SIGNALING, pkt_proc_type_signaling },
				      { PTP_MSG_TYPE_MANAGEMENT, pkt_proc_type_management },

				      { PTP_MSG_ERROR_TYPE, NULL } };

struct MsgRcv_t g_MsgRcvTable[] = { { PTP_MSG_TYPE_SYNC, pkt_rcv_type_event },
				    { PTP_MSG_TYPE_DELAY_REQ, pkt_rcv_type_event },
				    { PTP_MSG_TYPE_PDELAY_REQ, pkt_rcv_type_event },
				    { PTP_MSG_TYPE_PDELAY_RESP, pkt_rcv_type_event },

				    { PTP_MSG_TYPE_DELAY_RESP, pkt_rcv_type_delay_resp },

				    { PTP_MSG_ERROR_TYPE, NULL } };

bool is_event_message(const u8 msg_type)
{
	if (msg_type <= PTP_MSG_TYPE_PDELAY_RESP)
		return true;
	return false;
}

bool is_general_message(const u8 msg_type)
{
	if ((msg_type >= PTP_MSG_TYPE_FOLLOW_UP) && (msg_type <= PTP_MSG_TYPE_MANAGEMENT))
		return true;

	return false;
}

int process_extension_header(const u8 **ptr, u16 *remaining_len, u8 header_type)
{
	u16 ext_len = 0;

	if (*remaining_len == 0) {
		DEBUG_1588("Remaining length is 0, can't process extension header.\n");
		return 0;
	}

	ext_len = (u16)((*(*ptr)) + 1) * 8;
	DEBUG_1588("Extension header type: %d, declared length: %hu bytes\n", header_type, ext_len);
	if (ext_len > (*remaining_len + 1)) {
		DEBUG_1588(
			"Extension header length exceeds remaining length, can't process completely.\n");
		return 0;
	}

	*ptr = *ptr + (ext_len - 1);
	*remaining_len = *remaining_len - (ext_len - 1);
	DEBUG_1588(
		"Successfully processed extension header, new pointer position and remaining length updated.\n");
	return 1;
}

int is_fragmented_ipv6(struct ipv6hdr *ipv6h)
{
	u8 next_header_type = 0;
	const u8 *ptr = NULL;
	u16 remaining_len = 0;
	u16 payload_len = ntohs(ipv6h->payload_len);

	next_header_type = ipv6h->nexthdr;
	if (next_header_type == 44) {
		DEBUG_1588(
			"Encountered fragmentation-related next header in IPv6 header, packet is fragmented.\n");
		return 1;
	}

	ptr = (const u8 *)ipv6h + sizeof(struct ipv6hdr);
	remaining_len = payload_len;

	while (remaining_len > 0) {
		next_header_type = *ptr;
		ptr++;
		remaining_len--;
		DEBUG_1588(
			"Starting to process extension headers, initial remaining length: %hu bytes\n",
			remaining_len);
		DEBUG_1588("Processing extension header of type: %d\n", next_header_type);

		switch (next_header_type) {
		case 0:
		case 60:
		case 43:
			if (!process_extension_header(&ptr, &remaining_len, next_header_type))
				return 1;
			break;
		case 44:
			DEBUG_1588(
				"Encountered fragmentation-related extension header, packet is fragmented.\n");
			return 1;
		default:
			return 0;
		}
	}

	return 0;
}

bool is_fragmented_ipv4(struct iphdr *ipv4h)
{
	u16 mf_flag = 0;
	u16 flags_fragment_offset = 0;

	flags_fragment_offset = ntohs(ipv4h->frag_off);

	DEBUG_1588("frag_off:%hu\n", flags_fragment_offset);

	mf_flag = (flags_fragment_offset >> 13) & 0x01;
	DEBUG_1588("mf_flag:%hu\n", mf_flag);
	if (mf_flag != 0)
		return true;

	flags_fragment_offset = flags_fragment_offset & 0x1FFF;
	DEBUG_1588("flags_fragment_offset:%hu\n", flags_fragment_offset);
	if (flags_fragment_offset != 0)
		return true;
	return false;
}

s32 get_hdr_point(u8 *pData, u8 *piTs0ffset, u8 **ptpHdr)
{
	u16 udp_dest_port_ptp = 0;
	u16 offset = 0;
	u16 temp_len = 0;
	u16 eth_type_lay3 = ntohs(*((u16 *)(pData + (2 * ETHER_MAC_LEN)))); /* get Eth Type */
	u8 eth_type_lay4 = 0;
	u8 eth_type_lay4_ipv6 = 0;
	u16 eth_type_vlan_lay3 = ntohs(*((u16 *)(pData + (2 * ETHER_MAC_LEN) + VLAN_LEN)));
	struct iphdr *ipv4h = NULL;
	struct ipv6hdr *ipv6h = NULL;

	offset = L2_PKT_HDR_LEN;

	if ((eth_type_lay3 == VLAN_TPID) && (eth_type_vlan_lay3 != VLAN_TPID))
		offset += VLAN_LEN;
	else if ((eth_type_lay3 == VLAN_TPID) && (eth_type_vlan_lay3 == VLAN_TPID))
		offset += (VLAN_LEN * 2);

	eth_type_lay3 = ntohs(*((u16 *)(pData + offset - ETHER_TYPE_LEN)));
	eth_type_lay4 = *(pData + offset + IP_PROT_OFFSET);

	eth_type_lay4_ipv6 = *(pData + offset + IPV6_PROT_OFFSET);

	if ((eth_type_lay3 != ETH_TYPE_PTP) && (eth_type_lay3 != ETH_TYPE_IPV4) &&
	    (eth_type_lay3 != ETH_TYPE_IPV6)) {
		DEBUG_1588("unknown L3 eth type: %d\n", eth_type_lay3);
		return IS_NOT_PTP_MSG;
	}

	if (eth_type_lay3 == ETH_TYPE_IPV4) {
		ipv4h = (struct iphdr *)(pData + offset);
		if (is_fragmented_ipv4(ipv4h)) {
			DEBUG_1588("is fragmented ipv4!!\n");
			return IS_NOT_PTP_MSG;
		}

		temp_len = *(pData + offset);
		temp_len = (temp_len & 0x0f) * 4;
		offset += temp_len;

		if (eth_type_lay4 == ETH_TYPE_UDP) {
			udp_dest_port_ptp = ntohs(*(u16 *)(pData + offset + UDP_DEST_PORT_OFFSET));
			if ((udp_dest_port_ptp != UDP_PRORT_EVENT_1588) &&
			    (udp_dest_port_ptp != UDP_PRORT_GENERAL_1588)) {
				DEBUG_1588("UDP destination port(%hd) is not 319 or 320!!\n",
					   udp_dest_port_ptp);
				return IS_NOT_PTP_MSG;
			}
			temp_len = UDP_HDR_LEN;
			offset += temp_len;
		} else {
			DEBUG_1588("eth_type_lay4 = %hhu, is not UDP!!!!!\n", eth_type_lay4);
			return IS_NOT_PTP_MSG;
		}
	} else if (eth_type_lay3 == ETH_TYPE_IPV6) {
		ipv6h = (struct ipv6hdr *)(pData + offset);
		if (is_fragmented_ipv6(ipv6h)) {
			DEBUG_1588("is fragmented ipv6!!\n");
			return IS_NOT_PTP_MSG;
		}

		temp_len = IPV6_HDR_LEN;
		offset += temp_len;

		if (eth_type_lay4_ipv6 == ETH_TYPE_UDP) {
			udp_dest_port_ptp = ntohs(*(u16 *)(pData + offset + UDP_DEST_PORT_OFFSET));
			if ((udp_dest_port_ptp != UDP_PRORT_EVENT_1588) &&
			    (udp_dest_port_ptp != UDP_PRORT_GENERAL_1588)) {
				DEBUG_1588("UDP destination port(%hd) is not 319 or 320!!\n",
					   udp_dest_port_ptp);
				return IS_NOT_PTP_MSG;
			}
			temp_len = UDP_HDR_LEN;
			offset += temp_len;
		} else {
			DEBUG_1588("eth_type_lay4_ipv6 = %hhu, is not UDP!!!!!!\n",
				   eth_type_lay4_ipv6);
			return IS_NOT_PTP_MSG;
		}
	}

	*ptpHdr = pData + offset;

	*piTs0ffset = offset;

	return PTP_SUCCESS;
}

u8 get_msgtype_from_hrd(u8 *hrd, const u8 len)
{
	u8 msg_type = PTP_MSG_ERROR_TYPE;

	CHECK_UNEQUAL_ERR(len, PTP_MESSAGE_HRD_LEN, -EFAULT, "error len %d!", len);

	msg_type = hrd[0] & 0x0f;
	if (is_event_message(msg_type) || is_general_message(msg_type))
		return msg_type;

	DEBUG_1588("error message type %d", msg_type);
	return PTP_MSG_ERROR_TYPE;
}

#ifdef PTP_DRIVER_INTERFACE_EN
extern int get_pkt_timestamp(s32 clock_no, struct zxdh_en_device *en_dev, struct time_stamps *ts,
			     u32 *hwts);
#endif /* PTP_DRIVER_INTERFACE_EN */

s32 get_tstamps_from_ptp(s32 clock_no, struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			 struct zxdh_en_device *en_dev)
{
	u32 hwts = 0;
	struct time_stamps ts[2] = { 0 };

#ifdef PTP_DRIVER_INTERFACE_EN
	s32 ret = 0;

	ret = get_pkt_timestamp(clock_no, en_dev, ts, &hwts);
	if (unlikely(ret != 0)) {
		LOG_ERR("netdev %s get tsn clock %d failed!, ret = %d", en_dev->netdev->name,
			clock_no, ret);
		return -1;
	}
#endif /* PTP_DRIVER_INTERFACE_EN */

	LOG_DEBUG("===GET-PTP===: hwts=%u", hwts);
	LOG_DEBUG("===GET-PTP===: ts[0].s=%llu, ts[0].ns=%u", ts[0].s, ts[0].ns);
	LOG_DEBUG("===GET-PTP===: ts[1].s=%llu, ts[1].ns=%u", ts[1].s, ts[1].ns);

	*t5g = ts[1];
	*tsn = ts[1];
	*thw = hwts;

	return 0;
}

s32 pkt_1588_proc_xmit(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, s32 clock_no,
		       struct zxdh_en_device *en_dev, u8 *ptpHdr)
{
	struct time_stamps ts_5g;
	struct time_stamps ts_tsn;
	u32 ts_thw = 0;
	u8 ret = 0;
	u8 i = 0;
	u8 cnt = 0;
	u8 msg_type = 0xff;
	struct ptpHdr_t *ptPtpHdr = NULL;

	memset(&ts_5g, 0, sizeof(struct time_stamps));
	memset(&ts_tsn, 0, sizeof(struct time_stamps));

	CHECK_EQUAL_ERR(skb, NULL, -EADDRNOTAVAIL, "skb is NULL!\n");
	CHECK_EQUAL_ERR(hdr, NULL, -EADDRNOTAVAIL, "hdr is NULL!\n");

	ptPtpHdr = (struct ptpHdr_t *)ptpHdr;

	msg_type = get_msgtype_from_hrd(ptpHdr, PTP_MESSAGE_HRD_LEN);
	if (msg_type == PTP_MSG_ERROR_TYPE) {
		DEBUG_1588("unknown PTP msg type!\n");
		return -EFAULT;
	}

	LOG_DEBUG("%s msg_type %d\n", __func__, msg_type);

	if (is_event_message(msg_type)) {
		ret = get_tstamps_from_ptp(clock_no, &ts_5g, &ts_tsn, &ts_thw, en_dev);
		CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "get tstamps from ptp failed!\n");

		hdr->ptp_type[2] =
			(hdr->ptp_type[2] & 0x8F) + (PTP_EVENT_TYPE_NOSECURITY << PTP_TYPE_OFFSET);
		if (0 != ((ptPtpHdr->flagField) & 0x0080)) {
			hdr->ptp_type[2] = (hdr->ptp_type[2] & 0x8F) +
					   (PTP_EVENT_TYPE_SECURITY << PTP_TYPE_OFFSET);
		}
	} else {
		hdr->ptp_type[2] =
			(hdr->ptp_type[2] & 0x8F) + (PTP_GENERAL_TYPE << PTP_TYPE_OFFSET);
	}

	if (0 != ((ptPtpHdr->flagField) & 0x0080)) {
		hdr->ptp_type[2] = (hdr->ptp_type[2] & 0xF7) +
				   (PTP_L4_NEED_QUERY_IPSEC_TABLE << PTP_TYPE_L4_SECURITY_OFFSET);
	}

	hdr->port = en_dev->phy_port;

	cnt = sizeof(g_MsgProcTable) / sizeof(struct MsgProc_t);
	for (i = 0; i < cnt; i++) {
		if (g_MsgProcTable[i].type == msg_type) {
			if (likely(g_MsgProcTable[i].proc_func)) {
				ret = g_MsgProcTable[i].proc_func(skb, hdr, ptpHdr, &ts_5g, &ts_tsn,
								  &ts_thw, en_dev);
			}
		}
	}

	return ret;
}

s32 pkt_1588_proc_rcv(struct sk_buff *skb, struct zxdh_1588_pd_rx *hdr, s32 clock_no,
		      struct zxdh_en_device *en_dev)
{
	struct time_stamps ts_5g;
	struct time_stamps ts_tsn;
	u32 ts_thw = 0;
	u8 *pData = NULL;
	u8 *ptpHdr = NULL;
	s32 ret = 0;
	u8 i = 0;
	u8 cnt = 0;
	u8 msg_type = 0xff;
	u8 piTsOffset = 0;

	memset(&ts_5g, 0, sizeof(struct time_stamps));
	memset(&ts_tsn, 0, sizeof(struct time_stamps));

	CHECK_EQUAL_ERR(skb, NULL, -EADDRNOTAVAIL, "skb is NULL!\n");
	CHECK_EQUAL_ERR(hdr, NULL, -EADDRNOTAVAIL, "hdr is NULL!\n");

	pData = skb->data;

	ret = get_hdr_point(pData, &piTsOffset, &ptpHdr);
	CHECK_EQUAL_ERR(ptpHdr, NULL, -EADDRNOTAVAIL, "get ptp hdr failed!\n");
	if (ret != 0) {
		DEBUG_1588("is not ptp msg or get hdr err!!\n");
		return -EFAULT;
	}

	msg_type = get_msgtype_from_hrd(ptpHdr, PTP_MESSAGE_HRD_LEN);
	if (msg_type == PTP_MSG_ERROR_TYPE) {
		DEBUG_1588("unknown PTP msg type!\n");
		return -EFAULT;
	}

	if (is_event_message(msg_type)) {
		ret = get_tstamps_from_ptp(clock_no, &ts_5g, &ts_tsn, &ts_thw, en_dev);
		CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "get tstamps from ptp failed!\n");
	}

	cnt = sizeof(g_MsgRcvTable) / sizeof(struct MsgRcv_t);
	for (i = 0; i < cnt; i++) {
		if (g_MsgRcvTable[i].type == msg_type) {
			if (likely(g_MsgRcvTable[i].proc_func)) {
				ret = g_MsgRcvTable[i].proc_func(hdr, ptpHdr, &ts_5g, &ts_tsn,
								 &ts_thw, skb_shinfo(skb), en_dev);
			}
		}
	}

	return ret;
}

s32 is_delay_statistics_pkt(u8 *pData)
{
	u16 udp_dest_port = 0;
	u16 offset = 0;
	u16 temp_len = 0;
	u16 eth_type_lay3 = ntohs(*((u16 *)(pData + (2 * ETHER_MAC_LEN)))); /* get Eth Type */
	u8 eth_type_lay4 = 0;
	u8 eth_type_lay4_ipv6 = 0;
	u16 eth_type_vlan_lay3 = ntohs(*((u16 *)(pData + (2 * ETHER_MAC_LEN) + VLAN_LEN)));

	offset = L2_PKT_HDR_LEN;

	if ((eth_type_lay3 == VLAN_TPID) && (eth_type_vlan_lay3 != VLAN_TPID))
		offset += VLAN_LEN;
	else if ((eth_type_lay3 == VLAN_TPID) && (eth_type_vlan_lay3 == VLAN_TPID))
		offset += (VLAN_LEN * 2);

	eth_type_lay3 = ntohs(*((u16 *)(pData + offset - ETHER_TYPE_LEN)));
	eth_type_lay4 = *(pData + offset + IP_PROT_OFFSET);

	eth_type_lay4_ipv6 = *(pData + offset + IPV6_PROT_OFFSET);

	if (eth_type_lay3 != ETH_TYPE_IPV4) {
		// LOG_ERR("unknown L4 eth type: %d\n", eth_type_lay3);
		return IS_NOT_STATISTICS_PKT;
	}

	if (eth_type_lay3 == ETH_TYPE_IPV4) {
		temp_len = *(pData + offset);
		temp_len = (temp_len & 0x0f) * 4;
		offset += temp_len;

		if (eth_type_lay4 == ETH_TYPE_UDP) {
			udp_dest_port = ntohs(*(u16 *)(pData + offset + UDP_DEST_PORT_OFFSET));
			if (udp_dest_port != 49184)
				return IS_NOT_STATISTICS_PKT;
		} else {
			return IS_NOT_STATISTICS_PKT;
		}
	}

	return PTP_SUCCESS;
}

s32 pkt_delay_statistics_proc(struct sk_buff *skb, struct zxdh_net_hdr_tx *hdr,
			      struct zxdh_en_device *en_dev)
{
	u8 *pData = NULL;
	u8 ret = 0;
	u32 ts_thw = 0;

	CHECK_EQUAL_ERR(skb, NULL, -EADDRNOTAVAIL, "skb is NULL!\n");
	CHECK_EQUAL_ERR(hdr, NULL, -EADDRNOTAVAIL, "hdr is NULL!\n");

	pData = skb->data;

	if (is_delay_statistics_pkt(pData) == IS_NOT_STATISTICS_PKT)
		return DELAY_STATISTICS_FAILED;

	if (en_dev->dtp_drs_offload == true)
		hdr->pipd_hdr.pd_hdr.ol_flag |= htons(DELAY_STATISTICS_INSERT_EN_BIT);
	else
		hdr->pd_hdr.ol_flag |= htons(DELAY_STATISTICS_INSERT_EN_BIT);

#ifdef PTP_DRIVER_INTERFACE_EN
	ret = get_hw_timestamp(en_dev, &ts_thw);
	CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "get_hw_timestamp failed!\n");
#endif

	*(u32 *)(&(hdr->pd_hdr.tag_idx)) = htonl(ts_thw << CPU_TX_DECIMAL_NS);

	return ret;
}
