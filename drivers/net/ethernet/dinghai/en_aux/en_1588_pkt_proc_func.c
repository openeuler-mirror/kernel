// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*****************************************************************************
 * (C) 2023 ZTE Corporation. .
 * : en_1588_pkt_proc_func.c
 * :
 * /   : Limin / 2023.10.12
 * : 1.0
 *****************************************************************************
 */

#include "en_1588_pkt_proc_func.h"
#include "en_aux_cmd.h"
#include "en_aux_ioctl.h"

struct ptp_update_buff tGlobalPtpBuff = { 0 };

u64 htonll(u64 u64_host)
{
	u64 u64_net = 0;
	u32 u32_host_h = 0;
	u32 u32_host_l = 0;

	u32_host_l = u64_host & 0xffffffff;
	u32_host_h = (u64_host >> 32) & 0xffffffff;

	u64_net = htonl(u32_host_l);
	u64_net = (u64_net << 32) | htonl(u32_host_h);

	return u64_net;
}

s32 bits_80_minus(struct time_stamps subtraction, struct Bits80_t minuend,
		  struct time_stamps *ptMinusRet)
{
	u64 minusHigh48_s = 0;
	u32 minusLow32_ns = 0;

	memcpy((u8 *)(&minusHigh48_s), &minuend, S_SIZE);
	memcpy(&minusLow32_ns, (u8 *)(&minuend) + S_SIZE, NS_SIZE);

	minusHigh48_s = htonll(minusHigh48_s) >> 16;
	minusLow32_ns = htonl(minusLow32_ns);

	if ((subtraction.s < minusHigh48_s) ||
	    ((subtraction.s == minusHigh48_s) && (subtraction.ns < minusLow32_ns))) {
		LOG_ERR("The difference between the two times is negative！！");
		return PTP_RET_TIME_ERR;
	}

	if (subtraction.ns > minusLow32_ns) {
		ptMinusRet->ns = subtraction.ns - minusLow32_ns;
		ptMinusRet->s = subtraction.s - minusHigh48_s;
	} else {
		ptMinusRet->ns = S_HOLD - (minusLow32_ns - subtraction.ns);
		ptMinusRet->s = subtraction.s - minusHigh48_s - 1;
	}

	return PTP_RET_SUCCESS;
}

s32 pkt_proc_type_sync(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
		       struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
		       struct zxdh_en_device *en_dev)
{
	struct SkbSharedHwtstamps_t tShhwtstamps;
	struct time_stamps tMinusRet;
	struct skb_shared_hwtstamps tHwtstamps5g;
	struct skb_shared_hwtstamps tHwtstampsTsn;
	struct Bits80_t tTsi;
	struct ptpHdr_t *ptPtpHdr = NULL;
	u8 *pOriginTimeStamp = NULL;
	u8 majorSdoId = 0;
	u32 t5gNsBig = 0;
	u64 t5gSBig = 0;
	u32 tsnNsBig = 0;
	u64 tsnSBig = 0;
	u32 frequency = 0;
	u64 cfAddedVal = 0;
	u8 *tsiTlv = NULL;
	u32 cpuTx_ns = 0;
	u32 cpuTx_frac_ns = 0;
	u64 cfNs = 0;

	ptPtpHdr = (struct ptpHdr_t *)ptpHdr;
	majorSdoId = ((ptPtpHdr->majorType) & 0xf0) >> 4;
	pOriginTimeStamp = ptpHdr + sizeof(struct ptpHdr_t);
	t5gSBig = (htonll(t5g->s)) >> 16;
	t5gNsBig = htonl(t5g->ns);
	tsnSBig = (htonll(tsn->s)) >> 16;
	tsnNsBig = htonl(tsn->ns);

	memset(&tShhwtstamps, 0, sizeof(struct SkbSharedHwtstamps_t));
	memset(&tHwtstamps5g, 0, sizeof(struct skb_shared_hwtstamps));
	memset(&tHwtstampsTsn, 0, sizeof(struct skb_shared_hwtstamps));
	memset(&tMinusRet, 0, sizeof(struct time_stamps));
	memset(&tTsi, 0, sizeof(struct Bits80_t));

	if (majorSdoId == 0) {
		if (0 == ((ptPtpHdr->flagField) & 0x0002)) {
			memcpy(pOriginTimeStamp, &t5gSBig, S_SIZE);
			memcpy(pOriginTimeStamp + S_SIZE, &t5gNsBig, NS_SIZE);
		}
	} else if (majorSdoId == 1) {
		if (((ptPtpHdr->flagField) & 0x0002) == 0) {
			memcpy(pOriginTimeStamp, &tsnSBig, S_SIZE);
			memcpy(pOriginTimeStamp + S_SIZE, &tsnNsBig, NS_SIZE);

			if (((ptPtpHdr->flagField) & 0x8000) != 0) {
				frequency = *(u32 *)(ptpHdr + PTPHDR_FREQUENCY_OFFSET);
				frequency = htonl(frequency);

				memcpy(&tTsi, ptpHdr + PTPHDR_TSI_OFFSET, sizeof(struct Bits80_t));

				bits_80_minus(*t5g, tTsi, &tMinusRet);

				cfAddedVal = (tMinusRet.s * S_HOLD + tMinusRet.ns) * frequency;
				memcpy(&cfNs, ptPtpHdr->correctionField, CF_NS_SIZE);
				cfNs = htonll(cfNs) >> 16;
				cfNs += cfAddedVal;
				cfNs = htonll(cfNs) >> 16;
				memcpy(&(ptPtpHdr->correctionField[0]), &cfNs, CF_NS_SIZE);

				ptPtpHdr->flagField = (ptPtpHdr->flagField) & 0x7f;

				tsiTlv = ptpHdr + PTPHDR_TSI_TLV_OFFSET;
				memset(tsiTlv, 0, PTPHDR_TSI_TLV_LEN);

				ptPtpHdr->msglen = htons(ptPtpHdr->msglen);
				ptPtpHdr->msglen -= PTPHDR_TSI_TLV_LEN;
				ptPtpHdr->msglen = htons(ptPtpHdr->msglen);
			}
		} else {
			if (((ptPtpHdr->flagField) & 0x8000) != 0) {
				memcpy(&tTsi, ptpHdr + PTPHDR_TSI_OFFSET, sizeof(struct Bits80_t));

				bits_80_minus(*t5g, tTsi, &tMinusRet);

				frequency = htonl(ptPtpHdr->msgTypeSpecific);
				cfAddedVal = (tMinusRet.s * S_HOLD + tMinusRet.ns) * frequency;
				memcpy(&cfNs, ptPtpHdr->correctionField, CF_NS_SIZE);
				cfNs = htonll(cfNs) >> 16;
				cfNs += cfAddedVal;
				cfNs = htonll(cfNs) >> 16;
				memcpy(&(ptPtpHdr->correctionField[0]), &cfNs, CF_NS_SIZE);

				memset(&(ptPtpHdr->msgTypeSpecific), 0, sizeof(u32));

				ptPtpHdr->flagField = (ptPtpHdr->flagField) & 0x7f;

				tsiTlv = ptpHdr + PTPHDR_TSI_TLV_OFFSET_TWO;
				memset(tsiTlv, 0, PTPHDR_TSI_TLV_LEN);

				ptPtpHdr->msglen = htons(ptPtpHdr->msglen);
				ptPtpHdr->msglen -= PTPHDR_TSI_TLV_LEN;
				ptPtpHdr->msglen = htons(ptPtpHdr->msglen);
			}
		}
	}

	cpuTx_frac_ns = (hdr->cpu_tx) & 0x07;
	cpuTx_ns = *thw << CPU_TX_DECIMAL_NS;
	hdr->cpu_tx = htonl(cpuTx_ns + cpuTx_frac_ns);

	tShhwtstamps.ts_5g_t = *t5g;
	tShhwtstamps.ts_tsn_t = *tsn;
	tHwtstamps5g.hwtstamp = tShhwtstamps.ts_5g_t.ns + tShhwtstamps.ts_5g_t.s * S_HOLD;
	tHwtstampsTsn.hwtstamp = tShhwtstamps.ts_tsn_t.ns + tShhwtstamps.ts_tsn_t.s * S_HOLD;
	skb_tstamp_tx(skb, &tHwtstamps5g);
#ifdef CGEL_TSTAMP_2_PATCH_EN
	skb_tstamp_tx_2(skb, &tHwtstampsTsn);
#endif /* CGEL_TSTAMP_2_PATCH_EN */

	return PTP_RET_SUCCESS;
}

s32 delay_and_pdelay_req_proc(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr,
			      struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw)
{
	struct SkbSharedHwtstamps_t tShhwtstamps;
	struct skb_shared_hwtstamps tHwtstamps5g;
	struct skb_shared_hwtstamps tHwtstampsTsn;
	u32 cpuTx_ns = 0;
	u32 cpuTx_frac_ns = 0;

	memset(&tShhwtstamps, 0, sizeof(struct SkbSharedHwtstamps_t));
	memset(&tHwtstamps5g, 0, sizeof(struct skb_shared_hwtstamps));
	memset(&tHwtstampsTsn, 0, sizeof(struct skb_shared_hwtstamps));

	cpuTx_frac_ns = (hdr->cpu_tx) & 0x07;
	cpuTx_ns = *thw << CPU_TX_DECIMAL_NS;
	hdr->cpu_tx = htonl(cpuTx_ns + cpuTx_frac_ns);

	tShhwtstamps.ts_5g_t = *t5g;
	tShhwtstamps.ts_tsn_t = *tsn;

	tHwtstamps5g.hwtstamp = tShhwtstamps.ts_5g_t.ns + tShhwtstamps.ts_5g_t.s * S_HOLD;
	tHwtstampsTsn.hwtstamp = tShhwtstamps.ts_tsn_t.ns + tShhwtstamps.ts_tsn_t.s * S_HOLD;
	skb_tstamp_tx(skb, &tHwtstamps5g);
#ifdef CGEL_TSTAMP_2_PATCH_EN
	skb_tstamp_tx_2(skb, &tHwtstampsTsn);
#endif /* CGEL_TSTAMP_2_PATCH_EN */
	return PTP_RET_SUCCESS;
}

s32 pkt_proc_type_delay_req(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			    struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			    struct zxdh_en_device *en_dev)
{
	s32 ret = 0;

	ret = delay_and_pdelay_req_proc(skb, hdr, t5g, tsn, thw);
	return ret;
}

s32 pkt_proc_type_pdelay_req(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			     struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			     struct zxdh_en_device *en_dev)
{
	s32 ret = 0;

	ret = delay_and_pdelay_req_proc(skb, hdr, t5g, tsn, thw);
	return ret;
}

s32 pkt_proc_type_pdelay_resp(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			      struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			      struct zxdh_en_device *en_dev)
{
	struct Bits80_t tReqReceTs;
	struct SkbSharedHwtstamps_t tShhwtstamps;
	struct skb_shared_hwtstamps tHwtstamps5g;
	struct skb_shared_hwtstamps tHwtstampsTsn;
	struct time_stamps tMinusRet;
	struct ptpHdr_t *ptPtpHdr = NULL;
	u64 MinusVal = 0;
	u32 cpuTx_ns = 0;
	u32 cpuTx_frac_ns = 0;
	u64 cfNs = 0;

	memset(&tReqReceTs, 0, sizeof(struct Bits80_t));
	memset(&tShhwtstamps, 0, sizeof(struct SkbSharedHwtstamps_t));
	memset(&tMinusRet, 0, sizeof(struct time_stamps));
	memset(&tHwtstamps5g, 0, sizeof(struct skb_shared_hwtstamps));
	memset(&tHwtstampsTsn, 0, sizeof(struct skb_shared_hwtstamps));
	ptPtpHdr = (struct ptpHdr_t *)ptpHdr;

	cpuTx_frac_ns = (hdr->cpu_tx) & 0x07;
	cpuTx_ns = *thw << CPU_TX_DECIMAL_NS;
	hdr->cpu_tx = htonl(cpuTx_ns + cpuTx_frac_ns);

	if (0 == (ptPtpHdr->flagField & 0x0002)) {
		tReqReceTs = *(struct Bits80_t *)(ptpHdr + sizeof(struct ptpHdr_t));

		bits_80_minus(*tsn, tReqReceTs, &tMinusRet);
		MinusVal = tMinusRet.ns + tMinusRet.s * S_HOLD;
		memcpy(&cfNs, ptPtpHdr->correctionField, CF_NS_SIZE);
		cfNs = htonll(cfNs) >> 16;
		cfNs += MinusVal;
		cfNs = htonll(cfNs) >> 16;
		memcpy(&(ptPtpHdr->correctionField[0]), &cfNs, CF_NS_SIZE);
	}

	tShhwtstamps.ts_5g_t = *t5g;
	tShhwtstamps.ts_tsn_t = *tsn;

	tHwtstamps5g.hwtstamp = tShhwtstamps.ts_5g_t.ns + tShhwtstamps.ts_5g_t.s * S_HOLD;
	tHwtstampsTsn.hwtstamp = tShhwtstamps.ts_tsn_t.ns + tShhwtstamps.ts_tsn_t.s * S_HOLD;
	skb_tstamp_tx(skb, &tHwtstamps5g);
#ifdef CGEL_TSTAMP_2_PATCH_EN
	skb_tstamp_tx_2(skb, &tHwtstampsTsn);
#endif /* CGEL_TSTAMP_2_PATCH_EN */
	return PTP_RET_SUCCESS;
}

s32 pkt_rcv_type_event(struct zxdh_1588_pd_rx *hdr, u8 *ptpHdr, struct time_stamps *t5g,
		       struct time_stamps *tsn, u32 *thw, struct skb_shared_info *ptSkbSharedInfo,
		       struct zxdh_en_device *en_dev)
{
	struct SkbSharedHwtstamps_t tShhwtstamps;
	u32 tsRx = 0;
	u32 tsRx_ns = 0;
	u32 tsRx_frac_ns = 0;
	s32 MinusRetThwCpu = 0;
	u64 temp = 0x20000000;
	u32 i = 0;

	memset(&tShhwtstamps, 0, sizeof(struct SkbSharedHwtstamps_t));

	tsRx = htonl(hdr->rx_ts);

	tsRx_frac_ns = tsRx & 0x07;
	tsRx_ns = tsRx >> 3;
	// LOG_DEBUG("hdr->rx_ts = %d, tsRx = %d, tsRx_ns = %d\n", hdr->rx_ts, tsRx, tsRx_ns);

	if (tsRx_frac_ns > 4)
		tsRx_ns += 1;
	// LOG_DEBUG("thw = %d, tsRx_ns = %d\n", *thw, tsRx_ns);
	MinusRetThwCpu = (*thw & 0x1fffffff) - tsRx_ns;

	if (MinusRetThwCpu < 0)
		MinusRetThwCpu += temp;

	LOG_DEBUG("MinusRetThwCpu = %d\n", MinusRetThwCpu);

	tShhwtstamps.ts_5g_t = *t5g;
	tShhwtstamps.ts_tsn_t = *tsn;

	if (tShhwtstamps.ts_5g_t.ns > MinusRetThwCpu) {
		tShhwtstamps.ts_5g_t.ns -= MinusRetThwCpu;
	} else {
		for (i = 1; i < tShhwtstamps.ts_5g_t.s + 1; i++) {
			temp = i * S_HOLD + tShhwtstamps.ts_5g_t.ns;

			if (temp > MinusRetThwCpu) {
				tShhwtstamps.ts_5g_t.ns = temp - MinusRetThwCpu;
				tShhwtstamps.ts_5g_t.s -= i;
				break;
			}
		}
		if (temp < MinusRetThwCpu)
			LOG_ERR("ts_5g_t < MinusRetThwCpu!!!\n");
	}

	if (tShhwtstamps.ts_tsn_t.ns > MinusRetThwCpu) {
		tShhwtstamps.ts_tsn_t.ns -= MinusRetThwCpu;
	} else {
		for (i = 1; i < tShhwtstamps.ts_tsn_t.s + 1; i++) {
			temp = i * S_HOLD + tShhwtstamps.ts_tsn_t.ns;
			if (temp > MinusRetThwCpu) {
				tShhwtstamps.ts_tsn_t.ns = temp - MinusRetThwCpu;
				tShhwtstamps.ts_tsn_t.s -= i;
				break;
			}
		}
		if (temp < MinusRetThwCpu)
			LOG_ERR("ts_tsn_t < MinusRetThwCpu!!!\n");
	}

	LOG_DEBUG("enter in pkt rcv type event!!!!\n");
	LOG_DEBUG("tShhwtstamps.ts_5g_t.s = %llu, tShhwtstamps.ts_5g_t.ns = %d\n",
		  tShhwtstamps.ts_5g_t.s, tShhwtstamps.ts_5g_t.ns);
	LOG_DEBUG("tShhwtstamps.ts_tsn_t.s = %llu, tShhwtstamps.ts_tsn_t.ns = %d\n",
		  tShhwtstamps.ts_tsn_t.s, tShhwtstamps.ts_tsn_t.ns);

	ptSkbSharedInfo->hwtstamps.hwtstamp =
		ktime_set(tShhwtstamps.ts_5g_t.s, tShhwtstamps.ts_5g_t.ns);
#ifdef CGEL_TSTAMP_2_PATCH_EN
	ptSkbSharedInfo->hwtstamps2.hwtstamp =
		ktime_set(tShhwtstamps.ts_tsn_t.s, tShhwtstamps.ts_tsn_t.ns);
#endif /* CGEL_TSTAMP_2_PATCH_EN */
	return PTP_RET_SUCCESS;
}

/**
 * @fn read_ts_match_info

*/
s32 read_ts_match_info(u32 msgType, u8 *ptpHdr)
{
	u32 mssageType = 0;
	s32 cfNum = 0;
	u32 srcPortIdFifo = 0;
	u32 sequeIdFifo = 0;
	struct ptpHdr_t *ptPtpHdr = NULL;
	u32 matchInfo = 0;
	u8 srcPortId = 0;
	u64 cfVal = 0;

	ptPtpHdr = (struct ptpHdr_t *)ptpHdr;

	CHECK_EQUAL_ERR(ptPtpHdr, NULL, -EADDRNOTAVAIL, "tPtpBuff is NULL\n");

	srcPortId = *(u8 *)(ptPtpHdr->srcPortIdentity + SRCPORTID_LEN - 1);

	for (cfNum = 0; cfNum < tGlobalPtpBuff.cfCount; cfNum++) {
		matchInfo = tGlobalPtpBuff.ptpRegInfo[cfNum].matchInfo;
		mssageType = (matchInfo >> MSGTYPE_OFFSET) & 0xf;
		srcPortIdFifo = (matchInfo >> SRCPORTID_OFFSET) & 0xf;
		sequeIdFifo = htons(matchInfo & 0xffff);

		if ((mssageType == msgType) && (srcPortIdFifo == (srcPortId & 0xf)) &&
		    (sequeIdFifo == ptPtpHdr->sequenceId)) {
			LOG_DEBUG("read the match info successfully!!!\n");
			LOG_DEBUG("mssageType: %u, srcPortIdFifo: %u, sequeIdFifo: %u\n",
				  mssageType, srcPortIdFifo, sequeIdFifo);
			memcpy(&cfVal, &(tGlobalPtpBuff.ptpRegInfo[cfNum].cfVal[0]), CF_SIZE);
			cfVal = htonll(cfVal);
			memcpy(&(ptPtpHdr->correctionField[0]), &cfVal, CF_SIZE);

			tGlobalPtpBuff.cfCount--;
			if (cfNum == MAX_PTP_REG_INFO_NUM - 1) {
				memset(&(tGlobalPtpBuff.ptpRegInfo[cfNum]), 0,
				       sizeof(struct ptp_reg_info));
				return 0;
			}
			memcpy(&(tGlobalPtpBuff.ptpRegInfo[cfNum]),
			       &(tGlobalPtpBuff.ptpRegInfo[cfNum + 1]),
			       (MAX_PTP_REG_INFO_NUM - cfNum - 1) * sizeof(struct ptp_reg_info));
			memset(&(tGlobalPtpBuff.ptpRegInfo[MAX_PTP_REG_INFO_NUM - 1]), 0,
			       sizeof(struct ptp_reg_info));

			return 0;
		}
	}

	return -1;
}

#ifdef PTP_DRIVER_INTERFACE_EN
extern s32 get_event_ts_info(struct zxdh_en_device *en_dev, struct ptp_buff *p_tsInfo,
			     s32 mac_number);
#endif /* PTP_DRIVER_INTERFACE_EN */

/**
 * @fn general_encrypt_msg_proc

*/
s32 general_encrypt_msg_proc(u32 msgType, u8 *ptpHdr, struct zxdh_en_device *en_dev)
{
	s32 num = 0;
	s32 macNum = 0;
	s32 ret = 0;
	struct ptpHdr_t *ptPtpHdr = NULL;
	struct ptp_buff tempBuff;

	memset(&tempBuff, 0, sizeof(struct ptp_buff));
	ptPtpHdr = (struct ptpHdr_t *)ptpHdr;

	if (!(0x0080 == ((ptPtpHdr->flagField) & 0x0080)))
		return ret;

	macNum = zxdh_pf_macpcs_num_get(en_dev);
	if (macNum < 0) {
		LOG_ERR("get mac num %d err, its value should is 0-2!\n", macNum);
		return -1;
	}

	// LOG_INFO("ptp buff:\n ");
	// print_data((u8 *)&tGlobalPtpBuff, sizeof(struct ptp_update_buff));

	ret = read_ts_match_info(msgType, ptpHdr);

	if (ret != 0) {
		// LOG_INFO("cannot read the matchInfo from the BUFF!---------------");

#ifdef PTP_DRIVER_INTERFACE_EN
		ret = get_event_ts_info(en_dev, &tempBuff, macNum);
		CHECK_UNEQUAL_ERR(ret, 0, -EFAULT, "read FIFO form ptpDriver failed!!!");
#endif /* PTP_DRIVER_INTERFACE_EN */

		if (tempBuff.cfCount > 0) {
			if (tempBuff.cfCount + tGlobalPtpBuff.cfCount < MAX_PTP_REG_INFO_NUM) {
				memcpy(&(tGlobalPtpBuff.ptpRegInfo[tGlobalPtpBuff.cfCount]),
				       tempBuff.ptpRegInfo,
				       sizeof(struct ptp_reg_info) * tempBuff.cfCount);

				tGlobalPtpBuff.cfCount += tempBuff.cfCount;
				// LOG_INFO("tGlobalPtpBuff.cfCount: %u\n", tGlobalPtpBuff.cfCount);
			} else {
				num = tempBuff.cfCount + tGlobalPtpBuff.cfCount -
				      MAX_PTP_REG_INFO_NUM;

				memcpy(&(tGlobalPtpBuff.ptpRegInfo[0]),
				       &(tGlobalPtpBuff.ptpRegInfo[num]),
				       sizeof(struct ptp_reg_info) * (MAX_PTP_REG_INFO_NUM - num));
				tGlobalPtpBuff.cfCount -= num;

				memcpy(&(tGlobalPtpBuff.ptpRegInfo[tGlobalPtpBuff.cfCount]),
				       tempBuff.ptpRegInfo,
				       sizeof(struct ptp_reg_info) * tempBuff.cfCount);
				tGlobalPtpBuff.cfCount = MAX_PTP_REG_INFO_NUM;
			}

			ret = read_ts_match_info(msgType, ptpHdr);
			CHECK_UNEQUAL_ERR(ret, 0, -EFAULT,
					  "cannot read the matchInfo from the local BUFF!");
		}
	}

	// LOG_INFO("ptp buff:\n ");
	// print_data((u8 *)&tGlobalPtpBuff, sizeof(struct ptp_update_buff));

	return ret;
}

s32 pkt_proc_type_follow_up(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			    struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			    struct zxdh_en_device *en_dev)
{
	s32 ret = 0;

	ret = general_encrypt_msg_proc(PTP_MSG_TYPE_SYNC, ptpHdr, en_dev);

	return ret;
}

s32 pkt_proc_type_delay_resp(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			     struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			     struct zxdh_en_device *en_dev)
{
	return 0;
}

s32 pkt_rcv_type_delay_resp(struct zxdh_1588_pd_rx *hdr, u8 *ptpHdr, struct time_stamps *t5g,
			    struct time_stamps *tsn, u32 *thw,
			    struct skb_shared_info *ptSkbSharedInfo, struct zxdh_en_device *en_dev)
{
	s32 ret = 0;

	ret = general_encrypt_msg_proc(PTP_MSG_TYPE_DELAY_REQ, ptpHdr, en_dev);

	return ret;
}

s32 pkt_proc_type_pdelay_resp_follow_up(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr,
					u8 *ptpHdr, struct time_stamps *t5g,
					struct time_stamps *tsn, u32 *thw,
					struct zxdh_en_device *en_dev)
{
	s32 ret = 0;

	ret = general_encrypt_msg_proc(PTP_MSG_TYPE_PDELAY_RESP, ptpHdr, en_dev);

	return ret;
}

s32 pkt_proc_type_announce(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			   struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			   struct zxdh_en_device *en_dev)
{
	return 0;
}

s32 pkt_proc_type_signaling(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			    struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			    struct zxdh_en_device *en_dev)
{
	return 0;
}

s32 pkt_proc_type_management(struct sk_buff *skb, struct zxdh_1588_pd_tx *hdr, u8 *ptpHdr,
			     struct time_stamps *t5g, struct time_stamps *tsn, u32 *thw,
			     struct zxdh_en_device *en_dev)
{
	return 0;
}
