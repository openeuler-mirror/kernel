// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include "main.h"
#include "hw.h"
#include "aeq.h"
#include "ceq.h"
#include "debug.h"
#include "pble.h"
#include "cqp.h"
#include "hmc.h"
#include "grc.h"
#include "qp.h"
#include "counters.h"
#include "dump_fields.h"
#include "srq.h"
#include "fpga_ver.h"
#include "nbl_rdma_module.h"

void nbl_dump_hex(struct nbl_pci_f *rf, u8 *buf, int len)
{
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[NBL_HEX_DUMP_BUF_MAX];
	int rowsize = NBL_HEX_DUMP_ROW;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, NBL_HEX_DUMP_GRP,
				   linebuf, sizeof(linebuf), false);

		nbl_pr_info("[%d-%d] %s\n", i, (i + linelen - 1), linebuf);
	}
}

static void nbl_dump_cc_qpc_fields_qcn(u8 *qpc_data)
{
	u64 qcn_remain_trans_bits;
	u64 qcn_sendpkt_tarwin;
	u32 qcn_first_recdb_flag;
	u64 qcn_limit_rp;
	u64 qcn_target_rp;
	u32 qcn_main_status;

	qcn_remain_trans_bits =
		nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V2_QCN_REMAIN_TRANS_BITS);
	qcn_sendpkt_tarwin = nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V2_QCN_SENDPKT_TARGETWIN);
	qcn_first_recdb_flag =
		(u32)nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V2_QCN_FIRST_RECDB_FLAG);
	qcn_limit_rp = nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V2_QCN_LIMIT_RP);
	qcn_target_rp = nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V2_QCN_TARGET_RP);
	qcn_main_status = (u32)nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V2_QCN_MAIN_STATUS);

	pr_info("0x80 Rl:%lld Rt:%lld qcn_sendpkt_tarwin:%lld qcn_remain_trans_bits:%lld",
		qcn_limit_rp, qcn_target_rp, qcn_sendpkt_tarwin, qcn_remain_trans_bits);
}

static void nbl_dump_cc_qpc_fields_qcn_v4(u8 *qpc_data)
{
	u64 qcn_remain_trans_bits;
	u64 qcn_sendpkt_tarwin;
	u32 qcn_first_recdb_flag;
	u64 qcn_limit_rp;
	u64 qcn_target_rp;
	u32 qcn_main_status;

	qcn_remain_trans_bits =
		nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V4_QCN_REMAIN_TRANS_BITS);
	qcn_sendpkt_tarwin = nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V4_QCN_SENDPKT_TARGETWIN);
	qcn_first_recdb_flag =
		(u32)nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V4_QCN_FIRST_RECDB_FLAG);
	qcn_limit_rp = nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V4_QCN_LIMIT_RP);
	qcn_target_rp = nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V4_QCN_TARGET_RP);
	qcn_main_status = (u32)nbl_64bit_read((__be64 *)qpc_data, NBL_QPC_V4_QCN_MAIN_STATUS);

	pr_err("0x80 Rl:%lld Rt:%lld qcn_sendpkt_tarwin:%lld qcn_remain_trans_bits:%lld",
		qcn_limit_rp, qcn_target_rp, qcn_sendpkt_tarwin, qcn_remain_trans_bits);
}

static u32 get_qpn_from_cache_key(struct nbl_pci_f *rf, u8 *key)
{
	u32 qpn = rf->max_qp;
	u32 key32 = be32_to_cpu(*(u32 *)key);

	switch (NBL_RF_TO_HW_VER(rf)) {
	case NBL_VER_5:
		/* TODO: replace with Orion fields when its cache format is ready. */
		qpn = (key32 >> NBL_CACHE_QPCC_KEY_QPN_SHIFT_V2) &
		      NBL_CACHE_QPCC_KEY_QPN_MASK_V2;
		break;
	case NBL_VER_2:
		qpn = (key32 >> NBL_CACHE_QPCC_KEY_QPN_SHIFT_V2) &
		      NBL_CACHE_QPCC_KEY_QPN_MASK_V2;
		break;
	case NBL_VER_3:
	case NBL_VER_4:
		qpn = (key32 >> NBL_CACHE_QPCC_KEY_QPN_SHIFT_V34) &
		      NBL_CACHE_QPCC_KEY_QPN_MASK_V34;
		break;
	default:
		nbl_pr_err("get qpn from key wrong hw ver 0x%x\n",
			NBL_RF_TO_HW_VER(rf)); /* never here */
		break;
	}
	return qpn;
}
static u8 get_vfid_from_cache_key(struct nbl_pci_f *rf, u8 *key)
{
	u8 vfid = 0;
	u32 key32 = be32_to_cpu(*(u32 *)key);

	switch (NBL_RF_TO_HW_VER(rf)) {
	case NBL_VER_5:
		/* TODO: replace with Orion fields when its cache format is ready. */
		vfid = key32 >> NBL_CACHE_QPCC_KEY_VFID_SHIFT_V2;
		break;
	case NBL_VER_2:
		vfid = key32 >> NBL_CACHE_QPCC_KEY_VFID_SHIFT_V2;
		break;
	case NBL_VER_3:
	case NBL_VER_4:
		vfid = key32 >> NBL_CACHE_QPCC_KEY_VFID_SHIFT_V34;
		break;
	default:
		nbl_pr_err("get vfid from key wrong hw ver 0x%x\n",
			NBL_RF_TO_HW_VER(rf)); /* never here */
		break;
	}
	return vfid;
}

static void nbl_dump_cc_debug_info_qcn(struct nbl_pci_f *rf, u32 mask, u8 *key,
				       u8 *data)
{
	u32 qpn = get_qpn_from_cache_key(rf, key);

	if (qpn >= rf->max_qp)
		return;

	if (qpn == (mask & 0xFFFFF) || (mask & 0xFFFFF) == 0) {
		if (rf->qp_table[qpn]) {
			pr_info("qpn[%d] DCQCN's debug qpc info:\n", qpn);
			if (NBL_RF_TO_HW_VER(rf) >= NBL_VER_4)
				nbl_dump_cc_qpc_fields_qcn_v4(data);
			else
				nbl_dump_cc_qpc_fields_qcn(data);

			if (mask & 0x100000)
				nbl_dump_hex(rf, data, NBL_CACHE_QPCC_SIZE);
		}
	}
}

static int nbl_dump_cc_qpc_fields_v2(u8 hw_ver, u8 *qpc_data, u32 mask, u32 qpn)
{
	u32 cc_recreq_sendtx_blk_cnt;
	u32 cc_winm_busy;
	u32 cc_rcvack_flag;
	u32 cc_recack_lastwinm_blk_cnt;
	u32 cc_recack_epsn;

	u32 cc_time_lastta;
	u32 ccqcn_reqcarry_sendcnp_time;

	u32 qcn_rececn_flag;
	u32 cc_more_rttminth_flag;
	u32 cc_less_rttminth_flag;
	u32 cc_recack_rttflag;
	u32 cc_sendack_mid_blk_cnt;
	u32 cc_recreq_blk_cnt;
	u32 cc_recreq_mid_blk_cnt;
	u32 cc_recreq_epsn;

	u32 cc_rttmin;
	u32 cc_rtt;
	u32 cc_oamack_next_psn;

	u32 rttm_busy;
	u32 recack_rectx_blk_cnt;
	u32 targetwin;
	u32 targetwin_min;

	u32 rttm_psnts;
	u32 txp_sendpld_blk_cnt;
	u32 cc_mode;
	u32 rmt_rec_ecn_cnt = 0;
	u32 init_rec_ecn_cnt = 0;
	int inflight;
	bool is_print = true;

	if (qpc_data == NULL)
		return 0;

	if (hw_ver < NBL_VER_4) {
		rttm_busy = (u32)nbl_64bit_read((__be64 *)qpc_data,
						NBL_QPC_V2_CC_RTTM_BUSY);
		recack_rectx_blk_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_CC_RECACK_RECTX_BLK_CNT);
		cc_rcvack_flag = (u32)nbl_64bit_read((__be64 *)qpc_data,
						     NBL_QPC_V2_CC_RCVACK_FLAG);
		cc_more_rttminth_flag = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_CC_MORE_RTTMINTH_FLAG);
		cc_less_rttminth_flag = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_CC_LESS_RTTMINTH_FLAG);
		cc_time_lastta = (u32)nbl_64bit_read((__be64 *)qpc_data,
						     NBL_QPC_V2_CC_TIME_LASTTA);
		qcn_rececn_flag = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_QCN_RECECN_FLAG);
		cc_rttmin = (u32)nbl_64bit_read((__be64 *)qpc_data,
						NBL_QPC_V2_CC_RTTMIN);
		cc_rtt = (u32)nbl_64bit_read((__be64 *)qpc_data,
					     NBL_QPC_V2_CC_RTT_MEASURE);
		cc_rttmin *= 40;
		cc_rtt *= 640;
	} else {
		rttm_busy = (u32)nbl_64bit_read((__be64 *)qpc_data,
						NBL_QPC_V4_CC_RTTM_BUSY);
		recack_rectx_blk_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V4_CC_RECACK_RECTX_BLK_CNT);
		rmt_rec_ecn_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V4_RMT_REC_ECN_CNT);
		init_rec_ecn_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V4_INIT_REC_ECN_CNT);
		cc_rcvack_flag = (u32)nbl_64bit_read((__be64 *)qpc_data,
						     NBL_QPC_V4_CC_RCVACK_FLAG);
		cc_more_rttminth_flag = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V4_CC_MORE_RTTMINTH_FLAG);
		cc_less_rttminth_flag = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V4_CC_LESS_RTTMINTH_FLAG);
		cc_time_lastta = (u32)nbl_64bit_read((__be64 *)qpc_data,
						     NBL_QPC_V4_CC_TIME_LASTTA);
		qcn_rececn_flag = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V4_QCN_RECECN_FLAG);
		cc_rttmin = (u32)nbl_64bit_read((__be64 *)qpc_data,
						NBL_QPC_V4_CC_RTTMIN);
		cc_rtt = (u32)nbl_64bit_read((__be64 *)qpc_data,
					     NBL_QPC_V4_CC_RTT_MEASURE);
		cc_rttmin *= 40;
		cc_rtt *= 320;
	}
	txp_sendpld_blk_cnt = (u32)nbl_64bit_read(
		(__be64 *)qpc_data, NBL_QPC_V2_CC_TXP_SENDPLD_BLK_CNT);

	inflight = txp_sendpld_blk_cnt - recack_rectx_blk_cnt;

	/* dump only inflight < 0 */
	if (mask & 0x2000000)
		is_print = inflight >= 0 ? false : true;

	if (is_print) {
		cc_recreq_sendtx_blk_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data,
			NBL_QPC_V2_CC_RECREQ_SENDTX_BLK_CNT);
		cc_winm_busy = (u32)nbl_64bit_read((__be64 *)qpc_data,
						   NBL_QPC_V2_CC_WINM_BUSY);

		cc_recack_lastwinm_blk_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data,
			NBL_QPC_V2_CC_RECACK_LASTWINM_BLK_CNT);
		cc_recack_epsn = (u32)nbl_64bit_read((__be64 *)qpc_data,
						     NBL_QPC_V2_CC_RECACK_EPSN);

		pr_info("qpn[%d(%#x)] CC's debug qpc info:\n", qpn, qpn);
		pr_info("0x138 cc_recreq_sendtx_blk_cnt:%d cc_winm_busy:%d cc_rcvack_flag:%d cc_recack_lastwinm_blk_cnt:%d cc_recack_epsn:%d\n",
		       cc_recreq_sendtx_blk_cnt, cc_winm_busy, cc_rcvack_flag,
		       cc_recack_lastwinm_blk_cnt, cc_recack_epsn);

		ccqcn_reqcarry_sendcnp_time = (u32)nbl_64bit_read(
			(__be64 *)qpc_data,
			NBL_QPC_V2_CCQCN_REQCARRY_SENDCNP_TIME);
		pr_info("0x130 cc_time_lastta:%u ccqcn_reqcarry_sendcnp_time:%u rmt_rec_ecn_cnt:%u init_rec_ecn_cnt:%u\n",
		       cc_time_lastta, ccqcn_reqcarry_sendcnp_time,
		       rmt_rec_ecn_cnt, init_rec_ecn_cnt);

		cc_recack_rttflag = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_CC_RECACK_RTTFLAG);
		cc_sendack_mid_blk_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_CC_SENDACK_MID_BLK_CNT);
		cc_recreq_blk_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_CC_RECREQ_BLK_CNT);
		cc_recreq_mid_blk_cnt = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_CC_RECREQ_MID_BLK_CNT);
		cc_recreq_epsn = (u32)nbl_64bit_read((__be64 *)qpc_data,
						     NBL_QPC_V2_CC_RECREQ_EPSN);

		pr_info("0x128 cc_sendack_mid_blk_cnt:%d cc_recreq_blk_cnt:%d cc_recreq_mid_blk_cnt:%d cc_recreq_epsn:%d\n",
		       cc_sendack_mid_blk_cnt, cc_recreq_blk_cnt,
		       cc_recreq_mid_blk_cnt, cc_recreq_epsn);

		cc_oamack_next_psn = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V2_CC_OAMACK_NEXT_PSN);

		targetwin = (u32)nbl_64bit_read((__be64 *)qpc_data,
						NBL_QPC_V2_CC_TARGETWIN);

		targetwin_min = (u32)nbl_64bit_read(
			(__be64 *)qpc_data, NBL_QPC_V1_CC_TARGETWIN_MIN);

		rttm_psnts = (u32)nbl_64bit_read((__be64 *)qpc_data,
						 NBL_QPC_V2_CC_RTTM_PSNTS);

		cc_mode = (u32)nbl_64bit_read((__be64 *)qpc_data,
					      NBL_QPC_V2_CC_MODE);

		pr_info("0x120 qcn_rececn_flag:%d cc_more_rttminth_flag:%d cc_less_rttminth_flag:%d cc_recack_rttflag:%d rtt_measure:%d ns cc_rttmin:%d ns cc_oamack_next_psn:%d\n",
		       qcn_rececn_flag, cc_more_rttminth_flag,
		       cc_less_rttminth_flag, cc_recack_rttflag, cc_rtt,
		       cc_rttmin, cc_oamack_next_psn);

		pr_info("0x190 rttm_psnts:%d txp_sendpld_blk_cnt:%d\n",
		       rttm_psnts, txp_sendpld_blk_cnt);

		pr_info("0x198 rttm_busy:%d recack_rectx_blk_cnt:%d cc_mode:%d targetwin_min:%d targetwin:%d inflight:%d\n",
		       rttm_busy, recack_rectx_blk_cnt, cc_mode, targetwin_min,
		       targetwin, inflight);
	}

	return is_print;
}

/**
 * Dump QPC information based on given criteria.
 *
 * @nbl_dev: Pointer to the NBL device structure.
 * @mask: The mask to decide which fields of the key to compare.
 * @key: The key data (containing vfid and qpn).
 * @data: The QPC data.
 *
 * Note:
 * - The highest nibble of the mask is 2.
 *   -- Hex digits 6-5 represent the vfid, FF dump all vfids.
 *   -- Hex digits 4-0 represent the QPN, FFFFF dump all QPs.
 * for example, mask == 0x20100002 to dump vf1, qp2
 */
static void nbl_dump_qpc_info(struct nbl_pci_f *rf,
		struct nbl_func_file *func_file, u32 mask, u8 *key, u8 *data)
{
	u32 qpn = get_qpn_from_cache_key(rf, key);
	u8 vfid = get_vfid_from_cache_key(rf, key);
	u32 mask_qpn;
	u8 mask_vfid;

	if (qpn >= rf->max_qp)
		return;

	mask_qpn = mask & NBL_CACHE_QPCC_FIELDS_QPN_MASK;
	mask_vfid = (mask >> 20) & NBL_CACHE_QPCC_FIELDS_VFID_MASK;

	/* Check if the 6-5 hex digits are FF (dump all vfids)
	 * Check if the 4-0 hex digits are FFFFF (dump all QPs)
	 * or match based on vfid and qpn
	 */
	if (((mask & 0x0FF00000) == 0x0FF00000 && qpn == mask_qpn) ||
			((mask & 0x000FFFFF) == 0x000FFFFF && vfid == mask_vfid) ||
			(vfid == mask_vfid && qpn == mask_qpn) ||
			((mask & 0x0FFFFFFF) == 0x0FFFFFFF)) {
		pr_info("QPC INFO WRITE TO BUFFER: vfid[%d] qpn[%d]", vfid, qpn);
		write_to_file_buffer(func_file,
			"================vfid[%d] qpn[%d] qpc info================\n", vfid, qpn);
		nbl_dump_fields(rf, func_file, data, NBL_DBG_DUMP_QPC);
	}
}

static int nbl_dump_cc_debug_info(struct nbl_pci_f *rf, u32 mask, u8 *key,
				  u8 *data,
				  struct nbl_func_file *dump_func_file)
{
	u32 qpn = get_qpn_from_cache_key(rf, key);
	int ret = 0;

	if (qpn >= rf->max_qp)
		return 0;

	if (qpn == (mask & 0xFFFFF) || (mask & 0xFFFFF) == 0) {
		if ((mask & 0x1000000) || rf->qp_table[qpn]) {
			ret = nbl_dump_cc_qpc_fields_v2(NBL_RF_TO_HW_VER(rf), data, mask, qpn);
			/* dump more qpc info */
			if (mask & 0x100000 && ret) {
				nbl_dump_hex(rf, data, NBL_CACHE_QPCC_SIZE);
				nbl_dump_qpc_info(rf, dump_func_file, qpn, key,
						  data);
			}
		}
	}
	return ret;
}

static void nbl_dump_mrtc_debug_info(struct nbl_device *nbl_dev, u32 mask, u8 *key, u8 *data)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_func_file *func_file = &nbl_dev->func_dump_info->dump_func_file;
	u32 mkey = be32_to_cpu(*(u32 *)key);
	u8 vfid = mkey >> 30;

	mkey = (mkey >> 6) & 0xFFFFFF;
	if (mkey == (mask & 0xFFFFFF) || (mask & 0xFFFFFF) == 0) {
		pr_info("mrte cache key: 0x%x\n", mkey);
		nbl_dump_hex(rf, key, NBL_CACHE_KEY_BASE_SIZE);
		write_to_file_buffer(func_file,
			"================vfid[%d] mkey[%d] mrt info================\n", vfid, mkey);
		pr_info("mrte cache data:");
		nbl_dump_hex(rf, data, NBL_CACHE_MRTE_SIZE_V2);
		nbl_dump_fields(rf, func_file, data, NBL_DBG_DUMP_MRT);
	}
}

static void nbl_dump_mrt_key(struct nbl_func_file *func_file, u8 *key)
{
	u32 key32 = be32_to_cpu(*(u32 *)key);
	u8 vfid = key32 >> 30;
	u32 mkey = (key32 >> 6) & 0xFFFFFF;

	write_to_file_buffer(func_file,
		"================vfid[%d] mkey[%d] mrt info================\n", vfid, mkey);
}

static struct nbl_cache_key cache_key_tbl[NBL_VER_MAX][NBL_CACHE_MAX] = {
	[NBL_VER_2] = {
		{
			.offset = NBL_CACHE_QPCC_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_QPCC_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_CQCC_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_CQCC_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_MRTE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_MRTE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_SRQC_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_SRQC_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_IRQE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_IRQE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_ORQE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_ORQE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_SQRQE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_SQRQE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_RAQE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_RAQE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_PBLE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_PBLE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_UNAQ_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_UNAQ_KEY_VLD_MSK_V2,
		},
	},

	[NBL_VER_3] = {
		{
			.offset = NBL_CACHE_QPCC_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_QPCC_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_CQCC_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_CQCC_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_MRTE_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_MRTE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_SRQC_KEY_VLD_IX,
			.mask = NBL_CACHE_SRQC_KEY_VLD_MSK,
		},

		{
			.offset = NBL_CACHE_IRQE_KEY_VLD_IX,
			.mask = NBL_CACHE_IRQE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_ORQE_KEY_VLD_IX,
			.mask = NBL_CACHE_ORQE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_SQRQE_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_SQRQE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_RAQE_KEY_VLD_IX,
			.mask = NBL_CACHE_RAQE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_PBLE_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_PBLE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_UNAQ_KEY_VLD_IX,
			.mask = NBL_CACHE_UNAQ_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_PD_KEY_VLD_IX,
			.mask = NBL_CACHE_PD_KEY_VLD_MSK,
		}
	},

	[NBL_VER_4] = {
		{
			.offset = NBL_CACHE_QPCC_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_QPCC_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_CQCC_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_CQCC_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_MRTE_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_MRTE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_SRQC_KEY_VLD_IX,
			.mask = NBL_CACHE_SRQC_KEY_VLD_MSK,
		},

		{
			.offset = NBL_CACHE_IRQE_KEY_VLD_IX,
			.mask = NBL_CACHE_IRQE_KEY_VLD_MSK_V4,
		},

		{
			.offset = NBL_CACHE_ORQE_KEY_VLD_IX,
			.mask = NBL_CACHE_ORQE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_SQRQE_KEY_VLD_IX_V4,
			.mask = NBL_CACHE_SQRQE_KEY_VLD_MSK_V4,
		},

		{
			.offset = NBL_CACHE_RAQE_KEY_VLD_IX,
			.mask = NBL_CACHE_RAQE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_PBLE_KEY_VLD_IX_V3,
			.mask = NBL_CACHE_PBLE_KEY_VLD_MSK_V3,
		},

		{
			.offset = NBL_CACHE_UNAQ_KEY_VLD_IX,
			.mask = NBL_CACHE_UNAQ_KEY_VLD_MSK_V4,
		},

		{
			.offset = NBL_CACHE_PD_KEY_VLD_IX,
			.mask = NBL_CACHE_PD_KEY_VLD_MSK,
		}
	},
	/* TODO, Orion check and change to actural offset and mask */
	[NBL_VER_5] = {
		{
			.offset = NBL_CACHE_QPCC_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_QPCC_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_CQCC_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_CQCC_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_MRTE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_MRTE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_SRQC_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_SRQC_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_IRQE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_IRQE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_ORQE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_ORQE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_SQRQE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_SQRQE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_RAQE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_RAQE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_PBLE_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_PBLE_KEY_VLD_MSK_V2,
		},

		{
			.offset = NBL_CACHE_UNAQ_KEY_VLD_IX_V2,
			.mask = NBL_CACHE_UNAQ_KEY_VLD_MSK_V2,
		},
	},
};

static bool check_cache_key_vld(struct nbl_pci_f *rf, int type, u8 *key)
{
	int key_byte_offset;
	u8 valid_bit_mask;

	if (NBL_RF_TO_HW_VER(rf) < NBL_VER_2 || NBL_RF_TO_HW_VER(rf) >= NBL_VER_MAX)
		return false;

	if (type < NBL_CACHE_QPCC || type >= NBL_CACHE_MAX)
		return false;

	key_byte_offset = cache_key_tbl[NBL_RF_TO_HW_VER(rf)][type].offset;
	valid_bit_mask = cache_key_tbl[NBL_RF_TO_HW_VER(rf)][type].mask;

	return key[key_byte_offset] & valid_bit_mask;
}

static void nbl_mrte_dump_hex(struct nbl_pci_f *rf, u8 *buf)
{
	nbl_dump_hex(rf, buf, NBL_CACHE_MRTE_SIZE_V2);
}

static int nbl_hw_cache_handle(struct nbl_device *nbl_dev, int type, u32 mask,
	u8 *key, int key_len, u8 *data, int data_len)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_func_file *dump_func_file = &nbl_dev->func_dump_info->dump_func_file;

	int ix, jx, kx;

	ix = 0;
	jx = 0;
	kx = 0;
	if (type == NBL_CACHE_QPCC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				if (mask & NBL_CACHE_QPCC_CC_DATA_MASK)
					nbl_dump_cc_debug_info(rf, mask,
							       &key[ix],
							       &data[jx],
							       dump_func_file);
				else if (mask & NBL_CACHE_QPCC_FIELDS_MASK) {
					nbl_dump_qpc_info(
						rf, dump_func_file, mask, &key[ix], &data[jx]);
				} else if (mask & NBL_CACHE_QPCC_QCN_DATA_MASK) {
					nbl_dump_cc_debug_info_qcn(rf, mask, &key[ix], &data[jx]);
				} else {
					nbl_dev_info(&rf->pcidev->dev, "qpc cache key:");
					nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
					if (mask & NBL_CACHE_QPCC_DATA_MASK) {
						nbl_dev_info(&rf->pcidev->dev, "qpc cache data:");
						nbl_dump_hex(rf, &data[jx], NBL_CACHE_QPCC_SIZE);
						/* Write to cache_qpc */
						nbl_dump_fields(
							rf,
							dump_func_file,
							&data[jx],
							NBL_DBG_DUMP_QPC
						);
					}
				}

				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_QPCC_SIZE;
		}
	} else if (type == NBL_CACHE_CQCC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "cqc cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				write_to_file_buffer(dump_func_file, "cqc cache key:\n");
				nbl_dump_hex_to_file_buffer(dump_func_file,
					&key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_CQCC_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "cqc cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_CQCC_SIZE);
					write_to_file_buffer(dump_func_file, "cqc cache data:\n");
					nbl_dump_fields(
						rf,
						dump_func_file,
						&data[jx],
						NBL_DBG_DUMP_CQC
					);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_CQCC_SIZE;
		}
	} else if (type == NBL_CACHE_MRTC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {

				if (mask & NBL_CACHE_MRTE_MKEY_DUMP_MASK) {
					nbl_dump_mrtc_debug_info(
						nbl_dev, mask, &key[ix], &data[jx]);
				} else {
					nbl_dev_info(&rf->pcidev->dev, "mrte cache key:");
					nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
					nbl_dump_mrt_key(dump_func_file, &key[ix]);
					if (mask & NBL_CACHE_MRTE_DATA_MASK) {
						nbl_dev_info(&rf->pcidev->dev, "mrte cache data:");
						nbl_mrte_dump_hex(rf, &data[jx]);
						nbl_dump_fields(
							rf,
							dump_func_file,
							&data[jx],
							NBL_DBG_DUMP_MRT
						);
					}
				}

				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_MRTE_SIZE_V2;
		}
	} else if (type == NBL_CACHE_SRQC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "srqc cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				nbl_dev_info(&rf->pcidev->dev, "srqc cache data:");
				nbl_dump_hex(rf, &data[jx], NBL_CACHE_SRQC_SIZE);
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_SRQC_SIZE;
		}
	} else if (type == NBL_CACHE_PBLC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "pble cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_PBLE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "pble cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_PBLE_SIZE_V2);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_PBLE_SIZE_V2;
		}
	} else if (type == NBL_CACHE_SQRQEC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "sqrqe cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_SQRQE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "sqrqe cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_SQRQE_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_SQRQE_SIZE;
		}
	} else if (type == NBL_CACHE_IRQEC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "irqe cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_IRQE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "irqe cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_IRQE_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_IRQE_SIZE;
		}
	} else if (type == NBL_CACHE_RAQEC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "raqe cache key:");
				nbl_dump_hex(rf, &key[ix], NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_RAQE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "raqe cache data:");
					nbl_dump_hex(rf, &data[jx], NBL_CACHE_RAQE_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_RAQE_SIZE;
		}
	} else if (type == NBL_CACHE_ORQEC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "orqe cache key:");
				nbl_dump_hex(rf, &key[ix],
					     NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_ORQE_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "orqe cache data:");
					nbl_dump_hex(rf, &data[jx],
						     NBL_CACHE_ORQE_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_ORQE_SIZE;
		}
	} else if (type == NBL_CACHE_UNAQC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "unaq cache key:");
				nbl_dump_hex(rf, &key[ix],
					     NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_UNAQ_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "unaq cache data:");
					nbl_dump_hex(rf, &data[jx],
						     NBL_CACHE_UNAQ_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_UNAQ_SIZE;
		}
	} else if (type == NBL_CACHE_PDC) {
		while (ix < key_len) {
			if (check_cache_key_vld(rf, type, &key[ix])) {
				nbl_dev_info(&rf->pcidev->dev, "pdc cache key:");
				nbl_dump_hex(rf, &key[ix],
					     NBL_CACHE_KEY_BASE_SIZE);
				if (mask & NBL_CACHE_PD_DATA_MASK) {
					nbl_dev_info(&rf->pcidev->dev, "pdc cache data:");
					nbl_dump_hex(rf, &data[jx],
						     NBL_CACHE_PD_SIZE);
				}
				kx++;
			}
			ix += NBL_CACHE_KEY_BASE_SIZE;
			jx += NBL_CACHE_PD_SIZE;
		}
	}
	return kx;
}

static int nbl_get_cache_query_attr(struct nbl_pci_f *rf, enum nbl_cqp_cache_type type,
	int *query_once_num, int *cache_data_size, int *cache_deep)
{
	const struct nbl_product_limits *limits = rf->product->limits;

	switch (type) {
	case NBL_CACHE_QPCC:
		*query_once_num = NBL_CACHE_QPCC_NUM_ONCE;
		*cache_data_size = NBL_CACHE_QPCC_SIZE;
		*cache_deep = limits->qpcc_depth;
		break;
	case NBL_CACHE_CQCC:
		*query_once_num = NBL_CACHE_CQCC_NUM_ONCE;
		*cache_data_size = NBL_CACHE_CQCC_SIZE;
		*cache_deep = limits->cqcc_depth;
		break;
	case NBL_CACHE_MRTC:
		*query_once_num = NBL_CACHE_MRTE_NUM_ONCE;
		*cache_data_size = NBL_CACHE_MRTE_SIZE_V2;
		*cache_deep = limits->mrtc_depth;
		break;
	case NBL_CACHE_SRQC:
		*query_once_num = NBL_CACHE_SRQC_NUM_ONCE;
		*cache_data_size = NBL_CACHE_SRQC_SIZE;
		*cache_deep = limits->srqc_depth;
		break;
	case NBL_CACHE_PBLC:
		*query_once_num = NBL_CACHE_PBLE_NUM_ONCE;
		*cache_data_size = NBL_CACHE_PBLE_SIZE_V2;
		*cache_deep = limits->pblc_depth;
		break;
	case NBL_CACHE_SQRQEC:
		*query_once_num = NBL_CACHE_SQRQE_NUM_ONCE;
		*cache_data_size = NBL_CACHE_SQRQE_SIZE;
		*cache_deep = limits->sqrqec_depth;
		break;
	case NBL_CACHE_IRQEC:
		*query_once_num = NBL_CACHE_IRQE_NUM_ONCE;
		*cache_data_size = NBL_CACHE_IRQE_SIZE;
		*cache_deep = limits->irqec_depth;
		break;
	case NBL_CACHE_RAQEC:
		*query_once_num = NBL_CACHE_RAQE_NUM_ONCE;
		*cache_data_size = NBL_CACHE_RAQE_SIZE;
		*cache_deep = limits->raqec_depth;
		break;
	case NBL_CACHE_ORQEC:
		*query_once_num = NBL_CACHE_ORQE_NUM_ONCE;
		*cache_data_size = NBL_CACHE_ORQE_SIZE;
		*cache_deep = limits->orqec_depth;
		break;
	case NBL_CACHE_UNAQC:
		*query_once_num = NBL_CACHE_UNAQ_NUM_ONCE;
		*cache_data_size = NBL_CACHE_UNAQ_SIZE;
		*cache_deep = limits->unaqec_depth;
		break;
	case NBL_CACHE_PDC:
		*query_once_num = NBL_CACHE_PD_NUM_ONCE;
		*cache_data_size = NBL_CACHE_PD_SIZE;
		*cache_deep = limits->pdc_depth;
		break;
	default:
		nbl_ib_err(&rf->sc_dev, "[cache] dump unknown hw cache\n");
		return -EFAULT;
	}

	return 0;
}

int nbl_dbg_mem_read(struct nbl_device *nbl_dev, u64 pa)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	__be64 *in;
	__be64 *out;
	u8 *ptr;
	int err_code;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	out = kzalloc(NBL_CMD_OUTPUT_SIZE, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return -ENOMEM;
	}

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_MEM_READ);
	nbl_64bit_write(in, NBL_CQP_MEM_READ_ADDR, pa);

	nbl_pr_info("Mem read(cqp in) :\n");
	ptr = (u8 *)in;
	nbl_dump_hex(rf, ptr, NBL_CMD_INPUT_SIZE);

	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, out, NBL_CMD_OUTPUT_SIZE);
	if (err_code)
		nbl_pr_err("mem read cqp cmd failed err_code :%d\n", err_code);

	nbl_pr_info("mem read(cqp out) :\n");
	ptr = (u8 *)out;
	nbl_dump_hex(rf, ptr, NBL_CMD_OUTPUT_SIZE);

	kfree(out);
	kfree(in);
	return 0;
}

int nbl_dump_hw_cache(struct nbl_device *nbl_dev, u32 dump_mask, enum nbl_cqp_cache_type type)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	int err_code = 0;
	int ret;
	int ix, count;
	int query_once_num;
	int cache_type;
	int cache_data_size;
	int cache_deep;
	__be64 *in;
	struct nbl_dma_mem key_buf;
	struct nbl_dma_mem data_buf;

	cache_type = type;
	ret = nbl_get_cache_query_attr(rf, type,
				&query_once_num, &cache_data_size, &cache_deep);
	if (ret)
		return ret;

	data_buf.size = SZ_4K;
	data_buf.va = nbl_dma_alloc_coherent(sc_dev->hw,
						data_buf.size, &data_buf.pa,
						GFP_KERNEL | __GFP_ZERO);
	if (!data_buf.va) {
		nbl_ib_err(sc_dev, "Error, dump cache allocate data buf no mem\n");
		return -ENOMEM;
	}

	key_buf.size = SZ_4K;
	key_buf.va = nbl_dma_alloc_coherent(sc_dev->hw,
						key_buf.size, &key_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!key_buf.va) {
		nbl_ib_err(sc_dev, "Error, dump cache allocate key buf no mem\n");
		err_code = -ENOMEM;
		goto free_data;
	}

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		err_code = -ENOMEM;
		goto free_key;
	}

	ix = 0;
	count = 0;
	while (ix < cache_deep) {
		memset(key_buf.va, 0xff, key_buf.size);
		memset(data_buf.va, 0xff, data_buf.size);

		if (dump_mask & NBL_CACHE_DUMP_CQP_MASK)
			nbl_dev_info(&rf->pcidev->dev, "key pa[0x%llx], data pa[0x%llx], from %d to %d\n",
				(u64)key_buf.pa, (u64)data_buf.pa, ix, ix + query_once_num - 1);

		nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_QUERY_CACHE);
		nbl_64bit_write(in, NBL_CQP_CACHE_TYPE, cache_type);
		nbl_64bit_write(in, NBL_CQP_START_INDEX, ix);
		nbl_64bit_write(in, NBL_CQP_KEY_NUM, query_once_num);
		nbl_64bit_write(in, NBL_CQP_UNIT_BNUM, cache_data_size);
		nbl_64bit_write(in, NBL_CQP_CACHE_KEYPA, key_buf.pa);
		nbl_64bit_write(in, NBL_CQP_CACHE_DATAPA, data_buf.pa);

		if (dump_mask & NBL_CACHE_DUMP_CQP_MASK)
			print_hex_dump(KERN_INFO, "dump cqp: ", DUMP_PREFIX_NONE,
				NBL_CMD_DEBUG_ROW_SIZE, NBL_CMD_DEBUG_GROUP_SIZE,
				(u8 *)in, NBL_CMD_INPUT_SIZE, false);

		err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
		if (err_code) {
			nbl_ib_err(&rf->sc_dev, "%s cqp cmd failed,err=%d\n", __func__, err_code);
			break;
		}

		ret = nbl_hw_cache_handle(nbl_dev, cache_type, dump_mask, (u8 *)key_buf.va,
					  (NBL_CACHE_KEY_BASE_SIZE * query_once_num),
					  (u8 *)data_buf.va, (cache_data_size * query_once_num));
		count += ret;

		ix += query_once_num;
	}

	nbl_dev_info(&rf->pcidev->dev, "[cache] dump hw cache total valid num(%d)\n", count);

	kfree(in);
free_key:
	dma_free_coherent(sc_dev->hw->device, key_buf.size, key_buf.va, key_buf.pa);
free_data:
	dma_free_coherent(sc_dev->hw->device, data_buf.size, data_buf.va, data_buf.pa);

	return err_code;
}

void nbl_clear_hw_cache(struct nbl_pci_f *rf, enum nbl_cqp_cache_type cache_type)
{
	int ret_val;
	u8 in[NBL_GRC_INPUT_SIZE] = {};
	u8 out[NBL_GRC_OUTPUT_SIZE] = {};
	u8 data_len = 0;
	struct grc_cache_msg_header *head;
	struct clear_cache_req req = {};

	if (NBL_RF_TO_HW_VER(rf) >= NBL_VER_3)
		return;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_CLEAR_CACHE;
	head->payload_len = sizeof(req);
	data_len += sizeof(struct grc_cache_msg_header);
	req.cache_type = cache_type;

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_pr_err("clear cache %d cmd err=%d", cache_type, ret_val);
}

void nbl_dump_sqe(struct nbl_device *nbl_dev, u32 dump_mask)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_qp *qp;
	struct nbl_uk_qp *uk_qp;
	struct nbl_sc_qp *sc_qp;
	u16 qpn, pi;
	u64 dst_addr, *src_addr, temp_addr;
	void *addr;
	int base_idx, base_addr_delta;
	u32 sq_size, loc;
	int quanta_size = sizeof(struct nbl_qp_block);

	qpn = dump_mask & NBL_DEBUGFS_DUMP_SQE_COMMAND_QPN_MASK;
	if (qpn == 1) {
		nbl_ib_err(sc_dev, "qp1 no sq wqe");
		return;
	}

	qp = rf->qp_table[qpn];
	if (!qp) {
		nbl_ib_err(sc_dev, "no qp: %d", qpn);
		return;
	}
	sc_qp = &qp->sc_qp;
	uk_qp = &qp->sc_qp.uk_qp;
	/* uk_qp.sq_size is ilog2, the unit of sq_size is a block (64Byte) */
	sq_size = (1 << uk_qp->sq_size) << NBL_SQWQE_BLOCK_SHIFT;

	pi = dump_mask >> NBL_DEBUGFS_DUMP_SQE_COMMAND_PI_SHIFT;
	if (pi == 0)
		pi = 1;
	nbl_dev_info(&rf->pcidev->dev, "qpn: %d, sq_size: %d, head: %d, tail: %d, size: %d, dump loc: %d\n",
			qpn, sq_size, uk_qp->sq_ring.head,
			uk_qp->sq_ring.tail, uk_qp->sq_ring.size, pi);

	/* find the base addr that base addr + 4K contains last send wqe */
	loc = (pi - 1) * quanta_size;
	base_idx = loc / NBL_ADAPTER_PAGE_SIZE;
	base_addr_delta = base_idx * NBL_ADAPTER_PAGE_SIZE;

	/* page mode */
	if (sc_qp->sq_pm) {
		nbl_dev_info(&rf->pcidev->dev, "DUMP SQ WQE, LEVEL 1");
		src_addr = (sc_qp->sqmem.va + base_idx * NBL_LEVEL1_PAGE_ADDR_SIZE);
		memcpy(&dst_addr, src_addr, NBL_LEVEL1_PAGE_ADDR_SIZE);
		temp_addr = ((be64_to_cpu(dst_addr)) & NBL_LEVEL1_PAGE_ADDR_MASK);
		nbl_dev_info(&rf->pcidev->dev, "idx :%d, temp_addr:%llx\n", base_idx, temp_addr);
		addr =  phys_to_virt(temp_addr);
		nbl_dump_hex(rf, addr, SZ_4K);
	} else {
		if (qp->user_mode)
			addr = phys_to_virt(nbl_get_first_sg_dma_addr(sc_qp->sqbuf.umem));
		else
			addr = sc_qp->sqmem.va;
		nbl_dev_info(&rf->pcidev->dev, "DUMP SQ WQE, LEVEL 0, addr: %p\n",
				addr + base_addr_delta);
		nbl_dump_hex(rf, addr + base_addr_delta, SZ_4K);
	}
}
