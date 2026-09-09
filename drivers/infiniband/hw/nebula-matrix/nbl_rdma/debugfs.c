// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/list.h>
#include <linux/time.h>

#include "counters.h"
#include "dbgfs.h"
#include "qp.h"

static struct dentry *nbl_dbg_dir;
static struct dentry *rdma_dbg_dir;

const struct rdma_stat_desc nbl_vf_stats_names[] = {
	{"rx_resp", 0, NULL},
	{"rx_req", 0, NULL},
	{"rx_qpn_err", 0, NULL},
	{"rx_err", 0, NULL},
	{"tx_resp", 0, NULL},
	{"tx_req", 0, NULL},
	{"tx_qpn_err", 0, NULL},
	{"tx_err", 0, NULL},
};

const char *const nbl_qp_opcode_stats_names[] = {
		/* Rx rc opcode */
	[NBL_STATS_TYPE_RX_RC_OP_SEND_FIRST_PAYLD] = "Rx rc send first",
	[NBL_STATS_TYPE_RX_RC_OP_SEND_MIDDLE_PAYLD] = "Rx rc send middle",
	[NBL_STATS_TYPE_RX_RC_OP_SEND_LAST_PAYLD] = "Rx rc send last",
	[NBL_STATS_TYPE_RX_RC_OP_SEND_LAST_IMMD_PAYLD] =
		"Rx rc send last immediate",
	[NBL_STATS_TYPE_RX_RC_OP_SEND_ONLY_PAYLD] = "Rx rc send only",
	[NBL_STATS_TYPE_RX_RC_OP_SEND_ONLY_IMMD_PAYLD] =
		"Rx rc send only immediate",
	[NBL_STATS_TYPE_RX_RC_OP_WRITE_FIRST_PAYLD] = "Rx rc write first",
	[NBL_STATS_TYPE_RX_RC_OP_WRITE_MIDDLE_PAYLD] = "Rx rc write middle",
	[NBL_STATS_TYPE_RX_RC_OP_WRITE_LAST_PAYLD] = "Rx rc write last",
	[NBL_STATS_TYPE_RX_RC_OP_WRITE_LAST_IMMD_PAYLD] =
		"Rx rc write last immediate",
	[NBL_STATS_TYPE_RX_RC_OP_WRITE_ONLY_PAYLD] = "Rx rc write only",
	[NBL_STATS_TYPE_RX_RC_OP_WRITE_ONLY_IMMD_PAYLD] =
		"Rx rc write only immediate",
	[NBL_STATS_TYPE_RX_RC_OP_REQ_RETH] = "Rx rc read request",
	[NBL_STATS_TYPE_RX_RC_OP_RESP_FIRST_AETH_PAYLD] =
		"Rx rc read response first",
	[NBL_STATS_TYPE_RX_RC_OP_RESP_MIDDLE_AETH_PAYLD] =
		"Rx rc read response middle",
	[NBL_STATS_TYPE_RX_RC_OP_RESP_LAST_AETH_PAYLD] =
		"Rx rc read response last",
	[NBL_STATS_TYPE_RX_RC_OP_RESP_ONLY_AETH_PAYLD] =
		"Rx rc response only",
	[NBL_STATS_TYPE_RX_RC_OP_ACK_AETH] = "Rx rc ack",
	[NBL_STATS_TYPE_RX_RC_OP_ATOMIC_ACK_AETH] = "Rx rc Atomic ack",
	[NBL_STATS_TYPE_RX_RC_OP_CMPSWAP_AETH] = "Rx CmpSwap AtomicETH",
	[NBL_STATS_TYPE_RX_RC_OP_FETCHADD_AETH] = "Rx FetchAdd AtomicETH",
	[NBL_STATS_TYPE_RX_RC_OP_RSV_21] = "reserved",
	[NBL_STATS_TYPE_RX_RC_OP_SEND_LAST_INVALIDATE_IETH] =
		"Rx rc send last invalidate",
	[NBL_STATS_TYPE_RX_RC_OP_SEND_ONLY_INVALIDATE_IETH] =
		"Rx rc send only invalidate",

	/* Rx ud opcode */
	[NBL_STATS_TYPE_RX_UD_SEND_ONLY_DETH] = "Rx ud send only",
	[NBL_STATS_TYPE_RX_UD_SEND_ONLY_IMMD_DETH] = "Rx ud send only immediate",

	/* Rx normal db */
	[NBL_STATS_TYPE_RX_DB_OP_NORMAL_FLUSH_RQ] = "Rx normal db flush RQ",
	[NBL_STATS_TYPE_RX_DB_OP_NORMAL_RAQ] = "Rx normal db RAQ",

	[NBL_STATS_TYPE_RX_RSV_28] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_29] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_30] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_31] = "Rx flush RQ",

	[NBL_STATS_TYPE_SEND_OAM_REQ] = "Rx cc oamreq",
	[NBL_STATS_TYPE_SEND_OAM_ACK] = "Rx cc oamack",

	/* Rx rsv */
	[NBL_STATS_TYPE_RX_RSV_34] = "reserved",
	[NBL_STATS_RX_CNP] = "Rx CNP",
	[NBL_STATS_TYPE_RX_RSV_36] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_37] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_38] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_39] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_40] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_41] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_42] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_43] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_44] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_45] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_46] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_47] = "reserved",

	/* Tx drop DB */
	[NBL_STATS_TYPE_TX_DB_OP_DROP_INVAILD] = "Tx drop db invalid",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_SWSQ] = "Tx drop db SWSQ",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_TXPSQ] = "Tx drop db TXP SQ",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_TQRECHECK] = "Tx drop db TQ recheck",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_TQRNR] = "Tx drop db TQ RNR",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_TQRTO] = "Tx drop db TQ RTO",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_PSNERR] = "Tx drop db psnerr",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_RAQ] = "Tx drop db RAQ",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_TXPRAQ] = "Tx drop db TXP RAQ",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_TQ_WAITACK] = "Tx drop db TQ waitack",
	[NBL_STATS_TYPE_TX_DB_OP_DROP_OAMACK] = "Tx drop db oamack",

	/* Rx rsv */
	[NBL_STATS_TYPE_RX_RSV_59] = "Tx drop db CNP",
	[NBL_STATS_TYPE_RX_RSV_60] = "Tx drop db flush SQ",
	[NBL_STATS_TYPE_RX_RSV_61] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_62] = "reserved",
	[NBL_STATS_TYPE_RX_RSV_63] = "reserved",


	/* Tx rc opcode */
	[NBL_STATS_TYPE_TX_RC_OP_SEND_FIRST_PAYLD] = "Tx rc send first",
	[NBL_STATS_TYPE_TX_RC_OP_SEND_MIDDLE_PAYLD] = "Tx rc send middle",
	[NBL_STATS_TYPE_TX_RC_OP_SEND_LAST_PAYLD] = "Tx rc send last",
	[NBL_STATS_TYPE_TX_RC_OP_SEND_LAST_IMMD_PAYLD] =
		"Tx rc send last immediate",
	[NBL_STATS_TYPE_TX_RC_OP_SEND_ONLY_PAYLD] = "Tx rc send only",
	[NBL_STATS_TYPE_TX_RC_OP_SEND_ONLY_IMMD_PAYLD] =
		"Tx rc send only immediate ",
	[NBL_STATS_TYPE_TX_RC_OP_WRITE_FIRST_PAYLD] = "Tx rc write first",
	[NBL_STATS_TYPE_TX_RC_OP_WRITE_MIDDLE_PAYLD] = "Tx rc write middle",
	[NBL_STATS_TYPE_TX_RC_OP_WRITE_LAST_PAYLD] = "Tx rc write last",
	[NBL_STATS_TYPE_TX_RC_OP_WRITE_LAST_IMMD_PAYLD] =
		"Tx rc write last immediate",
	[NBL_STATS_TYPE_TX_RC_OP_WRITE_ONLY_PAYLD] = "Tx rc write only",
	[NBL_STATS_TYPE_TX_RC_OP_WRITE_ONLY_IMMD_PAYLD] =
		"Tx rc write only immediate",
	[NBL_STATS_TYPE_TX_RC_OP_REQ_RETH] = "Tx rc read request",
	[NBL_STATS_TYPE_TX_RC_OP_RESP_FIRST_AETH_PAYLD] =
		"Tx rc read response first",
	[NBL_STATS_TYPE_TX_RC_OP_RESP_MIDDLE_AETH_PAYLD] =
		"Tx rc read response middle",
	[NBL_STATS_TYPE_TX_RC_OP_RESP_LAST_AETH_PAYLD] =
		"Tx rc read response last",
	[NBL_STATS_TYPE_TX_RC_OP_RESP_ONLY_AETH_PAYLD] =
		"Tx rc read response only",
	[NBL_STATS_TYPE_TX_RC_OP_ACK_AETH] = "Tx rc ack",
	[NBL_STATS_TYPE_TX_RC_OP_ATOMIC_ACK_AETH] = "Tx rc Atomic ack",
	[NBL_STATS_TYPE_TX_RC_OP_CMPSWAP_AETH] = "Tx rc CmpSwap AtomicETH",
	[NBL_STATS_TYPE_TX_RC_OP_FETCHADD_AETH] = "Tx rc FetchAdd AtomicETH",
	[NBL_STATS_TYPE_TX_RC_OP_RSV_85] = "reserved",
	[NBL_STATS_TYPE_TX_RC_OP_SEND_LAST_INVALIDATE_IETH] =
		"Tx rc send last invalidate",
	[NBL_STATS_TYPE_TX_RC_OP_SEND_ONLY_INVALIDATE_IETH] =
		"Tx rc send only invalidate",

	/* Tx ud opcode */
	[NBL_STATS_TYPE_TX_UD_SEND_ONLY_DETH] = "Tx ud send only",
	[NBL_STATS_TYPE_TX_UD_SEND_ONLY_IMMD_DETH] = "Tx ud send only immediate",

	/* local */
	[NBL_STATS_TYPE_TX_OP_BIND_MW_LOCAL] = "Tx Bind MW local",
	[NBL_STATS_TYPE_TX_OP_LOCAL_INV_LOCAL] = "Tx local INV local",
	[NBL_STATS_TYPE_TX_OP_FRMR_LOCAL] = "Tx FRMR local",
	[NBL_STATS_TYPE_TX_OP_NOP_FOR_LOCAL] = "Tx NOP local",

	/* Tx rsv*/
	[NBL_STATS_TYPE_TX_RSV_94] = "Tx flush SQ",
	[NBL_STATS_TYPE_TX_RSV_95] = "reserved",

	/* CC OAM */
	[NBL_STATS_TYPE_SD_OAM_REQ] = "Tx cc oamreq",
	[NBL_STATS_TYPE_SD_OAM_ACK] = "Tx cc oamack",

	/* Tx rsv*/
	[NBL_STATS_TYPE_TX_RSV_98] = "reserved",
	[NBL_STATS_TX_CNP] = "Tx CNP",
	[NBL_STATS_TYPE_TX_RSV_100] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_101] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_102] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_103] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_104] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_105] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_106] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_107] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_108] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_109] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_110] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_111] = "reserved",

	/* Tx normal DB */
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_INVALID] = "Tx normal db invalid",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_SWSQ] = "Tx normal db SWSQ",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_TXPSQ] = "Tx normal db TXP SQ",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_TQRECHECK] = "Tx normal db TQ recheck",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_TQRNR] = "Tx normal db TQ RNR",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_TQRTO] = "Tx normal db TQ RTO",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_PSNERR] = "Tx normal db psnerr",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_RAQ] = "Tx normal db RAQ",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_TXPRAQ] = "Tx normal db TXP RAQ",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_TQ_WAITACK] = "Tx normal db TQ waitack",
	[NBL_STATS_TYPE_TX_DB_OP_NORMAL_OAMACK] = "Tx normal db cc oamack",

	/* Tx rsv*/
	[NBL_STATS_TYPE_TX_RSV_123] = "Tx normal db CNP",
	[NBL_STATS_TYPE_TX_RSV_124] = "Tx normal db flush SQ",
	[NBL_STATS_TYPE_TX_RSV_125] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_126] = "reserved",
	[NBL_STATS_TYPE_TX_RSV_127] = "reserved"
};

/**
 * dbg_vsnprintf -
 * @fmt: print formatting string
 */
static void dbg_vsnprintf(struct nbl_device *dev, char *fmt, ...) __attribute__
	((format(gnu_printf, 2, 3)));
static void dbg_vsnprintf(struct nbl_device *dev, char *fmt, ...)
{
	int cnt;
	va_list argp;
	struct nbl_func_file *func_file = &dev->func_stat->func_file;

	va_start(argp, fmt);
	cnt = vsnprintf(func_file->buf + func_file->used_len,
		func_file->total_len - func_file->used_len, fmt, argp);
	va_end(argp);

	func_file->used_len += cnt;
}

/**
 * stat_cmd_help -
 */
static void stat_cmd_help(struct nbl_device *nbl_dev)
{
	dbg_vsnprintf(nbl_dev, "Statistics commands:\n");

	dbg_vsnprintf(nbl_dev, " get func-stat\n");
	dbg_vsnprintf(nbl_dev, " get stat-id <stat-id>\n");
	dbg_vsnprintf(nbl_dev, " get err-qpn\n");
	dbg_vsnprintf(nbl_dev, " get all\n\n");

	dbg_vsnprintf(nbl_dev, " clear func-stat\n");
	dbg_vsnprintf(nbl_dev, " clear stat-id <stat-id>\n");
	dbg_vsnprintf(nbl_dev, " clear err-qpn\n");
	dbg_vsnprintf(nbl_dev, " clear all\n\n");

	dbg_vsnprintf(nbl_dev, " qp-stat add <qpn>\n");
	dbg_vsnprintf(nbl_dev, " qp-stat del <qpn>\n");
	dbg_vsnprintf(nbl_dev, " qp-stat get <qpn>\n");
	dbg_vsnprintf(nbl_dev, " qp-stat mod <qpn> <stat-id>\n\n");

	dbg_vsnprintf(nbl_dev, " lsstat\n");
	dbg_vsnprintf(nbl_dev, " time <time>\n");
	dbg_vsnprintf(nbl_dev, "\tConfigure an appropriate value of ");
	dbg_vsnprintf(nbl_dev, "60000-%dms, ", NBL_STATS_INTERVAL_MAX);
	dbg_vsnprintf(nbl_dev, "to update the software statistics regularly\n");

	dbg_vsnprintf(nbl_dev, " enable\n"
		"\tPerform opcode statistics on error messages\n");
	dbg_vsnprintf(nbl_dev, " disable\n"
		"\tDo not perform opcode statistics on error messages\n\n");
}

/**
 * get_id
 * @cbuf: input string
 * Return id if success, -1 if failed
 */
static u32 get_id(char *cbuf)
{
	int id = 0;
	char str[NBL_QPN_STR_LEN_MAX + 1];
	int offset;
	int rc;

	if (sscanf(cbuf, "%s%n", str, &offset) <= 0) {
		nbl_pr_err("failed to parse string(%s)\n", cbuf);
		return -1;
	}

	rc = kstrtoint(str, 0, &id);
	if (rc) {
		nbl_pr_err("Conversion string error. (str:%s)\n", str);
		return -1;
	}
	nbl_pr_dbg("get a id:%d by string(cbuf:%s, offset:%d)\n",
		id, cbuf, offset);

	return id;
}

static bool check_qpid_is_exist(struct nbl_device *nbl_dev, u32 qp_id)
{
	struct nbl_qp *qp = NULL;

	if (qp_id >= nbl_dev->rf->max_qp) {
		nbl_pr_err("qp_id:%d >= max\n", qp_id);
		return false;
	}

	qp = nbl_dev->rf->qp_table[qp_id];
	if (!qp) {
		nbl_pr_err("qp_table[%d] is NULL\n", qp_id);
		return false;
	}

	nbl_pr_info("qp:%d is exist\n", qp_id);

	return true;
}

static bool check_statid_is_exist(u8 stat_id)
{
	if (stat_id >= NBL_STATS_GROUP_START_NUM &&
		stat_id < NBL_STATS_GROUP_NUM)
		return true;
	else
		return false;
}

static void set_stats_period_cmd(struct nbl_device *nbl_dev, u32 time)
{
	if (NBL_STATS_INTERVAL_MIN <= time && NBL_STATS_INTERVAL_MAX >= time) {
		nbl_hw_stats_stop_timer(nbl_dev);
		nbl_hw_stats_start_timer(nbl_dev, time);
		dbg_vsnprintf(nbl_dev, "Configuration succeeded.\n");
	} else {
		dbg_vsnprintf(nbl_dev, "Error:Configure an appropriate value of ");
		dbg_vsnprintf(nbl_dev, "60000-%dms, ", NBL_STATS_INTERVAL_MAX);
		dbg_vsnprintf(nbl_dev, "to update the software statistics regularly\n");
	}
}

static void append_vf_stats(struct nbl_device *nbl_dev)
{
	int i;

	/* 4.append buffer from dma */
	dbg_vsnprintf(nbl_dev, "func-stat  :%s\n", nbl_dev->ibdev.name);
	for (i = 0; i < NBL_VF_CNTS; i++) {
		if (nbl_dev->func_stat->vf_mem[i].total_stats == 0)
			continue;
		dbg_vsnprintf(nbl_dev, "%-11s:0x%llx\n", nbl_vf_stats_names[i].name,
			nbl_dev->func_stat->vf_mem[i].total_stats);
	}
}

static int dump_vf_stats_cmd(struct nbl_device *nbl_dev)
{
	int ret;

	ret = update_vf_stats(nbl_dev);
	if (ret)
		goto err_info;

	append_vf_stats(nbl_dev);

	return 0;

err_info:
	if (ret == -ENOMEM)
		dbg_vsnprintf(nbl_dev, "failed to alloc dma buffer\n");
	else if (ret == -EBUSY)
		dbg_vsnprintf(nbl_dev, "HW is busy, please update again later\n");
	else
		dbg_vsnprintf(nbl_dev, "failed to get statistics, ret:%d\n", ret);
	return ret;
}

static void append_qp_opcode_stats(struct nbl_device *nbl_dev, int stat_id)
{
	int i;
	char *stat_out;
	const char *stat_name;

	dbg_vsnprintf(nbl_dev, "--------------------------------------------------\n");
	for (i = 0; i < NBL_STATS_GROUP_OPCODE_CNTS; i++) {
		if (nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats == 0)
			continue;
		stat_name = nbl_qp_opcode_stats_names[i];
		if (CHECK_STAT_NAME_IS_PACKET(i))
			stat_out = kasprintf(GFP_KERNEL, "%s(packets):", stat_name);
		else
			stat_out = kasprintf(GFP_KERNEL, "%s:", stat_name);

		dbg_vsnprintf(nbl_dev, "%-40s%lld\n", stat_out,
			nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats);
		kfree(stat_out);
	}
	dbg_vsnprintf(nbl_dev, "--------------------------------------------------\n");
}

static void append_qp_errorcode_stats(struct nbl_device *nbl_dev, int stat_id)
{
	int i;
	int err_idx;
	int normal_flag = 0;
	char *error_name;

	for (i = NBL_STATS_GROUP_ERR_CNTS; i < NBL_STATS_GROUP_CNTS; i++) {
		if (nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats == 0)
			continue;
		err_idx = i - NBL_STATS_GROUP_ERR_CNTS;
		if (CHECK_NORMAL_ERRCODE_STAT(err_idx)) {
			normal_flag = 1;
			error_name = kasprintf(GFP_KERNEL, "%x:", err_idx);
			dbg_vsnprintf(nbl_dev, "errorcode 0x%-5s%lld\n",
				error_name,
				nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats);
			kfree(error_name);
		}
	}

	if (normal_flag == 1)
		dbg_vsnprintf(nbl_dev, "--------------------------------------------------\n");

	for (i = NBL_STATS_GROUP_ERR_CNTS; i < NBL_STATS_GROUP_CNTS; i++) {
		if (nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats == 0)
			continue;
		err_idx = i - NBL_STATS_GROUP_ERR_CNTS;
		if (CHECK_NORMAL_ERRCODE_STAT(err_idx))
			continue;
		error_name = kasprintf(GFP_KERNEL, "%x:", err_idx);
		dbg_vsnprintf(nbl_dev, "errorcode 0x%-5s%lld\n",
			error_name,
			nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats);
		kfree(error_name);
	}
	dbg_vsnprintf(nbl_dev, "--------------------------------------------------\n");

}

static void append_qp_stats(struct nbl_device *nbl_dev, int stat_id)
{
	dbg_vsnprintf(nbl_dev, "stat-id : %d\n", stat_id);
	append_qp_opcode_stats(nbl_dev, stat_id);
	append_qp_errorcode_stats(nbl_dev, stat_id);
}

static int dump_qp_stats_cmd(struct nbl_device *nbl_dev, int stat_id)
{
	int ret;

	if (!check_statid_is_exist(stat_id)) {
		dbg_vsnprintf(nbl_dev, "stat_id %d is illegal\n", stat_id);
		return -EINVAL;
	}

	ret = update_qp_stats(nbl_dev, stat_id);
	if (ret)
		goto err_info;

	append_qp_stats(nbl_dev, stat_id);

	return 0;

err_info:
	if (ret == -EINVAL)
		dbg_vsnprintf(nbl_dev, "stat_id:%d is illegal\n", stat_id);
	else if (ret == -ENOMEM)
		dbg_vsnprintf(nbl_dev, "failed to alloc dma buffer\n");
	else if (ret == -EBUSY)
		dbg_vsnprintf(nbl_dev, "HW is busy, please update again later\n");
	else
		dbg_vsnprintf(nbl_dev, "failed to get statistics\n");

	return ret;
}

static void append_err_qpn_stats(struct nbl_device *nbl_dev)
{
	if (nbl_dev->func_stat->err_qpn_mem[0].total_stats != 0)
		dbg_vsnprintf(nbl_dev, "tx_err_qpn :0x%llx\n",
			nbl_dev->func_stat->err_qpn_mem[0].total_stats);
	if (nbl_dev->func_stat->err_qpn_mem[1].total_stats != 0)
		dbg_vsnprintf(nbl_dev, "rx_err_qpn :0x%llx\n",
			nbl_dev->func_stat->err_qpn_mem[1].total_stats);
}

static int dump_err_qpn_stats_cmd(struct nbl_device *nbl_dev)
{
	int ret;

	ret = update_err_qpn_stats(nbl_dev);
	if (ret)
		goto err_info;

	append_err_qpn_stats(nbl_dev);

	return 0;

err_info:
	if (ret == -ENOMEM)
		dbg_vsnprintf(nbl_dev, "failed to alloc dma buffer\n");
	else if (ret == -EBUSY)
		dbg_vsnprintf(nbl_dev, "HW is busy, please update again later\n");
	else
		dbg_vsnprintf(nbl_dev, "failed to get statistics\n");
	return ret;
}

static void append_all_stats(struct nbl_device *nbl_dev)
{
	int i;

	append_vf_stats(nbl_dev);

	for (i = NBL_STATS_GROUP_START_NUM; i < NBL_STATS_GROUP_NUM; i++) {
		if (nbl_dev->func_stat->stat_id_used_cnt[i] == 0)
			continue;
		append_qp_stats(nbl_dev, i);
	}

	append_err_qpn_stats(nbl_dev);
}

static int dump_all_stats_cmd(struct nbl_device *nbl_dev)
{
	int ret;

	ret = update_all_stats(nbl_dev);
	if (ret)
		goto err_info;

	append_all_stats(nbl_dev);

	return 0;

err_info:
	if (ret == -EINVAL)
		dbg_vsnprintf(nbl_dev, "illegal parameter\n");
	else if (ret == -ENOMEM)
		dbg_vsnprintf(nbl_dev, "failed to alloc dma buffer\n");
	else if (ret == -EBUSY)
		dbg_vsnprintf(nbl_dev, "HW is busy, please update again later\n");
	else
		dbg_vsnprintf(nbl_dev, "failed to get statistics\n");
	return ret;
}

static void get_stats_cmd(struct nbl_device *nbl_dev, char *cbuf)
{
	/* function stat */
	if (strncasecmp(cbuf, "func-stat", strlen("func-stat")) == 0)
		(void)dump_vf_stats_cmd(nbl_dev);
	/* qp stat */
	else if (strncasecmp(cbuf, "stat-id ", strlen("stat-id ")) == 0)
		(void)dump_qp_stats_cmd(nbl_dev, get_id(&cbuf[strlen("stat-id ")]));
	/* get err-qpn */
	else if (strncasecmp(cbuf, "err-qpn", strlen("err-qpn")) == 0)
		(void)dump_err_qpn_stats_cmd(nbl_dev);
	/* all stat */
	else if (strncasecmp(cbuf, "all", strlen("all")) == 0)
		(void)dump_all_stats_cmd(nbl_dev);
	else
		stat_cmd_help(nbl_dev);
}

static void clear_stats_cmd(struct nbl_device *nbl_dev, char *cbuf)
{
	/* clear function stat */
	u32 stat_id;
	struct nbl_stats_reg_info reg_info = { 0 };
	u16 func_id = nbl_dev->rf->sc_dev.function_id;

	reg_info.op_status = 1;
	reg_info.op_rc = OP_STATS_CLEAR;
	if (strncasecmp(cbuf, "func-stat", strlen("func-stat")) == 0) {
		reg_info.op_table_sel = NBL_VF_TABLE;
		reg_info.op_id = func_id;
		reg_info.op_len = 1;
	} else if (strncasecmp(cbuf, "stat-id ", strlen("stat-id ")) == 0) {
		stat_id = get_id(&cbuf[strlen("stat-id ")]);
		if (!check_statid_is_exist(stat_id)) {
			dbg_vsnprintf(nbl_dev, "stat-id %d is illegal\n", stat_id);
			return;
		}
		reg_info.op_table_sel = NBL_STATS_ID_TABLE;
		reg_info.op_id = stat_id;
		reg_info.op_len = 1;
	} else if (strncasecmp(cbuf, "err-qpn", strlen("err-qpn")) == 0) {
		reg_info.op_table_sel = NBL_ERR_QPN_TABLE;
		reg_info.op_id = func_id;
		reg_info.op_len = NBL_ERR_QPN_CNTS_PER_VF;
	} else if (strncasecmp(cbuf, "all", strlen("all")) == 0)
		reg_info.op_table_sel = NBL_CLEAR_ALL;
	else {
		stat_cmd_help(nbl_dev);
		return;
	}

	if (nbl_grc_hw_stat_clear(nbl_dev->rf, &reg_info)) {
		dbg_vsnprintf(nbl_dev, "clear failed\n");
		return;
	}

	nbl_stats_mem_clear(nbl_dev, &reg_info);

	dbg_vsnprintf(nbl_dev, "clear successfully\n");
}

void add_statid_of_qp_cmd(struct nbl_device *nbl_dev, u32 qp_id)
{
	unsigned long flags;
	struct nbl_qp *qp;
	u8 stat_id;
	struct nbl_qp_func *new_node;
	struct nbl_qp_ctx ctx_info = { 0 };
	int ret;
	struct nbl_rdma_stat *func_stat = nbl_dev->func_stat;
	struct nbl_pci_f *rf = nbl_dev->rf;

	if (!check_qpid_is_exist(nbl_dev, qp_id)) {
		dbg_vsnprintf(nbl_dev, "QP %d is illegal\n", qp_id);
		return;
	}
	qp = rf->qp_table[qp_id];
	stat_id = qp->ctx_info.stat_id;
	if (check_statid_is_exist(stat_id)) {
		dbg_vsnprintf(nbl_dev, "qp:%d already has statid:%d\n", qp_id, stat_id);
		return;
	}

	/* nbl_grc_exec in:vf_id + qpn out:stat_id */
	ret = nbl_grc_add_stat_id(rf, rf->sc_dev.function_id, qp_id, &stat_id);
	if (ret) {
		dbg_vsnprintf(nbl_dev, "failed to alloc stat_id:%d\n", stat_id);
		return;
	}

	if (!check_statid_is_exist(stat_id)) {
		dbg_vsnprintf(nbl_dev, "all stat groups is used\n");
		return;
	}
	nbl_pr_info("get stat_id:%d for qp:%d\n", stat_id, qp_id);

	if (func_stat->stat_id_used_cnt[stat_id] != 0) {
		dbg_vsnprintf(nbl_dev, "stat resource error\n");
		return;
	}

	/* cqp add hw qpc stat id */
	ctx_info.stat_id = stat_id;
	ret = nbl_modify_hw_qpc(qp, &ctx_info, NBL_QPC_STAT_ID_MASK);
	if (ret) {
		nbl_pr_err("failed to add stat_id of qp:%d, ret:%d\n",
			qp_id, ret);
		dbg_vsnprintf(nbl_dev, "failed to add stat_id of qp:%d, ret:%d\n",
			qp_id, ret);
		return;
	}

	spin_lock_irqsave(&qp->lock, flags);
	qp->ctx_info.stat_id = stat_id;
	spin_unlock_irqrestore(&qp->lock, flags);

	INIT_LIST_HEAD(&func_stat->stat_head[stat_id]);
	spin_lock_init(&func_stat->stat_head_lock[stat_id]);

	new_node = kzalloc(sizeof(struct nbl_qp_func), GFP_KERNEL);
	if (!new_node)
		return;

	new_node->func_id = rf->sc_dev.function_id;
	new_node->qpn = qp_id;
	INIT_LIST_HEAD(&new_node->list);

	spin_lock_irqsave(&func_stat->stat_head_lock[stat_id], flags);
	list_add_tail(&new_node->list, &func_stat->stat_head[stat_id]);
	spin_unlock_irqrestore(&func_stat->stat_head_lock[stat_id], flags);

	func_stat->stat_id_used_cnt[stat_id]++;

	dbg_vsnprintf(nbl_dev, "add stat_id:%d of qp:%d successfully\n",
		stat_id, qp_id);
}

static void del_statid_of_qp_cmd(struct nbl_device *nbl_dev, u32 qp_id)
{
	unsigned long flags;
	struct nbl_qp *qp;
	u8 stat_id;
	struct nbl_qp_ctx ctx_info = { 0 };
	int ret;
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_rdma_stat *func_stat = nbl_dev->func_stat;
	struct nbl_qp_func *cur_node;
	struct nbl_qp_func *tmp_node;

	if (!check_qpid_is_exist(nbl_dev, qp_id)) {
		dbg_vsnprintf(nbl_dev, "QP %d is not exist\n", qp_id);
		return;
	}
	qp = rf->qp_table[qp_id];
	stat_id = qp->ctx_info.stat_id;
	if (!check_statid_is_exist(stat_id)) {
		dbg_vsnprintf(nbl_dev, "qp %d don't have stat_id\n", qp_id);
		return;
	}

	/* cqp del hw qpc stat id */
	ret = nbl_modify_hw_qpc(qp, &ctx_info, NBL_QPC_STAT_ID_MASK);
	if (ret) {
		dbg_vsnprintf(nbl_dev, "failed to del stat_id of qp:%d, ret:%d\n",
			qp_id, ret);
		return;
	}

	func_stat->stat_id_used_cnt[stat_id]--;

	spin_lock_irqsave(&qp->lock, flags);
	qp->ctx_info.stat_id = 0;
	spin_unlock_irqrestore(&qp->lock, flags);

	spin_lock_irqsave(&func_stat->stat_head_lock[stat_id], flags);
	list_for_each_entry_safe(cur_node, tmp_node, &func_stat->stat_head[stat_id],
							list) {
		if (cur_node->func_id == rf->sc_dev.function_id &&
		cur_node->qpn == qp_id) {
			list_del(&cur_node->list);
			kfree(cur_node);
			break;
		}
	}
	spin_unlock_irqrestore(&func_stat->stat_head_lock[stat_id], flags);

	/* nbl_grc_exec IN:stat_id + vf_id + qpn */
	ret = nbl_grc_del_stat_id(rf, stat_id, rf->sc_dev.function_id, qp_id);
	if (ret) {
		dbg_vsnprintf(nbl_dev, "failed to del stat_id:%d\n", stat_id);
		return;
	}

	dbg_vsnprintf(nbl_dev, "delete stat_id:%d of qp:%d successfully\n", stat_id,
			qp_id);

}

static void get_statid_of_qp_cmd(struct nbl_device *nbl_dev, u32 qp_id)
{
	u32 stat_id;

	if (!check_qpid_is_exist(nbl_dev, qp_id)) {
		dbg_vsnprintf(nbl_dev, "QP %d is not exist\n", qp_id);
		return;
	}
	stat_id = (u32)nbl_dev->rf->qp_table[qp_id]->ctx_info.stat_id;

	dbg_vsnprintf(nbl_dev, "get successfully,qp:%d <--> stat_id:%d\n",
		qp_id, stat_id);
}

static void mod_statid_of_qp_cmd(struct nbl_device *nbl_dev, char *cbuf)
{
	int qp_id;
	u8 stat_id;
	u8 stat_id_old;
	char qp_id_str[NBL_QPN_STR_LEN_MAX + 1];
	int qp_id_offset;
	int rc;
	struct nbl_qp *qp = NULL;
	unsigned long flags;
	struct nbl_qp_ctx ctx_info = { 0 };
	int ret;
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_rdma_stat *func_stat = nbl_dev->func_stat;
	struct nbl_qp_func *cur_node;
	struct nbl_qp_func *tmp_node;
	struct nbl_qp_func *new_node;

	/* check qp_id */
	if (sscanf(cbuf, "%s%n", qp_id_str, &qp_id_offset) <= 0) {
		dbg_vsnprintf(nbl_dev, "failed to parse string:[%s]\n", cbuf);
		return;
	}

	rc = kstrtoint(qp_id_str, 0, &qp_id);
	if (rc) {
		dbg_vsnprintf(nbl_dev, "Conversion string:[%s] error\n", qp_id_str);
		return;
	}
	if (!check_qpid_is_exist(nbl_dev, qp_id)) {
		dbg_vsnprintf(nbl_dev, "QP %d is not exist\n", qp_id);
		return;
	}
	qp = rf->qp_table[qp_id];

	/* check stat_id */
	stat_id = (u8)get_id(cbuf + qp_id_offset + 1);
	if (!check_statid_is_exist(stat_id)) {
		dbg_vsnprintf(nbl_dev, "stat_id %d is illegal\n", stat_id);
		return;
	}

	/* modify qp_id stat_id */
	stat_id_old = qp->ctx_info.stat_id;
	if (stat_id == stat_id_old) {
		dbg_vsnprintf(nbl_dev, "stat_id %d is the same as before\n", stat_id);
		return;
	}

	/* cqp mod hw qpc stat id */
	ctx_info.stat_id = stat_id;
	ret = nbl_modify_hw_qpc(qp, &ctx_info, NBL_QPC_STAT_ID_MASK);
	if (ret) {
		dbg_vsnprintf(nbl_dev, "failed to modify stat_id of qp:%d, ret:%d\n",
			qp_id, ret);
		return;
	}

	if (check_statid_is_exist(stat_id_old)) {
		func_stat->stat_id_used_cnt[stat_id_old]--;

		spin_lock_irqsave(&func_stat->stat_head_lock[stat_id_old], flags);
		list_for_each_entry_safe(cur_node, tmp_node,
		&func_stat->stat_head[stat_id_old], list) {
			if (cur_node->func_id == rf->sc_dev.function_id &&
			cur_node->qpn == qp_id) {
				list_del(&cur_node->list);
				kfree(cur_node);
				break;
			}
		}
		spin_unlock_irqrestore(&func_stat->stat_head_lock[stat_id_old], flags);
	}

	spin_lock_irqsave(&qp->lock, flags);
	qp->ctx_info.stat_id = stat_id;
	spin_unlock_irqrestore(&qp->lock, flags);

	if (func_stat->stat_id_used_cnt[stat_id] == 0) {
		INIT_LIST_HEAD(&func_stat->stat_head[stat_id]);
		spin_lock_init(&func_stat->stat_head_lock[stat_id]);
	}

	new_node = kzalloc(sizeof(struct nbl_qp_func), GFP_KERNEL);
	if (!new_node)
		return;
	new_node->func_id = rf->sc_dev.function_id;
	new_node->qpn = qp_id;
	INIT_LIST_HEAD(&new_node->list);

	spin_lock_irqsave(&func_stat->stat_head_lock[stat_id], flags);
	list_add_tail(&new_node->list, &func_stat->stat_head[stat_id]);
	spin_unlock_irqrestore(&func_stat->stat_head_lock[stat_id], flags);

	func_stat->stat_id_used_cnt[stat_id]++;

	/* nbl_grc_exec IN: func_id qpn stat_id_old stat_id */
	ret = nbl_grc_mod_stat_id(rf, stat_id_old, stat_id,
		rf->sc_dev.function_id, qp_id);
	if (ret) {
		dbg_vsnprintf(nbl_dev, "mod stat_id cmd err qpn:%d, old:%d, new:%d\n",
			qp_id, stat_id_old, stat_id);
		return;
	}
	dbg_vsnprintf(nbl_dev, "modify qp:%d stat_id:%d successfully\n",
		qp_id, stat_id);
}

static void ls_stat_cmd(struct nbl_device *nbl_dev)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_rdma_stat *func_stat = nbl_dev->func_stat;
	int i;
	u32 req_used_cnt;
	unsigned long flags;
	struct nbl_qp_func *cur_node;
	struct nbl_qp_func *tmp_node;

	dbg_vsnprintf(nbl_dev, "stat_id   used_cnt  (device_name:qpn) ......\r\n");
	for (i = NBL_STATS_GROUP_START_NUM; i < NBL_STATS_GROUP_NUM; i++) {
		if (func_stat->stat_id_used_cnt[i] == 0)
			continue;
		/* nbl_grc_exec IN:stat_id OUT:req_used_cnt */
		if (nbl_grc_get_used_cnt(rf, i, &req_used_cnt)) {
			dbg_vsnprintf(nbl_dev, "get used_cnt cmd err stat_id:%d\n", i);
			return;
		}

		dbg_vsnprintf(nbl_dev, "%-10d%-10d", i, req_used_cnt);

		spin_lock_irqsave(&func_stat->stat_head_lock[i], flags);
		list_for_each_entry_safe(cur_node, tmp_node,
								&func_stat->stat_head[i], list) {
			dbg_vsnprintf(nbl_dev, "(%s:%d) ",
				nbl_dev->ibdev.name, cur_node->qpn);
		}
		spin_unlock_irqrestore(&func_stat->stat_head_lock[i], flags);
		dbg_vsnprintf(nbl_dev, "\n");
	}
	dbg_vsnprintf(nbl_dev, "lsstat successfully\n");
}

static void manage_statid_of_qp_cmd(struct nbl_device *nbl_dev, char *cbuf)
{
	/* add stat id */
	if (strncasecmp(cbuf, "add ", strlen("add ")) == 0)
		add_statid_of_qp_cmd(nbl_dev, get_id(&cbuf[strlen("add ")]));

	/* delete stat id */
	else if (strncasecmp(cbuf, "del ", strlen("del ")) == 0)
		del_statid_of_qp_cmd(nbl_dev, get_id(&cbuf[strlen("del ")]));

	/* modify stat id */
	else if (strncasecmp(cbuf, "mod ", strlen("mod ")) == 0)
		mod_statid_of_qp_cmd(nbl_dev, &cbuf[strlen("mod ")]);

	/* clear all stat */
	else if (strncasecmp(cbuf, "get ", strlen("get ")) == 0)
		get_statid_of_qp_cmd(nbl_dev, get_id(&cbuf[strlen("get ")]));

	else
		stat_cmd_help(nbl_dev);
}

static void set_opcode_stats_has_errcode_cmd(struct nbl_device *nbl_dev,
					     bool enable)
{
	struct nbl_pci_f *rf = nbl_dev->rf;

	if (nbl_grc_hw_stat_errcode_enable(rf, enable))
		dbg_vsnprintf(nbl_dev, "set hw errcode statistics cmd failed\n");
	else
		dbg_vsnprintf(nbl_dev, "set hw errcode statistics cmd successfully\n");
}

/**
 * nbl_dbg_stat_read
 * @filp: the opened file
 * @buf: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 */
static ssize_t nbl_dbg_stat_read(struct file *filp, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct nbl_device *nbl_dev = filp->private_data;
	struct nbl_func_file *func_file = &nbl_dev->func_stat->func_file;

	nbl_pr_dbg("copy continue[%lld/%ld]\n", *ppos, func_file->used_len);
	return simple_read_from_buffer(buf, count, ppos,
		&func_file->buf[*ppos], func_file->used_len);
}

/**
 * nbl_dbg_stat_write
 * @filp: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t nbl_dbg_stat_write(struct file *filp, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	int bytes_not_copied;
	struct nbl_device *nbl_dev = filp->private_data;
	struct nbl_func_file *func_file = &nbl_dev->func_stat->func_file;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(func_file->cmd))
		return -ENOSPC;

	bytes_not_copied = copy_from_user(func_file->cmd, buf, count);
	if (bytes_not_copied < 0)
		return bytes_not_copied;
	if (bytes_not_copied > 0)
		count -= bytes_not_copied;

	func_file->cmd[count - 1] = '\0';
	*ppos = 0;
	func_file->used_len = 0;

	nbl_pr_dbg("not_copied:%d, count:%ld, cmd:[%s]\n",
		bytes_not_copied, count, func_file->cmd);

	if (strncasecmp(func_file->cmd, "get ", strlen("get ")) == 0)
		get_stats_cmd(nbl_dev, &func_file->cmd[strlen("get ")]);
	else if (strncasecmp(func_file->cmd, "lsstat", strlen("lsstat")) == 0)
		ls_stat_cmd(nbl_dev);
	else if (strncasecmp(func_file->cmd, "clear ", strlen("clear ")) == 0)
		clear_stats_cmd(nbl_dev, &func_file->cmd[strlen("clear ")]);
	else if (strncasecmp(func_file->cmd, "qp-stat ", strlen("qp-stat ")) == 0)
		manage_statid_of_qp_cmd(nbl_dev, &func_file->cmd[strlen("qp-stat ")]);
	else if (strncasecmp(func_file->cmd, "enable", strlen("enable")) == 0)
		set_opcode_stats_has_errcode_cmd(nbl_dev, true);
	else if (strncasecmp(func_file->cmd, "disable", strlen("disable")) == 0)
		set_opcode_stats_has_errcode_cmd(nbl_dev, false);
	else if (strncasecmp(func_file->cmd, "time ", strlen("time ")) == 0)
		set_stats_period_cmd(nbl_dev, get_id(&func_file->cmd[strlen("time ")]));
	else
		stat_cmd_help(nbl_dev);

	return count;
}

ssize_t config_stats_param(struct nbl_device *nbl_dev, char *lbuf, size_t count)
{
	struct nbl_func_file *func_file = &nbl_dev->func_stat->func_file;

	if (count >= sizeof(func_file->cmd))
		return -ENOSPC;

	strscpy(func_file->cmd, lbuf, sizeof(func_file->cmd));
	func_file->used_len = 0;

	if (strncasecmp(func_file->cmd, "get ", strlen("get ")) == 0)
		get_stats_cmd(nbl_dev, &func_file->cmd[strlen("get ")]);
	else if (strncasecmp(func_file->cmd, "lsstat", strlen("lsstat")) == 0)
		ls_stat_cmd(nbl_dev);
	else if (strncasecmp(func_file->cmd, "clear ", strlen("clear ")) == 0)
		clear_stats_cmd(nbl_dev, &func_file->cmd[strlen("clear ")]);
	else if (strncasecmp(func_file->cmd, "qp-stat ", strlen("qp-stat ")) == 0)
		manage_statid_of_qp_cmd(nbl_dev, &func_file->cmd[strlen("qp-stat ")]);
	else if (strncasecmp(func_file->cmd, "enable", strlen("enable")) == 0)
		set_opcode_stats_has_errcode_cmd(nbl_dev, true);
	else if (strncasecmp(func_file->cmd, "disable", strlen("disable")) == 0)
		set_opcode_stats_has_errcode_cmd(nbl_dev, false);
	else if (strncasecmp(func_file->cmd, "time ", strlen("time ")) == 0)
		set_stats_period_cmd(nbl_dev, get_id(&func_file->cmd[strlen("time ")]));
	else
		stat_cmd_help(nbl_dev);

	return count;
}

static const struct file_operations nbl_dbg_dump_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = nbl_dbg_stat_read,
	.write = nbl_dbg_stat_write,
};

static void nbl_debugfs_stats_init(struct nbl_device *nbl_dev)
{
	struct nbl_func_file *func_file = &nbl_dev->func_stat->func_file;

	/* 1.create statistics file */
	func_file->file = debugfs_create_file("stat", 0600, nbl_dev->func_dbg_dir,
						nbl_dev, &nbl_dbg_dump_fops);
	if (!func_file->file) {
		nbl_pr_err("init stat file failed\n");
		return;
	}

	/* 2.allocate buffer for debugfs file stats */
	func_file->used_len = 0;
	func_file->buf = kzalloc(NBL_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!func_file->buf) {
		debugfs_remove_recursive(func_file->file);
		return;
	}
	func_file->total_len = NBL_DUMP_BUF_SIZE;
	nbl_pr_dbg("init stat debugfs successfully\n");
}

static void nbl_debugfs_stats_deinit(struct nbl_device *nbl_dev)
{
	struct nbl_func_file *func_file = &nbl_dev->func_stat->func_file;

	debugfs_remove_recursive(func_file->file);
	kfree(func_file->buf);
	func_file->total_len = 0;
}

/**
 * nbl_debugfs_function_init - setup the debugfs directory for the pf
 * return : void (device can run without debug)
 */
void nbl_debugfs_function_init(struct nbl_device *nbl_dev)
{
	if (nbl_dev->ibdev.name[0] == '\0')
		return;
	nbl_dev->func_dbg_dir = debugfs_create_dir(nbl_dev->ibdev.name,
							rdma_dbg_dir);
	if (!nbl_dev->func_dbg_dir) {
		nbl_pr_err("init function:%s directory failed\n", nbl_dev->ibdev.name);
		return;
	}
	nbl_debugfs_stats_init(nbl_dev);
	nbl_debugfs_cc_init(nbl_dev);
	nbl_debugfs_qos_dev_init(nbl_dev);
	nbl_debug_function_init(nbl_dev);
	nbl_pr_dbg("init function debugfs successfully\n");
}

/**
 * nbl_debugfs_function_exit - clear out the pf's debugfs entries
 */
void nbl_debugfs_function_exit(struct nbl_device *nbl_dev)
{
	if (!nbl_dev || !nbl_dev->func_dbg_dir) {
		pr_err("nbl_dev or func_dbg_dir is null\r\n");
		return;
	}

	nbl_debug_function_deinit(nbl_dev);
	nbl_debugfs_qos_dev_deinit(nbl_dev);
	nbl_debugfs_cc_deinit(nbl_dev);
	nbl_debugfs_stats_deinit(nbl_dev);
	debugfs_remove_recursive(nbl_dev->func_dbg_dir);
	nbl_dev->func_dbg_dir = NULL;
	nbl_pr_dbg("exit function debugfs successfully\n");
}

/**
 * nbl_debugfs_init - start up debugfs for the driver
 */
void nbl_debugfs_init(void)
{
	nbl_dbg_dir = debugfs_create_dir("nbl", NULL);
	if (!nbl_dbg_dir)
		nbl_pr_err("init nbl directory failed\n");

	rdma_dbg_dir = debugfs_create_dir("rdma", nbl_dbg_dir);
	if (!rdma_dbg_dir) {
		debugfs_remove_recursive(nbl_dbg_dir);
		nbl_pr_err("init rdma directory failed\n");
	}

	nbl_pr_dbg("init debugfs successfully\n");
}

/**
 * nbl_debugfs_exit - clean out the driver's debugfs entries
 */
void nbl_debugfs_exit(void)
{
	debugfs_remove_recursive(rdma_dbg_dir);
	debugfs_remove_recursive(nbl_dbg_dir);

	nbl_pr_dbg("exit debugfs successfully\n");
}
