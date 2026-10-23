// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>

#include "shared.h"
#include "counters.h"
#include "dbgfs.h"
#include "qp.h"
#include "nbl_pt_cfg.h"
#include "nbl_rdma_module.h"

struct dentry *nbl_dbg_dir;
struct dentry *rdma_dbg_dir;

static const struct rdma_stat_desc nbl_vf_stats_names[] = {
	{"rx_resp", 0, NULL},
	{"rx_req", 0, NULL},
	{"rx_qpn_err", 0, NULL},
	{"rx_err", 0, NULL},
	{"tx_resp", 0, NULL},
	{"tx_req", 0, NULL},
	{"tx_qpn_err", 0, NULL},
	{"tx_err", 0, NULL},
};

const char *const nbl_qp_opcode_stats_names_v2[NBL_STATS_GROUP_OPCODE_CNTS] = {
	/* Rx rc opcode */
	"Rx rc send first", /* 0 */
	"Rx rc send middle", /* 1 */
	"Rx rc send last", /* 2 */
	"Rx rc send last with IMM", /* 3 */
	"Rx rc send only", /* 4 */
	"Rx rc send only with IMM", /* 5 */
	"Rx rc write first", /* 6 */
	"Rx rc write middle", /* 7 */
	"Rx rc write last", /* 8 */
	"Rx rc write last with IMM", /* 9 */
	"Rx rc write only", /* 10 */
	"Rx rc write only with IMM", /* 11 */
	"Rx rc read request", /* 12 */
	"Rx rc read response first", /* 13 */
	"Rx rc read response middle", /* 14 */
	"Rx rc read response last", /* 15 */
	"Rx rc read response only", /* 16 */
	"Rx rc ack", /* 17 */
	"Rx rc Atomic ack", /* 18 */
	"Rx rc Atomic CmpSwap", /* 19 */
	"Rx rc Atomic FetchAdd", /* 20 */
	"reserved", /* 21 */
	"Rx rc send last INV", /* 22 */
	"Rx rc send only INV", /* 23 */
	/* Rx ud opcode */
	"Rx ud send only", /* 24 */
	"Rx ud send only with IMM", /* 25 */
	/* Rx xrc opcode */
	"Rx xrc send first", /* 26 */
	"Rx xrc send middle", /* 27 */
	"Rx xrc send last", /* 28 */
	"Rx xrc send last with IMM", /* 29 */
	"Rx xrc send only", /* 30 */
	"Rx xrc send only with IMM", /* 31 */
	"Rx xrc write first", /* 32 */
	"Rx xrc write middle", /* 33 */
	"Rx xrc write last", /* 34 */
	"Rx xrc write last with IMM", /* 35 */
	"Rx xrc write only", /* 36 */
	"Rx xrc write only with IMM", /* 37 */
	"Rx xrc read request", /* 38 */
	"Rx xrc read response first", /* 39 */
	"Rx xrc read response middle", /* 40 */
	"Rx xrc read response last", /* 41 */
	"Rx xrc read response only", /* 42 */
	"Rx xrc ack", /* 43 */
	"Rx xrc Atomic ack", /* 44 */
	"Rx xrc Atomic CmpSwap", /* 45 */
	"Rx xrc Atomic FetchAdd", /* 46 */
	"reserved", /* 47 */
	"Rx xrc send last INV", /* 48 */
	"Rx xrc send only INV", /* 49 */
	/* other */
	"Rx cc oamreq", /* 50 */
	"Rx cc oamack", /* 51 */
	"Rx CNP prc", /* 52 */
	"Rx CNP", /* 53 */
	"Rx CE CNT", /* 54 */
	"reserved", /* 55 */
	"reserved", /* 56 */
	"Tx CNP", /* 57 */
	"Tx Bind MW local", /* 58 */
	"Tx local INV local", /* 59 */
	"Tx FRMR local", /* 60 */
	"Tx NOP local", /* 61 */
	"Tx cc oamreq", /* 62 */
	"Tx cc oamack", /* 63 */

	/* Tx rc opcode */
	"Tx rc send first", /* 64 */
	"Tx rc send middle", /* 65 */
	"Tx rc send last", /* 66 */
	"Tx rc send last with IMM", /* 67 */
	"Tx rc send only", /* 68 */
	"Tx rc send only with IMM", /* 69 */
	"Tx rc write first", /* 70 */
	"Tx rc write middle", /* 71 */
	"Tx rc write last", /* 72 */
	"Tx rc write last with IMM", /* 73 */
	"Tx rc write only", /* 74 */
	"Tx rc write only with IMM", /* 75 */
	"Tx rc read request", /* 76 */
	"Tx rc read response first", /* 77 */
	"Tx rc read response middle", /* 78 */
	"Tx rc read response last", /* 79 */
	"Tx rc read response only", /* 80 */
	"Tx rc ack", /* 81 */
	"Tx rc Atomic ack", /* 82 */
	"Tx rc Atomic CmpSwap", /* 83 */
	"Tx rc Atomic FetchAdd", /* 84 */
	"reserved", /* 85 */
	"Tx rc send last with INV", /* 86 */
	"Tx rc send only with INV", /* 87 */
	/* Tx ud opcode */
	"Tx ud send only", /* 88 */
	"Tx ud send only with IMM", /* 89 */
	/* Tx xrc opcode */
	"Tx xrc send first", /* 90 */
	"Tx xrc send middle", /* 91 */
	"Tx xrc send last", /* 92 */
	"Tx xrc send last with IMM", /* 93 */
	"Tx xrc send only", /* 94 */
	"Tx xrc send only with IMM", /* 95 */
	"Tx xrc write first", /* 96 */
	"Tx xrc write middle", /* 97 */
	"Tx xrc write last", /* 98 */
	"Tx xrc write last with IMM", /* 99 */
	"Tx xrc write only", /* 100 */
	"Tx xrc write only with IMM", /* 101 */
	"Tx xrc read request", /* 102 */
	"Tx xrc read response first", /* 103 */
	"Tx xrc read response middle", /* 104 */
	"Tx xrc read response last", /* 105 */
	"Tx xrc read response only", /* 106 */
	"Tx xrc ack", /* 107 */
	"Tx xrc Atomic ack", /* 108 */
	"Tx xrc Atomic CmpSwap", /* 109 */
	"Tx xrc Atomic FetchAdd", /* 110 */
	"reserved", /* 111 */
	"Tx xrc send last with INV", /* 112 */
	"Tx xrc send only with INV", /* 113 */
	/* Tx normal DB */
	"Tx normal db invalid", /* 114 */
	"Tx normal db SW SQ", /* 115 */
	"Tx normal db TXP SQ", /* 116 */
	"Tx normal db TQ recheck", /* 117 */
	"Tx normal db TQ RNR", /* 118 */
	"Tx normal db TQ RTO", /* 119 */
	"Tx normal db psnerr", /* 120 */
	"Tx normal db RAQ", /* 121 */
	"Tx normal db TXP RAQ", /* 122 */
	"Tx normal db TQ waitack", /* 123 */
	"Tx normal db cc oamack", /* 124 */
	"Tx normal db CNP", /* 125 */
	"Tx normal db flush SQ", /* 126 */
	"reserved", /* 127 */
};

const char *const nbl_qp_opcode_stats_names_v4[NBL_STATS_GROUP_OPCODE_CNTS_V4] = {
	/* Rx rc opcode */
	"Rx rc send first", /* 0 */
	"Rx rc send middle", /* 1 */
	"Rx rc send last", /* 2 */
	"Rx rc send last with IMM", /* 3 */
	"Rx rc send only", /* 4 */
	"Rx rc send only with IMM", /* 5 */
	"Rx rc write first", /* 6 */
	"Rx rc write middle", /* 7 */
	"Rx rc write last", /* 8 */
	"Rx rc write last with IMM", /* 9 */
	"Rx rc write only", /* 10 */
	"Rx rc write only with IMM", /* 11 */
	"Rx rc read request", /* 12 */
	"Rx rc read response first", /* 13 */
	"Rx rc read response middle", /* 14 */
	"Rx rc read response last", /* 15 */
	"Rx rc read response only", /* 16 */
	"Rx rc ack", /* 17 */
	"Rx rc Atomic ack", /* 18 */
	"Rx rc Atomic CmpSwap", /* 19 */
	"Rx rc Atomic FetchAdd", /* 20 */
	"reserved", /* 21 */
	"Rx rc send last with INV", /* 22 */
	"Rx rc send only with INV", /* 23 */

	/* Rx ud opcode */
	"Rx ud send only", /* 24 */
	"Rx ud send only with IMM", /* 25 */

	/* Rx xrc opcode */
	"Rx xrc send first", /* 26 */
	"Rx xrc send middle", /* 27 */
	"Rx xrc send last", /* 28 */
	"Rx xrc send last with IMM", /* 29 */
	"Rx xrc send only", /* 30 */
	"Rx xrc send only with IMM", /* 31 */
	"Rx xrc write first", /* 32 */
	"Rx xrc write middle", /* 33 */
	"Rx xrc write last", /* 34 */
	"Rx xrc write last with IMM", /* 35 */
	"Rx xrc write only", /* 36 */
	"Rx xrc write only with IMM", /* 37 */
	"Rx xrc read request", /* 38 */
	"Rx xrc read response first", /* 39 */
	"Rx xrc read response middle", /* 40 */
	"Rx xrc read response last", /* 41 */
	"Rx xrc read response only", /* 42 */
	"Rx xrc ack", /* 43 */
	"Rx xrc Atomic ack", /* 44 */
	"Rx xrc Atomic CmpSwap", /* 45 */
	"Rx xrc Atomic FetchAdd", /* 46 */
	"reserved", /* 47 */
	"Rx xrc send last with INV", /* 48 */
	"Rx xrc send only with INV", /* 49 */

	/* other */
	"Rx cc oamreq", /* 50 */
	"Rx cc oamack", /* 51 */
	"Rx CNP prc", /* 52 */
	"Rx CNP", /* 53 */
	"Rx CE CNT", /* 54 */
	"Tx local read", /* 55 */
	"reserved", /* 56 */
	"Tx CNP", /* 57 */
	"Tx Bind MW local", /* 58 */
	"Tx local INV local", /* 59 */
	"Tx FRMR local", /* 60 */
	"Tx NOP local", /* 61 */
	"Tx cc oamreq", /* 62 */
	"Tx cc oamack", /* 63 */

	/* Rx SRP opcode */
	"Rx SRP send first", /* 64 */
	"Rx SRP send middle", /* 65 */
	"Rx SRP send last", /* 66 */
	"Rx SRP send last with IMM", /* 67 */
	"Rx SRP send only", /* 68 */
	"Rx SRP send only with IMM", /* 69 */
	"Rx SRP write first", /* 70 */
	"Rx SRP write middle", /* 71 */
	"Rx SRP write last", /* 72 */
	"Rx SRP write last with IMM", /* 73 */
	"Rx SRP write only", /* 74 */
	"Rx SRP write only with IMM", /* 75 */
	"Rx SRP read request", /* 76 */
	"Rx SRP read response first", /* 77 */
	"Rx SRP read response middle", /* 78 */
	"Rx SRP read response last", /* 79 */
	"Rx SRP read response only", /* 80 */
	"Rx SRP ack", /* 81 */
	"Rx SRP Atomic ack", /* 82 */
	"Rx SRP Atomic CmpSwap", /* 83 */
	"Rx SRP Atomic FetchAdd", /* 84 */
	"reserved", /* 85 */
	"Rx SRP send last with INV", /* 86 */
	"Rx SRP send only with INV", /* 87 */
	"Rx SRP Atomic MskCmpSwap", /* 88 */
	"Rx SRP Atomic MskFetchAdd", /* 89 */
	"Rx SRP SR_ACK", /* 90 */
	"Rx SRP SR_EACK", /* 91 */
	"Rx RC Atomic MskCmpSwap", /* 92 */
	"Rx RC Atomic MskFetchAdd", /* 93 */
	"Rx XRC Atomic MskCmpSwap", /* 94 */
	"Rx XRC Atomic MskFetchAdd", /* 95 */
	"Rx slow path", /* 96 */
	"Rx raw eth send", /* 97 */
	"reserved", /* 98 */
	"reserved", /* 99 */
	"reserved", /* 100 */
	"reserved", /* 101 */
	"reserved", /* 102 */
	"reserved", /* 103 */
	"reserved", /* 104 */
	"reserved", /* 105 */
	"reserved", /* 106 */
	"reserved", /* 107 */
	"reserved", /* 108 */
	"reserved", /* 109 */
	"reserved", /* 110 */
	"reserved", /* 111 */
	"reserved", /* 112 */
	"reserved", /* 113 */
	"reserved", /* 114 */
	"reserved", /* 115 */
	"reserved", /* 116 */
	"reserved", /* 117 */
	"reserved", /* 118 */
	"reserved", /* 119 */
	"reserved", /* 120 */
	"reserved", /* 121 */
	"reserved", /* 122 */
	"reserved", /* 123 */
	"reserved", /* 124 */
	"reserved", /* 125 */
	"reserved", /* 126 */
	"reserved", /* 127 */

	/* Tx rc opcode */
	"Tx rc send first", /* 128 */
	"Tx rc send middle", /* 129 */
	"Tx rc send last", /* 130 */
	"Tx rc send last with IMM", /* 131 */
	"Tx rc send only", /* 132 */
	"Tx rc send only with IMM", /* 133 */
	"Tx rc write first", /* 134 */
	"Tx rc write middle", /* 135 */
	"Tx rc write last", /* 136 */
	"Tx rc write last with IMM", /* 137 */
	"Tx rc write only", /* 138 */
	"Tx rc write only with IMM", /* 139 */
	"Tx rc read request", /* 140 */
	"Tx rc read response first", /* 141 */
	"Tx rc read response middle", /* 142 */
	"Tx rc read response last", /* 143 */
	"Tx rc read response only", /* 144 */
	"Tx rc ack", /* 145 */
	"Tx rc Atomic ack", /* 146 */
	"Tx rc Atomic CmpSwap", /* 147 */
	"Tx rc Atomic FetchAdd", /* 148 */
	"reserved", /* 149 */
	"Tx rc send last with INV", /* 150 */
	"Tx rc send only with INV", /* 151 */

	/* Tx ud opcode */
	"Tx ud send only", /* 152 */
	"Tx ud send only with IMM", /* 153 */

	/* Tx xrc opcode */
	"Tx xrc send first", /* 154 */
	"Tx xrc send middle", /* 155 */
	"Tx xrc send last", /* 156 */
	"Tx xrc send last with IMM", /* 157 */
	"Tx xrc send only", /* 158 */
	"Tx xrc send only with IMM", /* 159 */
	"Tx xrc write first", /* 160 */
	"Tx xrc write middle", /* 161 */
	"Tx xrc write last", /* 162 */
	"Tx xrc write last with IMM", /* 163 */
	"Tx xrc write only", /* 164 */
	"Tx xrc write only with IMM", /* 165 */
	"Tx xrc read request", /* 166 */
	"Tx xrc read response first", /* 167 */
	"Tx xrc read response middle", /* 168 */
	"Tx xrc read response last", /* 169 */
	"Tx xrc read response only", /* 170 */
	"Tx xrc ack", /* 171 */
	"Tx xrc Atomic ack", /* 172 */
	"Tx xrc Atomic CmpSwap", /* 173 */
	"Tx xrc Atomic FetchAdd", /* 174 */
	"reserved", /* 175 */
	"Tx xrc send last with INV", /* 176 */
	"Tx xrc send only with INV", /* 177 */

	/* Tx normal DB */
	"Tx normal db invalid", /* 178 */
	"Tx normal db SW SQ", /* 179 */
	"Tx normal db TXP SQ", /* 180 */
	"Tx normal db TQ recheck", /* 181 */
	"Tx normal db TQ RNR", /* 182 */
	"Tx normal db TQ RTO", /* 183 */
	"Tx normal db psnerr", /* 184 */
	"Tx normal db RAQ", /* 185 */
	"Tx normal db TXP RAQ", /* 186 */
	"Tx normal db TQ waitack", /* 187 */
	"Tx normal db cc oamack", /* 188 */
	"Tx normal db CNP", /* 189 */
	"Tx normal db flush SQ", /* 190 */
	"reserved", /* 191 */

	/* Tx SRP opcode */
	"Tx SRP send first", /* 192 */
	"Tx SRP send middle", /* 193 */
	"Tx SRP send last", /* 194 */
	"Tx SRP send last with IMM", /* 195 */
	"Tx SRP send only", /* 196 */
	"Tx SRP send only with IMM", /* 197 */
	"Tx SRP write first", /* 198 */
	"Tx SRP write middle", /* 199 */
	"Tx SRP write last", /* 200 */
	"Tx SRP write last with IMM", /* 201 */
	"Tx SRP write only", /* 202 */
	"Tx SRP write only with IMM", /* 203 */
	"Tx SRP read request", /* 204 */
	"Tx SRP read response first", /* 205 */
	"Tx SRP read response middle", /* 206 */
	"Tx SRP read response last", /* 207 */
	"Tx SRP read response only", /* 208 */
	"Tx SRP ack", /* 209 */
	"Tx SRP Atomic ack", /* 210 */
	"Tx SRP Atomic CmpSwap", /* 211 */
	"Tx SRP Atomic FetchAdd", /* 212 */
	"reserved", /* 213 */
	"Tx SRP send last with INV", /* 214 */
	"Tx SRP send only with INV", /* 215 */
	"Tx SRP Atomic MskCmpSwap", /* 216 */
	"Tx SRP Atomic MskFetchAdd", /* 217 */
	"Tx SRP SR_ACK", /* 218 */
	"Tx SRP SR_EACK", /* 219 */
	"Tx RC Atomic MskCmpSwap", /* 220 */
	"Tx RC Atomic MskFetchAdd", /* 221 */
	"Tx XRC Atomic MskCmpSwap", /* 222 */
	"Tx XRC Atomic MskFetchAdd", /* 223 */
	"Tx slow path", /* 224 */
	"Tx raw eth send", /* 225 */
	"reserved", /* 226 */
	"reserved", /* 227 */
	"reserved", /* 228 */
	"reserved", /* 229 */
	"reserved", /* 230 */
	"reserved", /* 231 */
	"reserved", /* 232 */
	"reserved", /* 233 */
	"reserved", /* 234 */
	"reserved", /* 235 */
	"reserved", /* 236 */
	"reserved", /* 237 */
	"reserved", /* 238 */
	"reserved", /* 239 */
	"reserved", /* 240 */
	"reserved", /* 241 */
	"reserved", /* 242 */
	"reserved", /* 243 */
	"reserved", /* 244 */
	"reserved", /* 245 */
	"reserved", /* 246 */
	"reserved", /* 247 */
	"reserved", /* 248 */
	"reserved", /* 249 */
	"reserved", /* 250 */
	"reserved", /* 251 */
	"reserved", /* 252 */
	"reserved", /* 253 */
	"reserved", /* 254 */
	"reserved", /* 255 */
};

enum {
	QP_STATE,
	QP_MTU,
	QP_RQPN,
	QP_XPORT,
};

static char *qp_fields[] = {
	[QP_STATE] = "state",
	[QP_MTU] = "mtu",
	[QP_RQPN] = "remote_qpn",
	[QP_XPORT] = "transport",
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
	dbg_vsnprintf(nbl_dev, " get qpn-info\n");
	dbg_vsnprintf(nbl_dev, " get all\n\n");

	dbg_vsnprintf(nbl_dev, " clear func-stat\n");
	dbg_vsnprintf(nbl_dev, " clear stat-id <stat-id>\n");
	dbg_vsnprintf(nbl_dev, " clear err-qpn\n");
	dbg_vsnprintf(nbl_dev, " clear all\n\n");

	dbg_vsnprintf(nbl_dev, " qp-stat get <qpn>\n");
	dbg_vsnprintf(nbl_dev, " qp-stat mod <qpn> <stat-id>\n\n");

	dbg_vsnprintf(nbl_dev, " enable\n"
		"\tPerform opcode statistics on error messages\n");
	dbg_vsnprintf(nbl_dev, " disable\n"
		"\tDo not perform opcode statistics on error messages\n\n");
}

static void stat_cmd_help_v2(struct nbl_device *nbl_dev)
{
	dbg_vsnprintf(nbl_dev, "Statistics commands:\n");
	dbg_vsnprintf(nbl_dev, " get stat-id <stat-id>\n");
	dbg_vsnprintf(nbl_dev, " clear stat-id <stat-id>\n");
}
/**
 * get_id
 * @cbuf: input string
 * Return id if success, -1 if failed
 */
static u32 get_id(char *cbuf)
{
	int id = 0;
	char *str;
	int offset;
	int rc;

	str = kzalloc(strlen(cbuf) + 1, GFP_KERNEL);
	if (sscanf(cbuf, "%s%n", str, &offset) <= 0) {
		nbl_pr_err("failed to parse string(%s)\n", cbuf);
		kfree(str);
		return -1;
	}

	rc = kstrtoint(str, 0, &id);
	if (rc) {
		nbl_pr_err("Conversion string error. (str:%s)\n", str);
		kfree(str);
		return -1;
	}

	kfree(str);
	nbl_pr_dbg("get a id:%d by string(cbuf:%s, offset:%d)\n", id, cbuf, offset);

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
	nbl_pr_dbg("qp:%d is exist\n", qp_id);

	return true;
}

static bool check_statid_is_exist(struct nbl_device *nbl_dev, u8 stat_id)
{
	int stats_group_num = nbl_dev->rf->product->stats->group_count;

	if (stat_id >= NBL_STATS_GROUP_START_NUM && stat_id < stats_group_num)
		return true;
	else
		return false;
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
		dbg_vsnprintf(nbl_dev, "HW is busy, please try again\n");
	else
		dbg_vsnprintf(nbl_dev, "failed to get statistics, ret:%d\n", ret);
	return ret;
}

static void append_qp_opcode_stats(struct nbl_device *nbl_dev, int stat_id)
{
	int i;
	const struct nbl_stats_layout *stats = nbl_dev->rf->product->stats;
	int opcode_cnt = stats->opcode_count;
	const char *stat_name;
	char *stat_out;

	dbg_vsnprintf(nbl_dev, "--------------------------------------------------\n");

	for (i = 0; i < opcode_cnt; i++) {
		if (nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats == 0)
			continue;
		stat_name = stats->extended_opcode ?
			    nbl_qp_opcode_stats_names_v4[i] :
			    nbl_qp_opcode_stats_names_v2[i];

		if (stats->extended_opcode ? CHECK_STAT_NAME_IS_PACKET_V4(i) :
		    CHECK_STAT_NAME_IS_PACKET_V2(i)) {
			stat_out = kasprintf(GFP_KERNEL, "%s(packets):", stat_name);
		} else {
			stat_out = kasprintf(GFP_KERNEL, "%s:", stat_name);
		}
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
	const struct nbl_stats_layout *stats = nbl_dev->rf->product->stats;
	int opcode_cnt = stats->opcode_count;
	int entry_num = stats->entry_count;
	char *error_name;

	for (i = opcode_cnt; i < entry_num; i++) {
		err_idx = i - opcode_cnt;
		if (nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats == 0)
			continue;
		if (CHECK_NORMAL_ERRCODE_STAT(err_idx)) {
			normal_flag = 1;
			error_name = kasprintf(GFP_KERNEL, "%x:", err_idx);
			dbg_vsnprintf(nbl_dev, "errorcode 0x%-5s%lld\n",
			error_name,
			nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats);
			kfree(error_name);
		}
	}
	if (normal_flag)
		dbg_vsnprintf(nbl_dev, "--------------------------------------------------\n");

	for (i = opcode_cnt; i < entry_num; i++) {
		err_idx = i - opcode_cnt;
		if (nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats == 0)
			continue;
		if (CHECK_NORMAL_ERRCODE_STAT(err_idx))
			continue;
		error_name = kasprintf(GFP_KERNEL, "%x:", err_idx);
		dbg_vsnprintf(nbl_dev, "errorcode 0x%-5s%lld\n",
			error_name,
			nbl_dev->func_stat->stat_id_mem[stat_id][i].total_stats);
		kfree(error_name);
	}

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

	if (!check_statid_is_exist(nbl_dev, stat_id)) {
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
		dbg_vsnprintf(nbl_dev, "HW is busy, please try again\n");
	else
		dbg_vsnprintf(nbl_dev, "failed to get statistics\n");

	return ret;
}

static int dump_err_qpn_stats_cmd(struct nbl_device *nbl_dev)
{
	dbg_vsnprintf(nbl_dev, "not support!\n");
	return 0;
}

static void append_all_stats(struct nbl_device *nbl_dev)
{
	int i;
	int stats_group_num = nbl_dev->rf->product->stats->group_count;

	append_vf_stats(nbl_dev);

	for (i = NBL_STATS_GROUP_START_NUM; i < stats_group_num; i++)
		append_qp_stats(nbl_dev, i);

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
		dbg_vsnprintf(nbl_dev, "HW is busy, please try again\n");
	else
		dbg_vsnprintf(nbl_dev, "failed to get statistics\n");
	return ret;
}

void nbl_init_qpn_info_record(struct nbl_device *nbl_dev)
{
	unsigned int qp_nums;
	unsigned long flags;

	spin_lock_irqsave(&nbl_dev->rf->rsrc_lock, flags);

	qp_nums = bitmap_weight(nbl_dev->rf->allocated_qps, nbl_dev->rf->max_qp);

	spin_unlock_irqrestore(&nbl_dev->rf->rsrc_lock, flags);

	nbl_dev->init_create_qp_num = qp_nums;

	nbl_pr_dbg("debug nbl_dev->init_create_qp_num: %u\n", nbl_dev->init_create_qp_num);
}

static void dump_qpn_info_stats_cmd(struct nbl_device *nbl_dev)
{
	unsigned int qp_nums;
	int qpn_max = 0;
	unsigned long flags;

	nbl_pr_dbg("debug nbl_dev->init_create_qp_num: %u\n", nbl_dev->init_create_qp_num);
	spin_lock_irqsave(&nbl_dev->rf->rsrc_lock, flags);

	qp_nums = bitmap_weight(nbl_dev->rf->allocated_qps, nbl_dev->rf->max_qp) -
		nbl_dev->init_create_qp_num;
	if (qp_nums)
		qpn_max = find_last_bit(nbl_dev->rf->allocated_qps, nbl_dev->rf->max_qp);

	spin_unlock_irqrestore(&nbl_dev->rf->rsrc_lock, flags);
	dbg_vsnprintf(nbl_dev, "current qp total  : %u\n", qp_nums);
	if (qp_nums)
		dbg_vsnprintf(nbl_dev, "used-qpn max-value: %d\n", qpn_max);
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
	/* qpn info stat */
	else if (strncasecmp(cbuf, "qpn-info", strlen("qpn-info")) == 0)
		(void)dump_qpn_info_stats_cmd(nbl_dev);
	else
		stat_cmd_help(nbl_dev);
}

static void get_stats_cmd_v2(struct nbl_device *nbl_dev, char *cbuf)
{
	/* qp stat */
	if (strncasecmp(cbuf, "stat-id ", strlen("stat-id ")) == 0)
		(void)dump_qp_stats_cmd(nbl_dev, get_id(&cbuf[strlen("stat-id ")]));
	else
		stat_cmd_help_v2(nbl_dev);
}

static void clear_stats_cmd_v2(struct nbl_device *nbl_dev, char *cbuf)
{
	/* clear function stat */
	u32 stat_id;
	struct nbl_stats_reg_info reg_info = {};

	reg_info.op_info.v2.op_status = 1;
	reg_info.op_info.v2.op_rc = OP_STATS_CLEAR;
	if (strncasecmp(cbuf, "stat-id ", strlen("stat-id ")) == 0) {
		stat_id = get_id(&cbuf[strlen("stat-id ")]);
		if (!check_statid_is_exist(nbl_dev, stat_id)) {
			dbg_vsnprintf(nbl_dev, "stat-id %d is illegal\n", stat_id);
			return;
		}
		reg_info.op_info.v2.op_table_sel = NBL_STATS_ID_TABLE;
		reg_info.op_info.v2.op_id = stat_id;
		reg_info.op_info.v2.op_len = 1;
	} else {
		stat_cmd_help_v2(nbl_dev);
		return;
	}

	if (grc_stat_clear(nbl_dev->rf, &reg_info)) {
		dbg_vsnprintf(nbl_dev, "clear failed\n");
		return;
	}

	nbl_stats_mem_clear(nbl_dev, &reg_info);

	dbg_vsnprintf(nbl_dev, "clear successfully\n");
}

static void clear_stats_cmd(struct nbl_device *nbl_dev, char *cbuf)
{
	/* clear function stat */
	u32 stat_id;
	struct nbl_stats_reg_info reg_info = {};
	u16 func_id = nbl_dev->rf->sc_dev.function_id;

	reg_info.op_info.v2.op_status = 1;
	reg_info.op_info.v2.op_rc = OP_STATS_CLEAR;
	if (strncasecmp(cbuf, "func-stat", strlen("func-stat")) == 0) {
		reg_info.op_info.v2.op_table_sel = NBL_VF_TABLE;
		reg_info.op_info.v2.op_id = func_id;
		reg_info.op_info.v2.op_len = 1;
	} else if (strncasecmp(cbuf, "stat-id ", strlen("stat-id ")) == 0) {
		stat_id = get_id(&cbuf[strlen("stat-id ")]);
		if (!check_statid_is_exist(nbl_dev, stat_id)) {
			dbg_vsnprintf(nbl_dev, "stat-id %d is illegal\n", stat_id);
			return;
		}
		reg_info.op_info.v2.op_table_sel = NBL_STATS_ID_TABLE;
		reg_info.op_info.v2.op_id = stat_id;
		reg_info.op_info.v2.op_len = 1;
	} else if (strncasecmp(cbuf, "err-qpn", strlen("err-qpn")) == 0) {
		dbg_vsnprintf(nbl_dev, "not support!\n");
		return;
	} else if (strncasecmp(cbuf, "all", strlen("all")) == 0)
		reg_info.op_info.v2.op_table_sel = NBL_CLEAR_ALL;
	else {
		stat_cmd_help(nbl_dev);
		return;
	}

	if (grc_stat_clear(nbl_dev->rf, &reg_info)) {
		dbg_vsnprintf(nbl_dev, "clear failed\n");
		return;
	}

	nbl_stats_mem_clear(nbl_dev, &reg_info);

	dbg_vsnprintf(nbl_dev, "clear successfully\n");
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
	char *qp_id_str;
	int qp_id_offset;
	int rc;
	struct nbl_qp *qp = NULL;
	struct nbl_qp_ctx ctx_info = {};
	int ret;
	struct nbl_pci_f *rf = nbl_dev->rf;

	/* check qp_id */
	qp_id_str = kzalloc(strlen(cbuf) + 1, GFP_KERNEL);
	if (sscanf(cbuf, "%s%n", qp_id_str, &qp_id_offset) <= 0) {
		dbg_vsnprintf(nbl_dev, "failed to parse string:[%s]\n", cbuf);
		kfree(qp_id_str);
		return;
	}

	rc = kstrtoint(qp_id_str, 0, &qp_id);
	if (rc) {
		dbg_vsnprintf(nbl_dev, "Conversion string:[%s] error\n", qp_id_str);
		kfree(qp_id_str);
		return;
	}
	kfree(qp_id_str);
	if (!check_qpid_is_exist(nbl_dev, qp_id)) {
		dbg_vsnprintf(nbl_dev, "QP %d is not exist\n", qp_id);
		return;
	}
	qp = rf->qp_table[qp_id];

	/* check stat_id */
	stat_id = (u8)get_id(cbuf + qp_id_offset + 1);
	if (!check_statid_is_exist(nbl_dev, stat_id)) {
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
	/* TODO disable qp_stat check */
	ctx_info.stat_id = stat_id;
	ret = nbl_modify_hw_qpc(qp, &ctx_info, NBL_QPC_STAT_ID_MASK);
	if (ret) {
		dbg_vsnprintf(nbl_dev, "failed to modify stat_id of qp:%d, ret:%d\n",
			qp_id, ret);
		return;
	}

	dbg_vsnprintf(nbl_dev, "modify qp:%d stat_id:%d successfully\n",
		qp_id, stat_id);
}

static void manage_statid_of_qp_cmd(struct nbl_device *nbl_dev, char *cbuf)
{
	/* modify stat id */
	if (strncasecmp(cbuf, "mod ", strlen("mod ")) == 0)
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

	if (grc_stat_errcode_enable(rf, enable))
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

	nbl_pr_dbg("copy continue[%lld/%zu]\n", *ppos, func_file->used_len);
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

	nbl_pr_dbg("not_copied:%d, count:%zu, cmd:[%s]\n", bytes_not_copied, count, func_file->cmd);

	if (strncasecmp(func_file->cmd, "get ", strlen("get ")) == 0)
		get_stats_cmd(nbl_dev, &func_file->cmd[strlen("get ")]);
	else if (strncasecmp(func_file->cmd, "clear ", strlen("clear ")) == 0)
		clear_stats_cmd(nbl_dev, &func_file->cmd[strlen("clear ")]);
	else if (strncasecmp(func_file->cmd, "qp-stat ", strlen("qp-stat ")) == 0)
		manage_statid_of_qp_cmd(nbl_dev, &func_file->cmd[strlen("qp-stat ")]);
	else if (strncasecmp(func_file->cmd, "enable", strlen("enable")) == 0)
		set_opcode_stats_has_errcode_cmd(nbl_dev, true);
	else if (strncasecmp(func_file->cmd, "disable", strlen("disable")) == 0)
		set_opcode_stats_has_errcode_cmd(nbl_dev, false);
	else
		stat_cmd_help(nbl_dev);

	return count;
}

static ssize_t nbl_dbg_stat_write_v2(struct file *filp, const char __user *buf,
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

	nbl_pr_dbg("not_copied:%d, count:%zu, cmd:[%s]\n", bytes_not_copied, count, func_file->cmd);

	if (strncasecmp(func_file->cmd, "get ", strlen("get ")) == 0)
		get_stats_cmd_v2(nbl_dev, &func_file->cmd[strlen("get ")]);
	else if (strncasecmp(func_file->cmd, "clear ", strlen("clear ")) == 0)
		clear_stats_cmd_v2(nbl_dev, &func_file->cmd[strlen("clear ")]);
	else
		stat_cmd_help_v2(nbl_dev);

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
		get_stats_cmd_v2(nbl_dev, &func_file->cmd[strlen("get ")]);
	else if (strncasecmp(func_file->cmd, "clear ", strlen("clear ")) == 0)
		clear_stats_cmd_v2(nbl_dev, &func_file->cmd[strlen("clear ")]);
	else
		stat_cmd_help_v2(nbl_dev);

	return count;
}

static const struct file_operations nbl_dbg_dump_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = nbl_dbg_stat_read,
	.write = nbl_dbg_stat_write,
};

static const struct file_operations nbl_dbg_dump_fops_v2 = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = nbl_dbg_stat_read,
	.write = nbl_dbg_stat_write_v2,
};

static void nbl_dbgfs_stats_init(struct nbl_device *nbl_dev)
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

static void nbl_dbgfs_stats_deinit(struct nbl_device *nbl_dev)
{
	struct nbl_func_file *func_file = &nbl_dev->func_stat->func_file;

	debugfs_remove_recursive(func_file->file);
	kfree(func_file->buf);
	func_file->total_len = 0;
}

static u64 qp_read_field(struct nbl_qp *nqp, int index, bool *is_str)
{
	struct nbl_uk_qp *uk_qp = &nqp->sc_qp.uk_qp;
	u64 param = 0;
	*is_str = false;

	switch (index) {
	case QP_STATE:
		param = (unsigned long)nbl_qp_stat_to_str(nqp->qp_state);
		*is_str = true;
		break;
	case QP_MTU:
		param = (256 * (1 << nqp->ctx_info.pmtu));
		break;
	case QP_RQPN:
		param = nqp->ctx_info.dest_qpn;
		break;
	case QP_XPORT:
		param = (unsigned long)nbl_qp_type_str(uk_qp->nbl_qp_service_type);
		*is_str = true;
		break;
	default:
		nbl_pr_err("qp dbgfs err\n");
		break;
	}
	return param;
}

static ssize_t dbg_read(struct file *filp, char __user *buf, size_t count,
	loff_t *pos)
{
	struct nbl_field_desc *desc;
	struct nbl_rsc_debug *rdbg;
	char tbuf[NBL_RSN_TBUF_LEN];
	bool is_str = false;
	u64 field;
	int ret;

	desc = filp->private_data;
	rdbg = desc->rdbg;
	switch (rdbg->type) {
	case NBL_DBG_RSC_QP:
		field = qp_read_field(rdbg->object, desc->idx, &is_str);
		break;
	default:
		nbl_pr_err("invalid type %d\n", rdbg->type);
		return -EINVAL;
	}

	if (is_str)
		ret = snprintf(tbuf, sizeof(tbuf), "%s\n", (const char *)(unsigned long)field);
	else
		ret = snprintf(tbuf, sizeof(tbuf), "0x%llx\n", field);

	return simple_read_from_buffer(buf, count, pos, tbuf, ret);
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = dbg_read,
};

static int add_res_tree(struct nbl_device *dev, enum dbg_rsc_type type,
	struct dentry *root, struct nbl_rsc_debug **dbg, int rsn,
	char **field, int nfile, void *data)
{
	struct nbl_rsc_debug *rdbg;
	char resn[NBL_RSN_DBG_LEN];
	int i;

	rdbg = kzalloc(struct_size(rdbg, fields, nfile), GFP_KERNEL);
	if (!rdbg)
		return -ENOMEM;

	rdbg->dev = dev;
	rdbg->object = data;
	rdbg->type = type;
	sprintf(resn, "0x%x", rsn);
	rdbg->root = debugfs_create_dir(resn, root);

	for (i = 0; i < nfile; i++) {
		rdbg->fields[i].idx = i;
		rdbg->fields[i].rdbg = rdbg;
		debugfs_create_file(field[i], 0400, rdbg->root,
			&rdbg->fields[i], &fops);
	}
	*dbg = rdbg;

	return 0;
}

static void rem_res_tree(struct nbl_rsc_debug *rdbg)
{
	debugfs_remove_recursive(rdbg->root);
	kfree(rdbg);
}

int nbl_debug_qp_add(struct nbl_device *dev, struct nbl_qp *qp)
{
	int err;

	err = add_res_tree(dev, NBL_DBG_RSC_QP, dev->qp_debugfs, &qp->dbg,
			qp->sc_qp.uk_qp.qpn, qp_fields, ARRAY_SIZE(qp_fields), qp);

	if (err)
		qp->dbg = NULL;

	return err;
}

void nbl_debug_qp_remove(struct nbl_device *dev, struct nbl_qp *qp)
{
	if (!dev->qp_debugfs || !qp->dbg || !dev->func_dbg_dir)
		return;

	rem_res_tree(qp->dbg);
	qp->dbg = NULL;
}

static void nbl_qp_debugfs_init(struct nbl_device *nbl_dev)
{
	nbl_dev->qp_debugfs = debugfs_create_dir("QPs", nbl_dev->func_dbg_dir);
}

static void nbl_qp_debugfs_cleanup(struct nbl_device *nbl_dev)
{
	if (!nbl_dev->qp_debugfs ||
		!nbl_dev->func_dbg_dir)
		return;

	debugfs_remove_recursive(nbl_dev->qp_debugfs);
	nbl_dev->qp_debugfs = NULL;
}

int nbl_debugfs_function_pre_init(struct nbl_device *nbl_dev)
{
	struct nbl_core_export *core_info = nbl_dev->rf->cdev;
	struct nbl_adev *nbl_adev = nbl_dev->rf->adev;
	char name[IB_DEVICE_NAME_MAX];
	int ret;

	if (!rdma_dbg_dir)
		return 0;

	nbl_get_ibname(name, sizeof(name), core_info->is_lag, nbl_adev->adev.id);

	nbl_dev->func_dbg_dir = debugfs_create_dir(name,
							rdma_dbg_dir);

	if (IS_ERR_OR_NULL(nbl_dev->func_dbg_dir)) {
		ret = nbl_dev->func_dbg_dir ? PTR_ERR(nbl_dev->func_dbg_dir) : -ENOMEM;
		nbl_dev->func_dbg_dir = NULL;
		nbl_pr_err("init function:%s directory failed, ret=%d\n", name, ret);
		return ret;
	}

	nbl_qp_debugfs_init(nbl_dev);

	return 0;
}

/**
 * nbl_debugfs_function_init - setup the debugfs directory for the pf
 * return : void (device can run without debug)
 */
void nbl_debugfs_function_init(struct nbl_device *nbl_dev)
{
	if (!nbl_dev->func_dbg_dir)
		return;

	nbl_dbgfs_stats_init(nbl_dev);
	nbl_dbgfs_cc_init(nbl_dev);
	nbl_dbgfs_qos_init(nbl_dev);
	nbl_pt_debugfs_init(nbl_dev);
	nbl_dbgfs_func_init(nbl_dev);
	nbl_dbgfs_cache_hit_init(nbl_dev);
	nbl_pr_dbg("init function debugfs successfully\n");
}

void nbl_debugfs_function_pre_exit(struct nbl_device *nbl_dev)
{
	nbl_qp_debugfs_cleanup(nbl_dev);
	debugfs_remove_recursive(nbl_dev->func_dbg_dir);
	nbl_dev->func_dbg_dir = NULL;
	nbl_pr_dbg("exit function debugfs successfully\n");
}

/**
 * nbl_debugfs_function_exit - clear out the pf's debugfs entries
 */
void nbl_debugfs_function_exit(struct nbl_device *nbl_dev)
{
	if (!nbl_dev->func_dbg_dir)
		return;

	nbl_dbgfs_cache_hit_deinit(nbl_dev);
	nbl_dbgfs_func_deinit(nbl_dev);
	nbl_dbgfs_qos_deinit(nbl_dev);
	nbl_pt_debugfs_cleanup(nbl_dev);
	nbl_dbgfs_cc_deinit(nbl_dev);
	nbl_dbgfs_stats_deinit(nbl_dev);
	nbl_pr_dbg("exit function debugfs successfully\n");
}

/**
 * nbl_debugfs_init - start up debugfs for the driver
 */
void nbl_debugfs_init(void)
{
	int ret;

	nbl_dbg_dir = debugfs_create_dir("nbl", NULL);
	if (IS_ERR_OR_NULL(nbl_dbg_dir)) {
		ret = nbl_dbg_dir ? PTR_ERR(nbl_dbg_dir) : -ENOMEM;
		nbl_dbg_dir = NULL;
		nbl_pr_err("init nbl directory failed, ret=%d\n", ret);
		return;
	}

	rdma_dbg_dir = debugfs_create_dir("rdma", nbl_dbg_dir);
	if (IS_ERR_OR_NULL(rdma_dbg_dir)) {
		ret = rdma_dbg_dir ? PTR_ERR(rdma_dbg_dir) : -ENOMEM;
		rdma_dbg_dir = NULL;
		debugfs_remove_recursive(nbl_dbg_dir);
		nbl_dbg_dir = NULL;
		nbl_pr_err("init rdma directory failed, ret=%d\n", ret);
		return;
	}

	nbl_pr_dbg("init debugfs successfully\n");
}

/**
 * nbl_debugfs_exit - clean out the driver's debugfs entries
 */
void nbl_debugfs_exit(void)
{
	/* Removing the parent recursively also removes rdma_dbg_dir. */
	debugfs_remove_recursive(nbl_dbg_dir);
	rdma_dbg_dir = NULL;
	nbl_dbg_dir = NULL;

	nbl_pr_dbg("exit debugfs successfully\n");
}
