// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/acpi.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_umem.h>

#include "hnae3.h"
#include "hns_roce_common.h"
#include "hns_roce_device.h"
#include "hns_roce_cmd.h"
#include "hns_roce_hem.h"
#include "hns_roce_hw_v2.h"

int hns_roce_v2_query_mpt_stat(struct hns_roce_dev *hr_dev,
				char *buf, int *desc)
{
	struct hns_roce_v2_mpt_entry *mpt_ctx;
	struct hns_roce_cmd_mailbox *mailbox;
	u32 key = hr_dev->hr_stat.key;
	int cur_len = 0;
	char *out = buf;
	u64 bt0_ba = 0;
	u64 bt1_ba = 0;
	int *mpt;
	int ret;
	int i;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, key, 0,
				HNS_ROCE_CMD_READ_MPT_BT0,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt0_ba, mailbox->buf, sizeof(bt0_ba));
	else
		goto err_cmd;

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, key, 0,
				HNS_ROCE_CMD_READ_MPT_BT1,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt1_ba, mailbox->buf, sizeof(bt1_ba));
	else
		goto err_cmd;

	mpt_ctx = kzalloc(sizeof(*mpt_ctx), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(mpt_ctx)) {
		ret = -ENOMEM;
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, key_to_hw_index(key),
				0, HNS_ROCE_CMD_QUERY_MPT,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(mpt_ctx, mailbox->buf, sizeof(*mpt_ctx));
	else
		goto err_mailbox;

	hns_roce_v2_sysfs_print(out, cur_len,
				"MPT(0x%x) BT0: 0x%llx\n", key, bt0_ba);
	hns_roce_v2_sysfs_print(out, cur_len,
				"MPT(0x%x) BT1: 0x%llx\n", key, bt1_ba);
	mpt = (int *)mpt_ctx;
	for (i = 0; i < (sizeof(*mpt_ctx) >> 2); i += 8) {
		hns_roce_v2_sysfs_print(out, cur_len,
		 "MPT(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			key, *mpt, *(mpt + 1), *(mpt + 2),
			*(mpt + 3), *(mpt + 4), *(mpt + 5),
			*(mpt + 6), *(mpt + 7));
		mpt += 8;
	}
	*desc += cur_len;

err_mailbox:
	kfree(mpt_ctx);
err_cmd:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}
int hns_roce_v2_query_srqc_stat(struct hns_roce_dev *hr_dev,
				char *buf, int *desc)
{
	struct hns_roce_srq_context *srq_context;
	struct hns_roce_cmd_mailbox *mailbox;
	u32 srqn = hr_dev->hr_stat.srqn;
	int cur_len = 0;
	char *out = buf;
	u64 bt0_ba = 0;
	u64 bt1_ba = 0;
	int *srqc;
	int i = 0;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, srqn, 0,
				HNS_ROCE_CMD_READ_SRQC_BT0,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt0_ba, mailbox->buf, sizeof(bt0_ba));
	else
		goto err_cmd;

	srq_context = kzalloc(sizeof(*srq_context), GFP_KERNEL);
	if (!srq_context) {
		ret = -ENOMEM;
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, srqn, 0,
				HNS_ROCE_CMD_QUERY_SRQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(srq_context, mailbox->buf, sizeof(*srq_context));
	else
		goto err_mailbox;

	hns_roce_v2_sysfs_print(out, cur_len,
				"SRQC(0x%x) BT0: 0x%llx\n", srqn, bt0_ba);
	hns_roce_v2_sysfs_print(out, cur_len,
				"SRQC(0x%x) BT1: 0x%llx\n", srqn, bt1_ba);
	srqc = (int *)srq_context;
	for (i = 0; i < (sizeof(*srq_context) >> 2); i += 8) {
		hns_roce_v2_sysfs_print(out, cur_len,
		 "SRQC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			srqn, *srqc, *(srqc + 1), *(srqc + 2),
			*(srqc + 3), *(srqc + 4), *(srqc + 5),
			*(srqc + 6), *(srqc + 7));
		srqc += 8;
	}
	*desc += cur_len;

err_mailbox:
	kfree(srq_context);
err_cmd:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}
int hns_roce_v2_query_qpc_stat(struct hns_roce_dev *hr_dev,
				char *buf, int *desc)
{
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_v2_qp_context *qp_context;
	u32 qpn = hr_dev->hr_stat.qpn;
	int cur_len = 0;
	char *out = buf;
	u64 bt0_ba = 0;
	u64 bt1_ba = 0;
	int *qpc;
	int i = 0;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, qpn, 0,
				HNS_ROCE_CMD_READ_QPC_BT0,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt0_ba, mailbox->buf, sizeof(bt0_ba));
	else
		goto err_cmd;

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, qpn, 0,
				HNS_ROCE_CMD_READ_QPC_BT1,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt1_ba, mailbox->buf, sizeof(bt1_ba));
	else
		goto err_cmd;

	qp_context = kzalloc(sizeof(*qp_context), GFP_KERNEL);
	if (!qp_context) {
		ret = -ENOMEM;
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, qpn, 0,
				HNS_ROCE_CMD_QUERY_QPC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(qp_context, mailbox->buf, sizeof(*qp_context));
	else
		goto err_mailbox;

	hns_roce_v2_sysfs_print(out, cur_len,
				"QPC(0x%x) BT0: 0x%llx\n", qpn, bt0_ba);
	hns_roce_v2_sysfs_print(out, cur_len,
				"QPC(0x%x) BT1: 0x%llx\n", qpn, bt1_ba);
	qpc = (int *)qp_context;
	for (i = 0; i < (sizeof(*qp_context) >> 2); i += 8) {
		hns_roce_v2_sysfs_print(out, cur_len,
			 "QPC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			qpn, *qpc, *(qpc + 1), *(qpc + 2),
			*(qpc + 3), *(qpc + 4), *(qpc + 5),
			*(qpc + 6), *(qpc + 7));
		qpc += 8;
	}
	*desc += cur_len;

err_mailbox:
	kfree(qp_context);
err_cmd:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

int hns_roce_v2_query_aeqc_stat(struct hns_roce_dev *hr_dev,
				char *buf, int *desc)
{
	struct hns_roce_eq_context *eq_context;
	struct hns_roce_cmd_mailbox *mailbox;
	u32 aeqn = hr_dev->hr_stat.aeqn;
	int cur_len = 0;
	char *out = buf;
	int i = 0;
	int *aeqc;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	eq_context = kzalloc(sizeof(*eq_context), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(eq_context)) {
		ret = -ENOMEM;
		goto err_context;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, aeqn, 0,
				HNS_ROCE_CMD_QUERY_AEQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(eq_context, mailbox->buf, sizeof(*eq_context));
	else
		goto err_mailbox;

	aeqc = (int *)eq_context;
	for (i = 0; i < (sizeof(*eq_context) >> 2); i += 8) {
		hns_roce_v2_sysfs_print(out, cur_len,
		 "AEQC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			aeqn, *aeqc, *(aeqc + 1), *(aeqc + 2),
			*(aeqc + 3), *(aeqc + 4), *(aeqc + 5),
			*(aeqc + 6), *(aeqc + 7));
		aeqc += 8;
	}
	*desc += cur_len;

err_mailbox:
	kfree(eq_context);
err_context:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}
#define CMD_NUM_QUERY_PKT_CNT	(8)
int hns_roce_v2_query_pkt_stat(struct hns_roce_dev *hr_dev,
				char *buf, int *buff_size)
{
	struct hns_roce_cmq_desc desc[CMD_NUM_QUERY_PKT_CNT] = { {0} };
	struct rdfx_query_pkt_cnt *resp_query[CMD_NUM_QUERY_PKT_CNT];
	struct hns_roce_cmq_desc desc_cqe = {0};
	struct rdfx_query_cqe_cnt *resp_cqe =
				(struct rdfx_query_cqe_cnt *)desc_cqe.data;
	struct hns_roce_cmq_desc desc_cnp_rx = {0};
	struct rdfx_query_cnp_rx_cnt *resp_cnp_rx =
			(struct rdfx_query_cnp_rx_cnt *)desc_cnp_rx.data;
	struct hns_roce_cmq_desc desc_cnp_tx = {0};
	struct rdfx_query_cnp_tx_cnt *resp_cnp_tx =
			(struct rdfx_query_cnp_tx_cnt *)desc_cnp_tx.data;
	int cur_len = 0;
	char *out = buf;
	int status;
	int i;

	for (i = 0; i < CMD_NUM_QUERY_PKT_CNT; i++) {
		hns_roce_cmq_setup_basic_desc(&desc[i],
			HNS_ROCE_OPC_QUEYR_PKT_CNT, true);

		if (i < (CMD_NUM_QUERY_PKT_CNT - 1))
			desc[i].flag |= cpu_to_le16(HNS_ROCE_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(HNS_ROCE_CMD_FLAG_NEXT);
		resp_query[i] = (struct rdfx_query_pkt_cnt *)desc[i].data;
	}

	status = hns_roce_cmq_send(hr_dev, desc, CMD_NUM_QUERY_PKT_CNT);
	if (status)
		return status;

	hns_roce_cmq_setup_basic_desc(&desc_cqe,
			HNS_ROCE_OPC_QUEYR_CQE_CNT, true);
	status = hns_roce_cmq_send(hr_dev, &desc_cqe, 1);
	if (status)
		return status;

	if (hr_dev->pci_dev->revision == PCI_REVISION_ID_HIP08_B) {
		hns_roce_cmq_setup_basic_desc(&desc_cnp_rx,
				HNS_ROCE_OPC_QUEYR_CNP_RX_CNT, true);
		status = hns_roce_cmq_send(hr_dev, &desc_cnp_rx, 1);
		if (status)
			return status;

		hns_roce_cmq_setup_basic_desc(&desc_cnp_tx,
				HNS_ROCE_OPC_QUEYR_CNP_TX_CNT, true);
		status = hns_roce_cmq_send(hr_dev, &desc_cnp_tx, 1);
		if (status)
			return status;
	}

	hns_roce_v2_sysfs_print(out, cur_len,
	 "RX RC PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[0]->rc_pkt_num, resp_query[1]->rc_pkt_num,
	 resp_query[2]->rc_pkt_num, resp_query[3]->rc_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "RX UC PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[0]->uc_pkt_num, resp_query[1]->uc_pkt_num,
	 resp_query[2]->uc_pkt_num, resp_query[3]->uc_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "RX UD PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[0]->ud_pkt_num, resp_query[1]->ud_pkt_num,
	 resp_query[2]->ud_pkt_num, resp_query[3]->ud_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "RX XRC PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	  resp_query[0]->xrc_pkt_num, resp_query[1]->xrc_pkt_num,
	  resp_query[2]->xrc_pkt_num, resp_query[3]->xrc_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "RX ALL PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[0]->total_pkt_num, resp_query[1]->total_pkt_num,
	 resp_query[2]->total_pkt_num, resp_query[3]->total_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	"RX ERR PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[0]->error_pkt_num, resp_query[1]->error_pkt_num,
	 resp_query[2]->error_pkt_num, resp_query[3]->error_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "TX RC PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[4]->rc_pkt_num, resp_query[5]->rc_pkt_num,
	 resp_query[6]->rc_pkt_num, resp_query[7]->rc_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "TX UC PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[4]->uc_pkt_num, resp_query[5]->uc_pkt_num,
	 resp_query[6]->uc_pkt_num, resp_query[7]->uc_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "TX UD PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[4]->ud_pkt_num, resp_query[5]->ud_pkt_num,
	 resp_query[6]->ud_pkt_num, resp_query[7]->ud_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "TX XRC PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[4]->xrc_pkt_num, resp_query[5]->xrc_pkt_num,
	 resp_query[6]->xrc_pkt_num, resp_query[7]->xrc_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "TX ALL PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[4]->total_pkt_num, resp_query[5]->total_pkt_num,
	 resp_query[6]->total_pkt_num, resp_query[7]->total_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "TX ERR PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_query[4]->error_pkt_num, resp_query[5]->error_pkt_num,
	 resp_query[6]->error_pkt_num, resp_query[7]->error_pkt_num);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "CQE       : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_cqe->port0_cqe, resp_cqe->port1_cqe,
	 resp_cqe->port2_cqe, resp_cqe->port3_cqe);
	hns_roce_v2_sysfs_print(out, cur_len,
	 "CNP RX    : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	 resp_cnp_rx->port0_cnp_rx, resp_cnp_rx->port1_cnp_rx,
	 resp_cnp_rx->port2_cnp_rx, resp_cnp_rx->port3_cnp_rx);
	hns_roce_v2_sysfs_print(out, cur_len,
		 "CNP TX    : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_cnp_tx->port0_cnp_tx, resp_cnp_tx->port1_cnp_tx,
	       resp_cnp_tx->port2_cnp_tx, resp_cnp_tx->port3_cnp_tx);

	*buff_size += cur_len;
	return status;
}

int hns_roce_v2_query_ceqc_stat(struct hns_roce_dev *hr_dev,
				 char *buf, int *desc)
{
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_eq_context *eq_context;
	u32 ceqn = hr_dev->hr_stat.ceqn;
	int cur_len = 0;
	char *out = buf;
	int *ceqc;
	int i = 0;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	eq_context = kzalloc(sizeof(*eq_context), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(eq_context)) {
		ret = -ENOMEM;
		goto err_context;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, ceqn, 0,
				HNS_ROCE_CMD_QUERY_CEQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(eq_context, mailbox->buf, sizeof(*eq_context));
	else
		goto err_mailbox;
	ceqc = (int *)eq_context;
	for (i = 0; i < (sizeof(*eq_context) >> 2); i += 8) {
		hns_roce_v2_sysfs_print(out, cur_len,
		 "CEQC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			ceqn, *ceqc, *(ceqc + 1), *(ceqc + 2),
			*(ceqc + 3), *(ceqc + 4), *(ceqc + 5),
			*(ceqc + 6), *(ceqc + 7));
		ceqc += 8;
	}
	*desc += cur_len;
err_mailbox:
	kfree(eq_context);
err_context:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

int hns_roce_v2_query_cmd_stat(struct hns_roce_dev *hr_dev,
				      char *buf, int *desc)
{
	struct hns_roce_cmq_desc desc_cnt;
	struct hns_roce_query_mbdb_cnt *resp_cnt =
				(struct hns_roce_query_mbdb_cnt *)desc_cnt.data;
	struct hns_roce_cmq_desc desc_dfx;
	int cur_len = 0;
	char *out = buf;
	int status;

	hns_roce_cmq_setup_basic_desc(&desc_cnt,
			HNS_ROCE_OPC_QUEYR_MBDB_CNT, true);
	status = hns_roce_cmq_send(hr_dev, &desc_cnt, 1);
	if (status)
		return status;

	hns_roce_cmq_setup_basic_desc(&desc_dfx,
			HNS_ROCE_OPC_QUEYR_MDB_DFX, true);
	status = hns_roce_cmq_send(hr_dev, &desc_dfx, 1);
	if (status)
		return status;

	hns_roce_v2_sysfs_print(out, cur_len, "MB ISSUE CNT   : 0x%08x\n",
				resp_cnt->mailbox_issue_cnt);
	hns_roce_v2_sysfs_print(out, cur_len, "MB EXEC CNT    : 0x%08x\n",
				resp_cnt->mailbox_exe_cnt);
	hns_roce_v2_sysfs_print(out, cur_len, "DB ISSUE CNT   : 0x%08x\n",
				resp_cnt->doorbell_issue_cnt);
	hns_roce_v2_sysfs_print(out, cur_len, "DB EXEC CNT    : 0x%08x\n",
				resp_cnt->doorbell_exe_cnt);
	hns_roce_v2_sysfs_print(out, cur_len, "EQDB ISSUE CNT : 0x%08x\n",
				resp_cnt->eq_doorbell_issue_cnt);
	hns_roce_v2_sysfs_print(out, cur_len, "EQDB EXEC CNT  : 0x%08x\n",
				resp_cnt->eq_doorbell_exe_cnt);
	*desc += cur_len;
	return status;
}

static int hns_roce_v2_query_cqc(struct hns_roce_dev *hr_dev,
				 u64 *bt0_ba, u64 *bt1_ba, u32 cqn,
				 struct hns_roce_v2_cq_context *cq_context)
{

	struct hns_roce_cmd_mailbox *mailbox;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, cqn, 0,
				HNS_ROCE_CMD_READ_CQC_BT0,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(bt0_ba, mailbox->buf, sizeof(*bt0_ba));
	else {
		pr_err("Query CQ bt0 cmd process error(%d).\n", ret);
		goto out;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, cqn, 0,
				HNS_ROCE_CMD_READ_CQC_BT1,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(bt1_ba, mailbox->buf, sizeof(*bt1_ba));
	else {
		pr_err("Query CQ bt1 cmd process error(%d).\n", ret);
		goto out;
	}
	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, cqn, 0,
				HNS_ROCE_CMD_QUERY_CQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);

	memcpy(cq_context, mailbox->buf, sizeof(*cq_context));

out:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);
	return ret;
}

int hns_roce_v2_query_cqc_stat(struct hns_roce_dev *hr_dev,
				      char *buf, int *desc)
{
	struct hns_roce_v2_cq_context *cq_context;
	u32 cqn = hr_dev->hr_stat.cqn;
	int cur_len = 0;
	char *out = buf;
	u64 bt0_ba = 0;
	u64 bt1_ba = 0;
	int *cqc;
	int i, ret;

	cq_context = kzalloc(sizeof(*cq_context), GFP_KERNEL);
	if (!cq_context)
		return -ENOMEM;

	ret = hns_roce_v2_query_cqc(hr_dev, &bt0_ba, &bt1_ba, cqn, cq_context);
	if (ret)
		goto out;

	hns_roce_v2_sysfs_print(out, cur_len,
				"CQC(0x%x) BT0: 0x%llx\n", cqn, bt0_ba);
	hns_roce_v2_sysfs_print(out, cur_len,
				"CQC(0x%x) BT1: 0x%llx\n", cqn, bt1_ba);

	cqc = (int *)cq_context;
	for (i = 0; i < (sizeof(*cq_context) >> 2); i += 8) {
		hns_roce_v2_sysfs_print(out, cur_len,
			 "CQC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			cqn, *cqc, *(cqc + 1), *(cqc + 2),
			*(cqc + 3), *(cqc + 4), *(cqc + 5),
			*(cqc + 6), *(cqc + 7));
		cqc += 8;
	}
	*desc += cur_len;
out:
	kfree(cq_context);
	return ret;
}

int hns_roce_v2_modify_eq(struct hns_roce_dev *hr_dev, struct hns_roce_eq *eq,
			  u16 eq_count, u16 eq_period, u16 type)
{
	struct hns_roce_eq_context *eqc;
	struct hns_roce_eq_context *eqc_mask;
	struct hns_roce_cmd_mailbox *mailbox;
	unsigned int eq_cmd;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	eqc = mailbox->buf;
	eqc_mask = (struct hns_roce_eq_context *)mailbox->buf + 1;

	memset(eqc_mask, 0xff, sizeof(*eqc_mask));

	if (type == HNS_ROCE_EQ_MAXCNT_MASK) {
		roce_set_field(eqc->byte_12,
			       HNS_ROCE_EQC_MAX_CNT_M,
			       HNS_ROCE_EQC_MAX_CNT_S, eq_count);
		roce_set_field(eqc_mask->byte_12,
			       HNS_ROCE_EQC_MAX_CNT_M,
			       HNS_ROCE_EQC_MAX_CNT_S, 0);

	} else if (type == HNS_ROCE_EQ_PERIOD_MASK) {
		roce_set_field(eqc->byte_12,
			       HNS_ROCE_EQC_PERIOD_M,
			       HNS_ROCE_EQC_PERIOD_S, eq_period);
		roce_set_field(eqc_mask->byte_12,
			       HNS_ROCE_EQC_PERIOD_M,
			       HNS_ROCE_EQC_PERIOD_S, 0);
	}
	eq_cmd = HNS_ROCE_CMD_MODIFY_CEQC;
	ret = hns_roce_cmd_mbox(hr_dev, mailbox->dma, 0, eq->eqn, 1,
				eq_cmd, HNS_ROCE_CMD_TIMEOUT_MSECS);
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);
	if (ret)
		dev_err(hr_dev->dev, "Modify EQ Failed(%d) for cmd mailbox.\n",
			ret);

	return ret;
}
