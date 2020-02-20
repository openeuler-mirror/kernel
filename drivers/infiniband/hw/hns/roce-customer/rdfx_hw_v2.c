// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <rdma/ib_verbs.h>

#include "hns_roce_common.h"
#include "hns_roce_device.h"
#include "hns_roce_cmd.h"
#include "hnae3.h"
#include "hns_roce_hw_v2.h"

#include "rdfx_main.h"
#include "rdfx_common.h"
#include "rdfx_hw_v2.h"

static ssize_t rdfx_v2_show(struct kobject *kobj, struct attribute *attr,
			    char *buf);
static ssize_t rdfx_v2_store(struct kobject *kobj, struct attribute *attr,
			     const char *buf, size_t count);

static void rdfx_v2_print_sq_wqe(void *wqe)
{
	pr_info("Print sq wqe\n");
}

static void rdfx_v2_print_rq_wqe(void *wqe)
{
	pr_info("Print rq wqe\n");
}

static void *rdfx_v2_get_dfx(struct ib_device *ib_dev)
{
	struct hns_roce_dev *hr_dev =
		container_of(ib_dev, struct hns_roce_dev, ib_dev);

	return hr_dev->dfx_priv;
}

static int rdfx_v2_ooo_show(struct rdfx_info *rdfx)
{
	pr_info("************** OOO INFO ***************\n");

	return 0;
}

static int rdfx_v2_err_show(struct rdfx_info *rdfx)
{
	pr_info("************** ERR INFO ***************\n");

	return 0;
}

enum {
	DIS_READ_CLEAR,
	EN_READ_CLEAR,
};
#define CMD_NUM_QUERY_PKT_CNT	8

void rdfx_v2_pkt_stroe_query_pkt_read_pkt_cnt(struct hns_roce_cmq_desc *desc)
{
	int i;

	for (i = 0; i < CMD_NUM_QUERY_PKT_CNT; i++) {
		(void)hns_roce_cmq_setup_basic_desc(&desc[i],
			HNS_ROCE_OPC_QUEYR_PKT_CNT, true);

		if (i < (CMD_NUM_QUERY_PKT_CNT - 1))
			desc[i].flag |=
				cpu_to_le16(HNS_ROCE_CMD_FLAG_NEXT);
		else
			desc[i].flag &=
				~cpu_to_le16(HNS_ROCE_CMD_FLAG_NEXT);
	}
}

static int rdfx_v2_pkt_stroe_query_pkt(struct hns_roce_dev *hr_dev,
				       struct hns_roce_cmq_desc *desc)
{
	struct hns_roce_cmq_desc desc_cnp_rx = {0};
	struct hns_roce_cmq_desc desc_cnp_tx = {0};
	struct hns_roce_cmq_desc desc_cqe = {0};
	struct rdfx_cnt_snap *resp;
	int status;

	/* config read clear enable */
	resp = (struct rdfx_cnt_snap *)desc[0].data;
	(void)hns_roce_cmq_setup_basic_desc(&desc[0],
		HNS_ROCE_OPC_CNT_SNAP, false);
	roce_set_bit(resp->data_0, CNT_SNAP_PARAM_DATA_0_CNT_CLR_CE_S,
		EN_READ_CLEAR);
	status = hns_roce_cmq_send(hr_dev, desc, 1);
	if (status)
		return status;

	rdfx_v2_pkt_stroe_query_pkt_read_pkt_cnt(desc);

	status = hns_roce_cmq_send(hr_dev, desc, CMD_NUM_QUERY_PKT_CNT);
	if (status)
		return status;

	(void)hns_roce_cmq_setup_basic_desc(&desc_cqe,
			HNS_ROCE_OPC_QUEYR_CQE_CNT, true);
	status = hns_roce_cmq_send(hr_dev, &desc_cqe, 1);
	if (status)
		return status;

	if (hr_dev->pci_dev->revision == 0x21) {
		(void)hns_roce_cmq_setup_basic_desc(&desc_cnp_rx,
				HNS_ROCE_OPC_QUEYR_CNP_RX_CNT, true);
		status = hns_roce_cmq_send(hr_dev, &desc_cnp_rx, 1);
		if (status)
			return status;

		(void)hns_roce_cmq_setup_basic_desc(&desc_cnp_tx,
				HNS_ROCE_OPC_QUEYR_CNP_TX_CNT, true);
		status = hns_roce_cmq_send(hr_dev, &desc_cnp_tx, 1);
		if (status)
			return status;
	}

	/* config read clear disable */
	resp = (struct rdfx_cnt_snap *)desc[0].data;
	(void)hns_roce_cmq_setup_basic_desc(&desc[0],
		HNS_ROCE_OPC_CNT_SNAP, false);
	roce_set_bit(resp->data_0, CNT_SNAP_PARAM_DATA_0_CNT_CLR_CE_S,
		DIS_READ_CLEAR);
	status = hns_roce_cmq_send(hr_dev, desc, 1);
	if (status)
		return status;

	return 0;
}

void rdfx_v2_pkt_store_print(struct rdfx_query_pkt_cnt **resp_query,
			     struct rdfx_query_cqe_cnt *resp_cqe,
			     struct rdfx_query_cnp_rx_cnt *resp_cnp_rx,
			     struct rdfx_query_cnp_tx_cnt *resp_cnp_tx)
{
	pr_info("**************** PKT INFO ********************************\n");
	pr_info("            port0       port1       port2       port3\n");
	pr_info("RX RC PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[0]->rc_pkt_num, resp_query[1]->rc_pkt_num,
	       resp_query[2]->rc_pkt_num, resp_query[3]->rc_pkt_num);
	pr_info("RX UC PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[0]->uc_pkt_num, resp_query[1]->uc_pkt_num,
	       resp_query[2]->uc_pkt_num, resp_query[3]->uc_pkt_num);
	pr_info("RX UD PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[0]->ud_pkt_num, resp_query[1]->ud_pkt_num,
	       resp_query[2]->ud_pkt_num, resp_query[3]->ud_pkt_num);
	pr_info("RX XRC PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[0]->xrc_pkt_num, resp_query[1]->xrc_pkt_num,
	       resp_query[2]->xrc_pkt_num, resp_query[3]->xrc_pkt_num);
	pr_info("RX ALL PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[0]->total_pkt_num, resp_query[1]->total_pkt_num,
	       resp_query[2]->total_pkt_num, resp_query[3]->total_pkt_num);
	pr_info("RX ERR PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[0]->error_pkt_num, resp_query[1]->error_pkt_num,
	       resp_query[2]->error_pkt_num, resp_query[3]->error_pkt_num);
	pr_info("TX RC PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[4]->rc_pkt_num, resp_query[5]->rc_pkt_num,
	       resp_query[6]->rc_pkt_num, resp_query[7]->rc_pkt_num);
	pr_info("TX UC PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[4]->uc_pkt_num, resp_query[5]->uc_pkt_num,
	       resp_query[6]->uc_pkt_num, resp_query[7]->uc_pkt_num);
	pr_info("TX UD PKT : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[4]->ud_pkt_num, resp_query[5]->ud_pkt_num,
	       resp_query[6]->ud_pkt_num, resp_query[7]->ud_pkt_num);
	pr_info("TX XRC PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[4]->xrc_pkt_num, resp_query[5]->xrc_pkt_num,
	       resp_query[6]->xrc_pkt_num, resp_query[7]->xrc_pkt_num);
	pr_info("TX ALL PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[4]->total_pkt_num, resp_query[5]->total_pkt_num,
	       resp_query[6]->total_pkt_num, resp_query[7]->total_pkt_num);
	pr_info("TX ERR PKT: 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_query[4]->error_pkt_num, resp_query[5]->error_pkt_num,
	       resp_query[6]->error_pkt_num, resp_query[7]->error_pkt_num);
	pr_info("CQE       : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_cqe->port0_cqe, resp_cqe->port1_cqe,
	       resp_cqe->port2_cqe, resp_cqe->port3_cqe);
	pr_info("CNP RX    : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_cnp_rx->port0_cnp_rx, resp_cnp_rx->port1_cnp_rx,
	       resp_cnp_rx->port2_cnp_rx, resp_cnp_rx->port3_cnp_rx);
	pr_info("CNP TX    : 0x%08x  0x%08x  0x%08x  0x%08x\n",
	       resp_cnp_tx->port0_cnp_tx, resp_cnp_tx->port1_cnp_tx,
	       resp_cnp_tx->port2_cnp_tx, resp_cnp_tx->port3_cnp_tx);
	pr_info("**********************************************************\n");
}

static int rdfx_v2_pkt_store(const char *p_buf, struct rdfx_info *rdfx)
{
	struct hns_roce_dev *hr_dev = (struct hns_roce_dev *)rdfx->priv;
	struct hns_roce_cmq_desc desc[CMD_NUM_QUERY_PKT_CNT] = { {0} };
	struct rdfx_query_pkt_cnt *resp_query[CMD_NUM_QUERY_PKT_CNT];
	struct hns_roce_cmq_desc desc_cqe = {0};
	struct rdfx_query_cqe_cnt *resp_cqe =
				(struct rdfx_query_cqe_cnt *)desc_cqe.data;
	struct hns_roce_cmq_desc desc_cnp_tx = {0};
	struct rdfx_query_cnp_tx_cnt *resp_cnp_tx =
			(struct rdfx_query_cnp_tx_cnt *)desc_cnp_tx.data;
	struct hns_roce_cmq_desc desc_cnp_rx = {0};
	struct rdfx_query_cnp_rx_cnt *resp_cnp_rx =
			(struct rdfx_query_cnp_rx_cnt *)desc_cnp_rx.data;
	char *buf = (char *)p_buf;
	char str[DEF_OPT_STR_LEN] = {0};
	int ret;
	int i;

	if (!parg_getopt(buf, "c", str))
		return rdfx_v2_pkt_stroe_query_pkt(hr_dev, desc);

	for (i = 0; i < CMD_NUM_QUERY_PKT_CNT; i++) {
		(void)hns_roce_cmq_setup_basic_desc(&desc[i],
			HNS_ROCE_OPC_QUEYR_PKT_CNT, true);
		if (i < (CMD_NUM_QUERY_PKT_CNT - 1))
			desc[i].flag |= cpu_to_le16(HNS_ROCE_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(HNS_ROCE_CMD_FLAG_NEXT);
		resp_query[i] = (struct rdfx_query_pkt_cnt *)desc[i].data;
	}
	ret = hns_roce_cmq_send(hr_dev, desc, CMD_NUM_QUERY_PKT_CNT);
	if (ret)
		return ret;

	(void)hns_roce_cmq_setup_basic_desc(&desc_cqe,
			HNS_ROCE_OPC_QUEYR_CQE_CNT, true);
	ret = hns_roce_cmq_send(hr_dev, &desc_cqe, 1);
	if (ret)
		return ret;

	if (hr_dev->pci_dev->revision == 0x21) {
		(void)hns_roce_cmq_setup_basic_desc(&desc_cnp_rx,
				HNS_ROCE_OPC_QUEYR_CNP_RX_CNT, true);
		ret = hns_roce_cmq_send(hr_dev, &desc_cnp_rx, 1);
		if (ret)
			return ret;

		(void)hns_roce_cmq_setup_basic_desc(&desc_cnp_tx,
				HNS_ROCE_OPC_QUEYR_CNP_TX_CNT, true);
		ret = hns_roce_cmq_send(hr_dev, &desc_cnp_tx, 1);
		if (ret)
			return ret;
	}

	rdfx_v2_pkt_store_print(resp_query, resp_cqe, resp_cnp_rx, resp_cnp_tx);

	return 0;
}

static int rdfx_v2_cmd_show(struct rdfx_info *rdfx)
{
	struct hns_roce_dev *hr_dev = (struct hns_roce_dev *)rdfx->priv;
	struct hns_roce_cmq_desc desc_cnt;
	struct rdfx_query_mbdb_cnt *resp_cnt =
				(struct rdfx_query_mbdb_cnt *)desc_cnt.data;
	struct hns_roce_cmq_desc desc_dfx;
	int status;

	(void)hns_roce_cmq_setup_basic_desc(&desc_cnt,
			HNS_ROCE_OPC_QUEYR_MBDB_CNT, true);
	status = hns_roce_cmq_send(hr_dev, &desc_cnt, 1);
	if (status)
		return status;

	(void)hns_roce_cmq_setup_basic_desc(&desc_dfx,
			HNS_ROCE_OPC_QUEYR_MDB_DFX, true);
	status = hns_roce_cmq_send(hr_dev, &desc_dfx, 1);
	if (status)
		return status;

	pr_info("*************** cmd INFO **************\n");
	pr_info("MB ISSUE CNT   : 0x%08x\n",
	       resp_cnt->mailbox_issue_cnt);
	pr_info("MB EXEC CNT    : 0x%08x\n",
	       resp_cnt->mailbox_exe_cnt);
	pr_info("DB ISSUE CNT   : 0x%08x\n",
	       resp_cnt->doorbell_issue_cnt);
	pr_info("DB EXEC CNT    : 0x%08x\n",
	       resp_cnt->doorbell_exe_cnt);
	pr_info("EQDB ISSUE CNT : 0x%08x\n",
	       resp_cnt->eq_doorbell_issue_cnt);
	pr_info("EQDB EXEC CNT  : 0x%08x\n",
	       resp_cnt->eq_doorbell_exe_cnt);
	pr_info("        EMPTY  FULL   ERR");
	pr_info("***************************************\n");

	return 0;
}

void rdfx_v2_ceqc_store_print(struct hns_roce_eq_context *eq_context, u32 ceqn)
{
	int i;
	int *eqc;
	eqc = (int *)eq_context;
	pr_info("************** CEQC INFO ***************\n");
	for (i = 0; i < (sizeof(*eq_context) >> 2); i += 8) {
		pr_info("CEQC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			ceqn, *eqc, *(eqc + 1), *(eqc + 2),
			*(eqc + 3), *(eqc + 4), *(eqc + 5),
			*(eqc + 6), *(eqc + 7));
		eqc += 8;
	}
	pr_info("****************************************\n");
}

int rdfx_ceqc_store_mbox_check(struct hns_roce_dev *hr_dev,
		struct hns_roce_cmd_mailbox *mailbox, u32 ceqn)
{
	int ret;
	struct hns_roce_eq_context *eq_context;

	eq_context = kzalloc(sizeof(*eq_context), GFP_KERNEL);

	if (ZERO_OR_NULL_PTR(eq_context)) {
		pr_info("alloc mailbox mem for ceqc failed\n");
		ret = -ENOMEM;
		goto err_context;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, ceqn, 0,
				HNS_ROCE_CMD_QUERY_CEQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(eq_context, mailbox->buf, sizeof(*eq_context));
	else {
		dev_err(hr_dev->dev, "QUERY CEQ cmd process error\n");
		goto err_mailbox;
	}
	rdfx_v2_ceqc_store_print(eq_context, ceqn);

err_mailbox:
	kfree(eq_context);
err_context:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

static int rdfx_v2_ceqc_store(const char *p_buf, struct rdfx_info *rdfx)
{
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_dev *hr_dev;
	long long convert_val;
	char *buf = (char *)p_buf;
	char str[DEF_OPT_STR_LEN] = {0};
	u32 ceqn = 0;
	int ret;

	hr_dev = (struct hns_roce_dev *)rdfx->priv;

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	ceqn = (u32)convert_val;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = rdfx_ceqc_store_mbox_check(hr_dev, mailbox, ceqn);

	return ret;
}

void rdfx_v2_aeqc_store_print(u32 aeqn, struct hns_roce_eq_context *eq_context)
{
	int i;
	int *eqc;

	eqc = (int *)eq_context;
	pr_info("************** AEQC(0x%x) INFO ***************\n", aeqn);
	for (i = 0; i < (sizeof(*eq_context) >> 2); i += 8) {
		pr_info("AEQC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			aeqn, *eqc, *(eqc + 1), *(eqc + 2),
			*(eqc + 3), *(eqc + 4), *(eqc + 5),
			*(eqc + 6), *(eqc + 7));
		eqc += 8;
	}
	pr_info("***************************************\n");
}

int rdfx_aeqc_store_mbox_check(struct hns_roce_dev *hr_dev,
	struct hns_roce_cmd_mailbox *mailbox, u32 aeqn)
{
	int ret;
	struct hns_roce_eq_context *eq_context;

	eq_context = kzalloc(sizeof(*eq_context), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(eq_context)) {
		pr_info("alloc mailbox mem for aeqc failed\n");
		ret = -ENOMEM;
		goto err_context;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, aeqn, 0,
				HNS_ROCE_CMD_QUERY_AEQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(eq_context, mailbox->buf, sizeof(*eq_context));
	else {
		dev_err(hr_dev->dev, "QUERY CEQ cmd process error\n");
		goto err_mailbox;
	}

	rdfx_v2_aeqc_store_print(aeqn, eq_context);

err_mailbox:
	kfree(eq_context);
err_context:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

static int rdfx_v2_aeqc_store(const char *p_buf, struct rdfx_info *rdfx)
{
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_dev *hr_dev;
	long long convert_val;
	char *buf = (char *)p_buf;
	char str[DEF_OPT_STR_LEN] = {0};
	u32 aeqn = 0;
	int ret;

	hr_dev = (struct hns_roce_dev *)rdfx->priv;

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	aeqn = (u32)convert_val;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = rdfx_aeqc_store_mbox_check(hr_dev, mailbox, aeqn);

	return ret;
}

void rdfx_v2_qpc_store_print(u32 qpn, u64 bt0_ba, u64 bt1_ba,
			struct hns_roce_v2_qp_context *qp_context)
{
	int i;
	int *qpc = (int *)qp_context;

	pr_info("************** QPC INFO ***************\n");
	pr_info("QPC(0x%x) BT0: 0x%llx\n", qpn, bt0_ba);
	pr_info("QPC(0x%x) BT1: 0x%llx\n", qpn, bt1_ba);
	for (i = 0; i < (sizeof(*qp_context) >> 2); i += 8) {
		pr_info("QPC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			qpn, *qpc, *(qpc + 1), *(qpc + 2),
			*(qpc + 3), *(qpc + 4), *(qpc + 5),
			*(qpc + 6), *(qpc + 7));
		qpc += 8;
	}
	pr_info("***************************************\n");
}

int rdfx_qpc_store_mbox_check(struct hns_roce_dev *hr_dev,
			      struct hns_roce_cmd_mailbox *mailbox,
			      u32 qpn, u64 bt0_ba, u64 bt1_ba)
{
	int ret;
	struct hns_roce_v2_qp_context *qp_context;

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, qpn, 0,
				HNS_ROCE_CMD_READ_QPC_BT0,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt0_ba, mailbox->buf, sizeof(bt0_ba));
	else {
		dev_err(hr_dev->dev, "QUERY QP bt0 cmd process error\n");
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, qpn, 0,
				HNS_ROCE_CMD_READ_QPC_BT1,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt1_ba, mailbox->buf, sizeof(bt1_ba));
	else {
		dev_err(hr_dev->dev, "QUERY QP bt1 cmd process error\n");
		goto err_cmd;
	}

	qp_context = kzalloc(sizeof(*qp_context), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(qp_context)) {
		pr_info("alloc mailbox mem for qpc failed\n");
		ret = -ENOMEM;
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, qpn, 0,
				HNS_ROCE_CMD_QUERY_QPC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(qp_context, mailbox->buf, sizeof(*qp_context));
	else {
		dev_err(hr_dev->dev, "QUERY QP cmd process error\n");
		goto err_mailbox;
	}

	rdfx_v2_qpc_store_print(qpn, bt0_ba, bt1_ba, qp_context);

err_mailbox:
	kfree(qp_context);
err_cmd:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

static int rdfx_v2_qpc_store(const char *p_buf, struct rdfx_info *rdfx)
{
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_dev *hr_dev;
	long long convert_val;
	char *buf = (char *)p_buf;
	char str[DEF_OPT_STR_LEN] = {0};
	u32 qpn = 0;
	u64 bt0_ba = 0;
	u64 bt1_ba = 0;
	int ret;

	hr_dev = (struct hns_roce_dev *)rdfx->priv;

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	qpn = (u32)convert_val;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = rdfx_qpc_store_mbox_check(hr_dev, mailbox, qpn, bt0_ba, bt1_ba);

	return ret;
}

void rdfx_v2_cqc_store_print(u32 cqn, u64 bt0_ba, u64 bt1_ba,
			struct hns_roce_v2_cq_context *cq_context)
{
	int i;
	int *cqc;

	cqc = (int *)cq_context;
	pr_info("************** CQC INFO ***************\n");
	pr_info("CQC(0x%x) BT0: 0x%llx\n", cqn, bt0_ba);
	pr_info("CQC(0x%x) BT1: 0x%llx\n", cqn, bt1_ba);
	for (i = 0; i < (sizeof(*cq_context) >> 2); i += 8) {
		pr_info("CQC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			cqn, *cqc, *(cqc + 1), *(cqc + 2),
			*(cqc + 3), *(cqc + 4), *(cqc + 5),
			*(cqc + 6), *(cqc + 7));
		cqc += 8;
	}
}

int rdfx_cqc_store_mbox_check(struct hns_roce_dev *hr_dev,
			      struct hns_roce_cmd_mailbox *mailbox,
			      u32 cqn, u64 bt0_ba, u64 bt1_ba)
{
	int ret;
	struct hns_roce_v2_cq_context *cq_context;

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, cqn, 0,
				HNS_ROCE_CMD_READ_CQC_BT0,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt0_ba, mailbox->buf, sizeof(bt0_ba));
	else {
		dev_err(hr_dev->dev, "QUERY CQ bt0 cmd process error\n");
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, cqn, 0,
				HNS_ROCE_CMD_READ_CQC_BT1,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt1_ba, mailbox->buf, sizeof(bt1_ba));
	else {
		dev_err(hr_dev->dev, "QUERY CQ bt1 cmd process error\n");
		goto err_cmd;
	}

	cq_context = kzalloc(sizeof(*cq_context), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(cq_context)) {
		pr_info("alloc mailbox mem for cqc failed\n");
		ret = -ENOMEM;
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, cqn, 0,
				HNS_ROCE_CMD_QUERY_CQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(cq_context, mailbox->buf, sizeof(*cq_context));
	else {
		dev_err(hr_dev->dev, "QUERY CQ cmd process error\n");
		goto err_mailbox;
	}

	rdfx_v2_cqc_store_print(cqn, bt0_ba, bt1_ba, cq_context);

err_mailbox:
	kfree(cq_context);
err_cmd:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

static int rdfx_v2_cqc_store(const char *p_buf, struct rdfx_info *rdfx)
{
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_dev *hr_dev;
	long long convert_val;
	char *buf = (char *)p_buf;
	char str[DEF_OPT_STR_LEN] = {0};
	u64 bt0_ba = 0;
	u64 bt1_ba = 0;
	u32 cqn = 0;
	int ret;

	hr_dev = (struct hns_roce_dev *)rdfx->priv;

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	cqn = (u32)convert_val;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = rdfx_cqc_store_mbox_check(hr_dev, mailbox, cqn, bt0_ba, bt1_ba);

	return ret;
}

void rdfx_v2_srqc_store_print(u32 srqn, u64 bt0_ba, u64 bt1_ba,
			struct hns_roce_srq_context *srq_context)
{
	int i;
	int *srqc = (int *)srq_context;

	pr_info("************** SRQC INFO ***************\n");
	pr_info("SRQC(0x%x) BT0: 0x%llx\n", srqn, bt0_ba);
	pr_info("SRQC(0x%x) BT1: 0x%llx\n", srqn, bt1_ba);
	for (i = 0; i < (sizeof(*srq_context) >> 2); i += 8) {
		pr_info("SRQC(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			srqn, *srqc, *(srqc + 1), *(srqc + 2),
			*(srqc + 3), *(srqc + 4), *(srqc + 5),
			*(srqc + 6), *(srqc + 7));
		srqc += 8;
	}
	pr_info("***************************************\n");
}

int rdfx_srqc_store_mbox_check(struct hns_roce_dev *hr_dev,
			       struct hns_roce_cmd_mailbox *mailbox,
			       u32 srqn, u64 bt0_ba, u64 bt1_ba)
{
	int ret;
	struct hns_roce_srq_context *srq_context;

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, srqn, 0,
				HNS_ROCE_CMD_READ_SRQC_BT0,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt0_ba, mailbox->buf, sizeof(bt0_ba));
	else {
		dev_err(hr_dev->dev, "QUERY SRQ bt0 cmd process error\n");
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, srqn, 0,
				HNS_ROCE_CMD_READ_SRQC_BT1,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt1_ba, mailbox->buf, sizeof(bt1_ba));
	else {
		dev_err(hr_dev->dev, "QUERY SRQ bt1 cmd process error\n");
		goto err_cmd;
	}

	srq_context = kzalloc(sizeof(*srq_context), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(srq_context)) {
		pr_info("alloc mailbox mem for srqc failed\n");
		ret = -ENOMEM;
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, srqn, 0,
				HNS_ROCE_CMD_QUERY_SRQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(srq_context, mailbox->buf, sizeof(*srq_context));
	else {
		dev_err(hr_dev->dev, "QUERY SRQ cmd process error\n");
		goto err_mailbox;
	}

	rdfx_v2_srqc_store_print(srqn, bt0_ba, bt1_ba, srq_context);

err_mailbox:
	kfree(srq_context);
err_cmd:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

static int rdfx_v2_srqc_store(const char *p_buf, struct rdfx_info *rdfx)
{
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_dev *hr_dev;
	long long convert_val;
	char *buf = (char *)p_buf;
	char str[DEF_OPT_STR_LEN] = {0};
	u64 bt0_ba = 0;
	u64 bt1_ba = 0;
	u32 srqn = 0;
	int ret;

	hr_dev = (struct hns_roce_dev *)rdfx->priv;

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	srqn = (u32)convert_val;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = rdfx_srqc_store_mbox_check(hr_dev, mailbox, srqn, bt0_ba, bt1_ba);

	return ret;
}

void rdfx_v2_mpt_store_print(int key, u64 bt0_ba, u64 bt1_ba,
			struct hns_roce_v2_mpt_entry *mpt_ctx)
{
	int i;
	int *mpt = (int *)mpt_ctx;

	pr_info("************** MPT INFO ***************\n");
	pr_info("MPT(0x%x) BT0: 0x%llx\n", key, bt0_ba);
	pr_info("MPT(0x%x) BT1: 0x%llx\n", key, bt1_ba);
	for (i = 0; i < (sizeof(*mpt_ctx) >> 2); i += 8) {
		pr_info("MPT(0x%x): %08x %08x %08x %08x %08x %08x %08x %08x\n",
			key, *mpt, *(mpt + 1), *(mpt + 2),
			*(mpt + 3), *(mpt + 4), *(mpt + 5),
			*(mpt + 6), *(mpt + 7));
		mpt += 8;
	}
	pr_info("***************************************\n");
}

int rdfx_mpt_store_mbox_check(struct hns_roce_dev *hr_dev,
			      struct hns_roce_cmd_mailbox *mailbox,
			      int key, u64 bt0_ba, u64 bt1_ba)
{
	struct hns_roce_v2_mpt_entry *mpt_ctx;
	int ret;

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, key, 0,
				HNS_ROCE_CMD_READ_MPT_BT0,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt0_ba, mailbox->buf, sizeof(bt0_ba));
	else {
		dev_err(hr_dev->dev, "QUERY MPT bt0 cmd process error\n");
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, key, 0,
				HNS_ROCE_CMD_READ_MPT_BT1,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(&bt1_ba, mailbox->buf, sizeof(bt1_ba));
	else {
		dev_err(hr_dev->dev, "QUERY MPT bt1 cmd process error\n");
		goto err_cmd;
	}

	mpt_ctx = kzalloc(sizeof(*mpt_ctx), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(mpt_ctx)) {
		pr_info("alloc mailbox mem for mpt failed\n");
		ret = -ENOMEM;
		goto err_cmd;
	}

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, key, 0,
				HNS_ROCE_CMD_QUERY_MPT,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (!ret)
		memcpy(mpt_ctx, mailbox->buf, sizeof(*mpt_ctx));
	else {
		dev_err(hr_dev->dev, "QUERY mtpt cmd process error\n");
		goto err_mailbox;
	}

	rdfx_v2_mpt_store_print(key, bt0_ba, bt1_ba, mpt_ctx);

err_mailbox:
	kfree(mpt_ctx);
err_cmd:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

static int rdfx_v2_mpt_store(const char *p_buf, struct rdfx_info *rdfx)
{
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_dev *hr_dev;
	long long convert_val;
	char *buf = (char *)p_buf;
	char str[DEF_OPT_STR_LEN] = {0};
	u64 bt0_ba = 0;
	u64 bt1_ba = 0;
	int key;
	int ret;

	hr_dev = (struct hns_roce_dev *)rdfx->priv;

	parg_getopt(buf, "v:", str);
	if (kstrtoll(str, 0, &convert_val)) {
		pr_info("convert str failed\n");
		return -EINVAL;
	}
	key = (int)convert_val;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = rdfx_mpt_store_mbox_check(hr_dev, mailbox, key, bt0_ba, bt1_ba);

	return ret;
}

rdfx_hw_file_attr_def(ooo, rdfx_v2_ooo_show, NULL);
rdfx_hw_file_attr_def(err, rdfx_v2_err_show, NULL);
rdfx_hw_file_attr_def(cmd, rdfx_v2_cmd_show, NULL);

rdfx_hw_file_attr_def(pkt, NULL, rdfx_v2_pkt_store);
rdfx_hw_file_attr_def(ceqc, NULL, rdfx_v2_ceqc_store);
rdfx_hw_file_attr_def(aeqc, NULL, rdfx_v2_aeqc_store);
rdfx_hw_file_attr_def(qpc, NULL, rdfx_v2_qpc_store);
rdfx_hw_file_attr_def(cqc, NULL, rdfx_v2_cqc_store);
rdfx_hw_file_attr_def(mpt, NULL, rdfx_v2_mpt_store);
rdfx_hw_file_attr_def(srqc, NULL, rdfx_v2_srqc_store);

static struct attribute *rdfx_hw_v2_attrs_list[] = {
	HW_ATTRS_LIST_MEMBER(ooo),
	HW_ATTRS_LIST_MEMBER(err),
	HW_ATTRS_LIST_MEMBER(pkt),
	HW_ATTRS_LIST_MEMBER(cmd),
	HW_ATTRS_LIST_MEMBER(ceqc),
	HW_ATTRS_LIST_MEMBER(aeqc),
	HW_ATTRS_LIST_MEMBER(qpc),
	HW_ATTRS_LIST_MEMBER(cqc),
	HW_ATTRS_LIST_MEMBER(mpt),
	HW_ATTRS_LIST_MEMBER(srqc),
	NULL
};

static const struct sysfs_ops rdfx_hw_v2_file_ops = {
	.show  = rdfx_v2_show,
	.store = rdfx_v2_store,
};

static struct kobj_type rdfx_hw_v2_kobj_ktype = {
	.release        = NULL,
	.sysfs_ops      = &rdfx_hw_v2_file_ops,
	.default_attrs  = rdfx_hw_v2_attrs_list,
};

static ssize_t rdfx_v2_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	struct rdfx_hw_sys_attr *p_roce_sys_attr =
		container_of(attr, struct rdfx_hw_sys_attr, attr);
	struct rdfx_info *rdfx = container_of(kobj, struct rdfx_info, kobj);
	int ret = 0;

	memset(buf, 0, SYSFS_PAGE_SIZE);
	if (p_roce_sys_attr->pub_show) {
		ret = p_roce_sys_attr->pub_show(rdfx);
		if (ret)
			return ret;
		else
			return strlen(buf);
	}

	return -EPERM;
}

static ssize_t rdfx_v2_store(struct kobject *kobj, struct attribute *attr,
			     const char *buf, size_t count)
{
	struct rdfx_hw_sys_attr *p_roce_sys_attr =
		container_of(attr, struct rdfx_hw_sys_attr, attr);
	struct rdfx_info *rdfx = container_of(kobj, struct rdfx_info, kobj);
	int ret = 0;

	if (p_roce_sys_attr->pub_store) {
		ret = p_roce_sys_attr->pub_store((char *)buf, rdfx);
		if (ret)
			return ret;
		else
			return count;
	}

	return -EPERM;
}

static int rdfx_v2_add_sysfs(struct rdfx_info *rdfx)
{
	struct device *dev = rdfx->drv_dev;
	int ret = 0;

	ret = kobject_init_and_add(&(rdfx->kobj),
				   &rdfx_hw_v2_kobj_ktype,
				   &(dev->kobj),
				   "%s", rdfx->dev.dev_name);
	if (ret) {
		pr_info("kobject_init_and_add failed!\r\n");
		return ret;
	}

	return ret;
}

static void rdfx_v2_del_sysfs(struct rdfx_info *rdfx)
{
	kobject_del(&(rdfx->kobj));
}

struct rdfx_ops rdfx_ops_hw_v2 = {
	.add_sysfs = rdfx_v2_add_sysfs,
	.del_sysfs = rdfx_v2_del_sysfs,
	.print_sq_wqe = rdfx_v2_print_sq_wqe,
	.print_rq_wqe = rdfx_v2_print_rq_wqe,
	.get_dfx = rdfx_v2_get_dfx,
};

