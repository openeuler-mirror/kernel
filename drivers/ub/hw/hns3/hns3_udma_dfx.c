// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/device.h>
#include "hns3_udma_jfr.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_tp.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_segment.h"
#include "hns3_udma_dfx.h"

struct class *drv_class;
struct device *drv_device;
static int major;
static int hns3_udma_dev_count;
struct hns3_udma_dfx_dev g_hns3_udma_dfx_list[MAX_HNS3_UDMA_DEV] = {NULL};
const struct file_operations chr_ops = {
	.owner = THIS_MODULE,
};

static int hns3_udma_dfx_read_buf(char *str, const char *buf)
{
	const char *str_buf = buf;
	int blk_cnt = 0;
	int cnt = 0;

	while (*str_buf == ' ') {
		str_buf++;
		blk_cnt++;
	}
	while ((cnt < (HNS3_UDMA_DFX_STR_LEN_MAX - 1)) && (str_buf[cnt] != ' ') &&
		(str_buf[cnt] != '\0'))
		cnt++;

	if (((uint32_t)(blk_cnt + cnt) < strlen(buf)) || str_buf[cnt] != '\0')
		return -EINVAL;

	memcpy(str, str_buf, cnt);
	str[cnt] = '\0';

	return 0;
}

static int hns3_udma_dfx_query_context(struct hns3_udma_dev *udma_dev, uint32_t id,
				       void *context, uint32_t len, uint16_t op)
{
	struct hns3_udma_cmd_mailbox *mailbox;
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_mbox *mb;
	int ret;

	mailbox = hns3_udma_alloc_cmd_mailbox(udma_dev);
	if (IS_ERR(mailbox)) {
		dev_err(udma_dev->dev, "alloc mailbox failed.\n");
		ret = PTR_ERR(mailbox);
		goto alloc_mailbox_fail;
	}

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mb = (struct hns3_udma_mbox *)desc.data;
	mbox_desc_init(mb, 0, mailbox->dma, id, op);

	ret = hns3_udma_cmd_mbox(udma_dev, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret) {
		dev_err(udma_dev->dev, "QUERY id(0x%x) cmd(0x%x) error(%d).\n",
			id, op, ret);
		goto err_mailbox;
	}
	memcpy(context, mailbox->buf, len);

err_mailbox:
	hns3_udma_free_cmd_mailbox(udma_dev, mailbox);
alloc_mailbox_fail:
	return ret;
}

static void hns3_udma_dfx_seg_print(struct hns3_udma_dev *udma_dev, uint32_t seg_key,
				    struct hns3_udma_mpt_entry *mpt_entry)
{
	uint32_t *mpt = (uint32_t *)mpt_entry;
	uint32_t i;

	dev_info(udma_dev->dev,
		 "************ SEG/MPT(0x%8x) ENTRY INFO *************\n",
		 seg_key);
	for (i = 0; i < (sizeof(*mpt_entry) / sizeof(uint32_t)); i++) {
		pr_info("MPT(byte%4lu): %08x\n", (i + 1) * sizeof(uint32_t), *mpt);
		mpt++;
	}
	dev_info(udma_dev->dev,
		 "*********************************************************\n");
}

static int hns3_udma_dfx_seg_store(const char *p_buf, struct hns3_udma_dfx_info *hns3_udma_dfx)
{
	struct hns3_udma_dev *udma_dev = (struct hns3_udma_dev *)hns3_udma_dfx->priv;
	struct hns3_udma_ida *seg_ida = &udma_dev->seg_table.seg_ida;
	struct hns3_udma_mpt_entry mpt_entry;
	char str[HNS3_UDMA_DFX_STR_LEN_MAX];
	uint32_t mpt_index;
	uint32_t seg_key;
	int ret;

	ret = hns3_udma_dfx_read_buf(str, p_buf);
	if (ret) {
		dev_info(udma_dev->dev, "the inputing is invalid.\n");
		return ret;
	}

	if (kstrtouint(str, 0, &seg_key)) {
		dev_err(udma_dev->dev, "convert str failed.\n");
		return -EINVAL;
	}

	mpt_index = key_to_hw_index(seg_key);
	if (mpt_index > seg_ida->max) {
		dev_err(udma_dev->dev, "seg_key(%u) is invalid.\n", seg_key);
		return -EINVAL;
	}

	ret = hns3_udma_dfx_query_context(udma_dev, mpt_index, &mpt_entry,
					  sizeof(mpt_entry), HNS3_UDMA_CMD_QUERY_MPT);
	if (ret) {
		dev_err(udma_dev->dev, "query seg context failed, ret = %d.\n", ret);
		return ret;
	}

	hns3_udma_dfx_seg_print(udma_dev, seg_key, &mpt_entry);

	return ret;
}

static void hns3_udma_dfx_qpc_print(struct hns3_udma_dev *udma_dev, uint32_t qpn,
				    struct hns3_udma_qp_context *qp_context)
{
	uint32_t *qpc = (uint32_t *)qp_context;
	uint32_t i;

	dev_info(udma_dev->dev,
		 "************ TP/QP(0x%8x) CONTEXT INFO *************\n",
		 qpn);
	for (i = 0; i < (sizeof(*qp_context) / sizeof(uint32_t)); i++) {
		pr_info("QPC(byte%4lu): %08x\n", (i + 1) * sizeof(uint32_t), *qpc);
		qpc++;
	}
	dev_info(udma_dev->dev,
		 "*********************************************************\n");
}

static void hns3_udma_dfx_query_sccc(struct hns3_udma_dev *udma_dev, uint32_t sccc_id)
{
	uint32_t *sccc, *temp;
	int ret, i, loop_cnt;

	sccc = kzalloc(udma_dev->caps.scc_ctx_sz, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(sccc))
		return;

	ret = hns3_udma_dfx_query_context(udma_dev, sccc_id, (void *)sccc,
					  udma_dev->caps.scc_ctx_sz,
					  HNS3_UDMA_CMD_QUERY_SCCC);
	if (ret) {
		dev_err(udma_dev->dev, "query sccc failed, ret = %d.\n", ret);
		kfree(sccc);
		return;
	}

	dev_info(udma_dev->dev, "************ SCC(0x%8x) CONTEXT INFO *************\n", sccc_id);
	temp = sccc;
	loop_cnt = udma_dev->caps.scc_ctx_sz / sizeof(uint32_t);
	for (i = 0; i < loop_cnt; i++) {
		pr_info("SCCC(byte%4lu): 0x%08x\n", (i + 1) * sizeof(uint32_t), *temp);
		temp++;
	}
	dev_info(udma_dev->dev, "*********************************************************\n");
	kfree(sccc);
}

static int hns3_udma_dfx_tp_store(const char *p_buf, struct hns3_udma_dfx_info *hns3_udma_dfx)
{
	struct hns3_udma_dev *udma_dev = (struct hns3_udma_dev *)hns3_udma_dfx->priv;
	struct hns3_udma_qp_context qp_context;
	char str[HNS3_UDMA_DFX_STR_LEN_MAX];
	uint32_t tpn, sccc_id;
	int ret;

	ret = hns3_udma_dfx_read_buf(str, p_buf);
	if (ret) {
		dev_info(udma_dev->dev, "the inputing is invalid.\n");
		return ret;
	}

	if (kstrtouint(str, 0, &tpn)) {
		dev_err(udma_dev->dev, "convert str failed.\n");
		return -EINVAL;
	}

	ret = hns3_udma_dfx_query_context(udma_dev, tpn, &qp_context,
					  sizeof(qp_context), HNS3_UDMA_CMD_QUERY_QPC);
	if (ret) {
		dev_err(udma_dev->dev, "query qp context failed, ret = %d.\n", ret);
		return ret;
	}

	hns3_udma_dfx_qpc_print(udma_dev, tpn, &qp_context);
	if ((udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_QP_FLOW_CTRL) &&
	    hns3_udma_reg_read(&qp_context, QPC_QP_ST)) {
		sccc_id = tpn;
		if (hns3_udma_reg_read(&qp_context.ext, QPCEX_DIP_CTX_IDX_VLD))
			sccc_id = hns3_udma_reg_read(&qp_context.ext, QPCEX_DIP_CTX_IDX);
		hns3_udma_dfx_query_sccc(udma_dev, sccc_id);
	}

	return 0;
}

static void hns3_udma_dfx_jfrc_print(struct hns3_udma_dev *udma_dev, uint32_t jfrn,
				     struct hns3_udma_jfr_context *jfr_context)
{
	uint32_t *jfrc = (uint32_t *)jfr_context;
	uint32_t i;

	dev_info(udma_dev->dev,
		 "************ JFR/SRQ(0x%8x) CONTEXT INFO *************\n",
		 jfrn);
	for (i = 0; i < (sizeof(*jfr_context) / sizeof(uint32_t)); i++) {
		pr_info("SRQC(byte%4lu): %08x\n", (i + 1) * sizeof(uint32_t),
			*jfrc);
		jfrc++;
	}
	dev_info(udma_dev->dev,
		 "*********************************************************\n");
}

static int hns3_udma_dfx_jfr_store(const char *p_buf, struct hns3_udma_dfx_info *hns3_udma_dfx)
{
	struct hns3_udma_dev *udma_dev = (struct hns3_udma_dev *)hns3_udma_dfx->priv;
	struct hns3_udma_jfr_context jfr_context;
	char str[HNS3_UDMA_DFX_STR_LEN_MAX];
	struct jfr_list *jfr_now;
	bool flag = false;
	uint32_t jfrn;
	uint32_t srqn;
	int ret;
	int i;

	ret = hns3_udma_dfx_read_buf(str, p_buf);
	if (ret) {
		dev_info(udma_dev->dev, "the inputing is invalid.\n");
		return ret;
	}

	if (kstrtouint(str, 0, &jfrn)) {
		dev_err(udma_dev->dev, "convert str failed\n");
		return -EINVAL;
	}

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	list_for_each_entry(jfr_now,
			    &g_hns3_udma_dfx_list[i].dfx->jfr_list->node, node) {
		if (jfr_now->jfr_id == jfrn) {
			srqn = jfr_now->srqn;
			flag = true;
			break;
		}
	}
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	if (!flag) {
		dev_err(udma_dev->dev, "failed to find jfr, jfrn = %u.\n", jfrn);
		return -EINVAL;
	}

	ret = hns3_udma_dfx_query_context(udma_dev, srqn, &jfr_context,
					  sizeof(jfr_context), HNS3_UDMA_CMD_QUERY_SRQC);
	if (ret) {
		dev_err(udma_dev->dev, "query jfr context failed, ret = %d.\n", ret);
		return ret;
	}

	hns3_udma_dfx_jfrc_print(udma_dev, jfrn, &jfr_context);

	return 0;
}

static void hns3_udma_dfx_jfcc_print(struct hns3_udma_dev *udma_dev, uint32_t jfcn,
				     struct hns3_udma_jfc_context *jfc_context)
{
	int *jfcc = (int *)jfc_context;
	uint32_t i;

	dev_info(udma_dev->dev,
		 "************ JFC/CQC(0x%8x) CONTEXT INFO *************\n",
		 jfcn);
	for (i = 0; i < (sizeof(*jfc_context) / sizeof(int)); i++) {
		pr_info("CQC(byte%4lu): %08x\n", (i + 1) * sizeof(int), *jfcc);
		jfcc++;
	}
	dev_info(udma_dev->dev,
		 "*********************************************************\n");
}

static int hns3_udma_dfx_jfc_store(const char *p_buf, struct hns3_udma_dfx_info *hns3_udma_dfx)
{
	struct hns3_udma_dev *udma_dev = (struct hns3_udma_dev *)hns3_udma_dfx->priv;
	struct hns3_udma_jfc_context jfc_context = {};
	char str[HNS3_UDMA_DFX_STR_LEN_MAX] = {};
	uint32_t jfcn;
	int ret;

	ret = hns3_udma_dfx_read_buf(str, p_buf);
	if (ret) {
		dev_info(udma_dev->dev, "the inputing is invalid.\n");
		return ret;
	}

	if (kstrtouint(str, 0, &jfcn)) {
		dev_err(udma_dev->dev, "convert str failed.\n");
		return -EINVAL;
	}

	ret = hns3_udma_dfx_query_context(udma_dev, jfcn, &jfc_context,
					  sizeof(jfc_context), HNS3_UDMA_CMD_QUERY_CQC);
	if (ret) {
		dev_info(udma_dev->dev, "query jfc context fail, ret = %d, jfcn = %u.\n",
			 ret, jfcn);
		return ret;
	}

	hns3_udma_dfx_jfcc_print(udma_dev, jfcn, &jfc_context);

	return 0;
}

int hns3_udma_find_dfx_dev(struct hns3_udma_dev *udma_dev, int *num)
{
	int i;

	for (i = 0; i < MAX_HNS3_UDMA_DEV; i++) {
		read_lock(&g_hns3_udma_dfx_list[i].rwlock);
		if (g_hns3_udma_dfx_list[i].dev == udma_dev) {
			*num = i;
			return 0;
		}
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
	}

	dev_err(udma_dev->dev, "failed to find dfx device!\n");
	return -EINVAL;
}

static int hns3_udma_query_res_tp_list(struct hns3_udma_dev *udma_dev,
				       struct ubcore_res_key *key,
				       struct ubcore_res_val *val)
{
	struct ubcore_res_list_val *res_list = (struct ubcore_res_list_val *)val->addr;
	struct tpn_list *tpn_now;
	uint32_t *tp_list;
	uint32_t tpn_cnt;
	int ret;
	int i;

	res_list->cnt = 0;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->tpn_list->node_lock);
	tpn_cnt = g_hns3_udma_dfx_list[i].dfx->tpn_cnt;
	if (tpn_cnt == 0) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->tpn_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return 0;
	}

	tp_list = vmalloc(sizeof(*tp_list) * tpn_cnt);
	if (!tp_list) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->tpn_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return -ENOMEM;
	}

	list_for_each_entry(tpn_now,
			    &g_hns3_udma_dfx_list[i].dfx->tpn_list->node, node) {
		tp_list[res_list->cnt] = tpn_now->tpn;
		res_list->cnt++;
	}
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->tpn_list->node_lock);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	res_list->list = tp_list;

	return 0;
}

static int hns3_udma_query_res_jfs_list(struct hns3_udma_dev *udma_dev,
					struct ubcore_res_key *key,
					struct ubcore_res_val *val)
{
	struct ubcore_res_list_val *res_list = (struct ubcore_res_list_val *)val->addr;
	struct jfs_list *jfs_now;
	uint32_t *jfs_list;
	uint32_t jfs_cnt;
	int ret;
	int i;

	res_list->cnt = 0;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->jfs_list->node_lock);
	jfs_cnt = g_hns3_udma_dfx_list[i].dfx->jfs_cnt;
	if (jfs_cnt == 0) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfs_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return 0;
	}

	jfs_list = vmalloc(sizeof(*jfs_list) * jfs_cnt);
	if (!jfs_list) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfs_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return -ENOMEM;
	}

	list_for_each_entry(jfs_now,
			    &g_hns3_udma_dfx_list[i].dfx->jfs_list->node, node) {
		jfs_list[res_list->cnt] = jfs_now->jfs_id;
		res_list->cnt++;
	}
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfs_list->node_lock);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	res_list->list = jfs_list;

	return 0;
}

static int hns3_udma_query_res_jfr_list(struct hns3_udma_dev *udma_dev,
					struct ubcore_res_key *key,
					struct ubcore_res_val *val)
{
	struct ubcore_res_list_val *res_list = (struct ubcore_res_list_val *)val->addr;
	struct jfr_list *jfr_now;
	uint32_t *jfr_list;
	uint32_t jfr_cnt;
	int ret;
	int i;

	res_list->cnt = 0;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->jfr_list->node_lock);
	jfr_cnt = g_hns3_udma_dfx_list[i].dfx->jfr_cnt;
	if (jfr_cnt == 0) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfr_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return 0;
	}

	jfr_list = vmalloc(sizeof(*jfr_list) * jfr_cnt);
	if (!jfr_list) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfr_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return -ENOMEM;
	}

	list_for_each_entry(jfr_now,
			    &g_hns3_udma_dfx_list[i].dfx->jfr_list->node, node) {
		jfr_list[res_list->cnt] = jfr_now->jfr_id;
		res_list->cnt++;
	}
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfr_list->node_lock);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	res_list->list = jfr_list;

	return 0;
}

static int hns3_udma_query_res_jetty_list(struct hns3_udma_dev *udma_dev,
					  struct ubcore_res_key *key,
					  struct ubcore_res_val *val)
{
	struct ubcore_res_list_val *res_list = (struct ubcore_res_list_val *)val->addr;
	struct jetty_list *jetty_now;
	uint32_t *jetty_list;
	uint32_t jetty_cnt;
	int ret;
	int i;

	res_list->cnt = 0;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->jetty_list->node_lock);
	jetty_cnt = g_hns3_udma_dfx_list[i].dfx->jetty_cnt;
	if (jetty_cnt == 0) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jetty_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return 0;
	}

	jetty_list = vmalloc(sizeof(*jetty_list) * jetty_cnt);
	if (!jetty_list) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jetty_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return -ENOMEM;
	}

	list_for_each_entry(jetty_now,
			    &g_hns3_udma_dfx_list[i].dfx->jetty_list->node, node) {
		jetty_list[res_list->cnt] = jetty_now->jetty_id;
		res_list->cnt++;
	}
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jetty_list->node_lock);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	res_list->list = jetty_list;

	return 0;
}

static int hns3_udma_query_res_jfc_list(struct hns3_udma_dev *udma_dev,
					struct ubcore_res_key *key,
					struct ubcore_res_val *val)
{
	struct ubcore_res_list_val *res_list = (struct ubcore_res_list_val *)val->addr;
	struct jfc_list *jfc_now;
	uint32_t *jfc_list;
	uint32_t jfc_cnt;
	int ret;
	int i;

	res_list->cnt = 0;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->jfc_list->node_lock);
	jfc_cnt = g_hns3_udma_dfx_list[i].dfx->jfc_cnt;
	if (jfc_cnt == 0) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfc_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return 0;
	}

	jfc_list = vmalloc(sizeof(*jfc_list) * jfc_cnt);
	if (!jfc_list) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfc_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return -ENOMEM;
	}

	list_for_each_entry(jfc_now,
			    &g_hns3_udma_dfx_list[i].dfx->jfc_list->node, node) {
		jfc_list[res_list->cnt] = jfc_now->jfc_id;
		res_list->cnt++;
	}
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfc_list->node_lock);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	res_list->list = jfc_list;

	return 0;
}

static int hns3_udma_query_res_seg_list(struct hns3_udma_dev *udma_dev,
					struct ubcore_res_key *key,
					struct ubcore_res_val *val)
{
	struct ubcore_res_seg_val *res_list = (struct ubcore_res_seg_val *)val->addr;
	struct ubcore_seg_info *seg_list;
	struct seg_list *seg_now;
	uint32_t seg_cnt;
	int ret;
	int i;

	res_list->seg_cnt = 0;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->seg_list->node_lock);
	seg_cnt = g_hns3_udma_dfx_list[i].dfx->seg_cnt;
	if (seg_cnt == 0) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->seg_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return 0;
	}

	seg_list = vmalloc(sizeof(*seg_list) * seg_cnt);
	if (!seg_list) {
		spin_unlock(&g_hns3_udma_dfx_list[i].dfx->seg_list->node_lock);
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return -ENOMEM;
	}

	list_for_each_entry(seg_now,
			    &g_hns3_udma_dfx_list[i].dfx->seg_list->node, node) {
		memcpy(&seg_list[res_list->seg_cnt].ubva.eid, &seg_now->eid,
		       sizeof(union ubcore_eid));
		seg_list[res_list->seg_cnt].ubva.va = seg_now->iova;
		seg_list[res_list->seg_cnt].len = seg_now->len;
		seg_list[res_list->seg_cnt].token_id = seg_now->key_id;
		res_list->seg_cnt++;
	}
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->seg_list->node_lock);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	res_list->seg_list = seg_list;

	return 0;
}

static enum ubcore_tp_state to_ubcore_tp_state(enum hns3_udma_qp_state state)
{
	switch (state) {
	case QPS_RESET:
		return UBCORE_TP_STATE_RESET;
	case QPS_RTR:
		return UBCORE_TP_STATE_RTR;
	case QPS_RTS:
		return UBCORE_TP_STATE_RTS;
	case QPS_ERR:
		return UBCORE_TP_STATE_ERR;
	default:
		return UBCORE_TP_STATE_SUSPENDED;
	}
}

static int hns3_udma_query_res_tp(struct hns3_udma_dev *udma_dev,
				  struct ubcore_res_key *key,
				  struct ubcore_res_val *val)
{
	struct ubcore_res_tp_val *tp = (struct ubcore_res_tp_val *)val->addr;
	struct hns3_udma_qp_context qp_context;
	int ret;

	if (key->key_cnt == 0)
		return hns3_udma_query_res_tp_list(udma_dev, key, val);

	ret = hns3_udma_dfx_query_context(udma_dev, key->key, &qp_context,
					  sizeof(qp_context), HNS3_UDMA_CMD_QUERY_QPC);
	if (ret) {
		dev_err(udma_dev->dev, "query qp context failed, ret = %d.\n", ret);
		return ret;
	}

	tp->tpn = key->key;
	tp->tx_psn = hns3_udma_reg_read(&qp_context, QPC_SQ_CUR_PSN);
	tp->dscp = hns3_udma_reg_read(&qp_context, QPC_DSCP);
	tp->oor_en = hns3_udma_reg_read(&qp_context.ext, QPCEX_OOR_EN);
	tp->state =
	    to_ubcore_tp_state((enum hns3_udma_qp_state)hns3_udma_reg_read(&qp_context, QPC_QP_ST));
	tp->data_udp_start = hns3_udma_reg_read(&qp_context.ext, QPCEX_DATA_UDP_SRCPORT_L) |
			     hns3_udma_reg_read(&qp_context.ext, QPCEX_DATA_UDP_SRCPORT_H) <<
			     QPCEX_DATA_UDP_SRCPORT_H_SHIFT;
	tp->ack_udp_start = hns3_udma_reg_read(&qp_context.ext, QPCEX_ACK_UDP_SRCPORT);
	tp->udp_range = hns3_udma_reg_read(&qp_context.ext, QPCEX_UDP_SRCPORT_RANGE);
	tp->spray_en = hns3_udma_reg_read(&qp_context.ext, QPCEX_AR_EN);

	val->len = sizeof(struct ubcore_res_tp_val);

	return 0;
}

static int hns3_udma_query_res_jfs(struct hns3_udma_dev *udma_dev,
				   struct ubcore_res_key *key,
				   struct ubcore_res_val *val)
{
	struct ubcore_res_jfs_val *jfs = (struct ubcore_res_jfs_val *)val->addr;
	struct jfs_list *jfs_now;
	int ret;
	int i;

	if (key->key_cnt == 0)
		return hns3_udma_query_res_jfs_list(udma_dev, key, val);

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	list_for_each_entry(jfs_now,
			    &g_hns3_udma_dfx_list[i].dfx->jfs_list->node, node) {
		if (jfs_now->jfs_id == key->key) {
			jfs->jfs_id = jfs_now->jfs_id;
			jfs->state = jfs_now->state;
			jfs->depth = jfs_now->depth;
			jfs->priority = jfs_now->pri;
			jfs->jfc_id = jfs_now->jfc_id;
			read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
			val->len = sizeof(struct ubcore_res_jfs_val);
			return 0;
		}
	}
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	dev_err(udma_dev->dev, "failed to find jfs!\n");
	return -EINVAL;
}

static int hns3_udma_query_res_jfr(struct hns3_udma_dev *udma_dev,
				   struct ubcore_res_key *key,
				   struct ubcore_res_val *val)
{
	struct ubcore_res_jfr_val *jfr = (struct ubcore_res_jfr_val *)val->addr;
	struct hns3_udma_jfr_context jfr_context;
	struct jfr_list *jfr_now;
	bool flag = false;
	uint32_t srqn;
	int ret;
	int i;

	if (key->key_cnt == 0)
		return hns3_udma_query_res_jfr_list(udma_dev, key, val);

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	list_for_each_entry(jfr_now,
			    &g_hns3_udma_dfx_list[i].dfx->jfr_list->node, node) {
		if (jfr_now->jfr_id == key->key) {
			jfr->jfc_id = jfr_now->jfc_id;
			srqn = jfr_now->srqn;
			flag = true;
			break;
		}
	}
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	if (!flag) {
		dev_err(udma_dev->dev, "failed to find jfr, jfrn = %u.\n", key->key);
		return -EINVAL;
	}

	ret = hns3_udma_dfx_query_context(udma_dev, srqn, &jfr_context,
					  sizeof(jfr_context), HNS3_UDMA_CMD_QUERY_SRQC);
	if (ret) {
		dev_err(udma_dev->dev,
			"query jfr context failed, ret = %d\n", ret);
		return ret;
	}

	jfr->jfr_id = key->key;
	jfr->state = hns3_udma_reg_read(&jfr_context, SRQC_SRQ_ST);
	jfr->depth = 1U << hns3_udma_reg_read(&jfr_context, SRQC_SHIFT);

	return 0;
}

static int hns3_udma_query_res_jetty(struct hns3_udma_dev *udma_dev,
				     struct ubcore_res_key *key,
				     struct ubcore_res_val *val)
{
	struct ubcore_res_jetty_val *jetty = (struct ubcore_res_jetty_val *)val->addr;
	struct jetty_list *jetty_now;
	int ret;
	int i;

	if (key->key_cnt == 0)
		return hns3_udma_query_res_jetty_list(udma_dev, key, val);

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	list_for_each_entry(jetty_now,
			    &g_hns3_udma_dfx_list[i].dfx->jetty_list->node, node) {
		if (jetty_now->jetty_id == key->key) {
			jetty->jetty_id = jetty_now->jetty_id;
			jetty->state = jetty_now->state;
			jetty->jfs_depth = jetty_now->jfs_depth;
			jetty->priority = jetty_now->pri;
			jetty->jfr_id = jetty_now->jfr_id;
			jetty->send_jfc_id  = jetty_now->jfc_s_id;
			jetty->recv_jfc_id  = jetty_now->jfc_r_id;
			read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
			val->len = sizeof(struct ubcore_res_jetty_val);
			return 0;
		}
	}
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	dev_err(udma_dev->dev, "failed to find jetty!\n");
	return -EINVAL;
}

static int hns3_udma_query_res_jfc(struct hns3_udma_dev *udma_dev,
				   struct ubcore_res_key *key,
				   struct ubcore_res_val *val)
{
	struct ubcore_res_jfc_val *jfc = (struct ubcore_res_jfc_val *)val->addr;
	struct hns3_udma_jfc_context jfc_context;
	int ret;

	if (key->key_cnt == 0)
		return hns3_udma_query_res_jfc_list(udma_dev, key, val);

	ret = hns3_udma_dfx_query_context(udma_dev, key->key, &jfc_context,
				     sizeof(jfc_context), HNS3_UDMA_CMD_QUERY_CQC);
	if (ret) {
		dev_err(udma_dev->dev, "query jfc context failed, ret = %d.\n", ret);
		return ret;
	}

	jfc->jfc_id = hns3_udma_reg_read(&jfc_context, CQC_CQN);
	jfc->state = hns3_udma_reg_read(&jfc_context, CQC_CQ_ST);
	jfc->depth = 1U << hns3_udma_reg_read(&jfc_context, CQC_SHIFT);

	val->len = sizeof(struct ubcore_res_jfc_val);

	return 0;
}

static int hns3_udma_query_res_seg(struct hns3_udma_dev *udma_dev, struct ubcore_res_key *key,
				   struct ubcore_res_val *val)
{
	struct ubcore_res_seg_val *seg = (struct ubcore_res_seg_val *)val->addr;
	struct hns3_udma_ida *seg_ida = &udma_dev->seg_table.seg_ida;
	struct hns3_udma_mpt_entry mpt_entry;
	uint32_t mpt_index, token_id;
	union ubcore_eid eid = {};
	struct seg_list *seg_now;
	int ret, i;

	if (key->key_cnt == 0)
		return hns3_udma_query_res_seg_list(udma_dev, key, val);

	mpt_index = key_to_hw_index(key->key);
	if (mpt_index > seg_ida->max) {
		dev_err(udma_dev->dev, "seg_key(%u) is invalid.\n", key->key);
		return -EINVAL;
	}

	ret = hns3_udma_dfx_query_context(udma_dev, mpt_index, &mpt_entry,
					  sizeof(mpt_entry), HNS3_UDMA_CMD_QUERY_MPT);
	if (ret) {
		dev_err(udma_dev->dev, "query seg context failed, ret = %d.\n", ret);
		return ret;
	}

	token_id = hns3_udma_reg_read(&mpt_entry, MPT_LKEY);
	seg->seg_cnt = 0;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->seg_list->node_lock);
	list_for_each_entry(seg_now, &g_hns3_udma_dfx_list[i].dfx->seg_list->node, node) {
		if (seg_now->key_id == token_id) {
			memcpy(&eid, &seg_now->eid, sizeof(union ubcore_eid));
			seg->seg_cnt = 1;
			break;
		}
	}
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->seg_list->node_lock);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	if (seg->seg_cnt == 0) {
		dev_err(udma_dev->dev, "failed to query seg, token_id = %u.\n", token_id);
		return -EINVAL;
	}

	seg->seg_list = vmalloc(sizeof(struct ubcore_seg_info));
	if (!seg->seg_list)
		return -ENOMEM;

	seg->seg_list->token_id = token_id;
	seg->seg_list->len = hns3_udma_reg_read(&mpt_entry, MPT_LEN_L) |
			     hns3_udma_reg_read(&mpt_entry, MPT_LEN_H) << MPT_LEN_H_SHIFT;
	seg->seg_list->ubva.va = hns3_udma_reg_read(&mpt_entry, MPT_VA_L) |
				 hns3_udma_reg_read(&mpt_entry, MPT_VA_H) << MPT_VA_H_SHIFT;
	seg->seg_list->ubva.eid = eid;

	return 0;
}

static int hns3_udma_query_res_dev_ta(struct hns3_udma_dev *udma_dev,
				      struct ubcore_res_key *key,
				      struct ubcore_res_val *val)
{
	struct ubcore_res_dev_ta_val *res_ta = (struct ubcore_res_dev_ta_val *)val->addr;
	int ret;
	int i;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->seg_list->node_lock);
	res_ta->seg_cnt = g_hns3_udma_dfx_list[i].dfx->seg_cnt;
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->seg_list->node_lock);

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->jfs_list->node_lock);
	res_ta->jfs_cnt = g_hns3_udma_dfx_list[i].dfx->jfs_cnt;
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfs_list->node_lock);

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->jfr_list->node_lock);
	res_ta->jfr_cnt = g_hns3_udma_dfx_list[i].dfx->jfr_cnt;
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfr_list->node_lock);

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->jfc_list->node_lock);
	res_ta->jfc_cnt = g_hns3_udma_dfx_list[i].dfx->jfc_cnt;
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jfc_list->node_lock);

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->jetty_list->node_lock);
	res_ta->jetty_cnt = g_hns3_udma_dfx_list[i].dfx->jetty_cnt;
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->jetty_list->node_lock);

	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	res_ta->jetty_group_cnt = 0;
	res_ta->rc_cnt = 0;

	return 0;
}

static int hns3_udma_query_res_dev_tp(struct hns3_udma_dev *udma_dev,
				      struct ubcore_res_key *key,
				      struct ubcore_res_val *val)
{
	struct ubcore_res_dev_tp_val *res_tp = (struct ubcore_res_dev_tp_val *)val->addr;
	int ret;
	int i;

	ret = hns3_udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return ret;

	spin_lock(&g_hns3_udma_dfx_list[i].dfx->tpn_list->node_lock);
	res_tp->tp_cnt = g_hns3_udma_dfx_list[i].dfx->tpn_cnt;
	spin_unlock(&g_hns3_udma_dfx_list[i].dfx->tpn_list->node_lock);

	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	res_tp->vtp_cnt = 0;
	res_tp->tpg_cnt = 0;
	res_tp->utp_cnt = 0;

	return 0;
}

int hns3_udma_query_res(struct ubcore_device *dev,
			struct ubcore_res_key *key, struct ubcore_res_val *val)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);

	switch (key->type) {
	case UBCORE_RES_KEY_TP:
		return hns3_udma_query_res_tp(udma_dev, key, val);
	case UBCORE_RES_KEY_JFS:
		return hns3_udma_query_res_jfs(udma_dev, key, val);
	case UBCORE_RES_KEY_JFR:
		return hns3_udma_query_res_jfr(udma_dev, key, val);
	case UBCORE_RES_KEY_JETTY:
		return hns3_udma_query_res_jetty(udma_dev, key, val);
	case UBCORE_RES_KEY_JFC:
		return hns3_udma_query_res_jfc(udma_dev, key, val);
	case UBCORE_RES_KEY_SEG:
		return hns3_udma_query_res_seg(udma_dev, key, val);
	case UBCORE_RES_KEY_DEV_TA:
		return hns3_udma_query_res_dev_ta(udma_dev, key, val);
	case UBCORE_RES_KEY_DEV_TP:
		return hns3_udma_query_res_dev_tp(udma_dev, key, val);
	default:
		dev_err(udma_dev->dev, "key type: %u invalid.\n", (uint32_t)key->type);
	}

	return -EINVAL;
}

HNS3_UDMA_DFX_FILE_ATTR_DEF(tp_context, NULL, hns3_udma_dfx_tp_store);
HNS3_UDMA_DFX_FILE_ATTR_DEF(jfr_context, NULL, hns3_udma_dfx_jfr_store);
HNS3_UDMA_DFX_FILE_ATTR_DEF(seg_context, NULL, hns3_udma_dfx_seg_store);
HNS3_UDMA_DFX_FILE_ATTR_DEF(jfc_context, NULL, hns3_udma_dfx_jfc_store);

static struct attribute *hns3_udma_dfx_attrs_list[] = {
	HW_ATTRS_LIST_MEMBER(tp_context),
	HW_ATTRS_LIST_MEMBER(jfr_context),
	HW_ATTRS_LIST_MEMBER(seg_context),
	HW_ATTRS_LIST_MEMBER(jfc_context),
	NULL
};

static ssize_t hns3_udma_dfx_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct hns3_udma_dfx_sys_attr *p_hns3_udma_sys_attr =
		container_of(attr, struct hns3_udma_dfx_sys_attr, attr);
	struct hns3_udma_dfx_info *hns3_udma_dfx =
		container_of(kobj, struct hns3_udma_dfx_info, kobj);
	int ret;

	memset(buf, 0, PAGE_SIZE);
	if (p_hns3_udma_sys_attr->pub_show) {
		ret = p_hns3_udma_sys_attr->pub_show(hns3_udma_dfx);
		if (ret)
			return ret;
		else
			return strlen(buf);
	}

	return -EPERM;
}

static ssize_t hns3_udma_dfx_store(struct kobject *kobj, struct attribute *attr,
			      const char *buf, size_t count)
{
	struct hns3_udma_dfx_sys_attr *p_hns3_udma_sys_attr =
		container_of(attr, struct hns3_udma_dfx_sys_attr, attr);
	struct hns3_udma_dfx_info *hns3_udma_dfx =
		container_of(kobj, struct hns3_udma_dfx_info, kobj);
	int ret;

	if (p_hns3_udma_sys_attr->pub_store) {
		ret = p_hns3_udma_sys_attr->pub_store((char *)buf, hns3_udma_dfx);
		if (ret)
			return ret;
		else
			return count;
	}

	return -EPERM;
}

static const struct sysfs_ops hns3_udma_dfx_file_ops = {
	.show  = hns3_udma_dfx_show,
	.store = hns3_udma_dfx_store,
};

static struct kobj_type hns3_udma_dfx_kobj_ktype = {
	.release		= NULL,
	.sysfs_ops		= &hns3_udma_dfx_file_ops,
	.default_attrs		= hns3_udma_dfx_attrs_list,
};

static int hns3_udma_dfx_add_sysfs(struct hns3_udma_dfx_info *hns3_udma_dfx)
{
	struct device *dev = hns3_udma_dfx->drv_dev;
	int ret;

	ret = kobject_init_and_add(&hns3_udma_dfx->kobj,
				   &hns3_udma_dfx_kobj_ktype,
				   &dev->kobj,
				   "%s", hns3_udma_dfx->dev.dev_name);
	if (ret)
		dev_err(drv_device, "kobject_init_and_add failed.\r\n");

	return ret;
}

static void hns3_udma_dfx_del_sysfs(struct hns3_udma_dfx_info *hns3_udma_dfx)
{
	kobject_del(&hns3_udma_dfx->kobj);
}

struct hns3_udma_dfx_ops hns3_udma_dfx_ops = {
	.add_sysfs = hns3_udma_dfx_add_sysfs,
	.del_sysfs = hns3_udma_dfx_del_sysfs,
};

static void list_lock_init(struct hns3_udma_dfx_info *dfx, int num)
{
	rwlock_init(&g_hns3_udma_dfx_list[num].rwlock);

	spin_lock_init(&dfx->tpn_list->node_lock);
	INIT_LIST_HEAD(&dfx->tpn_list->node);
	spin_lock_init(&dfx->jfs_list->node_lock);
	INIT_LIST_HEAD(&dfx->jfs_list->node);
	spin_lock_init(&dfx->jfr_list->node_lock);
	INIT_LIST_HEAD(&dfx->jfr_list->node);
	spin_lock_init(&dfx->jetty_list->node_lock);
	INIT_LIST_HEAD(&dfx->jetty_list->node);
	spin_lock_init(&dfx->jfc_list->node_lock);
	INIT_LIST_HEAD(&dfx->jfc_list->node);
	spin_lock_init(&dfx->seg_list->node_lock);
	INIT_LIST_HEAD(&dfx->seg_list->node);
}

static int hns3_udma_dfx_list_init(int num)
{
	struct hns3_udma_dfx_info *dfx;
	int ret = -ENOMEM;

	dfx = g_hns3_udma_dfx_list[num].dfx;

	dfx->tpn_list = kzalloc(sizeof(struct tpn_list), GFP_KERNEL);
	if (!dfx->tpn_list)
		return ret;

	dfx->jfs_list = kzalloc(sizeof(struct jfs_list), GFP_KERNEL);
	if (!dfx->jfs_list)
		goto tpn_list_alloc_failed;

	dfx->jfr_list = kzalloc(sizeof(struct jfr_list), GFP_KERNEL);
	if (!dfx->jfr_list)
		goto jfs_id_list_alloc_failed;

	dfx->jetty_list = kzalloc(sizeof(struct jetty_list), GFP_KERNEL);
	if (!dfx->jetty_list)
		goto jfr_id_list_alloc_failed;

	dfx->jfc_list = kzalloc(sizeof(struct jfc_list), GFP_KERNEL);
	if (!dfx->jfc_list)
		goto jetty_id_list_alloc_failed;

	dfx->seg_list = kzalloc(sizeof(struct seg_list), GFP_KERNEL);
	if (!dfx->seg_list)
		goto jfc_id_list_alloc_failed;

	list_lock_init(dfx, num);

	return 0;

jfc_id_list_alloc_failed:
	kfree(dfx->jfc_list);
jetty_id_list_alloc_failed:
	kfree(dfx->jetty_list);
jfr_id_list_alloc_failed:
	kfree(dfx->jfr_list);
jfs_id_list_alloc_failed:
	kfree(dfx->jfs_list);
tpn_list_alloc_failed:
	kfree(dfx->tpn_list);
	dev_err(drv_device, "dfx alloc list failed.\n");

	return ret;
}

#define DFX_LIST_FREE(name)						\
do {									\
	lock = &dfx->name##_list->node_lock;				\
	spin_lock_irqsave(lock, flags);					\
	list_for_each_entry_safe(name##_id, name##_tmp,	&dfx->name##_list->node, node) {	\
		list_del(&name##_id->node);				\
		kfree(name##_id);					\
	}								\
	spin_unlock_irqrestore(lock, flags);				\
} while (0)

static void hns3_udma_dfx_list_free(int num)
{
	struct jetty_list *jetty_id, *jetty_tmp;
	struct jfs_list *jfs_id, *jfs_tmp;
	struct jfr_list *jfr_id, *jfr_tmp;
	struct jfc_list *jfc_id, *jfc_tmp;
	struct seg_list *seg_id, *seg_tmp;
	struct tpn_list *tpn_id, *tpn_tmp;
	struct hns3_udma_dfx_info *dfx;
	unsigned long flags;
	spinlock_t *lock;

	dfx = g_hns3_udma_dfx_list[num].dfx;
	DFX_LIST_FREE(jetty);
	DFX_LIST_FREE(tpn);
	DFX_LIST_FREE(jfr);
	DFX_LIST_FREE(jfs);
	DFX_LIST_FREE(seg);
	DFX_LIST_FREE(jfc);
}

static int hns3_udma_dfx_add_hns3_udma_device(struct hns3_udma_dev *udma_dev)
{
	int ret;
	int i;

	if (hns3_udma_dev_count == MAX_HNS3_UDMA_DEV) {
		dev_err(drv_device,
			"hns3_udma dfx add device failed, g_hns3_udma_dfx_list is full.\n.");
		return -EINVAL;
	}
	for (i = 0; i < MAX_HNS3_UDMA_DEV; i++)
		if (!g_hns3_udma_dfx_list[i].dfx)
			break;
	if (i == MAX_HNS3_UDMA_DEV) {
		dev_err(drv_device, "no free hns3_udma dfx list.\n.");
		return -EINVAL;
	}

	g_hns3_udma_dfx_list[i].dev = udma_dev;
	g_hns3_udma_dfx_list[i].dfx = kzalloc(sizeof(struct hns3_udma_dfx_info),
					 GFP_KERNEL);
	if (!g_hns3_udma_dfx_list[i].dfx) {
		ret = -ENOMEM;
		goto dfx_info_alloc_failed;
	}
	g_hns3_udma_dfx_list[i].dfx->priv = (void *)udma_dev;
	g_hns3_udma_dfx_list[i].dfx->ops = &hns3_udma_dfx_ops;
	g_hns3_udma_dfx_list[i].dfx->drv_dev = drv_device;
	strlcpy(g_hns3_udma_dfx_list[i].dfx->dev.dev_name, udma_dev->dev_name,
		UBCORE_MAX_DEV_NAME);
	ret = hns3_udma_dfx_list_init(i);
	if (ret) {
		dev_err(drv_device, "dfx add dev list failed.\n");
		goto dfx_list_init_failed;
	}

	ret = g_hns3_udma_dfx_list[i].dfx->ops->add_sysfs(g_hns3_udma_dfx_list[i].dfx);
	if (ret) {
		dev_err(drv_device, "dfx add sysfs failed.\n");
		goto add_sysfs_failed;
	}

	dev_info(drv_device, "add hns3_udma device (%s) in hns3_udma dfx.\n",
		 g_hns3_udma_dfx_list[i].dfx->dev.dev_name);

	hns3_udma_dev_count++;

	return 0;

add_sysfs_failed:
	hns3_udma_dfx_list_free(i);
dfx_list_init_failed:
	kfree(g_hns3_udma_dfx_list[i].dfx);
	g_hns3_udma_dfx_list[i].dfx = NULL;
dfx_info_alloc_failed:
	g_hns3_udma_dfx_list[i].dev = NULL;
	return ret;
}

static int hns3_udma_dfx_chrdev_create(struct hns3_udma_dev *udma_dev)
{
	int ret;

	major = register_chrdev(0, DFX_DEVICE_NAME, &chr_ops);
	if (major < 0) {
		dev_err(udma_dev->dev, "hns3_udma dfx register the character device failed.\n");
		ret = major;
		goto device_register_failed;
	}

	drv_class = class_create(THIS_MODULE, DFX_DEVICE_NAME);
	if (IS_ERR(drv_class)) {
		dev_err(udma_dev->dev, "hns3_udma dfx class create failed.\n");
		ret = (int)PTR_ERR(drv_class);
		goto class_create_failed;
	}

	drv_device = device_create(drv_class, NULL, MKDEV(major, 0),
				   NULL, DFX_DEVICE_NAME);
	if (IS_ERR(drv_device)) {
		dev_err(udma_dev->dev, "hns3_udma dfx create device failed.\n");
		ret = (int)PTR_ERR(drv_device);
		goto device_create_failed;
	}

	return 0;

device_create_failed:
	drv_device = NULL;
	class_destroy(drv_class);
class_create_failed:
	drv_class = NULL;
	unregister_chrdev(major, DFX_DEVICE_NAME);
device_register_failed:
	major = -1;
	return ret;
}

static void hns3_udma_dfx_chrdev_destroy(void)
{
	device_destroy(drv_class, MKDEV(major, 0));
	drv_device = NULL;
	class_destroy(drv_class);
	drv_class = NULL;
	unregister_chrdev(major, DFX_DEVICE_NAME);
	major = -1;
}

int hns3_udma_dfx_init(struct hns3_udma_dev *udma_dev)
{
	int ret;

	if (!hns3_udma_dev_count) {
		ret = hns3_udma_dfx_chrdev_create(udma_dev);
		if (ret) {
			dev_err(udma_dev->dev, "hns3_udma dfx create chr device failed.\n");
			goto chrdev_create_failed;
		}
		dev_info(drv_device, "hns3_udma dfx create chr device success.\n");
	}

	ret = hns3_udma_dfx_add_hns3_udma_device(udma_dev);
	if (ret) {
		dev_err(drv_device, "hns3_udma dfx add hns3_udma device failed.\n");
		goto add_device_failed;
	}

	return 0;

add_device_failed:
	if (!hns3_udma_dev_count) {
		dev_info(drv_device, "hns3_udma dfx remove chr device.\n");
		hns3_udma_dfx_chrdev_destroy();
	}
chrdev_create_failed:
	return ret;
}

static void hns3_udma_dfx_remove_hns3_udma_device(struct hns3_udma_dev *udma_dev)
{
	int i;

	for (i = 0; i < MAX_HNS3_UDMA_DEV; i++) {
		write_lock(&g_hns3_udma_dfx_list[i].rwlock);
		if (g_hns3_udma_dfx_list[i].dev && g_hns3_udma_dfx_list[i].dev == udma_dev) {
			dev_info(drv_device, "remove hns3_udma device (%s) from hns3_udma dfx.\n",
				 g_hns3_udma_dfx_list[i].dfx->dev.dev_name);
			g_hns3_udma_dfx_list[i].dfx->ops->del_sysfs(g_hns3_udma_dfx_list[i].dfx);
			hns3_udma_dfx_list_free(i);

			kfree(g_hns3_udma_dfx_list[i].dfx);
			g_hns3_udma_dfx_list[i].dfx = NULL;
			g_hns3_udma_dfx_list[i].dev = NULL;
			hns3_udma_dev_count--;
			write_unlock(&g_hns3_udma_dfx_list[i].rwlock);
			break;
		}
		write_unlock(&g_hns3_udma_dfx_list[i].rwlock);
	}
}

void hns3_udma_dfx_uninit(struct hns3_udma_dev *udma_dev)
{
	if (!hns3_udma_dev_count) {
		dev_err(udma_dev->dev, "no hns3_udma dfx device.\n");
		return;
	}

	hns3_udma_dfx_remove_hns3_udma_device(udma_dev);
	if (!hns3_udma_dev_count) {
		dev_info(drv_device, "hns3_udma dfx remove chr device.\n");
		hns3_udma_dfx_chrdev_destroy();
	}
}
