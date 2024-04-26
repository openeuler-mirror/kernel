// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>
#include "hinic3_hw.h"
#include "hmm_comp.h"


struct hmm_comp_priv *get_hmm_comp_priv(void *hwdev, u32 service_type)
{
	return (struct hmm_comp_priv *)hinic3_get_service_adapter(hwdev,
		(enum hinic3_service_type)service_type);
}

static void assemble_mpt_hw2sw(struct rdma_mpt_hw2sw_inbuf **mpt_hw2sw_inbuf,
	struct hmm_comp_priv *comp_priv, struct tag_cqm_cmd_buf *cqm_cmd_inbuf)
{
	*mpt_hw2sw_inbuf = (struct rdma_mpt_hw2sw_inbuf *)cqm_cmd_inbuf->buf;
	memset(*mpt_hw2sw_inbuf, 0, sizeof(struct rdma_mpt_hw2sw_inbuf));

	(*mpt_hw2sw_inbuf)->dmtt_flags = 0; /* 默认按VF踢除cache */
	(*mpt_hw2sw_inbuf)->dmtt_num = 0;
	(*mpt_hw2sw_inbuf)->dmtt_cache_line_start = cpu_to_be32(comp_priv->rdma_cap.dmtt_cl_start);
	(*mpt_hw2sw_inbuf)->dmtt_cache_line_end = cpu_to_be32(comp_priv->rdma_cap.dmtt_cl_end);
	(*mpt_hw2sw_inbuf)->dmtt_cache_line_size = cpu_to_be32(comp_priv->rdma_cap.dmtt_cl_sz);
}

int hmm_enable_roce_mpt(void *hwdev, struct tag_cqm_cmd_buf *cqm_cmd_inbuf, u16 channel)
{
	int ret;

	ret = cqm_send_cmd_box(hwdev, HINIC3_MOD_ROCE, RDMA_ROCE_CMD_SW2HW_MPT,
		cqm_cmd_inbuf, NULL, NULL, RDMA_CMD_TIME_OUT_A, channel);
	if (ret != 0) {
		if (hinic3_get_heartbeat_status(hwdev) != PCIE_LINK_DOWN) {
			pr_err("%s: Send cmd rdma_roce_cmd_sw2hw_mpt failed, ret(%d)\n",
				__func__, ret);
			if ((ret == (-ETIMEDOUT)) || (ret == (-EPERM)))
				return -RDMA_CMDQ_TIMEOUT;

			return -RDMA_CMDQ_ERR;
		}
		pr_err("%s: Card not present, return err\n", __func__);
		return -RDMA_CMDQ_ERR;
	}

	return 0;
}

static int hmm_mpt_read_back_test(struct hmm_comp_priv *comp_priv, struct rdma_mpt *mpt)
{
	int retry;
	struct rdma_mpt_entry *mpt_entry = NULL;
	struct rdma_mpt_entry check_mpt_entry;

	/* 获取Host MPT内容 */
	mpt_entry = (struct rdma_mpt_entry *)mpt->vaddr;
	for (retry = 0; retry < RDMA_MAX_RETRY; retry++) {
		if (hinic3_get_heartbeat_status(comp_priv->hwdev) == PCIE_LINK_DOWN) {
			pr_err("%s: Card not present, return ok\n", __func__);
			return 0;
		}
		/*
		 * Confirm that the chip operation is complete by comparing the MPT State field.
		 * If the readback status is correct, the loop exits. Otherwise,
		 * the loop continues to read and compare data after a forcible
		 * delay until the loop ends.
		 */
		check_mpt_entry.roce_mpt_ctx.dw2.value =
			be32_to_cpu(mpt_entry->roce_mpt_ctx.dw2.value);
		if (check_mpt_entry.roce_mpt_ctx.dw2.bs.status == RDMA_MPT_STATUS_INVALID)
			return 0;

		/*lint -e160 -e506*/
		mdelay(RDMA_MS_DELAY);
	}

	pr_err("%s: RoCE mpt state read times(%d), mpt_index(0x%x), state_dw(0x%x)\n",
		__func__, retry, mpt->mpt_index, mpt_entry->roce_mpt_ctx.dw2.value);
	return -RDMA_CMDQ_ERR;
}

int hmm_disable_roce_mpt(struct hmm_comp_priv *comp_priv, struct rdma_mpt *mpt, u16 channel)
{
	int ret;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct rdma_mpt_hw2sw_inbuf *mpt_hw2sw_inbuf = NULL;

	cqm_cmd_inbuf = cqm_cmd_alloc(comp_priv->hwdev);
	if (cqm_cmd_inbuf == NULL) {
		pr_err("%s: RoCE alloc cmd_buf failed, err(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}
	cqm_cmd_inbuf->size = (u16)sizeof(struct rdma_mpt_hw2sw_inbuf);
	assemble_mpt_hw2sw(&mpt_hw2sw_inbuf, comp_priv, cqm_cmd_inbuf);
	mpt_hw2sw_inbuf->com.index = cpu_to_be32(mpt->mpt_index);
	mpt_hw2sw_inbuf->com.dw0.bs.cmd_bitmask = (u16)cpu_to_be16(VERBS_CMD_TYPE_MR_BITMASK);
	ret = cqm_send_cmd_box(comp_priv->hwdev, HINIC3_MOD_ROCE, RDMA_ROCE_CMD_HW2SW_MPT,
		cqm_cmd_inbuf, NULL, NULL, RDMA_CMD_TIME_OUT_A, channel);
	if (ret != 0) {
		if (hinic3_get_heartbeat_status(comp_priv->hwdev) != PCIE_LINK_DOWN) {
			pr_err("%s: Send cmd rdma_roce_cmd_hw2sw_mpt failed, ret(%d)\n",
				__func__, ret);
			cqm_cmd_free(comp_priv->hwdev, cqm_cmd_inbuf);
			if ((ret == (-ETIMEDOUT)) || (ret == (-EPERM)))
				return -RDMA_CMDQ_TIMEOUT;

			return -RDMA_CMDQ_ERR;
		}
		pr_err("%s: Card not present, return ok\n", __func__);
		cqm_cmd_free(comp_priv->hwdev, cqm_cmd_inbuf);
		return 0;
	}
	cqm_cmd_free(comp_priv->hwdev, cqm_cmd_inbuf);

	ret = hmm_mpt_read_back_test(comp_priv, mpt);
	return ret;
}


int hmm_modify_roce_mpt(void *hwdev, u32 mpt_index, u32 new_key, u64 length, u64 iova, u16 channel)
{
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf;
	struct rdma_mpt_modify_inbuf *mpt_modify_inbuf = NULL;
	int ret;

	cqm_cmd_inbuf = cqm_cmd_alloc(hwdev);
	if (cqm_cmd_inbuf == NULL) {
		pr_err("%s: RoCE alloc cmd_buf failed, err(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}

	cqm_cmd_inbuf->size = (u16)sizeof(struct rdma_mpt_modify_inbuf);
	mpt_modify_inbuf = (struct rdma_mpt_modify_inbuf *)cqm_cmd_inbuf->buf;
	memset(mpt_modify_inbuf, 0, sizeof(*mpt_modify_inbuf));

	mpt_modify_inbuf->com.dw0.bs.cmd_bitmask = (u16)cpu_to_be16(VERBS_CMD_TYPE_MR_BITMASK);
	mpt_modify_inbuf->com.index = cpu_to_be32(mpt_index);
	mpt_modify_inbuf->new_key = cpu_to_be32(new_key);
	mpt_modify_inbuf->length = cpu_to_be64(length);
	mpt_modify_inbuf->iova = cpu_to_be64(iova);

	ret = cqm_send_cmd_box(hwdev, HINIC3_MOD_ROCE, RDMA_ROCE_CMD_MODIFY_MPT,
		cqm_cmd_inbuf, NULL, NULL, RDMA_CMD_TIME_OUT_A, channel);
	if (ret != 0) {
		if (hinic3_get_heartbeat_status(hwdev) != PCIE_LINK_DOWN) {
			pr_err("%s: Send cmd rdma_roce_cmd_modify_mpt failed, ret(%d)\n",
				__func__, ret);
			cqm_cmd_free(hwdev, cqm_cmd_inbuf);
			if ((ret == (-ETIMEDOUT)) || (ret == (-EPERM)))
				return -RDMA_CMDQ_TIMEOUT;

			return -RDMA_CMDQ_ERR;
		}
		pr_err("%s: Card not present, return ok\n", __func__);
		cqm_cmd_free(hwdev, cqm_cmd_inbuf);
		return 0;
	}

	cqm_cmd_free(hwdev, cqm_cmd_inbuf);

	return 0;
}
