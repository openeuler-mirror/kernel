/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef NIC_NPU_CMD_H
#define NIC_NPU_CMD_H

/* NIC CMDQ MODE */
enum hinic3_ucode_cmd {
	/**< Modify queue context. @see > hinic3_sq_ctxt_block */
	HINIC3_UCODE_CMD_MODIFY_QUEUE_CTX = 0,
	/**< Clean queue context. @see > hinic3_clean_queue_ctxt */
	HINIC3_UCODE_CMD_CLEAN_QUEUE_CONTEXT,
	HINIC3_UCODE_CMD_ARM_SQ, /**< Unused */
	HINIC3_UCODE_CMD_ARM_RQ,	/**< Unused */
	/**< Set RSS indir table. @see > nic_rss_indirect_tbl */
	HINIC3_UCODE_CMD_SET_RSS_INDIR_TABLE,
	/**< Set RSS indir table. @see > nic_rss_context_tbl */
	HINIC3_UCODE_CMD_SET_RSS_CONTEXT_TABLE,
	HINIC3_UCODE_CMD_GET_RSS_INDIR_TABLE,
	HINIC3_UCODE_CMD_GET_RSS_CONTEXT_TABLE,	/**< Unused */
	HINIC3_UCODE_CMD_SET_IQ_ENABLE,	/**< Unused */
	HINIC3_UCODE_CMD_SET_RQ_FLUSH = 10, /**< Set RQ flush. @see > hinic3_cmd_set_rq_flush */
	HINIC3_UCODE_CMD_MODIFY_VLAN_CTX, /**< Get rxq info. @see > nic_vlan_ctx */
	HINIC3_UCODE_CMD_PPA_HASH_TABLE,
	/**< Get rxq info. @see > hinic3_rxq_hw, < rxq_check_info */
	HINIC3_UCODE_CMD_RXQ_INFO_GET = 13,
};

#endif /* NIC_NPU_CMD_H */
