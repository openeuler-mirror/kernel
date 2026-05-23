/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_npu_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : NIC Commands between Driver and NPU
 */

#ifndef NIC_NPU_CMD_H
#define NIC_NPU_CMD_H

/**
 * @enum hinic5_ucode_cmd
 * @brief Defines various commands related to NIC ucode
 *
 * @details This structure defines a series of commands related to NIC ucode, which are used to control NIC ucode behavior.
 */
enum hinic5_ucode_cmd {
	HINIC5_UCODE_CMD_MODIFY_QUEUE_CTX = 0, /* Modify queue context.
						* @see > hinic5_sq_ctxt_block
						*/
	HINIC5_UCODE_CMD_CLEAN_QUEUE_CONTEXT = 1, /* Clean queue context.
						   * @see > hinic5_clean_queue_ctxt
						   */
	HINIC5_UCODE_CMD_ARM_SQ = 2, /* Unused */
	HINIC5_UCODE_CMD_ARM_RQ = 3, /* Unused */
	HINIC5_UCODE_CMD_SET_RSS_INDIR_TABLE = 4, /* Set RSS indirect table.
						   * @see > nic_rss_indirect_tbl
						   */
	HINIC5_UCODE_CMD_SET_RSS_CONTEXT_TABLE = 5, /* Set RSS context table.
						     * @see > nic_rss_context_tbl
						     */
	HINIC5_UCODE_CMD_GET_RSS_INDIR_TABLE = 6,   /* Get RSS indirect table.
						     * @see > l2nic_cmdq_rss_indir_get
						     */
	HINIC5_UCODE_CMD_GET_RSS_CONTEXT_TABLE = 7,  /* Unused */
	HINIC5_UCODE_CMD_SET_IQ_ENABLE = 8, /* Unused */
	HINIC5_UCODE_CMD_SET_RQ_FLUSH = 10, /* Set RQ flush.
					     * @see > hinic5_cmd_set_rq_flush
					     */
	HINIC5_UCODE_CMD_MODIFY_VLAN_CTX = 11, /* Get rxq information.
						* @see > nic_vlan_ctx
						*/
	HINIC5_UCODE_CMD_PPA_HASH_TABLE = 12,    /* Unused*/
	HINIC5_UCODE_CMD_RXQ_INFO_GET = 13, /* Get rxq information.
					     * @see > hinic5_rxq_hw, < rxq_check_info
					     */
	HINIC5_UCODE_MIG_CFG_Q_CTX = 16,    /* Hot migration operation context table.
					     * @see > l2nic_migrate_op_ctx
					     */
	HINIC5_UCODE_MIG_CHK_SQ_STOP = 17,   /* Unused */
	HINIC5_UCODE_MIG_CHK_RQ_STOP = 18,   /* Hot migration check rq start/stop status.
					      * @see > l2nic_cmdq_migrate_check_rq_stop
					      */
	HINIC5_UCODE_MIG_CHK_CMDQ_STOP = 19, /* Hot migration check cmdq start/stop status.
					      * @see > l2nic_cmdq_migrate_check_cmdq_stop
					      */
	HINIC5_UCODE_MIG_CFG_BAT_INFO = 20,  /* Hot migration read/write bat table.
					      * @see > l2nic_migrate_cfg_bat
					      */
	HINIC5_UCODE_MIG_COMPENSATE_INTR = 21,   /* Hot migration interrupt compensation.
						  * @see > l2nic_cmdq_migrate_compensate_intr
						  */
	HINIC5_UCODE_MIG_CFG_FAST_MSG = 22,
	HINIC5_UCODE_CMD_CLEAR_VPORT_STATS = 23,   /* Get counter statistics.
						    * @see > l2nic_cmdq_get_vport_stats
						    */
	HINIC5_UCODE_CMD_GET_VPORT_STATS = 24,   /* Clear counter statistics.
						  * @see > l2nic_cmdq_clear_vport_stats
						  */

	HINIC5_UCODE_CMD_EXTEND_SECTION1_START = 192, /* NIC CMDQ reserved command start, for computing product line use */
	HINIC5_UCODE_CMD_EXTEND_SECTION1_END = 223, /* NIC CMDQ reserved command end, for computing product line use */
	HINIC5_UCODE_CMD_EXTEND_SECTION2_START = 224, /* NIC CMDQ reserved command start, for storage product line use */
	HINIC5_UCODE_CMD_EXTEND_SECTION2_END = 255,  /* NIC CMDQ reserved command end, for storage product line use */

	HINIC5_UCODE_CMD_MAX = 255,
};

#endif /* NIC_NPU_CMD_H */
