// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */
#include <linux/io.h>
#include <linux/sort.h>

#include "ub_cmdq.h"
#include "ub_cmd_ummu.h"

#define UBCTL_HW_VER_A_0_BIT_MASK 1U
#define UBCTL_HW_VER_A_1_BIT_MASK 2U
#define UBCTL_HW_VER_K_0_BIT_MASK 4U
#define UBCTL_HW_VER_K_1_BIT_MASK 8U

#define UBCTL_REG_SUPPORT_K1_ONLY UBCTL_HW_VER_K_1_BIT_MASK
#define UBCTL_REG_SUPPORT_ALL (UBCTL_HW_VER_A_0_BIT_MASK | UBCTL_HW_VER_A_1_BIT_MASK | \
			       UBCTL_HW_VER_K_0_BIT_MASK | UBCTL_HW_VER_K_1_BIT_MASK)

#define UBCTL_UMMU_TECT_TAG_INFO_COUNT 64U

struct ubctl_ummu_reg_info {
	u32 addr;
	u32 env_support;
};

static struct ubctl_ummu_reg_info g_ubctl_ummu_reg_addr[] = {
	// KCMD
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_KCMD_STATUS, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_KCMD_ERR_STATUS, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_FSM_STATUS_DFX0, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_SWIF_FSM_STATUS_DFX1, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_SWIF_FSM_STATUS_DFX2, UBCTL_REG_SUPPORT_K1_ONLY },
	// CMD_CTRL
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_SNP_ERR_CNT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_3, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_4, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_5, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_6, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_7, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_8, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_9, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_10, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_11, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_12, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_13, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_14, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_15, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_SNP_STATUS, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_CTRL_STATUS1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_CTRL_STATUS2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SYNC_TIMEOUT_INFO, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_DVM_RECEIVE_REQ_CNT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_DVM_SEND_REQ_CNT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_DVM_REQ_INFO0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_DVM_REQ_INFO1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_FSM_STATUS_DFX3, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_SWIF_FSM_STATUS_DFX4, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_SWIF_DFX_QID_STATUS0, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_SWIF_DFX_QID_STATUS1, UBCTL_REG_SUPPORT_K1_ONLY },
	// UCMD
	{ UBCTL_UMMU_SWIF_UMCMD_DFX0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_DFX1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_DFX2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_DFX3, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_3, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_4, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_5, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_6, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX3, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX4, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX5, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX6, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SWIF_UMCMD_NO_READY, UBCTL_REG_SUPPORT_K1_ONLY },
	// EVENT
	{ UBCTL_UMMU_SWIF_EVENTQ_DFX_DROP_CNT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_GLB_INT_EN, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_PMCG_INT_EN, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_INT_MASK, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_CTRL1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_SPEC_DEF_DFX, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TECT_BASE_CFG, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_ERR_STATUS_0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_ROOT_GPF_FAR_L, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_ROOT_GPF_FAR_H, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_EVENT_QUE_PI, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_EVENT_QUE_CI, UBCTL_REG_SUPPORT_ALL },
	// UBIF
	{ UBCTL_UMMU_UBIF_DFX0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_DFX1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_DSTEID_DFX, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_SYNC_DFX, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX3, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX4, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_UBIF_QUEUE_DFX, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_UBIF_KV_CACHE_DFX, UBCTL_REG_SUPPORT_K1_ONLY },
	// TBU
	{ UBCTL_UMMU_TBU_TLB_LKUP_PROC, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_TLB_STAT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_TLB_FAULT_CNT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_PLB_LKUP_PROC, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_PLB_STAT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_PLB_FAULT_CNT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_INVLD_MG_INFO, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_RAB_STAT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_CNT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_DFX_TBU_PERM_ERR_CNT, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_DFX0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_DFX1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TBU_IOPF_STS0, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_TBU_IOPF_STS1, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_TBU_IOPF_STS2, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_TBU_IOPF_STS3, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_TBU_RAB_TECT_TAG_INFO_0_63, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_TBU_RAB_ENTRY_INFO_0_7_15, UBCTL_REG_SUPPORT_ALL },
	// TCU
	{ UBCTL_UMMU_TCU_PTW_QUEUE_STAT_0_47, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TCU_PPTW_QUEUE_STAT_0_39, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_TCU_QUEUE_STAT, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_TCU_ITF_STAT0, UBCTL_REG_SUPPORT_K1_ONLY },
	// CCT
	{ UBCTL_UMMU_CCT_REQ_QUE_INFO0_DFX_0_31, UBCTL_REG_SUPPORT_K1_ONLY },
	// CFG
	{ UBCTL_UMMU_DFX_ECC_MONITOR_0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_DFX_ECC_MONITOR_1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_DFX_ECC_MONITOR_2, UBCTL_REG_SUPPORT_K1_ONLY },
	{ UBCTL_UMMU_CFG_DFX_CFGBUS_STATUS, UBCTL_REG_SUPPORT_ALL },
	// GPC
	{ UBCTL_UMMU_GPC_QUEUE_STAT_0_15, UBCTL_REG_SUPPORT_ALL },
	// SKY
	{ UBCTL_UMMU_SKY_QUEUE_STAT3_SP_0_63, UBCTL_REG_SUPPORT_ALL },
	// MCMD
	{ UBCTL_UMMU_MCMD_QUE_PI_0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_PI_1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_PI_2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_PI_3, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_PI_4, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_PI_5, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_PI_6, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_PI_7, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_CI_0, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_CI_1, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_CI_2, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_CI_3, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_CI_4, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_CI_5, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_CI_6, UBCTL_REG_SUPPORT_ALL },
	{ UBCTL_UMMU_MCMD_QUE_CI_7, UBCTL_REG_SUPPORT_ALL },
	// UMMU_EN
	{ UBCTL_UMMU_CTRL0, UBCTL_REG_SUPPORT_ALL },
	// OTHER
	{ UBCTL_UMMU_SYNC_TIMEOUT_OPEN, UBCTL_REG_SUPPORT_ALL },
};

static u32 g_ubctl_env_type;

#define UBCTL_UMMU_READ_ADDR_MAX 8
struct ubctl_ummu_relation {
	u32 reg_addr_list[UBCTL_UMMU_READ_ADDR_MAX];
	u32 reg_config_addr;
	u32 reg_count;
};

static int compare_resources(const void *a, const void *b)
{
	const struct resource *ra = *(const struct resource **)a;
	const struct resource *rb = *(const struct resource **)b;

	if (ra->start < rb->start)
		return -1;
	if (ra->start > rb->start)
		return 1;
	return 0;
}

static struct resource *ubctl_find_and_sort_resources(struct ubctl_dev *ucdev,
						      struct resource *root,
						      const char *name_substr,
						      u32 ummu_id)
{
#define UBCL_MAX_UMMU_NUM 32U

	struct resource *entry_arr[UBCL_MAX_UMMU_NUM] = {};
	struct resource *p;
	u32 count = 0;

	/*
	 * To traverse the UMMU memory subtree, only need to traverse the child
	 * subtree of the root node.
	 */
	for (p = root->child; p; p = p->sibling) {
		if (!p->name || !strstr(p->name, name_substr))
			continue;
		if (count >= UBCL_MAX_UMMU_NUM) {
			ubctl_err(ucdev, "ummu resources = %u must be in (0, %u).\n",
				  count, UBCL_MAX_UMMU_NUM);
			return NULL;
		}
		entry_arr[count] = p;
		count++;
	}

	if (ummu_id >= count) {
		ubctl_err(ucdev, "ummuid = %u is out of range, current count = %u\n",
			  ummu_id, count);
		return NULL;
	}

	sort(entry_arr, count, sizeof(struct resource *), compare_resources, NULL);

	return entry_arr[ummu_id];
}

static inline u32 ubctl_ummu_get_register_offset(u32 index)
{
	return g_ubctl_ummu_reg_addr[index].addr - UBCTL_UMMU_REGISTER_BASE;
}

static bool ubctl_ummu_is_reg_supported(u32 hw_version, u32 env_support)
{
	switch (hw_version) {
	case UBASE_HW_VER_A_0:
		return env_support & UBCTL_HW_VER_A_0_BIT_MASK;
	case UBASE_HW_VER_A_1:
		return env_support & UBCTL_HW_VER_A_1_BIT_MASK;
	case UBASE_HW_VER_K_0:
		return env_support & UBCTL_HW_VER_K_0_BIT_MASK;
	case UBASE_HW_VER_K_1:
		return env_support & UBCTL_HW_VER_K_1_BIT_MASK;
	default:
		return false;
	}
}

static u32 ubctl_ummu_get_reg_count(void)
{
#define UBCTL_UMMU_REPEAT_REG_TYPE_COUNT 7U
#define UBCTL_UMMU_TCU_PPTW_STAT_COUNT 2U
#define UBCTL_UMMU_TCU_CCT_STAT_COUNT 5U
#define UBCTL_UMMU_SKY_STAT_COUNT 4U

	return ARRAY_SIZE(g_ubctl_ummu_reg_addr) + UBCTL_UMMU_GPC_QUEUE_COUNT +
	       UBCTL_UMMU_SKY_QUEUE_COUNT * UBCTL_UMMU_SKY_STAT_COUNT +
	       UBCTL_UMMU_TCU_PTW_QUEUE_COUNT +
	       UBCTL_UMMU_TCU_PPTW_QUEUE_COUNT * UBCTL_UMMU_TCU_PPTW_STAT_COUNT +
	       UBCTL_UMMU_ENTRY_NUM * UBCTL_UMMU_BANK_NUM - UBCTL_UMMU_REPEAT_REG_TYPE_COUNT +
	       UBCTL_UMMU_CCT_QUEUE_COUNT * UBCTL_UMMU_TCU_CCT_STAT_COUNT +
	       UBCTL_UMMU_TECT_TAG_INFO_COUNT;
}

struct ubctl_reg_pro_cmd {
	struct ubctl_dev *ucdev;
	u32 reg_index;
	void __iomem *map_addr;
	u32 *ummu_data;
	u32 map_length;
	u32 *index_offset;
};

static int ubctl_ummu_normal_read(struct ubctl_reg_pro_cmd *cmd)
{
	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();
	u32 reg_addr_offset;

	reg_addr_offset = ubctl_ummu_get_register_offset(cmd->reg_index);
	if ((reg_addr_offset >= cmd->map_length) || (*cmd->index_offset >= ummu_reg_cnt)) {
		ubctl_err(cmd->ucdev, "ummu reg offset is bigger than map length, index=%u, reg offset=%#x, map length=%u, ummu_reg_cnt=%u.\n",
			  *cmd->index_offset, reg_addr_offset, cmd->map_length, ummu_reg_cnt);
		return -EFAULT;
	}
	cmd->ummu_data[*cmd->index_offset] = readl(cmd->map_addr + reg_addr_offset);
	(*cmd->index_offset)++;

	return 0;
}

static struct ubctl_ummu_relation *ubctl_ummu_get_relation(struct ubctl_reg_pro_cmd *cmd)
{
	static struct ubctl_ummu_relation ummu_relation[] = {
		{ { UBCTL_UMMU_GPC_QUEUE_STAT_0_15 }, UBCTL_UMMU_GPC_QUEUE_POINTER,
		  UBCTL_UMMU_GPC_QUEUE_COUNT },
		{ { UBCTL_UMMU_SKY_QUEUE_STAT3_SP_0_63 }, UBCTL_UMMU_SKY_QUEUE_POINTER_SP,
		  UBCTL_UMMU_SKY_QUEUE_COUNT },
		{ { UBCTL_UMMU_TCU_PTW_QUEUE_STAT_0_47 }, UBCTL_UMMU_TCU_PTW_QUEUE_POINTER,
		  UBCTL_UMMU_TCU_PTW_QUEUE_COUNT },
		{ { UBCTL_UMMU_TCU_PPTW_QUEUE_STAT_0_39 }, UBCTL_UMMU_TCU_PPTW_QUEUE_POINTER,
		  UBCTL_UMMU_TCU_PPTW_QUEUE_COUNT }
	};
	static struct ubctl_ummu_relation ummu_relation_K1[] = {
		{ { UBCTL_UMMU_GPC_QUEUE_STAT_0_15 }, UBCTL_UMMU_GPC_QUEUE_POINTER,
		  UBCTL_UMMU_GPC_QUEUE_COUNT },
		{ { UBCTL_UMMU_SKY_QUEUE_STAT3_SP_0_63, UBCTL_UMMU_SKY_QUEUE_STAT0_SP_0_63,
		    UBCTL_UMMU_SKY_QUEUE_STAT1_SP_0_63, UBCTL_UMMU_SKY_QUEUE_STAT2_SP_0_63 },
		  UBCTL_UMMU_SKY_QUEUE_POINTER_SP, UBCTL_UMMU_SKY_QUEUE_COUNT },
		{ { UBCTL_UMMU_TCU_PTW_QUEUE_STAT_0_47 }, UBCTL_UMMU_TCU_PTW_QUEUE_POINTER,
		  UBCTL_UMMU_TCU_PTW_QUEUE_COUNT },
		{ { UBCTL_UMMU_TCU_PPTW_QUEUE_STAT_0_39, UBCTL_UMMU_TCU_PPTW_QUEUE_STAT1_0_39 },
		 UBCTL_UMMU_TCU_PPTW_QUEUE_POINTER, UBCTL_UMMU_TCU_PPTW_QUEUE_COUNT },
		{ { UBCTL_UMMU_CCT_REQ_QUE_INFO0_DFX_0_31, UBCTL_UMMU_CCT_REQ_QUE_INFO1_DFX_0_31,
		    UBCTL_UMMU_CCT_REQ_QUE_INFO2_DFX_0_31, UBCTL_UMMU_CCT_REQ_QUE_INFO3_DFX_0_31,
		    UBCTL_UMMU_CCT_REQ_QUE_INFO4_DFX_0_31 }, UBCTL_UMMU_CCT_REQ_QUE_SEL_DFX,
		  UBCTL_UMMU_CCT_QUEUE_COUNT }
	};
	u32 target_reg_addr = g_ubctl_ummu_reg_addr[cmd->reg_index].addr;
	struct ubctl_ummu_relation *relation = NULL;
	struct ubctl_ummu_relation *relation_table;
	u32 relation_table_size;
	u32 i, j;

	if (g_ubctl_env_type == UBASE_HW_VER_K_1) {
		relation_table = ummu_relation_K1;
		relation_table_size = ARRAY_SIZE(ummu_relation_K1);
	} else {
		relation_table = ummu_relation;
		relation_table_size = ARRAY_SIZE(ummu_relation);
	}

	for (i = 0; i < relation_table_size; i++) {
		for (j = 0; j < UBCTL_UMMU_READ_ADDR_MAX &&
		     relation_table[i].reg_addr_list[j] != 0; j++) {
			if (relation_table[i].reg_addr_list[j] == target_reg_addr) {
				relation = &relation_table[i];
				break;
			}
		}
		if (relation != NULL)
			break;
	}

	return relation;
}

static int ubctl_ummu_process_repeat_reg(struct ubctl_reg_pro_cmd *cmd)
{
	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();
	struct ubctl_ummu_relation *relation = NULL;
	u32 set_reg_offset, read_reg_offset;
	u32 i, j;

	relation = ubctl_ummu_get_relation(cmd);
	if (relation == NULL)
		return ubctl_ummu_normal_read(cmd);

	set_reg_offset = relation->reg_config_addr - UBCTL_UMMU_REGISTER_BASE;
	if (set_reg_offset >= cmd->map_length) {
		ubctl_err(cmd->ucdev, "ummu set reg offset is bigger than map length, set offset=%#x, map length=%#x.\n",
			  set_reg_offset, cmd->map_length);
		return -EFAULT;
	}

	for (j = 0; j < ARRAY_SIZE(relation->reg_addr_list) &&
		    relation->reg_addr_list[j] != 0; j++) {
		read_reg_offset = relation->reg_addr_list[j] - UBCTL_UMMU_REGISTER_BASE;
		if (read_reg_offset >= cmd->map_length) {
			ubctl_err(cmd->ucdev, "ummu read reg offset is bigger than map length, read offset=%#x, map length=%#x.\n",
				  read_reg_offset, cmd->map_length);
			return -EFAULT;
		}

		for (i = 0; i < relation->reg_count; i++) {
			writel(i, cmd->map_addr + set_reg_offset);

			if (*cmd->index_offset >= ummu_reg_cnt) {
				ubctl_err(cmd->ucdev, "index offset is bigger than ummu reg count, index offset=%u, ummu reg count=%u, read offset=%#x.\n",
					  *cmd->index_offset, ummu_reg_cnt, read_reg_offset);
				return -EFAULT;
			}

			cmd->ummu_data[*cmd->index_offset] = readl(cmd->map_addr + read_reg_offset);
			(*cmd->index_offset)++;
		}
	}

	return 0;
}

static int ubctl_ummu_read_tect_tag_info(struct ubctl_reg_pro_cmd *cmd)
{
#define UBCTL_UMMU_TECT_TAG_INFO_OFFSET 0x04U

	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();
	u32 read_reg_offset;
	u32 i;

	read_reg_offset = ubctl_ummu_get_register_offset(cmd->reg_index);
	if ((read_reg_offset >= cmd->map_length) || (*cmd->index_offset >= ummu_reg_cnt)) {
		ubctl_err(cmd->ucdev, "ummu reg offset is bigger than map length, index=%u, reg offset=%#x, map length=%u, ummu_reg_cnt=%u.\n",
			  *cmd->index_offset, read_reg_offset, cmd->map_length, ummu_reg_cnt);
		return -EFAULT;
	}

	for (i = 0; i < UBCTL_UMMU_TECT_TAG_INFO_COUNT; i++) {
		if (*cmd->index_offset >= ummu_reg_cnt) {
			ubctl_err(cmd->ucdev, "index offset is bigger than ummu reg count, index offset=%u, ummu reg count=%u, read offset=%#x.\n",
				  *cmd->index_offset, ummu_reg_cnt, read_reg_offset);
			return -EFAULT;
		}

		cmd->ummu_data[*cmd->index_offset] = readl(cmd->map_addr + read_reg_offset);
		(*cmd->index_offset)++;

		read_reg_offset += UBCTL_UMMU_TECT_TAG_INFO_OFFSET;
	}

	return 0;
}

static int ubctl_ummu_process_reg(struct ubctl_reg_pro_cmd *cmd)
{
#define UBCTL_TBU_MASK 0xFFFFFC00U
#define UBCTL_BANK_OFFSET 6

	u32 read_reg_offset, set_reg_offset, origin_value, value, i, j;
	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();

	if (g_ubctl_ummu_reg_addr[cmd->reg_index].addr == UBCTL_UMMU_TBU_RAB_TECT_TAG_INFO_0_63)
		return ubctl_ummu_read_tect_tag_info(cmd);

	if (g_ubctl_ummu_reg_addr[cmd->reg_index].addr != UBCTL_UMMU_TBU_RAB_ENTRY_INFO_0_7_15)
		return ubctl_ummu_process_repeat_reg(cmd);

	set_reg_offset = UBCTL_UMMU_TBU_RAB_FUNC_EN - UBCTL_UMMU_REGISTER_BASE;
	read_reg_offset = UBCTL_UMMU_TBU_RAB_ENTRY_INFO_0_7_15 -
			  UBCTL_UMMU_REGISTER_BASE;
	if ((set_reg_offset >= cmd->map_length) ||
	    (read_reg_offset >= cmd->map_length)) {
		ubctl_err(cmd->ucdev,
			  "ummu set or read reg offset is bigger than map length, set offset=%#x, read offset=%#x, map length=%u.\n",
			  set_reg_offset, read_reg_offset, cmd->map_length);
		return -EFAULT;
	}

	origin_value = readl(cmd->map_addr + set_reg_offset);
	origin_value &= UBCTL_TBU_MASK;
	for (i = 0; i < UBCTL_UMMU_BANK_NUM; i++) {
		for (j = 0; j < UBCTL_UMMU_ENTRY_NUM; j++, (*cmd->index_offset)++) {
			value = (i << UBCTL_BANK_OFFSET) | j | origin_value;
			writel(value, cmd->map_addr + set_reg_offset);
			if (*cmd->index_offset >= ummu_reg_cnt) {
				ubctl_err(cmd->ucdev, "index offset is bigger than ummu reg count, index offset=%u, read offset=%#x, ummu reg count=%u.\n",
					  *cmd->index_offset, read_reg_offset, ummu_reg_cnt);
				return -EFAULT;
			}
			cmd->ummu_data[*cmd->index_offset] = readl(cmd->map_addr + read_reg_offset);
		}
	}
	return 0;
}

static int ubctl_ummu_copy_data(struct ubctl_dev *ucdev,
				struct ubctl_query_cmd_param *query_cmd_param,
				void __iomem *map_addr, u32 map_length)
{
	u32 ummu_array_cnt = ARRAY_SIZE(g_ubctl_ummu_reg_addr);
	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();
	u32 *ummu_data = query_cmd_param->out->data;
	u32 index_offset = 0;
	int ret;
	u32 i;

	struct ubctl_reg_pro_cmd reg_pro_cmd = {
		.ucdev = ucdev,
		.reg_index = 0,
		.map_addr = map_addr,
		.ummu_data = ummu_data,
		.map_length = map_length,
		.index_offset = &index_offset,
	};

	if (ummu_reg_cnt * sizeof(u32) > query_cmd_param->out_len) {
		ubctl_err(ucdev, "ummu reg size is big than out len, reg sie=%lu, out len=%lu.\n",
			  ummu_reg_cnt * sizeof(u32), query_cmd_param->out_len);
		return -EINVAL;
	}

	for (i = 0; i < ummu_array_cnt; i++) {
		if (!(ubctl_ummu_is_reg_supported(g_ubctl_env_type,
		      g_ubctl_ummu_reg_addr[i].env_support)))
			continue;
		reg_pro_cmd.reg_index = i;
		ret = ubctl_ummu_process_reg(&reg_pro_cmd);
		if (ret) {
			ubctl_err(ucdev, "failed to execute ummu process reg, ret=%d.\n", ret);
			return ret;
		}
	}
	query_cmd_param->out->data_size = ummu_reg_cnt * sizeof(u32);

	return 0;
}

static int ubctl_ummu_proc_all_data(struct ubctl_dev *ucdev, struct resource *res,
				    struct ubctl_query_cmd_param *query_cmd_param)
{
	u32 map_length = UBCTL_UMMU_REGISTER_MAX_ADDR - UBCTL_UMMU_REGISTER_BASE;
	void __iomem *vaddr;
	int ret;

	vaddr = ioremap(res->start + UBCTL_UMMU_REGISTER_BASE, map_length);
	if (!vaddr) {
		ubctl_err(ucdev, "failed to execute ioremap ummu reg base, map length = %u.\n",
			  map_length);
		return -ENOMEM;
	}
	ret = ubctl_ummu_copy_data(ucdev, query_cmd_param, vaddr, map_length);
	iounmap(vaddr);

	return ret;
}

static int ubctl_ummu_proc_sync_data(struct resource *res,
				     struct ubctl_query_cmd_param *query_cmd_param,
				     struct fwctl_pkt_in_ummuid_value *ummu_data,
				     bool is_query)
{
	u32 *out_data = query_cmd_param->out->data;
	u32 map_length = sizeof(u32);
	void __iomem *vaddr;

	if (sizeof(u32) > query_cmd_param->out_len)
		return -EINVAL;

	vaddr = ioremap(res->start + UBCTL_UMMU_SYNC_TIMEOUT_OPEN, map_length);
	if (!vaddr)
		return -ENOMEM;

	if (is_query) {
		*out_data = readl(vaddr);
	} else {
		if (!capable(CAP_SYS_ADMIN)) {
			query_cmd_param->out->retval = -EACCES;
			iounmap(vaddr);
			return -EACCES;
		}
		*out_data = ummu_data->value;
		writel(*out_data, vaddr);
	}

	query_cmd_param->out->data_size = sizeof(u32);
	iounmap(vaddr);

	return 0;
}

int ubctl_ummu_process_data(struct ubctl_dev *ucdev,
			    struct ubctl_query_cmd_param *query_cmd_param,
			    struct ubctl_func_dispatch *query_func)
{
#define UMMU_NAME_STR "ummu."

	struct fwctl_pkt_in_ummuid_value *ummu_data;
	struct resource *root = &iomem_resource;
	struct resource *res;

	if (!ucdev || !query_cmd_param || !query_func)
		return -EINVAL;

	if (!query_cmd_param->in || !query_cmd_param->out) {
		ubctl_err(ucdev, "invalid query_cmd_param internal pointers.\n");
		return -EINVAL;
	}

	g_ubctl_env_type = ubase_get_hw_ver(ucdev->adev);

	if (query_cmd_param->in->data_size != sizeof(*ummu_data)) {
		ubctl_err(ucdev, "ummuid value size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(*ummu_data));
		return -EINVAL;
	}

	ummu_data = (struct fwctl_pkt_in_ummuid_value *)(query_cmd_param->in->data);
	res = ubctl_find_and_sort_resources(ucdev, root, UMMU_NAME_STR,
					    ummu_data->ummu_id);
	if (!res)
		return -EINVAL;

	if (query_func->rpc_cmd == UTOOL_CMD_QUERY_UMMU_ALL)
		return ubctl_ummu_proc_all_data(ucdev, res, query_cmd_param);
	if (query_func->rpc_cmd == UTOOL_CMD_QUERY_UMMU_SYNC)
		return ubctl_ummu_proc_sync_data(res, query_cmd_param, ummu_data, true);
	if (query_func->rpc_cmd == UTOOL_CMD_CONFIG_UMMU_SYNC)
		return ubctl_ummu_proc_sync_data(res, query_cmd_param, ummu_data, false);

	return -EINVAL;
}
