/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU Configuration table header file
 */

#ifndef __UMMU_CFG_TABLE_H__
#define __UMMU_CFG_TABLE_H__

#include <linux/types.h>
#include <linux/kref.h>
#include "ummu.h"

/* TECT's max space size: 6(4K)/8(16K)/10(64K) */
#define TECT_SPLIT 8
#define TECT_L1_ENTRY_BYTES 8
#define TECT_L1_ENTRY_DWORDS 1
#define TECTD_V (1UL << 0)
#define TECT_L1_DESC_L2TECTE_NUM GENMASK_ULL(4, 1)
#define TECT_L1_DESC_L2PTR_MASK GENMASK_ULL(51, 6)

/* TECT Entry info */
#define TECT_ENTRY_SIZE_BYTES 64
#define TECT_ENTRY_SIZE_DWORDS 8

#define TECT_ENT0_V (1UL << 0)
#define TECT_ENT0_ST_MODE GENMASK(3, 1)
#define TECT_ENT0_ST_MODE_ABORT 0
#define TECT_ENT0_ST_MODE_BYPASS 4
#define TECT_ENT0_ST_MODE_S1 5
#define TECT_ENT0_ST_MODE_S2 6
#define TECT_ENT0_ST_MODE_NESTED 7
#define TECT_ENT0_MEM_ATTR GENMASK(7, 4)
#define TECT_ENT0_MEM_ATTR_SEL (1UL << 8)
#define TECT_ENT0_ALLOC_SEL GENMASK(12, 9)
#define TECT_ENT0_SECURE_SEL GENMASK(14, 13)
#define TECT_ENT0_PRIV_SEL GENMASK(16, 15)
#define TECT_ENT0_PRIV_SEL_USER_PRIV 0
#define TECT_ENT0_PRIV_SEL_UNPRIV 2
#define TECT_ENT0_PRIV_SEL_PRIV 3
#define TECT_ENT0_INST_SEL GENMASK(18, 17)
#define TECT_ENT0_MAPT_EN (1UL << 19)
#define TECT_ENT0_EM_EN (1UL << 20)
#define TECT_ENT0_TCRC_SEL GENMASK(22, 21)
#define TECT_ENT0_TCR_NSEL1 0UL
#define TECT_ENT0_TCR_EL2 2UL
#define TECT_ENT0_MSD_SEL GENMASK(24, 23)
#define TECT_ENT0_MSD_SEL_INCOMING 1UL
#define TECT_ENT0_DR_EN (1UL << 25)
#define TECT_ENT0_DCP_EN (1UL << 26)
#define TECT_ENT0_COUNT_HINT GENMASK(30, 27)
#define TECT_ENT0_S2_VMID GENMASK_ULL(47, 32)

#define TECTE_0_NESTED_CONFIG_MASK \
	cpu_to_le64(TECT_ENT0_V | TECT_ENT0_ST_MODE)

#define TECT_ENT1_TCT_MAX_NUM GENMASK(4, 0)
#define TECT_ENT1_TCT_PTR GENMASK_ULL(51, 6)
#define TECT_ENT1_TCT_FMT GENMASK_ULL(53, 52)
#define TECT_ENT1_DTB_TERMINATE 0x0
#define TECT_ENT1_DTB_BYPASS 0x1
#define TECT_ENT1_DTB_TID0 0x2
#define TECT_ENT1_TCT_STALL_DISABLE (1ULL << 56)
#define TECT_ENT1_TCT_MTM_EN (1ULL << 57)
#define TECT_ENT1_TCT_PTR_MD0 GENMASK_ULL(59, 58)
#define TECT_ENT1_TCT_PTR_MD1 GENMASK_ULL(61, 60)
#define TECT_ENT1_TCT_PTR_MSD GENMASK_ULL(63, 62)
#define TECT_ENT1_MD_CACHE_NC 0UL
#define TECT_ENT1_MD_CACHE_WBRA 1UL
#define TECT_ENT1_MD_CACHE_WT 2UL
#define TECT_ENT1_MD_CACHE_WB 3UL

#define TECTE_1_NESTED_CONFIG_MASK \
	cpu_to_le64(TECT_ENT1_TCT_MAX_NUM | TECT_ENT1_TCT_PTR | \
		    TECT_ENT1_TCT_FMT | TECT_ENT1_TCT_STALL_DISABLE | \
		    TECT_ENT1_TCT_PTR_MD0 | TECT_ENT1_TCT_PTR_MD1 | \
		    TECT_ENT1_TCT_PTR_MSD)

#define TECT_ENT2_NS_S2_TSZ GENMASK(5, 0)
#define TECT_ENT2_NS_S2_SL GENMASK(7, 6)
#define TECT_ENT2_NS_S2_TG GENMASK(9, 8)
#define TECT_ENT2_NS_S2_W (1UL << 10)
#define TECT_ENT2_NS_S2_A (1UL << 11)
#define TECT_ENT2_S2_PAS GENMASK(14, 12)
#define TECT_ENT2_S2_ENDI (1UL << 15)
#define TECT_ENT2_S2_HDF (1UL << 16)
#define TECT_ENT2_S2_HAF (1UL << 17)
#define TECT_ENT2_S2_AFFD (1UL << 18)
#define TECT_ENT2_S2_FBS (1UL << 19)
#define TECT_ENT2_S2_FBR (1UL << 20)
#define TECT_ENT2_S2_MD0 GENMASK(22, 21)
#define TECT_ENT2_S2_MD1 GENMASK(24, 23)
#define TECT_ENT2_S2_MSD GENMASK(26, 25)
#define TECT_ENT2_NS_VTCR GENMASK(26, 0)
#define TECT_ENT2_S2_PTW (1UL << 27)
#define TECT_ENT2_S2_FWB (1UL << 28)
#define TECT_ENT2_S2_AA64 (1UL << 29)
#define TECT_ENT2_S2_HWU59 (1ULL << 60)
#define TECT_ENT2_S2_HWU60 (1ULL << 61)
#define TECT_ENT2_S2_HWU61 (1ULL << 62)
#define TECT_ENT2_S2_HWU62 (1ULL << 63)

#define TECT_ENT3_S2_TTBR GENMASK_ULL(51, 4)

#define TECT_ENT5_MTMC_PTR GENMASK_ULL(51, 12)

#define TECT_ENT6_MTM_ID GENMASK(15, 0)
#define TECT_ENT6_MTM_GP GENMASK(23, 16)
#define TECT_ENT6_MTM_NS (1UL << 24)

struct ummu_tecte_data {
	__le64 data[TECT_ENTRY_SIZE_DWORDS];
};

/* target context table */
#define TCT_L1_ENTRY_SIZE_BYTES 8
#define TCT_L1_ENTRY_SIZE_DWORDS 1
#define TCT_L1_ENTRY_V (1UL << 0)
#define TCT_L1_ADDR_MASK GENMASK_ULL(51, 12)

#define TCT_ENTRY_SIZE_BYTES 64
#define TCT_ENTRY_SIZE_DWORDS 8
#define TCT_FMT_LINEAR 0
#define TCT_FMT_LVL2_4K 1
#define TCT_FMT_LVL2_64K 2
#define TCT_SPLIT_4K 6
/*
 * Linear: when less than 1024 tids are supported
 * 2lvl: at most 1024 L1 entries,
 *       1024 lazy entries per table.
 */
#define TCT_SPLIT_64K 10
#define TCT_L2_ENTRIES (1UL << TCT_SPLIT_64K)

/*
 * When only supports linear target context tables, pick a
 * reasonable size limit (64kB).
 */
#define TCT_LINEAR_ENTS_MAX ilog2(SZ_64K / TCT_ENTRY_SIZE_BYTES)

#define TCT_ENT0_V (1UL << 0)
#define TCT_ENT0_AA64 (1UL << 1)
#define TCT_ENT0_ENDI (1UL << 2)
#define TCT_ENT0_GPAS GENMASK(5, 3)
#define TCT_ENT0_WXN (1UL << 6)
#define TCT_ENT0_UWXN (1UL << 7)
#define TCT_ENT0_PAN (1UL << 8)
#define TCT_ENT0_AFFD (1UL << 9)
#define TCT_ENT0_HDF (1UL << 10)
#define TCT_ENT0_HAF (1UL << 11)
#define TCT_ENT0_FBS (1UL << 12)
#define TCT_ENT0_FBR (1UL << 13)
#define TCT_ENT0_FBA (1UL << 14)
#define TCT_ENT0_ASH (1UL << 15)
/* 0:entry mode; 1:table mode */
#define TCT_ENT0_MAPT_MOD (1UL << 16)
#define TCT_ENT0_RTES GENMASK(18, 17)
#define RTE_GRANULE_4K 1
#define RTE_GRANULE_2M 2
#define TCT_ENT0_MAPT_EN (1UL << 19)
#define TCT_ENT0_MAC_EN (1UL << 20)
#define TCT_ENT0_EBIT_EN (1UL << 21)
#define TCT_ENT0_MATT_BYPASS (1UL << 22)
#define TCT_ENT0_ASID GENMASK_ULL(47, 32)

#define TCT_ENT1_SZ GENMASK(5, 0)
#define TCT_ENT1_TGS GENMASK(7, 6)
#define TCT_TCR_TGS_4K 0
#define TCT_TCR_TGS_64K 1
#define TCT_TCR_TGS_16K 2
#define TCT_ENT1_TTWD (1UL << 8)
#define TCT_ENT1_MD0 GENMASK(10, 9)
#define TCT_ENT1_MD1 GENMASK(12, 11)
#define TCT_TCR_RGN_NC 0
#define TCT_TCR_RGN_WBWA 1
#define TCT_TCR_RGN_WT 2
#define TCT_TCR_RGN_WB 3

#define TCT_ENT1_MSD GENMASK(14, 13)
#define TCT_MSD_NS 0
#define TCT_MSD_OS 2
#define TCT_MSD_IS 3

#define TCT_ENT1_MTM_ID GENMASK_ULL(47, 32)
#define TCT_ENT1_MTM_GP GENMASK_ULL(55, 48)

#define TCT_ENT2_HWU59 (1UL << 0)
#define TCT_ENT2_HWU60 (1UL << 1)
#define TCT_ENT2_HWU61 (1UL << 2)
#define TCT_ENT2_HWU62 (1UL << 3)
#define TCT_ENT2_TTBA GENMASK_ULL(51, 4)
#define TCT_ENT2_NS (1ULL << 61)
#define TCT_ENT2_HAD (1ULL << 62)
#define TCT_ENT2_UPRID (1ULL << 63)

#define TCT_ENT3_MAPT_BBA_MA GENMASK(1, 0)
#define TCT_ENT3_MAPT_BBA_SH GENMASK(3, 2)
#define TCT_ENT3_MAPT_BBA GENMASK_ULL(47, 5)
#define TCT_ENT3_MAPT_BBA_SZ GENMASK_ULL(63, 60)

#define TCT_ENT4_MAPT_BTA_MA GENMASK(1, 0)
#define TCT_ENT4_MAPT_BTA_SH GENMASK(3, 2)
#define TCT_ENT4_MAPT_BTA GENMASK_ULL(47, 5)
#define TCT_ENT4_MAPT_BTA_SZ GENMASK_ULL(62, 60)

/* USER LOGIC DEFINE */
#define UMMU_KV_TABLE_BASE_OFFSET 0x3800
#define KV_TABLE_RA (1ULL << 63)
#define KV_TABLE_BASE_ADDR_MASK GENMASK_ULL(51, 5)

#define UMMU_KV_TABLE_BASE_CFG_OFFSET 0x3808
#define KV_TABLE_DEPTH_MASK GENMASK(31, 16)
#define KV_TABLE_DEPTH 0x100
#define KV_TABLE_BANK_NUM_MASK GENMASK(15, 8)
#define KV_TABLE_BANK_NUM 8
#define KV_TABLE_SH GENMASK(5, 4)
#define KV_TABLE_ATTR GENMASK(3, 0)

#define UMMU_KV_TABLE_HASH_CFG0_OFFSET 0x380C
#define KV_TABLE_HASH_WIDTH_MASK GENMASK(7, 4)
#define KV_TABLE_HASH_WIDTH_4BIT 0
#define KV_TABLE_HASH_WIDTH_8BIT 1
#define KV_TABLE_HASH_WIDTH_16BIT 2
#define KV_TABLE_HASH_SEL_MASK GENMASK(3, 0)
#define KV_TABLE_HASH_XOR 0
#define KV_TABLE_HASH_CRC32 1
#define KV_TABLE_XOR_HALF_BYTE_BIT 4
#define KV_TABLE_XOR_BYTE_TO_SHORT 2

#define UMMU_KV_TABLE_HASH_CFG1_OFFSET 0x3810
#define CRC32_INIT_VALUE 0xFFFFFFFF
#define CRC32_POLY_VALUE 0x4C11DB7
#define CRC32_CALC_LENGTH 8
#define CRC32_CALC_OFFSET 24
#define CRC32_CALC_MASK 0x80000000

#define UMMU_CAM_TABLE_BASE_OFFSET 0x3820
#define CAM_TABLE_RA (1ULL << 63)
#define CAM_TABLE_BASE_ADDR_MASK GENMASK_ULL(51, 5)

#define UMMU_CAM_TABLE_BASE_CFG_OFFSET 0x3828
#define CAM_TABLE_DEPTH_MASK GENMASK(31, 16)
#define CAM_TABLE_DEPTH 0x100
#define CAM_TABLE_SH GENMASK(5, 4)
#define CAM_TABLE_ATTR GENMASK(3, 0)

#define HASH_ENTRY_SIZE_BYTES 32
#define HASH_ENTRY_V (1UL << 0)

/* target OS config table */
struct ummu_tect_l1_desc {
	u32		l2_tecte_num;
	__le64		*l2ptr;
	phys_addr_t	l2ptr_pa;
};

struct ummu_tect_cfg {
	__le64				*tbl_vaddr;
	phys_addr_t			phys;
	size_t				tbl_size;
	unsigned int			num_ents;
	struct ummu_tect_l1_desc	*l1_tect_desc;
	u8				tect_fmt;
	u64				tect_reg_addr;
	u32				tect_reg_cfg;

	struct kref			ref;
};

const struct ummu_capability *ummu_get_cap(void);
int ummu_check_cap(struct ummu_device *ummu);
int ummu_prepare_tect_tct(struct ummu_device *ummu);
void ummu_device_set_tect(struct ummu_device *ummu);
int ummu_device_init_hash_table(struct ummu_device *ummu);
void ummu_device_config_hash_table(struct ummu_device *ummu);
void ummu_put_tct_table(struct ummu_tct_desc_cfg *cfg);
void ummu_put_tect_table(struct ummu_tect_cfg *tect);
int ummu_init_global_meta(void);
void ummu_free_global_meta(void);
int ummu_write_tct_desc(struct ummu_device *ummu, struct ummu_domain_cfgs *cfgs,
			bool is_clear);
void ummu_device_write_tecte(struct ummu_device *ummu, u32 deid,
			     struct ummu_tecte_data *src);
int ummu_get_tecte_tag_by_eid(eid_t eid, u32 *tecte_tag);
int ummu_add_eid(struct ummu_core_device *core_dev, guid_t *guid, eid_t eid, enum eid_type type);
void ummu_del_eid(struct ummu_core_device *core_dev, guid_t *guid, eid_t eid, enum eid_type type);
char *ummu_get_eid_list(void);
bool dev_work_on_local(struct ummu_master *master);
void ummu_build_s2_domain_tecte(struct ummu_domain *u_domain,
				struct ummu_tecte_data *target);
int ummu_set_domain_cfgs_tag(struct ummu_domain_cfgs *cfgs,
			     struct ummu_master *master);
__le64 *ummu_get_tecte_ptr(struct ummu_device *ummu, u32 tect_tag);
__le64 *ummu_get_tcte_ptr(struct ummu_tct_desc_cfg *tct_cfg, u32 tid);

#endif /* __UMMU_CFG_TABLE_H__ */
