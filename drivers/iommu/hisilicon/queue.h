/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: mcmdq/evtq/permq header file
 */

#ifndef __UMMU_QUEUE_H__
#define __UMMU_QUEUE_H__

#include "ummu.h"

#define Q_IDX(llq, p) ((p) & ((1 << (llq)->log2size) - 1))
#define Q_WRP(llq, p) ((p) & (1 << (llq)->log2size))
#define Q_OVERFLOW_FLAG (1UL << 31)
#define Q_OVF(p) ((p)&Q_OVERFLOW_FLAG)
#define Q_ENT(q, p) ((q)->base + Q_IDX(&((q)->llq), p) * (q)->ent_dwords)

/*
 * Ensure DMA allocations are naturally aligned
 * Hardware requirements base address by address length align
 */
#if IS_ENABLED(CONFIG_CMA_ALIGNMENT)
#define Q_MAX_SZ_SHIFT (PAGE_SHIFT + CONFIG_CMA_ALIGNMENT)
#else
#define Q_MAX_SZ_SHIFT (PAGE_SHIFT + MAX_ORDER)
#endif

#define Q_BASE_RWA (1ULL << 63)
#define Q_BASE_ADDR_MASK GENMASK_ULL(51, 5)
#define Q_BASE_LOG2SIZE GENMASK(4, 0)

/* multiple command queue */
#define MCMDQ_ENT_SZ_SHIFT 5
#define MCMDQ_ENT_DWORDS ((1UL << MCMDQ_ENT_SZ_SHIFT) / sizeof(u64))
#define MCMDQ_ENT_SIZE 16
#define MCMDQ_MAX_SZ_SHIFT 8

#define UMMU_MCMDQ_OFFSET 0x100
#define MCMDQ_PROD_OFFSET 0x8
#define MCMDQ_CONS_OFFSET 0xC
#define MCMDQ_CONS_ERR (1UL << 23)
#define MCMDQ_PROD_ERRACK (1UL << 23)
#define MCMDQ_PROD_EN (1UL << 31)
#define MCMDQ_EN_RESP (1UL << 31)

#define MCMDQ_CONS_ERR_REASON GENMASK(26, 24)
#define MCMDQ_CERROR_NONE_IDX 0
#define MCMDQ_CERROR_ILL_IDX 1
#define MCMDQ_CERROR_ABT_IDX 2

#define MCMDQ_PROD_OWNED_FLAG Q_OVERFLOW_FLAG

#define MCMDQ_BATCH_ENTRIES 32
#define CMD_0_OP GENMASK_ULL(7, 0)
#define CMD_0_SSV (1UL << 11)

#define CMD_SYNC_0_CM GENMASK_ULL(13, 12)
#define CMD_SYNC_0_CM_NONE 0
#define CMD_SYNC_0_CM_IRQ 1
#define CMD_SYNC_0_CM_SEV 2
#define CMD_SYNC_0_MSISH GENMASK_ULL(15, 14)
#define CMD_SYNC_0_MSIATTR GENMASK_ULL(19, 16)
#define CMD_SYNC_0_MSIDATA GENMASK_ULL(63, 32)
#define CMD_SYNC_1_MSIADDR GENMASK_ULL(51, 2)

#define CMD_STALL_0_DSEC (1UL << 10)
#define CMD_STALL_0_RETRY (1UL << 12)
#define CMD_STALL_0_ABORT (1UL << 13)
#define CMD_STALL_1_TAG GENMASK_ULL(15, 0)
#define CMD_STALL_2_TECT_TAG GENMASK_ULL(15, 0)

#define CMD_PREFET_0_TKV (1UL << 11)
#define CMD_PREFET_0_TID GENMASK_ULL(31, 12)
#define CMD_PREFET_0_SIZE GENMASK_ULL(56, 52)
#define CMD_PREFET_0_STRIDE GENMASK_ULL(61, 57)
#define CMD_PREFET_1_ADDR_MASK GENMASK_ULL(63, 12)
#define CMD_PREFET_2_TECTE_TAG GENMASK_ULL(15, 0)
#define CMD_PREFET_2_DEID_0 GENMASK_ULL(31, 0)
#define CMD_PREFET_2_DEID_1 GENMASK_ULL(63, 32)
#define CMD_PREFET_3_DEID_0 GENMASK_ULL(31, 0)
#define CMD_PREFET_3_DEID_1 GENMASK_ULL(63, 32)

#define CMD_CFGI_0_LEAF (1UL << 8)
#define CMD_CFGI_0_TID GENMASK_ULL(31, 12)
#define CMD_CFGI_0_VMID GENMASK_ULL(47, 32)
#define CMD_CFGI_0_RANGE GENMASK_ULL(56, 52)
#define CMD_CFGI_2_TECTE_TAG GENMASK_ULL(15, 0)
#define CMD_CFGI_2_DEID_0 GENMASK_ULL(31, 0)
#define CMD_CFGI_2_DEID_1 GENMASK_ULL(63, 32)
#define CMD_CFGI_3_DEID_0 GENMASK_ULL(31, 0)
#define CMD_CFGI_3_DEID_1 GENMASK_ULL(63, 32)

#define CMD_TLBI_0_LEAF (1UL << 8)
#define CMD_TLBI_0_ASID GENMASK_ULL(27, 12)
#define CMD_TLBI_0_TOKEN_ID GENMASK_ULL(31, 12)
#define CMD_TLBI_0_VMID GENMASK_ULL(47, 32)
#define CMD_TLBI_0_NUM GENMASK_ULL(56, 52)
#define CMD_TLBI_0_SCALE GENMASK_ULL(61, 57)
#define CMD_TLBI_0_TL GENMASK_ULL(63, 62)
#define CMD_TLBI_1_GS GENMASK_ULL(1, 0)
#define CMD_TLBI_1_VA_MASK GENMASK_ULL(63, 12)
#define CMD_TLBI_1_IPA_MASK GENMASK_ULL(51, 12)
#define CMD_TLBI_2_TECTE_TAG GENMASK_ULL(15, 0)
#define CMD_TLBI_RANGE_NUM_MAX 31

#define CMD_PLBI_0_TID GENMASK_ULL(31, 12)
#define CMD_PLBI_0_RANGE GENMASK_ULL(37, 32)
#define CMD_PLBI_1_ADDR_MASK GENMASK_ULL(63, 0)
#define CMD_PLBI_2_TECTE_TAG GENMASK_ULL(15, 0)
#define CMD_PLBI_1_NEXT_LEVEL_INDEX_MASK GENMASK_ULL(15, 0)
#define CMD_PLBI_1_NEXT_LEVEL_OFFSET_MASK GENMASK_ULL(61, 32)

#define CMD_CREATE_KVTBL0_EVT_EN BIT(8)
#define CMD_CREATE_KVTBL0_TAG_MASK GENMASK_ULL(31, 16)
#define CMD_CREATE_KVTBL0_KV_INDEX_MASK GENMASK_ULL(63, 32)
#define CMD_CREATE_KVTBL1_ADDR_MASK GENMASK_ULL(51, 6)
#define CMD_CREATE_KVTBL2_EID_LOW GENMASK_ULL(63, 0)
#define CMD_CREATE_KVTBL3_EID_HIGH GENMASK_ULL(63, 0)

#define CMD_DELETE_KVTBL0_EVT_EN BIT(8)
#define CMD_DELETE_KVTBL0_TAG_MASK GENMASK_ULL(31, 16)
#define CMD_DELETE_KVTBL0_KV_INDEX_MASK GENMASK_ULL(63, 32)
#define CMD_DELETE_KVTBL2_EID_LOW GENMASK_ULL(63, 0)
#define CMD_DELETE_KVTBL3_EID_HIGH GENMASK_ULL(63, 0)

#define CMD_NULL_OP_SUB_OP GENMASK(15, 8)
#define SUB_OP_CHECK_PA_CONTI_0_RESULT GENMASK(19, 16)
#define SUB_OP_CHECK_PA_CONTI_0_FLAG BIT(20)
#define SUB_OP_CHECK_PA_CONTI_0_SIZE GENMASK(29, 24)
#define SUB_OP_CHECK_PA_CONTI_0_ID GENMASK_ULL(40, 32)
#define SUB_OP_CHECK_PA_CONTI_1_ADDR GENMASK_ULL(63, 12)

/* event queue */
#define EVTQ_ENT_SZ_SHIFT 6
#define EVTQ_ENT_DWORDS (1UL << EVTQ_ENT_SZ_SHIFT >> 3)
#define EVTQ_MAX_SZ_SHIFT (Q_MAX_SZ_SHIFT - EVTQ_ENT_SZ_SHIFT)

#define UMMU_EVTQ_OFFSET 0x1100
#define UMMU_EVTQ_PROD_OFFSET 0x1108
#define UMMU_EVTQ_CONS_OFFSET 0x110C

#define EVTQ_ENT0_CODE GENMASK(7, 0)
#define EVTQ_ENT0_RNW (1U << 11)
#define EVTQ_ENT0_IND (1U << 12)
#define EVTQ_ENT0_PNU (1U << 13)
#define EVTQ_ENT0_CLS GENMASK(15, 14)
#define EVTQ_ENT0_NSIPA (1U << 16)
#define EVTQ_ENT0_S2 (1U << 17)
#define EVTQ_ENT0_STALL (1U << 18)
#define EVTQ_ENT0_TTRNW (1U << 19)
#define EVTQ_ENT0_TID GENMASK_ULL(51, 32)

#define EVTQ_ENT1_STAG GENMASK(15, 0)
#define EVTQ_ENT1_IMPL_DEF GENMASK(31, 16)
#define EVTQ_ENT1_REASON GENMASK_ULL(63, 32)

#define EVTQ_ENT2_IPA GENMASK_ULL(51, 12)
#define EVTQ_ENT3_IADDR GENMASK_ULL(63, 0)
#define EVTQ_ENT4_TECTE_TAG GENMASK(15, 0)
#define EVTQ_ENT4_EID_LOW GENMASK_ULL(63, 0)
#define EVTQ_ENT5_EID_HIGH GENMASK_ULL(63, 0)
#define EVTQ_ENT6_FTADDR GENMASK_ULL(51, 3)

struct ummu_mcmdq_batch {
	u64 cmds[MCMDQ_BATCH_ENTRIES * MCMDQ_ENT_DWORDS];
	int num;
};

struct ummu_mcmdq_ent {
	/* Common fields */
	u8 opcode;

	/* Command-specific fields */
	union {
#define CMD_SYNC 0x1
		struct {
			u64 msi_addr;
			bool support_sev;
		} sync;

#define CMD_STALL_RESUME 0x02
		struct {
			bool dsec;
			bool retry;
			bool abort;
			u16 tect_tag;
			u16 tag;
		} stall_resume;

#define CMD_STALL_TERM 0x03
		struct {
			u16 tect_tag;
		} stall_term;

#define CMD_PREFET_CFG 0x04
		struct {
			bool tkv;
			u32 tid;
			u32 deid_0;
			u32 deid_1;
			u32 deid_2;
			u32 deid_3;
		} prefet;

#define CMD_CFGI_TECT 0x08
#define CMD_CFGI_TECT_RANGE 0x09
#define CMD_CFGI_TCT 0x0A
#define CMD_CFGI_TCT_ALL 0x0B
		struct {
			bool leaf;
			u32 tid;
			u16 vmid;
			u8 range;
			u32 deid_0;
			u32 deid_1;
			u32 deid_2;
			u32 deid_3;
		} cfgi;

#define CMD_PLBI_OS_EID 0x14
#define CMD_PLBI_OS_EIDTID 0x15
#define CMD_PLBI_OS_VA 0x16
		struct {
			u32 tid;
			u16 tecte_tag;
			u8 range;
			u64 addr;
		} plbi;

#define CMD_TLBI_OS_ALL 0x10
#define CMD_TLBI_OS_TID 0x11
#define CMD_TLBI_OS_VA 0x12
#define CMD_TLBI_OS_VAA 0x13
#define CMD_TLBI_HYP_ALL 0x18
#define CMD_TLBI_HYP_TID 0x19
#define CMD_TLBI_HYP_VA 0x1A
#define CMD_TLBI_HYP_VAA 0x1B
#define CMD_TLBI_S1S2_VMALL 0x28
#define CMD_TLBI_S2_IPA 0x2A
#define CMD_TLBI_NS_OS_ALL 0x2C
#define CMD_TLBI_OS_ALL_U 0x90
#define CMD_TLBI_OS_ASID_U 0x91
#define CMD_TLBI_OS_VA_U 0x92
#define CMD_TLBI_OS_VAA_U 0x93
#define CMD_TLBI_HYP_ASID_U 0x99
#define CMD_TLBI_HYP_VA_U 0x9A
#define CMD_TLBI_S1S2_VMALL_U 0xA8
#define CMD_TLBI_S2_IPA_U 0xAA
		struct {
			bool leaf;
			u16 asid;
			u16 vmid;
			u32 tid;
			u16 tect_tag;
			u8 num;
			u8 scale;
			u8 tl;
			u8 gs;
			u64 addr;
		} tlbi;

#define CMD_RESUME 0x44
		struct {
			u32 deid;
			u16 stag;
			u8 resp;
		} resume;

#define CMD_CREATE_KVTBL 0x60
		struct {
			bool evt_en;
			u16 tecte_tag;
			u32 kv_index;
			u64 tect_base_addr;
			u64 eid_low;
			u64 eid_high;
		} create_kvtbl;

#define CMD_DELETE_KVTBL 0x61
		struct {
			bool evt_en;
			u16 tecte_tag;
			u32 kv_index;
			u64 eid_low;
			u64 eid_high;
		} delete_kvtbl;

#define CMD_NULL_OP 0x62
		struct {
			u8 sub_op;
			union {
#define SUB_CMD_NULL_CHECK_PA_CONTINUITY 0x1
				struct {
					u16 result;
					u16 flag;
					u32 size_order;
					u32 id;
					u64 addr;
				} check_pa_conti;
			};
		} null_op;
#define CMD_PLBI_OS_N 0x63
		struct {
			u32 tid;
			u16 tecte_tag;
			u32 next_lvl_idx;
			u32 next_lvl_offset;
		} plbi_free_bit;
	};
};

void ummu_queue_write(__le64 *dst, u64 *src, size_t n_dwords);
void ummu_queue_read(u64 *dst, __le64 *src, size_t n_dwords);
int ummu_queue_remove_raw(struct ummu_queue *q, u64 *ent);
int ummu_queue_sync_prod_in(struct ummu_queue *q);
bool ummu_queue_empty(struct ummu_ll_queue *q);
int ummu_write_evtq_regs(struct ummu_device *ummu);
int ummu_init_queues(struct ummu_device *ummu);
void ummu_device_free_mcmdq(struct ummu_device *ummu);
void ummu_device_free_evtq(struct ummu_device *ummu);
int ummu_device_mcmdq_init_cfg(struct ummu_device *ummu);
int ummu_mcmdq_issue_cmd(struct ummu_device *ummu, struct ummu_mcmdq_ent *ent);
int ummu_mcmdq_build_cmd(struct ummu_device *ummu, u64 *cmd,
			 struct ummu_mcmdq_ent *ent);
int ummu_mcmdq_issue_cmdlist(struct ummu_device *ummu, u64 *cmds,
			     int n, bool sync);
int ummu_mcmdq_issue_cmd_with_sync(struct ummu_device *ummu,
				   struct ummu_mcmdq_ent *ent);
void ummu_mcmdq_batch_add(struct ummu_device *ummu,
			  struct ummu_mcmdq_batch *cmds,
			  struct ummu_mcmdq_ent *cmd);
int ummu_mcmdq_batch_submit(struct ummu_device *ummu,
			    struct ummu_mcmdq_batch *cmds);
#endif /* __UMMU_QUEUE_H__ */
