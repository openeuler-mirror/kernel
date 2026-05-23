/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_vram_common.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Header File, hinic5_vram common
 */
#ifndef HINIC5_VRAM_COMMON_H
#define HINIC5_VRAM_COMMON_H

#if !defined(__UEFI__) && !defined(__WIN__)
#include <linux/notifier.h>
#include <linux/numa.h>
#endif

#define HINIC5_VRAM_BLOCK_SIZE_2M		0x200000UL
#define KEXEC_SIGN			"hinic-in-kexec"
// now hinic5_vram_name max len is 14, when add other hinic5_vram, attention this value
#define HINIC5_VRAM_NAME_SIZE			15
#define HINIC5_VRAM_NAME_MAX_LEN		16

#define HINIC5_VRAM_HINIC5_CQM_GLB_FUNC_BASE		"F"
#define HINIC5_VRAM_HINIC5_CQM_FAKE_MEM_BASE		"FK"
#define HINIC5_VRAM_HINIC5_CQM_CLA_BASE		"C"
#define HINIC5_VRAM_HINIC5_CQM_CLA_TYPE_BASE		"T"
#define HINIC5_VRAM_HINIC5_CQM_CLA_SMF_BASE		"M"
#define HINIC5_VRAM_HINIC5_CQM_CLA_COORD_X		"X"
#define HINIC5_VRAM_HINIC5_CQM_CLA_COORD_Y		"Y"
#define HINIC5_VRAM_HINIC5_CQM_CLA_COORD_Z		"Z"
#define HINIC5_VRAM_HINIC5_CQM_BITMAP_BASE		"B"

#define HINIC5_VRAM_NIC_DCB			"DCB"
#define HINIC5_VRAM_NIC_MHOST_MGMT             "MHOST_MGMT"
#define HINIC5_VRAM_NIC_HINIC5_VRAM			"NIC_HINIC5_VRAM"
#define HINIC5_VRAM_NIC_FUNC_BASE		"NIC_F"

#define HINIC5_VRAM_NIC_MQM                    "NM"

#define HINIC5_VRAM_VBS_IOCB		    "IOCB"
#define HINIC5_VRAM_VBS_RXQS_CQE		"RCQE"
#define HINIC5_VRAM_VBS_NAME_BASE      "VBS_"
#define HINIC5_VRAM_VBS_VOLQ_MTT		"VOLQMTT"
#define HINIC5_VRAM_VBS_VOLQ_MTT_PAGE		"MTT_PAGE"

#define HINIC5_VRAM_OVS_PORT_CONF              "OVS_PORT_CONF"
#define HINIC5_VRAM_OVS_DFX_MGR                "OVS_DFX_MGR"

#define HINIC5_VRAM_VROCE_ENTRY_POOL		"VROCE_ENTRY"
#define HINIC5_VRAM_VROCE_GROUP_POOL		"VROCE_GROUP"
#define HINIC5_VRAM_VROCE_UUID			"VROCE_UUID"
#define HINIC5_VRAM_VROCE_VID			"VROCE_VID"
#define HINIC5_VRAM_VROCE_BASE			"VROCE_BASE"
#define HINIC5_VRAM_VROCE_DSCP			"VROCE_DSCP"
#define HINIC5_VRAM_VROCE_QOS			"VROCE_QOS"
#define HINIC5_VRAM_VROCE_DEV			"VROCE_DEV"
#define HINIC5_VRAM_VROCE_RGROUP_HT_CNT	"RGROUP_CNT"
#define HINIC5_VRAM_VROCE_RACL_HT_CNT		"RACL_CNT"
#define HINIC5_VRAM_VROCE_MQM_ENQC			"VROCE_MQM_ENQC"

#define HINIC5_VRAM_DTOE_NUMA_MEM              "DTOE_NUMA"
#define HINIC5_VRAM_DTOE_CARD_MEM              "DTOE_CARD"
#define HINIC5_VRAM_DTOE_CONN_MEM              "DTOE_CONN"
#define HINIC5_VRAM_DTOE_SUB_LEN               10

#define HINIC5_VRAM_VROCE_MIG_ENTRY_POOL	"VROCE_MIG_ENTRY"
#define HINIC5_VRAM_VROCE_MIG_ENTRY_HT_CNT	"MIG_ENTRY_CNT"

#define MPU_OS_HOTREPLACE_FLAG          0x1

#define USE_HINIC5_VRAM    1
#define NO_USE_HINIC5_VRAM 0

#define OS_HOT_REPLACE_DOING 1
#define OS_HOT_REPLACE_DONE  0

#define HINIC5_VRAM_NUMA_NODE_NUM      2

/* Allocate from the CPU where runtime is located */
#define HINIC5_VRAM_AFFINITY_NUMA      0xfe

/* No NUMA specified, allocate from free NUMA */
#define HINIC5_VRAM_NO_NUMA            0xff

enum KUP_HOOK_POINT {
	PRE_FREEZE,
	FREEZE_TO_KILL,
	PRE_UPDATE_KERNEL,
	FLUSH_DURING_KUP,
	POST_UPDATE_KERNEL,
	UNFREEZE_TO_RUN,
	POST_RUN,
	KUP_HOOK_MAX,
};

#if defined(__UEFI__) || defined(__WIN__) || defined(__VMWARE__)
#define hinic5_hinic5_vram_kalloc(name, size) 0
#define hinic5_vram_get_kexec_flag() 0
#define hinic5_hinic5_vram_get_gfp_hinic5_vram() 0
#else

typedef int (*register_nvwa_notifier_t)(int hook, struct notifier_block *nb);
typedef int (*unregister_nvwa_notifier_t)(int hook, struct notifier_block *nb);
typedef int (*register_euleros_reboot_notifier_t)(struct notifier_block *nb);
typedef int (*unregister_euleros_reboot_notifier_t)(struct notifier_block *nb);
typedef void __iomem *(*hinic5_vram_kalloc_t)(char *name, u64 size);
typedef void __iomem *(*vpmem_kalloc_node_t)(char *name, u64 size, u8 numa);
typedef void (*hinic5_vram_kfree_t)(void __iomem *vaddr, char *name, u64 size);
typedef gfp_t (*hinic5_vram_get_gfp_hinic5_vram_t)(void);

/**
 * @brief init hinic5_vram related symbols
 **/
void lookup_hinic5_vram_related_symbols(void);
/**
 * @brief register nvwa notifier
 * @param hook @ref enum KUP_HOOK_POINT
 * @param nb   pointer of notifier block
 * @return
 *  - Zero if successful. Non-zero otherwise.
 **/
int hi_register_nvwa_notifier(int hook, struct notifier_block *nb);
/**
 * @brief unregister nvwa notifier
 * @param hook @ref enum KUP_HOOK_POINT
 * @param nb   pointer of notifier block
 * @return
 *  - Zero if successful. Non-zero otherwise.
 **/
int hi_unregister_nvwa_notifier(int hook, struct notifier_block *nb);
/**
 * @brief register machine-shutdown notifier
 * @param nb pointer of notifier block
 * @return
 *  - Zero if successful. Non-zero otherwise.
 **/
int hi_register_euleros_reboot_notifier(struct notifier_block *nb);
/**
 * @brief unregister machine-shutdown notifier
 * @param nb pointer of notifier block
 * @return
 *  - Zero if successful. Non-zero otherwise.
 **/
int hi_unregister_euleros_reboot_notifier(struct notifier_block *nb);
/**
 * @brief alloc hinic5_vram memory
 * @param name name of hinic5_vram memory
 * @param size size of hinic5_vram memory
 **/
void __iomem *hinic5_hinic5_vram_kalloc(char *name, u64 size);
/**
 * @brief get gfp of hinic5_vram for dma
 * @return
 * - gfp_t from sdi_nanoos
 **/
gfp_t hinic5_hinic5_vram_get_gfp_hinic5_vram(void);
/**
 * @brief set kexec status
 * @param status 1 : doing kexec, 0 : done kexec
 * @return
 *  - Zero if successful. Non-zero otherwise.
 **/
int hinic5_set_kexec_status(int status);
/**
 * @brief get kexec status
 * @return
 * - Zero if successful. Non-zero otherwise.
 **/
int hinic5_get_kexec_status(void);
/**
 * @brief set use-hinic5_vram flag
 * @param flag: true : use hinic5_vram, false : don't use hinic5_vram
 **/
void set_use_hinic5_vram_flag(bool flag);
/**
 * @brief get kexec flag
 * @return
 * - 0: done kexec
 * - 1: doing kexec
 **/
int hinic5_vram_get_kexec_flag(void);

#endif

#endif /* HINIC5_VRAM_COMMON_H */