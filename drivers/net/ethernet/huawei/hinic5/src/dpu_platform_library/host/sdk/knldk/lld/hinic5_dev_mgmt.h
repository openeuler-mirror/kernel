/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_dev_mgmt.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_DEV_MGMT_H
#define HINIC5_DEV_MGMT_H
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/proc_fs.h>

#include "ossl_knl.h"
#include "hinic5_bus.h"
#include "hinic5_sriov.h"
#include "hinic5_chip_info.h"
#ifndef __WIN__
#include "hinic5_lld.h"
#endif

#define HINIC5_VF_PCI_CFG_REG_BAR	0
#define HINIC5_PF_PCI_CFG_REG_BAR	1

#define HINIC5_PCI_INTR_REG_BAR		2
#define HINIC5_PCI_MGMT_REG_BAR		3 /* Only PF have mgmt bar */
#define HINIC5_PCI_DB_BAR		4

#define PRINT_ULD_DETACH_TIMEOUT_INTERVAL	5000 /* 5 second */
#define PRINT_ULD_DETACH_TIMES 30
#define PRINT_ULD_DETACH_TIMES_INTERVAL 5
#define ULD_LOCK_MIN_USLEEP_TIME		900
#define ULD_LOCK_MAX_USLEEP_TIME		1000

#define HINIC5_UBUS_FERS2               2
#define HINIC5_UBUS_DB_BAR              1
#define HINIC5_UBUS_INTR_REG_BAR        0

/*
 * 1825 UBUS FERS2 resource space layout
------------------------------------------
 * CPI VF BAR0 (CFG)       8 KB
 * CPI PF BAR1 (CFG)       64 KB
 * CPI PF BAR3 (MGMT)      128 KB
 */

#define HINIC5_VF_UBUS_CFG_REG_OFFSET   0
#define HINIC5_VF_UBUS_CFG_REG_SIZE     0x2000 /* 8 KB */

#define HINIC5_PF_UBUS_CFG_REG_OFFSET   HINIC5_VF_UBUS_CFG_REG_SIZE
#define HINIC5_PF_UBUS_CFG_REG_SIZE     0x10000 /* 64 KB */

#define HINIC5_PF_UBUS_MGMT_REG_OFFSET  (HINIC5_PF_UBUS_CFG_REG_OFFSET + HINIC5_PF_UBUS_CFG_REG_SIZE)
#define HINIC5_PF_UBUS_MGMT_REG_SIZE    0x20000 /* 128 KB */

/*
 * 1872 UBUS FERS2 resource space layout
 * Ref Semiconductor/Hi1872 V100/Docs/KIA2/0.1.System/1.4.FS/
 * Programming User Guide/Hi1872 V100 UB initialization.docx

 * PF FERS2
------------------------------------------
 * UB vendor space for UBD2H       128 KB
 * UB vendor space for UBG         128 KB
 * UMMU non-secure                 32 KB
 * CPI PF BAR3 (MGMT)              96 KB
 * CPI PF BAR1 (CFG)               128 KB

 * VF FERS2
------------------------------------------
 * UB vendor space for UBD2H       128 KB
 * UB vendor space for UBG         128 KB
 * CPI VF BAR01 (CFG)              256 KB
 */

#define HINIC5_HTN_VF_UBUS_CFG_REG_OFFSET       0x40000 /* 256 KB */
#define HINIC5_HTN_VF_UBUS_CFG_REG_SIZE         0x40000 /* 256 KB */

#define HINIC5_HTN_PF_UBUS_CFG_REG_OFFSET       0x60000 /* 384 KB */
#define HINIC5_HTN_PF_UBUS_CFG_REG_SIZE         0x20000 /* 128 KB */

#define HINIC5_HTN_PF_UBUS_MGMT_REG_OFFSET      0x48000 /* 288 KB */
#define HINIC5_HTN_PF_UBUS_MGMT_REG_SIZE        0x18000 /* 96 KB */

/* Default ubus dma bit mask */
#define HINIC5_UBUS_DMA_BIT_MASK_DEFAULT 48

/* ubus dma bit mask control range */
#define HINIC5_UBUS_DMA_BIT_MASK_MAX 64
#define HINIC5_UBUS_DMA_BIT_MASK_MIN 32

enum {
	HINIC5_NOT_PROBE = 1,
	HINIC5_PROBE_START = 2,
	HINIC5_PROBE_OK = 3,
	HINIC5_IN_REMOVE = 4,
};

#define HINIC5_VPMD_PROC_NAME_LEN 32
/* Structure for device private data */
struct hinic5_adev {
	struct hinic5_lld_dev lld_dev;
	struct device *dev;
	void *hwdev;
	void *bus_dev; /* pdev in pcie scenario, ub dev in ubus scenario */
	struct card_node *chip_node;
	/* Record the service object address,
	 * such as hinic5_dev, toe_dev, fc_dev
	 */
	void *uld_dev[SERVICE_T_MAX];
	/* Record the service object name */
	char uld_dev_name[SERVICE_T_MAX][IFNAMSIZ];
	/* It is a global variable for driver to manage
	 * all function device linked list
	 */
	struct list_head node;

	bool disable_vf_load;
	bool disable_srv_load[SERVICE_T_MAX];

	void __iomem *cfg_reg_base;
	void __iomem *intr_reg_base;
	void __iomem *mgmt_reg_base;
	void __iomem *fers2_reg_base;
	u64 db_dwqe_len;
	u64 db_base_phy;
	u64 cfg_base_phy;
	u64 cfg_base_len;
	u64 mgmt_base_phy; /* PF only */
	u64 mgmt_base_len;

	/* Used for tool adaptation, temporarily storing fers2 address and size manually in driver,
	 * to be removed after tool adaptation
	 */
	u64 fers2_base_phy;
	u64 fers2_total_len;
	void __iomem *db_base;

	/* lock for attach/detach uld */
	struct mutex adev_mutex;
	int lld_state;
	u32 rsvd1;

	struct hinic5_sriov_info sriov_info;

	/* setted when uld driver processing event */
	ulong state;
	struct pci_device_id id;

	atomic_t ref_cnt;

	atomic_t uld_ref_cnt[SERVICE_T_MAX];
	ulong uld_state;
	spinlock_t uld_lock; /* Spinlock to protect ULD (Upper Layer Driver) operations */

	u16 probe_fault_level;
	u16	rsvd2;

#ifdef __VMWARE__
	#include "vm_pci.h"
#endif
	struct hinic5_bus_ops *bus_ops;
	struct hinic5_device_info info;

	char vpmd_proc_name[HINIC5_VPMD_PROC_NAME_LEN];
	struct proc_dir_entry *vpmd_proc;
};

struct hinic_chip_info {
	u8 chip_id;   /* chip ID within card */
	u8 card_type; /* hinic_multi_chip_card_type */
	u8 rsvd[10];  /* reserved 10 bytes */
};

#define to_hinic5_adev(n) container_of(n, struct hinic5_adev, lld_dev)

struct list_head *get_hinic5_chip_list(void);

int hinic5_alloc_chip_node(struct hinic5_adev *adev);

void hinic5_free_chip_node(struct hinic5_adev *adev);

void hinic5_lld_lock_chip_node(void);

void hinic5_lld_unlock_chip_node(void);

void hinic5_lld_lock_init(void);

void hinic5_lld_dev_cnt_init(struct hinic5_adev *adev);
void hinic5_wait_lld_dev_unused(struct hinic5_adev *adev);

struct card_node *hinic5_get_chip_node_by_lld(struct hinic5_lld_dev *lld_dev);

struct hinic5_lld_dev *hinic5_get_lld_dev_by_func_id(const char *chip_name, u32 func_id);

#endif
