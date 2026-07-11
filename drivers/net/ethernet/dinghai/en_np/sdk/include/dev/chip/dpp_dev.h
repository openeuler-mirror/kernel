/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_DEV_H_
#define _DPP_DEV_H_
#include <linux/pci.h>
#include "zxic_common.h"
#include "dpp_type_api.h"
#define DEV_HASH_FUNC_ID_NUM (4)

#define DPP_KEYSIG_DEBUG (1)
#define DPP_DEV_CHANNEL_MAX (2)
#define DPP_DEV_PPU_CLS_MAX (6)
#define DPP_DEV_PPU_INSTR_REG_NUM (3)

#define DPP_DEV_ME_MAX (8)
#define DPP_DEV_SDT_ID_MAX (256U)
#define DPP_DTB_QUEUE_MAX (128)

#define DPP_CHIP_DPP (0x279221)

#define X86_ADDR_2_ARRCH64(X86_ADDR) (((X86_ADDR & (~0xFFFF)) << 4) | (X86_ADDR & 0xFFFF))

#define DPP_PCIE_SLOT_MAX (64)
#define DPP_PCIE_CHANNEL_MAX (64)
#define DPP_PCIE_CHANNEL_ID(VPORT) (((((VPORT)&0x7000) >> 9) | (((VPORT)&0x0700) >> 8)) & 0x3F)

#define DEV_ID(DEV) (((struct dpp_dev_t *)(DEV))->device_id)
#define DEV_PCIE_SLOT(DEV) (((struct dpp_dev_t *)(DEV))->pcie_channel.slot)
#define DEV_PCIE_VPORT(DEV) (((struct dpp_dev_t *)(DEV))->pcie_channel.vport)
#define DEV_PCIE_DEV(DEV) (((struct dpp_dev_t *)(DEV))->pcie_channel.device)
#define DEV_PCIE_ADDR(DEV) (((struct dpp_dev_t *)(DEV))->pcie_channel.base_addr)
#define DEV_PCIE_OFFSET_ADDR(DEV) (((struct dpp_dev_t *)(DEV))->pcie_channel.offset_addr)
#define DEV_PCIE_ID(DEV) (((struct dpp_dev_t *)(DEV))->pcie_channel.pcie_id)
#define DEV_PCIE_LOCK(DEV) (((struct dpp_dev_t *)(DEV))->pcie_channel.device_lock)
#define DEV_PCIE_BAR_MSG_NUM(DEV) (((struct dpp_dev_t *)(DEV))->pcie_channel.bar_msg_num)

#define DEV_PCIE_MSG_OFFSET_ADDR (0x2000)
#define DEV_PCIE_MSG_ADDR(DEV) (DEV_PCIE_ADDR(DEV) + DEV_PCIE_MSG_OFFSET_ADDR)
#define DEV_PCIE_REG_ADDR(DEV) (DEV_PCIE_ADDR(DEV) + DEV_PCIE_OFFSET_ADDR(DEV) - SYS_NP_BASE_ADDR1)

struct dpp_pf_info_t {
	u16 slot;
	u16 vport;
};

struct dpp_pcie_channel_t {
	u16 is_used;
	u16 slot;
	u16 vport;
	u16 pcie_id;
	ZXIC_ADDR_T base_addr;
	ZXIC_ADDR_T offset_addr;
	struct pci_dev *device;
	struct zxic_mutex_t *device_lock;
	u32 bar_msg_num;
	u32 hash_index;
	u32 dev_status;
	u32 dump_dma_size;
	ZXIC_ADDR_T dump_dma_phy_addr;
	ZXIC_ADDR_T dump_dma_vir_addr;
};

struct dpp_dev_t {
	u32 device_id;
	struct dpp_pcie_channel_t pcie_channel;
};

typedef DPP_STATUS (*DPP_DEV_WRITE_FUNC)(struct dpp_dev_t *dev, u32 addr, u32 size, u32 *p_data);
typedef DPP_STATUS (*DPP_DEV_READ_FUNC)(struct dpp_dev_t *dev, u32 addr, u32 size, u32 *p_data);
typedef DPP_STATUS (*DPP_ACCESS_SWITCH_FUNC)(u32 dev_id, u32 access_type);

enum dpp_dev_access_type_e {
	DPP_DEV_ACCESS_TYPE_PCIE = 0,
	DPP_DEV_ACCESS_TYPE_RISCV = 1,
};

enum dpp_dev_type_e {
	DPP_DEV_TYPE_SIM = 0,
	DPP_DEV_TYPE_VCS = 1,
	DPP_DEV_TYPE_CHIP = 2,
	DPP_DEV_TYPE_FPGA = 3,
	DPP_DEV_TYPE_PCIE_ACC = 4,
	DPP_DEV_TYPE_INVALID,
};

enum dpp_chip_version_e {
	DPP_CHIP_VERSION_DPP = 0U, /**<  @brief DPP */
	DPP_CHIP_VERSION_DPP_P = 1U, /**<  @brief DPP+ */
	DPP_CHIP_VERSION_INVALID,
};

enum dpp_dev_mutex_type_e {
	DPP_DEV_MUTEX_T_REG = 0,
	DPP_DEV_MUTEX_T_OAM = 1,
	DPP_DEV_MUTEX_T_ETM = 2,
	DPP_DEV_MUTEX_T_DDR = 4,
	DPP_DEV_MUTEX_T_IND = 5,
	DPP_DEV_MUTEX_T_ETCAM = 6,
	DPP_DEV_MUTEX_T_MMU = 7,
	DPP_DEV_MUTEX_T_CAR0 = 8,
	DPP_DEV_MUTEX_T_ALG = 9,
	DPP_DEV_MUTEX_T_NPPU = 10,
	DPP_DEV_MUTEX_T_SMMU0 = 11,
	DPP_DEV_MUTEX_T_SMMU1 = 12,
	DPP_DEV_MUTEX_T_ETM_2ND = 13,
	DPP_DEV_MUTEX_T_LPM = 14,
	DPP_DEV_MUTEX_T_CRM_TEMP = 15,
	DPP_DEV_MUTEX_T_SIM = 16,
	DPP_DEV_MUTEX_T_DTB = 17,
	DPP_DEV_MUTEX_T_DTB_RB = 18,
	DPP_DEV_MUTEX_T_PKTRX_MF_GLB_CFG_0 = 19,
	DPP_DEV_MUTEX_T_PKTRX_MF_GLB_CFG_1 = 20,
	DPP_DEV_MUTEX_T_PKTRX_MF_GLB_CFG_2 = 21,
	DPP_DEV_MUTEX_T_PKTRX_MF_GLB_CFG_3 = 22,
	DPP_DEV_MUTEX_T_SELF_RECOVER = 23,
	DPP_DEV_MUTEX_T_MAX
};

enum module_init_e {
	MODULE_INIT_NPPU = 0,
	MODULE_INIT_PPU,
	MODULE_INIT_SE,
	MODULE_INIT_ETM,
	MODULE_INIT_DLB,
	MODULE_INIT_TRPG,
	MODULE_INIT_TSN,
	MODULE_INIT_MAX
};

struct dpp_dev_cfg_t {
	u32 device_id;
	enum dpp_dev_type_e dev_type;
	u32 chip_ver;
	u32 access_type;
	ZXIC_ADDR_T pcie_addr;
	ZXIC_ADDR_T riscv_addr;
	ZXIC_ADDR_T dma_vir_addr;
	ZXIC_ADDR_T dma_phy_addr;
	u32 init_flags[MODULE_INIT_MAX];
	DPP_DEV_WRITE_FUNC p_pcie_write_fun;
	DPP_DEV_READ_FUNC p_pcie_read_fun;
	DPP_DEV_WRITE_FUNC p_riscv_write_fun;
	DPP_DEV_READ_FUNC p_riscv_read_fun;
	struct zxic_mutex_t reg_opr_mutex;
	struct zxic_mutex_t oam_mutex;
	struct zxic_mutex_t etm_mutex;
	struct zxic_mutex_t ddr_mutex;
	struct zxic_mutex_t ind_mutex;
	struct zxic_mutex_t etcam_mutex;
	struct zxic_mutex_t car0_mutex;
	struct zxic_mutex_t alg_mutex;
	struct zxic_mutex_t nppu_mutex;
	struct zxic_mutex_t smmu0_mutex;
	struct zxic_mutex_t smmu1_mutex;
	struct zxic_mutex_t etm_2nd_mutex;
	struct zxic_mutex_t lpm_mutex;
	struct zxic_mutex_t crm_temp_mutex;
	struct zxic_mutex_t sim_mutex;
	struct zxic_mutex_t dtb_mutex;
	struct zxic_mutex_t pktrx_mf_glb_cfg_mutex_0;
	struct zxic_mutex_t pktrx_mf_glb_cfg_mutex_1;
	struct zxic_mutex_t pktrx_mf_glb_cfg_mutex_2;
	struct zxic_mutex_t pktrx_mf_glb_cfg_mutex_3;
	struct zxic_mutex_t self_recover_mutex;
	struct zxic_mutex_t hash_mutex[DPP_PCIE_SLOT_MAX][DEV_HASH_FUNC_ID_NUM];
	struct zxic_mutex_t dtb_rb_mutex[DPP_DTB_QUEUE_MAX];
	struct zxic_mutex_t dtb_queue_mutex[DPP_DTB_QUEUE_MAX];
	struct dpp_pcie_channel_t pcie_channel[DPP_PCIE_SLOT_MAX][DPP_PCIE_CHANNEL_MAX];
	void *p_std_nic_res[DPP_PCIE_SLOT_MAX];
	u32 bar_msg_num[DPP_PCIE_SLOT_MAX];
};

struct dpp_dev_mngr_t {
	u32 device_num;
	u32 is_init;
	struct dpp_dev_cfg_t *p_dev_array[DPP_DEV_CHANNEL_MAX];
};

DPP_STATUS dpp_dev_init(void);
DPP_STATUS dpp_dev_add(u32 dev_id, enum dpp_dev_type_e dev_type,
		       enum dpp_dev_access_type_e access_type, ZXIC_ADDR_T pcie_addr,
		       ZXIC_ADDR_T riscv_addr, ZXIC_ADDR_T dma_vir_addr, ZXIC_ADDR_T dma_phy_addr,
		       DPP_DEV_WRITE_FUNC p_pcie_write_fun, DPP_DEV_READ_FUNC p_pcie_read_fun,
		       DPP_DEV_WRITE_FUNC p_riscv_write_fun, DPP_DEV_READ_FUNC p_riscv_read_fun);
DPP_STATUS dpp_dev_del(u32 dev_id);
DPP_STATUS dpp_dev_get(struct dpp_pf_info_t *pf_info, struct dpp_dev_t *dev);
DPP_STATUS dpp_dev_pcie_channel_add(struct dpp_pf_info_t *pf_info, struct pci_dev *p_dev);
DPP_STATUS dpp_dev_pcie_channel_del(struct dpp_pf_info_t *pf_info);
void *dpp_dev_get_se_res_ptr(struct dpp_dev_t *dev);
void dpp_dev_set_se_res_ptr(struct dpp_dev_t *dev, void *se_ptr);
DPP_STATUS dpp_dev_opr_mutex_get(struct dpp_dev_t *dev, u32 type,
				 struct zxic_mutex_t **p_mutex_out);
DPP_STATUS dpp_dev_dtb_opr_mutex_get(struct dpp_dev_t *dev, u32 type, u32 index,
				     struct zxic_mutex_t **p_mutex_out);
DPP_STATUS dpp_dev_pcie_default_write(struct dpp_dev_t *dev, u32 addr, u32 size, u32 *p_data);
DPP_STATUS dpp_dev_pcie_default_read(struct dpp_dev_t *dev, u32 addr, u32 size, u32 *p_data);
DPP_STATUS dpp_dev_write_channel(struct dpp_dev_t *dev, u32 addr, u32 size, u32 *p_data);
DPP_STATUS dpp_dev_read_channel(struct dpp_dev_t *dev, u32 addr, u32 size, u32 *p_data);
DPP_STATUS dpp_dev_hash_opr_mutex_get(struct dpp_dev_t *dev, u32 fun_id,
				      struct zxic_mutex_t **p_mutex_out);
DPP_STATUS dpp_dev_hash_opr_mutex_create(struct dpp_dev_t *dev);
DPP_STATUS dpp_dev_hash_opr_mutex_destroy(struct dpp_dev_t *dev);
DPP_STATUS dpp_dev_last_check(struct dpp_dev_t *dev, u32 *last_flag);
DPP_STATUS dpp_soft_hash_index_set(struct dpp_dev_t *dev, u32 hash_index);
DPP_STATUS dpp_soft_hash_index_get(struct dpp_dev_t *dev, u32 *hash_index);
DPP_STATUS dpp_dev_dump_dma_mem_get(struct dpp_dev_t *dev, u32 *p_dma_size, u64 *p_dma_phy_addr,
				    u64 *p_dma_vir_addr);

#endif
