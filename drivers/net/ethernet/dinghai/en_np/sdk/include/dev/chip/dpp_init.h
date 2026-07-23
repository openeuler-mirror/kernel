/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_INIT_H_
#define _DPP_INIT_H_

#define DPP_INIT_FLAG_ACCESS_TYPE (1 << 0)
#define DPP_INIT_FLAG_SERDES_DOWN_TP (1 << 1)
#define DPP_INIT_FLAG_DDR_BACKDOOR (1 << 2)
#define DPP_INIT_FLAG_SA_MODE (1 << 3)
#define DPP_INIT_FLAG_SA_MESH (1 << 4)
#define DPP_INIT_FLAG_SA_SERDES_MODE (1 << 5)
#define DPP_INIT_FLAG_INT_DEST_MODE (1 << 6)
#define DPP_INIT_FLAG_LIF0_MODE (1 << 7)
#define DPP_INIT_FLAG_DMA_ENABLE (1 << 8)
#define DPP_INIT_FLAG_TM_IMEM_FLAG (1 << 9)

struct dpp_sys_init_ctrl_t {
	enum dpp_dev_type_e device_type;
	u32 flags;
	u32 sa_id;
	u32 case_num;
	u32 lif0_port_type;
	u32 lif1_port_type;
	ZXIC_ADDR_T pcie_vir_baddr;
	ZXIC_ADDR_T riscv_vir_baddr;
	ZXIC_ADDR_T dma_vir_baddr;
	ZXIC_ADDR_T dma_phy_baddr;
	DPP_DEV_WRITE_FUNC pcie_write_fun;
	DPP_DEV_READ_FUNC pcie_read_fun;
	DPP_DEV_WRITE_FUNC riscv_write_fun;
	DPP_DEV_READ_FUNC riscv_read_fun;
	DPP_ACCESS_SWITCH_FUNC access_switch_fun;
};
DPP_STATUS dpp_init(u32 dev_id);

#endif /* dpp_init.h */
