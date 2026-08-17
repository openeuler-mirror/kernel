/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_OSDEP_H_
#define _TXGBE_OSDEP_H_

/* OS dependent compile time tunables, previously supplied via configure */

#ifndef CHNOS
#define CHNOS			0
#endif

#ifndef DEFAULT_FCPAUSE
#define DEFAULT_FCPAUSE		0xFFFF
#endif

#ifndef MAX_REQUEST_SIZE
#define MAX_REQUEST_SIZE	256
#endif

#ifndef DEFAULT_TXD
#define DEFAULT_TXD		1024
#endif

#ifndef DEFAULT_TX_WORK
#define DEFAULT_TX_WORK		256
#endif

#ifndef LASER_OFF
#define LASER_OFF		0
#endif

#ifndef CL72_KRTR_PRBS_MODE_EN
#define CL72_KRTR_PRBS_MODE_EN	0xFFFF
#endif

#ifndef AN73_TRAINNING_MODE
#define AN73_TRAINNING_MODE	2
#endif

#ifndef CL73_PDET_EN
#define CL73_PDET_EN		0
#endif

#ifndef CL74_KRTR_TRAINNING_TIMEOUT
#define CL74_KRTR_TRAINNING_TIMEOUT	6000
#endif

#ifndef AN_TRAINNING_MODE
#define AN_TRAINNING_MODE	0
#endif

#ifndef CTLE_BYPASS
#define CTLE_BYPASS		0
#endif

#ifndef SW_OEM_EPHY
#define SW_OEM_EPHY		0
#endif

#ifndef SW_CTRL_EPHY_FORCE
#define SW_CTRL_EPHY_FORCE	1
#endif

#ifndef SFI_SET
#define SFI_SET			0
#endif

#ifndef SFI_MAIN
#define SFI_MAIN		24
#endif

#ifndef SFI_PRE
#define SFI_PRE			4
#endif

#ifndef SFI_POST
#define SFI_POST		16
#endif

#ifndef SFI_TXRX_PIN
#define SFI_TXRX_PIN		0
#endif

#ifndef AUTO
#define AUTO			1
#endif

#ifndef KR_FEC
#define KR_FEC			1
#endif

#ifndef KR_MODE
#define KR_MODE			0
#endif

#ifndef KR_TRAINNING_MODE
#define KR_TRAINNING_MODE	2
#endif

#ifndef KR_SET
#define KR_SET			0
#endif

#ifndef KR_MAIN
#define KR_MAIN			27
#endif

#ifndef KR_PRE
#define KR_PRE			8
#endif

#ifndef KR_POST
#define KR_POST			44
#endif

#ifndef KR_TXRX_PIN
#define KR_TXRX_PIN		0
#endif

#ifndef KX4_SET
#define KX4_SET			0
#endif

#ifndef KX4_MAIN
#define KX4_MAIN		40
#endif

#ifndef KX4_PRE
#define KX4_PRE			0
#endif

#ifndef KX4_POST
#define KX4_POST		0
#endif

#ifndef KX4_TXRX_PIN
#define KX4_TXRX_PIN		0
#endif

#ifndef KX_SET
#define KX_SET			0
#endif

#ifndef KX_MAIN
#define KX_MAIN			24
#endif

#ifndef KX_PRE
#define KX_PRE			4
#endif

#ifndef KX_POST
#define KX_POST			16
#endif

#ifndef KX_SGMII
#define KX_SGMII		0
#endif

#ifndef BOND_CHECK_LINK_MODE
#define BOND_CHECK_LINK_MODE	0
#endif

#ifndef TXGBE_STATIC_ITR
#define TXGBE_STATIC_ITR	1
#endif

#ifndef TXGBE_PCIE_RECOVER
#define TXGBE_PCIE_RECOVER	1
#endif

#ifndef TXGBE_RECOVER_CHECK
#define TXGBE_RECOVER_CHECK	1
#endif

#ifndef TXGBE_DIS_COMP_TIMEOUT
#define TXGBE_DIS_COMP_TIMEOUT	1
#endif

#ifndef TXGBE_LINK_FAULT
#define TXGBE_LINK_FAULT	0
#endif

#ifndef TXGBE_TXHEAD_WB
#define TXGBE_TXHEAD_WB		0
#endif

#ifndef TXGBE_RX_MERGE
#define TXGBE_RX_MERGE		0
#endif

#ifndef TXGBE_1588_PPS_LEVEL
#define TXGBE_1588_PPS_LEVEL	1
#endif

#ifndef TXGBE_1588_PPS_WIDTH
#define TXGBE_1588_PPS_WIDTH	100
#endif

#ifndef TXGBE_1588_TOD_ENABLE
#define TXGBE_1588_TOD_ENABLE	1
#endif

#ifndef TXGBE_STORM_INTERVAL
#define TXGBE_STORM_INTERVAL	100
#endif

#ifndef TXGBE_STORM_UC
#define TXGBE_STORM_UC		0
#endif

#ifndef TXGBE_STORM_BC
#define TXGBE_STORM_BC		0
#endif

#ifndef TXGBE_STORM_BC_THRE
#define TXGBE_STORM_BC_THRE	100
#endif

#ifndef TXGBE_STORM_MC
#define TXGBE_STORM_MC		0
#endif

#ifndef TXGBE_STORM_MC_THRE
#define TXGBE_STORM_MC_THRE	100
#endif

#ifndef TXGBE_RX_BUF_MODE
#define TXGBE_RX_BUF_MODE	0
#endif

#endif /* _TXGBE_OSDEP_H_ */
