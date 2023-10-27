# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
# All rights reserved.
#
# Makefile for the Yunsilicon xsc ethernet driver
#
ccflags-y := -I $(srctree)/drivers/net/ethernet/yunsilicon/xsc/
obj-$(CONFIG_YUNSILICON_XSC_ETH) += xsc_net.o

xsc_net-y := main.o xsc_eth_ctrl.o xsc_eth_tx.o xsc_eth_rx.o \
	 	xsc_eth_txrx.o ut_main.o xsc_eth_ethtool.o \
		xsc_eth_stats.o xsc_dcbnl.o

