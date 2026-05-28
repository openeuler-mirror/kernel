# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
# All rights reserved.

ccflags-y += -I$(srctree)/drivers/net/ethernet/yunsilicon/xsc

ifeq ($(HAVE_TO_USE_M_IB_CORE), 1)
	ccflags-y += $(xsc-ccflags)
endif

obj-$(CONFIG_YUNSILICON_XSC_ETH) += xsc_eth.o

xsc_eth-y := main.o xsc_eth_ctrl.o xsc_eth_tx.o xsc_eth_rx.o xsc_eth_txrx.o \
		ut_main.o xsc_eth_ethtool.o xsc_eth_stats.o xsc_dcbnl.o xsc_hw_comm.o \
		xsc_eth_sysfs.o xsc_fs.o xsc_eth_dim.o xsc_mc_filter.o

xsc_eth-y += rep/xsc_eth_rep.o rep/neigh.o

xsc_eth-y += tc/mod_hdr.o tc/post_act.o tc/tc_flow.o rep/xsc_rep_tc.o

xsc_eth-y += tc/act/accept.o tc/act/act.o tc/act/csum.o tc/act/drop.o tc/act/goto.o \
			tc/act/mirred.o tc/act/pedit.o tc/act/ptype.o tc/act/vlan.o tc/act/vlan_mangle.o \
			diag/xsc_tc_tracepoint.o
