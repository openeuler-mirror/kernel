# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd.
#
# Makefile for the Wangxun(R) 10GbE PCI Express ethernet driver
#
ccflags-y += -I$(src)

obj-$(CONFIG_NSEVF) += nsevf.o

nsevf-y := nsevf_main.o \
        nsevf_ethtool.o \
        nsevf_virtchnl.o \
        nsevf_msgbox.o   \
        nsevf_adminq.o   \
        nsevf_common.o   \
        nsevf_debugfs.o  \
        nsevf_txrx.o \
        nsevf_idc.o \
	nsevf_test_suite.o \
        nsevf_fdir.o

