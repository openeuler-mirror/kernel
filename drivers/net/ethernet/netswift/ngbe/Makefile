# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2015 - 2017 Beijing WangXun Technology Co., Ltd.
#
# Makefile for the Netswift Gigabit PCI Express ethernet driver
#

obj-$(CONFIG_NGBE) += ngbe.o

ngbe-objs := ngbe_main.o ngbe_ethtool.o \
              ngbe_hw.o ngbe_phy.o ngbe_sriov.o \
              ngbe_mbx.o ngbe_pcierr.o ngbe_param.o ngbe_lib.o ngbe_ptp.o

ngbe-$(CONFIG_NGBE_HWMON) += ngbe_sysfs.o
ngbe-$(CONFIG_NGBE_DEBUG_FS) += ngbe_debugfs.o
ngbe-$(CONFIG_NGBE_SYSFS) += ngbe_sysfs.o
