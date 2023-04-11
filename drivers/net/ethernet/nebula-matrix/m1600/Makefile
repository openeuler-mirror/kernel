# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022 Nebula Matrix Limited.
# Author: Monte Song <monte.song@nebula-matrix.com>

ccflags-y += -DCONFIG_NBL_DEBUGFS

obj-$(CONFIG_M1600) += m1600.o

m1600-y += main.o \
	ethtool.o \
	common.o \
	interrupt.o \
	txrx.o \
	mailbox.o \
	debug.o \
	hwmon.o \
	macvlan.o \
	sriov.o

