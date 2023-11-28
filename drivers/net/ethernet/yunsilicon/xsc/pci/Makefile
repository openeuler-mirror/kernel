# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
# All rights reserved.
#
# Makefile for the Yunsilicon xsc ethernet driver
#
ccflags-y := -I $(srctree)/drivers/net/ethernet/yunsilicon/xsc/
ccflags-y += -Wno-implicit-fallthrough

obj-$(CONFIG_YUNSILICON_XSC_PCI) += xsc_pci.o

xsc_pci-y := main.o eq.o intf.o debugfs.o alloc.o wq.o cq.o qp.o \
             cmd2.o fw.o pagealloc.o port.o mr.o pd.o mad.o xsc_lag.o xsc_pci_ctrl.o\
             pci_irq.o vport.o sriov.o sriov_sysfs.o devlink.o eswitch.o xsc_port_ctrl.o \
	     fw/cmd.o \
	     fw/xsc_flow.o \
	     fw/xsc_res.o \
	     fw/osdep.o \
	     fw/xsc_mem.o
