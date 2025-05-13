# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
# All rights reserved.

ccflags-y += -I$(srctree)/drivers/net/ethernet/yunsilicon/xsc

ifeq ($(HAVE_TO_USE_M_IB_CORE), 1)
	ccflags-y += $(xsc-ccflags)
endif

obj-$(CONFIG_YUNSILICON_XSC_PCI) += xsc_pci.o

xsc_pci-y := main.o eq.o intf.o debugfs.o alloc.o wq.o cq.o qp.o \
		cmd2.o fw.o port.o mr.o pd.o xsc_lag.o xsc_pci_ctrl.o xsc_prgrmmbl_cc_ctrl.o\
		pci_irq.o vport.o sriov.o sriov_sysfs.o devlink.o eswitch.o xsc_port_ctrl.o res_obj.o qpts.o\
		fw/cmd.o \
		fw/xsc_flow.o \
		fw/xsc_res.o \
		hal/xsc_hal.o \
		hal/andes_impl.o \
		hal/diamond_impl.o \
		hal/diamond_next_impl.o \
		tunnel_cmd.o