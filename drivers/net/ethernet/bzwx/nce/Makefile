# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the BeiZhongWangXin network device drivers.
#

ccflags-y += -I$(srctree)/drivers/net/ethernet/bzwx/nce/comm
ccflags-y += -I$(srctree)/drivers/net/ethernet/bzwx/nce/ne6x
ccflags-y += -I$(srctree)/drivers/net/ethernet/bzwx/nce/ne6x_vf
subdir-ccflags-y += -I$(src)/comm
subdir-ccflags-y += -I$(src)/ne6x
subdir-ccflags-y += -I$(src)/ne6x_vf

obj-$(CONFIG_NE6X) += ncepf.o
ncepf-objs := comm/txrx.o	\
	 ne6x/ne6x_main.o	\
	 ne6x/ne6x_ethtool.o	\
	 ne6x/ne6x_procfs.o	\
	 ne6x/ne6x_netlink.o	\
	 ne6x/ne6x_interrupt.o	\
	 ne6x/ne6x_reg.o	\
	 ne6x/ne6x_dev.o	\
	 ne6x/ne6x_txrx.o

ncepf-$(CONFIG_DEBUG_FS) += ne6x/ne6x_debugfs.o
ncepf-$(CONFIG_PCI_IOV) += ne6x/ne6x_virtchnl_pf.o
ncepf-$(CONFIG_RFS_ACCEL) += ne6x/ne6x_arfs.o

obj-$(CONFIG_NE6XVF) += ncevf.o
ncevf-objs := comm/txrx.o	\
	 ne6x_vf/ne6xvf_main.o	\
	 ne6x_vf/ne6xvf_ethtool.o	\
	 ne6x_vf/ne6xvf_virtchnl.o	\
	 ne6x_vf/ne6xvf_txrx.o

ncevf-$(CONFIG_DEBUG_FS) += ne6x_vf/ne6xvf_debugfs.o
