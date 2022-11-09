# SPDX-License-Identifier: GPL-2.0+
#
# Makefile for the Hisilicon ROH hns3 device drivers.
#

ccflags-y :=  -I $(srctree)/drivers/net/ethernet/hisilicon/hns3
ccflags-y +=  -I $(srctree)/drivers/roh/core
ccflags-y +=  -I $(srctree)/drivers/roh/hw/hns3

hns-roh-v1-objs := hns3_cmdq.o	\
		   hns3_verbs.o	\
		   hns3_intr.o	\
		   hns3_main.o
obj-$(CONFIG_ROH_HNS) += hns-roh-v1.o
