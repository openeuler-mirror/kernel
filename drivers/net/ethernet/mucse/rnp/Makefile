# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2022 - 2023 Mucse Corporation.
#
# Makefile for the Mucse(R) 1/10/25/40GbE PCI Express ethernet driver
#
#

obj-$(CONFIG_MXGBE) += rnp.o

rnp-objs :=   \
		rnp_main.o \
		rnp_common.o \
		rnp_ethtool.o \
		rnp_lib.o \
		rnp_mbx.o \
		rnp_pcs.o \
		rnp_n10.o \
		rnp_mbx_fw.o\
		rnp_sriov.o \
		rnp_param.o \
		rnp_sysfs.o \
		rnp_ptp.o \
		rnp_mpe.o 

rnp-$(CONFIG_DEBUG_FS) += rnp_debugfs.o
rnp-$(CONFIG_MXGBE_DCB) +=  rnp_dcb.o
