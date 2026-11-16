# SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
# Copyright (c) 2019, WangXun Corporation.

#
# Makefile for the WangXun Ethernet Connection RDMA Linux Driver
#

obj-$(CONFIG_INFINIBAND_NSER) += nser.o

nser-objs := main.o      \
	      	 hw.o        \
	      	 ctrl.o      \
	     	 hmc.o       \
	      	 pble.o      \
	      	 uk.o        \
	      	 utils.o     \
	      	 uda.o       \
	      	 ws.o        \
	      	 nserdma_hw.o \
	      	 configfs.o  \
	      	 vf.o        \
	      	 verbs.o     \
	      	 virtchnl.o  \
	      	 nser_kcompat.o \
	      	 debugfs.o

CFLAGS_trace.o = -I$(src)
