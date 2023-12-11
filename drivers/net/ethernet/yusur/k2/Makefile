# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/$(src)/../include

obj-$(CONFIG_YUSUR_K2) += ysnic_k2.o

PLATFORM_OBJS := ../platform/ys_auxiliary.o \
		 ../platform/ys_init.o \
		 ../platform/ys_intr.o \
		 ../platform/ys_ndev.o \
		 ../platform/ys_pdev.o \
		 ../platform/ys_sysfs.o

NET_OBJS := ../net/ys_ethtool_ops.o \
	    ../net/ys_ndev_ops.o

ysnic_k2-y += ys_k2_cq.o \
              ys_k2_eq.o \
              ys_k2_main.o \
              ys_k2_rx.o \
              ys_k2_tx.o \
              ys_k2_core.o

ysnic_k2-y += $(NET_OBJS)
ysnic_k2-y += $(PLATFORM_OBJS)
