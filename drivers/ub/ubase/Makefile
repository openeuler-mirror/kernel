# SPDX-License-Identifier: GPL-2.0+
#
## Makefile for the Hisilicon ubase drivers.
#
##

ccflags-y += -I$(srctree)/$(src)
ccflags-y += -I$(srctree)/drivers/ub/ubase/debugfs

MODULE_NAME := ubase

UBASE_OBJS := ubase_main.o ubase_dev.o ubase_hw.o ubase_cmd.o ubase_ctrlq.o \
	debugfs/ubase_debugfs.o ubase_eq.o ubase_mailbox.o ubase_ubus.o \
	debugfs/ubase_ctx_debugfs.o debugfs/ubase_qos_debugfs.o \
	ubase_qos_hw.o ubase_tp.o ubase_reset.o ubase_stats.o ubase_arq.o \
	ubase_pmem.o ubase_rct.o ubase_usc.o ubase_dtumem.o ubase_proxy.o \
	debugfs/ubase_proxy_debugfs.o

$(MODULE_NAME)-objs := $(UBASE_OBJS)
obj-$(CONFIG_UB_UBASE) := ubase.o
