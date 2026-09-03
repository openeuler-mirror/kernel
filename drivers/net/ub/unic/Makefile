# SPDX-License-Identifier: GPL-2.0+
#
# Makefile for the HISILICON network device drivers.
#

ccflags-y += -I$(srctree)/$(src)
ccflags-y += -I$(srctree)/drivers/net/ub/unic/debugfs

MODULE_NAME := unic

UNIC_OBJS := unic_main.o unic_dev.o unic_netdev.o unic_hw.o unic_ethtool.o \
	debugfs/unic_debugfs.o unic_tx.o unic_rx.o unic_txrx.o unic_guid.o \
	unic_comm_addr.o unic_mac.o unic_vlan.o unic_lb.o \
	debugfs/unic_qos_debugfs.o unic_stats.o debugfs/unic_entry_debugfs.o unic_qos_hw.o \
	unic_channel.o debugfs/unic_ctx_debugfs.o unic_ip.o unic_crq.o \
	unic_event.o unic_reset.o unic_bond.o

ifeq ($(CONFIG_UB_UNIC_DCB), y)
	UNIC_OBJS += unic_dcbnl.o
endif

$(MODULE_NAME)-objs := $(UNIC_OBJS)
obj-$(CONFIG_UB_UNIC) += unic.o
