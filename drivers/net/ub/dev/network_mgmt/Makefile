# SPDX-License-Identifier: GPL-2.0+
#
# Makefile for the UB network management.
#

#### add inclue directory
MODULE_NAME := ub_nm
ccflags-y += -I$(srctree)/drivers/net/ub/dev/network_mgmt/ip_notify \
			-I$(srctree)/drivers/net/ub/dev/network_mgmt \
			-I$(srctree)/drivers/net/ub/dev \

#### compile NETWORK_MGNT
NETWORK_MGNT_OBJS := network_mgmt.o ./ip_notify/ip_notify.o
$(MODULE_NAME)-objs := $(NETWORK_MGNT_OBJS)
obj-$(CONFIG_NETWORK_MGNT) = ub_nm.o
