# SPDX-License-Identifier: GPL-2.0+
#
# Makefile for the UB network management.
#

#### add inclue directory
MODULE_NAME := ub_nm
ccflags-y += -I$(src)/ip_notify \
			-I$(src) \
			-I$(src)/../ \

#### compile NETWORK_MGNT
NETWORK_MGNT_OBJS := network_mgmt.o ./ip_notify/ip_notify.o
$(MODULE_NAME)-objs := $(NETWORK_MGNT_OBJS)
obj-$(CONFIG_NETWORK_MGNT) = ub_nm.o
