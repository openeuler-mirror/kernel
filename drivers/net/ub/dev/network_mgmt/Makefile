# SPDX-License-Identifier: GPL-2.0+
#
# Makefile for the UB network management.
#

#### add inclue directory
MODULE_NAME := ub_nm
ccflags-y +=-I$(src) \
	    -I$(src)/../

#### compile NETWORK_MGNT
NETWORK_MGNT_OBJS := network_mgmt.o
$(MODULE_NAME)-objs := $(NETWORK_MGNT_OBJS)
obj-$(CONFIG_NETWORK_MGNT) = ub_nm.o
