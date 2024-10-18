# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2021 Nebula Matrix Limited.
# Author: Walle Geng <walle.geng@nebula-matrix.com>

obj-$(CONFIG_NBL_CORE) := nbl_core.o

nbl_core-objs +=       nbl_common/nbl_common.o \
				nbl_common/nbl_event.o \
				nbl_channel/nbl_channel.o \
				nbl_hw/nbl_hw_leonis/nbl_phy_leonis.o \
				nbl_hw/nbl_hw_leonis/nbl_flow_leonis.o \
				nbl_hw/nbl_hw_leonis/nbl_queue_leonis.o \
				nbl_hw/nbl_hw_leonis/nbl_resource_leonis.o \
				nbl_hw/nbl_resource.o \
				nbl_hw/nbl_interrupt.o \
				nbl_hw/nbl_txrx.o \
				nbl_hw/nbl_queue.o \
				nbl_hw/nbl_vsi.o \
				nbl_hw/nbl_adminq.o \
				nbl_core/nbl_dispatch.o \
				nbl_core/nbl_debugfs.o \
				nbl_core/nbl_ethtool.o \
				nbl_core/nbl_service.o \
				nbl_core/nbl_dev.o \
				nbl_core/nbl_hwmon.o \
				nbl_core/nbl_dev_user.o \
				nbl_main.o

# Do not modify include path, unless you are adding a new file which needs some headers in its
# direct upper directory (see the exception part in below).
#
# The structure requires that codes can only access the header files in nbl_include, or the .h that
# has the same name as the .c file. The only exception is that the product-specific files can access
# the same headers as the common part, e.g. nbl_phy_leonis.c can access nbl_phy.h.
# Make sure to put all the things you need to expose to others in nbl_def_xxx.h, and make everything
# in your own .h private.
#
# Try not to break these rules, sincerely.
ccflags-y := -I $(src) -I $(src)/nbl_include -I $(src)/nbl_export -I $(src)/nbl_hw

