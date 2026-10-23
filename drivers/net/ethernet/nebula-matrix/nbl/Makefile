# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2021 Nebula Matrix Limited.
# Author: Walle Geng <walle.geng@nebula-matrix.com>

obj-$(CONFIG_NBL_CORE) := nbl_core.o

nbl_core-objs +=       nbl_common/nbl_common.o \
			nbl_common/nbl_event.o \
			nbl_common/nbl_devcomm.o \
			nbl_common/nbl_devshr.o \
			nbl_channel/nbl_channel.o \
			nbl_channel/nbl_cmdq.o \
			nbl_hw/nbl_hw_draco/nbl_phy_draco.o \
			nbl_hw/nbl_hw_draco/nbl_fc_draco.o \
			nbl_hw/nbl_hw_draco/nbl_tc_tun_draco.o \
			nbl_hw/nbl_hw_draco/nbl_flow_draco.o \
			nbl_hw/nbl_hw_draco/nbl_tc_flow_draco.o \
			nbl_hw/nbl_hw_draco/nbl_resource_draco.o \
			nbl_hw/nbl_hw_leonis/nbl_phy_leonis.o \
			nbl_hw/nbl_hw_leonis/nbl_fc_leonis.o \
			nbl_hw/nbl_hw_leonis/nbl_tc_tun_leonis.o \
			nbl_hw/nbl_hw_leonis/nbl_flow_leonis.o \
			nbl_hw/nbl_hw_leonis/nbl_tc_flow_leonis.o \
			nbl_hw/nbl_hw_leonis/nbl_tc_flow_filter_leonis.o \
			nbl_hw/nbl_hw_leonis/nbl_resource_leonis.o \
			nbl_hw/nbl_hw_leonis/nbl_tc_mcc_leonis.o \
			nbl_hw/nbl_hw_leonis/nbl_phy_leonis_regs.o \
			nbl_hw/nbl_tc_flow.o \
			nbl_hw/nbl_fc.o \
			nbl_hw/nbl_tc_pedit.o \
			nbl_hw/nbl_resource.o \
			nbl_hw/nbl_interrupt.o \
			nbl_hw/nbl_txrx.o \
			nbl_hw/nbl_queue.o \
			nbl_hw/nbl_vsi.o \
			nbl_hw/nbl_adminq.o \
			nbl_hw/nbl_accel.o \
			nbl_hw/nbl_fd.o \
			nbl_core/nbl_dispatch.o \
			nbl_core/nbl_debugfs.o \
			nbl_core/nbl_ethtool.o \
			nbl_core/nbl_service.o \
			nbl_core/nbl_dev_rdma.o \
			nbl_core/nbl_dev_lag.o \
			nbl_core/nbl_sysfs.o \
			nbl_core/nbl_dev.o \
			nbl_core/nbl_dev_user.o \
			nbl_core/nbl_ktls.o \
			nbl_core/nbl_ipsec.o \
			nbl_core/nbl_macsec.o \
			nbl_core/nbl_tc_tun.o \
			nbl_core/nbl_tc.o \
			nbl_core/nbl_hwmon.o \
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

ccflags-y += -I$(srctree)/$(src)
ccflags-y += -I$(srctree)/drivers/net/ethernet/nebula-matrix/nbl/nbl_include/
ccflags-y += -I$(srctree)/drivers/net/ethernet/nebula-matrix/nbl/nbl_hw
