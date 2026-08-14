# SPDX-License-Identifier: GPL-2.0
#
# Mucse N20/B850 PF Ethernet driver
#

obj-$(CONFIG_MCEPF) += mcepf.o

# This driver targets the in-tree kernel APIs directly.  Do not add an
# out-of-tree compatibility layer here.
mcepf-y := mce_main.o \
	mce_n20/mce_hw_n20.o \
	mce_n20/mce_hw_debugfs.o \
	mce_n20/mce_hw_dcb.o \
	mce_n20/mce_hw_npu.o \
	mce_n20/mce_hw_fdir.o \
	mce_fltr.o \
	mce_base.o \
	mce_lib.o \
	mce_irq.o \
	mce_txrx_lib.o \
	mce_txrx.o \
	mce_netdev.o \
	mce_ethtool.o \
	mce_ethtool_fdir.o \
	mce_fdir.o \
	mce_parse.o \
	mce_fdir_flow.o \
	mce_profile_mask.o \
	mce_tc_lib.o \
	mce_mbx.o \
	mce_dcb.o \
	mce_npu.o \
	mce_virtchnl.o \
	mce_fwchnl.o \
	mce_vf_lib.o \
	mce_idc.o \
	mce_fops.o \
	mce_eswitch.o \
	mce_switch.o

mcepf-$(CONFIG_PCI_IOV) += mce_sriov.o
mcepf-$(CONFIG_DCB) += mce_dcbnl.o
mcepf-$(CONFIG_SYSFS) += mce_sysfs.o
mcepf-$(CONFIG_NET_DEVLINK:m=y) += mce_devlink.o mce_repr.o

mcepf-$(CONFIG_DEBUG_FS) += mce_debugfs.o mce_debugfs_regs.o
mcepf-$(CONFIG_PTP_1588_CLOCK) += mce_n20/mce_hw_ptp.o mce_ptp.o
