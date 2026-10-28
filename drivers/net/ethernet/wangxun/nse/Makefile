# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2018 - 2024 Beijing WangXun Technology Co., Ltd.
#
# Makefile for the Wangxun(R) 100GbE PCI Express ethernet driver

obj-$(CONFIG_NSE) += nse.o

nse-objs := nse_main.o \
            nse_hw_conf.o \
            nse_fw_conf.o \
            nse_fwmng.o \
            nse_msgbox.o \
            nse_controlq.o \
            nse_common.o \
            nse_nvm.o \
            nse_neigh.o \
            nse_switch.o \
            nse_legacy_switch.o \
            nse_acl.o \
            nse_sched.o \
            nse_sched_aqc.o \
            nse_sched_internal.o \
            nse_base.o \
            nse_lib.o \
            nse_txrx_lib.o \
            nse_txrx.o \
            nse_fltr.o \
            nse_lpm.o \
            nse_irq.o \
            nse_pf_vsi_vlan_ops.o \
            nse_vsi_vlan_ops.o \
            nse_vsi_vlan_lib.o \
            nse_tc_ct.o \
            nse_tc_lib.o \
            nse_fdir.o \
            nse_flow.o \
            nse_lag.o \
            nse_lmac_phy.o \
            nse_ethtool.o \
            nse_idc.o \
            nse_test_suite.o \
            nse_devlink.o \
            nse_fw_update.o \
            nse_eswitch.o \
            nse_repr.o \
            nse_repr_sysfs.o \
            nse_repr_meter.o

nse-$(CONFIG_DEBUG_FS) += nse_debugfs.o
nse-$(CONFIG_PCI_IOV) += nse_sriov.o \
						 nse_sriov_sysfs.o \
						 nse_vf_meter.o \
                         nse_vf_mbx.o \
						 nse_vf_vsi_vlan_ops.o \
						 nse_virtchnl_allowlist.o \
                         nse_virtchnl.o \
						 nse_vf_lib.o
nse-$(CONFIG_PTP_1588_CLOCK) += nse_ptp.o nse_ptp_hw.o
nse-$(CONFIG_DCB) += nse_dcb.o nse_dcb_nl.o nse_dcb_lib.o
nse-$(CONFIG_RFS_ACCEL) += nse_arfs.o
nse-$(CONFIG_XDP_SOCKETS) += nse_xsk.o
