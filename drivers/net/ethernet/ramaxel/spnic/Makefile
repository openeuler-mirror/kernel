# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_SPNIC) += spnic.o

subdir-ccflags-y += -I$(srctree)/$(src)/hw

spnic-objs := hw/sphw_common.o \
		hw/sphw_hwif.o \
		hw/sphw_eqs.o \
		hw/sphw_mbox.o \
		hw/sphw_api_cmd.o \
		hw/sphw_mgmt.o \
		hw/sphw_wq.o \
		hw/sphw_cmdq.o \
		hw/sphw_prof_adap.o \
		hw/sphw_hw_cfg.o \
		hw/sphw_hw_comm.o \
		hw/sphw_hwdev.o \
		spnic_sriov.o \
		spnic_lld.o \
		spnic_dev_mgmt.o \
		spnic_main.o \
		spnic_tx.o \
		spnic_rx.o \
		spnic_rss.o \
		spnic_ntuple.o \
		spnic_dcb.o \
		spnic_ethtool.o \
		spnic_ethtool_stats.o \
		spnic_dbg.o \
		spnic_irq.o \
		spnic_filter.o \
		spnic_netdev_ops.o \
		spnic_nic_cfg.o \
		spnic_mag_cfg.o \
		spnic_nic_cfg_vf.o \
		spnic_rss_cfg.o \
		spnic_nic_event.o \
		spnic_nic_io.o \
		spnic_nic_dbg.o
