# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_SPNIC) += spnic.o

subdir-ccflags-y += -I$(src)/hw

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
		hw/sphw_hwdev.o
