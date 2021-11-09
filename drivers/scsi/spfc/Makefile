# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_SPFC) += spfc.o

subdir-ccflags-y += -I$(srctree)/$(src)/../../net/ethernet/ramaxel/spnic/hw
subdir-ccflags-y += -I$(srctree)/$(src)/hw
subdir-ccflags-y += -I$(srctree)/$(src)/common

spfc-objs := common/unf_init.o \
		common/unf_event.o \
		common/unf_exchg.o \
		common/unf_exchg_abort.o \
		common/unf_io.o \
		common/unf_io_abnormal.o \
		common/unf_lport.o \
		common/unf_npiv.o \
		common/unf_npiv_portman.o \
		common/unf_disc.o \
		common/unf_rport.o \
		common/unf_service.o \
		common/unf_ls.o \
		common/unf_gs.o \
		common/unf_portman.o \
		common/unf_scsi.o \
		hw/spfc_utils.o \
		hw/spfc_lld.o \
		hw/spfc_io.o \
		hw/spfc_wqe.o \
		hw/spfc_service.o \
		hw/spfc_chipitf.o \
		hw/spfc_queue.o \
		hw/spfc_hba.o \
		hw/spfc_cqm_bat_cla.o \
		hw/spfc_cqm_bitmap_table.o \
		hw/spfc_cqm_main.o \
		hw/spfc_cqm_object.o \
		sphw_hwdev.o \
		sphw_hw_cfg.o \
		sphw_hw_comm.o \
		sphw_prof_adap.o \
		sphw_common.o \
		sphw_hwif.o \
		sphw_wq.o \
		sphw_cmdq.o \
		sphw_eqs.o \
		sphw_mbox.o \
		sphw_mgmt.o \
		sphw_api_cmd.o
