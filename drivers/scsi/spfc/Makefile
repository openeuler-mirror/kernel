# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_SPFC) += spfc.o

subdir-ccflags-y += -I$(src)/../../net/ethernet/ramaxel/spnic/hw
subdir-ccflags-y += -I$(src)/hw
subdir-ccflags-y += -I$(src)/common

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
		../../net/ethernet/ramaxel/spnic/hw/sphw_hwdev.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_hw_cfg.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_hw_comm.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_prof_adap.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_common.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_hwif.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_wq.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_cmdq.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_eqs.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_mbox.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_mgmt.o \
		../../net/ethernet/ramaxel/spnic/hw/sphw_api_cmd.o
