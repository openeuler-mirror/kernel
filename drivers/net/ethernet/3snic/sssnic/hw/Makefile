# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 3SNIC
#

ccflags-y += -I$(srctree)/drivers/net/ethernet/3snic/sssnic/hw
ccflags-y += -I$(srctree)/drivers/net/ethernet/3snic/sssnic/include
ccflags-y += -I$(srctree)/drivers/net/ethernet/3snic/sssnic/include/hw
ccflags-y += -I$(srctree)/drivers/net/ethernet/3snic/sssnic/include/kernel
ccflags-y += -I$(srctree)/drivers/net/ethernet/3snic/sssnic/hw/include

ccflags-y += -Werror
ccflags-y += -Wno-implicit-fallthrough

obj-$(CONFIG_SSSNIC_HW) += sssdk.o
sssdk-y := sss_hw_main.o \
			sss_pci_probe.o \
			sss_pci_remove.o \
			sss_pci_shutdown.o \
			sss_pci_error.o \
			sss_pci_sriov.o \
			sss_pci_global.o \
			sss_hwdev_api.o \
			sss_hwdev_cap.o \
			sss_hwdev_export.o \
			sss_hwdev_link.o \
			sss_hwdev_init.o \
			sss_hwdev_mgmt_info.o \
			sss_hwdev_mgmt_channel.o \
			sss_hwdev_io_flush.o \
			sss_hwif_ctrlq.o \
			sss_hwif_ctrlq_init.o \
			sss_hwif_ctrlq_export.o \
			sss_hwif_mbx.o \
			sss_hwif_mbx_init.o \
			sss_hwif_mbx_export.o \
			sss_hwif_adm.o \
			sss_hwif_adm_init.o \
			sss_hwif_init.o \
			sss_hwif_api.o \
			sss_hwif_export.o \
			sss_hwif_eq.o \
			sss_hwif_mgmt_init.o \
			sss_hwif_irq.o \
			sss_hwif_aeq.o \
			sss_common.o \
			sss_wq.o \
			sss_hwif_ceq.o \
			sss_adapter_mgmt.o
