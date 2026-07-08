# SPDX-License-Identifier: GPL-2.0+

ccflags-y += -I$(src)

hisi_ubus-objs := hisi-ubus.o controller.o vdm.o local-ras.o msg.o msg-core.o
hisi_ubus-objs += msg-debugfs.o eu-table.o memory.o hisi-decoder.o

obj-$(CONFIG_UB_HISI_UBUS) += hisi_ubus.o
