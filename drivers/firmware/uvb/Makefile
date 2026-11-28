# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Create      : 2025-04-18
# Description : cis odf Makefile

ccflags-y += -I$(srctree)/drivers/firmware/uvb/include
ccflags-y += -I$(srctree)/drivers/firmware/uvb

obj-$(CONFIG_UDFI) = odf/odf_get_fdt.o
obj-$(CONFIG_UDFI_ODF) += odf.o
odf-objs := odf/odf_trans.o \
	odf/odf_data.o \
	odf/odf_helper.o

obj-$(CONFIG_UDFI_CIS) += cis.o
cis-objs := cis/cis_info_process.o \
	cis/uvb_info_process.o \
	cis/cis_core.o \
	cis/cis_ub.o
