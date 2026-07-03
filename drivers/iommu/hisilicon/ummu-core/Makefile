# SPDX-License-Identifier: GPL-2.0+

ummu_core_builtin-y := core_iova.o \
	core_eid.o \
	core_common.o

ummu-core-$(CONFIG_UB_UMMU_CORE_DRIVER) := core_tid.o \
	core_tdev.o \
	core.o \
	core_ioctl.o

ummu-core-$(CONFIG_UB_UMMU_SVA_SEPARATED_PAGES) += core_matt.o

obj-$(CONFIG_UB_UMMU_CORE) += ummu_core_builtin.o

obj-$(CONFIG_UB_UMMU_CORE_DRIVER) += ummu-core.o

# for tracing framework to find ummu_trace.h
CFLAGS_core_tid.o := -I$(src)
