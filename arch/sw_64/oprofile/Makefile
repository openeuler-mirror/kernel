# SPDX-License-Identifier: GPL-2.0
ccflags-y := -Werror -Wno-sign-compare

obj-$(CONFIG_OPROFILE) += oprofile.o

DRIVER_OBJS = $(addprefix ../../../drivers/oprofile/, \
		oprof.o cpu_buffer.o buffer_sync.o \
		event_buffer.o oprofile_files.o \
		oprofilefs.o oprofile_stats.o \
		timer_int.o )

oprofile-y				:= $(DRIVER_OBJS) common.o
oprofile-$(CONFIG_SW64)			+= op_model_sw2f.o
