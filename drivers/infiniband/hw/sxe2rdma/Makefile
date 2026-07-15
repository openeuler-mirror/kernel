# SPDX-License-Identifier: GPL-2.0
CONFIG_MODULE_SIG=n

# Makefile path under the current directory
MAKEPATH := $(abspath $(lastword $(MAKEFILE_LIST)))
# Current directory
CURDIR :=$(shell dirname $(MAKEPATH))
KDIR := /lib/modules/$(shell uname -r)/build
ifneq ($(KERNELRELEASE),)
# Compilation
obj-m += sxe2rdma.o
sxe2rdma-objs += $(patsubst %.c, rdma/%.o,  $(notdir $(wildcard $(CURDIR)/rdma/*.c)))
# Whether auxiliary device drivers are to be compiled
ifneq ($(wildcard $(CURDIR)/vercode_build.sh),)
KER_DIR=$(srctree)
SPECIFIC_LINUX=$(shell bash $(CURDIR)/vercode_build.sh $(KER_DIR))
ifneq ($(SPECIFIC_LINUX),)
ccflags-y += -DSPECIFIC_LINUX
ccflags-y += -D$(SPECIFIC_LINUX)
endif
endif
ifeq ($(SPECIFIC_LINUX),BCLINUX_21_10U4)
obj-m += sxe2_auxiliary.o
sxe2_auxiliary-objs += $(patsubst %.c, base/auxiliary/%.o, $(notdir $(wildcard $(CURDIR)/base/auxiliary/*.c)))
else
CHECK_AUX_BUS ?= $(CURDIR)/check_aux_support.sh
NEED_AUX_BUS := $(shell bash ${CHECK_AUX_BUS} --ksrc="$(KDIR)" >/dev/null 2>&1; echo $$?)
$(info "NEED_AUX_BUS = $(NEED_AUX_BUS)")
ifeq ($(NEED_AUX_BUS), 2)
obj-m += sxe2_auxiliary.o
sxe2_auxiliary-objs += $(patsubst %.c, base/auxiliary/%.o, $(notdir $(wildcard $(CURDIR)/base/auxiliary/*.c)))
endif
endif
# Add compiler options and macros
ccflags-y += -g -ggdb #Supports debug information
ccflags-y += -Wall  #-Werror Enable all GCC warnings and treat warnings as errors (-Werror).
ccflags-y += -Wextra #Enable additional GCC warning options
ccflags-y += -frecord-gcc-switches #Afterwards, you can view the number of compilation options using the command readelf -p .gcc.command.li
# Kernel headers do not strictly comply with variable usage standards; not disabling this check will cause compilation to fail
ccflags-y += -Wno-unused-parameter -Wno-missing-field-initializers -Wno-implicit-fallthrough -Wno-type-limits
ccflags-y += -Wmaybe-uninitialized -frecord-gcc-switches
ccflags-y += -I$(CURDIR)/baselib/include
ccflags-y += -I$(CURDIR)/common/mbx
ccflags-y += -I$(CURDIR)/common/sxe2flow
ccflags-y += -I$(CURDIR)/common/sxe2pf
ccflags-y += -I$(CURDIR)/include/drv
ccflags-y += -I$(CURDIR)/rdma/compat
ccflags-y += -I$(CURDIR)/base/auxiliary
ccflags-y += -DSXE2_SUPPORT_CONFIGFS
ccflags-y += -DSXE2_CFG_RELEASE

# Default FPGA platform support, compatible with different hardware platforms
ifeq ($(MT_BUILDMODE),asic)
	ccflags-y += -DSXE2_HARDWARE_ASIC
else #ifeq ($(MT_BUILDMODE),emu)
	ccflags-y += -DSXE2_HARDWARE_EMU
endif
# make linux kernel version code
else # KERNELRELEASE
# Path to the kernel source tree
KDIR := /lib/modules/$(shell uname -r)/build

all:
	@$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	@rm -rf *.o *.d *.ko Module.* modules.* *.mod* .*.d .*.cmd .tmp_versions *readme.txt
	@rm -rf ./rdma/*.o ./rdma/.*.cmd
	@rm -rf ./base/log/*.o ./common/mbx/*.o ./common/sxe2pf/*.o
endif # KERNELRELEASE

