# SPDX-License-Identifier: GPL-2.0
CONFIG_MODULE_SIG=n

# Makefile path under the current directory
MAKEPATH := $(abspath $(lastword $(MAKEFILE_LIST)))
# Current directory
CURDIR :=$(shell dirname $(MAKEPATH))
KDIR := /lib/modules/$(shell uname -r)/build
MT_BUILDMODE?=asic

ifneq ($(KERNELRELEASE),)
# CompilationCompilation
CONFIG_SXE2_VF ?= m
obj-$(CONFIG_SXE2_VF) += sxe2vf.o
sxe2vf-objs += $(patsubst %.c, sxe2vf/%.o, $(notdir $(wildcard $(CURDIR)/sxe2vf/*.c)))
sxe2vf-objs += $(patsubst %.c, sxe2vf/com_parse/%.o, $(notdir $(wildcard $(CURDIR)/sxe2vf/com_parse/*.c)))
sxe2vf-objs += $(patsubst %.c, common/mbx/%.o, $(notdir $(wildcard $(CURDIR)/common/mbx/*.c)))
sxe2vf-objs += $(patsubst %.c, common/sxe2vf/%.o, $(notdir $(wildcard $(CURDIR)/common/sxe2vf/*.c)))
ifeq ($(CONFIG_SXE2_VF),m)
sxe2vf-objs += $(patsubst %.c, base/log/%.o, $(notdir $(wildcard $(CURDIR)/base/log/*.c)))
sxe2vf-objs += $(patsubst %.c, base/compat/%.o, $(notdir $(wildcard $(CURDIR)/base/compat/*.c)))
sxe2vf-objs += $(patsubst %.c, base/ioctl/%.o, $(notdir $(wildcard $(CURDIR)/base/ioctl/*.c)))
endif

# Generate linux kernel version code
ifneq ($(wildcard $(CURDIR)/vercode_build.sh),)
  KER_DIR=$(srctree)
  SPECIFIC_LINUX=$(shell bash $(CURDIR)/vercode_build.sh $(KER_DIR))
  ifneq ($(SPECIFIC_LINUX),)
    ccflags-y += -DSPECIFIC_LINUX
    ccflags-y += -D$(SPECIFIC_LINUX)
  endif
endif

# Add compiler options and macros
ccflags-y += -I$(CURDIR)/sxe2vf
ccflags-y += -I$(CURDIR)/sxe2vf/com_parse
ccflags-y += -I$(CURDIR)/common/mbx
ccflags-y += -I$(CURDIR)/common/sxe2vf
ccflags-y += -I$(CURDIR)/common/ioctl
ccflags-y += -I$(CURDIR)/common/sxe2flow
ccflags-y += -I$(CURDIR)/include
ccflags-y += -I$(CURDIR)/base/compat
ccflags-y += -I$(CURDIR)/base/auxiliary
ccflags-y += -I$(CURDIR)/base/log
ccflags-y += -I$(CURDIR)/base/trace
ccflags-y += -I$(CURDIR)/base/cdev
ccflags-y += -I$(CURDIR)/base/ioctl
ccflags-y += -DSXE2_HOST_DRIVER
ccflags-y += -DSXE2_MBX_SUPPORT
ccflags-y += -DCUR_DIR=$(CURDIR)
# ccflags-y += -DSXE2_DRIVER_TRACE
ccflags-y += -DSXE2_CFG_RELEASE

# Default FPGA platform support, compatible with different hardware platforms
ifeq ($(MT_BUILDMODE),asic)
	ccflags-y += -DSXE2_HARDWARE_ASIC
else #ifeq ($(MT_BUILDMODE),emu)
	ccflags-y += -DSXE2_HARDWARE_EMU
endif

else # KERNELRELEASE
# Path to the kernel source tree
KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(info "HWVERSION = $(VER)" )
	@$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	@rm -rf *.o *.d *.ko Module.* modules.* *.mod* .*.d .*.cmd .tmp_versions *readme.txt
	@rm -rf ./sxe2vf/*.o ./sxe2vf/.*.cmd
	@rm -rf ./base/log/*.o ./common/mbx/*.o ./common/sxe2vf/*.o ./base/auxiliary/*.o ./base/compat/*.o

endif # KERNELRELEASE
