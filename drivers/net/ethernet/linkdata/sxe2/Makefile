# SPDX-License-Identifier: GPL-2.0
CONFIG_MODULE_SIG=n

#当前目录下的Makefile路径
MAKEPATH := $(abspath $(lastword $(MAKEFILE_LIST)))
#当前路径
CURDIR :=$(shell dirname $(MAKEPATH))
KDIR := /lib/modules/$(shell uname -r)/build
MT_BUILDMODE?=asic

ifneq ($(KERNELRELEASE),)
#编译
CONFIG_SXE2 ?= m
obj-$(CONFIG_SXE2) += sxe2.o
sxe2-objs += $(patsubst %.c, sxe2pf/%.o, $(notdir $(wildcard $(CURDIR)/sxe2pf/*.c)))
sxe2-objs += $(patsubst %.c, sxe2pf/com_parse/%.o, $(notdir $(wildcard $(CURDIR)/sxe2pf/com_parse/*.c)))
sxe2-objs += $(patsubst %.c, common/mbx/%.o, $(notdir $(wildcard $(CURDIR)/common/mbx/*.c)))
sxe2-objs += $(patsubst %.c, common/sxe2pf/%.o, $(notdir $(wildcard $(CURDIR)/common/sxe2pf/*.c)))
sxe2-objs += $(patsubst %.c, base/log/%.o, $(notdir $(wildcard $(CURDIR)/base/log/*.c)))
sxe2-objs += $(patsubst %.c, base/compat/%.o, $(notdir $(wildcard $(CURDIR)/base/compat/*.c)))
sxe2-objs += $(patsubst %.c, base/ioctl/%.o, $(notdir $(wildcard $(CURDIR)/base/ioctl/*.c)))

# 生成 linux kernel version code
ifneq ($(wildcard $(CURDIR)/vercode_build.sh),)
  KER_DIR=$(srctree)
  SPECIFIC_LINUX=$(shell bash $(CURDIR)/vercode_build.sh $(KER_DIR))
  ifneq ($(SPECIFIC_LINUX),)
    ccflags-y += -DSPECIFIC_LINUX
    ccflags-y += -D$(SPECIFIC_LINUX)
  endif
endif

#是否编译辅助设备
ifeq ($(SPECIFIC_LINUX),BCLINUX_21_10U4)
obj-$(CONFIG_SXE2) += sxe2_auxiliary.o
sxe2_auxiliary-objs += $(patsubst %.c, base/auxiliary/%.o, $(notdir $(wildcard $(CURDIR)/base/auxiliary/*.c)))
else
CHECK_AUX_BUS ?= $(CURDIR)/check_aux_support.sh
NEED_AUX_BUS := $(shell bash ${CHECK_AUX_BUS} --ksrc="$(KDIR)" >/dev/null 2>&1; echo $$?)
$(info "NEED_AUX_BUS = $(NEED_AUX_BUS)")
ifeq ($(NEED_AUX_BUS), 2)
obj-$(CONFIG_SXE2) += sxe2_auxiliary.o
sxe2_auxiliary-objs += $(patsubst %.c, base/auxiliary/%.o, $(notdir $(wildcard $(CURDIR)/base/auxiliary/*.c)))
endif
endif

#添加编译选项和编译宏
ccflags-y += -Werror -Wmaybe-uninitialized -frecord-gcc-switches
ccflags-y += -I$(CURDIR)/sxe2pf
ccflags-y += -I$(CURDIR)/sxe2pf/com_parse
ccflags-y += -I$(CURDIR)/common/mbx
ccflags-y += -I$(CURDIR)/common/sxe2pf
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

#默认支持fpga平台,支持不同的硬件平台
ifeq ($(MT_BUILDMODE),asic)
	ccflags-y += -DSXE2_HARDWARE_ASIC
else #ifeq ($(MT_BUILDMODE),emu)
	ccflags-y += -DSXE2_HARDWARE_EMU
endif

else # KERNELRELEASE
#内核树路径
KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(info "HWVERSION = $(VER)" )
	@$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	@rm -rf *.o *.d *.ko Module.* modules.* *.mod* .*.d .*.cmd .tmp_versions *readme.txt
	@rm -rf ./sxe2pf/*.o ./sxe2pf/.*.cmd
	@rm -rf ./base/log/*.o ./common/mbx/*.o ./common/sxe2pf/*.o ./base/auxiliary/*.o ./base/compat/*.o

endif # KERNELRELEASE
