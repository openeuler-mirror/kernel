# SPDX-License-Identifier: GPL-2.0
CONFIG_MODULE_SIG=n

# Makefile path
MAKEPATH := $(abspath $(lastword $(MAKEFILE_LIST)))
# current path
CURDIR :=$(shell dirname $(MAKEPATH))

ifneq ($(KERNELRELEASE),)
# compile
CONFIG_SXE_VF ?= m
obj-$(CONFIG_SXE_VF) += sxevf.o
sxevf-objs += base/log/sxe_log.o \
        base/trace/sxe_trace.o \
        sxevf/sxevf_csum.o \
        sxevf/sxevf_debug.o \
        sxevf/sxevf_ethtool.o \
        sxevf/sxevf_hw.o \
        sxevf/sxevf_ipsec.o \
        sxevf/sxevf_irq.o \
        sxevf/sxevf_main.o \
        sxevf/sxevf_monitor.o \
        sxevf/sxevf_msg.o \
        sxevf/sxevf_netdev.o \
        sxevf/sxevf_ring.o \
        sxevf/sxevf_rx_proc.o \
        sxevf/sxevf_tx_proc.o \
        sxevf/sxevf_xdp.o

# add compile ccflags and macro
ccflags-y += -Werror
ccflags-y += -I$(CURDIR)/sxevf
ccflags-y += -I$(CURDIR)/include/sxe
ccflags-y += -I$(CURDIR)/include
ccflags-y += -I$(CURDIR)/base/compat
ccflags-y += -I$(CURDIR)/base/trace
ccflags-y += -I$(CURDIR)/base/log
ccflags-y += -DSXE_HOST_DRIVER
ccflags-y += -DSXE_DRIVER_RELEASE
ccflags-$(CONFIG_DCB) += -DSXE_DCB_CONFIGURE

os_type = $(shell sed -n '/^ID=/p' /etc/os-release | awk -F '=' '{print $$2}' | sed 's/\"//g' | sed 's/ID=//g')
ifeq (${os_type}, opencloudos)
ccflags-y += -DOPENCLOUDOS
endif

# get linux kernel version code
ifneq ($(wildcard $(CURDIR)/vercode_build.sh),)
  KER_DIR=$(srctree)
  SPECIFIC_LINUX=$(shell bash $(CURDIR)/vercode_build.sh $(KER_DIR))
  ifneq ($(SPECIFIC_LINUX),)
    ccflags-y += -DSPECIFIC_LINUX
    ccflags-y += -D$(SPECIFIC_LINUX)
  endif
endif

else # KERNELRELEASE
# kernel build path
KDIR := /lib/modules/$(shell uname -r)/build
all:
	@$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	@rm -rf *.o *.d *.ko Module.* modules.* *.mod* .*.d .*.cmd .tmp_versions *readme.txt
	@rm -rf ./sxevf/*.o ./sxevf/.*.cmd
	@rm -rf ./base/log/*.o ./base/trace/*.o

endif # KERNELRELEASE
