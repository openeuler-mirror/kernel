# SPDX-License-Identifier: GPL-2.0
CONFIG_MODULE_SIG=n

# Makefile path
MAKEPATH := $(abspath $(lastword $(MAKEFILE_LIST)))
# current path
CURDIR :=$(shell dirname $(MAKEPATH))

ifneq ($(KERNELRELEASE),)
# compile
CONFIG_SXE ?= m
obj-$(CONFIG_SXE) += sxe.o
sxe-objs += base/log/sxe_log.o \
        base/trace/sxe_trace.o \
        sxepf/sxe_xdp.o \
        sxepf/sxe_csum.o \
        sxepf/sxe_dcb.o \
        sxepf/sxe_dcb_nl.o \
        sxepf/sxe_debug.o \
        sxepf/sxe_debugfs.o \
        sxepf/sxe_ethtool.o \
        sxepf/sxe_filter.o \
        sxepf/sxe_host_cli.o \
        sxepf/sxe_host_hdc.o \
        sxepf/sxe_hw.o \
        sxepf/sxe_ipsec.o \
        sxepf/sxe_irq.o \
        sxepf/sxe_main.o \
        sxepf/sxe_monitor.o \
        sxepf/sxe_netdev.o \
        sxepf/sxe_pci.o \
        sxepf/sxe_phy.o \
        sxepf/sxe_ptp.o \
        sxepf/sxe_ring.o \
        sxepf/sxe_rx_proc.o \
        sxepf/sxe_sriov.o \
        sxepf/sxe_tx_proc.o

# add compile ccflags and macro
ccflags-y += -Werror
ccflags-y += -I$(CURDIR)/sxepf
ccflags-y += -I$(CURDIR)/include/sxe
ccflags-y += -I$(CURDIR)/include
ccflags-y += -I$(CURDIR)/base/compat
ccflags-y += -I$(CURDIR)/base/trace
ccflags-y += -I$(CURDIR)/base/log
ccflags-y += -DSXE_HOST_DRIVER
ccflags-y += -DSXE_DRIVER_RELEASE
ccflags-$(CONFIG_DCB) += -DSXE_DCB_CONFIGURE

ifeq ($(CONFIG_SXE), y)
    ifeq ($(CONFIG_DCA), y)
        ccflags-y += -DSXE_TPH_CONFIGURE
    endif
else
    ifneq ($(CONFIG_DCA), )
        ccflags-y += -DSXE_TPH_CONFIGURE
    endif
endif

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
	@rm -rf ./sxepf/*.o ./sxepf/.*.cmd
	@rm -rf ./base/log/*.o ./base/trace/*.o

endif # KERNELRELEASE
