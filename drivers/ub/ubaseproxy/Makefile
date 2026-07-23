# SPDX-License-Identifier: GPL-2.0+
#
## Makefile for the Hisilicon ubaseproxy drivers.
#
##

ccflags-y += -I$(srctree)/$(src)

MODULE_NAME := ubaseproxy

UBASEPROXY_OBJS := ubaseproxy_main.o ubaseproxy_dev.o ubaseproxy_mbx.o \
	ubaseproxy_event.o ubaseproxy_jfc.o ubaseproxy_jfs.o \
	ubaseproxy_jfr.o ubaseproxy_jetty_grp.o ubaseproxy_ctx_mgt.o \
	ubaseproxy_debugfs.o ubaseproxy_rc.o ubaseproxy_eq.o \
	ubaseproxy_reset.o ubaseproxy_ctrlq.o

$(MODULE_NAME)-objs := $(UBASEPROXY_OBJS)
obj-m := ubaseproxy.o