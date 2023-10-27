# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
# All rights reserved.

ccflags-y := -I $(srctree)/drivers/net/ethernet/yunsilicon/xsc/
ccflags-y += -Wno-implicit-fallthrough

obj-$(CONFIG_INFINIBAND_XSC)	+= xsc_ib.o

xsc_ib-y := main.o xsc_rdma_ctrl.o cq.o qp.o mem.o mr.o ah.o mad.o counters.o devx.o global.o private_dev.o ib_umem_ex.o rtt.o
xsc_ib-$(CONFIG_MLX_PEER_SUPPORT) := peer_mem.o
