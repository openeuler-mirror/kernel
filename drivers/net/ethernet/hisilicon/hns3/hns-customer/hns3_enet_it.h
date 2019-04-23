/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef __HNS3_ENET_IT_H
#define __HNS3_ENET_IT_H

typedef int (*hns3_priv_func)(struct net_device *, void *);
hns3_priv_func hns3_ioctl;

#define VERSION_NUMBER "$FULL_VERSION"

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#endif
