// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>

#include "rnpvf.h"

#define to_net_device(n) container_of(n, struct net_device, dev)

int rnpvf_sysfs_init(struct net_device *ndev)
{
	return 0;
}

void rnpvf_sysfs_exit(struct net_device *ndev)
{
}
