/* SPDX-License-Identifier: GPL-2.0*/
/* Huawei HiNIC PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef OSSL_KNL_LINUX_H_
#define OSSL_KNL_LINUX_H_

#include <linux/string.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <net/checksum.h>
#include <net/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/udp.h>
#include <linux/highmem.h>

#ifndef SUPPORTED_100000baseKR4_Full
#define SUPPORTED_100000baseKR4_Full	0
#define ADVERTISED_100000baseKR4_Full	0
#endif
#ifndef SUPPORTED_100000baseCR4_Full
#define SUPPORTED_100000baseCR4_Full	0
#define ADVERTISED_100000baseCR4_Full	0
#endif

#ifndef SUPPORTED_40000baseKR4_Full
#define SUPPORTED_40000baseKR4_Full	0
#define ADVERTISED_40000baseKR4_Full	0
#endif
#ifndef SUPPORTED_40000baseCR4_Full
#define SUPPORTED_40000baseCR4_Full	0
#define ADVERTISED_40000baseCR4_Full	0
#endif

#ifndef SUPPORTED_25000baseKR_Full
#define	SUPPORTED_25000baseKR_Full	0
#define ADVERTISED_25000baseKR_Full	0
#endif
#ifndef SUPPORTED_25000baseCR_Full
#define SUPPORTED_25000baseCR_Full	0
#define	ADVERTISED_25000baseCR_Full	0
#endif

int local_atoi(const char *name);

#define nicif_err(priv, type, dev, fmt, args...)		\
	netif_level(err, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_warn(priv, type, dev, fmt, args...)		\
	netif_level(warn, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_notice(priv, type, dev, fmt, args...)		\
	netif_level(notice, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_info(priv, type, dev, fmt, args...)		\
	netif_level(info, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_dbg(priv, type, dev, fmt, args...)		\
	netif_level(dbg, priv, type, dev, "[NIC]"fmt, ##args)

#define tasklet_state(tasklet) ((tasklet)->state)

#endif
