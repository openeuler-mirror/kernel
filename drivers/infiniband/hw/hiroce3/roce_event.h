/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_EVENT_H
#define ROCE_EVENT_H

#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/bonding.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_addr.h>

#include "roce.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_qp.h"
#include "roce_cmd.h"

#define ROCE_M_DELAY 100
#define API_FORMAT_ERROR 0x2
#define UNKNOWN_RESERVED_ERROR1 0xe
#define QPC_LOOKUP_ERR_VALUE 0x300d00016

int to_unknown_event_str_index(u8 event_type, const u8 *val);

void roce3_handle_hotplug_arm_cq(struct roce3_device *rdev);
void roce3_kernel_hotplug_event_trigger(struct roce3_device *rdev);

#endif /* ROCE_EVENT_H */
