/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_MIX_H
#define ROCE_MIX_H

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <linux/mutex.h>
#include <linux/inetdevice.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/module.h>

#include <rdma/ib_addr.h>
#include <rdma/ib_verbs.h>

#include "roce.h"

#define IB_DEVICE_LOCAL_DMA_LKEY	(1 << 15)

#define ROCE_HW_VER 0ULL
#define ROCE_FW_VER_0 1ULL
#define ROCE_FW_VER_1 4ULL
#define ROCE_FW_VER_2 0ULL
#define ROCE_FW_VER_3 0ULL
#define ROCE_FW_VER ((ROCE_FW_VER_0 << 32) | (ROCE_FW_VER_1 << 16) | \
	(ROCE_FW_VER_2 << 8) | ROCE_FW_VER_3)

#define RESOLVE_IP_TIME_OUT 1000
#define ROCE_GID_HIGHEST_BYTE 15
#define ROCE_FW_VERSION_LEN 4
#define ROCE_DEFAULT_VLAN_ID 0xFFFF
#define ROCE_RAH_TC_SHIFT 2
#define ROCE_RAH_DMAC_H16_SHIFT 8
#define ROCE_RAH_DMAC_L32_START 2

#define ROCE3_DCB_PCP 0
#define ROCE3_DCB_DSCP 1

#define ROCE3_DSCP_IDX 2 // dscp begin from bit 2 in traffic_class

#define IB_DEVICE_NODE_DESC_MAX 64

#define MEND_CAP_DEVIDE 2   // to avoid chip cache problem
#define ROCE_PORT_NUM_2 2
#define ROCE_25G_PORT_SPEED 25

#define ROCE_GID_IP_IDX 3

enum {
	USR_MMAP_DB_OFFSET = 0,
	USR_MMAP_DWQE_OFFSET,
	USR_MMAP_DFX_OFFSET,
	USR_MMAP_DBAR3_OFFSET
};

enum roce_port_state_e {
	ROCE_PORT_PHYS_STATE_NO_CHANGE = 0,
	ROCE_PORT_PHYS_STATE_SLEEP,
	ROCE_PORT_PHYS_STATE_POLLING,
	ROCE_PORT_PHYS_STATE_DISABLED = 3,
	ROCE_PORT_PHYS_STATE_PORTCONFTRAIN,
	ROCE_PORT_PHYS_STATE_LINKUP = 5,
	ROCE_PORT_PHYS_STATE_LINKERRRECOVER,
	ROCE_PORT_PHYS_STATE_PHYTEST
};

enum ROCE_MBOX_CMD {
	ROCE_MBOX_CMD_SEND_MAIL_BOX,
	ROCE_MBOX_CMD_MAX
};

struct roce3_priv_ah {
	/* DW0 */
	union {
		struct {
#if (BYTE_ORDER != BIG_ENDIAN)
			u32 pd : 18;
			u32 rsvd0 : 6;
			u32 stat_rate : 4;
			u32 wqe_cos : 3;
			u32 fl : 1; /* forcelock flag, it is used in multicast communication */
#else
			u32 f1 : 1;
			u32 wqe_cos : 3;
			u32 stat_rate : 4;
			u32 rsvd0 : 6;
			u32 pd : 18;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if (BYTE_ORDER != BIG_ENDIAN)
			u32 hoplimit : 8;
			u32 sgid_index : 7;
			u32 resv : 1;
			u32 port : 4;
			u32 rsvd1 : 4;
			u32 tclass : 8;
#else
			u32 tclass : 8;
			u32 rsvd1 : 4;
			u32 port : 4;
			u32 resv : 1;
			u32 sgid_index : 7;
			u32 hoplimit : 8;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if (BYTE_ORDER != BIG_ENDIAN)
			u32 flow_label : 20;
			u32 smac_index : 10;
			u32 rsvd : 2;
#else
			u32 rsvd : 2;
			u32 smac_index : 10;
			u32 flow_label : 20;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3~6 */
	u8 dgid[16];

	/* DW7 */
	union {
		struct {
#if (BYTE_ORDER != BIG_ENDIAN)
			u32 dmac_h16 : 16;
			u32 vlan_id : 12;
			u32 rsvd : 1;
			u32 vlan_pri : 3;
#else
			u32 vlan_pri : 3;
			u32 rsvd : 1;
			u32 vlan_id : 12;
			u32 dmac_h16 : 16;
#endif
		} bs;
		u32 value;
	} dw7;

	/* DW8 */
	u32 dmac_l32;
};

struct roce3_ah {
	struct ib_ah ibah;
	struct roce3_priv_ah priv_ah;
};

union gid_addr {
	struct sockaddr _sockaddr;
	struct sockaddr_in _sockaddr_in;
	struct sockaddr_in6 _sockaddr_in6;
};

struct mailbox_header {
	u32 dest_host_id;
	u32 dest_global_function_id;
};

struct roce3_mail_box_buffer {
	struct mailbox_header header;
	u32 data[0]; //lint !e1501
};

struct roce3_resolve_cb_context {
	struct completion comp;
	int status;
};

struct roce3_get_cos_inbuf {
	u8 sl;
	u8 sgid_index;
	u8 port_num;
	u8 traffic_class;
};

/* Find struct roce3_ah through ibah */
static inline struct roce3_ah *to_roce3_ah(const struct ib_ah *ibah)
{
	return container_of(ibah, struct roce3_ah, ibah);
}

int roce3_resolve_grh(struct roce3_device *rdev, struct rdma_ah_attr *ah_attr,
	u16 *vlan_id, struct ib_udata *udata);
int roce3_get_dcb_cfg_cos(struct roce3_device *rdev, struct roce3_get_cos_inbuf *inbuf, u8 *cos);


#endif /* ROCE_MIX_H */
