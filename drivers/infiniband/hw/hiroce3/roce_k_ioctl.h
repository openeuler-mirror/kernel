/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_K_IOCTL_H
#define ROCE_K_IOCTL_H

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>

#define ROCE_IOCTL_MAGIC 'R'
#define ROCE_CMD_QUERY_DCB _IO(ROCE_IOCTL_MAGIC, 0)
#define ROCE_CMD_CREATE_AH _IO(ROCE_IOCTL_MAGIC, 1)

#define ROCE_CMD_QUERY_QP_TX_PORT _IO(ROCE_IOCTL_MAGIC, 3)
#define ROCE_CMD_SET_QP_TX_PORT _IO(ROCE_IOCTL_MAGIC, 4)
#define ROCE_CMD_QUERY_QP_RX_PORT _IO(ROCE_IOCTL_MAGIC, 5)
#define ROCE_CMD_QUERY_BOND_PORT_INFO _IO(ROCE_IOCTL_MAGIC, 6)
#define ROCE_CMD_SET_QP_UDP_SRC_PORT _IO(ROCE_IOCTL_MAGIC, 7)
#define ROCE_CMD_QUERY_QP_UDP_SRC_PORT _IO(ROCE_IOCTL_MAGIC, 8)
#define ROCE_CMD_QUERY_NEXT_WQE_IDX _IO(ROCE_IOCTL_MAGIC, 9)

#define ROCE_CMD_MAX _IO(ROCE_IOCTL_MAGIC, 10)

#ifdef ROCE_EXTEND
#define HW_ROCE_EXT_CMD_SET_QP_ATTR _IO(ROCE_IOCTL_MAGIC, 11)
#define HW_ROCE_EXT_CMD_CREATE_SQPC _IO(ROCE_IOCTL_MAGIC, 12)
#endif

// roce3_ioctrl_version
#define VERSION_LEN				 (20)
#define HW_ROCE_CMD_VERSION		 _IO(ROCE_IOCTL_MAGIC, 20)
// reserved op code
#define HW_ROCE_CMD_RESERVED_1	  _IO(ROCE_IOCTL_MAGIC, 21)
#define HW_ROCE_CMD_RESERVED_2	  _IO(ROCE_IOCTL_MAGIC, 22)
#define HW_ROCE_CMD_RESERVED_3	  _IO(ROCE_IOCTL_MAGIC, 23)
#define HW_ROCE_CMD_RESERVED_4	  _IO(ROCE_IOCTL_MAGIC, 24)
#define HW_ROCE_CMD_RESERVED_5	  _IO(ROCE_IOCTL_MAGIC, 25)
#define HW_ROCE_CMD_RESERVED_6	  _IO(ROCE_IOCTL_MAGIC, 26)

#define ROCE_DEV_NAME_MAX 64

union roce3_query_dcb_buf {
	struct roce3_query_dcb_cmd {
		u8 sl;
		u8 sgid_idx;
		u8 port;
		u8 traffic_class; // dscp
		u8 dscp_type;
		u8 rsvd[3];
	} cmd;

	struct roce3_query_dcb_resp {
		u8 cos;
		u8 rsvd[7];
	} resp;
};

union roce3_create_ah_buf {
	struct roce3_create_ah_cmd {
		struct ib_uverbs_ah_attr attr;
	} cmd;

	struct roce3_create_ah_resp {
		u8 dmac[ETH_ALEN];
		u16 vlan_id;
	} resp;
};

struct roce3_qp_port_buf {
	u32 qpn;
	u32 port;
};

struct roce3_bond_port_info_buf {
	int original_port_num;
	char original_port[8];
	int rsvd1;

	int alive_port_num;
	char alive_port[8];
	int rsvd2;
};

struct roce3_qp_udp_src_port_buf {
	u32 qpn;
	u32 udp_src_port;
};

#endif
