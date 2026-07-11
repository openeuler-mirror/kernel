/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZXDH_MSG_CHAN_IOCTL_H_
#define _ZXDH_MSG_CHAN_IOCTL_H_

#include "zf_mpf.h"

#define DEVICE_NAME "bar_ioctl_dev"
#define BAR_CHAN_SIZE (1024 * 2)
#define BAR_CHAN_PLOAD_SIZE (BAR_CHAN_SIZE - 12)
#define BAR_REV_HDR_LEN (4)
#define ZXDH_PF_DEV_NUM (40)

#define PCI_QUERY_TYPE_SINGLE (1)
#define PCI_QUERY_TYPE_ALL (2)

#define MSG_LIST_MAX_LEN (10)

enum {
	IOCTRL_OK,
	IOCTRL_ERR_MALLOC,
	IOCTRL_ERR_MSG_GET,
	IOCTRL_ERR_COPY_FROM_USR,
	IOCTRL_ERR_SEND_LENGTH_EXCCED,
	IOCTRL_ERR_SEND_EVENTID_EXCCED,
	IOCTRL_ERR_RECV_NOT_REGISTER,
	IOCTRL_ERR_RECV_REPEAT_REGISTER,
	IOCTRL_ERR_SEND_EXCEED_QUEUE_SIZE,
};

struct zxdh_ioctl_send_in {
	u16 pload_len;
	u16 src;
	u16 dst;
	u16 event_id;
};

struct zxdh_ioctl_send_out {
	int ioctl_state;
	int bar_state;
};

struct zxdh_ioctl_recv_in {
	u16 event_id;
	u16 rsv1;
	u32 rsv2;
};

struct zxdh_ioctl_recv_out {
	u16 event_id;
	u16 state;
	u32 rsv2;
};

struct normal_msg_entity {
	union ioctl_ctrl_hdr {
		struct zxdh_ioctl_send_in send_hdr_in;
		struct zxdh_ioctl_send_out send_hdr_out;
		struct zxdh_ioctl_recv_in recv_hdr_in;
		struct zxdh_ioctl_recv_out recv_hdr_out; //recv
		u8 std[8];
	} hdr;
	u8 pload[BAR_CHAN_PLOAD_SIZE];
};

struct zxdh_mpf_pci_res_item {
	u16 device_id;
	u16 pcie_id;
	u16 bdf;
	u8 link_state;
	u8 dev_type;
	u16 total_vfs;
	u16 initial_vfs;
	u16 num_vfs;
	u8 vf_stride;
	u8 first_vf_offset;
	u8 pad[8];
};

struct zxdh_mpf_pci_res_list {
	u16 num;
	u16 verno;
	int res;
	struct zxdh_mpf_pci_res_item pci_res_lis[ZXDH_PF_DEV_NUM];
};

struct zxdh_mpf_query_pci_res_msg {
	u16 pcie_id;
	u8 dev_type;
	u8 pad[5];
	struct zxdh_mpf_pci_res_list reply;
};

struct zxdh_mpf_query_bar_msg {
	int ioctl_state;
	int bar_state;
	struct zxdh_mpf_query_pci_res_msg pci_res_msg;
};

struct zxdh_pci_query_hdr {
	u16 mode;
	u16 pcie_id;
};

int zxdh_bar_ioctl_msg_mdl_init(struct dh_core_dev *core_dev);
void zxdh_bar_ioctl_msg_mdl_exit(struct dh_core_dev *core_dev);

#endif /* _ZXDH_MSG_CHAN_IOCTL_H_  */
