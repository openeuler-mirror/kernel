/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_IP_H__
#define __UNIC_IP_H__

#include "unic_dev.h"
#include "unic_comm_addr.h"

#define UNIC_RTATTR_PACK_LENGTH		256
#define UNIC_IP_TABLE_SIZE		128
#define UNIC_CTRLQ_IP_REQ_SIZE		4
#define UNIC_IP_FOURTH_PART		3
#define UNIC_MASKED_FORMAT_IP_LEN	40

enum unic_ctrlq_ip_event {
	UNIC_CTRLQ_ADD_IP,
	UNIC_CTRLQ_DEL_IP,
};

struct unic_netlink_ip_req {
	struct nlmsghdr		nh;
	struct ifaddrmsg	info;
	char			attrbuf[UNIC_RTATTR_PACK_LENGTH];
};

struct unic_ctrlq_query_ip_req {
	__le16	ip_index;
	u8	resv[18];
};

struct unic_ip_info {
	__le32	ip_addr[UNIC_CTRLQ_IP_REQ_SIZE];
	__le16	ip_mask;
	u8	resv[2];
};

struct unic_ctrlq_query_ip_resp {
	__le16	ip_index;
	u8	get_count;
	u8	resv;
	struct unic_ip_info ip_info[UNIC_CTRLQ_IP_REQ_SIZE];
};

struct unic_ctrlq_ip_notify_req {
	__le16	ip_cmd;
	__le16	ip_mask;
	__le32	ip_addr[UNIC_CTRLQ_IP_REQ_SIZE];
};

struct unic_ctrlq_ip_notify_resp {
	u8	resv[20];
};

struct unic_stack_ip_info {
	u16	ip_cmd;
	u16	ip_mask;
	__be32	ip_addr[UNIC_CTRLQ_IP_REQ_SIZE];
};

static inline void unic_format_masked_ip_addr(char *format_masked_ip_addr,
					      const u8 *ip_addr)
{
#define IP_START_BYTE	12

	snprintf(format_masked_ip_addr, UNIC_MASKED_FORMAT_IP_LEN,
		 "****:****:****:****:****:****:%02x%02x:%02x%02x",
		 ip_addr[IP_START_BYTE], ip_addr[IP_START_BYTE + 1],
		 ip_addr[IP_START_BYTE + 2], ip_addr[IP_START_BYTE + 3]);
}

void unic_sync_ip_table(struct unic_dev *unic_dev);
int unic_handle_notify_ip_event(struct auxiliary_device *adev, u8 service_ver,
				void *data, u16 len, u16 seq);
int unic_query_ip_addr(struct auxiliary_device *adev);
void unic_uninit_ip_table(struct unic_dev *unic_dev);
int unic_add_ip_addr(struct unic_dev *unic_dev, struct sockaddr *addr,
		     u16 ip_mask);
int unic_rm_ip_addr(struct unic_dev *unic_dev, struct sockaddr *addr,
		    u16 ip_mask);

#endif /* __UNIC_IP_H__ */
