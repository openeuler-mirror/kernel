/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: cis uvb interface header
 * Author: zhangrui
 * Create: 2025-04-18
 */

#ifndef CIS_UVB_INTERFACE_H
#define CIS_UVB_INTERFACE_H
#include <linux/firmware/uvb/cis.h>
#include <linux/list.h>

/**
 * struct cis_group - call id service group
 * @owner_user_id:    user id that indicates which component owns the cia[] array
 * @cis_count:        number of cia in the group
 * @cia:              array of call id attribute
 * @forwarder_id      forwarder id
 */
struct cis_group {
	u32 owner_user_id;
	u32 cis_count;
	u8 usage;
	u8 index;
	u32 forwarder_id;
	u32 call_id[];
};

/**
 * struct cis_ub - call id service ub struct
 * @usage:            usage for channel
 * @index:            index for uvb
 * @forwarder_id      forwarder id
 */
struct cis_ub {
	u8 usage;
	u8 index;
	u32 forwarder_id;
};

/**
 * struct cis_group_node - node for dynamic CIS group management
 * @owner:    0=ODF source, non-zero=sender_id from Notify
 * @group:    pointer to cis_group
 * @list:     linked list node
 */
struct cis_group_node {
	u32 owner;
	struct cis_group *group;
	struct list_head list;
};

/**
 * struct cis_info - call id service information
 * @group_count:    number of cis group
 * @group_list:     linked list of cis_group_node
 */
struct cis_info {
	u32 group_count;
	u32 reserved;
	struct cis_ub ub;
	struct list_head group_list;
};


extern struct cis_info *g_cis_info;
extern rwlock_t g_cis_group_lock;      /* protect g_cis_info->group_list / group_count */

#define UVB_OUTPUT_SIZE_NULL        0xFFFFFFFF
#define UVB_WINDOW_COUNT_MAX        0xFF

/**
 * struct uvb_window
 * @version:              uvb window version
 * @message_id:           call id
 * @sender_id:            user id of caller
 * @receiver_id:          user id of callee
 * @input_data_address:   input data physical address
 * @input_date_size:      input data size
 * @input_data_checksum:  input data checksum, not used yet
 * @output_data_address:  output data physical address
 * @output_data_size:     output data size
 * @output_data_checksum: output data checksum, not used yet
 * @returned_status:      UVB window index, if usage indicates UVB
 */
struct uvb_window {
	u8 version;
	u8 reserved1[3];
	u32 message_id;
	u32 sender_id;
	u32 receiver_id;
	u64 input_data_address;
	u32 input_data_size;
	u32 input_data_checksum;
	u64 output_data_address;
	u32 output_data_size;
	u32 output_data_checksum;
	u32 returned_status;
	u8 reserved2[8];
	u32 forwarder_id;
};
struct uvb_window_description {
	u64 obtain;      /* This address is used to obtain this window */
	u64 address;     /* The address of uvb window */
	u64 buffer;      /* Buffer address of this window, 0 if no buffer */
	u32 size;        /* The size of buffer, same for all windows in one uvb */
	u32 reserved;
};

struct uvb {
	u8 window_count;
	bool secure;
	u16 delay;   /* us */
	u32 reserved;
	struct uvb_window_description wd[];
};

struct uvb_info {
	u8 uvb_count;
	u8 reserved[7];
	struct uvb *uvbs[];
};

extern struct uvb_info *g_uvb_info;

#endif
