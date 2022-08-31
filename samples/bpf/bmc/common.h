/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: common header for both user prog and bpf kernel prog
 */
#ifndef __REDIS_BMC_COMMON_H__
#define __REDIS_BMC_COMMON_H__

#define REDIS_GET_PROG_INDEX	0
#define REDIS_SET_PROG_INDEX	1

struct redis_bmc_stat {
	__u64 total_get_requests;
	__u64 hit_get_requests;
	__u64 drop_get_requests;
	__u64 total_set_requests;
	__u64 hit_set_requests;
	__u64 drop_set_requests;
};

#endif
