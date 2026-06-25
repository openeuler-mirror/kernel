/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg dfx interfaces
 */

#ifndef UBAGG_DFX_H
#define UBAGG_DFX_H

#include <ub/urma/ubcore_types.h>

struct ubagg_device;

enum ubagg_show_res_type {
	UBAGG_SHOW_RES_JETTY = 0,
	UBAGG_SHOW_RES_JFS,
	UBAGG_SHOW_RES_JFR,
	UBAGG_SHOW_RES_JFC,
	UBAGG_SHOW_RES_SEG,
	UBAGG_SHOW_RES_MAX,
};

struct ubagg_show_res {
	struct ubcore_jetty_id jetty_id;
	enum ubagg_show_res_type res_type;
};

struct ubagg_cmd_v2p_res {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t type;
		uint32_t key;
		uint32_t key_cnt;
	} in;
	struct {
		uint64_t addr;
		uint32_t len;
		uint64_t save_ptr;
	} out;
};

int ubagg_query_v2p_res(struct ubagg_device *ubagg_dev,
			struct ubagg_cmd_v2p_res *arg);

#endif // UBAGG_DFX_H
