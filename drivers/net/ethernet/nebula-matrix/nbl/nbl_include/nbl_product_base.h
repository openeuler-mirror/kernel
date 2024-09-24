/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_PRODUCT_BASE_H_
#define _NBL_DEF_PRODUCT_BASE_H_

#include "nbl_include.h"

struct nbl_product_base_ops {
	int (*phy_init)(void *p, struct nbl_init_param *param);
	void (*phy_remove)(void *p);
	int (*res_init)(void *p, struct nbl_init_param *param);
	void (*res_remove)(void *p);
	int (*chan_init)(void *p, struct nbl_init_param *param);
	void (*chan_remove)(void *p);
};

#endif
