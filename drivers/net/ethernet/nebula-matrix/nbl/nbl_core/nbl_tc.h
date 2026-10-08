/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 nebula-matrix Limited.
 *
 */

#ifndef _NBL_TC_OFFLOAD_H
#define _NBL_TC_OFFLOAD_H

#include "nbl_service.h"

#define NBL_TC_MASK_FORWARD_OFT3(mask) ((mask) == 0xffffff)
#define NBL_TC_MASK_FORWARD_OFT2(mask) ((mask) == 0xffff)
#define NBL_TC_MASK_FORWARD_OFT1(mask) ((mask) == 0xff)
#define NBL_TC_MASK_FORWARD_OFT0(mask) ((mask) == 0)

#define NBL_TC_MASK_BACKWARD_OFT3(mask) ((mask) == 0xffffff00)
#define NBL_TC_MASK_BACKWARD_OFT2(mask) ((mask) == 0xffff0000)
#define NBL_TC_MASK_BACKWARD_OFT1(mask) ((mask) == 0xff000000)

int nbl_serv_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv);
int nbl_serv_indr_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv);

#endif
