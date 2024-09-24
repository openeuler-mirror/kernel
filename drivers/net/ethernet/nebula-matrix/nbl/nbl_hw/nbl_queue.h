/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_QUEUE_H_
#define _NBL_QUEUE_H_

#include "nbl_resource.h"

int nbl_queue_setup_ops_leonis(struct nbl_resource_ops *res_ops);
void nbl_queue_mgt_init_leonis(struct nbl_queue_mgt *queue_mgt);
void nbl_queue_mgt_init_bootis(struct nbl_queue_mgt *queue_mgt);

#endif
