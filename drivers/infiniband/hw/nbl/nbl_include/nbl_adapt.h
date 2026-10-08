/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef NBL_ADAPT_H
#define NBL_ADAPT_H

#include "nbl_compat.h"

#include "linux_adapt.h"

#define set_max_sge(props, rf) do { \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_sges); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_sges); \
	} while (0)

#endif /* NBL_ADAPT_H */
