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

#if __has_attribute(__fallthrough__)
# ifndef fallthrough
# define fallthrough __attribute__((__fallthrough__))
#endif
#else
# ifndef fallthrough
# define fallthrough do {} while (0)
#endif
#endif
#else
# ifndef fallthrough
# define fallthrough do {} while (0)
#endif

struct nbl_device;
void nbl_set_uverbs_cmd_mask_common(struct nbl_device *nbl_dev);

#endif /* NBL_ADAPT_H */
