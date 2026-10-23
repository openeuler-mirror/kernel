/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 nebula-matrix Limited.
 * Author: Rocky Xie <rocky.xie@nebula-matrix.com>
 */

#ifndef _NBL_MACSEC_H
#define _NBL_MACSEC_H

#include "nbl_service.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/if_vlan.h>
#include <uapi/linux/if_link.h>
#if IS_ENABLED(CONFIG_MACSEC)
#include <uapi/linux/if_macsec.h>
#endif

void nbl_serv_setup_macsec_ops(struct nbl_service_ops *serv_ops);

#endif /*_NBL_MACSEC_H*/
