/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NBL_TC_TUN_LEONIS_H__
#define __NBL_TC_TUN_LEONIS_H__

#include <net/ip_tunnels.h>
#include "nbl_include.h"
#include "nbl_core.h"
#include "nbl_resource.h"

int nbl_tc_tun_setup_ops(struct nbl_resource_ops *res_ops);
void nbl_tc_tun_remove_ops(struct nbl_resource_ops *res_ops);

int nbl_tc_tun_encap_del(void *priv, struct nbl_encap_key *key);

#endif /* end of __NBL_TC_TUN_H__ */
