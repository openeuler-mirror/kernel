/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NBL_TC_TUN_DRACO_H__
#define __NBL_TC_TUN_DRACO_H__

#include <net/ip_tunnels.h>
#include "nbl_include.h"
#include "nbl_core.h"
#include "nbl_resource.h"

enum nbl_tnl_l3_templt_type {
	NBL_TNL_L3_IP4_TYPE,
	NBL_TNL_L3_IP6_TYPE,
};

int nbl_draco_tc_tun_create_header(void *priv, struct nbl_tc_tun_create_header_param *param);
int nbl_tc_tun_setup_ops_draco(struct nbl_resource_ops *res_ops);
void nbl_tc_tun_remove_ops_draco(struct nbl_resource_ops *res_ops);
int nbl_draco_tc_tun_encap_del(void *priv, struct nbl_encap_key *key);

#endif /* end of __NBL_TC_TUN_DRACO_H__ */
