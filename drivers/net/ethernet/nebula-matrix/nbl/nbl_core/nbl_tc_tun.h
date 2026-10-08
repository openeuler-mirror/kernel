/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NBL_TC_TUN_H__
#define __NBL_TC_TUN_H__

#include <net/ip_tunnels.h>
#include "nbl_include.h"
#include "nbl_core.h"
#include "nbl_resource.h"

#define NBL_FLOW_IPV4 4
#define NBL_FLOW_IPV6 6
#define NBL_FLOW_IHL 5
#define NBL_FLOW_DF 0x40

#define NBL_FLOW_L4_CK_NO_MODIFY			7
#define NBL_FLOW_IPV4_LEN_OFFSET			2
#define NBL_FLOW_IPV6_LEN_OFFSET			4
#define NBL_FLOW_UDP_LEN_OFFSET				4
#define NBL_FLOW_VNI_OFFSET				4

#define NBL_FLOW_L4_CK_MODE_0				0
#define NBL_FLOW_L4_CK_MODE_1				1

enum {
	NBL_TC_TUNNEL_TYPE_UNKNOWN,
	NBL_TC_TUNNEL_TYPE_VXLAN,
	NBL_TC_TUNNEL_TYPE_GENEVE,
	NBL_TC_TUNNEL_TYPE_GRE,
};

struct nbl_decap_key {
	struct ethhdr key;
};

struct nbl_tc_tunnel {
	u8 tunnel_type;
	int (*generate_tunnel_hdr)(char buf[], u8 *ip_proto,
				   const struct ip_tunnel_key *tun_key);
	int (*get_tun_hlen)(void);
};

extern struct nbl_tc_tunnel vxlan_tunnel;

int nbl_tc_tun_parse_encap_info(struct nbl_rule_action *rule_act,
				struct nbl_tc_flow_param *param,
				struct net_device *encap_mirred_dev);

#endif /* end of __NBL_TC_TUN_H__ */
