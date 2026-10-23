// SPDX-License-Identifier: GPL-2.0
#include "nbl_resource.h"
#include "nbl_tc_tun_draco.h"
#include "nbl_tc_flow_draco.h"

static bool nbl_draco_tc_tun_encap_lookup(void *priv,
					  struct nbl_rule_action *rule_act,
					  struct nbl_tc_flow_param *param)
{
	return 0;
}

int nbl_draco_tc_tun_encap_del(void *priv, struct nbl_encap_key *key)
{
	return 0;
}

static int nbl_draco_tc_tun_encap_add(void *priv, struct nbl_rule_action *action)
{
	return 0;
}

static enum nbl_flow_vlan_type nbl_flow_get_vlan_type(u16 vlan)
{
	switch (vlan) {
	case ETH_P_8021Q:
		return NBL_FLOW_VLAN_TYPE_VLAN;
	case ETH_P_8021AD:
		return NBL_FLOW_VLAN_TYPE_QINQ;
	default:
		return NBL_FLOW_VLAN_TYPE_VLAN;
	}

	return NBL_FLOW_VLAN_TYPE_VLAN;
}

int nbl_draco_tc_tun_create_header(void *priv, struct nbl_tc_tun_create_header_param *param)
{
	struct nbl_rule_action *rule_act = param->rule_act;
	unsigned char *hw_dst = param->hw_dst;
	struct nbl_tc_tunnel_route_info *tun_route = param->tun_route;
	struct nbl_encap_key *key = param->key;
	u16 vlan_proto = 0;
	int idx = 0;
	struct nbl_flow_tnl_prof_node *prof_node =
				NBL_DRACO_GET_PROF_NODE_DATA(rule_act->draco_encap_buf);
	struct nbl_flow_tnl_vtep_node *vtep_node =
				NBL_DRACO_GET_VTEP_NODE_DATA(rule_act->draco_encap_buf);

	/* fill mac */
	for (idx = 0; idx < ETH_ALEN; ++idx) {
		prof_node->dmac[idx] = hw_dst[ETH_ALEN - idx - 1];
		vtep_node->smac[idx] = tun_route->out_dev->dev_addr[ETH_ALEN - idx - 1];
	}

	prof_node->otpid_sel = NBL_FLOW_VLAN_TYPE_VLAN;

	if (tun_route->vlan_num) {
		u16 vlan_tci;

		if (tun_route->vlan_num == 2) {
			vlan_tci = tun_route->ivlan_id | ((u16)tun_route->ivlan_pcp << 12);
			prof_node->iv_info = vlan_tci;
			vlan_proto = ntohs(vlan_dev_vlan_proto(tun_route->out_dev));
			prof_node->itpid_sel = nbl_flow_get_vlan_type(vlan_proto);

			vlan_tci = tun_route->ovlan_id | ((u16)tun_route->ovlan_pcp << 12);
			prof_node->ov_info = vlan_tci;
			vlan_proto = ntohs(vlan_dev_vlan_proto(tun_route->out_dev_parent));
			prof_node->otpid_sel = nbl_flow_get_vlan_type(vlan_proto);
		} else {
			vlan_tci = tun_route->ovlan_id | ((u16)tun_route->ovlan_pcp << 12);
			prof_node->ov_info = vlan_tci;
			vlan_proto = ntohs(vlan_dev_vlan_proto(tun_route->out_dev));
			prof_node->otpid_sel = nbl_flow_get_vlan_type(vlan_proto);
		}
		prof_node->vlan_num = tun_route->vlan_num;
	}

	/* fill ip */
	if (tun_route->is_ip6) {
		prof_node->ttl = tun_route->ttl;
		prof_node->dscp_inherit = 1;
		for (idx = 0; idx < NBL_IPV6_ADDR_LEN_AS_U8; ++idx) {
			prof_node->dip[idx] =
				tun_route->fl.fl6.daddr.s6_addr[NBL_IPV6_ADDR_LEN_AS_U8 - idx - 1];
			vtep_node->sip[idx] =
				tun_route->fl.fl6.saddr.s6_addr[NBL_IPV6_ADDR_LEN_AS_U8 - idx - 1];
		}
		prof_node->tnl_l3 = NBL_TNL_L3_IP6_TYPE;
		prof_node->flg = 2;
	} else {
		prof_node->ttl = tun_route->ttl;
		prof_node->dscp = key->ip_tun_key.tos;
		prof_node->dscp_inherit = 1;
		*(u32 *)(&prof_node->dip[0]) = cpu_to_be32(tun_route->fl.fl4.daddr);
		*(u32 *)(&vtep_node->sip[0]) = cpu_to_be32(tun_route->fl.fl4.saddr);
		prof_node->tnl_l3 = NBL_TNL_L3_IP4_TYPE;
		prof_node->id = 0;
		prof_node->flg = 2;
	}

	/* fill vni */
	rule_act->vni = be32_to_cpu(tunnel_id_to_key32(key->ip_tun_key.tun_id)) & 0xFFFFFF;
	rule_act->tnl_type = NBL_TNL_VXLAN_TYPE;
	prof_node->vx_data = cpu_to_be64(VXLAN_HF_VNI);
	prof_node->tnl_type = NBL_TNL_VXLAN_TYPE;

	nbl_debug(tun_route->common, NBL_DEBUG_FLOW, "draco create ipv%u tnl header ok, tun_route:vlan_num:%u, vni:0x%x, opri:%u, ovid:%u, ovlan_id:%u, ovlan_pcp:%u, otpid_sel:%u, ivlan_id:%u, ivlan_pcp:%u, itpid_sel:%u\n",
		  tun_route->is_ip6 ? 6 : 4, tun_route->vlan_num, rule_act->vni, prof_node->opri,
		  prof_node->ovid, tun_route->ovlan_id, tun_route->ovlan_pcp, prof_node->otpid_sel,
		  tun_route->ivlan_id, tun_route->ivlan_pcp, prof_node->itpid_sel);

	return 0;
}

/* NBL_TC_TUN_SET_OPS_DRACO(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_TC_TUN_OPS_TBL_DRACO							\
do {											\
	NBL_TC_TUN_SET_OPS_DRACO(tc_tun_encap_lookup, nbl_draco_tc_tun_encap_lookup);	\
	NBL_TC_TUN_SET_OPS_DRACO(tc_tun_encap_del, nbl_draco_tc_tun_encap_del);		\
	NBL_TC_TUN_SET_OPS_DRACO(tc_tun_encap_add, nbl_draco_tc_tun_encap_add);		\
	NBL_TC_TUN_SET_OPS_DRACO(tc_tun_create_header, nbl_draco_tc_tun_create_header);	\
} while (0)

int nbl_tc_tun_setup_ops_draco(struct nbl_resource_ops *res_ops)
{
#define NBL_TC_TUN_SET_OPS_DRACO(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_TC_TUN_OPS_TBL_DRACO;
#undef  NBL_TC_TUN_SET_OPS_DRACO

	return 0;
}

void nbl_tc_tun_remove_ops_draco(struct nbl_resource_ops *res_ops)
{
#define NBL_TC_TUN_SET_OPS_DRACO(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_TC_TUN_OPS_TBL_DRACO;
#undef  NBL_TC_TUN_SET_OPS_DRACO
}
