// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se_api.h"
#include "dpp_se_api.h"
#include "dpp_drv_sdt.h"
#include "dpp_drv_eram.h"
#include "dpp_apt_se.h"

static struct se_apt_eram_convert_t g_se_eram_callback[] = {
	{ ZXDH_SDT_VXLAN_ATTR_TABLE, dpp_apt_set_vxlan_data, dpp_apt_get_vxlan_data },
	{ ZXDH_SDT_SRIOV_VPORT_ATTR_TABLE, dpp_apt_set_vport_data, dpp_apt_get_vport_data },
	{ ZXDH_SDT_UPLINK_PHY_PORT_ATTR_TABLE, dpp_apt_set_uplink_phy_port_data,
	  dpp_apt_get_uplink_phy_port_data },
	{ ZXDH_SDT_RSS_TO_VQID_TABLE, dpp_apt_set_rss_to_vqid_data, dpp_apt_get_rss_to_vqid_data },
	{ ZXDH_SDT_VLAN_FILTER_TABLE, dpp_apt_set_vlan_filter_data, dpp_apt_get_vlan_filter_data },
	{ ZXDH_SDT_LAG_TABLE, dpp_apt_set_lag_data, dpp_apt_get_lag_data },
	{ ZXDH_SDT_BC_TABLE, dpp_apt_set_bc_data, dpp_apt_get_bc_data },
	{ ZXDH_SDT_DSCP_TO_UP_TABLE, dpp_apt_set_dscp_to_up_data, dpp_apt_get_dscp_to_up_data },
	{ ZXDH_SDT_UP_TO_TC_TABLE, dpp_apt_set_up_to_tc_data, dpp_apt_get_up_to_tc_data },
	{ ZXDH_SDT_ACL_INDEX_MNG_TABLE, dpp_apt_set_fd_index_mng, dpp_apt_get_fd_index_mng },
	{ ZXDH_SDT_VHCA_TABLE, dpp_apt_set_vhca_data, dpp_apt_get_vhca_data },
	{ ZXDH_SDT_UC_PROMISC_TABLE, dpp_apt_set_promisc_data, dpp_apt_get_promisc_data },
	{ ZXDH_SDT_MC_PROMISC_TABLE, dpp_apt_set_promisc_data, dpp_apt_get_promisc_data },
	{ ZXDH_SDT_VQM_VFID_VLAN_ATTR_TABLE, dpp_apt_set_vqm_vfid_vlan_data,
	  dpp_apt_get_vqm_vfid_vlan_data },
	{ ZXDH_SDT_CAP_KEYWORD_ATTR_TABLE, dpp_apt_set_cap_keyword_attr_data,
	  dpp_apt_get_cap_keyword_attr_data },
	{ ZXDH_SDT_STAT_ATTR_TABLE, dpp_apt_set_stat_attr_data, dpp_apt_get_stat_attr_data }
};

struct se_apt_eram_convert_t *se_eram_callback_get(u32 sdt_no)
{
	u32 index = 0;
	u32 num = 0;

	num = sizeof(g_se_eram_callback) / sizeof(struct se_apt_eram_convert_t);
	for (index = 0; index < num; index++) {
		if (g_se_eram_callback[index].sdt_no == sdt_no)
			return &g_se_eram_callback[index];
	}
	return NULL;
}

u32 dpp_apt_set_data(void *pData, u32 buff[4], u32 size)
{
	if (!pData)
		return DPP_ERR;
	memcpy(buff, pData, size);
	return DPP_OK;
}

u32 dpp_apt_get_data(void *pData, u32 buff[4], u32 size)
{
	if (!pData)
		return DPP_ERR;
	memcpy(pData, buff, size);
	return DPP_OK;
}

u32 dpp_apt_set_vxlan_data(void *pData, u32 buff[4])
{
	return dpp_apt_set_data(pData, buff, sizeof(struct zxdh_vxlan_t));
}

u32 dpp_apt_get_vxlan_data(void *pData, u32 buff[4])
{
	return dpp_apt_get_data(pData, buff, sizeof(struct zxdh_vxlan_t));
}

u32 dpp_apt_set_vport_data(void *pData, u32 buff[4])
{
	struct zxdh_sriov_vport_t *port_attr = (struct zxdh_sriov_vport_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->mtu_offload_enable, 30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->rss_enable, 29, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->sriov_business_vlan_offload_enable, 28, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->sriov_vlan_offload_enable, 27, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->promisc_enable, 26, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->rdma_offload_enable, 25, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->hw_bond_enable, 24, 1);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->business_enable, 23, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->is_up, 22, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->outer_ip_checksum_offload, 21, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->ip_checksum_offload, 20, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->tcp_udp_checksum_offload, 19, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->ip_recombine_offload, 18, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->lro_offload, 17, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->accelerator_offload_flag, 16, 1);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->virtio_enable, 15, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->virtio_version, 13, 2);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->is_vf, 12, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->vepa_enable, 11, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->lag_enable, 10, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->fd_enable, 9, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->inline_sec_offload, 8, 1);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->spoof_check_enable, 7, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->rsv1, 6, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->np_ingress_tm_enable, 5, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->np_egress_tm_enable, 4, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->np_ingress_meter_mode, 3, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->np_egress_meter_mode, 2, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->np_ingress_meter_enable, 1, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], port_attr->np_egress_meter_enable, 0, 1);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], port_attr->rsv2, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], port_attr->hash_search_index, 28, 3);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], port_attr->port_base_qid, 16, 12);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], port_attr->mtu, 0, 16);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], port_attr->rsv3, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], port_attr->pf_vqm_vfid, 20, 11);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], port_attr->fd_vxlan_offload_en, 19, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], port_attr->lag_id, 16, 3);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], port_attr->uplink_phy_port_id, 12, 4);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], port_attr->hash_alg, 8, 4);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], port_attr->rss_hash_factor, 0, 8);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], port_attr->flag_1588_enable, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], port_attr->rsv5, 26, 5);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], port_attr->vhca, 16, 10);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], port_attr->rsv6, 0, 16);

	return DPP_OK;
}

u32 dpp_apt_get_vport_data(void *pData, u32 buff[4])
{
	struct zxdh_sriov_vport_t *port_attr = (struct zxdh_sriov_vport_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(port_attr->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->mtu_offload_enable, buff[0], 30, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->rss_enable, buff[0], 29, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->sriov_business_vlan_offload_enable, buff[0], 28, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->sriov_vlan_offload_enable, buff[0], 27, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->promisc_enable, buff[0], 26, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->rdma_offload_enable, buff[0], 25, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->hw_bond_enable, buff[0], 24, 1);

	ZXIC_COMM_UINT32_GET_BITS(port_attr->business_enable, buff[0], 23, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->is_up, buff[0], 22, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->outer_ip_checksum_offload, buff[0], 21, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->ip_checksum_offload, buff[0], 20, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->tcp_udp_checksum_offload, buff[0], 19, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->ip_recombine_offload, buff[0], 18, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->lro_offload, buff[0], 17, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->accelerator_offload_flag, buff[0], 16, 1);

	ZXIC_COMM_UINT32_GET_BITS(port_attr->virtio_enable, buff[0], 15, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->virtio_version, buff[0], 13, 2);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->is_vf, buff[0], 12, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->vepa_enable, buff[0], 11, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->lag_enable, buff[0], 10, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->fd_enable, buff[0], 9, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->inline_sec_offload, buff[0], 8, 1);

	ZXIC_COMM_UINT32_GET_BITS(port_attr->spoof_check_enable, buff[0], 7, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->rsv1, buff[0], 6, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->np_ingress_tm_enable, buff[0], 5, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->np_egress_tm_enable, buff[0], 4, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->np_ingress_meter_mode, buff[0], 3, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->np_egress_meter_mode, buff[0], 2, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->np_ingress_meter_enable, buff[0], 1, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->np_egress_meter_enable, buff[0], 0, 1);

	ZXIC_COMM_UINT32_GET_BITS(port_attr->rsv2, buff[1], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->hash_search_index, buff[1], 28, 3);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->port_base_qid, buff[1], 16, 12);

	ZXIC_COMM_UINT32_GET_BITS(port_attr->mtu, buff[1], 0, 16);

	ZXIC_COMM_UINT32_GET_BITS(port_attr->rsv3, buff[2], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->pf_vqm_vfid, buff[2], 20, 11);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->fd_vxlan_offload_en, buff[2], 19, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->lag_id, buff[2], 16, 3);

	ZXIC_COMM_UINT32_GET_BITS(port_attr->uplink_phy_port_id, buff[2], 12, 4);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->hash_alg, buff[2], 8, 4);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->rss_hash_factor, buff[2], 0, 8);

	ZXIC_COMM_UINT32_GET_BITS(port_attr->flag_1588_enable, buff[3], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->rsv5, buff[3], 26, 6);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->vhca, buff[3], 16, 10);
	ZXIC_COMM_UINT32_GET_BITS(port_attr->rsv6, buff[3], 0, 16);

	return DPP_OK;
}

u32 dpp_apt_set_uplink_phy_port_data(void *pData, u32 buff[4])
{
	struct zxdh_uplink_phy_port_t *attr = (struct zxdh_uplink_phy_port_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->trust_mode, 30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->ptp_tc_enable, 28, 2);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->tm_shape_enable, 27, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->magic_packet_enable, 26, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->rsv1, 11, 15);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->ptp_port_vfid, 0, 11);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], attr->tm_base_queue, 20, 12);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], attr->rsv2, 17, 3);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], attr->mtu_offload_enable, 16, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], attr->mtu, 0, 16);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->hw_bond_enable, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->bond_link_up, 30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->is_up, 29, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->sriov_hdbond_enable, 28, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->rsv3, 27, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->lacp_pf_vqm_vfid, 16, 11);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->rsv4, 12, 4);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->lacp_pf_memport_qid, 0, 12);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], attr->rsv5, 27, 5);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], attr->pf_vqm_vfid, 16, 11);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], attr->rsv6, 11, 5);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], attr->primary_pf_vqm_vfid, 0, 11);

	return DPP_OK;
}

u32 dpp_apt_get_uplink_phy_port_data(void *pData, u32 buff[4])
{
	struct zxdh_uplink_phy_port_t *attr = (struct zxdh_uplink_phy_port_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(attr->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->trust_mode, buff[0], 30, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->ptp_tc_enable, buff[0], 28, 2);
	ZXIC_COMM_UINT32_GET_BITS(attr->tm_shape_enable, buff[0], 27, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->magic_packet_enable, buff[0], 26, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->rsv1, buff[0], 11, 15);
	ZXIC_COMM_UINT32_GET_BITS(attr->ptp_port_vfid, buff[0], 0, 11);
	ZXIC_COMM_UINT32_GET_BITS(attr->tm_base_queue, buff[1], 20, 12);
	ZXIC_COMM_UINT32_GET_BITS(attr->rsv2, buff[1], 17, 3);
	ZXIC_COMM_UINT32_GET_BITS(attr->mtu_offload_enable, buff[1], 16, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->mtu, buff[1], 0, 16);

	ZXIC_COMM_UINT32_GET_BITS(attr->hw_bond_enable, buff[2], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->bond_link_up, buff[2], 30, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->is_up, buff[2], 29, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->sriov_hdbond_enable, buff[2], 28, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->rsv3, buff[2], 27, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->lacp_pf_vqm_vfid, buff[2], 16, 11);
	ZXIC_COMM_UINT32_GET_BITS(attr->rsv4, buff[2], 12, 4);
	ZXIC_COMM_UINT32_GET_BITS(attr->lacp_pf_memport_qid, buff[2], 0, 12);

	ZXIC_COMM_UINT32_GET_BITS(attr->rsv5, buff[3], 27, 5);
	ZXIC_COMM_UINT32_GET_BITS(attr->pf_vqm_vfid, buff[3], 16, 11);
	ZXIC_COMM_UINT32_GET_BITS(attr->rsv6, buff[3], 11, 5);
	ZXIC_COMM_UINT32_GET_BITS(attr->primary_pf_vqm_vfid, buff[3], 0, 11);

	return DPP_OK;
}

u32 dpp_apt_set_dscp_to_up_data(void *pData, u32 buff[4])
{
	struct zxdh_dscp_to_up_t *attr = (struct zxdh_dscp_to_up_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->rsv1, 3, 28);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->up, 0, 3);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], attr->rsv2, 0, 32);

	return DPP_OK;
}

u32 dpp_apt_get_dscp_to_up_data(void *pData, u32 buff[4])
{
	struct zxdh_dscp_to_up_t *attr = (struct zxdh_dscp_to_up_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(attr->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->rsv1, buff[0], 3, 28);
	ZXIC_COMM_UINT32_GET_BITS(attr->up, buff[0], 0, 3);

	ZXIC_COMM_UINT32_GET_BITS(attr->rsv2, buff[1], 0, 32);

	return DPP_OK;
}

u32 dpp_apt_set_up_to_tc_data(void *pData, u32 buff[4])
{
	struct zxdh_up_to_tc_t *attr = (struct zxdh_up_to_tc_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->rsv1, 3, 28);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->tc, 0, 3);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], attr->rsv2, 0, 32);

	return DPP_OK;
}

u32 dpp_apt_get_up_to_tc_data(void *pData, u32 buff[4])
{
	struct zxdh_up_to_tc_t *attr = (struct zxdh_up_to_tc_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(attr->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->rsv1, buff[0], 3, 28);
	ZXIC_COMM_UINT32_GET_BITS(attr->tc, buff[0], 0, 3);

	ZXIC_COMM_UINT32_GET_BITS(attr->rsv2, buff[1], 0, 32);

	return DPP_OK;
}

u32 dpp_apt_set_rss_to_vqid_data(void *pData, u32 buff[4])
{
	struct zxdh_rss_to_vqid_t *attr = (struct zxdh_rss_to_vqid_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->vqm_qid[0], 16, 15);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], attr->vqm_qid[1], 0, 16);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], attr->vqm_qid[2], 16, 16);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], attr->vqm_qid[3], 0, 16);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->vqm_qid[4], 16, 16);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], attr->vqm_qid[5], 0, 16);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], attr->vqm_qid[6], 16, 16);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], attr->vqm_qid[7], 0, 16);

	return DPP_OK;
}

u32 dpp_apt_get_rss_to_vqid_data(void *pData, u32 buff[4])
{
	struct zxdh_rss_to_vqid_t *attr = (struct zxdh_rss_to_vqid_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(attr->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(attr->vqm_qid[0], buff[0], 16, 15);
	ZXIC_COMM_UINT32_GET_BITS(attr->vqm_qid[1], buff[0], 0, 16);

	ZXIC_COMM_UINT32_GET_BITS(attr->vqm_qid[2], buff[1], 16, 16);
	ZXIC_COMM_UINT32_GET_BITS(attr->vqm_qid[3], buff[1], 0, 16);

	ZXIC_COMM_UINT32_GET_BITS(attr->vqm_qid[4], buff[2], 16, 16);
	ZXIC_COMM_UINT32_GET_BITS(attr->vqm_qid[5], buff[2], 0, 16);

	ZXIC_COMM_UINT32_GET_BITS(attr->vqm_qid[6], buff[3], 16, 16);
	ZXIC_COMM_UINT32_GET_BITS(attr->vqm_qid[7], buff[3], 0, 16);

	return DPP_OK;
}

u32 dpp_apt_set_vlan_filter_data(void *pData, u32 buff[4])
{
	struct zxdh_vlan_filter_t *vlan_filter_table = (struct zxdh_vlan_filter_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_filter_table->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_filter_table->rsv, 24, 7);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_filter_table->vport_bitmap[0], 16, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_filter_table->vport_bitmap[1], 8, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_filter_table->vport_bitmap[2], 0, 8);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], vlan_filter_table->vport_bitmap[3], 24, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], vlan_filter_table->vport_bitmap[4], 16, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], vlan_filter_table->vport_bitmap[5], 8, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], vlan_filter_table->vport_bitmap[6], 0, 8);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], vlan_filter_table->vport_bitmap[7], 24, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], vlan_filter_table->vport_bitmap[8], 16, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], vlan_filter_table->vport_bitmap[9], 8, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], vlan_filter_table->vport_bitmap[10], 0, 8);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], vlan_filter_table->vport_bitmap[11], 24, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], vlan_filter_table->vport_bitmap[12], 16, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], vlan_filter_table->vport_bitmap[13], 8, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], vlan_filter_table->vport_bitmap[14], 0, 8);
	return DPP_OK;
}

u32 dpp_apt_get_vlan_filter_data(void *pData, u32 buff[4])
{
	struct zxdh_vlan_filter_t *vlan_filter_table = (struct zxdh_vlan_filter_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->rsv, buff[0], 24, 7);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[0], buff[0], 16, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[1], buff[0], 8, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[2], buff[0], 0, 8);

	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[3], buff[1], 24, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[4], buff[1], 16, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[5], buff[1], 8, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[6], buff[1], 0, 8);

	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[7], buff[2], 24, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[8], buff[2], 16, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[9], buff[2], 8, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[10], buff[2], 0, 8);

	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[11], buff[3], 24, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[12], buff[3], 16, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[13], buff[3], 8, 8);
	ZXIC_COMM_UINT32_GET_BITS(vlan_filter_table->vport_bitmap[14], buff[3], 0, 8);
	return DPP_OK;
}

u32 dpp_apt_set_lag_data(void *pData, u32 buff[4])
{
	struct zxdh_lag_t *lag_entry = (struct zxdh_lag_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], lag_entry->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], lag_entry->rsv1, 27, 4);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], lag_entry->member_num, 24, 3);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], lag_entry->bond_mode, 16, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], lag_entry->hash_factor, 8, 8);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], lag_entry->rsv2, 0, 8);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], lag_entry->rsv2, 16, 16);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], lag_entry->member_bitmap, 0, 16);

	return DPP_OK;
}

u32 dpp_apt_get_lag_data(void *pData, u32 buff[4])
{
	struct zxdh_lag_t *lag_entry = (struct zxdh_lag_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(lag_entry->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(lag_entry->rsv1, buff[0], 27, 4);
	ZXIC_COMM_UINT32_GET_BITS(lag_entry->member_num, buff[0], 24, 3);
	ZXIC_COMM_UINT32_GET_BITS(lag_entry->bond_mode, buff[0], 16, 8);
	ZXIC_COMM_UINT32_GET_BITS(lag_entry->hash_factor, buff[0], 8, 8);
	ZXIC_COMM_UINT32_GET_BITS(lag_entry->rsv2, buff[0], 0, 8);

	ZXIC_COMM_UINT32_GET_BITS(lag_entry->rsv2, buff[1], 16, 16);
	ZXIC_COMM_UINT32_GET_BITS(lag_entry->member_bitmap, buff[1], 0, 16);

	return DPP_OK;
}

u32 dpp_apt_set_bc_data(void *pData, u32 buff[4])
{
	u32 bc_bitmap = 0;
	struct zxdh_bc_t *bc_entry = (struct zxdh_bc_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], bc_entry->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], bc_entry->rsv1, 0, 31);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], bc_entry->rsv2, 0, 32);

	bc_bitmap = bc_entry->bc_bitmap >> 32;
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], bc_bitmap, 0, 32);

	bc_bitmap = bc_entry->bc_bitmap;
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], bc_bitmap, 0, 32);

	return DPP_OK;
}

u32 dpp_apt_get_bc_data(void *pData, u32 buff[4])
{
	u32 bc_bitmap = 0;
	struct zxdh_bc_t *bc_entry = (struct zxdh_bc_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(bc_entry->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(bc_entry->rsv1, buff[0], 0, 31);

	ZXIC_COMM_UINT32_GET_BITS(bc_entry->rsv2, buff[1], 0, 32);

	ZXIC_COMM_UINT32_GET_BITS(bc_bitmap, buff[2], 0, 32);
	bc_entry->bc_bitmap = (((u64)bc_bitmap) << 32);

	ZXIC_COMM_UINT32_GET_BITS(bc_bitmap, buff[3], 0, 32);
	bc_entry->bc_bitmap |= bc_bitmap;

	return DPP_OK;
}

u32 dpp_apt_set_promisc_data(void *pData, u32 buff[4])
{
	u32 bitmap = 0;
	struct zxdh_promisc_t *promisc_entry = (struct zxdh_promisc_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], promisc_entry->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], promisc_entry->pf_enable, 30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], promisc_entry->rsv1, 0, 30);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], promisc_entry->rsv2, 0, 32);

	bitmap = promisc_entry->bitmap >> 32;
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], bitmap, 0, 32);

	bitmap = promisc_entry->bitmap;
	ZXIC_COMM_UINT32_WRITE_BITS(buff[3], bitmap, 0, 32);

	return DPP_OK;
}

u32 dpp_apt_get_promisc_data(void *pData, u32 buff[4])
{
	u32 bitmap = 0;
	struct zxdh_promisc_t *promisc_entry = (struct zxdh_promisc_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(promisc_entry->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(promisc_entry->pf_enable, buff[0], 30, 1);
	ZXIC_COMM_UINT32_GET_BITS(promisc_entry->rsv1, buff[0], 0, 30);

	ZXIC_COMM_UINT32_GET_BITS(promisc_entry->rsv2, buff[1], 0, 32);

	ZXIC_COMM_UINT32_GET_BITS(bitmap, buff[2], 0, 32);
	promisc_entry->bitmap = (((u64)bitmap) << 32);

	ZXIC_COMM_UINT32_GET_BITS(bitmap, buff[3], 0, 32);
	promisc_entry->bitmap |= bitmap;

	return DPP_OK;
}

u32 dpp_apt_set_vhca_data(void *pData, u32 buff[4])
{
	struct zxdh_vhca_t *vhca_entry = (struct zxdh_vhca_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vhca_entry->valid, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vhca_entry->rsv1, 11, 20);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vhca_entry->vqm_vfid, 0, 11);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], vhca_entry->rsv2, 0, 32);
	return DPP_OK;
}

u32 dpp_apt_get_vhca_data(void *pData, u32 buff[4])
{
	struct zxdh_vhca_t *vhca_entry = (struct zxdh_vhca_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(vhca_entry->valid, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(vhca_entry->rsv1, buff[0], 11, 20);
	ZXIC_COMM_UINT32_GET_BITS(vhca_entry->vqm_vfid, buff[0], 0, 11);

	ZXIC_COMM_UINT32_GET_BITS(vhca_entry->rsv2, buff[1], 0, 32);

	return DPP_OK;
}

u32 dpp_apt_set_network_attr_data(void *pData, u32 buff[4])
{
	struct zxdh_network_attr_t *network_attr = (struct zxdh_network_attr_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], network_attr->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], network_attr->single_pipe, 30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], network_attr->three_plane_aggr, 29, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], network_attr->sdn_dyn_sriov_cni, 28, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], network_attr->upf, 27, 1);

	return DPP_OK;
}

u32 dpp_apt_get_network_attr_data(void *pData, u32 buff[4])
{
	struct zxdh_network_attr_t *network_attr = (struct zxdh_network_attr_t *)pData;

	ZXIC_COMM_MEMSET_S(network_attr, sizeof(struct zxdh_network_attr_t), 0x0,
			   sizeof(struct zxdh_network_attr_t));
	ZXIC_COMM_UINT32_GET_BITS(network_attr->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(network_attr->single_pipe, buff[0], 30, 1);
	ZXIC_COMM_UINT32_GET_BITS(network_attr->three_plane_aggr, buff[0], 29, 1);
	ZXIC_COMM_UINT32_GET_BITS(network_attr->sdn_dyn_sriov_cni, buff[0], 28, 1);
	ZXIC_COMM_UINT32_GET_BITS(network_attr->upf, buff[0], 27, 1);

	return DPP_OK;
}

u32 dpp_apt_set_vport_traffic_attr_data(void *pData, u32 buff[4])
{
	struct zxdh_vport_traffic_attr_t *vport_attr = (struct zxdh_vport_traffic_attr_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vport_attr->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vport_attr->vport_traffic_attr.ovs_attr.is_passthrough,
				    30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(
		buff[0], vport_attr->vport_traffic_attr.ovs_attr.uplink_vqm_vfid, 15, 16);

	return DPP_OK;
}

u32 dpp_apt_get_vport_traffic_attr_data(void *pData, u32 buff[4])
{
	struct zxdh_vport_traffic_attr_t *vport_attr = (struct zxdh_vport_traffic_attr_t *)pData;

	ZXIC_COMM_MEMSET_S(vport_attr, sizeof(struct zxdh_vport_traffic_attr_t), 0x0,
			   sizeof(struct zxdh_vport_traffic_attr_t));
	ZXIC_COMM_UINT32_GET_BITS(vport_attr->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(vport_attr->vport_traffic_attr.ovs_attr.is_passthrough, buff[0],
				  30, 1);
	ZXIC_COMM_UINT32_GET_BITS(vport_attr->vport_traffic_attr.ovs_attr.uplink_vqm_vfid, buff[0],
				  15, 16);

	return DPP_OK;
}

u32 dpp_apt_set_vqm_vfid_vlan_data(void *pData, u32 buff[4])
{
	struct zxdh_vqm_vfid_vlan_t *vlan_entry = (struct zxdh_vqm_vfid_vlan_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_entry->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_entry->sriov_business_vlan_filter, 30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_entry->sriov_business_qinq_vlan_strip_offload, 29,
				    1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_entry->sriov_business_vlan_strip_offload, 28, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_entry->rsv, 16, 12);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], vlan_entry->sriov_business_vlan_tpid, 0, 16);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], vlan_entry->sriov_vlan_tpid, 16, 16);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], vlan_entry->sriov_vlan_tci, 0, 16);

	return DPP_OK;
}

u32 dpp_apt_get_vqm_vfid_vlan_data(void *pData, u32 buff[4])
{
	struct zxdh_vqm_vfid_vlan_t *vlan_entry = (struct zxdh_vqm_vfid_vlan_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(vlan_entry->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(vlan_entry->sriov_business_vlan_filter, buff[0], 30, 1);
	ZXIC_COMM_UINT32_GET_BITS(vlan_entry->sriov_business_qinq_vlan_strip_offload, buff[0], 29,
				  1);
	ZXIC_COMM_UINT32_GET_BITS(vlan_entry->sriov_business_vlan_strip_offload, buff[0], 28, 1);
	ZXIC_COMM_UINT32_GET_BITS(vlan_entry->rsv, buff[0], 16, 12);
	ZXIC_COMM_UINT32_GET_BITS(vlan_entry->sriov_business_vlan_tpid, buff[0], 0, 16);

	ZXIC_COMM_UINT32_GET_BITS(vlan_entry->sriov_vlan_tpid, buff[1], 16, 16);
	ZXIC_COMM_UINT32_GET_BITS(vlan_entry->sriov_vlan_tci, buff[1], 0, 16);

	return DPP_OK;
}

u32 dpp_apt_set_fd_index_mng(void *pData, u32 buff[4])
{
	struct zxdh_fd_index_mng_t *fd_index_mng_entry = (struct zxdh_fd_index_mng_t *)pData;

	ZXIC_COMM_CHECK_POINT(fd_index_mng_entry);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], fd_index_mng_entry->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], fd_index_mng_entry->rsv, 16, 15);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], fd_index_mng_entry->vport, 0, 16);

	return DPP_OK;
}

u32 dpp_apt_get_fd_index_mng(void *pData, u32 buff[4])
{
	struct zxdh_fd_index_mng_t *fd_index_mng_entry = (struct zxdh_fd_index_mng_t *)pData;

	ZXIC_COMM_CHECK_POINT(fd_index_mng_entry);
	ZXIC_COMM_UINT32_GET_BITS(fd_index_mng_entry->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(fd_index_mng_entry->rsv, buff[0], 16, 15);
	ZXIC_COMM_UINT32_GET_BITS(fd_index_mng_entry->vport, buff[0], 0, 16);

	return DPP_OK;
}

u32 dpp_apt_set_cap_keyword_attr_data(void *pData, u32 buff[4])
{
	struct zxdh_pkt_cap_kw_mode_t *kw_mode = (struct zxdh_pkt_cap_kw_mode_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], kw_mode->hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], kw_mode->rule1_key_word_len, 16, 4);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], kw_mode->rule1_key_word_off, 0, 13);

	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], kw_mode->rule2_key_word_len, 16, 4);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], kw_mode->rule2_key_word_off, 0, 13);

	return DPP_OK;
}

u32 dpp_apt_get_cap_keyword_attr_data(void *pData, u32 buff[4])
{
	struct zxdh_pkt_cap_kw_mode_t *kw_mode = (struct zxdh_pkt_cap_kw_mode_t *)pData;

	ZXIC_COMM_UINT32_GET_BITS(kw_mode->hit_flag, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(kw_mode->rule1_key_word_len, buff[0], 16, 4);
	ZXIC_COMM_UINT32_GET_BITS(kw_mode->rule1_key_word_off, buff[0], 0, 13);

	ZXIC_COMM_UINT32_GET_BITS(kw_mode->rule2_key_word_len, buff[1], 16, 4);
	ZXIC_COMM_UINT32_GET_BITS(kw_mode->rule2_key_word_off, buff[1], 0, 13);

	return DPP_OK;
}

u32 dpp_apt_set_stat_attr_data(void *pData, u32 buff[4])
{
	struct zxdh_stat_attr_t *stat_attr = (struct zxdh_stat_attr_t *)pData;

	ZXIC_COMM_CHECK_POINT(stat_attr);
	ZXIC_COMM_MEMSET_S(buff, sizeof(u32) * 4, 0x0, sizeof(u32) * 4);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], stat_attr->valid, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[0], stat_attr->mode, 30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[1], stat_attr->addr_offset, 0, 32);
	ZXIC_COMM_UINT32_WRITE_BITS(buff[2], stat_attr->depth, 0, 32);

	return DPP_OK;
}

u32 dpp_apt_get_stat_attr_data(void *pData, u32 buff[4])
{
	struct zxdh_stat_attr_t *stat_attr = (struct zxdh_stat_attr_t *)pData;

	ZXIC_COMM_CHECK_POINT(stat_attr);
	ZXIC_COMM_MEMSET_S(stat_attr, sizeof(struct zxdh_stat_attr_t), 0x0,
			   sizeof(struct zxdh_stat_attr_t));
	ZXIC_COMM_UINT32_GET_BITS(stat_attr->valid, buff[0], 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(stat_attr->mode, buff[0], 30, 1);
	ZXIC_COMM_UINT32_GET_BITS(stat_attr->addr_offset, buff[1], 0, 32);
	ZXIC_COMM_UINT32_GET_BITS(stat_attr->depth, buff[2], 0, 32);

	return DPP_OK;
}
