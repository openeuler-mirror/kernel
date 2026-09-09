// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <rdma/ib_verbs.h>
#include <rdma/nbl-abi.h>

#include "debug.h"
#include "pd.h"
#include "grc.h"
#include "ah.h"
#include "gid.h"

/*
 * should get the MIN_SRC_UDP_SPORT by querying device,
 * temporarily define a value
 */
static u16 nbl_get_roce_udp_sport(const struct nbl_device *dev,
				      const struct ib_gid_attr *attr)
{
	u16 sport;

	if (attr->gid_type != IB_GID_TYPE_ROCE_UDP_ENCAP) {
		nbl_ib_warn(&dev->rf->sc_dev, "wrong gid_type.\n");
		return 0;
	}

	sport = get_random_u32() % (IB_ROCE_UDP_ENCAP_VALID_PORT_MAX + 1 -
				IB_ROCE_UDP_ENCAP_VALID_PORT_MIN) +
			IB_ROCE_UDP_ENCAP_VALID_PORT_MIN;

	return sport;
}

static u16 kc_rdma_flow_label_to_udp_sport(u32 fl)
{
	u32 fl_low = fl & 0x03FFF;
	u32 fl_high = fl & 0xFC000;

	fl_low ^= fl_high >> 14;

	return (u16)(fl_low | IB_ROCE_UDP_ENCAP_VALID_PORT_MIN);
}

u16 nbl_ah_get_udp_sport(const struct nbl_device *dev,
			 const struct rdma_ah_attr *ah_attr)
{
	enum ib_gid_type gid_type = ah_attr->grh.sgid_attr->gid_type;
	u16 sport;

	if ((gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP) &&
	    (rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH) &&
	    (ah_attr->grh.flow_label & IB_GRH_FLOWLABEL_MASK))
		sport = kc_rdma_flow_label_to_udp_sport(ah_attr->grh.flow_label);
	else
		sport = nbl_get_roce_udp_sport(dev, ah_attr->grh.sgid_attr);

	return sport;
}

static int create_ib_ah(const struct nbl_device *dev, struct nbl_ah *ah,
			const struct rdma_ah_attr *ah_attr)
{
	const struct ib_global_route *grh = rdma_ah_read_grh(ah_attr);
	const struct ib_gid_attr *sgid_attr = grh->sgid_attr;
	u8 vlan_tag_ipv4_valid = 0;
	u16 index;
	int ret;

	ah->sgid_index = grh->sgid_index;

	if (rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH) {
		memcpy(ah->av.dest_ip, &grh->dgid, NBL_GRH_DGID_RAW_SIZE);
		ah->av.flow_label = grh->flow_label;
		ah->av.hop_limit = grh->hop_limit;
		ah->av.tclass = grh->traffic_class;
	}

	if (ipv6_addr_v4mapped((struct in6_addr *)&sgid_attr->gid))
		vlan_tag_ipv4_valid |= NBL_AH_VECTOR_IPV4_VALID;

	if (sgid_attr->ndev) {
		if (is_vlan_dev(sgid_attr->ndev)) {
			vlan_tag_ipv4_valid |= NBL_AH_VECTOR_VLAN_TAG;
			ah->av.vlan_id = vlan_dev_vlan_id(sgid_attr->ndev);
		} else
			ah->av.vlan_id = VLAN_N_VID;
	}

	/* according to vf_id and ip type to set the src_addr_index */
	ret = nbl_get_src_addr_info(dev, grh->sgid_index, &index, NULL);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev,
			"get nbl src addr index failed, the function_id: %u, the sgid_index: %u.\n",
			dev->rf->sc_dev.function_id, grh->sgid_index);
		return ret;
	}
	ah->av.src_addr_index = (u8)index;

	memcpy(ah->av.dest_mac, ah_attr->roce.dmac, sizeof(ah_attr->roce.dmac));
	ah->av.udp_sport = nbl_ah_get_udp_sport(dev, ah_attr);
	ah->av.eth_prio = rdma_ah_get_sl(ah_attr);
	ah->av.vlan_tag_ipv4_valid = vlan_tag_ipv4_valid;

	return 0;
}

static int nbl_copy_to_udata(struct ib_udata *udata, const struct nbl_ah *nbl_ah)
{
	struct nbl_ib_create_ah_resp resp = {};
	int err;
	u32 min_resp_len;

	min_resp_len = offsetof(typeof(resp), ah_id) + sizeof(resp.ah_id) +
		       sizeof(resp.dest_mac) + sizeof(resp.vlan_tag_ipv4_valid) +
		       sizeof(resp.src_addr_index) + sizeof(resp.vlan_id);

	if (udata->outlen < min_resp_len) {
		nbl_ib_err(
			nbl_ah->dev,
			"outlen is less than min_resp_len! the min_resp_len is %u\n",
			min_resp_len);
		return -EINVAL;
	}

	resp.response_length = min_resp_len;
	resp.ah_id = nbl_ah->ah_id;
	memcpy(resp.dest_mac, nbl_ah->av.dest_mac, ETH_ALEN);
	resp.vlan_tag_ipv4_valid = nbl_ah->av.vlan_tag_ipv4_valid;
	resp.src_addr_index = nbl_ah->av.src_addr_index;
	resp.vlan_id = nbl_ah->av.vlan_id;
	err = ib_copy_to_udata(udata, &resp, resp.response_length);
	if (err) {
		nbl_ib_err(nbl_ah->dev, "ib copy info to udata failed!\n");
		return err;
	}

	return 0;
}

/* create ah */
/**
 * nbl_ib_create_ah - create address handle
 * @ibah: pointer to the address handle
 * @attr: address handle attributes
 * @flags: AH flags to wait
 * @udata: user data
 * Return: return 0 on success, fail otherwise
 */
int nbl_ib_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
		     struct ib_udata *udata)
{
	struct rdma_ah_attr *attr = init_attr->ah_attr;
	struct nbl_ah *ah = to_nbl_ah(ibah);
	struct nbl_device *dev = to_nbl_dev(ibah->device);
	struct nbl_pd *pd = to_nbl_pd(ibah->pd);
	struct nbl_pci_f *rf = dev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;

	enum rdma_ah_attr_type ah_type = attr->type;
	u32 ah_id = 0;
	int err;

	if (ah_type != RDMA_AH_ATTR_TYPE_ROCE) {
		nbl_ib_err(sc_dev, "wrong ah_type, the ah_type is %d.\n",
			   ah_type);
		return -EINVAL;
	}

	if (!(rdma_ah_get_ah_flags(attr) & IB_AH_GRH)) {
		nbl_ib_err(sc_dev, "wrong ah_flag, the ah_flag is %u.\n",
			   rdma_ah_get_ah_flags(attr));
		return -EINVAL;
	}

	err = nbl_alloc_rsrc(&rf->rsrc_lock, rf->allocated_ahs, rf->max_ah,
			     &ah_id, &rf->next_ah);
	if (err) {
		nbl_ib_err(sc_dev, "alloc rsrc failed!\n");
		return err;
	}

	err = create_ib_ah(dev, ah, attr);
	if (err) {
		nbl_ib_err(sc_dev, "create ib ah failed!\n");
		nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_ahs, ah_id);
		return err;
	}

	ah->pd = pd;
	ah->av.pd_idx = pd->sc_pd.pd_id;
	ah->dev = sc_dev;
	ah->ah_id = ah_id;

	if (udata) {
		err = nbl_copy_to_udata(udata, ah);
		if (err) {
			nbl_ib_err(sc_dev, "copy info to udata failed!\n");
			nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_ahs, ah_id);
			return err;
		}
	}

	return 0;
}

/* destroy ah */
/**
 * nbl_ib_destroy_ah - destroy address handle
 * @ibah: pointer to the address handle
 * @flags: destroy flag
 */
int nbl_ib_destroy_ah(struct ib_ah *ibah, u32 flags)
{
	struct nbl_device *dev = to_nbl_dev(ibah->device);
	const struct nbl_ah *ah = to_nbl_ah(ibah);

	nbl_free_rsrc(&dev->rf->rsrc_lock, dev->rf->allocated_ahs, ah->ah_id);

	return 0;
}

/**
 * nbl_ib_query_ah - query address handle
 * @ibah: pointer to the address handle
 * @ah_attr: address handle attributes
 * Return: return 0 on success, fail otherwise
 */
int nbl_ib_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr)
{
	struct nbl_ah *ah = to_nbl_ah(ibah);
	u32 flow_label;

	memset(ah_attr, 0, sizeof(*ah_attr));
	ah_attr->type = ibah->type;

	flow_label = ah->av.flow_label;
	rdma_ah_set_grh(ah_attr, NULL, flow_label, ah->sgid_index,
			ah->av.hop_limit, ah->av.tclass);
	rdma_ah_set_dgid_raw(ah_attr, ah->av.dest_ip);
	rdma_ah_set_sl(ah_attr, ah->av.eth_prio);
	if (ibah->type == RDMA_AH_ATTR_TYPE_ROCE)
		memcpy(ah_attr->roce.dmac, ah->av.dest_mac,
		       sizeof(ah->av.dest_mac));

	return 0;
}
