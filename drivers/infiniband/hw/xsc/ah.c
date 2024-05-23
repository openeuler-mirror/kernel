// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>

#include "xsc_ib.h"
#include "user.h"

static u32 xsc_calc_roce_udp_flow_label(void)
{
	u32 factor = 0;
	u32 hash = 0;
	u32 flow_label = 0;

	/*This function will generate a 20 bit flow_label*/
	factor = (IB_GRH_FLOWLABEL_MASK - IB_ROCE_UDP_ENCAP_VALID_PORT_MIN + 1);
	hash = get_random_u32() % factor;
	flow_label = hash & IB_GRH_FLOWLABEL_MASK;

	return flow_label;
}

static u16 xsc_ah_get_udp_sport(const struct xsc_ib_dev *dev,
				struct rdma_ah_attr *ah_attr)
{
	enum ib_gid_type gid_type = ah_attr->grh.sgid_attr->gid_type;
	u16 sport = 0;
	u32 fl = 0;

	if (gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP &&
	    (rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH) &&
	    (ah_attr->grh.flow_label & IB_GRH_FLOWLABEL_MASK)) {
		fl = ah_attr->grh.flow_label;
	} else {
		/*generate a 20bit flow_label and output to user layer*/
		fl = xsc_calc_roce_udp_flow_label();
		ah_attr->grh.flow_label = fl;
	}

	sport = xsc_flow_label_to_udp_sport(fl);
	xsc_ib_dbg(dev, "fl=0x%x,sport=0x%x\n", fl, sport);
	return sport;
}

static struct ib_ah *create_ib_ah(struct xsc_ib_dev *dev,
				  struct xsc_ib_ah *ah,
				  struct rdma_ah_attr *ah_attr)
{
	enum ib_gid_type gid_type;

	if (rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH) {
		const struct ib_global_route *grh = rdma_ah_read_grh(ah_attr);

		memcpy(ah->av.rgid, &grh->dgid, 16);
		ah->av.grh_gid_fl = cpu_to_be32(grh->flow_label |
						(1 << 30) |
						grh->sgid_index << 20);
		ah->av.hop_limit = grh->hop_limit;
		ah->av.tclass = grh->traffic_class;
	}

	ah->av.stat_rate_sl = (rdma_ah_get_static_rate(ah_attr) << 4);

	if (ah_attr->type == RDMA_AH_ATTR_TYPE_ROCE) {
		gid_type = ah_attr->grh.sgid_attr->gid_type;
		memcpy(ah->av.rmac, ah_attr->roce.dmac,
		       sizeof(ah_attr->roce.dmac));
		ah->av.udp_sport = xsc_ah_get_udp_sport(dev, ah_attr);
		ah->av.stat_rate_sl |= (rdma_ah_get_sl(ah_attr) & 0x7) << 1;
		if (gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP)
#define XSC_ECN_ENABLED BIT(1)
			ah->av.tclass |= XSC_ECN_ENABLED;
	} else {
		ah->av.rlid = cpu_to_be16(rdma_ah_get_dlid(ah_attr));
		ah->av.fl_mlid = rdma_ah_get_path_bits(ah_attr) & 0x7f;
		ah->av.stat_rate_sl |= (rdma_ah_get_sl(ah_attr) & 0xf);
	}

	return &ah->ibah;
}

xsc_ib_create_ah_def()
{
	struct xsc_ib_ah *ah = to_mah(ibah);
	struct xsc_ib_dev *dev = to_mdev(ibah->device);
	struct rdma_ah_attr *ah_attr = init_attr->ah_attr;
	enum rdma_ah_attr_type ah_type = ah_attr->type;

	if (ah_type == RDMA_AH_ATTR_TYPE_ROCE &&
	    !(rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH))
		return RET_VALUE(-EINVAL);

	if (ah_type == RDMA_AH_ATTR_TYPE_ROCE && udata) {
		int err;
		struct xsc_ib_create_ah_resp resp = {};
		u32 min_resp_len = offsetof(typeof(resp), dmac) +
				   sizeof(resp.dmac);

		if (udata->outlen < min_resp_len)
			return RET_VALUE(-EINVAL);

		resp.response_length = min_resp_len;

		memcpy(resp.dmac, ah_attr->roce.dmac, ETH_ALEN);
		err = ib_copy_to_udata(udata, &resp, resp.response_length);
		if (err)
			return RET_VALUE(err);
	}

	create_ib_ah(dev, ah, ah_attr); /* never fails */
	return 0;
}

int xsc_ib_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr)
{
	return 0;
}

xsc_ib_destroy_ah_def()
{
	return 0;
}
