/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _UDMA_EID_H
#define _UDMA_EID_H

#define UBOE_MAC_LEN 6
#define UDMA_SMAC_OFFSET 10

#define SMAC_L_SHIFT 0
#define SMAC_H_SHIFT 2

#define CFG_GMV_TBL_CMD_NUM 2
#define CFG_GMV_TB_VF_SGID_TYPE_S 0
#define CFG_GMV_TB_VF_SMAC_L_S 16
#define CFG_GMV_TB_VF_PATTERN_S 3
#define CFG_GMV_TB_VF_SGID_TYPE_M GENMASK(1, 0)
#define CFG_GMV_TB_VF_SMAC_L_M GENMASK(31, 16)

#define UDMA_IPV4_MAP_IPV6_PREFIX 0x0000ffff

enum udma_sgid_type {
	SGID_TYPE_IPV6,
	SGID_TYPE_IPV4,
};

struct udma_cfg_gmv_tb_a {
	uint32_t vf_sgid_l;
	uint32_t vf_sgid_ml;
	uint32_t vf_sgid_mh;
	uint32_t vf_sgid_h;
	uint32_t vf_type_vlan_smac;
	uint32_t vf_smac_h;
};

struct udma_cfg_gmv_tb_b {
	uint32_t vf_upi;
	uint32_t vf_eid_high;
	uint32_t table_idx_rsv;
	uint32_t vf_id;
	uint32_t resv[2];
};

struct udma_eid {
	union ubcore_eid eid;
	enum udma_sgid_type type;
};

int udma_add_ueid(struct ubcore_device *dev, uint16_t fe_idx, struct ubcore_ueid_cfg *cfg);
int udma_delete_ueid(struct ubcore_device *dev, uint16_t fe_idx,
		     struct ubcore_ueid_cfg *cfg);
int udma_find_eid_idx(struct udma_dev *dev, union ubcore_eid eid);

static inline enum udma_sgid_type get_sgid_type_from_eid(union ubcore_eid eid)
{
	if (eid.in4.reserved == 0 && eid.in4.prefix == htonl(UDMA_IPV4_MAP_IPV6_PREFIX))
		return SGID_TYPE_IPV4;
	return SGID_TYPE_IPV6;
}

static inline void udma_ipv4_map_to_eid(uint32_t ipv4, union ubcore_eid *eid)
{
	eid->in4.reserved = 0;
	eid->in4.prefix = cpu_to_be32(UDMA_IPV4_MAP_IPV6_PREFIX);
	eid->in4.addr = ipv4;
}

#endif /* _UDMA_EID_H */
