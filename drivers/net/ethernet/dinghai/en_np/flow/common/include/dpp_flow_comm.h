/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_FLOW_COMM_H
#define DPP_FLOW_COMM_H

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_dev.h"
#include "dpp_dtb.h"
#include "dpp_tbl_comm.h"

#define DPP_ATTR_FLAG_KEY (0 << 0)
#define DPP_ATTR_FLAG_MASK (1 << 0)
#define DPP_ATTR_FLAG_RST (1 << 1)

enum dpp_flow_sdt_type_e {
	DPP_FLOW_SDT_INVALID = 0,
	DPP_FLOW_SDT_ERAM = 1,
	DPP_FLOW_SDT_DDR = 2,
	DPP_FLOW_SDT_HASH = 3,
	DPP_FLOW_SDT_LPM = 4,
	DPP_FLOW_SDT_ACL = 5,
	DPP_FLOW_SDT_MAX = 6,
};

struct zxdh_flow_attr_field_t {
	char *p_field_name;
	u32 flags;
	u16 array_num;
	u32 element_size;
	u16 msb_pos;
	u16 len;
};

struct zxdh_flow_attr_t {
	char *attr_name;
	u32 sdt_no;
	u32 table_type;
	u32 width;
	u32 key_width;
	u32 rst_width;
	u32 field_num;
	struct zxdh_flow_attr_field_t *p_fields;
};

DPP_STATUS dpp_apt_dtb_eram_get_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index,
				   void *pData);
DPP_STATUS dpp_apt_dtb_eram_insert_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index,
				      void *pData);
DPP_STATUS dpp_apt_dtb_eram_clear_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index);

DPP_STATUS dpp_apt_dtb_hash_search_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData);
DPP_STATUS dpp_apt_dtb_hash_insert_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData);
DPP_STATUS dpp_apt_dtb_hash_delete_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData);

DPP_STATUS dpp_apt_dtb_acl_entry_search_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					   u32 handle, void *pData);
DPP_STATUS dpp_apt_dtb_acl_entry_get_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 handle,
					void *pData);
DPP_STATUS dpp_apt_dtb_acl_entry_insert_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					   u32 handle, void *pData);
DPP_STATUS dpp_apt_dtb_acl_entry_del_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					u32 handle);
u32 dpp_flow_attr_list_size_get(void);

#endif
