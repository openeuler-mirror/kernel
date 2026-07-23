// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_flow_comm.h"
#include "dpp_dtb_table_api.h"
#include "dpp_se_api.h"
#include "dpp_etcam.h"
#include "dpp_dtb_cfg.h"
#include "dpp_dtb_table.h"
#include "dpp_se.h"

extern struct zxdh_flow_attr_t g_flow_attr_list[];

struct zxdh_flow_attr_t *zxdh_flow_attr_get(u32 sdt_no)
{
	u32 index = 0;

	for (index = 0; index < dpp_flow_attr_list_size_get(); index++) {
		if (sdt_no == g_flow_attr_list[index].sdt_no)
			return &g_flow_attr_list[index];
	}

	return NULL;
}

static DPP_STATUS dpp_field_to_bitstream(struct zxdh_flow_attr_field_t *p_field, u32 width,
					 u8 *pData, u8 *p_buff, u32 *p_offset)
{
	DPP_STATUS rc = DPP_OK;
	u32 offset = 0;
	u32 element_width = 0; /*unit:bit*/
	u32 msb_temp = 0;
	u32 array_index = 0;
	u32 temp_data = 0;

	ZXIC_COMM_CHECK_POINT(p_field);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(p_buff);
	ZXIC_COMM_CHECK_POINT(p_offset);

	offset = *p_offset;

	for (array_index = 0; array_index < (p_field->array_num); array_index++) {
		element_width = (p_field->len) / (p_field->array_num);

		ZXIC_COMM_MEMCPY_S(&temp_data, p_field->element_size, pData + offset,
				   p_field->element_size);
		temp_data = temp_data & ZXIC_COMM_GET_BIT_MASK(u32, element_width);

		msb_temp = ((p_field->msb_pos) > (array_index * element_width)) ?
					 ((p_field->msb_pos) - (array_index * element_width)) :
					 0;

		rc = zxic_comm_write_bits_ex(p_buff, width, temp_data, msb_temp, element_width);
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_write_bits_ex");

		offset += p_field->element_size;
	}

	*p_offset = offset;

	return DPP_OK;
}

static DPP_STATUS dpp_bitstream_to_field(struct zxdh_flow_attr_field_t *p_field, u32 width,
					 u8 *pData, u8 *p_buff, u32 *p_offset)
{
	DPP_STATUS rc = DPP_OK;
	u32 offset = 0;
	u32 element_width = 0; /*unit:bit*/
	u32 msb_temp = 0;
	u32 array_index = 0;
	u32 temp_data = 0;

	ZXIC_COMM_CHECK_POINT(p_field);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(p_buff);
	ZXIC_COMM_CHECK_POINT(p_offset);

	offset = *p_offset;

	for (array_index = 0; array_index < (p_field->array_num); array_index++) {
		element_width = (p_field->len) / (p_field->array_num);

		msb_temp = ((p_field->msb_pos) > (array_index * element_width)) ?
					 ((p_field->msb_pos) - (array_index * element_width)) :
					 0;

		rc = zxic_comm_read_bits_ex(p_buff, width, &temp_data, msb_temp, element_width);
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_write_bits_ex");

		temp_data = temp_data & ZXIC_COMM_GET_BIT_MASK(u32, element_width);
		ZXIC_COMM_MEMCPY_S(pData + offset, p_field->element_size, &temp_data,
				   p_field->element_size);

		offset += p_field->element_size;
	}

	*p_offset = offset;

	return DPP_OK;
}

DPP_STATUS dpp_flow_eram_attr_to_bitstream(struct zxdh_flow_attr_t *p_flow_attr, void *pData,
					   struct dpp_dtb_eram_entry_info_t *eramEntry)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	u32 offset = 0;
	struct zxdh_flow_attr_field_t *p_field = NULL;

	ZXIC_COMM_CHECK_POINT(p_flow_attr);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(eramEntry);
	ZXIC_COMM_CHECK_POINT(eramEntry->p_data);

	for (index = 0; index < (p_flow_attr->field_num); index++) {
		p_field = p_flow_attr->p_fields + index;
		rc = dpp_field_to_bitstream(p_field, p_flow_attr->width, (u8 *)pData,
					    (u8 *)(eramEntry->p_data), &offset);
		ZXIC_COMM_CHECK_RC(rc, "dpp_field_to_bitstream");
	}

	zxic_comm_swap((u8 *)(eramEntry->p_data), p_flow_attr->width / 8);

	return DPP_OK;
}

static DPP_STATUS dpp_flow_hash_attr_to_bitstream(struct zxdh_flow_attr_t *p_flow_attr, void *pData,
						  struct dpp_dtb_hash_entry_info_t *hashEntry)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	u32 offset = 0;
	u32 width = 0;
	u32 flags = 0; /*key mask or rst*/
	u8 *p_buff = NULL;
	struct zxdh_flow_attr_field_t *p_field = NULL;

	ZXIC_COMM_CHECK_POINT(p_flow_attr);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(hashEntry);
	ZXIC_COMM_CHECK_POINT(hashEntry->p_actu_key);

	for (index = 0; index < (p_flow_attr->field_num); index++) {
		p_field = p_flow_attr->p_fields + index;
		flags = p_field->flags;
		if (flags == DPP_ATTR_FLAG_KEY) {
			width = p_flow_attr->key_width;
			p_buff = hashEntry->p_actu_key;
		} else if (flags == DPP_ATTR_FLAG_RST) {
			width = p_flow_attr->rst_width;
			p_buff = hashEntry->p_rst;
		}

		if (p_buff) {
			rc = dpp_field_to_bitstream(p_field, width, (u8 *)pData, p_buff, &offset);
			ZXIC_COMM_CHECK_RC(rc, "dpp_field_to_bitstream");
		}
	}

	return DPP_OK;
}

void dpp_acl_dtb_entry_print(struct dpp_dtb_acl_entry_info_t *aclEntry)
{
	u32 i = 0;

	ZXIC_COMM_TRACE_INFO("key_data:");

	for (i = 0; i < DPP_ETCAM_WIDTH_MAX / 8; i++)
		ZXIC_COMM_TRACE_INFO("%02x", aclEntry->key_data[i]);

	ZXIC_COMM_TRACE_INFO("\n");

	ZXIC_COMM_TRACE_INFO("key_mask:");

	for (i = 0; i < DPP_ETCAM_WIDTH_MAX / 8; i++)
		ZXIC_COMM_TRACE_INFO("%02x", aclEntry->key_mask[i]);

	ZXIC_COMM_TRACE_INFO("\n");

	ZXIC_COMM_TRACE_INFO("rst:");
	for (i = 0; i < (DPP_SMMU0_READ_REG_MAX_NUM * 4); i++)
		ZXIC_COMM_TRACE_INFO("%02x", aclEntry->p_as_rslt[i]);

	ZXIC_COMM_TRACE_INFO("\n");
}

static DPP_STATUS dpp_flow_acl_attr_to_bitstream(struct zxdh_flow_attr_t *p_flow_attr, void *pData,
						 struct dpp_dtb_acl_entry_info_t *aclEntry)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	u32 offset = 0;
	u32 width = 0;
	u32 flags = 0; /*key mask or rst*/
	u8 *p_buff = NULL;
	struct zxdh_flow_attr_field_t *p_field = NULL;

	ZXIC_COMM_CHECK_POINT(p_flow_attr);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(aclEntry);
	ZXIC_COMM_CHECK_POINT(aclEntry->key_data);
	ZXIC_COMM_CHECK_POINT(aclEntry->key_mask);

	for (index = 0; index < (p_flow_attr->field_num); index++) {
		p_field = p_flow_attr->p_fields + index;
		flags = p_field->flags;
		if (flags == DPP_ATTR_FLAG_KEY) {
			width = p_flow_attr->key_width;
			p_buff = aclEntry->key_data;
		} else if (flags == DPP_ATTR_FLAG_MASK) {
			width = p_flow_attr->key_width;
			p_buff = aclEntry->key_mask;
		} else if (flags == DPP_ATTR_FLAG_RST) {
			width = p_flow_attr->rst_width;
			p_buff = aclEntry->p_as_rslt;
		}

		if (p_buff) {
			rc = dpp_field_to_bitstream(p_field, width, (u8 *)pData, p_buff, &offset);
			ZXIC_COMM_CHECK_RC(rc, "dpp_field_to_bitstream");
		}
	}

	if (aclEntry->p_as_rslt)
		zxic_comm_swap((u8 *)(aclEntry->p_as_rslt), p_flow_attr->rst_width / 8);

	return DPP_OK;
}

static DPP_STATUS dpp_flow_eram_bitstream_to_attr(struct zxdh_flow_attr_t *p_flow_attr, void *pData,
						  struct dpp_dtb_eram_entry_info_t *eramEntry)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	u32 offset = 0;
	struct zxdh_flow_attr_field_t *p_field = NULL;

	ZXIC_COMM_CHECK_POINT(p_flow_attr);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(eramEntry);
	ZXIC_COMM_CHECK_POINT(eramEntry->p_data);

	zxic_comm_swap((u8 *)(eramEntry->p_data), p_flow_attr->width / 8);
	for (index = 0; index < (p_flow_attr->field_num); index++) {
		p_field = p_flow_attr->p_fields + index;
		rc = dpp_bitstream_to_field(p_field, p_flow_attr->width, (u8 *)pData,
					    (u8 *)(eramEntry->p_data), &offset);
		ZXIC_COMM_CHECK_RC(rc, "dpp_bitstream_to_field");
	}

	return DPP_OK;
}

static DPP_STATUS dpp_flow_hash_bitstream_to_attr(struct zxdh_flow_attr_t *p_flow_attr, void *pData,
						  struct dpp_dtb_hash_entry_info_t *hashEntry)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	u32 offset = 0;
	u32 width = 0;
	u32 flags = 0; /*key mask or rst*/
	u8 *p_buff = NULL;
	struct zxdh_flow_attr_field_t *p_field = NULL;

	ZXIC_COMM_CHECK_POINT(p_flow_attr);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(hashEntry);
	ZXIC_COMM_CHECK_POINT(hashEntry->p_actu_key);

	for (index = 0; index < (p_flow_attr->field_num); index++) {
		p_field = p_flow_attr->p_fields + index;
		flags = p_field->flags;
		if (flags == DPP_ATTR_FLAG_KEY) {
			width = p_flow_attr->key_width;
			p_buff = hashEntry->p_actu_key;
		} else if (flags == DPP_ATTR_FLAG_RST) {
			width = p_flow_attr->rst_width;
			p_buff = hashEntry->p_rst;
		}

		if (p_buff) {
			rc = dpp_bitstream_to_field(p_field, width, (u8 *)pData, p_buff, &offset);
			ZXIC_COMM_CHECK_RC(rc, "dpp_bitstream_to_field");
		}
	}

	return DPP_OK;
}

static DPP_STATUS dpp_flow_acl_bitstream_to_attr(struct zxdh_flow_attr_t *p_flow_attr, void *pData,
						 struct dpp_dtb_acl_entry_info_t *aclEntry)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	u32 offset = 0;
	u32 width = 0;
	u32 flags = 0; /*key mask or rst*/
	u8 *p_buff = NULL;
	struct zxdh_flow_attr_field_t *p_field = NULL;

	ZXIC_COMM_CHECK_POINT(p_flow_attr);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(aclEntry);
	ZXIC_COMM_CHECK_POINT(aclEntry->key_data);
	ZXIC_COMM_CHECK_POINT(aclEntry->key_mask);

	if (aclEntry->p_as_rslt)
		zxic_comm_swap((u8 *)(aclEntry->p_as_rslt), p_flow_attr->rst_width / 8);

	for (index = 0; index < (p_flow_attr->field_num); index++) {
		p_field = p_flow_attr->p_fields + index;
		flags = p_field->flags;
		if (flags == DPP_ATTR_FLAG_KEY) {
			width = p_flow_attr->key_width;
			p_buff = aclEntry->key_data;
		} else if (flags == DPP_ATTR_FLAG_MASK) {
			width = p_flow_attr->key_width;
			p_buff = aclEntry->key_mask;
		} else if (flags == DPP_ATTR_FLAG_RST) {
			width = p_flow_attr->rst_width;
			p_buff = aclEntry->p_as_rslt;
		}

		if (p_buff) {
			rc = dpp_bitstream_to_field(p_field, width, (u8 *)pData, p_buff, &offset);
			ZXIC_COMM_CHECK_RC(rc, "dpp_bitstream_to_field");
		}
	}

	return DPP_OK;
}

u32 dpp_flow_attr_to_bitstream(u32 sdt_no, void *pData, void *p_Entry)
{
	DPP_STATUS rc = DPP_OK;
	u32 flow_type = 0;
	struct zxdh_flow_attr_t *p_flow_attr = NULL;

	p_flow_attr = zxdh_flow_attr_get(sdt_no);
	ZXIC_COMM_CHECK_POINT(p_flow_attr);

	flow_type = p_flow_attr->table_type;
	switch (flow_type) {
	case DPP_FLOW_SDT_ERAM: {
		rc = dpp_flow_eram_attr_to_bitstream(p_flow_attr, pData,
						     (struct dpp_dtb_eram_entry_info_t *)p_Entry);
		ZXIC_COMM_CHECK_RC(rc, "dpp_flow_eram_attr_to_bitstream");
		break;
	}
	case DPP_FLOW_SDT_HASH: {
		rc = dpp_flow_hash_attr_to_bitstream(p_flow_attr, pData,
						     (struct dpp_dtb_hash_entry_info_t *)p_Entry);
		ZXIC_COMM_CHECK_RC(rc, "dpp_flow_hash_attr_to_bitstream");
		break;
	}
	case DPP_FLOW_SDT_ACL: {
		rc = dpp_flow_acl_attr_to_bitstream(p_flow_attr, pData,
						    (struct dpp_dtb_acl_entry_info_t *)p_Entry);
		ZXIC_COMM_CHECK_RC(rc, "dpp_flow_acl_attr_to_bitstream");

		dpp_acl_dtb_entry_print((struct dpp_dtb_acl_entry_info_t *)p_Entry);
		break;
	}
	default: {
		ZXIC_COMM_TRACE_ERROR("[%s]:sdt[%u] flow_type[%u] error!\n", __func__, sdt_no,
				      flow_type);
		return DPP_ERR;
	}
	}

	return DPP_OK;
}

u32 dpp_flow_bitstream_to_attr(u32 sdt_no, void *pData, void *p_Entry)
{
	DPP_STATUS rc = DPP_OK;
	u32 flow_type = 0;
	struct zxdh_flow_attr_t *p_flow_attr = NULL;

	p_flow_attr = zxdh_flow_attr_get(sdt_no);
	ZXIC_COMM_CHECK_POINT(p_flow_attr);

	flow_type = p_flow_attr->table_type;
	switch (flow_type) {
	case DPP_FLOW_SDT_ERAM: {
		rc = dpp_flow_eram_bitstream_to_attr(p_flow_attr, pData,
						     (struct dpp_dtb_eram_entry_info_t *)p_Entry);
		ZXIC_COMM_CHECK_RC(rc, "dpp_flow_eram_bitstream_to_attr");
		break;
	}
	case DPP_FLOW_SDT_HASH: {
		rc = dpp_flow_hash_bitstream_to_attr(p_flow_attr, pData,
						     (struct dpp_dtb_hash_entry_info_t *)p_Entry);
		ZXIC_COMM_CHECK_RC(rc, "dpp_flow_hash_bitstream_to_attr");
		break;
	}
	case DPP_FLOW_SDT_ACL: {
		rc = dpp_flow_acl_bitstream_to_attr(p_flow_attr, pData,
						    (struct dpp_dtb_acl_entry_info_t *)p_Entry);
		ZXIC_COMM_CHECK_RC(rc, "dpp_flow_acl_bitstream_to_attr");
		break;
	}
	default: {
		ZXIC_COMM_TRACE_ERROR("[%s]:sdt[%u] flow_type[%u] error!\n", __func__, sdt_no,
				      flow_type);
		return DPP_ERR;
	}
	}

	return DPP_OK;
}

DPP_STATUS dpp_apt_dtb_eram_get_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index,
				   void *pData)
{
	u32 rc = DPP_OK;
	u32 dump_data[DPP_SMMU0_READ_REG_MAX_NUM] = { 0 };

	struct dpp_dtb_eram_entry_info_t dump_eram_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	ZXIC_COMM_MEMSET_S(dump_data, sizeof(dump_data), 0x00, sizeof(dump_data));

	dump_eram_entry.index = index;
	dump_eram_entry.p_data = dump_data;
	rc = dpp_dtb_eram_data_get(dev, queue_id, sdt_no, &dump_eram_entry);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_eram_data_get");

	rc = dpp_flow_bitstream_to_attr(sdt_no, pData, &dump_eram_entry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_bitstream_to_attr");

	return rc;
}

DPP_STATUS dpp_apt_dtb_eram_insert_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index,
				      void *pData)
{
	u32 rc = DPP_OK;
	u32 element_id = 0;
	u32 dump_data[DPP_SMMU0_READ_REG_MAX_NUM] = { 0 };

	struct dpp_dtb_eram_entry_info_t dtb_eram_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	ZXIC_COMM_MEMSET_S(dump_data, sizeof(dump_data), 0x00, sizeof(dump_data));

	dtb_eram_entry.index = index;
	dtb_eram_entry.p_data = dump_data;

	rc = dpp_flow_attr_to_bitstream(sdt_no, pData, &dtb_eram_entry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_attr_to_bitstream");

	dtb_eram_entry.index = index;
	dtb_eram_entry.p_data = dump_data;
	rc = dpp_dtb_eram_dma_write(dev, queue_id, sdt_no, 1, &dtb_eram_entry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_eram_dma_write");

	return rc;
}

DPP_STATUS dpp_apt_dtb_eram_clear_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index)
{
	u32 rc = DPP_OK;
	u32 element_id = 0;
	u32 dump_data[DPP_SMMU0_READ_REG_MAX_NUM] = { 0 };

	struct dpp_dtb_eram_entry_info_t dtb_eram_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	ZXIC_COMM_MEMSET_S(dump_data, sizeof(dump_data), 0x00, sizeof(dump_data));

	dtb_eram_entry.index = index;
	dtb_eram_entry.p_data = dump_data;
	rc = dpp_dtb_eram_dma_write(dev, queue_id, sdt_no, 1, &dtb_eram_entry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_eram_dma_write");

	return rc;
}

DPP_STATUS dpp_apt_dtb_hash_search_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData)
{
	DPP_STATUS rc = DPP_OK;

	struct dpp_dtb_hash_entry_info_t tDtbHashEntry = { 0 };
	u8 key[HASH_KEY_MAX] = { 0 };
	u8 rst[HASH_RST_MAX] = { 0 };
	u32 srch_mode = HASH_SRH_MODE_HDW;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	tDtbHashEntry.p_actu_key = key;
	tDtbHashEntry.p_rst = rst;

	rc = dpp_flow_attr_to_bitstream(sdt_no, pData, &tDtbHashEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_attr_to_bitstream");

	rc = dpp_dtb_hash_data_get(dev, queue_id, sdt_no, &tDtbHashEntry, srch_mode);
	if (rc != DPP_OK) {
		if (rc == DPP_HASH_RC_SRH_FAIL) {
			ZXIC_COMM_PRINT("There is no such hash!\n");
			return DPP_HASH_RC_SRH_FAIL;
		}
		return DPP_ERR;
	}

	rc = dpp_flow_bitstream_to_attr(sdt_no, pData, &tDtbHashEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_bitstream_to_attr");

	return rc;
}

DPP_STATUS dpp_apt_dtb_hash_insert_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_dtb_hash_entry_info_t tDtbHashEntry = { 0 };
	u32 element_id = 0;
	u8 key[HASH_KEY_MAX] = { 0 };
	u8 rst[HASH_RST_MAX] = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	tDtbHashEntry.p_actu_key = key;
	tDtbHashEntry.p_rst = rst;

	rc = dpp_flow_attr_to_bitstream(sdt_no, pData, &tDtbHashEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_attr_to_bitstream");

	rc = dpp_dtb_hash_dma_insert(dev, queue_id, sdt_no, 1, &tDtbHashEntry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_hash_dma_insert");

	return rc;
}

DPP_STATUS dpp_apt_dtb_hash_delete_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_dtb_hash_entry_info_t tDtbHashEntry = { 0 };
	u32 element_id = 0;
	u8 key[HASH_KEY_MAX] = { 0 };
	u8 rst[HASH_RST_MAX] = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	tDtbHashEntry.p_actu_key = key;
	tDtbHashEntry.p_rst = rst;

	rc = dpp_flow_attr_to_bitstream(sdt_no, pData, &tDtbHashEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_attr_to_bitstream");

	rc = dpp_dtb_hash_dma_delete(dev, queue_id, sdt_no, 1, &tDtbHashEntry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_hash_dma_delete");

	return rc;
}

DPP_STATUS dpp_apt_dtb_acl_entry_search_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					   u32 handle, void *pData)
{
	u32 rc = DPP_OK;
	struct dpp_dtb_acl_entry_info_t tDtbAclEntry = { 0 };
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 rst[DPP_SMMU0_READ_REG_MAX_NUM * 4] = { 0 }; /*128bit*/

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(pData);

	ZXIC_COMM_MEMSET_S(&tDtbAclEntry, sizeof(struct dpp_dtb_acl_entry_info_t), 0x0,
			   sizeof(struct dpp_dtb_acl_entry_info_t));
	ZXIC_COMM_MEMSET_S(data, sizeof(data), 0x0, sizeof(data));
	ZXIC_COMM_MEMSET_S(mask, sizeof(mask), 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET_S(rst, sizeof(rst), 0x0, sizeof(rst));
	tDtbAclEntry.key_data = data;
	tDtbAclEntry.key_mask = mask;
	tDtbAclEntry.p_as_rslt = rst;

	rc = dpp_flow_attr_to_bitstream(sdt_no, pData, &tDtbAclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_attr_to_bitstream");

	tDtbAclEntry.handle = handle;

	rc = dpp_dtb_acl_data_get(dev, queue_id, sdt_no, &tDtbAclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_acl_data_get");

	dpp_acl_dtb_entry_print(&tDtbAclEntry);

	rc = dpp_flow_bitstream_to_attr(sdt_no, pData, &tDtbAclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_bitstream_to_attr");

	return rc;
}

DPP_STATUS dpp_apt_dtb_acl_entry_get_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 handle,
					void *pData)
{
	u32 rc = DPP_OK;
	struct dpp_dtb_acl_entry_info_t tDtbAclEntry = { 0 };
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 rst[DPP_SMMU0_READ_REG_MAX_NUM * 4] = { 0 }; /*128bit*/

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(pData);

	ZXIC_COMM_MEMSET_S(&tDtbAclEntry, sizeof(struct dpp_dtb_acl_entry_info_t), 0x0,
			   sizeof(struct dpp_dtb_acl_entry_info_t));
	ZXIC_COMM_MEMSET_S(data, sizeof(data), 0x0, sizeof(data));
	ZXIC_COMM_MEMSET_S(mask, sizeof(mask), 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET_S(rst, sizeof(rst), 0x0, sizeof(rst));
	tDtbAclEntry.key_data = data;
	tDtbAclEntry.key_mask = mask;
	tDtbAclEntry.p_as_rslt = rst;

	tDtbAclEntry.handle = handle;

	rc = dpp_dtb_etcam_data_get(dev, queue_id, sdt_no, &tDtbAclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_acl_data_get");

	dpp_acl_dtb_entry_print(&tDtbAclEntry);

	rc = dpp_flow_bitstream_to_attr(sdt_no, pData, &tDtbAclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_bitstream_to_attr");

	return rc;
}

DPP_STATUS dpp_apt_dtb_acl_entry_insert_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					   u32 handle, void *pData)
{
	u32 rc = DPP_OK;
	u32 element_id = 0;
	struct dpp_dtb_acl_entry_info_t tDtbAclEntry = { 0 };
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 rst[DPP_SMMU0_READ_REG_MAX_NUM * 4] = { 0 }; /*128bit*/

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(pData);

	ZXIC_COMM_MEMSET_S(&tDtbAclEntry, sizeof(struct dpp_dtb_acl_entry_info_t), 0x0,
			   sizeof(struct dpp_dtb_acl_entry_info_t));
	ZXIC_COMM_MEMSET_S(data, sizeof(data), 0x0, sizeof(data));
	ZXIC_COMM_MEMSET_S(mask, sizeof(mask), 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET_S(rst, sizeof(rst), 0x0, sizeof(rst));
	tDtbAclEntry.key_data = data;
	tDtbAclEntry.key_mask = mask;
	tDtbAclEntry.p_as_rslt = rst;

	rc = dpp_flow_attr_to_bitstream(sdt_no, pData, &tDtbAclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_flow_attr_to_bitstream");

	tDtbAclEntry.handle = handle;

	rc = dpp_dtb_acl_dma_insert(dev, queue_id, sdt_no, 1, &tDtbAclEntry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_acl_dma_insert");

	return rc;
}

DPP_STATUS dpp_apt_dtb_acl_entry_del_ex(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 handle)
{
	u32 rc = DPP_OK;
	u32 element_id = 0;
	struct dpp_dtb_acl_entry_info_t tDtbAclEntry = { 0 };
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 rst[DPP_SMMU0_READ_REG_MAX_NUM * 4] = { 0 }; /*128bit*/

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	ZXIC_COMM_MEMSET_S(&tDtbAclEntry, sizeof(struct dpp_dtb_acl_entry_info_t), 0x0,
			   sizeof(struct dpp_dtb_acl_entry_info_t));
	ZXIC_COMM_MEMSET_S(data, sizeof(data), 0xff, sizeof(data));
	ZXIC_COMM_MEMSET_S(mask, sizeof(mask), 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET_S(rst, sizeof(rst), 0xff, sizeof(rst));

	tDtbAclEntry.handle = handle;
	tDtbAclEntry.key_data = data;
	tDtbAclEntry.key_mask = mask;
	tDtbAclEntry.p_as_rslt = rst;

	rc = dpp_dtb_acl_dma_insert(dev, queue_id, sdt_no, 1, &tDtbAclEntry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_acl_dma_insert");

	return rc;
}
