// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/kernel.h>
#include <linux/ummu_core.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include "udma_dev.h"
#include "udma_cmd.h"
#include "udma_common.h"
#include <ub/urma/ubcore_types.h>
#include "udma_eid.h"

static void udma_dispatch_eid_event(struct udma_dev *udma_dev,
				    struct udma_ctrlq_eid_info *eid_entry,
				    enum ubcore_mgmt_event_type type)
{
	struct ubcore_mgmt_event event = {};
	struct ubcore_eid_info info = {};

	udma_swap_endian(eid_entry->eid.raw, info.eid.raw, sizeof(union ubcore_eid));
	info.eid_index = eid_entry->eid_idx;

	event.ub_dev = &udma_dev->ub_dev;
	event.element.eid_info = &info;
	event.event_type = type;
	ubcore_dispatch_mgmt_event(&event);
}

int udma_add_one_eid(struct udma_dev *udma_dev, struct udma_ctrlq_eid_info *eid_info)
{
	struct udma_ctrlq_eid_info *eid_entry;
	eid_t ummu_eid = 0;
	guid_t guid = {};
	int ret;

	eid_entry = (struct udma_ctrlq_eid_info *)
		xa_load(&udma_dev->eid_table, eid_info->eid_idx);
	if (eid_entry) {
		if (memcmp(eid_entry->eid.raw, eid_info->eid.raw, sizeof(eid_entry->eid.raw))) {
			dev_err(udma_dev->dev, "eid exist and does not match, index = %u.\n",
				eid_info->eid_idx);
			return -EINVAL;
		}
		dev_info(udma_dev->dev, "eid exist, index = %u.\n", eid_info->eid_idx);
		return 0;
	}

	eid_entry = kzalloc(sizeof(struct udma_ctrlq_eid_info), GFP_KERNEL);
	if (!eid_entry)
		return -ENOMEM;

	memcpy(eid_entry, eid_info, sizeof(struct udma_ctrlq_eid_info));
	ret = xa_err(xa_store(&udma_dev->eid_table, eid_info->eid_idx, eid_entry, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev,
			"save eid entry failed, ret = %d, eid index = %u.\n",
			ret, eid_info->eid_idx);
		goto store_err;
	}

	if (!udma_dev->is_ue) {
		(void)memcpy(&ummu_eid, eid_info->eid.raw, sizeof(ummu_eid));
		ret = ummu_core_add_eid(&guid, ummu_eid, EID_NONE);
		if (ret) {
			dev_err(udma_dev->dev,
				"set ummu eid entry failed, ret is %d.\n", ret);
			goto err_add_ummu_eid;
		}
	}
	udma_dispatch_eid_event(udma_dev, eid_entry, UBCORE_MGMT_EVENT_EID_ADD);

	return ret;
err_add_ummu_eid:
	xa_erase(&udma_dev->eid_table, eid_info->eid_idx);
store_err:
	kfree(eid_entry);

	return ret;
}

int udma_del_one_eid(struct udma_dev *udma_dev, struct udma_ctrlq_eid_info *eid_info)
{
	struct udma_ctrlq_eid_info *eid_entry;
	uint32_t index = eid_info->eid_idx;
	eid_t ummu_eid = 0;
	guid_t guid = {};

	eid_entry = (struct udma_ctrlq_eid_info *)xa_load(&udma_dev->eid_table, index);
	if (!eid_entry) {
		dev_err(udma_dev->dev, "get EID entry failed, EID index = %u.\n",
			index);
		return -EINVAL;
	}
	if (memcmp(eid_entry->eid.raw, eid_info->eid.raw, sizeof(eid_entry->eid.raw))) {
		dev_err(udma_dev->dev, "EID is not match, index = %u.\n", index);
		return -EINVAL;
	}
	xa_erase(&udma_dev->eid_table, index);

	if (!udma_dev->is_ue) {
		(void)memcpy(&ummu_eid, eid_entry->eid.raw, sizeof(ummu_eid));
		ummu_core_del_eid(&guid, ummu_eid, EID_NONE);
	}
	udma_dispatch_eid_event(udma_dev, eid_entry, UBCORE_MGMT_EVENT_EID_RMV);
	kfree(eid_entry);

	return 0;
}

static int udma_send_query_eid_cmd(struct udma_dev *udma_dev,
				   struct udma_ctrlq_eid_out_query *eid_out_query)
{
#define UDMA_CMD_CTRLQ_QUERY_SEID 0xb5
	struct udma_ctrlq_eid_in_query eid_in_query = {};
	struct ubase_ctrlq_msg msg = {};
	int ret;

	msg.opcode = UDMA_CTRLQ_GET_SEID_INFO;
	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER;
	msg.need_resp = 1;
	msg.is_resp = 0;
	msg.in_size = sizeof(eid_in_query);
	msg.in = &eid_in_query;
	msg.out_size = sizeof(*eid_out_query);
	msg.out = eid_out_query;
	eid_in_query.cmd = UDMA_CMD_CTRLQ_QUERY_SEID;

	ret = ubase_ctrlq_send_msg(udma_dev->comdev.adev, &msg);
	if (ret)
		dev_err(udma_dev->dev,
			"query seid from ctrl cpu failed, ret = %d.\n", ret);

	return ret;
}

int udma_query_eid_from_ctrl_cpu(struct udma_dev *udma_dev)
{
	struct udma_ctrlq_eid_out_query eid_out_query = {};
	int ret, ret_tmp, i;

	ret = udma_send_query_eid_cmd(udma_dev, &eid_out_query);
	if (ret) {
		dev_err(udma_dev->dev, "query EID failed, ret = %d.\n", ret);
		return ret;
	}

	if (eid_out_query.seid_num > UDMA_CTRLQ_SEID_NUM) {
		dev_err(udma_dev->dev, "Invalid param: source EID num is %u.\n",
			eid_out_query.seid_num);
		return -EINVAL;
	}

	mutex_lock(&udma_dev->eid_mutex);
	for (i = 0; i < (int)eid_out_query.seid_num; i++) {
		if (eid_out_query.eids[i].eid_idx >= SEID_TABLE_SIZE) {
			dev_err(udma_dev->dev, "invalid EID index = %u.\n",
				eid_out_query.eids[i].eid_idx);
			goto err_add_ummu_eid;
		}
		ret = udma_add_one_eid(udma_dev, &(eid_out_query.eids[i]));
		if (ret) {
			dev_err(udma_dev->dev, "Add EID failed, ret = %d, eid_idx = %u.\n",
				ret, eid_out_query.eids[i].eid_idx);
			goto err_add_ummu_eid;
		}
	}
	mutex_unlock(&udma_dev->eid_mutex);

	return 0;
err_add_ummu_eid:
	for (i--; i >= 0; i--) {
		ret_tmp = udma_del_one_eid(udma_dev, &eid_out_query.eids[i]);
		if (ret_tmp)
			dev_err(udma_dev->dev, "Delete EID failed, ret = %d, IDX = %u.\n",
				ret_tmp, eid_out_query.eids[i].eid_idx);
	}
	mutex_unlock(&udma_dev->eid_mutex);

	return ret;
}

int udma_add_one_eid_guid(struct udma_dev *udma_dev,
			  struct udma_ctrlq_ue_eid_guid_out *eid_guid_info)
{
	struct udma_ctrlq_ue_eid_guid_out *eid_guid_entry;
	uint32_t eid_guid_idx;
	eid_t ummu_eid = 0;
	guid_t guid = {};
	int ret;

	if (eid_guid_info->ue_id >= (1U << (UDMA_BITS_PER_INT - UDMA_EID_GUID_INDEX_OFFSET))) {
		dev_err(udma_dev->dev, "ue id %u is too large.\n", eid_guid_info->ue_id);
		return -EINVAL;
	}

	eid_guid_idx = eid_guid_info->ue_id << UDMA_EID_GUID_INDEX_OFFSET |
		       eid_guid_info->eid_info.eid_idx;

	eid_guid_entry = (struct udma_ctrlq_ue_eid_guid_out *)
		xa_load(&udma_dev->eid_guid_table, eid_guid_idx);
	if (eid_guid_entry) {
		if (memcmp(eid_guid_entry->eid_info.eid.raw, eid_guid_info->eid_info.eid.raw,
		    sizeof(eid_guid_entry->eid_info.eid.raw))) {
			dev_err(udma_dev->dev, "eid-guid exist and does not match, index = %u.\n",
				eid_guid_idx);
			return -EINVAL;
		}
		dev_info(udma_dev->dev, "eid-guid exist, index = %u.\n", eid_guid_idx);
		return 0;
	}

	eid_guid_entry = kzalloc(sizeof(*eid_guid_entry), GFP_KERNEL);
	if (!eid_guid_entry)
		return -ENOMEM;

	memcpy(eid_guid_entry, eid_guid_info, sizeof(*eid_guid_entry));

	ret = xa_err(xa_store(&udma_dev->eid_guid_table, eid_guid_idx,
			     eid_guid_entry, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev,
				"save eid_guid failed, ret = %d, eid_guid_index = %u.\n",
				ret, eid_guid_idx);
		goto store_err;
	}

	(void)memcpy(&ummu_eid, eid_guid_info->eid_info.eid.raw, sizeof(ummu_eid));
	(void)memcpy(&guid, &eid_guid_info->ue_guid, sizeof(guid));
	ret = ummu_core_add_eid(&guid, ummu_eid, EID_NONE);
	if (ret) {
		dev_err(udma_dev->dev,
				"set ummu eid entry failed, ret is %d.\n", ret);
		goto err_add_ummu_eid;
	}

	return ret;
err_add_ummu_eid:
	xa_erase(&udma_dev->eid_guid_table, eid_guid_idx);
store_err:
	kfree(eid_guid_entry);

	return ret;
}

void udma_del_eid_guid_by_ue_id(struct udma_dev *udma_dev, uint32_t ue_id)
{
	struct udma_ctrlq_ue_eid_guid_out *eid_guid_entry;
	unsigned long index = 0;
	eid_t ummu_eid = 0;
	guid_t guid = {};

	mutex_lock(&udma_dev->eid_guid_mutex);
	xa_for_each(&udma_dev->eid_guid_table, index, eid_guid_entry) {
		if (index >> UDMA_EID_GUID_INDEX_OFFSET == ue_id) {
			__xa_erase(&udma_dev->eid_guid_table, index);
			(void)memcpy(&guid, &eid_guid_entry->ue_guid, sizeof(guid));
			(void)memcpy(&ummu_eid, eid_guid_entry->eid_info.eid.raw, sizeof(ummu_eid));
			ummu_core_del_eid(&guid, ummu_eid, EID_NONE);
			kfree(eid_guid_entry);
		}
	}
	mutex_unlock(&udma_dev->eid_guid_mutex);
}

int udma_del_one_eid_guid(struct udma_dev *udma_dev,
			  struct udma_ctrlq_ue_eid_guid_out *eid_guid_info)
{
	struct udma_ctrlq_ue_eid_guid_out *eid_guid_entry;
	uint32_t eid_guid_idx;
	eid_t ummu_eid = 0;
	guid_t guid = {};

	eid_guid_idx = eid_guid_info->ue_id << UDMA_EID_GUID_INDEX_OFFSET |
		       eid_guid_info->eid_info.eid_idx;
	eid_guid_entry = (struct udma_ctrlq_ue_eid_guid_out *)
		xa_load(&udma_dev->eid_guid_table, eid_guid_idx);
	if (!eid_guid_entry) {
		dev_err(udma_dev->dev, "get UE EID-guid failed, index = %u.\n",
			eid_guid_idx);
		return -EINVAL;
	}
	if (memcmp(eid_guid_entry->eid_info.eid.raw, eid_guid_info->eid_info.eid.raw,
		   sizeof(eid_guid_entry->eid_info.eid.raw))) {
		dev_err(udma_dev->dev, "UE EID is not match, index = %u.\n",
			eid_guid_idx);
		return -EINVAL;
	}
	if (memcmp(&eid_guid_entry->ue_guid, &eid_guid_info->ue_guid,
		   sizeof(eid_guid_entry->ue_guid))) {
		dev_err(udma_dev->dev, "UE guid is not match, index = %u.\n",
			eid_guid_idx);
		return -EINVAL;
	}
	xa_erase(&udma_dev->eid_guid_table, eid_guid_idx);

	(void)memcpy(&guid, &eid_guid_entry->ue_guid, sizeof(guid));
	(void)memcpy(&ummu_eid, eid_guid_entry->eid_info.eid.raw, sizeof(ummu_eid));
	ummu_core_del_eid(&guid, ummu_eid, EID_NONE);

	kfree(eid_guid_entry);

	return 0;
}
