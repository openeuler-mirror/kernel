// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus entity: " fmt

#include <linux/dma-mapping.h>
#include <linux/list_sort.h>

#include "ubus.h"
#include "sysfs.h"
#include "msg.h"
#include "enum.h"
#include "route.h"
#include "port.h"
#include "eid.h"
#include "cna.h"
#include "resource.h"
#include "memory.h"
#include "ubus_controller.h"
#include "ubus_driver.h"
#include "ubus_inner.h"
#include "cap.h"
#include "eu.h"
#include "instance.h"
#include "task.h"
#include "ubus_entity.h"

/*
 * Entity lifecycle
 *
 * init process: {ub_alloc_ent -> ub_setup_ent -> ub_entity_add -> ub_start_ent}
 *
 * uninit process: {ub_stop_ent -> ub_remove_ent}
 */

#define UENT_NUM_START 1
#define UENT_NUM_END 0xfffff
#define UB_DEFAULT_MAX_SEG_SIZE SZ_64K

struct ub_entity *ub_alloc_ent(void)
{
	struct ub_entity *uent;

	uent = kzalloc(sizeof(*uent), GFP_KERNEL);
	if (!uent)
		return NULL;

	INIT_LIST_HEAD(&uent->node);
	INIT_LIST_HEAD(&uent->mue_list);
	INIT_LIST_HEAD(&uent->ue_list);
	INIT_LIST_HEAD(&uent->cna_list);
	INIT_LIST_HEAD(&uent->slot_list);
	INIT_LIST_HEAD(&uent->instance_node);

	mutex_init(&uent->active_mutex);

	uent->dev.type = &ub_dev_type;
	uent->cna = 0;
	uent->tid = 0; /* default tid according to ummu */
	ub_entity_assign_priv_flag(uent, UB_ENTITY_DETACHED, true);

	return uent;
}
EXPORT_SYMBOL_GPL(ub_alloc_ent);

static DEFINE_IDA(uent_num_ida);
static void ub_entity_num_free(struct ub_entity *uent)
{
	ida_free(&uent_num_ida, uent->uent_num);
}

static int ub_entity_num_alloc(void)
{
	return ida_alloc_range(&uent_num_ida, UENT_NUM_START, UENT_NUM_END,
			       GFP_KERNEL);
}

static int ub_get_guid(struct ub_entity *uent)
{
	char buf[SZ_64] = {};
	struct ub_guid guid;
	u16 code;
	int ret;

	if (is_primary(uent) && !uent->pool)
		return 0;

	if (!uent->pool || uent_type(uent->pue) == UB_TYPE_ICONTROLLER) {
		uent_type(uent) = uent_type(uent->pue);
		ret = ub_cfg_read_guid(uent, uent->guid.dw);
		if (ret)
			return ret;
	}

	if (uent->pool && uent_type(uent) == UB_TYPE_CONTROLLER) {
		ret = ub_cfg_read_guid(uent, guid.dw);
		if (ret)
			return ret;

		if (!guid_equal(&uent->guid.id, &guid.id)) {
			(void)ub_show_guid(&guid, buf);
			ub_err(uent, "pool pld guid is not equal entity guid %s\n",
			       buf);
			return -EINVAL;
		}
	}

	ret = ub_cfg_read_word(uent, UB_CLASS_CODE, &code);
	if (ret)
		return ret;

	uent->class_code = code;
	ub_entity_type_init(uent);
	if (!ub_type_valid(uent, false))
		return -EINVAL;
	return 0;
}

static void ub_config_upi(struct ub_entity *uent)
{
	struct device *dev;
	int ret;
	u16 upi;

	if (is_p_device(uent))
		return;

	if (is_ibus_controller(uent) && uent->ubc->cluster) {
		dev = &uent->ubc->dev;
		ret = ub_cfg_read_word(uent, UB_UPI, &upi);
		if (ret) {
			dev_err(dev, "update cluster upi failed, ret=%d\n", ret);
			return;
		}

		upi &= UB_UPI_MASK;
		if (upi) {
			dev_info(dev, "update cluster ubc upi, upi=%#x\n", upi);
			uent->upi = upi;
		}
		return;
	}

	ret = ub_cfg_write_dword(uent, UB_UPI, uent->upi);
	if (ret)
		ub_err(uent, "cfg upi failed, ret=%d\n", ret);
}

static void ub_res_space_prepare(struct ub_entity *pue)
{
	u32 source_support_map[MAX_UB_RES_NUM] = { UB_ERS0S_SUPPORT,
						   UB_ERS1S_SUPPORT,
						   UB_ERS2S_SUPPORT };
	u32 support_feature = 0;
	int i;

	if (ub_cfg_read_dword(pue, UB_CFG1_SUPPORT_FEATURE_L, &support_feature)) {
		ub_err(pue, "read cfg1 support feature failed\n");
		return;
	}

	if (is_idev(pue) || is_ibus_controller(pue)) {
		if (!(support_feature & UB_UBBAS_SUPPORT))
			return;

		for (i = 0; i < MAX_UB_RES_NUM; i++)
			if (support_feature & source_support_map[i])
				pue->zone[i].ubba_used = 1;
		return;
	}

	for (i = 0; i < MAX_UB_RES_NUM; i++) {
		if (!(support_feature & source_support_map[i]))
			continue;

		pue->zone[i].sa_used = 1;
		if (is_p_device(pue))
			pue->zone[i].res.flags = IORESOURCE_MEM;
	}
}

static int ub_setup_ent_primary(struct ub_entity *uent)
{
	int ret;

	if (uent->ent_type == UB_ENT_UNKNOWN) {
		ub_err(uent, "ignore unknown entity type, type=%#x, class=%#x\n",
		       uent_type(uent), uent_class(uent));
		return -EIO;
	}

	ub_res_space_prepare(uent);

	if (is_p_device(uent))
		return 0;

	ret = ub_cfg_read_word(uent, UB_TOTAL_NUMBER_ENTITIES,
			       (u16 *)&uent->total_funcs);
	if (ret) {
		ub_err(uent, "get UB_TOTAL_NUMBER_ENTITIES failed, ret=%d\n", ret);
		return ret;
	}

	if (!uent->total_funcs) {
		ub_err(uent, "total_funcs is zero\n");
		return -EINVAL;
	}
	/* Number of Entities presented to users, except Entity0. */
	uent->total_funcs -= 1;

	return 0;
}

static int ub_setup_ent_normal(struct ub_entity *uent)
{
	uent->dev.parent = &uent->pue->dev;
	return 0;
}

static int ub_uent_cfg(struct ub_entity *uent, u32 uent_num)
{
	struct ub_guid *guid = &uent->guid;
	char buf[SZ_64] = {};
	int ret;

	dev_set_name(&uent->dev, "%05x", uent_num);
	uent->uent_num = uent_num;
	uent->dev.bus = &ub_bus_type;
	/* Card driver set to 64bit if support */
	uent->dma_mask = GENMASK(31, 0);

	(void)ub_show_guid(guid, buf);
	ub_info(uent, "guid=%s\n", buf);

	if (is_primary(uent) || is_p_device(uent))
		ret = ub_setup_ent_primary(uent);
	else
		ret = ub_setup_ent_normal(uent);

	return ret;
}

static void ub_config_eid(struct ub_entity *uent)
{
	if (is_p_device(uent))
		return;

	if (is_ibus_controller(uent) && uent->ubc->cluster)
		return;

	ub_cfg_write_dword(uent, UB_EID_0, uent->eid);
}

static void ub_set_fm_info(struct ub_entity *uent)
{
	if (uent->entity_idx)
		return;

	if (uent->ubc->cluster && !is_idev(uent))
		return;

	ub_cfg_write_dword(uent, UB_FM_CNA, uent->ubc->uent->cna);
	ub_cfg_write_dword(uent, UB_FM_EID_0, uent->ubc->uent->eid);
}

static void ub_get_module_id(struct ub_entity *uent)
{
	int ret;
	u32 val;

	ret = ub_cfg_read_dword(uent, UB_MODULE, &val);
	if (ret) {
		ub_err(uent, "Get dev module failed %d\n", ret);
		return;
	}

	uent->mod_vendor = val >> SZ_16;
	uent->module = val & UB_MODULE_ID_MASK;
}

int ub_setup_ent(struct ub_entity *uent)
{
	int ret, uent_num;

	if (!uent)
		return -EINVAL;

	ret = message_probe_device(uent);
	if (ret) {
		ub_err(uent, "probe message failed, ret=%d\n", ret);
		return ret;
	}

	ret = ub_get_guid(uent);
	if (ret) {
		ub_err(uent, "get guid failed, ret=%d\n", ret);
		goto err_alloc;
	}

	ub_config_upi(uent);

	/* common setup */
	ret = ub_eid_alloc(uent);
	if (ret) {
		ub_err(uent, "alloc eid failed, ret=%d\n", ret);
		goto err_alloc;
	}

	uent_num = ub_entity_num_alloc();
	if (uent_num < 0) {
		ub_err(uent, "alloc dev uent_num failed, ret=%d\n", uent_num);
		ret = -ENOSPC;
		goto free_eid;
	}

	ret = ub_uent_cfg(uent, (u32)uent_num);
	if (ret)
		goto free_uent_num;

	ub_config_eid(uent);
	ub_set_cap_bitmap(uent);
	ub_set_fm_info(uent);
	ub_get_module_id(uent);

	ub_entity_assign_priv_flag(uent, UB_ENTITY_SETUP, true);
	return 0;
free_uent_num:
	ub_entity_num_free(uent);
free_eid:
	ub_eid_free(uent);
err_alloc:
	message_remove_device(uent);
	return ret;
}
EXPORT_SYMBOL_GPL(ub_setup_ent);

static void ub_configure_ent(struct ub_entity *uent)
{
	ub_eu_table_init(uent);
}

static void ub_unconfigure_ent(struct ub_entity *uent)
{
	ub_eu_table_uninit(uent);
}

static int ub_ue_sort_by_ent_idx(void *priv, const struct list_head *a,
				    const struct list_head *b)
{
	struct ub_entity *uent_a = container_of(a, struct ub_entity, node);
	struct ub_entity *uent_b = container_of(b, struct ub_entity, node);

	return uent_a->entity_idx > uent_b->entity_idx;
}

static void ub_release_ent(struct device *dev);
void ub_entity_add(struct ub_entity *uent, void *ctx)
{
	struct ub_bus_controller *ubc;
	struct list_head *list;
	struct ub_entity *pue;
	u8 need_sort = 0;
	int ret, node;

	if (!uent || !ctx)
		return;

	ret = ub_entity_setup_mmio(uent);
	WARN_ON(ret);

	ub_configure_ent(uent);

	device_initialize(&uent->dev);
	uent->dev.release = ub_release_ent;

	uent->dev.dma_mask = &uent->dma_mask;
	uent->dev.dma_parms = &uent->dma_parms;
	uent->dev.coherent_dma_mask = GENMASK_ULL(31, 0);
	dma_set_max_seg_size(&uent->dev, UB_DEFAULT_MAX_SEG_SIZE);
	dma_set_seg_boundary(&uent->dev, GENMASK(31, 0));

	uent->state_saved = false;
	ub_init_capabilities(uent);

	if (is_primary(uent) || is_p_device(uent)) {
		ubc = (struct ub_bus_controller *)ctx;
		node = ub_ubc_to_node(ubc);
		list = &ubc->devs;
	} else if (uent->is_mue) {
		pue = (struct ub_entity *)ctx;
		node = dev_to_node(&pue->dev);
		list = &pue->mue_list;
	} else {
		pue = (struct ub_entity *)ctx;
		node = dev_to_node(&pue->dev);
		list = &pue->ue_list;
		need_sort = 1;
	}

	set_dev_node(&uent->dev, node);
	ub_entity_assign_priv_flag(uent, UB_ENTITY_DETACHED, false);

	down_write(&ub_bus_sem);
	list_add_tail(&uent->node, list);
	if (need_sort)
		list_sort(NULL, list, ub_ue_sort_by_ent_idx);
	up_write(&ub_bus_sem);

	dev_set_msi_domain(&uent->dev, uent->ubc->dev.msi.domain);

	uent->match_driver = false;
	ret = device_add(&uent->dev);
	WARN_ON(ret < 0);

	if (is_primary(uent)) {
		ret = ub_ports_add(uent);
		WARN_ON(ret);
	}

	if (is_ibus_controller(uent)) {
		ret = ub_static_bus_instance_init(uent->ubc);
		WARN_ON(ret);
	}
}
EXPORT_SYMBOL_GPL(ub_entity_add);

static int ub_mue_enable_and_map(struct ub_entity *uent);
void ub_start_ent(struct ub_entity *uent)
{
	int ret;

	if (!uent)
		return;

	ret = ub_default_bus_instance_init(uent);
	if (ret) {
		ub_err(uent, "default bi init failed, ret=%d\n", ret);
		return;
	}

	ub_create_sysfs_dev_files(uent);
	ub_mem_decoder_init(uent);

	if (!((is_p_device(uent) || is_p_idevice(uent)) && is_dynamic(uent->bi))) {
		uent->match_driver = true;
		ret = device_attach(&uent->dev);
		if (ret < 0 && ret != -EPROBE_DEFER)
			ub_warn(uent, "device attach failed, ret=%d\n", ret);
	}

	if (is_primary(uent) && !is_p_device(uent)) {
		ret = ub_mue_enable_and_map(uent);
		if (ret)
			ub_err(uent, "enable pue failed, ret=%d\n", ret);
	}

	ub_entity_assign_priv_flag(uent, UB_ENTITY_START, true);
}
EXPORT_SYMBOL_GPL(ub_start_ent);

static void ub_release_ent(struct device *dev)
{
	struct ub_entity *uent;
	u32 uent_num;

	uent = to_ub_entity(dev);
	if (is_primary(uent) && !is_p_device(uent)) {
		ub_route_clear(uent);
		ub_cna_free(uent);
		ub_ports_unset(uent);
	}

	message_remove_device(uent);

	if (is_primary(uent) || (is_p_device(uent) && uent->is_mue))
		ub_ubc_put(uent->ubc);
	else
		ub_entity_put(uent->pue);

	kfree(uent->driver_override);
	uent->token_value = 0;
	uent_num = uent->uent_num;
	kfree(uent);
	pr_info("uent[%#x] release\n", uent_num);
}

void ub_stop_ent(struct ub_entity *uent)
{
	struct ub_entity *ent, *tmp;

	if (!uent)
		return;

	if (!ub_entity_test_priv_flag(uent, UB_ENTITY_START))
		return;
	ub_entity_assign_priv_flag(uent, UB_ENTITY_START, false);

	/* Stop ue in mue, when uent is not mue, ue_list is NULL */
	list_for_each_entry_safe_reverse(ent, tmp, &uent->ue_list, node)
		ub_stop_ent(ent);
	/* Stop mue in primary dev, when uent is entN, mue_list is NULL */
	list_for_each_entry_safe_reverse(ent, tmp, &uent->mue_list, node)
		ub_stop_ent(ent);

	device_release_driver(&uent->dev);
	uent->match_driver = false;
	ub_remove_sysfs_ent_files(uent);

	ub_default_bus_instance_uninit(uent);
}
EXPORT_SYMBOL_GPL(ub_stop_ent);

void ub_remove_ent(struct ub_entity *uent)
{
	struct ub_entity *ent, *tmp;

	if (!uent->dev.kobj.parent)
		return;

	/* Remove ue in mue, when uent is not mue, ue_list is NULL */
	list_for_each_entry_safe_reverse(ent, tmp, &uent->ue_list, node)
		ub_remove_ent(ent);
	/* Remove mue in primary dev, when uent is entN, mue_list is NULL */
	list_for_each_entry_safe_reverse(ent, tmp, &uent->mue_list, node)
		ub_remove_ent(ent);

	if (is_ibus_controller(uent))
		ub_static_bus_instance_uninit(uent->ubc);

	if (is_primary(uent))
		ub_ports_del(uent);

	device_del(&uent->dev);
	down_write(&ub_bus_sem);
	list_del(&uent->node);
	up_write(&ub_bus_sem);

	ub_mem_decoder_uninit(uent);
	ub_uninit_capabilities(uent);
	ub_unconfigure_ent(uent);
	ub_entity_unset_mmio(uent);
	ub_entity_num_free(uent);
	ub_eid_free(uent);
	ub_entity_assign_priv_flag(uent, UB_ENTITY_SETUP, false);

	put_device(&uent->dev);
}

void ub_stop_and_remove_ent(struct ub_entity *uent)
{
	if (!uent)
		return;

	ub_stop_ent(uent);
	ub_remove_ent(uent);
}
EXPORT_SYMBOL_GPL(ub_stop_and_remove_ent);

void ub_stop_entities(void)
{
	struct ub_bus_controller *ubc;
	struct ub_entity *uent;

	list_for_each_entry_reverse(ubc, &ubc_list, node)
		list_for_each_entry_reverse(uent, &ubc->devs, node)
			ub_stop_ent(uent);
}

void ub_remove_entities(void)
{
	struct ub_bus_controller *ubc;
	struct ub_entity *uent, *tmp;

	list_for_each_entry_reverse(ubc, &ubc_list, node)
		list_for_each_entry_safe_reverse(uent, tmp, &ubc->devs, node)
			ub_remove_ent(uent);
}

struct entity_info_msg_pld_rsp {
	u32 reserved;
	u16 entity_nums;
	u16 mue_nums;
	struct ue_map map[];
};
#define ENTITY_INFO_BASE_PLD_SIZE 8

struct entity_info_msg_pld {
	/* request payload is NULL */
	struct entity_info_msg_pld_rsp rsp;
};

struct entity_info_msg_pkt {
	struct msg_pkt_header header;
	struct entity_info_msg_pld pld;
};

static int ub_obtain_entity_info_rsp_handle(struct ub_entity *uent,
				       struct entity_info_msg_pkt *pkt, u16 *mue_nums,
				       struct ue_map *map)
{
	struct msg_extended_header *etah = &pkt->header.msgetah;
	struct entity_info_msg_pld_rsp *rsp = &pkt->pld.rsp;
	size_t size;
	u16 i;

	if (etah->rsp_status != UB_MSG_RSP_SUCCESS) {
		ub_err(uent, "obtain entity info rsp, status=%#02x\n",
		       etah->rsp_status);
		return -EINVAL;
	}

	if (etah->plen < ENTITY_INFO_BASE_PLD_SIZE) {
		ub_err(uent, "obtain entity info plen=%#x invalid\n",
		       etah->plen);
		return -EINVAL;
	}

	uent->total_funcs = rsp->entity_nums;
	*mue_nums = rsp->mue_nums;

	size = sizeof(struct ue_map) * (*mue_nums);
	if (*mue_nums == 0 || size > SZ_1K) {
		ub_err(uent, "mue_nums or size error, mue_nums=%#x, size=%#lx\n",
		       *mue_nums, size);
		return -EINVAL;
	}

	if (etah->plen != (*mue_nums * SZ_4 + ENTITY_INFO_BASE_PLD_SIZE)) {
		ub_err(uent, "obtain entity info plen=%#x, mue_nums=%#x invalid\n",
		       etah->plen, *mue_nums);
		return -EINVAL;
	}

	for (i = 0; i < *mue_nums; i++) {
		map[i].start_entity_idx = rsp->map[i].start_entity_idx;
		map[i].end_entity_idx = rsp->map[i].end_entity_idx;
	}

	return 0;
}

static int ub_obtain_entity_info(struct ub_entity *uent, u16 *mue_nums,
			    struct ue_map *map)
{
	struct message_device *mdev = uent->message->mdev;
	struct entity_info_msg_pkt req_pkt = {};
	struct entity_info_msg_pkt *rsp_pkt;
	struct msg_info info = {};
	int ret;

	if (is_ibus_controller(uent)) {
		*mue_nums = 1;
		map->start_entity_idx = 0;
		map->end_entity_idx = 0;
		return 0;
	}

	ub_msg_pkt_header_init(&req_pkt.header, uent, 0,
			       code_gen(UB_MSG_CODE_EXCH, UB_OBTAIN_ENTITY_INFO,
			       MSG_REQ), false);

	rsp_pkt = kzalloc(SZ_2K, GFP_KERNEL);
	if (!rsp_pkt)
		return -ENOMEM;

	message_info_init(
		&info, uent, &req_pkt, rsp_pkt,
		(sizeof(struct msg_pkt_header) << MSG_REQ_SIZE_OFFSET) | SZ_2K);

	ret = message_sync_request(mdev, &info, req_pkt.header.msgetah.code);
	if (ret)
		goto out;

	ret = ub_obtain_entity_info_rsp_handle(uent, rsp_pkt, mue_nums, map);
out:
	kfree(rsp_pkt);
	return ret;
}

static int ub_enable_mues(struct ub_entity *pue, int nums, struct ue_map *map);
int ub_mue_enable_and_map(struct ub_entity *uent)
{
	struct ue_map *map;
	u16 mue_nums;
	int ret;

	map = kzalloc(SZ_1K, GFP_KERNEL);
	if (!map)
		return -ENOMEM;

	ret = ub_obtain_entity_info(uent, &mue_nums, map);
	if (ret)
		goto out;

	/* add map information to Entity0 */
	uent->uem.start_entity_idx = map[0].start_entity_idx;
	uent->uem.end_entity_idx = map[0].end_entity_idx;
	uent->total_ues = uent->uem.end_entity_idx - uent->uem.start_entity_idx + 1;
	if (uent->entity_idx == map[0].start_entity_idx)
		uent->total_ues = 0;

	ret = ub_enable_mues(uent, mue_nums - 1, map);

out:
	kfree(map);
	return ret;
}

static int ub_enable_ent(struct ub_entity *pue, int idx, u8 is_mue,
			  struct ue_map *map)
{
	int ret;
	struct ub_entity *ue;

	ue = ub_alloc_ent();
	if (!ue)
		return -ENOMEM;

	ue->entity_idx = idx;
	ue->pue = pue;
	ue->dev.parent = &pue->dev;
	ue->ubc = pue->ubc;
	ue->cna = pue->cna;
	ue->upi = pue->upi;

	if (is_mue) {
		ue->is_mue = is_mue;
		ue->uem.start_entity_idx = map->start_entity_idx;
		ue->uem.end_entity_idx = map->end_entity_idx;
		ue->total_ues = map->end_entity_idx - map->start_entity_idx + 1;
		if (ue->entity_idx == map->start_entity_idx)
			ue->total_ues = 0;
	}

	ret = ub_setup_ent(ue);
	if (ret < 0) {
		kfree(ue);
		return ret;
	}

	ub_entity_get(pue);
	ub_entity_add(ue, pue);
	ub_entity_assign_task_src(ue, TASK_SRC_SELF, true);
	ub_start_ent(ue);

	return 0;
}

static void ub_disable_mues(struct ub_entity *pue);

static int ub_enable_mues(struct ub_entity *pue, int nums, struct ue_map *map)
{
	int ret;
	int i;

	/* Enable entities, excluding entity0 */
	for (i = 1; i <= nums; i++) {
		ret = ub_enable_ent(pue, i, 1, &map[i]);
		if (ret)
			goto failed;
	}

	return 0;
failed:
	ub_disable_mues(pue);
	return ret;
}

void ub_virt_notify(struct ub_entity *pue, u16 entity_idx, bool is_en)
{
	const char *operate = is_en ? "enable" : "disable";
	struct ub_driver *pdrv;
	int ret;

	if (pue) {
		pdrv = pue->driver;
		if (pdrv && pdrv->virt_notify) {
			ret = pdrv->virt_notify(pue, entity_idx, is_en);
			if (ret)
				ub_warn(pue, "drv virt notify %s ue with entity_idx %u failed, ret=%d\n",
					operate, entity_idx, ret);
		}
	}
}

void ub_disable_ent(struct ub_entity *uent)
{
	struct ub_entity *pue;
	bool ue_flag = false;
	u16 entity_idx;

	ub_info(uent, "disable entity, eid=%#05x\n", uent->eid);
	if (!uent->is_mue) {
		pue = uent->pue;
		entity_idx = uent->entity_idx;
		ue_flag = true;
	}

	ub_stop_and_remove_ent(uent);

	if (ue_flag)
		ub_virt_notify(pue, entity_idx, false);
}
EXPORT_SYMBOL_GPL(ub_disable_ent);

static void ub_disable_mues(struct ub_entity *pue)
{
	struct ub_entity *mue, *tmp;

	list_for_each_entry_safe_reverse(mue, tmp, &pue->mue_list, node)
		ub_disable_ent(mue);
}

void ub_disable_ues(struct ub_entity *mue)
{
	struct ub_entity *ue, *tmp;
	u16 pool_ues = 0;

	list_for_each_entry_safe_reverse(ue, tmp, &mue->ue_list,
					 node) {
		if (is_p_device(ue) || is_p_idevice(ue))
			pool_ues++;
		else
			ub_disable_ent(ue);
	}

	mue->num_ues = pool_ues;
}

static int ub_check_ue_para(struct ub_entity *pue, int entity_idx)
{
	if (!pue->is_mue || !pue->total_ues) {
		ub_err(pue, "It's not mue or ues 0.\n");
		return -EINVAL;
	}

	if (entity_idx < pue->uem.start_entity_idx || entity_idx > pue->uem.end_entity_idx) {
		ub_err(pue, "Entity idx is err, start=%d, pre=%d, end=%d.\n",
		       pue->uem.start_entity_idx, entity_idx, pue->uem.end_entity_idx);
		return -EINVAL;
	}

	return 0;
}

/* ub_enable_ue does not support parallel execution */
int ub_enable_ue(struct ub_entity *pue, int entity_idx)
{
	struct ub_entity *ue;
	int ret;

	if (!pue)
		return -EINVAL;

	ret = ub_check_ue_para(pue, entity_idx);
	if (ret)
		return ret;

	list_for_each_entry(ue, &pue->ue_list, node)
		if (ue->entity_idx == entity_idx) {
			ub_err(ue, "entity_idx[%d] already exists, eid=%#05x\n",
			       entity_idx, ue->eid);
			return -EEXIST;
		}

	ret = ub_enable_ent(pue, entity_idx, 0, NULL);
	if (ret)
		return ret;

	pue->num_ues += 1;

	return ret;
}
EXPORT_SYMBOL_GPL(ub_enable_ue);

int ub_disable_ue(struct ub_entity *pue, int entity_idx)
{
	struct ub_entity *vd_dev;
	int ret;

	if (!pue)
		return -EINVAL;

	ret = ub_check_ue_para(pue, entity_idx);
	if (ret)
		return ret;

	list_for_each_entry(vd_dev, &pue->ue_list, node)
		if (vd_dev->entity_idx == entity_idx) {
			ub_disable_ent(vd_dev);
			pue->num_ues -= 1;
			return 0;
		}

	ub_err(pue, "No matching entity_idx[%d] found\n", entity_idx);

	return -ENODEV;
}
EXPORT_SYMBOL_GPL(ub_disable_ue);

void ub_disable_entities(struct ub_entity *uent)
{
	if (!uent)
		return;

	if (!uent->is_mue)
		return;

	ub_disable_ues(uent);
}
EXPORT_SYMBOL_GPL(ub_disable_entities);

int ub_num_ue(struct ub_entity *uent)
{
	if (!uent)
		return -EINVAL;

	if (!uent->is_mue)
		return 0;

	return uent->num_ues;
}
EXPORT_SYMBOL_GPL(ub_num_ue);

int ub_entity_enable_return(struct ub_entity *uent, u8 enable)
{
	int ret;

	if (!uent)
		return -EINVAL;

	ret = ub_cfg_write_byte(uent, UB_BUS_ACCESS_EN, enable);
	if (ret) {
		ub_err(uent, "write bus en failed, ret[%d]\n", ret);
		return ret;
	}

	/* Failed branch does not roll back configuration access. */
	ret = ub_cfg_write_byte(uent, UB_ENTITY_RS_ACCESS_EN, enable);
	if (ret) {
		ub_err(uent, "write rs en failed, ret[%d]\n", ret);
		return ret;
	}

	mutex_lock(&uent->active_mutex);

	if (!enable && !ub_entity_test_priv_flag(uent, UB_ENTITY_ACTIVE)) {
		mutex_unlock(&uent->active_mutex);
		return 0;
	}

	if (uent->ubc && uent->ubc->ops && uent->ubc->ops->entity_enable) {
		ret = uent->ubc->ops->entity_enable(uent, enable);
		if (ret) {
			mutex_unlock(&uent->active_mutex);
			ub_err(uent, "entity enable, ret=%d, enable=%u\n",
			       ret, enable);
			return ret;
		}
	}

	ub_info(uent, "Change the entity status to %s\n", enable ?  "normal" : "disable");

	if (enable)
		ub_entity_assign_priv_flag(uent, UB_ENTITY_ACTIVE, true);
	else
		ub_entity_assign_priv_flag(uent, UB_ENTITY_ACTIVE, false);

	mutex_unlock(&uent->active_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(ub_entity_enable_return);

void ub_entity_enable(struct ub_entity *uent, u8 enable)
{
	ub_entity_enable_return(uent, enable);
}
EXPORT_SYMBOL_GPL(ub_entity_enable);

int ub_set_user_info(struct ub_entity *uent)
{
	if (!uent || !uent->ubc || !uent->ubc->uent)
		return -EINVAL;

	u32 eid = uent->ubc->uent->eid;

	if (is_p_device(uent) ||
	    (uent->ubc->cluster && is_ibus_controller(uent)))
		goto cfg1;

	/* set dsteid to device */
	if (uent->bi)
		eid = uent->bi->info.eid;
	ub_cfg_write_dword(uent, UB_UEID_0, eid);
	ub_cfg_write_dword(uent, UB_UEID_1, 0);
	ub_cfg_write_dword(uent, UB_UEID_2, 0);
	ub_cfg_write_dword(uent, UB_UEID_3, 0);
	ub_cfg_write_dword(uent, UB_UCNA, uent->ubc->uent->cna);

cfg1:
	/* set tid to device */
	ub_cfg_write_dword(uent, UB_ENTITY_TOKEN_ID, uent->tid);

	return 0;
}
EXPORT_SYMBOL_GPL(ub_set_user_info);

void ub_unset_user_info(struct ub_entity *uent)
{
	if (!uent)
		return;

	if (is_p_device(uent) ||
	    (uent->ubc->cluster && is_ibus_controller(uent)))
		goto cfg1;

	ub_cfg_write_dword(uent, UB_UCNA, 0);
	/* clear eid */
	ub_cfg_write_dword(uent, UB_UEID_0, 0);
	ub_cfg_write_dword(uent, UB_UEID_1, 0);
	ub_cfg_write_dword(uent, UB_UEID_2, 0);
	ub_cfg_write_dword(uent, UB_UEID_3, 0);

cfg1:
	/* clear tid */
	ub_cfg_write_dword(uent, UB_ENTITY_TOKEN_ID, 0);
}
EXPORT_SYMBOL_GPL(ub_unset_user_info);

static struct ub_entity *ub_get_ue_by_entity_idx(struct ub_entity *pue, u32 entity_idx)
{
	struct ub_entity *ue;

	list_for_each_entry(ue, &pue->ue_list, node) {
		if (ue->entity_idx == entity_idx)
			return ue;
	}

	return NULL;
}

int ub_activate_entity(struct ub_entity *uent, u32 entity_idx)
{
	struct ub_entity *target_dev;
	struct ub_driver *udrv;
	int ret;

	if (uent && uent->entity_idx != entity_idx && uent->is_mue)
		target_dev = ub_get_ue_by_entity_idx(uent, entity_idx);
	else
		target_dev = uent;
	if (!target_dev)
		return -EINVAL;

	udrv = uent->driver;
	if (!udrv || !udrv->activate) {
		ub_err(uent, "udrv or activate is null\n");
		return -EINVAL;
	}

	mutex_lock(&target_dev->active_mutex);

	if (ub_entity_test_priv_flag(target_dev, UB_ENTITY_ACTIVE)) {
		ub_warn(uent, "entity_idx[%u] is already in normal state\n", entity_idx);
		mutex_unlock(&target_dev->active_mutex);
		return 0;
	}

	ret = udrv->activate(uent, entity_idx);
	if (ret) {
		ub_err(uent, "udrv activate entity_idx[%u] failed, ret=%d\n", entity_idx, ret);
	} else {
		ub_entity_assign_priv_flag(target_dev, UB_ENTITY_ACTIVE, true);
		ub_info(uent, "udrv activate entity_idx[%u] success\n", entity_idx);
	}

	mutex_unlock(&target_dev->active_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(ub_activate_entity);

int ub_deactivate_entity(struct ub_entity *uent, u32 entity_idx)
{
	struct ub_entity *target_dev;
	struct ub_driver *udrv;
	int ret;

	if (uent && uent->entity_idx != entity_idx && uent->is_mue)
		target_dev = ub_get_ue_by_entity_idx(uent, entity_idx);
	else
		target_dev = uent;
	if (!target_dev)
		return -EINVAL;

	udrv = uent->driver;
	if (!udrv || !udrv->deactivate) {
		ub_err(uent, "udrv or deactivate is null\n");
		return -EINVAL;
	}

	mutex_lock(&target_dev->active_mutex);

	if (!ub_entity_test_priv_flag(target_dev, UB_ENTITY_ACTIVE)) {
		ub_warn(uent, "entity_idx[%u] is already in disable state\n", entity_idx);
		mutex_unlock(&target_dev->active_mutex);
		return 0;
	}

	ret = udrv->deactivate(uent, entity_idx);
	if (ret) {
		ub_err(uent, "udrv deactivate entity_idx[%u] failed, ret=%d\n", entity_idx, ret);
	} else {
		ub_entity_assign_priv_flag(target_dev, UB_ENTITY_ACTIVE, false);
		ub_info(uent, "udrv deactivate entity_idx[%u] success\n", entity_idx);
	}

	mutex_unlock(&target_dev->active_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(ub_deactivate_entity);

int ub_reinit_ent(struct ub_entity *uent)
{
	struct ub_driver *udrv;
	int ret;

	if (!uent)
		return -EINVAL;

	device_lock(&uent->dev);

	udrv = uent->driver;
	if (!udrv || !udrv->reinit) {
		ub_info(uent, "udrv or reinit is null\n");
		ret = 0;
		goto out;
	}

	ret = udrv->reinit(uent);
	if (ret) {
		ub_err(uent, "reinit ret[%d]\n", ret);
		if (ret == -EAGAIN)
			ub_add_retry_task(uent, TASK_TYPE_REINIT_RETRY);
	}
out:
	device_unlock(&uent->dev);
	return ret;
}
