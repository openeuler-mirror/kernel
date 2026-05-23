/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_dev_mgmt.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <net/addrconf.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/debugfs.h>

#include "ossl_knl.h"
#include "mpu_inband_cmd_defs.h"
#include "bond_pub_cmd.h"
#include "hinic5_mt.h"
#include "hinic5_crm.h"
#include "hinic5_lld.h"
#include "hinic5_lld_inner.h"
#include "hinic5_sriov.h"
#include "hinic5_id_tbl.h"
#include "hinic5_hwdev.h"
#include "hinic5_fw_update.h"
#include "hinic5_dev_mgmt.h"

#define HINIC5_WAIT_TOOL_CNT_TIMEOUT	10000
#define HINIC5_WAIT_TOOL_MIN_USLEEP_TIME	9900
#define HINIC5_WAIT_TOOL_MAX_USLEEP_TIME	10000

static ulong card_bit_map;

LIST_HEAD(g_hinic5_chip_list);

inline struct list_head *get_hinic5_chip_list(void)
{
	return &g_hinic5_chip_list;
}

void hinic5_uld_dev_hold(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type)
{
	struct hinic5_adev *adev = NULL;

	if (type >= SERVICE_T_MAX) {
		pr_err("array uld_ref_cnt upper bound\n");
		return;
	}
	if (!lld_dev || !to_hinic5_adev(lld_dev)) {
		pr_err("lld_dev is null, srv_type = 0x%x, when uld dev hold\n", type);
		return;
	}
	adev = to_hinic5_adev(lld_dev);

	atomic_inc(&adev->uld_ref_cnt[type]);
}
EXPORT_SYMBOL(hinic5_uld_dev_hold);

void hinic5_uld_dev_put(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev || !to_hinic5_adev(lld_dev)) {
		pr_err("lld_dev is null, srv_type = 0x%x, when uld dev put\n", type);
		return;
	}
	if (type >= SERVICE_T_MAX) {
		pr_err("array uld_ref_cnt upper bound\n");
		return;
	}
	adev = to_hinic5_adev(lld_dev);

	atomic_dec(&adev->uld_ref_cnt[type]);
}
EXPORT_SYMBOL(hinic5_uld_dev_put);

void hinic5_lld_dev_cnt_init(struct hinic5_adev *adev)
{
	atomic_set(&adev->ref_cnt, 0);
}

void hinic5_lld_dev_hold(struct hinic5_lld_dev *dev)
{
	struct hinic5_adev *adev = to_hinic5_adev(dev);

	atomic_inc(&adev->ref_cnt);
}
EXPORT_SYMBOL(hinic5_lld_dev_hold);

void hinic5_lld_dev_put(struct hinic5_lld_dev *dev)
{
	struct hinic5_adev *adev = to_hinic5_adev(dev);

	atomic_dec(&adev->ref_cnt);
}
EXPORT_SYMBOL(hinic5_lld_dev_put);

void hinic5_wait_lld_dev_unused(struct hinic5_adev *adev)
{
	ulong end;

	end = jiffies + msecs_to_jiffies(HINIC5_WAIT_TOOL_CNT_TIMEOUT);
	do {
		if (atomic_read(&adev->ref_cnt) == 0)
			return;

		/* if sleep 10ms, use usleep_range to be more precise */
		usleep_range(HINIC5_WAIT_TOOL_MIN_USLEEP_TIME,
			     HINIC5_WAIT_TOOL_MAX_USLEEP_TIME);
	} while (time_before(jiffies, end));
}

enum hinic5_lld_status {
	HINIC5_NODE_CHANGE	= BIT(0),
};

struct hinic5_lld_lock {
	/* lock for chip list */
	struct mutex		lld_mutex;
	ulong		    status;
	atomic_t		dev_ref_cnt;
};

struct hinic5_lld_lock hinic5_g_lld_lock;

/* max mbox timeout (200s) + extra (100s) */
#define WAIT_LLD_DEV_HOLD_TIMEOUT	(300 * 1000)
#define WAIT_LLD_DEV_NODE_CHANGED	WAIT_LLD_DEV_HOLD_TIMEOUT
#define WAIT_LLD_DEV_REF_CNT_EMPTY	(2 * 60 * 1000)	 /* 2minutes */
#define PRINT_TIMEOUT_INTERVAL		10000
#define MS_PER_SEC			1000
#define LLD_LOCK_MIN_USLEEP_TIME	900
#define LLD_LOCK_MAX_USLEEP_TIME	1000

/* node in chip_node will changed, tools or driver can't get node
 * during this situation
 */
void hinic5_lld_lock_chip_node(void)
{
	ulong end;
	bool timeout = true;
	u32 loop_cnt;

	mutex_lock(&hinic5_g_lld_lock.lld_mutex);

	loop_cnt = 0;
	end = jiffies + msecs_to_jiffies(WAIT_LLD_DEV_NODE_CHANGED);
	do {
		if (!test_and_set_bit(HINIC5_NODE_CHANGE, &hinic5_g_lld_lock.status)) {
			timeout = false;
			break;
		}

		loop_cnt++;
		if (loop_cnt % PRINT_TIMEOUT_INTERVAL == 0)
			pr_warn("Wait for lld node change complete for %us\n",
				loop_cnt / MS_PER_SEC);

		/* if sleep 1ms, use usleep_range to be more precise */
		usleep_range(LLD_LOCK_MIN_USLEEP_TIME,
			     LLD_LOCK_MAX_USLEEP_TIME);
	} while (time_before(jiffies, end));

	if (timeout && test_and_set_bit(HINIC5_NODE_CHANGE, &hinic5_g_lld_lock.status))
		pr_warn("Wait for lld node change complete timeout when trying to get lld lock\n");

	loop_cnt = 0;
	timeout = true;
	end = jiffies + msecs_to_jiffies(WAIT_LLD_DEV_NODE_CHANGED);
	do {
		if (atomic_read(&hinic5_g_lld_lock.dev_ref_cnt) == 0) {
			timeout = false;
			break;
		}

		loop_cnt++;
		if (loop_cnt % PRINT_TIMEOUT_INTERVAL == 0)
			pr_warn("Wait for lld dev unused for %us, reference count: %d\n",
				loop_cnt / MS_PER_SEC,
				atomic_read(&hinic5_g_lld_lock.dev_ref_cnt));

		/* if sleep 1ms, use usleep_range to be more precise */
		usleep_range(LLD_LOCK_MIN_USLEEP_TIME,
			     LLD_LOCK_MAX_USLEEP_TIME);
	} while (time_before(jiffies, end));

	if (timeout && (atomic_read(&hinic5_g_lld_lock.dev_ref_cnt) != 0))
		pr_warn("Wait for lld dev unused timeout\n");

	mutex_unlock(&hinic5_g_lld_lock.lld_mutex);
}

void hinic5_lld_unlock_chip_node(void)
{
	clear_bit(HINIC5_NODE_CHANGE, &hinic5_g_lld_lock.status);
}

/* When tools or other drivers want to get node of chip_node, use this function
 * to prevent node be freed
 */
void hinic5_lld_hold(void)
{
	ulong end;
	u32 loop_cnt = 0;

	/* ensure there have not any chip node in changing */
	mutex_lock(&hinic5_g_lld_lock.lld_mutex);

	end = jiffies + msecs_to_jiffies(WAIT_LLD_DEV_HOLD_TIMEOUT);
	do {
		if (!test_bit(HINIC5_NODE_CHANGE, &hinic5_g_lld_lock.status))
			break;

		loop_cnt++;

		if (loop_cnt % PRINT_TIMEOUT_INTERVAL == 0)
			pr_warn("Wait lld node change complete for %us\n",
				loop_cnt / MS_PER_SEC);
		/* if sleep 1ms, use usleep_range to be more precise */
		usleep_range(LLD_LOCK_MIN_USLEEP_TIME,
			     LLD_LOCK_MAX_USLEEP_TIME);
	} while (time_before(jiffies, end));

	if (test_bit(HINIC5_NODE_CHANGE, &hinic5_g_lld_lock.status))
		pr_warn("Wait lld node change complete timeout when trying to hode lld dev\n");

	atomic_inc(&hinic5_g_lld_lock.dev_ref_cnt);
	mutex_unlock(&hinic5_g_lld_lock.lld_mutex);
}

void hinic5_lld_put(void)
{
	atomic_dec(&hinic5_g_lld_lock.dev_ref_cnt);
}

void hinic5_lld_lock_init(void)
{
	mutex_init(&hinic5_g_lld_lock.lld_mutex);
	atomic_set(&hinic5_g_lld_lock.dev_ref_cnt, 0);
}

void hinic5_get_all_chip_id(void *id_info)
{
	struct nic_card_id *card_id = (struct nic_card_id *)id_info;
	struct card_node *chip_node = NULL;
	int i = 0;
	int id, err;

	hinic5_lld_hold();
	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		err = sscanf(chip_node->chip_name, HINIC5_CHIP_NAME "%d", &id);
		if (err != 1) {
			pr_err("Failed to get hinic5 id\n");
			continue;
		}
		card_id->id[i] = (u32)id;
		i++;
	}
	hinic5_lld_put();
	card_id->num = (u32)i;
}

static bool is_pcidev_match_chip_name(const char *ifname, struct hinic5_adev *adev,
				      struct card_node *chip_node, enum func_type type)
{
	if (strncmp(chip_node->chip_name, ifname, IFNAMSIZ) == 0) {
		if (hinic5_func_type(adev->hwdev) != type)
			return false;
		return true;
	}

	return false;
}

/**
 * @brief get_dst_type_lld_dev_by_chip_name - Get lld device pointer by device name
 *
 * @param[in] ifname Device name hinic0
 * @param[in] type function type
 * @param[in] check_active_flag Whether to check if function status is available
 *
 * @details NA
 *
 * @attention: NA
 *
 * @return: Returns the queried device
 *     @retval NULL Query no match
 *     @retval non-NULL Matched device
 */
static struct hinic5_lld_dev *get_dst_type_lld_dev_by_chip_name(const char *ifname,
								enum func_type type,
								bool check_active_flag)
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;

	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		list_for_each_entry(adev, &chip_node->func_list, node) {
			if ((!check_active_flag || hinic5_is_function_active(adev->hwdev)) &&
			    is_pcidev_match_chip_name(ifname, adev, chip_node, type)) {
				return &adev->lld_dev;
			}
		}
	}

	return NULL;
}

struct hinic5_lld_dev *hinic5_get_lld_dev_by_chip_name(const char *chip_name)
{
	struct hinic5_lld_dev *dev = NULL;
	int i;
	bool check_active_flag[] = {true, false};

	hinic5_lld_hold();

	for (i = 0; i < sizeof(check_active_flag) / sizeof(check_active_flag[0]); i++) {
		dev = get_dst_type_lld_dev_by_chip_name(chip_name, TYPE_PPF, check_active_flag[i]);
		if (dev)
			goto out;

		dev = get_dst_type_lld_dev_by_chip_name(chip_name, TYPE_PF, check_active_flag[i]);
		if (dev)
			goto out;

		dev = get_dst_type_lld_dev_by_chip_name(chip_name, TYPE_VF, check_active_flag[i]);
		if (dev)
			goto out;
	}

out:
	if (dev)
		hinic5_lld_dev_hold(dev);
	hinic5_lld_put();

	return dev;
}
EXPORT_SYMBOL(hinic5_get_lld_dev_by_chip_name);

static int get_dynamic_bond_uld_dev_name(struct hinic5_adev *adev, enum hinic5_service_type type,
					 char *ifname)
{
	const struct hinic5_uld_info *uld_info = hinic5_get_uld_info_by_type(type);
	u32 out_size = IFNAMSIZ;

	if (!uld_info || !uld_info->ioctl || !adev->uld_dev[type])
		return -EFAULT;

	return uld_info->ioctl(adev->uld_dev[type], CMD_CUSTOM_BOND_GET_ULD_DEV_NAME,
				      NULL, 0, ifname, &out_size);
}

static int get_dynamic_uld_dev_name(struct hinic5_adev *adev, enum hinic5_service_type type,
				    char *ifname)
{
	const struct hinic5_uld_info *uld_info = hinic5_get_uld_info_by_type(type);
	u32 out_size = IFNAMSIZ;

	if (!uld_info || !uld_info->ioctl)
		return -EFAULT;

	return uld_info->ioctl(adev->uld_dev[type], GET_ULD_DEV_NAME,
				      NULL, 0, ifname, &out_size);
}

static bool is_pcidev_match_dev_name(const char *dev_name, struct hinic5_adev *adev,
				     enum hinic5_service_type type)
{
	int i;
	char nic_uld_name[IFNAMSIZ] = {0};
	int err;

	if (type > SERVICE_T_MAX)
		return false;

	if (type == SERVICE_T_MAX) {
		for (i = SERVICE_T_OVS; i < SERVICE_T_MAX; i++) {
			if (strncmp(adev->uld_dev_name[i], dev_name, IFNAMSIZ) == 0)
				return true;
		}
	} else {
		if (strncmp(adev->uld_dev_name[type], dev_name, IFNAMSIZ) == 0)
			return true;
	}

	if (type == SERVICE_T_CUSTOM) {
		err = get_dynamic_bond_uld_dev_name(adev, SERVICE_T_CUSTOM, (char *)nic_uld_name);
		if (err == 0) {
			if (strncmp(nic_uld_name, dev_name, IFNAMSIZ) == 0)
				return true;
		}
	}

	err = get_dynamic_uld_dev_name(adev, SERVICE_T_NIC, (char *)nic_uld_name);
	if (err == 0) {
		if (strncmp(nic_uld_name, dev_name, IFNAMSIZ) == 0)
			return true;
	}

	return false;
}

static struct hinic5_lld_dev *get_lld_dev_by_dev_name(const char *dev_name,
						      enum hinic5_service_type type, bool hold)
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;

	hinic5_lld_hold();

	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (is_pcidev_match_dev_name(dev_name, adev, type)) {
				if (hold)
					hinic5_lld_dev_hold(&adev->lld_dev);
				hinic5_lld_put();
				return &adev->lld_dev;
			}
		}
	}

	hinic5_lld_put();

	return NULL;
}

struct hinic5_lld_dev *hinic5_get_lld_dev_by_chip_and_port(const char *chip_name, u8 port_id)
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;

	hinic5_lld_hold();
	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (hinic5_func_type(adev->hwdev) == TYPE_VF)
				continue;

			if ((hinic5_physical_port_id(adev->hwdev) == port_id) &&
			    (strncmp(chip_node->chip_name, chip_name, IFNAMSIZ) == 0) &&
			    (hinic5_support_nic(adev->hwdev, NULL) != 0)) {
				hinic5_lld_dev_hold(&adev->lld_dev);
				hinic5_lld_put();

				return &adev->lld_dev;
			}
		}
	}
	hinic5_lld_put();

	return NULL;
}

struct hinic5_lld_dev *hinic5_get_lld_dev_with_l3i_enabled(const char *chip_name)
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;
	struct hinic5_hwdev *hwdev = NULL;

	hinic5_lld_hold();
	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		if (strncmp(chip_node->chip_name, chip_name, IFNAMSIZ) != 0)
			continue;

		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (hinic5_func_type(adev->hwdev) == TYPE_VF)
				continue;

			hwdev = (struct hinic5_hwdev *)adev->hwdev;

			if (hinic5_fw_update_ddr_enabled(hwdev)) {
				hinic5_lld_dev_hold(&adev->lld_dev);
				hinic5_lld_put();

				return &adev->lld_dev;
			}
		}
	}
	hinic5_lld_put();

	return NULL;
}

void *hinic5_get_ppf_dev(void)
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;
	struct list_head *chip_list = NULL;

	hinic5_lld_hold();
	chip_list = get_hinic5_chip_list();

	list_for_each_entry(chip_node, chip_list, node)
		list_for_each_entry(adev, &chip_node->func_list, node)
			if (hinic5_func_type(adev->hwdev) == TYPE_PPF) {
				pr_info("Get ppf_func_id:%u", hinic5_global_func_id(adev->hwdev));
				hinic5_lld_put();
				return adev->lld_dev.hwdev;
			}

	hinic5_lld_put();
	return NULL;
}
EXPORT_SYMBOL(hinic5_get_ppf_dev);

struct hinic5_lld_dev *hinic5_get_lld_dev_by_dev_name(const char *dev_name,
						      enum hinic5_service_type type)
{
	if (!dev_name) {
		pr_err("dev_name is null\n");
		return NULL;
	}
	return get_lld_dev_by_dev_name(dev_name, type, true);
}

struct hinic5_lld_dev *hinic5_get_lld_dev_by_dev_name_unsafe(const char *dev_name,
							     enum hinic5_service_type type)
{
	if (!dev_name) {
		pr_err("dev_name is null\n");
		return NULL;
	}
	return get_lld_dev_by_dev_name(dev_name, type, false);
}
EXPORT_SYMBOL(hinic5_get_lld_dev_by_dev_name_unsafe);

static void *get_uld_by_lld_dev(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type,
				bool hold)
{
	struct hinic5_adev *adev = NULL;
	void *uld = NULL;

	if (!lld_dev)
		return NULL;

	adev = to_hinic5_adev(lld_dev);
	if (!adev)
		return NULL;

	spin_lock_bh(&adev->uld_lock);
	if (!adev->uld_dev[type] || !test_bit(type, &adev->uld_state)) {
		spin_unlock_bh(&adev->uld_lock);
		return NULL;
	}
	uld = adev->uld_dev[type];

	if (hold)
		atomic_inc(&adev->uld_ref_cnt[type]);
	spin_unlock_bh(&adev->uld_lock);

	return uld;
}

void *hinic5_get_uld_dev(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type)
{
	if (!lld_dev) {
		pr_err("lld_dev is null, srv_type = 0x%x, when get uld dev\n", type);
		return NULL;
	}
	return get_uld_by_lld_dev(lld_dev, type, true);
}
EXPORT_SYMBOL(hinic5_get_uld_dev);

void *hinic5_get_uld_dev_unsafe(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type type)
{
	if (!lld_dev) {
		pr_err("lld_dev is null, srv_type = 0x%x, when get uld dev unsafe\n", type);
		return NULL;
	}
	return get_uld_by_lld_dev(lld_dev, type, false);
}
EXPORT_SYMBOL(hinic5_get_uld_dev_unsafe);

static struct hinic5_lld_dev *get_ppf_lld_dev(struct hinic5_lld_dev *lld_dev, bool hold)
{
	struct hinic5_adev *adev = NULL;
	struct card_node *chip_node = NULL;
	struct hinic5_adev *temp_adev = NULL;

	if (!lld_dev)
		return NULL;

	adev = to_hinic5_adev(lld_dev);
	if (!adev)
		return NULL;

	hinic5_lld_hold();
	chip_node = adev->chip_node;
	list_for_each_entry(temp_adev, &chip_node->func_list, node) {
		/* In single card multi-cpihost scenario, multiple ppfs exist in the linked list */
		if (temp_adev->hwdev && hinic5_func_type(temp_adev->hwdev) == TYPE_PPF &&
		    hinic5_global_func_id(temp_adev->hwdev) == hinic5_ppf_idx(lld_dev->hwdev)) {
			if (hold)
				hinic5_lld_dev_hold(&temp_adev->lld_dev);
			hinic5_lld_put();
			return &temp_adev->lld_dev;
		}
	}
	hinic5_lld_put();

	return NULL;
}

struct hinic5_lld_dev *hinic5_get_ppf_lld_dev(struct hinic5_lld_dev *lld_dev)
{
	return get_ppf_lld_dev(lld_dev, true);
}
EXPORT_SYMBOL(hinic5_get_ppf_lld_dev);

struct hinic5_lld_dev *hinic5_get_ppf_lld_dev_unsafe(struct hinic5_lld_dev *lld_dev)
{
	return get_ppf_lld_dev(lld_dev, false);
}
EXPORT_SYMBOL(hinic5_get_ppf_lld_dev_unsafe);

void *hinic5_get_ppf_hw_dev_unsafe(void *hwdev)
{
	struct hinic5_hwdev *handle = hwdev;
	struct hinic5_adev *adev = NULL;
	struct card_node *chip_node = NULL;

	if (unlikely(!handle))
		return NULL;

	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (adev->hwdev && hinic5_func_type(adev->hwdev) == TYPE_PPF)
				return adev->lld_dev.hwdev;
		}
	}

	sdk_warn(handle->dev_hdl, "Current host has no PPF.\n");
	return NULL;
}
EXPORT_SYMBOL(hinic5_get_ppf_hw_dev_unsafe);

int hinic5_get_chip_name(struct hinic5_lld_dev *lld_dev, char *chip_name, u16 max_len)
{
	struct hinic5_adev *adev = NULL;

	if (!lld_dev || !chip_name || max_len == 0)
		return -EINVAL;

	adev = to_hinic5_adev(lld_dev);
	if (!adev)
		return -EFAULT;

	hinic5_lld_hold();
	strscpy(chip_name, adev->chip_node->chip_name, max_len);
	chip_name[max_len - 1] = '\0';

	hinic5_lld_put();

	return 0;
}
EXPORT_SYMBOL(hinic5_get_chip_name);

void *hinic5_get_sdk_hwdev_by_lld(struct hinic5_lld_dev *lld_dev)
{
	return lld_dev->hwdev;
}

struct card_node *hinic5_get_chip_node_by_lld(struct hinic5_lld_dev *lld_dev)
{
	struct hinic5_adev *adev = to_hinic5_adev(lld_dev);

	return adev->chip_node;
}

static struct card_node *hinic5_get_chip_node_by_hwdev(const void *hwdev)
{
	struct card_node *chip_node = NULL;
	struct card_node *node_tmp = NULL;
	struct hinic5_adev *adev = NULL;

	if (!hwdev)
		return NULL;

	hinic5_lld_hold();

	list_for_each_entry(node_tmp, get_hinic5_chip_list(), node) {
		if (!chip_node) {
			list_for_each_entry(adev, &node_tmp->func_list, node) {
				if (adev->hwdev == hwdev) {
					chip_node = node_tmp;
					break;
				}
			}
		}
	}

	hinic5_lld_put();

	return chip_node;
}

static bool is_func_valid(struct hinic5_adev *adev)
{
	if (hinic5_func_type(adev->hwdev) == TYPE_VF)
		return false;

	return true;
}

void hinic5_get_card_info(const void *hwdev, const void *bufin, void *bufout)
{
	struct card_node *chip_node = NULL;
	const struct card_info *info = (const struct card_info *)bufin;
	struct card_info *out_info = (struct card_info *)bufout;
	struct hinic5_adev *adev = NULL;
	void *fun_hwdev = NULL;
	u32 i = 0;
	u32 j = 0;

	out_info->pf_num = 0;

	chip_node = hinic5_get_chip_node_by_hwdev(hwdev);
	if (!chip_node)
		return;

	hinic5_lld_hold();

	list_for_each_entry(adev, &chip_node->func_list, node) {
		if (!is_func_valid(adev))
			continue;

		/* When the number of PFs already obtained exceeds the array size,
		 * stop getting info, only count PF numbers
		 */
		if (j >= PF_MAX_SIZE) {
			out_info->pf_num++;
			j = out_info->pf_num;
			continue;
		}

		// Skip PFs already obtained before
		if (i < info->pf_num) {
			i++;
			continue;
		}

		fun_hwdev = adev->hwdev;

		if (hinic5_support_nic(fun_hwdev, NULL)) {
			if (adev->uld_dev[SERVICE_T_NIC]) {
				out_info->pf[j].pf_type |= (u32)BIT(SERVICE_T_NIC);
				get_dynamic_uld_dev_name(adev, SERVICE_T_NIC, out_info->pf[j].name);
			}
		}

		if (hinic5_support_ppa(fun_hwdev, NULL)) {
			if (adev->uld_dev[SERVICE_T_PPA]) {
				out_info->pf[j].pf_type |= (u32)BIT(SERVICE_T_PPA);
				get_dynamic_uld_dev_name(adev, SERVICE_T_PPA, out_info->pf[j].name);
			}
		}

		if (hinic5_support_bifur(fun_hwdev))
			if (adev->uld_dev[SERVICE_T_BIFUR])
				get_dynamic_uld_dev_name(adev, SERVICE_T_BIFUR,
							 out_info->pf[j].name);

		if (hinic5_func_for_mgmt(fun_hwdev))
			strscpy(out_info->pf[j].name, "FOR_MGMT", IFNAMSIZ);

		strscpy(out_info->pf[j].bus_info, dev_name(adev->dev),
			sizeof(out_info->pf[j].bus_info));
		out_info->pf_num++;
		j = out_info->pf_num;
		i++;
	}

	hinic5_lld_put();
}

bool hinic5_is_in_host(void)
{
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;

	hinic5_lld_hold();
	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (hinic5_func_type(adev->hwdev) != TYPE_VF) {
				hinic5_lld_put();
				return true;
			}
		}
	}

	hinic5_lld_put();

	return false;
}

static bool chip_node_is_exist(struct hinic5_adev *adev)
{
#if !defined(__VMWARE__)
	struct card_node *chip_node = NULL;

	/* SPU connects through HVA, each function occupies a bus number,
	 * requires special handling; SPU PCI scenario not adapted for multi-card
	 */
	if (adev->lld_dev.dev_type == HINIC5_DEVICE_T_PCI &&
	    HINIC5_IS_SPU_DEV(hinic5_adev_get_device_id(adev))) {
		if (!list_empty(get_hinic5_chip_list())) {
			adev->chip_node =
				list_first_entry(get_hinic5_chip_list(), struct card_node, node);
			return true;
		}
		return false;
	}

	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		if (chip_node->id == adev->info.id) {
			adev->chip_node = chip_node;
			return true;
		}
	}

#endif /* __VMWARE__ */

	return false;
}

int hinic5_alloc_chip_node(struct hinic5_adev *adev)
{
	struct card_node *chip_node = NULL;
	unsigned char i;

	if (chip_node_is_exist(adev))
		return 0;

	for (i = 0; i < CARD_MAX_SIZE; i++) {
		if (test_and_set_bit(i, &card_bit_map) == 0)
			break;
	}

	if (i == CARD_MAX_SIZE) {
		sdk_err(adev->dev, "Failed to alloc card id\n");
		return -EFAULT;
	}

	chip_node = kzalloc(sizeof(*chip_node), GFP_KERNEL);
	if (!chip_node) {
		clear_bit(i, &card_bit_map);
		sdk_err(adev->dev,
			"Failed to alloc chip node\n");
		return -ENOMEM;
	}

	chip_node->id = adev->info.id;

	if (snprintf(chip_node->chip_name, IFNAMSIZ, "%s%u", HINIC5_CHIP_NAME, i) < 0) {
		clear_bit(i, &card_bit_map);
		kfree(chip_node);
		return -EINVAL;
	}

	spin_lock_init(&chip_node->fw_update_context_lock);
	spin_lock_init(&chip_node->dbgtool_info_lock);

	sdk_info(adev->dev,
		 "Add new chip %s to global list succeed\n",
		 chip_node->chip_name);

	list_add_tail(&chip_node->node, get_hinic5_chip_list());

	INIT_LIST_HEAD(&chip_node->func_list);
	adev->chip_node = chip_node;

	return 0;
}

void hinic5_free_chip_node(struct hinic5_adev *adev)
{
	struct card_node *chip_node = adev->chip_node;
	int id, err;

	if (list_empty(&chip_node->func_list) != 0) {
		list_del(&chip_node->node);
		sdk_info(adev->dev,
			 "Delete chip %s from global list succeed\n",
			 chip_node->chip_name);

		spin_lock_deinit(&chip_node->dbgtool_info_lock);
		spin_lock_deinit(&chip_node->fw_update_context_lock);

		err = sscanf(chip_node->chip_name, HINIC5_CHIP_NAME "%d", &id);
		if (err != 1)
			sdk_err(adev->dev, "Failed to get hinic5 id\n");

		if (chip_node->fw_update_context) {
			hinic5_fw_update_free_context(chip_node->fw_update_context);
			chip_node->fw_update_context = NULL;
		}

		clear_bit(id, &card_bit_map);

		kfree(chip_node);
	}
}

int hinic5_get_pf_id(struct card_node *chip_node, u32 port_id, u32 *pf_id, u32 *isvalid)
{
	struct hinic5_adev *adev = NULL;

	hinic5_lld_hold();
	list_for_each_entry(adev, &chip_node->func_list, node) {
		if (hinic5_func_type(adev->hwdev) == TYPE_VF)
			continue;

		if (hinic5_physical_port_id(adev->hwdev) == port_id) {
			*pf_id = hinic5_global_func_id(adev->hwdev);
			*isvalid = 1;
			break;
		}
	}
	hinic5_lld_put();

	return 0;
}

struct hinic5_lld_dev *hinic5_get_lld_dev_by_func_id(const char *chip_name, u32 func_id)
{
	struct hinic5_adev *adev = NULL;
	struct card_node *chip_node = NULL;

	hinic5_lld_hold();
	list_for_each_entry(chip_node, get_hinic5_chip_list(), node) {
		if (strncmp(chip_node->chip_name, chip_name, IFNAMSIZ) != 0)
			continue;
		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (hinic5_global_func_id(adev->hwdev) == func_id) {
				hinic5_lld_dev_hold(&adev->lld_dev);
				hinic5_lld_put();
				return &adev->lld_dev;
			}
		}
	}
	hinic5_lld_put();

	return NULL;
}

void hinic5_get_mbox_cnt(const void *hwdev, void *buf_out)
{
	struct card_node *chip_node = NULL;
	struct card_mbox_cnt_info *info = (struct card_mbox_cnt_info *)buf_out;
	struct hinic5_adev *adev = NULL;
	struct hinic5_hwdev *func_hwdev = NULL;
	u32 i = 0;

	info->func_num = 0;
	chip_node = hinic5_get_chip_node_by_hwdev(hwdev);
	if (!chip_node)
		return;

	hinic5_lld_hold();

	list_for_each_entry(adev, &chip_node->func_list, node) {
		func_hwdev = (struct hinic5_hwdev *)adev->hwdev;
		strscpy(info->func_info[i].bus_info, dev_name(adev->dev),
			sizeof(info->func_info[i].bus_info));

		info->func_info[i].send_cnt = func_hwdev->mbox_send_cnt;
		info->func_info[i].ack_cnt = func_hwdev->mbox_ack_cnt;
		info->func_num++;
		i = info->func_num;
		if (i >= ARRAY_SIZE(info->func_info)) {
			sdk_err(adev->dev, "chip_node->func_list bigger than pf_max + vf_max\n");
			break;
		}
	}

	hinic5_lld_put();
}

int hinic5_get_card_nic_uld_array(struct hinic5_lld_dev *lld_dev, u32 *dev_cnt, void *array[])
{
	struct hinic5_adev *adev = to_hinic5_adev(lld_dev);
	struct card_node *chip_node = NULL;
	void *uld_temp = NULL;
	u32 cnt;

	if (!lld_dev || !adev || !hinic5_support_nic(adev->hwdev, NULL) || !array)
		return -EINVAL;

	hinic5_lld_hold();

	cnt = 0;
	chip_node = adev->chip_node;
	list_for_each_entry(adev, &chip_node->func_list, node) {
		if (hinic5_func_type(adev->hwdev) == TYPE_VF)
			continue;

		uld_temp = hinic5_get_uld_dev_unsafe(&adev->lld_dev, SERVICE_T_NIC);
		if (!uld_temp)
			continue;

		array[cnt] = uld_temp;
		cnt++;
	}
	hinic5_lld_put();

	*dev_cnt = cnt;

	return 0;
}
EXPORT_SYMBOL(hinic5_get_card_nic_uld_array);

int hinic5_get_device_info(struct hinic5_lld_dev *lld_dev, struct hinic5_device_info *info)
{
	struct hinic5_adev *adev = to_hinic5_adev(lld_dev);

	if (!info)
		return -EINVAL;

	switch (lld_dev->dev_type) {
	case HINIC5_DEVICE_T_PCI:
	case HINIC5_DEVICE_T_UB:
		memcpy((info), &adev->info, sizeof(adev->info));
		return 0;
	default:
		break;
	}
	return -EINVAL;
}
EXPORT_SYMBOL(hinic5_get_device_info);
