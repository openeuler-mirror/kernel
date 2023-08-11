// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 3snic Technologies Co., Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [BASE]" fmt

#include <net/addrconf.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/debugfs.h>

#include "sss_kernel.h"
#include "sss_hw.h"
#include "sss_pci_sriov.h"
#include "sss_pci_id_tbl.h"
#include "sss_adapter_mgmt.h"
#include "sss_pci_global.h"

#define SSS_ADAPTER_CNT_TIMEOUT		10000
#define SSS_WAIT_ADAPTER_USLEEP_MIN	9900
#define SSS_WAIT_ADAPTER_USLEEP_MAX	10000

#define SSS_CHIP_NODE_HOLD_TIMEOUT		(10 * 60 * 1000)
#define SSS_WAIT_CHIP_NODE_CHANGED			(10 * 60 * 1000)
#define SSS_PRINT_TIMEOUT_INTERVAL			10000
#define SSS_MICRO_SECOND					1000
#define SSS_CHIP_NODE_USLEEP_MIN		900
#define SSS_CHIP_NODE_USLEEP_MAX		1000

#define SSS_CARD_CNT_MAX	64

#define SSS_IS_SPU_DEV(pdev)	((pdev)->device == SSS_DEV_ID_SPU)

enum sss_node_state {
	SSS_NODE_CHANGE	= BIT(0),
};

struct sss_chip_node_lock {
	/* lock for chip list */
	struct mutex		chip_mutex;
	unsigned long		state;
	atomic_t		ref_cnt;
};

static struct sss_chip_node_lock g_chip_node_lock;

static unsigned long g_index_bit_map;

LIST_HEAD(g_chip_list);

struct list_head *sss_get_chip_list(void)
{
	return &g_chip_list;
}

static void sss_chip_node_lock(void)
{
	unsigned long end;
	bool timeout = true;
	u32 loop_cnt;

	mutex_lock(&g_chip_node_lock.chip_mutex);

	loop_cnt = 0;
	end = jiffies + msecs_to_jiffies(SSS_WAIT_CHIP_NODE_CHANGED);
	do {
		if (!test_and_set_bit(SSS_NODE_CHANGE, &g_chip_node_lock.state)) {
			timeout = false;
			break;
		}

		loop_cnt++;
		if (loop_cnt % SSS_PRINT_TIMEOUT_INTERVAL == 0)
			pr_warn("Wait for adapter change complete for %us\n",
				loop_cnt / SSS_MICRO_SECOND);

		/* if sleep 1ms, use usleep_range to be more precise */
		usleep_range(SSS_CHIP_NODE_USLEEP_MIN,
			     SSS_CHIP_NODE_USLEEP_MAX);
	} while (time_before(jiffies, end));

	if (timeout && test_and_set_bit(SSS_NODE_CHANGE, &g_chip_node_lock.state))
		pr_warn("Wait for adapter change complete timeout when trying to get adapter lock\n");

	loop_cnt = 0;
	timeout = true;
	end = jiffies + msecs_to_jiffies(SSS_WAIT_CHIP_NODE_CHANGED);
	do {
		if (!atomic_read(&g_chip_node_lock.ref_cnt)) {
			timeout = false;
			break;
		}

		loop_cnt++;
		if (loop_cnt % SSS_PRINT_TIMEOUT_INTERVAL == 0)
			pr_warn("Wait for adapter unused for %us, reference count: %d\n",
				loop_cnt / SSS_MICRO_SECOND,
				atomic_read(&g_chip_node_lock.ref_cnt));

		usleep_range(SSS_CHIP_NODE_USLEEP_MIN,
			     SSS_CHIP_NODE_USLEEP_MAX);
	} while (time_before(jiffies, end));

	if (timeout && atomic_read(&g_chip_node_lock.ref_cnt))
		pr_warn("Wait for adapter unused timeout\n");

	mutex_unlock(&g_chip_node_lock.chip_mutex);
}

static void sss_chip_node_unlock(void)
{
	clear_bit(SSS_NODE_CHANGE, &g_chip_node_lock.state);
}

void sss_hold_chip_node(void)
{
	unsigned long end;
	u32 loop_cnt = 0;

	mutex_lock(&g_chip_node_lock.chip_mutex);

	end = jiffies + msecs_to_jiffies(SSS_CHIP_NODE_HOLD_TIMEOUT);
	do {
		if (!test_bit(SSS_NODE_CHANGE, &g_chip_node_lock.state))
			break;

		loop_cnt++;

		if (loop_cnt % SSS_PRINT_TIMEOUT_INTERVAL == 0)
			pr_warn("Wait adapter change complete for %us\n",
				loop_cnt / SSS_MICRO_SECOND);
		/* if sleep 1ms, use usleep_range to be more precise */
		usleep_range(SSS_CHIP_NODE_USLEEP_MIN,
			     SSS_CHIP_NODE_USLEEP_MAX);
	} while (time_before(jiffies, end));

	if (test_bit(SSS_NODE_CHANGE, &g_chip_node_lock.state))
		pr_warn("Wait adapter change complete timeout when trying to adapter dev\n");

	atomic_inc(&g_chip_node_lock.ref_cnt);
	mutex_unlock(&g_chip_node_lock.chip_mutex);
}

void sss_put_chip_node(void)
{
	atomic_dec(&g_chip_node_lock.ref_cnt);
}

void sss_pre_init(void)
{
	mutex_init(&g_chip_node_lock.chip_mutex);
	atomic_set(&g_chip_node_lock.ref_cnt, 0);
	sss_init_uld_lock();
}

struct sss_pci_adapter *sss_get_adapter_by_pcidev(struct pci_dev *pdev)
{
	struct sss_pci_adapter *adapter = pci_get_drvdata(pdev);

	if (!pdev)
		return NULL;

	return adapter;
}

static bool sss_chip_node_exist(struct sss_pci_adapter *adapter,
				unsigned char bus_id)
{
	struct sss_card_node *chip_node = NULL;

	sss_chip_node_lock();
	if (bus_id != 0) {
		list_for_each_entry(chip_node, &g_chip_list, node) {
			if (chip_node->bus_id == bus_id) {
				adapter->chip_node = chip_node;
				sss_chip_node_unlock();
				return true;
			}
		}
	} else if (SSS_IS_VF_DEV(adapter->pcidev) ||
		   SSS_IS_SPU_DEV(adapter->pcidev)) {
		list_for_each_entry(chip_node, &g_chip_list, node) {
			if (chip_node) {
				adapter->chip_node = chip_node;
				sss_chip_node_unlock();
				return true;
			}
		}
	}
	sss_chip_node_unlock();

	return false;
}

static unsigned char sss_get_pci_bus_id(struct sss_pci_adapter *adapter)
{
	struct pci_dev *pf_pdev = NULL;
	unsigned char bus_id = 0;

	if (!pci_is_root_bus(adapter->pcidev->bus))
		bus_id = adapter->pcidev->bus->number;

	if (bus_id == 0)
		return bus_id;

	if (adapter->pcidev->is_virtfn) {
		pf_pdev = adapter->pcidev->physfn;
		bus_id = pf_pdev->bus->number;
	}

	return bus_id;
}

static bool sss_alloc_card_id(u8 *id)
{
	unsigned char i;

	sss_chip_node_lock();
	for (i = 0; i < SSS_CARD_CNT_MAX; i++) {
		if (test_and_set_bit(i, &g_index_bit_map) == 0) {
			sss_chip_node_unlock();
			*id = i;
			return true;
		}
	}
	sss_chip_node_unlock();

	return false;
}

static void sss_free_card_id(u8 id)
{
	clear_bit(id, &g_index_bit_map);
}

int sss_alloc_chip_node(struct sss_pci_adapter *adapter)
{
	struct sss_card_node *chip_node = NULL;
	unsigned char card_id;
	unsigned char bus_id;

	bus_id = sss_get_pci_bus_id(adapter);

	if (sss_chip_node_exist(adapter, bus_id))
		return 0;

	chip_node = kzalloc(sizeof(*chip_node), GFP_KERNEL);
	if (!chip_node)
		return -ENOMEM;

	chip_node->bus_id = bus_id;

	if (!sss_alloc_card_id(&card_id)) {
		kfree(chip_node);
		sdk_err(&adapter->pcidev->dev, "chip node is exceed\n");
		return -EINVAL;
	}

	if (snprintf(chip_node->chip_name, IFNAMSIZ, "%s%u", SSS_CHIP_NAME, card_id) < 0) {
		sss_free_card_id(card_id);
		kfree(chip_node);
		return -EINVAL;
	}

	INIT_LIST_HEAD(&chip_node->func_list);
	sss_chip_node_lock();
	list_add_tail(&chip_node->node, &g_chip_list);
	sss_chip_node_unlock();
	adapter->chip_node = chip_node;
	sdk_info(&adapter->pcidev->dev,
		 "Success to add new chip %s to global list\n", chip_node->chip_name);

	return 0;
}

void sss_free_chip_node(struct sss_pci_adapter *adapter)
{
	struct sss_card_node *chip_node = adapter->chip_node;
	int id;
	int ret;

	sss_chip_node_lock();
	if (list_empty(&chip_node->func_list)) {
		list_del(&chip_node->node);
		sdk_info(&adapter->pcidev->dev,
			 "Success to delete chip %s from global list\n",
			 chip_node->chip_name);
		ret = sscanf(chip_node->chip_name, SSS_CHIP_NAME "%d", &id);
		if (ret < 0)
			sdk_err(&adapter->pcidev->dev, "Fail to get nic id\n");

		clear_bit(id, &g_index_bit_map);

		kfree(chip_node);
	}
	sss_chip_node_unlock();
}

void sss_add_func_list(struct sss_pci_adapter *adapter)
{
	sss_chip_node_lock();
	list_add_tail(&adapter->node, &adapter->chip_node->func_list);
	sss_chip_node_unlock();
}

void sss_del_func_list(struct sss_pci_adapter *adapter)
{
	sss_chip_node_lock();
	list_del(&adapter->node);
	sss_chip_node_unlock();
}
