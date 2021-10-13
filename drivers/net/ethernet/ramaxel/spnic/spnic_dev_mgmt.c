// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <net/addrconf.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/debugfs.h>

#include "sphw_common.h"
#include "sphw_mt.h"
#include "sphw_crm.h"
#include "spnic_lld.h"
#include "spnic_sriov.h"
#include "spnic_pci_id_tbl.h"
#include "spnic_dev_mgmt.h"

#define SPNIC_WAIT_TOOL_CNT_TIMEOUT		10000
#define SPNIC_WAIT_TOOL_MIN_USLEEP_TIME	9900
#define SPNIC_WAIT_TOOL_MAX_USLEEP_TIME	10000

#define MAX_CARD_ID 64
static unsigned long card_bit_map;

LIST_HEAD(g_spnic_chip_list);

void lld_dev_cnt_init(struct spnic_pcidev *pci_adapter)
{
	atomic_set(&pci_adapter->ref_cnt, 0);
}

void lld_dev_hold(struct spnic_lld_dev *dev)
{
	struct spnic_pcidev *pci_adapter = pci_get_drvdata(dev->pdev);

	atomic_inc(&pci_adapter->ref_cnt);
}

void lld_dev_put(struct spnic_lld_dev *dev)
{
	struct spnic_pcidev *pci_adapter = pci_get_drvdata(dev->pdev);

	atomic_dec(&pci_adapter->ref_cnt);
}

void wait_lld_dev_unused(struct spnic_pcidev *pci_adapter)
{
	unsigned long end;

	end = jiffies + msecs_to_jiffies(SPNIC_WAIT_TOOL_CNT_TIMEOUT);
	do {
		if (!atomic_read(&pci_adapter->ref_cnt))
			return;

		/* if sleep 10ms, use usleep_range to be more precise */
		usleep_range(SPNIC_WAIT_TOOL_MIN_USLEEP_TIME,
			     SPNIC_WAIT_TOOL_MAX_USLEEP_TIME);
	} while (time_before(jiffies, end));
}

enum spnic_lld_status {
	SPNIC_NODE_CHANGE	= BIT(0),
};

struct spnic_lld_lock {
	/* lock for chip list */
	struct mutex		lld_mutex;
	unsigned long		status;
	atomic_t		dev_ref_cnt;
};

struct spnic_lld_lock g_lld_lock;

#define WAIT_LLD_DEV_HOLD_TIMEOUT	(10 * 60 * 1000)	/* 10minutes */
#define WAIT_LLD_DEV_NODE_CHANGED	(10 * 60 * 1000)	/* 10minutes */
#define WAIT_LLD_DEV_REF_CNT_EMPTY	(2 * 60 * 1000)		/* 2minutes */
#define PRINT_TIMEOUT_INTERVAL		10000
#define MS_PER_SEC			1000
#define LLD_LOCK_MIN_USLEEP_TIME	900
#define LLD_LOCK_MAX_USLEEP_TIME	1000

/* node in chip_node will changed, tools or driver can't get node
 * during this situation
 */
void lld_lock_chip_node(void)
{
	unsigned long end;
	bool timeout = true;
	u32 loop_cnt;

	mutex_lock(&g_lld_lock.lld_mutex);

	loop_cnt = 0;
	end = jiffies + msecs_to_jiffies(WAIT_LLD_DEV_NODE_CHANGED);
	do {
		if (!test_and_set_bit(SPNIC_NODE_CHANGE, &g_lld_lock.status)) {
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

	if (timeout && test_and_set_bit(SPNIC_NODE_CHANGE, &g_lld_lock.status))
		pr_warn("Wait for lld node change complete timeout when trying to get lld lock\n");

	loop_cnt = 0;
	timeout = true;
	end = jiffies + msecs_to_jiffies(WAIT_LLD_DEV_NODE_CHANGED);
	do {
		if (!atomic_read(&g_lld_lock.dev_ref_cnt)) {
			timeout = false;
			break;
		}

		loop_cnt++;
		if (loop_cnt % PRINT_TIMEOUT_INTERVAL == 0)
			pr_warn("Wait for lld dev unused for %us, reference count: %d\n",
				loop_cnt / MS_PER_SEC,
				atomic_read(&g_lld_lock.dev_ref_cnt));

		/* if sleep 1ms, use usleep_range to be more precise */
		usleep_range(LLD_LOCK_MIN_USLEEP_TIME,
			     LLD_LOCK_MAX_USLEEP_TIME);
	} while (time_before(jiffies, end));

	if (timeout && atomic_read(&g_lld_lock.dev_ref_cnt))
		pr_warn("Wait for lld dev unused timeout\n");

	mutex_unlock(&g_lld_lock.lld_mutex);
}

void lld_unlock_chip_node(void)
{
	clear_bit(SPNIC_NODE_CHANGE, &g_lld_lock.status);
}

/* When tools or other drivers want to get node of chip_node, use this function
 * to prevent node be freed
 */
void lld_hold(void)
{
	unsigned long end;
	u32 loop_cnt = 0;

	/* ensure there have not any chip node in changing */
	mutex_lock(&g_lld_lock.lld_mutex);

	end = jiffies + msecs_to_jiffies(WAIT_LLD_DEV_HOLD_TIMEOUT);
	do {
		if (!test_bit(SPNIC_NODE_CHANGE, &g_lld_lock.status))
			break;

		loop_cnt++;

		if (loop_cnt % PRINT_TIMEOUT_INTERVAL == 0)
			pr_warn("Wait lld node change complete for %us\n",
				loop_cnt / MS_PER_SEC);
		/* if sleep 1ms, use usleep_range to be more precise */
		usleep_range(LLD_LOCK_MIN_USLEEP_TIME,
			     LLD_LOCK_MAX_USLEEP_TIME);
	} while (time_before(jiffies, end));

	if (test_bit(SPNIC_NODE_CHANGE, &g_lld_lock.status))
		pr_warn("Wait lld node change complete timeout when trying to hode lld dev\n");

	atomic_inc(&g_lld_lock.dev_ref_cnt);
	mutex_unlock(&g_lld_lock.lld_mutex);
}

void lld_put(void)
{
	atomic_dec(&g_lld_lock.dev_ref_cnt);
}

void spnic_lld_lock_init(void)
{
	mutex_init(&g_lld_lock.lld_mutex);
	atomic_set(&g_lld_lock.dev_ref_cnt, 0);
}

void spnic_get_all_chip_id(void *id_info)
{
	struct nic_card_id *card_id = (struct nic_card_id *)id_info;
	struct card_node *chip_node = NULL;
	int i = 0;
	int id, err;

	lld_hold();
	list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
		err = sscanf(chip_node->chip_name, SPHW_CHIP_NAME "%d", &id);
		if (err < 0)
			pr_err("Failed to get spnic id\n");
		card_id->id[i] = id;
		i++;
	}
	lld_put();
	card_id->num = i;
}

void spnic_get_card_func_info_by_card_name(const char *chip_name,
					   struct sphw_card_func_info *card_func)
{
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;
	struct func_pdev_info *pdev_info = NULL;

	card_func->num_pf = 0;

	lld_hold();

	list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
		if (strncmp(chip_node->chip_name, chip_name, IFNAMSIZ))
			continue;

		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (sphw_func_type(dev->hwdev) == TYPE_VF)
				continue;

			pdev_info = &card_func->pdev_info[card_func->num_pf];
			pdev_info->bar1_size =
				pci_resource_len(dev->pcidev, SPNIC_PF_PCI_CFG_REG_BAR);
			pdev_info->bar1_phy_addr =
				pci_resource_start(dev->pcidev, SPNIC_PF_PCI_CFG_REG_BAR);

			pdev_info->bar3_size =
				pci_resource_len(dev->pcidev, SPNIC_PCI_MGMT_REG_BAR);
			pdev_info->bar3_phy_addr =
				pci_resource_start(dev->pcidev, SPNIC_PCI_MGMT_REG_BAR);

			card_func->num_pf++;
			if (card_func->num_pf >= CARD_MAX_SIZE) {
				lld_put();
				return;
			}
		}
	}

	lld_put();
}

static bool is_pcidev_match_chip_name(const char *ifname, struct spnic_pcidev *dev,
				      struct card_node *chip_node, enum func_type type)
{
	if (!strncmp(chip_node->chip_name, ifname, IFNAMSIZ)) {
		if (sphw_func_type(dev->hwdev) != type)
			return false;
		return true;
	}

	return false;
}

static struct spnic_lld_dev *_get_lld_dev_by_chip_name(const char *ifname, enum func_type type)
{
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;

	lld_hold();

	list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (is_pcidev_match_chip_name(ifname, dev, chip_node, type)) {
				lld_put();
				return &dev->lld_dev;
			}
		}
	}

	lld_put();
	return NULL;
}

static struct spnic_lld_dev *spnic_get_lld_dev_by_chip_name(const char *ifname)
{
	struct spnic_lld_dev *dev_hw_init = NULL;
	struct spnic_lld_dev *dev = NULL;

	/*find hw init device first*/
	dev_hw_init = _get_lld_dev_by_chip_name(ifname, TYPE_UNKNOWN);
	if (dev_hw_init) {
		if (sphw_func_type(dev_hw_init->hwdev) == TYPE_PPF)
			return dev_hw_init;
	}

	dev = _get_lld_dev_by_chip_name(ifname, TYPE_PPF);
	if (dev) {
		if (dev_hw_init)
			return dev_hw_init;

		return dev;
	}

	dev = _get_lld_dev_by_chip_name(ifname, TYPE_PF);
	if (dev) {
		if (dev_hw_init)
			return dev_hw_init;

		return dev;
	}

	dev = _get_lld_dev_by_chip_name(ifname, TYPE_VF);
	if (dev)
		return dev;

	return NULL;
}

static bool is_pcidev_match_dev_name(const char *ifname, struct spnic_pcidev *dev,
				     enum sphw_service_type type)
{
	enum sphw_service_type i;
	char nic_uld_name[IFNAMSIZ] = {0};
	int err;

	if (type == SERVICE_T_MAX) {
		for (i = SERVICE_T_OVS; i < SERVICE_T_MAX; i++) {
			if (!strncmp(dev->uld_dev_name[i], ifname, IFNAMSIZ))
				return true;
		}
	} else {
		if (!strncmp(dev->uld_dev_name[type], ifname, IFNAMSIZ))
			return true;
	}

	err = spnic_get_uld_dev_name(dev, SERVICE_T_NIC, (char *)nic_uld_name);
	if (!err) {
		if (!strncmp(nic_uld_name, ifname, IFNAMSIZ))
			return true;
	}

	return false;
}

static struct spnic_lld_dev *spnic_get_lld_dev_by_dev_name(const char *ifname,
							   enum sphw_service_type type)
{
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;

	lld_hold();

	list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (is_pcidev_match_dev_name(ifname, dev, type)) {
				lld_put();
				return &dev->lld_dev;
			}
		}
	}

	lld_put();

	return NULL;
}

struct spnic_lld_dev *spnic_get_lld_dev_by_ifname(const char *ifname)
{
	struct spnic_lld_dev *dev = NULL;

	lld_hold();
	/* support search hwdev by chip name, net device name,
	 * or fc device name
	 */
	/* Find pcidev by chip_name first */
	dev = spnic_get_lld_dev_by_chip_name(ifname);
	if (dev)
		goto find_dev;

	/* If ifname not a chip name,
	 * find pcidev by FC name or netdevice name
	 */
	dev = spnic_get_lld_dev_by_dev_name(ifname, SERVICE_T_MAX);
	if (!dev) {
		lld_put();
		return NULL;
	}

find_dev:
	lld_dev_hold(dev);
	lld_put();
	return dev;
}

void *spnic_get_hwdev_by_ifname(const char *ifname)
{
	struct spnic_lld_dev *dev = NULL;

	dev = spnic_get_lld_dev_by_ifname(ifname);
	if (dev)
		return dev->hwdev;

	return NULL;
}

void *spnic_get_uld_dev_by_ifname(const char *ifname, enum sphw_service_type type)
{
	struct spnic_pcidev *dev = NULL;
	struct spnic_lld_dev *lld_dev = NULL;

	if (type >= SERVICE_T_MAX) {
		pr_err("Service type :%d is error\n", type);
		return NULL;
	}

	lld_dev = spnic_get_lld_dev_by_dev_name(ifname, type);
	if (!lld_dev)
		return NULL;

	dev = pci_get_drvdata(lld_dev->pdev);
	if (dev)
		return dev->uld_dev[type];

	return NULL;
}

static struct card_node *spnic_get_chip_node_by_hwdev(const void *hwdev)
{
	struct card_node *chip_node = NULL;
	struct card_node *node_tmp = NULL;
	struct spnic_pcidev *dev = NULL;

	if (!hwdev)
		return NULL;

	lld_hold();

	list_for_each_entry(node_tmp, &g_spnic_chip_list, node) {
		if (!chip_node) {
			list_for_each_entry(dev, &node_tmp->func_list, node) {
				if (dev->hwdev == hwdev) {
					chip_node = node_tmp;
					break;
				}
			}
		}
	}

	lld_put();

	return chip_node;
}

int spnic_get_chip_name_by_hwdev(const void *hwdev, char *ifname)
{
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;

	if (!hwdev || !ifname)
		return -EINVAL;

	lld_hold();

	list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (dev->hwdev == hwdev) {
				strncpy(ifname, chip_node->chip_name, IFNAMSIZ - 1);
				ifname[IFNAMSIZ - 1] = 0;
				lld_put();
				return 0;
			}
		}
	}

	lld_put();

	return -ENXIO;
}

void *spnic_get_uld_dev_by_pdev(struct pci_dev *pdev, enum sphw_service_type type)
{
	struct spnic_pcidev *pci_adapter = NULL;

	if (type >= SERVICE_T_MAX) {
		pr_err("Service type :%d is error\n", type);
		return NULL;
	}

	pci_adapter = pci_get_drvdata(pdev);
	if (pci_adapter)
		return pci_adapter->uld_dev[type];

	return NULL;
}

void *spnic_get_ppf_hwdev_by_pdev(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = NULL;
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;

	if (!pdev)
		return NULL;

	pci_adapter = pci_get_drvdata(pdev);
	if (!pci_adapter)
		return NULL;

	chip_node = pci_adapter->chip_node;
	lld_hold();
	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (dev->hwdev && sphw_func_type(dev->hwdev) == TYPE_PPF) {
			lld_put();
			return dev->hwdev;
		}
	}
	lld_put();

	return NULL;
}

/* NOTICE: nictool can't use this function, because this function can't keep
 * tool context mutual exclusive with remove context
 */
void *spnic_get_ppf_uld_by_pdev(struct pci_dev *pdev, enum sphw_service_type type)
{
	struct spnic_pcidev *pci_adapter = NULL;
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;

	if (!pdev)
		return NULL;

	pci_adapter = pci_get_drvdata(pdev);
	if (!pci_adapter)
		return NULL;

	chip_node = pci_adapter->chip_node;
	lld_hold();
	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (sphw_func_type(dev->hwdev) == TYPE_PPF) {
			lld_put();
			return dev->uld_dev[type];
		}
	}
	lld_put();

	return NULL;
}

int spnic_get_pf_nic_uld_array(struct pci_dev *pdev, u32 *dev_cnt, void *array[])
{
	struct spnic_pcidev *dev = pci_get_drvdata(pdev);
	struct card_node *chip_node = NULL;
	u32 cnt;

	if (!dev || !sphw_support_nic(dev->hwdev, NULL))
		return -EINVAL;

	lld_hold();

	cnt = 0;
	chip_node = dev->chip_node;
	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (sphw_func_type(dev->hwdev) == TYPE_VF)
			continue;

		array[cnt] = dev->uld_dev[SERVICE_T_NIC];
		cnt++;
	}
	lld_put();

	*dev_cnt = cnt;

	return 0;
}

static bool is_func_valid(struct spnic_pcidev *dev)
{
	if (sphw_func_type(dev->hwdev) == TYPE_VF)
		return false;

	return true;
}

int spnic_get_uld_dev_name(struct spnic_pcidev *dev, enum sphw_service_type type, char *ifname)
{
	u32 out_size = IFNAMSIZ;

	if (!g_uld_info[type].ioctl)
		return -EFAULT;

	return g_uld_info[type].ioctl(dev->uld_dev[type], GET_ULD_DEV_NAME,
				      NULL, 0, ifname, &out_size);
}

void spnic_get_card_info(const void *hwdev, void *bufin)
{
	struct card_node *chip_node = NULL;
	struct card_info *info = (struct card_info *)bufin;
	struct spnic_pcidev *dev = NULL;
	void *fun_hwdev = NULL;
	u32 i = 0;

	info->pf_num = 0;

	chip_node = spnic_get_chip_node_by_hwdev(hwdev);
	if (!chip_node)
		return;

	lld_hold();

	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (!is_func_valid(dev))
			continue;

		fun_hwdev = dev->hwdev;

		if (sphw_support_nic(fun_hwdev, NULL)) {
			if (dev->uld_dev[SERVICE_T_NIC]) {
				info->pf[i].pf_type |= (u32)BIT(SERVICE_T_NIC);
				spnic_get_uld_dev_name(dev, SERVICE_T_NIC, info->pf[i].name);
			}
		}

		/* to do : get other service info*/

		if (sphw_func_for_mgmt(fun_hwdev))
			strlcpy(info->pf[i].name, "FOR_MGMT", IFNAMSIZ);

		strlcpy(info->pf[i].bus_info, pci_name(dev->pcidev),
			sizeof(info->pf[i].bus_info));
		info->pf_num++;
		i = info->pf_num;
	}

	lld_put();
}

struct spnic_sriov_info *spnic_get_sriov_info_by_pcidev(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = NULL;

	if (!pdev)
		return NULL;

	pci_adapter = pci_get_drvdata(pdev);
	if (!pci_adapter)
		return NULL;

	return &pci_adapter->sriov_info;
}

void *spnic_get_hwdev_by_pcidev(struct pci_dev *pdev)
{
	struct spnic_pcidev *pci_adapter = NULL;

	if (!pdev)
		return NULL;

	pci_adapter = pci_get_drvdata(pdev);
	if (!pci_adapter)
		return NULL;

	return pci_adapter->hwdev;
}

bool spnic_is_in_host(void)
{
	struct card_node *chip_node = NULL;
	struct spnic_pcidev *dev = NULL;

	lld_hold();
	list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (sphw_func_type(dev->hwdev) != TYPE_VF) {
				lld_put();
				return true;
			}
		}
	}

	lld_put();

	return false;
}

int spnic_get_chip_up_bitmap(struct pci_dev *pdev, bool *is_setted, u8 *valid_up_bitmap)
{
	struct spnic_pcidev *dev = pci_get_drvdata(pdev);
	struct card_node *chip_node = NULL;

	if (!dev || !is_setted || !valid_up_bitmap)
		return -EINVAL;

	chip_node = dev->chip_node;
	*is_setted = chip_node->up_bitmap_setted;
	if (chip_node->up_bitmap_setted)
		*valid_up_bitmap = chip_node->valid_up_bitmap;

	return 0;
}

int spnic_set_chip_up_bitmap(struct pci_dev *pdev, u8 valid_up_bitmap)
{
	struct spnic_pcidev *dev = pci_get_drvdata(pdev);
	struct card_node *chip_node = NULL;

	if (!dev)
		return -EINVAL;

	chip_node = dev->chip_node;
	chip_node->up_bitmap_setted = true;
	chip_node->valid_up_bitmap = valid_up_bitmap;

	return 0;
}

static bool chip_node_is_exist(struct spnic_pcidev *pci_adapter, unsigned char *bus_number)
{
	struct card_node *chip_node = NULL;

	if  (!pci_is_root_bus(pci_adapter->pcidev->bus))
		*bus_number = pci_adapter->pcidev->bus->number;

	if (*bus_number != 0) {
		list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
			if (chip_node->bus_num == *bus_number) {
				pci_adapter->chip_node = chip_node;
				return true;
			}
		}
	} else if (pci_adapter->pcidev->device == SPNIC_DEV_ID_VF ||
		   pci_adapter->pcidev->device == SPNIC_DEV_ID_VF_HV) {
		list_for_each_entry(chip_node, &g_spnic_chip_list, node) {
			if (chip_node) {
				pci_adapter->chip_node = chip_node;
				return true;
			}
		}
	}

	return false;
}

int alloc_chip_node(struct spnic_pcidev *pci_adapter)
{
	struct card_node *chip_node = NULL;
	unsigned char i;
	unsigned char bus_number = 0;

	if (chip_node_is_exist(pci_adapter, &bus_number))
		return 0;

	for (i = 0; i < MAX_CARD_ID; i++) {
		if (!test_and_set_bit(i, &card_bit_map))
			break;
	}

	if (i == MAX_CARD_ID) {
		sdk_err(&pci_adapter->pcidev->dev, "Failed to alloc card id\n");
		return -EFAULT;
	}

	chip_node = kzalloc(sizeof(*chip_node), GFP_KERNEL);
	if (!chip_node) {
		clear_bit(i, &card_bit_map);
		sdk_err(&pci_adapter->pcidev->dev,
			"Failed to alloc chip node\n");
		return -ENOMEM;
	}

	/* bus number */
	chip_node->bus_num = bus_number;

	snprintf(chip_node->chip_name, IFNAMSIZ, "%s%u", SPHW_CHIP_NAME, i);

	sdk_info(&pci_adapter->pcidev->dev, "Add new chip %s to global list succeed\n",
		 chip_node->chip_name);

	list_add_tail(&chip_node->node, &g_spnic_chip_list);

	INIT_LIST_HEAD(&chip_node->func_list);
	pci_adapter->chip_node = chip_node;

	return 0;
}

void free_chip_node(struct spnic_pcidev *pci_adapter)
{
	struct card_node *chip_node = pci_adapter->chip_node;
	int id, err;

	if (list_empty(&chip_node->func_list)) {
		list_del(&chip_node->node);
		sdk_info(&pci_adapter->pcidev->dev, "Delete chip %s from global list succeed\n",
			 chip_node->chip_name);
		err = sscanf(chip_node->chip_name, SPHW_CHIP_NAME "%d", &id);
		if (err < 0)
			sdk_err(&pci_adapter->pcidev->dev, "Failed to get spnic id\n");

		clear_bit(id, &card_bit_map);

		kfree(chip_node);
	}
}
