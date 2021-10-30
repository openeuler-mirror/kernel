// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/aer.h>
#include <linux/debugfs.h>

#include "spfc_lld.h"
#include "sphw_hw.h"
#include "sphw_mt.h"
#include "sphw_hw_cfg.h"
#include "sphw_hw_comm.h"
#include "sphw_common.h"
#include "spfc_cqm_main.h"
#include "spfc_module.h"

#define SPFC_DRV_NAME "spfc"
#define SPFC_CHIP_NAME "spfc"

#define PCI_VENDOR_ID_RAMAXEL			0x1E81
#define SPFC_DEV_ID_PF_STD			0x9010
#define SPFC_DEV_ID_VF			        0x9008

#define SPFC_VF_PCI_CFG_REG_BAR 0
#define SPFC_PF_PCI_CFG_REG_BAR 1

#define SPFC_PCI_INTR_REG_BAR 2
#define SPFC_PCI_MGMT_REG_BAR 3
#define SPFC_PCI_DB_BAR 4

#define SPFC_SECOND_BASE (1000)
#define SPFC_SYNC_YEAR_OFFSET (1900)
#define SPFC_SYNC_MONTH_OFFSET (1)
#define SPFC_MINUTE_BASE (60)
#define SPFC_WAIT_TOOL_CNT_TIMEOUT 10000

#define SPFC_MIN_TIME_IN_USECS 900
#define SPFC_MAX_TIME_IN_USECS 1000
#define SPFC_MAX_LOOP_TIMES 10000

#define SPFC_TOOL_MIN_TIME_IN_USECS 9900
#define SPFC_TOOL_MAX_TIME_IN_USECS 10000

#define SPFC_EVENT_PROCESS_TIMEOUT 10000

#define FIND_BIT(num, n) (((num) & (1UL << (n))) ? 1 : 0)
#define SET_BIT(num, n) ((num) | (1UL << (n)))
#define CLEAR_BIT(num, n) ((num) & (~(1UL << (n))))

#define MAX_CARD_ID 64
static unsigned long card_bit_map;
LIST_HEAD(g_spfc_chip_list);
struct spfc_uld_info g_uld_info[SERVICE_T_MAX] = { {0} };

struct unf_cm_handle_op spfc_cm_op_handle = {0};

u32 allowed_probe_num = SPFC_MAX_PORT_NUM;
u32 dif_sgl_mode;
u32 max_speed = SPFC_SPEED_32G;
u32 accum_db_num = 1;
u32 dif_type = 0x1;
u32 wqe_page_size = 4096;
u32 wqe_pre_load = 6;
u32 combo_length = 128;
u32 cos_bit_map = 0x1f;
u32 spfc_dif_type;
u32 spfc_dif_enable;
u8 spfc_guard;
int link_lose_tmo = 30;

u32 exit_count = 4096;
u32 exit_stride = 4096;
u32 exit_base;

/* dfx counter */
atomic64_t rx_tx_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
atomic64_t rx_tx_err[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
atomic64_t scq_err_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
atomic64_t aeq_err_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
atomic64_t dif_err_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
atomic64_t mail_box_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
atomic64_t up_err_event_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
u64 link_event_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_LINK_EVENT_CNT];
u64 link_reason_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_LINK_REASON_CNT];
u64 hba_stat[SPFC_MAX_PORT_NUM][SPFC_HBA_STAT_BUTT];
atomic64_t com_up_event_err_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];

#ifndef MAX_SIZE
#define MAX_SIZE (16)
#endif

struct spfc_lld_lock g_lld_lock;

/* g_device_mutex */
struct mutex g_device_mutex;

/* pci device initialize lock */
struct mutex g_pci_init_mutex;

#define WAIT_LLD_DEV_HOLD_TIMEOUT (10 * 60 * 1000) /* 10minutes */
#define WAIT_LLD_DEV_NODE_CHANGED (10 * 60 * 1000) /* 10minutes */
#define WAIT_LLD_DEV_REF_CNT_EMPTY (2 * 60 * 1000) /* 2minutes */

void lld_dev_cnt_init(struct spfc_pcidev *pci_adapter)
{
	atomic_set(&pci_adapter->ref_cnt, 0);
}

void lld_dev_hold(struct spfc_lld_dev *dev)
{
	struct spfc_pcidev *pci_adapter = pci_get_drvdata(dev->pdev);

	atomic_inc(&pci_adapter->ref_cnt);
}

void lld_dev_put(struct spfc_lld_dev *dev)
{
	struct spfc_pcidev *pci_adapter = pci_get_drvdata(dev->pdev);

	atomic_dec(&pci_adapter->ref_cnt);
}

static void spfc_sync_time_to_fmw(struct spfc_pcidev *pdev_pri)
{
	struct tm tm = {0};
	u64 tv_msec;
	int err;

	tv_msec = ktime_to_ms(ktime_get_real());
	err = sphw_sync_time(pdev_pri->hwdev, tv_msec);
	if (err) {
		sdk_err(&pdev_pri->pcidev->dev, "Synchronize UTC time to firmware failed, errno:%d.\n",
			err);
	} else {
		time64_to_tm(tv_msec / MSEC_PER_SEC, 0, &tm);
		sdk_info(&pdev_pri->pcidev->dev, "Synchronize UTC time to firmware succeed. UTC time %ld-%02d-%02d %02d:%02d:%02d.\n",
			 tm.tm_year + 1900, tm.tm_mon + 1,
			 tm.tm_mday, tm.tm_hour,
			 tm.tm_min, tm.tm_sec);
	}
}

void wait_lld_dev_unused(struct spfc_pcidev *pci_adapter)
{
	u32 loop_cnt = 0;

	while (loop_cnt < SPFC_WAIT_TOOL_CNT_TIMEOUT) {
		if (!atomic_read(&pci_adapter->ref_cnt))
			return;

		usleep_range(SPFC_TOOL_MIN_TIME_IN_USECS, SPFC_TOOL_MAX_TIME_IN_USECS);
		loop_cnt++;
	}
}

static void lld_lock_chip_node(void)
{
	u32 loop_cnt;

	mutex_lock(&g_lld_lock.lld_mutex);

	loop_cnt = 0;
	while (loop_cnt < WAIT_LLD_DEV_NODE_CHANGED) {
		if (!test_and_set_bit(SPFC_NODE_CHANGE, &g_lld_lock.status))
			break;

		loop_cnt++;

		if (loop_cnt % SPFC_MAX_LOOP_TIMES == 0)
			pr_warn("[warn]Wait for lld node change complete for %us",
				loop_cnt / UNF_S_TO_MS);

		usleep_range(SPFC_MIN_TIME_IN_USECS, SPFC_MAX_TIME_IN_USECS);
	}

	if (loop_cnt == WAIT_LLD_DEV_NODE_CHANGED)
		pr_warn("[warn]Wait for lld node change complete timeout when  try to get lld lock");

	loop_cnt = 0;
	while (loop_cnt < WAIT_LLD_DEV_REF_CNT_EMPTY) {
		if (!atomic_read(&g_lld_lock.dev_ref_cnt))
			break;

		loop_cnt++;

		if (loop_cnt % SPFC_MAX_LOOP_TIMES == 0)
			pr_warn("[warn]Wait for lld dev unused for %us, reference count: %d",
				loop_cnt / UNF_S_TO_MS, atomic_read(&g_lld_lock.dev_ref_cnt));

		usleep_range(SPFC_MIN_TIME_IN_USECS, SPFC_MAX_TIME_IN_USECS);
	}

	if (loop_cnt == WAIT_LLD_DEV_REF_CNT_EMPTY)
		pr_warn("[warn]Wait for lld dev unused timeout");

	mutex_unlock(&g_lld_lock.lld_mutex);
}

static void lld_unlock_chip_node(void)
{
	clear_bit(SPFC_NODE_CHANGE, &g_lld_lock.status);
}

void lld_hold(void)
{
	u32 loop_cnt = 0;

	/* ensure there have not any chip node in changing */
	mutex_lock(&g_lld_lock.lld_mutex);

	while (loop_cnt < WAIT_LLD_DEV_HOLD_TIMEOUT) {
		if (!test_bit(SPFC_NODE_CHANGE, &g_lld_lock.status))
			break;

		loop_cnt++;

		if (loop_cnt % SPFC_MAX_LOOP_TIMES == 0)
			pr_warn("[warn]Wait lld node change complete for %u",
				loop_cnt / UNF_S_TO_MS);

		usleep_range(SPFC_MIN_TIME_IN_USECS, SPFC_MAX_TIME_IN_USECS);
	}

	if (loop_cnt == WAIT_LLD_DEV_HOLD_TIMEOUT)
		pr_warn("[warn]Wait lld node change complete timeout when try to hode lld dev %u",
			loop_cnt / UNF_S_TO_MS);

	atomic_inc(&g_lld_lock.dev_ref_cnt);

	mutex_unlock(&g_lld_lock.lld_mutex);
}

void lld_put(void)
{
	atomic_dec(&g_lld_lock.dev_ref_cnt);
}

static void spfc_lld_lock_init(void)
{
	mutex_init(&g_lld_lock.lld_mutex);
	atomic_set(&g_lld_lock.dev_ref_cnt, 0);
}

static void spfc_realease_cmo_op_handle(void)
{
	memset(&spfc_cm_op_handle, 0, sizeof(struct unf_cm_handle_op));
}

static void spfc_check_module_para(void)
{
	if (spfc_dif_enable) {
		dif_sgl_mode = true;
		spfc_dif_type = SHOST_DIF_TYPE1_PROTECTION | SHOST_DIX_TYPE1_PROTECTION;
		dix_flag = 1;
	}

	if (dif_sgl_mode != 0)
		dif_sgl_mode = 1;
}

void spfc_event_process(void *adapter, struct sphw_event_info *event)
{
	struct spfc_pcidev *dev = adapter;

	if (test_and_set_bit(SERVICE_T_FC, &dev->state)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[WARN]Event: fc is in detach");
		return;
	}

	if (g_uld_info[SERVICE_T_FC].event)
		g_uld_info[SERVICE_T_FC].event(&dev->lld_dev, dev->uld_dev[SERVICE_T_FC], event);

	clear_bit(SERVICE_T_FC, &dev->state);
}

int spfc_stateful_init(void *hwdev)
{
	struct sphw_hwdev *dev = hwdev;
	int stateful_en;
	int err;

	if (!dev)
		return -EINVAL;

	if (dev->statufull_ref_cnt++)
		return 0;

	stateful_en = IS_FT_TYPE(dev) | IS_RDMA_TYPE(dev);
	if (stateful_en && SPHW_IS_PPF(dev)) {
		err = sphw_ppf_ext_db_init(dev);
		if (err)
			goto out;
	}

	err = cqm3_init(dev);
	if (err) {
		sdk_err(dev->dev_hdl, "Failed to init cqm, err: %d\n", err);
		goto init_cqm_err;
	}

	sdk_info(dev->dev_hdl, "Initialize statefull resource success\n");

	return 0;

init_cqm_err:
	if (stateful_en)
		sphw_ppf_ext_db_deinit(dev);

out:
	dev->statufull_ref_cnt--;

	return err;
}

void spfc_stateful_deinit(void *hwdev)
{
	struct sphw_hwdev *dev = hwdev;
	u32 stateful_en;

	if (!dev || !dev->statufull_ref_cnt)
		return;

	if (--dev->statufull_ref_cnt)
		return;

	cqm3_uninit(hwdev);

	stateful_en = IS_FT_TYPE(dev) | IS_RDMA_TYPE(dev);
	if (stateful_en)
		sphw_ppf_ext_db_deinit(hwdev);

	sdk_info(dev->dev_hdl, "Clear statefull resource success\n");
}

static int attach_uld(struct spfc_pcidev *dev, struct spfc_uld_info *uld_info)
{
	void *uld_dev = NULL;
	int err;

	mutex_lock(&dev->pdev_mutex);
	if (dev->uld_dev[SERVICE_T_FC]) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]fc driver has attached to pcie device");
		err = 0;
		goto out_unlock;
	}

	err = spfc_stateful_init(dev->hwdev);
	if (err) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to initialize statefull resources");
		goto out_unlock;
	}

	err = uld_info->probe(&dev->lld_dev, &uld_dev,
			      dev->uld_dev_name[SERVICE_T_FC]);
	if (err || !uld_dev) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to add object for fc driver to pcie device");
		goto probe_failed;
	}

	dev->uld_dev[SERVICE_T_FC] = uld_dev;
	mutex_unlock(&dev->pdev_mutex);

	return RETURN_OK;

probe_failed:
	spfc_stateful_deinit(dev->hwdev);

out_unlock:
	mutex_unlock(&dev->pdev_mutex);

	return err;
}

static void detach_uld(struct spfc_pcidev *dev)
{
	struct spfc_uld_info *uld_info = &g_uld_info[SERVICE_T_FC];
	u32 cnt = 0;

	mutex_lock(&dev->pdev_mutex);
	if (!dev->uld_dev[SERVICE_T_FC]) {
		mutex_unlock(&dev->pdev_mutex);
		return;
	}

	while (cnt < SPFC_EVENT_PROCESS_TIMEOUT) {
		if (!test_and_set_bit(SERVICE_T_FC, &dev->state))
			break;
		usleep_range(900, 1000);
		cnt++;
	}

	uld_info->remove(&dev->lld_dev, dev->uld_dev[SERVICE_T_FC]);
	dev->uld_dev[SERVICE_T_FC] = NULL;
	spfc_stateful_deinit(dev->hwdev);
	if (cnt < SPFC_EVENT_PROCESS_TIMEOUT)
		clear_bit(SERVICE_T_FC, &dev->state);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "Detach fc driver from pcie device succeed");
	mutex_unlock(&dev->pdev_mutex);
}

int spfc_register_uld(struct spfc_uld_info *uld_info)
{
	memset(g_uld_info, 0, sizeof(g_uld_info));
	spfc_lld_lock_init();
	mutex_init(&g_device_mutex);
	mutex_init(&g_pci_init_mutex);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[event]Module Init Success, wait for pci init and probe");

	if (!uld_info || !uld_info->probe || !uld_info->remove) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Invalid information of fc driver to register");
		return -EINVAL;
	}

	lld_hold();

	if (g_uld_info[SERVICE_T_FC].probe) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]fc driver has registered");
		lld_put();
		return -EINVAL;
	}

	memcpy(&g_uld_info[SERVICE_T_FC], uld_info, sizeof(*uld_info));

	lld_put();

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[KEVENT]Register spfc driver succeed");
	return RETURN_OK;
}

void spfc_unregister_uld(void)
{
	struct spfc_uld_info *uld_info = NULL;

	lld_hold();
	uld_info = &g_uld_info[SERVICE_T_FC];
	memset(uld_info, 0, sizeof(*uld_info));
	lld_put();
}

static int spfc_pci_init(struct pci_dev *pdev)
{
	struct spfc_pcidev *pci_adapter = NULL;
	int err = 0;

	pci_adapter = kzalloc(sizeof(*pci_adapter), GFP_KERNEL);
	if (!pci_adapter) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to alloc pci device adapter");
		return -ENOMEM;
	}
	pci_adapter->pcidev = pdev;
	mutex_init(&pci_adapter->pdev_mutex);

	pci_set_drvdata(pdev, pci_adapter);

	err = pci_enable_device(pdev);
	if (err) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to enable PCI device");
		goto pci_enable_err;
	}

	err = pci_request_regions(pdev, SPFC_DRV_NAME);
	if (err) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to request regions");
		goto pci_regions_err;
	}

	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Couldn't set 64-bit DMA mask");
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_ERR, "[err]Failed to set DMA mask");
			goto dma_mask_err;
		}
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Couldn't set 64-bit coherent DMA mask");
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_ERR,
				     "[err]Failed to set coherent DMA mask");
			goto dma_consistnet_mask_err;
		}
	}

	return 0;

dma_consistnet_mask_err:
dma_mask_err:
	pci_clear_master(pdev);
	pci_release_regions(pdev);

pci_regions_err:
	pci_disable_device(pdev);

pci_enable_err:
	pci_set_drvdata(pdev, NULL);
	kfree(pci_adapter);

	return err;
}

static void spfc_pci_deinit(struct pci_dev *pdev)
{
	struct spfc_pcidev *pci_adapter = pci_get_drvdata(pdev);

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(pci_adapter);
}

static int alloc_chip_node(struct spfc_pcidev *pci_adapter)
{
	struct card_node *chip_node = NULL;
	unsigned char i;
	unsigned char bus_number = 0;

	if (!pci_is_root_bus(pci_adapter->pcidev->bus))
		bus_number = pci_adapter->pcidev->bus->number;

	if (bus_number != 0) {
		list_for_each_entry(chip_node, &g_spfc_chip_list, node) {
			if (chip_node->bus_num == bus_number) {
				pci_adapter->chip_node = chip_node;
				return 0;
			}
		}
	} else if (pci_adapter->pcidev->device == SPFC_DEV_ID_VF) {
		list_for_each_entry(chip_node, &g_spfc_chip_list, node) {
			if (chip_node) {
				pci_adapter->chip_node = chip_node;
				return 0;
			}
		}
	}

	for (i = 0; i < MAX_CARD_ID; i++) {
		if (!test_and_set_bit(i, &card_bit_map))
			break;
	}

	if (i == MAX_CARD_ID) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to alloc card id");
		return -EFAULT;
	}

	chip_node = kzalloc(sizeof(*chip_node), GFP_KERNEL);
	if (!chip_node) {
		clear_bit(i, &card_bit_map);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to alloc chip node");
		return -ENOMEM;
	}

	/* bus number */
	chip_node->bus_num = bus_number;

	snprintf(chip_node->chip_name, IFNAMSIZ, "%s%d", SPFC_CHIP_NAME, i);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[INFO]Add new chip %s to global list succeed",
		     chip_node->chip_name);

	list_add_tail(&chip_node->node, &g_spfc_chip_list);

	INIT_LIST_HEAD(&chip_node->func_list);
	pci_adapter->chip_node = chip_node;

	return 0;
}

#ifdef CONFIG_X86
void cfg_order_reg(struct spfc_pcidev *pci_adapter)
{
	u8 cpu_model[] = {0x3c, 0x3f, 0x45, 0x46, 0x3d, 0x47, 0x4f, 0x56};
	struct cpuinfo_x86 *cpuinfo = NULL;
	u32 i;

	if (sphw_func_type(pci_adapter->hwdev) == TYPE_VF)
		return;

	cpuinfo = &cpu_data(0);

	for (i = 0; i < sizeof(cpu_model); i++) {
		if (cpu_model[i] == cpuinfo->x86_model)
			sphw_set_pcie_order_cfg(pci_adapter->hwdev);
	}
}
#endif

static int mapping_bar(struct pci_dev *pdev, struct spfc_pcidev *pci_adapter)
{
	int cfg_bar;

	cfg_bar = pdev->is_virtfn ? SPFC_VF_PCI_CFG_REG_BAR : SPFC_PF_PCI_CFG_REG_BAR;

	pci_adapter->cfg_reg_base = pci_ioremap_bar(pdev, cfg_bar);
	if (!pci_adapter->cfg_reg_base) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Failed to map configuration regs");
		return -ENOMEM;
	}

	pci_adapter->intr_reg_base = pci_ioremap_bar(pdev, SPFC_PCI_INTR_REG_BAR);
	if (!pci_adapter->intr_reg_base) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Failed to map interrupt regs");
		goto map_intr_bar_err;
	}

	if (!pdev->is_virtfn) {
		pci_adapter->mgmt_reg_base = pci_ioremap_bar(pdev, SPFC_PCI_MGMT_REG_BAR);
		if (!pci_adapter->mgmt_reg_base) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_ERR, "Failed to map mgmt regs");
			goto map_mgmt_bar_err;
		}
	}

	pci_adapter->db_base_phy = pci_resource_start(pdev, SPFC_PCI_DB_BAR);
	pci_adapter->db_dwqe_len = pci_resource_len(pdev, SPFC_PCI_DB_BAR);
	pci_adapter->db_base = pci_ioremap_bar(pdev, SPFC_PCI_DB_BAR);
	if (!pci_adapter->db_base) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Failed to map doorbell regs");
		goto map_db_err;
	}

	return 0;

map_db_err:
	if (!pdev->is_virtfn)
		iounmap(pci_adapter->mgmt_reg_base);

map_mgmt_bar_err:
	iounmap(pci_adapter->intr_reg_base);

map_intr_bar_err:
	iounmap(pci_adapter->cfg_reg_base);

	return -ENOMEM;
}

static void unmapping_bar(struct spfc_pcidev *pci_adapter)
{
	iounmap(pci_adapter->db_base);

	if (!pci_adapter->pcidev->is_virtfn)
		iounmap(pci_adapter->mgmt_reg_base);

	iounmap(pci_adapter->intr_reg_base);
	iounmap(pci_adapter->cfg_reg_base);
}

static int spfc_func_init(struct pci_dev *pdev, struct spfc_pcidev *pci_adapter)
{
	struct sphw_init_para init_para = {0};
	int err;

	init_para.adapter_hdl = pci_adapter;
	init_para.pcidev_hdl = pdev;
	init_para.dev_hdl = &pdev->dev;
	init_para.cfg_reg_base = pci_adapter->cfg_reg_base;
	init_para.intr_reg_base = pci_adapter->intr_reg_base;
	init_para.mgmt_reg_base = pci_adapter->mgmt_reg_base;
	init_para.db_base = pci_adapter->db_base;
	init_para.db_base_phy = pci_adapter->db_base_phy;
	init_para.db_dwqe_len = pci_adapter->db_dwqe_len;
	init_para.hwdev = &pci_adapter->hwdev;
	init_para.chip_node = pci_adapter->chip_node;
	err = sphw_init_hwdev(&init_para);
	if (err) {
		pci_adapter->hwdev = NULL;
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to initialize hardware device");
		return -EFAULT;
	}

	pci_adapter->lld_dev.pdev = pdev;
	pci_adapter->lld_dev.hwdev = pci_adapter->hwdev;

	sphw_event_register(pci_adapter->hwdev, pci_adapter, spfc_event_process);

	if (sphw_func_type(pci_adapter->hwdev) != TYPE_VF)
		spfc_sync_time_to_fmw(pci_adapter);
	lld_lock_chip_node();
	list_add_tail(&pci_adapter->node, &pci_adapter->chip_node->func_list);
	lld_unlock_chip_node();
	err = attach_uld(pci_adapter, &g_uld_info[SERVICE_T_FC]);

	if (err) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Spfc3 attach uld fail");
		goto attach_fc_err;
	}

#ifdef CONFIG_X86
	cfg_order_reg(pci_adapter);
#endif

	return 0;

attach_fc_err:
	lld_lock_chip_node();
	list_del(&pci_adapter->node);
	lld_unlock_chip_node();
	wait_lld_dev_unused(pci_adapter);

	return err;
}

static void spfc_func_deinit(struct pci_dev *pdev)
{
	struct spfc_pcidev *pci_adapter = pci_get_drvdata(pdev);

	lld_lock_chip_node();
	list_del(&pci_adapter->node);
	lld_unlock_chip_node();
	wait_lld_dev_unused(pci_adapter);

	detach_uld(pci_adapter);
	sphw_disable_mgmt_msg_report(pci_adapter->hwdev);
	sphw_flush_mgmt_workq(pci_adapter->hwdev);
	sphw_event_unregister(pci_adapter->hwdev);
	sphw_free_hwdev(pci_adapter->hwdev);
}

static void free_chip_node(struct spfc_pcidev *pci_adapter)
{
	struct card_node *chip_node = pci_adapter->chip_node;
	int id, err;

	if (list_empty(&chip_node->func_list)) {
		list_del(&chip_node->node);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
			     "[INFO]Delete chip %s from global list succeed",
			     chip_node->chip_name);
		err = sscanf(chip_node->chip_name, SPFC_CHIP_NAME "%d", &id);
		if (err < 0) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_ERR, "[err]Failed to get spfc id");
		}

		clear_bit(id, &card_bit_map);

		kfree(chip_node);
	}
}

static int spfc_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct spfc_pcidev *pci_adapter = NULL;
	int err;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[event]Spfc3 Pcie device probe begin");

	mutex_lock(&g_pci_init_mutex);
	err = spfc_pci_init(pdev);
	if (err) {
		mutex_unlock(&g_pci_init_mutex);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]pci init fail, return %d", err);
		return err;
	}
	pci_adapter = pci_get_drvdata(pdev);
	err = mapping_bar(pdev, pci_adapter);
	if (err) {
		mutex_unlock(&g_pci_init_mutex);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to map bar");
		goto map_bar_failed;
	}
	mutex_unlock(&g_pci_init_mutex);
	pci_adapter->id = *id;
	lld_dev_cnt_init(pci_adapter);

	/* if chip information of pcie function exist, add the function into chip */
	lld_lock_chip_node();
	err = alloc_chip_node(pci_adapter);
	if (err) {
		lld_unlock_chip_node();
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Failed to add new chip node to global list");
		goto alloc_chip_node_fail;
	}

	lld_unlock_chip_node();
	err = spfc_func_init(pdev, pci_adapter);
	if (err) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]spfc func init fail");
		goto func_init_err;
	}

	return 0;

func_init_err:
	lld_lock_chip_node();
	free_chip_node(pci_adapter);
	lld_unlock_chip_node();

alloc_chip_node_fail:
	unmapping_bar(pci_adapter);

map_bar_failed:
	spfc_pci_deinit(pdev);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
		     "[err]Pcie device probe failed");
	return err;
}

static void spfc_remove(struct pci_dev *pdev)
{
	struct spfc_pcidev *pci_adapter = pci_get_drvdata(pdev);

	if (!pci_adapter)
		return;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[INFO]Pcie device remove begin");
	sphw_detect_hw_present(pci_adapter->hwdev);
	spfc_func_deinit(pdev);
	lld_lock_chip_node();
	free_chip_node(pci_adapter);
	lld_unlock_chip_node();
	unmapping_bar(pci_adapter);
	mutex_lock(&g_pci_init_mutex);
	spfc_pci_deinit(pdev);
	mutex_unlock(&g_pci_init_mutex);
	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[INFO]Pcie device removed");
}

static void spfc_shutdown(struct pci_dev *pdev)
{
	struct spfc_pcidev *pci_adapter = pci_get_drvdata(pdev);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
		     "[err]Shutdown device");

	if (pci_adapter)
		sphw_shutdown_hwdev(pci_adapter->hwdev);

	pci_disable_device(pdev);
}

static pci_ers_result_t spfc_io_error_detected(struct pci_dev *pdev,
					       pci_channel_state_t state)
{
	struct spfc_pcidev *pci_adapter = NULL;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
		     "[err]Uncorrectable error detected, log and cleanup error status: 0x%08x",
		     state);

	pci_aer_clear_nonfatal_status(pdev);
	pci_adapter = pci_get_drvdata(pdev);

	if (pci_adapter)
		sphw_record_pcie_error(pci_adapter->hwdev);

	return PCI_ERS_RESULT_CAN_RECOVER;
}

static int unf_global_value_init(void)
{
	memset(rx_tx_stat, 0, sizeof(rx_tx_stat));
	memset(rx_tx_err, 0, sizeof(rx_tx_err));
	memset(scq_err_stat, 0, sizeof(scq_err_stat));
	memset(aeq_err_stat, 0, sizeof(aeq_err_stat));
	memset(dif_err_stat, 0, sizeof(dif_err_stat));
	memset(link_event_stat, 0, sizeof(link_event_stat));
	memset(link_reason_stat, 0, sizeof(link_reason_stat));
	memset(hba_stat, 0, sizeof(hba_stat));
	memset(&spfc_cm_op_handle, 0, sizeof(struct unf_cm_handle_op));
	memset(up_err_event_stat, 0, sizeof(up_err_event_stat));
	memset(mail_box_stat, 0, sizeof(mail_box_stat));
	memset(spfc_hba, 0, sizeof(spfc_hba));

	spin_lock_init(&probe_spin_lock);

	/* 4. Get COM Handlers used for low_level */
	if (unf_get_cm_handle_ops(&spfc_cm_op_handle) != RETURN_OK) {
		spfc_realease_cmo_op_handle();
		return RETURN_ERROR_S32;
	}

	return RETURN_OK;
}

static const struct pci_device_id spfc_pci_table[] = {
	{PCI_VDEVICE(RAMAXEL, SPFC_DEV_ID_PF_STD), 0},
	{0, 0}
};

MODULE_DEVICE_TABLE(pci, spfc_pci_table);

static struct pci_error_handlers spfc_err_handler = {
	.error_detected = spfc_io_error_detected,
};

static struct pci_driver spfc_driver = {.name = SPFC_DRV_NAME,
					 .id_table = spfc_pci_table,
					 .probe = spfc_probe,
					 .remove = spfc_remove,
					 .shutdown = spfc_shutdown,
					 .err_handler = &spfc_err_handler};

static __init int spfc_lld_init(void)
{
	if (unf_common_init() != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]UNF_Common_init failed");
		return RETURN_ERROR_S32;
	}

	spfc_check_module_para();

	if (unf_global_value_init() != RETURN_OK)
		return RETURN_ERROR_S32;

	spfc_register_uld(&fc_uld_info);
	return pci_register_driver(&spfc_driver);
}

static __exit void spfc_lld_exit(void)
{
	pci_unregister_driver(&spfc_driver);
	spfc_unregister_uld();

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[event]SPFC module removing...");

	spfc_realease_cmo_op_handle();

	/* 2. Unregister FC COM module(level) */
	unf_common_exit();
}

module_init(spfc_lld_init);
module_exit(spfc_lld_exit);

MODULE_AUTHOR("Ramaxel Memory Technology, Ltd");
MODULE_DESCRIPTION(SPFC_DRV_DESC);
MODULE_VERSION(SPFC_DRV_VERSION);
MODULE_LICENSE("GPL");

module_param(allowed_probe_num, uint, 0444);
module_param(dif_sgl_mode, uint, 0444);
module_param(max_speed, uint, 0444);
module_param(wqe_page_size, uint, 0444);
module_param(combo_length, uint, 0444);
module_param(cos_bit_map, uint, 0444);
module_param(spfc_dif_enable, uint, 0444);
MODULE_PARM_DESC(spfc_dif_enable, "set dif enable/disable(1/0), default is 0(disable).");
module_param(link_lose_tmo, uint, 0444);
MODULE_PARM_DESC(link_lose_tmo, "set link time out, default is 30s.");
