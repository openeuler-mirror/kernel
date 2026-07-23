// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/driver.h>
#include <linux/random.h>
#include "en_pf.h"
#include <linux/time.h>
#include "msg_common.h"
#include "en_pf/en_pf_eq.h"
#include "en_np/init/include/dpp_np_init.h"

#define ZXDH_RISCV_HB_OFFSET 0x5300
#define ZXDH_M7_HB_OFFSET 0x5350
#define ZXDH_M7_ZIOS_LOG_OFFSET 0x10b000
#define ZXDH_M7_CGEL_LOG_OFFSET 0x3e0000
#define ZXDH_RISCV_FWLOG_OFFSET 0x100000
#define ZXDH_M7_LOG_SIZE 0x4010
#define ZXDH_ZIOS_LOG_SIZE 0x700000
#define ZXDH_CGEL_LOG_SIZE 0x120000

#define ZXDH_FOUR_BYTE_FF 0xffffffff

static void zxdh_start_health_poll(struct dh_core_dev *dh_dev);

#ifdef NEED_SYSFS_EMIT
int sysfs_emit(char *buf, const char *fmt, ...);
#endif

enum {
	ZXDH_HEALTH_POLL_INTERVAL = 1 * HZ,
	M7_LOGDUMP = 6,
	RISCV_LOG_DUMP = 10,
	M7_MAX_MISSES = 20,
	RISCV_BBX_DUMP = 40,
	RISCV_MAX_MISSES = 60,
};

#define INVALID_SYND 0xff
enum {
	RISCV_FW_EXCEPTION,
	RISCV_CORE_EXCEPTION,
	RISCV_COUNTER_MISSED,
	BAR_ERROR,
	VQM_FATAL,
	BTTL_FATAL,
	DRR_FATAL,
	OCM_FATAL,
	PCIE_FATAL,
	RDMA_FATAL,
	FLR_RESET,
	RISCV_SYND_COUNT_MAX,
	M7_COUNTER_MISSED = 32,
	SYND_COUNT_MAX,
};

static const char *const synd_name[] = {
	"RISCV_FW_EXCEPTION",
	"RISCV_CORE_EXCEPTION",
	"RISCV_COUNTER_MISSED",
	"BAR_ERROR",
	"VQM_FATAL",
	"BTTL_FATAL",
	"DRR_FATAL",
	"OCM_FATAL",
	"PCIE_FATAL",
	"RDMA_FATAL",
	"FLR_RESET",
	"M7_COUNTER_MISSED",
};

static void dh_health_version_get(struct zxdh_core_health *health)
{
	struct health_buffer __iomem *hb = health->riscv.hb;
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	health->health_version = ioread8(&hb->health_version);
	HEAL_INFO("%s health_version: %d\n", pci_name(dh_dev->pdev), health->health_version);
}

struct health_attribute {
	const char *name;
	umode_t mode;
	ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			 size_t count);
};

enum {
	HEALTH_FATAL = 0,
	HEALTH_SYND,
	HEALTH_RECOVERY_CNT,
	HEALTH_ACTION,
	HEALTH_SELFHEALING,
};

static ssize_t health_action_store(struct kobject *kobj, struct kobj_attribute *attr,
				   const char *buf, size_t count);

static ssize_t health_selfhealing_store(struct kobject *kobj, struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct zxdh_core_health *health =
		container_of(attr, struct zxdh_core_health, attrs[HEALTH_SELFHEALING]);
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	int err = 0;
	int selfhealing;

	err = kstrtoint(buf, 10, &selfhealing);
	if (err)
		return err;

	health->selfhealing = selfhealing;
	HEAL_INFO("%s selfhealing  = %d\n", pci_name(dh_dev->pdev), selfhealing);

	return count;
}

struct health_attribute health_attrs[DH_HEALTH_ATTR_NUM] = {
	{ "fatal", 0440, NULL },
	{ "synd", 0440, NULL },
	{ "recovery_cnt", 0440, NULL },
	{ "action", 0640, health_action_store },
	{ "selfhealing", 0640, health_selfhealing_store },
};

static ssize_t health_attrs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct zxdh_core_health *health;
	int i = 0;

	for (i = 0; i < DH_HEALTH_ATTR_NUM; ++i) {
		if (strcmp(attr->attr.name, health_attrs[i].name) == 0)
			break;
	}

	HEAL_DEBUG("attr->attr.name = %s, i = %d\n", attr->attr.name, i);
	if (i == DH_HEALTH_ATTR_NUM)
		return -1;

	health = container_of(attr, struct zxdh_core_health, attrs[i]);

	switch (i) {
	case HEALTH_FATAL:
		return sysfs_emit(buf, "%d\n", health->fatal == 0 ? 0 : 1);
	case HEALTH_SYND:
		return sysfs_emit(buf, "0x%lx\n", health->synd);
	case HEALTH_RECOVERY_CNT:
		return sysfs_emit(buf, "%d\n", health->recovery_cnt);
	case HEALTH_ACTION:
		return sysfs_emit(buf, "[%d]health_info, [%d]bbx_log, [%d]reset, [%d]reload\n",
				  act_health_info_show, act_bbx_log_dump, act_reset, act_reload);
	case HEALTH_SELFHEALING:
		return sysfs_emit(buf, "%d\n", health->selfhealing);
	}

	return -1;
}

static void get_m7_and_riscv_counter(struct zxdh_core_health *dh_health)
{
	struct health_buffer __iomem *riscv_hb = dh_health->riscv.hb;
	struct health_buffer __iomem *m7_hb = dh_health->m7.hb;
	u32 riscv_count;
	u32 m7_count;

	m7_count = ioread32(&m7_hb->health_counter);
	riscv_count = ioread32(&riscv_hb->health_counter);
	pr_info("** m7_health_counter: 0x%x\n", m7_count);
	pr_info("** riscv_health_counter: 0x%x\n", riscv_count);
}

static void zxdh_health_info_show(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	u8 i = 0;

	pr_info("***************** %s nic info *****************\n", pci_name(dh_dev->pdev));
	pr_info("** board_type: %d\n", pf_dev->board_type);
	pr_info("** health_version: %d\n", health->health_version);
	pr_info("** health_supported: %d\n", health->health_supported);
	if (!health->health_supported)
		return;
	pr_info("** bar_chan_valid: %d\n", pf_dev->bar_chan_valid);
	pr_info("** fast_unload: %d\n", pf_dev->fast_unload);
	pr_info("** fatal: %d\n", health->fatal);
	pr_info("** health->flags: %ld, 1 means ZXDH_DROP_NEW_HEALTH_WORK\n", health->flags);
	pr_info("** recovery_cnt: %d\n", health->recovery_cnt);
	get_m7_and_riscv_counter(health);

	pr_info("****************** health config ***************\n");
	pr_info("** DH_HEALTH_ATTR_NUM: %d\n", DH_HEALTH_ATTR_NUM);
	pr_info("** health->riscv.hb: 0x%p, health->m7.hb: 0x%p\n", health->riscv.hb,
		health->m7.hb);
	pr_info("** m7_log_offset: 0x%llx, riscv_crdump_size: 0x%llx\n", health->m7_log_offset,
		health->riscv_crdump_size);
	pr_info("** timer_poll: %d\n", ZXDH_HEALTH_POLL_INTERVAL);
	pr_info("** M7_MAX_MISSES: %d\n", M7_MAX_MISSES);
	pr_info("** RISCV_LOG_DUMP: %d\n", RISCV_LOG_DUMP);
	pr_info("** RISCV_MAX_MISSES: %d\n", RISCV_MAX_MISSES);

	pr_info("************ dh_dev->device_state: 0x%x **********\n", dh_dev->device_state);
	pr_info("** [%d]: ZXDH_DEVICE_STATE_UNINITIALIZED\n", ZXDH_DEVICE_STATE_UNINITIALIZED);
	pr_info("** [%d]: ZXDH_DEVICE_STATE_UP\n", ZXDH_DEVICE_STATE_UP);
	pr_info("** [%d]: ZXDH_DEVICE_STATE_INTERNAL_ERROR\n", ZXDH_DEVICE_STATE_INTERNAL_ERROR);

	pr_info("******************** synd: 0x%lx *************\n", health->synd);
	for (i = 0; i < SYND_COUNT_MAX; ++i) {
		if (i < RISCV_SYND_COUNT_MAX)
			pr_info("** bit[%d]: %s set %d times\n", i, synd_name[i],
				health->synd_statics[i]);
		else if (i >= M7_COUNTER_MISSED)
			pr_info("** bit[%d]: %s set %d times\n", i,
				synd_name[i - 32 + RISCV_SYND_COUNT_MAX], health->synd_statics[i]);
	}
	pr_info("****************************************************\n");
}

static s32 zxdh_pf_dh_reset_request(struct dh_core_dev *dh_dev);
static ssize_t health_action_store(struct kobject *kobj, struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	struct zxdh_core_health *health =
		container_of(attr, struct zxdh_core_health, attrs[HEALTH_ACTION]);
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	int err = 0;
	int action;

	err = kstrtoint(buf, 10, &action);
	if (err)
		return err;

	HEAL_DEBUG("action = %d\n", action);
	switch (action) {
	case act_health_info_show:
		zxdh_health_info_show(dh_dev);
		break;
	case act_bbx_log_dump:
		queue_work(health->wq, &health->riscv_log_saving_work);
		queue_work(health->wq, &health->riscv_bbx_saving_work);
		queue_work(health->wq, &health->m7_bbx_saving_work);
		break;
	case act_reset:
		zxdh_pf_dh_reset_request(dh_dev);
		break;
	case act_reload:
		if (!zxdh_load_one(dh_dev))
			zxdh_start_health_poll(dh_dev);
		break;
	}

	return count;
}

static int zxdh_health_attr_create(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	struct kobj_attribute *attr = NULL;
	int err = 0;
	int i = 0;
	int j = 0;

	for (i = 0; i < DH_HEALTH_ATTR_NUM; ++i) {
		attr = &health->attrs[i];
		attr->attr.name = health_attrs[i].name;
		attr->attr.mode = health_attrs[i].mode;
		attr->show = health_attrs_show;
		attr->store = health_attrs[i].store;
		err = sysfs_create_file(&dh_dev->device->kobj, &attr->attr);
		if (err != 0) {
			HEAL_ERR("%s %s sysfs_create_file failed!\n", pci_name(dh_dev->pdev),
				 health_attrs[i].name);
			goto cleanup;
		}
	}

	return 0;

cleanup:
	for (j = --i; j >= 0; --j) {
		attr = &health->attrs[j];
		sysfs_remove_file(&dh_dev->device->kobj, &attr->attr);
	}
	return err;
}

static void zxdh_health_attr_remove(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	struct kobj_attribute *attr = NULL;
	int i = 0;

	for (i = 0; i < DH_HEALTH_ATTR_NUM; ++i) {
		attr = &health->attrs[i];
		sysfs_remove_file(&dh_dev->device->kobj, &attr->attr);
	}
}

struct bbox_hdr __iomem {
	u32 magic;
	u16 start_offset;
	u16 end_offset;
	bool wrap;
	u8 rsv[3];
};

enum {
	ZIOS_M7_LOG,
	CGEL_M7_LOG,
	ZIOS_RISCV_LOG1,
	ZIOS_RISCV_LOG2,
	CGEL_RISCV_LOG1,
	CGEL_RISCV_LOG2,
};

static u8 log_name[6][32] = {
	"zios_m7_log",	   "cgel_m7_log",     "zios_riscv_log1",
	"zios_riscv_log2", "cgel_riscv_log1", "cgel_riscv_log2",
};

#define EP4_DUMP_SIZE_MAX (0x10000)
static void fw_log_dump(struct dh_core_dev *dh_dev, u8 type)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	const char *dev_name = pci_name(dh_dev->pdev);
	char filename[64];
	struct file *file;
	u8 *buf;
	u64 offset;
	u64 real_offset;
	u64 dump_size;
	u8 i = 0;

	HEAL_DEBUG("%s_%s dump start\n", log_name[type], dev_name);
	/* NOTE: writing to /var/log from kernel is intentionally kept for
	 * compatibility with existing user-space log-collection tooling.
	 * The preferred modern mechanism is dev_coredumpv(); migrating to
	 * it would require coordinated user-space changes.
	 */
	snprintf(filename, sizeof(filename), "/var/log/%s_%s.txt", log_name[type], dev_name);
	file = filp_open(filename, O_WRONLY | O_CREAT, 0640);
	if (!file || IS_ERR(file)) {
		HEAL_ERR("%s Error opening file %s\n", pci_name(dh_dev->pdev), filename);
		return;
	}

	if (type == ZIOS_M7_LOG || type == CGEL_M7_LOG) {
		offset = health->m7_log_offset;
		dump_size = ZXDH_M7_LOG_SIZE;
	} else {
		offset = ZXDH_RISCV_FWLOG_OFFSET;
		dump_size = health->riscv_crdump_size;
	}

	buf = vmalloc(dump_size);
	if (!buf) {
		HEAL_ERR("%s vmalloc buf failed\n", pci_name(dh_dev->pdev));
		goto out;
	}

	memset(buf, 0, dump_size);

	if ((pf_dev->pcie_id & BIT(14)) != 0) {
		for (i = 0; (i * EP4_DUMP_SIZE_MAX) < dump_size; ++i) {
			real_offset = TO_EP4_ADDR(offset);
			memcpy_fromio(buf + i * EP4_DUMP_SIZE_MAX,
				      (void __iomem *)(pf_dev->pci_ioremap_addr[0] + real_offset),
				      EP4_DUMP_SIZE_MAX);
			offset += EP4_DUMP_SIZE_MAX;
		}
	} else {
		memcpy_fromio(buf, (void __iomem *)(pf_dev->pci_ioremap_addr[0] + offset), dump_size);
	}
	kernel_write(file, buf, dump_size, &file->f_pos);

	vfree(buf);
	HEAL_DEBUG("%s_%s dump success\n", log_name[type], dev_name);
out:
	filp_close(file, NULL);
}

static void zxdh_m7_bbx_log_dump_work(struct work_struct *work)
{
	struct zxdh_core_health *health =
		container_of(work, struct zxdh_core_health, m7_bbx_saving_work);
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return;

	if (IS_STD_BOARD(pf_dev->board_type))
		fw_log_dump(dh_dev, ZIOS_M7_LOG);
	else
		fw_log_dump(dh_dev, CGEL_M7_LOG);
}

static void zxdh_riscv_fw_log_dump_work(struct work_struct *work)
{
	struct zxdh_core_health *health =
		container_of(work, struct zxdh_core_health, riscv_log_saving_work);
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return;

	if (IS_STD_BOARD(pf_dev->board_type))
		fw_log_dump(dh_dev, ZIOS_RISCV_LOG1);
	else
		fw_log_dump(dh_dev, CGEL_RISCV_LOG1);
}

static void zxdh_riscv_bbx_log_dump_work(struct work_struct *work)
{
	struct zxdh_core_health *health =
		container_of(work, struct zxdh_core_health, riscv_bbx_saving_work);
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return;

	if (IS_STD_BOARD(pf_dev->board_type))
		fw_log_dump(dh_dev, ZIOS_RISCV_LOG2);
	else
		fw_log_dump(dh_dev, CGEL_RISCV_LOG2);
}

static void zxdh_trigger_health_work(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	unsigned long flags;

	if (!health->selfhealing) {
		HEAL_INFO("%s selfhealing is not permitted\n", pci_name(dh_dev->pdev));
		return;
	}

	spin_lock_irqsave(&health->wq_lock, flags);
	if (test_bit(ZXDH_DROP_NEW_HEALTH_WORK, &health->flags)) {
		HEAL_ERR("%s new health works are not permitted at this stage\n",
			 pci_name(dh_dev->pdev));
	} else {
		queue_work(health->wq, &health->fw_fatal_err_work);
	}
	spin_unlock_irqrestore(&health->wq_lock, flags);
}

static void zxdh_riscv_cnt_check(struct core_health *health)
{
	struct zxdh_core_health *dh_health = container_of(health, struct zxdh_core_health, riscv);
	struct zxdh_pf_device *pf_dev = container_of(dh_health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct health_buffer __iomem *hb = health->hb;
	u32 count;

	count = ioread32(&hb->health_counter);
	if (count == health->prev)
		++health->miss_counter;
	else
		health->miss_counter = 0;

	health->prev = count;
	if (health->miss_counter == RISCV_MAX_MISSES) {
		HEAL_ERR("%s riscv health compromised - reached miss count\n",
			 pci_name(dh_dev->pdev));
		set_bit(RISCV_COUNTER_MISSED, &dh_health->synd);
	} else if (health->miss_counter == RISCV_LOG_DUMP) {
		queue_work(dh_health->wq, &dh_health->riscv_log_saving_work);
	} else if (health->miss_counter == RISCV_BBX_DUMP) {
		queue_work(dh_health->wq, &dh_health->riscv_bbx_saving_work);
	}
}

static void zxdh_m7_cnt_check(struct core_health *health)
{
	struct health_buffer __iomem *hb = health->hb;
	struct zxdh_core_health *dh_health = container_of(health, struct zxdh_core_health, m7);
	struct zxdh_pf_device *pf_dev = container_of(dh_health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	u32 count;

	count = ioread32(&hb->health_counter);
	if (count == 0)
		return;
	else if (count == health->prev)
		++health->miss_counter;
	else
		health->miss_counter = 0;

	health->prev = count;
	if (health->miss_counter == M7_MAX_MISSES) {
		HEAL_ERR("%s m7 health compromised - reached miss count\n", pci_name(dh_dev->pdev));
		set_bit(M7_COUNTER_MISSED, &dh_health->synd);
	} else if (health->miss_counter == M7_LOGDUMP) {
		queue_work(dh_health->wq, &dh_health->m7_bbx_saving_work);
	}
}

#define MAX_DETECT_CNT 3
static bool sensor_bar_error(struct zxdh_core_health *health)
{
	struct health_buffer __iomem *hb = health->riscv.hb;
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	if (ioread32(&hb->fw_version) == ZXDH_FOUR_BYTE_FF) {
		health->fatal_detect_cnt++;
		HEAL_INFO("%s bar_err_detect_cnt: %d\n", pci_name(dh_dev->pdev),
			  health->fatal_detect_cnt);
	} else {
		health->fatal_detect_cnt = 0;
	}
	if (health->fatal_detect_cnt == MAX_DETECT_CNT) {
		health->reset_done = true;
		return true;
	}

	return false;
}

static inline bool sensor_fw_synd_rfr(struct zxdh_core_health *health)
{
	struct health_buffer __iomem *hb = health->riscv.hb;
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	if (ioread8(&hb->rfr) != 1)
		return false;

	if (dh_dev->coredev_type == DH_COREDEV_PF)
		queue_work(health->wq, &health->dh_reset_work);

	return true;
}

static inline bool sensor_fw_exception(const struct core_health *health)
{
	struct health_buffer __iomem *hb = health->hb;

	return (ioread8(&hb->fw_exception) == 1);
}

static bool sensor_dh_fw_exception(struct zxdh_core_health *health)
{
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	s32 i = 0;
	struct {
		struct core_health *core;
		struct work_struct *work;
		const char *name;
	} cores[] = { { &health->riscv, &health->riscv_bbx_saving_work, "riscv" },
		      { &health->m7, &health->m7_bbx_saving_work, "m7" } };

	for (i = 0; i < ARRAY_SIZE(cores); i++) {
		if (sensor_fw_exception(cores[i].core)) {
			HEAL_ERR("%s %s fw_exception\n", pci_name(dh_dev->pdev), cores[i].name);
			if (!queue_work(health->wq, cores[i].work)) {
				HEAL_ERR("%s Failed to queue work for %s\n", pci_name(dh_dev->pdev),
					 cores[i].name);
				continue;
			}
			return 1;
		}
	}
	return 0;
}

static inline bool sensor_dh_reset_ok(struct core_health *health)
{
	struct health_buffer __iomem *hb = health->hb;

	return (ioread8(&hb->riscv_power_on) == 1);
}

static bool sensor_flr_reset(struct zxdh_core_health *health)
{
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);

	if (ioread8(&pf_dev->common->device_status) != 0xb)
		return false;

	health->reset_done = true;
	return true;
}

static bool sensor_cnt_missed(struct zxdh_core_health *health)
{
	if (test_bit(RISCV_COUNTER_MISSED, &health->synd))
		return true;

	if (test_bit(M7_COUNTER_MISSED, &health->synd))
		return true;

	return false;
}

static void update_synd_statics(struct zxdh_core_health *health, u64 synd)
{
	s32 i = 0;

	for (i = 0; i < 64; i++) {
		if ((synd >> i) & 1)
			health->synd_statics[i]++;
	}
}

static void zxdh_synd_detect(struct zxdh_core_health *health)
{
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct core_health *riscv = &health->riscv;
	struct core_health *m7 = &health->m7;
	struct health_buffer __iomem *hb = NULL;
	u32 prev_synd;
	u64 total_synd;
	u64 prev_total_synd;

	prev_total_synd = health->synd;

	hb = riscv->hb;
	prev_synd = riscv->synd;
	riscv->synd = ioread32(&hb->synd);
	if (riscv->synd && riscv->synd != ZXDH_FOUR_BYTE_FF && riscv->synd != prev_synd) {
		HEAL_ERR("%s riscv->synd 0x%x\n", pci_name(dh_dev->pdev), riscv->synd);
		health->synd |= riscv->synd;
	}

	if (health->health_version != 1)
		goto out;

	hb = m7->hb;
	prev_synd = m7->synd;
	m7->synd = ioread32(&hb->synd);
	if (m7->synd && m7->synd != ZXDH_FOUR_BYTE_FF && m7->synd != prev_synd) {
		HEAL_ERR("%s m7->synd 0x%x\n", pci_name(dh_dev->pdev), m7->synd);
		total_synd = m7->synd;
		health->synd |= (total_synd << 32);
	}

out:
	if (health->synd && health->synd != prev_total_synd)
		update_synd_statics(health, health->synd ^ prev_total_synd);
}

static void zxdh_health_sync(struct zxdh_core_health *health, u8 synd)
{
	set_bit(synd, &health->synd);
	update_synd_statics(health, (u64)1 << (synd));
}

struct sensor_check {
	bool (*func)(struct zxdh_core_health *health);
	const char *error_msg;
	u32 sync_code;
} const checks[] = {
	{ sensor_bar_error, "bar error", BAR_ERROR },
	{ sensor_flr_reset, "sensor_flr_reset", FLR_RESET },
	{ sensor_fw_synd_rfr, "fw need rfr", INVALID_SYND },
	{ sensor_dh_fw_exception, "sensor_dh_fw_exception", INVALID_SYND },
	{ sensor_cnt_missed, "sensor_cnt_missed", INVALID_SYND },
};

static u8 zxdh_health_check_fatal_sensors(struct zxdh_core_health *health)
{
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	u8 i = 0;
	u8 check_num = ARRAY_SIZE(checks);

	if (health->fatal)
		check_num = 2;

	for (i = 0; i < check_num; i++) {
		if (checks[i].func(health)) {
			HEAL_ERR("%s %s\n", pci_name(dh_dev->pdev), checks[i].error_msg);
			if (checks[i].sync_code == INVALID_SYND)
				zxdh_synd_detect(health);
			else
				zxdh_health_sync(health, checks[i].sync_code);

			return health->fatal++;
		}
	}

	return health->fatal;
}

#define ZXDH_HEALTH_MAX_WAIT_MSECS 600000

static int zxdh_health_wait_dh_ok(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	unsigned long end = jiffies + msecs_to_jiffies(ZXDH_HEALTH_MAX_WAIT_MSECS);

	while (!(sensor_dh_reset_ok(&health->riscv))) {
		if (dh_dev->driver_process == ZXDH_REMOVE)
			return -ETIMEDOUT;
		if (time_after(jiffies, end))
			return -ETIMEDOUT;
		msleep(1000);
	}

	HEAL_INFO("%s dh is ok\n", pci_name(dh_dev->pdev));
	return 0;
}

static int wait_vital(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	struct health_buffer __iomem *hb = health->riscv.hb;
	const int niter = 600;
	u32 last_count = 0;
	u32 count;
	int i;

	for (i = 0; i < niter; i++) {
		count = ioread32(&hb->health_counter);
		if (count && count != 0xffffffff) {
			if (last_count && last_count != count) {
				HEAL_INFO("%s wait vital counter value 0x%x after %d iterations\n",
					  pci_name(dh_dev->pdev), count, i);
				return 0;
			}
			last_count = count;
		}
		if (dh_dev->driver_process == ZXDH_REMOVE)
			return -ETIMEDOUT;

		msleep(1000);
	}

	return -ETIMEDOUT;
}

static inline bool dh_reload_confirm(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	struct dpp_pf_info_t pf_info = { .slot = pf_dev->slot_id, .vport = pf_dev->vport };

	if (!sensor_flr_reset(health)) {
		pf_dev->bar_chan_valid = true;
		dpp_dev_status_set(&pf_info, 1);
		dh_dev->device_state = ZXDH_DEVICE_STATE_UP;
		zxdh_pf_call_aux_events_with_data(dh_dev, DH_EVENT_TYPE_AUX_STATE,
						  &dh_dev->device_state);
		return false;
	}

	return true;
}

int dh_pf_wait_riscv_ready(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	int i = 0;

	health->riscv.hb = (struct health_buffer __iomem *)(pf_dev->pci_ioremap_addr[0] +
							    ZXDH_RISCV_HB_OFFSET);
	health->m7.hb =
		(struct health_buffer __iomem *)(pf_dev->pci_ioremap_addr[0] + ZXDH_M7_HB_OFFSET);

	dh_health_version_get(health);

	if (health->health_version != 1 && pf_dev->fw_compat.patch < DH_HPIRQ_PATCH) {
		HEAL_INFO("%s riscv_power_on not valid\n", pci_name(dh_dev->pdev));
		return 0;
	}

	for (i = 0; i < 200; ++i) {
		if (sensor_dh_reset_ok(&health->riscv)) {
			HEAL_INFO("%s wait %ds\n", pci_name(dh_dev->pdev), i);
			return 0;
		}

		if (dh_dev->driver_process == ZXDH_REMOVE)
			return -ETIMEDOUT;

		msleep(1000);
	}

	return -1;
}

int zxdh_vf_wait_pf_ok(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	struct health_buffer __iomem *hb = health->riscv.hb;
	u8 ep_id = (pf_dev->pcie_id >> 12) & 0x7;
	u8 pf_id = (pf_dev->pcie_id >> 8) & 0x7;
	u8 pf_ok = 1 << pf_id;
	unsigned long end = jiffies + msecs_to_jiffies(ZXDH_HEALTH_MAX_WAIT_MSECS);

	while (!(ioread8(&hb->pf_status[ep_id]) & pf_ok)) {
		if (dh_dev->driver_process == ZXDH_REMOVE)
			return -ETIMEDOUT;
		if (time_after(jiffies, end))
			return -ETIMEDOUT;
		msleep(1000);
	}

	return 0;
}

static int zxdh_pf_health_msg_send(struct dh_core_dev *dh_dev, union zxdh_msg *msg)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (pf_dev->health.health_version != 1)
		return -1;

	return zxdh_pf_msg_send_cmd(dh_dev, MODULE_HEALTH, msg, msg, &para);
}

int zxdh_pf_status_ok(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	union zxdh_msg *msg = NULL;
	s32 err = 0;

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return 0;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		HEAL_ERR("%s kzalloc(%lu, GFP_KERNEL) failed\n", pci_name(dh_dev->pdev),
			 sizeof(union zxdh_msg));
		return -1;
	}

	msg->payload.health_hdr.opcode = 1;
	msg->payload.pf_status_msg.pcie_id = pf_dev->pcie_id;
	msg->payload.health_hdr.sum_check = sum_func(&msg->payload.pf_status_msg, 2);

	err = zxdh_pf_health_msg_send(dh_dev, msg);
	kfree(msg);
	return err;
}

#define PCIE_CONFIG_STORE (0x1c)
int zxdh_pf_pcie_config_store(struct dh_core_dev *dh_dev)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return 0;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		HEAL_ERR("%s kzalloc(%lu, GFP_KERNEL) failed\n", pci_name(dh_dev->pdev),
			 sizeof(union zxdh_msg));
		return -1;
	}

	msg->payload.health_hdr.opcode = 0;
	msg->payload.health_config_msg.act = PCIE_CONFIG_STORE;
	msg->payload.health_hdr.sum_check = PCIE_CONFIG_STORE;

	err = zxdh_pf_health_msg_send(dh_dev, msg);
	kfree(msg);
	return err;
}

#define DH_RESET_REQUEST (0x1a)
static s32 zxdh_pf_dh_reset_request(struct dh_core_dev *dh_dev)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return 0;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		HEAL_ERR("%s kzalloc(%lu, GFP_KERNEL) failed\n", pci_name(dh_dev->pdev),
			 sizeof(union zxdh_msg));
		return -1;
	}

	msg->payload.health_hdr.opcode = 0;
	msg->payload.health_config_msg.act = DH_RESET_REQUEST;
	msg->payload.health_hdr.sum_check = DH_RESET_REQUEST;

	err = zxdh_pf_health_msg_send(dh_dev, msg);
	HEAL_INFO("%s dh reset request, err = %d\n", pci_name(dh_dev->pdev), err);
	kfree(msg);
	return err;
}

static void poll_health(struct timer_list *t)
{
	struct zxdh_core_health *health = from_timer(health, t, timer);
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	u8 fatal = 0;

	if (pf_dev->aux_comp_flag == 0)
		goto out;

	fatal = zxdh_health_check_fatal_sensors(health);
	if (fatal != health->fatal) {
		HEAL_ERR("%s Fatal error detected: %d\n", pci_name(dh_dev->pdev), health->fatal);
		dh_dev->device_state = ZXDH_DEVICE_STATE_INTERNAL_ERROR;
		zxdh_pf_call_aux_events_with_data(dh_dev, DH_EVENT_TYPE_AUX_STATE,
						  &dh_dev->device_state);
		if (health->reset_done)
			return zxdh_trigger_health_work(dh_dev);
	}

	zxdh_riscv_cnt_check(&health->riscv);
	if (health->health_version == 1)
		zxdh_m7_cnt_check(&health->m7);
	zxdh_synd_detect(health);

out:
	mod_timer(&health->timer, jiffies + ZXDH_HEALTH_POLL_INTERVAL);
}

static void zxdh_start_health_poll(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;

	clear_bit(ZXDH_DROP_NEW_HEALTH_WORK, &health->flags);
	health->synd = 0;
	health->fatal = 0;
	health->reset_done = false;
	health->fatal_detect_cnt = 0;
	mod_timer(&health->timer, jiffies + ZXDH_HEALTH_POLL_INTERVAL);
}

static int zxdh_health_try_recover(struct dh_core_dev *dh_dev)
{
	HEAL_INFO("%s handling bad device here\n", pci_name(dh_dev->pdev));
	if (wait_vital(dh_dev)) {
		HEAL_ERR("%s wait_vital time out\n", pci_name(dh_dev->pdev));
		return -EIO;
	}
	if (zxdh_health_wait_dh_ok(dh_dev)) {
		HEAL_ERR("%s zxdh_health_wait_dh_ok time out\n", pci_name(dh_dev->pdev));
		return -EIO;
	}
	if (!dh_reload_confirm(dh_dev)) {
		HEAL_INFO("%s no need to reload\n", pci_name(dh_dev->pdev));
		goto out;
	}

	zxdh_unload_one(dh_dev);
	HEAL_INFO("%s zxdh_unload_one finish\n", pci_name(dh_dev->pdev));
	if (zxdh_load_one(dh_dev)) {
		HEAL_ERR("%s zxdh_load_one failed\n", pci_name(dh_dev->pdev));
		return -EIO;
	}

out:
	zxdh_start_health_poll(dh_dev);
	return 0;
}

static void zxdh_dh_reset_work(struct work_struct *work)
{
	struct zxdh_core_health *health =
		container_of(work, struct zxdh_core_health, dh_reset_work);
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	zxdh_pf_dh_reset_request(dh_dev);
}

static void zxdh_fw_fatal_err_work(struct work_struct *work)
{
	struct zxdh_core_health *health =
		container_of(work, struct zxdh_core_health, fw_fatal_err_work);
	struct zxdh_pf_device *pf_dev = container_of(health, struct zxdh_pf_device, health);
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct dpp_pf_info_t pf_info = { .slot = pf_dev->slot_id, .vport = pf_dev->vport };

	HEAL_INFO("%s %s start\n", pci_name(dh_dev->pdev), __func__);
	if (dh_dev->coredev_type == DH_COREDEV_PF)
		dpp_dev_status_set(&pf_info, 0);

	pf_dev->bar_chan_valid = false;
	if (health->health_version != 1)
		return;

	zxdh_health_try_recover(dh_dev);
}

void zxdh_drain_health_wq(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	unsigned long flags;

	if (!health->health_supported)
		return;

	spin_lock_irqsave(&health->wq_lock, flags);
	set_bit(ZXDH_DROP_NEW_HEALTH_WORK, &health->flags);
	spin_unlock_irqrestore(&health->wq_lock, flags);
	cancel_work_sync(&health->fw_fatal_err_work);
	cancel_work_sync(&health->dh_reset_work);
	cancel_work_sync(&health->m7_bbx_saving_work);
	cancel_work_sync(&health->riscv_bbx_saving_work);
	cancel_work_sync(&health->riscv_log_saving_work);
}

static void zxdh_stop_health_poll(struct dh_core_dev *dh_dev, bool disable_health)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	unsigned long flags;

	if (disable_health) {
		spin_lock_irqsave(&health->wq_lock, flags);
		set_bit(ZXDH_DROP_NEW_HEALTH_WORK, &health->flags);
		spin_unlock_irqrestore(&health->wq_lock, flags);
	}

	del_timer_sync(&health->timer);
}

void zxdh_health_cleanup(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;

	if (!health->health_supported)
		return;

	zxdh_stop_health_poll(dh_dev, true);
	destroy_workqueue(health->wq);
	zxdh_health_attr_remove(dh_dev);
}

int zxdh_crdump_size_get(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u8 board_type = pf_dev->board_type;
	struct zxdh_core_health *health = &pf_dev->health;

	if (IS_STD_BOARD(board_type)) {
		health->m7_log_offset = ZXDH_M7_ZIOS_LOG_OFFSET;
		health->riscv_crdump_size = ZXDH_ZIOS_LOG_SIZE;
	} else if (IS_INIC_BOARD(board_type)) {
		health->m7_log_offset = ZXDH_M7_CGEL_LOG_OFFSET;
		health->riscv_crdump_size = ZXDH_CGEL_LOG_SIZE;
	} else {
		HEAL_INFO("%s invalid board_type: %d\n", pci_name(dh_dev->pdev), board_type);
		return -1;
	}

	if (dh_dev->coredev_type == DH_COREDEV_PF &&
	    (ZXDH_RISCV_FWLOG_OFFSET + health->riscv_crdump_size >
	     pci_resource_len(dh_dev->pdev, 0))) {
		HEAL_ERR("%s pci_resource_len: %llx\n", pci_name(dh_dev->pdev),
			 pci_resource_len(dh_dev->pdev, 0));
		return -1;
	}

	return 0;
}

int zxdh_health_init(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	char name[64];
	int err = 0;

	if (health->health_version > 1)
		goto out;

	if (zxdh_crdump_size_get(dh_dev))
		goto out;

	scnprintf(name, sizeof(name), "zxdh_health%s", dev_name(dh_dev->device));
	health->wq = create_singlethread_workqueue(name);

	if (!health->wq)
		return -ENOMEM;

	spin_lock_init(&health->wq_lock);
	INIT_WORK(&health->fw_fatal_err_work, zxdh_fw_fatal_err_work);
	INIT_WORK(&health->dh_reset_work, zxdh_dh_reset_work);
	INIT_WORK(&health->m7_bbx_saving_work, zxdh_m7_bbx_log_dump_work);
	INIT_WORK(&health->riscv_log_saving_work, zxdh_riscv_fw_log_dump_work);
	INIT_WORK(&health->riscv_bbx_saving_work, zxdh_riscv_bbx_log_dump_work);

	if (health->health_version == 1) {
		err = zxdh_pf_rp_config_init(dh_dev);
		if (err != 0) {
			HEAL_ERR("%s zxdh_pf_rp_config_init failed: %d\n", pci_name(dh_dev->pdev),
				 err);
			goto destroy_wq;
		}
		err = zxdh_pf_status_ok(dh_dev);
		if (err != 0) {
			HEAL_ERR("%s zxdh_pf_status_ok failed: %d\n", pci_name(dh_dev->pdev), err);
			goto destroy_wq;
		}
	}

	if (zxdh_health_attr_create(dh_dev) != 0)
		goto destroy_wq;

	timer_setup(&health->timer, poll_health, 0);
	health->health_supported = true;
	health->selfhealing = 1;
	zxdh_start_health_poll(dh_dev);
	return 0;

destroy_wq:
	destroy_workqueue(health->wq);
	return -ENOEXEC;
out:
	health->health_supported = false;
	HEAL_INFO("%s health buffer not supported\n", pci_name(dh_dev->pdev));
	return 0;
}
