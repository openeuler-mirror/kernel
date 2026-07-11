// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/err.h>
#include <linux/dinghai/dh_cmd.h>
#include "zf_mpf.h"

#define ZXDH_SYSFS_DIR "zxdh_host_reset"
#define ZXDH_SYSFS_FILE_EP_CHECK_REGISTER "ep_check_register"
#define ZXDH_SYSFS_FILE_EP_RESET_INFO "ep_reset_info"

struct zxdh_reset_dev {
	u16 pcie_id;
	u64 bar0_base_virt_addr;
	u64 is_valid;
} reset_dev = { 0 };

struct zxdh_reset_dev *zxdh_get_reset_dev(void)
{
	return &reset_dev;
}

int zxdh_init_reset_dev(struct dh_core_dev *core_dev)
{
	struct zxdh_reset_dev *dev = zxdh_get_reset_dev();
	struct dh_en_mpf_dev *mpf_dev = dh_core_priv(core_dev);

	dev->bar0_base_virt_addr = mpf_dev->pci_ioremap_addr;
	dev->is_valid = 1;
	dev->pcie_id = mpf_dev->pcie_id;
	return 0;
}

enum e_reset_event {
	EV_HOST_RESET = 0,
	EV_ZF_RESET = 1,
	EV_DINGHAI_RESET = 2,
	EV_ZXDH_RESET_TEST = 3,
	EV_MAX_RESET
};

struct host_reset_ev_info {
	int ep_no;
};

struct zxdh_reset_priv {
	enum e_reset_event e_reset_event;
	union {
		struct host_reset_ev_info host_reset_ev;
	} ev_info;
	struct work_struct work;
};

unsigned int ep_check_register;
unsigned int ep_reset_info;

struct kobject *kobj_zxdh_host_reset;

static ssize_t sysfs_show_ep_check_register(struct kobject *kobj, struct kobj_attribute *attr,
					    char *buf)
{
	return scnprintf(buf, sizeof(buf), "0x%08x", ep_check_register);
}

static ssize_t sysfs_store_ep_check_register(struct kobject *kobj, struct kobj_attribute *attr,
					     const char *buf, size_t count)
{
	u16 ret = 0;

	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	u8 recv_buffer[20] = { 0 };
	u16 recv_buff_len = 20;
	struct zxdh_reset_dev *dev = zxdh_get_reset_dev();

	if (sscanf(buf, "0x%x", &ep_check_register) != 1)
		return ret;

	in.virt_addr = dev->bar0_base_virt_addr + ZXDH_BAR1_CHAN_OFFSET;
	in.payload_addr = &ep_check_register;
	in.payload_len = sizeof(ep_check_register);
	in.src = MSG_CHAN_END_PF; // MSG_CHAN_END_MPF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_RESET_MSG;
	in.src_pcieid = dev->pcie_id;

	result.recv_buffer = recv_buffer;
	result.buffer_len = recv_buff_len;

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret)
		DH_LOG_ERR(MODULE_MPF, "  '%s' zxdh_bar_chan_sync_msg_send failed.\n", __func__);
	return count;
}

static ssize_t sysfs_show_ep_reset_info(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	return scnprintf(buf, sizeof(buf), "0x%08x", ep_reset_info);
}

static ssize_t sysfs_store_ep_reset_info(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	if (sscanf(buf, "0x%x", &ep_reset_info) == 1)
		return (ssize_t)count;
	return 0;
}

struct kobj_attribute zxdh_host_reset_attr_ep_check_register = __ATTR(
	ep_check_register, 0664, sysfs_show_ep_check_register, sysfs_store_ep_check_register);
struct kobj_attribute zxdh_host_reset_attr_ep_reset_info =
	__ATTR(ep_reset_info, 0664, sysfs_show_ep_reset_info, sysfs_store_ep_reset_info);

s32 zxdh_reset_zf_rec_risc(void *pay_load, u16 len, void *reps_buffer, u16 *reps_len, void *dev)
{
	struct zxdh_reset_priv *priv = NULL;
	u32 ep_no = 0;
	u32 ep_reset_info_tmp = ep_reset_info;

	if (pay_load && len && reps_buffer && reps_len) {
		DH_LOG_INFO(MODULE_MPF, "%s: para check ok.(%p, %x, %p, %p)\n", __func__, pay_load,
			    len, reps_buffer, reps_len);
	} else {
		DH_LOG_ERR(MODULE_MPF, "%s: para error.(%p, %x, %p, %p)\n", __func__, pay_load, len,
			   reps_buffer, reps_len);
		return (u16)-1;
	}

	priv = pay_load;
	ep_no = priv->ev_info.host_reset_ev.ep_no;
	pcie_zte_zf_signal_epc_dev_init(ep_no);

	DH_LOG_INFO(MODULE_MPF, "  %s: received msg from RISC-V: event_id[%d] len 0x%x, ep_no=%u\n",
		    __func__, MODULE_RESET_MSG, len, ep_no);

	ep_reset_info |= 1 << ep_no;
	DH_LOG_INFO(MODULE_MPF, "  %s: ep_reset_info 0x%08x -> 0x%08x\n", __func__,
		    ep_reset_info_tmp, ep_reset_info);

	return 0;
}

int zxdh_host_reset_driver_init(struct dh_core_dev *core_dev)
{
	s32 ret = 0;

	kobj_zxdh_host_reset = kobject_create_and_add(ZXDH_SYSFS_DIR, NULL);

	zxdh_init_reset_dev(core_dev);

	if (sysfs_create_file(kobj_zxdh_host_reset, &zxdh_host_reset_attr_ep_check_register.attr)) {
		DH_LOG_ERR(MODULE_MPF, "  'ep_check_register' sysfs create failed.\n");
		goto error_sysfs;
	}

	if (sysfs_create_file(kobj_zxdh_host_reset, &zxdh_host_reset_attr_ep_reset_info.attr)) {
		DH_LOG_ERR(MODULE_MPF, "  'ep_reset_info' sysfs create failed.\n");
		goto error_sysfs;
	}

	ret = zxdh_bar_chan_msg_recv_register(MODULE_RESET_MSG, zxdh_reset_zf_rec_risc);
	if (ret != 0) {
		DH_LOG_ERR(MODULE_MPF,
			   "  zxdh_bar_chan_msg_recv_register: event_id[%d] register failed: %d\n",
			   MODULE_RESET_MSG, ret);
		// return ret;
	}

	DH_LOG_INFO(MODULE_MPF, "  zxdh host reset module init ok.\n");
	return 0;

error_sysfs:
	zxdh_bar_chan_msg_recv_unregister(MODULE_RESET_MSG);
	sysfs_remove_file(kernel_kobj, &zxdh_host_reset_attr_ep_reset_info.attr);
	sysfs_remove_file(kernel_kobj, &zxdh_host_reset_attr_ep_check_register.attr);
	kobject_put(kobj_zxdh_host_reset);
	return -1;
}

void zxdh_host_reset_driver_exit(struct dh_core_dev *core_dev)
{
	zxdh_bar_chan_msg_recv_unregister(MODULE_RESET_MSG);
	sysfs_remove_file(kernel_kobj, &zxdh_host_reset_attr_ep_reset_info.attr);
	sysfs_remove_file(kernel_kobj, &zxdh_host_reset_attr_ep_check_register.attr);
	kobject_put(kobj_zxdh_host_reset);
	DH_LOG_INFO(MODULE_MPF, "  zxdh host reset module remove ok.\n");
}
