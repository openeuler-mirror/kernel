// SPDX-License-Identifier: GPL-2.0
/*
 * Scsi Host Layer for hst2dr based controllers
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_init.c

 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * NO WARRANTY
 * THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT
 * LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is
 * solely responsible for determining the appropriateness of using and
 * distributing the Program and assumes all risks associated with its
 * exercise of rights under this Agreement, including but not limited to
 * the risks and costs of program errors, damage to or loss of data,
 * programs or equipment, and unavailability or interruption of operations.

 * DISCLAIMER OF LIABILITY
 * NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED
 * HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES

 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <scsi/sg.h>
#include <linux/interrupt.h>
#include <linux/aer.h>
#include <linux/raid_class.h>
#include <asm/unaligned.h>

#include "hst2dr_base.h"
#include "hst2dr_comm.h"
#include "hst2dr_debug.h"

/* forward proto's */
static void _hst2dr_expander_node_remove(struct HST2DR_ADAPTER *ioa,
	struct _sas_node *sas_expander);
static void _firmware_event_work(struct work_struct *work);

static void _hst2dr_remove_device(struct HST2DR_ADAPTER *ioa,
	struct _sas_device *sas_device);
static int _hst2dr_add_device(struct HST2DR_ADAPTER *ioa, u16 handle,
	u8 retry_count);

static u8 _hst2dr_check_for_pending_task(struct HST2DR_ADAPTER *ioa,
	u16 host_tag_id);
static void
_hst2dr_block_io_all_device(struct HST2DR_ADAPTER *ioa);

/* global parameters */
LIST_HEAD(hst2dr_ioa_list);
/* global ioa lock for list operations */
DEFINE_SPINLOCK(gioa_lock);

MODULE_AUTHOR(HST2DR_AUTHOR);
MODULE_DESCRIPTION(HST2DR_DESCRIPTION);
MODULE_VERSION(HST2DR_FULL_VERSION);
MODULE_LICENSE("GPL");
#define RAID_CHANNEL 1

/* local parameters */
static u8 scsi_io_cb_idx = INVALID_CB_INDEX;
static u8 tm_cb_idx = INVALID_CB_INDEX;
static u8 ctl_cb_idx = INVALID_CB_INDEX;
static u8 base_cb_idx = INVALID_CB_INDEX;
static u8 port_enable_cb_idx = INVALID_CB_INDEX;
static u8 transport_cb_idx = INVALID_CB_INDEX;
static u8 config_cb_idx = INVALID_CB_INDEX;
static int hst2dr_ids;
static u8 tr_cb_idx = INVALID_CB_INDEX;
static u8 tr_vol_cb_idx = INVALID_CB_INDEX;

/* command line options */

static ushort max_sectors = 0xFFFF;

static int missing_delay[2] = {-1, -1};

/* scsi-mid layer global parmeter is max_report_luns, which is 511 */
#define HST2DR_MAX_LUN (16895)
static int max_lun = HST2DR_MAX_LUN;
static int disable_discovery = -1;

/* permit overriding the host protection capabilities mask (EEDP/T10 PI) */
static int prot_mask = -1;

int hst2dr_select_q_mode = -1;
module_param(hst2dr_select_q_mode, int, 0644);
MODULE_PARM_DESC(hst2dr_select_q_mode, "Select IO queue mode: default -1 for auto detect");

/**
 * struct sense_info - common structure for obtaining sense keys
 * @skey: sense key
 * @asc: additional sense code
 * @ascq: additional sense code qualifier
 */
struct sense_info {
	u8 skey;
	u8 asc;
	u8 ascq;
};

#define HST2DR_PORT_ENABLE_COMPLETE (0xFFFD)
#define HST2DR_REMOVE_UNRESPONDING_DEVICES (0xFFFF)
/**
 * struct fw_event_work - firmware event struct
 * @list: link list framework
 * @work: work object (ioa->fault_reset_work_queue)
 * @ioa: per adapter object
 * @device_handle: device handle
 * @ignore: flag meaning this event has been marked to ignore
 * @event: firmware event SSI2_EVENT_XXX defined in ssi2_ioa.h
 * @refcount: kref for this event
 * @event_data: reply event data payload follows
 *
 * This object stored on ioa->fw_event_list.
 */
struct fw_event_work {
	struct list_head	list;
	struct work_struct	work;

	struct HST2DR_ADAPTER *ioa;
	u16			device_handle;
	u8			pending_dev;
	u8			ignore;
	u16			event;
	struct kref		refcount;
	char			event_data[] __aligned(4);
};

static void fw_event_work_free(struct kref *r)
{
	kfree(container_of(r, struct fw_event_work, refcount));
}

static void fw_event_work_get(struct fw_event_work *fw_work)
{
	kref_get(&fw_work->refcount);
}

static void fw_event_work_put(struct fw_event_work *fw_work)
{
	kref_put(&fw_work->refcount, fw_event_work_free);
}

static struct fw_event_work *alloc_fw_event_work(int len)
{
	struct fw_event_work *fw_event;

	fw_event = kzalloc(sizeof(*fw_event) + len, GFP_ATOMIC);
	if (!fw_event)
		return NULL;

	kref_init(&fw_event->refcount);
	return fw_event;
}
/**
 * _hst2dr_raid_device_find_by_id - raid device search
 * @ioa: per adapter object
 * @id: sas device target id
 * @channel: sas device channel
 * Context: Calling function should acquire ioa>raid_device_lock
 *
 * This searches for raid_device based on target id, then return raid_device
 * object.
 */
static struct _raid_device *
_hst2dr_raid_device_find_by_id(struct HST2DR_ADAPTER *ioa, int id, int channel)
{
	struct _raid_device *raid_device, *r;

	r = NULL;
	list_for_each_entry(raid_device, &ioa->raid_device_list, list) {
		if (raid_device->id == id && raid_device->channel == channel) {
			r = raid_device;
			goto out;
		}
	}

 out:
	return r;
}
/**
 * _hst2dr_raid_device_find_by_handle - raid device search
 * @ioa: per adapter object
 * @handle: sas device handle (assigned by firmware)
 * Context: Calling function should acquire ioa->raid_device_lock
 *
 * This searches for raid_device based on handle, then return raid_device
 * object.
 */
struct _raid_device *
_hst2dr_raid_device_find_by_handle(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _raid_device *raid_device, *r;

	r = NULL;
	list_for_each_entry(raid_device, &ioa->raid_device_list, list) {
		if (raid_device->handle != handle)
			continue;
		r = raid_device;
		goto out;
	}

 out:
	return r;
}
/**
 * _hst2dr_raid_device_find_by_wwid - raid device search
 * @ioa: per adapter object
 * @handle: sas device handle (assigned by firmware)
 * This searches for raid_device based on wwid, then return raid_device
 * object.
 */
static struct _raid_device *
_hst2dr_raid_device_find_by_wwid(struct HST2DR_ADAPTER *ioa, u64 wwid)
{
	struct _raid_device *raid_device, *r;

	r = NULL;
	if (list_empty(&ioa->raid_device_list))
		return r;

	list_for_each_entry(raid_device, &ioa->raid_device_list, list) {
		if (raid_device->wwid != wwid)
			continue;
		r = raid_device;
		goto out;
	}

 out:
	return r;
}
/**
 * _hst2dr_get_sas_address - get the sas_address for given device handle
 * @handle: device handle
 * @sas_address: sas address
 *
 * Returns 0 success, non-zero when failure
 */
static int
_hst2dr_get_sas_address(struct HST2DR_ADAPTER *ioa, u16 handle,
	u64 *sas_address)
{
	SSI2_INQUIRY_SAS_DEV sas_dev00;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	u32 ioa_status;

	*sas_address = 0;

	if ((hst2dr_cfg_get_sas_dev(ioa, &ssi_reply, &sas_dev00,
		SSI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -ENXIO;
	}

	ioa_status = le16_to_cpu(ssi_reply.status) & SSI2_IOASTATUS_MASK;
	if (ioa_status == SSI2_IOASTATUS_SUCCESS) {
		/* For HBA, vSES doesn't return HBA SAS address. Instead return
		 * vSES's sas address.
		 */
		if ((handle <= ioa->sas_hba.num_phys) &&
			(!(le32_to_cpu(sas_dev00.dev_info) &
			SSI2_SAS_DEVICE_INFO_SEP)))
			*sas_address = ioa->sas_hba.sas_address;
		else
			*sas_address = le64_to_cpu(sas_dev00.sas_address);
		return 0;
	}

	/* we hit this because the given parent handle doesn't exist */
	if (ioa_status == SSI2_IOASTATUS_CONFIG_INVALID_PAGE)
		return -ENXIO;

	/* else error case */
	log_error(ioa,
		"handle(0x%04x), ioa_status(0x%04x), failure at %s:%d/%s()!\n",
		handle, ioa_status,
		__FILE__, __LINE__, __func__);
	return -EIO;
}
static struct _sas_device *
__hst2dr_get_sdev_from_target(struct HST2DR_ADAPTER *ioa,
		struct HST2DR_TARGET *tgt_priv)
{
	struct _sas_device *ret;

	assert_spin_locked(&ioa->sas_device_lock);

	ret = tgt_priv->sdev;
	if (ret)
		sas_device_get(ret);

	return ret;
}
/**
 * hst2dr_get_sdev_from_target - get the sas_device for given target
 * @ioa: Pointer to HST2DR_ADAPTER structure
 * @tgt_priv: Pointer to target private structure
 *
 * This searches for sas_device based on target, then return sas_device
 * Returns 0 no device found
 */
static struct _sas_device *
hst2dr_get_sdev_from_target(struct HST2DR_ADAPTER *ioa,
		struct HST2DR_TARGET *tgt_priv)
{
	struct _sas_device *ret;
	unsigned long flags;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	ret = __hst2dr_get_sdev_from_target(ioa, tgt_priv);
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	return ret;
}

struct _sas_device *
__hst2dr_get_sdev_by_addr(struct HST2DR_ADAPTER *ioa,
					u64 sas_address)
{
	struct _sas_device *sas_device;

	assert_spin_locked(&ioa->sas_device_lock);

	list_for_each_entry(sas_device, &ioa->sas_device_list, list)
		if (sas_device->sas_address == sas_address)
			goto found_device;
	list_for_each_entry(sas_device, &ioa->sas_device_init_list, list)
		if (sas_device->sas_address == sas_address)
			goto found_device;
	return NULL;

found_device:
	sas_device_get(sas_device);
	return sas_device;
}

/**
 * hst2dr_get_sdev_by_addr - sas device search
 * @ioa: per adapter object
 * @sas_address: sas address
 * Context: Calling function should acquire ioa->sas_device_lock
 *
 * This searches for sas_device based on sas_address, then return sas_device
 * object.
 */
struct _sas_device *
hst2dr_get_sdev_by_addr(struct HST2DR_ADAPTER *ioa,
	u64 sas_address)
{
	struct _sas_device *sas_device;
	unsigned long flags;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_addr(ioa,
			sas_address);
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	return sas_device;
}

static struct _sas_device *
__hst2dr_get_sdev_by_handle(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _sas_device *sas_device;

	assert_spin_locked(&ioa->sas_device_lock);

	list_for_each_entry(sas_device, &ioa->sas_device_list, list)
		if (sas_device->handle == handle)
			goto found_device;
	list_for_each_entry(sas_device, &ioa->sas_device_init_list, list)
		if (sas_device->handle == handle)
			goto found_device;
	return NULL;

found_device:
	sas_device_get(sas_device);
	return sas_device;
}

/**
 * hst2dr_get_sdev_by_handle - sas device search
 * @ioa: per adapter object
 * @handle: sas device handle (assigned by firmware)
 * Context: Calling function should acquire ioa->sas_device_lock
 *
 * This searches for sas_device based on sas_address, then return sas_device
 * object.
 */
static struct _sas_device *
hst2dr_get_sdev_by_handle(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _sas_device *sas_device;
	unsigned long flags;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_handle(ioa, handle);
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	return sas_device;
}

/**
 * _hst2dr_display_enclosure_chassis_info - display device location info
 * @ioa: per adapter object
 * @sas_device: per sas device object
 * @sdev: scsi device struct
 * @starget: scsi target struct
 *
 * Returns nothing.
 */
static void
_hst2dr_display_enclosure_chassis_info(struct HST2DR_ADAPTER *ioa,
	struct _sas_device *sas_device, struct scsi_device *sdev,
	struct scsi_target *starget)
{
	if (sdev) {
		if (sas_device->enclosure_handle != 0)
			sdev_printk(KERN_INFO, sdev,
				"enclosure logical id (0x%016llx), slot(%d)\n",
				(unsigned long long)
				sas_device->enclosure_logical_id,
				sas_device->slot);
		if (sas_device->connector_name[0] != '\0')
			sdev_printk(KERN_INFO, sdev,
				"enclosure level(0x%04x), connector name( %s)\n",
				sas_device->enclosure_level,
				sas_device->connector_name);
		if (sas_device->is_chassis_slot_valid)
			sdev_printk(KERN_INFO, sdev, "chassis slot(0x%04x)\n",
				sas_device->chassis_slot);
	} else if (starget) {
		if (sas_device->enclosure_handle != 0)
			starget_printk(KERN_INFO, starget,
				"enclosure logical id(0x%016llx), slot(%d)\n",
				(unsigned long long)
				sas_device->enclosure_logical_id,
				sas_device->slot);
		if (sas_device->connector_name[0] != '\0')
			starget_printk(KERN_INFO, starget,
				"enclosure level(0x%04x), connector name( %s)\n",
				sas_device->enclosure_level,
				sas_device->connector_name);
		if (sas_device->is_chassis_slot_valid)
			starget_printk(KERN_INFO, starget,
				"chassis slot(0x%04x)\n",
				sas_device->chassis_slot);
	} else {
		if (sas_device->enclosure_handle != 0)
			log_always(ioa,
				"enclosure logical id(0x%016llx), slot(%d)\n",
				(unsigned long long)
				sas_device->enclosure_logical_id,
				sas_device->slot);
		if (sas_device->connector_name[0] != '\0')
			log_always(ioa,
				"enclosure level(0x%04x), connector name( %s)\n",
				sas_device->enclosure_level,
				sas_device->connector_name);
		if (sas_device->is_chassis_slot_valid)
			log_always(ioa, "chassis slot(0x%04x)\n",
				sas_device->chassis_slot);
	}
}

/**
 * _hst2dr_device_remove - remove sas_device from list.
 * @ioa: per adapter object
 * @sas_device: the sas_device object
 * Context: This function will acquire ioa->sas_device_lock.
 *
 * If sas_device is on the list, remove it and decrement its reference count.
 */
static void
_hst2dr_device_remove(struct HST2DR_ADAPTER *ioa,
	struct _sas_device *sas_device)
{
	unsigned long flags;

	if (!sas_device)
		return;
	log_always(ioa,
		"removing handle(0x%04x), sas_addr(0x%016llx)\n",
		sas_device->handle,
		(unsigned long long) sas_device->sas_address);

	_hst2dr_display_enclosure_chassis_info(ioa, sas_device, NULL, NULL);

	/*
	 * The lock serializes access to the list, but we still need to verify
	 * that nobody removed the entry while we were waiting on the lock.
	 */
	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	if (!list_empty(&sas_device->list)) {
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}

	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
}

/**
 * _hst2dr_device_remove_by_handle - removing device object by handle
 * @ioa: per adapter object
 * @handle: device handle
 *
 * Return nothing.
 */
static void
_hst2dr_device_remove_by_handle(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _sas_device *sas_device;
	unsigned long flags;

	if (ioa->shost_recovery)
		return;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_handle(ioa, handle);
	if (sas_device) {
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	if (sas_device) {
		_hst2dr_remove_device(ioa, sas_device);
		sas_device_put(sas_device);
	}
}

/**
 * hst2dr_device_remove_by_sas_address - removing device object by sas address
 * @ioa: per adapter object
 * @sas_address: device sas_address
 *
 * Return nothing.
 */
void
hst2dr_device_remove_by_sas_address(struct HST2DR_ADAPTER *ioa,
	u64 sas_address)
{
	struct _sas_device *sas_device;
	unsigned long flags;

	if (ioa->shost_recovery)
		return;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_addr(ioa, sas_address);
	if (sas_device) {
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	if (sas_device) {
		_hst2dr_remove_device(ioa, sas_device);
		sas_device_put(sas_device);
	}
}

/**
 * _hst2dr_device_add - insert sas_device to the list.
 * @ioa: per adapter object
 * @sas_device: the sas_device object
 * Context: This function will acquire ioa->sas_device_lock.
 *
 * Adding new object to the ioa->sas_device_list.
 */
static void
_hst2dr_device_add(struct HST2DR_ADAPTER *ioa,
	struct _sas_device *sas_device)
{
	unsigned long flags;

	log_always(ioa,
		"device add: handle(0x%04x), sas_addr(0x%016llx)\n",
		sas_device->handle,
		(unsigned long long)sas_device->sas_address);

	_hst2dr_display_enclosure_chassis_info(ioa, sas_device, NULL, NULL);
	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device_get(sas_device);
	list_add_tail(&sas_device->list, &ioa->sas_device_list);
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	if (!hst2dr_transport_port_add(ioa, sas_device->handle,
			sas_device->sas_address_parent)) {
		_hst2dr_device_remove(ioa, sas_device);
	} else if (!sas_device->starget) {
		/*
		 * When asyn scanning is enabled, its not possible to remove
		 * devices while scanning is turned on due to an oops in
		 * scsi_sysfs_add_sdev()->add_device()->sysfs_addrm_start()
		 */
		if (!ioa->is_driver_loading) {
			hst2dr_transport_port_remove(ioa,
				sas_device->sas_address,
				sas_device->sas_address_parent);
			_hst2dr_device_remove(ioa, sas_device);
		}
	} else
		clear_bit(sas_device->handle, ioa->pend_os_device_add);
}
/**
 * _hst2dr_device_init_add - insert sas_device to the list.
 * @ioa: per adapter object
 * @sas_device: the sas_device object
 * Context: This function will acquire ioa->sas_device_lock.
 *
 * Adding new object at driver load time to the ioa->sas_device_init_list.
 */
static void
_hst2dr_device_init_add(struct HST2DR_ADAPTER *ioa,
	struct _sas_device *sas_device)
{
	unsigned long flags;

	log_always(ioa,
		"device init add: handle(0x%04x), sas_addr(0x%016llx)\n",
		sas_device->handle,
		(unsigned long long)sas_device->sas_address);

	_hst2dr_display_enclosure_chassis_info(ioa, sas_device, NULL, NULL);
	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device_get(sas_device);
	list_add_tail(&sas_device->list, &ioa->sas_device_init_list);
	//_hst2dr_determine_boot_device(ioa, sas_device, 0);
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
}
/**
 * hst2dr_expander_find_by_handle - expander device search
 * @ioa: per adapter object
 * @handle: expander handle (assigned by firmware)
 * Context: Calling function should acquire ioa->sas_device_lock
 *
 * This searches for expander device based on handle, then returns the
 * sas_node object.
 */
struct _sas_node *
hst2dr_expander_find_by_handle(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _sas_node *sas_expander, *r;

	r = NULL;
	list_for_each_entry(sas_expander, &ioa->sas_expander_list, list) {
		if (sas_expander->handle != handle)
			continue;
		r = sas_expander;
		goto out;
	}
 out:
	return r;
}

/**
 * hst2dr_expander_find_by_sas_address - expander device search
 * @ioa: per adapter object
 * @sas_address: sas address
 * Context: Calling function should acquire ioa->sas_node_lock.
 *
 * This searches for expander device based on sas_address, then returns the
 * sas_node object.
 */
struct _sas_node *
hst2dr_expander_find_by_sas_address(struct HST2DR_ADAPTER *ioa,
	u64 sas_address)
{
	struct _sas_node *sas_expander, *r;

	r = NULL;
	list_for_each_entry(sas_expander, &ioa->sas_expander_list, list) {
		if (sas_expander->sas_address != sas_address)
			continue;
		r = sas_expander;
		goto out;
	}
 out:
	return r;
}

/**
 * _hst2dr_expander_node_add - insert expander device to the list.
 * @ioa: per adapter object
 * @sas_expander: the sas_device object
 * Context: This function will acquire ioa->sas_node_lock.
 *
 * Adding new object to the ioa->sas_expander_list.
 *
 * Return nothing.
 */
static void
_hst2dr_expander_node_add(struct HST2DR_ADAPTER *ioa,
	struct _sas_node *sas_expander)
{
	unsigned long flags;

	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	list_add_tail(&sas_expander->list, &ioa->sas_expander_list);
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
}

/**
 * _hst2dr_is_end_device - determines if device is an end device
 * @device_info: bitfield providing information about the device.
 * Context: none
 *
 * Returns 1 if end device.
 */
static int
_hst2dr_is_end_device(u32 device_info)
{
	if (device_info & SSI2_SAS_DEVICE_INFO_END_DEVICE &&
		((device_info & SSI2_SAS_DEVICE_INFO_SSP_TARGET) |
		(device_info & SSI2_SAS_DEVICE_INFO_STP_TARGET) |
		(device_info & SSI2_SAS_DEVICE_INFO_SATA_DEVICE)))
		return 1;
	else
		return 0;
}

/**
 * _hst2dr_scsi_lookup_get - returns scmd entry
 * @ioa: per adapter object
 * @host_tag_id: request message index
 *
 * Returns the host_tag_id stored scmd pointer.
 */
struct scsi_cmnd *
_hst2dr_scsi_lookup_get(struct HST2DR_ADAPTER *ioa, u16 host_tag_id)
{
	struct scsi_cmnd *scmd = NULL;
	struct scsiio_tracker *st;
	u32 unique_tag;
	u16 hwq;

	if (ioa->tag_queue_number == NULL)
		return scmd;
	hwq = ioa->tag_queue_number[host_tag_id];
	if (host_tag_id >= 0  &&
			host_tag_id < ioa->scsiio_depth -
			INTERNAL_SCSIIO_CMDS_COUNT) {
		unique_tag = (hwq << BLK_MQ_UNIQUE_TAG_BITS) |
			(host_tag_id - ioa->host_tag_id_offset[hwq]);

		scmd = scsi_host_find_tag(ioa->shost, unique_tag);
		if (scmd) {
			st = scsi_cmd_priv(scmd);
			if (!st || (st->cb_idx == INVALID_CB_INDEX) ||
					(st->direct_io != MAGIC_NUMBER))
				scmd = NULL;
		}
	}
	return scmd;
}

/**
 * hst2dr_change_queue_depth - setting device queue depth
 * @sdev: scsi device struct
 * @qdepth: requested queue depth
 * @reason: SCSI_QDEPTH_DEFAULT/SCSI_QDEPTH_QFULL/SCSI_QDEPTH_RAMP_UP
 * (see include/scsi/scsi_host.h for defhst2n)
 *
 * Returns queue depth.
 */
static int
hst2dr_change_queue_depth(struct scsi_device *sdev, int qdepth)
{
	struct Scsi_Host *shost = sdev->host;
	int max_depth;
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct HST2DR_TARGET *sas_target_priv_data;
	struct _sas_device *sas_device;
	unsigned long flags;

	max_depth = shost->can_queue;
	/* limit max device queue for SATA to 32 */
	sas_device_priv_data = sdev->hostdata;
	if (!sas_device_priv_data)
		goto not_sata;
	sas_target_priv_data = sas_device_priv_data->sas_target;
	if (!sas_target_priv_data)
		goto not_sata;
	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_from_target(ioa, sas_target_priv_data);
	if (sas_device) {
		if (sas_device->device_info & SSI2_SAS_DEVICE_INFO_SATA_DEVICE)
			max_depth = HST2DR_SATA_QUEUE_DEPTH;

		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

 not_sata:

	if (!sdev->tagged_supported)
		max_depth = 1;
	if (qdepth >= max_depth)
		qdepth = max_depth - 1;
	switch (ioa->info.driver_version >> 16) {
	case HST2DR_V2:
	default:
		scsi_change_queue_depth(sdev, qdepth);
		break;
	}
	log_debug(ioa, "change queue depth to %d\n", sdev->queue_depth);
	return sdev->queue_depth;
}


/**
 * hst2dr_target_alloc - target add routine
 * @starget: scsi target struct
 *
 * Returns 0 if ok. Any other return is assumed to be an error and
 * the device is ignored.
 */
static int
hst2dr_target_alloc(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(&starget->dev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	struct HST2DR_TARGET *sas_target_priv_data;
	struct _sas_device *sas_device;
	unsigned long flags;
	struct sas_rphy *rphy;
	struct _raid_device *raid_device;

	sas_target_priv_data = kzalloc(sizeof(*sas_target_priv_data),
				GFP_KERNEL);
	if (!sas_target_priv_data)
		return -ENOMEM;

	starget->hostdata = sas_target_priv_data;
	sas_target_priv_data->starget = starget;
	sas_target_priv_data->handle = HST2DR_INVALID_DEVICE_HANDLE;
	/* RAID volumes */
	if (starget->channel == RAID_CHANNEL) {
		spin_lock_irqsave(&ioa->raid_device_lock, flags);
		raid_device = _hst2dr_raid_device_find_by_id(ioa, starget->id,
			starget->channel);
		if (raid_device) {
			sas_target_priv_data->handle = raid_device->handle;
			sas_target_priv_data->sas_address = raid_device->wwid;
			sas_target_priv_data->flags |=
				HST2DR_TARGET_FLAGS_VOLUME;
			sas_target_priv_data->device_info =
				raid_device->device_info;
			raid_device->starget = starget;
		}
		spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
		return 0;
	}
	/* sas/sata devices */
	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	rphy = dev_to_rphy(starget->dev.parent);
	sas_device = __hst2dr_get_sdev_by_addr(ioa,
		rphy->identify.sas_address);

	if (sas_device) {
		sas_target_priv_data->handle = sas_device->handle;
		sas_target_priv_data->sas_address = sas_device->sas_address;
		sas_target_priv_data->sdev = sas_device;
		sas_target_priv_data->device_info = sas_device->device_info;
		sas_device->starget = starget;
		sas_device->id = starget->id;
		sas_device->channel = starget->channel;
		if (test_bit(sas_device->handle, ioa->pd_handles))
			sas_target_priv_data->flags |=
				HST2DR_TARGET_FLAGS_RAID_COMPONENT;
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	return 0;
}

/**
 * hst2dr_target_destroy - target destroy routine
 * @starget: scsi target struct
 *
 * Returns nothing.
 */
static void
hst2dr_target_destroy(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(&starget->dev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	struct HST2DR_TARGET *sas_target_priv_data;
	struct _sas_device *sas_device;
	unsigned long flags;
	struct _raid_device *raid_device;

	sas_target_priv_data = starget->hostdata;
	if (!sas_target_priv_data)
		return;

	if (starget->channel == RAID_CHANNEL) {
		spin_lock_irqsave(&ioa->raid_device_lock, flags);
		raid_device = _hst2dr_raid_device_find_by_id(ioa, starget->id,
			starget->channel);
		if (raid_device) {
			raid_device->starget = NULL;
			raid_device->sdev = NULL;
		}
		spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
		goto out;
	}

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_from_target(ioa, sas_target_priv_data);
	if (sas_device && (sas_device->starget == starget) &&
			(sas_device->id == starget->id) &&
			(sas_device->channel == starget->channel))
		sas_device->starget = NULL;

	if (sas_device) {
		/*
		 * Corresponding get() is in _hst2dr_target_alloc()
		 */
		sas_target_priv_data->sdev = NULL;
		sas_device_put(sas_device);

		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
out:
	kfree(sas_target_priv_data);
	starget->hostdata = NULL;
}

/**
 * hst2dr_slave_alloc - device add routine
 * @sdev: scsi device struct
 *
 * Returns 0 if ok. Any other return is assumed to be an error and
 * the device is ignored.
 */
static int
hst2dr_slave_alloc(struct scsi_device *sdev)
{
	struct Scsi_Host *shost;
	struct HST2DR_ADAPTER *ioa;
	struct HST2DR_TARGET *sas_target_priv_data;
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_target *starget;
	struct _sas_device *sas_device;
	unsigned long flags;
	struct _raid_device *raid_device;


	sas_device_priv_data = kzalloc(sizeof(*sas_device_priv_data),
				GFP_KERNEL);
	if (!sas_device_priv_data)
		return -ENOMEM;

	sas_device_priv_data->lun = sdev->lun;
	sas_device_priv_data->flags = HST2DR_DEVICE_FLAGS_INIT;

	starget = scsi_target(sdev);
	sas_target_priv_data = starget->hostdata;
	sas_target_priv_data->num_luns++;
	sas_device_priv_data->sas_target = sas_target_priv_data;
	sdev->hostdata = sas_device_priv_data;
	if ((sas_target_priv_data->flags & HST2DR_TARGET_FLAGS_RAID_COMPONENT))
		sdev->no_uld_attach = 1;

	shost = dev_to_shost(&starget->dev);
	ioa = shost_priv(shost);
	if (starget->channel == RAID_CHANNEL) {

		spin_lock_irqsave(&ioa->raid_device_lock, flags);
		raid_device = _hst2dr_raid_device_find_by_id(ioa,
			starget->id, starget->channel);

		if (raid_device)
			raid_device->sdev = sdev; /* raid is single lun */

		spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
	}
	if (!(sas_target_priv_data->flags & HST2DR_TARGET_FLAGS_VOLUME)) {
		spin_lock_irqsave(&ioa->sas_device_lock, flags);
		sas_device = __hst2dr_get_sdev_by_addr(ioa,
					sas_target_priv_data->sas_address);
		if (sas_device && (sas_device->starget == NULL)) {
			sdev_printk(KERN_INFO, sdev,
				"%s : sas_device->starget set to starget @ %d\n",
				__func__, __LINE__);
				sas_device->starget = starget;
		}

		if (sas_device)
			sas_device_put(sas_device);

		spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	}

	return 0;
}

/**
 * hst2dr_slave_destroy - device destroy routine
 * @sdev: scsi device struct
 *
 * Returns nothing.
 */
static void
hst2dr_slave_destroy(struct scsi_device *sdev)
{
	struct HST2DR_TARGET *sas_target_priv_data;
	struct scsi_target *starget;
	struct Scsi_Host *shost;
	struct HST2DR_ADAPTER *ioa;
	struct _sas_device *sas_device;
	unsigned long flags;

	if (!sdev->hostdata)
		return;

	starget = scsi_target(sdev);
	sas_target_priv_data = starget->hostdata;
	sas_target_priv_data->num_luns--;

	shost = dev_to_shost(&starget->dev);
	ioa = shost_priv(shost);

	if (!(sas_target_priv_data->flags & HST2DR_TARGET_FLAGS_VOLUME)) {
		spin_lock_irqsave(&ioa->sas_device_lock, flags);
		sas_device = __hst2dr_get_sdev_from_target(ioa,
				sas_target_priv_data);
		if (sas_device && !sas_target_priv_data->num_luns)
			sas_device->starget = NULL;

		if (sas_device)
			sas_device_put(sas_device);
		spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	}

	kfree(sdev->hostdata);
	sdev->hostdata = NULL;
}

/**
 * _hst2dr_display_sata_capabilities - sata capabilities
 * @ioa: per adapter object
 * @handle: device handle
 * @sdev: scsi device struct
 */
static void
_hst2dr_display_sata_capabilities(struct HST2DR_ADAPTER *ioa,
	u16 handle, struct scsi_device *sdev)
{
	SSI2_INQUIRY_SAS_DEV sas_dev00;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	u32 ioa_status;
	u16 flags;
	u32 device_info;

	if ((hst2dr_cfg_get_sas_dev(ioa, &ssi_reply, &sas_dev00,
			SSI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}

	ioa_status = le16_to_cpu(ssi_reply.status) &
		SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}

	flags = le16_to_cpu(sas_dev00.flags);
	device_info = le32_to_cpu(sas_dev00.dev_info);

	sdev_printk(KERN_INFO, sdev,
		"atapi(%s), ncq(%s), %s(%s), smart(%s), fua(%s), %s(%s)\n",
		(device_info & SSI2_SAS_DEVICE_INFO_ATAPI_DEVICE) ? "y" : "n",
		(flags & SSI2_SAS_DEVICE0_FLAGS_SATA_NCQ_SUPPORTED) ? "y" : "n",
		"asyn_notify",
		(flags & SSI2_SAS_DEVICE0_FLAGS_SATA_ASYNCHRONOUS_NOTIFY) ?
		"y" : "n",
		(flags & SSI2_SAS_DEVICE0_FLAGS_SATA_SMART_SUPPORTED) ? "y" : "n",
		(flags & SSI2_SAS_DEVICE0_FLAGS_SATA_FUA_SUPPORTED) ? "y" : "n",
		"sw_preserve",
		(flags & SSI2_SAS_DEVICE0_FLAGS_SATA_SW_PRESERVE) ? "y" : "n");
}

/**
 * _hst2dr_get_volume_capabilities - volume capabilities
 * @ioa: per adapter object
 * @sas_device: the raid_device object
 *
 * Returns 0 for success, else 1
 */
static int
_hst2dr_get_volume_capabilities(struct HST2DR_ADAPTER *ioa,
	struct _raid_device *raid_device)
{
	SSI2_INQUIRY_RAID_VOL *vol_pg0;
	SSI2_INQUIRY_RAID_PD pd_pg0;
	SSI2_INQUIRY_SAS_DEV sas_device_pg0;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	u16 sz;
	u16 num_pds;

	if ((hst2dr_config_get_number_pds(ioa, raid_device->handle,
			&num_pds)) || !num_pds) {
		log_warn(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}

	raid_device->num_pds = num_pds;
	sz = offsetof(SSI2_INQUIRY_RAID_VOL, phys_disk) + (num_pds *
		sizeof(struct _SSI2_RAID_VOL_PHYS_DISK));
	vol_pg0 = kzalloc(sz, GFP_KERNEL);
	if (!vol_pg0) {
		log_warn(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}

	if ((hst2dr_cfg_get_raid_vol(ioa, &ssi_reply, vol_pg0, sz,
		SSI2_RAID_VOLUME_PGAD_FORM_HANDLE, raid_device->handle))) {
		log_warn(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		kfree(vol_pg0);
		return 1;
	}

	raid_device->volume_type = vol_pg0->volume_type;

	/* figure out what the underlying devices are by
	 * obtaining the device_info bits for the 1st device
	 */

	if (!(hst2dr_cfg_get_raid_pd(ioa, &ssi_reply,
			&pd_pg0, SSI2_PHYSDISK_PGAD_FORM_PHYSDISKNUM,
			vol_pg0->phys_disk[0].phys_dev_handle))) {
		if (!(hst2dr_cfg_get_sas_dev(ioa, &ssi_reply,
				&sas_device_pg0,
				SSI2_SAS_DEVICE_PGAD_FORM_HANDLE,
				le16_to_cpu(raid_device->handle)))) {
			raid_device->device_info =
				le32_to_cpu(sas_device_pg0.dev_info);
		}
	}

	kfree(vol_pg0);
	return 0;
}
/**
 * hst2dr_slave_configure - device configure routine.
 * @sdev: scsi device struct
 *
 * Returns 0 if ok. Any other return is assumed to be an error and
 * the device is ignored.
 */
static int
hst2dr_slave_configure(struct scsi_device *sdev)
{
	struct Scsi_Host *shost = sdev->host;
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct HST2DR_TARGET *sas_target_priv_data;
	struct _sas_device *sas_device;
	struct _raid_device *raid_device;
	unsigned long flags;
	int qdepth;
	u8 ssp_target = 0;
	char *ds = "";
	char *r_level = "";
	u16 handle;

	qdepth = 1;
	sas_device_priv_data = sdev->hostdata;
	sas_device_priv_data->configured_lun = 1;
	sas_device_priv_data->flags &= ~HST2DR_DEVICE_FLAGS_INIT;
	sas_target_priv_data = sas_device_priv_data->sas_target;
	handle = sas_target_priv_data->handle;

	/* raid volume handling */
	if (sas_target_priv_data->flags & HST2DR_TARGET_FLAGS_VOLUME) {

		spin_lock_irqsave(&ioa->raid_device_lock, flags);
		raid_device = _hst2dr_raid_device_find_by_handle(ioa, handle);
		spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
		if (!raid_device) {
			log_warn(ioa, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			return 1;
		}
		if (_hst2dr_get_volume_capabilities(ioa, raid_device)) {
			log_warn(ioa, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			return 1;
		}

		if (raid_device->device_info &
				SSI2_SAS_DEVICE_INFO_SSP_TARGET) {
			qdepth = HST2DR_SAS_QUEUE_DEPTH;
			ds = "SSP";
		} else {
			qdepth = HST2DR_SAS_QUEUE_DEPTH;
			if (raid_device->device_info &
					SSI2_SAS_DEVICE_INFO_STP_TARGET)
				ds = "SATA";
			else
				ds = "STP";
		}

		switch (raid_device->volume_type) {
		case SSI2_RAID_VOL_TYPE_RAID0:
			r_level = "RAID0";
			break;
		case SSI2_RAID_VOL_TYPE_RAID1:
			qdepth = HST2DR_RAID_QUEUE_DEPTH;
			r_level = "RAID1";
			break;
		case SSI2_RAID_VOL_TYPE_RAID10:
			qdepth = HST2DR_RAID_QUEUE_DEPTH;
			r_level = "RAID10";
			break;
		case SSI2_RAID_VOL_TYPE_RAID5:
			qdepth = HST2DR_RAID_QUEUE_DEPTH;
			r_level = "RAID5";
			break;
		case SSI2_RAID_VOL_TYPE_RAID6:
			qdepth = HST2DR_RAID_QUEUE_DEPTH;
			r_level = "RAID6";
			break;
		case SSI2_RAID_VOL_TYPE_UNKNOWN:
		default:
			qdepth = HST2DR_RAID_QUEUE_DEPTH;
			r_level = "RAIDX";
			break;
		}
		/*
		 * The RAID firmware may require extended timeouts.
		 */
		blk_queue_rq_timeout(sdev->request_queue, 90 * HZ);

		qdepth = raid_device->io_qdepth;
		sdev_printk(KERN_INFO, sdev,
			"%s: handle(0x%04x), wwid(0x%016llx), %s(%d), %s(%s)\n",
			r_level, raid_device->handle,
			(unsigned long long)raid_device->wwid,
			"pd_count", raid_device->num_pds,
			"type", ds);

		if (shost->max_sectors > HST2DR_RAID_MAX_SECTORS) {
			blk_queue_max_hw_sectors(sdev->request_queue,
						HST2DR_RAID_MAX_SECTORS);
			sdev_printk(KERN_INFO, sdev,
					"Set queue's max_sector to: %u\n",
						HST2DR_RAID_MAX_SECTORS);
		}

		hst2dr_change_queue_depth(sdev, qdepth - 1);
		return 0;
	}

	/* non-raid handling */

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_addr(ioa,
		sas_device_priv_data->sas_target->sas_address);
	if (!sas_device) {
		spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
		log_warn(ioa, "raid_device none, failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}

	if (sas_device->device_info & SSI2_SAS_DEVICE_INFO_SSP_TARGET) {
		qdepth = HST2DR_SAS_QUEUE_DEPTH;
		ssp_target = 1;
		if (sas_device->device_info &
				SSI2_SAS_DEVICE_INFO_SEP) {
			sdev_printk(KERN_WARNING, sdev,
			"set ignore_delay_remove for handle(0x%04x)\n",
			sas_device_priv_data->sas_target->handle);
			sas_device_priv_data->ignore_delay_remove = 1;
			ds = "SES";
		} else
			ds = "SSP";
	} else {
		qdepth = HST2DR_SATA_QUEUE_DEPTH;
		if (sas_device->device_info & SSI2_SAS_DEVICE_INFO_STP_TARGET)
			ds = "STP";
		else if (sas_device->device_info &
			SSI2_SAS_DEVICE_INFO_SATA_DEVICE)
			ds = "SATA";
	}

	sdev_printk(KERN_INFO, sdev,
		"%s: handle(0x%04x), sas_addr(0x%016llx), phy(%d), %s(0x%016llx)\n",
		ds, handle, (unsigned long long)sas_device->sas_address,
		sas_device->phy,
		"device_name", (unsigned long long)sas_device->device_name);

	_hst2dr_display_enclosure_chassis_info(NULL, sas_device, sdev, NULL);

	sas_device_put(sas_device);
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	if (!ssp_target)
		_hst2dr_display_sata_capabilities(ioa, handle, sdev);

	hst2dr_change_queue_depth(sdev, qdepth);

	if (ssp_target)
		sas_read_port_mode_page(sdev);

	return 0;
}

/**
 * _hst2dr_response_code - translation of device response code
 * @ioa: per adapter object
 * @response_code: response code returned by the device
 *
 * Return nothing.
 */
static void
_hst2dr_response_code(struct HST2DR_ADAPTER *ioa, u8 response_code)
{
	char *desc;

	switch (response_code) {
	case SSI2_SCSITASKMGMT_RSP_TM_COMPLETE:
		desc = "task management request completed";
		break;
	case SSI2_SCSITASKMGMT_RSP_INVALID_FRAME:
		desc = "invalid frame";
		break;
	case SSI2_SCSITASKMGMT_RSP_TM_NOT_SUPPORTED:
		desc = "task management request not supported";
		break;
	case SSI2_SCSITASKMGMT_RSP_TM_FAILED:
		desc = "task management request failed";
		break;
	case SSI2_SCSITASKMGMT_RSP_TM_SUCCEEDED:
		desc = "task management request succeeded";
		break;
	case SSI2_SCSITASKMGMT_RSP_TM_INVALID_LUN:
		desc = "invalid lun";
		break;
	case SSI2_SCSITASKMGMT_RSP_TM_OVERLAPPED_TAG:
		desc = "overlapped tag attempted";
		break;
	case SSI2_SCSITASKMGMT_RSP_IO_QUEUED_ON_IOA:
		desc = "task queued, however not sent to target";
		break;
	default:
		desc = "unknown";
		break;
	}

	log_warn(ioa, "response_code(0x%01x): %s\n",
		response_code, desc);
}

/**
 * _hst2dr_tm_done - tm completion routine
 * @ioa: per adapter object
 * @cqe: completion queue entity
 * Context: none.
 *
 * The callback handler when using hst2dr_issue_tm.
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
static u8
_hst2dr_tm_done(struct HST2DR_ADAPTER *ioa,
	hst2dr_nvme_completion *cqe)
{
	SSI2_DEFAULT_REPLY *ssi_reply = NULL;

	if (ioa->tm_cmds.status == HST2DR_CMD_NOT_USED)
		return 1;
	if (ioa->tm_cmds.host_tag_id != cqe->host_tag_id) {
		log_tm(ioa, "%s %d %s%x cqe->host_tag_id:%x\n",
			__func__, __LINE__,
			"host_tag_id error, tm_cmd.host_tag_id:",
			ioa->tm_cmds.host_tag_id, cqe->host_tag_id);
		return 1;
	}
	ioa->tm_cmds.status |= HST2DR_CMD_COMPLETE;
	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply =  hst2dr_base_get_reply_virt_addr(ioa,
			cqe->reply_id);
	if (ssi_reply) {
		ssi_reply->status = cqe->ctrl.status;
		memcpy(ioa->tm_cmds.reply, ssi_reply,
			min_t(u8, ssi_reply->msg_len * 4, 128));
		if (ssi_reply->msg_len == 0)
			ioa->tm_cmds.status |= HST2DR_CMD_NOT_USED;
		else
			ioa->tm_cmds.status |= HST2DR_CMD_REPLY_VALID;
	}
	ioa->tm_cmds.status &= ~HST2DR_CMD_PENDING;
	complete(&ioa->tm_cmds.done);
	return 1;
}

/**
 * hst2dr_set_tm_flag - set per target tm_busy
 * @ioa: per adapter object
 * @handle: device handle
 *
 * During taskmangement request, we need to freeze the device queue.
 */
void
hst2dr_set_tm_flag(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;
	u8 skip = 0;

	shost_for_each_device(sdev, ioa->shost) {
		if (skip)
			continue;
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data)
			continue;
		if (sas_device_priv_data->sas_target->handle == handle) {
			sas_device_priv_data->sas_target->tm_busy = 1;
			skip = 1;
			ioa->ignore_loginfos = 1;
		}
	}
}

/**
 * hst2dr_clear_tm_flag - clear per target tm_busy
 * @ioa: per adapter object
 * @handle: device handle
 *
 * During taskmangement request, we need to freeze the device queue.
 */
void
hst2dr_clear_tm_flag(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;
	u8 skip = 0;

	shost_for_each_device(sdev, ioa->shost) {
		if (skip)
			continue;
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data)
			continue;
		if (sas_device_priv_data->sas_target->handle == handle) {
			sas_device_priv_data->sas_target->tm_busy = 0;
			skip = 1;
			ioa->ignore_loginfos = 0;
		}
	}
}

/**
 * hst2dr_issue_tm - main routine for sending tm requests
 * @ioa: per adapter struct
 * @device_handle: device handle
 * @channel: the channel assigned by the OS
 * @id: the id assigned by the OS
 * @lun: lun number
 * @type: SSI2_SCSITASKMGMT_TASKTYPE__XXX (defined in ssi2_init.h)
 * @host_tag_id_task: host_tag_id assigned to the task
 * @timeout: timeout in seconds
 * Context: user
 *
 * A generic API for sending task management requests to firmware.
 *
 * The callback index is set inside `ioa->tm_cb_idx`.
 *
 * Return SUCCESS or FAILED.
 */
int
hst2dr_issue_tm(struct HST2DR_ADAPTER *ioa, u16 handle, uint channel,
	uint id, uint lun, u8 type, u16 host_tag_id_task, ulong timeout)
{
	SSI2_SCSI_TM_REQUEST *ssi_request;
	SSI2_SCSI_TM_REPLY *ssi_reply;
	u16 host_tag_id = NO_HOST_TAG_ID;
	u32 ioa_state;
	struct scsiio_tracker *scsi_lookup = NULL;
	int rc;
	u16 msix_task = 0;
	hst2dr_command *scmd;
	SSI2_SCSI_REQUEST *io_frame;

	lockdep_assert_held(&ioa->tm_cmds.mutex);

	if (ioa->tm_cmds.status != HST2DR_CMD_NOT_USED) {
		log_tm(ioa, "%s: tm_cmd busy!\n",
			__func__);
		return FAILED;
	}

	if (ioa->shost_recovery || ioa->remove_host ||
			ioa->pci_error_recovery) {
		log_tm(ioa, "%s: host reset in progress!\n",
			__func__);
		return FAILED;
	}

	ioa_state = hst2dr_base_get_ioastate(ioa, 0);
	if (ioa_state & SSI2_IOA_USED) {
		rc = hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 5);
		return (!rc) ? SUCCESS : FAILED;
	}

	if ((ioa_state & SSI2_IOA_STATE_MASK) == SSI2_IOA_STATE_FAULT) {
		hst2dr_base_fault_info(ioa, ioa_state &
			SSI2_IOA_DATA_MASK);
		rc = hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 6);
		return (!rc) ? SUCCESS : FAILED;
	}

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->tm_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		log_error(ioa, "%s: failed obtaining a host_tag_id\n",
			__func__);
		return FAILED;
	}

	if (type == SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK)
		scsi_lookup = &ioa->scsi_lookup[host_tag_id_task - 1];

	log_tm(ioa,
		"tm: handle(0x%04x), task_type(0x%02x), host_tag_id_task(%x)\n",
		 handle, type, host_tag_id_task);

	ioa->tm_cmds.status = HST2DR_CMD_PENDING;
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	ssi_request = (SSI2_SCSI_TM_REQUEST *)scmd;
	ioa->tm_cmds.host_tag_id = host_tag_id;
	memset(ssi_request, 0, sizeof(SSI2_SCSI_TM_REQUEST));
	memset(ioa->tm_cmds.reply, 0, sizeof(SSI2_SCSI_TM_REPLY));
	ssi_request->dev_handle = cpu_to_le16(handle);
	ssi_request->task_type = type;
	ssi_request->task_manage_id = cpu_to_le16(host_tag_id_task);
	ssi_request->msg_flags = ioa->io_sequence_num[host_tag_id_task];
	int_to_scsilun(lun, (struct scsi_lun *)ssi_request->lun);
	hst2dr_set_tm_flag(ioa, handle);
	io_frame = hst2dr_base_get_msg_frame(ioa, host_tag_id_task);
	if (io_frame)
		ssi_request->io_qid = io_frame->sq_id;

	init_completion(&ioa->tm_cmds.done);
	if ((type == SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK) &&
			(scsi_lookup->msix_io < ioa->reply_queue_count))
		msix_task = scsi_lookup->msix_io;
	else
		msix_task = 0;
	scmd->cmd.internal.cmd.head.opcode = SSI2_FUNCTION_SCSI_TASK_MANAGE;
	scmd->cmd.internal.cmd.head.opflags =
		cmd_flag_fw_mode_admin | HI_PRIORITY;
	scmd->cmd.internal.cmd.head.host_tag_id = host_tag_id;
	scmd->cmd.internal.cmd.head.host_flag = hst2dr_cmd_scsih;
	scmd->cmd.internal.cmd.head.request_flags =
		SSI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY;
	ioa->put_host_tag_id_default(ioa, scmd);
retry:
	wait_for_completion_timeout(&ioa->tm_cmds.done, timeout * HZ);
	if (!(ioa->tm_cmds.status & HST2DR_CMD_COMPLETE)) {
		log_error(ioa, "%s: SSI2_FUNCTION_SCSI_TASK_MANAGE timeout\n",
			__func__);
		if (!(ioa->tm_cmds.status & HST2DR_CMD_RESET)) {
			rc = hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 7);
			rc = (!rc) ? SUCCESS : FAILED;
			goto out;
		}
	}

	/* sync IRQs in case those were busy during flush. */
	hst2dr_base_sync_reply_irqs(ioa);
	debug_dump_mem("TM reply: ", ioa->tm_cmds.reply, sizeof(*ssi_reply));
	if (ioa->tm_cmds.status & HST2DR_CMD_REPLY_VALID) {
		ssi_reply = ioa->tm_cmds.reply;
		log_tm(ioa,
			"%s(0x%04x), log_info(0x%08x), term_count(0x%08x)\n",
			"tm complete: status",
			le16_to_cpu(ssi_reply->status),
			le32_to_cpu(ssi_reply->log_info),
			le32_to_cpu(ssi_reply->termination_count));
		if (ioa->log_level & LOG_TM) {
			_hst2dr_response_code(ioa, ssi_reply->response_code);
			if (ssi_reply->status)
				debug_dump_mem("tm req", ssi_request,
					sizeof(SSI2_SCSI_TM_REQUEST));
		}
	} else {
		rc = FAILED;
		goto out;
	}

	switch (type) {
	case SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK:
		if (ioa->is_io_seq_num_check) {
			if (ssi_reply->msg_flags != ssi_request->msg_flags) {
				log_debug(ioa,
					"io abort seq num not match, retry waiting\n");
				ioa->tm_cmds.status = HST2DR_CMD_PENDING;
				init_completion(&ioa->tm_cmds.done);
				goto retry;
			}
		}
		if (ssi_reply->response_code ==
				SSI2_SCSITASKMGMT_RSP_TM_NOT_SUPPORTED)
			rc = FAILED;
		else
			rc = SUCCESS;
		break;
	case SSI2_SCSITASKMGMT_TASKTYPE_I_T_NEXUS_RESET:
	case SSI2_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET:
		if (ssi_reply->response_code ==
				SSI2_SCSITASKMGMT_RSP_TM_NOT_SUPPORTED)
			rc = FAILED;
		else
			rc = SUCCESS;
		break;
	default:
		rc = SUCCESS;
		break;
	}

out:
	hst2dr_clear_tm_flag(ioa, handle);
	ioa->tm_cmds.status = HST2DR_CMD_NOT_USED;
	return rc;
}

int hst2dr_issue_locked_tm(struct HST2DR_ADAPTER *ioa, u16 handle,
	uint channel, uint id, uint lun, u8 type,
	u16 host_tag_id_task, ulong timeout)
{
	int ret;

	mutex_lock(&ioa->tm_cmds.mutex);
	ret = hst2dr_issue_tm(ioa, handle, channel, id, lun, type,
			host_tag_id_task, timeout);
	mutex_unlock(&ioa->tm_cmds.mutex);

	return ret;
}

/**
 * _hst2dr_tm_display_info - displays info about the device
 * @ioa: per adapter struct
 * @scmd: pointer to scsi command object
 *
 * Called by task management callback handlers.
 */
static void
_hst2dr_tm_display_info(struct HST2DR_ADAPTER *ioa, struct scsi_cmnd *scmd)
{
	struct scsi_target *starget = scmd->device->sdev_target;
	struct HST2DR_TARGET *priv_target = starget->hostdata;
	struct _sas_device *sas_device = NULL;
	unsigned long flags;
	char *device_str = NULL;

	if (!priv_target)
		return;
	device_str = "volume";

	scsi_print_command(scmd);
	if (priv_target->flags & HST2DR_TARGET_FLAGS_VOLUME) {
		starget_printk(KERN_INFO, starget,
			"%s handle(0x%04x), %s wwid(0x%016llx)\n",
			device_str, priv_target->handle,
			device_str,
			(unsigned long long)priv_target->sas_address);
	} else {
		spin_lock_irqsave(&ioa->sas_device_lock, flags);
		sas_device = __hst2dr_get_sdev_from_target(ioa, priv_target);
		if (sas_device) {
			starget_printk(KERN_INFO, starget,
				"handle(0x%04x), sas_address(0x%016llx), phy(%d)\n",
				sas_device->handle,
				(unsigned long long)sas_device->sas_address,
				sas_device->phy);

			_hst2dr_display_enclosure_chassis_info(NULL, sas_device,
				NULL, starget);

			sas_device_put(sas_device);
		}
		spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	}
}

/**
 * hst2dr_abort - eh threads main abort routine
 * @scmd: pointer to scsi command object
 *
 * Returns SUCCESS if command aborted else FAILED
 */
static int
hst2dr_abort(struct scsi_cmnd *scmd)
{
	struct HST2DR_ADAPTER *ioa = shost_priv(scmd->device->host);
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsiio_tracker *st = scsi_cmd_priv(scmd);
	u16 handle;
	int r;
	SSI2_SCSI_REQUEST *ssi_request;

	sdev_printk(KERN_INFO, scmd->device,
		"attempting task abort! scmd(%p)\n", scmd);
	_hst2dr_tm_display_info(ioa, scmd);

	sas_device_priv_data = scmd->device->hostdata;
	if (!sas_device_priv_data || !sas_device_priv_data->sas_target) {
		sdev_printk(KERN_INFO, scmd->device,
			"device been deleted! scmd(%p)\n", scmd);
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		r = SUCCESS;
		goto out;
	}

	/* search for the command */
	if (st == NULL || st->cb_idx == INVALID_CB_INDEX ||
			st->direct_io != MAGIC_NUMBER) {
		scmd->result = DID_RESET << 16;
		r = SUCCESS;
		goto out;
	}
	ssi_request = hst2dr_base_get_msg_frame(ioa, st->host_tag_id);
	debug_dump_mem("abort io", ssi_request, 128);

	handle = sas_device_priv_data->sas_target->handle;
	if ((handle == HST2DR_INVALID_DEVICE_HANDLE) || (handle == 0))
		handle = ssi_request->logical_dev_id;

	r = hst2dr_issue_locked_tm(ioa, handle, scmd->device->channel,
		scmd->device->id, scmd->device->lun,
		SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK, st->host_tag_id, 30);
	if ((r == SUCCESS) && (st->direct_io == MAGIC_NUMBER))
		r = FAILED;

 out:
	sdev_printk(KERN_INFO, scmd->device, "task abort: %s scmd(%p)\n",
		((r == SUCCESS) ? "SUCCESS" : "FAILED"), scmd);
	return r;
}

static void
_hst2dr_unblock_io_all_device(struct HST2DR_ADAPTER *ioa);

int hst2dr_query(struct HST2DR_ADAPTER *ioa, U8 is_abrt)
{
	struct scsi_cmnd *scmd;
	struct scsi_device *sdev;
	u16 host_tag_id, handle;
	u32 lun;
	struct HST2DR_DEVICE *sas_device_priv_data;
	u32 termination_count;
	u32 query_count;
	SSI2_SCSI_TM_REPLY *ssi_reply;
	u16 ioa_status;

	unsigned long flags;
	int r = 0;
	u8 max_retries = 0;
	u8 task_abort_retries;

	mutex_lock(&ioa->tm_cmds.mutex);
	_hst2dr_block_io_all_device(ioa);

	spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
	ssi_reply = ioa->tm_cmds.reply;
 broadcast_aen_retry:

	/* sanity checks for retrying this loop */
	if (max_retries++ == 5)
		goto out;

	termination_count = 0;
	query_count = 0;
	for (host_tag_id = 0; host_tag_id < ioa->scsiio_depth; host_tag_id++) {
		if (ioa->shost_recovery)
			goto out;
		scmd = _hst2dr_scsi_lookup_get(ioa, host_tag_id);
		if (!scmd)
			continue;
		sdev = scmd->device;
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data || !sas_device_priv_data->sas_target)
			continue;
		/* skip volumes */
		if (sas_device_priv_data->sas_target->flags &
				HST2DR_TARGET_FLAGS_VOLUME)
			continue;
			 /* skip hidden raid components */
		if (sas_device_priv_data->sas_target->flags &
				HST2DR_TARGET_FLAGS_RAID_COMPONENT)
			continue;
		handle = sas_device_priv_data->sas_target->handle;
		lun = sas_device_priv_data->lun;
		query_count++;

		if (ioa->shost_recovery)
			goto out;

		spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);
		if (is_abrt == 0) {
			r = hst2dr_issue_tm(ioa, handle, 0, 0, lun,
				SSI2_SCSITASKMGMT_TASKTYPE_QUERY_TASK,
				host_tag_id, TM_WAITING);
			if (r == FAILED) {
				sdev_printk(KERN_WARNING, sdev,
					"%s QUERY_TASK: scmd(%p)\n",
					"hst2dr_issue_tm: FAILED when sending",
					scmd);
				spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
				goto broadcast_aen_retry;
			}
			ioa_status = le16_to_cpu(ssi_reply->status)
				& SSI2_IOASTATUS_MASK;
			if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
				sdev_printk(KERN_WARNING, sdev,
					"%s(0x%04x), scmd(%p)\n",
					"query task: FAILED with IOASTATUS",
					ioa_status, scmd);
				spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
				goto broadcast_aen_retry;
			}

			/* see if IO is still owned by IOA and target */
			if (ssi_reply->response_code ==
				SSI2_SCSITASKMGMT_RSP_TM_SUCCEEDED ||
				ssi_reply->response_code ==
				SSI2_SCSITASKMGMT_RSP_IO_QUEUED_ON_IOA) {
				spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
				continue;
			}
		}
		if (is_abrt == 1) {
			task_abort_retries = 0;
 tm_retry:
			if (task_abort_retries++ == 60) {
				spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
				goto broadcast_aen_retry;
			}

			if (ioa->shost_recovery)
				goto out_no_lock;
			r = hst2dr_issue_tm(ioa, handle, sdev->channel,
				sdev->id,
				sdev->lun,
				SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK,
				host_tag_id,
				TM_WAITING);
			if (r == FAILED) {
				sdev_printk(KERN_WARNING, sdev,
					"%s scmd(%p)\n",
					"hst2dr_issue_tm: ABORT_TASK: FAILED :",
					scmd);
				goto tm_retry;
			}

			if (task_abort_retries > 1)
				sdev_printk(KERN_WARNING, sdev,
					"%s RETRIES (%d): scmd(%p)\n",
					"hst2dr_issue_tm: ABORT_TASK:",
					task_abort_retries - 1, scmd);
		}
		termination_count += le32_to_cpu(ssi_reply->termination_count);
		spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
	}

	if (ioa->broadcast_aen_pending) {
		ioa->broadcast_aen_pending = 0;
		goto broadcast_aen_retry;
	}

 out:
	spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);
 out_no_lock:

	ioa->broadcast_aen_busy = 0;
	if (!ioa->shost_recovery)
		_hst2dr_unblock_io_all_device(ioa);
	mutex_unlock(&ioa->tm_cmds.mutex);
	return r;
}

/**
 * hst2dr_dev_reset - eh threads main device reset routine
 * @scmd: pointer to scsi command object
 *
 * Returns SUCCESS if command aborted else FAILED
 */
static int
hst2dr_dev_reset(struct scsi_cmnd *scmd)
{
	struct HST2DR_ADAPTER *ioa = shost_priv(scmd->device->host);
	struct HST2DR_DEVICE *sas_device_priv_data;

	struct scsi_target *starget = scmd->device->sdev_target;
	struct _sas_device *sas_device = NULL;
	struct HST2DR_TARGET *target_priv_data = starget->hostdata;

	u16	handle;
	int r;

	sdev_printk(KERN_INFO, scmd->device,
		"attempting device reset! scmd(%p)\n", scmd);
	_hst2dr_tm_display_info(ioa, scmd);

	sas_device_priv_data = scmd->device->hostdata;
	if (!sas_device_priv_data || !sas_device_priv_data->sas_target ||
			ioa->remove_host) {
		sdev_printk(KERN_INFO, scmd->device,
			"device been deleted! scmd(%p)\n", scmd);
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		r = SUCCESS;
		goto out;
	}

	/* for hidden raid components obtain the volume_handle */
	handle = 0;
	if (sas_device_priv_data->sas_target->flags &
			HST2DR_TARGET_FLAGS_RAID_COMPONENT) {
		sas_device = hst2dr_get_sdev_from_target(ioa,
				target_priv_data);
		if (sas_device)
			handle = sas_device->volume_handle;
	} else {
		handle = sas_device_priv_data->sas_target->handle;
	}


	if (!handle) {
		scmd->result = DID_RESET << 16;
		r = FAILED;
		goto out;
	}

	if (handle == HST2DR_INVALID_DEVICE_HANDLE) {
		sdev_printk(KERN_INFO, scmd->device,
			"device been deleted! scmd(%p)\n", scmd);
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		r = SUCCESS;
		goto out;
	}
	r = hst2dr_issue_locked_tm(ioa, handle, scmd->device->channel,
		scmd->device->id, scmd->device->lun,
		SSI2_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET, 0, 30);
	if ((r == SUCCESS) && scsi_device_busy(scmd->device))
		r = FAILED;
out:
	sdev_printk(KERN_INFO, scmd->device, "device reset: %s scmd(%p)\n",
		((r == SUCCESS) ? "SUCCESS" : "FAILED"), scmd);

	return r;
}
/**
 * hst2dr_target_reset - eh threads main target reset routine
 * @scmd: pointer to scsi command object
 *
 * Returns SUCCESS if command aborted else FAILED
 */
static int
hst2dr_target_reset(struct scsi_cmnd *scmd)
{
	struct HST2DR_ADAPTER *ioa = shost_priv(scmd->device->host);
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct _sas_device *sas_device = NULL;
	struct scsi_target *starget = scmd->device->sdev_target;
	struct HST2DR_TARGET *target_priv_data = starget->hostdata;

	u16	handle;
	u8	tr_method = 0;
	u8	tr_timeout = 30;
	int r;


	starget_printk(KERN_INFO, starget,
		"attempting target reset! scmd(%p)\n",
		scmd);
	_hst2dr_tm_display_info(ioa, scmd);

	sas_device_priv_data = scmd->device->hostdata;
	if (!sas_device_priv_data || !sas_device_priv_data->sas_target ||
			ioa->remove_host) {
		starget_printk(KERN_INFO, starget,
			"target been deleted! scmd(%p)\n",
			scmd);
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		r = SUCCESS;
		goto out;
	}

	/* for hidden raid components obtain the volume_handle */
	handle = 0;
	if (sas_device_priv_data->sas_target->flags &
			HST2DR_TARGET_FLAGS_RAID_COMPONENT) {
		sas_device = hst2dr_get_sdev_from_target(ioa,
				target_priv_data);
		if (sas_device)
			handle = sas_device->volume_handle;
	} else {
		handle = sas_device_priv_data->sas_target->handle;
	}

	if (!handle) {
		scmd->result = DID_RESET << 16;
		r = FAILED;
		goto out;
	}

	if (handle == HST2DR_INVALID_DEVICE_HANDLE) {
		starget_printk(KERN_INFO, starget,
			"target been deleted! scmd(%p)\n", scmd);
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		r = SUCCESS;
		goto out;
	}
	tr_method = 0;
	r = hst2dr_issue_locked_tm(ioa, handle, 0, 0, 0,
		SSI2_SCSITASKMGMT_TASKTYPE_I_T_NEXUS_RESET,
		tr_method, tr_timeout);
	/* Check for busy commands after reset */
	if (r == SUCCESS && atomic_read(&starget->target_busy))
		r = FAILED;

 out:
	starget_printk(KERN_INFO, starget, "target reset: %s scmd(%p)\n",
		((r == SUCCESS) ? "SUCCESS" : "FAILED"), scmd);

	if (sas_device)
		sas_device_put(sas_device);

	return r;

}


/**
 * hst2dr_host_reset - eh threads main host reset routine
 * @scmd: pointer to scsi command object
 *
 * Returns SUCCESS if command aborted else FAILED
 */
static int
hst2dr_host_reset(struct scsi_cmnd *scmd)
{
	struct HST2DR_ADAPTER *ioa = shost_priv(scmd->device->host);
	int r, retval;

	log_always(ioa, "attempting host reset! scmd(%p)\n",
		scmd);
	scsi_print_command(scmd);

	if (ioa->is_driver_loading) {
		log_error(ioa, "Blocking the host reset\n");
		r = FAILED;
		goto out;
	}

	retval = hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 8);
	r = (retval < 0) ? FAILED : SUCCESS;
out:
	log_always(ioa, "host reset: %s scmd(%p)\n",
		((r == SUCCESS) ? "SUCCESS" : "FAILED"), scmd);

	return r;
}

/**
 * _hst2dr_fw_event_add - insert and queue up fw_event
 * @ioa: per adapter object
 * @fw_event: object describing the event
 * Context: This function will acquire ioa->fw_event_lock.
 *
 * This adds the firmware event object into link list, then queues it up to
 * be processed from user context.
 *
 * Return nothing.
 */
static void
_hst2dr_fw_event_add(struct HST2DR_ADAPTER *ioa, struct fw_event_work *fw_event)
{
	unsigned long flags;

	if (ioa->firmware_event_work_queue == NULL)
		return;

	spin_lock_irqsave(&ioa->fw_event_lock, flags);
	fw_event_work_get(fw_event);
	INIT_LIST_HEAD(&fw_event->list);
	list_add_tail(&fw_event->list, &ioa->fw_event_list);
	INIT_WORK(&fw_event->work, _firmware_event_work);
	fw_event_work_get(fw_event);
	queue_work(ioa->firmware_event_work_queue, &fw_event->work);
	spin_unlock_irqrestore(&ioa->fw_event_lock, flags);
}

/**
 * _hst2dr_fw_event_del_from_list - delete fw_event from the list
 * @ioa: per adapter object
 * @fw_event: object describing the event
 * Context: This function will acquire ioa->fw_event_lock.
 *
 * If the fw_event is on the fw_event_list, remove it and do a put.
 *
 * Return nothing.
 */
static void
_hst2dr_fw_event_del_from_list(struct HST2DR_ADAPTER *ioa, struct fw_event_work
	*fw_event)
{
	unsigned long flags;

	spin_lock_irqsave(&ioa->fw_event_lock, flags);
	if (!list_empty(&fw_event->list)) {
		list_del_init(&fw_event->list);
		fw_event_work_put(fw_event);
	}
	spin_unlock_irqrestore(&ioa->fw_event_lock, flags);
}

/**
 * _log_ini_emergor_recovery_delete_devices - remove devices not responding
 * @ioa: per adapter object
 *
 * Return nothing.
 */
static void
_log_ini_emergor_recovery_delete_devices(struct HST2DR_ADAPTER *ioa)
{
	struct fw_event_work *fw_event;

	if (ioa->is_driver_loading)
		return;
	fw_event = alloc_fw_event_work(0);
	if (!fw_event)
		return;
	fw_event->event = HST2DR_REMOVE_UNRESPONDING_DEVICES;
	fw_event->ioa = ioa;
	_hst2dr_fw_event_add(ioa, fw_event);
	fw_event_work_put(fw_event);
}

/**
 * hst2dr_port_enable_complete - port enable completed (fake event)
 * @ioa: per adapter object
 *
 * Return nothing.
 */
void
hst2dr_port_enable_complete(struct HST2DR_ADAPTER *ioa)
{
	struct fw_event_work *fw_event;

	fw_event = alloc_fw_event_work(0);
	if (!fw_event)
		return;
	fw_event->event = HST2DR_PORT_ENABLE_COMPLETE;
	fw_event->ioa = ioa;
	_hst2dr_fw_event_add(ioa, fw_event);
	fw_event_work_put(fw_event);
}

static struct fw_event_work *dequeue_next_fw_event(struct HST2DR_ADAPTER *ioa)
{
	unsigned long flags;
	struct fw_event_work *fw_event = NULL;

	spin_lock_irqsave(&ioa->fw_event_lock, flags);
	if (!list_empty(&ioa->fw_event_list)) {
		fw_event = list_first_entry(&ioa->fw_event_list,
				struct fw_event_work, list);
		list_del_init(&fw_event->list);
		fw_event_work_put(fw_event);
	}
	spin_unlock_irqrestore(&ioa->fw_event_lock, flags);

	return fw_event;
}

/**
 * _hst2dr_fw_event_cleanup_queue - cleanup event queue
 * @ioa: per adapter object
 *
 * Walk the firmware event queue, either killing timers, or waiting
 * for outstanding events to complete
 *
 * Return nothing.
 */
static void
_hst2dr_fw_event_cleanup_queue(struct HST2DR_ADAPTER *ioa)
{
	struct fw_event_work *fw_event;

	if ((list_empty(&ioa->fw_event_list) && !ioa->current_event) ||
			!ioa->firmware_event_work_queue || in_interrupt())
		return;
	if (ioa->current_event)
		ioa->current_event->ignore = 1;

	log_reset(ioa, "%s\n", __func__);
	while ((fw_event = dequeue_next_fw_event(ioa))) {
		/*
		 * Wait on the fw_event to complete. If this returns 1, then
		 * the event was never executed, and we need a put for the
		 * reference the work had on the fw_event.
		 *
		 * If it did execute, we wait for it to finish, and the put will
		 * happen from _firmware_event_work()
		 */

		if (fw_event == ioa->current_event)
			continue;
		if (cancel_work_sync(&fw_event->work))
			fw_event_work_put(fw_event);

		fw_event_work_put(fw_event);
	}
}

/**
 * _hst2dr_internal_device_block - block the sdev device
 * @sdev: per device object
 * @sas_device_priv_data : per device driver private data
 *
 * make sure device is blocked without error, if not
 * print an error
 */
static void
_hst2dr_internal_device_block(struct scsi_device *sdev,
			struct HST2DR_DEVICE *sas_device_priv_data)
{
	int r = 0;

	sdev_printk(KERN_INFO, sdev, "device_block, handle(0x%04x)\n",
		sas_device_priv_data->sas_target->handle);
	sas_device_priv_data->block = 1;

	r = scsi_internal_device_block_nowait(sdev);
	if (r == -EINVAL)
		sdev_printk(KERN_WARNING, sdev,
			"device_block failed with return(%d) for handle(0x%04x)\n",
			r, sas_device_priv_data->sas_target->handle);
}

/**
 * _hst2dr_internal_device_unblock - unblock the sdev device
 * @sdev: per device object
 * @sas_device_priv_data : per device driver private data
 * make sure device is unblocked without error, if not retry
 * by blocking and then unblocking
 */

static void
_hst2dr_internal_device_unblock(struct scsi_device *sdev,
			struct HST2DR_DEVICE *sas_device_priv_data)
{
	int r = 0;

	sdev_printk(KERN_WARNING, sdev, "%s, handle(0x%04x)\n",
		"device_unblock and setting to running",
		sas_device_priv_data->sas_target->handle);
	sas_device_priv_data->block = 0;
	r = scsi_internal_device_unblock_nowait(sdev, SDEV_RUNNING);
	if (r == -EINVAL) {
		/* The device has been set to SDEV_RUNNING by SD layer during
		 * device addition but the request queue is still stopped by
		 * our earlier block call. We need to perform a block again
		 * to get the device to SDEV_BLOCK and then to SDEV_RUNNING
		 */

		sdev_printk(KERN_WARNING, sdev,
			"%s(%d) for handle(0x%04x) %s\n",
			"device_unblock failed with return",
			r, sas_device_priv_data->sas_target->handle,
			"performing a block followed by an unblock");
		sas_device_priv_data->block = 1;
		r = scsi_internal_device_block_nowait(sdev);
		if (r)
			sdev_printk(KERN_WARNING, sdev,
				"%s(%d) for handle(0x%04x)\n",
				"retried device_block failed with return",
				r, sas_device_priv_data->sas_target->handle);

		sas_device_priv_data->block = 0;
		r = scsi_internal_device_unblock_nowait(sdev, SDEV_RUNNING);
		if (r)
			sdev_printk(KERN_WARNING, sdev,
				"%s(%d) for handle(0x%04x)\n",
				"retried device_unblock failed with return",
				r, sas_device_priv_data->sas_target->handle);
	}
}

/**
 * _hst2dr_unblock_io_all_device - unblock every device
 * @ioa: per adapter object
 *
 * change the device state from block to running
 */
static void
_hst2dr_unblock_io_all_device(struct HST2DR_ADAPTER *ioa)
{
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;

	shost_for_each_device(sdev, ioa->shost) {
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data)
			continue;
		if (!sas_device_priv_data->block)
			continue;

		sdev_printk(KERN_INFO, sdev,
			"device_running, handle(0x%04x)\n",
			sas_device_priv_data->sas_target->handle);
		_hst2dr_internal_device_unblock(sdev, sas_device_priv_data);
	}
}

void hst2dr_unblock_io_all_device(struct HST2DR_ADAPTER *ioa)
{
	_hst2dr_unblock_io_all_device(ioa);
}


/**
 * _hst2dr_unblock_io_device - prepare device to be deleted
 * @ioa: per adapter object
 * @sas_addr: sas address
 *
 * unblock then put device in offline state
 */
static void
_hst2dr_unblock_io_device(struct HST2DR_ADAPTER *ioa, u64 sas_address)
{
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;

	shost_for_each_device(sdev, ioa->shost) {
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data)
			continue;
		if (sas_device_priv_data->sas_target->sas_address
				!= sas_address)
			continue;
		if (sas_device_priv_data->block)
			_hst2dr_internal_device_unblock(sdev,
				sas_device_priv_data);
	}
}

/**
 * _hst2dr_block_io_all_device - set the device state to SDEV_BLOCK
 * @ioa: per adapter object
 * @handle: device handle
 *
 * During device pull we need to appropriately set the sdev state.
 */
static void
_hst2dr_block_io_all_device(struct HST2DR_ADAPTER *ioa)
{
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;

	shost_for_each_device(sdev, ioa->shost) {
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data)
			continue;
		if (sas_device_priv_data->block)
			continue;
		if (sas_device_priv_data->ignore_delay_remove) {
			sdev_printk(KERN_INFO, sdev,
			"%s skip device_block for SES handle(0x%04x)\n",
			__func__, sas_device_priv_data->sas_target->handle);
			continue;
		}
		_hst2dr_internal_device_block(sdev, sas_device_priv_data);
	}
}

int _hst2dr_get_device_is_block(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;

	shost_for_each_device(sdev, ioa->shost) {
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data)
			continue;
		if (sas_device_priv_data->sas_target->handle != handle)
			continue;
		if (sas_device_priv_data->block)
			return 1;
	}

	return 0;
}

/**
 * _hst2dr_block_io_device - set the device state to SDEV_BLOCK
 * @ioa: per adapter object
 * @handle: device handle
 *
 * During device pull we need to appropriately set the sdev state.
 */
static void
_hst2dr_block_io_device(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;
	struct _sas_device *sas_device;

	sas_device = hst2dr_get_sdev_by_handle(ioa, handle);
	if (!sas_device)
		return;

	shost_for_each_device(sdev, ioa->shost) {
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data)
			continue;
		if (sas_device_priv_data->sas_target->handle != handle)
			continue;
		if (sas_device_priv_data->block)
			continue;
		if (sas_device && sas_device->pend_sas_rphy_add)
			continue;
		if (sas_device_priv_data->ignore_delay_remove) {
			sdev_printk(KERN_INFO, sdev,
			"%s skip device_block for SES handle(0x%04x)\n",
			__func__, sas_device_priv_data->sas_target->handle);
			continue;
		}
		_hst2dr_internal_device_block(sdev, sas_device_priv_data);
	}

	sas_device_put(sas_device);
}

/**
 * _hst2dr_block_io_to_children_attached_to_ex
 * @ioa: per adapter object
 * @sas_expander: the sas_device object
 *
 * This routine set sdev state to SDEV_BLOCK for all devices
 * attached to this expander. This function called when expander is
 * pulled.
 */
static void
_hst2dr_block_io_to_children_attached_to_ex(struct HST2DR_ADAPTER *ioa,
	struct _sas_node *sas_expander)
{
	struct _sas_port *hst2dr_port;
	struct _sas_device *sas_device;
	struct _sas_node *expander_sibling;
	unsigned long flags;

	if (!sas_expander)
		return;

	list_for_each_entry(hst2dr_port,
			&sas_expander->sas_port_list, port_list) {
		if (hst2dr_port->remote_identify.device_type ==
				SAS_END_DEVICE) {
			spin_lock_irqsave(&ioa->sas_device_lock, flags);
			sas_device = __hst2dr_get_sdev_by_addr(ioa,
				hst2dr_port->remote_identify.sas_address);
			if (sas_device) {
				set_bit(sas_device->handle,
						ioa->blocking_handles);
				sas_device_put(sas_device);
			}
			spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
		}
	}

	list_for_each_entry(hst2dr_port,
			&sas_expander->sas_port_list, port_list) {

		if (hst2dr_port->remote_identify.device_type ==
				SAS_EDGE_EXPANDER_DEVICE ||
				hst2dr_port->remote_identify.device_type ==
				SAS_FANOUT_EXPANDER_DEVICE) {
			expander_sibling =
				hst2dr_expander_find_by_sas_address(
				ioa, hst2dr_port->remote_identify.sas_address);
			_hst2dr_block_io_to_children_attached_to_ex(ioa,
				expander_sibling);
		}
	}
}

/**
 * _hst2dr_block_io_to_children_attached_directly
 * @ioa: per adapter object
 * @event_data: topology change event data
 *
 * This routine set sdev state to SDEV_BLOCK for all devices
 * direct attached during device pull.
 */
static void
_hst2dr_block_io_to_children_attached_directly(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST *event_data)
{
	int i;
	u16 handle;
	u16 reason_code;

	for (i = 0; i < event_data->num_entries; i++) {
		handle = le16_to_cpu(event_data->phy[i].attached_dev_handle);
		if (!handle)
			continue;
		reason_code = event_data->phy[i].phy_status &
			SSI2_EVENT_SAS_TOPO_RC_MASK;
		if (reason_code == SSI2_EVENT_SAS_TOPO_RC_DELAY_NOT_RESPONDING)
			_hst2dr_block_io_device(ioa, handle);
	}
}

/**
 * _hst2dr_tr_send - link reset send
 * @ioa: per adapter object
 * @handle: device handle
 * @sendflag: is need send link reset, 1: send, 0: not send
 * Context: interrupt time.
 *
 * This code will issue link reset.
 *
 * This is designed to send muliple link reset at the same
 * time to the fifo. If the fifo is full, we will append the request,
 * and process it in a future completion.
 */
static void
_hst2dr_tr_send(struct HST2DR_ADAPTER *ioa, u16 handle, u8 sendflag)
{
	SSI2_SCSI_TM_REQUEST *ssi_request;
	u16 host_tag_id;
	struct _sas_device *sas_device = NULL;
	struct HST2DR_TARGET *sas_target_priv_data = NULL;
	u64 sas_address = 0;
	unsigned long flags;
	struct _tr_list *delayed_tr;
	u32 ioa_state;
	u8 tr_method = 0;
	hst2dr_command *scmd;

	if (ioa->remove_host)
		return;
	else if (ioa->pci_error_recovery)
		return;

	ioa_state = hst2dr_base_get_ioastate(ioa, 1);
	if (ioa_state != SSI2_IOA_STATE_OPERATIONAL)
		return;

	if (test_bit(handle, ioa->pd_handles))
		return;

	clear_bit(handle, ioa->pend_os_device_add);

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_handle(ioa, handle);
	if (sas_device && sas_device->starget &&
			sas_device->starget->hostdata) {
		sas_target_priv_data = sas_device->starget->hostdata;
		sas_target_priv_data->deleted = 1;
		sas_address = sas_device->sas_address;
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	if (sas_target_priv_data) {
		log_comm(ioa,
			"setting delete flag: handle(0x%04x), sas_addr(0x%016llx)\n",
			handle,
			(unsigned long long)sas_address);
		if (sas_device) {
			if (sas_device->enclosure_handle != 0)
				log_comm(ioa,
					"setting delete flag:enclosure logical id(0x%016llx), slot(%d)\n",
					(u64)sas_device->enclosure_logical_id,
					sas_device->slot);
			if (sas_device->connector_name[0] != '\0')
				log_comm(ioa,
					"setting delete flag: enclosure level(0x%04x), connector name( %s)\n",
					sas_device->enclosure_level,
					sas_device->connector_name);
		}
		_hst2dr_unblock_io_device(ioa, sas_address);
		sas_target_priv_data->handle = HST2DR_INVALID_DEVICE_HANDLE;
	}
	if (sendflag == 0)
		goto out;
	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->tr_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		delayed_tr = kzalloc(sizeof(*delayed_tr), GFP_ATOMIC);
		if (!delayed_tr)
			goto out;
		INIT_LIST_HEAD(&delayed_tr->list);
		delayed_tr->handle = handle;
		list_add_tail(&delayed_tr->list, &ioa->delayed_tr_list);
		log_comm(ioa, "DELAYED:tr:handle(0x%04x), (open)\n", handle);
		goto out;
	}

	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	ssi_request = (SSI2_SCSI_TM_REQUEST *)scmd;
	memset(ssi_request, 0, sizeof(SSI2_SCSI_TM_REQUEST));
	ssi_request->dev_handle = cpu_to_le16(handle);
	ssi_request->task_type = SSI2_SCSITASKMGMT_TASKTYPE_I_T_NEXUS_RESET;
	ssi_request->msg_flags = tr_method;
	set_bit(handle, ioa->device_remove_in_progress);


	scmd->cmd.internal.cmd.head.opcode = SSI2_FUNCTION_SCSI_TASK_MANAGE;
	scmd->cmd.internal.cmd.head.opflags =
		cmd_flag_fw_mode_admin | HI_PRIORITY;
	scmd->cmd.internal.cmd.head.host_tag_id = host_tag_id;
	scmd->cmd.internal.cmd.head.host_flag = hst2dr_cmd_tm;
	scmd->cmd.internal.cmd.head.request_flags =
		SSI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY;
	ioa->put_host_tag_id_default(ioa, scmd);

out:
	if (sas_device)
		sas_device_put(sas_device);
}

/**
 * _hst2dr_tr_done -
 * @ioa: per adapter object
 * @cqe: completion queue entity
 * Context: interrupt time.
 *
 * This is the link reset completion routine.
 * This code is part of the code to initiate the device removal
 * handshake protocol with controller firmware.
 * It will send a sas iounit control request (SSI2_SAS_OP_REMOVE_DEVICE)
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
static u8
_hst2dr_tr_done(struct HST2DR_ADAPTER *ioa,
	hst2dr_nvme_completion *cqe)
{
	SSI2_SCSI_TM_REPLY *ssi_reply = NULL;
	u32 ioa_state;
	u16 handle;

	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);

	if (ioa->remove_host)
		return 1;
	else if (ioa->pci_error_recovery)
		return 1;

	ioa_state = hst2dr_base_get_ioastate(ioa, 1);
	if (ioa_state != SSI2_IOA_STATE_OPERATIONAL)
		return 1;

	if (unlikely(!ssi_reply)) {
		log_error(ioa, "ssi_reply not valid at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}

	handle = le16_to_cpu(ssi_reply->dev_handle);
	clear_bit(handle, ioa->device_remove_in_progress);
	ioa->ioa_link_reset_in_progress = 0;

	return _hst2dr_check_for_pending_task(ioa, cqe->host_tag_id);
}
/**
 * hst2dr_issue_task_reset - issue link reset messages
 * @ioa: per adapter object
 * @handle: device handle
 *
 * Context - export link reset.
 */
int hst2dr_issue_task_reset(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	_hst2dr_tr_send(ioa, handle, 1);
	return 0;
}
/**
 * _hst2dr_tr_vol_send - send target reset request for volumes
 * @ioa: per adapter object
 * @handle: device handle
 * Context: interrupt time.
 *
 * This is designed to send muliple task management request at the same
 * time to the fifo. If the fifo is full, we will append the request,
 * and process it in a future completion.
 */
static void
_hst2dr_tr_vol_send(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	SSI2_SCSI_TM_REQUEST *ssi_request;
	u16 host_tag_id;
	struct _tr_list *delayed_tr;

	if (ioa->pci_error_recovery || ioa->remove_host ||
			ioa->pci_error_recovery) {
		log_tm(ioa, "%s: host reset in progress!\n", __func__);
		return;
	}

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->tr_vol_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		delayed_tr = kzalloc(sizeof(*delayed_tr), GFP_ATOMIC);
		if (!delayed_tr)
			return;
		INIT_LIST_HEAD(&delayed_tr->list);
		delayed_tr->handle = handle;
		list_add_tail(&delayed_tr->list, &ioa->delayed_tr_vol_list);
		log_tm(ioa, "DELAYED:tr:handle(0x%04x), (open)\n", handle);
		return;
	}

	log_tm(ioa, "tr_send:handle(0x%04x), (open), host_tag_id(%d), cb(%d)\n",
		handle, host_tag_id, ioa->tr_vol_cb_idx);


	ssi_request = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	memset(ssi_request, 0, sizeof(SSI2_SCSI_TM_REQUEST));
	ssi_request->opcode = SSI2_FUNCTION_SCSI_TASK_MANAGE;
	ssi_request->host_tag_id = host_tag_id;
	ssi_request->opflags = cmd_flag_fw_mode_admin | HI_PRIORITY;
	ssi_request->host_flag = hst2dr_cmd_tm;
	ssi_request->dev_handle = cpu_to_le16(handle);
	ssi_request->task_type = SSI2_SCSITASKMGMT_TASKTYPE_I_T_NEXUS_RESET;
	ssi_request->msg_flags = 0;
	ssi_request->request_flags = SSI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY;
	ioa->put_host_tag_id_default(ioa, ssi_request);
}

/**
 * _hst2dr_tr_vol_done - target reset completion
 * @ioa: per adapter object
 * @cqe: completion queue entity
 * Context: interrupt time.
 *
 * Return: 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
static u8
_hst2dr_tr_vol_done(struct HST2DR_ADAPTER *ioa,
	hst2dr_nvme_completion *cqe)
{
	u16 handle;
	u16 host_tag_id;
	SSI2_SCSI_TM_REQUEST *ssi_request_tm;
	SSI2_SCSI_TM_REPLY *ssi_reply =
		hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);
	host_tag_id = cqe->host_tag_id;

	if (ioa->shost_recovery || ioa->remove_host ||
			ioa->pci_error_recovery) {
		log_tm(ioa, "%s: host reset in progress!\n", __func__);
		return 1;
	}
	if (unlikely(!ssi_reply)) {
		log_fail(ioa, "mpi_reply not valid at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}

	ssi_request_tm = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	handle = le16_to_cpu(ssi_request_tm->dev_handle);
	if (handle != le16_to_cpu(ssi_reply->dev_handle)) {
		log_tm(ioa, "spurious interrupt: handle(0x%04x:0x%04x), host_tag_id(%d)!!!\n",
			handle, le16_to_cpu(ssi_reply->dev_handle),
			host_tag_id);
		return 0;
	}

	log_tm(ioa, "tr_complete:handle(0x%04x), (open) host_tag_id(%d), status(0x%04x), loginfo(0x%08x), completed(%d)\n",
			handle, host_tag_id, le16_to_cpu(ssi_reply->status),
			le32_to_cpu(ssi_reply->log_info),
			le32_to_cpu(ssi_reply->termination_count));

	return _hst2dr_check_for_pending_task(ioa, host_tag_id);
}

/**
 * _hst2dr_issue_delayed_event_ack - issue delayed Event ACK messages
 * @ioa: per adapter object
 * @host_tag_id: request message index
 * @event: Event ID
 * @event_context: used to track events uniquely
 *
 * Context - processed in interrupt context.
 */
static void
_hst2dr_issue_delayed_event_ack(struct HST2DR_ADAPTER *ioa,
	u16 host_tag_id, u16 event,
				u32 event_context)
{
	SSI2_EVENT_ACK_REQUEST *ack_request;
	int i = host_tag_id - ioa->internal_host_tag_id;
	unsigned long flags;
	hst2dr_command *scmd;

	/* Without releasing the host_tag_id just update the
	 * call back index and reuse the same host_tag_id for
	 * processing this delayed request
	 */
	spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
	ioa->internal_lookup[i].cb_idx = ioa->base_cb_idx;
	spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);

	ack_request = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	scmd = (hst2dr_command *)ack_request;
	memset(ack_request, 0, sizeof(SSI2_EVENT_ACK_REQUEST));
	ack_request->event = event;
	ack_request->event_context = event_context;

	scmd->cmd.internal.cmd.head.opcode = SSI2_FUNCTION_EVENT_ACK;
	scmd->cmd.internal.cmd.head.opflags = cmd_flag_fw_mode_admin;
	scmd->cmd.internal.cmd.head.host_tag_id = host_tag_id;
	scmd->cmd.internal.cmd.head.host_flag = hst2dr_cmd_scsih;

	ioa->put_host_tag_id_default(ioa, scmd);
}
/**
 * _hst2dr_check_for_pending_internal_cmds - check for pending internal messages
 * @ioa: per adapter object
 * @host_tag_id: request message index
 *
 * Context: Executed in interrupt context
 *
 * This will check delayed internal messages list, and process the
 * next request.
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
u8
hst2dr_check_for_pending_internal_cmds(struct HST2DR_ADAPTER *ioa,
	u16 host_tag_id)
{
	struct _event_ack_list *delayed_event_ack;

	if (!list_empty(&ioa->delayed_event_ack_list)) {
		delayed_event_ack = list_entry(ioa->delayed_event_ack_list.next,
						struct _event_ack_list, list);
		_hst2dr_issue_delayed_event_ack(ioa, host_tag_id,
			delayed_event_ack->event,
			delayed_event_ack->event_context);
		list_del_init(&delayed_event_ack->list);
		kfree(delayed_event_ack);
		return 0;
	}

	return 1;
}

/**
 * _hst2dr_check_for_pending_task - check for pending task
 * @ioa: per adapter object
 * @host_tag_id: request message index
 *
 * This will check delayed link reset list, and feed the
 * next request.
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
static u8
_hst2dr_check_for_pending_task(struct HST2DR_ADAPTER *ioa, u16 host_tag_id)
{
	struct _tr_list *delayed_tr;

	if (!list_empty(&ioa->delayed_tr_vol_list)) {
		delayed_tr = list_entry(ioa->delayed_tr_vol_list.next,
			struct _tr_list, list);
		hst2dr_base_free_host_tag_id(ioa, host_tag_id);
		_hst2dr_tr_vol_send(ioa, delayed_tr->handle);
		list_del_init(&delayed_tr->list);
		kfree(delayed_tr);
		return 0;
	}

	if (!list_empty(&ioa->delayed_tr_list)) {
		delayed_tr = list_entry(ioa->delayed_tr_list.next,
			struct _tr_list, list);
		hst2dr_base_free_host_tag_id(ioa, host_tag_id);
		_hst2dr_tr_send(ioa, delayed_tr->handle, 1);
		list_del_init(&delayed_tr->list);
		kfree(delayed_tr);
		return 0;
	}

	return 1;
}


/**
 * _hst2dr_check_topo_delete_events - sanity check on topo events
 * @ioa: per adapter object
 * @event_data: the event data payload
 *
 * This routine added to better handle cable breaker.
 *
 * This handles the case where driver receives multiple expander
 * add and delete events in a single shot.  When there is a delete event
 * the routine will void any pending add events waiting in the event queue.
 *
 * Return nothing.
 */
static void
_hst2dr_check_topo_delete_events(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST *event_data)
{
	struct fw_event_work *fw_event;
	SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST *local_event_data;
	u16 expander_handle;
	struct _sas_node *sas_expander;
	unsigned long flags;
	int i, reason_code;
	u16 handle;

	for (i = 0 ; i < event_data->num_entries; i++) {
		handle = le16_to_cpu(event_data->phy[i].attached_dev_handle);
		if (!handle)
			continue;
		reason_code = event_data->phy[i].phy_status &
			SSI2_EVENT_SAS_TOPO_RC_MASK;
		if (reason_code == SSI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING)
			_hst2dr_tr_send(ioa, handle, 0);

	}

	expander_handle = le16_to_cpu(event_data->expander_dev_handle);
	if (expander_handle < ioa->sas_hba.num_phys) {
		_hst2dr_block_io_to_children_attached_directly(ioa, event_data);
		return;
	}
	if (event_data->exp_status ==
			SSI2_EVENT_SAS_TOPO_ES_DELAY_NOT_RESPONDING) {
		/* put expander attached devices into blocking state */
		spin_lock_irqsave(&ioa->sas_node_lock, flags);
		sas_expander = hst2dr_expander_find_by_handle(ioa,
			expander_handle);
		_hst2dr_block_io_to_children_attached_to_ex(ioa, sas_expander);
		spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
		do {
			handle = find_first_bit(ioa->blocking_handles,
				ioa->info.max_dev_handle);
			if (handle < ioa->info.max_dev_handle)
				_hst2dr_block_io_device(ioa, handle);
			else
				break;
		} while (test_and_clear_bit(handle, ioa->blocking_handles));
	} else if (event_data->exp_status == SSI2_EVENT_SAS_TOPO_ES_RESPONDING)
		_hst2dr_block_io_to_children_attached_directly(ioa, event_data);

	if (event_data->exp_status != SSI2_EVENT_SAS_TOPO_ES_NOT_RESPONDING)
		return;

	/* mark ignore flag for pending events */
	spin_lock_irqsave(&ioa->fw_event_lock, flags);
	list_for_each_entry(fw_event, &ioa->fw_event_list, list) {
		if (fw_event->event != SSI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST ||
				fw_event->ignore)
			continue;
		local_event_data = (SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST *)
				fw_event->event_data;
		if (local_event_data->exp_status ==
				SSI2_EVENT_SAS_TOPO_ES_ADDED ||
				local_event_data->exp_status ==
				SSI2_EVENT_SAS_TOPO_ES_RESPONDING) {
			if ((le16_to_cpu(local_event_data->expander_dev_handle)
					== expander_handle)
					&& (local_event_data->num_entries ==
					event_data->num_entries)
					&& (local_event_data->start_phy_num ==
					event_data->start_phy_num)) {
				fw_event->ignore = 1;
			}
		}
	}
	spin_unlock_irqrestore(&ioa->fw_event_lock, flags);
}

/**
 * _hst2dr_set_volume_delete_flag - setting volume delete flag
 * @ioa: per adapter object
 * @handle: device handle
 *
 * This returns nothing.
 */
static void
_hst2dr_set_volume_delete_flag(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _raid_device *raid_device;
	struct HST2DR_TARGET *sas_target_priv_data;
	unsigned long flags;

	spin_lock_irqsave(&ioa->raid_device_lock, flags);
	raid_device = _hst2dr_raid_device_find_by_handle(ioa, handle);
	if (raid_device && raid_device->starget &&
		raid_device->starget->hostdata) {
		sas_target_priv_data =
			raid_device->starget->hostdata;
		sas_target_priv_data->deleted = 1;
			log_event(ioa, "setting delete flag: handle(0x%04x), wwid(0x%016llx)\n",
				handle, (u64)raid_device->wwid);
	}
	spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
}

/**
 * _hst2dr_set_volume_block_flag - setting volume block flag
 * @ioa: per adapter object
 * @handle: device handle
 *
 * This returns nothing.
 */
static void
_hst2dr_set_volume_block_flag(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _raid_device *raid_device;
	struct HST2DR_TARGET *sas_target_priv_data;
	unsigned long flags;
	int r;

	spin_lock_irqsave(&ioa->raid_device_lock, flags);
	raid_device = _hst2dr_raid_device_find_by_handle(ioa, handle);
	if (raid_device && raid_device->starget &&
			raid_device->starget->hostdata) {
		sas_target_priv_data =
			raid_device->starget->hostdata;
		if (sas_target_priv_data->block == 0) {
			r = scsi_internal_device_block_nowait(raid_device->sdev);
			if (r == -EINVAL) {
				sdev_printk(KERN_WARNING, raid_device->sdev,
			"device_block failed with return(%d) for handle(0x%04x)\n", r, handle);
			} else {
				sas_target_priv_data->block = 1;
				log_event(ioa, "setting block flag: handle(0x%04x), wwid(0x%016llx)\n",
					handle, (u64)raid_device->wwid);
			}
		}
	}
	spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
}
/**
 * _hst2dr_set_volume_unblock_flag - setting volume unblock flag
 * @ioa: per adapter object
 * @handle: device handle
 *
 * This returns nothing.
 */
static void
_hst2dr_set_volume_unblock_flag(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _raid_device *raid_device;
	struct HST2DR_TARGET *sas_target_priv_data;
	unsigned long flags;
	int r;

	spin_lock_irqsave(&ioa->raid_device_lock, flags);
	raid_device = _hst2dr_raid_device_find_by_handle(ioa, handle);
	if (raid_device && raid_device->starget &&
			raid_device->starget->hostdata) {
		sas_target_priv_data =
			raid_device->starget->hostdata;
		if (sas_target_priv_data->block == 1) {
			r = scsi_internal_device_unblock_nowait(
				raid_device->sdev, SDEV_RUNNING);
			if (r == -EINVAL) {
				/* The device has been set to SDEV_RUNNING by SD layer during
				 * device addition but the request queue is still stopped by
				 * our earlier block call. We need to perform a block again
				 * to get the device to SDEV_BLOCK and then to SDEV_RUNNING
				 */

				sdev_printk(KERN_WARNING, raid_device->sdev,
					"%s(%d) for handle(0x%04x) ",
					"device_unblock failed with return",
					r, handle);
			} else {
				sas_target_priv_data->block = 0;
				log_event(ioa, "%s(0x%04x), wwid(0x%016llx)\n",
					"setting unblock flag: handle",
					handle, (u64)raid_device->wwid);
			}
		}
	}
	spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
}
/**
 * _hst2dr_check_ir_config_unhide_events - check for UNHIDE events
 * @ioa: per adapter object
 * @event_data: the event data payload
 * Context: interrupt time.
 *
 * This routine will send target reset to volume, followed by target
 * resets to the PDs. This is called when a PD has been removed, or
 * volume has been deleted or removed. When the target reset is sent
 * to volume, the PD target resets need to be queued to start upon
 * completion of the volume target reset.
 */
static void
_hst2dr_check_ir_config_unhide_events(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_IR_CONFIG_CHANGE_LIST *event_data)
{
	SSI2_EVENT_IR_CONFIG_ELEMENT *element;
	int i;
	u16 volume_handle;


	/* Volume Resets for Deleted or Removed */
	element = (SSI2_EVENT_IR_CONFIG_ELEMENT *)
		&event_data->config_element[0];
	for (i = 0; i < event_data->num_elements; i++, element++) {
		if (le32_to_cpu(event_data->flags) &
				SSI2_EVENT_IR_CHANGE_FLAGS_FOREIGN_CONFIG)
			continue;
		if (element->reason_code ==
				SSI2_EVENT_IR_CHANGE_RC_VOLUME_DELETED ||
				element->reason_code ==
				SSI2_EVENT_IR_CHANGE_RC_REMOVED) {
			volume_handle = le16_to_cpu(element->vol_dev_handle);
			_hst2dr_set_volume_delete_flag(ioa, volume_handle);
		}
	}

}


/**
 * _hst2dr_check_volume_delete_events - set delete flag for volumes
 * @ioa: per adapter object
 * @event_data: the event data payload
 * Context: interrupt time.
 *
 * This will handle the case when the cable connected to entire volume is
 * pulled. We will take care of setting the deleted flag so normal IO will
 * not be sent.
 */
static void
_hst2dr_check_volume_delete_events(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_IR_VOLUME *event_data)
{
	u32 state;

	if (event_data->reason_code != SSI2_EVENT_IR_VOLUME_RC_STATE_CHANGED)
		return;
	state = le32_to_cpu(event_data->new_value);
	if (state == SSI2_RAID_VOL_STATE_MISSING || state ==
			SSI2_RAID_VOL_STATE_FAILED)
		_hst2dr_set_volume_delete_flag(ioa,
			le16_to_cpu(event_data->vol_dev_handle));
	else if (state == SSI2_RAID_VOL_STATE_DELAY)
		_hst2dr_set_volume_block_flag(ioa,
			le16_to_cpu(event_data->vol_dev_handle));

}

/**
 * _hst2dr_flush_running_cmds - completing outstanding commands.
 * @ioa: per adapter object
 *
 * The flushing out of all pending scmd commands following host reset,
 * where all IO is dropped to the floor.
 *
 * Return nothing.
 */
static void
_hst2dr_flush_running_cmds(struct HST2DR_ADAPTER *ioa)
{
	struct scsi_cmnd *scmd;
	u16 host_tag_id;
	u16 count = 0;
	struct scsiio_tracker *st;

	for (host_tag_id = 0; host_tag_id < ioa->scsiio_depth; host_tag_id++) {
		scmd = _hst2dr_scsi_lookup_get(ioa, host_tag_id);
		if (!scmd)
			continue;
		st = scsi_cmd_priv(scmd);
		if (!st || st->host_tag_id == NO_HOST_TAG_ID ||
				st->direct_io != MAGIC_NUMBER)
			continue;
		count++;
		hst2dr_base_clear_st(ioa, st);
		scsi_dma_unmap(scmd);
		if (ioa->pci_error_recovery || ioa->remove_host)
			scmd->result = DID_NO_CONNECT << 16;
		else
			scmd->result = DID_RESET << 16;
		scsi_done(scmd);
	}
	log_debug(ioa,  "completing %d cmds\n", count);
}

/**
 * _hst2dr_setup_eedp - setup SSI request for EEDP transfer
 * @ioa: per adapter object
 * @scmd: pointer to scsi command object
 * @ssi_request: pointer to the SCSI_IO request message frame
 *
 * Supporting protection 1 and 3.
 *
 * Returns nothing
 */
static void
_hst2dr_setup_eedp(struct HST2DR_ADAPTER *ioa, struct scsi_cmnd *scmd,
	SSI2_SCSI_REQUEST *ssi_request)
{
	u16 eedp_flags;
	unsigned char prot_op = scsi_get_prot_op(scmd);
	unsigned char prot_type = scsi_get_prot_type(scmd);

	if (prot_type == SCSI_PROT_DIF_TYPE0 || prot_op == SCSI_PROT_NORMAL)
		return;

	if (prot_op ==  SCSI_PROT_READ_STRIP)
		eedp_flags = SSI2_SCSIIO_EEDPFLAGS_CHECK_REMOVE_OP;
	else if (prot_op ==  SCSI_PROT_WRITE_INSERT)
		eedp_flags = SSI2_SCSIIO_EEDPFLAGS_INSERT_OP;
	else
		return;

	switch (prot_type) {
	case SCSI_PROT_DIF_TYPE1:
	case SCSI_PROT_DIF_TYPE2:

		/*
		 * enable ref/guard checking
		 * auto increment ref tag
		 */
		eedp_flags |= SSI2_SCSIIO_EEDPFLAGS_INC_PRI_REFTAG |
			SSI2_SCSIIO_EEDPFLAGS_CHECK_REFTAG |
			SSI2_SCSIIO_EEDPFLAGS_CHECK_GUARD;
		ssi_request->cdb.eedp.primary_ref =
			cpu_to_be32(scsi_get_lba(scmd));
		break;

	case SCSI_PROT_DIF_TYPE3:

		/*
		 * enable guard checking
		 */
		eedp_flags |= SSI2_SCSIIO_EEDPFLAGS_CHECK_GUARD;

		break;
	}
	eedp_flags |= SSI2_SCSIIO_EEDPFLAGS_APPTAG_DISABLE_MODE;
	ssi_request->eedp_flags = cpu_to_le16(eedp_flags);
}

/**
 * _hst2dr_eedp_error_handling - return sense code for EEDP errors
 * @scmd: pointer to scsi command object
 * @ioa_status: ioa status
 *
 * Returns nothing
 */
static void
_hst2dr_eedp_error_handling(struct scsi_cmnd *scmd, u16 ioa_status)
{
	u8 ascq;

	switch (ioa_status) {
	case SSI2_IOASTATUS_EEDP_GUARD_ERROR:
		ascq = 0x01;
		break;
	case SSI2_IOASTATUS_EEDP_APP_TAG_ERROR:
		ascq = 0x02;
		break;
	case SSI2_IOASTATUS_EEDP_REF_TAG_ERROR:
		ascq = 0x03;
		break;
	default:
		ascq = 0x00;
		break;
	}
	scsi_build_sense_buffer(0, scmd->sense_buffer, ILLEGAL_REQUEST, 0x10,
		ascq);
	scmd->result = DRIVER_SENSE << 24 | (DID_ABORT << 16) |
		SAM_STAT_CHECK_CONDITION;
}

/**
 * hst2dr_qcmd - main scsi request entry point
 * @scmd: pointer to scsi command object
 * @done: function pointer to be invoked on completion
 *
 * The callback index is set inside `ioa->scsi_io_cb_idx`.
 *
 * Returns 0 on success.  If there's a failure, return either:
 * SCSI_MLQUEUE_DEVICE_BUSY if the device queue is full, or
 * SCSI_MLQUEUE_HOST_BUSY if the entire host queue is full
 */
static int
hst2dr_qcmd(struct Scsi_Host *shost, struct scsi_cmnd *scmd)
{
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct HST2DR_TARGET *sas_target_priv_data;
	SSI2_SCSI_REQUEST *ssi_request;
	struct request *rq;
	u32 ssi_control;
	u16 port_protocols;
	u16 host_tag_id;
	u16 handle;
	int status;
	int class;

	rq = scsi_cmd_to_rq(scmd);

	sas_device_priv_data = scmd->device->hostdata;
	if (!sas_device_priv_data || !sas_device_priv_data->sas_target) {
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		return 0;
	}

	if (ioa->pci_error_recovery || ioa->remove_host) {
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		return 0;
	}


	sas_target_priv_data = sas_device_priv_data->sas_target;

	/* invalid device handle */
	handle = sas_target_priv_data->handle;
	if (handle == HST2DR_INVALID_DEVICE_HANDLE) {
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		return 0;
	}


	/* host recovery or link resets sent via IOCTLs */
	if (ioa->shost_recovery || ioa->ioa_link_reset_in_progress ||
			ioa->ioa_reset_in_progress)
		return SCSI_MLQUEUE_HOST_BUSY;

	/* device has been deleted */
	else if (sas_target_priv_data->deleted) {
		scmd->result = DID_NO_CONNECT << 16;
		scsi_done(scmd);
		return 0;
	/* device busy with task management */
	} else if (sas_target_priv_data->tm_busy ||
		sas_device_priv_data->block || sas_target_priv_data->block)
		return SCSI_MLQUEUE_DEVICE_BUSY;

	if (scmd->sc_data_direction == DMA_FROM_DEVICE)
		ssi_control = SSI2_SCSIIO_CONTROL_READ;
	else if (scmd->sc_data_direction == DMA_TO_DEVICE)
		ssi_control = SSI2_SCSIIO_CONTROL_WRITE;
	else if (scmd->sc_data_direction == DMA_NONE)
		ssi_control = SSI2_SCSIIO_CONTROL_NODATATRANSFER;
	else
		ssi_control = SSI2_SCSIIO_CONTROL_READ |
			SSI2_SCSIIO_CONTROL_WRITE;

	/* set tags */
	ssi_control |= SSI2_SCSIIO_CONTROL_SIMPLEQ;

	host_tag_id = hst2dr_base_get_host_tag_id_scsiio(ioa,
		ioa->scsi_io_cb_idx, scmd);
	if (host_tag_id == NO_HOST_TAG_ID)
		goto out;

	ssi_request = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	memset(ssi_request, 0, sizeof(SSI2_SCSI_REQUEST));
	_hst2dr_setup_eedp(ioa, scmd, ssi_request);
	ssi_request->block_size = cpu_to_le16(scmd->device->sector_size);

	if (scmd->cmd_len == 32)
		ssi_control |= 4 << SSI2_SCSIIO_CONTROL_ADDCDBLEN_SHIFT;
	if (!ioa->ir_firmware) {
		ssi_request->opcode = SSI2_FUNCTION_SCSI_IO;
	} else {
		if (sas_device_priv_data->sas_target->flags &
				HST2DR_TARGET_FLAGS_VOLUME)
			ssi_request->opcode = SSI2_FUNCTION_SCSI_IO;
		else
			ssi_request->opcode =
				SSI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH;
	}
	if (sas_device_priv_data->ncq_prio_enable) {
		class = IOPRIO_PRIO_CLASS(req_get_ioprio(rq));
		if (class == IOPRIO_CLASS_RT)
			ssi_control |= SSI2_SCSIIO_CONTROL_HIGH_PRIORITY;
	}
	if (sas_target_priv_data->device_info != 0)
		port_protocols = ((sas_target_priv_data->device_info >> 7) &
			0xffff);
	else
		port_protocols = 0x08;

	if (port_protocols & 0x100) //SAGE_VSES
		ssi_request->opflags = cmd_flag_fw_mode_io;
	if (scmd->cmd_len <= 16)
		ssi_request->host_cmd_flags.cdb_flag = 0;
	else if (scmd->cmd_len <= 32)
		ssi_request->host_cmd_flags.cdb_flag = 1;
	else {
		ssi_request->host_cmd_flags.cdb_flag = 2;
		ssi_request->opflags = cmd_flag_fw_mode_io;
	}

	if (ssi_control & SSI2_SCSIIO_CONTROL_HIGH_PRIORITY)
		ssi_request->opflags |= cmd_flag_high_priority;
	if (port_protocols & 0x01) //SATA DEVICE
		ssi_request->opflags |= (2 << 5);
	else if (port_protocols & 0x08) //SSP
		ssi_request->opflags |= (1 << 5);

	if (ssi_control & SSI2_SCSIIO_CONTROL_READ) {
		if (ssi_control & SSI2_SCSIIO_CONTROL_WRITE)
			ssi_request->host_cmd_flags.dma_dir_flag = 3;
		else
			ssi_request->host_cmd_flags.dma_dir_flag = 2;
	} else if (ssi_control & SSI2_SCSIIO_CONTROL_WRITE)
		ssi_request->host_cmd_flags.dma_dir_flag = 1;
	else
		ssi_request->host_cmd_flags.dma_dir_flag = 0;

	ssi_request->control_flag = ((ssi_control >> 8) & 7);
	ssi_request->control_addition = (ssi_control >> 24) & 0xfc;

	ssi_request->logical_dev_id = cpu_to_le16(handle);
	ssi_request->data_len = cpu_to_le32(scsi_bufflen(scmd));
	ssi_request->cdb_len =  cpu_to_le16(scmd->cmd_len);

	if (ssi_request->cdb_len <= 16)
		ssi_request->host_cmd_flags.cdb_flag = 0;
	else if (ssi_request->cdb_len <= 32)
		ssi_request->host_cmd_flags.cdb_flag = 1;
	else {
		ssi_request->host_cmd_flags.cdb_flag = 2;
		ssi_request->opflags = cmd_flag_fw_mode_io;
	}

	/*the cmd len include cdb, control, lun */
	if (ssi_request->cdb_len <= 16)
		ssi_request->cdb_len = 0x1c;
	else
		ssi_request->cdb_len = 0x2c;
	int_to_scsilun(sas_device_priv_data->lun, (struct scsi_lun *)
		ssi_request->lun);
	memcpy(ssi_request->cdb.cdb, scmd->cmnd, scmd->cmd_len);

	if ((ssi_request->cdb.cdb[0] == 0xa1) ||
			(ssi_request->cdb.cdb[0] == 0x85)) {
		if (ssi_control & SSI2_SCSIIO_CONTROL_READ)
			log_debug(ioa,
				"\tata passthrough (%x) dma dir READ change to NON data\n",
				ssi_request->cdb.cdb[0]);
		else if (ssi_control & SSI2_SCSIIO_CONTROL_WRITE)
			log_debug(ioa,
				"\tata passthrough (%x) dma dir WRITE change to NON data\n",
				ssi_request->cdb.cdb[0]);
	}

	if (ssi_request->data_len) {
		if (ioa->build_sg_scmd(ioa, scmd, host_tag_id)) {
			log_fail(ioa, "build_sg_scmd fail!\n");
			hst2dr_base_free_host_tag_id(ioa, host_tag_id);
			goto out;
		}
	} else
		ioa->build_zero_len_sge(ioa, &ssi_request->sgl);

	if (likely((ssi_request->opcode == SSI2_FUNCTION_SCSI_IO) ||
			(ssi_request->opcode ==
			SSI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH))) {
		if ((sas_target_priv_data->flags &
				HST2DR_TARGET_FLAGS_VOLUME) ==
				HST2DR_TARGET_FLAGS_VOLUME &&
				ioa->ir_firmware) {
			hst2dr_build_scsiio_cmd_force_fw_mode_api(ioa,
				ssi_request, host_tag_id);
		} else {
			hst2dr_build_scsiio_cmd_api(ioa, ssi_request,
				host_tag_id);
		}
		status = ioa->put_host_tag_id_default(ioa, ssi_request);
		if (status != 0) {
			hst2dr_base_free_host_tag_id(ioa, host_tag_id);
			goto out;
		}
	}
	return 0;

 out:
	return SCSI_MLQUEUE_HOST_BUSY;
}

/**
 * _hst2dr_normalize_sense - normalize descriptor and fixed format sense data
 * @sense_buffer: sense data returned by target
 * @data: normalized skey/asc/ascq
 *
 * Return nothing.
 */
static void
_hst2dr_normalize_sense(char *sense_buffer, struct sense_info *data)
{
	if ((sense_buffer[0] & 0x7F) >= 0x72) {
		/* descriptor format */
		data->skey = sense_buffer[1] & 0x0F;
		data->asc = sense_buffer[2];
		data->ascq = sense_buffer[3];
	} else {
		/* fixed format */
		data->skey = sense_buffer[2] & 0x0F;
		data->asc = sense_buffer[12];
		data->ascq = sense_buffer[13];
	}
}

/**
 * _hst2dr_scsi_ioa_info - translated non-succesfull SCSI_IO request
 * @ioa: per adapter object
 * @scmd: pointer to scsi command object
 * @ssi_reply: reply mf payload returned from firmware
 *
 * scsi_status - SCSI Status code returned from target device
 * scsi_state - state info associated with SCSI_IO determined by ioa
 * ioa_status - ioa supplied status info
 *
 * Return nothing.
 */
static void
_hst2dr_scsi_ioa_info(struct HST2DR_ADAPTER *ioa, struct scsi_cmnd *scmd,
	SSI2_SCSI_IO_REPLY *ssi_reply, u16 host_tag_id)
{
	u32 response_info;
	u8 *response_bytes;
	u16 ioa_status = le16_to_cpu(ssi_reply->status) &
		SSI2_IOASTATUS_MASK;
	u8 scsi_state = ssi_reply->scsi_state;
	u8 scsi_status = ssi_reply->scsi_status;
	char *desc_ioa_state = NULL;
	char *desc_scsi_status = NULL;
	char *desc_scsi_state = ioa->tmp_string;
	struct _sas_device *sas_device = NULL;
	struct scsi_target *starget = scmd->device->sdev_target;
	struct HST2DR_TARGET *priv_target = starget->hostdata;
	char *device_str = NULL;

	if (!priv_target)
		return;
	device_str = "volume";

	switch (ioa_status) {
	case SSI2_IOASTATUS_SUCCESS:
		desc_ioa_state = "success";
		break;
	case SSI2_IOASTATUS_INVALID_FUNCTION:
		desc_ioa_state = "invalid function";
		break;
	case SSI2_IOASTATUS_SCSI_RECOVERED_ERROR:
		desc_ioa_state = "scsi recovered error";
		break;
	case SSI2_IOASTATUS_SCSI_INVALID_DEVHANDLE:
		desc_ioa_state = "scsi invalid dev handle";
		break;
	case SSI2_IOASTATUS_SCSI_DEVICE_NOT_THERE:
		desc_ioa_state = "scsi device not there";
		break;
	case SSI2_IOASTATUS_SCSI_DATA_OVERRUN:
		desc_ioa_state = "scsi data overrun";
		break;
	case SSI2_IOASTATUS_SCSI_DATA_UNDERRUN:
		desc_ioa_state = "scsi data underrun";
		break;
	case SSI2_IOASTATUS_SCSI_IO_DATA_ERROR:
		desc_ioa_state = "scsi io data error";
		break;
	case SSI2_IOASTATUS_SCSI_PROTOCOL_ERROR:
		desc_ioa_state = "scsi protocol error";
		break;
	case SSI2_IOASTATUS_SCSI_TASK_TERMINATED:
		desc_ioa_state = "scsi task terminated";
		break;
	case SSI2_IOASTATUS_SCSI_RESIDUAL_MISMATCH:
		desc_ioa_state = "scsi residual mismatch";
		break;
	case SSI2_IOASTATUS_SCSI_TASK_MGMT_FAILED:
		desc_ioa_state = "scsi task mgmt failed";
		break;
	case SSI2_IOASTATUS_SCSI_IOA_TERMINATED:
		desc_ioa_state = "scsi ioa terminated";
		break;
	case SSI2_IOASTATUS_SCSI_EXT_TERMINATED:
		desc_ioa_state = "scsi ext terminated";
		break;
	case SSI2_IOASTATUS_EEDP_GUARD_ERROR:
		desc_ioa_state = "eedp guard error";
		break;
	case SSI2_IOASTATUS_EEDP_REF_TAG_ERROR:
		desc_ioa_state = "eedp ref tag error";
		break;
	case SSI2_IOASTATUS_EEDP_APP_TAG_ERROR:
		desc_ioa_state = "eedp app tag error";
		break;
	case SSI2_IOASTATUS_INSUFFICIENT_POWER:
		desc_ioa_state = "insufficient power";
		break;
	default:
		desc_ioa_state = "unknown";
		break;
	}

	switch (scsi_status) {
	case SSI2_SCSI_STATUS_GOOD:
		desc_scsi_status = "good";
		break;
	case SSI2_SCSI_STATUS_CHECK_CONDITION:
		desc_scsi_status = "check condition";
		break;
	case SSI2_SCSI_STATUS_CONDITION_MET:
		desc_scsi_status = "condition met";
		break;
	case SSI2_SCSI_STATUS_BUSY:
		desc_scsi_status = "busy";
		break;
	case SSI2_SCSI_STATUS_INTERMEDIATE:
		desc_scsi_status = "intermediate";
		break;
	case SSI2_SCSI_STATUS_INTERMEDIATE_CONDMET:
		desc_scsi_status = "intermediate condmet";
		break;
	case SSI2_SCSI_STATUS_RESERVATION_CONFLICT:
		desc_scsi_status = "reservation conflict";
		break;
	case SSI2_SCSI_STATUS_COMMAND_TERMINATED:
		desc_scsi_status = "command terminated";
		break;
	case SSI2_SCSI_STATUS_TASK_SET_FULL:
		desc_scsi_status = "task set full";
		break;
	case SSI2_SCSI_STATUS_ACA_ACTIVE:
		desc_scsi_status = "aca active";
		break;
	case SSI2_SCSI_STATUS_TASK_ABORTED:
		desc_scsi_status = "task aborted";
		break;
	default:
		desc_scsi_status = "unknown";
		break;
	}

	desc_scsi_state[0] = '\0';
	if (!scsi_state)
		desc_scsi_state = " ";
	if (scsi_state & SSI2_SCSI_STATE_RESPONSE_INFO_VALID)
		strcat(desc_scsi_state, "response info ");
	if (scsi_state & SSI2_SCSI_STATE_TERMINATED)
		strcat(desc_scsi_state, "state terminated ");
	if (scsi_state & SSI2_SCSI_STATE_NO_SCSI_STATUS)
		strcat(desc_scsi_state, "no status ");
	if (scsi_state & SSI2_SCSI_STATE_AUTOSENSE_FAILED)
		strcat(desc_scsi_state, "autosense failed ");
	if (scsi_state & SSI2_SCSI_STATE_AUTOSENSE_VALID)
		strcat(desc_scsi_state, "autosense valid ");

	scsi_print_command(scmd);

	if (priv_target->flags & HST2DR_TARGET_FLAGS_VOLUME) {
		log_warn(ioa, "\t%s wwid(0x%016llx)\n",
			device_str,
			(unsigned long long)priv_target->sas_address);
	} else {
		sas_device = hst2dr_get_sdev_from_target(ioa, priv_target);
		if (sas_device) {
			log_warn(ioa,
				"\tsas_address(0x%016llx), phy(%d)\n",
				(unsigned long long)
				sas_device->sas_address, sas_device->phy);

			_hst2dr_display_enclosure_chassis_info(ioa, sas_device,
				NULL, NULL);

			sas_device_put(sas_device);
		}
	}

	log_warn(ioa,
		"\thandle(0x%04x), ioa_status(%s)(0x%04x), host_tag_id(%d)\n",
		le16_to_cpu(ssi_reply->dev_handle),
		desc_ioa_state, ioa_status, host_tag_id);
	log_warn(ioa,
		"\trequest_len(%d), underflow(%d), resid(%d)\n",
		scsi_bufflen(scmd), scmd->underflow,
		scsi_get_resid(scmd));
	log_warn(ioa,
		"\ttag(%d), transfer_count(%d), sc->result(0x%08x)\n",
		le16_to_cpu(ssi_reply->task_tag),
		le32_to_cpu(ssi_reply->transfer_count), scmd->result);
	log_warn(ioa,
		"\tscsi_status(%s)(0x%02x), scsi_state(%s)(0x%02x)\n",
		desc_scsi_status,
		scsi_status, desc_scsi_state, scsi_state);

	if (scsi_state & SSI2_SCSI_STATE_AUTOSENSE_VALID) {
		struct sense_info data;

		_hst2dr_normalize_sense(scmd->sense_buffer, &data);
		log_warn(ioa,
			"\t[sense_key,asc,ascq]: [0x%02x,0x%02x,0x%02x], count(%d)\n",
			data.skey,
			data.asc, data.ascq,
			le32_to_cpu(ssi_reply->sense_count));
	}

	if (scsi_state & SSI2_SCSI_STATE_RESPONSE_INFO_VALID) {
		response_info = le32_to_cpu(ssi_reply->response_info);
		response_bytes = (u8 *)&response_info;
		_hst2dr_response_code(ioa, response_bytes[0]);
	}
}


/**
 * _hst2dr_io_done - scsi request callback
 * @ioa: per adapter object
 * @cqe: completion queue entity
 *
 * Callback handler when using _hst2dr_qcmd.
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
static u8
_hst2dr_io_done(struct HST2DR_ADAPTER *ioa,
	hst2dr_nvme_completion *cqe)
{
	SSI2_SCSI_REQUEST *ssi_request;
	SSI2_SCSI_IO_REPLY *ssi_reply = NULL;
	struct scsi_cmnd *scmd;
	u16 ioa_status;
	u32 xfer_cnt;
	u8 scsi_state;
	u8 scsi_status;
	u32 log_info;
	struct HST2DR_DEVICE *sas_device_priv_data;
	u32 response_code = 0;
	unsigned int sector_sz;
	unsigned long flags;
	struct scsiio_tracker *st;

	st = _get_st_from_host_tag_id(ioa, cqe->host_tag_id);
	if (!st || st->host_tag_id == NO_HOST_TAG_ID ||
			st->direct_io != MAGIC_NUMBER ||
			(ioa->ioa_reset_in_progress & 2)) {
		log_error(ioa, "no host id or reset in progress\n");
		return 1;
	}

	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);

	scmd = _hst2dr_scsi_lookup_get(ioa, cqe->host_tag_id);

	if (scmd == NULL) {
		log_warn(ioa, "scmd:NULL\n");
		return 1;
	}

	ssi_request = hst2dr_base_get_msg_frame(ioa, cqe->host_tag_id);
	if (scmd->retries > 0) {
		log_scsi(ioa, "scmd retries=%d allowed:%d\n",
			scmd->retries, scmd->allowed);
		debug_dump_mem("retries io done", ssi_request, 128);
	}

	if (ssi_reply == NULL) {
		scmd->result = DID_OK << 16;
		goto out;
	}

	sas_device_priv_data = scmd->device->hostdata;
	if (!sas_device_priv_data ||
			!sas_device_priv_data->sas_target ||
			sas_device_priv_data->sas_target->deleted) {
		scmd->result = DID_NO_CONNECT << 16;
		goto out;
	}
	ioa_status = le16_to_cpu(cqe->ctrl.status);
	scsi_state = ssi_reply->scsi_state;
	if (scsi_state & SSI2_SCSI_STATE_RESPONSE_INFO_VALID)
		response_code =
			le32_to_cpu(ssi_reply->response_info) & 0xFF;

	xfer_cnt = le32_to_cpu(ssi_reply->transfer_count);

	/* In case of bogus fw or device, we could end up having
	 * unaligned partial completion. We can force alignment here,
	 * then scsi-ml does not need to handle this misbehavior.
	 */
	sector_sz = scmd->device->sector_size;

	scsi_set_resid(scmd, scsi_bufflen(scmd) - xfer_cnt);
	if (ioa_status & SSI2_IOASTATUS_FLAG_LOG_INFO_AVAILABLE)
		log_info =  le32_to_cpu(ssi_reply->log_info);
	else
		log_info = 0;
	ioa_status &= SSI2_IOASTATUS_MASK;
	scsi_status = ssi_reply->scsi_status;

	if (ioa_status == SSI2_IOASTATUS_SCSI_DATA_UNDERRUN &&
			xfer_cnt == 0 &&
			(scsi_status == SSI2_SCSI_STATUS_BUSY ||
			scsi_status == SSI2_SCSI_STATUS_RESERVATION_CONFLICT ||
			scsi_status == SSI2_SCSI_STATUS_TASK_SET_FULL)) {
		ioa_status = SSI2_IOASTATUS_SUCCESS;
	}

	if (scsi_state & SSI2_SCSI_STATE_AUTOSENSE_VALID) {
		struct sense_info data;
		const void *sense_data = hst2dr_base_get_sense_buffer(ioa,
			ssi_reply->sense_id);
		if (sense_data == NULL) {
			memset(scmd->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);
			log_scsi(ioa, "err sense_id:%d\n", ssi_reply->sense_id);
		} else {
			u32 sz = min_t(u32, SCSI_SENSE_BUFFERSIZE,
			le32_to_cpu(ssi_reply->sense_count));
			memcpy(scmd->sense_buffer, sense_data, sz);
			_hst2dr_normalize_sense(scmd->sense_buffer, &data);
			/* failure prediction threshold exceeded */

			if (ioa->log_level & LOG_DEBUG_REPLY)
				_hst2dr_scsi_ioa_info(ioa, scmd,
					ssi_reply, cqe->host_tag_id);
		}
		log_debug(ioa,
			"Sense id: %d, reply id: %d\n",
			ssi_reply->sense_id,
			cqe->reply_id);
		debug_dump_mem("IO SENSE: ", (void *)sense_data,
			min_t(u32, SCSI_SENSE_BUFFERSIZE,
		le32_to_cpu(ssi_reply->sense_count)));
		spin_lock_irqsave(&ioa->reply_sense_q_lock, flags);
		ioa->reply_sense_q_ctrl.ctrl.reg.reply_push = 0;
		ioa->reply_sense_q_ctrl.ctrl.reg.sense_push = 1;
		ioa->reply_sense_q_ctrl.ctrl.reg.sense_id = ssi_reply->sense_id;
		hst2dr_write_direct_reg_hal_api(ioa,
			NVME_REG_REPLY_SENSE_Q_CTRL,
			ioa->reply_sense_q_ctrl.ctrl.dw);
		spin_unlock_irqrestore(&ioa->reply_sense_q_lock, flags);
		log_scsi(ioa,
			"sense push:%x\n",
			ioa->reply_sense_q_ctrl.ctrl.dw);
	}
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_scsi(ioa,
			"ioa status:%x retries:%d allowed:%d scsi_state:%x scsi_status:%x\n",
			ioa_status, scmd->retries,
			scmd->allowed,
			scsi_state,
			scsi_status);
		debug_dump_mem("failed io", ssi_request, 128);
	}
	switch (ioa_status) {
	case SSI2_IOASTATUS_BUSY:
	case SSI2_IOASTATUS_INSUFFICIENT_RESOURCES:
		log_scsi(ioa, "busy or insufficent resources\n");
		scmd->result = SAM_STAT_BUSY;
		break;

	case SSI2_IOASTATUS_SCSI_DEVICE_NOT_THERE:
		log_scsi(ioa, "scsi device not there\n");
		scmd->result = DID_NO_CONNECT << 16;
		break;

	case SSI2_IOASTATUS_SCSI_IOA_TERMINATED:
		if (sas_device_priv_data->block) {
			scmd->result = DID_TRANSPORT_DISRUPTED << 16;
			log_scsi(ioa, "device block\n");
			goto out;
		}
		if ((scmd->device->channel == RAID_CHANNEL) &&
		   (scsi_state == (SSI2_SCSI_STATE_TERMINATED |
		   SSI2_SCSI_STATE_NO_SCSI_STATUS))) {
			log_scsi(ioa, "terminated of no scsi status\n");
			scmd->result = DID_RESET << 16;
			break;
		}
		log_scsi(ioa, "Terminated, soft error\n");
		scmd->result = DID_SOFT_ERROR << 16;
		break;
	case SSI2_IOASTATUS_SCSI_TASK_TERMINATED:
	case SSI2_IOASTATUS_SCSI_EXT_TERMINATED:
		log_scsi(ioa, "scsi task terminated or scsi ext terminated\n");
		scmd->result = DID_RESET << 16;
		break;

	case SSI2_IOASTATUS_SCSI_RESIDUAL_MISMATCH:
		if ((xfer_cnt == 0) || (scmd->underflow > xfer_cnt)) {
			log_scsi(ioa, "xfer_cnt == 0 or underflow > xfer_cnt\n");
			scmd->result = DID_SOFT_ERROR << 16;
		} else {
			scmd->result = (DID_OK << 16) | scsi_status;
		}
		break;

	case SSI2_IOASTATUS_SCSI_DATA_UNDERRUN:
		scmd->result = (DID_OK << 16) | scsi_status;

		if ((scsi_state & SSI2_SCSI_STATE_AUTOSENSE_VALID)) {
			log_scsi(ioa, "autosense valid\n");
			break;
		}
		if (xfer_cnt < scmd->underflow) {
			log_scsi(ioa, "xfer_cnd < scmd->underflow\n");
			if (scsi_status == SAM_STAT_BUSY)
				scmd->result = SAM_STAT_BUSY;
			else
				scmd->result = DID_SOFT_ERROR << 16;
		} else if (scsi_state & (SSI2_SCSI_STATE_AUTOSENSE_FAILED |
				SSI2_SCSI_STATE_NO_SCSI_STATUS)) {
			log_scsi(ioa, "autosense failed or no scsi status\n");
			scmd->result = DID_SOFT_ERROR << 16;
		} else if (scsi_state & SSI2_SCSI_STATE_TERMINATED) {
			log_scsi(ioa, "scsi_state_terminated\n");
			scmd->result = DID_RESET << 16;
		} else if (!xfer_cnt && scmd->cmnd[0] == REPORT_LUNS) {
			log_scsi(ioa, "!xfer_cnt && scmd->cmnd[0] == REPORT_LUNS\n");
			ssi_reply->scsi_state = SSI2_SCSI_STATE_AUTOSENSE_VALID;
			ssi_reply->scsi_status = SAM_STAT_CHECK_CONDITION;
			scmd->result = (DRIVER_SENSE << 24) |
				SAM_STAT_CHECK_CONDITION;
			scmd->sense_buffer[0] = 0x70;
			scmd->sense_buffer[2] = ILLEGAL_REQUEST;
			scmd->sense_buffer[12] = 0x20;
			scmd->sense_buffer[13] = 0;
		}
		break;

	case SSI2_IOASTATUS_SCSI_DATA_OVERRUN:
		scsi_set_resid(scmd, 0);
		fallthrough;
	case SSI2_IOASTATUS_SCSI_RECOVERED_ERROR:
	case SSI2_IOASTATUS_SUCCESS:
		scmd->result = (DID_OK << 16) | scsi_status;
		if (response_code ==
				SSI2_SCSITASKMGMT_RSP_INVALID_FRAME ||
				(scsi_state &
				(SSI2_SCSI_STATE_AUTOSENSE_FAILED |
				SSI2_SCSI_STATE_NO_SCSI_STATUS))) {
			log_scsi(ioa, "invalid fram or autosense failed or no scsi status\n");
			scmd->result = DID_SOFT_ERROR << 16;
		} else if (scsi_state & SSI2_SCSI_STATE_TERMINATED) {
			log_scsi(ioa, "scsi state terminated\n");
			scmd->result = DID_RESET << 16;
		}
		break;

	case SSI2_IOASTATUS_EEDP_GUARD_ERROR:
	case SSI2_IOASTATUS_EEDP_REF_TAG_ERROR:
	case SSI2_IOASTATUS_EEDP_APP_TAG_ERROR:
		log_scsi(ioa, "eedp error handling\n");
		_hst2dr_eedp_error_handling(scmd, ioa_status);
		break;

	case SSI2_IOASTATUS_SCSI_PROTOCOL_ERROR:
	case SSI2_IOASTATUS_INVALID_FUNCTION:
	case SSI2_IOASTATUS_INVALID_SGL:
	case SSI2_IOASTATUS_INTERNAL_ERROR:
	case SSI2_IOASTATUS_INVALID_FIELD:
	case SSI2_IOASTATUS_INVALID_STATE:
	case SSI2_IOASTATUS_SCSI_IO_DATA_ERROR:
	case SSI2_IOASTATUS_SCSI_TASK_MGMT_FAILED:
	case SSI2_IOASTATUS_INSUFFICIENT_POWER:
	default:
		scmd->result = DID_SOFT_ERROR << 16;
		break;

	}

 out:

	scsi_dma_unmap(scmd);
	hst2dr_base_free_host_tag_id(ioa, cqe->host_tag_id);

	scsi_done(scmd);
	return 0;
}

/**
 * _hst2dr_host_refresh - refreshing sas host object contents
 * @ioa: per adapter object
 * Context: user
 *
 * During port enable, fw will send topology events for every device. Its
 * possible that the handles may change from the previous setting, so this
 * code keeping handles updating if changed.
 *
 * Return nothing.
 */
static void
_hst2dr_host_refresh(struct HST2DR_ADAPTER *ioa)
{
	u16 sz;
	u16 ioa_status;
	int i;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_SAS_UNIT0 *sas_unit0 = NULL;
	u16 attached_handle;
	u8 link_rate;

	log_tm(ioa, HST2DR_FMT
		"updating sas_address(0x%016llx)\n", ioa->name,
		(unsigned long long)ioa->sas_hba.sas_address);

	sz = offsetof(SSI2_INQUIRY_SAS_UNIT0, PhyData) + (ioa->sas_hba.num_phys
		* sizeof(SSI2_SAS_UNIT0_PHY_DATA));
	sas_unit0 = kzalloc(sz, GFP_KERNEL);
	if (!sas_unit0) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}

	if ((hst2dr_cfg_get_sas_unit0(ioa, &ssi_reply,
			sas_unit0, sz)) != 0)
		goto out;
	ioa_status = le16_to_cpu(ssi_reply.status) & SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS)
		goto out;
	for (i = 0; i < ioa->sas_hba.num_phys ; i++) {
		link_rate = sas_unit0->PhyData[i].negotiated_linkrate >> 4;
		if (i == 0)
			ioa->sas_hba.handle = le16_to_cpu(
				sas_unit0->PhyData[0].controller_dev_handle);
		ioa->sas_hba.phy[i].handle = ioa->sas_hba.handle;
		attached_handle =
			sas_unit0->PhyData[i].attached_dev_handle;
		if (attached_handle && link_rate < SSI2_SAS_NEG_LINK_RATE_1_5)
			link_rate = SSI2_SAS_NEG_LINK_RATE_1_5;
		hst2dr_transport_update_links(ioa, ioa->sas_hba.sas_address,
			attached_handle, i, link_rate);
	}
 out:
	kfree(sas_unit0);
}

/**
 * _hst2dr_host_add - create sas host object
 * @ioa: per adapter object
 *
 * Creating host side data object, stored in ioa->sas_hba
 *
 * Return nothing.
 */
static void
_hst2dr_host_add(struct HST2DR_ADAPTER *ioa)
{
	int i;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_SAS_UNIT0 *sas_unit0 = NULL;
	SSI2_INQUIRY_SAS_UNIT1 *sas_unit1 = NULL;
	SSI2_INQUIRY_PHY phy_pg0, *phy_pg00;
	SSI2_INQUIRY_SAS_DEV sas_dev00;
	SSI2_INQUIRY_ENCLOSURE enclosure;
	u16 ioa_status;
	u16 sz;
	u8 device_missing_delay;
	u8 num_phys;

	hst2dr_cfg_get_number_hba_phys(ioa, &num_phys);
	if (!num_phys) {
		log_error(ioa, "No HBA found at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}
	ioa->sas_hba.phy = kcalloc(num_phys,
		sizeof(struct _sas_phy), GFP_KERNEL);
	if (!ioa->sas_hba.phy) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioa->sas_hba.num_phys = num_phys;

	/* sas_iounit page 0 */
	sz = offsetof(SSI2_INQUIRY_SAS_UNIT0, PhyData) +
		(ioa->sas_hba.num_phys *
		sizeof(SSI2_SAS_UNIT0_PHY_DATA));
	sas_unit0 = kzalloc(sz, GFP_KERNEL);
	if (!sas_unit0) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}
	if ((hst2dr_cfg_get_sas_unit0(ioa, &ssi_reply,
			sas_unit0, sz))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioa_status = le16_to_cpu(ssi_reply.status) &
		SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}

	/* sas_iounit page 1 */
	sz = offsetof(SSI2_INQUIRY_SAS_UNIT1, PhyData) +
		(ioa->sas_hba.num_phys *
		sizeof(SSI2_SAS_UNIT1_PHY_DATA));
	sas_unit1 = kzalloc(sz, GFP_KERNEL);
	if (!sas_unit1) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	if ((hst2dr_cfg_get_sas_unit1(ioa, &ssi_reply,
			sas_unit1, sz))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioa_status = le16_to_cpu(ssi_reply.status) &
		SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}

	ioa->io_missing_delay =
		sas_unit1->io_dev_missing_delay;
	device_missing_delay =
		sas_unit1->report_dev_missing_delay;
	if (device_missing_delay & SSI2_SASIOUNIT1_REPORT_MISSING_UNIT_16)
		ioa->device_missing_delay = (device_missing_delay &
			SSI2_SASIOUNIT1_REPORT_MISSING_TIMEOUT_MASK) * 16;
	else
		ioa->device_missing_delay = device_missing_delay &
			SSI2_SASIOUNIT1_REPORT_MISSING_TIMEOUT_MASK;

	ioa->sas_hba.parent_dev = &ioa->shost->shost_gendev;
	phy_pg00 = kcalloc(ioa->sas_hba.num_phys,
		sizeof(SSI2_INQUIRY_PHY), GFP_KERNEL);
	if (!phy_pg00) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	if ((hst2dr_cfg_get_phy(ioa, &ssi_reply, phy_pg00,
			ioa->sas_hba.num_phys | 0x8000))) {
		kfree(phy_pg00);
		for (i = 0; i < ioa->sas_hba.num_phys ; i++) {
			if ((hst2dr_cfg_get_phy(ioa, &ssi_reply, &phy_pg0,
				i))) {
				log_error(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				goto out;
			}
			ioa_status = le16_to_cpu(ssi_reply.status) &
				SSI2_IOASTATUS_MASK;
			if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
				log_error(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				goto out;
			}

			if (i == 0)
				ioa->sas_hba.handle = le16_to_cpu(
					sas_unit0->PhyData[0].controller_dev_handle);
			ioa->sas_hba.phy[i].handle = ioa->sas_hba.handle;
			ioa->sas_hba.phy[i].phy_id = i;
			hst2dr_transport_add_host_phy(ioa, &ioa->sas_hba.phy[i],
				phy_pg0, ioa->sas_hba.parent_dev);
		}
	} else {
		for (i = 0; i < ioa->sas_hba.num_phys ; i++) {
			ioa_status = le16_to_cpu(ssi_reply.status) &
				SSI2_IOASTATUS_MASK;
			if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
				log_error(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				goto out;
			}

			if (i == 0)
				ioa->sas_hba.handle = le16_to_cpu(
					sas_unit0->PhyData[0].controller_dev_handle);
			ioa->sas_hba.phy[i].handle = ioa->sas_hba.handle;
			ioa->sas_hba.phy[i].phy_id = i;
			hst2dr_transport_add_host_phy(ioa, &ioa->sas_hba.phy[i],
				phy_pg00[i], ioa->sas_hba.parent_dev);
		}
		kfree(phy_pg00);
	}
	if ((hst2dr_cfg_get_sas_dev(ioa, &ssi_reply, &sas_dev00,
			SSI2_SAS_DEVICE_PGAD_FORM_HANDLE,
			ioa->sas_hba.handle))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioa->sas_hba.enclosure_handle =
		le16_to_cpu(sas_dev00.enclosure_handle);
	ioa->sas_hba.sas_address = le64_to_cpu(sas_dev00.sas_address);
	log_always(ioa,
		"host_add: handle(0x%04x), sas_addr(0x%016llx), phys(%d)\n",
		ioa->sas_hba.handle,
		(unsigned long long) ioa->sas_hba.sas_address,
		ioa->sas_hba.num_phys);

	if (ioa->sas_hba.enclosure_handle) {
		if (!(hst2dr_cfg_get_enclosure(ioa, &ssi_reply,
				&enclosure,
				SSI2_SAS_ENCLOS_PGAD_FORM_HANDLE,
				ioa->sas_hba.enclosure_handle)))
			ioa->sas_hba.enclosure_logical_id =
				le64_to_cpu(enclosure.enclosure_logical_id);
	}

 out:
	kfree(sas_unit1);
	kfree(sas_unit0);
}

/**
 * _hst2dr_expander_add -  creating expander object
 * @ioa: per adapter object
 * @handle: expander handle
 *
 * Creating expander object, stored in ioa->sas_expander_list.
 *
 * Return 0 for success, else error.
 */
static int
_hst2dr_expander_add(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _sas_node *sas_expander;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_EXPANDER expander;
	SSI2_INQUIRY_EXPANDER_PHY expander_phy, *pexpander_phy;
	SSI2_INQUIRY_ENCLOSURE enclosure;
	u32 ioa_status;
	u16 parent_handle;
	u64 sas_address, sas_address_parent = 0;
	int i;
	unsigned long flags;
	struct _sas_port *hst2dr_port = NULL;

	int rc = 0;

	if (!handle)
		return -1;

	if (ioa->shost_recovery || ioa->pci_error_recovery)
		return -1;

	if ((hst2dr_cfg_get_expander(ioa, &ssi_reply, &expander,
			SSI2_SAS_EXPAND_PGAD_FORM_HNDL, handle))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}

	ioa_status = le16_to_cpu(ssi_reply.status) &
		SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}

	/* handle out of order topology events */
	parent_handle = le16_to_cpu(expander.parent_dev_handle);
	if (_hst2dr_get_sas_address(ioa, parent_handle, &sas_address_parent)
			!= 0) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}
	if (sas_address_parent != ioa->sas_hba.sas_address) {
		spin_lock_irqsave(&ioa->sas_node_lock, flags);
		sas_expander = hst2dr_expander_find_by_sas_address(ioa,
			sas_address_parent);
		spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
		if (!sas_expander) {
			rc = _hst2dr_expander_add(ioa, parent_handle);
			if (rc != 0)
				return rc;
		}
	}

	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	sas_address = le64_to_cpu(expander.sas_address);
	sas_expander = hst2dr_expander_find_by_sas_address(ioa,
		sas_address);
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);

	if (sas_expander)
		return 0;

	if (sas_address == 0) {
		log_error(ioa, "%s sas_address:NULL\n", __func__);
		return 0;
	}
	sas_expander = kzalloc(sizeof(struct _sas_node),
		GFP_KERNEL);
	if (!sas_expander) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}

	sas_expander->handle = handle;
	sas_expander->num_phys = expander.num_phys;
	sas_expander->sas_address_parent = sas_address_parent;
	sas_expander->sas_address = sas_address;

	log_always(ioa,
		"%s(0x%04x), %s(0x%04x), %s(%016llx), %s(0x%016llx), %s(%d)\n",
		"expander_add: handle", handle,
		"parent", parent_handle,
		"parent address", sas_address_parent,
		"sas_addr", (unsigned long long)sas_expander->sas_address,
		"phys", sas_expander->num_phys);

	if (!sas_expander->num_phys)
		goto out_fail;
	sas_expander->phy = kcalloc(sas_expander->num_phys,
		sizeof(struct _sas_phy), GFP_KERNEL);
	if (!sas_expander->phy) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		rc = -1;
		goto out_fail;
	}

	INIT_LIST_HEAD(&sas_expander->sas_port_list);
	hst2dr_port = hst2dr_transport_port_add(ioa, handle,
		sas_address_parent);
	if (!hst2dr_port) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		rc = -1;
		goto out_fail;
	}
	sas_expander->parent_dev = &hst2dr_port->rphy->dev;
	pexpander_phy = kcalloc(sas_expander->num_phys,
		sizeof(SSI2_INQUIRY_EXPANDER_PHY), GFP_KERNEL);
	if (!pexpander_phy) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}
	if ((hst2dr_cfg_get_expander_phy(ioa, &ssi_reply, pexpander_phy,
		sas_expander->num_phys | 0x8000, handle))) {
		kfree(pexpander_phy);
		for (i = 0; i < sas_expander->num_phys; i++) {
			if ((hst2dr_cfg_get_expander_phy(ioa, &ssi_reply,
				&expander_phy, i, handle))) {
				log_error(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				rc = -1;
				goto out_fail;
			}
			sas_expander->phy[i].handle = handle;
			sas_expander->phy[i].phy_id = i;

			if ((hst2dr_transport_add_expander_phy(ioa,
				&sas_expander->phy[i], expander_phy,
				sas_expander->parent_dev))) {
				log_error(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				rc = -1;
				goto out_fail;
			}
		}
	} else {
		for (i = 0; i < sas_expander->num_phys; i++) {
			sas_expander->phy[i].handle = handle;
			sas_expander->phy[i].phy_id = i;

			if ((hst2dr_transport_add_expander_phy(ioa,
				&sas_expander->phy[i], pexpander_phy[i],
				sas_expander->parent_dev))) {
				log_error(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				rc = -1;
				kfree(pexpander_phy);
				goto out_fail;
			}
		}
		kfree(pexpander_phy);
	}
	if (sas_expander->enclosure_handle) {
		if (!(hst2dr_cfg_get_enclosure(ioa, &ssi_reply,
				&enclosure, SSI2_SAS_ENCLOS_PGAD_FORM_HANDLE,
				sas_expander->enclosure_handle)))
			sas_expander->enclosure_logical_id =
				le64_to_cpu(enclosure.enclosure_logical_id);
	}

	_hst2dr_expander_node_add(ioa, sas_expander);
	return 0;

 out_fail:

	if (hst2dr_port)
		hst2dr_transport_port_remove(ioa, sas_expander->sas_address,
			sas_address_parent);
	kfree(sas_expander);
	return rc;
}

/**
 * hst2dr_expander_remove - removing expander object
 * @ioa: per adapter object
 * @sas_address: expander sas_address
 *
 * Return nothing.
 */
void
hst2dr_expander_remove(struct HST2DR_ADAPTER *ioa, u64 sas_address)
{
	struct _sas_node *sas_expander;
	unsigned long flags;

	if (ioa->shost_recovery)
		return;

	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	sas_expander = hst2dr_expander_find_by_sas_address(ioa,
		sas_address);
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
	if (sas_expander)
		_hst2dr_expander_node_remove(ioa, sas_expander);

}

/**
 * _hst2dr_check_access_status - check access flags
 * @ioa: per adapter object
 * @sas_address: sas address
 * @handle: sas device handle
 * @access_flags: errors returned during discovery of the device
 *
 * Return 0 for success, else failure
 */
static u8
_hst2dr_check_access_status(struct HST2DR_ADAPTER *ioa, u64 sas_address,
	u16 handle, u8 access_status)
{
	u8 rc = 1;
	char *desc = NULL;

	switch (access_status) {
	case SSI2_SAS_DEVICE0_ASTATUS_NO_ERRORS:
	case SSI2_SAS_DEVICE0_ASTATUS_SATA_NEEDS_INITIALIZATION:
		rc = 0;
		break;
	case SSI2_SAS_DEVICE0_ASTATUS_SATA_CAPABILITY_FAILED:
		desc = "sata capability failed";
		break;
	case SSI2_SAS_DEVICE0_ASTATUS_SATA_AFFILIATION_CONFLICT:
		desc = "sata affiliation conflict";
		break;
	case SSI2_SAS_DEVICE0_ASTATUS_ROUTE_NOT_ADDRESSABLE:
		desc = "route not addressable";
		break;
	case SSI2_SAS_DEVICE0_ASTATUS_SMP_ERROR_NOT_ADDRESSABLE:
		desc = "smp error not addressable";
		break;
	case SSI2_SAS_DEVICE0_ASTATUS_DEVICE_BLOCKED:
		desc = "device blocked";
		break;
	case SSI2_SAS_DEVICE0_ASTATUS_SATA_INIT_FAILED:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_UNKNOWN:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_AFFILIATION_CONFLICT:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_IDENTIFICATION:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_CHECK_POWER:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_PIO_SN:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_MDMA_SN:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_UDMA_SN:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_ZONING_VIOLATION:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_NOT_ADDRESSABLE:
	case SSI2_SAS_DEVICE0_ASTATUS_SIF_MAX:
		desc = "sata initialization failed";
		break;
	default:
		desc = "unknown";
		break;
	}

	if (!rc)
		return 0;

	log_error(ioa,
		"discovery errors(%s): sas_address(0x%016llx), handle(0x%04x)\n",
		desc, (unsigned long long)sas_address, handle);
	return rc;
}

/**
 * _hst2dr_get_enclosure_logicalid_chassis_slot - get device's
 *			enclosure_logical_id and chassis_slot information.
 * @ioa: per adapter object
 * @sas_dev00: SAS device page0
 * @sas_device: per sas device object
 *
 * Returns nothing.
 */
static void
_hst2dr_get_enclosure_logicalid_chassis_slot(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_SAS_DEV *sas_dev00, struct _sas_device *sas_device)
{
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_ENCLOSURE enclosure;

	if (!sas_dev00 || !sas_device)
		return;

	sas_device->enclosure_handle =
		le16_to_cpu(sas_dev00->enclosure_handle);
	sas_device->is_chassis_slot_valid = 0;

	if (!le16_to_cpu(sas_dev00->enclosure_handle))
		return;

	if (hst2dr_cfg_get_enclosure(ioa, &ssi_reply,
			&enclosure, SSI2_SAS_ENCLOS_PGAD_FORM_HANDLE,
			le16_to_cpu(sas_dev00->enclosure_handle))) {
		log_error(ioa,
			"Enclosure Pg0 read failed for handle(0x%04x)\n",
			le16_to_cpu(sas_dev00->enclosure_handle));
		return;
	}

	sas_device->enclosure_logical_id =
		le64_to_cpu(enclosure.enclosure_logical_id);

	if (le16_to_cpu(enclosure.flags) &
			SSI2_SAS_ENCLOSURE_FLAGS_CHASSIS_SLOT_VALID) {
		sas_device->is_chassis_slot_valid = 1;
		sas_device->chassis_slot = enclosure.chassis_slot;
	}
}


/**
 * _hst2dr_check_device - checking device responsiveness
 * @ioa: per adapter object
 * @parent_sas_address: sas address of parent expander or sas host
 * @handle: attached device handle
 * @phy_numberv: phy number
 * @link_rate: new link rate
 *
 * Returns nothing.
 */
static void
_hst2dr_check_device(struct HST2DR_ADAPTER *ioa,
	u64 parent_sas_address, u16 handle, u8 phy_number, u8 link_rate)
{
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_SAS_DEV sas_dev00;
	struct _sas_device *sas_device;
	u32 ioa_status;
	unsigned long flags;
	u64 sas_address;
	struct scsi_target *starget;
	struct HST2DR_TARGET *sas_target_priv_data;
	u32 device_info;

	if ((hst2dr_cfg_get_sas_dev(ioa, &ssi_reply, &sas_dev00,
			SSI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle)))
		return;

	ioa_status = le16_to_cpu(ssi_reply.status) & SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS)
		return;

	/* wide port handling ~ we need only handle device once for the phy that
	 * is matched in sas device page zero
	 */
	if (phy_number != sas_dev00.phy_num)
		return;

	/* check if this is end device */
	device_info = le32_to_cpu(sas_dev00.dev_info);
	if (!(_hst2dr_is_end_device(device_info)))
		return;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_address = le64_to_cpu(sas_dev00.sas_address);
	sas_device = __hst2dr_get_sdev_by_addr(ioa,
			sas_address);

	if (!sas_device)
		goto out_unlock;

	if (unlikely(sas_device->handle != handle)) {
		starget = sas_device->starget;
		sas_target_priv_data = starget->hostdata;
		starget_printk(KERN_INFO, starget,
			"handle changed from(0x%04x) to (0x%04x)!\n",
			sas_device->handle, handle);
		sas_target_priv_data->handle = handle;
		sas_device->handle = handle;
		if (le16_to_cpu(sas_dev00.flags) &
				SSI2_SAS_DEVICE0_FLAGS_ENCL_LEVEL_VALID) {
			sas_device->enclosure_level =
				sas_dev00.enclosure_handle;
			memcpy(sas_device->connector_name,
				sas_dev00.connector_name, 4);
			sas_device->connector_name[4] = '\0';
		} else {
			sas_device->enclosure_level = 0;
			sas_device->connector_name[0] = '\0';
		}

		_hst2dr_get_enclosure_logicalid_chassis_slot(ioa,
			&sas_dev00, sas_device);
	}

	/* check if device is present */
	if (!(le16_to_cpu(sas_dev00.flags) &
			SSI2_SAS_DEVICE0_FLAGS_DEVICE_PRESENT)) {
		log_error(ioa,
			"device is not present handle(0x%04x), flags!\n",
			handle);
		goto out_unlock;
	}

	/* check if there were any issues with discovery */
	if (_hst2dr_check_access_status(ioa, sas_address, handle,
			sas_dev00.access_status))
		goto out_unlock;

	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	_hst2dr_unblock_io_device(ioa, sas_address);

	if (sas_device)
		sas_device_put(sas_device);
	return;

out_unlock:
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	if (sas_device)
		sas_device_put(sas_device);
}

/**
 * _hst2dr_add_device -  creating sas device object
 * @ioa: per adapter object
 * @handle: sas device handle
 * @phy_num: phy number end device attached to
 *
 * Creating end device object, stored in ioa->sas_device_list.
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_hst2dr_add_device(struct HST2DR_ADAPTER *ioa, u16 handle, u8 phy_num)
{
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_SAS_DEV sas_dev00;
	SSI2_INQUIRY_ENCLOSURE enclosure;
	struct _sas_device *sas_device;
	u32 ioa_status;
	u64 sas_address;
	u32 device_info;
	int encl_pg0_rc = -1;

	if ((hst2dr_cfg_get_sas_dev(ioa, &ssi_reply, &sas_dev00,
			SSI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle))) {
		log_warn(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 0;
	}

	ioa_status = le16_to_cpu(ssi_reply.status) &
		SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_warn(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 0;
	}

	/* check if this is end device */
	device_info = le32_to_cpu(sas_dev00.dev_info);
	if (!(_hst2dr_is_end_device(device_info))) {
		log_warn(ioa, "%s %s:%d/%s()!\n",
			"add device failure, not end device at",
			__FILE__, __LINE__, __func__);
		return 0;
	}
	if (device_info & SSI2_SAS_DEVICE_INFO_HIDE_DEVICE) {
		log_warn(ioa, "%s handle:%x %s:%d/%s()!\n",
			"add device failure, device hide",
			handle, __FILE__, __LINE__, __func__);
		return 0;
	}
	set_bit(handle, ioa->pend_os_device_add);
	sas_address = le64_to_cpu(sas_dev00.sas_address);

	/* check if device is present */
	if (!(le16_to_cpu(sas_dev00.flags) &
			SSI2_SAS_DEVICE0_FLAGS_DEVICE_PRESENT)) {
		log_warn(ioa, "%s handle(0x04%x)!\n",
			"add device failure, device is not present",
			handle);
		return 0;
	}

	/* check if there were any issues with discovery */
	if (_hst2dr_check_access_status(ioa, sas_address, handle,
			sas_dev00.access_status)) {
		log_warn(ioa,
			"add device failure, access_status:%x at %s:%d/%s()!\n",
			sas_dev00.access_status, __FILE__, __LINE__, __func__);
		return 0;
	}

	sas_device = hst2dr_get_sdev_by_addr(ioa,
					sas_address);
	if (sas_device) {
		clear_bit(handle, ioa->pend_os_device_add);
		sas_device_put(sas_device);
		log_warn(ioa, "%s sas_addr:%llx at %s:%d/%s()!\n",
			"device already exist,",
			sas_address, __FILE__, __LINE__, __func__);
		return 0;
	}

	if (sas_dev00.enclosure_handle) {
		encl_pg0_rc = hst2dr_cfg_get_enclosure(ioa, &ssi_reply,
			&enclosure, SSI2_SAS_ENCLOS_PGAD_FORM_HANDLE,
			sas_dev00.enclosure_handle);
		if (encl_pg0_rc)
			log_scsi(ioa,
				"Enclosure Pg0 read failed for handle(0x%04x)\n",
				sas_dev00.enclosure_handle);
	}

	sas_device = kzalloc(sizeof(struct _sas_device),
			GFP_KERNEL);
	if (!sas_device) {
		log_warn(ioa,
			"add device failure, NOMEM failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 0;
	}

	kref_init(&sas_device->refcount);
	sas_device->handle = handle;
	if (_hst2dr_get_sas_address(ioa,
			le16_to_cpu(sas_dev00.parent_dev_handle),
			&sas_device->sas_address_parent) != 0)
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
	sas_device->enclosure_handle =
		le16_to_cpu(sas_dev00.enclosure_handle);
	if (sas_device->enclosure_handle != 0)
		sas_device->slot =
			le16_to_cpu(sas_dev00.slot);
	sas_device->device_info = device_info;
	sas_device->sas_address = sas_address;
	sas_device->phy = sas_dev00.phy_num;

	if (le16_to_cpu(sas_dev00.flags)
		& SSI2_SAS_DEVICE0_FLAGS_ENCL_LEVEL_VALID) {
		sas_device->enclosure_level =
			sas_dev00.enclosure_handle;
		memcpy(sas_device->connector_name,
			sas_dev00.connector_name, 4);
		sas_device->connector_name[4] = '\0';
	} else {
		sas_device->enclosure_level = 0;
		sas_device->connector_name[0] = '\0';
	}

	/* get enclosure_logical_id & chassis_slot */
	sas_device->is_chassis_slot_valid = 0;
	if (encl_pg0_rc == 0) {
		sas_device->enclosure_logical_id =
			le64_to_cpu(enclosure.enclosure_logical_id);

		if (le16_to_cpu(enclosure.flags) &
				SSI2_SAS_ENCLOSURE_FLAGS_CHASSIS_SLOT_VALID) {
			sas_device->is_chassis_slot_valid = 1;
			sas_device->chassis_slot =
				enclosure.chassis_slot;
		}
	}

	/* get device name */
	sas_device->device_name = le64_to_cpu(sas_dev00.dev_name);
	if (ioa->wait_for_discovery_to_complete)
		_hst2dr_device_init_add(ioa, sas_device);
	else
		_hst2dr_device_add(ioa, sas_device);

	sas_device_put(sas_device);
	return 0;
}

/**
 * _hst2dr_remove_device -  removing sas device object
 * @ioa: per adapter object
 * @sas_device_delete: the sas_device object
 *
 * Return nothing.
 */
static void
_hst2dr_remove_device(struct HST2DR_ADAPTER *ioa,
	struct _sas_device *sas_device)
{
	struct HST2DR_TARGET *sas_target_priv_data;

	log_scsi(ioa, "%s handle(0x%04x), sas_addr(0x%016llx)\n",
		__func__, sas_device->handle,
		(unsigned long long)sas_device->sas_address);

	_hst2dr_display_enclosure_chassis_info(ioa, sas_device, NULL, NULL);
	if (sas_device->starget && sas_device->starget->hostdata) {
		sas_target_priv_data = sas_device->starget->hostdata;
		sas_target_priv_data->deleted = 1;
		_hst2dr_unblock_io_device(ioa, sas_device->sas_address);
		sas_target_priv_data->handle =
			HST2DR_INVALID_DEVICE_HANDLE;
	}

	hst2dr_transport_port_remove(ioa,
		sas_device->sas_address,
		sas_device->sas_address_parent);

	log_always(ioa,
		"removing handle(0x%04x), sas_addr(0x%016llx)\n",
		sas_device->handle,
		(unsigned long long) sas_device->sas_address);

	_hst2dr_display_enclosure_chassis_info(ioa, sas_device, NULL, NULL);
}
/**
 * _hst2dr_topology_change_event_debug - debug for topology event
 * @ioa: per adapter object
 * @event_data: event data payload
 * Context: user.
 */
static void
_hst2dr_topology_change_event_debug(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST *event_data)
{
	int i;
	u16 handle;
	u16 reason_code;
	u8 phy_number;
	char *status_str = NULL;
	u8 link_rate, prev_link_rate;

	switch (event_data->exp_status) {
	case SSI2_EVENT_SAS_TOPO_ES_ADDED:
		status_str = "add";
		break;
	case SSI2_EVENT_SAS_TOPO_ES_NOT_RESPONDING:
		status_str = "remove";
		break;
	case SSI2_EVENT_SAS_TOPO_ES_RESPONDING:
	case 0:
		status_str =  "responding";
		break;
	case SSI2_EVENT_SAS_TOPO_ES_DELAY_NOT_RESPONDING:
		status_str = "remove delay";
		break;
	default:
		status_str = "unknown status";
		break;
	}
	log_event(ioa, "sas topology change: (%s)\n",
		status_str);
	log_event(ioa,
		"\t%s(0x%04x), %s(0x%04x) start_phy(%02d), count(%d)\n",
		"handle", le16_to_cpu(event_data->expander_dev_handle),
		"enclosure_handle", le16_to_cpu(event_data->enclosure_handle),
		event_data->start_phy_num, event_data->num_entries);
	for (i = 0; i < event_data->num_entries; i++) {
		handle = le16_to_cpu(event_data->phy[i].attached_dev_handle);
		if (!handle)
			continue;
		phy_number = event_data->start_phy_num + i;
		reason_code = event_data->phy[i].phy_status &
			SSI2_EVENT_SAS_TOPO_RC_MASK;
		switch (reason_code) {
		case SSI2_EVENT_SAS_TOPO_RC_TARG_ADDED:
			status_str = "target add";
			break;
		case SSI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING:
			status_str = "target remove";
			break;
		case SSI2_EVENT_SAS_TOPO_RC_DELAY_NOT_RESPONDING:
			status_str = "delay target remove";
			break;
		case SSI2_EVENT_SAS_TOPO_RC_PHY_CHANGED:
			status_str = "link rate change";
			break;
		case SSI2_EVENT_SAS_TOPO_RC_NO_CHANGE:
			status_str = "target responding";
			break;
		default:
			status_str = "unknown";
			break;
		}
		link_rate = event_data->phy[i].linkrate >> 4;
		prev_link_rate = event_data->phy[i].linkrate & 0xF;
		log_event(ioa,
			"\tphy(%02d), %s(0x%04x): %s: %s(0x%02x), old(0x%02x)\n",
			phy_number,
			"attached_handle", handle, status_str,
			"link rate: new", link_rate,
			prev_link_rate);

	}
}

/**
 * _hst2dr_topology_change_event - handle topology changes
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 */
static int
_hst2dr_topology_change_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	int i;
	u16 parent_handle, handle;
	u16 reason_code;
	u8 phy_number, max_phys;
	struct _sas_node *sas_expander;
	u64 sas_address;
	unsigned long flags;
	u8 link_rate, prev_link_rate;
	SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST *event_data =
		(SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST *)
		fw_event->event_data;

	_hst2dr_topology_change_event_debug(ioa, event_data);
	if (ioa->shost_recovery || ioa->remove_host || ioa->pci_error_recovery)
		return 0;

	if (!ioa->sas_hba.num_phys)
		_hst2dr_host_add(ioa);
	else
		_hst2dr_host_refresh(ioa);

	if (fw_event->ignore) {
		log_event(ioa, "ignore %s\n", __func__);
		return 0;
	}

	parent_handle = le16_to_cpu(event_data->expander_dev_handle);

	/* handle expander add */
	if (event_data->exp_status == SSI2_EVENT_SAS_TOPO_ES_ADDED)
		if (_hst2dr_expander_add(ioa, parent_handle) != 0)
			return 0;

	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	sas_expander = hst2dr_expander_find_by_handle(ioa,
		parent_handle);
	if (sas_expander) {
		sas_address = sas_expander->sas_address;
		max_phys = sas_expander->num_phys;
	} else if (parent_handle < ioa->sas_hba.num_phys) {
		sas_address = ioa->sas_hba.sas_address;
		max_phys = ioa->sas_hba.num_phys;
	} else {
		spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
		log_event(ioa, "expander error %s\n", __func__);
		return 0;
	}
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
	/* handle siblings events */
	for (i = 0; i < event_data->num_entries; i++) {
		if (fw_event->ignore) {
			log_event(ioa, "ignore %s\n", __func__);
			return 0;
		}
		if (ioa->remove_host || ioa->pci_error_recovery)
			return 0;
		phy_number = event_data->start_phy_num + i;
		if (phy_number >= max_phys)
			continue;
		reason_code = event_data->phy[i].phy_status &
			SSI2_EVENT_SAS_TOPO_RC_MASK;
		if ((event_data->phy[i].phy_status &
				SSI2_EVENT_SAS_TOPO_PHYSTATUS_VACANT) &&
				(reason_code !=
				SSI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING))
			continue;
		handle = le16_to_cpu(event_data->phy[i].attached_dev_handle);
		if (!handle)
			continue;
		link_rate = event_data->phy[i].linkrate >> 4;
		prev_link_rate = event_data->phy[i].linkrate & 0xF;
		switch (reason_code) {
		case SSI2_EVENT_SAS_TOPO_RC_PHY_CHANGED:

			if (ioa->shost_recovery)
				break;

			if (link_rate == prev_link_rate) {
				_hst2dr_check_device(ioa, sas_address, handle,
				phy_number, link_rate);
				break;
			}

			hst2dr_transport_update_links(ioa, sas_address,
				handle, phy_number, link_rate);

			if (link_rate < SSI2_SAS_NEG_LINK_RATE_1_5)
				break;

			_hst2dr_check_device(ioa, sas_address, handle,
				phy_number, link_rate);

			if (!test_bit(handle, ioa->pend_os_device_add))
				break;

			/* fall through */
			fallthrough;

		case SSI2_EVENT_SAS_TOPO_RC_TARG_ADDED:

			if (ioa->shost_recovery)
				break;
			ioa->current_event->pending_dev = 1;
			hst2dr_transport_update_links(ioa, sas_address,
				handle, phy_number, link_rate);

			_hst2dr_add_device(ioa, handle, phy_number);
			ioa->current_event->pending_dev = 0;

			break;
		case SSI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING:

		ioa->current_event->pending_dev = 1;
		_hst2dr_device_remove_by_handle(ioa, handle);
		ioa->current_event->pending_dev = 0;
			break;
		}
	}

	/* handle expander removal */
	if (event_data->exp_status == SSI2_EVENT_SAS_TOPO_ES_NOT_RESPONDING &&
			sas_expander)
		hst2dr_expander_remove(ioa, sas_address);

	return 0;
}

/**
 * _hst2dr_device_status_change_event_debug - debug for device event
 * @event_data: event data payload
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_device_status_change_event_debug(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_SAS_DEVICE_STATUS_CHANGE *event_data)
{
	char *reason_str = NULL;

	switch (event_data->reason_code) {
	case SSI2_EVENT_SAS_DEV_STAT_RC_SMART_DATA:
		reason_str = "smart data";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_UNSUPPORTED:
		reason_str = "unsupported device discovered";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET:
		reason_str = "internal device reset";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_TASK_ABORT_INTERNAL:
		reason_str = "internal task abort";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_ABORT_TASK_SET_INTERNAL:
		reason_str = "internal task abort set";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_CLEAR_TASK_SET_INTERNAL:
		reason_str = "internal clear task set";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_QUERY_TASK_INTERNAL:
		reason_str = "internal query task";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_SATA_INIT_FAILURE:
		reason_str = "sata init failure";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_CMP_INTERNAL_DEV_RESET:
		reason_str = "internal device reset complete";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_CMP_TASK_ABORT_INTERNAL:
		reason_str = "internal task abort complete";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_ASYNC_NOTIFICATION:
		reason_str = "internal async notification";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_EXPANDER_REDUCED_FUNCTIONALITY:
		reason_str = "expander reduced functionality";
		break;
	case SSI2_EVENT_SAS_DEV_STAT_RC_CMP_EXPANDER_REDUCED_FUNCTIONALITY:
		reason_str = "expander reduced functionality complete";
		break;
	default:
		reason_str = "unknown reason";
		break;
	}
	log_event(ioa, "device status change: (%s)\n"
		"\thandle(0x%04x), sas address(0x%016llx)",
		reason_str, le16_to_cpu(event_data->dev_handle),
		(unsigned long long)le64_to_cpu(event_data->sas_address));
	if (event_data->reason_code == SSI2_EVENT_SAS_DEV_STAT_RC_SMART_DATA)
		log_event(ioa, ", ASC(0x%x), ASCQ(0x%x)\n",
			event_data->asc, event_data->ascq);
	log_event(ioa, "\n");
}

/**
 * _hst2dr_device_status_change_event - handle device status change
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_device_status_change_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	struct HST2DR_TARGET *target_priv_data;
	struct _sas_device *sas_device;
	u64 sas_address;
	unsigned long flags;
	SSI2_EVENT_DATA_SAS_DEVICE_STATUS_CHANGE *event_data =
		(SSI2_EVENT_DATA_SAS_DEVICE_STATUS_CHANGE *)
		fw_event->event_data;
	_hst2dr_device_status_change_event_debug(ioa, event_data);

	if (event_data->reason_code !=
			SSI2_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET &&
			event_data->reason_code !=
			SSI2_EVENT_SAS_DEV_STAT_RC_CMP_INTERNAL_DEV_RESET)
		return;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_address = le64_to_cpu(event_data->sas_address);
	sas_device = __hst2dr_get_sdev_by_addr(ioa,
		sas_address);

	if (!sas_device || !sas_device->starget)
		goto out;

	target_priv_data = sas_device->starget->hostdata;
	if (!target_priv_data)
		goto out;

	if (event_data->reason_code ==
			SSI2_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET)
		target_priv_data->tm_busy = 1;
	else
		target_priv_data->tm_busy = 0;

out:
	if (sas_device)
		sas_device_put(sas_device);

	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

}

/**
 * _hst2dr_enclosure_dev_status_change_event_debug - debug for enclosure
 * event
 * @ioa: per adapter object
 * @event_data: event data payload
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_enclosure_dev_status_change_event_debug(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_SAS_ENCLOSURE_DEV_STATUS_CHANGE *event_data)
{
	char *reason_str = NULL;

	switch (event_data->reason_code) {
	case SSI2_EVENT_SAS_ENCL_RC_ADDED:
		reason_str = "enclosure add";
		break;
	case SSI2_EVENT_SAS_ENCL_RC_NOT_RESPONDING:
		reason_str = "enclosure remove";
		break;
	default:
		reason_str = "unknown reason";
		break;
	}

	log_event(ioa, "%s (%s)\n\t%s(0x%04x), %s(0x%016llx) %s(%d)\n",
		"enclosure status change:", reason_str,
		"handle", le16_to_cpu(event_data->enclosure_handle),
		"enclosure logical id", (unsigned long long)
			le64_to_cpu(event_data->enclosure_logical_id),
		"number slots", le16_to_cpu(event_data->start_slot));
}

/**
 * _hst2dr_enclosure_dev_status_change_event - handle enclosure events
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_enclosure_dev_status_change_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	_hst2dr_enclosure_dev_status_change_event_debug(ioa,
		(SSI2_EVENT_DATA_SAS_ENCLOSURE_DEV_STATUS_CHANGE *)
		fw_event->event_data);
}

/**
 * _hst2dr_broadcast_primitive_event - handle broadcast events
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_broadcast_primitive_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	struct scsi_cmnd *scmd;
	struct scsi_device *sdev;
	u16 host_tag_id, handle;
	u32 lun;
	struct HST2DR_DEVICE *sas_device_priv_data;
	u32 termination_count;
	u32 query_count;
	SSI2_SCSI_TM_REPLY *ssi_reply;
	SSI2_EVENT_DATA_SAS_BC_PRIMITIVE *event_data =
		(SSI2_EVENT_DATA_SAS_BC_PRIMITIVE *)
		fw_event->event_data;
	u16 ioa_status;
	unsigned long flags;
	int r;
	u8 max_retries = 0;
	u8 task_abort_retries;

	mutex_lock(&ioa->tm_cmds.mutex);
	log_event(ioa,
		"%s: enter: phy number(%d), width(%d)\n",
		__func__, event_data->phy_num,
		event_data->port_width);

	_hst2dr_block_io_all_device(ioa);

	spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
	ssi_reply = ioa->tm_cmds.reply;
 broadcast_aen_retry:

	/* sanity checks for retrying this loop */
	if (max_retries++ == 5)
		goto out;

	termination_count = 0;
	query_count = 0;
	for (host_tag_id = 0; host_tag_id < ioa->scsiio_depth; host_tag_id++) {
		if (ioa->shost_recovery)
			goto out;
		scmd = _hst2dr_scsi_lookup_get(ioa, host_tag_id);
		if (!scmd)
			continue;
		sdev = scmd->device;
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data || !sas_device_priv_data->sas_target)
			continue;
		 /* skip volumes */
		if (sas_device_priv_data->sas_target->flags &
				HST2DR_TARGET_FLAGS_VOLUME)
			continue;
			 /* skip hidden raid components */
		if (sas_device_priv_data->sas_target->flags &
			HST2DR_TARGET_FLAGS_RAID_COMPONENT)
			continue;
		handle = sas_device_priv_data->sas_target->handle;
		lun = sas_device_priv_data->lun;
		query_count++;

		if (ioa->shost_recovery)
			goto out;

		spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);
		r = hst2dr_issue_tm(ioa, handle, 0, 0, lun,
			SSI2_SCSITASKMGMT_TASKTYPE_QUERY_TASK,
			host_tag_id, TM_WAITING);
		if (r == FAILED) {
			sdev_printk(KERN_WARNING, sdev,
				"%s QUERY_TASK: scmd(%p)\n",
				"hst2dr_issue_tm: FAILED when sending",
				scmd);
			spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
			goto broadcast_aen_retry;
		}
		ioa_status = le16_to_cpu(ssi_reply->status)
			& SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
			sdev_printk(KERN_WARNING, sdev,
				"%s IOASTATUS(0x%04x), scmd(%p)\n",
				"query task: FAILED with",
				ioa_status, scmd);
			spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
			goto broadcast_aen_retry;
		}

		/* see if IO is still owned by IOA and target */
		if (ssi_reply->response_code ==
				SSI2_SCSITASKMGMT_RSP_TM_SUCCEEDED ||
				ssi_reply->response_code ==
				SSI2_SCSITASKMGMT_RSP_IO_QUEUED_ON_IOA) {
			spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
			continue;
		}
		task_abort_retries = 0;
tm_retry:
		if (task_abort_retries++ == 60) {
			spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
			goto broadcast_aen_retry;
		}

		if (ioa->shost_recovery)
			goto out_no_lock;

		r = hst2dr_issue_tm(ioa, handle, sdev->channel, sdev->id,
			sdev->lun, SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK,
			host_tag_id, TM_WAITING);
		if (r == FAILED) {
			sdev_printk(KERN_WARNING, sdev, "%s FAILED: scmd(%p)\n",
				"hst2dr_issue_tm: ABORT_TASK:",
				scmd);
			goto tm_retry;
		}

		if (task_abort_retries > 1)
			sdev_printk(KERN_WARNING, sdev,
				"%s RETRIES (%d): scmd(%p)\n",
				"hst2dr_issue_tm: ABORT_TASK:",
				task_abort_retries - 1, scmd);

		termination_count += le32_to_cpu(ssi_reply->termination_count);
		spin_lock_irqsave(&ioa->scsi_lookup_lock, flags);
	}

	if (ioa->broadcast_aen_pending) {
		ioa->broadcast_aen_pending = 0;
		goto broadcast_aen_retry;
	}

 out:
	spin_unlock_irqrestore(&ioa->scsi_lookup_lock, flags);
 out_no_lock:

	ioa->broadcast_aen_busy = 0;
	if (!ioa->shost_recovery)
		_hst2dr_unblock_io_all_device(ioa);
	mutex_unlock(&ioa->tm_cmds.mutex);
}

/**
 * _hst2dr_discovery_event - handle discovery events
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_discovery_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	SSI2_EVENT_DATA_SAS_DISCOVERY *event_data =
		(SSI2_EVENT_DATA_SAS_DISCOVERY *) fw_event->event_data;

	if (event_data->reason_code == SSI2_EVENT_SAS_DISC_RC_STARTED &&
			!ioa->sas_hba.num_phys) {
		if (disable_discovery > 0 && ioa->shost_recovery) {
			/* Wait for the reset to complete */
			while (ioa->shost_recovery)
				ssleep(1);
		}
		_hst2dr_host_add(ioa);
	}
}

/**
 * _hst2dr_reprobe_lun - reprobing lun
 * @sdev: scsi device struct
 * @no_uld_attach: sdev->no_uld_attach flag setting
 *
 **/
static void
_hst2dr_reprobe_lun(struct scsi_device *sdev, void *no_uld_attach)
{
	sdev->no_uld_attach = no_uld_attach ? 1 : 0;
	sdev_printk(KERN_INFO, sdev, "%s raid component\n",
		sdev->no_uld_attach ? "hiding" : "exposing");
	WARN_ON(scsi_device_reprobe(sdev));
}


/**
 * _hst2dr_raid_device_add - add raid_device object
 * @ioa: per adapter object
 * @raid_device: raid_device object
 *
 * This is added to the raid_device_list link list.
 */
static void
_hst2dr_raid_device_add(struct HST2DR_ADAPTER *ioa,
	struct _raid_device *raid_device)
{
	unsigned long flags;

	log_always(ioa,
		"raid_device_add %s: handle(0x%04x), wwid(0x%016llx)\n",
		__func__, raid_device->handle,
		(unsigned long long)raid_device->wwid);

	spin_lock_irqsave(&ioa->raid_device_lock, flags);
	list_add_tail(&raid_device->list, &ioa->raid_device_list);
	spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
}

/**
 * _hst2dr_raid_device_remove - delete raid_device object
 * @ioa: per adapter object
 * @raid_device: raid_device object
 *
 */
static void
_hst2dr_raid_device_remove(struct HST2DR_ADAPTER *ioa,
	struct _raid_device *raid_device)
{
	unsigned long flags;

	spin_lock_irqsave(&ioa->raid_device_lock, flags);
	list_del_init(&raid_device->list);
	kfree(raid_device);
	spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
}
/**
 * _hst2dr_volume_add - add new volume
 * @ioa: per adapter object
 * @element: IR config element data
 * Context:user
 * Return nothing
 */

static void
_hst2dr_volume_add(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_IR_CONFIG_ELEMENT *element)
{
	struct _raid_device *raid_device;
	unsigned long flags;
	u64 wwid;
	u32 device_info;
	u16 handle = le16_to_cpu(element->vol_dev_handle);
	u16 qdepth;
	int rc;

	hst2dr_config_get_volume_wwid(ioa, handle, &wwid,
		&device_info, &qdepth);
	if (!wwid) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}


	spin_lock_irqsave(&ioa->raid_device_lock, flags);
	raid_device = _hst2dr_raid_device_find_by_wwid(ioa, wwid);
	spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
	if (raid_device) {
		log_error(ioa, "raid_device already added\n");
		return;
	}
	raid_device = kzalloc(sizeof(struct _raid_device), GFP_KERNEL);
	if (!raid_device) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}
	raid_device->id = ioa->sas_id++;
	raid_device->channel = RAID_CHANNEL;
	raid_device->handle = handle;
	raid_device->wwid = wwid;
	raid_device->device_info = device_info;
	raid_device->io_qdepth = qdepth;
	_hst2dr_raid_device_add(ioa, raid_device);
	if (!ioa->wait_for_discovery_to_complete) {
		rc = scsi_add_device(ioa->shost, RAID_CHANNEL,
			raid_device->id, 0);
		if (rc) {
			log_error(ioa, "%s raid_device_remove\n", __func__);
			_hst2dr_raid_device_remove(ioa, raid_device);
		}

	}

}
/**
 * _hst2dr_sas_volume_delete - delete volume
 * @ioa: per adapter object
 * @handle: volume device handle
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_sas_volume_delete(struct HST2DR_ADAPTER *ioa, u16 handle)
{
	struct _raid_device *raid_device;
	unsigned long flags;
	struct HST2DR_TARGET *sas_target_priv_data;
	struct scsi_target *starget = NULL;

	spin_lock_irqsave(&ioa->raid_device_lock, flags);
	raid_device = _hst2dr_raid_device_find_by_handle(ioa, handle);
	if (raid_device) {
		if (raid_device->starget) {
			starget = raid_device->starget;
			sas_target_priv_data = starget->hostdata;
			sas_target_priv_data->deleted = 1;
		}
		log_always(ioa, "removing handle(0x%04x), wwid(0x%016llx)\n",
			raid_device->handle,
			(unsigned long long) raid_device->wwid);
		list_del_init(&raid_device->list);
		kfree(raid_device);
	}
	spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
	if (starget)
		scsi_remove_target(&starget->dev);
}

/**
 * _hst2dr_pd_expose - expose pd component to /dev/sdX
 * @ioa: per adapter object
 * @element: IR config element data
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_pd_expose(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_IR_CONFIG_ELEMENT *element)
{
	struct _sas_device *sas_device;
	struct scsi_target *starget = NULL;
	struct HST2DR_TARGET *sas_target_priv_data;
	unsigned long flags;
	u16 handle = le16_to_cpu(element->phys_disk_dev_handle);

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_handle(ioa, handle);
	if (sas_device) {
		sas_device->volume_handle = 0;
		sas_device->volume_wwid = 0;
		clear_bit(handle, ioa->pd_handles);
		if (sas_device->starget && sas_device->starget->hostdata) {
			starget = sas_device->starget;
			sas_target_priv_data = starget->hostdata;
			sas_target_priv_data->flags &=
				~HST2DR_TARGET_FLAGS_RAID_COMPONENT;
		}
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	if (!sas_device)
		return;
	/* exposing raid component */
	if (starget)
		starget_for_each_device(starget, NULL, _hst2dr_reprobe_lun);

	sas_device_put(sas_device);
}

/**
 * _hst2dr_pd_hide - hide pd component from /dev/sdX
 * @ioa: per adapter object
 * @element: IR config element data
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_pd_hide(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_IR_CONFIG_ELEMENT *element)
{
	struct _sas_device *sas_device;
	struct scsi_target *starget = NULL;
	struct HST2DR_TARGET *sas_target_priv_data;
	unsigned long flags;
	u16 handle = le16_to_cpu(element->phys_disk_dev_handle);
	u16 volume_handle = 0;
	u64 volume_wwid = 0;
	u32 device_info = 0;
	u16 qdepth;

	hst2dr_config_get_volume_handle(ioa, handle, &volume_handle);
	if (volume_handle)
		hst2dr_config_get_volume_wwid(ioa, volume_handle,
			&volume_wwid, &device_info, &qdepth);

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_handle(ioa, handle);
	if (sas_device) {
		set_bit(handle, ioa->pd_handles);
		if (sas_device->starget && sas_device->starget->hostdata) {
			starget = sas_device->starget;
			sas_target_priv_data = starget->hostdata;
			sas_target_priv_data->flags |=
				HST2DR_TARGET_FLAGS_RAID_COMPONENT;
			sas_device->volume_handle = volume_handle;
			sas_device->volume_wwid = volume_wwid;
		}
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	if (!sas_device)
		return;

	if (starget)
		starget_for_each_device(starget, (void *)1,
			_hst2dr_reprobe_lun);

	sas_device_put(sas_device);
}

/**
 * _hst2dr_sas_pd_add - remove pd component
 * @ioa: per adapter object
 * @element: IR config element data
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_pd_add(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_IR_CONFIG_ELEMENT *element)
{
	struct _sas_device *sas_device;
	u16 handle = le16_to_cpu(element->phys_disk_dev_handle);
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_SAS_DEV sas_device_pg0;
	u32 status;
	u64 sas_address;
	u16 parent_handle;

	set_bit(handle, ioa->pd_handles);
	sas_device = hst2dr_get_sdev_by_handle(ioa, handle);
	if (sas_device) {
		sas_device_put(sas_device);
		return;
	}

	if ((hst2dr_cfg_get_sas_dev(ioa, &ssi_reply, &sas_device_pg0,
			SSI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}

	status = le16_to_cpu(ssi_reply.status) &
		SSI2_IOASTATUS_MASK;
	if (status != SSI2_IOASTATUS_SUCCESS) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}

	parent_handle = le16_to_cpu(sas_device_pg0.parent_dev_handle);
	if (!_hst2dr_get_sas_address(ioa, parent_handle, &sas_address))
		hst2dr_transport_update_links(ioa, sas_address, handle,
			sas_device_pg0.phy_num, SSI2_SAS_NEG_LINK_RATE_1_5);

	_hst2dr_add_device(ioa, handle, 0);
}

/**
 * _hst2dr_pd_delete - delete pd component
 * @ioa: per adapter object
 * @element: IR config element data
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_pd_delete(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_IR_CONFIG_ELEMENT *element)
{
	u16 handle = le16_to_cpu(element->phys_disk_dev_handle);

	_hst2dr_device_remove_by_handle(ioa, handle);
}
/**
 * _hst2dr_sas_ir_config_change_event_debug - debug for IR Config Change events
 * @ioa: per adapter object
 * @event_data: event data payload
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_ir_config_change_event_debug(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_IR_CONFIG_CHANGE_LIST *event_data)
{
	SSI2_EVENT_IR_CONFIG_ELEMENT *element;
	u8 element_type;
	int i;
	char *reason_str = NULL, *element_str = NULL;

	element = (SSI2_EVENT_IR_CONFIG_ELEMENT *)
		&event_data->config_element[0];

	pr_info(HST2DR_FMT "raid config change: (%s), elements(%d)\n",
		ioa->name, (le32_to_cpu(event_data->flags) &
		SSI2_EVENT_IR_CHANGE_FLAGS_FOREIGN_CONFIG) ?
		"foreign" : "native", event_data->num_elements);
	for (i = 0; i < event_data->num_elements; i++, element++) {
		switch (element->reason_code) {
		case SSI2_EVENT_IR_CHANGE_RC_ADDED:
			reason_str = "add";
			break;
		case SSI2_EVENT_IR_CHANGE_RC_REMOVED:
			reason_str = "remove";
			break;
		case SSI2_EVENT_IR_CHANGE_RC_NO_CHANGE:
			reason_str = "no change";
			break;
		case SSI2_EVENT_IR_CHANGE_RC_HIDE:
			reason_str = "hide";
			break;
		case SSI2_EVENT_IR_CHANGE_RC_UNHIDE:
			reason_str = "unhide";
			break;
		case SSI2_EVENT_IR_CHANGE_RC_VOLUME_CREATED:
			reason_str = "volume_created";
			break;
		case SSI2_EVENT_IR_CHANGE_RC_VOLUME_DELETED:
			reason_str = "volume_deleted";
			break;
		case SSI2_EVENT_IR_CHANGE_RC_PD_CREATED:
			reason_str = "pd_created";
			break;
		case SSI2_EVENT_IR_CHANGE_RC_PD_DELETED:
			reason_str = "pd_deleted";
			break;
		default:
			reason_str = "unknown reason";
			break;
		}
		element_type = le16_to_cpu(element->element_flags) &
			SSI2_EVENT_IR_CHANGE_EFLAGS_ELEMENT_TYPE_MASK;
		switch (element_type) {
		case SSI2_EVENT_IR_CHANGE_EFLAGS_VOLUME_ELEMENT:
			element_str = "volume";
			break;
		case SSI2_EVENT_IR_CHANGE_EFLAGS_VOLPHYSDISK_ELEMENT:
			element_str = "phys disk";
			break;
		case SSI2_EVENT_IR_CHANGE_EFLAGS_HOTSPARE_ELEMENT:
			element_str = "hot spare";
			break;
		default:
			element_str = "unknown element";
			break;
		}
		pr_info("\t(%s:%s), %s(0x%04x), %s(0x%04x), %s(0x%02x)\n",
			element_str, reason_str,
			"vol handle", le16_to_cpu(element->vol_dev_handle),
			"pd handle", le16_to_cpu(element->phys_disk_dev_handle),
			"pd num", element->phys_logic_id);
	}
}
/**
 * _hst2dr_ir_config_change_event - handle ir configuration change events
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */

static void
_hst2dr_ir_config_change_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	u8 foreign_config;
	int i;
	SSI2_EVENT_IR_CONFIG_ELEMENT *element;
	SSI2_EVENT_DATA_IR_CONFIG_CHANGE_LIST *event_data =
	(SSI2_EVENT_DATA_IR_CONFIG_CHANGE_LIST *) fw_event->event_data;
	SSI2_INQUIRY_RAID_VOL vol_pg0;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	struct _raid_device *raid_device;
	unsigned long flags;

	if (ioa->log_level & LOG_DEBUG)
		_hst2dr_ir_config_change_event_debug(ioa, event_data);

	foreign_config = (le32_to_cpu(event_data->flags) &
		SSI2_EVENT_IR_CHANGE_FLAGS_FOREIGN_CONFIG) ? 1 : 0;
	element = (SSI2_EVENT_IR_CONFIG_ELEMENT *)
		&event_data->config_element[0];

	if (ioa->shost_recovery)
		return;

	for (i = 0; i < event_data->num_elements; i++, element++) {
		switch (element->reason_code) {
		case SSI2_EVENT_IR_CHANGE_RC_VOLUME_CREATED:
		case SSI2_EVENT_IR_CHANGE_RC_ADDED:
			if (!foreign_config)
				_hst2dr_volume_add(ioa, element);
			spin_lock_irqsave(&ioa->raid_device_lock, flags);
			raid_device = _hst2dr_raid_device_find_by_handle(ioa,
				le16_to_cpu(element->vol_dev_handle));
			spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
			if (raid_device == NULL) {
				log_warn(ioa, "%s %d raid_device:NULL\n",
					__func__, __LINE__);
				return;
			}
			if ((hst2dr_cfg_get_raid_vol(ioa, &ssi_reply,
					&vol_pg0, sizeof(vol_pg0),
					SSI2_RAID_VOLUME_PGAD_FORM_HANDLE,
					raid_device->handle))) {
				log_warn(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				return;
			}

			raid_device->volume_type = vol_pg0.volume_type;

			break;
		case SSI2_EVENT_IR_CHANGE_RC_VOLUME_DELETED:
		case SSI2_EVENT_IR_CHANGE_RC_REMOVED:
			if (!foreign_config)
				_hst2dr_sas_volume_delete(ioa,
					le16_to_cpu(element->vol_dev_handle));
			break;
		case SSI2_EVENT_IR_CHANGE_RC_PD_CREATED:
			_hst2dr_pd_hide(ioa, element);
			break;
		case SSI2_EVENT_IR_CHANGE_RC_PD_DELETED:
			_hst2dr_pd_expose(ioa, element);
			break;
		case SSI2_EVENT_IR_CHANGE_RC_HIDE:
			_hst2dr_pd_add(ioa, element);
			_hst2dr_pd_expose(ioa, element);
			break;
		case SSI2_EVENT_IR_CHANGE_RC_UNHIDE:
			_hst2dr_pd_delete(ioa, element);

		default:
			break;
		}
	}
}

/**
 * _hst2dr_ir_volume_event - IR volume event
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_ir_volume_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	u64 wwid;
	u32 device_info;
	unsigned long flags;
	struct _raid_device *raid_device;
	u16 handle;
	u32 state;
	int rc;
	u16 qdepth;
	SSI2_EVENT_DATA_IR_VOLUME *event_data =
		(SSI2_EVENT_DATA_IR_VOLUME *) fw_event->event_data;

	if (ioa->shost_recovery)
		return;

	if (event_data->reason_code != SSI2_EVENT_IR_VOLUME_RC_STATE_CHANGED)
		return;

	handle = le16_to_cpu(event_data->vol_dev_handle);
	state = le32_to_cpu(event_data->new_value);
	log_event(ioa, HST2DR_FMT
		"%s: handle(0x%04x), old(0x%08x), new(0x%08x)\n",
		ioa->name, __func__,  handle,
		le32_to_cpu(event_data->previous_value), state);
	switch (state) {
	case SSI2_RAID_VOL_STATE_MISSING:
	case SSI2_RAID_VOL_STATE_FAILED:
		_hst2dr_sas_volume_delete(ioa, handle);
		break;

	case SSI2_RAID_VOL_STATE_PART_OPTIMAL:
	case SSI2_RAID_VOL_STATE_DEGRADED:
	case SSI2_RAID_VOL_STATE_OPTIMAL:

		spin_lock_irqsave(&ioa->raid_device_lock, flags);
		raid_device = _hst2dr_raid_device_find_by_handle(ioa, handle);
		spin_unlock_irqrestore(&ioa->raid_device_lock, flags);

		if (raid_device) {
			_hst2dr_set_volume_unblock_flag(ioa, handle);
			break;
		}
		hst2dr_config_get_volume_wwid(ioa, handle, &wwid,
			&device_info, &qdepth);
		if (!wwid) {
			log_error(ioa, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			break;
		}

		raid_device = kzalloc(sizeof(struct _raid_device), GFP_KERNEL);
		if (!raid_device) {
			log_error(ioa, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			break;
		}

		raid_device->id = ioa->sas_id++;
		raid_device->channel = RAID_CHANNEL;
		raid_device->handle = handle;
		raid_device->wwid = wwid;
		raid_device->device_info = device_info;
		raid_device->io_qdepth = qdepth;
		_hst2dr_raid_device_add(ioa, raid_device);
		rc = scsi_add_device(ioa->shost, RAID_CHANNEL,
			raid_device->id, 0);
		if (rc)
			_hst2dr_raid_device_remove(ioa, raid_device);
		break;

	default:
		break;
	}
}

/**
 * _hst2dr_ir_physical_disk_event - PD event
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_ir_physical_disk_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	u16 handle, parent_handle;
	u32 state;
	struct _sas_device *sas_device;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_SAS_DEV sas_device_pg0;
	u32 ioa_status;
	SSI2_EVENT_DATA_IR_PHYSICAL_DISK *event_data =
		(SSI2_EVENT_DATA_IR_PHYSICAL_DISK *) fw_event->event_data;
	u64 sas_address;

	if (ioa->shost_recovery)
		return;

	if (event_data->reason_code != SSI2_EVENT_IR_PHYSDISK_RC_STATE_CHANGED)
		return;

	handle = le16_to_cpu(event_data->phys_disk_dev_handle);
	state = le32_to_cpu(event_data->new_value);

	log_event(ioa, "%s: handle(0x%04x), old(0x%08x), new(0x%08x)\n",
		__func__, handle, le32_to_cpu(event_data->previous_value),
		state);

	switch (state) {
	case SSI2_RAID_PD_STATE_ONLINE:
	case SSI2_RAID_PD_STATE_DEGRADED:
	case SSI2_RAID_PD_STATE_REBUILDING:
	case SSI2_RAID_PD_STATE_OPTIMAL:
	case SSI2_RAID_PD_STATE_HOT_SPARE:

		set_bit(handle, ioa->pd_handles);

		sas_device = hst2dr_get_sdev_by_handle(ioa, handle);
		if (sas_device) {
			sas_device_put(sas_device);
			return;
		}

		if ((hst2dr_cfg_get_sas_dev(ioa, &ssi_reply,
				&sas_device_pg0,
				SSI2_SAS_DEVICE_PGAD_FORM_HANDLE,
				handle))) {
			log_error(ioa, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			return;
		}

		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
			log_error(ioa, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			return;
		}

		parent_handle = le16_to_cpu(sas_device_pg0.parent_dev_handle);
		if (!_hst2dr_get_sas_address(ioa, parent_handle, &sas_address))
			hst2dr_transport_update_links(ioa, sas_address, handle,
				sas_device_pg0.phy_num,
				SSI2_SAS_NEG_LINK_RATE_1_5);

		_hst2dr_add_device(ioa, handle, 0);

		break;

	case SSI2_RAID_PD_STATE_OFFLINE:
	case SSI2_RAID_PD_STATE_NOT_CONFIGURED:
	case SSI2_RAID_PD_STATE_NOT_COMPATIBLE:
	default:
		break;
	}
}
/**
 * _hst2dr_ir_operation_status_event_log - debug for IR operation event
 * @ioa: per adapter object
 * @event_data: event data payload
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_ir_operation_status_event_log(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_DATA_IR_OPERATION_STATUS *event_data)
{
	char *reason_str = NULL;

	switch (event_data->raid_operation) {
	case SSI2_EVENT_IR_RAIDOP_RESYNC:
		reason_str = "resync";
		break;
	case SSI2_EVENT_IR_RAIDOP_ONLINE_CAP_EXPANSION:
		reason_str = "online capacity expansion";
		break;
	case SSI2_EVENT_IR_RAIDOP_CONSISTENCY_CHECK:
		reason_str = "consistency check";
		break;
	case SSI2_EVENT_IR_RAIDOP_BACKGROUND_INIT:
		reason_str = "background init";
		break;
	case SSI2_EVENT_IR_RAIDOP_MAKE_DATA_CONSISTENT:
		reason_str = "make data consistent";
		break;
	}

	if (!reason_str)
		return;

	log_event(ioa, HST2DR_FMT
		"%s (%s)\thandle(0x%04x), percent complete(%d)\n",
		ioa->name, "raid operational status:", reason_str,
		le16_to_cpu(event_data->vol_dev_handle),
		event_data->percent_complete);
}
/**
 * _hst2dr_ir_operation_status_event - handle RAID operation events
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_ir_operation_status_event(struct HST2DR_ADAPTER *ioa,
	struct fw_event_work *fw_event)
{
	SSI2_EVENT_DATA_IR_OPERATION_STATUS *event_data =
		(SSI2_EVENT_DATA_IR_OPERATION_STATUS *)
		fw_event->event_data;
	static struct _raid_device *raid_device;
	unsigned long flags;
	u16 handle;

	_hst2dr_ir_operation_status_event_log(ioa, event_data);
	/* code added for raid transport support */
	if (event_data->raid_operation == SSI2_EVENT_IR_RAIDOP_RESYNC) {

		spin_lock_irqsave(&ioa->raid_device_lock, flags);
		handle = le16_to_cpu(event_data->vol_dev_handle);
		raid_device = _hst2dr_raid_device_find_by_handle(ioa, handle);
		if (raid_device)
			raid_device->percent_complete =
				event_data->percent_complete;
		spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
	}
}
/**
 * _hst2dr_prep_device_scan - initialize parameters prior to device scan
 * @ioa: per adapter object
 *
 * Set the deleted flag prior to device scan.  If the device is found during
 * the scan, then we clear the deleted flag.
 */
static void
_hst2dr_prep_device_scan(struct HST2DR_ADAPTER *ioa)
{
	struct HST2DR_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;

	shost_for_each_device(sdev, ioa->shost) {
		sas_device_priv_data = sdev->hostdata;
		if (sas_device_priv_data && sas_device_priv_data->sas_target)
			sas_device_priv_data->sas_target->deleted = 1;
	}
}

/**
 * _hst2dr_mark_responding_sas_device - mark a sas_devices as responding
 * @ioa: per adapter object
 * @pg0800: SAS Device page 0
 *
 * After host reset, find out whether devices are still responding.
 * Used in _hst2dr_remove_unresponsive_sas_devices.
 *
 * Return nothing.
 */
static void
_hst2dr_mark_responding_sas_device(struct HST2DR_ADAPTER *ioa,
SSI2_INQUIRY_SAS_DEV *sas_dev00)
{
	struct HST2DR_TARGET *sas_target_priv_data = NULL;
	struct scsi_target *starget;
	struct _sas_device *sas_device = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	list_for_each_entry(sas_device, &ioa->sas_device_list, list) {
		if ((sas_device->sas_address == sas_dev00->sas_address) &&
			(sas_device->slot == sas_dev00->slot)) {
			sas_device->responding = 1;
			starget = sas_device->starget;
			if (starget && starget->hostdata) {
				sas_target_priv_data = starget->hostdata;
				sas_target_priv_data->tm_busy = 0;
				sas_target_priv_data->deleted = 0;
			} else
				sas_target_priv_data = NULL;
			if (starget) {
				starget_printk(KERN_INFO, starget,
					"handle(0x%04x), sas_addr(0x%016llx)\n",
					sas_dev00->dev_handle,
					(unsigned long long)
					sas_device->sas_address);

				if (sas_device->enclosure_handle != 0)
					starget_printk(KERN_INFO, starget,
					"%s(0x%016llx), slot(%d)\n",
					"enclosure logical id",
					(unsigned long long)
						sas_device->enclosure_logical_id,
					sas_device->slot);
			}
			if (sas_dev00->flags &
					SSI2_SAS_DEVICE0_FLAGS_ENCL_LEVEL_VALID) {
				sas_device->enclosure_level =
					sas_dev00->enclosure_handle;
				memcpy(&sas_device->connector_name[0],
					&sas_dev00->connector_name[0], 4);
			} else {
				sas_device->enclosure_level = 0;
				sas_device->connector_name[0] = '\0';
			}

			_hst2dr_get_enclosure_logicalid_chassis_slot(ioa,
				sas_dev00, sas_device);

			if (sas_device->handle == sas_dev00->dev_handle)
				goto out;
			log_event(ioa, "\thandle changed from(0x%04x)!\n",
				sas_device->handle);
			sas_device->handle = sas_dev00->dev_handle;
			if (sas_target_priv_data)
				sas_target_priv_data->handle =
					sas_dev00->dev_handle;
			goto out;
		}
	}
 out:
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
}

/**
 * _hst2dr_search_responding_sas_devices -
 * @ioa: per adapter object
 *
 * After host reset, find out whether devices are still responding.
 * If not remove.
 *
 * Return nothing.
 */
static void
_hst2dr_search_responding_sas_devices(struct HST2DR_ADAPTER *ioa)
{
	SSI2_INQUIRY_SAS_DEV sas_dev00;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	u16 ioa_status;
	u16 handle;
	u32 device_info;

	log_reset(ioa, "search for end-devices: start\n");

	if (list_empty(&ioa->sas_device_list))
		goto out;

	handle = 0xFFFF;
	while (!(hst2dr_cfg_get_sas_dev(ioa, &ssi_reply,
			&sas_dev00, SSI2_SAS_DEVICE_PGAD_FORM_GET_NEXT_HANDLE,
			handle))) {
		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS)
			break;
		handle = sas_dev00.dev_handle =
				le16_to_cpu(sas_dev00.dev_handle);
		device_info = le32_to_cpu(sas_dev00.dev_info);
		if (!(_hst2dr_is_end_device(device_info)))
			continue;
		sas_dev00.sas_address =
				le64_to_cpu(sas_dev00.sas_address);
		sas_dev00.slot = le16_to_cpu(sas_dev00.slot);
		sas_dev00.flags = le16_to_cpu(sas_dev00.flags);
		_hst2dr_mark_responding_sas_device(ioa, &sas_dev00);
	}

 out:
	log_reset(ioa, "search for end-devices: complete\n");
}
/**
 * _hst2dr_mark_responding_raid_device - mark a raid_device as responding
 * @ioa: per adapter object
 * @wwid: world wide identifier for raid volume
 * @handle: device handle
 *
 * After host reset, find out whether devices are still responding.
 * Used in _scsih_remove_unresponsive_raid_devices.
 */
static void
_hst2dr_mark_responding_raid_device(struct HST2DR_ADAPTER *ioa, u64 wwid,
	u16 handle)
{
	struct HST2DR_TARGET *sas_target_priv_data = NULL;
	struct scsi_target *starget;
	struct _raid_device *raid_device;
	unsigned long flags;

	spin_lock_irqsave(&ioa->raid_device_lock, flags);
	list_for_each_entry(raid_device, &ioa->raid_device_list, list) {
		if (raid_device->wwid == wwid && raid_device->starget) {
			starget = raid_device->starget;
			if (starget && starget->hostdata) {
				sas_target_priv_data = starget->hostdata;
				sas_target_priv_data->deleted = 0;
			} else
				sas_target_priv_data = NULL;
			raid_device->responding = 1;
			spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
			starget_printk(KERN_INFO, raid_device->starget,
				"handle(0x%04x), wwid(0x%016llx)\n", handle,
				(unsigned long long)raid_device->wwid);

			spin_lock_irqsave(&ioa->raid_device_lock, flags);
			if (raid_device->handle == handle) {
				spin_unlock_irqrestore(&ioa->raid_device_lock,
					flags);
				return;
			}
			pr_info("\thandle changed from(0x%04x)!!!\n",
				raid_device->handle);
			raid_device->handle = handle;
			if (sas_target_priv_data)
				sas_target_priv_data->handle = handle;
			spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
			return;
		}
	}
	spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
}

/**
 * _hst2dr_search_responding_raid_devices -
 * @ioa: per adapter object
 *
 * After host reset, find out whether devices are still responding.
 * If not remove.
 */
static void
_hst2dr_search_responding_raid_devices(struct HST2DR_ADAPTER *ioa)
{
	SSI2_INQUIRY_RAID_INFO volume_pg1;
	SSI2_INQUIRY_RAID_VOL volume_pg0;
	SSI2_INQUIRY_RAID_PD pd_pg0;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	u16 ioa_status;
	u16 handle;
	u16 phys_logic_id;
	int n;
	u64 vol_handles;

	if (!ioa->ir_firmware)
		return;

	log_reset(ioa, "search for raid volumes: start\n");

	if (list_empty(&ioa->raid_device_list))
		goto out;

	hst2dr_config_get_raid_handles(ioa, &vol_handles);
	for (n = 0 ; n < 64; n++) {
		if ((vol_handles & ((u64)1 << n)) == 0)
			handle = 0x800 + n;
		else
			continue;

		if (hst2dr_cfg_get_raid_vol(ioa, &ssi_reply,
				&volume_pg0,
				sizeof(SSI2_INQUIRY_RAID_VOL),
				SSI2_RAID_VOLUME_PGAD_FORM_HANDLE,
				handle))
			continue;
		if (hst2dr_cfg_get_raid_info(ioa, &ssi_reply,
				&volume_pg1,
				SSI2_RAID_VOLUME_PGAD_FORM_HANDLE,
				handle))
			continue;
		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS)
			break;
		handle = le16_to_cpu(volume_pg1.dev_handle);
		if (volume_pg0.volume_state == SSI2_RAID_VOL_STATE_OPTIMAL ||
				volume_pg0.volume_state ==
				SSI2_RAID_VOL_STATE_PART_OPTIMAL ||
				volume_pg0.volume_state ==
				SSI2_RAID_VOL_STATE_DEGRADED)
			_hst2dr_mark_responding_raid_device(ioa,
				le64_to_cpu(volume_pg1.WWID), handle);
	}

	/* refresh the pd_handles */
	phys_logic_id = 0xFFFF;
	memset(ioa->pd_handles, 0, ioa->pd_handles_sz);
	while (!(hst2dr_cfg_get_raid_pd(ioa, &ssi_reply,
			&pd_pg0,
			SSI2_PHYSDISK_PGAD_FORM_GET_NEXT_PHYSDISKNUM,
			phys_logic_id))) {
		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS)
			break;
		phys_logic_id = pd_pg0.phys_logic_id;
		handle = le16_to_cpu(pd_pg0.dev_handle);
		set_bit(handle, ioa->pd_handles);
	}
 out:
	log_reset(ioa, "search for responding raid volumes: complete\n");
}

/**
 * _hst2dr_mark_responding_expander - mark a expander as responding
 * @ioa: per adapter object
 * @pg0E00:SAS Expander Config Page0
 *
 * After host reset, find out whether devices are still responding.
 * Used in _hst2dr_remove_unresponsive_expanders.
 *
 * Return nothing.
 */
static void
_hst2dr_mark_responding_expander(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_EXPANDER *expander)
{
	struct _sas_node *sas_expander = NULL;
	unsigned long flags;
	int i, encl_pg0_rc = -1;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_ENCLOSURE enclosure;
	u16 handle = le16_to_cpu(expander->dev_handle);
	u64 sas_address = le64_to_cpu(expander->sas_address);

	if (le16_to_cpu(expander->enclosure_handle)) {
		encl_pg0_rc = hst2dr_cfg_get_enclosure(ioa, &ssi_reply,
			&enclosure, SSI2_SAS_ENCLOS_PGAD_FORM_HANDLE,
			le16_to_cpu(expander->enclosure_handle));
		if (encl_pg0_rc)
			log_event(ioa,
				"%s for handle(0x%04x)\n",
				"Enclosure Pg0 read failed",
				le16_to_cpu(expander->enclosure_handle));
	}

	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	list_for_each_entry(sas_expander, &ioa->sas_expander_list, list) {
		if (sas_expander->sas_address != sas_address)
			continue;
		sas_expander->responding = 1;

		if (!encl_pg0_rc)
			sas_expander->enclosure_logical_id =
				le64_to_cpu(enclosure.enclosure_logical_id);

		sas_expander->enclosure_handle =
			le16_to_cpu(expander->enclosure_handle);

		if (sas_expander->handle == handle)
			goto out;
		log_event(ioa, "\t%s(0x%016llx): %s(0x%04x) %s (0x%04x)!\n",
			"expander",
			(unsigned long long)sas_expander->sas_address,
			"handle changed from", sas_expander->handle,
			"to", handle);
		sas_expander->handle = handle;
		for (i = 0; i < sas_expander->num_phys; i++)
			sas_expander->phy[i].handle = handle;
		goto out;
	}
 out:
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
}

/**
 * _hst2dr_search_responding_expanders -
 * @ioa: per adapter object
 *
 * After host reset, find out whether expanders are still responding.
 * If not remove.
 *
 * Return nothing.
 */
static void
_hst2dr_search_responding_expanders(struct HST2DR_ADAPTER *ioa)
{
	SSI2_INQUIRY_EXPANDER expander;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	u16 ioa_status;
	u64 sas_address;
	u16 handle;

	log_event(ioa, "search for expanders: start\n");

	if (list_empty(&ioa->sas_expander_list))
		goto out;

	handle = 0xFFFF;
	while (!(hst2dr_cfg_get_expander(ioa, &ssi_reply, &expander,
			SSI2_SAS_EXPAND_PGAD_FORM_GET_NEXT_HNDL, handle))) {

		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS)
			break;

		handle = le16_to_cpu(expander.dev_handle);
		sas_address = le64_to_cpu(expander.sas_address);
		log_event(ioa,
			"\t%s handle(0x%04x), sas_addr(0x%016llx)\n",
			"expander present:",
			handle,
			(unsigned long long)sas_address);
		_hst2dr_mark_responding_expander(ioa, &expander);
	}

 out:
	log_event(ioa, "search for expanders: complete\n");
}

/**
 * _hst2dr_remove_unresponding_devices - removing unresponding devices
 * @ioa: per adapter object
 *
 * Return nothing.
 */
static void
_hst2dr_remove_unresponding_devices(struct HST2DR_ADAPTER *ioa)
{
	struct _sas_device *sas_device, *sas_device_next;
	struct _raid_device *raid_device, *raid_device_next;
	struct _sas_node *sas_expander, *sas_expander_next;
	struct list_head tmp_list;
	unsigned long flags;
	LIST_HEAD(head);

	log_scsi(ioa, "removing unresponding devices: start\n");

	/* removing unresponding end devices */
	log_scsi(ioa, "removing unresponding devices: end-devices\n");
	/*
	 * Iterate, pulling off devices marked as non-responding. We become the
	 * owner for the reference the list had on any object we prune.
	 */
	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	list_for_each_entry_safe(sas_device, sas_device_next,
			&ioa->sas_device_list, list) {
		if (!sas_device->responding)
			list_move_tail(&sas_device->list, &head);
		else
			sas_device->responding = 0;
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	/* removing unresponding volumes */
	if (ioa->ir_firmware) {
		log_scsi(ioa, "removing unresponding devices: volumes\n");
		list_for_each_entry_safe(raid_device, raid_device_next,
		    &ioa->raid_device_list, list) {
			if (!raid_device->responding)
				_hst2dr_sas_volume_delete(ioa,
				    raid_device->handle);
			else
				raid_device->responding = 0;
		}
	}

	/*
	 * Now, uninitialize and remove the unresponding devices we pruned.
	 */
	list_for_each_entry_safe(sas_device, sas_device_next, &head, list) {
		_hst2dr_remove_device(ioa, sas_device);
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}

	/* removing unresponding expanders */
	log_scsi(ioa, "removing unresponding devices: expanders\n");
	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	INIT_LIST_HEAD(&tmp_list);
	list_for_each_entry_safe(sas_expander, sas_expander_next,
		&ioa->sas_expander_list, list) {
		if (!sas_expander->responding)
			list_move_tail(&sas_expander->list, &tmp_list);
		else
			sas_expander->responding = 0;
	}
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
	list_for_each_entry_safe(sas_expander, sas_expander_next, &tmp_list,
			list) {
		_hst2dr_expander_node_remove(ioa, sas_expander);
	}

	log_scsi(ioa, "removing unresponding devices: complete\n");

	/* unblock devices */
	_hst2dr_unblock_io_all_device(ioa);
}

static void
_hst2dr_refresh_expander_links(struct HST2DR_ADAPTER *ioa,
	struct _sas_node *sas_expander, u16 handle)
{
	SSI2_INQUIRY_EXPANDER_PHY expander_phy, *pexpander_phy;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	int i;

	pexpander_phy = kcalloc(sas_expander->num_phys,
		sizeof(SSI2_INQUIRY_EXPANDER_PHY), GFP_KERNEL);
	if (!pexpander_phy) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}
	if ((hst2dr_cfg_get_expander_phy(ioa, &ssi_reply, pexpander_phy,
		sas_expander->num_phys | 0x8000, handle))) {
		kfree(pexpander_phy);
		for (i = 0; i < sas_expander->num_phys; i++) {
			if ((hst2dr_cfg_get_expander_phy(ioa, &ssi_reply,
					&expander_phy, i, handle))) {
				log_error(ioa, "failure at %s:%d/%s()!\n",
					__FILE__, __LINE__, __func__);
				return;
			}

			hst2dr_transport_update_links(ioa,
				sas_expander->sas_address,
				le16_to_cpu(expander_phy.exp_dev_handle), i,
				expander_phy.negotiated_linkrate >> 4);
		}
	} else {
		for (i = 0; i < sas_expander->num_phys; i++) {
			hst2dr_transport_update_links(ioa,
				sas_expander->sas_address,
				le16_to_cpu(pexpander_phy[i].exp_dev_handle),
				i,
				pexpander_phy[i].negotiated_linkrate >> 4);
		}
		kfree(pexpander_phy);
	}
}

/**
 * _hst2dr_scan_for_devices_after_reset - scan for devices after host reset
 * @ioa: per adapter object
 *
 * Return nothing.
 */
static void
_hst2dr_scan_for_devices_after_reset(struct HST2DR_ADAPTER *ioa)
{
	SSI2_INQUIRY_EXPANDER expander;
	SSI2_INQUIRY_SAS_DEV sas_dev00;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	SSI2_INQUIRY_RAID_INFO volume_pg1;
	SSI2_INQUIRY_RAID_VOL volume_pg0;
	SSI2_EVENT_IR_CONFIG_ELEMENT element;

	u8 retry_count;
	u16 ioa_status;
	u16 handle, parent_handle;
	u64 sas_address;
	struct _sas_device *sas_device;
	struct _sas_node *expander_device;
	static struct _raid_device *raid_device;
	unsigned long flags;
	int n;
	u64 vol_handles;


	log_event(ioa, "scan devices: start\n");

	_hst2dr_host_refresh(ioa);

	log_event(ioa, "\tscan devices: expanders start\n");

	/* expanders */
	handle = 0xFFFF;
	while (!(hst2dr_cfg_get_expander(ioa, &ssi_reply, &expander,
			SSI2_SAS_EXPAND_PGAD_FORM_GET_NEXT_HNDL, handle))) {
		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
			log_event(ioa,
				"\t%s ioa_status(0x%04x), loginfo(0x%08x)\n",
				"break from expander scan:",
				ioa_status,
				le32_to_cpu(ssi_reply.log_info));
			break;
		}
		handle = le16_to_cpu(expander.dev_handle);
		spin_lock_irqsave(&ioa->sas_node_lock, flags);
		expander_device = hst2dr_expander_find_by_sas_address(
			ioa, le64_to_cpu(expander.sas_address));
		spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
		if (expander_device)
			_hst2dr_refresh_expander_links(ioa, expander_device,
				handle);
		else {
			log_event(ioa,
				"\t%s handle (0x%04x), sas_addr(0x%016llx)\n",
				"BEFORE adding expander:",
				handle, (unsigned long long)
				le64_to_cpu(expander.sas_address));
			_hst2dr_expander_add(ioa, handle);
			log_event(ioa,
				"\t%s handle (0x%04x), sas_addr(0x%016llx)\n",
				"AFTER adding expander:",
				handle, (unsigned long long)
				le64_to_cpu(expander.sas_address));
		}
	}

	log_event(ioa, "\tscan devices: expanders complete\n");

	log_event(ioa, "\tscan devices: end devices start\n");

	/* sas devices */
	handle = 0xFFFF;
	while (!(hst2dr_cfg_get_sas_dev(ioa, &ssi_reply,
			&sas_dev00, SSI2_SAS_DEVICE_PGAD_FORM_GET_NEXT_HANDLE,
			handle))) {
		ioa_status = le16_to_cpu(ssi_reply.status) &
			SSI2_IOASTATUS_MASK;
		if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
			log_event(ioa,
				"\t%s ioa_status(0x%04x), loginfo(0x%08x)\n",
				"break from end device scan:",
				ioa_status,
				le32_to_cpu(ssi_reply.log_info));
			break;
		}
		handle = le16_to_cpu(sas_dev00.dev_handle);
		if (!(_hst2dr_is_end_device(
				le32_to_cpu(sas_dev00.dev_info))))
			continue;
		sas_device = hst2dr_get_sdev_by_addr(ioa,
			le64_to_cpu(sas_dev00.sas_address));
		if (sas_device) {
			sas_device_put(sas_device);
			continue;
		}
		parent_handle = le16_to_cpu(sas_dev00.parent_dev_handle);
		if (!_hst2dr_get_sas_address(ioa, parent_handle,
				&sas_address)) {
			log_event(ioa,
				"\t%s handle (0x%04x), sas_addr(0x%016llx)\n",
				"BEFORE adding end device:",
				handle, (unsigned long long)
				le64_to_cpu(sas_dev00.sas_address));
			hst2dr_transport_update_links(ioa, sas_address, handle,
				sas_dev00.phy_num, SSI2_SAS_NEG_LINK_RATE_1_5);
			retry_count = 0;
			/* This will retry adding the end device.
			 * _hst2dr_add_device() will decide on retries and
			 * return "1" when it should be retried
			 */
			while (_hst2dr_add_device(ioa, handle, retry_count++))
				ssleep(1);

			log_event(ioa,
				"\t%s handle (0x%04x), sas_addr(0x%016llx)\n",
				"AFTER adding end device:",
				handle, (unsigned long long)
				le64_to_cpu(sas_dev00.sas_address));
		}
	}
	log_event(ioa, "\tscan devices: end devices complete\n");
	/* volumes */
	hst2dr_config_get_raid_handles(ioa, &vol_handles);
	for (n = 0 ; n < 64; n++) {
		if ((vol_handles & ((u64)1 << n)) == 0)
			handle = 0x800 + n;
		else
			continue;
	//handle = 0xFFFF;
		if (!(hst2dr_cfg_get_raid_info(ioa, &ssi_reply,
			&volume_pg1, SSI2_RAID_VOLUME_PGAD_FORM_HANDLE,
			handle))) {
			ioa_status = le16_to_cpu(ssi_reply.status) &
				SSI2_IOASTATUS_MASK;
			if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
				log_reset(ioa, "\t%s(0x%04x), loginfo(0x%08x)\n",
					"break from volume scan: ioc_status",
					ioa_status,
					le32_to_cpu(ssi_reply.log_info));
				break;
			}
			handle = le16_to_cpu(volume_pg1.dev_handle);
			spin_lock_irqsave(&ioa->raid_device_lock, flags);
			raid_device = _hst2dr_raid_device_find_by_wwid(ioa,
				le64_to_cpu(volume_pg1.WWID));
			spin_unlock_irqrestore(&ioa->raid_device_lock, flags);
			if (raid_device)
				continue;
			if (hst2dr_cfg_get_raid_vol(ioa, &ssi_reply,
				&volume_pg0, sizeof(SSI2_INQUIRY_RAID_VOL),
				SSI2_RAID_VOLUME_PGAD_FORM_HANDLE, handle))
				continue;
			ioa_status = le16_to_cpu(ssi_reply.status) &
				SSI2_IOASTATUS_MASK;
			if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
				log_reset(ioa, "\t%s(0x%04x), log_info(0x%08x)\n",
					"break from volume scan: ioa_status",
					ioa_status, le32_to_cpu(ssi_reply.log_info));
				break;
			}
			if (volume_pg0.volume_state == SSI2_RAID_VOL_STATE_OPTIMAL ||
				volume_pg0.volume_state == SSI2_RAID_VOL_STATE_PART_OPTIMAL ||
				volume_pg0.volume_state == SSI2_RAID_VOL_STATE_DEGRADED) {
				memset(&element, 0,
					sizeof(SSI2_EVENT_IR_CONFIG_ELEMENT));
				element.reason_code1 =
					SSI2_EVENT_IR_CHANGE_RC_ADDED;
				element.vol_dev_handle = volume_pg1.dev_handle;
				log_reset(ioa, "\t%s handle (0x%04x)\n",
					"BEFORE adding volume:",
					volume_pg1.dev_handle);
				_hst2dr_volume_add(ioa, &element);
				log_reset(ioa,
					"\t%s (0x%04x)\n",
					"AFTER adding volume: handle",
					volume_pg1.dev_handle);
			}
		}
	}
	log_reset(ioa, "\tscan devices: volumes complete\n");

	log_event(ioa, "scan devices: complete\n");
}
/**
 * hst2dr_scsih_reset_handler - reset callback handler (for scsih)
 * @ioa: per adapter object
 * @reset_phase: phase
 *
 * The handler for doing any required cleanup or initialization.
 *
 * The reset phase can be HST2DR_IOA_PRE_RESET, HST2DR_IOA_AFTER_RESET,
 * HST2DR_IOA_DONE_RESET
 *
 * Return nothing.
 */
void
hst2dr_scsih_reset_handler(struct HST2DR_ADAPTER *ioa, int reset_phase)
{
	switch (reset_phase) {
	case HST2DR_IOA_PRE_RESET:
		log_tm(ioa, HST2DR_FMT
			"%s: HST2DR_IOA_PRE_RESET\n", ioa->name, __func__);
		break;
	case HST2DR_IOA_AFTER_RESET:
		log_tm(ioa, HST2DR_FMT
			"%s: HST2DR_IOA_AFTER_RESET\n", ioa->name, __func__);
		if (ioa->tm_cmds.status & HST2DR_CMD_PENDING) {
			ioa->tm_cmds.status |= HST2DR_CMD_RESET;
			hst2dr_base_free_host_tag_id(ioa,
				ioa->tm_cmds.host_tag_id);
			complete(&ioa->tm_cmds.done);
		}

		memset(ioa->pend_os_device_add, 0, ioa->pend_os_device_add_sz);
		memset(ioa->device_remove_in_progress, 0,
			ioa->device_remove_in_progress_sz);
		_hst2dr_fw_event_cleanup_queue(ioa);
		_hst2dr_flush_running_cmds(ioa);
		break;
	case HST2DR_IOA_DONE_RESET:
		log_tm(ioa, HST2DR_FMT
			"%s: HST2DR_IOA_DONE_RESET\n", ioa->name, __func__);
		if ((!ioa->is_driver_loading) && !(disable_discovery > 0 &&
				!ioa->sas_hba.num_phys)) {
			_hst2dr_prep_device_scan(ioa);
			_hst2dr_search_responding_sas_devices(ioa);
			_hst2dr_search_responding_raid_devices(ioa);
			_hst2dr_search_responding_expanders(ioa);
			_log_ini_emergor_recovery_delete_devices(ioa);
		}
		break;
	}
}

/**
 * _hst2dr_fw_work - delayed task for processing firmware events
 * @ioa: per adapter object
 * @fw_event: The fw_event_work object
 * Context: user.
 *
 * Return nothing.
 */
static void
_hst2dr_fw_work(struct HST2DR_ADAPTER *ioa, struct fw_event_work *fw_event)
{
	_hst2dr_fw_event_del_from_list(ioa, fw_event);
	ioa->current_event = fw_event;

	/* the queue is being flushed so ignore this event */
	if (ioa->remove_host || ioa->pci_error_recovery) {
		fw_event_work_put(fw_event);
		return;
	}
	if (ioa->mask_interrupts) {
		fw_event_work_put(fw_event);
		log_event(ioa, "mask interrupt, stop fw work\n");
		return;
	}

	switch (fw_event->event) {
	case HST2DR_REMOVE_UNRESPONDING_DEVICES:
		while (scsi_host_in_recovery(ioa->shost) ||
					 ioa->shost_recovery) {
			/*
			 * If we're unloading, bail. Otherwise, this can become
			 * an infinite loop.
			 */
			if (ioa->remove_host)
				goto out;
			ssleep(1);
		}
		_hst2dr_remove_unresponding_devices(ioa);
		_hst2dr_scan_for_devices_after_reset(ioa);
		break;
	case HST2DR_PORT_ENABLE_COMPLETE:
		ioa->start_scan = 0;
		if (missing_delay[0] != -1 && missing_delay[1] != -1)
			hst2dr_base_update_missing_delay(ioa, missing_delay[0],
				missing_delay[1]);
		break;
	case SSI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST:
		_hst2dr_topology_change_event(ioa, fw_event);
		break;
	case SSI2_EVENT_SAS_DEVICE_STATUS_CHANGE:
		_hst2dr_device_status_change_event(ioa, fw_event);
		break;
	case SSI2_EVENT_SAS_DISCOVERY:
		_hst2dr_discovery_event(ioa, fw_event);
		break;
	case SSI2_EVENT_SAS_BROADCAST_PRIMITIVE:
		_hst2dr_broadcast_primitive_event(ioa, fw_event);
		break;
	case SSI2_EVENT_SAS_ENCL_DEVICE_STATUS_CHANGE:
		_hst2dr_enclosure_dev_status_change_event(ioa,
			fw_event);
		break;
	case SSI2_EVENT_IR_CONFIGURATION_CHANGE_LIST:
		_hst2dr_ir_config_change_event(ioa, fw_event);
		break;
	case SSI2_EVENT_IR_VOLUME:
		_hst2dr_ir_volume_event(ioa, fw_event);
		break;
	case SSI2_EVENT_IR_PHYSICAL_DISK:
		_hst2dr_ir_physical_disk_event(ioa, fw_event);
		break;
	case SSI2_EVENT_IR_OPERATION_STATUS:
		_hst2dr_ir_operation_status_event(ioa, fw_event);
		break;
	default:
		break;


	}
out:
	fw_event_work_put(fw_event);
	ioa->current_event = NULL;
}

/**
 * _firmware_event_work
 * @ioa: per adapter object
 * @work: The fw_event_work object
 * Context: user.
 *
 * wrappers for the work thread handling firmware events
 *
 * Return nothing.
 */

static void
_firmware_event_work(struct work_struct *work)
{
	struct fw_event_work *fw_event = container_of(work,
		struct fw_event_work, work);

	_hst2dr_fw_work(fw_event->ioa, fw_event);
}

/**
 * hst2dr_scsih_event_callback - firmware event handler (called at ISR time)
 * @ioa: per adapter object
 * @cqe: completion queue entity
 * Context: interrupt.
 *
 * This function merely adds a new work task into ioa->firmware_event_work_queue.
 * The tasks are worked from _firmware_event_work in user context.
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
u8
hst2dr_scsih_event_callback(struct HST2DR_ADAPTER *ioa,
	hst2dr_nvme_completion *cqe)
{
	struct fw_event_work *fw_event;
	SSI2_EVENT_NOTIFICATION_REPLY *ssi_reply = NULL;
	u16 event;
	u16 sz;

	/* events turned off due to host reset or driver unloading */
	if (ioa->remove_host || ioa->pci_error_recovery)
		return 1;

	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply = hst2dr_base_get_reply_virt_addr(ioa, cqe->reply_id);

	if (unlikely(!ssi_reply)) {
		log_error(ioa, "ssi_reply not valid at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}

	event = le16_to_cpu(ssi_reply->event);
	ssi_reply->status = cqe->ctrl.status;


	switch (event) {
	/* handle these */
	case SSI2_EVENT_SAS_BROADCAST_PRIMITIVE:
	{
		SSI2_EVENT_DATA_SAS_BC_PRIMITIVE *bcp_data =
			(SSI2_EVENT_DATA_SAS_BC_PRIMITIVE *)
			ssi_reply->event_data;

		if (bcp_data->primitive !=
				SSI2_EVENT_PRIMITIVE_ASYNCHRONOUS_EVENT)
			return 1;

		if ((ioa->broadcast_aen_busy) &&
				(ioa->broadcast_aen_pending < 0xff)) {
			ioa->broadcast_aen_pending++;
			return 1;
		} else
			ioa->broadcast_aen_busy = 1;
		break;
	}

	case SSI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST:
		_hst2dr_check_topo_delete_events(ioa,
			(SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST *)
			ssi_reply->event_data);
		break;
	case SSI2_EVENT_IR_PHYSICAL_DISK:
		break;
	case SSI2_EVENT_IR_CONFIGURATION_CHANGE_LIST:
		_hst2dr_check_ir_config_unhide_events(ioa,
			(SSI2_EVENT_DATA_IR_CONFIG_CHANGE_LIST *)
			ssi_reply->event_data);
		break;
	case SSI2_EVENT_SAS_DEVICE_STATUS_CHANGE:
	case SSI2_EVENT_SAS_DISCOVERY:
	case SSI2_EVENT_SAS_ENCL_DEVICE_STATUS_CHANGE:
		break;
	case SSI2_EVENT_IR_VOLUME:
		_hst2dr_check_volume_delete_events(ioa,
		(SSI2_EVENT_DATA_IR_VOLUME *)ssi_reply->event_data);
		break;
	case SSI2_EVENT_IR_OPERATION_STATUS:
		return 1;
	default: /* ignore the rest */
		return 1;
	}

	sz = le16_to_cpu(ssi_reply->event_data_len) * 4;
	fw_event = alloc_fw_event_work(sz);
	if (!fw_event) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}

	memcpy(fw_event->event_data, ssi_reply->event_data, sz);
	fw_event->ioa = ioa;
	fw_event->event = event;
	_hst2dr_fw_event_add(ioa, fw_event);
	fw_event_work_put(fw_event);
	return 1;
}

/**
 * _hst2dr_expander_node_remove - removing expander device from list.
 * @ioa: per adapter object
 * @sas_expander: the sas_device object
 *
 * Removing object and freeing associated memory from the
 * ioa->sas_expander_list.
 *
 * Return nothing.
 */
static void
_hst2dr_expander_node_remove(struct HST2DR_ADAPTER *ioa,
	struct _sas_node *sas_expander)
{
	struct _sas_port *hst2dr_port, *next;
	unsigned long flags;

	/* remove sibling ports attached to this expander */
	list_for_each_entry_safe(hst2dr_port, next,
			&sas_expander->sas_port_list, port_list) {
		if (ioa->shost_recovery)
			return;
		if (hst2dr_port->remote_identify.device_type ==
				SAS_END_DEVICE)
			hst2dr_device_remove_by_sas_address(ioa,
				hst2dr_port->remote_identify.sas_address);
		else if (hst2dr_port->remote_identify.device_type ==
				SAS_EDGE_EXPANDER_DEVICE ||
				hst2dr_port->remote_identify.device_type ==
				SAS_FANOUT_EXPANDER_DEVICE)
			hst2dr_expander_remove(ioa,
				hst2dr_port->remote_identify.sas_address);
	}

	hst2dr_transport_port_remove(ioa, sas_expander->sas_address,
		sas_expander->sas_address_parent);

	log_always(ioa,
		"expander_remove: handle(0x%04x), sas_addr(0x%016llx)\n",
		sas_expander->handle, (unsigned long long)
		sas_expander->sas_address);

	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	list_del_init(&sas_expander->list);
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);

	kfree(sas_expander->phy);
	kfree(sas_expander);
}

/**
 * hst2dr_shutdown - shutdown notification
 * @ioa: per adapter object
 *
 * Sending shutdown to alert the subsystem of the IOA that
 * the host system is shutting down.
 *
 * Return nothing.
 */
static void
hst2dr_shutdown(struct HST2DR_ADAPTER *ioa)
{
	SSI2_SHUTDOWN_REQUEST *ssi_request;
	SSI2_DEFAULT_REPLY *ssi_reply;
	u16 host_tag_id;
	u32 csts;

	csts = hst2dr_base_get_ioastate(ioa, 0);
	if ((csts & SSI2_IOA_STATE_MASK) != SSI2_IOA_STATE_OPERATIONAL)
		return;

	mutex_lock(&ioa->base_cmds.mutex);

	if (ioa->base_cmds.status != HST2DR_CMD_NOT_USED) {
		pr_err(HST2DR_FMT "%s: base_cmd in use\n",
			ioa->name, __func__);
		mutex_unlock(&ioa->base_cmds.mutex);
		return;
	}
	ioa->base_cmds.status = HST2DR_CMD_PENDING;

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->base_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		pr_err(HST2DR_FMT "%s: failed obtaining a host_tag_id\n",
			ioa->name, __func__);
		goto out;
	}

	ssi_request = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	ioa->base_cmds.host_tag_id = host_tag_id;
	memset(ssi_request, 0, sizeof(SSI2_SHUTDOWN_REQUEST));

	ssi_request->opcode = SSI2_FUNCTION_SHUTDOWN;
	ssi_request->action = SSI2_SYSTEM_SHUTDOWN_NORMAL;
	ssi_request->host_tag_id = host_tag_id;
	ssi_request->opflags = cmd_flag_fw_mode_admin;
	ssi_request->host_flag = hst2dr_cmd_base;

	log_exit(ioa, "shutdown (sending)\n");
	init_completion(&ioa->base_cmds.done);
	ioa->put_host_tag_id_default(ioa, ssi_request);
	wait_for_completion_timeout(&ioa->base_cmds.done,
		SHUTDOWN_WAITING * HZ);

	if (!(ioa->base_cmds.status & HST2DR_CMD_COMPLETE)) {
		pr_err(HST2DR_FMT "%s: timeout\n",
			ioa->name, __func__);
		goto out;
	}

	if (ioa->base_cmds.status & HST2DR_CMD_REPLY_VALID) {
		ssi_reply = ioa->base_cmds.reply;
		log_exit(ioa,
			"%s (complete): status(0x%04x), loginfo(0x%08x)\n",
			"shutdown",
			le16_to_cpu(ssi_reply->status),
			le32_to_cpu(ssi_reply->log_info));
	}

 out:
	ioa->base_cmds.status = HST2DR_CMD_NOT_USED;
	mutex_unlock(&ioa->base_cmds.mutex);
}

/**
 * hst2dr_remove - detach and remove add host
 * @pdev: PCI device struct
 *
 * Routine called when unloading the driver.
 * Return nothing.
 */
static void hst2dr_remove_adapter(struct pci_dev *pdev)
{
	struct Scsi_Host *shost = pci_get_drvdata(pdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	struct _sas_port *hst2dr_port, *next_port;
	struct _raid_device *raid_device, *next;
	struct HST2DR_TARGET *sas_target_priv_data;
	struct workqueue_struct	*wq;
	unsigned long flags;

	ioa->remove_host = 1;
	ioa->drv_stop_processing = 1;
	_hst2dr_fw_event_cleanup_queue(ioa);
	hst2dr_wait_for_commands_to_complete(ioa);
	_hst2dr_flush_running_cmds(ioa);
	spin_lock_irqsave(&ioa->fw_event_lock, flags);
	wq = ioa->firmware_event_work_queue;
	ioa->firmware_event_work_queue = NULL;
	spin_unlock_irqrestore(&ioa->fw_event_lock, flags);
	if (wq)
		destroy_workqueue(wq);

	hst2dr_shutdown(ioa);
	list_for_each_entry_safe(raid_device, next, &ioa->raid_device_list,
			list) {
		if (raid_device->starget) {
			sas_target_priv_data =
				raid_device->starget->hostdata;
			sas_target_priv_data->deleted = 1;
			scsi_remove_target(&raid_device->starget->dev);
		}
		pr_info(HST2DR_FMT "removing handle(0x%04x), wwid(0x%016llx)\n",
			ioa->name,  raid_device->handle,
			(unsigned long long) raid_device->wwid);
		_hst2dr_raid_device_remove(ioa, raid_device);
	}

	/* free ports attached to the sas_host */
	list_for_each_entry_safe(hst2dr_port, next_port,
			&ioa->sas_hba.sas_port_list, port_list) {
		if (hst2dr_port->remote_identify.device_type ==
				SAS_END_DEVICE)
			hst2dr_device_remove_by_sas_address(ioa,
				hst2dr_port->remote_identify.sas_address);
		else if (hst2dr_port->remote_identify.device_type ==
				SAS_EDGE_EXPANDER_DEVICE ||
				hst2dr_port->remote_identify.device_type ==
				SAS_FANOUT_EXPANDER_DEVICE)
			hst2dr_expander_remove(ioa,
				hst2dr_port->remote_identify.sas_address);
	}

	/* free phys attached to the sas_host */
	if (ioa->sas_hba.num_phys) {
		kfree(ioa->sas_hba.phy);
		ioa->sas_hba.phy = NULL;
		ioa->sas_hba.num_phys = 0;
	}

	sas_remove_host(shost);
	scsi_remove_host(shost);
	hst2dr_base_detach(ioa);
	spin_lock(&gioa_lock);
	list_del_init(&ioa->list);
	spin_unlock(&gioa_lock);
	scsi_host_put(shost);
}

/**
 * hst2dr_shutdown - routine call during system shutdown
 * @pdev: PCI device struct
 *
 * Return nothing.
 */
static void
hst2dr_shutdown_adapter(struct pci_dev *pdev)
{
	struct Scsi_Host *shost = pci_get_drvdata(pdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	struct workqueue_struct	*wq;
	unsigned long flags;

	ioa->remove_host = 1;
	ioa->drv_stop_processing = 1;
	hst2dr_wait_for_commands_to_complete(ioa);
	_hst2dr_flush_running_cmds(ioa);
	_hst2dr_fw_event_cleanup_queue(ioa);

	spin_lock_irqsave(&ioa->fw_event_lock, flags);
	wq = ioa->firmware_event_work_queue;
	ioa->firmware_event_work_queue = NULL;
	spin_unlock_irqrestore(&ioa->fw_event_lock, flags);
	if (wq)
		destroy_workqueue(wq);

	hst2dr_shutdown(ioa);
	hst2dr_base_detach(ioa);
}

/**
 * hst2dr_scan_start - scsi lld callback for .scan_start
 * @shost: SCSI host pointer
 *
 * The shost has the ability to discover targets on its own instead
 * of scanning the entire bus.  In our implementation, we will kick off
 * firmware discovery.
 */
static void
hst2dr_scan_start(struct Scsi_Host *shost)
{
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	int rc;

	if (disable_discovery > 0)
		return;

	ioa->start_scan = 1;
	rc = hst2dr_port_enable(ioa);

	if (rc != 0)
		log_warn(ioa, "port enable: FAILED\n");
}
/**
 * _hst2dr_probe_raid - reporting raid volumes to scsi-ml
 * @ioa: per adapter object
 *
 * Called during initial loading of the driver.
 */
static void
_hst2dr_probe_raid(struct HST2DR_ADAPTER *ioa)
{
	struct _raid_device *raid_device, *raid_next;
	int rc;

	list_for_each_entry_safe(raid_device, raid_next,
			&ioa->raid_device_list, list) {
		if (raid_device->starget)
			continue;
		rc = scsi_add_device(ioa->shost, RAID_CHANNEL,
			raid_device->id, 0);
		if (rc)
			_hst2dr_raid_device_remove(ioa, raid_device);
	}
}
static struct _sas_device *get_next_sas_device(struct HST2DR_ADAPTER *ioa)
{
	struct _sas_device *sas_device = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	if (!list_empty(&ioa->sas_device_init_list)) {
		sas_device = list_first_entry(&ioa->sas_device_init_list,
				struct _sas_device, list);
		sas_device_get(sas_device);
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);

	return sas_device;
}
static void sas_device_make_active(struct HST2DR_ADAPTER *ioa,
		struct _sas_device *sas_device)
{
	unsigned long flags;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);

	/*
	 * Since we dropped the lock during the call to port_add(), we need to
	 * be careful here that somebody else didn't move or delete this item
	 * while we were busy with other things.
	 *
	 * If it was on the list, we need a put() for the reference the list
	 * had. Either way, we need a get() for the destination list.
	 */
	if (!list_empty(&sas_device->list)) {
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}

	sas_device_get(sas_device);
	list_add_tail(&sas_device->list, &ioa->sas_device_list);

	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
}
/**
 * _hst2dr_probe_sas - reporting sas devices to sas transport
 * @ioa: per adapter object
 *
 * Called during initial loading of the driver.
 */
static void
_hst2dr_probe_sas(struct HST2DR_ADAPTER *ioa)
{
	struct _sas_device *sas_device;


	while ((sas_device = get_next_sas_device(ioa))) {
		if (!hst2dr_transport_port_add(ioa, sas_device->handle,
				sas_device->sas_address_parent)) {
			_hst2dr_device_remove(ioa, sas_device);
			sas_device_put(sas_device);
			continue;
		} else if (!sas_device->starget) {
			/*
			 * When asyn scanning is enabled, its not possible to
			 * remove devices while scanning is turned on due to an
			 * oops in scsi_sysfs_add_sdev()->add_device()->
			 * sysfs_addrm_start()
			 */
			if (!ioa->is_driver_loading) {
				hst2dr_transport_port_remove(ioa,
					sas_device->sas_address,
					sas_device->sas_address_parent);
				_hst2dr_device_remove(ioa, sas_device);
				sas_device_put(sas_device);
				continue;
			}
		}
		sas_device_make_active(ioa, sas_device);
		sas_device_put(sas_device);
	}
}
/**
 * _hst2dr_probe_devices - probing for devices
 * @ioa: per adapter object
 *
 * Called during initial loading of the driver.
 */
static void
_hst2dr_probe_devices(struct HST2DR_ADAPTER *ioa)
{
	if (ioa->ir_firmware) {
		_hst2dr_probe_raid(ioa);
		_hst2dr_probe_sas(ioa);
	} else
		_hst2dr_probe_sas(ioa);
}
/**
 * hst2dr_scan_finished - scsi lld callback for .scan_finished
 * @shost: SCSI host pointer
 * @time: elapsed time of the scan in jiffies
 *
 * This function will be called periodicallyn until it returns 1 with the
 * scsi_host and the elapsed time of the scan in jiffies. In our implementation,
 * we wait for firmware discovery to complete, then return 1.
 */
static int
hst2dr_scan_finished(struct Scsi_Host *shost, unsigned long time)
{
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	if (disable_discovery > 0) {
		ioa->is_driver_loading = 0;
		ioa->wait_for_discovery_to_complete = 0;
		return 1;
	}

	if (time >= (300 * HZ)) {
		ioa->base_cmds.status = HST2DR_CMD_NOT_USED;
		log_config(ioa, "port enable: FAILED with timeout (300s)\n");
		ioa->is_driver_loading = 0;
		return 1;
	}

	if (ioa->start_scan)
		return 0;

	if (ioa->start_scan_failed) {
		log_config(ioa, "port enable: FAILED with (ioa_status=0x%08x)\n",
			ioa->start_scan_failed);
		ioa->is_driver_loading = 0;
		ioa->wait_for_discovery_to_complete = 0;
		ioa->remove_host = 1;
		return 1;
	}

	log_config(ioa, "port enable: SUCCESS\n");
	ioa->base_cmds.status = HST2DR_CMD_NOT_USED;
	if (ioa->wait_for_discovery_to_complete) {
		ioa->wait_for_discovery_to_complete = 0;
		_hst2dr_probe_devices(ioa);
	}
	hst2dr_base_start_watchdog(ioa);
	ioa->is_driver_loading = 0;
	return 1;
}


/* shost template for SAS 3.0 HBA devices */
static struct scsi_host_template hst2dr_driver_template = {
	.module				= THIS_MODULE,
	.name				= " hst2dr host",
	.proc_name			= HST2DR_DRIVER_NAME,
	.queuecommand			= hst2dr_qcmd,
	.target_alloc			= hst2dr_target_alloc,
	.target_destroy			= hst2dr_target_destroy,
	.slave_alloc			= hst2dr_slave_alloc,
	.slave_configure		= hst2dr_slave_configure,
	.slave_destroy			= hst2dr_slave_destroy,
	.scan_finished			= hst2dr_scan_finished,
	.scan_start			= hst2dr_scan_start,
	.change_queue_depth		= hst2dr_change_queue_depth,
	.eh_abort_handler		= hst2dr_abort,
	.eh_device_reset_handler	= hst2dr_dev_reset,
	.eh_target_reset_handler	= hst2dr_target_reset,
	.eh_host_reset_handler		= hst2dr_host_reset,
	.can_queue			= 1,
	.this_id			= -1,
	.sg_tablesize			= HST2DR_SG_DEPTH,
	.max_sectors			= 32767,
	.cmd_per_lun			= 256,

	.shost_groups		= hst2dr_host_attr_groups,
	.sdev_groups		= hst2dr_dev_attr_groups,
	.track_queue_depth	= 1,
	.cmd_size			= sizeof(struct scsiio_tracker),
};

/**
 * _hst2dr_probe - attach and add scsi host
 * @pdev: PCI device struct
 * @id: pci device id
 *
 * Returns 0 success, anything else error.
 */
static int
_hst2dr_probe_adapter(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct HST2DR_ADAPTER *ioa;
	struct Scsi_Host *shost = NULL;
	int rv;
	int i;

	/* Use hst2dr driver host template for SAS 3.0 HBA's */
	shost = scsi_host_alloc(&hst2dr_driver_template,
		sizeof(struct HST2DR_ADAPTER));
	if (!shost)
		return -ENOMEM;
	ioa = shost_priv(shost);
	memset(ioa, 0, sizeof(struct HST2DR_ADAPTER));
	ioa->hba_ssi_version_belonged = SSI2_VERSION;
	switch (pdev->device) {
	case SSI2_MFG_DEVID_HST2DR_RAID:
		ioa->ir_firmware = 1;
		break;
	case SSI2_MFG_DEVID_HST2DR_HBA:
	default:
		ioa->ir_firmware = 0;
		break;
	}
	ioa->id = hst2dr_ids++;
	snprintf(ioa->driver_name, sizeof(ioa->driver_name), "%s",
		HST2DR_DRIVER_NAME);
	// set the default log type on module start phase.
	ioa->log_level = LOG_DEFAULT;

	INIT_LIST_HEAD(&ioa->list);
	spin_lock(&gioa_lock);
	list_add_tail(&ioa->list, &hst2dr_ioa_list);
	spin_unlock(&gioa_lock);
	ioa->shost = shost;
	ioa->pdev = pdev;
	ioa->scsi_io_cb_idx = scsi_io_cb_idx;
	ioa->tm_cb_idx = tm_cb_idx;
	ioa->ctl_cb_idx = ctl_cb_idx;
	ioa->base_cb_idx = base_cb_idx;
	ioa->port_enable_cb_idx = port_enable_cb_idx;
	ioa->transport_cb_idx = transport_cb_idx;
	ioa->config_cb_idx = config_cb_idx;
	ioa->tr_cb_idx = tr_cb_idx;
	ioa->tr_vol_cb_idx = tr_vol_cb_idx;
	ioa->schedule_dead_ioa_flush_running_cmds = &_hst2dr_flush_running_cmds;
	atomic_set(&ioa->fair_dispatched, 0);
	atomic_set(&ioa->ioctl_in_use, 0);
	/* misc semaphores and spin locks */
	mutex_init(&ioa->reset_in_progress_mutex);
	/* initializing pci_access_mutex lock */
	mutex_init(&ioa->pci_access_mutex);
	spin_lock_init(&ioa->ioa_reset_in_progress_lock);
	spin_lock_init(&ioa->scsi_lookup_lock);
	spin_lock_init(&ioa->sas_device_lock);
	spin_lock_init(&ioa->sas_node_lock);
	spin_lock_init(&ioa->fw_event_lock);
	spin_lock_init(&ioa->raid_device_lock);
	spin_lock_init(&ioa->reply_sense_q_lock);
	for (i = 0; i < NUM_OF_IO_Q + 1; i++)
		spin_lock_init(&ioa->nvmeq_lock[i]);

	INIT_LIST_HEAD(&ioa->sas_device_list);
	INIT_LIST_HEAD(&ioa->sas_device_init_list);
	INIT_LIST_HEAD(&ioa->sas_expander_list);
	INIT_LIST_HEAD(&ioa->fw_event_list);
	INIT_LIST_HEAD(&ioa->sas_hba.sas_port_list);
	INIT_LIST_HEAD(&ioa->delayed_tr_list);
	INIT_LIST_HEAD(&ioa->delayed_tr_vol_list);
	INIT_LIST_HEAD(&ioa->delayed_event_ack_list);
	INIT_LIST_HEAD(&ioa->reply_queue_list);
	INIT_LIST_HEAD(&ioa->raid_device_list);

	snprintf(ioa->name, sizeof(ioa->name), "%s_cm%d",
		ioa->driver_name, ioa->id);

	/* init shost parameters */
	shost->max_cmd_len = 32;
	shost->max_lun = max_lun;
	shost->transportt = hst2dr_transport_template;
	shost->unique_id = ioa->id;

	if (max_sectors != 0xFFFF) {
		if (max_sectors < 64) {
			shost->max_sectors = 64;
			log_warn(ioa, "Invalid value %d passed %s %s.\n",
				max_sectors,
				"for max_sectors, range is 64 to 32767. Assigning",
				"value of 64");
		} else if (max_sectors > 32767) {
			shost->max_sectors = 32767;
			log_warn(ioa, "Invalid value %d passed %s %s\n",
				max_sectors,
				"for max_sectors, range is 64 to 32767. Assigning",
				"default value of 32767");
		} else {
			shost->max_sectors = max_sectors & 0xFFFE;
			log_init(ioa, "The max_sectors value is set to %d\n",
				shost->max_sectors);
		}
	}

	/* register EEDP capabilities with SCSI layer */
	if (prot_mask > 0)
		scsi_host_set_prot(shost, prot_mask);
	else
		scsi_host_set_prot(shost, SHOST_DIF_TYPE1_PROTECTION
				| SHOST_DIF_TYPE2_PROTECTION
				| SHOST_DIF_TYPE3_PROTECTION);

	scsi_host_set_guard(shost, SHOST_DIX_GUARD_CRC);

	/* event thread */
	snprintf(ioa->firmware_event_name, sizeof(ioa->firmware_event_name),
		"fw_event_%s%d", ioa->driver_name, ioa->id);
	ioa->firmware_event_work_queue = alloc_ordered_workqueue(
		ioa->firmware_event_name, WQ_MEM_RECLAIM);
	if (!ioa->firmware_event_work_queue) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		rv = -ENODEV;
		goto out_thread_fail;
	}

	ioa->is_driver_loading = 1;
	if ((hst2dr_base_attach(ioa))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		rv = -ENODEV;
		goto out_attach_fail;
	}

	ioa->shost->nr_hw_queues = 1;
	rv = scsi_add_host(shost, &pdev->dev);
	if (rv) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_add_shost_fail;
	}

	scsi_scan_host(shost);
	return 0;
out_add_shost_fail:
	hst2dr_base_detach(ioa);
 out_attach_fail:
	destroy_workqueue(ioa->firmware_event_work_queue);
	ioa->firmware_event_work_queue = NULL;
 out_thread_fail:
	spin_lock(&gioa_lock);
	list_del_init(&ioa->list);
	spin_unlock(&gioa_lock);
	scsi_host_put(shost);
	return rv;
}

#ifdef CONFIG_PM
/**
 * hst2dr_suspend_adapter - power management suspend main entry point
 * @pdev: PCI device struct
 * @state: PM state change to (usually PCI_D3)
 *
 * Return: 0 success, anything else error.
 */
static int
hst2dr_suspend_adapter(struct pci_dev *pdev, pm_message_t state)
{
	struct Scsi_Host *shost = pci_get_drvdata(pdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	pci_power_t device_state;

	ioa->pm_state = PM_STATE_SUSPEND;
	hst2dr_base_stop_watchdog(ioa);
	ioa->drv_stop_processing = 1;
	flush_workqueue(ioa->firmware_event_work_queue);
	scsi_block_requests(shost);
	device_state = pci_choose_state(pdev, state);
	log_config(ioa, "pdev=0x%p, slot=%s, entering operating state [D%d]\n",
		 pdev, pci_name(pdev), (int)device_state);

	pci_save_state(pdev);
	hst2dr_base_free_resources(ioa);
	pci_set_power_state(pdev, device_state);
	ioa->pm_state = PM_STATE_NORMAL;
	return 0;
}

/**
 * hst2dr_resume_adapter - power management resume main entry point
 * @pdev: PCI device struct
 *
 * Return: 0 success, anything else error.
 */
static int
hst2dr_resume_adapter(struct pci_dev *pdev)
{
	struct Scsi_Host *shost = pci_get_drvdata(pdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	pci_power_t device_state = pdev->current_state;
	int r;

	log_config(ioa, "pdev=0x%p, slot=%s, previous operating state [D%d]\n",
		 pdev, pci_name(pdev), (int)device_state);
	ioa->pm_state = PM_STATE_RESUME;
	pci_set_power_state(pdev, PCI_D0);
	pci_enable_wake(pdev, PCI_D0, 0);
	pci_restore_state(pdev);
	ioa->pdev = pdev;
	r = hst2dr_base_map_resources(ioa);
	if (r)
		return r;

	hst2dr_base_hard_reset_handler(ioa, SOFT_RESET, 10);
	ioa->pm_state = PM_STATE_NORMAL;
	scsi_unblock_requests(shost);
	hst2dr_base_start_watchdog(ioa);
	ioa->drv_stop_processing = 0;
	return 0;
}
#endif /* CONFIG_PM */

/**
 * hst2dr_pci_error_detected - Called when a PCI error is detected.
 * @pdev: PCI device struct
 * @state: PCI channel state
 *
 * Description: Called when a PCI error is detected.
 *
 * Return value:
 *	PCI_ERS_RESULT_NEED_RESET or PCI_ERS_RESULT_DISCONNECT
 */
static pci_ers_result_t
hst2dr_pci_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct Scsi_Host *shost = pci_get_drvdata(pdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	log_fail(ioa, "PCI error: detected callback, state(%d)!\n",
		state);

	switch (state) {
	case pci_channel_io_normal:
		return PCI_ERS_RESULT_CAN_RECOVER;
	case pci_channel_io_frozen:
		/* Fatal error, prepare for slot reset */
		ioa->pci_error_recovery = 1;
		scsi_block_requests(ioa->shost);
		hst2dr_base_stop_watchdog(ioa);
		hst2dr_base_free_resources(ioa);
		return PCI_ERS_RESULT_NEED_RESET;
	case pci_channel_io_perm_failure:
		/* Permanent error, prepare for device removal */
		ioa->pci_error_recovery = 1;
		hst2dr_base_stop_watchdog(ioa);
		_hst2dr_flush_running_cmds(ioa);
		return PCI_ERS_RESULT_DISCONNECT;
	}
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * hst2dr_pci_slot_reset - Called when PCI slot has been reset.
 * @pdev: PCI device struct
 *
 * Description: This routine is called by the pci error recovery
 * code after the PCI slot has been reset, just before we
 * should resume normal operations.
 */
static pci_ers_result_t
hst2dr_pci_slot_reset(struct pci_dev *pdev)
{
	struct Scsi_Host *shost = pci_get_drvdata(pdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	int rc;

	log_reset(ioa, "PCI error: slot reset callback!\n");

	ioa->pci_error_recovery = 0;
	ioa->pdev = pdev;
	pci_restore_state(pdev);
	rc = hst2dr_base_map_resources(ioa);
	if (rc)
		return PCI_ERS_RESULT_DISCONNECT;

	rc = hst2dr_base_hard_reset_handler(ioa, AER_RESET, 11);

	log_warn(ioa, "hard reset: %s\n",
		(rc == 0) ? "success" : "failed");

	if (!rc)
		return PCI_ERS_RESULT_RECOVERED;
	else
		return PCI_ERS_RESULT_DISCONNECT;
}

/**
 * hst2dr_pci_resume() - resume normal ops after PCI reset
 * @pdev: pointer to PCI device
 *
 * Called when the error recovery driver tells us that its
 * OK to resume normal operation. Use completion to allow
 * halted scsi ops to resume.
 */
static void
hst2dr_pci_resume(struct pci_dev *pdev)
{
	struct Scsi_Host *shost = pci_get_drvdata(pdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	log_fail(ioa, "PCI error: resume callback!\n");

	pci_aer_clear_nonfatal_status(pdev);
	hst2dr_base_start_watchdog(ioa);
	scsi_unblock_requests(ioa->shost);
}

/**
 * hst2dr_pci_mmio_enabled - Enable MMIO and dump debug registers
 * @pdev: pointer to PCI device
 */
static pci_ers_result_t
hst2dr_pci_mmio_enabled(struct pci_dev *pdev)
{
	struct Scsi_Host *shost = pci_get_drvdata(pdev);
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);

	log_fail(ioa, "PCI error: mmio enabled callback!\n");

	/* TODO - dump whatever for debugging purposes */

	/* This called only if hst2dr_pci_error_detected returns
	 * PCI_ERS_RESULT_CAN_RECOVER. Read/write to the device still
	 * works, no need to reset slot.
	 */
	return PCI_ERS_RESULT_RECOVERED;
}
/**
 * hst2dr_ncq_prio_supp - Check for NCQ command priority support
 * @sdev: scsi device struct
 *
 * This is called when a user indicates they would like to enable
 * ncq command priorities. This works only on SATA devices.
 */
bool hst2dr_ncq_prio_supp(struct scsi_device *sdev)
{
	unsigned char *buf;
	bool ncq_prio_supp = false;

	if (!scsi_device_supports_vpd(sdev))
		return ncq_prio_supp;

#if !defined(SCSI_VPD_PG_LEN)
#define SCSI_VPD_PG_LEN 255
#endif

	buf = kmalloc(SCSI_VPD_PG_LEN, GFP_KERNEL);
	if (!buf)
		return ncq_prio_supp;

	if (!scsi_get_vpd_page(sdev, 0x89, buf, SCSI_VPD_PG_LEN))
		ncq_prio_supp = (buf[213] >> 4) & 1;

	kfree(buf);
	return ncq_prio_supp;
}

/*
 * The pci device ids are defined in ssi/ssi2_conf.h.
 */
static const struct pci_device_id hst2dr_pci_table[] = {
	/* HST2DR */
	{ SSI2_MFG_VENDORID_HST2, SSI2_MFG_DEVID_HST2DR_HBA,
		PCI_ANY_ID, PCI_ANY_ID },
	{ SSI2_MFG_VENDORID_HST2, SSI2_MFG_DEVID_HST2DR_RAID,
		PCI_ANY_ID, PCI_ANY_ID },

	{0}	/* Terminating entry */
};
MODULE_DEVICE_TABLE(pci, hst2dr_pci_table);

static struct pci_error_handlers _log_ini_emerg_handler = {
	.error_detected	= hst2dr_pci_error_detected,
	.mmio_enabled	= hst2dr_pci_mmio_enabled,
	.slot_reset	= hst2dr_pci_slot_reset,
	.resume		= hst2dr_pci_resume,
};

static struct pci_driver hst2dr_driver = {
	.name		= HST2DR_DRIVER_NAME,
	.id_table	= hst2dr_pci_table,
	.probe		= _hst2dr_probe_adapter,
	.remove		= hst2dr_remove_adapter,
	.shutdown	= hst2dr_shutdown_adapter,
	.err_handler	= &_log_ini_emerg_handler,
#ifdef CONFIG_PM
	.suspend	= hst2dr_suspend_adapter,
	.resume		= hst2dr_resume_adapter,
#endif
};

/**
 * hst2dr_shost_init - main entry point for this driver.
 *
 * Returns 0 success, anything else error.
 */
static int
hst2dr_shost_init(void)
{
	hst2dr_ids = 0;

	hst2dr_base_initialize_callback_handler();

	 /* scsi io queuecommand callback handler */
	scsi_io_cb_idx = hst2dr_base_register_callback_handler(_hst2dr_io_done);

	/* task management callback handler */
	tm_cb_idx = hst2dr_base_register_callback_handler(_hst2dr_tm_done);

	/* base internal commands callback handler */
	base_cb_idx = hst2dr_base_register_callback_handler(hst2dr_base_done);

	/* port enable command callback handler */
	port_enable_cb_idx = hst2dr_base_register_callback_handler(
		hst2dr_port_enable_done);

	/* transport internal commands callback handler */
	transport_cb_idx = hst2dr_base_register_callback_handler(
		hst2dr_transport_done);

	/* configuration page API internal commands callback handler */
	config_cb_idx = hst2dr_base_register_callback_handler(
		hst2dr_cfg_done);

	/* ctl module callback handler */
	ctl_cb_idx = hst2dr_base_register_callback_handler(hst2dr_ctl_done);

	/* link reset callback handler */

	tr_cb_idx = hst2dr_base_register_callback_handler(
		_hst2dr_tr_done);

	tr_vol_cb_idx = hst2dr_base_register_callback_handler(
		_hst2dr_tr_vol_done);

	return 0;
}

/**
 * hst2dr_shost_exit - exit point for this driver (when it is a module).
 *
 * Returns 0 success, anything else error.
 */
static void
hst2dr_shost_exit(void)
{

	hst2dr_base_release_callback_handler(scsi_io_cb_idx);
	hst2dr_base_release_callback_handler(tm_cb_idx);
	hst2dr_base_release_callback_handler(base_cb_idx);
	hst2dr_base_release_callback_handler(port_enable_cb_idx);
	hst2dr_base_release_callback_handler(transport_cb_idx);
	hst2dr_base_release_callback_handler(config_cb_idx);
	hst2dr_base_release_callback_handler(ctl_cb_idx);

	hst2dr_base_release_callback_handler(tr_cb_idx);
	hst2dr_base_release_callback_handler(tr_vol_cb_idx);

/* transport support */

	sas_release_transport(hst2dr_transport_template);
}

/**
 * _hst2dr_init - main entry point for this driver.
 *
 * Returns 0 success, anything else error.
 */
static int __init
_hst2dr_init(void)
{
	int error;

	pr_info("HST2DR INIT INFO: %s version %s is loading\n",
				HST2DR_DRIVER_NAME, HST2DR_FULL_VERSION);

	if (hst2dr_select_q_mode != -1 && ((hst2dr_select_q_mode & 0xf) < 2 ||
			(hst2dr_select_q_mode & 0xf) > 4))
		hst2dr_select_q_mode = -1;
	if ((hst2dr_select_q_mode >> 16) > 1)
		hst2dr_select_q_mode = -1;

	hst2dr_transport_template =
		sas_attach_transport(&hst2dr_transport_functions);
	if (!hst2dr_transport_template)
		return -ENODEV;

	error = hst2dr_shost_init();
	if (error) {
		hst2dr_shost_exit();
		return error;
	}

	hst2dr_ctl_init();

	error = pci_register_driver(&hst2dr_driver);
	if (error) {
		hst2dr_ctl_exit();
		hst2dr_shost_exit();
	}
	return error;
}

/**
 * _hst2dr_exit - exit point for this driver (when it is a module).
 *
 */
static void __exit
_hst2dr_exit(void)
{
	pr_info("HST2DR EXIT INFO: %s version %s is unloading\n",
				HST2DR_DRIVER_NAME, HST2DR_FULL_VERSION);

	pci_unregister_driver(&hst2dr_driver);

	hst2dr_ctl_exit();

	hst2dr_shost_exit();
}

module_init(_hst2dr_init);
module_exit(_hst2dr_exit);
