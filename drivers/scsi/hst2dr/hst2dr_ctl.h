/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Management Module Support for hst2dr based controllers
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_ctl.h

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

#ifndef HST2DR_CTL_H_INCLUDED
#define HST2DR_CTL_H_INCLUDED

#ifdef __KERNEL__
#include <linux/miscdevice.h>
#endif

#ifndef HST2DR_MINOR
#define HST2DR_MINOR		(210)

#endif
#define HST2DR_DEV_NAME	"hst2ctl"
#define HST2DR_MAGIC_NUMBER	'L'
#define HST2DR_IOCTL_DEFAULT_TIMEOUT (10) /* in seconds */

/**
 * IOCTL opcodes
 */
#define HST2IOAINFO	_IOWR(HST2DR_MAGIC_NUMBER, 17, \
	struct hst2dr_cli_kernel_infos)

#define HST2RESETHBA	_IOWR(HST2DR_MAGIC_NUMBER, 18, \
	struct hst2dr_rsttype)

#define HST2COMMAND	_IOWR(HST2DR_MAGIC_NUMBER, 20, \
	struct hst2dr_ioctl_command)
#ifdef CONFIG_COMPAT
#define HST2COMMAND32	_IOWR(HST2DR_MAGIC_NUMBER, 20, \
	struct hst2dr_ioctl_command32)
#endif
#define HST2EVENTQUERY	_IOWR(HST2DR_MAGIC_NUMBER, 21, \
	struct hst2dr_ioctl_eventquery)
#define HST2EVENTENABLE	_IOWR(HST2DR_MAGIC_NUMBER, 22, \
	struct hst2dr_ioctl_eventenable)
#define HST2EVENTREPORT	_IOWR(HST2DR_MAGIC_NUMBER, 23, \
	struct hst2dr_ioctl_eventreport)
#define HST2HARDRESET	_IOWR(HST2DR_MAGIC_NUMBER, 24, \
	struct hst2dr_ioctl_reset)
#define HST2BTDHMAPPING	_IOWR(HST2DR_MAGIC_NUMBER, 31, \
	struct hst2dr_ioctl_btdh_mapping)



/**
 * struct hst2dr_ioctl_header - main header structure
 * @ioa_number -  IOA unit number
 * @port_number - IOA port number
 * @max_data_size - maximum number bytes to transfer on read
 */
struct hst2dr_ioctl_header {
	uint32_t ioa_number;
	uint32_t max_data_size; // Only for event report
};

/**
 * struct hst2dr_ioctl_reset
 * @hdr - generic header
 */
struct hst2dr_ioctl_reset {
	struct hst2dr_ioctl_header hdr;
};


/**
 * struct hst2dr_ioctl_pci_info - pci device info
 * @device - pci device id
 * @function - pci function id
 * @bus - pci bus id
 * @segment_id - pci segment id
 */
struct hst2dr_ioctl_pci_info {
	union {
		struct {
			uint32_t device:5;
			uint32_t function:3;
			uint32_t bus:24;
		} bits;
		uint32_t  word;
	} u;
	uint32_t segment_id;
};


#define HST2DR_IOCTL_INTERFACE_SAS3	(0x06)
#define HST2DR_IOCTL_VERSION_LENGTH	(32)

/**
 * struct hst2dr_ioctl_iocinfo - generic controller info
 * @hdr - generic header
 * @adapter_type - type of adapter (spi, fc, sas)
 * @port_number - port number
 * @pci_id - PCI Id
 * @hw_rev - hardware revision
 * @sub_system_device - PCI subsystem Device ID
 * @sub_system_vendor - PCI subsystem Vendor ID
 * @rsvd0 - reserved
 * @firmware_version - firmware version
 * @bios_version - BIOS version
 * @driver_version - driver version - 32 ASCII characters
 * @rsvd1 - reserved
 * @scsi_id - scsi id of adapter 0
 * @rsvd2 - reserved
 * @pci_information - pci info (2nd revision)
 */
struct hst2dr_ioctl_ioainfo {
	struct hst2dr_ioctl_header hdr;
	uint32_t adapter_type;
	uint32_t port_number;
	uint32_t pci_id;
	uint32_t hw_rev;
	uint32_t subsystem_device;
	uint32_t subsystem_vendor;
	uint32_t rsvd0;
	uint32_t firmware_version;
	uint32_t bios_version;
	uint8_t driver_version[HST2DR_IOCTL_VERSION_LENGTH];
	uint8_t rsvd1;
	uint8_t scsi_id;
	uint16_t rsvd2;
	struct hst2dr_ioctl_pci_info pci_information;
};

struct driver2cli_additional_infos {
	unsigned short vendor_id;
};

/**
 * used for hst2dr cli and kernel pass some infos
 *
 */
struct hst2dr_cli_kernel_infos {
	struct hst2dr_ioctl_ioainfo ioainfo;
	struct hst2dr_info info;
	struct driver2cli_additional_infos additioanal_infos;
};
/**
 * @brief used for reset hba
 * rst_type:1. hard reset; 2.softreset
 *
 */
struct hst2dr_rsttype {
	struct hst2dr_ioctl_header hdr;
	uint32_t reset_type;
};
/* number of event log entries */
#define HST2DR_CTL_EVENT_LOG_SIZE (50)

/**
 * struct hst2dr_ioctl_eventquery - query event count and type
 * @hdr - generic header
 * @event_entries - number of events returned by get_event_report
 * @rsvd - reserved
 * @event_types - type of events currently being captured
 */
struct hst2dr_ioctl_eventquery {
	struct hst2dr_ioctl_header hdr;
	uint16_t event_entries;
	uint16_t rsvd;
	uint32_t event_types[SSI2_EVENT_NOTIFY_EVENTMASK];
};

/**
 * struct hst2dr_ioctl_eventenable - enable/disable event capturing
 * @hdr - generic header
 * @event_types - toggle off/on type of events to be captured
 */
struct hst2dr_ioctl_eventenable {
	struct hst2dr_ioctl_header hdr;
	uint32_t event_types[4];
};

#define HST2DR_EVENT_DATA_SIZE (192)
/**
 * struct HST2DR_IOCTL_EVENTS -
 * @event - the event that was reported
 * @context - unique value for each event assigned by driver
 * @data - event data returned in fw reply message
 */
struct HST2DR_IOCTL_EVENTS {
	uint32_t event;
	uint32_t context;
	uint8_t data[HST2DR_EVENT_DATA_SIZE];
};

/**
 * struct hst2dr_ioctl_eventreport - returing event log
 * @hdr - generic header
 * @event_data - (see struct HST2DR_IOCTL_EVENTS)
 */
struct hst2dr_ioctl_eventreport {
	struct hst2dr_ioctl_header hdr;
	struct HST2DR_IOCTL_EVENTS event_data[];
};

/**
 * struct hst2dr_ioctl_command - generic hst2dr firmware passthru ioctl
 * @hdr - generic header
 * @timeout - command timeout in seconds. (if zero then use driver default
 *  value).
 * @reply_frame_buf_ptr - reply location
 * @data_in_buf_ptr - destination for read
 * @data_out_buf_ptr - data source for write
 * @sense_data_ptr - sense data location
 * @max_reply_bytes - maximum number of reply bytes to be sent to app.
 * @data_in_size - number bytes for data transfer in (read)
 * @data_out_size - number bytes for data transfer out (write)
 * @max_sense_bytes - maximum number of bytes for auto sense buffers
 * @data_sge_offset - offset in words from the start of the request message to
 * the first SGL
 * @mf -message frame
 */
struct hst2dr_ioctl_command {
	struct hst2dr_ioctl_header hdr;
	uint32_t timeout;
	void __user *reply_frame_buf_ptr;
	void __user *data_in_buf_ptr;
	void __user *data_out_buf_ptr;
	void __user *sense_data_ptr;
	uint32_t max_reply_bytes;
	uint32_t data_in_size;
	uint32_t data_out_size;
	uint32_t max_sense_bytes;
	uint32_t data_sge_offset;
	uint8_t mf[];
};

#ifdef CONFIG_COMPAT
struct hst2dr_ioctl_command32 {
	struct hst2dr_ioctl_header hdr;
	uint32_t timeout;
	uint32_t reply_frame_buf_ptr;
	uint32_t data_in_buf_ptr;
	uint32_t data_out_buf_ptr;
	uint32_t sense_data_ptr;
	uint32_t max_reply_bytes;
	uint32_t data_in_size;
	uint32_t data_out_size;
	uint32_t max_sense_bytes;
	uint32_t data_sge_offset;
	uint8_t mf[];
};
#endif

/**
 * struct hst2dr_ioctl_btdh_mapping - mapping info
 * @hdr - generic header
 * @id - target device identification number
 * @bus - SCSI bus number that the target device exists on
 * @handle - device handle for the target device
 * @rsvd - reserved
 *
 * To obtain a bus/id the application sets
 * handle to valid handle, and bus/id to 0xFFFF.
 *
 * To obtain the device handle the application sets
 * bus/id valid value, and the handle to 0xFFFF.
 */
struct hst2dr_ioctl_btdh_mapping {
	struct hst2dr_ioctl_header hdr;
	uint32_t id;
	uint32_t bus;
	uint16_t handle;
	uint16_t rsvd;
};


#endif /* HST2DR_CTL_H_INCLUDED */
