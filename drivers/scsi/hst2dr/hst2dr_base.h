/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This is the  hst2dr base driver providing common API layer interface
 * for access to hst2dr firmware.
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_base.h

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

#ifndef HST2DR_BASE_H_INCLUDED
#define HST2DR_BASE_H_INCLUDED

typedef u8 U8;
typedef u16 U16;
typedef u32 U32;
typedef u64 U64;

#include "ssi/ssi2.h"
#include "ssi/ssi2_ioa.h"
#include "ssi/ssi2_conf.h"
#include "ssi/ssi2_init.h"
#include "ssi/ssi2_sas.h"

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_transport_sas.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_eh.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/nvme.h>
/* driver versioning info */
#define HST2DR_DRIVER_NAME		"hst2dr"
#define HST2DR_AUTHOR "Hangzhou Hualan Microelectronique CO.,Ltd"
#define HST2DR_DESCRIPTION	"HST2DR Storage Controller Device Driver"

#define HST2DR_MAJOR_VERSION		3
#define HST2DR_MINOR_VERSION		0
#define HST2DR_REVISION_VERSION		6

#define HST2DR_BUILD_DATE		"260803"
#define HST2DR_EXT_VERSION		"01"

#define strhelper(x) #x
#define str(x) strhelper(x)
#define HST2DR_DRIVER_VERSION		str(HST2DR_MAJOR_VERSION) "." \
					str(HST2DR_MINOR_VERSION) "." \
					str(HST2DR_REVISION_VERSION)
#define DRIVER_VERSION	((HST2DR_MAJOR_VERSION << 24) \
			| (HST2DR_MINOR_VERSION << 16)\
			| (HST2DR_REVISION_VERSION))

#define HST2DR_BUILD_VERSION HST2DR_BUILD_DATE "_" HST2DR_EXT_VERSION

#define HST2DR_FULL_VERSION HST2DR_DRIVER_VERSION "." HST2DR_BUILD_VERSION

enum HST2DR_VERSION {
	HST2DR_V2 = (HST2DR_MAJOR_VERSION << 8) | HST2DR_MINOR_VERSION,
};

/*
 * Set HST2DR_SG_DEPTH value based on user input.
 */
#define HST2DR_MAX_PHYS_SEGMENTS	SG_CHUNK_SIZE
#define HST2DR_MIN_PHYS_SEGMENTS	16
#define HST2DR_KDUMP_MIN_PHYS_SEGMENTS	32

#define HST2DR_SG_DEPTH			HST2DR_MAX_PHYS_SEGMENTS

#define NVME_REG_VENDOR_BASE		ioa->nvme_reg_dbs
#define RESET_UNLOCK_RETRY_COUNT	5
#define MAX_NUMA_NODE			32

#define NVME_REG_WD				(NVME_REG_VENDOR_BASE + 0x400)
#define	NVME_REG_HR_RES				(NVME_REG_VENDOR_BASE + 0x404)
#define	NVME_REG_Q_PENDING			(NVME_REG_VENDOR_BASE + 0x408)
#define	NVME_REG_HR_HS				(NVME_REG_VENDOR_BASE + 0x410)
#define	NVME_REG_Q_MODE				(NVME_REG_VENDOR_BASE + 0x43c)
#define	NVME_REG_Q_MODE_SUPPORTED		(NVME_REG_VENDOR_BASE + 0x410)
#define	NVME_REG_Q_MODE_SET			(NVME_REG_VENDOR_BASE + 0x414)
#define	NVME_REG_REPLY_SENSE_Q_CTRL		(NVME_REG_VENDOR_BASE + 0x440)
#define	NVME_REG_ADMIN_SQ			(NVME_REG_VENDOR_BASE + 0x500)
#define	NVME_REG_IO_SQ				(NVME_REG_VENDOR_BASE + 0x504)
enum {
	NVME_REG_SEQUENCE		= 0x81000,
	NVME_REG_CHIP_STATUS		= 0x81004,
	NVME_REG_CHIP_STATUS_CTRL	= 0x81008,
	NVME_REG_CHIP_STATUS_IS		= 0x8100C,
	PCI_REG_CONFIG_CHIP_RESET	= 0x3fc,
};
enum {
	CHIP_STATUS_IDLE	= 0x00,
	CHIP_STATUS_S1		= 0x10,
	CHIP_STATUS_S2		= 0x20,
	CHIP_STATUS_S3		= 0x30,
	CHIP_STATUS_S4		= 0x40,
	CHIP_STATUS_ACTIVE	= 0x50,
	CHIP_STATUS_INIT	= 0x00,
	CHIP_STATUS_READY	= 0x01,
};
enum {
	Q_MODE_2			= 2,
	Q_MODE_3			= 3,
	Q_MODE_4			= 4,
};
enum {
	VS_V2M2			= 0x00220001,
	VS_V2N1			= 0x80210001,
};
#define CHIP_STATUS_MASK			0x0f
#define SIGNATURE_SEQUENCE_STATUS_MASK		0x70
#define CHIP_RESET_IS_INTERVAL			50	// >32us
#define CHIP_RESET_INTERVAL			50	// 50ms
#define IS_WAITING				1000	// 1000ms
#define CHIP_RESET_WAITING			3000	// 3000ms
#define CHIP_RESET_QUERY_INTERVAL		10	// 10ms
#define IO_COMPLETION_WAITING			20	// 20s
#define PORT_ENABLE_WAITING			300	// 300s
#define EVENT_NOTIFICATION_WAITING		30	// 30s
#define SMP_PASSTHROUGH_WAITING			30	// 30s
#define SHUTDOWN_WAITING			10	// 10s default, max 120s
#define TM_WAITING				30	// 30s
enum {
	HW_BALANCE_EN			= 0x8,
	SPU_RESET			= 0x4,
	SMU_RESET			= 0x2,
	CHIP_RESET			= 0x1,
};
enum SIGNATURE_SEQUENCE {
	SIGNATURE_SEQUENCE4 = 0x06,
	SIGNATURE_SEQUENCE3 = 0x28,
	SIGNATURE_SEQUENCE2 = 0x05,
	SIGNATURE_SEQUENCE1 = 0x16,
	SIGNATURE_SEQUENCE0 = 0x25,
};
enum CHIP_RESET_SEQUENCE {
	CHIP_RESET_SEQUENCE3 = 0x54,
	CHIP_RESET_SEQUENCE2 = 0x53,
	CHIP_RESET_SEQUENCE1 = 0x52,
	CHIP_RESET_SEQUENCE0 = 0x48,
};
enum PM_STATE {
	PM_STATE_NORMAL			= 0,
	PM_STATE_SUSPEND		= 1,
	PM_STATE_RESUME			= 2,
};

/*
 * Generic Defines
 */
#define HST2DR_SATA_QUEUE_DEPTH		32
#define HST2DR_SAS_QUEUE_DEPTH		254
#define HST2DR_RAID_QUEUE_DEPTH		128
#define INTERNAL_QUEUE_DEPTH		64

#define HST2DR_KDUMP_SCSI_IO_DEPTH	200

#define HST2DR_HOST_PAGE_SIZE_4K	12
#define HST2DR_NVME_QUEUE_DEPTH		128
#define HST2DR_NAME_LENGTH		32	/* generic length of strings */
#define HST2DR_STRING_LENGTH		64

#define HST2DR_MAX_CALLBACKS		32

#define INTERNAL_CMDS_COUNT		10	/* reserved cmds */
/* reserved for issuing internally framed scsi io cmds */
#define INTERNAL_SCSIIO_CMDS_COUNT	3

#define SSI3_HIM_MASK			0xFFFFFFFF /* mask every bit*/

#define HST2DR_INVALID_DEVICE_HANDLE	0xFFFF

#define MAX_CHAIN_ELEMT_SZ		16
#define DEFAULT_NUM_FWCHAIN_ELEMTS	0x80  // 8


#define HST2DR_RAID_MAX_SECTORS		8192

/*
 * reset phases
 */
#define HST2DR_IOA_PRE_RESET		1 /* prior to host reset */
#define HST2DR_IOA_AFTER_RESET		2 /* just after host reset */
#define HST2DR_IOA_DONE_RESET		3 /* links re-initialized */

/*
 * logging format
 */
#define HST2DR_FMT				"%s: "

#define MAGIC_NUMBER				0xC73D

#define INVALID_CB_INDEX			0xFF

/*
 * per target private data
 */
#define HST2DR_TARGET_FLAGS_RAID_COMPONENT	0x01
#define HST2DR_TARGET_FLAGS_VOLUME		0x02
#define HST2DR_TARGET_FLAGS_DELETED		0x04

#define VIRTUAL_IO_FAILED_RETRY			(0x32010081)

/**
 * struct HST2DR_TARGET - starget private hostdata
 * @starget: starget object
 * @sas_address: target sas address
 * @handle: device handle
 * @num_luns: number luns
 * @flags: HST2DR_TARGET_FLAGS_XXX flags
 * @deleted: target flaged for deletion
 * @tm_busy: target is busy with TM request.
 * @sdev: The sas_device associated with this target
 */
struct HST2DR_TARGET {
	struct scsi_target *starget;
	u64	sas_address;
	u16	handle;
	int	num_luns;
	u32	flags;
	u8	deleted;
	u8	tm_busy;
	u8	block;
	u8	resv;
	u32	device_info;
	struct _sas_device *sdev;
};


/*
 * per device private data
 */
#define HST2DR_DEVICE_FLAGS_INIT		0x01

/**
 * struct HST2DR_DEVICE - sdev private hostdata
 * @sas_target: starget private hostdata
 * @lun: lun number
 * @flags: HST2DR_DEVICE_XXX flags
 * @configured_lun: lun is configured
 * @block: device is in SDEV_BLOCK state
 * @ncq_prio_enable: ncq priority enable
 */
struct HST2DR_DEVICE {
	struct HST2DR_TARGET *sas_target;
	unsigned int	lun;
	u32	flags;
	u8	configured_lun;
	u8	block;
	u8	ignore_delay_remove;
	/* Iopriority Command Handling */
	u8	ncq_prio_enable;

};

#define HST2DR_CMD_NOT_USED		0x8000	/* free */
#define HST2DR_CMD_COMPLETE		0x0001	/* completed */
#define HST2DR_CMD_PENDING		0x0002	/* pending */
#define HST2DR_CMD_REPLY_VALID		0x0004	/* reply is valid */
#define HST2DR_CMD_RESET		0x0008	/* host reset dropped the command */

/**
 * struct _internal_cmd - internal commands struct
 * @mutex: mutex
 * @done: completion
 * @reply: reply message pointer
 * @sense: sense data
 * @status: HST2DR_CMD_XXX status
 * @host_tag_id: message index
 */
struct _internal_cmd {
	struct mutex mutex;
	struct completion done;
	void	*reply;
	void	*sense;
	u16	status;
	u16	host_tag_id;
};



/**
 * struct _sas_device - attached device information
 * @list: sas device list
 * @starget: starget object
 * @sas_address: device sas address
 * @device_name: retrieved from the SAS IDENTIFY frame.
 * @handle: device handle
 * @sas_address_parent: sas address of parent expander or sas host
 * @enclosure_handle: enclosure handle
 * @enclosure_logical_id: enclosure logical identifier
 * @device_info: bitfield provides detailed info about the device
 * @id: target id
 * @channel: target channel
 * @slot: slot number
 * @phy: phy identifier provided in sas device page 0
 * @responding: used in _hst2dr_device_mark_responding
 * @pend_sas_rphy_add: flag to check if device is in sas_rphy_add()
 *	addition routine.
 * @chassis_slot: chassis slot
 * @is_chassis_slot_valid: chassis slot valid or not
 */
struct _sas_device {
	struct list_head list;
	struct scsi_target *starget;
	u64	sas_address;
	u64	device_name;
	u64	sas_address_parent;
	u16	handle;
	u16	enclosure_handle;
	u64	enclosure_logical_id;
	u32	device_info;
	int	id;
	int	channel;
	u16	slot;
	u8	phy;
	u8	responding;
	u8	pend_sas_rphy_add;
	u8	enclosure_level;
	u8	chassis_slot;
	u8	is_chassis_slot_valid;
	u8	connector_name[5];
	struct kref refcount;
	u16	rsv1;
	u16	volume_handle;
	u64	volume_wwid;
};

static inline void sas_device_get(struct _sas_device *s)
{
	kref_get(&s->refcount);
}

static inline void sas_device_free(struct kref *r)
{
	kfree(container_of(r, struct _sas_device, refcount));
}

static inline void sas_device_put(struct _sas_device *s)
{
	kref_put(&s->refcount, sas_device_free);
}

/**
 * struct _sas_port - wide/narrow sas port information
 * @port_list: list of ports belonging to expander
 * @num_phys: number of phys belonging to this port
 * @remote_identify: attached device identification
 * @rphy: sas transport rphy object
 * @port: sas transport wide/narrow port object
 * @phy_list: _sas_phy list objects belonging to this port
 */
struct _sas_port {
	struct list_head port_list;
	u8	num_phys;
	struct sas_identify remote_identify;
	struct sas_rphy *rphy;
	struct sas_port *port;
	struct list_head phy_list;
};

/**
 * struct _sas_phy - phy information
 * @port_siblings: list of phys belonging to a port
 * @identify: phy identification
 * @remote_identify: attached device identification
 * @phy: sas transport phy object
 * @phy_id: unique phy id
 * @handle: device handle for this phy
 * @attached_handle: device handle for attached device
 * @phy_belongs_to_port: port has been created for this phy
 */
struct _sas_phy {
	struct list_head port_siblings;
	struct sas_identify identify;
	struct sas_identify remote_identify;
	struct sas_phy *phy;
	u8	phy_id;
	u16	handle;
	u16	attached_handle;
	u8	phy_belongs_to_port;
};

/**
 * struct _sas_node - sas_host/expander information
 * @list: list of expanders
 * @parent_dev: parent device class
 * @num_phys: number phys belonging to this sas_host/expander
 * @sas_address: sas address of this sas_host/expander
 * @handle: handle for this sas_host/expander
 * @sas_address_parent: sas address of parent expander or sas host
 * @enclosure_handle: handle for this a member of an enclosure
 * @device_info: bitwise defining capabilities of this sas_host/expander
 * @responding: used in _hst2dr_expander_device_mark_responding
 * @phy: a list of phys that make up this sas_host/expander
 * @sas_port_list: list of ports attached to this sas_host/expander
 */
struct _sas_node {
	struct list_head list;
	struct device *parent_dev;
	u8	num_phys;
	u64	sas_address;
	u16	handle;
	u64	sas_address_parent;
	u16	enclosure_handle;
	u64	enclosure_logical_id;
	u8	responding;
	struct	_sas_phy *phy;
	struct list_head sas_port_list;
};

/**
 * enum reset_type - reset state
 * @HARD_RESET: issue hard reset
 * @SOFT_RESET: issue soft reset, if fails to hard reset
 * @AER_RESET: issue CHIP RESET
 * @AER_RESET: isuue interrupt status for AER reset
 */
enum reset_type {
	HARD_RESET,
	SOFT_RESET,
	AER_RESET,
	AER_RESET_IS,
};



/**
 * struct chain_segment_t - firmware chain segment
 * @chain_buffer: chain buffer
 * @chain_buffer_dma: physical address
 * @free_list: list of free request (ioa->free_chain_list)
 */
struct chain_segment_t {
	struct list_head free_list;
	void *chain_buffer;
	dma_addr_t chain_buffer_dma;
};

struct chain_lookup {
	struct chain_segment_t *chains_per_host_tag_id;
	atomic_t	chain_offset;
};

/**
 * struct scsiio_tracker - scsi mf request tracker
 * @host_tag_id: message index
 * @scmd: scsi request pointer
 * @cb_idx: callback index
 * @direct_io: To indicate whether I/O is direct (WARPDRIVE)
 * @tracker_list: list of free request (ioa->free_list)
 * @msix_io: IO's msix
 */
struct scsiio_tracker {
	u16	host_tag_id;
	u8	cb_idx;
	u8	resv;
	u16	msix_io;
	u16	direct_io;
	struct list_head tracker_list;
};

/**
 * struct request_tracker - firmware request tracker
 * @host_tag_id: message index
 * @cb_idx: callback index
 * @tracker_list: list of free request (ioa->free_list)
 */
struct request_tracker {
	u16	host_tag_id;
	u8	cb_idx;
	struct list_head tracker_list;
};

/**
 * struct _tr_list - link reset list
 * @handle: device handle
 * @state: state machine
 */
struct _tr_list {
	struct list_head list;
	u16	handle;
	u16	state;
};

/**
 * struct _sc_list - delayed SAS_IO_UNIT_CONTROL message list
 * @handle: device handle
 */
struct _sc_list {
	struct list_head list;
	u16	handle;
};

/**
 * struct _event_ack_list - delayed event acknowledgment list
 * @event: Event ID
 * @event_context: used to track the event uniquely
 */
struct _event_ack_list {
	struct list_head list;
	u16	event;
	u32	event_context;
};

/**
 * struct adapter_reply_queue - the reply queue struct
 * @ioa: per adapter object
 * @msix_index: msix index into vector table
 * @vector: irq vector
 * @reply_post_host_index: head index in the pool where FW completes IO
 * @reply_post_free: reply post base virt address
 * @name: the name registered to request_irq()
 * @busy: isr is actively processing replies on another cpu
 * @list: this list
 */
struct adapter_reply_queue {
	struct HST2DR_ADAPTER	*ioa;
	u8			msix_index;
	SSI2_REPLY_DESCRIPTORS_UNION *reply_post_free;
	char			name[HST2DR_NAME_LENGTH];
	atomic_t		busy;
	struct list_head	list;
};

typedef void (*HST2DR_ADD_SGE)(void *paddr, u32 flags_length,
		dma_addr_t dma_addr);

/* SAS3.0 support */
typedef int (*HST2DR_BUILD_SG_SCMD)(struct HST2DR_ADAPTER *ioa,
		struct scsi_cmnd *scmd, u16 host_tag_id);
typedef void (*HST2DR_BUILD_SG)(struct HST2DR_ADAPTER *ioa, void *psge,
		dma_addr_t data_out_dma, size_t data_out_sz,
		dma_addr_t data_in_dma, size_t data_in_sz);
typedef void (*HST2DR_BUILD_ZERO_LEN_SGE)(struct HST2DR_ADAPTER *ioa,
		void *paddr);

typedef int (*HST2DR_PUT_MSG_INDEX_DEFAULT) (struct HST2DR_ADAPTER *, void *);


/* IOA Facts and Port Facts converted from little endian to cpu */
union SSI2_version_union {
	SSI2_VERSION_STRUCT		version;
	u32				dword;
};

struct hst2dr_info {
	u32			driver_version;
	u16			ioa_exceptions;
	u16			status;
	u32			log_info;
	u8			max_chain_depth;
	u8			owner;
	u8			num_ports;
	u16			max_msix_vectors;
	u16			max_sq;
	u16			max_cq;
	u16			max_sense;
	u16			request_credit;
	u16			PID;
	u32			ioa_capabilities;
	union SSI2_version_union	fw_version;
	u16			ioa_request_frame_size;
	u16			ioa_max_chain_segment_size;
	u16			max_initiators;
	u16			max_targets;
	u16			max_sas_expanders;
	u16			max_enclosures;
	u16			protocol_flags;
	u16			high_priority_credit;
	u16			max_reply_descriptor_post_queue_depth;
	u8			reply_frame_size;
	u16			max_dev_handle;
	u16			min_dev_handle;
	u8			host_page_size;
};


struct hst2dr_port_info {
	u8			port_number;
	u8			port_type;
	u16			max_cmd_buffers;
};

struct reply_post_struct {
	SSI2_REPLY_DESCRIPTORS_UNION	*reply_post_free;
	dma_addr_t			reply_post_free_dma;
};
struct sas_topo_struct {
	struct list_head list;
	SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST sas_topo;
};

#include "hst2dr_hal.h"
typedef void (*HST2DR_FLUSH_RUNNING_CMDS)(struct HST2DR_ADAPTER *ioa);
/**
 * struct HST2DR_ADAPTER - per adapter struct
 * @list: ioa_list
 * @shost: shost object
 * @id: unique adapter id
 * @cpu_count: number online cpus
 * @numa_count: numa nodes count
 * @numa_node_vectors: vectors in every numa node
 * @resv_vectos: reserved for numa vecotrs process
 * @name: generic ioa string
 * @driver_name: driver name string
 * @tmp_string: tmp string used for logging
 * @pdev: pci pdev object
 * @chip: memory mapped register space
 * @chip_phys: physical addrss prior to mapping
 * @fwfault_debug: debuging FW timeouts
 * @bars: bitmask of BAR's that must be configured
 * @mask_interrupts: ignore interrupt
 * @dma_mask: used to set the consistent dma mask
 * @fault_reset_work_queue_name: fw fault work queue
 * @fault_reset_work_queue: ""
 * @fault_reset_work: ""
 * @firmware_event_name: fw event work queue
 * @firmware_event_work_queue: ""
 * @fw_event_lock:
 * @fw_event_list: list of fw events
 * @aen_event_read_flag: event log was read
 * @broadcast_aen_busy: broadcast aen waiting to be serviced
 * @broadcast_aes_pending:
 * @shost_recovery: host reset in progress
 * @got_task_abort_from_ioctl:
 * @recent_reset_status: recently hard reset status
 * @reset_status: reset status
 * @reset_in_progress_mutex:
 * @ioa_reset_in_progress_lock:
 * @ioa_link_reset_in_progress: phy reset in progress
 * @ioa_reset_in_program: hard reset in grogress
 * @ignore_loginfos: ignore loginfos during task management
 * @remove_host: flag for when driver unloads, to avoid sending dev resets
 * @pci_error_recovery: flag to prevent ioa access until slot reset completes
 * @is_driver_loading: flag set at driver load time
 * @port_enable_failed: flag set when port enable has failed
 * @start_scan: flag set from scan_start callback, cleared from _hst2dr_fw_work
 * @start_scan_failed: means port enable failed, return's the ioa_status
 * @msix_enable: flag indicating msix is enabled
 * @msix_vector_count: number msix vectors
 * @cpu_msix_table: table for mapping cpus to msix index
 * @cpu_msix_table_sz: table size
 * @ioa_reset_count:
 * @schedule_dead_ioa_flush_running_cmds: callback to flush pending commands
 * @non_operational_loop:
 * @scsi_io_cb_idx: shost generated commands
 * @tm_cb_idx: task management commands
 * @transport_cb_idx: transport internal commands
 * @ctl_cb_idx: clt internal commands
 * @base_cb_idx: base internal commands
 * @config_cb_idx: base internal commands
 * @tr_cb_idx: device target reset handshake
 * @tr_vol_cb_idx: vd device target reset handshake
 * @admin_queues: admin queues
 * @pm_state: PM state
 * @base_cmds:
 * @port_enable_cmds:
 * @transport_cmds:
 * @tm_cmds:
 * @ctl_cmds:
 * @config_cmds:
 * @base_fill_1_sg: handler for either 32/64 bit sgl's
 * @event_type: bits indicating which events to log
 * @event_context: unique id for each logged event
 * @event_log: event log pointer
 * @event_masks: events that are masked
 * @info: static info data
 * @pinfo: static port info data
 * @vendor: static vendor page 0
 * @ioa01: static ioa page 1
 * @sas_hba: sas host object
 * @sas_expander_list: expander object list
 * @sas_node_lock:
 * @sas_device_list: sas device object list
 * @sas_device_init_list:
 * @sas_device_lock:
 * @io_missing_delay: time for IO completed by fw when PDR enabled
 * @device_missing_delay: time for device missing by fw when PDR enabled
 * @sas_id:
 * @blocking_handles: bitmask used to identify which devices need blocking
 * @config_page_sz: config page size
 * @config_page: reserve memory for config page payload
 * @config_page_dma:
 * @hba_queue_depth: hba request queue depth
 * @sge_size: sg element size for either 32/64 bit
 * @scsiio_depth: SCSI_IO queue depth
 * @request_sz: per request frame size
 * @request: pool of request frames
 * @request_dma:
 * @request_dma_sz:
 * @scsi_lookup: firmware request tracker list
 * @scsi_lookup_lock:
 * @free_list: free list of request
 * @pending_io_count:
 * @reset_wq:
 * @page_size:
 * @chain: pool of chains
 * @chain_dma:
 * @max_sges_in_main_message: number sg elements in main message
 * @max_sges_in_chain_message: number sg elements per chain
 * @chains_needed_per_io: max chains per io
 * @chain_depth: total chains allocated
 * @chain_segment_sz: gives the max number of
 *			SGEs accommodate on single chain buffer
 * @internal_host_tag_id:
 * @internal:
 * @internal_dma:
 * @internal_depth:
 * @internal_lookup:
 * @internal_free_list:
 * @sense: pool of sense
 * @sense_dma:
 * @sense_dma_pool:
 * @reply_sz: per reply frame size:
 * @reply: pool of replies:
 * @reply_dma:
 * @reply_dma_max_address:
 * @reply_dma_min_address:
 * @reply_dma_pool:
 * @reply_queue_depth: reply free depth
 * @reply_free: pool for reply free queue (32 bit addr)
 * @reply_free_dma:
 * @reply_free_dma_pool:
 * @reply_free_host_index: tail index in pool to insert free replies
 * @reply_post_queue_depth: reply post queue depth
 * @reply_post_free_dma_pool: struct for reply_post_free physical & virt address
 * @reply_queue_count: number of reply queue's
 * @reply_queue_list: link list contaning the reply queue info
 * @delayed_tr_list: link reset link list
 * @delayed_tr_vol_list: volume link reset link list
 * @delayed_event_ack_list:
 * @pci_access_mutex: Mutex to synchronize ioctl,sysfs show path and
 *	pci resource handling. PCI resource freeing will lead to free
 *	vital hardware/memory resource, which might be in use by cli/sysfs
 *	path functions resulting in Null pointer reference followed by kernel
 *	crash. To avoid the above race condition we use mutex syncrhonization
 *	which ensures the syncrhonization between cli/sysfs_show path.
 * @device_remove_in_progress_sz:
 * @raid_device_list: raid device object list
 * @raid_device_lock: raid device lock
 * @pd_handles: bitmask for PD handles
 * @pd_handles_sz: size of pd_handle bitmask
 * @wait_for_discovery_to_complete:
 * @ir_firmware: is raid firmware flag
 * @hst2dr_var: struct for hst2dr hal
 * @hst2dr_nvme_dma: nvme queue dma
 * @heartbeat: heart beat, update per 500ms
 */
struct HST2DR_ADAPTER {
	struct list_head list;
	struct Scsi_Host *shost;
	u8		id;
	u8		q_mode;
	u16		current_Q_num;
	u16		*tag_queue_number;
	u16		host_tag_id_offset[NUM_OF_IO_Q];
	u8		io_sequence_num[IO_QUEUE_SIZE + 64];
	int		cpu_count;
	int		numa_count;
	u8		numa_node_vectors[MAX_NUMA_NODE];
	int		total_irq;
	char		name[HST2DR_NAME_LENGTH];
	char		driver_name[HST2DR_NAME_LENGTH - 8];
	char		tmp_string[HST2DR_STRING_LENGTH];
	struct pci_dev	*pdev;

	SSI2_NVME_REGS __iomem *chip;
	resource_size_t	chip_phys;
	int ioa_debug_cmd;
	int		bars;
	u8		mask_interrupts;
	u8		smp_flags;
	u8		nonio_flags;
	u8		is_io_seq_num_check;
	unsigned int	log_level;
	int		dma_mask;

	/* fw fault handler */
	char	fault_reset_work_queue_name[20];
	struct workqueue_struct *fault_reset_work_queue;
	struct delayed_work fault_reset_work;

	/* fw event handler */
	char		firmware_event_name[20];
	struct workqueue_struct	*firmware_event_work_queue;
	spinlock_t	fw_event_lock;
	struct list_head fw_event_list;

	 /* misc flags */
	int		aen_event_read_flag;
	u8		broadcast_aen_busy;
	u8		broadcast_aen_pending;
	u8		shost_recovery;
	u8		got_task_abort_from_ioctl;
	int		recent_reset_status;
	int		reset_status;
	struct mutex	reset_in_progress_mutex;
	spinlock_t	ioa_reset_in_progress_lock;
	u8		ioa_link_reset_in_progress;
	u8		ioa_reset_in_progress;

	u8		ignore_loginfos;
	u8		remove_host;
	u8		pci_error_recovery;
	u8		is_driver_loading;
	u8		port_enable_failed;
	u8		start_scan;
	u16		start_scan_failed;
	u8		drv_stop_processing;

	u8		msix_enable;
	u16		msix_vector_count;
	u16		cpu_msix_table_sz;
	u8		*cpu_msix_table;
	u8		vector_node[256];
	u32		ioa_reset_count;
	HST2DR_FLUSH_RUNNING_CMDS schedule_dead_ioa_flush_running_cmds;
	u32		non_operational_loop;

	/* internal commands, callback index */
	u8		scsi_io_cb_idx;
	u8		tm_cb_idx;
	u8		transport_cb_idx;
	u8		ctl_cb_idx;
	u8		base_cb_idx;
	u8		port_enable_cb_idx;
	u8		config_cb_idx;
	u8		tr_cb_idx;
	u8		tr_vol_cb_idx;
	u8		admin_queues;
	u8		pm_state;
	u8		rsv1;

	struct _internal_cmd base_cmds;
	struct _internal_cmd port_enable_cmds;
	struct _internal_cmd transport_cmds;
	struct _internal_cmd tm_cmds;
	struct _internal_cmd ctl_cmds;
	struct _internal_cmd config_cmds;

	HST2DR_ADD_SGE	base_fill_1_sg;

	/* function ptr for either IEEE or SSI sg elements */
	HST2DR_BUILD_SG_SCMD build_sg_scmd;
	HST2DR_BUILD_SG		build_sg;
	HST2DR_BUILD_ZERO_LEN_SGE build_zero_len_sge;
	u16		sge_size_ieee;
	u16		hba_ssi_version_belonged;

	/* function ptr for SSI sg elements only */
	HST2DR_BUILD_SG		build_sg_ssi;
	HST2DR_BUILD_ZERO_LEN_SGE build_zero_len_sge_ssi;

	/* event log */
	u32		event_type[SSI2_EVENT_NOTIFY_EVENTMASK];
	u32		event_context;
	void		*event_log;
	u32		event_masks[SSI2_EVENT_NOTIFY_EVENTMASK];

	/* static config pages */
	struct hst2dr_info info;
	struct hst2dr_port_info *pinfo;
	SSI2_INQUIRY_PAGE_VENDOR vendor;
	SSI2_INQUIRY_IOA01 ioa01;

	/* sas hba, expander, and device list */
	struct _sas_node sas_hba;
	struct list_head sas_expander_list;
	struct list_head enclosure_list;
	spinlock_t	sas_node_lock;
	struct list_head sas_device_list;
	struct list_head sas_device_init_list;

	spinlock_t	sas_device_lock;

	u8		io_missing_delay;
	u8		rsv2;
	u16		device_missing_delay;
	int		sas_id;

	void		*blocking_handles;

	void		*pend_os_device_add;
	u16		pend_os_device_add_sz;

	/* config page */
	u16		config_page_sz;
	void		*config_page;
	dma_addr_t	config_page_dma;

	/* scsiio request */
	u16		hba_queue_depth;
	u16		sge_size;
	u16		scsiio_depth;
	u16		sense_depth;
	u16		request_sz;
	u16		host_tag_id_poll;
	u8		*request;
	dma_addr_t	request_dma;
	u32		request_dma_sz;
	struct scsiio_tracker *scsi_lookup;
	ulong		scsi_lookup_pages;
	spinlock_t	scsi_lookup_lock;
	struct list_head free_list;
	int		pending_io_count;
	wait_queue_head_t reset_wq;

	/* Host Page Size */
	u32		page_size;

	/* chain */
	struct chain_lookup *chain_lookup;
	struct list_head free_chain_list;
	struct dma_pool *chain_dma_pool;
	ulong		chain_pages;
	u16		max_sges_in_main_message;
	u16		max_sges_in_chain_message;
	u16		chains_needed_per_io;
	u16		chain_segment_sz;
	u32		chain_depth;


	/* internal queue */
	u16		internal_host_tag_id;
	u16		internal_depth;
	u8		*internal;
	dma_addr_t	internal_dma;
	struct request_tracker *internal_lookup;
	struct list_head internal_free_list;

	/* sense */
	u8		*sense;
	dma_addr_t	sense_dma;
	struct dma_pool *sense_dma_pool;

	/* reply */
	u16		reply_sz;
	u16		reply_queue_depth;
	u8		*reply;
	dma_addr_t	reply_dma;
	u32		reply_dma_max_address;
	u32		reply_dma_min_address;
	struct dma_pool *reply_dma_pool;

	/* reply free queue */
	__le32		*reply_free;
	dma_addr_t	reply_free_dma;
	struct dma_pool *reply_free_dma_pool;

	/* reply post queue */
	struct reply_post_struct *reply_post;
	u16		reply_post_queue_depth;
	u16		reply_queue_count;
	struct list_head reply_queue_list;


	struct list_head delayed_tr_list;
	struct list_head delayed_tr_vol_list;
	struct list_head delayed_event_ack_list;
	struct mutex pci_access_mutex;
	void	*device_remove_in_progress;
	u16		device_remove_in_progress_sz;
	u16		rsv3;
	HST2DR_PUT_MSG_INDEX_DEFAULT put_host_tag_id_default;
	HST2DR_PUT_MSG_INDEX_DEFAULT put_host_tag_id_ioctl;

	struct list_head raid_device_list;
	spinlock_t	raid_device_lock;
	void		*pd_handles;
	u16		pd_handles_sz;
	u8		wait_for_discovery_to_complete;
	u8		ir_firmware;
	struct	hst2dr_hba_var hst2dr_var;
	struct	hst2dr_hba_nvme_dma hst2dr_nvme_dma[NUM_OF_IO_Q + 1];
	U64 jiffies_ref;
	hst2dr_nvme_reply_sense_q_ctrl reply_sense_q_ctrl;
	spinlock_t	reply_sense_q_lock;
	u32		heartbeat;
	spinlock_t	nvmeq_lock[NUM_OF_IO_Q + 1];

	struct fw_event_work *current_event;
	u16		nvme_reg_dbs;
	u32		chip_version;
	atomic_t	fair_dispatched;
	atomic_t	ioctl_in_use;
};

typedef u8 (*HST2DR_CALLBACK)(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe);


/* base shared API */
extern struct list_head hst2dr_ioa_list;
extern char driver_name[HST2DR_NAME_LENGTH];
/* spinlock on list operations over IOAs
 * Case: when multiple warpdrive cards(IOAs) are in use
 * Each IOA will added to the ioa list structure on initialization.
 * Watchdog threads run at regular intervals to check IOA for any
 * fault conditions which will trigger the dead_ioa thread to
 * deallocate pci resource, resulting deleting the IOA netry from list,
 * this deletion need to protected by spinlock to enusre that
 * ioa removal is syncrhonized, if not synchronized it might lead to
 * list_del_init corruption as the ioa list is traversed in cli path.
 */
extern spinlock_t gioa_lock;
/**
 * struct _raid_device - raid volume link list
 * @list: sas device list
 * @starget: starget object
 * @sdev: scsi device struct (volumes are single lun)
 * @wwid: unique identifier for the volume
 * @handle: device handle
 * @block_size: Block size of the volume
 * @id: target id
 * @channel: target channel
 * @volume_type: the raid level
 * @device_info: bitfield provides detailed info about the hidden components
 * @num_pds: number of hidden raid components
 * @responding: used in _scsih_raid_device_mark_responding
 * @percent_complete: resync percent complete
 * @direct_io_enabled: Whether direct io to PDs are allowed or not
 * @stripe_exponent: X where 2powX is the stripe sz in blocks
 * @block_exponent: X where 2powX is the block sz in bytes
 * @max_lba: Maximum number of LBA in the volume
 * @stripe_sz: Stripe Size of the volume
 * @device_info: Device info of the volume member disk
 * @pd_handle: Array of handles of the physical drives for direct I/O in le16
 */
#define HST2DR_MAX_PDS		256
struct _raid_device {
	struct scsi_target *starget;
	struct scsi_device *sdev;
	u64	wwid;
	u16	handle;
	u16	block_sz;
	int	id;
	int	channel;
	u16	num_pds;
	u8	volume_type;
	u8	responding;
	u8	percent_complete;
	u8	direct_io_enabled;
	u8	stripe_exponent;
	u8	block_exponent;
	u16	io_qdepth;
	u16	resv;
	u64	max_lba;
	u32	stripe_sz;
	u32	device_info;
	struct list_head list;
	u16	pd_handle[HST2DR_MAX_PDS];
};

void hst2dr_base_start_watchdog(struct HST2DR_ADAPTER *ioa);
void hst2dr_base_stop_watchdog(struct HST2DR_ADAPTER *ioa);

int hst2dr_base_attach(struct HST2DR_ADAPTER *ioa);
void hst2dr_base_detach(struct HST2DR_ADAPTER *ioa);
int hst2dr_base_map_resources(struct HST2DR_ADAPTER *ioa);
void hst2dr_base_free_resources(struct HST2DR_ADAPTER *ioa);
int hst2dr_base_hard_reset_handler(struct HST2DR_ADAPTER *ioa,
	enum reset_type type, u32 res);

void *hst2dr_base_get_msg_frame(struct HST2DR_ADAPTER *ioa, u16 host_tag_id);
void *hst2dr_base_get_sense_buffer(struct HST2DR_ADAPTER *ioa, u16 host_tag_id);
__le32 hst2dr_base_get_sense_buffer_dma(struct HST2DR_ADAPTER *ioa,
	u16 host_tag_id);
void hst2dr_base_sync_reply_irqs(struct HST2DR_ADAPTER *ioa);

u16 hst2dr_base_get_host_tag_id_scsiio(struct HST2DR_ADAPTER *ioa, u8 cb_idx,
	struct scsi_cmnd *scmd);
struct scsiio_tracker *
_get_st_from_host_tag_id(struct HST2DR_ADAPTER *ioa, u16 host_tag_id);
void hst2dr_base_clear_st(struct HST2DR_ADAPTER *ioa,
		struct scsiio_tracker *st);
u16 hst2dr_base_get_host_tag_id(struct HST2DR_ADAPTER *ioa, u8 cb_idx);
void hst2dr_base_free_host_tag_id(struct HST2DR_ADAPTER *ioa, u16 host_tag_id);
void hst2dr_base_initialize_callback_handler(void);
u8 hst2dr_base_register_callback_handler(HST2DR_CALLBACK cb_func);
void hst2dr_base_release_callback_handler(u8 cb_idx);

u8 hst2dr_base_done(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe);
u8 hst2dr_port_enable_done(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe);
void *hst2dr_base_get_reply_virt_addr(struct HST2DR_ADAPTER *ioa,
	u16 reply_id);

u32 hst2dr_base_get_ioastate(struct HST2DR_ADAPTER *ioa, int cooked);

void hst2dr_base_fault_info(struct HST2DR_ADAPTER *ioa, u16 fault_code);
int hst2dr_base_sas_iounit_control(struct HST2DR_ADAPTER *ioa,
	SSI2_SAS_UNIT_CONTROL_REPLY *ssi_reply,
	SSI2_SAS_UNIT_CONTROL_REQUEST *ssi_request);

void hst2dr_base_validate_event_type(struct HST2DR_ADAPTER *ioa,
	u32 *event_type);

void hst2dr_base_update_missing_delay(struct HST2DR_ADAPTER *ioa,
	u16 device_missing_delay, u8 io_missing_delay);

int hst2dr_port_enable(struct HST2DR_ADAPTER *ioa);
void
hst2dr_wait_for_commands_to_complete(struct HST2DR_ADAPTER *ioa);
struct scsi_cmnd *
_hst2dr_scsi_lookup_get(struct HST2DR_ADAPTER *ioa, u16 host_tag_id);

/* scsih shared API */
u8 hst2dr_scsih_event_callback(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe);
void hst2dr_scsih_reset_handler(struct HST2DR_ADAPTER *ioa, int reset_phase);

int hst2dr_issue_tm(struct HST2DR_ADAPTER *ioa, u16 handle,
	uint channel, uint id, uint lun, u8 type, u16 host_tag_id_task,
	ulong timeout);
int hst2dr_issue_locked_tm(struct HST2DR_ADAPTER *ioa, u16 handle,
	uint channel, uint id, uint lun, u8 type, u16 host_tag_id_task,
	ulong timeout);
int hst2dr_issue_task_reset(struct HST2DR_ADAPTER *ioa, u16 handle);

void hst2dr_set_tm_flag(struct HST2DR_ADAPTER *ioa, u16 handle);
void hst2dr_clear_tm_flag(struct HST2DR_ADAPTER *ioa, u16 handle);
void hst2dr_expander_remove(struct HST2DR_ADAPTER *ioa, u64 sas_address);
void hst2dr_device_remove_by_sas_address(struct HST2DR_ADAPTER *ioa,
	u64 sas_address);
u8 hst2dr_check_for_pending_internal_cmds(struct HST2DR_ADAPTER *ioa,
	u16 host_tag_id);

struct _sas_node *hst2dr_expander_find_by_handle(
	struct HST2DR_ADAPTER *ioa, u16 handle);
struct _sas_node *hst2dr_expander_find_by_sas_address(
	struct HST2DR_ADAPTER *ioa, u64 sas_address);
struct _sas_device *hst2dr_get_sdev_by_addr(
	 struct HST2DR_ADAPTER *ioa, u64 sas_address);
struct _sas_device *__hst2dr_get_sdev_by_addr(
	 struct HST2DR_ADAPTER *ioa, u64 sas_address);

void hst2dr_port_enable_complete(struct HST2DR_ADAPTER *ioa);

/* config shared API */
u8 hst2dr_cfg_done(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe);
int hst2dr_cfg_get_number_hba_phys(struct HST2DR_ADAPTER *ioa,
	u8 *num_phys);
int hst2dr_cfg_get_vendor(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply,
	SSI2_INQUIRY_PAGE_VENDOR *config_page);

int hst2dr_cfg_get_sas_dev(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_SAS_DEV *config_page,
	u32 form, u32 handle);
int hst2dr_cfg_get_sas_unit0(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_SAS_UNIT0 *config_page,
	u16 sz);
int hst2dr_cfg_get_sas_unit1(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_SAS_UNIT1 *config_page,
	u16 sz);
int hst2dr_cfg_set_sas_unit1(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply,
	SSI2_INQUIRY_SAS_UNIT1 *config_page,
	u16 sz);
int hst2dr_cfg_get_ioa01(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_IOA01 *config_page);
int hst2dr_cfg_get_expander(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_EXPANDER *config_page,
	u32 form, u32 handle);
int hst2dr_cfg_get_expander_phy(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply,
	SSI2_INQUIRY_EXPANDER_PHY *config_page,
	u32 phy_number, u16 handle);
int hst2dr_cfg_get_enclosure(struct HST2DR_ADAPTER *ioa,
	SSI2_INQUIRY_PAGE_REPLY *ssi_reply, SSI2_INQUIRY_ENCLOSURE *config_page,
	u32 form, u32 handle);
int hst2dr_cfg_get_phy(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_PHY *config_page, int phy_number);
int hst2dr_cfg_get_phy_counter(struct HST2DR_ADAPTER *ioa,
		SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_PHY_COUNTER *config_page, int phy_number);
int
hst2dr_cfg_get_raid_vol(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_RAID_VOL *config_page,
	int sz, u32 form, u32 handle);
int hst2dr_cfg_get_raid_info(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_RAID_INFO *config_page, u32 form, u32 handle);
int
hst2dr_cfg_get_raid_pd(struct HST2DR_ADAPTER *ioa, SSI2_INQUIRY_PAGE_REPLY
	*ssi_reply, SSI2_INQUIRY_RAID_PD *config_page, u32 form, u32 handle);
int hst2dr_config_get_volume_wwid(struct HST2DR_ADAPTER *ioa, u16 volume_handle,
	u64 *wwid, U32 *device_info, u16 *qdepth);
struct _raid_device *
_hst2dr_raid_device_find_by_handle(struct HST2DR_ADAPTER *ioa, u16 handle);
/* ctl shared API */
extern const struct attribute_group *hst2dr_host_attr_groups[];
extern const struct attribute_group *hst2dr_dev_attr_groups[];
void hst2dr_ctl_init(void);
void hst2dr_ctl_exit(void);
u8 hst2dr_ctl_done(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe);
void hst2dr_ctl_reset_handler(struct HST2DR_ADAPTER *ioa, int reset_phase);
u8 hst2dr_ctl_event_callback(struct HST2DR_ADAPTER *ioa,
	hst2dr_nvme_completion *cqe);
void hst2dr_ctl_add_to_event_log(struct HST2DR_ADAPTER *ioa,
	SSI2_EVENT_NOTIFICATION_REPLY *ssi_reply);
/* transport shared API */
extern struct scsi_transport_template *hst2dr_transport_template;
u8 hst2dr_transport_done(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe);
struct _sas_port *hst2dr_transport_port_add(struct HST2DR_ADAPTER *ioa,
	u16 handle, u64 sas_address);
void hst2dr_transport_port_remove(struct HST2DR_ADAPTER *ioa, u64 sas_address,
	u64 sas_address_parent);
int hst2dr_transport_add_host_phy(struct HST2DR_ADAPTER *ioa, struct _sas_phy
	*hst2dr_phy, SSI2_INQUIRY_PHY phy_pg0, struct device *parent_dev);
int hst2dr_transport_add_expander_phy(struct HST2DR_ADAPTER *ioa,
	struct _sas_phy *hst2dr_phy, SSI2_INQUIRY_EXPANDER_PHY expander_phy,
	struct device *parent_dev);
void hst2dr_transport_update_links(struct HST2DR_ADAPTER *ioa,
	u64 sas_address, u16 handle, u8 phy_number, u8 link_rate);
int
hst2dr_config_get_volume_handle(struct HST2DR_ADAPTER *ioa, u16 pd_handle,
	u16 *volume_handle);
int
hst2dr_config_get_number_pds(struct HST2DR_ADAPTER *ioa, u16 handle,
	u16 *num_pds);
int
hst2dr_config_get_raid_handles(struct HST2DR_ADAPTER *ioa,
	U64 *volume_handles);

extern struct sas_function_template hst2dr_transport_functions;
extern struct scsi_transport_template *hst2dr_transport_template;
extern int hst2dr_select_q_mode;

/* NCQ Prio Handling Check */
bool hst2dr_ncq_prio_supp(struct scsi_device *sdev);

void hst2dr_ioa_debug(struct HST2DR_ADAPTER *ioa, int cmd, int data);
int
_base_allocate_memory_request_dma(struct HST2DR_ADAPTER *ioa);
int hst2dr_signature_sequence_check(struct HST2DR_ADAPTER *ioa);
void hst2dr_send_chip_reset_sequence(struct HST2DR_ADAPTER *ioa);
int _hst2dr_get_device_is_block(struct HST2DR_ADAPTER *ioa, u16 handle);
#endif /* HST2DR_BASE_H_INCLUDED */
