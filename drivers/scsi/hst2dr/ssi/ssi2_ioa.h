/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
 *
 * Name:  ssi2_ioa.h
 * Title:  SSI IOA, Port, Event, FW Download, and FW Upload messages
 * Creation Date:  Mar 1, 2022
 *
 * ssi2_ioa.h Version:  02.00.00
 *
 * NOTE: Names (typedefs, defines, etc.) beginning with an SSI2
 *       SSI2 are for use with both SSI v2.0 and later products.
 *
 * Version History
 * ---------------
 *
 * Date      Version   Description
 * --------  --------  ------------------------------------------------------
 * 03-01-22  02.00.00  Corresponds to -hst2dr SSI Specification Rev A.
 * --------------------------------------------------------------------------
 */

#ifndef SSI2_IOA_H
#define SSI2_IOA_H

/*****************************************************************************
 *
 *              IOA Messages
 *
 *****************************************************************************/

/****************************************************************************
 * IOAInit message
 ****************************************************************************/

/* IOAInit Request message */
typedef struct _SSI2_IOA_INIT_REQUEST {
	u8 opcode;			/* 0x00 */
	u8 opflags;			/* 0x01 */
	u16 host_tag_id;		/* 0x02 */
	u8 host_flag;			/* 0x04 */
	u8 reserved0[3];		/* 0x05 */

	U8 owner;			/* 0x08 */
	U8 resv0[3];			/* 0x09 */
	U32 driver_version;		/* 0x0C */
	U8 host_page_size;		/* 0x10 */
	U8 host_msix_vectors;		/* 0x11 */
	U16 reply_queue_depth;		/* 0x12 */
	U16 sense_queue_depth;		/* 0x14 */
	U16 sense_size;			/* 0x16 */
	U64 sense_buffer_address;	/* 0x18 */
	U64 reply_queue_address;	/* 0x20 */
	U64 time_stamp;			/* 0x28 */
	SSI2_SGE sgl;			/* 0x30 */
} SSI2_IOA_INIT_REQUEST;

/* WhoInit values */
#define SSI2_WHOINIT_HOST_DRIVER		(0x04)


/* MsgFlags */
#define SSI2_IOAINIT_MSGFLAG_RDPQ_ARRAY_MODE	(0x01)

/* IOAInit Reply message */
typedef struct _SSI2_IOA_INIT_REPLY {
	U8 msg_len;			/* 0x00 */
	U8 owner;			/* 0x01 */
	U8 msg_flags;			/* 0x02 */
	U8 opcode;			/* 0x03 */
	U32 resv0;			/* 0x04 */
	U16 resv1;			/* 0x08 */
	U16 status;			/* 0x0A */
	U32 log_info;			/* 0x0C */
} SSI2_IOA_INIT_REPLY;

/****************************************************************************
 * IOAFacts message
 ****************************************************************************/
typedef struct _SSI2_IOA_INFO_REQUEST {
	u8 opcode;			/* 0x00 */
	u8 opflags;			/* 0x01 */
	u16 host_tag_id;		/* 0x02 */
	u8 host_flag;			/* 0x04 */
	u8 reserved0[11];		/* 0x05 */
	SSI2_SGE sgl;			/* 0x10 */
} SSI2_IOA_INFO_REQUEST;

/* IOAFacts Reply message */
typedef struct _SSI2_IOA_INFO_REPLY {
	U8 msg_len;					/* 0x00 */
	U8 ioa_num;					/* 0x01 */
	U8 msg_flags;					/* 0x02 */
	U8 opcode;					/* 0x03 */
	U32 driver_version;				/* 0x04 */
	U16 ioa_exceptions;				/* 0x08 */
	U16 max_msix_vectors;				/* 0x0A */
	U32 log_info;					/* 0x0C */
	U8 max_chain_depth;				/* 0x10 */
	U8 owner;					/* 0x11 */
	U8 num_ports;					/* 0x12 */
	U8 resv0;					/* 0x13 */
	U16 max_sq;					/* 0x14 */
	U16 max_sense;					/* 0x16 */
	U16 request_credit;				/* 0x18 */
	U16 PID;					/* 0x1A */
	U32 ioa_capabilities;				/* 0x1C */
	SSI2_VERSION_UNION fw_version;			/* 0x20 */
	U16 ioa_request_frame_size;			/* 0x24 */
	U16 ioa_max_chain_segment_size;			/* 0x26 */
	U16 max_initiators;				/* 0x28 */
	U16 max_targets;				/* 0x2A */
	U16 max_sas_expanders;				/* 0x2C */
	U16 max_enclosures;				/* 0x2E */
	U16 protocol_flags;				/* 0x30 */
	U16 high_priority_credit;			/* 0x32 */
	U16 max_reply_descriptor_post_queue_depth;	/* 0x34 */
	U8 reply_frame_size;				/* 0x36 */
	U8 smp_flags;					/* 0x37 */
	U16 max_dev_handle;				/* 0x38 */
	U16 min_dev_handle;				/* 0x3A */
	U8 host_page_size;				/* 0x3C */
	U8 nonio_flags;					/* 0x3D */
	U16 max_cq;					/* 0x3E */
	U16 max_vds;					/* 0x40 */
	U16 max_host_pds;				/* 0x42 */
	U16 max_raid_pds;				/* 0x44 */
	U16 max_raid_group;				/* 0x46 */
	U16 shutdown_timeout;				/* 0x48 */
	U16 resv1;					/* 0x4A */
	U16 max_log_size;				/* 0x4C */
	U16 max_fw_log_buffer;				/* 0x4E */
	U32 log_level;					/* 0x50 */
} SSI2_IOA_INFO_REPLY;

/* defines for owner field are after the IOAInit Request */

/* ProductID field uses SSI2_FW_HEADER_PID_ */

/* ProtocolFlags */
#define SSI2_IOA_INFO_PROTOCOL_SCSI_INITIATOR		(0x0002)
#define SSI2_IOA_INFO_PROTOCOL_SCSI_TARGET		(0x0001)

/****************************************************************************
 * PortEnable message
 ****************************************************************************/

/* PortEnable Request message */
typedef struct _SSI2_PORT_ENABLE_REQUEST {
	u8 opcode;			/* 0x00 */
	u8 opflags;			/* 0x01 */
	u16 host_tag_id;		/* 0x02 */
	u8 host_flag;			/* 0x04 */
	u8 reserved0[3];		/* 0x05 */
} SSI2_PORT_ENABLE_REQUEST;

/* PortEnable Reply message */
typedef struct _SSI2_PORT_ENABLE_REPLY {
	U8 msg_len;			/* 0x00 */
	U8 resv0;			/* 0x01 */
	U8 msg_flags;			/* 0x02 */
	U8 opcode;			/* 0x03 */
	U32 resv1;			/* 0x04 */
	U16 resv2;			/* 0x08 */
	U16 status;			/* 0x0A */
	U32 log_info;			/* 0x0C */
} SSI2_PORT_ENABLE_REPLY;

/****************************************************************************
 * EventNotification message
 ****************************************************************************/

/* EventNotification Request message */
#define SSI2_EVENT_NOTIFY_EVENTMASK		(4)

typedef struct _SSI2_EVENT_NOTIFICATION_REQUEST {
	u8 opcode;			/* 0x00 */
	u8 opflags;			/* 0x01 */
	u16 host_tag_id;		/* 0x02 */
	u8 host_flag;			/* 0x04 */
	u8 reserved0[3];		/* 0x05 */

	U8 resv1[8];			/* 0x08 */
	U32 event_masks[SSI2_EVENT_NOTIFY_EVENTMASK];	/* 0x10 */
} SSI2_EVENT_NOTIFICATION_REQUEST;

/* EventNotification Reply message */
typedef struct _SSI2_EVENT_NOTIFICATION_REPLY {
	U8 msg_len;			/* 0x00 */
	U8 ack_required;		/* 0x01 */
	U8 msg_flags;			/* 0x02 */
	U8 opcode;			/* 0x03 */
	U32 resv0;			/* 0x04 */
	U16 event_data_len;		/* 0x08 */
	U16 status;			/* 0x0A */
	U32 log_info;			/* 0x0C */
	U16 event;			/* 0x10 */
	U16 resv1;			/* 0x12 */
	U32 event_context;		/* 0x14 */
	U32 event_data[];		/* 0x18 */
} SSI2_EVENT_NOTIFICATION_REPLY;

/* AckRequired */

#define SSI2_EVENT_NOTIFICATION_ACK_REQUIRED		(0x01)

/* Event */
#define SSI2_EVENT_SAS_DEVICE_STATUS_CHANGE		(0x000F)
#define SSI2_EVENT_SAS_DISCOVERY			(0x0016)
#define SSI2_EVENT_SAS_BROADCAST_PRIMITIVE		(0x0017)
#define SSI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST		(0x001C)
#define SSI2_EVENT_SAS_ENCL_DEVICE_STATUS_CHANGE	(0x001D)
//raid related event
#define SSI2_EVENT_IR_CONFIGURATION_CHANGE_LIST		(0x0020)
#define SSI2_EVENT_IR_VOLUME				(0x001E)
#define SSI2_EVENT_IR_PHYSICAL_DISK			(0x001F)
#define SSI2_EVENT_IR_OPERATION_STATUS			(0x0014)


/* SAS Device Status Change Event data */

typedef struct _SSI2_EVENT_DATA_SAS_DEVICE_STATUS_CHANGE {
	U8 reason_code;				/* 0x00 */
	U8 resv[3];				/* 0x01 */
	U8 asc;					/* 0x04 */
	U8 ascq;				/* 0x05 */
	U16 dev_handle;				/* 0x06 */
	U64 sas_address;			/* 0x08 */
	U8 lun[8];				/* 0x10 */
} SSI2_EVENT_DATA_SAS_DEVICE_STATUS_CHANGE;

/*SAS Device Status Change Event data ReasonCode values */
#define SSI2_EVENT_SAS_DEV_STAT_RC_SMART_DATA				(0x05)
#define SSI2_EVENT_SAS_DEV_STAT_RC_UNSUPPORTED				(0x07)
#define SSI2_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET		(0x08)
#define SSI2_EVENT_SAS_DEV_STAT_RC_TASK_ABORT_INTERNAL			(0x09)
#define SSI2_EVENT_SAS_DEV_STAT_RC_ABORT_TASK_SET_INTERNAL		(0x0A)
#define SSI2_EVENT_SAS_DEV_STAT_RC_CLEAR_TASK_SET_INTERNAL		(0x0B)
#define SSI2_EVENT_SAS_DEV_STAT_RC_QUERY_TASK_INTERNAL			(0x0C)
#define SSI2_EVENT_SAS_DEV_STAT_RC_ASYNC_NOTIFICATION			(0x0D)
#define SSI2_EVENT_SAS_DEV_STAT_RC_CMP_INTERNAL_DEV_RESET		(0x0E)
#define SSI2_EVENT_SAS_DEV_STAT_RC_CMP_TASK_ABORT_INTERNAL		(0x0F)
#define SSI2_EVENT_SAS_DEV_STAT_RC_SATA_INIT_FAILURE			(0x10)
#define SSI2_EVENT_SAS_DEV_STAT_RC_EXPANDER_REDUCED_FUNCTIONALITY	(0x11)
#define SSI2_EVENT_SAS_DEV_STAT_RC_CMP_EXPANDER_REDUCED_FUNCTIONALITY	(0x12)

/* SAS Discovery Event data */

typedef struct _SSI2_EVENT_DATA_SAS_DISCOVERY {
	U8 reason_code;				/* 0x00 */
	U8 resv[3];				/* 0x02 */
	U32 discovery_status;			/* 0x04 */
} SSI2_EVENT_DATA_SAS_DISCOVERY;

/* SAS Discovery Event data ReasonCode values */
#define SSI2_EVENT_SAS_DISC_RC_STARTED		(0x01)
#define SSI2_EVENT_SAS_DISC_RC_COMPLETED	(0x02)

/* SAS Broadcast Primitive Event data */

typedef struct _SSI2_EVENT_DATA_SAS_BC_PRIMITIVE {
	U8 phy_num;				/* 0x00 */
	U8 port;				/* 0x01 */
	U8 port_width;				/* 0x02 */
	U8 primitive;				/* 0x03 */
} SSI2_EVENT_DATA_SAS_BC_PRIMITIVE;

/* defines for the Primitive field */

#define SSI2_EVENT_PRIMITIVE_ASYNCHRONOUS_EVENT			(0x04)

/* SAS Topology Change List Event data */

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this define set to
 * one and check NumEntries at runtime.
 */

typedef struct _SSI2_EVENT_SAS_TOPO_PHY_ENTRY {
	U16 attached_dev_handle;		/* 0x00 */
	U8 linkrate;				/* 0x02 */
	U8 phy_status;				/* 0x03 */
} SSI2_EVENT_SAS_TOPO_PHY_ENTRY;

typedef struct _SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST {
	U16 enclosure_handle;			/* 0x00 */
	U16 expander_dev_handle;		/* 0x02 */
	U8 num_phys;				/* 0x04 */
	U8 num_entries;				/* 0x05 */
	U8 start_phy_num;			/* 0x06 */
	U8 exp_status;				/* 0x07 */
	U8 physical_port;			/* 0x08 */
	U8 resv[3];				/* 0x09 */
	SSI2_EVENT_SAS_TOPO_PHY_ENTRY phy[];	/* 0x0C */
} SSI2_EVENT_DATA_SAS_TOPOLOGY_CHANGE_LIST;

/* values for the ExpStatus field */
#define SSI2_EVENT_SAS_TOPO_ES_ADDED				(0x01)
#define SSI2_EVENT_SAS_TOPO_ES_NOT_RESPONDING			(0x02)
#define SSI2_EVENT_SAS_TOPO_ES_RESPONDING			(0x03)
#define SSI2_EVENT_SAS_TOPO_ES_DELAY_NOT_RESPONDING		(0x04)

/* values for the PhyStatus field */
#define SSI2_EVENT_SAS_TOPO_PHYSTATUS_VACANT			(0x80)
#define SSI2_EVENT_SAS_TOPO_RC_MASK				(0x0F)
#define SSI2_EVENT_SAS_TOPO_RC_TARG_ADDED			(0x01)
#define SSI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING		(0x02)
#define SSI2_EVENT_SAS_TOPO_RC_PHY_CHANGED			(0x03)
#define SSI2_EVENT_SAS_TOPO_RC_NO_CHANGE			(0x04)
#define SSI2_EVENT_SAS_TOPO_RC_DELAY_NOT_RESPONDING		(0x05)

/* SAS Enclosure Device Status Change Event data */

typedef struct _SSI2_EVENT_DATA_SAS_ENCLOSURE_DEV_STATUS_CHANGE {
	U16 enclosure_handle;			/* 0x00 */
	U8 reason_code;				/* 0x02 */
	U8 resv0;				/* 0x03 */
	U16 num_slots;				/* 0x04 */
	U16 start_slot;				/* 0x06 */
	U64 enclosure_logical_id;		/* 0x08 */
} SSI2_EVENT_DATA_SAS_ENCLOSURE_DEV_STATUS_CHANGE;

/* SAS Enclosure Device Status Change event ReasonCode values */
#define SSI2_EVENT_SAS_ENCL_RC_ADDED		(0x01)
#define SSI2_EVENT_SAS_ENCL_RC_NOT_RESPONDING	(0x02)

/****************************************************************************
 * EventAck message
 ****************************************************************************/

/*EventAck Request message */
typedef struct _SSI2_EVENT_ACK_REQUEST {
	u8 opcode;				/* 0x00 */
	u8 opflags;				/* 0x01 */
	u16 host_tag_id;			/* 0x02 */
	u8 host_flag;				/* 0x04 */
	u8 reserved0[3];			/* 0x05 */

	U8 resv0[2];				/* 0x08 */
	U8 msg_flags;				/* 0x0A */
	U8 resv1;				/* 0x0B */
	U16 event;				/* 0x0C */
	U16 resv2;				/* 0x0E */
	U32 event_context;			/* 0x10 */
	U32 resv3;				/* 0x14 */
} SSI2_EVENT_ACK_REQUEST;

typedef struct _SSI2_EVENT_IR_CONFIG_ELEMENT {
	U8 element_flags;			/* 0x00 */
	U8 reason_code1;			/* 0x01 */
	U16 vol_dev_handle;			/* 0x02 */
	U8 reason_code;				/* 0x04 */
	U8 phys_logic_id;			/* 0x05 */
	U16 phys_disk_dev_handle;		/* 0x06 */
} SSI2_EVENT_IR_CONFIG_ELEMENT, *PTR_SSI2_EVENT_IR_CONFIG_ELEMENT;

typedef struct _SSI2_EVENT_DATA_IR_CONFIG_CHANGE_LIST {
	U8 num_elements;
	U8 config_num;
	U16 reserved1;
	U32 flags;
	SSI2_EVENT_IR_CONFIG_ELEMENT	config_element[];
} SSI2_EVENT_DATA_IR_CONFIG_CHANGE_LIST,
*PTR_SSI2_EVENT_DATA_IR_CONFIG_CHANGE_LIST;
/* flags values */
#define SSI2_EVENT_IR_CHANGE_FLAGS_FOREIGN_CONFIG		(0x00000001)

/* IR Configuration Change List Event data element_flags values */
#define SSI2_EVENT_IR_CHANGE_EFLAGS_ELEMENT_TYPE_MASK		(0x000F)
#define SSI2_EVENT_IR_CHANGE_EFLAGS_VOLUME_ELEMENT		(0x0000)
#define SSI2_EVENT_IR_CHANGE_EFLAGS_VOLPHYSDISK_ELEMENT		(0x0001)
#define SSI2_EVENT_IR_CHANGE_EFLAGS_HOTSPARE_ELEMENT		(0x0002)

/* IR Configuration Change List Event data ReasonCode values */
#define SSI2_EVENT_IR_CHANGE_RC_ADDED				(0x01)
#define SSI2_EVENT_IR_CHANGE_RC_REMOVED				(0x02)
#define SSI2_EVENT_IR_CHANGE_RC_NO_CHANGE			(0x03)
#define SSI2_EVENT_IR_CHANGE_RC_HIDE				(0x09)
#define SSI2_EVENT_IR_CHANGE_RC_UNHIDE				(0x08)
#define SSI2_EVENT_IR_CHANGE_RC_VOLUME_CREATED			(0x06)
#define SSI2_EVENT_IR_CHANGE_RC_VOLUME_DELETED			(0x07)
#define SSI2_EVENT_IR_CHANGE_RC_PD_CREATED			(0x05)
#define SSI2_EVENT_IR_CHANGE_RC_PD_DELETED			(0x04)

/****************************************************************************
 * EVENT DATA IR VOLUME
 ****************************************************************************/
typedef struct _SSI2_EVENT_DATA_IR_VOLUME {
	u16 vol_dev_handle;
	u8 reason_code;
	u8 reserved1;
	u32 new_value;
	u32 previous_value;
} SSI2_EVENT_DATA_IR_VOLUME;

/* Integrated RAID Volume Event data reason_code values */
#define SSI2_EVENT_IR_VOLUME_RC_SETTINGS_CHANGED		(0x01)
#define SSI2_EVENT_IR_VOLUME_RC_STATUS_FLAGS_CHANGED		(0x02)
#define SSI2_EVENT_IR_VOLUME_RC_STATE_CHANGED			(0x03)

/****************************************************************************
 * EVENT DATA IR PHYSICAL DISK
 ****************************************************************************/
typedef struct _SSI2_EVENT_DATA_IR_PHYSICAL_DISK {
	u8 reason_code;
	u8 resv0;
	u16 phys_disk_dev_handle;
	u16 slot;
	u16 enclosure_handle;
	u32 new_value;
	u32 previous_value;
	u16 phys_logic_id;
	u16 resv1;
} SSI2_EVENT_DATA_IR_PHYSICAL_DISK;

/* Integrated RAID Physical Disk Event data ReasonCode values */
#define SSI2_EVENT_IR_PHYSDISK_RC_SETTINGS_CHANGED		(0x01)
#define SSI2_EVENT_IR_PHYSDISK_RC_STATUS_FLAGS_CHANGED		(0x02)
#define SSI2_EVENT_IR_PHYSDISK_RC_STATE_CHANGED			(0x03)
/* PhysDiskState defines */
#define SSI2_RAID_PD_STATE_NOT_CONFIGURED			(0x00)
#define SSI2_RAID_PD_STATE_NOT_COMPATIBLE			(0x01)
#define SSI2_RAID_PD_STATE_OFFLINE				(0x02)
#define SSI2_RAID_PD_STATE_ONLINE				(0x03)
#define SSI2_RAID_PD_STATE_HOT_SPARE				(0x04)
#define SSI2_RAID_PD_STATE_DEGRADED				(0x05)
#define SSI2_RAID_PD_STATE_REBUILDING				(0x06)
#define SSI2_RAID_PD_STATE_OPTIMAL				(0x07)
/****************************************************************************
 * EVENT DATA IR OPERATION STATUS
 ****************************************************************************/
typedef struct _SSI2_EVENT_DATA_IR_OPERATION_STATUS {
	u16 vol_dev_handle;
	u8 raid_operation;
	u8 percent_complete;
	u32 elapsed_seconds;
} SSI2_EVENT_DATA_IR_OPERATION_STATUS;

/* Integrated RAID Operation Status Event data RAIDOperation values */
#define SSI2_EVENT_IR_RAIDOP_RESYNC				(0x00)
#define SSI2_EVENT_IR_RAIDOP_ONLINE_CAP_EXPANSION		(0x01)
#define SSI2_EVENT_IR_RAIDOP_CONSISTENCY_CHECK			(0x02)
#define SSI2_EVENT_IR_RAIDOP_BACKGROUND_INIT			(0x03)
#define SSI2_EVENT_IR_RAIDOP_MAKE_DATA_CONSISTENT		(0x04)
/****************************************************************************
 * RAID Action messages
 ****************************************************************************/
/*RAID Action Request Message */
typedef struct _SSI2_RAID_ACTION_REQUEST {
	u8 opcode;				/* 0x00 */
	u8 opflags;				/* 0x01 */
	u16 host_tag_id;			/* 0x02 */
	u8 host_flag;				/* 0x04 */
	u8 reserved0[3];			/* 0x05 */

	U8 action;				/* 0x08 */
	U8 msg_flags;				/* 0x09 */
	U8 reserved1[2];			/* 0x0A */
	U16 vol_dev_handle;			/* 0x0C */
	U16 phys_logic_id;			/* 0x0E */
} SSI2_RAID_ACTION_REQUEST;

/*RAID Action request Action values */

#define SSI2_RAID_ACTION_INDICATOR_STRUCT		(0x01)
#define SSI2_RAID_ACTION_CREATE_VOLUME			(0x02)
#define SSI2_RAID_ACTION_DELETE_VOLUME			(0x03)
#define SSI2_RAID_ACTION_DISABLE_ALL_VOLUMES		(0x04)
#define SSI2_RAID_ACTION_ENABLE_ALL_VOLUMES		(0x05)
#define SSI2_RAID_ACTION_PHYSDISK_OFFLINE		(0x0A)
#define SSI2_RAID_ACTION_PHYSDISK_ONLINE		(0x0B)
#define SSI2_RAID_ACTION_FAIL_PHYSDISK			(0x0F)
#define SSI2_RAID_ACTION_ACTIVATE_VOLUME		(0x11)
#define SSI2_RAID_ACTION_DEVICE_FW_UPDATE_MODE		(0x15)
#define SSI2_RAID_ACTION_CHANGE_VOL_WRITE_CACHE		(0x17)
#define SSI2_RAID_ACTION_SET_VOLUME_NAME		(0x18)
#define SSI2_RAID_ACTION_SET_RAID_FUNCTION_RATE		(0x19)
#define SSI2_RAID_ACTION_ENABLE_FAILED_VOLUME		(0x1C)
#define SSI2_RAID_ACTION_CREATE_HOT_SPARE		(0x1D)
#define SSI2_RAID_ACTION_DELETE_HOT_SPARE		(0x1E)
#define SSI2_RAID_ACTION_SYSTEM_SHUTDOWN_INITIATED	(0x20)
#define SSI2_RAID_ACTION_START_RAID_FUNCTION		(0x21)
#define SSI2_RAID_ACTION_STOP_RAID_FUNCTION		(0x22)
#define SSI2_RAID_ACTION_COMPATIBILITY_CHECK		(0x23)
#define SSI2_RAID_ACTION_PHYSDISK_HIDDEN		(0x24)
#define SSI2_RAID_ACTION_MIN_PRODUCT_SPECIFIC		(0x80)
#define SSI2_RAID_ACTION_MAX_PRODUCT_SPECIFIC		(0xFF)

/*RAID Volume Creation Structure */
/*RAID Action Reply Message */
typedef struct _SSI2_RAID_ACTION_REPLY {
	U8 msg_len;			/* 0x00 */
	U8 msg_flags;			/* 0x01 */
	U8 action;			/* 0x02 */
	U8 opcode;			/* 0x03 */
	U16 vol_dev_handle;		/* 0x04 */
	U16 phys_logic_id;		/* 0x06 */
	U16 resv;			/* 0x08 */
	U16 status;			/* 0x0A */
	U32 log_info;			/* 0x0C */
} SSI2_RAID_ACTION_REPLY;

/****************************************************************************
 * Shutdown messages
 ****************************************************************************/
/*	shutdown Request Message */
typedef struct _SSI2_SHUTDOWN_REQUEST {
	u8 opcode;				/* 0x00 */
	u8 opflags;				/* 0x01 */
	u16 host_tag_id;			/* 0x02 */
	u8 host_flag;				/* 0x04 */
	u8 reserved0[3];			/* 0x05 */

	U8 action;				/* 0x08 */
	U8 reserved1[3];			/* 0x09 */
} SSI2_SHUTDOWN_REQUEST;

#define SSI2_SYSTEM_SHUTDOWN_NORMAL		0x20
#define SSI2_SYSTEM_SHUTDOWN_ERROR		0x01

/****************************************************************************
 * UPLOAD & DOWNLOAD FW
 ****************************************************************************/
typedef struct _SSI2_FW_UP_DOWN_REQUEST {
	u8 opcode;				/* 0x00 */
	u8 opflags;				/* 0x01 */
	u16 host_tag_id;			/* 0x02 */
	u8 host_flag;				/* 0x04 */
	u8 reserved0[3];			/* 0x05 */

	u16 msg_len;				/* 0x08 */
	u8 msg_flags;				/* 0x0A */
	u8 resv0;				/* 0x0B */
	u16 dev_handle;				/* 0x0C */
	u16 resv1;				/* 0x0E */
	u32 offset;				/* 0x10 */
	u32 length;				/* 0x04 */
	u32 resv2[2];				/* 0x18 */
	SSI2_SGE sgl[2];			/* 0x20 */
} SSI2_FW_UP_DOWN_REQUEST, *PTR_SSI2_FW_UP_DOWN_REQUEST;
#endif
