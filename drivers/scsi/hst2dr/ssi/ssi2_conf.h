/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
 *
 *
 * Name:  ssi2_init.h
 * Creation Date:  March 1st, 2022
 *
 * Version History
 * ---------------
 *
 * Date      Version   Description
 * --------  --------  ------------------------------------------------------
 * 03-01-22  02.00.00  Corresponds to -hst2dr SSI Specification Rev A.
 * --------------------------------------------------------------------------
 */
#ifndef SSI2_CNFG_H
#define SSI2_CNFG_H

/*****************************************************************************
 *  Configuration Page Header and defines
 *****************************************************************************/

/*Inquiry Page Header */
typedef struct _SSI2_INQUIRY_PAGE_H {
	U8		type;		/* 0x00 */
	U8		number;		/* 0x01 */
	U8		cmd;		/* 0x02 */
	U8		resv0;		/* 0x03 */
	U16		len;		/* 0x04 */
	U8		resv1[2];	/* 0x06 */
} SSI2_INQUIRY_PAGE_H, *PTR_SSI2_INQUIRY_PAGE_H;

/*Type field values */
#define SSI2_CONFIG_TYPE_PHY				(0x07)
#define SSI2_CONFIG_TYPE_SAS_DEV			(0x08)
#define SSI2_CONFIG_TYPE_VENDOR				(0x0A)
#define SSI2_CONFIG_TYPE_IOA				(0x0B)
#define SSI2_CONFIG_TYPE_SAS_UNIT			(0x0C)
#define SSI2_CONFIG_TYPE_ENCLOSURE			(0x0D)
#define SSI2_CONFIG_TYPE_EXPANDER			(0x0E)
#define SSI2_CONFIG_TYPE_RAID				(0x0F)

/*values for the cmd field */
#define SSI2_CONFIG_CMD_PAGE_READ_CURRENT		(0x01)
#define SSI2_CONFIG_CMD_PAGE_WRITE_CURRENT		(0x02)
#define SSI2_CONFIG_CMD_PAGE_READ_NVRAM			(0x03)
#define SSI2_CONFIG_CMD_PAGE_WRITE_NVRAM		(0x04)

/*Expander PageAddress format */
#define SSI2_SAS_EXPAND_PGAD_FORM_GET_NEXT_HNDL		(0x00000000)
#define SSI2_SAS_EXPAND_PGAD_FORM_HNDL_PHY_NUM		(0x10000000)
#define SSI2_SAS_EXPAND_PGAD_FORM_HNDL			(0x20000000)

#define SSI2_SAS_EXPAND_PGAD_PHYNUM_SHIFT		(16)


/*SAS Device PageAddress format */
#define SSI2_SAS_DEVICE_PGAD_FORM_GET_NEXT_HANDLE	(0x00000000)
#define SSI2_SAS_DEVICE_PGAD_FORM_HANDLE		(0x20000000)



/*SAS PHY PageAddress format */

#define SSI2_SAS_PHY_PGAD_FORM_PHY_NUMBER		(0x00000000)


/*SAS Enclosure PageAddress format */

#define SSI2_SAS_ENCLOS_PGAD_FORM_HANDLE		(0x10000000)

/*SAS Raid PageAddress format */
#define SSI2_RAID_VOLUME_PGAD_FORM_HANDLE		(0x10000000)
#define SSI2_RAID_VOLUME_PGAD_FORM_GET_NEXT_HANDLE	(0x00000000)
/*RAID Physical Disk PageAddress format */
#define SSI2_PHYSDISK_PGAD_FORM_MASK			(0xF0000000)
#define SSI2_PHYSDISK_PGAD_FORM_GET_NEXT_PHYSDISKNUM	(0x00000000)
#define SSI2_PHYSDISK_PGAD_FORM_PHYSDISKNUM		(0x10000000)
#define SSI2_PHYSDISK_PGAD_FORM_DEVHANDLE		(0x20000000)

#define SSI2_PHYSDISK_PGAD_PHYSDISKNUM_MASK		(0x000000FF)
#define SSI2_PHYSDISK_PGAD_DEVHANDLE_MASK		(0x0000FFFF)

/****************************************************************************
 *  Configuration messages
 ****************************************************************************/

/*Inquiry Request Message */

typedef struct _SSI2_INQUIRY_PAGE_REQUEST {
	u8 opcode;			/* 0x00 */
	u8 opflags;			/* 0x01 */
	u16 host_tag_id;		/* 0x02 */
	u8 host_flag;			/* 0x04 */
	u8 reserved0[3];		/* 0x05 */

	SSI2_INQUIRY_PAGE_H header;	/* 0x08 */
	U8		sgl_type;	/* 0x10 */
	U8		resv0[3];	/* 0x11 */
	U32		address;	/* 0x14 */
	U32		resv1[2];	/* 0x18 */
	SSI2_SGE	sge;		/* 0x20 */
} SSI2_INQUIRY_PAGE_REQUEST, *PTR_SSI2_INQUIRY_PAGE_REQUEST;




/*Inquiry Reply Message */

typedef struct _SSI2_INQUIRY_PAGE_REPLY {
	SSI2_INQUIRY_PAGE_H	header;		/* 0x00 */
	U8	sgl_type;			/* 0x08 */
	U8	msg_len;			/* 0x09 */
	U16	status;				/* 0x0A */
	U32	log_info;			/* 0x0C */
} SSI2_INQUIRY_PAGE_REPLY, *PTR_SSI2_INQUIRY_PAGE_REPLY;

/*****************************************************************************
 *
 *              cfg    pgs
 *
 *****************************************************************************/

/****************************************************************************
 *  VENDOR Config pages
 ****************************************************************************/
#define SSI2_MFG_VENDORID_HST2				(0x20ca)
#define SSI2_MFG_DEVID_HST2DR_HBA			(0x033d)
#define SSI2_MFG_DEVID_HST2DR_RAID			(0x133d)

/*VENDOR Page 0 */

typedef struct _SSI2_INQUIRY_PAGE_VENDOR {
	U8 chip_name[16];			/* 0x00 */
	U8 chip_revision[8];			/* 0x10 */
	U8 board_name[16];			/* 0x18 */
	U8 module_id[16];			/* 0x28 */
	U8 serial_number[20];			/* 0x38 */
	u8 board_assembly[2];			/* 0x4C */
	u8 board_tracer_number[2];		/* 0x4E */
	u8 vpd[32];				/* 0x50 */
} SSI2_INQUIRY_PAGE_VENDOR,
	*PTR_SSI2_INQUIRY_PAGE_VENDOR;


/****************************************************************************
 *  IOA Config Pages
 ****************************************************************************/
/*IOA01 */

typedef struct _SSI2_INQUIRY_IOA01 {
	U8	num_dev_per_enclosure;		/* 0x00 */
	U8	resv0;				/* 0x01 */
	U16	max_persistent_entries;		/* 0x02 */
	U16	max_num_physical_mapped_ids;	/* 0x04 */
	U16	flags;				/* 0x06 */
	u16	ir_volume_mapping_flags;	/* 0x08 */
	U16	resv2;				/* 0x0A */
	U32	resv3;				/* 0x0C */
} SSI2_INQUIRY_IOA01,
	*PTR_SSI2_INQUIRY_IOA01;

/*values for negotiated_linkrates fields */

#define SSI2_SAS_NEG_LINK_RATE_MASK_PHYSICAL		(0x0F)
/*link rates used for negotiated physical and logical link rate */
#define SSI2_SAS_NEG_LINK_RATE_UNKNOWN_LINK_RATE	(0x00)
#define SSI2_SAS_NEG_LINK_RATE_PHY_DISABLED		(0x01)
#define SSI2_SAS_NEG_LINK_RATE_NEGOTIATION_FAILED	(0x02)
#define SSI2_SAS_NEG_LINK_RATE_SATA_OOB_COMPLETE	(0x03)
#define SSI2_SAS_NEG_LINK_RATE_PORT_SELECTOR		(0x04)
#define SSI2_SAS_NEG_LINK_RATE_SMP_RESET_IN_PROGRESS	(0x05)
#define SSI2_SAS_NEG_LINK_RATE_1_5			(0x08)
#define SSI2_SAS_NEG_LINK_RATE_3_0			(0x09)
#define SSI2_SAS_NEG_LINK_RATE_6_0			(0x0A)
#define SSI2_SAS_NEG_LINK_RATE_12_0			(0x0B)


/* programmed_linkrate */

#define SSI2_SAS_PRATE_MIN_RATE_MASK			(0x0F)



/* hw_linkrate fields */

#define SSI2_SAS_HWRATE_MIN_RATE_MASK			(0x0F)



/****************************************************************************
 *  SAS_UNIT Config Pages
 ****************************************************************************/

/*SAS_UNIT0 */



typedef struct _SSI2_SAS_UNIT0_PHY_DATA {
	U8 port;				 /* 0x00 */
	U8 port_flags;				 /* 0x01 */
	U8 phy_flags;				 /* 0x02 */
	U8 negotiated_linkrate;			/* 0x03 */
	U16 attached_dev_handle;		/* 0x04 */
	U16 controller_dev_handle;		/* 0x06 */
	U32 discovery_status;			/* 0x08 */
} SSI2_SAS_UNIT0_PHY_DATA, *PTR_SSI2_SAS_UNIT0_PHY_DATA;

typedef struct _SSI2_INQUIRY_SAS_UNIT0 {
	U8 num_phys;				/* 0x00 */
	U8 resv0;				/* 0x01 */
	U16 resv1[3];				/* 0x02 */
	SSI2_SAS_UNIT0_PHY_DATA PhyData[]; /* 0x08 */
} SSI2_INQUIRY_SAS_UNIT0, *PTR_SSI2_INQUIRY_SAS_UNIT0;

/*port_flags */
#define SSI2_SAS_UNIT_PORTFLAGS_DISCOVERY_IN_PROGRESS		(0x08)
#define SSI2_SAS_UNIT_PORTFLAGS_AUTO_PORT_CONFIG		(0x01)

/*phy_flags */
#define SSI2_SAS_UNIT_PHYFLAGS_ZONING_ENABLED			(0x10)
#define SSI2_SAS_UNIT_PHYFLAGS_PHY_DISABLED			(0x08)


/*SAS IO Unit Page 1 */

typedef struct _SSI2_SAS_UNIT1_PHY_DATA {
	U8 port;		/* 0x00 */
	U8 port_flag;		/* 0x01 */
	U8 phy_flag;		/* 0x02 */
	U8 linkrate;		/* 0x03 */
	U32 resv;		/* 0x04 */
} SSI2_SAS_UNIT1_PHY_DATA,
	*PTR_SSI2_SAS_UNIT1_PHY_DATA;

typedef struct _SSI2_INQUIRY_SAS_UNIT1 {
	U8 num_phys;				/* 0x00 */
	U8 report_dev_missing_delay;		/* 0x01 */
	U8 io_dev_missing_delay;		/* 0x02 */
	u8  sata_max_q_depth;			/* 0x03 */
	u16 control_flags;			/* 0x04 */
	u16 additional_control_flags;		/* 0x06 */
	u32 resv0;				/* 0x08 */
	SSI2_SAS_UNIT1_PHY_DATA PhyData[];	/* 0x0C */
} SSI2_INQUIRY_SAS_UNIT1,
	*PTR_SSI2_INQUIRY_SAS_UNIT1;
/*report_device_missing_delay */
#define SSI2_SASIOUNIT1_REPORT_MISSING_TIMEOUT_MASK			(0x7F)
#define SSI2_SASIOUNIT1_REPORT_MISSING_UNIT_16				(0x80)



/*phy_flags */

#define SSI2_SASIOUNIT1_PHYFLAGS_PHY_DISABLE				(0x08)


/*EXPANDER */

typedef struct _SSI2_INQUIRY_EXPANDER {
	U8	num_phys;				/* 0x00 */
	U8	physical_port;				/* 0x01 */
	U16	enclosure_handle;			/* 0x02 */
	U64	sas_address;				/* 0x04 */
	U32	discovery_status;			/* 0x0c */
	U16	dev_handle;				/* 0x10 */
	U16	parent_dev_handle;			/* 0x12 */
	U16	flag;					/* 0x14 */
	u16	resv0;					/* 0x16 */
	u16	expander_change_count;			/* 0x18 */
	u16	expander_route_indexes;			/* 0x1A */
	u8	sas_level;				/* 0x1B */
	u8	resv1;					/* 0x1C */
	u16	stp_bus_inactivity_time_limit;		/* 0x1E */
	u16	stp_max_connect_time_limit;		/* 0x20 */
	u16	stp_smp_nexus_loss_time;		/* 0x22 */
	u16	max_num_routed_sas_address;		/* 0x24 */
	u16	zone_lock_inactivity_limit;		/* 0x26 */
	u64	activity_zone_manager_sas_addr;		/* 0x28 */
	u8	time_toreduces_func;			/* 0x30 */
	u8	initial_time_toreduced_func;		/* 0x31 */
	u8	max_reduces_function;			/* 0x32 */
	u8	resv3;					/* 0x33 */
	U16	resv4[3];				/* 0x34 */
} SSI2_INQUIRY_EXPANDER, *PTR_SSI2_INQUIRY_EXPANDER;

/*EXPANDER_PHY */
typedef struct _SSI2_INQUIRY_EXPANDER_PHY {
	U8 physical_port;				/* 0x00 */
	U8 num_phys;					/* 0x01 */
	U8 phy;						/* 0x02 */
	U8 programmed_linkrate;				/* 0x03 */
	U8 hw_linkrate;					/* 0x04 */
	U8 negotiated_linkrate;				/* 0x05 */
	U16 exp_dev_handle;				/* 0x06 */
	U32 phy_info;					/* 0x08 */
	U32 attached_dev_info;				/* 0x0C */
	U16 attached_dev_handle;			/* 0x10 */
	U16 resv0;					/* 0x12 */
	u16 num_table_entries_programmed;		/* 0x14 */
	u8  change_count;				/* 0x16 */
	u8  resv1;					/* 0x17 */
	u8  phy_identifier;				/* 0x18 */
	u8  attached_phy_identifier;			/* 0x19 */
	u8  discovery_info;				/* 0x1A */
	u8  resv2;					/* 0x1B */
	u32 attached_phy_info;				/* 0x1C */
	u8  zonegroup;					/* 0x20 */
	u8  self_config_status;				/* 0x21 */
	u16 resv3;					/* 0x22 */
} SSI2_INQUIRY_EXPANDER_PHY,
	*PTR_SSI2_INQUIRY_EXPANDER_PHY;

/*SAS_DEV */
typedef struct _SSI2_INQUIRY_SAS_DEV {
	U16 slot;					/* 0x00 */
	U16 enclosure_handle;				/* 0x02 */
	U64 sas_address;				/* 0x04 */
	U16 parent_dev_handle;				/* 0x0C */
	U8 phy_num;					/* 0x0E */
	U8 access_status;					/* 0x0F */
	U16 dev_handle;					/* 0x10 */
	U16 flags;					/* 0x12 */
	U32 dev_info;					/* 0x14 */
	U64 dev_name;					/* 0x18 */
	U8 physical_port;				/* 0x20 */
	U8 enclosure_level;				/* 0x21 */
	U16 resv;					/* 0x22 */
	u8  attached_phy_identifier;			/* 0x24 */
	u8	zone_group;				/* 0x25 */
	u8	max_port_connections;			/* 0x26 */
	u8	port_groups;				/* 0x27 */
	u8	dma_group;				/* 0x28 */
	u8	control_group;				/* 0x29 */
	u16 resv2;					/* 0x2A */
	U32 connector_name[4];		/* 0x2C */
} SSI2_INQUIRY_SAS_DEV, *PTR_SSI2_INQUIRY_SAS_DEV;

/*values for SAS Device Page 0 AccessStatus field */
#define SSI2_SAS_DEVICE0_ASTATUS_NO_ERRORS			(0x00)
#define SSI2_SAS_DEVICE0_ASTATUS_SATA_INIT_FAILED		(0x01)
#define SSI2_SAS_DEVICE0_ASTATUS_SATA_CAPABILITY_FAILED		(0x02)
#define SSI2_SAS_DEVICE0_ASTATUS_SATA_AFFILIATION_CONFLICT	(0x03)
#define SSI2_SAS_DEVICE0_ASTATUS_SATA_NEEDS_INITIALIZATION	(0x04)
#define SSI2_SAS_DEVICE0_ASTATUS_ROUTE_NOT_ADDRESSABLE		(0x05)
#define SSI2_SAS_DEVICE0_ASTATUS_SMP_ERROR_NOT_ADDRESSABLE	(0x06)
#define SSI2_SAS_DEVICE0_ASTATUS_DEVICE_BLOCKED			(0x07)
/*specific values for SATA Init failures */
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_UNKNOWN			(0x10)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_AFFILIATION_CONFLICT	(0x11)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_IDENTIFICATION		(0x13)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_CHECK_POWER		(0x14)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_PIO_SN			(0x15)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_MDMA_SN			(0x16)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_UDMA_SN			(0x17)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_ZONING_VIOLATION		(0x18)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_NOT_ADDRESSABLE		(0x19)
#define SSI2_SAS_DEVICE0_ASTATUS_SIF_MAX			(0x1F)


/* Flags field */

#define SSI2_SAS_DEVICE0_FLAGS_SATA_ASYNCHRONOUS_NOTIFY		(0x0400)
#define SSI2_SAS_DEVICE0_FLAGS_SATA_SW_PRESERVE			(0x0200)
#define SSI2_SAS_DEVICE0_FLAGS_SATA_SMART_SUPPORTED		(0x0040)
#define SSI2_SAS_DEVICE0_FLAGS_SATA_NCQ_SUPPORTED		(0x0020)
#define SSI2_SAS_DEVICE0_FLAGS_SATA_FUA_SUPPORTED		(0x0010)
#define SSI2_SAS_DEVICE0_FLAGS_ENCL_LEVEL_VALID			(0x0002)
#define SSI2_SAS_DEVICE0_FLAGS_DEVICE_PRESENT			(0x0001)

/****************************************************************************
 *  SAS PHY Config Pages
 ****************************************************************************/


typedef struct _SSI2_INQUIRY_PHY {
	U16	attached_dev_handle;		/* 0x00 */
	U8	negotiated_linkrate;		/* 0x02 */
	U8	programmed_linkrate;		/* 0x03 */
	U8	hw_linkrate;			/* 0x04 */
	U8	flag;				/* 0x05 */
	U16	resv0;				/* 0x06 */
	u32	phy_info;			/* 0x08 */
	u32	attached_phy_info;		/* 0x0C */
	u16	owner_dev_handle;		/* 0x10 */
	u8	attached_phy_identifier;	/* 0x12 */
	u8	change_count;			/* 0x13 */
	U32	resv1[2];			/* 0x14 */
} SSI2_INQUIRY_PHY,
	*PTR_SSI2_INQUIRY_PHY;

typedef struct _SSSI2_INQUIRY_PHY_COUNTER {
	U32	invalid_count;			/* 0x00 */
	U32	running_disparity_error_count;	/* 0x04 */
	U32	loss_sync_count;		/* 0x08 */
	U32	phy_reset_problem_count;	/* 0x0C */
} SSI2_INQUIRY_PHY_COUNTER,
	*PTR_SSI2_INQUIRY_PHY_COUNTER;

/****************************************************************************
 *  Enclosure pg0
 ****************************************************************************/

/*Enclosure Page 0 */
typedef struct _SSI2_INQUIRY_ENCLOSURE {
	U64	enclosure_logical_id;		/* 0x00 */
	U16	flags;				/* 0x08 */
	U16	enclosure_handle;		/* 0x0A */
	U16	num_slots;			/* 0x0C */
	U16	start_slot;			/* 0x0E */
	U8	chassis_slot;			/* 0x10 */
	U8	enclosure_level;		/* 0x11 */
	U16	sep_dev_handle;			/* 0x12 */
	U32	resv1;				/* 0x14 */

} SSI2_INQUIRY_ENCLOSURE, *PTR_SSI2_INQUIRY_ENCLOSURE;

/*values for SAS Enclosure Page 0 Flags field */
#define SSI2_SAS_ENCLOSURE_FLAGS_CHASSIS_SLOT_VALID	(0x0020)

/*raid pages*/
typedef struct _SSI2_RAID_VOL_PHYS_DISK {
	U16	phys_dev_handle;
	U8	phys_logic_id;
	U8	reserved2;
} SSI2_RAID_VOL_PHYS_DISK, *PTR_SSI2_RAID_VOL_PHYS_DISK;
/*vol_pg0*/
typedef struct _SSI2_INQUIRY_RAID_VOL {
	U16	dev_handle;
	U16	num_phys_disks;
	U32	volume_status_flags;
	U64	array_size;		// vd total capacity
	U64	max_expand_size;	// vd max size can expand
	U64	device_size;		// capacity of every vd
	U32	stripe_size;
	U8	volume_state;
	U8	volume_type;
	U8	resync_rate;
	U8	expander_status;
	U64	resv;
	SSI2_RAID_VOL_PHYS_DISK phys_disk[];
} SSI2_INQUIRY_RAID_VOL, *PTR_SSI2_INQUIRY_RAID_VOL;
/*values for RAID volume_state */
#define SSI2_RAID_VOL_STATE_MISSING				(0x03)
#define SSI2_RAID_VOL_STATE_FAILED				(0x04)
#define SSI2_RAID_VOL_STATE_DELETED				(0x02)
#define SSI2_RAID_VOL_STATE_PART_OPTIMAL			(0x05)
#define SSI2_RAID_VOL_STATE_DEGRADED				(0x01)
#define SSI2_RAID_VOL_STATE_OPTIMAL				(0x00)
#define SSI2_RAID_VOL_STATE_MASK				(0x07)
#define SSI2_RAID_VOL_STATE_MORPHING				(0x08)
#define SSI2_RAID_VOL_STATE_DELAY				(0x09)
#define SSI2_RAID_VOL_STATE_INCONSISTENT			(0x10)

/*values for RAID VolumeType */
#define SSI2_RAID_VOL_TYPE_RAID0				(0x00)
#define SSI2_RAID_VOL_TYPE_RAID1				(0x01)
#define SSI2_RAID_VOL_TYPE_RAID10				(0x10)
#define SSI2_RAID_VOL_TYPE_RAID5				(0x05)
#define SSI2_RAID_VOL_TYPE_RAID6				(0x06)
#define SSI2_RAID_VOL_TYPE_JBOD					(0x0F)
#define SSI2_RAID_VOL_TYPE_UNKNOWN				(0xFF)

#define SSI2_RAIDVOL0_STATUS_FLAG_RESYNC_IN_PROGRESS		(0x00010000)

/* virtual_entry.state is a bigendian bitmap */
#define SSI2_DDF_state_optimal					0x0
#define SSI2_DDF_state_degraded					0x1
#define SSI2_DDF_state_deleted					0x2
#define SSI2_DDF_state_missing					0x3
#define SSI2_DDF_state_failed					0x4
#define SSI2_DDF_state_part_optimal				0x5
#define SSI2_DDF_state_mask					0x7
#define SSI2_DDF_state_morphing					0x8
#define SSI2_DDF_state_inconsistent 0x10

/* virtual_entry.init_state is a bigendian bitmap */
#define SSI2_DDF_init_not		0x00
#define SSI2_DDF_init_quick		0x01 /* initialisation is progress.*/
#define SSI2_DDF_init_full		0x02
#define SSI2_DDF_initstate_mask		0x03
#define SSI2_DDF_access_mask		0xc0
#define SSI2_DDF_access_rw		0x00
#define SSI2_DDF_access_ro		0x80
#define SSI2_DDF_access_blocked		0xc0

/*values for RAID volume_type */
#define SSI2_DDF_RAID0			0x00
#define SSI2_DDF_RAID1			0x01
#define SSI2_DDF_RAID3			0x03
#define SSI2_DDF_RAID4			0x04
#define SSI2_DDF_RAID5			0x05
#define SSI2_DDF_RAID10			0x10
#define SSI2_DDF_RAID1E			0x11
#define SSI2_DDF_JBOD			0x0f
#define SSI2_DDF_CONCAT			0x1f
#define SSI2_DDF_RAID5E			0x15
#define SSI2_DDF_RAID5EE		0x25
#define SSI2_DDF_RAID6			0x06


typedef struct _SSI2_INQUIRY_RAID_INFO {
	U16	dev_handle;
	U16	io_qdepth;
	U8	GUID[24];
	U8	name[16];
	U64	WWID;
	U32	device_info;
} SSI2_INQUIRY_RAID_INFO, *PTR_SSI2_INQUIRY_RAID_INFO;

/*pd pg0*/
typedef struct _SSI2_INQUIRY_RAID_PD {
	U16	dev_handle;
	U16	resv0;
	U16	phys_logic_id;
	U8	phys_disk_state;
	U8	offline_reason;
} SSI2_INQUIRY_RAID_PD;
/* phys_disk_entry.state is a bigendian bitmap */
#define SSI2_DDF_ONLINE			1
#define SSI2_DDF_FAILED			2 /* overrides ?1,4,8 */
#define SSI2_DDF_REBUILDING		4
#define SSI2_DDF_TRANSATION		8
#define SSI2_DDF_SMART			16
#define SSI2_DDF_READ_ERRORS		32
#define SSI2_DDF_MISSING		64
/*off_line_reason defines */
#define SSI2_PHYSDISK0_ONLINE					(0x00)
#define SSI2_PHYSDISK0_OFFLINE_MISSING				(0x01)
#define SSI2_PHYSDISK0_OFFLINE_FAILED				(0x03)
#define SSI2_PHYSDISK0_OFFLINE_INITIALIZING			(0x04)
#define SSI2_PHYSDISK0_OFFLINE_REQUESTED			(0x05)
#define SSI2_PHYSDISK0_OFFLINE_FAILED_REQUESTED			(0x06)
#define SSI2_PHYSDISK0_OFFLINE_OTHER				(0xFF)


typedef struct _SSI2_CONFIG_ELEMENT {
	U16	element_flags;
	U16	vol_dev_handle;
	U8	hot_spare_pool;
	U8	phys_logic_id;
	U16	phys_disk_dev_handle;
} SSI2_CONFIG_ELEMENT;
/******extend page 0x16**********/
typedef struct _SSI2_INQUIRY_RAID_CONFIG {
	U8	num_phys_disks;
	U8	num_elements;
	U8	num_volumes;
	U8	config_num;
	U32	flags;
	U8	config_GUID[24];
	SSI2_CONFIG_ELEMENT	config_element[0x10];
} SSI2_INQUIRY_RAID_CONFIG, *PTR_SSI2_INQUIRY_RAID_CONFIG;
/*values for the element_flags field */
#define SSI2_RAID_CONFIG_EFLAGS_MASK_ELEMENT_TYPE		(0x000F)
#define SSI2_RAID_CONFIG_EFLAGS_VOLUME_ELEMENT			(0x0000)
#define SSI2_RAID_CONFIG_EFLAGS_VOL_PHYS_DISK_ELEMENT		(0x0001)
#define SSI2_RAID_CONFIG_EFLAGS_HOT_SPARE_ELEMENT		(0x0002)
#define SSI2_RAID_CONFIG_EFLAGS_OCE_ELEMENT			(0x0003)


/* flags field */
#define SSI2_RAID_CONFIG_FLAG_FOREIGN_CONFIG			(0x00000001)



#endif
