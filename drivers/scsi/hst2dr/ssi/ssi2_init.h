/* SPDX-License-Identifier: GPL-2.0 */
/*
 *
 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
 *
 * Name:  ssi2_init.h
 * Creation Date:  March 1st, 2022
 * Version History
 * ---------------
 *
 * Date      Version   Description
 * --------  --------  ------------------------------------------------------
 * 03-01-22  02.00.00  Corresponds to -hst2dr SSI Specification Rev A.
 * --------------------------------------------------------------------------
 */


#ifndef SSI2_INIT_H
#define SSI2_INIT_H

/*****************************************************************************
 *
 *              SCSI Initiator Messages
 *
 *****************************************************************************/

/****************************************************************************
 * SCSI IO messages and associated structures
 ****************************************************************************/




typedef struct _SSI2_SCSI_CDB_EEDP {
	U8 cdb[20];				/* 0x00 */
	U32 primary_ref;			/* 0x14 */
	U16 primary_app;			/* 0x18 */
	U16 primary_app_mask;			/* 0x1A */
	U32 transfer_len;			/* 0x1C */
} SSI2_SCSI_CDB_EEDP;

typedef union _SSI2_SCSI_CDB_UNION {
	U8 cdb[32];
	SSI2_SCSI_CDB_EEDP eedp;
} SSI2_SCSI_CDB_UNION;

#define SSI2_SCSI_REQUEST hst2dr_vendor_cmd

/*SCSI IO MsgFlags bits */

/*MsgFlags for SenseBufferAddressSpace */
#define SSI2_SCSIIO_MSGFLAGS_SYSTEM_SENSE_ADDR		(0x00)


/*SCSI IO EEDPFlags bits */

#define SSI2_SCSIIO_EEDPFLAGS_INC_PRI_REFTAG		(0x8000)

#define SSI2_SCSIIO_EEDPFLAGS_CHECK_REFTAG		(0x0400)
#define SSI2_SCSIIO_EEDPFLAGS_CHECK_GUARD		(0x0100)
#define SSI2_SCSIIO_EEDPFLAGS_APPTAG_DISABLE_MODE	(0x0080)
#define SSI2_SCSIIO_EEDPFLAGS_CHECK_REMOVE_OP		(0x0003)
#define SSI2_SCSIIO_EEDPFLAGS_INSERT_OP			(0x0004)

/*SCSI IO LUN fields: use SSI2_LUN_ from ssi2.h */

/*SCSI IO Control bits */
#define SSI2_SCSIIO_CONTROL_ADDCDBLEN_SHIFT		(26)

#define SSI2_SCSIIO_CONTROL_NODATATRANSFER		(0x00000000)
#define SSI2_SCSIIO_CONTROL_WRITE			(0x01000000)
#define SSI2_SCSIIO_CONTROL_READ			(0x02000000)
/*alternate name for the previous field; called Command Priority in SAM-4 */
#define SSI2_SCSIIO_CONTROL_SIMPLEQ			(0x00000000)
#define SSI2_SCSIIO_CONTROL_ORDEREDQ			(0x00000200)
#define SSI2_SCSIIO_CONTROL_HIGH_PRIORITY		(0x00000400)


/*SCSI IO Error Reply Message */
typedef struct _SSI2_SCSI_IO_REPLY {
	U8 msg_len;			/* 0x00 */
	U8 resv0;			/* 0x01 */
	U8 msg_flags;			/* 0x02 */
	U8 opcode;			/* 0x03 */
	U16 dev_handle;			/* 0x04 */
	U16 sense_id;			/* 0x06 */
	U8 scsi_status;			/* 0x08 */
	U8 scsi_state;			/* 0x09 */
	U16 status;			/* 0x0A */
	U32 log_info;			/* 0x0C */
	U32 resv2;			/* 0x10 */

	U32 transfer_count;		/* 0x14 */
	U32 sense_count;		/* 0x18 */
	U32 response_info;		/* 0x1C */
	U16 task_tag;			/* 0x20 */
	U16 resv3;			/* 0x22 */
	U32 resv4[3];			/* 0x24 */

} SSI2_SCSI_IO_REPLY;

/*SCSI IO Reply SCSIStatus values (SAM-4 status codes) */

#define SSI2_SCSI_STATUS_GOOD			(0x00)
#define SSI2_SCSI_STATUS_CHECK_CONDITION	(0x02)
#define SSI2_SCSI_STATUS_CONDITION_MET		(0x04)
#define SSI2_SCSI_STATUS_BUSY			(0x08)
#define SSI2_SCSI_STATUS_INTERMEDIATE		(0x10)	/*obsolete */
#define SSI2_SCSI_STATUS_INTERMEDIATE_CONDMET	(0x14)	/*obsolete */
#define SSI2_SCSI_STATUS_RESERVATION_CONFLICT	(0x18)
#define SSI2_SCSI_STATUS_COMMAND_TERMINATED	(0x22)	/*obsolete */
#define SSI2_SCSI_STATUS_TASK_SET_FULL		(0x28)
#define SSI2_SCSI_STATUS_ACA_ACTIVE		(0x30)
#define SSI2_SCSI_STATUS_TASK_ABORTED		(0x40)

/*SCSI IO Reply SCSIState flags */

#define SSI2_SCSI_STATE_RESPONSE_INFO_VALID	(0x10)
#define SSI2_SCSI_STATE_TERMINATED		(0x08)
#define SSI2_SCSI_STATE_NO_SCSI_STATUS		(0x04)
#define SSI2_SCSI_STATE_AUTOSENSE_FAILED	(0x02)
#define SSI2_SCSI_STATE_AUTOSENSE_VALID		(0x01)
#pragma pack(1)
typedef struct _hst2dr_nvme_completion {
	/*
	 * Used by commands to return data:
	 */
	__le16 reply_id;
	__le16 resv0;
	__le16 resv1[2];
	__le16	sq_head;	/* how much of this queue may be reclaimed */
	__le16	sq_id;		/* submission queue that generated this entry */
	__le16	host_tag_id;
	struct {
		__le16 phase:1;
		__le16 status:10;
		__le16 description:5;
	} ctrl;
} hst2dr_nvme_completion;
typedef struct _hst2dr_nvme_reply_sense_q_ctrl {
	union{
		struct {
			unsigned reply_id:15;
			unsigned reply_push:1;
			unsigned sense_id:15;
			unsigned sense_push:1;
		} reg;
		U32 dw;
	} ctrl;
} hst2dr_nvme_reply_sense_q_ctrl;


#pragma pack()
/****************************************************************************
 * SCSI Task Management messages
 ****************************************************************************/

/*SCSI Task Management Request Message */
typedef struct _SSI2_SCSI_TM_REQUEST {
	u8 opcode;			/* 0x00 */
	u8 opflags;			/* 0x01 */
	u16 host_tag_id;		/* 0x02 */
	u8 host_flag;			/* 0x04 */
	u8 request_flags;		/* 0x05 */
	u16 reserved0;			/* 0x06 */

	U8 task_type;			/* 0x08 */
	U8 msg_flags;			/* 0x09 */
	U8 resv1[2];			/* 0x0A */
	U16 dev_handle;			/* 0x0C */
	U16 io_qid;			/* 0x0E */
	U8 lun[8];			/* 0x10 */
	U32 resv3;			/* 0x18 */
	U16 task_manage_id;		/* 0x1C */
	U16 resv4;			/* 0x1E */
} SSI2_SCSI_TM_REQUEST;

/*TaskType values */

#define SSI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK		(0x01)
#define SSI2_SCSITASKMGMT_TASKTYPE_ABRT_TASK_SET	(0x02)
#define SSI2_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET	(0x08)
#define SSI2_SCSITASKMGMT_TASKTYPE_I_T_NEXUS_RESET	(0x10)
#define SSI2_SCSITASKMGMT_TASKTYPE_QUERY_TASK		(0x80)


/*SCSI Task Management Reply Message */
typedef struct _SSI2_SCSI_TM_REPLY {
	U8 msg_len;			/* 0x00 */
	U8 task_type;			/* 0x01 */
	U8 resv0;			/* 0x02 */
	U8 opcode;			/* 0x03 */
	U16 dev_handle;			/* 0x04 */
	U16 resv1;			/* 0x06 */
	U8 response_code;		/* 0x08 */
	U8 msg_flags;			/* 0x09 */
	U16 status;			/* 0x0A */	//For FW must be reserved
	U32 log_info;			/* 0x0C */
	U32 termination_count;		/* 0x10 */
	U32 resv3[2];			/* 0x14 */
} SSI2_SCSI_TM_REPLY;

/*ResponseCode values */

#define SSI2_SCSITASKMGMT_RSP_TM_COMPLETE		(0x00)
#define SSI2_SCSITASKMGMT_RSP_INVALID_FRAME		(0x02)
#define SSI2_SCSITASKMGMT_RSP_TM_NOT_SUPPORTED		(0x04)
#define SSI2_SCSITASKMGMT_RSP_TM_FAILED			(0x05)
#define SSI2_SCSITASKMGMT_RSP_TM_SUCCEEDED		(0x08)
#define SSI2_SCSITASKMGMT_RSP_TM_INVALID_LUN		(0x09)
#define SSI2_SCSITASKMGMT_RSP_TM_OVERLAPPED_TAG		(0x0A)
#define SSI2_SCSITASKMGMT_RSP_IO_QUEUED_ON_IOA		(0x80)

#endif
