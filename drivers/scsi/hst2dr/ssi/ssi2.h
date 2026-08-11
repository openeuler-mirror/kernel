/* SPDX-License-Identifier: GPL-2.0 */
/*
 *
 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
 *
 * Name:  ssi2.h
 * Title:  SSI Message independent structures and definitions including
 *         System Interface Register Set and scatter/gather formats.
 * Creation Date:  Mar 1, 2022
 *
 * ssi2.h Version:  02.00.00
 *
 * NOTE: Names (typedefs, defines, etc.) beginning with an SSI2 prefix are
 *       for use only on SSI v2.0 products, and must not be used with SSI
 *       v2.0 products. Unless otherwise noted, names beginning with SSI2
 *       are for use with SSI v2.0 products.
 *
 * Version History
 * ---------------
 *
 * Date      Version   Description
 * --------  --------  ------------------------------------------------------
 * 03-01-22  02.00.00  Corresponds to -hst2dr SSI Specification Rev A.
 * --------------------------------------------------------------------------
 */

#ifndef SSI2_H
#define SSI2_H

/*****************************************************************************
 *
 *       SSI Version Definitions
 *
 *****************************************************************************/

#define SSI2_MAJOR_VERSION	(HST2DR_MAJOR_VERSION)
#define SSI2_MINOR_VERSION	(HST2DR_MINOR_VERSION)
#define	SSI2_VERSION		((SSI2_MAJOR_VERSION << 8) | SSI2_MINOR_VERSION)


/*****************************************************************************
 *
 *       IOA State Definitions
 *
 *****************************************************************************/

#define SSI2_IOA_STATE_RESET		(0x00000000)
#define SSI2_IOA_STATE_READY		(0x10000000)
#define SSI2_IOA_STATE_OPERATIONAL	(0x20000000)
#define SSI2_IOA_STATE_FAULT		(0x40000000)
#define SSI2_IOA_STATE_NEED_RESET	(0x80000000)
#define SSI2_IOA_STATE_MASK		(0xF0000000)


/*****************************************************************************
 *
 *       System Interface Register Definitions
 *
 *****************************************************************************/
typedef struct _SSI2_NVME_REGS {
	U32 RegsBase;		/* 0x00 */
} SSI2_NVME_REGS;

/*
 *Defines for working with the IOA register.
 */

/*IOA --> System values */
#define SSI2_IOA_USED				(0x08000000)
#define SSI2_IOA_DATA_MASK			(0x0000FFFF)


/*
 *Defines for the Reply Descriptor Post Queue
 */

#define SSI2_SUP_REPLY_POST_HOST_INDEX_OFFSET  (0x0000030C) /*SSI v2.5 only*/


/*****************************************************************************
 *
 *       Message Descriptors
 *
 *****************************************************************************/

/*defines for the RequestFlags field */

#define SSI2_REQ_DESCRIPT_FLAGS_SCSI_IO			(0x00)
#define SSI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY		(0x06)

/*for the RequestFlags field, use the same
 *defines as SSI2_DEFAULT_REQUEST_DESCRIPTOR
 */

/*defines for the ReplyFlags field */
#define SSI2_RPY_DESCRIPT_FLAGS_SCSI_IO_SUCCESS		(0x00)
#define SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY		(0x01)

#define SSI2_RPY_DESCRIPT_FLAGS_UNUSED			(0x0F)

/*union of Reply Descriptors */
typedef union _SSI2_REPLY_DESCRIPTORS_UNION {
	U8 reply_descriptor[16];
	U64 qwords;
} SSI2_REPLY_DESCRIPTORS_UNION;

/*****************************************************************************
 *
 *       Message Functions
 *
 *****************************************************************************/

#define SSI2_FUNCTION_SCSI_IO			(0x00)
#define SSI2_FUNCTION_SCSI_TASK_MANAGE		(0x21)
#define SSI2_FUNCTION_IOA_INFO			(0x22)
#define SSI2_FUNCTION_IOA_INIT			(0x23)
#define SSI2_FUNCTION_CONFIG			(0x24)
#define SSI2_FUNCTION_PORT_ENABLE		(0x25)
#define SSI2_FUNCTION_EVENT			(0x26)
#define SSI2_FUNCTION_EVENT_ACK			(0x27)
#define SSI2_FUNCTION_FW_DOWNLOAD		(0x29)
#define SSI2_FUNCTION_FW_UPLOAD			(0x2A)
#define SSI2_FUNCTION_SMP_PASSTHROUGH		(0x41)
#define SSI2_FUNCTION_SAS_UNIT			(0x42)
#define SSI2_FUNCTION_POWER_MANAGE		(0x44)
#define SSI2_FUNCTION_IOA_MESSAGE_UNIT_RESET	(0x50)
#define SSI2_FUNCTION_RAID_ACTION		(0x35)
#define SSI2_FUNCTION_SHUTDOWN			(0x35)

#define SSI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH	(0x36)


/*****************************************************************************
 *
 *       IOA Status Values
 *
 *****************************************************************************/

/*mask for IOAStatus status value */
#define SSI2_IOASTATUS_MASK			(0x03FF)

/****************************************************************************
 * Common IOAStatus values for all replies
 ****************************************************************************/

#define SSI2_IOASTATUS_SUCCESS			(0x0000)
#define SSI2_IOASTATUS_INVALID_FUNCTION		(0x0001)
#define SSI2_IOASTATUS_BUSY			(0x0002)
#define SSI2_IOASTATUS_INVALID_SGL		(0x0003)
#define SSI2_IOASTATUS_INTERNAL_ERROR		(0x0004)
#define SSI2_IOASTATUS_INSUFFICIENT_RESOURCES	(0x0006)
#define SSI2_IOASTATUS_INVALID_FIELD		(0x0007)
#define SSI2_IOASTATUS_INVALID_STATE		(0x0008)
#define SSI2_IOASTATUS_OP_STATE_NOT_SUPPORTED	(0x0009)
#define SSI2_IOASTATUS_INSUFFICIENT_POWER	(0x000A)

/****************************************************************************
 * Config IOAStatus values
 ****************************************************************************/

#define SSI2_IOASTATUS_CONFIG_INVALID_ACTION	(0x0020)
#define SSI2_IOASTATUS_CONFIG_INVALID_TYPE	(0x0021)
#define SSI2_IOASTATUS_CONFIG_INVALID_PAGE	(0x0022)
#define SSI2_IOASTATUS_CONFIG_INVALID_DATA	(0x0023)
#define SSI2_IOASTATUS_CONFIG_NO_DEFAULTS	(0x0024)
#define SSI2_IOASTATUS_CONFIG_CANT_COMMIT	(0x0025)

/****************************************************************************
 * SCSI IO Reply
 ****************************************************************************/

#define SSI2_IOASTATUS_SCSI_RECOVERED_ERROR	(0x0040)
#define SSI2_IOASTATUS_SCSI_INVALID_DEVHANDLE	(0x0042)
#define SSI2_IOASTATUS_SCSI_DEVICE_NOT_THERE	(0x0043)
#define SSI2_IOASTATUS_SCSI_DATA_OVERRUN	(0x0044)
#define SSI2_IOASTATUS_SCSI_DATA_UNDERRUN	(0x0045)
#define SSI2_IOASTATUS_SCSI_IO_DATA_ERROR	(0x0046)
#define SSI2_IOASTATUS_SCSI_PROTOCOL_ERROR	(0x0047)
#define SSI2_IOASTATUS_SCSI_TASK_TERMINATED	(0x0048)
#define SSI2_IOASTATUS_SCSI_RESIDUAL_MISMATCH	(0x0049)
#define SSI2_IOASTATUS_SCSI_TASK_MGMT_FAILED	(0x004A)
#define SSI2_IOASTATUS_SCSI_IOA_TERMINATED	(0x004B)
#define SSI2_IOASTATUS_SCSI_EXT_TERMINATED	(0x004C)

/****************************************************************************
 * For use by SCSI Initiator and SCSI Target end-to-end data protection
 ****************************************************************************/

#define SSI2_IOASTATUS_EEDP_GUARD_ERROR		(0x004D)
#define SSI2_IOASTATUS_EEDP_REF_TAG_ERROR	(0x004E)
#define SSI2_IOASTATUS_EEDP_APP_TAG_ERROR	(0x004F)

/****************************************************************************
 * SCSI Target values
 ****************************************************************************/

#define SSI2_IOASTATUS_TARGET_INVALID_IO_INDEX		(0x0062)
#define SSI2_IOASTATUS_TARGET_ABORTED			(0x0063)
#define SSI2_IOASTATUS_TARGET_NO_CONN_RETRYABLE		(0x0064)
#define SSI2_IOASTATUS_TARGET_NO_CONNECTION		(0x0065)
#define SSI2_IOASTATUS_TARGET_XFER_COUNT_MISMATCH	(0x006A)
#define SSI2_IOASTATUS_TARGET_DATA_OFFSET_ERROR		(0x006D)
#define SSI2_IOASTATUS_TARGET_TOO_MUCH_WRITE_DATA	(0x006E)
#define SSI2_IOASTATUS_TARGET_IU_TOO_SHORT		(0x006F)
#define SSI2_IOASTATUS_TARGET_ACK_NAK_TIMEOUT		(0x0070)
#define SSI2_IOASTATUS_TARGET_NAK_RECEIVED		(0x0071)

/****************************************************************************
 * Serial Attached SCSI values
 ****************************************************************************/

#define SSI2_IOASTATUS_SAS_SMP_REQUEST_FAILED		(0x0090)
#define SSI2_IOASTATUS_SAS_SMP_DATA_OVERRUN		(0x0091)
/****************************************************************************
 * IOAStatus flag to indicate that log info is available
 ****************************************************************************/

#define SSI2_IOASTATUS_FLAG_LOG_INFO_AVAILABLE		(0x100)

#define SSI2_IOALOGINFO_TYPE_SAS			(0x3)

/*****************************************************************************
 *
 *       Standard Message Structures
 *
 *****************************************************************************/

/****************************************************************************
 *Request Message Header for all request messages
 ****************************************************************************/

typedef struct _SSI2_REQUEST_HEADER {
	u8	opcode;			/* 0x00 */
	u8	opflags;		/* 0x01 */
	u16	host_tag_id;		/* 0x02 */
	u8	host_flag;		/* 0x04 */
	u8	request_flags;		/* 0x05 */
	u16	reserved0;		/* 0x06 */

	U8	resv0[2];		/* 0x08 */
	U8	msg_flags;		/* 0x0A */
	U8	resv1;			/* 0x0B */
	U16	dev_handle;		/* 0x0C */
	U16	resv2;			/* 0x0E */
	U32 resv3;			/* 0x10 */
} SSI2_REQUEST_HEADER;

/****************************************************************************
 * Default Reply
 ****************************************************************************/

typedef struct _SSI2_DEFAULT_REPLY {
	U8	msg_len;		/* 0x00 */
	u8	resv0;			/* 0x01 */
	U8	msg_flags;		/* 0x02 */
	U8	opcode;			/* 0x03 */
	U16	dev_handle;		/* 0x04 */
	U16	resv1;			/* 0x06 */
	U16	resv2;			/* 0x08 */
	U16	status;			/* 0x0A */
	U32	log_info;		/* 0x0C */
} SSI2_DEFAULT_REPLY;

/*common version structure/union used in messages and configuration pages */

typedef struct _SSI2_VERSION_STRUCT {
	U8	release;		/* 0x00 */
	U8	build;			/* 0x01 */
	U8	minor;			/* 0x02 */
	U8	major;			/* 0x03 */
} SSI2_VERSION_STRUCT;

typedef union _SSI2_VERSION_UNION {
	SSI2_VERSION_STRUCT version;
	U32 dword;
} SSI2_VERSION_UNION;

typedef struct _SSI2_SGE {
	U64	address;
	U32	len;
	U16	resv;
	U8	resv1;
	U8	flag;
} SSI2_SGE;

/*****************************************************************************
 *
 *       -hst2dr SSI Scatter Gather Elements
 *
 *****************************************************************************/

/****************************************************************************
 * SSI Simple Element structures
 ****************************************************************************/

typedef struct _SSI2_SGE_SIMPLE32 {
	U32 FlagsLength;
	U32 Address;
} SSI2_SGE_SIMPLE32, *PTR_SSI2_SGE_SIMPLE32,
	SSI2SGESimple32_t, *pSSI2SGESimple32_t;

typedef struct _SSI2_SGE_SIMPLE64 {
	U32 FlagsLength;
	U64 Address;
} SSI2_SGE_SIMPLE64, *PTR_SSI2_SGE_SIMPLE64,
	SSI2SGESimple64_t, *pSSI2SGESimple64_t;

typedef struct _SSI2_SGE_SIMPLE_UNION {
	U32 FlagsLength;
	union {
		U32 Address32;
		U64 Address64;
	} u;
} SSI2_SGE_SIMPLE_UNION,
	*PTR_SSI2_SGE_SIMPLE_UNION,
	SSI2SGESimpleUnion_t,
	*pSSI2SGESimpleUnion_t;


/****************************************************************************
 * SSI SGE field definitions and masks
 ****************************************************************************/

/*Flags field bit definitions */

#define SSI2_SGE_FLAGS_LAST_ELEMENT		(0x80)
#define SSI2_SGE_FLAGS_END_OF_BUFFER		(0x40)
#define SSI2_SGE_FLAGS_END_OF_LIST		(0x01)

#define SSI2_SGE_FLAGS_SHIFT			(24)

#define SSI2_SGE_LENGTH_MASK			(0x00FFFFFF)

/*Element Type */

#define SSI2_SGE_FLAGS_SIMPLE_ELEMENT		(0x10)

/*Address location */

#define SSI2_SGE_FLAGS_SYSTEM_ADDRESS		(0x00)

/*Direction */

#define SSI2_SGE_FLAGS_HOST_TO_IOA		(0x04)


/*Address Size */

#define SSI2_SGE_FLAGS_32_BIT_ADDRESSING	(0x00)
#define SSI2_SGE_FLAGS_64_BIT_ADDRESSING	(0x02)

/*****************************************************************************
 *
 *       -hst2dr IEEE Scatter Gather Elements
 *
 *****************************************************************************/

/****************************************************************************
 * IEEE Simple Element structures
 ****************************************************************************/

/*SSI2_IEEE_SGE_SIMPLE32 is for SSI v2.0 products only */
typedef struct _SSI2_IEEE_SGE_SIMPLE32 {
	U32 Address;
	U32 FlagsLength;
} SSI2_IEEE_SGE_SIMPLE32, *PTR_SSI2_IEEE_SGE_SIMPLE32,
	SSI2IeeeSgeSimple32_t, *pSSI2IeeeSgeSimple32_t;

typedef struct _SSI2_IEEE_SGE_SIMPLE64 {
	U64 Address;
	U32 Length;
	U16 Reserved1;
	U8 Reserved2;
	U8 Flags;
} SSI2_IEEE_SGE_SIMPLE64, *PTR_SSI2_IEEE_SGE_SIMPLE64,
	SSI2IeeeSgeSimple64_t, *pSSI2IeeeSgeSimple64_t;

typedef union _SSI2_IEEE_SGE_SIMPLE_UNION {
	SSI2_IEEE_SGE_SIMPLE32 Simple32;
	SSI2_IEEE_SGE_SIMPLE64 Simple64;
} SSI2_IEEE_SGE_SIMPLE_UNION,
	*PTR_SSI2_IEEE_SGE_SIMPLE_UNION,
	SSI2IeeeSgeSimpleUnion_t,
	*pSSI2IeeeSgeSimpleUnion_t;

/****************************************************************************
 * IEEE Chain Element structures
 ****************************************************************************/


/*SSI2_IEEE_SGE_CHAIN64 is for SSI v2.0 and later */
typedef struct _SSI2_IEEE_SGE_CHAIN64 {
	U64 Address;
	U32 Length;
	U16 Reserved1;
	U8 Reserved2;
	U8 Flags;
} SSI2_IEEE_SGE_CHAIN64,
	*PTR_SSI2_IEEE_SGE_CHAIN64,
	SSI2IeeeSgeChain64_t,
	*pSSI2IeeeSgeChain64_t;

/****************************************************************************
 * All IEEE SGE types union
 ****************************************************************************/

/****************************************************************************
 * IEEE SGE union for IO SGL's
 ****************************************************************************/

/****************************************************************************
 * IEEE SGE field definitions and masks
 ****************************************************************************/

/*Flags field bit definitions */

#define SSI2_IEEE_SGE_FLAGS_END_OF_LIST		(0x40)

/*Element Type */

#define SSI2_IEEE_SGE_FLAGS_CHAIN_ELEMENT	(0x80)


/*Data Location Address Space */

#define SSI2_IEEE_SGE_FLAGS_SYSTEM_ADDR		(0x00)

/*****************************************************************************
 *
 *       -hst2dr SSI/IEEE Scatter Gather Unions
 *
 *****************************************************************************/

typedef union _SSI2_SIMPLE_SGE_UNION {
	SSI2_SGE_SIMPLE_UNION SsiSimple;
	SSI2_IEEE_SGE_SIMPLE_UNION IeeeSimple;
} SSI2_SIMPLE_SGE_UNION, *PTR_SSI2_SIMPLE_SGE_UNION,
	SSI2SimpleSgeUntion_t, *pSSI2SimpleSgeUntion_t;

typedef union _SSI2_SGE_IO_UNION {
	SSI2_IEEE_SGE_SIMPLE_UNION IeeeSimple;
	SSI2_IEEE_SGE_CHAIN64 IeeeChain;
} SSI2_SGE_IO_UNION, *PTR_SSI2_SGE_IO_UNION,
	SSI2SGEIOUnion_t, *pSSI2SGEIOUnion_t;

#endif
