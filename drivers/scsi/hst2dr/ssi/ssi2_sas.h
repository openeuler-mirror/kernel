/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
 *
 * Name:  ssi2_sas.h
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

#ifndef SSI2_SAS_H
#define SSI2_SAS_H

/*
 *Values for the SAS DeviceInfo field used in SAS Device Status Change Event
 *data and SAS Configuration pages.
 */
#define SSI2_SAS_DEVICE_INFO_JBOD_DEVICE		(0x00010000)
#define SSI2_SAS_DEVICE_INFO_HIDE_DEVICE		(0x10000000)
#define SSI2_SAS_DEVICE_INFO_VSES_DEVICE		(0x00008000)
#define SSI2_SAS_DEVICE_INFO_SEP			(0x00004000)
#define SSI2_SAS_DEVICE_INFO_ATAPI_DEVICE		(0x00002000)
#define SSI2_SAS_DEVICE_INFO_SSP_TARGET			(0x00000400)
#define SSI2_SAS_DEVICE_INFO_STP_TARGET			(0x00000200)
#define SSI2_SAS_DEVICE_INFO_SMP_TARGET			(0x00000100)
#define SSI2_SAS_DEVICE_INFO_SATA_DEVICE		(0x00000080)
#define SSI2_SAS_DEVICE_INFO_SSP_INITIATOR		(0x00000040)
#define SSI2_SAS_DEVICE_INFO_STP_INITIATOR		(0x00000020)
#define SSI2_SAS_DEVICE_INFO_SMP_INITIATOR		(0x00000010)
#define SSI2_SAS_DEVICE_INFO_SATA_HOST			(0x00000008)

#define SSI2_SAS_DEVICE_INFO_MASK_DEVICE_TYPE		(0x00000007)
#define SSI2_SAS_DEVICE_INFO_NO_DEVICE			(0x00000000)
#define SSI2_SAS_DEVICE_INFO_END_DEVICE			(0x00000001)
#define SSI2_SAS_DEVICE_INFO_EDGE_EXPANDER		(0x00000002)
#define SSI2_SAS_DEVICE_INFO_FANOUT_EXPANDER		(0x00000003)

/*****************************************************************************
 *
 *       SAS Messages
 *
 *****************************************************************************/

/****************************************************************************
 * SMP Passthrough messages
 ****************************************************************************/

/*SMP Passthrough Request Message */
typedef struct _SSI2_SMP_PASSTHROUGH_REQUEST {
	u8 opcode;			/* 0x00 */
	u8 opflags;			/* 0x01 */
	u16 host_tag_id;		/* 0x02 */
	u8 host_flag;			/* 0x04 */
	u8 reserved0[3];		/* 0x05 */

	U8 passthrough_flags;		/* 0x08 */
	U8 sgl_flags;			/* 0x09 */
	U8 msg_flags;			/* 0x0A */
	U8 resv0;			/* 0x0B */
	U16 request_data_len;		/* 0x0C */
	U16 handle;			/* 0x0E */
	U32 resv2[2];			/* 0x10 */
	U64 sas_address;		/* 0x18 */
	SSI2_SGE sgl;			/* 0x20 */
	SSI2_SGE sgl1;			/* 0x30 */
} SSI2_SMP_PASSTHROUGH_REQUEST;

/*values for PassthroughFlags field */
#define SSI2_SMP_PT_REQ_PT_FLAGS_IMMEDIATE      (0x80)

/*SSI v2.0: use SSI2_SGLFLAGS_ defines from ssi2.h for the SGLFlags field */

/*SMP Passthrough Reply Message */
typedef struct _SSI2_SMP_PASSTHROUGH_REPLY {
	U8 msg_len;			/* 0x00 */
	U8 passthrough_flags;		/* 0x01 */
	U8 msg_flags;			/* 0x02 */
	U8 opcode;			/* 0x03 */
	U16 response_data_len;		/* 0x04 */
	U8 resv0[2];			/* 0x06 */
	U8 sgl_flags;			/* 0x08 */
	U8 sas_status;			/* 0x09 */
	U16 status;			/* 0x0A */
	U32 log_info;			/* 0x0C */
	U32 resv1;			/* 0x10 */
	U8 response_data[4];		/* 0x14 */
} SSI2_SMP_PASSTHROUGH_REPLY;

/*values for PassthroughFlags field */
#define SSI2_SMP_PT_REPLY_PT_FLAGS_IMMEDIATE    (0x80)


/*values for SASStatus field are at the top of this file */

/****************************************************************************
 * SAS IO Unit Control messages
 * (SSI v2.5 and earlier only.
 * Replaced by IO Unit Control messages in SSI v2.6 and later.)
 ****************************************************************************/

/*SAS IO Unit Control Request Message */
typedef struct _SSI2_SAS_UNIT_CONTROL_REQUEST {
	u8 opcode;			/* 0x00 */
	u8 opflags;			/* 0x01 */
	u16 host_tag_id;		/* 0x02 */
	u8 host_flag;			/* 0x04 */
	u8 reserved0[3];		/* 0x06 */

	U8 operation;			/* 0x08 */
	U8 resv0[3];			/* 0x09 */
	U16 dev_handle;			/* 0x0C */
	U16 resv1;			/* 0x0E */
	U8 phy_num;			/* 0x10 */
	U8 resv2[3];			/* 0x11 */
	U32 primitive;			/* 0x14 */
	U32 resv3[4];			/* 0x18 */
} SSI2_SAS_UNIT_CONTROL_REQUEST;

/*values for the Operation field */

#define SSI2_SAS_OP_PHY_LINK_RESET		(0x06)
#define SSI2_SAS_OP_PHY_HARD_RESET		(0x07)

#define SSI2_SAS_OP_REMOVE_DEVICE		(0x0D)

/*SAS IO Unit Control Reply Message */
typedef struct _SSI2_SAS_UNIT_CONTROL_REPLY {
	U8 msg_len;			/* 0x00 */
	U8 operation;			/* 0x01 */
	U8 resv0;			/* 0x02 */
	U8 opcode;			/* 0x03 */
	U16 dev_handle;			/* 0x04 */
	U16 resv1[2];			/* 0x06 */
	U16 status;			/* 0x0A */
	U32 log_info;			/* 0x0C */
} SSI2_SAS_UNIT_CONTROL_REPLY;

#endif
