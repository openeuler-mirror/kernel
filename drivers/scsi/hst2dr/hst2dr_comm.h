/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This is the hst2dr driver providing communication ssi2 interface
 * for access to hst2dr firmware.
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_comm.h

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

#ifndef HST2DR_COMM_H_INCLUDED
#define HST2DR_COMM_H_INCLUDED

#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/nvme.h>
#include "hst2dr_hal.h"

#undef Ex
#ifdef HST2DR_COMM_C
#define Ex
#else
#define Ex extern
#endif
#define NVME_COMMAND_LENGTH_128		128
#define HI_PRIORITY			0x80
enum hst2dr_opcode {
	cmd_hst2dr_scsi_io	=	0x80,
	cmd_internal		=	0x90,
};
enum hst2dr_nvme_flag_mode {
	cmd_flag_fw_mode_io		= 2,
	cmd_flag_fw_mode_admin		= 1,
	cmd_flag_hw_mode		= 0,
	cmd_flag_high_priority		= 0x80,
};
enum hst2dr_io_flag {
	io_flag_non_io			= 0,
	io_flag_write			= 1,
	io_flag_read			= 2,
};

enum hst2dr_internal_cmd_type {
	hst2dr_cmd_base			= 0,
	hst2dr_cmd_port_enable,
	hst2dr_cmd_transport,
	hst2dr_cmd_scsih,
	hst2dr_cmd_tm,
	hst2dr_cmd_ctl,
	hst2dr_cmd_config,
	hst2dr_cmd_ioa_init,
	hst2dr_cmd_ioa_info,
};
/**
 * struct hst2dr_command_head - hst2dr command head
 * @opcode: operation code
 * @flags: hst2dr nvme flag mode
 * @host_id: message index
 * @subcode: sub operation code
 * @request_flags: request flags
 * @reserved0: reserved
 * @reserved1: reserved
 * @reserved2: reserved
 *
 **/

typedef struct hst2dr_command_head {
	__u8 opcode;
	__u8 opflags;
	__u16 host_tag_id;
	__u8 host_flag;
	__u8 request_flags;
	__u16 reserved0;
	__u32 reserved1;
	__u32 reserved2;
} hst2dr_command_head;
#ifndef hst2dr_nvme_internal_cmd
typedef struct _hst2dr_nvme_internal_cmd {
	union hst2dr_hal {
		struct hst2dr_command_head head;
		SSI2_INQUIRY_PAGE_REQUEST cfg_request;
		SSI2_IOA_INFO_REQUEST ioa_info_request;
		SSI2_IOA_INIT_REQUEST ioa_init_request;
		__u8 request[0x70];
	} cmd;
} hst2dr_nvme_internal_cmd;

enum {
	SAGE_NVME_INTERNAL_COMMAND,
	SAGE_NVME_SCSI_COMMAND,
};

typedef struct _hst2dr_command {
	union _cmd {
		struct _hst2dr_nvme_internal_cmd internal;
		hst2dr_vendor_cmd io;
	} cmd;
} hst2dr_command;
#endif

#define hst2dr_send_cmd_via_nvme_hal_api hst2dr_send_nvme_vendor_cmd_hal_api

Ex int hst2dr_get_ioa_info_comm_api(struct HST2DR_ADAPTER *ioa,
	SSI2_IOA_INFO_REPLY *basic_info);
Ex int hst2dr_ioa_init_comm_api(struct HST2DR_ADAPTER *ioa,
	SSI2_IOA_INIT_REQUEST *ssi_request, SSI2_IOA_INIT_REPLY *ioa_init_reply);
Ex int hst2dr_send_cmd_via_nvme_hal_api(struct HST2DR_ADAPTER *ioa, void *cmd);
Ex void hst2dr_build_scsiio_cmd_api(struct HST2DR_ADAPTER *ioa,
	SSI2_SCSI_REQUEST *ssi_request, u16 host_tag_id);
Ex void hst2dr_build_scsiio_cmd_force_fw_mode_api(struct HST2DR_ADAPTER *ioa,
	SSI2_SCSI_REQUEST *ssi_request, u16 host_tag_id);
Ex void _debug_dump_mem(char *hints, void *mem, int sz);


#endif
