/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_IO_ABNORMAL_H
#define UNF_IO_ABNORMAL_H

#include "unf_type.h"
#include "unf_lport.h"
#include "unf_exchg.h"

#define UNF_GET_LL_ERR(pkg) (((pkg)->status) >> 16)

void unf_process_scsi_mgmt_result(struct unf_frame_pkg *pkg,
				  struct unf_xchg *xchg);
u32 unf_hardware_start_io(struct unf_lport *lport, struct unf_frame_pkg *pkg);
u32 unf_recv_abts_marker_status(void *lport, struct unf_frame_pkg *pkg);
u32 unf_recv_tmf_marker_status(void *lport, struct unf_frame_pkg *pkg);

#endif
