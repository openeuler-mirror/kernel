/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_EXCHG_ABORT_H
#define UNF_EXCHG_ABORT_H

#include "unf_type.h"
#include "unf_exchg.h"

#define UNF_RAW_LUN_ID_MASK 0x000000000000ffff

void unf_xchg_abort_by_lun(void *lport, void *rport, u64 lun_id, void *tm_xchg,
			   bool abort_all_lun_flag);
void unf_xchg_abort_by_session(void *lport, void *rport);
void unf_xchg_mgr_io_xchg_abort(void *lport, void *rport, u32 sid, u32 did,
				u32 extra_io_state);
void unf_xchg_mgr_sfs_xchg_abort(void *lport, void *rport, u32 sid, u32 did);
void unf_xchg_abort_all_xchg(void *lport, u32 xchg_type, bool clean);
void unf_fc_abort_time_out_cmnd(struct unf_lport *lport, struct unf_xchg *xchg);
void unf_fc_ini_io_xchg_time_out(struct work_struct *work);
void unf_sfs_xchg_time_out(struct work_struct *work);
void unf_xchg_up_abort_io_by_scsi_id(void *lport, u32 scsi_id);
#endif
