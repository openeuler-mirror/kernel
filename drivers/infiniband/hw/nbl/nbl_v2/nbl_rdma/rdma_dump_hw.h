/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
#ifndef NBL_RDMA_DUMP_HW_H
#define NBL_RDMA_DUMP_HW_H

#include "regs_v2/nbl_reg_uepro.h"
#include "regs_v2/nbl_reg_dipro.h"
#include "regs_v2/nbl_reg_depro.h"

/* RNIC400 */
#define GET_MIRROR_ID_FROM_VFID(vfid) (vfid)

void nbl_set_dump_rdma_cfg_v3(struct nbl_hw *hw, u16 vsi_id,
			      bool enable_flag);
void nbl_set_dump_rdma_cfg_v4(struct nbl_hw *hw, u16 vsi_id,
			      u16 function_id, u8 host, bool enable_flag);

#endif
