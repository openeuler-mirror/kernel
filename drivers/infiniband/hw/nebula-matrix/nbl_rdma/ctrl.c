// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include <linux/kernel.h>
#include <linux/bitfield.h>
#include "main.h"
#include "type.h"
#include "user.h"
#include "ctrl.h"
#include "defs.h"
#include "osdep.h"
#include "cqp.h"
#include "debug.h"

enum nbl_status_code nbl_sc_dev_init(struct nbl_sc_dev *sc_dev,
				     struct nbl_device_init_info *info)
{
	sc_dev->hw = info->hw;
	sc_dev->hw->hw_addr = info->bar0;
	/* to do set other dev attr */

	sc_dev->hw_attrs.max_hw_ird = info->ost_rd_atom;
	sc_dev->hw_attrs.max_hw_ord = NBL_MAX_ORD_SIZE;
	sc_dev->hw_attrs.max_hw_pds = NBL_MAX_PDS;
	sc_dev->hw_attrs.max_hw_ahs = NBL_MAX_AHS;
	sc_dev->hw_attrs.max_mr_size = NBL_MAX_MR_SIZE;
	sc_dev->hw_attrs.min_hw_aeqe_count = NBL_MIN_AEQ_ENTRIES;
	sc_dev->hw_attrs.max_hw_aeqe_count = NBL_MAX_AEQ_ENTRIES;
	sc_dev->hw_attrs.min_hw_ceqe_count = NBL_MIN_CEQ_ENTRIES;
	sc_dev->hw_attrs.max_hw_ceqe_count = NBL_MAX_CEQ_ENTRIES;
	sc_dev->hw_attrs.max_hw_outbound_msg_size = NBL_MAX_OUTBOUND_MSG_SIZE;
	sc_dev->hw_attrs.max_hw_inbound_msg_size = NBL_MAX_INBOUND_MSG_SIZE;
	sc_dev->hw_attrs.uk_attrs.min_hw_cq_size = NBL_MIN_CQ_SIZE;
	sc_dev->hw_attrs.uk_attrs.max_hw_cq_size = NBL_MAX_CQ_SIZE;

	return nbl_init_hw(sc_dev);
}
