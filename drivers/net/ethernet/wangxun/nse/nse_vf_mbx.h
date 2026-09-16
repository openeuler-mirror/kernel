/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VF_MBX_H_
#define _NSE_VF_MBX_H_

#include "nse_type.h"
#include "nse_controlq.h"

#ifdef CONFIG_PCI_IOV
enum nse_status
nse_aq_send_msg_to_vf(struct nse_hw *hw, u16 vf_vsi_abs_id, u32 v_opcode, u32 v_retval,
		      u8 *msg, u16 msglen, struct nse_sq_cd *cd);

enum nse_status
nse_msgbox_p2v_send_msg_to_vf(struct nse_hw *hw, u16 vf_vsi_abs_id, u32 v_opcode, u32 v_retval,
		      u8 *msg, u16 msglen);

u32 nse_conv_link_speed_to_virtchnl(struct nse_hw *hw, bool adv_link_support, u32 link_speed);
#else /* CONFIG_PCI_IOV */
static inline enum nse_status
nse_aq_send_msg_to_vf(struct nse_hw __always_unused *hw,
		      u16 __always_unused vf_vsi_abs_id, u32 __always_unused v_opcode,
		      u32 __always_unused v_retval, u8 __always_unused *msg,
		      u16 __always_unused msglen,
		      struct nse_sq_cd __always_unused *cd)
{
	return 0;
}

static inline enum nse_status
nse_msgbox_p2v_send_msg_to_vf(struct nse_hw __always_unused *hw,
		      u16 __always_unused vf_vsi_abs_id, u32 __always_unused v_opcode,
		      u32 __always_unused v_retval, u8 __always_unused *msg,
		      u16 __always_unused msglen)
{
	return 0;
}

static inline u32
nse_conv_link_speed_to_virtchnl(struct nse_hw __always_unused *hw,
				bool __always_unused adv_link_support,
				u32 __always_unused link_speed)
{
	return 0;
}

#endif /* CONFIG_PCI_IOV */
#endif /* _NSE_VF_MBX_H_ */

