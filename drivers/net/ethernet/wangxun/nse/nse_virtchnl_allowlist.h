/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VIRTCHNL_ALLOWLIST_H_
#define _NSE_VIRTCHNL_ALLOWLIST_H_
#include "nse.h"

bool nse_vc_is_opcode_allowed(struct nse_vf *vf, u32 opcode);

void nse_vc_set_default_allowlist(struct nse_vf *vf);
void nse_vc_set_working_allowlist(struct nse_vf *vf);
void nse_vc_set_caps_allowlist(struct nse_vf *vf);
#endif /* _NSE_VIRTCHNL_ALLOWLIST_H_ */
