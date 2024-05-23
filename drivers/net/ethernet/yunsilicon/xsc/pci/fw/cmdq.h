/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef CMDQ_H
#define CMDQ_H

//hw will use this for some records(e.g. vf_id)
struct cmdq_rsv {
	u16 func_id;
	u8 rsv[2];
};

//related with hw, won't change
#define CMDQ_ENTRY_SIZE 64
#define CMD_FIRST_SIZE 8
#define RSP_FIRST_SIZE 14

struct xsc_cmd_layout {
	struct cmdq_rsv    rsv0;
	__be32		inlen;
	__be64		in_ptr;
	__be32		in[CMD_FIRST_SIZE];
	__be64		out_ptr;
	__be32		outlen;
	u8		token;
	u8		sig;
	u8		idx;
	u8		type: 7;
	u8      owner_bit: 1; //rsv for hw, arm will check this bit to make sure mem written
};

struct xsc_rsp_layout {
	struct cmdq_rsv    rsv0;
	__be32		out[RSP_FIRST_SIZE];
	u8		token;
	u8		sig;
	u8		idx;
	u8		type: 7;
	u8      owner_bit: 1; //rsv for hw, driver will check this bit to make sure mem written
};

struct xsc_cmd_prot_block {
	u8		data[512];
	u8		rsvd0[48];
	__be64		next;
	__be32		block_num;
	u8		owner_status; //fw should change this val to 1
	u8		token;
	u8		ctrl_sig;
	u8		sig;
};

#endif // XSC_CMD_H
