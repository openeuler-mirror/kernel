/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_FLEX_TYPE_H_
#define _NSE_FLEX_TYPE_H_

#define NSE_FV_OFFSET_INVAL	0x1FF
#define NSE_FV_DISABLE      0x0
#define NSE_FV_ENABLE       0x1

/* Extraction Sequence (Field Vector) Table */
struct nse_fv_word {
	u8 prot_id;
	u16 off;		/* Offset within the protocol header */
	u8 enable;
} __packed;

#define NSE_MAX_NUM_PROFILES 256

#define NSE_AQ_MAX_FV_WORDS 64 /*max field vector config regs in adminq cmd*/
#define NSE_MAX_FV_WORDS 80
#define NSE_FW_RSV_FV_WORD_OFF 71
/*filed vector config array*/
struct nse_fv {
	struct nse_fv_word ew[NSE_MAX_FV_WORDS];
};

enum nse_tunnel_type {
	TNL_VXLAN = 0,
	TNL_GENEVE,
	TNL_GRETAP,
	TNL_GTP,
	TNL_GTPC,
	TNL_GTPU,
	TNL_ECPRI,
	TNL_LAST = 0xFF,
	TNL_ALL = 0xFF,
};

#endif
