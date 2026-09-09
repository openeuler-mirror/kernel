/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_CQP_H
#define NBL_IB_CQP_H

#include "main.h"

/* cqp dynamic debug use */
#define NBL_CMD_DEBUG_HEAD_LEN 64
#define NBL_CMD_DEBUG_ROW_SIZE 16
#define NBL_CMD_DEBUG_GROUP_SIZE 1

#define NBM_CMD_TYPE2STR(t) ((t) == NBL_CMD_COMP_TYPE_EVENT ? "event" :\
	((t) == NBL_CMD_COMP_TYPE_FORCED ? "force" : "polling"))

#define NBL_CMD_INPUT_SIZE 64
#define NBL_CMD_OUTPUT_SIZE 64

#define NBL_HALF_ADDR_SIZE_BITS 32

#define NBL_CMD_TIMEOUT_SCHEDULE 120000 /* wait wq schedule time, 120s for EMU */
#define NBL_CMD_TIMEOUT_MSEC 10000 /* poll cmd time, 10s for EMU */
#define NBL_CMD_IN_WQEVALID_BIT 0x80
#define NBL_CMD_IN_WQEINTERUPT_BIT 0x40
#define NBL_CMD_OUT_WQEDONE_BIT 0x80
#define NBL_CMD_OUT_ERRFLAG_BIT 0x40
#define NBL_CMD_ENT_STATE_PENDING_COMP 0
#define NBL_CMD_ENT_STATUS_ERR_VAL 1 /* value when cmd execute failed */

#define NBL_CMD_VALID_VAL_INIT 0

enum { CMD_MODE_POLLING, CMD_MODE_EVENTS };

enum nbl_comp_t {
	NBL_CMD_COMP_TYPE_EVENT,
	NBL_CMD_COMP_TYPE_FORCED,
	NBL_CMD_COMP_TYPE_POLLING,
};

#if NBL_CMD_INT_USE_WQ
struct cmpl_work {
	struct work_struct work;
	struct nbl_cmd *cmd;
	u32 cmd_index;
};
#endif

struct nbl_cmd_layout {
	/* cmd input, 64 Bytes */
	union {
		struct {
			__be64 cmd_in[8];
		} general;
		struct {
			u8 valid_interrupt; /* Cmd Input Byte7 */
			u8 cmd_code; /* Cmd Input Byte6 */
			u8 input_cmd_depend0[6]; /* Cmd Input Byte5-0 */
			u8 input_cmd_depend1[56]; /* Cmd Input Byte63-8 */
		} detail;
	} in;

	/* cmd output, 64 Bytes */
	union {
		struct {
			__be64 cmd_out[8];
		} general;
		struct {
			u8 wqe_done; /* Cmd Output Byte7 */
			u8 err_code; /* Cmd Output Byte6 */
			u8 consumer_index; /* Cmd Output Byte5 */
			u8 cmd_code; /* Cmd Output Byte4 */
			u8 output_cmd_depend0[4]; /* Cmd Output Byte3-0 */
			u8 output_cmd_depend1[56]; /* Cmd Output Byte63-8 */
		} detail;
	} out;
};

struct nbl_cmd_work_ent {
	unsigned long state;
	void *in;
	int in_size;
	void *out;
	int out_size;
	u32 idx;
	struct completion handling;
	struct completion done;
	struct nbl_cmd *cmd;
	struct work_struct work;
	struct nbl_cmd_layout *lay;
	int ret;
	u8 status; /* 0 for cmd exec success, 1 for failed */
	u8 token;
	u8 valid_val; /* 0 for first circle, wqe_valid should set */
	u64 ts1;
	u64 ts2;
	u16 op;
	bool polling;
};

void nbl_cmd_comp_notifier(struct nbl_pci_f *rf, u32 cmd_index);
void nbl_cmd_use_events(struct nbl_pci_f *rf);
void nbl_cmd_use_polling(struct nbl_pci_f *rf);
int nbl_cmd_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out,
	int out_size);
int nbl_cmd_init(struct nbl_pci_f *rf);
void nbl_cmd_cleanup(struct nbl_pci_f *rf);
int nbl_cmd_exec_polling(struct nbl_pci_f *rf, void *in, int in_size, void *out,
	int out_size);

#endif /* NBL_IB_CQP_H */
