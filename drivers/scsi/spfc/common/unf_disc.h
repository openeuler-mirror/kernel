/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_DISC_H
#define UNF_DISC_H

#include "unf_type.h"

#define UNF_DISC_RETRY_TIMES 3
#define UNF_DISC_NONE 0
#define UNF_DISC_FABRIC 1
#define UNF_DISC_LOOP 2

enum unf_disc_state {
	UNF_DISC_ST_START = 0x3000,
	UNF_DISC_ST_GIDPT_WAIT,
	UNF_DISC_ST_GIDFT_WAIT,
	UNF_DISC_ST_END
};

enum unf_disc_event {
	UNF_EVENT_DISC_NORMAL_ENTER = 0x8000,
	UNF_EVENT_DISC_FAILED = 0x8001,
	UNF_EVENT_DISC_SUCCESS = 0x8002,
	UNF_EVENT_DISC_RETRY_TIMEOUT = 0x8003,
	UNF_EVENT_DISC_LINKDOWN = 0x8004
};

enum unf_disc_type {
	UNF_DISC_GET_PORT_NAME = 0,
	UNF_DISC_GET_NODE_NAME,
	UNF_DISC_GET_FEATURE
};

struct unf_disc_gs_event_info {
	void *lport;
	void *rport;
	u32 rport_id;
	enum unf_disc_type type;
	struct list_head list_entry;
};

u32 unf_get_and_post_disc_event(void *lport, void *sns_port, u32 nport_id,
				enum unf_disc_type type);

void unf_flush_disc_event(void *disc, void *vport);
void unf_disc_ctrl_size_inc(void *lport, u32 cmnd);
void unf_disc_error_recovery(void *lport);
void unf_disc_mgr_destroy(void *lport);

#endif
