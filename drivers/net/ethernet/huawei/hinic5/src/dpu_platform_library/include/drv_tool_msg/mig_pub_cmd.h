/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mig_pub_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   :
 */

#ifndef MIG_PUB_CMD_H
#define MIG_PUB_CMD_H

#include "base_type.h"

#define MAX_MIGRATE_STAGE 15
#define HIMIG_ULD_DEV_NAME "himig"
typedef struct ub_mig_time {
	u64 start_time; /* stage start times */
	u64 end_time;   /* stage end times */
} ub_mig_time_t;

typedef struct ub_migrate_stat_resp {
	struct ub_mig_time stage_time[MAX_MIGRATE_STAGE];
	u64 mig_start_time;
	u64 mig_end_time;
	u64 success_cnt;
	u64 fail_cnt;
	u16 stage;
	u16 func_id;
} ub_migrate_stat_resp_t;

typedef struct mig_query_inbuf {
    /* public */
	u32 service_type;
	u32 cmd_type;
	u32 bdf;

    /* Feature-specific parameters */
} mig_query_inbuf_t;

typedef union mig_query_outbuf {
	struct ub_migrate_stat_resp stat_resp;
} mig_query_outbuf_u;

typedef enum tag_mig_query_cmd {
    /* Public MIGRATE */
	MIG_QUERY_CMD_QUERY_UB_MIG_STAT_INFO = 0,
	MIG_QUERY_CMD_MAX
} mig_query_cmd_e;

#endif /* MIG_PUB_CMD_H */