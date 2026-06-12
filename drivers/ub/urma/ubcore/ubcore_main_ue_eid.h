/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore main ue EID map
 */

#ifndef UBCORE_MAIN_UE_EID_H
#define UBCORE_MAIN_UE_EID_H

#include <linux/errno.h>
#include <linux/types.h>
#include <ub/urma/ubcore_types.h>

enum ubcore_main_ue_eid_event_type {
	UBCORE_MAIN_UE_EID_FIRST_ADD = 0,
	UBCORE_MAIN_UE_EID_LAST_DEL,
};

typedef void (*ubcore_main_ue_eid_event_cb_t)(
	const union ubcore_eid *main_ue_eid,
	enum ubcore_main_ue_eid_event_type event_type);

int ubcore_insert_main_ue_eid(const union ubcore_eid *eid,
			      const union ubcore_eid *main_ue_eid);

int ubcore_delete_main_ue_eid(const union ubcore_eid *eid);

int ubcore_lookup_main_ue_eid(const union ubcore_eid *eid,
			      union ubcore_eid *main_ue_eid);

int ubcore_register_main_ue_eid_event_cb(ubcore_main_ue_eid_event_cb_t cb);

int ubcore_unregister_main_ue_eid_event_cb(ubcore_main_ue_eid_event_cb_t cb);

void ubcore_flush_main_ue_eid(void);

#endif
