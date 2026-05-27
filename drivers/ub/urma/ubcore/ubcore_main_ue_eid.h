/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore main ue EID trie
 */

#ifndef UBCORE_MAIN_UE_EID_H
#define UBCORE_MAIN_UE_EID_H

#include <linux/types.h>
#include <ub/urma/ubcore_types.h>

int ubcore_insert_main_ue_eid(const union ubcore_eid *eid,
			      const union ubcore_eid *main_ue_eid);

int ubcore_delete_main_ue_eid(const union ubcore_eid *eid);

int ubcore_lookup_main_ue_eid(const union ubcore_eid *eid,
			      union ubcore_eid *main_ue_eid);

void ubcore_flush_main_ue_eid(void);

#endif
