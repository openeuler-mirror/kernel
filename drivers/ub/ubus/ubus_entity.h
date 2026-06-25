/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __UBUS_ENTITY_H__
#define __UBUS_ENTITY_H__

extern bool entity_flex_en;

struct ub_entity *ub_alloc_ent(void);
int ub_setup_ent(struct ub_entity *uent);
void ub_entity_add(struct ub_entity *uent, void *ctx);
void ub_start_ent(struct ub_entity *uent);
void ub_remove_ent(struct ub_entity *uent);
void ub_stop_entities(void);
void ub_remove_entities(void);
int ub_num_ue(struct ub_entity *uent);
void ub_disable_ent(struct ub_entity *uent);
int ub_virt_notify(struct ub_entity *pue, u16 entity_idx, bool is_en);
int ub_entity_enable_force(struct ub_entity *uent, u8 enable);
int ub_reinit_ent(struct ub_entity *uent);

#endif /* __UBUS_ENTITY_H__ */
