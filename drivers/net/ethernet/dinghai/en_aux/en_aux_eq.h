/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_AUX_EQ_H__
#define __EN_AUX_EQ_H__

#include "../en_aux.h"
#define ZXDH_AUX_ASYNC_EQ_NUM 4

struct dh_aux_eq_table {
	struct dh_eq_async async_eq_tbl[ZXDH_AUX_ASYNC_EQ_NUM];
};

s32 dh_aux_eq_table_init(struct zxdh_en_priv *en_priv);
s32 dh_aux_eq_table_create(struct zxdh_en_priv *en_priv);
void dh_aux_eq_table_destroy(struct zxdh_en_priv *en_priv);
void dh_aux_eq_table_cleanup(struct zxdh_en_priv *en_priv);
s32 dh_eq_async_link_info_int_process(struct zxdh_en_priv *en_priv);
s32 dh_bond_pf_link_info_get(struct zxdh_en_priv *en_priv);
#endif
