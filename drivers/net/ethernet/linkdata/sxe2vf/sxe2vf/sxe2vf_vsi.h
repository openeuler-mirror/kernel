/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_vsi.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_VSI_H__
#define __SXE2VF_VSI_H__

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

#ifdef SXE2_TEST
#define SXE2VF_REALLOC(p, new_n, new_size, gfp, old_n)                         \
	sxe2_krealloc_array(p, new_n, new_size, gfp, old_n)
#else
#define SXE2VF_REALLOC(p, new_n, new_size, gfp)                                \
	krealloc_array(p, new_n, new_size, gfp)
#endif

s32 sxe2vf_vsi_reopen_locked(struct sxe2vf_vsi *vsi);

s32 sxe2vf_vsi_close(struct sxe2vf_vsi *vsi);

s32 sxe2vf_vsi_disable(struct sxe2vf_vsi *adapter);

s32 sxe2vf_vsi_open(struct sxe2vf_vsi *vsi);

s32 sxe2vf_vsi_rebuild(struct sxe2vf_vsi *vsi);

void sxe2vf_adv_cfg_restore(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vsi_reopen(struct sxe2vf_vsi *vsi);

s32 __sxe2vf_vsi_open(struct sxe2vf_vsi *vsi, bool is_change, bool need_up);

void sxe2vf_queues_depth_update(struct sxe2vf_vsi *vf_vsi);

void sxe2vf_vsi_qs_stats_deinit(struct sxe2vf_vsi *vsi);

s32 sxe2vf_vsi_qs_stats_init(struct sxe2vf_vsi *vsi);

s32 sxe2vf_vsi_irq_cfg_record(struct sxe2vf_vsi *vsi);

s32 sxe2vf_dpdk_irq_cnt_get(void *adapter);
s32 sxe2vf_dpdk_irq_vector_idx_get(void *adapter, u16 irq_idx);

s32 sxe2vf_dpdk_resource_release(void *adapter, struct sxe2_obj *obj);

#endif
