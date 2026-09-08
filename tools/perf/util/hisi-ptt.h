/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HiSilicon PCIe Trace and Tuning (PTT) support
 * Copyright (c) 2022 HiSilicon Technologies Co., Ltd.
 */

#ifndef INCLUDE__PERF_HISI_PTT_H__
#define INCLUDE__PERF_HISI_PTT_H__

#include <linux/bits.h>

#define HISI_PTT_PMU_NAME			"hisi_ptt"
#define HISI_PTT_AUXTRACE_PRIV_SIZE_LEGACY	sizeof(u64)
#define HISI_PTT_AUXTRACE_PRIV_SIZE_V1		(2 * sizeof(u64))
#define HISI_PTT_AUXTRACE_PRIV_SIZE		HISI_PTT_AUXTRACE_PRIV_SIZE_V1
#define HISI_PTT_PMU_PATTERN_MASK		GENMASK_ULL(39, 36)

struct auxtrace_record *hisi_ptt_recording_init(int *err,
						struct perf_pmu *hisi_ptt_pmu);

int hisi_ptt_process_auxtrace_info(union perf_event *event,
				   struct perf_session *session);

#endif
