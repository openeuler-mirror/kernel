// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Arch specific functions for perf kvm stat.
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 */
#include <errno.h>
#include "../../util/kvm-stat.h"
#include "../../util/evsel.h"
#include "aarch64_guest_exits.h"

define_exit_reasons_table(arm64_exit_reasons, kvm_arm_exception_type);

static struct kvm_events_ops exit_events = {
	.is_begin_event = exit_event_begin,
	.is_end_event = exit_event_end,
	.decode_key = exit_event_decode_key,
	.name = "VM-EXIT"
};

const char *vcpu_id_str = "vcpu_id";
const int decode_str_len = 20;
const char *kvm_exit_reason = "ret";
const char *kvm_entry_trace = "kvm:kvm_entry";
const char *kvm_exit_trace = "kvm:kvm_exit";

const char *kvm_events_tp[] = {
	"kvm:kvm_entry",
	"kvm:kvm_exit",
	NULL,
};

struct kvm_reg_events_ops kvm_reg_events_ops[] = {
	{ .name = "vmexit", .ops = &exit_events },
	{ NULL, NULL },
};

const char * const kvm_skip_events[] = {
	NULL,
};

int cpu_isa_init(struct perf_kvm_stat *kvm, const char *cpuid __maybe_unused)
{
	kvm->exit_reasons = arm64_exit_reasons;
	kvm->exit_reasons_isa = "aarch64";

	return 0;
}
