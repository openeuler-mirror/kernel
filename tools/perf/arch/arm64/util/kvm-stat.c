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
define_exit_reasons_table(arm64_trap_reasons, kvm_arm_exception_class);

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

const char *kvm_trap_reason = "esr_ec";
const char *kvm_trap_enter_trace = "kvm:kvm_trap_enter";
const char *kvm_trap_exit_trace = "kvm:kvm_trap_exit";

static void trap_event_get_key(struct perf_evsel *evsel,
			       struct perf_sample *sample,
			       struct event_key *key)
{
	key->info = 0;
	key->key = perf_evsel__intval(evsel, sample, kvm_trap_reason);
}

static const char *get_trap_reason(u64 exit_code)
{
	struct exit_reasons_table *tbl = arm64_trap_reasons;

	while (tbl->reason != NULL) {
		if (tbl->exit_code == exit_code)
			return tbl->reason;
		tbl++;
	}

	pr_err("Unknown kvm trap exit code: %lld on aarch64\n",
	       (unsigned long long)exit_code);
	return "UNKNOWN";
}

static bool trap_event_end(struct perf_evsel *evsel,
			   struct perf_sample *sample __maybe_unused,
			   struct event_key *key __maybe_unused)
{
	return (!strcmp(evsel->name, kvm_trap_exit_trace));
}

static bool trap_event_begin(struct perf_evsel *evsel,
			     struct perf_sample *sample, struct event_key *key)
{
	if (!strcmp(evsel->name, kvm_trap_enter_trace)) {
		trap_event_get_key(evsel, sample, key);
		return true;
	}

	return false;
}

static void trap_event_decode_key(struct perf_kvm_stat *kvm __maybe_unused,
				  struct event_key *key,
				  char *decode)
{
	const char *trap_reason = get_trap_reason(key->key);

	scnprintf(decode, decode_str_len, "%s", trap_reason);
}

static struct kvm_events_ops trap_events = {
	.is_begin_event = trap_event_begin,
	.is_end_event = trap_event_end,
	.decode_key = trap_event_decode_key,
	.name = "TRAP-EVENT",
};

const char *kvm_events_tp[] = {
	"kvm:kvm_entry",
	"kvm:kvm_exit",
	"kvm:kvm_trap_enter",
	"kvm:kvm_trap_exit",
	NULL,
};

struct kvm_reg_events_ops kvm_reg_events_ops[] = {
	{ .name = "vmexit", .ops = &exit_events },
	{ .name = "trap", .ops = &trap_events },
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
