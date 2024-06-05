// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Huawei Technologies Ltd */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "spe-mem-sampling-record.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

SEC("raw_tracepoint/spe_record")
int handle_exec(struct bpf_raw_tracepoint_args *ctx)
{
	// TP_PROTO(struct mem_sampling_record *record)
	struct mem_sampling_record *rd = (struct mem_sampling_record *)ctx->args[0];
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	if (bpf_get_current_comm(e->comm, sizeof(e->comm)))
		e->comm[0] = 0;

	e->context_id = BPF_CORE_READ(rd, context_id);
	e->virt_addr = BPF_CORE_READ(rd, virt_addr);
	e->phys_addr = BPF_CORE_READ(rd, phys_addr);
	e->latency = BPF_CORE_READ(rd, latency);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

