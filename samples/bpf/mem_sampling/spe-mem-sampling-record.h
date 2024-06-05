/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024, Huawei Technologies Ltd */
#ifndef __SPE_RECORD_H
#define __SPE_RECORD_H

enum mem_sampling_sample_type {
	MEM_SAMPLING_L1D_ACCESS		= 1 << 0,
	MEM_SAMPLING_L1D_MISS		= 1 << 1,
	MEM_SAMPLING_LLC_ACCESS		= 1 << 2,
	MEM_SAMPLING_LLC_MISS		= 1 << 3,
	MEM_SAMPLING_TLB_ACCESS		= 1 << 4,
	MEM_SAMPLING_TLB_MISS		= 1 << 5,
	MEM_SAMPLING_BRANCH_MISS	= 1 << 6,
	MEM_SAMPLING_REMOTE_ACCESS	= 1 << 7,
};

struct mem_sampling_record {
	enum mem_sampling_sample_type	type;
	int				err;
	unsigned int			op;
	unsigned int			latency;
	unsigned long long		from_ip;
	unsigned long long		to_ip;
	unsigned long long		timestamp;
	unsigned long long		virt_addr;
	unsigned long long		phys_addr;
	unsigned long long		context_id;
	unsigned char			source;
};

/* definition of a sample sent to user-space from BPF program */
struct event {
	enum mem_sampling_sample_type	type;
	int				err;
	unsigned int			op;
	unsigned int			latency;
	unsigned long long		from_ip;
	unsigned long long		to_ip;
	unsigned long long		timestamp;
	unsigned long long		virt_addr;
	unsigned long long		phys_addr;
	unsigned long long		context_id;
	unsigned char			source;
	char				comm[16];
};

#endif /* __SPE_RECORD_H */
