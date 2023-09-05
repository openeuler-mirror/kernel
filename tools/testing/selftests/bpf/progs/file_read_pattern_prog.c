// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

/* Need to keep consistent with definitions in include/linux/fs.h */
#define FMODE_CTL_RANDOM 0x1000
#define FMODE_CTL_WILLNEED 0x400000

struct fs_file_read_ctx {
	const unsigned char *name;
	unsigned int f_mode;
	unsigned int rsvd;
	/* clear from f_ctl_mode */
	unsigned int clr_f_mode;
	/* set into f_ctl_mode */
	unsigned int set_f_mode;
	unsigned long key;
	/* file size */
	long long i_size;
	/* previous page index */
	long long prev_index;
	/* current page index */
	long long index;
};

struct fs_file_read_args {
	struct fs_file_read_ctx *ctx;
	int version;
};

struct fs_file_release_args {
	void *inode;
	void *filp;
};

struct file_rd_hist {
	__u64 last_nsec;
	__u32 seq_nr;
	__u32 tot_nr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, struct file_rd_hist);
	__uint(max_entries, 10000);
} htab SEC(".maps");

static bool is_expected_file(void *name)
{
	char prefix[5];
	int err;

	err = bpf_probe_read_str(&prefix, sizeof(prefix), name);
	if (err <= 0)
		return false;
	return !strncmp(prefix, "blk_", 4);
}

SEC("raw_tracepoint.w/fs_file_read")
int fs_file_read(struct fs_file_read_args *args)
{
	const char fmt[] = "elapsed %llu, seq %u, tot %u\n";
	struct fs_file_read_ctx *rd_ctx = args->ctx;
	struct file_rd_hist *hist;
	struct file_rd_hist new_hist;
	__u64 key;
	__u64 now;
	bool first;

	if (!is_expected_file((void *)rd_ctx->name))
		return 0;

	if (rd_ctx->i_size <= (4 << 20)) {
		rd_ctx->set_f_mode = FMODE_CTL_WILLNEED;
		return 0;
	}

	first = false;
	now = bpf_ktime_get_ns();
	key = rd_ctx->key;
	hist = bpf_map_lookup_elem(&htab, &key);
	if (!hist) {
		__builtin_memset(&new_hist, 0, sizeof(new_hist));
		new_hist.last_nsec = now;
		first = true;
		hist = &new_hist;
	}

	if (rd_ctx->index >= rd_ctx->prev_index &&
	    rd_ctx->index - rd_ctx->prev_index <= 1)
		hist->seq_nr += 1;
	hist->tot_nr += 1;

	bpf_trace_printk(fmt, sizeof(fmt), now - hist->last_nsec,
			 hist->seq_nr, hist->tot_nr);

	if (first) {
		bpf_map_update_elem(&htab, &key, hist, 0);
		return 0;
	}

	/* 500ms or 10 read */
	if (now - hist->last_nsec >= 500000000ULL || hist->tot_nr >= 10) {
		if (hist->tot_nr >= 10) {
			if (hist->seq_nr <= hist->tot_nr * 3 / 10)
				rd_ctx->set_f_mode = FMODE_CTL_RANDOM;
			else if (hist->seq_nr >= hist->tot_nr * 7 / 10)
				rd_ctx->clr_f_mode = FMODE_CTL_RANDOM;
		}

		hist->last_nsec = now;
		hist->tot_nr = 0;
		hist->seq_nr = 0;
	}

	return 0;
}

SEC("raw_tracepoint/fs_file_release")
int fs_file_release(struct fs_file_release_args *args)
{
	__u64 key = (unsigned long)args->filp;
	void *value;

	value = bpf_map_lookup_elem(&htab, &key);
	if (value)
		bpf_map_delete_elem(&htab, &key);

	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
