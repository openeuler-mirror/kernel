// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include "bpf_helpers.h"
#include <string.h>
#include <linux/xfs.h>

/* from /sys/kernel/debug/tracing/events/xfs/xfs_read_file */
struct xfs_read_buffer_args {
	struct xfs_writable_file *file;
};

SEC("tracepoint/xfs/xfs_file_read")
int bpf_prog1(struct xfs_read_buffer_args *ctx)
{
	char fmt[] = "name: %s, clear_f_mode: %u, f_mode: %u\n";
	struct xfs_writable_file *file = ctx->file;
	char name[64] = {};
	char *tmp;
	unsigned long i_size;
	int len;

	bpf_probe_read(&tmp, 8, &(file->name));
	len = bpf_probe_read_str(name, 64, tmp);
	bpf_probe_read(&i_size, 8, &(file->i_size));

	if (!strncmp("blk_", name, 4)) {
		/* blk_xxx.meta or blk_xxx with size < 2M */
		if (len == 27 || (len == 15 && i_size <= 2 * 1024 * 1024)) {
			file->f_mode |= FMODE_WILLNEED;
		/* blk_xxx */
		} else if (len == 15) {
			if (file->prev_pos == file->pos)
				file->clear_f_mode |= FMODE_RANDOM;
		}
		bpf_trace_printk(fmt, sizeof(fmt), name, file->clear_f_mode,
				file->f_mode);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
