/* SPDX-License-Identifier: GPL-2.0 */
#ifdef CONFIG_BPF_READAHEAD

#undef TRACE_SYSTEM
#define TRACE_SYSTEM fs

#if !defined(_TRACE_FS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FS_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/fs.h>

#undef FS_DECLARE_TRACE
#ifdef DECLARE_TRACE_WRITABLE
#define FS_DECLARE_TRACE(call, proto, args, size) \
	DECLARE_TRACE_WRITABLE(call, PARAMS(proto), PARAMS(args), size)
#else
#define FS_DECLARE_TRACE(call, proto, args, size) \
	DECLARE_TRACE(call, PARAMS(proto), PARAMS(args))
#endif

FS_DECLARE_TRACE(fs_file_read,
	TP_PROTO(struct fs_file_read_ctx *ctx, int version),
	TP_ARGS(ctx, version),
	sizeof(struct fs_file_read_ctx));

DECLARE_TRACE(fs_file_release,
	TP_PROTO(struct inode *inode, struct file *filp),
	TP_ARGS(inode, filp));

#endif /* _TRACE_FS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
#else
#define trace_fs_file_release(...)
#define trace_fs_file_read(...)
#endif /* CONFIG_BPF_READAHEAD */
