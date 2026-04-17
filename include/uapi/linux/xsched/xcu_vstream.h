/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_XSCHED_XCU_VSTREAM_H
#define _UAPI_LINUX_XSCHED_XCU_VSTREAM_H

#include <linux/types.h>

#define PAYLOAD_SIZE_MAX 512
#define XCU_SQE_SIZE_MAX 64
#define XCU_CQE_SIZE_MAX 32
#define XCU_CQE_REPORT_NUM 4
#define XCU_CQE_BUF_SIZE (XCU_CQE_REPORT_NUM * XCU_CQE_SIZE_MAX)

#define KABI_RESERVE_BYTES(idx, n) \
	__u8 __kabi_reserved_##idx[n]

/*
 * VSTREAM_ALLOC: alloc a vstream, buffer for tasks
 * VSTREAM_FREE: free a vstream
 * VSTREAM_KICK: there are tasks to be executed in the vstream
 */
typedef enum VSTREAM_COMMAND {
	VSTREAM_ALLOC = 0,
	VSTREAM_FREE,
	VSTREAM_KICK,
	VSTREAM_HBM_ALLOC,
	VSTREAM_HBM_FREE,
	MAX_COMMAND
} vstream_command_t;

typedef struct vstream_alloc_args {
	__s32 type;
	__u32 user_stream_id;

	KABI_RESERVE_BYTES(0, 8);
	KABI_RESERVE_BYTES(1, 8);
	KABI_RESERVE_BYTES(2, 8);
} vstream_alloc_args_t;

typedef struct vstream_free_args {
	KABI_RESERVE_BYTES(0, 8);
	KABI_RESERVE_BYTES(1, 8);
	KABI_RESERVE_BYTES(2, 8);
} vstream_free_args_t;

typedef struct vstream_kick_args {
	__u32 sqe_num;
	__u32 exec_time;
	__s32 timeout;
	__s8 sqe[XCU_SQE_SIZE_MAX];

	KABI_RESERVE_BYTES(0, 8);
	KABI_RESERVE_BYTES(1, 8);
	KABI_RESERVE_BYTES(2, 8);
} vstream_kick_args_t;

typedef struct vstream_hbm_args {
	__u64 size;
	__u64 addr;
} vstream_hbm_args_t;

typedef struct vstream_args {
	__u32 channel_id;
	__u32 fd;
	__u32 dev_id;
	__u32 task_type;
	__u32 sq_id;
	__u32 cq_id;

	/* Device related structures. */
	union {
		vstream_alloc_args_t va_args;
		vstream_free_args_t vf_args;
		vstream_kick_args_t vk_args;
		vstream_hbm_args_t vm_args;
	};

	__u32 payload_size;
	__s8 payload[PAYLOAD_SIZE_MAX];

	KABI_RESERVE_BYTES(0, 8);
	KABI_RESERVE_BYTES(1, 8);
	KABI_RESERVE_BYTES(2, 8);
} vstream_args_t;

#endif /* _UAPI_LINUX_XSCHED_XCU_VSTREAM_H */
