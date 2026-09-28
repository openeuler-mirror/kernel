/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_CMD_H
#define _LINUX_IO_URING_CMD_H

#include <uapi/linux/io_uring.h>

/* only top 8 bits of sqe->uring_cmd_flags for kernel internal use */
#define IORING_URING_CMD_CANCELABLE	(1U << 30)
#define IORING_URING_CMD_POLLED		(1U << 31)

enum {
	/*
	 * A hint to not wake right away but delay until there are enough of
	 * tw's queued to match the number of CQEs the task is waiting for.
	 *
	 * Must not be used wirh requests generating more than one CQE.
	 * It's also ignored unless IORING_SETUP_DEFER_TASKRUN is set.
	 */
	IOU_F_TWQ_LAZY_WAKE			= 1,

	/*
	 * Set when task_work is queued from a waitqueue wakeup handler, where
	 * an arbitrary provider waitqueue lock is held. Signaling the CQ ring
	 * eventfd inline from there can recurse back into that lock through
	 * epoll, so the eventfd signal must be deferred.
	 */
	IOU_F_TWQ_IN_WAKE			= 2,
};

enum io_uring_cmd_flags {
	IO_URING_F_COMPLETE_DEFER	= 1,
	IO_URING_F_UNLOCKED		= 2,
	/* the request is executed from poll, it should not be freed */
	IO_URING_F_MULTISHOT		= 4,
	/* executed by io-wq */
	IO_URING_F_IOWQ			= 8,
	/* int's last bit, sign checks are usually faster than a bit test */
	IO_URING_F_NONBLOCK		= INT_MIN,

	/* ctx state flags, for URING_CMD */
	IO_URING_F_SQE128		= (1 << 8),
	IO_URING_F_CQE32		= (1 << 9),
	IO_URING_F_IOPOLL		= (1 << 10),

	/* set when uring wants to cancel a previously issued command */
	IO_URING_F_CANCEL		= (1 << 11),
	IO_URING_F_TASK_DEAD		= (1 << 13),
};

struct io_uring_cmd {
	struct file	*file;
	const struct io_uring_sqe *sqe;
	union {
		/* callback to defer completions to task context */
		void (*task_work_cb)(struct io_uring_cmd *cmd, unsigned);
		/* used for polled completion */
		void *cookie;
	};
	u32		cmd_op;
	u32		flags;
	u8		pdu[32]; /* available inline for free use */
};

static inline const void *io_uring_sqe_cmd(const struct io_uring_sqe *sqe)
{
	return sqe->cmd;
}

static inline void io_uring_cmd_private_sz_check(size_t cmd_sz)
{
	BUILD_BUG_ON(cmd_sz > sizeof_field(struct io_uring_cmd, pdu));
}
#define io_uring_cmd_to_pdu(cmd, pdu_type) ( \
	io_uring_cmd_private_sz_check(sizeof(pdu_type)), \
	((pdu_type *)&(cmd)->pdu) \
)

#if defined(CONFIG_IO_URING)
int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter, void *ioucmd);

/*
 * Completes the request, i.e. posts an io_uring CQE and deallocates @ioucmd
 * and the corresponding io_uring request.
 *
 * Note: the caller should never hard code @issue_flags and is only allowed
 * to pass the mask provided by the core io_uring code.
 */
void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret, ssize_t res2,
			unsigned issue_flags);

void __io_uring_cmd_do_in_task(struct io_uring_cmd *ioucmd,
			    void (*task_work_cb)(struct io_uring_cmd *, unsigned),
			    unsigned flags);

/*
 * Note: the caller should never hard code @issue_flags and only use the
 * mask provided by the core io_uring code.
 */
void io_uring_cmd_mark_cancelable(struct io_uring_cmd *cmd,
		unsigned int issue_flags);
struct task_struct *io_uring_cmd_get_task(struct io_uring_cmd *cmd);

/* Execute the request from a blocking context */
void io_uring_cmd_issue_blocking(struct io_uring_cmd *ioucmd);

#else
static inline int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter, void *ioucmd)
{
	return -EOPNOTSUPP;
}
static inline void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret,
		ssize_t ret2, unsigned issue_flags)
{
}
static inline void __io_uring_cmd_do_in_task(struct io_uring_cmd *ioucmd,
			    void (*task_work_cb)(struct io_uring_cmd *, unsigned),
			    unsigned flags)
{
}
static inline void io_uring_cmd_mark_cancelable(struct io_uring_cmd *cmd,
		unsigned int issue_flags)
{
}
static inline struct task_struct *io_uring_cmd_get_task(struct io_uring_cmd *cmd)
{
	return NULL;
}
static inline void io_uring_cmd_issue_blocking(struct io_uring_cmd *ioucmd)
{
}
#endif

/* users must follow the IOU_F_TWQ_LAZY_WAKE semantics */
static inline void io_uring_cmd_do_in_task_lazy(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *, unsigned))
{
	__io_uring_cmd_do_in_task(ioucmd, task_work_cb, IOU_F_TWQ_LAZY_WAKE);
}

static inline void io_uring_cmd_complete_in_task(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *, unsigned))
{
	__io_uring_cmd_do_in_task(ioucmd, task_work_cb, 0);
}

#endif /* _LINUX_IO_URING_CMD_H */
