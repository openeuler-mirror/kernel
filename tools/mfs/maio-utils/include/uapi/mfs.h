/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI_LINUX_MFS_H
#define _UAPI_LINUX_MFS_H

#include <linux/types.h>
#include <linux/ioctl.h>

enum mfs_opcode {
	MFS_OP_READ = 0,
	MFS_OP_FAULT,
	MFS_OP_FAROUND,
};

enum {
	MFS_MODE_NONE = 0,
	MFS_MODE_LOCAL,
	MFS_MODE_REMOTE,
};

struct mfs_ioc_ra {
	__u64 off;
	__u64 len;
};

struct mfs_ioc_done {
	__u32 id;
	__u32 ret;
};

struct mfs_ioc_rpath {
	__u16 max;
	__u16 len;
	__u8 d[];
};

#define MFS_IOC_RA	_IOW(0xbc,	1, struct mfs_ioc_ra)
#define MFS_IOC_DONE	_IOW(0xbc,	2, struct mfs_ioc_done)
#define MFS_IOC_RPATH	_IOWR(0xbc,	3, struct mfs_ioc_rpath)

struct mfs_ioc_fsinfo {
	__u8 mode;  /* 0: none, 1: local, 2: remote */
};

#define MFS_IOC_FSINFO	_IOR(0xbd,	1, struct  mfs_ioc_fsinfo)

struct mfs_msg {
	__u8 version;
	__u8 opcode;
	__u16 len;
	__u32 fd;
	__u32 id;
	__u8 data[];
};

struct mfs_read {
	__u64 off;
	__u64 len;
	__s32 pid;
};

#endif /* _UAPI_LINUX_MFS_H */
