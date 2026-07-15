.. SPDX-License-Identifier: GPL-2.0

==============
MFS Filesystem
==============

Overview
========

MFS is a stackable file system that utilizes a lower and a cache layer. It
provides users with programmable caching capabilities. MFS only supports
read-only operations for regular files, directories and symbolic links. When
MFS is stacked on top of the lower and cache layers (which are themselves
mounted on other file systems, such as ext4 or xfs), the underlying file
systems must be also kept read-only to prevent the data inconsistency.

MFS supports three running mode: none, local and remote. These modes are
explained in running mode section. In short, MFS requires the `mtree` and
`cachedir` mount options. The `mtree` option specifies the metadata source
for MFS, while the `cachedir` option specifies the data source. In local or
remote mode, `cachedir` points to a local cache (in memory or on disk) for
backend file systems.


Mount options
=============

================    ==========================================================
mode=%s             Supported running mode. Here are:

		    ======  ==================================================
                      none  As a stackable file system on the lower file
                            system, and just pass through operations to the
                            backend file system.
                     local  Working at local mode which lower and cachedir
                            layer are both local file system. And the miss
                            event (not hit in page cache) will post the async
                            events to the userspace.
                    remote  Working at remote mode which the target data is in
                            the remote storage such as OBS or other private
                            distributed file system without POSIX-like
                            interface. And the miss event (not hit in local
                            cache) will post the sync events to the userspace
                            and waiting for replying.
		    ======  ==================================================
mtree=%s            Lower layer path.
cachedir=%s         Cache layer path.
================    ==========================================================

**NOTE**: The path in `mtree` and `cachedir` options must not be the same as
the mount point, nor can they be a subdirectories of each other.

Communication Framework
=======================

Each MFS instance has a unique communication device named `/dev/mfs${minor}`.
MFS sends the MISS events to the user daemon as needed. The user daemon can
obtain these events by polling and reading from the device. To obtain the
minor number for an MFS instance, the user must call `statfs()` on its mount
point and parse the value from `f_spare[0]` in the `struct statfs`.

Each request starts with a message header of the form::

	struct mfs_msg {
		__u8 version;
		__u8 opcode;
		__u16 len;
		__u32 fd;
		__u32 id;
		__u8 data[];
	};

where:

	* ``version`` indicates the version number which for extension.

	* ``opcode`` indicates the type of the event.

	* ``len`` indicates the whole length of the event, including the
	  header and the following type-specific payload.

	* ``fd`` indicates the file handle of internal file object.

	* ``id`` is a unique ID identifying the event.

	* ``data`` indicates the payload of the event.

The MFS mainly posts reading events when the data is missing in the local
cache (memory or disk). The payload format is define as follows::

	struct mfs_read {
		__u64 off;
		__u64 len;
		__s32 pid;
	};

where:

	* ``off`` indicates the offset of the reading request which triggers
	  this event.

	* ``len`` indicates the length of the reading request which triggers
	  this event.

	* ``pid`` indicates the pid of the reading process which triggers
	  this event.

Currently the opcode is defined as follows::

	enum mfs_opcode {
		MFS_OP_READ = 0,
		MFS_OP_FAULT,
		MFS_OP_CLOSE,
	};

where means: normal read event, page fault event and close event.
Please refer to the `include/uapi/linux/mfs.h` file for the latest
definitions.

Running mode
============

There are three running mode in MFS: none, local and remote. The user can use
`MFS_IOC_FSINFO ioctl` on device fd to obtain the information.

The parameter for this request is as follows::

	struct mfs_ioc_fsinfo {
		__u8 mode;  /* 0: none, 1: local, 2: remote */
	};

where mode will be assigned the value defined in a enum structure as follows::

	enum {
		MFS_MODE_NONE = 0,
		MFS_MODE_LOCAL,
		MFS_MODE_REMOTE,
	};

In none mode, MFS does not report any events. It just passes operations
through to the underlying file system.

In local mode, MFS uses page cache as its local cache. If a read request
results in a cache miss, the MISS events are reported for the non-contiguous
missing range. This is an asynchronous event, which means the kernel does not
block waiting for it. The user daemon can prefetch subsequence data based on
this event to avoid future cache misses.

In remote mode, MFS uses a local disk (as specified by the `cachedir` mount
option) as its cache. If a read request misses in the local disk cache (checked
using `SEEK_HOLE` and `SEEK_DATA`), the MISS events are reported. This is a
synchronous event, which means the kernel will block on this event and wait
for the user daemon to respond with the corresponding message id.

The following structure definition will be used for user daemon to respond the
target events::

	struct mfs_ioc_ra {
		__u64 off;
		__u64 len;
	};

where:

	* ``off`` indicates the offset where to prefetch.

	* ``len`` indicates the length to prefetch.

and it used in local mode by using the `MFS_IOC_RA ioctl` on the `fd` in the
message header.

When running in remote mode, the use daemon should 1) fetch the target data
from remote storage, 2) write the data to MFS using the `write()` syscal on
the `fd` provided in the message header, 3) reply by calling the
`MFS_IOC_DONE ioctl` with the parameter::

	struct mfs_ioc_done {
		__u32 id;
		__u32 ret;
	};

where:

	* ``id``: indicates the message id in message header.

	* ``ret``: indicates the return code for the event, and 0 means success.

In some cases, the use daemon may need to obtain the full path of file object
associated with the event to implement more complex strategy, such as one based
on tracing. To do this, it uses the `MFS_IOC_RPATH ioctl` on `fd` which
provided in the  message header. The parameter for this is::

	struct mfs_ioc_rpath {
		__u16 max;
		__u16 len;
		__u8 d[];
	};

where:

	* ``max`` indicates the max length of input data area to fill the full
	  path.

	* ``len`` indicates the real length of the full path.

	* ``d[]`` indicate the input data area allocated by user daemon.

The user daemon will use the flexible strategy to prefetch the data. So
in MFS, the default prefetch in VFS is disabled.


Use cases
=========

- Boost model weight loading.

In this case, the user daemon can employ several strategies to improve
performance, such as: concurrent loading, larger I/O size for read-ahead, numa
aware allocation and trace-based prefetching triggered by MISS events.

- Tracing the reading io.

In this case, the user daemon can log the MISS io during running the process by
parsing `offset` and `length` in the message.


Sysfs interfaces
================

- Set the event reporting filter.

Users can filter events reported by MFS through `/sys/fs/mfs/mfs${minor}/ev_mask`.
The filtering rules are controlled by bitwise masks, and the mask calculation
is performed based on the input value. For example, bit 0 represents a read event,
and bit 1 represents a fault event. The order of the bits is determined by the
value of `enum mfs_opcode`.
