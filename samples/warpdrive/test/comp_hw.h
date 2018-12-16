// SPDX-License-Identifier: GPL-2.0
/**
 * This file is shared bewteen user and kernel space Wrapdrive which is
 * including algorithm attibutions that both user and driver are caring for
 */

#ifndef __VFIO_WDEV_COMP_H
#define __VFIO_WDEV_COMP_H

/* De-compressing algorithms' parameters */
struct vfio_wdev_comp_param {
	__u32 window_size;
	__u32 comp_level;
	__u32 mode;
	__u32 alg;
};

enum wd_comp_op_type {
	WD_COMPRESS,
	WD_DECOMPRESS,
};

/* WD defines all the De-compressing algorithm names here */
#define VFIO_WDEV_ZLIB			"zlib"
#define VFIO_WDEV_GZIP			"gzip"
#define VFIO_WDEV_LZ4			"lz4"

/* Operational types for COMP */
enum wd_comp_op {
	WD_COMP_INVALID,
	WD_COMP_DEFLATE,
	WD_COMP_INFLATE,
	WD_COMP_PSSTHRH,
};

/* Flush types */
enum wd_comp_flush {
	WD_INVALID_FLUSH,

	/* output as much data as we can to improve performance */
	WD_NO_FLUSH,

	/* output as bytes aligning or some other conditions satisfied */
	WD_SYNC_FLUSH,

	/* indicates the end of the file/data */
	WD_FINISH,
};

#define STREAM_FLUSH_SHIFT	25

enum alg_type {
	HW_ZLIB  = 0x02,
	HW_GZIP,
};
enum hw_comp_op {
	HW_DEFLATE,
	HW_INFLATE,
};
enum hw_flush {
	HZ_SYNC_FLUSH,
	HZ_FINISH,
};

enum hw_state {
	STATELESS,
	STATEFUL,
};

enum hw_stream_status {
	STREAM_OLD,
	STREAM_NEW,
};

#endif
