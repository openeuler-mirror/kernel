/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef __CDMA_UOBJ_H__
#define __CDMA_UOBJ_H__
#include "cdma_types.h"

enum cdma_uobj_type {
	CDMA_UOBJ_TYPE_JFCE,
	CDMA_UOBJ_TYPE_JFC,
	CDMA_UOBJ_TYPE_CTP,
	CDMA_UOBJ_TYPE_JFS,
	CDMA_UOBJ_TYPE_QUEUE,
	CDMA_UOBJ_TYPE_SEGMENT
};

struct cdma_uobj {
	struct cdma_file *cfile;
	enum cdma_uobj_type type;
	int id;
	void *object;
	atomic_t rcnt;
};

void cdma_init_uobj_idr(struct cdma_file *cfile);
struct cdma_uobj *cdma_uobj_create(struct cdma_file *cfile,
				   enum cdma_uobj_type obj_type);
void cdma_uobj_delete(struct cdma_uobj *uobj);
struct cdma_uobj *cdma_uobj_get(struct cdma_file *cfile, int id,
				enum cdma_uobj_type type);
void cdma_cleanup_context_uobj(struct cdma_file *cfile, enum cdma_remove_reason why);
void cdma_close_uobj_fd(struct cdma_file *cfile);

#endif /* __CDMA_UOBJ_H__ */
