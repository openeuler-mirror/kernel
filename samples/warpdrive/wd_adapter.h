/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __WD_ADAPTER_H__
#define __WD_ADAPTER_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "wd.h"

struct wd_drv_dio_if {
	char *hw_type;
	int (*open)(struct wd_queue *q);
	void (*close)(struct wd_queue *q);
	int (*set_pasid)(struct wd_queue *q);
	int (*unset_pasid)(struct wd_queue *q);
	int (*send)(struct wd_queue *q, void *req);
	int (*recv)(struct wd_queue *q, void **req);
	void (*flush)(struct wd_queue *q);
	int (*share)(struct wd_queue *q, const void *addr,
		size_t size, int flags);
	int (*unshare)(struct wd_queue *q, const void *addr, size_t size);
	int (*get_capa)(struct wd_capa *capa);
};

extern int drv_open(struct wd_queue *q);
extern void drv_close(struct wd_queue *q);
extern int drv_send(struct wd_queue *q, void *req);
extern int drv_recv(struct wd_queue *q, void **req);
extern void drv_flush(struct wd_queue *q);
extern int drv_share(struct wd_queue *q, const void *addr,
	size_t size, int flags);
extern void drv_unshare(struct wd_queue *q, const void *addr, size_t size);
extern int drv_can_do_mem_share(struct wd_queue *q);
extern int wd_drv_dio_tbl_set(struct wd_drv_dio_if *tbl);
extern int _wd_dyn_load(char *drv);
extern int _wd_get_capa(char *drv, struct wd_capa *capa);
#endif
