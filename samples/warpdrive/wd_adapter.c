// SPDX-License-Identifier: GPL-2.0
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>

#include "wd_adapter.h"

#if (defined(HAVE_DYNDRV) & HAVE_DYNDRV)
#define WD_MAX_DRV_NUM			16

static struct wd_drv_dio_if *hw_dio_tbl[WD_MAX_DRV_NUM];

static char *available_lib_dirs[] = {
	"/usr/lib/",
	"/usr/lib64/",
	"/lib64/",
	"/lib/",
	"./",
	NULL,
};

int wd_drv_dio_tbl_set(struct wd_drv_dio_if *tbl)
{
	int i;

	if (!tbl || !tbl->hw_type || !tbl->send ||
	    !tbl->recv || !tbl->open || !tbl->close)
		return -EINVAL;

	for (i = 0; i < WD_MAX_DRV_NUM; i++) {
		if (hw_dio_tbl[i])
			continue;
		if (tbl == hw_dio_tbl[i])
			return 0;
		hw_dio_tbl[i] = tbl;

		return 0;
	}

	return -ENODEV;
}

/* Load the driver library */
int _wd_dyn_load(char *drv)
{
	char fpath[PATH_STR_SIZE];
	char lib[WD_NAME_SZ];
	void *handle;
	char *dir;
	int i, ret;

	if (!drv)
		return -EINVAL;
	memset((void *)lib, 0, WD_NAME_SZ);
	(void)strcat(lib, "lib");
	(void)strcat(lib, drv);
	(void)strcat(lib, ".so");

	for (i = 0; i < sizeof(available_lib_dirs); i++) {
		memset((void *)fpath, 0, sizeof(fpath));
		dir = available_lib_dirs[i];
		if (dir) {
			ret = snprintf(fpath, PATH_STR_SIZE, "%s/%s", dir, lib);
			if (ret < 0)
				return ret;
		} else {
			break;
		}
		handle = dlopen(fpath, RTLD_LAZY);
		if (!handle)
			continue;
		return 0;
	}

	return -ENODEV;
}
#else
#include "./drv/hisi_zip_udrv.h"
#include "./drv/hisi_hpre_udrv.h"

#define WD_MAX_DRV_NUM	(sizeof(hw_dio_tbl) / sizeof(struct wd_drv_dio_if *))
static struct wd_drv_dio_if hisi_zip_dio_tbl = {
	.hw_type = "hisi_zip",
	.open = hisi_zip_set_queue_dio,
	.close = hisi_zip_unset_queue_dio,
	.send = hisi_zip_add_to_dio_q,
	.recv = hisi_zip_get_from_dio_q,
	.get_capa = hisi_zip_get_capa,
};

static struct wd_drv_dio_if hisi_hpre_dio_tbl = {
	.hw_type = "hisi_hpre",
	.open = hpre_set_queue_dio,
	.close = hpre_unset_queue_dio,
	.send = hpre_add_to_dio_q,
	.recv = hpre_get_from_dio_q,
	.get_capa = hpre_get_capa,
};

static struct wd_drv_dio_if *hw_dio_tbl[] = {
	&hisi_zip_dio_tbl,
	&hisi_hpre_dio_tbl,
	/* Add other drivers direct IO operations here */
};
#endif

int _wd_get_capa(char *drv, struct wd_capa *capa)
{
	int i;

	for (i = 0; i < WD_MAX_DRV_NUM; i++) {
		if (!strcmp(drv, hw_dio_tbl[i]->hw_type))
			return hw_dio_tbl[i]->get_capa(capa);
	}

	return -ENODEV;
}

int drv_open(struct wd_queue *q)
{
	int i;

	for (i = 0; i < WD_MAX_DRV_NUM; i++) {
		if (!strcmp(q->hw_type, hw_dio_tbl[i]->hw_type)) {
			q->hw_type_id = i;
			return hw_dio_tbl[q->hw_type_id]->open(q);
		}
	}

	WD_ERR("No available driver to use!\n");

	return -ENODEV;
}

void drv_close(struct wd_queue *q)
{
	hw_dio_tbl[q->hw_type_id]->close(q);
}

int drv_send(struct wd_queue *q, void *req)
{
	return hw_dio_tbl[q->hw_type_id]->send(q, req);
}

int drv_recv(struct wd_queue *q, void **req)
{
	return hw_dio_tbl[q->hw_type_id]->recv(q, req);
}

int drv_share(struct wd_queue *q, const void *addr, size_t size, int flags)
{
	return hw_dio_tbl[q->hw_type_id]->share(q, addr, size, flags);
}

void drv_unshare(struct wd_queue *q, const void *addr, size_t size)
{
	hw_dio_tbl[q->hw_type_id]->unshare(q, addr, size);
}

int drv_can_do_mem_share(struct wd_queue *q)
{
	return hw_dio_tbl[q->hw_type_id]->share != NULL;
}

void drv_flush(struct wd_queue *q)
{
	if (hw_dio_tbl[q->hw_type_id]->flush)
		hw_dio_tbl[q->hw_type_id]->flush(q);
}
