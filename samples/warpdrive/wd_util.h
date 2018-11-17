/* SPDX-License-Identifier: GPL-2.0+ */
/* the common drv header define the unified interface for wd */
#ifndef __WD_UTIL_H__
#define __WD_UTIL_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "../../include/uapi/linux/vfio.h"
#include "wd.h"


struct wd_lock {
	__u8 lock;
};

#ifndef WD_ERR
#define WD_ERR(format, args...) fprintf(stderr, format, ##args)
#endif

#define alloc_obj(objp) do { \
	objp = malloc(sizeof(*objp)); \
	memset(objp, 0, sizeof(*objp)); \
} while (0)
#define free_obj(objp) do { if (objp)free(objp); } while (0)

void wd_spinlock(struct wd_lock *lock);
void wd_unspinlock(struct wd_lock *lock);

static inline void wd_reg_write(void *reg_addr, uint32_t value)
{
	*((uint32_t *)reg_addr) = value;
}

static inline uint32_t wd_reg_read(void *reg_addr)
{
	uint32_t temp;

	temp = *((uint32_t *)reg_addr);

	return temp;
}

static inline int _get_attr_str(const char *path, char *value)
{
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		WD_ERR("open %s fail\n", path);
		return fd;
	}
	memset(value, 0, SYS_VAL_SIZE);
	ret = read(fd, value, SYS_VAL_SIZE);
	if (ret > 0) {
		close(fd);
		return ret;
	}
	close(fd);

	return -EINVAL;
}

static inline int _get_attr_int(const char *path)
{
	char value[SYS_VAL_SIZE];

	_get_attr_str(path, value);
	return atoi(value);
}

static inline int _get_dir_attr_int(const char *dir, char *attr)
{
	char attr_path[PATH_STR_SIZE];
	char value[SYS_VAL_SIZE];
	int ret;

	if (strlen(dir) + strlen(attr) > PATH_STR_SIZE - 1)
		return -EINVAL;
	ret = snprintf(attr_path, PATH_STR_SIZE, "%s/%s", dir, attr);
	if (ret < 0)
		return ret;
	_get_attr_str(attr_path, value);

	return atoi(value);
}

static inline int _get_dir_attr_str(const char *dir, char *attr, char *str)
{
	char attr_path[PATH_STR_SIZE];
	int ret;

	if (strlen(dir) + strlen(attr) > PATH_STR_SIZE - 1)
		return -EINVAL;
	ret = snprintf(attr_path, PATH_STR_SIZE, "%s/%s", dir, attr);
	if (ret < 0)
		return ret;

	return _get_attr_str(attr_path, str);
}
#endif
