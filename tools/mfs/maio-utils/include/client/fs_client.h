// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#ifndef _FS_CLIENT_H_
#define _FS_CLIENT_H_

#include <stdint.h>

int fs_evict_by_path(const char *path, uint64_t off, uint64_t len);
int fs_load_by_path(const char *path, uint64_t off, uint64_t len);
int fs_load_by_fd(int fd, uint64_t off, uint64_t len);
int fs_sync_by_path(const char *path, void *buf, uint64_t off, uint64_t len);

int fs_client_init(const char *source);
void fs_client_exit(void);

#endif
