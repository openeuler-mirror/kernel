/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __HISI_SDMA_AUTH_H__
#define __HISI_SDMA_AUTH_H__

#include "sdma_hal.h"

int sdma_authority_hash_init(void);
void sdma_authority_ht_free(void);
void sdma_free_authority_ht_with_pid(u32 pid);
int sdma_auth_add(u32 pasid, int num, u32 *pid_list);
int sdma_check_authority(u32 pasid, u32 owner_pid, u32 submitter_pid, u32 *owner_pasid);

#endif
