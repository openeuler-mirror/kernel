/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_MEM_H_
#define P2P_MEM_H_

#include "mem_abi.h"

int p2p_mem_get_pa_list(struct devmm_svm_process_id *process_id, u64 addr,
			u64 size, u64 *pa_list, u32 pa_num);
void p2p_mem_put_pa_list(struct devmm_svm_process_id *process_id, u64 addr,
			 u64 size, u64 *pa_list, u32 pa_num);
int p2p_mem_get_page_size(struct devmm_svm_process_id *process_id, u64 addr,
			  u64 size);

int p2p_mem_init(void);
void p2p_mem_exit(void);

#endif
