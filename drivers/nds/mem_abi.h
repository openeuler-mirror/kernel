/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_MEM_ABI_H_
#define P2P_MEM_ABI_H_

#include <linux/types.h>

struct devmm_svm_process_id {
	int32_t host_pid;
	union {
		uint16_t devid;
		uint16_t vm_id;
	};
	uint16_t vfid;
};

int devmm_get_mem_pa_list(struct devmm_svm_process_id *process_id, u64 addr,
			  u64 size, u64 *pa_list, u32 pa_num);
void devmm_put_mem_pa_list(struct devmm_svm_process_id *process_id, u64 addr,
			   u64 size, u64 *pa_list, u32 pa_num);
int devmm_get_mem_page_size(struct devmm_svm_process_id *process_id, u64 addr,
			    u64 size);

#endif
