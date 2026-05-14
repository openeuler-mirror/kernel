/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef _UB_UBUS_UB_MEM_DECODER_H_
#define _UB_UBUS_UB_MEM_DECODER_H_

#include <linux/types.h>

enum ras_err_type {
	UB_MEM_ATOMIC_DATA_ERR = 0,
	UB_MEM_READ_DATA_ERR,
	UB_MEM_FLOW_POISON,
	UB_MEM_FLOW_READ_AUTH_POISON,
	UB_MEM_FLOW_READ_AUTH_RESPERR,
	UB_MEM_TIMEOUT_POISON,
	UB_MEM_TIMEOUT_RESPERR,
	UB_MEM_READ_DATA_POISON,
	UB_MEM_READ_DATA_RESPERR,
	MAR_NOPORT_VLD_INT_ERR,
	MAR_FLUX_INT_ERR,
	MAR_WITHOUT_CXT_ERR,
	RSP_BKPRE_OVER_TIMEOUT_ERR,
	MAR_NEAR_AUTH_FAIL_ERR,
	MAR_FAR_AUTH_FAIL_ERR,
	MAR_TIMEOUT_ERR,
	MAR_ILLEGAL_ACCESS_ERR,
	REMOTE_READ_DATA_ERR_OR_WRITE_RESPONSE_ERR,
#ifndef __GENKSYMS__
	UB_MEM_PORT_WARNING,
	UB_MEM_PORT_RECOVERY,
#endif
};

typedef int (*ubmem_ras_handler)(u64, enum ras_err_type);

#ifdef CONFIG_UB_UBUS

/*
 * ub_mem_ras_handler_register - register ub memory ras handler for OBMM
 * @handler: OBMM ras handler
 */
void ub_mem_ras_handler_register(ubmem_ras_handler handler);

/*
 * ub_mem_ras_handler_unregister - unregister ub memory ras handler for OBMM
 */
void ub_mem_ras_handler_unregister(void);

/*
 * ub_mem_ras_handler_get - get ub memory ras handler
 * RETURN VALUE: ubmem_ras_handler
 */
ubmem_ras_handler ub_mem_ras_handler_get(void);

/*
 * ub_mem_drain_start - start ub memory drain
 * @scna: source cna
 */
void ub_mem_drain_start(u32 scna);

/*
 * ub_mem_drain_state - whether ub memory drain has been finished
 * @scna: source cna
 * RETURN VALUE:
 * 0 if drain not finish; 1 if drain finish
 * other if failed.
 */
int ub_mem_drain_state(u32 scna);

/*
 * ub_mem_drain_start_enhanced - start ub memory drain enhanced
 */
void ub_mem_drain_start_enhanced(void);

/*
 * ub_mem_drain_state_enhanced - whether ub memory drain enhanced has been finished
 * RETURN VALUE:
 * 0 if drain not finish; 1 if drain finish
 * other if failed.
 */
int ub_mem_drain_state_enhanced(void);

/*
 * ub_mem_get_numa_id - get ubc numa id from scna
 * @scna: source cna
 * RETURN VALUE:
 * numa id
 */
int ub_mem_get_numa_id(u32 scna);

/*
 * ub_memory_validate_pa - Determine whether hpa is valid
 * @scna: source cna
 * @pa_start: hpa start address
 * @pa_end: hpa end address
 * @cacheable: cacheable flag
 * RETURN VALUE:
 * true if hpa is valid
 * false if hpa is invalid
 */
bool ub_memory_validate_pa(u32 scna, u64 pa_start, u64 pa_end, bool cacheable);

#else /* CONFIG_UB_UBUS is not enabled */
static inline void ub_mem_ras_handler_register(ubmem_ras_handler handler) {}
static inline void ub_mem_ras_handler_unregister(void) {}
static inline ubmem_ras_handler ub_mem_ras_handler_get(void) { return NULL; }
static inline void ub_mem_drain_start(u32 scna) {}
static inline int ub_mem_drain_state(u32 scna) { return -EINVAL; }
static inline int ub_mem_get_numa_id(u32 scna) { return NUMA_NO_NODE; }
static inline bool ub_memory_validate_pa(u32 scna, u64 pa_start, u64 pa_end,
					 bool cacheable)
{ return false; }
#endif /* CONFIG_UB_UBUS */

#endif /* _UB_UBUS_UB_MEM_DECODER_H_ */
