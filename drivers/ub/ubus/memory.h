/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __MEMORY_H__
#define __MEMORY_H__

#include <linux/types.h>
#include <linux/kfifo.h>
#include <ub/ubus/ubus.h>
#include <ub/ubus/ub-mem-decoder.h>

#define MAX_RAS_ERROR_SOURCES_CNT 256

void ub_mem_decoder_init(struct ub_entity *uent);
void ub_mem_decoder_uninit(struct ub_entity *uent);
void ub_mem_init_usi(struct ub_entity *uent);
void ub_mem_uninit_usi(struct ub_entity *uent);

extern struct mutex mem_ras_mutex;

struct ub_mem_ras_err_info {
	enum ras_err_type type;
	u64 val0; /* addr or transaction id + port bitmap or 0*/
	u64 val1; /* port bitmap or 0 */
};

struct ub_mem_ras_ctx {
	DECLARE_KFIFO(ras_fifo, struct ub_mem_ras_err_info,
		      MAX_RAS_ERROR_SOURCES_CNT);
};

struct ub_mem_device_ops {
	void (*mem_drain_start)(struct ub_bus_controller *ubc);
	int (*mem_drain_state)(struct ub_bus_controller *ubc);
	bool (*mem_validate_pa)(struct ub_bus_controller *ubc, u64 pa_start,
				u64 pa_end, bool cacheable);

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
};

struct ub_mem_device {
	struct device *dev;
	struct ub_entity *uent;
	struct ub_mem_ras_ctx ras_ctx;
	int ubmem_irq_num;
	const struct ub_mem_device_ops *ops;
	void *priv_data;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
};

#endif /* __MEMORY_H__ */
