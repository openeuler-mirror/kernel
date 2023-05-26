/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Huawei Technologies Co., Ltd */

#ifndef HINIC3_COMMON_H
#define HINIC3_COMMON_H

#include <linux/types.h>

struct hinic3_dma_addr_align {
	u32 real_size;

	void *ori_vaddr;
	dma_addr_t ori_paddr;

	void *align_vaddr;
	dma_addr_t align_paddr;
};

enum hinic3_wait_return {
	WAIT_PROCESS_CPL	= 0,
	WAIT_PROCESS_WAITING	= 1,
	WAIT_PROCESS_ERR	= 2,
};

struct hinic3_sge {
	u32 hi_addr;
	u32 lo_addr;
	u32 len;
};

#ifdef static
#undef static
#define LLT_STATIC_DEF_SAVED
#endif

/* *
 * hinic_cpu_to_be32 - convert data to big endian 32 bit format
 * @data: the data to convert
 * @len: length of data to convert, must be Multiple of 4B
 */
static inline void hinic3_cpu_to_be32(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	int data_len = len;
	u32 *mem = data;

	if (!data)
		return;

	data_len = data_len / chunk_sz;

	for (i = 0; i < data_len; i++) {
		*mem = cpu_to_be32(*mem);
		mem++;
	}
}

/* *
 * hinic3_cpu_to_be32 - convert data from big endian 32 bit format
 * @data: the data to convert
 * @len: length of data to convert
 */
static inline void hinic3_be32_to_cpu(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	int data_len = len;
	u32 *mem = data;

	if (!data)
		return;

	data_len = data_len / chunk_sz;

	for (i = 0; i < data_len; i++) {
		*mem = be32_to_cpu(*mem);
		mem++;
	}
}

/* *
 * hinic3_set_sge - set dma area in scatter gather entry
 * @sge: scatter gather entry
 * @addr: dma address
 * @len: length of relevant data in the dma address
 */
static inline void hinic3_set_sge(struct hinic3_sge *sge, dma_addr_t addr,
				  int len)
{
	sge->hi_addr = upper_32_bits(addr);
	sge->lo_addr = lower_32_bits(addr);
	sge->len = len;
}

#define hinic3_hw_be32(val) (val)
#define hinic3_hw_cpu32(val) (val)
#define hinic3_hw_cpu16(val) (val)

static inline void hinic3_hw_be32_len(void *data, int len)
{
}

static inline void hinic3_hw_cpu32_len(void *data, int len)
{
}

int hinic3_dma_zalloc_coherent_align(void *dev_hdl, u64 size, u64 align,
				     unsigned int flag,
				     struct hinic3_dma_addr_align *mem_align);

void hinic3_dma_free_coherent_align(void *dev_hdl,
				    struct hinic3_dma_addr_align *mem_align);

typedef enum hinic3_wait_return (*wait_cpl_handler)(void *priv_data);

int hinic3_wait_for_timeout(void *priv_data, wait_cpl_handler handler,
			    u32 wait_total_ms, u32 wait_once_us);

#endif
