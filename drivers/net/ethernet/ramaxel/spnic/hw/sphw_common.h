/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_COMMON_H
#define SPHW_COMMON_H

#include <linux/types.h>

struct sphw_dma_addr_align {
	u32 real_size;

	void *ori_vaddr;
	dma_addr_t ori_paddr;

	void *align_vaddr;
	dma_addr_t align_paddr;
};

int sphw_dma_alloc_coherent_align(void *dev_hdl, u64 size, u64 align, unsigned int flag,
				  struct sphw_dma_addr_align *mem_align);

void sphw_dma_free_coherent_align(void *dev_hdl, struct sphw_dma_addr_align *mem_align);

enum sphw_wait_return {
	WAIT_PROCESS_CPL	= 0,
	WAIT_PROCESS_WAITING	= 1,
	WAIT_PROCESS_ERR	= 2,
};

typedef enum sphw_wait_return (*wait_cpl_handler)(void *priv_data);

int sphw_wait_for_timeout(void *priv_data, wait_cpl_handler handler,
			  u32 wait_total_ms, u32 wait_once_us);

/* *
 * sphw_cpu_to_be32 - convert data to big endian 32 bit format
 * @data: the data to convert
 * @len: length of data to convert, must be Multiple of 4B
 */
static inline void sphw_cpu_to_be32(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	u32 *mem = data;

	if (!data)
		return;

	len = len / chunk_sz;

	for (i = 0; i < len; i++) {
		*mem = cpu_to_be32(*mem);
		mem++;
	}
}

/* *
 * sphw_cpu_to_be32 - convert data from big endian 32 bit format
 * @data: the data to convert
 * @len: length of data to convert
 */
static inline void sphw_be32_to_cpu(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	u32 *mem = data;

	if (!data)
		return;

	len = len / chunk_sz;

	for (i = 0; i < len; i++) {
		*mem = be32_to_cpu(*mem);
		mem++;
	}
}

struct sphw_sge {
	u32 hi_addr;
	u32 lo_addr;
	u32 len;
};

/* *
 * sphw_set_sge - set dma area in scatter gather entry
 * @sge: scatter gather entry
 * @addr: dma address
 * @len: length of relevant data in the dma address
 */
static inline void sphw_set_sge(struct sphw_sge *sge, dma_addr_t addr, int len)
{
	sge->hi_addr = upper_32_bits(addr);
	sge->lo_addr = lower_32_bits(addr);
	sge->len = len;
}

#define sdk_err(dev, format, ...) dev_err(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_warn(dev, format, ...) dev_warn(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_notice(dev, format, ...) dev_notice(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_info(dev, format, ...) dev_info(dev, "[COMM]" format, ##__VA_ARGS__)

#define nic_err(dev, format, ...) dev_err(dev, "[NIC]" format, ##__VA_ARGS__)
#define nic_warn(dev, format, ...) dev_warn(dev, "[NIC]" format, ##__VA_ARGS__)
#define nic_notice(dev, format, ...) dev_notice(dev, "[NIC]" format, ##__VA_ARGS__)
#define nic_info(dev, format, ...) dev_info(dev, "[NIC]" format, ##__VA_ARGS__)

#endif
