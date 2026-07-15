/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_common.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_COMMON_H
#define HINIC5_COMMON_H

#include <asm/byteorder.h>
#include <linux/types.h>

/**
 * @brief struct hinic5_dma_addr_align
 * @details DMA address alignment structure
 */
struct hinic5_dma_addr_align {
	u32 real_size;		/**< real size */

	void *ori_vaddr;	/**< original virtual address */
	dma_addr_t ori_paddr;	/**< original physical address */

	void *align_vaddr;	/**< aligned virtual address */
	dma_addr_t align_paddr;	/**< aligned physical address */
};

/**
 * @brief enum hinic5_wait_return - wait processing return value enum
 * @details there are three cases: processing completed, processing in progress, processing error
 */
enum hinic5_wait_return {
	WAIT_PROCESS_CPL = 0,		/**< processing completed, can proceed to next step */
	WAIT_PROCESS_WAITING = 1,	/**< processing in progress, need to continue waiting */
	WAIT_PROCESS_ERR = 2,		/**< processing error, need error handling */
};

/**
 * @brief struct hinic5_sge
 * @details hardware scatter-gather entry
 */
struct hinic5_sge {
	u32 hi_addr;  /**< high 32 bits of address */
	u32 lo_addr;  /**< low 32 bits of address */
	u32 len;      /**< data size */
};

/**
 * @brief allocate device-related memory with specified alignment
 * @param dev_hdl: device handle for memory allocation
 * @param size: memory size to allocate
 * @param align: memory address alignment
 * @param flag: memory allocation flags
 * @param mem_align: returned memory address alignment information
 *
 * @details allocate device-related memory with specified alignment
 *
 * @return success or failure
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_dma_zalloc_coherent_align(void *dev_hdl, u64 size, u64 align,
				     unsigned int flag,
				     struct hinic5_dma_addr_align *mem_align);

/**
 * @brief free DMA coherent memory
 * @param dev_hdl: device handle
 * @param mem_align: memory alignment structure pointer
 *
 * @details this function frees DMA memory allocated by hinic5_dma_alloc_coherent_align()
 *
 * @return void
 */
void hinic5_dma_free_coherent_align(void *dev_hdl,
				    struct hinic5_dma_addr_align *mem_align);


/**
 * @brief define a function pointer type named wait_cpl_handler
 * @param priv_data: private data, can be any type of data
 *
 * @return returns hinic5_wait_return enum type
 */
typedef enum hinic5_wait_return (*wait_cpl_handler)(void *priv_data);

/**
 * @brief  wait for a period of time and then check if completed
 * @param  priv_data: private data for passing
 * @param  handler: handler function for wait operation
 * @param  wait_total_ms: total wait time in milliseconds
 * @param  wait_once_us: single wait duration in microseconds
 *
 * @details wait for a period of time and then check if completed
 *
 * @return check result
 *		@retval 0: success
 *		@retval -EINVAL: invalid parameter
 *		@retval -EIO: processing error
 *		@retval -ETIMEDOUT: timeout
 */
int hinic5_wait_for_timeout(void *priv_data, wait_cpl_handler handler,
			    u32 wait_total_ms, u32 wait_once_us);

/**
 * @brief convert data from CPU byte order to big-endian byte order
 * @param data data to convert
 * @param len data length
 *
 * @details this function converts data from CPU byte order to big-endian byte order.
 * 			parameter data is the data to convert, len is the data length.
 *
 * @return void
 */
static inline void hinic5_cpu_to_be32(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	int data_len = len;
	u32 *mem = (u32 *)data;

	if (!data)
		return;

	data_len = data_len / chunk_sz;

	for (i = 0; i < data_len; i++) {
		*mem = cpu_to_be32(*mem);
		mem++;
	}
}

/**
 * @brief convert 32-bit big-endian data to CPU byte order
 * @param data pointer to data to convert
 * @param len length of data to convert
 *
 * @details this function converts 32-bit big-endian data to CPU byte order.
 * 			parameter data points to the data to convert, len is the length of data to convert.
 *
 * @return void
 */
static inline void hinic5_be32_to_cpu(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	int data_len = len;
	u32 *mem = (u32 *)data;

	if (!data)
		return;

	data_len = data_len / chunk_sz;

	for (i = 0; i < data_len; i++) {
		*mem = be32_to_cpu(*mem);
		mem++;
	}
}

/**
 * @brief set values for hinic5_sge structure
 * @param sge pointer to hinic5_sge structure to set
 * @param addr address to set
 * @param len length to set
 *
 * @return void
 */
static inline void hinic5_set_sge(struct hinic5_sge *sge, dma_addr_t addr,
				  u32 len)
{
	sge->hi_addr = upper_32_bits(addr);
	sge->lo_addr = lower_32_bits(addr);
	sge->len = len;
}

#ifdef HW_CONVERT_ENDIAN
#define hinic5_hw_be32(val) (val)		/**< convert 32-bit value to big-endian, return original value directly */
#define hinic5_hw_cpu64(val) (val)		/**< convert 64-bit value to CPU byte order, return original value directly */
#define hinic5_hw_cpu32(val) (val)		/**< convert 32-bit value to CPU byte order, return original value directly */
#define hinic5_hw_cpu16(val) (val)		/**< convert 16-bit value to CPU byte order, return original value directly */
#else
#define hinic5_hw_be32(val) cpu_to_be32(val)	/**< convert 32-bit value to big-endian, call cpu_to_be32 for conversion */
#define hinic5_hw_cpu64(val) be64_to_cpu(val)	/**< convert 64-bit value to CPU byte order, call be64_to_cpu for conversion */
#define hinic5_hw_cpu32(val) be32_to_cpu(val)	/**< convert 32-bit value to CPU byte order, call be32_to_cpu for conversion */
#define hinic5_hw_cpu16(val) be16_to_cpu(val)	/**< convert 16-bit value to CPU byte order, call be16_to_cpu for conversion */
#endif

/**
 * @brief convert data from host byte order to network byte order
 * @param data data to convert
 * @param len data length
 *
 * @return void
 */
static inline void hinic5_hw_be32_len(void *data, int len)
{
#ifndef HW_CONVERT_ENDIAN
	int i, chunk_sz = sizeof(u32);
	int data_len = len;
	u32 *mem = (u32 *)data;

	if (!data)
		return;

	data_len = data_len / chunk_sz;

	for (i = 0; i < data_len; i++) {
		*mem = hinic5_hw_be32(*mem);
		mem++;
	}
#endif
}

/**
 * @brief this function converts data from CPU to HW 32-bit data
 * @param data data to convert
 * @param len length of data to convert
 *
 * @return void
 */
static inline void hinic5_hw_cpu32_len(void *data, int len)
{
#ifndef HW_CONVERT_ENDIAN
	int i, chunk_sz = sizeof(u32);
	int data_len = len;
	u32 *mem = (u32 *)data;

	if (!data)
		return;

	data_len = data_len / chunk_sz;

	for (i = 0; i < data_len; i++) {
		*mem = hinic5_hw_cpu32(*mem);
		mem++;
	}
#endif
}

#endif
