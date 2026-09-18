/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_common.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : Common definitions for hinic5 driver
 */

#ifndef HINIC5_COMMON_H
#define HINIC5_COMMON_H

#include <asm/byteorder.h>
#include <linux/types.h>

/**
 * @brief struct hinic5_dma_addr_align
 * @details DMA address alignment struct
 */
struct hinic5_dma_addr_align {
	u32 real_size;			/**< Real size */

	void *ori_vaddr;		/**< Original virtual address */
	dma_addr_t ori_paddr;	/**< Original physical address */

	void *align_vaddr;		/**< Aligned virtual address */
	dma_addr_t align_paddr;	/**< Aligned physical address */
};

/**
 * @brief enum hinic5_wait_return - Return value enum for wait processing
 * @details Three cases: process complete, processing, process error
 */
enum hinic5_wait_return {
	WAIT_PROCESS_CPL = 0,		/**< Indicates process complete, can proceed to next step */
	WAIT_PROCESS_WAITING = 1,	/**< Indicates processing, need to continue waiting */
	WAIT_PROCESS_ERR = 2,		/**< Indicates process error, need error handling */
};

/**
 * @brief struct hinic5_sge
 * @details Hardware identifier
 */
struct hinic5_sge {
	u32 hi_addr;  /**< High 32 bits of address */
	u32 lo_addr;  /**< Low 32 bits of address */
	u32 len;      /**< Data size */
};

/**
 * @brief Allocate a block of device-related memory, and the memory address needs to be aligned according to a certain alignment method
 * @param dev_hdl: Device handle for memory allocation
 * @param size: Size of memory to allocate
 * @param align: Memory address alignment method
 * @param flag: Memory allocation flag
 * @param mem_align: Returned memory address alignment information
 *
 * @details Allocate a block of device-related memory, and the memory address needs to be aligned according to a certain alignment method
 *
 * @return Whether successful
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_dma_zalloc_coherent_align(void *dev_hdl, u64 size, u64 align,
				     unsigned int flag,
				     struct hinic5_dma_addr_align *mem_align);

/**
 * @brief Free DMA memory
 * @param dev_hdl: Device handle
 * @param mem_align: Memory alignment struct pointer
 *
 * @details This function is used to free DMA memory allocated by hinic5_dma_alloc_coherent_align()
 *
 * @return void
 */
void hinic5_dma_free_coherent_align(void *dev_hdl,
				    struct hinic5_dma_addr_align *mem_align);


/**
 * @brief Define a function pointer type named wait_cpl_handler
 * @param priv_data: Private data, can be any type of data
 *
 * @return Returns hinic5_wait_return enum type
 */
typedef enum hinic5_wait_return (*wait_cpl_handler)(void *priv_data);

/**
 * @brief  After waiting for a certain time, check whether complete
 * @param  priv_data: Used to pass private data
 * @param  handler: Wait operation handler function
 * @param  wait_total_ms: Total wait time, unit: milliseconds
 * @param  wait_once_us: Each wait time, unit: microseconds
 *
 * @details After waiting for a certain time, check whether complete
 *
 * @return Returns the check result
 *		@retval 0: Success
 *		@retval -EINVAL: Invalid parameter
 *		@retval -EIO: Process error
 *		@retval -ETIMEDOUT: Timeout
 */
int hinic5_wait_for_timeout(void *priv_data, wait_cpl_handler handler,
			    u32 wait_total_ms, u32 wait_once_us);

/**
 * @brief Convert data from CPU byte order to big-endian byte order
 * @param data Data to convert
 * @param len Data length
 *
 * @details This function converts data from CPU byte order to big-endian byte order.
 * 			The parameter data indicates the data to convert, len indicates the data length.
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
 * @brief Convert 32-bit data in big-endian mode to current CPU byte order
 * @param data Pointer to data to convert
 * @param len Length of data to convert
 *
 * @details This function converts 32-bit data in big-endian mode to current CPU byte order.
 * 			The parameter data points to the data to convert, len indicates the length of data to convert.
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
 * @brief Set the values of hinic5_sge struct
 * @param sge Pointer to hinic5_sge struct to set
 * @param addr Address to set
 * @param len Length to set
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
#define hinic5_hw_be32(val) (val)		/**< Convert 32-bit value to big-endian, returns original value directly here */
#define hinic5_hw_cpu64(val) (val)		/**< Convert 64-bit value to CPU byte order, returns original value directly here */
#define hinic5_hw_cpu32(val) (val)		/**< Convert 32-bit value to CPU byte order, returns original value directly here */
#define hinic5_hw_cpu16(val) (val)		/**< Convert 16-bit value to CPU byte order, returns original value directly here */
#else
#define hinic5_hw_be32(val) cpu_to_be32(val)	/**< Convert 32-bit value to big-endian, calls cpu_to_be32 function for conversion here */
#define hinic5_hw_cpu64(val) be64_to_cpu(val)	/**< Convert 64-bit value to CPU byte order, calls be64_to_cpu function for conversion here */
#define hinic5_hw_cpu32(val) be32_to_cpu(val)	/**< Convert 32-bit value to CPU byte order, calls be32_to_cpu function for conversion here */
#define hinic5_hw_cpu16(val) be16_to_cpu(val)	/**< Convert 16-bit value to CPU byte order, calls be16_to_cpu function for conversion here */
#endif

/**
 * @brief Convert data from host byte order to network byte order
 * @param data Data to convert
 * @param len Data length
 *
 * @return None
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
 * @brief This function is used to convert data from CPU side to 32-bit data on HW side
 * @param data Data to convert
 * @param len Length of data to convert
 *
 * @return None
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
