/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef NBL_SHARED_H
#define NBL_SHARED_H

/* General Public Define */
#define NBL_ENABLE_MASK 1

#define NBL_ADAPTER_PAGE_SHIFT 12
#define NBL_ADAPTER_PAGE_SIZE BIT(NBL_ADAPTER_PAGE_SHIFT)

#define NBL_CMD_ENTRY_SIZE 128
#define NBL_CMD_ENTRY_SIZE_LOG 7
#define NBL_CMD_ENTRY_MAX_NUM (NBL_ADAPTER_PAGE_SIZE / NBL_CMD_ENTRY_SIZE)
#define NBL_CMD_WQ_MAX_NAME 32
#define NBL_CMD_INT_USE_WQ 1 /* 1- use wq when interrupt mode, save time, 0- not use wq */

#define NBL_RDMA_FIRST_FUNCTION_ID 0
#define NBL_RDMA_TOTAL_FUNCTION_NUM 64
#define NBL_HMC_MAX_OBJ_LOG_SZ 9   /* qpc log size (1 << 9) */

#define NBL_RESERVE_START_IOVA 0x1000
#define NBL_RESERVE_END_IOVA 0x10000
#define NBL_RESERVE_RANGE_IOVA (NBL_RESERVE_END_IOVA - NBL_RESERVE_START_IOVA)

/* RDMA spec related Define */
#define NBL_DEFAULT_PKEY 0xFFFF

/*
 * default read ost: orion 64 rnic 64, df200 32, draco 16, leonis 16
 * 1111100101b, 0x3E5
 */
#define NBL_DEFAULT_RD_ATOMIC 0x3E5
#define RNIC_OST(x)    (((x) >> 6) & 0x03)
#define DF200_OST(x)   (((x) >> 4) & 0x03)
#define DRACO_OST(x)   (((x) >> 2) & 0x03)
#define LEONIS_OST(x)  ((x) & 0x03)
#define NBL_READ_OST_CODE_8 0
#define NBL_READ_OST_CODE_16 1
#define NBL_READ_OST_CODE_32 2
#define NBL_READ_OST_CODE_64 3
#define NBL_READ_OST_VAL(x) (8 << (x))

#define RDMA_DRIVER_NBLPRIV 41
#define EMP_FW_VERSION_NAME_MAX 7
#define NBL_RDMA_FW_MAJOR_VER 1
#define NBL_RDMA_FW_MINOR_VER 0

#define NBL_RDMA_INTERNAL_CFG_MASK (0xFFFF)
#define NBL_DEV_MAX_QP_FLAG BIT(0)
#define NBL_DISABLE_RDMA_BYPASS_FLAG BIT(1)

/* QP number reserved */
#define NBL_QP_NUM_FOR_RSV 0 /* qp num 0 is reserve */
#define NBL_QP_NUM_FOR_CM 1 /* qp num 1 is cm use */
#define NBL_QP_NUM_FOR_DUMP 2 /* qp num 2 is for rdma dump */

#define SNIC_RDMA_PF_START_DEVICE_ID	0x3403
#define SNIC_RDMA_PF_END_DEVICE_ID	0x3412
#define SNIC_RDMA_VF_DEVICE_ID		0x3413

#define DF200_ECPU_PF2_DEVICE_ID        0x1226
#define DF200_ECPU_PF3_DEVICE_ID        0x1227
#define DF200_HOST_RDMA_DEVICE_ID       0x1047
#define ASIC_V2R1_PF_DEVICE_ID          0x3500
#define ASIC_V2R1_VF_DEVICE_ID          0x3501
#define DRACO_RDMA_PF_START_DEVICE_ID   0x3502
#define DRACO_RDMA_PF_END_DEVICE_ID     0x3509
#define DRACO_RDMA_VF_DEVICE_ID         0x350a
#define ORION_RDMA_PF_DEVICE_ID         0x3600
#define ORION_RDMA_VF_DEVICE_ID         0x3601
#define RNIC400_PF_DEVICE_ID            0x1610

/*
 * in snic POC test, we limit the max qp num to 4096 per pf,
 * and resv qp0 and qp1
 * so the real max qp num is 4094
 */
#define LEONIS_POC_MAX_QP_NUM 4094

/*
 * in draco POC test, we limit the max qp num to 4096 per pf,
 * and resv qp0 and qp1
 * qp2 for tcpdump, one qp for umr,
 * so the real max qp num is 4092
 */
#define DRACO_POC_MAX_QP_NUM 4092

static inline void nbl_get_ibname(char *name, size_t size, bool is_lag, u32 id)
{
	if (is_lag)
		snprintf(name, size - 1, "nbl_bond%d", id);
	else
		snprintf(name, size - 1, "nbl%d", id);
}

/**
 * set_64bit_val - set 64 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_64bit_val(__be64 *wqe_words, u32 byte_index, u64 val)
{
	wqe_words[byte_index >> 3] = cpu_to_be64(val);
}

/**
 * set_16bit_val - set 16 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_16bit_val(__be16 *wqe_words, __u32 byte_index, __u16 val)
{
	wqe_words[byte_index >> 1] = cpu_to_be16(val);
}

/**
 * set_32bit_val - set 32 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_32bit_val(__be32 *wqe_words, u32 byte_index, u32 val)
{
	wqe_words[byte_index >> 2] = cpu_to_be32(val);
}

/**
 * get_32bit_val - read 32 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to reaad from
 * @val: return 32 bit value
 **/
static inline void get_32bit_val(__be32 *wqe_words, u32 byte_index, u32 *val)
{
	*val = be32_to_cpu(wqe_words[byte_index >> 2]);
}

/**
 * get_64bit_val - read 64 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to read from
 * @val: read value
 **/
static inline void get_64bit_val(__be64 *wqe_words, u32 byte_index, u64 *val)
{
	*val = be64_to_cpu(wqe_words[byte_index >> 3]);
}

#endif /* NBL_SHARED_H */
