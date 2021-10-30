/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_TYPE_H
#define UNF_TYPE_H

#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/kref.h>
#include <linux/scatterlist.h>
#include <linux/crc-t10dif.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/cpufreq.h>
#include <linux/semaphore.h>
#include <linux/jiffies.h>

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_transport_fc.h>
#include <linux/sched/signal.h>

#ifndef SPFC_FT
#define SPFC_FT
#endif

#define BUF_LIST_PAGE_SIZE (PAGE_SIZE << 8)

#define UNF_S_TO_NS (1000000000)
#define UNF_S_TO_MS (1000)

enum UNF_OS_THRD_PRI_E {
	UNF_OS_THRD_PRI_HIGHEST = 0,
	UNF_OS_THRD_PRI_HIGH,
	UNF_OS_THRD_PRI_SUBHIGH,
	UNF_OS_THRD_PRI_MIDDLE,
	UNF_OS_THRD_PRI_LOW,
	UNF_OS_THRD_PRI_BUTT
};

#define UNF_OS_LIST_NEXT(a) ((a)->next)
#define UNF_OS_LIST_PREV(a) ((a)->prev)

#define UNF_OS_PER_NS (1000000000)
#define UNF_OS_MS_TO_NS (1000000)

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

#ifndef INVALID_VALUE64
#define INVALID_VALUE64 0xFFFFFFFFFFFFFFFFULL
#endif /* INVALID_VALUE64 */

#ifndef INVALID_VALUE32
#define INVALID_VALUE32 0xFFFFFFFF
#endif /* INVALID_VALUE32 */

#ifndef INVALID_VALUE16
#define INVALID_VALUE16 0xFFFF
#endif /* INVALID_VALUE16 */

#ifndef INVALID_VALUE8
#define INVALID_VALUE8 0xFF
#endif /* INVALID_VALUE8 */

#ifndef RETURN_OK
#define RETURN_OK 0
#endif

#ifndef RETURN_ERROR
#define RETURN_ERROR (~0)
#endif
#define UNF_RETURN_ERROR (~0)

/* define shift bits */
#define UNF_SHIFT_1 1
#define UNF_SHIFT_2 2
#define UNF_SHIFT_3 3
#define UNF_SHIFT_4 4
#define UNF_SHIFT_6 6
#define UNF_SHIFT_7 7
#define UNF_SHIFT_8 8
#define UNF_SHIFT_11 11
#define UNF_SHIFT_12 12
#define UNF_SHIFT_15 15
#define UNF_SHIFT_16 16
#define UNF_SHIFT_17 17
#define UNF_SHIFT_19 19
#define UNF_SHIFT_20 20
#define UNF_SHIFT_23 23
#define UNF_SHIFT_24 24
#define UNF_SHIFT_25 25
#define UNF_SHIFT_26 26
#define UNF_SHIFT_28 28
#define UNF_SHIFT_29 29
#define UNF_SHIFT_32 32
#define UNF_SHIFT_35 35
#define UNF_SHIFT_37 37
#define UNF_SHIFT_39 39
#define UNF_SHIFT_40 40
#define UNF_SHIFT_43 43
#define UNF_SHIFT_48 48
#define UNF_SHIFT_51 51
#define UNF_SHIFT_56 56
#define UNF_SHIFT_57 57
#define UNF_SHIFT_59 59
#define UNF_SHIFT_60 60
#define UNF_SHIFT_61 61

/* array index */
#define ARRAY_INDEX_0 0
#define ARRAY_INDEX_1 1
#define ARRAY_INDEX_2 2
#define ARRAY_INDEX_3 3
#define ARRAY_INDEX_4 4
#define ARRAY_INDEX_5 5
#define ARRAY_INDEX_6 6
#define ARRAY_INDEX_7 7
#define ARRAY_INDEX_8 8
#define ARRAY_INDEX_10 10
#define ARRAY_INDEX_11 11
#define ARRAY_INDEX_12 12
#define ARRAY_INDEX_13 13

/* define mask bits */
#define UNF_MASK_BIT_7_0 0xff
#define UNF_MASK_BIT_15_0 0x0000ffff
#define UNF_MASK_BIT_31_16 0xffff0000

#define UNF_IO_SUCCESS 0x00000000
#define UNF_IO_ABORTED 0x00000001 /* the host system aborted the command */
#define UNF_IO_FAILED 0x00000002
#define UNF_IO_ABORT_ABTS 0x00000003
#define UNF_IO_ABORT_LOGIN 0x00000004  /* abort login */
#define UNF_IO_ABORT_REET 0x00000005   /* reset event aborted the transport */
#define UNF_IO_ABORT_FAILED 0x00000006 /* abort failed */
/* data out of order ,data reassembly error */
#define UNF_IO_OUTOF_ORDER 0x00000007
#define UNF_IO_FTO 0x00000008 /* frame time out */
#define UNF_IO_LINK_FAILURE 0x00000009
#define UNF_IO_OVER_FLOW 0x0000000a /* data over run */
#define UNF_IO_RSP_OVER 0x0000000b
#define UNF_IO_LOST_FRAME 0x0000000c
#define UNF_IO_UNDER_FLOW 0x0000000d /* data under run */
#define UNF_IO_HOST_PROG_ERROR 0x0000000e
#define UNF_IO_SEST_PROG_ERROR 0x0000000f
#define UNF_IO_INVALID_ENTRY 0x00000010
#define UNF_IO_ABORT_SEQ_NOT 0x00000011
#define UNF_IO_REJECT 0x00000012
#define UNF_IO_RS_INFO 0x00000013
#define UNF_IO_EDC_IN_ERROR 0x00000014
#define UNF_IO_EDC_OUT_ERROR 0x00000015
#define UNF_IO_UNINIT_KEK_ERR 0x00000016
#define UNF_IO_DEK_OUTOF_RANGE 0x00000017
#define UNF_IO_KEY_UNWRAP_ERR 0x00000018
#define UNF_IO_KEY_TAG_ERR 0x00000019
#define UNF_IO_KEY_ECC_ERR 0x0000001a
#define UNF_IO_BLOCK_SIZE_ERROR 0x0000001b
#define UNF_IO_ILLEGAL_CIPHER_MODE 0x0000001c
#define UNF_IO_CLEAN_UP 0x0000001d
#define UNF_SRR_RECEIVE 0x0000001e /* receive srr */
/* The target device sent an ABTS to abort the I/O.*/
#define UNF_IO_ABORTED_BY_TARGET 0x0000001f
#define UNF_IO_TRANSPORT_ERROR 0x00000020
#define UNF_IO_LINK_FLASH 0x00000021
#define UNF_IO_TIMEOUT 0x00000022
#define UNF_IO_PORT_UNAVAILABLE 0x00000023
#define UNF_IO_PORT_LOGOUT 0x00000024
#define UNF_IO_PORT_CFG_CHG 0x00000025
#define UNF_IO_FIRMWARE_RES_UNAVAILABLE 0x00000026
#define UNF_IO_TASK_MGT_OVERRUN 0x00000027
#define UNF_IO_DMA_ERROR 0x00000028
#define UNF_IO_DIF_ERROR 0x00000029
#define UNF_IO_NO_LPORT 0x0000002a
#define UNF_IO_NO_XCHG 0x0000002b
#define UNF_IO_SOFT_ERR 0x0000002c
#define UNF_IO_XCHG_ADD_ERROR 0x0000002d
#define UNF_IO_NO_LOGIN 0x0000002e
#define UNF_IO_NO_BUFFER 0x0000002f
#define UNF_IO_DID_ERROR 0x00000030
#define UNF_IO_UNSUPPORT 0x00000031
#define UNF_IO_NOREADY 0x00000032
#define UNF_IO_NPORTID_REUSED 0x00000033
#define UNF_IO_NPORT_HANDLE_REUSED 0x00000034
#define UNF_IO_NO_NPORT_HANDLE 0x00000035
#define UNF_IO_ABORT_BY_FW 0x00000036
#define UNF_IO_ABORT_PORT_REMOVING 0x00000037
#define UNF_IO_INCOMPLETE 0x00000038
#define UNF_IO_DIF_REF_ERROR 0x00000039
#define UNF_IO_DIF_GEN_ERROR 0x0000003a

#define UNF_IO_ERREND 0xFFFFFFFF

#endif
