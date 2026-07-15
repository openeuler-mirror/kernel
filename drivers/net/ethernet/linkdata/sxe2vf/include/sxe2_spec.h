/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_spec.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_SPEC__
#define __SXE2_SPEC__

#define SXE2_TXSCHED_LAYER_MAX_7	7
#define SXE2_TXSCHED_LAYER_MAX_4	4
#define SXE2_TXSCHED_LAYER_MAX_3	3
#define SXE2_TXSCHED_LEAF_MAX_3072	3072
#define SXE2_TXSCHED_LEAF_MAX_512	512
#define SXE2_TXSCHED_LEAF_MAX_256	256
#define SXE2_TXSCHED_LEAF_MAX_128	128
#define SXE2_TXSCHED_LEAF_MAX_64	64

#define SXE2_TXSCHED_LAYER_MAX SXE2_TXSCHED_LAYER_MAX_7
#define SXE2_TXSCHED_LEAF_MAX SXE2_TXSCHED_LEAF_MAX_3072

#define SXE2_DFLT_IRQS_MAX_CNT 64
#define SXE2_XDP_TX_Q_NUM      8

#ifndef SXE2_TXSCHED_LAYER_MAX
#define SXE2_TXSCHED_LAYER_MAX SXE2_TXSCHED_LAYER_MAX_7
#endif

#ifndef SXE2_TXSCHED_LEAF_MAX
#define SXE2_TXSCHED_LEAF_MAX SXE2_TXSCHED_LEAF_MAX_3072
#endif

#ifndef SXE2_VSI_PF_ASSURED_NUM
#define SXE2_VSI_PF_ASSURED_NUM 256
#endif

#ifndef SXE2_PF_NUM
#define SXE2_PF_NUM    8
#endif

#ifndef SXE2_VSI_NUM
#define SXE2_VSI_NUM   768
#endif

#ifndef SXE2_QUEUE_NUM
#define SXE2_QUEUE_NUM 2048
#endif

#ifndef SXE2_IRQ_NUM
#define SXE2_IRQ_NUM   2048
#endif

#ifndef SXE2_VF_NUM
#define SXE2_VF_NUM    256
#endif

#ifndef SXE2_MAX_MACVLANS
#define SXE2_MAX_MACVLANS    16
#endif

#define SXE2_BUF_SIZE_FW_TQ  (8 * 1024)
#define SXE2_BUF_SIZE_FW_RQ  (8 * 1024)

#ifndef SXE2_BUF_SIZE_MBX_TQ
#define SXE2_BUF_SIZE_MBX_TQ (4 * 1024)
#endif

#ifndef SXE2_BUF_SIZE_MBX_RQ
#define SXE2_BUF_SIZE_MBX_RQ (4 * 1024)
#endif

#ifndef SXE2_DFLT_IRQS_MAX_CNT
#define SXE2_DFLT_IRQS_MAX_CNT 64
#endif

#ifndef SXE2_DFLT_IRQS_MIN_CNT
#define SXE2_DFLT_IRQS_MIN_CNT 8

#endif

#ifndef SXE2_VF_RSS_Q_NUM
#define SXE2_VF_RSS_Q_NUM	16
#endif

#ifndef SXE2_IPSEC_RX_SA_DEPTH
#define SXE2_IPSEC_RX_SA_DEPTH 4096
#endif

#ifndef SXE2_IPSEC_RX_DCAM_DEPTH
#define SXE2_IPSEC_RX_DCAM_DEPTH 4096
#endif

#ifndef SXE2_IPSEC_TX_SA_DEPTH
#define SXE2_IPSEC_TX_SA_DEPTH 4096
#endif

#define SXE2_MACSEC_ENABLE

#endif
