/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_COMPILE_MACRO_H
#define ROCE_COMPILE_MACRO_H

#include "node_id.h"

#ifdef ROCE_LB_MODE1_EN
#define ROCE_LBF_MODE1
#endif

#ifdef ROCE_LB_MODE0_EN
#define ROCE_LBF_MODE0
#endif

#ifdef TBL_ID_ROCE_QDFX_CTR_SM_NODE
#define ROCE_SRQ_QDFX_EN
#endif

/* ******************************************************** */
enum ROCE_LBF_E {
	ROCE_LBF_DIS = 0,
	ROCE_LBF_TYPE1,
	ROCE_LBF_TYPE2,
};

#ifdef ROCE_LB_MODE1_ECO_EN
#define ROCE_LB_XID_MASK 0x1
#else
#define ROCE_LB_XID_MASK 0x3
#endif

#if defined(ROCE_LBF_MODE0) || defined(ROCE_LBF_MODE1)

#ifdef ROCE_LB_MODE1_ECO_EN
#define NODE_SMF_0 NODE_ID_SMF0
#define NODE_SMF_1 NODE_ID_SMF0
#define NODE_SMF_2 NODE_ID_SMF2
#define NODE_SMF_3 NODE_ID_SMF2
#else
#define NODE_SMF_0 NODE_ID_SMF0
#define NODE_SMF_1 NODE_ID_SMF1
#define NODE_SMF_2 NODE_ID_SMF2
#define NODE_SMF_3 NODE_ID_SMF3
#endif /* ROCE_LB_MODE1_ECO_EN */

#define ROCE_LBF_MODE ROCE_LBF_TYPE1
#else
#define NODE_SMF_0 NODE_ID_SMF0
#define NODE_SMF_1 NODE_ID_SMF0
#define NODE_SMF_2 NODE_ID_SMF0
#define NODE_SMF_3 NODE_ID_SMF0

#define ROCE_LBF_MODE ROCE_LBF_DIS
#endif /* defined(ROCE_LBF_MODE0) || defined(ROCE_LBF_MODE1) */

#define ROCE_LBF_INLINE_SMFPG23(idx) ((0 == ((idx) & 0x2)) ? NODE_SMF_2 : NODE_SMF_3)
#define ROCE_LBF_INLINE_SMFPG01(idx) ((0 == ((idx) & 0x2)) ? NODE_SMF_0 : NODE_SMF_1)
#define ROCE_LBF_INLINE_SMFID(idx) ((0 == ((idx) & 0x1)) ? \
	ROCE_LBF_INLINE_SMFPG01(idx) : ROCE_LBF_INLINE_SMFPG23(idx))
/* ******************************************************** */

#define ROCE_FUNC_CHECK(roce_en) ((roce_en) ^ 0x1)

#endif /* ROCE_COMPILE_MACRO_H */
