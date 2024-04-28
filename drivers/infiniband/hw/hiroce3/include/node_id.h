/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */
#ifndef NODE_ID_H
#define NODE_ID_H

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/** RING NODE ID */
enum {
	NODE_ID_CPI = 0,
	NODE_ID_MQM = 1,
	NODE_ID_QUF = 2,
	NODE_ID_Reserved0 = 3,
	NODE_ID_SMF0 = 4,
	NODE_ID_TILE_F0 = 5,
	NODE_ID_TILE_F1 = 6,
	NODE_ID_SMF1 = 7,
	NODE_ID_DP_NETWORK = 8,
	NODE_ID_CPB = 9,
	NODE_ID_QUL = 10,
	NODE_ID_TS = 11,
	NODE_ID_TILE_L1 = 12,
	NODE_ID_SML1 = 13,
	NODE_ID_SML0 = 14,
	NODE_ID_TILE_L0 = 15,
	NODE_ID_SMF2 = 16,
	NODE_ID_TILE_F2 = 17,
	NODE_ID_TILE_F3 = 18,
	NODE_ID_SMF3 = 19,
	NODE_ID_TILE_L3 = 20,
	NODE_ID_SML3 = 21,
	NODE_ID_SML2 = 22,
	NODE_ID_TILE_L2 = 23,
	NODE_ID_CRYPTO = 24,
	NODE_ID_LCAM = 25,
	NODE_ID_MPU = 26,
	NODE_ID_DP_HOST = 27,
	NODE_ID_UP_HOST = 31  /* Used for API chain function in the CPI */
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* NODE_ID_H */

