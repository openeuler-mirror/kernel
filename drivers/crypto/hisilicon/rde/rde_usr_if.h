/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __RDE_USR_IF_H__
#define __RDE_USR_IF_H__

struct hisi_rde_sqe {
	__u64 rsvd0: 16;
	__u64 op_tag: 16;
	__u64 alg_blk_size: 2;
	__u64 cm_type: 1;
	__u64 cm_le: 1;
	__u64 abort: 1;
	__u64 src_nblks: 6;
	__u64 dst_nblks: 5;
	__u64 chk_dst_ref_ctrl: 4;
	__u64 chk_dst_grd_ctrl: 4;
	__u64 op_type: 8;
	__u64 block_size: 16;
	__u64 page_pad_type: 2;
	__u64 dif_type: 1;
	__u64 rsvd1: 3;
	__u64 crciv_sel: 1;
	__u64 crciv_en: 1;
	__u64 status: 8;
	__u64 rsvd2: 10;
	__u64 cm_len: 6;
	__u64 transfer_size: 16;
	__u64 coef_matrix_addr;
	__u64 src_addr;
	__u64 src_tag_addr;
	__u64 dst_addr;
	__u64 dst_tag_addr;
	__u64 dw7;
};

/** @addtogroup RDE_SET_OPT
 *  @brief RDE_SET_OPT is set of flag.
 *  @{
 */
/**
 * @brief RDE algorithm types.
 */
enum {
	MPCC = 0x00, /*!< EC */
	PQ = 0x40, /*!< RAID5/RAID6/FlexEC */
	XOR = 0x60, /*!< XOR */
};
/**
 * @brief RDE buffer access types.
 */
enum {
	PBUF = 0x00, /*!< Direct Access */
	SGL = 0x08, /*!< Scatter Gather List */
	PRP = 0x10, /*!< Physical Region Page List */
	REVD = 0x18, /*!< Reserved */
};
/**
 * @brief RDE Memory saving types.
 */
enum {
	NO_MEM_SAVE = 0x00, /*!< Non-Memory Saving */
	MEM_SAVE = 0x04, /*!< Memory Saving, only support MPCC EC */
};
/**
 * @brief RDE opration types.
 */
enum {
	GEN = 0x00, /*!< Generate */
	VLD = 0x01, /*!< Validate */
	UPD = 0x02, /*!< Update */
	RCT = 0x03, /*!< Reconstruct */
};
/**
 *  @}
 */

/** @addtogroup ACC_CTRL
 *  @brief ACC_CTRL is arguments to acc_set_ctrl().
 *  @{
 */
/**
 * @brief RDE DIF GRD types.
 */
enum {
	NO_GRD = 0, /*!< no GRD domain */
	GRD = 1, /*!< GRD domain without checking */
	GRD_CHECK = 2, /*!< GRD domain with checking */
};
/**
 * @brief RDE DIF REF types.
 */
enum {
	NO_REF = 0, /*!< no REF domain */
	REF = 1, /*!< REF domain without checking */
	REF_CHECK_LBA = 2, /*!< REF domain checking with lab */
	REF_CHECK_PRI = 3, /*!< REF domain checking with private info */
};
/**
 *  @}
 */

/** @addtogroup ACC_SDK_API
 *  @brief ACC_SDK_API is export to users.
 *  @{
 */
/**
 * @brief RDE max numbers of data blocks.
 */
enum {
	MAX_DST_NUM = 0x11, /*!<  destination blocks */
	MAX_SRC_NUM = 0x20, /*!< source blocks */
};
/**
 * @brief RDE IO abort switch.
 */
enum {
	NO_ABT = 0x0, /*!< don't abort the io */
	ABT = 0x1, /*!< abort the io */
};
/**
 * @brief RDE coefficient matrix load enable.
 */
enum {
	NO_CML = 0x0, /*!< don't load matrix */
	CML = 0x1, /*!< load matrix */
};
/**
 * @brief RDE coefficient matrix types.
 */
enum {
	CM_ENCODE = 0x0, /*!< encode type */
	CM_DECODE = 0x1, /*!< decode type */
};
/**
 * @brief RDE algorithms block size.
 */
enum {
	ABS0 = 0x0, /*!< 512 bytes */
	ABS1 = 0x1, /*!< 4K bytes */
};
/**
 * @brief RDE crc iv enable.
 */
enum {
	NO_CRCIV = 0x0, /*!< default IV is 0 */
	CRCIV = 0x1, /*!< IV is register's value */
};
/**
 * @brief RDE crc iv switch.
 */
enum {
	CRCIV0 = 0x0, /*!< select crc16_iv0 of register */
	CRCIV1 = 0x1, /*!< select crc16_iv1 of register */
};
/**
 * @brief RDE DIF types.
 */
enum {
	NO_RDE_DIF = 0x0, /*!< without DIF */
	RDE_DIF = 0x1, /*!< DIF */
};
/**
 * @brief RDE page padding types.
 */
enum {
	NO_PAD = 0, /*!< without padding */
	PRE_PAD = 1, /*!< padding before DIF */
	POST_PAD = 2, /*!< padding after DIF */
};

#endif
