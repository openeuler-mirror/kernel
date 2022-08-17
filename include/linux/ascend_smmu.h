/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_ASCEND_SMMU_H
#define __LINUX_ASCEND_SMMU_H

#define INV_REQ			0xff
#define INV_STAGE		0xfe
#define INTERNAL_ERR		0xfd
#define C_BAD_STREAMID		0x02
#define F_STE_FETCH		0x03
#define C_BAD_STE		0x04
#define F_STREAM_DISABLED	0x06
#define C_BAD_SUBSTREAMID	0x08
#define F_CD_FETCH		0x09
#define C_BAD_CD		0x0a
#define F_WALK_EABT		0x0b
#define F_TRANSLATION		0x10
#define F_ADDR_SIZE		0x11
#define F_ACCESS		0x12
#define F_PERMISSION		0x13
#define F_TLB_CONFLICT		0x20
#define F_CFG_CONFLICT		0x21
#define F_VMS_FETCH		0x25

/**
 * struct agent_smmu_atos_data - information required for address translation
 * @sid: stream id
 * @ssid: substream id
 * @flag: Requested input address's attributes
 *  [6]   HTTUI, 0 for HTTU might occur, 1 for HTTU inhibited
 *  [7]   InD, 0 for Data, 1 for Instruction
 *  [8]   RnW, 0 for Write, 1 for Read
 *  [9]   PnU, 0 for Unprivileged, 1 for Privileged
 * @nr: number of addresses
 * @iova: iova addresses to be translated
 * @pa: translated physical addresses
 * @device_id: agent smmu uid
 */
struct agent_smmu_atos_data {
	u32 sid;
	u32 ssid;
	u32 flag;
	int nr;
	dma_addr_t *iova;
	phys_addr_t *pa;
	u64 device_id;
};

extern int agent_smmu_iova_to_phys(struct agent_smmu_atos_data *data, int *succeed);

#endif
