/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __HISI_SDMA_HAL_H__
#define __HISI_SDMA_HAL_H__

#include <linux/bitfield.h>
#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/io.h>

#include "hisi_sdma.h"
#include "sdma_reg.h"

#define RW_R_R			0644
#define SDMA_IRQ_NUM_MAX	512

/**
 * struct hisi_sdma_channel - Information about one channel in the SDMA device
 * @idx: SDMA channel's ID
 * @sq_base: Base address of the CQE queue in the DDR
 * @cq_base: Base address of the SQE queue in the DDR
 * @sync_info_base: Share information for user driver in the DDR
 * @io_base: SDMA channel address
 * @cnt_used: Number of times that the channel is used
 */
struct hisi_sdma_channel {
	u16 idx;
	struct hisi_sdma_device *pdev;

	/* must be page-aligned and continuous physical memory */
	struct hisi_sdma_sq_entry *sq_base;
	struct hisi_sdma_cq_entry *cq_base;
	struct hisi_sdma_queue_info *sync_info_base;

	void __iomem *io_base;
	u16 cnt_used;
};

/**
 * struct hisi_sdma_device - SDMA device structure
 * @idx: SDMA device's ID
 * @nr_channel: Number of channels owned by SDMA devices
 * @nr_channel_used: Number of channels used by SDMA devices
 * @channels: Pointer to the hisi_sdma_channel structure
 * @channel_map: Bitmap indicating the usage of the SDMA channel
 * @io_orig_base: I/O base address after mapping
 * @io_base: io_orig_base + 32 channel address offsets
 * @base_addr: SDMA I/O base phyisical address
 * @name: SDMA device name in the /dev directory
 */
struct hisi_sdma_device {
	u16 idx;
	u16 node_idx;
	u16 nr_channel;
	u16 nr_channel_used;
	spinlock_t channel_lock;
	struct hisi_sdma_channel *channels;
	char name[HISI_SDMA_DEVICE_NAME_MAX];
	DECLARE_BITMAP(channel_map, HISI_SDMA_DEFAULT_CHANNEL_NUM);

	struct platform_device *pdev;
	struct cdev cdev;
	u32 streamid;

	void __iomem *io_orig_base;
	void __iomem *io_base;
	void __iomem *common_base;
	u64 base_addr;
	resource_size_t base_addr_size;
	u64 common_base_addr;
	resource_size_t common_base_addr_size;

	int irq_cnt;
	int base_vir_irq;
	int irq[SDMA_IRQ_NUM_MAX];
};

struct hisi_sdma_core_device {
	u32 sdma_major;
	u32 sdma_device_num;
	struct hisi_sdma_device *sdma_devices[HISI_SDMA_MAX_DEVS];
};

struct hisi_sdma_global_info {
	u32 *share_chns;
	struct hisi_sdma_core_device *core_dev;
	struct ida *fd_ida;
};

void sdma_cdev_init(struct cdev *cdev);
void sdma_info_sync_cdev(struct hisi_sdma_global_info *g_info);

static inline void chn_set_val(struct hisi_sdma_channel *pchan, int reg, u32 val, u32 mask)
{
	u32 reg_val = readl(pchan->io_base + reg);

	reg_val &= ~mask;
	reg_val |= FIELD_PREP(mask, val);
	asm volatile("dsb st" ::: "memory");

	writel(reg_val, pchan->io_base + reg);
}

static inline u32 chn_get_val(struct hisi_sdma_channel *pchan, int reg, u32 mask)
{
	u32 reg_val = readl(pchan->io_base + reg);

	return FIELD_GET(mask, reg_val);
}

static inline void sdma_channel_set_pause(struct hisi_sdma_channel *pchan)
{
	chn_set_val(pchan, HISI_SDMA_CH_TEST_REG, 1, HISI_SDMA_CH_PAUSE_MSK);
}

static inline bool sdma_channel_is_paused(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_STATUS_REG, HISI_SDMA_CHN_FSM_PAUSE_MSK) == 1;
}

static inline bool sdma_channel_is_idle(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_STATUS_REG, HISI_SDMA_CHN_FSM_IDLE_MSK) == 1;
}

static inline bool sdma_channel_is_quiescent(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_STATUS_REG, HISI_SDMA_CHN_FSM_QUIESCENT_MSK) == 1;
}

static inline void sdma_channel_write_reset(struct hisi_sdma_channel *pchan)
{
	chn_set_val(pchan, HISI_SDMA_CH_TEST_REG, 1, HISI_SDMA_CH_RESET_MSK);
}

static inline void sdma_channel_enable(struct hisi_sdma_channel *pchan)
{
	chn_set_val(pchan, HISI_SDMA_CH_CTRL_REG, 1, HISI_SDMA_CH_ENABLE_MSK);
}

static inline void sdma_channel_disable(struct hisi_sdma_channel *pchan)
{
	chn_set_val(pchan, HISI_SDMA_CH_CTRL_REG, 0, HISI_SDMA_CH_ENABLE_MSK);
}

static inline void sdma_channel_set_sq_size(struct hisi_sdma_channel *pchan, u32 size)
{
	union sdmam_ch_regs_sdmam_ch_sq_attr reg_val = {0};

	reg_val.bits.sq_size = size;
	reg_val.bits.sq_shareability = HISI_SDMA_CH_SQ_SHARE_ATTR;
	reg_val.bits.sq_cacheability = HISI_SDMA_CH_SQ_CACHE_ATTR;

	chn_set_val(pchan, HISI_SDMA_CH_SQ_ATTR_REG, reg_val.u32, HISI_SDMA_U32_MSK);
}

static inline void sdma_channel_set_cq_size(struct hisi_sdma_channel *pchan, u32 size)
{
	union sdmam_ch_regs_sdmam_ch_cq_attr reg_val = {0};

	reg_val.bits.cq_size = size;
	reg_val.bits.cq_shareability = HISI_SDMA_CH_CQ_SHARE_ATTR;
	reg_val.bits.cq_cacheability = HISI_SDMA_CH_CQ_CACHE_ATTR;

	chn_set_val(pchan, HISI_SDMA_CH_CQ_ATTR_REG, reg_val.u32, HISI_SDMA_U32_MSK);
}

static inline u32 sdma_channel_get_sq_tail(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_SQTDBR_REG, HISI_SDMA_U32_MSK);
}

static inline void sdma_channel_set_sq_tail(struct hisi_sdma_channel *pchan, u32 val)
{
	chn_set_val(pchan, HISI_SDMA_CH_SQTDBR_REG, val, HISI_SDMA_U32_MSK);
}

static inline u32 sdma_channel_get_sq_head(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_SQHDBR_REG, HISI_SDMA_U32_MSK);
}

static inline void sdma_channel_set_cq_head(struct hisi_sdma_channel *pchan, u32 val)
{
	chn_set_val(pchan, HISI_SDMA_CH_CQHDBR_REG, val, HISI_SDMA_U32_MSK);
}

static inline u32 sdma_channel_get_cq_tail(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_CQTDBR_REG, HISI_SDMA_U32_MSK);
}

static inline u32 sdma_channel_get_cq_head(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_CQHDBR_REG, HISI_SDMA_U32_MSK);
}

static inline void sdma_channel_set_irq_mask(void __iomem *io_addr, u32 val)
{
	writel(val, io_addr + HISI_SDMA_CH_IRQ_CTRL_REG);
}

static inline u32 sdma_channel_get_err_status(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_IRQ_STATUS, HISI_SDMA_CHN_IRQ_STATUS_MSK);
}

static inline void sdma_channel_clear_ioe_status(void __iomem *io_addr)
{
	union sdmam_irq_status reg_val = {0};

	reg_val.bits.ch_ioe_status = 1;
	writel(HISI_SDMA_U32_MSK, io_addr + HISI_SDMA_IRQ_STATUS);
}

static inline u32 sdma_channel_get_cqe_status(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_CQE_STATUS_REG, HISI_SDMA_CHN_CQE_STATUS_MSK);
}

static inline u32 sdma_channel_get_cqe_sqeid(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_CQE_STATUS_REG, HISI_SDMA_CHN_CQE_SQEID_MSK);
}

static inline void sdma_channel_clear_cqe_status(void __iomem *io_addr)
{
	writel(HISI_SDMA_U32_MSK, io_addr + HISI_SDMA_CH_CQE_STATUS_REG);
}

static inline u32 sdma_channel_get_dfx(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_DFX_REG, HISI_SDMA_U32_MSK);
}

static inline void sdma_channel_clr_normal_sqe_cnt(struct hisi_sdma_channel *pchan)
{
	chn_set_val(pchan, HISI_SDMA_CH_DFX_REG, 0, HISI_SDMA_CHN_NORMAL_SQE_CNT_MSK);
}

static inline void sdma_channel_clr_err_sqe_cnt(struct hisi_sdma_channel *pchan)
{
	chn_set_val(pchan, HISI_SDMA_CH_DFX_REG, 0, HISI_SDMA_CHN_ERROR_SQE_CNT_MSK);
}

static inline void sdma_int_converge_dis(void __iomem *common_base)
{
	union sdmam_dfx_feature_en reg_val = {0};

	reg_val.u32 = readl(common_base + HISI_SDMA_DFX_FEATURE_EN);
	reg_val.bits.ch_int_converge_en = 1;
	reg_val.bits.ch_int_group_converge_en = 0;
	writel(reg_val.u32, common_base + HISI_SDMA_DFX_FEATURE_EN);
}

static inline void sdma_common_mpamid_cfg(void __iomem *common_base, struct hisi_sdma_mpamcfg *cfg)
{
	union sdmam_common_regs_dma_mpamid_cfg reg_val;

	reg_val.u32 = readl(common_base + HISI_SDMA_DMA_MPAMID_CFG);
	reg_val.bits.mpam_id_replace_en = cfg->mpamid_replace_en;
	reg_val.bits.replace_mpam_partid = cfg->partid;
	reg_val.bits.replace_mpam_pmg = cfg->pmg;
	reg_val.bits.replace_qos = cfg->qos;
	writel(reg_val.u32, common_base + HISI_SDMA_DMA_MPAMID_CFG);
}

static inline u32 sdma_channel_get_normal_sqe_cnt(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_DFX_REG, HISI_SDMA_CHN_NORMAL_SQE_CNT_MSK);
}

static inline u32 sdma_channel_get_err_sqe_cnt(struct hisi_sdma_channel *pchan)
{
	return chn_get_val(pchan, HISI_SDMA_CH_DFX_REG, HISI_SDMA_CHN_ERROR_SQE_CNT_MSK);
}

#endif
