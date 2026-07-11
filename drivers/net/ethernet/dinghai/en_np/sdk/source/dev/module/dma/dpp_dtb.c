// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/io.h>
#include "zxic_common.h"
#include "dpp_dev.h"
#include "dpp_type_api.h"
#include "dpp_dtb_cfg.h"
#include "dpp_dtb.h"
#include "dpp_dtb_table.h"
#include "dpp_hash.h"
#include "dpp_dtb_reg.h"
#include "dpp_reg_api.h"
#include "dpp_reg_info.h"
#include "dpp_se_api.h"

#if ZXIC_REAL("DTB")

char *g_dpp_dtb_name[] = {
	"DOWN TAB",
	"UP TAB",
};

struct dpp_dtb_mgr_t *p_dpp_dtb_mgr[DPP_PCIE_SLOT_MAX][DPP_DEV_CHANNEL_MAX] = { { NULL } };

static u32 g_dtb_down_overtime = 2 * 1000;
static u32 g_dtb_dump_overtime = 5 * 1000 * 1000;

static u32 g_dtb_debug_fun_en;
static u32 g_dtb_print_en;
static u32 g_dtb_soft_perf_test;
static u32 g_dtb_hardware_perf_test;

static u32 g_dtb_func_switch_en = 1;
u32 dtb_table_function_switch_get(void)
{
	return g_dtb_func_switch_en;
}

u32 dtb_table_function_switch_enable(void)
{
	g_dtb_func_switch_en = 1;
	return 0;
}
EXPORT_SYMBOL(dtb_table_function_switch_enable);

u32 dtb_table_function_switch_disable(void)
{
	g_dtb_func_switch_en = 0;
	return 0;
}
EXPORT_SYMBOL(dtb_table_function_switch_disable);

u32 dpp_dtb_debug_fun_enable(void)
{
	g_dtb_debug_fun_en = 1;
	return 0;
}

u32 dpp_dtb_debug_fun_disable(void)
{
	g_dtb_debug_fun_en = 0;
	return 0;
}

u32 dpp_dtb_debug_fun_get(void)
{
	return g_dtb_debug_fun_en;
}

u32 dpp_dtb_prt_enable(void)
{
	g_dtb_print_en = 1;
	return 0;
}

u32 dpp_dtb_prt_disable(void)
{
	g_dtb_print_en = 0;
	return 0;
}

u32 dpp_dtb_prt_get(void)
{
	return g_dtb_print_en;
}

u32 dpp_dtb_soft_perf_test_set(u32 value)
{
	g_dtb_soft_perf_test = value;
	return 0;
}

u32 dpp_dtb_soft_perf_test_get(void)
{
	return g_dtb_soft_perf_test;
}

u32 dpp_dtb_hardware_perf_test_set(u32 value)
{
	g_dtb_hardware_perf_test = value;
	return 0;
}

u32 dpp_dtb_hardware_perf_test_get(void)
{
	return g_dtb_hardware_perf_test;
}

u32 dpp_dtb_down_table_overtime_set(u32 times_s)
{
	g_dtb_down_overtime = times_s;
	return 0;
}

u32 dpp_dtb_down_table_overtime_get(void)
{
	return g_dtb_down_overtime;
}

u32 dpp_dtb_dump_table_overtime_set(u32 times_s)
{
	g_dtb_dump_overtime = times_s;
	return 0;
}

u32 dpp_dtb_dump_table_overtime_get(void)
{
	return g_dtb_dump_overtime;
}

#if ZXIC_REAL("MGR")
u32 dpp_dtb_mgr_create(u32 slot_id, u32 dev_id)
{
	ZXIC_COMM_CHECK_INDEX(slot_id, 0, DPP_PCIE_SLOT_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	if (p_dpp_dtb_mgr[slot_id][dev_id] != ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id,
					  "slot %d ErrorCode[0x%x]: DTB Manager is not exist!!!\n",
					  slot_id, DPP_RC_DTB_MGR_NOT_EXIST);
		return DPP_RC_DTB_MGR_EXIST;
	}

	p_dpp_dtb_mgr[slot_id][dev_id] =
		(struct dpp_dtb_mgr_t *)ZXIC_COMM_MALLOC(sizeof(struct dpp_dtb_mgr_t));
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_dpp_dtb_mgr[slot_id][dev_id]);

	ZXIC_COMM_MEMSET(p_dpp_dtb_mgr[slot_id][dev_id], 0, sizeof(struct dpp_dtb_mgr_t));

	ZXIC_COMM_TRACE_NOTICE("dpp dtb_mgr_create:slot %d dev %d done!!!", slot_id, dev_id);

	return DPP_OK;
}
u32 dpp_dtb_mgr_destory_all(void)
{
	u32 slot_id = 0;
	u32 dev_id = 0;

	for (slot_id = 0; slot_id < DPP_DEV_SLOT_MAX; slot_id++) {
		for (dev_id = 0; dev_id < DPP_DEV_CHANNEL_MAX; dev_id++)
			dpp_dtb_mgr_destory(slot_id, dev_id);
	}

	return DPP_OK;
}

u32 dpp_dtb_mgr_destory(u32 slot_id, u32 dev_id)
{
	ZXIC_COMM_CHECK_INDEX(slot_id, 0, DPP_PCIE_SLOT_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	if (p_dpp_dtb_mgr[slot_id][dev_id] != ZXIC_NULL) {
		ZXIC_COMM_FREE(p_dpp_dtb_mgr[slot_id][dev_id]);
		p_dpp_dtb_mgr[slot_id][dev_id] = ZXIC_NULL;
		ZXIC_COMM_TRACE_NOTICE("dpp dtb_mgr_destory:slot %d dev %d done!!!", slot_id,
				       dev_id);
	}

	return DPP_OK;
}
u32 dpp_dtb_mgr_reset(u32 slot_id, u32 dev_id)
{
	ZXIC_COMM_CHECK_INDEX(slot_id, 0, DPP_PCIE_SLOT_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	if (p_dpp_dtb_mgr[slot_id][dev_id] == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id,
					  "slot %d ErrorCode[0x%x]: dtb manager is not exist!!!\n",
					  slot_id, DPP_RC_DTB_MGR_NOT_EXIST);
		return DPP_RC_DTB_MGR_NOT_EXIST;
	}

	ZXIC_COMM_MEMSET(p_dpp_dtb_mgr[slot_id][dev_id], 0, sizeof(struct dpp_dtb_mgr_t));

	return DPP_OK;
}
struct dpp_dtb_mgr_t *dpp_dtb_mgr_get(u32 slot_id, u32 dev_id)
{
	if ((slot_id >= DPP_PCIE_SLOT_MAX) || (dev_id >= DPP_DEV_CHANNEL_MAX))
		return ZXIC_NULL;
	return p_dpp_dtb_mgr[slot_id][dev_id];
}
#endif

#if ZXIC_REAL("QUEUE_ADDR")
u32 dpp_dtb_down_table_elemet_addr_get(struct dpp_dev_t *dev, u32 queue_id, u32 element_id,
				       u32 *p_element_start_addr_h, u32 *p_element_start_addr_l,
				       u32 *p_element_table_addr_h, u32 *p_element_table_addr_l)
{
	u32 addr_h = 0;
	u32 addr_l = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), element_id, 0,
					    DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	addr_h = (DPP_DTB_TAB_DOWN_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						element_id) >>
		  32) &
		 0xffffffff;
	addr_l = DPP_DTB_TAB_DOWN_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
					       element_id) &
		 0xffffffff;

	*p_element_start_addr_h = addr_h;
	*p_element_start_addr_l = addr_l;

	addr_h = ((DPP_DTB_TAB_DOWN_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						 element_id) +
		   DPP_DTB_ITEM_ACK_SIZE) >>
		  32) &
		 0xffffffff;
	addr_l = (DPP_DTB_TAB_DOWN_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						element_id) +
		  DPP_DTB_ITEM_ACK_SIZE) &
		 0xffffffff;

	*p_element_table_addr_h = addr_h;
	*p_element_table_addr_l = addr_l;

	return DPP_OK;
}
u32 dpp_dtb_dump_table_elemet_addr_get(struct dpp_dev_t *dev, u32 queue_id, u32 element_id,
				       u32 *p_element_start_addr_h, u32 *p_element_start_addr_l,
				       u32 *p_element_dump_addr_h, u32 *p_element_dump_addr_l,
				       u32 *p_element_table_info_addr_h,
				       u32 *p_element_table_info_addr_l)
{
	u32 rc = 0;
	u32 addr_h = 0;
	u32 addr_l = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), element_id, 0,
					    DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	addr_h = ((DPP_DTB_TAB_UP_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
					       element_id)) >>
		  32) &
		 0xffffffff;
	addr_l = (DPP_DTB_TAB_UP_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
					      element_id)) &
		 0xffffffff;

	*p_element_start_addr_h = addr_h;
	*p_element_start_addr_l = addr_l;

	addr_h = ((DPP_DTB_TAB_UP_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
					       element_id) +
		   DPP_DTB_ITEM_ACK_SIZE) >>
		  32) &
		 0xffffffff;
	addr_l = (DPP_DTB_TAB_UP_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
					      element_id) +
		  DPP_DTB_ITEM_ACK_SIZE) &
		 0xffffffff;

	*p_element_dump_addr_h = addr_h;
	*p_element_dump_addr_l = addr_l;

	rc = dpp_dtb_tab_up_item_addr_get(dev, queue_id, element_id, p_element_table_info_addr_h,
					  p_element_table_info_addr_l);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_tab_up_item_addr_get");

	return DPP_OK;
}

#endif

#if ZXIC_REAL("MEM_RW")
u32 dpp_dtb_wr32(struct dpp_dev_t *dev, ZXIC_ADDR_T addr, u32 data)
{
	u32 value = data;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), data, 0, ZXIC_UINT32_MAX);

	if (!zxic_comm_is_big_endian())
		value = ZXIC_COMM_CONVERT32(value);

	writel(value, (void __iomem *)(unsigned long)addr);

	return DPP_OK;
}
u32 dpp_dtb_rd32(struct dpp_dev_t *dev, ZXIC_ADDR_T addr, u32 *p_data)
{
	u32 value = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	value = readl((void __iomem *)(unsigned long)addr);

	if (!zxic_comm_is_big_endian())
		value = ZXIC_COMM_CONVERT32(value);

	*p_data = value;

	return DPP_OK;
}
#endif

#if ZXIC_REAL("ACK_RW")
u32 dpp_dtb_item_ack_rd(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 pos,
			u32 *p_data)
{
	u32 rc = 0;
	ZXIC_ADDR_T addr = 0;
	u32 val = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), dir_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), pos, 0, 3);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (dir_flag == DPP_DTB_DIR_UP_TYPE) {
		addr = DPP_DTB_TAB_UP_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						   index) +
		       pos * 4;
	} else {
		addr = DPP_DTB_TAB_DOWN_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						     index) +
		       pos * 4;
	}

	rc = dpp_dtb_rd32(dev, addr, &val);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_rd32");

	*p_data = val;

	return DPP_OK;
}
u32 dpp_dtb_item_ack_wr(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 pos,
			u32 data)
{
	u32 rc = 0;
	ZXIC_ADDR_T addr = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), dir_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), pos, 0, 3);

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (dir_flag == DPP_DTB_DIR_UP_TYPE) {
		addr = DPP_DTB_TAB_UP_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						   index) +
		       pos * 4;
	} else {
		addr = DPP_DTB_TAB_DOWN_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						     index) +
		       pos * 4;
	}

	rc = dpp_dtb_wr32(dev, addr, data);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_wr32");

	return DPP_OK;
}
u32 dpp_dtb_item_ack_prt(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index)
{
	u32 rc = 0;
	u32 i = 0;
	u32 ack_data[4] = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), dir_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	for (i = 0; i < DPP_DTB_ITEM_ACK_SIZE / 4; i++) {
		rc = dpp_dtb_item_ack_rd(dev, queue_id, dir_flag, index, i, ack_data + i);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_item_ack_rd");
	}

	ZXIC_COMM_PRINT("\n=====> [%s] BD INFO:", g_dpp_dtb_name[dir_flag]);
	ZXIC_COMM_PRINT("\n[ index : %u] : 0x%08x 0x%08x 0x%08x 0x%08x\n", index, ack_data[0],
			ack_data[1], ack_data[2], ack_data[3]);

	return DPP_OK;
}
u32 dpp_dtb_item_buff_prt(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 len)
{
	u32 rc = 0;
	u32 i = 0;
	u32 j = 0;
	u32 *p_item_buff = ZXIC_NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), dir_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	p_item_buff = ZXIC_COMM_MALLOC((len * sizeof(u32)) % ZXIC_COMM_WORD32_MASK);
	if (p_item_buff == ZXIC_NULL) {
		ZXIC_COMM_PRINT("Alloc dtb item buffer failed!!!\n");
		return DPP_RC_DTB_MEMORY_ALLOC_ERR;
	}

	ZXIC_COMM_MEMSET(p_item_buff, 0, len * sizeof(u32));

	rc = dpp_dtb_item_buff_rd(dev, queue_id, dir_flag, index, 0, len, p_item_buff);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE(DEV_ID(dev), rc, "dpp_dtb_item_buff_rd", p_item_buff);

	ZXIC_COMM_PRINT("\n=====> [%s] BUFF INFO:", g_dpp_dtb_name[dir_flag]);
	for (i = 0, j = 0; i < len; i++, j++) {
		if (j % 4 == 0)
			ZXIC_COMM_PRINT("\n0x%08x ", (*(p_item_buff + i)));
		else
			ZXIC_COMM_PRINT("0x%08x ", (*(p_item_buff + i)));
	}
	ZXIC_COMM_PRINT("\n");

	ZXIC_COMM_FREE(p_item_buff);

	return DPP_OK;
}

#endif

#if ZXIC_REAL("BUFF_RW")
u32 dpp_dtb_item_buff_rd(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 pos,
			 u32 len, u32 *p_data)
{
	ZXIC_ADDR_T addr = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), dir_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), pos, 0, 3);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (dir_flag == DPP_DTB_DIR_UP_TYPE) {
		if (DPP_DTB_TAB_UP_USER_PHY_ADDR_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
							  index) == DPP_DTB_TAB_UP_USER_ADDR_TYPE) {
			addr = DPP_DTB_TAB_UP_USER_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
								queue_id, index) +
			       pos * 4;
			p_dpp_dtb_mgr[DEV_PCIE_SLOT(dev)][DEV_ID(dev)]
				->queue_info[queue_id]
				.tab_up.user_addr[index]
				.user_flag = 0;
		} else {
			addr = DPP_DTB_TAB_UP_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
							   queue_id, index) +
			       DPP_DTB_ITEM_ACK_SIZE + pos * 4;
		}
	} else {
		addr = DPP_DTB_TAB_DOWN_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						     index) +
		       DPP_DTB_ITEM_ACK_SIZE + pos * 4;
	}

	ZXIC_COMM_MEMCPY_S(p_data, len * 4, (u8 *)(addr), len * 4);

	zxic_comm_swap((u8 *)p_data, len * 4);

	return DPP_OK;
}
u32 dpp_dtb_item_buff_wr(struct dpp_dev_t *dev, u32 queue_id, u32 dir_flag, u32 index, u32 pos,
			 u32 len, u32 *p_data)
{
	ZXIC_ADDR_T addr = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), dir_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), pos, 0, 3);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (dir_flag == DPP_DTB_DIR_UP_TYPE) {
		addr = DPP_DTB_TAB_UP_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						   index) +
		       DPP_DTB_ITEM_ACK_SIZE + pos * 4;
	} else {
		addr = DPP_DTB_TAB_DOWN_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						     index) +
		       DPP_DTB_ITEM_ACK_SIZE + pos * 4;
	}

	ZXIC_COMM_MEMCPY_S((u8 *)(addr), len * 4, p_data, len * 4);

	return DPP_OK;
}
#endif

#if ZXIC_REAL("API")
#if ZXIC_REAL("TAB_DOWN")

/** dtb info print*/
u32 dpp_dtb_info_print(struct dpp_dev_t *dev, u32 queue_id, u32 item_index,
		       struct dpp_dtb_queue_item_info_t *item_info)
{
	ZXIC_ADDR_T element_start_addr = 0;
	ZXIC_ADDR_T ack_start_addr = 0;
	ZXIC_ADDR_T data_addr = 0;
	u32 i = 0;

	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_PRINT("dpp dtb_info_print: slot %d queue: %d, element:%d,  %s table info is:\n",
			DEV_PCIE_SLOT(dev), queue_id, item_index,
			(item_info->cmd_type) ? "up" : "down");
	ZXIC_COMM_PRINT("cmd_vld    : %d\n", item_info->cmd_vld);
	ZXIC_COMM_PRINT("cmd_type   : %s\n", (item_info->cmd_type) ? "up" : "down");
	ZXIC_COMM_PRINT("int_en     : %d\n", item_info->int_en);
	ZXIC_COMM_PRINT("data_len   : %d\n", item_info->data_len);
	ZXIC_COMM_PRINT("data_hddr  : 0x%08x\n", item_info->data_hddr);
	ZXIC_COMM_PRINT("data_laddr : 0x%08x\n", item_info->data_laddr);

	if (item_info->cmd_type == DPP_DTB_DIR_UP_TYPE) {
		if (DPP_DTB_TAB_UP_USER_PHY_ADDR_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
							  item_index) ==
		    DPP_DTB_TAB_UP_USER_ADDR_TYPE) {
			ack_start_addr = DPP_DTB_TAB_UP_USER_VIR_ADDR_GET(
				DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id, item_index);
		}
		ack_start_addr = DPP_DTB_TAB_UP_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
							     queue_id, item_index);
		element_start_addr = DPP_DTB_TAB_UP_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
								 queue_id, item_index) +
				     DPP_DTB_ITEM_ACK_SIZE;
	} else {
		ack_start_addr = DPP_DTB_TAB_DOWN_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
							       queue_id, item_index);
		element_start_addr = DPP_DTB_TAB_DOWN_VIR_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
								   queue_id, item_index) +
				     DPP_DTB_ITEM_ACK_SIZE;
	}
	ZXIC_COMM_PRINT("dtb data:\n");

	ZXIC_COMM_PRINT("ack info: 0x%08x 0x%08x 0x%08x 0x%08x\n",
			ZXIC_COMM_CONVERT32(*((u32 *)(ack_start_addr + 4 * 0))),
			ZXIC_COMM_CONVERT32(*((u32 *)(ack_start_addr + 4 * 1))),
			ZXIC_COMM_CONVERT32(*((u32 *)(ack_start_addr + 4 * 2))),
			ZXIC_COMM_CONVERT32(*((u32 *)(ack_start_addr + 4 * 3))));

	for (i = 0; i < item_info->data_len; i++) {
		data_addr = element_start_addr + 16 * i;

		ZXIC_COMM_PRINT("row_%d:", i);
		ZXIC_COMM_PRINT("0x%08x 0x%08x 0x%08x 0x%08x ",
				ZXIC_COMM_CONVERT32(*((u32 *)(data_addr + 4 * 0))),
				ZXIC_COMM_CONVERT32(*((u32 *)(data_addr + 4 * 1))),
				ZXIC_COMM_CONVERT32(*((u32 *)(data_addr + 4 * 2))),
				ZXIC_COMM_CONVERT32(*((u32 *)(data_addr + 4 * 3))));

		ZXIC_COMM_PRINT("\n");
	}

	ZXIC_COMM_PRINT("dpp dtb info print end.\n");
	return DPP_OK;
}
u32 dpp_dtb_tab_down_info_set(struct dpp_dev_t *dev, u32 queue_id, u32 int_flag, u32 data_len,
			      u32 *p_data, u32 *p_item_index)
{
	u32 rc = 0;
	u32 i = 0;
	u32 queue_en = 0;
	u32 ack_vale = 0;
	u32 item_index = 0;
	u32 unused_item_num = 0;
	struct dpp_dtb_queue_item_info_t item_info = { 0 };
	struct zxic_mutex_t *p_mutex = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), int_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), data_len, 4, 0xffc);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_item_index);

	rc = dpp_dev_dtb_opr_mutex_get(dev, DPP_DEV_MUTEX_T_DTB, queue_id, &p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dev_dtb_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	rc = dpp_dtb_queue_enable_get(dev, queue_id, &queue_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_queue_enable_get",
						p_mutex);
	if (!queue_en) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "the slot %d queue %d is not enable!",
					  DEV_PCIE_SLOT(dev), queue_id);
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_QUEUE_NOT_ENABLE;
	}

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (data_len % 4 != 0) {
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

		return DPP_RC_DTB_PARA_INVALID;
	}

	rc = dpp_dtb_queue_unused_item_num_get(dev, queue_id, &unused_item_num);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
						"dpp_dtb_queue_unused_item_num_get", p_mutex);

	if (unused_item_num == 0) {
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_QUEUE_ITEM_HW_EMPTY;
	}

	for (i = 0; i < DPP_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		item_index =
			DPP_DTB_TAB_DOWN_WR_INDEX_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) %
			DPP_DTB_QUEUE_ITEM_NUM_MAX;

		rc = dpp_dtb_item_ack_rd(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, item_index, 0,
					 &ack_vale);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_item_ack_rd",
							p_mutex);

		DPP_DTB_TAB_DOWN_WR_INDEX_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id)
		++;

		if ((ack_vale >> 8) == DPP_DTB_TAB_ACK_UNUSED_MASK)
			break;
	}

	if (i == DPP_DTB_QUEUE_ITEM_NUM_MAX) {
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_QUEUE_ITEM_SW_EMPTY;
	}

	rc = dpp_dtb_item_buff_wr(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, item_index, 0, data_len,
				  p_data);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_item_buff_wr", p_mutex);

	rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, item_index, 0,
				 DPP_DTB_TAB_ACK_IS_USING_MASK);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr", p_mutex);

	item_info.cmd_vld = 1;
	item_info.cmd_type = DPP_DTB_DIR_DOWN_TYPE;
	item_info.int_en = int_flag;
	item_info.data_len = data_len / 4;
	item_info.data_hddr = ((DPP_DTB_TAB_DOWN_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
							      queue_id, item_index) >>
				4) >>
			       32) &
			      0xffffffff;
	item_info.data_laddr = (DPP_DTB_TAB_DOWN_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
							      queue_id, item_index) >>
				4) &
			       0xffffffff;

	if (item_info.data_len < DPP_DTB_LEN_MIN || item_info.data_len > DPP_DTB_DOWN_LEN) {
		ZXIC_COMM_PRINT("DTB DATA_LEN :0x%08x.\n", item_info.data_len);
		rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, item_index, 0,
					 DPP_DTB_TAB_ACK_UNUSED_MASK);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_PARA_INVALID;
	}

	if (dpp_dtb_prt_get())
		dpp_dtb_info_print(dev, queue_id, item_index, &item_info);

	if (dpp_dtb_soft_perf_test_get()) {
		*p_item_index = item_index;
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_OK;
	}

	rc = dpp_dtb_queue_item_info_set(dev, queue_id, &item_info);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_queue_item_info_set",
						p_mutex);
	*p_item_index = item_index;

	rc = zxic_comm_mutex_unlock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
u32 dpp_dtb_down_table_element_info_prt(struct dpp_dev_t *dev, u32 queue_id, u32 element_id)
{
	u32 rc = 0;

	u32 element_start_addr_h = 0;
	u32 element_start_addr_l = 0;
	u32 element_table_addr_h = 0;
	u32 element_table_addr_l = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), element_id, 0,
					    DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	rc = dpp_dtb_down_table_elemet_addr_get(dev, queue_id, element_id, &element_start_addr_h,
						&element_start_addr_l, &element_table_addr_h,
						&element_table_addr_l);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_elemet_addr_get");

	ZXIC_COMM_DBGCNT32_PRINT("slot_id", DEV_PCIE_SLOT(dev));
	ZXIC_COMM_DBGCNT32_PRINT("queue_id", queue_id);
	ZXIC_COMM_DBGCNT32_PRINT("element_id", element_id);
	ZXIC_COMM_DBGCNT32_PRINT("element_start_addr_h", element_start_addr_h);
	ZXIC_COMM_DBGCNT32_PRINT("element_start_addr_l", element_start_addr_l);
	ZXIC_COMM_DBGCNT32_PRINT("element_table_addr_h", element_table_addr_h);
	ZXIC_COMM_DBGCNT32_PRINT("element_table_addr_l", element_table_addr_l);

	rc = dpp_dtb_item_ack_prt(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, element_id);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_item_ack_prt");

	rc = dpp_dtb_item_buff_prt(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, element_id, 24);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_item_buff_prt");

	return DPP_OK;
}
u32 dpp_dtb_tab_down_success_status_check(struct dpp_dev_t *dev, u32 queue_id, u32 element_id)
{
	u32 rc = 0;
	u32 rd_cnt = 0;
	u32 ack_value = 0;
	u32 success_flag = 0;
	u32 dtb_interrupt_status = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), element_id, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	dtb_interrupt_status = dpp_dtb_interrupt_status_get();

	if (dpp_dtb_soft_perf_test_get() || dpp_dtb_hardware_perf_test_get()) {
		rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, element_id, 0,
					 DPP_DTB_TAB_ACK_UNUSED_MASK);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");
		return rc;
	}

	if (dpp_dtb_debug_fun_get())
		return DPP_OK;

	while (!success_flag) {
		rc = dpp_dtb_item_ack_rd(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, element_id, 0,
					 &ack_value);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_rd");

		ZXIC_COMM_TRACE_DEBUG("dpp_dtb_item_ack_rd ack_value:0x%08x\n", ack_value);

		if (((ack_value >> 8) & 0xffffff) == DPP_DTB_TAB_DOWN_ACK_VLD_MASK) {
			success_flag = 1;
			break;
		}

		if (rd_cnt > dpp_dtb_down_table_overtime_get()) {
			ZXIC_COMM_TRACE_ERROR(
				"Error!!! dpp dtb down slot [%d] vport [0x%x] queue [%d] item [%d] ack success is overtime!\n",
				DEV_PCIE_SLOT(dev), DEV_PCIE_VPORT(dev), queue_id, element_id);

			ZXIC_COMM_PRINT("dtb down table info\n");

			rc = dpp_dtb_down_table_element_info_prt(dev, queue_id, element_id);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc,
					       "dpp_dtb_down_table_element_info_prt");

			rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, element_id,
						 0, DPP_DTB_TAB_ACK_UNUSED_MASK);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");

			ZXIC_COMM_PRINT("dtb reg info\n");

			rc = diag_dpp_dtb_axi_last_operate_info_prt(dev);
			ZXIC_COMM_CHECK_DEV_RC(0, rc, "diag_dpp_dtb_axi_last_operate_info_prt");

			rc = diag_dpp_dtb_channels_state_info_prt(dev);
			ZXIC_COMM_CHECK_DEV_RC(0, rc, "diag_dpp_dtb_channels_state_info_prt");

			rc = diag_dpp_dtb_channels_axi_resp_err_cnt_prt(dev);
			ZXIC_COMM_CHECK_DEV_RC(0, rc, "diag_dpp_dtb_channels_axi_resp_err_cnt_prt");

			return DPP_RC_DTB_OVER_TIME;
		}

		rd_cnt++;
		zxic_comm_udelay(1);
	}

	if (dtb_interrupt_status) {
		rc = dpp_dtb_finish_interrupt_event_state_clr(dev, queue_id);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc,
						 "dpp_dtb_finish_interrupt_event_state_clr");
	}

	if ((ack_value & 0xff) != DPP_DTB_TAB_ACK_SUCCESS_MASK) {
		rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, element_id, 0,
					 DPP_DTB_TAB_ACK_UNUSED_MASK);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");
		return ack_value & 0xff;
	}

	rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, element_id, 0,
				 DPP_DTB_TAB_ACK_UNUSED_MASK);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");

	return rc;
}

#endif
#if ZXIC_REAL("TAB_UP")
u32 dpp_dtb_tab_up_free_item_get(struct dpp_dev_t *dev, u32 queue_id, u32 *p_item_index)
{
	u32 rc = 0;
	u32 i = 0;
	u32 ack_vale = 0;
	u32 item_index = 0;
	u32 unused_item_num = 0;
	struct zxic_mutex_t *p_mutex = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_item_index);

	rc = dpp_dev_dtb_opr_mutex_get(dev, DPP_DEV_MUTEX_T_DTB, queue_id, &p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dev_dtb_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	rc = dpp_dtb_queue_unused_item_num_get(dev, queue_id, &unused_item_num);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc,
						"dpp_dtb_queue_unused_item_num_get", p_mutex);

	if (unused_item_num == 0) {
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_QUEUE_ITEM_HW_EMPTY;
	}

	for (i = 0; i < DPP_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		item_index =
			DPP_DTB_TAB_UP_WR_INDEX_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) %
			DPP_DTB_QUEUE_ITEM_NUM_MAX;

		rc = dpp_dtb_item_ack_rd(dev, queue_id, DPP_DTB_DIR_UP_TYPE, item_index, 0,
					 &ack_vale);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_item_ack_rd",
							p_mutex);

		DPP_DTB_TAB_UP_WR_INDEX_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id)
		++;

		if ((ack_vale >> 8) == DPP_DTB_TAB_ACK_UNUSED_MASK)
			break;
	}

	if (i == DPP_DTB_QUEUE_ITEM_NUM_MAX) {
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_QUEUE_ITEM_SW_EMPTY;
	}

	rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_UP_TYPE, item_index, 0,
				 DPP_DTB_TAB_ACK_IS_USING_MASK);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_item_buff_wr", p_mutex);

	*p_item_index = item_index;

	rc = zxic_comm_mutex_unlock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
u32 dpp_dtb_tab_up_item_addr_get(struct dpp_dev_t *dev, u32 queue_id, u32 item_index,
				 u32 *p_phy_haddr, u32 *p_phy_laddr)
{
	ZXIC_ADDR_T addr = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), item_index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_phy_haddr);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_phy_laddr);

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (DPP_DTB_TAB_UP_USER_PHY_ADDR_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						  item_index) == DPP_DTB_TAB_UP_USER_ADDR_TYPE) {
		addr = DPP_DTB_TAB_UP_USER_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
							item_index);
	} else {
		addr = DPP_DTB_TAB_UP_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						   item_index) +
		       DPP_DTB_ITEM_ACK_SIZE;
	}

	// addr = addr >> 4;

	*p_phy_haddr = (addr >> 32) & 0xffffffff;
	*p_phy_laddr = addr & 0xffffffff;

	return DPP_OK;
}
u32 dpp_dtb_tab_up_item_offset_addr_get(struct dpp_dev_t *dev, u32 queue_id, u32 item_index,
					u32 addr_offset, u32 *p_phy_haddr, u32 *p_phy_laddr)
{
	ZXIC_ADDR_T addr = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), item_index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_phy_haddr);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_phy_laddr);

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (DPP_DTB_TAB_UP_USER_PHY_ADDR_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						  item_index) == DPP_DTB_TAB_UP_USER_ADDR_TYPE) {
		addr = DPP_DTB_TAB_UP_USER_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
							item_index);
	} else {
		addr = DPP_DTB_TAB_UP_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id,
						   item_index) +
		       DPP_DTB_ITEM_ACK_SIZE;
	}

	addr = addr + addr_offset;

	*p_phy_haddr = (addr >> 32) & 0xffffffff;
	*p_phy_laddr = addr & 0xffffffff;

	return DPP_OK;
}
u32 dpp_dtb_tab_up_item_user_addr_set(struct dpp_dev_t *dev, u32 queue_id, u32 item_index,
				      ZXIC_ADDR_T phy_addr, ZXIC_ADDR_T vir_addr)
{
	struct dpp_dtb_mgr_t *p_dtb_mgr = ZXIC_NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), item_index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	p_dtb_mgr = dpp_dtb_mgr_get(DEV_PCIE_SLOT(dev), DEV_ID(dev));
	if (p_dtb_mgr == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "slot %d ErrorCode[0x%x]: DTB Manager is not exist!!!\n",
					  DEV_PCIE_SLOT(dev), DPP_RC_DTB_MGR_NOT_EXIST);
		return DPP_RC_DTB_MGR_NOT_EXIST;
	}

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	p_dtb_mgr->queue_info[queue_id].tab_up.user_addr[item_index].phy_addr = phy_addr;
	p_dtb_mgr->queue_info[queue_id].tab_up.user_addr[item_index].vir_addr = vir_addr;
	p_dtb_mgr->queue_info[queue_id].tab_up.user_addr[item_index].user_flag =
		DPP_DTB_TAB_UP_USER_ADDR_TYPE;

	return DPP_OK;
}
u32 dpp_dtb_tab_up_item_user_addr_clr(struct dpp_dev_t *dev, u32 queue_id, u32 item_index)
{
	struct dpp_dtb_mgr_t *p_dtb_mgr = ZXIC_NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), item_index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	p_dtb_mgr = dpp_dtb_mgr_get(DEV_PCIE_SLOT(dev), DEV_ID(dev));
	if (p_dtb_mgr == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "slot %d ErrorCode[0x%x]: DTB Manager is not exist!!!\n",
					  DEV_PCIE_SLOT(dev), DPP_RC_DTB_MGR_NOT_EXIST);
		return DPP_RC_DTB_MGR_NOT_EXIST;
	}

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	p_dtb_mgr->queue_info[queue_id].tab_up.user_addr[item_index].phy_addr = 0;
	p_dtb_mgr->queue_info[queue_id].tab_up.user_addr[item_index].vir_addr = 0;
	p_dtb_mgr->queue_info[queue_id].tab_up.user_addr[item_index].user_flag =
		DPP_DTB_TAB_UP_NOUSER_ADDR_TYPE;

	return DPP_OK;
}
u32 dpp_dtb_tab_up_info_set(struct dpp_dev_t *dev, u32 queue_id, u32 item_index, u32 int_flag,
			    u32 data_len, u32 desc_len, u32 *p_desc_data)
{
	u32 rc = 0;
	u32 queue_en = 0;
	struct dpp_dtb_queue_item_info_t item_info = { 0 };
	struct zxic_mutex_t *p_mutex = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), item_index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), desc_len, 0, 0x400);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), int_flag, 0, 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_desc_data);

	rc = dpp_dev_dtb_opr_mutex_get(dev, DPP_DEV_MUTEX_T_DTB, queue_id, &p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dev_dtb_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_lock");

	rc = dpp_dtb_queue_enable_get(dev, queue_id, &queue_en);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_queue_enable_get",
						p_mutex);
	if (!queue_en) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "the slot %d queue %d is not enable!",
					  DEV_PCIE_SLOT(dev), queue_id);
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "the queue %d is not enable!", queue_id);
		return DPP_RC_DTB_QUEUE_NOT_ENABLE;
	}

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (desc_len % 4 != 0) {
		rc = zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

		return DPP_RC_DTB_PARA_INVALID;
	}

	rc = dpp_dtb_item_buff_wr(dev, queue_id, DPP_DTB_DIR_UP_TYPE, item_index, 0, desc_len,
				  p_desc_data);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_item_buff_wr", p_mutex);

	rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_UP_TYPE, item_index, 0,
				 DPP_DTB_TAB_ACK_IS_USING_MASK);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr", p_mutex);

	DPP_DTB_TAB_UP_DATA_LEN_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id, item_index) =
		data_len;

	item_info.cmd_vld = 1;
	item_info.cmd_type = DPP_DTB_DIR_UP_TYPE;
	item_info.int_en = int_flag;
	item_info.data_len = desc_len / 4;
	item_info.data_hddr = ((DPP_DTB_TAB_UP_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
							    queue_id, item_index) >>
				4) >>
			       32) &
			      0xffffffff;
	item_info.data_laddr = (DPP_DTB_TAB_UP_PHY_ADDR_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev),
							    queue_id, item_index) >>
				4) &
			       0xffffffff;

	if (dpp_dtb_prt_get())
		dpp_dtb_info_print(dev, queue_id, item_index, &item_info);

	rc = dpp_dtb_queue_item_info_set(dev, queue_id, &item_info);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(DEV_ID(dev), rc, "dpp_dtb_queue_item_info_set",
						p_mutex);

	rc = zxic_comm_mutex_unlock(p_mutex);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}
u32 dpp_dtb_dump_table_element_info_prt(struct dpp_dev_t *dev, u32 queue_id, u32 element_id)
{
	u32 rc = 0;

	u32 element_start_addr_h = 0;
	u32 element_start_addr_l = 0;
	u32 element_dump_addr_h = 0;
	u32 element_dump_addr_l = 0;
	u32 element_table_info_addr_h = 0;
	u32 element_table_info_addr_l = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), element_id, 0,
					    DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	rc = dpp_dtb_dump_table_elemet_addr_get(dev, queue_id, element_id, &element_start_addr_h,
						&element_start_addr_l, &element_dump_addr_h,
						&element_dump_addr_l, &element_table_info_addr_h,
						&element_table_info_addr_l);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_dump_table_elemet_addr_get");

	ZXIC_COMM_DBGCNT32_PRINT("slot_id", DEV_PCIE_SLOT(dev));
	ZXIC_COMM_DBGCNT32_PRINT("queue_id", queue_id);
	ZXIC_COMM_DBGCNT32_PRINT("element_id", element_id);
	ZXIC_COMM_DBGCNT32_PRINT("element_start_addr_h", element_start_addr_h);
	ZXIC_COMM_DBGCNT32_PRINT("element_start_addr_l", element_start_addr_l);
	ZXIC_COMM_DBGCNT32_PRINT("element_dump_addr_h", element_dump_addr_h);
	ZXIC_COMM_DBGCNT32_PRINT("element_dump_addr_l", element_dump_addr_l);
	ZXIC_COMM_DBGCNT32_PRINT("element_table_info_addr_h", element_table_info_addr_h);
	ZXIC_COMM_DBGCNT32_PRINT("element_table_info_addr_l", element_table_info_addr_l);

	rc = dpp_dtb_item_ack_prt(dev, queue_id, DPP_DTB_DIR_UP_TYPE, element_id);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_item_ack_prt");

	rc = dpp_dtb_item_buff_prt(dev, queue_id, DPP_DTB_DIR_UP_TYPE, element_id, 32);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_item_buff_prt");

	return DPP_OK;
}
u32 dpp_dtb_tab_up_success_status_check(struct dpp_dev_t *dev, u32 queue_id, u32 element_id)
{
	u32 rc = 0;
	u32 rd_cnt = 0;
	u32 ack_value = 0;
	u32 success_flag = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), element_id, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);

	if (dpp_dtb_soft_perf_test_get() || dpp_dtb_hardware_perf_test_get())
		return rc;

	while (!success_flag) {
		rc = dpp_dtb_item_ack_rd(dev, queue_id, DPP_DTB_DIR_UP_TYPE, element_id, 0,
					 &ack_value);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_rd");

		if ((((ack_value >> 8) & 0xffffff) == DPP_DTB_TAB_UP_ACK_VLD_MASK) &&
		    ((ack_value & 0xff) == DPP_DTB_TAB_ACK_SUCCESS_MASK)) {
			success_flag = 1;
			break;
		}

		if (rd_cnt > dpp_dtb_dump_table_overtime_get()) {
			ZXIC_COMM_TRACE_ERROR(
				"Error!!! dpp dtb dump slot [%d] vport [0x%x] queue [%d] item [%d] ack success is overtime!\n",
				DEV_PCIE_SLOT(dev), DEV_PCIE_VPORT(dev), queue_id, element_id);

			ZXIC_COMM_PRINT("dtb dump table info\n");
			rc = dpp_dtb_dump_table_element_info_prt(dev, queue_id, element_id);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc,
					       "dpp_dtb_dump_table_element_info_prt");

			rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_UP_TYPE, element_id, 0,
						 DPP_DTB_TAB_ACK_UNUSED_MASK);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");

			ZXIC_COMM_PRINT("dtb reg info\n");

			rc = diag_dpp_dtb_axi_last_operate_info_prt(dev);
			ZXIC_COMM_CHECK_DEV_RC(0, rc, "diag_dpp_dtb_axi_last_operate_info_prt");

			rc = diag_dpp_dtb_channels_state_info_prt(dev);
			ZXIC_COMM_CHECK_DEV_RC(0, rc, "diag_dpp_dtb_channels_state_info_prt");

			rc = diag_dpp_dtb_channels_axi_resp_err_cnt_prt(dev);
			ZXIC_COMM_CHECK_DEV_RC(0, rc, "diag_dpp_dtb_channels_axi_resp_err_cnt_prt");

			return DPP_ERR;
		}

		rd_cnt++;
		zxic_comm_udelay(1);
	}

	return rc;
}
u32 dpp_dtb_tab_up_data_get(struct dpp_dev_t *dev, u32 queue_id, u32 item_index, u32 data_len,
			    u32 *p_data)
{
	u32 rc = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), item_index, 0, DPP_DTB_QUEUE_ITEM_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) == 0) {
		ZXIC_COMM_TRACE_ERROR("dtb slot %d queue %d is not init.\n", DEV_PCIE_SLOT(dev),
				      queue_id);
		return DPP_RC_DTB_QUEUE_IS_NOT_INIT;
	}

	if (dpp_dtb_hardware_perf_test_get())
		return rc;

	rc = dpp_dtb_item_buff_rd(dev, queue_id, DPP_DTB_DIR_UP_TYPE, item_index, 0, data_len,
				  p_data);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_buff_rd");

	if (dpp_dtb_debug_fun_get())
		return DPP_OK;

	rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_UP_TYPE, item_index, 0,
				 DPP_DTB_TAB_ACK_UNUSED_MASK);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");

	return DPP_OK;
}

#endif
u32 dpp_dtb_queue_down_init(struct dpp_dev_t *dev, u32 queue_id,
			    struct dpp_dtb_queue_cfg_t *p_queue_cfg)
{
	u32 rc = 0;
	u32 i = 0;
	u32 ack_vale = 0;
	u32 tab_down_item_size = 0;
	struct dpp_dtb_mgr_t *p_dtb_mgr = ZXIC_NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_queue_cfg);

	p_dtb_mgr = dpp_dtb_mgr_get(DEV_PCIE_SLOT(dev), DEV_ID(dev));
	if (p_dtb_mgr == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "slot %d ErrorCode[0x%x]: DTB Manager is not exist!!!\n",
					  DEV_PCIE_SLOT(dev), DPP_RC_DTB_MGR_NOT_EXIST);
		return DPP_RC_DTB_MGR_NOT_EXIST;
	}

	p_dtb_mgr->queue_info[queue_id].init_flag = 1;
	p_dtb_mgr->queue_info[queue_id].slot_id = DEV_PCIE_SLOT(dev);
	p_dtb_mgr->queue_info[queue_id].vport = DEV_PCIE_VPORT(dev);

	tab_down_item_size = (p_queue_cfg->down_item_size == 0) ? DPP_DTB_ITEM_SIZE :
									p_queue_cfg->down_item_size;

	p_dtb_mgr->queue_info[queue_id].tab_down.item_size = tab_down_item_size;
	p_dtb_mgr->queue_info[queue_id].tab_down.start_phy_addr = p_queue_cfg->down_start_phy_addr;
	p_dtb_mgr->queue_info[queue_id].tab_down.start_vir_addr = p_queue_cfg->down_start_vir_addr;
	p_dtb_mgr->queue_info[queue_id].tab_down.wr_index = 0;
	p_dtb_mgr->queue_info[queue_id].tab_down.rd_index = 0;

	for (i = 0; i < DPP_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, i, 0,
					 DPP_DTB_TAB_ACK_CHECK_VALUE);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");
	}

	for (i = 0; i < DPP_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		rc = dpp_dtb_item_ack_rd(dev, queue_id, DPP_DTB_DIR_DOWN_TYPE, i, 0, &ack_vale);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_rd");
		if (ack_vale != DPP_DTB_TAB_ACK_CHECK_VALUE) {
			ZXIC_COMM_PRINT("dtb slot [%d] queue [%d] down init failed, mem err!!!\n",
					DEV_PCIE_SLOT(dev), queue_id);
			return DPP_RC_DTB_MEMORY_ALLOC_ERR;
		}
	}

	ZXIC_COMM_TRACE_NOTICE("dtb slot [%d] queue [%d] down init success!!!\n",
			       DEV_PCIE_SLOT(dev), queue_id);

	ZXIC_COMM_MEMSET((u8 *)(p_queue_cfg->down_start_vir_addr), 0,
			 tab_down_item_size * DPP_DTB_QUEUE_ITEM_NUM_MAX);

	return DPP_OK;
}
u32 dpp_dtb_queue_dump_init(struct dpp_dev_t *dev, u32 queue_id,
			    struct dpp_dtb_queue_cfg_t *p_queue_cfg)
{
	u32 rc = 0;
	u32 i = 0;
	u32 ack_vale = 0;
	u32 tab_up_item_size = 0;
	struct dpp_dtb_mgr_t *p_dtb_mgr = ZXIC_NULL;
	u32 slot_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_queue_cfg);

	slot_id = (u32)DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot_id, 0, DPP_DEV_SLOT_MAX - 1);

	p_dtb_mgr = dpp_dtb_mgr_get(slot_id, DEV_ID(dev));
	if (p_dtb_mgr == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "slot %d ErrorCode[0x%x]: DTB Manager is not exist!!!\n",
					  DEV_PCIE_SLOT(dev), DPP_RC_DTB_MGR_NOT_EXIST);
		return DPP_RC_DTB_MGR_NOT_EXIST;
	}

	p_dtb_mgr->queue_info[queue_id].init_flag = 1;
	p_dtb_mgr->queue_info[queue_id].slot_id = DEV_PCIE_SLOT(dev);
	p_dtb_mgr->queue_info[queue_id].vport = DEV_PCIE_VPORT(dev);

	tab_up_item_size = (p_queue_cfg->up_item_size == 0) ? DPP_DTB_ITEM_SIZE :
								    p_queue_cfg->up_item_size;

	p_dtb_mgr->queue_info[queue_id].tab_up.item_size = tab_up_item_size;
	p_dtb_mgr->queue_info[queue_id].tab_up.start_phy_addr = p_queue_cfg->up_start_phy_addr;
	p_dtb_mgr->queue_info[queue_id].tab_up.start_vir_addr = p_queue_cfg->up_start_vir_addr;
	p_dtb_mgr->queue_info[queue_id].tab_up.wr_index = 0;
	p_dtb_mgr->queue_info[queue_id].tab_up.rd_index = 0;

	for (i = 0; i < DPP_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		rc = dpp_dtb_item_ack_wr(dev, queue_id, DPP_DTB_DIR_UP_TYPE, i, 0,
					 DPP_DTB_TAB_ACK_CHECK_VALUE);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_wr");
	}

	for (i = 0; i < DPP_DTB_QUEUE_ITEM_NUM_MAX; i++) {
		rc = dpp_dtb_item_ack_rd(dev, queue_id, DPP_DTB_DIR_UP_TYPE, i, 0, &ack_vale);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_item_ack_rd");
		if (ack_vale != DPP_DTB_TAB_ACK_CHECK_VALUE) {
			ZXIC_COMM_PRINT("dtb slot [%d] queue [%d] init failed, mem err!!!\n",
					DEV_PCIE_SLOT(dev), queue_id);
			return DPP_RC_DTB_MEMORY_ALLOC_ERR;
		}
	}

	ZXIC_COMM_TRACE_NOTICE("dtb slot [%d] queue [%d] up init success!!!\n", DEV_PCIE_SLOT(dev),
			       queue_id);

	ZXIC_COMM_MEMSET((u8 *)(p_queue_cfg->up_start_vir_addr), 0,
			 tab_up_item_size * DPP_DTB_QUEUE_ITEM_NUM_MAX);

	return DPP_OK;
}
u32 dpp_dtb_down_channel_addr_set(struct dpp_dev_t *dev, u32 channelId, u64 phyAddr, u64 virAddr,
				  u32 size)
{
	u32 rc = 0;

	struct dpp_dtb_queue_cfg_t down_queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT_NO_ASSERT(dev);

	down_queue_cfg.down_start_phy_addr = phyAddr;
	down_queue_cfg.down_start_vir_addr = virAddr;
	down_queue_cfg.down_item_size = size;

	rc = dpp_dtb_queue_down_init(dev, channelId, &down_queue_cfg);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_queue_down_init");

	return rc;
}
u32 dpp_dtb_dump_channel_addr_set(struct dpp_dev_t *dev, u32 channelId, u64 phyAddr, u64 virAddr,
				  u32 size)
{
	u32 rc = 0;

	struct dpp_dtb_queue_cfg_t dump_queue_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT_NO_ASSERT(dev);

	dump_queue_cfg.up_start_phy_addr = phyAddr;
	dump_queue_cfg.up_start_vir_addr = virAddr;
	dump_queue_cfg.up_item_size = size;

	rc = dpp_dtb_queue_dump_init(dev, channelId, &dump_queue_cfg);

	return rc;
}
u32 dpp_dtb_queue_id_free(struct dpp_dev_t *dev, u32 queue_id)
{
	u32 rc = 0;
	u32 item_num = 0;
	struct dpp_dtb_mgr_t *p_dtb_mgr = ZXIC_NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);

	p_dtb_mgr = dpp_dtb_mgr_get(DEV_PCIE_SLOT(dev), DEV_ID(dev));
	if (p_dtb_mgr == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "slot %d ErrorCode[0x%x]: DTB Manager is not exist!!!\n",
					  DEV_PCIE_SLOT(dev), DPP_RC_DTB_MGR_NOT_EXIST);
		return DPP_RC_DTB_MGR_NOT_EXIST;
	}

	rc = dpp_dtb_queue_unused_item_num_get(dev, queue_id, &item_num);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_queue_unused_item_num_get");

	if (item_num != DPP_DTB_QUEUE_ITEM_NUM_MAX)
		return DPP_RC_DTB_QUEUE_IS_WORKING;

	p_dtb_mgr->queue_info[queue_id].init_flag = 0;

	ZXIC_COMM_MEMSET(&(p_dtb_mgr->queue_info[queue_id].tab_up), 0,
			 sizeof(struct dpp_dtb_tab_up_info_t));
	ZXIC_COMM_MEMSET(&(p_dtb_mgr->queue_info[queue_id].tab_down), 0,
			 sizeof(struct dpp_dtb_tab_down_info_t));

	return DPP_OK;
}
u32 dpp_dtb_init(struct dpp_dev_t *dev)
{
	u32 rc = 0;
	struct dpp_dtb_mgr_t *p_dtb_mgr = ZXIC_NULL;

	ZXIC_COMM_CHECK_POINT(dev);

	p_dtb_mgr = dpp_dtb_mgr_get(DEV_PCIE_SLOT(dev), DEV_ID(dev));
	if (p_dtb_mgr == ZXIC_NULL) {
		rc = dpp_dtb_mgr_create(DEV_PCIE_SLOT(dev), DEV_ID(dev));
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_mgr_create");

		p_dtb_mgr = dpp_dtb_mgr_get(DEV_PCIE_SLOT(dev), DEV_ID(dev));
		if (p_dtb_mgr == ZXIC_NULL) {
			ZXIC_COMM_TRACE_DEV_ERROR(
				DEV_ID(dev),
				"slot %d ErrorCode[0x%x]: DTB Manager is not exist!!!\n",
				DEV_PCIE_SLOT(dev), DPP_RC_DTB_MGR_NOT_EXIST);
			return DPP_RC_DTB_MGR_NOT_EXIST;
		}
	}

	return DPP_OK;
}
u32 dpp_dtb_queue_id_search_by_vport(struct dpp_dev_t *dev, u32 *p_queue_arr, u32 *p_num)
{
	u32 queue_id = 0;
	u32 count = 0;

	struct dpp_dtb_mgr_t *p_dtb_mgr = ZXIC_NULL;

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_queue_arr);

	p_dtb_mgr = dpp_dtb_mgr_get(DEV_PCIE_SLOT(dev), DEV_ID(dev));
	if (p_dtb_mgr == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "slot %d ErrorCode[0x%x]: DTB Manager is not exist!!!\n",
					  DEV_PCIE_SLOT(dev), DPP_RC_DTB_MGR_NOT_EXIST);
		return DPP_RC_DTB_MGR_NOT_EXIST;
	}

	for (queue_id = 0; queue_id < DPP_DTB_QUEUE_NUM_MAX; queue_id++) {
		if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id) != 0) {
			if (DEV_PCIE_VPORT(dev) ==
			    DPP_DTB_QUEUE_VPORT_GET(DEV_PCIE_SLOT(dev), DEV_ID(dev), queue_id)) {
				p_queue_arr[count] = queue_id;
				count++;
			}
		}
	}

	if (count == 0) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			DEV_ID(dev),
			"slot %d ErrorCode[0x%x]: vport 0x%04x no queue not found!!!\n",
			DEV_PCIE_SLOT(dev), DPP_RC_DTB_QUEUE_NOT_ALLOC, DEV_PCIE_VPORT(dev));
		return DPP_RC_DTB_QUEUE_NOT_ALLOC;
	}

	*p_num = count;

	return DPP_OK;
}
u32 dpp_dtb_queue_id_get(struct dpp_dev_t *dev, u32 *queue)
{
	u32 num = 0;
	u32 rc = DPP_OK;

	u32 queue_arr[DPP_DTB_QUEUE_NUM_MAX] = { 0 };

	ZXIC_COMM_CHECK_POINT_NO_ASSERT(dev);

	rc = dpp_dtb_queue_id_search_by_vport(dev, queue_arr, &num);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_queue_id_search_by_vport");

	*queue = queue_arr[0];

	return DPP_OK;
}
u32 dpp_dtb_queue_valid_flag_get(struct dpp_dev_t *dev, u32 queue, u32 *valid_flag)
{
	u32 vport = 0;
	u32 dev_id = 0;
	u32 slot_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(valid_flag);

	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, queue, 0, DPP_DTB_QUEUE_NUM_MAX - 1);

	slot_id = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot_id, 0, DPP_DEV_SLOT_MAX - 1);

	vport = DEV_PCIE_VPORT(dev);
	*valid_flag = 0;
	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), dev_id, queue) &&
	    (DPP_DTB_QUEUE_VPORT_GET(DEV_PCIE_SLOT(dev), dev_id, queue) == vport)) {
		*valid_flag = 1;
	}

	return DPP_OK;
}
u32 dpp_dtb_queue_init_flag_get(struct dpp_dev_t *dev, u32 queue, u32 *init_flag)
{
	u32 vport = 0;
	u32 dev_id = 0;
	u32 slot_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(init_flag);

	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, queue, 0, DPP_DTB_QUEUE_NUM_MAX - 1);

	slot_id = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot_id, 0, DPP_DEV_SLOT_MAX - 1);

	vport = DEV_PCIE_VPORT(dev);
	*init_flag = 0;
	if (DPP_DTB_QUEUE_INIT_FLAG_GET(DEV_PCIE_SLOT(dev), dev_id, queue))
		*init_flag = 1;

	return DPP_OK;
}

#endif
#endif
