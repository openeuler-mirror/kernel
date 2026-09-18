/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_db.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM doorbell implementation
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_mt.h"
#include "hinic5_hwdev.h"

#include "cqm_object.h"
#include "cqm_bitmap_table.h"
#include "cqm_bat_cla.h"
#include "cqm_object_intern.h"
#include "cqm_main.h"
#include "cqm_db.h"

/**
 * Prototype    : cqm5_db_addr_alloc
 * Description  : Apply for a page of hardware doorbell and dwqe.
 *		  The indexes are the same. The obtained addresses are physical
 *		  addresses. Each function has a maximum of 1K addresses(DB).
 * Input        : void *ex_handle
 *		  void __iomem **db_addr,
 *		  void __iomem **dwqe_addr
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
s32 cqm5_db_addr_alloc(void *ex_handle, void __iomem **db_addr,
		      void __iomem **dwqe_addr)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return CQM_FAIL;
	}
	if (unlikely(db_addr == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(db_addr));
		return CQM_FAIL;
	}
	if (unlikely(dwqe_addr == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(dwqe_addr));
		return CQM_FAIL;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm5_db_addr_alloc_cnt);

	return hinic5_alloc_db_addr(ex_handle, db_addr, dwqe_addr);
}

s32 cqm_db_phy_addr_alloc(void *ex_handle, u64 *db_paddr, u64 *dwqe_addr)
{
	return hinic5_alloc_db_phy_addr(ex_handle, db_paddr, dwqe_addr);
}

/**
 * Prototype    : cqm5_db_addr_free
 * Description  : Release a page of hardware doorbell and dwqe.
 * Input        : void *ex_handle
 *		  const void __iomem **db_addr,
 *		  void __iomem **dwqe_addr
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
void cqm5_db_addr_free(void *ex_handle, const void __iomem *db_addr,
		      void __iomem *dwqe_addr)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm5_db_addr_free_cnt);

	hinic5_free_db_addr(ex_handle, db_addr, dwqe_addr);
}

static void cqm_db_phy_addr_free(void *ex_handle, const u64 *db_paddr, const u64 *dwqe_addr)
{
	hinic5_free_db_phy_addr(ex_handle, *db_paddr, *dwqe_addr);
}

static bool cqm_need_db_init(s32 service)
{
	switch (service) {
	case CQM_SERVICE_T_NIC:
	case CQM_SERVICE_T_OVS:
	case CQM_SERVICE_T_IPSEC:
	case CQM_SERVICE_T_VIRTIO:
	case CQM_SERVICE_T_PPA:
		return false;
	default:
		return true;
	}
}

/**
 * Prototype    : cqm_db_init
 * Description  : Initialize the doorbell of the CQM.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
s32 cqm_db_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	s32 i;

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);

	/* Allocate hardware doorbells to services. */
	for (i = 0; i < CQM_SERVICE_T_MAX; i++) {
		service = &cqm_handle->service[i];
		if (!cqm_need_db_init(i) || !service->valid)
			continue;

		if (cqm5_db_addr_alloc(ex_handle, &service->hardware_db_vaddr,
				      &service->dwqe_vaddr) != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm5_db_addr_alloc));
			break;
		}

		if (cqm_db_phy_addr_alloc(handle, &service->hardware_db_paddr,
					  &service->dwqe_paddr) !=
		    CQM_SUCCESS) {
			cqm5_db_addr_free(ex_handle, service->hardware_db_vaddr,
					 service->dwqe_vaddr);
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_db_phy_addr_alloc));
			break;
		}
	}

	if (i != CQM_SERVICE_T_MAX) {
		i--;
		for (; i >= 0; i--) {
			service = &cqm_handle->service[i];
			if (!cqm_need_db_init(i) || !service->valid)
				continue;

			cqm5_db_addr_free(ex_handle, service->hardware_db_vaddr,
					 service->dwqe_vaddr);
			cqm_db_phy_addr_free(ex_handle,
					     &service->hardware_db_paddr,
					     &service->dwqe_paddr);
		}
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * Prototype    : cqm_db_uninit
 * Description  : Deinitialize the doorbell of the CQM.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
void cqm_db_uninit(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	s32 i;

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);

	/* Release hardware doorbell. */
	for (i = 0; i < CQM_SERVICE_T_MAX; i++) {
		service = &cqm_handle->service[i];
		if (service->valid && cqm_need_db_init(i)) {
			cqm5_db_addr_free(ex_handle, service->hardware_db_vaddr,
					 service->dwqe_vaddr);
			cqm_db_phy_addr_free(ex_handle, &service->hardware_db_paddr,
					     &service->dwqe_paddr);
		}
	}
}

/**
 * Prototype    : cqm5_get_db_addr
 * Description  : Return hardware DB vaddr.
 * Input        : void *ex_handle
 *		  u32 service_type
 * Output       : None
 * Return Value : void *
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
void *cqm5_get_db_addr(void *ex_handle, u32 service_type)
{
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct hinic5_hwdev *handle = NULL;

	if (service_type >= CQM_SERVICE_T_MAX) {
		pr_err("service_type is out of bounds\n");
		return NULL;
	}

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return NULL;
	}
	handle = (struct hinic5_hwdev *)ex_handle;
	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);

	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return NULL;
	}

	service = &cqm_handle->service[service_type];

	return (void *)service->hardware_db_vaddr;
}
EXPORT_SYMBOL(cqm5_get_db_addr);

/**
 * Prototype    : cqm5_get_db_addr
 * Description  : Return hardware DB Phyaddr.
 * Input        : void *ex_handle
 *		  u32 service_type
 * Output       : None
 * Return Value : void *
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
s32 cqm5_get_hardware_db_addr(void *ex_handle, u64 *addr,
			     enum hinic5_service_type service_type)
{
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct hinic5_hwdev *handle = NULL;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return CQM_FAIL;
	}
	if (unlikely(addr == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(addr));
		return CQM_FAIL;
	}

	if (service_type < SERVICE_T_NIC || service_type >= SERVICE_T_MAX) {
		pr_err("%s service_type = %d state is error\n", __func__,
		       service_type);
		return CQM_FAIL;
	}

	handle = (struct hinic5_hwdev *)ex_handle;
	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);

	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return CQM_FAIL;
	}

	service = &cqm_handle->service[service_type];

	*addr = service->hardware_db_paddr;
	return CQM_SUCCESS;
}
EXPORT_SYMBOL(cqm5_get_hardware_db_addr);

/**
 * Prototype    : cqm5_ring_hardware_db
 * Description  : Ring hardware DB to chip.
 * Input        : void *ex_handle
 *		  u32 service_type: Each kernel-mode service is allocated a
 *				    hardware db page.
 *		  u8 db_count: The bit[7:0] of PI can't be store in 64-bit db.
 *		  u64 db: It contains the content of db, whitch is organized by
 *			  service, including big-endian conversion
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
s32 cqm5_ring_hardware_db(void *ex_handle, u32 service_type, u8 db_count, u64 db)
{
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct hinic5_hwdev *handle = NULL;
#if defined(__UEFI__) && defined(__HIFC__)
	EFI_STATUS Status;
	u64 *offset = NULL;
#endif

	if (service_type >= CQM_SERVICE_T_MAX) {
		pr_err("service_type is out of bounds\n");
		return CQM_FAIL;
	}
	if (!ex_handle)
		return CQM_FAIL;
	handle = (struct hinic5_hwdev *)ex_handle;
	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (!cqm_handle)
		return CQM_FAIL;

	service = &cqm_handle->service[service_type];

	/* Considering the performance of ringing hardware db,
	 * the parameter is not checked.
	 */
#if defined(__UEFI__) && defined(__HIFC__)
	offset = ((u64 *)service->hardware_db_vaddr + db_count);
	MemoryFence();
	Status = ((BUS_IO_PROTOCOL *)handle->pcidev_hdl)->Mem.Write(handle->pcidev_hdl,
									EfiBusIoWidthUint64, 0x2,
									(u64)offset, 1,
									(void *)&db);
	MemoryFence();

	if (EFI_ERROR(Status))
		DEBUGPRINT(CRITICAL, "Hifc: write doorbell fails: %r\n",
			   Status);
#else
	/* Considering the performance of ringing hardware db,
	 * the parameter is not checked.
	 */
	wmb();
	*((u64 *)service->hardware_db_vaddr + db_count) = db;
#endif
	return CQM_SUCCESS;
}
EXPORT_SYMBOL(cqm5_ring_hardware_db);

/**
 * Prototype    : cqm5_ring_hardware_db_fc
 * Description  : Ring fake vf hardware DB to chip.
 * Input        : void *ex_handle
 *		  u32 service_type: Each kernel-mode service is allocated a
 *				    hardware db page.
 *		  u8 db_count: The bit[7:0] of PI can't be store in 64-bit db.
 *		  u8 pagenum: Indicates the doorbell address offset of the fake
 *			      VFID.
 *		  u64 db: It contains the content of db, whitch is organized by
 *			  service, including big-endian conversion.
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
s32 cqm5_ring_hardware_db_fc(void *ex_handle, u32 service_type, u8 db_count,
			    u8 pagenum, u64 db)
{
#define HIFC_DB_FAKE_VF_OFFSET 32
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct hinic5_hwdev *handle = NULL;
	void *dbaddr = NULL;

	handle = (struct hinic5_hwdev *)ex_handle;
	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	service = &cqm_handle->service[service_type];
	/* Considering the performance of ringing hardware db,
	 * the parameter is not checked.
	 */
	wmb();
	dbaddr = (u8 *)service->hardware_db_vaddr +
		 ((pagenum + HIFC_DB_FAKE_VF_OFFSET) * HINIC5_DB_PAGE_SIZE);
	*((u64 *)dbaddr + db_count) = db;
	return CQM_SUCCESS;
}

/**
 * Prototype    : cqm5_ring_direct_wqe_db
 * Description  : Ring direct wqe hardware DB to chip.
 * Input        : void *ex_handle
 *		  u32 service_type: Each kernel-mode service is allocated a
 *				    hardware db page.
 *		  u8 db_count: The bit[7:0] of PI can't be store in 64-bit db.
 *		  void *direct_wqe: The content of direct_wqe.
 *		  u16 length: The length of direct_wqe.
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
s32 cqm5_ring_direct_wqe_db(void *ex_handle, u32 service_type, u8 db_count,
			   void *direct_wqe)
{
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct hinic5_hwdev *handle = NULL;
	u64 *tmp = (u64 *)direct_wqe;
	int i;

	if (!ex_handle)
		return CQM_FAIL;

	if (service_type >= CQM_SERVICE_T_MAX) {
		pr_err("service_type is out of bounds\n");
		return CQM_FAIL;
	}

	handle = (struct hinic5_hwdev *)ex_handle;
	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (!cqm_handle)
		return CQM_FAIL;

	service = &cqm_handle->service[service_type];

	/* Considering the performance of ringing hardware db,
	 * the parameter is not checked.
	 */
	wmb();
	for (i = 0; i < 0x80 / 0x8; i++)
		*((u64 *)service->dwqe_vaddr + 0x40 + i) = *tmp++;

	return CQM_SUCCESS;
}
EXPORT_SYMBOL(cqm5_ring_direct_wqe_db);

s32 cqm5_ring_direct_wqe_db_fc(void *ex_handle, u32 service_type,
			      void *direct_wqe)
{
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct hinic5_hwdev *handle = NULL;
	u64 *tmp = (u64 *)direct_wqe;
	int i;

	handle = (struct hinic5_hwdev *)ex_handle;
	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	service = &cqm_handle->service[service_type];

	/* Considering the performance of ringing hardware db,
	 * the parameter is not checked.
	 */
	wmb();
	*((u64 *)service->dwqe_vaddr + 0x0) = tmp[0x2];
	*((u64 *)service->dwqe_vaddr + 0x1) = tmp[0x3];
	*((u64 *)service->dwqe_vaddr + 0x2) = tmp[0x0];
	*((u64 *)service->dwqe_vaddr + 0x3) = tmp[0x1];
	tmp += 0x4;

	/* The FC use 256B WQE. The directwqe is written at block0,
	 * and the length is 256B
	 */
	for (i = 0x4; i < 0x20; i++)
		*((u64 *)service->dwqe_vaddr + i) = *tmp++;

	return CQM_SUCCESS;
}

/**
 * Prototype    : cqm5_ring_hardware_db_update_pri
 * Description  : Provides the doorbell interface for the CQM to convert the PRI
 *		  to the CoS. The doorbell transmitted by the service must be
 *		  the host sequence. This interface converts the network
 *		  sequence.
 * Input        : void *ex_handle
 *		  u32 service_type: Each kernel-mode service is allocated a
 *				    hardware db page.
 *		  u8 db_count: The bit[7:0] of PI can't be store in 64-bit db.
 *		  u64 db: It contains the content of db, whitch is organized by
 *			  service, including big-endian conversion.
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/11/24
 *   Modification : Created function
 */
s32 cqm5_ring_hardware_db_update_pri(void *ex_handle, u32 service_type,
				    u8 db_count, u64 db)
{
	struct tag_cqm_db_common *db_common = (struct tag_cqm_db_common *)(void *)(&db);
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct hinic5_hwdev *handle = NULL;

	handle = (struct hinic5_hwdev *)ex_handle;

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	service = &cqm_handle->service[service_type];

	/* the CQM converts the PRI to the CoS */
	db_common->cos = 0x7 - db_common->cos;

	cqm_swab32((u8 *)db_common, sizeof(u64) >> CQM_DW_SHIFT);

	/* Considering the performance of ringing hardware db,
	 * the parameter is not checked.
	 */
	wmb();
	*((u64 *)service->hardware_db_vaddr + db_count) = db;

	return CQM_SUCCESS;
}

/**
 * Prototype    : cqm5_ring_software_db
 * Description  : Ring software db.
 * Input        : struct tag_cqm_object *object
 *		  u64 db_record: It contains the content of db, whitch is
 *				 organized by service, including big-endian
 *				 conversion. For RQ/SQ: This field is filled
 *				 with the doorbell_record area of queue_header.
 *				 For CQ: This field is filled with the value of
 *				 ci_record in queue_header.
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
s32 cqm5_ring_software_db(struct tag_cqm_object *object, u64 db_record)
{
	struct tag_cqm_nonrdma_qinfo *nonrdma_qinfo = NULL;
	struct tag_cqm_rdma_qinfo *rdma_qinfo = NULL;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct hinic5_hwdev *handle = NULL;

	if (unlikely(object == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(object));
		return CQM_FAIL;
	}

	cqm_handle = (struct tag_cqm_handle *)object->cqm_handle;
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return CQM_FAIL;
	}
	handle = cqm_handle->ex_handle;

	if (object->object_type == CQM_OBJECT_NONRDMA_EMBEDDED_RQ ||
	    object->object_type == CQM_OBJECT_NONRDMA_EMBEDDED_SQ ||
	    object->object_type == CQM_OBJECT_NONRDMA_SRQ) {
		nonrdma_qinfo = (struct tag_cqm_nonrdma_qinfo *)(void *)object;
		nonrdma_qinfo->common.q_header_vaddr->doorbell_record =
		    db_record;
	} else if ((object->object_type == CQM_OBJECT_NONRDMA_EMBEDDED_CQ) ||
		   (object->object_type == CQM_OBJECT_NONRDMA_SCQ)) {
		nonrdma_qinfo = (struct tag_cqm_nonrdma_qinfo *)(void *)object;
		nonrdma_qinfo->common.q_header_vaddr->ci_record = db_record;
	} else if ((object->object_type == CQM_OBJECT_RDMA_QP) ||
		   (object->object_type == CQM_OBJECT_RDMA_SRQ)) {
		rdma_qinfo = (struct tag_cqm_rdma_qinfo *)(void *)object;
		rdma_qinfo->common.q_header_vaddr->doorbell_record = db_record;
	} else if (object->object_type == CQM_OBJECT_RDMA_SCQ) {
		rdma_qinfo = (struct tag_cqm_rdma_qinfo *)(void *)object;
		rdma_qinfo->common.q_header_vaddr->ci_record = db_record;
	} else {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object->object_type));
	}

	return CQM_SUCCESS;
}
EXPORT_SYMBOL(cqm5_ring_software_db);
