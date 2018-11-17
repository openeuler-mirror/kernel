// SPDX-License-Identifier: GPL-2.0
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "hisi_zip_udrv.h"
#include "wd_adapter.h"
#include "../config.h"

#if __AARCH64EL__ == 1
/* Define memory barrier on ARM64 */
#define mb() {asm volatile("dsb sy" : : : "memory"); }
#else
#warning "this file need to be used on AARCH64EL mode"
/* Doing nothing */
#define mb()
#endif

#define PAGE_SHIFT		12

#define ZIP_SQE_SIZE		128
#define ZIP_CQE_SIZE		16
#define ZIP_EQ_DEPTH		1024

/* cqe shift */
#define CQE_PHASE(cq)	(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_NUM(cq)	((*((__u32 *)(cq) + 2)) >> 16)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

#define ZIP_IOMEM_SIZE		4096

/* For D06 board */
#define ZIP_DOORBELL_OFFSET_V1	(0x340)
#define ZIP_DOORBELL_OFFSET_V2	(0)

#define ZIP_DMA_BUF_SZ		(4096 << 10)

struct cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7; /* phase, status */
};

struct hisi_zip_queue_info {
	void *sq_base;
	void *cq_base;
	void *doorbell_base;
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	__u32 ver;
	int cqc_phase;
	void *req_cache[ZIP_EQ_DEPTH];
	int is_sq_full;
	int (*db)(struct hisi_zip_queue_info *q, __u8 cmd, __u16 index,
		  __u8 priority);
	unsigned long long dma_page;
	void *dma_buf;
};

int hacc_db_v1(struct hisi_zip_queue_info *q, __u8 cmd, __u16 index,
	       __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)cmd << 16);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;
	*((__u64 *)base) = doorbell;

	return 0;
}

int hacc_db_v2(struct hisi_zip_queue_info *q, __u8 cmd, __u16 index,
	       __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn;
	__u64 doorbell = 0;
	__u16 randata = 0;

	doorbell = (__u64)sqn | ((__u64)cmd << 12) | ((__u64)randata << 16);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;
	*((__u64 *)base) = doorbell;

	return 0;
}

static int hisi_zip_fill_sqe(void *msg, struct wd_queue *q,  __u16 i)
{
	struct hisi_zip_queue_info *info = q->priv;
	struct hisi_zip_msg *sqe = (struct hisi_zip_msg *)info->sq_base + i;
	unsigned long long src_addr = info->dma_page;
	unsigned long long dst_addr = src_addr;
	void *in;

	memcpy((void *)sqe, msg, sizeof(struct hisi_zip_msg));

	if (q->dma_flag & VFIO_SPIMDEV_DMA_PHY) {
		/* while decompression, we need more space */
		if (sqe->input_date_length > ZIP_DMA_BUF_SZ)
			return -EINVAL;
		in = (void *)((__u64)sqe->source_addr_l |
			((__u64)sqe->source_addr_h << 32));
		memcpy(info->dma_buf, in, sqe->input_date_length);
		sqe->source_addr_l = src_addr & 0xffffffff;
		sqe->source_addr_h = src_addr >> 32;
		sqe->dest_addr_l =  dst_addr & 0xffffffff;
		sqe->dest_addr_h = dst_addr >> 32;
	}
	assert(!info->req_cache[i]);
	info->req_cache[i] = msg;

	return 0;
}

static int hisi_zip_recv_sqe(struct hisi_zip_msg *sqe, struct wd_queue *q,
			       __u16 i)
{
	__u32 status = sqe->dw3 & 0xff;
	__u32 type = sqe->dw9 & 0xff;
	struct hisi_zip_queue_info *info = q->priv;
	void *out, *dma_out = info->dma_buf;
	struct hisi_zip_msg *umsg = info->req_cache[i];

	if (status != 0 && status != 0x0d) {
		fprintf(stderr, "bad status (s=%d, t=%d)\n", status, type);
		return -EIO;
	}

	assert(umsg);
	if (q->dma_flag & VFIO_SPIMDEV_DMA_PHY) {
		out = (void *)((__u64)umsg->dest_addr_l |
			((__u64)umsg->dest_addr_h << 32));
		memcpy(out, dma_out, sqe->produced);
		umsg->produced = sqe->produced;
		umsg->consumed = sqe->consumed;
		umsg->tag = sqe->tag;

		/* other area to be filled */
		return 1;
	}
	memcpy((void *)info->req_cache[i], sqe, sizeof(*umsg));

	return 1;
}

static int zip_get_dma_buf(struct wd_queue *q)
{
	struct hisi_zip_queue_info *info = q->priv;
	int ret, fd;
	void *dma_buf;

	if (!(q->dma_flag & VFIO_SPIMDEV_DMA_PHY))
		return 0;

	info->dma_page = ZIP_DMA_BUF_SZ;
	ret = ioctl(q->fd, ZIP_GET_DMA_PAGES, &info->dma_page);
	if (ret < 0) {
		printf("GET_DMA_PAGE ioctl fail!\n");
		return ret;
	}
	fd = open("/dev/mem", O_RDWR, 0);
	if (fd < 0) {
		printf("\n%s():Can't open /dev/mem!", __func__);
		ret = fd;
		goto put_pages;
	}
	dma_buf = mmap((void *)0x0, ZIP_DMA_BUF_SZ, PROT_READ |
		       PROT_WRITE,
		       MAP_SHARED, fd, info->dma_page);
	if (!dma_buf || dma_buf == MAP_FAILED) {
		printf("\nmmap dma buf fail!");
		ret = -1;
		goto close_mem;
	}
	memset(dma_buf, 0, ZIP_DMA_BUF_SZ);
	info->dma_buf = dma_buf;
	close(fd);

	return 0;
close_mem:
	close(fd);

put_pages:
	(void)ioctl(q->fd, ZIP_PUT_DMA_PAGES, &info->dma_page);

	return ret;
}

static void zip_put_dma_buf(struct wd_queue *q)
{
	struct hisi_zip_queue_info *info = q->priv;

	if (!(q->dma_flag & VFIO_SPIMDEV_DMA_PHY))
		return;

	munmap(info->dma_buf, ZIP_DMA_BUF_SZ);
	(void)ioctl(q->fd, ZIP_PUT_DMA_PAGES, &info->dma_page);
}

int hisi_zip_set_queue_dio(struct wd_queue *q)
{
	struct hisi_zip_queue_info *info;
	void *vaddr;
	int ret;

	info = malloc(sizeof(*info));
	if (!info)
		return -1;
	memset((void *)info, 0, sizeof(*info));
	q->priv = info;

	vaddr = mmap(NULL,
		ZIP_SQE_SIZE * ZIP_EQ_DEPTH + ZIP_CQE_SIZE * ZIP_EQ_DEPTH,
		PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 4096);
	if (vaddr <= 0) {
		ret = (intptr_t)vaddr;
		goto err_with_info;
	}
	info->sq_base = vaddr;
	info->cq_base = vaddr + ZIP_SQE_SIZE * ZIP_EQ_DEPTH;
	info->sqn = *(__u32 *)vaddr;
	info->ver = *((__u32 *)vaddr + 1);
	*(__u64 *)vaddr = 0;
	vaddr = mmap(NULL, ZIP_IOMEM_SIZE,
		PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
	if (vaddr <= 0) {
		ret = (intptr_t)vaddr;
		goto err_with_scq;
	}
	if (info->ver == 1) {
		info->db = hacc_db_v1;
		info->doorbell_base = vaddr + ZIP_DOORBELL_OFFSET_V1;
	} else if (info->ver == 2) {
		info->db = hacc_db_v2;
		info->doorbell_base = vaddr + ZIP_DOORBELL_OFFSET_V2;
	} else {
		ret = -ENODEV;
		goto unmap_io;
	}
	info->sq_tail_index = 0;
	info->sq_head_index = 0;
	info->cq_head_index = 0;
	info->cqc_phase = 1;
	info->is_sq_full = 0;

	ret = zip_get_dma_buf(q);
	if (ret)
		goto unmap_io;

	return 0;

unmap_io:
	munmap(vaddr, ZIP_IOMEM_SIZE);
err_with_scq:
	munmap(info->sq_base,
	       ZIP_SQE_SIZE * ZIP_EQ_DEPTH + ZIP_CQE_SIZE * ZIP_EQ_DEPTH);
err_with_info:
	free(info);
	return ret;
}

void hisi_zip_unset_queue_dio(struct wd_queue *q)
{
	struct hisi_zip_queue_info *info = q->priv;

	zip_put_dma_buf(q);

	if (info->ver == 1)
		munmap(info->doorbell_base - ZIP_DOORBELL_OFFSET_V1,
		       ZIP_IOMEM_SIZE);
	else if (info->ver == 2)
		munmap(info->doorbell_base - ZIP_DOORBELL_OFFSET_V2,
		       ZIP_IOMEM_SIZE);

	munmap(info->cq_base, ZIP_CQE_SIZE * ZIP_EQ_DEPTH);
	munmap(info->sq_base, ZIP_SQE_SIZE * ZIP_EQ_DEPTH);
	free(info);
	q->priv = NULL;
}

int hisi_zip_add_to_dio_q(struct wd_queue *q, void *req)
{
	struct hisi_zip_queue_info *info = q->priv;
	__u16 i;
	int ret;

	if (info->is_sq_full)
		return -EBUSY;

	i = info->sq_tail_index;

	ret = hisi_zip_fill_sqe(req, q, i);
	if (ret)
		return ret;
	/*memory barrier*/
	mb();

	if (i == (ZIP_EQ_DEPTH - 1))
		i = 0;
	else
		i++;

	info->db(info, DOORBELL_CMD_SQ, i, 0);

	info->sq_tail_index = i;

	if (i == info->sq_head_index)
		info->is_sq_full = 1;

	return 0;
}

int hisi_zip_get_from_dio_q(struct wd_queue *q, void **resp)
{
	struct hisi_zip_queue_info *info = q->priv;
	__u16 i = info->cq_head_index;
	struct cqe *cq_base = info->cq_base;
	struct hisi_zip_msg *sq_base = info->sq_base;
	struct cqe *cqe = cq_base + i;
	struct hisi_zip_msg *sqe;
	int ret;

	if (info->cqc_phase == CQE_PHASE(cqe)) {
		sqe = sq_base + CQE_SQ_HEAD_INDEX(cqe);
		ret = hisi_zip_recv_sqe(sqe, q, i);
		if (ret < 0)
			return -EIO;

		if (info->is_sq_full)
			info->is_sq_full = 0;
	} else {
		return 0;
	}

	*resp = info->req_cache[i];
	info->req_cache[i] = NULL;

	if (i == (ZIP_EQ_DEPTH - 1)) {
		info->cqc_phase = !(info->cqc_phase);
		i = 0;
	} else
		i++;
	info->db(info, DOORBELL_CMD_CQ, i, 0);
	info->cq_head_index = i;
	info->sq_head_index = i;


	return ret;
}

int hisi_zip_get_capa(struct wd_capa *capa)
{
	if (capa && !strncmp(capa->alg, "zlib", 4)) {
		capa->latency = 10;
		capa->throughput = 10;

		/* capa->priv is to be extended */
		return 0;
	} else if (capa && !strncmp(capa->alg, "gzip", 4)) {
		capa->latency = 10;
		capa->throughput = 10;

		/* capa->priv is to be extended */
		return 0;
	}

	return -ENODEV;
}

#if (defined(HAVE_DYNDRV) & HAVE_DYNDRV)
static struct wd_drv_dio_if zip_dio_tbl = {
	.hw_type = "hisi_zip",
	.open = hisi_zip_set_queue_dio,
	.close = hisi_zip_unset_queue_dio,
	.send = hisi_zip_add_to_dio_q,
	.recv = hisi_zip_get_from_dio_q,
	.get_capa = hisi_zip_get_capa,
};

void __attribute__ ((constructor)) wd_load_hisilicon_zip_init(void)
{
	int ret;

	ret = wd_drv_dio_tbl_set(&zip_dio_tbl);
	if (ret) {
		printf("Load hisilicon zip user driver fail!\n");
		return;
	}
}
#endif
