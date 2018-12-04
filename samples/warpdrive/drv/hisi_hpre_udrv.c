// SPDX-License-Identifier: GPL-2.0+
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../wd_util.h"
#include "../wd_adapter.h"
#include "../wd_rsa.h"

#include "../config.h"
#include "./hisi_hpre_udrv.h"

/* Memory barrier */
#define mb() {asm volatile("dsb sy" : /* no out */ : /* no in */ : "memory"); }

#define HPRE_DOORBELL_OFFSET_V2	(0)
#define HPRE_IOMEM_SIZE		4096

static int hpre_bn_format(unsigned char *buf, int len)
{
	int i = len - 1, j;

	if (!buf || len <= 0) {
		printf("%s fail!\n", __func__);
		return -1;
	}
	while (!buf[i] && i >= 0)
		i--;
	if (i == len - 1)
		return 0;

	for (j = len - 1; j >= 0; j--, i--) {
		if (i >= 0)
			buf[j] = buf[i];
		else
			buf[j] = 0;
	}

	return 0;
}

static int hpre_db_v2(struct hpre_queue_info *q, __u8 cmd,
		      __u16 index, __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn & 0x3ff;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)(cmd & 0xf) << 12);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;

	*((__u64 *)base) = doorbell;

	return 0;
}

static int hpre_fill_sqe(void *msg, struct wd_queue *q, __u16 i)
{
	struct hpre_queue_info *info = q->priv;
	struct hpre_sqe *cc_sqe = &info->cache_sqe;
	struct hpre_sqe *sqe = (struct hpre_sqe *)info->sq_base + i;
	char *alg = q->capa.alg;
	struct wd_rsa_msg *rsa_msg = msg;
	void *dma_buf = info->dma_buf;

	if (!strncmp(alg, "rsa", 3)) {
		if (rsa_msg->prikey_type == WD_RSA_PRIKEY2)
			cc_sqe->alg = HPRE_ALG_NC_CRT;
		else if (rsa_msg->prikey_type == WD_RSA_PRIKEY1)
			cc_sqe->alg = HPRE_ALG_NC_NCRT;
		else
			return -1;
		cc_sqe->task_len1 = rsa_msg->nbytes / 8 - 1;
		if (rsa_msg->op_type == WD_RSA_SIGN) {
			/* Since SVA and key SGLs is not supported now, we
			 * should copy
			 */
			if (cc_sqe->alg == HPRE_ALG_NC_CRT) {
				struct wd_rsa_prikey2 *prikey2 =
						(void *)rsa_msg->prikey;

				memcpy(dma_buf, prikey2->dq,
				       rsa_msg->nbytes / 2);
				(void)hpre_bn_format(dma_buf, rsa_msg->nbytes /
						     2);
				memcpy(dma_buf + rsa_msg->nbytes / 2,
				       prikey2->dp, rsa_msg->nbytes / 2);
				(void)hpre_bn_format(dma_buf + rsa_msg->nbytes /
						     2, rsa_msg->nbytes / 2);
				memcpy(dma_buf + rsa_msg->nbytes, prikey2->q,
				       rsa_msg->nbytes / 2);
				(void)hpre_bn_format(dma_buf + rsa_msg->nbytes,
						     rsa_msg->nbytes / 2);
				memcpy(dma_buf + 3 * rsa_msg->nbytes / 2,
				       prikey2->p, rsa_msg->nbytes / 2);
				(void)hpre_bn_format(dma_buf + 3 *
				 rsa_msg->nbytes / 2, rsa_msg->nbytes / 2);
				memcpy(dma_buf + 2 * rsa_msg->nbytes,
				       prikey2->qinv, rsa_msg->nbytes / 2);
				(void)hpre_bn_format(dma_buf + 2 *
				 rsa_msg->nbytes, rsa_msg->nbytes / 2);
			} else {
				struct wd_rsa_prikey1 *prikey1 =
						(void *)rsa_msg->prikey;

				memcpy(dma_buf, prikey1->d, rsa_msg->nbytes);
				(void)hpre_bn_format(dma_buf, rsa_msg->nbytes);
				memcpy(dma_buf + rsa_msg->nbytes, prikey1->n,
				       rsa_msg->nbytes);
				(void)hpre_bn_format(dma_buf + rsa_msg->nbytes,
						     rsa_msg->nbytes);
			}
		} else if (rsa_msg->op_type == WD_RSA_VERIFY) {
			struct wd_rsa_pubkey *pubkey = (void *)rsa_msg->pubkey;

			memcpy(dma_buf, pubkey->e, rsa_msg->nbytes);
			(void)hpre_bn_format(dma_buf, rsa_msg->nbytes);
			memcpy(dma_buf + rsa_msg->nbytes, pubkey->n,
			       rsa_msg->nbytes);
			(void)hpre_bn_format(dma_buf + rsa_msg->nbytes,
					     rsa_msg->nbytes);
			cc_sqe->alg = HPRE_ALG_NC_NCRT;

		} else {
			WD_ERR("\nrsa ALG support only sign and verify now!");
			return -1;
		}
	} else {
		WD_ERR("\nalg=%s,rsa algorithm support only now!", alg);
		return -1;
	}
	dma_buf += 2048;
	memcpy(dma_buf, (void *)rsa_msg->in, rsa_msg->nbytes);

	/* This need more processing logic. to do more */
	cc_sqe->tag = (__u32)rsa_msg->udata;
	cc_sqe->done = 0x1;
	cc_sqe->etype = 0x0;
	memcpy((void *)sqe, (void *)cc_sqe, sizeof(*cc_sqe));

	return 0;
}

void hpre_sqe_dump(struct wd_queue *q, struct hpre_sqe *sqe)
{
	struct hpre_queue_info *info = q->priv;
	struct hpre_sqe *sq_base = info->sq_base;

	printf("sqe=%p, index=%ld\n", sqe, ((unsigned long)sqe -
	       (unsigned long)sq_base)/sizeof(struct hpre_sqe));
	printf("sqe:alg=0x%x\n", sqe->alg);
	printf("sqe:etype=0x%x\n", sqe->etype);
	printf("sqe:done=0x%x\n", sqe->done);
	printf("sqe:task_len1=0x%x\n", sqe->task_len1);
	printf("sqe:task_len2=0x%x\n", sqe->task_len2);
	printf("sqe:mrttest_num=0x%x\n", sqe->mrttest_num);
	printf("sqe:low_key=0x%x\n", sqe->low_key);
	printf("sqe:hi_key=0x%x\n", sqe->hi_key);
	printf("sqe:low_in=0x%x\n", sqe->low_in);
	printf("sqe:hi_in=0x%x\n", sqe->hi_in);
	printf("sqe:low_out=0x%x\n", sqe->low_out);
	printf("sqe:hi_out=0x%x\n", sqe->hi_out);
	printf("sqe:tag=0x%x\n", sqe->tag);
}

static int hpre_recv_sqe(struct wd_queue *q, struct hpre_sqe *sqe,
			 struct wd_rsa_msg *recv_msg)
{
	__u32 status = sqe->done;
	struct hpre_queue_info *info = q->priv;
	void *out;

	if (q->dma_flag & VFIO_SPIMDEV_DMA_PHY)
		out = (void *)((((__u64)(sqe->hi_out) << 32) |
		 (sqe->low_out)) + ((unsigned long long)info->dma_buf -
		 info->dma_page));
	else
		out = (void *)(((__u64)(sqe->hi_out) << 32) | (sqe->low_out));
	if (status != 0x3 || sqe->etype) {
		WD_ERR("HPRE do %s fail!done=0x%x, etype=0x%x\n", "rsa",
		       status, sqe->etype);
		return -1;
	}
	recv_msg->alg = "rsa";
	recv_msg->aflags = 0;
	recv_msg->outbytes = (__u16)((sqe->task_len1 + 1) << 3);
	memcpy((void *)recv_msg->out, out, recv_msg->outbytes);

	return 1;
}
#define HPRE_DMA_PAGE			4096

static int hpre_init_cache_buf(struct wd_queue *q)
{
	void *dma_buf;
	struct hpre_queue_info *info = q->priv;
	int ret, fd;
	__u64 temp;

	if (q->dma_flag & VFIO_SPIMDEV_DMA_PHY) {
		info->dma_page = HPRE_DMA_PAGE;
		ret = ioctl(q->fd, HPRE_GET_DMA_PAGES, &info->dma_page);
		if (ret == -1) {
			printf("HPRE_GET_DMA_PAGE ioctl fail!\n");
			return -1;
		}
		fd = open("/dev/mem", O_RDWR, 0);
		if (fd < 0) {
			printf("\n%s():Can't open /dev/mem!", __func__);
			return -1;
		}
		dma_buf = mmap((void *)0x0, HPRE_DMA_PAGE, PROT_READ |
			       PROT_WRITE,
			       MAP_SHARED, fd, info->dma_page);
		if (!dma_buf || dma_buf == MAP_FAILED) {
			close(fd);
			printf("\nmmap dma buf fail!");
			return -1;
		}
		memset(dma_buf, 0, HPRE_DMA_PAGE);
		temp = (__u64)info->dma_page;
		close(fd);
	/* For HPRE, we choose to copy user data. */
	} else {
		dma_buf = mmap((void *)0x0, HPRE_DMA_PAGE, PROT_READ |
			       PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (!dma_buf) {
			printf("\nmmap dma buf fail!");
			return -1;
		}
		memset(dma_buf, 0, HPRE_DMA_PAGE);
		ret = wd_mem_share(q, (const void *)dma_buf, HPRE_DMA_PAGE, 0);
		if (ret) {
			printf("\nwd_mem_share dma buf fail!");
			return ret;
		}
		temp = (__u64)dma_buf;
	}
	info->dma_buf = dma_buf;
	info->cache_sqe.low_key = (__u32)(temp & 0xffffffff);
	info->cache_sqe.hi_key = (__u32)((temp >> 32) & 0xffffffff);
	temp += 2048;
	info->cache_sqe.low_in = (__u32)(temp & 0xffffffff);
	info->cache_sqe.hi_in = (__u32)((temp >> 32) & 0xffffffff);
	temp += 512;
	info->cache_sqe.low_out = (__u32)(temp & 0xffffffff);
	info->cache_sqe.hi_out = (__u32)((temp >> 32) & 0xffffffff);

	return 0;
}

static int hpre_uninit_cache_buf(struct wd_queue *q)
{
	struct hpre_queue_info *info = q->priv;
	int ret;

	if (q->dma_flag & VFIO_SPIMDEV_DMA_PHY) {
		munmap(info->dma_buf, HPRE_DMA_PAGE);
		ret = ioctl(q->fd, HPRE_PUT_DMA_PAGES, &info->dma_page);
		if (ret == -1) {
			printf("HPRE_PUT_DMA_PAGE ioctl fail!\n");
			return -1;
		}
	} else {
		wd_mem_unshare(q, (const void *)info->dma_buf, HPRE_DMA_PAGE);
		munmap(info->dma_buf, HPRE_DMA_PAGE);
	}

	return 0;
}

int hpre_set_queue_dio(struct wd_queue *q)
{
	struct hpre_queue_info *info;
	void *vaddr;
	int ret;

	info = malloc(sizeof(struct hpre_queue_info));
	if (!info)
		return -ENOMEM;
	memset((void *)info, 0, sizeof(*info));
	q->priv = info;
	vaddr = mmap(NULL,
		HPRE_SQE_SIZE * HPRE_EQ_DEPTH + HPRE_CQE_SIZE * HPRE_EQ_DEPTH,
		PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 4096);
	if (vaddr <= 0) {
		ret = -EIO;
		goto err_with_info;
	}
	info->sq_base = vaddr;
	info->cq_base = vaddr + HPRE_SQE_SIZE * HPRE_EQ_DEPTH;
	info->sqn = *(__u32 *)vaddr;
	info->ver = *((__u32 *)vaddr + 1);
	*(__u64 *)vaddr = 0;
	vaddr = mmap(NULL, HPRE_IOMEM_SIZE,
		PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
	if (vaddr <= 0) {
		ret = -EIO;
		goto err_with_scq;
	}

	/* Only support version 2 */
	if (info->ver == 2) {
		info->db = hpre_db_v2;
		info->doorbell_base = vaddr + HPRE_DOORBELL_OFFSET_V2;
	} else {
		ret = -ENODEV;
		munmap(vaddr, HPRE_IOMEM_SIZE);
		goto err_with_scq;
	}
	info->sq_tail_index = 0;
	info->sq_head_index = 0;
	info->cq_head_index = 0;
	info->cqc_phase = 1;
	info->is_sq_full = 0;

	info->recv = malloc(HPRE_EQ_DEPTH * sizeof(struct wd_rsa_msg));
	if (!info->recv) {
		ret = -ENOMEM;
		goto err_with_scq;
	}
	memset(info->recv, 0, HPRE_EQ_DEPTH * sizeof(struct wd_rsa_msg));
	ret = hpre_init_cache_buf(q);
	if (ret)
		goto init_cache_fail;

	return ret;

init_cache_fail:
	(void)hpre_uninit_cache_buf(q);
err_with_scq:
	munmap(info->sq_base,
	       HPRE_SQE_SIZE * HPRE_EQ_DEPTH + HPRE_CQE_SIZE * HPRE_EQ_DEPTH);
err_with_info:
	free(info);
	return ret;
}

void hpre_unset_queue_dio(struct wd_queue *q)
{
	struct hpre_queue_info *info = q->priv;
	int ret;

	ret = hpre_uninit_cache_buf(q);
	if (ret)
		return;

	if (info->ver == 2)
		munmap(info->doorbell_base - HPRE_DOORBELL_OFFSET_V2,
		       HPRE_IOMEM_SIZE);

	munmap(info->sq_base, (HPRE_CQE_SIZE + HPRE_SQE_SIZE) * HPRE_EQ_DEPTH);
	free(info->recv);
	free(info);
	q->priv = NULL;
}

int hpre_add_to_dio_q(struct wd_queue *q, void *req)
{
	struct wd_rsa_msg *msg = req;
	struct hpre_queue_info *info = q->priv;
	__u16 i;
	struct wd_rsa_msg *recv_msg;

	if (info->is_sq_full)
		return -EBUSY;

	i = info->sq_tail_index;
	recv_msg = info->recv + i * sizeof(struct wd_rsa_msg);
	recv_msg->out = msg->out;
	recv_msg->udata = msg->udata;
	hpre_fill_sqe(msg, q, i);

	/* memory barrier */
	mb()

	if (i == (HPRE_EQ_DEPTH - 1))
		i = 0;
	else
		i++;

	info->db(info, DOORBELL_CMD_SQ, i, 0);

	info->sq_tail_index = i;

	if (i == info->sq_head_index)
		info->is_sq_full = 1;

	return 0;
}

int hpre_get_from_dio_q(struct wd_queue *q, void **resp)
{
	struct hpre_queue_info *info = q->priv;
	__u16 i = info->cq_head_index;
	struct hpre_cqe *cq_base = info->cq_base;
	struct hpre_sqe *sq_base = info->sq_base;
	struct hpre_cqe *cqe = cq_base + i;
	struct hpre_sqe *sqe;
	struct wd_rsa_msg *recv_msg = info->recv +
		i * sizeof(struct wd_rsa_msg);
	int ret;

	if (info->cqc_phase == HPRE_CQE_PHASE(cqe)) {
		sqe = sq_base + HPRE_CQE_SQ_HEAD_INDEX(cqe);
		ret = hpre_recv_sqe(q, sqe, recv_msg);
		if (ret < 0) {
			hpre_sqe_dump(q, sqe);
			return -EIO;
		}
		if (info->is_sq_full)
			info->is_sq_full = 0;

	} else {
		return 0;
	}
	if (i == (HPRE_EQ_DEPTH - 1)) {
		info->cqc_phase = !(info->cqc_phase);
		i = 0;
	} else {
		i++;
	}

	info->db(info, DOORBELL_CMD_CQ, i, 0);
	info->cq_head_index = i;
	info->sq_head_index = i;
	*resp = recv_msg;

	return ret;
}

int hpre_get_capa(struct wd_capa *capa)
{
	if (capa && !strncmp(capa->alg, "rsa", 3)) {
		capa->latency = 10;
		capa->throughput = 10;

		/* capa->priv is to be extended */
		return 0;
	} else if (capa && !strncmp(capa->alg, "dh", 2)) {
		capa->latency = 10;
		capa->throughput = 10;

		/* capa->priv is to be extended */
		return 0;
	}

	return -ENODEV;
}

#if (defined(HAVE_DYNDRV) & HAVE_DYNDRV)
static struct wd_drv_dio_if hpre_dio_tbl = {
	.hw_type = "hisi_hpre",
	.open = hpre_set_queue_dio,
	.close = hpre_unset_queue_dio,
	.send = hpre_add_to_dio_q,
	.recv = hpre_get_from_dio_q,
	.get_capa = hpre_get_capa,
};

void __attribute__ ((constructor)) wd_load_hpre_init(void)
{
	int ret;

	ret = wd_drv_dio_tbl_set(&hpre_dio_tbl);
	if (ret) {
		printf("Load hisilicon hpre user driver fail!\n");
		return;
	}
}
#endif
