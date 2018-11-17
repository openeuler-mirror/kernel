// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>

#include "./openssl/bn.h"
#include "./openssl/rsa.h"
#include "../wd.h"
#include "../wd_rsa.h"

static int dbg_thrd_num;
static int key_bits = 4096;
#define  TEST_MAX_THRD		8
#define TEST_THRDS_NUM		dbg_thrd_num
static pthread_t request_release_q_thrds[TEST_MAX_THRD];

#define DEBUG_NOIOMMU

#define ASIZE			(16 * 4096)

#define SYS_ERR_COND(cond, msg)		\
do {					\
	if (cond) {			\
		perror(msg);		\
		exit(EXIT_FAILURE);	\
	}				\
} while (0)

#define OP_NUMBER		4000
#define RSA_KEY_BITS		key_bits
struct test_wd_bn {
	unsigned long long  *d;
	int top;

	/* The next are internal book keeping for bn_expand. */
	int dmax;
	int neg;
	int flags;
};

static inline __u64 test_const_bswap64(__u64 ullTmp)
{
	return	((ullTmp & 0x00000000000000ffULL) << 56) |
		((ullTmp & 0x000000000000ff00ULL) << 40) |
		((ullTmp & 0x0000000000ff0000ULL) << 24) |
		((ullTmp & 0x00000000ff000000ULL) <<  8) |
		((ullTmp & 0x000000ff00000000ULL) >>  8) |
		((ullTmp & 0x0000ff0000000000ULL) >> 24) |
		((ullTmp & 0x00ff000000000000ULL) >> 40) |
		((ullTmp & 0xff00000000000000ULL) >> 56);
}


void test_rsa_bn_endian_swap(BIGNUM *p)
{
	struct test_wd_bn *b = (struct test_wd_bn *)p;
	int i;

	for (i = 0; i < ((struct test_wd_bn *)b)->top; i++)
		((struct test_wd_bn *)b)->d[i] =
		test_const_bswap64(((struct test_wd_bn *)b)->d[i]);
}
int test_rsa_key_gen(void *ctx)
{
	BIGNUM *p, *q, *e_value, *n, *e, *d, *dmp1, *dmq1, *iqmp;
	int ret, bits;
	RSA *test_rsa;
	union wd_rsa_prikey *prikey;
	struct wd_rsa_pubkey *pubkey;

	bits = wd_rsa_key_bits(ctx);

	test_rsa = RSA_new();
	if (!test_rsa || !bits) {
		WD_ERR("\n RSA new fail!");
		return -1;
	}
	e_value = BN_new();
	if (!e_value) {
		RSA_free(test_rsa);
		WD_ERR("\n BN new e fail!");
		ret = -1;
		return ret;
	}
	ret = BN_set_word(e_value, 65537);
	if (ret != 1) {
		WD_ERR("\n BN_set_word fail!");
		ret = -1;
		goto gen_fail;
	}

	ret = RSA_generate_key_ex(test_rsa, RSA_KEY_BITS, e_value, NULL);
	if (ret != 1) {
		WD_ERR("\n RSA_generate_key_ex fail!");
		ret = -1;
		goto gen_fail;
	}
	RSA_get0_key((const RSA *)test_rsa, (const BIGNUM **)&n,
		       (const BIGNUM **)&e, (const BIGNUM **)&d);
	RSA_get0_factors((const RSA *)test_rsa, (const BIGNUM **)&p,
			 (const BIGNUM **)&q);
	RSA_get0_crt_params((const RSA *)test_rsa, (const BIGNUM **)&dmp1,
			    (const BIGNUM **)&dmq1, (const BIGNUM **)&iqmp);

	wd_get_rsa_pubkey(ctx, &pubkey);
	wd_get_rsa_prikey(ctx, &prikey);

	if (wd_rsa_is_crt(ctx)) {
		BN_bn2bin(dmp1, prikey->pkey2.dp);
		BN_bn2bin(dmq1, prikey->pkey2.dq);
		BN_bn2bin(p, prikey->pkey2.p);
		BN_bn2bin(q, prikey->pkey2.q);
		BN_bn2bin(iqmp, prikey->pkey2.qinv);

	} else {
		BN_bn2bin(d, prikey->pkey1.d);
		BN_bn2bin(n, prikey->pkey1.n);

	}
	BN_bn2bin(e, pubkey->e);
	BN_bn2bin(n, pubkey->n);
	BN_free(e_value);

	return 0;

gen_fail:
	RSA_free(test_rsa);
	BN_free(e_value);

	return ret;
}
void  *test_q_mng_thread(void *data)
{
	struct wd_queue q;
	int ret;
	int container;

	container = *(int *)data;
	memset(&q, 0, sizeof(q));
	q.capa.alg = "rsa";
	q.capa.throughput = 10;
	q.capa.latency = 10;
	q.container = container;
	while (1) {
		ret = wd_request_queue(&q);
		if (ret) {
			WD_ERR("\nwd_request_queue fail!");
			return NULL;
		}
		usleep(100);
		wd_release_queue(&q);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	struct wd_queue q;
	struct wd_rsa_msg *msg;
	void *a, *src, *dst;
	int ret, i, loops;
	int output_num;
	struct timeval start_tval, end_tval;
	float time, speed;
	int mode, dir;
	unsigned int pkt_len;
	void *ctx = NULL;
	struct wd_rsa_ctx_setup setup;
	struct wd_rsa_op_data opdata;
	int is_new_container = 0;
	int container = 0;

	if (argv[1]) {
		key_bits = strtoul(argv[1], NULL, 10);
		if (key_bits != 1024 && key_bits != 2048 &&
		    key_bits != 3072 && key_bits != 4096)
			key_bits = 4096;
	} else {
		key_bits = 4096;
	}

	if (argv[2])
		mode = strtoul(argv[2], NULL, 10);
	else
		mode = 0;

	if (argv[3])
		dir = strtoul(argv[3], NULL, 10);
	else
		dir = 0;
	if (argv[4])
		TEST_THRDS_NUM = strtoul(argv[4], NULL, 10);
	else
		TEST_THRDS_NUM = 0;
	if (argv[5])
		is_new_container = strtoul(argv[5], NULL, 10);
	else
		is_new_container = 0;
	if (TEST_THRDS_NUM > TEST_MAX_THRD)
		TEST_THRDS_NUM = TEST_MAX_THRD;
	pkt_len = (RSA_KEY_BITS >> 3);

	if (is_new_container) {
		container = open("/dev/vfio/vfio", O_RDWR);
		if (container < 0) {
			WD_ERR("Create VFIO container fail!\n");
			return -ENODEV;
		}
	}
	memset(&q, 0, sizeof(q));
	q.capa.alg = "rsa";
	q.capa.throughput = 10;
	q.capa.latency = 10;

	for (i = 0; i < TEST_THRDS_NUM; i++) {
		ret = pthread_create(&request_release_q_thrds[i], NULL,
				     test_q_mng_thread, &container);
		if (ret) {
			printf("\npthread_create %dth thread fail!", i);
			return -1;
		}
	}
	ret = wd_request_queue(&q);
	SYS_ERR_COND(ret, "wd_request_queue");
	printf("\npasid=%d, dma_flag=%d", q.pasid, q.dma_flag);

	setup.alg = "rsa";
	setup.key_bits = RSA_KEY_BITS;
	setup.is_crt = mode;
	setup.cb = NULL;

	ctx = wd_create_rsa_ctx(&q, &setup);
	if (!ctx) {
		WD_ERR("\ncreate rsa ctx fail!");
		goto release_q;
	}
	ret = test_rsa_key_gen(ctx);
	if (ret) {
		wd_del_rsa_ctx(ctx);
		goto release_q;
	}

	/* Allocate some space and setup a DMA mapping */
	a = mmap((void *)0x0, ASIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (!a) {
		wd_del_rsa_ctx(ctx);
		printf("\nmmap fail!");
		goto release_q;
	}
	memset(a, 0, ASIZE);

	/* set input rsa sample data */
	for (i = 0; i < ASIZE / 8; i++)
		*(__u32 *)(a + i * 4) = i;
#ifndef DEBUG_NOIOMMU
	ret = wd_mem_share(&q, a, ASIZE, 0);
	SYS_ERR_COND(ret, "wd_mem_share err\n");
	printf("WD dma map VA=IOVA=%p successfully!\n", a);
#endif
	src = a;
	dst = (char *)a + (ASIZE / 2);

	msg = malloc(sizeof(*msg));
	if (!msg) {
		printf("\nalloc msg fail!");
		goto alloc_msg_fail;
	}
	memset((void *)msg, 0, sizeof(*msg));
	loops = ASIZE / (2 * pkt_len);
	gettimeofday(&start_tval, NULL);
	for (i = 0; i < OP_NUMBER; i++) {
		opdata.in_bytes = pkt_len;
		if (dir)
			opdata.op_type = WD_RSA_SIGN;
		else
			opdata.op_type = WD_RSA_VERIFY;
		opdata.in = src + (i % loops) * pkt_len;
		opdata.out = dst + (i % loops) * pkt_len;
		ret = wd_do_rsa(ctx, &opdata);
		if (ret) {
			free(msg);
			printf("\nwd_do_rsa fail!optimes=%d\n", i);
			goto alloc_msg_fail;
		}
	}
	output_num = opdata.out_bytes;
	if (output_num != pkt_len) {
		free(msg);
		goto alloc_msg_fail;
	}
	gettimeofday(&end_tval, NULL);
	time = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		end_tval.tv_usec - start_tval.tv_usec);
	speed = 1 / (time / OP_NUMBER) * 1000;
	if (mode) {
		printf("\r\nPID(%d):%s CRT mode %dbits sign:",
		       getpid(), "rsa", RSA_KEY_BITS);

		printf("\r\ntime %0.0fus, pktlen = %d bytes, %0.3f Kops",
		       time, pkt_len, speed);
	} else {
		printf("\r\nPID(%d):%s NCRT mode %dbits sign:",
		       getpid(), "rsa", RSA_KEY_BITS);
		printf("\r\ntime %0.0fus, pktlen = %d bytes, %0.3f Kops",
		       time, pkt_len, speed);
	}
	free(msg);

alloc_msg_fail:
	wd_del_rsa_ctx(ctx);
#ifndef DEBUG_NOIOMMU
	wd_mem_unshare(&q, a, ASIZE);
#endif
	munmap(a, ASIZE);
release_q:
	wd_release_queue(&q);
	for (i = 0; i < TEST_THRDS_NUM; i++) {
		ret = pthread_join(request_release_q_thrds[i], NULL);
		if (ret) {
			printf("\npthread_join %dth thread fail!", i);
			return -1;
		}
	}
	return EXIT_SUCCESS;
}
