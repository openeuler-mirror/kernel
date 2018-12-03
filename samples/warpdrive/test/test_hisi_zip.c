// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <string.h>
#define __USE_GNU
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "../wd.h"
#include "comp_hw.h"
#include "../drv/hisi_zip_udrv.h"

#define TEST_MORE	1

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)

#define ASIZE (8*512*4096)	/*16MB*/

#define SYS_ERR_COND(cond, msg)		\
do {					\
	if (cond) {			\
		perror(msg);		\
		exit(EXIT_FAILURE);	\
	}				\
} while (0)

#define ZLIB 0
#define GZIP 1

#define CHUNK 65535
#define TEST_MAX_THRD		8
#define THR_2_CPUID(i)		(1 + (i) * 13)
#define CPUID_2_THR(i)		(((i) - 1) / 13)

static pthread_t request_release_q_thrds[TEST_MAX_THRD];
static int thd_cpuid[TEST_MAX_THRD];
static char exp_test;

int hizip_comp_test(FILE *source, FILE *dest,  int alg_type, int op_type)
{
	__u64 in, out;
	struct wd_queue q, *queue;
	struct hisi_zip_msg msg, *recv_msg;
	void *a, *b;
	char *src, *dst;
	int ret, total_len;
	int output_num, recv_count = 0;
	int fd, file_msize;
	struct stat s;
	struct timeval start_tval, end_tval;
	float time;

	/* add zlib compress head and write head + compressed date to a file */
	const char zip_head[2] = {0x78, 0x9c};
	const char gzip_head[10] = {0x1f, 0x8b, 0x08, 0x0,
				    0x0, 0x0, 0x0, 0x0, 0x0, 0x03};
	fd = fileno(source);
	if (fstat(fd, &s) < 0) {
		close(fd);
		ret = -EBADF;
		SYS_ERR_COND(ret, "fd error!");
	}

	total_len = s.st_size;
	if (!total_len) {
		ret = -EINVAL;
		fputs("invalid or incomplete deflate data!\n", stderr);
		return ret;
	}
	if (total_len > 0x800000) {
		ret = -EINVAL;
		fputs("file size more than 8M!invalid input!\n", stderr);
		return ret;
	}
#ifdef TEST_MORE
	struct wd_queue q1;
	static int q1_tested;
#endif
	memset((void *)&msg, 0, sizeof(msg));
	memset(&q, 0, sizeof(q));
	q.container = -1;
	if (alg_type == ZLIB) {
		q.capa.alg = "zlib";
		msg.dw9 = 2;
	} else if (alg_type == GZIP) {
		msg.dw9 = 3;
		q.capa.alg = "gzip";
	}
	q.capa.latency = 10;
	q.capa.throughput = 0;
	q.capa.flags = op_type;
	ret = wd_request_queue(&q);
	SYS_ERR_COND(ret, "wd_request q fail!");
	fprintf(stderr, "q: node_id=%d, dma_flag=%d\n", q.node_id, q.dma_flag);
#ifdef TEST_MORE
	memset(&q1, 0, sizeof(q1));
	q1.capa.alg = q.capa.alg;
	q1.capa.latency = 10;
	q1.capa.throughput = 0;
	q1.container = -1;
	q1.capa.flags = q.capa.flags;
	ret = wd_request_queue(&q1);
	SYS_ERR_COND(ret, "wd_request q1 fail!");
	fprintf(stderr, "q1: node_id=%d, dma_flag=%d\n",
		q1.node_id, q1.dma_flag);
#endif
	file_msize = !(total_len % PAGE_SIZE) ? total_len :
			(total_len / PAGE_SIZE + 1) * PAGE_SIZE;
	/* mmap file and  DMA mapping */
	a = mmap((void *)0x0, file_msize, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE, fd, 0);
	if (!a) {
		fputs("mmap file fail!\n", stderr);
		goto release_q;
	}
	ret = wd_mem_share(&q, a, file_msize, 0);
	if (ret) {
		fprintf(stderr, "wd_mem_share dma a buf fail!err=%d\n", -errno);
		goto unmap_file;
	}
	/* Allocate some space and setup a DMA mapping */
	b = mmap((void *)0x0, ASIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (!b) {
		fputs("mmap b fail!\n", stderr);
		goto unshare_file;
	}
	memset(b, 0, ASIZE);
	ret = wd_mem_share(&q, b, ASIZE, 0);
	if (ret) {
		fputs("wd_mem_share dma b buf fail!\n", stderr);
		goto unmap_mem;
	}
	src = (char *)a;
	dst = (char *)b;

	if (op_type == WD_COMPRESS)
		in = (__u64)src;
	else {
		if (alg_type == ZLIB) {
			in = (__u64)src + 2;
			total_len -= 2;
		} else {
			in = (__u64)src + 10;
			total_len -= 10;
		}
	}

	out = (__u64)dst;
	msg.source_addr_l = in & 0xffffffff;
	msg.source_addr_h = in >> 32;
	msg.dest_addr_l = out & 0xffffffff;
	msg.dest_addr_h = out >> 32;
	msg.input_date_length = total_len;
	msg.dest_avail_out = 0x800000;
	queue = &q;
test_q1:
	gettimeofday(&start_tval, NULL);
	ret = wd_send(queue, &msg);
	if (ret < 0) {
		fputs("wd send fail!\n", stderr);
		goto unshare_all;
	}
recv_again:
	ret = wd_recv(queue, (void **)&recv_msg);
	if (ret < 0) {
		fprintf(stderr, "wd recevice q%d fail!\n", q1_tested);
		goto unshare_all;
	/* synchronous mode, if get none, then get again */
	} else if (ret == 0) {
		recv_count++;
		goto recv_again;
	}
	gettimeofday(&end_tval, NULL);
	time = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		end_tval.tv_usec - start_tval.tv_usec);
	output_num = recv_msg->produced;
	if (output_num == 0 || output_num > 0x800000) {
		fprintf(stderr, "q%d compressing fail!output_size =%d!\n",
			q1_tested, output_num);
		goto unshare_all;
	}
	fprintf(stderr, "q%d intput %dB output %dB,re_cnt=%d, %0.0fus!\n",
		q1_tested, total_len, output_num, recv_count, time);
#ifdef TEST_MORE
	if (!q1_tested) {
		recv_msg->produced = 0;
		queue = &q1;
		q1_tested = 1;
		recv_count = 0;
		goto test_q1;
	}
#endif
	if (op_type == WD_COMPRESS) {
		if (alg_type == ZLIB)
			fwrite(zip_head, 1, 2, dest);
		else
			fwrite(gzip_head, 1, 10, dest);
	}

	fwrite((char *)out, 1, output_num, dest);
	fclose(dest);

unshare_all:
	wd_mem_unshare(&q, b, ASIZE);
unmap_mem:
	munmap(b, ASIZE);
unshare_file:
	wd_mem_unshare(&q, a, file_msize);
unmap_file:
	munmap(a, file_msize);
release_q:
	wd_release_queue(&q);

#ifdef TEST_MORE
	wd_release_queue(&q1);
#endif
	return ret;
}

/* multiple threads on queue management testing */
void  *test_q_mng_thread(void *data)
{
	struct wd_queue q;
	int ret;
	__u64 cnt = 0;
	cpu_set_t mask;
	int cpuid = *(int *)data;

	CPU_ZERO(&mask);
	CPU_SET(cpuid, &mask);
	if (pthread_setaffinity_np(pthread_self(), sizeof(mask),
				&mask) < 0) {
		perror("pthread_setaffinity_np");
	}

	while (1) {
		memset(&q, 0, sizeof(q));
		q.capa.throughput = 0;
		q.capa.latency = 10;
		q.container = -1;

		if (cnt & 1)
			q.capa.alg = "zlib";
		else
			q.capa.alg = "gzip";
		ret = wd_request_queue(&q);
		if (ret) {
			WD_ERR("\ntid(%d) request queue at %lld fail!",
			       (int)syscall(__NR_gettid), cnt);
			return NULL;
		}
		cnt++;
		if (!(cnt & 0x1ff))
			fprintf(stderr, "\ntid(%d) request %lld queues nd=%d",
				(int)syscall(__NR_gettid), cnt, q.node_id);
		usleep(10);
		wd_release_queue(&q);
		if (cnt > 0xffff) {
			(void)__atomic_add_fetch(&exp_test, 1,
						 __ATOMIC_ACQUIRE);
			break;
		}
	}

	return NULL;
}

void  *test_devs_max_q(void)
{
	struct wd_queue q;
	int ret, cnt = 0;

	while (1) {
		memset(&q, 0, sizeof(q));
		q.capa.throughput = 0;
		q.capa.latency = 10;
		q.container = -1;

		if (cnt & 1)
			q.capa.alg = "zlib";
		else
			q.capa.alg = "gzip";
		ret = wd_request_queue(&q);
		if (ret) {
			WD_ERR("\ntid(%d) request queue at %d fail!",
			       (int)syscall(__NR_gettid), cnt);
			return NULL;
		}
		cnt++;
	}

	return NULL;
}

void multiple_thread_test(int cpuid)
{
	int i, ret;

/* To test the multiple threads feature */
	if (cpuid == 0) {
		for (i = 0; i < TEST_MAX_THRD; i++) {
			thd_cpuid[i] = THR_2_CPUID(i);
			ret = pthread_create(&request_release_q_thrds[i], NULL,
				  test_q_mng_thread, &thd_cpuid[i]);
			if (ret) {
				fprintf(stderr,
				"\npthread_create %dth thread fail!", i);
				return -1;
			}
		}
		for (i = 0; i < TEST_MAX_THRD; i++) {
			ret = pthread_join(request_release_q_thrds[i], NULL);
			if (ret) {
				fprintf(stderr,
				"\npthread_join %dth thread fail!", i);
				return -1;
			}
		}
		while (exp_test < TEST_MAX_THRD)
			usleep(10000);

		test_devs_max_q();
	}
}

int main(int argc, char *argv[])
{
	int alg_type = 0;
	int op_type = 0;
	cpu_set_t mask;
	int cmd = 0;
	int cpuid = 0;

	CPU_ZERO(&mask);
	if (argv[2]) {
		cpuid = strtoul(argv[2], NULL, 10);
		if (cpuid <= 0 || cpuid > 128) {
			fputs("set cpu no affinity!\n", stderr);
			goto no_affinity;
		}
		CPU_SET(cpuid, &mask);
		if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
			perror("sched_setaffinityfail!");
			return -1;
		}
	}
no_affinity:
	/* avoid end-of-line conversions */
	SET_BINARY_MODE(stdin);
	SET_BINARY_MODE(stdout);

	if (!argv[1]) {
		fputs("<<use ./test_hisi_zip -h get more details>>\n", stderr);
		goto EXIT;
	}

	if (!strcmp(argv[1], "-z")) {
		alg_type = ZLIB;
		op_type = WD_COMPRESS;
	} else if (!strcmp(argv[1], "-zd")) {
		alg_type = ZLIB;
		op_type = WD_DECOMPRESS;
	} else if (!strcmp(argv[1], "-g")) {
		alg_type = GZIP;
		op_type = WD_COMPRESS;
	} else if (!strcmp(argv[1], "-gd")) {
		alg_type = GZIP;
		op_type = WD_DECOMPRESS;
	} else if (!strcmp(argv[1], "-t")) {
		cmd = 1;
	} else if (!strcmp(argv[1], "-h")) {
		fputs("[version]:1.0.2\n", stderr);
		fputs("[usage]: ./test_hisi_zip [type] <src_file> dest_file\n",
			stderr);
		fputs("     [type]:\n", stderr);
		fputs("            -z  = zlib\n", stderr);
		fputs("            -g  = gzip\n", stderr);
		fputs("            -h  = usage\n", stderr);
		fputs("Example:\n", stderr);
		fputs("./test_hisi_zip -z < test.data > out.data\n", stderr);
		goto EXIT;
	} else {
		fputs("Unknow option\n", stderr);
		fputs("<<use ./test_hisi_zip -h get more details>>\n",
			stderr);
		goto EXIT;
	}

	switch (cmd) {
	case 0:
		hizip_comp_test(stdin, stdout, alg_type, op_type);
		break;
	case 1:
		multiple_thread_test(cpuid);
		break;
	default:
		fputs("default cmd!\n", stderr);
	}

EXIT:
	return EXIT_SUCCESS;
}
