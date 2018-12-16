// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include "../wd.h"
#include "comp_hw.h"
#include "../drv/hisi_zip_udrv.h"
#include <assert.h>

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

#define HW_CTX_SIZE (64*1024)

#define Z_OK            0
#define Z_STREAM_END    1
#define Z_ERRNO (-1)
#define Z_STREAM_ERROR (-EIO)

#define STREAM_CHUNK 1024
#define STREAM_CHUNK_OUT (64*1024)

#define swab32(x) \
	((((x) & 0x000000ff) << 24) | \
	(((x) & 0x0000ff00) <<  8) | \
	(((x) & 0x00ff0000) >>  8) | \
	(((x) & 0xff000000) >> 24))

#define cpu_to_be32(x) swab32(x)

struct zip_stream {
	struct wd_queue *q;
	int alg_type;
	int stream_pos;
	unsigned char *next_in;   /* next input byte */
	unsigned char *temp_in;   /* temp input byte */
	unsigned long  avail_in;  /* number of bytes available at next_in */
	unsigned long    total_in;  /* total nb of input bytes read so far */
	unsigned char    *next_out;  /* next output byte should be put there */
	unsigned long avail_out; /* remaining free space at next_out */
	unsigned long    total_out; /* total nb of bytes output so far */
	char     *msg;      /* last error message, NULL if no error */
	void     *workspace; /* memory allocated for this stream */
	int     data_type;  /*the data type: ascii or binary */
	unsigned char *ctx_buf;
	int ctx_dw0;
	int ctx_dw1;
	int ctx_dw2;
	int isize;
	int checksum;
	unsigned long   adler;      /* adler32 value of the uncompressed data */
	unsigned long   reserved;   /* reserved for future use */
};

int hw_init(struct zip_stream *zstrm, int alg_type, int comp_optype)
{
	int ret;
	char *dma_buf;
	char *dma_ctx_buf;

	zstrm->q = malloc(sizeof(struct wd_queue));
	if (!zstrm->q) {
		fputs("alloc zstrm fail!\n", stderr);
		return -1;
	}
	memset((void *)zstrm->q, 0, sizeof(struct wd_queue));

	switch (alg_type) {
	case 0:
		zstrm->alg_type = HW_ZLIB;
		zstrm->q->capa.alg = "zlib";
		break;
	case 1:
		zstrm->alg_type = HW_GZIP;
		zstrm->q->capa.alg = "gzip";
		break;
	default:
		zstrm->alg_type = HW_ZLIB;
		zstrm->q->capa.alg = "zlib";
	}
	zstrm->q->container = -1;
	zstrm->q->capa.latency = 10;
	zstrm->q->capa.throughput = 0;
	zstrm->q->capa.flags = comp_optype;
	ret = wd_request_queue(zstrm->q);
	if (ret) {
		fputs("wd_request_queue fail!\n", stderr);
		goto zstrm_q_free;
	}
	SYS_ERR_COND(ret, "wd_request_queue");
	/* Allocate some space and setup a DMA mapping */
	dma_buf = mmap((void *)0x0, ASIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (!dma_buf) {
		fputs("mmap buff fail!\n", stderr);
		goto release_q;
	}
	memset(dma_buf, 0, ASIZE);
	ret = wd_mem_share(zstrm->q, dma_buf, ASIZE, 0);
	if (ret) {
		fputs("wd_mem_share dma buf fail!\n", stderr);
		goto unmap_mem;
	}

	if (comp_optype == HW_INFLATE) {
		/* Allocate  space and setup a DMA map for stream inflate ctx*/
		dma_ctx_buf = mmap((void *)0x0, HW_CTX_SIZE,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (!dma_ctx_buf) {
			fputs("mmap dma_ctx_buf fail!\n", stderr);
			goto release_q;
		}
		memset(dma_ctx_buf, 0, HW_CTX_SIZE);
		ret = wd_mem_share(zstrm->q, dma_ctx_buf, HW_CTX_SIZE, 0);
		if (ret) {
			fputs("wd_mem_share dma_ctx_buf fail!\n", stderr);
			goto unmap_mem;
		}
		zstrm->ctx_buf = (__u64)dma_ctx_buf;
	}
	zstrm->next_in = (__u64)dma_buf;
	zstrm->next_out = (__u64)dma_buf + ASIZE / 2;
	zstrm->workspace = dma_buf;
	zstrm->temp_in = zstrm->next_in;
	return Z_OK;
unmap_mem:
	munmap(dma_buf, ASIZE);
release_q:
	wd_release_queue(zstrm->q);
zstrm_q_free:
	free(zstrm->q);

	return ret;
}

void hw_end(struct zip_stream *zstrm)
{
	wd_mem_unshare(zstrm->q, zstrm->workspace, ASIZE);
	munmap(zstrm->workspace, ASIZE);
	wd_release_queue(zstrm->q);
	free(zstrm->q);
}

unsigned int bit_reverse(register unsigned int x)
{
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));

	return((x >> 16) | (x << 16));
}

/* output an empty store block */
int append_store_block(struct zip_stream *zstrm, int flush)
{
	char store_block[5] = {0x1, 0x00, 0x00, 0xff, 0xff};
	__u32 checksum = zstrm->checksum;
	__u32 isize = zstrm->isize;

	memcpy(zstrm->next_out, store_block, 5);
	zstrm->total_out += 5;
	zstrm->avail_out -= 5;
	if (flush != WD_FINISH)
		return Z_STREAM_END;

	if (zstrm->alg_type == HW_ZLIB) { /*if zlib, ADLER32*/
		checksum = (__u32) cpu_to_be32(checksum);
		memcpy(zstrm->next_out + 5, &checksum, 4);
		zstrm->total_out += 4;
		zstrm->avail_out -= 4;
	} else if (zstrm->alg_type == HW_GZIP) {  /*if gzip, CRC32 and ISIZE*/
		checksum = ~checksum;
		checksum = bit_reverse(checksum);
		memcpy(zstrm->next_out + 5, &checksum, 4);
		memcpy(zstrm->next_out + 9, &isize, 4);
		zstrm->total_out += 8;
		zstrm->avail_out -= 8;
	} else
		fprintf(stderr, "in append store block, wrong alg type %d.\n",
				zstrm->alg_type);

	return Z_STREAM_END;
}

int hw_send_and_recv(struct zip_stream *zstrm, int flush, int comp_optype)
{
	struct hisi_zip_msg *msg, *recv_msg;
	int ret = 0;
	__u64 stream_mode, stream_new, flush_type;

	if (zstrm->avail_in == 0)
		return append_store_block(zstrm, flush);

	msg = malloc(sizeof(*msg));
	if (!msg) {
		fputs("alloc msg fail!\n", stderr);
		goto msg_free;
	}

	stream_mode = STATEFUL;
	stream_new = zstrm->stream_pos;
	flush_type = (flush == WD_FINISH) ? HZ_FINISH : HZ_SYNC_FLUSH;

	memset((void *)msg, 0, sizeof(*msg));
	msg->dw9 = zstrm->alg_type;
	msg->dw7 |= ((stream_new << 2 | stream_mode << 1 |
			flush_type)) << STREAM_FLUSH_SHIFT;
	msg->source_addr_l = (__u64)zstrm->next_in & 0xffffffff;
	msg->source_addr_h = (__u64)zstrm->next_in >> 32;
	msg->dest_addr_l = (__u64)zstrm->next_out & 0xffffffff;
	msg->dest_addr_h = (__u64)zstrm->next_out >> 32;
	msg->input_date_length = zstrm->avail_in;
	msg->dest_avail_out = zstrm->avail_out;
	if (comp_optype == HW_INFLATE) {
		msg->stream_ctx_addr_l = (__u64)zstrm->ctx_buf & 0xffffffff;
		msg->stream_ctx_addr_h = (__u64)zstrm->ctx_buf >> 32;
	}
	msg->ctx_dw0 = zstrm->ctx_dw0;
	msg->ctx_dw1 = zstrm->ctx_dw1;
	msg->ctx_dw2 = zstrm->ctx_dw2;
	msg->isize = zstrm->isize;
	msg->checksum = zstrm->checksum;
	if (zstrm->stream_pos == STREAM_NEW) {
		zstrm->stream_pos = STREAM_OLD;
		zstrm->total_out = 0;
	}
	ret = wd_send(zstrm->q, msg);
	if (ret == -EBUSY) {
		usleep(1);
		goto recv_again;
	}
	SYS_ERR_COND(ret, "send fail!\n");
recv_again:
	ret = wd_recv(zstrm->q, (void **)&recv_msg);
	if (ret < 0) {
		fputs(" wd_recv fail!\n", stderr);
		goto msg_free;
	/* synchronous mode, if get none, then get again */
	} else if (ret == 0)
		goto recv_again;

	zstrm->avail_out -= recv_msg->produced;
	zstrm->total_out += recv_msg->produced;
	zstrm->avail_in -= recv_msg->consumed;
	zstrm->ctx_dw0 = recv_msg->ctx_dw0;
	zstrm->ctx_dw1 = recv_msg->ctx_dw1;
	zstrm->ctx_dw2 = recv_msg->ctx_dw2;
	zstrm->isize = recv_msg->isize;
	zstrm->checksum = recv_msg->checksum;
	if (zstrm->avail_out == 0)
		zstrm->next_in +=  recv_msg->consumed;
	if (zstrm->avail_out > 0) {
		zstrm->avail_in = 0;
		zstrm->next_in = zstrm->temp_in;
	}
	ret = 0;
	if (ret == 0 && flush == WD_FINISH)
		ret = Z_STREAM_END;
	else if (ret == 0 &&  (recv_msg->dw3 & 0x1ff) == 0x113)
		ret = Z_STREAM_END;    /* decomp_is_end  region */

msg_free:
	free(msg);
	return ret;
}

int hw_deflate_ex(struct zip_stream *zstrm, int flush)
{
	return hw_send_and_recv(zstrm, flush, HW_DEFLATE);
}

int hw_inflate_ex(struct zip_stream *zstrm, int flush)
{
	return hw_send_and_recv(zstrm, flush, HW_INFLATE);
}

int hw_stream_def(FILE *source, FILE *dest,  int alg_type)
{
	int flush, have;
	int ret;
	struct zip_stream zstrm;
	const char zip_head[2] = {0x78, 0x9c};
	const char gzip_head[10] = {0x1f, 0x8b, 0x08, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x03};

	ret = hw_init(&zstrm, alg_type, HW_DEFLATE);
	if (ret != Z_OK)
		return ret;
	/* add zlib compress head and write head + compressed date to a file */
	if (alg_type == ZLIB)
		fwrite(zip_head, 1, 2, dest);
	else
		fwrite(gzip_head, 1, 10, dest);

	zstrm.stream_pos = STREAM_NEW;
	do {
		zstrm.avail_in =  fread(zstrm.next_in, 1, STREAM_CHUNK, source);
		flush = feof(source) ? WD_FINISH : WD_SYNC_FLUSH;

		do {
			zstrm.avail_out = STREAM_CHUNK_OUT;
			ret = hw_deflate_ex(&zstrm, flush);
			assert(ret != Z_STREAM_ERROR);
			have = STREAM_CHUNK_OUT - zstrm.avail_out;
			if (fwrite(zstrm.next_out, 1, have, dest) != have ||
				ferror(dest)) {
				(void)hw_end(&zstrm);
				return Z_ERRNO;
			}
		} while (zstrm.avail_out == 0);
		assert(zstrm.avail_in == 0);   /* all input will be used */

		/* done when last data in file processed */
	} while (flush != WD_FINISH);

	assert(ret == Z_STREAM_END);       /* stream will be complete */
	hw_end(&zstrm);
	return Z_OK;
}

int hw_stream_inf(FILE *source, FILE *dest,  int alg_type)
{
	int have;
	int ret;
	char zip_head[2] = {0};
	char gzip_head[10] = {0};
	struct zip_stream zstrm;

	hw_init(&zstrm, alg_type, HW_INFLATE);
	if (alg_type == ZLIB)
		zstrm.avail_in = fread(zip_head, 1, 2, source);
	else
		zstrm.avail_in = fread(gzip_head, 1, 10, source);

	zstrm.stream_pos = STREAM_NEW;
	do {
		zstrm.avail_in = fread(zstrm.next_in, 1, STREAM_CHUNK, source);
		if (ferror(source)) {
			hw_end(&zstrm);
			return Z_ERRNO;
		}
		if (zstrm.avail_in == 0)
			break;
		/* finish compression if all of source has been read in */
		do {
			zstrm.avail_out = STREAM_CHUNK_OUT;
			ret = hw_inflate_ex(&zstrm, WD_SYNC_FLUSH);
			assert(ret != Z_STREAM_ERROR);
			have = STREAM_CHUNK_OUT - zstrm.avail_out;
			if (fwrite(zstrm.next_out, 1, have, dest) != have ||
				ferror(dest)) {
				hw_end(&zstrm);
				return Z_ERRNO;
			}

		} while (zstrm.avail_out == 0);
		assert(zstrm.avail_in == 0);    /* all input will be used */

		/* done when last data in file processed */
	} while (ret != Z_STREAM_END);

	assert(ret == Z_STREAM_END);            /* stream will be complete */
	hw_end(&zstrm);
	return Z_OK;
}

int main(int argc, char *argv[])
{
	int alg_type = 0;
	int cmd = 0;
	int ret;

	/* avoid end-of-line conversions */
	SET_BINARY_MODE(stdin);
	SET_BINARY_MODE(stdout);

	if (!argv[1]) {
		fputs("<<use ./test_hisi_zlib -h get more details>>\n", stderr);
		goto EXIT;
	}

	if (!strcmp(argv[1], "-z")) {
		alg_type = ZLIB;
		cmd = 0;
	} else if (!strcmp(argv[1], "-g")) {
		alg_type = GZIP;
		cmd = 0;
	} else if (!strcmp(argv[1], "-zd")) {
		alg_type = ZLIB;
		cmd = 1;
	} else if (!strcmp(argv[1], "-gd")) {
		alg_type = GZIP;
		cmd = 1;
	} else if (!strcmp(argv[1], "-h")) {
		fputs("[version]:1.0.2\n", stderr);
		fputs("[usage]: ./test_hisi_zlib [type] <src_file> dest_file\n",
			stderr);
		fputs("     [type]:\n", stderr);
		fputs("            -z  = zlib stream compress\n", stderr);
		fputs("            -zd = zlib stream decompress\n", stderr);
		fputs("            -g  = gzip stream compress\n", stderr);
		fputs("            -gd = gzip stream decompress\n", stderr);
		fputs("            -h  = usage\n", stderr);
		fputs("Example:\n", stderr);
		fputs("./test_hisi_zlib -z < test.data > out.data\n", stderr);
		goto EXIT;
	} else {
		fputs("Unknown option\n", stderr);
		fputs("<<use ./test_hisi_zlib -h get more details>>\n",
			stderr);
		goto EXIT;
	}

	switch (cmd) {
	case 0:
		ret = hw_stream_def(stdin, stdout, alg_type);
		if (ret)
			fputs("hw_stream_deflate error!\n", stderr);
		break;
	case 1:
		ret = hw_stream_inf(stdin, stdout, alg_type);
		if (ret)
			fputs("hw_stream_inflate error!\n", stderr);
		break;
	default:
		fputs("default cmd!\n", stderr);
	}
EXIT:
	return EXIT_SUCCESS;
}
