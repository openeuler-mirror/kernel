/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __WD_H
#define __WD_H
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "../../include/uapi/linux/vfio.h"
#include "../../include/uapi/linux/vfio_spimdev.h"

#define UUID_STR_SZ		36
#define SYS_VAL_SIZE		64
#define PATH_STR_SIZE		256
#define WD_NAME_SZ		64
#define WD_MAX_MEMLIST_SZ	128


#ifndef dma_addr_t
#define dma_addr_t __u64
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef WD_ERR
#define WD_ERR(format, args...) fprintf(stderr, format, ##args)
#endif
#define WD_CAPA_PRIV_DATA_SIZE	64

/* Queue Capabilities header */
struct wd_capa {
	char *alg;
	__u32 throughput;
	__u32 latency;
	__u32 flags;
	__u32 ver;/* Used for checking WD version */
	__u8 priv[WD_CAPA_PRIV_DATA_SIZE];
};

struct wd_queue {
	int hw_type_id;
	int dma_flag;
	struct wd_capa capa;
	void *priv; /* private data used by the drv layer */
	void *alg_info;
	void *ctx;
	int container;
	int group;
	int mdev;
	int fd;
	int pasid;
	int iommu_type;
	int node_id;
	int numa_dis;
	__u16 is_new_group;
	__u16 is_ext_container;
	int type;
	char mdev_name[WD_NAME_SZ];
	char hw_type[WD_NAME_SZ];
	char vfio_group_path[PATH_STR_SIZE];
};

extern int wd_request_queue(struct wd_queue *q);
extern void wd_release_queue(struct wd_queue *q);
extern int wd_send(struct wd_queue *q, void *req);
extern int wd_recv(struct wd_queue *q, void **resp);
extern void wd_flush(struct wd_queue *q);
extern int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms);
extern int wd_mem_share(struct wd_queue *q, const void *addr,
			size_t size, int flags);
extern void wd_mem_unshare(struct wd_queue *q, const void *addr, size_t size);

/* for debug only */
extern int wd_dump_all_algos(void);

/* this is only for drv used */
extern int wd_set_queue_attr(struct wd_queue *q, const char *name,
				char *value);
extern int __iommu_type(struct wd_queue *q);

#endif
