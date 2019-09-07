/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __HI1610_ROCE_KTEST_H__
#define __HI1610_ROCE_KTEST_H__

#define DFX_DEVICE_NAME "rdma_dfx"

#ifndef SYSFS_PAGE_SIZE
#define SYSFS_PAGE_SIZE	(4096)           /* sysfs�ļ��Ĵ�С */
#endif
#define SYSFS_MAX_PARA	(16)
#define MAX_IB_DEV	(12)
#define CQE_SIZE	(32)

#define DEF_OPT_STR_LEN	(10)

int rdfx_add_common_sysfs(struct device *p_dev);
void rdfx_del_common_sysfs(void);

int parg_getopt(char *input, char *optstring, char *parg);
char *strtok(char *s, const char *delim);
int str_to_ll(char *p_buf, unsigned long long *pll_val, unsigned int *num);
int str_match(char *s, const char *delim);
int check_input(char *buf, unsigned long long *a_val, unsigned int max,
		unsigned int min, unsigned int *param_num);
struct rdfx_info *rdfx_find_rdfx_info(char *dev_name);

struct dfx_buf_list {
	void		*buf;
	dma_addr_t	map;
};

struct dfx_buf {
	struct dfx_buf_list	direct;
	struct dfx_buf_list	*page_list;
	int			nbufs;
	u32			npages;
	unsigned int			page_shift;
};

extern struct rdfx_ops rdfx_ops_hw_v2;

void *rdfx_buf_offset(struct dfx_buf *buf, int offset);

#endif
