/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NET_OENETCLS_H
#define _NET_OENETCLS_H
#include <linux/if.h>
#include <linux/mutex.h>
#include <linux/cpufeature.h>

#define OECLS_MAX_NETDEV_NUM 8
#define OECLS_MAX_RXQ_NUM_PER_DEV 256
#define OECLS_MAX_NUMA_NUM 16
#define OECLS_MAX_CPU_NUM 1024

#define OECLS_TIMEOUT (5 * HZ)
#define OECLS_NO_FILTER 0xffff
#define OECLS_NO_CPU 0xffff

struct oecls_netdev_queue_info {
	int irq;
	int affinity_cpu;
};

struct oecls_netdev_info {
	char				dev_name[IFNAMSIZ];
	struct net_device		*netdev;
	int				rxq_num;
	struct oecls_netdev_queue_info	rxq[OECLS_MAX_RXQ_NUM_PER_DEV];
	int				old_filter_state;
};

struct oecls_numa_bound_dev_info {
	DECLARE_BITMAP(bitmap_rxq, OECLS_MAX_RXQ_NUM_PER_DEV);
};

struct oecls_numa_info {
	DECLARE_BITMAP(avail_cpus, OECLS_MAX_CPU_NUM);
	struct oecls_numa_bound_dev_info bound_dev[OECLS_MAX_NETDEV_NUM];
};

struct cmd_context {
	char netdev[IFNAMSIZ];
	u32 dip4;
	u16 dport;
	u16 action;
	u32 ruleid;
	u32 del_ruleid;
	int ret_loc;
};

#define OECLS_SK_RULE_HASHSIZE	256
#define OECLS_SK_RULE_HASHMASK	(OECLS_SK_RULE_HASHSIZE - 1)

struct oecls_sk_rule_list {
	struct hlist_head hash[OECLS_SK_RULE_HASHSIZE];
	/* Mutex to synchronize access to ntuple rule locking */
	struct mutex mutex;
};

struct oecls_sk_rule {
	struct hlist_node node;
	int devid;
	void *sk;
	int dip4;
	int dport;
	int action;
	int ruleid;
	int nid;
};

struct oecls_dev_flow {
	unsigned short cpu;
	unsigned short filter;
	unsigned int last_qtail;
	int isvalid;
	unsigned long timeout;
};

struct oecls_dev_flow_table {
	unsigned int	mask;
	struct rcu_head rcu;
	struct oecls_dev_flow flows[];
};

struct oecls_sock_flow_table {
	u32 mask;
	u32 ents[] ____cacheline_aligned_in_smp;
};

#define OECLS_DEV_FLOW_TABLE_NUM	0x1000
#define OECLS_SOCK_FLOW_TABLE_NUM	0x100000
#define OECLS_DEV_FLOW_TABLE_SIZE(_num) (sizeof(struct oecls_dev_flow_table) + \
		((_num) * sizeof(struct oecls_dev_flow)))
#define OECLS_SOCK_FLOW_TABLE_SIZE(_num) (offsetof(struct oecls_sock_flow_table, ents[_num]))

#define ETH_ALL_FLAGS	(ETH_FLAG_LRO | ETH_FLAG_RXVLAN | ETH_FLAG_TXVLAN | \
			  ETH_FLAG_NTUPLE | ETH_FLAG_RXHASH)
#define ETH_ALL_FEATURES (NETIF_F_LRO | NETIF_F_HW_VLAN_CTAG_RX | \
			  NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_NTUPLE | \
			  NETIF_F_RXHASH)

struct rmgr_ctrl {
	int					driver_select;
	unsigned long		*slot;
	__u32				n_rules;
	__u32				size;
};

extern int match_ip_flag;
extern int debug;
extern int oecls_netdev_num;
extern int oecls_numa_num;

#define oecls_debug(fmt, ...)					\
	do {							\
		if (debug)					\
			trace_printk(fmt, ## __VA_ARGS__);	\
	} while (0)

#define oecls_error(fmt, ...) \
	do { \
		pr_err("oenetcls [%s:%d]: " fmt, __FILE__, __LINE__, ## __VA_ARGS__); \
		trace_printk(fmt, ## __VA_ARGS__); \
	} while (0)

struct oecls_netdev_info *get_oecls_netdev_info(unsigned int index);

#define for_each_oecls_netdev(devid, oecls_dev) \
	for (devid = 0, oecls_dev = get_oecls_netdev_info(devid); \
		(devid < oecls_netdev_num) && oecls_dev; \
		devid++, oecls_dev = get_oecls_netdev_info(devid))

struct oecls_numa_info *get_oecls_numa_info(unsigned int nid);

#define for_each_oecls_numa(nid, numa_info) \
	for (nid = 0, numa_info = get_oecls_numa_info(nid); \
		(nid < oecls_numa_num) && numa_info; \
		nid++, numa_info = get_oecls_numa_info(nid))

#ifdef CONFIG_ARM64_SVE
void *__memcpy_aarch64_sve(void *, const void *, size_t);
#define memcpy_r(dst, src, len)					\
	do {							\
		if (system_supports_sve())			\
			__memcpy_aarch64_sve(dst, src, len);	\
		else						\
			memcpy(dst, src, len);			\
	} while (0)
#else
#define memcpy_r(dst, src, len) memcpy(dst, src, len)
#endif

int check_appname(char *task_name);
int send_ethtool_ioctl(struct cmd_context *ctx, void *cmd);
int alloc_rxq_id(int nid, int devid);
void free_rxq_id(int nid, int devid, int rxq_id);
void oecls_ntuple_res_init(void);
void oecls_ntuple_res_clean(void);
void oecls_flow_res_init(void);
void oecls_flow_res_clean(void);

#define L0_MAX_PAGE_SIZE (8192)
#define L0_MAX_PAGE_NUM  (4096)

struct l0_vma_data {
	struct page *page;
	unsigned long size;
	int nid;
};

void clean_oecls_l0_cache(void);
void init_oecls_l0_cache(void);
void *alloc_from_l0(int size);
void free_to_l0(void *addr);
int l3t_shared_lock(int nid, unsigned long pfn, unsigned long size);
int l3t_shared_unlock(int nid, unsigned long pfn, unsigned long size);

#endif	/* _NET_OENETCLS_H */
