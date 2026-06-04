/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NET_OENETCLS_H
#define _NET_OENETCLS_H
#include <linux/if.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/cpufeature.h>

#define OECLS_MAX_NETDEV_NUM 8
#define OECLS_MAX_RXQ_NUM_PER_DEV 256
#define OECLS_MAX_CPU_NUM 1024

#define OECLS_TIMEOUT (5 * HZ)
#define OECLS_NO_FILTER 0xffff
#define OECLS_NO_CPU 0xffff

#define OECLS_CMD_UNKNOWN      0
#define OECLS_CMD_MATCHED      1
#define OECLS_CMD_NO_MATCH     2

#define RXQ_MAX_USECNT        0xFF

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

struct oecls_rxq {
	int rxq_id;
	int status;
};

struct oecls_numa_clusterinfo {
	int cluster_id;
	int cur_freeidx;
	struct oecls_rxq rxqs[OECLS_MAX_RXQ_NUM_PER_DEV];
};

struct oecls_numa_bound_dev_info {
	unsigned char bitmap_rxq[OECLS_MAX_RXQ_NUM_PER_DEV];
	struct oecls_numa_clusterinfo *cluster_info;
};

struct oecls_numa_info {
	DECLARE_BITMAP(avail_cpus, OECLS_MAX_CPU_NUM);
	struct oecls_numa_bound_dev_info bound_dev[OECLS_MAX_NETDEV_NUM];
};

struct cmd_context {
	char netdev[IFNAMSIZ];
	bool is_ipv6;
	u32 dip4;
	u32 dip6[4];
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
	bool is_ipv6;
	u32 dip4;
	u32 dip6[4];
	u16 dport;
	int action;
	int ruleid;
	int nid;
};

struct oecls_sk_entry {
	struct hlist_node node;
	void *sk;
	u32 sk_rule_hash;
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

struct cfg_param {
	struct work_struct work;
	struct cmd_context ctx;
	struct sock *sk;
	struct {
		struct net *net;
		u16 family;
		u16 lport;
		__be32 rcv_saddr_v4;
		struct in6_addr rcv_saddr_v6;
	} sk_snapshot;
	bool is_del;
	int nid;
	int cpu;
};

extern int match_ip_flag;
extern int debug;
extern int mode;
extern int rcpu_probability;
extern int oecls_netdev_num;
extern int oecls_numa_num;
extern int check_nic_feature;
extern unsigned int dft_num;
extern unsigned int sft_num;
extern int rps_policy;
extern int lo_rps_policy;

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
int oecls_ntuple_res_init(void);
void oecls_ntuple_res_clean(void);
int oecls_flow_res_init(void);
void oecls_flow_res_clean(void);
void _oecls_flow_update(struct sock *sk, struct sk_buff *skb);
void _oecls_set_cpu(struct sk_buff *skb, int *cpu, int *last_qtail);

#endif	/* _NET_OENETCLS_H */
