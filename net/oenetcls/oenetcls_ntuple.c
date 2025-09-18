// SPDX-License-Identifier: GPL-2.0-only
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/inet.h>
#include <linux/jhash.h>
#include <net/sock.h>
#include <linux/oenetcls.h>
#include "oenetcls.h"

struct oecls_sk_rule_list oecls_sk_rules, oecls_sk_list;
static struct workqueue_struct *do_cfg_workqueue;
static atomic_t oecls_worker_count = ATOMIC_INIT(0);

static void init_oecls_sk_rules(void)
{
	unsigned int i;

	for (i = 0; i < OECLS_SK_RULE_HASHSIZE; i++)
		INIT_HLIST_HEAD(oecls_sk_rules.hash + i);
	mutex_init(&oecls_sk_rules.mutex);
}

static inline struct hlist_head *get_rule_hashlist(u32 dip4, u16 dport)
{
	return oecls_sk_rules.hash + (jhash_2words(dip4, dport, 0) & OECLS_SK_RULE_HASHMASK);
}

static inline struct hlist_head *get_sk_hashlist(void *sk)
{
	return oecls_sk_list.hash + (jhash(sk, sizeof(sk), 0) & OECLS_SK_RULE_HASHMASK);
}

static void add_sk_rule(int devid, u32 dip4, u16 dport, void *sk, int action, int ruleid, int cpu)
{
	struct hlist_head *hlist = get_rule_hashlist(dip4, dport);
	struct hlist_head *sk_hlist = get_sk_hashlist(sk);
	struct oecls_sk_rule *rule;
	struct oecls_sk_entry *entry;

	rule = alloc_from_l0(sizeof(struct oecls_sk_rule));
	entry = alloc_from_l0(sizeof(struct oecls_sk_entry));
	if (!rule || !entry)
		goto out;

	rule->sk = sk;
	rule->dip4 = dip4;
	rule->dport = dport;
	rule->devid = devid;
	rule->action = action;
	rule->ruleid = ruleid;
	rule->cpu = cpu;
	hlist_add_head(&rule->node, hlist);

	entry->sk = sk;
	entry->sk_rule_hash = jhash_2words(dip4, dport, 0);
	hlist_add_head(&entry->node, sk_hlist);
	return;
out:
	oecls_debug("alloc failed rule:%p entry:%p\n", rule, entry);
	free_to_l0(entry);
	free_to_l0(rule);
}

static struct oecls_sk_entry *get_sk_entry(void *sk)
{
	struct hlist_head *sk_hlist = get_sk_hashlist(sk);
	struct oecls_sk_entry *entry = NULL;

	hlist_for_each_entry(entry, sk_hlist, node) {
		if (entry->sk == sk)
			break;
	}
	return entry;
}

static void del_sk_rule(struct oecls_sk_rule *rule)
{
	struct oecls_sk_entry *entry;

	entry = get_sk_entry(rule->sk);
	if (!entry)
		return;
	hlist_del_init(&entry->node);
	free_to_l0(entry);

	oecls_debug("del rule=%p\n", rule);
	hlist_del_init(&rule->node);
	free_to_l0(rule);
}

static struct oecls_sk_rule *get_sk_rule(int devid, u32 dip4, u16 dport)
{
	struct hlist_head *hlist = get_rule_hashlist(dip4, dport);
	struct oecls_sk_rule *rule = NULL;

	hlist_for_each_entry(rule, hlist, node) {
		if (rule->devid == devid && rule->dip4 == dip4 && rule->dport == dport)
			break;
	}
	return rule;
}

static struct oecls_sk_rule *get_rule_from_sk(int devid, void *sk)
{
	struct oecls_sk_rule *rule = NULL;
	struct oecls_sk_entry *entry;
	struct hlist_head *hlist;

	entry = get_sk_entry(sk);
	if (!entry)
		return NULL;

	hlist = oecls_sk_rules.hash + (entry->sk_rule_hash & OECLS_SK_RULE_HASHMASK);
	hlist_for_each_entry(rule, hlist, node) {
		if (rule->devid == devid && rule->sk == sk)
			break;
	}
	return rule;
}

static inline bool reuseport_check(int devid, u32 dip4, u16 dport)
{
	return !!get_sk_rule(devid, dip4, dport);
}

static u32 get_first_ip4_addr(struct net *net)
{
	struct in_device *in_dev;
	struct net_device *dev;
	struct in_ifaddr *ifa;
	u32 dip4 = 0;

	rtnl_lock();
	rcu_read_lock();
	for_each_netdev(net, dev) {
		if (dev->flags & IFF_LOOPBACK || !(dev->flags & IFF_UP))
			continue;
		in_dev = __in_dev_get_rcu(dev);
		if (!in_dev)
			continue;

		in_dev_for_each_ifa_rcu(ifa, in_dev) {
			if (!strcmp(dev->name, ifa->ifa_label)) {
				dip4 = ifa->ifa_local;
				oecls_debug("dev: %s, dip4:%pI4\n", dev->name, &dip4);
				goto out;
			}
		}
	}
out:
	rcu_read_unlock();
	rtnl_unlock();
	return dip4;
}

static void get_sk_rule_addr(struct sock *sk, u32 *dip4, u16 *dport)
{
	*dport = htons(sk->sk_num);

	if (!match_ip_flag) {
		*dip4 = 0;
		return;
	}

	if (sk->sk_rcv_saddr)
		*dip4 = sk->sk_rcv_saddr;
	else
		*dip4 = get_first_ip4_addr(sock_net(sk));
}

static int rxclass_rule_del(struct cmd_context *ctx, __u32 loc)
{
	struct ethtool_rxnfc nfccmd;
	int err;

	nfccmd.cmd = ETHTOOL_SRXCLSRLDEL;
	nfccmd.fs.location = loc;
	err = send_ethtool_ioctl(ctx, &nfccmd);
	if (err < 0)
		oecls_debug("rmgr: Cannot delete RX class rule, loc:%u\n", loc);
	return err;
}

static int rmgr_ins(struct rmgr_ctrl *rmgr, __u32 loc)
{
	if (loc >= rmgr->size) {
		oecls_error("rmgr: Location out of range\n");
		return -1;
	}

	set_bit(loc, rmgr->slot);
	return 0;
}

static int rmgr_find_empty_slot(struct rmgr_ctrl *rmgr, struct ethtool_rx_flow_spec *fsp)
{
	__u32 loc, slot_num;

	if (rmgr->driver_select)
		return 0;

	loc = rmgr->size - 1;
	slot_num = loc / BITS_PER_LONG;
	if (!~(rmgr->slot[slot_num] | (~1UL << rmgr->size % BITS_PER_LONG))) {
		loc -= 1 + (loc % BITS_PER_LONG);
		slot_num--;
	}

	while (loc < rmgr->size && !~(rmgr->slot[slot_num])) {
		loc -= BITS_PER_LONG;
		slot_num--;
	}

	while (loc < rmgr->size && test_bit(loc, rmgr->slot))
		loc--;

	if (loc < rmgr->size) {
		fsp->location = loc;
		return rmgr_ins(rmgr, loc);
	}

	return -1;
}

static int rxclass_get_dev_info(struct cmd_context *ctx, __u32 *count, int *driver_select)
{
	struct ethtool_rxnfc nfccmd;
	int err;

	nfccmd.cmd = ETHTOOL_GRXCLSRLCNT;
	nfccmd.data = 0;
	err = send_ethtool_ioctl(ctx, &nfccmd);
	*count = nfccmd.rule_cnt;
	if (driver_select)
		*driver_select = !!(nfccmd.data & RX_CLS_LOC_SPECIAL);
	if (err < 0)
		oecls_debug("rxclass: Cannot get RX class rule count\n");

	return err;
}

static int rmgr_init(struct cmd_context *ctx, struct rmgr_ctrl *rmgr)
{
	struct ethtool_rxnfc *nfccmd;
	__u32 *rule_locs;
	int i, err = 0;

	memset(rmgr, 0, sizeof(*rmgr));
	err = rxclass_get_dev_info(ctx, &rmgr->n_rules, &rmgr->driver_select);
	if (err < 0)
		return err;

	if (rmgr->driver_select)
		return err;

	nfccmd = kzalloc(sizeof(*nfccmd) + (rmgr->n_rules * sizeof(__u32)), GFP_ATOMIC);
	if (!nfccmd) {
		oecls_error("rmgr: Cannot allocate memory for RX class rule locations\n");
		err = -ENOMEM;
		goto out;
	}

	nfccmd->cmd = ETHTOOL_GRXCLSRLALL;
	nfccmd->rule_cnt = rmgr->n_rules;
	err = send_ethtool_ioctl(ctx, nfccmd);
	if (err < 0) {
		oecls_debug("rmgr: Cannot get RX class rules\n");
		goto out;
	}

	rmgr->size = nfccmd->data;
	if (rmgr->size == 0 || rmgr->size < rmgr->n_rules) {
		oecls_error("rmgr: Invalid RX class rules table size\n");
		err = -EINVAL;
		goto out;
	}

	rmgr->slot = kzalloc(BITS_TO_LONGS(rmgr->size) * sizeof(long), GFP_ATOMIC);
	if (!rmgr->slot) {
		oecls_error("rmgr: Cannot allocate memory for RX class rules\n");
		err = -ENOMEM;
		goto out;
	}

	rule_locs = nfccmd->rule_locs;
	for (i = 0; i < rmgr->n_rules; i++) {
		err = rmgr_ins(rmgr, rule_locs[i]);
		if (err < 0)
			break;
	}

out:
	kfree(nfccmd);
	return err;
}

static void rmgr_cleanup(struct rmgr_ctrl *rmgr)
{
	kfree(rmgr->slot);
	rmgr->slot = NULL;
	rmgr->size = 0;
}

static int rmgr_set_location(struct cmd_context *ctx,
			     struct ethtool_rx_flow_spec *fsp)
{
	struct rmgr_ctrl rmgr;
	int ret;

	ret = rmgr_init(ctx, &rmgr);
	if (ret < 0)
		goto out;

	ret = rmgr_find_empty_slot(&rmgr, fsp);
out:
	rmgr_cleanup(&rmgr);
	return ret;
}

static int rxclass_rule_ins(struct cmd_context *ctx,
			    struct ethtool_rx_flow_spec *fsp, u32 rss_context)
{
	struct ethtool_rxnfc nfccmd;
	u32 loc = fsp->location;
	int ret;

	if (loc & RX_CLS_LOC_SPECIAL) {
		ret = rmgr_set_location(ctx, fsp);
		if (ret < 0)
			return ret;
	}

	nfccmd.cmd = ETHTOOL_SRXCLSRLINS;
	nfccmd.rss_context = rss_context;
	nfccmd.fs = *fsp;
	ret = send_ethtool_ioctl(ctx, &nfccmd);
	if (ret < 0) {
		oecls_debug("Can not insert the clasification rule\n");
		return ret;
	}

	if (loc & RX_CLS_LOC_SPECIAL)
		oecls_debug("Added rule with ID %d\n", nfccmd.fs.location);

	return 0;
}

static void flow_spec_to_ntuple(struct ethtool_rx_flow_spec *fsp,
				struct ethtool_rx_ntuple_flow_spec *ntuple)
{
	int i;

	memset(ntuple, ~0, sizeof(*ntuple));
	ntuple->flow_type = fsp->flow_type;
	ntuple->action = fsp->ring_cookie;
	memcpy_r(&ntuple->h_u, &fsp->h_u, sizeof(fsp->h_u));
	memcpy_r(&ntuple->m_u, &fsp->m_u, sizeof(fsp->m_u));
	for (i = 0; i < sizeof(ntuple->m_u); i++)
		ntuple->m_u.hdata[i] ^= 0xFF;
	ntuple->flow_type &= ~FLOW_EXT;
}

static int do_srxntuple(struct cmd_context *ctx, struct ethtool_rx_flow_spec *fsp)
{
	struct ethtool_rx_ntuple ntuplecmd;
	struct ethtool_value eval;
	int ret = 0;

	flow_spec_to_ntuple(fsp, &ntuplecmd.fs);

	eval.cmd = ETHTOOL_GFLAGS;
	ret = send_ethtool_ioctl(ctx, &eval);
	if (ret || !(eval.data & ETH_FLAG_NTUPLE))
		return -1;

	ntuplecmd.cmd = ETHTOOL_SRXNTUPLE;
	ret = send_ethtool_ioctl(ctx, &ntuplecmd);
	if (ret)
		oecls_debug("Cannot add new rule via N-tuple, ret:%d\n", ret);

	return ret;
}

static int cfg_ethtool_rule(struct cmd_context *ctx, bool is_del)
{
	struct ethtool_rx_flow_spec *fsp, rx_rule_fs;
	u32 rss_context = 0;
	int ret;

	oecls_debug("is_del:%d netdev:%s, dip4:%pI4, dport:%d, action:%d, ruleid:%u, del_ruleid:%u\n",
		    is_del, ctx->netdev, &ctx->dip4, ntohs(ctx->dport), ctx->action, ctx->ruleid,
		    ctx->del_ruleid);

	if (is_del)
		return rxclass_rule_del(ctx, ctx->del_ruleid);

	ctx->ret_loc = -1;

	fsp = &rx_rule_fs;
	memset(fsp, 0, sizeof(*fsp));
	fsp->flow_type = TCP_V4_FLOW;
	fsp->location = RX_CLS_LOC_ANY;
	fsp->h_u.tcp_ip4_spec.ip4dst = ctx->dip4;
	fsp->h_u.tcp_ip4_spec.pdst = ctx->dport;
	if (ctx->dip4)
		fsp->m_u.tcp_ip4_spec.ip4dst = (u32)~0ULL;
	fsp->m_u.tcp_ip4_spec.pdst = (u16)~0ULL;
	if (ctx->ruleid)
		fsp->location = ctx->ruleid;
	fsp->ring_cookie = ctx->action;

	ret = do_srxntuple(ctx, &rx_rule_fs);
	if (!ret)
		return 0;

	ret = rxclass_rule_ins(ctx, &rx_rule_fs, rss_context);
	if (!ret)
		ctx->ret_loc = rx_rule_fs.location;
	return ret;
}

static void cfg_work(struct work_struct *work)
{
	struct cfg_param *ctx_p = container_of(work, struct cfg_param, work);
	struct oecls_netdev_info *oecls_dev;
	struct oecls_sk_rule *rule;
	int devid, rxq_id;
	int err;

	mutex_lock(&oecls_sk_rules.mutex);
	for_each_oecls_netdev(devid, oecls_dev) {
		strncpy(ctx_p->ctx.netdev, oecls_dev->dev_name, IFNAMSIZ);
		if (!ctx_p->is_del) {
			if (reuseport_check(devid, ctx_p->ctx.dip4, ctx_p->ctx.dport)) {
				oecls_error("dip4:%pI4, dport:%d reuse!\n", &ctx_p->ctx.dip4,
					    ctx_p->ctx.dport);
				continue;
			}

			// Calculate the bound queue
			rxq_id = alloc_rxq_id(ctx_p->cpu, devid);
			if (rxq_id < 0)
				continue;

			// Config Ntuple rule to dev
			ctx_p->ctx.action = (u16)rxq_id;
			err = cfg_ethtool_rule(&ctx_p->ctx, ctx_p->is_del);
			// Add sk rule only on success
			if (err) {
				free_rxq_id(ctx_p->cpu, devid, rxq_id);
				continue;
			}
			add_sk_rule(devid, ctx_p->ctx.dip4, ctx_p->ctx.dport, ctx_p->sk,
				    ctx_p->ctx.action, ctx_p->ctx.ret_loc, ctx_p->cpu);
		} else {
			rule = get_rule_from_sk(devid, ctx_p->sk);
			if (!rule) {
				oecls_debug("rule not found! sk:%p, devid:%d, dip4:%pI4, dport:%d\n",
					    ctx_p->sk, devid, &ctx_p->ctx.dip4,
					    ntohs(ctx_p->ctx.dport));
				continue;
			}

			// Config Ntuple rule to dev
			ctx_p->ctx.del_ruleid = rule->ruleid;
			err = cfg_ethtool_rule(&ctx_p->ctx, ctx_p->is_del);
			// Free the bound queue
			free_rxq_id(rule->cpu, devid, rule->action);
			// Delete sk rule
			del_sk_rule(rule);
		}
	}
	mutex_unlock(&oecls_sk_rules.mutex);
	kfree(ctx_p);
	atomic_dec(&oecls_worker_count);
}

static bool has_sock_rule(struct sock *sk)
{
	struct oecls_netdev_info *oecls_dev;
	struct oecls_sk_rule *rule;
	int devid;

	for_each_oecls_netdev(devid, oecls_dev) {
		rule = get_rule_from_sk(devid, sk);
		if (rule)
			return true;
	}
	return false;
}

static void del_ntuple_rule(struct sock *sk)
{
	struct cfg_param *ctx_p;

	if (!has_sock_rule(sk))
		return;

	ctx_p = kzalloc(sizeof(*ctx_p), GFP_ATOMIC);
	if (!ctx_p)
		return;
	get_sk_rule_addr(sk, &ctx_p->ctx.dip4, &ctx_p->ctx.dport);

	ctx_p->is_del = true;
	ctx_p->sk = sk;
	INIT_WORK(&ctx_p->work, cfg_work);
	queue_work(do_cfg_workqueue, &ctx_p->work);
	atomic_inc(&oecls_worker_count);
}

static void add_ntuple_rule(struct sock *sk)
{
	struct cfg_param *ctx_p;

	if (check_appname(current->comm))
		return;

	ctx_p = kzalloc(sizeof(*ctx_p), GFP_ATOMIC);
	if (!ctx_p)
		return;
	get_sk_rule_addr(sk, &ctx_p->ctx.dip4, &ctx_p->ctx.dport);

	ctx_p->is_del = false;
	ctx_p->sk = sk;
	ctx_p->cpu = raw_smp_processor_id();
	INIT_WORK(&ctx_p->work, cfg_work);
	queue_work(do_cfg_workqueue, &ctx_p->work);
	atomic_inc(&oecls_worker_count);
}

static void ethtool_cfg_rxcls(struct sock *sk, int is_del)
{
	if (sk->sk_state != TCP_LISTEN)
		return;

	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
		return;

	oecls_debug("[cpu:%d] app:%s, sk:%p, is_del:%d, ip:%pI4, port:%d\n", raw_smp_processor_id(),
		    current->comm, sk, is_del, &sk->sk_rcv_saddr, (u16)sk->sk_num);

	if (is_del)
		del_ntuple_rule(sk);
	else
		add_ntuple_rule(sk);
}

static void clean_oecls_sk_rules(void)
{
	struct oecls_netdev_info *oecls_dev;
	struct cmd_context ctx = { 0 };
	struct oecls_sk_rule *rule;
	struct hlist_head *hlist;
	struct hlist_node *n;
	unsigned int i;
	int err;

	mutex_lock(&oecls_sk_rules.mutex);
	for (i = 0; i < OECLS_SK_RULE_HASHSIZE; i++) {
		hlist = &oecls_sk_rules.hash[i];

		hlist_for_each_entry_safe(rule, n, hlist, node) {
			oecls_dev = get_oecls_netdev_info(rule->devid);
			if (!oecls_dev)
				continue;
			strncpy(ctx.netdev, oecls_dev->dev_name, IFNAMSIZ);
			ctx.del_ruleid = rule->ruleid;
			err = cfg_ethtool_rule(&ctx, true);
			oecls_debug("sk:%p, dev_id:%d, action:%d, ruleid:%d, err:%d\n", rule->sk,
				    rule->devid, rule->action, rule->ruleid, err);

			hlist_del(&rule->node);
			oecls_debug("clean rule=%p\n", rule);
			free_to_l0(rule);
		}
	}
	mutex_unlock(&oecls_sk_rules.mutex);
}

static const struct oecls_hook_ops oecls_ntuple_ops = {
	.oecls_flow_update = NULL,
	.oecls_set_cpu = NULL,
	.oecls_timeout = NULL,
	.oecls_cfg_rxcls = ethtool_cfg_rxcls,
};

int oecls_ntuple_res_init(void)
{
	do_cfg_workqueue = alloc_ordered_workqueue("oecls_cfg", 0);
	if (!do_cfg_workqueue) {
		oecls_debug("alloc_ordered_workqueue fails\n");
		return -ENOMEM;
	}

	init_oecls_sk_rules();
	RCU_INIT_POINTER(oecls_ops, &oecls_ntuple_ops);
	synchronize_rcu();
	return 0;
}

void oecls_ntuple_res_clean(void)
{
	rcu_assign_pointer(oecls_ops, NULL);
	synchronize_rcu();

	oecls_debug("oecls_worker_count:%d\n", atomic_read(&oecls_worker_count));
	while (atomic_read(&oecls_worker_count) != 0)
		mdelay(1);

	destroy_workqueue(do_cfg_workqueue);
	clean_oecls_sk_rules();
}
