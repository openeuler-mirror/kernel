/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_OENETCLS_H
#define _LINUX_OENETCLS_H

struct oecls_hook_ops {
	void (*oecls_cfg_rxcls)(struct sock *sk, int is_del);
	void (*oecls_flow_update)(struct sock *sk);
	void (*oecls_set_cpu)(struct sk_buff *skb, int *cpu, int *last_qtail);
	bool (*oecls_timeout)(struct net_device *dev, u16 rxq_index,
							u32 flow_id, u16 filter_id);
};

typedef int (*enqueue_f)(struct sk_buff *skb, int cpu, unsigned int *qtail);
extern const struct oecls_hook_ops __rcu *oecls_ops;
extern struct static_key_false oecls_rps_needed;

static inline void oenetcls_cfg_rxcls(struct sock *sk, int is_del)
{
	const struct oecls_hook_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(oecls_ops);
	if (ops && ops->oecls_cfg_rxcls)
		ops->oecls_cfg_rxcls(sk, is_del);
	rcu_read_unlock();
}

static inline void oenetcls_flow_update(struct sock *sk)
{
	const struct oecls_hook_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(oecls_ops);
	if (ops && ops->oecls_flow_update)
		ops->oecls_flow_update(sk);
	rcu_read_unlock();
}

static inline bool
oenetcls_skb_set_cpu(struct sk_buff *skb, enqueue_f enq_func, int *ret)
{
	const struct oecls_hook_ops *ops;
	int cpu, last_qtail;
	bool result = false;

	rcu_read_lock();
	ops = rcu_dereference(oecls_ops);
	if (ops && ops->oecls_set_cpu) {
		ops->oecls_set_cpu(skb, &cpu, &last_qtail);
		if (cpu >= 0) {
			*ret = enq_func(skb, cpu, &last_qtail);
			result = true;
		}
	}
	rcu_read_unlock();
	return result;
}

static inline void
oenetcls_skblist_set_cpu(struct list_head *head, enqueue_f enq_func)
{
	const struct oecls_hook_ops *ops;
	struct sk_buff *skb, *next;
	int cpu, last_qtail;

	rcu_read_lock();
	ops = rcu_dereference(oecls_ops);
	if (ops && ops->oecls_set_cpu) {
		list_for_each_entry_safe(skb, next, head, list) {
			ops->oecls_set_cpu(skb, &cpu, &last_qtail);
			if (cpu >= 0) {
				skb_list_del_init(skb);
				enq_func(skb, cpu, &last_qtail);
			}
		}
	}
	rcu_read_unlock();
}

static inline bool oenetcls_may_expire_flow(struct net_device *dev,
					    u16 rxq_index, u32 flow_id,
					    u16 filter_id, bool *expire)
{
	const struct oecls_hook_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(oecls_ops);
	if (ops && ops->oecls_timeout) {
		*expire = ops->oecls_timeout(dev, rxq_index, flow_id, filter_id);
		rcu_read_unlock();
		return true;
	}
	rcu_read_unlock();

	return false;
}

#endif  /* _LINUX_OENETCLS_H */

