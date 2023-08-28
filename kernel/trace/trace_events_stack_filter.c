// SPDX-License-Identifier: GPL-2.0

#include <linux/mutex.h>
#include <linux/slab.h>

#include "trace.h"

#define TP_BUF_SIZE 1023	/* trace parser buf size */
#define CS_BUF_SIZE 64		/* call stack buf size */

#define MAX_SF_LEN 64		/* max stack filter length */
#define DSTARS_ADDR 1		/* '**' wildcard */

#define list_length(head) ({ \
	int __len = 0; \
	struct list_head *__pos; \
	list_for_each(__pos, head) \
		__len++; \
	__len; \
})

#define ADDR_MAP_HASH(key) \
	(((key) >> 2) % STACK_FILTER_ADDR_MAP_SIZE)

struct function_address {
	struct list_head list;
	size_t addr;			/* some addresses may represent wildcards */
};

struct stack_filter {
	struct list_head list;
	char *string;			/* original string */
	struct list_head addrs;		/* function addresses */
	bool neg;			/* negate the filter */
};

struct addr_map_node {
	struct hlist_node node;
	unsigned long key;
	unsigned long value;
};

static inline void
function_address_list_clear(struct list_head *faddrs)
{
	struct function_address *faddr, *tmp;

	list_for_each_entry_safe(faddr, tmp, faddrs, list) {
		list_del(&faddr->list);
		kfree(faddr);
	}
}

static inline int
function_address_list_copy(struct list_head *copy, struct list_head *faddrs)
{
	struct function_address *faddr, *new_faddr;

	INIT_LIST_HEAD(copy);
	list_for_each_entry_reverse(faddr, faddrs, list) {
		new_faddr = kmalloc(sizeof(*new_faddr), GFP_KERNEL);
		if (!new_faddr) {
			function_address_list_clear(copy);
			return -ENOMEM;
		}
		new_faddr->addr = faddr->addr;
		list_add(&new_faddr->list, copy);
	}
	return 0;
}

static inline void
stack_filter_init(struct stack_filter *filter)
{
	INIT_LIST_HEAD(&filter->addrs);
}

static inline struct stack_filter *
stack_filter_new(void)
{
	struct stack_filter *filter;

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return NULL;

	stack_filter_init(filter);
	return filter;
}

static inline void
stack_filter_free(struct stack_filter *filter)
{
	struct function_address *faddr, *tmp;

	list_for_each_entry_safe(faddr, tmp, &filter->addrs, list) {
		list_del(&faddr->list);
		kfree(faddr);
	}

	kfree(filter->string);
	kfree(filter);
}

static inline int
stack_filter_copy(struct stack_filter *copy, struct stack_filter *filter)
{
	int ret = 0;

	copy->string = kstrdup(filter->string, GFP_KERNEL);
	if (!copy->string)
		return -ENOMEM;

	ret = function_address_list_copy(&copy->addrs, &filter->addrs);
	if (ret < 0) {
		kfree(copy->string);
		return ret;
	}

	copy->neg = filter->neg;
	return 0;
}

static inline void
stack_filter_list_clear(struct list_head *filters)
{
	struct stack_filter *filter, *tmp;

	list_for_each_entry_safe(filter, tmp, filters, list) {
		list_del(&filter->list);
		stack_filter_free(filter);
	}
}

static inline int
stack_filter_list_copy(struct list_head *copy, struct list_head *filters)
{
	int ret = 0;
	struct stack_filter *filter, *new_filter;

	/* merge initialization with copy */
	INIT_LIST_HEAD(copy);
	list_for_each_entry_reverse(filter, filters, list) {
		new_filter = kmalloc(sizeof(*new_filter), GFP_KERNEL);
		if (!new_filter) {
			ret = -ENOMEM;
			goto bad;
		}

		ret = stack_filter_copy(new_filter, filter);
		if (ret < 0)
			goto bad;

		list_add(&new_filter->list, copy);
	}
	return 0;

 bad:
	stack_filter_list_clear(copy);
	return ret;
}

static inline void
stack_filter_enable(struct trace_event_file *file)
{
	unsigned long old_flags = file->flags;

	file->flags |= EVENT_FILE_FL_STACK_FILTER;
	if (file->flags != old_flags)
		trace_buffered_event_enable();
}

static inline void
stack_filter_disable(struct trace_event_file *file)
{
	unsigned long old_flags = file->flags;

	file->flags &= ~EVENT_FILE_FL_STACK_FILTER;
	if (file->flags != old_flags)
		trace_buffered_event_disable();
}

static inline void
addr_map_init(struct stack_filter_addr_map *addr_map)
{
	int i;

	for (i = 0; i < STACK_FILTER_ADDR_MAP_SIZE; i++)
		INIT_HLIST_HEAD(&addr_map->map[i]);
	spin_lock_init(&addr_map->lock);
}

/*
 * Typically, the number of functions in the call stack of a trace event
 * is not large, so we use a simple hash table to store the mapping,
 * without limiting its cache size.
 */
static inline int
addr_map_insert(struct stack_filter_addr_map *addr_map, unsigned long key, unsigned long value)
{
	struct addr_map_node *node;
	int idx, ret = 0;
	unsigned long flags;

	idx = ADDR_MAP_HASH(key);
	spin_lock_irqsave(&addr_map->lock, flags);

	hlist_for_each_entry(node, &addr_map->map[idx], node) {
		/* new value is always the same as the old here... maybe */
		if (node->key == key)
			goto out;
	}

	node = kmalloc(sizeof(*node), GFP_ATOMIC);
	if (!node) {
		ret = -ENOMEM;
		goto out;
	}

	node->key = key;
	node->value = value;

	hlist_add_head_rcu(&node->node, &addr_map->map[idx]);

 out:
	spin_unlock_irqrestore(&addr_map->lock, flags);
	return ret;
}

static inline unsigned long
addr_map_get(struct stack_filter_addr_map *addr_map, unsigned long key)
{
	struct addr_map_node *node;
	int idx;
	unsigned long ret = 0; /* value can't be 0 */

	idx = ADDR_MAP_HASH(key);
	/* nested critical section, not necessary in fact */
	rcu_read_lock_sched();

	hlist_for_each_entry_rcu(node, &addr_map->map[idx], node) {
		if (node->key == key) {
			ret = node->value;
			goto out;
		}
	}

 out:
	rcu_read_unlock_sched();
	return ret;
}

/* require holding event_mutex */
static inline void
addr_map_clear(struct hlist_head *addr_map)
{
	int i;
	struct addr_map_node *node;
	struct hlist_node *tmp;

	for (i = 0; i < STACK_FILTER_ADDR_MAP_SIZE; i++) {
		hlist_for_each_entry_safe(node, tmp, &addr_map[i], node) {
			hlist_del(&node->node);
			kfree(node);
		}
	}
}

static inline void
addr_map_free(struct stack_filter_addr_map *addr_map)
{
	addr_map_clear(addr_map->map);
	kfree(addr_map);
}

static inline void
event_stack_filter_init(struct event_stack_filter *esf)
{
	INIT_LIST_HEAD(&esf->filters);

	/* addr_map should be pre-allocated, just init it here */
	addr_map_init(esf->addr_map);
}

static inline struct event_stack_filter *
event_stack_filter_new(void)
{
	struct event_stack_filter *esf;

	esf = kmalloc(sizeof(*esf), GFP_KERNEL);
	if (!esf)
		return NULL;

	esf->addr_map = kmalloc(sizeof(*esf->addr_map), GFP_KERNEL);
	if (!esf->addr_map)
		return NULL;

	event_stack_filter_init(esf);
	return esf;
}

static inline void
event_stack_filter_free(struct event_stack_filter *esf, bool free_addr_map)
{
	stack_filter_list_clear(&esf->filters);

	/*
	 * addr_map may be passed to a new event_stack_filter,
	 * in this situation, we cannot free it.
	 */
	if (free_addr_map)
		addr_map_free(esf->addr_map);

	kfree(esf);
}

/* require holding event_mutex */
static inline int
event_stack_filter_copy(struct event_stack_filter *copy,
			struct event_stack_filter *esf)
{
	int ret;

	ret = stack_filter_list_copy(&copy->filters, &esf->filters);
	if (ret < 0)
		return ret;

	/*
	 * Not use deepcopy here to speed up copy.
	 * Must be vigilant about this when use or free addr_map.
	 */
	copy->addr_map = esf->addr_map;
	return 0;
}

/*
 * require holding event_mutex
 * combine new and copy
 */
static inline struct event_stack_filter *
event_stack_filter_clone(struct event_stack_filter *esf)
{
	struct event_stack_filter *copy;

	copy = kmalloc(sizeof(*copy), GFP_KERNEL);
	if (!copy)
		return NULL;

	if (event_stack_filter_copy(copy, esf) < 0) {
		kfree(copy);
		return NULL;
	}

	return copy;
}

/*
 * parse a string with the form below:
 *   '!'?function(/(function|'**'))*
 * where:
 *   '!' negates the filter
 *   '**' matches any function call path
 * e.g.
 *   [1] work_pending/do_notify_resume/schedule/__schedule/'**'
 *   [2] '**'/kthread/kcompactd/schedule_timeout/schedule/'**'
 *   [3] !el0_sync/el0_sync_handler/'**'/invoke_syscall/'**'/schedule/'**'
 *   [4] !ret_from_fork/'**'/kthread/worker_thread/schedule/'**'
 * Please remove '' around '**' if you want to use it.
 *
 * The full call path will end at stack_filter_match function,
 * like
 *   work_pending/do_notify_resume/schedule/__schedule/\
 *   trace_event_raw_event_sched_switch/trace_event_buffer_commit/stack_filter_match.
 *
 * We recommand that you use '**' at the end of the string,
 * because it will match any function call path.
 * So that you don't have to know the deeper call path.
 *
 * Call paths that matches example [1] can also match
 *   schedule/__schedule/'**' or '**'/schedule/__schedule/'**',
 * because we are matching call stacks, not the full path, to speed up filtering.
 * Function calls at the bottom of stack will be ignored.
 *
 * We convert symbols to their addresses here to avoid
 * changing stacktrace addresses to their names at runtime,
 * which would greatly slow down the function call.
 * The downside is that we can't handle '*' wildcard.
 */
static int
stack_filter_parse(struct stack_filter *filter, char *buf)
{
	char *p = buf;
	char name[NAME_MAX + 1];
	struct function_address *faddr, *tmp;
	size_t addr;
	int i, len = 0, ret = 0;

	if (*p == '!') {
		filter->neg = true;
		p++;
	}
	if (*p == '\0')
		return -EINVAL;

	while (*p) {
		i = 0;
		while (*p && *p != '/') {
			name[i++] = *(p++);
			if (i > NAME_MAX) {
				ret = -EINVAL;
				goto bad;
			}
		}
		name[i] = '\0';

		while (*p == '/')
			p++;

		if (!strcmp(name, "**")) {
			/* wildcard '**' */
			addr = DSTARS_ADDR;
		} else {
			/* function name (maybe empty) */
			addr = kallsyms_lookup_name(name);
			if (!addr) {
				ret = -EINVAL;
				goto bad;
			}
		}

		/* remove repetitive '**' */
		if (addr == DSTARS_ADDR && !list_empty(&filter->addrs)) {
			faddr = list_first_entry(&filter->addrs, struct function_address, list);

			if (faddr->addr == DSTARS_ADDR)
				continue;
		}

		if (++len > MAX_SF_LEN) {
			ret = -EINVAL;
			goto bad;
		}

		faddr = kzalloc(sizeof(*faddr), GFP_KERNEL);
		if (!faddr) {
			ret = -ENOMEM;
			goto bad;
		}

		faddr->addr = addr;
		list_add(&faddr->list, &filter->addrs);
	}

	if (list_empty(&filter->addrs))
		return -EINVAL;

	/* save original string as well */
	filter->string = kstrdup(buf, GFP_KERNEL);
	if (!filter->string) {
		ret = -ENOMEM;
		goto bad;
	}

	return ret;

 bad:
	list_for_each_entry_safe(faddr, tmp, &filter->addrs, list) {
		list_del(&faddr->list);
		kfree(faddr);
	}
	return ret;
}

static bool
__stack_filter_match_one(struct stack_filter *filter,
			 unsigned long *buf, int num_entries, bool *dp)
{
	int num_faddrs, i, j;
	bool ok;
	struct function_address *faddr;

	num_faddrs = list_length(&filter->addrs);

#define pos(i, j) ((i) * (num_faddrs + 1) + (j))

	/* dynamic programming */
	dp[pos(0, 0)] = true;
	ok = false;

	for (i = 0; i <= num_entries; i++) {
		faddr = list_entry(&filter->addrs, struct function_address, list);
		for (j = 1; j <= num_faddrs; j++) {
			faddr = list_next_entry(faddr, list);
			dp[pos(i, j)] = false;

			if (faddr->addr == DSTARS_ADDR) {
				dp[pos(i, j)] = dp[pos(i, j - 1)];
				if (i > 0)
					dp[pos(i, j)] |= dp[pos(i - 1, j)];
			} else if (i > 0 && buf[i - 1] == faddr->addr)
				dp[pos(i, j)] = dp[pos(i - 1, j - 1)];
		}

		if (dp[pos(i, num_faddrs)]) {
			ok = true;
			break;
		}
	}

#undef pos

	return ok;
}

/* return 0 on error */
static inline unsigned long
addr_remove_offset(struct event_stack_filter *esf, unsigned long addr)
{
	unsigned long new_addr;
	char name[KSYM_NAME_LEN];

	/*
	 * This operation is very slow,
	 * so we use a small cache to optimize it.
	 */
	new_addr = addr_map_get(esf->addr_map, addr);
	if (new_addr)
		return new_addr;

	if (lookup_symbol_name(addr, name) < 0)
		return 0;

	new_addr = kallsyms_lookup_name(name);
	if (!new_addr)
		return 0;

	if (addr_map_insert(esf->addr_map, addr, new_addr) < 0)
		return 0;

	return new_addr;
}

/*
 * return 1 on matching and 0 otherwise.
 *
 * A call path is matched successfully if the following conditions are met simultaneously:
 * [1] It matches any positive stack filter.
 * [2] It doesn't match any negative stack filter.
 * If no positive filter are set, condition [1] don't need to be satisified.
 */
int stack_filter_match(struct event_stack_filter *esf)
{
	int i, num_entries, num_faddrs;
	int size, maxsize;
	bool hasp, okp, *dp;
	struct stack_filter *filter;
	unsigned long buf[CS_BUF_SIZE], new_addr;
	struct list_head *stack_filters;

	/*
	 * We have already been inside rcu_read_lock_sched critical section.
	 * It's safe to visit esf.
	 */
	if (!esf)
		return 1;

	stack_filters = &esf->filters;
	if (list_empty(stack_filters))
		return 1;

	num_entries = stack_trace_save(buf, CS_BUF_SIZE, 0);

	for (i = num_entries - 1; i >= 0; i--) {
		/*
		 * buf[i] contains addr of a symbol plus an offset.
		 * We should remove the offset here.
		 */
		new_addr = addr_remove_offset(esf, buf[i]);
		if (new_addr)
			buf[i] = new_addr;
	}

	/* pre allocate memory for dp */
	maxsize = 0;
	list_for_each_entry(filter, stack_filters, list) {
		num_faddrs = list_length(&filter->addrs);
		size = (num_entries + 1) * (num_faddrs + 1);

		if (size > maxsize)
			maxsize = size;
	}

	dp = kmalloc(maxsize, GFP_ATOMIC);
	if (!dp)
		return 0;

	hasp = 0; okp = 0;
	list_for_each_entry(filter, stack_filters, list) {
		if (!filter->neg) {
			hasp = 1;
			if (__stack_filter_match_one(filter, buf, num_entries, dp)) {
				okp = 1;
				break;
			}
		}
	}
	if (hasp && !okp)
		goto bad_match;

	list_for_each_entry(filter, stack_filters, list) {
		if (filter->neg && __stack_filter_match_one(filter, buf, num_entries, dp))
			goto bad_match;
	}

	kfree(dp);
	return 1;

 bad_match:
	kfree(dp);
	return 0;
}

/*
 * use seq_file APIs to read from stack_filters
 */
static void *sf_start(struct seq_file *m, loff_t *pos)
{
	struct trace_event_file *file;
	loff_t n = *pos;

	mutex_lock(&event_mutex);
	file = m->private;

	if (!file->stack_filter)
		return NULL;

	return seq_list_start(&file->stack_filter->filters, n);
}

static void *sf_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct trace_event_file *file = m->private;

	return seq_list_next(v, &file->stack_filter->filters, pos);
}

static void sf_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&event_mutex);
}

static int sf_show(struct seq_file *m, void *v)
{
	struct stack_filter *filter = v;

	seq_printf(m, "%s\n", filter->string);
	return 0;
}

const struct seq_operations stack_filter_seq_ops = {
	.start = sf_start,
	.stop = sf_stop,
	.next = sf_next,
	.show = sf_show,
};

/*
 * operations for stack_filter file
 * not for 'struct event_stack_filter'
 */
static ssize_t
event_stack_filter_write(struct file *filp, const char __user *ubuf,
			 size_t cnt, loff_t *ppos)
{
	struct trace_event_file *event_file;
	struct trace_parser parser;
	struct stack_filter *filter;
	struct event_stack_filter *esf, *old;
	int read, ret;

	filter = stack_filter_new();
	if (!filter)
		return -ENOMEM;

	if (trace_parser_get_init(&parser, TP_BUF_SIZE + 1)) {
		kfree(filter);
		return -ENOMEM;
	}

	read = trace_get_user(&parser, ubuf, cnt, ppos);

	if (read >= 0 && trace_parser_loaded(&parser)) {
		/*
		 * e.g. use 'echo 0 > stack_filter' to disable stack_filter
		 * Most data structures has been cleared in event_stack_filter_open.
		 * Just make some judgements to avoid reporting error.
		 */
		if (!strcmp(strstrip(parser.buffer), "0")) {
			kfree(filter);
			trace_parser_put(&parser);

			event_file = event_file_data(filp);
			if (!rcu_dereference(event_file->stack_filter))
				return read;

			/* maybe use append mode or something else */
			return -EINVAL;
		}

		ret = stack_filter_parse(filter, parser.buffer);
		if (ret < 0) {
			kfree(filter);
			trace_parser_put(&parser);
			return ret;
		}
	} else {
		kfree(filter);
		goto out;
	}

	mutex_lock(&event_mutex);
	event_file = event_file_data(filp);

	if (event_file->stack_filter) {
		/*
		 * Copy the old and replace it with the new one to follow rcu rules.
		 * It doesn't cost much time since this function is called seldomly.
		 * In this way, codes can be simple.
		 *
		 * We didn't use a separate rcu for stack_filter->filters
		 * since its elements cannot be deleted one by one.
		 */
		esf = event_stack_filter_clone(event_file->stack_filter);
		if (!esf) {
			mutex_unlock(&event_mutex);
			stack_filter_free(filter);
			goto out;
		}
		list_add_tail(&filter->list, &esf->filters);

		old = event_file->stack_filter;
		rcu_assign_pointer(event_file->stack_filter, esf);

		/* make sure old esf is not being used */
		tracepoint_synchronize_unregister();
		event_stack_filter_free(old, false);

	} else {
		esf = event_stack_filter_new();
		if (!esf) {
			mutex_unlock(&event_mutex);
			stack_filter_free(filter);
			goto out;
		}
		list_add_tail(&filter->list, &esf->filters);

		rcu_assign_pointer(event_file->stack_filter, esf);
		tracepoint_synchronize_unregister();

		stack_filter_enable(event_file);
	}

	mutex_unlock(&event_mutex);

 out:
	trace_parser_put(&parser);
	return read;
}

static int event_stack_filter_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct trace_event_file *event_file;
	struct event_stack_filter *esf;
	struct seq_file *seq;

	ret = security_locked_down(LOCKDOWN_TRACEFS);
	if (ret)
		return ret;

	mutex_lock(&event_mutex);

	event_file = inode->i_private;
	if (!event_file) {
		mutex_unlock(&event_mutex);
		return -ENODEV;
	}

	if ((filp->f_mode & FMODE_WRITE) && (filp->f_flags & O_TRUNC)) {
		stack_filter_disable(event_file);

		if (event_file->stack_filter) {
			esf = event_file->stack_filter;
			RCU_INIT_POINTER(event_file->stack_filter, NULL);

			/* wait until esf is not being used */
			tracepoint_synchronize_unregister();
			event_stack_filter_free(esf, true);
		}
	}

	ret = seq_open(filp, &stack_filter_seq_ops);
	if (!ret) {
		seq = filp->private_data;
		seq->private = inode->i_private;
	}

	mutex_unlock(&event_mutex);

	return ret;
}

const struct file_operations event_stack_filter_fops = {
	.open = event_stack_filter_open,
	.read = seq_read,
	.write = event_stack_filter_write,
	.llseek = tracing_lseek,
	.release = seq_release,
};
