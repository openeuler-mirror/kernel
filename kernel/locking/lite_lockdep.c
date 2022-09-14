#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hash.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/debug_locks.h>
#include <linux/irqflags.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/kallsyms.h>
#include <linux/nmi.h>
#include <linux/utsname.h>
#include <linux/jhash.h>
#include <linux/hashtable.h>
#include <linux/sysctl.h>

#define CREATE_TRACE_POINTS
#include <trace/events/lite_lock.h>

#ifdef CONFIG_LITE_LOCKDEP
int lite_lockdep = 1;
module_param(lite_lockdep, int, 0644);
#else
#define lite_lockdep 0
#endif

/*
 * The hash-table for lite-lockdep classes:
 */
#define LITE_CLASSHASH_BITS	(MAX_LITE_LOCKDEP_KEYS_BITS - 1)
#define LITE_CLASSHASH_SIZE	(1UL << LITE_CLASSHASH_BITS)
#define __liteclasshashfn(key)	hash_long((unsigned long)key, LITE_CLASSHASH_BITS)
#define liteclasshashentry(key)	(lite_classhash_table + __liteclasshashfn((key)))

static struct hlist_head lite_classhash_table[LITE_CLASSHASH_SIZE];

#define LITE_KEYHASH_BITS	(MAX_LITE_LOCKDEP_KEYS_BITS - 1)
#define LITE_KEYHASH_SIZE	(1UL << LITE_KEYHASH_BITS)
static struct hlist_head lite_lock_keys_hash[LITE_KEYHASH_SIZE];

unsigned long nr_lite_lock_classes;
struct lite_lock_class lite_lock_classes[MAX_LITE_LOCKDEP_KEYS];
static DECLARE_BITMAP(lite_lock_classes_in_use, MAX_LITE_LOCKDEP_KEYS);

static LIST_HEAD(all_lite_lock_classes);
static LIST_HEAD(free_lite_lock_classes);

/*
 * lite_lockdep_lock: protects the reachability graph, and
 * other shared data structures.
 */
static arch_spinlock_t __lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
static struct task_struct *__owner;

struct lite_lock_class_key __lite_lockdep_no_validate__;
EXPORT_SYMBOL_GPL(__lite_lockdep_no_validate__);

static inline void lite_lockdep_lock(void)
{
	DEBUG_LOCKS_WARN_ON(!irqs_disabled());

	arch_spin_lock(&__lock);
	__owner = current;
}

static inline void lite_lockdep_unlock(void)
{
	DEBUG_LOCKS_WARN_ON(!irqs_disabled());

	if (debug_locks && DEBUG_LOCKS_WARN_ON(__owner != current))
		return;

	__owner = NULL;
	arch_spin_unlock(&__lock);
}

static int lite_graph_lock(void)
{
	lite_lockdep_lock();

	if (!debug_locks) {
		lite_lockdep_unlock();
		return 0;
	}
	return 1;
}

static inline void lite_graph_unlock(void)
{
	lite_lockdep_unlock();
}

static inline int lite_debug_locks_off_graph_unlock(void)
{
	int ret = debug_locks_off();

	lite_lockdep_unlock();

	return ret;
}

static inline 
struct hlist_head *litekeyhashentry(const struct lock_class_key *key)
{
	unsigned long hash = hash_long((uintptr_t)key, LITE_KEYHASH_BITS);

	return lite_lock_keys_hash + hash;
}

/**
 * Judge if the address of a static object, same
 * as the one in lockdep.c.
 */
#ifdef __KERNEL__
static int static_obj(const void *obj)
{
	unsigned long start = (unsigned long) &_stext,
		      end   = (unsigned long) &_end,
		      addr  = (unsigned long) obj;

	if (arch_is_kernel_initmem_freed(addr))
		return 0;

	if ((addr >= start) && (addr < end))
		return 1;

	if (arch_is_kernel_data(addr))
		return 1;

	if (is_kernel_percpu_address(addr))
		return 1;

	return is_module_address(addr) || is_module_percpu_address(addr);
}
#endif

/* Check whether a key has been registered as a dynamic key,
 * same as the one in lockdep.c.
 */
static bool is_dynamic_key(const struct lite_lock_class_key *key)
{
	struct hlist_head *hash_head;
	struct lite_lock_class_key *k;
	bool found = false;

	if (WARN_ON_ONCE(static_obj(key)))
		return false;

	if (!debug_locks)
		return true;

	hash_head = litekeyhashentry(key);

	rcu_read_lock();
	hlist_for_each_entry_rcu(k, hash_head, hash_entry) {
		if (k == key) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

/**
 * Assign lock keys, same as the one in lockdep.c.
 */
static bool assign_lite_lock_key(struct lite_lockdep_map *lock)
{
	unsigned long can_addr, addr = (unsigned long)lock;

	if (__is_kernel_percpu_address(addr, &can_addr))
		lock->key = (void *)can_addr;
	else if (__is_module_percpu_address(addr, &can_addr))
		lock->key = (void *)can_addr;
	else if (static_obj(lock))
		lock->key = (void *)lock;
	else {
		debug_locks_off();
		pr_err("INFO: trying to register non-static key.\n");
		pr_err("you didn't initialize this object before use?\n");
		pr_err("turning off the locking correctness validator.\n");
		dump_stack();
		return false;
	}

	return true;
}

static inline struct lite_lock_class *lite_hlock_class(struct lite_held_lock *hlock)
{
	unsigned int class_idx = hlock->class_idx;

	barrier();

	if (!test_bit(class_idx, lite_lock_classes_in_use)) {
		DEBUG_LOCKS_WARN_ON(1);
		return NULL;
	}

	return lite_lock_classes + class_idx;
}

const char *__get_key_name(const struct lite_lock_class_sub_key *key, char *str)
{
	return kallsyms_lookup((unsigned long)key, NULL, NULL, NULL, str);
}

static void lite_print_lock_name(struct lite_lock_class *class)
{
	char str[KSYM_NAME_LEN];
	const char *name;

	name = class->name;
	if (!name) {
		name = __get_key_name(class->key, str);
		printk(KERN_CONT "%s", name);
	} else {
		printk(KERN_CONT "%s", name);
	}
}

static void lite_print_lock(struct lite_held_lock *hlock)
{
	struct lite_lock_class *lock = lite_hlock_class(hlock);

	if (!lock) {
		printk(KERN_CONT "<RELEASED>\n");
		return;
	}

	printk(KERN_CONT "%px", hlock->instance);
	lite_print_lock_name(lock);
	printk(KERN_CONT ", at: %pS\n", (void *)hlock->acquire_ip);
}

void lite_lockdep_print_held_locks(struct task_struct *p)
{
	int i, depth = READ_ONCE(p->lite_lockdep_depth);

	if (!depth)
		printk("no locks held by %s/%d.\n", p->comm, task_pid_nr(p));
	else
		printk("%d lock%s held by %s/%d:\n", depth,
		       depth > 1 ? "s" : "", p->comm, task_pid_nr(p));

	if (p->state == TASK_RUNNING && p != current)
		return;
	for (i = 0; i < depth; i++) {
		printk(" #%d: ", i);
		lite_print_lock(p->held_locks + i);
	}
}

#ifdef __KERNEL__
void lite_debug_show_all_locks(void)
{
	struct task_struct *g, *p;

	if (unlikely(!debug_locks)) {
		pr_warn("INFO: lite-lockdep is turned off.\n");
		return;
	}
	pr_warn("\nShowing all locks held in the system:\n");

	rcu_read_lock();
	for_each_process_thread(g, p) {
		if (!p->lite_lockdep_depth)
			continue;
		lite_lockdep_print_held_locks(p);
		touch_nmi_watchdog();
		touch_all_softlockup_watchdogs();
	}
	rcu_read_unlock();

	pr_warn("\n");
	pr_warn("=============================================\n\n");
}
EXPORT_SYMBOL_GPL(lite_debug_show_all_locks);
#endif

static void print_lite_kernel_ident(void)
{
	printk("%s %.*s %s\n", init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version,
		print_tainted());
}

static void init_data_structures_once(void)
{
	static bool __read_mostly initialized;
	int i;

	if (likely(initialized))
		return;

	initialized = true;

	for (i = 0; i < ARRAY_SIZE(lite_lock_classes); i++) {
		list_add_tail(&lite_lock_classes[i].lock_entry, &free_lite_lock_classes);
	}
}

static noinstr struct lite_lock_class *
look_up_lite_lock_class(const struct lite_lockdep_map *lock)
{
	struct lite_lock_class_sub_key *key;
	struct hlist_head *hash_head;
	struct lite_lock_class *class;

	if (unlikely(!lock->key))
		return NULL;

	key = lock->key->sub_key;

	hash_head = liteclasshashentry(key);

	if (DEBUG_LOCKS_WARN_ON(!irqs_disabled()))
		return NULL;

	hlist_for_each_entry_rcu_notrace(class, hash_head, hash_entry) {
		if (class->key == key) {
			WARN_ON_ONCE(class->name != lock->name &&
				     lock->key != &__lite_lockdep_no_validate__);
			return class;
		}
	}

	return NULL;
}

/*
 * Register a lock's class in the hash-table.
 */
static struct lite_lock_class *
register_lite_lock_class(struct lite_lockdep_map *lock)
{
	struct lite_lock_class_sub_key *key;
	struct hlist_head *hash_head;
	struct lite_lock_class *class;

	DEBUG_LOCKS_WARN_ON(!irqs_disabled());

	class = look_up_lite_lock_class(lock);

	if (likely(class))
		goto out_set_class;

	if (!lock->key) {
		if (!assign_lite_lock_key(lock))
			return NULL;
	} else if (!static_obj(lock->key) && !is_dynamic_key(lock->key)) {
		return NULL;
	}

	key = lock->key->sub_key;
	hash_head = liteclasshashentry(key);

	if (!lite_graph_lock()) {
		return NULL;
	}

	hlist_for_each_entry_rcu(class, hash_head, hash_entry) {
		if (class->key == key)
			goto out_unlock_set;
	}

	init_data_structures_once();

	class = list_first_entry_or_null(&free_lite_lock_classes, typeof(*class),
					 lock_entry);

	if (!class) {
		printk(KERN_DEBUG "BUG: MAX_LOCKDEP_KEYS too low!");
		dump_stack();
		return NULL;
	}

	nr_lite_lock_classes++;
	__set_bit(class - lite_lock_classes, lite_lock_classes_in_use);

	class->key = key;
	class->name = lock->name;

	hlist_add_head_rcu(&class->hash_entry, hash_head);

	list_move_tail(&class->lock_entry, &all_lite_lock_classes);

out_unlock_set:
	lite_graph_unlock();

out_set_class:
	lock->class = class;
	return class;
}

static int 
__lite_lock_acquire(struct lite_lockdep_map *lock, unsigned int subclass, 
		    int trylock, int read, int check, 
		    struct lite_lockdep_map *nest_lock, unsigned long ip, 
		    int reacquire)
{
	struct task_struct *curr = current;
	struct lite_lock_class *class = NULL;
	struct lite_held_lock *hlock;
	unsigned int depth;
	int class_idx;
	int ret;

	if (unlikely(!debug_locks))
		return 0;

	if (!lite_lockdep)
		return 0;

	if (lock->key == &__lite_lockdep_no_validate__)
		check = 0;

	class = lock->class;

	if (unlikely(!class)) {
		class = register_lite_lock_class(lock);
		if (!class)
			return 0;
	}

	depth = curr->lite_lockdep_depth;

	if (DEBUG_LOCKS_WARN_ON(depth >= MAX_LITE_LOCK_DEPTH))
		return 0;

	class_idx = class - lite_lock_classes;

	hlock = curr->held_locks + depth;
	hlock->class_idx = class_idx;
	hlock->subclass = subclass;
	hlock->acquire_ip = ip;
	hlock->instance = lock;
	hlock->nest_lock = nest_lock;
	hlock->trylock = trylock;
	hlock->read = read;
	hlock->check = check;

	if (DEBUG_LOCKS_WARN_ON(!test_bit(class_idx, lite_lock_classes_in_use)))
		return 0;

	curr->lite_lockdep_depth++;

	if (unlikely(curr->lite_lockdep_depth >= MAX_LITE_LOCK_DEPTH)) {
		debug_locks_off();
		printk(KERN_DEBUG "BUG: MAX_LOCK_DEPTH too low!");
		printk(KERN_DEBUG "depth: %i  max: %lu!\n",
		       curr->lite_lockdep_depth, MAX_LITE_LOCK_DEPTH);
		lite_lockdep_print_held_locks(current);
		lite_debug_show_all_locks();
		dump_stack();
		return 0;
	}
	
	return ret;
}

static noinstr int match_lite_held_lock(const struct lite_held_lock *hlock,
				        const struct lite_lockdep_map *lock)
{
	if (hlock->instance == lock)
		return 1;
	return 0;
}

static struct lite_held_lock *find_lite_held_lock(struct task_struct *curr,
					          struct lite_lockdep_map *lock,
					          unsigned int depth, int *idx)
{
	struct lite_held_lock *ret, *hlock, *prev_hlock;
	int i;

	i = depth - 1;
	hlock = curr->held_locks + i;
	ret = hlock;
	if (match_lite_held_lock(hlock, lock))
		goto out;

	ret = NULL;
	for (i--, prev_hlock = hlock--;
	     i >= 0;
	     i--, prev_hlock = hlock--) {
		if (match_lite_held_lock(hlock, lock)) {
			ret = hlock;
			break;
		}
	}

out:
	*idx = i;
	return ret;
}

static int 
lite_reacquire_held_locks(struct task_struct *curr, unsigned int depth, int idx)
{
	struct lite_held_lock *hlock;

	if (DEBUG_LOCKS_WARN_ON(!irqs_disabled()))
		return 0;

	for (hlock = curr->held_locks + idx; idx < depth; idx++, hlock++) {
		switch (__lite_lock_acquire(hlock->instance,
				    hlock->subclass,
				    hlock->trylock,
				    hlock->read,
				    hlock->check,
				    hlock->nest_lock, 
				    hlock->acquire_ip,
				    1)) {
		case 0:
			return 1;
		case 1:
			break;
		default:
			WARN_ON(1);
			return 0;
		}
	}
	return 0;
}

static void print_lite_lockdep_cache(struct lite_lockdep_map *lock)
{
	const char *name;
	char str[KSYM_NAME_LEN];

	name = lock->name;
	if (!name)
		name = __get_key_name(lock->key->sub_key, str);

	printk(KERN_CONT "%s", name);
}

static inline void print_lite_ip_sym(const char *loglvl, unsigned long ip)
{
	printk("%s[<%px>] %pS\n", loglvl, (void *) ip, (void *) ip);
}

static void print_lite_unlock_imbalance_bug(struct task_struct *curr,
				            struct lite_lockdep_map *lock,
				            unsigned long ip)
{
	pr_warn("\n");
	pr_warn("=====================================\n");
	pr_warn("WARNING: bad unlock balance detected!\n");
	print_lite_kernel_ident();
	pr_warn("-------------------------------------\n");
	pr_warn("%s/%d is trying to release lock (",
		curr->comm, task_pid_nr(curr));
	print_lite_lockdep_cache(lock);
	pr_cont(") at:\n");
	print_lite_ip_sym(KERN_WARNING, ip);
	pr_warn("but there are no more locks to release!\n");
	pr_warn("\nother info that might help us debug this:\n");
	lite_lockdep_print_held_locks(curr);

	pr_warn("\nstack backtrace:\n");
	dump_stack();
}

static int
__lite_lock_release(struct lite_lockdep_map *lock, unsigned long ip)
{
	struct task_struct *curr = current;
	unsigned int depth = 1;
	struct lite_held_lock *hlock;
	int i;

	if (unlikely(!debug_locks))
		return 0;

	if (!lite_lockdep)
		return 0;

	depth = curr->lite_lockdep_depth;

	if (depth <= 0) {
		print_lite_unlock_imbalance_bug(curr, lock, ip);
		return 0;
	}

	hlock = find_lite_held_lock(curr, lock, depth, &i);

	if (!hlock) {
		print_lite_unlock_imbalance_bug(curr, lock, ip);
		return 0;
	}

	curr->lite_lockdep_depth = i;

	if (i == depth - 1)
		return 1;

	if (lite_reacquire_held_locks(curr, depth, i + 1))
		return 0;

	return 0;
}

void lite_lock_acquire(struct lite_lockdep_map *lock, unsigned int subclass,
		       int trylock, int read, int check,
		       struct lite_lockdep_map *nest_lock, unsigned long ip)
{	
	unsigned long flags;

	if (!debug_locks)
		return;

	raw_local_irq_save(flags);

	trace_lock_acquire_lite(lock, subclass, trylock, read, check, nest_lock, ip);
	
	__lite_lock_acquire(lock, subclass, trylock, read, check, nest_lock, ip, 0);
	raw_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(lite_lock_acquire);

void lite_lock_release(struct lite_lockdep_map *lock, unsigned long ip)
{
	unsigned long flags;

	trace_lock_release_lite(lock, ip);

	raw_local_irq_save(flags);

	__lite_lock_release(lock, ip);
	raw_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(lite_lock_release);

void lite_lockdep_init_map_type(struct lite_lockdep_map *lock, const char *name,
			    struct lite_lock_class_key *key, int subclass)
{
	lock->class = NULL;

	if (DEBUG_LOCKS_WARN_ON(!name)) {
		lock->name = "NULL";
		return;
	}

	lock->name = name;

	if (DEBUG_LOCKS_WARN_ON(!key))
		return;

	if (!static_obj(key) && !is_dynamic_key(key)) {
		if (debug_locks)
			printk(KERN_ERR "BUG: key %px has not been registered!\n", key);
		DEBUG_LOCKS_WARN_ON(1);
		return;
	}
	lock->key = key;

	if (unlikely(!debug_locks))
		return;
}
EXPORT_SYMBOL_GPL(lite_lockdep_init_map_type);
