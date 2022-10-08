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

int lite_lockdep = CONFIG_LITE_LOCKDEP;
module_param(lite_lockdep, int, 0644);

#ifdef CONFIG_LOCK_REACHABILITY
int check_reachability = 1;
#else
int check_reachability = 0;
#endif
module_param(check_reachability, int, 0644);

int detect_deadlocks = 0;
module_param(detect_deadlocks, int, 0644);

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

unsigned long nr_lite_list_entries;
static struct lite_lock_list lite_list_entries[MAX_LITE_LOCKDEP_ENTRIES];
static DECLARE_BITMAP(lite_list_entries_in_use, MAX_LITE_LOCKDEP_ENTRIES);

/* Temporarily saves the cycles to be printed. */
unsigned long nr_ind_cycle_entries;
static struct ind_cycle_list ind_cycle_entries[LITE_CLASSHASH_SIZE];
static DECLARE_BITMAP(ind_cycle_entries_in_use, LITE_CLASSHASH_SIZE);

/* Records entries of current path in dfs. */
unsigned long nr_stack_entries;
static struct stack_list stack_entries[LITE_CLASSHASH_SIZE];
static DECLARE_BITMAP(stack_entries_in_use, LITE_CLASSHASH_SIZE);

/* Indicate whether an item has been visited in dfs. */
unsigned long nr_visit_entries;
static struct visit_hlist visit_entries[LITE_CLASSHASH_SIZE];
static DECLARE_BITMAP(visit_entries_in_use, LITE_CLASSHASH_SIZE);
static DEFINE_HASHTABLE(visited, LITE_CLASSHASH_BITS);

/* Indicate equivalent deadlocks. */
unsigned long nr_detected_deadlocks;
static struct deadlock_entry detected_deadlocks[LITE_CLASSHASH_SIZE];

/* Indicate detected cycles. */
unsigned long nr_checked_cycles;
static struct ind_cycle_entry checked_cycles[LITE_CLASSHASH_SIZE];

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

static inline
struct hlist_head *litedephashentry(struct hlist_head *head,
				    const struct lite_lock_class_sub_key *key) 
{
	unsigned long hash = hash_long((unsigned long)key, LITE_CLASSDEP_HASH_BITS);

	return head + hash;
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

/* If the heads and the tails of two cycles are the same, 
 * we consider they are identical deadlocks.
 */
static bool deadlock_checked(unsigned long head, unsigned long tail)
{
	struct deadlock_entry *deadlock;
	int i;

	for (i = 0; i < nr_detected_deadlocks; i++) {
		deadlock = detected_deadlocks + i;
		if (deadlock->chain_head == head && 
		    deadlock->chain_tail == tail)
			return true;
	}

	return false;
}

static int add_deadlock(unsigned long head, unsigned long tail)
{
	struct deadlock_entry *deadlock;

	if (nr_detected_deadlocks >= LITE_CLASSHASH_SIZE) {
		debug_locks_off();
		lite_lockdep_unlock();

		printk(KERN_DEBUG "BUG: max detected_deadlocks size too small!");
		dump_stack();
		return 0;
	}

	deadlock = detected_deadlocks + nr_detected_deadlocks;
	deadlock->chain_head = head;
	deadlock->chain_tail = tail;
	nr_detected_deadlocks++;
	
	return 1;
}

/**
 * Returns 2 on deadlocks has already been checked.
 * Returns 1 on OK.
 */
static int record_dir_deadlocks(struct lite_lock_class *first, 
				struct lite_lock_class *next)
{
	unsigned long first_key = (unsigned long)first->key;
	unsigned long next_key = (unsigned long)next->key;
	unsigned long bigger = first_key > next_key ? first_key : next_key;
	unsigned long smaller = first_key < next_key ? first_key : next_key;
	int ret;

	if (deadlock_checked(bigger, smaller))
		return 2;

	ret = add_deadlock(bigger, smaller);
	if (!ret)
		return 0;
	
	return 1;
}

static int record_ind_deadlocks(struct list_head *stack)
{
	struct stack_list *first, *entry;
	struct lite_lock_class *class;
	unsigned long bigger, smaller, curr_key;
	int ret;

	first = list_first_entry(stack, struct stack_list, stack_entry);
	bigger = (unsigned long)first->lock_entry->class->key;
	smaller = (unsigned long)first->lock_entry->class->key;

	list_for_each_entry(entry, stack, stack_entry) {
		class = entry->lock_entry->class;
		curr_key = (unsigned long)class->key;
		if (curr_key < smaller)
			smaller = curr_key;
		if (curr_key > bigger)
			bigger = curr_key;
	}

	if (deadlock_checked(bigger, smaller))
		return 2;

	ret = add_deadlock(bigger, smaller);
	if (!ret)
		return 0;

	return 1;
}

/* If the keys of two pair of locks are the same, 
 * we consider they are identical cycles.
 */
static bool cycle_checked(struct lite_lock_class *lock, 
			  struct lite_lock_class *dep)
{
	struct ind_cycle_entry ind_cycle;
	bool found = false;
	int i;

	for (i = 0; i < nr_checked_cycles; i++) {
		ind_cycle = checked_cycles[i];
		if (ind_cycle.head == lock->key && 
		    ind_cycle.dep == dep->key)
			    found = true;
	}

	return found;
}

static int add_checked_cycle(struct lite_lock_class *lock, 
			     struct lite_lock_class *dep)
{
	struct ind_cycle_entry *ind_cycle;

	if (nr_checked_cycles >= LITE_CLASSHASH_SIZE) {
		debug_locks_off();
		lite_lockdep_unlock();

		printk(KERN_DEBUG "BUG: max checked_cycles size too small!");
		dump_stack();
		return 0;
	}

	ind_cycle = &checked_cycles[nr_checked_cycles];
	ind_cycle->head = lock->key;
	ind_cycle->dep = dep->key;

	nr_checked_cycles++;

	return 1;
}

static void print_lite_kernel_ident(void)
{
	printk("%s %.*s %s\n", init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version,
		print_tainted());
}

static noinline void print_dir_deadlock_bug(struct lite_lock_class *prev, 
				   	    struct lite_lock_list *next)
{
	struct task_struct *curr = current;
	struct lite_lock_list *entry;
	struct hlist_head *head = next->class->dir_from;
	const struct lite_lock_class_sub_key *key = prev->key;
	unsigned int from_read, to_read;
	unsigned long from_ip, to_ip;
	pid_t from_pid, to_pid;
	char *from_comm, *to_comm;
	bool found = false;

	if (record_dir_deadlocks(prev, next->class) == 2)
		return;

	if (debug_locks) {
		if (!lite_debug_locks_off_graph_unlock())
			return;
	}
		
	hlist_for_each_entry(entry, litedephashentry(head, key), hash_entry) {
		if (entry->class->key == key) {
			from_read = entry->read;
			from_ip = entry->acquire_ip;
			from_pid = entry->pid;
			from_comm = entry->comm;
			found = true;
			break;
		}
	}

	if (!found)
		WARN_ON(1);

	/* If the entry of next is in DirectFrom(prev), then the entry of 
	 * prev can be found in DirectTo(class of next).
	 */
	found = false;
	head = next->class->dir_to;

	hlist_for_each_entry(entry, litedephashentry(head, key), hash_entry) {
		if (entry->class->key == key) {
			to_read = entry->read;
			to_ip = entry->acquire_ip;
			to_pid = entry->pid;
			to_comm = entry->comm;
			found = true;
			break;
		}
	}

	if (!found)
		WARN_ON(1);

	pr_warn("\n");
	pr_warn("======================================================\n");
	pr_warn("WARNING: possible circular locking dependency detected\n");
	print_lite_kernel_ident();
	pr_warn("------------------------------------------------------\n");
	pr_warn("\nthe existing dependency chain is:\n");
	
	lite_print_lock_name(prev);
	printk(KERN_CONT ", at: %pS", (void *)from_ip);
	printk(KERN_CONT ", %lx", from_ip);
	printk(KERN_CONT ", held by %s/%d\n", from_comm, from_pid);

	printk("\n-- depends on -->\n\n");

	lite_print_lock_name(next->class);
	printk(KERN_CONT ", at: %pS", (void *)next->acquire_ip);
	printk(KERN_CONT ", %lx", next->acquire_ip);
	printk(KERN_CONT ", held by %s/%d\n", next->comm, next->pid);

	printk("\n-- depends on -->\n\n");

	lite_print_lock_name(prev);
	printk(KERN_CONT ", at: %pS", (void *)to_ip);
	printk(KERN_CONT ", %lx", to_ip);
	printk(KERN_CONT ", held by %s/%d\n", to_comm, to_pid);
	printk("\n");

	lite_lockdep_print_held_locks(curr);
}

static void print_ind_deadlock_bug(struct list_head *stack)
{
	struct task_struct *curr = current;
	struct stack_list *prev, *next, *last, *last_prev;
	struct hlist_head *head;
	struct lite_lock_list *entry;
	struct lite_lock_class_sub_key *key;
	bool found = false;

	if (record_ind_deadlocks(stack) == 2)
		return;

	if (debug_locks) {
		if (!lite_debug_locks_off_graph_unlock())
			return;
	}

	/* The last entry is filled in dfs_head. */
	last = list_last_entry(stack, struct stack_list, stack_entry);
	last_prev = list_prev_entry(last, stack_entry);

	head = last_prev->lock_entry->class->dir_to;
	key = last->lock_entry->class->key;

	hlist_for_each_entry(entry, litedephashentry(head, key), hash_entry) {
		if (entry->class->key == key) {
			last->lock_entry->read = entry->read;
			last->lock_entry->acquire_ip = entry->acquire_ip;
			last->lock_entry->pid = entry->pid;
			strcpy(last->lock_entry->comm, entry->comm);
			found = true;
			break;
		}
	}

	if (!found)
		WARN_ON(1);

	pr_warn("\n");
	pr_warn("======================================================\n");
	pr_warn("WARNING: possible circular locking dependency detected\n");
	print_lite_kernel_ident();
	pr_warn("------------------------------------------------------\n");
	pr_warn("\nthe existing dependency chain is:\n");

	list_for_each_entry(prev, stack, stack_entry) {
		next = list_next_entry(prev, stack_entry);
		
		lite_print_lock_name(prev->lock_entry->class);
		printk(KERN_CONT ", at: %pS", (void *)prev->lock_entry->acquire_ip);
		printk(KERN_CONT ", %lx", prev->lock_entry->acquire_ip);
		printk(KERN_CONT ", held by %s/%d\n", prev->lock_entry->comm, 
						      prev->lock_entry->pid);
						      
		if (!list_entry_is_head(next, stack, stack_entry)) {
			printk("\n-- depends on -->\n\n");
			continue;
		}

		printk("\n");
	}

	lite_lockdep_print_held_locks(curr);
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
		hash_init(lite_lock_classes[i].dir_from);
		hash_init(lite_lock_classes[i].dir_to);
		hash_init(lite_lock_classes[i].ind_from);
		hash_init(lite_lock_classes[i].ind_to);
		hash_init(lite_lock_classes[i].ind_cycle_dir_from);
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

/**
 * Check whether the provided key is in a hash table.
 */
static bool in_lite_hlist_possible(struct hlist_head *head,
				   const struct lite_lock_class_sub_key *key)
{
	struct lite_lock_list *entry;

	hlist_for_each_entry(entry, litedephashentry(head, key), hash_entry) {
		if (entry->class->key == key)
			return true;
	}

	return false;
}

/*
 * Allocate a dependency entry, assumes the graph_lock held.
 */
static struct lite_lock_list *alloc_lite_list_entry(void)
{
	int idx = find_first_zero_bit(lite_list_entries_in_use,
				      ARRAY_SIZE(lite_list_entries));

	if (idx >= ARRAY_SIZE(lite_list_entries)) {
		debug_locks_off();
		lite_lockdep_unlock();

		printk(KERN_DEBUG "BUG: MAX_LITE_LOCKDEP_ENTRIES too low!");
		dump_stack();
		return NULL;
	}
	nr_lite_list_entries++;
	__set_bit(idx, lite_list_entries_in_use);
	return lite_list_entries + idx;
}

/**
 * Add a new dependency to the head of the hash list.
 */
static int
add_lite_lock_to_hlist(struct hlist_head *head, struct lite_lock_class *class, 
		       unsigned int read, unsigned long acquire_ip,
		       pid_t pid, char *comm)
{
	struct lite_lock_list *entry;
	const struct lite_lock_class_sub_key *key = class->key;

	if (in_lite_hlist_possible(head, key))
		return 2;

	entry = alloc_lite_list_entry();
	if (!entry)
		return 0;

	entry->class = class;
	entry->read = read;
	entry->acquire_ip = acquire_ip;
	entry->pid = pid;
	strcpy(entry->comm, comm);

	hlist_add_head_rcu(&entry->hash_entry, litedephashentry(head, key));

	return 1;
}

static struct ind_cycle_list *alloc_ind_cycle_entry(void)
{
	int idx = find_first_zero_bit(ind_cycle_entries_in_use,
				      ARRAY_SIZE(ind_cycle_entries));

	if (idx >= ARRAY_SIZE(ind_cycle_entries)) {
		debug_locks_off();
		lite_lockdep_unlock();

		printk(KERN_DEBUG "BUG: MAX_IND_CYCLE_ENTRIES too low!");
		dump_stack();
		return NULL;
	}
	nr_ind_cycle_entries++;
	__set_bit(idx, ind_cycle_entries_in_use);
	return ind_cycle_entries + idx;
}

static int
add_cycle_to_list(struct list_head *head, struct lite_lock_class *class)
{
	struct ind_cycle_list *entry;

	entry = alloc_ind_cycle_entry();
	if (!entry)
		return 0;

	entry->class = class;

	list_add_rcu(&entry->cycle_entry, head);

	return 1;
}

static void init_cycle_list(void)
{
	unsigned long pos;
	for_each_set_bit(pos, ind_cycle_entries_in_use, 
			 ARRAY_SIZE(ind_cycle_entries)) {
		__clear_bit(pos, ind_cycle_entries_in_use);
	}
	nr_ind_cycle_entries = 0;
}

static struct stack_list *alloc_stack_entry(void)
{
	int idx = find_first_zero_bit(stack_entries_in_use,
				      ARRAY_SIZE(stack_entries));

	if (idx >= ARRAY_SIZE(stack_entries)) {
		debug_locks_off();
		lite_lockdep_unlock();

		printk(KERN_DEBUG "BUG: MAX_STACK_ENTRIES too low!");
		dump_stack();
		return NULL;
	}
	nr_stack_entries++;
	__set_bit(idx, stack_entries_in_use);
	return stack_entries + idx;
}

static int add_stack_to_list(struct list_head *head, 
			     struct lite_lock_list *lock_entry)
{
	struct stack_list *entry;

	entry = alloc_stack_entry();
	if (!entry)
		return 0;

	entry->lock_entry = lock_entry;

	list_add_rcu(&entry->stack_entry, head);

	return 1;
}

static void del_stack_in_list(struct list_head *node)
{ 
	struct stack_list *entry = list_entry(node, struct stack_list, stack_entry);
	int idx = entry - stack_entries;

	if (!test_bit(idx, stack_entries_in_use)) {
		debug_locks_off();
		lite_lockdep_unlock();

		printk(KERN_DEBUG "BUG: unbalanced MAX_LITE_LOCKDEP_STACK_ENTRIES del!");
		dump_stack();
	}

	__clear_bit(idx, stack_entries_in_use);

	list_del_init(&entry->stack_entry);
	nr_stack_entries--;
}

static void init_stack_list(void)
{
	unsigned long pos;
	for_each_set_bit(pos, stack_entries_in_use, 
			 ARRAY_SIZE(stack_entries)) {
		__clear_bit(pos, stack_entries_in_use);
	}
	nr_stack_entries = 0;
}

static struct visit_hlist *alloc_visit_entry(void)
{
	int idx = find_first_zero_bit(visit_entries_in_use,
				      ARRAY_SIZE(visit_entries));

	if (idx >= ARRAY_SIZE(visit_entries)) {
		debug_locks_off();
		lite_lockdep_unlock();

		printk(KERN_DEBUG "BUG: MAX_LITE_LOCKDEP_VISIT_ENTRIES too low!");
		dump_stack();
		return NULL;
	}
	nr_visit_entries++;
	__set_bit(idx, visit_entries_in_use);
	return visit_entries + idx;
}

static int add_visit_to_hlist(struct hlist_head *head, 
			      struct lite_lock_class *class)
{
	struct visit_hlist *entry;

	entry = alloc_visit_entry();
	if (!entry)
		return 0;

	entry->class = class;

	hlist_add_head_rcu(&entry->vis_entry, litedephashentry(head, class->key));

	return 1;
}

static void init_visit_hlist(void)
{
	unsigned long pos;
	for_each_set_bit(pos, visit_entries_in_use, 
			 ARRAY_SIZE(visit_entries)) {
		__clear_bit(pos, visit_entries_in_use);
	}
	nr_visit_entries = 0;
}

/* Find hlist_node and delete it */
static void del_visit_in_hlist(struct hlist_head *head, 
			       const struct lite_lock_class_sub_key *key)
{
	struct visit_hlist *entry;
	int idx;

	hlist_for_each_entry(entry, litedephashentry(head, key), vis_entry) {
		if (entry->class->key == key) {
			idx = entry - visit_entries;

			if (!test_bit(idx, visit_entries_in_use)) {
				debug_locks_off();
				lite_lockdep_unlock();

				printk(KERN_DEBUG "BUG: unbalanced MAX_LITE_LOCKDEP_VISIT_ENTRIES del!");
				dump_stack();
			}

			__clear_bit(idx, visit_entries_in_use);
			hash_del(&entry->vis_entry);
			nr_visit_entries--;
			
			break;
		}
	}
}

/*
 * Update reachability graph dued to the direct edge: prev → next.
 * Then all indirect reachabilities are constructed.
 */
static void
propagate_reachability(struct lite_held_lock *p, struct lite_held_lock *n)
{
	struct lite_lock_class *prev = lite_hlock_class(p);
	struct lite_lock_class *next = lite_hlock_class(n);
	struct lite_lock_class *_prev, *_next;
	struct lite_lock_list *p_entry, *n_entry;
	int i, j;
	unsigned int read;
	unsigned long ip;
	pid_t pid;
	char *comm;
	
	hash_for_each(prev->dir_to, i, p_entry, hash_entry) {
		_prev = p_entry->class;
		hash_for_each(next->dir_from, j, n_entry, hash_entry) {
			_next = n_entry->class;
			read = n_entry->read;
			ip = n_entry->acquire_ip;
			pid = n_entry->pid;
			comm = n_entry->comm;
			add_lite_lock_to_hlist(_prev->ind_from, _next, read, ip,
					       pid, comm);
		}
		hash_for_each(next->ind_from, j, n_entry, hash_entry) {
			_next = n_entry->class;
			read = n_entry->read;
			ip = n_entry->acquire_ip;
			pid = n_entry->pid;
			comm = n_entry->comm;
			add_lite_lock_to_hlist(_prev->ind_from, _next, read, ip,
					       pid, comm);
		}
		add_lite_lock_to_hlist(_prev->ind_from, next, n->read, n->acquire_ip,
				       n->pid, n->comm);
	}
	hash_for_each(prev->ind_to, i, p_entry, hash_entry) {
		_prev = p_entry->class;
		hash_for_each(next->dir_from, j, n_entry, hash_entry) {
			_next = n_entry->class;
			read = n_entry->read;
			ip = n_entry->acquire_ip;
			pid = n_entry->pid;
			comm = n_entry->comm;
			add_lite_lock_to_hlist(_prev->ind_from, _next, read, ip,
					       pid, comm);
		}
		hash_for_each(next->ind_from, j, n_entry, hash_entry) {
			_next = n_entry->class;
			read = n_entry->read;
			ip = n_entry->acquire_ip;
			pid = n_entry->pid;
			comm = n_entry->comm;
			add_lite_lock_to_hlist(_prev->ind_from, _next, read, ip,
					       pid, comm);
		}
		add_lite_lock_to_hlist(_prev->ind_from, next, n->read, n->acquire_ip,
				       n->pid, n->comm);
	}

	hash_for_each(next->dir_from, i, n_entry, hash_entry) {
		_next = n_entry->class;
		hash_for_each(prev->dir_to, j, p_entry, hash_entry) {
			_prev = p_entry->class;
			read = p_entry->read;
			ip = p_entry->acquire_ip;
			pid = p_entry->pid;
			comm = p_entry->comm;
			add_lite_lock_to_hlist(_next->ind_to, _prev, read, ip,
					       pid, comm);
		}
		hash_for_each(prev->ind_to, j, p_entry, hash_entry) {
			_prev = p_entry->class;
			read = p_entry->read;
			ip = p_entry->acquire_ip;
			pid = p_entry->pid;
			comm = p_entry->comm;
			add_lite_lock_to_hlist(_next->ind_to, _prev, read, ip,
					       pid, comm);
		}
		add_lite_lock_to_hlist(_next->ind_to, prev, p->read, p->acquire_ip,
				       p->pid, p->comm);
	}
	hash_for_each(next->ind_from, i, n_entry, hash_entry) {
		_next = n_entry->class;
		hash_for_each(prev->dir_to, j, p_entry, hash_entry) {
			_prev = p_entry->class;
			read = p_entry->read;
			ip = p_entry->acquire_ip;
			pid = p_entry->pid;
			comm = p_entry->comm;
			add_lite_lock_to_hlist(_next->ind_to, _prev, read, ip,
					       pid, comm);
		}
		hash_for_each(prev->ind_to, j, p_entry, hash_entry) {
			_prev = p_entry->class;
			read = p_entry->read;
			ip = p_entry->acquire_ip;
			pid = p_entry->pid;
			comm = p_entry->comm;
			add_lite_lock_to_hlist(_next->ind_to, _prev, read, ip,
					       pid, comm);
		}
		add_lite_lock_to_hlist(_next->ind_to, prev, p->read, p->acquire_ip,
				       p->pid, p->comm);
	}

	hash_for_each(next->dir_from, i, n_entry, hash_entry) {
		_next = n_entry->class;
		read = n_entry->read;
		ip = n_entry->acquire_ip;
		pid = n_entry->pid;
		comm = n_entry->comm;
		add_lite_lock_to_hlist(prev->ind_from, _next, read, ip,
				       pid, comm);
	}
	hash_for_each(next->ind_from, i, n_entry, hash_entry) {
		_next = n_entry->class;
		read = n_entry->read;
		ip = n_entry->acquire_ip;
		pid = n_entry->pid;
		comm = n_entry->comm;
		add_lite_lock_to_hlist(prev->ind_from, _next, read, ip,
				       pid, comm);
	}

	hash_for_each(prev->dir_to, i, p_entry, hash_entry) {
		_prev = p_entry->class;
		read = p_entry->read;
		ip = p_entry->acquire_ip;
		pid = p_entry->pid;
		comm = p_entry->comm;
		add_lite_lock_to_hlist(next->ind_to, _prev, read, ip,
				       pid, comm);
	}
	hash_for_each(prev->ind_to, i, p_entry, hash_entry) {
		_prev = p_entry->class;
		read = p_entry->read;
		ip = p_entry->acquire_ip;
		pid = p_entry->pid;
		comm = p_entry->comm;
		add_lite_lock_to_hlist(next->ind_to, _prev, read, ip,
				       pid, comm);
	}
}

/**
 * Search a complete cycle catched by detect_cycles.
 */
static void dfs(struct lite_lock_list *entry, struct list_head *stack, 
		struct hlist_head *visited)
{
	struct lite_lock_class *lock = entry->class;
	struct lite_lock_class *ind_lock;
	struct lite_lock_list *ind_entry;
	struct stack_list *st_entry;
	int i;

	if (entry->read == 2)
		return;

	add_stack_to_list(stack, entry);

	hash_for_each(lock->ind_cycle_dir_from, i, ind_entry, hash_entry) {
		ind_lock = ind_entry->class;
		st_entry = list_entry(stack->prev, struct stack_list, stack_entry);
		if (st_entry->lock_entry->class->key == ind_lock->key) {
			add_stack_to_list(stack, ind_entry);
			print_ind_deadlock_bug(stack);
			del_stack_in_list(stack->next);
			del_stack_in_list(stack->next);
			return;
		}

		if(!in_lite_hlist_possible(visited, ind_lock->key)) {
			add_visit_to_hlist(visited, ind_lock);
			dfs(ind_entry, stack, visited);
			del_visit_in_hlist(visited, ind_lock->key);
		}
	}

	del_stack_in_list(stack->next);
}

/**
 * Make a dummy entry for the @class and start searching.
 */
static void dfs_head(struct lite_lock_class *class, struct list_head *stack, 
		     struct hlist_head *visited)
{
	struct lite_lock_list lock_entry;
	INIT_HLIST_NODE(&lock_entry.hash_entry);
	lock_entry.class = class;
	lock_entry.read = 0;
	lock_entry.acquire_ip = _RET_IP_;
	lock_entry.pid = 0;
	lock_entry.comm[0] = '\0';
	dfs(&lock_entry, stack, visited);
}

/**
 * First, check on simple cycles. DFS will be
 * performed if only simple cycle exists.
 * This function is called by detect_cycles_handler.
 */
static int detect_cycles(void)
{
	LIST_HEAD(ind_cycle_locks);
	LIST_HEAD(stack);
	struct lite_lock_class *class, *dep;
	struct lite_lock_list *entry;
	struct ind_cycle_list *ind_list;
	struct lite_lock_class_sub_key *key;
	int i, j ,ret = 1;
	unsigned int read;
	unsigned long ip;
	pid_t pid;
	char *comm;
	unsigned long flags;

	raw_local_irq_save(flags);

	if (!lite_graph_lock()) {
		return 0;
	}
	
	init_visit_hlist();
	init_cycle_list();
	init_stack_list();

	for_each_set_bit(i, lite_lock_classes_in_use, ARRAY_SIZE(stack_entries)) {
		class = lite_lock_classes + i;
		key = class->key;

		hash_for_each(class->dir_from, j, entry, hash_entry) {
			dep = entry->class;
			read = entry->read;
			ip = entry->acquire_ip;
			comm = entry->comm;
			pid = entry->pid;

			if (in_lite_hlist_possible(dep->dir_from, key)) {
				if (cycle_checked(class, dep))
					continue;
				
				print_dir_deadlock_bug(class, entry);
				add_checked_cycle(class, dep);
				ret = 0;
			}

			if (in_lite_hlist_possible(dep->ind_from, key) &&
			    dep->key != key) {
				if (cycle_checked(class, dep))
					continue;
						
				add_lite_lock_to_hlist(class->ind_cycle_dir_from, 
						       dep, read, ip, pid, comm);
				add_cycle_to_list(&ind_cycle_locks, class);
				add_checked_cycle(class, dep);
				ret = 0;
			}
		}
	}

	list_for_each_entry(ind_list, &ind_cycle_locks, cycle_entry) {
		add_visit_to_hlist(visited, ind_list->class);
		dfs_head(ind_list->class, &stack, visited);
		del_visit_in_hlist(visited, ind_list->class->key);
	}

	lite_graph_unlock();

	raw_local_irq_restore(flags);

	return ret;
}

/*
 * Construct the reachability graph (including direct 
 * and indirect) due to the @next lock.
 */
static int
check_lock_reachability(struct task_struct *curr, struct lite_held_lock *next,
			int end)
{
	struct lite_held_lock *hlock;
	struct lite_lock_class *prev_class;
	struct lite_lock_class *next_class = lite_hlock_class(next);
	int i, ret = 1;

	if (next->read == 2)
		return 1;

	for (i = 0; i < end; i++) {
		hlock = curr->held_locks + i;
		prev_class = lite_hlock_class(hlock);

		// record direct edges
		if (in_lite_hlist_possible(prev_class->dir_from, next_class->key))
			continue;

		ret = add_lite_lock_to_hlist(prev_class->dir_from, next_class,
					     next->read, next->acquire_ip,
					     next->pid, next->comm);

		if (!ret)
			return 0;

		ret = add_lite_lock_to_hlist(next_class->dir_to, prev_class,
					     hlock->read, hlock->acquire_ip,
					     next->pid, next->comm);

		if (!ret)
			return 0;

		// propagate indirect dependencies
		propagate_reachability(hlock, next);
	}

	return ret;
}

/**
 * Since trylocks can be held in any order, we don't 
 * construct their reachabilities until the next non-
 * trylock comes. See check_prevs_add in lockdep.c.
 */
static int 
check_prevs_reachability(struct task_struct *curr, struct lite_held_lock *next)
{
	int i, ret = 1;
	int depth = curr->lite_lockdep_depth;
	int start = depth;
	struct lite_held_lock *hlock;

	for (;;) {
		if (!depth)
			break;

		hlock = curr->held_locks + depth - 1;
		if (!hlock->trylock) {
			start = depth;
			break;
		}

		depth--;
	}

	depth = curr->lite_lockdep_depth;

	for (i = start; i <= depth; i++) {
		hlock = curr->held_locks + i;
		
		if (hlock->read != 2 && !hlock->nest_lock && !hlock->subclass &&
		    hlock->check)
			ret &= check_lock_reachability(curr, hlock, i);
	}

	return ret;
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
	int ret = 1;

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
	hlock->pid = curr->pid;
	strcpy(hlock->comm, curr->comm);

	if (DEBUG_LOCKS_WARN_ON(!test_bit(class_idx, lite_lock_classes_in_use)))
		return 0;

	/* If the hlock is a recursive reader or nested lock, we don't
	 * propagate its reachability.
	 */
	if (check_reachability &&hlock->read != 2 && !nest_lock && !subclass && 
	    !reacquire && check && !trylock && lite_graph_lock()) {
		ret = check_prevs_reachability(curr, hlock);
		lite_graph_unlock();
	}

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

int detect_cycles_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	int old_value = detect_deadlocks;
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0 && write && old_value != detect_deadlocks && 
	    detect_deadlocks == 1) {
		detect_deadlocks = 0;
		detect_cycles();
	}
	return ret;
}
