#ifndef __LINUX_LITE_LOCKDEP_H
#define __LINUX_LITE_LOCKDEP_H

#include <linux/lite_lockdep_types.h>

struct task_struct;

/* sysctl */
extern int lite_lockdep;
extern int check_reachability;
extern int detect_deadlocks;

#ifdef CONFIG_LITE_LOCKDEP

#include <linux/lite_lockdep_types.h>

extern void lite_lock_acquire(struct lite_lockdep_map *lock, unsigned int subclass,
			      int trylock, int read, int check,
			      struct lite_lockdep_map *nest_lock, unsigned long ip);

extern void lite_lock_release(struct lite_lockdep_map *lock, unsigned long ip);

#define lite_lock_acquire_exclusive(l, s, t, n, i)		lite_lock_acquire(l, s, t, 0, 1, n, i)
#define lite_lock_acquire_shared(l, s, t, n, i)			lite_lock_acquire(l, s, t, 1, 1, n, i)
#define lite_lock_acquire_shared_recursive(l, s, t, n, i)	lite_lock_acquire(l, s, t, 2, 1, n, i)

#define lite_spin_acquire(l, s, t, i)		lite_lock_acquire_exclusive(l, s, t, NULL, i)
#define lite_spin_acquire_nest(l, s, t, n, i)	lite_lock_acquire_exclusive(l, s, t, n, i)
#define lite_spin_release(l, i)			lite_lock_release(l, i)

#define lite_mutex_acquire(l, s, t, i)		lite_lock_acquire_exclusive(l, s, t, NULL, i)
#define lite_mutex_acquire_nest(l, s, t, n, i)	lite_lock_acquire_exclusive(l, s, t, n, i)
#define lite_mutex_release(l, i)		lite_lock_release(l, i)

#define lite_rwsem_acquire(l, s, t, i)		lite_lock_acquire_exclusive(l, s, t, NULL, i)
#define lite_rwsem_acquire_nest(l, s, t, n, i)	lite_lock_acquire_exclusive(l, s, t, n, i)
#define lite_rwsem_acquire_read(l, s, t, i)	lite_lock_acquire_shared(l, s, t, NULL, i)
#define lite_rwsem_release(l, i)		lite_lock_release(l, i)

struct lite_held_lock {
	unsigned long			acquire_ip;
	struct lite_lockdep_map		*instance;
	struct lite_lockdep_map		*nest_lock;
	unsigned int 			subclass;
	pid_t				pid;
	char				comm[TASK_COMM_LEN];
	unsigned int			class_idx:MAX_LITE_LOCKDEP_KEYS_BITS;
	unsigned int 			trylock:1;
	unsigned int 			read:2;
	unsigned int 			check:1;
};


struct lite_lock_list {
	struct hlist_node		hash_entry;
	struct lite_lock_class		*class;
	unsigned long			acquire_ip;
	pid_t				pid;
	char				comm[TASK_COMM_LEN];
	unsigned int			read:2;
};

struct ind_cycle_list {
	struct list_head		cycle_entry;
	struct lite_lock_class		*class;
};

struct stack_list {
	struct list_head		stack_entry;
	struct lite_lock_list		*lock_entry;
};

struct visit_hlist {
	struct hlist_node		vis_entry;
	struct lite_lock_class		*class;
};

struct deadlock_entry {
	unsigned long 			chain_head;
	unsigned long 			chain_tail;
};

struct ind_cycle_entry {
	const struct lite_lock_class_sub_key *head;
	const struct lite_lock_class_sub_key *dep;
};

extern int detect_cycles_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);

extern void lite_lockdep_print_held_locks(struct task_struct *p);

extern void lite_debug_show_all_locks(void);

extern void lite_lockdep_init_map_type(struct lite_lockdep_map *lock, const char *name,
	struct lite_lock_class_key *key, int subclass);

static inline void
lite_lockdep_init_map(struct lite_lockdep_map *lock, const char *name,
		       struct lite_lock_class_key *key, int subclass)
{
	lite_lockdep_init_map_type(lock, name, key, subclass);
}

#define lite_lockdep_set_class(lock, key)					\
	lite_lockdep_init_map(&(lock)->lite_dep_map, #key, key, 0)

#define lite_lockdep_set_class_and_name(lock, key, name)			\
	lite_lockdep_init_map(&(lock)->lite_dep_map, name, key, 0)

#define lite_lockdep_set_novalidate_class(lock) \
	lite_lockdep_set_class_and_name(lock, &__lite_lockdep_no_validate__, #lock)

#define lite_lockdep_match_class(lock, key) \
	lite_lockdep_match_key(&(lock)->lite_dep_map, key)

static inline int lite_lockdep_match_key(struct lite_lockdep_map *lock,
				    	 struct lite_lock_class_key *key)
{
	return lock->key == key;
}

#else /* !CONFIG_LITE_LOCKDEP */

# define lite_lock_acquire(l, s, t, r, c, n, i)	do { } while (0)
# define lite_lock_release(l, i)		do { } while (0)
# define lite_lockdep_set_novalidate_class(l)   do { } while (0)
# define lite_lockdep_set_class(l, m)		do { } while (0)

#endif /* CONFIG_LITE_LOCKDEP */

#endif /* __LINUX_LITE_LOCKDEP_H */