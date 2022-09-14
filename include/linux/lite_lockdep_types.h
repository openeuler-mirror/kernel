#ifndef __LINUX_LITE_LOCKDEP_TYPES_H
#define __LINUX_LITE_LOCKDEP_TYPES_H

#include <linux/types.h>

#ifdef CONFIG_LITE_LOCKDEP

#define MAX_LITE_LOCKDEP_KEYS_BITS	13
#define MAX_LITE_LOCKDEP_KEYS		(1UL << MAX_LITE_LOCKDEP_KEYS_BITS)
#define MAX_LITE_LOCKDEP_CHAINS_BITS	16

struct lite_lock_class_sub_key {
	char __one_byte;
} __attribute__ ((__packed__));

/* hash_entry is used to keep track of dynamically allocated keys. */
struct lite_lock_class_key {
	union {
		struct hlist_node		hash_entry;
		struct lite_lock_class_sub_key	sub_key[1];
	};
};

struct lite_lock_class {
    	/*
	 * class-hash:
	 */
    	struct hlist_node		hash_entry;

	struct list_head		lock_entry;

	const struct lite_lock_class_sub_key *key;

	const char			*name;
} __no_randomize_layout;

/*
 * Map the lock object (the lock instance) to the lock-class object.
 * This is embedded into specific lock instances:
 */
struct lite_lockdep_map {
	struct lite_lock_class_key	*key;
	struct lite_lock_class		*class;
	const char			*name;
};

#else /* !CONFIG_LITE_LOCKDEP */
struct lite_lock_class_key { };
struct lite_lockdep_map { };

#endif /* CONFIG_LITE_LOCKDEP */

#endif /* __LINUX_LITE_LOCKDEP_TYPES_H */
