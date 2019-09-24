/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _GEN_CNA_LOCK_SLOWPATH
#error "do not include this file"
#endif

#include <linux/topology.h>
#include <linux/random.h>

/*
 * Implement a NUMA-aware version of MCS (aka CNA, or compact NUMA-aware lock).
 *
 * In CNA, spinning threads are organized in two queues, a main queue for
 * threads running on the same NUMA node as the current lock holder, and a
 * secondary queue for threads running on other nodes. Schematically, it
 * looks like this:
 *
 *    cna_node
 *   +----------+    +--------+        +--------+
 *   |mcs:next  | -> |mcs:next| -> ... |mcs:next| -> NULL      [Main queue]
 *   |mcs:locked|    +--------+        +--------+
 *   +----------+
 *             |   +--------+         +--------+
 *             +-> |mcs:next| -> ...  |mcs:next| -> NULL  [Secondary queue]
 *                 |cna:tail| -+      +--------+
 *                 +--------+  |        ^
 *                              +-------+
 *
 * N.B. locked = 1 if secondary queue is absent.
 *
 * At the unlock time, the lock holder scans the main queue looking for a thread
 * running on the same node. If found (call it thread T), all threads in the
 * main queue between the current lock holder and T are moved to the end of the
 * secondary queue, and the lock is passed to T. If such T is not found, the
 * lock is passed to the first node in the secondary queue. Finally, if the
 * secondary queue is empty, the lock is passed to the next thread in the
 * main queue. To avoid starvation of threads in the secondary queue,
 * those threads are moved back to the head of the main queue after a certain
 * expected number of intra-node lock hand-offs.
 *
 *
 * For more details, see https://arxiv.org/abs/1810.05600.
 *
 * Authors: Alex Kogan <alex.kogan@oracle.com>
 *          Dave Dice <dave.dice@oracle.com>
 */

struct cna_node {
	struct	mcs_spinlock mcs;
	int	numa_node;
	u32	encoded_tail;
	struct	cna_node *tail;    /* points to the secondary queue tail */
};

#ifndef CONFIG_PARAVIRT_SPINLOCKS
void (*cna_queued_spin_lock_slowpath)(struct qspinlock *lock, u32 val) =
		native_queued_spin_lock_slowpath;
EXPORT_SYMBOL(cna_queued_spin_lock_slowpath);
#endif

/* Per-CPU pseudo-random number seed */
static DEFINE_PER_CPU(u32, seed);

/*
 * Controls the probability for intra-node lock hand-off. It can be
 * tuned and depend, e.g., on the number of CPUs per node. For now,
 * choose a value that provides reasonable long-term fairness without
 * sacrificing performance compared to a version that does not have any
 * fairness guarantees.
 */
#define INTRA_NODE_HANDOFF_PROB_ARG (16)

/*
 * Controls the probability for enabling the scan of the main queue when
 * the secondary queue is empty. The chosen value reduces the amount of
 * unnecessary shuffling of threads between the two waiting queues when
 * the contention is low, while responding fast enough and enabling
 * the shuffling when the contention is high.
 */
#define SHUFFLE_REDUCTION_PROB_ARG  (7)

/*
 * Return false with probability 1 / 2^@num_bits.
 * Intuitively, the larger @num_bits the less likely false is to be returned.
 * @num_bits must be a number between 0 and 31.
 */
static bool probably(unsigned int num_bits)
{
	u32 s;

	s = this_cpu_read(seed);
	s = next_pseudo_random32(s);
	this_cpu_write(seed, s);

	return s & ((1 << num_bits) - 1);
}

static void __init cna_init_nodes_per_cpu(unsigned int cpu)
{
	struct mcs_spinlock *base = per_cpu_ptr(&qnodes[0].mcs, cpu);
	int numa_node = cpu_to_node(cpu);
	int i;

	for (i = 0; i < MAX_NODES; i++) {
		struct cna_node *cn = (struct cna_node *)grab_mcs_node(base, i);

		cn->numa_node = numa_node;
		cn->encoded_tail = encode_tail(cpu, i);
		/*
		 * @encoded_tail has to be larger than 1, so we do not confuse
		 * it with other valid values for @locked (0 or 1)
		 */
		WARN_ON(cn->encoded_tail <= 1);
	}
}

static void __init cna_init_nodes(void)
{
	unsigned int cpu;

	BUILD_BUG_ON(sizeof(struct cna_node) > sizeof(struct qnode));
	/* we store an ecoded tail word in the node's @locked field */
	BUILD_BUG_ON(sizeof(u32) > sizeof(unsigned int));

	for_each_possible_cpu(cpu)
		cna_init_nodes_per_cpu(cpu);
}
early_initcall(cna_init_nodes);

static inline bool cna_try_change_tail(struct qspinlock *lock, u32 val,
				       struct mcs_spinlock *node)
{
	struct cna_node *succ;
	u32 new;

	/* If the secondary queue is empty, do what MCS does. */
	if (node->locked <= 1)
		return __try_clear_tail(lock, val, node);

	/*
	 * Try to update the tail value to the last node in the secondary queue.
	 * If successful, pass the lock to the first thread in the secondary
	 * queue. Doing those two actions effectively moves all nodes from the
	 * secondary queue into the main one.
	 */
	succ = (struct cna_node *)decode_tail(node->locked);
	new = succ->tail->encoded_tail + _Q_LOCKED_VAL;

	if (atomic_try_cmpxchg_relaxed(&lock->val, &val, new)) {
		arch_mcs_spin_unlock_contended(&succ->mcs.locked, 1);
		return true;
	}

	return false;
}

/*
 * cna_splice_tail -- splice nodes in the main queue between [first, last]
 * onto the secondary queue.
 */
static void cna_splice_tail(struct cna_node *cn, struct cna_node *first,
			    struct cna_node *last)
{
	/* remove [first,last] */
	cn->mcs.next = last->mcs.next;
	last->mcs.next = NULL;

	/* stick [first,last] on the secondary queue tail */
	if (cn->mcs.locked <= 1) {	/* if secondary queue is empty */
		/* create secondary queue */
		first->tail = last;
		cn->mcs.locked = first->encoded_tail;
	} else {
		/* add to the tail of the secondary queue */
		struct cna_node *head_2nd =
			(struct cna_node *)decode_tail(cn->mcs.locked);
		head_2nd->tail->mcs.next = &first->mcs;
		head_2nd->tail = last;
	}
}

/*
 * cna_try_find_next - scan the main waiting queue looking for the first
 * thread running on the same NUMA node as the lock holder. If found (call it
 * thread T), move all threads in the main queue between the lock holder and
 * T to the end of the secondary queue and return T; otherwise, return NULL.
 *
 * Schematically, this may look like the following (nn stands for numa_node and
 * et stands for encoded_tail).
 *
 *     when cna_try_find_next() is called (the secondary queue is empty):
 *
 *  A+------------+   B+--------+   C+--------+   T+--------+
 *   |mcs:next    | -> |mcs:next| -> |mcs:next| -> |mcs:next| -> NULL
 *   |mcs:locked=1|    |cna:nn=0|    |cna:nn=2|    |cna:nn=1|
 *   |cna:nn=1    |    +--------+    +--------+    +--------+
 *   +----------- +
 *
 *     when cna_try_find_next() returns (the secondary queue contains B and C):
 *
 *  A+----------------+    T+--------+
 *   |mcs:next        | ->  |mcs:next| -> NULL
 *   |mcs:locked=B.et | -+  |cna:nn=1|
 *   |cna:nn=1        |  |  +--------+
 *   +--------------- +  |
 *                       |
 *                       +->  B+--------+   C+--------+
 *                             |mcs:next| -> |mcs:next|
 *                             |cna:nn=0|    |cna:nn=2|
 *                             |cna:tail| -> +--------+
 *                             +--------+
 *
 * The worst case complexity of the scan is O(n), where n is the number
 * of current waiters. However, the fast path, which is expected to be the
 * common case, is O(1).
 */
static struct mcs_spinlock *cna_try_find_next(struct mcs_spinlock *node,
					      struct mcs_spinlock *next)
{
	struct cna_node *cn = (struct cna_node *)node;
	struct cna_node *cni = (struct cna_node *)next;
	struct cna_node *first, *last = NULL;
	int my_numa_node = cn->numa_node;

	/* fast path: immediate successor is on the same NUMA node */
	if (cni->numa_node == my_numa_node)
		return next;

	/* find any next waiter on 'our' NUMA node */
	for (first = cni;
	     cni && cni->numa_node != my_numa_node;
	     last = cni, cni = (struct cna_node *)READ_ONCE(cni->mcs.next))
		;

	/* if found, splice any skipped waiters onto the secondary queue */
	if (cni && last)
		cna_splice_tail(cn, first, last);

	return (struct mcs_spinlock *)cni;
}

static inline void cna_pass_lock(struct mcs_spinlock *node,
				 struct mcs_spinlock *next)
{
	struct mcs_spinlock *next_holder = next, *new_next = NULL;
	u32 val = 1;

	/*
	 * Limit thread shuffling when the secondary queue is empty.
	 * This copes with the overhead the shuffling creates when the
	 * lock is only lightly contended, and threads do not stay
	 * in the secondary queue long enough to reap the benefit of moving
	 * them there.
	 */
	if (node->locked <= 1 && probably(SHUFFLE_REDUCTION_PROB_ARG))
		goto pass_lock;

	/*
	 * Try to find a successor running on the same NUMA node
	 * as the current lock holder. For long-term fairness,
	 * search for such a thread with high probability rather than always.
	 */
	if (probably(INTRA_NODE_HANDOFF_PROB_ARG))
		new_next = cna_try_find_next(node, next);

	if (new_next) {		          /* if such successor is found */
		next_holder = new_next;
		/*
		 * Note that @locked here can be 0, 1 or an encoded pointer to
		 * the head of the secondary queue. We pass the lock by storing
		 * a non-zero value, so make sure @val gets 1 iff @locked is 0.
		 */
		val = node->locked + (node->locked == 0);
	} else if (node->locked > 1) {	  /* if secondary queue is not empty */
		/* next holder will be the first node in the secondary queue */
		next_holder = decode_tail(node->locked);
		/* splice the secondary queue onto the head of the main queue */
		((struct cna_node *)next_holder)->tail->mcs.next = next;
	}

pass_lock:
	arch_mcs_spin_unlock_contended(&next_holder->locked, val);
}
