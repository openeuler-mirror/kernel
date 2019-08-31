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
 * threads running on the same node as the current lock holder, and a
 * secondary queue for threads running on other nodes. At the unlock time,
 * the lock holder scans the main queue looking for a thread running on
 * the same node. If found (call it thread T), all threads in the main queue
 * between the current lock holder and T are moved to the end of the
 * secondary queue, and the lock is passed to T. If such T is not found, the
 * lock is passed to the first node in the secondary queue. Finally, if the
 * secondary queue is empty, the lock is passed to the next thread in the
 * main queue. To avoid starvation of threads in the secondary queue,
 * those threads are moved back to the head of the main queue
 * after a certain expected number of intra-node lock hand-offs.
 *
 * For more details, see https://arxiv.org/abs/1810.05600.
 *
 * Authors: Alex Kogan <alex.kogan@oracle.com>
 *          Dave Dice <dave.dice@oracle.com>
 */

struct cna_node {
	struct	mcs_spinlock mcs;
	u32	numa_node;
	u32	encoded_tail;
	struct	cna_node *tail;    /* points to the secondary queue tail */
};

#define CNA_NODE(ptr) ((struct cna_node *)(ptr))

/* Per-CPU pseudo-random number seed */
static DEFINE_PER_CPU(u32, seed);

/*
 * Controls the probability for intra-node lock hand-off. It can be
 * tuned and depend, e.g., on the number of CPUs per node. For now,
 * choose a value that provides reasonable long-term fairness without
 * sacrificing performance compared to a version that does not have any
 * fairness guarantees.
 */
#define INTRA_NODE_HANDOFF_PROB_ARG 0x10000

/*
 * Controls the probability for enabling the scan of the main queue when
 * the secondary queue is empty. The chosen value reduces the amount of
 * unnecessary shuffling of threads between the two waiting queues when
 * the contention is low, while responding fast enough and enabling
 * the shuffling when the contention is high.
 */
#define SHUFFLE_REDUCTION_PROB_ARG  0x80

/*
 * Return false with probability 1 / @range.
 * @range must be a power of 2.
 */
static bool probably(unsigned int range)
{
	u32 s;

	s = this_cpu_read(seed);
	s = next_pseudo_random32(s);
	this_cpu_write(seed, s);

	return s & (range - 1);
}

static void cna_init_node(struct mcs_spinlock *node)
{
	struct cna_node *cn = CNA_NODE(node);
	struct mcs_spinlock *base_node;
	int cpuid;

	BUILD_BUG_ON(sizeof(struct cna_node) > sizeof(struct qnode));
	/* we store a pointer in the node's @locked field */
	BUILD_BUG_ON(sizeof(uintptr_t) > sizeof_field(struct mcs_spinlock, locked));

	cpuid = smp_processor_id();
	cn->numa_node = cpu_to_node(cpuid);

	base_node = this_cpu_ptr(&qnodes[0].mcs);
	cn->encoded_tail = encode_tail(cpuid, base_node->count - 1);
}

/**
 * find_successor - Scan the main waiting queue looking for the first
 * thread running on the same node as the lock holder. If found (call it
 * thread T), move all threads in the main queue between the lock holder
 * and T to the end of the secondary queue and return T; otherwise, return NULL.
 */
static struct cna_node *find_successor(struct mcs_spinlock *me)
{
	struct cna_node *me_cna = CNA_NODE(me);
	struct cna_node *head_other, *tail_other, *cur;
	struct cna_node *next = CNA_NODE(READ_ONCE(me->next));
	int my_node;

	/* @next should be set, else we would not be calling this function. */
	WARN_ON_ONCE(next == NULL);

	my_node = me_cna->numa_node;

	/*
	 * Fast path - check whether the immediate successor runs on
	 * the same node.
	 */
	if (next->numa_node == my_node)
		return next;

	head_other = next;
	tail_other = next;

	/*
	 * Traverse the main waiting queue starting from the successor of my
	 * successor, and look for a thread running on the same node.
	 */
	cur = CNA_NODE(READ_ONCE(next->mcs.next));
	while (cur) {
		if (cur->numa_node == my_node) {
			/*
			 * Found a thread on the same node. Move threads
			 * between me and that node into the secondary queue.
			 */
			if (me->locked > 1)
				CNA_NODE(me->locked)->tail->mcs.next =
					(struct mcs_spinlock *)head_other;
			else
				me->locked = (uintptr_t)head_other;
			tail_other->mcs.next = NULL;
			CNA_NODE(me->locked)->tail = tail_other;
			return cur;
		}
		tail_other = cur;
		cur = CNA_NODE(READ_ONCE(cur->mcs.next));
	}
	return NULL;
}

static inline bool cna_set_locked_empty_mcs(struct qspinlock *lock, u32 val,
					struct mcs_spinlock *node)
{
	/* Check whether the secondary queue is empty. */
	if (node->locked <= 1) {
		if (atomic_try_cmpxchg_relaxed(&lock->val, &val,
				_Q_LOCKED_VAL))
			return true; /* No contention */
	} else {
		/*
		 * Pass the lock to the first thread in the secondary
		 * queue, but first try to update the queue's tail to
		 * point to the last node in the secondary queue.
		 */
		struct cna_node *succ = CNA_NODE(node->locked);
		u32 new = succ->tail->encoded_tail + _Q_LOCKED_VAL;

		if (atomic_try_cmpxchg_relaxed(&lock->val, &val, new)) {
			arch_mcs_spin_unlock_contended(&succ->mcs.locked, 1);
			return true;
		}
	}

	return false;
}

static inline void cna_pass_mcs_lock(struct mcs_spinlock *node,
				     struct mcs_spinlock *next)
{
	struct cna_node *succ = NULL;
	u64 *var = &next->locked;
	u64 val = 1;

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
	 * Try to pass the lock to a thread running on the same node.
	 * For long-term fairness, search for such a thread with high
	 * probability rather than always.
	 */
	if (probably(INTRA_NODE_HANDOFF_PROB_ARG))
		succ = find_successor(node);

	if (succ) {
		var = &succ->mcs.locked;
		/*
		 * We unlock a successor by passing a non-zero value,
		 * so set @val to 1 iff @locked is 0, which will happen
		 * if we acquired the MCS lock when its queue was empty
		 */
		val = node->locked + (node->locked == 0);
	} else if (node->locked > 1) { /* if the secondary queue is not empty */
		/* pass the lock to the first node in that queue */
		succ = CNA_NODE(node->locked);
		succ->tail->mcs.next = next;
		var = &succ->mcs.locked;
	}	/*
		 * Otherwise, pass the lock to the immediate successor
		 * in the main queue.
		 */

pass_lock:
	arch_mcs_spin_unlock_contended(var, val);
}
