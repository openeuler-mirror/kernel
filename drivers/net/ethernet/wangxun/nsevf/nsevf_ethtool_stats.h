/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/* ethtool statistics helpers */

/**
 * struct nsevf_stats - definition for an ethtool statistic
 * @stat_string: statistic name to display in ethtool -S output
 * @sizeof_stat: the sizeof() the stat, must be no greater than sizeof(u64)
 * @stat_offset: offsetof() the stat from a base pointer
 *
 * This structure defines a statistic to be added to the ethtool stats buffer.
 * It defines a statistic as offset from a common base pointer. Stats should
 * be defined in constant arrays using the NSEVF_STAT macro, with every element
 * of the array using the same _type for calculating the sizeof_stat and
 * stat_offset.
 *
 * The @sizeof_stat is expected to be sizeof(u8), sizeof(u16), sizeof(u32) or
 * sizeof(u64). Other sizes are not expected and will produce a WARN_ONCE from
 * the nsevf_add_ethtool_stat() helper function.
 *
 * The @stat_string is interpreted as a format string, allowing formatted
 * values to be inserted while looping over multiple structures for a given
 * statistics array. Thus, every statistic string in an array should have the
 * same type and number of format specifiers, to be formatted by variadic
 * arguments to the nsevf_add_stat_string() helper function.
 **/
struct nsevf_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

/* Helper macro to define an nsevf_stat structure with proper size and type.
 * Use this when defining constant statistics arrays. Note that @_type expects
 * only a type name and is used multiple times.
 */
#define NSEVF_STAT(_type, _name, _stat)              \
	{ .stat_string = _name,                      \
	  .sizeof_stat = sizeof_field(_type, _stat), \
	  .stat_offset = offsetof(_type, _stat) }

/* Helper macro for defining some statistics related to queues */
#define NSEVF_QUEUE_STAT(_name, _stat) \
	NSEVF_STAT(struct nsevf_ring, _name, _stat)

#define NSEVF_TXCQ_STAT(_name, _stat) \
	NSEVF_STAT(struct nsevf_txcq_ring, _name, _stat)

#define PICK(legacy_stat, unified_stat) legacy_stat

#define NSEVF_TXQ_PACKETS PICK("tx_queue-%u.packets", "txq-%u.pkts")
#define NSEVF_TXQ_BYTES PICK("tx_queue-%u.bytes", "txq-%u.bytes")
#define NSEVF_RXQ_PACKETS PICK("rx_queue-%u.packets", "rxq-%u.pkts")
#define NSEVF_RXQ_BYTES PICK("rx_queue-%u.bytes", "rxq-%u.bytes")

#define NSEVF_TXCQ_PACKETS PICK("txcqueue-%u.packets", "txcq-%u.pkts")
#define NSEVF_TXCQ_BYTES PICK("txcqueue-%u.bytes", "txcq-%u.bytes")
#define NSEVF_TXCQ_CQE_CNT PICK("txcqueue-%u.cqe_cnt", "txcq-%u.cqe_cnt")
#define NSEVF_TXCQ_GEN_FLIP_CNT PICK("txcqueue-%u.flip_cnt", "txcq-%u.flip_cnt")
#define NSEVF_TXCQ_TXQE_CNT PICK("txcqueue-%u.txqe_cnt", "txcq-%u.txqe_cnt")

/* Stats associated with a Tx ring */
static struct nsevf_stats nsevf_gstrings_txq_stats[] = {
	NSEVF_QUEUE_STAT(NSEVF_TXQ_PACKETS, stats.packets),
	NSEVF_QUEUE_STAT(NSEVF_TXQ_BYTES, stats.bytes),
};

/* Stats associated with a Rx ring */
static struct nsevf_stats nsevf_gstrings_rxq_stats[] = {
	NSEVF_QUEUE_STAT(NSEVF_RXQ_PACKETS, stats.packets),
	NSEVF_QUEUE_STAT(NSEVF_RXQ_BYTES, stats.bytes),
};

/* Stats associated with a Tx-CQ ring */
static struct nsevf_stats nsevf_gstrings_txcq_stats[] = {
	NSEVF_TXCQ_STAT(NSEVF_TXCQ_PACKETS, stats.pkts),
	NSEVF_TXCQ_STAT(NSEVF_TXCQ_BYTES, stats.bytes),
	NSEVF_TXCQ_STAT(NSEVF_TXCQ_CQE_CNT, stats.cqe_cnt),
	NSEVF_TXCQ_STAT(NSEVF_TXCQ_GEN_FLIP_CNT, stats.gen_flip_cnt),
	NSEVF_TXCQ_STAT(NSEVF_TXCQ_TXQE_CNT, stats.txqe_cnt),
};

/**
 * nsevf_add_one_ethtool_stat - copy the stat into the supplied buffer
 * @data: location to store the stat value
 * @pointer: basis for where to copy from
 * @stat: the stat definition
 *
 * Copies the stat data defined by the pointer and stat structure pair into
 * the memory supplied as data. Used to implement nsevf_add_ethtool_stats and
 * nsevf_add_queue_stats. If the pointer is null, data will be zero'd.
 */
static void nsevf_add_one_ethtool_stat(u64 *data, void *pointer,
				       const struct nsevf_stats *stat)
{
	char *p;

	if (!pointer) {
		/* ensure that the ethtool data buffer is zero'd for any stats
		 * which don't have a valid pointer.
		 */
		*data = 0;
		return;
	}

	p = (char *)pointer + stat->stat_offset;
	switch (stat->sizeof_stat) {
	case sizeof(u64):
		*data = *((u64 *)p);
		break;
	case sizeof(u32):
		*data = *((u32 *)p);
		break;
	case sizeof(u16):
		*data = *((u16 *)p);
		break;
	case sizeof(u8):
		*data = *((u8 *)p);
		break;
	default:
		WARN_ONCE(1, "unexpected stat size for %s", stat->stat_string);
		*data = 0;
	}
}

/**
 * __nsevf_add_ethtool_stats - copy stats into the ethtool supplied buffer
 * @data: ethtool stats buffer
 * @pointer: location to copy stats from
 * @stats: array of stats to copy
 * @size: the size of the stats definition
 *
 * Copy the stats defined by the stats array using the pointer as a base into
 * the data buffer supplied by ethtool. Updates the data pointer to point to
 * the next empty location for successive calls to __nsevf_add_ethtool_stats.
 * If pointer is null, set the data values to zero and update the pointer to
 * skip these stats.
 **/
static void __nsevf_add_ethtool_stats(u64 **data, void *pointer,
				      const struct nsevf_stats stats[],
				      const unsigned int size)
{
	unsigned int i;

	for (i = 0; i < size; i++)
		nsevf_add_one_ethtool_stat((*data)++, pointer, &stats[i]);
}

/**
 * nsevf_add_ethtool_stats - copy stats into ethtool supplied buffer
 * @data: ethtool stats buffer
 * @pointer: location where stats are stored
 * @stats: static const array of stat definitions
 *
 * Macro to ease the use of __nsevf_add_ethtool_stats by taking a static
 * constant stats array and passing the ARRAY_SIZE(). This avoids typos by
 * ensuring that we pass the size associated with the given stats array.
 *
 * The parameter @stats is evaluated twice, so parameters with side effects
 * should be avoided.
 **/
#define nsevf_add_ethtool_stats(data, pointer, stats) \
	__nsevf_add_ethtool_stats(data, pointer, stats, ARRAY_SIZE(stats))

/**
 * nsevf_add_queue_stats - copy queue statistics into supplied buffer
 * @data: ethtool stats buffer
 * @ring: the ring to copy
 *
 * Queue statistics must be copied while protected by
 * u64_stats_fetch_begin, so we can't directly use nsevf_add_ethtool_stats.
 * Assumes that queue stats are defined in nsevf_gstrings_queue_stats. If the
 * ring pointer is null, zero out the queue stat values and update the data
 * pointer. Otherwise safely copy the stats from the ring into the supplied
 * buffer and update the data pointer when finished.
 *
 * This function expects to be called while under rcu_read_lock().
 **/
static void nsevf_add_txq_rxq_stats(u64 **data, struct nsevf_ring *ring,
				    bool txq)
{
	unsigned int size;
	struct nsevf_stats *stats;
	unsigned int start;
	unsigned int i;

	if (txq) {
		size = ARRAY_SIZE(nsevf_gstrings_txq_stats);
		stats = nsevf_gstrings_txq_stats;
	} else {
		size = ARRAY_SIZE(nsevf_gstrings_rxq_stats);
		stats = nsevf_gstrings_rxq_stats;
	}

	/* To avoid invalid statistics values, ensure that we keep retrying
	 * the copy until we get a consistent value according to
	 * u64_stats_fetch_retry_irq. But first, make sure our ring is
	 * non-null before attempting to access its syncp.
	 */
	do {
		start = !ring ? 0 : u64_stats_fetch_begin(&ring->syncp);
		for (i = 0; i < size; i++) {
			nsevf_add_one_ethtool_stat(&(*data)[i], ring,
						   &stats[i]);
		}
	} while (ring && u64_stats_fetch_retry(&ring->syncp, start));

	/* Once we successfully copy the stats in, update the data pointer */
	*data += size;
}

static void nsevf_add_txcq_stats(u64 **data, struct nsevf_txcq_ring *ring)
{
	unsigned int size;
	struct nsevf_stats *stats;
	unsigned int start;
	unsigned int i;

	size = ARRAY_SIZE(nsevf_gstrings_txcq_stats);
	stats = nsevf_gstrings_txcq_stats;

	/* To avoid invalid statistics values, ensure that we keep retrying
	 * the copy until we get a consistent value according to
	 * u64_stats_fetch_retry_irq. But first, make sure our ring is
	 * non-null before attempting to access its syncp.
	 */
	do {
		start = !ring ? 0 : u64_stats_fetch_begin(&ring->syncp);
		for (i = 0; i < size; i++) {
			nsevf_add_one_ethtool_stat(&(*data)[i], ring,
						   &stats[i]);
		}
	} while (ring && u64_stats_fetch_retry(&ring->syncp, start));

	/* Once we successfully copy the stats in, update the data pointer */
	*data += size;
}

/**
 * __nsevf_add_stat_strings - copy stat strings into ethtool buffer
 * @p: ethtool supplied buffer
 * @stats: stat definitions array
 * @size: size of the stats array
 *
 * Format and copy the strings described by stats into the buffer pointed at
 * by p.
 **/
static void __nsevf_add_stat_strings(u8 **p, const struct nsevf_stats *stats,
				     const unsigned int size, ...)
{
	unsigned int i;

	for (i = 0; i < size; i++) {
		va_list args;

		va_start(args, size);
		vsnprintf(*p, ETH_GSTRING_LEN, stats[i].stat_string, args);
		*p += ETH_GSTRING_LEN;
		va_end(args);
	}
}

/**
 * nsevf_add_stat_strings - copy stat strings into ethtool buffer
 * @p: ethtool supplied buffer
 * @stats: stat definitions array
 *
 * Format and copy the strings described by the const static stats value into
 * the buffer pointed at by p.
 *
 * The parameter @stats is evaluated twice, so parameters with side effects
 * should be avoided. Additionally, stats must be an array such that
 * ARRAY_SIZE can be called on it.
 **/
#define nsevf_add_stat_strings(p, stats, ...) \
	__nsevf_add_stat_strings(p, stats, ARRAY_SIZE(stats), ##__VA_ARGS__)
