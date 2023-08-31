// SPDX-License-Identifier: GPL-2.0, BSD
/*
 * Waiting stations allows threads to be waited for a given
 * number of events are completed
 *
 * Original file developed by SSRG at Virginia Tech.
 *
 * author, Javier Malave, Rebecca Shapiro, Andrew Hughes,
 * Narf Industries 2020 (modifications for upstream RFC)
 *
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/err.h>

#include "wait_station.h"

#define MAX_WAIT_STATIONS 1024
#define MAX_WAIT_IO_TIMEOUT (300 * HZ)

static struct wait_station wait_stations[MAX_WAIT_STATIONS];

static DEFINE_SPINLOCK(wait_station_lock);
static DECLARE_BITMAP(wait_station_available, MAX_WAIT_STATIONS) = { 0 };

struct wait_station *get_wait_station(void)
{
	int id;
	struct wait_station *ws;

	spin_lock(&wait_station_lock);
	id = find_first_zero_bit(wait_station_available, MAX_WAIT_STATIONS);
	ws = wait_stations + id;
	set_bit(id, wait_station_available);
	spin_unlock(&wait_station_lock);

	ws->id = id;
	ws->private = (void *)0xbad0face;
	init_completion(&ws->pendings);

	return ws;
}
EXPORT_SYMBOL_GPL(get_wait_station);

struct wait_station *wait_station(int id)
{
	/* memory barrier */
	smp_rmb();
	return wait_stations + id;
}
EXPORT_SYMBOL_GPL(wait_station);

void put_wait_station(struct wait_station *ws)
{
	int id = ws->id;

	spin_lock(&wait_station_lock);
	clear_bit(id, wait_station_available);
	spin_unlock(&wait_station_lock);
}
EXPORT_SYMBOL_GPL(put_wait_station);

void *wait_at_station(struct wait_station *ws)
{
	void *ret;

	if (!try_wait_for_completion(&ws->pendings)) {
		if (wait_for_completion_io_timeout(&ws->pendings, MAX_WAIT_IO_TIMEOUT) == 0) {
			pr_err("%s timeout\n", __func__);
			ret = ERR_PTR(-ETIMEDOUT);
			goto out;
		}
	}
	/* memory barrier */
	smp_rmb();
	ret = ws->private;
out:
	put_wait_station(ws);
	return ret;
}
EXPORT_SYMBOL_GPL(wait_at_station);
