/* SPDX-License-Identifier: GPL-2.0, BSD
 *
 * /kernel/popcorn/wait_station.c
 *
 * Waiting stations allows threads to be waited for a given
 * number of events are completed
 *
 * Original file developed by SSRG at Virginia Tech.
 *
 * author, Javier Malave, Rebecca Shapiro, Andrew Hughes,
 * Narf Industries 2020 (modifications for upstream RFC)
 *
 */

#ifndef _REMOTE_PAGER_WAIT_STATION_H_
#define _REMOTE_PAGER_WAIT_STATION_H_

#include <linux/completion.h>
#include <linux/atomic.h>

struct wait_station {
	unsigned int id;
	void *private;
	struct completion pendings;
};

struct wait_station *get_wait_station(void);
struct wait_station *wait_station(int id);
void put_wait_station(struct wait_station *ws);
void *wait_at_station(struct wait_station *ws);
#endif
