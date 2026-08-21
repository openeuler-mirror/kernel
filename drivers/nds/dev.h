/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_DEV_H_
#define P2P_DEV_H_

#include <linux/blk_types.h>

struct request;

void p2p_complete_io(struct request *req, blk_status_t status);

#endif
