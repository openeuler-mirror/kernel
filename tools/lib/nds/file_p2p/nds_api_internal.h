/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NDS_API_INTERNAL_H_
#define NDS_API_INTERNAL_H_

#include "nds_api.h"

/* Private layout shared by the library bindings and white-box tests. */
struct nds_io_ctx {
	int p2p_fd;
};

#endif
