/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _HNS_ROCE_INTF_H
#define _HNS_ROCE_INTF_H

struct rdfx_qp_info *rdfx_find_rdfx_qp(struct rdfx_info *rdfx,
					      unsigned long qpn);
struct rdfx_cq_info *rdfx_find_rdfx_cq(struct rdfx_info *rdfx,
					     unsigned long cqn);

#endif
