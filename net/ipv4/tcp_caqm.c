// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) Huawei Technologies Co., Ltd. 2020-2024
 * All rights reserved.
 *
 * DataCenter TCP with CAQM (Confined Active Queue Management).
 * enable needs specific switch support
 *
 * Authors:
 *	Chengjun Jia <jiachengjun2@huawei.com>
 *	Shurui Ding <dongshurui@huawei.com>
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include "tcp_caqm.h"

static struct tcp_congestion_ops caqm_reno;

static size_t caqm_get_info(struct sock *sk, u32 ext, int *attr, union tcp_cc_info *info)
{
	return 0;
}

static void caqm_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct caqm_ca *ca = inet_csk_ca(sk);

	if ((tp->ecn_flags & TCP_CAQM_OK) == TCP_CAQM_OK) {
		init_caqm_ca(ca);
		return;
	}

	/* No CAQM support Fall back to Reno.
	 * checkout clear work, see tcp_dctcp.c:95
	 */
	WRITE_ONCE(inet_csk(sk)->icsk_ca_ops, &caqm_reno);
}

static u32 tcp_caqm_ssthresh(struct sock *sk)
{
	struct caqm_ca *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (!ca->caqm_ca_enable)
		return tcp_reno_ssthresh(sk);
	ca->loss_cwnd = tp->snd_cwnd;
	// reno: 1/2*snd_cwnd, dctcp: (1-alpha/2)*snd_cwnd; caqm: keep it
	return max(tp->snd_cwnd, caqm_para_min_cwnd);
}

static void tcp_caqm_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct caqm_ca *ca = inet_csk_ca(sk);

	if (!ca->caqm_ca_enable) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}
}

static void tcp_caqm_react_to_loss(struct sock *sk)
{
	struct caqm_ca *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->loss_cwnd = tp->snd_cwnd;
	tp->snd_ssthresh = max(tp->snd_cwnd >> 1U, 2U);
}

static void tcp_caqm_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Recovery &&
	    new_state != inet_csk(sk)->icsk_ca_state)
		tcp_caqm_react_to_loss(sk);
	/* We handle RTO in tcp_caqm_cwnd_event to ensure that we perform only
	 * one loss-adjustment per RTT.
	 */
}

static u32 tcp_caqm_undo_cwnd(struct sock *sk)
{
	struct caqm_ca *ca = inet_csk_ca(sk);

	if (!ca->caqm_ca_enable)
		return tcp_reno_undo_cwnd(sk);
	// Update 7.22: reno_undo_cwnd can not keep the cwnd, so keep it
	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

/* alg works as reno by default.
 * Only after syn--syn-ack to enable, the alg changes to caqm.*/
static struct tcp_congestion_ops caqm __read_mostly = {
	.init		= caqm_init,
	.ssthresh	= tcp_caqm_ssthresh,
	.cong_avoid	= tcp_caqm_cong_avoid,
	.undo_cwnd	= tcp_caqm_undo_cwnd,
	.set_state	= tcp_caqm_state,
	.get_info	= caqm_get_info,
	.flags		= TCP_CONG_NEEDS_CAQM,
	.owner		= THIS_MODULE,
	.name		= "caqm",
};

static struct tcp_congestion_ops caqm_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= caqm_get_info,
	.owner		= THIS_MODULE,
	.name		= "caqm_reno",
};

static int __init caqm_register(void)
{
	BUILD_BUG_ON(sizeof(struct caqm_ca) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&caqm);
}

static void __exit caqm_unregister(void)
{
	tcp_unregister_congestion_control(&caqm);
}

module_init(caqm_register);
module_exit(caqm_unregister);

MODULE_AUTHOR("Chengjun Jia <jiachengjun2@huawei.com>");
MODULE_AUTHOR("Shurui Dong <dongshurui@huawei.com>");

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP w Confined Active Queue Management(CAQM)");
