/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _TCP_EXT_H
#define _TCP_EXT_H

void tcp_wfree(struct sk_buff *skb);

static inline bool is_skb_wmem(const struct sk_buff *skb)
{
	return skb->destructor == sock_wfree ||
	       skb->destructor == __sock_wfree ||
	       (IS_ENABLED(CONFIG_INET) && skb->destructor == tcp_wfree);
}
#endif /* _TCP_EXT_H */
