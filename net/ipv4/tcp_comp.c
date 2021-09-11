// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP compression support
 *
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 */

#include <net/tcp.h>
#include <net/strparser.h>
#include <linux/zstd.h>

#define TCP_COMP_MAX_PADDING	64
#define TCP_COMP_SCRATCH_SIZE	65535
#define TCP_COMP_MAX_CSIZE	(TCP_COMP_SCRATCH_SIZE + TCP_COMP_MAX_PADDING)
#define TCP_COMP_ALLOC_ORDER	get_order(65536)
#define TCP_COMP_MAX_WINDOWLOG 17
#define TCP_COMP_MAX_INPUT (1 << TCP_COMP_MAX_WINDOWLOG)

#define TCP_COMP_SEND_PENDING	1
#define ZSTD_COMP_DEFAULT_LEVEL	1

static unsigned long tcp_compression_ports[65536 / 8];

unsigned long *sysctl_tcp_compression_ports = tcp_compression_ports;
int sysctl_tcp_compression_local __read_mostly;

static struct proto tcp_prot_override;

struct tcp_comp_context_tx {
	ZSTD_CStream *cstream;
	void *cworkspace;
	void *plaintext_data;
	void *compressed_data;

	struct scatterlist sg_data[MAX_SKB_FRAGS];
	unsigned int sg_size;
	int sg_num;

	struct scatterlist *partially_send;
	bool in_tcp_sendpages;
};

struct tcp_comp_context_rx {
	ZSTD_DStream *dstream;
	void *dworkspace;
	void *plaintext_data;
	void *compressed_data;
	void *remaining_data;

	size_t data_offset;
	struct strparser strp;
	void (*saved_data_ready)(struct sock *sk);
	struct sk_buff *pkt;
	struct sk_buff *dpkt;
};

struct tcp_comp_context {
	struct rcu_head rcu;

	struct proto *sk_proto;
	void (*sk_write_space)(struct sock *sk);

	struct tcp_comp_context_tx tx;
	struct tcp_comp_context_rx rx;

	unsigned long flags;
};

static bool tcp_comp_is_write_pending(struct tcp_comp_context *ctx)
{
	return test_bit(TCP_COMP_SEND_PENDING, &ctx->flags);
}

static void tcp_comp_err_abort(struct sock *sk, int err)
{
	sk->sk_err = err;
	sk->sk_error_report(sk);
}

static bool tcp_comp_enabled(__be32 saddr, __be32 daddr, int port)
{
	if (!sysctl_tcp_compression_local &&
	    (saddr == daddr || ipv4_is_loopback(daddr)))
		return false;

	return test_bit(port, sysctl_tcp_compression_ports);
}

bool tcp_syn_comp_enabled(const struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	return tcp_comp_enabled(inet->inet_saddr, inet->inet_daddr,
				ntohs(inet->inet_dport));
}

bool tcp_synack_comp_enabled(const struct sock *sk,
			     const struct inet_request_sock *ireq)
{
	struct inet_sock *inet = inet_sk(sk);

	if (!ireq->comp_ok)
		return false;

	return tcp_comp_enabled(ireq->ir_loc_addr, ireq->ir_rmt_addr,
				ntohs(inet->inet_sport));
}

static struct tcp_comp_context *comp_get_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	return (__force void *)icsk->icsk_ulp_data;
}

static int tcp_comp_tx_context_init(struct tcp_comp_context *ctx)
{
	ZSTD_parameters params;
	int csize;

	params = ZSTD_getParams(ZSTD_COMP_DEFAULT_LEVEL, PAGE_SIZE, 0);
	csize = ZSTD_CStreamWorkspaceBound(params.cParams);
	if (csize <= 0)
		return -EINVAL;

	ctx->tx.cworkspace = kmalloc(csize, GFP_KERNEL);
	if (!ctx->tx.cworkspace)
		return -ENOMEM;

	ctx->tx.cstream = ZSTD_initCStream(params, 0, ctx->tx.cworkspace,
					   csize);
	if (!ctx->tx.cstream)
		goto err_cstream;

	ctx->tx.plaintext_data = kvmalloc(TCP_COMP_SCRATCH_SIZE, GFP_KERNEL);
	if (!ctx->tx.plaintext_data)
		goto err_cstream;

	ctx->tx.compressed_data = kvmalloc(TCP_COMP_MAX_CSIZE, GFP_KERNEL);
	if (!ctx->tx.compressed_data)
		goto err_compressed;

	return 0;

err_compressed:
	kvfree(ctx->tx.plaintext_data);
	ctx->tx.plaintext_data = NULL;
err_cstream:
	kfree(ctx->tx.cworkspace);
	ctx->tx.cworkspace = NULL;

	return -ENOMEM;
}

static void *tcp_comp_get_tx_stream(struct sock *sk)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	if (!ctx->tx.plaintext_data)
		tcp_comp_tx_context_init(ctx);

	return ctx->tx.plaintext_data;
}

static int alloc_compressed_sg(struct sock *sk, int len)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	int rc = 0;

	rc = sk_alloc_sg(sk, len, ctx->tx.sg_data, 0,
			 &ctx->tx.sg_num, &ctx->tx.sg_size, 0);
	if (rc == -ENOSPC)
		ctx->tx.sg_num = ARRAY_SIZE(ctx->tx.sg_data);

	return rc;
}

static int memcopy_from_iter(struct sock *sk, struct iov_iter *from, int copy)
{
	void *dest;
	int rc;

	dest = tcp_comp_get_tx_stream(sk);
	if (!dest)
		return -ENOSPC;

	if (sk->sk_route_caps & NETIF_F_NOCACHE_COPY)
		rc = copy_from_iter_nocache(dest, copy, from);
	else
		rc = copy_from_iter(dest, copy, from);

	if (rc != copy)
		rc = -EFAULT;

	return rc;
}

static int memcopy_to_sg(struct sock *sk, int bytes)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct scatterlist *sg = ctx->tx.sg_data;
	char *from, *to;
	int copy;

	from = ctx->tx.compressed_data;
	while (bytes && sg) {
		to = sg_virt(sg);
		copy = min_t(int, sg->length, bytes);
		memcpy(to, from, copy);
		bytes -= copy;
		from += copy;
		sg = sg_next(sg);
	}

	return bytes;
}

static void trim_sg(struct sock *sk, int target_size)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct scatterlist *sg = ctx->tx.sg_data;
	int trim = ctx->tx.sg_size - target_size;
	int i = ctx->tx.sg_num - 1;

	if (trim <= 0) {
		WARN_ON_ONCE(trim < 0);
		return;
	}

	ctx->tx.sg_size = target_size;
	while (trim >= sg[i].length) {
		trim -= sg[i].length;
		sk_mem_uncharge(sk, sg[i].length);
		put_page(sg_page(&sg[i]));
		i--;

		if (i < 0)
			goto out;
	}

	sg[i].length -= trim;
	sk_mem_uncharge(sk, trim);

out:
	ctx->tx.sg_num = i + 1;
	sg_mark_end(ctx->tx.sg_data + ctx->tx.sg_num - 1);
}

static int tcp_comp_compress_to_sg(struct sock *sk, int bytes)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	ZSTD_outBuffer outbuf;
	ZSTD_inBuffer inbuf;
	size_t ret;

	inbuf.src = ctx->tx.plaintext_data;
	outbuf.dst = ctx->tx.compressed_data;
	inbuf.size = bytes;
	outbuf.size = TCP_COMP_MAX_CSIZE;
	inbuf.pos = 0;
	outbuf.pos = 0;

	ret = ZSTD_compressStream(ctx->tx.cstream, &outbuf, &inbuf);
	if (ZSTD_isError(ret))
		return -EIO;

	ret = ZSTD_flushStream(ctx->tx.cstream, &outbuf);
	if (ZSTD_isError(ret))
		return -EIO;

	if (inbuf.pos != inbuf.size)
		return -EIO;

	if (memcopy_to_sg(sk, outbuf.pos))
		return -EIO;

	trim_sg(sk, outbuf.pos);

	return 0;
}

static int tcp_comp_push_sg(struct sock *sk, struct scatterlist *sg, int flags)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	int ret, offset;
	struct page *p;
	size_t size;

	ctx->tx.in_tcp_sendpages = true;
	while (sg) {
		offset = sg->offset;
		size = sg->length;
		p = sg_page(sg);
retry:
		ret = do_tcp_sendpages(sk, p, offset, size, flags);
		if (ret != size) {
			if (ret > 0) {
				sk_mem_uncharge(sk, ret);
				sg->offset += ret;
				sg->length -= ret;
				size -= ret;
				offset += ret;
				goto retry;
			}
			ctx->tx.partially_send = (void *)sg;
			ctx->tx.in_tcp_sendpages = false;
			return ret;
		}

		sk_mem_uncharge(sk, ret);
		put_page(p);
		sg = sg_next(sg);
	}

	clear_bit(TCP_COMP_SEND_PENDING, &ctx->flags);
	ctx->tx.in_tcp_sendpages = false;
	ctx->tx.sg_size = 0;
	ctx->tx.sg_num = 0;

	return 0;
}

static int tcp_comp_push(struct sock *sk, int bytes, int flags)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	int ret;

	ret = tcp_comp_compress_to_sg(sk, bytes);
	if (ret < 0) {
		pr_debug("%s: failed to compress sg\n", __func__);
		return ret;
	}

	set_bit(TCP_COMP_SEND_PENDING, &ctx->flags);

	ret = tcp_comp_push_sg(sk, ctx->tx.sg_data, flags);
	if (ret) {
		pr_debug("%s: failed to tcp_comp_push_sg\n", __func__);
		return ret;
	}

	return 0;
}

static int wait_on_pending_writer(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int ret = 0;

	add_wait_queue(sk_sleep(sk), &wait);
	while (1) {
		if (!*timeo) {
			ret = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			ret = sock_intr_errno(*timeo);
			break;
		}

		if (sk_wait_event(sk, timeo, !sk->sk_write_pending, &wait))
			break;
	}
	remove_wait_queue(sk_sleep(sk), &wait);

	return ret;
}

static int tcp_comp_push_pending_sg(struct sock *sk, int flags)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct scatterlist *sg;

	if (!ctx->tx.partially_send)
		return 0;

	sg = ctx->tx.partially_send;
	ctx->tx.partially_send = NULL;

	return tcp_comp_push_sg(sk, sg, flags);
}

static int tcp_comp_complete_pending_work(struct sock *sk, int flags,
					  long *timeo)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	int ret = 0;

	if (unlikely(sk->sk_write_pending))
		ret = wait_on_pending_writer(sk, timeo);

	if (!ret && tcp_comp_is_write_pending(ctx))
		ret = tcp_comp_push_pending_sg(sk, flags);

	return ret;
}

static int tcp_comp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	int copied = 0, err = 0;
	size_t try_to_copy;
	int required_size;
	long timeo;

	lock_sock(sk);

	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);

	err = tcp_comp_complete_pending_work(sk, msg->msg_flags, &timeo);
	if (err)
		goto out_err;

	while (msg_data_left(msg)) {
		if (sk->sk_err) {
			err = -sk->sk_err;
			goto out_err;
		}

		try_to_copy = msg_data_left(msg);
		if (try_to_copy > TCP_COMP_SCRATCH_SIZE)
			try_to_copy = TCP_COMP_SCRATCH_SIZE;
		required_size = try_to_copy + TCP_COMP_MAX_PADDING;

		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;

alloc_compressed:
		err = alloc_compressed_sg(sk, required_size);
		if (err) {
			if (err != -ENOSPC)
				goto wait_for_memory;
			goto out_err;
		}

		err = memcopy_from_iter(sk, &msg->msg_iter, try_to_copy);
		if (err < 0)
			goto out_err;

		copied += try_to_copy;

		err = tcp_comp_push(sk, try_to_copy, msg->msg_flags);
		if (err < 0) {
			if (err == -ENOMEM)
				goto wait_for_memory;
			if (err != -EAGAIN)
				tcp_comp_err_abort(sk, EBADMSG);
			goto out_err;
		}

		continue;
wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		err = sk_stream_wait_memory(sk, &timeo);
		if (err)
			goto out_err;
		if (ctx->tx.sg_size < required_size)
			goto alloc_compressed;
	}

out_err:
	err = sk_stream_error(sk, msg->msg_flags, err);

	release_sock(sk);

	return copied ? copied : err;
}

static struct sk_buff *comp_wait_data(struct sock *sk, int flags,
				      long timeo, int *err)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct sk_buff *skb;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	while (!(skb = ctx->rx.pkt)) {
		if (sk->sk_err) {
			*err = sock_error(sk);
			return NULL;
		}

		if (!skb_queue_empty(&sk->sk_receive_queue)) {
			__strp_unpause(&ctx->rx.strp);
			if (ctx->rx.pkt)
				return ctx->rx.pkt;
		}

		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return NULL;

		if (sock_flag(sk, SOCK_DONE))
			return NULL;

		if ((flags & MSG_DONTWAIT) || !timeo) {
			*err = -EAGAIN;
			return NULL;
		}

		add_wait_queue(sk_sleep(sk), &wait);
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		sk_wait_event(sk, &timeo, ctx->rx.pkt != skb, &wait);
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		remove_wait_queue(sk_sleep(sk), &wait);

		/* Handle signals */
		if (signal_pending(current)) {
			*err = sock_intr_errno(timeo);
			return NULL;
		}
	}

	return skb;
}

static bool comp_advance_skb(struct sock *sk, struct sk_buff *skb,
			     unsigned int len)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct strp_msg *rxm = strp_msg(skb);

	if (len < rxm->full_len) {
		rxm->offset += len;
		rxm->full_len -= len;
		return false;
	}

	/* Finished with message */
	ctx->rx.pkt = NULL;
	kfree_skb(skb);
	__strp_unpause(&ctx->rx.strp);

	return true;
}

static bool comp_advance_dskb(struct sock *sk, struct sk_buff *skb,
			      unsigned int len)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct strp_msg *rxm = strp_msg(skb);

	if (len < rxm->full_len) {
		rxm->offset += len;
		rxm->full_len -= len;
		return false;
	}

	/* Finished with message */
	ctx->rx.dpkt = NULL;
	kfree_skb(skb);
	return true;
}

static int tcp_comp_rx_context_init(struct tcp_comp_context *ctx)
{
	int dsize;

	dsize = ZSTD_DStreamWorkspaceBound(TCP_COMP_MAX_INPUT);
	if (dsize <= 0)
		return -EINVAL;

	ctx->rx.dworkspace = kmalloc(dsize, GFP_KERNEL);
	if (!ctx->rx.dworkspace)
		return -ENOMEM;

	ctx->rx.dstream = ZSTD_initDStream(TCP_COMP_MAX_INPUT,
					   ctx->rx.dworkspace, dsize);
	if (!ctx->rx.dstream)
		goto err_dstream;

	ctx->rx.plaintext_data = kvmalloc(TCP_COMP_MAX_CSIZE * 32, GFP_KERNEL);
	if (!ctx->rx.plaintext_data)
		goto err_dstream;

	ctx->rx.compressed_data = kvmalloc(TCP_COMP_MAX_CSIZE, GFP_KERNEL);
	if (!ctx->rx.compressed_data)
		goto err_compressed;

	ctx->rx.remaining_data = kvmalloc(TCP_COMP_MAX_CSIZE, GFP_KERNEL);
	if (!ctx->rx.remaining_data)
		goto err_remaining;

	ctx->rx.data_offset = 0;

	return 0;

err_remaining:
	kvfree(ctx->rx.compressed_data);
	ctx->rx.compressed_data = NULL;
err_compressed:
	kvfree(ctx->rx.plaintext_data);
	ctx->rx.plaintext_data = NULL;
err_dstream:
	kfree(ctx->rx.dworkspace);
	ctx->rx.dworkspace = NULL;

	return -ENOMEM;
}

static void *tcp_comp_get_rx_stream(struct sock *sk)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	if (!ctx->rx.plaintext_data)
		tcp_comp_rx_context_init(ctx);

	return ctx->rx.plaintext_data;
}

static int tcp_comp_decompress(struct sock *sk, struct sk_buff *skb, int flags)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct strp_msg *rxm = strp_msg(skb);
	const int plen = skb->len;
	ZSTD_outBuffer outbuf;
	ZSTD_inBuffer inbuf;
	struct sk_buff *nskb;
	int len;
	void *to;

	to = tcp_comp_get_rx_stream(sk);
	if (!to)
		return -ENOSPC;

	if (skb_linearize_cow(skb))
		return -ENOMEM;

	if (plen + ctx->rx.data_offset > TCP_COMP_MAX_CSIZE)
		return -ENOMEM;

	nskb = skb_copy(skb, GFP_KERNEL);
	if (!nskb)
		return -ENOMEM;

	if (ctx->rx.data_offset)
		memcpy(ctx->rx.compressed_data, ctx->rx.remaining_data,
		       ctx->rx.data_offset);

	memcpy((char *)ctx->rx.compressed_data + ctx->rx.data_offset,
	       (char *)skb->data + rxm->offset, plen - rxm->offset);

	inbuf.src = ctx->rx.compressed_data;
	inbuf.pos = 0;
	inbuf.size = plen - rxm->offset + ctx->rx.data_offset;
	ctx->rx.data_offset = 0;

	outbuf.dst = ctx->rx.plaintext_data;
	outbuf.pos = 0;
	outbuf.size = TCP_COMP_MAX_CSIZE * 32;

	while (1) {
		size_t ret;

		to = outbuf.dst;
		ret = ZSTD_decompressStream(ctx->rx.dstream, &outbuf, &inbuf);
		if (ZSTD_isError(ret)) {
			kfree_skb(nskb);
			return -EIO;
		}

		len = outbuf.pos - plen;
		if (len > skb_tailroom(nskb))
			len = skb_tailroom(nskb);

		__skb_put(nskb, len);

		len += plen;
		skb_copy_to_linear_data(nskb, to, len);

		while ((to += len, outbuf.pos -= len) > 0) {
			struct page *pages;
			skb_frag_t *frag;

			if (WARN_ON(skb_shinfo(nskb)->nr_frags >= MAX_SKB_FRAGS)) {
				kfree_skb(nskb);
				return -EMSGSIZE;
			}

			frag = skb_shinfo(nskb)->frags +
			       skb_shinfo(nskb)->nr_frags;
			pages = alloc_pages(__GFP_NOWARN | GFP_KERNEL | __GFP_COMP,
					    TCP_COMP_ALLOC_ORDER);

			if (!pages) {
				kfree_skb(nskb);
				return -ENOMEM;
			}

			__skb_frag_set_page(frag, pages);
			len = PAGE_SIZE << TCP_COMP_ALLOC_ORDER;
			if (outbuf.pos < len)
				len = outbuf.pos;

			frag->page_offset = 0;
			skb_frag_size_set(frag, len);
			memcpy(skb_frag_address(frag), to, len);

			nskb->truesize += len;
			nskb->data_len += len;
			nskb->len += len;
			skb_shinfo(nskb)->nr_frags++;
		}

		if (ret == 0)
			break;

		if (inbuf.pos >= plen || !inbuf.pos) {
			if (inbuf.pos < inbuf.size) {
				memcpy((char *)ctx->rx.remaining_data,
				       (char *)inbuf.src + inbuf.pos,
				       inbuf.size - inbuf.pos);
				ctx->rx.data_offset = inbuf.size - inbuf.pos;
			}
			break;
		}
	}

	ctx->rx.dpkt = nskb;
	rxm = strp_msg(nskb);
	rxm->full_len = nskb->len;
	rxm->offset = 0;
	comp_advance_skb(sk, skb, plen - rxm->offset);

	return 0;
}

static int tcp_comp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			    int nonblock, int flags, int *addr_len)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct strp_msg *rxm;
	struct sk_buff *skb;
	ssize_t copied = 0;
	int target, err = 0;
	long timeo;

	flags |= nonblock;

	if (unlikely(flags & MSG_ERRQUEUE))
		return sock_recv_errqueue(sk, msg, len, SOL_IP, IP_RECVERR);

	lock_sock(sk);

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	timeo = sock_rcvtimeo(sk, flags & MSG_WAITALL);

	do {
		int chunk = 0;

		if (!ctx->rx.dpkt) {
			skb = comp_wait_data(sk, flags, timeo, &err);
			if (!skb)
				goto recv_end;

			err = tcp_comp_decompress(sk, skb, flags);
			if (err < 0) {
				goto recv_end;
			}
		}
		skb = ctx->rx.dpkt;
		rxm = strp_msg(skb);
		chunk = min_t(unsigned int, rxm->full_len, len);
		err = skb_copy_datagram_msg(skb, rxm->offset, msg,
					    chunk);
		if (err < 0)
			goto recv_end;

		copied += chunk;
		len -= chunk;
		if (likely(!(flags & MSG_PEEK)))
			comp_advance_dskb(sk, skb, chunk);
		else
			break;

		if (copied >= target && !ctx->rx.dpkt)
			break;
	} while (len > 0);

recv_end:
	release_sock(sk);
	return copied ? : err;
}

bool comp_stream_read(const struct sock *sk)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	if (!ctx)
		return false;

	if (ctx->rx.pkt || ctx->rx.dpkt)
		return true;

	return false;
}

static void comp_data_ready(struct sock *sk)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	strp_data_ready(&ctx->rx.strp);
}

static void comp_queue(struct strparser *strp, struct sk_buff *skb)
{
	struct tcp_comp_context *ctx = comp_get_ctx(strp->sk);

	ctx->rx.pkt = skb;
	strp_pause(strp);
	ctx->rx.saved_data_ready(strp->sk);
}

static int comp_read_size(struct strparser *strp, struct sk_buff *skb)
{
	struct strp_msg *rxm = strp_msg(skb);

	if (rxm->offset > skb->len)
		return 0;

	return skb->len - rxm->offset;
}

void comp_setup_strp(struct sock *sk, struct tcp_comp_context *ctx)
{
	struct strp_callbacks cb;

	memset(&cb, 0, sizeof(cb));
	cb.rcv_msg = comp_queue;
	cb.parse_msg = comp_read_size;
	strp_init(&ctx->rx.strp, sk, &cb);

	write_lock_bh(&sk->sk_callback_lock);
	ctx->rx.saved_data_ready = sk->sk_data_ready;
	sk->sk_data_ready = comp_data_ready;
	write_unlock_bh(&sk->sk_callback_lock);

	strp_check_rcv(&ctx->rx.strp);
}

static void tcp_comp_write_space(struct sock *sk)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	if (ctx->tx.in_tcp_sendpages) {
		ctx->sk_write_space(sk);
		return;
	}

	if (!sk->sk_write_pending && tcp_comp_is_write_pending(ctx)) {
		gfp_t sk_allocation = sk->sk_allocation;
		int rc;

		sk->sk_allocation = GFP_ATOMIC;
		rc = tcp_comp_push_pending_sg(sk, MSG_DONTWAIT | MSG_NOSIGNAL);
		sk->sk_allocation = sk_allocation;

		if (rc < 0)
			return;
	}

	ctx->sk_write_space(sk);
}

void tcp_init_compression(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_comp_context *ctx = NULL;
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->rx_opt.smc_ok)
		return;

	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return;

	sg_init_table(ctx->tx.sg_data, ARRAY_SIZE(ctx->tx.sg_data));

	ctx->sk_write_space = sk->sk_write_space;
	ctx->sk_proto = sk->sk_prot;
	WRITE_ONCE(sk->sk_prot, &tcp_prot_override);
	sk->sk_write_space = tcp_comp_write_space;

	rcu_assign_pointer(icsk->icsk_ulp_data, ctx);

	sock_set_flag(sk, SOCK_COMP);
	comp_setup_strp(sk, ctx);
}

static void free_sg(struct sock *sk, struct scatterlist *sg)
{
	while (sg) {
		sk_mem_uncharge(sk, sg->length);
		put_page(sg_page(sg));
		sg = sg_next(sg);
	}
}

static void tcp_comp_context_tx_free(struct tcp_comp_context *ctx)
{
	kfree(ctx->tx.cworkspace);
	ctx->tx.cworkspace = NULL;

	kvfree(ctx->tx.plaintext_data);
	ctx->tx.plaintext_data = NULL;

	kvfree(ctx->tx.compressed_data);
	ctx->tx.compressed_data = NULL;
}

static void tcp_comp_context_rx_free(struct tcp_comp_context *ctx)
{
	kfree(ctx->rx.dworkspace);
	ctx->rx.dworkspace = NULL;

	kvfree(ctx->rx.plaintext_data);
	ctx->rx.plaintext_data = NULL;

	kvfree(ctx->rx.compressed_data);
	ctx->rx.compressed_data = NULL;

	kvfree(ctx->rx.remaining_data);
	ctx->rx.remaining_data = NULL;
}

static void tcp_comp_context_free(struct rcu_head *head)
{
	struct tcp_comp_context *ctx;

	ctx = container_of(head, struct tcp_comp_context, rcu);

	tcp_comp_context_tx_free(ctx);
	tcp_comp_context_rx_free(ctx);
	strp_done(&ctx->rx.strp);
	kfree(ctx);
}

void tcp_cleanup_compression(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	if (!ctx || !sock_flag(sk, SOCK_COMP))
		return;

	if (ctx->tx.partially_send) {
		free_sg(sk, ctx->tx.partially_send);
		ctx->tx.partially_send = NULL;
	}

	if (ctx->rx.pkt) {
		kfree_skb(ctx->rx.pkt);
		ctx->rx.pkt = NULL;
	}
	if (ctx->rx.dpkt) {
		kfree_skb(ctx->rx.dpkt);
		ctx->rx.dpkt = NULL;
	}
	strp_stop(&ctx->rx.strp);

	rcu_assign_pointer(icsk->icsk_ulp_data, NULL);
	call_rcu(&ctx->rcu, tcp_comp_context_free);
}

int tcp_comp_init(void)
{
	tcp_prot_override = tcp_prot;
	tcp_prot_override.sendmsg = tcp_comp_sendmsg;
	tcp_prot_override.recvmsg = tcp_comp_recvmsg;
	tcp_prot_override.stream_memory_read = comp_stream_read;

	return 0;
}
