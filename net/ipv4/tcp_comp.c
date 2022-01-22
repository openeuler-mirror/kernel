// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP compression support
 *
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 */

#include <linux/skmsg.h>
#include <linux/zstd.h>

#define TCP_COMP_MAX_PADDING	64
#define TCP_COMP_SCRATCH_SIZE	65400
#define TCP_COMP_MAX_CSIZE	(TCP_COMP_SCRATCH_SIZE + TCP_COMP_MAX_PADDING)

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
	struct sk_msg msg;
	bool in_tcp_sendpages;
};

struct tcp_comp_context {
	struct rcu_head rcu;

	struct proto *sk_proto;
	void (*sk_write_space)(struct sock *sk);

	struct tcp_comp_context_tx tx;

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
	csize = zstd_cstream_workspace_bound(&params.cParams);
	if (csize <= 0)
		return -EINVAL;

	ctx->tx.cworkspace = kmalloc(csize, GFP_KERNEL);
	if (!ctx->tx.cworkspace)
		return -ENOMEM;

	ctx->tx.cstream = zstd_init_cstream(&params, 0, ctx->tx.cworkspace,
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

static int alloc_compressed_msg(struct sock *sk, int len)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct sk_msg *msg = &ctx->tx.msg;

	sk_msg_init(msg);

	return sk_msg_alloc(sk, msg, len, 0);
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

static int memcopy_to_msg(struct sock *sk, int bytes)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct sk_msg *msg = &ctx->tx.msg;
	int i = msg->sg.curr;
	struct scatterlist *sge;
	u32 copy, buf_size;
	void *from, *to;

	from = ctx->tx.compressed_data;
	do {
		sge = sk_msg_elem(msg, i);
		/* This is possible if a trim operation shrunk the buffer */
		if (msg->sg.copybreak >= sge->length) {
			msg->sg.copybreak = 0;
			sk_msg_iter_var_next(i);
			if (i == msg->sg.end)
				break;
			sge = sk_msg_elem(msg, i);
		}
		buf_size = sge->length - msg->sg.copybreak;
		copy = (buf_size > bytes) ? bytes : buf_size;
		to = sg_virt(sge) + msg->sg.copybreak;
		msg->sg.copybreak += copy;
		memcpy(to, from, copy);
		bytes -= copy;
		from += copy;
		if (!bytes)
			break;
		msg->sg.copybreak = 0;
		sk_msg_iter_var_next(i);
	} while (i != msg->sg.end);

	msg->sg.curr = i;
	return bytes;
}

static int tcp_comp_compress_to_msg(struct sock *sk, int bytes)
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

	if (memcopy_to_msg(sk, outbuf.pos))
		return -EIO;

	sk_msg_trim(sk, &ctx->tx.msg, outbuf.pos);

	return 0;
}

static int tcp_comp_push_msg(struct sock *sk, struct sk_msg *msg, int flags)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct scatterlist *sg;
	int ret, offset;
	struct page *p;
	size_t size;

	ctx->tx.in_tcp_sendpages = true;
	while (1) {
		sg = sk_msg_elem(msg, msg->sg.start);
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
			ctx->tx.in_tcp_sendpages = false;
			return ret;
		}

		sk_mem_uncharge(sk, ret);
		msg->sg.size -= size;
		put_page(p);
		sk_msg_iter_next(msg, start);
		if (msg->sg.start == msg->sg.end)
			break;
	}

	clear_bit(TCP_COMP_SEND_PENDING, &ctx->flags);
	ctx->tx.in_tcp_sendpages = false;

	return 0;
}

static int tcp_comp_push(struct sock *sk, int bytes, int flags)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	int ret;

	ret = tcp_comp_compress_to_msg(sk, bytes);
	if (ret < 0) {
		pr_debug("%s: failed to compress sg\n", __func__);
		return ret;
	}

	set_bit(TCP_COMP_SEND_PENDING, &ctx->flags);

	ret = tcp_comp_push_msg(sk, &ctx->tx.msg, flags);
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

static int tcp_comp_push_pending_msg(struct sock *sk, int flags)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	struct sk_msg *msg = &ctx->tx.msg;

	if (msg->sg.start == msg->sg.end)
		return 0;

	return tcp_comp_push_msg(sk, msg, flags);
}

static int tcp_comp_complete_pending_work(struct sock *sk, int flags,
					  long *timeo)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);
	int ret = 0;

	if (unlikely(sk->sk_write_pending))
		ret = wait_on_pending_writer(sk, timeo);

	if (!ret && tcp_comp_is_write_pending(ctx))
		ret = tcp_comp_push_pending_msg(sk, flags);

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
		err = alloc_compressed_msg(sk, required_size);
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
		if (ctx->tx.msg.sg.size < required_size)
			goto alloc_compressed;
	}

out_err:
	err = sk_stream_error(sk, msg->msg_flags, err);

	release_sock(sk);

	return copied ? copied : err;
}

static int tcp_comp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			    int nonblock, int flags, int *addr_len)
{
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	return ctx->sk_proto->recvmsg(sk, msg, len, nonblock, flags, addr_len);
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
		rc = tcp_comp_push_pending_msg(sk, MSG_DONTWAIT | MSG_NOSIGNAL);
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
	struct sk_msg *msg = NULL;
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->rx_opt.comp_ok)
		return;

	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return;

	msg = &ctx->tx.msg;
	sk_msg_init(msg);

	ctx->sk_write_space = sk->sk_write_space;
	ctx->sk_proto = sk->sk_prot;
	WRITE_ONCE(sk->sk_prot, &tcp_prot_override);
	sk->sk_write_space = tcp_comp_write_space;

	rcu_assign_pointer(icsk->icsk_ulp_data, ctx);

	sock_set_flag(sk, SOCK_COMP);
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

static void tcp_comp_context_free(struct rcu_head *head)
{
	struct tcp_comp_context *ctx;

	ctx = container_of(head, struct tcp_comp_context, rcu);

	tcp_comp_context_tx_free(ctx);
	kfree(ctx);
}

void tcp_cleanup_compression(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_comp_context *ctx = comp_get_ctx(sk);

	if (!ctx || !sock_flag(sk, SOCK_COMP))
		return;

	rcu_assign_pointer(icsk->icsk_ulp_data, NULL);
	call_rcu(&ctx->rcu, tcp_comp_context_free);
}

int tcp_comp_init(void)
{
	tcp_prot_override = tcp_prot;
	tcp_prot_override.sendmsg = tcp_comp_sendmsg;
	tcp_prot_override.recvmsg = tcp_comp_recvmsg;

	return 0;
}
