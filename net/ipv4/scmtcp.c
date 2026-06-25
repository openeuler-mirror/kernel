// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Huawei Technologies Co., Ltd */
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/uuid.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/protocol.h>
#include <net/scm.h>
#include <net/net_namespace.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

struct scm_file_msg {
	uuid_t dmi_uuid;    /* check if loopback */
	uintptr_t htable;   /* check if loopback */
	uintptr_t owner_sk; /* hash key */
	u32 flist_seq;      /* search file_list */
};

/* hash table value */
struct scm_file_ctl {
	struct hlist_node hnode;
	struct list_head fhead;
	uintptr_t owner_sk; /* check hash conflict */
	u16 flist_count;
	u16 fd_count;
};

struct scm_file_list {
	struct list_head fnode;
	struct scm_fp_list *fp;
	u32 flist_seq;
};

struct scm_file_hashtable {
#define FILE_HASHTABLE_MAX      4096
#define FILE_HASHTABLE_BITS     8
	uuid_t dmi_uuid;
	DECLARE_HASHTABLE(htable, FILE_HASHTABLE_BITS);
	spinlock_t lock; /* protects htable */
	s64 fctl_count;  /* total scm_file_ctl count */
	s64 flist_count; /* total scm_file_list count */
	s64 fd_count;    /* total fd count */
};

struct scm_file_hashtable scm_fhtable;

struct scmtcp_sock {
	struct tcp_sock tp;  /* must be first */
	atomic_t flist_seq;
};

#define scmtcp_sk(ptr) container_of_const(ptr, struct scmtcp_sock, tp.inet_conn.icsk_inet.sk)

static int read_proc_uuid(const char *path, uuid_t *uuid)
{
	char uuid_str[UUID_STRING_LEN + 1];
	struct file *filp;
	ssize_t ret;

	filp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		pr_err("filp_open failed\n");
		return (int)PTR_ERR(filp);
	}

	ret = kernel_read(filp, uuid_str, UUID_STRING_LEN, NULL);
	filp_close(filp, NULL);
	if (ret != UUID_STRING_LEN) {
		pr_err("kernel_read failed\n");
		return -EINVAL;
	}

	uuid_str[UUID_STRING_LEN] = '\0';
	ret = uuid_parse(uuid_str, uuid);
	pr_debug("%s %d: %s, uuid %s, uuid %llx-%llx\n", __func__, __LINE__,
		 path, uuid_str, *(u64 *)uuid, *(u64 *)(uuid + 8));
	return ret;
}

static bool scm_is_loopback(const struct scm_file_msg *fmsg)
{
	if (!fmsg->owner_sk ||
	    fmsg->htable != (uintptr_t)scm_fhtable.htable ||
	    !uuid_equal(&fmsg->dmi_uuid, &scm_fhtable.dmi_uuid))
		return false;
	return true;
}

static struct scm_file_list *file_list_alloc(struct sock *sk)
{
	struct scm_file_list *flist;

	flist = kzalloc(sizeof(*flist), GFP_KERNEL);
	if (flist)
		flist->flist_seq = atomic_fetch_inc(&scmtcp_sk(sk)->flist_seq);
	return flist;
}

static void file_list_free(struct scm_file_list *flist)
{
	struct scm_cookie scm = {0};

	if (flist->fp) {
		scm.fp = flist->fp;
		flist->fp = NULL;
		__scm_destroy(&scm);
	}
	kfree(flist);
}

static bool file_list_has_self(const struct sock *sk, const struct scm_file_list *flist)
{
	const struct socket *sock;
	struct scm_fp_list *fpl = flist->fp;
	int i;

	if (fpl) {
		for (i = fpl->count - 1; i >= 0; i--) {
			sock = sock_from_file(fpl->fp[i]);
			if (sock && sock->sk == sk)
				return true;
		}
	}
	return false;
}

static struct scm_file_ctl *file_ctl_alloc(struct sock *sk)
{
	struct scm_file_ctl *fctl;

	fctl = kzalloc(sizeof(*fctl), GFP_KERNEL);
	if (!fctl)
		return NULL;

	INIT_HLIST_NODE(&fctl->hnode);
	INIT_LIST_HEAD(&fctl->fhead);
	fctl->owner_sk = (uintptr_t)sk;

	return fctl;
}

static void file_ctl_enqueue(struct scm_file_ctl *fctl, struct scm_file_list *flist)
{
	list_add_tail(&flist->fnode, &fctl->fhead);
	fctl->flist_count++;
	fctl->fd_count += flist->fp->count;
}

static struct scm_file_list *file_ctl_dequeue(struct scm_file_ctl *fctl)
{
	struct scm_file_list *flist;

	if (list_empty(&fctl->fhead))
		return NULL;

	flist = list_first_entry(&fctl->fhead, struct scm_file_list, fnode);
	list_del(&flist->fnode);
	fctl->flist_count--;
	fctl->fd_count -= flist->fp->count;
	return flist;
}

static struct scm_file_list *file_ctl_del(struct scm_file_ctl *fctl,
					  u32 flist_seq)
{
	struct scm_file_list *flist;
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &fctl->fhead) {
		flist = list_entry(pos, struct scm_file_list, fnode);
		if (flist->flist_seq == flist_seq) {
			list_del(&flist->fnode);
			fctl->flist_count--;
			fctl->fd_count -= flist->fp->count;
			return flist;
		}
	}
	return NULL;
}

static void file_ctl_free(struct scm_file_ctl *fctl)
{
	struct scm_file_list *flist;

	while (true) {
		flist = file_ctl_dequeue(fctl);
		if (!flist)
			break;
		file_list_free(flist);
	}
	kfree(fctl);
}

static int file_htable_init(void)
{
	int ret;

	memset(&scm_fhtable, 0, sizeof(scm_fhtable));

	hash_init(scm_fhtable.htable);
	spin_lock_init(&scm_fhtable.lock);

	/* ignore ENOENT */
	ret = read_proc_uuid("/sys/class/dmi/id/product_uuid", &scm_fhtable.dmi_uuid);
	if (ret != -ENOENT)
		return ret;
	ret = read_proc_uuid("/proc/sys/kernel/random/boot_id", &scm_fhtable.dmi_uuid);
	if (ret != -ENOENT)
		return ret;
	return 0;
}

static int file_htable_destroy(void)
{
	u64 count;

	spin_lock_bh(&scm_fhtable.lock);
	count = scm_fhtable.fctl_count + scm_fhtable.flist_count;
	spin_unlock_bh(&scm_fhtable.lock);
	return count != 0 ? -EBUSY : 0;
}

static struct scm_file_ctl *file_htable_get_ctl(uintptr_t owner_sk)
{
	struct hlist_node *tmp;
	struct scm_file_ctl *fctl;
	u32 key32 = hash_ptr((void *)owner_sk, FILE_HASHTABLE_BITS);

	hash_for_each_possible_safe(scm_fhtable.htable, fctl, tmp, hnode, key32) {
		if (fctl->owner_sk == owner_sk)
			return fctl;
	}
	return NULL;
}

static void file_htable_del_ctl(uintptr_t owner_sk)
{
	struct scm_file_ctl *fctl;

	spin_lock_bh(&scm_fhtable.lock);
	fctl = file_htable_get_ctl(owner_sk);
	if (fctl) {
		hash_del(&fctl->hnode);
		scm_fhtable.fctl_count--;
		scm_fhtable.flist_count -= fctl->flist_count;
		scm_fhtable.fd_count -= fctl->fd_count;
	}
	spin_unlock_bh(&scm_fhtable.lock);

	if (fctl)
		file_ctl_free(fctl);
}

static void file_htable_add_ctl(uintptr_t owner_sk, struct scm_file_ctl *fctl)
{
	u32 key32 = hash_ptr((void *)owner_sk, FILE_HASHTABLE_BITS);

	spin_lock_bh(&scm_fhtable.lock);
	hash_add(scm_fhtable.htable, &fctl->hnode, key32);
	scm_fhtable.fctl_count++;
	scm_fhtable.flist_count += fctl->flist_count;
	scm_fhtable.fd_count += fctl->fd_count;
	spin_unlock_bh(&scm_fhtable.lock);
}

static int file_htable_add_flist(uintptr_t owner_sk, struct scm_file_list *flist)
{
	struct scm_file_ctl *fctl;
	int ret = -ETOOMANYREFS;

	spin_lock_bh(&scm_fhtable.lock);
	fctl = file_htable_get_ctl(owner_sk);
	if (fctl && fctl->fd_count + flist->fp->count <= SCM_MAX_FD &&
	    scm_fhtable.flist_count < FILE_HASHTABLE_MAX) {
		file_ctl_enqueue(fctl, flist);
		scm_fhtable.flist_count++;
		scm_fhtable.fd_count += flist->fp->count;
		ret = 0;
	}
	spin_unlock_bh(&scm_fhtable.lock);
	return ret;
}

static struct scm_file_list *file_htable_del_flist(uintptr_t owner_sk, u32 flist_seq)
{
	struct scm_file_ctl *fctl;
	struct scm_file_list *flist = NULL;

	spin_lock_bh(&scm_fhtable.lock);
	fctl = file_htable_get_ctl(owner_sk);
	if (fctl) {
		flist = file_ctl_del(fctl, flist_seq);
		if (flist) {
			scm_fhtable.flist_count--;
			scm_fhtable.fd_count -= flist->fp->count;
		}
	}
	spin_unlock_bh(&scm_fhtable.lock);
	return flist;
}

static void __scmtcp_sk_init(struct sock *sk)
{
	struct scm_file_ctl *fctl;

	atomic_set(&scmtcp_sk(sk)->flist_seq, 0);

	fctl = file_ctl_alloc(sk);
	/* Don't worry, there will be errors in file_htable_add_flist(). */
	if (!fctl)
		return;
	file_htable_add_ctl((uintptr_t)sk, fctl);
}

static int scmtcp_sk_init(struct sock *sk)
{
	__scmtcp_sk_init(sk);
	return tcp_prot.init(sk);
}

static void scmtcp_sk_destroy(struct sock *sk)
{
	file_htable_del_ctl((uintptr_t)sk);
	tcp_prot.destroy(sk);
}

struct sock *scmtcp_sk_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct sock *newsk;

	newsk = tcp_prot.accept(sk, flags, err, kern);
	if (newsk)
		__scmtcp_sk_init(newsk);
	return newsk;
}

static int scm_disconnect(struct sock *sk)
{
	lock_sock(sk);
	sk->sk_prot->disconnect(sk, 0);
	release_sock(sk);
	return -ENOTCONN;
}

static void scm_set_skb_eor(struct sock *sk)
{
	struct sk_buff *skb;
	/* Set MSG_EOR to ensure that fmsg is not split into two skbs. */
	skb = tcp_write_queue_tail(sk);
	if (skb)
		TCP_SKB_CB(skb)->eor = 1;
}

static int scm_count_fds(const void __user *msg_control_user)
{
	int cmlen, fd_count;
	const struct cmsghdr __user *cm;

	cm = (__force const struct cmsghdr __user *)msg_control_user;
	if (get_user(cmlen, &cm->cmsg_len))
		return -EFAULT;
	fd_count = (cmlen - CMSG_LEN(0)) / sizeof(int);
	return fd_count > 0 ? fd_count : -EMFILE;
}

/* see kernel_sendmsg() */
static int scm_kernel_sendmsg(struct sock *sk, struct msghdr *msg,
			      struct kvec *vec, size_t num, size_t size, int flags)
{
	int ret;

	if (vec)
		iov_iter_kvec(&msg->msg_iter, ITER_SOURCE, vec, num, size);

	lock_sock(sk);
	if (flags & MSG_EOR)
		scm_set_skb_eor(sk);
	ret = tcp_sendmsg_locked(sk, msg, msg_data_left(msg));
	release_sock(sk);

	return ret;
}

/* see kernel_recvmsg() */
static int scm_kernel_recvmsg(struct sock *sk, struct msghdr *msg,
			      struct kvec *vec, size_t num, size_t size, int flags)
{
	int addr_len = 0;
	int ret;

	msg->msg_control_is_user = false;
	if (vec)
		iov_iter_kvec(&msg->msg_iter, ITER_DEST, vec, num, size);
	ret = tcp_recvmsg(sk, msg, msg_data_left(msg), flags, &addr_len);
	if (ret >= 0)
		msg->msg_namelen = addr_len;

	return ret;
}

static int scmtcp_sk_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	int ret;
	struct scm_file_msg fmsg = {0};
	struct scm_file_list *flist;
	struct msghdr scm_msg = {0};
	struct kvec scm_iov;
	struct cmsghdr *cmsg;
	int count;

	if (!msg->msg_controllen)
		return scm_kernel_sendmsg(sk, msg, NULL, 0, size, 0);

	if (msg->msg_controllen < CMSG_LEN(sizeof(int)) || msg->msg_iter.nr_segs)
		return -EINVAL;

	/* send fmsg */
	flist = file_list_alloc(sk);
	if (!flist)
		return -ENOMEM;

	/* see sock_cmsg_send() */
	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg)) {
			file_list_free(flist);
			return -EINVAL;
		}
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		if (scm_fp_copy(cmsg, &flist->fp) <= 0) {
			file_list_free(flist);
			return -EINVAL;
		}
	}
	if (!flist->fp || flist->fp->count == 0 || file_list_has_self(sk, flist)) {
		file_list_free(flist);
		return -EINVAL;
	}
	count = flist->fp->count;

	uuid_copy(&fmsg.dmi_uuid, &scm_fhtable.dmi_uuid);
	fmsg.htable = (uintptr_t)scm_fhtable.htable;
	fmsg.owner_sk = (uintptr_t)sk;
	fmsg.flist_seq = flist->flist_seq;
	scm_iov.iov_base = &fmsg;
	scm_iov.iov_len = sizeof(fmsg);

	ret = file_htable_add_flist(fmsg.owner_sk, flist);
	if (ret != 0) {
		file_list_free(flist);
		return ret;
	}

	ret = scm_kernel_sendmsg(sk, &scm_msg, &scm_iov, 1,
				 scm_iov.iov_len, MSG_EOR);
	if (ret != sizeof(fmsg)) {
		flist = file_htable_del_flist(fmsg.owner_sk, fmsg.flist_seq);
		if (flist)
			file_list_free(flist);
		if (ret <= 0)
			return ret;
		/* It should never happen. */
		pr_err("scm_kernel_sendmsg failed, ret %d\n", ret);
		return scm_disconnect(sk);
	}

	return count;
}

static int scmtcp_sk_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			     int flags, int *addr_len)
{
	int ret;
	struct scm_file_msg fmsg;
	struct scm_file_list *flist;
	struct msghdr scm_msg = {0};
	struct kvec scm_iov;
	struct scm_cookie scm = {0};
	const void __user *msg_control_user;

	if (!msg->msg_controllen)
		return scm_kernel_recvmsg(sk, msg, NULL, 0, len, flags);

	if (msg->msg_controllen < CMSG_LEN(sizeof(int)) || msg->msg_iter.nr_segs)
		return -EINVAL;

	scm_iov.iov_base = &fmsg;
	scm_iov.iov_len = sizeof(fmsg);

	ret = scm_kernel_recvmsg(sk, &scm_msg, &scm_iov, 1,
				 scm_iov.iov_len, MSG_WAITALL);
	if (ret != sizeof(fmsg)) {
		if (ret <= 0)
			return ret;
		/* It should never happen. */
		pr_err("scm_kernel_recvmsg failed, ret %d\n", ret);
		return scm_disconnect(sk);
	}

	if (!scm_is_loopback(&fmsg))
		return -EINVAL;
	flist = file_htable_del_flist(fmsg.owner_sk, fmsg.flist_seq);
	if (!flist)
		return -EINVAL;

	scm.fp = scm_fp_dup(flist->fp);
	file_list_free(flist);
	if (!scm.fp)
		return -ENOMEM;
	msg_control_user = msg->msg_control_user;
	scm_detach_fds(msg, &scm);

	return scm_count_fds(msg_control_user);
}

static struct timewait_sock_ops scmtcp_timewait_sock_ops;
static struct request_sock_ops scmtcp_request_sock_ops;
static struct proto scmtcp_prot;
/* see inetsw_array[] */
static struct inet_protosw scmtcp_inetsw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_SCMTCP,
	.prot		= &scmtcp_prot,
	.ops		= &inet_stream_ops,
	.flags		= INET_PROTOSW_ICSK, /* Cannot set INET_PROTOSW_PERMANENT */
};

static void scmtcp_prot_init(void)
{
	scmtcp_prot = tcp_prot;

	scmtcp_timewait_sock_ops = *tcp_prot.twsk_prot;
	/* Cannot share slab with TCP. */
	scmtcp_timewait_sock_ops.twsk_slab = NULL;
	scmtcp_timewait_sock_ops.twsk_slab_name = NULL;

	scmtcp_request_sock_ops = *tcp_prot.rsk_prot;
	/* Cannot share slab with TCP. */
	scmtcp_request_sock_ops.slab = NULL;
	scmtcp_request_sock_ops.slab_name = NULL;

	/* Do not inherit the following fields from tcp_prot. */
	strscpy(scmtcp_prot.name, "SCMTCP", sizeof(scmtcp_prot.name));
	scmtcp_prot.owner	= THIS_MODULE;
	scmtcp_prot.obj_size	= sizeof(struct scmtcp_sock);
	scmtcp_prot.twsk_prot	= &scmtcp_timewait_sock_ops;
	scmtcp_prot.rsk_prot	= &scmtcp_request_sock_ops;
	scmtcp_prot.h.hashinfo	= NULL;

	scmtcp_prot.init	= scmtcp_sk_init;
	scmtcp_prot.destroy	= scmtcp_sk_destroy;
	scmtcp_prot.accept	= scmtcp_sk_accept;
	scmtcp_prot.sendmsg	= scmtcp_sk_sendmsg;
	scmtcp_prot.recvmsg	= scmtcp_sk_recvmsg;
}

static int scmtcp_seq_show(struct seq_file *m, void *v)
{
	seq_printf(m, "sk_count:    %lld\n", scm_fhtable.fctl_count);
	seq_printf(m, "flist_count: %lld\n", scm_fhtable.flist_count);
	seq_printf(m, "fd_count:    %lld\n", scm_fhtable.fd_count);
	return 0;
}

static int scmtcp_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, scmtcp_seq_show, NULL);
}

static const struct proc_ops scmtcp_proc_ops = {
	.proc_open    = scmtcp_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *scmtcp_proc_entry;

static int __init scmtcp_init(void)
{
	int ret;

	ret = file_htable_init();
	if (ret != 0) {
		pr_err("file_htable_init failed\n");
		return ret;
	}

	/* create /proc/net/scmtcp */
	scmtcp_proc_entry = proc_create("scmtcp", 0444, init_net.proc_net, &scmtcp_proc_ops);
	if (!scmtcp_proc_entry) {
		pr_err("proc_create failed\n");
		ret = -ENOENT;
		goto out;
	}

	scmtcp_prot_init();
	ret = proto_register(&scmtcp_prot, 1);
	if (ret != 0) {
		pr_err("proto_register failed\n");
		goto out;
	}
	inet_register_protosw(&scmtcp_inetsw);

	pr_info("%s successful\n", __func__);
	return 0;

out:
	if (scmtcp_proc_entry)
		proc_remove(scmtcp_proc_entry);
	file_htable_destroy();
	return ret;
}

static void __exit scmtcp_exit(void)
{
	inet_unregister_protosw(&scmtcp_inetsw);
	proto_unregister(&scmtcp_prot);

	if (scmtcp_proc_entry) {
		proc_remove(scmtcp_proc_entry);
		scmtcp_proc_entry = NULL;
	}
	if (file_htable_destroy() != 0)
		pr_err("file_htable_destroy failed\n");

	pr_info("%s successful\n", __func__);
}

module_init(scmtcp_init);
module_exit(scmtcp_exit);

MODULE_ALIAS_NET_PF_PROTO(PF_INET, /* IPPROTO_SCMTCP */ 518);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCMTCP: TCP with SCM_RIGHTS on loopback");
