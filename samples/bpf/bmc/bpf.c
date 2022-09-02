// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: BPF program to accelerate Redis. The idea is to add a kernel
 * cache for Redis data. When new Redis request is received, the kernel cache
 * is checked, and if the requested data is found in the cache, a Redis reply
 * message is constructed and sent back directly.
 */

#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

#define BMC_MAX_REDIS_KEY_LEN	64
#define BMC_MAX_REDIS_VALUE_LEN 128

#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 16);
} bmc_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} bmc_interface SEC(".maps");

struct redis_key {
	u32 len;
	/* encoded in redis format */
	u8 data[BMC_MAX_REDIS_KEY_LEN + 16];
};

struct redis_value {
	u32 len;
	/* encoded in redis format */
	u8 data[BMC_MAX_REDIS_VALUE_LEN + 16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(struct redis_key));
	__uint(value_size, sizeof(struct redis_value));
	__uint(max_entries, 10000);
} bmc_storage SEC(".maps");

struct redis_ctx {
	struct redis_key key;
	struct redis_value value;
	u32 offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct redis_ctx));
	__uint(max_entries, 1);
} ctxmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct redis_bmc_stat));
	__uint(max_entries, 1);
} bmc_stats SEC(".maps");

static inline struct redis_ctx *get_ctx(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&ctxmap, &key);
}

static inline struct redis_bmc_stat *get_stat(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&bmc_stats, &key);
}

static bool is_bmc_port(u32 port)
{
	u32 *val = bpf_map_lookup_elem(&bmc_ports, &port);

	return val != NULL && *val != 0;
}

static inline void compute_ip_checksum(struct iphdr *ip)
{
	u32 csum = 0;
	u16 *next_ip_u16 = (u16 *)ip;

	ip->check = 0;

#pragma clang loop unroll(full)
	for (int i = 0; i < (sizeof(*ip) >> 1); i++)
		csum += *next_ip_u16++;

	ip->check = ~((csum & 0xffff) + (csum >> 16));
}

static inline void compute_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp,
					__u16 len, void *data_end)
{
	struct tcp_psedu_head {
		__be32 saddr;
		__be32 daddr;
		__u8 zero;
		__u8 proto;
		__u16 tcplen;
	};
	struct tcp_psedu_head psedu;
	char *tail = NULL;
	char left_over[2] = {0};

	psedu.saddr = ip->saddr;
	psedu.daddr = ip->daddr;
	psedu.zero = 0;
	psedu.proto = 6;
	psedu.tcplen = bpf_htons(len);

	tcp->check = 0;

	u32 csum = 0;
	u16 *next_u16 = (u16 *)&psedu;
	unsigned int i;

#pragma clang loop unroll(full)
	for (i = 0; i < (sizeof(struct tcp_psedu_head) >> 1); i++)
		csum += *next_u16++;

	next_u16 = (u16 *)tcp;
	for (i = 0; i < 1024 && (i < len / 2); i++) {
		if (next_u16 + 1 > data_end)
			break;
		csum += *next_u16++;
	}

	if (len % 2 == 1) {
		tail = (char *)next_u16;
		if (tail < data_end)
			left_over[0] = *tail;
		csum += *(unsigned short *)left_over;
	}
	csum = (csum >> 16) + (csum & 0xffff); /* add in accumulated carries */
	csum += csum >> 16;               /* add potential last carry */

	tcp->check =  (0xffff & ~csum);
}

#define extract_kvdata(field, size, kv_data, kv_len)				\
do {										\
	kv_data = payload;							\
	kv_len = 0;								\
										\
	if (payload + 1 > data_end || payload[0] != '$')			\
		return XDP_PASS;						\
										\
	payload++;								\
	if (payload < data_end && payload[0] >= '0' && payload[0] <= '9') {	\
		kv_len = kv_len * 10 + (payload[0] - '0');			\
		payload++;							\
	}									\
										\
	if (payload < data_end && payload[0] >= '0' && payload[0] <= '9') {	\
		kv_len = kv_len * 10 + (payload[0] - '0');			\
		payload++;							\
	}									\
										\
	if (payload < data_end && payload[0] >= '0' && payload[0] <= '9') {	\
		kv_len = kv_len * 10 + (payload[0] - '0');			\
		payload++;							\
	}									\
										\
	if (payload < data_end && payload[0] >= '0' && payload[0] <= '9') {	\
		kv_len = kv_len * 10 + (payload[0] - '0');			\
		payload++;							\
	}									\
										\
	if (payload + 2 > data_end || payload[0] != '\r' || payload[1] != '\n')	\
		return XDP_PASS;						\
										\
	payload += 2;								\
										\
	if (kv_len == 0 || kv_len > size)					\
		return XDP_PASS;						\
										\
	payload += kv_len + 2;							\
	kv_len = payload - kv_data;						\
										\
	if (kv_len > sizeof(ctx->field.data))					\
		return XDP_PASS;						\
										\
	bpf_xdp_load_bytes(xdp, kv_data - data, ctx->field.data, kv_len);	\
	ctx->field.len = kv_len;						\
} while (0)

#define adjust_xdp_tail(size, len)						\
do {										\
	char *new_end;								\
										\
	new_end = payload = (char *)thdr + thdr->doff * 4;			\
	for (i = 0; i < size && i < len; i++)					\
		new_end++;							\
										\
	if (new_end > data_end)							\
		err = bpf_xdp_adjust_tail(xdp, new_end - data_end);		\
	else if (new_end  < data_end)						\
		err = bpf_xdp_adjust_tail(xdp, -(data_end - new_end));		\
										\
	if (err)								\
		return XDP_PASS;						\
} while (0)

#define sync_tcp_seq(len, ndrop)						\
do {										\
	struct bpf_sock_tuple tuple;						\
										\
	tuple.ipv4.saddr = ihdr->saddr;						\
	tuple.ipv4.daddr = ihdr->daddr;						\
	tuple.ipv4.sport = thdr->source;					\
	tuple.ipv4.dport = thdr->dest;						\
										\
	tuple.seq = __bpf_ntohl(thdr->seq);					\
	tuple.delta = __bpf_ntohs(ihdr->tot_len) - ihlen - thlen;		\
	tuple.ack_seq = __bpf_ntohs(thdr->ack_seq) + len;			\
										\
	if (bpf_update_tcp_seq(xdp, &tuple, sizeof(tuple.ipv4), -1, 0)) {	\
		ndrop++;							\
		return XDP_DROP;						\
	}									\
} while (0)

#define build_reply_head(len)							\
do {										\
	thdr->doff = 5; /* discard tcp options */				\
	port = thdr->source;							\
	thdr->source = thdr->dest;						\
	thdr->dest = port;							\
										\
	seq = __bpf_ntohl(thdr->seq);						\
	seq += __bpf_ntohs(ihdr->tot_len) - ihlen - thlen;			\
	thdr->seq = thdr->ack_seq;						\
	thdr->ack_seq = __bpf_ntohl(seq);					\
										\
	ipaddr = ihdr->saddr;							\
	ihdr->saddr = ihdr->daddr;						\
	ihdr->daddr = ipaddr;							\
	ihdr->tot_len = __bpf_htons(ihlen + thdr->doff * 4 + len);		\
										\
	memcpy(macaddr, ehdr->h_source, ETH_ALEN);				\
	memcpy(ehdr->h_source, ehdr->h_dest, ETH_ALEN);				\
	memcpy(ehdr->h_dest, macaddr, ETH_ALEN);				\
} while (0)

SEC("bmc/main")
int bmc_main(struct xdp_md *xdp)
{
	int err;
	u32 klen;
	u32 vlen;
	unsigned int i;
	unsigned int seq;
	u8 macaddr[ETH_ALEN];
	__be32 ipaddr;
	__le16 port;
	char *data = (char *)(long)xdp->data;
	char *data_end = (char *)(long)xdp->data_end;
	struct ethhdr *ehdr = NULL;
	struct iphdr *ihdr = NULL;
	struct tcphdr *thdr = NULL;
	unsigned int ihlen;
	unsigned int thlen;
	char *payload;
	u32 offset;
	int is_get = 0;
	int expect_get = 0;
	struct redis_ctx *ctx;
	struct redis_bmc_stat *stat;
	char *key_data;
	char *value_data;
	u32 key_len;
	u32 value_len;

	ehdr = (struct ethhdr *)data;
	if (ehdr + 1 > data_end)
		return XDP_PASS;

	if (ehdr->h_proto != __bpf_constant_htons(ETH_P_IP))
		return XDP_PASS;

	ihdr = (struct iphdr *)(ehdr + 1);
	if (ihdr + 1 > data_end)
		return XDP_PASS;

	if (ihdr->ihl != 5 || ihdr->protocol != IPPROTO_TCP)
		return XDP_PASS;

	ihlen  = ihdr->ihl * 4;

	if (ihdr->frag_off & __bpf_htons(IP_MF | IP_OFFSET))
		return XDP_PASS;

	if (__bpf_htons(ihdr->tot_len) > ETH_DATA_LEN)
		return XDP_PASS;

	thdr = (struct tcphdr *)(ihdr + 1);
	if (thdr + 1 > data_end)
		return XDP_PASS;

	if (thdr->syn || thdr->fin || thdr->rst)
		return XDP_PASS;

	if (!is_bmc_port(thdr->dest))
		return XDP_PASS;

	thlen = thdr->doff * 4;
	payload = (void *)thdr + thlen;

	/*
	 * SET message format:
	 * "*3\r\n"	// this is an array with 3 elements
	 * "$3\r\n"	// the first element is a string with 3 characters
	 * "set\r\n"	// the string is "set"
	 * "$5\r\n"	// the second element is a string with 5 characters
	 * "key01\r\n"	// the string is "key01"
	 * "$5\r\n"	// the third element is a string with 5 characters
	 * "val01\r\n"  // the string is "valu01"
	 *
	 * GET message format:
	 * "*2\r\n"	// this is an array with 3 elements
	 * "$3\r\n"	// the first element is a string with 3 characters
	 * "get\r\n"	// the string is "get"
	 * "$5\r\n"	// the second element is a string with 5 characters
	 * "key01\r\n"	// the string is "key01"
	 */
	if (payload + 8 > data_end)
		return XDP_PASS;

	if (payload[0] != '*' || (payload[1] != '2' && payload[1] != '3') ||
		payload[2] != '\r' || payload[3] != '\n' || payload[4] != '$' ||
		payload[5] != '3' || payload[6] != '\r' || payload[7] != '\n')
		return XDP_PASS;

	expect_get = (payload[1] == '2');
	payload += 8;

	if (payload + 5 > data_end)
		return XDP_PASS;

	switch (payload[0]) {
	case 'g':
		is_get = 1;
	case 's':
		if (payload[1] != 'e' || payload[2] != 't' ||
			payload[3] != '\r' || payload[4] != '\n')
			return XDP_PASS;
		break;
	case 'G':
		is_get = 1;
	case 'S':
		if (payload[1] != 'E' || payload[2] != 'T' ||
			payload[3] != '\r' || payload[4] != '\n')
			return XDP_PASS;
		break;
	default:
		return XDP_PASS;
	}

	payload += 5;

	if (expect_get != is_get)
		return XDP_PASS;

	ctx = get_ctx();
	if (!ctx)
		return XDP_PASS;

	memset(ctx, 0, sizeof(*ctx));

	stat = get_stat();
	if (!stat)
		return XDP_PASS;

	extract_kvdata(key, BMC_MAX_REDIS_KEY_LEN, key_data, key_len);

	if (is_get) {
		struct redis_value *val;

		stat->total_get_requests++;

		val = bpf_map_lookup_elem(&bmc_storage, &ctx->key);
		if (!val || !val->len || val->len > sizeof(val->data))
			return XDP_PASS;
		vlen = val->len;

		sync_tcp_seq(vlen, stat->drop_get_requests);

		build_reply_head(vlen);

		adjust_xdp_tail(BMC_MAX_REDIS_VALUE_LEN, vlen);

		data = (char *)(long)xdp->data;
		data_end = (char *)(long)xdp->data_end;

		ihdr = (struct iphdr *)(data + sizeof(struct ethhdr));
		thdr = (struct tcphdr *)(ihdr + 1);
		if (ihdr + 1 > data_end || thdr + 1 > data_end)
			return XDP_PASS;

		offset = sizeof(*ehdr) + ihdr->ihl * 4 + thdr->doff * 4;
		bpf_xdp_store_bytes(xdp, offset, val->data, vlen);

		compute_ip_checksum(ihdr);

		compute_tcp_checksum(ihdr, thdr, vlen + thdr->doff * 4,
				     data_end);

		stat->hit_get_requests++;

		return XDP_TX;
	} else {
		char reply[] = { '+', 'O', 'K', '\r', '\n'};

		stat->total_set_requests++;

		/* make sure the stupid verifier will not reject the prog */
		payload = key_data;
		for (i = 0; i < sizeof(ctx->key.data) && i < key_len; i++)
			payload++;

		extract_kvdata(value, BMC_MAX_REDIS_VALUE_LEN, value_data,
			       value_len);

		err = bpf_map_update_elem(&bmc_storage, &ctx->key,
					  &ctx->value, BPF_ANY);
		if (err)
			return XDP_PASS;

		sync_tcp_seq(sizeof(reply), stat->drop_set_requests);

		build_reply_head(sizeof(reply));

		adjust_xdp_tail(sizeof(reply), sizeof(reply));

		data = (char *)(long)xdp->data;
		data_end = (char *)(long)xdp->data_end;

		ihdr = (struct iphdr *)(data + sizeof(struct ethhdr));
		thdr = (struct tcphdr *)(ihdr + 1);
		if (ihdr + 1 > data_end || thdr + 1 > data_end)
			return XDP_PASS;

		offset = sizeof(*ehdr) + ihdr->ihl * 4 + thdr->doff * 4;
		bpf_xdp_store_bytes(xdp, offset, reply, sizeof(reply));

		compute_ip_checksum(ihdr);

		compute_tcp_checksum(ihdr, thdr, thdr->doff * 4 + sizeof(reply),
				     data_end);

		stat->hit_set_requests++;

		return XDP_TX;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
