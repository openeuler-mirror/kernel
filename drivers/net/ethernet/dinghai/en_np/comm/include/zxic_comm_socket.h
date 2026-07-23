/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZXIC_COMM_SOCKET_H_
#define _ZXIC_COMM_SOCKET_H_
#ifdef ZXIC_OS_WIN
#include <winsock.h>
#define ZXIC_SOCKET SOCKET

#else
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#define ZXIC_SOCKET s32
#endif

struct sockaddr;
struct sockaddr_in;

#define ZXIC_SOCK_VALID (0)
#define ZXIC_SOCK_INVALID (-1)
#define ZXIC_SOCK_NUM_MAX (16)

#define ZXIC_SOCK_INADDR_ANY (0x00000000)
#define ZXIC_SOCK_INADDR_LOOPBACK (0x7f000001)
#define ZXIC_SOCK_INADDR_BROADCAST (0xffffffff)
#define ZXIC_SOCK_INADDR_NONE (0xffffffff)

/* socket domain */
#define ZXIC_SOCK_AF_INET AF_INET /* internetwork: UDP, TCP, etc. */
#define ZXIC_SOCK_AF_INET6 AF_INET6 /* Internetwork Version 6 */

/* socket type */
#define ZXIC_SOCK_STREAM SOCK_STREAM /* stream socket */
#define ZXIC_SOCK_DGRAM SOCK_DGRAM /* datagram socket */
#define ZXIC_SOCK_RAW SOCK_RAW /* raw-protocol interface */
#define ZXIC_SOCK_RDM SOCK_RDM /* reliably-delivered message */
#define ZXIC_SOCK_SEQPACKET SOCK_SEQPACKET /* sequenced packet stream */

/* socket protocol */
#define ZXIC_SOCK_IPPROTO_IP IPPROTO_IP /* dummy for IP */
#define ZXIC_SOCK_IPPROTO_TCP IPPROTO_TCP /* tcp */
#define ZXIC_SOCK_IPPROTO_UDP IPPROTO_UDP /* user datagram protocol */

/* socket level */
#define ZXIC_SOCK_SOL_SOCKET SOL_SOCKET /* options for socket level */

/* socket OptName */
#define ZXIC_SOCK_SO_DEBUG SO_DEBUG /* turn on debugging info recording */
#define ZXIC_SOCK_SO_ACCEPTCONN SO_ACCEPTCONN /* socket has had listen() */
#define ZXIC_SOCK_SO_REUSEADDR SO_REUSEADDR /* allow local address reuse */
#define ZXIC_SOCK_SO_KEEPALIVE SO_KEEPALIVE /* keep connections alive */
#define ZXIC_SOCK_SO_DONTROUTE SO_DONTROUTE /* just use interface addresses */
#define ZXIC_SOCK_SO_BROADCAST SO_BROADCAST /* permit sending of broadcast msgs */
#define ZXIC_SOCK_SO_USELOOPBACK SO_USELOOPBACK /* bypass hardware when possible */
#define ZXIC_SOCK_SO_LINGER SO_LINGER /* linger on close if data present */
#define ZXIC_SOCK_SO_OOBINLINE SO_OOBINLINE /* leave received OOB data in line */
#define ZXIC_SOCK_SO_SNDBUF SO_SNDBUF /* send buffer size */
#define ZXIC_SOCK_SO_RCVBUF SO_RCVBUF /* receive buffer size */
#define ZXIC_SOCK_SO_SNDLOWAT SO_SNDLOWAT /* send low-water mark */
#define ZXIC_SOCK_SO_RCVLOWAT SO_RCVLOWAT /* receive low-water mark */
#define ZXIC_SOCK_SO_SNDTIMEO SO_SNDTIMEO /* send timeout */
#define ZXIC_SOCK_SO_RCVTIMEO SO_RCVTIMEO /* receive timeout */
#define ZXIC_SOCK_SO_ERROR SO_ERROR /* get error status and clear */
#define ZXIC_SOCK_SO_TYPE SO_TYPE /* get socket type */

#define ZXIC_TCP_OP_NODELAY TCP_NODELAY

struct zxic_comm_sock_addr_t {
	u32 family;
	u32 port;
	u32 addr;
};

struct zxic_comm_sock_mgr_t {
	u32 is_init;
	u32 count;
	ZXIC_SOCKET socks[ZXIC_SOCK_NUM_MAX];
	u8 sock_vld[ZXIC_SOCK_NUM_MAX];
	struct zxic_mutex_t mutex;
};

/* API */
u32 zxic_comm_sock_init(void);
u32 zxic_comm_sock_service_start(void);
u32 zxic_comm_sock_service_close(void);
u32 zxic_comm_sock_create(ZXIC_SOCKET *p_socket, s32 domain, s32 type, s32 protocol);

u32 zxic_comm_sock_set_opt(ZXIC_SOCKET sock, s32 level, s32 opt_name, void *p_opt_val, u32 opt_len);

u32 zxic_comm_sock_get_opt(ZXIC_SOCKET sock, s32 level, s32 opt_name, void *p_opt_val,
			   u32 *p_opt_len);

u32 zxic_comm_sock_bind_listen(ZXIC_SOCKET sock, struct zxic_comm_sock_addr_t *p_sock_addr);

u32 zxic_comm_sock_accpet(ZXIC_SOCKET listen_sock, ZXIC_SOCKET *p_cnnt_sock,
			  struct zxic_comm_sock_addr_t *p_sock_addr);

u32 zxic_comm_sock_connect(ZXIC_SOCKET sock, struct zxic_comm_sock_addr_t *p_sock_addr);

s32 zxic_comm_sock_send(ZXIC_SOCKET sock, char *p_buf, s32 len, s32 flag);

s32 zxic_comm_sock_recv(ZXIC_SOCKET sock, char *p_buf, s32 len, s32 flag);

u32 zxic_comm_sock_close(ZXIC_SOCKET sock);

#endif
