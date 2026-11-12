/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright (c) 2026 Huawei Technologies Co., Ltd. All Rights Reserved.
 *
 * famem_hbm_server.c — Native Famem HBM server for one Ascend NPU.
 *
 * This binary owns the physical HBM extents of a single device and serves
 * the Famem control protocol (famem_protocol.h) on a Unix stream socket
 * named after the device UUID.  Clients (vLLM Worker processes and, for
 * handle authorization, their Copier subprocesses) connect, claim a lease
 * and drive the sleep/wake cycle; see FamemClient in
 * vllm_ascend/device_allocator/famem_client.py for the client side.
 *
 * Server model
 * ------------
 *   - One thread per client connection; a mutex (server_state.mutex)
 *     serializes all state transitions.
 *   - One pool of at most FAMEM_MAX_EXTENTS physical extents, sized either
 *     by --pool-size at startup or by the first ACQUIRE request (pool_size
 *     == 0 defers sizing).  Later ACQUIRE requests must request the exact
 *     same size or they are rejected — multi-instance time-sharing
 *     therefore requires identical arena sizes across instances.
 *   - At most one ACTIVE lease per NPU ("active" = extents currently
 *     allocated and mapped).  Other connected leases may exist in the
 *     sleeping state; ACQUIRE/WAKE from a second lease gets
 *     FAMEM_STATUS_BUSY until the active lease SLEEPs or RELEASEs.
 *
 * Lease lifecycle
 * ---------------
 *   HELLO    create lease; record Worker + Copier identities (pidfd or
 *            pid+start_time) for liveness checking
 *   ACQUIRE  allocate pool extents; authorize shareable handles for the
 *            Worker and Copier TGIDs; lease becomes active
 *   SLEEP    free the physical extents (clients must have unmapped first);
 *            lease stays; epoch unchanged on the wire (client keeps it)
 *   WAKE     re-allocate the same extent layout; epoch += 1; fresh
 *            shareable handles are exported and authorized
 *   RELEASE  destroy the lease (frees extents if still active)
 *
 * Orphan reclamation
 * ------------------
 *   If a client disconnects while its lease is still active, the server
 *   blocks in the connection thread until the Worker and Copier processes
 *   exit (pidfd poll, or pid liveness + start_time comparison when pidfd
 *   is unavailable), then frees the extents.  This guarantees CANN
 *   physical memory is never freed while a mapping in another process
 *   still references it.
 *
 * Poisoning
 * ---------
 *   Any failure to free or allocate physical extents marks the server
 *   poisoned: it refuses new leases (FAMEM_STATUS_INTERNAL) until
 *   restarted, because the physical pool state is no longer trustworthy.
 *
 * Flags: --device (required), --socket-dir, --socket-name, --pool-size,
 *        --log-level, --skip-tgid-check (containers without SO_PEERCRED).
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define FAMEM_DEFAULT_SOCKET_DIR "/run/vllm-ascend/famem"
#define FAMEM_SOCKET_PATH_MAX 103U
#define FAMEM_UUID_SIZE 32U
#define FAMEM_SESSION_SIZE 32U
#define FAMEM_MAX_EXTENTS 2U
#define FAMEM_PAGE_HUGE_1G 1
#define FAMEM_PAGE_HUGE_2M 2
#define FAMEM_HUGE_1G_BYTES (UINT64_C(1) << 30)
#define FAMEM_HUGE_2M_BYTES (UINT64_C(2) << 20)
#define FAMEM_MAX_POOL_GIB UINT64_C(4096)

enum log_level {
	LOG_DEBUG = 0,
	LOG_INFO = 1,
	LOG_WARNING = 2,
	LOG_ERROR = 3,
};

struct request_frame {
	uint16_t operation;
	uint32_t request_id;
	uint32_t payload_size;
	uint8_t payload[FAMEM_PROTOCOL_MAX_PAYLOAD];
};
struct physical_extent {
	int page_type;
	uint64_t size;
	uint64_t physical_handle;
	uint64_t shareable_handle;
};
struct process_identity {
	pid_t pid;
	int pidfd;
	uint64_t start_time;
	bool has_start_time;
};
struct lease {
	bool acquired;
	bool active;
	char session_id[FAMEM_SESSION_SIZE + 1U];
	struct process_identity worker_process;
	struct process_identity copier_process;
	int32_t bare_tgid;
	int32_t copier_bare_tgid;
	uint64_t epoch;
};
struct server_state;
struct client_context {
	int socket_fd;
	pthread_t thread;
	bool thread_finished;
	struct lease lease;
	struct server_state *server;
	struct client_context *next;
};
struct server_state {
	int device;
	char device_uuid[FAMEM_UUID_SIZE + 1U];
	pthread_mutex_t mutex;
	struct client_context *clients;
	struct lease *active_lease;
	uint64_t pool_size;
	uint64_t epoch;
	size_t pool_extent_count;
	struct physical_extent pool_extents[FAMEM_MAX_EXTENTS];
	bool poisoned;
};

static volatile sig_atomic_t g_stop;
static enum log_level g_log_level = LOG_INFO;
static int g_skip_tgid_check;

/* Level-filtered stderr logger with a fixed [Famem HBM Server] prefix. */
static void log_message(enum log_level level, const char *format, ...)
{
	static const char * const names[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
	va_list arguments;
	if (level < g_log_level) {
		return;
	}
	fprintf(stderr, "[Famem HBM Server] %s: ", names[level]);
	va_start(arguments, format);
	vfprintf(stderr, format, arguments);
	va_end(arguments);
	fputc('\n', stderr);
}

/* SIGTERM/SIGINT handler: set the global stop flag (checked by accept/poll loops). */
static void stop_server(int signal_number)
{
	(void)signal_number;
	g_stop = 1;
}

/* Read one big-endian uint16 (wire protocol; see famem_protocol.h). */
static uint16_t load_u16(const uint8_t *input)
{
	return (uint16_t)(((uint16_t)input[0] << 8U) | (uint16_t)input[1]);
}
/* Read one big-endian uint32. */
static uint32_t load_u32(const uint8_t *input)
{
	return ((uint32_t)input[0] << 24U) | ((uint32_t)input[1] << 16U) | ((uint32_t)input[2] << 8U) | (uint32_t)input[3];
}
/* Read one big-endian uint64. */
static uint64_t load_u64(const uint8_t *input)
{
	return ((uint64_t)load_u32(input) << 32U) | (uint64_t)load_u32(input + 4U);
}
/* Write one big-endian uint16. */
static void store_u16(uint8_t *output, uint16_t value)
{
	output[0] = (uint8_t)(value >> 8U);
	output[1] = (uint8_t)value;
}
/* Write one big-endian uint32. */
static void store_u32(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)(value >> 24U);
	output[1] = (uint8_t)(value >> 16U);
	output[2] = (uint8_t)(value >> 8U);
	output[3] = (uint8_t)value;
}
/* Write one big-endian uint64. */
static void store_u64(uint8_t *output, uint64_t value)
{
	store_u32(output, (uint32_t)(value >> 32U));
	store_u32(output + 4U, (uint32_t)value);
}

/* Read exactly *size* bytes; *clean_eof* distinguishes EOF-before-any-data from a mid-frame close. */
static int receive_exact(int socket_fd, uint8_t *output, size_t size, bool *clean_eof)
{
	size_t offset = 0;
	*clean_eof = false;
	while (offset < size) {
		const ssize_t received = recv(socket_fd, output + offset, size - offset, 0);
		if (received > 0) {
			offset += (size_t)received;
			continue;
		}
		if (received == 0) {
			*clean_eof = offset == 0;
			return -1;
		}
		if (errno == EINTR && !g_stop) {
			continue;
		}
		return -1;
	}
	return 0;
}
/* Write exactly *size* bytes; retries on EINTR, fails on short writes. */
static int send_exact(int socket_fd, const uint8_t *input, size_t size)
{
	size_t offset = 0;
	while (offset < size) {
		const ssize_t sent = send(socket_fd, input + offset, size - offset, MSG_NOSIGNAL);
		if (sent > 0) {
			offset += (size_t)sent;
			continue;
		}
		if (sent < 0 && errno == EINTR && !g_stop) {
			continue;
		}
		return -1;
	}
	return 0;
}
/* Read + validate one request frame into *request*; on error fills *error* and returns -1. */
static int receive_request(int socket_fd, struct request_frame *request, char *error, size_t error_size)
{
	uint8_t header[FAMEM_PROTOCOL_HEADER_SIZE];
	bool clean_eof = false;

	memset(request, 0, sizeof(*request));
	if (receive_exact(socket_fd, header, sizeof(header), &clean_eof) != 0) {
		if (clean_eof) {
			return 0;
		}
		snprintf(error, error_size, "connection closed while reading a frame header");
		return -1;
	}
	request->operation = load_u16(header + 8U);
	request->request_id = load_u32(header + 12U);
	request->payload_size = load_u32(header + 20U);

	if (load_u32(header) != FAMEM_PROTOCOL_MAGIC || load_u16(header + 4U) != FAMEM_PROTOCOL_VERSION ||
			load_u16(header + 6U) != FAMEM_MESSAGE_REQUEST || load_u16(header + 10U) != 0U ||
			load_u32(header + 16U) != FAMEM_STATUS_OK || request->operation < FAMEM_OP_HELLO ||
			request->operation > FAMEM_OP_STATS || request->request_id == 0U ||
			request->payload_size > FAMEM_PROTOCOL_MAX_PAYLOAD) {
		snprintf(error, error_size, "invalid protocol header");
		return -2;
	}
	if (request->operation > FAMEM_OP_STATS) {
		snprintf(error, error_size, "unsupported operation %u", request->operation);
		return -2;
	}
	if (request->payload_size != 0U &&
			receive_exact(socket_fd, request->payload, request->payload_size, &clean_eof) != 0) {
		snprintf(error, error_size, "connection closed while reading a frame payload");
		return -1;
	}
	return 1;
}
/* Frame and send one response (payload optional). */
static int send_response(int socket_fd, uint16_t operation, uint32_t request_id, uint32_t status,
												 const uint8_t *payload, uint32_t payload_size)
{
	uint8_t frame[FAMEM_PROTOCOL_HEADER_SIZE + FAMEM_PROTOCOL_MAX_PAYLOAD];
	if (payload_size > FAMEM_PROTOCOL_MAX_PAYLOAD) {
		errno = EMSGSIZE;
		return -1;
	}
	store_u32(frame, FAMEM_PROTOCOL_MAGIC);
	store_u16(frame + 4U, FAMEM_PROTOCOL_VERSION);
	store_u16(frame + 6U, FAMEM_MESSAGE_RESPONSE);
	store_u16(frame + 8U, operation);
	store_u16(frame + 10U, 0U);
	store_u32(frame + 12U, request_id);
	store_u32(frame + 16U, status);
	store_u32(frame + 20U, payload_size);
	if (payload_size != 0U) {
		memcpy(frame + FAMEM_PROTOCOL_HEADER_SIZE, payload, payload_size);
	}
	return send_exact(socket_fd, frame, FAMEM_PROTOCOL_HEADER_SIZE + payload_size);
}
/* send_response wrapper encoding a UTF-8 error message payload. */
static int send_error_response(int socket_fd, const struct request_frame *request, uint32_t status,
															 const char *message)
{
	const size_t message_size = strnlen(message, FAMEM_PROTOCOL_MAX_PAYLOAD);
	return send_response(socket_fd, request->operation, request->request_id, status, (const uint8_t *)message,
											 (uint32_t)message_size);
}
/* Send an error response and log the rejection at WARNING. */
static int reject_client(int socket_fd, const struct request_frame *request, uint32_t status, const char *message)
{
	(void)send_error_response(socket_fd, request, status, message);
	return -1;
}

/* True when every byte is a lowercase hex digit (session/UUID validation). */
static bool is_lower_hex(const uint8_t *value, size_t size)
{
	size_t index;
	for (index = 0; index < size; ++index) {
		if (!((value[index] >= (uint8_t)'0' && value[index] <= (uint8_t)'9') ||
					(value[index] >= (uint8_t)'a' && value[index] <= (uint8_t)'f'))) {
			return false;
		}
	}
	return true;
}

/* True when the buffer is all zero bytes (UUID-unsupported detection). */
static bool is_all_zero(const uint8_t *value, size_t size)
{
	size_t index;
	for (index = 0; index < size; ++index) {
		if (value[index] != 0) {
			return false;
		}
	}
	return true;
}

/* Parse /proc/<pid>/stat for the start time (field 22) and parent PID (field 4). */
static bool read_process_stat(pid_t pid, uint64_t *start_time, pid_t *parent_pid)
{
	char path[64];
	char buffer[4096];
	char *closing_parenthesis;
	char *save_pointer = NULL;
	char *token;
	unsigned int field = 4U;
	FILE *process_stat;
	char *end = NULL;
	unsigned long long parsed;

	if (pid <= 0 || start_time == NULL || snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) < 0) {
		return false;
	}
	process_stat = fopen(path, "r");
	if (process_stat == NULL) {
		return false;
	}
	if (fgets(buffer, sizeof(buffer), process_stat) == NULL) {
		(void)fclose(process_stat);
		return false;
	}
	(void)fclose(process_stat);
	closing_parenthesis = strrchr(buffer, ')');
	if (closing_parenthesis == NULL) {
		return false;
	}
	token = strtok_r(closing_parenthesis + 1, " \t\r\n", &save_pointer);
	token = token == NULL ? NULL : strtok_r(NULL, " \t\r\n", &save_pointer);
	if (token == NULL) {
		return false;
	}
	if (parent_pid != NULL) {
		errno = 0;
		parsed = strtoull(token, &end, 10);
		if (errno != 0 || end == token || *end != '\0' || parsed > INT_MAX) {
			return false;
		}
		*parent_pid = (pid_t)parsed;
	}
	while (token != NULL && field < 22U) {
		token = strtok_r(NULL, " \t\r\n", &save_pointer);
		++field;
	}
	if (token == NULL || field != 22U) {
		return false;
	}
	errno = 0;
	parsed = strtoull(token, &end, 10);
	if (errno != 0 || end == token || *end != '\0') {
		return false;
	}
	*start_time = (uint64_t)parsed;
	return true;
}

/* Open a pidfd for *pid* (0 on kernels without pidfd_open). */
static int open_process_pidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
	const long descriptor = syscall(SYS_pidfd_open, pid, 0U);
	if (descriptor >= 0 && descriptor <= INT_MAX) {
		return (int)descriptor;
	}
#else
	(void)pid;
#endif
	return -1;
}
/* Snapshot (pid, pidfd, start_time) for liveness tracking of a lease peer. */
static void capture_process_identity(struct process_identity *identity, pid_t pid, pid_t *parent_pid)
{
	memset(identity, 0, sizeof(*identity));
	identity->pid = pid;
	identity->pidfd = open_process_pidfd(pid);
	identity->has_start_time = read_process_stat(pid, &identity->start_time, parent_pid);
}
/* Liveness check: pidfd poll or pid signal-probe plus start_time comparison (PID reuse guard). */
static bool process_exists(const struct process_identity *identity)
{
	uint64_t current_start_time = 0U;
	if (identity->pid <= 0) {
		return false;
	}
	if (kill(identity->pid, 0) == 0) {
		if (identity->has_start_time && read_process_stat(identity->pid, &current_start_time, NULL) &&
				current_start_time != identity->start_time) {
			return false;
		}
		return true;
	}
	return errno == EPERM;
}
/* Block until the tracked process exits (pidfd poll or 200ms polling loop). */
static void wait_for_process_exit(const struct process_identity *identity)
{
	struct timespec interval = {.tv_sec = 0, .tv_nsec = 200000000L};
	if (identity->pid <= 0) {
		return;
	}
	if (identity->pidfd >= 0) {
		struct pollfd descriptor = {.fd = identity->pidfd, .events = POLLIN | POLLHUP | POLLERR, .revents = 0};
		while (poll(&descriptor, 1U, -1) < 0) {
			if (errno != EINTR) {
				break;
			}
		}
		if (descriptor.revents != 0) {
			return;
		}
	}
	while (process_exists(identity)) {
		(void)nanosleep(&interval, NULL);
	}
}
/* Close one identity's pidfd. */
static void close_process_identity(struct process_identity *identity)
{
	if (identity->pid > 0 && identity->pidfd >= 0) {
		(void)close(identity->pidfd);
	}
	memset(identity, 0, sizeof(*identity));
	identity->pidfd = -1;
}
/* Close the Worker and Copier identity pidfds of one lease. */
static void close_lease_process_identities(struct lease *lease)
{
	close_process_identity(&lease->worker_process);
	close_process_identity(&lease->copier_process);
}

/* Famem last_error() string, or a placeholder when the library is silent. */
static const char *native_error(void)
{
	const char *error = famem_last_error();
	return error == NULL || error[0] == '\0' ? "unknown native allocator error" : error;
}

/* Release N physical extents via famem_server_free; any failure poisons the server. */
static int free_extents(struct physical_extent *extents, size_t extent_count)
{
	int result = 0;
	while (extent_count > 0U) {
		struct physical_extent *extent = &extents[extent_count - 1U];
		if (extent->physical_handle != 0U) {
			if (famem_server_free(extent->physical_handle) != 0) {
				log_message(LOG_ERROR, "failed to free physical extent: %s", native_error());
				result = -1;
			} else {
				extent->physical_handle = 0U;
				extent->shareable_handle = 0U;
			}
		}
		--extent_count;
	}
	return result;
}

enum { EXTENT_ALLOCATION_ROLLBACK_FAILED = -2 };
/* Allocate N extents and authorize the lease's TGIDs on each shareable handle. */
static int allocate_extents(int device, struct physical_extent *extents, size_t extent_count)
{
	size_t index;
	for (index = 0; index < extent_count; ++index) {
		if (famem_server_allocate_export(device, extents[index].size, extents[index].page_type,
																		 &extents[index].physical_handle, &extents[index].shareable_handle) != 0) {
			log_message(LOG_WARNING, "failed to allocate extent %zu: %s", index, native_error());
			if (free_extents(extents, index) != 0) {
				return EXTENT_ALLOCATION_ROLLBACK_FAILED;
			}
			return -1;
		}
	}
	return 0;
}

/* (Re)authorize both lease TGIDs on every pool shareable handle (called after WAKE too). */
static int authorize_pool(struct server_state *server, const struct lease *lease)
{
	const int32_t bare_tgids[] = {lease->bare_tgid, lease->copier_bare_tgid};
	size_t index;
	for (index = 0; index < server->pool_extent_count; ++index) {
		if (famem_server_authorize(server->pool_extents[index].shareable_handle, bare_tgids,
															 sizeof(bare_tgids) / sizeof(bare_tgids[0])) != 0) {
			log_message(LOG_ERROR, "failed to authorize extent %zu: %s", index, native_error());
			server->poisoned = true;
			log_message(LOG_ERROR, "pool authorization state is uncertain; server poisoned");
			return -1;
		}
	}
	return 0;
}

/* Choose the extent layout: fill with 1G pages up to availability, remainder 2M pages. */
static int plan_extents(int device, uint64_t size, struct physical_extent *extents, size_t *extent_count)
{
	uint64_t small_granularity = 0U;
	uint64_t large_granularity = 0U;
	uint64_t free_large = 0U;
	uint64_t large_size = 0U;
	if (famem_get_page_granularity(device, FAMEM_PAGE_HUGE_2M, &small_granularity) != 0 ||
			small_granularity != FAMEM_HUGE_2M_BYTES) {
		return -1;
	}
	if (size == 0U || size % small_granularity != 0U) {
		return -1;
	}
	if (famem_get_page_granularity(device, FAMEM_PAGE_HUGE_1G, &large_granularity) == 0 &&
			large_granularity == FAMEM_HUGE_1G_BYTES &&
			famem_get_page_free_memory(device, FAMEM_PAGE_HUGE_1G, &free_large) == 0) {
		large_size = size < free_large ? size : free_large;
		large_size -= large_size % large_granularity;
	} else {
		log_message(LOG_WARNING, "1 GiB pages are unavailable; using 2 MiB pages only: %s", native_error());
	}
	memset(extents, 0, sizeof(*extents) * FAMEM_MAX_EXTENTS);
	*extent_count = 0U;
	if (large_size != 0U) {
		extents[*extent_count].page_type = FAMEM_PAGE_HUGE_1G;
		extents[*extent_count].size = large_size;
		++(*extent_count);
	}
	if (large_size != size) {
		extents[*extent_count].page_type = FAMEM_PAGE_HUGE_2M;
		extents[*extent_count].size = size - large_size;
		++(*extent_count);
	}
	return 0;
}

/* Allocate the pool extents once (first ACQUIRE) and fix server->pool_size. */
static int initialize_pool(struct server_state *server, uint64_t size)
{
	int result;
	if (plan_extents(server->device, size, server->pool_extents, &server->pool_extent_count) != 0) {
		log_message(LOG_ERROR, "cannot plan the physical pool layout: %s", native_error());
		return -1;
	}
	result = allocate_extents(server->device, server->pool_extents, server->pool_extent_count);
	if (result == -1 && server->pool_extents[0].page_type == FAMEM_PAGE_HUGE_1G) {
		log_message(LOG_WARNING, "preferred pool layout failed; retrying with 2 MiB pages");
		memset(server->pool_extents, 0, sizeof(server->pool_extents));
		server->pool_extents[0].page_type = FAMEM_PAGE_HUGE_2M;
		server->pool_extents[0].size = size;
		server->pool_extent_count = 1U;
		result = allocate_extents(server->device, server->pool_extents, server->pool_extent_count);
	}
	if (result != 0) {
		log_message(LOG_ERROR, "cannot allocate the physical pool%s",
								result == EXTENT_ALLOCATION_ROLLBACK_FAILED ? "; rollback left HBM allocated" : "");
		return -1;
	}
	server->pool_size = size;
	log_message(LOG_INFO, "allocated persistent pool of %llu bytes in %zu extent(s)", (unsigned long long)size,
							server->pool_extent_count);
	return 0;
}

/* ACQUIRE/WAKE success response: extent page types, sizes, and shareable handles. */
static int send_mapping_response(int socket_fd, const struct request_frame *request, const struct server_state *server,
																 const struct lease *lease)
{
	uint8_t payload[FAMEM_MAPPING_PREFIX_SIZE + FAMEM_MAX_EXTENTS * FAMEM_MAPPING_EXTENT_SIZE];
	size_t offset = FAMEM_MAPPING_PREFIX_SIZE;
	size_t index;
	store_u64(payload, server->pool_size);
	store_u64(payload + 8U, lease->epoch);
	store_u32(payload + 16U, (uint32_t)server->pool_extent_count);
	for (index = 0; index < server->pool_extent_count; ++index) {
		store_u32(payload + offset, (uint32_t)server->pool_extents[index].page_type);
		store_u64(payload + offset + 4U, server->pool_extents[index].size);
		store_u64(payload + offset + 12U, server->pool_extents[index].shareable_handle);
		offset += FAMEM_MAPPING_EXTENT_SIZE;
	}
	return send_response(socket_fd, request->operation, request->request_id, FAMEM_STATUS_OK, payload, (uint32_t)offset);
}

/* Mark *lease *the single active lease and authorize its TGIDs on the pool. */
static int activate_lease(struct server_state *server, struct lease *lease)
{
	if (server->epoch == UINT64_MAX) {
		server->poisoned = true;
	}
	if (server->poisoned) {
		log_message(LOG_DEBUG, "activate_lease: server is poisoned");
		return -1;
	}
	if (!g_skip_tgid_check && !process_exists(&lease->worker_process)) {
		log_message(LOG_DEBUG, "activate_lease: worker process (pid=%d) does not exist", lease->worker_process.pid);
		return -1;
	}
	if (authorize_pool(server, lease) != 0) {
		log_message(LOG_DEBUG, "activate_lease: authorize_pool failed");
		return -1;
	}
	lease->epoch = ++server->epoch;
	lease->active = true;
	server->active_lease = lease;
	return 0;
}

/* ACQUIRE: fix pool size on first use, verify capacity match, activate the lease. */
static int handle_acquire(int socket_fd, const struct request_frame *request, struct server_state *server,
													struct lease *lease)
{
	log_message(LOG_INFO, "ACQUIRE: lease->acquired=%d, poisoned=%d, worker_pid=%d, copier_pid=%d",
							lease->acquired, server->poisoned, lease->worker_process.pid, lease->copier_process.pid);
	if (request->payload_size != FAMEM_SESSION_U64_REQUEST_SIZE) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_PROTOCOL, "invalid ACQUIRE session or payload size");
	}
	if (lease->acquired) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_PROTOCOL, "the lease has already acquired an arena");
	}
	if (server->poisoned) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_INTERNAL, "server pool authorization is uncertain");
	}
	if (server->active_lease != NULL && server->active_lease != lease) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_BUSY, "another Famem lease is active");
	}
	if (load_u64(request->payload + FAMEM_SESSION_SIZE) != server->pool_size) {
		if (server->pool_size == 0U) {
			/* Pool not yet allocated; use the client's requested size. */
			uint64_t requested_size = load_u64(request->payload + FAMEM_SESSION_SIZE);
			log_message(LOG_INFO, "allocating pool on first ACQUIRE: %llu bytes", (unsigned long long)requested_size);
			if (initialize_pool(server, requested_size) != 0) {
				return send_error_response(socket_fd, request, FAMEM_STATUS_INTERNAL, "failed to allocate Famem pool");
			}
		} else {
			return send_error_response(socket_fd, request, FAMEM_STATUS_PROTOCOL,
																 "requested arena size does not match the configured pool");
		}
	}
	if (activate_lease(server, lease) != 0) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_INTERNAL,
															 server->poisoned ? "Famem pool is poisoned; restart the server"
																								: "failed to authorize the Famem pool");
	}
	lease->acquired = true;
	return send_mapping_response(socket_fd, request, server, lease);
}

/* Reject SLEEP/WAKE/RELEASE with a stale epoch (PROTOCOL error). */
static int validate_epoch_request(int socket_fd, const struct request_frame *request, const struct lease *lease)
{
	if (request->payload_size != FAMEM_SESSION_U64_REQUEST_SIZE || !lease->acquired ||
			load_u64(request->payload + FAMEM_SESSION_SIZE) != lease->epoch) {
		(void)send_error_response(socket_fd, request, FAMEM_STATUS_PROTOCOL, "invalid lease epoch");
		return -1;
	}
	return 0;
}

/* SLEEP: free the physical extents; the lease stays and the client keeps the epoch. */
static int handle_sleep(int socket_fd, const struct request_frame *request, struct server_state *server,
												struct lease *lease)
{
	uint8_t payload[FAMEM_EPOCH_RESPONSE_SIZE];
	if (validate_epoch_request(socket_fd, request, lease) != 0) {
		return 0;
	}
	if (!lease->active || server->active_lease != lease) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_PROTOCOL, "the arena is already sleeping");
	}
	lease->active = false;
	server->active_lease = NULL;
	store_u64(payload, lease->epoch);
	return send_response(socket_fd, request->operation, request->request_id, FAMEM_STATUS_OK, payload, sizeof(payload));
}

/* WAKE: re-allocate the same extent plan, bump the epoch, re-authorize, reply with mapping. */
static int handle_wake(int socket_fd, const struct request_frame *request, struct server_state *server,
											 struct lease *lease)
{
	if (validate_epoch_request(socket_fd, request, lease) != 0) {
		return 0;
	}
	if (lease->active) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_PROTOCOL, "the arena is not sleeping");
	}
	if (server->poisoned) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_INTERNAL, "server pool authorization is uncertain");
	}
	if (server->active_lease != NULL && server->active_lease != lease) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_BUSY, "another Famem lease is active");
	}
	if (activate_lease(server, lease) != 0) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_INTERNAL,
															 server->poisoned ? "Famem pool is poisoned; restart the server"
																								: "failed to authorize the Famem pool");
	}
	return send_mapping_response(socket_fd, request, server, lease);
}

/* RELEASE: free extents if still active and destroy the lease. */
static int handle_release(int socket_fd, const struct request_frame *request, struct server_state *server,
													struct lease *lease, bool *released)
{
	if (validate_epoch_request(socket_fd, request, lease) != 0) {
		return 0;
	}
	if (server->active_lease == lease) {
		server->active_lease = NULL;
	}
	close_lease_process_identities(lease);
	memset(lease, 0, sizeof(*lease));
	*released = true;
	return send_response(socket_fd, request->operation, request->request_id, FAMEM_STATUS_OK, NULL, 0U);
}

/* STATS: read-only pool/lease diagnostics. */
static int handle_stats(int socket_fd, const struct request_frame *request, struct server_state *server,
												const struct lease *lease)
{
	uint8_t payload[FAMEM_STATS_RESPONSE_SIZE];
	uint64_t huge_1g_bytes = 0U;
	uint64_t huge_2m_bytes = 0U;
	size_t index;
	if (request->payload_size != FAMEM_SESSION_REQUEST_SIZE) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_PROTOCOL, "invalid STATS payload size");
	}
	if (!lease->acquired) {
		return send_error_response(socket_fd, request, FAMEM_STATUS_PROTOCOL, "session has not acquired an arena");
	}
	for (index = 0; index < server->pool_extent_count; ++index) {
		if (server->pool_extents[index].page_type == FAMEM_PAGE_HUGE_1G) {
			huge_1g_bytes += server->pool_extents[index].size;
		} else if (server->pool_extents[index].page_type == FAMEM_PAGE_HUGE_2M) {
			huge_2m_bytes += server->pool_extents[index].size;
		}
	}
	store_u64(payload, server->pool_size);
	store_u64(payload + 8U, lease->epoch);
	store_u32(payload + 16U, lease->active ? 1U : 0U);
	store_u32(payload + 20U, (uint32_t)server->pool_extent_count);
	store_u64(payload + 24U, huge_1g_bytes);
	store_u64(payload + 32U, huge_2m_bytes);
	return send_response(socket_fd, request->operation, request->request_id, FAMEM_STATUS_OK, payload,
											 sizeof(payload));
}

/* True when a connected client already holds this session_id (duplicate HELLO guard). */
static bool session_exists(const struct server_state *server, const uint8_t session_id[FAMEM_SESSION_SIZE])
{
	const struct client_context *client = server->clients;
	while (client != NULL) {
		if (client->lease.session_id[0] != '\0' && memcmp(client->lease.session_id, session_id, FAMEM_SESSION_SIZE) == 0) {
			return true;
		}
		client = client->next;
	}
	return false;
}

/* One client's whole lifecycle: HELLO handshake, request loop, disconnect reclamation. */
static int handle_client(struct client_context *client)
{
	struct server_state *server = client->server;
	struct lease *lease = &client->lease;
	const int socket_fd = client->socket_fd;
	struct ucred credentials;
	socklen_t credentials_size = sizeof(credentials);
	struct timeval hello_timeout = {.tv_sec = 10, .tv_usec = 0};
	struct timeval no_timeout = {.tv_sec = 0, .tv_usec = 0};
	struct request_frame request;
	uint32_t worker_bare_tgid;
	uint32_t copier_bare_tgid;
	pid_t copier_parent;
	char error[256];
	int receive_result;
	int response_result;
	bool released = false;

	if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_size) != 0 ||
			credentials_size != sizeof(credentials)) {
		log_message(LOG_WARNING, "cannot read client credentials: %s", strerror(errno));
		return -1;
	}
	(void)setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &hello_timeout, sizeof(hello_timeout));
	receive_result = receive_request(socket_fd, &request, error, sizeof(error));
	if (receive_result <= 0) {
		if (receive_result < 0) {
			log_message(LOG_WARNING, "invalid HELLO frame: %s", error);
		}
		return -1;
	}
	if (request.operation != FAMEM_OP_HELLO || request.payload_size != FAMEM_HELLO_REQUEST_SIZE) {
		return reject_client(socket_fd, &request, FAMEM_STATUS_PROTOCOL, "the first request must be a valid HELLO");
	}
	worker_bare_tgid = load_u32(request.payload + FAMEM_UUID_SIZE + FAMEM_SESSION_SIZE);
	copier_bare_tgid = load_u32(request.payload + FAMEM_UUID_SIZE + FAMEM_SESSION_SIZE + 4U);
	log_message(LOG_INFO, "HELLO: uuid_cmp=%d, uuid_hex=%d, sess_hex=%d, pid=%d, tgid=%u, copier_tgid=%u",
							memcmp(request.payload, server->device_uuid, FAMEM_UUID_SIZE),
							is_lower_hex(request.payload, FAMEM_UUID_SIZE) ? 1 : 0,
							is_lower_hex(request.payload + FAMEM_UUID_SIZE, FAMEM_SESSION_SIZE) ? 1 : 0,
							credentials.pid, worker_bare_tgid, copier_bare_tgid);
	if ((!g_skip_tgid_check && memcmp(request.payload, server->device_uuid, FAMEM_UUID_SIZE) != 0) ||
			!is_lower_hex(request.payload, FAMEM_UUID_SIZE) ||
			!is_lower_hex(request.payload + FAMEM_UUID_SIZE, FAMEM_SESSION_SIZE) ||
			copier_bare_tgid == 0U || copier_bare_tgid > INT32_MAX ||
			copier_bare_tgid == worker_bare_tgid) {
		log_message(LOG_WARNING, "HELLO rejected: uuid_match=%d, uuid_hex=%d, sess_hex=%d, pid=%d, tgid=%u, copier_tgid=%u, skip_tgid=%d",
								memcmp(request.payload, server->device_uuid, FAMEM_UUID_SIZE) == 0 ? 1 : 0,
								is_lower_hex(request.payload, FAMEM_UUID_SIZE) ? 1 : 0,
								is_lower_hex(request.payload + FAMEM_UUID_SIZE, FAMEM_SESSION_SIZE) ? 1 : 0,
								credentials.pid, worker_bare_tgid, copier_bare_tgid, g_skip_tgid_check);
		return reject_client(socket_fd, &request, FAMEM_STATUS_PROTOCOL, "invalid Famem HELLO identity");
	}
	pthread_mutex_lock(&server->mutex);
	if (server->poisoned) {
		pthread_mutex_unlock(&server->mutex);
		return reject_client(socket_fd, &request, FAMEM_STATUS_INTERNAL,
												 "the Famem server has uncertain authorization state and must restart");
	}
	if (session_exists(server, request.payload + FAMEM_UUID_SIZE)) {
		pthread_mutex_unlock(&server->mutex);
		return reject_client(socket_fd, &request, FAMEM_STATUS_BUSY, "this Famem session is already connected");
	}

	memset(lease, 0, sizeof(*lease));
	memcpy(lease->session_id, request.payload + FAMEM_UUID_SIZE, FAMEM_SESSION_SIZE);
	lease->session_id[FAMEM_SESSION_SIZE] = '\0';
	capture_process_identity(&lease->worker_process, credentials.pid, NULL);
	capture_process_identity(&lease->copier_process, (pid_t)copier_bare_tgid, &copier_parent);
	lease->bare_tgid = (int32_t)worker_bare_tgid;
	lease->copier_bare_tgid = (int32_t)copier_bare_tgid;
	pthread_mutex_unlock(&server->mutex);
	if (send_response(socket_fd, request.operation, request.request_id, FAMEM_STATUS_OK,
										(const uint8_t *)server->device_uuid, FAMEM_UUID_SIZE) != 0) {
		goto disconnect;
	}
	(void)setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &no_timeout, sizeof(no_timeout));

	while (!g_stop && !released) {
		receive_result = receive_request(socket_fd, &request, error, sizeof(error));
		if (receive_result == 0) {
			break;
		}
		if (receive_result < 0) {
			log_message(LOG_WARNING, "invalid request frame: %s", error);
			if (receive_result == -2 && request.request_id != 0U && request.operation >= FAMEM_OP_HELLO &&
					request.operation <= FAMEM_OP_STATS) {
				(void)send_error_response(socket_fd, &request, FAMEM_STATUS_PROTOCOL, error);
			}
			break;
		}
		pthread_mutex_lock(&server->mutex);
		if (lease->session_id[0] == '\0' || request.payload_size < FAMEM_SESSION_SIZE ||
				memcmp(request.payload, lease->session_id, FAMEM_SESSION_SIZE) != 0) {
			(void)send_error_response(socket_fd, &request, FAMEM_STATUS_PROTOCOL,
																"the request session does not belong to this connection");
			pthread_mutex_unlock(&server->mutex);
			continue;
		}
		switch (request.operation) {
		case FAMEM_OP_ACQUIRE:
			response_result = handle_acquire(socket_fd, &request, server, lease);
			break;
		case FAMEM_OP_SLEEP:
			response_result = handle_sleep(socket_fd, &request, server, lease);
			break;
		case FAMEM_OP_WAKE:
			response_result = handle_wake(socket_fd, &request, server, lease);
			break;
		case FAMEM_OP_RELEASE:
			response_result = handle_release(socket_fd, &request, server, lease, &released);
			break;
		case FAMEM_OP_STATS:
			response_result = handle_stats(socket_fd, &request, server, lease);
			break;
		case FAMEM_OP_HELLO:
		default:
			response_result =
					send_error_response(socket_fd, &request, FAMEM_STATUS_PROTOCOL, "HELLO is only valid as the first request");
			break;
		}
		pthread_mutex_unlock(&server->mutex);
		if (response_result != 0) {
			goto disconnect;
		}
	}

disconnect:
	pthread_mutex_lock(&server->mutex);
	if (lease->session_id[0] != '\0') {
		if (lease->active) {
			log_message(LOG_WARNING, "client disconnected with mapped HBM; waiting for Worker PID %ld and Copier PID %ld",
								(long)lease->worker_process.pid, (long)lease->copier_process.pid);
			pthread_mutex_unlock(&server->mutex);
			if (!g_skip_tgid_check) {
			wait_for_process_exit(&lease->worker_process);
			}
			wait_for_process_exit(&lease->copier_process);
			pthread_mutex_lock(&server->mutex);
		}
		if (server->active_lease == lease) {
			server->active_lease = NULL;
		}
		lease->active = false;
		close_lease_process_identities(lease);
		memset(lease, 0, sizeof(*lease));
	}
	pthread_mutex_unlock(&server->mutex);
	return 0;
}

/* Per-connection thread entry: run handle_client, then flag the context finished. */
static void *client_thread_main(void *argument)
{
	struct client_context *client = (struct client_context *)argument;
	(void)handle_client(client);
	close(client->socket_fd);
	pthread_mutex_lock(&client->server->mutex);
	client->socket_fd = -1;
	client->thread_finished = true;
	pthread_mutex_unlock(&client->server->mutex);
	return NULL;
}

/* Join finished client threads and unlink their contexts from the list. */
static void reap_finished_clients(struct server_state *server)
{
	while (true) {
		struct client_context **link;
		struct client_context *client = NULL;
		pthread_mutex_lock(&server->mutex);
		link = &server->clients;
		while (*link != NULL) {
			if ((*link)->thread_finished && (*link)->lease.session_id[0] == '\0') {
			client = *link;
			*link = client->next;
			break;
			}
			link = &(*link)->next;
		}
		pthread_mutex_unlock(&server->mutex);
		if (client == NULL) {
			return;
		}
		(void)pthread_join(client->thread, NULL);
		free(client);
	}
}

/* On shutdown: shutdown() every socket, join threads, reclaim still-active leases. */
static void shutdown_clients(struct server_state *server)
{
	struct client_context *client;
	pthread_mutex_lock(&server->mutex);
	for (client = server->clients; client != NULL; client = client->next) {
		if (client->socket_fd >= 0) {
			(void)shutdown(client->socket_fd, SHUT_RDWR);
		}
	}
	pthread_mutex_unlock(&server->mutex);

	while (true) {
		pthread_mutex_lock(&server->mutex);
		client = server->clients;
		if (client != NULL) {
			server->clients = client->next;
		}
		pthread_mutex_unlock(&server->mutex);
		if (client == NULL) {
			break;
		}
		(void)pthread_join(client->thread, NULL);
		close_lease_process_identities(&client->lease);
		free(client);
	}
}

/* mkdir -p the socket directory with 0750, validating each created component. */
static int make_directories(const char *directory)
{
	char path[PATH_MAX];
	size_t length;
	size_t index;
	struct stat directory_stat;
	length = strlen(directory);
	if (length >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(path, directory, length + 1U);
	while (length > 1U && path[length - 1U] == '/') {
		path[--length] = '\0';
	}
	for (index = 1U; index < length; ++index) {
		if (path[index] != '/') {
			continue;
		}
		path[index] = '\0';
		if (mkdir(path, 0750) != 0 && errno != EEXIST) {
			return -1;
		}
		path[index] = '/';
	}
	if (mkdir(path, 0750) != 0 && errno != EEXIST) {
		return -1;
	}
	if (stat(path, &directory_stat) != 0 || !S_ISDIR(directory_stat.st_mode)) {
		errno = ENOTDIR;
		return -1;
	}
	if (directory_stat.st_uid != getuid() || (directory_stat.st_mode & S_IWOTH) != 0U) {
		errno = EACCES;
		return -1;
	}
	return 0;
}

/* Unlink a dead socket (ECONNREFUSED probe); a live one aborts startup. */
static int remove_stale_socket(const char *socket_path)
{
	struct stat socket_stat;
	struct stat current_socket_stat;
	struct sockaddr_un address;
	int probe_fd;
	int connect_error;
	if (lstat(socket_path, &socket_stat) != 0) {
		return errno == ENOENT ? 0 : -1;
	}
	if (!S_ISSOCK(socket_stat.st_mode) || socket_stat.st_uid != getuid()) {
		errno = EACCES;
		return -1;
	}
	probe_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (probe_fd < 0) {
		return -1;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, socket_path, strlen(socket_path) + 1U);
	if (connect(probe_fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
		close(probe_fd);
		errno = EADDRINUSE;
		return -1;
	}
	connect_error = errno;
	close(probe_fd);
	if (connect_error == ENOENT) {
		return 0;
	}
	if (connect_error != ECONNREFUSED) {
		errno = connect_error;
		return -1;
	}
	if (lstat(socket_path, &current_socket_stat) != 0 || !S_ISSOCK(current_socket_stat.st_mode) ||
			current_socket_stat.st_dev != socket_stat.st_dev || current_socket_stat.st_ino != socket_stat.st_ino) {
		errno = ESTALE;
		return -1;
	}
	return unlink(socket_path) == 0 || errno == ENOENT ? 0 : -1;
}

/* Unlink our socket at exit only if (dev,ino) still matches what we bound. */
static int unlink_owned_socket(const char *socket_path, const struct stat *bound_socket_stat)
{
	struct stat current_socket_stat;
	if (lstat(socket_path, &current_socket_stat) != 0) {
		return errno == ENOENT ? 0 : -1;
	}
	if (!S_ISSOCK(current_socket_stat.st_mode) || current_socket_stat.st_dev != bound_socket_stat->st_dev ||
			current_socket_stat.st_ino != bound_socket_stat->st_ino) {
		errno = ESTALE;
		return -1;
	}
	return unlink(socket_path);
}

/* Listener cleanup path shared between fatal startup errors. */
static int discard_listener(int listener_fd, const char *socket_path, const struct stat *bound_socket_stat,
													int saved_errno)
{
	close(listener_fd);
	if (bound_socket_stat != NULL) {
		(void)unlink_owned_socket(socket_path, bound_socket_stat);
	}
	errno = saved_errno;
	return -1;
}

/* bind()+listen() the server socket, chmod 0600, record (dev,ino) identity. */
static int create_listener(const char *socket_path, struct stat *bound_socket_stat)
{
	struct sockaddr_un address;
	const size_t path_length = strlen(socket_path);
	int listener_fd;
	listener_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener_fd < 0) {
		return -1;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, socket_path, path_length + 1U);
	if (bind(listener_fd, (struct sockaddr *)&address,
				 offsetof(struct sockaddr_un, sun_path) + path_length + 1U) != 0) {
		return discard_listener(listener_fd, socket_path, NULL, errno);
	}
	if (lstat(socket_path, bound_socket_stat) != 0) {
		return discard_listener(listener_fd, socket_path, NULL, errno);
	}
	if (!S_ISSOCK(bound_socket_stat->st_mode) || bound_socket_stat->st_uid != getuid()) {
		return discard_listener(listener_fd, socket_path, NULL, EACCES);
	}
	if (chmod(socket_path, 0600) != 0 || listen(listener_fd, 8) != 0) {
		return discard_listener(listener_fd, socket_path, bound_socket_stat, errno);
	}
	return listener_fd;
}

/* Print the --help text. */
static void print_usage(FILE *output, const char *program)
{
	fprintf(output,
				"Usage: %s --device DEVICE [--size-gib GIB | --size-bytes BYTES] [--socket-dir DIR] [--socket-name NAME] [--skip-tgid-check] [--log-level LEVEL]\n"
				"Serve Famem physical HBM for one Ascend NPU.\n",
				program);
}

/* Map --log-level names to the enum. */
static int parse_log_level(const char *value, enum log_level *output)
{
	static const char *const names[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
	size_t index;
	for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
		if (strcmp(value, names[index]) == 0) {
			*output = (enum log_level)index;
			return 0;
		}
	}
	return -1;
}

/* Parse --device as a non-negative integer. */
static int parse_device(const char *value, int *output)
{
	char *end = NULL;
	long device;
	errno = 0;
	device = strtol(value, &end, 10);
	if (errno != 0 || end == value || *end != '\0' || device < 0 || device > INT_MAX) {
		return -1;
	}
	*output = (int)device;
	return 0;
}

/* Parse --pool-size in GiB (0 = defer to first ACQUIRE). */
static int parse_pool_size(const char *value, uint64_t *output)
{
	char *end = NULL;
	unsigned long long size_gib;
	errno = 0;
	size_gib = strtoull(value, &end, 10);
	if (errno != 0 || end == value || *end != '\0' || size_gib == 0U || size_gib > FAMEM_MAX_POOL_GIB) {
		return -1;
	}
	*output = (uint64_t)size_gib * FAMEM_HUGE_1G_BYTES;
	return 0;
}

/* Entry point: parse flags, bind the socket, serve until SIGTERM, reclaim everything. */
int main(int argc, char **argv)
{
	static const struct option options[] = {
			{"device", required_argument, NULL, 'd'},
			{"size-gib", required_argument, NULL, 'm'},
			{"size-bytes", required_argument, NULL, 'b'},
			{"socket-dir", required_argument, NULL, 's'},
			{"socket-name", required_argument, NULL, 'n'},
			{"skip-tgid-check", no_argument, NULL, 'k'},
			{"log-level", required_argument, NULL, 'l'},
			{"help", no_argument, NULL, 'h'},
			{NULL, 0, NULL, 0},
	};
	const char *socket_dir = NULL;
	const char *socket_name = NULL;
	char socket_path[PATH_MAX] = {0};
	struct sigaction action;
	struct stat bound_socket_stat;
	struct server_state server;
	int device = -1;
	int listener_fd = -1;
	int socket_dir_fd = -1;
	uint64_t pool_size = 0U;
	int option;
	int exit_code = EXIT_FAILURE;
	while ((option = getopt_long(argc, argv, "d:m:b:s:n:kl:h", options, NULL)) != -1) {
		switch (option) {
		case 'd':
			if (parse_device(optarg, &device) != 0) {
				fprintf(stderr, "Invalid --device value: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'm':
			if (parse_pool_size(optarg, &pool_size) != 0) {
				fprintf(stderr, "Invalid --size-gib value: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'b': {
			char *end = NULL;
			errno = 0;
			pool_size = strtoull(optarg, &end, 10);
			if (errno != 0 || end == optarg || *end != '\0' || pool_size == 0U) {
				fprintf(stderr, "Invalid --size-bytes value: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
			}
		case 's':
			socket_dir = optarg;
			break;
		case 'n':
			socket_name = optarg;
			break;
		case 'k':
			/* --skip-tgid-check: skip PID/TGID verification (needed in containers
				 where the PID namespace differs from the host) */
			g_skip_tgid_check = 1;
			break;
		case 'l':
			if (parse_log_level(optarg, &g_log_level) != 0) {
				fprintf(stderr, "Invalid --log-level value: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'h':
			print_usage(stdout, argv[0]);
			return EXIT_SUCCESS;
		default:
			print_usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (device < 0 || optind != argc) {
		print_usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
	prctl(PR_SET_NAME, "hbm_server", 0, 0, 0);
	/* Pool size will be determined by the first ACQUIRE request when not
		 explicitly set via --size-gib / --size-bytes.  This allows a single
		 server binary to serve models with different per-NPU arena sizes
		 (e.g. 27 GiB for TP1-7B, 54 GiB for TP4-72B) without changing the
		 launch command. */
	server.pool_size = pool_size;  /* 0 means "defer to first ACQUIRE" */
	if (socket_dir == NULL) {
		socket_dir = getenv("VLLM_ASCEND_FAMEM_SOCKET_DIR");
	}
	if (socket_dir == NULL || socket_dir[0] == '\0') {
		socket_dir = FAMEM_DEFAULT_SOCKET_DIR;
	}
	memset(&action, 0, sizeof(action));
	action.sa_handler = stop_server;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGINT, &action, NULL) != 0) {
		log_message(LOG_ERROR, "cannot install signal handlers: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	signal(SIGPIPE, SIG_IGN);
	if (famem_server_initialize(device) != 0) {
		log_message(LOG_ERROR, "cannot initialize Famem backend: %s", native_error());
		return EXIT_FAILURE;
	}
	memset(&server, 0, sizeof(server));
	server.device = device;
	if (famem_get_device_uuid(device, server.device_uuid, sizeof(server.device_uuid)) != 0 ||
			!is_lower_hex((const uint8_t *)server.device_uuid, FAMEM_UUID_SIZE) ||
			is_all_zero((const uint8_t *)server.device_uuid, FAMEM_UUID_SIZE)) {
		/* Some NPU models (e.g. Ascend 910B3) do not provide a valid UUID via
			 aclrtDeviceGetUuid (returns ACL_ERROR_RT_DEVICE_UNAVAILABLE or an
			 all-zero UUID).  In that case, synthesize a deterministic UUID from
			 the device index so that the server can still operate. */
		log_message(LOG_WARNING,
							"NPU UUID not available (device %d), synthesizing from device index",
							device);
		option = snprintf(server.device_uuid, sizeof(server.device_uuid),
										"d%031d", device);
		if (option < 0 || (size_t)option != FAMEM_UUID_SIZE) {
			log_message(LOG_ERROR, "cannot synthesize device UUID");
			goto cleanup_backend;
		}
	}
	server.device_uuid[FAMEM_UUID_SIZE] = '\0';
	if (pthread_mutex_init(&server.mutex, NULL) != 0) {
		log_message(LOG_ERROR, "cannot initialize Famem server mutex");
		goto cleanup_backend;
	}
	if (make_directories(socket_dir) != 0) {
		log_message(LOG_ERROR, "cannot prepare socket directory %s: %s", socket_dir, strerror(errno));
		goto cleanup_mutex;
	}
	socket_dir_fd = open(socket_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (socket_dir_fd < 0 || flock(socket_dir_fd, LOCK_EX) != 0) {
		log_message(LOG_ERROR, "cannot lock Famem socket directory %s: %s", socket_dir, strerror(errno));
		goto cleanup_mutex;
	}
	/* Build socket path: use --socket-name if provided, otherwise device_uuid */
	if (socket_name != NULL) {
		option = snprintf(socket_path, sizeof(socket_path), "%s/%s.sock", socket_dir, socket_name);
	} else {
		option = snprintf(socket_path, sizeof(socket_path), "%s/%s.sock", socket_dir, server.device_uuid);
	}
	if (option < 0 || (size_t)option >= sizeof(socket_path) || (size_t)option > FAMEM_SOCKET_PATH_MAX) {
		errno = ENAMETOOLONG;
		log_message(LOG_ERROR, "Famem socket path is too long");
		goto cleanup_pool;
	}
	if (remove_stale_socket(socket_path) != 0) {
		log_message(LOG_ERROR, "cannot prepare Famem socket %s: %s", socket_path, strerror(errno));
		goto cleanup_pool;
	}
	if (pool_size != 0U && initialize_pool(&server, pool_size) != 0) {
		goto cleanup_pool;
	}
	if (pool_size == 0U) {
		log_message(LOG_INFO, "pool size not specified; will be determined by the first ACQUIRE request");
	}
	listener_fd = create_listener(socket_path, &bound_socket_stat);
	option = errno;
	/* When --socket-name overrides the socket filename, create a UUID-named
		 hard link so that clients using famem_get_device_uuid() can find the socket.
		 A hard link (not symlink) is required because the client checks S_ISSOCK
		 with follow_symlinks=False, and only a hard link preserves the socket mode. */
	if (socket_name != NULL) {
		char uuid_sock[PATH_MAX];
		option = snprintf(uuid_sock, sizeof(uuid_sock), "%s/%s.sock", socket_dir, server.device_uuid);
		if (option > 0 && (size_t)option < sizeof(uuid_sock)) {
			(void)unlink(uuid_sock);
			if (link(socket_path, uuid_sock) != 0) {
			log_message(LOG_WARNING, "cannot create UUID hardlink %s: %s", uuid_sock, strerror(errno));
			}
		}
	}
	close(socket_dir_fd);
	socket_dir_fd = -1;
	errno = option;
	if (listener_fd < 0) {
		log_message(LOG_ERROR, "cannot create Famem listener: %s", strerror(errno));
		goto cleanup_pool;
	}
	log_message(LOG_INFO, "pool ready; listening on %s for NPU UUID %s", socket_path, server.device_uuid);

	while (!g_stop) {
		struct client_context *client;
		int client_fd = accept(listener_fd, NULL, NULL);
		if (client_fd < 0) {
			if (errno == EINTR) {
			continue;
			}
			log_message(LOG_ERROR, "accept failed: %s", strerror(errno));
			goto cleanup;
		}
		client = (struct client_context *)calloc(1U, sizeof(*client));
		if (client == NULL) {
			log_message(LOG_ERROR, "cannot allocate Famem client context");
			close(client_fd);
			continue;
		}
		client->socket_fd = client_fd;
		client->server = &server;
		pthread_mutex_lock(&server.mutex);
		client->next = server.clients;
		server.clients = client;
		pthread_mutex_unlock(&server.mutex);
		if (pthread_create(&client->thread, NULL, client_thread_main, client) != 0) {
			pthread_mutex_lock(&server.mutex);
			server.clients = client->next;
			pthread_mutex_unlock(&server.mutex);
			log_message(LOG_ERROR, "cannot start Famem client thread");
			close(client_fd);
			free(client);
			continue;
		}
		reap_finished_clients(&server);
	}
	exit_code = EXIT_SUCCESS;

cleanup:
	close(listener_fd);
	shutdown_clients(&server);
	if (unlink_owned_socket(socket_path, &bound_socket_stat) != 0 && errno != ENOENT) {
		log_message(LOG_WARNING, "cannot remove owned socket %s: %s", socket_path, strerror(errno));
	}
cleanup_pool:
	if (free_extents(server.pool_extents, server.pool_extent_count) != 0) {
		log_message(LOG_ERROR, "cannot release every persistent pool extent");
		exit_code = EXIT_FAILURE;
	}
cleanup_mutex:
	if (socket_dir_fd >= 0) {
		close(socket_dir_fd);
	}
	(void)pthread_mutex_destroy(&server.mutex);
cleanup_backend:
	if (famem_server_finalize() != 0) {
		log_message(LOG_ERROR, "cannot finalize Famem backend: %s", native_error());
		exit_code = EXIT_FAILURE;
	}
	return exit_code;
}
