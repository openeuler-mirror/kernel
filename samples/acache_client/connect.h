#ifndef ACACHE_CONNENECT_H
#define ACACHE_CONNENECT_H
#include <stdint.h>

#define ACACHE_MAGIC 2
enum acache_conn_types {
	ACACHE_NO_CONN = 0,
	ACACHE_RINGBUFFER_CONN,
	ACACHE_READWRITE_CONN,
};
#define acache_path "/dev/acache"

struct acache_info {
	uint64_t length;
	uint64_t offset;
	uint64_t start_time;
	uint32_t dev;
	int opcode;
};

struct connection;
struct connection_operations {

	/*
	 * initialize connnection
	 * parameters: none
	 * return values:
	 *  - void *: private data for connection
	 */
	void *(*initialize)(struct connection *self);
	/*
	 * send_items send items to peer side
	 * parameters:
	 *  - infos: data to send
	 *  - count: data length
	 * return values:
	 *  - number of sent items
	 */
	int (*send_items)(struct connection *self, struct acache_info *infos,
			   size_t count);
	/*
	 * send_items recieve items from peer side
	 * paremeters:
	 *  - infos: buffer to place recieved items
	 *  - count: length of buffer
	 * return values:
	 *  - number of recieved items
	 */
	int (*fetch_items)(struct connection *self, struct acache_info *infos,
			    size_t count);
	/*
	 * close closes the connection
	 */
	int (*close)(struct connection *self);

	/*
	 * get_capacity return the capacity of items that can send and revice at once
	 */
	int (*get_capacity)(struct connection *self);

};

struct connection {
	/*
	 * private data for specific connnetion
	 */
	void *private;
	struct connection_operations ops;
};

struct connection *initialize_conn_rw(void);

#endif

