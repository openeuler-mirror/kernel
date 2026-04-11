/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore session header
 * Author: Wang Hang
 * Create: 2025-04-11
 * Note:
 * History: 2025-04-11: create file
 */

#ifndef NET_UBCORE_SESSION_H
#define NET_UBCORE_SESSION_H

#include <ub/urma/ubcore_types.h>

#define UBCORE_DEF_CONN_TIMEOUT 128
#define UBCORE_CONN_MAX_TIMEOUT 10000 /* maximum timeout 10s */

struct ubcore_session;

typedef void (*ubcore_session_callback)(struct ubcore_device *dev,
					const void *session_data);
typedef void (*ubcore_session_free_callback)(const void *session_data);

/**
 * Creates a new session, caller must release the reference using session_ref_release. This callback
 * guarantees that it will be called exactly once. If the session is not explicitly completed
 * by calling ubcore_session_complete, it will be automatically called when timeout occurs.
 * @param[in] session_data: User data associated with the session
 * @param[in] timeout: Session timeout in milliseconds, timer starts upon creation
 * @param[in] complete_cb: Callback for session completion
 * @param[in] free_cb: Callback for session_data cleanup, (if NULL, uses kfree)
 * @return: Pointer to new session with acquired reference
 */
struct ubcore_session *
ubcore_session_create(struct ubcore_device *dev, void *session_data,
		      uint32_t timeout, ubcore_session_callback complete_cb,
		      ubcore_session_free_callback free_cb);

/**
 * Finds a session by its ID, caller must release the reference using session_ref_release.
 * @param[in] session_id: Session ID to search for
 * @return: Found session pointer with acquired reference, NULL if not found
 */
struct ubcore_session *ubcore_session_find(uint32_t session_id);

/**
 * Marks a session as completed. Invokes the completion callback if the session hasn't timed out.
 * @param[in] session: Target session
 */
void ubcore_session_complete(struct ubcore_session *session);

/**
 * Blocks caller until the session completes or times out.
 * @param[in] session: Target session
 */
void ubcore_session_wait(struct ubcore_session *session);

/**
 * Acquire a reference to the session.
 * @param[in] session: Target session
 */
void ubcore_session_ref_acquire(struct ubcore_session *session);

/**
 * Releases a reference to the session.
 * @param[in] session: Target session
 */
void ubcore_session_ref_release(struct ubcore_session *session);

/**
 * Get session ID.
 * @param[in] session: Target session
 * @return" Unique session ID
 */
uint32_t ubcore_session_get_id(struct ubcore_session *session);

/**
 * Get session user data.
 * @param[in] session: Target session
 * @return: User data provided during session creation
 */
void *ubcore_session_get_data(struct ubcore_session *session);

void ubcore_session_flush(struct ubcore_device *dev);
int ubcore_session_init(void);
void ubcore_session_uninit(void);

#endif
