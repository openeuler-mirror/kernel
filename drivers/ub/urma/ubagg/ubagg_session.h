/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg session header
 * Author: Chen Chongyu
 * Create: 2026-05-13
 * Note:
 * History: 2026-05-13: create file
 */

#ifndef NET_UBAGG_SESSION_H
#define NET_UBAGG_SESSION_H

#include <ub/urma/ubcore_types.h>

#define UBAGG_DEF_CONN_TIMEOUT 16384
#define UBAGG_CONN_MAX_TIMEOUT 30000 /* maximum timeout 30s */

struct ubagg_session;
struct ubagg_device;

typedef void (*ubagg_session_callback)(struct ubagg_device *dev,
				       const void *session_data);
typedef void (*ubagg_session_free_callback)(const void *session_data);

/**
 * Creates a new session, caller must release the reference using session_ref_release. This callback
 * guarantees that it will be called exactly once. If the session is not explicitly completed
 * by calling ubagg_session_complete, it will be automatically called when timeout occurs.
 * @param[in] session_data: User data associated with the session
 * @param[in] timeout: Session timeout in milliseconds, timer starts upon creation
 * @param[in] complete_cb: Callback for session completion
 * @param[in] free_cb: Callback for session_data cleanup, (if NULL, uses kfree)
 * @return: Pointer to new session with acquired reference
 */
struct ubagg_session *ubagg_session_create(struct ubagg_device *dev,
					   void *session_data, uint32_t timeout,
					   ubagg_session_callback complete_cb,
					   ubagg_session_free_callback free_cb);

/**
 * Finds a session by its ID, caller must release the reference using session_ref_release.
 * @param[in] session_id: Session ID to search for
 * @return: Found session pointer with acquired reference, NULL if not found
 */
struct ubagg_session *ubagg_session_find(uint32_t session_id);

/**
 * Marks a session as completed. Invokes the completion callback if the session hasn't timed out.
 * @param[in] session: Target session
 */
void ubagg_session_complete(struct ubagg_session *session);

/**
 * Blocks caller until the session completes or times out.
 * @param[in] session: Target session
 */
void ubagg_session_wait(struct ubagg_session *session);

/**
 * Acquire a reference to the session.
 * @param[in] session: Target session
 */
void ubagg_session_ref_acquire(struct ubagg_session *session);

/**
 * Releases a reference to the session.
 * @param[in] session: Target session
 */
void ubagg_session_ref_release(struct ubagg_session *session);

/**
 * Get session ID.
 * @param[in] session: Target session
 * @return" Unique session ID
 */
uint32_t ubagg_session_get_id(struct ubagg_session *session);

/**
 * Get session user data.
 * @param[in] session: Target session
 * @return: User data provided during session creation
 */
void *ubagg_session_get_data(struct ubagg_session *session);

void ubagg_session_flush(struct ubagg_device *dev);
int ubagg_session_init(void);
void ubagg_session_uninit(void);

#endif
