/*
 * Copyright (C) 2011-2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __LIBHOMEBUS_H
#define __LIBHOMEBUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libubox/avl.h>
#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <stdint.h>
#include "homebusmsg.h"
#include "homebus_common.h"

#define HOMEBUS_MAX_NOTIFY_PEERS	16

struct homebus_context;
struct homebus_msg_src;
struct homebus_object;
struct homebus_request;
struct homebus_request_data;
struct homebus_object_data;
struct homebus_event_handler;
struct homebus_subscriber;
struct homebus_notify_request;

struct homebus_msghdr_buf {
	struct homebus_msghdr hdr;
	struct blob_attr *data;
};

typedef void (*homebus_lookup_handler_t)(struct homebus_context *ctx,
				      struct homebus_object_data *obj,
				      void *priv);
typedef int (*homebus_handler_t)(struct homebus_context *ctx, struct homebus_object *obj,
			      struct homebus_request_data *req,
			      const char *method, struct blob_attr *msg);
typedef void (*homebus_state_handler_t)(struct homebus_context *ctx, struct homebus_object *obj);
typedef void (*homebus_remove_handler_t)(struct homebus_context *ctx,
				      struct homebus_subscriber *obj, uint32_t id);
typedef void (*homebus_event_handler_t)(struct homebus_context *ctx, struct homebus_event_handler *ev,
				     const char *type, struct blob_attr *msg);
typedef void (*homebus_data_handler_t)(struct homebus_request *req,
				    int type, struct blob_attr *msg);
typedef void (*homebus_fd_handler_t)(struct homebus_request *req, int fd);
typedef void (*homebus_complete_handler_t)(struct homebus_request *req, int ret);
typedef void (*homebus_notify_complete_handler_t)(struct homebus_notify_request *req,
					       int idx, int ret);
typedef void (*homebus_notify_data_handler_t)(struct homebus_notify_request *req,
					   int type, struct blob_attr *msg);
typedef void (*homebus_connect_handler_t)(struct homebus_context *ctx);
typedef bool (*homebus_new_object_handler_t)(struct homebus_context *ctx, struct homebus_subscriber *sub, const char *path);

#define HOMEBUS_OBJECT_TYPE(_name, _methods)		\
	{						\
		.name = _name,				\
		.id = 0,				\
		.n_methods = ARRAY_SIZE(_methods),	\
		.methods = _methods			\
	}

#define __HOMEBUS_METHOD_NOARG(_name, _handler, _tags)	\
	.name = _name,					\
	.handler = _handler,				\
	.tags = _tags

#define __HOMEBUS_METHOD(_name, _handler, _policy, _tags)	\
	__HOMEBUS_METHOD_NOARG(_name, _handler, _tags),	\
	.policy = _policy,				\
	.n_policy = ARRAY_SIZE(_policy)

#define HOMEBUS_METHOD(_name, _handler, _policy)		\
	{ __HOMEBUS_METHOD(_name, _handler, _policy, 0) }

#define HOMEBUS_METHOD_TAG(_name, _handler, _policy, _tags)\
	{ __HOMEBUS_METHOD(_name, _handler, _policy, _tags) }

#define HOMEBUS_METHOD_MASK(_name, _handler, _policy, _mask) \
	{						\
		__HOMEBUS_METHOD(_name, _handler, _policy, 0),\
		.mask = _mask				\
	}

#define HOMEBUS_METHOD_NOARG(_name, _handler)		\
	{ __HOMEBUS_METHOD_NOARG(_name, _handler, 0) }

#define HOMEBUS_METHOD_TAG_NOARG(_name, _handler, _tags)	\
	{ __HOMEBUS_METHOD_NOARG(_name, _handler, _tags) }

#define HOMEBUS_TAG_STATUS		BIT(0)
#define HOMEBUS_TAG_ADMIN		BIT(1)
#define HOMEBUS_TAG_PRIVATE	BIT(2)

struct homebus_method {
	const char *name;
	homebus_handler_t handler;

	unsigned long mask;
	unsigned long tags;
	const struct blobmsg_policy *policy;
	int n_policy;
};

struct homebus_object_type {
	const char *name;
	uint32_t id;

	const struct homebus_method *methods;
	int n_methods;
};

struct homebus_object {
	struct avl_node avl;

	const char *name;
	uint32_t id;

	const char *path;
	struct homebus_object_type *type;

	homebus_state_handler_t subscribe_cb;
	bool has_subscribers;

	const struct homebus_method *methods;
	int n_methods;
};

struct homebus_subscriber {
	struct list_head list;
	struct homebus_object obj;

	homebus_handler_t cb;
	homebus_remove_handler_t remove_cb;
	homebus_new_object_handler_t new_obj_cb;
};

struct homebus_event_handler {
	struct homebus_object obj;

	homebus_event_handler_t cb;
};

struct homebus_context {
	struct list_head requests;
	struct avl_tree objects;
	struct list_head pending;

	struct uloop_fd sock;
	struct uloop_timeout pending_timer;

	uint32_t local_id;
	uint16_t request_seq;
	bool cancel_poll;
	int stack_depth;

	void (*connection_lost)(struct homebus_context *ctx);
	void (*monitor_cb)(struct homebus_context *ctx, uint32_t seq, struct blob_attr *data);

	struct homebus_msghdr_buf msgbuf;
	uint32_t msgbuf_data_len;
	int msgbuf_reduction_counter;

	struct list_head auto_subscribers;
	struct homebus_event_handler auto_subscribe_event_handler;
};

struct homebus_object_data {
	uint32_t id;
	uint32_t type_id;
	const char *path;
	struct blob_attr *signature;
};

struct homebus_acl_key {
	const char *user;
	const char *group;
	const char *object;
};

struct homebus_request_data {
	uint32_t object;
	uint32_t peer;
	uint16_t seq;

	struct homebus_acl_key acl;

	/* internal use */
	bool deferred;
	int fd;
	int req_fd; /* fd received from the initial request */
};

struct homebus_request {
	struct list_head list;

	struct list_head pending;
	int status_code;
	bool status_msg;
	bool blocked;
	bool cancelled;
	bool notify;

	uint32_t peer;
	uint16_t seq;

	homebus_data_handler_t raw_data_cb;
	homebus_data_handler_t data_cb;
	homebus_fd_handler_t fd_cb;
	homebus_complete_handler_t complete_cb;

	int fd;

	struct homebus_context *ctx;
	void *priv;
};

struct homebus_notify_request {
	struct homebus_request req;

	homebus_notify_complete_handler_t status_cb;
	homebus_notify_complete_handler_t complete_cb;
	homebus_notify_data_handler_t data_cb;

	uint32_t pending;
	uint32_t id[HOMEBUS_MAX_NOTIFY_PEERS + 1];
};

struct homebus_auto_conn {
	struct homebus_context ctx;
	struct uloop_timeout timer;
	const char *path;
	homebus_connect_handler_t cb;
};

struct homebus_context *homebus_connect(const char *path);
int homebus_connect_ctx(struct homebus_context *ctx, const char *path);
void homebus_auto_connect(struct homebus_auto_conn *conn);
int homebus_reconnect(struct homebus_context *ctx, const char *path);

/* call this only for struct homebus_context pointers returned by homebus_connect() */
void homebus_free(struct homebus_context *ctx);

/* call this only for struct homebus_context pointers initialised by homebus_connect_ctx() */
void homebus_shutdown(struct homebus_context *ctx);

static inline void homebus_auto_shutdown(struct homebus_auto_conn *conn)
{
	uloop_timeout_cancel(&conn->timer);
	homebus_shutdown(&conn->ctx);
}

const char *homebus_strerror(int error);

static inline void homebus_add_uloop(struct homebus_context *ctx)
{
	uloop_fd_add(&ctx->sock, ULOOP_BLOCKING | ULOOP_READ);
}

/* call this for read events on ctx->sock.fd when not using uloop */
static inline void homebus_handle_event(struct homebus_context *ctx)
{
	ctx->sock.cb(&ctx->sock, ULOOP_READ);
}

/* ----------- raw request handling ----------- */

/* wait for a request to complete and return its status */
int homebus_complete_request(struct homebus_context *ctx, struct homebus_request *req,
			  int timeout);

/* complete a request asynchronously */
void homebus_complete_request_async(struct homebus_context *ctx,
				 struct homebus_request *req);

/* abort an asynchronous request */
void homebus_abort_request(struct homebus_context *ctx, struct homebus_request *req);

/* ----------- objects ----------- */

int homebus_lookup(struct homebus_context *ctx, const char *path,
		homebus_lookup_handler_t cb, void *priv);

int homebus_lookup_id(struct homebus_context *ctx, const char *path, uint32_t *id);

/* make an object visible to remote connections */
int homebus_add_object(struct homebus_context *ctx, struct homebus_object *obj);

/* remove the object from the homebus connection */
int homebus_remove_object(struct homebus_context *ctx, struct homebus_object *obj);

/* add a subscriber notifications from another object */
int homebus_register_subscriber(struct homebus_context *ctx, struct homebus_subscriber *obj);

static inline int
homebus_unregister_subscriber(struct homebus_context *ctx, struct homebus_subscriber *obj)
{
	if (!list_empty(&obj->list))
		list_del_init(&obj->list);
	return homebus_remove_object(ctx, &obj->obj);
}

int homebus_subscribe(struct homebus_context *ctx, struct homebus_subscriber *obj, uint32_t id);
int homebus_unsubscribe(struct homebus_context *ctx, struct homebus_subscriber *obj, uint32_t id);

int __homebus_monitor(struct homebus_context *ctx, const char *type);

static inline int homebus_monitor_start(struct homebus_context *ctx)
{
	return __homebus_monitor(ctx, "add");
}

static inline int homebus_monitor_stop(struct homebus_context *ctx)
{
	return __homebus_monitor(ctx, "remove");
}


/* ----------- acl ----------- */

struct acl_object {
	struct homebus_acl_key key;
	struct avl_node avl;
	struct blob_attr *acl;
};

extern struct avl_tree acl_objects;
int homebus_register_acl(struct homebus_context *ctx);

#define acl_for_each(o, m) \
	if ((m)->object && (m)->user && (m)->group) \
		avl_for_element_range(avl_find_ge_element(&acl_objects, m, o, avl), avl_find_le_element(&acl_objects, m, o, avl), o, avl)

/* ----------- rpc ----------- */

/* invoke a method on a specific object */
int homebus_invoke_fd(struct homebus_context *ctx, uint32_t obj, const char *method,
		struct blob_attr *msg, homebus_data_handler_t cb, void *priv,
		int timeout, int fd);
static inline int
homebus_invoke(struct homebus_context *ctx, uint32_t obj, const char *method,
	    struct blob_attr *msg, homebus_data_handler_t cb, void *priv,
	    int timeout)
{
	return homebus_invoke_fd(ctx, obj, method, msg, cb, priv, timeout, -1);
}

/* asynchronous version of homebus_invoke() */
int homebus_invoke_async_fd(struct homebus_context *ctx, uint32_t obj, const char *method,
		      struct blob_attr *msg, struct homebus_request *req, int fd);
static inline int
homebus_invoke_async(struct homebus_context *ctx, uint32_t obj, const char *method,
		  struct blob_attr *msg, struct homebus_request *req)
{
	return homebus_invoke_async_fd(ctx, obj, method, msg, req, -1);
}

/* send a reply to an incoming object method call */
int homebus_send_reply(struct homebus_context *ctx, struct homebus_request_data *req,
		    struct blob_attr *msg);

static inline void homebus_defer_request(struct homebus_context *ctx,
				      struct homebus_request_data *req,
				      struct homebus_request_data *new_req)
{
    (void) ctx;
    memcpy(new_req, req, sizeof(*req));
    req->deferred = true;
}

static inline void homebus_request_set_fd(struct homebus_context *ctx,
				       struct homebus_request_data *req, int fd)
{
    (void) ctx;
    req->fd = fd;
}

static inline int homebus_request_get_caller_fd(struct homebus_request_data *req)
{
    int fd = req->req_fd;
    req->req_fd = -1;
    
    return fd;
}

void homebus_complete_deferred_request(struct homebus_context *ctx,
				    struct homebus_request_data *req, int ret);

/*
 * send a notification to all subscribers of an object
 * if timeout < 0, no reply is expected from subscribers
 */
int homebus_notify(struct homebus_context *ctx, struct homebus_object *obj,
		const char *type, struct blob_attr *msg, int timeout);

int homebus_notify_async(struct homebus_context *ctx, struct homebus_object *obj,
		      const char *type, struct blob_attr *msg,
		      struct homebus_notify_request *req);


/* ----------- events ----------- */

int homebus_send_event(struct homebus_context *ctx, const char *id,
		    struct blob_attr *data);

int homebus_register_event_handler(struct homebus_context *ctx,
				struct homebus_event_handler *ev,
				const char *pattern);

static inline int homebus_unregister_event_handler(struct homebus_context *ctx,
						struct homebus_event_handler *ev)
{
    return homebus_remove_object(ctx, &ev->obj);
}

#ifdef __cplusplus
}
#endif

#endif
