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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include "libhomebus.h"
#include "libhomebus-internal.h"
#include "homebusmsg.h"

const char *__homebus_strerror[__HOMEBUS_STATUS_LAST] = {
	[HOMEBUS_STATUS_OK] = "Success",
	[HOMEBUS_STATUS_INVALID_COMMAND] = "Invalid command",
	[HOMEBUS_STATUS_INVALID_ARGUMENT] = "Invalid argument",
	[HOMEBUS_STATUS_METHOD_NOT_FOUND] = "Method not found",
	[HOMEBUS_STATUS_NOT_FOUND] = "Not found",
	[HOMEBUS_STATUS_NO_DATA] = "No response",
	[HOMEBUS_STATUS_PERMISSION_DENIED] = "Permission denied",
	[HOMEBUS_STATUS_TIMEOUT] = "Request timed out",
	[HOMEBUS_STATUS_NOT_SUPPORTED] = "Operation not supported",
	[HOMEBUS_STATUS_UNKNOWN_ERROR] = "Unknown error",
	[HOMEBUS_STATUS_CONNECTION_FAILED] = "Connection failed",
	[HOMEBUS_STATUS_NO_MEMORY] = "Out of memory",
	[HOMEBUS_STATUS_PARSE_ERROR] = "Parsing message data failed",
	[HOMEBUS_STATUS_SYSTEM_ERROR] = "System error",
};

struct blob_buf b __hidden = {};

struct homebus_pending_msg {
	struct list_head list;
	struct homebus_msghdr_buf hdr;
};

static int homebus_cmp_id(const void *k1, const void *k2, void *ptr)
{
	const uint32_t *id1 = k1, *id2 = k2;

	if (*id1 < *id2)
		return -1;
	else
		return *id1 > *id2;
}

const char *homebus_strerror(int error)
{
	static char err[32];

	if (error < 0 || error >= __HOMEBUS_STATUS_LAST)
		goto out;

	if (!__homebus_strerror[error])
		goto out;

	return __homebus_strerror[error];

out:
	sprintf(err, "Unknown error: %d", error);
	return err;
}

static void
homebus_queue_msg(struct homebus_context *ctx, struct homebus_msghdr_buf *buf)
{
	struct homebus_pending_msg *pending;
	void *data;

	pending = calloc_a(sizeof(*pending), &data, blob_raw_len(buf->data));

	pending->hdr.data = data;
	memcpy(&pending->hdr.hdr, &buf->hdr, sizeof(buf->hdr));
	memcpy(data, buf->data, blob_raw_len(buf->data));
	list_add_tail(&pending->list, &ctx->pending);
	if (ctx->sock.registered)
		uloop_timeout_set(&ctx->pending_timer, 1);
}

void __hidden
homebus_process_msg(struct homebus_context *ctx, struct homebus_msghdr_buf *buf, int fd)
{
	switch(buf->hdr.type) {
	case HOMEBUS_MSG_STATUS:
	case HOMEBUS_MSG_DATA:
		homebus_process_req_msg(ctx, buf, fd);
		break;

	case HOMEBUS_MSG_INVOKE:
	case HOMEBUS_MSG_UNSUBSCRIBE:
	case HOMEBUS_MSG_NOTIFY:
		if (ctx->stack_depth) {
			homebus_queue_msg(ctx, buf);
			break;
		}

		ctx->stack_depth++;
		homebus_process_obj_msg(ctx, buf, fd);
		ctx->stack_depth--;
		break;
	case HOMEBUS_MSG_MONITOR:
		if (ctx->monitor_cb)
			ctx->monitor_cb(ctx, buf->hdr.seq, buf->data);
		break;
	}
}

static void homebus_process_pending_msg(struct uloop_timeout *timeout)
{
	struct homebus_context *ctx = container_of(timeout, struct homebus_context, pending_timer);
	struct homebus_pending_msg *pending;

	while (!list_empty(&ctx->pending)) {
		if (ctx->stack_depth)
			break;

		pending = list_first_entry(&ctx->pending, struct homebus_pending_msg, list);
		list_del(&pending->list);
		homebus_process_msg(ctx, &pending->hdr, -1);
		free(pending);
	}
}

struct homebus_lookup_request {
	struct homebus_request req;
	homebus_lookup_handler_t cb;
};

static void homebus_lookup_cb(struct homebus_request *ureq, int type, struct blob_attr *msg)
{
	struct homebus_lookup_request *req;
	struct homebus_object_data obj = {};
	struct blob_attr **attr;

	req = container_of(ureq, struct homebus_lookup_request, req);
	attr = homebus_parse_msg(msg, blob_raw_len(msg));

	if (!attr[HOMEBUS_ATTR_OBJID] || !attr[HOMEBUS_ATTR_OBJPATH] ||
	    !attr[HOMEBUS_ATTR_OBJTYPE])
		return;

	obj.id = blob_get_u32(attr[HOMEBUS_ATTR_OBJID]);
	obj.path = blob_data(attr[HOMEBUS_ATTR_OBJPATH]);
	obj.type_id = blob_get_u32(attr[HOMEBUS_ATTR_OBJTYPE]);
	obj.signature = attr[HOMEBUS_ATTR_SIGNATURE];
	req->cb(ureq->ctx, &obj, ureq->priv);
}

int homebus_lookup(struct homebus_context *ctx, const char *path,
		homebus_lookup_handler_t cb, void *priv)
{
	struct homebus_lookup_request lookup;

	blob_buf_init(&b, 0);
	if (path)
		blob_put_string(&b, HOMEBUS_ATTR_OBJPATH, path);

	if (homebus_start_request(ctx, &lookup.req, b.head, HOMEBUS_MSG_LOOKUP, 0) < 0)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	lookup.req.raw_data_cb = homebus_lookup_cb;
	lookup.req.priv = priv;
	lookup.cb = cb;
	return homebus_complete_request(ctx, &lookup.req, 0);
}

static void homebus_lookup_id_cb(struct homebus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr **attr;
	uint32_t *id = req->priv;

	attr = homebus_parse_msg(msg, blob_raw_len(msg));

	if (!attr[HOMEBUS_ATTR_OBJID])
		return;

	*id = blob_get_u32(attr[HOMEBUS_ATTR_OBJID]);
}

int homebus_lookup_id(struct homebus_context *ctx, const char *path, uint32_t *id)
{
	struct homebus_request req;

	blob_buf_init(&b, 0);
	if (path)
		blob_put_string(&b, HOMEBUS_ATTR_OBJPATH, path);

	if (homebus_start_request(ctx, &req, b.head, HOMEBUS_MSG_LOOKUP, 0) < 0)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	req.raw_data_cb = homebus_lookup_id_cb;
	req.priv = id;

	return homebus_complete_request(ctx, &req, 0);
}

static int homebus_event_cb(struct homebus_context *ctx, struct homebus_object *obj,
			 struct homebus_request_data *req,
			 const char *method, struct blob_attr *msg)
{
	struct homebus_event_handler *ev;

	ev = container_of(obj, struct homebus_event_handler, obj);
	ev->cb(ctx, ev, method, msg);
	return 0;
}

static const struct homebus_method event_method = {
	.name = NULL,
	.handler = homebus_event_cb,
};

int homebus_register_event_handler(struct homebus_context *ctx,
				struct homebus_event_handler *ev,
				const char *pattern)
{
	struct homebus_object *obj = &ev->obj;
	struct blob_buf b2 = {};
	int ret;

	if (!obj->id) {
		obj->methods = &event_method;
		obj->n_methods = 1;

		if (!!obj->name ^ !!obj->type)
			return HOMEBUS_STATUS_INVALID_ARGUMENT;

		ret = homebus_add_object(ctx, obj);
		if (ret)
			return ret;
	}

	/* use a second buffer, homebus_invoke() overwrites the primary one */
	blob_buf_init(&b2, 0);
	blobmsg_add_u32(&b2, "object", obj->id);
	if (pattern)
		blobmsg_add_string(&b2, "pattern", pattern);

	ret = homebus_invoke(ctx, HOMEBUS_SYSTEM_OBJECT_EVENT, "register", b2.head,
			  NULL, NULL, 0);
	blob_buf_free(&b2);

	return ret;
}

int homebus_send_event(struct homebus_context *ctx, const char *id,
		    struct blob_attr *data)
{
	struct homebus_request req;
	void *s;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, HOMEBUS_SYSTEM_OBJECT_EVENT);
	blob_put_string(&b, HOMEBUS_ATTR_METHOD, "send");
	s = blob_nest_start(&b, HOMEBUS_ATTR_DATA);
	blobmsg_add_string(&b, "id", id);
	blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "data", blob_data(data), blob_len(data));
	blob_nest_end(&b, s);

	if (homebus_start_request(ctx, &req, b.head, HOMEBUS_MSG_INVOKE, HOMEBUS_SYSTEM_OBJECT_EVENT) < 0)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	return homebus_complete_request(ctx, &req, 0);
}

static void homebus_default_connection_lost(struct homebus_context *ctx)
{
	if (ctx->sock.registered)
		uloop_end();
}

int homebus_connect_ctx(struct homebus_context *ctx, const char *path)
{
	uloop_init();
	memset(ctx, 0, sizeof(*ctx));

	ctx->sock.fd = -1;
	ctx->sock.cb = homebus_handle_data;
	ctx->connection_lost = homebus_default_connection_lost;
	ctx->pending_timer.cb = homebus_process_pending_msg;

	ctx->msgbuf.data = calloc(1, HOMEBUS_MSG_CHUNK_SIZE);
	if (!ctx->msgbuf.data)
		return -1;
	ctx->msgbuf_data_len = HOMEBUS_MSG_CHUNK_SIZE;

	INIT_LIST_HEAD(&ctx->requests);
	INIT_LIST_HEAD(&ctx->pending);
	INIT_LIST_HEAD(&ctx->auto_subscribers);
	avl_init(&ctx->objects, homebus_cmp_id, false, NULL);
	if (homebus_reconnect(ctx, path)) {
		free(ctx->msgbuf.data);
		ctx->msgbuf.data = NULL;
		return -1;
	}

	return 0;
}

static void homebus_auto_reconnect_cb(struct uloop_timeout *timeout)
{
	struct homebus_auto_conn *conn = container_of(timeout, struct homebus_auto_conn, timer);

	if (!homebus_reconnect(&conn->ctx, conn->path))
		homebus_add_uloop(&conn->ctx);
	else
		uloop_timeout_set(timeout, 1000);
}

static void homebus_auto_disconnect_cb(struct homebus_context *ctx)
{
	struct homebus_auto_conn *conn = container_of(ctx, struct homebus_auto_conn, ctx);

	conn->timer.cb = homebus_auto_reconnect_cb;
	uloop_timeout_set(&conn->timer, 1000);
}

static void homebus_auto_connect_cb(struct uloop_timeout *timeout)
{
	struct homebus_auto_conn *conn = container_of(timeout, struct homebus_auto_conn, timer);

	if (homebus_connect_ctx(&conn->ctx, conn->path)) {
		uloop_timeout_set(timeout, 1000);
		fprintf(stderr, "failed to connect to homebus\n");
		return;
	}
	conn->ctx.connection_lost = homebus_auto_disconnect_cb;
	if (conn->cb)
		conn->cb(&conn->ctx);
	homebus_add_uloop(&conn->ctx);
}

void homebus_auto_connect(struct homebus_auto_conn *conn)
{
	conn->timer.cb = homebus_auto_connect_cb;
	homebus_auto_connect_cb(&conn->timer);
}

struct homebus_context *homebus_connect(const char *path)
{
	struct homebus_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	if (homebus_connect_ctx(ctx, path)) {
		free(ctx);
		ctx = NULL;
	}

	return ctx;
}

void homebus_shutdown(struct homebus_context *ctx)
{
	blob_buf_free(&b);
	if (!ctx)
		return;
	uloop_fd_delete(&ctx->sock);
	close(ctx->sock.fd);
	uloop_timeout_cancel(&ctx->pending_timer);
	free(ctx->msgbuf.data);
}

void homebus_free(struct homebus_context *ctx)
{
	homebus_shutdown(ctx);
	free(ctx);
}
