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

#include <unistd.h>
#include "libhomebus.h"
#include "libhomebus-internal.h"

struct homebus_pending_data {
	struct list_head list;
	int type;
	struct blob_attr data[];
};

static void req_data_cb(struct homebus_request *req, int type, struct blob_attr *data)
{
	struct blob_attr **attr;

	if (req->raw_data_cb)
		req->raw_data_cb(req, type, data);

	if (!req->data_cb)
		return;

	attr = homebus_parse_msg(data, blob_raw_len(data));
	if (!attr[HOMEBUS_ATTR_DATA])
		return;

	req->data_cb(req, type, attr[HOMEBUS_ATTR_DATA]);
}

static void __homebus_process_req_data(struct homebus_request *req)
{
	struct homebus_pending_data *data, *tmp;

	list_for_each_entry_safe(data, tmp, &req->pending, list) {
		list_del(&data->list);
		if (!req->cancelled)
			req_data_cb(req, data->type, data->data);
		free(data);
	}
}

int __hidden __homebus_start_request(struct homebus_context *ctx, struct homebus_request *req,
				struct blob_attr *msg, int cmd, uint32_t peer)
{

	if (msg && blob_pad_len(msg) > HOMEBUS_MAX_MSGLEN)
		return -1;

	INIT_LIST_HEAD(&req->list);
	INIT_LIST_HEAD(&req->pending);
	req->ctx = ctx;
	req->peer = peer;
	req->seq = ++ctx->request_seq;

	return homebus_send_msg(ctx, req->seq, msg, cmd, peer, req->fd);
}

int __hidden homebus_start_request(struct homebus_context *ctx, struct homebus_request *req,
				struct blob_attr *msg, int cmd, uint32_t peer)
{
	memset(req, 0, sizeof(*req));

	req->fd = -1;

	return __homebus_start_request(ctx, req, msg, cmd, peer);
}


void homebus_abort_request(struct homebus_context *ctx, struct homebus_request *req)
{
	if (list_empty(&req->list))
		return;

	req->cancelled = true;
	__homebus_process_req_data(req);
	list_del_init(&req->list);
}

void homebus_complete_request_async(struct homebus_context *ctx, struct homebus_request *req)
{
	if (!list_empty(&req->list))
		return;

	list_add(&req->list, &ctx->requests);
}

static void
homebus_req_complete_cb(struct homebus_request *req)
{
	homebus_complete_handler_t cb = req->complete_cb;

	if (!cb)
		return;

	req->complete_cb = NULL;
	cb(req, req->status_code);
}

static void
homebus_set_req_status(struct homebus_request *req, int ret)
{
	if (!list_empty(&req->list))
		list_del_init(&req->list);

	req->status_msg = true;
	req->status_code = ret;
	if (!req->blocked)
		homebus_req_complete_cb(req);
}

static void homebus_sync_req_cb(struct homebus_request *req, int ret)
{
	req->status_msg = true;
	req->status_code = ret;
	req->ctx->cancel_poll = true;
}

static int64_t get_time_msec(void)
{
	struct timespec ts;
	int64_t val;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	val = (int64_t) ts.tv_sec * 1000LL;
	val += ts.tv_nsec / 1000000LL;
	return val;
}

int homebus_complete_request(struct homebus_context *ctx, struct homebus_request *req,
			  int req_timeout)
{
	homebus_complete_handler_t complete_cb = req->complete_cb;
	int status = HOMEBUS_STATUS_NO_DATA;
	int64_t timeout = 0, time_end = 0;

	if (req_timeout)
		time_end = get_time_msec() + req_timeout;

	homebus_complete_request_async(ctx, req);
	req->complete_cb = homebus_sync_req_cb;

	ctx->stack_depth++;
	while (!req->status_msg) {
		if (req_timeout) {
			timeout = time_end - get_time_msec();
			if (timeout <= 0) {
				homebus_set_req_status(req, HOMEBUS_STATUS_TIMEOUT);
				break;
			}
		}

		homebus_poll_data(ctx, (unsigned int) timeout);

		if (ctx->sock.eof) {
			homebus_set_req_status(req, HOMEBUS_STATUS_CONNECTION_FAILED);
			ctx->cancel_poll = true;
			break;
		}
	}

	ctx->stack_depth--;
	if (ctx->stack_depth)
		ctx->cancel_poll = true;

	if (req->status_msg)
		status = req->status_code;

	req->complete_cb = complete_cb;
	if (req->complete_cb)
		req->complete_cb(req, status);

	if (!ctx->stack_depth && !ctx->sock.registered)
		ctx->pending_timer.cb(&ctx->pending_timer);

	return status;
}

void homebus_complete_deferred_request(struct homebus_context *ctx, struct homebus_request_data *req, int ret)
{
	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_STATUS, ret);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, req->object);
	homebus_send_msg(ctx, req->seq, b.head, HOMEBUS_MSG_STATUS, req->peer, req->fd);
}

static void homebus_put_data(struct blob_buf *buf, struct blob_attr *msg)
{
	if (msg)
		blob_put(buf, HOMEBUS_ATTR_DATA, blob_data(msg), blob_len(msg));
	else
		blob_put(buf, HOMEBUS_ATTR_DATA, NULL, 0);
}

int homebus_send_reply(struct homebus_context *ctx, struct homebus_request_data *req,
		    struct blob_attr *msg)
{
	int ret;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, req->object);
	homebus_put_data(&b, msg);
	ret = homebus_send_msg(ctx, req->seq, b.head, HOMEBUS_MSG_DATA, req->peer, -1);
	if (ret < 0)
		return HOMEBUS_STATUS_NO_DATA;

	return 0;
}

int homebus_invoke_async_fd(struct homebus_context *ctx, uint32_t obj,
			 const char *method, struct blob_attr *msg,
			 struct homebus_request *req, int fd)
{
	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj);
	blob_put_string(&b, HOMEBUS_ATTR_METHOD, method);
	homebus_put_data(&b, msg);

	memset(req, 0, sizeof(*req));
	req->fd = fd;
	if (__homebus_start_request(ctx, req, b.head, HOMEBUS_MSG_INVOKE, obj) < 0)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;
	return 0;
}

int homebus_invoke_fd(struct homebus_context *ctx, uint32_t obj, const char *method,
		   struct blob_attr *msg, homebus_data_handler_t cb, void *priv,
		   int timeout, int fd)
{
	struct homebus_request req;
	int rc;

	rc = homebus_invoke_async_fd(ctx, obj, method, msg, &req, fd);
	if (rc)
		return rc;

	req.data_cb = cb;
	req.priv = priv;
	return homebus_complete_request(ctx, &req, timeout);
}

static void
homebus_notify_complete_cb(struct homebus_request *req, int ret)
{
	struct homebus_notify_request *nreq;

	nreq = container_of(req, struct homebus_notify_request, req);
	if (!nreq->complete_cb)
		return;

	nreq->complete_cb(nreq, 0, 0);
}

static void
homebus_notify_data_cb(struct homebus_request *req, int type, struct blob_attr *msg)
{
	struct homebus_notify_request *nreq;

	nreq = container_of(req, struct homebus_notify_request, req);
	if (!nreq->data_cb)
		return;

	nreq->data_cb(nreq, type, msg);
}

static int
__homebus_notify_async(struct homebus_context *ctx, struct homebus_object *obj,
		    const char *type, struct blob_attr *msg,
		    struct homebus_notify_request *req, bool reply)
{
	memset(req, 0, sizeof(*req));

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id);
	blob_put_string(&b, HOMEBUS_ATTR_METHOD, type);
	homebus_put_data(&b, msg);

	if (!reply)
		blob_put_int8(&b, HOMEBUS_ATTR_NO_REPLY, true);

	if (homebus_start_request(ctx, &req->req, b.head, HOMEBUS_MSG_NOTIFY, obj->id) < 0)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	/* wait for status message from homebusd first */
	req->req.notify = true;
	req->pending = 1;
	req->id[0] = obj->id;
	req->req.complete_cb = homebus_notify_complete_cb;
	req->req.data_cb = homebus_notify_data_cb;

	return 0;
}

int homebus_notify_async(struct homebus_context *ctx, struct homebus_object *obj,
		      const char *type, struct blob_attr *msg,
		      struct homebus_notify_request *req)
{
	return __homebus_notify_async(ctx, obj, type, msg, req, true);
}

int homebus_notify(struct homebus_context *ctx, struct homebus_object *obj,
		const char *type, struct blob_attr *msg, int timeout)
{
	struct homebus_notify_request req;
	int ret;

	ret = __homebus_notify_async(ctx, obj, type, msg, &req, timeout >= 0);
	if (ret < 0)
		return ret;

	if (timeout < 0) {
		homebus_abort_request(ctx, &req.req);
		return 0;
	}

	return homebus_complete_request(ctx, &req.req, timeout);
}

static bool homebus_get_status(struct homebus_msghdr_buf *buf, int *ret)
{
	struct blob_attr **attrbuf = homebus_parse_msg(buf->data, blob_raw_len(buf->data));

	if (!attrbuf[HOMEBUS_ATTR_STATUS])
		return false;

	*ret = blob_get_u32(attrbuf[HOMEBUS_ATTR_STATUS]);
	return true;
}

static int
homebus_process_req_status(struct homebus_request *req, struct homebus_msghdr_buf *buf)
{
	int ret = HOMEBUS_STATUS_INVALID_ARGUMENT;

	homebus_get_status(buf, &ret);
	req->peer = buf->hdr.peer;
	homebus_set_req_status(req, ret);

	return ret;
}

static void
homebus_process_req_data(struct homebus_request *req, struct homebus_msghdr_buf *buf)
{
	struct homebus_pending_data *data;
	int len;

	if (!req->blocked) {
		req->blocked = true;
		req_data_cb(req, buf->hdr.type, buf->data);
		__homebus_process_req_data(req);
		req->blocked = false;

		if (req->status_msg)
			homebus_req_complete_cb(req);

		return;
	}

	len = blob_raw_len(buf->data);
	data = calloc(1, sizeof(*data) + len);
	if (!data)
		return;

	data->type = buf->hdr.type;
	memcpy(data->data, buf->data, len);
	list_add(&data->list, &req->pending);
}

static int
homebus_find_notify_id(struct homebus_notify_request *n, uint32_t objid)
{
	uint32_t pending = n->pending;
	int i;

	for (i = 0; pending; i++, pending >>= 1) {
		if (!(pending & 1))
			continue;

		if (n->id[i] == objid)
			return i;
	}

	return -1;
}

static struct homebus_request *
homebus_find_request(struct homebus_context *ctx, uint32_t seq, uint32_t peer, int *id)
{
	struct homebus_request *req;

	list_for_each_entry(req, &ctx->requests, list) {
		struct homebus_notify_request *nreq;
		nreq = container_of(req, struct homebus_notify_request, req);

		if (seq != req->seq)
			continue;

		if (req->notify) {
			if (!nreq->pending)
				continue;

			*id = homebus_find_notify_id(nreq, peer);
			if (*id < 0)
				continue;
		} else if (peer != req->peer)
			continue;

		return req;
	}
	return NULL;
}

static void homebus_process_notify_status(struct homebus_request *req, int id, struct homebus_msghdr_buf *buf)
{
	struct homebus_notify_request *nreq;
	struct blob_attr **tb;
	struct blob_attr *cur;
	size_t rem;
	int idx = 1;
	int ret = 0;

	nreq = container_of(req, struct homebus_notify_request, req);
	nreq->pending &= ~(1 << id);

	if (!id) {
		/* first id: homebusd's status message with a list of ids */
		tb = homebus_parse_msg(buf->data, blob_raw_len(buf->data));
		if (tb[HOMEBUS_ATTR_SUBSCRIBERS]) {
			blob_for_each_attr(cur, tb[HOMEBUS_ATTR_SUBSCRIBERS], rem) {
				if (!blob_check_type(blob_data(cur), blob_len(cur), BLOB_ATTR_INT32))
					continue;

				nreq->pending |= (1 << idx);
				nreq->id[idx] = blob_get_int32(cur);
				idx++;

				if (idx == HOMEBUS_MAX_NOTIFY_PEERS + 1)
					break;
			}
		}
	} else {
		homebus_get_status(buf, &ret);
		if (nreq->status_cb)
			nreq->status_cb(nreq, id, ret);
	}

	if (!nreq->pending)
		homebus_set_req_status(req, 0);
}

void __hidden homebus_process_req_msg(struct homebus_context *ctx, struct homebus_msghdr_buf *buf, int fd)
{
	struct homebus_msghdr *hdr = &buf->hdr;
	struct homebus_request *req;
	int id = -1;

	switch(hdr->type) {
	case HOMEBUS_MSG_STATUS:
		req = homebus_find_request(ctx, hdr->seq, hdr->peer, &id);
		if (!req)
			break;

		if (fd >= 0) {
			if (req->fd_cb)
				req->fd_cb(req, fd);
			else
				close(fd);
		}

		if (id >= 0)
			homebus_process_notify_status(req, id, buf);
		else
			homebus_process_req_status(req, buf);
		break;

	case HOMEBUS_MSG_DATA:
		req = homebus_find_request(ctx, hdr->seq, hdr->peer, &id);
		if (req && (req->data_cb || req->raw_data_cb))
			homebus_process_req_data(req, buf);
		break;
	}
}

int __homebus_monitor(struct homebus_context *ctx, const char *type)
{
	blob_buf_init(&b, 0);
	return homebus_invoke(ctx, HOMEBUS_SYSTEM_OBJECT_MONITOR, type, b.head, NULL, NULL, 1000);
}
