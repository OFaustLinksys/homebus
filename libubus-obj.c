/*
 * Copyright (C) 2011-2012 Felix Fietkau <nbd@openwrt.org>
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

static void
homebus_process_unsubscribe(struct homebus_context *ctx, struct homebus_msghdr *hdr,
			 struct homebus_object *obj, struct blob_attr **attrbuf, int fd)
{
	struct homebus_subscriber *s;

	if (!obj || !attrbuf[HOMEBUS_ATTR_TARGET])
		return;

	if (obj->methods != &watch_method)
		return;

	s = container_of(obj, struct homebus_subscriber, obj);
	if (s->remove_cb)
		s->remove_cb(ctx, s, blob_get_u32(attrbuf[HOMEBUS_ATTR_TARGET]));

	if (fd >= 0)
		close(fd);
}

static void
homebus_process_notify(struct homebus_context *ctx, struct homebus_msghdr *hdr,
		    struct homebus_object *obj, struct blob_attr **attrbuf, int fd)
{
	if (!obj || !attrbuf[HOMEBUS_ATTR_ACTIVE])
		return;

	obj->has_subscribers = blob_get_u8(attrbuf[HOMEBUS_ATTR_ACTIVE]);
	if (obj->subscribe_cb)
		obj->subscribe_cb(ctx, obj);

	if (fd >= 0)
		close(fd);
}
static void
homebus_process_invoke(struct homebus_context *ctx, struct homebus_msghdr *hdr,
		    struct homebus_object *obj, struct blob_attr **attrbuf, int fd)
{
	struct homebus_request_data req = {
		.fd = -1,
		.req_fd = fd,
	};

	int method;
	int ret;
	bool no_reply = false;

	if (!obj) {
		ret = HOMEBUS_STATUS_NOT_FOUND;
		goto send;
	}

	if (!attrbuf[HOMEBUS_ATTR_METHOD]) {
		ret = HOMEBUS_STATUS_INVALID_ARGUMENT;
		goto send;
	}

	if (attrbuf[HOMEBUS_ATTR_NO_REPLY])
		no_reply = blob_get_int8(attrbuf[HOMEBUS_ATTR_NO_REPLY]);

	req.peer = hdr->peer;
	req.seq = hdr->seq;
	req.object = obj->id;
	if (attrbuf[HOMEBUS_ATTR_USER] && attrbuf[HOMEBUS_ATTR_GROUP]) {
		req.acl.user = blobmsg_get_string(attrbuf[HOMEBUS_ATTR_USER]);
		req.acl.group = blobmsg_get_string(attrbuf[HOMEBUS_ATTR_GROUP]);
		req.acl.object = obj->name;
	}
	for (method = 0; method < obj->n_methods; method++)
		if (!obj->methods[method].name ||
		    !strcmp(obj->methods[method].name,
		            blob_data(attrbuf[HOMEBUS_ATTR_METHOD])))
			goto found;

	/* not found */
	ret = HOMEBUS_STATUS_METHOD_NOT_FOUND;
	goto send;

found:
	if (!attrbuf[HOMEBUS_ATTR_DATA]) {
		ret = HOMEBUS_STATUS_INVALID_ARGUMENT;
		goto send;
	}

	ret = obj->methods[method].handler(ctx, obj, &req,
					   blob_data(attrbuf[HOMEBUS_ATTR_METHOD]),
					   attrbuf[HOMEBUS_ATTR_DATA]);
	if (req.req_fd >= 0)
		close(req.req_fd);
	if (req.deferred || no_reply)
		return;

send:
	homebus_complete_deferred_request(ctx, &req, ret);
}


void __hidden homebus_process_obj_msg(struct homebus_context *ctx, struct homebus_msghdr_buf *buf, int fd)
{
	void (*cb)(struct homebus_context *, struct homebus_msghdr *,
		   struct homebus_object *, struct blob_attr **, int fd);
	struct homebus_msghdr *hdr = &buf->hdr;
	struct blob_attr **attrbuf;
	struct homebus_object *obj;
	uint32_t objid;
	void *prev_data = NULL;
	attrbuf = homebus_parse_msg(buf->data, blob_raw_len(buf->data));
	if (!attrbuf[HOMEBUS_ATTR_OBJID])
		return;

	objid = blob_get_u32(attrbuf[HOMEBUS_ATTR_OBJID]);
	obj = avl_find_element(&ctx->objects, &objid, obj, avl);

	switch (hdr->type) {
	case HOMEBUS_MSG_INVOKE:
		cb = homebus_process_invoke;
		break;
	case HOMEBUS_MSG_UNSUBSCRIBE:
		cb = homebus_process_unsubscribe;
		break;
	case HOMEBUS_MSG_NOTIFY:
		cb = homebus_process_notify;
		break;
	default:
		return;
	}

	if (buf == &ctx->msgbuf) {
		prev_data = buf->data;
		buf->data = NULL;
	}

	cb(ctx, hdr, obj, attrbuf, fd);

	if (prev_data) {
		if (buf->data)
			free(prev_data);
		else
			buf->data = prev_data;
	}
}

static void homebus_add_object_cb(struct homebus_request *req, int type, struct blob_attr *msg)
{
	struct homebus_object *obj = req->priv;
	struct blob_attr **attrbuf = homebus_parse_msg(msg, blob_raw_len(msg));

	if (!attrbuf[HOMEBUS_ATTR_OBJID])
		return;

	obj->id = blob_get_u32(attrbuf[HOMEBUS_ATTR_OBJID]);

	if (attrbuf[HOMEBUS_ATTR_OBJTYPE])
		obj->type->id = blob_get_u32(attrbuf[HOMEBUS_ATTR_OBJTYPE]);

	obj->avl.key = &obj->id;
	avl_insert(&req->ctx->objects, &obj->avl);
}

static void homebus_push_method_data(const struct homebus_method *m)
{
	void *mtbl;
	int i;

	mtbl = blobmsg_open_table(&b, m->name);

	for (i = 0; i < m->n_policy; i++) {
		if (m->mask && !(m->mask & (1 << i)))
			continue;

		blobmsg_add_u32(&b, m->policy[i].name, m->policy[i].type);
	}

	blobmsg_close_table(&b, mtbl);
}

static bool homebus_push_object_type(const struct homebus_object_type *type)
{
	void *s;
	int i;

	s = blob_nest_start(&b, HOMEBUS_ATTR_SIGNATURE);

	for (i = 0; i < type->n_methods; i++)
		homebus_push_method_data(&type->methods[i]);

	blob_nest_end(&b, s);

	return true;
}

int homebus_add_object(struct homebus_context *ctx, struct homebus_object *obj)
{
	struct homebus_request req;
	int ret;

	blob_buf_init(&b, 0);

	if (obj->name && obj->type) {
		blob_put_string(&b, HOMEBUS_ATTR_OBJPATH, obj->name);

		if (obj->type->id)
			blob_put_int32(&b, HOMEBUS_ATTR_OBJTYPE, obj->type->id);
		else if (!homebus_push_object_type(obj->type))
			return HOMEBUS_STATUS_INVALID_ARGUMENT;
	}

	if (homebus_start_request(ctx, &req, b.head, HOMEBUS_MSG_ADD_OBJECT, 0) < 0)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	req.raw_data_cb = homebus_add_object_cb;
	req.priv = obj;
	ret = homebus_complete_request(ctx, &req, 0);
	if (ret)
		return ret;

	if (!obj->id)
		return HOMEBUS_STATUS_NO_DATA;

	return 0;
}

static void homebus_remove_object_cb(struct homebus_request *req, int type, struct blob_attr *msg)
{
	struct homebus_object *obj = req->priv;
	struct blob_attr **attrbuf = homebus_parse_msg(msg, blob_raw_len(msg));

	if (!attrbuf[HOMEBUS_ATTR_OBJID])
		return;

	avl_delete(&req->ctx->objects, &obj->avl);

	obj->id = 0;

	if (attrbuf[HOMEBUS_ATTR_OBJTYPE] && obj->type)
		obj->type->id = 0;
}

int homebus_remove_object(struct homebus_context *ctx, struct homebus_object *obj)
{
	struct homebus_request req;
	int ret;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id);

	if (homebus_start_request(ctx, &req, b.head, HOMEBUS_MSG_REMOVE_OBJECT, 0) < 0)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	req.raw_data_cb = homebus_remove_object_cb;
	req.priv = obj;
	ret = homebus_complete_request(ctx, &req, 0);
	if (ret)
		return ret;

	if (obj->id)
		return HOMEBUS_STATUS_NO_DATA;

	return 0;
}
