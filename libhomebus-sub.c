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

#include "libhomebus.h"
#include "libhomebus-internal.h"

static int homebus_subscriber_cb(struct homebus_context *ctx, struct homebus_object *obj,
			 struct homebus_request_data *req,
			 const char *method, struct blob_attr *msg)
{
	struct homebus_subscriber *s;

	s = container_of(obj, struct homebus_subscriber, obj);
	if (s->cb)
		return s->cb(ctx, obj, req, method, msg);
	return 0;
}

const struct homebus_method watch_method __hidden = {
	.name = NULL,
	.handler = homebus_subscriber_cb,
};

static void
homebus_auto_sub_event_handler_cb(struct homebus_context *ctx,  struct homebus_event_handler *ev,
			       const char *type, struct blob_attr *msg)
{
	enum {
		EVENT_ID,
		EVENT_PATH,
		__EVENT_MAX
	};

	static const struct blobmsg_policy event_policy[__EVENT_MAX] = {
		[EVENT_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
		[EVENT_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__EVENT_MAX];
	struct homebus_subscriber *s;
	const char *path;
	int id;

	blobmsg_parse(event_policy, __EVENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[EVENT_ID] || !tb[EVENT_PATH])
		return;

	path = blobmsg_get_string(tb[EVENT_PATH]);
	id = blobmsg_get_u32(tb[EVENT_ID]);

	list_for_each_entry(s, &ctx->auto_subscribers, list)
		if (s->new_obj_cb(ctx, s, path))
			homebus_subscribe(ctx, s, id);
}

static void
homebus_auto_sub_lookup(struct homebus_context *ctx, struct homebus_object_data *obj,
		     void *priv)
{
	struct homebus_subscriber *s = priv;

	if (s->new_obj_cb(ctx, s, obj->path))
		homebus_subscribe(ctx, s, obj->id);
}

int homebus_register_subscriber(struct homebus_context *ctx, struct homebus_subscriber *s)
{
	struct homebus_object *obj = &s->obj;
	int ret;

	INIT_LIST_HEAD(&s->list);
	obj->methods = &watch_method;
	obj->n_methods = 1;

	ret = homebus_add_object(ctx, obj);
	if (ret)
		return ret;

	if (s->new_obj_cb) {
		struct homebus_event_handler *ev = &ctx->auto_subscribe_event_handler;
		list_add(&s->list, &ctx->auto_subscribers);
		ev->cb = homebus_auto_sub_event_handler_cb;
		if (!ev->obj.id)
			homebus_register_event_handler(ctx, ev, "homebus.object.add");
		homebus_lookup(ctx, NULL, homebus_auto_sub_lookup, s);
	}

	return 0;
}

static int
__homebus_subscribe_request(struct homebus_context *ctx, struct homebus_object *obj, uint32_t id, int type)
{
	struct homebus_request req;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id);
	blob_put_int32(&b, HOMEBUS_ATTR_TARGET, id);

	if (homebus_start_request(ctx, &req, b.head, type, 0) < 0)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	return homebus_complete_request(ctx, &req, 0);

}

int homebus_subscribe(struct homebus_context *ctx, struct homebus_subscriber *obj, uint32_t id)
{
	return __homebus_subscribe_request(ctx, &obj->obj, id, HOMEBUS_MSG_SUBSCRIBE);
}

int homebus_unsubscribe(struct homebus_context *ctx, struct homebus_subscriber *obj, uint32_t id)
{
	return __homebus_subscribe_request(ctx, &obj->obj, id, HOMEBUS_MSG_UNSUBSCRIBE);
}

