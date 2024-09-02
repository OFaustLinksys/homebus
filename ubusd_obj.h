/*
 * Copyright (C) 2011 Felix Fietkau <nbd@openwrt.org>
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

#ifndef __HOMEBUSD_OBJ_H
#define __HOMEBUSD_OBJ_H

#include "homebusd_id.h"

extern struct avl_tree obj_types;
extern struct avl_tree objects;
extern struct avl_tree path;

struct homebus_client;
struct homebus_msg_buf;

struct homebus_object_type {
	struct homebus_id id;
	int refcount;
	struct list_head methods;
};

struct homebus_method {
	struct list_head list;
	const char *name;
	struct blob_attr data[];
};

struct homebus_subscription {
	struct list_head list, target_list;
	struct homebus_object *subscriber, *target;
};

struct homebus_object {
	struct homebus_id id;
	struct list_head list;

	struct list_head events;

	struct list_head subscribers, target_list;

	struct homebus_object_type *type;
	struct avl_node path;

	struct homebus_client *client;
	int (*recv_msg)(struct homebus_client *client, struct homebus_msg_buf *ub,
			const char *method, struct blob_attr *msg);

	int event_seen;
	unsigned int invoke_seq;
};

struct homebus_object *homebusd_create_object(struct homebus_client *cl, struct blob_attr **attr);
struct homebus_object *homebusd_create_object_internal(struct homebus_object_type *type, uint32_t id);
void homebusd_free_object(struct homebus_object *obj);

static inline struct homebus_object *homebusd_find_object(uint32_t objid)
{
	struct homebus_object *obj;
	struct homebus_id *id;

	id = homebus_find_id(&objects, objid);
	if (!id)
		return NULL;

	obj = container_of(id, struct homebus_object, id);
	return obj;
}

void homebus_subscribe(struct homebus_object *obj, struct homebus_object *target);
void homebus_unsubscribe(struct homebus_subscription *s);
void homebus_notify_unsubscribe(struct homebus_subscription *s);
void homebus_notify_subscription(struct homebus_object *obj);

#endif
