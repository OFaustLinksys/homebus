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

#include "homebusd.h"
#include "homebusd_obj.h"

struct avl_tree obj_types;
struct avl_tree objects;
struct avl_tree path;

static void homebus_unref_object_type(struct homebus_object_type *type)
{
	struct homebus_method *m, *tmp;

	if (--type->refcount > 0)
		return;

	list_for_each_entry_safe(m, tmp, &type->methods, list) {
		list_del(&m->list);
		free(m);
	}

	homebus_free_id(&obj_types, &type->id);
	free(type);
}

static bool homebus_create_obj_method(struct homebus_object_type *type, struct blob_attr *attr)
{
	struct homebus_method *m;
	int bloblen = blob_raw_len(attr);

	m = calloc(1, sizeof(*m) + bloblen);
	if (!m)
		return false;

	list_add_tail(&m->list, &type->methods);
	memcpy(m->data, attr, bloblen);
	m->name = blobmsg_name(m->data);

	return true;
}

static struct homebus_object_type *homebus_create_obj_type(struct blob_attr *sig)
{
	struct homebus_object_type *type;
	struct blob_attr *pos;
	size_t rem;

	type = calloc(1, sizeof(*type));
	if (!type)
		return NULL;

	type->refcount = 1;

	if (!homebus_alloc_id(&obj_types, &type->id, 0))
		goto error_free;

	INIT_LIST_HEAD(&type->methods);

	blob_for_each_attr(pos, sig, rem) {
		if (!blobmsg_check_attr(pos, true))
			goto error_unref;

		if (!homebus_create_obj_method(type, pos))
			goto error_unref;
	}

	return type;

error_unref:
	homebus_unref_object_type(type);
	return NULL;

error_free:
	free(type);
	return NULL;
}

static struct homebus_object_type *homebus_get_obj_type(uint32_t obj_id)
{
	struct homebus_object_type *type;
	struct homebus_id *id;

	id = homebus_find_id(&obj_types, obj_id);
	if (!id)
		return NULL;

	type = container_of(id, struct homebus_object_type, id);
	type->refcount++;
	return type;
}

struct homebus_object *homebusd_create_object_internal(struct homebus_object_type *type, uint32_t id)
{
	struct homebus_object *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;

	if (!homebus_alloc_id(&objects, &obj->id, id))
		goto error_free;

	obj->type = type;
	INIT_LIST_HEAD(&obj->list);
	INIT_LIST_HEAD(&obj->events);
	INIT_LIST_HEAD(&obj->subscribers);
	INIT_LIST_HEAD(&obj->target_list);
	if (type)
		type->refcount++;

	return obj;

error_free:
	free(obj);
	return NULL;
}

struct homebus_object *homebusd_create_object(struct homebus_client *cl, struct blob_attr **attr)
{
	struct homebus_object *obj;
	struct homebus_object_type *type = NULL;

	if (attr[HOMEBUS_ATTR_OBJTYPE])
		type = homebus_get_obj_type(blob_get_u32(attr[HOMEBUS_ATTR_OBJTYPE]));
	else if (attr[HOMEBUS_ATTR_SIGNATURE])
		type = homebus_create_obj_type(attr[HOMEBUS_ATTR_SIGNATURE]);

	obj = homebusd_create_object_internal(type, 0);
	if (type)
		homebus_unref_object_type(type);

	if (!obj)
		return NULL;

	if (attr[HOMEBUS_ATTR_OBJPATH]) {
		if (homebusd_acl_check(cl, blob_data(attr[HOMEBUS_ATTR_OBJPATH]), NULL, HOMEBUS_ACL_PUBLISH))
			goto free;

		obj->path.key = strdup(blob_data(attr[HOMEBUS_ATTR_OBJPATH]));
		if (!obj->path.key)
			goto free;

		if (avl_insert(&path, &obj->path) != 0) {
			free((void *) obj->path.key);
			obj->path.key = NULL;
			goto free;
		}
		homebusd_send_obj_event(obj, true);
	}

	obj->client = cl;
	list_add(&obj->list, &cl->objects);

	return obj;

free:
	homebusd_free_object(obj);
	return NULL;
}

void homebus_subscribe(struct homebus_object *obj, struct homebus_object *target)
{
	struct homebus_subscription *s;
	bool first = list_empty(&target->subscribers);

	s = calloc(1, sizeof(*s));
	if (!s)
		return;

	s->subscriber = obj;
	s->target = target;
	list_add(&s->list, &target->subscribers);
	list_add(&s->target_list, &obj->target_list);

	if (first)
		homebus_notify_subscription(target);
}

void homebus_unsubscribe(struct homebus_subscription *s)
{
	struct homebus_object *obj = s->target;

	list_del(&s->list);
	list_del(&s->target_list);
	free(s);

	if (list_empty(&obj->subscribers))
		homebus_notify_subscription(obj);
}

void homebusd_free_object(struct homebus_object *obj)
{
	struct homebus_subscription *s, *tmp;

	list_for_each_entry_safe(s, tmp, &obj->target_list, target_list) {
		homebus_unsubscribe(s);
	}
	list_for_each_entry_safe(s, tmp, &obj->subscribers, list) {
		homebus_notify_unsubscribe(s);
	}

	homebusd_event_cleanup_object(obj);
	if (obj->path.key) {
		homebusd_send_obj_event(obj, false);
		avl_delete(&path, &obj->path);
		free((void *) obj->path.key);
	}
	if (!list_empty(&obj->list))
		list_del(&obj->list);
	homebus_free_id(&objects, &obj->id);
	if (obj->type)
		homebus_unref_object_type(obj->type);
	free(obj);
}

static void __constructor homebusd_obj_init(void)
{
	homebus_init_id_tree(&objects);
	homebus_init_id_tree(&obj_types);
	homebus_init_string_tree(&path, false);
	homebusd_event_init();
	homebusd_acl_init();
	homebusd_monitor_init();
}
