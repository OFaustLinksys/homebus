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

#include <arpa/inet.h>
#include "homebusd.h"

static struct avl_tree patterns;
static struct homebus_object *event_obj;
static int event_seq = 0;
static int obj_event_seq = 1;

struct event_source {
	struct list_head list;
	struct homebus_object *obj;
	struct avl_node avl;
	bool partial;
};

static void homebusd_delete_event_source(struct event_source *evs)
{
	list_del(&evs->list);
	avl_delete(&patterns, &evs->avl);
	free(evs);
}

void homebusd_event_cleanup_object(struct homebus_object *obj)
{
	struct event_source *ev, *tmp;

	list_for_each_entry_safe(ev, tmp, &obj->events, list) {
		homebusd_delete_event_source(ev);
	}
}

enum {
	EVREG_PATTERN,
	EVREG_OBJECT,
	EVREG_LAST,
};

static struct blobmsg_policy evr_policy[] = {
	[EVREG_PATTERN] = { .name = "pattern", .type = BLOBMSG_TYPE_STRING },
	[EVREG_OBJECT] = { .name = "object", .type = BLOBMSG_TYPE_INT32 },
};

static int homebusd_alloc_event_pattern(struct homebus_client *cl, struct blob_attr *msg)
{
	struct event_source *ev;
	struct homebus_object *obj;
	struct blob_attr *attr[EVREG_LAST];
	char *pattern, *name;
	uint32_t id;
	bool partial = false;
	int len;

	if (!msg)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(evr_policy, EVREG_LAST, attr, blob_data(msg), blob_len(msg));
	if (!attr[EVREG_OBJECT] || !attr[EVREG_PATTERN])
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	id = blobmsg_get_u32(attr[EVREG_OBJECT]);
	if (id < HOMEBUS_SYSTEM_OBJECT_MAX)
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	obj = homebusd_find_object(id);
	if (!obj)
		return HOMEBUS_STATUS_NOT_FOUND;

	if (obj->client != cl)
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	pattern = blobmsg_data(attr[EVREG_PATTERN]);

	len = strlen(pattern);
	if (pattern[len - 1] == '*') {
		partial = true;
		pattern[len - 1] = 0;
		len--;
	}

	if (pattern[0] && homebusd_acl_check(cl, pattern, NULL, HOMEBUS_ACL_LISTEN))
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	ev = calloc(1, sizeof(*ev) + len + 1);
	if (!ev)
		return HOMEBUS_STATUS_NO_DATA;

	list_add(&ev->list, &obj->events);
	ev->obj = obj;
	ev->partial = partial;
	name = (char *) (ev + 1);
	strcpy(name, pattern);
	ev->avl.key = name;
	avl_insert(&patterns, &ev->avl);

	return 0;
}

static void homebusd_send_event_msg(struct homebus_msg_buf **ub, struct homebus_client *cl,
				 struct homebus_object *obj, const char *id,
				 event_fill_cb fill_cb, void *cb_priv)
{
	uint32_t *objid_ptr;

	/* do not loop back events */
	if (obj->client == cl)
	    return;

	/* do not send duplicate events */
	if (obj->event_seen == obj_event_seq)
		return;

	obj->event_seen = obj_event_seq;

	if (!*ub) {
		*ub = fill_cb(cb_priv, id);
		(*ub)->hdr.type = HOMEBUS_MSG_INVOKE;
		(*ub)->hdr.peer = 0;
	}

	objid_ptr = blob_data(blob_data((*ub)->data));
	*objid_ptr = htonl(obj->id.id);

	(*ub)->hdr.seq = ++event_seq;
	homebus_msg_send(obj->client, *ub);
}

int homebusd_send_event(struct homebus_client *cl, const char *id,
		     event_fill_cb fill_cb, void *cb_priv)
{
	struct homebus_msg_buf *ub = NULL;
	struct event_source *ev;
	int match_len = 0;

	if (homebusd_acl_check(cl, id, NULL, HOMEBUS_ACL_SEND))
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	obj_event_seq++;

	/*
	 * Since this tree is sorted alphabetically, we can only expect to find
	 * matching entries as long as the number of matching characters
	 * between the pattern string and our string is monotonically increasing.
	 */
	avl_for_each_element(&patterns, ev, avl) {
		const char *key = ev->avl.key;
		int cur_match_len;
		bool full_match;

		full_match = homebus_strmatch_len(id, key, &cur_match_len);
		if (cur_match_len < match_len)
			break;

		match_len = cur_match_len;

		if (!full_match) {
			if (!ev->partial)
				continue;

			if (match_len != (int) strlen(key))
				continue;
		}

		homebusd_send_event_msg(&ub, cl, ev->obj, id, fill_cb, cb_priv);
	}

	if (ub)
		homebus_msg_free(ub);

	return 0;
}

enum {
	EVMSG_ID,
	EVMSG_DATA,
	EVMSG_LAST,
};

static struct blobmsg_policy ev_policy[] = {
	[EVMSG_ID] = { .name = "id", .type = BLOBMSG_TYPE_STRING },
	[EVMSG_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
};

static struct homebus_msg_buf *
homebusd_create_event_from_msg(void *priv, const char *id)
{
	struct blob_attr *msg = priv;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, 0);
	blob_put_string(&b, HOMEBUS_ATTR_METHOD, id);
	blob_put(&b, HOMEBUS_ATTR_DATA, blobmsg_data(msg), blobmsg_data_len(msg));

	return homebus_msg_new(b.head, blob_raw_len(b.head), true);
}

static int homebusd_forward_event(struct homebus_client *cl, struct blob_attr *msg)
{
	struct blob_attr *data;
	struct blob_attr *attr[EVMSG_LAST];
	const char *id;

	if (!msg)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(ev_policy, EVMSG_LAST, attr, blob_data(msg), blob_len(msg));
	if (!attr[EVMSG_ID] || !attr[EVMSG_DATA])
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	id = blobmsg_data(attr[EVMSG_ID]);
	data = attr[EVMSG_DATA];

	if (!strncmp(id, "homebus.", 5))
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	return homebusd_send_event(cl, id, homebusd_create_event_from_msg, data);
}

static int homebusd_event_recv(struct homebus_client *cl, struct homebus_msg_buf *ub, const char *method, struct blob_attr *msg)
{
	if (!strcmp(method, "register"))
		return homebusd_alloc_event_pattern(cl, msg);

	if (!strcmp(method, "send"))
		return homebusd_forward_event(cl, msg);

	return HOMEBUS_STATUS_INVALID_COMMAND;
}

static struct homebus_msg_buf *
homebusd_create_object_event_msg(void *priv, const char *id)
{
	struct homebus_object *obj = priv;
	void *s;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, 0);
	blob_put_string(&b, HOMEBUS_ATTR_METHOD, id);
	s = blob_nest_start(&b, HOMEBUS_ATTR_DATA);
	blobmsg_add_u32(&b, "id", obj->id.id);
	blobmsg_add_string(&b, "path", obj->path.key);
	blob_nest_end(&b, s);

	return homebus_msg_new(b.head, blob_raw_len(b.head), true);
}

void homebusd_send_obj_event(struct homebus_object *obj, bool add)
{
	const char *id = add ? "homebus.object.add" : "homebus.object.remove";

	homebusd_send_event(NULL, id, homebusd_create_object_event_msg, obj);
}

void homebusd_event_init(void)
{
	homebus_init_string_tree(&patterns, true);
	event_obj = homebusd_create_object_internal(NULL, HOMEBUS_SYSTEM_OBJECT_EVENT);
	if (event_obj != NULL)
		event_obj->recv_msg = homebusd_event_recv;
}

