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

#include <arpa/inet.h>
#include <unistd.h>

#include "homebusd.h"

struct blob_buf b;
static struct avl_tree clients;

static struct blob_attr *attrbuf[HOMEBUS_ATTR_MAX];

typedef int (*homebus_cmd_cb)(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr);

static const struct blob_attr_info homebus_policy[HOMEBUS_ATTR_MAX] = {
	[HOMEBUS_ATTR_SIGNATURE] = { .type = BLOB_ATTR_NESTED },
	[HOMEBUS_ATTR_OBJTYPE] = { .type = BLOB_ATTR_INT32 },
	[HOMEBUS_ATTR_OBJPATH] = { .type = BLOB_ATTR_STRING },
	[HOMEBUS_ATTR_OBJID] = { .type = BLOB_ATTR_INT32 },
	[HOMEBUS_ATTR_STATUS] = { .type = BLOB_ATTR_INT32 },
	[HOMEBUS_ATTR_METHOD] = { .type = BLOB_ATTR_STRING },
	[HOMEBUS_ATTR_USER] = { .type = BLOB_ATTR_STRING },
	[HOMEBUS_ATTR_GROUP] = { .type = BLOB_ATTR_STRING },
};

struct blob_attr **homebus_parse_msg(struct blob_attr *msg, size_t len)
{
	blob_parse_untrusted(msg, len, attrbuf, homebus_policy, HOMEBUS_ATTR_MAX);
	return attrbuf;
}

static void homebus_msg_close_fd(struct homebus_msg_buf *ub)
{
	if (ub->fd < 0)
		return;

	close(ub->fd);
	ub->fd = -1;
}

static void homebus_msg_init(struct homebus_msg_buf *ub, uint8_t type, uint16_t seq, uint32_t peer)
{
	ub->hdr.version = 0;
	ub->hdr.type = type;
	ub->hdr.seq = seq;
	ub->hdr.peer = peer;
}

static struct homebus_msg_buf *homebus_msg_from_blob(bool shared)
{
	return homebus_msg_new(b.head, blob_raw_len(b.head), shared);
}

static struct homebus_msg_buf *homebus_reply_from_blob(struct homebus_msg_buf *ub, bool shared)
{
	struct homebus_msg_buf *new;

	new = homebus_msg_from_blob(shared);
	if (!new)
		return NULL;

	homebus_msg_init(new, HOMEBUS_MSG_DATA, ub->hdr.seq, ub->hdr.peer);
	return new;
}

void
homebus_proto_send_msg_from_blob(struct homebus_client *cl, struct homebus_msg_buf *ub,
			uint8_t type)
{
	/* keep the fd to be passed if it is HOMEBUS_MSG_INVOKE */
	int fd = ub->fd;
	ub = homebus_reply_from_blob(ub, true);
	if (!ub)
		return;

	ub->hdr.type = type;
	ub->fd = fd;

	homebus_msg_send(cl, ub);
	homebus_msg_free(ub);
}

static bool homebusd_send_hello(struct homebus_client *cl)
{
	struct homebus_msg_buf *ub;

	blob_buf_init(&b, 0);
	ub = homebus_msg_from_blob(true);
	if (!ub)
		return false;

	homebus_msg_init(ub, HOMEBUS_MSG_HELLO, 0, cl->id.id);
	homebus_msg_send(cl, ub);
	homebus_msg_free(ub);
	return true;
}

static int homebusd_send_pong(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	ub->hdr.type = HOMEBUS_MSG_DATA;
	homebus_msg_send(cl, ub);
	return 0;
}

static int homebusd_handle_remove_object(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	struct homebus_object *obj;

	if (!attr[HOMEBUS_ATTR_OBJID])
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	obj = homebusd_find_object(blob_get_u32(attr[HOMEBUS_ATTR_OBJID]));
	if (!obj)
		return HOMEBUS_STATUS_NOT_FOUND;

	if (obj->client != cl)
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id.id);

	/* check if we're removing the object type as well */
	if (obj->type && obj->type->refcount == 1)
		blob_put_int32(&b, HOMEBUS_ATTR_OBJTYPE, obj->type->id.id);

	homebus_proto_send_msg_from_blob(cl, ub, HOMEBUS_MSG_DATA);
	homebusd_free_object(obj);

	return 0;
}

static int homebusd_handle_add_object(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	struct homebus_object *obj;

	obj = homebusd_create_object(cl, attr);
	if (!obj)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id.id);
	if (attr[HOMEBUS_ATTR_SIGNATURE] && obj->type)
		blob_put_int32(&b, HOMEBUS_ATTR_OBJTYPE, obj->type->id.id);

	homebus_proto_send_msg_from_blob(cl, ub, HOMEBUS_MSG_DATA);
	return 0;
}

static void homebusd_send_obj(struct homebus_client *cl, struct homebus_msg_buf *ub, struct homebus_object *obj)
{
	struct homebus_method *m;
	int all_cnt = 0, cnt = 0;
	void *s;

	if (!obj->type)
		return;

	blob_buf_init(&b, 0);

	blob_put_string(&b, HOMEBUS_ATTR_OBJPATH, obj->path.key);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id.id);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJTYPE, obj->type->id.id);

	s = blob_nest_start(&b, HOMEBUS_ATTR_SIGNATURE);
	list_for_each_entry(m, &obj->type->methods, list) {
		all_cnt++;
		if (!homebusd_acl_check(cl, obj->path.key, blobmsg_name(m->data), HOMEBUS_ACL_ACCESS)) {
			blobmsg_add_blob(&b, m->data);
			cnt++;
		}
	}
	blob_nest_end(&b, s);

	if (cnt || !all_cnt)
		homebus_proto_send_msg_from_blob(cl, ub, HOMEBUS_MSG_DATA);
}

static int homebus_client_cmd_queue_add(struct homebus_client *cl,
					struct homebus_msg_buf *msg,
					struct homebus_object *obj)
{
	struct homebus_client_cmd *cmd = malloc(sizeof(*cmd));

	if (cmd) {
		cmd->msg = msg;
		cmd->obj = obj;
		list_add_tail(&cmd->list, &cl->cmd_queue);
		return -2;
	}
	return HOMEBUS_STATUS_UNKNOWN_ERROR;
}

static int __homebusd_handle_lookup(struct homebus_client *cl,
				struct homebus_msg_buf *ub,
				struct blob_attr **attr,
				struct homebus_client_cmd *cmd)
{
	struct homebus_object *obj = NULL;
	char *objpath;
	bool found = false;
	int len;

	if (!attr[HOMEBUS_ATTR_OBJPATH]) {
		if (cmd)
			obj = cmd->obj;

		/* Start from beginning or continue from the last object */
		if (obj == NULL)
			obj = avl_first_element(&path, obj, path);

		avl_for_element_range(obj, avl_last_element(&path, obj, path), obj, path) {
			/* Keep sending objects until buffering starts */
			if (list_empty(&cl->tx_queue)) {
				homebusd_send_obj(cl, ub, obj);
			} else {
				/* Queue command and continue on the next call */
				int ret;

				if (cmd == NULL) {
					ret = homebus_client_cmd_queue_add(cl, ub, obj);
				} else {
					cmd->obj = obj;
					ret = -2;
				}
				return ret;
			}
		}
		return 0;
	}

	objpath = blob_data(attr[HOMEBUS_ATTR_OBJPATH]);
	len = strlen(objpath);
	if (objpath[len - 1] != '*') {
		obj = avl_find_element(&path, objpath, obj, path);
		if (!obj)
			return HOMEBUS_STATUS_NOT_FOUND;

		homebusd_send_obj(cl, ub, obj);
		return 0;
	}

	objpath[--len] = 0;

	obj = avl_find_ge_element(&path, objpath, obj, path);
	if (!obj)
		return HOMEBUS_STATUS_NOT_FOUND;

	while (!strncmp(objpath, obj->path.key, len)) {
		found = true;
		homebusd_send_obj(cl, ub, obj);
		if (obj == avl_last_element(&path, obj, path))
			break;
		obj = avl_next_element(obj, path);
	}

	if (!found)
		return HOMEBUS_STATUS_NOT_FOUND;

	return 0;
}

static int homebusd_handle_lookup(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	int rc;

	if (list_empty(&cl->tx_queue))
		rc = __homebusd_handle_lookup(cl, ub, attr, NULL);
	else
		rc = homebus_client_cmd_queue_add(cl, ub, NULL);

	return rc;
}

int homebusd_cmd_lookup(struct homebus_client *cl, struct homebus_client_cmd *cmd)
{
	struct homebus_msg_buf *ub = cmd->msg;
	struct blob_attr **attr;
	int ret;

	attr = homebus_parse_msg(ub->data, blob_raw_len(ub->data));
	ret = __homebusd_handle_lookup(cl, ub, attr, cmd);

	if (ret != -2) {
		struct homebus_msg_buf *retmsg = cl->retmsg;
		int *retmsg_data = blob_data(blob_data(retmsg->data));

		retmsg->hdr.seq = ub->hdr.seq;
		retmsg->hdr.peer = ub->hdr.peer;

		*retmsg_data = htonl(ret);
		homebus_msg_send(cl, retmsg);
	}
	return ret;
}

static void
homebusd_forward_invoke(struct homebus_client *cl, struct homebus_object *obj,
		     const char *method, struct homebus_msg_buf *ub,
		     struct blob_attr *data)
{
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id.id);
	blob_put_string(&b, HOMEBUS_ATTR_METHOD, method);
	if (cl->user)
		blob_put_string(&b, HOMEBUS_ATTR_USER, cl->user);
	if (cl->group)
		blob_put_string(&b, HOMEBUS_ATTR_GROUP, cl->group);
	if (data)
		blob_put(&b, HOMEBUS_ATTR_DATA, blob_data(data), blob_len(data));

	homebus_proto_send_msg_from_blob(obj->client, ub, HOMEBUS_MSG_INVOKE);
}

static int homebusd_handle_invoke(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	struct homebus_object *obj = NULL;
	struct homebus_id *id;
	const char *method;

	if (!attr[HOMEBUS_ATTR_METHOD] || !attr[HOMEBUS_ATTR_OBJID])
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	id = homebus_find_id(&objects, blob_get_u32(attr[HOMEBUS_ATTR_OBJID]));
	if (!id)
		return HOMEBUS_STATUS_NOT_FOUND;

	obj = container_of(id, struct homebus_object, id);

	method = blob_data(attr[HOMEBUS_ATTR_METHOD]);

	if (homebusd_acl_check(cl, obj->path.key, method, HOMEBUS_ACL_ACCESS))
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	if (!obj->client)
		return obj->recv_msg(cl, ub, method, attr[HOMEBUS_ATTR_DATA]);

	ub->hdr.peer = cl->id.id;
	blob_buf_init(&b, 0);

	homebusd_forward_invoke(cl, obj, method, ub, attr[HOMEBUS_ATTR_DATA]);

	return -1;
}

static int homebusd_handle_notify(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	struct homebus_object *obj = NULL;
	struct homebus_subscription *s;
	struct homebus_id *id;
	const char *method;
	bool no_reply = false;
	void *c;

	if (!attr[HOMEBUS_ATTR_METHOD] || !attr[HOMEBUS_ATTR_OBJID])
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	if (attr[HOMEBUS_ATTR_NO_REPLY])
		no_reply = blob_get_int8(attr[HOMEBUS_ATTR_NO_REPLY]);

	id = homebus_find_id(&objects, blob_get_u32(attr[HOMEBUS_ATTR_OBJID]));
	if (!id)
		return HOMEBUS_STATUS_NOT_FOUND;

	obj = container_of(id, struct homebus_object, id);
	if (obj->client != cl)
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	if (!no_reply) {
		blob_buf_init(&b, 0);
		blob_put_int32(&b, HOMEBUS_ATTR_OBJID, id->id);
		c = blob_nest_start(&b, HOMEBUS_ATTR_SUBSCRIBERS);
		list_for_each_entry(s, &obj->subscribers, list) {
			blob_put_int32(&b, 0, s->subscriber->id.id);
		}
		blob_nest_end(&b, c);
		blob_put_int32(&b, HOMEBUS_ATTR_STATUS, 0);
		homebus_proto_send_msg_from_blob(cl, ub, HOMEBUS_MSG_STATUS);
	}

	ub->hdr.peer = cl->id.id;
	method = blob_data(attr[HOMEBUS_ATTR_METHOD]);
	list_for_each_entry(s, &obj->subscribers, list) {
		blob_buf_init(&b, 0);
		if (no_reply)
			blob_put_int8(&b, HOMEBUS_ATTR_NO_REPLY, 1);
		homebusd_forward_invoke(cl, s->subscriber, method, ub, attr[HOMEBUS_ATTR_DATA]);
	}

	return -1;
}

static struct homebus_client *homebusd_get_client_by_id(uint32_t id)
{
	struct homebus_id *clid;

	clid = homebus_find_id(&clients, id);
	if (!clid)
		return NULL;

	return container_of(clid, struct homebus_client, id);
}

static int homebusd_handle_response(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	struct homebus_object *obj;

	if (!attr[HOMEBUS_ATTR_OBJID] ||
	    (ub->hdr.type == HOMEBUS_MSG_STATUS && !attr[HOMEBUS_ATTR_STATUS]) ||
	    (ub->hdr.type == HOMEBUS_MSG_DATA && !attr[HOMEBUS_ATTR_DATA]))
		goto out;

	obj = homebusd_find_object(blob_get_u32(attr[HOMEBUS_ATTR_OBJID]));
	if (!obj)
		goto out;

	if (cl != obj->client)
		goto out;

	cl = homebusd_get_client_by_id(ub->hdr.peer);
	if (!cl)
		goto out;

	ub->hdr.peer = blob_get_u32(attr[HOMEBUS_ATTR_OBJID]);
	homebus_msg_send(cl, ub);
out:
	return -1;
}

static int homebusd_handle_add_watch(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	struct homebus_object *obj, *target;

	if (!attr[HOMEBUS_ATTR_OBJID] || !attr[HOMEBUS_ATTR_TARGET])
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	obj = homebusd_find_object(blob_get_u32(attr[HOMEBUS_ATTR_OBJID]));
	if (!obj)
		return HOMEBUS_STATUS_NOT_FOUND;

	if (cl != obj->client)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	target = homebusd_find_object(blob_get_u32(attr[HOMEBUS_ATTR_TARGET]));
	if (!target || !target->client)
		return HOMEBUS_STATUS_NOT_FOUND;

	if (cl == target->client)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	if (!target->path.key) {
		if (strcmp(target->client->user, cl->user) && strcmp(target->client->group, cl->group))
			return HOMEBUS_STATUS_NOT_FOUND;
	} else if (homebusd_acl_check(cl, target->path.key, NULL, HOMEBUS_ACL_SUBSCRIBE)) {
		return HOMEBUS_STATUS_NOT_FOUND;
	}

	homebus_subscribe(obj, target);
	return 0;
}

static int homebusd_handle_remove_watch(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr)
{
	struct homebus_object *obj;
	struct homebus_subscription *s;
	uint32_t id;

	if (!attr[HOMEBUS_ATTR_OBJID] || !attr[HOMEBUS_ATTR_TARGET])
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	obj = homebusd_find_object(blob_get_u32(attr[HOMEBUS_ATTR_OBJID]));
	if (!obj)
		return HOMEBUS_STATUS_NOT_FOUND;

	if (cl != obj->client)
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	id = blob_get_u32(attr[HOMEBUS_ATTR_TARGET]);
	list_for_each_entry(s, &obj->target_list, target_list) {
		if (s->target->id.id != id)
			continue;

		homebus_unsubscribe(s);
		return 0;
	}

	return HOMEBUS_STATUS_NOT_FOUND;
}

static const homebus_cmd_cb handlers[__HOMEBUS_MSG_LAST] = {
	[HOMEBUS_MSG_PING] = homebusd_send_pong,
	[HOMEBUS_MSG_ADD_OBJECT] = homebusd_handle_add_object,
	[HOMEBUS_MSG_REMOVE_OBJECT] = homebusd_handle_remove_object,
	[HOMEBUS_MSG_LOOKUP] = homebusd_handle_lookup,
	[HOMEBUS_MSG_INVOKE] = homebusd_handle_invoke,
	[HOMEBUS_MSG_STATUS] = homebusd_handle_response,
	[HOMEBUS_MSG_DATA] = homebusd_handle_response,
	[HOMEBUS_MSG_SUBSCRIBE] = homebusd_handle_add_watch,
	[HOMEBUS_MSG_UNSUBSCRIBE] = homebusd_handle_remove_watch,
	[HOMEBUS_MSG_NOTIFY] = homebusd_handle_notify,
};

void homebusd_proto_receive_message(struct homebus_client *cl, struct homebus_msg_buf *ub)
{
	homebus_cmd_cb cb = NULL;
	int ret;
	struct homebus_msg_buf *retmsg = cl->retmsg;
	int *retmsg_data = blob_data(blob_data(retmsg->data));

	retmsg->hdr.seq = ub->hdr.seq;
	retmsg->hdr.peer = ub->hdr.peer;

	if (ub->hdr.type < __HOMEBUS_MSG_LAST)
		cb = handlers[ub->hdr.type];

	if (ub->hdr.type != HOMEBUS_MSG_STATUS && ub->hdr.type != HOMEBUS_MSG_INVOKE)
		homebus_msg_close_fd(ub);

	/* Note: no callback should free the `ub` buffer
	         that's always done right after the callback finishes */
	if (cb)
		ret = cb(cl, ub, homebus_parse_msg(ub->data, blob_raw_len(ub->data)));
	else
		ret = HOMEBUS_STATUS_INVALID_COMMAND;

	/* Command has not been completed yet and got queued */
	if (ret == -2)
		return;

	homebus_msg_free(ub);

	if (ret == -1)
		return;

	*retmsg_data = htonl(ret);
	homebus_msg_send(cl, retmsg);
}

static int homebusd_proto_init_retmsg(struct homebus_client *cl)
{
	struct blob_buf *b = &cl->b;

	blob_buf_init(&cl->b, 0);
	blob_put_int32(&cl->b, HOMEBUS_ATTR_STATUS, 0);

	/* we make the 'retmsg' buffer shared with the blob_buf b, to reduce mem duplication */
	cl->retmsg = homebus_msg_new(b->head, blob_raw_len(b->head), true);
	if (!cl->retmsg)
		return -1;

	cl->retmsg->hdr.type = HOMEBUS_MSG_STATUS;
	return 0;
}

struct homebus_client *homebusd_proto_new_client(int fd, uloop_fd_handler cb)
{
	struct homebus_client *cl;

	cl = calloc(1, sizeof(*cl));
	if (!cl)
		return NULL;

	if (homebusd_acl_init_client(cl, fd))
		goto free;

	INIT_LIST_HEAD(&cl->objects);
	INIT_LIST_HEAD(&cl->cmd_queue);
	INIT_LIST_HEAD(&cl->tx_queue);
	cl->sock.fd = fd;
	cl->sock.cb = cb;
	cl->pending_msg_fd = -1;

	if (!homebus_alloc_id(&clients, &cl->id, 0))
		goto free;

	if (homebusd_proto_init_retmsg(cl))
		goto free;

	if (!homebusd_send_hello(cl))
		goto delete;

	return cl;

delete:
	homebus_free_id(&clients, &cl->id);
free:
	free(cl);
	return NULL;
}

void homebusd_proto_free_client(struct homebus_client *cl)
{
	struct homebus_object *obj, *tmp;

	list_for_each_entry_safe(obj, tmp, &cl->objects, list) {
		homebusd_free_object(obj);
	}

	homebus_msg_free(cl->retmsg);
	blob_buf_free(&cl->b);

	homebusd_acl_free_client(cl);
	homebus_free_id(&clients, &cl->id);
}

void homebus_notify_subscription(struct homebus_object *obj)
{
	bool active = !list_empty(&obj->subscribers);
	struct homebus_msg_buf *ub;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id.id);
	blob_put_int8(&b, HOMEBUS_ATTR_ACTIVE, active);

	ub = homebus_msg_from_blob(false);
	if (!ub)
		return;

	homebus_msg_init(ub, HOMEBUS_MSG_NOTIFY, ++obj->invoke_seq, 0);
	homebus_msg_send(obj->client, ub);
	homebus_msg_free(ub);
}

void homebus_notify_unsubscribe(struct homebus_subscription *s)
{
	struct homebus_msg_buf *ub;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, s->subscriber->id.id);
	blob_put_int32(&b, HOMEBUS_ATTR_TARGET, s->target->id.id);

	ub = homebus_msg_from_blob(false);
	if (ub != NULL) {
		homebus_msg_init(ub, HOMEBUS_MSG_UNSUBSCRIBE, ++s->subscriber->invoke_seq, 0);
		homebus_msg_send(s->subscriber->client, ub);
		homebus_msg_free(ub);
	}

	homebus_unsubscribe(s);
}

static void __constructor homebusd_proto_init(void)
{
	homebus_init_id_tree(&clients);
}
