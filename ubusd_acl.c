/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
 * Copyright (C) 2018 Hans Dedecker <dedeckeh@gmail.com>
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

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <syslog.h>
#include <unistd.h>
#include <glob.h>
#include <grp.h>
#include <pwd.h>

#include <libubox/vlist.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl-cmp.h>
#include <libubox/ulog.h>

#include "homebusd.h"

#ifndef SO_PEERCRED
struct ucred {
	int pid;
	int uid;
	int gid;
};
#endif

struct homebusd_acl_obj {
	struct avl_node avl;
	struct list_head list;

	bool partial;

	const char *user;
	const char *group;

	struct blob_attr *methods;
	struct blob_attr *tags;
	struct blob_attr *priv;
	bool subscribe;
	bool publish;
	bool listen;
	bool send;
};

struct homebusd_acl_file {
	struct vlist_node avl;

	const char *user;
	const char *group;

	struct blob_attr *blob;
	struct list_head acl;

	int ok;
};

const char *homebusd_acl_dir = "/usr/share/acl.d";
static struct blob_buf bbuf;
static struct avl_tree homebusd_acls;
static int homebusd_acl_seq;
static struct homebus_object *acl_obj;

static int
homebusd_acl_match_cred(struct homebus_client *cl, struct homebusd_acl_obj *obj)
{
	if (obj->user && !strcmp(cl->user, obj->user))
		return 0;

	if (obj->group && !strcmp(cl->group, obj->group))
		return 0;

	return -1;
}

int
homebusd_acl_check(struct homebus_client *cl, const char *obj,
		const char *method, enum homebusd_acl_type type)
{
	struct homebusd_acl_obj *acl;
	int match_len = 0;

	if (!cl || !cl->uid || !obj)
		return 0;

	/*
	 * Since this tree is sorted alphabetically, we can only expect
	 * to find matching entries as long as the number of matching
	 * characters between the access list string and the object path
	 * is monotonically increasing.
	 */
	avl_for_each_element(&homebusd_acls, acl, avl) {
		const char *key = acl->avl.key;
		int cur_match_len;
		bool full_match;

		full_match = homebus_strmatch_len(obj, key, &cur_match_len);
		if (cur_match_len < match_len)
			break;

		match_len = cur_match_len;

		if (!full_match) {
			if (!acl->partial)
				continue;

			if (match_len != (int) strlen(key))
				continue;
		}

		if (homebusd_acl_match_cred(cl, acl))
			continue;

		switch (type) {
		case HOMEBUS_ACL_PUBLISH:
			if (acl->publish)
				return 0;
			break;

		case HOMEBUS_ACL_SUBSCRIBE:
			if (acl->subscribe)
				return 0;
			break;

		case HOMEBUS_ACL_LISTEN:
			if (acl->listen)
				return 0;
			break;

		case HOMEBUS_ACL_SEND:
			if (acl->send)
				return 0;
			break;

		case HOMEBUS_ACL_ACCESS:
			if (acl->methods) {
				struct blob_attr *cur;
				char *cur_method;
				size_t rem;

				blobmsg_for_each_attr(cur, acl->methods, rem)
					if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
						cur_method = blobmsg_get_string(cur);

						if (!strcmp(method, cur_method) || !strcmp("*", cur_method))
							return 0;
					}
			}
			break;
		}
	}

	return -1;
}

int
homebusd_acl_init_client(struct homebus_client *cl, int fd)
{
	struct ucred cred;
	struct passwd *pwd;
	struct group *group;

#ifdef SO_PEERCRED
	unsigned int len = sizeof(struct ucred);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
		ULOG_ERR("Failed getsockopt(): %m\n");
		return -1;
	}
#else
	memset(&cred, 0, sizeof(cred));
#endif

	pwd = getpwuid(cred.uid);
	if (!pwd) {
		ULOG_ERR("Failed getpwuid(): %m\n");
		return -1;
	}

	group = getgrgid(cred.gid);
	if (!group) {
		ULOG_ERR("Failed getgrgid(): %m\n");
		return -1;
	}

	cl->uid = cred.uid;
	cl->gid = cred.gid;

	cl->group = strdup(group->gr_name);
	cl->user = strdup(pwd->pw_name);

	return 0;
}

void
homebusd_acl_free_client(struct homebus_client *cl)
{
	free(cl->group);
	free(cl->user);
}

static void
homebusd_acl_file_free(struct homebusd_acl_file *file)
{
	struct homebusd_acl_obj *p, *q;

	list_for_each_entry_safe(p, q, &file->acl, list) {
		avl_delete(&homebusd_acls, &p->avl);
		list_del(&p->list);
		free(p);
	}

	free(file);
}

enum {
	ACL_ACCESS_METHODS,
	ACL_ACCESS_TAGS,
	ACL_ACCESS_PRIV,
	__ACL_ACCESS_MAX
};

static const struct blobmsg_policy acl_obj_policy[__ACL_ACCESS_MAX] = {
	[ACL_ACCESS_METHODS] = { .name = "methods", .type = BLOBMSG_TYPE_ARRAY },
	[ACL_ACCESS_TAGS] = { .name = "tags", .type = BLOBMSG_TYPE_ARRAY },
	[ACL_ACCESS_PRIV] = { .name = "acl", .type = BLOBMSG_TYPE_TABLE },
};

static struct homebusd_acl_obj*
homebusd_acl_alloc_obj(struct homebusd_acl_file *file, const char *obj)
{
	struct homebusd_acl_obj *o;
	int len = strlen(obj);
	char *k;
	bool partial = false;

	if (obj[len - 1] == '*') {
		partial = true;
		len--;
	}

	o = calloc_a(sizeof(*o), &k, len + 1);
	o->partial = partial;
	o->user = file->user;
	o->group = file->group;
	o->avl.key = memcpy(k, obj, len);

	list_add(&o->list, &file->acl);
	avl_insert(&homebusd_acls, &o->avl);

	return o;
}

static void
homebusd_acl_add_access(struct homebusd_acl_file *file, struct blob_attr *obj)
{
	struct blob_attr *tb[__ACL_ACCESS_MAX];
	struct homebusd_acl_obj *o;

	blobmsg_parse(acl_obj_policy, __ACL_ACCESS_MAX, tb, blobmsg_data(obj),
		      blobmsg_data_len(obj));

	if (!tb[ACL_ACCESS_METHODS] && !tb[ACL_ACCESS_TAGS] && !tb[ACL_ACCESS_PRIV])
		return;

	o = homebusd_acl_alloc_obj(file, blobmsg_name(obj));

	o->methods = tb[ACL_ACCESS_METHODS];
	o->tags = tb[ACL_ACCESS_TAGS];
	o->priv = tb[ACL_ACCESS_PRIV];

	if (file->user || file->group)
		file->ok = 1;
}

static void
homebusd_acl_add_subscribe(struct homebusd_acl_file *file, const char *obj)
{
	struct homebusd_acl_obj *o = homebusd_acl_alloc_obj(file, obj);

	o->subscribe = true;
}

static void
homebusd_acl_add_publish(struct homebusd_acl_file *file, const char *obj)
{
	struct homebusd_acl_obj *o = homebusd_acl_alloc_obj(file, obj);

	o->publish = true;
}

static void homebusd_acl_add_listen(struct homebusd_acl_file *file, const char *obj)
{
	struct homebusd_acl_obj *o = homebusd_acl_alloc_obj(file, obj);

	o->listen = true;
}

static void homebusd_acl_add_send(struct homebusd_acl_file *file, const char *obj)
{
	struct homebusd_acl_obj *o = homebusd_acl_alloc_obj(file, obj);

	o->send = true;
}

enum {
	ACL_USER,
	ACL_GROUP,
	ACL_ACCESS,
	ACL_PUBLISH,
	ACL_SUBSCRIBE,
	ACL_INHERIT,
	ACL_LISTEN,
	ACL_SEND,
	__ACL_MAX
};

static const struct blobmsg_policy acl_policy[__ACL_MAX] = {
	[ACL_USER] = { .name = "user", .type = BLOBMSG_TYPE_STRING },
	[ACL_GROUP] = { .name = "group", .type = BLOBMSG_TYPE_STRING },
	[ACL_ACCESS] = { .name = "access", .type = BLOBMSG_TYPE_TABLE },
	[ACL_PUBLISH] = { .name = "publish", .type = BLOBMSG_TYPE_ARRAY },
	[ACL_SUBSCRIBE] = { .name = "subscribe", .type = BLOBMSG_TYPE_ARRAY },
	[ACL_INHERIT] = { .name = "inherit", .type = BLOBMSG_TYPE_ARRAY },
	[ACL_LISTEN] = { .name= "listen", .type = BLOBMSG_TYPE_ARRAY },
	[ACL_SEND] = { .name= "send", .type = BLOBMSG_TYPE_ARRAY },
};

static void
homebusd_acl_file_add(struct homebusd_acl_file *file)
{
	struct blob_attr *tb[__ACL_MAX], *cur;
	size_t rem;

	blobmsg_parse(acl_policy, __ACL_MAX, tb, blob_data(file->blob),
		      blob_len(file->blob));

	if (tb[ACL_USER])
		file->user = blobmsg_get_string(tb[ACL_USER]);
	else if (tb[ACL_GROUP])
		file->group = blobmsg_get_string(tb[ACL_GROUP]);
	else
		return;

	if (tb[ACL_ACCESS])
		blobmsg_for_each_attr(cur, tb[ACL_ACCESS], rem)
			homebusd_acl_add_access(file, cur);

	if (tb[ACL_SUBSCRIBE])
		blobmsg_for_each_attr(cur, tb[ACL_SUBSCRIBE], rem)
			if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
				homebusd_acl_add_subscribe(file, blobmsg_get_string(cur));

	if (tb[ACL_PUBLISH])
		blobmsg_for_each_attr(cur, tb[ACL_PUBLISH], rem)
			if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
				homebusd_acl_add_publish(file, blobmsg_get_string(cur));

	if (tb[ACL_LISTEN])
		blobmsg_for_each_attr(cur, tb[ACL_LISTEN], rem)
			if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
				homebusd_acl_add_listen(file, blobmsg_get_string(cur));

	if (tb[ACL_SEND])
		blobmsg_for_each_attr(cur, tb[ACL_SEND], rem)
			if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
				homebusd_acl_add_send(file, blobmsg_get_string(cur));
}

static void
homebusd_acl_update_cb(struct vlist_tree *tree, struct vlist_node *node_new,
	struct vlist_node *node_old)
{
	struct homebusd_acl_file *file;

	if (node_old) {
		file = container_of(node_old, struct homebusd_acl_file, avl);
		homebusd_acl_file_free(file);
	}

	if (node_new) {
		file = container_of(node_new, struct homebusd_acl_file, avl);
		homebusd_acl_file_add(file);
	}
}

static struct homebus_msg_buf *
homebusd_create_sequence_event_msg(void *priv, const char *id)
{
	void *s;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, 0);
	blob_put_string(&b, HOMEBUS_ATTR_METHOD, id);
	s = blob_nest_start(&b, HOMEBUS_ATTR_DATA);
	blobmsg_add_u32(&b, "sequence", homebusd_acl_seq);
	blob_nest_end(&b, s);

	return homebus_msg_new(b.head, blob_raw_len(b.head), true);
}

static VLIST_TREE(homebusd_acl_files, avl_strcmp, homebusd_acl_update_cb, false, false);

static int
homebusd_acl_load_file(const char *filename)
{
	struct homebusd_acl_file *file;
	void *blob;

	blob_buf_init(&bbuf, 0);
	if (!blobmsg_add_json_from_file(&bbuf, filename)) {
		syslog(LOG_ERR, "failed to parse %s\n", filename);
		return -1;
	}

	file = calloc_a(sizeof(*file), &blob, blob_raw_len(bbuf.head));
	if (!file)
		return -1;

	file->blob = blob;

	memcpy(blob, bbuf.head, blob_raw_len(bbuf.head));
	INIT_LIST_HEAD(&file->acl);

	vlist_add(&homebusd_acl_files, &file->avl, filename);
	syslog(LOG_INFO, "loading %s\n", filename);

	return 0;
}

void
homebusd_acl_load(void)
{
	struct stat st;
	glob_t gl;
	size_t j;
	const char *suffix = "/*.json";
	char *path = alloca(strlen(homebusd_acl_dir) + strlen(suffix) + 1);

	sprintf(path, "%s%s", homebusd_acl_dir, suffix);
	if (glob(path, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl))
		return;

	vlist_update(&homebusd_acl_files);
	for (j = 0; j < gl.gl_pathc; j++) {
		if (stat(gl.gl_pathv[j], &st) || !S_ISREG(st.st_mode))
			continue;

		if (st.st_uid || st.st_gid) {
			syslog(LOG_ERR, "%s has wrong owner\n", gl.gl_pathv[j]);
			continue;
		}
		if (st.st_mode & (S_IWOTH | S_IWGRP | S_IXOTH)) {
			syslog(LOG_ERR, "%s has wrong permissions\n", gl.gl_pathv[j]);
			continue;
		}
		homebusd_acl_load_file(gl.gl_pathv[j]);
	}

	globfree(&gl);
	vlist_flush(&homebusd_acl_files);
	homebusd_acl_seq++;
	homebusd_send_event(NULL, "homebus.acl.sequence", homebusd_create_sequence_event_msg, NULL);
}

static void
homebusd_reply_add(struct homebus_object *obj)
{
	struct homebusd_acl_obj *acl;
	int match_len = 0;

	if (!obj->path.key)
		return;

	/*
	 * Since this tree is sorted alphabetically, we can only expect
	 * to find matching entries as long as the number of matching
	 * characters between the access list string and the object path
	 * is monotonically increasing.
	 */
	avl_for_each_element(&homebusd_acls, acl, avl) {
		const char *key = acl->avl.key;
		int cur_match_len;
		bool full_match;
		void *c;

		if (!acl->priv)
			continue;

		full_match = homebus_strmatch_len(obj->path.key, key, &cur_match_len);
		if (cur_match_len < match_len)
			break;

		match_len = cur_match_len;

		if (!full_match) {
			if (!acl->partial)
				continue;

			if (match_len != (int) strlen(key))
				continue;
		}

		c = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "obj", obj->path.key);
		if (acl->user)
			blobmsg_add_string(&b, "user", acl->user);
		if (acl->group)
			blobmsg_add_string(&b, "group", acl->group);

		blobmsg_add_field(&b, blobmsg_type(acl->priv), "acl",
			blobmsg_data(acl->priv), blobmsg_data_len(acl->priv));

		blobmsg_close_table(&b, c);
	}
}

static int homebusd_reply_query(struct homebus_client *cl, struct homebus_msg_buf *ub, struct blob_attr **attr, struct blob_attr *msg)
{
	struct homebus_object *obj;
	void *d, *a;

	if (!attr[HOMEBUS_ATTR_OBJID])
		return HOMEBUS_STATUS_INVALID_ARGUMENT;

	obj = homebusd_find_object(blob_get_u32(attr[HOMEBUS_ATTR_OBJID]));
	if (!obj)
		return HOMEBUS_STATUS_NOT_FOUND;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, HOMEBUS_ATTR_OBJID, obj->id.id);
	d = blob_nest_start(&b, HOMEBUS_ATTR_DATA);

	blobmsg_add_u32(&b, "seq", homebusd_acl_seq);
	a = blobmsg_open_array(&b, "acl");
	list_for_each_entry(obj, &cl->objects, list)
		homebusd_reply_add(obj);
	blobmsg_close_table(&b, a);

	blob_nest_end(&b, d);

	homebus_proto_send_msg_from_blob(cl, ub, HOMEBUS_MSG_DATA);

	return 0;
}

static int homebusd_acl_recv(struct homebus_client *cl, struct homebus_msg_buf *ub, const char *method, struct blob_attr *msg)
{
	if (!strcmp(method, "query"))
		return homebusd_reply_query(cl, ub, homebus_parse_msg(ub->data, blob_raw_len(ub->data)), msg);

	return HOMEBUS_STATUS_INVALID_COMMAND;
}

void homebusd_acl_init(void)
{
	homebus_init_string_tree(&homebusd_acls, true);
	acl_obj = homebusd_create_object_internal(NULL, HOMEBUS_SYSTEM_OBJECT_ACL);
	acl_obj->recv_msg = homebusd_acl_recv;
}
