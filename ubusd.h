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

#ifndef __HOMEBUSD_H
#define __HOMEBUSD_H

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include "homebus_common.h"
#include "homebusd_id.h"
#include "homebusd_obj.h"
#include "homebusmsg.h"
#include "homebusd_acl.h"

#define HOMEBUS_OBJ_HASH_BITS	4
#define HOMEBUS_CLIENT_MAX_TXQ_LEN	HOMEBUS_MAX_MSGLEN

extern struct blob_buf b;

struct homebus_msg_buf {
	uint32_t refcount; /* ~0: uses external data buffer */
	struct homebus_msghdr hdr;
	struct blob_attr *data;
	int fd;
	int len;
};

struct homebus_msg_buf_list {
	struct list_head list;
	struct homebus_msg_buf *msg;
};

struct homebus_client_cmd {
	struct list_head list;
	struct homebus_msg_buf *msg;
	struct homebus_object *obj;
};

struct homebus_client {
	struct homebus_id id;
	struct uloop_fd sock;
	struct blob_buf b;

	uid_t uid;
	gid_t gid;
	char *user;
	char *group;

	struct list_head objects;

	struct list_head cmd_queue;
	struct list_head tx_queue;
	unsigned int txq_ofs;
	unsigned int txq_len;

	struct homebus_msg_buf *pending_msg;
	struct homebus_msg_buf *retmsg;
	int pending_msg_offset;
	int pending_msg_fd;
	struct {
		struct homebus_msghdr hdr;
		struct blob_attr data;
	} hdrbuf;
};

struct homebus_path {
	struct list_head list;
	const char name[];
};

extern const char *homebusd_acl_dir;

struct homebus_msg_buf *homebus_msg_new(void *data, int len, bool shared);
void homebus_msg_send(struct homebus_client *cl, struct homebus_msg_buf *ub);
ssize_t homebus_msg_writev(int fd, struct homebus_msg_buf *ub, size_t offset);
void homebus_msg_free(struct homebus_msg_buf *ub);
void homebus_msg_list_free(struct homebus_msg_buf_list *ubl);
struct blob_attr **homebus_parse_msg(struct blob_attr *msg, size_t len);

struct homebus_client *homebusd_proto_new_client(int fd, uloop_fd_handler cb);
void homebusd_proto_receive_message(struct homebus_client *cl, struct homebus_msg_buf *ub);
void homebusd_proto_free_client(struct homebus_client *cl);
void homebus_proto_send_msg_from_blob(struct homebus_client *cl, struct homebus_msg_buf *ub,
				   uint8_t type);
int homebusd_cmd_lookup(struct homebus_client *cl, struct homebus_client_cmd *cmd);

typedef struct homebus_msg_buf *(*event_fill_cb)(void *priv, const char *id);
void homebusd_event_init(void);
void homebusd_event_cleanup_object(struct homebus_object *obj);
void homebusd_send_obj_event(struct homebus_object *obj, bool add);
int homebusd_send_event(struct homebus_client *cl, const char *id,
		     event_fill_cb fill_cb, void *cb_priv);

void homebusd_acl_init(void);

void homebusd_monitor_init(void);
void homebusd_monitor_message(struct homebus_client *cl, struct homebus_msg_buf *ub, bool send);
void homebusd_monitor_disconnect(struct homebus_client *cl);

#endif
