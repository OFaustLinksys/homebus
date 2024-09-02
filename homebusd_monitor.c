/*
 * Copyright (C) 2015 Felix Fietkau <nbd@openwrt.org>
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

static struct homebus_object *monitor_obj;
static LIST_HEAD(monitors);

struct homebus_monitor {
	struct list_head list;
	struct homebus_client *cl;
	uint32_t seq;
};

static void
homebusd_monitor_free(struct homebus_monitor *m)
{
	list_del(&m->list);
	free(m);
}

static bool
homebusd_monitor_connect(struct homebus_client *cl, struct homebus_msg_buf *ub)
{
	struct homebus_monitor *m;

	homebusd_monitor_disconnect(cl);

	m = calloc(1, sizeof(*m));
	if (!m)
		return false;

	m->cl = cl;
	list_add_tail(&m->list, &monitors);

	return true;
}

static struct homebus_monitor*
homebusd_monitor_find(struct homebus_client *cl)
{
	struct homebus_monitor *m, *tmp;

	list_for_each_entry_safe(m, tmp, &monitors, list) {
		if (m->cl != cl)
			continue;

		return m;
	}

	return NULL;
}

void
homebusd_monitor_disconnect(struct homebus_client *cl)
{
	struct homebus_monitor *m;

	m = homebusd_monitor_find(cl);
	if (!m)
		return;

	homebusd_monitor_free(m);
}

void
homebusd_monitor_message(struct homebus_client *cl, struct homebus_msg_buf *ub, bool send)
{
	static struct blob_buf mb;
	struct homebus_monitor *m;

	if (list_empty(&monitors))
		return;

	blob_buf_init(&mb, 0);
	blob_put_int32(&mb, HOMEBUS_MONITOR_CLIENT, cl->id.id);
	blob_put_int32(&mb, HOMEBUS_MONITOR_PEER, ub->hdr.peer);
	blob_put_int32(&mb, HOMEBUS_MONITOR_SEQ, ub->hdr.seq);
	blob_put_int32(&mb, HOMEBUS_MONITOR_TYPE, ub->hdr.type);
	blob_put_int8(&mb, HOMEBUS_MONITOR_SEND, send);
	blob_put(&mb, HOMEBUS_MONITOR_DATA, blob_data(ub->data), blob_len(ub->data));

	ub = homebus_msg_new(mb.head, blob_raw_len(mb.head), true);
	ub->hdr.type = HOMEBUS_MSG_MONITOR;

	list_for_each_entry(m, &monitors, list) {
		ub->hdr.seq = ++m->seq;
		homebus_msg_send(m->cl, ub);
	}

	homebus_msg_free(ub);
}

static int
homebusd_monitor_recv(struct homebus_client *cl, struct homebus_msg_buf *ub,
		   const char *method, struct blob_attr *msg)
{
	/* Only root is allowed for now */
	if (cl->uid != 0 || cl->gid != 0)
		return HOMEBUS_STATUS_PERMISSION_DENIED;

	if (!strcmp(method, "add")) {
		if (!homebusd_monitor_connect(cl, ub))
			return HOMEBUS_STATUS_UNKNOWN_ERROR;

		return HOMEBUS_STATUS_OK;
	}

	if (!strcmp(method, "remove")) {
		homebusd_monitor_disconnect(cl);
		return HOMEBUS_STATUS_OK;
	}

	return HOMEBUS_STATUS_METHOD_NOT_FOUND;
}

void
homebusd_monitor_init(void)
{
	monitor_obj = homebusd_create_object_internal(NULL, HOMEBUS_SYSTEM_OBJECT_MONITOR);
	if (monitor_obj != NULL)
		monitor_obj->recv_msg = homebusd_monitor_recv;
}
