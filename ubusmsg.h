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

#ifndef __HOMEBUSMSG_H
#define __HOMEBUSMSG_H

#include <stdint.h>
#include <libubox/blob.h>

#define __packetdata __attribute__((packed)) __attribute__((__aligned__(4)))

#define HOMEBUS_MSG_CHUNK_SIZE	65536

#define HOMEBUS_SYSTEM_OBJECT_EVENT	1
#define HOMEBUS_SYSTEM_OBJECT_ACL		2
#define HOMEBUS_SYSTEM_OBJECT_MONITOR	3
#define HOMEBUS_SYSTEM_OBJECT_MAX		1024

struct homebus_msghdr {
	uint8_t version;
	uint8_t type;
	uint16_t seq;
	uint32_t peer;
} __packetdata;

enum homebus_msg_type {
	/* initial server message */
	HOMEBUS_MSG_HELLO,

	/* generic command response */
	HOMEBUS_MSG_STATUS,

	/* data message response */
	HOMEBUS_MSG_DATA,

	/* ping request */
	HOMEBUS_MSG_PING,

	/* look up one or more objects */
	HOMEBUS_MSG_LOOKUP,

	/* invoke a method on a single object */
	HOMEBUS_MSG_INVOKE,

	HOMEBUS_MSG_ADD_OBJECT,
	HOMEBUS_MSG_REMOVE_OBJECT,

	/*
	 * subscribe/unsubscribe to object notifications
	 * The unsubscribe message is sent from homebusd when
	 * the object disappears
	 */
	HOMEBUS_MSG_SUBSCRIBE,
	HOMEBUS_MSG_UNSUBSCRIBE,

	/*
	 * send a notification to all subscribers of an object.
	 * when sent from the server, it indicates a subscription
	 * status change
	 */
	HOMEBUS_MSG_NOTIFY,

	HOMEBUS_MSG_MONITOR,

	/* must be last */
	__HOMEBUS_MSG_LAST,
};

enum homebus_msg_attr {
	HOMEBUS_ATTR_UNSPEC,

	HOMEBUS_ATTR_STATUS,

	HOMEBUS_ATTR_OBJPATH,
	HOMEBUS_ATTR_OBJID,
	HOMEBUS_ATTR_METHOD,

	HOMEBUS_ATTR_OBJTYPE,
	HOMEBUS_ATTR_SIGNATURE,

	HOMEBUS_ATTR_DATA,
	HOMEBUS_ATTR_TARGET,

	HOMEBUS_ATTR_ACTIVE,
	HOMEBUS_ATTR_NO_REPLY,

	HOMEBUS_ATTR_SUBSCRIBERS,

	HOMEBUS_ATTR_USER,
	HOMEBUS_ATTR_GROUP,

	/* must be last */
	HOMEBUS_ATTR_MAX,
};

enum homebus_monitor_attr {
	HOMEBUS_MONITOR_CLIENT,
	HOMEBUS_MONITOR_PEER,
	HOMEBUS_MONITOR_SEND,
	HOMEBUS_MONITOR_SEQ,
	HOMEBUS_MONITOR_TYPE,
	HOMEBUS_MONITOR_DATA,

	/* must be last */
	HOMEBUS_MONITOR_MAX,
};

enum homebus_msg_status {
	HOMEBUS_STATUS_OK,
	HOMEBUS_STATUS_INVALID_COMMAND,
	HOMEBUS_STATUS_INVALID_ARGUMENT,
	HOMEBUS_STATUS_METHOD_NOT_FOUND,
	HOMEBUS_STATUS_NOT_FOUND,
	HOMEBUS_STATUS_NO_DATA,
	HOMEBUS_STATUS_PERMISSION_DENIED,
	HOMEBUS_STATUS_TIMEOUT,
	HOMEBUS_STATUS_NOT_SUPPORTED,
	HOMEBUS_STATUS_UNKNOWN_ERROR,
	HOMEBUS_STATUS_CONNECTION_FAILED,
	HOMEBUS_STATUS_NO_MEMORY,
	HOMEBUS_STATUS_PARSE_ERROR,
	HOMEBUS_STATUS_SYSTEM_ERROR,
	__HOMEBUS_STATUS_LAST
};

#endif
