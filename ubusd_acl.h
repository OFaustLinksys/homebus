/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
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

#ifndef __HOMEBUSD_ACL_H
#define __HOMEBUSD_ACL_H

enum homebusd_acl_type {
	HOMEBUS_ACL_PUBLISH,
	HOMEBUS_ACL_SUBSCRIBE,
	HOMEBUS_ACL_ACCESS,
	HOMEBUS_ACL_LISTEN,
	HOMEBUS_ACL_SEND,
};

int homebusd_acl_check(struct homebus_client *cl, const char *obj, const char *method, enum homebusd_acl_type type);
int homebusd_acl_init_client(struct homebus_client *cl, int fd);
void homebusd_acl_free_client(struct homebus_client *cl);
void homebusd_acl_load(void);

#endif
