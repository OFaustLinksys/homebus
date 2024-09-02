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

#ifndef __LIBHOMEBUS_IO_H
#define __LIBHOMEBUS_IO_H

extern struct blob_buf b;
extern const struct homebus_method watch_method;

struct blob_attr **homebus_parse_msg(struct blob_attr *msg, size_t len);
bool homebus_validate_hdr(struct homebus_msghdr *hdr);
void homebus_handle_data(struct uloop_fd *u, unsigned int events);
int homebus_send_msg(struct homebus_context *ctx, uint32_t seq,
		  struct blob_attr *msg, int cmd, uint32_t peer, int fd);
void homebus_process_msg(struct homebus_context *ctx, struct homebus_msghdr_buf *buf, int fd);
int __hidden homebus_start_request(struct homebus_context *ctx, struct homebus_request *req,
				struct blob_attr *msg, int cmd, uint32_t peer);
int __hidden __homebus_start_request(struct homebus_context *ctx, struct homebus_request *req,
				struct blob_attr *msg, int cmd, uint32_t peer);
void homebus_process_obj_msg(struct homebus_context *ctx, struct homebus_msghdr_buf *buf, int fd);
void homebus_process_req_msg(struct homebus_context *ctx, struct homebus_msghdr_buf *buf, int fd);
void __hidden homebus_poll_data(struct homebus_context *ctx, int timeout);


#endif
