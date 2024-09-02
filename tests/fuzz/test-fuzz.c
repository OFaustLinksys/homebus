#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include "homebusmsg.h"
#include "libhomebus.h"
#include "libhomebus-internal.h"

static void _homebus_validate_hdr(const uint8_t *data, size_t size)
{
	if (size > sizeof(struct homebus_msghdr))
		return;

	homebus_validate_hdr((struct homebus_msghdr *) data);
}

static void _homebus_parse_msg(const uint8_t *data, size_t size)
{
	struct blob_attr *attr = (struct blob_attr *) data;

	if (size < sizeof(struct blob_attr *))
		return;

	if (blob_pad_len(attr) > HOMEBUS_MAX_MSGLEN)
		return;

	homebus_parse_msg(attr, size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	_homebus_validate_hdr(data, size);
	_homebus_parse_msg(data, size);

	return 0;
}
