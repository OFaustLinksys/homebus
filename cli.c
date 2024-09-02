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

#include <unistd.h>

#include <libubox/blobmsg_json.h>
#include "libhomebus.h"

static struct blob_buf b;
static int listen_timeout;
static int timeout = 30;
static bool simple_output = false;
static int verbose = 0;
static int monitor_dir = -1;
static uint32_t monitor_mask;
static const char * const monitor_types[] = {
	[HOMEBUS_MSG_HELLO] = "hello",
	[HOMEBUS_MSG_STATUS] = "status",
	[HOMEBUS_MSG_DATA] = "data",
	[HOMEBUS_MSG_PING] = "ping",
	[HOMEBUS_MSG_LOOKUP] = "lookup",
	[HOMEBUS_MSG_INVOKE] = "invoke",
	[HOMEBUS_MSG_ADD_OBJECT] = "add_object",
	[HOMEBUS_MSG_REMOVE_OBJECT] = "remove_object",
	[HOMEBUS_MSG_SUBSCRIBE] = "subscribe",
	[HOMEBUS_MSG_UNSUBSCRIBE] = "unsubscribe",
	[HOMEBUS_MSG_NOTIFY] = "notify",
};

static const char *format_type(void *priv, struct blob_attr *attr)
{
	static const char * const attr_types[] = {
		[BLOBMSG_TYPE_INT8] = "\"Boolean\"",
		[BLOBMSG_TYPE_INT32] = "\"Integer\"",
		[BLOBMSG_TYPE_STRING] = "\"String\"",
		[BLOBMSG_TYPE_ARRAY] = "\"Array\"",
		[BLOBMSG_TYPE_TABLE] = "\"Table\"",
	};
	const char *type = NULL;
	size_t typeid;

	if (blob_id(attr) != BLOBMSG_TYPE_INT32)
		return NULL;

	typeid = blobmsg_get_u32(attr);
	if (typeid < ARRAY_SIZE(attr_types))
		type = attr_types[typeid];
	if (!type)
		type = "\"(unknown)\"";

	return type;
}

static void receive_list_result(struct homebus_context *ctx, struct homebus_object_data *obj, void *priv)
{
	struct blob_attr *cur;
	char *s;
	size_t rem;

	if (simple_output || !verbose) {
		printf("%s\n", obj->path);
		return;
	}

	printf("'%s' @%08x\n", obj->path, obj->id);

	if (!obj->signature)
		return;

	blob_for_each_attr(cur, obj->signature, rem) {
		s = blobmsg_format_json_with_cb(cur, false, format_type, NULL, -1);
		printf("\t%s\n", s);
		free(s);
	}
}

static void receive_call_result_data(struct homebus_request *req, int type, struct blob_attr *msg)
{
	char *str;
	if (!msg)
		return;

	str = blobmsg_format_json_indent(msg, true, simple_output ? -1 : 0);
	printf("%s\n", str);
	free(str);
}

static void print_event(const char *type, struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);
	printf("{ \"%s\": %s }\n", type, str);
	fflush(stdout);
	free(str);
}

static int receive_request(struct homebus_context *ctx, struct homebus_object *obj,
			    struct homebus_request_data *req,
			    const char *method, struct blob_attr *msg)
{
	print_event(method, msg);
	return 0;
}

static void receive_event(struct homebus_context *ctx, struct homebus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	print_event(type, msg);
}

static int homebus_cli_error(char *cmd, int argc, char **argv, int err)
{
       int i;

       if (!simple_output && !isatty(fileno(stderr))) {
	       fprintf(stderr, "Command failed: homebus %s ", cmd);
	       for (i = 0; i < argc; i++) {
		       fprintf(stderr, "%s ", argv[i]);
	       }
	       fprintf(stderr, "(%s)\n", homebus_strerror(err));

	       return -err;
       }

       return err;
}

static int homebus_cli_list(struct homebus_context *ctx, int argc, char **argv)
{
	const char *path = NULL;

	if (argc > 1)
		return -2;

	if (argc == 1)
		path = argv[0];

	return homebus_lookup(ctx, path, receive_list_result, NULL);
}

static int homebus_cli_call(struct homebus_context *ctx, int argc, char **argv)
{
	uint32_t id;
	int ret;

	if (argc < 2 || argc > 3)
		return -2;

	blob_buf_init(&b, 0);
	if (argc == 3 && !blobmsg_add_json_from_string(&b, argv[2])) {
		return homebus_cli_error("call", argc, argv, HOMEBUS_STATUS_PARSE_ERROR);
	}

	ret = homebus_lookup_id(ctx, argv[0], &id);
	if (ret)
		return ret;

	ret = homebus_invoke(ctx, id, argv[1], b.head, receive_call_result_data, NULL, timeout * 1000);
	if (ret)
		return homebus_cli_error("call", argc, argv, ret);

	return ret;
}

struct cli_listen_data {
	struct uloop_timeout timeout;
	bool timed_out;
};

static void homebus_cli_listen_timeout(struct uloop_timeout *timeout)
{
	struct cli_listen_data *data = container_of(timeout, struct cli_listen_data, timeout);
	data->timed_out = true;
	uloop_end();
}

static void do_listen(struct homebus_context *ctx, struct cli_listen_data *data)
{
	memset(data, 0, sizeof(*data));
	data->timeout.cb = homebus_cli_listen_timeout;
	uloop_init();
	homebus_add_uloop(ctx);
	if (listen_timeout)
		uloop_timeout_set(&data->timeout, listen_timeout * 1000);
	uloop_run();
	uloop_done();
}

static int homebus_cli_listen(struct homebus_context *ctx, int argc, char **argv)
{
	struct homebus_event_handler ev = {
		.cb = receive_event,
	};
	struct cli_listen_data data;
	const char *event;
	int ret = 0;

	if (argc > 0) {
		event = argv[0];
	} else {
		event = "*";
		argc = 1;
	}

	do {
		ret = homebus_register_event_handler(ctx, &ev, event);
		if (ret)
			break;

		argv++;
		argc--;
		if (argc <= 0)
			break;

		event = argv[0];
	} while (1);

	if (ret) {
		if (!simple_output)
			fprintf(stderr, "Error while registering for event '%s': %s\n",
				event, homebus_strerror(ret));
		return -1;
	}

	do_listen(ctx, &data);

	return 0;
}

static int homebus_cli_subscribe(struct homebus_context *ctx, int argc, char **argv)
{
	struct homebus_subscriber sub = {
		.cb = receive_request,
	};
	struct cli_listen_data data;
	const char *event;
	int ret = 0;

	if (argc > 0) {
		event = argv[0];
	} else {
		if (!simple_output)
			fprintf(stderr, "You need to specify an object to subscribe to\n");
		return -1;
	}

	ret = homebus_register_subscriber(ctx, &sub);
	for (; !ret && argc > 0; argc--, argv++) {
		uint32_t id;

		ret = homebus_lookup_id(ctx, argv[0], &id);
		if (ret)
			break;

		ret = homebus_subscribe(ctx, &sub, id);
	}

	if (ret) {
		if (!simple_output)
			fprintf(stderr, "Error while registering for event '%s': %s\n",
				event, homebus_strerror(ret));
		return -1;
	}

	do_listen(ctx, &data);

	return 0;
}


static int homebus_cli_send(struct homebus_context *ctx, int argc, char **argv)
{
	if (argc < 1 || argc > 2)
		return -2;

	blob_buf_init(&b, 0);

	if (argc == 2 && !blobmsg_add_json_from_string(&b, argv[1])) {
		return HOMEBUS_STATUS_PARSE_ERROR;
	}

	return homebus_send_event(ctx, argv[0], b.head);
}

struct cli_wait_data {
	struct uloop_timeout timeout;
	struct homebus_event_handler ev;
	char **pending;
	int n_pending;
};

static void wait_check_object(struct cli_wait_data *data, const char *path)
{
	int i;

	for (i = 0; i < data->n_pending; i++) {
		if (strcmp(path, data->pending[i]) != 0)
			continue;

		data->n_pending--;
		if (i == data->n_pending)
			break;

		memmove(&data->pending[i], &data->pending[i + 1],
			(data->n_pending - i) * sizeof(*data->pending));
		i--;
	}

	if (!data->n_pending)
		uloop_end();
}

static void wait_event_cb(struct homebus_context *ctx, struct homebus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy = {
		"path", BLOBMSG_TYPE_STRING
	};
	struct cli_wait_data *data = container_of(ev, struct cli_wait_data, ev);
	struct blob_attr *attr;
	const char *path;

	if (strcmp(type, "homebus.object.add") != 0)
		return;

	blobmsg_parse(&policy, 1, &attr, blob_data(msg), blob_len(msg));
	if (!attr)
		return;

	path = blobmsg_data(attr);
	wait_check_object(data, path);
}

static void wait_list_cb(struct homebus_context *ctx, struct homebus_object_data *obj, void *priv)
{
	struct cli_wait_data *data = priv;

	wait_check_object(data, obj->path);
}


static void wait_timeout(struct uloop_timeout *timeout)
{
	uloop_end();
}

static int homebus_cli_wait_for(struct homebus_context *ctx, int argc, char **argv)
{
	struct cli_wait_data data = {
		.timeout.cb = wait_timeout,
		.ev.cb = wait_event_cb,
		.pending = argv,
		.n_pending = argc,
	};
	int ret;

	if (argc < 1)
		return -2;

	uloop_init();
	homebus_add_uloop(ctx);

	ret = homebus_register_event_handler(ctx, &data.ev, "homebus.object.add");
	if (ret)
		return ret;

	if (!data.n_pending)
		return ret;

	ret = homebus_lookup(ctx, NULL, wait_list_cb, &data);
	if (ret)
		return ret;

	if (!data.n_pending)
		return ret;

	uloop_timeout_set(&data.timeout, timeout * 1000);
	uloop_run();
	uloop_done();

	if (data.n_pending)
		return HOMEBUS_STATUS_TIMEOUT;

	return ret;
}

static const char *
homebus_cli_msg_type(uint32_t type)
{
	const char *ret = NULL;
	static char unk_type[16];


	if (type < ARRAY_SIZE(monitor_types))
		ret = monitor_types[type];

	if (!ret) {
		snprintf(unk_type, sizeof(unk_type), "%d", type);
		ret = unk_type;
	}

	return ret;
}

static char *
homebus_cli_get_monitor_data(struct blob_attr *data)
{
	static const struct blob_attr_info policy[HOMEBUS_ATTR_MAX] = {
		[HOMEBUS_ATTR_STATUS] = { .type = BLOB_ATTR_INT32 },
		[HOMEBUS_ATTR_OBJPATH] = { .type = BLOB_ATTR_STRING },
		[HOMEBUS_ATTR_OBJID] = { .type = BLOB_ATTR_INT32 },
		[HOMEBUS_ATTR_METHOD] = { .type = BLOB_ATTR_STRING },
		[HOMEBUS_ATTR_OBJTYPE] = { .type = BLOB_ATTR_INT32 },
		[HOMEBUS_ATTR_SIGNATURE] = { .type = BLOB_ATTR_NESTED },
		[HOMEBUS_ATTR_DATA] = { .type = BLOB_ATTR_NESTED },
		[HOMEBUS_ATTR_ACTIVE] = { .type = BLOB_ATTR_INT8 },
		[HOMEBUS_ATTR_NO_REPLY] = { .type = BLOB_ATTR_INT8 },
		[HOMEBUS_ATTR_USER] = { .type = BLOB_ATTR_STRING },
		[HOMEBUS_ATTR_GROUP] = { .type = BLOB_ATTR_STRING },
	};
	static const char * const names[HOMEBUS_ATTR_MAX] = {
		[HOMEBUS_ATTR_STATUS] = "status",
		[HOMEBUS_ATTR_OBJPATH] = "objpath",
		[HOMEBUS_ATTR_OBJID] = "objid",
		[HOMEBUS_ATTR_METHOD] = "method",
		[HOMEBUS_ATTR_OBJTYPE] = "objtype",
		[HOMEBUS_ATTR_SIGNATURE] = "signature",
		[HOMEBUS_ATTR_DATA] = "data",
		[HOMEBUS_ATTR_ACTIVE] = "active",
		[HOMEBUS_ATTR_NO_REPLY] = "no_reply",
		[HOMEBUS_ATTR_USER] = "user",
		[HOMEBUS_ATTR_GROUP] = "group",
	};
	struct blob_attr *tb[HOMEBUS_ATTR_MAX];
	int i;

	blob_buf_init(&b, 0);
	blob_parse(data, tb, policy, HOMEBUS_ATTR_MAX);

	for (i = 0; i < HOMEBUS_ATTR_MAX; i++) {
		const char *n = names[i];
		struct blob_attr *v = tb[i];

		if (!tb[i] || !n)
			continue;

		switch(policy[i].type) {
		case BLOB_ATTR_INT32:
			blobmsg_add_u32(&b, n, blob_get_int32(v));
			break;
		case BLOB_ATTR_STRING:
			blobmsg_add_string(&b, n, blob_data(v));
			break;
		case BLOB_ATTR_INT8:
			blobmsg_add_u8(&b, n, !!blob_get_int8(v));
			break;
		case BLOB_ATTR_NESTED:
			blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, n, blobmsg_data(v), blobmsg_data_len(v));
			break;
		}
	}

	return blobmsg_format_json(b.head, true);
}

static void
homebus_cli_monitor_cb(struct homebus_context *ctx, uint32_t seq, struct blob_attr *msg)
{
	static const struct blob_attr_info policy[HOMEBUS_MONITOR_MAX] = {
		[HOMEBUS_MONITOR_CLIENT] = { .type = BLOB_ATTR_INT32 },
		[HOMEBUS_MONITOR_PEER] = { .type = BLOB_ATTR_INT32 },
		[HOMEBUS_MONITOR_SEND] = { .type = BLOB_ATTR_INT8 },
		[HOMEBUS_MONITOR_TYPE] = { .type = BLOB_ATTR_INT32 },
		[HOMEBUS_MONITOR_DATA] = { .type = BLOB_ATTR_NESTED },
	};
	struct blob_attr *tb[HOMEBUS_MONITOR_MAX];
	uint32_t client, peer, type;
	bool send;
	char *data;

	blob_parse_untrusted(msg, blob_raw_len(msg), tb, policy, HOMEBUS_MONITOR_MAX);

	if (!tb[HOMEBUS_MONITOR_CLIENT] ||
	    !tb[HOMEBUS_MONITOR_PEER] ||
	    !tb[HOMEBUS_MONITOR_SEND] ||
	    !tb[HOMEBUS_MONITOR_TYPE] ||
	    !tb[HOMEBUS_MONITOR_DATA]) {
		printf("Invalid monitor msg\n");
		return;
	}

	send = blob_get_int32(tb[HOMEBUS_MONITOR_SEND]);
	client = blob_get_int32(tb[HOMEBUS_MONITOR_CLIENT]);
	peer = blob_get_int32(tb[HOMEBUS_MONITOR_PEER]);
	type = blob_get_int32(tb[HOMEBUS_MONITOR_TYPE]);

	if (monitor_mask && type < 32 && !(monitor_mask & (1 << type)))
		return;

	if (monitor_dir >= 0 && send != monitor_dir)
		return;

	data = homebus_cli_get_monitor_data(tb[HOMEBUS_MONITOR_DATA]);
	printf("%s %08x #%08x %14s: %s\n", send ? "->" : "<-", client, peer, homebus_cli_msg_type(type), data);
	free(data);
	fflush(stdout);
}

static int homebus_cli_monitor(struct homebus_context *ctx, int argc, char **argv)
{
	int ret;

	uloop_init();
	homebus_add_uloop(ctx);
	ctx->monitor_cb = homebus_cli_monitor_cb;
	ret = homebus_monitor_start(ctx);
	if (ret)
		return ret;

	uloop_run();
	uloop_done();

	homebus_monitor_stop(ctx);
	return 0;
}

static int add_monitor_type(const char *type)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(monitor_types); i++) {
		if (!monitor_types[i] || strcmp(monitor_types[i], type) != 0)
			continue;

		monitor_mask |= 1 << i;
		return 0;
	}

	return -1;
}

static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [<options>] <command> [arguments...]\n"
		"Options:\n"
		" -s <socket>:		Set the unix domain socket to connect to\n"
		" -t <timeout>:		Set the timeout (in seconds) for a command to complete\n"
		" -S:			Use simplified output (for scripts)\n"
		" -v:			More verbose output\n"
		" -m <type>:		(for monitor): include a specific message type\n"
		"			(can be used more than once)\n"
		" -M <r|t>		(for monitor): only capture received or transmitted traffic\n"
		"\n"
		"Commands:\n"
		" - list [<path>]			List objects\n"
		" - call <path> <method> [<message>]	Call an object method\n"
		" - subscribe <path> [<path>...]	Subscribe to object(s) notifications\n"
		" - listen [<path>...]			Listen for events\n"
		" - send <type> [<message>]		Send an event\n"
		" - wait_for <object> [<object>...]	Wait for multiple objects to appear on homebus\n"
		" - monitor				Monitor homebus traffic\n"
		"\n", prog);
	return 1;
}


static struct {
	const char *name;
	int (*cb)(struct homebus_context *ctx, int argc, char **argv);
} commands[] = {
	{ "list", homebus_cli_list },
	{ "call", homebus_cli_call },
	{ "listen", homebus_cli_listen },
	{ "subscribe", homebus_cli_subscribe },
	{ "send", homebus_cli_send },
	{ "wait_for", homebus_cli_wait_for },
	{ "monitor", homebus_cli_monitor },
};

int main(int argc, char **argv)
{
	const char *progname, *homebus_socket = NULL;
	struct homebus_context *ctx;
	int ret = 0;
	char *cmd;
	size_t i;
	int ch;

	progname = argv[0];

	while ((ch = getopt(argc, argv, "m:M:vs:t:S")) != -1) {
		switch (ch) {
		case 's':
			homebus_socket = optarg;
			break;
		case 't':
			listen_timeout = atoi(optarg);
			timeout = atoi(optarg);
			break;
		case 'S':
			simple_output = true;
			break;
		case 'v':
			verbose++;
			break;
		case 'm':
			if (add_monitor_type(optarg))
			    return usage(progname);
			break;
		case 'M':
			switch (optarg[0]) {
			case 'r':
				monitor_dir = 0;
				break;
			case 't':
				monitor_dir = 1;
				break;
			default:
				return usage(progname);
			}
			break;
		default:
			return usage(progname);
		}
	}

	argc -= optind;
	argv += optind;

	cmd = argv[0];
	if (argc < 1)
		return usage(progname);

	ctx = homebus_connect(homebus_socket);
	if (!ctx) {
		if (!simple_output)
			fprintf(stderr, "Failed to connect to homebus\n");
		return -1;
	}

	argv++;
	argc--;

	ret = -2;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(commands[i].name, cmd) != 0)
			continue;

		ret = commands[i].cb(ctx, argc, argv);
		break;
	}

	if (ret > 0 && !simple_output)
		fprintf(stderr, "Command failed: %s\n", homebus_strerror(ret));
	else if (ret == -2)
		usage(progname);

	homebus_free(ctx);
	return ret;
}
