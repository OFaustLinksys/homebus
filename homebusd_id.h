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

#ifndef __HOMEBUSD_ID_H
#define __HOMEBUSD_ID_H

#include <libubox/avl.h>
#include <stdint.h>

struct homebus_id {
	struct avl_node avl;
	uint32_t id;
};

void homebus_init_id_tree(struct avl_tree *tree);
void homebus_init_string_tree(struct avl_tree *tree, bool dup);
bool homebus_alloc_id(struct avl_tree *tree, struct homebus_id *id, uint32_t val);

static inline void homebus_free_id(struct avl_tree *tree, struct homebus_id *id)
{
	avl_delete(tree, &id->avl);
}

static inline struct homebus_id *homebus_find_id(struct avl_tree *tree, uint32_t id)
{
	struct avl_node *avl;

	avl = avl_find(tree, &id);
	if (!avl)
		return NULL;

	return container_of(avl, struct homebus_id, avl);
}

#endif
