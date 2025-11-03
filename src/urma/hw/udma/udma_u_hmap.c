// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <errno.h>
#include <stdatomic.h>
#include "udma_u_log.h"
#include "udma_u_common.h"
#include "udma_u_hmap.h"

static int udma_u_hmap_init(struct udma_u_hmap *map, uint32_t count)
{
	map->count = 0;
	map->mask = calc_mask(count);
	map->bucket =
		(struct udma_u_hmap_head *)calloc(1, sizeof(struct udma_u_hmap_head) *
						     (map->mask + (uint32_t)1));
	if (map->bucket != NULL)
		return 0;

	return ENOMEM;
}

static void udma_u_hmap_destroy(struct udma_u_hmap *hmap)
{
	if (hmap->bucket)
		free(hmap->bucket);
	hmap->bucket = NULL;
}

struct udma_u_hmap_node
*udma_u_hmap_first_with_hash(const struct udma_u_hmap *hmap, uint32_t hash)
{
	struct udma_u_hmap_head *head = &hmap->bucket[hash & hmap->mask];
	struct udma_u_hmap_node *node;

	if (head == NULL)
		return NULL;

	node = head->next;

	while (node != NULL && node->hash != hash)
		node = node->next;

	return node;
}

int udma_u_hmap_insert(struct udma_u_hmap *hmap,
		       struct udma_u_hmap_node *node,
		       uint32_t hash)
{
	struct udma_u_hmap_head *head = &hmap->bucket[hash & hmap->mask];

	if (udma_u_hmap_first_with_hash(hmap, hash))
		return EINVAL;

	node->hash = hash;
	node->next = head->next;
	head->next = node;
	hmap->count++;

	return 0;
}

void udma_u_hmap_remove(struct udma_u_hmap *hmap,
			const struct udma_u_hmap_node *node)
{
	struct udma_u_hmap_node *pre_node =
		(struct udma_u_hmap_node *)&hmap->bucket[node->hash & hmap->mask];
	struct udma_u_hmap_node *tmp_node = pre_node->next;

	while (tmp_node != NULL) {
		struct udma_u_hmap_node *next_node = tmp_node->next;

		if (tmp_node == node) {
			pre_node->next = next_node;
			hmap->count--;
			return;
		}
		pre_node = tmp_node;
		tmp_node = next_node;
	}
}

static void udma_u_destroy_node(struct node_tbl *node_tbl, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		(void)pthread_rwlock_destroy(&node_tbl[i].rwlock);
		udma_u_hmap_destroy(&node_tbl[i].hmap);
	}
}

void udma_u_uninit_node_tbl(struct node_tbl *node_tbl)
{
	udma_u_destroy_node(node_tbl, UDMA_U_TBL_NUM);
}

int udma_u_init_node_tbl(struct node_tbl *node_tbl)
{
	int i = 0;

	for (i = 0; i < (int)UDMA_U_TBL_NUM; i++) {
		(void)pthread_rwlock_init(&node_tbl[i].rwlock, NULL);
		if (udma_u_hmap_init(&node_tbl[i].hmap, UDMA_NODE_TABLE_SIZE)) {
			UDMA_LOG_ERR("init src idx tbl failed\n");
			udma_u_destroy_node(node_tbl, i + 1);

			return ENOMEM;
		}
	}

	return 0;
}
