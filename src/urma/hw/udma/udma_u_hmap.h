/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_H_HMAP__
#define __UDMA_H_HMAP__

#include <stdint.h>
#include <stdlib.h>

#define UDMA_NODE_TABLE_SIZE 128

enum udma_u_node_tbl_type {
	UDMA_U_JFR_TBL,
	UDMA_U_JETTY_TBL,
	UDMA_U_TBL_NUM,
};

struct udma_u_hmap_node {
	struct udma_u_hmap_node *next;
	uint32_t hash;
};

struct udma_u_hmap_head {
	struct udma_u_hmap_node *next;
};

struct udma_u_hmap {
	uint32_t count;
	uint32_t mask;
	struct udma_u_hmap_head *bucket;
};

struct node_tbl {
	pthread_rwlock_t rwlock;
	struct udma_u_hmap hmap;
};

int udma_u_hmap_insert(struct udma_u_hmap *hmap,
		       struct udma_u_hmap_node *node,
		       uint32_t hash);
void udma_u_hmap_remove(struct udma_u_hmap *hmap,
			const struct udma_u_hmap_node *node);
struct udma_u_hmap_node
*udma_u_hmap_first_with_hash(const struct udma_u_hmap *hmap, uint32_t hash);
int udma_u_init_node_tbl(struct node_tbl *node_tbl);
void udma_u_uninit_node_tbl(struct node_tbl *node_tbl);
#endif /* __UDMA_H_HMAP__ */
