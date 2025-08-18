// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include "udma_u_db.h"

int udma_u_alloc_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db)
{
	struct udma_u_context *udma_u_ctx = to_udma_u_ctx(urma_ctx);
	off_t offset;

	offset = get_mmap_offset(db->id, udma_u_ctx->page_size, db->type);

	db->addr = mmap(NULL, udma_u_ctx->page_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, urma_ctx->dev_fd, offset);
	if (db->addr == MAP_FAILED) {
		UDMA_LOG_ERR("failed to mmap doorbell page, id = %u, type = %d.",
			     db->id, db->type);
		return EINVAL;
	}

	if (db->type == UDMA_MMAP_JETTY_DSQE)
		db->addr = db->addr + udma_get_dsqe_db_offset(udma_u_ctx, db);

	return 0;
}

void udma_u_free_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db)
{
	struct udma_u_context *udma_u_ctx = to_udma_u_ctx(urma_ctx);

	if (db->addr == MAP_FAILED || db->addr == NULL)
		return;

	if (db->type == UDMA_MMAP_JETTY_DSQE)
		db->addr = db->addr - udma_get_dsqe_db_offset(udma_u_ctx, db);

	munmap((void *)db->addr, (size_t)udma_u_ctx->page_size);
	db->addr = NULL;
}
