/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_DB_H__
#define __UDMA_U_DB_H__

#include "udma_u_common.h"

int udma_u_alloc_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db);
void udma_u_free_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db);

static inline uint32_t udma_get_dsqe_db_offset(struct udma_u_context *udma_u_ctx, struct udma_u_doorbell *db)
{
	return (db->id + (uint32_t)1) % (udma_u_ctx->page_size / UDMA_HW_PAGE_SIZE) * UDMA_HW_PAGE_SIZE;
}

#endif /* __UDMA_U_DB_H__ */
