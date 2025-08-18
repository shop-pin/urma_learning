/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_COMMON_H__
#define __UDMA_U_COMMON_H__

#include <unistd.h>
#include <stdatomic.h>
#include <arm_neon.h>
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "urma_provider.h"
#include "udma_u_abi.h"
#include "udma_u_log.h"
#include "udma_u_hmap.h"

#define UDMA_HW_PAGE_SIZE 4096U
#define UDMA_JFC_DB_OFFSET 0

struct udma_u_doorbell {
	uint32_t id;
	enum db_mmap_type type;
	void volatile *addr;
};

struct udma_u_context {
	urma_context_t		urma_ctx;
	void			*db_addr;
	uint32_t		page_size;
	struct udma_u_db_page	*db_list[UDMA_DB_TYPE_NUM];
	pthread_mutex_t		db_list_mutex;
	struct udma_u_doorbell	db;
	uint32_t		ue_id;
	uint32_t		chip_id;
	uint32_t		die_id;
	struct node_tbl		src_idx_tbl[UDMA_U_TBL_NUM];
};

#if INT_MAX >= 2147483647
#define builtin_ilog32_nz(v) \
	(((int)sizeof(uint32_t) * CHAR_BIT) - __builtin_clz(v))
#elif LONG_MAX >= 2147483647L
#define builtin_ilog32_nz(v) \
	(((int)sizeof(uint32_t) * CHAR_BIT) - __builtin_clzl(v))
#endif

#define ilog32(_v) ((uint32_t)builtin_ilog32_nz(_v)&((_v) == 0UL ? 0UL : 0xFFFFFFFFUL))
#define ilog64(_v) ((uint64_t)builtin_ilog64_nz(_v)&((_v) == 0ULL ? 0ULL : 0xFFFFFFFFFFFFFFFFULL))

#define check_types_match(expr1, expr2)		\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

#ifndef container_of
#define container_off(containing_type, member)                                 \
	offsetof(containing_type, member)
#define container_of(member_ptr, containing_type, member)                      \
	 ((containing_type *)                                                  \
	  ((void *)(member_ptr)                                                \
	   - container_off(containing_type, member))                           \
	  + (uint8_t)check_types_match(*(member_ptr), ((containing_type *)0)->member))
#endif

static inline void udma_u_set_udata(urma_cmd_udrv_priv_t *udrv_data,
				    void *in_addr, uint32_t in_len,
				    void *out_addr, uint32_t out_len)
{
	udrv_data->in_addr = (uint64_t)in_addr;
	udrv_data->in_len = in_len;
	udrv_data->out_addr = (uint64_t)out_addr;
	udrv_data->out_len = out_len;
}

static inline struct udma_u_context *to_udma_u_ctx(urma_context_t *ctx)
{
	return container_of(ctx, struct udma_u_context, urma_ctx);
}

/* index value is offset[32:8] */
static inline void udma_mmap_set_index(unsigned long index, off_t *offset)
{
	unsigned long offset_u = (unsigned long)*offset;
	offset_u |= ((index & (unsigned long)MAP_INDEX_MASK) << MAP_INDEX_SHIFT);
	*offset = (off_t)offset_u;
}

/* command value is offset[7:0] */
static inline void udma_mmap_set_command(uint32_t command, off_t *offset)
{
	uint32_t offset_u = (uint32_t)*offset;
	offset_u |= (command & (uint32_t)MAP_COMMAND_MASK);
	*offset = (off_t)offset_u;
}

static inline off_t get_mmap_offset(uint32_t idx, int page_size, uint32_t cmd)
{
	off_t offset = 0;

	udma_mmap_set_command(cmd, &offset);
	udma_mmap_set_index(idx, &offset);

	return offset * page_size;
}

static inline uint32_t calc_mask(uint32_t capacity)
{
	return ((uint32_t)1 << ilog32(capacity)) - (uint32_t)1;
}

#endif /* __UDMA_U_COMMON_H__ */
