/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_TID_H__
#define __UDMA_U_TID_H__

#include "udma_u_common.h"

urma_token_id_t *udma_u_alloc_tid(urma_context_t *ctx);
urma_token_id_t *udma_u_alloc_tid_ex(urma_context_t *ctx, urma_token_id_flag_t flag);
urma_status_t udma_u_free_tid(urma_token_id_t *tid);

#endif /* __UDMA_U_TID_H__ */
