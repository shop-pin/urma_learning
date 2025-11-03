/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_SEGMENT_H__
#define __UDMA_U_SEGMENT_H__

#include "urma_types.h"

#define UDMA_TOKEN_VALUE_INPUT 0

urma_target_seg_t *udma_u_register_seg(urma_context_t *urma_ctx,
				       urma_seg_cfg_t *seg_cfg);
urma_status_t udma_u_unregister_seg(urma_target_seg_t *target_seg);
urma_target_seg_t *udma_u_import_seg(urma_context_t *ctx, urma_seg_t *seg,
				     urma_token_t *token, uint64_t addr,
				     urma_import_seg_flag_t flag);
urma_status_t udma_u_unimport_seg(urma_target_seg_t *target_seg);
#endif /* __UDMA_U_SEGMENT_H__ */
