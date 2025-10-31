/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UB helper for UMQ
 * Create: 2025-7-19
 * Note:
 * History: 2025-7-19
 */

#ifndef UMQ_UB_IMPL_H
#define UMQ_UB_IMPL_H

#include "umq_types.h"
#include "umq_pro_types.h"
#include "umq_ub_imm_data.h"
#include "util_id_generator.h"

typedef struct ub_ref_sge {
    uint64_t addr;
    uint32_t length;
    uint32_t token_id;
    uint32_t token_value;
} ub_ref_sge_t;

uint8_t *umq_ub_ctx_init_impl(umq_init_cfg_t *cfg);
void umq_ub_ctx_uninit_impl(uint8_t *ctx);

uint64_t umq_ub_create_impl(uint8_t *ctx, umq_create_option_t *option);
int32_t umq_ub_destroy_impl(uint64_t umqh);

int umq_ub_bind_info_get_impl(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size);
int umq_ub_bind_impl(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size);
int umq_ub_unbind_impl(uint64_t umqh);

int32_t umq_ub_register_memory_impl(uint8_t *ub_ctx, void *buf, uint64_t size);
void umq_ub_unregister_memory_impl(uint8_t *ub_ctx);

int32_t umq_ub_huge_qbuf_pool_init(umq_init_cfg_t *cfg);
void umq_ub_huge_qbuf_pool_uninit(void);

umq_buf_t *umq_tp_ub_alloc_impl(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
    umq_alloc_option_t *option);
void umq_tp_ub_buf_free_impl(umq_buf_t *qbuf, uint64_t umqh_tp);

int umq_ub_post_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_io_direction_t io_direction, umq_buf_t **bad_qbuf);
int umq_ub_poll_impl(uint64_t umqh_tp, umq_io_direction_t io_direction, umq_buf_t **buf, uint32_t max_buf_count);

int32_t umq_ub_enqueue_impl(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);
int32_t umq_ub_enqueue_impl_plus(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);
umq_buf_t *umq_ub_dequeue_impl(uint64_t umqh_tp);
int umq_ub_rearm_impl(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option);

int umq_ub_get_cq_event_impl(uint64_t umqh_tp, umq_interrupt_option_t *option);

int umq_ub_wait_interrupt_impl(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option);

void umq_ub_ack_interrupt_impl(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option);

int umq_ub_interrupt_fd_get_impl(uint64_t umqh_tp, umq_interrupt_option_t *option);

int umq_ub_write_imm(uint64_t umqh_tp, uint64_t target_addr, uint32_t len);
int umq_ub_read(uint64_t umqh_tp, umq_buf_t *rx_buf, umq_ub_imm_t imm);

// ubmm rendezvous related functions
void umq_ub_get_token(uint64_t umqh_tp, uint32_t *token_id, uint32_t *token_value);
void umq_ub_record_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id, umq_buf_t *buf);
void umq_ub_remove_rendezvous_buf(uint64_t umqh_tp, uint16_t msg_id);
util_id_allocator_t *umq_ub_get_msg_id_generator(uint64_t umqh_tp);

#endif
