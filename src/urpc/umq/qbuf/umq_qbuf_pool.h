/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define qbuf pool function
 * Create: 2025-7-26
 * Note:
 * History: 2025-7-26
 */

#ifndef UMQ_QBUF_POOL_H
#define UMQ_QBUF_POOL_H

#include <pthread.h>

#include "urpc_util.h"
#include "qbuf_list.h"
#include "umq_types.h"
#include "umq_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_SIZE_8K                     (8192)                  // 8K size
#define UMQ_SIZE_256K                   (262144)                // 256K size
#define UMQ_SIZE_8M                     (8388608)               // 8M size
#define UMQ_BUF_SIZE                    (1000L * 1024 * 1024)   // 1000M size
#define UMQ_EMPTY_HEADER_COEFFICIENT    16      // if block count is n, there will be n*16 count of empty qbuf header
#define UMQ_QBUF_DEFAULT_MEMPOOL_ID     (0)

typedef struct qbuf_pool_cfg {
    void *buf_addr;             // buffer addr
    uint64_t total_size;        // total buffer size
    uint32_t data_size;         // size of one data slab
    uint32_t headroom_size;     // reserve head room size
    umq_buf_mode_t mode;
} qbuf_pool_cfg_t;

/*
 * init qbuf pool
 */
int umq_qbuf_pool_init(qbuf_pool_cfg_t *cfg);

/*
 * uninit qbuf pool
 */
void umq_qbuf_pool_uninit(void);

/*
 * alloc memory from qbuf pool.
 * try to alloc from thread local pool.
 * if not enough, fetch some more memory fragments from global pool to thread local pool first.
 */
int umq_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list);

/*
 * release memory to qbuf pool.
 * if memory fragments count in thread local pool reach threshold after release,
 * return some of fragments to global pool.
 */
void umq_qbuf_free(umq_buf_list_t *list);

/*
 * reset head room size of qbuf
 * if headroom_size is not appropriate, UMQ_FAIL will be returned
 */
int umq_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size);

/*
 * find umq_buf_t corresponding to data
 * if data is not in qbuf_pool, NULL will be returned
 */
umq_buf_t *umq_qbuf_data_to_head(void *data);

void umq_qbuf_config_get(qbuf_pool_cfg_t *cfg);

typedef struct local_block_pool {
    umq_buf_list_t head_with_data;
    uint64_t buf_cnt_with_data;
    umq_buf_list_t head_without_data;
    uint64_t buf_cnt_without_data;
} local_block_pool_t;

typedef struct global_block_pool {
    pthread_mutex_t global_mutex;
    umq_buf_list_t head_with_data;
    uint64_t buf_cnt_with_data;
    umq_buf_list_t head_without_data;
    uint64_t buf_cnt_without_data;
} global_block_pool_t;

static ALWAYS_INLINE uint64_t round_up(uint64_t size, uint64_t align)
{
    return (size + align - 1) & ~(align - 1);
}

static ALWAYS_INLINE void *floor_to_align(void *ptr, uint64_t align)
{
    return (void *)((uint64_t)(uintptr_t)ptr & ~(align - 1));
}

/* get n elements from input and insert them at the head of output
 * input list elements count must more than n
 */
static ALWAYS_INLINE uint32_t allocate_batch(umq_buf_list_t *input, uint32_t n, umq_buf_list_t *output)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    QBUF_LIST_FOR_EACH(cur_node, input) {
        if (++cnt == n) {
            break;
        }
    }

    umq_buf_t *input_head = QBUF_LIST_FIRST(input);
    umq_buf_t *output_head = QBUF_LIST_FIRST(output);
    // switch head node
    QBUF_LIST_FIRST(input) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_FIRST(output) = input_head;
    // set output
    QBUF_LIST_NEXT(cur_node) = output_head;
    return cnt;
}

// release input to output and return count of elements released
static ALWAYS_INLINE uint32_t release_batch(umq_buf_list_t *input, umq_buf_list_t *output)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    umq_buf_t *last_node = NULL;
    QBUF_LIST_FOR_EACH(cur_node, input) {
        ++cnt;
        last_node = cur_node;
    }

    umq_buf_t *output_head = QBUF_LIST_FIRST(output);
    // switch head node
    QBUF_LIST_FIRST(output) = QBUF_LIST_FIRST(input);
    // set output
    QBUF_LIST_NEXT(last_node) = output_head;
    return cnt;
}

// fetch list nodes from to global to local cache
static ALWAYS_INLINE int32_t fetch_from_global(
        global_block_pool_t *global_pool, local_block_pool_t *cache_pool, bool with_data, uint32_t batch_count)
{
    uint32_t count = 0;
    uint64_t *global_buf_cnt;
    umq_buf_list_t *global_head;
    uint64_t *local_buf_cnt;
    umq_buf_list_t *local_head;
    pthread_mutex_lock(&global_pool->global_mutex);
    if (with_data) {
        global_buf_cnt = &global_pool->buf_cnt_with_data;
        global_head = &global_pool->head_with_data;

        local_buf_cnt = &cache_pool->buf_cnt_with_data;
        local_head = &cache_pool->head_with_data;
    } else {
        global_buf_cnt = &global_pool->buf_cnt_without_data;
        global_head = &global_pool->head_without_data;

        local_buf_cnt = &cache_pool->buf_cnt_without_data;
        local_head = &cache_pool->head_without_data;
    }

    if (*global_buf_cnt < batch_count) {
        pthread_mutex_unlock(&global_pool->global_mutex);
        UMQ_VLOG_ERR("%s not enough, rest count: %u\n", with_data ? "buf with data" : "buf with no data",
        *global_buf_cnt);
        return UMQ_FAIL;
    }

    count = allocate_batch(global_head, batch_count, local_head);
    *global_buf_cnt -= count;
    *local_buf_cnt += count;

    pthread_mutex_unlock(&global_pool->global_mutex);
    return count;
}

// flush list nodes from local cache to global
static ALWAYS_INLINE void return_to_global(
        global_block_pool_t *global_pool, local_block_pool_t *cache, bool with_data, uint32_t threshold)
{
    uint32_t cnt = 0;
    uint32_t remove_cnt = 0;
    umq_buf_t *cur_node = NULL;
    umq_buf_t *switch_node = NULL;
    umq_buf_t *last_node = NULL;
    uint64_t *global_buf_cnt;
    umq_buf_list_t *global_head;
    uint64_t *local_buf_cnt;
    umq_buf_list_t *local_head;
    (void)pthread_mutex_lock(&global_pool->global_mutex);
    if (with_data) {
        global_buf_cnt = &global_pool->buf_cnt_with_data;
        global_head = &global_pool->head_with_data;

        local_buf_cnt = &cache->buf_cnt_with_data;
        local_head = &cache->head_with_data;
    } else {
        global_buf_cnt = &global_pool->buf_cnt_without_data;
        global_head = &global_pool->head_without_data;

        local_buf_cnt =  &cache->buf_cnt_without_data;
        local_head = &cache->head_without_data;
    }

    QBUF_LIST_FOR_EACH(cur_node, local_head) {
        if (++cnt <= threshold) {
            switch_node = cur_node;
        } else {
            remove_cnt++;
            last_node = cur_node;
        }
    }

    // switch head node
    umq_buf_t *head = QBUF_LIST_FIRST(global_head); // record original head node
    QBUF_LIST_FIRST(global_head) = QBUF_LIST_NEXT(switch_node); // switch head node
    QBUF_LIST_NEXT(last_node) = head; // append head node to last node
    QBUF_LIST_NEXT(switch_node) = NULL; // break chain between switch_node and next of switch_node
    *global_buf_cnt += remove_cnt;
    *local_buf_cnt -= remove_cnt;

    (void)pthread_mutex_unlock(&global_pool->global_mutex);
}

// flush polled buf to global
static ALWAYS_INLINE void return_qbuf_to_global(global_block_pool_t *global_pool, umq_buf_t *buf, bool with_data)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node = NULL;
    umq_buf_t *last_node = NULL;

    uint64_t *global_buf_cnt;
    umq_buf_list_t *global_head;

    (void)pthread_mutex_lock(&global_pool->global_mutex);
    if (with_data) {
        global_buf_cnt = &global_pool->buf_cnt_with_data;
        global_head = &global_pool->head_with_data;
    } else {
        global_buf_cnt = &global_pool->buf_cnt_without_data;
        global_head = &global_pool->head_without_data;
    }

    cur_node = buf;
    while (cur_node != NULL) {
        last_node = cur_node;
        cur_node = QBUF_LIST_NEXT(cur_node);
        cnt++;
    }
    // switch head node
    umq_buf_t *head = QBUF_LIST_FIRST(global_head); // record original head node
    QBUF_LIST_FIRST(global_head) = buf; // switch head node
    QBUF_LIST_NEXT(last_node) = head; // append head node to last node
    *global_buf_cnt += cnt;

    (void)pthread_mutex_unlock(&global_pool->global_mutex);
}

static ALWAYS_INLINE umq_buf_t *id_to_buf_with_data_split(char *addr, uint32_t id)
{
    return (umq_buf_t *)(addr + id * sizeof(umq_buf_t));
}

static ALWAYS_INLINE umq_buf_t *id_to_buf_without_data_split(char *addr, uint32_t id)
{
    return (umq_buf_t *)(addr + id * sizeof(umq_buf_t));
}

static ALWAYS_INLINE umq_buf_t *id_to_buf_combine(char *addr, uint32_t id, uint32_t block_size)
{
    return (umq_buf_t *)(addr + id * block_size);
}

static ALWAYS_INLINE void umq_qbuf_alloc_nodata(local_block_pool_t *local_pool, uint32_t num, umq_buf_list_t *list)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    QBUF_LIST_FOR_EACH(cur_node, &local_pool->head_without_data) {
        if (++cnt == num) {
            break;
        }
    }

    umq_buf_t *input_head = QBUF_LIST_FIRST(&local_pool->head_without_data);
    // switch head node
    QBUF_LIST_FIRST(&local_pool->head_without_data) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_NEXT(cur_node) = QBUF_LIST_FIRST(list);

    // set output
    QBUF_LIST_FIRST(list) = input_head;
    local_pool->buf_cnt_without_data -= num;
}

static ALWAYS_INLINE void umq_qbuf_alloc_data(local_block_pool_t *local_pool, uint32_t request_size,
                                              uint32_t num, umq_buf_list_t *list, int32_t headroom_size)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    QBUF_LIST_FOR_EACH(cur_node, &local_pool->head_with_data) {
        cur_node->buf_data = floor_to_align(cur_node->buf_data, UMQ_SIZE_8K) + headroom_size;
        cur_node->headroom_size = headroom_size;
        cur_node->data_size = request_size;
        cur_node->total_data_size = request_size;
        if (++cnt == num) {
            break;
        }
    }

    umq_buf_t *head = QBUF_LIST_FIRST(&local_pool->head_with_data);
    // switch head node
    QBUF_LIST_FIRST(&local_pool->head_with_data) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_NEXT(cur_node) = QBUF_LIST_FIRST(list);

    // set output
    QBUF_LIST_FIRST(list) = head;
    local_pool->buf_cnt_with_data -= num;
}

static ALWAYS_INLINE int headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size, umq_buf_mode_t mode,
        uint32_t block_size)
{
    umq_buf_t *data = qbuf;
    uint64_t size = headroom_size + (mode == UMQ_BUF_COMBINE ? sizeof(umq_buf_t) : 0);
    if (size > block_size) {
        UMQ_VLOG_ERR("headroom_size: %u invalid\n", headroom_size);
        return UMQ_FAIL;
    }

    int32_t diff = (int32_t)headroom_size - (int32_t)data->headroom_size;
    while (data != NULL) {
        data->buf_data = data->buf_data + diff;
        data->data_size -= (uint32_t)diff;
        data->total_data_size -= (uint32_t)diff;
        data->headroom_size = headroom_size;
        data = data->qbuf_next;
    }
    return UMQ_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif
