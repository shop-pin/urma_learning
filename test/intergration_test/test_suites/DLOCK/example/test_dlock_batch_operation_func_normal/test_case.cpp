/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: dlock example
 */

#include "../public.h"
using namespace dlock;
#define TEST_NUM 100

static int run_test(test_dlock_ctx_t *ctx)
{
    int ret, rc = TEST_FAILED;
    int lock_id = 0;
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, nullptr);
    int lock_ids[MAX_LOCK_BATCH_SIZE];
    int check_ids[MAX_LOCK_BATCH_SIZE];
    struct lock_desc lock_descs[MAX_LOCK_BATCH_SIZE];
    struct lock_request lock_reqs[MAX_LOCK_BATCH_SIZE];
    struct lock_op_res lock_results[MAX_LOCK_BATCH_SIZE];
    ret = test_server_prepare(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_prepare", EXIT);
    sync_time("-------------------------- 1");
    if (ctx->app_id == PROC_2) {
        ret = test_client_prepare(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_prepare", EXIT);
    }
    sync_time("-------------------------- 2");
    if (ctx->app_id == PROC_2) {
        for(int k = 0; k < TEST_NUM; k++) {
            TEST_LOG_INFO("[k:%d] start\n", k);
            for(int i = 0; i < MAX_LOCK_BATCH_SIZE; i++) {
                lock_ids[i] = i + 1;
                lock_descs[i].lock_type = (k % 2) ? DLOCK_ATOMIC : DLOCK_FAIR;
                lock_descs[i].lease_time = tv_start.tv_sec + 60000;
                lock_descs[i].p_desc = (char *)(lock_ids + i);
                lock_descs[i].len = 4;
            }
            ret = batch_get_lock(ctx->client_ids[0], MAX_LOCK_BATCH_SIZE, lock_descs, lock_ids);
            CHKERR_JUMP(ret != TEST_SUCCESS, "batch_get_lock", EXIT);
            for(int i = 0; i < MAX_LOCK_BATCH_SIZE; i++) {
                lock_reqs[i].lock_id = lock_ids[i];
                lock_reqs[i].lock_op = LOCK_EXCLUSIVE;
                lock_reqs[i].expire_time = DLOCK_MAX_EXPIRE_TIMEOUT;
            }
            memset(lock_results, 0, sizeof(lock_results));
            ret = batch_trylock(ctx->client_ids[0], MAX_LOCK_BATCH_SIZE, lock_reqs, lock_results);
            CHKERR_JUMP(ret != TEST_SUCCESS, "batch_trylock", EXIT);
            for(int i = 0; i < MAX_LOCK_BATCH_SIZE; i++) {
                CHKERR_JUMP(lock_results[i].op_ret != DLOCK_SUCCESS, "batch_trylock", EXIT);
            }
            for(int i = 0; i < MAX_LOCK_BATCH_SIZE; i++) {
                lock_reqs[i].lock_id = lock_ids[i];
                lock_reqs[i].lock_op = EXTEND_LOCK_EXCLUSIVE;
                lock_reqs[i].expire_time = DLOCK_MAX_EXPIRE_TIMEOUT * 2;
            }
            memset(lock_results, 0, sizeof(lock_results));
            ret = batch_lock_extend(ctx->client_ids[0], MAX_LOCK_BATCH_SIZE, lock_reqs, lock_results);
            CHKERR_JUMP(ret != TEST_SUCCESS, "batch_lock_extend", EXIT);

            memset(lock_results, 0, sizeof(lock_results));
            ret = batch_unlock(ctx->client_ids[0], MAX_LOCK_BATCH_SIZE, lock_ids, lock_results);
            CHKERR_JUMP(ret != TEST_SUCCESS, "batch_unlock", EXIT);
            ret = batch_release_lock(ctx->client_ids[0], MAX_LOCK_BATCH_SIZE, lock_ids);
            CHKERR_JUMP(ret != TEST_SUCCESS, "batch_unlock", EXIT);
            TEST_LOG_INFO("[k:%d] end\n", k);
        }
    }
    sync_time("-------------------------- 3");
    rc = TEST_SUCCESS;
EXIT:
    sync_time("-------------------------- 4");
    return rc;
}


int main(int argc, char *argv[])
{
    int ret;
    test_dlock_ctx_t *ctx = test_dlock_ctx_init(argc, argv, 1);
    ret = run_test(ctx);
    ret += test_dlock_ctx_uninit(ctx);
    return ret;
}