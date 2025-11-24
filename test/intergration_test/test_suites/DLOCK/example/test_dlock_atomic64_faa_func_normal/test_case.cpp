/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: dlock example
 */

#include "../public.h"
using namespace dlock;
#define TEST_NUM 1000

static int run_test(test_dlock_ctx_t *ctx)
{
    int ret, rc = TEST_FAILED;
    int obj_id = 1;
    uint64_t init_val = 0;
    uint64_t res_val = 0;
    uint64_t add_val = 0;
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, nullptr);
    int p_desc = ctx->app_id;
    struct umo_atomic64_desc desc = {0};
    ret = test_server_prepare(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_prepare", EXIT);
    sync_time("-------------------------- 1");
    ret = test_client_prepare(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_prepare", EXIT);
    sync_time("-------------------------- 2");
    desc.lease_time = tv_start.tv_sec + 60000;
    desc.p_desc = (char *)(&p_desc);
    desc.len = 4;
    ret = test_dlock_atomic64_create_get(ctx->client_ids[0], &desc, init_val, &obj_id);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_dlock_atomic64_create_get", EXIT);
    sync_time("-------------------------- 3");
    for (int i = 0; i < TEST_NUM; i++) {
        TEST_LOG_INFO("[i:%d] start\n",i);
        add_val = 1;
        ret = umo_atomic64_faa(ctx->client_ids[0], obj_id, add_val, &res_val);
        CHKERR_JUMP(ret != TEST_SUCCESS, "umo_atomic64_faa", EXIT);
        CHKERR_JUMP(res_val != i, "umo_atomic64_faa", EXIT);

        ret = umo_atomic64_get_snapshot(ctx->client_ids[0], obj_id, &res_val);
        CHKERR_JUMP(ret != TEST_SUCCESS, "umo_atomic64_get_snapshot", EXIT);
        CHKERR_JUMP(res_val != i + 1, "umo_atomic64_get_snapshot", EXIT);
        TEST_LOG_INFO("[i:%d] end\n",i);
    }
    ret = test_dlock_atomic64_create_get(ctx->client_ids[0], obj_id);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_dlock_atomic64_create_get", EXIT);
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