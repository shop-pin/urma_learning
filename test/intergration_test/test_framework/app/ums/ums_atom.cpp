/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: ums app
*/
#include "ums_atom.h"
using namespace ums;
test_ums_ctx_t g_test_ums_ctx;

test_ums_ctx_t *test_ums_ctx_init(int argc, char *argv[], int thread_num)
{
    (void)memset(&g_test_ums_ctx, 0, sizeof(test_ums_ctx_t));
    pid_t pid = getpid();
    g_test_ums_ctx.pid = (uint64_t)pid;
    test_context *ctx = create_test_ctx(argc, argv, thread_num);
    if (ctx == nullptr) {
        TEST_LOG_ERROR("create_test_ctx failed\n");
        return nullptr;
    }
    g_test_ums_ctx.ctx = ctx;
    g_test_ums_ctx.app_id = ctx->app_id;
    g_test_ums_ctx.app_num = ctx->app_num;
    g_test_ums_ctx.test_port = ctx->test_port;
    g_test_ums_ctx.server_ip = ctx->server_ip;
    g_test_ums_ctx.trans_mode = static_cast<trans_mode_t>(ctx->mode);
    if (ctx->mode == 0) {
        TEST_LOG_INFO("test_case trans_mode_t=%d is SEPERATE_CONN\n", ctx->mode);
    } else if (ctx->mode == 1) {
        TEST_LOG_INFO("test_case trans_mode_t=%d is UNI_CONN\n", ctx->mode);
    }
    g_test_ums_ctx.log_level = 4;
    g_test_ums_ctx.ssl_enable = false;
    g_test_ums_ctx.client_num = 1;
    return &g_test_ums_ctx;
}

int test_ums_server_uninit(test_ums_ctx_t *ctx) 
{
    int ret = 0;
    if(ctx->app_id <= PROC_2) {
        if (ctx->server_id == 0) {
            return TEST_SUCCESS;
        }
        ret = server_stop(ctx->server_id);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("server stop ret = %d\n", ret);
            return TEST_FAILED;
        }
        dserver_lib_deinit();
    }
    return TEST_SUCCESS;
}

int test_ums_client_uninit(test_ums_ctx_t *ctx)
{
    int ret;
    if (ctx->client_ids == nullptr) {
        return TEST_SUCCESS;
    }
    for(int i = 0; i < ctx->client_num; i++) {
        if (ctx->client_ids[i] == 0) {
            TEST_LOG_WARN("client_id %d is null\n", i);
            continue;
        }
        ret = client_deinit(ctx->client_ids[i]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("client_deinit ctx->ids[%d] %lu ret=%d\n", i, ctx->client_ids[i], ret);
            CHECK_FREE(ctx->client_ids);
            dclient_lib_deinit();
            return TEST_FAILED;
        }
    }
    CHECK_FREE(ctx->client_ids);
    dclient_lib_deinit();
    return TEST_SUCCESS;
}

int test_ums_ctx_uninit(test_ums_ctx_t *ctx) 
{
    int ret = 0;
    ret += test_ums_client_uninit(ctx);
    sync_time("-------------------------- end");
    ret += test_ums_server_uninit(ctx);
    CHECK_FREE(ctx->client_ids);
    destroy_test_ctx(g_test_ums_ctx.ctx);
    return ret;
}

int query_proc_net_ums_detail_stram_num(const char *fbk, const char *msg)
{
    char cmd[1024];
    exec_cmd(buf, MAX_EXEC_CMD_RET_LEN, "cat /proc/net/ums | awk '/%s/ {if ($5==\"%s\") print $0}' | wc -l", msg, fbk);

    return atoi(buf);
}