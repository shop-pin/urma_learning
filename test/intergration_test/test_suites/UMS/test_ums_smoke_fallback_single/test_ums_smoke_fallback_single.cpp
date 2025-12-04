/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: ums example
 */

#include "public.h"
#include <set>
#include <vector>
#include <string>

using namespace std;
using namespace publiccase;

static int run_test()
{
    int ret = 0;
    int rc = TEST_FAILED;
    if (ctx->app_id == PROC_2) {
        char serv_cmd[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(serv_cmd, MAX_EXEC_CMD_RET_LEN, "nohup qperf -lp %d &", g_test_ums_ctx.test_port,);
    }
    sync_time("----------------------------1");
    if (ctx->app_id == PROC_1) {
        char clnt_cmd[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(clnt_cmd, MAX_EXEC_CMD_RET_LEN, "nohup ums_run qperf %s -lp %d -m 8192 -t 0 tcp_bw 2>&1 &", g_test_ums_ctx.server_ip, g_test_ums_ctx.test_port);
    }
    sync_time("----------------------------2");
    
    // 校验流量走ums
    char port_str[10]={0};
    sprintf(port_str, "%d", g_test_ums_ctx.test_port);
    int check_num = query_proc_net_ums_detail_stram_num("False", port_str);
    if (ctx->app_id == PROC_1 && check_num != 2) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "fallback single connect failed", EXIT);

    char close_qperf[MAX_EXEC_CMD_RET_LEN];
    exec_cmd(close_qperf, MAX_EXEC_CMD_RET_LEN, "pkill -9 qperf");
    rc = UMS_SUCCESS;
EXIT:
    sync_time("----------------------------3");
    return rc;
}

int main(int argc, char *argv[]) {
    int ret;
    test_ums_ctx_t *ctx = test_ums_ctx_init(argc, argv, 1);
    ret = run_test(ctx);
    ret += test_ums_ctx_uninit(ctx);
    return ret;
}