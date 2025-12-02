/*
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: ums example
 */

#include "../public.h"
#include <string>

using namespace std;
using namespace publiccase;

static int run_test()
{
    int ret = 0;
    int rc = TEST_FAILED;
    if (ctx->app_id == PROC_2) {
        char buf0[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf0, MAX_EXEC_CMD_RET_LEN, "nohup ums_run qperf -lp 4549 &");
        char buf1[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf1, MAX_EXEC_CMD_RET_LEN, "nohup qperf -lp 4549 &");
    }
    sync_time("----------------------------1");
    if (ctx->app_id == PROC_1) {
        char buf2[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf2, MAX_EXEC_CMD_RET_LEN, "nohup ums_run qperf %s -lp 4549 -t 0 -m 8192 tcp_lat &", server_ip);
        char buf3[MAX_EXEC_CMD_RET_LEN];
        exec_cmd(buf3, "nohup ums_run qperf %s -lp 4550 -t 0 -m 8192 tcp_lat &", server_ip);
    }
    sync_time("----------------------------2");
    int check_num_ums = query_proc_net_ums_detail_stram_num("False", "4549");
    if (ctx->app_id == PROC_1 && check_num_ums != 2) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "ums connection error", EXIT);
    int check_num_fallback = query_proc_net_ums_detail_stram_num("True", "4550");
    if (ctx->app_id == PROC_1 && check_num_fallback != 2) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "fallback connection error", EXIT);
    
    rc = UMS_SUCCESS;
EXIT:
    sync_time("----------------------------3");
    return rc;
}

int main(int argc, char *argv[]) {
    int rc;
    main_init_test(argc, argv);
    sync_time("### run_test begin ###");
    rc = run_test();
    sync_time("### run_test end ###");
    TEST_LOG_INFO("\ntest result is %d\n", rc);
    main_exit();
    return rc;
}