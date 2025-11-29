/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: UMS fault isolation on the management plane and date plane test
 * Author: l30057389
 * TestCase: ums回退信息读取
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
        char cmd0[100] = "nohup ums_run qperf -lp 4549 &";
        exec_cmd(cmd0);
        char cmd1[100] = "nohup qperf -lp 4550 &";
        exec_cmd(cmd1);
    }
    sync_time("----------------------------1");
    if (ctx->app_id == PROC_1) {
        char cmd2[100];
        sprinf(cmd2, "nohup ums_run qperf %s -lp 4549 -t 0 -m 8192 tcp_lat &", server_ip);
        exec_cmd(cmd2);
        char cmd3[100];
        sprinf(cmd3, "nohup ums_run qperf %s -lp 4550 -t 0 -m 8192 tcp_lat &", server_ip);
        exec_cmd(cmd3);
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