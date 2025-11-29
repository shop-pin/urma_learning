/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: UMS fault isolation on the management plane and date plane test
 * Author: l30057389
 * TestCase: ums建链地址读取
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
        char serv_cmd[300];
        sprintf(serv_cmd, "nohup ums_run qperf -lp ${i} &");
        exec_cmd(serv_cmd);
    }
    sync_time("----------------------------1");
    if (ctx->app_id == PROC_1) {
        char clnt_cmd[300];
        sprintf(clnt_cmd, "nohup ums_run qperf %s -lp ${i} -m 8192 -t 0 tcp_bw 2>&1 &", serv_ip);
        exec_cmd(clnt_cmd);
    }
    sync_time("----------------------------2");
    
    // 校验流量走ums
    int check_num = query_proc_net_ums_detail_stram_num("False", servr_ip);
    if (ctx->app_id == PROC_1 && check_num != 2) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "fallback single connect failed", EXIT);

    char close_qperf[50];
    sprintf(close_qperf, "pkill -9 qperf");
    exec_cmd(close_qperf);
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