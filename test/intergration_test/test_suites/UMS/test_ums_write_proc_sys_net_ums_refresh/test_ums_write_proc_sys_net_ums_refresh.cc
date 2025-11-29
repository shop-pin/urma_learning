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
    char clnt_buf[2097152] = {0}, serv_buf[2097152] = {0};
    vector<int> vec_random = {131072, 262144, 524288, 1048576, 2097152, 4194304}
    int ret = 0;
    int rc = TEST_FAILED;
    for (int i=0; i<vec_random.size(); i++) {
        char cmd_revise_snd[100];
        sprintf(cmd_revise_snd, "echo %d > /proc/sys/net/ums/snd_buf", vec_random[i]);
        exec_cmd(cmd_revise_snd);
        char cmd_revise_rcv[100];
        sprintf(cmd_revise_rcv, "echo %d > /proc/sys/net/ums/rcv_buf", vec_random[i]);
        exec_cmd(cmd_revise_rcv);

        if (ctx->app_id == PROC_2) {
            char cmd0[100] = "nohup ums_run qperf -lp 4549 &";
            exec_cmd(cmd0);

        }
        sync_time("----------------------------1");
        if (ctx->app_id == PROC_1) {
            char cmd1[100];
            sprinf(cmd1, "nohup ums_run qperf %s -lp 4549 -t 0 -m 8192 tcp_lat &", server_ip);
            exec_cmd(cmd1);
        }
        sync_time("----------------------------2");
        char server_ip_str[10]={0};
        sprintf(server_ip_str, "%d", server_ip);
        int check_num = query_proc_net_ums_detail_stram_num("False", server_ip_str);
        if (ctx->app_id == PROC_1 && check_num != 2) {
            ret = -1;
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "ums connection error", EXIT);
        exec_cmd("pkill -9 qperf");
    }
    
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