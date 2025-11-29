/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: UMS fault isolation on the management plane and date plane test
 * Author: l30057389
 * TestCase: ums配置参数读取
 */

#include "../public.h"
#include <string>

using namespace std;
using namespace publiccase;

static int run_test()
{
    int ret = 0;
    int rc = TEST_FAILED;
    char ret1[50], ret2[50], ret3[50], ret4[50]
    char cmd1[100] = "cat /proc/sys/net/ums/autocorking_size";
    char cmd2[100] = "cat /proc/sys/net/ums/dim_enable";
    char cmd3[100] = "cat /proc/sys/net/ums/rcv_buf";
    char cmd4[100] = "cat /proc/sys/net/ums/snd_buf";
    host2.exec_cmd(cmd1);
    strcpy(ret1, host1.stdout_);
    if (atoi(ret1) != 524288) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "autocorking_size error", EXIT);
    host2.exec_cmd(cmd2);
    strcpy(ret1, host1.stdout_);
    if (atoi(ret1) != 0) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "dim_enable error", EXIT);
    host2.exec_cmd(cmd3);
    strcpy(ret1, host1.stdout_);
    if (atoi(ret1) != 1048576) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "recv_buf error", EXIT);
    host2.exec_cmd(cmd4);
    strcpy(ret1, host1.stdout_);
    if (atoi(ret1) != 1048576) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "snd_buf error", EXIT);
    rc = UMS_SUCCESS;
EXIT:
    sync_time("----------------------------1");
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