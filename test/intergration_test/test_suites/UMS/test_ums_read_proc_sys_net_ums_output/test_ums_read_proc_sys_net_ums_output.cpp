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
    char ret1[50], ret2[50], ret3[50], ret4[50]
    char cmd1[MAX_EXEC_CMD_RET_LEN];
    char cmd2[MAX_EXEC_CMD_RET_LEN];
    char cmd3[MAX_EXEC_CMD_RET_LEN];
    char cmd4[MAX_EXEC_CMD_RET_LEN];
    exec_cmd(cmd1, MAX_EXEC_CMD_RET_LEN, "cat /proc/sys/net/ums/autocorking_size");
    strcpy(ret1, cmd1);
    if (atoi(ret1) != 524288) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "autocorking_size error", EXIT);
    exec_cmd(cmd2, MAX_EXEC_CMD_RET_LEN, "cat /proc/sys/net/ums/dim_enable");
    strcpy(ret2, cmd2);
    if (atoi(ret2) != 0) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "dim_enable error", EXIT);
    exec_cmd(cmd3, MAX_EXEC_CMD_RET_LEN, "cat /proc/sys/net/ums/rcv_buf");
    strcpy(ret3, cmd3);
    if (atoi(ret3) != 1048576) {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "recv_buf error", EXIT);
    exec_cmd(cmd4, MAX_EXEC_CMD_RET_LEN, "cat /proc/sys/net/ums/snd_buf");
    strcpy(ret4, cmd4);
    if (atoi(ret4) != 1048576) {
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