/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: UMS fault isolation on the management plane and date plane test
 * Author: l30057389
 * TestCase: ums建链信息读取
 */

#include "../public.h"
#include <string>

using namespace std;
using namespace publiccase;

static int run_test()
{
    int ret = 0;
    int rc = TEST_FAILED;
    char ret1[50]
    char cmd[100] = "tail -n 10 /proc/net/ums | head -n 1 | awk '{print $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11}'";
    char para_num[40]
    host1.exec_cmd(cmd);
    strcpy(para_num, host1.stdout_);
    string str_para_num(para_num);
    if (str_para_num != "Index SRC_IP:Port DEST_IP State Fallback SRC_EID, JETTY_ID DEST_EID, JETTY_ID L_QPN R_QPN") {
        ret = -1;
    }
    CHKERR_JUMP(ret != TEST_SUCCESS, "para num name error", EXIT);
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