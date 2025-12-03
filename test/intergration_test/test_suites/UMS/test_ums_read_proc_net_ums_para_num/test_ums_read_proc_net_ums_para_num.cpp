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
    char ret1[50]
    char cmd[MAX_EXEC_CMD_RET_LEN];
    char para_num[40]
    exec_cmd(cmd, MAX_EXEC_CMD_RET_LEN, "tail -n 10 /proc/net/ums | head -n 1 | awk '{print $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11}'");
    strcpy(para_num, cmd);
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
    int ret;
    test_ums_ctx_t *ctx = test_ums_ctx_init(argc, argv, 1);
    ret = run_test(ctx);
    ret += test_ums_ctx_uninit(ctx);
    return ret;
}