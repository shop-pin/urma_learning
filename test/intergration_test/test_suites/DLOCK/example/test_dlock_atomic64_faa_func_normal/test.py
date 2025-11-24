# -*- coding: utf-8 -*-
"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: dlock example
"""

"""DLOCK分布式状态对象FAA基础功能

:Preparation
1、两个计算节点

:TestStep
1、host1启动server，执行dserver_lib_init，server_start接口
2、host1和host2个字实例化一个client_id,调用dclient_lib_init,client_init接口
3、host1和host2各自创建一个分布式对象，调用umo_atomic64_create, umo_atomic64_get接口
4、host1和host2循环进行faa操作，调用umo_atomic64_faa，调用umo_atomic64_get_snapshot验证faa操作是否成功
5、host1和host2执行反初始化，依次调用umo_atomic64_release, umo_atomic64_destroy，client_deinit,dclient_lib_deinit
6、host1停止server端，调用server_stop,dserver_lib_deinit

:ExpectOutput
1、成功
2、成功
3、成功
4、成功，faa操作校验成功
5、成功
6、成功

"""

import logging
import os
import sys

from app.dlock.dlock_app import prepare_test_case, exec_test_case

local_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(local_path))
from public import UBUSFeature

log = logging.getLogger()

class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')
        prepare_test_case(self.host_list, local_path)

    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    def test_dlock_atomic64_faa_func_normal(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, random_host=False)
