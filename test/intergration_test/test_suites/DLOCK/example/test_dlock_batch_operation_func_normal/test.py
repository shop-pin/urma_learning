# -*- coding: utf-8 -*-
"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: dlock example
"""

"""DLOCK batch接口基础功能

:Preparation
1、两个计算节点

:TestStep
1、client、server初始化
2、client调用batch_get_lock接口获取31把锁
3、client调用batch_trylock 31把锁， batch_lock_extend 31把锁
4、client调用batch_unlock 31把锁
5、client调用batch_release_lock 31把锁
6、client、server反初始化

:ExpectOutput
1、成功
2、成功
3、成功
4、成功
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

    def test_dlock_batch_operation_func_normal(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, random_host=False)
