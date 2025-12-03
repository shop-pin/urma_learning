# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma example
"""

import random
import logging
from public import UBUSFeature
 
log = logging.getLogger()
 
 
class Test(UBUSFeature):
 
    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')
 
    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()
 
    def test_urma_qemu_smoke_8host_agg_dev_type(self):
        p_list = []
        cmd_list = ["read_bw", "write_bw", "send_bw", "read_lat", "write_lat", "send_lat"]
        mode_list = ["-p 0", "-p 1"]

        # 随机打20条流
        for _ in range(20):
            host1, host2 = random.sample(self.host_list, 2)
            p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2))
        # 遍历所有打流类型
        for cmd in cmd_list:
            for mode in mode_list:
                host1, host2 = random.sample(self.host_list, 2)
                p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2, cmd_syntax=cmd, opt=mode))

        # 再次随机打20条流
        for _ in range(20):
            host1, host2 = random.sample(self.host_list, 2)
            p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2))