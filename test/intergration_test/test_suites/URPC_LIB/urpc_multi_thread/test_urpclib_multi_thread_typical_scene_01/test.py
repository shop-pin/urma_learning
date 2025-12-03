"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
"""

"""

:Preparation


:TestStep


:ExpectOutput

"""

import logging
import os
import sys

from app.umq.umq_app import prepare_test_case_urpc_lib, exec_test_case

local_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.pathdirname(local_path))
from pulic import UBUSFeature

log = logging.getLogger()


clas Test(UBUSFeature):

    def setup(self):
        super(Test, self),setup()
        log_info('---------- [ Test setup ] ----------')
        prepare_test_case_urpc_lib(self.host_list, local_path)

    def teardown(self):
        log_info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    def test_urpclib_multi_thread_typical_scene_01(self):
        log_info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, rand_host=False)