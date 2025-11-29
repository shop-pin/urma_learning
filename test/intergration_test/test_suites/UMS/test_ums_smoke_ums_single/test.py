# -*- coding: utf-8 -*-

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This progream is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# See LICENSE for more details.

# Copyright (C) 2016-2021 Huawei Inc

# Author l30057389
# pylint: disable=

import logging
import os
import sys
import random

from app.ums.ums_app import prepare_test_case

local_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(local_path))
from public import UBUSFeature

log = logging.getLogger()

class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('--------- [ Test setup ] ---------')
        prepare_test_case(self.host_list, local_path)

    def teardown(self):
        log.info('--------- [ Test teardown ] ---------')
        super(Test, self).teardown()

    def test_ums_smoke_ums_single(self):
        log.info(f'--------- [ Test local_path = {local_path} ] ---------')
        self.exec_test_case(local_path=local_path)

if __name__ == '__main__':
    Test.test1()