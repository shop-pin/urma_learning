#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: deepep init file
# Create: 2025-12-03
# Note:
# History: 2025-12-03 create deepep init file
#

import os
import torch

current_dir = os.path.dirname(os.path.abspath(__file__))
opp_path = os.path.join(current_dir, "vendors", "CAM")
lib_path = os.path.join(current_dir, "vendors", "CAM", "op_api", "lib")
# Set environment variables related to custom operators
os.environ["ASCEND_CUSTOM_OPP_PATH"] = (
    f"{opp_path}:{os.environ.get('ASCEND_CUSTOM_OPP_PATH', '')}"
)
os.environ["LD_LIBRARY_PATH"] = f"{lib_path}:{os.environ.get('LD_LIBRARY_PATH', '')}"

from .buffer import Buffer