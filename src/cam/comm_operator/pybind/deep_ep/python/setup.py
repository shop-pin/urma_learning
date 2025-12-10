#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: pybind setup file
# Create: 2025-12-03
# Note:
# History: 2025-12-03 create pybind setup file

import os
import subprocess
import setuptools
from setuptools import find_namespace_packages, find_packages
from setuptools.dist import Distribution

# Eliminate timestamp differences in whl compressed packages
os.environ["SOURCE_DATE_EPOCH"] = "0"

current_version = os.getenv("VERSION", "1.0.0")

class BinaryDistribution(Distribution):
    """Distribution which always forces a binary package with platform name"""

    def has_ext_modules(self):
        return True

try:
    cmd = ["git", "rev-parse", "--short=8", "HEAD"]
    revision = "+" + subprocess.check_output(cmd).strip().decode("utf-8")
except Exception as _:
    revision = ""
print(f'revision: {revision}')

setuptools.setup(
    name="umdk_cam_operator_normal",
    version=current_version + revision,
    author="",
    author_email="",
    description="python api for deep_ep",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=["torch"],
    python_requires=">=3.7",
    package_data={"deep_ep": ["deep_ep_cpp.cpython*.so", "vendors", "vendors/**"]},
    distclass=BinaryDistribution
)
