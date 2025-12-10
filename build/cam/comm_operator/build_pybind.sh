#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: pybind building script
# Create: 2025-12-09
# Note:
# History: 2025-12-09 create pybind building script

set -e
EXT_PATH=${MODULE_BUILD_PATH}/deep_ep
DIST_OUT_PATH=$MODULE_BUILD_OUT_PATH
DIST_GEN_PATH=$EXT_PATH/output

OUTPUT_DIR=${MODULE_BUILD_PATH}/deep_ep/output
echo "outpath: ${OUTPUT_DIR}"

COMPILE_OPTIONS=""

build_deepep()
{
    BUILD_DIR="build"

    if [ -d "$BUILD_DIR" ]; then
        rm -rf $BUILD_DIR
    fi
    mkdir -p $BUILD_DIR

    cmake $COMPILE_OPTIONS -DCMAKE_INSTALL_PREFIX="$OUTPUT_DIR" -DASCEND_HOME_PATH=$ASCEND_HOME_PATH -B "$BUILD_DIR" -S .
    cmake --build "$BUILD_DIR" -j8 && cmake --build "$BUILD_DIR" --target install
}

make_deepep_package()
{
    if pip3 show wheel;then
        echo "wheel has been installed"
    else
        pip3 install wheel
    fi

    PYTHON_DIR="python"
    cd "$PYTHON_DIR" || exit

    cp -v ${OUTPUT_DIR}/lib/* "$EXT_PATH"/python/deep_ep/
    if [ -d "${EXT_PATH}/python/dist" ]; then
        rm -rf ${EXT_PATH}/python/dist
    fi
    python3 setup.py bdist_wheel
    mv -v "$EXT_PATH"/python/dist/umdk_cam_operator_normal*.whl ${OUTPUT_DIR}/
}

build_pybind()
{
    if [ -d "$$MODULE_SRC_PATH/pybind/deep_ep" ]; then
        rm -rf $MODULE_SRC_PATH/pybind/deep_ep
    fi
    cp -rf $MODULE_SRC_PATH/pybind/deep_ep $MODULE_BUILD_PATH
    cp -rf $MODULE_SRC_PATH/pybind/pytorch_extension $MODULE_BUILD_PATH
    cd $EXT_PATH
    build_deepep
    make_deepep_package
    if [ -d "$DIST_GEN_PATH" ]; then
        echo "copy $DIST_GEN_PATH to $DIST_OUT_PATH/"
        cp -rf $DIST_GEN_PATH/umdk_cam_operator_normal*.whl $DIST_OUT_PATH/
    else
        echo $DIST_GEN_PATH does not exist
        echo "build_pybind fail"
    fi
}

build_pybind