# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

# this is the cmakelist file for deepep build
# deepep will be built as separated wheel package
project("DeepepCam")
cmake_minimum_required(VERSION 3.16)
set(PROJECT_BUILD_PATH ${PROJECT_BINARY_DIR})
set(TARGET_INSTALL_DIR ${CMAKE_INSTALL_PREFIX})
set(ASCEND_HOME_PATH ${ASCEND_HOME_PATH})

find_program(PYTHON_EXECUTABLE NAMES python3 python)
message(STATUS "PYTHON_EXECUTABLE:${PYTHON_EXECUTABLE}")

# find pybind11
execute_process(
    COMMAND ${PYTHON_EXECUTABLE} "-c"
    "from __future__ import print_function; import os; import pybind11;
print(os.path.dirname(pybind11.__file__),end='');"
    RESULT_VARIABLE _PYTHON_SUCCESS
    OUTPUT_VARIABLE PYBIND11_DIR)

if(NOT _PYTHON_SUCCESS MATCHES 0)
    message(STATUS "PYBIND11_DIR: ${PYBIND11_DIR}")
    message(FATAL_ERROR "Pybind11 config Error.")
endif()

message(STATUS "PYBIND11_DIR: ${PYBIND11_DIR}")
list(APPEND CMAKE_PREFIX_PATH ${PYBIND11_DIR})
find_package(pybind11 REQUIRED)

# find torch
execute_process(
    COMMAND ${PYTHON_EXECUTABLE} "-c"
    "from __future__ import print_function; import os; import torch;
print(os.path.dirname(torch.__file__),end='');"
    RESULT_VARIABLE _TORCH_SUCCESS
    OUTPUT_VARIABLE TORCH_DIR)

if(NOT _TORCH_SUCCESS MATCHES 0)
    message(STATUS "PyTorch: ${TORCH_DIR}")
    message(FATAL_ERROR "Torch config Error.")
endif()
message(STATUS "TORCH_DIR: ${TORCH_DIR}")
list(APPEND CMAKE_PREFIX_PATH ${TORCH_DIR})

# find torch_npu
execute_process(
    COMMAND ${PYTHON_EXECUTABLE} "-c"
    "from __future__ import print_function; import os; import importlib.util;
print(os.path.dirname(importlib.util.find_spec('torch_npu').origin),end='');"
    RESULT_VARIABLE _TORCH_NPU_SUCCESS
    OUTPUT_VARIABLE TORCH_NPU_DIR)

if(NOT _TORCH_NPU_SUCCESS MATCHES 0)
    message(STATUS "PyTorch npu: ${TORCH_NPU_DIR}")
    message(FATAL_ERROR "Torch_npu config Error.")
endif()
message(STATUS "TORCH_NPU_DIR: ${TORCH_NPU_DIR}")
list(APPEND CMAKE_PREFIX_PATH ${TORCH_NPU_DIR})

message(STATUS "CMAKE_PREFIX_PATH = ${CMAKE_PREFIX_PATH}")

file(GLOB SOURCES_DEEPEP *.cpp)

# --- Dynamically determine the value of _GLIBCXX_USE_CXX11_ABI  ---
if (NOT DEFINED GLIBCXX_USE_CXX11_ABI)
    message(STATUS "Attempting to determine PyTorch C++ ABI compatibility...")

    execute_process(
        COMMAND ${PYTHON_EXECUTABLE} "-c"
    "import torch; print(torch.compiled_with_cxx11_abi())"
    OUTPUT_VARIABLE PYTORCH_ABI_OUTPUT
    ERROR_VARIABLE PYTORCH_ABI_ERROR
    RESULT_VARIABLE PYTORCH_ABI_RESULT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (PYTORCH_ABI_RESULT EQUAL 0)
        if ("${PYTORCH_ABI_OUTPUT}" STREQUAL "False")
            set(GLIBCXX_USE_CXX11_ABI 0)
            message(STATUS "Pytorch reports old C++ ABI (False). Setting _GLIBCXX_USE_CXX11_ABI=0.")
        elseif ("${PYTORCH_ABI_OUTPUT}" STREQUAL "True")
            set(GLIBCXX_USE_CXX11_ABI 1)
            message(STATUS "Pytorch reports C++11 ABI (True). Setting _GLIBCXX_USE_CXX11_ABI=1.")
        else()
            message(WARNING "Unexpected output from torch.compiled_with_cxx11_abi(): '${PYTORCH_ABI_OUTPUT}'"
                    "Defaulting to C++11 ABI (1). Please verify your Pytorch installation.")
            set(GLIBCXX_USE_CXX11_ABI 1)
        endif()
    else()
        message(FATAL_ERROR "Failed to determine Pytorch C++ ABI."
                "Please ensure 'torch' is installed and "
                "'torch.compiled_with_cxx11_abi()' is available in your Python environment. "
                "Error output: ${PYTORCH_ABI_ERROR}"
                "Result code: ${PYTORCH_ABI_RESULT}")
    endif()
endif()
message(STATUS "Final determined _GLIBCXX_USE_CXX11_ABI=${GLIBCXX_USE_CXX11_ABI}.")
set(_GLIBCXX_USE_CXX11_ABI ${GLIBCXX_USE_CXX11_ABI})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_USE_CXX11_ABI=${_GLIBCXX_USE_CXX11_ABI}")

pybind11_add_module(deep_ep_cpp pybind_extension.cpp ${SOURCES_DEEPEP})
target_compile_options(deep_ep_cpp PRIVATE -fstack-protector-strong -O2 -D_FORTIFY_SOURCE=2)
target_link_options(deep_ep_cpp PRIVATE -Wl,-z,relro,-z,now)
set_target_properties(deep_ep_cpp PROPERTIES CXX_STANDARD 17)
target_include_directories( deep_ep_cpp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}

    ${TORCH_DIR}/include
    ${TORCH_DIR}/include/torch/csrc/api/include
    ${TORCH_NPU_DIR}/include
    ${TORCH_NPU_DIR}/include/third_party/acl/inc/acl
    ${TORCH_NPU_DIR}/include/third_party/acl/inc
    ${ASCEND_HOME_PATH}/include
)
target_link_directories(deep_ep_cpp PRIVATE
        ${TORCH_DIR}/lib
        ${TORCH_NPU_DIR}/lib
        ${ASCEND_HOME_PATH}/lib64
)
target_link_libraries(deep_ep_cpp PRIVATE
    torch_python
    ascendcl
    hccl
    torch_npu
)

message(STATUS "TARGET_INSTALL_DIR = ${TARGET_INSTALL_DIR}")
install(TARGETS deep_ep_cpp
    LIBRARY DESTINATION ${TARGET_INSTALL_DIR}/lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)
