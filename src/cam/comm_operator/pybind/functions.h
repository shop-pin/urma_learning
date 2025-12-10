/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add functions
 * Create: 2025-12-10
 * Note:
 * History: 2025-12-10 add functions
 */

#ifndef COMMON_OPS_CSRC_FUNCTIONS_H_
#define COMMON_OPS_CSRC_FUNCTIONS_H_

#include <ATen/ATen.h>
#include <torch/script.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"

at::Tensor fused_deep_moe_impl_autograd(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::Tensor &gmm1PermutedWeight, \
    const at::Tensor &gmm1PermutedWeightScale, \
    const at::Tensor &gmm2Weight, \
    const at::Tensor &gmm2WeightScale, \
    const at::Tensor &expertSmoothScalesOptional, \
    const at::Tensor &expertScalesOptional, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t shareExpertNum, \
    int64_t shareExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBs);
#endif // COMMON_OPS_CSRC_FUNCTIONS_H_