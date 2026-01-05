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

std::vector<at::Tensor> fused_deep_moe_impl_autograd(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::Tensor &gmm1PermutedWeight, \
    const at::Tensor &gmm1PermutedWeightScale, \
    const at::Tensor &gmm2Weight, \
    const at::Tensor &gmm2WeightScale, \
    const c10::optional<at::Tensor> &expertSmoothScalesOptional, \
    const c10::optional<at::Tensor> &expertScalesOptional, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBs);

std::tuple<at::Tensor, at::Tensor, at::Tensor>
moe_dispatch_normal_impl_autograd(
    const at::Tensor &x, \
    const at::Tensor &topkIdx, \
    const at::Tensor &sendOffset, \
    const at::Tensor &sendTokenIdx, \
    const at::Tensor &recvOffset, \
    const at::Tensor &recvCount, \
    c10::string_view groupEp, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    c10::string_view groupTp, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t moeExpertNum, \
    int64_t quantMode, \
    int64_t globalBs);

at::Tensor
moe_combine_normal_impl_autograd(
    const at::Tensor &recvX, \
    const at::Tensor &tokenSrcInfo, \
    const at::Tensor &epRecvCounts, \
    const at::Tensor &recvTopkWeights, \
    const c10::optional<at::Tensor> &tpRecvCounts, \
    c10::string_view epGroupName, \
    int64_t epWorldSize, \
    int64_t epRankId, \
    c10::string_view tpGroupName, \
    int64_t tpWorldSize, \
    int64_t tpRankId, \
    int64_t moeExpertNum, \
    int64_t globalBs);
#endif // COMMON_OPS_CSRC_FUNCTIONS_H_