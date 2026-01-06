/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add pybind
 * Create: 2025-12-10
 * Note:
 * History: 2025-12-10 add pybind
 */

#include <torch/extension.h>
#include "functions.h"

PYBIND11_MODULE(TORCH_EXTENSION_NAME, m)
{
    m.def("fused_deep_moe", &fused_deep_moe_impl_autograd, "fused_deep_moe");
    m.def("moe_dispatch_normal", &moe_dispatch_normal_impl_autograd, "moe_dispatch_normal");
    m.def("moe_combine_normal", &moe_combine_normal_impl_autograd, "moe_combine_normal");
}

TORCH_LIBRARY(umdk_cam_op_lib, m) {
    m.def("fused_deep_moe(Tensor x, Tensor expertIds, Tensor[] gmm1PermutedWeight, Tensor[] gmm1PermutedWeightScale, \
    Tensor[] gmm2Weight, Tensor[] gmm2WeightScale, Tensor? expertSmoothScalesOptional, Tensor? expertScalesOptional, \
    str groupEp, int epRankSize, int epRankId, int moeExpertNum, int sharedExpertNum, int sharedExpertRankNum, \
    int quantMode, int globalBs) -> Tensor[]");
    m.def("moe_dispatch_normal(Tensor x, Tensor topkIdx, Tensor sendOffset, Tensor sendTokenIdx, Tensor recvOffset, \
    Tensor recvCount, str groupEp, int epWorldSize, int epRankId, str groupTp, int tpWorldSize, int tpRankId, \
    int moeExpertNum, int quantMode, int globalBs) -> (Tensor, Tensor, Tensor)");
    m.def("moe_combine_normal(Tensor recvX, Tensor tokenSrcInfo, Tensor epRecvCounts, Tensor recvTopkWeights, \
    Tensor? tpRecvCounts, str epGroupName, int epWorldSize, int epRankId, str tpGroupName, int tpWorldSize, \
    int tpRankId, int moeExpertNum, int globalBs) -> Tensor");
}