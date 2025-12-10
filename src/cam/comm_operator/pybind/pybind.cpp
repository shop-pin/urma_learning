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
}

TORCH_LIBRARY(umdk_cam_op_lib, m) {
    m.def("fused_deep_moe(Tensor x, Tensor expertIds, Tensor gmm1PermutedWeight, Tensor gmm1PermutedWeightScale, \
    Tensor gmm2Weight, Tensor gmm2WeightScale, Tensor expertSmoothScalesOptional, Tensor expertScalesOptional, \
    str groupEp, int epRankSize, int epRankId, int moeExpertNum, int shareExpertNum, int shareExpertRankNum, \
    int quantMode, int globalBs) -> Tensor");
}