/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add fused_deep_moe file
 * Create: 2025-12-10
 * Note:
 * History: 2025-12-10 fused_deep_moe file
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include <hccl/hccl.h>
#include <iostream>

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using tensor_list = std::vector<at::Tensor>;
using namespace at;
using namespace std;

constexpr int KERNEL_PARAM_CNT = 3;

std::vector<at::Tensor> fused_deep_moe_impl_npu(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1PermutedWeight, \
    const at::TensorList &gmm1PermutedWeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const c10::optional<at::Tensor> &expertSmoothScalesOptional, \
    const c10::optional<at::Tensor> &expertScalesOptional, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBs
)
{
    auto xShape = x.sizes();
    auto expertIdsShape = expertIds.sizes();
    int h = xShape[1];
    int bs = expertIdsShape[0];
    int topk = expertIdsShape[1];
    
    at::Tensor output = at::empty({bs, h}, x.options());
    
    bool isShareExpert = (epRankId < sharedExpertRankNum);
    int64_t localExpertNum = 0;
    if (isShareExpert) {
        localExpertNum = 1;
    } else {
        localExpertNum = moeExpertNum / (epRankSize - sharedExpertRankNum);
    }
    auto opts = expertIds.options().dtype(at::kLong);
    at::Tensor expert_token_nums = at::empty({localExpertNum}, opts);
    
    // 必须要求对齐fused_deep_moe.cpp 先input 跟着 attr， 然后output
    vector<char> group_ep_chrs(groupEp.begin(), groupEp.end());
    group_ep_chrs.push_back('\0');
    char *group_ep_ptr = &group_ep_chrs[0];
    
    // 必须要求对齐fused_deep_moe.cpp 先input 跟着 attr, 然后output
    EXEC_NPU_CMD(aclnnFusedDeepMoe,
        // input
        x, expertIds, gmm1PermutedWeight, gmm1PermutedWeightScale, gmm2Weight, gmm2WeightScale, \
        expertSmoothScalesOptional, expertScalesOptional, \
        // attr
        group_ep_ptr, epRankSize, epRankId, moeExpertNum, sharedExpertNum, sharedExpertRankNum, quantMode, globalBs, \
        // output
        output, expert_token_nums);
    return {output, expert_token_nums};
}

std::vector<at::Tensor> fused_deep_moe_backward_impl_npu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self); // 创建输出内存
    return {result, result};
}

std::vector<at::Tensor> fused_deep_moe_impl_meta(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1PermutedWeight, \
    const at::TensorList &gmm1PermutedWeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const c10::optional<at::Tensor> &expertSmoothScalesOptional, \
    const c10::optional<at::Tensor> &expertScalesOptional, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBs)
{
    auto xShape = x.sizes();
    auto expertIdsShape = expertIds.sizes();
    int h = xShape[1];
    int bs = expertIdsShape[0];
    at::Tensor output = at::empty({bs, h}, x.options().device(at::kMeta));

    bool isShareExpert = (epRankId < sharedExpertRankNum);
    int64_t localExpertNum = 0;
    if (isShareExpert) {
        localExpertNum = 1;
    } else {
        localExpertNum = moeExpertNum / (epRankSize - sharedExpertRankNum);
    }
    auto opts = expertIds.options().dtype(at::kLong); 
    at::Tensor expert_token_nums = at::empty({localExpertNum}, opts.device(at::kMeta)); 
    
    return {output, expert_token_nums};
}

std::vector<at::Tensor> fused_deep_moe_impl(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1PermutedWeight, \
    const at::TensorList &gmm1PermutedWeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const c10::optional<at::Tensor> &expertSmoothScalesOptional, \
    const c10::optional<at::Tensor> &expertScalesOptional, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBs)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::fused_deep_moe", "")
                        .typed<decltype(fused_deep_moe_impl)>();
    return op.call(x, expertIds, gmm1PermutedWeight, gmm1PermutedWeightScale, gmm2Weight, gmm2WeightScale, \
        expertSmoothScalesOptional, expertScalesOptional, \
        groupEp, epRankSize, epRankId, moeExpertNum, sharedExpertNum, sharedExpertRankNum, quantMode, globalBs);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class ExtFusedDeepMoe : public torch::autograd::Function<ExtFusedDeepMoe> {
public:
    static std::vector<at::Tensor> forward(AutogradContext *ctx, \
                            const at::Tensor &x, \
                            const at::Tensor &expertIds, \
                            const at::TensorList &gmm1PermutedWeight, \
                            const at::TensorList &gmm1PermutedWeightScale, \
                            const at::TensorList &gmm2Weight, \
                            const at::TensorList &gmm2WeightScale, \
                            const c10::optional<at::Tensor> &expertSmoothScalesOptional, \
                            const c10::optional<at::Tensor> &expertScalesOptional, \
                            c10::string_view groupEp, \
                            int64_t epRankSize, \
                            int64_t epRankId, \
                            int64_t moeExpertNum, \
                            int64_t sharedExpertNum, \
                            int64_t sharedExpertRankNum, \
                            int64_t quantMode, \
                            int64_t globalBs)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = fused_deep_moe_impl(x, expertIds, gmm1PermutedWeight, gmm1PermutedWeightScale, gmm2Weight, \
            gmm2WeightScale, expertSmoothScalesOptional, expertScalesOptional, \
            groupEp, epRankSize, epRankId, moeExpertNum, sharedExpertNum, sharedExpertRankNum, quantMode, globalBs);
        return result;
    }

    static std::vector<at::Tensor> backward(AutogradContext *ctx, std::vector<at::Tensor> grad_outputs)
    {
        return {at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor()};
    }
};

std::vector<at::Tensor> fused_deep_moe_impl_autograd(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1PermutedWeight, \
    const at::TensorList &gmm1PermutedWeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const c10::optional<at::Tensor> &expertSmoothScalesOptional, \
    const c10::optional<at::Tensor> &expertScalesOptional, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t sharedExpertNum, \
    int64_t sharedExpertRankNum, \
    int64_t quantMode, \
    int64_t globalBs)
{
    auto result = ExtFusedDeepMoe::apply(x, expertIds, gmm1PermutedWeight, gmm1PermutedWeightScale, gmm2Weight, \
            gmm2WeightScale, expertSmoothScalesOptional, expertScalesOptional, \
            groupEp, epRankSize, epRankId, moeExpertNum, sharedExpertNum, sharedExpertRankNum, quantMode, globalBs);
        return result;
}

// fused_deep_moe
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("fused_deep_moe", &fused_deep_moe_impl_npu);
    m.impl("fused_deep_moe_backward", &fused_deep_moe_backward_impl_npu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("fused_deep_moe", &fused_deep_moe_impl_autograd);
}

// 为Meta设备注册前反向实现
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("fused_deep_moe", &fused_deep_moe_impl_meta);
}