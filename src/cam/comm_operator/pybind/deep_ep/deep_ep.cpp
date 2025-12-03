/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: buffer class cpp implementation file
 * Create: 2025-12-03
 * Note:
 * History: 2025-12-03 create buffer class cpp implementation file
 */

#include <memory>
#include <pybind11/functional.h>

#include "hccl/hccl.h"
#include "deep_ep.hpp"
#include "../pytorch_extension/pytorch_npu_helper.hpp"

#define TOKEN_SRC_INFO_LEN 3
#define NO_SCALES 0

namespace deep_ep {
Buffer::Buffer(int64_t rank, int64_t num_ranks, std::string moe_all_to_all_group_name)
    : rank(rank),
      num_ranks(num_ranks),
      moe_all_to_all_group_name(moe_all_to_all_group_name)
{
    rdma_rank = rank;

    if (moe_all_to_all_group_name.empty()) {
        char *ranktable_file = std::getenv("RANK_TABLE_FILE");
        aclrtGetDevice(&device_id);
        HcclCommInitClusterInfo(ranktable_file, device_id, &ep_comm);
    }
}

Buffer::~Buffer() noexcept(false) {}

std::tuple<at::Tensor, std::optional<at::Tensor>, std::vector<int>, at::Tensor, at::Tensor>
Buffer::intranode_dispatch(const at::Tensor &x, const std::optional<at::Tensor> &x_scales,
                           const std::optional<at::Tensor> &topk_idx, const std::optional<at::Tensor> &topk_weights,
                           const std::optional<at::Tensor> &num_tokens_per_rank, const at::Tensor &is_token_in_rank,
                           const std::optional<at::Tensor> &num_tokens_per_expert, const std::optional<at::Tensor>& recv_count,
                           const std::optional<at::Tensor>& recv_offset, int num_worst_tokens)
{
    auto num_tokens = static_cast<int>(x.size(0)), hidden = static_cast<int>(x.size(1));
    auto num_experts = static_cast<int64_t>(num_tokens_per_expert->size(0));
    auto num_local_experts = static_cast<int>(num_experts / num_ranks);

    int num_topk = static_cast<int>(topk_idx->size(1));

    auto options_cpu = torch::TensorOptions().dtype(torch::kInt32).device(torch::kCPU);
    at::Tensor send_data_cpu = at::zeros({num_experts * TOKEN_SRC_INFO_LEN}, options_cpu);
    at::Tensor num_tokens_per_expert_cpu = num_tokens_per_expert.value().to(torch::kCPU);
    auto num_tokens_per_expert_ptr = num_tokens_per_expert_cpu.data_ptr<int>();
    auto send_data_ptr =  send_data_cpu.data_ptr<int>();
    int32_t prefix_sum = 0;
    at::Tensor send_data_offset_cpu = at::zeros({num_experts},options_cpu);
    auto send_data_offset_ptr = send_data_offset_cpu.data_ptr<int>();
    for (int i = 0; i < num_experts; ++i) {
        send_data_ptr[i * TOKEN_SRC_INFO_LEN] = num_tokens_per_expert_ptr[i];
        send_data_ptr[i * TOKEN_SRC_INFO_LEN + 1] = prefix_sum;
        send_data_ptr[i * TOKEN_SRC_INFO_LEN + 2] = num_tokens;
        send_data_offset_ptr[i] = prefix_sum;
        prefix_sum += num_tokens_per_expert_ptr[i];
    }

    auto send_data_offset = send_data_offset_cpu.to(x.device());
    
    // get ep name
    char hcom_ep_name[128];
    if (!moe_all_to_all_group_name.empty()) {
        std::memcpy(hcom_ep_name, moe_all_to_all_group_name.data(), moe_all_to_all_group_name.size() + 1);
    } else {
        HcclGetCommName(ep_comm, hcom_ep_name);
    }

    std::vector<int32_t> local_expert_acc(num_experts, 0);
    auto send_token_idx_cpu = at::zeros({num_tokens, num_topk}, options_cpu);
    auto send_token_idx_ptr = send_token_idx_cpu.data_ptr<int>();

    auto topk_idx_cpu = topk_idx.value().to(at::kCPU);
    auto topk_idx_ptr = topk_idx_cpu.data_ptr<int32_t>();
    for (int i = 0; i < num_tokens; ++i) {
        for (int j = 0; j < num_topk; ++j) {
            int32_t expert_idx = topk_idx_ptr[i * num_topk + j];
            if (expert_idx >= 0) {
                int32_t cnt = local_expert_acc[expert_idx];
                send_token_idx_ptr[i * num_topk + j] = cnt;
                local_expert_acc[expert_idx]++;
            }
        }
    }

    auto recv_count_cpu = recv_count.value().to(at::kCPU);
    auto recv_data_ptr = recv_data_cpu.data_ptr<int>();
    std::vector<int> num_recv_tokens_per_expert_list;

    for (int i = 0; i < num_local_experts; ++i) {
        num_recv_tokens_per_expert_list.push_back(recv_count_ptr[(i + 1) * num_ranks - 1]);
    }

    int64_t tp_size = 1;
    int64_t tp_rank = 0;
    int64_t quant_mode = NO_SCALES;
    int64_t global_bs = num_ranks * static_cast<int64_t>(num_worst_tokens);

    auto send_token_idx = send_token_idx_cpu.to(x.device());
    int64_t total_recv_tokens = recv_count_ptr[num_experts - 1];
    int total_cnt = total_recv_tokens == 0 ? 1 : total_recv_tokens;
    auto expandx_out = at::zeros({total_cnt, hidden}, x.options());
    auto dynamic_scales_out = at::zeros({total_cnt}, at::dtype(at::kFloat).device(x.device()));
    auto expand_idx_out = at::zeros({total_cnt * TOKEN_SRC_INFO_LEN}, at::dtype(at::kInt).device(x.device()));
    at::Tensor expert_ids = topk_idx.value().to(at::kInt);

    EXEC_NPU_CMD(aclnnCamMoeDispatchNormal, x, expert_ids, send_data_offset, send_token_idx, recv_offset.value(),
                 recv_count.value(), hcom_ep_name,
                 num_ranks,  // rankSize
                 rank,       // rankId
                 hcom_ep_name, tp_size, tp_rank, num_experts, quant_mode, global_bs, expandx_out, dynamic_scales_out,
                 expand_idx_out);

    // Return values
    return {expandx_out,
            dynamic_scales_out,
            num_recv_tokens_per_expert_list,
            expand_idx_out,
            recv_count.value()};
}

std::tuple<torch::Tensor, std::optional<torch::Tensor>>
Buffer::intranode_combine(const torch::Tensor &x, const torch::Tensor &topk_idx,
                          const std::optional<torch::Tensor> &topk_weights, const torch::Tensor &src_idx,
                          const torch::Tensor &send_head)
{
    at::Tensor recv_x = x;

    at::Tensor topk_idx_p = topk_idx;

    auto topk_idx_int32 = topk_idx_p.to(at::kInt);
    at::Tensor expand_ids = topk_idx_int32;
    at::Tensor token_src_info = src_idx;
    at::Tensor ep_send_counts = send_head;
    auto device = x.device();

    const int num_tokens = topk_idx_p.size(0);
    const int num_topk = topk_idx_p.size(1);
    at::Tensor expert_scales;
    // for padding
    if (topk_weights.has_value()) {
        std::vector<at::Tensor> weight_blocks;
        if (topk_weights->size(0) != 0) {
            weight_blocks.emplace_back(topk_weights.value());
        }
        expert_scales = torch::cat(weight_blocks, 0);
    } else {
        expert_scales = at::ones({num_tokens, num_topk}, at::dtype(at::kFloat).device(device));
    }

    int64_t hidden = static_cast<int>(recv_x.size(1));
    at::Tensor tp_send_counts = at::empty({1}, at::dtype(at::kInt).device(device));
    int64_t tp_world_size = 1;
    int64_t tp_rankId = 0;
    int64_t moe_expert_number = send_head.size(0) * num_ranks;
    int64_t global_bs = topk_idx_p.size(0) * num_ranks;

    // get ep & tp name
    char hcom_ep_name[128];
    if (!moe_all_to_all_group_name.empty()) {
        std::copy(moe_all_to_all_group_name.begin(), moe_all_to_all_group_name.end(), hcom_ep_name);
        hcom_ep_name[moe_all_to_all_group_name.length()] = '\0';
    } else {
        HcclGetCommName(ep_comm, hcom_ep_name);
    }

    // Combine data
    auto combined_x = torch::empty({expert_scales.size(0), hidden}, x.options());
    std::optional<torch::Tensor> recv_topk_weights;

    EXEC_NPU_CMD(aclnnCamMoeCombineNormal, recv_x, token_src_info, ep_send_counts, expert_scales, tp_send_counts,
                 hcom_ep_name, num_ranks, rank, hcom_ep_name, tp_world_size, tp_rankId, moe_expert_number, global_bs,
                 combined_x);

    return {combined_x, recv_topk_weights};
}
}  // namespace deep_ep
