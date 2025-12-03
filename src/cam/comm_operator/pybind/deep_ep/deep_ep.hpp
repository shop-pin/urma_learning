/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: buffer class cpp header file
 * Create: 2025-12-03
 * Note:
 * History: 2025-12-03 create buffer class cpp header file
 */
 
#pragma once

#include <torch/types.h>
#include <torch/python.h>
#include <tuple>
#include <vector>
#include <optional>
#include "hccl/hccl.h"
#include "hccl/hccl_types.h"

namespace deep_ep {

struct Buffer {
    int64_t rank, rdma_rank;
    int64_t num_ranks;
private:
    std::string moe_all_to_all_group_name;
    int device_id;
    HcclComm ep_comm;

public:
    Buffer(int64_t rank, int64_t num_ranks, std::string moe_all_to_all_group_name);

    ~Buffer() noexcept(false);

    std::tuple<at::Tensor, std::optional<at::Tensor>, std::vector<int>, at::Tensor, at::Tensor>
    intranode_dispatch(const at::Tensor &x, const std::optional<at::Tensor> &x_scales,
                       const std::optional<at::Tensor> &topk_idx, const std::optional<at::Tensor> &topk_weights,
                       const std::optional<at::Tensor> &num_tokens_per_rank, const at::Tensor &is_token_in_rank,
                       const std::optional<at::Tensor> &num_tokens_per_expert, const std::optional<at::Tensor>& recv_count,
                       const std::optional<at::Tensor>& recv_offset, int num_worst_tokens);

    std::tuple<torch::Tensor, std::optional<torch::Tensor>>
    intranode_combine(const torch::Tensor &x, const torch::Tensor &topk_idx,
                      const std::optional<torch::Tensor> &topk_weights, const torch::Tensor &src_idx,
                      const torch::Tensor &send_head);
};
}  // namespace deep_ep
