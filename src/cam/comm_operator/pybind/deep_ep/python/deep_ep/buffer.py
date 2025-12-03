#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: buffer class implementation file
# Create: 2025-12-03
# Note:
# History: 2025-12-03 create buffer class implementation file
#

import os
import torch
import torch_npu
import torch.distributed as dist

import deep_ep_cpp
from typing import Callable, List, Optional, Tuple, Union

class Buffer:
    def __init__(self, group: dist.ProcessGroup) -> None:
        self.rank = group.rank()
        self.group_size = group.size()
        try:
            backend = group._get_backend(torch.device("npu"))
            moe_all_to_all_group_name = backend.get_hccl_comm_name(self.rank)
        except Exception as e:
            print("get_hccl_comm_name failed", e)
            moe_all_to_all_group_name = ""
        self.runtime = deep_ep_cpp.Buffer(self.rank, self.group_size, moe_all_to_all_group_name)

    # noinspection PyTypeChecker
    def dispatch(
        self,
        x: Union[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]],
        handle: Optional[Tuple] = None,
        num_tokens_per_rank: Optional[torch.Tensor] = None,
        is_token_in_rank: Optional[torch.Tensor] = None,
        num_tokens_per_expert: Optional[torch.Tensor] = None,
        recv_count: Optional[torch.Tensor] = None,
        recv_offset: Optional[torch.Tensor] = None,
        topk_idx: Optional[torch.Tensor] = None,
        topk_weights: Optional[torch.Tensor] = None,
        num_worst_tokens: int = 0) -> Tuple[
        Union[Tuple[torch.Tensor, torch.Tensor], torch.Tensor],
        List[int],
        Tuple]:
        """
        Dispatch tokens to different ranks.

        Arguments:
            x: `torch.Tensor` or tuple of `torch.Tensor`, for the first type, the shape must be `[num_tokens, hidden]`,
                and type must be `torch.bfloat16`; for the second type, the first element of the tuple must be shaped as
                `[num_tokens, hidden]` with type `torch.float8_e4m3fn`, the second must be `[num_tokens, hidden // 128]`
                 (requiring divisible) with type `torch.float`.
            handle: an optional communication handle, if set, the CPU will reuse the layout information to save some time.
            num_tokens_per_rank: `[num_ranks]` with `torch.int`, the number of tokens to be sent to each rank.
            num_tokens_per_rdma_rank: `[num_rdma_ranks]` with `torch.int`, the number of tokens to be sent to each RDMA
                rank (with the same GPU index), return `None` for intranode settings.
            is_token_in_rank: `[num_tokens, num_ranks]` with `torch.bool`, whether a token be sent to a rank.
            num_tokens_per_expert: `[num_experts]` with `torch.int`, the number of tokens to be sent to each expert.
            recv_count: `[num_experts]` with `torch.int`, the number of tokens to be receive of each expert.
            recv_offset: `[num_experts]` with `torch.int`, the offset number of tokens for each expert.
            topk_idx: `[num_tokens, num_topk]` with `torch.int64`, the expert indices selected by each token,
                `-1` means no selections.
            topk_weights: `[num_tokens, num_topk]` with `torch.float`, the expert weights of each token to dispatch.
            num_worst_tokens: the worst number of tokens to receive, if specified, there will be no CPU sync, and it
                will be CUDA-graph compatible. Please also notice that this flag is for intranode only.

        Returns:
            recv_x: received tokens, the first element is a `torch.Tensor` shaped as `[received_token_count, hidden]` with
                `torch.int8`, the second tensor is the corresponding scales for the first element with shape `[received_token_count]`
                with `torch.float`.
            num_recv_tokens_per_expert_list: Python list shaped `[num_local_experts]`, the received token count by
                each local expert, aligned to the input `expert_alignment`. If `num_worst_tokens` is specified, the list
                will be empty.
            handle: the returned communication handle.
        """
        # Default config
        config = self.get_dispatch_config(self.group_size) if config is None else config

        # Launch the kernel with cached or non-cached mode
        if isinstance(x, tuple):
            raise NotImplementedError("Not support fp8")
        x_scales = None

        if handle is not None:
            raise NotImplementedError(
                "Optional communication handle is not supported yet."
            )
        else:
            assert (
                num_tokens_per_rank is not None
                and num_tokens_per_expert is not None
            )
            (
                recv_x,
                recv_x_scales,
                num_recv_tokens_per_expert_list,
                recv_src_idx,
                send_head
            ) = self.runtime.intranode_dispatch(
                x,
                x_scales,
                topk_idx,
                topk_weights,
                num_tokens_per_rank,
                is_token_in_rank,
                num_tokens_per_expert,
                recv_count,
                recv_offset,
                num_worst_tokens
            )
            handle = (
                recv_src_idx,
                is_token_in_rank,
                topk_idx,
                send_head
            )
            return (
                (recv_x, recv_x_scales),
                num_recv_tokens_per_expert_list,
                handle
            )

        # noinspection PyTypeChecker

    def combine(
        self,
        x: torch.Tensor,
        handle: Tuple,
        topk_weights: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        """
        Combine (reduce) tokens (addition **without** weights) from different ranks.

        Arguments:
            x: `[num_tokens, hidden]` with `torch.bfloat16`, the tokens to send for reducing to its original ranks.
            handle: a must-set communication handle, you can obtain this from the dispatch function.
            topk_weights: `[num_tokens, num_topk]` with `torch.float`, the tokens' top-k weights for reducing to its original ranks.

        Returns:
            recv_x: the reduced token from its dispatched ranks.
            recv_topk_weights: the reduced top-k weights from its dispatch ranks.
        """

        (
            recv_src_idx,
            is_token_in_rank,
            topk_idx,
            send_head
        ) = handle

        # Launch the kernel
        recv_x, recv_topk_weights = self.runtime.intranode_combine(
            x, topk_idx, topk_weights, recv_src_idx, send_head)
        return recv_x, recv_topk_weights