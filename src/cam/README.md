# CAM

 **CAM**  is short for  **C** ommunication  **A** cceleration for  **M** atrix on Ascend NPU. CAM provides EP (Expert Parallelism) communication kernels, high performance KVCache transfer for PD disaggregation and KVC pooling, AFD communication kernels, RL weights transfer and so on. CAM is easily to be run in single kernel mode or integrated into vllm or SGLang framework. 

# Roadmap

- [x]  **EP Communication: Dispatch & Combine** 
  - [x] Support A2
  - [x] Support A3
  - [x] Support low latency mode
  - [ ] Support high throughput mode
  - [ ] Support BF16/FP16 input
- [x]  **FusedDeepMoE: Dispatch + GEMM + Combine** 
  - [ ] Support A2
  - [x] Support A3
  - [x] Support low latency mode
  - [ ] Support high throughput mode
  - [ ] Support BF16/FP16 input
  - [x] Support W8A8 for GEMM
  - [ ] Support W4A8 for GEMM
- [ ]  **KVCache Transfer** 
- [ ]  **RL Weights Transfer** 
- [ ]  **AFD Communication**
 
# Performance
(To be done)

# Quick Start
(To be done)