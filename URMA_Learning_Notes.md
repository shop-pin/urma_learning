# URMA 学习笔记

> 📚 本文档记录URMA (Unified Remote Memory Access) 的学习内容，持续更新中...
> 
> 最后更新: 2026-01-12

---

## 目录

- [一、URMA概述](#一urma概述)
- [二、核心概念](#二核心概念)
- [三、数据结构详解](#三数据结构详解)
- [四、API接口参考](#四api接口参考)
- [五、编程流程](#五编程流程)
- [六、示例代码解析](#六示例代码解析)
- [七、核心实现解析](#七核心实现解析)
- [八、硬件驱动层](#八硬件驱动层)
- [九、常见问题与解答](#九常见问题与解答)
- [十、代码目录索引](#十代码目录索引)

---

## 一、URMA概述

### 1.1 什么是URMA？

**URMA (Unified Remote Memory Access)** 是UMDK中的统一远程内存访问子系统，它在UBUS系统内提供高带宽、低延迟的数据服务。

### 1.2 URMA在UMDK中的位置

这幅架构图展示了UMDK软件栈的**分层结构**，从上到下分为5层：

```
┌─────────────────────────────────────────────────────────────────┐
│                        应用层 (Application)                      │
├─────────────────────────────────────────────────────────────────┤
│   CAM    │   URPC   │   ULOCK   │   USOCK   │   用户程序         │
│  (AI加速) │  (RPC)   │  (分布式锁)│  (Socket) │                   │
├─────────────────────────────────────────────────────────────────┤
│                    ⭐ URMA (统一内存语义层) ⭐                    │
│         提供: read/write/send/recv/atomic 等操作                 │
├─────────────────────────────────────────────────────────────────┤
│                    UDMA 用户态驱动                               │
├─────────────────────────────────────────────────────────────────┤
│                    内核驱动 (ubcore/uburma)                      │
├─────────────────────────────────────────────────────────────────┤
│                    灵衢总线硬件 (UBUS Hardware)                   │
└─────────────────────────────────────────────────────────────────┘
```

#### 各层详细说明

**🔹 第一层：应用层 (Application)**

这是最上层，直接面向用户的应用程序和高级库：

| 组件 | 全称 | 说明 | 使用场景 |
|------|------|------|----------|
| **CAM** | Communication Acceleration for Machine learning | AI训练通信加速 | 深度学习训练中的allreduce、allgather等集合通信 |
| **URPC** | Unified Remote Procedure Call | 统一远程过程调用 | 微服务通信、RPC调用 |
| **ULOCK** | Unified Lock | 统一分布式锁 | 跨节点的资源同步、分布式锁服务 |
| **USOCK** | Unified Socket | 统一Socket | 兼容标准Socket API，透明加速TCP应用 |
| **用户程序** | - | 直接使用URMA API的程序 | 自定义的分布式应用 |

**🔹 第二层：URMA (统一内存语义层) ⭐ 核心层**

**这是学习的核心层！** URMA是整个架构的**中间抽象层**，起到承上启下的关键作用：

- **向上**：为上层应用（CAM/URPC/ULOCK等）提供统一的内存访问API
- **向下**：屏蔽不同硬件驱动的差异，提供统一的抽象接口

**提供的核心操作：**
- `urma_read()` / `urma_write()` - 单边读写操作
- `urma_send()` / `urma_recv()` - 双边消息传递
- `urma_post_jfs_wr()` - 批量提交工作请求
- 原子操作 (CAS, FAA) - 跨节点的原子操作

**设计优势：**
- **抽象隔离**：上层应用无需关心底层硬件细节
- **性能优化**：数据面操作在用户态完成，避免频繁的syscall
- **可扩展性**：支持多种硬件Provider（UDMA等）
- **复用性**：多个上层应用共享同一套接口

**🔹 第三层：UDMA 用户态驱动**

UDMA (Unified DMA) 是URMA的**Provider驱动**实现：

- **运行位置**：用户态空间，避免频繁的用户态-内核态切换
- **实现功能**：实现`urma_ops_t`中定义的所有操作接口
- **性能优化**：
  - 通过**mmap**直接访问硬件寄存器（Doorbell）
  - 用户态轮询完成队列，实现零拷贝
  - 性能关键代码路径在此实现
- **主要文件**：`src/urma/hw/udma/`目录下的所有文件

**🔹 第四层：内核驱动 (ubcore/uburma)**

内核空间的驱动程序，负责系统级资源管理：

| 模块 | 功能 | 职责 |
|------|------|------|
| **ubcore** | UBUS Core（统一总线核心模块） | 提供UBUS总线的基础功能：<br>- 设备发现和管理<br>- EID分配和管理<br>- 传输路径(TP)管理<br>- 硬件资源抽象 |
| **uburma** | URMA内核模块 | URMA在内核空间的实现：<br>- 内存注册和页锁定(pin memory)<br>- 权限控制和安全检查<br>- 异常事件处理<br>- 与ubcore交互完成资源分配 |

**关系说明：**
- `uburma` **依赖** `ubcore`，必须先加载`ubcore`再加载`uburma`
- `ubcore`提供UBUS总线的**基础服务**
- `uburma`在`ubcore`基础上实现URMA的**特定功能**
- 两者协同工作，共同完成内核层的资源管理

**加载顺序：**
```bash
modprobe ubcore    # 先加载核心模块
modprobe uburma    # 再加载URMA模块
```

**🔹 第五层：灵衢总线硬件 (UBUS Hardware)**

实际执行DMA操作的**物理硬件**：

- **高速互联总线**：连接多个节点的物理链路
- **DMA引擎**：执行远程内存访问的硬件单元
- **硬件队列**：SQ (Send Queue)、RQ (Receive Queue)、CQ (Completion Queue)
- **网络接口**：物理网络接口卡

#### 数据流向示意

```
用户程序调用 urma_write()
        │
        ▼
    URMA层 (urma_dp_api.c)
        │ 调用Provider操作接口
        ▼
    UDMA层 (udma_u_jfs.c)
        │ 填充WQE + 写Doorbell寄存器
        ▼ mmap (内存映射)
    ──────────────────────────────────────
    内核驱动 (ubcore/uburma)
        │ 处理中断、异常事件、资源管理
    ──────────────────────────────────────
        ▼
    灵衢总线硬件
        │ DMA传输
        ▼
    远程节点内存
```

#### 为什么这样分层？

1. **抽象隔离**：每一层只关心自己的职责，降低复杂度
2. **性能优化**：
   - 数据面操作（read/write）在用户态完成，避免syscall开销
   - 通过mmap直接访问硬件，减少内核干预
3. **可扩展性**：可以添加新的Provider支持不同硬件
4. **复用性**：CAM、URPC、ULOCK等上层应用共享同一套URMA接口
5. **安全性**：内核层负责权限控制和资源管理，保证系统安全

### 1.3 URMA的主要功能

- **单边操作 (One-Sided)**: Read/Write - 远程端不感知
- **双边操作 (Two-Sided)**: Send/Recv - 需要远程端配合
- **原子操作**: CAS (Compare-And-Swap), FAA (Fetch-And-Add)
- **多种传输模式**: RM (可靠消息), RC (可靠连接), UM (不可靠消息)

---

## 二、核心概念

### 2.1 EID (Endpoint ID) - 端点标识

#### 2.1.1 什么是EID？

**EID (Endpoint ID)** 是UBUS总线上每个设备/端点的**唯一标识符**，类似于网络中的**IP地址**。它用于在分布式系统中唯一标识一个节点上的通信端点。

#### 2.1.2 EID的结构和设计理念

EID是UBUS网络内部使用的标识符，固定为16字节。为了兼容现有的网络地址格式，EID支持两种表示方式：

**结构定义：**

```c
#define URMA_EID_SIZE 16

typedef union urma_eid {
    uint8_t raw[URMA_EID_SIZE];  // 原始字节数组（网络字节序）
    
    // IPv4映射格式 (::ffff:IPv4_addr) - 前12字节固定，仅最后4字节有效
    struct {
        uint64_t reserved;        // == 0 (固定值，高8字节全0)
        uint32_t prefix;          // == 0x0000ffff (固定值，IPv4映射前缀)
        uint32_t addr;            // IPv4地址 (网络字节序，唯一可变部分)
    } in4;
    
    // IPv6原生格式 - 16字节全部有效
    struct {
        uint64_t subnet_prefix;   // 子网前缀 (IPv6高64位)
        uint64_t interface_id;    // 接口标识 (IPv6低64位)
    } in6;
} urma_eid_t;
```

**设计要点：**

1. **UBUS网络内部使用**：EID是UBUS总线内部的路由和标识机制，用于在UBUS网络内部标识本节点和定位远程节点
2. **格式兼容**：支持IPv4映射格式和IPv6格式，便于复用节点已有的网络地址
3. **统一长度**：无论使用哪种格式，EID统一为16字节，简化处理逻辑

#### 2.1.3 EID格式详解

EID是UBUS网络内部使用的标识符，类似于IP地址在网络中的作用。为了兼容和复用现有的网络地址格式（IPv4/IPv6），EID支持两种格式表示方式：

**格式1：IPv4映射格式 (in4)**

当节点使用IPv4地址时，EID采用IPv4映射到IPv6的格式（遵循RFC 4291标准）：

- **特点**：前12字节为固定值，只有最后4字节存储实际的IPv4地址
- **固定部分**：
  - `reserved` (8字节) = `0x0000000000000000`（全0）
  - `prefix` (4字节) = `0x0000ffff`（IPv4映射前缀）
- **可变部分**：
  - `addr` (4字节) = 实际的IPv4地址（网络字节序）

```
IPv4地址: 192.168.1.100 (0xc0a80164)
映射后EID格式: ::ffff:192.168.1.100

内存布局:
┌─────────────────────────────────────────────────────────────────┐
│   reserved (8 bytes)      │  prefix (4 bytes) │  addr (4 bytes) │
│   0x0000000000000000      │   0x0000ffff      │  0xc0a80164     │
│   (固定全0)               │   (固定前缀)      │  (IPv4地址)     │
└─────────────────────────────────────────────────────────────────┘
```

**格式2：IPv6格式 (in6)**

当节点使用IPv6地址时，EID直接使用IPv6的原生格式：

- **特点**：16字节完全使用，存储完整的IPv6地址
- **结构**：
  - `subnet_prefix` (8字节) = IPv6地址的高64位（子网前缀）
  - `interface_id` (8字节) = IPv6地址的低64位（接口标识）

```
IPv6地址: 2001:0db8:85a3:0000:0000:8a2e:0370:7334

内存布局:
┌─────────────────────────────────────────────────────────────────┐
│   subnet_prefix (8 bytes)          │   interface_id (8 bytes)  │
│   2001:0db8:85a3:0000              │   0000:8a2e:0370:7334     │
│   (IPv6高64位)                      │   (IPv6低64位)            │
└─────────────────────────────────────────────────────────────────┘
```

**设计原因：**

- **兼容性**：如果节点已经有IPv4或IPv6网络地址，可以直接映射为EID使用，无需重新分配
- **统一格式**：EID统一为16字节，简化了处理逻辑
- **UBUS网络内部使用**：EID在UBUS总线内部用于路由和标识，与外部网络通信由底层网络协议栈处理

#### 2.1.4 EID的用途

EID在UBUS网络内部的核心作用：

1. **节点标识**：每个UBUS节点有一个或多个EID，用于在UBUS网络内唯一标识该节点
2. **路由寻址**：在跨节点通信时，EID用于UBUS硬件路由数据包到目标节点
3. **资源关联**：Jetty、Segment等资源与EID关联，标识资源所属的节点
4. **连接建立**：建立远程连接时需要指定对端的EID，用于确定通信目标

#### 2.1.5 EID的使用示例

```c
// 1. 获取设备的EID列表
urma_eid_info_t *eid_list;
uint32_t eid_cnt;
eid_list = urma_get_eid_list(dev, &eid_cnt);
for (uint32_t i = 0; i < eid_cnt; i++) {
    printf("EID[%u]: ", eid_list[i].eid_index);
    // 打印EID (可以转换为字符串)
}

// 2. 从字符串创建EID
urma_eid_t eid;
urma_str_to_eid("192.168.1.100", &eid);

// 3. 从IPv4整数创建EID
urma_eid_t eid;
urma_u32_to_eid(0xc0a80164, &eid);  // 192.168.1.100

// 4. 在创建上下文时指定EID索引
urma_context_t *ctx = urma_create_context(dev, eid_index);
```

#### 2.1.6 EID vs IP地址

| 特性 | EID | IP地址 |
|------|-----|--------|
| **使用范围** | UBUS总线内部网络 | 全球互联网或局域网 |
| **用途** | 标识UBUS总线端点/节点 | 标识网络节点 |
| **长度** | 固定16字节 | IPv4: 4字节, IPv6: 16字节 |
| **格式** | 支持IPv4映射格式（前12字节固定）和IPv6格式 | IPv4或IPv6 |
| **路由** | 由UBUS硬件路由 | 由网络协议栈路由 |
| **关系** | 可以基于IP地址映射生成，但在UBUS网络内独立使用 | 标准网络地址 |

#### 2.1.7 关键点总结

- **使用范围**：EID是UBUS网络内部使用的标识符，用于在UBUS总线内部标识节点和路由数据
- **格式特点**：
  - IPv4映射格式：前12字节固定（reserved=0, prefix=0x0000ffff），只有最后4字节的IPv4地址有效
  - IPv6格式：16字节全部有效，存储完整的IPv6地址
- **兼容设计**：支持基于IPv4/IPv6地址映射生成，便于复用现有网络地址
- **唯一性**：在UBUS总线上，每个EID必须是唯一的
- **网络字节序**：EID使用网络字节序（大端序）存储
- **多EID支持**：一个节点可以配置多个EID，用于不同的用途
- **分配方式**：EID通常由硬件配置或内核驱动（ubcore）分配

### 2.2 UBVA (Unified Bus Virtual Address) - 统一总线虚拟地址

#### 2.2.1 什么是UBVA？

**UBVA (Unified Bus Virtual Address)** 是URMA中用于**跨节点统一寻址**的虚拟地址。它打破了各个节点的地址边界，允许应用通过统一的虚拟地址访问分布在多个节点上的共享内存。

**核心思想：** 就像互联网上的URL可以访问全球任何地方的资源一样，UBVA可以在UBUS总线上访问任何节点的内存。

#### 2.2.1.1 为什么说"打破节点地址边界"？

为了更好地理解这个概念，让我们对比传统方式和UBVA方式：

**传统方式：节点地址空间相互隔离**

在传统的分布式系统中，每个节点的进程都有**独立的虚拟地址空间**，地址只在节点内部有效：

```
节点A (EID: 192.168.1.100)          节点B (EID: 192.168.1.101)
┌─────────────────────────┐         ┌─────────────────────────┐
│  进程P1的地址空间        │         │  进程P2的地址空间        │
│                         │         │                         │
│  0x1000 ──→ [数据A]     │         │  0x1000 ──→ [数据B]     │
│  0x2000 ──→ [数据C]     │         │  0x2000 ──→ [数据D]     │
│                         │         │                         │
│  ❌ 无法直接访问节点B    │         │  ❌ 无法直接访问节点A    │
│     的内存               │         │     的内存               │
└─────────────────────────┘         └─────────────────────────┘
```

**问题：**
- 节点A的进程P1想访问节点B的数据B（地址0x1000），但节点A的0x1000指向的是数据A
- 仅凭虚拟地址0x1000无法区分是哪个节点的内存
- 必须通过**网络协议**（如TCP/IP）进行通信，需要额外的序列化/反序列化

**UBVA方式：统一地址空间**

UBVA通过**EID + UASID + VA**的组合，创建了一个**跨节点的统一地址空间**：

```
┌─────────────────────────────────────────────────────────────────┐
│                    UBUS统一地址空间 (UBVA)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  节点A (EID: 192.168.1.100)                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ UBVA: {EID: A, UASID: 1, VA: 0x1000} ──→ [数据A]       │   │
│  │ UBVA: {EID: A, UASID: 1, VA: 0x2000} ──→ [数据C]       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  节点B (EID: 192.168.1.101)                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ UBVA: {EID: B, UASID: 1, VA: 0x1000} ──→ [数据B]       │   │
│  │ UBVA: {EID: B, UASID: 1, VA: 0x2000} ──→ [数据D]       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ✅ 节点A可以通过完整UBVA直接访问节点B的内存！                    │
│     例如：{EID: B, UASID: 1, VA: 0x1000} → 数据B              │
└─────────────────────────────────────────────────────────────────┘
```

**关键理解：**

1. **"打破边界"的含义**：
   - 传统：每个节点的地址空间是**隔离的**，地址只在节点内有效
   - UBVA：通过EID标识节点，创建了**全局统一的地址空间**

2. **"统一虚拟地址"的含义**：
   - 不是指所有节点使用相同的VA值
   - 而是指通过**UBVA（EID+UASID+VA）**可以唯一标识任何节点的任何内存
   - 就像URL（协议+域名+路径）可以访问全球任何资源一样

3. **实际效果**：
   - 应用可以使用**统一的UBVA格式**访问任何节点的内存
   - 不需要关心目标内存在哪個节点上
   - 硬件自动根据EID路由到正确的节点

#### 2.2.1.2 实际应用示例

**场景：节点A的进程需要访问节点B的内存**

```c
// === 节点B：注册内存段 ===
// 节点B的进程在地址0x1000处有数据
urma_seg_cfg_t seg_cfg = {
    .va = 0x1000,  // 节点B内部的虚拟地址
    .len = 1024,
    // ...
};
urma_target_seg_t *local_seg = urma_register_seg(ctx_b, &seg_cfg);

// 注册后，系统生成UBVA：
// UBVA = {EID: 节点B的EID, UASID: 节点B进程的UASID, VA: 0x1000}

// === 节点A：导入并访问节点B的内存 ===
// 1. 通过信息交换获得节点B的UBVA信息
urma_seg_t remote_seg_info = {
    .ubva = {
        .eid = node_b_eid,      // 节点B的EID
        .uasid = node_b_uasid,  // 节点B进程的UASID
        .va = 0x1000            // 节点B的虚拟地址
    },
    .len = 1024,
    // ...
};

// 2. 导入远程段
urma_target_seg_t *remote_seg = urma_import_seg(ctx_a, &remote_seg_info, 
                                                  &token, 0, 0);

// 3. 使用UBVA直接访问节点B的内存（就像访问本地内存一样）
urma_read(jfs, target_jetty,
          local_seg,      // 本地目标段
          remote_seg,     // 远程源段（包含完整UBVA）
          local_va,       // 本地目标地址
          remote_seg->seg.ubva.va,  // 远程源地址（从UBVA获取）
          1024, flag, user_ctx);

// ✅ 节点A成功读取了节点B地址0x1000处的数据！
//    虽然两个节点都有地址0x1000，但通过UBVA可以明确区分
```

#### 2.2.1.3 UBVA的唯一性保证

**核心理解：EID+UASID+VA = 全局唯一标识**

你的理解完全正确！**UBVA通过EID+UASID+VA的组合来唯一标识UBUS网络中的每一个虚拟内存地址**。

**唯一性保证：**

```
给定 UBVA = {EID: X, UASID: Y, VA: Z}

无论从哪个节点访问这个UBVA：
┌─────────────────────────────────────────────────────────────┐
│  节点A访问 {EID:X, UASID:Y, VA:Z}                          │
│  节点B访问 {EID:X, UASID:Y, VA:Z}                          │
│  节点C访问 {EID:X, UASID:Y, VA:Z}                          │
│  ...                                                       │
│                                                             │
│  ✅ 所有访问都指向：节点X的进程Y的虚拟地址Z                  │
│     即：同一主机的同一进程的同一VA                           │
└─────────────────────────────────────────────────────────────┘
```

**示例说明：**

```
节点A (EID: 192.168.1.100)          节点B (EID: 192.168.1.101)
进程P1 (UASID: 1)                   进程P2 (UASID: 1)
地址0x1000处有数据"Hello"            地址0x1000处有数据"World"

UBVA_A = {EID: 192.168.1.100, UASID: 1, VA: 0x1000} → "Hello"
UBVA_B = {EID: 192.168.1.101, UASID: 1, VA: 0x1000} → "World"

从节点C访问：
- 访问UBVA_A → 读取到"Hello"（节点A的数据）
- 访问UBVA_B → 读取到"World"（节点B的数据）

✅ 即使两个节点都有相同的UASID和VA，通过EID可以明确区分
```

**关键要点：**

1. **全局唯一性**：EID+UASID+VA的组合在UBUS网络内是唯一的
2. **访问一致性**：无论从哪个节点访问同一个UBVA，都访问到同一个目标
3. **地址解析**：
   - EID → 确定目标节点
   - UASID → 确定目标进程地址空间
   - VA → 确定目标虚拟地址
4. **类比理解**：
   - 就像URL（协议+域名+路径）可以唯一标识互联网上的资源
   - UBVA（EID+UASID+VA）可以唯一标识UBUS网络上的内存

**注意事项：**

- **Token验证**：虽然UBVA唯一标识内存，但访问还需要Token验证权限
- **段必须已注册**：目标内存段必须在目标节点上通过`urma_register_seg()`注册
- **导入后才能访问**：访问节点必须先通过`urma_import_seg()`导入远程段

**对比总结：**

| 特性 | 传统方式 | UBVA方式 |
|------|---------|----------|
| **地址范围** | 每个节点独立 | 跨节点统一 |
| **访问方式** | 通过网络协议（TCP/IP） | 直接内存访问（DMA） |
| **地址标识** | 仅VA（无法跨节点） | EID+UASID+VA（全局唯一） |
| **唯一性** | 仅在同一节点内唯一 | 在整个UBUS网络内唯一 |
| **访问一致性** | 不同节点访问相同VA指向不同内存 | 相同UBVA从任何节点访问都指向同一内存 |
| **性能** | 需要序列化/网络传输 | 硬件DMA，零拷贝 |
| **透明度** | 需要显式网络调用 | 像访问本地内存一样 |

#### 2.2.2 UBVA的组成

UBVA由三个部分组成，总共28字节：

```
┌──────────────────────────────────────────────────────────────────┐
│                          UBVA (28 bytes)                         │
├─────────────────┬─────────────────┬─────────────────────────────┤
│      EID        │     UASID       │            VA                │
│   (16 bytes)    │   (4 bytes)     │        (8 bytes)             │
│   端点标识       │  地址空间ID      │       虚拟地址               │
│  (哪个节点)      │  (哪个进程空间)   │     (哪个内存地址)           │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

**结构定义：**

```c
typedef struct urma_ubva {
    urma_eid_t eid;      // 端点标识 (16字节) - 标识目标节点
    uint32_t uasid;      // 用户地址空间ID (4字节) - 区分不同进程空间
    uint64_t va;         // 虚拟地址 (8字节) - 目标内存地址
} __attribute__((packed)) urma_ubva_t;
```

#### 2.2.3 三个组成部分详解

**1. EID (Endpoint ID) - 端点标识 (16字节)**

- **作用**：标识目标节点/设备
- **类比**：就像IP地址标识网络中的主机
- **示例**：`192.168.1.100` 对应的EID

**2. UASID (User Address Space ID) - 用户地址空间ID (4字节)**

- **全称**：User Address Space ID（用户地址空间标识符）
- **作用**：区分同一节点上的不同进程地址空间
- **原因**：不同进程的虚拟地址可能相同（如都是0x1000），需要用UASID区分
- **类比**：就像端口号区分同一主机上的不同进程
- **分配**：由系统分配，通常通过`urma_init()`或上下文创建时指定

**3. VA (Virtual Address) - 虚拟地址 (8字节)**

- **作用**：目标内存的虚拟地址
- **范围**：进程虚拟地址空间内的地址
- **说明**：这是目标进程看到的虚拟地址，不是物理地址

#### 2.2.4 UBVA地址解析流程

```
应用使用UBVA访问远程内存
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  1. 解析EID → 找到目标节点                                   │
│     "这是哪个节点？"                                          │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  2. 解析UASID → 找到目标进程地址空间                          │
│     "这是节点上的哪个进程空间？"                               │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  3. 解析VA → 找到具体内存地址                                 │
│     "这是进程空间中的哪个地址？"                               │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
   硬件DMA引擎执行远程内存访问
```

#### 2.2.5 UBVA的使用场景

**场景1：注册内存段**

```c
// 本地节点注册内存段
urma_seg_cfg_t seg_cfg = {
    .va = (uint64_t)buffer,      // 本地虚拟地址
    .len = 1024 * 1024,
    // ...
};
urma_target_seg_t *local_seg = urma_register_seg(ctx, &seg_cfg);

// local_seg->seg.ubva 包含完整的UBVA信息：
// - ubva.eid: 本地节点的EID
// - ubva.uasid: 当前进程的UASID
// - ubva.va: buffer的虚拟地址
```

**场景2：导入远程内存段**

```c
// 远程节点通过信息交换获得UBVA
urma_seg_t remote_seg = {
    .ubva = {
        .eid = remote_eid,        // 远程节点EID
        .uasid = remote_uasid,    // 远程进程UASID
        .va = remote_va           // 远程虚拟地址
    },
    .len = 1024 * 1024,
    // ...
};

// 导入远程段（需要Token验证）
urma_target_seg_t *import_seg = urma_import_seg(ctx, &remote_seg, 
                                                  &token, 0, 0);
```

**场景3：远程内存访问**

```c
// 使用导入的段进行远程写操作
urma_write(jfs, target_jetty,
           import_seg,      // 目标段（包含UBVA信息）
           local_seg,       // 源段
           import_seg->seg.ubva.va,  // 目标地址（从UBVA获取）
           (uint64_t)local_buffer,   // 源地址
           1024,            // 长度
           flag, user_ctx);
```

#### 2.2.6 UBVA vs 普通虚拟地址

| 特性 | UBVA | 普通VA |
|------|------|--------|
| **范围** | 跨多个节点 | 单个进程空间 |
| **组成** | EID + UASID + VA | 仅VA |
| **长度** | 28字节 | 8字节 (64位系统) |
| **用途** | 分布式共享内存 | 本地进程内存 |
| **解析** | 需要硬件支持 | CPU MMU解析 |

#### 2.2.7 UBVA的设计优势

1. **统一编址**：打破节点边界，实现全局地址空间
2. **透明访问**：应用可以像访问本地内存一样访问远程内存
3. **安全性**：通过UASID隔离不同进程，通过Token验证权限
4. **可扩展性**：支持大量节点和进程

#### 2.2.8 EID与UBVA的关系

**关系图示：**

```
UBVA = EID + UASID + VA
  │     │     │      │
  │     │     │      └── 进程虚拟地址
  │     │     └───────── 进程地址空间ID
  │     └─────────────── 节点标识 (EID)
  └───────────────────── 完整的远程地址
```

**关键理解：**

- **EID是UBVA的一部分**：UBVA使用EID来标识目标节点
- **EID标识"在哪里"**：告诉系统数据要发送到哪个节点
- **UBVA标识"在哪里+哪个进程+哪个地址"**：完整描述远程内存位置
- **关系类比**：
  - EID = IP地址（标识主机）
  - UBVA = IP:端口:路径（完整资源定位）

#### 2.2.9 实际示例

假设有两个节点：

```
节点A (EID: 192.168.1.100, UASID: 1)
  进程P1 (UASID: 1) 在地址0x1000处有数据

节点B (EID: 192.168.1.101, UASID: 1)
  进程P2 (UASID: 1) 想要访问节点A的数据
```

节点B使用UBVA访问：

```c
urma_ubva_t target_ubva = {
    .eid = { /* 192.168.1.100 */ },  // 节点A的EID
    .uasid = 1,                       // 进程P1的UASID
    .va = 0x1000                      // 数据地址
};

// 使用这个UBVA进行远程读操作
urma_read(jfs, target_jetty, 
          import_seg, local_seg,
          local_va, target_ubva.va,  // 使用UBVA中的VA
          len, flag, user_ctx);
```

### 2.3 Segment - 内存段

#### 2.3.1 什么是Segment？

**Segment（内存段）** 是URMA中用于远程内存访问的**连续内存区域**。它是URMA内存管理的基本单位，应用程序必须先将内存注册为Segment，才能进行远程内存访问操作。

**核心概念：**
- Segment是一段**连续的虚拟地址空间**，对应已分配的物理内存
- Segment由**Home节点**创建和注册
- 其他节点通过**导入**Segment来获得访问权限
- 每个Segment都有唯一的**UBVA**标识

#### 2.3.2 Segment的数据结构

**1. 注册配置结构 (urma_seg_cfg_t)**

用于注册本地内存段的配置：

```c
typedef struct urma_seg_cfg {
    uint64_t va;                  // [必需] 内存的虚拟地址（必须是页对齐）
    uint64_t len;                 // [必需] 内存长度（必须是页大小的倍数）
    urma_token_id_t *token_id;    // [可选] Token ID（用于Token表模式）
    urma_token_t token_value;     // [必需] 安全Token值（用于访问验证）
    urma_reg_seg_flag_t flag;     // [必需] 标志位（访问权限、Token策略、缓存策略等）
    uint64_t user_ctx;            // [可选] 用户上下文数据
    uint64_t iova;                // [可选] 用户指定的IO虚拟地址
} urma_seg_cfg_t;
```

**2. Segment信息结构 (urma_seg_t)**

用于描述Segment的信息（在信息交换时传递）：

```c
typedef struct urma_seg {
    urma_ubva_t ubva;     // [公开] Segment的UBVA（包含EID+UASID+VA）
    uint64_t len;         // [公开] Segment长度
    urma_seg_attr_t attr; // [公开] Segment属性（访问权限、Token策略、缓存性等）
    uint32_t token_id;    // [私有] Token ID（内部使用）
} urma_seg_t;
```

**3. 目标Segment结构 (urma_target_seg_t)**

注册或导入后返回的Segment句柄：

```c
typedef struct urma_target_seg {
    urma_seg_t seg;            // [私有] Segment信息
    uint64_t user_ctx;         // [私有] 用户上下文数据
    uint64_t mva;              // [公开] 映射地址（导入远程段时使用）
    urma_context_t *urma_ctx;  // [私有] 关联的URMA上下文
    urma_token_id_t *token_id; // Token ID（注册时有值，导入时为NULL）
    uint64_t handle;           // [私有] 内核句柄
} urma_target_seg_t;
```

#### 2.3.3 Segment的注册标志 (urma_reg_seg_flag_t)

注册Segment时需要设置的标志位：

```c
typedef union urma_reg_seg_flag {
    struct {
        uint32_t token_policy   : 3;  // Token验证策略
        uint32_t cacheable      : 1;  // 是否可缓存
        uint32_t dsva           : 1;  // DSVA（直接共享虚拟地址）模式
        uint32_t access         : 6;  // 访问权限（见下方详解）
        uint32_t non_pin        : 1;  // 是否不锁定页
        uint32_t user_iova      : 1;  // 是否使用用户指定的IOVA
        uint32_t token_id_valid : 1;  // Token ID是否有效
        uint32_t reserved       : 18;
    } bs;
    uint32_t value;
} urma_reg_seg_flag_t;
```

#### 2.3.4 访问权限 (Access Flags)

Segment的访问权限控制哪些操作可以被允许：

| 权限标志 | 值 | 说明 |
|---------|-----|------|
| `URMA_ACCESS_LOCAL_ONLY` | `0x1 << 0` | **仅本地访问**：只能本地进程访问，拒绝所有远程访问 |
| `URMA_ACCESS_READ` | `0x1 << 1` | **允许远程读**：远程节点可以读取此Segment |
| `URMA_ACCESS_WRITE` | `0x1 << 2` | **允许远程写**：远程节点可以写入此Segment |
| `URMA_ACCESS_ATOMIC` | `0x1 << 3` | **允许远程原子操作**：远程节点可以执行CAS、FAA等原子操作 |

**权限组合规则：**

1. **LOCAL_ONLY与其他权限互斥**：
   - 如果设置了`LOCAL_ONLY`，不能同时设置`READ`、`WRITE`、`ATOMIC`
   - `LOCAL_ONLY`表示仅本地访问，本地进程拥有所有权限（读、写、原子操作）

2. **权限层次关系**：
   - `WRITE`权限隐含`READ`权限（要写必须先能读）
   - `ATOMIC`权限需要同时有`READ`和`WRITE`权限
   - **说明**：`access`字段控制的是**远程访问权限**（READ、WRITE、ATOMIC控制远程节点能否访问本地内存）。如果设置了`WRITE`或`ATOMIC`位，意味着允许远程节点写入，那么`access`字段本身就必须包含`WRITE`位（这是代码检查的规则）。这不是说需要单独声明"本地写权限"，而是`WRITE`位本身就意味着这段内存是可写的（包括本地和远程）。

3. **权限组合示例**：
   ```c
   // 仅本地访问
   .access = URMA_ACCESS_LOCAL_ONLY
   
   // 允许远程读
   .access = URMA_ACCESS_READ
   
   // 允许远程读写
   .access = URMA_ACCESS_READ | URMA_ACCESS_WRITE
   
   // 允许远程读、写、原子操作
   .access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC
   ```

#### 2.3.5 Token策略 (Token Policy)

Token用于安全验证，控制谁可以访问Segment：

| Token策略 | 值 | 说明 |
|----------|-----|------|
| `URMA_TOKEN_NONE` | 0 | **无验证**：不需要Token验证（不安全，仅用于测试） |
| `URMA_TOKEN_PLAIN_TEXT` | 1 | **明文Token**：简单的Token验证 |
| `URMA_TOKEN_SIGNED` | 2 | **签名Token**：带签名的Token验证 |
| `URMA_TOKEN_ALL_ENCRYPTED` | 3 | **全加密**：所有数据加密传输 |

**Token工作机制：**

1. **Token值创建**：`token_value`由**注册端（Home节点）创建**（通常使用随机数生成，如`RAND_priv_bytes`）

2. **Token值传递**：通过**信息交换**（Socket等带外方式）传递给导入端
   - 在信息交换时，可以将`token_value`包含在交换的数据结构中
   - 示例代码中，`seg_jetty_info_t`结构包含`seg_token_id`（token_id），但`token_value`需要在应用层面通过信息交换传递
   - 导入端调用`urma_import_seg`时需要传入匹配的`token_value`

3. **Token验证**：导入端使用接收到的`token_value`调用`import_seg`，内核会验证Token是否匹配

```
注册Segment (节点A)                   导入Segment (节点B)
┌─────────────────────┐              ┌─────────────────────┐
│ register_seg()      │              │                      │
│ token_value = 0x123 │              │                      │
│ (由注册端生成)       │              │                      │
│                     │              │                      │
│ ────信息交换────►   │              │ import_seg()        │
│ {UBVA, token_id,    │              │ token_value = 0x123  │
│  token_value=0x123} │              │ (从信息交换获取)     │
│                     │              │                      │
│ ✅ Token匹配成功     │              │ ✅ 导入成功          │
└─────────────────────┘              └─────────────────────┘
```

**注意**：`token_id`和`token_value`的区别：
- **token_id**：由内核分配的唯一标识符，用于标识Segment（包含在`seg_jetty_info_t`中）
- **token_value**：由应用程序生成的安全凭证，用于验证访问权限（需要应用程序自己通过信息交换传递）

#### 2.3.6 缓存策略 (Cacheability)

控制Segment的内存缓存行为：

| 策略 | 值 | 说明 |
|------|-----|------|
| `URMA_NON_CACHEABLE` | 0 | **不可缓存（免缓存）**：直接访问物理内存，不经过CPU缓存（推荐用于高性能场景） |
| `URMA_CACHEABLE` | 1 | **可缓存**：允许CPU缓存（可能影响一致性） |

**NON_CACHEABLE的作用和意义：**

1. **直接访问物理内存**：`NON_CACHEABLE`表示内存访问**不经过CPU缓存层**，CPU和硬件（如网卡）直接访问物理内存

2. **避免缓存一致性问题**：
   - 在远程内存访问场景中，多个节点可能同时访问同一块内存
   - 如果使用CPU缓存，可能出现缓存一致性问题（Cache Coherency）
   - 使用`NON_CACHEABLE`可以避免缓存一致性问题，确保数据的一致性和实时性

3. **适用于DMA场景**：
   - 网卡等硬件设备通过DMA（Direct Memory Access）直接访问内存
   - 如果内存被CPU缓存，硬件和CPU可能看到不同的数据
   - `NON_CACHEABLE`确保硬件和CPU访问的是同一份物理内存数据

4. **性能考虑**：
   - `NON_CACHEABLE`通常用于对延迟敏感、需要数据一致性的高性能场景
   - 虽然失去了CPU缓存的加速效果，但避免了缓存同步的开销，在远程内存访问场景中通常性能更好

**使用建议**：对于URMA的远程内存访问，推荐使用`URMA_NON_CACHEABLE`，以确保数据一致性和最佳性能。

#### 2.3.7 Segment的完整生命周期

**流程图：**

```
┌─────────────────────────────────────────────────────────────────┐
│                      节点A（Home节点）                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 分配内存（页对齐）                                           │
│     void *buffer = memalign(4096, size);                        │
│                                                                  │
│  2. 注册Segment                                                  │
│     urma_register_seg(ctx, &seg_cfg)                            │
│     ┌────────────────────────────────────────┐                 │
│     │ • 锁定内存页（pin memory）              │                 │
│     │ • 分配Token ID                          │                 │
│     │ • 生成UBVA                              │                 │
│     │ • 注册到内核                            │                 │
│     └────────────────────────────────────────┘                 │
│     ↓ 返回 urma_target_seg_t *local_seg                        │
│                                                                  │
│  3. 信息交换（通过Socket等带外方式）                              │
│     发送：{UBVA, len, token, flags}                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      节点B（访问节点）                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  4. 接收信息                                                     │
│     收到：{UBVA, len, token, flags}                            │
│                                                                  │
│  5. 导入Segment                                                  │
│     urma_import_seg(ctx, &remote_seg, &token, ...)             │
│     ┌────────────────────────────────────────┐                 │
│     │ • 验证Token                             │                 │
│     │ • 创建本地映射                          │                 │
│     │ • 返回target_seg                        │                 │
│     └────────────────────────────────────────┘                 │
│     ↓ 返回 urma_target_seg_t *import_seg                       │
│                                                                  │
│  6. 使用Segment进行远程访问                                      │
│     urma_read(jfs, target_jetty,                               │
│               local_seg, import_seg, ...)                      │
│                                                                  │
│  7. 取消导入                                                     │
│     urma_unimport_seg(import_seg)                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      节点A（Home节点）                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  8. 注销Segment                                                  │
│     urma_unregister_seg(local_seg)                             │
│     ┌────────────────────────────────────────┐                 │
│     │ • 释放Token ID                          │                 │
│     │ • 解锁内存页                            │                 │
│     │ • 从内核注销                            │                 │
│     └────────────────────────────────────────┘                 │
│                                                                  │
│  9. 释放内存                                                     │
│     free(buffer)                                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### 2.3.8 注册Segment示例

```c
// 1. 分配内存（必须页对齐，通常是4KB对齐）
#define PAGE_SIZE 4096
#define MEM_SIZE (1024 * 1024)  // 1MB
void *buffer = memalign(PAGE_SIZE, MEM_SIZE);
if (buffer == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
}
memset(buffer, 0, MEM_SIZE);

// 2. 设置访问权限标志
urma_reg_seg_flag_t flag = {
    .bs.token_policy = URMA_TOKEN_NONE,           // Token策略
    .bs.cacheable = URMA_NON_CACHEABLE,           // 不可缓存
    .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
    .bs.token_id_valid = URMA_TOKEN_ID_INVALID,   // 由系统分配Token ID
    .bs.reserved = 0
};

// 3. 设置Token值（用于安全验证）
urma_token_t token = { .token = 0xACFE };

// 4. 配置Segment
urma_seg_cfg_t seg_cfg = {
    .va = (uint64_t)buffer,        // 内存地址
    .len = MEM_SIZE,               // 内存长度
    .token_id = NULL,              // 由系统分配
    .token_value = token,          // Token值
    .flag = flag,                  // 标志位
    .user_ctx = 0,                 // 用户上下文
    .iova = 0                      // 使用系统分配的IOVA
};

// 5. 注册Segment
urma_target_seg_t *local_seg = urma_register_seg(ctx, &seg_cfg);
if (local_seg == NULL) {
    fprintf(stderr, "Failed to register segment\n");
    free(buffer);
    return -1;
}

// 6. 获取UBVA信息（用于信息交换）
urma_ubva_t ubva = local_seg->seg.ubva;
printf("Registered segment UBVA: EID=%x, UASID=%u, VA=%lx\n",
       /* 打印EID */, ubva.uasid, ubva.va);
```

#### 2.3.9 导入Segment示例

```c
// 1. 通过信息交换获得远程Segment信息
// （实际应用中通过Socket等带外方式交换）
urma_seg_t remote_seg_info = {
    .ubva = {
        .eid = remote_eid,         // 远程节点EID
        .uasid = remote_uasid,     // 远程进程UASID
        .va = remote_va            // 远程虚拟地址
    },
    .len = MEM_SIZE,
    .attr = {
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE,
        .bs.token_policy = URMA_TOKEN_NONE,
        .bs.cacheable = URMA_NON_CACHEABLE
    },
    .token_id = 0  // 内部使用
};

// 2. Token值（必须与注册时一致）
urma_token_t token = { .token = 0xACFE };

// 3. 导入标志
urma_import_seg_flag_t import_flag = {
    .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE,
    .bs.cacheable = URMA_NON_CACHEABLE,
    .bs.mapping = URMA_SEG_NOMAP  // 不映射到本地地址空间
};

// 4. 导入Segment
urma_target_seg_t *import_seg = urma_import_seg(ctx, &remote_seg_info,
                                                  &token, 0, import_flag);
if (import_seg == NULL) {
    fprintf(stderr, "Failed to import segment\n");
    return -1;
}

// 5. 使用导入的Segment进行远程访问
urma_read(jfs, target_jetty,
          local_seg,      // 本地目标Segment
          import_seg,     // 远程源Segment
          local_va,       // 本地目标地址
          remote_va,      // 远程源地址（从import_seg->seg.ubva.va获取）
          len, flag, user_ctx);

// 6. 使用完毕后取消导入
urma_unimport_seg(import_seg);
```

#### 2.3.10 关键注意事项

1. **内存对齐要求**：
   - 内存地址（VA）必须是页对齐（通常是4KB）
   - 内存长度必须是页大小的倍数
   - 使用`memalign(4096, size)`分配对齐内存

2. **权限设置规则**：
   - 如果允许远程写，必须同时允许远程读
   - 如果允许远程原子操作，必须同时允许远程读写
   - （详细说明见Q6.1）

3. **Token安全**：
   - 生产环境应使用Token验证（不使用`URMA_TOKEN_NONE`）
   - Token值应通过安全通道交换
   - Token值必须匹配才能成功导入

4. **生命周期管理**：
   - 注册的Segment在使用完毕后必须注销
   - 导入的Segment在使用完毕后必须取消导入
   - 先取消导入，再注销，最后释放内存

5. **性能考虑**：
   - 通常使用`URMA_NON_CACHEABLE`以获得最佳性能
   - 大块内存注册为单个Segment更高效
   - 避免频繁注册/注销Segment

### 2.4 Jetty - 队列管理 (最核心概念)

Jetty是URMA命令执行的"端口"，由以下组件构成：

```
┌─────────────────────────────────────────────────────────────────────┐
│                              JFCE                                   │
│                    (Jetty For Completion Event)                     │
│                         完成事件通知                                 │
│                    用于中断模式等待完成事件                           │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                              JFC                                    │
│                     (Jetty For Completion)                          │
│                          完成队列                                    │
│              存储 JFS/JFR 操作的完成记录 (Completion Record)          │
└─────────────────────────────────────────────────────────────────────┘
           ▲                                           ▲
           │ 绑定                                      │ 绑定
           │                                           │
┌───────────────────────────┐           ┌───────────────────────────┐
│          JFS              │           │           JFR             │
│   (Jetty For Send)        │           │    (Jetty For Receive)    │
│       发送队列             │           │         接收队列          │
│                           │           │                           │
│  - 提交 Write/Read 请求    │           │  - 准备接收缓冲区          │
│  - 发送消息                │           │  - 接收消息               │
│  - 原子操作                │           │                           │
└───────────────────────────┘           └───────────────────────────┘
           │                                           ▲
           │ 发送数据                                   │ 接收数据
           └───────────────────────────────────────────┘
                                网络

┌─────────────────────────────────────────────────────────────────────┐
│                             Jetty                                   │
│                       (JFS + JFR 的组合)                             │
│                    封装了发送和接收能力的完整队列对                     │
└─────────────────────────────────────────────────────────────────────┘
```

**组件说明：**

| 组件 | 全称 | 功能 |
|------|------|------|
| **JFS** | Jetty For Send | 发送队列，用于提交DMA任务或发送消息 |
| **JFR** | Jetty For Receive | 接收队列，用于准备接收消息的资源 |
| **JFC** | Jetty For Completion | 完成队列，存储JFS/JFR的完成记录 |
| **JFCE** | Jetty For Completion Event | 完成事件，用于中断模式感知完成 |
| **Jetty** | - | JFS+JFR的组合，是一个完整的通信端点 |

### 2.5 传输模式 (Transport Mode)

| 传输模式 | 缩写 | 特点 | 应用场景 |
|----------|------|------|----------|
| **Reliable Message** | RM | 可靠消息，一对多通信 | 广播、多播场景 |
| **Reliable Connection** | RC | 可靠连接，一对一通信 | 点对点可靠传输 |
| **Unreliable Message** | UM | 不可靠消息，无确认 | 对延迟敏感但可丢失的场景 |

```c
typedef enum urma_transport_mode {
    URMA_TM_RM = 0x1,      // Reliable message
    URMA_TM_RC = 0x1 << 1, // Reliable connection
    URMA_TM_UM = 0x1 << 2, // Unreliable message
} urma_transport_mode_t;
```

---

## 三、数据结构详解

### 3.1 设备和上下文

#### 3.1.1 urma_device_t - 设备结构

**urma_device是抽象概念吗？是什么硬件的抽象？**

是的，`urma_device_t` 是一个**抽象的设备表示**。它不代表物理硬件，而是URMA库对底层硬件设备的抽象封装。

**具体是什么硬件？**

`urma_device` 是对**UDMA（UnifiedBus Direct Memory Access）硬件设备**的抽象。UDMA不是传统意义上的网卡，而是一种提供直接内存访问（DMA）能力的硬件I/O设备控制器。

**UDMA硬件的特点：**
- **类型**：硬件I/O设备控制器，提供DMA能力
- **功能**：支持UnifiedBus协议，提供远程内存访问能力
- **物理形态**：通过PCIe等接口连接到系统，在系统中显示为"UB network controller"（虽然名字包含network，但实际上是DMA控制器）
- **支持的操作**：Read/Write（远程内存读写）、Send/Recv（消息传递）、原子操作等

**类比说明：**
- **传统网卡**：主要用于网络数据包的发送和接收
- **UDMA设备**：更像是RDMA网卡，但专门用于UnifiedBus协议，提供硬件加速的远程内存访问能力

**支持的硬件型号：**
UDMA驱动支持多个硬件型号（通过Vendor ID和Device ID识别），例如：
- Vendor ID: 0xCC08 (Huawei Technologies)
- Device ID: 0xA001, 0xA002, 0xD802, 0xD803, 0xD80B, 0xD80C 等

可以通过 `lsub` 命令查看系统中的UDMA设备。

**设备发现和创建流程：**

```
内核驱动注册设备到sysfs
        │
        ▼
URMA库扫描sysfs (/sys/class/ubcore)
        │
        ▼
创建 urma_sysfs_dev (从sysfs读取设备信息)
        │
        ▼
匹配Provider (根据vendor_id/device_id或driver_name)
        │
        ▼
创建 urma_device (封装sysfs_dev和provider_ops)
        │
        ▼
应用程序使用 urma_device 访问设备
```

**结构定义：**

```c
typedef struct urma_device {
    char name[URMA_MAX_NAME];         // [公开] 设备名称
    char path[URMA_MAX_PATH];         // [公开] 字符设备路径
    urma_transport_type_t type;       // [公开] 传输类型
    struct urma_provider_ops *ops;    // [私有] Provider操作接口
    struct urma_sysfs_dev *sysfs_dev; // [私有] 内部设备信息
} urma_device_t;
```

**字段详解：**

| 字段 | 类型 | 可见性 | 说明 |
|------|------|--------|------|
| `name` | `char[64]` | [公开] | **设备名称**：URMA设备的名称标识符，例如 `"udma0"`。不同传输模式下的设备名称格式不同。<br><br>**主要用途**：<br>- 通过 `urma_get_device_by_name(name)` 查找设备<br>- 标识和区分不同的URMA设备<br>- 主要用于设备查找和标识，应用程序一般通过名称获取设备后使用设备指针 |
| `path` | `char[4096]` | [公开] | **字符设备路径**：设备字符设备文件的路径，例如 `"/dev/uburma/udma0"`（注意：不是sysfs路径，而是/dev下的字符设备路径）。<br><br>**主要用途**：<br>- 用于打开设备文件（`open(path, O_RDWR)`），获取 `dev_fd`<br>- 在创建上下文时，通过 `dev_fd` 与内核驱动通信（ioctl）<br>- 用于设备属性查询、EID查询等需要内核交互的操作<br><br>**注意**：虽然字段名为"path"且注释提到sysfs，但实际存储的是 `/dev/uburma/设备名` 这样的字符设备路径 |
| `type` | `urma_transport_type_t` | [公开] | **传输类型**：设备的传输类型，目前支持 `URMA_TRANSPORT_UB`（灵衢总线）。用于标识设备所属的传输协议栈。 |
| `ops` | `struct urma_provider_ops *` | [私有] | **Provider操作接口**：指向Provider的操作函数表（`urma_provider_ops_t`），包含设备的初始化、查询设备属性、创建上下文等接口。<br><br>**什么是Provider？**<br>- Provider是URMA的**插件机制**，用于支持不同的硬件后端<br>- 不同的硬件（如UDMA）实现不同的Provider（`liburma-udma.so`）<br>- Provider通过 `urma_register_provider_ops()` 注册到URMA库<br>- 每个设备关联一个Provider，通过Provider的操作接口与硬件交互<br><br>**Provider接口包括**：<br>- `init()` / `uninit()`：初始化/反初始化<br>- `query_device()`：查询设备属性<br>- `create_context()` / `delete_context()`：创建/删除上下文<br><br>由URMA内部使用，应用程序不应直接访问。 |
| `sysfs_dev` | `struct urma_sysfs_dev *` | [私有] | **内部设备信息**：指向 `urma_sysfs_dev_t` 结构，这是从sysfs文件系统读取的设备信息。<br><br>**什么是sysfs_dev？**<br>- `urma_sysfs_dev` 是URMA库从 `/sys/class/ubcore/设备名/` 读取的设备信息<br>- 包含设备的底层信息：设备名称、驱动名称、vendor_id、device_id、设备属性等<br>- `urma_device` 从 `urma_sysfs_dev` 创建，两者互相引用<br>- `sysfs_dev` 用于设备发现、匹配Provider、读取设备属性等内部操作<br><br>**sysfs_dev包含的信息**：<br>- `dev_name`：设备名称（从sysfs读取）<br>- `sysfs_path`：sysfs路径（如 `/sys/class/ubcore/udma0`）<br>- `driver_name`：驱动名称<br>- `vendor_id` / `device_id`：硬件厂商ID和设备ID（用于匹配Provider）<br>- `dev_attr`：设备属性（能力、限制等）<br><br>由URMA内部使用，应用程序不应直接访问。 |

**使用示例：**

```c
// 1. 通过名称获取设备
urma_device_t *dev = urma_get_device_by_name("udma0");

// 2. 查询设备属性
urma_device_attr_t dev_attr;
urma_query_device(dev, &dev_attr);

// 3. 访问设备信息（公开字段）
printf("Device name: %s\n", dev->name);
printf("Device path: %s\n", dev->path);
printf("Transport type: %d\n", dev->type);
```

#### 3.1.2 urma_context_t - 上下文结构

**urma_context和应用程序的关系：**

`urma_context_t` 代表一个URMA上下文，是应用程序与URMA设备交互的核心对象。所有资源（Jetty、Segment等）都关联到某个上下文。

**为什么需要context？context不存在不行吗？**

**答案：必须要有context，没有context应用程序无法使用URMA功能。**

**原因：**

1. **所有资源创建都需要context**：应用程序要使用URMA功能，必须创建资源（Segment、Jetty等），而所有资源创建函数都要求传入context参数。没有context，无法创建任何资源。

2. **所有数据操作都需要context**：进行远程内存读写、消息传递等操作时，需要访问context中的信息（如EID、设备操作函数等）。

3. **context提供了应用程序工作所需的所有上下文信息**：
   - 设备信息（通过 `ctx->dev`）
   - 操作函数（通过 `ctx->ops`）
   - 网络身份标识（通过 `ctx->eid`、`ctx->uasid`）
   - 与内核通信的通道（通过 `ctx->dev_fd`）

4. **资源生命周期管理**：context通过引用计数管理资源生命周期，确保资源在使用期间不会被错误释放。

**类比说明：**
- **设备（device）**：像是"硬件设备"
- **上下文（context）**：像是"打开设备后获得的句柄/会话"，应用程序通过这个"会话"来使用设备的所有功能
- 没有context，就像有设备但没有打开，无法使用

**urma_device和urma_context的关系：**

`urma_context_t` 代表一个URMA上下文，是应用程序与URMA设备交互的核心对象。所有资源（Jetty、Segment等）都关联到某个上下文。

**关系图：**

```
urma_device (设备抽象)
    │
    │ 通过 urma_create_context(dev, eid_index) 创建
    │
    ▼
urma_context (上下文，应用程序的主要工作对象)
    │
    │ 包含指向 dev 的指针 (ctx->dev)
    │ 包含运行时操作函数表 (ctx->ops)
    │ 包含 EID 信息 (ctx->eid, ctx->eid_index)
    │ 包含设备文件描述符 (ctx->dev_fd)
    │
    │ 所有资源创建都使用 context
    │
    ▼
资源 (Jetty, Segment, JFC, JFS, JFR等)
    │ 每个资源都包含 urma_ctx 指针
    │ 创建资源时增加 ctx->ref 引用计数
```

**关键区别：**

| 特性 | urma_device | urma_context |
|------|-------------|--------------|
| **作用** | 设备抽象，代表硬件设备 | 工作上下文，应用程序的主要操作对象 |
| **创建时机** | 设备发现时自动创建 | 应用程序主动调用 `urma_create_context()` 创建 |
| **数量关系** | 一个设备可以创建多个上下文 | 每个上下文关联一个设备 |
| **ops类型** | `urma_provider_ops_t`（设备级操作） | `urma_ops_t`（运行时操作） |
| **使用场景** | 设备查询、上下文创建 | 所有资源创建、数据操作 |

**结构定义：**

```c
typedef struct urma_context {
    struct urma_device *dev;          // [私有] 指向关联的设备
    struct urma_ops *ops;             // [私有] 设备操作函数表
    int dev_fd;                       // [私有] 设备文件描述符
    int async_fd;                     // [私有] 异步事件文件描述符
    pthread_mutex_t mutex;            // [私有] 互斥锁
    urma_eid_t eid;                   // [公开] 端点标识
    uint32_t eid_index;               // [私有] EID索引
    uint32_t uasid;                   // [公开] 用户地址空间ID
    struct urma_ref ref;              // [私有] 引用计数
    urma_context_aggr_mode_t aggr_mode; // [公开] 聚合模式
} urma_context_t;
```

**字段详解：**

| 字段 | 类型 | 可见性 | 说明 |
|------|------|--------|------|
| `dev` | `struct urma_device *` | [私有] | **关联设备**：指向创建此上下文时使用的URMA设备。一个设备可以创建多个上下文，但每个上下文只关联一个设备。 |
| `ops` | `struct urma_ops *` | [私有] | **操作函数表**：指向设备的运行时操作函数表（`urma_ops_t`），包含创建Jetty、提交WR、轮询完成等接口。由URMA内部使用。 |
| `dev_fd` | `int` | [私有] | **设备文件描述符**：打开设备控制文件（字符设备）的文件描述符，用于与内核驱动通信（ioctl）。 |
| `async_fd` | `int` | [私有] | **异步事件文件描述符**：用于接收异步事件的文件描述符，用于处理设备错误、端口状态变化等异步事件。 |
| `mutex` | `pthread_mutex_t` | [私有] | **互斥锁**：保护上下文内部状态的互斥锁，确保多线程访问的安全性。 |
| `eid` | `urma_eid_t` | [公开] | **端点标识**：此上下文使用的EID（Endpoint ID），用于标识上下文所属的端点。16字节的EID，可以通过 `ctx->eid` 访问。 |
| `eid_index` | `uint32_t` | [私有] | **EID索引**：创建上下文时指定的EID索引，用于从设备中选择特定的EID。<br><br>**EID索引的作用**：<br>- 一个设备可能有多个EID（端点标识），通过EID索引（0, 1, 2...）来区分<br>- 创建上下文时，通过 `urma_create_context(dev, eid_index)` 指定要使用的EID索引<br>- 系统根据eid_index从设备的EID列表中选择对应的EID，并存储在 `ctx->eid` 中<br>- EID索引范围通常是 0 到 `max_eid_cnt - 1`（最多1024个）<br><br>**EID和上下文的关系**：<br>- 上下文创建时绑定一个EID（通过eid_index选择）<br>- 上下文的 `ctx->eid` 字段存储了完整的16字节EID值<br>- 上下文的 `ctx->eid_index` 字段存储了EID的索引<br>- 这个EID用于标识此上下文在网络中的身份，所有通过此上下文创建的资源都使用这个EID<br><br>**每个context都有全局唯一的EID吗？**<br>- **EID在UBUS网络中是全局唯一的**：每个EID在网络中唯一标识一个端点<br>- **多个context可以共享同一个EID**：同一个设备可以使用相同的eid_index创建多个context，这些context使用相同的EID<br>- **典型场景**：一个进程可能创建多个context用于不同的用途（如不同的线程），它们可能使用相同的EID<br>- **唯一性保证**：EID本身是全局唯一的（在网络范围内），但多个context可以绑定到同一个EID |
| `uasid` | `uint32_t` | [公开] | **用户地址空间ID**：当前进程的用户地址空间标识符，用于区分不同进程的地址空间。4字节标识符，可以通过 `ctx->uasid` 访问。 |
| `ref` | `struct urma_ref` | [私有] | **引用计数**：上下文的引用计数，用于管理上下文生命周期。当创建资源（Jetty、Segment等）时增加计数，删除资源时减少计数。只有当引用计数为1时才能删除上下文。 |
| `aggr_mode` | `urma_context_aggr_mode_t` | [公开] | **聚合模式**：上下文的聚合模式，用于多路径聚合场景。可选值：<br>- `URMA_AGGR_MODE_STANDALONE`：独立模式（默认）<br>- `URMA_AGGR_MODE_ACTIVE_BACKUP`：主备模式<br>- `URMA_AGGR_MODE_BALANCE`：负载均衡模式 |

**聚合模式说明：**

- **STANDALONE（独立模式）**：默认模式，上下文独立工作，不进行多路径聚合。适用于单设备单路径场景。

- **ACTIVE_BACKUP（主备模式）**：使用主路径传输，主路径故障时自动切换到备份路径。提供高可用性，但只使用一条路径的带宽。适用于对可靠性要求高的场景。

- **BALANCE（负载均衡模式）**：在多个路径间进行负载均衡，充分利用所有路径的带宽。适用于需要高带宽的场景。需要硬件支持多路径聚合。

**使用示例：**

```c
// 1. 创建上下文
urma_device_t *dev = urma_get_device_by_name("udma0");
urma_context_t *ctx = urma_create_context(dev, eid_index);

// 2. 访问公开字段
printf("EID: ...\n");  // 可以通过ctx->eid访问
printf("UASID: %u\n", ctx->uasid);
printf("Aggregation mode: %d\n", ctx->aggr_mode);

// 3. 设置聚合模式（仅对聚合设备有效）
urma_context_aggr_mode_t mode = URMA_AGGR_MODE_BALANCE;
urma_set_context_opt(ctx, URMA_OPT_AGGR_MODE, &mode, sizeof(mode));

// 4. 使用上下文创建资源
urma_jfc_t *jfc = urma_create_jfc(ctx, &jfc_cfg);
urma_target_seg_t *seg = urma_register_seg(ctx, &seg_cfg);

// 5. 删除上下文（必须先删除所有关联的资源）
urma_delete_context(ctx);
```

**生命周期管理：**

1. **创建**：通过 `urma_create_context(dev, eid_index)` 创建，关联到指定的设备和EID索引。
2. **使用**：所有资源创建、数据操作都需要使用上下文。
3. **引用计数**：创建资源时自动增加引用计数，删除资源时自动减少。
4. **删除**：必须确保所有关联的资源都已删除（引用计数为1），才能调用 `urma_delete_context()`。

**为什么所有资源创建都需要上下文？**

所有资源创建函数（如 `urma_create_jfc()`、`urma_register_seg()` 等）都需要上下文参数，原因包括：

1. **操作函数表（ops）**：资源创建需要调用具体的操作函数，这些函数存储在 `ctx->ops` 中。不同的硬件Provider有不同的实现，通过上下文可以访问到正确的操作函数。

2. **设备信息（dev）**：资源创建时需要访问设备信息（如设备能力、限制等），通过 `ctx->dev` 可以访问到设备结构。

3. **设备文件描述符（dev_fd）**：资源创建需要与内核驱动通信（通过ioctl），`ctx->dev_fd` 提供了与内核通信的通道。

4. **EID和UASID**：资源需要关联到特定的EID和UASID，这些信息存储在上下文中（`ctx->eid`、`ctx->uasid`）。

5. **引用计数管理（ref）**：资源创建时会增加上下文的引用计数（`atomic_fetch_add(&ctx->ref.atomic_cnt, 1)`），确保上下文在使用期间不会被删除。

6. **资源关联**：每个资源结构都包含 `urma_ctx` 指针，指向创建它的上下文，用于后续的资源操作和清理。

**总结**：上下文是应用程序与URMA设备交互的核心对象，所有资源都必须在某个上下文的"作用域"内创建和使用。

### 3.2 Work Request (WR) - 工作请求

```c
// SGE - Scatter/Gather Element
typedef struct urma_sge {
    uint64_t addr;            // 数据地址
    uint32_t len;             // 数据长度
    urma_target_seg_t *tseg;  // 目标段指针
    urma_user_tseg_t *user_tseg; // 用户目标段 (免导入)
} urma_sge_t;

// SG - Scatter/Gather 列表
typedef struct urma_sg {
    urma_sge_t *sge;
    uint32_t num_sge;
} urma_sg_t;

// 发送WR的标志位
typedef union urma_jfs_wr_flag {
    struct {
        uint32_t place_order : 2;      // 顺序控制
        uint32_t comp_order       : 1; // 完成顺序
        uint32_t fence            : 1; // 栅栏
        uint32_t solicited_enable : 1; // 触发远程事件
        uint32_t complete_enable  : 1; // 生成完成记录
        uint32_t inline_flag      : 1; // 内联数据
        uint32_t reserved         : 25;
    } bs;
    uint32_t value;
} urma_jfs_wr_flag_t;

// 发送工作请求
typedef struct urma_jfs_wr {
    urma_opcode_t opcode;        // 操作码
    urma_jfs_wr_flag_t flag;     // 标志
    urma_target_jetty_t *tjetty; // 目标Jetty
    uint64_t user_ctx;           // 用户上下文 (CR中返回)
    union {
        urma_rw_wr_t rw;         // 读写操作
        urma_send_wr_t send;     // 发送操作
        urma_cas_wr_t cas;       // CAS原子操作
        urma_faa_wr_t faa;       // FAA原子操作
    };
    struct urma_jfs_wr *next;    // 链表 (批量提交)
} urma_jfs_wr_t;

// 接收工作请求
typedef struct urma_jfr_wr {
    urma_sg_t src;               // 接收缓冲区
    uint64_t user_ctx;           // 用户上下文
    struct urma_jfr_wr *next;
} urma_jfr_wr_t;
```

### 3.3 Completion Record (CR) - 完成记录

```c
typedef struct urma_cr {
    urma_cr_status_t status;     // 完成状态
    uint64_t user_ctx;           // 用户上下文 (从WR传递)
    urma_cr_opcode_t opcode;     // 操作码 (仅接收时有效)
    urma_cr_flag_t flag;         // 标志 (s_r区分发送/接收)
    uint32_t completion_len;     // 实际传输字节数

    uint32_t local_id;           // 本地Jetty/JFS/JFR ID
    urma_jetty_id_t remote_id;   // 远程Jetty ID (仅接收)
    union {
        uint64_t imm_data;       // 立即数
        urma_cr_token_t invalid_token;
    };
    uint32_t tpn;                // 传输路径号
    uintptr_t user_data;         // 用户数据指针
} urma_cr_t;

// 完成状态枚举
typedef enum urma_cr_status {
    URMA_CR_SUCCESS = 0,                // 成功
    URMA_CR_UNSUPPORTED_OPCODE_ERR,     // 不支持的操作码
    URMA_CR_LOC_LEN_ERR,                // 本地长度错误
    URMA_CR_LOC_OPERATION_ERR,          // 本地操作错误
    URMA_CR_LOC_ACCESS_ERR,             // 本地访问错误
    URMA_CR_REM_RESP_LEN_ERR,           // 远程响应长度错误
    URMA_CR_REM_OPERATION_ERR,          // 远程操作错误
    URMA_CR_REM_ACCESS_ABORT_ERR,       // 远程访问错误
    URMA_CR_ACK_TIMEOUT_ERR,            // ACK超时
    URMA_CR_RNR_RETRY_CNT_EXC_ERR,      // RNR重试超限
    URMA_CR_WR_FLUSH_ERR,               // 刷新错误
    // ...
} urma_cr_status_t;
```

### 3.4 操作码

```c
typedef enum urma_opcode {
    // 写操作
    URMA_OPC_WRITE = 0x00,
    URMA_OPC_WRITE_IMM = 0x01,      // 带立即数的写
    URMA_OPC_WRITE_NOTIFY = 0x02,
    
    // 读操作
    URMA_OPC_READ = 0x10,
    
    // 原子操作
    URMA_OPC_CAS = 0x20,            // Compare-And-Swap
    URMA_OPC_SWAP = 0x21,           // Swap
    URMA_OPC_FADD = 0x22,           // Fetch-And-Add
    URMA_OPC_FSUB = 0x23,           // Fetch-And-Sub
    URMA_OPC_FAND = 0x24,           // Fetch-And-And
    URMA_OPC_FOR = 0x25,            // Fetch-And-Or
    URMA_OPC_FXOR = 0x26,           // Fetch-And-Xor
    
    // 发送操作
    URMA_OPC_SEND = 0x40,
    URMA_OPC_SEND_IMM = 0x41,       // 带立即数的发送
    URMA_OPC_SEND_INVALIDATE = 0x42,
    
    URMA_OPC_NOP = 0x51,
} urma_opcode_t;
```

---

## 四、API接口参考

### 4.1 初始化和设备管理

```c
// 初始化URMA环境
urma_status_t urma_init(urma_init_attr_t *conf);
urma_status_t urma_uninit(void);

// 设备发现
urma_device_t **urma_get_device_list(int *num_devices);
void urma_free_device_list(urma_device_t **device_list);
urma_device_t *urma_get_device_by_name(char *dev_name);
urma_device_t *urma_get_device_by_eid(urma_eid_t eid, urma_transport_type_t type);
urma_status_t urma_query_device(urma_device_t *dev, urma_device_attr_t *dev_attr);

// EID管理
urma_eid_info_t *urma_get_eid_list(urma_device_t *dev, uint32_t *cnt);
void urma_free_eid_list(urma_eid_info_t *eid_list);

// 上下文管理
urma_context_t *urma_create_context(urma_device_t *dev, uint32_t eid_index);
urma_status_t urma_delete_context(urma_context_t *ctx);
```

### 4.2 Jetty管理

```c
// JFCE - 完成事件通道
urma_jfce_t *urma_create_jfce(urma_context_t *ctx);
urma_status_t urma_delete_jfce(urma_jfce_t *jfce);

// JFC - 完成队列
urma_jfc_t *urma_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *jfc_cfg);
urma_status_t urma_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr);
urma_status_t urma_delete_jfc(urma_jfc_t *jfc);

// JFS - 发送队列
urma_jfs_t *urma_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *jfs_cfg);
urma_status_t urma_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr);
urma_status_t urma_query_jfs(urma_jfs_t *jfs, urma_jfs_cfg_t *cfg, urma_jfs_attr_t *attr);
urma_status_t urma_delete_jfs(urma_jfs_t *jfs);

// JFR - 接收队列
urma_jfr_t *urma_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *jfr_cfg);
urma_status_t urma_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr);
urma_status_t urma_delete_jfr(urma_jfr_t *jfr);
urma_target_jetty_t *urma_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token);
urma_status_t urma_unimport_jfr(urma_target_jetty_t *target_jfr);
urma_status_t urma_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr); // RM模式

// Jetty - 完整队列对
urma_jetty_t *urma_create_jetty(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg);
urma_status_t urma_modify_jetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr);
urma_status_t urma_query_jetty(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_jetty_attr_t *attr);
urma_status_t urma_delete_jetty(urma_jetty_t *jetty);
urma_target_jetty_t *urma_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token);
urma_status_t urma_unimport_jetty(urma_target_jetty_t *tjetty);
urma_status_t urma_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);   // RC模式
urma_status_t urma_unbind_jetty(urma_jetty_t *jetty);
```

### 4.3 内存段管理

```c
// Token管理
urma_token_id_t *urma_alloc_token_id(urma_context_t *ctx);
urma_status_t urma_free_token_id(urma_token_id_t *token_id);

// 内存段注册/导入
urma_target_seg_t *urma_register_seg(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg);
urma_status_t urma_unregister_seg(urma_target_seg_t *target_seg);
urma_target_seg_t *urma_import_seg(urma_context_t *ctx, urma_seg_t *seg, 
                                   urma_token_t *token, uint64_t addr, 
                                   urma_import_seg_flag_t flag);
urma_status_t urma_unimport_seg(urma_target_seg_t *tseg);
```

### 4.4 数据面操作

```c
// 简化API
urma_status_t urma_write(urma_jfs_t *jfs, urma_target_jetty_t *tjfr,
                         urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg,
                         uint64_t dst, uint64_t src, uint32_t len,
                         urma_jfs_wr_flag_t flag, uint64_t user_ctx);

urma_status_t urma_read(urma_jfs_t *jfs, urma_target_jetty_t *tjfr,
                        urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg,
                        uint64_t dst, uint64_t src, uint32_t len,
                        urma_jfs_wr_flag_t flag, uint64_t user_ctx);

urma_status_t urma_send(urma_jfs_t *jfs, urma_target_jetty_t *tjfr,
                        urma_target_seg_t *src_tseg, uint64_t src, uint32_t len,
                        urma_jfs_wr_flag_t flag, uint64_t user_ctx);

urma_status_t urma_recv(urma_jfr_t *jfr, urma_target_seg_t *recv_tseg,
                        uint64_t buf, uint32_t len, uint64_t user_ctx);

// 批量操作API
urma_status_t urma_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
urma_status_t urma_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
urma_status_t urma_post_jetty_send_wr(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
urma_status_t urma_post_jetty_recv_wr(urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
```

### 4.5 完成处理

```c
// 轮询模式
int urma_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);

// 中断模式
urma_status_t urma_rearm_jfc(urma_jfc_t *jfc, bool solicited_only);
int urma_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int timeout, urma_jfc_t *jfc[]);
void urma_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);
```

---

## 五、编程流程

### 5.1 标准编程流程图

```
【初始化阶段】
     │
     ▼
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ urma_init() │ ──► │ urma_get_device │ ──► │ urma_query_device│
│ 初始化环境   │     │ 获取设备        │     │ 查询设备能力      │
└─────────────┘     └─────────────────┘     └──────────────────┘
                                                     │
                                                     ▼
                                            ┌──────────────────┐
                                            │urma_create_context│
                                            │   创建上下文      │
                                            └──────────────────┘
                                                     │
【资源创建阶段】                                       ▼
┌────────────────────────────────────────────────────────────────────┐
│  create_jfce() ──► create_jfc() ──► create_jetty()                │
│  分配内存 ──► urma_register_seg()                                  │
└────────────────────────────────────────────────────────────────────┘
                                                     │
【连接建立阶段】                                       ▼
┌────────────────────────────────────────────────────────────────────┐
│  1. 交换信息 (通过Socket等带外方式)                                  │
│  2. urma_import_jetty() / urma_import_seg()                        │
│  3. urma_bind_jetty() (RC模式)                                     │
└────────────────────────────────────────────────────────────────────┘
                                                     │
【数据传输阶段】                                       ▼
┌────────────────────────────────────────────────────────────────────┐
│  urma_write() / urma_read() / urma_send() / urma_recv()            │
│  urma_poll_jfc() 或 urma_wait_jfc() 等待完成                       │
└────────────────────────────────────────────────────────────────────┘
                                                     │
【清理阶段】                                           ▼
┌────────────────────────────────────────────────────────────────────┐
│  urma_unimport_* ──► urma_unregister_seg() ──► urma_delete_*      │
│  urma_delete_context() ──► urma_uninit()                          │
└────────────────────────────────────────────────────────────────────┘
```

### 5.2 完成处理 - 两种模式对比

**轮询模式 (Polling)：**
- 特点：CPU忙等待，低延迟，高CPU占用
- 适用：对延迟敏感的场景

```c
for (int i = 0; i < MAX_POLL_CNT; i++) {
    int cnt = urma_poll_jfc(jfc, 1, &cr);
    if (cnt > 0 && cr.status == URMA_CR_SUCCESS) {
        return 0;  // 成功
    }
    usleep(100);  // 可选：减少CPU占用
}
```

**中断模式 (Event)：**
- 特点：线程休眠等待，低CPU占用，稍高延迟
- 适用：通信不频繁的场景

```c
// 1. 等待完成事件
urma_wait_jfc(jfce, 1, TIMEOUT, &ev_jfc);

// 2. 读取完成记录
urma_poll_jfc(jfc, 1, &cr);

// 3. 确认事件已处理
urma_ack_jfc(&ev_jfc, &ack_cnt, 1);

// 4. 重新启用事件
urma_rearm_jfc(jfc, false);
```

---

## 六、示例代码解析

### 6.1 初始化示例

```c
// 1. 初始化URMA
urma_init_attr_t init_attr = { .uasid = 0 };
urma_init(&init_attr);

// 2. 获取设备
urma_device_t *dev = urma_get_device_by_name("udma0");
urma_device_attr_t dev_attr;
urma_query_device(dev, &dev_attr);

// 3. 获取EID并创建上下文
urma_eid_info_t *eid_list = urma_get_eid_list(dev, &eid_cnt);
int eid_index = eid_list[0].eid_index;
urma_context_t *ctx = urma_create_context(dev, eid_index);
urma_free_eid_list(eid_list);
```

### 6.2 创建队列资源示例

```c
// 1. 创建JFCE
urma_jfce_t *jfce = urma_create_jfce(ctx);

// 2. 创建JFC
urma_jfc_cfg_t jfc_cfg = {
    .depth = dev_attr.dev_cap.max_jfc_depth,
    .flag = {.value = 0},
    .jfce = jfce,
};
urma_jfc_t *jfc = urma_create_jfc(ctx, &jfc_cfg);

// 3. 创建JFR
urma_jfr_cfg_t jfr_cfg = {
    .depth = 256,
    .trans_mode = URMA_TM_RM,  // 或 URMA_TM_RC
    .min_rnr_timer = 12,
    .jfc = jfc,
    .token_value = { .token = 0xACFE },
};
urma_jfr_t *jfr = urma_create_jfr(ctx, &jfr_cfg);

// 4. 创建Jetty
urma_jfs_cfg_t jfs_cfg = {
    .depth = 256,
    .trans_mode = URMA_TM_RM,
    .priority = 15,
    .rnr_retry = 7,
    .err_timeout = 17,
    .jfc = jfc,
};
urma_jetty_cfg_t jetty_cfg = {
    .flag.bs.share_jfr = 1,
    .jfs_cfg = jfs_cfg,
    .shared.jfr = jfr,
};
urma_jetty_t *jetty = urma_create_jetty(ctx, &jetty_cfg);
```

### 6.3 注册内存示例

```c
// 分配内存
void *buffer = memalign(4096, 1024 * 1024);  // 1MB, 4KB对齐
memset(buffer, 0, 1024 * 1024);

// 设置访问权限
urma_reg_seg_flag_t flag = {
    .bs.token_policy = URMA_TOKEN_NONE,
    .bs.cacheable = URMA_NON_CACHEABLE,
    .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
};

// 注册内存段
urma_seg_cfg_t seg_cfg = {
    .va = (uint64_t)buffer,
    .len = 1024 * 1024,
    .token_value = { .token = 0xACFE },
    .flag = flag,
};
urma_target_seg_t *local_seg = urma_register_seg(ctx, &seg_cfg);
```

### 6.4 Write操作示例

```c
// 准备数据
snprintf(buffer, MSG_SIZE, "Hello from %d", getpid());

// 构建SGE
urma_sge_t src_sge = {
    .addr = (uint64_t)buffer,
    .len = MSG_SIZE,
    .tseg = local_seg
};
urma_sge_t dst_sge = {
    .addr = remote_seg.ubva.va,
    .len = MSG_SIZE,
    .tseg = import_seg
};
urma_sg_t src_sg = { .sge = &src_sge, .num_sge = 1 };
urma_sg_t dst_sg = { .sge = &dst_sge, .num_sge = 1 };

// 构建WR
urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_WRITE,
    .flag.bs.complete_enable = 1,
    .tjetty = target_jetty,
    .user_ctx = request_id,
    .rw = { .src = src_sg, .dst = dst_sg },
    .next = NULL
};

// 提交请求
urma_jfs_wr_t *bad_wr = NULL;
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);

// 等待完成
urma_cr_t cr;
int cnt = urma_poll_jfc(jfc, 1, &cr);
if (cnt > 0 && cr.status == URMA_CR_SUCCESS) {
    printf("Write completed, user_ctx=%lu\n", cr.user_ctx);
}
```

### 6.5 Send/Recv操作示例

```c
// === 接收端 (预先提交接收缓冲区) ===
urma_sge_t recv_sge = {
    .addr = (uint64_t)recv_buffer,
    .len = MSG_SIZE,
    .tseg = local_seg
};
urma_sg_t recv_sg = { .sge = &recv_sge, .num_sge = 1 };
urma_jfr_wr_t recv_wr = {
    .src = recv_sg,
    .user_ctx = recv_id,
};
urma_post_jetty_recv_wr(jetty, &recv_wr, &bad_wr);

// === 发送端 ===
urma_sge_t send_sge = {
    .addr = (uint64_t)send_buffer,
    .len = MSG_SIZE,
    .tseg = local_seg
};
urma_sg_t send_sg = { .sge = &send_sge, .num_sge = 1 };
urma_jfs_wr_t send_wr = {
    .opcode = URMA_OPC_SEND,
    .flag.bs.complete_enable = 1,
    .tjetty = target_jetty,
    .user_ctx = send_id,
    .send = { .src = send_sg },
};
urma_post_jetty_send_wr(jetty, &send_wr, &bad_wr);

// === 处理完成 ===
urma_cr_t cr;
urma_poll_jfc(jfc, 1, &cr);
if (cr.flag.bs.s_r == 0) {
    // 发送完成
} else {
    // 接收完成
    printf("Received: %s\n", recv_buffer);
}
```

---

## 七、核心实现解析

> 📝 本节解析URMA核心实现代码

### 7.1 代码架构

```
src/urma/lib/urma/core/
├── urma_main.c           # 主入口，初始化/反初始化
├── urma_device.c         # 设备管理
├── urma_cp_api.c         # 控制面API实现
├── urma_dp_api.c         # 数据面API实现
├── urma_cmd.c            # 命令处理
├── urma_cmd_tlv.c        # TLV编解码
├── urma_format_convert.c # 格式转换
├── urma_log.c            # 日志
└── urma_private.h        # 私有头文件

src/urma/lib/urma/core/include/
├── urma_api.h            # 公开API声明
├── urma_types.h          # 类型定义
├── urma_opcode.h         # 操作码和状态码
├── urma_provider.h       # Provider接口定义
└── urma_cmd.h            # 内核命令接口
```

### 7.2 Provider机制

URMA使用 **Provider (驱动提供者)** 机制支持不同的硬件后端。这是一种插件式架构：

```
┌────────────────────────────────────────────────────────────────────┐
│                        URMA Core Library                          │
│                         (liburma.so)                               │
├────────────────────────────────────────────────────────────────────┤
│                      Provider Interface                            │
│                    (urma_provider_ops_t)                           │
├─────────────────┬──────────────────┬──────────────────────────────┤
│    UDMA Provider │   Other Provider  │     ...                     │
│  (liburma-udma.so)                   │                             │
└─────────────────┴──────────────────┴──────────────────────────────┘
```

**Provider注册机制：**

```c
// Provider操作结构
typedef struct urma_provider_ops {
    const char *name;                 // Provider名称
    urma_provider_attr_t attr;        // 属性 (版本, 传输类型)
    urma_match_entry_t *match_table;  // 设备匹配表
    
    urma_status_t (*init)(urma_init_attr_t *conf);
    urma_status_t (*uninit)(void);
    urma_status_t (*query_device)(urma_device_t *dev, urma_device_attr_t *dev_attr);
    urma_context_t *(*create_context)(urma_device_t *dev, uint32_t eid_index, int dev_fd);
    urma_status_t (*delete_context)(urma_context_t *ctx);
} urma_provider_ops_t;

// 注册Provider
int urma_register_provider_ops(urma_provider_ops_t *provider_ops);
int urma_unregister_provider_ops(urma_provider_ops_t *provider_ops);
```

**自动加载机制：**

Provider通过 `__attribute__((constructor))` 在库加载时自动注册：

```c
// udma_u_main.c
static __attribute__((constructor)) void urma_provider_ub_init(void)
{
    urma_register_provider_ops(&g_udma_provider_ops);
}
```

### 7.3 运行时操作接口 (urma_ops_t)

Provider除了初始化接口外，还需要提供运行时操作接口：

```c
typedef struct urma_ops {
    const char *name;
    
    // Jetty管理操作
    urma_jfc_t *(*create_jfc)(urma_context_t *ctx, urma_jfc_cfg_t *jfc_cfg);
    urma_jfs_t *(*create_jfs)(urma_context_t *ctx, urma_jfs_cfg_t *jfs);
    urma_jfr_t *(*create_jfr)(urma_context_t *ctx, urma_jfr_cfg_t *jfr);
    urma_jetty_t *(*create_jetty)(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg);
    
    // 数据面操作 (性能关键路径)
    urma_status_t (*post_jfs_wr)(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
    urma_status_t (*post_jfr_wr)(urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
    urma_status_t (*post_jetty_send_wr)(urma_jetty_t *jetty, urma_jfs_wr_t *wr, ...);
    urma_status_t (*post_jetty_recv_wr)(urma_jetty_t *jetty, urma_jfr_wr_t *wr, ...);
    int (*poll_jfc)(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);
    
    // ... 更多操作
} urma_ops_t;
```

### 7.4 urma_init() 实现流程

```c
urma_status_t urma_init(urma_init_attr_t *conf)
{
    // 1. 检查是否已初始化
    if (atomic_load(&g_init_flag) > 0) {
        return URMA_EEXIST;
    }
    
    // 2. 动态加载Provider库 (/usr/lib64/urma/liburma-*.so)
    urma_open_drivers();
    
    // 3. 初始化设备列表锁
    pthread_spin_init(&g_dev_list_lock, PTHREAD_PROCESS_PRIVATE);
    
    // 4. 调用每个Provider的init函数
    UB_LIST_FOR_EACH_SAFE(driver, next, node, &g_driver_list) {
        if (driver->ops->init(conf) != URMA_SUCCESS) {
            // 移除失败的Provider
            ub_list_remove(&driver->node);
        }
    }
    
    // 5. 发现设备
    urma_discover_devices(&g_dev_list, &g_driver_list);
    
    atomic_fetch_add(&g_init_flag, 1);
    return URMA_SUCCESS;
}
```

### 7.5 控制面API实现模式

控制面API遵循统一的实现模式：

```c
urma_jfc_t *urma_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *jfc_cfg)
{
    // 1. 参数校验
    if (ctx == NULL || jfc_cfg == NULL) {
        errno = EINVAL;
        return NULL;
    }
    
    // 2. 获取Provider操作接口
    urma_ops_t *ops = ctx->ops;
    if (ops == NULL || ops->create_jfc == NULL) {
        errno = EINVAL;
        return NULL;
    }
    
    // 3. 设备能力校验
    urma_device_attr_t *attr = &ctx->dev->sysfs_dev->dev_attr;
    if (jfc_cfg->depth > attr->dev_cap.max_jfc_depth) {
        errno = EINVAL;
        return NULL;
    }
    
    // 4. 增加上下文引用计数
    atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
    
    // 5. 调用Provider实现
    urma_jfc_t *jfc = ops->create_jfc(ctx, jfc_cfg);
    
    // 6. 错误处理
    if (jfc == NULL) {
        atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
    }
    
    return jfc;
}
```

### 7.6 数据面API实现 (性能关键)

数据面API设计强调性能，尽量减少检查：

```c
// 简化的write实现
urma_status_t urma_write(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,
                         urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg,
                         uint64_t dst, uint64_t src, uint32_t len,
                         urma_jfs_wr_flag_t flag, uint64_t user_ctx)
{
    // 最小化参数检查
    urma_ops_t *dp_ops = jfs->urma_ctx->ops;
    
    // 构建WR (栈上分配，避免malloc)
    urma_sge_t src_sge = {.addr = src, .len = len, .tseg = src_tseg};
    urma_sge_t dst_sge = {.addr = dst, .len = len, .tseg = dst_tseg};
    urma_jfs_wr_t wr = {
        .opcode = URMA_OPC_WRITE,
        .flag = flag,
        .user_ctx = user_ctx,
        .tjetty = target_jfr,
        .rw = {
            .src = { .sge = &src_sge, .num_sge = 1 },
            .dst = { .sge = &dst_sge, .num_sge = 1 }
        },
        .next = NULL
    };
    
    // 直接调用Provider实现
    urma_jfs_wr_t *bad_wr;
    return dp_ops->post_jfs_wr(jfs, &wr, &bad_wr);
}
```

### 7.7 引用计数机制

URMA使用原子引用计数管理对象生命周期：

```c
// 创建资源时增加上下文引用
atomic_fetch_add(&ctx->ref.atomic_cnt, 1);

// 删除资源时减少引用
atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);

// 删除上下文时检查引用
if (atomic_load(&ctx->ref.atomic_cnt) > 1) {
    return URMA_EAGAIN;  // 仍有资源在使用
}
```

---

## 八、硬件驱动层 (UDMA)

> 📝 本节解析UDMA (Unified DMA) 用户态驱动实现

### 8.1 UDMA目录结构

```
src/urma/hw/udma/
├── udma_u_main.c         # 驱动主入口，Provider注册
├── udma_u_ops.c          # Provider操作函数表
├── udma_u_jetty.c        # Jetty实现
├── udma_u_jfs.c          # JFS (发送队列) 实现
├── udma_u_jfr.c          # JFR (接收队列) 实现
├── udma_u_jfc.c          # JFC (完成队列) 实现
├── udma_u_segment.c      # 内存段注册/导入
├── udma_u_db.c           # Doorbell机制
├── udma_u_buf.c          # 缓冲区管理
├── udma_u_tid.c          # Token ID管理
├── udma_u_ctrlq_tp.c     # 传输路径控制
├── udma_u_ctl.c          # 用户控制命令
└── kernel_headers/udma_abi.h  # 用户态-内核态ABI
```

### 8.2 UDMA Provider注册

```c
// udma_u_main.c - 库加载时自动注册
static __attribute__((constructor)) void urma_provider_ub_init(void)
{
    urma_register_provider_ops(&g_udma_provider_ops);
}

// udma_u_ops.c - Provider操作定义
urma_provider_ops_t g_udma_provider_ops = {
    .name = "udma",
    .attr = {
        .version = 1,
        .transport_type = URMA_TRANSPORT_UB,  // 灵衢总线
    },
    .init = udma_u_init,
    .uninit = udma_u_uninit,
    .query_device = udma_u_query_device,
    .create_context = udma_u_create_context,
    .delete_context = udma_u_delete_context,
};

// 运行时操作
static urma_ops_t g_udma_ops = {
    .name = "UDMA_OPS",
    // Jetty管理
    .create_jfc = udma_u_create_jfc,
    .create_jfs = udma_u_create_jfs,
    .create_jfr = udma_u_create_jfr,
    .create_jetty = udma_u_create_jetty,
    // 数据面 (性能关键)
    .post_jfs_wr = udma_u_post_jfs_wr,
    .post_jfr_wr = udma_u_post_jfr_wr,
    .post_jetty_send_wr = udma_u_post_jetty_send_wr,
    .post_jetty_recv_wr = udma_u_post_jetty_recv_wr,
    .poll_jfc = udma_u_poll_jfc,
    // ...
};
```

### 8.3 UDMA Context结构

```c
struct udma_u_context {
    urma_context_t urma_ctx;        // 基础上下文
    
    // 硬件相关
    uint32_t page_size;              // 系统页大小
    uint32_t cqe_size;               // CQE大小
    uint32_t dwqe_enable;            // Direct WQE使能
    uint32_t reduce_enable;          // Reduce操作使能
    
    // 标识
    uint32_t ue_id;                  // UE ID
    uint32_t chip_id;                // 芯片ID
    uint32_t die_id;                 // DIE ID
    
    // Doorbell
    struct udma_u_doorbell db;       // JFC doorbell
    pthread_mutex_t db_list_mutex;
    struct udma_u_db_page *db_list[UDMA_DB_TYPE_NUM];
    
    // Jetty管理
    struct {
        atomic_uint refcnt;
        struct udma_u_jetty *table;
    } jetty_table[UDMA_JETTY_TABLE_NUM];
    struct {
        atomic_uint refcnt;
        struct udma_u_jfr *table;
    } jfr_table[UDMA_JETTY_TABLE_NUM];
    pthread_rwlock_t jetty_table_lock;
    pthread_rwlock_t jfr_table_lock;
    
    // 大页管理
    void *hugepage_list;
    pthread_mutex_t hugepage_lock;
    uint32_t hugepage_enable;
};
```

### 8.4 Doorbell机制

**Doorbell** 是CPU通知硬件有新工作的机制，是性能关键路径：

```
┌─────────────────────────────────────────────────────────────────────┐
│                          用户态进程                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  1. 填充WQE (Work Queue Entry)                               │   │
│  │  2. 更新PI (Producer Index)                                  │   │
│  │  3. 写Doorbell寄存器 → 通知硬件                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓ mmap                                │
├─────────────────────────────────────────────────────────────────────┤
│                        Doorbell Page (内存映射)                      │
│                    通过mmap直接映射到用户空间                         │
└─────────────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                          硬件 (DMA引擎)                              │
│              读取WQE → 执行操作 → 写入CQE                            │
└─────────────────────────────────────────────────────────────────────┘
```

**Doorbell类型：**

```c
enum udma_db_type {
    UDMA_JFC_DB = 0,          // JFC doorbell
    UDMA_SW_DB_TYPE_NUM,      // 软件DB数量
    UDMA_MMAP_JFC_PAGE = 0,   // JFC页映射
    UDMA_MMAP_JETTY_DSQE,     // Direct SQE页映射
    // ...
};

// Doorbell分配
int udma_u_alloc_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db)
{
    off_t offset = get_mmap_offset(db->id, page_size, db->type);
    
    // 通过mmap将硬件寄存器映射到用户空间
    db->addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, urma_ctx->dev_fd, offset);
    return 0;
}
```

### 8.5 发送队列 (SQ) 实现

```c
// 创建发送队列
int udma_u_create_sq(struct udma_u_jetty_queue *sq, urma_jfs_cfg_t *cfg)
{
    // 1. 初始化锁 (可选lock-free模式)
    if (!sq->lock_free) {
        pthread_spin_init(&sq->lock, PTHREAD_PROCESS_PRIVATE);
    }
    
    // 2. 计算WQEBB (Work Queue Entry Basic Block) 数量
    uint32_t sqe_bb_cnt = sq_cal_wqebb_num(SQE_WRITE_NOTIFY_CTL_LEN,
                                           cfg->max_sge, UDMA_JFS_WQEBB);
    
    // 3. 分配队列缓冲区 (可能使用大页)
    udma_u_alloc_queue_buf(sq, sqe_bb_cnt * cfg->depth,
                           UDMA_JFS_WQEBB, UDMA_HW_PAGE_SIZE, true);
    return 0;
}

// 提交发送请求
urma_status_t udma_u_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr,
                                  urma_jfs_wr_t **bad_wr)
{
    struct udma_u_jfs *udma_jfs = to_udma_u_jfs(jfs);
    
    // 1. 获取锁 (除非lock-free)
    if (!sq->lock_free) {
        pthread_spin_lock(&sq->lock);
    }
    
    // 2. 遍历WR链表
    while (wr != NULL) {
        // 3. 填充WQE到队列
        fill_wqe_to_sq(sq, wr);
        
        // 4. 更新PI
        sq->head++;
        wr = wr->next;
    }
    
    // 5. 写Doorbell通知硬件
    write_doorbell(sq);
    
    // 6. 释放锁
    if (!sq->lock_free) {
        pthread_spin_unlock(&sq->lock);
    }
    return URMA_SUCCESS;
}
```

### 8.6 完成队列 (CQ) 轮询

```c
int udma_u_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
    struct udma_u_jfc *udma_jfc = to_udma_u_jfc(jfc);
    int polled = 0;
    
    // 1. 获取锁
    pthread_spin_lock(&udma_jfc->lock);
    
    // 2. 遍历CQ
    while (polled < cr_cnt) {
        // 3. 检查CQE有效性 (通过owner bit)
        struct udma_cqe *cqe = get_cqe(udma_jfc, udma_jfc->ci);
        if (!cqe_valid(cqe, udma_jfc->ci)) {
            break;  // 没有更多完成
        }
        
        // 4. 解析CQE，填充CR
        parse_cqe_to_cr(cqe, &cr[polled]);
        
        // 5. 更新CI (Consumer Index)
        udma_jfc->ci++;
        polled++;
    }
    
    // 6. 更新硬件CI (通过doorbell)
    if (polled > 0) {
        update_cq_ci(udma_jfc);
    }
    
    pthread_spin_unlock(&udma_jfc->lock);
    return polled;
}
```

### 8.7 用户态-内核态交互

UDMA通过ioctl与内核驱动交互：

```c
// 命令结构 (urma_cmd.c)
int urma_cmd_create_jfs(urma_context_t *ctx, urma_jfs_t *jfs,
                        urma_jfs_cfg_t *cfg, urma_cmd_udrv_priv_t *udata)
{
    struct ubcore_cmd cmd = {
        .opcode = UBCORE_CMD_CREATE_JFS,
        .in = { .cfg = cfg, .udata = udata },
        .out = { .jfs_id = &jfs->jfs_id }
    };
    
    // 通过ioctl发送命令到内核
    return ioctl(ctx->dev_fd, UBCORE_IOCTL, &cmd);
}
```

### 8.8 Direct WQE (DWQE) 优化

DWQE是一种性能优化，允许直接写入WQE到硬件：

```c
// 使用DWQE发送小消息
if (udma_ctx->dwqe_enable && msg_len <= DWQE_MAX_SIZE) {
    // 直接写入WQE到映射的DWQE区域，跳过普通队列
    memcpy(sq->dwqe_addr, wqe, wqe_size);
    // 硬件立即处理，无需doorbell
} else {
    // 普通路径：写入SQ + doorbell
    fill_wqe_to_sq(sq, wqe);
    write_doorbell(sq);
}
```

---

## 九、常见问题与解答

### Q1: RM模式和RC模式如何选择？

| 特性 | RM (Reliable Message) | RC (Reliable Connection) |
|------|----------------------|--------------------------|
| 连接方式 | 无连接，一对多 | 有连接，一对一 |
| 建立连接 | 不需要bind | 需要urma_bind_jetty() |
| 资源开销 | 较低 | 较高 |
| 适用场景 | 广播、多播 | 点对点可靠传输 |

### Q2: 如何区分发送和接收的完成记录？

```c
urma_cr_t cr;
urma_poll_jfc(jfc, 1, &cr);
if (cr.flag.bs.s_r == 0) {
    // 发送完成 (s_r = 0 表示 send)
} else {
    // 接收完成 (s_r = 1 表示 recv)
}
```

### Q3: 为什么注册内存需要页对齐？

URMA底层的DMA操作需要物理地址对齐，使用`memalign(4096, size)`分配4KB对齐的内存。

### Q4: 如何处理完成错误？

```c
if (cr.status != URMA_CR_SUCCESS) {
    switch (cr.status) {
        case URMA_CR_LOC_ACCESS_ERR:
            // 本地内存访问错误，检查内存段是否正确注册
            break;
        case URMA_CR_REM_ACCESS_ABORT_ERR:
            // 远程内存访问错误，检查远程段权限
            break;
        case URMA_CR_ACK_TIMEOUT_ERR:
            // 超时，检查网络连接
            break;
        // ...
    }
}
```

### Q5: ubcore和uburma有什么区别？它们是什么关系？

**ubcore (UBUS Core)** 和 **uburma (URMA内核模块)** 是两个内核模块，它们的关系和区别如下：

| 特性 | ubcore | uburma |
|------|--------|--------|
| **全称** | Unified Bus Core (统一总线核心) | URMA内核模块 |
| **层级** | 内核驱动层 - 基础层 | 内核驱动层 - 应用层 |
| **职责** | UBUS总线的基础服务 | URMA特定的内核功能 |
| **功能** | • 设备发现和管理<br>• EID分配和管理<br>• 传输路径(TP)管理<br>• 硬件资源抽象<br>• 提供UBUS总线基础设施 | • 内存注册和页锁定(pin memory)<br>• URMA权限控制和安全检查<br>• URMA异常事件处理<br>• 与ubcore交互完成URMA资源分配 |
| **依赖关系** | 不依赖uburma，是基础模块 | **依赖ubcore**，必须在ubcore之后加载 |
| **使用范围** | 所有基于UBUS的应用（URMA、CAM、URPC等） | 仅URMA应用使用 |

**关系图示：**

```
┌─────────────────────────────────────────────────────────────────┐
│                      内核驱动层 (Kernel Space)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │              uburma (URMA内核模块)                      │    │
│  │  • 内存注册/页锁定                                      │    │
│  │  • URMA权限控制                                         │    │
│  │  • URMA异常处理                                         │    │
│  └────────────────────┬───────────────────────────────────┘    │
│                       │ 依赖                                   │
│                       ▼                                        │
│  ┌────────────────────────────────────────────────────────┐    │
│  │              ubcore (UBUS核心模块)                      │    │
│  │  • 设备管理                                             │    │
│  │  • EID管理                                              │    │
│  │  • 传输路径管理                                          │    │
│  │  • 硬件资源抽象                                         │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**加载顺序：**

```bash
# 必须按顺序加载
modprobe ubcore    # 先加载基础核心模块
modprobe uburma    # 再加载URMA模块（依赖ubcore）
```

**设计原因：**

1. **分层设计**：ubcore提供通用的UBUS总线服务，uburma在此基础上实现URMA特定功能
2. **职责分离**：ubcore负责硬件抽象，uburma负责URMA语义
3. **可扩展性**：其他应用（如CAM、URPC）也可以直接使用ubcore，不一定需要uburma
4. **模块化**：两个模块可以独立开发和维护

### Q6: 关于Segment访问权限的常见问题

**Q6.1: 如果声明了远程写或原子操作，必须声明本地写权限？本地权限不是只有LOCAL_ONLY吗？**

**回答**：
- `access`字段控制的是**远程访问权限**（READ、WRITE、ATOMIC控制远程节点能否访问本地内存）
- `LOCAL_ONLY`是一个特殊标志，表示**仅本地访问**（不允许远程访问），与其他权限互斥
- 如果设置了`WRITE`或`ATOMIC`位，意味着允许远程节点写入，那么`access`字段本身就必须包含`WRITE`位（这是代码检查的规则）
- **这不是说需要单独声明"本地写权限"**，而是`WRITE`位本身就意味着这段内存是可写的（包括本地和远程）
- 实际上，如果允许远程写，本地进程本身也需要能够写入这个内存（因为这是本地进程的内存），这是自然的，不需要单独声明

**Q6.2: Token的值是由注册端创建，然后传输给导入端吗？通过信息交换获得远程Segment信息时不能同时获取到该segment的token值吗？**

**回答**：
- **Token值创建**：`token_value`由**注册端（Home节点）创建**（通常使用随机数生成，如`RAND_priv_bytes`）
- **Token值传递**：通过**信息交换**（Socket等带外方式）传递给导入端
  - 在信息交换时，可以将`token_value`包含在交换的数据结构中
  - 示例代码中，`seg_jetty_info_t`结构包含`seg_token_id`（token_id），但`token_value`需要在应用层面通过信息交换传递
  - 导入端调用`urma_import_seg`时需要传入匹配的`token_value`
- **Token验证**：导入端使用接收到的`token_value`调用`import_seg`，内核会验证Token是否匹配
- **注意**：`token_id`和`token_value`的区别：
  - **token_id**：由内核分配的唯一标识符，用于标识Segment（包含在`seg_jetty_info_t`中）
  - **token_value**：由应用程序生成的安全凭证，用于验证访问权限（需要应用程序自己通过信息交换传递）

**Q6.3: URMA_NON_CACHEABLE的作用是什么？什么是免缓存？**

**回答**：
- **NON_CACHEABLE（免缓存）**表示内存访问**不经过CPU缓存层**，CPU和硬件（如网卡）直接访问物理内存
- **作用**：
  1. **避免缓存一致性问题**：在远程内存访问场景中，多个节点可能同时访问同一块内存，使用CPU缓存可能出现缓存一致性问题，`NON_CACHEABLE`可以确保数据的一致性和实时性
  2. **适用于DMA场景**：网卡等硬件设备通过DMA直接访问内存，如果内存被CPU缓存，硬件和CPU可能看到不同的数据，`NON_CACHEABLE`确保硬件和CPU访问的是同一份物理内存数据
  3. **性能考虑**：虽然失去了CPU缓存的加速效果，但避免了缓存同步的开销，在远程内存访问场景中通常性能更好
- **使用建议**：对于URMA的远程内存访问，推荐使用`URMA_NON_CACHEABLE`，以确保数据一致性和最佳性能

---

## 十、代码目录索引

### 10.1 URMA相关目录

| 目录 | 说明 |
|------|------|
| `src/urma/lib/urma/core/` | 核心实现 |
| `src/urma/lib/urma/core/include/` | **核心头文件** (urma_api.h, urma_types.h) |
| `src/urma/lib/urma/bond/` | 多路径聚合实现 |
| `src/urma/lib/uvs/` | 传输路径服务 |
| `src/urma/hw/udma/` | 用户态硬件驱动 |
| `src/urma/tools/urma_admin/` | 管理工具 |
| `src/urma/tools/urma_perftest/` | 性能测试工具 |
| `src/urma/examples/` | **示例代码** (urma_sample.c) |
| `src/urma/common/` | 公共工具库 |

### 10.2 文档目录

| 目录 | 说明 |
|------|------|
| `doc/en/urma/` | 英文文档 |
| `doc/ch/urma/` | 中文文档 |

### 10.3 测试目录

| 目录 | 说明 |
|------|------|
| `test/urma/` | 单元测试 |
| `test/intergration_test/test_suites/URMA/` | 集成测试 |

---

## 更新日志

| 日期 | 内容 |
|------|------|
| 2026-01-12 | 初始创建，完成第一至第六阶段学习内容 |
| 2026-01-12 | 新增第七节：核心实现解析（Provider机制、API实现模式） |
| 2026-01-12 | 新增第八节：硬件驱动层解析（UDMA实现、Doorbell机制） |
| 2026-01-12 | 补充1.2节详细内容：各层详细说明、数据流向、设计原因 |
| 2026-01-12 | 新增Q5：ubcore和uburma的区别和关系说明 |
| 2026-01-12 | 大幅扩展2.1节：EID详细说明（结构、格式、用途、示例） |
| 2026-01-12 | 大幅扩展2.2节：UBVA详细说明（组成、解析流程、使用场景、与EID关系） |
| 2026-01-12 | 新增2.2.1.1节：详细解释"打破节点地址边界"的含义（传统vs UBVA对比） |
| 2026-01-12 | 新增2.2.1.2节：实际应用示例，展示如何使用UBVA跨节点访问内存 |
| 2026-01-12 | 大幅扩展2.3节：Segment详细说明（数据结构、访问权限、Token策略、完整生命周期、示例代码） |
| 2026-01-12 | 澄清2.3.4节：修正权限组合规则的描述，说明access字段控制远程访问权限 |
| 2026-01-12 | 扩展2.3.5节：详细说明Token工作机制，token_value的创建和传递流程，token_id和token_value的区别 |
| 2026-01-12 | 扩展2.3.6节：详细解释NON_CACHEABLE的作用和意义（缓存一致性、DMA场景、性能考虑） |
| 2026-01-12 | 新增Q6：关于Segment访问权限的常见问题（权限规则、Token传递、NON_CACHEABLE作用） |
| 2026-01-12 | 删除2.3.10节中的不准确描述，避免与Q6.1重复 |
| 2026-01-12 | 扩展2.4.1节：详细说明JFCE的作用、工作原理、使用场景和使用流程 |
| 2026-01-12 | 大幅扩展3.1节：详细说明urma_device和urma_context的每个字段（类型、可见性、说明、使用示例） |
| 2026-01-12 | 扩展3.1.2节：详细解释urma_device和urma_context的关系、dev->ops和ctx->ops的区别、EID索引的作用、聚合模式说明、为什么所有资源创建都需要上下文 |

---

## 附录A：关键代码文件速查

| 功能 | 文件位置 |
|------|----------|
| API声明 | `src/urma/lib/urma/core/include/urma_api.h` |
| 类型定义 | `src/urma/lib/urma/core/include/urma_types.h` |
| 操作码 | `src/urma/lib/urma/core/include/urma_opcode.h` |
| Provider接口 | `src/urma/lib/urma/core/include/urma_provider.h` |
| 初始化实现 | `src/urma/lib/urma/core/urma_main.c` |
| 控制面实现 | `src/urma/lib/urma/core/urma_cp_api.c` |
| 数据面实现 | `src/urma/lib/urma/core/urma_dp_api.c` |
| UDMA操作 | `src/urma/hw/udma/udma_u_ops.c` |
| UDMA JFS | `src/urma/hw/udma/udma_u_jfs.c` |
| 示例代码 | `src/urma/examples/urma_sample.c` |

---

## 附录B：学习路线图

```
┌─────────────────────────────────────────────────────────────────────┐
│                         URMA学习路线图                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  第一阶段 ──► 第二阶段 ──► 第三阶段 ──► 第四阶段                      │
│  (概念架构)   (数据结构)   (API接口)   (示例代码)                      │
│     ✓            ✓           ✓           ✓                          │
│                                                                      │
│  第五阶段 ──► 第六阶段 ──► 实践应用                                   │
│  (核心实现)   (硬件驱动)   (编写自己的程序)                            │
│     ✓            ✓                                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

> 📌 **备注**: 本文档持续更新中，如有疑问或发现错误，请随时反馈。
