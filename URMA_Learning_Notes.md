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

### 1.3 URMA的主要功能

- **单边操作 (One-Sided)**: Read/Write - 远程端不感知
- **双边操作 (Two-Sided)**: Send/Recv - 需要远程端配合
- **原子操作**: CAS (Compare-And-Swap), FAA (Fetch-And-Add)
- **多种传输模式**: RM (可靠消息), RC (可靠连接), UM (不可靠消息)

---

## 二、核心概念

### 2.1 EID (Endpoint ID) - 端点标识

EID是设备的端点标识符，类似于网络中的IP地址：
- 16字节，支持IPv4映射到IPv6
- 用于标识UBUS总线上的每个设备/端点

```c
typedef union urma_eid {
    uint8_t raw[16];          // 原始字节
    struct {                   // IPv4映射
        uint64_t reserved;     // == 0
        uint32_t prefix;       // == 0x0000ffff
        uint32_t addr;         // IPv4地址
    } in4;
    struct {                   // IPv6
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} urma_eid_t;
```

### 2.2 UBVA (Unified Bus Virtual Address) - 统一总线虚拟地址

UBVA用于跨节点寻址，由三部分组成：

```
┌─────────────────┬─────────────┬─────────────────────────┐
│      EID        │    UASID    │          VA             │
│   (16 bytes)    │  (4 bytes)  │       (8 bytes)         │
│   端点标识       │  地址空间ID  │      虚拟地址           │
└─────────────────┴─────────────┴─────────────────────────┘
```

```c
typedef struct urma_ubva {
    urma_eid_t eid;
    uint32_t uasid;   // 用户地址空间ID，区分不同进程
    uint64_t va;      // 虚拟地址
} urma_ubva_t;
```

### 2.3 Segment - 内存段

Segment是一块连续的内存区域，用于远程访问：

```c
// 注册内存段的配置
typedef struct urma_seg_cfg {
    uint64_t va;              // 内存地址
    uint64_t len;             // 内存长度
    urma_token_id_t *token_id;
    urma_token_t token_value; // 安全Token
    urma_reg_seg_flag_t flag; // 访问权限等标志
    uint64_t user_ctx;
    uint64_t iova;
} urma_seg_cfg_t;

// 访问权限标志
#define URMA_ACCESS_LOCAL_ONLY (0x1 << 0)  // 仅本地访问
#define URMA_ACCESS_READ       (0x1 << 1)  // 允许远程读
#define URMA_ACCESS_WRITE      (0x1 << 2)  // 允许远程写
#define URMA_ACCESS_ATOMIC     (0x1 << 3)  // 允许远程原子操作
```

**内存段操作流程：**
```
本地端                              远程端
┌──────────────┐                  ┌──────────────┐
│ register_seg │                  │              │
│   注册内存    │ ──信息交换───►   │ import_seg   │
│              │                  │   导入内存    │
└──────────────┘                  └──────────────┘
```

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

```c
// 设备结构
typedef struct urma_device {
    char name[64];               // 设备名称，如 "udma0"
    char path[4096];             // sysfs路径
    urma_transport_type_t type;  // 传输类型
    struct urma_provider_ops *ops;    // 驱动操作 (私有)
    struct urma_sysfs_dev *sysfs_dev; // 内部设备 (私有)
} urma_device_t;

// 上下文结构
typedef struct urma_context {
    struct urma_device *dev;     // 设备指针
    struct urma_ops *ops;        // 操作函数
    int dev_fd;                  // 设备文件描述符
    int async_fd;                // 异步事件文件描述符
    pthread_mutex_t mutex;       // 互斥锁
    urma_eid_t eid;              // 端点标识 [公开]
    uint32_t eid_index;          // EID索引
    uint32_t uasid;              // 用户地址空间ID [公开]
    struct urma_ref ref;         // 引用计数
    urma_context_aggr_mode_t aggr_mode; // 聚合模式
} urma_context_t;
```

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
