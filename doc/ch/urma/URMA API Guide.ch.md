## URMA接口规范

接口文件列表： 
[urma_api.h](../../../src/urma/lib/urma/core/include/urma_api.h)

### URMA简介
### 1. 基础概念
#### 1.1 UBVA地址模型
UBVA，Unified Bus Virtual Address，是UBUS总线上的分级的虚拟地址，支持对总线的多个节点共享内存进行统一编址，打破了各个节点地址边界，允许应用通过VA进行跨节点寻址和数据访问。包括了EID/CID，UASID和VA地址三个部分。

#### 1.2 TPA(Tagged PA)
Tagged PA：由于远端内存需要映射到本地的物理地址空间，为了与主机原有的物理地址区分，引入了tagged PA的概念。Tagged PA 是一段连续的物理地址空间，被映射到相应的UBEP设备空间，当有远端内存被挂载到本地时，UBEP驱动会分配对等大小的地址空间。

#### 1.3 mVA(Mapped VA)
mVA是将远端内存映射到本地虚拟地址空间时分配的虚拟地址，mVA也是进程页表里合法地址，经过CPU MMU可以翻译为TPA。User对mVA的访问最终会转换为对远端内存的访问。

#### 1.4 segment
Segment是一段连续的VA地址空间，同时分配物理内存来对应到一个segment。由segment home节点创建。User侧的APP把segment映射到进程虚拟地址空间，通过被映射地址直接访问远端内存。segment的VA地址和user进程映射的VA可以相同，也可以不同。VA地址相同的场景，即DSVA场景。

#### 1.5 URMA Region
URMA Region，简称UR，是一种分布式共享内存的管理方式，由一个或者多个segment组成。UR由owner节点进程创建。一个URMA Region上的多个segment可能来自于不同的home节点。应用可以选择是否创建UR。

#### 1.6 Jetty
Jetty是用于管理提交的IO任务或接收的消息的队列，可看成URMA命令执行的“港口”，由以下几个对象组成：
JFS(Jetty for send)：用于在user侧提交DMA任务，或者发送某个消息；
JFR(Jetty for receive)：用于在home侧准备接收某个消息的资源；
JFC(Jetty for completion)：用于存放JFS/JFR的完成记录，可以与JFS或JFR绑定，也可以在具体的URMA命令中单独指定；
JFCE(Jetty for completion event):  用于存放完成事件，所谓完成事件即为：新完成记录所在的JFC指针；多个JFC可以关联同一个JFCE，但不推荐多个线程之间共享同一个JFCE。

### 管理面接口说明
#### 1. 上下文管理
**概述**:
    URMA支持不同的硬件平台，在初始化时需要配置对应的provider，同时指定使用的设备，创建出上下文。

**应用场景**:
    URMA的上下文管理需要在应用运行初期执行，后续的Jetty、Segment管理和数据面操作都依赖该操作。

**使用说明**：
    (1) 调用urma_init函数配置使用的平台和配置uasid。uasid不指定时由系统随机分配，指定uasid时可能导致函数执行失败。使用编排时必须配置 enable_orch=1。
    (2) 调用urma_query_device函数查询设备的属性，获取eid等信息。如果应用已经获取设备的eid，则该步骤可不执行。
    (3) 调用urma_create_context函数创建设备上下文。

#### 2. Jetty管理
**概述**:
    URMA执行资源管理通过Jetty进行管理。Jetty为URMA软件操作对象，借助Jetty UBEP和软件实现消息交互。
    Jetty主要用于消息语义接收、发送以及内存语义的命令下发。
    Jetty为进程独享，根据用途的不同Jetty可细分为Jetty For Send（JFS）、Jetty For Receive（JFR）、Jetty For Complete（JFC）、Jetty For Completion event（JFCE）。

**应用场景**:
    在进行具体的read, write，send，receive等操作前需要建立相关的jetty资源，后续的read,write,send,receive等操作都依赖创建的jetty资源。

**注意事项**:
    创建JFC时指定相关的JFCE，才能以中断模式等待完成事件和获取完成记录。

**使用说明**：
    (1) 使用Jetty实现消息语义的编程框架如下图所示，其中JFC为轮询模式，没有绑定JFCE：

![](./figures/send_recv_example_polling_mode.png)
    (2) 中断模式使用JFCE的编程框架如下图所示：

![](./figures/send_recv_example_break_mode.png)

#### 3. Segment管理
**概述**:
    Segment是一段连续的VA地址空间，同时分配物理内存来对应到一个segment。
    获取本地内存，需使用urma_register_seg得到ubva, 获取远端内存需使用urma_import_seg得到ubva或mva。

**应用场景**:
    urma语义的内存管理

**注意事项**:
    (1) 本地用户对远端内存读写时，本地buf和远端内存必须提前调用urma_register_seg注册到设备, 不使用必须调用urma_unregister_seg注销。
    (2) 应用使用远端内存读写之前，必须调用urma_import_seg获取target_segment。
    (3) 注册segment时，如果声明了remote write或者remote atomic权限，那么应用也必须同时声明local write权限，否则注册失败。

**使用说明**：
    (1) 使用本地内存：申请va，调用urma_register_seg注册segment。
    (2) 释放本地内存：调用urma_unregister注销segment
    (3) 使用远端内存：import_segment获取targ_segment和mva。
    (4) 释放远端内存：unimport_segment注销segment

基于segment实现内存语义的编程框架如下图所示：

![](./figures/segment_example.png)

#### 4. 异常事件
**概述**:
    (1) 应用发送硬件无法处理的WR，访问超出本端或远端内存的权限，Jetty或者JFC溢出，驱动卸载，端口状态异常等情况下，硬件将上报异常事件。
    (2) 应用获取发生的异常类型、具体的异常的对象：异常的上下文、端口、JFS、JFC、JFR等。应用处理完异常后，向UMDK确认已经完成异常处理。

**应用场景**：
    urma异常场景

**注意事项**：
    应用删除某个对象（例如JFS，JFR，JFC，Jetty）之前，如果获得过改对象产生的异常事件时，必须调用确认异常接口（urma_ack_async_event），然后才能删除该对象。

**使用说明**：
    (1) 用户调用urma_get_async_event接口获取异常事件；
    (2) 用户根据异常事件类型，进行分类处理，例如打印log信息；
    (3) 用户调用urma_ack_async_event接口，通知UMDK已经处理完异常。

#### 5. 设备属性
UB设备属性包含大致分为三类：只读且不变的设备资源规格、可读可写的设备配置信息、只读且可变的设备端口状态。目前urma框架通过sysfs文件系统统一呈现，这些文件可以直接通过cat、echo等命令进行操作。

### 数据面接口说明
#### 1. 单边操作
**概述**：
    UMDK单边操作提供了read write语义，类似于IB的read/write接口，需要知道本地的地址和对端的地址，进行单边操作时只有本端进程在操作，不需要对端的应用感知。
    UMDK单边操作缓存支持本端连续内存、非连续内存和远端连续内存。urma_read，urma_write只支持连续地址的读写。urma_post_jfs_wr支持本端以sgl的形式访问非连续地址。
    UMDK支持立即数的写操作，见urma_post_jfs_wr接口，所写的立即数将出现在接收端的完成记录（completion record）中。
    根据UB协议，write和read操作只支持一个远端sge。因此对于write操作，dst.num_sge必须为1，对于read操作，src.num_sge必须为1。超出部分sge网卡将忽略。

**应用场景**：
    UMDK单边操作不需要对端的CPU参与，不同于双边操作send/recv一般用于传输一些控制信息，单边操作read/write适用于传输大量的数据，实现大规模数据的搬移等。

**注意事项**：
    (1) 用户发送和接收的本地缓存必须事先调用urma_register_seg注册到设备。
    (2) 对于IB传输层，JFS向某个JFR发送消息之前，必须调用urma_advise_jfr通知UMDK建立从JFS到JFR的传输通道。UB JFS天然具有一对多通信能力，发送消息之前无需调用urma_advise_jfr这个步骤。
    (3) 不同的传输层最大发送消息大小有所不同，可以通过查询设备属性获取发送消息的规格。

**使用说明**:
    UMDK单边读/写的过程为：
    (1) 调用urma_read，urma_write或urma_post_jfs_wr提交一个读或写的请求至先前注册好的jfs。
    (2) 调用urma_poll_jfc进行轮询，查看jfc中是否有cqe到来，当urma_poll_jfc返回值大于0时，即表示轮询到有cqe,表示此次读操作完成。请求完成后，用户才能重新使用（修改或释放）发送消息缓存。

#### 2. 双边操作
**概述**:
    消息语义提供了双边Messaging服务，类似于UDP/TCP socket接口或IB的send/receive接口。UMDK的消息语义是异步非阻塞的，消息接收端需要显示地接收消息，接收完成后读取消息继续其他处理。
    UMDK支持一对多消息语义：从同一个JFS向不同的JFR发送消息，这些JFR可能位于不同的远端节点或进程。
    UMDK支持以inline方式发送消息，当消息小于UMDK inline阈值时，将UMDK将自动以inline方式发送消息，减少DMA开销以提高发送性能。
    UMDK双边操作对本端和远端均支持连续内存和非连续内存。urma_send与urma_recv只支持连续地址。urma_post_jfs_wr和urma_post_jfr_wr支持本端和远端使用连续地址或sgl类型的非连续地址。
    UMDK支持向接收端发送立即数，见urma_post_jfs_wr接口，所发送的立即数将出现在接收端的完成记录（completion record）中。

**应用场景**:
    消息语义应用广泛，例如实现MPI send、recv消息发送，RPC语义，实现UCX的am消息语义等。

**注意事项**：
    (1) 用户发送和接收的本地缓存必须事先调用urma_register_seg注册到设备。
    (2) 对于IB传输层，JFS向某个JFR发送消息之前，必须调用urma_advise_jfr通知UMDK建立从JFS到JFR的传输通道。UB JFS天然具有一对多通信能力，发送消息之前无需调用urma_advise_jfr这个步骤。
    (3) 不同的传输层最大发送消息大小有所不同，可以通过查询设备属性获取发送消息的规格。

**使用说明**:
    接收消息过程为:
    (1) 调用urma recv或urma_post_jfr_wr提交一个接收请求，将本地接收缓存添加到jfr中
    (2) 调用urma_poll_jfc轮询接收请求，请求完成后，用户才能从接收缓存中读取消息内容
    为了提高吞吐量服务器端可以批量提交多个接收请求。每成功接收到一个消息后，向JFR补充新的接收请求。或者当JFR的接收请求数低于某个阈值时，向JFR补充新的接收请求。
    接收端通过完成记录中的接收长度获得具体收到的有效消息长度，也通过完成记录获知发送端是否发送了立即数。
    发送消息过程为：
    (1) 用户调用urma send或urma_post_jfs_wr通过JFS提交一个发送请求，
    (2) 调用urma_poll_jfc轮询接收请求，请求完成后，用户才能重新使用（修改或释放）发送消息缓存。

#### 3. 完成记录
**概述**:
    上述单边、双边和原子操作都是非阻塞的，操作返回成功仅表示命令已经添加到发送或者接受队列，并不意味着已经全部完成。
    UMDK支持以轮询或中断方式获知单边、双边或原子操作是否已经完成。完成记录（completion record）用来描述操作完成信息。
    操作完成后，硬件会将完成记录写到JFC完成队列中。当用户轮询JFC时，UMDK读取完成队列的完成记录返回给用户。
    单边、双边、原子等操作的完成记录将默认写入JFS或JFR所关联的JFC中。UB设备支持在JFS command（即WQE）中指定完成记录待写入的JFC id。

**应用场景**:
    轮询方式应用于低时延场景，用户通过不断查询完成记录，获取操作的执行状态以进行下一步操作，不断轮询操作将提高CPU占用率。中断方式应用于通信不太频繁的场景，用户线程以睡眠状态等待完成事件，CPU开销小，当完成事件发生时，UMDK将唤醒等待的线程。

**注意事项**:
    (1) 用户调用urma_recv时，接收完成时总会产生一个完成记录。用户调用urma_read/write/cas/fao/send时，默认操作将会产生一个完成记录；如果JFC处于事件使能状态（armed）也默认将产生一个完成事件。
    (2) 如果用户使用urma_post_jfs_wr批量发送请求时，用户可以指定是否产生完成记录或者完成事件。
    (3) 用户提交操作（包括单边、双边、原子等）时，需要自行保证完成记录待写入的JFC不会溢出。
    (4) 如果JFC中尚有未读取的完成记录，那么urma_rearm_jfc将返回失败。

**使用说明**:
    用户调用urma_poll_jfc以轮询方式查询完成记录，轮询是一种非阻塞的查询完成记录的方式，如果完成队列为空，则用户获取不到完成记录。完成记录的**使用说明**如下：
    (1) 用户通过完成记录的状态字段得知操作是否成功完成，如果出错，完成记录的状态字段反应出操作出错的原因；
    (2) 完成长度表示已经成功执行的数据长度，例如发送长度或接收消息长度
    (3) 如果完成记录为JFS类型，则用户可以修改或释放操作对应的本地缓存
    (4) 如果完成记录为JFR类型，表示用户可以从接收缓存中读取消息；
    (5) 如果notify_data标志位使能，则完成记录中还携带了立即数
    (6) 用户通过完成记录的completion_record_data等于操作上下文（例如urma_read api中的user_ctx参数），关联到具体某个操作
    中断模式等待完成事件的流程如下：
    (1) 调用urma_rearm_jfc使能完成事件；
    (2) 提交JFS操作（包括单边、双边、原子等），指定需要完成记录和完成时间
    (3) 调用urma_wait_jfc阻塞等待一个完成事件，返回产生完成事件的JFC；UMDK将默认去使能JFC完成事件
    (4) 判断返回的JFC和提交JFS操作所有的JFC相符合
    (5) 循环调用urma_poll_jfc读取完成记录，直到没有新的完成记录为止
    (6) 回到步骤（1）重新开启事件