<!--
  Native-Universal.md
  SimpleBCM

  Created by laobamac on 2026/11/2.
  Copyright © 2026 laobamac. All rights reserved.
-->

# 原生 Skywalk 适配

SimpleBCM 在启动时按 Darwin 主版本选择配置，不以系统小版本、构建号或 UUID 限制加载。加载前检查实际依赖的原生类大小和虚方法布局。包内包含 Legacy、原始 AirPort 和 Tahoe AirPort 三个载荷，每次只映射并注册 Legacy 与当前系统的 AirPort。旧 IOSkywalkFamily 仅用于构建期 ABI 对照，不嵌入驱动。

## 构建参考

| 系统 | 构建 | IOSkywalkFamily UUID | IO80211Family UUID |
| --- | --- | --- | --- |
| Sonoma 14.8.8 | 23J620 | 9F5908B5-BA4B-37E3-AC31-62E1D45F1589 | EC4BA672-6E08-3AD2-B882-01690A960FF4 |
| Sequoia 15.8 | 24H23 | 70DFAA8E-E369-3417-B6FD-B19FB6D5D49B | 13D3592A-A6BE-35E7-984C-0ACD90A76356 |
| Tahoe 26.7.2 | 25G332 | A6EDB8DB-175B-3A49-8919-5769FCDB6BED | 4C2B4969-2B92-3646-9512-C1769BE0F9A4 |

以上版本和 UUID 用于固定构建输入，不是运行时白名单。配置源为 `Tools/system_profiles.py`，生成器为 `Tools/native_abi.py`、`Tools/native_payload.py` 和 `Tools/embed.py`。运行时通过元类与符号地址核对 15 个原生类和接口、包池、用户客户端的虚表布局。

## 对象与调用转接

| 原生布局 | Sonoma | Sequoia | Tahoe |
| --- | ---: | ---: | ---: |
| IOSkywalkNetworkInterface 大小 | 208 | 208 | 224 |
| IOSkywalkEthernetInterface 大小 | 272 | 272 | 288 |
| Ethernet 扩展指针偏移 | 264 | 264 | 280 |
| Ethernet 虚表槽数 | 353 | 352 | 353 |
| IOSkywalkPacketBufferPool 大小 | 184 | 184 | 192 |
| IOSkywalkNetworkBSDClient 大小 | 328 | 328 | 336 |
| IO80211API/AsyncEventUserClient 大小 | 224 | 224 | 224 |

Legacy 在 `this+0x118` 保存控制器，而 Tahoe 的 Ethernet 父类在同一位置保存扩展指针。`NativeSkywalk.cpp` 通过 272 字节的 BCMLegacyInterface 保留旧布局，另行构造原生 Ethernet 对象。原生派生对象统一分配 296 字节，在偏移 288 保存上下文；方法转发时切换接收对象，回调期间临时持有旧对象引用。

接口回调按各系统的完整虚表生成。Sonoma 的逻辑链路注册入口从原生 Ethernet 虚表取得；Sequoia、Tahoe 在原生代码段内匹配注册包装函数，并核对其调用的 Ethernet 注销入口。匹配要求唯一，支持地址移动，不使用固定函数地址偏移。

数据包和队列使用原生 Skywalk 对象，不引入每包适配对象或额外包数据复制。Packet 虚调用与构造函数虚表按新增槽位调整。包池分配、元类大小与释放按系统配置选择；Sonoma、Sequoia 使用 Pool::release，Tahoe 使用 OSObject::release 和 Pool::taggedRelease。TxSubmission 使用 const 包数组回调重载，保留原 flags，并向新增参数传入 UINT32_MAX。

## 类名与控制接口

Legacy 与原生 IO80211Family 的冲突元类在载荷 CString 中重命名，保留原字符串槽位大小及 C++ 符号解析。旧控制器注册为 AirPortDriver，使 SystemConfiguration 将其识别为无线控制器。

`NativeUserClient.cpp` 使用原生 API/AsyncEvent 用户客户端的构造函数和元类，将实例方法转接到 BCM80211UserClient。系统进程仍取得原生客户端类型，权限检查沿用原控制实现。`WirelessABI.hpp` 处理三个系统的 selector、关联结构、扫描结果和事件格式差异。

## 电源与载荷

原生 IOSkywalkNetworkBSDClient 的电源父节点通过 `joinPMtree` 接到无线控制器的实际 IOPCIDevice provider；网络 IOService 的 provider 关系保持不变。接口上下文持有 PCI provider，停止或启动失败时释放。AirPort 原始电源表不作改写。

载荷原件由 `Tools/bootstrap.py` 固定提交与 SHA-256。生成阶段只改写构建目录内的映射副本，运行时修改限于自有载荷和实例虚表。`Tools/build.py` 检查原生导出、继承虚表、重定位、转发调用约定和控制面编解码；完整构建环境见 [Build.md](Build.md)。
