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

以上版本和 UUID 用于固定构建参考，不是运行时白名单。`Resources/NativeABI` 保存从这些系统提取的符号、虚表及必要代码片段，构建时校验 SHA-256 后读取。配置源为 `Tools/system_profiles.py`，生成器为 `Tools/native_abi.py`、`Tools/native_payload.py` 和 `Tools/embed.py`。运行时通过元类与符号地址核对 15 个原生类和接口、包池、用户客户端的虚表布局。

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

## 热点与 IBSS

请求 24（IBSS）和 25（HostAP）共用 Legacy 的 `setIBSS_Or_HostAP_Mode`。旧函数的配置栈缓冲区只有 `0x5DC`（1500 字节），而 Sonoma、Sequoia、Tahoe 的原生配置分别为 `0x6DC`、`0x6E4`、`0x6E8`，直接复制原生长度会覆盖栈保护值及返回地址。

`WirelessABI.hpp` 在已有堆缓冲区内验证并转换启动配置，将扩大的认证字段、密钥、RSN 和附加 IE 按旧布局整理，仅向旧函数传递 1500 字节。无法表示的扩展或不一致的安全配置在改动输入前返回错误。启动操作值为 1，停止值为 2；停止保留零长度请求。Legacy 共用入口只接受转换后的完整启动配置或零长度停止请求，使用经指令边界核对的 20 字节转接前缀。

桥接器完成主热点启动请求后，在真实无线控制器上记录 `SimpleBCMHostAPActive`，避免依赖旧处理函数可空的 Classic 接口参数。共享配置期间，旧网络接口的 disable 路径会发送关闭无线电请求；仅这一处已核对的调用转接到电源保护，保留正在工作且没有系统电源切换的热点无线电。停止热点、切换关联或模式、显式关闭 Wi-Fi、系统休眠及设备终止均释放或绕过保护，接口、队列和 BPF 仍由原实现处理。

原生 `airportd` 的普通 WPA2 Personal 热点使用认证下层值 1、上层值 8，密钥版本和类型均为 0，密钥区保存原始 UTF-8 密码，RSN 区留空。转换层将上层认证改为 Legacy 的 `0x400`，使固件采用 WPA2-PSK `0x80`；密钥版本设为 1，类型设为 10。8 至 63 字节密码保持原内容和长度，64 字符密钥必须为有效十六进制 PSK。类型 6 的 32 字节 PMK 配合 CCMP/PSK RSN 时转换为十六进制密钥。要求管理帧保护或安全字段不一致的请求直接拒绝，不退回开放网络。

原 `setHOST_AP_MODE` 的空密钥清理会清除 `wsec`。后续密码安装调用先确认 AP BSS 和认证模块，对空认证对象调用原 `_wlc_authenticator_attach`，再用原 `_wlc_sae_process_akm_type` 设置 WPA2 的 Open System 认证策略。通过原 `wlIovarSetInt` 设置 AES `wsec=4`，随后使用原 `wlIoctl` 命令 268 安装密码或密钥，参数长度为 68 字节，使用后清零。错误向原调用方传播，认证对象的握手和释放沿用驱动已有实现。

最终 `setSSID` 会依据缓存 RSN 重算加密值；普通原生热点的 RSN 为空，原计算结果为 0。只转接该函数中一处加密计算调用，在当前已转换的 WPA2 HostAP 请求的线程、控制器及接口均匹配时补 AES 位 4。开放热点、IBSS 和普通 STA 关联继续使用原计算结果。

实机确认过热点广播 BSSID 与接收地址不一致：广播使用热点生成的随机地址，BSS 的当前地址仍为网卡原地址；通过系统网络接口重新应用同一热点地址后，手机成功连接。桥接器在调用旧驱动前保存 HostAP 启停操作，启动请求被接受后在真实控制器上记录活动状态，覆盖 Classic、Virtual 和 Skywalk 请求出口。读取主 AP BSS 偏移 232 的 BSSID，通过原 `_wlc_validate_mac_pub` 同步公开地址、BSS 偏移 238 的当前地址以及硬件地址缓存；该原函数在必要时暂停 MAC、更新接收匹配并恢复 MAC，避免直接写运行中的匹配表。随后重新查询 BSS，确认两地址均正确。非法地址、非主 BSS、设置失败或同步后仍不一致均返回错误。没有新增入口转接或接入追踪钩子。

原生热点面板只提供 WPA2 且安全性下拉框置灰，由 CoreWLANKit 的平台能力决定；这与驱动的实际加密配置及客户端能否连接是不同的检查。

活动状态和启动时同步成功不能保证后续驱动操作维持同一接收地址。现有事件工作线程以及每秒状态更新在控制器工作循环中复核活动主 AP 的 BSSID 和当前地址，发现不一致时才执行原地址设置及接收匹配刷新。设备终止、休眠、电源切换、非工作电源状态或 BSS 尚未 up 时不写硬件。该复核不读取报文、不改动 STA 地址，也不增加全局收发钩子。

## 电源与载荷

原生 IOSkywalkNetworkBSDClient 的电源父节点通过 `joinPMtree` 接到无线控制器的实际 IOPCIDevice provider；网络 IOService 的 provider 关系保持不变。接口上下文持有 PCI provider，停止或启动失败时释放。AirPort 原始电源表不作改写。

载荷原件由 `Tools/bootstrap.py` 固定提交与 SHA-256。两种 AirPort 共用一份基础载荷和相同的重定位、符号及入口表，Tahoe 的差异以偏移、长度和替换字节保存。启动时仅在选中载荷的独立映射中恢复字节，差分边界检查通过后才写入，完整载荷校验通过后才重定位；基础载荷保持只读，不增加收发阶段的处理。

生成阶段只改写构建目录内的映射副本，运行时修改限于自有载荷和实例虚表。`Tools/build.py` 检查载荷恢复、原生导出、继承虚表、重定位、转发调用约定和控制面编解码；完整构建环境见 [Build.md](Build.md)。
