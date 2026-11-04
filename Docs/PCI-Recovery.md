<!--
  PCI-Recovery.md
  SimpleBCM

  Created by laobamac on 2026/11/5.
  Copyright © 2026 laobamac. All rights reserved.
-->

# PCI 配置恢复

v1.2.1 在内嵌 AirPort 的启动完成、电源降低和 D3 退出校验处接入恢复逻辑。适用于网卡运行中失去 PCIe 访问，随后 AirPort 自动 OFF/ON 时报告 BAR0 未恢复的情况。修复针对配置恢复缺口；首次链路掉线的诱因尚未由现场证据确定。

启动成功后保存这张网卡的 PCI 配置和 registry ID。正常降低电源前，只有身份、BAR 和解码状态仍与有效快照一致才更新快照。掉线时读到的全 FF 数据不会覆盖有效快照。快照随控制器属性的生命周期释放，不维护全局设备指针。

恢复在 AirPort 工作循环持有 gate、执行原始 `wlc_verify_d3_exit` 之前进行。身份、BAR 与解码正常时直接执行原函数。异常时每个控制器实例最多尝试三次：

1. 端点不可访问时，仅当 DeviceTree 上游节点是 PCI 桥、下游唯一节点就是这张单功能网卡、上游不在低电源状态且未处于复位中，才执行一次次级总线复位。等待端点重新出现的上限为一秒。
2. 核对设备身份，拒绝把有效但不同的 BAR 地址覆盖成旧地址。
3. 先关闭解码、总线主控和传统中断并核对，再恢复 D0 和 BAR；恢复必要的缓存、PCIe 控制及 MSI 地址、数据、屏蔽位。最后校验 BAR 和 MSI，再恢复 PCI Command。
4. 始终执行原驱动的 PCI 状态校验，保留其错误。自身恢复失败时，即使原校验返回成功，也返回失败。

恢复不整块回写 256 字节配置空间，不写 PCI 身份和状态寄存器，不重放 PM 状态清除位、PCIe FLR、Link Disable 或 Retrain 命令。已启用 MSI-X 的设备不建立该恢复快照。包内保留原始 AirPort 电源表与接口路由。

`bcmprobe` 的 SimpleBCM 节点报告 `PCIRecoveryState`、`PCIRecoveryAttempts`、恢复前后 ID/BAR0、原驱动校验结果与最终返回结果。`Verified` 表示 PCI 恢复和原驱动校验通过，不代替实际收发验证。`ResetRefused` 表示拓扑或设备状态不满足复位条件。

`collect.py` 同时收集控制器状态与最近三份 AXIWrapRdFail CoreCapture 中的压缩驱动日志、PCI 配置快照及元数据。文件读取失败和容量限制会写入 diagnostics.json。

构建验证包含正常设备不写配置、BAR 丢失、端点消失、禁止复位、链路无法恢复、设备身份变化、资源地址变化、配置写回失败和损坏 capability 链，使用 ASan/UBSan 执行。真实 PCIe 复位、睡眠唤醒和长期收发需要加载新驱动后的实机验收；构建过程不会执行硬件复位。

## English

The embedded AirPort driver now retains a validated per-controller PCI configuration and restores lost configuration before its original D3-exit check. A secondary bus reset is allowed only for an isolated, single-function endpoint below a PCI bridge. Recovery is bounded, validates identity and resources, restores MSI before enabling bus mastering, and preserves failures. The initial cause of PCIe link loss remains unconfirmed. Hardware recovery and traffic require validation after loading the new kext.
