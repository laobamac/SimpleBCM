<!--
  Radio-Policy.md
  SimpleBCM

  Created by laobamac on 2026/11/7.
  Copyright © 2026 laobamac. All rights reserved.
-->

# CN 80 MHz 地区策略

1.2.1 修复 CN 修订号 **24、29、37、40、204、206、245、280** 在主信道 **36、40、44、48** 下缺少 80 MHz 有效功率记录的问题。无需增加启动参数。已测试用户反馈修复后问题消失；全部八条规则另经原始 CLM 函数离线验证。

驱动保留实际国家码、修订号和国家记录句柄。自有 AirPort 载荷注册之前安装常驻只读 CLM 表副本，只有八条目标国家记录指向追加的 locale。共享原 locale 的其他国家及修订号继续使用原数据。2.4 GHz、5 GHz 20/40 MHz、其他 80 MHz 信道和原生电源流程均保持原样。

缺失的中心信道 42 功率条目采用同一载荷 CN/242 中已有的速率分组，并逐项限制到所有配对原生 US 80 MHz 记录的共同保守上限；配对关系来自 aggregate 映射。不支持的速率保留原生不可用值。该过程不切换到 US 或 CN/242 的整套地区配置。CN/29 保留受限的速率集合；更保守的功率可能影响远距离性能。

原本支持该信道块的 CN/205、219、242、244、278、279 不修改。CN/3、7、12、16、22、23、225、227、229、231 不具有本次相同的显式禁用记录，保留其原有频段和带宽能力。

运行时核对载荷 SHA、CLM 格式、重定位、表校验和、范围及初始化状态，全部通过后替换两处表指针。数据由 SimpleBCM 常驻；唤醒重新初始化时由原始驱动读取相同策略。原驱动继续完成地区应用、逐速率功率计算、板卡校准和最终信道检查。

构建分别对原始／Tahoe 载荷执行 21,680 项信道与 12,544 项功率对照，要求除目标中心 42／80 MHz 外结果一致，并验证国家句柄、天线索引和错误输入下无部分写入。`Extra/Validation.json` 保存验证结果，`Extra/RadioPolicy.json` 保存规则来源及生成数据。

常规 `bcmprobe` 和 `collect.py` 会保留 `RadioPolicyVersion`、`RadioPolicyStatus`、`RadioPolicyScope`、`RadioPolicyRuleCount`、`RadioPolicyLocaleSHA256` 状态属性。没有额外国家映射或电源诊断 Hook。表已安装不代表当前 AP 一定协商 80 MHz，实际连接仍受硬件、AP 和信号条件影响。
