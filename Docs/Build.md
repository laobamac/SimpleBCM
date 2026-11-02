<!--
  Build.md
  SimpleBCM

  Created by laobamac on 2026/11/2.
  Copyright © 2026 laobamac. All rights reserved.
-->

# 构建与 CI

通用版的 ABI 配置在构建时从三个已核对系统的原生二进制生成。完整校验还会执行 Tahoe 的真实用户态消费者，因此需要运行 Tahoe 26.7.2 / 25G332 的 x86_64 Mac、完整 Xcode，以及 [Native-Universal.md](Native-Universal.md) 列出的三个参考系统。

## 参考文件

默认只检查当前系统、`/Volumes/Macintosh HD 1` 和 `/Volumes/Macintosh HD 2`，按实际版本号与构建号匹配系统。也可设置 `SIMPLEBCM_REFERENCE_ROOT`，使用以下目录布局；每个目录都需要相应系统的 `SystemVersion.plist` 和原始 `BootKernelExtensions.kc`：

```text
<SIMPLEBCM_REFERENCE_ROOT>/
  Sonoma/System/Library/CoreServices/SystemVersion.plist
  Sonoma/System/Library/KernelCollections/BootKernelExtensions.kc
  Sequoia/System/Library/CoreServices/SystemVersion.plist
  Sequoia/System/Library/KernelCollections/BootKernelExtensions.kc
  Tahoe/System/Library/CoreServices/SystemVersion.plist
  Tahoe/System/Library/KernelCollections/BootKernelExtensions.kc
```

生成前检查三套系统版本、Darwin 主版本和两个原生框架的 UUID；缺少文件或不匹配会终止。参考文件需自行准备，原生 KC 不纳入源码与发布包。

## 本地命令

```sh
python3 -B Tools/check.py
python3 -B Tools/system_profiles.py
python3 -B Tools/bootstrap.py
python3 -B Tools/build.py build --configuration Debug
python3 -B Tools/build.py build --configuration Release
python3 -B Tools/build.py analyze --configuration Release
python3 -B Tools/build.py package --configuration Debug --channel pre
python3 -B Tools/build.py package --configuration Release --channel pre
```

`check.py` 只使用 Python 标准库，可在 Linux 运行，不访问 Xcode 或 Apple 二进制。`bootstrap.py` 只准备固定提交的 MacKernelSDK 和 OCLP 载荷。完整构建调用同一个 Xcode 工程，验证三套原生 ABI、重定位、实际转发汇编及用户态编解码，宿主执行启用 ASan/UBSan；Release 另执行 Clang 静态分析。临时验证源码随执行自动清理。

打包要求 Debug/Release 各自的验证报告和 Release 静态分析都对应当前源码指纹；该指纹包含工作流。还会检查驱动、诊断工具、符号文件、配置片段和压缩包校验和。`--channel pre` 使用当前提交号命名 alpha 包，`--channel rel` 使用正式版本号。构建输出在 `build`，发布包在 `dist`，二者均忽略提交。

## GitHub Actions

- `Source checks`：push、pull request 和手动触发，在 GitHub 托管 Ubuntu runner 上运行 `Tools/check.py`。
- `Native Build and Publish`：push、正式 release 和手动触发，在带有 `self-hosted`、`macOS`、`X64`、`simplebcm-native` 标签的 runner 上运行。该 runner 必须满足上述宿主和参考文件条件；可用仓库变量 `SIMPLEBCM_REFERENCE_ROOT` 指定目录，也可使用默认挂载点。完整构建不运行 pull request 代码。
- push 在全部构建与校验通过后更新 alpha release；正式 release 的标签必须是 `1.2.0` 或 `v1.2.0`。手动触发只上传 Actions artifacts。
- 发布独立运行在 Ubuntu，只有发布任务获得 `contents: write`；构建任务只有读取权限。失败时上传构建日志，校验失败不会发布。

GitHub 托管的 `macos-26-intel` 不保证具有三个指定 KC 或相同的 Tahoe 用户态框架，因此不用于完整原生校验。请在仓库中注册带上述标签的 runner；源码检查可独立运行。

## English

Full builds require an Intel Mac running Tahoe 26.7.2 / 25G332, full Xcode, and all three audited native reference systems. Validation executes the host's real Tahoe userspace consumers as well as checking the Sonoma, Sequoia and Tahoe kernel collections. Run the commands above in order.

Set `SIMPLEBCM_REFERENCE_ROOT` to use the directory layout above, or leave it unset to inspect the current system and the two documented volume paths. All versions and native UUIDs are checked before generation. References are neither downloaded automatically nor included in packages.

Source checks run on hosted Ubuntu for pushes and pull requests. Full builds require a self-hosted runner labeled `macOS`, `X64`, `simplebcm-native`; configure the repository variable `SIMPLEBCM_REFERENCE_ROOT` if needed. Pull request code does not run on that runner. Pushes publish alpha packages only after validation, formal releases require a matching version tag, and manual runs only upload artifacts. Register the labeled runner in the repository settings before enabling full builds.
