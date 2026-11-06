<!--
  Build.md
  SimpleBCM

  Created by laobamac on 2026/11/2.
  Copyright © 2026 laobamac. All rights reserved.
-->

# 构建与 CI

构建需要 Intel Mac、完整 Xcode 和 Python 3。`Resources/NativeABI` 提供 Sonoma、Sequoia、Tahoe 的 ABI 参考数据，包含符号、虚表、布局指令和注册入口片段；普通构建不需要挂载其他系统盘。参考数据只用于生成和校验，不加入驱动载荷。

## 构建

```sh
python3 -B Tools/bootstrap.py
python3 -B Tools/check.py
python3 -B Tools/build.py build --configuration Debug
python3 -B Tools/build.py build --configuration Release
python3 -B Tools/build.py analyze --configuration Release
python3 -B Tools/build.py package --configuration Debug --channel pre
python3 -B Tools/build.py package --configuration Release --channel pre
```

`bootstrap.py` 获取固定提交的 MacKernelSDK 和 OCLP 驱动归档。构建通过参考数据核对原生导出和虚表，并在 ASan/UBSan 下执行重定位、转发和编解码检查；Release 另执行 Clang 静态分析。针对特定 Apple 私有函数布局的附加检查，只在宿主框架匹配时执行。

打包要求构建、校验和静态分析对应当前源码指纹。`--channel pre` 使用提交号命名 alpha 包，`--channel rel` 使用正式版本号。构建输出在 `build`，压缩包在 `dist`。

无线地区策略校验直接在用户态执行原始和 Tahoe 载荷中的 CLM 函数，检查 2,710 条国家记录、八个 CN 修订号及生产代码的安装边界。结果记入 `Validation.json`，生成规则记入 `RadioPolicy.json`；临时验证源码自动清理，不加入发布包。构建还检查生成的地区表确实进入 Kext。

## 更新 ABI 参考数据

维护适配配置时，可设置 `SIMPLEBCM_NATIVE_SOURCE=system` 直接读取原生内核集合。默认读取当前系统及 `/Volumes/Macintosh HD 1`、`/Volumes/Macintosh HD 2`，按实际版本与 UUID 匹配 [Native-Universal.md](Native-Universal.md) 中的参考系统。

自定义路径使用 `SIMPLEBCM_REFERENCE_ROOT`，每个系统目录需要原始 `SystemVersion.plist` 和 `BootKernelExtensions.kc`：

```text
<SIMPLEBCM_REFERENCE_ROOT>/<Sonoma|Sequoia|Tahoe>/System/Library/CoreServices/SystemVersion.plist
<SIMPLEBCM_REFERENCE_ROOT>/<Sonoma|Sequoia|Tahoe>/System/Library/KernelCollections/BootKernelExtensions.kc
```

```sh
SIMPLEBCM_NATIVE_SOURCE=system python3 -B Tools/build.py build --configuration Release
python3 -B Tools/native_references.py export
python3 -B Tools/native_references.py verify
```

导出工具从原始 KC 读取参考数据，检查注册入口在完整代码段中的唯一性，并更新文件校验和。运行时仍按大版本与实际 ABI 选择适配，不以参考构建号或 UUID 限制加载。

## GitHub Actions

- `Source checks` 使用 GitHub 托管的 `ubuntu-latest`，检查源码、版本、配置和参考数据校验和。
- `Native Build and Publish` 使用 GitHub 托管的 `macos-26-intel`，自动准备依赖，构建 Debug/Release、执行校验与静态分析并打包。无需自建 runner 或配置系统盘路径。
- push 在构建通过后更新 alpha release；正式 release 标签需匹配项目版本。pull request 和手动触发只上传 Actions artifacts。
- 发布任务使用 `ubuntu-latest`，只有该任务获得 `contents: write` 权限。

## English

Build with Python 3 and full Xcode on an Intel Mac. ABI references are included under `Resources/NativeABI`; no additional system volumes are required. Run the build commands above. Reference data is checked before generation and is not embedded in the driver.

GitHub Actions uses hosted `macos-26-intel` for builds and hosted `ubuntu-latest` for source checks and publishing. No self-hosted runner or custom volume setup is needed. Pushes publish alpha packages after validation; release tags must match the project version. Pull requests and manual runs only upload artifacts.

Maintainers can use `SIMPLEBCM_NATIVE_SOURCE=system` to validate directly against the original kernel collections, then run `Tools/native_references.py export` to refresh the committed references and checksums. `SIMPLEBCM_REFERENCE_ROOT` selects custom reference paths for that mode only.
