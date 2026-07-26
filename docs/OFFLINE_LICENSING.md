# AutoSec Guard 离线设备绑定许可证

客户包使用 Ed25519 签名许可证。客户程序只包含公钥；签发私钥只保留在供应商侧，绝不能提交到 Git、上传到 GitHub Actions Artifact，或交付给客户。

## 1. 首次生成签发密钥

项目当前存在一个匹配本次构建公钥的旧版明文私钥：

```text
private/license-issuer-private.pem
```

该目录已由 `.gitignore` 排除，但明文私钥不满足发行要求。首次签发前必须用至少 16 字符的口令迁移到离线加密保险库，然后安全删除工作区中的明文副本：

```bash
read -s AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD
export AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD
python3 server/license_cli.py protect-key \
  --input private/license-issuer-private.pem \
  --output /安全离线位置/autosec-license-issuer.pem
unset AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD
```

先用加密密钥试签并验证许可证，再删除明文源文件。遗失私钥后，已发布程序无法接受由新密钥签发的续期许可证，除非发布包含新公钥的新版本。

若需要轮换为自己的加密私钥，先设置口令，再重新生成：

```bash
read -s AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD  # 至少 16 个字符；禁止生成明文私钥
export AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD
python3 server/license_cli.py generate-keypair \
  --private-key /安全位置/autosec-license-issuer.pem \
  --public-module server/generated_license_public_key.py
unset AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD
```

重新生成公钥模块后，必须重新构建并交付客户程序。不要在已有客户仍需续期时随意覆盖旧公钥。

## 2. 获取客户设备码

客户启动交付包、创建或登录管理员账号后，会自动进入许可证激活页。点击“复制”取得类似下面的设备码：

```text
01234567-89ABCDEF-01234567-89ABCDEF-01234567-89ABCDEF-01234567-89ABCDEF
```

设备码由操作系统设备标识与 AutoSec 安装 ID 共同派生，不包含原始硬件标识。客户重装系统、删除整个 `AUTOSEC_DATA_DIR` 或更换设备后，需要重新签发。

## 3. 使用桌面签发器（推荐）

在供应商离线电脑运行：

```bash
python3 server/license_issuer_gui.py
```

界面中依次选择加密私钥、输入私钥口令和客户名称、粘贴设备码，再选择 1、3、6、12、24 或 36 个月即可生成许可证。口令在签发后立即从界面清空，不写入许可证或命令行。

如果希望签发电脑无需配置 Python，可以在该电脑上单独编译供应商工具：

```bash
python3 packaging/build_license_issuer.py
```

产物位于 `build/vendor-license-issuer/`。该工具和加密私钥仅供供应商内部使用，不能上传到客户 Release，也不能与客户包放在同一交付介质中。构建脚本不会把私钥嵌入签发器。

## 4. 使用命令行签发

```bash
python3 server/license_cli.py issue \
  --private-key /安全位置/autosec-license-issuer.pem \
  --customer "客户公司名称" \
  --machine-code "客户复制的设备码" \
  --months 1 \
  --output deliveries/customer-a-1m.autosec
```

签发 3 个月时将 `--months 1` 改为 `--months 3`。这里的“月”按自然月计算，例如 7 月 26 日签发 1 个月会在 8 月 26 日到期。

若私钥已加密，执行签发前通过环境变量输入口令：

```bash
read -s AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD
export AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD
# 执行 issue 命令
unset AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD
```

用于离线自动化时，推荐创建仅签发账号可读的口令文件，并只传文件路径：

```bash
chmod 600 /安全离线位置/issuer-password
export AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD_FILE=/安全离线位置/issuer-password
# 执行 issue 或客户验收命令
unset AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD_FILE
```

程序会拒绝在 POSIX 系统上读取组用户或其他用户可访问的口令文件。

还可以使用：

- `--days 30`：按固定天数授权；
- `--expires-at 2026-12-31T16:00:00Z`：指定 UTC 到期时间；
- `--features scan,poc_execution`：只授权部分功能；
- `--license-id LIC-CUSTOMER-001`：使用合同或订单中的授权编号。

## 5. 客户激活和续期

将生成的 `.autosec` 文件发送给对应客户。客户在激活页选择文件并点击“验证并激活许可证”。程序会验证：

1. Ed25519 签名是否正确；
2. 产品和许可证格式是否匹配；
3. 设备码是否与当前工作站一致；
4. 是否已生效、是否到期；
5. 系统时间是否出现明显回拨；
6. 当前操作所需功能是否包含在许可证中。

续期不需要重新打包。使用相同设备码重新执行 `issue`，签发更晚的到期时间，让客户导入新文件即可。

## 6. 开发与测试

源码模式默认显示 `development` 状态，不要求许可证。需要在源码模式验证真实授权流程时：

```bash
AUTOSEC_LICENSE_ENFORCEMENT=on AUTOSEC_DATA_DIR=/tmp/autosec-license-test python3 server/server.py
```

Nuitka 和 PyInstaller 客户包始终强制授权，设置环境变量无法关闭。完全离线环境无法做到实时撤销，也无法绝对防御拥有管理员权限的专业逆向人员；本实现提供签名防伪、设备绑定、关键后端边界校验和基础时间回拨检测。
