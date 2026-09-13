# shitty-minecraft-hwidban-mod

一个号称「目前 0 人成功破解」的 Minecraft 机器码封禁模组。

本仓库包含该模组**完整还原的客户端源码**与**按协议补齐的服务端实现**——破解它不需要攻破 Ed25519,只需要读懂它是怎么写的。

## 背景

原作者的悬赏帖:

![悬赏帖](images/01-bounty-300yuan.jpg)

作者解释为什么没人破解得了:

![作者解释](images/02-author-ed25519.jpg)

评论区:

![评论区](images/03-comments.jpg)

## 代码质量鉴赏

以下全部来自对原 jar 的反编译与语义还原,无一句虚构。

### 1. 密钥保护:用 XOR 保护非对称密码学

Ed25519 私钥被逐字节 `^ 0x5E` 混淆后硬编码进客户端 jar。作者说得对,你要破解的确实是 Ed25519 非对称签名——不过在碰到 Ed25519 之前,先碰到了一个常数 94。

更妙的是「每个 jar 硬编码不同密钥」这个设计:客户端要签名,私钥就必须在客户端手里。于是每一份付费用户的 jar 里都躺着一把完整私钥,唯一的区别是它被 `^ 94` 化了妆。吊销公钥确实能让一个包报废——顺便也让「非对称签名」的存在意义报废了。

### 2. 信任模型:客户端说什么就是什么

`nameMatch`(用户名是否匹配)和 `isVM`(是否虚拟机)都由**客户端自己计算**,然后连同一份签名发给服务器。签名只能证明「这个 jar 声称了这些字段」,不能证明字段是真的。想上报 `isVM=false`?Mixin 在 `dofuw()Z` 的 HEAD 设个返回值就行,我们就是这么干的。

### 3. 协议:同一个字段,两种宽度

编解码器编码端 `writeVarInt(protoVer)`,解码端 `readInt()`。同一份 CODEC 里,varint 写入、定宽读出。好在解码分支在客户端是死代码,所以这个 bug 从发布至今从未被发现——直到有人为了写 README 把它反编译了一遍。

### 4. 性能:每次进服 fork 一堆 PowerShell

设备指纹的原料(MAC / CPU / 主板 / BIOS)靠 `powershell -NoProfile -Command Get-CimInstance ...` 获取,算一次指纹最多 4 次 WMI 查询;VM 检测**没有缓存**,每次进服重新跑,再 fork 2~3 个 PowerShell。一个 Minecraft mod,运行时的主要 I/O 是启动 PowerShell。

### 5. 指纹原料的质量

- MAC 地址:一句话就能改
- `PROCESSOR_IDENTIFIER`:环境变量,也能改
- 主板/BIOS 序列号:大量整机出厂就是 `Default string`
- 查询失败:统一返回 `"unknown"`,继续参与哈希——同款精简系统/沙箱环境指纹直接撞车

最终指纹 = `SHA256(...)` 截前 32 位。哈希函数没问题,问题在于喂给它的东西没有一样是 trustworthy 的。

### 6. VM 检测:字符串 grep 大师

四组启发式,本质是在各种字符串里找 `vmware|vbox|qemu|hyper-v|...`,外加 12 个网卡 OUI 前缀和一个注册表键值。改一个注册表值即绕过;反过来,主板 DMI 里恰好带 `Virtual` 字样的真机会被当场认定为虚拟机。

### 7. 异常处理:沉默是金

客户端共 12 处 `catch (Exception) {}`,全部静默吞掉。认证失败时统一回复一个**空包**,服务器无法区分「客户端拒绝认证」和「客户端炸了」。安全告警用 `System.err.println` 输出——一个引入了 slf4j 的项目。

## 这个仓库包含什么

| 模块 | 说明 |
|------|------|
| `authcredential-client` | 客户端模组,按原 jar 语义逐方法还原(类名/方法名保留混淆名,便于 Mixin 注入) |
| `authcredential-server` | 服务端验证模组,按协议行为补齐:登录下发挑战、验签、激活记录、进世上报 |
| `keygen` | 构建期密钥嵌入工具,从 `embed/keys.properties` 生成 XOR 混淆的 `ServerBindingConfig` |

## 构建

```bash
./gradlew build
```

产物:

- `authcredential-client/build/libs/authcredential-client-1.0.0.jar`
- `authcredential-server/build/libs/authcredential-server-1.0.0.jar`

## 免责声明

本项目仅用于学习、研究与安全分析。请勿用于绕过任何服务器的访问控制——虽然事实证明这不是技术问题,是阅读理解问题。
