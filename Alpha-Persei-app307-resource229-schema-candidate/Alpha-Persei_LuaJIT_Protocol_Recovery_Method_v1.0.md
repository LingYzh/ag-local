# Alpha Persei LuaJIT 协议描述恢复方法

版本 1.0 · 2026 年 10 月 11 日

## 1 这份方法解决什么问题

本次恢复的目标，是从客户端 `scripts64` 资源中提取协议描述，生成 Alpha Persei 加载器需要的 `lua_proto_messages.json`。实际采用的链路是：

```text
客户端资源索引
  → 定位并校验 scripts64 资源文件
  → UnityFS 解包
  → SerializedFile 中的 TextAsset 提取
  → LuaJIT 字节码格式解析
  → 受限静态声明分析
  → 带来源的协议描述
  → 处理同名类型和服务器兼容别名
  → JSON 与独立校验
```

关键区别如下。

- **提取**：从容器取出原始 TextAsset 字节，不修改 LuaJIT 字节码
- **反汇编**：把指令字、常量和寄存器操作解读为可检查的数据
- **完整反编译**：重建可读 Lua 源码、控制流和函数行为。本次没有做这一步
- **协议描述恢复**：只分析协议文件中的构造器与赋值声明，恢复消息、字段和引用关系
- **JSON 适配**：把这些描述转换成 Alpha 的索引格式。这一层含有名称消歧和明确记录的兼容处理

因此，本方法不承诺恢复完整游戏源码、解密任意资源包，或让任意版本的客户端与服务器兼容。对这次样本，协议声明足够规整，可以在**不执行游戏 Lua、不启动游戏和服务端、不安装第三方提取器**的条件下完成恢复。

### 本文与附件

正文解释证据链、格式、算法、复现步骤和失效条件。配套 `Alpha-Persei_LuaJIT_Protocol_Recovery_Scripts_v1.0.zip` 保存实际使用过的六个分析脚本、历史校验报告和文件指纹；不包含客户端资源、游戏字节码、公共 Lua 源码或可执行安装程序。

四个核心提取与恢复脚本保持原样。两个复核脚本仅把公共 Lua 输入位置改为相对路径 `public-protocol/protocol`，解析逻辑不变；原版和附件版 SHA-256 见 `script-manifest.json`。

这些是**针对已验证历史样本的分析脚本**，不是经过完整加固的通用解析器。先读第 11 节，再运行第 9 节。不要直接对当前游戏安装目录操作，也不要在已交付候选文件所在目录重跑。

## 2 固定样本和验收基线

### 2.1 实际分析过的输入

| 项目 | 已确认值 |
|---|---|
| 样本身份 | app 307 / resource 229，历史 v5.2.1 资源样本 |
| 原资源逻辑名 | `scripts64` |
| 第一段长度 | 18,874,368 字节 |
| 第二段长度 | 16,916,566 字节 |
| 拼接总长度 | 35,790,934 字节 |
| 完整原文件 MD5 | `86add1e9d150efa2464ec96f0579a0b9` |
| 完整原文件 SHA-256 | `f1501ccee59271f6e47fe3eb945111dbef252985110b2d34f65f96583611d485` |
| 外层前缀 | 恰好 10 个 `00` 字节 |
| 容器 | UnityFS，格式版本 8 |
| Unity 标识 | `5.x.x` / `2022.3.62f3c1` |
| 内部序列化文件 | `CAB-win64`，SerializedFile 版本 22 |
| LuaJIT 头 | `1b 4c 4a 02 0a` |

本次先按 part01、part02 顺序拼接，再对完整文件计算摘要。不能把任意一段的 MD5 与资源索引中的完整文件 MD5 比较，也不能把两段当成两个独立 UnityFS 包。

**版本边界**：用户后来已恢复正常的 5.3.1 客户端；本文的恢复结果仍属于上表中的 resource 229。此前另有一份 app 307 / buildCode 321 / v5.3.1 索引，其中 `scripts64` 条目为 MD5 `f9468cd00564c3c98e4f819210760be1`、35,812,429 字节。这只是另一份索引的记录，不是本文已解包验证的输入，也不能据此认定用户现在磁盘上的文件仍是该条目。以后处理 5.3.1 或其他版本，必须重新取得实际索引与资源文件并核对。

### 2.2 恢复结果的三个计数层次

| 层次 | 消息或资产数量 | 字段数量 | 含义 |
|---|---:|---:|---|
| 容器提取 | 10,267 个 TextAsset | 不适用 | 该包中的资产，均识别为 LuaJIT 字节码 |
| 协议源定义 | 92 个文件，3,061 个消息描述 | 6,889 | 来自客户端协议声明 |
| Alpha 候选 JSON | 3,062 个消息键 | 6,892 | 3,061 个定义，加一个三字段兼容别名 |

补充验收值：

- 1,368 个消息类型字段引用，未解析引用为 0
- 53 组跨模块同名类型，合计 124 个定义，均保留模块身份
- 名称归一化后的索引冲突为 0，`cs_` 和 `sc_` 包名没有改动
- 92 个协议字节码文件均为单一原型，数值常量池数量为 0
- 与固定公开 Lua 源逐项比较：3,061 个源定义全部一致，差异为 0
- 最终 JSON 为 1,310,683 字节，SHA-256 为 `b9101c965ed4f75317aa9c0199e17e5a7d2c3e0c0e23b982217a960b1a6ee79f`

这些数字是该样本的回归基线，不是新版本应当被“修到”的目标数字。

## 3 从资源索引定位文件

### 3.1 索引中的逻辑名称与物理文件名

本次所见索引为 JSON，`assetHashList` 的条目采用：

```text
逻辑路径或逻辑名称|MD5|文件字节数
```

先找逻辑名为 `scripts64` 的条目，再用其 MD5 定位资源。已确认的 Windows 缓存布局使用 MD5 前两个字符作为两级目录。因此，这次 MD5 对应的相对位置为：

```text
Windows/8/6/86add1e9d150efa2464ec96f0579a0b9.ys
```

这里的 `Windows` 是资源树中的目录名，不代表 Windows 系统目录。文件扩展名 `.ys` 不足以判断内容；应检查文件头、索引摘要和长度。若新版目录结构改变，先查新版索引与实际目录，不要强行沿用此路径规则。

### 3.2 Windows 只读定位示例

下面的 PowerShell 只读取用户指定的索引与资源文件，不修改游戏、网络、证书或系统设置。输入的资源目录应当是实际包含分片目录的 `Windows` 文件夹。

```powershell
$IndexPath = Read-Host "输入实际资源索引文件的完整路径"
$WindowsRoot = Read-Host "输入资源树中 Windows 文件夹的完整路径"
$index = Get-Content -Raw -LiteralPath $IndexPath | ConvertFrom-Json
$rows = @($index.assetHashList | Where-Object {
    ($_ -split '\|')[0] -eq 'scripts64'
})
if ($rows.Count -ne 1) { throw "scripts64 条目不是唯一一个，先检查索引" }
$parts = $rows[0] -split '\|'
if ($parts.Count -ne 3) { throw "条目格式不是 名称|MD5|大小" }
$md5 = $parts[1].ToLowerInvariant()
if ($md5 -notmatch '^[0-9a-f]{32}$') { throw "MD5 格式不正确" }
$expectedBytes = [Int64]$parts[2]
$relative = "$($md5[0])\$($md5[1])\$md5.ys"
$file = Join-Path $WindowsRoot $relative
$item = Get-Item -LiteralPath $file
$actualMD5 = (Get-FileHash -LiteralPath $file -Algorithm MD5).Hash.ToLowerInvariant()
if ($item.Length -ne $expectedBytes -or $actualMD5 -ne $md5) {
    throw "资源长度或 MD5 不匹配，停止分析"
}
[pscustomobject]@{
    AppVersion = $index.appVersion
    BuildCode = $index.buildCode
    VersionName = $index.versionName
    File = $item.FullName
    Bytes = $item.Length
    MD5 = $actualMD5
    SHA256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
}
```

若索引不存在、存在多个 `scripts64` 条目，或资源文件长度不符，应保留现场并重新确认来源。MD5 在这里用于核对索引身份和传输完整性，不提供来源签名；另外保存 SHA-256 和文件获取记录。

## 4 UnityFS 解包

### 4.1 先识别封装再解释偏移

样本最前面的 10 个字节全部是 `00`，紧随其后的是以 NUL 终止的 `UnityFS` 签名。脚本在确认这 10 个字节之后，以 `raw[10:]` 作为 UnityFS 视图。它没有修改原文件。

**不能把“删除前 10 字节”当成通用修复方法。** 这是本样本的已验证封装。未知前缀应重新分析；本文没有证明这 10 个字节的业务用途，也没有使用密钥或执行解密。

下表的相对偏移以 `UnityFS` 的 `U` 为 0；原文件绝对偏移等于相对偏移加 10。头部整数使用大端序。

| 相对偏移 | 长度 | 内容 |
|---:|---:|---|
| 0 | 8 | `UnityFS` 加终止字节 |
| 8 | 4 | 容器版本 8 |
| 12 | 6 | `5.x.x` 加终止字节 |
| 18 | 14 | `2022.3.62f3c1` 加终止字节 |
| 32 | 8 | UnityFS 部分总长度 35,790,924 |
| 40 | 4 | 压缩块表长度 39 |
| 44 | 4 | 解压块表长度 64 |
| 48 | 4 | 标志 `0x243` |
| 52 至 63 | 12 | 对齐填充 |
| 64 | 39 | 压缩块表 |
| 103 至 111 | 9 | 数据前对齐填充 |
| 112 | 35,790,812 | 压缩数据块 |

最后一行在原文件中的起点是 122。35,790,924 与完整原文件 35,790,934 相差 10，原因就是外层前缀。

### 4.2 块表与压缩

块表解压后先读取 16 字节的头部摘要区域，再读取块数、块记录、目录数和目录记录。本样本只有一个数据块和一个目录条目：

| 项目 | 实际值 |
|---|---|
| 容器标志 | `0x243` |
| 块表压缩类型 | 低 6 位为 3，对应 LZ4HC 数据格式 |
| 其他已用标志 | `0x40` 组合块与目录信息，`0x200` 数据前对齐 |
| 数据块标志 | `0x41`，低 6 位为 1，使用 LZMA |
| 数据块压缩长度 | 35,790,812 字节 |
| 数据块解压长度 | 498,799,864 字节 |
| 目录记录 | 偏移 0，长度 498,799,864，标志 4，名称 `CAB-win64` |

本次解压组合比较容易被误判：**块表是 LZ4，数据本体是 LZMA**。不能只看容器标志就用同一种算法解压所有部分。

脚本使用 Linux 环境中已有的 `liblz4`，通过 `ctypes` 调用 `LZ4_decompress_safe`，把 39 字节块表还原成 64 字节；数据块由 Python 标准库 `lzma` 按 RAW LZMA1 解压。数据块的前五字节是 `5d 00 00 08 00`，包含属性字节和小端字典大小。由属性字节解析 `lc`、`lp`、`pb` 后，传入 LZMA1 filter，而不是把它作为普通 `.xz` 文件打开。

提取出的 `CAB-win64` SHA-256 是：

```text
8e67989989547b4497a42a05ef910c432c858f2fdd4d145aabb7c7e9fd11c712
```

Unity 官方说明了 AssetBundle 的 LZMA 与 LZ4 压缩方式；二进制布局的本次实现还参考了 UnityPy 自身的容器解析源码，并用上述样本字节和长度校验。[Unity 压缩说明](https://docs.unity3d.com/2022.3/Documentation/Manual/AssetBundles-Cache.html) · [UnityPy BundleFile 实现](https://github.com/K0lb3/UnityPy/blob/master/UnityPy/files/BundleFile.py)

**实现边界**：现有脚本按这个前置块表布局读取，没有完整支持 `flags & 0x80` 所表示的尾部块表布局。虽然代码中提供若干压缩分支，也不能据此声称其他封装和标志组合经过验证。

## 5 从 SerializedFile 提取 TextAsset

`CAB-win64` 不是 Lua 文件，而是 Unity 的序列化对象容器。现有 `extract-static-textassets.py` 依次读取：

1. 基本头部和版本 22 的扩展头部
2. 字节序标记、Unity 版本、构建目标、TypeTree 标记和类型列表
3. 对象表中的 path ID、数据偏移、对象长度和类型索引
4. class ID 142 的 AssetBundle 对象，建立 path ID 到资源路径的映射
5. class ID 49 的 TextAsset 对象，读取名称、有效载荷长度及原始字节

本样本基本头部的部分旧式长度字段为 0，实际长度应取版本 22 的扩展头部。已核对的值是：metadata size 248,929，file size 498,799,864，data offset 248,992。头部按规定读取后，再依据 endian 标记切换到小端的主体数据，不能把整个文件统一当作小端或大端。

实际有 10,268 个对象：10,267 个 TextAsset 和 1 个 AssetBundle。TypeTree 存在；脚本跳过其节点和字符串缓冲区，使用本样本已知的两个对象结构提取内容。它不是能处理所有 Unity 类的反序列化库。[SerializedFile 参考实现](https://github.com/K0lb3/UnityPy/blob/master/UnityPy/files/SerializedFile.py)

TextAsset 载荷总计 496,940,267 字节，均以 LuaJIT 签名开头。输出有两类辅助证据：

- `asset-paths.json`：对象 path ID 与容器路径的映射
- `textassets-manifest.json`：每个 TextAsset 的 ID、名称、路径、长度、内容分类和 SHA-256

协议子集位于：

```text
static-bundle-extracted/textassets/assets/luabuilds/luajit2.0/x64/protocol/
```

其中有 92 个 `.lua.bytes` 文件。后缀含有 `lua`，不代表内容是文本；目录名含有 `luajit2.0`，也不决定真实的 dump 版本。

## 6 根据文件头解析 LuaJIT

### 6.1 以实际签名判断版本

本样本协议文件头为 `1b 4c 4a 02`，对应 LuaJIT dump version 2，随后读取的 flags 为十进制 10，即 `0x0a`：

- `0x02`：STRIP，调试信息已剥离
- `0x08`：FR2，使用双槽帧约定
- BE 位未设置，因此指令字按小端读取
- FFI 位未设置

版本、标志和各字段含义按 LuaJIT 自身的 dump 定义核对；不能因为目录名而套用 dump v1 的格式或旧 opcode 表。[LuaJIT dump 定义](https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/lj_bcdump.h)

### 6.2 读取顺序

`parse-static-luajit.py` 读取 ULEB128 编码的原型长度，再读取原型 flags、参数数、frame size、upvalue 数、GC 常量数、数值常量数和字节码条数。随后按声明数量读取指令、upvalue 数据和常量池，并检查原型结束位置；最后还必须读到 dump 的零长度终止标记和文件末尾。

GC 常量在 dump 中的读取顺序与本分析器按指令索引访问的顺序相反，因此原脚本使用 `k[::-1]`。若漏掉这一点，消息名、字段名与被引用对象可能全部错位。独立复核器用另一种实现方式，在读取时向列表头部插入常量，验证了相同结果。[LuaJIT 字节码读取实现](https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/lj_bcread.c)

每条指令为 32 位，分析器从同一个字中提取：

```python
opcode = word & 0xff
A = (word >> 8) & 0xff
C = (word >> 16) & 0xff
B = (word >> 24) & 0xff
D = word >> 16
```

具体指令使用 ABC 或 AD 形式，不能把 D 当成独立于 B、C 的额外字段。opcode 次序需要与相应 LuaJIT 定义一致。[LuaJIT opcode 定义](https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/lj_bc.h)

### 6.3 本次范围为何可控

92 个协议文件全部只有一个原型，协议恢复实际只涉及 13 种 opcode：

```text
GGET KSTR CALL TGETS TNEW TSETS GSET
KSHORT KPRI TSETB RET1 TGETV TSETV
```

没有需要恢复的分支或循环，也没有数值常量池条目。虽然格式读取器包含部分其他常量类型的读取代码，**并不表示协议恢复器支持这些结构或任意 LuaJIT 程序**。多原型、未知标志、未知指令和新出现的声明模式必须进入人工复核，不应跳过继续生成。

## 7 用受限静态分析还原描述

### 7.1 分析的是声明状态

`recover-static-descriptors.py` 自行维护三个数据结构：寄存器表、模块全局表、带来源的节点。来源记录包含模块名和指令位置。它顺序读取指令，把常量写入寄存器，把 table 读写变为 Python 数据操作。

遇到 `CALL` 时，脚本没有调用目标函数。它只识别如下明确的声明词汇：

| 字节码中的调用目标 | 静态分析器的处理 |
|---|---|
| `require("...")` | 创建模块符号，不加载 Lua 模块 |
| `module(..., package.seeall)` | 核对模块声明 |
| `protobuf.Descriptor()` | 创建消息描述节点 |
| `protobuf.FieldDescriptor()` | 创建字段描述节点 |
| `protobuf.Message(descriptor)` | 记录消息符号，不建立运行时消息类 |

其他调用目标直接报错。`runpy` 只载入随附的自有 Python 格式读取器，输入的 `.bytes` 文件从未交给 Lua VM、`eval` 或 `exec`。

FR2 模式下，现有分析器从 `A+2` 开始读取 CALL 的参数槽，而不是直接从 `A+1` 开始。这里的偏移来自所验证的调用帧约定；若按错误模式取参，可能把函数或参数引用解析错。

### 7.2 必须保留哪些字段

Alpha 所需的输出字段为：

```json
{
  "name": "result",
  "number": 1,
  "type": "uint32",
  "label": "required",
  "ref": null
}
```

消息类型字段的 `ref` 由实际描述对象或跨模块符号解析，不根据变量名大小写猜测目标。类型编号和 label 编号按 protobuf 的 `FieldDescriptorProto` 定义映射；例如 type 11 是 message，type 13 是 uint32，label 1、2、3 分别是 optional、required、repeated。[protobuf 官方定义](https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/descriptor.proto)

整数类型也必须保真。例如本样本的 `sc_10039.user_id` 是字段 5、`uint64`，不能因为相邻字段多为 `uint32` 就统一改写。

原始来源报告还保留 `source_module`、消息 `full_name`，以及嵌套引用的 `ref_module`。因此可以在输出名称发生消歧之后，仍然追溯到原始模块和目标。

这一 JSON 是 Alpha 的简化描述格式。它不等于完整 `.proto` 文件，也未承诺表达所有 protobuf 特性。原描述对象的 default、扩展、枚举、选项等元数据不能简单据此视为完整保留。该样本没有 enum 字段；现有恢复器遇到 enum 会明确报错。未来版本出现更多语义时，应先确认目标加载器的数据模型是否能表达，再扩展映射与测试。

### 7.3 保证不悄悄漏字段

原恢复与独立复核组合检查了：

- 消息 fields 表索引连续，字段 `index` 与顺序一致
- 一个消息内的字段名称和编号没有重复
- 已构造的字段节点都被实际消息使用，且没有被重复计入
- 每个消息引用均能解析到描述对象
- 输出消息索引唯一，消息引用闭合
- 独立复核还检查字段编号合法范围和 protobuf 保留区间

如果某一步出现无法解释的符号、缺失模块、未知目标或解析位置不吻合，停止并保留报错、模块、指令位置和输入 SHA-256。不要为了凑出 JSON 而把未知字段默认成 `uint32`、把引用置空或忽略异常。

## 8 同名类型和 Alpha 兼容层

### 8.1 同名类型不能直接合并

源协议存在 53 组跨模块同名类型，覆盖 124 个定义。即使某一组的字段暂时相同，也不意味着模块身份可以永久丢弃；部分同名定义本来就不同。

输出规则是：短名称唯一时保持原名；出现冲突时使用 `模块.短名称`，并从原始对象关系同步改写 `ref`。例如保留独立的 `p13_pb.equip_list` 与 `p14_pb.equip_list`。对于唯一的 `cs_数字` 和 `sc_数字` 消息，原名称不变。

这是 JSON 索引命名处理，不改变 protobuf 字段编号或线上 payload 的编码。实际服务器加载器如何归一化名称，仍须以对应版本的 `decode_schema.py` 为准；本次还检查了 trim、去前导点和转小写后的索引无冲突。[本次核对的 Alpha 加载器](https://github.com/Mint-ARK/Alpha-Persei-Cluster/blob/83c03f1d75004ecb9f0ac1484676f6b5181dfa4e/v5_server/decode_schema.py)

### 8.2 唯一额外别名

基础恢复输出是 3,061 条。针对本次检查过的 Alpha `codec.py`，其舞蹈相关补丁仍使用裸名 `crickets_round_score_net_rec`，因此另加一个同名兼容入口，字段深拷贝自 `p58_pb.crickets_round_score_net_rec`：

| 字段 | 编号 | 类型 | 标签 |
|---|---:|---|---|
| peculiarity_score | 1 | uint32 | required |
| skill_score | 2 | int32 | required |
| sum_score | 3 | uint32 | required |

它是加载器侧兼容层，不是新发现的第 3,062 个客户端定义；也不是可以给所有冲突类型补裸名的理由。[Alpha 兼容补丁依据](https://github.com/Mint-ARK/Alpha-Persei-Cluster/blob/83c03f1d75004ecb9f0ac1484676f6b5181dfa4e/v5_server/codec.py#L94-L105)

**重跑风险**：`recover-static-descriptors.py` 本身不添加这个别名。直接重跑会覆盖输出目录里的候选 JSON，重新变成 3,061 条。必须在新的工作目录中复现，再明确执行第 9.5 节的别名步骤。

## 9 在独立目录复现历史样本

### 9.1 环境和附件布局

原分析发生在 Linux 云端，Python 3.12，系统已经有 `liblz4.so.1`。没有安装 UnityPy、LuaJIT、反编译器或额外软件。

本文的 shell 复现命令面向已有 Python 与 liblz4 的 Linux 环境。脚本使用 `str.removesuffix`，因此至少需要 Python 3.9；实际重放验证版本是 3.12。**这些脚本没有经过原生 Windows 适配验证**，不能直接承诺在 Windows 上 `python script.py` 即可运行。Windows 用户可先用第 3 节采集文件，再在已有的分析环境中处理；也可以自行选择已配置好的 WSL/Linux。本文不要求安装 WSL 或任何新软件。

解压脚本附件到一个新目录，并在该目录执行命令。必要布局为：

```text
复现工作目录/
  extract-static-unity.py
  extract-static-textassets.py
  parse-static-luajit.py
  recover-static-descriptors.py
  compare-public-descriptors.py
  script-parts/
    scripts64.part01.bin
    scripts64.part02.bin
  schema-audit/
    independent_audit.py
  baseline/
    历史只读校验报告
```

输入的两段文件需要自行放入 `script-parts`。如果保留的是完整 `.ys` 文件，可将其**副本**命名为 `scripts64.assembled.bin`，直接核对第 2 节长度和摘要，跳过拼接。不要修改或移动游戏正在使用的资源。

依赖自检如下；失败就停下来，不需要为了运行本文而自动安装软件：

```bash
python3 -B - <<'PY'
import sys, ctypes, ctypes.util, lzma
assert sys.flags.optimize == 0, "禁止 -O 或 PYTHONOPTIMIZE；会关闭脚本断言"
name = ctypes.util.find_library('lz4')
assert name, "当前环境没有可定位的 liblz4"
lib = ctypes.CDLL(name)
assert hasattr(lib, 'LZ4_decompress_safe')
print(sys.version)
print("LZ4:", name)
PY
```

### 9.2 拼接并锁定输入身份

以下是把原来临时拼接操作整理成的可复现命令，不是声称原先存在另一个同名脚本。它只适用于本次两个分段，目标文件已存在时会拒绝覆盖。

```bash
python3 -B - <<'PY'
from pathlib import Path
import hashlib
parts = [Path('script-parts/scripts64.part01.bin'),
         Path('script-parts/scripts64.part02.bin')]
assert [p.stat().st_size for p in parts] == [18874368, 16916566]
data = b''.join(p.read_bytes() for p in parts)
assert len(data) == 35790934
assert hashlib.md5(data).hexdigest() == '86add1e9d150efa2464ec96f0579a0b9'
assert hashlib.sha256(data).hexdigest() == 'f1501ccee59271f6e47fe3eb945111dbef252985110b2d34f65f96583611d485'
with Path('scripts64.assembled.bin').open('xb') as f:
    f.write(data)
print('历史输入校验通过')
PY
```

### 9.3 依次执行核心分析

以下命令对应附件中真实存在的脚本。它们没有 `--input`、`--output` 等命令行接口，使用固定相对布局。尤其 `parse-static-luajit.py` 依赖当前工作目录；应在附件根目录运行。

```bash
set -e
python3 -B extract-static-unity.py > unityfs-extraction-log.txt
python3 -B extract-static-textassets.py > static-textassets-log.txt
python3 -B parse-static-luajit.py > luajit-parse-log.txt
python3 -B recover-static-descriptors.py > recovered-descriptors-log.txt
```

每步失败都应停止。输出依次包括：

1. `static-bundle-extracted/CAB-win64`
2. `textassets` 目录、路径映射和 TextAsset 清单
3. opcode 统计及 `p10-static-disassembly.json`
4. `recovered-protocol/raw-descriptors-with-provenance.json`、基础 `lua_proto_messages.json` 和基础 `extraction-validation.json`

第四步此时应为 3,061 个消息、6,889 个字段。历史交付版的 `extraction-validation.json` 还追加过输入信息、兼容层和候选摘要，所以不能要求这份新生成的基础报告与历史报告逐字节相同。

### 9.4 可选的公开源码交叉比较

需要准备下面固定提交中的 92 个 `protocol/*.lua` 文件，将其放入 `public-protocol/protocol`。可以通过可信 GitHub 来源获取文本；不需要安装或执行该仓库的任何代码。

[固定公开协议目录](https://github.com/PackageInstaller/DataTable/tree/83b4bf07a62a73b05e74c22f1c47e59ae0983ae2/MasterData/Lua/x64/protocol)

固定提交：`83b4bf07a62a73b05e74c22f1c47e59ae0983ae2`。附件的 `baseline/public-source-inventory.json` 保存各文件路径和 Git blob SHA。该清单最初生成时的 `version_match` 字段是 `Unverified`；后续描述逐项比较结果见 `public-comparison.json`，不能把早期清单字段单独当作最终结论。

```bash
python3 -B compare-public-descriptors.py
python3 -B - <<'PY'
from pathlib import Path
import hashlib, json
inventory = json.loads(Path('baseline/public-source-inventory.json').read_text())
assert inventory['commit'] == '83b4bf07a62a73b05e74c22f1c47e59ae0983ae2'
assert len(inventory['files']) == 92
exact = extra_lf = 0
for record in inventory['files']:
    data = (Path('public-protocol') / record['path']).read_bytes()
    def git_blob(content):
        return hashlib.sha1(b'blob ' + str(len(content)).encode()
                            + b'\0' + content).hexdigest()
    if git_blob(data) != record['blob_sha']:
        # 历史文本获取曾额外添加末尾换行；仅接受去掉一个后完全匹配。
        assert data.endswith(b'\n') and git_blob(data[:-1]) == record['blob_sha']
        extra_lf += 1
    else:
        exact += 1
r = json.loads(Path('recovered-protocol/public-comparison.json').read_text())
assert (r['actual_records'], r['public_records'], r['same_records']) == (3061, 3061, 3061)
assert r['changed_records'] == 0 and not r['actual_only'] and not r['public_only']
assert not r['differences']
print('92 个公开源 blob 与全部描述比较通过', '原字节匹配', exact,
      '仅多一个末尾 LF', extra_lf)
PY
```

比较器只读取 Lua 文本中的特定赋值语句，使用字面量解析和正则提取，**不执行 Lua**。它不是完整 Lua 语法解析器；文件格式变化应视为需要复核，不能自动忽略匹配失败。

原比较脚本发现差异后仍可能以退出码 0 结束，报告中的 commit 字段也是固定文字。因此上面的额外检查同时验证输入 blob 和报告内容；不能把“脚本没有报错”当成比较通过。

比较键是 `(source_module, name)`。比较项包含消息名、完整名、字段顺序、字段名、编号、类型、label，以及消息引用的目标模块和名称。预期为 actual 3,061、public 3,061、same 3,061、changed 0，且两侧独有项均为空。

公开源码只是独立交叉证据，输入客户端字节码仍是本次恢复的依据。描述一致不意味着整个公开仓库、客户端和服务器构建完全相同。

### 9.5 加入已核实的兼容别名

仅在复现本次历史候选、且基础输出检查通过时执行。代码先检查数量、别名不存在、目标字段形状，再对最终序列化字节核对已交付 SHA-256，最后才写回新工作目录中的 JSON。

```bash
python3 -B - <<'PY'
from pathlib import Path
import copy, hashlib, json
p = Path('recovered-protocol/lua_proto_messages.json')
d = json.loads(p.read_text(encoding='utf-8'))
messages = d['messages']
assert len(messages) == 3061
assert sum(len(m['fields']) for m in messages) == 6889
index = {m['name']: m for m in messages}
assert len(index) == len(messages)
assert 'crickets_round_score_net_rec' not in index
alias = copy.deepcopy(index['p58_pb.crickets_round_score_net_rec'])
assert [(f['name'], f['number'], f['type'], f['label'], f['ref'])
        for f in alias['fields']] == [
    ('peculiarity_score', 1, 'uint32', 'required', None),
    ('skill_score', 2, 'int32', 'required', None),
    ('sum_score', 3, 'uint32', 'required', None),
]
alias['name'] = 'crickets_round_score_net_rec'
messages.append(alias)
messages.sort(key=lambda m: m['name'])
data = (json.dumps(d, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
expected = 'b9101c965ed4f75317aa9c0199e17e5a7d2c3e0c0e23b982217a960b1a6ee79f'
assert hashlib.sha256(data).hexdigest() == expected
p.write_bytes(data)
print(len(messages), sum(len(m['fields']) for m in messages), expected)
PY
```

这里使用 UTF-8 和 LF；若自行用其他编辑器重排 JSON 或改为不同换行，字节摘要会改变，即使解析后的数据相同。复现历史候选时应保留规定的序列化形式；新版本则应生成自己的新摘要，不能强求与本例一致。

### 9.6 独立复核入口

附件中的 `schema-audit/independent_audit.py` 没有导入核心提取器。它重新解析协议字节码，并从 LuaJIT 官方 opcode 表和 protobuf 官方枚举文本读取编号映射，检查结果与原始描述、最终 JSON 一致。

运行前还需要准备：

```text
schema-audit/source/src/lj_bc.h
schema-audit/source/src/google/protobuf/descriptor.proto
public-protocol/protocol/*.lua
```

这些参考文件不在脚本附件内。`lj_bc.h` 来自 LuaJIT `v2.1` 分支；`descriptor.proto` 来自 protobuf 官方源码，原审计保存的是包含 Type 和 Label 枚举的片段，不是完整 proto 文件。附件的 `reference-inputs.json` 记录已保存参考文本的 SHA-256 和来源说明。分支链接会变化；若要重现原审计环境，必须核对文本快照或重新审核新的映射，不能把浮动分支冒充固定提交。

```bash
python3 -B schema-audit/independent_audit.py
```

当前执行生成 `schema-audit/independent-validation.json`；附件 `baseline/validation-review.json` 是保存的历史报告副本，不能混作本次运行新生成的结果。

该审计脚本针对这份历史最终候选，预期唯一额外名称就是上述兼容别名。它还校验公开 `p10_pb.lua` 的 Git blob；原本的文本获取过程多附加过一个末尾换行，审计代码仅为此处理了已知的一字节差异。它不允许任意修改公开文本后继续宣称源文件一致。

本文整理时，另在独立目录逐项执行了上述 Linux 静态流程，并验证全部 TextAsset 清单、原始描述及最终候选与历史产物一致。结果见脚本附件的 `reproduction-check.json`。这一重放仍不包含运行游戏、服务器或原生 Windows 测试。

## 10 怎样判断结果足够可信

### 10.1 四层证据应分别保留

| 证据层 | 核查内容 | 能证明什么 |
|---|---|---|
| 输入身份 | 索引、长度、MD5、SHA-256、分段顺序 | 分析的是哪一份资源 |
| 容器与格式 | 头部、压缩长度、解压长度、对象数量、各资产摘要 | 载荷提取过程可追踪 |
| 描述恢复 | 所有声明、字段、来源、引用和名称映射 | JSON 与协议声明一致 |
| 集成验证 | 实际加载位置、加载器补丁、只读 decode、客户端流程 | 在特定运行环境中走到了哪一步 |

不能用某一层替代另一层。消息数量相同不证明字段相同，JSON 可解析不证明引用可用，进入大厅也不证明所有玩法协议已覆盖。

### 10.2 本次已有的复核

一份独立检查对最终 JSON 和 Alpha 的常量补丁做了结构检查、AST 静态检查及登录相关描述核对；另一份检查重新实现了字节码读取和声明分析。后者验证 3,061 个源定义、6,889 个字段与主分析一致，并确认 1,368 个引用闭合、124 个限定名称正确、包名无改动。相关报告均在附件 `baseline` 中。

静态检查还发现，服务器部分可选 boss-team 处理器引用 `sc_45109`、`sc_45111`，但对应请求和响应名称不在这份客户端协议中。处理方式是保留原协议事实并记录兼容性缺口，没有编造这些消息定义。[相关服务器处理器](https://github.com/Mint-ARK/Alpha-Persei-Cluster/blob/83c03f1d75004ecb9f0ac1484676f6b5181dfa4e/v5_server/operations.py#L6172-L6207)

原静态审计报告的 `runtime_test_performed: false` 表示审计本身没有运行客户端或 Alpha 模块。之后用户自行安装候选并报告该历史环境能进入主界面，这属于后续用户运行反馈，不能改写成静态审计执行过全流程测试，也不能外推为全游戏兼容。

### 10.3 安装前后的小范围验证

仅在准备实际替换 schema 时执行：停止后端，确认真正的安装根目录和加载器选择的路径，备份已有 JSON，再复制经过检查的候选。不要把整个提取目录、原始字节码或分析脚本放进 `v5_server`。

若便携安装确实已有以下 Python 路径，可在安装根目录进行最小 decode 检查：

```powershell
& ".\runtime\python\python.exe" -B ".\v5_server\decode_schema.py" 0800 sc_10039
```

路径不存在时应改用该安装已有的真实 Python 路径。命令中的 `0800` 只有 `result=0`，并不是完整登录响应；不添加 `--out`。其用途是确认 schema 可被加载、该字段能被解码，不检查完整响应的 required 字段，也不证明登录或大厅流程成功。

通过后再由用户按正常流程启动后端和客户端，记录版本、候选摘要、操作步骤、日志时间与实际到达的界面。回退时停止后端后恢复备份；原本缺失该文件时，仅移除本次候选。协议描述修复不需要顺带修改证书、端口转发、防火墙或网络配置。

## 11 安全限制和必须停止的情况

### 11.1 现有脚本已做的检查

多个读取函数检查剩余长度；解压后检查预期输出长度；LuaJIT 原型解析检查结束位置；TextAsset 检查对象读取终点；输出路径拒绝绝对路径和 `..`；声明分析对未知调用和未知 opcode 报错。

这些检查有价值，但不足以把脚本描述为“全面安全的非可信文件解析器”。例如部分对象与目录使用 Python 切片，切片本身不会因越界而报错；部分索引、累计长度和格式标志没有完整校验。脚本还大量使用 `assert`，必须禁用 Python 优化模式。

### 11.2 未实现的通用加固

下面是未来扩展前应补充的要求，**不是现有脚本已经具备的功能**：

- 限制输入总量、解压累计总量、块数、对象数、字符串长度、原型数与指令数
- 在分配内存前限制 LZMA 字典大小和所有声明的解压长度
- 校验每个目录和对象区间、类型索引、常量索引以及对齐后的边界
- 拒绝未支持的 flags、压缩方式、端序、SerializedFile 版本和 LuaJIT 标志
- 使用受限输出目录，防止路径覆盖、平台特殊路径或已有符号链接改变落盘目标
- 把关键 `assert` 改成始终生效的显式异常，并保留可定位的错误上下文
- 区分“语法读取成功”“支持其语义”和“输出格式能表达”，不能只看 parser 没报错

本样本虽只有约 35.8 MB，解包后 CAB 已接近 499 MB，另有约 497 MB TextAsset，现有脚本还会在内存中保留大块数据。应预留数 GB 内存和至少数 GB 可用磁盘；这属于运行资源建议，脚本没有自动预算管理。针对未知输入，不应仅凭文件很小就放心运行。

### 11.3 典型停止条件

| 现象 | 正确处理 |
|---|---|
| 资源摘要或长度不符 | 重新确认索引、分段顺序和获取过程 |
| 没有已确认的 10 字节前缀或 UnityFS 签名 | 重新识别封装，不盲目删头 |
| 压缩标志未知或块表位置不同 | 核对格式并补解析支持，不试错解压后继续 |
| SerializedFile 版本不是 22 | 为新格式单独验证对象布局 |
| LuaJIT flags 不是 `0x0a` | 重新确认端序、FR2、调试信息和其他标志 |
| 多原型、跳转、未知 CALL 或新 opcode | 停止静态恢复，设计新的受限分析与测试 |
| 同名类型、引用或字段序号不闭合 | 回到原始描述关系定位问题 |
| JSON 加载成功但玩法报错 | 检查服务端逻辑与版本差异，不能直接归咎于提取 |

## 12 新版本如何重新生成

针对当前 5.3.1 或以后版本，复用的是方法和检查顺序，不是旧哈希、旧目录、旧偏移、旧字段数或兼容别名。

1. **重新采样**：保存实际索引、app/build/version 信息、资源路径、大小、MD5 和 SHA-256；保留原件
2. **重新识别容器**：确定是否仍有外层前缀、UnityFS 版本和 flags、块表位置、压缩方式与资源预算
3. **重新核对对象布局**：确认 SerializedFile、端序、TypeTree 和 TextAsset 结构
4. **重新识别字节码**：统计 dump 版本、flags、原型数、常量类型和 opcode，先与现有支持范围比较
5. **扩展前先解释差异**：遇到新语义先停止；为其补充格式或声明分析，再增加独立测试，不直接关闭断言
6. **恢复原始描述**：保留模块身份、字段编号、类型、标签与目标来源；输出独立的原始描述文件
7. **重新适配目标服务器**：读取实际使用版本的加载器和补丁，重新评估名称归一化与别名；不自动复制 p58 裸名策略
8. **生成语义差异报告**：以模块和消息名比较新增、删除、字段编号、类型、label、引用及服务器补丁变化
9. **独立校验与回归**：对新输入建立新摘要、新统计和新报告，保留源码固定提交与参考文本快照
10. **受控集成**：在可回退副本上验证加载和最小场景，按真实流程逐步扩大覆盖并记录未测试项目

若只能完成前几步，就报告已完成的层次和具体阻碍。不要用历史资源 229 的成功替代新版本的验证，也不要为了继续流程而执行未知游戏字节码。

## 附录 产物与来源索引

### 分析脚本的职责

| 文件 | 职责 | 重要限制 |
|---|---|---|
| `extract-static-unity.py` | 读取本例封装与 UnityFS，解压 `CAB-win64` | 固定输入文件名与本例布局 |
| `extract-static-textassets.py` | 读取版本 22 对象表并提取 TextAsset | 两类已知对象结构 |
| `parse-static-luajit.py` | 读取 dump v2、常量和指令，生成诊断反汇编 | flags 固定为 10 |
| `recover-static-descriptors.py` | 静态还原声明，消歧并输出基础 JSON | 不含最终兼容别名；摘要字段含历史常量 |
| `compare-public-descriptors.py` | 与固定公开 Lua 声明进行文本级比较 | 需要 92 个外部文本文件 |
| `schema-audit/independent_audit.py` | 独立读取与映射复核 | 需要官方参考文本和最终别名 |

### 需要保留的证据文件

- 原资源或原分段，以及来源索引
- 输入和中间容器摘要，`textassets-manifest.json`
- `raw-descriptors-with-provenance.json`
- 基础描述输出与最终候选，以及单独记录的兼容变更
- `extraction-validation.json`、`public-comparison.json`
- `independent-static-validation.json`、`validation-review.json`
- 实际脚本版本、依赖版本、参考源码快照与摘要
- 后续用户运行验证的版本、步骤、日志和结果，和静态报告分别保存

### 固定来源与浮动来源

协议公开源固定为 `PackageInstaller/DataTable` 提交 `83b4bf07a62a73b05e74c22f1c47e59ae0983ae2`；Alpha 代码核对固定为 `Mint-ARK/Alpha-Persei-Cluster` 提交 `83c03f1d75004ecb9f0ac1484676f6b5181dfa4e`。这两个固定来源与本次结果的核对关系已经记录。

UnityPy `master`、LuaJIT `v2.1` 和 protobuf `main` 的格式参考链接是浮动分支，不是本次已固定的 commit。其用途是理解和核对格式；不要声称这些网页本身永远保持相同内容。未来复现应另存参考文本与摘要，并在升级参考实现时重新核对。

**结论**：可靠恢复依靠的是一条可核验的数据链：知道输入是哪份文件，解释每一层封装，只分析能够证明语义的协议声明，并把适配服务器的变化单独记录。某次能进入大厅是有价值的集成结果，不能替代这条证据链，也不能保证下一个版本仍然适用。
