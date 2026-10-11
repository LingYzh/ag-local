Alpha Persei 协议 schema 恢复候选

候选 JSON 的 SHA-256
b9101c965ed4f75317aa9c0199e17e5a7d2c3e0c0e23b982217a960b1a6ee79f

用途
本目录的 lua_proto_messages.json 用于补回 Alpha Persei 缺失的协议描述文件。
它来自你上传的客户端 scripts64 资源包，已经完成静态提取和结构校验。
尚未在你的服务端安装目录或游戏客户端中运行验证，不能承诺复制后所有功能正常。

来源与完整性
- 客户端：app 307 / resource 229，用户当前 v5.2.1 资源；不是此前索引中的 resource 321
- 两段文件按 part01、part02 顺序拼接：35,790,934 字节
- 原始文件 MD5：86add1e9d150efa2464ec96f0579a0b9
- 原始文件 SHA-256：f1501ccee59271f6e47fe3eb945111dbef252985110b2d34f65f96583611d485
- 文件头：10 个 NUL 字节，随后为 UnityFS v8；Unity 2022.3.62f3c1
- 从资源包静态读取 10,267 个 TextAsset，其中 protocol 目录有 92 个 LuaJIT 字节码文件
- 恢复 3,061 个源协议定义、6,889 个字段，包括 1,368 个嵌套消息字段
- 不运行游戏 Lua、不启动服务端、不安装第三方提取器；仅解析文件格式和静态声明

校验结果
- 所有字段的编号、类型、标签、嵌套目标均可从客户端字节码恢复
- 输出没有重复的消息键，没有未解析的嵌套引用
- 与下面固定提交中的 92 个公开 Lua 文件逐项比较：3,061 个定义全部一致，0 个差异
  比较项包含所属模块、消息名、完整名、字段名、字段编号、类型、标签和嵌套目标模块/名称
  https://github.com/PackageInstaller/DataTable/tree/83b4bf07a62a73b05e74c22f1c47e59ae0983ae2/MasterData/Lua/x64/protocol
- 上述一致性只确认协议描述匹配上传的资源包，不等于整个客户端或服务器代码版本完全相同

同名嵌套类型处理
源协议有 53 组跨模块同名类型，合计 124 个定义，部分字段结构互不相同。
若只保留短名称，Alpha 的加载器可能合并不相关的类型。
本候选仅将这些冲突的嵌套类型改成“模块.名称”，并按原始对象关系同步修改引用。
例如 p13_pb.equip_list 和 p14_pb.equip_list 分开保留。
另保留一个有源码依据的兼容别名 crickets_round_score_net_rec，指向 p58_pb 的同名三字段定义，满足 Alpha 自带补丁的短名称引用。
因此最终文件共有 3,062 个消息键：3,061 个客户端定义，加 1 个兼容别名。
唯一的 cs_ / sc_ 消息名称不变；这只是 schema 内部索引名，不改变 protobuf 字段编号或线上消息内容。

使用前
1. 完全停止 Alpha 后端进程。先把本压缩包解压到一个单独的临时目录。
2. 找到实际运行的 Alpha 安装根目录，确认其中有 v5_server\decode_schema.py。
3. 检查 v5_server\lua_proto_messages.json 是否已经存在。
   - 不存在：把本包的 lua_proto_messages.json 复制到该位置
   - 已存在：先把原文件复制备份到安装目录以外；不要未经备份直接覆盖
   - 若安装内还有其他同名 schema 文件，先确认 decode_schema.py 实际选择哪一个，避免改错副本
4. 不需要复制验证报告、原始字节码、客户端资源或任何脚本到 v5_server。

先做只读检查
在安装根目录打开 PowerShell。如果便携包的 Python 位于下列路径，可运行：

& ".\runtime\python\python.exe" -B ".\v5_server\decode_schema.py" 0800 sc_10039

这条命令不启动服务器、不连接游戏、不写数据库；不加 --out，-B 用于避免生成 Python 缓存。
0800 是只带 result=0 的测试 protobuf 片段，并非完整登录响应。
预期能看到 result 为 0 的解码结果。目标只是确认 schema 能被读取且该字段可以解码，不再出现缺少 lua_proto_messages.json 的错误。
它不检查完整登录消息的必填字段，也不能验证真正进入大厅成功。
如果 Python 不在这个位置，使用该便携包已有的真实 Python 路径，不必另行安装 Python。
如果仍报错，保留完整报错和实际加载的 schema 路径，先不要继续替换更多文件。

再做运行验证
只读检查通过后，正常重新启动 Alpha 后端，再启动客户端并重复一次此前失败的进入大厅流程。
观察是否已经收到 sc_10039，以及是否出现新的明确错误；把新的服务端日志和时间点保留下来。
这个候选只处理缺失的协议描述。后续数据库、内容、客户端兼容性问题仍可能独立存在。
不用为此次 schema 验证修改 portproxy、证书、端口或防火墙设置。
若需要回退，停止后端，然后恢复备份；原本没有此文件时，只移除本次复制的候选文件。

附带报告
- extraction-validation.json：客户端提取数量、字段类型分布、同名类型处理和各协议文件来源哈希
- public-comparison.json：与固定公开 Lua 源逐项比较的结果
- independent-static-validation.json：加载格式、服务器补丁后的引用闭合性和登录协议复核
- validation-review.json（若包含）：独立静态复核结果

服务器接口参考
https://github.com/Mint-ARK/Alpha-Persei-Cluster/blob/83c03f1d75004ecb9f0ac1484676f6b5181dfa4e/v5_server/decode_schema.py
https://github.com/Mint-ARK/Alpha-Persei-Cluster/blob/83c03f1d75004ecb9f0ac1484676f6b5181dfa4e/v5_server/codec.py
