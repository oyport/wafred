# WAFred 1.0.4 引擎复核与修正记录

本轮复核沿用早期 PingWAF 版本测试的 blazehttp 语料和逐样本分析脉络，并针对 WAFred 1.0.4 修复候选版本重新验证。当前指标和实验细节以[完整基准报告](wafred-baseline-test-report-2026-11-22.md)为准。

## 本轮发现

### 1. 请求体夹具 framing 不完整

部分攻击夹具有 body 字节，却缺少 Content-Length 和 Transfer-Encoding。回放器仍发送了 body 字节，但 HTTP/1.1 服务端按协议将其视为请求体之外的数据，WAF 实际未收到这些载荷。这些样本此前被统计为引擎漏报，主要问题在测试输入 framing。

此外，15 条正常样本在声明的 Content-Length 后含有额外字节，导致代理报告 Sent data after end of body 并返回 500。修正回放 framing 后，四种策略都不再出现这 15 个 500。

### 2. 归一化覆盖面不足

未声明 Content-Type 的 URL-encoded/multipart 正文之前没有按字段进行受限解析，单个高风险字段可能达不到 Strict 的评分门槛。带斜杠的 Base64 路径也可能因整条路径解码失败而未进入对应扫描路径。

### 3. Strict 高危脚本调用签名缺失

alert.call 与 prompt.call 这两种高危 JavaScript 调用形态此前没有 Strict 专用签名。

## 本轮代码调整

| 文件 | 调整 |
|---|---|
| tools/waf-bench/replay.py | 为无 framing 头的非空请求体补准确 Content-Length；对单个有效长度截断尾部多余字节；保留重复/无效长度及 Transfer-Encoding 协议夹具 |
| wafred-waf/src/normalize/mod.rs | 对未声明类型的表单与 multipart 请求体做有界 sniff/字段解析；按路径段扫描 Base64 |
| wafred-waf/src/rules/signatures.rs | Strict 档新增高危 alert.call 与 prompt.call 签名 |
| wafred-waf/src/engine/mod.rs | 加入引擎层回归用例 |
| tools/waf-bench/test_replay.py | 覆盖缺失长度补齐、合法长度截断、异常 framing 保留等行为 |

## 回归结果

| 指标 | 原部署构建 | 修复候选构建 | 变化 |
|---|---:|---:|---:|
| Strict 攻击命中 | 500/658 | 501/658 | +1，无已命中样本丢失 |
| Strict + body 攻击命中 | 630/658 | 632/658 | +2，无已命中样本丢失 |
| 新增正常样本拦截/质询 | — | 0 | 未增加 |

候选版本四档全量指标分别为 397/658、494/658、501/658、632/658；正常请求受影响分别为 4、12、4、19 条。全量回放错误为 0，HTTP 500 为 0。20 条固定漏报集有 1 条拦截、18 条放行、1 条方法层 405；27 条固定正常样本中 17 条拦截、2 条质询、8 条放行。

## 尚未覆盖的边界

- 修复候选版本未做高并发 soak；现有 256/512 并发数据属于原部署二进制。
- HTTPS 已用自签证书验证客户端信任、SNI 与 TLS 1.2/1.3；上游 HTTPS、HTTP/2/3 和真实业务源站仍需单独测试。
- 语料中的应用专用探针、多层编码和低证据载荷仍有放行项；不以扩大低置信规则的方式追求表面拦截率。

Rust WAF 单测 271/271 通过，replay.py 单测 4/4 通过，格式检查通过。