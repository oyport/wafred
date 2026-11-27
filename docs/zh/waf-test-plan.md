# WAFred 1.0.4 WAF 测试方案

本方案沿用此前 WAFred 版本测试使用的语料和分析流程，记录 WAFred 1.0.4 候选版本的当前测试设置及后续验证项。

- 测试日期：2026-11-22
- 候选版本 SHA-256：93b4b6e92e39eb3417dabec510945fe847667660ffad0493c1a3f31d50fc9796
- 语料：chaitin/blazehttp，commit afc88a94d03db1cd52156c34c3c9c58053c9f658；33,877 条请求，恶意 658、正常 33,219
- 环境：五台 Debian 13 虚拟机，隔离 WAF、模拟源站、两台负载机和结果收集机
- 当前结果：[WAF 实测报告](waf-test-report.md)、[完整实验室报告](../wafred-baseline-test-report-2026-11-22.md)、[基准摘要及旧版本测试背景](../waf-benchmark-report.md)

## 测试矩阵

| 档位 | 攻击拦截/质询 | 正常请求受影响 | 回放 p50 / p95 | HTTP 500 |
|---|---:|---:|---:|---:|
| Normal | 397/658（60.33%） | 4/33,219（0.012%） | 43 / 48 ms | 0 |
| Normal + body | 494/658（75.08%） | 12/33,219（0.036%） | 43 / 48 ms | 0 |
| Strict | 501/658（76.14%） | 4/33,219（0.012%） | 43 / 48 ms | 0 |
| Strict + body | 632/658（96.05%） | 19/33,219（0.057%） | 43 / 48 ms | 0 |

WAF 返回 403 拦截或 503 质询均计作攻击命中；正常流量出现这两类响应计作受影响。解析器/方法响应（400/405）、回放错误和 5xx 分开记录。

## 可重复检查

- 回放 framing 单测：python tools/waf-bench/test_replay.py
- Rust WAF 测试：cargo test -p pingwaf-waf
- 格式检查：cargo fmt --all -- --check
- 站点内容、构建和站内链接：在 site/ 目录运行 npm run verify

全量回放使用 tools/waf-bench/conf 下的档位配置和 run_suite.sh。每轮记录候选二进制哈希、配置、语料 commit、并发/延迟参数及结果目录。

回放器每个连接只发送一个请求。非空请求体缺少 Content-Length 和 Transfer-Encoding 时补齐按字节计算的 Content-Length；只有一个合法 Content-Length 时截断声明长度以外的多余字节；歧义或非法 framing 样本保留给协议测试。

## HTTPS 与容量范围

隔离候选版本已使用自签证书和显式 CA 信任完成 HTTPS 测试。TLS 1.2/1.3 握手验证通过；HTTP/HTTPS 正常请求返回 200，HTTPS 攻击探针返回 403，未信任客户端拒绝证书。上游模拟源站使用 HTTP。

高并发 soak 和文件句柄上限数据来自原部署二进制，不代表修复候选版；候选版本高并发容量仍待补测。HTTP/2、HTTP/3、上游 TLS、生产路由、agent 连接行为、限速和真实业务源站也不在本轮范围内。

## 验收与报告

每档分别记录攻击命中、正常流量受影响、回放错误、协议/方法拒绝和 5xx。基线与候选使用相同 framing，按样本路径比较新增/丢失检测和正常请求判决变化。语料分母或网络链路不同的第三方数值须标为历史参考。
