---
title: WAFred 1.0.4 实测报告
description: WAFred 全量语料修正结果、漏报修复、自签 HTTPS 检查和历史防火墙对比。
minutes: 5
---

## 结果速览

测试日期为 2026-11-22，被测版本为本地重建的 WAFred 1.0.4 候选构建。公开 chaitin/blazehttp 语料共 33,877 条 HTTP 请求（恶意 658、正常 33,219）。拦截与质询均计为攻击命中，正常流量受影响也统计这两类响应。

| 档位 | 攻击样本拦截 | 正常流量受影响 | 回放 p50 / p95 | HTTP 500 |
|---|---:|---:|---:|---:|
| Normal | 397/658（60.33%） | 4/33,219（0.012%） | 43 / 48 ms | 0 |
| Normal + 请求体检查 | 494/658（75.08%） | 12/33,219（0.036%） | 43 / 48 ms | 0 |
| Strict | 501/658（76.14%；491 拦截、10 质询） | 4/33,219（0.012%） | 43 / 48 ms | 0 |
| Strict + 请求体检查 | **632/658（96.05%；622 拦截、10 质询）** | **19/33,219（0.057%）** | 43 / 48 ms | 0 |

## 漏报修复

原回放器未修改语料报文。带请求体但缺少 `Content-Length` / `Transfer-Encoding` 的样本实际上按无请求体请求发送，低估了请求体检测效果。回放器现会补充精确长度，并截去一个合法 `Content-Length` 之外的尾字节；同时修复了 15 条异常正常样本在代理转发时出现的 HTTP 500，四档最终结果均为 0 个 500。

WAFred 新增有界的未声明类型 URL-encoded / multipart 表单解析、Base64 路径片段检测，以及两条 Strict 专用 `alert.call` / `prompt.call` 签名。Strict + body 拦截 632/658 条攻击；19 条正常请求受影响（17 拦截、2 质询），启用前应复核固定样本。

## 与其他防火墙的历史比较

图表将 WAFred 1.0.4 本轮实测与 PingWAF 早期版本最后一轮 P13 结果并列，并保留 SafeLine、ModSecurity 和 Cloudflare 的历史参考。早期测试使用相同名义语料，但请求体 framing 路径不同；本轮回放器修正了 15 个 framing 相关 HTTP 500。这里呈现的是各版本的实测记录，并非严格控制变量的前后实验。其他产品本轮未重测，样本分母和网络链路也不同。WAFred p95 包含虚拟机、代理及模拟源站，不宜直接比较不同链路的时延。

## 压缩请求体与 HTTPS

gzip 套件中，关闭请求体检查时拦截 0/8 条攻击；Normal + body 拦截 7/8；Strict + body 拦截 8/8。每档的两条正常 gzip 请求均通过。

隔离 HTTPS 监听使用对 `wafred-test.local` 和 `127.0.0.1` 有效的自签证书。显式 `curl --cacert` 验证成功；默认 curl 信任库按预期拒绝该证书。OpenSSL SNI 握手在 TLS 1.2 和 1.3 下均成功。正常 HTTP/HTTPS 请求返回 200；HTTPS 表单攻击和 Base64 路径攻击返回 403。TLS 在 WAFred 终止，上游模拟源站使用 HTTP。

## 容量和测试范围

256 并发三分钟 soak、512 并发文件句柄结果来自原部署二进制，不是本次修复候选版。原进程软 `nofile=1,024` 在 512 并发出现 502；隔离副本提高到 65,536 后未出现 502，部署中的 all-in-one 没有修改。

安全矩阵使用隔离的 HTTP/1.1 代理和模拟源站。真实业务源站、HTTP/2/HTTP/3、生产路由、限速/CC 和候选版本高并发 soak 仍待补测。完整漏报归因、机器分工和归档见[WAFred 完整基准报告](https://github.com/oyport/wafred/blob/main/docs/wafred-baseline-test-report-2026-11-22.md)。本轮沿用早期 PingWAF 测试的语料和分析脉络；[基准附录](https://github.com/oyport/wafred/blob/main/docs/waf-benchmark-report.md)同时呈现相关背景与 WAFred 当前实测。
