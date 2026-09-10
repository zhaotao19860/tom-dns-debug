# tom-dns-debug

一个用于排查 DNS 问题的 Claude Code / Claude Agent SDK 技能（skill）。只做只读采集，把协议事实和推测分开，输出一份普通人能看懂的中文诊断报告。

## 能查什么

一条命令跑完五层基准检查，另有一层可选的异地观测：

| 层 | 它回答的问题 | 开关 |
| --- | --- | --- |
| 本机解析器 | 这台机器现在实际问到的是什么 | 默认开启 |
| 防篡改签名（DNSSEC） | 有没有签名、签名有没有过期、解析器有没有校验 | `--dnssec` |
| 公共 DNS | 8.8.8.8、180.76.76.76、114.114.114.114 是否给出一致的答案 | `--public-resolvers` |
| 委派链路 | 从根服务器往下，是哪一跳出问题 | `--trace` |
| 权威服务器 | 绕开所有缓存，域名来源自己怎么答 | `--authoritative` |
| 异地观测 | 别的国家问到的是什么（唯一的外发步骤，需双重确认） | `--regions CN,US,DE` |

## 怎么用

```bash
python3 scripts/dns_probe.py --target www.example.com --output-dir /tmp/dns-check --baseline
python3 scripts/dns_analyze.py --input /tmp/dns-check/dns-debug-report.json --output /tmp/dns-check/dns-debug-report.md --finalize-bundle
```

产物是同目录下的 `dns-debug-report.md`（中文报告）和 `dns-debug-report.json`（完整原始记录）。

报告里有一张解析链路图，把你的电脑 → 本机解析器 / 公共 DNS / 异地观测 → 根服务器 → 顶级域 → 权威服务器整条链路画在一起，哪个节点有问题就标在哪个节点上：

```text
[你的电脑]　查 www.example.com
│
├─ 本机默认解析器 ✅　203.0.113.20
│
├─ 公共 DNS
│  ├─ 114.114.114.114 ✅　203.0.113.20
│  ├─ 180.76.76.76 ⚠️　10.0.0.9（内网地址，公网到不了）
│  └─ 8.8.8.8 ✅　203.0.113.45
│
└─ 权威服务器一侧（绕过缓存，从根往下问）
   根服务器 ✅　交给 13 台服务器，8 毫秒
      └─ com ✅　交给 13 台服务器，93 毫秒
         └─ example.com ✅　交给 ns1.example.net、ns2.example.net
```

作为技能使用时，把整个目录放到 `~/.claude/skills/tom-dns-debug`，用 `/tom-dns-debug <域名>` 触发；完整的执行约定见 [SKILL.md](SKILL.md)。

## 安全边界

- 只读：不用 sudo、不改配置、不清缓存、不重启服务、不抓包、不装任何东西。
- 可自动执行的命令限于白名单内的 argv 形态，其余只生成命令、由用户自行执行后粘贴结果。
- 采集到的证据、命令输出、内网解析器地址、搜索域**永不外发**，产物只留在本机。
- 异地观测是唯一的外发步骤：必须同时给出 `--regions` 和 `--acknowledge-remote-query`，只发送被查询的域名与记录类型给 `api.globalping.io`；内网名、单标签名、`.local`、RFC 1918 地址即使确认过也一律拒绝。每次运行的 `safety[]` 都会记录本次是否发生外发。

## 开发

标准库 unittest，无外部依赖，测试不发起任何网络请求：

```bash
python3 -m unittest discover -s tests
```
