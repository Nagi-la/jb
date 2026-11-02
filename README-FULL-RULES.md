# MagicRule 完整规则迁移索引

生成方式：从已成功抓取的原站 manifest 中筛选 `key=rules` 或 `role=full`；规则文件内容保持原样，扩展名按客户端格式命名。

## 客户端语法边界

- **Surge**：Surge RULE-SET/纯规则列表语法；不可直接当作 Mihomo YAML。
- **Mihomo**：Mihomo/Clash 规则集语法；不可直接当作 Surge/Quantumult X。
- **Shadowrocket**：Shadowrocket 规则语法；不可直接当作其他客户端。
- **Loon**：Loon 规则语法；不可直接当作 Surge。
- **Egern**：Egern 规则语法；不可直接当作其他客户端。
- **AdGuard**：AdGuard filter 语法；不是代理客户端规则语法。
- **Stash**：Stash/Clash 风格语法；不可直接当作 Surge。
- **QuantumultX**：Quantumult X 规则语法；不可直接当作 Surge。
- **Surfboard**：Surfboard 规则语法；不可直接当作其他客户端。
- **SingBox**：sing-box JSON/规则格式；不是 .list 代理规则语法。

## 目录

| 客户端 | 完整规则文件数 | 说明 |
|---|---:|---|
| AdGuard | 4 | [客户端目录](rules/AdGuard/README.md) |
| Egern | 677 | [客户端目录](rules/Egern/README.md) |
| Loon | 652 | [客户端目录](rules/Loon/README.md) |
| Mihomo | 656 | [客户端目录](rules/Mihomo/README.md) |
| QuantumultX | 677 | [客户端目录](rules/QuantumultX/README.md) |
| Shadowrocket | 650 | [客户端目录](rules/Shadowrocket/README.md) |
| SingBox | 0 | [客户端目录](rules/SingBox/README.md) |
| Stash | 657 | [客户端目录](rules/Stash/README.md) |
| Surfboard | 655 | [客户端目录](rules/Surfboard/README.md) |
| Surge | 650 | [客户端目录](rules/Surge/README.md) |
