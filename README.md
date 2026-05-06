# SecureFile Vault — 安全编码训练项目

一个模拟真实网络文件存储服务的 C 语言训练项目，刻意引入 10+ 安全漏洞，用于提升开发人员的安全编码能力。配合 GitHub Actions + CodeQL 静态扫描质量卡点。

## 项目概述

**业务场景**: 多用户 TCP 文件存储服务，支持用户认证、文件上传/下载/删除、操作审计日志、基于配置文件的运行时管理。

**技术栈**: C99, POSIX sockets, Makefile + CMake, Docker, GitHub Actions, CodeQL

## 快速开始

```bash
# 构建所有目标
./scripts/build.sh all

# 启动含漏洞版本（训练用）
./scripts/run_vulnerable.sh

# 启动修复后版本
./scripts/run_fixed.sh

# 运行测试
./scripts/run_tests.sh

# Docker 方式
docker compose -f docker/docker-compose.yml up dev
```

## 目录结构

```
├── src/            # 核心业务源码（含漏洞）
├── include/        # 头文件
├── vulnerable/     # 漏洞独立演示（10 个）
├── fixed/          # 修复版本参考（10 个）
├── tests/          # 单元测试和回归测试
├── docker/         # Docker 开发环境
├── scripts/        # 构建和运行脚本
├── docs/           # 培训文档
├── .github/        # CI/CD 配置
└── .codeql/        # CodeQL 扫描配置
```

## 漏洞清单

| # | 漏洞 | CWE | 模块 |
|---|------|-----|------|
| 1 | 缓冲区溢出 | CWE-120 | protocol.c |
| 2 | 格式化字符串 | CWE-134 | logger.c |
| 3 | Use-After-Free | CWE-416 | session.c |
| 4 | Double Free | CWE-415 | network.c |
| 5 | 整数溢出 | CWE-190 | file_handler.c |
| 6 | 未校验输入 | CWE-20 | auth.c |
| 7 | 命令注入 | CWE-78 | config.c |
| 8 | 路径遍历 | CWE-22 | file_handler.c |
| 9 | 不安全随机数 | CWE-338 | session.c |
| 10 | 硬编码密钥 | CWE-798 | auth.c |

## 培训路径

1. **初级**: 识别漏洞 — 阅读代码，运行服务，理解 CodeQL 报告
2. **中级**: 修复漏洞 — 逐个修复，编写测试，验证通过
3. **高级**: 编写安全代码 — 从零实现新功能，通过 CI 质量门禁

详见 [docs/TRAINING.md](docs/TRAINING.md)

## CI/CD

GitHub Actions + CodeQL:
- Push/PR 到 main/develop 自动触发扫描
- 定期扫描（每周二）
- Critical 漏洞阻断合并，Medium 仅告警

详见 [.github/workflows/codeql-analysis.yml](.github/workflows/codeql-analysis.yml)

## 文档

- [培训路径](docs/TRAINING.md)
- [漏洞清单与安全标准映射](docs/VULNERABILITIES.md)
- [安全编码最佳实践](docs/SECURITY_GUIDE.md)
