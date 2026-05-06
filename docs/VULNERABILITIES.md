# 漏洞清单与安全标准映射

## 漏洞总览

| # | 漏洞类型 | CWE | OWASP 2021 | CERT C | 优先级 | 模块 | 函数 |
|---|---------|-----|-----------|--------|-------|------|------|
| 1 | 缓冲区溢出 | CWE-120 | A03 Injection | STR31-C, STR32-C | Critical | protocol.c | parse_message() |
| 2 | 格式化字符串 | CWE-134 | A03 Injection | FIO30-C, FIO47-C | High | logger.c | log_write() |
| 3 | Use-After-Free | CWE-416 | A04 Insecure Design | MEM30-C | Critical | session.c | session_validate() |
| 4 | Double Free | CWE-415 | A04 Insecure Design | MEM31-C | Critical | network.c | conn_close() |
| 5 | 整数溢出 | CWE-190 | A04 Insecure Design | INT30-C, INT32-C | High | file_handler.c | file_store() |
| 6 | 未校验输入 | CWE-20 | A03 Injection | STR31-C, ARR30-C | High | auth.c | auth_verify() |
| 7 | 命令注入 | CWE-78 | A03 Injection | ENV33-C | Critical | config.c | config_backup() |
| 8 | 路径遍历 | CWE-22 | A01 Broken Access Control | FIO02-C | High | file_handler.c | file_retrieve() |
| 9 | 不安全随机数 | CWE-338 | A02 Cryptographic Failures | MSC30-C | High | session.c | session_create() |
| 10 | 硬编码密钥 | CWE-798 | A02 Cryptographic Failures | MSC41-C | Critical | auth.c | auth_hash_password() |

## 各漏洞详情

### 1. 缓冲区溢出 (CWE-120)

- **位置**: `src/protocol.c:parse_message()`
- **演示**: `vulnerable/01_buffer_overflow.c`
- **修复**: `fixed/01_buffer_overflow_fixed.c`

**原理**: 从网络接收的可变长度数据 `data_len` 被直接用作 `memcpy` 的长度参数，目的地是一个固定大小的栈缓冲区。当 `data_len > sizeof(buffer)` 时，栈上的返回地址被覆盖。

**攻击影响**: 远程代码执行 (RCE)，攻击者获得服务器 shell。

**修复方式**:
1. 在 memcpy 前检查 `data_len < sizeof(dest_buffer)`
2. 使用有界拷贝 `memcpy(dest, src, MIN(data_len, sizeof(dest)-1))`
3. 显式 NUL 终止目标缓冲区

**安全编码最佳实践**:
- 永远不要信任网络数据中的长度字段
- 使用 `strncpy`/`snprintf` 等有界函数
- 启用编译器保护: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`

---

### 2. 格式化字符串 (CWE-134)

- **位置**: `src/logger.c:log_write()`
- **演示**: `vulnerable/02_format_string.c`
- **修复**: `fixed/02_format_string_fixed.c`

**原理**: `log_write(level, user_input)` 中用户输入被直接传递给 `vfprintf` 作为格式字符串。攻击者使用 `%x` 泄漏栈内容，使用 `%n` 向任意地址写入。

**攻击影响**: 信息泄露（栈/内存内容），任意内存写入。

**修复方式**:
1. 始终使用 `fprintf(fp, "%s", user_data)` 格式
2. 启用编译器格式检查: `__attribute__((format(printf, ...)))`

---

### 3. Use-After-Free (CWE-416)

- **位置**: `src/session.c:session_destroy_by_ptr()` → `session_validate()`
- **演示**: `vulnerable/03_use_after_free.c`
- **修复**: `fixed/03_use_after_free_fixed.c`

**原理**: `session_destroy_by_ptr()` 释放 session_t 对象后，调用方持有的指针未被置为 NULL。后续 `session_validate()` 通过悬挂指针访问已释放的内存。

**攻击影响**: 信息泄露或代码执行，取决于释放后内存被重新分配为何种对象。

**修复方式**:
1. 释放后立即 `ptr = NULL`
2. 使用双指针参数 `session_destroy(session_t **s)` 让函数可以 NULL 掉调用方的指针
3. 在解引用前检查 NULL

---

### 4. Double Free (CWE-415)

- **位置**: `src/network.c:conn_close()`
- **演示**: `vulnerable/04_double_free.c`
- **修复**: `fixed/04_double_free_fixed.c`

**原理**: `conn_close()` 的错误处理路径中 `free(conn->buffer)` 后跳转到 `cleanup` 标签，该标签再次 `free(conn->buffer)`。

**攻击影响**: 堆分配器元数据损坏，可导致任意写。

**修复方式**:
1. `free(ptr); ptr = NULL;` — free(NULL) 是安全的
2. 使用 `SAFE_FREE` 宏: `#define SAFE_FREE(p) do { free(p); (p) = NULL; } while(0)`

---

### 5. 整数溢出 (CWE-190)

- **位置**: `src/file_handler.c:file_store()`
- **演示**: `vulnerable/05_integer_overflow.c`
- **修复**: `fixed/05_integer_overflow_fixed.c`

**原理**: `malloc(data_len + 1)` 当 `data_len == SIZE_MAX` 时，加法回绕为 0，malloc(0) 返回极小的缓冲区。随后 memcpy 写入大量数据导致堆溢出。

**攻击影响**: 堆缓冲区溢出 → RCE。

**修复方式**:
1. 设置最大数据长度限制 `MAX_PAYLOAD_SIZE`
2. 加法前检查溢出: `if (data_len > SIZE_MAX - 1) reject()`
3. 拒绝 `data_len == 0`

---

### 6. 未校验输入 (CWE-20)

- **位置**: `src/auth.c:auth_verify()`
- **演示**: `vulnerable/06_unchecked_input.c`
- **修复**: `fixed/06_unchecked_input_fixed.c`

**原理**: 用户名和密码直接用于字符串操作和认证判断，未检查长度、字符集和格式。

**攻击影响**: 缓冲区溢出（超长输入），认证绕过（特殊字符）。

**修复方式**:
1. 检查 `strlen(input)` 范围
2. 强制字符允许列表 [a-zA-Z0-9_-.@]
3. 拒绝控制字符和 NULL 字节

---

### 7. 命令注入 (CWE-78)

- **位置**: `src/config.c:config_backup()`
- **演示**: `vulnerable/07_command_injection.c`
- **修复**: `fixed/07_command_injection_fixed.c`

**原理**: 用户提供的备份路径直接拼接到 `system()` 命令中。shell 元字符（`;`, `|`, `&&`, `` ` ``）被解释执行。

**攻击影响**: 任意命令执行，完整系统控制。

**修复方式**:
1. 使用 `fork() + execve()` 替代 `system()`
2. 参数通过 argv 数组传递，不经过 shell
3. 验证目标路径不含 shell 元字符

---

### 8. 路径遍历 (CWE-22)

- **位置**: `src/file_handler.c:file_retrieve()`
- **演示**: `vulnerable/08_path_traversal.c`
- **修复**: `fixed/08_path_traversal_fixed.c`

**原理**: 文件名直接拼接到基础目录路径后，`../` 序列未被过滤，攻击者可访问任意文件。

**攻击影响**: 任意文件读取（/etc/shadow），任意文件写入。

**修复方式**:
1. 拒绝包含 `..`, `/`, `\\` 的文件名
2. 使用 `realpath()` 解析规范路径
3. 验证规范路径前缀等于允许的基础目录

---

### 9. 不安全随机数 (CWE-338)

- **位置**: `src/session.c:session_create()`
- **演示**: `vulnerable/09_insecure_random.c`
- **修复**: `fixed/09_insecure_random_fixed.c`

**原理**: 使用 `rand()` 生成会话 ID 和令牌。rand() 是确定性 LCG，默认种子为 1。

**攻击影响**: 会话劫持（预测会话 ID），令牌伪造。

**修复方式**:
1. 使用 `/dev/urandom` 或 `getrandom()`
2. 在 BSD/macOS 上使用 `arc4random()`
3. 使用 OpenSSL 的 `RAND_bytes()`

---

### 10. 硬编码密钥 (CWE-798)

- **位置**: `src/auth.c:auth_hash_password()`
- **演示**: `vulnerable/10_hardcoded_key.c`
- **修复**: `fixed/10_hardcoded_key_fixed.c`

**原理**: 加密密钥以明文嵌入源代码，编译进二进制。用 `strings` 命令即可提取。

**攻击影响**: 密钥泄露 → 所有用户凭据可被解密，批量账户劫持。

**修复方式**:
1. 从环境变量读取密钥
2. 使用 KMS（AWS KMS / HashiCorp Vault）
3. 使用标准密码哈希算法（bcrypt, scrypt, argon2, PBKDF2）
4. 始终使用随机盐

## CERT C 编码规范参考

| 规则 | 描述 |
|------|------|
| STR31-C | 保证字符串存储有足够空间 |
| STR32-C | 不以 NULL 结尾的字符串不要传递给期望字符串的函数 |
| MEM30-C | 不要访问已释放的内存 |
| MEM31-C | 不要多次释放同一内存 |
| INT30-C | 确保无符号整数运算不回绕 |
| INT32-C | 确保有符号整数运算不溢出 |
| FIO30-C | 从格式字符串中排除用户输入 |
| FIO47-C | 不要使用可能触发副作用的表达式作为 printf 参数 |
| ENV33-C | 不要调用 system() |
| FIO02-C | 验证路径是否在安全的目录内 |
| MSC30-C | 不要使用 rand() 生成安全令牌 |
| MSC41-C | 不要在代码中硬编码敏感信息 |
| ARR30-C | 不要越界访问数组 |
