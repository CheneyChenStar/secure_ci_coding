# 安全编码最佳实践指南

## 一、内存安全

### 1.1 缓冲区操作

```c
/* ❌ 不安全 */
char buf[32];
strcpy(buf, user_input);           // 无长度检查
memcpy(buf, data, data_len);       // data_len 未验证

/* ✅ 安全 */
char buf[32];
if (strlen(user_input) >= sizeof(buf)) return -1;
strncpy(buf, user_input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';
```

**规则**:
- 永远验证长度再拷贝
- 使用 `strncpy`/`snprintf`/`memcpy_s`（C11 Annex K）
- 显式空终止字符串
- 启用 `-D_FORTIFY_SOURCE=2` 编译时保护

### 1.2 动态内存管理

```c
/* ❌ 不安全 */
free(ptr);
// ptr 并未置 NULL
if (ptr->field) { ... }  // UAF!

/* ✅ 安全 */
#define SAFE_FREE(p) do { free(p); (p) = NULL; } while (0)
SAFE_FREE(ptr);
if (ptr) { ... }  // 永远不会执行，ptr 是 NULL
```

**规则**:
- `free()` 后立即 `ptr = NULL`
- free(NULL) 是安全的 no-op
- 使用 Valgrind / AddressSanitizer 检测内存错误
- 考虑使用 talloc / arena allocators

### 1.3 整数运算

```c
/* ❌ 不安全 */
size_t alloc = user_size + 1;         // 可能溢出
char *buf = malloc(alloc);

/* ✅ 安全 */
if (user_size > SIZE_MAX - 1) return -1;  // 检查溢出
if (user_size > MAX_ALLOWED) return -1;    // 业务限制
size_t alloc = user_size + 1;
char *buf = malloc(alloc);
```

**规则**:
- 对每一个算术运算检查溢出
- Pattern: `if (a > TYPE_MAX - b) overflow`
- 设置并强制业务层面的上限

---

## 二、输入验证

### 2.1 验证所有外部输入

```c
/* ✅ 完整的输入验证 */
int validate_input(const char *input, size_t max_len) {
    if (!input) return -1;

    size_t len = strlen(input);
    if (len == 0 || len >= max_len) return -1;

    /* 字符允许列表 */
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)input[i]) &&
            input[i] != '_' && input[i] != '-')
            return -1;
    }

    return 0;
}
```

**规则**:
- 在信任边界验证（网络输入、文件输入、用户输入）
- 允许列表 > 拒绝列表
- 验证长度、类型、范围、格式
- 拒绝，不要试图"修复"恶意输入

---

## 三、命令执行

### 3.1 避免 Shell 解释

```c
/* ❌ 不安全 */
char cmd[1024];
snprintf(cmd, sizeof(cmd), "backup %s", user_path);
system(cmd);  // shell 解释元字符

/* ✅ 安全 */
pid_t pid = fork();
if (pid == 0) {
    const char *argv[] = {"backup", user_path, NULL};
    execvp("backup", argv);  // 直接执行，不经过 shell
    _exit(127);
}
```

**规则**:
- 优先使用库函数而非外部命令
- 如果必须执行外部程序: `fork()` + `execve()`
- 绝不使用 `system()`, `popen()`, `exec*()` with shell
- 验证所有参数不含 shell 元字符

---

## 四、文件路径安全

### 4.1 路径遍历防护

```c
/* ✅ 安全的文件路径处理 */
int safe_open_file(const char *user_filename, const char *base_dir) {
    /* 1. 拒绝危险字符 */
    if (strstr(user_filename, "..")) return -1;
    if (strchr(user_filename, '/')) return -1;
    if (strchr(user_filename, '\\')) return -1;

    /* 2. 构造完整路径 */
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, user_filename);

    /* 3. 解析规范路径 */
    char resolved[PATH_MAX];
    if (realpath(full_path, resolved) == NULL) return -1;

    /* 4. 验证在允许目录内 */
    if (strncmp(resolved, base_dir, strlen(base_dir)) != 0) {
        return -1;  // 路径遍历尝试
    }

    return open(resolved, O_RDONLY);
}
```

---

## 五、加密与密钥管理

### 5.1 密码哈希

```c
/* ❌ 不安全 */
const char *key = "SecretKey";  // 硬编码
// 自定义 XOR 加密
// MD5/SHA1
// 无盐

/* ✅ 安全 */
// 使用标准算法: bcrypt, scrypt, argon2, PBKDF2
// 随机盐
// 高迭代次数 (≥100,000 for PBKDF2)
// 密钥从环境变量/KMS 获取
```

### 5.2 随机数生成

```c
/* ❌ 不安全 */
int token = rand();                    // 可预测
srand(time(NULL)); int id = rand();   // 基于时间，可预测

/* ✅ 安全 */
// Linux
int fd = open("/dev/urandom", O_RDONLY);
read(fd, &token, sizeof(token));

// OpenSSL
RAND_bytes((unsigned char*)&token, sizeof(token));

// C2x (未来标准)
getrandom(&token, sizeof(token), 0);
```

---

## 六、格式化字符串

### 6.1 日志安全

```c
/* ❌ 不安全 */
printf(user_data);              // 用户输入作为格式字符串
syslog(LOG_INFO, user_data);

/* ✅ 安全 */
printf("%s", user_data);        // 用户输入作为参数
syslog(LOG_INFO, "%s", user_data);
```

---

## 七、编译器安全标志

```makefile
CFLAGS += -Wall -Wextra -Werror          # 启用所有警告
CFLAGS += -Wformat=2 -Wformat-security   # 格式字符串警告
CFLAGS += -fstack-protector-strong       # Stack canary
CFLAGS += -D_FORTIFY_SOURCE=2            # 有界函数检查
CFLAGS += -fPIE -pie                     # ASLR (position-independent)
CFLAGS += -ftrapv                        # 有符号溢出陷阱 (调试用)
```

## 八、运行时检测工具

| 工具 | 检测内容 | 命令 |
|------|---------|------|
| AddressSanitizer | UAF, double free, buffer overflow | `-fsanitize=address` |
| UndefinedBehaviorSanitizer | 整数溢出, null deref | `-fsanitize=undefined` |
| Valgrind | 内存泄漏, 未初始化内存 | `valgrind --leak-check=full` |
| CodeQL | 静态分析 (CI) | GitHub Actions |

## 九、CI/CD 集成

1. **每次 PR/commit** — CodeQL 扫描
2. **Critical/High 告警** — 阻断合并
3. **Medium 告警** — 记录警告
4. **定期扫描** — 检测新发现的漏洞模式
5. **禁止内联取消注释** — 不允许 `// lgtm[skip]`

## 十、Checklist

提交代码前确认:

- [ ] 所有内存分配都有对应的释放
- [ ] 释放后指针置为 NULL
- [ ] 所有数组访问有边界检查
- [ ] 所有整数运算有溢出检查
- [ ] 所有外部输入经过验证
- [ ] 不使用 system() / popen()
- [ ] 文件路径经过 realpath() 验证
- [ ] 密码使用标准哈希算法存储
- [ ] 安全令牌使用 /dev/urandom 生成
- [ ] 无硬编码密钥/凭据
- [ ] printf-like 函数使用固定格式字符串
- [ ] 编译无警告（-Wall -Werror）
- [ ] CodeQL 扫描无新增告警
- [ ] 单元测试通过
