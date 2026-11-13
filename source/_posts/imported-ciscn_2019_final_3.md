---
title: "ciscn_2019_final_3"
date: 2026-11-11 00:00:00
categories:
  - 题目复现
  - CISCN
tags: [UAF, tcache dup, tcache poisoning, fake chunk size, unsorted bin 切割错位泄露, __free_hook]
---

> 本文由 `tools/import_from_wp.py` 从 `ciscn_2019_final_3.md` 导入，正文未改动。
>
> - 赛事：CISCN 2019 总决赛（BUUCTF 收录）
> - 来源：全网公开 writeup 汇总（见「七、来源清单」）
> - 方向：Pwn / glibc heap exploitation
> - 难度：中等偏难
> - flag：未取得（本次仅做资料检索与 exp 讲解，未连接靶机、未做本地复现）
> - 日期：2026-11-11
> - 技术栈：UAF / tcache dup / tcache poisoning / fake chunk size / unsorted bin 切割错位泄露 / __free_hook / __malloc_hook + one_gadget

<!-- 原始题解元信息保留如上；Hexo 分类/标签见 front matter -->
# ciscn_2019_final_3 题解汇总与 exp 逐段拆解

> 声明：本文是对公开 writeup 的整理与机制复盘。本次会话没有题目附件、没有连接靶机，
> 所有 exp 均来自公开来源，未按本地环境验证；文中所有「成功」表述都是原作者回显的结论，
> 不构成本次复现证据。偏移、one_gadget 必须用题目给的 libc.so.6 重新核对。

## 一、题面

C++ 编写的 64 位堆菜单题，Ubuntu 18.04 + 题目自带 `libc.so.6`（glibc 2.27 早期版本，
**没有 tcache double free 检测**）。`checksec` 保护全开：Full RELRO / Canary / NX / PIE。

两个功能：

| 功能 | 行为 | 约束 |
|---|---|---|
| `add(idx, size, content)` | `malloc(size)` → 读 size 字节写入 → 指针存入全局数组 `0x2022a0 + idx` → **打印 malloc 返回的用户指针（`gift :`）** | `0 <= idx <= 0x18`（共 25 次、不可重复）、`size <= 0x78` |
| `delete(idx)` | `free(ptr[idx])` | **free 后不清空指针** → UAF / 可 double free |

没有 `show`、没有 `edit`。

三条硬约束决定了整道题的形状：

1. **唯一输出是 add 打印的 chunk 地址**。要泄露 libc，只能想办法让某次 `malloc` 返回 libc 里的地址，让程序自己把地址打印出来。
2. **size 上限 0x78** → 最大 chunk size 0x80，永远落在 tcache / fastbin 范围内，正常途径拿不到 unsorted bin chunk。要泄露 libc 就必须**伪造 chunk size**。
3. **Full RELRO** → GOT 不可写，收尾只能打 `__free_hook` / `__malloc_hook`。

## 二、思路（主流解，四阶段）

```
UAF/double free → 任意地址分配 → 改写 chunk0 的 size 域
        ↓
free 大 chunk → 进 unsorted bin（fd/bk = main_arena+96）
        ↓
切割 unsorted bin，让剩余块的开头与一个已在 tcache 链里的小 chunk 对齐
→ main_arena 地址被当成该 tcache chunk 的 next 指针
→ 再 malloc 两次，第二次返回 libc 地址，被 gift 打印 → 泄露 libc
        ↓
再来一次 tcache dup → 写 __free_hook = system（或 __malloc_hook = one_gadget）→ getshell
```

核心矛盾：题目不给 show，却给「每次 malloc 的地址」。于是一切手段都服务于
**把 libc 地址塞进 tcache 的 next 链**，让 malloc 把 libc 地址当堆块返回。

## 三、关键步骤

以 PYozo_free（博客园）/ mcmuyanga（CSDN）这一版最清晰的 exp 为基准。

### 阶段 0：堆布局，`heap = add(0, 0x78, 'a')` 拿到堆地址

```python
heap = add(0, 0x78, b'a')     # chunk0, size 0x80 —— 后面要被伪造成大 chunk
add(1, 0x18, b'b')            # chunk1, size 0x20 —— 泄露用的「错位」小 chunk
for i in range(2, 12):
    add(i, 0x78, b'c')       # 10 个 0x80 chunk，给伪造大 chunk 当「身体」和边界
add(12, 0x28, b'd')          # 0x30 chunk，double free 的牺牲品
```

`gift` 返回的是 **用户指针**，chunk 头在 `heap - 0x10`。

### 阶段 1：tcache dup → 任意地址分配 → 伪造 size

```python
delete(12); delete(12)                    # 2.27 早期无 tcache key 检查，可直接 free 两次
add(13, 0x28, p64(heap - 0x10))          # 取回 chunk12，把它的 next 改成 chunk0 的 chunk 头
add(14, 0x28, p64(heap - 0x10))          # 第二次取回同一个 chunk12（自环）
add(15, 0x28, p64(0) + p64(0x421))       # 第三次 malloc 返回 heap-0x10 → 写 prev_size=0, size=0x421
```

`tcache_put/get` 是 FILO 单链表，2.27 的 `tcache_get` 不校验目标地址：
free 两次后 `entries[0x30] → chunk12 → chunk12`；第一次取出并改写 `next`，
第二次取出后 `entries` 就指向我们写的 `heap-0x10`，第三次分配即落到 chunk0 头部。

`0x421` = `0x420 | PREV_INUSE`。它必须**精确等于从 chunk0 开始连续若干 chunk 的总长度**：
`0x80(chunk0) + 0x20(chunk1) + 7*0x80 = 0x420`。
因为 > `0x410`（tcache 最大 bin），free 时绕过 tcache 直接进 unsorted bin。
后面多申请的 3 个 0x80 chunk 是为了让 `nextchunk` 落在合法已分配堆块上，
避开 `free(): invalid next size` / `next chunk exceeds arena` 检查 —— 这正是博客园那篇标题的坑。

各 WP 的伪造 size 不同只是布局不同：`0x461`（zylxixixi，覆盖 chunk0~8）、
`0x4a1`（FreeBuf treebacker）、`0x451`（isolator-1）、`0xa1`（xia0ji233，
配合连续 free 8 次填满 tcache 让 0xa0 尺寸的块进 unsorted bin）。

### 阶段 2：unsorted bin 与 tcache 错位 → 泄露 libc（本题最精妙的一步）

```python
delete(0)                      # 大 chunk 进 unsorted bin，fd/bk = main_arena+96
delete(1)                      # chunk1 (0x20) 进 tcache；物理上它在 unsorted chunk 内部
add(16, 0x78, b'e')            # 从 unsorted bin 切割 0x80
leak = add(18, 0x18, ...)      # 中间 add(17) 取回 chunk1；add(18) 返回 libc 地址
libc_base = leak - 0x3ebca0
```

机制：从 unsorted bin 切走 0x80 后，**剩余块被重新挂回 unsorted bin**，
其 `fd/bk` 写入 `main_arena+96`。剩余块的起点正好是 chunk1 的 chunk 头，
于是 `main_arena+96` 落在 **chunk1 用户区的前 8 字节**，也就是 chunk1 的 tcache `next` 上。
此时 tcache[0x20] 链变成 `chunk1 → main_arena+96`：
第一次同尺寸 malloc 返回 chunk1，第二次就返回 `main_arena+96`（libc 内地址），
而 add 会把这个地址通过 `gift` 打印出来 —— 泄露完成。

偏移的等价写法（更抗 libc 小版本差异）：

- `main_arena = __malloc_hook + 0x10`
- `leak = main_arena + 96 = libc_base + __malloc_hook + 0x70`
- glibc 2.27 ubuntu 里 `__malloc_hook = 0x3ebc30`，故 `leak - libc_base = 0x3ebca0`
- 稳妥写法：`malloc_hook = (leak & ~0xfff) + (libc.sym['__malloc_hook'] & 0xfff)`，
  再 `libc_base = malloc_hook - libc.sym['__malloc_hook']`（yongbaoii 版），
  或直接用 LibcSearcher。

### 阶段 3：再打一次 tcache dup，写 hook

路线 A（`__free_hook = system`，多数 WP）：

```python
delete(3); delete(3)
add(19, 0x78, p64(free_hook))
add(20, 0x78, p64(free_hook))
add(21, 0x78, p64(system_addr))
add(22, 0x78, b'/bin/sh\x00')
delete(22)                     # __free_hook(ptr) == system("/bin/sh")
```

路线 B（`__malloc_hook = one_gadget`，mcmuyanga / yongbaoii）：

```python
free(5); free(5)
add(19, 0x78, p64(malloc_hook)); add(20, 0x78, p64(malloc_hook))
add(21, 0x78, p64(libc_base + 0x10a38c))   # one_gadget，按实际 libc 重算
# 再触发一次 malloc 即 getshell
```

## 四、核心脚本

见同目录 `exp_ciscn_2019_final_3.py`：整合主流解法、带 local/remote 切换与逐段注释。

parameter 说明：

```
python3 exp_ciscn_2019_final_3.py local  ./ciscn_final_3 ./libc.so.6
python3 exp_ciscn_2019_final_3.py remote node5.buuoj.cn 29058 ./libc.so.6
```

## 五、坑点 / 失败路径

1. **libc 版本是生死线**。glibc 2.29+ 引入 `tcache key`（bk 指向 tcache struct）与
   double free 遍历检查，`free(12); free(12)` 直接 abort；2.27-3ubuntu1.x 后期补丁版也修了。
   有 WP 明确写「连 ubuntu18.04 的 libc 都不行，必须用题目给的」。
2. **C++ 二进制换 libc 更麻烦**：除了 libc 还要换匹配的 `libstdc++`、ld，
   否则本地复现不起来（xia0ji233、2301_79326813 都专门写了更换方法）。
3. **伪造 size 必须精确覆盖整数个 chunk**，且后面要有合法 chunk 头，否则
   `free(): invalid next size (fast)` / `next chunk exceeds arena`。
   博客园那篇的标题就是这条。xia0ji233 的建议：让小堆块**完全**被大堆块包含。
4. **add 次数只有 25 次**（idx ≤ 0x18）。arttnba3 数过：stash 版要 19 次才拿到
   第一次任意地址写，只剩 4 次机会，必须精算。
5. **`gift` 是用户指针不是 chunk 头**，所以任意地址分配要写 `heap - 0x10`。
6. **`send` vs `sendline`**：题目用 `read(0, ptr, size)` 精确读，多送的 `\n` 会污染下一次输入；
   覆盖 fd 时也应只写必要字节，别写满破坏相邻数据。有 WP 特意只写 `b'\x00'`
   去修 `main_arena+88` 的低字节。
7. **`0x3ebca0` 不是通用常量**，换 libc 就变；LibcSearcher / 页对齐技巧更稳。
8. **Full RELRO** ⇒ 只能打 hook，不能改 GOT。
9. **失败路径记录**：2301_79326813 试过收尾用 `__malloc_hook` 没成功
   （「我尝试过用修改malloc来解题，但没试出来」），改 `__free_hook` 才通；
   isolator-1 提到 tcache struct 路线里「0x40 改 0x50 也行、改 0x70 就不对」尚未想明白；
   yichen 最初想用 IO 泄露，后来才意识到 `gift` 才是唯一出口。
10. **别误读 `0;cat flag`**：mcmuyanga 版最后 `sendline('0;cat flag')` 是**size 输入**，
    不是命令注入；`atoi` 得到 0，`malloc(0)` 触发 `__malloc_hook` 上的 one_gadget 而已。
    getshell 后要自己 `cat /flag` 或 `cat flag.txt`。

## 六、复盘：四种流派

| 流派 | 关键手法 | 代表来源 | 适用/特点 |
|---|---|---|---|
| A 主流 | tcache dup 伪造 `0x421` 等大 size → unsorted/tcache 错位泄露 → hook | PYozo_free、mcmuyanga、yongbaoii、zylxixixi、FreeBuf、CSDN 2301 等 8+ 篇 | 最短、最易读，依赖无 double free 检测的 2.27 |
| B 填满 tcache | 伪造较小 size `0xa1`，靠连续 free 8 次填满 tcache 让块落进 unsorted bin | xia0ji233、CSDN 2301_79326813 | 不需要 >0x410 的大 size，堆布局更紧凑 |
| C stash 绕过 | 不用 tcache dup，fastbin `A→B→A` double free + tcache stash 把块倒回 tcache → 劫持 `tcache_perthread_struct`(0x250) → free 它进 unsorted bin 泄露 | arttnba3、isolator-1 转述 | 可对抗有 double free 检测的新 libc；次数极紧 |
| D 劫持 tcache 结构 | 把 fd 改到 `heap_base+0x10`，篡改 `counts` / `entries`，或直接 house of spirit 改 size | yichen（腾讯云/看雪）、FreeBuf treebacker | 路径最绕，但对理解 tcache 布局帮助最大 |

一句话总结这道题的考点：**当程序只肯告诉你「malloc 返回了哪里」时，就把 libc 地址伪装成一个
即将被 malloc 返回的堆块**。

## 七、来源清单

| # | 来源 | 链接 | 备注 |
|---|---|---|---|
| 1 | PYozo_free（博客园，2020-11） | https://www.cnblogs.com/pppyyyzzz/p/14040210.html | 最清晰的 `0x421` + `__free_hook` 版；标题即 nextchunk 坑 |
| 2 | mcmuyanga（CSDN，2021-03） | https://blog.csdn.net/mcmuyanga/article/details/113995633 | tcache 结构讲解 + `0x421` + `__malloc_hook`+one_gadget 版 |
| 3 | yichen（腾讯云开发者社区 / 看雪，2020-10） | https://cloud.tencent.com/developer/article/1732424 、 https://bbs.kanxue.com/thread-262480.htm | 劫持 tcache struct 路线，含大量调试心路 |
| 4 | yongbaoii（CSDN，2021-02） | https://blog.csdn.net/yongbaoii/article/details/113812564 | 页对齐算 `__malloc_hook` 的技巧、overlap 配图 |
| 5 | xia0ji233（2021-11） | https://xia0ji233.pro/2021/11/01/ciscn2019_final_3%20writeup | `0xa1` + 填满 tcache 版；C++ 换 libc 提示 |
| 6 | CSDN 2301_79326813（2024-02） | https://blog.csdn.net/2301_79326813/article/details/136122825 | 明确 libc 为 GLIBC 2.27-3ubuntu1、 LibcSearcher 版 |
| 7 | zylxixixi（CSDN，2021-10） | https://blog.csdn.net/zylxixixi/article/details/120659051 | `0x461` 版；讲清 unsorted bin 切割写 fd/bk |
| 8 | FreeBuf / treebacker《Tcache Attack 总结》（2019-10） | https://www.freebuf.com/vuls/217458.html | 最早一批公开分析，`0x4a1` + house of spirit |
| 9 | arttnba3《PWN.0x01 Glibc heap exploit》（2021-05） | https://arttnba3.cn/2021/05/10/PWN-0X01-GLIBC_HEAP-EXPLOIT | stash + fastbin double free + 劫持 tcache struct，例题 2 |
| 10 | isolator-1《tcache poisoning》（2023-12） | https://isolator-1.github.io/2023/12/01/ctf-pwn/tcache%20attack/ | 「没有 show 如何泄露」的思路推演，含 stash 版 |
| 11 | CSDN m0_73756460（2023-03） | https://blog.csdn.net/m0_73756460/article/details/129640158 | `tcache_get` 源码级解释；正文后半被付费墙截断 |
| 12 | CSDN zylxixixi / mcmuyanga 的转载镜像 | http://www.chinadongda.com/j?mcmuyanga/article/details/113995633 | 镜像站，内容同上 |
| 13 | BUUCTF 题目页 | https://buuoj.cn/challenges#ciscn_2019_final_3 | 靶机与附件入口，动态 flag |

检索结论：中文社区这道题的 writeup 高度同源（多数可追溯到 2019 年 FreeBuf 那篇与
2020 年博客园/看雪那几篇），差异集中在伪造 size 的取值、泄露偏移的写法、
以及收尾用 `__free_hook` 还是 `__malloc_hook`。**没有检索到独立的英文 writeup**。

## 八、专题：libc 泄露机制的统一模型与四流派对照

### 8.1 题眼：gift 打印的是 malloc 的返回值，不是堆块内容

程序没有 `show`，不打印任何堆块内容；`add` 里的 `printf("gift : %p", ptr)` 打印的是
`malloc` 返回的**用户指针**。因此「泄露 libc」不是「读出 unsorted bin 的 fd 字段」，
而是「**让 malloc 的返回值本身变成 libc 地址**」。

tcache 的 `entries[tc_idx]` 链表里存的就是「下一个待返回的用户指针」，`tcache_get`
直接把它返回，2.27 早期不校验该地址是否合法。所以只要链上出现一个 libc 地址，
那次 `add` 就会把这个地址通过 `gift` 打印出来。这是全部流派的共同出口。

### 8.2 三条件模型

| 条件 | 内容 | 为什么难 |
|---|---|---|
| ① libc 地址来源 | 需要一个 `fd/bk = main_arena+96` 的 **unsorted bin chunk** | `size <= 0x78` → 最大 0x80，永远进 tcache/fastbin；free 进 tcache 只写 `next`（堆地址或 NULL），不写 libc 指针 |
| ② 传送通道 | 让这个 libc 地址出现在某条 tcache `entries` 链上，充当 `next` | 需要 unsorted bin 的 `fd` 与某个已 free tcache chunk 的 `next` **落在同一格内存** |
| ③ 输出通道 | 连续两次同尺寸 malloc，第二次由 `gift` 打印 | 只有 25 次 add，且中途不能把链弄断 |

`_int_free` 把块插入 unsorted bin 时写 `fd = bk = unsorted_chunks(av) = main_arena + 96`；
`main_arena` 是 libc 的全局变量，所以这个指针天然就是 libc 地址。
`_int_malloc` 从 unsorted bin **切割**时，剩余块要重新挂回 unsorted bin，
于是 `fd/bk` 被写到**新的剩余块开头** —— 这就是条件 ② 可利用的「地址搬家」。

另有一个隐含前提：能触发 unsorted bin 切割，必须**该尺寸的 tcache 链为空**，
否则 malloc 优先从 tcache 取块。主流 exp 里 `add(16, 0x78, ...)` 之前从不 free 0x78 的块，
正是为此。CSDN 2301_79326813 也明写「因为 tcachebin 里没有类似大小的堆块，所以可以切割」。

### 8.3 四流派分别怎么满足条件 ① ②

**A · 伪造大 size（0x421 / 0x461 / 0x4a1，8+ 篇）**
- ① `tcache dup` → 分配到 `heap-0x10` → 把 chunk0 的 size 改成 `0x421`（> 0x410，
  tcache 最大 bin 之外），`delete(0)` 直接绕过 tcache 进 unsorted bin。
- ② 布局时让 chunk1(0x20) 紧跟 chunk0(0x80)，`delete(1)` 让它进 tcache[0x20]；
  再 `add(0x78)` 从 unsorted bin 切走 0x80，剩余块开头恰好 = chunk1 的 chunk 头，
  挂回时写的 `main_arena+96` 正好落在 chunk1 用户区前 8 字节 = 它的 tcache `next`。
- ③ `tcache[0x20]` 变成 `chunk1 → main_arena+96`；第一次 0x18 malloc 取回 chunk1，
  第二次返回 `main_arena+96` 并被打印。

**B · 小 size + 填满 tcache（0xa1，xia0ji233 / CSDN 2301_79326813）**
- ① 不追求 >0x410：伪造 `0xa1`（0xa0 > fastbin 上限 0x80，但仍在 tcache 范围内），
  然后 **连续 `free(0)` 8 次**把 0xa0 的 tcache 链填满 7 个，第 8 次 free 时
  `tcache_put` 的 `count < 7` 不成立，块走 `_int_free` → 因尺寸属 smallbin 范围而进
  **unsorted bin**。能连 free 同一块 8 次，靠的仍是 2.27 早期无 tcache key 检查。
- ② 同样靠切割错位，但这一派多了两步调试技巧：`alloc(6, 0x10, ...)` 切割后
  用 `alloc(7/8, 0x70, b'\x00')` **只写一个字节**去修残留指针的低位
  （作者注释「main_arena+88 的最后一个字节相对固定」，属部分写修指针）。
- ③ 连续两次同尺寸 malloc，第二次 `gift` 打印；这一派用 `LibcSearcher`
  按 `__malloc_hook` 反查 libc，而不是硬编码 `0x3ebca0`。

**C · stash + 劫持 tcache struct（arttnba3 / isolator-1）**
- ① **完全不伪造 size**：`tcache_perthread_struct` 本身大小 `0x250`（2.27），
  大于 fastbin 上限，直接 `free(20)` 就进 unsorted bin，其 `fd/bk = main_arena+96`。
  拿到它的方式是填满 tcache → `free(7);free(8);free(7)` 做 fastbin `A→B→A`
  double free → 消耗 tcache 触发 **stash** 把 fastbin 剩余块倒回 tcache →
  污染 `next` 指向 `heap_base+0x10` → 分配到 tcache struct 并控制 `counts/entries`。
- ② 巧妙之处：tcache struct 被 free 后，**它自己的内存开头被改写成 fd/bk**，
  而它同时正是 `entries[]` 指向的位置 —— 所以 `next` 天然变成了 libc 地址，
  不需要再手工做「切割对齐」。这仍然是条件 ② 的另一种实现，内核没变。
- ③ `new(21,0x20)`、`new(22,0x20)` 沿被污染的链取两次，第二次 `gift` 打印
  `libc_leak`，`libc_base = libc_leak - 0x3ebca0`。

**D · 篡改 counts 假装满 / house of spirit（yichen 腾讯云+看雪、FreeBuf treebacker）**
- ① yichen 走的是另一条：把 tcache struct 的 `counts` 全写成 `0x61`（'a' ≥ 7），
  让 glibc **误以为每条链都满了**，于是连 `0x100` 的小 chunk 被 free 时也不进 tcache、
  直接进 unsorted bin。等价于「用软件状态绕过 tcache」而非「用尺寸绕过」。
- ② 他手工把 double free 块的 `fd` 改回「刚才释放的那个」，强行把 unsorted bin
  的地址排队进 tcache 链（文中原话「强行排队」）。
- ③ 第三次 malloc 落到 unsorted bin 处，`gift` 得到 `main_arena+96`，
  `libc_base = main_arena_addr - 0x10 - libc.sym['__malloc_hook']`。
  FreeBuf treebacker 版则是 `0x4a1` 大 size + `add(15/16, size=0, ...)` 用空块错位，
  本质与 A 相同，只是错位载体换成 size=0 的 0x20 块。

### 8.4 泄露值的换算与各 WP 的分歧

统一关系：`main_arena = __malloc_hook + 0x10`，`leak = main_arena + 96`，
2.27 ubuntu 的 `__malloc_hook = 0x3ebc30` ⇒ `leak - libc_base = 0x3ebca0`。

但各 WP 拿到的并不总是同一个值：

- 多数 WP：`leak = main_arena+96`，`libc_base = leak - 0x3ebca0`。
- 腾讯云 / isolator-1：`main_arena_addr = gift - 96`，再减 `__malloc_hook + 0x10`。
- CSDN 2301_79326813：拿到的是 `mainarena+88`（切割尺寸不同，落在 `bk` 或另一格），
  且用 `mallochook = mainarena - 0x18`，作者自己承认「这些地方是根据习惯去写的，
  实际可能不准，但最后的 mallochook 肯定是对的」。
- yongbaoii 的稳妥写法（页内偏移固定，抗 libc 小版本差异）：
  `malloc_hook = (leak & ~0xfff) + (libc.sym['__malloc_hook'] & 0xfff)`，
  `libc_base = malloc_hook - libc.sym['__malloc_hook']`。

结论：`+96/+88`、`-0x10/-0x18` 的分歧来自**切割尺寸不同导致落在 fd 还是 bk**
以及不同 2.27 小版本的符号偏移。可靠做法是页对齐技巧或 LibcSearcher，
并对着题目给的 `libc.so.6` 用 `readelf -s | grep __malloc_hook` 核对。

### 8.5 一句话复盘

> 所有流派都在做同一件事：**造一个带 libc 指针的 unsorted bin chunk，
> 把这个指针「搬」到 tcache 的 `next` 上，再让题目亲手把 malloc 的返回值打印出来**。
> 差异只在「怎么造 unsorted bin」和「怎么搬指针」，
> 而「搬」的四种实现分别是：切割对齐（A/B）、free tcache struct 自身（C）、
> 篡改 counts + 手工改 fd（D）。

## 九、专题：azraelxuemo 版（2022-03-10）与两处归类更正

来源：https://blog.csdn.net/azraelxuemo/article/details/123405694
《linux_pwn(6)--tcache&&double free&&ciscn_2019_final_3》，作者自述「网上普遍用的是
修改大小超过 0x400 进 unsorted bin，我第一次也是用这个打的，现在讲的是另一种解法」。

### 9.1 定位：B 派造 bin + A 派搬运 = 混合派

| 环节 | 主流 0x421（博客园） | xia0ji233（用户复现版） | 本文 azraelxuemo |
|---|---|---|---|
| 造 unsorted bin | 伪 `0x421`，一次 free | 伪 `0xa1` + free ×8 | 伪 `0xa1` + free ×8 |
| 伪造对象 | chunk0 (0x80) | chunk0 (0x20) | **chunk1 (0x20)** |
| 指针怎么到 `next` | 切割，剩余块 fd 落在 chunk1 | **不切割**，第 8 次 free 直接写同一格 | 切割，剩余块 fd 落在 chunk2 |
| 泄露档位 | `0x20`（add 0x18 ×2） | `0x30`（add 0x28 ×2） | `0x80`（add 0x78 ×2） |
| add 次数 | 约 23 次（逼近 25 上限） | 16 次 | **13 次** |

**更正 8.3 节 B 派的描述**：xia0ji233 那版并不靠「切割错位」，而是同一块 chunk0 既挂在
tcache[0x30]、又是 unsorted bin 块，`C0+0x10` 这一格同时是 `next` 和 `fd`，第 8 次 free
一步写成 `main_arena+96`。真正用「切割对齐」的 B 派是本文 azraelxuemo 版。

### 9.2 堆地址表（C0 = chunk0 头 = heap_0_addr - 0x10）

| 地址 | 内容 |
|---|---|
| `C0+0x00` | chunk0，size 0x20（第一次 dup 的牺牲品） |
| `C0+0x20` | chunk1 头，size 被 `add(5)` 改成 **0xa1**；伪造大块起点 |
| `C0+0x30` | chunk1 用户区 = unsorted bin 的 `fd`（8 次 free 后为 `main_arena+96`） |
| `C0+0x40` | chunk2 头，size 0x80；切割后剩余块的起点 |
| `C0+0x50` | chunk2 用户区 = tcache[0x80] 节点的 `next` ← **泄露的关键共格** |
| `C0+0xc0` | `add(6,0x18)` 隔离块（0x20），正好是伪造 0xa0 的 `nextchunk` |
| `C0+0xe0` | top chunk |

`chunk1(0x20) + chunk2(0x80) = 0xa0` 就是 `0xa1` 的跨度；作者原文
「0x18+0x78 的大小是 0x20+0x80=0xa0」算的是这两块，不含 chunk0。

### 9.3 泄露链（与 8.2 三条件模型对照）

1. `free(2); free(2)` → chunk2 提前挂进 tcache[0x80]，自环 `count=2`（条件 ② 的载体）。
2. `for i in range(8): free(1)` → 前 7 次填满 tcache[0xa0]，第 8 次进 unsorted bin，
   `fd/bk = main_arena+96` 写到 `C0+0x30/38`（条件 ①）。
3. `add(7, 0x18, ...)` → tcache[0x20] 已空（第一次 dup 消耗完、`add(6)` 从 top 分配），
   **必然**从 unsorted bin 切走 0x20；剩余 0x80 块 @ `C0+0x40` 挂回 unsorted bin 时
   `fd/bk` 写到 `C0+0x50/58` —— 正好是 chunk2 的 `next`（条件 ② 的「地址搬家」）。
   无论 glibc 走 `last_remainder` 分支还是 binmap 扫描分支，剩余块挂回 unsorted bin 都写
   `unsorted_chunks(av)`，机制成立。
4. `add(8, 0x78)` 取走 chunk2；`add(9, 0x78)` 的 `tcache_get` 直接返回 `main_arena+96`，
   `gift` 打印（条件 ③）。`libc_base = leak - 0x3ebca0`。

**为什么 0x18 不能改成 0x28**：切 0x30 会让剩余块落在 `C0+0x50`、fd 写到 `C0+0x60`，
错开 chunk2 的 `next`，泄露断掉。这是「尺寸精算」而非随便挑档位。
**为什么 free(2) 要提前**：切割写入的 libc 地址只有落在已挂链的块的用户区才有意义。
free 两次只是让 `count` 非负、链更干净，理论上一次也够（2.27 只看 `entries != NULL`）。

### 9.4 原文的可疑写法 / 照抄会踩的坑

1. `libc_base = int(rld(),16) + 0x7F2DEB7F2000 - 0x7F2DEBBDDCA0`：看似写死 gdb 的
   ASLR 绝对地址，实为调试残留的**常量差**——`0x7F2DEBBDDCA0 - 0x7F2DEB7F2000 =
   0x3EBCA0`，与 ASLR 无关，等价于 `leak - 0x3ebca0`，功能正常；但换 libc 必须重算。
   建议 `leak - (libc.sym['__malloc_hook'] + 0x70)`。
2. `from LibcSearcher import LibcSearcheronline`（拼写异常）、`libc_23_gadget`
   （glibc 2.23 的 one_gadget）全文未使用，属模板残留；收尾用 `__free_hook + system`，
   与 one_gadget 无关。
3. `libc_path = elf.linker.decode().replace("ld", "./libc")` 依赖作者本地 patchelf 的
   目录约定，不通用；直接 `ELF('./libc.so.6')` 更稳。
4. `sla(..., b"")` 实际发 `\n`。这版 payload 都极短，`read(0,ptr,size)` 会把换行一起
   读进 buf、不残留 stdin；代价是 `add(9)` 往 `main_arena+96` 写一个 `0x0a`。已拿到
   leak 且后续全走 tcache / `__free_hook`，无碍。**但若把 payload 改成填满 size，
   sendline 就会污染下一次输入**——这正是 xia0ji233 版必须用 `sendafter` 的原因。
   整理版脚本把空内容改为 `b'\x00'`（read 至少收到 1 字节才返回，发 `b''` 会卡死）。
5. 文中「marene+88」是泛泛说法，本版实际为 `main_arena+96`；见 8.4 的偏移分歧。
6. `free(0)×3` 而非 ×2：让三次 `tcache_get` 后 count 归 0 更干净；×2 会得到 -1，
   pwndbg 显示怪但 2.27 不检查 count，照样能跑（用户复现版即如此）。
7. 作者截图提到「作为 unsorted bin free 时会把后面块 prev_inuse 清空」，是
   `clear_inuse_bit_at_offset` 的副作用；后续分配全走 tcache，不影响利用。

### 9.5 交付与边界

见同目录 `exp_ciscn_2019_final_3_azraelxuemo.py`：按原文逻辑重写，修正上述 1/2/3/4，
带 local/remote 参数、逐段堆状态注释与 `libc.sym` 校验。**该脚本为静态整理，
未在附件/靶机上复现，未取得 flag**；`LEAK_OFF`、`__free_hook`、`system` 偏移必须按
题目给的 `libc.so.6` 核对。

---

## 十、第五种解法：直接劫持 tcache_perthread_struct（用户提供版 exp）

### 10.1 定位

不伪造任何 chunk size；用 tcache dup 把 malloc 返回到 `tcache_perthread_struct`
用户区，篡改 `counts`，再 `free` struct 自身进 unsorted bin，最后用一次精确切割
把 `main_arena+96` 写到 `entries[0]`。等价于 **C 派（free struct 自身）+ D 派（改 counts
假装满）的混合简化版**，但不需要 fastbin stash，只依赖 2.27 无 tcache `key` 检查。
全链 13 次 add，远低于 25 次上限。

### 10.2 前置：本地启动模板（中文标识符）

- 三种启动方式：`修补`（patchelf 产物）/ `加载器`（题附 ld + `--library-path`）/ `自动`。
  **C++ + 旧 libc 必须用「加载器」**：patchelf 只换 interpreter，`libstdc++.so.6`、
  `libgcc_s.so.1` 仍会从系统加载，其 `GLIBC_2.3x` 符号要求与题附 2.27 冲突。
- `--library-path` 顺序为 `题目目录:库目录`：题附 `libc.so.6` 优先，库目录补 C++ 运行库。
- `args.REMOTE` / `args.GDB` 为 pwntools 命令行开关；`libc = ELF(库文件)` 必须用题附 libc
  取 `__free_hook` / `system` 偏移。
- `add()` 用 `sendafter(b'now you can write something\\n', ...)` 而非 `sendline`：
  程序 `read()` 精确读 size 字节，多送换行会污染下一次 `> `。
  等待串写 `b'> '` 是 `choice >` 的子串，可匹配。

### 10.3 利用链（heap = struct chunk 头）

| 幕 | 代码 | 堆状态 |
|---|---|---|
| 1 | `add(0..3,0x60)` → `delete(0..3)` | tcache[0x70]：U3→U2→U1→U0，count=4 |
| 1 | `add(4,0x60)` | 取回 U3，`gift` 打印；`heap = gift - 0x11fc0`（调试量出的 heap base 差值） |
| 1 | `delete(0)×2` | U0 自环：entries=U0，`U0->next=U0` |
| 2 | `add(5,0x60,p64(heap+0x10))` | 第 1 次 get 返回 U0，写 next=heap+0x10；entries 仍为 U0 |
| 2 | `add(6,0x60,b'a')` | 第 2 次 get 返回 U0，读出 next → entries[0x70]=heap+0x10 |
| 2 | `add(7,0x60,payload)` | **第 3 次 get 返回 heap+0x10 = struct 用户区**，写 payload |
| 3 | `delete(7)` | `free(heap+0x10)`，size=0x251；counts[35]=7 → 跳过 tcache；0x250>0x80 → 进 unsorted bin，`fd/bk=main_arena+96` 写到 heap+0x10/18 |
| 4 | `add(8,0x30,b'\x00'*0x10)` | nb=0x40、tc_idx=2 且 entries[2]=NULL → 切割 0x250 struct；remainder 用户区 = heap+0x50 = **entries[0]**，挂回时写 fd 覆盖链头；同时 16 个 0 清掉被 libc 地址污染的 counts[0..15] |
| 4 | `add(9,0x10,b'\x00')` | nb=0x20、tc_idx=0 → tcache_get 返回 `main_arena+96`，`gift` 打印；`libc_addr = leak - 0x3ebca0` |
| 5 | `delete(1)×2` → `add(10/11/12,0x60)` | 重置被 add(7) 弄脏的 0x70 链；写 `__free_hook = system`，`add(11)` 内容 `/bin/sh\0` |
| 5 | `delete(11)` | `__libc_free` 在 `_int_free` 前检查 hook → `system("/bin/sh")` |

### 10.4 payload 的精确含义

```python
payload = b'\x00'*0x20 + b'\x07'*(64-0x20) + p64(heap+0x40)
```

`64 - 0x20` = 64 − 32 = **32**（十进制 64 减十六进制 0x20），故前 32 + 后 32 = **64 字节，
正好铺满 `counts[64]`**（`char` 数组，每档 1 字节，不是 qword）；末 8 字节落在 `entries[0]`。

- `counts[0..31]`（size 0x20..0x220 的小档）= 0 → 后续小块 free 仍正常进 tcache；
- `counts[32..63]`（size 0x230..0x410 的大档）= 7 → 大块 free 时 `count < 7` 不成立，
  被迫走 `_int_free`。关键档：`tc_idx(0x250) = (0x250-0x20)/0x10 = 35` 落在此区间；
- `p64(heap+0x40)` 只是占位，随后会被 `add(8)` 切割写入的 fd 覆盖。详析：
  - 这一格是 `entries[0]`（`heap+0x50`）；值 `heap+0x40` 既是 `counts[48..55]`
    的地址，也正好是 `add(8)` 切割后 `remainder` 的 **chunk 头**
    （`chunk_at_offset(victim, 0x40)`），而 remainder 的**用户区**才是 `heap+0x50`。
  - 切割时 glibc 写 `remainder->fd = main_arena+96` 到 `heap+0x50`，把这一格整个覆盖；
    `add(9)` 的 `tcache_get` 读到的是覆盖后的值，与 payload 里写了什么无关。
  - 佐证「它不打算被消费」：tcache `entries[]` 存的应是 **用户指针**（`chunk2mem`），
    而 `heap+0x40` 是 chunk 头地址；若真被 `tcache_get` 返回，程序 `read` 会写坏
    刚切好的 `prev_size`/`size`。所以它只是把 `entries[0]` 初始化为非 NULL
    （2.27 只判断 `entries != NULL`），保证切割意外未发生时 `add(9)` 仍走 tcache、
    失败表现稳定，同时把 payload 补齐到 0x48 不留半截数据。
  - 验证：改成 `p64(0)` / `p64(0xdeadbeef)` / 直接删掉，泄露结果不变；或 gdb 里
    `add(7)` 后 `x/2gx heap+0x50` 见 `0x...40`，`add(8)` 后见 `0x7f...ca0`。
  - 常见误读：以为它是「把链头指向剩余块好让 add(9) 返回」。真正把 libc 地址
    搬进 `entries[0]` 的是**切割时 glibc 自己写的 `fd`**，不是这一句。

### 10.5 泄露机制与精算点

与 A 派内核一致（`fd` 搬到 tcache `next`），但「搬」的目标是 **struct 自己的 `entries[0]`**：

1. `delete(7)` 让 struct 自身成为 unsorted bin chunk，`fd/bk` 写在 struct 用户区开头；
2. `add(8,0x30)` 切走 `0x40`，`remainder` chunk 头 @ `heap+0x40`、用户区 @ `heap+0x50`
   = `entries[0]`；剩余块挂回 unsorted bin 时写 `remainder->fd = unsorted_chunks(av)`；
3. 于是 `tcache[0x20]` 的链头直接变成 `main_arena+96`，`add(9,0x10)` 由 `gift` 打印。

**0x30 是精算值**：换 `0x28`（nb=0x30）会让 remainder 用户区落在 `heap+0x40`，
fd 写进 counts 尾部而非 `entries[0]`，泄露断掉。与第九节 azraelxuemo 版的
「`0x18` 不能换 `0x28`」同理。

### 10.6 坑点与失败路径

1. **两处硬编码常量差性质不同**：`0x771f7bdebca0 - 0x771f7ba00000 = 0x3ebca0`
   是 libc 内部固定偏移，与 ASLR 无关、可靠；`0x55558f14cfc0 - 0x55558f13b000 =
   0x11fc0` 是 gdb 会话里量出的 heap base 差值，**依赖启动方式、环境变量、C++ 初始化
   把堆撑到多大**，换 `process`/`gdb.debug`/机器就得重新 `vmmap` 量。这是全版最脆弱处。
2. `counts[35]` 必须 ≥7，否则 struct 进 `tcache[0x250]`，只有堆地址、没有 libc 指针。
3. 前 32 档不能一起设 7：否则 `delete(1)×2` 的 0x70 档（idx=5）也绕过 tcache，
   收尾第二次 dup 做不成。
4. `add(7)` 的 `tcache_get` 会把 `*(heap+0x10)`（旧 counts 前 8 字节）当 `next`
   存进 `entries[0x70]`，把 0x70 链弄脏；**靠 `delete(1)×2` 重置链头躲过**，
   少 delete 一次或改顺序就会踩非法地址。
   - **容易漏的副作用**：`delete(7)` 的 `fd/bk = main_arena+96` 写在
     `heap+0x10/0x18`，也就是 `counts[0..15]`；小端字节 `a0 bc 41 ac d5 7f 00 00`
     让 `counts[0..11]` 全部 ≥7，小档 `tcache_put` 同样会被跳过。
     **`add(8,0x30,b'\x00'*0x10)` 的 16 个 0 正是为了把这段清零**，恢复小档 tcache，
     后面 `delete(1)×2` 才能正常进 tcache 做第二次 dup；否则 0x70 走 fastbin，
     连续两次 free 会触发 `double free or corruption (fasttop)`。
   - 调试截图佐证：`delete(7)` 之后 `heap+0x050` 仍是 `heap+0x40`、`heap+0x010/018`
     变成 `0x7fd5ac41bca0`，说明 fd/bk 落在 counts 而非 entries[0]；
     `add(8)` 之后应看到 `heap+0x010` 归零、`heap+0x050` 变成 `main_arena+96`。
5. `add(9)` 往 `main_arena+96` 写 1 字节 `0`，破坏 bins 一个字节；已拿到 leak 且
   后续只走 tcache / `__free_hook` 故无碍，但之后不能再走 unsorted bin。
6. `add(8)` / `add(9)` 的 payload 只发 16 / 1 字节，而 size 是 0x30 / 0x10：依赖程序
   单次 `read()` 不读满就返回；若程序循环读满 size 会卡死。
7. `bug()` 放在 `io.interactive()` 之前：已经 getshell 再 attach 会挂住等待；
   `REMOTE` 下 `gdb.attach` 会失败；`args.GDB` 已用 `gdb.debug` 起进程，重复 attach。
8. 明确无关项：全链用 `__free_hook + system`，**与 one_gadget 无关**；
   `elf` 只用来启动/取符号，未参与偏移计算。

### 10.7 边界

本节为对用户提供 exp 的**静态机制复盘**：没有题目附件、没有连接靶机、没有运行该脚本，
未取得 flag，也没有 getshell 回显证据。`__free_hook`、`system`、`0x3ebca0`
须按题目 `libc.so.6` 核对；`heap` 差值须在当前启动方式下用 `vmmap` 实测。
