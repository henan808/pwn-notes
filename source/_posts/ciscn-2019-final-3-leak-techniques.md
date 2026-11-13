---
title: "ciscn_2019_final_3：四种流派怎么泄露 libc"
date: 2026-11-13 17:50:00
categories:
  - 题目复现
  - CISCN
tags:
  - glibc2.27
  - tcache
  - UAF
  - unsortedbin
  - BUUCTF
---

> 平台：BUUCTF 收录 · CISCN 2019 决赛
> 环境：C++ 64 位，保护全开，glibc 2.27 早期版（无 tcache `key` / double free 检查）
> 漏洞：`delete` 不清空指针（UAF）
> 约束：`idx <= 0x18`（25 次 add）、`size <= 0x78`、无 `show`

## 一、题面里最要紧的一句话

唯一输出是每次 `add` 打印的 `gift`，而它打印的是 **malloc 的返回值**，不是堆块内容。所以「泄露 libc」在这题里不是「读出 fd」，而是**让某次 malloc 直接返回一个 libc 地址，让程序自己打印出来**。

## 二、三条件模型

不管哪一派，都必须同时满足：

1. **造一个 `fd/bk = main_arena+96` 的 unsorted bin chunk** —— libc 地址的唯一来源。
2. **把这个地址放到某条 tcache `entries` 链上，充当 `next`** —— 搬运。
3. **连续两次同尺寸 malloc**，第二次的返回值被 `gift` 打印 —— 出口。

`tcache_get` 在 2.27 早期不校验目标地址是否合法，链上是 libc 地址就会把它当 chunk 返回。条件 ③ 四派完全一样，**差异全在 ① 和 ②**。

## 三、四个流派

| 派 | 怎么造 unsorted bin（①） | 怎么搬指针（②） | 代表 |
|---|---|---|---|
| A | tcache dup 把 chunk0 的 size 伪造成 `0x421`（> tcache 上限 `0x410`） | `add(0x78)` 切割 unsorted bin，remainder 的 `fd` 正好落在另一个 chunk 的 `next` 上 | 博客园 PYozo_free、CSDN mcmuyanga |
| B | 伪造 `0xa1`，`free` 同一块 8 次：前 7 次填满 tcache，第 8 次走 `_int_free` 进 unsorted | **不切割**：同一格内存既是 unsorted bin 的 `fd`，又是 tcache[0x30] 节点的 `next` | xia0ji233 |
| B' | 同 B | 切割：`free(2)×2` 先埋 tcache[0x80] 跳板，`add(0x18)` 切走 `0x20`，remainder 的 `fd` 写进 chunk2 的 `next` | azraelxuemo（CSDN 123405694） |
| C | 填满 tcache → fastbin `A→B→A` → **stash** 把 fastbin 倒回 tcache → 劫持 `tcache_perthread_struct` | `free(struct)` 让它自己进 unsorted bin，而 struct 开头同时就是 `entries` 区域 | arttnba3、isolator-1 |
| D | 篡改 `counts` 让小尺寸也「假装满」，或劫持 struct 后 `free` 自身 | 手工改 `fd` 把 unsorted bin 地址排队进 tcache 链，或靠一次精算切割 | yichen、FreeBuf |
| E | 不伪造任何 chunk size：改 `counts` 让 `0x250` 档绕开 tcache，`free` struct 自身 | `add(0x30)` 切割后 remainder 用户区 = `entries[0]`，`fd` 直接覆盖链头 | 本次新增的 struct 版 |

所有派最后都是 `__free_hook = system` + `free("/bin/sh")`（或 `__malloc_hook = one_gadget`）。Full RELRO 下 GOT 不可写，只能打 hook。

## 四、两个最容易抄错的数字

**偏移换算**：`main_arena = __malloc_hook + 0x10`，`leak = main_arena + 96`，2.27 ubuntu 的 `__malloc_hook = 0x3ebc30` → `libc_base = leak - 0x3ebca0`。换 libc 就变，稳妥写法：

```python
libc_base = (leak & ~0xfff) + (libc.sym['__malloc_hook'] & 0xfff) - 0x70
# 或直接用 LibcSearcher / 对题目 libc 执行 readelf -Ws | grep __malloc_hook
```

**切割尺寸是精算值**：主流版切 `0x80`、azraelxuemo 版切 `0x20`、struct 版切 `0x40`。差一档（比如 `0x18` 换成 `0x28`）remainder 就错开 `entries`，泄露直接断掉。这些数字不是随手挑的，是「让 remainder 用户区正好等于某个 tcache 节点的 `next` 所在地址」算出来的。

## 五、坑点

- **libc 版本是生死线**：2.29+ 有 tcache `key` 与 double free 检查，`free(12); free(12)` 直接 abort；后期 2.27 补丁也修了。必须用题目给的 libc，本地复现还要连 `libstdc++`/ld 一起换。
- **伪造 size 必须精确覆盖整数个 chunk**，且后面留一个已分配、非 top 的 chunk 头，否则 `free(): invalid next size` / 与 top 合并。
- **切割前该尺寸 tcache 链必须为空**：否则 malloc 优先从 tcache 取块，根本不进 `_int_malloc`。
- **只有 25 次 add**：stash 版要 19 次才拿到第一次任意写，余量很紧；主流 `0x421` 版约 23 次。
- `gift` 是**用户指针**，所以任意地址分配要写 `heap-0x10`（chunk 头）；`read` 精确读 size 字节，用 `sendline` 多送的换行会污染下一次输入。
- 各 WP 的 `+88 / +96`、`mainarena - 0x18` 等写法互相矛盾，来源是切割尺寸落在 `fd` 还是 `bk` 以及 libc 小版本，最终以题目 libc 实测为准。

## 六、复盘

**四派都在做同一件事：造一个带 libc 指针的 unsorted bin chunk，把这个指针搬到 tcache 的 `next` 上，再让题目亲手把 malloc 的返回值打印出来。** 区别只在「怎么造」和「怎么搬」——「搬」的四种实现分别是切割对齐、同一格内存直接共格、free tcache struct 自身、篡改 counts + 手工改 fd。

> 证据边界：本篇是对全网 12+ 篇公开 writeup 与本地调试截图的机制复盘，未连接靶机、未取得本次 flag；所有偏移需按手上的 `libc.so.6` 重新核对。
