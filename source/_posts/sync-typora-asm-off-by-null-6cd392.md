---
title: "off by null"
date: 2026-11-13 19:08:03
categories:
  - "知识点"
  - "汇编"
tags: ["tcache", "double-free", "off-by-null"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-asm/汇编语言：.md#1 -->
strcpy函数：复制的时候在末尾会加上/

我觉得就是申请堆块，然后再修改相关size字段之后再次free

四个堆块

![image-20261102161233897](/pwn-notes/images/notes/image-20261102161233897.png)

主要就是将还未释放掉的堆块chunk1进入bin中

*overflow chunk的大小，因为要产生off by null，所以它的大小应该为八字节结尾（例如0x58,0x68,0x78···）*

就主要修改chunk2的presize位和presize的大小，之后触发向前合并，大小需要满足chunk0和chunk1

之后free掉就会包含chunk1































## 2.27

#### tcache

两个结构体

```
tcache_entry`和`tcache_perthread_struct
```

额，现在的话就只是知道在堆块被释放之后，进入对应大小的tcache中，之后相同大小的会在同一块链表中，并且是通过fd指针进行连接的，并且fd链表中是用户数据区起始地址。

第二次：

[Tcache攻击实战：从UAF到任意地址分配的堆利用入门-CSDN博客](https://blog.csdn.net/weixin_29327977/article/details/168277575#:~:text=本文深入解析Tcache堆利用机制，聚焦于UAF漏洞触发下的Tcache,poisoning实战。 详细阐述Tcache与fastbin的底层差异、tcache_entry结构、key字段绕过、异或混淆（safe-linking）计算、double-free构造及任意地址分配的边界条件。)

这个不错，从中看就是。你如果想完成double free 的话，就只需要在释放完之后再次修改其key值。

还有目标地址，你需要进行异或一下。

<!-- sync-hash: e06c870b7326e371ffa333876848970439f604b63a285508cdbbcafbdec5909d -->
