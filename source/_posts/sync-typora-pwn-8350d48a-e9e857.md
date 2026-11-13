---
title: "单身杯"
date: 2026-11-13 19:08:05
categories:
  - "题目复现"
  - "单身杯"
tags: []
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#7 -->
## 1.CheckIn

保护全开

![image-20261016231113941](/pwn-notes/images/notes/image-20261016231113941.png)

![image-20261016231136177](/pwn-notes/images/notes/image-20261016231136177.png)

主流程

然后发现一个函数

![image-20261016231229526](/pwn-notes/images/notes/image-20261016231229526.png)

这里似乎是触发，输入字符串

这个jmp跳转的地方好像是rax的值，那个read函数不是读取字符数量会存到rax中吗

<!-- sync-hash: 76dac1e0ecc0323cbb990082a15225e0fa017369c604ab5880491bb1f63fc19e -->
