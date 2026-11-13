---
title: "canary"
date: 2026-11-13 19:08:04
categories:
  - "知识点"
  - "堆"
tags: ["canary"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#0 -->
add函数:

![image-20261026185050913](/pwn-notes/images/notes/image-20261026185050913.png)

Puts函数：

![image-20261026185123445](/pwn-notes/images/notes/image-20261026185123445.png)

![image-20261026185220930](/pwn-notes/images/notes/image-20261026185220930.png)

堆溢出，主要就是在这里修改topchunk

<!-- sync-hash: 8903b01ffe59125cbfb2c78983a09806518a78c0020c92990878e51d401577c9 -->
