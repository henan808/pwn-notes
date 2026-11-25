---
title: "接收地址"
date: 2026-11-25 10:02:11
categories:
  - "知识点"
  - "栈"
tags: ["canary"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#12 -->
![image-20261118144631002](/pwn-notes/images/notes/image-20261118144631002.png)

下面的一行就是程序输出的内容接下来接收

![image-20261118144831313](/pwn-notes/images/notes/image-20261118144831313.png)

Int（x,16）

将接收的字符串转化为整数

![image-20261118145953395](/pwn-notes/images/notes/image-20261118145953395.png)

接受代码块:

将接受安空格分开，之后再int(x,16)转化

```python
parts=p.recvline().split()
canary=int(parts[0],16)
stack=int(parts[1],16)
laddr=int(parts[2],16)
```

<!-- sync-hash: 60cdc376da0884c305ef0a9b74404fd7cd1e63643537493e0ca8d643cf7a13a7 -->
