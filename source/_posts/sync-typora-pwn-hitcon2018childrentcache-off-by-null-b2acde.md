---
title: "hitcon2018childrentcache（off by null）"
date: 2026-11-25 10:02:11
categories:
  - "题目复现"
  - "HITCON"
tags: ["unsorted-bin", "double-free", "off-by-null"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#9 -->
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

![image-20261102164658329](/pwn-notes/images/notes/image-20261102164658329.png)

这个是修改成绝对路径成功的

![image-20261102164809384](/pwn-notes/images/notes/image-20261102164809384.png)

检查，还需要泄露libc地址

Ida分析

add函数

![image-20261102165537226](/pwn-notes/images/notes/image-20261102165537226.png)

show函数

![image-20261102165657594](/pwn-notes/images/notes/image-20261102165657594.png)

而off by null漏洞就是看的是strcpy函数来触发的

然后就是那四个堆块，首先释放那个chunk0进入unsortedbin (为了之后修改完相关操作之后，发现是空闲的，因此向前合并)

接下来chunk1,因为申请有先后顺序，所以一开始在申请完之后释放掉，之后再次申请相同大小的堆块，之后利用add函数的添加内容操作进行修改chun2的presize位

首先创建完堆块之后

tcache大小条件：

**`[0x20, 0x410]`**

所以如果好计算地址的话，那么就直接0x4f0,因为增加对头就会补充到0x500

![image-20261102182014196](/pwn-notes/images/notes/image-20261102182014196.png)

接下来释放·chun0和chunk1

![image-20261102182140557](/pwn-notes/images/notes/image-20261102182140557.png)

一个进入unsortedbin 一个进入tcache

接下来再次申请0x58大小的堆块，并且写入数据覆盖到

![image-20261102182614232](/pwn-notes/images/notes/image-20261102182614232.png)

这个是目前chunk1的状态，可以看到其数据区确实是填充到了chunk2的pre_size的位置

然后再次申请和tcashe大小相同的堆块

![image-20261102202426955](/pwn-notes/images/notes/image-20261102202426955.png)

可以看到填充到头部的同时，也将chunk2的低字节改写成了0（strcpy）

现在需要修改chunk2的pre_size位

这里你释放之后再次申请，其实序号会变化，也就是会变成chunk0

噗，自己想通过直接写入修改其0x50-0x58字节，不会试过

所以用的人家的循环写入

![image-20261102204821622](/pwn-notes/images/notes/image-20261102204821622.png)

之后的话直接将大小写入就行

![image-20261102205228954](/pwn-notes/images/notes/image-20261102205228954.png)

就像是这样

之后的话直接freechunk2这样的话，chunk1和chunk0就会合并和chunk2

![image-20261102205453912](/pwn-notes/images/notes/image-20261102205453912.png)

free之后就是这样

这样的话没就把chunk1也包含进去了

![image-20261102210048067](/pwn-notes/images/notes/image-20261102210048067.png)

delete 0之后有申请了一个，有释放掉了2，所以再次申请的话，那么就会成为1

不不不。你把那个原来的chunk0申请完之后，此时那个unsortedbin的头部就会成为原来Index0也就是那个0x60大小头部，所以最后只需要show(0)就可以得到libc地址

所以现在的chunk1的地址在bin中出现，又在没有被free掉的里面出现

![image-20261102211955995](/pwn-notes/images/notes/image-20261102211955995.png)

![image-20261102212008994](/pwn-notes/images/notes/image-20261102212008994.png)

而这个时候如果再释放hcunk1的话，那么就会double free(不对)



应该是再次申请和chunk1大小相同的堆块，然后因为Index0指向它，还有新申请的index2指向他，接着分别释放，就可以

![image-20261102212649648](/pwn-notes/images/notes/image-20261102212649648.png)

就像这样

接着就是将free_hook的地址写入，之后就修改吧

<!-- sync-hash: 4c623b0010d319e6b4cc3be780b7e9a36786d8b5f49a4f8ec2df7a5c665b395d -->
