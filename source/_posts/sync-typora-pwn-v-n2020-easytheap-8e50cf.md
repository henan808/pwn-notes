---
title: "[V&N2020 公开赛]easyTHeap（差一步美满）"
date: 2026-11-13 19:08:05
categories:
  - "题目复现"
  - "V&N"
tags: ["tcache", "unsorted-bin", "double-free", "malloc-hook", "堆风水"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#10 -->
![image-20261105181836066](/pwn-notes/images/notes/image-20261105181836066.png)

edit函数

![image-20261105182749131](/pwn-notes/images/notes/image-20261105182749131.png)

好像是没有限制大小，可以溢出

delete函数：

![image-20261105182900794](/pwn-notes/images/notes/image-20261105182900794.png)

保护依旧全开，还是应该先泄露libc地址，之后写入

```bash
patchelf --set-interpreter /home/nan/桌面/pwn/2.27-3ubuntu1_amd64/ld-2.27.so ./pwn
patchelf --set-rpath /home/nan/桌面/pwn/2.27-3ubuntu1_amd64 ./pwn
```

![image-20261106165642907](/pwn-notes/images/notes/image-20261106165642907.png)

这里的add限制大小了

可是这道题中delete函数存在uaf漏洞

![image-20261106171158302](/pwn-notes/images/notes/image-20261106171158302.png)

![image-20261106171252050](/pwn-notes/images/notes/image-20261106171252050.png)

s0是指针数组，s1是大小数组

![image-20261106171656745](/pwn-notes/images/notes/image-20261106171656745.png)

所以才说这个delete函数存在uaf漏洞

整体思路：

**利用连续两次 `delete` 制造 Tcache Dup（双重释放） -> 泄露 `tcache_perthread_struct` 结构体地址 -> 篡改 Tcache 计数使块进入 Unsorted Bin 泄露 Libc -> 最终通过 Tcache Poisoning 劫持 `__malloc_hook` 并配合 `realloc` 调栈拿 Shell。**

现在只是能够理解到double free

之后的话泄露结构体地址之后不清楚

![image-20261106172221355](/pwn-notes/images/notes/image-20261106172221355.png)

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

![image-20261106175044484](/pwn-notes/images/notes/image-20261106175044484.png)

这是一个大堆块

正好，了解一下存在于tcashe中堆块结构

![image-20261106175555658](/pwn-notes/images/notes/image-20261106175555658.png)

0x30大小的堆块

也就是说原来的bk字段就是key的值，但是这里是0

或许是因为没有清零堆指针

所以接下来就直接uaf看一下效果

![image-20261106182627669](/pwn-notes/images/notes/image-20261106182627669.png)

![image-20261106182730834](/pwn-notes/images/notes/image-20261106182730834.png)

不是，你究竟可以泄露出什么？

![image-20261106182850361](/pwn-notes/images/notes/image-20261106182850361.png)

heap一开始的大堆块：

![image-20261106183046702](/pwn-notes/images/notes/image-20261106183046702.png)

又一次堆开头：

![image-20261106183252670](/pwn-notes/images/notes/image-20261106183252670.png)

这次看到变成200，或许这就是计数器

那后下面那个存的是这个堆块大小的头指针

![image-20261106183827595](/pwn-notes/images/notes/image-20261106183827595.png)

这次申请3个大小不同的堆块释放进入tcachebin中

![image-20261106184047058](/pwn-notes/images/notes/image-20261106184047058.png)

在这里或许可以看清counts数组,然后就是tcache指针存储情况

哦哦，也就是泄露这个起始地址之后再次修改其connts数量，之后再次释放堆块就可以进入unsortedbin了

所以说修改tcashebin的fd指针就是到开头

![image-20261106190338685](/pwn-notes/images/notes/image-20261106190338685.png)

地址接收完毕

修改地址怎么传？

![image-20261106191350577](/pwn-notes/images/notes/image-20261106191350577.png)

这个，额

fd指针指向的就是，将要分配的地址

所以应该是-250这样才会到想要修改的哪里

![image-20261106192237928](/pwn-notes/images/notes/image-20261106192237928.png)

但是仔细看这里，edit函数的read函数，这里可以看到，S_1已经被清零了，所以说这一步只能得到堆块起始地址

所以后续还需要再次申请堆块进行，修改得到起始堆块

我去了，你倒是神请相同大小的堆块进行修改啊，之后申请两次之后，就可以得到counts数组所在的地址，之后进行修改就可以

![image-20261107151321639](/pwn-notes/images/notes/image-20261107151321639.png)

可以看到已经修改为我们想要的地址了，010

之后只需要申请两次就可以得到想要修改的地址

![image-20261107151441731](/pwn-notes/images/notes/image-20261107151441731.png)

![image-20261107151720033](/pwn-notes/images/notes/image-20261107151720033.png)

这就是修改完之后的

之后释放一个相同大小的堆块，就会进入unsortedbin

![image-20261107152549716](/pwn-notes/images/notes/image-20261107152549716.png)

这里想的就是或许就只是将那一行填充为大于7的就可以，可是释放完之后还是进入的是fastbin

![image-20261107170445013](/pwn-notes/images/notes/image-20261107170445013.png)

这次改的应该可以

8

![image-20261107172012510](/pwn-notes/images/notes/image-20261107172012510.png)

这个蛮有意思，确实是从0x20开始计算数组的

之后确实是填满了

![image-20261107172604231](/pwn-notes/images/notes/image-20261107172604231.png)

果然还是需要隔离起来吗，这样才能进入unsortedbin

这里确实，就是你在申请的时候还是需要满足大小的，像是这样释放一个小块，之后进入的就是fasbin

![image-20261107173116537](/pwn-notes/images/notes/image-20261107173116537.png)

泄露成功

之后计算出基址就可以

那么就收集一下

![image-20261109192026178](/pwn-notes/images/notes/image-20261109192026178.png)

![image-20261109192709519](/pwn-notes/images/notes/image-20261109192709519.png)

这样的话就可以得到先关地址

![image-20261109201353966](/pwn-notes/images/notes/image-20261109201353966.png)

找附近满足的堆块

![image-20261109201727924](/pwn-notes/images/notes/image-20261109201727924.png)

不是正确地址

![image-20261109201801136](/pwn-notes/images/notes/image-20261109201801136.png)

这样写有问题

![image-20261109202652235](/pwn-notes/images/notes/image-20261109202652235.png)

这里之前就有unsortedbin 之后的话就直接从这里面切割了

![image-20261109203223322](/pwn-notes/images/notes/image-20261109203223322.png)

写进去了

![image-20261109203319631](/pwn-notes/images/notes/image-20261109203319631.png)

满足堆块大小条件，之后呢？

![image-20261109205906001](/pwn-notes/images/notes/image-20261109205906001.png)

两个挨在一起

到目前为止，已经找到相关的函数地址，

只是差一个double free 将这个写入并且修改可是之后7个堆块，我已经弄完了，无法接着添加

还有那个堆风水吗？难道就是需要满足onegadget的条件吗？

神了

<!-- sync-hash: cabedfed272f7905eac56fb69e2708ea2db0b9ef73635cbd411fc754638811df -->
