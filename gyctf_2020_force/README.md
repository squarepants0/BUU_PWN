#  onegadget全部失效

在一般的onegadgets中都会有条件，比较容易满足的就是需要栈环境的onegadget

```bash
➜  gyctf_2020_force one_gadget ./libc-2.23.so 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

在这个题目中通过向realloc填入onegadget，malloc填入realloc+offset可以达到修改栈空间的目的：

**<u>__libc_realloc:</u>**

```assembly
pwndbg> x/16gi &__libc_realloc 
   0x7ffff7ab1d00 <__GI___libc_realloc>:	push   r15
   0x7ffff7ab1d02 <__GI___libc_realloc+2>:	push   r14
   0x7ffff7ab1d04 <__GI___libc_realloc+4>:	push   r13
   0x7ffff7ab1d06 <__GI___libc_realloc+6>:	push   r12
   0x7ffff7ab1d08 <__GI___libc_realloc+8>:	push   rbp
   0x7ffff7ab1d09 <__GI___libc_realloc+9>:	push   rbx
   0x7ffff7ab1d0a <__GI___libc_realloc+10>:	sub    rsp,0x18
   0x7ffff7ab1d0e <__GI___libc_realloc+14>:	mov    rax,QWORD PTR [rip+0x3222bb]        # 0x7ffff7dd3fd0
```

原因如上表：libc_realloc在调用时会多次push这样就会修改栈空间，而且在__libc_realloc最开始也是对realloc_hook检查，而realloc_hook与malloc_hook相邻。不过需要调试才能确定offset具体是多少

此题最终劫持顺序为：`malloc->realloc+4->realloc_hook->onegadget(0x4526a)`

注意one_gadget工具得到的环境要求是进行转跳之后的条件要求，比如这里利用call rax劫持hook，还未转跳，call之后会进行一次push rsp也会影响栈空间，要注意~



# mmap分配的空间与libc地址

在这个题目中利用mmap分配得到libc附近的地址空间，由于该空间与libc加载地址有固偏移所以可以用来计算libc地址，但是不知为何我用本地的glibc2.23库算出来的偏移和网上大佬的偏移始终不一样。



# libc与glibc

+   对于已经给出的libc可以通过libcsearcher获取其可能版本
+   然后用glibc-all-in-one下载
+   也可以去官网搜索对于版本

得到整个版本的.deb文件后加载方式：

在pwntools中：process([ld_path,elf_path], env={"LD_PRELOAD":libc_path})