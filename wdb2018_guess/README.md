# canary 绕过

改程序fork一个子程序来接收输入，其gets存在栈溢出。但是程序开启canary保护。需要进行绕过

## SSP Leak

Stack Smashing Protect Leak

___stack_chk_fail跟踪：

 glibc/debug/fortify_fail.c

```c
extern char **__libc_argv attribute_hidden;
void
__attribute__ ((noreturn))
__fortify_fail_abort (_Bool need_backtrace, const char *msg)
{
  /* The loop is added only to keep gcc happy.  Don't pass down
     __libc_argv[0] if we aren't doing backtrace since __libc_argv[0]
     may point to the corrupted stack.  */
  while (1)
    __libc_message (need_backtrace ? (do_abort | do_backtrace) : do_abort,
                    "*** %s ***: %s terminated\n",
                    msg,
                    (need_backtrace && __libc_argv[0] != NULL
                     ? __libc_argv[0] : "<unknown>"));
}
void
__attribute__ ((noreturn))
__fortify_fail (const char *msg)
{
  __fortify_fail_abort (true, msg);
}
```

__libc_argv[0]指向程序的绝对路径字符串

在程序中：

````bash
In file: /glibc/source/glibc-2.23/debug/fortify_fail.c
   22 extern char **__libc_argv attribute_hidden;
   23 
   24 void
   25 __attribute__ ((noreturn)) internal_function
   26 __fortify_fail (const char *msg)
 ► 27 {
   28   /* The loop is added only to keep gcc happy.  */
   29   while (1)
   30     __libc_message (2, "*** %s ***: %s terminated\n",
   31 		    msg, __libc_argv[0] ?: "<unknown>");
   32 }
───────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────
40:0200│ r13  0x7fffffffdea0 ◂— 0x1
41:0208│ rsi  0x7fffffffdea8 —▸ 0x7fffffffe22f ◂— '/home/matrix/PWN/BUU/wdb2018_guess/Canary_t/t1'  <<<<<<<
42:0210│      0x7fffffffdeb0 ◂— 0x0
43:0218│      0x7fffffffdeb8 —▸ 0x7fffffffe25e ◂— 'XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat0'
44:0220│      0x7fffffffdec0 —▸ 0x7fffffffe292 ◂— 'XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/usr/share/upstart/xdg:/etc/xdg'
45:0228│      0x7fffffffdec8 —▸ 0x7fffffffe2d6 ◂— 'SESSION=ubuntu'

─────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────
 ► f 0     7ffff7b30b20 __fortify_fail
   f 1     7ffff7b30b20 __fortify_fail
   f 2           400606 main+112
   f 3     7ffff7a59730 __libc_start_main+240
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> p /x __libc_argv[0]
$2 = 0x7fffffffe22f   <<<<<<<<
````

可以看到__libc_argv[0]的值正是rsi指针所指向的，所以只要把这个0x7fffffffe22f覆盖为其他地址通过触发\___stack_chk_fail便可以泄露地址：`任意地址读`



这个题目由于fork一个子进程来获取输入，虽然两程序地址空间不同但是数据是相同的即可以多次触发子进程的___stack_chk_fail来泄露：libc_addr -> \_\_environ -> stack_addr -> buff_addr -> flag



## ___stack_chk_fail 的got劫持

对于开启canary的程序如果buffer溢出，那么程序将会调用___stack_chk_fail函数，那么这样就给我们提供了一个程序流劫持的方法：劫持\_\_stack_chk_fail_got，然后触发buffer溢出