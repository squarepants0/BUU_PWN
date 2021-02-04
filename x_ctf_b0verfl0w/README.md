# shellcode

没有开启保护，能溢出18个字节padding为0x20个字节

## 绕过

利用elf中的jmp esp将执行流交给栈区，前面0x20填入shellcode，后面利用asm：

asm(sub esp,0x20;call esp)即可